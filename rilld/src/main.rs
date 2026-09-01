//! lrill — landscape-rill rill ext 节点守护进程与 CLI
//!
//! 子命令：
//! - `lrill pubkey <signing_seed_hex>`：signing_seed → Ed25519 公钥，供节点配置信任锚
//! - `lrill run [config_path]`：前台运行 daemon（缺省 /etc/landscape/overlay.json）；
//!   systemd 场景由 unit 调用，容器场景由 ENTRYPOINT 调用（REQ-042）
//! - `lrill authkey --network <slug>`：生成 auth key（lrk 格式，REQ-036），输出仅 stdout
//! - `lrill up | down | status`：systemd 托管（REQ-042）；无 systemd 环境报错提示 `lrill run`
//!
//! 配置文件（JSON，默认 /etc/landscape/overlay.json）：
//! - node 角色：coordinator_url / auth_key / static_key_seed(hex32) / announce_routes /
//!   coord_signing_pubkey(hex32) / ca_cert_path / tun（可选）
//! - coord 角色（可选，同进程共存）：见 rill-coord `CoordConfig`（network / listen_addr /
//!   master_key / signing_seed / tls / auth_keys / announce_whitelist），加载即校验（fail-closed）
//!
//! coordinator 配置变更生效 = SIGHUP 重载（增量应用，不中断在途连接；重载失败保持旧配置）。
//! 配置与执行分离（REQ-038，CONTROL_PLANE §3.12）：CoordConfig 解析/校验在 rill-coord，
//! 生效走 CoordinatorServer::from_config/apply_config 库 API；本文件只是薄调用层。

use clap::{Parser, Subcommand};
use landscape_rill_coord::authkey::{
    generate_auth_key, is_expired, parse_auth_key, validate_network, AUTH_KEY_DEFAULT_TTL_SECS,
};
use landscape_rill_coord::config::CoordConfig;
use landscape_rill_core::error::format_chain;
use landscape_rill_core::rate::{RateCounter, RATE_SUMMARY_PERIOD};
use landscape_rill_mesh::control::{
    read_envelope, server_tls_stream, ConnectionState, CoordinatorServer,
};
use landscape_rill_node::config::Config;
use landscape_rill_node::runtime::{Node, NodeOptions};
use landscape_rill_node::tun::TunConfig;
use serde::{Deserialize, Deserializer, Serializer};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

/// 边界 I/O 结果别名（ERROR_ID §2.2）：统一 `Box<dyn Error + Send + Sync>`
type BoxResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

mod logging;

const DEFAULT_CONFIG_PATH: &str = "/etc/landscape/overlay.json";
const UNIT_NAME: &str = "lrill.service";
/// 配置文件路径环境变量（CONTROL_PLANE §3.12：CLI > env > 默认）
const CONFIG_ENV: &str = "LRILL_CONFIG";

/// 配置文件路径选择（CONTROL_PLANE §3.12 通用约定）：`run [config]` > `LRILL_CONFIG` > 默认
fn select_config(cli: Option<PathBuf>) -> PathBuf {
    cli.or_else(|| std::env::var_os(CONFIG_ENV).map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH))
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Parser)]
#[command(name = "lrill", version, about = "landscape-rill edge node daemon")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// 从 signing_seed(hex) 生成 Ed25519 公钥(hex)，供节点配置信任锚
    Pubkey { seed: String },
    /// 前台运行 daemon（缺省配置 /etc/landscape/overlay.json）
    Run {
        config: Option<PathBuf>,
        /// 追加文件日志（按天轮转 + 保留 7 个，LOGGING §4）；优先级 --log-file > LRILL_LOG_FILE > 默认仅 stderr
        #[arg(long)]
        log_file: Option<PathBuf>,
        /// 日志级别（LOGGING §2）；优先级 --log-level > RUST_LOG > 默认 info
        #[arg(long)]
        log_level: Option<LogLevel>,
    },
    /// 生成 auth key（lrk-<network>-<expiry>-<base32>，输出仅 stdout，不落日志；
    /// 默认有效期 24h，--ttl 0 永不过期；REQ-036/REQ-043）
    Authkey {
        /// 网络标识（归域绑定，须与 coordinator 配置 network 一致）
        #[arg(long)]
        network: String,
        /// 有效期：<num><s|m|h|d>（如 30m/12h/7d），0 = 永不过期；默认 24h
        #[arg(long, value_parser = parse_duration_arg)]
        ttl: Option<u64>,
    },
    /// 安装并启动 systemd 服务（无 systemd 环境报错提示 `lrill run`）
    Up,
    /// 停止 systemd 服务
    Down,
    /// 查询 systemd 服务状态
    Status,
}

/// CLI 日志级别（LOGGING §2；显式指定时覆盖 RUST_LOG）
#[derive(Clone, Copy, clap::ValueEnum)]
enum LogLevel {
    Off,
    Error,
    Warn,
    Info,
    Debug,
}

/// `--ttl` 的 clap value_parser（复用 authkey 解析，错误信息面向 CLI）
fn parse_duration_arg(s: &str) -> Result<u64, String> {
    landscape_rill_coord::authkey::parse_duration(s)
        .map_err(|_| "expected <num><s|m|h|d> (e.g. 30m/12h/7d), or 0 = never expires".to_string())
}

impl LogLevel {
    fn as_filter(self) -> tracing_subscriber::filter::LevelFilter {
        use tracing_subscriber::filter::LevelFilter;
        match self {
            LogLevel::Off => LevelFilter::OFF,
            LogLevel::Error => LevelFilter::ERROR,
            LogLevel::Warn => LevelFilter::WARN,
            LogLevel::Info => LevelFilter::INFO,
            LogLevel::Debug => LevelFilter::DEBUG,
        }
    }
}

// ============================================================================
// 配置文件（serde）
// ============================================================================

#[derive(Debug, Deserialize)]
struct FileConfig {
    /// node 角色字段（缺省 = 纯 coordinator）
    #[serde(default)]
    coordinator_url: Option<String>,
    #[serde(default)]
    auth_key: Option<String>,
    #[serde(default, with = "hex32_opt")]
    static_key_seed: Option<[u8; 32]>,
    #[serde(default)]
    capabilities: u32,
    #[serde(default)]
    announce_routes: Vec<String>,
    #[serde(default, with = "hex32_opt")]
    coord_signing_pubkey: Option<[u8; 32]>,
    #[serde(default)]
    ca_cert_path: String,
    /// coordinator UDP 回显地址（host:port）；缺省 = coordinator_url host + 8443
    #[serde(default)]
    udp_echo_addr: Option<String>,
    #[serde(default)]
    tun: Option<TunFile>,
    #[serde(default)]
    coord: Option<CoordConfig>,
}

#[derive(Debug, Deserialize)]
struct TunFile {
    #[serde(default = "default_tun_name")]
    name: String,
    #[serde(default = "default_mtu")]
    mtu: u16,
    /// "10.42.0.1/24"
    #[serde(default)]
    address4: Option<String>,
    /// "fd00:2::1/64"（IPv6 组播泛洪/ND 需要，FRAME_HEADER §2.6）
    #[serde(default)]
    address6: Option<String>,
}

fn default_tun_name() -> String {
    "land0".into()
}

fn default_mtu() -> u16 {
    1420
}

/// [u8; 32] ⇄ 64 字符 hex（无第三方 hex crate）
mod hex32 {
    pub(crate) fn decode(s: &str) -> Result<Vec<u8>, String> {
        if !s.len().is_multiple_of(2) {
            return Err("odd hex length".into());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
            .collect()
    }

    pub(crate) fn encode_owned(v: &[u8; 32]) -> String {
        v.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

/// Option<[u8; 32]>（字段缺省 = None）
mod hex32_opt {
    use super::*;

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 32]>, D::Error> {
        Option::<String>::deserialize(d)?
            .map(|s| {
                let bytes = hex32::decode(&s).map_err(serde::de::Error::custom)?;
                bytes
                    .try_into()
                    .map_err(|_| serde::de::Error::custom("expected 32 bytes (64 hex chars)"))
            })
            .transpose()
    }

    #[allow(dead_code)]
    pub fn serialize<S: Serializer>(v: &Option<[u8; 32]>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(k) => s.serialize_some(&hex32::encode_owned(k)),
            None => s.serialize_none(),
        }
    }
}

// ============================================================================
// coordinator 角色：共享注册表 + 按连接隔离状态的多连接服务
// 配置变更（SIGHUP）→ 重新解析 + apply_config 增量应用（REQ-038）
// ============================================================================

/// 从 overlay.json 取出嵌套的 coord 配置（coord 角色字段），加载即校验（fail-closed）
fn load_coord(path: &Path) -> BoxResult<CoordConfig> {
    let text = std::fs::read_to_string(path)?;
    let file: FileConfig = serde_json::from_str(&text)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    let coord = file.coord.ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "配置中无 coord 角色字段")
    })?;
    coord.validate().map_err(|e| {
        Box::<dyn std::error::Error + Send + Sync>::from(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            e.to_string(),
        ))
    })?;
    Ok(coord)
}

async fn run_coord(config_path: &Path) -> BoxResult<()> {
    let config = load_coord(config_path)?;
    let cert = std::fs::read(&config.tls_cert_path)?;
    let key = std::fs::read(&config.tls_key_path)?;
    let mut listener = TcpListener::bind(config.listen_addr.parse::<SocketAddr>()?).await?;
    let server = Arc::new(Mutex::new(CoordinatorServer::from_config(&config)?));
    let mut hangup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
    // 高频失败 → 周期摘要（LOGGING §5）：事件只计数，每周期 ≤1 条，0 不输出
    let mut accept_failed = RateCounter::new(RATE_SUMMARY_PERIOD);
    let mut summary = tokio::time::interval(RATE_SUMMARY_PERIOD);
    // UDP 数据面（CONNECTIVITY §2/§5）：coordinator 回显 + relay RTT 排序；独立任务
    let networks: Vec<(String, u32)> = config
        .networks
        .iter()
        .map(|n| {
            (
                n.name.clone(),
                landscape_rill_coord::domain::network_id_for(&n.name),
            )
        })
        .collect();
    let udp_addr: SocketAddr = config
        .udp_listen_addr
        .as_deref()
        .map(|s| s.parse().expect("validated"))
        .unwrap_or_else(|| config.listen_addr.parse().expect("validated"));
    let udp = tokio::net::UdpSocket::bind(udp_addr).await?;
    let udp_server = server.clone();
    tokio::spawn(async move { run_coord_udp(udp, udp_server, networks).await });
    let net_names: Vec<String> = config.networks.iter().map(|n| n.name.clone()).collect();
    info!(
        "[coord] listening on {} (networks={}, udp={}, reload=SIGHUP)",
        listener.local_addr()?,
        net_names.join(","),
        udp_addr
    );
    loop {
        tokio::select! {
            // 注意：首次 poll 才注册信号监听，首个连接也走同一 select（无提前 await 窗口）
            _ = hangup.recv() => {
                info!("[coord] SIGHUP received");
                match load_coord(config_path) {
                    Ok(new_cfg) => {
                        server.lock().await.apply_config(&new_cfg);
                        info!("[coord] config reloaded (SIGHUP)");
                    }
                    Err(e) => {
                        error!("[coord] reload failed, keeping old config: {}", format_chain(&*e))
                    }
                }
            }
            _ = summary.tick() => {
                if let Some(n) = accept_failed.poll(Instant::now()) {
                    if n > 0 {
                        warn!("[coord] accept failed: {n} in last 1s");
                    }
                }
                let mut guard = server.lock().await;
                if let Some(n) = guard.register_rejected.poll(Instant::now()) {
                    if n > 0 {
                        warn!("[coord] register rejected: {n} in last 1s");
                    }
                }
            }
            next = accept_next(&mut listener, &cert, &key) => {
                // 单连接 TLS 错误不得杀死 coordinator（恶意/畸形握手 → 计数摘要后继续监听）
                let tls = match next {
                    Ok(t) => t,
                    Err(_) => {
                        accept_failed.tick();
                        continue;
                    }
                };
                let srv = server.clone();
                tokio::spawn(async move {
                    let mut conn = ConnectionState::default();
                    let mut tls = tls;
                    loop {
                        let (msg_type, body) = match read_envelope(&mut tls).await {
                            Ok(v) => v,
                            Err(_) => break,
                        };
                        let mut guard = srv.lock().await;
                        if guard
                            .handle_message(&mut conn, &mut tls, msg_type, &body)
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                });
            }
        }
    }
}

async fn accept_next(
    listener: &mut TcpListener,
    cert: &[u8],
    key: &[u8],
) -> BoxResult<tokio_rustls::server::TlsStream<tokio::net::TcpStream>> {
    server_tls_stream(listener, cert, key).await.map_err(|e| {
        Box::<dyn std::error::Error + Send + Sync>::from(std::io::Error::other(e.to_string()))
    })
}

/// relay RTT 探测周期（CONNECTIVITY §5：可达性验证 + RTT 测量）
const RELAY_RTT_PERIOD: std::time::Duration = std::time::Duration::from_secs(30);
/// RTT 收集窗口（PONG 应答等待）
const RELAY_RTT_COLLECT: std::time::Duration = std::time::Duration::from_secs(3);

/// coordinator UDP 数据面任务（CONNECTIVITY §2/§5）：
/// ① 回显：probe PING（to=0 标记）→ PONG 携带 seen 地址（STUN 式），按源 IP 限速（§2.2）
/// ② relay RTT 排序：周期向各网 relay 端点发 PING 测 RTT → 排序写入 relay_list +
///    PathService relay 顺序（挂靠优先级）
async fn run_coord_udp(
    udp: tokio::net::UdpSocket,
    server: std::sync::Arc<tokio::sync::Mutex<CoordinatorServer>>,
    networks: Vec<(String, u32)>,
) {
    use landscape_rill_coord::echo::{
        echo_response, EchoLimiter, ECHO_CAPACITY, ECHO_RATE_PER_SEC,
    };
    use landscape_rill_core::probe::{probe_type, ProbePacket, NODE_ID_COORDINATOR};
    let mut limiter = EchoLimiter::new(ECHO_RATE_PER_SEC, ECHO_CAPACITY);
    let mut answered = RateCounter::new(RATE_SUMMARY_PERIOD);
    let mut limited = RateCounter::new(RATE_SUMMARY_PERIOD);
    let mut summary = tokio::time::interval(RATE_SUMMARY_PERIOD);
    // RTT 探测状态：nonce → (network_id, node_id, endpoint, sent)
    let mut rtt_probes: HashMap<u32, (u32, u32, String, std::time::Instant)> = HashMap::new();
    // 已测 RTT：network_id → (node_id, endpoint) → rtt
    let mut rtt_done: HashMap<u32, HashMap<(u32, String), u64>> = HashMap::new();
    let mut collecting = false;
    let mut collect_deadline = std::time::Instant::now();
    let mut next_rtt = std::time::Instant::now() + RELAY_RTT_PERIOD;
    let mut buf = vec![0u8; 65535];
    loop {
        let until = if collecting {
            tokio::time::Instant::from_std(collect_deadline)
        } else {
            tokio::time::Instant::from_std(next_rtt)
        };
        tokio::select! {
            r = udp.recv_from(&mut buf) => {
                let Ok((n, from)) = r else { continue };
                let Some(p) = ProbePacket::decode(&buf[..n]) else { continue };
                match p.packet_type {
                    probe_type::PING if p.to_node_id == NODE_ID_COORDINATOR => {
                        if limiter.allow(from.ip()) {
                            if let Some(resp) = echo_response(&buf[..n], from) {
                                let _ = udp.send_to(&resp, from).await;
                                answered.tick();
                            }
                        } else {
                            limited.tick();
                        }
                        limiter.prune();
                    }
                    probe_type::PONG if collecting => {
                        if let Some((net_id, node, ep, sent)) = rtt_probes.remove(&p.nonce) {
                            let rtt_ms = sent.elapsed().as_millis() as u64;
                            rtt_done.entry(net_id).or_default().insert((node, ep), rtt_ms);
                        }
                    }
                    _ => {}
                }
            }
            _ = tokio::time::sleep_until(until) => {
                if collecting {
                    // 收集窗口结束：按 RTT 排序应用（relay_list + 路径挂靠顺序）
                    collecting = false;
                    for (name, net_id) in &networks {
                        let done = rtt_done.remove(net_id).unwrap_or_default();
                        if done.is_empty() {
                            continue;
                        }
                        let mut node_best: HashMap<u32, u64> = HashMap::new();
                        for ((node, _ep), rtt) in &done {
                            let e = node_best.entry(*node).or_insert(u64::MAX);
                            *e = (*e).min(*rtt);
                        }
                        let mut eps: Vec<(String, u64)> = done
                            .into_iter()
                            .map(|((_n, ep), rtt)| (ep, rtt))
                            .collect();
                        eps.sort_by_key(|(_, r)| *r);
                        let mut nodes: Vec<(u32, u64)> =
                            node_best.into_iter().collect();
                        nodes.sort_by_key(|(_, r)| *r);
                        let mut guard = server.lock().await;
                        guard.coordinator.set_relay_list(
                            name,
                            eps.iter().map(|(e, _)| e.clone()).collect(),
                        );
                        guard.coordinator.set_relay_order(
                            name,
                            nodes.iter().map(|(n, _)| *n).collect(),
                        );
                        info!(
                            "[coord] relay rtt (net={}): {}",
                            name,
                            eps.iter()
                                .map(|(e, r)| format!("{e}({r}ms)"))
                                .collect::<Vec<_>>()
                                .join(" ")
                        );
                    }
                    next_rtt = std::time::Instant::now() + RELAY_RTT_PERIOD;
                } else {
                    // 发起新一轮 RTT 探测（各网络 relay 能力节点的全部已上报端点）
                    rtt_probes.clear();
                    let mut sent = 0usize;
                    for (_name, net_id) in &networks {
                        let targets = server
                            .lock()
                            .await
                            .coordinator
                            .relay_probe_targets(*net_id);
                        for (node, eps) in targets {
                            for ep in eps {
                                let Ok(addr) = ep.parse::<SocketAddr>() else { continue };
                                let nonce = landscape_rill_core::probe::random_nonce();
                                let ping = ProbePacket::ping(NODE_ID_COORDINATOR, node, nonce);
                                if udp.send_to(&ping.encode(), addr).await.is_ok() {
                                    rtt_probes.insert(
                                        nonce,
                                        (*net_id, node, ep, std::time::Instant::now()),
                                    );
                                    sent += 1;
                                }
                            }
                        }
                    }
                    if sent > 0 {
                        collecting = true;
                        collect_deadline = std::time::Instant::now() + RELAY_RTT_COLLECT;
                    } else {
                        next_rtt = std::time::Instant::now() + RELAY_RTT_PERIOD;
                    }
                    debug!("[coord] relay rtt probe sent: {sent}");
                }
            }
            _ = summary.tick() => {
                if let Some(n) = answered.poll(std::time::Instant::now()) {
                    if n > 0 {
                        debug!("[coord] echo answered: {n} in last 1s");
                    }
                }
                if let Some(n) = limited.poll(std::time::Instant::now()) {
                    if n > 0 {
                        warn!("[coord] echo rate-limited: {n} in last 1s (SEC-26)");
                    }
                }
            }
        }
    }
}

// ============================================================================
// systemd 托管（REQ-042）：unit 模板生成/安装；无 systemd 明确报错提示 lrill run
// ============================================================================

fn systemd_unit() -> String {
    let exe = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "/usr/local/bin/lrill".into());
    format!(
        "[Unit]\n\
         Description=landscape-rill edge node daemon\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={exe} run\n\
         ExecReload=/bin/kill -HUP $MAINPID\n\
         Restart=on-failure\n\
         RestartSec=3\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    )
}

fn require_systemctl() -> Result<(), String> {
    if std::process::Command::new("systemctl")
        .arg("--version")
        .output()
        .is_err()
    {
        return Err("无 systemd 环境：请用 `lrill run` 前台运行".into());
    }
    Ok(())
}

fn systemctl(args: &[&str]) -> Result<(), String> {
    let out = std::process::Command::new("systemctl")
        .args(args)
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(())
}

fn cmd_up() -> Result<(), String> {
    require_systemctl()?;
    let unit_path = PathBuf::from("/etc/systemd/system").join(UNIT_NAME);
    std::fs::write(&unit_path, systemd_unit())
        .map_err(|e| format!("写入 {}: {e}", unit_path.display()))?;
    systemctl(&["daemon-reload"])?;
    systemctl(&["enable", "--now", UNIT_NAME])?;
    println!("lrill.service installed and started");
    Ok(())
}

fn cmd_down() -> Result<(), String> {
    require_systemctl()?;
    systemctl(&["stop", UNIT_NAME])?;
    systemctl(&["disable", UNIT_NAME])?;
    println!("lrill.service stopped");
    Ok(())
}

fn cmd_status() -> Result<(), String> {
    require_systemctl()?;
    let out = std::process::Command::new("systemctl")
        .args(["status", UNIT_NAME, "--no-pager"])
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() || !out.stderr.is_empty() {
        print!("{}", String::from_utf8_lossy(&out.stdout));
        print!("{}", String::from_utf8_lossy(&out.stderr));
    } else {
        println!("lrill.service 未运行（或未安装）");
    }
    Ok(())
}

// ============================================================================
// main
// ============================================================================

fn main() -> BoxResult<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cli = Cli::parse();
    match cli.command {
        Some(Command::Pubkey { seed }) => {
            let seed = hex32::decode(&seed)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
            let seed: [u8; 32] = seed
                .try_into()
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad seed"))?;
            let vk =
                ed25519_dalek::VerifyingKey::from(&ed25519_dalek::SigningKey::from_bytes(&seed));
            println!("{}", hex32::encode_owned(&vk.to_bytes()));
            Ok(())
        }
        Some(Command::Authkey { network, ttl }) => {
            validate_network(&network).map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string())
            })?;
            let key = generate_auth_key(&network, ttl.unwrap_or(AUTH_KEY_DEFAULT_TTL_SECS))?;
            println!("{key}");
            Ok(())
        }
        Some(Command::Up) => cmd_up().map_err(Into::into),
        Some(Command::Down) => cmd_down().map_err(Into::into),
        Some(Command::Status) => cmd_status().map_err(Into::into),
        None => run_daemon(&select_config(None), None, None),
        Some(Command::Run {
            config,
            log_file,
            log_level,
        }) => run_daemon(
            &select_config(config),
            log_file,
            log_level.map(LogLevel::as_filter),
        ),
    }
}

fn run_daemon(
    path: &Path,
    log_file: Option<PathBuf>,
    log_level: Option<tracing_subscriber::filter::LevelFilter>,
) -> BoxResult<()> {
    // 仅 daemon 初始化日志框架（LOGGING §1）；CLI 子命令直接 stdout/stderr
    logging::init_logging(log_level, log_file)?;
    let text = std::fs::read_to_string(path)
        .map_err(|e| std::io::Error::new(e.kind(), format!("config {}: {}", path.display(), e)))?;
    let file: FileConfig = serde_json::from_str(&text)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{:?}", e)))?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let config_path = path.to_path_buf();
    runtime.block_on(async move {
        if file.coord.is_some() {
            let path = config_path.clone();
            tokio::spawn(async move {
                if let Err(e) = run_coord(&path).await {
                    error!("[coord] fatal: {}", format_chain(&*e));
                }
            });
        }
        let node_fields = (
            file.coordinator_url.clone(),
            file.auth_key.clone(),
            file.static_key_seed,
            file.coord_signing_pubkey,
            file.ca_cert_path.clone(),
        );
        let (
            Some(coordinator_url),
            Some(auth_key),
            Some(static_key_seed),
            Some(coord_signing_pubkey),
            ca_cert_path,
        ) = node_fields
        else {
            info!("[node] 无 node 角色字段，仅运行 coordinator");
            std::future::pending::<()>().await;
            return Ok(());
        };
        // coordinator UDP 回显目标（host:port，允许主机名）：显式配置优先，
        // 缺省从 coordinator_url 推导（coordinator 默认 TCP/UDP 同端口，CONNECTIVITY §2）
        let udp_echo_addr = match &file.udp_echo_addr {
            Some(s) => Some(s.clone()),
            None => Some(landscape_rill_node::config::Config::coord_echo_target(
                &coordinator_url,
            )),
        };
        let config = Config {
            coordinator_url,
            auth_key,
            static_key_seed,
            capabilities: file.capabilities,
            announce_routes: file.announce_routes.clone(),
            coord_signing_pubkey,
            ca_cert_path,
            udp_echo_addr,
            coord: None,
        };
        config.validate().map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("config invalid: {:?}", e),
            )
        })?;
        // REQ-043：auth key 过期 → 告警不阻断（已注册节点仍可走挑战恢复路径，
        // 硬拒绝会卡死重连）；格式非法同样只告警（coordinator 是最终裁决）。
        // auth key 不进日志（LOGGING §6，REQ-036/AO-01/AO-02）
        if is_expired(&config.auth_key, unix_now()) {
            warn!("[node] auth key 已过期，新注册将被拒；已注册节点仍可经挑战恢复");
        } else if parse_auth_key(&config.auth_key).is_err() {
            warn!("[node] auth key 格式无法解析，注册将失败");
        }
        let opts = NodeOptions {
            tun: file.tun.as_ref().map(|t| TunConfig {
                name: t.name.clone(),
                mtu: t.mtu,
                address4: t.address4.as_ref().and_then(|s| {
                    let (ip, prefix) = s.split_once('/')?;
                    Some((ip.parse().ok()?, prefix.parse().ok()?))
                }),
                address6: t.address6.as_ref().and_then(|s| {
                    let (ip, prefix) = s.split_once('/')?;
                    Some((ip.parse().ok()?, prefix.parse().ok()?))
                }),
            }),
            ..NodeOptions::default()
        };
        info!(
            "[node] starting (coordinator={}, tun={})",
            config.coordinator_url,
            opts.tun
                .as_ref()
                .map(|t| t.name.clone())
                .unwrap_or_else(|| "-".into())
        );
        let node = Node::new(config, opts)
            .await
            .map_err(std::io::Error::other)?;
        node.run().await;
        Ok(())
    })
}
