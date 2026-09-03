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
    generate_auth_key, validate_network, AUTH_KEY_DEFAULT_TTL_SECS,
};
use landscape_rill_coord::config::CoordConfig;
use serde::{Deserialize, Deserializer, Serializer};
use std::path::{Path, PathBuf};

/// 边界 I/O 结果别名（ERROR_ID §2.2）：统一 `Box<dyn Error + Send + Sync>`
pub(crate) type BoxResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

mod coord_run;
mod logging;
mod node_run;
mod status_http;

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
    /// 数据面 underlay 传输（REQ-054）："udp"（默认）/"tcp"
    #[serde(default)]
    data_transport: Option<String>,
    #[serde(default)]
    tun: Option<TunFile>,
    #[serde(default)]
    coord: Option<CoordConfig>,
    /// dn42 接入（DN42_LEG）：缺省 = 未启用
    #[serde(default)]
    dn42: Option<Dn42File>,
}

/// dn42 接入配置（serde 形态；校验在 rill-node config::dn42，加载即校验）
#[derive(Debug, Deserialize)]
struct Dn42File {
    local_as: u32,
    bgp_id: String,
    #[serde(default = "default_hold_time")]
    hold_time: u16,
    #[serde(default)]
    own_prefixes: Vec<String>,
    peers: Vec<Dn42PeerFile>,
}

fn default_hold_time() -> u16 {
    90
}

#[derive(Debug, Deserialize)]
struct Dn42PeerFile {
    name: String,
    endpoint: String,
    /// 对端 WG 公钥（base64，wg pubkey 格式）
    public_key: String,
    #[serde(default)]
    preshared_key: Option<String>,
    local_v4: String,
    local_v6: String,
    peer_v4: String,
    peer_v6: String,
    peer_as: u32,
    #[serde(default = "default_bgp_port")]
    bgp_port: u16,
    local_bgp_port: u16,
    /// import 白名单（covered-by）
    whitelist: Vec<String>,
    #[serde(default)]
    max_prefixes: Option<u32>,
}

fn default_bgp_port() -> u16 {
    179
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
        None => node_run::run_daemon(&select_config(None), None, None),
        Some(Command::Run {
            config,
            log_file,
            log_level,
        }) => node_run::run_daemon(
            &select_config(config),
            log_file,
            log_level.map(LogLevel::as_filter),
        ),
    }
}
