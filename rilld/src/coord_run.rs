//! coordinator 运行入口：TLS accept 循环 + SIGHUP 重载 + UDP 数据面
//! （echo 回显限速 + relay RTT 排序，CONNECTIVITY §2/§5）

use crate::{load_coord, BoxResult};
use landscape_rill_core::error::format_chain;
use landscape_rill_core::rate::{RateCounter, RATE_SUMMARY_PERIOD};
use landscape_rill_mesh::control::{
    read_envelope, server_tls_stream, ConnectionState, CoordinatorServer,
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

pub(crate) async fn run_coord(config_path: &Path) -> BoxResult<()> {
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
    let mut buf = bytes::BytesMut::with_capacity(2048);
    loop {
        buf.clear();
        let until = if collecting {
            tokio::time::Instant::from_std(collect_deadline)
        } else {
            tokio::time::Instant::from_std(next_rtt)
        };
        tokio::select! {
            r = udp.recv_buf_from(&mut buf) => {
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
