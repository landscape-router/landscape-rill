//! ts2021 服务端运行入口（REQ-068，TS2021_LEG §4）：TLS accept 循环 +
//! 单连接分派（serve_connection：/key、/ts2021、/derp）。
//! v1 内存态、无 SIGHUP 重载（重启即清空注册表，客户端重注册自愈）。

use crate::BoxResult;
use landscape_rill_core::error::format_chain;
use landscape_rill_ts2021::server::{serve_connection, tls_acceptor, ServerConfig, Ts2021Server};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info, warn};

/// e2e 注入 marker 路径（RILL_E2E_TS2021_EVICT_NODE 指定的 hostname，
/// marker 文件出现即驱逐；REQ-057 同源哲学：env 装填 + 文件触发）
const EVICT_MARKER: &str = "/tmp/rill-e2e-evict";

pub(crate) async fn run_ts2021_server(cfg: ServerConfig) -> BoxResult<()> {
    cfg.validate().map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("ts2021_server: {e}"),
        )
    })?;
    let cert = std::fs::read(&cfg.tls_cert_path)?;
    let key = std::fs::read(&cfg.tls_key_path)?;
    let acceptor = tls_acceptor(&cert, &key)?;
    let server = Arc::new(Ts2021Server::from_config(&cfg).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("ts2021_server: {e}"),
        )
    })?);
    let listener = TcpListener::bind(cfg.listen_addr.parse::<SocketAddr>()?).await?;
    info!(
        "[ts2021-server] listening on {} (network={}, noise={})",
        listener.local_addr()?,
        cfg.network,
        landscape_rill_ts2021::tailcfg::hex(&server.noise_pub())
    );
    // e2e 驱逐注入（阶段三增量推送场景）：仅 env 装填时启动
    if let Ok(host) = std::env::var("RILL_E2E_TS2021_EVICT_NODE") {
        let srv = server.clone();
        warn!("[ts2021-server] e2e injection armed: evict '{host}' on {EVICT_MARKER}");
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_millis(500));
            loop {
                tick.tick().await;
                if std::path::Path::new(EVICT_MARKER).exists() {
                    let _ = std::fs::remove_file(EVICT_MARKER);
                    srv.registry.lock().unwrap().evict(&host);
                }
            }
        });
    }
    loop {
        // 只 select 裸 accept（取消安全），TLS 握手在 spawn 任务里进行（coord 同源）
        let (tcp, _) = match listener.accept().await {
            Ok(t) => t,
            Err(e) => {
                warn!("[ts2021-server] accept error: {e}");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let server = server.clone();
        tokio::spawn(async move {
            let tls = match acceptor.accept(tcp).await {
                Ok(t) => t,
                Err(_) => return,
            };
            let _ = serve_connection(tls, server).await;
        });
    }
}

/// 装配辅助：FileConfig.ts2021_server 校验后转交运行入口（失败 fail-closed）
pub(crate) fn spawn_ts2021_server(cfg: ServerConfig) {
    tokio::spawn(async move {
        if let Err(e) = run_ts2021_server(cfg).await {
            error!("[ts2021-server] fatal: {}", format_chain(&*e));
        }
    });
}
