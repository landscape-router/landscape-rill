//! node 守护入口：FileConfig → Config 装配 + node/coord 角色分派

use crate::coord_run::run_coord;
use crate::{unix_now, BoxResult, FileConfig};
use landscape_rill_coord::authkey::{is_expired, parse_auth_key};
use landscape_rill_core::error::format_chain;
use landscape_rill_node::config::Config;
use landscape_rill_node::runtime::{Node, NodeOptions};
use landscape_rill_node::tun::TunConfig;
use std::path::{Path, PathBuf};
use tracing::{error, info, warn};

pub(crate) fn run_daemon(
    path: &Path,
    log_file: Option<PathBuf>,
    log_level: Option<tracing_subscriber::filter::LevelFilter>,
) -> BoxResult<()> {
    // 仅 daemon 初始化日志框架（LOGGING §1）；CLI 子命令直接 stdout/stderr
    crate::logging::init_logging(log_level, log_file)?;
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
