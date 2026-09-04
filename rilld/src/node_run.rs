//! node 守护入口：FileConfig → Config 装配 + node/coord 角色分派

use crate::coord_run::run_coord;
use crate::{unix_now, BoxResult, FileConfig};
use landscape_rill_coord::authkey::{is_expired, parse_auth_key};
use landscape_rill_core::error::format_chain;
use landscape_rill_node::config::{Config, DataTransport, Dn42Config, Dn42PeerConfig};
use landscape_rill_node::runtime::{Node, NodeOptions};
use landscape_rill_node::tun::TunConfig;
use std::path::{Path, PathBuf};
use tracing::{error, info, warn};

/// FileConfig.dn42 → 节点 dn42 配置（字符串字段解析；语义校验在 Config::validate，fail-closed）
pub(crate) fn dn42_config_from_file(d: &crate::Dn42File) -> std::io::Result<Dn42Config> {
    let bad = |what: String| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("dn42 config: {what}"),
        )
    };
    let peers = d
        .peers
        .iter()
        .map(|p| {
            Ok(Dn42PeerConfig {
                name: p.name.clone(),
                endpoint: p
                    .endpoint
                    .parse()
                    .map_err(|e| bad(format!("peer {}: endpoint: {e}", p.name)))?,
                public_key: p.public_key.clone(),
                preshared_key: p.preshared_key.clone(),
                local_v4: p
                    .local_v4
                    .parse()
                    .map_err(|e| bad(format!("peer {}: local_v4: {e}", p.name)))?,
                local_v6: p
                    .local_v6
                    .parse()
                    .map_err(|e| bad(format!("peer {}: local_v6: {e}", p.name)))?,
                peer_v4: p
                    .peer_v4
                    .parse()
                    .map_err(|e| bad(format!("peer {}: peer_v4: {e}", p.name)))?,
                peer_v6: p
                    .peer_v6
                    .parse()
                    .map_err(|e| bad(format!("peer {}: peer_v6: {e}", p.name)))?,
                peer_as: p.peer_as,
                bgp_port: p.bgp_port,
                local_bgp_port: p.local_bgp_port,
                whitelist: p.whitelist.clone(),
                max_prefixes: p.max_prefixes,
            })
        })
        .collect::<Result<Vec<_>, std::io::Error>>()?;
    Ok(Dn42Config {
        local_as: d.local_as,
        bgp_id: d.bgp_id.parse().map_err(|e| bad(format!("bgp_id: {e}")))?,
        hold_time: d.hold_time,
        own_prefixes: d.own_prefixes.clone(),
        announce_to_mesh: d.announce_to_mesh,
        peers,
    })
}

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
            data_transport: match file.data_transport.as_deref() {
                None => DataTransport::default(),
                Some(s) => DataTransport::parse(s).ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "data_transport must be \"udp\" or \"tcp\"",
                    )
                })?,
            },
            coord: None,
            dn42: file.dn42.as_ref().map(dn42_config_from_file).transpose()?,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FileConfig;

    #[test]
    fn dn42_file_config_maps_to_node_config() {
        let text = r#"{
            "coordinator_url": "https://coord:8443",
            "auth_key": "lrk-lab-1735689600-deadbeef",
            "static_key_seed": "0101010101010101010101010101010101010101010101010101010101010101",
            "coord_signing_pubkey": "0707070707070707070707070707070707070707070707070707070707070707",
            "ca_cert_path": "/etc/landscape/ca.pem",
            "dn42": {
                "local_as": 4242420001,
                "bgp_id": "172.20.100.1",
                "hold_time": 15,
                "own_prefixes": ["172.20.1.0/24"],
                "peers": [
                    {
                        "name": "peer-r",
                        "endpoint": "192.168.243.10:51820",
                        "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                        "local_v4": "172.20.100.1",
                        "local_v6": "fd00:100::1",
                        "peer_v4": "172.20.100.2",
                        "peer_v6": "fd00:100::2",
                        "peer_as": 4242420002,
                        "local_bgp_port": 1179,
                        "whitelist": ["172.20.0.0/14"],
                        "max_prefixes": 1000
                    }
                ]
            }
        }"#;
        let file: FileConfig = serde_json::from_str(text).unwrap();
        let dn42 = dn42_config_from_file(file.dn42.as_ref().unwrap()).unwrap();
        assert_eq!(dn42.local_as, 4242420001);
        assert_eq!(dn42.peers.len(), 1);
        assert_eq!(dn42.peers[0].name, "peer-r");
        assert_eq!(
            dn42.peers[0].endpoint,
            "192.168.243.10:51820".parse().unwrap()
        );
        assert_eq!(dn42.peers[0].bgp_port, 179); // 缺省值
        assert!(dn42.validate().is_ok());
    }

    #[test]
    fn dn42_file_config_bad_address_rejected() {
        let text = r#"{
            "local_as": 4242420001,
            "bgp_id": "172.20.100.1",
            "peers": [
                {
                    "name": "peer-r",
                    "endpoint": "not-an-addr",
                    "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                    "local_v4": "172.20.100.1",
                    "local_v6": "fd00:100::1",
                    "peer_v4": "172.20.100.2",
                    "peer_v6": "fd00:100::2",
                    "peer_as": 4242420002,
                    "local_bgp_port": 1179,
                    "whitelist": ["172.20.0.0/14"]
                }
            ]
        }"#;
        let file: crate::Dn42File = serde_json::from_str(text).unwrap();
        assert!(dn42_config_from_file(&file).is_err());
    }
}
