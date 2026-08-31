//! lrill — landscape-rill 边缘节点守护进程与 CLI
//!
//! 子命令：
//! - `lrill pubkey <signing_seed_hex>`：signing_seed → Ed25519 公钥，供节点配置信任锚
//! - `lrill run [config_path]`：前台运行 daemon（缺省 /etc/landscape/overlay.json）；
//!   systemd 场景由 unit 调用，容器场景由 ENTRYPOINT 调用（REQ-042）
//!
//! 配置文件（JSON，默认 /etc/landscape/overlay.json）：
//! - node 角色：coordinator_url / auth_key / static_key_seed(hex32) / announce_routes /
//!   coord_signing_pubkey(hex32) / ca_cert_path / tun（可选）
//! - coord 角色（可选，同进程共存）：listen_addr / master_key(hex32) / signing_seed(hex32) /
//!   tls_cert_path / tls_key_path / auth_keys
//!
//! 密钥均为 64 字符 hex；coord 角色 = 共享注册表多连接服务（ConnectionState 按连接隔离）。

use clap::{Parser, Subcommand};
use landscape_rill_core::control::registry::AuthKeyPolicy;
use landscape_rill_mesh::control::{
    read_envelope, server_tls_stream, ConnectionState, CoordinatorServer,
};
use landscape_rill_node::config::Config;
use landscape_rill_node::runtime::{Node, NodeOptions};
use landscape_rill_node::tun::TunConfig;
use serde::{Deserialize, Deserializer, Serializer};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

const DEFAULT_CONFIG_PATH: &str = "/etc/landscape/overlay.json";

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
    Run { config: Option<PathBuf> },
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
    #[serde(default)]
    tun: Option<TunFile>,
    #[serde(default)]
    coord: Option<CoordFile>,
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

#[derive(Debug, Clone, Deserialize)]
struct CoordFile {
    listen_addr: String,
    #[serde(with = "hex32")]
    master_key: [u8; 32],
    #[serde(with = "hex32")]
    signing_seed: [u8; 32],
    tls_cert_path: String,
    tls_key_path: String,
    #[serde(default)]
    auth_keys: Vec<AuthKeyFile>,
}

#[derive(Debug, Clone, Deserialize)]
struct AuthKeyFile {
    key: String,
    #[serde(default = "default_policy")]
    policy: String,
}

fn default_policy() -> String {
    "reusable".into()
}

/// [u8; 32] ⇄ 64 字符 hex（无第三方 hex crate）
mod hex32 {
    use super::*;

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let bytes = decode(&s).map_err(serde::de::Error::custom)?;
        bytes.try_into().map_err(|_| serde::de::Error::custom("expected 32 bytes (64 hex chars)"))
    }

    #[allow(dead_code)]
    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&encode_owned(v))
    }

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
// ============================================================================

async fn run_coord(coord: CoordFile) -> Result<(), Box<dyn std::error::Error>> {
    let cert = std::fs::read(&coord.tls_cert_path)?;
    let key = std::fs::read(&coord.tls_key_path)?;
    let mut listener = TcpListener::bind(coord.listen_addr.parse::<SocketAddr>()?).await?;
    let server = Arc::new(Mutex::new(CoordinatorServer::new(coord.master_key, coord.signing_seed)));
    {
        let mut guard = server.lock().await;
        for ak in &coord.auth_keys {
            let policy = match ak.policy.as_str() {
                "onetime" => AuthKeyPolicy::OneTime,
                _ => AuthKeyPolicy::Reusable,
            };
            guard.coordinator.add_auth_key(&ak.key, policy);
        }
    }
    eprintln!("[coord] listening on {}", listener.local_addr()?);
    loop {
        let mut tls = server_tls_stream(&mut listener, &cert, &key).await?;
        let srv = server.clone();
        tokio::spawn(async move {
            let mut conn = ConnectionState::default();
            loop {
                let (msg_type, body) = match read_envelope(&mut tls).await {
                    Ok(v) => v,
                    Err(_) => break,
                };
                let mut guard = srv.lock().await;
                if guard.handle_message(&mut conn, &mut tls, msg_type, &body).await.is_err() {
                    break;
                }
            }
        });
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cli = Cli::parse();
    match cli.command {
        Some(Command::Pubkey { seed }) => {
            let seed = hex32::decode(&seed)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
            let seed: [u8; 32] = seed
                .try_into()
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad seed"))?;
            let vk = ed25519_dalek::VerifyingKey::from(&ed25519_dalek::SigningKey::from_bytes(&seed));
            println!("{}", hex32::encode_owned(&vk.to_bytes()));
            Ok(())
        }
        None => run_daemon(&PathBuf::from(DEFAULT_CONFIG_PATH)),
        Some(Command::Run { config }) => run_daemon(&config.unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH))),
    }
}

fn run_daemon(path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| std::io::Error::new(e.kind(), format!("config {}: {}", path.display(), e)))?;
    let file: FileConfig = serde_json::from_str(&text)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{:?}", e)))?;

    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(async move {
        if let Some(coord) = file.coord {
            tokio::spawn(async move {
                if let Err(e) = run_coord(coord).await {
                    eprintln!("[coord] fatal: {}", e);
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
            eprintln!("[node] 无 node 角色字段，仅运行 coordinator");
            std::future::pending::<()>().await;
            return Ok(());
        };
        let config = Config {
            coordinator_url,
            auth_key,
            static_key_seed,
            capabilities: file.capabilities,
            announce_routes: file.announce_routes.clone(),
            coord_signing_pubkey,
            ca_cert_path,
            coord: None,
        };
        config.validate().map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("config invalid: {:?}", e),
            )
        })?;
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
        eprintln!(
            "[node] starting (coordinator={}, tun={})",
            config.coordinator_url,
            opts.tun.as_ref().map(|t| t.name.clone()).unwrap_or_else(|| "-".into())
        );
        let node = Node::new(config, opts).await?;
        node.run().await;
        Ok(())
    })
}
