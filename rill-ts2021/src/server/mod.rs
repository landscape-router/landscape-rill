//! ts2021 自研服务端（REQ-068，TS2021_LEG §4）：headscale 替换。
//! 与 mesh coordinator 同进程可共存、协议独立（ARCHITECTURE §6 浅结合）；
//! v1 内存态、auth key 准入（lrk）、子网路由白名单自动审批、内嵌 DERP。
//!
//! 连接路由（单 TLS 监听，HTTP/1.1 首请求分流）：
//! - `GET /key`：Noise 公钥预取（JSON，headscale 小写字段名）
//! - `POST /ts2021`：controlhttp 升级 → Noise IK 响应侧 → early payload → h2 控制面
//! - `GET /derp`：DERP 升级 → 内嵌 DERP 会话
//!
//! 本模块面向任意 IO（测试经裸 TCP 直驱）；TLS 终结在 `tls_accept`（rilld 边缘调用）。

pub mod control;
pub mod derp;
pub mod netmap;
pub mod registry;
#[cfg(test)]
mod tests;

pub use netmap::NetmapCtx;
pub use registry::{NodeEntry, Registry, RoutesWhitelist};

use crate::base64;
use crate::controlbase::{NoiseStream, ServerHandshake};
use netmap::NetmapCtx as Ctx;
use serde::Deserialize;
use std::io;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};

/// DERP 问候 magic（与客户端 derp.rs 同源："DERP🔑"）
const DERP_MAGIC: [u8; 8] = [0x44, 0x45, 0x52, 0x50, 0xf0, 0x9f, 0x94, 0x91];

/// 服务端配置（rilld `ts2021_server` 段 serde 形态；加载即校验 fail-closed）
#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// lrk network 段（auth key 准入比对）
    pub network: String,
    /// UserProfiles LoginName（v1 单用户；缺省 "ts"）
    #[serde(default = "default_user")]
    pub user: String,
    /// DERPMap HostName（客户端回连地址：容器名/域名）+ Domain 字段
    pub hostname: String,
    pub listen_addr: String,
    pub tls_cert_path: String,
    pub tls_key_path: String,
    /// Noise 控制面私钥（hex 文件，缺省生成——重启稳定，客户端缓存公钥）
    pub noise_key_path: String,
    /// DERP 私钥（hex 文件，缺省生成）
    pub derp_key_path: String,
    #[serde(default)]
    pub auth_keys: Vec<String>,
    /// 子网路由审批白名单（公告前缀 covered-by 即批准；默认路由不在此列）
    #[serde(default)]
    pub routes_whitelist: Vec<String>,
    /// exit node 广播（0.0.0.0/0 + ::/0）审批开关
    #[serde(default)]
    pub allow_exit: bool,
    #[serde(default = "default_derp_region")]
    pub derp_region: u16,
}

fn default_user() -> String {
    "ts".into()
}

fn default_derp_region() -> u16 {
    1
}

impl ServerConfig {
    /// 加载即校验（fail-closed）：监听地址可解析、白名单前缀合法、
    /// auth key 可按 lrk 解析、DERPPort 从监听端口派生
    pub fn validate(&self) -> Result<(), String> {
        self.listen_addr
            .parse::<std::net::SocketAddr>()
            .map_err(|e| format!("invalid ts2021_server.listen_addr: {e}"))?;
        if self.hostname.is_empty() {
            return Err("ts2021_server.hostname is empty".into());
        }
        RoutesWhitelist::parse(&self.routes_whitelist, self.allow_exit)?;
        for k in &self.auth_keys {
            let body = k
                .strip_prefix("lrk-")
                .ok_or_else(|| format!("ts2021_server.auth_keys: not an lrk key: {k}"))?;
            let (network, tail) = body
                .split_once('-')
                .ok_or_else(|| format!("ts2021_server.auth_keys: malformed: {k}"))?;
            if network != self.network {
                return Err(format!(
                    "ts2021_server.auth_keys: network '{network}' != configured '{}'",
                    self.network
                ));
            }
            let expiry = tail
                .split_once('-')
                .and_then(|(e, _)| e.parse::<u64>().ok())
                .ok_or_else(|| format!("ts2021_server.auth_keys: malformed expiry: {k}"))?;
            if expiry != 0
                && std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() > expiry)
                    .unwrap_or(false)
            {
                warn!("[ts2021-server] configured auth key already expired (ignored): {k}");
            }
        }
        Ok(())
    }

    /// DERPMap DERPPort = 控制面监听端口（同 TLS 监听路径复用）
    pub fn derp_port(&self) -> u16 {
        self.listen_addr
            .parse::<std::net::SocketAddr>()
            .map(|a| a.port())
            .unwrap_or(8443)
    }
}

/// 服务端共享状态（连接间共享；注册表 StdMutex 锁内无 await）
pub struct Ts2021Server {
    pub registry: Mutex<Registry>,
    pub ctx: NetmapCtx,
    pub noise_priv: [u8; 32],
    pub derp_priv: crypto_box::SecretKey,
    pub derp_pub: [u8; 32],
    pub derp_hub: derp::DerpHub,
}

impl Ts2021Server {
    pub fn from_config(cfg: &ServerConfig) -> Result<Self, String> {
        cfg.validate()?;
        let noise_priv = load_or_create_key(&cfg.noise_key_path, "noise")?;
        let derp_priv_bytes = load_or_create_key(&cfg.derp_key_path, "derp")?;
        let derp_priv = crypto_box::SecretKey::from(derp_priv_bytes);
        let derp_pub = *crypto_box::PublicKey::from(&derp_priv).as_bytes();
        let whitelist = RoutesWhitelist::parse(&cfg.routes_whitelist, cfg.allow_exit)?;
        Ok(Self {
            registry: Mutex::new(Registry::new(cfg.auth_keys.clone(), whitelist)),
            ctx: Ctx {
                user: cfg.user.clone(),
                dns_domain: cfg.network.clone(),
                domain: cfg.hostname.clone(),
                derp_region: cfg.derp_region,
                derp_hostname: cfg.hostname.clone(),
                derp_port: cfg.derp_port(),
            },
            noise_priv,
            derp_priv,
            derp_pub,
            derp_hub: Arc::new(Mutex::new(std::collections::HashMap::new())),
        })
    }

    /// Noise 控制面公钥（/key 响应；与 snow 握手同一 x25519 曲线）
    pub fn noise_pub(&self) -> [u8; 32] {
        *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(self.noise_priv))
            .as_bytes()
    }
}

/// hex 私钥持久化（文件存在即读，否则生成落盘 0600——重启稳定，机器/节点侧同源）
fn load_or_create_key(path: &str, label: &str) -> Result<[u8; 32], String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    match std::fs::read_to_string(path) {
        Ok(s) => {
            let hex = s.trim();
            if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(format!("{label} key file corrupt: {path}"));
            }
            let mut k = [0u8; 32];
            for (i, pair) in hex.as_bytes().chunks(2).enumerate() {
                let hi = (pair[0] as char).to_digit(16).ok_or("bad hex")? as u8;
                let lo = (pair[1] as char).to_digit(16).ok_or("bad hex")? as u8;
                k[i] = hi << 4 | lo;
            }
            Ok(k)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let (privk, _) = crate::ts2021::generate_keypair().map_err(|e| e.to_string())?;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .map_err(|e| format!("create {label} key: {e}"))?;
            f.write_all(crate::tailcfg::hex(&privk).as_bytes())
                .map_err(|e| format!("write {label} key: {e}"))?;
            Ok(privk)
        }
        Err(e) => Err(format!("read {label} key: {e}")),
    }
}

/// TLS acceptor（自签/CA 证书；官方客户端无跳过校验开关，证书须有效）
pub fn tls_acceptor(cert_pem: &[u8], key_pem: &[u8]) -> Result<TlsAcceptor, String> {
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::{CertificateDer, PrivateKeyDer};
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<Result<_, _>>()
        .map_err(|e| format!("parse tls cert: {e}"))?;
    let key = PrivateKeyDer::pem_slice_iter(key_pem)
        .next()
        .transpose()
        .map_err(|e| format!("parse tls key: {e}"))?
        .ok_or("no private key in pem")?;
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("tls config: {e}"))?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// 单连接服务（任意 IO；TLS 已由调用方终结）
pub async fn serve_connection<IO>(mut io: IO, server: Arc<Ts2021Server>)
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let head = match read_http_head(&mut io).await {
        Ok(h) => h,
        Err(_) => return,
    };
    let (method, path, headers) = match parse_head(&head) {
        Some(v) => v,
        None => {
            let _ = write_simple_response(&mut io, 400, "bad request").await;
            return;
        }
    };
    let path = path.split('?').next().unwrap_or("").to_owned();
    let header = |name: &str| {
        headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    };
    match (method.as_str(), path.as_str()) {
        ("GET", "/key") => {
            let body = netmap::key_response(&server.noise_pub());
            let _ = write_json_response(&mut io, &body).await;
        }
        ("POST", "/ts2021") => {
            if header("upgrade").map(|v| v.to_ascii_lowercase()).as_deref()
                != Some(crate::controlhttp::UPGRADE_VALUE)
            {
                let _ = write_simple_response(&mut io, 400, "missing upgrade header").await;
                return;
            }
            let Some(init) = header("x-tailscale-handshake")
                .and_then(|v| base64::decode(v).ok())
                .filter(|b| b.len() == crate::controlbase::INITIATION_FRAME_LEN)
            else {
                let _ = write_simple_response(&mut io, 400, "bad handshake header").await;
                return;
            };
            // 101 → msg2 → early payload → h2 控制面（同一 TLS 流复用）
            let switch = format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: {}\r\nConnection: upgrade\r\n\r\n",
                crate::controlhttp::UPGRADE_VALUE
            );
            if io.write_all(switch.as_bytes()).await.is_err() {
                return;
            }
            let (resp, session, machine) =
                match ServerHandshake::new(&server.noise_priv).respond(&init) {
                    Ok(v) => v,
                    Err(e) => {
                        warn!("[ts2021-server] noise handshake failed: {e:?}");
                        return;
                    }
                };
            // msg2 是未加密 Noise 帧，必须裸写；封进 record 会让客户端帧头解析失步
            if io.write_all(&resp).await.is_err() {
                return;
            }
            let mut stream = NoiseStream::new(io, session);
            let challenge = rand::random::<[u8; 32]>();
            if stream
                .write_all(&netmap::early_payload(&challenge))
                .await
                .is_err()
            {
                return;
            }
            info!(
                "[ts2021-server] noise session established: machine={}",
                crate::tailcfg::hex(&machine)
            );
            let _ = control::serve_control(stream, server, machine).await;
        }
        ("GET", "/derp") => {
            if header("upgrade").map(|v| v.to_ascii_lowercase()).as_deref() != Some("derp") {
                let _ = write_simple_response(&mut io, 400, "missing derp upgrade").await;
                return;
            }
            let switch =
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n";
            if io.write_all(switch.as_bytes()).await.is_err() {
                return;
            }
            derp::serve_derp(io, server).await;
        }
        _ => {
            let _ = write_simple_response(&mut io, 404, "not found").await;
        }
    }
}

type Head = (String, String, Vec<(String, String)>);

/// 解析请求头块（方法/路径/小写头域；只取首个请求）
fn parse_head(head: &str) -> Option<Head> {
    let mut lines = head.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_owned();
    let path = parts.next()?.to_owned();
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (k, v) = line.split_once(':')?;
        headers.push((k.trim().to_ascii_lowercase(), v.trim().to_owned()));
    }
    Some((method, path, headers))
}

async fn read_http_head<IO>(io: &mut IO) -> io::Result<String>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        io.read_exact(&mut byte).await?;
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            return Ok(String::from_utf8_lossy(&head).into_owned());
        }
        if head.len() > 16 * 1024 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "head too large"));
        }
    }
}

async fn write_json_response<IO>(io: &mut IO, body: &[u8]) -> io::Result<()>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    io.write_all(head.as_bytes()).await?;
    io.write_all(body).await?;
    io.flush().await
}

async fn write_simple_response<IO>(io: &mut IO, status: u16, msg: &str) -> io::Result<()>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        _ => "Error",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{msg}",
        msg.len()
    );
    io.write_all(head.as_bytes()).await?;
    io.flush().await
}
