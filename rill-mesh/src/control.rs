use crate::framing;
use landscape_rill_coord::config::CoordConfig;
use landscape_rill_coord::coordinator::Coordinator;
use landscape_rill_core::control::session::{ClientSession, SessionState};
use landscape_rill_core::rate::{RateCounter, RATE_SUMMARY_PERIOD};
use landscape_rill_proto::wire::control::*;
use quick_protobuf::{BytesReader, MessageRead, MessageWrite, Writer};
use std::borrow::Cow;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::error;

pub const PROTOCOL_VERSION: u32 = 2;
pub const CHALLENGE_NONCE_LEN: usize = 16;

/// hops → bytes（每 node_id 4B 大端；avoid quick-protobuf packed fixed32 对齐缺陷）
pub fn hops_bytes(hops: &[u32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(hops.len() * 4);
    for h in hops {
        out.extend_from_slice(&h.to_be_bytes());
    }
    out
}

/// bytes → hops（4B 大端）
pub fn hops_to_vec(hops: &[u8]) -> Vec<u32> {
    let (full, rem) = hops.as_chunks::<4>();
    debug_assert!(rem.is_empty());
    full.iter().map(|c| u32::from_be_bytes(*c)).collect()
}

pub struct MeshLegConfig {
    pub coordinator_host: String,
    pub coordinator_port: u16,
    pub auth_key: String,
    pub static_key: [u8; 32],
    pub capabilities: u32,
    pub announce_routes: Vec<String>,
}

#[derive(Debug)]
pub enum MeshEvent {
    Netmap {
        version: u64,
    },
    Revoked {
        node_id: u32,
    },
    KeyDist {
        to_node_id: u32,
        key: Vec<u8>,
        key_version: u32,
    },
}

pub struct MeshClient {
    session: ClientSession,
    static_key: [u8; 32],
}

impl MeshClient {
    pub fn new(static_key: [u8; 32]) -> Self {
        Self {
            session: ClientSession::new(),
            static_key,
        }
    }

    /// 重连场景：以已注册的 node_id 恢复会话（挑战 tag 计算需要）
    pub fn with_node_id(static_key: [u8; 32], node_id: u32) -> Self {
        let mut client = Self::new(static_key);
        client.session.restore(node_id);
        client
    }

    pub fn static_pubkey(&self) -> [u8; 32] {
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(self.static_key)).to_bytes()
    }

    pub fn state(&self) -> &SessionState {
        self.session.state()
    }

    pub fn session_mut(&mut self) -> &mut ClientSession {
        &mut self.session
    }

    pub fn register_request(&self, config: &MeshLegConfig) -> Vec<u8> {
        let msg = RegisterRequest {
            auth_key: Cow::Borrowed(&config.auth_key),
            static_pubkey: Cow::Owned(self.static_pubkey().to_vec()),
            capabilities: config.capabilities,
            protocol_version: PROTOCOL_VERSION,
            hostname: Cow::Borrowed(""),
            os: Cow::Borrowed(""),
            routes: config
                .announce_routes
                .iter()
                .map(|r| Cow::Borrowed(r.as_str()))
                .collect(),
        };
        envelope_bytes(MsgType::REGISTER, &msg)
    }

    pub fn challenge_ack(&self, challenge: &Challenge<'_>) -> Vec<u8> {
        let node_id = match self.session.state() {
            SessionState::Reconnecting { node_id } => *node_id,
            _ => 0,
        };
        let mut eph_pub = [0u8; 32];
        eph_pub.copy_from_slice(challenge.eph_pub.as_ref());
        let tag = landscape_rill_core::control::challenge::compute_tag(
            &self.static_key,
            &eph_pub,
            challenge.nonce.as_ref(),
            node_id,
        );
        let ack = ChallengeAck {
            node_id,
            tag: Cow::Owned(tag.to_vec()),
        };
        envelope_bytes(MsgType::CHALLENGE_ACK, &ack)
    }

    pub fn heartbeat(&self) -> Vec<u8> {
        envelope_bytes(MsgType::HEARTBEAT, &Heartbeat {})
    }

    /// 路径请求（v1.5，CONTROL_PLANE §3.11）：请求本节点 → dest 的候选路径集
    pub fn path_request(&self, destination_node_id: u32) -> Vec<u8> {
        let msg = PathRequest {
            destination_node_id,
            max_candidates: 4,
        };
        envelope_bytes(MsgType::PATH_REQUEST, &msg)
    }
}

pub fn envelope_bytes<T: MessageWrite>(msg_type: MsgType, msg: &T) -> Vec<u8> {
    let mut body = Vec::new();
    {
        let mut writer = Writer::new(&mut body);
        msg.write_message(&mut writer).unwrap();
    }
    let envelope = Envelope {
        msg_type,
        body: Cow::Owned(body),
    };
    let mut out = Vec::new();
    {
        let mut writer = Writer::new(&mut out);
        envelope.write_message(&mut writer).unwrap();
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeError {
    Decode,
}

impl std::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for EnvelopeError {}

pub fn parse_envelope(body: &[u8]) -> Result<(MsgType, Vec<u8>), EnvelopeError> {
    let owned = EnvelopeOwned::try_from(body.to_vec()).map_err(|_| EnvelopeError::Decode)?;
    Ok((owned.proto().msg_type, owned.proto().body.to_vec()))
}

pub fn envelope_body<T: MessageWrite>(msg: &T) -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut writer = Writer::new(&mut out);
        msg.write_message(&mut writer).unwrap();
    }
    out
}

pub async fn write_msg<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    msg_type: MsgType,
    body: &[u8],
) -> std::io::Result<()> {
    let envelope = Envelope {
        msg_type,
        body: Cow::Borrowed(body),
    };
    let mut out = Vec::new();
    {
        let mut w = Writer::new(&mut out);
        envelope
            .write_message(&mut w)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    }
    framing::write_frame(writer, &out).await
}

pub async fn read_envelope<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> std::io::Result<(MsgType, Vec<u8>)> {
    let body = framing::read_frame(reader).await?;
    parse_envelope(&body)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad envelope"))
}

pub async fn client_tls_stream(
    host: &str,
    port: u16,
    ca_cert_pem: &[u8],
) -> Result<TlsStream<TcpStream>, Box<dyn std::error::Error>> {
    let mut roots = rustls::RootCertStore::empty();
    let certs: Vec<_> =
        rustls_pemfile::certs(&mut std::io::Cursor::new(ca_cert_pem)).collect::<Result<_, _>>()?;
    for cert in certs {
        roots.add(cert)?;
    }
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    // tokio 的 (host, port) 走 getaddrinfo（容器内 compose DNS/公网 DNS 均可解析）
    let tcp = TcpStream::connect((host, port)).await?;
    let server_name = rustls_pki_types::ServerName::try_from(host.to_string())?;
    Ok(connector.connect(server_name, tcp).await?)
}

pub async fn server_tls_stream(
    listener: &mut tokio::net::TcpListener,
    cert_pem: &[u8],
    key_pem: &[u8],
) -> Result<tokio_rustls::server::TlsStream<TcpStream>, Box<dyn std::error::Error>> {
    let certs: Vec<_> =
        rustls_pemfile::certs(&mut std::io::Cursor::new(cert_pem)).collect::<Result<_, _>>()?;
    let key = rustls_pemfile::private_key(&mut std::io::Cursor::new(key_pem))?
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "no key"))?;
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let (tcp, _) = listener.accept().await?;
    Ok(acceptor.accept(tcp).await?)
}

pub fn netmap_push_message(coordinator: &Coordinator) -> NetmapPush<'static> {
    let entries = coordinator
        .netmap_snapshot()
        .into_iter()
        .map(|info| NetmapEntry {
            node_id: info.node_id,
            network_id: info.network_id,
            static_pubkey: Cow::Owned(info.static_pubkey.to_vec()),
            endpoints: info.endpoints.into_iter().map(Cow::Owned).collect(),
            capabilities: info.capabilities,
            routes: info.routes.into_iter().map(Cow::Owned).collect(),
            protocol_version: info.protocol_version,
        })
        .collect();
    NetmapPush {
        version: coordinator.netmap_version(),
        entries,
        relay_list: coordinator
            .relay_list()
            .iter()
            .map(|s| Cow::Owned(s.clone()))
            .collect(),
    }
}

pub struct CoordinatorServer {
    pub coordinator: Coordinator,
    /// 注册拒绝计数（LOGGING §5：周期摘要；run_coord 周期取走打印）
    pub register_rejected: RateCounter,
}

/// 单连接挑战状态（重连认证，CONTROL_PLANE §3.9）
struct ChallengeState {
    eph_priv: [u8; 32],
    nonce: Vec<u8>,
    issued_at: u64,
}

impl ChallengeState {
    fn new() -> Self {
        Self {
            eph_priv: rand::random::<[u8; 32]>(),
            nonce: rand::random::<[u8; 16]>().to_vec(),
            issued_at: unix_seconds(),
        }
    }
}

pub fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn key_dist_message(coordinator: &Coordinator, node_id: u32) -> Option<Vec<u8>> {
    let data = coordinator.key_dist(node_id)?;
    let msg = KeyDist {
        to_node_id: data.to_node_id,
        key: Cow::Owned(data.key.to_vec()),
        key_version: data.key_version,
        broadcast_key: Cow::Owned(data.broadcast_key.to_vec()),
    };
    Some(envelope_body(&msg))
}

impl CoordinatorServer {
    pub fn new(master_key: [u8; 32], signing_seed: [u8; 32]) -> Self {
        Self {
            coordinator: Coordinator::new(master_key, signing_seed),
            register_rejected: RateCounter::new(RATE_SUMMARY_PERIOD),
        }
    }

    /// 管理面库 API（REQ-038，CONTROL_PLANE §3.12）：从配置构造（auth keys + 白名单）；
    /// 配置 storage_path 时打开持久化存储（REQ-037），损坏/不一致 → Err（fail-closed）
    pub fn from_config(
        cfg: &CoordConfig,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let coordinator = match &cfg.storage_path {
            Some(path) => {
                Coordinator::open(std::path::Path::new(path), cfg.master_key, cfg.signing_seed)?
            }
            None => Coordinator::new(cfg.master_key, cfg.signing_seed),
        };
        let mut server = Self {
            coordinator,
            register_rejected: RateCounter::new(RATE_SUMMARY_PERIOD),
        };
        cfg.apply_to(&mut server.coordinator);
        Ok(server)
    }

    /// 管理面库 API（REQ-038）：配置重载（SIGHUP）入口，增量收敛、不中断在途连接
    pub fn apply_config(&mut self, cfg: &CoordConfig) {
        cfg.apply_to(&mut self.coordinator);
    }

    /// 注册成功/挑战通过后：全量 netmap + 逐节点 key_dst + 广播密钥（v1 全量互连）
    async fn push_snapshot<W: AsyncWriteExt + Unpin>(
        &self,
        stream: &mut W,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let push = netmap_push_message(&self.coordinator);
        write_msg(stream, MsgType::NETMAP_PUSH, &envelope_body(&push)).await?;
        let node_ids: Vec<u32> = self
            .coordinator
            .netmap_snapshot()
            .into_iter()
            .map(|n| n.node_id)
            .collect();
        for node_id in node_ids {
            if let Some(body) = key_dist_message(&self.coordinator, node_id) {
                write_msg(stream, MsgType::KEY_DIST, &body).await?;
            }
        }
        if let Some(body) = key_dist_message(&self.coordinator, 0xFFFF_FFFF) {
            write_msg(stream, MsgType::KEY_DIST, &body).await?;
        }
        Ok(())
    }

    pub async fn handle_connection(
        &mut self,
        stream: &mut tokio_rustls::server::TlsStream<TcpStream>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut state = ConnectionState::default();
        loop {
            let (msg_type, body) = read_envelope(stream).await?;
            self.handle_message(&mut state, stream, msg_type, &body)
                .await?;
        }
    }

    /// 单消息处理（连接循环按消息粒度持锁；共享 coordinator 多连接场景由调用方保证互斥）。
    /// ConnectionState 保存单连接状态（注册归属/挑战），由调用方维护。
    pub async fn handle_message(
        &mut self,
        state: &mut ConnectionState,
        stream: &mut tokio_rustls::server::TlsStream<TcpStream>,
        msg_type: MsgType,
        body: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        match msg_type {
            MsgType::REGISTER => {
                let mut reader = BytesReader::from_bytes(body);
                let req = RegisterRequest::from_reader(&mut reader, body)?;
                let mut pubkey = [0u8; 32];
                pubkey.copy_from_slice(req.static_pubkey.as_ref());
                let routes: Vec<String> = if req.routes.is_empty() {
                    req.hostname
                        .as_ref()
                        .split(',')
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                        .collect()
                } else {
                    req.routes.iter().map(|r| r.to_string()).collect()
                };
                match self.coordinator.register(
                    req.auth_key.as_ref(),
                    &pubkey,
                    req.capabilities,
                    routes,
                ) {
                    Ok(data) => {
                        self.coordinator
                            .set_protocol_version(data.node_id, req.protocol_version);
                        let resp = RegisterResponse {
                            node_id: data.node_id,
                            network_id: data.network_id,
                            identity_binding: Cow::Owned(data.identity_binding),
                            leader_redirect: None,
                        };
                        write_msg(stream, MsgType::REGISTER_RESPONSE, &envelope_body(&resp))
                            .await?;
                        state.registered = Some(data.node_id);
                        self.coordinator.heartbeat(data.node_id, unix_seconds());
                        self.push_snapshot(stream).await?;
                        state.challenge = None;
                    }
                    Err(landscape_rill_core::control::registry::RegisterError::InvalidAuthKey) => {
                        // 可能的重连：auth key 失效（一次性已消费）+ 公钥已知 → 挑战认证
                        match self.coordinator.node_id_by_pubkey(&pubkey) {
                            Some(_node_id) => {
                                let ch = ChallengeState::new();
                                let msg = Challenge {
                                    eph_pub: Cow::Owned(
                                        x25519_dalek::PublicKey::from(
                                            &x25519_dalek::StaticSecret::from(ch.eph_priv),
                                        )
                                        .to_bytes()
                                        .to_vec(),
                                    ),
                                    nonce: Cow::Borrowed(&ch.nonce),
                                    issued_at: ch.issued_at,
                                };
                                write_msg(stream, MsgType::CHALLENGE, &envelope_body(&msg)).await?;
                                state.challenge = Some(ch);
                            }
                            None => {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::PermissionDenied,
                                    "unknown pubkey",
                                )
                                .into())
                            }
                        }
                    }
                    Err(e) => {
                        // 逐条输出 → 周期摘要（LOGGING §5；run_coord 打印）
                        self.register_rejected.tick();
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("{:?}", e),
                        )
                        .into());
                    }
                }
            }
            MsgType::CHALLENGE_ACK => {
                let mut reader = BytesReader::from_bytes(body);
                let ack = ChallengeAck::from_reader(&mut reader, body)?;
                let node_id = ack.node_id;
                let Some(entry_pub) = self.coordinator.static_pubkey_of(node_id) else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "unknown node in challenge ack",
                    )
                    .into());
                };
                let Some(ch) = state.challenge.as_ref() else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "unexpected challenge ack",
                    )
                    .into());
                };
                let ok = landscape_rill_core::control::challenge::verify_tag(
                    &entry_pub,
                    &ch.eph_priv,
                    &ch.nonce,
                    node_id,
                    ack.tag.as_ref(),
                ) && landscape_rill_core::control::challenge::within_window(
                    ch.issued_at,
                    unix_seconds(),
                    30,
                );
                if !ok {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "challenge failed",
                    )
                    .into());
                }
                state.registered = Some(node_id);
                self.coordinator.heartbeat(node_id, unix_seconds());
                self.push_snapshot(stream).await?;
                state.challenge = None;
            }
            MsgType::HEARTBEAT => {
                let mut reader = BytesReader::from_bytes(body);
                let _ = Heartbeat::from_reader(&mut reader, body)?;
                if let Some(node_id) = state.registered {
                    self.coordinator.heartbeat(node_id, unix_seconds());
                    // 周期收敛：端点/离线等软状态随心跳广播（v1 无增量推送）
                    self.push_snapshot(stream).await?;
                    // 路径事件推送（v1.5，CONTROL_PLANE §3.11）：PathUpdate/PathWithdraw
                    self.push_path_events(stream, node_id).await?;
                    let lease = Lease {
                        granted: true,
                        expires_at: unix_seconds() + 60,
                    };
                    write_msg(stream, MsgType::LEASE, &envelope_body(&lease)).await?;
                }
            }
            MsgType::PATH_REQUEST => {
                let mut reader = BytesReader::from_bytes(body);
                let req = PathRequest::from_reader(&mut reader, body)?;
                let Some(source) = state.registered else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "path request before registration",
                    )
                    .into());
                };
                let _ = self.coordinator.request_paths(
                    source,
                    req.destination_node_id,
                    req.max_candidates,
                );
                // 响应不下发：路径集事件走心跳推送通道（push_path_events），
                // 与 NETMAP/LEASE 同批次写入——即时写回在并发下不可靠
            }
            MsgType::PATH_PROBE
            | MsgType::PATH_PROBE_RESPONSE
            | MsgType::PATH_UPDATE
            | MsgType::PATH_WITHDRAW => {
                // 节点↔节点 PathProbe 走数据面语义（活性由数据面心跳承担，v1.5）；
                // PathUpdate/PathWithdraw 为 coordinator → 节点单向推送，不收
                let _ = body;
            }
            MsgType::ENDPOINT_REPORT => {
                let mut reader = BytesReader::from_bytes(body);
                let report = EndpointReport::from_reader(&mut reader, body)?;
                if let Some(node_id) = state.registered {
                    let endpoints: Vec<String> =
                        report.endpoints.iter().map(|s| s.to_string()).collect();
                    if !endpoints.is_empty() {
                        self.coordinator.set_endpoints(node_id, endpoints);
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// 心跳推送：该节点（source 身份）的未推送路径事件（PathUpdate/PathWithdraw）
    async fn push_path_events<W: AsyncWriteExt + Unpin>(
        &mut self,
        stream: &mut W,
        source: u32,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let events = self.coordinator.take_path_events(source);
        for event in events {
            match event {
                landscape_rill_coord::path_service::PathEvent::Update {
                    source: src,
                    dest,
                    set,
                } => {
                    let msg = PathUpdate {
                        destination_node_id: dest,
                        candidates: set
                            .candidates
                            .iter()
                            .map(|c| CandidatePath {
                                path_id: c.path_id,
                                path_epoch: c.path_epoch,
                                hops: Cow::Owned(hops_bytes(&c.hops)),
                                expires_at: c.expires_at,
                                key_path: Cow::Owned(
                                    self.coordinator
                                        .key_path_for(c.path_id, c.path_epoch)
                                        .to_vec(),
                                ),
                            })
                            .collect(),
                        path_version: set.version,
                        source_node_id: src,
                    };
                    write_msg(stream, MsgType::PATH_UPDATE, &envelope_body(&msg)).await?;
                }
                landscape_rill_coord::path_service::PathEvent::Withdraw { dest, path_id } => {
                    let msg = PathWithdraw {
                        destination_node_id: dest,
                        path_id,
                        path_version: 0,
                    };
                    write_msg(stream, MsgType::PATH_WITHDRAW, &envelope_body(&msg)).await?;
                }
            }
        }
        Ok(())
    }
}

/// 单连接状态：注册归属 + 重连挑战（由连接循环维护，与 coordinator 互斥解耦）
#[derive(Default)]
pub struct ConnectionState {
    pub registered: Option<u32>,
    challenge: Option<ChallengeState>,
}

// ============================================================================
// 客户端控制会话（runtime 驱动：注册 → 事件循环；断线由调用方重连）
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetmapNode {
    pub node_id: u32,
    pub network_id: u32,
    pub static_pubkey: [u8; 32],
    pub endpoints: Vec<String>,
    pub capabilities: u32,
    pub routes: Vec<String>,
    /// 协议版本（v2 路径能力协商）
    pub protocol_version: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetmapData {
    pub version: u64,
    pub entries: Vec<NetmapNode>,
    pub relay_list: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlEvent {
    Registered {
        node_id: u32,
        network_id: u32,
        identity_binding: Vec<u8>,
    },
    Netmap(NetmapData),
    KeyDist {
        to_node_id: u32,
        key: Vec<u8>,
        key_version: u32,
        broadcast_key: Vec<u8>,
    },
    Lease {
        granted: bool,
        expires_at: u64,
    },
    Challenge {
        ack: Vec<u8>,
    },
    Revoked {
        node_id: u32,
    },
    /// 候选路径集（PathResponse/PathUpdate，v1.5 CONTROL_PLANE §3.11）
    Paths {
        destination_node_id: u32,
        candidates: Vec<PathCandidateMsg>,
        version: u64,
        /// 路径发起方：= 自己时路径可写入发送路径表；否则仅 key_path 授权
        source_node_id: u32,
    },
    /// 路径撤销（PathWithdraw）
    PathWithdrawn {
        destination_node_id: u32,
        path_id: u64,
    },
}

/// 路径候选（control 层消息载体 → runtime 注入 MeshData）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathCandidateMsg {
    pub path_id: u64,
    pub path_epoch: u32,
    pub hops: Vec<u32>,
    pub expires_at: u64,
    pub key_path: Vec<u8>,
}

pub struct ControlSession {
    client: MeshClient,
    stream: TlsStream<TcpStream>,
}

impl ControlSession {
    /// 连接 + 初始注册（一次调用完成 REGISTER 发送；事件随后由 read_event 消费）。
    /// previous_node_id：重连时传上次注册的 node_id（幂等注册/挑战路径）。
    pub async fn connect(
        host: &str,
        port: u16,
        ca_cert_pem: &[u8],
        config: &MeshLegConfig,
        previous_node_id: Option<u32>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let stream = client_tls_stream(host, port, ca_cert_pem).await?;
        let client = match previous_node_id {
            Some(node_id) => MeshClient::with_node_id(config.static_key, node_id),
            None => MeshClient::new(config.static_key),
        };
        let mut session = Self { client, stream };
        session
            .send_envelope(&session.client.register_request(config))
            .await?;
        Ok(session)
    }

    pub fn client(&self) -> &MeshClient {
        &self.client
    }

    pub fn client_mut(&mut self) -> &mut MeshClient {
        &mut self.client
    }

    pub async fn send_envelope(&mut self, envelope: &[u8]) -> std::io::Result<()> {
        framing::write_frame(&mut self.stream, envelope).await
    }

    pub fn heartbeat_envelope(&self) -> Vec<u8> {
        self.client.heartbeat()
    }

    /// 端点上报（数据面 UDP 地址；注册后/地址变化时发送，服务端并入 netmap）
    pub fn endpoint_report_envelope(&self, endpoints: Vec<String>) -> Vec<u8> {
        let msg = EndpointReport {
            endpoints: endpoints.into_iter().map(Cow::Owned).collect(),
        };
        envelope_bytes(MsgType::ENDPOINT_REPORT, &msg)
    }

    /// 读取一个控制面事件（阻塞读；io 错误 = 断线，调用方重连）
    pub async fn read_event(&mut self) -> std::io::Result<ControlEvent> {
        let (msg_type, body) = read_envelope(&mut self.stream).await?;
        match msg_type {
            MsgType::REGISTER_RESPONSE => {
                let resp = RegisterResponseOwned::try_from(body).map_err(decoding_err)?;
                let node_id = resp.proto().node_id;
                let network_id = resp.proto().network_id;
                let identity_binding = resp.proto().identity_binding.to_vec();
                self.client
                    .session_mut()
                    .handle(
                        landscape_rill_core::control::session::SessionEvent::RegisterOk { node_id },
                    )
                    .map_err(io_err)?;
                Ok(ControlEvent::Registered {
                    node_id,
                    network_id,
                    identity_binding,
                })
            }
            MsgType::NETMAP_PUSH => {
                let owned = NetmapPushOwned::try_from(body).map_err(decoding_err)?;
                let entries = owned
                    .proto()
                    .entries
                    .iter()
                    .map(|e| {
                        let mut static_pubkey = [0u8; 32];
                        static_pubkey.copy_from_slice(e.static_pubkey.as_ref());
                        NetmapNode {
                            node_id: e.node_id,
                            network_id: e.network_id,
                            static_pubkey,
                            endpoints: e.endpoints.iter().map(|s| s.to_string()).collect(),
                            capabilities: e.capabilities,
                            routes: e.routes.iter().map(|s| s.to_string()).collect(),
                            protocol_version: e.protocol_version,
                        }
                    })
                    .collect();
                Ok(ControlEvent::Netmap(NetmapData {
                    version: owned.proto().version,
                    entries,
                    relay_list: owned
                        .proto()
                        .relay_list
                        .iter()
                        .map(|s| s.to_string())
                        .collect(),
                }))
            }
            MsgType::KEY_DIST => {
                let owned = KeyDistOwned::try_from(body).map_err(decoding_err)?;
                Ok(ControlEvent::KeyDist {
                    to_node_id: owned.proto().to_node_id,
                    key: owned.proto().key.to_vec(),
                    key_version: owned.proto().key_version,
                    broadcast_key: owned.proto().broadcast_key.to_vec(),
                })
            }
            MsgType::LEASE => {
                let mut reader = BytesReader::from_bytes(&body);
                let lease = Lease::from_reader(&mut reader, &body).map_err(decoding_err)?;
                Ok(ControlEvent::Lease {
                    granted: lease.granted,
                    expires_at: lease.expires_at,
                })
            }
            MsgType::CHALLENGE => {
                let owned = ChallengeOwned::try_from(body).map_err(decoding_err)?;
                let challenge = Challenge {
                    eph_pub: Cow::Borrowed(owned.proto().eph_pub.as_ref()),
                    nonce: Cow::Borrowed(owned.proto().nonce.as_ref()),
                    issued_at: owned.proto().issued_at,
                };
                let ack = self.client.challenge_ack(&challenge);
                Ok(ControlEvent::Challenge { ack })
            }
            MsgType::REVOKE => {
                let mut reader = BytesReader::from_bytes(&body);
                let revoke = Revoke::from_reader(&mut reader, &body).map_err(decoding_err)?;
                Ok(ControlEvent::Revoked {
                    node_id: revoke.node_id,
                })
            }
            MsgType::PATH_RESPONSE | MsgType::PATH_UPDATE => {
                let owned = match PathResponseOwned::try_from(body) {
                    Ok(o) => o,
                    Err(e) => {
                        error!("[node] PATH parse failed: {:?}", e);
                        return Err(decoding_err(e));
                    }
                };
                let candidates = owned
                    .proto()
                    .candidates
                    .iter()
                    .map(|c| PathCandidateMsg {
                        path_id: c.path_id,
                        path_epoch: c.path_epoch,
                        hops: hops_to_vec(&c.hops),
                        expires_at: c.expires_at,
                        key_path: c.key_path.to_vec(),
                    })
                    .collect();
                Ok(ControlEvent::Paths {
                    destination_node_id: owned.proto().destination_node_id,
                    candidates,
                    version: owned.proto().path_version,
                    source_node_id: owned.proto().source_node_id,
                })
            }
            MsgType::PATH_WITHDRAW => {
                let mut reader = BytesReader::from_bytes(&body);
                let w = PathWithdraw::from_reader(&mut reader, &body).map_err(decoding_err)?;
                Ok(ControlEvent::PathWithdrawn {
                    destination_node_id: w.destination_node_id,
                    path_id: w.path_id,
                })
            }
            MsgType::PATH_PROBE | MsgType::PATH_PROBE_RESPONSE => {
                // v1.5：路径活性由数据面心跳承担，PathProbe 消息族协议已定义、运行时未启用
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unexpected path probe on control connection",
                ))
            }
            other => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unexpected control message {:?}", other),
            )),
        }
    }
}

fn decoding_err(e: impl std::fmt::Debug) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{:?}", e))
}

fn io_err(e: landscape_rill_core::control::session::SessionError) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{:?}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use landscape_rill_coord::signer::verify_binding;

    fn ca_pair() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut params = rcgen::CertificateParams::new(vec!["coord.test".into()]).unwrap();
        params
            .subject_alt_names
            .push(rcgen::SanType::IpAddress("127.0.0.1".parse().unwrap()));
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let ca = params.self_signed(&key_pair).unwrap();
        (
            ca.pem().into_bytes(),
            ca.pem().into_bytes(),
            key_pair.serialize_pem().into_bytes(),
        )
    }

    #[tokio::test]
    async fn register_over_tls_loopback() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (ca_cert, cert, key) = ca_pair();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let master = [0x11; 32];
        let seed = [0x22; 32];
        let ak_loop = landscape_rill_coord::config::generate_auth_key("lab", 3600).unwrap();
        let ak_server = ak_loop.clone();
        let server = tokio::spawn(async move {
            let mut listener = listener;
            let mut tls = server_tls_stream(&mut listener, &cert, &key).await.unwrap();
            let mut server = CoordinatorServer::new(master, seed);
            server.coordinator.add_auth_key(
                &ak_server,
                landscape_rill_core::control::registry::AuthKeyPolicy::OneTime,
            );
            server.handle_connection(&mut tls).await.unwrap();
        });

        let host = addr.ip().to_string();
        let mut tls = client_tls_stream(&host, addr.port(), &ca_cert)
            .await
            .unwrap();
        let client = MeshClient::new([0x33; 32]);
        let config = MeshLegConfig {
            coordinator_host: host,
            coordinator_port: addr.port(),
            auth_key: ak_loop.clone(),
            static_key: [0x33; 32],
            capabilities: 0x01,
            announce_routes: vec![],
        };
        let reg = client.register_request(&config);
        crate::framing::write_frame(&mut tls, &reg).await.unwrap();
        let (mt, body) = read_envelope(&mut tls).await.unwrap();
        assert_eq!(mt, MsgType::REGISTER_RESPONSE);
        assert_eq!(mt, MsgType::REGISTER_RESPONSE);
        let mut reader = BytesReader::from_bytes(&body);
        let resp = RegisterResponse::from_reader(&mut reader, &body).unwrap();
        assert_eq!(resp.node_id, 1);
        assert_eq!(resp.network_id, 1);
        let (mt2, body2) =
            tokio::time::timeout(std::time::Duration::from_secs(2), read_envelope(&mut tls))
                .await
                .expect("timeout waiting for second message")
                .unwrap();
        assert_eq!(mt2, MsgType::NETMAP_PUSH);
        let mut reader2 = BytesReader::from_bytes(&body2);
        let push = NetmapPush::from_reader(&mut reader2, &body2).unwrap();
        assert_eq!(push.entries.len(), 1);
        assert_eq!(push.entries[0].node_id, 1);
        drop(server);
    }

    #[test]
    fn envelope_roundtrip() {
        let msg = RegisterRequest {
            auth_key: Cow::Borrowed("ak"),
            static_pubkey: Cow::Owned(vec![0x42; 32]),
            capabilities: 0x01,
            protocol_version: PROTOCOL_VERSION,
            hostname: Cow::Borrowed(""),
            os: Cow::Borrowed(""),
            routes: vec![],
        };
        let bytes = envelope_bytes(MsgType::REGISTER, &msg);
        let (mt, inner) = parse_envelope(&bytes).unwrap();
        assert_eq!(mt, MsgType::REGISTER);
        let mut reader = BytesReader::from_bytes(&inner);
        let parsed = RegisterRequest::from_reader(&mut reader, &inner).unwrap();
        assert_eq!(parsed.auth_key, "ak");
        assert_eq!(parsed.capabilities, 0x01);
    }

    #[tokio::test]
    async fn tls_echo_two_frames() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut params = rcgen::CertificateParams::new(vec!["coord.test".into()]).unwrap();
        params
            .subject_alt_names
            .push(rcgen::SanType::IpAddress("127.0.0.1".parse().unwrap()));
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let ca = params.self_signed(&key_pair).unwrap();
        let cert = ca.pem().into_bytes();
        let key = key_pair.serialize_pem().into_bytes();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cert2 = cert.clone();
        let server = tokio::spawn(async move {
            let mut listener = listener;
            let mut tls = server_tls_stream(&mut listener, &cert2, &key)
                .await
                .unwrap();
            let f1 = framing::read_frame(&mut tls).await.unwrap();
            let _ = f1;
            let reply1 = b"response-one".to_vec();
            let reply2 = b"push-with-larger-body".to_vec();
            framing::write_frame(&mut tls, &reply1).await.unwrap();
            framing::write_frame(&mut tls, &reply2).await.unwrap();
        });
        let host = addr.ip().to_string();
        let mut tls = client_tls_stream(&host, addr.port(), &cert).await.unwrap();
        framing::write_frame(&mut tls, b"hello".as_slice())
            .await
            .unwrap();
        let r1 = framing::read_frame(&mut tls).await.unwrap();
        let r2 = framing::read_frame(&mut tls).await.unwrap();
        drop(server);
        assert_eq!(r1, b"response-one");
        assert_eq!(r2, b"push-with-larger-body");
    }

    #[test]
    fn binding_verifies_with_ed25519() {
        use landscape_rill_core::control::registry::IdentitySigner;
        let signer = landscape_rill_coord::signer::Ed25519Signer::new([0x99; 32]);
        let msg = landscape_rill_core::control::registry::binding_message(7, &[0x42; 32]);
        let sig = signer.sign(&msg);
        assert!(verify_binding(&signer.verifier(), 7, &[0x42; 32], &sig));
    }
}
