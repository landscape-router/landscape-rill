//! 控制面服务端（coordinator 线格式胶水）：TLS accept + 信封分派 + 快照/路径推送

use crate::control::codec::{envelope_body, read_envelope, write_msg};
use crate::control::BoxResult;
use landscape_rill_coord::config::CoordConfig;
use landscape_rill_coord::coordinator::Coordinator;
use landscape_rill_core::rate::{RateCounter, SourceRateLimiter, TokenBucket, RATE_SUMMARY_PERIOD};
use landscape_rill_proto::wire::control::*;
use quick_protobuf::{BytesReader, MessageRead};
use std::borrow::Cow;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

/// 连接级消息限速（REQ-047，SEC-19 速率维度）：每 TLS 连接令牌桶，
/// 桶空 → 断连（复用单连接隔离语义，其他连接不受影响）。
/// 正常负载 ~0.1 msg/s（心跳 10s + 快照推送），200 倍余量
pub const CONN_MSG_RATE_PER_SEC: f64 = 20.0;
pub const CONN_MSG_CAPACITY: u32 = 40;
/// Register 准入限速（REQ-047，SEC-20）：per-源 IP 令牌桶（注册是重操作：
/// node_id 分配 + redb 快照整写，防可复用 key + 不同公钥风暴放大）
pub const REGISTER_RATE_PER_SEC: f64 = 0.5;
pub const REGISTER_CAPACITY: u32 = 5;
/// auth key 验证失败递增锁定：连续失败达阈值 → 锁定时长 30s×2^n（封顶 1h），
/// 成功注册清零；已知 pubkey 的挑战认证不计失败（合法重连路径）
pub const REGISTER_LOCKOUT_FAILS: u32 = 5;
pub const REGISTER_LOCKOUT_BASE: Duration = Duration::from_secs(30);
pub const REGISTER_LOCKOUT_MAX: Duration = Duration::from_secs(3600);
/// 心跳最小间隔（REQ-047）：更近的心跳直接忽略（零成本——不更新 last_seen、
/// 不推快照、不回 LEASE），租约/离线判定语义不变；默认 = 心跳间隔/2
pub const HEARTBEAT_MIN_INTERVAL: Duration = Duration::from_secs(5);

/// 单连接挑战状态（重连认证，CONTROL_PLANE §3.9）
struct ChallengeState {
    eph_priv: [u8; 32],
    nonce: Vec<u8>,
    issued_at: u64,
    /// 挑战绑定的身份（REQ-057）：发起时由触发 REGISTER 的 pubkey 解析——
    /// 验证不信任 ACK 自报 node_id，以服务端存储为准（CP-02）
    node_id: u32,
    pubkey: [u8; 32],
}

impl ChallengeState {
    fn new(node_id: u32, pubkey: [u8; 32]) -> Self {
        Self {
            eph_priv: rand::random::<[u8; 32]>(),
            nonce: rand::random::<[u8; 16]>().to_vec(),
            issued_at: unix_seconds(),
            node_id,
            pubkey,
        }
    }
}

pub fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 网络隔离（SEC-21/CTL-09）：只推指定网络的条目与 relay 列表
pub fn netmap_push_message(coordinator: &Coordinator, network_id: u32) -> NetmapPush<'static> {
    let entries = coordinator
        .netmap_snapshot(network_id)
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
            .relay_list_for(network_id)
            .iter()
            .map(|s| Cow::Owned(s.clone()))
            .collect(),
    }
}

fn key_dist_message(coordinator: &Coordinator, node_id: u32) -> Option<Vec<u8>> {
    let data = coordinator.key_dist(node_id)?;
    let msg = KeyDist {
        to_node_id: data.to_node_id,
        key: Cow::Owned(data.key.to_vec()),
        key_version: data.key_version,
        // 空 bytes = 未 opt-in（REQ-035，CONTROL_PLANE §3.3 按需下发）
        broadcast_key: data
            .broadcast_key
            .map(|k| Cow::Owned(k.to_vec()))
            .unwrap_or(Cow::Borrowed(&[])),
    };
    Some(envelope_body(&msg))
}

pub struct CoordinatorServer {
    pub coordinator: Coordinator,
    /// 注册拒绝计数（LOGGING §5：周期摘要；run_coord 周期取走打印）
    pub register_rejected: RateCounter,
    /// 控制面限速/锁定触发计数（LOGGING §5；run_coord 周期取走打印，SEC-20 证据）
    pub rate_limited: RateCounter,
    /// Register 准入 per-源 IP 限速（REQ-047）；测试可调（localhost 共源场景放大）
    pub register_limiter: SourceRateLimiter,
    /// Register 连续失败锁定（REQ-047）：源 IP → (连续失败数, 锁定截止)
    pub(crate) register_lockout: HashMap<IpAddr, (u32, Instant)>,
    /// 心跳最小间隔（REQ-047，超频忽略）；测试可调（主机测试 300ms 心跳泵）
    pub heartbeat_min_interval: Duration,
    /// e2e 故障注入（REQ-057）：武装后丢弃首个 REGISTER_RESPONSE——注册已
    /// 消费、响应不写出并断连（ack 丢失模拟）；仅 run_coord 的 env 开关设置
    pub(crate) drop_first_register_response: bool,
}

impl CoordinatorServer {
    /// 武装 e2e 注入（REQ-057）：丢弃下一个成功的 REGISTER_RESPONSE
    pub fn arm_drop_first_register_response(&mut self) {
        self.drop_first_register_response = true;
    }
    fn default_limiter() -> SourceRateLimiter {
        SourceRateLimiter::new(REGISTER_RATE_PER_SEC, REGISTER_CAPACITY)
    }

    /// Register 失败锁定判定（REQ-047/SEC-20）：锁定期间一律拒绝（含挑战路径——
    /// 严格优先，NAT 共源受害节点靠锁过期 + 重连退避恢复）
    pub(crate) fn register_locked(&self, ip: IpAddr, now: Instant) -> bool {
        self.register_lockout
            .get(&ip)
            .is_some_and(|(_, until)| now < *until)
    }

    /// Register 失败记账：连续失败达阈值 → 指数锁定（30s×2^n 封顶 1h）
    pub(crate) fn note_register_failure(&mut self, ip: IpAddr, now: Instant) {
        let fails = self
            .register_lockout
            .get(&ip)
            .map_or(1u32, |(f, _)| f.saturating_add(1));
        let until = if fails >= REGISTER_LOCKOUT_FAILS {
            let shift = (fails - REGISTER_LOCKOUT_FAILS).min(7);
            now + (REGISTER_LOCKOUT_BASE * (1u32 << shift)).min(REGISTER_LOCKOUT_MAX)
        } else {
            now // 未达阈值：无锁定（截止 = 当前时刻）
        };
        self.register_lockout.insert(ip, (fails, until));
    }

    pub fn new(master_key: [u8; 32], signing_seed: [u8; 32]) -> Self {
        Self {
            coordinator: Coordinator::new(signing_seed),
            register_rejected: RateCounter::new(RATE_SUMMARY_PERIOD),
            rate_limited: RateCounter::new(RATE_SUMMARY_PERIOD),
            register_limiter: Self::default_limiter(),
            register_lockout: HashMap::new(),
            heartbeat_min_interval: HEARTBEAT_MIN_INTERVAL,
            drop_first_register_response: false,
        }
        .with_network("lab", master_key)
    }

    /// 注册网络域（多网络；网络名 → fnv1a network_id，CONTROL_PLANE §1.5）
    pub fn with_network(mut self, name: &str, master_key: [u8; 32]) -> Self {
        self.coordinator.add_network(name, master_key);
        self
    }

    /// 管理面库 API（REQ-038，CONTROL_PLANE §3.12）：从配置构造（网络域 + auth keys + 白名单）；
    /// 配置 storage_path 时打开持久化存储（REQ-037），损坏/不一致 → Err（fail-closed）
    pub fn from_config(cfg: &CoordConfig) -> BoxResult<Self> {
        let networks: Vec<(String, [u8; 32])> = cfg
            .networks
            .iter()
            .map(|n| (n.name.clone(), n.master_key))
            .collect();
        let coordinator = match &cfg.storage_path {
            Some(path) => {
                Coordinator::open(std::path::Path::new(path), &networks, cfg.signing_seed)?
            }
            None => {
                let mut coord = Coordinator::new(cfg.signing_seed);
                for (name, key) in &networks {
                    coord.add_network(name, *key);
                }
                coord
            }
        };
        let mut server = Self {
            coordinator,
            register_rejected: RateCounter::new(RATE_SUMMARY_PERIOD),
            rate_limited: RateCounter::new(RATE_SUMMARY_PERIOD),
            register_limiter: Self::default_limiter(),
            register_lockout: HashMap::new(),
            heartbeat_min_interval: HEARTBEAT_MIN_INTERVAL,
            drop_first_register_response: false,
        };
        cfg.apply_to(&mut server.coordinator);
        Ok(server)
    }

    /// 管理面库 API（REQ-038）：配置重载（SIGHUP）入口，增量收敛、不中断在途连接
    pub fn apply_config(&mut self, cfg: &CoordConfig) {
        cfg.apply_to(&mut self.coordinator);
    }

    /// 注册成功/挑战通过后：全量 netmap + 逐节点 key_dst + 广播密钥（v1 全量互连）。
    /// 按注册节点所属网络隔离（SEC-21/CTL-09）。
    async fn push_snapshot<W: AsyncWriteExt + Unpin>(
        &self,
        stream: &mut W,
        network_id: u32,
    ) -> BoxResult<()> {
        let push = netmap_push_message(&self.coordinator, network_id);
        write_msg(stream, MsgType::NETMAP_PUSH, &envelope_body(&push)).await?;
        let node_ids: Vec<u32> = self
            .coordinator
            .netmap_snapshot(network_id)
            .into_iter()
            .map(|n| n.node_id)
            .collect();
        for node_id in node_ids {
            if let Some(body) = key_dist_message(&self.coordinator, node_id) {
                write_msg(stream, MsgType::KEY_DIST, &body).await?;
            }
        }
        Ok(())
    }

    pub async fn handle_connection(
        &mut self,
        stream: &mut tokio_rustls::server::TlsStream<TcpStream>,
    ) -> BoxResult<()> {
        let mut state = ConnectionState::default();
        loop {
            let (msg_type, body) = read_envelope(stream).await?;
            self.handle_message(&mut state, stream, msg_type, &body)
                .await?;
        }
    }

    /// 单消息处理（连接循环按消息粒度持锁；共享 coordinator 多连接场景由调用方保证互斥）。
    /// ConnectionState 保存单连接状态（注册归属/挑战/连接级限速），由调用方维护。
    pub async fn handle_message(
        &mut self,
        state: &mut ConnectionState,
        stream: &mut tokio_rustls::server::TlsStream<TcpStream>,
        msg_type: MsgType,
        body: &[u8],
    ) -> BoxResult<()> {
        // 连接级限速（REQ-047，SEC-19 速率维度）：桶空 → 断连该连接（隔离不扩散）
        if !state.msg_bucket.take() {
            self.rate_limited.tick();
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "connection message rate exceeded",
            )
            .into());
        }
        let peer_ip = stream.get_ref().0.peer_addr().ok().map(|a| a.ip());
        match msg_type {
            MsgType::REGISTER => {
                // 准入闸门（REQ-047/SEC-20）：锁定优先，其次 per-源 IP 限速
                if let Some(ip) = peer_ip {
                    if self.register_locked(ip, Instant::now()) {
                        self.rate_limited.tick();
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::PermissionDenied,
                            "register locked (repeated auth key failures)",
                        )
                        .into());
                    }
                    if !self.register_limiter.allow(ip) {
                        self.rate_limited.tick();
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::PermissionDenied,
                            "register rate limited",
                        )
                        .into());
                    }
                }
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
                        if let Some(ip) = peer_ip {
                            self.register_lockout.remove(&ip);
                        }
                        self.coordinator
                            .set_protocol_version(data.node_id, req.protocol_version);
                        // e2e 故障注入（REQ-057）：注册已消费、响应丢弃并断连——
                        // 客户端须走退避重连 + 挑战恢复（ack 丢失模拟）
                        if self.drop_first_register_response {
                            self.drop_first_register_response = false;
                            tracing::warn!(
                                "[coord] e2e injection: first REGISTER_RESPONSE dropped"
                            );
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::ConnectionAborted,
                                "e2e: first register response dropped",
                            )
                            .into());
                        }
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
                        self.push_snapshot(
                            stream,
                            self.coordinator.network_id_of(data.node_id).unwrap_or(0),
                        )
                        .await?;
                        state.challenge = None;
                    }
                    Err(landscape_rill_core::control::registry::RegisterError::InvalidAuthKey) => {
                        // 可能的重连/注册响应丢失恢复：auth key 失效（一次性已消费）
                        // + 公钥已知 → 挑战认证（合法恢复路径，不计失败锁定；
                        // 锁定闸门在其之前已拦截）
                        match self.coordinator.node_id_by_pubkey(&pubkey) {
                            Some(node_id) => {
                                let ch = ChallengeState::new(node_id, pubkey);
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
                                    node_id,
                                };
                                write_msg(stream, MsgType::CHALLENGE, &envelope_body(&msg)).await?;
                                state.challenge = Some(ch);
                            }
                            None => {
                                if let Some(ip) = peer_ip {
                                    self.note_register_failure(ip, Instant::now());
                                }
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::PermissionDenied,
                                    "unknown pubkey",
                                )
                                .into());
                            }
                        }
                    }
                    Err(e) => {
                        // 逐条输出 → 周期摘要（LOGGING §5；run_coord 打印）
                        if let Some(ip) = peer_ip {
                            self.note_register_failure(ip, Instant::now());
                        }
                        self.register_rejected.tick();
                        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e).into());
                    }
                }
            }
            MsgType::CHALLENGE_ACK => {
                let mut reader = BytesReader::from_bytes(body);
                let ack = ChallengeAck::from_reader(&mut reader, body)?;
                let Some(ch) = state.challenge.as_ref() else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "unexpected challenge ack",
                    )
                    .into());
                };
                // 身份以挑战绑定的存储状态为准（REQ-057）：node_id 来自发起时
                // pubkey 解析，不信任 ACK 自报；条目须仍存在且 pubkey 一致
                // （吊销/重注册后旧挑战失效）
                let node_id = ch.node_id;
                let Some(entry_pub) = self.coordinator.static_pubkey_of(node_id) else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "unknown node in challenge ack",
                    )
                    .into());
                };
                if entry_pub != ch.pubkey {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "challenge pubkey mismatch",
                    )
                    .into());
                }
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
                tracing::info!("[coord] challenge ok: node_id={node_id}");
                let network_id = self.coordinator.network_id_of(node_id).unwrap_or(0);
                // 补发 REGISTER_RESPONSE（REQ-057）：注册响应丢失的客户端（Fresh
                // 态）走既有注册处理链完成完整初始化（handshake ctx 等）；
                // 重连客户端对同一 node_id 幂等。条目校验刚通过，binding 缺失
                // 属不变量破坏——fail-closed 而非空绑定静默降级
                let Some(identity_binding) = self.coordinator.identity_binding_of(node_id) else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "challenge entry binding missing",
                    )
                    .into());
                };
                let resp = RegisterResponse {
                    node_id,
                    network_id,
                    identity_binding: Cow::Owned(identity_binding),
                    leader_redirect: None,
                };
                write_msg(stream, MsgType::REGISTER_RESPONSE, &envelope_body(&resp)).await?;
                self.push_snapshot(stream, network_id).await?;
                state.challenge = None;
            }
            MsgType::HEARTBEAT => {
                let mut reader = BytesReader::from_bytes(body);
                let _ = Heartbeat::from_reader(&mut reader, body)?;
                if let Some(node_id) = state.registered {
                    // 超频忽略（REQ-047）：间隔不足即丢弃——不更新 last_seen、
                    // 不推快照、不回 LEASE（零成本），租约/离线判定语义不变
                    let now = Instant::now();
                    if state
                        .last_heartbeat
                        .is_some_and(|last| now.duration_since(last) < self.heartbeat_min_interval)
                    {
                        return Ok(());
                    }
                    state.last_heartbeat = Some(now);
                    self.coordinator.heartbeat(node_id, unix_seconds());
                    // 周期收敛：端点/离线等软状态随心跳广播（v1 无增量推送）
                    let network_id = self.coordinator.network_id_of(node_id).unwrap_or(0);
                    self.push_snapshot(stream, network_id).await?;
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
    ) -> BoxResult<()> {
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
                                hops: Cow::Owned(crate::control::hops_bytes(&c.hops)),
                                expires_at: c.expires_at,
                                key_path: Cow::Owned(
                                    self.coordinator
                                        .key_path_for(src, c.path_id, c.path_epoch)
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

/// 单连接状态：注册归属 + 重连挑战 + 连接级限速（由连接循环维护，与 coordinator 互斥解耦）
pub struct ConnectionState {
    pub registered: Option<u32>,
    challenge: Option<ChallengeState>,
    /// 连接级消息令牌桶（REQ-047）：桶空 → 断连
    pub(crate) msg_bucket: TokenBucket,
    /// 上次接受的心跳时刻（超频忽略判定，REQ-047）
    pub(crate) last_heartbeat: Option<Instant>,
}

impl Default for ConnectionState {
    fn default() -> Self {
        Self {
            registered: None,
            challenge: None,
            msg_bucket: TokenBucket::new(CONN_MSG_RATE_PER_SEC, CONN_MSG_CAPACITY),
            last_heartbeat: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::client::{MeshClient, MeshLegConfig};
    use crate::control::codec::envelope_bytes;
    use crate::control::codec::read_envelope;
    use crate::control::tls::{client_tls_stream, server_tls_stream};
    use crate::framing;
    use landscape_rill_coord::signer::verify_binding;
    use landscape_rill_core::control::registry::AuthKeyPolicy;

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
        let ak_loop = landscape_rill_coord::authkey::generate_auth_key("lab", 3600).unwrap();
        let ak_server = ak_loop.clone();
        let server = tokio::spawn(async move {
            let mut listener = listener;
            let mut tls = server_tls_stream(&mut listener, &cert, &key).await.unwrap();
            let mut server = CoordinatorServer::new(master, seed);
            server
                .coordinator
                .add_auth_key(&ak_server, AuthKeyPolicy::OneTime);
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
        framing::write_frame(&mut tls, &reg).await.unwrap();
        let (mt, body) = read_envelope(&mut tls).await.unwrap();
        assert_eq!(mt, MsgType::REGISTER_RESPONSE);
        let mut reader = BytesReader::from_bytes(&body);
        let resp = RegisterResponse::from_reader(&mut reader, &body).unwrap();
        assert_eq!(resp.node_id, 1);
        assert_eq!(
            resp.network_id,
            landscape_rill_coord::domain::network_id_for("lab")
        );
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
    fn binding_verifies_with_ed25519() {
        use landscape_rill_core::control::registry::IdentitySigner;
        let signer = landscape_rill_coord::signer::Ed25519Signer::new([0x99; 32]);
        let msg = landscape_rill_core::control::registry::binding_message(7, &[0x42; 32]);
        let sig = signer.sign(&msg);
        assert!(verify_binding(&signer.verifier(), 7, &[0x42; 32], &sig));
    }

    // ==================== 控制面限速/准入（REQ-047，SEC-19/SEC-20） ====================

    fn bad_leg_config(auth_key: &str, seed: u8) -> MeshLegConfig {
        MeshLegConfig {
            coordinator_host: String::new(),
            coordinator_port: 0,
            auth_key: auth_key.into(),
            static_key: [seed; 32],
            capabilities: 0x01,
            announce_routes: vec![],
        }
    }

    /// 连接级消息限速（REQ-047）：桶空 → 断连该连接（SEC-19 速率维度）
    #[tokio::test]
    async fn conn_message_flood_disconnects() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (ca_cert, cert, key) = ca_pair();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let master = [0x11; 32];
        let seed = [0x22; 32];
        let server = tokio::spawn(async move {
            let mut listener = listener;
            let mut tls = server_tls_stream(&mut listener, &cert, &key).await.unwrap();
            let mut server = CoordinatorServer::new(master, seed);
            let r = server.handle_connection(&mut tls).await;
            assert!(r.is_err(), "消息洪泛超桶容量必须断连");
            // 推进 1s 摘要窗口（LOGGING §5）取计数
            let later = std::time::Instant::now() + RATE_SUMMARY_PERIOD;
            assert!(server.rate_limited.poll(later).unwrap_or(0) >= 1);
        });
        let host = addr.ip().to_string();
        let mut tls = client_tls_stream(&host, addr.port(), &ca_cert)
            .await
            .unwrap();
        let client = MeshClient::new([0x44; 32]);
        // 未注册心跳 = 无操作消息：纯测连接级限速
        for _ in 0..(CONN_MSG_CAPACITY as usize + 10) {
            framing::write_frame(&mut tls, &client.heartbeat())
                .await
                .unwrap();
        }
        let r = read_envelope(&mut tls).await;
        assert!(r.is_err(), "服务端断连后客户端应读到 EOF");
        server.await.unwrap();
    }

    /// auth key 爆破锁定（REQ-047/SEC-20）：连续失败（未知 key + 未知 pubkey）
    /// 达阈值 → 源 IP 锁定，后续连接注册直接拒绝
    #[tokio::test]
    async fn register_failures_lockout_after_repeated_bad_keys() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (ca_cert, cert, key) = ca_pair();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let master = [0x11; 32];
        let seed = [0x22; 32];
        let server = tokio::spawn(async move {
            let mut listener = listener;
            let mut server = CoordinatorServer::new(master, seed);
            for _ in 0..=REGISTER_LOCKOUT_FAILS {
                let mut tls = server_tls_stream(&mut listener, &cert, &key).await.unwrap();
                assert!(server.handle_connection(&mut tls).await.is_err());
            }
            let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
            assert!(server.register_locked(ip, std::time::Instant::now()));
        });
        let host = addr.ip().to_string();
        for i in 0..=REGISTER_LOCKOUT_FAILS {
            let mut tls = client_tls_stream(&host, addr.port(), &ca_cert)
                .await
                .unwrap();
            // 每次不同未知 pubkey + 垃圾 key：全部走失败路径（无挑战资格）
            let client = MeshClient::new([0x50 + i as u8; 32]);
            let reg =
                client.register_request(&bad_leg_config("lrk-lab-0-badbadbad", 0x50 + i as u8));
            framing::write_frame(&mut tls, &reg).await.unwrap();
            assert!(
                read_envelope(&mut tls).await.is_err(),
                "失败/锁定注册都应被断连"
            );
        }
        server.await.unwrap();
    }

    /// 心跳超频忽略（REQ-047）：间隔不足 → 零成本跳过（无快照/LEASE 推送），
    /// 正常心跳（≥ 最小间隔）照常处理
    #[tokio::test]
    async fn heartbeat_overspeed_ignored() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (ca_cert, cert, key) = ca_pair();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let master = [0x11; 32];
        let seed = [0x22; 32];
        let ak = landscape_rill_coord::authkey::generate_auth_key("lab", 3600).unwrap();
        let ak_server = ak.clone();
        let server = tokio::spawn(async move {
            let mut listener = listener;
            let mut tls = server_tls_stream(&mut listener, &cert, &key).await.unwrap();
            let mut server = CoordinatorServer::new(master, seed);
            server
                .coordinator
                .add_auth_key(&ak_server, AuthKeyPolicy::Reusable);
            let _ = server.handle_connection(&mut tls).await;
        });
        let host = addr.ip().to_string();
        let mut tls = client_tls_stream(&host, addr.port(), &ca_cert)
            .await
            .unwrap();
        let client = MeshClient::new([0x33; 32]);
        let reg = client.register_request(&bad_leg_config(&ak, 0x33));
        framing::write_frame(&mut tls, &reg).await.unwrap();
        // 消费注册响应 + 初始快照（NETMAP_PUSH + KEY_DIST）
        assert_eq!(
            read_envelope(&mut tls).await.unwrap().0,
            MsgType::REGISTER_RESPONSE
        );
        while read_envelope(&mut tls).await.unwrap().0 != MsgType::KEY_DIST {}
        // 心跳 1（首个，间隔充分）→ 快照 + LEASE 推送
        framing::write_frame(&mut tls, &client.heartbeat())
            .await
            .unwrap();
        while read_envelope(&mut tls).await.unwrap().0 != MsgType::LEASE {}
        // 心跳 2（紧随其后，< 最小间隔）→ 忽略：无任何推送
        framing::write_frame(&mut tls, &client.heartbeat())
            .await
            .unwrap();
        let r = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            read_envelope(&mut tls),
        )
        .await;
        assert!(r.is_err(), "超频心跳不应产生推送");
        drop(tls);
        let _ = server.await;
    }

    /// REQ-057：注册响应丢失（等价进程重启）→ Fresh 客户端重发已消费 key →
    /// 挑战携带 node_id → 按消息 node_id 计算 tag → 验证通过补发
    /// REGISTER_RESPONSE（同 node_id，完整初始化链）
    #[tokio::test]
    async fn register_ack_loss_challenge_recovery() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (ca_cert, cert, key) = ca_pair();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let master = [0x11; 32];
        let seed = [0x22; 32];
        let ak_loop = landscape_rill_coord::authkey::generate_auth_key("lab", 3600).unwrap();
        let ak_server = ak_loop.clone();
        let coordinator = std::sync::Arc::new(tokio::sync::Mutex::new({
            let mut server = CoordinatorServer::new(master, seed);
            server
                .coordinator
                .add_auth_key(&ak_server, AuthKeyPolicy::OneTime);
            server
        }));
        let cert_key = cert;
        let server = tokio::spawn(async move {
            let mut listener = listener;
            for _ in 0..2 {
                let mut tls = server_tls_stream(&mut listener, &cert_key, &key)
                    .await
                    .unwrap();
                let mut server = coordinator.lock().await;
                let _ = server.handle_connection(&mut tls).await;
            }
        });
        let host = addr.ip().to_string();

        // 连接 1：正常注册消费 one-time key；客户端读走响应后丢弃会话
        let mut tls1 = client_tls_stream(&host, addr.port(), &ca_cert)
            .await
            .unwrap();
        let c1 = MeshClient::new([0x33; 32]);
        let config = MeshLegConfig {
            coordinator_host: host.clone(),
            coordinator_port: addr.port(),
            auth_key: ak_loop.clone(),
            static_key: [0x33; 32],
            capabilities: 0x01,
            announce_routes: vec![],
        };
        framing::write_frame(&mut tls1, &c1.register_request(&config))
            .await
            .unwrap();
        let (mt, _body) = read_envelope(&mut tls1).await.unwrap();
        assert_eq!(mt, MsgType::REGISTER_RESPONSE);
        drop(tls1);

        // 连接 2：Fresh 客户端（同静态密钥 = ack 丢失/重启等价）重发同一已消费 key
        let mut tls2 = client_tls_stream(&host, addr.port(), &ca_cert)
            .await
            .unwrap();
        let c2 = MeshClient::new([0x33; 32]);
        framing::write_frame(&mut tls2, &c2.register_request(&config))
            .await
            .unwrap();
        let (mt2, body2) = read_envelope(&mut tls2).await.unwrap();
        assert_eq!(mt2, MsgType::CHALLENGE);
        let mut reader2 = BytesReader::from_bytes(&body2);
        let ch = Challenge::from_reader(&mut reader2, &body2).unwrap();
        assert_eq!(ch.node_id, 1, "挑战必须携带服务端解析的 node_id");
        let ack = c2.challenge_ack(&ch);
        framing::write_frame(&mut tls2, &ack).await.unwrap();
        let (mt3, body3) = read_envelope(&mut tls2).await.unwrap();
        assert_eq!(mt3, MsgType::REGISTER_RESPONSE, "挑战通过后补发注册响应");
        let mut reader3 = BytesReader::from_bytes(&body3);
        let resp = RegisterResponse::from_reader(&mut reader3, &body3).unwrap();
        assert_eq!(resp.node_id, 1, "恢复保持原 node_id，无新注册");
        assert_eq!(
            resp.network_id,
            landscape_rill_coord::domain::network_id_for("lab")
        );
        assert!(!resp.identity_binding.is_empty());
        drop(tls2);
        server.await.unwrap();
    }

    /// REQ-057：坏 tag → 挑战失败断连（持有证明不通过）
    #[tokio::test]
    async fn register_ack_loss_challenge_bad_tag_rejected() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (ca_cert, cert, key) = ca_pair();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let ak_loop = landscape_rill_coord::authkey::generate_auth_key("lab", 3600).unwrap();
        let ak_server = ak_loop.clone();
        let coordinator = std::sync::Arc::new(tokio::sync::Mutex::new({
            let mut server = CoordinatorServer::new([0x11; 32], [0x22; 32]);
            server
                .coordinator
                .add_auth_key(&ak_server, AuthKeyPolicy::OneTime);
            server
        }));
        let server = tokio::spawn(async move {
            let mut listener = listener;
            for _ in 0..2 {
                let mut tls = server_tls_stream(&mut listener, &cert, &key).await.unwrap();
                let mut server = coordinator.lock().await;
                let _ = server.handle_connection(&mut tls).await;
            }
        });
        let host = addr.ip().to_string();

        let mut tls1 = client_tls_stream(&host, addr.port(), &ca_cert)
            .await
            .unwrap();
        let c1 = MeshClient::new([0x33; 32]);
        let config = MeshLegConfig {
            coordinator_host: host.clone(),
            coordinator_port: addr.port(),
            auth_key: ak_loop.clone(),
            static_key: [0x33; 32],
            capabilities: 0x01,
            announce_routes: vec![],
        };
        framing::write_frame(&mut tls1, &c1.register_request(&config))
            .await
            .unwrap();
        let (mt, _) = read_envelope(&mut tls1).await.unwrap();
        assert_eq!(mt, MsgType::REGISTER_RESPONSE);
        drop(tls1);

        let mut tls2 = client_tls_stream(&host, addr.port(), &ca_cert)
            .await
            .unwrap();
        let c2 = MeshClient::new([0x33; 32]);
        framing::write_frame(&mut tls2, &c2.register_request(&config))
            .await
            .unwrap();
        let (mt2, body2) = read_envelope(&mut tls2).await.unwrap();
        assert_eq!(mt2, MsgType::CHALLENGE);
        let mut reader2 = BytesReader::from_bytes(&body2);
        let ch = Challenge::from_reader(&mut reader2, &body2).unwrap();
        let bad = ChallengeAck {
            node_id: ch.node_id,
            tag: Cow::Owned(vec![0u8; 32]),
        };
        framing::write_frame(&mut tls2, &envelope_bytes(MsgType::CHALLENGE_ACK, &bad))
            .await
            .unwrap();
        let r = read_envelope(&mut tls2).await;
        assert!(r.is_err(), "坏 tag 必须断连");
        drop(tls2);
        server.await.unwrap();
    }

    /// REQ-057：已消费 key + 不同 pubkey → unknown pubkey 拒绝（tombstone
    /// 对第二身份语义不变，persist 场景阶段 4 断言保持）
    #[tokio::test]
    async fn register_consumed_key_different_pubkey_rejected() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (ca_cert, cert, key) = ca_pair();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let ak_loop = landscape_rill_coord::authkey::generate_auth_key("lab", 3600).unwrap();
        let ak_server = ak_loop.clone();
        let coordinator = std::sync::Arc::new(tokio::sync::Mutex::new({
            let mut server = CoordinatorServer::new([0x11; 32], [0x22; 32]);
            server
                .coordinator
                .add_auth_key(&ak_server, AuthKeyPolicy::OneTime);
            server
        }));
        let server = tokio::spawn(async move {
            let mut listener = listener;
            for _ in 0..2 {
                let mut tls = server_tls_stream(&mut listener, &cert, &key).await.unwrap();
                let mut server = coordinator.lock().await;
                let _ = server.handle_connection(&mut tls).await;
            }
        });
        let host = addr.ip().to_string();

        let mut tls1 = client_tls_stream(&host, addr.port(), &ca_cert)
            .await
            .unwrap();
        let c1 = MeshClient::new([0x33; 32]);
        let config1 = MeshLegConfig {
            coordinator_host: host.clone(),
            coordinator_port: addr.port(),
            auth_key: ak_loop.clone(),
            static_key: [0x33; 32],
            capabilities: 0x01,
            announce_routes: vec![],
        };
        framing::write_frame(&mut tls1, &c1.register_request(&config1))
            .await
            .unwrap();
        let (mt, _) = read_envelope(&mut tls1).await.unwrap();
        assert_eq!(mt, MsgType::REGISTER_RESPONSE);
        drop(tls1);

        // 不同静态密钥的身份复用同一 key：不得进入挑战分支
        let mut tls2 = client_tls_stream(&host, addr.port(), &ca_cert)
            .await
            .unwrap();
        let c2 = MeshClient::new([0x44; 32]);
        let config2 = MeshLegConfig {
            coordinator_host: host.clone(),
            coordinator_port: addr.port(),
            auth_key: ak_loop.clone(),
            static_key: [0x44; 32],
            capabilities: 0x01,
            announce_routes: vec![],
        };
        framing::write_frame(&mut tls2, &c2.register_request(&config2))
            .await
            .unwrap();
        let r = read_envelope(&mut tls2).await;
        assert!(r.is_err(), "unknown pubkey 必须断连");
        drop(tls2);
        server.await.unwrap();
    }
}
