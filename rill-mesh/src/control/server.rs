//! 控制面服务端（coordinator 线格式胶水）：TLS accept + 信封分派 + 快照/路径推送

use crate::control::codec::{envelope_body, read_envelope, write_msg};
use crate::control::{
    BoxResult, AUDIT_VERDICT_BEHIND, AUDIT_VERDICT_CONFLICT, AUDIT_VERDICT_UNKNOWN,
    AUDIT_VERDICT_VERIFIED,
};
use landscape_rill_coord::config::CoordConfig;
use landscape_rill_coord::coordinator::Coordinator;
use landscape_rill_coord::raft::backend::{AuditVerdict, CoordBackend, Leadership, WriteError};
use landscape_rill_coord::status::{
    DirectPairView as DirectPairDst, DropView, PeerTrafficView as PeerTrafficDst, TelemetryView,
};
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
    /// 挑战绑定的身份：恢复类 = 存储 pubkey 解析值（REQ-057，CP-02）；新建类 = 0
    /// （REQ-060：身份在 PoP 通过后的准入时才分配，由 REGISTER_RESPONSE 携带）
    node_id: u32,
    /// 验证锚：恢复类 = 存储 pubkey（不信任自报）；新建类 = REGISTER 自报 pubkey
    /// （PoP 的目标就是这把钥匙——绑定的是它，冒充他人无从谈起）
    pubkey: [u8; 32],
    pending: PendingRegister,
}

/// 挑战期间保留的注册数据（REQ-060）：PoP 通过后才执行对应完成语义
/// proto 遥测载荷 → coordinator 视图（REQ-052；字段直拷，node_id 0 = 无对端归因保留）
fn telemetry_view(t: TelemetryPayload) -> TelemetryView {
    TelemetryView {
        peers: t
            .peers
            .into_iter()
            .map(|p| PeerTrafficDst {
                node_id: p.node_id,
                tx_frames: p.tx_frames,
                tx_bytes: p.tx_bytes,
                rx_frames: p.rx_frames,
                rx_bytes: p.rx_bytes,
            })
            .collect(),
        drop_global: t.drop_global,
        drops: t
            .drops
            .into_iter()
            .map(|d| DropView {
                node_id: d.node_id,
                count: d.count,
            })
            .collect(),
        direct: t
            .direct
            .into_iter()
            .map(|d| DirectPairDst {
                node_id: d.node_id,
                endpoint: d.endpoint.into_owned(),
                rtt_ms: d.rtt_ms,
            })
            .collect(),
        updated_at: 0,
    }
}

struct PendingRegister {
    auth_key: String,
    capabilities: u32,
    routes: Vec<String>,
    protocol_version: u32,
    /// 构建版本元数据（REQ-052；可选，仅状态端点展示）
    version: String,
    /// true = 恢复类（pubkey 已注册表命中）；false = 新建类
    resume: bool,
}

impl ChallengeState {
    fn new(node_id: u32, pubkey: [u8; 32], pending: PendingRegister) -> Self {
        Self {
            eph_priv: rand::random::<[u8; 32]>(),
            nonce: rand::random::<[u8; 16]>().to_vec(),
            issued_at: unix_seconds(),
            node_id,
            pubkey,
            pending,
        }
    }
}

pub fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 网络隔离（SEC-21/CTL-09）：只推指定网络的条目与 relay 列表。
/// replica_endpoints = raft 成员端点（绑定审计目标，REQ-049②；单机 = 空）
pub fn netmap_push_message(
    coordinator: &Coordinator,
    network_id: u32,
    replica_endpoints: Vec<String>,
) -> NetmapPush<'static> {
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
            offline: info.offline,
            identity_binding: Cow::Owned(info.identity_binding),
            raft_log_index: info.binding_log_id.0,
            raft_term: info.binding_log_id.1,
        })
        .collect();
    NetmapPush {
        version: coordinator.netmap_version(),
        entries,
        relay_roster: coordinator.relay_roster_for(network_id).to_vec().into(),
        // ACL 策略随 netmap 原子下发（REQ-045，CONTROL_PLANE §3.10；None = 未启用）
        acl: Some(acl_policy_message(&coordinator.acl_policy_of(network_id))),
        replica_endpoints: replica_endpoints.into_iter().map(Cow::Owned).collect(),
    }
}

/// rill-core 策略 → 线格式（主体字符串化：node:<id> / group:<name> / any）
fn acl_policy_message(policy: &landscape_rill_core::control::acl::AclPolicy) -> AclPolicy<'static> {
    use landscape_rill_core::control::acl::{AclAction, AclSubject};
    AclPolicy {
        enabled: policy.enabled,
        rules: policy
            .rules
            .iter()
            .map(|r| AclRule {
                subjects: r
                    .subjects
                    .iter()
                    .map(|s| match s {
                        AclSubject::Any => Cow::Borrowed("any"),
                        AclSubject::Node(id) => Cow::Owned(format!("node:{id}")),
                        AclSubject::Group(name) => Cow::Owned(format!("group:{name}")),
                    })
                    .collect(),
                prefix: Cow::Owned(r.prefix.to_cidr()),
                deny: r.action == AclAction::Deny,
            })
            .collect(),
        groups: policy
            .groups
            .iter()
            .map(|(name, ids)| AclGroup {
                name: Cow::Owned(name.clone()),
                // 4B 大端序列（同 CandidatePath.hops 惯例）
                node_ids: Cow::Owned(ids.iter().flat_map(|id| id.to_be_bytes()).collect()),
            })
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
    /// 写路径单一门面（REQ-070）：Single = 单机直调；Cluster = 持久写过日志提案、
    /// 读走本副本已 apply 状态；领导权视图驱动 LeaderRedirect（§3.6）
    pub coordinator: CoordBackend,
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
            coordinator: CoordBackend::single(Coordinator::new(signing_seed)),
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
    pub fn with_network(self, name: &str, master_key: [u8; 32]) -> Self {
        self.coordinator
            .with_coord_mut(|c| c.add_network(name, master_key));
        self
    }

    fn with_backend(coordinator: CoordBackend) -> Self {
        Self {
            coordinator,
            register_rejected: RateCounter::new(RATE_SUMMARY_PERIOD),
            rate_limited: RateCounter::new(RATE_SUMMARY_PERIOD),
            register_limiter: Self::default_limiter(),
            register_lockout: HashMap::new(),
            heartbeat_min_interval: HEARTBEAT_MIN_INTERVAL,
            drop_first_register_response: false,
        }
    }

    /// 管理面库 API（REQ-038，CONTROL_PLANE §3.12）：从配置构造（网络域 + auth keys + 白名单）；
    /// 配置 storage_path 时打开持久化存储（REQ-037），损坏/不一致 → Err（fail-closed）。
    /// 单机形态——集群形态见 [`Self::from_config_cluster`]
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
        let server = Self::with_backend(CoordBackend::single(coordinator));
        server.coordinator.with_coord_mut(|c| cfg.apply_to(c));
        Ok(server)
    }

    /// 集群形态（REQ-070 阶段二）：openraft 单副本——日志/状态存储从 storage_path
    /// 派生，配置面在 Raft::new 前注入（选主期间可能重放日志，auth key 须先就位），
    /// 静态成员 initialize（首次组网单点执行，已是成员的 NotAllowed 静默），
    /// 副本间 raft RPC 监听（mTLS）随返回一并拉起
    pub async fn from_config_cluster(cfg: &CoordConfig) -> BoxResult<Self> {
        use landscape_rill_coord::raft::log_store::RaftLogStore;
        use landscape_rill_coord::raft::machine::{MachineConfig, SharedStateMachine};
        use openraft::{BasicNode, Config as RaftConfig, Raft};

        let cluster = cfg.cluster.as_ref().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "no cluster section")
        })?;
        let storage = cfg.storage_path.as_deref().expect("validated");
        let (log_path, state_path) = cluster.raft_storage_paths(storage);
        let log_store = RaftLogStore::open(&log_path)?;
        let machine = SharedStateMachine::open(
            MachineConfig {
                signing_seed: cfg.signing_seed,
                networks: cfg
                    .networks
                    .iter()
                    .map(|n| (n.name.clone(), n.master_key))
                    .collect(),
            },
            &state_path,
        )?;
        machine.with_coordinator_mut(|c| cfg.apply_to(c));
        let material = crate::control::raft_rpc::RaftTlsMaterial {
            cert_pem: std::fs::read(&cfg.tls_cert_path)?,
            key_pem: std::fs::read(&cfg.tls_key_path)?,
            ca_pem: std::fs::read(&cluster.ca_cert_path)?,
        };
        let rpc_addrs: std::collections::HashMap<u64, String> = cluster
            .members
            .iter()
            .map(|m| (m.id, m.addr.clone()))
            .collect();
        // LeaderRedirect 提示用节点面地址（§3.6：节点重连目标）
        let advertise: std::collections::HashMap<u64, String> = cluster
            .members
            .iter()
            .map(|m| (m.id, m.advertise.clone()))
            .collect();
        let factory = crate::control::raft_rpc::RaftTlsNetworkFactory::new(material.clone());
        let raft_config = RaftConfig {
            cluster_name: format!("coord-ha-{}", cluster.node_id),
            // 跨主机副本（非共址）：心跳/选主留足网络与调度余量——过紧的超时
            // 在负载下会误判心跳丢失触发无谓选主（写路径 ForwardToLeader 抖动）
            heartbeat_interval: 100,
            election_timeout_min: 1000,
            election_timeout_max: 2000,
            ..Default::default()
        }
        .validate()?;
        let raft = Raft::new(
            cluster.node_id,
            std::sync::Arc::new(raft_config),
            factory,
            log_store,
            machine.clone(),
        )
        .await?;
        // 静态成员首启组网：任一成员单点 initialize；已在集群中的成员收 NotAllowed（正常）
        let nodes: std::collections::BTreeMap<u64, BasicNode> = rpc_addrs
            .iter()
            .map(|(id, addr)| (*id, BasicNode::new(addr.clone())))
            .collect();
        if let Err(e) = raft.initialize(nodes).await {
            if e.to_string().contains("NotAllowed") {
                tracing::debug!("[coord] raft already initialized (rejoin)");
            } else {
                tracing::warn!("[coord] raft initialize: {e} (retry via replication)");
            }
        }
        let listener = tokio::net::TcpListener::bind(
            cluster.raft_listen_addr.parse::<std::net::SocketAddr>()?,
        )
        .await?;
        tokio::spawn(crate::control::raft_rpc::serve_raft_rpc(
            raft.clone(),
            listener,
            material,
        ));
        // 领导权转移观测（REQ-070 阶段二验收证据）：state/leader/term 变更时记一条；
        // 接管 Leader 时重置活性软状态（陈旧 last_seen 会把在线节点扫成离线，§5.2）
        tokio::spawn({
            let raft = raft.clone();
            let machine = machine.clone();
            let node_id = cluster.node_id;
            async move {
                let mut rx = raft.metrics();
                let mut seen: (openraft::ServerState, Option<u64>, u64) =
                    (openraft::ServerState::Learner, None, 0);
                while rx.changed().await.is_ok() {
                    let m = rx.borrow_and_update();
                    let key = (m.state, m.current_leader, m.current_term);
                    if key != seen {
                        if m.state == openraft::ServerState::Leader && seen.0 != m.state {
                            machine.with_coordinator_mut(|c| {
                                c.reset_liveness_on_takeover(unix_seconds())
                            });
                        }
                        seen = key;
                        tracing::info!(
                            "[coord] raft node_id={} state={:?} leader={:?} term={}",
                            node_id,
                            m.state,
                            m.current_leader,
                            m.current_term
                        );
                    }
                }
            }
        });
        tracing::info!(
            "[coord] raft cluster started: node_id={} members={} rpc={}",
            cluster.node_id,
            cluster.members.len(),
            cluster.raft_listen_addr
        );
        Ok(Self::with_backend(CoordBackend::Cluster {
            raft,
            machine,
            members: std::sync::Arc::new(advertise),
            self_id: cluster.node_id,
        }))
    }

    /// 管理面库 API（REQ-038）：配置重载（SIGHUP）入口，增量收敛、不中断在途连接
    pub fn apply_config(&mut self, cfg: &CoordConfig) {
        self.coordinator.with_coord_mut(|c| cfg.apply_to(c));
    }

    /// 注册成功/挑战通过后：全量 netmap + 逐节点 key_dst + 广播密钥（v1 全量互连）。
    /// 按注册节点所属网络隔离（SEC-21/CTL-09）。
    async fn push_snapshot<W: AsyncWriteExt + Unpin>(
        &self,
        stream: &mut W,
        network_id: u32,
    ) -> BoxResult<()> {
        let replicas = self.coordinator.replica_endpoints();
        let push = self
            .coordinator
            .with_coord(|c| netmap_push_message(c, network_id, replicas));
        write_msg(stream, MsgType::NETMAP_PUSH, &envelope_body(&push)).await?;
        let node_ids: Vec<u32> = self.coordinator.with_coord(|c| {
            c.netmap_snapshot(network_id)
                .into_iter()
                .map(|n| n.node_id)
                .collect()
        });
        for node_id in node_ids {
            if let Some(body) = self
                .coordinator
                .with_coord(|c| key_dist_message(c, node_id))
            {
                write_msg(stream, MsgType::KEY_DIST, &body).await?;
            }
        }
        Ok(())
    }

    /// LeaderRedirect 应答（§3.6）：空端点 = 选主中（节点退避重试）
    async fn write_leader_redirect<W: AsyncWriteExt + Unpin>(
        &self,
        stream: &mut W,
        leadership: &Leadership,
    ) -> BoxResult<()> {
        let Leadership::Follower {
            leader_endpoint,
            term,
        } = leadership
        else {
            return Ok(());
        };
        let msg = LeaderRedirect {
            leader_endpoint: Cow::Owned(leader_endpoint.clone().unwrap_or_default()),
            raft_term: *term,
        };
        tracing::debug!(
            "[coord] leader redirect: endpoint={:?} term={}",
            msg.leader_endpoint,
            msg.raft_term
        );
        Ok(write_msg(stream, MsgType::LEADER_REDIRECT, &envelope_body(&msg)).await?)
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
                // follower 不准入：直接重定向（§3.6），挑战/限速面一并跳过
                let leadership = self.coordinator.leadership();
                if matches!(leadership, Leadership::Follower { .. }) {
                    self.write_leader_redirect(stream, &leadership).await?;
                    return Ok(());
                }
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
                // 统一挑战触发（REQ-060）：无持有证明不发身份。注册不在此处准入，
                // 只做分类（pubkey 是否在册）；key 校验/消费全部后置到 PoP 之后
                let pending = PendingRegister {
                    auth_key: req.auth_key.to_string(),
                    capabilities: req.capabilities,
                    routes,
                    protocol_version: req.protocol_version,
                    version: req.version.to_string(),
                    resume: false,
                };
                let (node_id, ch_pubkey, pending) = match self
                    .coordinator
                    .with_coord(|c| c.node_id_by_pubkey(&pubkey))
                {
                    // 恢复类：key 有效性不参与（PoP 强于共享 key 的成员资格证明），
                    // 不计失败锁定（合法恢复路径，§3.9）
                    Some(node_id) => (
                        node_id,
                        pubkey,
                        PendingRegister {
                            resume: true,
                            ..pending
                        },
                    ),
                    // 新建类：key 只读校验（格式/过期/归域/在册），失败计入锁定闸门
                    None => {
                        if !self
                            .coordinator
                            .with_coord(|c| c.auth_key_admissible(&pending.auth_key))
                        {
                            if let Some(ip) = peer_ip {
                                self.note_register_failure(ip, Instant::now());
                            }
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::PermissionDenied,
                                "invalid auth key",
                            )
                            .into());
                        }
                        (0, pubkey, pending)
                    }
                };
                let ch = ChallengeState::new(node_id, ch_pubkey, pending);
                let msg = Challenge {
                    eph_pub: Cow::Owned(
                        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(
                            ch.eph_priv,
                        ))
                        .to_bytes()
                        .to_vec(),
                    ),
                    nonce: Cow::Borrowed(&ch.nonce),
                    issued_at: ch.issued_at,
                    node_id: ch.node_id,
                };
                write_msg(stream, MsgType::CHALLENGE, &envelope_body(&msg)).await?;
                state.challenge = Some(ch);
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
                // 拷贝挑战态后立即释放借用；验证锚为挑战绑定的 pubkey（REQ-057/060：
                // 恢复类 = 服务端存储，不信任自报；新建类 = REGISTER 自报的 PoP 目标）
                let ch_node = ch.node_id;
                let ch_pub = ch.pubkey;
                let eph_priv = ch.eph_priv;
                let nonce = ch.nonce.clone();
                let issued_at = ch.issued_at;
                let (auth_key, capabilities, routes, protocol_version, version, resume) = {
                    let p = &ch.pending;
                    (
                        p.auth_key.clone(),
                        p.capabilities,
                        p.routes.clone(),
                        p.protocol_version,
                        p.version.clone(),
                        p.resume,
                    )
                };
                // 恢复类前置检查：条目须仍存在且 pubkey 一致（吊销/重注册后旧挑战失效）
                if resume {
                    let entry_pub = self.coordinator.with_coord(|c| c.static_pubkey_of(ch_node));
                    let Some(entry_pub) = entry_pub else {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::PermissionDenied,
                            "unknown node in challenge ack",
                        )
                        .into());
                    };
                    if entry_pub != ch_pub {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::PermissionDenied,
                            "challenge pubkey mismatch",
                        )
                        .into());
                    }
                }
                let ok = landscape_rill_core::control::challenge::verify_tag(
                    &ch_pub,
                    &eph_priv,
                    &nonce,
                    ch_node,
                    ack.tag.as_ref(),
                ) && landscape_rill_core::control::challenge::within_window(
                    issued_at,
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
                state.challenge = None;
                if resume {
                    // 恢复完成（REQ-060）：幂等比对在 PoP 之后；不走注册准入、
                    // 不校验 key 有效性（吊销以条目移除为准）
                    if !self
                        .coordinator
                        .with_coord(|c| c.resume_matches(ch_node, capabilities, &routes))
                    {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::PermissionDenied,
                            "registration changed (capabilities/routes)",
                        )
                        .into());
                    }
                    tracing::info!("[coord] challenge ok: node_id={ch_node}");
                    state.registered = Some(ch_node);
                    self.coordinator
                        .with_coord_mut(|c| c.heartbeat(ch_node, unix_seconds()));
                    self.coordinator
                        .with_coord_mut(|c| c.set_protocol_version(ch_node, protocol_version));
                    if !version.is_empty() {
                        self.coordinator
                            .with_coord_mut(|c| c.set_build_version(ch_node, version.clone()));
                    }
                    let network_id = self
                        .coordinator
                        .with_coord(|c| c.network_id_of(ch_node))
                        .unwrap_or(0);
                    // binding 缺失属不变量破坏——fail-closed 而非空绑定静默降级
                    let Some((identity_binding, binding_log_id)) =
                        self.coordinator.with_coord(|c| {
                            c.identity_binding_of(ch_node)
                                .zip(c.binding_log_id_of(ch_node))
                        })
                    else {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::PermissionDenied,
                            "challenge entry binding missing",
                        )
                        .into());
                    };
                    let resp = RegisterResponse {
                        node_id: ch_node,
                        network_id,
                        identity_binding: Cow::Owned(identity_binding),
                        raft_log_index: binding_log_id.0,
                        raft_term: binding_log_id.1,
                    };
                    write_msg(stream, MsgType::REGISTER_RESPONSE, &envelope_body(&resp)).await?;
                    self.push_snapshot(stream, network_id).await?;
                } else {
                    // 新建类完成（REQ-060）：准入（白名单/分配/binding/一次性 key 消费）
                    // 全部后置到 PoP 之后；失败仍 fail-closed
                    match self
                        .coordinator
                        .register(&auth_key, &ch_pub, capabilities, routes, unix_seconds())
                        .await
                    {
                        Ok(data) => {
                            if let Some(ip) = peer_ip {
                                self.register_lockout.remove(&ip);
                            }
                            self.coordinator.with_coord_mut(|c| {
                                c.set_protocol_version(data.node_id, protocol_version)
                            });
                            if !version.is_empty() {
                                self.coordinator.with_coord_mut(|c| {
                                    c.set_build_version(data.node_id, version.clone())
                                });
                            }
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
                            tracing::info!("[coord] challenge ok: node_id={}", data.node_id);
                            state.registered = Some(data.node_id);
                            self.coordinator
                                .with_coord_mut(|c| c.heartbeat(data.node_id, unix_seconds()));
                            let resp = RegisterResponse {
                                node_id: data.node_id,
                                network_id: data.network_id,
                                identity_binding: Cow::Owned(data.identity_binding),
                                raft_log_index: data.binding_log_id.0,
                                raft_term: data.binding_log_id.1,
                            };
                            write_msg(stream, MsgType::REGISTER_RESPONSE, &envelope_body(&resp))
                                .await?;
                            let network_id = self
                                .coordinator
                                .with_coord(|c| c.network_id_of(data.node_id))
                                .unwrap_or(0);
                            self.push_snapshot(stream, network_id).await?;
                        }
                        Err(WriteError::Local(e)) => {
                            // 准入在 PoP 后失败：按注册失败计（LOGGING §5 周期摘要）
                            if let Some(ip) = peer_ip {
                                self.note_register_failure(ip, Instant::now());
                            }
                            self.register_rejected.tick();
                            return Err(
                                std::io::Error::new(std::io::ErrorKind::InvalidData, e).into()
                            );
                        }
                        Err(WriteError::Forward { .. }) => {
                            // 提案期间领导权易主：重定向节点（幂等重注册走新主）
                            let leadership = self.coordinator.leadership();
                            self.write_leader_redirect(stream, &leadership).await?;
                            return Ok(());
                        }
                        Err(WriteError::Raft(e)) => {
                            if let Some(ip) = peer_ip {
                                self.note_register_failure(ip, Instant::now());
                            }
                            self.register_rejected.tick();
                            return Err(
                                std::io::Error::other(format!("raft unavailable: {e}")).into()
                            );
                        }
                    }
                }
            }
            MsgType::HEARTBEAT => {
                let mut reader = BytesReader::from_bytes(body);
                let hb = Heartbeat::from_reader(&mut reader, body)?;
                if let Some(node_id) = state.registered {
                    // 领导权易主（failover 后旧连接）：重定向节点重连新主（§3.6/§5.6）
                    let leadership = self.coordinator.leadership();
                    if matches!(leadership, Leadership::Follower { .. }) {
                        self.write_leader_redirect(stream, &leadership).await?;
                        return Ok(());
                    }
                    // 遥测聚合（REQ-052/§3.15）：latest-wins 快照，旧值直接覆盖；
                    // 无载荷（旧节点）不触碰已有快照
                    if let Some(telemetry) = hb.telemetry {
                        self.coordinator.with_coord_mut(|c| {
                            c.store_telemetry(node_id, telemetry_view(telemetry))
                        });
                    }
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
                    self.coordinator
                        .with_coord_mut(|c| c.heartbeat(node_id, unix_seconds()));
                    // 周期收敛：端点/离线等软状态随心跳广播（v1 无增量推送）
                    let network_id = self
                        .coordinator
                        .with_coord(|c| c.network_id_of(node_id))
                        .unwrap_or(0);
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
            MsgType::AUDIT_REQUEST => {
                // 绑定审计（REQ-049②，CONTROL_PLANE §3.16）：任意副本以本地已
                // apply 状态裁决——不重定向（交叉验证正是用多数派状态制衡 leader）
                let mut reader = BytesReader::from_bytes(body);
                let req = AuditRequest::from_reader(&mut reader, body)?;
                let mut pubkey = [0u8; 32];
                if req.static_pubkey.len() != pubkey.len() || req.binding.len() != 64 {
                    let resp = AuditResponse {
                        verdict: AUDIT_VERDICT_UNKNOWN,
                        applied_index: self.coordinator.applied_index(),
                    };
                    write_msg(stream, MsgType::AUDIT_RESPONSE, &envelope_body(&resp)).await?;
                    return Ok(());
                }
                pubkey.copy_from_slice(&req.static_pubkey);
                let (verdict, applied_index) = self.coordinator.audit_binding(
                    req.node_id,
                    &pubkey,
                    &req.binding,
                    (req.raft_log_index, req.raft_term),
                );
                let resp = AuditResponse {
                    verdict: match verdict {
                        AuditVerdict::Verified => AUDIT_VERDICT_VERIFIED,
                        AuditVerdict::Conflict => AUDIT_VERDICT_CONFLICT,
                        AuditVerdict::Behind => AUDIT_VERDICT_BEHIND,
                        AuditVerdict::Unknown => AUDIT_VERDICT_UNKNOWN,
                    },
                    applied_index,
                };
                write_msg(stream, MsgType::AUDIT_RESPONSE, &envelope_body(&resp)).await?;
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
                // 响应不下发：路径集事件走心跳推送通道（push_path_events），
                // 与 NETMAP/LEASE 同批次写入——即时写回在并发下不可靠
                if let Err(WriteError::Forward { .. }) = self
                    .coordinator
                    .request_paths(
                        source,
                        req.destination_node_id,
                        req.max_candidates,
                        unix_seconds(),
                    )
                    .await
                {
                    let leadership = self.coordinator.leadership();
                    self.write_leader_redirect(stream, &leadership).await?;
                }
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
                    // 分列落位（REQ-062）：本地接口地址 + echo seen 地址
                    //（公网准入判定基准；空上报无意义不写）
                    let local: Vec<String> =
                        report.endpoints.iter().map(|s| s.to_string()).collect();
                    let seen: Vec<String> = report.seen.iter().map(|s| s.to_string()).collect();
                    if !local.is_empty() || !seen.is_empty() {
                        if let Err(WriteError::Forward { .. }) =
                            self.coordinator.set_endpoints(node_id, local, seen).await
                        {
                            let leadership = self.coordinator.leadership();
                            self.write_leader_redirect(stream, &leadership).await?;
                        }
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
        let events = self
            .coordinator
            .with_coord_mut(|c| c.take_path_events(source));
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
                            .map(|c| {
                                let key_path = self.coordinator.with_coord(|coord| {
                                    coord.key_path_for(src, c.path_id, c.path_epoch).to_vec()
                                });
                                CandidatePath {
                                    path_id: c.path_id,
                                    path_epoch: c.path_epoch,
                                    hops: Cow::Owned(crate::control::hops_bytes(&c.hops)),
                                    expires_at: c.expires_at,
                                    key_path: Cow::Owned(key_path),
                                }
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
#[path = "server_tests.rs"]
mod tests;
