//! rill ext 节点运行时编排：控制面（TLS 注册/netmap/keydist/心跳/挑战）↔ 数据面（MeshData）
//! ↔ 路由引擎 ↔ tun0（LAN 侧）。v1 单线程循环，所有状态收敛在 Node。
//!
//! 可测性：pump_* 接口单步驱动（pump_control / pump_mesh / pump_lan_packet / pump_timers），
//! 无 tun 环境（无 /dev/net/tun）下全链路可主机验证；run() 仅在容器环境启用 tun。

use crate::config::{Config, DEFAULT_HEARTBEAT_INTERVAL, DEFAULT_SESSION_REKEY_HOURS};
use crate::packet::mtu::{build_ptb, clamp_mss, is_tcp_syn, TUN_CONSERVATIVE_MTU};
use crate::packet::{parse_packet, PacketInfo, TransportProto};
use crate::tun::{TunConfig, TunDevice};
use crate::BoxResult;
use ed25519_dalek::VerifyingKey;
use futures_util::StreamExt;
use landscape_rill_core::control::acl::AclPolicy;
use landscape_rill_core::control::session::{SessionEvent, SessionState};
use landscape_rill_core::control::CAPABILITY_ACL;
use landscape_rill_core::frame::VERSION;
use landscape_rill_core::handshake::HandshakeContext;
use landscape_rill_core::rate::{RateCounter, TokenBucket, RATE_SUMMARY_PERIOD};
use landscape_rill_core::route::{
    DefaultRouteResolver, RouteEngine, RouteEntry, RouteSource, RouteVia,
};
use landscape_rill_mesh::control::{
    audit_binding, ControlEvent, ControlSession, MeshLegConfig, NetmapData, AUDIT_VERDICT_BEHIND,
    AUDIT_VERDICT_CONFLICT, AUDIT_VERDICT_UNKNOWN, AUDIT_VERDICT_VERIFIED,
};
use landscape_rill_mesh::data::is_emsgsize;
use landscape_rill_mesh::data::{
    BindingClaim, IncomingEvent, MeshData, PathEntry, TcpTransport, UdpTransport, Underlay,
    UnderlayKind,
};
use probe::RelayEntry;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

pub mod control;
pub mod dn42;
pub mod lan;
pub mod probe;
pub mod reconnect;
pub mod route_report;
pub mod ts2021;
pub(crate) use lan::TransitFrom;
pub const DATA_HEARTBEAT_MISSES: u32 = 3;
/// 握手重试间隔：上次尝试无响应视为该路径 miss（UDP 黑洞探活）
pub const HANDSHAKE_RETRY_INTERVAL: Duration = Duration::from_secs(2);
/// mesh→LAN 广播帧写入 land0 后被内核回送入 tun 的防再泛洪窗口
/// （组播包指纹，FRAME_HEADER §2.6 防环）
pub const MULTICAST_REWRITE_GUARD: Duration = Duration::from_secs(2);
/// 待发路径请求上限（REQ-047：防大规模 netmap 内存放大；饱和丢弃靠重触发收敛）
pub const PATH_REQUEST_PENDING_MAX: usize = 256;

/// 本机非 loopback、非 tun 接口的 IPv4/IPv6 地址（端点通告用；失败回退空列表）
async fn collect_local_ips() -> Vec<IpAddr> {
    let Ok((connection, handle, _)) = rtnetlink::new_connection() else {
        return Vec::new();
    };
    tokio::spawn(connection);
    let mut skip = HashSet::new();
    let mut links = handle.link().get().execute();
    while let Some(Ok(link)) = links.next().await {
        let name = link
            .attributes
            .iter()
            .find_map(|a| match a {
                netlink_packet_route::link::LinkAttribute::IfName(n) => Some(n.clone()),
                _ => None,
            })
            .unwrap_or_default();
        if name.starts_with("lo") || name.starts_with("land") || name.starts_with("tun") {
            skip.insert(link.header.index);
        }
    }
    let mut out = Vec::new();
    let mut addrs = handle.address().get().execute();
    while let Some(Ok(a)) = addrs.next().await {
        if skip.contains(&a.header.index) {
            continue;
        }
        for attr in a.attributes {
            if let netlink_packet_route::address::AddressAttribute::Address(ip) = attr {
                if !ip.is_loopback() {
                    out.push(ip);
                }
            }
        }
    }
    out
}

/// 当前 unix 秒（租约看门狗 §5.2 用；时钟回拨只会延迟触发，无正确性风险）
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Debug, Clone)]
pub struct NodeOptions {
    /// 可选 tun0（容器/主机环境）；None = 无 LAN 侧（测试/纯转发形态）
    pub tun: Option<TunConfig>,
    /// 控制面心跳间隔（租约保活）
    pub heartbeat_interval: Duration,
    /// 数据面心跳间隔（会话活性探测，FRAME_HEADER §2.5）
    pub data_heartbeat_interval: Duration,
    /// 数据面心跳连续未收次数阈值（超过 → 会话拆除）
    pub data_heartbeat_misses: u32,
    /// rekey 间隔（Noise rekey 双窗口，FRAME_HEADER §2.4）
    pub rekey_interval: Duration,
    /// 进程级停机信号（SIGTERM，rilld 注入）：true = run loop 收尾退出
    /// （控制会话 TLS close_notify 后返回）；None = 无停机语义（测试/默认）
    pub shutdown: Option<tokio::sync::watch::Receiver<bool>>,
}

impl Default for NodeOptions {
    fn default() -> Self {
        Self {
            tun: None,
            heartbeat_interval: DEFAULT_HEARTBEAT_INTERVAL,
            data_heartbeat_interval: Duration::from_secs(5),
            data_heartbeat_misses: DATA_HEARTBEAT_MISSES,
            rekey_interval: Duration::from_secs(DEFAULT_SESSION_REKEY_HOURS * 3600),
            shutdown: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LanOutcome {
    /// 已加密帧发往 rill 节点
    Sent { peer: u32 },
    /// 包已进 dn42 隧道（DN42_LEG）
    SentDn42 { peer: String },
    /// 包已进 ts2021 出站通道（TS2021_LEG §3.3.2）
    SentTailnet { peer: String },
    /// 无会话，已发起懒握手（包丢弃，TCP 重传语义兜底）
    Handshaking { peer: u32 },
    /// 组播包已泛洪（广播帧，FRAME_HEADER §2.6）
    Flooded { peers: usize },
    /// 本地处理（本节点 LAN 前缀）
    Local,
    /// 无路由/解析失败 → 丢弃
    Dropped,
}

pub struct Node {
    cfg: Config,
    opts: NodeOptions,
    mesh: MeshData,
    /// 对外通告 IP（UDP connect 探测路由表得真实出口；mesh socket 绑 0.0.0.0 需此通告）
    advertise_ips: Vec<IpAddr>,
    engine: RouteEngine,
    /// 默认路由解析（ROUTE_ENGINE §5/§8，REQ-071）：LPM 未命中后的 exit 链
    default_route: DefaultRouteResolver,
    control: Option<ControlSession>,
    /// LeaderRedirect 会话级覆盖（§3.6，Raft 期）：重连目标优先于配置地址；
    /// 空 = 用配置地址（重定向到选举中时不清除既有覆盖）
    coord_override: Option<String>,
    tun: Option<TunDevice>,
    node_id: Option<u32>,
    network_id: u32,
    netmap_peers: HashSet<u32>,
    key_versions: HashMap<u32, u32>,
    broadcast_key: Option<[u8; 32]>,
    last_control_heartbeat: Instant,
    last_data_heartbeat: Instant,
    next_rekey: Instant,
    reconnect: reconnect::ReconnectPolicy,
    peer_heartbeats: HashMap<u32, u32>,
    /// netmap 发现 v2 peer 后待发的路径请求（v1.5，CONTROL_PLANE §3.11）
    pending_path_requests: Vec<u32>,
    /// 本节点主动请求过路径的 dest（PathUpdate 只对它们写入发送路径表；
    /// 作为 dest/relay 参与者收到的路径仅注入 key_path，不覆盖发送表）
    path_requested: HashSet<u32>,
    /// 上次握手尝试时刻（peer → 时间；无响应超时驱动路径 miss）
    last_handshake_attempt: HashMap<u32, Instant>,
    /// 近期写入 land0 的组播包指纹（(src,dst,len) → 时间）；LAN 侧再读到 = 回环，跳过泛洪
    recent_multicast_writes: HashMap<(IpAddr, IpAddr, usize), Instant>,
    /// per-peer 握手拒绝计数（LOGGING §5：周期摘要；仅已知 peer，防伪造 node_id 膨胀）
    rejected_stats: HashMap<u32, RateCounter>,
    /// 控制面连接失败计数（LOGGING §5：周期摘要替代逐条输出，退避逻辑不变）
    connect_failed: RateCounter,
    /// 最近一次 LEASE.expires_at（unix 秒，None = 未收到/会话已重置——看门狗不生效）。
    /// 节点侧租约看门狗（CONTROL_PLANE §5.2，REQ-070）：逾期仍在会话 =
    /// coordinator 静默僵死（TCP 可写但不应答）→ 主动断开走重连
    lease_expires_at: Option<u64>,
    /// 进程级停机信号（NodeOptions.shutdown 注入）
    shutdown: Option<tokio::sync::watch::Receiver<bool>>,
    /// coordinator UDP 回显目标（CONNECTIVITY §2）：(host, port)；host 为容器名/主机名
    /// 时每周期经 DNS 解析（30s 节奏，缓存无必要）；None = 未配置（跳过 echo）
    echo_target: Option<(String, u16)>,
    /// 上次 probe 周期时刻（echo + 互探 + relay 探测，PROBE_PERIOD）
    last_probe: Instant,
    /// probe 发送令牌桶（CN-01 强制限速，REQ-046）：桶空本轮不发
    probe_send_bucket: TokenBucket,
    /// 每端点探退避：端点 → (连续 miss, 下次允许探测时刻)；PONG 确认即清除
    probe_backoff: HashMap<SocketAddr, (u32, Instant)>,
    /// 挂靠中继（netmap relay_list 权威全量替换）
    pub(crate) relays: Vec<RelayEntry>,
    /// netmap 端点缓存（apply_relay_endpoints 用：direct ++ 确认 relay 追加）
    peer_endpoints: HashMap<u32, Vec<SocketAddr>>,
    /// echo 得到的 seen 地址（候选端点补充；变化时重发 EndpointReport）
    echoed_endpoints: Vec<SocketAddr>,
    /// dn42 leg 运行态（DN42_LEG，None = 未启用）
    dn42_peers: Vec<dn42::Dn42PeerLeg>,
    /// RouteSync 上报防抖状态（REQ-065，CONTROL_PLANE §3.17）
    route_report: route_report::RouteReporter,
    /// ts2021 leg 运行态（TS2021_LEG §3.3.2，None = 未启用）
    pub(crate) ts2021: Option<ts2021::Ts2021Leg>,
    /// 网络级 ACL 策略（REQ-045，CONTROL_PLANE §3.10）：随 netmap 原子切换；
    /// default = 未启用（v1 全放行）。裁决点 = 解密后（Data 臂），
    /// AEAD 会话即源认证，直连/中继/多跳全覆盖（CN-04）
    acl: AclPolicy,
    /// 绑定交叉审计（REQ-049②）：replica 端点（netmap 权威下发）+ 轮转游标
    audit_endpoints: Vec<String>,
    audit_cursor: usize,
    /// 已审终态的声明：peer → 锚点（Verified/Conflict 后记录；Behind/Unknown
    /// 不记录——下个 netmap/会话建立重试，replica 追上后返回终态）
    audited_claims: HashMap<u32, (u64, u64)>,
    /// 审计结果回投（后台任务 → pump_timers 100ms 节奏收账，不进 select!）
    audit_tx: Option<tokio::sync::mpsc::UnboundedSender<AuditOutcome>>,
    audit_rx: Option<tokio::sync::mpsc::UnboundedReceiver<AuditOutcome>>,
    /// CA 证书缓存（审计连接用，lazy 读取）
    ca_pem: Option<Vec<u8>>,
}

/// 绑定交叉审计结果（REQ-049②）：node_id = 0 表示自身绑定
struct AuditOutcome {
    node_id: u32,
    anchor: (u64, u64),
    verdict: u32,
}

impl Node {
    pub async fn new(cfg: Config, mut opts: NodeOptions) -> BoxResult<Self> {
        cfg.validate()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        let shutdown = opts.shutdown.take();
        // underlay 选择（REQ-054）：UDP 默认 / TCP 兜底（v1 全网统一）
        let underlay = match cfg.data_transport {
            crate::config::DataTransport::Udp => {
                Underlay::Udp(UdpTransport::bind("0.0.0.0:0".parse()?).await?)
            }
            crate::config::DataTransport::Tcp => {
                Underlay::Tcp(TcpTransport::bind("0.0.0.0:0".parse()?).await?)
            }
        };
        let mesh = MeshData::bind_underlay(underlay, 0).await?;
        // 枚举本机非 loopback、非 tun 接口地址（供 EndpointReport 通告；多宿主节点
        // 通告全部端点，coordinator 并入 netmap，对端按可达性选用）
        let advertise_ips = collect_local_ips().await;
        let tun = match &opts.tun {
            Some(tun_cfg) => Some(TunDevice::open(tun_cfg).await?),
            None => None,
        };
        let next_rekey = Instant::now() + opts.rekey_interval;
        let echo_target = cfg.udp_echo_addr.as_deref().and_then(|s| {
            let (host, port) = s.rsplit_once(':')?;
            Some((host.to_string(), port.parse::<u16>().ok()?))
        });
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let default_route = DefaultRouteResolver::new(cfg.default_route_preference.clone());
        let mut node = Self {
            cfg,
            opts,
            mesh,
            advertise_ips,
            engine: RouteEngine::new(),
            default_route,
            control: None,
            tun,
            node_id: None,
            network_id: 0,
            netmap_peers: HashSet::new(),
            key_versions: HashMap::new(),
            broadcast_key: None,
            last_control_heartbeat: Instant::now(),
            last_data_heartbeat: Instant::now(),
            next_rekey,
            reconnect: reconnect::ReconnectPolicy::new(),
            coord_override: None,
            peer_heartbeats: HashMap::new(),
            pending_path_requests: Vec::new(),
            path_requested: HashSet::new(),
            last_handshake_attempt: HashMap::new(),
            recent_multicast_writes: HashMap::new(),
            rejected_stats: HashMap::new(),
            connect_failed: RateCounter::new(RATE_SUMMARY_PERIOD),
            lease_expires_at: None,
            shutdown,
            echo_target,
            last_probe: Instant::now(),
            probe_send_bucket: TokenBucket::new(
                probe::PROBE_SEND_RATE_PER_SEC,
                probe::PROBE_SEND_CAPACITY,
            ),
            probe_backoff: HashMap::new(),
            relays: Vec::new(),
            peer_endpoints: HashMap::new(),
            echoed_endpoints: Vec::new(),
            dn42_peers: Vec::new(),
            ts2021: None,
            acl: AclPolicy::default(),
            audit_endpoints: Vec::new(),
            audit_cursor: 0,
            audited_claims: HashMap::new(),
            audit_tx: Some(tx.clone()),
            audit_rx: Some(rx),
            ca_pem: None,
            route_report: route_report::RouteReporter::default(),
        };
        // dn42 接入（DN42_LEG）：配置启用即 spawn peer 会话任务
        if let Some(dn42_cfg) = node.cfg.dn42.clone() {
            node.spawn_dn42_legs(&dn42_cfg).await?;
        }
        // ts2021 接入（TS2021_LEG §3.3.2）：配置启用即 spawn 腿任务
        // （控制面不可达不阻塞启动——任务内自退避重连）
        if let Some(ts_cfg) = node.cfg.ts2021.clone() {
            node.ts2021 = Some(ts2021::spawn_ts2021_leg(&ts_cfg).await?);
        }
        Ok(node)
    }

    pub fn node_id(&self) -> Option<u32> {
        self.node_id
    }

    pub fn registered(&self) -> bool {
        self.node_id.is_some()
    }

    pub fn has_session(&self, peer: u32) -> bool {
        self.mesh.has_session(peer)
    }

    pub fn mesh_local_addr(&self) -> std::io::Result<SocketAddr> {
        self.mesh.local_addr()
    }

    fn parse_url(url: &str) -> BoxResult<(String, u16)> {
        let rest = url
            .strip_prefix("https://")
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad url"))?;
        let (host, port) = match rest.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse::<u16>()?),
            None => (rest.to_string(), 8443),
        };
        Ok((host, port))
    }

    /// 控制面连接（含初始注册）。重连传上次 node_id（幂等注册/挑战路径）。
    pub async fn connect_control(&mut self) -> BoxResult<()> {
        let url = self
            .coord_override
            .clone()
            .unwrap_or_else(|| self.cfg.coordinator_url.clone());
        match Self::establish_control(&self.cfg, &url, self.node_id).await {
            Ok(session) => {
                self.control = Some(session);
                // 新会话租约未卜：旧值残留会在首跳心跳前误触发看门狗（§5.2）
                self.lease_expires_at = None;
                info!("[node] control connected");
                Ok(())
            }
            Err(e) => {
                // 重定向目标失效（failover 后旧 leader 不可达）→ 回落配置地址；
                // 若配置地址也是 follower 会再次收到重定向形成新覆盖（§3.6/§5.6）
                self.coord_override = None;
                Err(e)
            }
        }
    }

    /// 字段级构造控制面会话（run() 的 connect 分支做字段级借用，不经 &mut self）
    async fn establish_control(
        cfg: &Config,
        url: &str,
        node_id: Option<u32>,
    ) -> BoxResult<ControlSession> {
        let (host, port) = Self::parse_url(url)?;
        let ca = std::fs::read(&cfg.ca_cert_path)
            .map_err(|e| std::io::Error::new(e.kind(), format!("ca: {}", e)))?;
        let mut announce_routes = cfg.announce_routes.clone();
        // dn42 聚合公告（M2，DN42_LEG §7 ③）：opt-in 打开即并进注册 routes[]，
        // 与 LAN 公告同通道同 fail-closed 语义（coord 白名单 covered-by 放行）
        if let Some(dn42) = &cfg.dn42 {
            announce_routes.extend(dn42.mesh_announces());
        }
        let leg = MeshLegConfig {
            coordinator_host: host.clone(),
            coordinator_port: port,
            auth_key: cfg.auth_key.clone(),
            static_key: cfg.static_key_seed,
            // ACL 能力位恒置（REQ-045）：本节点实现解密后裁决，注册即声明；
            // 网络开启策略后无该位的节点被 fail-closed 拒绝（§3.1）
            capabilities: cfg.capabilities | CAPABILITY_ACL,
            announce_routes,
        };
        ControlSession::connect(&host, port, &ca, &leg, node_id).await
    }

    /// 握手拒绝计数（LOGGING §5）：仅已知 peer 记 per-peer，防伪造 node_id 膨胀
    fn note_rejected(&mut self, peer: u32) {
        if self.netmap_peers.contains(&peer) {
            let rc = self
                .rejected_stats
                .entry(peer)
                .or_insert_with(|| RateCounter::new(RATE_SUMMARY_PERIOD));
            rc.tick();
        }
    }

    /// 停机信号已触发（SIGTERM，rilld 注入）
    fn is_shutting_down(&self) -> bool {
        self.shutdown.as_ref().is_some_and(|rx| *rx.borrow())
    }

    /// 优雅收尾：控制会话发 TLS close_notify（对端立即感知而非等 TCP 超时），
    /// mesh/dn42 随 run loop 返回自然释放（进程退出兜底在 rilld）
    async fn graceful_shutdown(&mut self) {
        if let Some(control) = self.control.as_mut() {
            let _ = control.close().await;
        }
        self.control = None;
        info!("[node] shutdown complete");
    }

    /// 处理一个控制面事件（阻塞读；Err = 断线，调用方清 control 并重连）
    pub async fn pump_control(&mut self) -> BoxResult<()> {
        let Some(control) = self.control.as_mut() else {
            return Ok(());
        };
        let ev = control.read_event().await?;
        self.handle_control_event(ev).await
    }

    /// 处理一个数据面事件（阻塞读）；返回需要写入 LAN 侧的解密载荷
    pub async fn pump_mesh(&mut self) -> Option<bytes::Bytes> {
        let ev = match self.mesh.handle_incoming().await {
            Ok(ev) => ev,
            Err(_) => return None,
        };
        match ev {
            IncomingEvent::Data { from, payload } => {
                self.peer_heartbeats.insert(from, 0);
                self.acl_deliver(from, payload)
            }
            IncomingEvent::Broadcast { from, payload } => {
                self.peer_heartbeats.insert(from, 0);
                Some(payload)
            }
            IncomingEvent::Heartbeat { from } => {
                self.peer_heartbeats.insert(from, 0);
                None
            }
            IncomingEvent::Established { peer } => {
                info!("[node] session established with {}", peer);
                self.peer_heartbeats.insert(peer, 0);
                if let Some(claim) = self.mesh.binding_claim(peer).cloned() {
                    self.queue_binding_audit(peer, &claim);
                }
                None
            }
            IncomingEvent::Rejected { peer, .. } => {
                self.note_rejected(peer);
                None
            }
            IncomingEvent::Responded { .. } => None,
            IncomingEvent::Relayed { to } => {
                info!("[node] relayed frame to {}", to);
                None
            }
            IncomingEvent::ProbePing { from } => {
                debug!("[node] probe ping from {}", from);
                None
            }
            IncomingEvent::ProbePong {
                from,
                endpoint,
                payload,
            } => {
                self.handle_probe_pong(from, endpoint, payload).await;
                None
            }
            IncomingEvent::PathProbeRtt {
                dest,
                path_id,
                rtt_ms,
            } => {
                debug!("[node] path {path_id} to {dest} rtt {rtt_ms}ms");
                None
            }
            IncomingEvent::PathProbeServed { from } => {
                debug!("[node] path probe served for {from}");
                None
            }
            IncomingEvent::Dropped { reason } => {
                debug!("[node] dropped frame: {:?}", reason);
                None
            }
        }
    }

    /// 排队一次绑定交叉审计（REQ-049②，CONTROL_PLANE §3.16）：轮转选 replica
    /// 目标（多副本时逐次轮换——任意副本的 Conflict 都是终局证据）；
    /// 该锚点已出终态 → 跳过；单机（无 replica 列表）→ 无审计目标
    fn queue_binding_audit(&mut self, node_id: u32, claim: &BindingClaim) {
        if self.audited_claims.get(&node_id) == Some(&claim.anchor) {
            return;
        }
        if self.audit_endpoints.is_empty() {
            return;
        }
        let Some(tx) = self.audit_tx.clone() else {
            return;
        };
        if self.ca_pem.is_none() {
            match std::fs::read(&self.cfg.ca_cert_path) {
                Ok(pem) => self.ca_pem = Some(pem),
                Err(e) => {
                    debug!("[node] binding audit skipped: ca read failed: {e}");
                    return;
                }
            }
        }
        let ca = self.ca_pem.clone().unwrap_or_default();
        let endpoint = self.audit_endpoints[self.audit_cursor % self.audit_endpoints.len()].clone();
        self.audit_cursor = self.audit_cursor.wrapping_add(1);
        let claim = claim.clone();
        tokio::spawn(async move {
            let Some((host, port)) = endpoint
                .rsplit_once(':')
                .map(|(h, p)| (h.to_string(), p.parse::<u16>().unwrap_or(8443)))
            else {
                return;
            };
            let res = tokio::time::timeout(
                Duration::from_secs(5),
                audit_binding(
                    &host,
                    port,
                    &ca,
                    node_id,
                    &claim.static_pubkey,
                    &claim.binding,
                    claim.anchor,
                ),
            )
            .await;
            match res {
                Ok(Ok((verdict, applied))) => {
                    debug!(
                        "[node] binding audit reply: node_id={} verdict={} applied_index={}",
                        node_id, verdict, applied
                    );
                    let _ = tx.send(AuditOutcome {
                        node_id,
                        anchor: claim.anchor,
                        verdict,
                    });
                }
                _ => debug!("[node] binding audit failed: node_id={}", node_id),
            }
        });
    }

    /// 审计结果收账（pump_timers 节奏调用）。Conflict = 确定伪造/未进日志：
    /// 拆会话移除对端身份（自身绑定 Conflict 只告警——签发者可疑但不自断数据面，
    /// v1 语义）；Behind/Unknown 不记账，下个触发点重试
    fn pump_audits(&mut self) {
        let Some(rx) = self.audit_rx.as_mut() else {
            return;
        };
        while let Ok(out) = rx.try_recv() {
            match out.verdict {
                AUDIT_VERDICT_VERIFIED => {
                    info!(
                        "[node] binding audit verified: node_id={} anchor=({},{})",
                        out.node_id, out.anchor.0, out.anchor.1
                    );
                    self.audited_claims.insert(out.node_id, out.anchor);
                }
                AUDIT_VERDICT_CONFLICT => {
                    if out.node_id == 0 {
                        warn!(
                            "[node] own binding failed cross-audit (issuance not in raft log, split-view?)"
                        );
                    } else {
                        warn!(
                            "[node] peer {} binding failed cross-audit (unlogged signature), dropping session",
                            out.node_id
                        );
                        self.mesh.drop_session(out.node_id);
                        self.mesh.remove_peer_static(out.node_id);
                    }
                    self.audited_claims.insert(out.node_id, out.anchor);
                }
                AUDIT_VERDICT_BEHIND | AUDIT_VERDICT_UNKNOWN => {}
                _ => {}
            }
        }
    }

    /// 定时器：控制面心跳（租约保活）/ 数据面心跳（会话活性 + 3 次超时拆会话）/ rekey。
    /// dn42 leg 事件/明文 drain 同挂此节奏（非阻塞）：控制面退避分片（sleep_with_timers）
    /// 也持续调用，dn42-only 形态（无 coordinator）路由事件不饿死（DN42_LEG §5）
    pub async fn pump_timers(&mut self) {
        self.pump_dn42().await;
        self.pump_ts2021().await;
        self.pump_audits();
        let now = Instant::now();
        // 租约看门狗（CONTROL_PLANE §5.2 节点侧，REQ-070）：LEASE.expires_at 逾期
        // 且会话仍在 = coordinator 静默僵死（TCP 可写但不应答）→ 断开走既有
        // 重连退避；正常路径心跳响应在租约窗口内持续续期，不会触发
        if self.control.is_some() && self.lease_expires_at.is_some_and(|t| unix_now() > t) {
            info!(
                "[node] lease expired (expires_at={}), dropping control session",
                self.lease_expires_at.unwrap_or(0)
            );
            self.lease_expires_at = None;
            self.control = None;
        }
        if now.duration_since(self.last_control_heartbeat) >= self.opts.heartbeat_interval {
            self.last_control_heartbeat = now;
            if let Some(control) = self.control.as_mut() {
                // 遥测随控制面心跳上报（REQ-052/§3.15）：区间计数取走即清零
                let tele = self.mesh.take_telemetry();
                let hb = control.heartbeat_envelope(Some(tele));
                if control.send_envelope(&hb).await.is_err() {
                    self.control = None;
                }
            }
            // 待发路径请求（netmap 发现 v2 peer 后；随控制面心跳节奏发送——
            // 无节奏闸门会以 pump_timers 周期（100ms）洪泛，打爆 REQ-047
            // 连接级限速引发断连循环）。收到对应 Paths 事件才移除——即时
            // PathResponse 可能丢失，靠心跳重发收敛
            if let Some(control) = self.control.as_mut() {
                let reqs: Vec<u32> = self.pending_path_requests.clone();
                for dest in reqs {
                    let req = control.client().path_request(dest);
                    if control.send_envelope(&req).await.is_err() {
                        self.control = None;
                        break;
                    }
                }
            }
        }
        if now.duration_since(self.last_data_heartbeat) >= self.opts.data_heartbeat_interval {
            self.last_data_heartbeat = now;
            let peers: Vec<u32> = self.mesh.sessions().map(|s| s.peer()).collect();
            for peer in peers {
                let miss = self.peer_heartbeats.entry(peer).or_insert(0);
                *miss += 1;
                // 路径活性联动（v1.5）：miss 累计 → 主路径健康下降 → pick_path 切备用
                self.mesh.path_miss_peer(peer);
                self.mesh.miss_endpoint(peer);
                debug!(
                    "[node] path health for {}: {:?}",
                    peer,
                    self.mesh.path_health_snapshot(peer)
                );
                if let Ok(frame) = self.mesh.build_heartbeat_frame(peer) {
                    // 心跳帧同样走路径首跳（会话经 relay 建立后保活同路径）
                    let hop = self.mesh.path_first_hop(peer);
                    let _ = self.mesh.send_to_node_hop(peer, hop, &frame).await;
                }
                if *miss >= self.opts.data_heartbeat_misses {
                    info!(
                        "[node] session {} dropped: {} heartbeat misses",
                        peer, *miss
                    );
                    self.mesh.drop_session(peer);
                    self.peer_heartbeats.remove(&peer);
                }
            }
        }
        if now >= self.next_rekey {
            self.next_rekey = now + self.opts.rekey_interval;
            for session in self.mesh.sessions_mut() {
                session.rekey(now);
            }
        }
        // RouteSync 防抖窗口冲刷（REQ-065，§3.17）：窗口到期合并上报。
        // 控制面不可用（dn42-only/退避期）不冲刷——保留待报增量，注册后随
        // resync 重放收敛，避免上报丢失造成协调端视图漂移
        if self.control.is_some() && self.route_report.is_due(now) {
            if let Some((announced, withdrawn)) = self.route_report.flush(&self.engine) {
                if !announced.is_empty() || !withdrawn.is_empty() {
                    debug!(
                        "[node] route sync flush: {} announced, {} withdrawn",
                        announced.len(),
                        withdrawn.len()
                    );
                    if let Some(control) = self.control.as_mut() {
                        let env = control.route_sync_envelope(announced, withdrawn);
                        if control.send_envelope(&env).await.is_err() {
                            self.control = None;
                        }
                    }
                }
            }
        }
        self.pump_probes(now).await;
        self.pump_fail_summaries(now);
    }

    /// 高频失败事件 → 周期摘要（LOGGING §5）：事件只计数，每周期 ≤1 条，0 不输出
    fn pump_fail_summaries(&mut self, now: Instant) {
        if let Some(n) = self.connect_failed.poll(now) {
            if n > 0 {
                warn!("[node] control connect failed: {n} in last 1s");
            }
        }
        if let Some((per_peer, global)) = self.mesh.poll_drop_stats() {
            let total: u64 = global + per_peer.iter().map(|(_, n)| n).sum::<u64>();
            if total > 0 {
                let detail = if per_peer.is_empty() {
                    " (unattributed)".to_string()
                } else {
                    format!(" (peer {per_peer:?}, unattributed {global})")
                };
                warn!("[node] frame dropped: {total} in last 1s{detail}");
            }
        }
        if !self.rejected_stats.is_empty() {
            let mut rejected: Vec<(u32, u64)> = Vec::new();
            for (peer, rc) in self.rejected_stats.iter_mut() {
                if let Some(n) = rc.poll(now) {
                    if n > 0 {
                        rejected.push((*peer, n));
                    }
                }
            }
            self.rejected_stats.retain(|_, rc| rc.has_pending());
            if !rejected.is_empty() {
                warn!("[node] handshake rejected: {rejected:?} in last 1s");
            }
        }
    }

    /// 主循环：控制面事件 / 数据面事件 / tun 入包 / 定时器（v1 单线程）。
    /// dn42 leg 事件泵挂在 100ms 定时器与退避分片上，控制面不可用不停数据面。
    pub async fn run(mut self) {
        loop {
            if self.is_shutting_down() {
                self.graceful_shutdown().await;
                return;
            }
            if self.control.is_none() {
                // 连接在后台任务执行（§4.3）：注册经 raft 写路径（failover 后
                // 新主挑战重注册）可达秒级，前台 await 会停摆数据面输入——
                // 退避等待已分片服务 mesh/tun，但 connect 本身同样不得阻塞；
                // 结果按 100ms 分片轮询，等待期数据面照常收发（ha e2e 实证）
                let url = self
                    .coord_override
                    .clone()
                    .unwrap_or_else(|| self.cfg.coordinator_url.clone());
                let cfg = self.cfg.clone();
                let node_id = self.node_id;
                let (tx, mut rx) = tokio::sync::oneshot::channel();
                tokio::spawn(async move {
                    let _ = tx.send(Self::establish_control(&cfg, &url, node_id).await);
                });
                let res = loop {
                    if self.is_shutting_down() {
                        self.graceful_shutdown().await;
                        return;
                    }
                    match rx.try_recv() {
                        Ok(r) => break r,
                        Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {}
                        // establish_control panic 崩任务：按连接失败走退避
                        Err(tokio::sync::oneshot::error::TryRecvError::Closed) => {
                            break Err(std::io::Error::other("connect task aborted").into())
                        }
                    }
                    self.sleep_with_timers(Duration::from_millis(100)).await;
                };
                match res {
                    Ok(session) => {
                        self.control = Some(session);
                        // 新会话租约未卜：旧值残留会在首跳心跳前误触发看门狗（§5.2）
                        self.lease_expires_at = None;
                        self.reconnect.on_connect();
                        info!("[node] control connected");
                    }
                    Err(e) => {
                        debug!("[node] connect_control error: {}", e);
                        // 逐条输出 → 周期摘要（LOGGING §5）；退避 1s→300s 保持；
                        // 重定向目标失效 → 回落配置地址（connect_control 同语义）
                        self.connect_failed.tick();
                        self.coord_override = None;
                        let wait = self.reconnect.on_disconnect();
                        self.sleep_with_timers(wait).await;
                        continue;
                    }
                }
            }
            let control_ready = self.control.is_some();
            let tun_ready = self.tun.is_some();
            let control_read = async { self.control.as_mut().unwrap().read_event().await };
            let tun_read = async { self.tun.as_mut().unwrap().read_packet().await };
            tokio::select! {
                ev = self.mesh.handle_incoming() => {
                    if let Ok(ev) = ev {
                        if let Some(payload) = self.handle_mesh_event(ev).await {
                            // 跨腿 transit（M2）：dst 命中 dn42 路由且 leg 建立即出隧道，
                            // 否则写 TUN（本地投递，含组播/广播泛洪语义不变）
                            if !self.forward_transit(&payload, TransitFrom::Mesh).await {
                                self.write_lan(&payload).await;
                            }
                        }
                    }
                }
                ev = control_read, if control_ready => {
                    match ev {
                        Ok(ev) => { let _ = self.handle_control_event(ev).await; }
                        Err(e) => {
                            // 断线同样走退避（REQ-056）：连上即断不再热循环
                            debug!("[node] control read error: {e}");
                            self.control = None;
                            let wait = self.reconnect.on_disconnect();
                            self.sleep_with_timers(wait).await;
                            continue;
                        }
                    }
                }
                pkt = tun_read, if tun_ready => {
                    if let Ok(pkt) = pkt {
                        let _ = self.pump_lan_packet(&pkt).await;
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(100)) => {
                    self.pump_timers().await;
                }
            }
        }
    }

    /// 分片退避等待（REQ-056）：100ms 片轮转，片内持续服务数据面——
    /// mesh 收帧 + tun 读 + dn42 leg 事件/明文 + 定时器。控制面退避不得
    /// 停摆数据面（DN42_LEG §5 / REQ-070 §4.3 failover 期间数据面不中断）：
    /// 会话心跳/握手在重连窗口内照常收发，否则 coordinator 故障波及 mesh 会话
    async fn sleep_with_timers(&mut self, mut remaining: Duration) {
        while remaining > Duration::ZERO {
            if self.is_shutting_down() {
                return;
            }
            let slice = remaining.min(Duration::from_millis(100));
            remaining = remaining.saturating_sub(slice);
            let deadline = tokio::time::Instant::now() + slice;
            tokio::select! {
                ev = self.mesh.handle_incoming() => {
                    if let Ok(ev) = ev {
                        if let Some(payload) = self.handle_mesh_event(ev).await {
                            if !self.forward_transit(&payload, TransitFrom::Mesh).await {
                                self.write_lan(&payload).await;
                            }
                        }
                    }
                }
                pkt = async { self.tun.as_mut().unwrap().read_packet().await }, if self.tun.is_some() => {
                    if let Ok(pkt) = pkt {
                        let _ = self.pump_lan_packet(&pkt).await;
                    }
                }
                _ = tokio::time::sleep_until(deadline) => {}
            }
            self.pump_dn42().await;
            self.pump_timers().await;
        }
    }

    async fn handle_mesh_event(&mut self, ev: IncomingEvent) -> Option<bytes::Bytes> {
        match ev {
            IncomingEvent::Established { peer } => {
                info!("[node] session established with {}", peer);
                self.peer_heartbeats.insert(peer, 0);
                // 会话对端绑定声明交叉审计（REQ-049②）：握手只验签名有效性，
                // "签了但未进日志"（split-view 签发）由审计兜底
                if let Some(claim) = self.mesh.binding_claim(peer).cloned() {
                    self.queue_binding_audit(peer, &claim);
                }
                None
            }
            IncomingEvent::Rejected { peer, .. } => {
                self.note_rejected(peer);
                None
            }
            IncomingEvent::Data { from, payload } => {
                self.peer_heartbeats.insert(from, 0);
                self.acl_deliver(from, payload)
            }
            IncomingEvent::Broadcast { from, payload } => {
                self.peer_heartbeats.insert(from, 0);
                Some(payload)
            }
            IncomingEvent::Heartbeat { from } => {
                self.peer_heartbeats.insert(from, 0);
                None
            }
            IncomingEvent::Responded { .. } => None,
            IncomingEvent::Relayed { to } => {
                info!("[node] relayed frame to {}", to);
                None
            }
            IncomingEvent::ProbePing { from } => {
                debug!("[node] probe ping from {}", from);
                None
            }
            IncomingEvent::ProbePong {
                from,
                endpoint,
                payload,
            } => {
                self.handle_probe_pong(from, endpoint, payload).await;
                None
            }
            IncomingEvent::PathProbeRtt {
                dest,
                path_id,
                rtt_ms,
            } => {
                debug!("[node] path {path_id} to {dest} rtt {rtt_ms}ms");
                None
            }
            IncomingEvent::PathProbeServed { from } => {
                debug!("[node] path probe served for {from}");
                None
            }
            IncomingEvent::Dropped { reason } => {
                debug!("[node] dropped frame: {:?}", reason);
                None
            }
        }
    }

    /// ACL 裁决（REQ-045，CONTROL_PLANE §3.10）：目标节点解密后入口——
    /// from = AEAD 认证的源节点（会话即源认证，不可冒充），dst = 内层包
    /// 目的地址；未启用全放行。拒绝只丢载荷（会话/心跳/遥测归因不受影响）
    fn acl_deliver(&mut self, from: u32, payload: bytes::Bytes) -> Option<bytes::Bytes> {
        if self.acl.allows_packet(from, &payload) {
            Some(payload)
        } else {
            info!(
                "[node] acl denied {} byte frame from {}",
                payload.len(),
                from
            );
            self.mesh.note_drop(Some(from));
            None
        }
    }
}

#[cfg(test)]
mod tests;
