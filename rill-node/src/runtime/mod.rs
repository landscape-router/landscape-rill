//! rill ext 节点运行时编排：控制面（TLS 注册/netmap/keydist/心跳/挑战）↔ 数据面（MeshData）
//! ↔ 路由引擎 ↔ tun0（LAN 侧）。v1 单线程循环，所有状态收敛在 Node。
//!
//! 可测性：pump_* 接口单步驱动（pump_control / pump_mesh / pump_lan_packet / pump_timers），
//! 无 tun 环境（无 /dev/net/tun）下全链路可主机验证；run() 仅在容器环境启用 tun。

use crate::config::{Config, DEFAULT_HEARTBEAT_INTERVAL, DEFAULT_SESSION_REKEY_HOURS};
use crate::packet::{parse_packet, PacketInfo, TransportProto};
use crate::tun::{TunConfig, TunDevice};
use crate::BoxResult;
use ed25519_dalek::VerifyingKey;
use futures_util::StreamExt;
use landscape_rill_core::control::session::{SessionEvent, SessionState};
use landscape_rill_core::frame::VERSION;
use landscape_rill_core::handshake::HandshakeContext;
use landscape_rill_core::rate::{RateCounter, TokenBucket, RATE_SUMMARY_PERIOD};
use landscape_rill_core::route::{RouteEngine, RouteEntry, RouteSource, RouteVia};
use landscape_rill_mesh::control::{ControlEvent, ControlSession, MeshLegConfig, NetmapData};
use landscape_rill_mesh::data::{
    IncomingEvent, MeshData, PathEntry, TcpTransport, UdpTransport, Underlay, UnderlayKind,
};
use probe::RelayEntry;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

pub mod control;
pub mod lan;
pub mod probe;

pub const RECONNECT_INITIAL_BACKOFF: Duration = Duration::from_secs(1);
pub const RECONNECT_MAX_BACKOFF: Duration = Duration::from_secs(300);
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
}

impl Default for NodeOptions {
    fn default() -> Self {
        Self {
            tun: None,
            heartbeat_interval: DEFAULT_HEARTBEAT_INTERVAL,
            data_heartbeat_interval: Duration::from_secs(5),
            data_heartbeat_misses: DATA_HEARTBEAT_MISSES,
            rekey_interval: Duration::from_secs(DEFAULT_SESSION_REKEY_HOURS * 3600),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum LanOutcome {
    /// 已加密帧发往 rill 节点
    Sent { peer: u32 },
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
    control: Option<ControlSession>,
    tun: Option<TunDevice>,
    node_id: Option<u32>,
    network_id: u32,
    netmap_peers: HashSet<u32>,
    key_versions: HashMap<u32, u32>,
    broadcast_key: Option<[u8; 32]>,
    last_control_heartbeat: Instant,
    last_data_heartbeat: Instant,
    next_rekey: Instant,
    reconnect_backoff: Duration,
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
}

impl Node {
    pub async fn new(cfg: Config, opts: NodeOptions) -> BoxResult<Self> {
        cfg.validate()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
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
        Ok(Self {
            cfg,
            opts,
            mesh,
            advertise_ips,
            engine: RouteEngine::new(),
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
            reconnect_backoff: RECONNECT_INITIAL_BACKOFF,
            peer_heartbeats: HashMap::new(),
            pending_path_requests: Vec::new(),
            path_requested: HashSet::new(),
            last_handshake_attempt: HashMap::new(),
            recent_multicast_writes: HashMap::new(),
            rejected_stats: HashMap::new(),
            connect_failed: RateCounter::new(RATE_SUMMARY_PERIOD),
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
        })
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

    fn leg_config(&self) -> MeshLegConfig {
        MeshLegConfig {
            coordinator_host: String::new(),
            coordinator_port: 0,
            auth_key: self.cfg.auth_key.clone(),
            static_key: self.cfg.static_key_seed,
            capabilities: self.cfg.capabilities,
            announce_routes: self.cfg.announce_routes.clone(),
        }
    }

    /// 控制面连接（含初始注册）。重连传上次 node_id（幂等注册/挑战路径）。
    pub async fn connect_control(&mut self) -> BoxResult<()> {
        let (host, port) = Self::parse_url(&self.cfg.coordinator_url)?;
        let ca = std::fs::read(&self.cfg.ca_cert_path)
            .map_err(|e| std::io::Error::new(e.kind(), format!("ca: {}", e)))?;
        let mut leg = self.leg_config();
        leg.coordinator_host = host.clone();
        leg.coordinator_port = port;
        let session = ControlSession::connect(&host, port, &ca, &leg, self.node_id).await?;
        self.control = Some(session);
        info!("[node] control connected to {}:{}", host, port);
        Ok(())
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
                Some(payload)
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
            IncomingEvent::Dropped { reason } => {
                debug!("[node] dropped frame: {:?}", reason);
                None
            }
        }
    }

    /// 定时器：控制面心跳（租约保活）/ 数据面心跳（会话活性 + 3 次超时拆会话）/ rekey
    pub async fn pump_timers(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_control_heartbeat) >= self.opts.heartbeat_interval {
            self.last_control_heartbeat = now;
            if let Some(control) = self.control.as_mut() {
                let hb = control.heartbeat_envelope();
                if control.send_envelope(&hb).await.is_err() {
                    self.control = None;
                }
            }
        }
        // 待发路径请求（netmap 发现 v2 peer 后；随控制面心跳节奏发送）。
        // 收到对应 Paths 事件才移除——即时 PathResponse 可能丢失，靠心跳重发收敛
        if !self.pending_path_requests.is_empty() {
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
                if let Ok(frame) = self.mesh.build_heartbeat_frame(peer) {
                    // 心跳帧同样走路径首跳（会话经 relay 建立后保活同路径）
                    let hop = self.mesh.path_first_hop(peer);
                    let _ = self.mesh.send_to_node_hop(peer, hop, &frame).await;
                }
                if *miss >= self.opts.data_heartbeat_misses {
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

    /// 主循环：控制面事件 / 数据面事件 / tun 入包 / 定时器（v1 单线程）
    pub async fn run(mut self) {
        loop {
            if self.control.is_none() {
                match self.connect_control().await {
                    Ok(()) => self.reconnect_backoff = RECONNECT_INITIAL_BACKOFF,
                    Err(_) => {
                        // 逐条输出 → 周期摘要（LOGGING §5）；退避 1s→300s 保持
                        self.connect_failed.tick();
                        tokio::time::sleep(self.reconnect_backoff).await;
                        self.reconnect_backoff =
                            (self.reconnect_backoff * 2).min(RECONNECT_MAX_BACKOFF);
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
                            self.write_lan(&payload).await;
                        }
                    }
                }
                ev = control_read, if control_ready => {
                    match ev {
                        Ok(ev) => { let _ = self.handle_control_event(ev).await; }
                        Err(_) => { self.control = None; }
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

    async fn handle_mesh_event(&mut self, ev: IncomingEvent) -> Option<bytes::Bytes> {
        match ev {
            IncomingEvent::Established { peer } => {
                info!("[node] session established with {}", peer);
                self.peer_heartbeats.insert(peer, 0);
                None
            }
            IncomingEvent::Rejected { peer, .. } => {
                self.note_rejected(peer);
                None
            }
            IncomingEvent::Data { from, payload } => {
                self.peer_heartbeats.insert(from, 0);
                Some(payload)
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
            IncomingEvent::Dropped { reason } => {
                debug!("[node] dropped frame: {:?}", reason);
                None
            }
        }
    }
}

#[cfg(test)]
mod tests;
