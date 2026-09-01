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
use landscape_rill_core::rate::{RateCounter, RATE_SUMMARY_PERIOD};
use landscape_rill_core::route::{RouteEngine, RouteEntry, RouteSource, RouteVia};
use landscape_rill_mesh::control::{ControlEvent, ControlSession, MeshLegConfig, NetmapData};
use landscape_rill_mesh::data::{IncomingEvent, MeshData, PathEntry};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

pub const RECONNECT_INITIAL_BACKOFF: Duration = Duration::from_secs(1);
pub const RECONNECT_MAX_BACKOFF: Duration = Duration::from_secs(300);
pub const DATA_HEARTBEAT_MISSES: u32 = 3;
/// 握手重试间隔：上次尝试无响应视为该路径 miss（UDP 黑洞探活）
pub const HANDSHAKE_RETRY_INTERVAL: Duration = Duration::from_secs(2);
/// mesh→LAN 广播帧写入 land0 后被内核回送入 tun 的防再泛洪窗口
/// （组播包指纹，FRAME_HEADER §2.6 防环）
pub const MULTICAST_REWRITE_GUARD: Duration = Duration::from_secs(2);

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
}

impl Node {
    pub async fn new(cfg: Config, opts: NodeOptions) -> BoxResult<Self> {
        cfg.validate()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        let mesh = MeshData::bind("0.0.0.0:0".parse()?, 0).await?;
        // 枚举本机非 loopback、非 tun 接口地址（供 EndpointReport 通告；多宿主节点
        // 通告全部端点，coordinator 并入 netmap，对端按可达性选用）
        let advertise_ips = collect_local_ips().await;
        let tun = match &opts.tun {
            Some(tun_cfg) => Some(TunDevice::open(tun_cfg).await?),
            None => None,
        };
        let next_rekey = Instant::now() + opts.rekey_interval;
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
    pub async fn pump_mesh(&mut self) -> Option<Vec<u8>> {
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
            IncomingEvent::Dropped { .. } => None,
        }
    }

    /// LAN 侧入包（tun0 读取的原始 IP 包）：路由裁决 → 懒握手 → 加密帧发送
    pub async fn pump_lan_packet(&mut self, packet: &[u8]) -> LanOutcome {
        let Ok(info) = parse_packet(packet) else {
            return LanOutcome::Dropped;
        };
        // 组播（IPv6 ff00::/8 含 ND solicited-node、IPv4 224.0.0.0/4）→ 泛洪
        // （FRAME_HEADER §2.6）；v1 不含 IPv4 子网定向广播地址
        if info.dst.is_multicast() {
            // 回环防护：本包若刚由 mesh→LAN 广播帧写入 land0（内核回送），跳过泛洪
            // （再泛洪会用新 from 绕过 relay 去重，形成泛洪环）
            let fingerprint = (info.src, info.dst, info.total_len);
            let now = Instant::now();
            self.recent_multicast_writes
                .retain(|_, t| now.duration_since(*t) < MULTICAST_REWRITE_GUARD);
            if self.recent_multicast_writes.contains_key(&fingerprint) {
                return LanOutcome::Local;
            }
            let peers = self.mesh.flood(packet).await;
            return LanOutcome::Flooded { peers };
        }
        let (via, _prefix) = {
            let Some(entry) = self
                .engine
                .lookup_best(&info.dst, &|e| matches!(e.via, RouteVia::Mesh(_)))
            else {
                warn!("[node] no mesh route for {}", info.dst);
                return LanOutcome::Dropped;
            };
            (entry.via.clone(), entry.prefix)
        };
        match via {
            RouteVia::Mesh(peer) => {
                if !self.mesh.has_session(peer) {
                    // 上次握手尝试超时无响应（UDP 黑洞：sendto 成功但被网关丢弃）→
                    // 主路径 miss + 丢弃在途发起状态，下一次调用重新发起 msg1，
                    // 经候选备用路径收敛（CONTROL_PLANE §3.11 快速切换）
                    if self
                        .last_handshake_attempt
                        .get(&peer)
                        .is_some_and(|t| t.elapsed() >= HANDSHAKE_RETRY_INTERVAL)
                    {
                        self.mesh.path_miss_peer(peer);
                        self.mesh.miss_endpoint(peer);
                        self.mesh.drop_initiator(peer);
                    }
                    match self.mesh.initiate_handshake(peer) {
                        Ok(Some(msg1)) => {
                            // 握手帧走候选路径首跳（v1.5：relay 场景经中继建立会话）
                            let hop = self.mesh.path_first_hop(peer);
                            let ok = self
                                .mesh
                                .send_to_node_hop(peer, hop, &msg1)
                                .await
                                .unwrap_or(false);
                            if !ok {
                                // 发送失败（端点未收敛）：放弃在途状态，等 netmap 收敛后重试
                                self.mesh.drop_initiator(peer);
                            } else {
                                self.last_handshake_attempt.insert(peer, Instant::now());
                            }
                            LanOutcome::Handshaking { peer }
                        }
                        Err(e) => {
                            warn!("[node] lan packet: handshake initiate failed: {:?}", e);
                            LanOutcome::Dropped
                        }
                        Ok(None) => LanOutcome::Handshaking { peer },
                    }
                } else {
                    // flow hash：五元组 → 候选路径选择（CONTROL_PLANE §3.11）
                    let flow = flow_hash(&info);
                    match self.mesh.build_data_frame(peer, packet, flow) {
                        Ok((frame, first_hop)) => {
                            match self.mesh.send_to_node_hop(peer, first_hop, &frame).await {
                                Ok(true) => LanOutcome::Sent { peer },
                                _ => LanOutcome::Dropped,
                            }
                        }
                        Err(_) => LanOutcome::Dropped,
                    }
                }
            }
            RouteVia::Dn42(_) | RouteVia::Tailnet(_) | RouteVia::Direct(_) => LanOutcome::Local,
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
                        if let Some(payload) = self.handle_mesh_event(ev) {
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

    async fn write_lan(&mut self, payload: &[u8]) {
        if let Some(tun) = self.tun.as_mut() {
            let _ = tun.write_packet(payload).await;
            // 记录组播指纹：内核会把写入的组播包回送入 tun（回环），防再泛洪
            if let Ok(info) = parse_packet(payload) {
                if info.dst.is_multicast() {
                    let now = Instant::now();
                    self.recent_multicast_writes
                        .retain(|_, t| now.duration_since(*t) < MULTICAST_REWRITE_GUARD);
                    self.recent_multicast_writes
                        .insert((info.src, info.dst, info.total_len), now);
                }
            }
        }
    }

    fn handle_mesh_event(&mut self, ev: IncomingEvent) -> Option<Vec<u8>> {
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
            IncomingEvent::Dropped { .. } => None,
        }
    }

    async fn handle_control_event(&mut self, ev: ControlEvent) -> BoxResult<()> {
        match ev {
            ControlEvent::Registered {
                node_id,
                network_id,
                identity_binding,
            } => {
                self.node_id = Some(node_id);
                self.network_id = network_id;
                self.mesh.set_self_node_id(node_id);
                info!(
                    "[node] registered: node_id={} network_id={}",
                    node_id, network_id
                );
                let ctx = HandshakeContext {
                    network_id,
                    version: VERSION,
                    local_static: self.cfg.static_key_seed,
                    identity_binding,
                };
                self.mesh.set_handshake_context(ctx);
                let vk = VerifyingKey::from_bytes(&self.cfg.coord_signing_pubkey)?;
                self.mesh
                    .set_binding_verifier(move |node_id, static_pubkey, binding| {
                        landscape_rill_coord::signer::verify_binding(
                            &vk,
                            node_id,
                            static_pubkey,
                            binding,
                        )
                    });
                // 端点上报：数据面 UDP 地址（本机各接口 IP + 端口）→ coordinator 并入 netmap
                if let Some(control) = self.control.as_mut() {
                    if let Ok(addr) = self.mesh.local_addr() {
                        let mut eps: Vec<String> = self
                            .advertise_ips
                            .iter()
                            .map(|ip| SocketAddr::new(*ip, addr.port()).to_string())
                            .collect();
                        if eps.is_empty() {
                            eps.push(addr.to_string());
                        }
                        debug!("[node] endpoint report: {:?}", eps);
                        let report = control.endpoint_report_envelope(eps);
                        let _ = control.send_envelope(&report).await;
                    }
                }
            }
            ControlEvent::Netmap(netmap) => {
                // 挑战通过后服务端重推 netmap：Reconnecting → ChallengeOk
                if let Some(control) = self.control.as_mut() {
                    if matches!(control.client().state(), SessionState::Reconnecting { .. }) {
                        let _ = control
                            .client_mut()
                            .session_mut()
                            .handle(SessionEvent::ChallengeOk);
                    }
                }
                self.apply_netmap(&netmap);
                info!(
                    "[node] netmap v{}: {} entries, {} routes, endpoints: {:?}",
                    netmap.version,
                    netmap.entries.len(),
                    netmap.entries.iter().map(|e| e.routes.len()).sum::<usize>(),
                    netmap
                        .entries
                        .iter()
                        .map(|e| (e.node_id, e.endpoints.clone()))
                        .collect::<Vec<_>>()
                );
            }
            ControlEvent::KeyDist {
                to_node_id,
                key,
                key_version,
                broadcast_key,
            } => {
                if key.len() == 32 {
                    let mut k = [0u8; 32];
                    k.copy_from_slice(&key);
                    self.mesh.set_key_dst(to_node_id, k);
                    self.key_versions.insert(to_node_id, key_version);
                }
                // 广播密钥随每条 KeyDist 携带（网络级共享，FRAME_HEADER §2.6）
                if broadcast_key.len() == 32 {
                    let mut b = [0u8; 32];
                    b.copy_from_slice(&broadcast_key);
                    self.broadcast_key = Some(b);
                    self.mesh.set_broadcast_key(b);
                }
            }
            ControlEvent::Lease { granted, .. } => {
                let _ = granted;
            }
            ControlEvent::Challenge { ack } => {
                if let Some(control) = self.control.as_mut() {
                    control.send_envelope(&ack).await?;
                }
            }
            ControlEvent::Revoked { node_id } => {
                self.mesh.drop_session(node_id);
                self.mesh.remove_peer_static(node_id);
                self.mesh.remove_key_dst(node_id);
                self.mesh.remove_endpoint(node_id);
                self.mesh.remove_paths_for(node_id);
                self.engine.remove_mesh_node(node_id);
                self.netmap_peers.remove(&node_id);
                self.peer_heartbeats.remove(&node_id);
                if let Some(control) = self.control.as_mut() {
                    let _ = control
                        .client_mut()
                        .session_mut()
                        .handle(SessionEvent::Revoked { node_id });
                }
            }
            ControlEvent::Paths {
                destination_node_id,
                candidates,
                source_node_id,
                ..
            } => {
                // key_path 全部注入（路径级授权，CONTROL_PLANE §3.11.5：参与者校验/转发用）
                for c in &candidates {
                    if c.key_path.len() == 32 {
                        let mut kp = [0u8; 32];
                        kp.copy_from_slice(&c.key_path);
                        self.mesh.set_key_path(c.path_id, kp);
                    }
                }
                // 发送路径表只写自己发起的路径（source = 自己）；作为 dest/relay
                // 参与者收到的其他源路径仅注入 key_path（覆盖会污染发送选择表）
                if source_node_id == self.node_id.unwrap_or(u32::MAX) {
                    let entries: Vec<PathEntry> = candidates
                        .iter()
                        .map(|c| PathEntry {
                            path_id: c.path_id,
                            path_epoch: c.path_epoch,
                            hops: c.hops.clone(),
                            expires_at: c.expires_at,
                        })
                        .collect();
                    self.mesh.set_paths(destination_node_id, entries);
                    // 已收敛：该 dest 的请求不再重发
                    self.pending_path_requests
                        .retain(|d| *d != destination_node_id);
                }
                debug!(
                    "[node] paths to {} (src {}) {:?} (kp: {:?})",
                    destination_node_id,
                    source_node_id,
                    candidates
                        .iter()
                        .map(|c| (c.path_id, c.hops.clone()))
                        .collect::<Vec<_>>(),
                    candidates
                        .iter()
                        .map(|c| (c.path_id, c.key_path.len()))
                        .collect::<Vec<_>>()
                );
            }
            ControlEvent::PathWithdrawn {
                destination_node_id,
                path_id,
            } => {
                self.mesh.withdraw_path(destination_node_id, path_id);
                debug!(
                    "[node] path withdrawn {} -> {}",
                    destination_node_id, path_id
                );
            }
        }
        Ok(())
    }

    /// netmap 全量替换语义（CONTROL_PLANE §3.2）：peer 静态公钥/端点/mesh 路由重建
    fn apply_netmap(&mut self, netmap: &NetmapData) {
        let mut fresh: HashSet<u32> = HashSet::new();
        self.engine.reset_mesh_routes();
        for entry in &netmap.entries {
            if Some(entry.node_id) == self.node_id {
                continue;
            }
            fresh.insert(entry.node_id);
            self.mesh
                .set_peer_static(entry.node_id, entry.static_pubkey);
            let mut addrs: Vec<SocketAddr> = Vec::new();
            for ep in &entry.endpoints {
                if let Ok(addr) = ep.parse::<SocketAddr>() {
                    addrs.push(addr);
                }
            }
            self.mesh.set_endpoints(entry.node_id, addrs);
            for route in &entry.routes {
                if let Ok(prefix) = landscape_rill_core::route::Prefix::parse(route) {
                    self.engine.insert(RouteEntry {
                        prefix,
                        source: RouteSource::Mesh,
                        via: RouteVia::Mesh(entry.node_id),
                        metric: None,
                    });
                }
            }
            // v2 peer（protocol_version >= 2）：请求候选路径（v1.5，CONTROL_PLANE §3.11）
            if entry.protocol_version >= 2 {
                self.request_paths_for(entry.node_id);
            }
        }
        for stale in self.netmap_peers.difference(&fresh) {
            self.mesh.remove_peer_static(*stale);
            self.mesh.remove_endpoint(*stale);
            self.mesh.drop_session(*stale);
            self.mesh.remove_paths_for(*stale);
            self.engine.remove_mesh_node(*stale);
        }
        self.netmap_peers = fresh;
    }

    /// 登记待发路径请求（netmap 全量替换每次都会触发，幂等：重复请求 = 刷新路径集）
    fn request_paths_for(&mut self, dest: u32) {
        self.path_requested.insert(dest);
        if !self.pending_path_requests.contains(&dest) {
            self.pending_path_requests.push(dest);
        }
    }
}
/// flow hash：五元组（src/dst/proto）FNV-1a——同流同路径，负载均衡不拆流
/// （CONTROL_PLANE §3.11 候选路径 flow hash 选择）
fn flow_hash(info: &PacketInfo) -> u64 {
    fn addr_bytes(ip: IpAddr) -> Vec<u8> {
        match ip {
            IpAddr::V4(v4) => v4.octets().to_vec(),
            IpAddr::V6(v6) => v6.octets().to_vec(),
        }
    }
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in addr_bytes(info.src)
        .iter()
        .chain(addr_bytes(info.dst).iter())
    {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h ^= match info.proto {
        TransportProto::Tcp => 6,
        TransportProto::Udp => 17,
        TransportProto::Icmp => 1,
        TransportProto::Icmpv6 => 58,
        TransportProto::Other(v) => v as u64,
    };
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use landscape_rill_core::control::registry::AuthKeyPolicy;
    use landscape_rill_mesh::control::{server_tls_stream, CoordinatorServer};
    use std::net::IpAddr;
    use std::sync::Arc;
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;

    fn coord_ca() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let _ = rustls::crypto::ring::default_provider().install_default();
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

    /// 唯一 CA 路径（并行测试互不覆盖）
    fn unique_ca_path() -> String {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        format!("/tmp/landscape-test-ca-{}-{}.pem", std::process::id(), n)
    }

    /// 启动共享 coordinator（每连接独立任务，注册表共享）
    async fn start_coord() -> (String, String) {
        let (ca, cert, key) = coord_ca();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let master = [0x11; 32];
        let seed = [0x22; 32];
        let server = Arc::new(Mutex::new(CoordinatorServer::new(master, seed)));
        let ak = auth_test_key();
        server
            .lock()
            .await
            .coordinator
            .add_auth_key(&ak, AuthKeyPolicy::Reusable);
        server.lock().await.coordinator.set_announce_whitelist(vec![
            landscape_rill_core::route::Prefix::parse("10.0.0.0/8").unwrap(),
        ]);
        let srv = server.clone();
        tokio::spawn(async move {
            let mut listener = listener;
            loop {
                let mut tls = server_tls_stream(&mut listener, &cert, &key).await.unwrap();
                let srv = srv.clone();
                tokio::spawn(async move {
                    // 按消息粒度持锁（避免长连接互斥死锁）
                    let mut conn = landscape_rill_mesh::control::ConnectionState::default();
                    loop {
                        let (msg_type, body) =
                            match landscape_rill_mesh::control::read_envelope(&mut tls).await {
                                Ok(v) => v,
                                Err(_) => break,
                            };
                        let mut guard = srv.lock().await;
                        if guard
                            .handle_message(&mut conn, &mut tls, msg_type, &body)
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                });
            }
        });
        let ca_path = unique_ca_path();
        std::fs::write(&ca_path, &ca).unwrap();
        (format!("https://127.0.0.1:{}", addr.port()), ca_path)
    }

    fn node_config(url: &str, ca_path: &str, seed: u8, routes: Vec<String>) -> Config {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x22; 32]);
        Config {
            coordinator_url: url.into(),
            auth_key: auth_test_key(),
            static_key_seed: [seed; 32],
            capabilities: 0x01,
            announce_routes: routes,
            coord_signing_pubkey: VerifyingKey::from(&signing_key).to_bytes(),
            ca_cert_path: ca_path.into(),
            coord: None,
        }
    }

    /// 与 start_coord 共享的 key（测试专用；生成一次全局复用，24h 有效）
    fn auth_test_key() -> String {
        static KEY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        KEY.get_or_init(|| landscape_rill_coord::authkey::generate_auth_key("lab", 86_400).unwrap())
            .clone()
    }

    fn v4_packet(dst: [u8; 4]) -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&20u16.to_be_bytes());
        p[9] = 17;
        p[12..16].copy_from_slice(&[10, 0, 0, 1]);
        p[16..20].copy_from_slice(&dst);
        p
    }

    /// IPv6 组播包（ND solicited-node 形态，dst=ff02::1:ffxx:xxxx）
    fn v6_multicast_packet(dst: [u8; 16]) -> Vec<u8> {
        let mut p = vec![0u8; 40];
        p[0] = 0x60;
        p[6] = 58;
        p[8..24].copy_from_slice(&[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        p[24..40].copy_from_slice(&dst);
        p
    }

    /// 测试用短心跳（端点收敛快）
    fn fast_opts() -> NodeOptions {
        NodeOptions {
            heartbeat_interval: Duration::from_millis(300),
            data_heartbeat_interval: Duration::from_secs(3600),
            data_heartbeat_misses: 99,
            ..NodeOptions::default()
        }
    }

    /// 泵到全部节点满足条件（控制面/数据面/定时器交替；每次泵带超时——无事件时立即继续）
    async fn pump_until_all<F: FnMut(&mut Node) -> bool>(
        nodes: &mut [&mut Node],
        label: &str,
        mut cond: F,
    ) {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            assert!(
                Instant::now() < deadline,
                "pump_until_all timeout [{}]",
                label
            );
            for node in nodes.iter_mut() {
                let _ = tokio::time::timeout(Duration::from_millis(100), node.pump_control()).await;
                let _ = tokio::time::timeout(Duration::from_millis(100), node.pump_mesh()).await;
                node.pump_timers().await;
            }
            if nodes.iter_mut().all(|n| cond(n)) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// 反复触发 A→B 懒握手直到会话建立（端点随心跳收敛后重试自然成功）
    async fn establish_session(a: &mut Node, b: &mut Node, packet: &[u8], peer: u32) {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            assert!(Instant::now() < deadline, "establish_session timeout");
            let _ = a.pump_lan_packet(packet).await;
            let _ = tokio::time::timeout(Duration::from_millis(100), a.pump_mesh()).await;
            let _ = tokio::time::timeout(Duration::from_millis(100), b.pump_mesh()).await;
            let _ = tokio::time::timeout(Duration::from_millis(100), a.pump_control()).await;
            let _ = tokio::time::timeout(Duration::from_millis(100), b.pump_control()).await;
            if a.has_session(peer) && b.has_session(a.node_id().unwrap()) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    #[tokio::test]
    async fn e2e_register_netmap_keydist_handshake_data() {
        let (url, ca) = start_coord().await;
        let mut a = Node::new(
            node_config(&url, &ca, 1, vec!["10.0.0.0/24".into()]),
            fast_opts(),
        )
        .await
        .unwrap();
        let mut b = Node::new(
            node_config(&url, &ca, 2, vec!["10.0.0.0/24".into()]),
            fast_opts(),
        )
        .await
        .unwrap();

        a.connect_control().await.unwrap();
        b.connect_control().await.unwrap();

        // 注册 + netmap（含路由公告）+ keydist + 端点上报（随心跳收敛）
        pump_until_all(&mut [&mut a, &mut b], "registered", |n| n.registered()).await;
        pump_until_all(&mut [&mut a, &mut b], "keydst2", |n| n.mesh.has_key_dst(2)).await;
        pump_until_all(&mut [&mut a, &mut b], "keydst1", |n| n.mesh.has_key_dst(1)).await;
        pump_until_all(&mut [&mut a, &mut b], "routes", |n| {
            !n.engine
                .lookup(&"10.0.0.2".parse::<IpAddr>().unwrap())
                .is_empty()
        })
        .await;

        // A → B：懒握手 → 加密帧 → B 解密
        let packet = v4_packet([10, 0, 0, 2]);
        establish_session(&mut a, &mut b, &packet, 2).await;
        assert_eq!(
            a.pump_lan_packet(&packet).await,
            LanOutcome::Sent { peer: 2 }
        );
        let payload = b.pump_mesh().await.expect("B 应收到解密载荷");
        assert_eq!(payload, packet);

        // 反向
        establish_session(&mut b, &mut a, &packet, 1).await;
        assert_eq!(
            b.pump_lan_packet(&packet).await,
            LanOutcome::Sent { peer: 1 }
        );
        let payload = a.pump_mesh().await.expect("A 应收到解密载荷");
        assert_eq!(payload, packet);
    }

    #[tokio::test]
    async fn multicast_flooded_across_nodes() {
        let (url, ca) = start_coord().await;
        let mut a = Node::new(
            node_config(&url, &ca, 1, vec!["10.0.0.0/24".into()]),
            fast_opts(),
        )
        .await
        .unwrap();
        let mut b = Node::new(
            node_config(&url, &ca, 2, vec!["10.0.0.0/24".into()]),
            fast_opts(),
        )
        .await
        .unwrap();
        a.connect_control().await.unwrap();
        b.connect_control().await.unwrap();
        pump_until_all(&mut [&mut a, &mut b], "registered", |n| n.registered()).await;
        pump_until_all(&mut [&mut a, &mut b], "broadcast_key", |n| {
            n.broadcast_key.is_some()
        })
        .await;
        pump_until_all(&mut [&mut a, &mut b], "endpoints", |n| {
            let peer = if n.node_id() == Some(1) { 2 } else { 1 };
            n.mesh.endpoint(peer).is_some()
        })
        .await;

        // IPv6 组播（ND NS）→ 泛洪（不走路由表，无需会话）
        let ns = v6_multicast_packet([
            0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0x00, 0x00, 0x02,
        ]);
        assert_eq!(
            a.pump_lan_packet(&ns).await,
            LanOutcome::Flooded { peers: 1 }
        );
        assert_eq!(b.pump_mesh().await.expect("B 应收到广播解密载荷"), ns);
    }

    #[tokio::test]
    async fn data_heartbeat_misses_drop_session() {
        let (url, ca) = start_coord().await;
        let mut a = Node::new(
            node_config(&url, &ca, 1, vec!["10.0.0.0/24".into()]),
            fast_opts(),
        )
        .await
        .unwrap();
        let mut b = Node::new(
            node_config(&url, &ca, 2, vec!["10.0.0.0/24".into()]),
            fast_opts(),
        )
        .await
        .unwrap();
        a.connect_control().await.unwrap();
        b.connect_control().await.unwrap();
        pump_until_all(&mut [&mut a, &mut b], "registered", |n| n.registered()).await;
        pump_until_all(&mut [&mut a, &mut b], "keydst2", |n| n.mesh.has_key_dst(2)).await;
        pump_until_all(&mut [&mut a, &mut b], "routes", |n| {
            !n.engine
                .lookup(&"10.0.0.2".parse::<IpAddr>().unwrap())
                .is_empty()
        })
        .await;

        let packet = v4_packet([10, 0, 0, 2]);
        establish_session(&mut a, &mut b, &packet, 2).await;

        // B 不再泵（收不到心跳）→ A 侧 3 次 miss 后拆会话
        a.opts.data_heartbeat_interval = Duration::from_millis(50);
        a.opts.data_heartbeat_misses = 3;
        a.peer_heartbeats.insert(2, 0);
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            assert!(Instant::now() < deadline, "session drop timeout");
            a.pump_timers().await;
            if !a.has_session(2) {
                break;
            }
        }
        assert!(!a.has_session(2));
    }

    #[test]
    fn config_rejects_missing_trust_anchors() {
        let mut c = node_config("https://coord.test:8443", "/tmp/x.pem", 1, vec![]);
        c.coord_signing_pubkey = [0; 32];
        assert!(c.validate().is_err());
        c.coord_signing_pubkey = [7; 32];
        c.ca_cert_path = "".into();
        assert!(c.validate().is_err());
    }
}
