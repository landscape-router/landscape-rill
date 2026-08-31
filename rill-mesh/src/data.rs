use landscape_rill_core::frame::{
    build_frame, build_handshake_frame, frame_payload, open_frame, packet_type, MeshFrameHeader,
    ReplayWindow, BROADCAST_NODE_ID, HEADER_LEN, VERSION, VERSION2,
};
use landscape_rill_core::handshake::{
    HandshakeContext, HandshakeError, HandshakeInitiator, HandshakeResponder, Session,
    MSG1_PAYLOAD_LEN, MSG2_PAYLOAD_LEN, MSG3_PAYLOAD_LEN,
};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

/// 广播泛洪令牌桶参数（FRAME_HEADER §2.6）：容量 64、补充 16/s
pub const FLOOD_BUCKET_CAPACITY: u32 = 64;
pub const FLOOD_BUCKET_RATE_PER_SEC: f64 = 16.0;
/// 泛洪去重 seen 集条目存活时长
pub const FLOOD_SEEN_TTL: Duration = Duration::from_secs(30);
/// 主路径健康 miss 阈值：累计达此值 → 快速切换备用路径（CONTROL_PLANE §3.11）
pub const PATH_HEALTH_MISS_LIMIT: u32 = 3;

fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// coordinator 公钥持有者注入的身份绑定校验器（与签名算法解耦）
pub type BindingVerifier = dyn Fn(u32, &[u8; 32], &[u8]) -> bool + Send + Sync;

/// v2 候选路径条目（CONTROL_PLANE §3.11）：hops 显式（direct = [dest]，relay = [relay, dest]）
#[derive(Debug, Clone)]
pub struct PathEntry {
    pub path_id: u64,
    pub path_epoch: u32,
    /// 有序跳（首跳 = 发送端点；转发节点按自己在路径中的位置取下一跳）
    pub hops: Vec<u32>,
    /// unix 秒过期
    pub expires_at: u64,
}

impl PathEntry {
    pub fn expired(&self, now_unix: u64) -> bool {
        self.expires_at != 0 && now_unix > self.expires_at
    }
}

pub struct MeshData {
    socket: UdpSocket,
    key_dst_table: HashMap<u32, [u8; 32]>,
    /// 端点表：node_id → 候选端点列表（多宿主通告全部；发送按可达性逐个尝试）
    endpoint_table: HashMap<u32, Vec<SocketAddr>>,
    self_node_id: u32,
    ctx: Option<HandshakeContext>,
    peer_statics: HashMap<u32, [u8; 32]>,
    binding_verifier: Option<Box<BindingVerifier>>,
    initiators: HashMap<u32, HandshakeInitiator>,
    responders: HashMap<u32, HandshakeResponder>,
    sessions: HashMap<u32, Session>,
    /// 广播密钥（keydist 下发，FRAME_HEADER §2.6）：AEAD 与 route_mac 共用
    broadcast_key: Option<[u8; 32]>,
    /// 每源全局广播计数器（广播 = 虚拟会话，独立于节点对 seq）
    broadcast_seq: u32,
    /// 广播重放窗口：按 from_node_id 每源一个
    broadcast_replay: HashMap<u32, ReplayWindow>,
    /// relay 泛洪去重集：(from_node_id, seq) → 首次见时间
    flood_seen: HashMap<(u32, u32), Instant>,
    /// 泛洪出口令牌桶（发送与转发共用）
    flood_bucket: TokenBucket,
    /// v2 路径授权密钥：path_id → key_path（coordinator 签发，只发路径参与者）
    key_path_table: HashMap<u64, [u8; 32]>,
    /// v2 候选路径表：dest → 候选路径集合（2~4 条）
    path_table: HashMap<u32, Vec<PathEntry>>,
    /// 主路径健康 miss 计数（快速切换，CONTROL_PLANE §3.11）
    path_health: HashMap<u64, u32>,
    /// 入站路径记录：from_node_id → 帧实际到达的上一跳（UDP 发送者归属节点；
    /// 直连 = from 自身，经中继 = relay 节点）。逐路径活性更新的依据。
    ingress_hop: HashMap<u32, u32>,
    /// 端点活性 miss 计数：(端点归属节点, 端点) → miss。发送成功但无响应
    /// （UDP 黑洞：sendto Ok 但包被网关丢弃）时由握手重试/心跳驱动递增，
    /// 发送排序时活性差的端点置后，逐个排除。
    endpoint_health: HashMap<(u32, SocketAddr), u32>,
    /// 上次对该发送目标实际使用的端点（miss 定位用——黑洞端点无法从收包侧感知）
    last_sent_endpoint: HashMap<u32, SocketAddr>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RelayOutcome {
    Forwarded {
        to: u32,
    },
    Delivered {
        frame: Vec<u8>,
        from: u32,
    },
    /// 广播帧：自交付 + 泛洪转发（FRAME_HEADER §2.6）
    Flooded {
        frame: Vec<u8>,
        from: u32,
        forwarded: Vec<u32>,
    },
    Dropped {
        reason: DropReason,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    BadVersion,
    BadRouteMac,
    TtlExpired,
    NoEndpoint,
    NoKeyDst,
    Short,
    NoSession,
    Aead,
    Replay,
    UnsupportedType,
    Duplicate,
    RateLimited,
}

#[derive(Debug, PartialEq)]
pub enum SendError {
    NoSession,
    NoKeyDst,
    NoContext,
    NoPeerBinding,
    Handshake(HandshakeError),
    Aead,
}

#[derive(Debug, PartialEq)]
pub enum IncomingEvent {
    /// 已建会话的解密数据载荷（AEAD 解密收尾出口）
    Data {
        from: u32,
        payload: Vec<u8>,
    },
    /// 心跳帧（AEAD 空载荷，仅已建会话对）
    Heartbeat {
        from: u32,
    },
    /// 握手完成，会话建立（双方各在自己的收帧侧触发一次）
    Established {
        peer: u32,
    },
    /// 握手进行中，响应帧已回发（msg1→msg2）
    Responded {
        peer: u32,
    },
    /// 握手被拒绝（携带原因）
    Rejected {
        peer: u32,
        reason: HandshakeError,
    },
    /// 中继转发
    Relayed {
        to: u32,
    },
    /// 广播帧解密载荷（广播密钥，FRAME_HEADER §2.6）
    Broadcast {
        from: u32,
        payload: Vec<u8>,
    },
    Dropped {
        reason: DropReason,
    },
}

/// 令牌桶（泛洪限速，FRAME_HEADER §2.6）
#[derive(Debug)]
pub struct TokenBucket {
    capacity: u32,
    rate_per_sec: f64,
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    pub fn new(rate_per_sec: f64, capacity: u32) -> Self {
        Self {
            capacity,
            rate_per_sec,
            tokens: capacity as f64,
            last: Instant::now(),
        }
    }

    /// 尝试取一个令牌；桶空返回 false
    pub fn take(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate_per_sec).min(self.capacity as f64);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

impl MeshData {
    pub async fn bind(bind: SocketAddr, self_node_id: u32) -> std::io::Result<Self> {
        let socket = UdpSocket::bind(bind).await?;
        Ok(Self {
            socket,
            key_dst_table: HashMap::new(),
            endpoint_table: HashMap::new(),
            self_node_id,
            ctx: None,
            peer_statics: HashMap::new(),
            binding_verifier: None,
            initiators: HashMap::new(),
            responders: HashMap::new(),
            sessions: HashMap::new(),
            broadcast_key: None,
            broadcast_seq: 0,
            broadcast_replay: HashMap::new(),
            flood_seen: HashMap::new(),
            flood_bucket: TokenBucket::new(FLOOD_BUCKET_RATE_PER_SEC, FLOOD_BUCKET_CAPACITY),
            key_path_table: HashMap::new(),
            path_table: HashMap::new(),
            path_health: HashMap::new(),
            ingress_hop: HashMap::new(),
            endpoint_health: HashMap::new(),
            last_sent_endpoint: HashMap::new(),
        })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// 注册完成后由 runtime 注入真实 node_id（bind 时未知）
    pub fn set_self_node_id(&mut self, node_id: u32) {
        self.self_node_id = node_id;
    }

    // ==================== v2 路径 API（CONTROL_PLANE §3.11） ====================

    /// key_path 注入（PathResponse 签发，只发路径参与者）；轮换 = 同 path_id 覆盖
    pub fn set_key_path(&mut self, path_id: u64, key: [u8; 32]) {
        self.key_path_table.insert(path_id, key);
    }

    pub fn remove_key_path(&mut self, path_id: u64) {
        self.key_path_table.remove(&path_id);
        self.path_health.remove(&path_id);
    }

    pub fn has_key_path(&self, path_id: u64) -> bool {
        self.key_path_table.contains_key(&path_id)
    }

    /// 候选路径集注入（PathResponse/PathUpdate）；同 dest 全量替换。
    /// key_path 生命周期由 withdraw_path/remove_paths_for 管理（不在此清理——
    /// 跨 dest 的全局清理会误删其他路径集的授权密钥）。
    pub fn set_paths(&mut self, dest: u32, paths: Vec<PathEntry>) {
        self.path_table.insert(dest, paths);
    }

    /// PathWithdraw：移除某路径；空集时移除该 dest 的路径表
    pub fn withdraw_path(&mut self, dest: u32, path_id: u64) {
        self.remove_key_path(path_id);
        if let Some(paths) = self.path_table.get_mut(&dest) {
            paths.retain(|p| p.path_id != path_id);
            if paths.is_empty() {
                self.path_table.remove(&dest);
            }
        }
    }

    pub fn paths_for(&self, dest: u32) -> Option<&Vec<PathEntry>> {
        self.path_table.get(&dest)
    }

    /// 吊销联动：清空该 dest 的全部路径（runtime Revoked 事件）
    pub fn remove_paths_for(&mut self, dest: u32) {
        if let Some(paths) = self.path_table.remove(&dest) {
            for p in paths {
                self.key_path_table.remove(&p.path_id);
                self.path_health.remove(&p.path_id);
            }
        }
    }

    /// flow hash 选路径（每目标 2~4 候选）：首选未过期、有 key_path 的路径；
    /// 主路径健康 miss 达阈值 → 切备用（快速切换）。
    pub fn pick_path(&mut self, dest: u32, flow_hash: u64) -> Option<PathEntry> {
        let now = unix_seconds();
        let paths = self.path_table.get(&dest)?;
        let live: Vec<&PathEntry> = paths
            .iter()
            .filter(|p| !p.expired(now) && self.key_path_table.contains_key(&p.path_id))
            .collect();
        if live.is_empty() {
            return None;
        }
        // 主路径 = 有序候选第一条；flow hash 仅在候选健康时做负载
        let healthy: Vec<&PathEntry> = live
            .iter()
            .copied()
            .filter(|p| {
                self.path_health.get(&p.path_id).copied().unwrap_or(0) < PATH_HEALTH_MISS_LIMIT
            })
            .collect();
        let pool = if healthy.is_empty() { live } else { healthy };
        let idx = (flow_hash as usize) % pool.len();
        Some(pool[idx].clone())
    }

    /// 路径活性上报：健康 miss 清零 / 累计（runtime 按数据面心跳/PathProbe 喂）
    pub fn path_miss(&mut self, path_id: u64) {
        let miss = self.path_health.entry(path_id).or_insert(0);
        *miss = miss.saturating_add(1);
    }

    pub fn path_ok(&mut self, path_id: u64) {
        self.path_health.insert(path_id, 0);
    }

    /// peer 级：数据面心跳 miss → 该 peer 主路径（候选第一条）miss（快速切换，
    /// CONTROL_PLANE §3.11——备用路径活性由独立探活承担）
    pub fn path_miss_peer(&mut self, dest: u32) {
        if let Some(paths) = self.path_table.get(&dest).cloned() {
            if let Some(main) = paths.first() {
                self.path_miss(main.path_id);
            }
        }
    }

    /// peer 级：收包成功 → 该 peer 全部路径健康恢复
    pub fn path_ok_peer(&mut self, dest: u32) {
        if let Some(paths) = self.path_table.get(&dest).cloned() {
            for p in paths {
                self.path_ok(p.path_id);
            }
        }
    }

    /// 逐路径活性（v1.5）：按帧实际到达的上一跳更新——首跳 == 入站跳的路径
    /// ok，其余 miss。直连帧（入站 == 源节点）全 ok；经中继的帧证明中继路径
    /// 存活、直连路径死亡，避免收到中继帧误重置直连 miss（不对称拓扑快速切换）。
    fn apply_ingress_health(&mut self, from: u32) {
        let Some(ingress) = self.ingress_hop.get(&from).copied() else {
            return;
        };
        let Some(paths) = self.path_table.get(&from).cloned() else {
            return;
        };
        for p in paths {
            let hop0 = p.hops.first().copied().unwrap_or(from);
            if hop0 == ingress {
                self.path_ok(p.path_id);
            } else {
                self.path_miss(p.path_id);
            }
        }
    }

    /// 端点归属反查：UDP 发送者地址 → 节点（NAT 改写等未匹配场景 = None）
    fn endpoint_owner(&self, addr: SocketAddr) -> Option<u32> {
        self.endpoint_table
            .iter()
            .find_map(|(id, addrs)| addrs.contains(&addr).then_some(*id))
    }

    /// 发送端点排序：活性 miss 少优先；同活性时上次未用的优先（轮换尝试，
    /// 避免黑洞端点被反复选中）
    fn order_endpoints(&self, hop: u32, dest: u32, addrs: &mut [SocketAddr]) {
        let last = self.last_sent_endpoint.get(&dest).copied();
        addrs.sort_by_key(|a| {
            (
                self.endpoint_health.get(&(hop, *a)).copied().unwrap_or(0),
                Some(*a) == last,
            )
        });
    }

    /// 端点级活性 miss：上次对该目标实际使用的端点 miss+1（UDP 黑洞端点
    /// 逐个排除，与 path_miss_peer 同源驱动）
    pub fn miss_endpoint(&mut self, dest: u32) {
        let Some(addr) = self.last_sent_endpoint.get(&dest).copied() else {
            return;
        };
        let Some(owner) = self.endpoint_owner(addr) else {
            return;
        };
        let m = self.endpoint_health.entry((owner, addr)).or_insert(0);
        *m = m.saturating_add(1);
    }

    /// 收帧：来源端点活性恢复（入站帧证明该端点可达）
    fn note_endpoint_ok(&mut self, owner: u32, addr: SocketAddr) {
        if let Some(m) = self.endpoint_health.get_mut(&(owner, addr)) {
            *m = 0;
        }
    }

    pub fn set_key_dst(&mut self, node_id: u32, key: [u8; 32]) {
        self.key_dst_table.insert(node_id, key);
    }

    pub fn remove_key_dst(&mut self, node_id: u32) {
        self.key_dst_table.remove(&node_id);
    }

    /// 全量替换端点列表（netmap 全量语义）；过滤无 scope 的链路本地地址（不可路由）
    pub fn set_endpoints(&mut self, node_id: u32, addrs: Vec<SocketAddr>) {
        let usable: Vec<SocketAddr> = addrs
            .into_iter()
            .filter(|a| {
                !a.ip().is_unspecified()
                    && match a.ip() {
                        IpAddr::V6(v6) => !v6.is_unicast_link_local(),
                        _ => true,
                    }
            })
            .collect();
        if !usable.is_empty() {
            self.endpoint_table.insert(node_id, usable);
        }
    }

    /// 单端点注入（测试/单端点场景便捷入口）
    pub fn set_endpoint(&mut self, node_id: u32, addr: SocketAddr) {
        self.set_endpoints(node_id, vec![addr]);
    }

    pub fn endpoint(&self, node_id: u32) -> Option<SocketAddr> {
        self.endpoint_table
            .get(&node_id)
            .and_then(|v| v.first())
            .copied()
    }

    pub fn set_handshake_context(&mut self, ctx: HandshakeContext) {
        self.ctx = Some(ctx);
    }

    /// netmap 注入：peer 静态公钥（发起方 msg3 后交叉验证依据）
    pub fn set_peer_static(&mut self, peer: u32, static_pubkey: [u8; 32]) {
        self.peer_statics.insert(peer, static_pubkey);
    }

    pub fn remove_peer_static(&mut self, peer: u32) {
        self.peer_statics.remove(&peer);
    }

    pub fn remove_endpoint(&mut self, peer: u32) {
        self.endpoint_table.remove(&peer);
    }

    /// coordinator 公钥持有者注入：`verify(node_id, static_pubkey, binding)`，
    /// 与签名算法解耦（coord/ 的 verify_binding 是标准实现）。
    pub fn set_binding_verifier<F>(&mut self, verify: F)
    where
        F: Fn(u32, &[u8; 32], &[u8]) -> bool + Send + Sync + 'static,
    {
        self.binding_verifier = Some(Box::new(verify));
    }

    /// 广播密钥注入（keydist 下发，FRAME_HEADER §2.6）。轮换时重置广播重放窗口与去重集。
    pub fn set_broadcast_key(&mut self, key: [u8; 32]) {
        self.broadcast_key = Some(key);
        self.broadcast_replay.clear();
        self.flood_seen.clear();
    }

    pub fn has_session(&self, peer: u32) -> bool {
        self.sessions.contains_key(&peer)
    }

    pub fn has_key_dst(&self, node_id: u32) -> bool {
        self.key_dst_table.contains_key(&node_id)
    }

    pub fn sessions(&self) -> impl Iterator<Item = &Session> {
        self.sessions.values()
    }

    pub fn sessions_mut(&mut self) -> impl Iterator<Item = &mut Session> {
        self.sessions.values_mut()
    }

    /// 丢弃会话（rekey 链失同步等场景，runtime 决定重新握手）
    pub fn drop_session(&mut self, peer: u32) {
        self.sessions.remove(&peer);
    }

    /// 丢弃在途发起状态（msg1 发送失败等场景，允许下次重试）
    pub fn drop_initiator(&mut self, peer: u32) {
        self.initiators.remove(&peer);
    }

    /// 主动发起握手（懒握手入口）。已有会话 → Ok(None)；
    /// 在途握手中 → Ok(None)（不重复发起，避免 eph 状态轮换）；
    /// 否则返回 msg1 帧供调用方发送。
    pub fn initiate_handshake(&mut self, peer: u32) -> Result<Option<Vec<u8>>, SendError> {
        if self.sessions.contains_key(&peer) || self.initiators.contains_key(&peer) {
            return Ok(None);
        }
        let ctx = self.ctx.as_ref().ok_or(SendError::NoContext)?;
        let peer_static = self
            .peer_statics
            .get(&peer)
            .copied()
            .ok_or(SendError::NoPeerBinding)?;
        let mut initiator = HandshakeInitiator::new(
            &ctx.local_static,
            ctx.network_id,
            ctx.version,
            peer,
            &ctx.identity_binding,
            rand::random::<u32>(),
            &peer_static,
        )
        .map_err(SendError::Handshake)?;
        let msg1 = initiator.write_msg1().map_err(SendError::Handshake)?;
        self.initiators.insert(peer, initiator);
        Ok(Some(self.build_handshake_frame(peer, &msg1)?))
    }

    /// 构建加密数据帧（seq 自增）。需会话已建立。
    /// 返回 (帧, 首跳)：有 v2 路径时首跳 = 路径第一跳（经 relay），帧为 v2 帧头；
    /// 否则首跳 = None（直连 dest），帧为 v1 帧头（path_id=0 隐式默认路径，v1 兼容）。
    pub fn build_data_frame(
        &mut self,
        to: u32,
        payload: &[u8],
        flow_hash: u64,
    ) -> Result<(Vec<u8>, Option<u32>), SendError> {
        let path = self.pick_path(to, flow_hash);
        let frame = match path {
            Some(ref p) => self.build_typed_frame_v2(to, p, packet_type::UNICAST, payload)?,
            None => self.build_typed_frame(to, packet_type::UNICAST, payload)?,
        };
        let first_hop = path.as_ref().and_then(|p| p.hops.first()).copied();
        Ok((frame, first_hop))
    }

    /// 心跳帧（AEAD 空载荷，仅已建会话对；CONNECTIVITY §6 / FRAME_HEADER §2.5）。
    /// 心跳恒走默认路径（v1 帧头 + key_dst）——路径活性由 PathProbe 承担。
    pub fn build_heartbeat_frame(&mut self, to: u32) -> Result<Vec<u8>, SendError> {
        self.build_typed_frame(to, packet_type::HEARTBEAT, &[])
    }

    /// v2 数据帧：路径授权（key_path 签发 route_mac），path_id 纳入 AAD（FRAME_HEADER §9）
    fn build_typed_frame_v2(
        &mut self,
        to: u32,
        path: &PathEntry,
        packet_type: u8,
        payload: &[u8],
    ) -> Result<Vec<u8>, SendError> {
        let session = self.sessions.get_mut(&to).ok_or(SendError::NoSession)?;
        let key_path = self
            .key_path_table
            .get(&path.path_id)
            .copied()
            .ok_or(SendError::NoKeyDst)?;
        let seq = session.next_seq();
        let header = MeshFrameHeader {
            version: VERSION2,
            packet_type,
            to_node_id: to,
            from_node_id: self.self_node_id,
            seq,
            path_id: path.path_id,
            ..Default::default()
        };
        build_frame(
            &header,
            &key_path,
            &session.keys().tx_key,
            session.keys().salt,
            payload,
        )
        .map_err(|_| SendError::Aead)
    }

    fn build_typed_frame(
        &mut self,
        to: u32,
        packet_type: u8,
        payload: &[u8],
    ) -> Result<Vec<u8>, SendError> {
        let session = self.sessions.get_mut(&to).ok_or(SendError::NoSession)?;
        let key_dst = self.key_dst_table.get(&to).ok_or(SendError::NoKeyDst)?;
        let seq = session.next_seq();
        let header = MeshFrameHeader {
            packet_type,
            to_node_id: to,
            from_node_id: self.self_node_id,
            seq,
            ..Default::default()
        };
        build_frame(
            &header,
            key_dst,
            &session.keys().tx_key,
            session.keys().salt,
            payload,
        )
        .map_err(|_| SendError::Aead)
    }

    fn build_handshake_frame(&self, to: u32, payload: &[u8]) -> Result<Vec<u8>, SendError> {
        let key_dst = self.key_dst_table.get(&to).ok_or(SendError::NoKeyDst)?;
        let header = MeshFrameHeader {
            to_node_id: to,
            from_node_id: self.self_node_id,
            ..Default::default()
        };
        Ok(build_handshake_frame(&header, key_dst, payload))
    }

    /// 广播帧构建（FRAME_HEADER §2.6）：AEAD 与 route_mac 均用 broadcast_key，
    /// seq = 每源全局广播计数器（虚拟会话）。
    pub fn build_broadcast_frame(&mut self, payload: &[u8]) -> Result<Vec<u8>, SendError> {
        let bkey = self.broadcast_key.ok_or(SendError::NoKeyDst)?;
        let seq = self.broadcast_seq;
        self.broadcast_seq = self.broadcast_seq.wrapping_add(1);
        let header = MeshFrameHeader {
            packet_type: packet_type::BROADCAST,
            to_node_id: BROADCAST_NODE_ID,
            from_node_id: self.self_node_id,
            seq,
            ..Default::default()
        };
        build_frame(&header, &bkey, &bkey, 0, payload).map_err(|_| SendError::Aead)
    }

    /// 组播泛洪：向全部已知端点（除自己）发送广播帧。无会话端点直接发送
    /// （广播帧不依赖逐对会话密钥，不触发懒握手）。返回成功发送数。
    pub async fn flood(&mut self, payload: &[u8]) -> usize {
        if !self.flood_bucket.take() {
            return 0;
        }
        let Ok(frame) = self.build_broadcast_frame(payload) else {
            return 0;
        };
        let mut sent = 0;
        for peer in self.endpoint_ids() {
            if self.send_to_node(peer, &frame).await.unwrap_or(false) {
                sent += 1;
            }
        }
        sent
    }

    fn endpoint_ids(&self) -> Vec<u32> {
        self.endpoint_table
            .keys()
            .copied()
            .filter(|id| *id != self.self_node_id)
            .collect()
    }

    pub async fn send_to_node(&self, to_node_id: u32, frame: &[u8]) -> std::io::Result<bool> {
        match self.endpoint_table.get(&to_node_id) {
            Some(addrs) => {
                for addr in addrs {
                    if self.socket.send_to(frame, addr).await.is_ok() {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            None => Ok(false),
        }
    }

    /// 按路径首跳发送（v2）：首跳 = 路径第一跳（relay 或 dest 本身）。
    /// 多端点按活性排序逐个尝试（黑洞端点靠 miss 置后，见 order_endpoints）。
    pub async fn send_to_node_hop(
        &mut self,
        to_node_id: u32,
        first_hop: Option<u32>,
        frame: &[u8],
    ) -> std::io::Result<bool> {
        let hop = first_hop.unwrap_or(to_node_id);
        match self.endpoint_table.get(&hop) {
            Some(addrs) => {
                let mut ordered = addrs.clone();
                self.order_endpoints(hop, to_node_id, &mut ordered);
                let mut last_err = None;
                let mut last_tried = None;
                for addr in ordered {
                    last_tried = Some(addr);
                    match self.socket.send_to(frame, addr).await {
                        Ok(_) => {
                            self.last_sent_endpoint.insert(to_node_id, addr);
                            return Ok(true);
                        }
                        Err(e) => last_err = Some(e),
                    }
                }
                // 发送失败（无路由等）→ 主路径 + 端点 miss，推进快速切换
                self.path_miss_peer(to_node_id);
                if let Some(addr) = last_tried {
                    if let Some(owner) = self.endpoint_owner(addr) {
                        let m = self.endpoint_health.entry((owner, addr)).or_insert(0);
                        *m = m.saturating_add(1);
                    }
                }
                Err(last_err.unwrap_or_else(|| std::io::Error::other("no endpoint")))
            }
            None => Ok(false),
        }
    }

    /// 到目的的首跳（候选路径第一条 hops[0]）；无路径表 = 直发（v1 语义）
    pub fn path_first_hop(&mut self, dest: u32) -> Option<u32> {
        self.pick_path(dest, 0)
            .and_then(|p| p.hops.first().copied())
    }

    pub async fn recv_frame(&self) -> std::io::Result<(SocketAddr, Vec<u8>)> {
        let mut buf = vec![0u8; 65535];
        let (n, from) = self.socket.recv_from(&mut buf).await?;
        buf.truncate(n);
        Ok((from, buf))
    }

    /// 收帧处理：relay 路径校验 → 按包类型分发（握手/数据/心跳/广播）。
    /// 入站路径记录 + 逐路径活性在分发前更新（帧实际到达的上一跳 = UDP 发送者归属）。
    pub async fn handle_incoming(&mut self) -> std::io::Result<IncomingEvent> {
        let (from_addr, frame) = self.recv_frame().await?;
        match self.relay(&frame).await {
            RelayOutcome::Delivered { frame, from } => {
                if let Some(ingress) = self.endpoint_owner(from_addr) {
                    self.ingress_hop.insert(from, ingress);
                    self.note_endpoint_ok(ingress, from_addr);
                }
                self.apply_ingress_health(from);
                Ok(self.dispatch_delivered(from, &frame).await)
            }
            RelayOutcome::Flooded { frame, from, .. } => {
                if let Some(ingress) = self.endpoint_owner(from_addr) {
                    self.ingress_hop.insert(from, ingress);
                    self.note_endpoint_ok(ingress, from_addr);
                }
                self.apply_ingress_health(from);
                Ok(self.dispatch_delivered(from, &frame).await)
            }
            RelayOutcome::Forwarded { to } => Ok(IncomingEvent::Relayed { to }),
            RelayOutcome::Dropped { reason } => Ok(IncomingEvent::Dropped { reason }),
        }
    }

    async fn dispatch_delivered(&mut self, from: u32, frame: &[u8]) -> IncomingEvent {
        let Some(header) = MeshFrameHeader::decode(frame).ok() else {
            return IncomingEvent::Dropped {
                reason: DropReason::Short,
            };
        };
        let Some(payload) = frame_payload(frame) else {
            return IncomingEvent::Dropped {
                reason: DropReason::Short,
            };
        };
        match header.packet_type {
            packet_type::HANDSHAKE => self.handle_handshake(from, payload).await,
            packet_type::UNICAST => self.handle_session_frame(from, frame, false),
            packet_type::HEARTBEAT => self.handle_session_frame(from, frame, true),
            packet_type::BROADCAST => self.handle_broadcast_frame(from, frame),
            _ => IncomingEvent::Dropped {
                reason: DropReason::UnsupportedType,
            },
        }
    }

    /// 广播帧解密（FRAME_HEADER §2.6）：route_mac + AEAD 均用 broadcast_key，
    /// 按源节点的独立重放窗口拦截重放。
    fn handle_broadcast_frame(&mut self, from: u32, frame: &[u8]) -> IncomingEvent {
        let Some(bkey) = self.broadcast_key else {
            return IncomingEvent::Dropped {
                reason: DropReason::NoKeyDst,
            };
        };
        let Some(header) = MeshFrameHeader::decode(frame).ok() else {
            return IncomingEvent::Dropped {
                reason: DropReason::Short,
            };
        };
        let window = self.broadcast_replay.entry(from).or_default();
        if !window.check_and_mark(header.seq) {
            return IncomingEvent::Dropped {
                reason: DropReason::Replay,
            };
        }
        match open_frame(frame, &bkey, &bkey, 0) {
            Ok((_, payload)) => IncomingEvent::Broadcast { from, payload },
            Err(landscape_rill_core::frame::OpenError::RouteMac) => IncomingEvent::Dropped {
                reason: DropReason::BadRouteMac,
            },
            Err(_) => IncomingEvent::Dropped {
                reason: DropReason::Aead,
            },
        }
    }

    /// 握手分发：按载荷长度区分 msg1/msg2/msg3（36/144/132B，互不重叠）。
    /// 与角色状态解耦——重发/乱序/状态残留不会误归类。
    async fn handle_handshake(&mut self, from: u32, payload: &[u8]) -> IncomingEvent {
        match payload.len() {
            MSG1_PAYLOAD_LEN => self.handle_msg1(from, payload).await,
            MSG2_PAYLOAD_LEN => self.handle_msg2(from, payload).await,
            MSG3_PAYLOAD_LEN => self.handle_msg3(from, payload).await,
            _ => IncomingEvent::Rejected {
                peer: from,
                reason: HandshakeError::MalformedPayload,
            },
        }
    }

    async fn handle_msg1(&mut self, from: u32, payload: &[u8]) -> IncomingEvent {
        let Some(ctx) = self.ctx.clone() else {
            return IncomingEvent::Rejected {
                peer: from,
                reason: HandshakeError::WrongStep,
            };
        };
        let mut responder = match HandshakeResponder::new(
            &ctx.local_static,
            ctx.network_id,
            ctx.version,
            self.self_node_id,
        ) {
            Ok(r) => r,
            Err(e) => {
                return IncomingEvent::Rejected {
                    peer: from,
                    reason: e,
                }
            }
        };
        if let Err(e) = responder.read_msg1(payload) {
            return IncomingEvent::Rejected {
                peer: from,
                reason: e,
            };
        }
        let msg2 = match responder.write_msg2() {
            Ok(m) => m,
            Err(e) => {
                return IncomingEvent::Rejected {
                    peer: from,
                    reason: e,
                }
            }
        };
        self.responders.insert(from, responder);
        match self.send_response(from, &msg2).await {
            true => IncomingEvent::Responded { peer: from },
            false => IncomingEvent::Dropped {
                reason: DropReason::NoEndpoint,
            },
        }
    }

    async fn handle_msg2(&mut self, from: u32, payload: &[u8]) -> IncomingEvent {
        let Some(mut initiator) = self.initiators.remove(&from) else {
            return IncomingEvent::Rejected {
                peer: from,
                reason: HandshakeError::WrongStep,
            };
        };
        let msg3 = match initiator.read_msg2(payload) {
            Ok(m) => m,
            Err(e) => {
                return IncomingEvent::Rejected {
                    peer: from,
                    reason: e,
                }
            }
        };
        let keys = match initiator.finish() {
            Ok(k) => k,
            Err(e) => {
                return IncomingEvent::Rejected {
                    peer: from,
                    reason: e,
                }
            }
        };
        let frame = match self.build_handshake_frame(from, &msg3) {
            Ok(f) => f,
            Err(_) => {
                return IncomingEvent::Dropped {
                    reason: DropReason::NoKeyDst,
                }
            }
        };
        let hop = self.path_first_hop(from);
        match self.send_to_node_hop(from, hop, &frame).await {
            Ok(true) => {
                self.sessions.insert(from, Session::new(from, keys));
                IncomingEvent::Established { peer: from }
            }
            _ => IncomingEvent::Dropped {
                reason: DropReason::NoEndpoint,
            },
        }
    }

    async fn handle_msg3(&mut self, from: u32, payload: &[u8]) -> IncomingEvent {
        let Some(verifier) = self.binding_verifier.as_ref() else {
            return IncomingEvent::Rejected {
                peer: from,
                reason: HandshakeError::BadBinding,
            };
        };
        let Some(mut responder) = self.responders.remove(&from) else {
            return IncomingEvent::Rejected {
                peer: from,
                reason: HandshakeError::WrongStep,
            };
        };
        let result = responder.read_msg3(payload, from, |node_id, static_pubkey, binding| {
            verifier(node_id, static_pubkey, binding)
        });
        match result {
            Ok(keys) => {
                self.sessions.insert(from, Session::new(from, keys));
                IncomingEvent::Established { peer: from }
            }
            Err(e) => IncomingEvent::Rejected {
                peer: from,
                reason: e,
            },
        }
    }

    async fn send_response(&mut self, to: u32, payload: &[u8]) -> bool {
        let frame = match self.build_handshake_frame(to, payload) {
            Ok(f) => f,
            Err(_) => return false,
        };
        let hop = self.path_first_hop(to);
        matches!(self.send_to_node_hop(to, hop, &frame).await, Ok(true))
    }

    /// AEAD 解密收尾：已建会话的 UNICAST/HEARTBEAT 帧统一走这里
    /// 路由密钥按帧头版本选择：v1 = key_dst（默认路径）；v2 = 该 path_id 的 key_path
    fn handle_session_frame(&mut self, from: u32, frame: &[u8], heartbeat: bool) -> IncomingEvent {
        let Some(session) = self.sessions.get_mut(&from) else {
            return IncomingEvent::Dropped {
                reason: DropReason::NoSession,
            };
        };
        let Some(header) = MeshFrameHeader::decode(frame).ok() else {
            return IncomingEvent::Dropped {
                reason: DropReason::Short,
            };
        };
        let route_key = if header.version == VERSION2 {
            match self.key_path_table.get(&header.path_id) {
                Some(k) => *k,
                None => {
                    return IncomingEvent::Dropped {
                        reason: DropReason::NoKeyDst,
                    }
                }
            }
        } else {
            match self.key_dst_table.get(&self.self_node_id) {
                Some(k) => *k,
                None => {
                    return IncomingEvent::Dropped {
                        reason: DropReason::NoKeyDst,
                    }
                }
            }
        };
        match session.open(frame, &route_key, Instant::now()) {
            Ok((_, payload)) => {
                if heartbeat && !payload.is_empty() {
                    return IncomingEvent::Dropped {
                        reason: DropReason::Aead,
                    };
                }
                if heartbeat {
                    IncomingEvent::Heartbeat { from }
                } else {
                    IncomingEvent::Data { from, payload }
                }
            }
            Err(landscape_rill_core::handshake::OpenError::Replay) => IncomingEvent::Dropped {
                reason: DropReason::Replay,
            },
            Err(landscape_rill_core::handshake::OpenError::RouteMac) => IncomingEvent::Dropped {
                reason: DropReason::BadRouteMac,
            },
            Err(_) => IncomingEvent::Dropped {
                reason: DropReason::Aead,
            },
        }
    }

    pub async fn relay(&mut self, frame: &[u8]) -> RelayOutcome {
        if frame.len() < HEADER_LEN {
            return RelayOutcome::Dropped {
                reason: DropReason::Short,
            };
        }
        let header = match MeshFrameHeader::decode(frame) {
            Ok(h) => h,
            Err(_) => {
                return RelayOutcome::Dropped {
                    reason: DropReason::Short,
                }
            }
        };
        if header.version != VERSION && header.version != VERSION2 {
            return RelayOutcome::Dropped {
                reason: DropReason::BadVersion,
            };
        }
        if header.to_node_id == BROADCAST_NODE_ID {
            return self.relay_broadcast(&header, frame).await;
        }
        // 路由密钥按帧头版本选择：v2 = 该 path_id 的 key_path（路径级授权，
        // CONTROL_PLANE §3.11.5——转发节点必须持路径授权才能校验/转发）
        let route_key = if header.version == VERSION2 {
            match self.key_path_table.get(&header.path_id) {
                Some(k) => *k,
                None => {
                    return RelayOutcome::Dropped {
                        reason: DropReason::NoKeyDst,
                    }
                }
            }
        } else {
            match self.key_dst_table.get(&header.to_node_id) {
                Some(k) => *k,
                None => {
                    return RelayOutcome::Dropped {
                        reason: DropReason::NoKeyDst,
                    }
                }
            }
        };
        let (ai, ai_len) = header.auth_input();
        if landscape_rill_core::crypto::route_mac(&route_key, &ai[..ai_len]) != header.route_mac {
            return RelayOutcome::Dropped {
                reason: DropReason::BadRouteMac,
            };
        }
        if header.to_node_id == self.self_node_id {
            return RelayOutcome::Delivered {
                frame: frame.to_vec(),
                from: header.from_node_id,
            };
        }
        if header.ttl == 0 {
            return RelayOutcome::Dropped {
                reason: DropReason::TtlExpired,
            };
        }
        // 转发端点：v2 路径按路径下一跳（本节点在 hops 中的后继），v1 直连目标端点
        let next_hop = if header.version == VERSION2 {
            self.path_next_hop(&header)
        } else {
            None
        };
        let endpoint = match next_hop {
            Some(e) => Some(e),
            None => self
                .endpoint_table
                .get(&header.to_node_id)
                .and_then(|v| v.first())
                .copied(),
        };
        let Some(endpoint) = endpoint else {
            return RelayOutcome::Dropped {
                reason: DropReason::NoEndpoint,
            };
        };
        let mut out = frame.to_vec();
        out[3] -= 1;
        match self.socket.send_to(&out, endpoint).await {
            Ok(_) => RelayOutcome::Forwarded {
                to: header.to_node_id,
            },
            Err(_) => RelayOutcome::Dropped {
                reason: DropReason::NoEndpoint,
            },
        }
    }

    /// v2 路径转发下一跳：本节点在路径 hops 中的后继节点
    fn path_next_hop(&self, header: &MeshFrameHeader) -> Option<SocketAddr> {
        let paths = self.path_table.get(&header.to_node_id)?;
        let path = paths
            .iter()
            .find(|p| p.path_id == header.path_id && !p.expired(unix_seconds()))?;
        let idx = path.hops.iter().position(|h| *h == self.self_node_id)?;
        let next = path.hops.get(idx + 1)?;
        self.endpoint_table
            .get(next)
            .and_then(|v| v.first())
            .copied()
    }

    /// 广播帧泛洪路径（FRAME_HEADER §2.6）：
    /// version（已验）→ type=广播 → broadcast_key 存在 → route_mac（bkey）→
    /// (from, seq) 去重（30s）→ ttl>0 → 自交付 + ttl-1 泛洪（除自己与源，出口令牌桶限速）。
    async fn relay_broadcast(&mut self, header: &MeshFrameHeader, frame: &[u8]) -> RelayOutcome {
        if header.packet_type != packet_type::BROADCAST {
            return RelayOutcome::Dropped {
                reason: DropReason::UnsupportedType,
            };
        }
        let Some(bkey) = self.broadcast_key else {
            return RelayOutcome::Dropped {
                reason: DropReason::NoKeyDst,
            };
        };
        let (ai, ai_len) = header.auth_input();
        if landscape_rill_core::crypto::route_mac(&bkey, &ai[..ai_len]) != header.route_mac {
            return RelayOutcome::Dropped {
                reason: DropReason::BadRouteMac,
            };
        }
        if header.from_node_id == self.self_node_id {
            return RelayOutcome::Dropped {
                reason: DropReason::Duplicate,
            };
        }
        self.prune_flood_seen();
        if self
            .flood_seen
            .contains_key(&(header.from_node_id, header.seq))
        {
            return RelayOutcome::Dropped {
                reason: DropReason::Duplicate,
            };
        }
        if header.ttl == 0 {
            return RelayOutcome::Dropped {
                reason: DropReason::TtlExpired,
            };
        }
        self.flood_seen
            .insert((header.from_node_id, header.seq), Instant::now());
        let mut forwarded = Vec::new();
        if self.flood_bucket.take() {
            let mut out = frame.to_vec();
            out[3] -= 1;
            for (id, addrs) in &self.endpoint_table {
                if *id == self.self_node_id || *id == header.from_node_id {
                    continue;
                }
                let mut ok = false;
                for ep in addrs {
                    if self.socket.send_to(&out, *ep).await.is_ok() {
                        ok = true;
                        break;
                    }
                }
                if ok {
                    forwarded.push(*id);
                }
            }
        }
        RelayOutcome::Flooded {
            frame: frame.to_vec(),
            from: header.from_node_id,
            forwarded,
        }
    }

    /// 清理过期泛洪去重条目（FLOOD_SEEN_TTL）
    fn prune_flood_seen(&mut self) {
        let cutoff = Instant::now() - FLOOD_SEEN_TTL;
        self.flood_seen.retain(|_, seen_at| *seen_at >= cutoff);
    }

    pub fn is_handshake(frame: &[u8]) -> bool {
        frame.len() >= HEADER_LEN && frame[1] == packet_type::HANDSHAKE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use landscape_rill_core::crypto::{derive_key_dst, KEY_DST_LEN};
    use landscape_rill_core::frame::{build_frame, packet_type, HEADER_LEN_V2, TAG_LEN, VERSION2};
    use landscape_rill_core::handshake::{BINDING_LEN, SESSION_KEY_LEN};

    const MASTER: [u8; 32] = [0x42; 32];
    const NETWORK_ID: u32 = 0x0000_0001;

    fn node_key(node_id: u32) -> [u8; KEY_DST_LEN] {
        derive_key_dst(&MASTER, node_id)
    }

    fn ctx(id: u8) -> HandshakeContext {
        HandshakeContext {
            network_id: NETWORK_ID,
            version: VERSION,
            local_static: [id; SESSION_KEY_LEN],
            identity_binding: [0x5a; BINDING_LEN].to_vec(),
        }
    }

    /// 私钥 [id; 32] 的 X25519 公钥（netmap/身份绑定携带的是公钥）
    fn peer_static(id: u8) -> [u8; 32] {
        use x25519_dalek::{PublicKey, StaticSecret};
        PublicKey::from(&StaticSecret::from([id; 32])).to_bytes()
    }

    fn verifier(node_id: u32, static_pubkey: &[u8; 32], _binding: &[u8]) -> bool {
        static_pubkey == &peer_static(node_id as u8)
    }

    fn frame_from(from: u32, to: u32, payload: &[u8], ttl: u8, seq: u32) -> Vec<u8> {
        let header = MeshFrameHeader {
            to_node_id: to,
            from_node_id: from,
            seq,
            ttl,
            ..Default::default()
        };
        build_frame(&header, &node_key(to), &[0x24; 32], 0x1234_5678, payload).unwrap()
    }

    async fn setup_pair() -> (MeshData, MeshData) {
        let mut a = MeshData::bind("127.0.0.1:0".parse().unwrap(), 1)
            .await
            .unwrap();
        let mut b = MeshData::bind("127.0.0.1:0".parse().unwrap(), 2)
            .await
            .unwrap();
        let a_addr = a.local_addr().unwrap();
        let b_addr = b.local_addr().unwrap();
        for id in [1u32, 2] {
            a.set_key_dst(id, node_key(id));
            b.set_key_dst(id, node_key(id));
        }
        a.set_handshake_context(ctx(1));
        b.set_handshake_context(ctx(2));
        a.set_peer_static(2, peer_static(2));
        b.set_peer_static(1, peer_static(1));
        a.set_binding_verifier(verifier);
        b.set_binding_verifier(verifier);
        a.set_endpoint(2, b_addr);
        b.set_endpoint(1, a_addr);
        (a, b)
    }

    #[tokio::test]
    async fn full_handshake_and_data_roundtrip() {
        let (mut a, mut b) = setup_pair().await;
        let msg1 = a.initiate_handshake(2).unwrap().unwrap();
        a.send_to_node(2, &msg1).await.unwrap();
        assert_eq!(
            b.handle_incoming().await.unwrap(),
            IncomingEvent::Responded { peer: 1 }
        );
        assert_eq!(
            a.handle_incoming().await.unwrap(),
            IncomingEvent::Established { peer: 2 }
        );
        assert_eq!(
            b.handle_incoming().await.unwrap(),
            IncomingEvent::Established { peer: 1 }
        );
        assert!(a.has_session(2) && b.has_session(1));

        let (frame, hop) = a.build_data_frame(2, b"hello mesh", 0).unwrap();
        a.send_to_node_hop(2, hop, &frame).await.unwrap();
        assert_eq!(
            b.handle_incoming().await.unwrap(),
            IncomingEvent::Data {
                from: 1,
                payload: b"hello mesh".to_vec()
            }
        );

        let (frame, hop) = b.build_data_frame(1, b"reply", 0).unwrap();
        b.send_to_node_hop(1, hop, &frame).await.unwrap();
        assert_eq!(
            a.handle_incoming().await.unwrap(),
            IncomingEvent::Data {
                from: 2,
                payload: b"reply".to_vec()
            }
        );
    }

    #[tokio::test]
    async fn initiate_handshake_idempotent_after_session() {
        let (mut a, mut b) = setup_pair().await;
        let msg1 = a.initiate_handshake(2).unwrap().unwrap();
        a.send_to_node(2, &msg1).await.unwrap();
        assert_eq!(
            b.handle_incoming().await.unwrap(),
            IncomingEvent::Responded { peer: 1 }
        );
        assert_eq!(
            a.handle_incoming().await.unwrap(),
            IncomingEvent::Established { peer: 2 }
        );
        assert_eq!(
            b.handle_incoming().await.unwrap(),
            IncomingEvent::Established { peer: 1 }
        );
        assert_eq!(a.initiate_handshake(2).unwrap(), None);
    }

    #[tokio::test]
    async fn handshake_redirect_rejected() {
        let (mut a, mut b) = setup_pair().await;
        a.set_peer_static(3, peer_static(3));
        a.set_key_dst(3, node_key(3));
        let msg1 = a.initiate_handshake(3).unwrap().unwrap();

        let h = MeshFrameHeader::decode(&msg1).unwrap();
        let payload = frame_payload(&msg1).unwrap();
        let mut redirected = h.clone();
        redirected.to_node_id = 2;
        let frame = build_handshake_frame(&redirected, &node_key(2), payload);

        a.send_to_node(2, &frame).await.unwrap();
        assert_eq!(
            b.handle_incoming().await.unwrap(),
            IncomingEvent::Rejected {
                peer: 1,
                reason: HandshakeError::WrongTarget
            }
        );
    }

    #[tokio::test]
    async fn bad_binding_rejected_over_wire() {
        let (mut a, mut b) = setup_pair().await;
        b.set_binding_verifier(|_, _, _| false);
        let msg1 = a.initiate_handshake(2).unwrap().unwrap();
        a.send_to_node(2, &msg1).await.unwrap();
        assert_eq!(
            b.handle_incoming().await.unwrap(),
            IncomingEvent::Responded { peer: 1 }
        );
        assert_eq!(
            a.handle_incoming().await.unwrap(),
            IncomingEvent::Established { peer: 2 }
        );
        assert_eq!(
            b.handle_incoming().await.unwrap(),
            IncomingEvent::Rejected {
                peer: 1,
                reason: HandshakeError::BadBinding
            }
        );
        assert!(a.has_session(2));
        assert!(!b.has_session(1));
    }

    #[tokio::test]
    async fn prologue_mismatch_rejected_over_wire() {
        // B 网络不同：msg1 无加密可读、B 回 msg2，A 在 msg2 解密时失败（AEAD AAD=h 含 prologue）
        let (mut a, mut b) = setup_pair().await;
        let mut ctx_b = ctx(2);
        ctx_b.network_id = 0x0000_0002;
        b.set_handshake_context(ctx_b);
        let msg1 = a.initiate_handshake(2).unwrap().unwrap();
        a.send_to_node(2, &msg1).await.unwrap();
        assert_eq!(
            b.handle_incoming().await.unwrap(),
            IncomingEvent::Responded { peer: 1 }
        );
        match a.handle_incoming().await.unwrap() {
            IncomingEvent::Rejected {
                peer: 2,
                reason: HandshakeError::Noise(_),
            } => {}
            other => panic!("expected Noise rejection, got {:?}", other),
        }
        assert!(!a.has_session(2));
        assert!(!b.has_session(1));
    }

    #[tokio::test]
    async fn msg2_without_initiator_rejected() {
        let (a, mut b) = setup_pair().await;
        let header = MeshFrameHeader {
            to_node_id: 2,
            from_node_id: 1,
            ..Default::default()
        };
        let junk = [0u8; MSG2_PAYLOAD_LEN];
        let frame = build_handshake_frame(&header, &node_key(2), &junk);
        a.send_to_node(2, &frame).await.unwrap();
        assert_eq!(
            b.handle_incoming().await.unwrap(),
            IncomingEvent::Rejected {
                peer: 1,
                reason: HandshakeError::WrongStep
            }
        );
    }

    #[tokio::test]
    async fn heartbeat_roundtrip() {
        let (mut a, mut b) = setup_pair().await;
        let msg1 = a.initiate_handshake(2).unwrap().unwrap();
        a.send_to_node(2, &msg1).await.unwrap();
        assert_eq!(
            b.handle_incoming().await.unwrap(),
            IncomingEvent::Responded { peer: 1 }
        );
        assert_eq!(
            a.handle_incoming().await.unwrap(),
            IncomingEvent::Established { peer: 2 }
        );
        assert_eq!(
            b.handle_incoming().await.unwrap(),
            IncomingEvent::Established { peer: 1 }
        );

        let hb = a.build_heartbeat_frame(2).unwrap();
        a.send_to_node(2, &hb).await.unwrap();
        assert_eq!(
            b.handle_incoming().await.unwrap(),
            IncomingEvent::Heartbeat { from: 1 }
        );
    }

    #[tokio::test]
    async fn heartbeat_before_session_rejected() {
        let mut a = MeshData::bind("127.0.0.1:0".parse().unwrap(), 1)
            .await
            .unwrap();
        assert_eq!(
            a.build_heartbeat_frame(2).unwrap_err(),
            SendError::NoSession
        );
        assert_eq!(
            a.build_data_frame(2, b"x", 0).unwrap_err(),
            SendError::NoSession
        );
    }

    #[tokio::test]
    async fn tampered_data_frame_dropped() {
        let (mut a, mut b) = setup_pair().await;
        let msg1 = a.initiate_handshake(2).unwrap().unwrap();
        a.send_to_node(2, &msg1).await.unwrap();
        assert_eq!(
            b.handle_incoming().await.unwrap(),
            IncomingEvent::Responded { peer: 1 }
        );
        assert_eq!(
            a.handle_incoming().await.unwrap(),
            IncomingEvent::Established { peer: 2 }
        );
        assert_eq!(
            b.handle_incoming().await.unwrap(),
            IncomingEvent::Established { peer: 1 }
        );

        let mut frame = a.build_data_frame(2, b"payload", 0).unwrap().0;
        let n = frame.len();
        frame[n - 1] ^= 0xff;
        a.send_to_node(2, &frame).await.unwrap();
        assert_eq!(
            b.handle_incoming().await.unwrap(),
            IncomingEvent::Dropped {
                reason: DropReason::Aead
            }
        );
    }

    #[tokio::test]
    async fn replayed_data_frame_dropped() {
        let (mut a, mut b) = setup_pair().await;
        let msg1 = a.initiate_handshake(2).unwrap().unwrap();
        a.send_to_node(2, &msg1).await.unwrap();
        assert_eq!(
            b.handle_incoming().await.unwrap(),
            IncomingEvent::Responded { peer: 1 }
        );
        assert_eq!(
            a.handle_incoming().await.unwrap(),
            IncomingEvent::Established { peer: 2 }
        );
        assert_eq!(
            b.handle_incoming().await.unwrap(),
            IncomingEvent::Established { peer: 1 }
        );

        let frame = a.build_data_frame(2, b"payload", 0).unwrap().0;
        a.send_to_node(2, &frame).await.unwrap();
        assert_eq!(
            b.handle_incoming().await.unwrap(),
            IncomingEvent::Data {
                from: 1,
                payload: b"payload".to_vec()
            }
        );
        a.send_to_node(2, &frame).await.unwrap();
        assert_eq!(
            b.handle_incoming().await.unwrap(),
            IncomingEvent::Dropped {
                reason: DropReason::Replay
            }
        );
    }

    #[tokio::test]
    async fn data_without_session_dropped() {
        let mut a = MeshData::bind("127.0.0.1:0".parse().unwrap(), 1)
            .await
            .unwrap();
        let mut b = MeshData::bind("127.0.0.1:0".parse().unwrap(), 2)
            .await
            .unwrap();
        let b_addr = b.local_addr().unwrap();
        a.set_key_dst(2, node_key(2));
        b.set_key_dst(2, node_key(2));
        a.set_endpoint(2, b_addr);

        let frame = frame_from(1, 2, b"payload", 64, 0);
        a.send_to_node(2, &frame).await.unwrap();
        assert_eq!(
            b.handle_incoming().await.unwrap(),
            IncomingEvent::Dropped {
                reason: DropReason::NoSession
            }
        );
    }

    #[tokio::test]
    async fn unsupported_type_dropped() {
        let mut a = MeshData::bind("127.0.0.1:0".parse().unwrap(), 1)
            .await
            .unwrap();
        let mut b = MeshData::bind("127.0.0.1:0".parse().unwrap(), 2)
            .await
            .unwrap();
        let b_addr = b.local_addr().unwrap();
        a.set_key_dst(2, node_key(2));
        b.set_key_dst(2, node_key(2));
        a.set_endpoint(2, b_addr);

        let header = MeshFrameHeader {
            packet_type: packet_type::CONTROL,
            to_node_id: 2,
            from_node_id: 1,
            ..Default::default()
        };
        let mut frame = vec![0u8; HEADER_LEN + 4];
        let mut h = header.clone();
        h.len = 4;
        let (ai, ai_len) = h.auth_input();
        h.route_mac = landscape_rill_core::crypto::route_mac(&node_key(2), &ai[..ai_len]);
        h.encode(&mut frame);
        frame[HEADER_LEN..].copy_from_slice(b"ctrl");
        a.send_to_node(2, &frame).await.unwrap();
        assert_eq!(
            b.handle_incoming().await.unwrap(),
            IncomingEvent::Dropped {
                reason: DropReason::UnsupportedType
            }
        );
    }

    #[tokio::test]
    async fn forward_through_relay() {
        let mut relay = MeshData::bind("127.0.0.1:0".parse().unwrap(), 2)
            .await
            .unwrap();
        let mut b = MeshData::bind("127.0.0.1:0".parse().unwrap(), 3)
            .await
            .unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let b_addr = b.local_addr().unwrap();

        relay.set_key_dst(3, node_key(3));
        relay.set_endpoint(3, b_addr);
        b.set_key_dst(3, node_key(3));

        let frame = frame_from(1, 3, b"payload", 64, 1);
        relay.socket.send_to(&frame, relay_addr).await.unwrap();
        let (_, recv) = relay.recv_frame().await.unwrap();
        assert_eq!(relay.relay(&recv).await, RelayOutcome::Forwarded { to: 3 });
        let (_, recv2) = b.recv_frame().await.unwrap();
        assert_eq!(recv2[3], 63);
        let delivered = b.relay(&recv2).await;
        match delivered {
            RelayOutcome::Delivered { frame, from } => {
                assert_eq!(from, 1);
                assert_eq!(frame.len(), recv2.len());
            }
            other => panic!("expected delivered, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn tampered_frame_dropped() {
        let mut relay = MeshData::bind("127.0.0.1:0".parse().unwrap(), 2)
            .await
            .unwrap();
        relay.set_key_dst(3, node_key(3));
        let mut frame = frame_from(1, 3, b"payload", 64, 1);
        frame[8] ^= 0x01;
        assert_eq!(
            relay.relay(&frame).await,
            RelayOutcome::Dropped {
                reason: DropReason::BadRouteMac
            }
        );
    }

    // ==================== v2 路径（CONTROL_PLANE §3.11 / FRAME_HEADER §9） ====================

    fn path_key(_path_id: u64) -> [u8; KEY_DST_LEN] {
        [0x77; 32] // 测试用 key_path（真实 = derive_key_path）
    }

    #[tokio::test]
    async fn v2_data_frame_roundtrip_via_direct_path() {
        let (mut a, mut b) = setup_pair().await;
        // 完整握手（v1 帧）
        let msg1 = a.initiate_handshake(2).unwrap().unwrap();
        a.send_to_node(2, &msg1).await.unwrap();
        assert_eq!(
            b.handle_incoming().await.unwrap(),
            IncomingEvent::Responded { peer: 1 }
        );
        assert_eq!(
            a.handle_incoming().await.unwrap(),
            IncomingEvent::Established { peer: 2 }
        );
        assert_eq!(
            b.handle_incoming().await.unwrap(),
            IncomingEvent::Established { peer: 1 }
        );
        // 路径注入（direct：hops=[2]）
        let path = PathEntry {
            path_id: 0x100,
            path_epoch: 1,
            hops: vec![2],
            expires_at: unix_seconds() + 3600,
        };
        a.set_paths(2, vec![path.clone()]);
        a.set_key_path(0x100, path_key(0x100));
        b.set_key_path(0x100, path_key(0x100));
        // v2 数据帧（42B + path_id）
        let (frame, first_hop) = a.build_data_frame(2, b"hello path", 0x1234).unwrap();
        assert_eq!(first_hop, Some(2));
        assert_eq!(frame.len(), HEADER_LEN_V2 + 10 + TAG_LEN);
        assert_eq!(MeshFrameHeader::decode(&frame).unwrap().version, VERSION2);
        assert_eq!(MeshFrameHeader::decode(&frame).unwrap().path_id, 0x100);
        a.send_to_node_hop(2, first_hop, &frame).await.unwrap();
        // B 收帧：path_id 选 key_path 校验 + 解密
        match b.handle_incoming().await.unwrap() {
            IncomingEvent::Data { from, payload } => {
                assert_eq!(from, 1);
                assert_eq!(payload, b"hello path");
            }
            other => panic!("expected data, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn v2_frame_without_key_path_dropped() {
        // path_id 无对应 key_path → NoKeyDst（fail-closed）
        let (mut a, mut b) = setup_pair().await;
        let msg1 = a.initiate_handshake(2).unwrap().unwrap();
        a.send_to_node(2, &msg1).await.unwrap();
        let _ = b.handle_incoming().await.unwrap();
        let _ = a.handle_incoming().await.unwrap();
        let _ = b.handle_incoming().await.unwrap();
        let path = PathEntry {
            path_id: 0x200,
            path_epoch: 1,
            hops: vec![2],
            expires_at: unix_seconds() + 3600,
        };
        a.set_paths(2, vec![path]);
        a.set_key_path(0x200, path_key(0x200));
        // B 无 key_path(0x200)
        let (frame, hop) = a.build_data_frame(2, b"secret", 1).unwrap();
        a.send_to_node_hop(2, hop, &frame).await.unwrap();
        match b.handle_incoming().await.unwrap() {
            IncomingEvent::Dropped {
                reason: DropReason::NoKeyDst,
            } => {}
            other => panic!("expected NoKeyDst drop, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn v2_frame_forwarded_through_relay_path() {
        // A(1) → R(3) → B(2)：v2 帧经 relay 按路径转发（key_path 校验）
        // 握手直连（真实场景 netmap 全量互连）；数据面走 relay 路径
        let mut a = MeshData::bind("127.0.0.1:0".parse().unwrap(), 1)
            .await
            .unwrap();
        let mut r = MeshData::bind("127.0.0.1:0".parse().unwrap(), 3)
            .await
            .unwrap();
        let mut b = MeshData::bind("127.0.0.1:0".parse().unwrap(), 2)
            .await
            .unwrap();
        let a_addr = a.local_addr().unwrap();
        let r_addr = r.local_addr().unwrap();
        let b_addr = b.local_addr().unwrap();
        for id in [1u32, 2, 3] {
            a.set_key_dst(id, node_key(id));
            r.set_key_dst(id, node_key(id));
            b.set_key_dst(id, node_key(id));
        }
        a.set_handshake_context(ctx(1));
        r.set_handshake_context(ctx(3));
        b.set_handshake_context(ctx(2));
        a.set_peer_static(2, peer_static(2));
        b.set_peer_static(1, peer_static(1));
        a.set_binding_verifier(verifier);
        b.set_binding_verifier(verifier);
        a.set_endpoint(2, b_addr);
        b.set_endpoint(1, a_addr);
        // A 的路径首跳 = R（relay 路径发送端点）
        a.set_endpoint(3, r_addr);
        // R 的转发表：知道 B 的端点
        r.set_endpoint(2, b_addr);
        // 握手直连 A↔B
        let msg1 = a.initiate_handshake(2).unwrap().unwrap();
        a.send_to_node(2, &msg1).await.unwrap();
        assert_eq!(
            b.handle_incoming().await.unwrap(),
            IncomingEvent::Responded { peer: 1 }
        );
        assert_eq!(
            a.handle_incoming().await.unwrap(),
            IncomingEvent::Established { peer: 2 }
        );
        assert_eq!(
            b.handle_incoming().await.unwrap(),
            IncomingEvent::Established { peer: 1 }
        );
        // 路径注入：A → B 经 R（hops=[3,2]）；R 持有同路径做转发
        let path = PathEntry {
            path_id: 0x300,
            path_epoch: 1,
            hops: vec![3, 2],
            expires_at: unix_seconds() + 3600,
        };
        for node in [&mut a, &mut r, &mut b] {
            node.set_key_path(0x300, path_key(0x300));
        }
        a.set_paths(2, vec![path.clone()]);
        r.set_paths(2, vec![path.clone()]);
        // A 发 v2 帧（首跳 = R）
        let (frame, first_hop) = a.build_data_frame(2, b"via relay", 0xabc).unwrap();
        assert_eq!(first_hop, Some(3));
        assert_eq!(MeshFrameHeader::decode(&frame).unwrap().version, VERSION2);
        a.send_to_node_hop(2, first_hop, &frame).await.unwrap();
        // R 校验 key_path 并转发到 B
        let (_, rcv4) = r.recv_frame().await.unwrap();
        assert_eq!(r.relay(&rcv4).await, RelayOutcome::Forwarded { to: 2 });
        // B 收帧解密
        match b.handle_incoming().await.unwrap() {
            IncomingEvent::Data { from, payload } => {
                assert_eq!(from, 1);
                assert_eq!(payload, b"via relay");
            }
            other => panic!("expected data, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn pick_path_switches_on_health_miss() {
        // 快速切换（CONTROL_PLANE §3.11）：主路径 miss 达阈值 → flow hash 选备用
        let mut a = MeshData::bind("127.0.0.1:0".parse().unwrap(), 1)
            .await
            .unwrap();
        let p1 = PathEntry {
            path_id: 1,
            path_epoch: 1,
            hops: vec![2],
            expires_at: unix_seconds() + 3600,
        };
        let p2 = PathEntry {
            path_id: 2,
            path_epoch: 1,
            hops: vec![3, 2],
            expires_at: unix_seconds() + 3600,
        };
        a.set_key_path(1, path_key(1));
        a.set_key_path(2, path_key(2));
        a.set_paths(2, vec![p1.clone(), p2.clone()]);
        // 健康时：flow hash 0 → 路径 1
        let picked = a.pick_path(2, 0).unwrap();
        assert_eq!(picked.path_id, 1);
        // 主路径 miss 达阈值 → 切备用
        for _ in 0..PATH_HEALTH_MISS_LIMIT {
            a.path_miss_peer(2);
        }
        let picked = a.pick_path(2, 0).unwrap();
        assert_eq!(picked.path_id, 2);
        // 收包恢复 → 主路径回归
        a.path_ok_peer(2);
        let picked = a.pick_path(2, 0).unwrap();
        assert_eq!(picked.path_id, 1);
    }

    #[tokio::test]
    async fn relayed_ingress_misses_direct_path() {
        // 经中继到达的帧（UDP 发送者 = relay）：直连路径 miss 递增（中继帧不续命
        // 直连），中继路径 ok——不对称拓扑下响应方也能收敛到中继路径
        let mut a = MeshData::bind("127.0.0.1:0".parse().unwrap(), 1)
            .await
            .unwrap();
        let mut b = MeshData::bind("127.0.0.1:0".parse().unwrap(), 2)
            .await
            .unwrap();
        a.set_endpoint(2, b.local_addr().unwrap());
        b.set_endpoint(1, a.local_addr().unwrap());
        a.set_key_dst(1, node_key(1)); // 自身 key_dst（relay 路由校验用）
        let direct = PathEntry {
            path_id: 1,
            path_epoch: 1,
            hops: vec![3],
            expires_at: unix_seconds() + 3600,
        };
        let relayed = PathEntry {
            path_id: 2,
            path_epoch: 1,
            hops: vec![2, 3],
            expires_at: unix_seconds() + 3600,
        };
        a.set_key_path(1, path_key(1));
        a.set_key_path(2, path_key(2));
        a.set_paths(3, vec![direct, relayed]);
        // 直连预置 miss 2 次（距阈值差 1）
        a.path_miss_peer(3);
        a.path_miss_peer(3); // 节点 3 的 msg1 由中继 b 转发到 a（帧头 from=3，UDP 发送者=2）
        let header = MeshFrameHeader {
            to_node_id: 1,
            from_node_id: 3,
            ..Default::default()
        };
        let frame = build_handshake_frame(&header, &node_key(1), &[0u8; MSG1_PAYLOAD_LEN]);
        b.send_to_node(1, &frame).await.unwrap();
        let _ = a.handle_incoming().await.unwrap();
        // 入站跳=2：直连 miss 达阈值被剔除 → flow hash 选中继路径
        assert_eq!(a.pick_path(3, 0).unwrap().path_id, 2);
    }

    #[tokio::test]
    async fn direct_ingress_resets_path_health() {
        // 直连到达的帧（UDP 发送者 = 源节点）：全部路径健康恢复，主路径回归
        let mut a = MeshData::bind("127.0.0.1:0".parse().unwrap(), 1)
            .await
            .unwrap();
        let mut b = MeshData::bind("127.0.0.1:0".parse().unwrap(), 2)
            .await
            .unwrap();
        a.set_endpoint(3, b.local_addr().unwrap()); // b 充当节点 3 的端点
        b.set_endpoint(1, a.local_addr().unwrap());
        a.set_key_dst(1, node_key(1)); // 自身 key_dst（relay 路由校验用）
        let direct = PathEntry {
            path_id: 1,
            path_epoch: 1,
            hops: vec![3],
            expires_at: unix_seconds() + 3600,
        };
        let relayed = PathEntry {
            path_id: 2,
            path_epoch: 1,
            hops: vec![2, 3],
            expires_at: unix_seconds() + 3600,
        };
        a.set_key_path(1, path_key(1));
        a.set_key_path(2, path_key(2));
        a.set_paths(3, vec![direct, relayed]);
        for _ in 0..PATH_HEALTH_MISS_LIMIT {
            a.path_miss_peer(3);
        }
        assert_eq!(a.pick_path(3, 0).unwrap().path_id, 2); // 直连已剔除
                                                           // 节点 3 直接发来帧（UDP 发送者 = 3 的端点）
        let header = MeshFrameHeader {
            to_node_id: 1,
            from_node_id: 3,
            ..Default::default()
        };
        let frame = build_handshake_frame(&header, &node_key(1), &[0u8; MSG1_PAYLOAD_LEN]);
        b.send_to_node(1, &frame).await.unwrap();
        let _ = a.handle_incoming().await.unwrap();
        // 直连路径恢复 → 主路径回归
        assert_eq!(a.pick_path(3, 0).unwrap().path_id, 1);
    }

    #[tokio::test]
    async fn miss_endpoint_rotates_send_order() {
        // 多端点节点：黑洞端点 miss 后置 → 发送轮换到活性好的端点
        let mut a = MeshData::bind("127.0.0.1:0".parse().unwrap(), 1)
            .await
            .unwrap();
        let ep1 = UdpSocket::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
            .await
            .unwrap();
        let ep2 = UdpSocket::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
            .await
            .unwrap();
        let a1 = ep1.local_addr().unwrap();
        let a2 = ep2.local_addr().unwrap();
        a.set_endpoints(2, vec![a1, a2]);
        let mut buf = [0u8; 8];
        // 活性相同 → 原顺序第一个（ep1）
        a.send_to_node_hop(2, Some(2), b"m1").await.unwrap();
        let (n, _) = ep1.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"m1");
        // 黑洞 miss（上次发送无响应）→ 下次发送轮换到 ep2
        a.miss_endpoint(2);
        a.send_to_node_hop(2, Some(2), b"m2").await.unwrap();
        let (n, _) = ep2.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"m2");
    }

    #[tokio::test]
    async fn expired_path_skipped() {
        let mut a = MeshData::bind("127.0.0.1:0".parse().unwrap(), 1)
            .await
            .unwrap();
        let expired = PathEntry {
            path_id: 9,
            path_epoch: 1,
            hops: vec![2],
            expires_at: 1, // 已过期
        };
        a.set_key_path(9, path_key(9));
        a.set_paths(2, vec![expired]);
        assert!(a.pick_path(2, 0).is_none());
    }

    #[tokio::test]
    async fn ttl_expired_dropped() {
        let mut relay = MeshData::bind("127.0.0.1:0".parse().unwrap(), 2)
            .await
            .unwrap();
        relay.set_key_dst(3, node_key(3));
        let frame = frame_from(1, 3, b"payload", 0, 1);
        assert_eq!(
            relay.relay(&frame).await,
            RelayOutcome::Dropped {
                reason: DropReason::TtlExpired
            }
        );
    }

    #[tokio::test]
    async fn no_endpoint_dropped() {
        let mut relay = MeshData::bind("127.0.0.1:0".parse().unwrap(), 2)
            .await
            .unwrap();
        relay.set_key_dst(3, node_key(3));
        let frame = frame_from(1, 3, b"payload", 64, 1);
        assert_eq!(
            relay.relay(&frame).await,
            RelayOutcome::Dropped {
                reason: DropReason::NoEndpoint
            }
        );
    }

    #[tokio::test]
    async fn short_frame_dropped() {
        let mut relay = MeshData::bind("127.0.0.1:0".parse().unwrap(), 2)
            .await
            .unwrap();
        assert_eq!(
            relay.relay(&[0u8; 10]).await,
            RelayOutcome::Dropped {
                reason: DropReason::Short
            }
        );
    }

    #[tokio::test]
    async fn delivered_to_self() {
        let mut node = MeshData::bind("127.0.0.1:0".parse().unwrap(), 3)
            .await
            .unwrap();
        node.set_key_dst(3, node_key(3));
        let frame = frame_from(1, 3, b"payload", 64, 1);
        match node.relay(&frame).await {
            RelayOutcome::Delivered { from, .. } => assert_eq!(from, 1),
            other => panic!("expected delivered, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn bad_version_dropped() {
        let mut relay = MeshData::bind("127.0.0.1:0".parse().unwrap(), 2)
            .await
            .unwrap();
        relay.set_key_dst(3, node_key(3));
        let mut frame = frame_from(1, 3, b"payload", 64, 1);
        frame[0] = 0x03; // 非法版本（0x01=v1，0x02=v2）
        assert_eq!(
            relay.relay(&frame).await,
            RelayOutcome::Dropped {
                reason: DropReason::BadVersion
            }
        );
    }

    #[tokio::test]
    async fn v2_frame_shorter_than_header_rejected() {
        let mut relay = MeshData::bind("127.0.0.1:0".parse().unwrap(), 2)
            .await
            .unwrap();
        let frame = frame_from(1, 3, b"payload", 64, 1);
        let mut short = frame[..HEADER_LEN].to_vec(); // 34B
        short[0] = VERSION2; // v2 帧头要求 42B
        assert_eq!(
            relay.relay(&short).await,
            RelayOutcome::Dropped {
                reason: DropReason::Short
            }
        );
    }

    #[tokio::test]
    async fn send_to_unknown_node_returns_false() {
        let a = MeshData::bind("127.0.0.1:0".parse().unwrap(), 1)
            .await
            .unwrap();
        let frame = frame_from(1, 9, b"payload", 64, 1);
        assert!(!a.send_to_node(9, &frame).await.unwrap());
    }

    fn broadcast_key() -> [u8; 32] {
        derive_key_dst(&MASTER, 0xFFFF_FFFF)
    }

    async fn broadcast_setup(ids: &[u32]) -> Vec<MeshData> {
        let mut nodes = Vec::new();
        for id in ids {
            nodes.push(
                MeshData::bind("127.0.0.1:0".parse().unwrap(), *id)
                    .await
                    .unwrap(),
            );
        }
        let addrs: Vec<(u32, SocketAddr)> = nodes
            .iter()
            .map(|n| (n.self_node_id, n.local_addr().unwrap()))
            .collect();
        for node in nodes.iter_mut() {
            node.set_broadcast_key(broadcast_key());
            for (peer, addr) in &addrs {
                if *peer == node.self_node_id {
                    continue;
                }
                node.set_endpoint(*peer, *addr);
            }
        }
        nodes
    }

    #[tokio::test]
    async fn broadcast_roundtrip_delivered() {
        let mut nodes = broadcast_setup(&[1, 2]).await;
        let payload = b"nd multicast ns";
        let frame = nodes[0].build_broadcast_frame(payload).unwrap();
        nodes[0].send_to_node(2, &frame).await.unwrap();
        assert_eq!(
            nodes[1].handle_incoming().await.unwrap(),
            IncomingEvent::Broadcast {
                from: 1,
                payload: payload.to_vec()
            }
        );
    }

    #[tokio::test]
    async fn broadcast_before_key_dropped() {
        let mut a = MeshData::bind("127.0.0.1:0".parse().unwrap(), 1)
            .await
            .unwrap();
        assert_eq!(
            a.build_broadcast_frame(b"x").unwrap_err(),
            SendError::NoKeyDst
        );
    }

    #[tokio::test]
    async fn broadcast_replay_dropped() {
        // relay 去重（30s）只挡短期重复；重放窗口挡去重过期后的旧帧重注入
        let mut nodes = broadcast_setup(&[1, 2]).await;
        let frame = nodes[0].build_broadcast_frame(b"payload").unwrap();
        assert!(matches!(
            nodes[1].handle_broadcast_frame(1, &frame),
            IncomingEvent::Broadcast { from: 1, .. }
        ));
        assert_eq!(
            nodes[1].handle_broadcast_frame(1, &frame),
            IncomingEvent::Dropped {
                reason: DropReason::Replay
            }
        );
    }

    #[tokio::test]
    async fn broadcast_relay_floods_to_all_except_source() {
        let mut nodes = broadcast_setup(&[1, 2, 3]).await;
        let frame = nodes[0].build_broadcast_frame(b"hello all").unwrap();
        nodes[0].send_to_node(2, &frame).await.unwrap();
        let outcome = nodes[1].relay(&frame).await;
        match outcome {
            RelayOutcome::Flooded {
                from, forwarded, ..
            } => {
                assert_eq!(from, 1);
                assert_eq!(forwarded, vec![3]);
            }
            other => panic!("expected flood, got {:?}", other),
        }
        assert_eq!(
            nodes[2].handle_incoming().await.unwrap(),
            IncomingEvent::Broadcast {
                from: 1,
                payload: b"hello all".to_vec()
            }
        );
    }

    #[tokio::test]
    async fn broadcast_relay_no_echo_to_source() {
        let mut nodes = broadcast_setup(&[1, 2, 3]).await;
        let frame = nodes[0].build_broadcast_frame(b"hello").unwrap();
        nodes[0].send_to_node(2, &frame).await.unwrap();
        let outcome = nodes[1].relay(&frame).await;
        match outcome {
            RelayOutcome::Flooded { forwarded, .. } => assert!(!forwarded.contains(&1)),
            other => panic!("expected flood, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn broadcast_relay_dedup_drops_repeat() {
        let mut nodes = broadcast_setup(&[1, 2]).await;
        let frame = nodes[0].build_broadcast_frame(b"hello").unwrap();
        nodes[0].send_to_node(2, &frame).await.unwrap();
        assert!(matches!(
            nodes[1].relay(&frame).await,
            RelayOutcome::Flooded { .. }
        ));
        nodes[0].send_to_node(2, &frame).await.unwrap();
        assert_eq!(
            nodes[1].relay(&frame).await,
            RelayOutcome::Dropped {
                reason: DropReason::Duplicate
            }
        );
    }

    #[tokio::test]
    async fn broadcast_self_origin_dropped() {
        let mut nodes = broadcast_setup(&[1, 2]).await;
        let frame = nodes[0].build_broadcast_frame(b"loop").unwrap();
        assert_eq!(
            nodes[0].relay(&frame).await,
            RelayOutcome::Dropped {
                reason: DropReason::Duplicate
            }
        );
    }

    #[tokio::test]
    async fn broadcast_ttl_zero_dropped() {
        let mut nodes = broadcast_setup(&[1, 2]).await;
        let mut frame = nodes[0].build_broadcast_frame(b"x").unwrap();
        frame[3] = 0;
        let mut b = MeshData::bind("127.0.0.1:0".parse().unwrap(), 3)
            .await
            .unwrap();
        b.set_broadcast_key(broadcast_key());
        assert_eq!(
            b.relay(&frame).await,
            RelayOutcome::Dropped {
                reason: DropReason::TtlExpired
            }
        );
    }

    #[tokio::test]
    async fn broadcast_wrong_type_dropped() {
        let _nodes = broadcast_setup(&[1, 2]).await;
        // 单播载荷伪装 to=广播保留值：type≠广播 → 广播路径拒绝
        let mut b = MeshData::bind("127.0.0.1:0".parse().unwrap(), 2)
            .await
            .unwrap();
        b.set_broadcast_key(broadcast_key());
        let header = MeshFrameHeader {
            packet_type: packet_type::UNICAST,
            to_node_id: BROADCAST_NODE_ID,
            from_node_id: 1,
            ..Default::default()
        };
        let frame = build_frame(&header, &[0x24; 32], &[0x24; 32], 0, b"x").unwrap();
        assert_eq!(
            b.relay(&frame).await,
            RelayOutcome::Dropped {
                reason: DropReason::UnsupportedType
            }
        );
    }

    #[tokio::test]
    async fn broadcast_tampered_route_mac_dropped() {
        let mut nodes = broadcast_setup(&[1, 2]).await;
        let mut frame = nodes[0].build_broadcast_frame(b"x").unwrap();
        frame[8] ^= 0x01;
        assert_eq!(
            nodes[1].relay(&frame).await,
            RelayOutcome::Dropped {
                reason: DropReason::BadRouteMac
            }
        );
    }

    #[tokio::test]
    async fn broadcast_no_key_dropped() {
        let mut nodes = broadcast_setup(&[1, 2]).await;
        let frame = nodes[0].build_broadcast_frame(b"x").unwrap();
        let mut no_key = MeshData::bind("127.0.0.1:0".parse().unwrap(), 3)
            .await
            .unwrap();
        assert_eq!(
            no_key.relay(&frame).await,
            RelayOutcome::Dropped {
                reason: DropReason::NoKeyDst
            }
        );
    }

    #[tokio::test]
    async fn flood_sends_to_all_peers() {
        let mut nodes = broadcast_setup(&[1, 2, 3]).await;
        let sent = nodes[0].flood(b"multicast frame").await;
        assert_eq!(sent, 2);
        assert!(matches!(
            nodes[1].handle_incoming().await.unwrap(),
            IncomingEvent::Broadcast { from: 1, payload: ref p } if p == b"multicast frame"
        ));
        assert!(matches!(
            nodes[2].handle_incoming().await.unwrap(),
            IncomingEvent::Broadcast { from: 1, .. }
        ));
    }

    #[tokio::test]
    async fn flood_skips_self_endpoint() {
        let mut nodes = broadcast_setup(&[1, 2]).await;
        let (a_addr, b_addr) = (
            nodes[0].local_addr().unwrap(),
            nodes[1].local_addr().unwrap(),
        );
        nodes[1].set_endpoint(1, a_addr);
        nodes[1].set_endpoint(2, b_addr);
        let sent = nodes[1].flood(b"self test").await;
        assert_eq!(sent, 1);
        assert_eq!(nodes[1].endpoint_table.len(), 2);
    }

    #[test]
    fn token_bucket_refills_and_exhausts() {
        let mut bucket = TokenBucket::new(10.0, 2);
        assert!(bucket.take());
        assert!(bucket.take());
        assert!(!bucket.take());
        std::thread::sleep(Duration::from_millis(300));
        assert!(bucket.take());
    }

    #[tokio::test]
    async fn flood_rate_limited_when_exhausted() {
        let mut nodes = broadcast_setup(&[1, 2]).await;
        nodes[0].flood_bucket = TokenBucket::new(0.0, 0);
        assert_eq!(nodes[0].flood(b"x").await, 0);
    }
}
