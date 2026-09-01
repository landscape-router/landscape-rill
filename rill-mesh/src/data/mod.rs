use bytes::{Bytes, BytesMut};
use landscape_rill_core::frame::{
    build_frame, build_handshake_frame, decrement_ttl, frame_payload, header_len,
    open_frame_in_place, packet_type, MeshFrameHeader, ReplayWindow, BROADCAST_NODE_ID, HEADER_LEN,
    HEADER_LEN_V2, TAG_LEN, VERSION, VERSION2,
};
use landscape_rill_core::handshake::{
    HandshakeContext, HandshakeError, HandshakeInitiator, HandshakeResponder, Session,
    MSG1_PAYLOAD_LEN, MSG2_PAYLOAD_LEN, MSG3_PAYLOAD_LEN,
};
use landscape_rill_core::rate::RateCounter;
use landscape_rill_core::rate::TokenBucket;
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
/// 丢帧摘要周期（LOGGING §5）：事件只计数不逐条输出，每周期最多 1 条摘要
pub const DROP_STATS_PERIOD: Duration = landscape_rill_core::rate::RATE_SUMMARY_PERIOD;
/// 数据面接收缓冲上限（REQ-053）：MTU(1420) + v2 帧头(42) + TAG(16) + 余量。
/// 超长报文被内核截断 → 显式丢弃计数（原为 65535 全收后解析失败丢弃，净效果相同）；
/// 缓冲跨包复用后尺寸只影响常驻内存，不影响每包开销。
pub const MAX_FRAME: usize = 2048;
// 编译期确保上限覆盖最大合法帧（MTU 数据帧与全部握手帧）
const _: () = assert!(MAX_FRAME >= HEADER_LEN_V2 + TAG_LEN + 1420);
const _: () = assert!(MAX_FRAME >= HEADER_LEN + MSG1_PAYLOAD_LEN);
const _: () = assert!(MAX_FRAME >= HEADER_LEN + MSG2_PAYLOAD_LEN);
const _: () = assert!(MAX_FRAME >= HEADER_LEN + MSG3_PAYLOAD_LEN);

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
    /// WAN 接收缓冲（REQ-053）：跨包复用，recv_buf_from 直写 spare 容量免零初始化
    recv_buf: BytesMut,
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
    /// 上次对该发送目标实际选用的路径（pick_path 记录；心跳 miss 定位用——
    /// 非主路径死亡时主路径 miss 不触发切换，CON-06 故障切换）
    last_sent_path: HashMap<u32, u64>,
    /// per-peer 丢帧计数（LOGGING §5：周期摘要；仅已知 peer，防伪造 node_id 膨胀）
    drop_stats: HashMap<u32, RateCounter>,
    /// 全局丢帧计数（未知节点/畸形包，无 peer 可归因）
    drop_stats_global: RateCounter,
    /// 未确认的探针：nonce → (目标节点, 探测端点)；PONG 匹配即移除
    probe_pending: HashMap<u32, (u32, SocketAddr)>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RelayOutcome {
    Forwarded {
        to: u32,
    },
    /// 送达本节点：帧留在调用方的接收缓冲中（零拷贝），由 dispatch 就地解密
    Delivered {
        from: u32,
    },
    /// 广播帧：已泛洪转发；自交付同 Delivered（FRAME_HEADER §2.6）
    Flooded {
        from: u32,
        forwarded: Vec<u32>,
    },
    Dropped {
        reason: DropReason,
    },
}

#[derive(Debug, PartialEq)]
pub enum IncomingEvent {
    /// 已建会话的解密数据载荷（AEAD 解密收尾出口）
    Data {
        from: u32,
        payload: Bytes,
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
        payload: Bytes,
    },
    /// probe PING 到达（CONNECTIVITY §4）：对本节点的 PING 已自动回 PONG
    ProbePing {
        from: u32,
    },
    /// probe PONG 匹配（nonce 一致，CONNECTIVITY §4.1）：endpoint = PONG 的 UDP 源地址；
    /// payload 非空 = coordinator 回显的 seen 地址（"ip:port"，CONNECTIVITY §2）
    ProbePong {
        from: u32,
        endpoint: SocketAddr,
        payload: Vec<u8>,
    },
    Dropped {
        reason: DropReason,
    },
}

pub mod error;
pub use error::{DropReason, SendError};

pub mod broadcast;
pub mod dispatch;
pub mod paths;
pub mod relay;
pub mod session;

impl MeshData {
    pub async fn bind(bind: SocketAddr, self_node_id: u32) -> std::io::Result<Self> {
        let socket = UdpSocket::bind(bind).await?;
        Ok(Self {
            socket,
            recv_buf: BytesMut::with_capacity(MAX_FRAME),
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
            last_sent_path: HashMap::new(),
            drop_stats: HashMap::new(),
            drop_stats_global: RateCounter::new(DROP_STATS_PERIOD),
            probe_pending: HashMap::new(),
        })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// 注册完成后由 runtime 注入真实 node_id（bind 时未知）
    pub fn set_self_node_id(&mut self, node_id: u32) {
        self.self_node_id = node_id;
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

    /// 到目的的首跳（候选路径第一条 hops[0]）；无路径表 = 直发（v1 语义）
    pub fn path_first_hop(&mut self, dest: u32) -> Option<u32> {
        self.pick_path(dest, 0)
            .and_then(|p| p.hops.first().copied())
    }

    /// WAN 接收原语（REQ-053）：BytesMut 跨包复用，返回缓冲切片（未 freeze），
    /// 转发 TTL 递减与就地解密在 freeze 前完成（零拷贝扇出）。
    /// 超长报文（≥ MAX_FRAME）被内核截断 → 丢弃并计全局桶。
    pub async fn recv_frame(&mut self) -> std::io::Result<(SocketAddr, BytesMut)> {
        self.recv_buf.reserve(MAX_FRAME);
        let (n, from) = self.socket.recv_buf_from(&mut self.recv_buf).await?;
        if n >= MAX_FRAME {
            self.recv_buf.clear();
            self.drop_stats_global.tick();
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "frame exceeds MAX_FRAME",
            ));
        }
        Ok((from, self.recv_buf.split_to(n)))
    }

    /// WAN 发送原语（REQ-053 函数级接缝）：数据面全部 socket 发送收口于此，
    /// P4 XDP 快速路径在此抽取。
    pub(super) async fn wan_send(&self, frame: &[u8], addr: SocketAddr) -> std::io::Result<usize> {
        self.socket.send_to(frame, addr).await
    }

    pub fn is_handshake(frame: &[u8]) -> bool {
        frame.len() >= HEADER_LEN && frame[1] == packet_type::HANDSHAKE
    }
}

#[cfg(test)]
mod tests;
