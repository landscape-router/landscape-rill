//! ts2021 腿（TS2021_LEG §3.3.2，runtime 内建会话模块）：与 dn42 腿同构的
//! 后台任务 + 通道接驳。控制面任务（register → /machine/map 长轮询流）与
//! 数据面任务（DERP 驱动 + UDP 直连收包，per-peer boringtun 会话）全在
//! spawn 的任务内，Node 侧只持通道句柄（出站包 / netmap 事件 / 入站明文）。
//!
//! 可测性：Ts2021Leg 可不经任务直接构造（test_leg 持通道端点单步驱动 pump_ts2021）。

use super::*;
use crate::config::Ts2021Config;
use landscape_rill_core::route::Prefix;
use landscape_rill_ts2021::controlhttp;
use landscape_rill_ts2021::tailcfg::{self, MapResponse};
use landscape_rill_ts2021::ts2021::{self, ControlClient};
use landscape_rill_ts2021::wg::WgTunnel;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, ServerName};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::Mutex as AsyncMutex;
use tokio_rustls::client::TlsStream;

type Derp = landscape_rill_ts2021::derp::DerpClient<TlsStream<tokio::net::TcpStream>>;

/// DERP 驱动循环的收包观察窗（出站包排空延迟上界；探针实证形态收紧到 100ms）
const DERP_POLL_SLICE: Duration = Duration::from_millis(100);
/// 控制面重连退避上限（mesh 控制面同值语义：1s → 300s）
const CONTROL_BACKOFF_MAX: Duration = Duration::from_secs(300);

/// netmap peer 快照（Node 侧镜像 + 数据面会话表共用形态）
#[derive(Debug, Clone)]
pub struct Ts2021Peer {
    /// hex(node key)——RouteVia::Tailnet 载荷与 WG 会话表键
    pub id: String,
    /// 服务端数字 node ID——增量帧（PeersChanged/Removed/Patch）关联键；0 = 未携带
    pub nid: i64,
    pub key: [u8; 32],
    pub endpoints: Vec<SocketAddr>,
    /// AllowedIPs 原文（发送侧 peer 匹配与引擎路由注入各取所需）
    pub allowed_ips: Vec<String>,
}

pub enum Ts2021Event {
    /// netmap 全量替换（peer 集空也下发——清空路由）
    Netmap { peers: Vec<Ts2021Peer> },
}

/// test_leg 产出的测试侧通道端点
#[cfg(test)]
pub(crate) struct Ts2021TestHandles {
    pub events: mpsc::Sender<Ts2021Event>,
    pub plaintext: mpsc::Sender<Vec<u8>>,
    pub outbound: mpsc::Receiver<(String, Vec<u8>)>,
}

/// 数据面内部命令（控制面任务 → 数据面任务）
enum DataCmd {
    SetPeers(Vec<Ts2021Peer>),
    SetDerp(Box<Derp>, u16),
}

/// 数据面会话表条目（任务内部）
struct PeerSess {
    key: [u8; 32],
    endpoints: Vec<SocketAddr>,
    allowed_ips: Vec<String>,
    tunnel: WgTunnel,
}

/// Node 侧句柄（任务侧通道端点的持有者）
pub struct Ts2021Leg {
    outbound: mpsc::Sender<(String, Vec<u8>)>,
    events: mpsc::Receiver<Ts2021Event>,
    plaintext: mpsc::Receiver<Vec<u8>>,
    /// 广播前缀（subnet routes / exit）：静态（配置）++ mesh routes[] 汇总
    advertise: Arc<std::sync::Mutex<Vec<String>>>,
    advertise_poke: tokio::sync::watch::Sender<u64>,
    /// 静态部分（自家 LAN / exit 开关；mesh 汇总经 set_mesh_routes 并入）
    static_advertise: Vec<String>,
    /// mesh routes[] 汇总开关（advertise_mesh_routes）：仅 ext 形节点开启
    summarize_mesh: bool,
    /// 本节点 tailnet 地址（netmap 全量帧 Node 条目，服务端分配）：
    /// tailnet 侧对本节点的源认可集 = 此地址 ∪ 已广播前缀
    self_addrs: Arc<std::sync::Mutex<Vec<String>>>,
    /// Node 侧镜像（可达性谓词/观测）
    pub(crate) peers: HashMap<String, Ts2021Peer>,
}

impl Ts2021Leg {
    /// 按显式 peer 出站（封装在数据面任务内做）。裁决在引擎（LPM / exit
    /// 解析器）——数据面不做 dst 匹配：exit（对端 0/0 广播）方向 dst 不落在
    /// 对端任何具体前缀内，dst 匹配无法表达"把对端当 exit"的本端决策
    pub async fn send_to(&self, peer: &str, packet: &[u8]) -> bool {
        self.outbound
            .send((peer.to_string(), packet.to_vec()))
            .await
            .is_ok()
    }

    pub fn has_peer(&self, id: &str) -> bool {
        self.peers.contains_key(id)
    }

    /// 直发源可受理性（tailnet allowed-ips 反向约束）：对端（官方 tailscaled）
    /// 按源地址过滤解包后的内层包——仅接受本节点服务端分配地址与已广播前缀
    /// 为源。源不符时直发必被静默丢弃，调用方可达性谓词应判不可达，
    /// LPM 顺延下一候选（如经 ext 回程，ROUTE_ENGINE §3 tailnet 回程模型）
    pub fn accepts_source(&self, src: &IpAddr) -> bool {
        let self_addrs = self.self_addrs.lock().unwrap().clone();
        let adv = self.advertise.lock().unwrap().clone();
        self_addrs
            .iter()
            .chain(adv.iter())
            .any(|cidr| Prefix::parse(cidr).is_ok_and(|p| p.matches(src)))
    }

    /// mesh routes[] 汇总注入（netmap 联动重广播，TSL-05）：静态前缀合并去重，
    /// 变更 poke 控制面任务重发长轮询（Hostinfo 只在新 MapRequest 生效）
    pub fn set_mesh_routes(&self, mesh_routes: Vec<String>) {
        // 汇总门控（TS2021_LEG §3.3.2：广播主体是 ext 节点，advertise_mesh_routes
        // 显式开启）：普通成员注入会把 tailnet 池/他人前缀泄漏回 tailnet，
        // 且自家前缀经 tailnet 绕回成影子路由与本地网段冲突（跨腿互转环）
        if !self.summarize_mesh {
            return;
        }
        let mut merged = self.static_advertise.clone();
        for r in mesh_routes {
            if !merged.contains(&r) {
                merged.push(r);
            }
        }
        let mut adv = self.advertise.lock().unwrap();
        if *adv != merged {
            *adv = merged;
            self.advertise_poke.send_modify(|v| *v += 1);
        }
    }

    /// 测试形态：不 spawn 任务，通道端点交测试单步驱动
    #[cfg(test)]
    pub(crate) fn test_leg() -> (Self, Ts2021TestHandles) {
        Self::test_leg_static(Vec::new(), Vec::new(), false)
    }

    /// 同 test_leg，携带静态广播/本节点地址/汇总开关（门控与源受测试例）
    #[cfg(test)]
    pub(crate) fn test_leg_static(
        advertise: Vec<String>,
        self_addrs: Vec<String>,
        summarize_mesh: bool,
    ) -> (Self, Ts2021TestHandles) {
        let (out_tx, out_rx) = mpsc::channel::<(String, Vec<u8>)>(64);
        let (ev_tx, ev_rx) = mpsc::channel(64);
        let (pt_tx, pt_rx) = mpsc::channel(64);
        let (poke_tx, _poke_rx) = tokio::sync::watch::channel(0u64);
        (
            Self {
                outbound: out_tx,
                events: ev_rx,
                plaintext: pt_rx,
                advertise: Arc::new(std::sync::Mutex::new(advertise.clone())),
                advertise_poke: poke_tx,
                static_advertise: advertise,
                summarize_mesh,
                self_addrs: Arc::new(std::sync::Mutex::new(self_addrs)),
                peers: HashMap::new(),
            },
            Ts2021TestHandles {
                events: ev_tx,
                plaintext: pt_tx,
                outbound: out_rx,
            },
        )
    }
}

/// 依据配置 spawn ts2021 腿（Node::new 期调用；控制面不可达不阻塞启动——
/// 任务内自退避重连，与 mesh 控制面同哲学）
pub(crate) async fn spawn_ts2021_leg(cfg: &Ts2021Config) -> BoxResult<Ts2021Leg> {
    // 身份：machine key 持久化（TSL-10）；node/disco key 每次启动新生成
    let state = std::path::PathBuf::from(&cfg.state_path);
    if let Some(parent) = state.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let machine_key = ts2021::load_or_create_machine_key(&state)?;
    let (node_priv, node_pub) = ts2021::generate_keypair()?;
    let (_, disco_pub) = ts2021::generate_keypair()?;

    // 静态广播：自家 LAN + exit（0.0.0.0/0 + ::/0）
    let mut static_advertise = cfg.advertise_routes.clone();
    if cfg.advertise_exit {
        for d in ["0.0.0.0/0", "::/0"] {
            if !static_advertise.iter().any(|r| r == d) {
                static_advertise.push(d.to_owned());
            }
        }
    }
    let advertise = Arc::new(std::sync::Mutex::new(static_advertise.clone()));
    let self_addrs: Arc<std::sync::Mutex<Vec<String>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    let (poke_tx, poke_rx) = tokio::sync::watch::channel(0u64);

    // 数据面 UDP socket（直连路径）先绑定，端点交控制面任务上报。
    // 端点必须带真实源 IP：0.0.0.0 对端不可拨（wireguard-go "no UDP or
    // DERP addr" 只能等 magicsock lazyEndpoint 从流量源地址反推，竞态分钟级）
    let udp = Arc::new(tokio::net::UdpSocket::bind("0.0.0.0:0").await?);
    let port = udp.local_addr()?.port();
    let host_port = cfg.control_url.trim_start_matches("https://").to_owned();
    let real_ip = async {
        let mut addrs = tokio::net::lookup_host(host_port.as_str()).await.ok()?;
        let a = addrs.find(|a| a.is_ipv4())?;
        let probe = tokio::net::UdpSocket::bind("0.0.0.0:0").await.ok()?;
        probe.connect(a).await.ok()?;
        Some(probe.local_addr().ok()?.ip())
    }
    .await;
    let udp_endpoint = match real_ip {
        Some(ip) => format!("{ip}:{port}"),
        None => format!("0.0.0.0:{port}"),
    };

    let (out_tx, out_rx) = mpsc::channel::<(String, Vec<u8>)>(128);
    let (ev_tx, ev_rx) = mpsc::channel::<Ts2021Event>(16);
    let (pt_tx, pt_rx) = mpsc::channel::<Vec<u8>>(128);
    let (cmd_tx, cmd_rx) = mpsc::channel::<DataCmd>(16);
    let (derp_lost_tx, derp_lost_rx) = mpsc::channel::<()>(1);

    let sessions: Arc<std::sync::Mutex<HashMap<String, PeerSess>>> =
        Arc::new(std::sync::Mutex::new(HashMap::new()));
    let derp: Arc<AsyncMutex<Option<Derp>>> = Arc::new(AsyncMutex::new(None));

    tokio::spawn(run_data_plane(
        node_priv,
        udp.clone(),
        sessions.clone(),
        derp,
        out_rx,
        cmd_rx,
        pt_tx.clone(),
        derp_lost_tx,
    ));
    tokio::spawn(run_udp_recv(udp, sessions, pt_tx));

    tokio::spawn(run_control(
        cfg.clone(),
        machine_key,
        node_priv,
        node_pub,
        disco_pub,
        udp_endpoint,
        advertise.clone(),
        self_addrs.clone(),
        poke_rx,
        derp_lost_rx,
        ev_tx,
        cmd_tx,
    ));

    Ok(Ts2021Leg {
        outbound: out_tx,
        events: ev_rx,
        plaintext: pt_rx,
        advertise,
        advertise_poke: poke_tx,
        static_advertise,
        summarize_mesh: cfg.advertise_mesh_routes,
        self_addrs,
        peers: HashMap::new(),
    })
}

/// 双路发送：对端全部 UDP 端点 + DERP（探针实证形态；DERP 锁短持——
/// 互斥与收包循环的锁交替由 DERP_POLL_SLICE 观察窗保证）
async fn send_wg(
    udp: &tokio::net::UdpSocket,
    derp: &AsyncMutex<Option<Derp>>,
    key: &[u8; 32],
    endpoints: &[SocketAddr],
    bytes: &[u8],
) {
    for ep in endpoints {
        let _ = udp.send_to(bytes, ep).await;
    }
    if let Some(d) = derp.lock().await.as_mut() {
        if let Err(e) = d.send(key, bytes).await {
            debug!("[ts2021] derp send failed: {e}");
        }
    }
}

/// 发送产物（锁内封装完成，锁外异步发送）
type Emit = ([u8; 32], Vec<SocketAddr>, Vec<Vec<u8>>);

/// netmap 全量替换会话表：在场 peer 保留既有 WgTunnel（含活会话），
/// 仅刷新端点/AllowedIPs；新建消失差集。全量重建会杀活会话——对端
/// 按旧 session index 续传，boringtun 静默丢弃，最长 REKEY_AFTER(90s) 才恢复
fn merge_sessions(
    old: &mut HashMap<String, PeerSess>,
    peers: Vec<Ts2021Peer>,
    node_priv: &[u8; 32],
) -> HashMap<String, PeerSess> {
    let mut fresh = HashMap::new();
    for p in peers {
        match old.remove(&p.id) {
            Some(mut sess) => {
                sess.endpoints = p.endpoints;
                sess.allowed_ips = p.allowed_ips;
                fresh.insert(p.id, sess);
            }
            None => {
                let id = p.id.clone();
                fresh.insert(
                    id,
                    PeerSess {
                        key: p.key,
                        endpoints: p.endpoints.clone(),
                        allowed_ips: p.allowed_ips.clone(),
                        tunnel: WgTunnel::new(node_priv, &p.key, index_of(&p.id)),
                    },
                );
            }
        }
    }
    fresh
}

/// 定时器帧（全 peer：握手重传/keepalive/rekey）；std Mutex 不跨 await
fn collect_timer(sessions: &Arc<std::sync::Mutex<HashMap<String, PeerSess>>>) -> Vec<Emit> {
    let mut out = Vec::new();
    let mut s = sessions.lock().unwrap();
    for sess in s.values_mut() {
        let frames = sess.tunnel.update_timers();
        if !frames.is_empty() {
            out.push((sess.key, sess.endpoints.clone(), frames));
        }
    }
    out
}

/// 入站 WG 包解封装：按对端 node key（DERP）或来源地址（UDP）定位会话，
/// 未命中逐个尝试（boringtun 错会话 = Err，无副作用）。返回明文 + 待发帧
fn decap_session(
    sessions: &mut HashMap<String, PeerSess>,
    by_key: Option<&[u8; 32]>,
    by_addr: Option<SocketAddr>,
    datagram: &[u8],
) -> (Option<Vec<u8>>, Vec<Emit>) {
    let mut order: Vec<String> = Vec::new();
    if let Some(k) = by_key {
        order.push(tailcfg::hex(k));
    } else if let Some(addr) = by_addr {
        order.extend(
            sessions
                .iter()
                .filter(|(_, s)| s.endpoints.contains(&addr))
                .map(|(id, _)| id.clone()),
        );
    }
    order.extend(sessions.keys().cloned());
    let src_ip = by_addr.map(|a| a.ip());
    for id in order {
        let Some(sess) = sessions.get_mut(&id) else {
            continue;
        };
        let outcome = sess.tunnel.decapsulate(src_ip, datagram);
        if outcome.plaintext.is_none() && outcome.to_send.is_empty() {
            continue;
        }
        let emit = (sess.key, sess.endpoints.clone(), outcome.to_send);
        return (outcome.plaintext, vec![emit]);
    }
    (None, Vec::new())
}

/// 数据面驱动任务：命令（netmap/DERP）→ 出站包排空 → 定时器（≈1s）→ DERP 收包
#[allow(clippy::too_many_arguments)]
async fn run_data_plane(
    node_priv: [u8; 32],
    udp: Arc<tokio::net::UdpSocket>,
    sessions: Arc<std::sync::Mutex<HashMap<String, PeerSess>>>,
    derp: Arc<AsyncMutex<Option<Derp>>>,
    mut outbound: mpsc::Receiver<(String, Vec<u8>)>,
    mut cmd: mpsc::Receiver<DataCmd>,
    plaintext_tx: mpsc::Sender<Vec<u8>>,
    derp_lost_tx: mpsc::Sender<()>,
) {
    let mut last_timer = Instant::now();
    loop {
        loop {
            match cmd.try_recv() {
                Ok(DataCmd::SetPeers(peers)) => {
                    let mut s = sessions.lock().unwrap();
                    *s = merge_sessions(&mut s, peers, &node_priv);
                }
                Ok(DataCmd::SetDerp(d, _region)) => {
                    *derp.lock().await = Some(*d);
                }
                Err(_) => break,
            }
        }
        // 出站包（LAN/mesh → tailnet）：显式 peer 封装（裁决在引擎，
        // exit 0/0 方向不经 dst 匹配）
        while let Ok((peer, pkt)) = outbound.try_recv() {
            let mut target: Option<Emit> = None;
            {
                let mut s = sessions.lock().unwrap();
                if let Some(sess) = s.get_mut(&peer) {
                    let frames = sess.tunnel.encapsulate(&pkt);
                    if !frames.is_empty() {
                        target = Some((sess.key, sess.endpoints.clone(), frames));
                    }
                }
            }
            if let Some((key, endpoints, frames)) = target {
                for b in frames {
                    send_wg(&udp, &derp, &key, &endpoints, &b).await;
                }
            }
        }
        // 定时器（握手重传/keepalive/rekey）
        let now = Instant::now();
        if now.duration_since(last_timer) >= Duration::from_secs(1) {
            last_timer = now;
            for (key, endpoints, frames) in collect_timer(&sessions) {
                for b in frames {
                    send_wg(&udp, &derp, &key, &endpoints, &b).await;
                }
            }
        }
        // DERP 收包（观察窗切片；None = 未就绪休眠；Err = 连接死亡上报重建）
        let recv = async {
            match derp.lock().await.as_mut() {
                Some(d) => Some(d.recv().await),
                None => {
                    tokio::time::sleep(DERP_POLL_SLICE).await;
                    None
                }
            }
        };
        if let Ok(Some(r)) = tokio::time::timeout(DERP_POLL_SLICE, recv).await {
            match r {
                Ok(pkt) => {
                    let (plain, emits) = {
                        let mut s = sessions.lock().unwrap();
                        decap_session(&mut s, Some(&pkt.source), None, &pkt.data)
                    };
                    debug!(
                        "[ts2021] derp decap: {}B plain={} emits={}",
                        pkt.data.len(),
                        plain.is_some(),
                        emits.len()
                    );
                    for (key, endpoints, frames) in emits {
                        for b in frames {
                            send_wg(&udp, &derp, &key, &endpoints, &b).await;
                        }
                    }
                    if let Some(p) = plain {
                        let _ = plaintext_tx.send(p).await;
                    }
                }
                Err(_) => {
                    *derp.lock().await = None;
                    let _ = derp_lost_tx.try_send(());
                }
            }
        }
    }
}

/// UDP 直连收包任务（对端端点已知时的直接路径；应答原路返回，探针实证形态）
async fn run_udp_recv(
    udp: Arc<tokio::net::UdpSocket>,
    sessions: Arc<std::sync::Mutex<HashMap<String, PeerSess>>>,
    plaintext_tx: mpsc::Sender<Vec<u8>>,
) {
    let mut buf = vec![0u8; 65535 + 148];
    loop {
        let (n, src) = match udp.recv_from(&mut buf).await {
            Ok(x) => x,
            Err(_) => continue,
        };
        let (plain, emits) = {
            let mut s = sessions.lock().unwrap();
            decap_session(&mut s, None, Some(src), &buf[..n])
        };
        for (_key, _endpoints, frames) in emits {
            for b in frames {
                let _ = udp.send_to(&b, src).await;
            }
        }
        if let Some(p) = plain {
            let _ = plaintext_tx.send(p).await;
        }
    }
}

/// 会话索引（boringtun 发起侧 index；id 稳定散列避免 peer 间冲突）
fn index_of(id: &str) -> u32 {
    let mut h: u32 = 0x9e37_79b9;
    for b in id.bytes() {
        h ^= b as u32;
        h = h.wrapping_mul(0x85eb_ca6b);
    }
    h
}

impl Node {
    /// ts2021 leg 事件/明文泵（pump_timers 节奏调用，非阻塞）：netmap →
    /// 引擎路由全量替换 + 镜像更新；明文 → 跨腿 transit 裁决
    /// （tailnet 入站：mesh/dn42 命中走对应腿，否则写 TUN——本地投递或 WAN 出口）
    pub(crate) async fn pump_ts2021(&mut self) {
        let mut inbound: Vec<Vec<u8>> = Vec::new();
        if let Some(leg) = self.ts2021.as_mut() {
            while let Ok(Ts2021Event::Netmap { peers }) = leg.events.try_recv() {
                // 全量替换语义：消失 peer 清路由；在场 peer 先清再插（AllowedIPs 可能变化）
                let fresh: HashSet<String> = peers.iter().map(|p| p.id.clone()).collect();
                for id in leg.peers.keys() {
                    if !fresh.contains(id) {
                        self.engine.remove_tailnet_peer(id);
                    }
                }
                // tailnet exit 候选（REQ-071，ROUTE_ENGINE §5/§8）：对端 0/0 广播方
                // = "把对端当 exit"的方向——不进 LPM，喂默认路由解析器
                let exit_peers: Vec<String> = peers
                    .iter()
                    .filter(|p| p.allowed_ips.iter().any(|c| c.ends_with("/0")))
                    .map(|p| p.id.clone())
                    .collect();
                self.default_route.set_tailnet_exits(exit_peers);
                for p in &peers {
                    self.engine.remove_tailnet_peer(&p.id);
                    for cidr in &p.allowed_ips {
                        // 默认路由（exit 方向）不进 LPM：那是"把对端当 exit"，
                        // 不是"经对端可达此前缀"（exit 语义见 default_route 解析器）
                        if cidr.ends_with("/0") {
                            continue;
                        }
                        if let Ok(prefix) = Prefix::parse(cidr) {
                            self.engine.insert(RouteEntry {
                                prefix,
                                source: RouteSource::Tailnet,
                                via: RouteVia::Tailnet(p.id.clone()),
                                metric: None,
                            });
                        }
                    }
                }
                leg.peers = peers.into_iter().map(|p| (p.id.clone(), p)).collect();
            }
            while let Ok(pkt) = leg.plaintext.try_recv() {
                inbound.push(pkt);
            }
        }
        for pkt in inbound {
            // tailnet → mesh/dn42 = subnet router 转发；未命中 = 本地/WAN（写 TUN，
            // 内核转发 + MASQUERADE 回程 = exit 被用作，ROUTE_ENGINE §5）
            if !self.forward_transit(&pkt, TransitFrom::Tailnet).await {
                self.write_lan(&pkt).await;
            }
        }
    }

    /// mesh routes[] 汇总注入 ts2021 广播（netmap 联动重广播，TSL-05；
    /// control.rs apply_netmap 调用）
    pub(crate) fn ts2021_set_mesh_routes(&self, mesh_routes: Vec<String>) {
        if let Some(leg) = &self.ts2021 {
            leg.set_mesh_routes(mesh_routes);
        }
    }
}

/// 控制面任务：establish（TLS → GET /key → noise 升级 → register）→ 长轮询流。
/// 流断开 / DERP 失联 → 重建连接（同 machine/node keys 重注册幂等，TSL-10 语义）；
/// 广播变更（poke）→ 只发 Lite 端点更新（Hostinfo.RoutableIPs 任何请求生效），
/// 长轮询流全程持有（tailscaled 同源语义）
#[allow(clippy::too_many_arguments)]
async fn run_control(
    cfg: Ts2021Config,
    machine_key: [u8; 32],
    node_priv: [u8; 32],
    node_pub: [u8; 32],
    disco_pub: [u8; 32],
    udp_endpoint: String,
    advertise: Arc<std::sync::Mutex<Vec<String>>>,
    self_addrs: Arc<std::sync::Mutex<Vec<String>>>,
    mut poke_rx: tokio::sync::watch::Receiver<u64>,
    mut derp_lost_rx: mpsc::Receiver<()>,
    ev_tx: mpsc::Sender<Ts2021Event>,
    cmd_tx: mpsc::Sender<DataCmd>,
) {
    // host:port（:authority）与 TLS SNI
    let host_port = cfg.control_url.trim_start_matches("https://").to_owned();
    let mut backoff = Duration::from_secs(1);
    let mut preferred_derp: Option<u16> = None;
    // netmap 快照（数字 node ID 键控）：全量帧重建 / 增量帧合并的基线
    let mut snapshot: HashMap<i64, Ts2021Peer> = HashMap::new();
    // TLS 信任锚 = 配置 CA（自签，同 mesh 控制面哲学）；establish 与 DERP 共用
    let connector = match tls_connector(&cfg.ca_cert_path) {
        Ok(c) => c,
        Err(_) => return,
    };
    loop {
        let mut client =
            match establish(&connector, &cfg, &machine_key, &host_port, &node_pub).await {
                Ok(c) => c,
                Err(e) => {
                    debug!("[ts2021] control establish failed: {e}");
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(CONTROL_BACKOFF_MAX);
                    continue;
                }
            };
        backoff = Duration::from_secs(1);
        let mut stream_ok = true;
        while stream_ok {
            let routables = advertise.lock().unwrap().clone();
            let mut stream = match client
                .map_stream(
                    &node_pub,
                    &disco_pub,
                    &cfg.hostname,
                    &host_port,
                    &routables,
                    preferred_derp,
                )
                .await
            {
                Ok(s) => s,
                Err(e) => {
                    debug!("[ts2021] map_stream open failed: {e}");
                    break;
                }
            };
            // 长轮询流保持持有：后续 netmap 以新帧继续到达（断开重连会造成
            // headscale 侧 online 状态抖动，peer 撤订阅户路由）
            let mut hold = true;
            while hold {
                tokio::select! {
                    r = stream.next_netmap() => match r {
                        Ok(map) => {
                            apply_netmap(
                                &map, &mut client, &connector, &node_pub, &node_priv,
                                &disco_pub, &cfg.hostname, &host_port, &udp_endpoint,
                                &advertise, &self_addrs, &mut preferred_derp, &ev_tx, &cmd_tx,
                                &mut snapshot,
                            )
                            .await;
                        }
                        Err(e) => {
                            debug!("[ts2021] map stream closed: {e}");
                            hold = false;
                        }
                    },
                    _ = poke_rx.changed() => {
                        let _ = poke_rx.borrow_and_update();
                        // 广播变更只发 Lite 更新（OmitPeers=true）：Hostinfo.RoutableIPs
                        // 在任何 MapRequest 生效；长轮询流保持持有——重建流存在
                        // headscale 侧竞态（旧流关闭处理晚于新流注册，e2e 实证）
                        let routables = advertise.lock().unwrap().clone();
                        let endpoints = [udp_endpoint.to_owned()];
                        if let Err(e) = client
                            .map_endpoints_update(
                                &node_pub,
                                &disco_pub,
                                &cfg.hostname,
                                &host_port,
                                &endpoints,
                                preferred_derp,
                                &routables,
                            )
                            .await
                        {
                            debug!("[ts2021] advertise lite update failed: {e}");
                        }
                    }
                    _ = derp_lost_rx.recv() => {
                        info!("[ts2021] derp lost, re-establishing");
                        preferred_derp = None;
                        hold = false;
                        stream_ok = false;
                    }
                }
            }
        }
        tokio::time::sleep(backoff).await;
    }
}

/// TLS 连接器（配置 CA 信任锚）
fn tls_connector(ca_cert_path: &str) -> BoxResult<tokio_rustls::TlsConnector> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter(ca_cert_path)? {
        roots.add(cert?)?;
    }
    let tls_config = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    Ok(tokio_rustls::TlsConnector::from(tls_config))
}

/// netmap 应用：peer 快照下发（Node 路由注入 + 数据面会话表）+ DERP 连接 +
/// Lite 端点上报（对端 netmap 获知本端 UDP 端点与 HomeDERP，反向可达前提）。
/// 全量帧（Peers）重建快照；增量帧（PeersChanged/Removed/Patch）在快照上合并
/// 后同样走 Netmap + SetPeers 下发（merge_sessions 保活语义对两者一致）
#[allow(clippy::too_many_arguments)]
async fn apply_netmap(
    map: &MapResponse,
    client: &mut ControlClient,
    connector: &tokio_rustls::TlsConnector,
    node_pub: &[u8; 32],
    node_priv: &[u8; 32],
    disco_pub: &[u8; 32],
    hostname: &str,
    host_port: &str,
    udp_endpoint: &str,
    advertise: &Arc<std::sync::Mutex<Vec<String>>>,
    self_addrs: &Arc<std::sync::Mutex<Vec<String>>>,
    preferred_derp: &mut Option<u16>,
    ev_tx: &mpsc::Sender<Ts2021Event>,
    cmd_tx: &mpsc::Sender<DataCmd>,
    snapshot: &mut HashMap<i64, Ts2021Peer>,
) {
    if let Some(map_peers) = map.peers.as_ref() {
        // 本节点 tailnet 地址（服务端分配）：源受理性判定的基准
        if let Some(n) = map.node.as_ref() {
            *self_addrs.lock().unwrap() = n.addresses.clone();
        }
        let mut synth = 0i64;
        let peers: Vec<Ts2021Peer> = map_peers
            .iter()
            .filter_map(|p| {
                let key = p.node_key().ok()?;
                Some(Ts2021Peer {
                    id: tailcfg::hex(&key),
                    nid: p.nid.unwrap_or_else(|| {
                        synth -= 1;
                        synth
                    }),
                    key,
                    endpoints: p.endpoints.iter().filter_map(|e| e.parse().ok()).collect(),
                    allowed_ips: p.allowed_ips.clone(),
                })
            })
            .collect();
        // 全量替换增量合并基线（快照键 = 数字 node ID）
        *snapshot = peers.iter().map(|p| (p.nid, p.clone())).collect();
        info!("[ts2021] netmap applied: {} peer(s)", peers.len());
        let _ = ev_tx
            .send(Ts2021Event::Netmap {
                peers: peers.clone(),
            })
            .await;
        let _ = cmd_tx.send(DataCmd::SetPeers(peers)).await;
        if let Some(dn) = map.derp_node() {
            // DERP 连接（region 变化才重建；身份 = node key，tailscaled 同源）
            if *preferred_derp != Some(dn.region_id) {
                match connect_derp(connector, &dn, node_pub, node_priv).await {
                    Ok(derp) => {
                        *preferred_derp = Some(dn.region_id);
                        let _ = cmd_tx
                            .send(DataCmd::SetDerp(Box::new(derp), dn.region_id))
                            .await;
                    }
                    Err(e) => warn!("[ts2021] derp connect failed: {e}"),
                }
            }
            let endpoints = [udp_endpoint.to_owned()];
            // Lite 更新带同构 Hostinfo（含 RoutableIPs）：服务端按请求覆写广播路由，
            // 缺省会清空（tailscaled 每个 MapRequest 全量 Hostinfo，同源）
            let routables = advertise.lock().unwrap().clone();
            if let Err(e) = client
                .map_endpoints_update(
                    node_pub,
                    disco_pub,
                    hostname,
                    host_port,
                    &endpoints,
                    *preferred_derp,
                    &routables,
                )
                .await
            {
                debug!("[ts2021] endpoints update failed: {e}");
            }
        }
    } else if let Some(stats) = apply_delta(snapshot, map) {
        // 增量帧不触发 Lite/DERP：端点广播节奏维持全量帧路径（delta 频率高——
        // 对端 online 抖动即产生，逐帧 Lite 只会放大服务端写放大）
        info!(
            "[ts2021] netmap delta applied: +{} -{} ~{} → {} peer(s)",
            stats.changed,
            stats.removed,
            stats.patched,
            snapshot.len()
        );
        let mut peers: Vec<Ts2021Peer> = snapshot.values().cloned().collect();
        peers.sort_by_key(|p| p.nid);
        let _ = ev_tx
            .send(Ts2021Event::Netmap {
                peers: peers.clone(),
            })
            .await;
        let _ = cmd_tx.send(DataCmd::SetPeers(peers)).await;
    }
    // 无任何 peer 字段 = keepalive/轻量更新帧，整帧跳过
}

/// 增量帧合并统计（观测/单测断言用）
#[derive(Debug, Default, PartialEq)]
struct DeltaStats {
    changed: usize,
    removed: usize,
    patched: usize,
}

/// 字段存在且非空（增量帧判定）
fn non_empty<T>(v: &Option<Vec<T>>) -> bool {
    v.as_ref().is_some_and(|v| !v.is_empty())
}

/// 增量 peer 帧合并（REQ-067，TS2021_LEG §3.3.2）：快照按数字 node ID 键控，
/// hex(node key) 仍是 WG 会话身份——key 轮换 = 同 nid 整条替换，下游
/// merge_sessions 走旧删新建（旧会话拆、新隧道建）。I/O-free 纯快照变换。
/// 返回 None = 本帧无增量字段（keepalive）；未携带 nid 的 patch/removed 条目
/// 无法关联，跳过（全量 Peers 帧总是携带 ID，稳态不落此分支）
fn apply_delta(snapshot: &mut HashMap<i64, Ts2021Peer>, map: &MapResponse) -> Option<DeltaStats> {
    if !(non_empty(&map.peers_changed)
        || non_empty(&map.peers_removed)
        || non_empty(&map.peers_changed_patch))
    {
        return None;
    }
    let mut stats = DeltaStats::default();
    let mut synth = snapshot
        .keys()
        .copied()
        .filter(|k| *k < 0)
        .min()
        .unwrap_or(0);
    if let Some(changed) = map.peers_changed.as_ref() {
        for p in changed {
            let Ok(key) = p.node_key() else {
                continue;
            };
            let nid = p.nid.unwrap_or_else(|| {
                synth -= 1;
                synth
            });
            snapshot.insert(
                nid,
                Ts2021Peer {
                    id: tailcfg::hex(&key),
                    nid,
                    key,
                    endpoints: p.endpoints.iter().filter_map(|e| e.parse().ok()).collect(),
                    allowed_ips: p.allowed_ips.clone(),
                },
            );
            stats.changed += 1;
        }
    }
    if let Some(removed) = map.peers_removed.as_ref() {
        for nid in removed {
            if snapshot.remove(nid).is_some() {
                stats.removed += 1;
            }
        }
    }
    if let Some(patches) = map.peers_changed_patch.as_ref() {
        for patch in patches {
            let Some(nid) = patch.node_id else {
                continue;
            };
            let Some(peer) = snapshot.get_mut(&nid) else {
                continue;
            };
            // 消费字段（Key/Endpoints/AllowedIPs）之外的 patch 字段
            //（Online/PeerSeen/DERP 区域）显式不解析
            if let Some(k) = patch
                .key
                .as_deref()
                .and_then(|k| tailcfg::parse_node_public(k).ok())
            {
                peer.key = k;
                peer.id = tailcfg::hex(&k);
            }
            if let Some(eps) = patch.endpoints.as_ref() {
                peer.endpoints = eps.iter().filter_map(|e| e.parse().ok()).collect();
            }
            if let Some(ips) = patch.allowed_ips.as_ref() {
                peer.allowed_ips = ips.clone();
            }
            stats.patched += 1;
        }
    }
    Some(stats)
}

async fn connect_derp(
    connector: &tokio_rustls::TlsConnector,
    dn: &tailcfg::DerpNode,
    node_pub: &[u8; 32],
    node_priv: &[u8; 32],
) -> BoxResult<Derp> {
    let tcp = tokio::net::TcpStream::connect((dn.hostname.as_str(), dn.port)).await?;
    let tls = connector
        .connect(ServerName::try_from(dn.hostname.clone())?, tcp)
        .await?;
    let host = format!("{}:{}", dn.hostname, dn.port);
    Ok(landscape_rill_ts2021::derp::DerpClient::connect(tls, &host, *node_pub, *node_priv).await?)
}

/// 建立控制面会话并注册（auth key 预授权路径；重注册幂等）
async fn establish(
    connector: &tokio_rustls::TlsConnector,
    cfg: &Ts2021Config,
    machine_key: &[u8; 32],
    host_port: &str,
    node_pub: &[u8; 32],
) -> BoxResult<ControlClient> {
    let hostname = host_port
        .rsplit_once(':')
        .map(|(h, _)| h.to_owned())
        .unwrap_or_else(|| host_port.to_owned());
    let server_name = ServerName::try_from(hostname.clone())?;
    // 连接 1：GET /key 预取服务端 Noise 公钥
    let tcp = tokio::net::TcpStream::connect(host_port).await?;
    let control_key = controlhttp::fetch_control_key(
        connector.connect(server_name.clone(), tcp).await?,
        host_port,
        tailcfg::CURRENT_CAP_VERSION,
    )
    .await?;
    // 连接 2：controlhttp 升级 + Noise IK + register
    let tcp = tokio::net::TcpStream::connect(host_port).await?;
    let stream = controlhttp::upgrade(
        connector.connect(server_name, tcp).await?,
        host_port,
        machine_key,
        &control_key,
        tailcfg::CURRENT_CAP_VERSION,
    )
    .await?;
    let mut client = ts2021::connect(stream).await?;
    let resp = client
        .register(node_pub, &cfg.auth_key, &cfg.hostname, host_port)
        .await?;
    if !resp.is_success() {
        return Err(format!("ts2021 register rejected: {}", resp.error).into());
    }
    Ok(client)
}

#[cfg(test)]
mod tests {
    use super::*;
    use landscape_rill_ts2021::wg::icmp_echo_request;
    use std::net::Ipv4Addr;

    fn delta_frame(
        changed: Vec<landscape_rill_ts2021::tailcfg::NetPeer>,
        removed: Vec<i64>,
        patch: Vec<landscape_rill_ts2021::tailcfg::PeerPatch>,
    ) -> MapResponse {
        let mut m = keepalive_frame();
        if !changed.is_empty() {
            m.peers_changed = Some(changed);
        }
        if !removed.is_empty() {
            m.peers_removed = Some(removed);
        }
        if !patch.is_empty() {
            m.peers_changed_patch = Some(patch);
        }
        m
    }

    fn keepalive_frame() -> MapResponse {
        MapResponse {
            node: None,
            peers: None,
            peers_changed: None,
            peers_removed: None,
            peers_changed_patch: None,
            derp_map: None,
        }
    }

    fn net_peer(
        nid: i64,
        key: &[u8; 32],
        eps: &[&str],
        ips: &[&str],
    ) -> landscape_rill_ts2021::tailcfg::NetPeer {
        landscape_rill_ts2021::tailcfg::NetPeer {
            nid: Some(nid),
            key: format!("nodekey:{}", tailcfg::hex(key)),
            endpoints: eps.iter().map(|s| s.to_string()).collect(),
            allowed_ips: ips.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// 增量帧合并语义（REQ-067）：keepalive 判 None；upsert 保留 hex 身份；
    /// patch 按 nid 应用端点/AllowedIPs；removed 清理；key 轮换 = 同 nid 换身份
    ///（下游 merge_sessions 走旧删新建）；未知 nid 跳过
    #[test]
    fn apply_delta_merges_incremental_frames() {
        let (_, peer_pub) = ts2021::generate_keypair().unwrap();
        let mut snap = HashMap::from([(
            5i64,
            Ts2021Peer {
                id: tailcfg::hex(&peer_pub),
                nid: 5,
                key: peer_pub,
                endpoints: vec![],
                allowed_ips: vec!["10.99.0.0/24".to_owned()],
            },
        )]);

        // keepalive（无增量字段）→ None
        assert_eq!(apply_delta(&mut snap, &keepalive_frame()), None);

        // PeersChanged 同 nid 新端点：hex 身份不变（会话保活前提）
        let frame = delta_frame(
            vec![net_peer(5, &peer_pub, &["192.0.2.10:41641"], &[])],
            vec![],
            vec![],
        );
        assert_eq!(
            apply_delta(&mut snap, &frame),
            Some(DeltaStats {
                changed: 1,
                removed: 0,
                patched: 0
            })
        );
        assert_eq!(snap[&5].id, tailcfg::hex(&peer_pub));
        assert_eq!(
            snap[&5].endpoints,
            vec!["192.0.2.10:41641".parse::<SocketAddr>().unwrap()]
        );

        // patch：仅出现字段替换（端点 + AllowedIPs）
        let patch = landscape_rill_ts2021::tailcfg::PeerPatch {
            node_id: Some(5),
            key: None,
            endpoints: Some(vec!["192.0.2.11:41641".to_owned()]),
            allowed_ips: Some(vec!["10.98.0.0/24".to_owned()]),
        };
        let frame = delta_frame(vec![], vec![], vec![patch]);
        assert_eq!(
            apply_delta(&mut snap, &frame),
            Some(DeltaStats {
                changed: 0,
                removed: 0,
                patched: 1
            })
        );
        assert_eq!(
            snap[&5].endpoints,
            vec!["192.0.2.11:41641".parse::<SocketAddr>().unwrap()]
        );
        assert_eq!(snap[&5].allowed_ips, vec!["10.98.0.0/24".to_owned()]);

        // key 轮换：同 nid 新 key → hex 身份迁移
        let (_, new_pub) = ts2021::generate_keypair().unwrap();
        let frame = delta_frame(vec![net_peer(5, &new_pub, &[], &[])], vec![], vec![]);
        apply_delta(&mut snap, &frame).unwrap();
        assert_eq!(snap[&5].id, tailcfg::hex(&new_pub));
        assert_eq!(snap[&5].key, new_pub);

        // removed：清理 + 统计；未知 nid 跳过
        let frame = delta_frame(vec![], vec![5, 99], vec![]);
        assert_eq!(
            apply_delta(&mut snap, &frame),
            Some(DeltaStats {
                changed: 0,
                removed: 1,
                patched: 0
            })
        );
        assert!(snap.is_empty());
    }

    /// netmap 全量重放不得杀活会话（对端按旧 session index 续传，
    /// 重建隧道 = 最长 REKEY_AFTER 90s 数据面黑洞，e2e 实证）
    #[test]
    fn merge_sessions_preserves_live_session() {
        let (our_priv, our_pub) = ts2021::generate_keypair().unwrap();
        let (peer_priv, peer_pub) = ts2021::generate_keypair().unwrap();
        let id = tailcfg::hex(&peer_pub);
        let mut sessions = HashMap::new();
        sessions.insert(
            id.clone(),
            PeerSess {
                key: peer_pub,
                endpoints: vec![],
                allowed_ips: vec!["10.99.0.0/24".to_owned()],
                tunnel: WgTunnel::new(&our_priv, &peer_pub, 7),
            },
        );
        // 对侧（模拟 tailscaled）：握手 initiation → 我侧应答 → 双侧会话建立
        let mut peer_side = WgTunnel::new(&peer_priv, &our_pub, 9);
        let init = peer_side.ensure_initiated();
        let (_, emits) = decap_session(&mut sessions, Some(&peer_pub), None, &init[0]);
        let resp = emits[0].2[0].clone();
        peer_side.decapsulate(None, &resp);
        assert!(peer_side.session_established());
        // 握手后数据可解（我侧会话存在的唯一可靠观测：stats 首包数据后才置位）
        let data = peer_side.encapsulate(&icmp_echo_request(
            "10.99.0.2".parse::<Ipv4Addr>().unwrap(),
            "10.99.0.1".parse().unwrap(),
            1,
            1,
            b"lrill",
        ));
        let (plain, _) = decap_session(&mut sessions, Some(&peer_pub), None, &data[0]);
        assert!(plain.is_some());

        // 同 peer netmap 重放（端点/AllowedIPs 更新）：隧道保留，会话存活
        let replay = Ts2021Peer {
            id: id.clone(),
            nid: 5,
            key: peer_pub,
            endpoints: vec!["192.0.2.10:41641".parse().unwrap()],
            allowed_ips: vec!["10.99.0.0/24".to_owned()],
        };
        let mut merged = merge_sessions(&mut sessions, vec![replay], &our_priv);
        assert_eq!(
            merged[&id].endpoints,
            vec!["192.0.2.10:41641".parse::<SocketAddr>().unwrap()]
        );
        // 重放后旧会话数据仍可解（重建隧道时此处为 None）
        let data2 = peer_side.encapsulate(&icmp_echo_request(
            "10.99.0.2".parse().unwrap(),
            "10.99.0.1".parse().unwrap(),
            1,
            2,
            b"lrill",
        ));
        let (plain2, _) = decap_session(&mut merged, Some(&peer_pub), None, &data2[0]);
        assert!(plain2.is_some(), "netmap 重放后活会话应继续解包");

        // 差集语义：消失 peer 移除，新增 peer 建隧道
        let (_, gone_pub) = ts2021::generate_keypair().unwrap();
        let gone = Ts2021Peer {
            id: tailcfg::hex(&gone_pub),
            nid: 6,
            key: gone_pub,
            endpoints: vec![],
            allowed_ips: vec![],
        };
        let fresh = merge_sessions(&mut merged, vec![gone], &our_priv);
        assert!(!fresh.contains_key(&id));
        assert!(fresh.len() == 1);
    }

    /// 汇总门控：未开启 advertise_mesh_routes 的普通成员不注入 mesh 汇总
    /// （防 tailnet 池/他人前缀泄漏 + 影子路由诱导环）；ext 形节点正常合并去重
    #[test]
    fn set_mesh_routes_gated_to_announcer_shape() {
        let (member, _th) = Ts2021Leg::test_leg_static(
            vec!["10.42.0.0/24".into()],
            vec!["100.64.0.1/32".into()],
            false,
        );
        member.set_mesh_routes(vec!["100.64.0.0/10".into()]);
        assert_eq!(
            *member.advertise.lock().unwrap(),
            vec!["10.42.0.0/24".to_owned()],
            "普通成员（静态广播非空）仍不得注入 mesh 汇总"
        );

        let (ext, _th) = Ts2021Leg::test_leg_static(
            vec!["10.43.0.0/24".into(), "0.0.0.0/0".into()],
            vec!["100.64.0.2/32".into()],
            true,
        );
        ext.set_mesh_routes(vec!["10.42.0.0/24".into(), "10.43.0.0/24".into()]);
        assert_eq!(
            *ext.advertise.lock().unwrap(),
            vec![
                "10.43.0.0/24".to_owned(),
                "0.0.0.0/0".to_owned(),
                "10.42.0.0/24".to_owned()
            ]
        );
    }

    /// 直发源可受理性：tailnet 侧仅认可本节点分配地址与已广播前缀为源
    #[test]
    fn accepts_source_scopes_to_assigned_and_advertised() {
        // 无广播成员：仅本节点 tailnet 地址可直发
        let (member, _th) = Ts2021Leg::test_leg_static(vec![], vec!["100.64.0.1/32".into()], false);
        assert!(member.accepts_source(&"100.64.0.1".parse().unwrap()));
        assert!(!member.accepts_source(&"10.42.0.1".parse().unwrap()));

        // 子网路由成员：自家 LAN 前缀亦可直发
        let (subnet, _th) = Ts2021Leg::test_leg_static(
            vec!["10.42.0.0/24".into()],
            vec!["100.64.0.1/32".into()],
            false,
        );
        assert!(subnet.accepts_source(&"10.42.0.1".parse().unwrap()));
        assert!(!subnet.accepts_source(&"10.43.0.9".parse().unwrap()));

        // exit 成员：0.0.0.0/0 广播 = 任意 v4 源可直发
        let (exit_node, _th) = Ts2021Leg::test_leg_static(
            vec!["0.0.0.0/0".into()],
            vec!["100.64.0.2/32".into()],
            true,
        );
        assert!(exit_node.accepts_source(&"192.0.2.9".parse().unwrap()));
    }
}
