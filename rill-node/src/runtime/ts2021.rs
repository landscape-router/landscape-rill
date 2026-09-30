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
    pub outbound: mpsc::Receiver<Vec<u8>>,
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

impl PeerSess {
    /// 发送侧 dst 匹配：AllowedIPs 含 dst 即选此 peer。
    /// 默认路由（0.0.0.0/0、::/0）不匹配——那是"把对端当 exit"的方向，
    /// 反向（我们持有对端全量路由）不成立
    fn match_dst(&self, packet: &[u8]) -> bool {
        let Ok(info) = crate::packet::parse_packet(packet) else {
            return false;
        };
        self.allowed_ips.iter().any(|cidr| {
            !cidr.ends_with("/0") && Prefix::parse(cidr).is_ok_and(|p| p.matches(&info.dst))
        })
    }
}

/// Node 侧句柄（任务侧通道端点的持有者）
pub struct Ts2021Leg {
    outbound: mpsc::Sender<Vec<u8>>,
    events: mpsc::Receiver<Ts2021Event>,
    plaintext: mpsc::Receiver<Vec<u8>>,
    /// 广播前缀（subnet routes / exit）：静态（配置）++ mesh routes[] 汇总
    advertise: Arc<std::sync::Mutex<Vec<String>>>,
    advertise_poke: tokio::sync::watch::Sender<u64>,
    /// 静态部分（自家 LAN / exit 开关；mesh 汇总经 set_mesh_routes 并入）
    static_advertise: Vec<String>,
    /// Node 侧镜像（可达性谓词/观测）
    pub(crate) peers: HashMap<String, Ts2021Peer>,
}

impl Ts2021Leg {
    /// 包进 ts2021 出站通道（发送侧 peer 匹配在数据面任务内做）
    pub async fn send(&self, packet: &[u8]) -> bool {
        self.outbound.send(packet.to_vec()).await.is_ok()
    }

    pub fn has_peer(&self, id: &str) -> bool {
        self.peers.contains_key(id)
    }

    /// mesh routes[] 汇总注入（netmap 联动重广播，TSL-05）：静态前缀合并去重，
    /// 变更 poke 控制面任务重发长轮询（Hostinfo 只在新 MapRequest 生效）
    pub fn set_mesh_routes(&self, mesh_routes: Vec<String>) {
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
        let (out_tx, out_rx) = mpsc::channel(64);
        let (ev_tx, ev_rx) = mpsc::channel(64);
        let (pt_tx, pt_rx) = mpsc::channel(64);
        let (poke_tx, _poke_rx) = tokio::sync::watch::channel(0u64);
        (
            Self {
                outbound: out_tx,
                events: ev_rx,
                plaintext: pt_rx,
                advertise: Arc::new(std::sync::Mutex::new(Vec::new())),
                advertise_poke: poke_tx,
                static_advertise: Vec::new(),
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
    let (poke_tx, poke_rx) = tokio::sync::watch::channel(0u64);

    // 数据面 UDP socket（直连路径）先绑定，端点交控制面任务上报
    let udp = Arc::new(tokio::net::UdpSocket::bind("0.0.0.0:0").await?);
    let udp_endpoint = format!("{}", udp.local_addr()?);

    let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>(128);
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

/// 出站明文封装（peer 匹配）或定时器帧（全 peer）；std Mutex 不跨 await
fn collect_emit(
    sessions: &Arc<std::sync::Mutex<HashMap<String, PeerSess>>>,
    packet: &[u8],
    timer: bool,
) -> Vec<Emit> {
    let mut out = Vec::new();
    let mut s = sessions.lock().unwrap();
    for sess in s.values_mut() {
        let frames = if timer {
            sess.tunnel.update_timers()
        } else if sess.match_dst(packet) {
            sess.tunnel.encapsulate(packet)
        } else {
            continue;
        };
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
    mut outbound: mpsc::Receiver<Vec<u8>>,
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
                    *s = peers
                        .into_iter()
                        .map(|p| {
                            let id = p.id.clone();
                            (
                                id,
                                PeerSess {
                                    key: p.key,
                                    endpoints: p.endpoints.clone(),
                                    allowed_ips: p.allowed_ips.clone(),
                                    tunnel: WgTunnel::new(&node_priv, &p.key, index_of(&p.id)),
                                },
                            )
                        })
                        .collect();
                }
                Ok(DataCmd::SetDerp(d, _region)) => {
                    *derp.lock().await = Some(*d);
                }
                Err(_) => break,
            }
        }
        // 出站包（LAN/mesh → tailnet）
        while let Ok(pkt) = outbound.try_recv() {
            for (key, endpoints, frames) in collect_emit(&sessions, &pkt, false) {
                for b in frames {
                    send_wg(&udp, &derp, &key, &endpoints, &b).await;
                }
            }
        }
        // 定时器（握手重传/keepalive/rekey）
        let now = Instant::now();
        if now.duration_since(last_timer) >= Duration::from_secs(1) {
            last_timer = now;
            for (key, endpoints, frames) in collect_emit(&sessions, &[], true) {
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
                for p in &peers {
                    self.engine.remove_tailnet_peer(&p.id);
                    for cidr in &p.allowed_ips {
                        // 默认路由（exit 方向）不进 LPM：那是"把对端当 exit"，
                        // 不是"经对端可达此前缀"
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
/// 广播变更（poke）→ 同连接重发 MapRequest（Hostinfo 只在新请求生效）
#[allow(clippy::too_many_arguments)]
async fn run_control(
    cfg: Ts2021Config,
    machine_key: [u8; 32],
    node_priv: [u8; 32],
    node_pub: [u8; 32],
    disco_pub: [u8; 32],
    udp_endpoint: String,
    advertise: Arc<std::sync::Mutex<Vec<String>>>,
    mut poke_rx: tokio::sync::watch::Receiver<u64>,
    mut derp_lost_rx: mpsc::Receiver<()>,
    ev_tx: mpsc::Sender<Ts2021Event>,
    cmd_tx: mpsc::Sender<DataCmd>,
) {
    // host:port（:authority）与 TLS SNI
    let host_port = cfg.control_url.trim_start_matches("https://").to_owned();
    let mut backoff = Duration::from_secs(1);
    let mut preferred_derp: Option<u16> = None;
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
                                &advertise, &mut preferred_derp, &ev_tx, &cmd_tx,
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
                        info!("[ts2021] advertise changed, re-issuing map request");
                        hold = false;
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
/// Lite 端点上报（对端 netmap 获知本端 UDP 端点与 HomeDERP，反向可达前提）
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
    preferred_derp: &mut Option<u16>,
    ev_tx: &mpsc::Sender<Ts2021Event>,
    cmd_tx: &mpsc::Sender<DataCmd>,
) {
    // 无 Peers 字段 = 不变更（keepalive/轻量更新帧），整帧跳过
    let Some(map_peers) = map.peers.as_ref() else {
        return;
    };
    let peers: Vec<Ts2021Peer> = map_peers
        .iter()
        .filter_map(|p| {
            let key = p.node_key().ok()?;
            Some(Ts2021Peer {
                id: tailcfg::hex(&key),
                key,
                endpoints: p.endpoints.iter().filter_map(|e| e.parse().ok()).collect(),
                allowed_ips: p.allowed_ips.clone(),
            })
        })
        .collect();
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
