//! 会话驱动（DN42_LEG §2/§5）：每 peer 一个 tokio task。
//! WG UDP 传输（boringtun）+ 隧道内用户态 TCP（smoltcp，BGP）+ 定时器，
//! FSM/policy/RIB 纯逻辑串联。隧道断 ⇒ TCP 物理断 ⇒ BGP 会话断 ⇒ 路由撤销。

#[cfg(test)]
mod tests;

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use landscape_rill_core::route::Prefix;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp::{Socket as TcpSocket, SocketBuffer, State as TcpState};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpListenEndpoint};
use tokio::sync::mpsc;

use crate::fsm::{Action, BgpFsm, LocalConfig};
use crate::policy::{ExportPolicy, ImportPolicy};
use crate::rib::{LocRib, RouteChange};
use crate::tunnel::WgTunnel;
use crate::wire::{FrameReader, Message, PathAttr, Segment, UpdateMsg, AFI_IPV6, SAFI_UNICAST};

/// 隧道内 MTU：保守静态值（1500 underlay − WG/外层开销，ROUTE_ENGINE §6 语义）
const TUNNEL_MTU: usize = 1400;
/// smoltcp 轮询周期
const POLL_INTERVAL: Duration = Duration::from_millis(20);
/// TCP 重拨节流
const DIAL_INTERVAL: Duration = Duration::from_secs(1);
const SOCK_BUF: usize = 65535;
/// smoltcp 出口队列上限（防阻塞时无界增长）
const TX_QUEUE_CAP: usize = 64;

#[derive(Debug, Clone)]
pub struct BgpSessionConfig {
    pub local_as: u32,
    pub bgp_id: Ipv4Addr,
    pub peer_as: u32,
    /// 建议 hold time（秒，协商取小；0 = 禁用）
    pub hold_time: u16,
    /// export stub：只公告的自家前缀
    pub own_prefixes: Vec<Prefix>,
    /// import 白名单（covered-by 语义）
    pub whitelist: Vec<Prefix>,
    pub max_prefixes: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct PeerConfig {
    pub name: String,
    /// true = 主动拨号；false = 只 listen（避免双向同时拨号的碰撞）
    pub active: bool,
    /// 对端 underlay UDP 端点
    pub endpoint: SocketAddr,
    pub keys: crate::tunnel::WgPeerKeys,
    /// 本端隧道地址（隧道 /30 + /126 内）
    pub local_v4: Ipv4Addr,
    pub local_v6: Ipv6Addr,
    /// 对端隧道地址（BGP 目标）
    pub peer_v4: Ipv4Addr,
    pub peer_v6: Ipv6Addr,
    pub bgp_port: u16,
    pub local_bgp_port: u16,
    pub bgp: BgpSessionConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteEvent {
    SessionUp,
    SessionDown,
    Changes(Vec<RouteChange>),
}

/// runtime 侧注入的出口
pub struct PeerHooks {
    /// 隧道解密出的数据面明文包 → runtime 转发
    pub plaintext_out: mpsc::Sender<Vec<u8>>,
    /// BGP 会话状态与路由变更
    pub events: mpsc::Sender<RouteEvent>,
}

/// runtime → leg 的出站句柄（数据面包经此进入隧道）
#[derive(Clone)]
pub struct PeerHandle {
    pub outbound: mpsc::Sender<Vec<u8>>,
}

/// spawn 一条 peer 会话任务（自动绑定 UDP），返回出站句柄与事件接收端
pub async fn spawn_peer(
    cfg: PeerConfig,
    hooks: PeerHooks,
) -> std::io::Result<(PeerHandle, mpsc::Receiver<RouteEvent>)> {
    let bind_addr = if cfg.endpoint.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let udp = tokio::net::UdpSocket::bind(bind_addr).await?;
    let (out_tx, out_rx) = mpsc::channel(128);
    let (ev_tx, ev_rx) = mpsc::channel(64);
    tokio::spawn(run_peer(cfg, udp, out_rx, hooks, ev_tx));
    Ok((PeerHandle { outbound: out_tx }, ev_rx))
}

/// 会话任务主体（预绑定 UDP 形态供测试复用）。任务常驻：断开后按退避重连。
pub async fn run_peer(
    cfg: PeerConfig,
    udp: tokio::net::UdpSocket,
    mut outbound: mpsc::Receiver<Vec<u8>>,
    hooks: PeerHooks,
    events: mpsc::Sender<RouteEvent>,
) {
    let mut backoff = Duration::from_secs(1);
    loop {
        let established = session_round(&cfg, &udp, &mut outbound, &hooks, &events).await;
        if established {
            backoff = Duration::from_secs(1);
        }
        tracing::info!(peer = %cfg.name, established, "session round ended, reconnecting");
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}

/// smoltcp 队列设备（medium-ip）
#[derive(Default)]
struct QueueDevice {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
}

struct QueueRx<'a>(&'a mut VecDeque<Vec<u8>>);
struct QueueTx<'a>(&'a mut VecDeque<Vec<u8>>);

impl RxToken for QueueRx<'_> {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        let pkt = self.0.pop_front().unwrap_or_default();
        f(&pkt)
    }
}

impl TxToken for QueueTx<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        buf.truncate(len);
        self.0.push_back(buf);
        r
    }
}

impl Device for QueueDevice {
    type RxToken<'a>
        = QueueRx<'a>
    where
        Self: 'a;
    type TxToken<'a>
        = QueueTx<'a>
    where
        Self: 'a;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if self.rx.is_empty() {
            return None;
        }
        Some((QueueRx(&mut self.rx), QueueTx(&mut self.tx)))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        if self.tx.len() >= TX_QUEUE_CAP {
            return None;
        }
        Some(QueueTx(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = TUNNEL_MTU;
        caps
    }
}

/// 明文包去向：BGP 控制面（目标 = 本端隧道地址）或数据面
enum Destiny {
    Netstack(Vec<u8>),
    Data(Vec<u8>),
}

fn classify(pkt: Vec<u8>, local_v4: Ipv4Addr, local_v6: Ipv6Addr) -> Option<Destiny> {
    let v = *pkt.first()?;
    let dst_matches = match v >> 4 {
        4 if pkt.len() >= 20 => pkt[16..20] == local_v4.octets(),
        6 if pkt.len() >= 40 => pkt[24..40] == local_v6.octets(),
        _ => return None,
    };
    Some(if dst_matches {
        Destiny::Netstack(pkt)
    } else {
        Destiny::Data(pkt)
    })
}

/// 一轮会话：建隧道/网栈/FSM，跑到 TCP 断/超时/对端通知/runtime 停机为止。
/// 返回本轮是否达到过 Established（用于重连退避重置）。
async fn session_round(
    cfg: &PeerConfig,
    udp: &tokio::net::UdpSocket,
    outbound: &mut mpsc::Receiver<Vec<u8>>,
    hooks: &PeerHooks,
    events: &mpsc::Sender<RouteEvent>,
) -> bool {
    let mut device = QueueDevice::default();
    let mut iface_config = Config::new(HardwareAddress::Ip);
    iface_config.random_seed = (cfg.keys.index as u64) | 1;
    let mut iface = Interface::new(iface_config, &mut device, SmolInstant::from_millis(0));
    iface.update_ip_addrs(|addrs| {
        addrs
            .push(IpCidr::new(IpAddress::Ipv4(cfg.local_v4), 30))
            .expect("iface addr v4");
        addrs
            .push(IpCidr::new(IpAddress::Ipv6(cfg.local_v6), 126))
            .expect("iface addr v6");
    });
    let mut sockets: SocketSet<'static> = SocketSet::new(vec![]);
    let tcp_handle = sockets.add(TcpSocket::new(
        SocketBuffer::new(vec![0; SOCK_BUF]),
        SocketBuffer::new(vec![0; SOCK_BUF]),
    ));

    let mut tunnel = WgTunnel::new(cfg.keys.clone());
    let mut fsm = BgpFsm::new(LocalConfig {
        as4: cfg.bgp.local_as,
        bgp_id: cfg.bgp.bgp_id,
        hold_time: cfg.bgp.hold_time,
        peer_as4: Some(cfg.bgp.peer_as),
    });
    let mut policy = ImportPolicy::new(
        cfg.bgp.whitelist.clone(),
        None,
        cfg.bgp.local_as,
        cfg.bgp.max_prefixes,
    );
    let export = ExportPolicy::new(cfg.bgp.own_prefixes.clone());
    let mut rib = LocRib::new();
    let mut frame_reader = FrameReader::default();
    let mut bgp_out: VecDeque<u8> = VecDeque::new();

    let mut was_established = false;
    let mut ever_established = false;
    let mut open_sent = false;
    let mut last_rx = Instant::now();
    let mut last_keepalive = Instant::now();
    let mut last_dial = Instant::now() - DIAL_INTERVAL;

    if cfg.active {
        dial_if_needed(cfg, &mut sockets, tcp_handle, &mut iface, &mut last_dial);
    } else {
        let _ = sockets
            .get_mut::<TcpSocket>(tcp_handle)
            .listen(cfg.bgp_port);
    }

    let mut buf = vec![0u8; 65535];
    let mut recv_buf = vec![0u8; 65535];
    let mut poll_tick = tokio::time::interval(POLL_INTERVAL);
    let mut slow_tick = tokio::time::interval(Duration::from_secs(1));
    poll_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    slow_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // 起始时间基准（smoltcp 需单调递增时间戳）
    let started = Instant::now();

    loop {
        tokio::select! {
                biased;

                // underlay UDP → 隧道
                r = udp.recv_from(&mut buf) => {
                    let Ok((n, src)) = r else { return ever_established };
                    let dec = tunnel.decapsulate(Some(src.ip()), &buf[..n]);
                    for d in dec.to_send {
                        let _ = udp.send_to(&d, cfg.endpoint).await;
                    }
                    if let Some(pkt) = dec.plaintext {
                        match classify(pkt, cfg.local_v4, cfg.local_v6) {
                            Some(Destiny::Netstack(p)) => device.rx.push_back(p),
                            Some(Destiny::Data(p)) => {
                                if hooks.plaintext_out.send(p).await.is_err() {
                                    return ever_established;
                                }
                            }
                            None => {}
                        }
                    }
                }

                // runtime 数据包 → 隧道（None = runtime 停机）
                pkt = outbound.recv() => {
                    let Some(pkt) = pkt else { return ever_established };
                    for d in tunnel.encapsulate(&pkt) {
                        let _ = udp.send_to(&d, cfg.endpoint).await;
                    }
                }

                // 快轮询：smoltcp + BGP 推进
                _ = poll_tick.tick() => {
                    let now = Instant::now();
                    let ts = SmolInstant::from_millis(now.duration_since(started).as_millis() as i64);
                    iface.poll(ts, &mut device, &mut sockets);
                    while let Some(pkt) = device.tx.pop_front() {
                        for d in tunnel.encapsulate(&pkt) {
                            let _ = udp.send_to(&d, cfg.endpoint).await;
                        }
                    }

                    let state = sockets.get_mut::<TcpSocket>(tcp_handle).state();
                    match state {
                        TcpState::Established => {
                            let socket = sockets.get_mut::<TcpSocket>(tcp_handle);
                            if !open_sent {
                                open_sent = true;
                                for act in fsm.on_tcp_established() {
                                    queue_action(act, &mut bgp_out);
                                }
                            }
                            // 收 BGP 字节
                            while socket.can_recv() {
                                match socket.recv_slice(&mut recv_buf) {
                                    Ok(n) if n > 0 => {
                                        last_rx = now;
                                        let mut msgs = Vec::new();
                                        if frame_reader.feed(&recv_buf[..n], &mut msgs).is_err() {
                                            // 畸形流：fail-closed 收场
                                            socket.abort();
                                            break;
                                        }
                                        for msg in msgs {
                                            let established_before =
                                                fsm.state() == crate::fsm::State::Established;
                                            if established_before {
                                                if let Message::Update(update) = &msg {
                                                    let mut outcome =
                                                        rib.apply(&cfg.name, update, &mut policy);
                                                    if !outcome.changes.is_empty() {
                                                        let _ = events
                                                            .send(RouteEvent::Changes(std::mem::take(
                                                                &mut outcome.changes,
                                                            )))
                                                            .await;
                                                    }
                                                    for (cidr, reason) in &outcome.rejected {
                                                        tracing::debug!(peer = %cfg.name, cidr, reason = %reason, "route rejected");
                                                    }
                                                    if outcome.max_prefix_exceeded {
                                                        for act in fsm.notify_max_prefix() {
                                                            queue_action(act, &mut bgp_out);
                                                        }
                                                    }
                                                }
                                            }
                                            let resend =
                                                matches!(msg, Message::RouteRefresh(_)) && established_before;
                                            let acts = fsm.on_message(msg);
                                            for act in acts {
                                                let is_close = matches!(act, Action::Close);
                                                queue_action(act, &mut bgp_out);
                                                if is_close {
                                                    socket.abort();
                                                }
                                            }
                                            if resend {
                                                for m in export_messages(&export, cfg) {
                                                    queue_action(Action::Send(m), &mut bgp_out);
                                                }
                                            }
                                        }
                                    }
                                    _ => break,
                                }
                            }
                        }
                        TcpState::Closed => {
                            open_sent = false;
                            if cfg.active {
                                if cfg.active {
            dial_if_needed(cfg, &mut sockets, tcp_handle, &mut iface, &mut last_dial);
        } else {
            let _ = sockets.get_mut::<TcpSocket>(tcp_handle).listen(cfg.bgp_port);
        }
                            } else {
                                let _ = sockets.get_mut::<TcpSocket>(tcp_handle).listen(cfg.bgp_port);
                            }
                        }
                        _ => {}
                    }

                    // 待发 BGP 字节
                    let socket = sockets.get_mut::<TcpSocket>(tcp_handle);
                    if socket.state() == TcpState::Established && socket.can_send() && !bgp_out.is_empty() {
                        let bytes: Vec<u8> = bgp_out.drain(..).collect();
                        let _ = socket.send_slice(&bytes);
                    }

                    // FSM 进入 Established：发 export + 上报 SessionUp
                    if fsm.state() == crate::fsm::State::Established && !was_established {
                        was_established = true;
                        ever_established = true;
                        for m in export_messages(&export, cfg) {
                            queue_action(Action::Send(m), &mut bgp_out);
                        }
                        let _ = events.send(RouteEvent::SessionUp).await;
                    }
                }

                // 慢轮询：WG 定时器 + BGP keepalive/hold
                _ = slow_tick.tick() => {
                    for d in tunnel.update_timers() {
                        let _ = udp.send_to(&d, cfg.endpoint).await;
                    }
                    if !tunnel.session_established() {
                        for d in tunnel.ensure_initiated() {
                            let _ = udp.send_to(&d, cfg.endpoint).await;
                        }
                    }
                    let now = Instant::now();
                    if fsm.state() == crate::fsm::State::Established {
                        if let Some(interval) = fsm.keepalive_interval() {
                            if now.duration_since(last_keepalive) >= interval {
                                queue_action(Action::Send(Message::Keepalive), &mut bgp_out);
                                last_keepalive = now;
                            }
                        }
                        if fsm.negotiated_hold() > 0
                            && now.duration_since(last_rx) >= Duration::from_secs(fsm.negotiated_hold() as u64)
                        {
                            for act in fsm.on_hold_timer() {
                                queue_action(act, &mut bgp_out);
                            }
                        }
                    }
                }
            }

        if fsm.state() == crate::fsm::State::Idle && was_established {
            // 会话收场：撤销路由 + 通知
            let changes = rib.purge_peer(&cfg.name, &mut policy);
            let _ = events.send(RouteEvent::Changes(changes)).await;
            let _ = events.send(RouteEvent::SessionDown).await;
            return ever_established;
        }
    }
}

fn dial_if_needed(
    cfg: &PeerConfig,
    sockets: &mut SocketSet<'static>,
    handle: SocketHandle,
    iface: &mut Interface,
    last_dial: &mut Instant,
) {
    let now = Instant::now();
    if now.duration_since(*last_dial) < DIAL_INTERVAL {
        return;
    }
    *last_dial = now;
    let socket = sockets.get_mut::<TcpSocket>(handle);
    let remote = smoltcp::wire::IpEndpoint::new(IpAddress::from(cfg.peer_v4), cfg.bgp_port);
    let local = IpListenEndpoint {
        addr: Some(IpAddress::from(cfg.local_v4)),
        port: cfg.local_bgp_port,
    };
    if let Err(e) = socket.connect(iface.context(), remote, local) {
        tracing::debug!(peer = %cfg.name, error = %e, "tcp connect not started");
    }
}

fn queue_action(act: Action, out: &mut VecDeque<u8>) {
    if let Action::Send(msg) = act {
        let mut buf = Vec::new();
        if msg.encode(&mut buf).is_ok() {
            out.extend(buf);
        }
    }
}

/// export stub 的 UPDATE 集：v4 走 NLRI 字段、v6 走 MP_REACH，附 v4 EOR
fn export_messages(export: &ExportPolicy, cfg: &PeerConfig) -> Vec<Message> {
    let mut msgs = Vec::new();
    let v4: Vec<Prefix> = export
        .own_prefixes
        .iter()
        .filter(|p| p.v4)
        .copied()
        .collect();
    let v6: Vec<Prefix> = export
        .own_prefixes
        .iter()
        .filter(|p| !p.v4)
        .copied()
        .collect();
    let as_path = vec![Segment {
        set: false,
        asns: vec![cfg.bgp.local_as],
    }];
    if !v4.is_empty() {
        msgs.push(Message::Update(UpdateMsg {
            withdrawn: vec![],
            // 4B-capable 会话：AS_PATH 直接 4 字节编码，不发 AS4_PATH
            //（RFC 6793——4B 会话上出现 AS4_PATH 按 treat-as-withdraw 处理，FRR 实测拒绝）
            attrs: vec![
                PathAttr::Origin(0),
                PathAttr::AsPath(as_path.clone()),
                PathAttr::NextHop(cfg.local_v4),
            ],
            announced: v4,
        }));
    }
    if !v6.is_empty() {
        msgs.push(Message::Update(UpdateMsg {
            withdrawn: vec![],
            attrs: vec![
                PathAttr::Origin(0),
                PathAttr::AsPath(as_path),
                PathAttr::MpReach {
                    afi: AFI_IPV6,
                    safi: SAFI_UNICAST,
                    next_hop: IpAddr::V6(cfg.local_v6),
                    nlri: v6,
                },
            ],
            announced: vec![],
        }));
    }
    msgs.push(Message::Update(UpdateMsg {
        withdrawn: vec![],
        attrs: vec![],
        announced: vec![],
    }));
    msgs
}
