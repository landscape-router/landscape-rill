//! dn42 leg 适配（DN42_LEG §2/§5）：peer 会话任务编排 + 路由注入 + 数据面接驳。
//! - 路由事件 → 用户态路由引擎 LPM（source=Dn42, via=peer 名，ROUTE_ENGINE §3）
//! - 隧道明文包 → 跨腿 transit 裁决（M2）：mesh 路由命中回 mesh，否则 LAN 侧出口
//! - LAN 侧 dn42 路由命中 → 包经 leg 出站通道进隧道

use super::*;
use crate::config::{Dn42Config, Dn42PeerConfig};
use landscape_rill_dn42::rib::RouteChange;
use landscape_rill_dn42::session::{
    BgpSessionConfig, PeerConfig, PeerHooks, RouteEvent as Dn42RouteEvent,
};
use landscape_rill_dn42::tunnel::WgPeerKeys;
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::sync::mpsc;
/// 单 peer 运行态：出站句柄 + 事件/明文接收端 + 会话状态
pub struct Dn42PeerLeg {
    pub name: String,
    /// 对端隧道地址（内核 WG 的 connected /30 等价物：SessionUp 时注入 LPM，
    /// 使内核发往对端隧道地址的应答可裁决进本 leg）
    peer_v4: Ipv4Addr,
    peer_v6: Ipv6Addr,
    outbound: mpsc::Sender<Vec<u8>>,
    events: mpsc::Receiver<Dn42RouteEvent>,
    plaintext: mpsc::Receiver<Vec<u8>>,
    established: bool,
}

impl Dn42PeerLeg {
    pub fn established(&self) -> bool {
        self.established
    }

    /// 明文通道非阻塞探测（观测/测试用）
    pub fn try_recv_plaintext(&mut self) -> Result<Vec<u8>, mpsc::error::TryRecvError> {
        self.plaintext.try_recv()
    }

    pub async fn send(&self, packet: &[u8]) -> bool {
        self.outbound.send(packet.to_vec()).await.is_ok()
    }
}

fn build_peer_config(cfg: &Dn42Config, peer: &Dn42PeerConfig) -> PeerConfig {
    let psk = peer
        .preshared_key
        .as_deref()
        .map(|s| crate::config::dn42::wg_key_decode(s).expect("validated"));
    PeerConfig {
        name: peer.name.clone(),
        active: true,
        endpoint: peer.endpoint,
        keys: WgPeerKeys {
            // 本端私钥由 static_key_seed 派生（节点级），对端公钥来自 peer 配置；
            // boringtun 用 x25519-dalek 同版本类型，clamping 在密钥生成侧完成
            own_private: [0u8; 32], // 由调用方填充（见 spawn_dn42_legs）
            peer_public: crate::config::dn42::wg_key_decode(&peer.public_key).expect("validated"),
            preshared: psk,
            index: peer.local_bgp_port as u32 & 0xffff,
        },
        local_v4: peer.local_v4,
        local_v6: peer.local_v6,
        peer_v4: peer.peer_v4,
        peer_v6: peer.peer_v6,
        bgp_port: peer.bgp_port,
        local_bgp_port: peer.local_bgp_port,
        bgp: BgpSessionConfig {
            local_as: cfg.local_as,
            bgp_id: cfg.bgp_id,
            peer_as: peer.peer_as,
            hold_time: cfg.hold_time,
            own_prefixes: cfg
                .own_prefixes
                .iter()
                .filter_map(|p| landscape_rill_core::route::Prefix::parse(p).ok())
                .collect(),
            whitelist: peer
                .whitelist
                .iter()
                .filter_map(|p| landscape_rill_core::route::Prefix::parse(p).ok())
                .collect(),
            max_prefixes: peer.max_prefixes,
        },
    }
}

impl Node {
    /// 依据配置 spawn 全部 dn42 peer 会话任务（Node::new 期调用）
    pub(crate) async fn spawn_dn42_legs(&mut self, cfg: &Dn42Config) -> BoxResult<()> {
        for peer in &cfg.peers {
            let mut pc = build_peer_config(cfg, peer);
            // 本端 WG 私钥：static_key_seed 派生（节点级密钥，WG clamp 规则）
            let mut own = self.cfg.static_key_seed;
            own[0] &= 248;
            own[31] = own[31] & 127 | 64;
            pc.keys.own_private = own;
            let (out_tx, out_rx) = tokio::sync::mpsc::channel(128);
            let (pt_tx, pt_rx) = tokio::sync::mpsc::channel(128);
            let (ev_tx, ev_rx) = tokio::sync::mpsc::channel(64);
            let udp = tokio::net::UdpSocket::bind(if peer.endpoint.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            })
            .await?;
            tokio::spawn(landscape_rill_dn42::session::run_peer(
                pc,
                udp,
                out_rx,
                PeerHooks {
                    plaintext_out: pt_tx,
                    events: ev_tx.clone(),
                },
                ev_tx,
            ));
            self.dn42_peers.push(Dn42PeerLeg {
                name: peer.name.clone(),
                peer_v4: peer.peer_v4,
                peer_v6: peer.peer_v6,
                outbound: out_tx,
                events: ev_rx,
                plaintext: pt_rx,
                established: false,
            });
        }
        Ok(())
    }

    /// dn42 leg 事件/明文泵（每次主循环迭代调用，非阻塞）
    pub async fn pump_dn42(&mut self) {
        // 先收集再写 LAN：避免 legs 借用与 &mut self 方法冲突
        let mut inbound: Vec<Vec<u8>> = Vec::new();
        for leg in &mut self.dn42_peers {
            loop {
                match leg.events.try_recv() {
                    Ok(ev) => match ev {
                        Dn42RouteEvent::SessionUp => {
                            info!("[node] dn42 session established: {}", leg.name);
                            leg.established = true;
                            // 对端隧道地址入 LPM（等价内核 WG connected 路由）
                            self.engine.insert(RouteEntry {
                                prefix: landscape_rill_core::route::Prefix::from_ip(IpAddr::V4(
                                    leg.peer_v4,
                                )),
                                source: RouteSource::Dn42,
                                via: RouteVia::Dn42(leg.name.clone()),
                                metric: None,
                            });
                            self.engine.insert(RouteEntry {
                                prefix: landscape_rill_core::route::Prefix::from_ip(IpAddr::V6(
                                    leg.peer_v6,
                                )),
                                source: RouteSource::Dn42,
                                via: RouteVia::Dn42(leg.name.clone()),
                                metric: None,
                            });
                        }
                        Dn42RouteEvent::SessionDown => {
                            info!("[node] dn42 session down: {}", leg.name);
                            leg.established = false;
                            self.engine.remove_dn42_peer(&leg.name);
                        }
                        Dn42RouteEvent::Changes(changes) => {
                            for change in changes {
                                match change {
                                    RouteChange::Learned { prefix, .. } => {
                                        info!(
                                            "[node] dn42 learned {} via {}",
                                            prefix.to_cidr(),
                                            leg.name
                                        );
                                        self.engine.insert(RouteEntry {
                                            prefix,
                                            source: RouteSource::Dn42,
                                            via: RouteVia::Dn42(leg.name.clone()),
                                            metric: None,
                                        });
                                    }
                                    RouteChange::Withdrawn(prefix) => {
                                        self.engine.remove_dn42_route(&prefix, &leg.name);
                                    }
                                }
                            }
                        }
                    },
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
                }
            }
            loop {
                match leg.plaintext.try_recv() {
                    Ok(pkt) => inbound.push(pkt),
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
                }
            }
        }
        for pkt in inbound {
            // 回程 transit（M2）：dst 命中 mesh 路由且有会话即回 mesh（dn42 主机 → mesh 节点），
            // 否则写 TUN（本节点自身会话的回程，行为不变）
            if !self.forward_transit(&pkt, false).await {
                self.write_lan(&pkt).await;
            }
        }
    }

    pub fn dn42_peer_names(&self) -> Vec<String> {
        self.dn42_peers.iter().map(|l| l.name.clone()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config as NodeConfig;
    use landscape_rill_core::route::Prefix;

    /// 构造带假 leg 的 Node（无 tun；事件/明文/出站通道由测试持有）
    async fn node_with_leg() -> (
        Node,
        mpsc::Sender<Dn42RouteEvent>,
        mpsc::Sender<Vec<u8>>,
        mpsc::Receiver<Vec<u8>>,
    ) {
        let cfg = NodeConfig {
            coordinator_url: "https://coord.test:8443".into(),
            auth_key: "lrk-lab-1735689600-deadbeef".into(),
            static_key_seed: [1; 32],
            capabilities: 0,
            announce_routes: vec![],
            coord_signing_pubkey: [7; 32],
            ca_cert_path: "/nonexistent".into(),
            udp_echo_addr: None,
            data_transport: Default::default(),
            coord: None,
            dn42: None,
        };
        let mut node = Node::new(cfg, NodeOptions::default()).await.unwrap();
        let (out_tx, _out_rx) = mpsc::channel(64);
        let (ev_tx, ev_rx) = mpsc::channel(64);
        let (pt_tx, pt_rx) = mpsc::channel(64);
        node.dn42_peers.push(Dn42PeerLeg {
            name: "peer-t".into(),
            peer_v4: Ipv4Addr::new(172, 20, 101, 2),
            peer_v6: "fd00:101::2".parse().unwrap(),
            outbound: out_tx,
            events: ev_rx,
            plaintext: pt_rx,
            established: false,
        });
        (node, ev_tx, pt_tx, _out_rx)
    }

    /// 最小 IPv4 包（头 20 字节；校验和不参与转发裁决）
    fn v4_packet(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
        let mut p = vec![0x45, 0, 0, 20, 0, 0, 0, 0, 64, 1, 0, 0];
        p.extend_from_slice(&src);
        p.extend_from_slice(&dst);
        p
    }

    fn learned(cidr: &str) -> Dn42RouteEvent {
        Dn42RouteEvent::Changes(vec![RouteChange::Learned {
            prefix: Prefix::parse(cidr).unwrap(),
            path: landscape_rill_dn42::rib::BgpPath {
                as_path: vec![4242420002],
                next_hop: Some("172.20.100.2".parse().unwrap()),
                origin: 0,
                communities: vec![],
            },
        }])
    }

    fn lookups(node: &Node, cidr: &str) -> Vec<(RouteSource, String)> {
        node.engine
            .lookup(&cidr.parse().unwrap())
            .into_iter()
            .map(|(e, _)| {
                (
                    e.source,
                    match &e.via {
                        RouteVia::Dn42(n) => n.clone(),
                        _ => String::new(),
                    },
                )
            })
            .collect()
    }

    #[tokio::test]
    async fn session_up_injects_peer_tunnel_routes() {
        let (mut node, ev_tx, _pt, _out) = node_with_leg().await;
        ev_tx.send(Dn42RouteEvent::SessionUp).await.unwrap();
        node.pump_dn42().await;
        assert!(node.dn42_peers[0].established());
        // 对端隧道地址入 LPM（内核 WG connected 路由等价物）
        assert_eq!(
            lookups(&node, "172.20.101.2"),
            vec![(RouteSource::Dn42, "peer-t".into())]
        );
        assert_eq!(
            lookups(&node, "fd00:101::2"),
            vec![(RouteSource::Dn42, "peer-t".into())]
        );
    }

    #[tokio::test]
    async fn learned_then_withdrawn_roundtrip() {
        let (mut node, ev_tx, _pt, _out) = node_with_leg().await;
        ev_tx.send(Dn42RouteEvent::SessionUp).await.unwrap();
        ev_tx.send(learned("172.20.100.0/24")).await.unwrap();
        node.pump_dn42().await;
        assert_eq!(
            lookups(&node, "172.20.100.5"),
            vec![(RouteSource::Dn42, "peer-t".into())]
        );
        ev_tx
            .send(Dn42RouteEvent::Changes(vec![RouteChange::Withdrawn(
                Prefix::parse("172.20.100.0/24").unwrap(),
            )]))
            .await
            .unwrap();
        node.pump_dn42().await;
        assert!(lookups(&node, "172.20.100.5").is_empty());
    }

    #[tokio::test]
    async fn session_down_purges_all_dn42_routes() {
        let (mut node, ev_tx, _pt, _out) = node_with_leg().await;
        ev_tx.send(Dn42RouteEvent::SessionUp).await.unwrap();
        ev_tx.send(learned("172.20.100.0/24")).await.unwrap();
        node.pump_dn42().await;
        assert!(!lookups(&node, "172.20.101.2").is_empty());

        ev_tx.send(Dn42RouteEvent::SessionDown).await.unwrap();
        node.pump_dn42().await;
        // 学习路由 + 隧道路由随会话撤销全部清理
        assert!(lookups(&node, "172.20.100.5").is_empty());
        assert!(lookups(&node, "172.20.101.2").is_empty());
        assert!(!node.dn42_peers[0].established());
    }

    #[tokio::test]
    async fn plaintext_channel_drained_by_pump() {
        let (mut node, _ev, pt, _out) = node_with_leg().await;
        pt.send(vec![0x45, 0, 0, 20]).await.unwrap();
        node.pump_dn42().await;
        // 无 tun 时 write_lan 为 no-op，但通道必须被消费（防堆积）
        assert!(matches!(
            node.dn42_peers[0].try_recv_plaintext(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn transit_mesh_to_dn42_via_established_leg() {
        let (mut node, ev_tx, _pt, mut out_rx) = node_with_leg().await;
        ev_tx.send(Dn42RouteEvent::SessionUp).await.unwrap();
        ev_tx.send(learned("172.20.100.0/24")).await.unwrap();
        node.pump_dn42().await;
        let pkt = v4_packet([10, 0, 0, 1], [172, 20, 100, 9]);
        // mesh 入站 + dn42 路由命中 → 出隧道，出站通道收到原包
        assert!(node.forward_transit(&pkt, true).await);
        assert_eq!(out_rx.recv().await.unwrap(), pkt);
        // dn42 入站带 dn42 路由命中 → 不 transit（防环：dn42→dn42 禁止）
        assert!(!node.forward_transit(&pkt, false).await);
    }

    #[tokio::test]
    async fn transit_mesh_ingress_requires_established_leg() {
        let (mut node, _ev, _pt, _out) = node_with_leg().await;
        // leg 未建立：路由在但 reachable 谓词失败 → 回退本地投递
        node.engine.insert(RouteEntry {
            prefix: Prefix::parse("172.20.100.0/24").unwrap(),
            source: RouteSource::Dn42,
            via: RouteVia::Dn42("peer-t".into()),
            metric: None,
        });
        let pkt = v4_packet([10, 0, 0, 1], [172, 20, 100, 9]);
        assert!(!node.forward_transit(&pkt, true).await);
        // 组播永不 transit（广播帧维持写 TUN 泛洪语义）
        let mut mcast = v4_packet([10, 0, 0, 1], [224, 0, 0, 1]);
        mcast[15] = 224;
        assert!(!node.forward_transit(&mcast, true).await);
    }

    #[tokio::test]
    async fn transit_dn42_to_mesh_requires_session() {
        let (mut node, _ev, _pt, _out) = node_with_leg().await;
        // mesh 路由在但无会话 → false（回退写 TUN）
        node.engine.insert(RouteEntry {
            prefix: Prefix::parse("10.42.0.0/24").unwrap(),
            source: RouteSource::Mesh,
            via: RouteVia::Mesh(2),
            metric: None,
        });
        let pkt = v4_packet([172, 20, 100, 9], [10, 42, 0, 5]);
        assert!(!node.forward_transit(&pkt, false).await);
    }
}
