//! dn42 leg 适配（DN42_LEG §2/§5）：peer 会话任务编排 + 路由注入 + 数据面接驳。
//! - 路由事件 → 用户态路由引擎 LPM（source=Dn42, via=peer 名，ROUTE_ENGINE §3）
//! - 隧道明文包 → LAN 侧出口（v1：对端回程流量；leg→leg 转发属 M2）
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
            self.write_lan(&pkt).await;
        }
    }

    pub fn dn42_peer_names(&self) -> Vec<String> {
        self.dn42_peers.iter().map(|l| l.name.clone()).collect()
    }
}
