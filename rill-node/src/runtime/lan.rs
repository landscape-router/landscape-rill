//! LAN 侧（tun0）：入包路由裁决 → 懒握手 → 加密帧发送；回写出口

use super::*;

impl Node {
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
                        Err(e) => {
                            debug!("[node] data frame build failed to {}: {:?}", peer, e);
                            LanOutcome::Dropped
                        }
                    }
                }
            }
            RouteVia::Dn42(_) | RouteVia::Tailnet(_) | RouteVia::Direct(_) => LanOutcome::Local,
        }
    }

    pub(super) async fn write_lan(&mut self, payload: &[u8]) {
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
