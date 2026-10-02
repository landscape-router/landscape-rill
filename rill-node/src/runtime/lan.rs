//! LAN 侧（tun0）：入包路由裁决 → 懒握手 → 加密帧发送；回写出口

use super::*;

impl Node {
    /// LAN 侧入包（tun0 读取的原始 IP 包）：路由裁决 → 懒握手 → 加密帧发送
    pub async fn pump_lan_packet(&mut self, packet: &[u8]) -> LanOutcome {
        // MSS clamp（ROUTE_ENGINE §6.2）：SYN 的 MSS 压到 min(配置 MTU, 保守值)；
        // 非 SYN 零拷贝直读（预检先行，避免逐包拷贝）
        let clamped;
        let packet = if is_tcp_syn(packet) {
            let mtu = self
                .tun
                .as_ref()
                .map(|t| t.mtu())
                .unwrap_or(TUN_CONSERVATIVE_MTU)
                .min(TUN_CONSERVATIVE_MTU);
            let mut buf = packet.to_vec();
            if clamp_mss(&mut buf, mtu) {
                clamped = buf;
                &clamped
            } else {
                packet
            }
        } else {
            packet
        };
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
            // 可达性谓词：mesh 会话存在即可达；dn42 peer 以 BGP 会话建立为准（DN42_LEG §5）；
            // tailnet peer 在表即可达（WG 封装懒握手，无需预建会话）
            let dn42_up = &self.dn42_peers;
            let reachable = |e: &RouteEntry| match &e.via {
                RouteVia::Mesh(_) => true,
                RouteVia::Dn42(name) => dn42_up
                    .iter()
                    .find(|l| l.name == *name)
                    .is_some_and(|l| l.established()),
                RouteVia::Tailnet(id) => self.ts2021.as_ref().is_some_and(|l| l.has_peer(id)),
                RouteVia::Direct(_) => false,
            };
            let Some(entry) = self.engine.lookup_best(&info.dst, &reachable) else {
                warn!("[node] no route for {}", info.dst);
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
                                Err(e) if is_emsgsize(&e) => {
                                    // DF 超限（EMSGSIZE）：v1 无帧内分片，伪造 PTB
                                    // 回注源端收缩 PMTU（§6.2；src = 内层 dst，
                                    // 探测失败时保守值兜底）
                                    let next_hop_mtu =
                                        self.mesh.take_ptb_mtu().unwrap_or(TUN_CONSERVATIVE_MTU);
                                    if let Some(ptb) = build_ptb(packet, next_hop_mtu) {
                                        self.write_lan(&ptb).await;
                                    }
                                    LanOutcome::Dropped
                                }
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
            RouteVia::Dn42(name) => {
                let Some(leg) = self.dn42_peers.iter().find(|l| l.name == name) else {
                    return LanOutcome::Dropped;
                };
                // 包直接进 WG 隧道（明文由 leg 侧 boringtun 封装）
                if leg.send(packet).await {
                    LanOutcome::SentDn42 { peer: name }
                } else {
                    LanOutcome::Dropped
                }
            }
            RouteVia::Tailnet(id) => {
                // 包进 ts2021 出站通道（peer 匹配/封装在数据面任务内，TS2021_LEG §3.3.2）
                let sent = match self.ts2021.as_ref() {
                    Some(leg) => leg.send(packet).await,
                    None => false,
                };
                if sent {
                    LanOutcome::SentTailnet { peer: id }
                } else {
                    LanOutcome::Dropped
                }
            }
            RouteVia::Direct(_) => LanOutcome::Local,
        }
    }
}

/// 跨腿 transit 来源（转发图边集，TS2021_LEG §3.3.2 / DN42_LEG §7 ⑤）：
/// mesh ↔ dn42、mesh → tailnet（回程）、tailnet → mesh/dn42（subnet router 转发）。
/// 严格单向配对，同腿进出禁止（tailnet 入站命中 Tailnet 路由 = 反射，丢弃），
/// 转发图无环，不依赖 TTL 衰减；v1 不减 TTL
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TransitFrom {
    Mesh,
    Dn42,
    Tailnet,
}

impl TransitFrom {
    /// 日志标签（e2e 断言按 `transit mesh->dn42` 小写格式 grep）
    pub(crate) fn tag(self) -> &'static str {
        match self {
            TransitFrom::Mesh => "mesh",
            TransitFrom::Dn42 => "dn42",
            TransitFrom::Tailnet => "tailnet",
        }
    }
}

impl Node {
    /// 跨腿 transit 转发：mesh/dn42/ts2021 入站明文 → 对应腿。
    /// 未命中 → false，调用方写 TUN（本地投递/WAN 出口）
    pub(super) async fn forward_transit(&mut self, packet: &[u8], from: TransitFrom) -> bool {
        let Ok(info) = parse_packet(packet) else {
            debug!(
                "[node] transit drop: parse failed ({}B from {})",
                packet.len(),
                from.tag()
            );
            return false;
        };
        // 组播/广播维持既有语义（mesh 广播帧写 TUN 由内核泛洪；dn42/ts2021 侧不 transit 组播）
        if info.dst.is_multicast() {
            return false;
        }
        let (via, dst) = {
            let dn42_up = &self.dn42_peers;
            let reachable = |e: &RouteEntry| match &e.via {
                RouteVia::Mesh(_) => true,
                RouteVia::Dn42(name) => dn42_up
                    .iter()
                    .find(|l| l.name == *name)
                    .is_some_and(|l| l.established()),
                RouteVia::Tailnet(id) => self.ts2021.as_ref().is_some_and(|l| l.has_peer(id)),
                RouteVia::Direct(_) => false,
            };
            let Some(entry) = self.engine.lookup_best(&info.dst, &reachable) else {
                debug!(
                    "[node] transit drop: no route for {} (from {})",
                    info.dst,
                    from.tag()
                );
                return false;
            };
            (entry.via.clone(), info.dst)
        };
        match (&via, from) {
            (RouteVia::Dn42(name), TransitFrom::Mesh | TransitFrom::Tailnet) => {
                let Some(leg) = self.dn42_peers.iter().find(|l| &l.name == name) else {
                    debug!("[node] transit drop: dn42 leg missing: {}", name);
                    return false;
                };
                if leg.send(packet).await {
                    info!(
                        "[node] transit {}->dn42: {} via {}",
                        from.tag(),
                        dst,
                        leg.name
                    );
                    true
                } else {
                    debug!("[node] transit drop: dn42 send failed: {}", leg.name);
                    false
                }
            }
            (RouteVia::Mesh(peer), TransitFrom::Dn42 | TransitFrom::Tailnet) => {
                let peer = *peer;
                if !self.mesh.has_session(peer) {
                    debug!(
                        "[node] transit {}->mesh: {} no session with {}",
                        from.tag(),
                        dst,
                        peer
                    );
                    return false;
                }
                let flow = flow_hash(&info);
                match self.mesh.build_data_frame(peer, packet, flow) {
                    Ok((frame, first_hop)) => {
                        // EMSGSIZE 同样按 drop：PTB 回注 dn42/ts2021 腿不在 v1 范围（§6.2 仅 tun0 侧）
                        let ok = self
                            .mesh
                            .send_to_node_hop(peer, first_hop, &frame)
                            .await
                            .unwrap_or(false);
                        if ok {
                            info!(
                                "[node] transit {}->mesh: {} via node {}",
                                from.tag(),
                                dst,
                                peer
                            );
                        }
                        ok
                    }
                    Err(e) => {
                        debug!(
                            "[node] transit {}->mesh: {} frame build failed: {:?}",
                            from.tag(),
                            dst,
                            e
                        );
                        false
                    }
                }
            }
            // 回程（ROUTE_ENGINE §3）：mesh 入站 dst 命中 tailnet 路由 → ts2021 出站
            (RouteVia::Tailnet(id), TransitFrom::Mesh) => {
                let sent = match self.ts2021.as_ref() {
                    Some(leg) => leg.send(packet).await,
                    None => false,
                };
                if sent {
                    info!("[node] transit mesh->tailnet: {} via {}", dst, id);
                }
                sent
            }
            // 反射防护：tailnet 入站不得再出 tailnet（同腿进出 = 环）
            (RouteVia::Tailnet(_), TransitFrom::Tailnet) => {
                debug!("[node] transit tailnet reflection dropped: {}", dst);
                true
            }
            // dn42 → tailnet 不在 v1 边集（dn42 侧可达 tailnet 经 mesh 中转）
            (RouteVia::Tailnet(_), TransitFrom::Dn42) => false,
            // 同腿进出（mesh→mesh / dn42→dn42）不存在于边集；Local 出口走 TUN
            _ => {
                let cands: Vec<(u8, std::string::String)> = self
                    .engine
                    .table()
                    .matches(&dst)
                    .into_iter()
                    .map(|e| (e.source.priority(), format!("{:?}", e.via)))
                    .collect();
                debug!(
                    "[node] transit drop: no edge via {:?} ({}->) dst {} candidates {:?}",
                    via,
                    from.tag(),
                    dst,
                    cands
                );
                false
            }
        }
    }

    pub(super) async fn write_lan(&mut self, payload: &[u8]) {
        let Some(tun) = self.tun.as_mut() else {
            return;
        };
        // MSS clamp（§6.2）：mesh → LAN 方向的 SYN 同样压 MSS（对端不参与改写）
        let clamped;
        let payload = {
            let mtu = tun.mtu().min(TUN_CONSERVATIVE_MTU);
            if is_tcp_syn(payload) {
                let mut buf = payload.to_vec();
                if clamp_mss(&mut buf, mtu) {
                    clamped = buf;
                    &clamped
                } else {
                    payload
                }
            } else {
                payload
            }
        };
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
