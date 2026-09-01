//! 入口分派（CONNECTIVITY §2.1）：帧/probe 端口分派、
//! 送达分发（握手/数据/心跳/广播）、probe 收发、丢帧统计

use super::*;

impl MeshData {
    /// 收帧处理（CONNECTIVITY §2.1 端口分派）：首字节 0x01..=0x0F → 34B 帧；
    /// 其余匹配 probe magic → probe 处理；都不匹配 → 丢弃（fail-closed）。
    /// 帧路径：relay 校验 → 按包类型分发（握手/数据/心跳/广播）。
    /// 入站路径记录 + 逐路径活性在分发前更新（帧实际到达的上一跳 = UDP 发送者归属）。
    /// 丢帧统计在入口收口（LOGGING §5）：relay 无法归因时从帧头补解析。
    pub async fn handle_incoming(&mut self) -> std::io::Result<IncomingEvent> {
        let (from_addr, packet) = self.recv_frame().await?;
        let first = packet.first().copied();
        if matches!(first, Some(b) if (0x01..=0x0F).contains(&b)) {
            // 34B 帧路径（version 值域 0x01..=0x0F，FRAME_HEADER §2.1）
            self.handle_frame(from_addr, &packet).await
        } else if packet.len() >= 4 && packet[..4] == crate::probe::PROBE_MAGIC {
            self.handle_probe(from_addr, &packet).await
        } else {
            // 非帧非 probe → 丢弃（解析 fail-closed，CN-02）
            self.note_drop(None);
            Ok(IncomingEvent::Dropped {
                reason: DropReason::UnknownProtocol,
            })
        }
    }

    /// probe 处理（CONNECTIVITY §4）：PING 对己 → 自动回 PONG；PONG → nonce 匹配确认
    async fn handle_probe(
        &mut self,
        from_addr: SocketAddr,
        packet: &[u8],
    ) -> std::io::Result<IncomingEvent> {
        let Some(probe) = crate::probe::ProbePacket::decode(packet) else {
            self.note_drop(None);
            return Ok(IncomingEvent::Dropped {
                reason: DropReason::UnknownProtocol,
            });
        };
        match probe.packet_type {
            crate::probe::probe_type::PING => {
                if probe.to_node_id == self.self_node_id {
                    let reply = crate::probe::ProbePacket::pong(&probe, Vec::new());
                    let _ = self.wan_send(&reply.encode(), from_addr).await;
                }
                Ok(IncomingEvent::ProbePing {
                    from: probe.from_node_id,
                })
            }
            crate::probe::probe_type::PONG => {
                if self.probe_pending.remove(&probe.nonce).is_some() {
                    Ok(IncomingEvent::ProbePong {
                        from: probe.from_node_id,
                        endpoint: from_addr,
                        payload: probe.payload,
                    })
                } else {
                    // 未知 nonce（迟到/重复/伪造）→ 丢弃
                    self.note_drop(None);
                    Ok(IncomingEvent::Dropped {
                        reason: DropReason::UnknownProtocol,
                    })
                }
            }
            _ => {
                self.note_drop(None);
                Ok(IncomingEvent::Dropped {
                    reason: DropReason::UnknownProtocol,
                })
            }
        }
    }

    /// 向候选端点发送 PING（互探/echo，CONNECTIVITY §4.1）；返回 nonce（PONG 匹配用）。
    /// pending 超上限清空（防伪造 PONG 洪泛撑爆状态，活跃探测由 runtime 周期重发）。
    pub async fn send_probe_ping(
        &mut self,
        endpoint: SocketAddr,
        from: u32,
        to: u32,
    ) -> Option<u32> {
        if self.probe_pending.len() >= 1024 {
            self.probe_pending.clear();
        }
        let nonce = rand::random::<u32>();
        self.probe_pending.insert(nonce, (to, endpoint));
        let packet = crate::probe::ProbePacket::ping(from, to, nonce);
        match self.wan_send(&packet.encode(), endpoint).await {
            Ok(_) => Some(nonce),
            Err(_) => {
                self.probe_pending.remove(&nonce);
                None
            }
        }
    }

    /// 帧路径（原 relay 入口逻辑，分派后调用）
    async fn handle_frame(
        &mut self,
        from_addr: SocketAddr,
        frame: &[u8],
    ) -> std::io::Result<IncomingEvent> {
        match self.relay(frame).await {
            RelayOutcome::Delivered { frame, from } => {
                if let Some(ingress) = self.endpoint_owner(from_addr) {
                    self.ingress_hop.insert(from, ingress);
                    self.note_endpoint_ok(ingress, from_addr);
                }
                self.apply_ingress_health(from);
                let ev = self.dispatch_delivered(from, &frame).await;
                // dispatch 路径丢帧同样收口计数（from 已过 route_mac 校验，归因可信）
                if matches!(ev, IncomingEvent::Dropped { .. }) {
                    self.note_drop(Some(from));
                }
                Ok(ev)
            }
            RelayOutcome::Flooded { frame, from, .. } => {
                if let Some(ingress) = self.endpoint_owner(from_addr) {
                    self.ingress_hop.insert(from, ingress);
                    self.note_endpoint_ok(ingress, from_addr);
                }
                self.apply_ingress_health(from);
                let ev = self.dispatch_delivered(from, &frame).await;
                if matches!(ev, IncomingEvent::Dropped { .. }) {
                    self.note_drop(Some(from));
                }
                Ok(ev)
            }
            RelayOutcome::Forwarded { to } => Ok(IncomingEvent::Relayed { to }),
            RelayOutcome::Dropped { reason } => {
                // 帧头可解析 → 归因源节点（伪造 node_id 不落 per-peer，进全局桶）
                let from = MeshFrameHeader::decode(frame).ok().map(|h| h.from_node_id);
                self.note_drop(from);
                Ok(IncomingEvent::Dropped { reason })
            }
        }
    }

    /// 丢帧计数（LOGGING §5）：仅已知 peer 记 per-peer，未知/畸形包记全局桶
    pub(super) fn note_drop(&mut self, from: Option<u32>) {
        match from {
            Some(f) if self.is_known_peer(f) => {
                let rc = self
                    .drop_stats
                    .entry(f)
                    .or_insert_with(|| RateCounter::new(DROP_STATS_PERIOD));
                rc.tick();
            }
            _ => self.drop_stats_global.tick(),
        }
    }

    /// 已知 peer = 持有转发密钥或已建会话（netmap/keydist 收敛后）；伪造 node_id 不在表内
    fn is_known_peer(&self, peer: u32) -> bool {
        self.key_dst_table.contains_key(&peer) || self.sessions.contains_key(&peer)
    }

    /// 取走本周期丢帧摘要（LOGGING §5；pump_timers 周期调用，0 不输出由调用方决定）
    pub fn poll_drop_stats(&mut self) -> Option<(Vec<(u32, u64)>, u64)> {
        let now = Instant::now();
        let mut per_peer = Vec::new();
        for (peer, rc) in self.drop_stats.iter_mut() {
            if let Some(n) = rc.poll(now) {
                if n > 0 {
                    per_peer.push((*peer, n));
                }
            }
        }
        self.drop_stats.retain(|_, rc| rc.has_pending());
        let global = self.drop_stats_global.poll(now).unwrap_or(0);
        if per_peer.is_empty() && global == 0 {
            return None;
        }
        Some((per_peer, global))
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
}
