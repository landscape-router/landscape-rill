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
        let (from_addr, mut frame) = self.recv_frame().await?;
        let first = frame.first().copied();
        if matches!(first, Some(b) if (0x01..=0x0F).contains(&b)) {
            // 34B 帧路径（version 值域 0x01..=0x0F，FRAME_HEADER §2.1）
            self.handle_frame(from_addr, &mut frame).await
        } else if frame.len() >= 4 && frame[..4] == crate::probe::PROBE_MAGIC {
            self.handle_probe(from_addr, &frame).await
        } else {
            // 非帧非 probe → 丢弃（解析 fail-closed，CN-02）
            self.note_drop(None);
            Ok(IncomingEvent::Dropped {
                reason: DropReason::UnknownProtocol,
            })
        }
    }

    /// probe 处理（CONNECTIVITY §4）：PING 对己 → 按源限速回 PONG（SEC-26）；
    /// PONG → nonce 匹配确认
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
                if probe.to_node_id == self.self_node_id && self.pong_limiter.allow(from_addr.ip())
                {
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
    /// 并发上限（CN-01）：pending 达 PROBE_MAX_PENDING 拒绝新发送（runtime 周期重试收敛）。
    pub async fn send_probe_ping(
        &mut self,
        endpoint: SocketAddr,
        from: u32,
        to: u32,
    ) -> Option<u32> {
        if self.probe_pending.len() >= PROBE_MAX_PENDING {
            return None;
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

    /// 在途 probe 数（并发上限观测，CN-01）
    pub fn probe_pending_len(&self) -> usize {
        self.probe_pending.len()
    }

    /// 取走上轮全部在途探测（目标, 端点）：pump 周期开始调用——
    /// 剩余 = 上轮无 PONG 确认 → 驱动发送侧指数退避（CN-01/REQ-046）
    pub fn take_pending_probes(&mut self) -> Vec<(u32, SocketAddr)> {
        self.probe_pending.drain().map(|(_, v)| v).collect()
    }

    /// 帧路径（原 relay 入口逻辑，分派后调用）。帧留在接收缓冲中：
    /// 转发原地递减 TTL、送达就地解密后 freeze 载荷（REQ-053 零拷贝）。
    async fn handle_frame(
        &mut self,
        from_addr: SocketAddr,
        frame: &mut BytesMut,
    ) -> std::io::Result<IncomingEvent> {
        match self.relay(frame).await {
            RelayOutcome::Delivered { from } => {
                if let Some(ingress) = self.endpoint_owner(from_addr) {
                    self.ingress_hop.insert(from, ingress);
                    self.note_endpoint_ok(ingress, from_addr);
                }
                self.apply_ingress_health(from);
                let ev = self.dispatch_delivered(from, frame).await;
                // dispatch 路径丢帧同样收口计数（from 已过 route_mac 校验，归因可信）
                if matches!(ev, IncomingEvent::Dropped { .. }) {
                    self.note_drop(Some(from));
                }
                Ok(ev)
            }
            RelayOutcome::Flooded { from, .. } => {
                if let Some(ingress) = self.endpoint_owner(from_addr) {
                    self.ingress_hop.insert(from, ingress);
                    self.note_endpoint_ok(ingress, from_addr);
                }
                self.apply_ingress_health(from);
                let ev = self.dispatch_delivered(from, frame).await;
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

    /// 取走本周期丢帧摘要（LOGGING §5；pump_timers 周期调用，0 不输出由调用方决定）；
    /// 顺带清理 PONG 限速桶表（防伪造源地址洪泛撑爆状态）
    pub fn poll_drop_stats(&mut self) -> Option<(Vec<(u32, u64)>, u64)> {
        self.pong_limiter.prune();
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

    /// 送达分发：握手路径借用解析；数据/心跳/广播路径就地解密，
    /// 明文 freeze 成 Bytes 零拷贝出帧（REQ-053）。
    async fn dispatch_delivered(&mut self, from: u32, frame: &mut BytesMut) -> IncomingEvent {
        let Some(header) = MeshFrameHeader::decode(&frame[..]).ok() else {
            return IncomingEvent::Dropped {
                reason: DropReason::Short,
            };
        };
        match header.packet_type {
            packet_type::HANDSHAKE => match frame_payload(&frame[..]) {
                Some(payload) => self.handle_handshake(from, payload).await,
                None => IncomingEvent::Dropped {
                    reason: DropReason::Short,
                },
            },
            packet_type::UNICAST => self.handle_session_frame(from, frame, false),
            packet_type::HEARTBEAT => self.handle_session_frame(from, frame, true),
            packet_type::BROADCAST => self.handle_broadcast_frame(from, frame),
            _ => IncomingEvent::Dropped {
                reason: DropReason::UnsupportedType,
            },
        }
    }
}
