//! 广播/泛洪（FRAME_HEADER §2.6）：broadcast_key 帧、去重泛洪、
//! 令牌桶限速（发送与转发共用）

use super::*;

impl MeshData {
    /// 广播帧构建（FRAME_HEADER §2.6）：AEAD 与 route_mac 均用 broadcast_key，
    /// seq = 每源全局广播计数器（虚拟会话）。
    pub fn build_broadcast_frame(&mut self, payload: &[u8]) -> Result<Vec<u8>, SendError> {
        let bkey = self.broadcast_key.ok_or(SendError::NoKeyDst)?;
        let seq = self.broadcast_seq;
        self.broadcast_seq = self.broadcast_seq.wrapping_add(1);
        let header = MeshFrameHeader {
            packet_type: packet_type::BROADCAST,
            to_node_id: BROADCAST_NODE_ID,
            from_node_id: self.self_node_id,
            seq,
            ..Default::default()
        };
        build_frame(&header, &bkey, &bkey, 0, payload).map_err(|_| SendError::Aead)
    }

    /// 组播泛洪：向 opt-in 端点（除自己）发送广播帧。无会话端点直接发送
    /// （广播帧不依赖逐对会话密钥，不触发懒握手）。返回成功发送数。
    /// 目标收窄（REQ-035）：仅能力位含 broadcast 的端点，未 opt-in 不发。
    pub async fn flood(&mut self, payload: &[u8]) -> usize {
        if !self.flood_bucket.take() {
            return 0;
        }
        let Ok(frame) = self.build_broadcast_frame(payload) else {
            return 0;
        };
        let mut sent = 0;
        for peer in self.flood_targets(self.self_node_id) {
            if self.send_to_node(peer, &frame).await.unwrap_or(false) {
                sent += 1;
            }
        }
        sent
    }

    /// 泛洪目标（FRAME_HEADER §2.6 v0.9）：endpoint_table 中除自己与源外、
    /// 且能力位含 broadcast 的端点；无能力记录按未 opt-in（fail-closed）
    pub(super) fn flood_targets(&self, source: u32) -> Vec<u32> {
        self.endpoint_table
            .keys()
            .copied()
            .filter(|id| *id != self.self_node_id && *id != source && self.broadcast_opted_in(*id))
            .collect()
    }

    /// 广播帧解密（FRAME_HEADER §2.6）：route_mac + AEAD 均用 broadcast_key，
    /// 按源节点的独立重放窗口拦截重放。就地解密，明文 freeze 零拷贝出帧（REQ-053）。
    pub(super) fn handle_broadcast_frame(
        &mut self,
        from: u32,
        frame: &mut BytesMut,
    ) -> IncomingEvent {
        let Some(bkey) = self.broadcast_key else {
            return IncomingEvent::Dropped {
                reason: DropReason::NoKeyDst,
            };
        };
        let Some(header) = MeshFrameHeader::decode(&frame[..]).ok() else {
            return IncomingEvent::Dropped {
                reason: DropReason::Short,
            };
        };
        let window = self.broadcast_replay.entry(from).or_default();
        if !window.check_and_mark(header.seq) {
            return IncomingEvent::Dropped {
                reason: DropReason::Replay,
            };
        }
        match open_frame_in_place(frame, &bkey, &bkey, 0) {
            Ok((h, payload)) => {
                let pt_len = payload.len();
                let hlen = header_len(h.version);
                let _ = frame.split_to(hlen);
                let payload = frame.split_to(pt_len).freeze();
                IncomingEvent::Broadcast { from, payload }
            }
            Err(landscape_rill_core::frame::OpenError::RouteMac) => IncomingEvent::Dropped {
                reason: DropReason::BadRouteMac,
            },
            Err(_) => IncomingEvent::Dropped {
                reason: DropReason::Aead,
            },
        }
    }

    /// 广播帧泛洪路径（FRAME_HEADER §2.6）：
    /// version（已验）→ type=广播 → broadcast_key 存在 → route_mac（bkey）→
    /// (from, seq) 去重（30s）→ ttl>0 → 原地 ttl-1 泛洪（除自己与源，出口令牌桶限速）；
    /// 自交付由 handle_frame 就地解密（REQ-053：整程零拷贝）。
    pub(super) async fn relay_broadcast(
        &mut self,
        header: &MeshFrameHeader,
        frame: &mut [u8],
    ) -> RelayOutcome {
        if header.packet_type != packet_type::BROADCAST {
            return RelayOutcome::Dropped {
                reason: DropReason::UnsupportedType,
            };
        }
        let Some(bkey) = self.broadcast_key else {
            return RelayOutcome::Dropped {
                reason: DropReason::NoKeyDst,
            };
        };
        let (ai, ai_len) = header.auth_input();
        if landscape_rill_core::crypto::route_mac(&bkey, &ai[..ai_len]) != header.route_mac {
            return RelayOutcome::Dropped {
                reason: DropReason::BadRouteMac,
            };
        }
        if header.from_node_id == self.self_node_id {
            return RelayOutcome::Dropped {
                reason: DropReason::Duplicate,
            };
        }
        self.prune_flood_seen();
        if self
            .flood_seen
            .contains_key(&(header.from_node_id, header.seq))
        {
            return RelayOutcome::Dropped {
                reason: DropReason::Duplicate,
            };
        }
        if header.ttl == 0 {
            return RelayOutcome::Dropped {
                reason: DropReason::TtlExpired,
            };
        }
        self.flood_seen
            .insert((header.from_node_id, header.seq), Instant::now());
        let mut forwarded = Vec::new();
        if self.flood_bucket.take() {
            // 原地 TTL 递减后直接从接收缓冲泛洪（REQ-053：转发零拷贝）；
            // 目标收窄（REQ-035）：仅 opt-in 端点（发送侧过滤的转发侧对应）
            decrement_ttl(frame);
            for id in self.flood_targets(header.from_node_id) {
                let Some(addrs) = self.endpoint_table.get(&id) else {
                    continue;
                };
                let mut ok = false;
                for ep in addrs {
                    if self.wan_send(&frame[..], *ep).await.is_ok() {
                        ok = true;
                        break;
                    }
                }
                if ok {
                    forwarded.push(id);
                }
            }
        }
        RelayOutcome::Flooded {
            from: header.from_node_id,
            forwarded,
        }
    }

    /// 清理过期泛洪去重条目（FLOOD_SEEN_TTL）
    pub(super) fn prune_flood_seen(&mut self) {
        let cutoff = Instant::now() - FLOOD_SEEN_TTL;
        self.flood_seen.retain(|_, seen_at| *seen_at >= cutoff);
    }
}
