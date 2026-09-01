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

    /// 组播泛洪：向全部已知端点（除自己）发送广播帧。无会话端点直接发送
    /// （广播帧不依赖逐对会话密钥，不触发懒握手）。返回成功发送数。
    pub async fn flood(&mut self, payload: &[u8]) -> usize {
        if !self.flood_bucket.take() {
            return 0;
        }
        let Ok(frame) = self.build_broadcast_frame(payload) else {
            return 0;
        };
        let mut sent = 0;
        for peer in self.endpoint_ids() {
            if self.send_to_node(peer, &frame).await.unwrap_or(false) {
                sent += 1;
            }
        }
        sent
    }

    pub(super) fn endpoint_ids(&self) -> Vec<u32> {
        self.endpoint_table
            .keys()
            .copied()
            .filter(|id| *id != self.self_node_id)
            .collect()
    }

    /// 广播帧解密（FRAME_HEADER §2.6）：route_mac + AEAD 均用 broadcast_key，
    /// 按源节点的独立重放窗口拦截重放。
    pub(super) fn handle_broadcast_frame(&mut self, from: u32, frame: &[u8]) -> IncomingEvent {
        let Some(bkey) = self.broadcast_key else {
            return IncomingEvent::Dropped {
                reason: DropReason::NoKeyDst,
            };
        };
        let Some(header) = MeshFrameHeader::decode(frame).ok() else {
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
        match open_frame(frame, &bkey, &bkey, 0) {
            Ok((_, payload)) => IncomingEvent::Broadcast { from, payload },
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
    /// (from, seq) 去重（30s）→ ttl>0 → 自交付 + ttl-1 泛洪（除自己与源，出口令牌桶限速）。
    pub(super) async fn relay_broadcast(
        &mut self,
        header: &MeshFrameHeader,
        frame: &[u8],
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
            let mut out = frame.to_vec();
            out[3] -= 1;
            for (id, addrs) in &self.endpoint_table {
                if *id == self.self_node_id || *id == header.from_node_id {
                    continue;
                }
                let mut ok = false;
                for ep in addrs {
                    if self.socket.send_to(&out, *ep).await.is_ok() {
                        ok = true;
                        break;
                    }
                }
                if ok {
                    forwarded.push(*id);
                }
            }
        }
        RelayOutcome::Flooded {
            frame: frame.to_vec(),
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
