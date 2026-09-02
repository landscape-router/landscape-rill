//! 会话与握手（FRAME_HEADER §2.3/§2.4）：Noise_XX 发起/响应、
//! 帧构建/发送（数据/心跳/握手）、会话帧解密

use super::*;
use tracing::debug;

impl MeshData {
    /// 主动发起握手（懒握手入口）。已有会话 → Ok(None)；
    /// 在途握手中 → Ok(None)（不重复发起，避免 eph 状态轮换）；
    /// 否则返回 msg1 帧供调用方发送。
    pub fn initiate_handshake(&mut self, peer: u32) -> Result<Option<Vec<u8>>, SendError> {
        if self.sessions.contains_key(&peer) || self.initiators.contains_key(&peer) {
            return Ok(None);
        }
        let ctx = self.ctx.as_ref().ok_or(SendError::NoContext)?;
        let peer_static = self
            .peer_statics
            .get(&peer)
            .copied()
            .ok_or(SendError::NoPeerBinding)?;
        let mut initiator = HandshakeInitiator::new(
            &ctx.local_static,
            ctx.network_id,
            ctx.version,
            peer,
            &ctx.identity_binding,
            rand::random::<u32>(),
            &peer_static,
        )
        .map_err(SendError::Handshake)?;
        let msg1 = initiator.write_msg1().map_err(SendError::Handshake)?;
        self.initiators.insert(peer, initiator);
        Ok(Some(self.build_handshake_frame(peer, &msg1)?))
    }

    /// 构建加密数据帧（seq 自增）。需会话已建立。
    /// 返回 (帧, 首跳)：有 v2 路径时首跳 = 路径第一跳（经 relay），帧为 v2 帧头；
    /// 否则首跳 = None（直连 dest），帧为 v1 帧头（path_id=0 隐式默认路径，v1 兼容）。
    pub fn build_data_frame(
        &mut self,
        to: u32,
        payload: &[u8],
        flow_hash: u64,
    ) -> Result<(Vec<u8>, Option<u32>), SendError> {
        let path = self.pick_path(to, flow_hash);
        match &path {
            Some(p) => debug!(
                "[mesh] data frame to {} via path {} hops {:?}",
                to, p.path_id, p.hops
            ),
            None => debug!("[mesh] data frame to {} via default path (v1)", to),
        }
        let frame = match path {
            Some(ref p) => self.build_typed_frame_v2(to, p, packet_type::UNICAST, payload)?,
            None => self.build_typed_frame(to, packet_type::UNICAST, payload)?,
        };
        let first_hop = path.as_ref().and_then(|p| p.hops.first()).copied();
        Ok((frame, first_hop))
    }

    /// 心跳帧（AEAD 空载荷，仅已建会话对；CONNECTIVITY §6 / FRAME_HEADER §2.5）。
    /// 心跳恒走默认路径（v1 帧头 + key_dst）——路径活性由 PathProbe 承担。
    pub fn build_heartbeat_frame(&mut self, to: u32) -> Result<Vec<u8>, SendError> {
        self.build_typed_frame(to, packet_type::HEARTBEAT, &[])
    }

    /// v2 数据帧：路径授权（key_path 签发 route_mac），path_id 纳入 AAD（FRAME_HEADER §9）
    pub(super) fn build_typed_frame_v2(
        &mut self,
        to: u32,
        path: &PathEntry,
        packet_type: u8,
        payload: &[u8],
    ) -> Result<Vec<u8>, SendError> {
        let session = self.sessions.get_mut(&to).ok_or(SendError::NoSession)?;
        let key_path = self
            .key_path_table
            .get(&path.path_id)
            .copied()
            .ok_or(SendError::NoKeyDst)?;
        let seq = session.next_seq();
        let header = MeshFrameHeader {
            version: VERSION2,
            packet_type,
            to_node_id: to,
            from_node_id: self.self_node_id,
            seq,
            path_id: path.path_id,
            ..Default::default()
        };
        build_frame(
            &header,
            &key_path,
            &session.keys().tx_key,
            session.keys().salt,
            payload,
        )
        .map_err(|_| SendError::Aead)
    }

    pub(super) fn build_typed_frame(
        &mut self,
        to: u32,
        packet_type: u8,
        payload: &[u8],
    ) -> Result<Vec<u8>, SendError> {
        let session = self.sessions.get_mut(&to).ok_or(SendError::NoSession)?;
        let key_dst = self.key_dst_table.get(&to).ok_or(SendError::NoKeyDst)?;
        let seq = session.next_seq();
        let header = MeshFrameHeader {
            packet_type,
            to_node_id: to,
            from_node_id: self.self_node_id,
            seq,
            ..Default::default()
        };
        build_frame(
            &header,
            key_dst,
            &session.keys().tx_key,
            session.keys().salt,
            payload,
        )
        .map_err(|_| SendError::Aead)
    }

    pub(super) fn build_handshake_frame(
        &self,
        to: u32,
        payload: &[u8],
    ) -> Result<Vec<u8>, SendError> {
        let key_dst = self.key_dst_table.get(&to).ok_or(SendError::NoKeyDst)?;
        let header = MeshFrameHeader {
            to_node_id: to,
            from_node_id: self.self_node_id,
            ..Default::default()
        };
        Ok(build_handshake_frame(&header, key_dst, payload))
    }

    pub async fn send_to_node(&self, to_node_id: u32, frame: &[u8]) -> std::io::Result<bool> {
        match self.endpoint_table.get(&to_node_id) {
            Some(addrs) => {
                for addr in addrs {
                    if self.wan_send(frame, *addr).await.is_ok() {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            None => Ok(false),
        }
    }

    /// 按路径首跳发送（v2）：首跳 = 路径第一跳（relay 或 dest 本身）。
    /// 多端点按活性排序逐个尝试（黑洞端点靠 miss 置后，见 order_endpoints）。
    pub async fn send_to_node_hop(
        &mut self,
        to_node_id: u32,
        first_hop: Option<u32>,
        frame: &[u8],
    ) -> std::io::Result<bool> {
        let hop = first_hop.unwrap_or(to_node_id);
        match self.endpoint_table.get(&hop) {
            Some(addrs) => {
                let mut ordered = addrs.clone();
                // v2 帧（版本字节 = 0x02）限定首跳自有端点：非参与者兜底中继
                // 无法转发 v2，发了必丢（v1 保留兜底语义）
                if frame.first() == Some(&VERSION2) {
                    self.retain_hop_endpoints(hop, &mut ordered);
                }
                self.order_endpoints(hop, to_node_id, &mut ordered);
                let mut last_err = None;
                let mut last_tried = None;
                for addr in ordered {
                    last_tried = Some(addr);
                    match self.wan_send(frame, addr).await {
                        Ok(_) => {
                            debug!("[mesh] send to {} hop {} via {}", to_node_id, hop, addr);
                            self.last_sent_endpoint.insert(to_node_id, addr);
                            return Ok(true);
                        }
                        Err(e) => last_err = Some(e),
                    }
                }
                // 发送失败（无路由等）→ 主路径 + 端点 miss，推进快速切换
                self.path_miss_peer(to_node_id);
                if let Some(addr) = last_tried {
                    if let Some(owner) = self.endpoint_owner(addr) {
                        let m = self.endpoint_health.entry((owner, addr)).or_insert(0);
                        *m = m.saturating_add(1);
                    }
                }
                Err(last_err.unwrap_or_else(|| std::io::Error::other("no endpoint")))
            }
            None => {
                debug!("[mesh] no endpoints for hop {}", hop);
                Ok(false)
            }
        }
    }

    /// 握手分发：按载荷长度区分 msg1/msg2/msg3（36/144/132B，互不重叠）。
    /// 与角色状态解耦——重发/乱序/状态残留不会误归类。
    pub(super) async fn handle_handshake(&mut self, from: u32, payload: &[u8]) -> IncomingEvent {
        match payload.len() {
            MSG1_PAYLOAD_LEN => self.handle_msg1(from, payload).await,
            MSG2_PAYLOAD_LEN => self.handle_msg2(from, payload).await,
            MSG3_PAYLOAD_LEN => self.handle_msg3(from, payload).await,
            _ => IncomingEvent::Rejected {
                peer: from,
                reason: HandshakeError::MalformedPayload,
            },
        }
    }

    pub(super) async fn handle_msg1(&mut self, from: u32, payload: &[u8]) -> IncomingEvent {
        let Some(ctx) = self.ctx.clone() else {
            return IncomingEvent::Rejected {
                peer: from,
                reason: HandshakeError::WrongStep,
            };
        };
        let mut responder = match HandshakeResponder::new(
            &ctx.local_static,
            ctx.network_id,
            ctx.version,
            self.self_node_id,
        ) {
            Ok(r) => r,
            Err(e) => {
                return IncomingEvent::Rejected {
                    peer: from,
                    reason: e,
                }
            }
        };
        if let Err(e) = responder.read_msg1(payload) {
            return IncomingEvent::Rejected {
                peer: from,
                reason: e,
            };
        }
        let msg2 = match responder.write_msg2() {
            Ok(m) => m,
            Err(e) => {
                return IncomingEvent::Rejected {
                    peer: from,
                    reason: e,
                }
            }
        };
        self.responders.insert(from, responder);
        match self.send_response(from, &msg2).await {
            true => IncomingEvent::Responded { peer: from },
            false => IncomingEvent::Dropped {
                reason: DropReason::NoEndpoint,
            },
        }
    }

    pub(super) async fn handle_msg2(&mut self, from: u32, payload: &[u8]) -> IncomingEvent {
        let Some(mut initiator) = self.initiators.remove(&from) else {
            return IncomingEvent::Rejected {
                peer: from,
                reason: HandshakeError::WrongStep,
            };
        };
        let msg3 = match initiator.read_msg2(payload) {
            Ok(m) => m,
            Err(e) => {
                return IncomingEvent::Rejected {
                    peer: from,
                    reason: e,
                }
            }
        };
        let keys = match initiator.finish() {
            Ok(k) => k,
            Err(e) => {
                return IncomingEvent::Rejected {
                    peer: from,
                    reason: e,
                }
            }
        };
        let frame = match self.build_handshake_frame(from, &msg3) {
            Ok(f) => f,
            Err(_) => {
                return IncomingEvent::Dropped {
                    reason: DropReason::NoKeyDst,
                }
            }
        };
        let hop = self.path_first_hop(from);
        match self.send_to_node_hop(from, hop, &frame).await {
            Ok(true) => {
                self.sessions.insert(from, Session::new(from, keys));
                IncomingEvent::Established { peer: from }
            }
            _ => IncomingEvent::Dropped {
                reason: DropReason::NoEndpoint,
            },
        }
    }

    pub(super) async fn handle_msg3(&mut self, from: u32, payload: &[u8]) -> IncomingEvent {
        let Some(verifier) = self.binding_verifier.as_ref() else {
            return IncomingEvent::Rejected {
                peer: from,
                reason: HandshakeError::BadBinding,
            };
        };
        let Some(mut responder) = self.responders.remove(&from) else {
            return IncomingEvent::Rejected {
                peer: from,
                reason: HandshakeError::WrongStep,
            };
        };
        let result = responder.read_msg3(payload, from, |node_id, static_pubkey, binding| {
            verifier(node_id, static_pubkey, binding)
        });
        match result {
            Ok(keys) => {
                self.sessions.insert(from, Session::new(from, keys));
                IncomingEvent::Established { peer: from }
            }
            Err(e) => IncomingEvent::Rejected {
                peer: from,
                reason: e,
            },
        }
    }

    pub(super) async fn send_response(&mut self, to: u32, payload: &[u8]) -> bool {
        let frame = match self.build_handshake_frame(to, payload) {
            Ok(f) => f,
            Err(_) => return false,
        };
        let hop = self.path_first_hop(to);
        matches!(self.send_to_node_hop(to, hop, &frame).await, Ok(true))
    }

    /// AEAD 解密收尾：已建会话的 UNICAST/HEARTBEAT 帧统一走这里。
    /// 就地解密（REQ-053）：明文写回接收缓冲，freeze 成 Bytes 零拷贝出帧。
    /// 路由密钥按帧头版本选择：v1 = key_dst（默认路径）；v2 = 该 path_id 的 key_path
    pub(super) fn handle_session_frame(
        &mut self,
        from: u32,
        frame: &mut BytesMut,
        heartbeat: bool,
    ) -> IncomingEvent {
        let Some(header) = MeshFrameHeader::decode(&frame[..]).ok() else {
            return IncomingEvent::Dropped {
                reason: DropReason::Short,
            };
        };
        let route_key = if header.version == VERSION2 {
            match self.key_path_table.get(&header.path_id) {
                Some(k) => *k,
                None => {
                    return IncomingEvent::Dropped {
                        reason: DropReason::NoKeyDst,
                    }
                }
            }
        } else {
            match self.key_dst_table.get(&self.self_node_id) {
                Some(k) => *k,
                None => {
                    return IncomingEvent::Dropped {
                        reason: DropReason::NoKeyDst,
                    }
                }
            }
        };
        let Some(session) = self.sessions.get_mut(&from) else {
            return IncomingEvent::Dropped {
                reason: DropReason::NoSession,
            };
        };
        match session.open_in_place(frame, &route_key, Instant::now()) {
            Ok((h, pt_len)) => {
                if heartbeat && pt_len != 0 {
                    return IncomingEvent::Dropped {
                        reason: DropReason::Aead,
                    };
                }
                if heartbeat {
                    IncomingEvent::Heartbeat { from }
                } else {
                    // 帧头区切离丢弃，明文区 freeze 零拷贝交付（REQ-053）
                    let hlen = header_len(h.version);
                    let _ = frame.split_to(hlen);
                    let payload = frame.split_to(pt_len).freeze();
                    IncomingEvent::Data { from, payload }
                }
            }
            Err(landscape_rill_core::handshake::OpenError::Replay) => IncomingEvent::Dropped {
                reason: DropReason::Replay,
            },
            Err(landscape_rill_core::handshake::OpenError::RouteMac) => IncomingEvent::Dropped {
                reason: DropReason::BadRouteMac,
            },
            Err(_) => IncomingEvent::Dropped {
                reason: DropReason::Aead,
            },
        }
    }
}
