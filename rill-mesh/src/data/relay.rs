//! 中继转发（FRAME_HEADER §4）：帧头解析 → version/route_mac 校验 →
//! 端点/路径下一跳查表 → ttl 递减转发（不重签 route_mac）

use super::*;

impl MeshData {
    pub async fn relay(&mut self, frame: &[u8]) -> RelayOutcome {
        if frame.len() < HEADER_LEN {
            return RelayOutcome::Dropped {
                reason: DropReason::Short,
            };
        }
        let header = match MeshFrameHeader::decode(frame) {
            Ok(h) => h,
            Err(_) => {
                return RelayOutcome::Dropped {
                    reason: DropReason::Short,
                }
            }
        };
        if header.version != VERSION && header.version != VERSION2 {
            return RelayOutcome::Dropped {
                reason: DropReason::BadVersion,
            };
        }
        if header.to_node_id == BROADCAST_NODE_ID {
            return self.relay_broadcast(&header, frame).await;
        }
        // 路由密钥按帧头版本选择：v2 = 该 path_id 的 key_path（路径级授权，
        // CONTROL_PLANE §3.11.5——转发节点必须持路径授权才能校验/转发）
        let route_key = if header.version == VERSION2 {
            match self.key_path_table.get(&header.path_id) {
                Some(k) => *k,
                None => {
                    return RelayOutcome::Dropped {
                        reason: DropReason::NoKeyDst,
                    }
                }
            }
        } else {
            match self.key_dst_table.get(&header.to_node_id) {
                Some(k) => *k,
                None => {
                    return RelayOutcome::Dropped {
                        reason: DropReason::NoKeyDst,
                    }
                }
            }
        };
        let (ai, ai_len) = header.auth_input();
        if landscape_rill_core::crypto::route_mac(&route_key, &ai[..ai_len]) != header.route_mac {
            return RelayOutcome::Dropped {
                reason: DropReason::BadRouteMac,
            };
        }
        if header.to_node_id == self.self_node_id {
            return RelayOutcome::Delivered {
                frame: frame.to_vec(),
                from: header.from_node_id,
            };
        }
        if header.ttl == 0 {
            return RelayOutcome::Dropped {
                reason: DropReason::TtlExpired,
            };
        }
        // 转发端点：v2 路径按路径下一跳（本节点在 hops 中的后继），v1 直连目标端点
        let next_hop = if header.version == VERSION2 {
            self.path_next_hop(&header)
        } else {
            None
        };
        let endpoint = match next_hop {
            Some(e) => Some(e),
            None => self
                .endpoint_table
                .get(&header.to_node_id)
                .and_then(|v| v.first())
                .copied(),
        };
        let Some(endpoint) = endpoint else {
            return RelayOutcome::Dropped {
                reason: DropReason::NoEndpoint,
            };
        };
        let mut out = frame.to_vec();
        out[3] -= 1;
        match self.socket.send_to(&out, endpoint).await {
            Ok(_) => RelayOutcome::Forwarded {
                to: header.to_node_id,
            },
            Err(_) => RelayOutcome::Dropped {
                reason: DropReason::NoEndpoint,
            },
        }
    }

    /// v2 路径转发下一跳：本节点在路径 hops 中的后继节点
    pub(super) fn path_next_hop(&self, header: &MeshFrameHeader) -> Option<SocketAddr> {
        let paths = self.path_table.get(&header.to_node_id)?;
        let path = paths
            .iter()
            .find(|p| p.path_id == header.path_id && !p.expired(unix_seconds()))?;
        let idx = path.hops.iter().position(|h| *h == self.self_node_id)?;
        let next = path.hops.get(idx + 1)?;
        self.endpoint_table
            .get(next)
            .and_then(|v| v.first())
            .copied()
    }
}
