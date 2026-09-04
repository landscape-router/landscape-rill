//! 中继转发（FRAME_HEADER §4）：帧头解析 → 版本/route_mac 校验 →
//! 端点/路径下一跳查表 → ttl 递减转发（不重签 route_mac）

use super::*;
use tracing::debug;

impl MeshData {
    pub async fn relay(&mut self, frame: &mut [u8]) -> RelayOutcome {
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
        if header.version != VERSION {
            return RelayOutcome::Dropped {
                reason: DropReason::BadVersion,
            };
        }
        if header.to_node_id == BROADCAST_NODE_ID {
            return self.relay_broadcast(&header, frame).await;
        }
        // 路由密钥按路径选择：显式路径 = 该 path_id 的 key_path（路径级授权，
        // CONTROL_PLANE §3.11.5——转发节点必须持路径授权才能校验/转发）；
        // path_id=0 = 默认路径（key_dst）
        let route_key = if header.path_id != PATH_ID_DEFAULT {
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
        let ai = header.auth_input();
        if landscape_rill_core::crypto::route_mac(&route_key, &ai) != header.route_mac {
            return RelayOutcome::Dropped {
                reason: DropReason::BadRouteMac,
            };
        }
        if header.to_node_id == self.self_node_id {
            return RelayOutcome::Delivered {
                from: header.from_node_id,
            };
        }
        if header.ttl == 0 {
            return RelayOutcome::Dropped {
                reason: DropReason::TtlExpired,
            };
        }
        // 转发下一跳节点：显式路径 = 本节点在 hops 中的后继，默认路径 = 直连目标。
        // 端点按活性排序逐个尝试（REQ-054 决策 6：relay 侧同样择优，
        // 修复此前固定取 .first() 的缺口）
        let next_node = if header.path_id != PATH_ID_DEFAULT {
            self.path_next_node(&header)
        } else {
            Some(header.to_node_id)
        };
        let Some(next_node) = next_node else {
            return RelayOutcome::Dropped {
                reason: DropReason::NoEndpoint,
            };
        };
        let mut candidates = match self.endpoint_table.get(&next_node) {
            Some(v) => v.clone(),
            None => {
                return RelayOutcome::Dropped {
                    reason: DropReason::NoEndpoint,
                };
            }
        };
        // 路径帧限定下一跳自有端点（非参与者兜底中继无法转发，见 paths.rs）
        if header.path_id != PATH_ID_DEFAULT {
            self.retain_hop_endpoints(next_node, &mut candidates);
        }
        self.order_endpoints(next_node, header.to_node_id, &mut candidates);
        // 原地 TTL 递减后直接从接收缓冲发出（REQ-053：转发零拷贝；
        // ttl 不参与认证，自交付解密不受影响；逐端点尝试先成功即止）
        decrement_ttl(frame);
        for addr in candidates {
            if self.wan_send(&frame[..], addr).await.is_ok() {
                debug!("[mesh] relay to {} via {}", header.to_node_id, addr);
                self.note_tx(header.to_node_id, frame.len());
                return RelayOutcome::Forwarded {
                    to: header.to_node_id,
                };
            }
        }
        RelayOutcome::Dropped {
            reason: DropReason::NoEndpoint,
        }
    }

    /// 路径转发下一跳节点：本节点在路径 hops 中的后继。
    /// 先查发送选择表（source = 自己），未命中查转发表（非自源路径中
    /// 自己是 hops 参与者的条目——中继转发的正常形态）
    pub(super) fn path_next_node(&self, header: &MeshFrameHeader) -> Option<u32> {
        let path = self
            .path_table
            .get(&header.to_node_id)
            .and_then(|paths| {
                paths
                    .iter()
                    .find(|p| p.path_id == header.path_id && !p.expired(unix_seconds()))
                    .cloned()
            })
            .or_else(|| {
                let p = self.forward_paths.get(&header.path_id)?;
                (!p.expired(unix_seconds())).then_some(p.clone())
            })?;
        let idx = path.hops.iter().position(|h| *h == self.self_node_id)?;
        path.hops.get(idx + 1).copied()
    }
}
