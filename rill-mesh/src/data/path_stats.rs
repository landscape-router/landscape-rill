//! 逐路径统计与 PathProbe 激活（REQ-064，CONTROL_PLANE §3.11）：
//! 接收侧 (peer, path_id) 分桶被动统计（seq gap = 丢包/乱序估计）+
//! 空闲候选路径免会话活跃探活（PATH_PROBE 帧，route_mac 即认证，
//! 响应沿同路径反向返回）。统计仅 advisory：喂 pick_path 择优，
//! 不改变 miss/failover 语义

use super::*;
use tracing::debug;

/// PATH_PROBE 响应标记（帧头 flags bit0；flags 在 auth_input 内不可翻转）
pub const PATH_PROBE_FLAG_RESPONSE: u8 = 0x01;

/// 在途 PATH_PROBE 上限（CN-01/REQ-046，与 probe pending 同值）
const PATH_PROBE_MAX_PENDING: usize = 64;
/// 在途 PATH_PROBE 判死窗口：超时未响应 → path_miss（泵周期 30s + 余量）
const PATH_PROBE_TIMEOUT: Duration = Duration::from_secs(35);

/// 路径质量桶：区间计数（遥测取走即清零，§3.15 语义）+ 跨区间 EWMA
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PathStat {
    /// 本区间收帧数
    pub frames: u64,
    /// 丢失 seq 单元估计（前向 seq 跳越）
    pub gap_missing: u64,
    /// 乱序到达计数（回退 seq，非重放）
    pub reorder: u64,
    /// 丢包率 EWMA（千分比）：pick_path advisory 排序键
    pub loss_ewma_permille: u32,
    /// 最近 PATH_PROBE RTT（0 = 未测；观测/上报用）
    pub rtt_ms: u32,
    /// 已随遥测上报过的 RTT：空闲路径仅 RTT 变化才重报（探活每周期抖动）
    last_reported_rtt: u32,
    /// 会话 seq 轨迹（gap 判定基准；None = 首帧）
    last_seq: Option<u32>,
}

/// 遥测取走的区间快照（§3.15 paths 字段）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathStatInterval {
    pub peer: u32,
    pub path_id: u64,
    pub frames: u64,
    pub gap_missing: u64,
    pub reorder: u64,
    pub rtt_ms: u32,
}

impl MeshData {
    /// 接收侧统计入口（会话帧解密成功后调用）：按 (peer, path_id) 分桶，
    /// wrapping diff 判 gap/乱序（回绕安全：前向距离 < 2³¹ 视为跳越）
    pub(super) fn note_path_frame(&mut self, peer: u32, path_id: u64, seq: u32) {
        let st = self.path_stats.entry((peer, path_id)).or_default();
        if let Some(last) = st.last_seq.replace(seq) {
            let diff = seq.wrapping_sub(last);
            if diff > 1 && diff < 0x8000_0000 {
                st.gap_missing = st.gap_missing.saturating_add((diff - 1) as u64);
            } else if diff >= 0x8000_0000 {
                st.reorder = st.reorder.saturating_add(1);
            }
        }
        st.frames = st.frames.saturating_add(1);
    }

    /// 桶观测（测试/调试）
    pub fn path_stat(&self, peer: u32, path_id: u64) -> Option<PathStat> {
        self.path_stats.get(&(peer, path_id)).copied()
    }

    /// 遥测区间取走（心跳周期调用）：区间计数清零并折入 EWMA
    /// （有新证据 = 3/4 旧 + 1/4 新；无帧 = 指数冷却）；rtt/seq 轨迹保留。
    /// 仅携带有效区间：有帧 或 探活 RTT 变化（空闲路径唯一信号），
    /// 静默桶不占心跳字节
    pub(super) fn take_path_stats(&mut self) -> Vec<PathStatInterval> {
        let mut out = Vec::new();
        for (&(peer, path_id), st) in self.path_stats.iter_mut() {
            if let Some(rate) = st
                .gap_missing
                .saturating_mul(1000)
                .checked_div(st.frames)
                .map(|r| r as u32)
            {
                st.loss_ewma_permille = st.loss_ewma_permille / 4 * 3 + rate / 4;
            } else {
                st.loss_ewma_permille = st.loss_ewma_permille / 4 * 3;
            }
            let rtt_changed = st.rtt_ms > 0 && st.rtt_ms != st.last_reported_rtt;
            if st.frames == 0 && !rtt_changed {
                continue;
            }
            st.last_reported_rtt = st.rtt_ms;
            out.push(PathStatInterval {
                peer,
                path_id,
                frames: std::mem::take(&mut st.frames),
                gap_missing: std::mem::take(&mut st.gap_missing),
                reorder: std::mem::take(&mut st.reorder),
                rtt_ms: st.rtt_ms,
            });
        }
        out.sort_by_key(|i| (i.peer, i.path_id));
        out
    }

    /// 空闲候选路径探活目标：未过期、有 key_path、非当前在用
    /// （last_sent_path）的候选——备份路径无数据流量，被动统计覆盖不到
    pub fn idle_path_probe_targets(&self) -> Vec<(u32, u64, u32)> {
        let now = unix_seconds();
        let mut out = Vec::new();
        for (dest, paths) in &self.path_table {
            let in_use = self.last_sent_path.get(dest).copied();
            for p in paths {
                if p.expired(now) || !self.key_path_table.contains_key(&p.path_id) {
                    continue;
                }
                if in_use == Some(p.path_id) {
                    continue;
                }
                if let Some(&hop0) = p.hops.first() {
                    out.push((*dest, p.path_id, hop0));
                }
            }
        }
        out.sort_by_key(|(dest, path_id, _)| (*dest, *path_id));
        out
    }

    /// 发送 PATH_PROBE 请求（沿路径首跳 hop 的端点，端点过滤/排序同 relay）：
    /// 免会话，route_mac = key_path。在途上限（CN-01）：饱和拒绝（泵周期重试收敛）
    pub async fn send_path_probe(&mut self, dest: u32, path_id: u64, hop: u32) -> Option<u32> {
        if self.path_probe_pending.len() >= PATH_PROBE_MAX_PENDING {
            return None;
        }
        let &key = self.key_path_table.get(&path_id)?;
        let mut candidates = self.endpoint_table.get(&hop).cloned()?;
        self.retain_hop_endpoints(hop, &mut candidates);
        self.order_endpoints(hop, dest, &mut candidates);
        if candidates.is_empty() {
            return None;
        }
        let nonce = rand::random::<u32>();
        let payload = landscape_rill_core::frame::PathProbePayload {
            nonce,
            sent_ms: unix_millis(),
            response: false,
        };
        let header = MeshFrameHeader {
            to_node_id: dest,
            from_node_id: self.self_node_id,
            path_id,
            packet_type: packet_type::PATH_PROBE,
            ..Default::default()
        };
        let frame =
            landscape_rill_core::frame::build_unsealed_frame(&header, &key, &payload.encode());
        for addr in candidates {
            if self.wan_send(&frame, addr).await.is_ok() {
                self.note_tx(hop, frame.len());
                self.path_probe_pending
                    .insert(nonce, (dest, path_id, Instant::now()));
                return Some(nonce);
            }
        }
        None
    }

    /// 在途 PATH_PROBE 判死（泵周期调用）：超时未响应 → 该路径 miss
    /// （空闲路径活性由探活驱动，心跳只走默认路径）
    pub fn poll_path_probe_timeouts(&mut self) {
        let now = Instant::now();
        let expired: Vec<u32> = self
            .path_probe_pending
            .iter()
            .filter(|(_, (_, _, sent))| now.duration_since(*sent) > PATH_PROBE_TIMEOUT)
            .map(|(nonce, _)| *nonce)
            .collect();
        for nonce in expired {
            if let Some((_, path_id, _)) = self.path_probe_pending.remove(&nonce) {
                self.path_miss(path_id);
            }
        }
    }

    /// PATH_PROBE 帧送达处理（已过 route_mac 校验）：请求 = 按源限速回响应
    /// （沿同路径反向）；响应 = nonce 匹配 → RTT + path_ok + 桶更新
    pub(super) async fn handle_path_probe(
        &mut self,
        from_addr: SocketAddr,
        header: &MeshFrameHeader,
        payload: &[u8],
    ) -> IncomingEvent {
        let Some(p) = landscape_rill_core::frame::PathProbePayload::decode(payload) else {
            self.note_drop(Some(header.from_node_id));
            return IncomingEvent::Dropped {
                reason: DropReason::Short,
            };
        };
        if p.response {
            return match self.path_probe_pending.remove(&p.nonce) {
                Some((dest, path_id, sent)) => {
                    let rtt_ms = u32::try_from(sent.elapsed().as_millis()).unwrap_or(u32::MAX);
                    self.path_ok(path_id);
                    if let Some(st) = self.path_stats.get_mut(&(dest, path_id)) {
                        st.rtt_ms = rtt_ms;
                    }
                    debug!(
                        "[mesh] path probe rtt: dest={} path={} {}ms",
                        dest, path_id, rtt_ms
                    );
                    IncomingEvent::PathProbeRtt {
                        dest,
                        path_id,
                        rtt_ms,
                    }
                }
                // 未知 nonce（迟到/重复/伪造）→ 丢弃
                None => {
                    self.note_drop(Some(header.from_node_id));
                    IncomingEvent::Dropped {
                        reason: DropReason::Replay,
                    }
                }
            };
        }
        // 请求：按源限速（与 PONG 同值同桶——同类响应面，REQ-046 纪律）
        if !self.pong_limiter.allow(from_addr.ip()) {
            return IncomingEvent::Dropped {
                reason: DropReason::RateLimited,
            };
        }
        let Some(&key) = self.key_path_table.get(&header.path_id) else {
            return IncomingEvent::Dropped {
                reason: DropReason::NoKeyDst,
            };
        };
        let resp = landscape_rill_core::frame::PathProbePayload {
            nonce: p.nonce,
            sent_ms: p.sent_ms,
            response: true,
        };
        let resp_header = MeshFrameHeader {
            to_node_id: header.from_node_id,
            from_node_id: self.self_node_id,
            path_id: header.path_id,
            packet_type: packet_type::PATH_PROBE,
            flags: PATH_PROBE_FLAG_RESPONSE,
            ..Default::default()
        };
        let frame =
            landscape_rill_core::frame::build_unsealed_frame(&resp_header, &key, &resp.encode());
        // 响应沿同路径反向：本节点在 hops 中的前驱（首跳位置 = 直回源）
        if self
            .send_along_path(&frame, header.path_id, header.from_node_id)
            .await
        {
            IncomingEvent::PathProbeServed {
                from: header.from_node_id,
            }
        } else {
            IncomingEvent::Dropped {
                reason: DropReason::NoEndpoint,
            }
        }
    }

    /// 沿路径反向发送（PATH_PROBE 响应）：查发送/转发表取 hops，本节点
    /// 位置的前驱为下一跳（首跳位置 = 源直连）；端点过滤/排序同 relay()
    async fn send_along_path(&mut self, frame: &[u8], path_id: u64, to_node: u32) -> bool {
        let path = self
            .path_table
            .get(&to_node)
            .and_then(|paths| paths.iter().find(|p| p.path_id == path_id).cloned())
            .or_else(|| self.forward_paths.get(&path_id).cloned());
        let Some(path) = path else {
            return false;
        };
        let next = match path.hops.iter().position(|h| *h == self.self_node_id) {
            Some(0) | None => to_node,
            Some(idx) => path.hops[idx - 1],
        };
        let Some(candidates) = self.endpoint_table.get(&next).cloned() else {
            return false;
        };
        let mut candidates = candidates;
        self.retain_hop_endpoints(next, &mut candidates);
        self.order_endpoints(next, to_node, &mut candidates);
        for addr in candidates {
            if self.wan_send(frame, addr).await.is_ok() {
                self.note_tx(to_node, frame.len());
                return true;
            }
        }
        false
    }
}

fn unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
