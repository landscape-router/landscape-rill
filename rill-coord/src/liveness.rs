//! 节点活性域：心跳与离线状态（CONTROL_PLANE §5.2）
//!
//! 软状态：last_seen/offline 不落盘（REQ-037 持久类清单），重启后重建。

use std::collections::HashMap;

/// 租约超时（CTL-11）：last_seen 距今超过该值 = 离线。与心跳处理回发的
/// LEASE.expires_at（now + LEASE_EXPIRY_SECS）同一来源——续租即心跳
pub const LEASE_EXPIRY_SECS: u64 = 60;

#[derive(Debug, Default)]
pub struct Liveness {
    last_seen: HashMap<u32, u64>,
    offline: Vec<u32>,
}

impl Liveness {
    pub fn new() -> Self {
        Self::default()
    }

    /// 记录心跳并清除离线标记；返回是否发生离线 → 在线的恢复转移
    /// （调用方据以递增 netmap 版本，CTL-11）
    pub fn heartbeat(&mut self, node_id: u32, now: u64) -> bool {
        let was_offline = self.offline.contains(&node_id);
        self.last_seen.insert(node_id, now);
        self.offline.retain(|id| *id != node_id);
        was_offline
    }

    /// 租约超时扫描（CTL-11）：last_seen 距 now 超过 LEASE_EXPIRY_SECS 的节点
    /// 标记离线；返回新进入离线集合的节点（调用方据以递增 netmap 版本）。
    /// 事件驱动——挂在心跳处理上执行，无后台任务
    pub fn sweep(&mut self, now: u64) -> Vec<u32> {
        let expired: Vec<u32> = self
            .last_seen
            .iter()
            .filter(|(_, &seen)| now.saturating_sub(seen) > LEASE_EXPIRY_SECS)
            .map(|(&id, _)| id)
            .filter(|id| !self.offline.contains(id))
            .collect();
        for id in &expired {
            self.offline.push(*id);
        }
        expired
    }

    /// 标记离线；返回是否新加入离线集合（新增时 netmap 版本应递增）
    pub fn mark_offline(&mut self, node_id: u32) -> bool {
        if self.offline.contains(&node_id) {
            return false;
        }
        self.offline.push(node_id);
        true
    }

    pub fn is_offline(&self, node_id: u32) -> bool {
        self.offline.contains(&node_id)
    }

    pub fn offline_nodes(&self) -> &[u32] {
        &self.offline
    }

    /// 节点吊销/移除时清理全部活性状态
    pub fn remove(&mut self, node_id: u32) {
        self.last_seen.remove(&node_id);
        self.offline.retain(|id| *id != node_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heartbeat_and_offline() {
        let mut l = Liveness::new();
        l.heartbeat(1, 100);
        assert!(l.offline_nodes().is_empty());
        assert!(l.mark_offline(1));
        assert_eq!(l.offline_nodes(), &[1]);
        assert!(l.is_offline(1));
        assert!(!l.mark_offline(1), "重复标记不重复计数");
        assert!(l.heartbeat(1, 200), "恢复转移返回 true");
        assert!(l.offline_nodes().is_empty());
        assert!(!l.is_offline(1));
    }

    #[test]
    fn sweep_marks_only_expired_transitions() {
        let mut l = Liveness::new();
        l.heartbeat(1, 100);
        l.heartbeat(2, 130);
        // 阈值内：无人离线
        assert!(l.sweep(100 + LEASE_EXPIRY_SECS).is_empty());
        // 超时：仅节点 1（130 + 60 > 191 未超）进入离线集合
        assert_eq!(l.sweep(100 + LEASE_EXPIRY_SECS + 1), vec![1]);
        // 重复扫描不重复报告（转移语义）
        assert!(l.sweep(100 + LEASE_EXPIRY_SECS + 2).is_empty());
        assert!(l.is_offline(1));
        assert!(!l.is_offline(2));
    }

    #[test]
    fn remove_clears_state() {
        let mut l = Liveness::new();
        l.heartbeat(1, 100);
        l.mark_offline(2);
        l.remove(1);
        l.remove(2);
        assert!(l.offline_nodes().is_empty());
        assert!(!l.is_offline(1));
    }
}
