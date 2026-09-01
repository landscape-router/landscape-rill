//! 节点活性域：心跳与离线状态（CONTROL_PLANE §5.2）
//!
//! 软状态：last_seen/offline 不落盘（REQ-037 持久类清单），重启后重建。

use std::collections::HashMap;

#[derive(Debug, Default)]
pub struct Liveness {
    last_seen: HashMap<u32, u64>,
    offline: Vec<u32>,
}

impl Liveness {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn heartbeat(&mut self, node_id: u32, now: u64) {
        self.last_seen.insert(node_id, now);
        self.offline.retain(|id| *id != node_id);
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
        l.heartbeat(1, 200);
        assert!(l.offline_nodes().is_empty());
        assert!(!l.is_offline(1));
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
