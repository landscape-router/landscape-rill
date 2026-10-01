//! 密钥域：主密钥派生与版本（CONTROL_PLANE §3.3/§5.4/§5.5）
//!
//! key_dst/key_path/broadcast_key 为派生值（不落盘）；master_key 轮换与吊销
//! bump key_version，使旧密钥全部失效（节点重新注册/重连后收敛）。
//! 吊销触发的轮换经合并窗口批次生效（REQ-048）。

use landscape_rill_core::crypto::{derive_key_dst, derive_key_path, KEY_DST_LEN};

pub struct KeyManager {
    master_key: [u8; 32],
    key_version: u32,
    /// 吊销合并轮换窗口（REQ-048）：首条吊销定的到期时刻（unix 秒）；
    /// 到期在事件驱动点统一生效，窗口内后续吊销共享同一次轮换
    pending_revoke_rotation: Option<u64>,
}

impl KeyManager {
    pub fn new(master_key: [u8; 32]) -> Self {
        Self {
            master_key,
            key_version: 1,
            pending_revoke_rotation: None,
        }
    }

    /// 节点转发密钥 key_dst = KDF(主密钥, node_id)
    pub fn key_for(&self, node_id: u32) -> [u8; KEY_DST_LEN] {
        derive_key_dst(&self.master_key, node_id)
    }

    /// 广播密钥（FRAME_HEADER §2.6）：全部广播能力位节点共享
    pub fn broadcast_key(&self) -> [u8; KEY_DST_LEN] {
        derive_key_dst(&self.master_key, 0xFFFF_FFFF)
    }

    /// 路径授权密钥 key_path = KDF(主密钥, path_id, path_epoch)
    /// （CONTROL_PLANE §3.11.5，只发路径参与者）
    pub fn key_path_for(&self, path_id: u64, path_epoch: u32) -> [u8; KEY_DST_LEN] {
        derive_key_path(&self.master_key, path_id, path_epoch)
    }

    /// 主密钥轮换（REQ-037 写穿透；key_version 递增使旧密钥全部失效）
    pub fn rotate(&mut self, new_master_key: [u8; 32]) {
        self.master_key = new_master_key;
        self.key_version += 1;
    }

    /// 吊销触发的轮换入合并窗口（REQ-048）：首条吊销定窗，
    /// 窗口内后续吊销共享（不延期）
    pub fn arm_revoke_rotation(&mut self, deadline: u64) {
        if self.pending_revoke_rotation.is_none() {
            self.pending_revoke_rotation = Some(deadline);
        }
    }

    /// 批次末轮换（REQ-048）：窗口到期即一次 bump 并清窗；未到期不动
    pub fn take_revoke_rotation(&mut self, now: u64) -> bool {
        if self.pending_revoke_rotation.is_some_and(|d| now >= d) {
            self.pending_revoke_rotation = None;
            self.key_version += 1;
            true
        } else {
            false
        }
    }

    /// 显式主密钥轮换吸收挂起窗口（REQ-048：手动轮换不走合并窗口）
    pub fn clear_revoke_rotation(&mut self) {
        self.pending_revoke_rotation = None;
    }

    pub fn pending_revoke_rotation(&self) -> Option<u64> {
        self.pending_revoke_rotation
    }

    /// 恢复持久化窗口（REQ-048）：重启后下一事件驱动点按 deadline 复评
    pub fn restore_revoke_rotation(&mut self, deadline: u64) {
        self.pending_revoke_rotation = Some(deadline);
    }

    /// 恢复持久化快照（REQ-037）：key_version 落盘后原样恢复
    pub fn restore_version(&mut self, key_version: u32) {
        self.key_version = key_version;
    }

    pub fn version(&self) -> u32 {
        self.key_version
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use landscape_rill_core::crypto::derive_key_dst;

    #[test]
    fn key_dist_deterministic_per_node() {
        let km = KeyManager::new([0x77; 32]);
        let k1 = km.key_for(1);
        let k2 = km.key_for(1);
        assert_eq!(k1, k2);
        assert_ne!(k1, derive_key_dst(&[0x77; 32], 2));
        assert_eq!(km.broadcast_key(), derive_key_dst(&[0x77; 32], 0xFFFF_FFFF));
        assert_eq!(km.version(), 1);
    }

    #[test]
    fn rotate_changes_keys_and_bumps_version() {
        let mut km = KeyManager::new([0x77; 32]);
        let before = km.key_for(1);
        km.rotate([0x99; 32]);
        assert_ne!(before, km.key_for(1));
        assert_eq!(km.version(), 2);
    }

    #[test]
    fn key_path_is_derived_per_path() {
        let km = KeyManager::new([0x77; 32]);
        assert_ne!(km.key_path_for(1, 1), km.key_path_for(2, 1));
        assert_ne!(km.key_path_for(1, 1), km.key_path_for(1, 2));
        assert_eq!(km.key_path_for(1, 1), km.key_path_for(1, 1));
    }

    /// REQ-048：首条吊销定窗，窗口内重复 arm 不延期；到期一次 bump 清窗
    #[test]
    fn revoke_rotation_window_first_arm_wins_and_takes_once() {
        let mut km = KeyManager::new([0x77; 32]);
        km.arm_revoke_rotation(100);
        km.arm_revoke_rotation(200); // 窗口内后续吊销，不延期
        assert_eq!(km.pending_revoke_rotation(), Some(100));
        assert!(!km.take_revoke_rotation(99), "未到期不动");
        assert_eq!(km.version(), 1);
        assert!(km.take_revoke_rotation(100), "到期生效");
        assert_eq!(km.version(), 2);
        assert!(!km.take_revoke_rotation(1000), "清窗后幂等");
        assert_eq!(km.version(), 2);
        assert_eq!(km.pending_revoke_rotation(), None);
    }

    /// REQ-048：显式轮换吸收挂起窗口（无额外 bump）
    #[test]
    fn explicit_rotation_absorbs_pending_window() {
        let mut km = KeyManager::new([0x77; 32]);
        km.arm_revoke_rotation(100);
        km.rotate([0x99; 32]); // 版本已 +1，挂起窗口不再需要
        km.clear_revoke_rotation();
        assert_eq!(km.version(), 2);
        assert!(!km.take_revoke_rotation(1000));
        assert_eq!(km.version(), 2);
    }

    /// REQ-048：恢复的窗口照常到期生效
    #[test]
    fn restored_window_fires_on_due() {
        let mut km = KeyManager::new([0x77; 32]);
        km.restore_revoke_rotation(50);
        assert!(km.take_revoke_rotation(60));
        assert_eq!(km.version(), 2);
    }
}
