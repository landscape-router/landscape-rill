//! 密钥域：主密钥派生与版本（CONTROL_PLANE §3.3/§5.4）
//!
//! key_dst/key_path/broadcast_key 为派生值（不落盘）；master_key 轮换与吊销
//! bump key_version，使旧密钥全部失效（节点重新注册/重连后收敛）。

use landscape_rill_core::crypto::{derive_key_dst, derive_key_path, KEY_DST_LEN};

pub struct KeyManager {
    master_key: [u8; 32],
    key_version: u32,
}

impl KeyManager {
    pub fn new(master_key: [u8; 32]) -> Self {
        Self {
            master_key,
            key_version: 1,
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

    /// 吊销等密钥域变更时递增（旧 key_dst 立废）
    pub fn bump_version(&mut self) {
        self.key_version += 1;
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
}
