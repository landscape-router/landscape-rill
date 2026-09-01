//! 网络域（CONTROL_PLANE §1.5 多网络隔离）：一个 coordinator 进程服务多个默认互不可见的
//! 隔离网络。隔离域 = 每网络独立的：network_id / 主密钥（KeyManager）/ 注册表（Registry，
//! auth key 空间 + 白名单 + 条目）/ 路径服务（PathService，relay 集合与 PathMap）/ relay_list。
//! 共享：进程、存储、signer（同一 coordinator 签名）、Liveness/Directory（node_id 全局键控）。

use landscape_rill_core::control::registry::Registry;
use serde::{Deserialize, Serialize};

use crate::keys::KeyManager;
use crate::path_service::PathService;

/// network_id 保留值：0 = 未分配（合法网络名散列值不得为 0）
pub const NETWORK_ID_UNSET: u32 = 0;

/// 网络名 → network_id（FNV-1a 32 位，确定性散列）：
/// - 跨重启/重载稳定（配置顺序变化不漂移）
/// - 碰撞在配置加载时 fail-closed 拒绝（validate 校验唯一性）
/// - 0 保留（散列到 0 视为不可用，换名即可）
pub fn network_id_for(name: &str) -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    for b in name.as_bytes() {
        hash ^= *b as u32;
        hash = hash.wrapping_mul(0x0100_0193);
    }
    if hash == NETWORK_ID_UNSET {
        NETWORK_ID_UNSET + 1
    } else {
        hash
    }
}

/// 单个网络的隔离域（registry + 主密钥 + 路径 + relay 列表）
pub struct NetworkDomain {
    pub network_id: u32,
    pub name: String,
    pub registry: Registry,
    pub keys: KeyManager,
    pub paths: PathService,
    /// relay 列表（DERP map 等价物，CONNECTIVITY §5）：按 RTT 排序的本网 relay 端点，
    /// 随 netmap 下发（CONTROL_PLANE §3.2）
    pub relay_list: Vec<String>,
}

impl NetworkDomain {
    pub fn new(name: &str, network_id: u32, master_key: [u8; 32]) -> Self {
        Self {
            network_id,
            name: name.to_string(),
            registry: Registry::new(network_id),
            keys: KeyManager::new(master_key),
            paths: PathService::new(),
            relay_list: Vec::new(),
        }
    }

    /// relay 节点集合 = 能力位含 relay 的节点（voluntary opt-in，CONNECTIVITY §5）
    pub fn sync_relays(&mut self) {
        let relays: Vec<u32> = self
            .registry
            .entries()
            .filter(|e| e.capabilities & crate::coordinator::CAPABILITY_RELAY != 0)
            .map(|e| e.node_id)
            .collect();
        self.paths.set_relays(relays);
    }
}

/// relay 列表持久化条目（RTT 排序结果随快照落盘，重启不丢挂靠顺序）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSnapshot {
    pub network_id: u32,
    pub relay_list: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_id_deterministic_and_distinct() {
        let a = network_id_for("lab");
        let b = network_id_for("work");
        assert_eq!(a, network_id_for("lab"));
        assert_ne!(a, b);
        assert_ne!(a, NETWORK_ID_UNSET);
        assert_ne!(b, NETWORK_ID_UNSET);
    }

    #[test]
    fn network_id_differs_by_name_only() {
        assert_eq!(network_id_for("family"), network_id_for("family"));
        assert_ne!(network_id_for("family"), network_id_for("familY"));
    }
}
