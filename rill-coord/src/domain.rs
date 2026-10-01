//! 网络域（CONTROL_PLANE §1.5 多网络隔离）：一个 coordinator 进程服务多个默认互不可见的
//! 隔离网络。隔离域 = 每网络独立的：network_id / 主密钥（KeyManager）/ 注册表（Registry，
//! auth key 空间 + 白名单 + 条目）/ 路径服务（PathService，relay 集合与 PathMap）/ relay roster。
//! 共享：进程、存储、signer（同一 coordinator 签名）、Liveness/Directory（node_id 全局键控）。

use crate::config::RelayRosterConfig;
use landscape_rill_core::control::acl::AclPolicy;
use landscape_rill_core::control::registry::Registry;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::keys::KeyManager;
use crate::path_service::PathService;

/// network_id 保留值：0 = 未分配（合法网络名散列值不得为 0）
pub const NETWORK_ID_UNSET: u32 = 0;

/// roster 退出滞回（REQ-062 开放问题 ②默认值）：连续 N 轮 RTT 探测无响应才移出，
/// 防健康抖动导致名单抖动；进入 = 首次探测命中即入（或 include 兜底）
pub const RELAY_EXIT_MISS_ROUNDS: u32 = 3;

/// network 名 → network_id（FNV-1a 32 位，确定性散列）：
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

/// 单个网络的隔离域（registry + 主密钥 + 路径 + relay roster）
pub struct NetworkDomain {
    pub network_id: u32,
    pub name: String,
    pub registry: Registry,
    pub keys: KeyManager,
    pub paths: PathService,
    /// relay roster（REQ-062）：有序激活名单（顺序 = 挂靠优先级，RTT 升序）。
    /// PathService relay 集 = roster（双资格：能力位 ∩ 选用）；变更只经
    /// `apply_roster`（raft 过日志，确定性重放）——单一写者，注册不再自动全量进
    pub roster: Vec<u32>,
    /// roster 硬约束（配置权威，REQ-062 模式 C；SIGHUP 经 set_relay_constraints 落位）
    pub relay_cfg: RelayRosterConfig,
    /// 最近一轮 RTT（毫秒；leader 视角软状态，不落盘——roster 提案输入）
    pub relay_rtt: HashMap<u32, u64>,
    /// 连续 RTT 探测 miss 轮数（退出滞回计数）
    pub relay_miss: HashMap<u32, u32>,
    /// ACL 策略（REQ-045，CONTROL_PLANE §3.10）：coordinator 权威，随 netmap 原子下发；
    /// 配置是唯一来源（apply_to 应用），不持久化
    pub acl: AclPolicy,
}

impl NetworkDomain {
    pub fn new(name: &str, network_id: u32, master_key: [u8; 32]) -> Self {
        Self {
            network_id,
            name: name.to_string(),
            registry: Registry::new(network_id),
            keys: KeyManager::new(master_key),
            paths: PathService::new(),
            roster: Vec::new(),
            relay_cfg: RelayRosterConfig::default(),
            relay_rtt: HashMap::new(),
            relay_miss: HashMap::new(),
            acl: AclPolicy::default(),
        }
    }

    /// roster 落位（apply 侧唯一入口）：PathService relay 集同步 = roster。
    /// 返回集合（无序）是否变化（netmap bump 依据——顺序变化不 bump，
    /// 经服务端路径候选即时生效，netmap 侧随下次推送懒传播）
    pub fn apply_roster(&mut self, roster: Vec<u32>) -> bool {
        let mut old: Vec<u32> = self.roster.clone();
        let mut new = roster.clone();
        old.sort_unstable();
        new.sort_unstable();
        let changed = old != new;
        self.roster = roster;
        self.paths.set_relays(self.roster.clone());
        changed
    }
}

/// roster 持久化条目（REQ-062）：重启不丢挂靠顺序与激活状态
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSnapshot {
    pub network_id: u32,
    pub roster: Vec<u32>,
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

    /// roster 落位：集合变化才报变更；PathService relay 集始终 = roster
    #[test]
    fn apply_roster_syncs_path_service() {
        let mut d = NetworkDomain::new("lab", 7, [1; 32]);
        assert!(d.apply_roster(vec![3, 1]));
        assert_eq!(d.paths.relays(), &[3, 1]);
        // 同集不同序 = 无集合变化（不 bump）
        assert!(!d.apply_roster(vec![1, 3]));
        assert_eq!(d.paths.relays(), &[1, 3]);
        assert!(d.apply_roster(vec![1]));
        assert_eq!(d.paths.relays(), &[1]);
    }
}
