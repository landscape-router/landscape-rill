//! RouteMap 服务（CONTROL_PLANE §3.17，REQ-065）
//!
//! 动态"怎么到"与 netmap"谁存在"分离（PathMap 同哲学）：
//! - dn42 ext 节点 RouteSync 增量上报 BGP LocRib 真实可达性（前缀 + NEXT_HOP）
//! - 服务端聚合"前缀 → ext 节点"表（多 ext 同前缀 = 多条，不做 best-path）
//! - 独立版本空间：变更 +1，不 bump netmap version（路由抖动不污染拓扑版本）
//! - 第二道闸：覆盖域校验（前缀必须被该节点注册聚合公告覆盖）+ per-node 条数上限
//! - 震荡阻尼：同 (node, prefix) 翻转 10min 内 3 次 → 阻尼（移出 + 期内忽略）
//! - 生命周期：BGP 会话断（客户端随窗口全撤）/ 离线 / 吊销 → withdraw_node
//! - leader 视角软状态（不进 raft 日志、不落盘）：派生数据可由节点重上报重建
//!   （注册完成后全量首发；主切换 → 重定向重注册 → 全量补报）

use landscape_rill_core::route::Prefix;
use std::collections::HashMap;

/// per-node 动态路由条数上限（缺省镜像节点侧 max_prefixes 量级；REQ-047 语义）
pub const ROUTE_MAP_MAX_PER_NODE: usize = 2000;
/// 震荡阻尼窗口（秒）：窗口内达到 FLAP_LIMIT 次翻转 → 阻尼该前缀
pub const FLAP_WINDOW_SECS: u64 = 600;
/// 阻尼阈值：窗口内翻转次数上限
pub const FLAP_LIMIT: usize = 3;

/// RouteSync 应用结果（观测/测试）
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RouteSyncOutcome {
    pub accepted: usize,
    /// 覆盖域外拒绝（不进表）
    pub rejected_coverage: usize,
    /// per-node 上限拒绝
    pub rejected_cap: usize,
    /// 阻尼期内忽略
    pub damped: usize,
    /// 表是否变化（版本 bump 依据）
    pub changed: bool,
}

/// 单条快照（全量推送）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteMapSnapshotEntry {
    pub prefix: Prefix,
    pub node_id: u32,
    pub next_hop: String,
}

#[derive(Debug, Default)]
pub struct RouteMapService {
    /// (prefix, node) → next_hop（规范 CIDR 键，多 ext 同前缀 = 多条）
    entries: HashMap<(Prefix, u32), String>,
    /// per-node 条目数（上限判定）
    per_node: HashMap<u32, usize>,
    /// (prefix, node) 翻转时间戳窗口（阻尼判定）
    flaps: HashMap<(Prefix, u32), Vec<u64>>,
    /// 阻尼到期（unix 秒）：期内忽略该 (prefix, node)
    damped_until: HashMap<(Prefix, u32), u64>,
    version: u64,
}

impl RouteMapService {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    /// 应用一次增量上报。coverage = 该节点注册聚合公告（覆盖域判定，
    /// import policy 之外的协调者强制闸）。解析失败的前缀按覆盖域拒绝计。
    /// 阻尼只计**状态翻转**（缺席→在场 / 在场→缺席）：next_hop 刷新等
    /// 稳态重报不算震荡（注册后全量补报不该触发阻尼）
    pub fn apply_sync(
        &mut self,
        node: u32,
        announced: &[(Prefix, String)],
        withdrawn: &[Prefix],
        coverage: &[Prefix],
        max_per_node: usize,
        now: u64,
    ) -> RouteSyncOutcome {
        let mut out = RouteSyncOutcome::default();
        for (prefix, next_hop) in announced {
            let key = (*prefix, node);
            if self
                .damped_until
                .get(&key)
                .is_some_and(|&until| now < until)
            {
                out.damped += 1;
                continue;
            }
            if !coverage.iter().any(|c| prefix.is_covered_by(c)) {
                out.rejected_coverage += 1;
                continue;
            }
            let is_new = !self.entries.contains_key(&key);
            if is_new && self.per_node.get(&node).copied().unwrap_or(0) >= max_per_node {
                out.rejected_cap += 1;
                continue;
            }
            if is_new && self.flip(node, *prefix, now) {
                // 阻尼触发：不进表 + 期内忽略后续翻转
                self.damped_until.insert(key, now + FLAP_WINDOW_SECS);
                out.damped += 1;
                continue;
            }
            if self.entries.insert(key, next_hop.clone()).is_none() {
                *self.per_node.entry(node).or_insert(0) += 1;
                out.changed = true;
            }
            out.accepted += 1;
        }
        for prefix in withdrawn {
            let key = (*prefix, node);
            if self
                .damped_until
                .get(&key)
                .is_some_and(|&until| now < until)
            {
                out.damped += 1;
                continue;
            }
            if self.entries.contains_key(&key) && self.flip(node, *prefix, now) {
                self.damped_until.insert(key, now + FLAP_WINDOW_SECS);
            }
            if self.remove_entry(&key) {
                out.changed = true;
            }
        }
        if out.changed {
            self.version = self.version.saturating_add(1);
        }
        out
    }

    /// 记录一次状态翻转；返回是否触发阻尼（窗口内第 FLAP_LIMIT 次）
    fn flip(&mut self, node: u32, prefix: Prefix, now: u64) -> bool {
        let key = (prefix, node);
        let ts = self.flaps.entry(key).or_default();
        ts.retain(|t| now.saturating_sub(*t) <= FLAP_WINDOW_SECS);
        ts.push(now);
        ts.len() >= FLAP_LIMIT
    }

    fn remove_entry(&mut self, key: &(Prefix, u32)) -> bool {
        if self.entries.remove(key).is_some() {
            if let Some(n) = self.per_node.get_mut(&key.1) {
                *n = n.saturating_sub(1);
            }
            true
        } else {
            false
        }
    }

    /// 节点全部动态路由移除（离线/吊销/会话断兜底）；返回是否变化
    pub fn withdraw_node(&mut self, node: u32) -> bool {
        let before = self.entries.len();
        self.entries.retain(|(_, n), _| *n != node);
        let changed = self.entries.len() != before;
        if changed {
            self.per_node.remove(&node);
            self.flaps.retain(|(_, n), _| *n != node);
            self.damped_until.retain(|(_, n), _| *n != node);
            self.version = self.version.saturating_add(1);
        }
        changed
    }

    /// 全量快照（确定性排序：前缀 CIDR 字典序 → node_id）
    pub fn snapshot(&self) -> Vec<RouteMapSnapshotEntry> {
        let mut out: Vec<RouteMapSnapshotEntry> = self
            .entries
            .iter()
            .map(|((prefix, node), nh)| RouteMapSnapshotEntry {
                prefix: *prefix,
                node_id: *node,
                next_hop: nh.clone(),
            })
            .collect();
        out.sort_by_key(|e| (e.prefix.to_cidr(), e.node_id));
        out
    }

    /// 条目数（状态端点观测）
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 条目归属查询（测试）
    pub fn has(&self, prefix: &Prefix, node: u32) -> bool {
        self.entries.contains_key(&(*prefix, node))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(cidr: &str) -> Prefix {
        Prefix::parse(cidr).unwrap()
    }

    fn coverage() -> Vec<Prefix> {
        vec![p("172.20.0.0/14"), p("fd00::/8")]
    }

    #[test]
    fn sync_accumulates_multi_ext_same_prefix() {
        let mut m = RouteMapService::new();
        let out = m.apply_sync(
            1,
            &[(p("172.20.1.0/24"), "172.20.100.2".into())],
            &[],
            &coverage(),
            ROUTE_MAP_MAX_PER_NODE,
            1000,
        );
        assert_eq!((out.accepted, out.changed), (1, true));
        let out = m.apply_sync(
            2,
            &[(p("172.20.1.0/24"), "172.20.101.2".into())],
            &[],
            &coverage(),
            ROUTE_MAP_MAX_PER_NODE,
            1000,
        );
        assert_eq!((out.accepted, out.changed), (1, true));
        // 同 (node,prefix) 重复上报：next_hop 刷新，不 double count，不 bump
        let out = m.apply_sync(
            1,
            &[(p("172.20.1.0/24"), "172.20.100.9".into())],
            &[],
            &coverage(),
            ROUTE_MAP_MAX_PER_NODE,
            1000,
        );
        assert_eq!((out.accepted, out.changed), (1, false));
        assert_eq!(m.len(), 2);
        assert!(m.has(&p("172.20.1.0/24"), 1));
        assert!(m.has(&p("172.20.1.0/24"), 2));
        let snap = m.snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].node_id, 1, "字典序 + node 排序");
    }

    #[test]
    fn coverage_and_cap_rejected() {
        let mut m = RouteMapService::new();
        let out = m.apply_sync(
            1,
            &[
                (p("172.20.1.0/24"), "nh".into()),
                (p("10.99.0.0/16"), "nh".into()), // 覆盖域外
                (p("fd42:1::/48"), "nh".into()),  // 域内（fd00::/8）
            ],
            &[],
            &coverage(),
            2,
            1000,
        );
        assert_eq!(
            (out.accepted, out.rejected_coverage, out.rejected_cap),
            (2, 1, 0)
        );
        // 上限 2 已满：第三条域内前缀拒绝
        let out = m.apply_sync(
            1,
            &[(p("172.21.1.0/24"), "nh".into())],
            &[],
            &coverage(),
            2,
            1000,
        );
        assert_eq!((out.rejected_cap, out.changed), (1, false));
    }

    #[test]
    fn flap_damping_suppresses_prefix() {
        let mut m = RouteMapService::new();
        let px = p("172.20.1.0/24");
        // A(1000) → W(1010) → A(1020)：第 3 次翻转触发阻尼（条目不进表）
        m.apply_sync(1, &[(px, "nh".into())], &[], &coverage(), 100, 1000);
        m.apply_sync(1, &[], &[px], &coverage(), 100, 1010);
        let out = m.apply_sync(1, &[(px, "nh".into())], &[], &coverage(), 100, 1020);
        assert_eq!(out.damped, 1);
        assert!(!m.has(&px, 1), "阻尼 = 不进表");
        // 阻尼期内上报忽略
        let out = m.apply_sync(1, &[(px, "nh".into())], &[], &coverage(), 100, 1030);
        assert_eq!(out.damped, 1);
        assert!(!m.has(&px, 1));
        // 窗口外恢复准入
        let out = m.apply_sync(
            1,
            &[(px, "nh".into())],
            &[],
            &coverage(),
            100,
            1020 + FLAP_WINDOW_SECS,
        );
        assert_eq!(out.accepted, 1);
        assert!(m.has(&px, 1));
    }

    #[test]
    fn steady_refresh_is_not_flap() {
        // 稳态重报（next_hop 刷新/注册后全量补报）不构成翻转，不触发阻尼
        let mut m = RouteMapService::new();
        let px = p("172.20.1.0/24");
        for t in 0..6 {
            let out = m.apply_sync(
                1,
                &[(px, format!("nh{t}"))],
                &[],
                &coverage(),
                100,
                1000 + t,
            );
            assert_eq!(out.damped, 0, "t={t}");
            assert_eq!(out.accepted, 1);
        }
        assert!(m.has(&px, 1));
    }

    #[test]
    fn withdraw_node_clears_and_bumps() {
        let mut m = RouteMapService::new();
        m.apply_sync(
            1,
            &[(p("172.20.1.0/24"), "nh".into())],
            &[],
            &coverage(),
            100,
            1000,
        );
        let v = m.version();
        assert!(m.withdraw_node(1));
        assert!(m.is_empty());
        assert_eq!(m.version(), v + 1);
        assert!(!m.withdraw_node(1), "幂等：无变化不 bump");
    }

    #[test]
    fn withdraw_releases_cap_slot() {
        let mut m = RouteMapService::new();
        let px = p("172.20.1.0/24");
        m.apply_sync(1, &[(px, "nh".into())], &[], &coverage(), 1, 1000);
        let out = m.apply_sync(1, &[], &[px], &coverage(), 1, 1010);
        assert!(out.changed);
        // 槽位已释放：可再进（时间轴离开翻转窗口，不触发阻尼）
        let out = m.apply_sync(1, &[(px, "nh".into())], &[], &coverage(), 1, 3000);
        assert_eq!(out.rejected_cap, 0);
        assert!(m.has(&px, 1));
    }
}
