//! 路径服务（CONTROL_PLANE §3.11，REQ-034，v1.5 控制面）
//!
//! PathMap 与 netmap 分离：netmap 描述"节点是谁"，PathMap 描述"节点之间怎么到"。
//! - 候选路径 = 直连（目标端点）+ 每条 relay 节点一条中继路径（2~4 条）
//! - key_path = KDF(主密钥, path_id, path_epoch) 按路径签发，只发路径参与者
//! - 生命周期：节点吊销 → 撤销涉及路径；路径集变更 → PathUpdate/PathWithdraw 推送

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// 路径活性租约时长（unix 秒）；过期后节点侧从候选剔除（重新请求刷新）
pub const PATH_DEFAULT_TTL: u64 = 3600;
/// per-source 待推送事件上限（REQ-047：防 pending 无界内存放大；饱和丢弃，
/// 节点随心跳重发请求 → 幂等刷新重建，最终一致）
pub const PENDING_EVENTS_MAX: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathCandidate {
    pub path_id: u64,
    pub path_epoch: u32,
    /// 有序跳（首跳 = 发送端点；direct = [dest]，relay = [relay, dest]）
    pub hops: Vec<u32>,
    /// unix 秒过期
    pub expires_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathSet {
    pub version: u64,
    pub candidates: Vec<PathCandidate>,
}

impl PathSet {
    /// 路径集是否全部过期（幂等请求的刷新依据）
    pub fn expired(&self, now: u64) -> bool {
        self.candidates.is_empty()
            || self
                .candidates
                .iter()
                .all(|c| c.expires_at != 0 && now > c.expires_at)
    }
}

/// 路径事件（心跳推送，节点以 source 身份取走）
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathEvent {
    /// 路径集变更（全量替换该 dest 的候选；source = 路径发起方）
    Update {
        source: u32,
        dest: u32,
        set: PathSet,
    },
    /// 路径撤销
    Withdraw { dest: u32, path_id: u64 },
}

#[derive(Debug, Default)]
pub struct PathService {
    /// (source, dest) → 路径集
    map: HashMap<(u32, u32), PathSet>,
    /// path_id 分配（全局递增，不复用）
    seq: u64,
    /// 未推送的路径事件（按 source 归类，心跳时取走）
    pending: HashMap<u32, Vec<PathEvent>>,
    /// relay 节点列表（能力位含 relay=0x01，voluntary opt-in；保序）
    relays: Vec<u32>,
}

impl PathService {
    pub fn new() -> Self {
        Self::default()
    }

    /// relay 节点列表更新（netmap 变更时同步）
    pub fn set_relays(&mut self, relays: Vec<u32>) {
        self.relays = relays;
    }

    pub fn relays(&self) -> &[u32] {
        &self.relays
    }

    /// 请求候选路径（直连 + 经 relay）。幂等：已有未过期路径集直接返回
    /// （避免重复分配 path_id 导致参与者间路径分叉）；重建时 push 事件给全部参与者。
    /// max_candidates 上限 4（CONTROL_PLANE §3.11：每目标 2~4 候选）。
    pub fn request(&mut self, source: u32, dest: u32, max: u32, now: u64) -> Vec<PathCandidate> {
        let key = (source, dest);
        let relays: Vec<u32> = self
            .relays
            .iter()
            .copied()
            .filter(|r| *r != source && *r != dest)
            .collect();
        if let Some(set) = self.map.get(&key).cloned() {
            if !set.expired(now) {
                // 幂等命中：refresh 推送全部参与者（路径下发走心跳推送通道，
                // 即时响应可能丢失；refresh 保证请求方最终收敛）
                self.push_to_participants(source, dest, &relays, &set);
                return set.candidates.clone();
            }
        }
        let version = self.map.get(&key).map(|s| s.version).unwrap_or(0) + 1;
        let mut candidates = vec![PathCandidate {
            path_id: self.alloc_path_id(),
            path_epoch: 1,
            hops: vec![dest],
            expires_at: now + PATH_DEFAULT_TTL,
        }];
        // relay 路径：每条 relay 一条中继路径（同 key_path 参与者的路径级授权）
        let relay_ids = relays.clone();
        for relay in relay_ids {
            candidates.push(PathCandidate {
                path_id: self.alloc_path_id(),
                path_epoch: 1,
                hops: vec![relay, dest],
                expires_at: now + PATH_DEFAULT_TTL,
            });
            if candidates.len() >= (max.clamp(2, 4) as usize) {
                break;
            }
        }
        let set = PathSet {
            version,
            candidates,
        };
        // 路径参与者全量下发（CONTROL_PLANE §3.11.5：key_path 只发路径参与者）：
        // source = 路径选择方；dest 与 relay 为接收/转发校验方，同样需要 key_path
        self.push_to_participants(source, dest, &relays, &set);
        self.map.insert(key, set);
        self.map[&key].candidates.clone()
    }

    /// 路径集事件推给全部参与者（source/dest/relay）；source 也推——即时
    /// PathResponse 可能丢失，心跳推送通道是权威下发路径。
    /// per-source 上限 PENDING_EVENTS_MAX（REQ-047：防 pending 无界放大；
    /// 饱和丢弃，节点随心跳重发请求最终一致）
    fn push_to_participants(&mut self, source: u32, dest: u32, relays: &[u32], set: &PathSet) {
        let event = PathEvent::Update {
            source,
            dest,
            set: set.clone(),
        };
        self.push_event(source, event);
        for participant in std::iter::once(dest).chain(relays.iter().copied()) {
            self.push_event(
                participant,
                PathEvent::Update {
                    source,
                    dest,
                    set: set.clone(),
                },
            );
        }
    }

    /// 入队一条待推送事件（per-source 饱和，REQ-047）
    fn push_event(&mut self, node: u32, event: PathEvent) {
        let queue = self.pending.entry(node).or_default();
        if queue.len() < PENDING_EVENTS_MAX {
            queue.push(event);
        }
    }

    /// 吊销联动：撤销所有涉及 node_id 的路径（作为源/目的 = 全撤；仅中继 = 撤该候选保留其余）。
    pub fn withdraw_node(&mut self, node_id: u32) {
        let affected_keys: Vec<(u32, u32)> = self
            .map
            .keys()
            .copied()
            .filter(|(s, d)| {
                *s == node_id
                    || *d == node_id
                    || self
                        .map
                        .get(&(*s, *d))
                        .map(|set| set.candidates.iter().any(|c| c.hops.contains(&node_id)))
                        .unwrap_or(false)
            })
            .collect();
        for key in affected_keys {
            let (source, dest) = key;
            // 源/目的被吊销：整组撤销；仅中继：撤掉含该节点的候选，其余保留
            if source == node_id || dest == node_id {
                if let Some(set) = self.map.remove(&key) {
                    for c in &set.candidates {
                        self.pending
                            .entry(source)
                            .or_default()
                            .push(PathEvent::Withdraw {
                                dest,
                                path_id: c.path_id,
                            });
                    }
                }
                continue;
            }
            if let Some(set) = self.map.get_mut(&key) {
                let withdrawn: Vec<u64> = set
                    .candidates
                    .iter()
                    .filter(|c| c.hops.contains(&node_id))
                    .map(|c| c.path_id)
                    .collect();
                set.candidates.retain(|c| !c.hops.contains(&node_id));
                let remaining = set.candidates.clone();
                if remaining.is_empty() {
                    self.map.remove(&key);
                    for path_id in withdrawn {
                        self.pending
                            .entry(source)
                            .or_default()
                            .push(PathEvent::Withdraw { dest, path_id });
                    }
                } else {
                    set.version += 1;
                    self.pending
                        .entry(source)
                        .or_default()
                        .push(PathEvent::Update {
                            source,
                            dest,
                            set: set.clone(),
                        });
                }
            }
        }
    }

    /// 取走该 source 的未推送路径事件（心跳推送）
    pub fn take_events(&mut self, source: u32) -> Vec<PathEvent> {
        self.pending.remove(&source).unwrap_or_default()
    }

    /// 持久化快照（REQ-037）：PathMap 条目 + path_id 分配器（重启不重用）
    pub fn persistent(&self) -> (Vec<(u32, u32, PathSet)>, u64) {
        let mut map: Vec<(u32, u32, PathSet)> = self
            .map
            .iter()
            .map(|((s, d), set)| (*s, *d, set.clone()))
            .collect();
        map.sort_by_key(|(s, d, _)| (*s, *d));
        (map, self.seq)
    }

    /// 恢复持久化快照（软状态 pending 不落盘，节点重新请求即重建）
    pub fn restore(&mut self, map: HashMap<(u32, u32), PathSet>, seq: u64) {
        self.map = map;
        self.seq = seq;
    }

    fn alloc_path_id(&mut self) -> u64 {
        // path_id=0 保留（默认路径回退，v1 兼容）；从 1 起分配
        self.seq += 1;
        self.seq
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_plus_relay_candidates() {
        let mut ps = PathService::new();
        ps.set_relays(vec![3, 4]);
        let cands = ps.request(1, 2, 4, 1000);
        assert_eq!(cands.len(), 3); // direct + 2 relays
        assert_eq!(cands[0].hops, vec![2]);
        assert_eq!(cands[1].hops, vec![3, 2]);
        assert_eq!(cands[2].hops, vec![4, 2]);
        // path_id 不重用、不取 0
        assert_ne!(cands[0].path_id, 0);
        assert_ne!(cands[0].path_id, cands[1].path_id);
        // 过期时间
        assert_eq!(cands[0].expires_at, 1000 + PATH_DEFAULT_TTL);
    }

    #[test]
    fn max_candidates_clamped() {
        let mut ps = PathService::new();
        ps.set_relays(vec![3, 4, 5, 6]);
        let cands = ps.request(1, 2, 8, 0);
        assert!(cands.len() <= 4);
        let cands2 = ps.request(1, 2, 0, 0);
        assert!(cands2.len() >= 2);
        assert!(cands2.len() <= 4);
    }

    #[test]
    fn relay_not_self_or_dest() {
        let mut ps = PathService::new();
        ps.set_relays(vec![1, 2, 3]);
        let cands = ps.request(1, 2, 4, 0);
        // 排除 source(1) 与 dest(2)：只剩 direct + relay3
        assert_eq!(cands.len(), 2);
        assert_eq!(cands[1].hops, vec![3, 2]);
    }

    /// per-source 待推送事件上限（REQ-047）：饱和丢弃，取走后恢复接收
    #[test]
    fn pending_events_capped_per_source() {
        let mut ps = PathService::new();
        for dest in 1..=(PENDING_EVENTS_MAX as u32 + 50) {
            ps.request(1, dest, 2, 0);
        }
        assert_eq!(ps.pending.get(&1).unwrap().len(), PENDING_EVENTS_MAX);
        // 取走（心跳推送）后恢复接收
        let _ = ps.take_events(1);
        ps.request(1, 9, 2, 0); // 幂等命中同样入队 refresh 事件
        assert_eq!(ps.pending.get(&1).unwrap().len(), 1);
    }

    #[test]
    fn withdraw_node_affects_paths() {
        let mut ps = PathService::new();
        ps.set_relays(vec![3]);
        ps.request(1, 2, 4, 0); // 路径：1→2 direct + via3
        let events = ps.take_events(1);
        assert_eq!(events.len(), 1);
        // 吊销 relay 3 → 1 的 via3 路径撤销，direct 保留（Update）
        ps.withdraw_node(3);
        let evs = ps.take_events(1);
        assert_eq!(evs.len(), 1);
        match &evs[0] {
            PathEvent::Update { source, dest, set } => {
                assert_eq!(*source, 1);
                assert_eq!(*dest, 2);
                assert_eq!(set.candidates.len(), 1); // 只剩 direct
                assert_eq!(set.candidates[0].hops, vec![2]);
            }
            _ => panic!("expected update"),
        }
        // 吊销 dest → 整组 Withdraw
        ps.withdraw_node(2);
        let evs = ps.take_events(1);
        assert_eq!(evs.len(), 1);
        assert!(matches!(evs[0], PathEvent::Withdraw { .. }));
        // 吊销 source → 整组 Withdraw
        ps.request(1, 2, 4, 0);
        let _ = ps.take_events(1);
        ps.withdraw_node(1);
        let evs = ps.take_events(1);
        assert!(evs.iter().all(|e| matches!(e, PathEvent::Withdraw { .. })));
    }

    #[test]
    fn events_delivered_per_source() {
        let mut ps = PathService::new();
        ps.set_relays(vec![]);
        ps.request(1, 2, 2, 0);
        ps.request(5, 2, 2, 0);
        assert_eq!(ps.take_events(1).len(), 1);
        assert_eq!(ps.take_events(5).len(), 1);
        assert!(ps.take_events(1).is_empty());
    }
}
