//! RouteSync 上报防抖状态机（REQ-065，CONTROL_PLANE §3.17）：BGP LocRib 变更
//! 经窗口合并后增量上报。I/O-free——窗口判定/合并/全量重报纯状态，发送由
//! run loop 驱动（flush 产出 wire 载荷）。
//!
//! 语义要点：
//! - pending 同前缀 latest-wins（窗口内震荡只报末态）
//! - 会话断：已上报中该 peer 归因的前缀转撤销；多 peer 同前缀仍有供应则保留
//! - 服务端 RouteMap 是 leader 本地软状态：重注册即全量重报（reported 重放）

use landscape_rill_core::route::{Prefix, RouteEngine};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// 批处理窗口（REQ-065 决策 3）：BGP 变更合并节奏
pub const ROUTE_REPORT_WINDOW: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq, Eq)]
enum PendingChange {
    /// next_hop = BGP NEXT_HOP；peer = 学习来源（会话断撤销归因）
    Announce {
        next_hop: String,
        peer: String,
    },
    Withdraw,
}

/// flush 产物：announced = (prefix, next_hop)；withdrawn = prefix
pub type RouteSyncPayload = (Vec<(String, String)>, Vec<String>);

#[derive(Debug, Default)]
pub struct RouteReporter {
    /// 待上报增量（同前缀 latest-wins）
    pending: BTreeMap<Prefix, PendingChange>,
    /// 已上报状态（协调端应有视图）：prefix → (next_hop, peer)
    reported: BTreeMap<Prefix, (String, String)>,
    /// 窗口起点（首条待报变更时刻；None = 空闲）
    window: Option<Instant>,
}

impl RouteReporter {
    fn note(&mut self, now: Instant) {
        if self.window.is_none() {
            self.window = Some(now);
        }
    }

    pub fn learned(&mut self, prefix: Prefix, next_hop: String, peer: &str, now: Instant) {
        self.note(now);
        self.pending.insert(
            prefix,
            PendingChange::Announce {
                next_hop,
                peer: peer.to_string(),
            },
        );
    }

    pub fn withdrawn(&mut self, prefix: Prefix, now: Instant) {
        self.note(now);
        self.pending.insert(prefix, PendingChange::Withdraw);
    }

    /// 会话断：该 peer 归因的已上报前缀全部转撤销（本地引擎已随
    /// remove_dn42_peer 清理；flush 时再校验是否仍有其他 peer 供应）
    pub fn session_down(&mut self, peer: &str, now: Instant) {
        for (prefix, (_, owner)) in &self.reported {
            if owner == peer && !self.pending.contains_key(prefix) {
                self.pending.insert(*prefix, PendingChange::Withdraw);
            }
        }
        if !self.pending.is_empty() {
            self.note(now);
        }
    }

    /// 重注册全量重报：服务端 RouteMap 为 leader 本地软状态（不落盘、
    /// failover 后为空），注册成功即重放已上报视图收敛
    pub fn resync_on_registered(&mut self, now: Instant) {
        let entries: Vec<(Prefix, (String, String))> =
            self.reported.iter().map(|(p, v)| (*p, v.clone())).collect();
        for (prefix, (next_hop, peer)) in entries {
            self.pending
                .insert(prefix, PendingChange::Announce { next_hop, peer });
        }
        if !self.pending.is_empty() {
            self.note(now);
        }
    }

    pub fn is_due(&self, now: Instant) -> bool {
        self.window
            .is_some_and(|start| now.duration_since(start) >= ROUTE_REPORT_WINDOW)
    }

    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// 窗口到期冲刷：产出 (announced, withdrawn) wire 载荷；None = 无可报。
    /// engine 用于撤销前校验（多 peer 同前缀仍有供应则保留，不报撤销）
    pub fn flush(&mut self, engine: &RouteEngine) -> Option<RouteSyncPayload> {
        if self.pending.is_empty() {
            self.window = None;
            return None;
        }
        let pending = std::mem::take(&mut self.pending);
        self.window = None;
        let mut announced: Vec<(String, String)> = Vec::new();
        let mut withdrawn: Vec<String> = Vec::new();
        for (prefix, change) in pending {
            match change {
                PendingChange::Announce { next_hop, peer } => {
                    self.reported.insert(prefix, (next_hop.clone(), peer));
                    announced.push((prefix.to_cidr(), next_hop));
                }
                PendingChange::Withdraw => {
                    if let Some(peer) = engine.dn42_via(&prefix) {
                        // 其他会话仍供应：保留公告，仅换归因
                        if let Some((next_hop, _)) = self.reported.get(&prefix).cloned() {
                            self.reported.insert(prefix, (next_hop, peer));
                        }
                        continue;
                    }
                    self.reported.remove(&prefix);
                    withdrawn.push(prefix.to_cidr());
                }
            }
        }
        Some((announced, withdrawn))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use landscape_rill_core::route::{RouteEntry, RouteSource, RouteVia};

    fn p(cidr: &str) -> Prefix {
        Prefix::parse(cidr).unwrap()
    }

    fn engine_with(peer: &str, cidr: &str) -> RouteEngine {
        let mut e = RouteEngine::new();
        e.insert(RouteEntry {
            prefix: p(cidr),
            source: RouteSource::Dn42,
            via: RouteVia::Dn42(peer.into()),
            metric: None,
        });
        e
    }

    #[test]
    fn window_merges_latest_wins() {
        let mut r = RouteReporter::default();
        let t0 = Instant::now();
        r.learned(p("172.20.1.0/24"), "172.20.100.2".into(), "a", t0);
        r.withdrawn(p("172.20.1.0/24"), t0 + Duration::from_secs(1));
        assert!(!r.is_due(t0 + Duration::from_secs(4)));
        assert!(r.is_due(t0 + ROUTE_REPORT_WINDOW));
        let (announced, withdrawn) = r.flush(&RouteEngine::new()).unwrap();
        assert!(announced.is_empty());
        assert_eq!(withdrawn, vec!["172.20.1.0/24".to_string()]);
        assert!(!r.has_pending());
        assert!(!r.is_due(t0 + Duration::from_secs(3600)));
    }

    #[test]
    fn announce_then_flush_reports_state() {
        let mut r = RouteReporter::default();
        let t0 = Instant::now();
        r.learned(p("fd42:1::/48"), "fd00:100::2".into(), "a", t0);
        let (announced, withdrawn) = r.flush(&engine_with("a", "fd42:1::/48")).unwrap();
        assert_eq!(
            announced,
            vec![("fd42:1::/48".to_string(), "fd00:100::2".to_string())]
        );
        assert!(withdrawn.is_empty());
    }

    #[test]
    fn session_down_withdraws_only_unsupplied() {
        let mut r = RouteReporter::default();
        let t0 = Instant::now();
        r.learned(p("172.20.1.0/24"), "172.20.100.2".into(), "a", t0);
        r.learned(p("172.20.2.0/24"), "172.20.100.3".into(), "b", t0);
        let _ = r.flush(&engine_with("a", "172.20.1.0/24")).unwrap();

        // a 断：1.0/24 仍由 b 供应（引擎里 2.0/24 由 b、1.0/24 视引擎状态）；
        // 构造引擎 = b 供应两前缀 → 均不撤销但 1.0/24 换归因
        let mut engine = engine_with("b", "172.20.1.0/24");
        engine.insert(RouteEntry {
            prefix: p("172.20.2.0/24"),
            source: RouteSource::Dn42,
            via: RouteVia::Dn42("b".into()),
            metric: None,
        });
        r.session_down("a", t0);
        assert!(r.has_pending());
        let (announced, withdrawn) = r.flush(&engine).unwrap();
        assert!(announced.is_empty());
        assert!(withdrawn.is_empty());
        // 归因已换到 b：b 再断 → 无引擎供应 → 撤销
        r.session_down("b", t0);
        let (_, withdrawn) = r.flush(&RouteEngine::new()).unwrap();
        assert_eq!(withdrawn.len(), 2);
    }

    #[test]
    fn resync_replays_reported() {
        let mut r = RouteReporter::default();
        let t0 = Instant::now();
        r.learned(p("172.20.1.0/24"), "172.20.100.2".into(), "a", t0);
        let _ = r.flush(&engine_with("a", "172.20.1.0/24")).unwrap();
        assert!(!r.has_pending());

        r.resync_on_registered(t0);
        assert!(r.has_pending());
        let (announced, _) = r.flush(&engine_with("a", "172.20.1.0/24")).unwrap();
        assert_eq!(announced.len(), 1);
        assert_eq!(announced[0].0, "172.20.1.0/24");
    }

    #[test]
    fn flush_empty_is_none() {
        let mut r = RouteReporter::default();
        assert!(r.flush(&RouteEngine::new()).is_none());
    }
}
