//! ts2021 服务端注册表（REQ-068，TS2021_LEG §4）：
//! 机器（Noise IK 静态公钥）→ 节点（node key / 端点 / 广播路由 / 地址），
//! tailnet 地址顺序分配（100.64.0.0/10 + fd7a:115c:a1e0::/48 同序号），
//! 变更经 broadcast 事件推送（长轮询流订阅 → 增量帧，PeersChanged/PeersRemoved）。
//!
//! v1 内存态：服务端重启即清空，客户端经重注册自愈（幂等）。
//! I/O-free：锁内纯数据变换，帧构造与发送在锁外（调用方快照后组帧）。

use landscape_rill_core::route::Prefix;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;
use tracing::{info, warn};

/// 广播路由白名单语义：具体前缀被白名单条目 covered-by 即批准；
/// 默认路由（0.0.0.0/0、::/0 = exit node 广播）由独立开关放行——
/// 白名单内含默认路由会 covered-by 放行一切，语义不成立（加载即拒绝）
#[derive(Debug, Clone)]
pub struct RoutesWhitelist {
    prefixes: Vec<Prefix>,
    allow_exit: bool,
}

impl RoutesWhitelist {
    pub fn parse(rules: &[String], allow_exit: bool) -> Result<Self, String> {
        let mut out = Vec::with_capacity(rules.len());
        for r in rules {
            if r == "0.0.0.0/0" || r == "::/0" {
                return Err(format!(
                    "default route '{r}' belongs to allow_exit switch, not routes_whitelist"
                ));
            }
            out.push(Prefix::parse(r).map_err(|e| format!("invalid route prefix {r}: {e:?}"))?);
        }
        Ok(Self {
            prefixes: out,
            allow_exit,
        })
    }

    pub fn allow_exit(&self) -> bool {
        self.allow_exit
    }

    /// 公告前缀是否批准（exit 方向单独裁决）
    pub fn approves(&self, route: &str) -> bool {
        if route == "0.0.0.0/0" || route == "::/0" {
            return self.allow_exit;
        }
        match Prefix::parse(route) {
            Ok(p) => self.prefixes.iter().any(|w| p.is_covered_by(w)),
            Err(_) => false,
        }
    }
}

/// 注册表事件（长轮询流订阅；帧构造在订阅方）
#[derive(Debug, Clone)]
pub enum Event {
    /// peer 条目新增/变更 + 删除（同一帧可并存：PeersChanged + PeersRemoved）
    Delta {
        changed: Vec<i64>,
        removed: Vec<i64>,
    },
}

/// 节点条目（netmap 组帧数据源）
#[derive(Debug, Clone)]
pub struct NodeEntry {
    pub nid: i64,
    /// 机器公钥（Noise IK 静态；注册幂等键）
    pub machine: [u8; 32],
    pub node_key: [u8; 32],
    pub disco_key: [u8; 32],
    pub hostname: String,
    /// 已批准广播路由（白名单过滤后；进对端 AllowedIPs 与 PrimaryRoutes）
    pub approved_routes: Vec<String>,
    /// 最近一次 MapRequest 声明的广播路由原文（覆写语义基准）
    pub announced_routes: Vec<String>,
    pub endpoints: Vec<String>,
    pub preferred_derp: Option<u16>,
    pub online: bool,
    /// 地址序号（100.64.0.N / fd7a:115c:a1e0::N）
    pub suffix: u32,
    pub created: u64,
    pub last_seen: u64,
}

impl NodeEntry {
    pub fn addresses(&self) -> Vec<String> {
        vec![
            format!("100.64.0.{}/32", self.suffix),
            format!("fd7a:115c:a1e0::{}/128", self.suffix),
        ]
    }
}

/// 注册失败原因（/machine/register 响应 Error 载荷）
#[derive(Debug)]
pub enum RegisterError {
    BadAuthKey(String),
    BadNodeKey,
    NodeKeyTaken,
}

impl std::fmt::Display for RegisterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegisterError::BadAuthKey(m) => write!(f, "auth key rejected: {m}"),
            RegisterError::BadNodeKey => write!(f, "invalid NodeKey"),
            RegisterError::NodeKeyTaken => {
                write!(f, "node key already registered by another machine")
            }
        }
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 注册表（StdMutex 保护；锁内无 await）
pub struct Registry {
    nodes: HashMap<i64, NodeEntry>,
    by_machine: HashMap<[u8; 32], i64>,
    by_node_key: HashMap<[u8; 32], i64>,
    next_id: i64,
    next_suffix: u32,
    events: broadcast::Sender<Event>,
    auth_keys: Vec<String>,
    whitelist: RoutesWhitelist,
}

impl Registry {
    pub fn new(auth_keys: Vec<String>, whitelist: RoutesWhitelist) -> Self {
        let (events, _) = broadcast::channel(64);
        Self {
            nodes: HashMap::new(),
            by_machine: HashMap::new(),
            by_node_key: HashMap::new(),
            next_id: 1,
            next_suffix: 1,
            events,
            auth_keys,
            whitelist,
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.events.subscribe()
    }

    /// auth key 准入：lrk 解析（网络段 + 过期）+ 与配置集合精确匹配
    fn admit_auth_key(&self, key: &str) -> Result<(), RegisterError> {
        let bad = |m: String| RegisterError::BadAuthKey(m);
        let body = key
            .strip_prefix("lrk-")
            .ok_or_else(|| bad("not an lrk key".into()))?;
        let (network, tail) = body
            .split_once('-')
            .ok_or_else(|| bad("malformed lrk key".into()))?;
        let (expiry, _secret) = tail
            .split_once('-')
            .ok_or_else(|| bad("malformed lrk key".into()))?;
        let expiry: u64 = expiry
            .parse()
            .map_err(|_| bad("malformed lrk expiry".into()))?;
        if expiry != 0 && unix_now() > expiry {
            return Err(bad("expired".into()));
        }
        if !self.auth_keys.iter().any(|k| k == key) {
            return Err(bad(format!("unknown key for network '{network}'")));
        }
        Ok(())
    }

    /// 注册（幂等）：同机器重注册 = 更新 node key/disco/hostname（保 nid 与地址）；
    /// 变更广播 Delta。node key 已被其他机器占用 → 拒绝。
    pub fn register(
        &mut self,
        machine: [u8; 32],
        node_key: [u8; 32],
        hostname: &str,
        auth_key: &str,
    ) -> Result<i64, RegisterError> {
        self.admit_auth_key(auth_key)?;
        if let Some(&owner) = self.by_node_key.get(&node_key) {
            if self.nodes.get(&owner).is_some_and(|n| n.machine != machine) {
                return Err(RegisterError::NodeKeyTaken);
            }
        }
        let now = unix_now();
        let nid = match self.by_machine.get(&machine) {
            Some(&nid) => {
                let entry = self.nodes.get_mut(&nid).expect("by_machine 一致性");
                self.by_node_key.remove(&entry.node_key);
                entry.node_key = node_key;
                entry.disco_key = [0u8; 32];
                entry.hostname = hostname.to_owned();
                entry.online = true;
                entry.last_seen = now;
                entry.announced_routes.clear();
                entry.approved_routes.clear();
                self.by_node_key.insert(node_key, nid);
                info!("[ts2021-server] machine re-registered: nid={nid} host={hostname}");
                nid
            }
            None => {
                let nid = self.next_id;
                self.next_id += 1;
                let suffix = self.next_suffix;
                self.next_suffix += 1;
                self.nodes.insert(
                    nid,
                    NodeEntry {
                        nid,
                        machine,
                        node_key,
                        disco_key: [0u8; 32],
                        hostname: hostname.to_owned(),
                        approved_routes: Vec::new(),
                        announced_routes: Vec::new(),
                        endpoints: Vec::new(),
                        preferred_derp: None,
                        online: true,
                        suffix,
                        created: now,
                        last_seen: now,
                    },
                );
                self.by_machine.insert(machine, nid);
                self.by_node_key.insert(node_key, nid);
                info!(
                    "[ts2021-server] node registered: nid={nid} host={hostname} addr=100.64.0.{}",
                    suffix
                );
                nid
            }
        };
        let _ = self.events.send(Event::Delta {
            changed: vec![nid],
            removed: Vec::new(),
        });
        Ok(nid)
    }

    pub fn node_by_key(&self, node_key: &[u8; 32]) -> Option<i64> {
        self.by_node_key.get(node_key).copied()
    }

    pub fn get(&self, nid: i64) -> Option<NodeEntry> {
        self.nodes.get(&nid).cloned()
    }

    /// 全部节点快照（组帧用）
    pub fn snapshot(&self) -> Vec<NodeEntry> {
        let mut v: Vec<NodeEntry> = self.nodes.values().cloned().collect();
        v.sort_by_key(|n| n.nid);
        v
    }

    /// MapRequest 增量应用：Hostinfo 覆写广播路由（白名单过滤）、端点、HomeDERP、
    /// disco key（长轮询请求携带）。路由/端点变化广播 Delta。
    pub fn apply_map_update(
        &mut self,
        nid: i64,
        disco_key: Option<[u8; 32]>,
        endpoints: Vec<String>,
        routable_ips: Vec<String>,
        preferred_derp: Option<u16>,
    ) {
        let Some(entry) = self.nodes.get_mut(&nid) else {
            return;
        };
        if let Some(d) = disco_key {
            entry.disco_key = d;
        }
        entry.endpoints = endpoints;
        entry.preferred_derp = preferred_derp;
        entry.last_seen = unix_now();
        entry.online = true;
        if entry.announced_routes != routable_ips {
            entry.announced_routes = routable_ips.clone();
            let approved: Vec<String> = routable_ips
                .iter()
                .filter(|r| {
                    let ok = self.whitelist.approves(r);
                    if !ok {
                        warn!(
                            "[ts2021-server] route not whitelisted, dropped: nid={nid} route={r}"
                        );
                    }
                    ok
                })
                .cloned()
                .collect();
            if approved != entry.approved_routes {
                entry.approved_routes = approved.clone();
                info!(
                    "[ts2021-server] routes approved: nid={nid} host={} routes=[{}]",
                    entry.hostname,
                    approved.join(",")
                );
                let _ = self.events.send(Event::Delta {
                    changed: vec![nid],
                    removed: Vec::new(),
                });
            }
        }
    }

    /// 长轮询流在线标记（流在场 = online，headscale 同源）
    pub fn mark_online(&mut self, nid: i64, online: bool) {
        let Some(entry) = self.nodes.get_mut(&nid) else {
            return;
        };
        if entry.online != online {
            entry.online = online;
            entry.last_seen = unix_now();
            let _ = self.events.send(Event::Delta {
                changed: vec![nid],
                removed: Vec::new(),
            });
        }
    }

    /// 节点删除（e2e 注入触发；广播 Removed）
    pub fn evict(&mut self, hostname: &str) -> bool {
        let Some(nid) = self
            .nodes
            .values()
            .find(|n| n.hostname == hostname)
            .map(|n| n.nid)
        else {
            return false;
        };
        if let Some(entry) = self.nodes.remove(&nid) {
            self.by_machine.remove(&entry.machine);
            self.by_node_key.remove(&entry.node_key);
            info!("[ts2021-server] node evicted: nid={nid} host={hostname}");
            let _ = self.events.send(Event::Delta {
                changed: Vec::new(),
                removed: vec![nid],
            });
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wl(rules: &[&str]) -> RoutesWhitelist {
        RoutesWhitelist::parse(
            &rules.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            false,
        )
        .unwrap()
    }

    fn registry() -> Registry {
        Registry::new(
            vec!["lrk-lab-0-".to_string() + &"A".repeat(52)],
            wl(&["10.42.0.0/16"]),
        )
    }

    const KEY: &str = "lrk-lab-0-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    #[test]
    fn register_admission_and_idempotency() {
        let mut r = registry();
        let nid = r.register([1; 32], [2; 32], "a", KEY).unwrap();
        // 同机器重注册 = 同 nid（node key 轮换）
        let nid2 = r.register([1; 32], [9; 32], "a2", KEY).unwrap();
        assert_eq!(nid, nid2);
        assert_eq!(r.get(nid).unwrap().node_key, [9; 32]);
        // 第二机器占已有 node key → 拒绝
        assert!(matches!(
            r.register([3; 32], [9; 32], "b", KEY),
            Err(RegisterError::NodeKeyTaken)
        ));
        // 坏 auth key
        assert!(matches!(
            r.register([4; 32], [5; 32], "c", "tskey-x"),
            Err(RegisterError::BadAuthKey(_))
        ));
        let nid_b = r.register([3; 32], [5; 32], "b", KEY).unwrap();
        assert_ne!(nid, nid_b);
    }

    #[test]
    fn expired_auth_key_rejected() {
        let past = unix_now() - 10;
        let expired = format!("lrk-lab-{past}-{}", "A".repeat(52));
        let mut r = Registry::new(vec![expired.clone()], wl(&[]));
        assert!(matches!(
            r.register([1; 32], [2; 32], "a", &expired),
            Err(RegisterError::BadAuthKey(_))
        ));
    }

    #[test]
    fn whitelist_filters_announced_routes() {
        let mut r = registry();
        let nid = r.register([1; 32], [2; 32], "a", KEY).unwrap();
        r.apply_map_update(
            nid,
            None,
            vec![],
            vec![
                "10.42.0.0/24".into(),
                "10.99.0.0/24".into(),
                "0.0.0.0/0".into(),
            ],
            None,
        );
        let e = r.get(nid).unwrap();
        // 具体前缀 covered-by 白名单；白名单外与 exit（未开 allow_exit）均拒
        assert_eq!(e.approved_routes, vec!["10.42.0.0/24".to_owned()]);
        // 覆写语义：再次上报缺省即清空
        r.apply_map_update(nid, None, vec![], vec![], None);
        assert!(r.get(nid).unwrap().approved_routes.is_empty());
    }

    #[test]
    fn default_routes_gated_by_allow_exit() {
        let whitelist = RoutesWhitelist::parse(&["10.42.0.0/16".to_owned()], true).unwrap();
        let mut r = Registry::new(vec![KEY.to_owned()], whitelist);
        let nid = r.register([1; 32], [2; 32], "a", KEY).unwrap();
        r.apply_map_update(
            nid,
            None,
            vec![],
            vec!["0.0.0.0/0".into(), "::/0".into(), "10.99.0.0/24".into()],
            None,
        );
        assert_eq!(
            r.get(nid).unwrap().approved_routes,
            vec!["0.0.0.0/0".to_owned(), "::/0".to_owned()]
        );
        // 默认路由不得混入白名单（covered-by 放行一切，语义不成立）
        assert!(RoutesWhitelist::parse(&["0.0.0.0/0".to_owned()], false).is_err());
    }

    #[test]
    fn evict_broadcasts_removed() {
        let mut r = registry();
        let nid = r.register([1; 32], [2; 32], "a", KEY).unwrap();
        let mut rx = r.subscribe();
        assert!(r.evict("a"));
        match rx.try_recv().unwrap() {
            Event::Delta { changed, removed } => {
                assert!(changed.is_empty());
                assert_eq!(removed, vec![nid]);
            }
        }
        assert!(r.get(nid).is_none());
        assert!(!r.evict("missing"));
    }
}
