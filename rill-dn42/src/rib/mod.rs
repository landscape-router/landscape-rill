//! LocRib / best-path（DN42_LEG §4.2：v1 单路径，最短 AS path 优先）。
//! 会话层喂入 UPDATE，输出 RouteChange 流，rill-node runtime 据此注入/移除
//! 路由引擎的 dn42 来源条目（ROUTE_ENGINE §3）。

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::net::IpAddr;

use landscape_rill_core::route::Prefix;

use crate::policy::ImportReject;
use crate::wire::{PathAttr, UpdateMsg};

/// 生效路径：AS4_PATH 优先（RFC 6793；dn42 全 4B ASN 场景即真实路径），
/// 否则用 2B AS_PATH 扁平化。AS_SET 段也全部展开（环路检测覆盖所有成员）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgpPath {
    pub as_path: Vec<u32>,
    pub next_hop: Option<IpAddr>,
    pub origin: u8,
    pub communities: Vec<u32>,
}

impl BgpPath {
    pub fn path_len(&self) -> usize {
        self.as_path.len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteChange {
    Learned { prefix: Prefix, path: BgpPath },
    Withdrawn(Prefix),
}

/// apply 的结果：变更流 + 拒绝记录 + max-prefix 溢出标志
#[derive(Debug, Default)]
pub struct ApplyOutcome {
    pub changes: Vec<RouteChange>,
    pub rejected: Vec<(String, ImportReject)>,
    pub max_prefix_exceeded: bool,
}

type PfxKey = ([u8; 16], u8, bool);

fn key(p: &Prefix) -> PfxKey {
    (p.bits, p.len, p.v4)
}

#[derive(Debug, Default)]
struct PeerPaths {
    peers: Vec<(String, BgpPath)>,
    best: Option<String>,
}

/// v1 best-path：最短 AS path，平局取 peer 名字典序最小（确定性）
fn select_best(peers: &[(String, BgpPath)]) -> Option<String> {
    peers
        .iter()
        .min_by(|a, b| {
            a.1.path_len()
                .cmp(&b.1.path_len())
                .then_with(|| a.0.cmp(&b.0))
        })
        .map(|(p, _)| p.clone())
}

#[derive(Debug, Default)]
pub struct LocRib {
    entries: HashMap<PfxKey, PeerPaths>,
}

impl LocRib {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn best(&self, prefix: &Prefix) -> Option<&BgpPath> {
        let e = self.entries.get(&key(prefix))?;
        let best = e.best.as_ref()?;
        e.peers
            .iter()
            .find(|(p, _)| p == best)
            .map(|(_, path)| path)
    }

    pub fn accepted_prefixes(&self) -> usize {
        self.entries.len()
    }

    /// 会话层入口：处理一条 UPDATE（公告走 policy，撤销直通）
    pub fn apply(
        &mut self,
        peer: &str,
        update: &UpdateMsg,
        policy: &mut crate::policy::ImportPolicy,
    ) -> ApplyOutcome {
        let mut out = ApplyOutcome::default();
        for (prefix, path) in extract_announced(update) {
            if let Err(reason) = policy.admit(&prefix, &path) {
                out.rejected.push((prefix.to_cidr(), reason));
                continue;
            }
            let k = key(&prefix);
            let e = self.entries.entry(k).or_default();
            let existing = e.peers.iter_mut().find(|(p, _)| p == peer);
            match existing {
                Some((_, slot)) => {
                    // 同 peer 重公告：原地替换，不重复计数
                    let replaced = slot != &path;
                    *slot = path.clone();
                    if replaced {
                        e.best = select_best(&e.peers);
                        push_learned(&mut out.changes, &prefix, e);
                    }
                }
                None => {
                    if policy.note_accepted().is_err() {
                        out.max_prefix_exceeded = true;
                        return out;
                    }
                    e.peers.push((peer.to_string(), path.clone()));
                    e.best = select_best(&e.peers);
                    push_learned(&mut out.changes, &prefix, e);
                }
            }
        }
        for prefix in extract_withdrawn(update) {
            if let Some(changes) = self.remove_one(peer, &prefix) {
                policy.note_withdrawn();
                out.changes.extend(changes);
            }
        }
        out
    }

    /// 会话撤销：purge 该 peer 的全部路由（netmap 移除/隧道断语义）
    pub fn purge_peer(
        &mut self,
        peer: &str,
        policy: &mut crate::policy::ImportPolicy,
    ) -> Vec<RouteChange> {
        let keys: Vec<PfxKey> = self.entries.keys().copied().collect();
        let mut changes = Vec::new();
        for k in keys {
            let prefix = Prefix {
                bits: k.0,
                len: k.1,
                v4: k.2,
            };
            if let Some(c) = self.remove_one(peer, &prefix) {
                policy.note_withdrawn();
                changes.extend(c);
            }
        }
        changes
    }

    fn remove_one(&mut self, peer: &str, prefix: &Prefix) -> Option<Vec<RouteChange>> {
        let k = key(prefix);
        let e = self.entries.get_mut(&k)?;
        let before = e.peers.len();
        e.peers.retain(|(p, _)| p != peer);
        if e.peers.len() == before {
            return None;
        }
        let mut changes = Vec::new();
        if e.peers.is_empty() {
            self.entries.remove(&k);
            changes.push(RouteChange::Withdrawn(*prefix));
        } else {
            let new_best = select_best(&e.peers);
            if new_best != e.best {
                e.best = new_best;
                push_learned(&mut changes, prefix, e);
            }
        }
        Some(changes)
    }
}

fn push_learned(changes: &mut Vec<RouteChange>, prefix: &Prefix, e: &PeerPaths) {
    if let Some(best) = &e.best {
        if let Some((_, path)) = e.peers.iter().find(|(p, _)| p == best) {
            changes.push(RouteChange::Learned {
                prefix: *prefix,
                path: path.clone(),
            });
        }
    }
}

/// 公告候选：v4 NLRI（NEXT_HOP 属性）+ MP_REACH（afi 1/2, safi 1）。
/// 生效路径 = AS4_PATH（非空则优先），否则 AS_PATH。
fn extract_announced(update: &UpdateMsg) -> Vec<(Prefix, BgpPath)> {
    let mut base = BgpPath {
        as_path: vec![],
        next_hop: None,
        origin: 2,
        communities: vec![],
    };
    let mut mp_reach: Option<(u16, IpAddr)> = None;
    for attr in &update.attrs {
        match attr {
            PathAttr::Origin(o) => base.origin = *o,
            PathAttr::AsPath(segs) | PathAttr::As4Path(segs) => {
                let flat: Vec<u32> = segs.iter().flat_map(|s| s.asns.iter().copied()).collect();
                // AS4_PATH 优先（RFC 6793；后出现的 As4Path 覆盖 AsPath 的展开结果）
                match attr {
                    PathAttr::As4Path(_) if !flat.is_empty() => base.as_path = flat,
                    PathAttr::AsPath(_) if base.as_path.is_empty() => base.as_path = flat,
                    _ => {}
                }
            }
            PathAttr::NextHop(ip) => base.next_hop = Some(IpAddr::V4(*ip)),
            PathAttr::Communities(cs) => base.communities = cs.clone(),
            PathAttr::MpReach {
                afi,
                safi: 1,
                next_hop,
                ..
            } => {
                mp_reach = Some((*afi, *next_hop));
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    for p in &update.announced {
        out.push((*p, base.clone()));
    }
    if let Some((afi, nh)) = mp_reach {
        for attr in &update.attrs {
            if let PathAttr::MpReach {
                afi: a,
                safi: 1,
                nlri,
                ..
            } = attr
            {
                if *a != afi {
                    continue;
                }
                let mut path = base.clone();
                path.next_hop = Some(nh);
                for p in nlri {
                    out.push((*p, path.clone()));
                }
            }
        }
    }
    out
}

/// 撤销：v4 WITHDRAWN + MP_UNREACH（afi 1/2, safi 1）
fn extract_withdrawn(update: &UpdateMsg) -> Vec<Prefix> {
    let mut out = update.withdrawn.clone();
    for attr in &update.attrs {
        if let PathAttr::MpUnreach {
            afi: 1 | 2,
            safi: 1,
            nlri,
        } = attr
        {
            out.extend(nlri.iter().copied());
        }
    }
    out
}
