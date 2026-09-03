//! import/export policy（DN42_LEG §4/§4.1）：安全性全部来源。
//! import = 白名单 + bogon + AS 环路 + max-prefix；export = stub（只 announce 自家前缀）。

#[cfg(test)]
mod tests;

use landscape_rill_core::route::Prefix;

use crate::rib::BgpPath;

/// 默认 bogon 表（保留/不可路由空间）。
/// 注意：10/8、172.16/12、fc00::/7 **不在**默认表——dn42 合法使用这些空间
/// （10/8 = Free Range Cloud/ChaosVPN、172.20/14 ⊆ 172.16/12、fd00::/8 ⊆ fc00::/7）。
pub fn default_bogons() -> Vec<Prefix> {
    [
        "0.0.0.0/8",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "192.168.0.0/16",
        "100.64.0.0/10",
        "224.0.0.0/4",
        "240.0.0.0/4",
    ]
    .iter()
    .filter_map(|c| Prefix::parse(c).ok())
    .chain(
        [
            "::/128",
            "::1/128",
            "fe80::/10",
            "ff00::/8",
            "2001:db8::/32",
        ]
        .iter()
        .filter_map(|c| Prefix::parse(c).ok()),
    )
    .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, landscape_rill_macro::ErrorId)]
pub enum ImportReject {
    #[error("prefix {0} not covered by whitelist")]
    #[error_id("dn42.policy.not_in_whitelist")]
    NotInWhitelist(String),
    #[error("prefix {0} is bogon")]
    #[error_id("dn42.policy.bogon")]
    Bogon(String),
    #[error("AS path contains own AS {0}")]
    #[error_id("dn42.policy.as_loop")]
    AsLoop(u32),
    #[error("missing next hop")]
    #[error_id("dn42.policy.missing_next_hop")]
    MissingNextHop,
    #[error("max-prefix limit {0} reached")]
    #[error_id("dn42.policy.max_prefix")]
    MaxPrefixes(u32),
}

#[derive(Debug, Clone)]
pub struct ImportPolicy {
    /// 白名单：公告前缀必须被某条白名单前缀覆盖（covered-by，与 CONTROL_PLANE §3.8 同语义）。
    /// 空 = 拒绝一切（fail-closed）。
    whitelist: Vec<Prefix>,
    bogons: Vec<Prefix>,
    own_as: u32,
    /// 会话级前缀数上限（None = 不限；DN42_LEG §4）
    max_prefixes: Option<u32>,
    accepted: u32,
}

impl ImportPolicy {
    pub fn new(
        whitelist: Vec<Prefix>,
        bogons: Option<Vec<Prefix>>,
        own_as: u32,
        max_prefixes: Option<u32>,
    ) -> Self {
        Self {
            whitelist,
            bogons: bogons.unwrap_or_else(default_bogons),
            own_as,
            max_prefixes,
            accepted: 0,
        }
    }

    /// 学到一条路由（已过 admit）——max-prefix 计数 +1
    pub fn note_accepted(&mut self) -> Result<(), ImportReject> {
        if let Some(max) = self.max_prefixes {
            if self.accepted >= max {
                return Err(ImportReject::MaxPrefixes(max));
            }
        }
        self.accepted += 1;
        Ok(())
    }

    /// 撤销一条路由——计数 -1
    pub fn note_withdrawn(&mut self) {
        self.accepted = self.accepted.saturating_sub(1);
    }

    pub fn accepted_count(&self) -> u32 {
        self.accepted
    }

    /// 是否超限（会话层据此触发 Cease/Max-Prefixes 关会话）
    pub fn over_limit(&self) -> bool {
        matches!(self.max_prefixes, Some(max) if self.accepted > max)
    }

    /// 无状态四查：next hop 存在 → bogon → 白名单 → AS 环路
    pub fn admit(&self, prefix: &Prefix, path: &BgpPath) -> Result<(), ImportReject> {
        if path.next_hop.is_none() {
            return Err(ImportReject::MissingNextHop);
        }
        for b in &self.bogons {
            if prefix.is_covered_by(b) {
                return Err(ImportReject::Bogon(prefix.to_cidr()));
            }
        }
        if !self.whitelist.iter().any(|w| prefix.is_covered_by(w)) {
            return Err(ImportReject::NotInWhitelist(prefix.to_cidr()));
        }
        if path.as_path.contains(&self.own_as) {
            return Err(ImportReject::AsLoop(self.own_as));
        }
        Ok(())
    }
}

/// export policy v1 = stub：只 announce 配置的自家前缀，不重公告学到的路由（DN42_LEG §4.1）
#[derive(Debug, Clone, Default)]
pub struct ExportPolicy {
    pub own_prefixes: Vec<Prefix>,
}

impl ExportPolicy {
    pub fn new(own_prefixes: Vec<Prefix>) -> Self {
        Self { own_prefixes }
    }
}
