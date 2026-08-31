use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RouteSource {
    Lan,
    Mesh,
    Dn42,
    Tailnet,
}

impl RouteSource {
    pub fn priority(self) -> u8 {
        match self {
            RouteSource::Lan => 0,
            RouteSource::Mesh => 1,
            RouteSource::Dn42 => 2,
            RouteSource::Tailnet => 3,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteVia {
    Mesh(u32),
    Dn42(String),
    Tailnet(String),
    Direct(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteEntry {
    pub prefix: Prefix,
    pub source: RouteSource,
    pub via: RouteVia,
    pub metric: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prefix {
    pub bits: [u8; 16],
    pub len: u8,
    /// 地址族：true = IPv4。IPv6 短前缀（len ≤ 32）与 IPv4 靠此标志区分
    pub v4: bool,
}

impl Prefix {
    pub fn new(bits: [u8; 16], len: u8) -> Self {
        Self {
            bits,
            len,
            v4: len <= 32,
        }
    }

    pub fn from_ip(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(v4) => {
                let mut bits = [0u8; 16];
                bits[..4].copy_from_slice(&v4.octets());
                Self {
                    bits,
                    len: 32,
                    v4: true,
                }
            }
            IpAddr::V6(v6) => Self {
                bits: v6.octets(),
                len: 128,
                v4: false,
            },
        }
    }

    pub fn parse(cidr: &str) -> Result<Self, PrefixError> {
        let (addr, len) = cidr.split_once('/').ok_or(PrefixError::BadCidr)?;
        let len: u8 = len.parse().map_err(|_| PrefixError::BadCidr)?;
        let ip: IpAddr = addr.parse().map_err(|_| PrefixError::BadCidr)?;
        let max_len = if ip.is_ipv4() { 32 } else { 128 };
        if len > max_len {
            return Err(PrefixError::BadCidr);
        }
        let mut bits = [0u8; 16];
        match ip {
            IpAddr::V4(v4) => bits[..4].copy_from_slice(&v4.octets()),
            IpAddr::V6(v6) => bits.copy_from_slice(&v6.octets()),
        }
        let mask = mask_bits(len);
        for (b, m) in bits.iter_mut().zip(mask.iter()) {
            *b &= *m;
        }
        Ok(Self {
            bits,
            len,
            v4: matches!(ip, IpAddr::V4(_)),
        })
    }

    pub fn matches(&self, addr: &IpAddr) -> bool {
        let other = Self::from_ip(*addr);
        if self.len == 0 {
            return true;
        }
        let bytes = (self.len as usize).div_ceil(8);
        for i in 0..bytes {
            if i == bytes - 1 {
                let rem = self.len as usize % 8;
                if rem != 0 {
                    let mask = !(0xffu8 << rem);
                    if self.bits[i] & mask != other.bits[i] & mask {
                        return false;
                    }
                    continue;
                }
            }
            if self.bits[i] != other.bits[i] {
                return false;
            }
        }
        true
    }

    pub fn to_cidr(&self) -> String {
        if self.v4 {
            let ip =
                std::net::Ipv4Addr::new(self.bits[0], self.bits[1], self.bits[2], self.bits[3]);
            format!("{}/{}", ip, self.len)
        } else {
            let ip = std::net::Ipv6Addr::from(self.bits);
            format!("{}/{}", ip, self.len)
        }
    }

    /// self ⊆ other（self 被 other 覆盖）：self 范围不得超出 other。
    /// 白名单校验用：公告前缀必须被某条白名单前缀覆盖（CONTROL_PLANE §3.8）。
    pub fn is_covered_by(&self, other: &Prefix) -> bool {
        if other.len > self.len {
            return false;
        }
        let bytes = (other.len as usize).div_ceil(8);
        for i in 0..bytes {
            if i == bytes - 1 {
                let rem = other.len as usize % 8;
                if rem != 0 {
                    let mask = !(0xffu8 << rem);
                    if (self.bits[i] ^ other.bits[i]) & mask != 0 {
                        return false;
                    }
                    continue;
                }
            }
            if self.bits[i] != other.bits[i] {
                return false;
            }
        }
        true
    }
}

fn mask_bits(len: u8) -> [u8; 16] {
    let mut mask = [0u8; 16];
    let full = len as usize / 8;
    let rem = len as usize % 8;
    for m in mask.iter_mut().take(full) {
        *m = 0xff;
    }
    if rem != 0 {
        mask[full] = 0xff << (8 - rem);
    }
    mask
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefixError {
    BadCidr,
}

#[derive(Debug, Default)]
pub struct LpmTable {
    entries: Vec<RouteEntry>,
}

impl LpmTable {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn insert(&mut self, entry: RouteEntry) {
        self.entries.push(entry);
    }

    pub fn remove(&mut self, prefix: &Prefix, source: RouteSource, via: &RouteVia) -> bool {
        let before = self.entries.len();
        self.entries
            .retain(|e| !(e.prefix == *prefix && e.source == source && &e.via == via));
        self.entries.len() != before
    }

    pub fn remove_where(&mut self, pred: impl Fn(&RouteEntry) -> bool) {
        self.entries.retain(|e| !pred(e));
    }

    pub fn matches(&self, addr: &IpAddr) -> Vec<&RouteEntry> {
        let mut matched: Vec<&RouteEntry> = self
            .entries
            .iter()
            .filter(|e| e.prefix.matches(addr))
            .collect();
        matched.sort_by_key(|e| e.prefix.len);
        matched
    }
}

pub struct RouteEngine {
    table: LpmTable,
}

impl Default for RouteEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl RouteEngine {
    pub fn new() -> Self {
        Self {
            table: LpmTable::new(),
        }
    }

    pub fn table(&self) -> &LpmTable {
        &self.table
    }

    pub fn insert(&mut self, entry: RouteEntry) {
        self.table.insert(entry);
    }

    pub fn lookup(&self, addr: &IpAddr) -> Vec<(&RouteEntry, u8)> {
        let mut candidates: Vec<(&RouteEntry, u8)> = self
            .table
            .matches(addr)
            .into_iter()
            .map(|e| (e, e.source.priority()))
            .collect();
        candidates.sort_by_key(|(e, p)| (std::cmp::Reverse(e.prefix.len), *p));
        candidates
    }

    pub fn lookup_best(
        &self,
        addr: &IpAddr,
        reachable: &dyn Fn(&RouteEntry) -> bool,
    ) -> Option<&RouteEntry> {
        self.lookup(addr)
            .into_iter()
            .map(|(entry, _)| entry)
            .find(|entry| reachable(entry))
    }

    /// 移除某 rill 节点的全部路由（吊销/netmap 消失）
    pub fn remove_mesh_node(&mut self, node_id: u32) {
        self.table
            .remove_where(|e| e.source == RouteSource::Mesh && e.via == RouteVia::Mesh(node_id));
    }

    /// 重建 mesh 来源路由（netmap 全量替换语义）
    pub fn reset_mesh_routes(&mut self) {
        self.table.remove_where(|e| e.source == RouteSource::Mesh);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mesh_via(id: u32) -> RouteVia {
        RouteVia::Mesh(id)
    }

    fn mesh_route(cidr: &str, via: u32) -> RouteEntry {
        RouteEntry {
            prefix: Prefix::parse(cidr).unwrap(),
            source: RouteSource::Mesh,
            via: mesh_via(via),
            metric: None,
        }
    }

    #[test]
    fn parse_cidr_v4_v6() {
        let p = Prefix::parse("10.0.0.0/24").unwrap();
        assert_eq!(p.len, 24);
        assert_eq!(p.bits[..4], [10, 0, 0, 0]);
        let p = Prefix::parse("fd00::/8").unwrap();
        assert_eq!(p.len, 8);
        assert_eq!(p.bits[0], 0xfd);
        assert!(Prefix::parse("bad").is_err());
        assert!(Prefix::parse("10.0.0.0/33").is_err());
    }

    #[test]
    fn prefix_matches() {
        let p = Prefix::parse("10.1.0.0/16").unwrap();
        let ip: IpAddr = "10.1.2.3".parse().unwrap();
        assert!(p.matches(&ip));
        let ip: IpAddr = "10.2.2.3".parse().unwrap();
        assert!(!p.matches(&ip));
        let p = Prefix::parse("0.0.0.0/0").unwrap();
        assert!(p.matches(&ip));
        let p = Prefix::parse("fd00::/8").unwrap();
        let ip: IpAddr = "fd12:3456::1".parse().unwrap();
        assert!(p.matches(&ip));
        let ip: IpAddr = "fe80::1".parse().unwrap();
        assert!(!p.matches(&ip));
        let p = Prefix::parse("2001:db8:1::/48").unwrap();
        let ip: IpAddr = "2001:db8:1:2::3".parse().unwrap();
        assert!(p.matches(&ip));
        let ip: IpAddr = "2001:db8:2::3".parse().unwrap();
        assert!(!p.matches(&ip));
    }

    #[test]
    fn longest_prefix_wins() {
        let mut engine = RouteEngine::new();
        engine.insert(mesh_route("10.0.0.0/8", 1));
        engine.insert(mesh_route("10.1.0.0/16", 2));
        let ip: IpAddr = "10.1.2.3".parse().unwrap();
        let best = engine.lookup_best(&ip, &|_| true).unwrap();
        assert_eq!(best.prefix.to_cidr(), "10.1.0.0/16");
        assert_eq!(best.via, mesh_via(2));
        let ip: IpAddr = "10.9.9.9".parse().unwrap();
        let best = engine.lookup_best(&ip, &|_| true).unwrap();
        assert_eq!(best.prefix.to_cidr(), "10.0.0.0/8");
    }

    #[test]
    fn source_priority_resolves_equal_length() {
        let mut engine = RouteEngine::new();
        let dn42 = RouteEntry {
            prefix: Prefix::parse("172.20.0.0/16").unwrap(),
            source: RouteSource::Dn42,
            via: RouteVia::Dn42("peer-a".into()),
            metric: None,
        };
        let lan = RouteEntry {
            prefix: Prefix::parse("172.20.0.0/16").unwrap(),
            source: RouteSource::Lan,
            via: RouteVia::Direct("eth0".into()),
            metric: None,
        };
        engine.insert(dn42);
        engine.insert(lan);
        let ip: IpAddr = "172.20.1.1".parse().unwrap();
        let best = engine.lookup_best(&ip, &|_| true).unwrap();
        assert_eq!(best.source, RouteSource::Lan);
    }

    #[test]
    fn same_source_multiple_via_all_returned() {
        let mut engine = RouteEngine::new();
        engine.insert(mesh_route("10.0.0.0/24", 1));
        engine.insert(mesh_route("10.0.0.0/24", 2));
        engine.insert(mesh_route("10.0.0.0/24", 3));
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let candidates = engine.lookup(&ip);
        assert_eq!(candidates.len(), 3);
        let best = engine.lookup_best(&ip, &|_| true).unwrap();
        assert_eq!(best.via, mesh_via(1));
    }

    #[test]
    fn fallback_chain_on_unreachable() {
        let mut engine = RouteEngine::new();
        engine.insert(mesh_route("10.0.0.0/24", 1));
        engine.insert(mesh_route("10.0.0.0/24", 2));
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let best = engine.lookup_best(&ip, &|e| match &e.via {
            RouteVia::Mesh(id) => *id == 2,
            _ => false,
        });
        assert_eq!(best.unwrap().via, mesh_via(2));
        assert_eq!(engine.lookup_best(&ip, &|_| false), None);
    }

    #[test]
    fn policy_checkpoint_allow_all_v1() {
        let mut engine = RouteEngine::new();
        engine.insert(mesh_route("10.0.0.0/24", 1));
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let policy = |_: &IpAddr, _: &RouteEntry| true;
        let best = engine
            .lookup(&ip)
            .into_iter()
            .find(|(e, _)| policy(&ip, e))
            .map(|(e, _)| e);
        assert!(best.is_some());
    }

    #[test]
    fn remove_route() {
        let mut engine = RouteEngine::new();
        engine.insert(mesh_route("10.0.0.0/24", 1));
        let p = Prefix::parse("10.0.0.0/24").unwrap();
        assert!(engine.table.remove(&p, RouteSource::Mesh, &mesh_via(1)));
        assert!(!engine.table.remove(&p, RouteSource::Mesh, &mesh_via(1)));
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(engine.lookup(&ip), vec![]);
    }

    #[test]
    fn default_route_via_wan() {
        let mut engine = RouteEngine::new();
        let wan = RouteEntry {
            prefix: Prefix::parse("0.0.0.0/0").unwrap(),
            source: RouteSource::Lan,
            via: RouteVia::Direct("wan".into()),
            metric: None,
        };
        let tailnet = RouteEntry {
            prefix: Prefix::parse("0.0.0.0/0").unwrap(),
            source: RouteSource::Tailnet,
            via: RouteVia::Tailnet("exit-1".into()),
            metric: None,
        };
        engine.insert(tailnet);
        engine.insert(wan);
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let best = engine.lookup_best(&ip, &|_| true).unwrap();
        assert_eq!(best.source, RouteSource::Lan);
        let via_exit = engine.lookup_best(&ip, &|e| e.source != RouteSource::Lan);
        assert_eq!(via_exit.unwrap().source, RouteSource::Tailnet);
    }
}
