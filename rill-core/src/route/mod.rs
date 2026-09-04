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

/// 存储即规范形态：len 位之外全零（含 v4 第 4 字节之后），由 [`Prefix::new`] 保证
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prefix {
    bits: [u8; 16],
    len: u8,
    /// 地址族：true = IPv4。IPv6 短前缀（len ≤ 32）与 IPv4 靠此标志区分
    v4: bool,
}

impl Prefix {
    /// 唯一构造入口：校验家族长度上限，u128 移位归零尾位（无 byte 级掩码算术）
    pub fn new(bits: [u8; 16], len: u8, v4: bool) -> Option<Self> {
        if len > if v4 { 32 } else { 128 } {
            return None;
        }
        if len == 0 {
            return Some(Self {
                bits: [0; 16],
                len,
                v4,
            });
        }
        let shift = 128 - u32::from(len);
        let significant = u128::from_be_bytes(bits) >> shift;
        Some(Self {
            bits: (significant << shift).to_be_bytes(),
            len,
            v4,
        })
    }

    pub fn from_ip(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(v4) => {
                let mut bits = [0u8; 16];
                bits[..4].copy_from_slice(&v4.octets());
                Self::new(bits, 32, true).expect("v4 /32 恒合法")
            }
            IpAddr::V6(v6) => Self::new(v6.octets(), 128, false).expect("v6 /128 恒合法"),
        }
    }

    /// 前缀长度（非集合长度，is_empty 无意义）
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> u8 {
        self.len
    }

    pub fn is_v4(&self) -> bool {
        self.v4
    }

    pub fn bits(&self) -> &[u8; 16] {
        &self.bits
    }

    pub fn parse(cidr: &str) -> Result<Self, PrefixError> {
        let (addr, len) = cidr.split_once('/').ok_or(PrefixError::BadCidr)?;
        let len: u8 = len.parse().map_err(|_| PrefixError::BadCidr)?;
        let ip: IpAddr = addr.parse().map_err(|_| PrefixError::BadCidr)?;
        let mut bits = [0u8; 16];
        match ip {
            IpAddr::V4(v4) => bits[..4].copy_from_slice(&v4.octets()),
            IpAddr::V6(v6) => bits.copy_from_slice(&v6.octets()),
        }
        Self::new(bits, len, ip.is_ipv4()).ok_or(PrefixError::BadCidr)
    }

    pub fn matches(&self, addr: &IpAddr) -> bool {
        self.contains(&Self::from_ip(*addr))
    }

    /// 前缀有效位（高 self.len 位，低位对齐到 128 位尾）。len==0 → 0
    fn significant(&self) -> u128 {
        if self.len == 0 {
            return 0;
        }
        u128::from_be_bytes(self.bits) >> (128 - self.len as u32)
    }

    /// self 精确包含 other（同地址族、other.len ≥ self.len、有效位一致）。
    /// u128 移位实现：无逐字节/偏字节掩码算术（掩码取反位错的根除手段）
    fn contains(&self, other: &Prefix) -> bool {
        if self.v4 != other.v4 || other.len < self.len {
            return false;
        }
        // 把 other 的有效位右移对齐到 self 的长度再比较
        (other.significant() >> (other.len - self.len)) == self.significant()
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
    /// self ⊆ other（self 被 other 覆盖）。跨地址族一律 false
    pub fn is_covered_by(&self, other: &Prefix) -> bool {
        other.contains(self)
    }
}

pub mod error;
pub use error::PrefixError;

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

    /// 移除 dn42 peer 的单条路由（BGP WITHDRAW，DN42_LEG §5）
    pub fn remove_dn42_route(&mut self, prefix: &Prefix, peer: &str) -> bool {
        self.table
            .remove(prefix, RouteSource::Dn42, &RouteVia::Dn42(peer.to_string()))
    }

    /// 移除 dn42 peer 的全部路由（会话撤销，DN42_LEG §5）
    pub fn remove_dn42_peer(&mut self, peer: &str) {
        let via = RouteVia::Dn42(peer.to_string());
        self.table
            .remove_where(|e| e.source == RouteSource::Dn42 && e.via == via);
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
        assert_eq!(p.len(), 24);
        assert_eq!(p.bits()[..4], [10, 0, 0, 0]);
        let p = Prefix::parse("fd00::/8").unwrap();
        assert_eq!(p.len(), 8);
        assert_eq!(p.bits()[0], 0xfd);
        assert!(Prefix::parse("bad").is_err());
        assert!(Prefix::parse("10.0.0.0/33").is_err());
    }

    /// 唯一构造入口的守卫语义：家族长度上限 fail-closed、尾位/家族外字节归零
    #[test]
    fn new_validates_and_canonicalizes() {
        assert!(Prefix::new([0xff; 16], 33, true).is_none());
        assert!(Prefix::new([0xff; 16], 129, false).is_none());
        assert!(Prefix::new([0xff; 16], 32, true).is_some());
        assert!(Prefix::new([0xff; 16], 128, false).is_some());
        // 脏尾位 + v4 第 4 字节之后的脏字节，一律归零
        assert_eq!(
            Prefix::new([0xff; 16], 24, true).unwrap(),
            Prefix::parse("255.255.255.0/24").unwrap()
        );
        assert_eq!(
            Prefix::new([0xff; 16], 48, false).unwrap(),
            Prefix::parse("ffff:ffff:ffff::/48").unwrap()
        );
        assert_eq!(
            Prefix::new([0xff; 16], 0, true).unwrap(),
            Prefix::parse("0.0.0.0/0").unwrap()
        );
        // 规范形态可往返：parse("172.20.0.0/14") 对脏输入构造等价
        let mut raw = [0u8; 16];
        raw[..4].copy_from_slice(&[172, 20, 255, 255]);
        assert_eq!(
            Prefix::new(raw, 14, true).unwrap(),
            Prefix::parse("172.20.0.0/14").unwrap()
        );
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

    /// 独立参照性质测试：用整除构造块边界（测试自身不含位掩码逻辑），
    /// 对每个长度验证 首✓ / 末✓ / 块前✗ / 块后✗。u128 掩码实现的根除性守卫。
    #[test]
    fn contains_matches_arithmetic_block_reference_v4() {
        use std::net::Ipv4Addr;
        let base: u32 = 0xAC140000; // 172.20.0.0
        for len in 0..=32u32 {
            let block: u64 = if len == 0 {
                u64::from(u32::MAX) + 1
            } else {
                1u64 << (32 - len)
            };
            let net = (base as u64) / block * block;
            let p = Prefix::parse(&format!(
                "{}.{}.{}.{}/{len}",
                net >> 24 & 0xff,
                net >> 16 & 0xff,
                net >> 8 & 0xff,
                net & 0xff
            ))
            .unwrap();
            let ip = |v: u64| IpAddr::V4(Ipv4Addr::from(v as u32));
            assert!(p.matches(&ip(net)), "len {len}: 网络地址应匹配");
            assert!(p.matches(&ip(net + block - 1)), "len {len}: 块末地址应匹配");
            if net > 0 {
                assert!(!p.matches(&ip(net - 1)), "len {len}: 块前地址不应匹配");
            }
            if net + block <= u64::from(u32::MAX) {
                assert!(!p.matches(&ip(net + block)), "len {len}: 块后地址不应匹配");
            }
        }
    }

    #[test]
    fn contains_matches_arithmetic_block_reference_v6() {
        use std::net::Ipv6Addr;
        let base: u128 = 0xFD00_0000_0000_0000_0000_0000_0000_0000; // fd00::/8 锚点
        for len in [8u32, 16, 24, 32, 48, 64, 96, 128] {
            let block: u128 = if len == 0 {
                return;
            } else {
                1u128 << (128 - len)
            };
            let net = base / block * block;
            let p = Prefix::parse(&format!("fd00::/{len}")).unwrap();
            let ip = |v: u128| IpAddr::V6(Ipv6Addr::from(v));
            assert!(p.matches(&ip(net)), "len {len}: 网络地址应匹配");
            assert!(p.matches(&ip(net + block - 1)), "len {len}: 块末地址应匹配");
            if net > 0 {
                assert!(!p.matches(&ip(net - 1)), "len {len}: 块前地址不应匹配");
            }
            assert!(!p.matches(&ip(net + block)), "len {len}: 块后地址不应匹配");
        }
    }

    #[test]
    fn non_byte_aligned_prefix_lengths() {
        // /14 聚合（dn42 白名单，172.20.0.0/14 = 172.20-172.23）
        let agg = Prefix::parse("172.20.0.0/14").unwrap();
        for cidr in [
            "172.20.1.55",
            "172.21.250.9",
            "172.22.142.7",
            "172.23.255.255",
        ] {
            let ip: IpAddr = cidr.parse().unwrap();
            assert!(agg.matches(&ip), "agg {agg:?} 应匹配 {cidr}");
        }
        for cidr in ["172.19.255.255", "172.24.0.1"] {
            let ip: IpAddr = cidr.parse().unwrap();
            assert!(!agg.matches(&ip), "agg {agg:?} 不应匹配 {cidr}");
        }
        // covered-by 同语义
        let p = Prefix::parse("172.22.142.0/24").unwrap();
        assert!(p.is_covered_by(&agg));
        assert!(!Prefix::parse("172.24.0.0/24").unwrap().is_covered_by(&agg));
        // /10（第二字节高 2 位）
        let p10 = Prefix::parse("172.128.0.0/10").unwrap();
        let ip: IpAddr = "172.191.255.1".parse().unwrap();
        assert!(p10.matches(&ip));
        let ip: IpAddr = "172.192.0.1".parse().unwrap();
        assert!(!p10.matches(&ip));
    }

    #[test]
    fn remove_dn42_routes() {
        let mut engine = RouteEngine::new();
        let dn42 = |cidr: &str, peer: &str| RouteEntry {
            prefix: Prefix::parse(cidr).unwrap(),
            source: RouteSource::Dn42,
            via: RouteVia::Dn42(peer.into()),
            metric: None,
        };
        engine.insert(dn42("172.20.1.0/24", "peer-a"));
        engine.insert(dn42("fd00:100::/48", "peer-a"));
        engine.insert(dn42("172.20.2.0/24", "peer-b"));
        let ip: IpAddr = "172.20.1.5".parse().unwrap();
        assert_eq!(engine.lookup(&ip).len(), 1);
        // 单条撤销
        assert!(engine.remove_dn42_route(&Prefix::parse("172.20.1.0/24").unwrap(), "peer-a"));
        assert!(!engine.remove_dn42_route(&Prefix::parse("172.20.1.0/24").unwrap(), "peer-a"));
        assert_eq!(engine.lookup(&ip), vec![]);
        // 会话撤销：peer-a 余下全部移除，peer-b 不受影响
        engine.remove_dn42_peer("peer-a");
        let ip6: IpAddr = "fd00:100::1".parse().unwrap();
        assert_eq!(engine.lookup(&ip6), vec![]);
        assert_eq!(engine.lookup(&"172.20.2.5".parse().unwrap()).len(), 1);
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
