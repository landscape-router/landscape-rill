//! ImportPolicy / ExportPolicy 测试：import 四查、max-prefix 会话级计数。

use std::net::IpAddr;

use super::*;
use crate::policy::{default_bogons, ExportPolicy, ImportPolicy};
use crate::rib::BgpPath;
use landscape_rill_core::route::Prefix;

fn p(cidr: &str) -> Prefix {
    Prefix::parse(cidr).unwrap()
}

fn wl() -> Vec<Prefix> {
    vec![p("172.20.0.0/14"), p("fd00::/8")]
}

fn path_v4(octets: [u8; 4]) -> BgpPath {
    BgpPath {
        as_path: vec![65001],
        next_hop: Some(IpAddr::from(octets)),
        origin: 0,
        communities: vec![],
    }
}

#[test]
fn admit_whitelist_bogon_loop_next_hop() {
    let policy = ImportPolicy::new(wl(), None, 4242420001, None);
    let ok = path_v4([172, 20, 100, 2]);
    assert_eq!(policy.admit(&p("172.20.100.0/24"), &ok), Ok(()));
    // 白名单外
    assert_eq!(
        policy.admit(&p("10.99.0.0/16"), &ok),
        Err(ImportReject::NotInWhitelist("10.99.0.0/16".into()))
    );
    // bogon：100.64/10（tailnet 空间）即使被白名单覆盖也先拒
    assert_eq!(
        policy.admit(&p("100.64.1.0/24"), &ok),
        Err(ImportReject::Bogon("100.64.1.0/24".into()))
    );
    assert!(matches!(
        policy.admit(&p("fe80::/10"), &ok),
        Err(ImportReject::Bogon(_))
    ));
    // AS 环路：path 含自身 ASN
    let looped = BgpPath {
        as_path: vec![4242420001, 65001],
        next_hop: Some(IpAddr::from([172, 20, 100, 2])),
        origin: 0,
        communities: vec![],
    };
    assert_eq!(
        policy.admit(&p("172.20.100.0/24"), &looped),
        Err(ImportReject::AsLoop(4242420001))
    );
    // 缺 next hop
    let no_nh = BgpPath {
        as_path: vec![65001],
        next_hop: None,
        origin: 0,
        communities: vec![],
    };
    assert_eq!(
        policy.admit(&p("172.20.100.0/24"), &no_nh),
        Err(ImportReject::MissingNextHop)
    );
    // 空白名单 = 拒绝一切（fail-closed）
    let none = ImportPolicy::new(vec![], None, 4242420001, None);
    assert!(none.admit(&p("172.20.100.0/24"), &ok).is_err());
}

#[test]
fn default_bogons_keep_dn42_space() {
    let bogons = default_bogons();
    // dn42 合法使用的空间不在默认 bogon 表
    assert!(!bogons.iter().any(|b| p("10.0.0.0/8").is_covered_by(b)));
    assert!(!bogons.iter().any(|b| p("172.20.0.0/14").is_covered_by(b)));
    assert!(!bogons.iter().any(|b| p("fd00::/8").is_covered_by(b)));
    // 保留空间在
    assert!(bogons.iter().any(|b| p("127.0.0.1/32").is_covered_by(b)));
    assert!(bogons.iter().any(|b| p("192.168.1.0/24").is_covered_by(b)));
    assert!(bogons.iter().any(|b| p("2001:db8:1::/48").is_covered_by(b)));
}

#[test]
fn max_prefix_counter_and_overflow() {
    let mut policy = ImportPolicy::new(wl(), None, 4242420001, Some(2));
    policy.note_accepted().unwrap();
    policy.note_accepted().unwrap();
    assert_eq!(policy.accepted_count(), 2);
    assert_eq!(policy.note_accepted(), Err(ImportReject::MaxPrefixes(2)));
    assert!(!policy.over_limit());
    policy.note_withdrawn();
    assert_eq!(policy.accepted_count(), 1);
    assert!(policy.note_accepted().is_ok());
}

#[test]
fn export_stub_only_own_prefixes() {
    let export = ExportPolicy::new(vec![p("172.20.100.0/24")]);
    assert_eq!(export.own_prefixes.len(), 1);
    // stub 语义：export 集合是静态配置，不存在"学习后重公告"路径（编译期即无此 API）
}
