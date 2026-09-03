//! LocRib 测试：学习/撤销、best-path 切换与回落、purge、max-prefix 溢出标志。

use std::net::IpAddr;

use super::*;
use crate::policy::ImportPolicy;
use crate::wire::{PathAttr, Segment, UpdateMsg, AFI_IPV6, SAFI_UNICAST};
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

fn update_v4(prefixes: Vec<Prefix>, as_seq: Vec<u32>, nh: [u8; 4]) -> UpdateMsg {
    UpdateMsg {
        withdrawn: vec![],
        attrs: vec![
            PathAttr::Origin(0),
            PathAttr::AsPath(vec![Segment {
                set: false,
                asns: as_seq,
            }]),
            PathAttr::NextHop(nh.into()),
        ],
        announced: prefixes,
    }
}

fn mp_reach_v6(prefixes: Vec<Prefix>, nh: IpAddr) -> UpdateMsg {
    UpdateMsg {
        withdrawn: vec![],
        attrs: vec![
            PathAttr::Origin(0),
            PathAttr::AsPath(vec![Segment {
                set: false,
                asns: vec![65001],
            }]),
            PathAttr::MpReach {
                afi: AFI_IPV6,
                safi: SAFI_UNICAST,
                next_hop: nh,
                nlri: prefixes,
            },
        ],
        announced: vec![],
    }
}

fn rib_policy() -> ImportPolicy {
    ImportPolicy::new(wl(), None, 4242420001, None)
}

#[test]
fn learn_v4_and_v6_then_withdraw() {
    let mut rib = LocRib::new();
    let mut policy = rib_policy();
    let out = rib.apply(
        "peer-r",
        &update_v4(vec![p("172.20.100.0/24")], vec![65001], [172, 20, 100, 2]),
        &mut policy,
    );
    assert!(out.rejected.is_empty() && !out.max_prefix_exceeded);
    assert_eq!(
        out.changes,
        vec![RouteChange::Learned {
            prefix: p("172.20.100.0/24"),
            path: path_v4([172, 20, 100, 2])
        }]
    );

    let out = rib.apply(
        "peer-r",
        &mp_reach_v6(vec![p("fd00:100::/48")], "fd00::1:2".parse().unwrap()),
        &mut policy,
    );
    assert_eq!(out.changes.len(), 1);
    assert!(
        matches!(&out.changes[0], RouteChange::Learned { prefix, .. }
        if *prefix == p("fd00:100::/48"))
    );

    // 撤销：v4 WITHDRAWN + MP_UNREACH 双通道
    let wd = UpdateMsg {
        withdrawn: vec![p("172.20.100.0/24")],
        attrs: vec![PathAttr::MpUnreach {
            afi: AFI_IPV6,
            safi: SAFI_UNICAST,
            nlri: vec![p("fd00:100::/48")],
        }],
        announced: vec![],
    };
    let out = rib.apply("peer-r", &wd, &mut policy);
    assert_eq!(
        out.changes,
        vec![
            RouteChange::Withdrawn(p("172.20.100.0/24")),
            RouteChange::Withdrawn(p("fd00:100::/48"))
        ]
    );
    assert_eq!(rib.accepted_prefixes(), 0);
}

#[test]
fn best_path_shortest_as_path_and_failover() {
    let mut rib = LocRib::new();
    let mut policy = rib_policy();
    // peer-a：AS path 长（2 跳）
    let out = rib.apply(
        "peer-a",
        &update_v4(
            vec![p("172.20.100.0/24")],
            vec![65001, 65002],
            [172, 20, 100, 2],
        ),
        &mut policy,
    );
    assert_eq!(out.changes.len(), 1);
    // peer-r：AS path 短（1 跳）→ best 切换到 peer-r
    let out = rib.apply(
        "peer-r",
        &update_v4(vec![p("172.20.100.0/24")], vec![65001], [172, 20, 200, 2]),
        &mut policy,
    );
    assert_eq!(out.changes.len(), 1);
    assert!(matches!(&out.changes[0], RouteChange::Learned { path, .. }
        if path.next_hop == Some("172.20.200.2".parse().unwrap())));
    // peer-r 撤销 → 回落到 peer-a
    let wd = UpdateMsg {
        withdrawn: vec![p("172.20.100.0/24")],
        attrs: vec![],
        announced: vec![],
    };
    let out = rib.apply("peer-r", &wd, &mut policy);
    assert_eq!(out.changes.len(), 1);
    assert!(matches!(&out.changes[0], RouteChange::Learned { path, .. }
        if path.next_hop == Some("172.20.100.2".parse().unwrap())));
    // peer-a 也撤 → Withdrawn
    let out = rib.apply("peer-a", &wd, &mut policy);
    assert_eq!(
        out.changes,
        vec![RouteChange::Withdrawn(p("172.20.100.0/24"))]
    );
}

#[test]
fn equal_path_length_tie_breaks_by_peer_name() {
    let mut rib = LocRib::new();
    let mut policy = rib_policy();
    // 等长路径：确定性地选 peer 名字典序最小者
    rib.apply(
        "peer-z",
        &update_v4(vec![p("172.20.1.0/24")], vec![65001], [172, 20, 200, 2]),
        &mut policy,
    );
    rib.apply(
        "peer-a",
        &update_v4(vec![p("172.20.1.0/24")], vec![65001], [172, 20, 100, 2]),
        &mut policy,
    );
    // peer-a 后到但字典序小 → best 切换到 peer-a
    assert!(matches!(&rib.best(&p("172.20.1.0/24")).unwrap().next_hop,
        Some(nh) if *nh == "172.20.100.2".parse::<IpAddr>().unwrap()));
}

#[test]
fn as4_path_takes_precedence_over_as_path() {
    let mut rib = LocRib::new();
    let mut policy = rib_policy();
    // AS_PATH 含 AS_TRANS 占位 + AS4_PATH 真实 4B 路径（RFC 6793 典型 dn42 UPDATE）
    let update = UpdateMsg {
        withdrawn: vec![],
        attrs: vec![
            PathAttr::Origin(0),
            PathAttr::AsPath(vec![Segment {
                set: false,
                asns: vec![23456],
            }]),
            PathAttr::As4Path(vec![Segment {
                set: false,
                asns: vec![4242420002],
            }]),
            PathAttr::NextHop([172, 20, 100, 2].into()),
        ],
        announced: vec![p("172.20.100.0/24")],
    };
    let out = rib.apply("peer-r", &update, &mut policy);
    assert!(out.rejected.is_empty());
    // 生效路径 = AS4_PATH（4B 真实 ASN），环路检测针对真实路径
    assert!(
        matches!(&out.changes[0], RouteChange::Learned { path, .. } if path.as_path == vec![4242420002])
    );
}

#[test]
fn purge_peer_removes_all_and_falls_back() {
    let mut rib = LocRib::new();
    let mut policy = rib_policy();
    rib.apply(
        "peer-a",
        &update_v4(
            vec![p("172.20.1.0/24")],
            vec![65001, 65002],
            [172, 20, 1, 2],
        ),
        &mut policy,
    );
    rib.apply(
        "peer-r",
        &update_v4(vec![p("172.20.1.0/24")], vec![65001], [172, 20, 200, 2]),
        &mut policy,
    );
    rib.apply(
        "peer-r",
        &mp_reach_v6(vec![p("fd00:100::/48")], "fd00::1:2".parse().unwrap()),
        &mut policy,
    );
    let mut changes = rib.purge_peer("peer-r", &mut policy);
    // purge 按 HashMap 键序产出，排序保证断言确定性
    changes.sort_by(|a, b| {
        let cidr = |c: &RouteChange| match c {
            RouteChange::Learned { prefix, .. } => prefix.to_cidr(),
            RouteChange::Withdrawn(x) => x.to_cidr(),
        };
        cidr(a).cmp(&cidr(b))
    });
    assert_eq!(changes.len(), 2);
    // 172.20.1.0/24 回落到 peer-a；fd00:100::/48 无备选 → Withdrawn
    assert!(
        matches!(&changes[0], RouteChange::Learned { prefix, .. } if *prefix == p("172.20.1.0/24"))
    );
    assert!(matches!(&changes[1], RouteChange::Withdrawn(x) if *x == p("fd00:100::/48")));
    assert_eq!(rib.accepted_prefixes(), 1);
}

#[test]
fn rejected_routes_are_reported_not_stored() {
    let mut rib = LocRib::new();
    let mut policy = rib_policy();
    // 白名单外 + AS 环路各一条
    let update = UpdateMsg {
        withdrawn: vec![],
        attrs: vec![
            PathAttr::Origin(0),
            PathAttr::AsPath(vec![Segment {
                set: false,
                asns: vec![65001, 4242420001],
            }]),
            PathAttr::NextHop([172, 20, 100, 2].into()),
        ],
        announced: vec![p("10.99.0.0/16"), p("172.20.100.0/24")],
    };
    let out = rib.apply("peer-r", &update, &mut policy);
    assert_eq!(out.rejected.len(), 2);
    assert!(matches!(
        out.rejected[0].1,
        crate::policy::ImportReject::NotInWhitelist(_)
    ));
    assert!(matches!(
        out.rejected[1].1,
        crate::policy::ImportReject::AsLoop(4242420001)
    ));
    assert_eq!(out.changes.len(), 0);
    assert_eq!(rib.accepted_prefixes(), 0);
}

#[test]
fn max_prefix_overflow_flags_session_close() {
    let mut rib = LocRib::new();
    let mut policy = ImportPolicy::new(wl(), None, 4242420001, Some(1));
    rib.apply(
        "peer-r",
        &update_v4(vec![p("172.20.1.0/24")], vec![65001], [172, 20, 100, 2]),
        &mut policy,
    );
    let out = rib.apply(
        "peer-r",
        &update_v4(vec![p("172.20.2.0/24")], vec![65001], [172, 20, 100, 2]),
        &mut policy,
    );
    assert!(out.max_prefix_exceeded);
    assert!(out.changes.is_empty());
}

#[test]
fn reannounce_replaces_path_without_double_count() {
    let mut rib = LocRib::new();
    let mut policy = ImportPolicy::new(wl(), None, 4242420001, Some(1));
    rib.apply(
        "peer-r",
        &update_v4(vec![p("172.20.1.0/24")], vec![65001], [172, 20, 100, 2]),
        &mut policy,
    );
    // 同前缀重公告（next hop 变化）——不超限，best 更新
    let out = rib.apply(
        "peer-r",
        &update_v4(vec![p("172.20.1.0/24")], vec![65001], [172, 20, 100, 9]),
        &mut policy,
    );
    assert!(!out.max_prefix_exceeded);
    assert!(matches!(&out.changes[0], RouteChange::Learned { path, .. }
        if path.next_hop == Some("172.20.100.9".parse().unwrap())));
}
