use super::*;
use crate::authkey::generate_auth_key;
use crate::liveness::LEASE_EXPIRY_SECS;

fn pubkey(seed: u8) -> [u8; 32] {
    [seed; 32]
}

/// lrk 格式 auth key（REQ-043 起注册校验要求可解析 + 未过期）
fn lrk(network: &str, ttl_secs: u64) -> String {
    generate_auth_key(network, ttl_secs).unwrap()
}

/// 单网络 coordinator（默认 lab）
fn setup() -> (Coordinator, String) {
    let ak = lrk("lab", 86_400);
    let mut c = Coordinator::new([0x5a; 32]);
    c.add_network("lab", [0x77; 32]);
    c.add_auth_key(&ak, AuthKeyPolicy::Reusable);
    (c, ak)
}

/// 双网络 coordinator（lab + work，SEC-21~25/CTL-09 用）
fn two_networks() -> (Coordinator, String, String) {
    let ak_a = lrk("lab", 86_400);
    let ak_b = lrk("work", 86_400);
    let mut c = Coordinator::new([0x5a; 32]);
    c.add_network("lab", [0x77; 32]);
    c.add_network("work", [0x88; 32]);
    c.add_auth_key(&ak_a, AuthKeyPolicy::Reusable);
    c.add_auth_key(&ak_b, AuthKeyPolicy::Reusable);
    (c, ak_a, ak_b)
}

fn register_node(c: &mut Coordinator, ak: &str, seed: u8) -> u32 {
    register_node_caps(c, ak, seed, 0x01)
}

fn register_node_caps(c: &mut Coordinator, ak: &str, seed: u8, caps: u32) -> u32 {
    c.register(ak, &pubkey(seed), caps, vec![], 0, (0, 0))
        .unwrap()
        .node_id
}

#[test]
fn register_and_netmap() {
    let (mut c, ak) = setup();
    let v0 = c.netmap_version();
    let id = register_node(&mut c, &ak, 1);
    assert_eq!(id, 1);
    assert_eq!(c.netmap_version(), v0 + 1);
    let nid = c.network_id_of(id).unwrap();
    let snap = c.netmap_snapshot(nid);
    assert_eq!(snap.len(), 1);
    assert_eq!(snap[0].node_id, 1);
    assert_eq!(snap[0].static_pubkey, pubkey(1));
}

#[test]
fn register_idempotent_no_version_bump() {
    let (mut c, ak) = setup();
    let v0 = c.netmap_version();
    register_node(&mut c, &ak, 1);
    let v1 = c.netmap_version();
    assert_eq!(v1, v0 + 1);
    let out = c
        .register(&ak, &pubkey(1), 0x01, vec![], 0, (0, 0))
        .unwrap();
    assert_eq!(out.node_id, 1);
    assert_eq!(c.netmap_version(), v1);
}

/// REQ-062 验收 ③：注册不再自动进 relay 集（能力位只是必要条件）；
/// roster 落位后路径候选才含中继跳
#[test]
fn relay_roster_gates_path_candidates() {
    let (mut c, ak) = setup();
    let relay = c
        .register(&ak, &pubkey(1), 0x01, vec![], 0, (0, 0))
        .unwrap()
        .node_id;
    let src = c
        .register(&ak, &pubkey(2), 0x00, vec![], 0, (0, 0))
        .unwrap()
        .node_id;
    let dst = c
        .register(&ak, &pubkey(3), 0x00, vec![], 0, (0, 0))
        .unwrap()
        .node_id;
    // 未落位 roster：能力位节点不进任何候选路径（无 key_path 签发 = 停用语义）
    let cands = c.request_paths(src, dst, 4, 1_000);
    assert_eq!(cands.len(), 1, "仅 direct（roster 空）");
    // roster 落位（apply 侧入口）→ 中继候选出现
    let nid = c.network_id_of(src).unwrap();
    assert!(c.apply_relay_roster(nid, vec![relay], 1_000));
    let cands = c.request_paths(src, dst, 4, 1_000);
    assert!(cands.iter().any(|(p, _)| p.hops == vec![relay, dst]));
    assert_eq!(cands.len(), 2); // direct + relay

    // roster 清空 → 候选收窄回 direct
    assert!(c.apply_relay_roster(nid, vec![], 1_000));
    let cands = c.request_paths(src, dst, 4, 1_000);
    assert_eq!(cands.len(), 1);
    assert!(cands.iter().all(|(p, _)| !p.hops.contains(&relay)));
}

#[test]
fn key_dist_unknown_node_none() {
    let (c, _ak) = setup();
    assert!(c.key_dist(99).is_none());
}

/// REQ-048：吊销即时语义不变，轮换延后到窗口末一次生效
#[test]
fn revoke_immediate_removal_rotation_deferred() {
    let (mut c, ak) = setup();
    let id = register_node(&mut c, &ak, 1);
    let nid = c.network_id_of(id).unwrap();
    let nv = c.netmap_version();
    let kv = c.key_version_for("lab");
    c.revoke(id, 100, (0, 0));
    assert_eq!(c.netmap_snapshot(nid).len(), 0);
    assert_eq!(c.netmap_version(), nv + 1); // 即时：条目移除
    assert_eq!(c.key_version_for("lab"), kv); // REQ-048：轮换入窗口
    assert!(c.key_dist(id).is_none());
    assert!(!c.flush_revoke_rotations(100 + REVOKE_ROTATION_WINDOW_SECS - 1));
    assert_eq!(c.key_version_for("lab"), kv);
    assert!(c.flush_revoke_rotations(100 + REVOKE_ROTATION_WINDOW_SECS));
    assert_eq!(c.key_version_for("lab"), kv + 1);
    assert!(!c.flush_revoke_rotations(1000), "清窗后幂等");
    assert_eq!(c.key_version_for("lab"), kv + 1);
}

/// REQ-048：窗口内 N 次吊销共享一次轮换
#[test]
fn revoke_batch_shares_single_rotation() {
    let (mut c, ak) = setup();
    let a = register_node(&mut c, &ak, 1);
    let b = register_node(&mut c, &ak, 2);
    let d = register_node(&mut c, &ak, 3);
    let kv = c.key_version_for("lab");
    c.revoke(a, 100, (0, 0));
    c.revoke(b, 130, (0, 0));
    c.revoke(d, 159, (0, 0));
    assert_eq!(c.key_version_for("lab"), kv);
    assert!(c.flush_revoke_rotations(160));
    assert_eq!(c.key_version_for("lab"), kv + 1, "3 次吊销 → 1 次轮换");
}

/// REQ-048：窗口外的吊销各自触发轮换
#[test]
fn revoke_outside_window_rotates_separately() {
    let (mut c, ak) = setup();
    let a = register_node(&mut c, &ak, 1);
    let b = register_node(&mut c, &ak, 2);
    let kv = c.key_version_for("lab");
    c.revoke(a, 100, (0, 0));
    assert!(c.flush_revoke_rotations(100 + REVOKE_ROTATION_WINDOW_SECS));
    c.revoke(b, 200, (0, 0));
    assert_eq!(c.key_version_for("lab"), kv + 1);
    assert!(c.flush_revoke_rotations(200 + REVOKE_ROTATION_WINDOW_SECS));
    assert_eq!(c.key_version_for("lab"), kv + 2);
}

/// REQ-048：显式 rotate_master_key 不走合并窗口——立即轮换并吸收挂起窗口
#[test]
fn rotate_master_key_bypasses_and_absorbs_window() {
    let (mut c, ak) = setup();
    let id = register_node(&mut c, &ak, 1);
    let kv = c.key_version_for("lab");
    c.revoke(id, 100, (0, 0)); // 挂起窗口
    c.rotate_master_key("lab", [0x99; 32]);
    assert_eq!(c.key_version_for("lab"), kv + 1, "立即生效");
    assert!(!c.flush_revoke_rotations(1000), "挂起窗口被吸收");
    assert_eq!(c.key_version_for("lab"), kv + 1);
}

/// REQ-048：合并窗口 deadline 落盘，重启后到期自愈（下一事件驱动点生效）
#[test]
fn revoke_rotation_window_survives_restore() {
    let ak = lrk("lab", 86_400);
    let path = tmp_db("req048-window");
    {
        let mut c = Coordinator::open(&path, &networks_arg(), [0x5a; 32]).unwrap();
        c.add_auth_key(&ak, AuthKeyPolicy::Reusable);
        let a = c
            .register(&ak, &pubkey(1), 0x01, vec![], 0, (0, 0))
            .unwrap()
            .node_id;
        c.revoke(a, 100, (0, 0));
        drop(c);
    }
    let mut c = Coordinator::open(&path, &networks_arg(), [0x5a; 32]).unwrap();
    assert_eq!(c.key_version_for("lab"), 1, "重启不提前生效");
    assert!(c.flush_revoke_rotations(1000), "deadline 已过 → 到期轮换");
    assert_eq!(c.key_version_for("lab"), 2);
    drop(c);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn rotate_master_key_changes_keys() {
    let (mut c, ak) = setup();
    let id = register_node(&mut c, &ak, 1);
    let before = c.key_dist(id).unwrap();
    c.rotate_master_key("lab", [0x99; 32]);
    let after = c.key_dist(id).unwrap();
    assert_ne!(before.key, after.key);
    assert_eq!(after.key_version, before.key_version + 1);
}

#[test]
fn heartbeat_and_offline_enters_netmap() {
    let (mut c, ak) = setup();
    let id = register_node(&mut c, &ak, 1);
    c.heartbeat(id, 100);
    assert!(c.offline_nodes().is_empty());
    c.mark_offline(id);
    assert_eq!(c.offline_nodes(), &[1]);
    let nid = c.network_id_of(id).unwrap();
    assert!(c.netmap_snapshot(nid)[0].offline);
    assert!(c.heartbeat(id, 200), "恢复转移返回 true");
    assert!(c.offline_nodes().is_empty());
    assert!(!c.netmap_snapshot(nid)[0].offline);
}

/// CTL-11：租约超时 → 离线扫描撤销其公告路由（netmap 版本递增）；
/// 恢复心跳 → 回在线、路由随 netmap 恢复；他人公告不受影响
#[test]
fn offline_sweep_withdraws_routes_and_restores() {
    let (mut c, ak) = setup();
    c.set_announce_whitelist("lab", vec![Prefix::parse("10.0.0.0/8").unwrap()]);
    let a = c
        .register(
            &ak,
            &pubkey(1),
            0x01,
            vec!["10.60.0.0/24".into()],
            0,
            (0, 0),
        )
        .unwrap()
        .node_id;
    let b = c
        .register(
            &ak,
            &pubkey(2),
            0x01,
            vec!["10.61.0.0/24".into()],
            0,
            (0, 0),
        )
        .unwrap()
        .node_id;
    let nid = c.network_id_of(a).unwrap();
    c.heartbeat(a, 100);
    c.heartbeat(b, 101);
    let routes_of = |c: &Coordinator, id: u32| {
        c.netmap_snapshot(nid)
            .into_iter()
            .find(|e| e.node_id == id)
            .unwrap()
    };
    assert!(!routes_of(&c, a).routes.is_empty());

    // b 的下一次心跳触发扫描：a 租约超时 → 离线 + 版本递增 + 路由撤销
    let v1 = c.netmap_version();
    c.heartbeat(b, 100 + LEASE_EXPIRY_SECS + 1);
    assert!(c.netmap_version() > v1, "离线转移递增 netmap 版本");
    let a_entry = routes_of(&c, a);
    assert!(a_entry.offline, "租约超时 → 可达性标记为离线");
    assert_eq!(
        a_entry.routes,
        vec!["10.60.0.0/24".to_string()],
        "快照保持注册表镜像；撤销由节点侧按 offline 标记执行（CTL-11）"
    );
    assert!(!routes_of(&c, b).offline, "他人公告不受影响");

    // a 恢复心跳 → 回在线（版本递增）、路由恢复
    let v2 = c.netmap_version();
    c.heartbeat(a, 100 + LEASE_EXPIRY_SECS + 2);
    assert!(c.netmap_version() > v2, "恢复转移递增 netmap 版本");
    let a_entry = routes_of(&c, a);
    assert!(!a_entry.offline);
    assert_eq!(a_entry.routes, vec!["10.60.0.0/24".to_string()]);
}

/// REQ-070 阶段二：接管重置活性软状态——陈旧 last_seen（旧主时代的本地快照，
/// 未随 raft 日志复制）不会把在线节点立即扫成离线；接管后静默超过一个租约
/// 窗口仍会被 sweep 正常判离线
#[test]
fn takeover_reset_liveness_avoids_stale_offline_sweep() {
    let (mut c, ak) = setup();
    let a = c
        .register(&ak, &pubkey(1), 0x01, vec![], 0, (0, 0))
        .unwrap()
        .node_id;
    let b = c
        .register(&ak, &pubkey(2), 0x01, vec![], 0, (0, 0))
        .unwrap()
        .node_id;
    let nid = c.network_id_of(a).unwrap();
    // 旧主时代心跳只落在旧主本地（t=100 后未再复制到日志）
    c.heartbeat(a, 100);
    c.heartbeat(b, 100);
    // 新主接管（t=1000）→ 全员新租约 + netmap 版本递增
    let v = c.netmap_version();
    c.reset_liveness_on_takeover(1000);
    assert!(c.netmap_version() > v, "接管重置递增 netmap 版本");
    // b 先完成重注册（t=1004）：若沿用陈旧快照，a 会被立即扫成离线
    c.heartbeat(b, 1004);
    assert!(
        c.netmap_snapshot(nid).iter().all(|e| !e.offline),
        "接管租约窗口内不误判离线"
    );
    // 接管后静默超过租约窗口 → sweep 恢复正常判离线
    c.heartbeat(b, 1000 + LEASE_EXPIRY_SECS + 1);
    let a_entry = c
        .netmap_snapshot(nid)
        .into_iter()
        .find(|e| e.node_id == a)
        .unwrap();
    assert!(a_entry.offline, "接管租约耗尽后仍会被判离线");
}

#[test]
fn endpoints_enter_netmap() {
    let (mut c, ak) = setup();
    let id = register_node(&mut c, &ak, 1);
    c.set_endpoints(id, vec!["203.0.113.1:41641".into()], vec![]);
    let nid = c.network_id_of(id).unwrap();
    let snap = c.netmap_snapshot(nid);
    assert_eq!(snap[0].endpoints, vec!["203.0.113.1:41641"]);
}

/// CTL-10（REQ-008）：白名单内公告并入 netmap；白名单外/过短前缀 → RouteNotAllowed（不部分采纳）
#[test]
fn announce_routes_enter_netmap_and_whitelist_gates() {
    let ak = lrk("lab", 86_400);
    let mut c = Coordinator::new([0x5a; 32]);
    c.add_network("lab", [0x77; 32]);
    c.add_auth_key(&ak, AuthKeyPolicy::Reusable);
    c.set_announce_whitelist(
        "lab",
        vec![
            Prefix::parse("10.0.0.0/8").unwrap(),
            Prefix::parse("fd00::/8").unwrap(),
        ],
    );
    // 白名单内公告 → 注册成功 + 进入 netmap
    let id = c
        .register(
            &ak,
            &pubkey(1),
            0x01,
            vec!["10.42.0.0/24".into(), "fd00:2::/64".into()],
            0,
            (0, 0),
        )
        .unwrap()
        .node_id;
    let snap = c.netmap_snapshot(c.network_id_of(id).unwrap());
    assert_eq!(
        snap.iter().find(|n| n.node_id == id).unwrap().routes,
        vec!["10.42.0.0/24", "fd00:2::/64"]
    );
    // 白名单外公告 → 整批拒绝（不部分采纳）
    let err = c.register(
        &ak,
        &pubkey(2),
        0x01,
        vec!["10.42.0.0/24".into(), "172.16.0.0/12".into()],
        0,
        (0, 0),
    );
    assert!(matches!(err, Err(RegisterError::RouteNotAllowed)));
    // 过短前缀（IPv4 < /8）→ 拒绝
    let err = c.register(&ak, &pubkey(3), 0x01, vec!["10.0.0.0/7".into()], 0, (0, 0));
    assert!(matches!(err, Err(RegisterError::RouteNotAllowed)));
    // 空白名单 = fail-closed（拒绝一切公告）
    let mut c2 = Coordinator::new([0x5a; 32]);
    c2.add_network("lab", [0x77; 32]);
    c2.add_auth_key(&ak, AuthKeyPolicy::Reusable);
    let err = c2.register(
        &ak,
        &pubkey(4),
        0x01,
        vec!["10.42.0.0/24".into()],
        0,
        (0, 0),
    );
    assert!(matches!(err, Err(RegisterError::RouteNotAllowed)));
}

/// SEC-28（REQ-020）：acl 能力位 v1 恒 false——注册/转发不做裁决，位原样透传（v1 恒放行）
#[test]
fn capability_acl_bit_reserved_v1() {
    let (mut c, ak) = setup();
    // 保留位 0x40（acl）：策略未启用时 coordinator 不解释、netmap 原样带出
    let id = c
        .register(&ak, &pubkey(7), 0x40, vec![], 0, (0, 0))
        .unwrap()
        .node_id;
    let snap = c.netmap_snapshot(c.network_id_of(id).unwrap());
    assert_eq!(
        snap.iter().find(|n| n.node_id == id).unwrap().capabilities & 0x40,
        0x40
    );
    // 策略检查点恒放行断言在 rill-core/src/route.rs（policy_checkpoint_allow_all_v1）
}

// ==================== ACL v2 策略层（REQ-045，前缀级先行） ====================

fn lab_policy() -> landscape_rill_core::control::acl::AclPolicy {
    use landscape_rill_core::control::acl::*;
    let mut groups = std::collections::HashMap::new();
    groups.insert("admins".to_string(), vec![1]);
    AclPolicy {
        enabled: true,
        rules: vec![AclRule {
            subjects: vec![AclSubject::Group("admins".into()), AclSubject::Node(2)],
            prefix: landscape_rill_core::route::Prefix::parse("10.42.0.0/24").unwrap(),
            action: AclAction::Allow,
        }],
        groups,
    }
}

/// 网络开启 ACL 后，无 acl 能力位的节点注册被拒（fail-closed：防最弱环节绕过裁决）
#[test]
fn acl_enabled_register_without_bit_rejected() {
    let (mut c, ak) = setup();
    c.set_acl_policy("lab", lab_policy());
    // 不带 0x40 → 拒绝
    let err = c
        .register(&ak, &pubkey(8), 0x01, vec![], 0, (0, 0))
        .unwrap_err();
    assert_eq!(err, RegisterError::AclCapabilityRequired);
    // 带 0x40 → 放行（线格式装配断言在 rill-mesh server_tests）
    let id = c
        .register(&ak, &pubkey(8), 0x41, vec![], 0, (0, 0))
        .unwrap()
        .node_id;
    // 幂等重注册同受约束（能力位是注册字段）
    let again = c.register(&ak, &pubkey(8), 0x41, vec![], 0, (0, 0));
    assert_eq!(again.unwrap().node_id, id);
    let err = c
        .register(&ak, &pubkey(8), 0x01, vec![], 0, (0, 0))
        .unwrap_err();
    assert_eq!(err, RegisterError::AclCapabilityRequired);
}

/// 策略变更 bump netmap 版本（version 一版本两用，节点侧随心跳快照收敛）
#[test]
fn acl_policy_change_bumps_netmap_version() {
    let (mut c, ak) = setup();
    let id = c
        .register(&ak, &pubkey(9), 0x41, vec![], 0, (0, 0))
        .unwrap()
        .node_id;
    let network_id = c.network_id_of(id).unwrap();
    let v0 = c.netmap_version();

    c.set_acl_policy("lab", lab_policy());
    assert_eq!(c.netmap_version(), v0 + 1);
    assert_eq!(c.acl_policy_of(network_id), lab_policy());
    // 未启用网络 = default（disabled）
    c.set_acl_policy(
        "lab",
        landscape_rill_core::control::acl::AclPolicy::default(),
    );
    assert!(!c.acl_policy_of(network_id).enabled);
}

// ==================== 多网络隔离（SEC-21~25/CTL-09，CONTROL_PLANE §1.5） ====================

/// SEC-21/CTL-09：netmap 按网络过滤——A 网条目不进 B 网快照
#[test]
fn netmap_isolated_per_network() {
    let (mut c, ak_a, ak_b) = two_networks();
    let a1 = register_node(&mut c, &ak_a, 1);
    let a2 = register_node(&mut c, &ak_a, 2);
    let b1 = register_node(&mut c, &ak_b, 3);
    let net_a = c.network_id_of(a1).unwrap();
    let net_b = c.network_id_of(b1).unwrap();
    assert_ne!(net_a, net_b);
    let snap_a = c.netmap_snapshot(net_a);
    assert_eq!(snap_a.len(), 2);
    assert!(snap_a.iter().all(|n| n.node_id == a1 || n.node_id == a2));
    let snap_b = c.netmap_snapshot(net_b);
    assert_eq!(snap_b.len(), 1);
    assert_eq!(snap_b[0].node_id, b1);
    // 条目 network_id 恒为本网络（联邦钩子语义）
    assert!(snap_a.iter().all(|n| n.network_id == net_a));
}

/// SEC-23：auth key 归域——A 网 key 进 B 网（网络名不存在/不匹配）→ 拒绝
#[test]
fn auth_key_scoped_to_network() {
    let (mut c, ak_a, _ak_b) = two_networks();
    // 网络不存在（key 内嵌未配置网络）→ 拒绝
    let err = c.register(&lrk("ghost", 86_400), &pubkey(9), 0x00, vec![], 0, (0, 0));
    assert!(matches!(err, Err(RegisterError::InvalidAuthKey)));
    // A 网 key 只能注册进 A 网（返回 A 的 network_id）
    let id = c
        .register(&ak_a, &pubkey(1), 0x00, vec![], 0, (0, 0))
        .unwrap();
    assert_eq!(id.network_id, network_id_for("lab"));
    // 同 key 幂等：仍是 A 网
    let again = c
        .register(&ak_a, &pubkey(1), 0x00, vec![], 0, (0, 0))
        .unwrap();
    assert_eq!(again.node_id, id.node_id);
    assert_eq!(again.network_id, network_id_for("lab"));
    // A 网 key 重复注册（不同 pubkey）进 B 网表不存在 → 仍是 A 网新节点
    let a2 = c
        .register(&ak_a, &pubkey(2), 0x00, vec![], 0, (0, 0))
        .unwrap();
    assert_eq!(a2.network_id, network_id_for("lab"));
}

/// SEC-22：key_dst 按网络主密钥派生——A 网节点 key 与 B 网不同，跨网伪造必失配
#[test]
fn key_dst_isolated_per_network() {
    let (mut c, ak_a, ak_b) = two_networks();
    let a1 = register_node_caps(&mut c, &ak_a, 1, 0x21);
    let a2 = register_node_caps(&mut c, &ak_a, 2, 0x21);
    let b1 = register_node_caps(&mut c, &ak_b, 3, 0x21);
    let ka1 = c.key_dist(a1).unwrap();
    let ka2 = c.key_dist(a2).unwrap();
    let kb1 = c.key_dist(b1).unwrap();
    // 同网络同 node_id 语义：不同 node 不同 key（KDF(主密钥, node_id)）
    assert_ne!(ka1.key, ka2.key);
    // 跨网络即使 node_id 相同也不得同 key（主密钥独立）
    assert_ne!(ka1.key, kb1.key);
    // 广播密钥按网络独立（opt-in 节点，REQ-035 按需下发语义）
    let b2 = register_node_caps(&mut c, &ak_b, 4, 0x21);
    let kb2 = c.key_dist(b2).unwrap();
    assert_eq!(ka1.broadcast_key, ka2.broadcast_key);
    assert_eq!(kb1.broadcast_key, kb2.broadcast_key);
    assert_ne!(ka1.broadcast_key, kb1.broadcast_key);
}

/// REQ-035/CTL-14：broadcast_key 按能力位按需下发——未 opt-in 节点不携带
#[test]
fn keydist_broadcast_key_opt_in_only() {
    let (mut c, ak) = setup();
    let opted_in = register_node_caps(&mut c, &ak, 1, CAPABILITY_BROADCAST);
    let relay_only = register_node(&mut c, &ak, 2);
    assert!(c.key_dist(opted_in).unwrap().broadcast_key.is_some());
    assert!(c.key_dist(relay_only).unwrap().broadcast_key.is_none());
    // 混合能力位（relay + broadcast）同样下发
    let mixed = register_node_caps(&mut c, &ak, 3, CAPABILITY_RELAY | CAPABILITY_BROADCAST);
    assert!(c.key_dist(mixed).unwrap().broadcast_key.is_some());
}

/// SEC-25：前缀公告白名单按网络分域——A 网白名单不影响 B 网
#[test]
fn whitelist_isolated_per_network() {
    let ak_a = lrk("lab", 86_400);
    let ak_b = lrk("work", 86_400);
    let mut c = Coordinator::new([0x5a; 32]);
    c.add_network("lab", [0x77; 32]);
    c.add_network("work", [0x88; 32]);
    c.add_auth_key(&ak_a, AuthKeyPolicy::Reusable);
    c.add_auth_key(&ak_b, AuthKeyPolicy::Reusable);
    c.set_announce_whitelist("lab", vec![Prefix::parse("10.0.0.0/8").unwrap()]);
    c.set_announce_whitelist("work", vec![Prefix::parse("192.168.0.0/16").unwrap()]);
    // A 网：白名单外前缀拒绝
    let err = c.register(
        &ak_a,
        &pubkey(1),
        0x00,
        vec!["192.168.1.0/24".into()],
        0,
        (0, 0),
    );
    assert!(matches!(err, Err(RegisterError::RouteNotAllowed)));
    // B 网：其白名单内的 192.168.1.0/24 正常接受（分域证明）
    let b1 = c.register(
        &ak_b,
        &pubkey(2),
        0x00,
        vec!["192.168.1.0/24".into()],
        0,
        (0, 0),
    );
    assert!(b1.is_ok());
    // A 网节点无法公告 B 网白名单前缀（其白名单无此覆盖）
    let err = c.register(
        &ak_a,
        &pubkey(3),
        0x00,
        vec!["192.168.2.0/24".into()],
        0,
        (0, 0),
    );
    assert!(matches!(err, Err(RegisterError::RouteNotAllowed)));
}

/// 跨网络路径请求被拒（fail-closed）：netmap 隔离下源看不到异网节点
#[test]
fn cross_network_path_request_rejected() {
    let (mut c, ak_a, ak_b) = two_networks();
    let a1 = register_node(&mut c, &ak_a, 1);
    let b1 = register_node(&mut c, &ak_b, 2);
    assert!(c.request_paths(a1, b1, 4, 1_000).is_empty());
    // 同网正常
    let a2 = register_node(&mut c, &ak_a, 3);
    assert!(!c.request_paths(a1, a2, 4, 1_000).is_empty());
}

/// 每网络独立 relay 集合：A 网 relay 不进 B 网路径候选
#[test]
fn relays_isolated_per_network() {
    let ak_a = lrk("lab", 86_400);
    let ak_b = lrk("work", 86_400);
    let mut c = Coordinator::new([0x5a; 32]);
    c.add_network("lab", [0x77; 32]);
    c.add_network("work", [0x88; 32]);
    c.add_auth_key(&ak_a, AuthKeyPolicy::Reusable);
    c.add_auth_key(&ak_b, AuthKeyPolicy::Reusable);
    // A 网 relay（capabilities 0x01）注册
    let r = c
        .register(&ak_a, &pubkey(1), 0x01, vec![], 0, (0, 0))
        .unwrap()
        .node_id;
    let a1 = c
        .register(&ak_a, &pubkey(2), 0x00, vec![], 0, (0, 0))
        .unwrap()
        .node_id;
    let a2 = c
        .register(&ak_a, &pubkey(3), 0x00, vec![], 0, (0, 0))
        .unwrap()
        .node_id;
    let b1 = c
        .register(&ak_b, &pubkey(4), 0x00, vec![], 0, (0, 0))
        .unwrap()
        .node_id;
    let b2 = c
        .register(&ak_b, &pubkey(5), 0x00, vec![], 0, (0, 0))
        .unwrap()
        .node_id;
    // A 网 roster 落位 → A 网路径含 A relay
    let nid_a = c.network_id_of(r).unwrap();
    assert!(c.apply_relay_roster(nid_a, vec![r], 1_000));
    let cands_a = c.request_paths(a1, a2, 4, 1_000);
    assert!(cands_a.iter().any(|(p, _)| p.hops == vec![r, a2]));
    // B 网路径不含 A relay（roster 按网络独立）
    let cands_b = c.request_paths(b1, b2, 4, 1_000);
    assert!(cands_b.iter().all(|(p, _)| !p.hops.contains(&r)));
    assert_eq!(cands_b.len(), 1); // 仅 direct（B 无 relay）
}

// ---------------------------------------------------------------------------
// relay roster 策划（REQ-062 验收 ①②：交集语义 / exclude 优先 / include 兜底 /
// 滞回退出 / max_size 名额 / 在线过滤）
// ---------------------------------------------------------------------------

/// 构造：公网直连 relay 候选（seen ∈ 本地）+ 已测得 RTT
fn roster_setup(relay_count: usize) -> (Coordinator, String, u32, Vec<u32>) {
    let (mut c, ak) = setup();
    let mut relays = Vec::new();
    for i in 0..relay_count {
        let id = c
            .register(&ak, &pubkey((i + 1) as u8), 0x01, vec![], 0, (0, 0))
            .unwrap()
            .node_id;
        c.set_endpoints(
            id,
            vec![format!("203.0.113.{id}:41641")],
            vec![format!("203.0.113.{id}:41641")],
        );
        relays.push(id);
    }
    let network_id = c.network_id_of(relays[0]).unwrap();
    // 一轮全命中 RTT（rtt 值 = node_id，便于断言排序）
    let results: Vec<(u32, Option<u64>)> = relays.iter().map(|&r| (r, Some(r as u64))).collect();
    c.record_relay_rtt_round(network_id, &results);
    (c, ak, network_id, relays)
}

/// REQ-062 验收 ①：能力位 ∩ roster；exclude 优先于自动策划；include 兜底判定失败节点
#[test]
fn roster_intersection_exclude_and_include_semantics() {
    // 3 个公网直连 relay 候选 + 1 个 NAT 后候选（include 兜底对象）
    let (mut c, ak, network_id, relays) = roster_setup(3);
    let natted = c
        .register(&ak, &pubkey(0x40), 0x01, vec![], 0, (0, 0))
        .unwrap()
        .node_id;
    c.set_endpoints(
        natted,
        vec!["192.168.1.5:41641".into()],
        vec!["198.51.100.7:52010".into()], // NAT 映射，seen ∉ 本地
    );
    c.record_relay_rtt_round(network_id, &[(natted, Some(9))]);
    // ① 双资格：无能力位节点不进（include 也不行——能力位是必要条件）
    let plain = register_node_caps(&mut c, &ak, 0x50, 0x00);
    let mut cfg = crate::config::RelayRosterConfig::default();
    cfg.include.push(plain);
    c.set_relay_constraints("lab", cfg.clone());
    assert!(!c.propose_relay_roster(network_id).contains(&plain));
    // ② exclude 优先：自动策划命中者被剔除
    cfg.exclude.push(relays[0]);
    c.set_relay_constraints("lab", cfg.clone());
    let proposed = c.propose_relay_roster(network_id);
    assert!(!proposed.contains(&relays[0]), "exclude 优先于自动策划");
    assert!(proposed.contains(&relays[1]));
    // ③ include 兜底：NAT 后（判定失败）候选经 include 进 roster
    assert!(!proposed.contains(&natted), "无 include 时 NAT 后不进");
    cfg.include.push(natted);
    c.set_relay_constraints("lab", cfg);
    let proposed = c.propose_relay_roster(network_id);
    assert!(proposed.contains(&natted), "include 兜底判定失败节点");
    // RTT 升序（rtt 值 = node_id：2 < 3 < 4=natted(9)）
    assert_eq!(proposed, vec![relays[1], relays[2], natted]);
}

/// max_size 名额截断自动策划；include 追加不计名额
#[test]
fn roster_max_size_caps_auto_but_not_include() {
    let (mut c, _ak, network_id, relays) = roster_setup(3);
    let mut cfg = crate::config::RelayRosterConfig {
        max_size: 2,
        ..Default::default()
    };
    c.set_relay_constraints("lab", cfg.clone());
    let proposed = c.propose_relay_roster(network_id);
    assert_eq!(proposed.len(), 2, "自动策划截断到 max_size");
    cfg.include.push(relays[2]);
    c.set_relay_constraints("lab", cfg);
    let proposed = c.propose_relay_roster(network_id);
    assert_eq!(proposed.len(), 3, "include 追加不计名额");
    assert!(proposed.contains(&relays[2]));
}

/// 滞回（REQ-062 开放问题 ②默认值）：miss < 3 轮保留；满 3 轮移出；重新命中即回
#[test]
fn roster_exit_hysteresis_by_consecutive_misses() {
    let (mut c, _ak, network_id, relays) = roster_setup(1);
    let r = relays[0];
    assert_eq!(c.propose_relay_roster(network_id), vec![r]);
    // miss 1~2 轮：仍在（防健康抖动）
    for _ in 0..2 {
        c.record_relay_rtt_round(network_id, &[(r, None)]);
    }
    assert_eq!(c.propose_relay_roster(network_id), vec![r]);
    // 第 3 轮 miss：移出
    c.record_relay_rtt_round(network_id, &[(r, None)]);
    assert!(c.propose_relay_roster(network_id).is_empty());
    // 重新命中：回 roster
    c.record_relay_rtt_round(network_id, &[(r, Some(5))]);
    assert_eq!(c.propose_relay_roster(network_id), vec![r]);
}

/// 在线过滤：租约超时（离线）节点不进 roster；include 不豁免离线
#[test]
fn roster_excludes_offline_nodes() {
    let (mut c, _ak, network_id, relays) = roster_setup(1);
    let r = relays[0];
    // 心跳维持在线（liveness 默认无记录 = 不离线；这里显式打 miss 标记离线）
    c.mark_offline(r);
    assert!(c.propose_relay_roster(network_id).is_empty());
    let mut cfg = crate::config::RelayRosterConfig::default();
    cfg.include.push(r);
    c.set_relay_constraints("lab", cfg);
    assert!(
        c.propose_relay_roster(network_id).is_empty(),
        "include 不豁免离线"
    );
}

/// roster 落位（apply）→ netmap/状态可见；集合变化才 bump netmap（顺序变化不 bump）
#[test]
fn roster_apply_bumps_netmap_on_set_change_only() {
    let (mut c, _ak, network_id, relays) = roster_setup(2);
    let v0 = c.netmap_version();
    assert!(c.apply_relay_roster(network_id, vec![relays[0], relays[1]], 1_000));
    let v1 = c.netmap_version();
    assert_eq!(v1, v0 + 1);
    assert_eq!(c.relay_roster_for(network_id), &[relays[0], relays[1]]);
    // 同集不同序：无集合变化（不 bump），但顺序（挂靠优先级）已更新
    assert!(!c.apply_relay_roster(network_id, vec![relays[1], relays[0]], 1_000));
    assert_eq!(c.netmap_version(), v1);
    assert_eq!(c.relay_roster_for(network_id), &[relays[1], relays[0]]);
}

/// 吊销 roster 成员：roster 即时收口 + 路径撤销（联动断言见 path_service 测试）
#[test]
fn revoke_removes_node_from_roster() {
    let (mut c, ak, network_id, relays) = roster_setup(1);
    let r = relays[0];
    assert!(c.apply_relay_roster(network_id, vec![r], 1_000));
    let src = register_node_caps(&mut c, &ak, 0x60, 0x00);
    let dst = register_node_caps(&mut c, &ak, 0x61, 0x00);
    let cands = c.request_paths(src, dst, 4, 1_000);
    assert!(cands.iter().any(|(p, _)| p.hops == vec![r, dst]));
    c.revoke(r, 1_000, (0, 0));
    assert!(!c.relay_roster_for(network_id).contains(&r));
    let cands = c.request_paths(src, dst, 4, 1_000);
    assert!(cands.iter().all(|(p, _)| !p.hops.contains(&r)));
}

/// 跨网络 identity_binding 验签失败（SEC-24 核心断言；数据面握手跨网互拒见
/// rill-core/src/handshake.rs prologue_mismatch_rejected 与 data.rs 线级测试）
#[test]
fn binding_not_verifiable_across_networks() {
    let (mut c, ak_a, ak_b) = two_networks();
    let a1 = c
        .register(&ak_a, &pubkey(1), 0x00, vec![], 0, (0, 0))
        .unwrap();
    let b1 = c
        .register(&ak_b, &pubkey(2), 0x00, vec![], 0, (0, 0))
        .unwrap();
    let verifier = c.verifier();
    // 各自绑定对各自节点有效（绑定消息构造 sanity：node_id || static_pubkey）
    let _binding = landscape_rill_core::control::registry::binding_message(
        a1.node_id,
        &pubkey(1),
        a1.binding_log_id,
    );
    assert!(!_binding.is_empty());
    assert!(crate::signer::verify_binding(
        &verifier,
        a1.node_id,
        &pubkey(1),
        &a1.identity_binding,
        a1.binding_log_id
    ));
    assert!(crate::signer::verify_binding(
        &verifier,
        b1.node_id,
        &pubkey(2),
        &b1.identity_binding,
        b1.binding_log_id
    ));
    // A 网节点把 B 网绑定混入握手：B 节点身份配 A 绑定 → 验签失败
    assert!(!crate::signer::verify_binding(
        &verifier,
        b1.node_id,
        &pubkey(2),
        &a1.identity_binding,
        a1.binding_log_id
    ));
    // A 网绑定替换节点号/公钥任意字段 → 失败
    assert!(!crate::signer::verify_binding(
        &verifier,
        a1.node_id,
        &pubkey(3),
        &a1.identity_binding,
        a1.binding_log_id
    ));
    assert!(!crate::signer::verify_binding(
        &verifier,
        999,
        &pubkey(1),
        &a1.identity_binding,
        a1.binding_log_id
    ));
}

// ==================== 持久化（REQ-037） ====================

#[test]
fn expired_key_rejected_at_admission() {
    // REQ-043：过期内嵌 key，注册时（admission）拒绝；挑战恢复路径不受影响
    let now = unix_seconds();
    let expired = format!("lrk-lab-{}-{}", now - 1, "A".repeat(52));
    let mut c = Coordinator::new([0x5a; 32]);
    c.add_network("lab", [0x77; 32]);
    c.add_auth_key(&expired, AuthKeyPolicy::Reusable);
    assert!(c.has_auth_key(&expired)); // 过期 key 可配置（inert），admission 时拒绝
    let err = c.register(&expired, &pubkey(1), 0x00, vec![], now, (0, 0));
    assert!(matches!(err, Err(RegisterError::InvalidAuthKey)));
    // 非 lrk 格式 → fail-closed 拒绝
    let mut c = Coordinator::new([0x5a; 32]);
    c.add_network("lab", [0x77; 32]);
    c.add_auth_key("opaque-key", AuthKeyPolicy::Reusable);
    assert!(!c.has_auth_key("opaque-key"));
    let err = c.register("opaque-key", &pubkey(1), 0x00, vec![], 0, (0, 0));
    assert!(matches!(err, Err(RegisterError::InvalidAuthKey)));
}

fn tmp_db(name: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!(
        "lrill-{name}-{}-{}.redb",
        std::process::id(),
        rand::random::<u32>()
    ));
    let _ = std::fs::remove_file(&p);
    p
}

fn networks_arg() -> Vec<(String, [u8; 32])> {
    vec![("lab".to_string(), [0x77; 32])]
}

#[test]
fn persist_roundtrip_restores_full_state() {
    let ak = lrk("lab", 86_400);

    let path = tmp_db("roundtrip");
    let mut c = Coordinator::open(&path, &networks_arg(), [0x5a; 32]).unwrap();
    c.add_auth_key(&ak, AuthKeyPolicy::Reusable);
    let a = c
        .register(&ak, &pubkey(1), 0x01, vec![], 0, (0, 0))
        .unwrap()
        .node_id;
    c.set_endpoints(a, vec!["203.0.113.1:41641".into()], vec![]);
    let b = c
        .register(&ak, &pubkey(2), 0x00, vec![], 0, (0, 0))
        .unwrap()
        .node_id;
    c.request_paths(a, b, 4, 1_000);
    drop(c);

    let c = Coordinator::open(&path, &networks_arg(), [0x5a; 32]).unwrap();
    let net_a = c.network_id_of(a).unwrap();
    assert_eq!(c.netmap_version(), 3); // 注册 a + 端点 + 注册 b
    assert_eq!(c.key_version_for("lab"), 1);
    assert_eq!(c.netmap_snapshot(net_a).len(), 2);
    let mut snap = c.netmap_snapshot(net_a);
    snap.sort_by_key(|n| n.node_id);
    assert_eq!(snap[0].node_id, 1);
    assert_eq!(snap[0].static_pubkey, pubkey(1));
    assert_eq!(snap[1].node_id, 2);
    assert_eq!(snap[0].endpoints, vec!["203.0.113.1:41641"]);
    // 身份绑定恢复（签名确定性，可直接比对）
    assert!(c.key_dist(a).is_some());
    assert!(c.node_id_by_pubkey(&pubkey(1)) == Some(a));
    drop(c);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn one_time_consumption_survives_restart() {
    let ak = lrk("lab", 86_400);

    let path = tmp_db("onetime");
    let mut c = Coordinator::open(&path, &networks_arg(), [0x5a; 32]).unwrap();
    c.add_auth_key(&ak, AuthKeyPolicy::OneTime);
    c.register(&ak, &pubkey(1), 0x00, vec![], 0, (0, 0))
        .unwrap();
    assert!(!c.has_auth_key(&ak));
    drop(c);

    let mut c = Coordinator::open(&path, &networks_arg(), [0x5a; 32]).unwrap();
    assert!(!c.has_auth_key(&ak), "一次性 key 消费必须持久化");
    // 同 key 二次注册被拒（未知公钥 + 无有效 key）
    let err = c.register(&ak, &pubkey(2), 0x00, vec![], 0, (0, 0));
    assert!(matches!(err, Err(RegisterError::InvalidAuthKey)));
    drop(c);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn consumed_key_not_revived_by_reload() {
    let ak = lrk("lab", 86_400);

    // SIGHUP 重载（config 重新 apply）不复活已消费的一次性 key
    let path = tmp_db("reload");
    let mut c = Coordinator::open(&path, &networks_arg(), [0x5a; 32]).unwrap();
    c.add_auth_key(&ak, AuthKeyPolicy::OneTime);
    c.register(&ak, &pubkey(1), 0x00, vec![], 0, (0, 0))
        .unwrap();
    drop(c);

    let mut c = Coordinator::open(&path, &networks_arg(), [0x5a; 32]).unwrap();
    c.add_auth_key(&ak, AuthKeyPolicy::OneTime);
    assert!(!c.has_auth_key(&ak), "重载不得复活已消费 key");
    drop(c);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn node_and_path_ids_monotonic_across_restart() {
    let ak = lrk("lab", 86_400);

    let path = tmp_db("ids");
    let mut c = Coordinator::open(&path, &networks_arg(), [0x5a; 32]).unwrap();
    c.add_auth_key(&ak, AuthKeyPolicy::Reusable);
    let a = c
        .register(&ak, &pubkey(1), 0x00, vec![], 0, (0, 0))
        .unwrap()
        .node_id;
    let b = c
        .register(&ak, &pubkey(2), 0x00, vec![], 0, (0, 0))
        .unwrap()
        .node_id;
    let paths = c.request_paths(a, b, 4, 1_000);
    drop(c);

    // 重启后新节点不重用 node_id；新路径不重用 path_id
    // （auth key 为配置权威，重启后须重新 apply——模拟 from_config 的 apply_to）
    let mut c = Coordinator::open(&path, &networks_arg(), [0x5a; 32]).unwrap();
    c.add_auth_key(&ak, AuthKeyPolicy::Reusable);
    let d = c
        .register(&ak, &pubkey(3), 0x00, vec![], 0, (0, 0))
        .unwrap()
        .node_id;
    assert_eq!(d, 3);
    let paths2 = c.request_paths(a, d, 4, 1_000);
    for (p, _) in &paths2 {
        assert!(!paths.iter().any(|(q, _)| q.path_id == p.path_id));
    }
    // 幂等命中保留原 path_id（参与者间不分叉）
    let paths3 = c.request_paths(a, b, 4, 1_000);
    assert_eq!(paths3.len(), paths.len());
    assert!(paths3
        .iter()
        .zip(&paths)
        .all(|(p, q)| p.0.path_id == q.0.path_id));
    drop(c);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn corrupt_store_fails_closed() {
    let path = tmp_db("corrupt");
    {
        let c = Coordinator::open(&path, &networks_arg(), [0x5a; 32]).unwrap();
        drop(c);
    }
    std::fs::write(&path, b"not a redb file at all").unwrap();
    assert!(Coordinator::open(&path, &networks_arg(), [0x5a; 32]).is_err());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn inconsistent_state_fails_closed() {
    let ak = lrk("lab", 86_400);

    // next_node_id 与节点表不一致 → 拒绝启动（不猜测重建）
    let path = tmp_db("inconsistent");
    {
        let mut c = Coordinator::open(&path, &networks_arg(), [0x5a; 32]).unwrap();
        c.add_auth_key(&ak, AuthKeyPolicy::Reusable);
        c.register(&ak, &pubkey(1), 0x00, vec![], 0, (0, 0))
            .unwrap();
        drop(c);
    }
    // 篡改快照：把 next_node_id 改回 1（与已注册 node 1 冲突）
    let store = crate::store::CoordStore::open(&path).unwrap();
    let mut state = store.load().unwrap().unwrap();
    state.next_node_id = 1;
    store.save(&state).unwrap();
    assert!(Coordinator::open(&path, &networks_arg(), [0x5a; 32]).is_err());
    let _ = std::fs::remove_file(&path);
}

/// 多网络持久化：跨重启归域恢复（nodes/consumed/key_version/path 按网络分组）
#[test]
fn persist_roundtrip_two_networks() {
    let ak_a = lrk("lab", 86_400);
    let ak_b = lrk("work", 86_400);

    let path = tmp_db("twonet");
    {
        let mut c = Coordinator::open(&path, &two_networks_arg(), [0x5a; 32]).unwrap();
        c.add_auth_key(&ak_a, AuthKeyPolicy::Reusable);
        c.add_auth_key(&ak_b, AuthKeyPolicy::Reusable);
        let a1 = c
            .register(&ak_a, &pubkey(1), 0x00, vec![], 0, (0, 0))
            .unwrap();
        let b1 = c
            .register(&ak_b, &pubkey(2), 0x00, vec![], 0, (0, 0))
            .unwrap();
        c.rotate_master_key("lab", [0x99; 32]);
        drop(a1);
        drop(b1);
    }
    let c = Coordinator::open(&path, &two_networks_arg(), [0x5a; 32]).unwrap();
    let net_a = c.network_id_of(1).unwrap();
    let net_b = c.network_id_of(2).unwrap();
    assert_ne!(net_a, net_b);
    // 每网络恢复自己的条目
    assert_eq!(c.netmap_snapshot(net_a).len(), 1);
    assert_eq!(c.netmap_snapshot(net_b).len(), 1);
    // 每网络独立 key 版本：lab 轮换过（v2），work 未动（v1）
    assert_eq!(c.key_version_for("lab"), 2);
    assert_eq!(c.key_version_for("work"), 1);
    drop(c);
    let _ = std::fs::remove_file(&path);
}

fn two_networks_arg() -> Vec<(String, [u8; 32])> {
    vec![
        ("lab".to_string(), [0x77; 32]),
        ("work".to_string(), [0x88; 32]),
    ]
}

// ==================== 遥测聚合与状态端点视图（REQ-051/052） ====================

use crate::status::{CoordRuntimeMeta, DropView, PeerTrafficView, StatusView, TelemetryView};

fn view(node_id: u32, tx: u64) -> TelemetryView {
    TelemetryView {
        peers: vec![PeerTrafficView {
            node_id,
            tx_frames: tx,
            tx_bytes: tx * 100,
            rx_frames: tx,
            rx_bytes: tx * 100,
        }],
        drop_global: 1,
        drops: vec![DropView { node_id, count: 1 }],
        direct: vec![],
        paths: vec![],
        updated_at: 0,
    }
}

#[test]
fn telemetry_latest_wins_aggregation() {
    // §3.15：coord 聚合 = latest-wins 快照（旧值直接覆盖），不承诺时序存储
    let (mut c, ak) = setup();
    let id = register_node(&mut c, &ak, 0x11);
    c.store_telemetry(id, view(id, 1));
    c.store_telemetry(id, view(id, 7));
    let all = c.telemetry_all();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].0, id);
    assert_eq!(all[0].1.peers[0].tx_frames, 7);
    assert!(all[0].1.updated_at > 0, "coordinator 侧打点");
}

#[test]
fn telemetry_cleared_on_revoke() {
    let (mut c, ak) = setup();
    let id = register_node(&mut c, &ak, 0x11);
    c.store_telemetry(id, view(id, 1));
    c.revoke(id, 0, (0, 0));
    assert!(c.telemetry_all().is_empty());
}

#[test]
fn build_version_roundtrip_and_empty_skip() {
    // §3.1 version 字段：可选元数据；空值 = 旧节点 → 不写 build_version
    let (mut c, ak) = setup();
    let id = register_node(&mut c, &ak, 0x11);
    assert!(c.build_version(id).is_none());
    c.set_build_version(id, "lrill 0.1.0".into());
    assert_eq!(c.build_version(id), Some("lrill 0.1.0"));
    // 恢复类重注册（PoP 后 set_build_version 由 server 侧空值守卫）——直接验证存储
    c.set_build_version(id, String::new());
    assert_eq!(c.build_version(id), Some(""));
}

#[test]
fn status_view_multi_network_offline_consumed() {
    // §3.14 内容组 1-3：多网络全量视图 + 离线节点分支 + 一次性 key 已消费分支；
    // 红线：master_key/signing_seed 不出现在序列化输出
    let (mut c, ak_lab, _ak_work) = two_networks();
    let id_a = register_node(&mut c, &ak_lab, 0x21);
    let id_b = register_node(&mut c, &ak_lab, 0x22);
    c.mark_offline(id_b);
    c.store_telemetry(id_a, view(id_a, 3));
    // 一次性 key 注册即消费（消费 tombstone 进台账）
    let ak_one = lrk("lab", 86_400);
    c.add_auth_key(&ak_one, AuthKeyPolicy::OneTime);
    let _id_c = register_node(&mut c, &ak_one, 0x23);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let meta = CoordRuntimeMeta {
        control_addr: "0.0.0.0:8443".into(),
        status_addr: Some("127.0.0.1:8444".into()),
        storage_path: Some("/var/lib/rill/state.redb".into()),
        started_at_unix: now - 120,
        now_unix: now,
        reload_log: vec!["ok test".into()],
    };
    let snap = StatusView::snapshot(&c, &meta);

    // 网络概览：双网络全量
    assert_eq!(snap.networks.len(), 2);
    assert!(snap.networks.iter().any(|n| n.name == "lab"));
    assert!(snap.networks.iter().any(|n| n.name == "work"));

    // 节点表：在线/离线分支 + last_seen age + 遥测聚合展示
    let a = snap.nodes.iter().find(|n| n.node_id == id_a).unwrap();
    assert!(a.online);
    assert_eq!(a.network, "lab");
    assert!(a.pubkey_fingerprint.starts_with("sha256:"));
    let b = snap.nodes.iter().find(|n| n.node_id == id_b).unwrap();
    assert!(!b.online);

    // auth key 台账：脱敏 + 已消费分支
    assert!(snap
        .auth_keys
        .iter()
        .any(|k| k.consumed && k.network == "lab"));
    assert!(snap.auth_keys.iter().all(|k| !k
        .key_masked
        .contains(&ak_lab[ak_lab.len() - 12..ak_lab.len() - 4])));

    // 遥测快照组（内容组 6）
    assert_eq!(snap.telemetry.len(), 1);
    assert_eq!(snap.telemetry[0].peers[0].tx_frames, 3);

    // coord 自身（内容组 5）：uptime + 存储模式 + 重载历史
    assert_eq!(snap.coord.uptime_secs, 120);
    assert_eq!(snap.coord.storage, "redb:/var/lib/rill/state.redb");
    assert_eq!(snap.coord.reload_log, vec!["ok test"]);

    // 红线：密钥材料零输出（signing_seed 0x5a 序列不得出现）
    let json = serde_json::to_string(&snap).unwrap();
    assert!(!json.contains(&"5a".repeat(8)));
}

/// REQ-065：RouteSync 覆盖域 = 该节点注册 routes[]；RouteMap 推送按版本变化门控
#[test]
fn route_sync_coverage_gate_and_versioned_push() {
    let ak = lrk("lab", 86_400);
    let mut c = Coordinator::new([0x5a; 32]);
    c.add_network("lab", [0x77; 32]);
    c.add_auth_key(&ak, AuthKeyPolicy::Reusable);
    c.set_announce_whitelist(
        "lab",
        vec![
            Prefix::parse("172.20.0.0/14").unwrap(),
            Prefix::parse("fd00::/8").unwrap(),
        ],
    );
    let ext = c
        .register(
            &ak,
            &pubkey(1),
            0x01,
            vec!["172.20.0.0/14".into(), "fd00::/8".into()],
            0,
            (0, 0),
        )
        .unwrap()
        .node_id;
    let consumer = c
        .register(&ak, &pubkey(2), 0x01, vec![], 0, (0, 0))
        .unwrap()
        .node_id;

    // 覆盖域内采纳；域外拒绝（协调者侧 import policy 之外的强制）
    let out = c
        .apply_route_sync(
            ext,
            vec![
                (
                    Prefix::parse("172.20.100.0/24").unwrap(),
                    "172.20.100.2".into(),
                ),
                (
                    Prefix::parse("10.99.0.0/16").unwrap(),
                    "172.20.100.2".into(),
                ),
            ],
            vec![],
        )
        .unwrap();
    assert_eq!((out.accepted, out.rejected_coverage), (1, 1));

    // 版本门控：首次推送带表，无变化不重复推
    let (v1, entries) = c.take_route_map_push(consumer).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].node_id, ext);
    assert_eq!(entries[0].prefix.to_cidr(), "172.20.100.0/24");
    assert_eq!(entries[0].next_hop, "172.20.100.2");
    assert!(c.take_route_map_push(consumer).is_none(), "版本未变不推");

    // 增量撤销 → 版本变化 → 再推（空表也是有效状态）
    c.apply_route_sync(ext, vec![], vec![Prefix::parse("172.20.100.0/24").unwrap()])
        .unwrap();
    let (v2, entries) = c.take_route_map_push(consumer).unwrap();
    assert!(v2 > v1);
    assert!(entries.is_empty());

    // 未注册节点上报 → None（无域可归）
    assert!(c.apply_route_sync(99, vec![], vec![]).is_none());
}

/// REQ-065 生命周期：ext 离线（租约超时扫描）→ 动态路由随 RouteMap 撤销
#[test]
fn offline_sweep_withdraws_route_map_entries() {
    let ak = lrk("lab", 86_400);
    let mut c = Coordinator::new([0x5a; 32]);
    c.add_network("lab", [0x77; 32]);
    c.add_auth_key(&ak, AuthKeyPolicy::Reusable);
    c.set_announce_whitelist(
        "lab",
        vec![
            Prefix::parse("172.20.0.0/14").unwrap(),
            Prefix::parse("fd00::/8").unwrap(),
        ],
    );
    let ext = c
        .register(
            &ak,
            &pubkey(1),
            0x01,
            vec!["172.20.0.0/14".into()],
            0,
            (0, 0),
        )
        .unwrap()
        .node_id;
    let consumer = c
        .register(&ak, &pubkey(2), 0x01, vec![], 0, (0, 0))
        .unwrap()
        .node_id;
    c.heartbeat(ext, 100);
    c.heartbeat(consumer, 101);
    c.apply_route_sync(
        ext,
        vec![
            (
                Prefix::parse("172.20.100.0/24").unwrap(),
                "172.20.100.2".into(),
            ),
            (Prefix::parse("fd42:1::/48").unwrap(), "fd00:100::2".into()),
        ],
        vec![],
    )
    .unwrap();
    let _ = c.take_route_map_push(consumer).unwrap();

    // ext 租约超时（consumer 心跳触发扫描）→ withdraw_node → 版本变化
    c.heartbeat(consumer, 101 + LEASE_EXPIRY_SECS + 1);
    let (_, entries) = c.take_route_map_push(consumer).unwrap();
    assert!(
        entries.is_empty(),
        "离线 ext 的动态路由全部撤销: {entries:?}"
    );

    // ext 回在线重报 → 恢复
    c.heartbeat(ext, 101 + LEASE_EXPIRY_SECS + 2);
    c.apply_route_sync(
        ext,
        vec![(
            Prefix::parse("172.20.100.0/24").unwrap(),
            "172.20.100.2".into(),
        )],
        vec![],
    )
    .unwrap();
    let (_, entries) = c.take_route_map_push(consumer).unwrap();
    assert_eq!(entries.len(), 1);
}

/// REQ-065 生命周期：吊销 → 该节点动态路由撤销 + 推送游标全清
#[test]
fn revoke_withdraws_route_map_entries() {
    let (mut c, ak) = setup();
    c.set_announce_whitelist("lab", vec![Prefix::parse("fd00::/8").unwrap()]);
    let ext = c
        .register(&ak, &pubkey(1), 0x01, vec!["fd00::/8".into()], 0, (0, 0))
        .unwrap()
        .node_id;
    let consumer = register_node(&mut c, &ak, 2);
    c.apply_route_sync(
        ext,
        vec![(Prefix::parse("fd42:1::/48").unwrap(), "fd00:100::2".into())],
        vec![],
    )
    .unwrap();
    let _ = c.take_route_map_push(consumer).unwrap();

    c.revoke(ext, 200, (7, 1));
    let (_, entries) = c.take_route_map_push(consumer).unwrap();
    assert!(entries.is_empty());
}
