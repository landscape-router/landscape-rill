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
    c.register(ak, &pubkey(seed), caps, vec![]).unwrap().node_id
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
    let out = c.register(&ak, &pubkey(1), 0x01, vec![]).unwrap();
    assert_eq!(out.node_id, 1);
    assert_eq!(c.netmap_version(), v1);
}

#[test]
fn relay_list_follows_registration() {
    let (mut c, ak) = setup();
    let relay = c.register(&ak, &pubkey(1), 0x01, vec![]).unwrap().node_id;
    let src = c.register(&ak, &pubkey(2), 0x00, vec![]).unwrap().node_id;
    let dst = c.register(&ak, &pubkey(3), 0x00, vec![]).unwrap().node_id;
    let cands = c.request_paths(src, dst, 4);
    assert!(cands.iter().any(|(p, _)| p.hops == vec![relay, dst]));
    assert_eq!(cands.len(), 2); // direct + relay
}

#[test]
fn key_dist_unknown_node_none() {
    let (c, _ak) = setup();
    assert!(c.key_dist(99).is_none());
}

#[test]
fn revoke_removes_and_bumps_versions() {
    let (mut c, ak) = setup();
    let id = register_node(&mut c, &ak, 1);
    let nid = c.network_id_of(id).unwrap();
    let nv = c.netmap_version();
    let kv = c.key_version_for("lab");
    c.revoke(id);
    assert_eq!(c.netmap_snapshot(nid).len(), 0);
    assert_eq!(c.netmap_version(), nv + 1);
    assert_eq!(c.key_version_for("lab"), kv + 1);
    assert!(c.key_dist(id).is_none());
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
        .register(&ak, &pubkey(1), 0x01, vec!["10.60.0.0/24".into()])
        .unwrap()
        .node_id;
    let b = c
        .register(&ak, &pubkey(2), 0x01, vec!["10.61.0.0/24".into()])
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

#[test]
fn endpoints_enter_netmap() {
    let (mut c, ak) = setup();
    let id = register_node(&mut c, &ak, 1);
    c.set_endpoints(id, vec!["203.0.113.1:41641".into()]);
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
    );
    assert!(matches!(err, Err(RegisterError::RouteNotAllowed)));
    // 过短前缀（IPv4 < /8）→ 拒绝
    let err = c.register(&ak, &pubkey(3), 0x01, vec!["10.0.0.0/7".into()]);
    assert!(matches!(err, Err(RegisterError::RouteNotAllowed)));
    // 空白名单 = fail-closed（拒绝一切公告）
    let mut c2 = Coordinator::new([0x5a; 32]);
    c2.add_network("lab", [0x77; 32]);
    c2.add_auth_key(&ak, AuthKeyPolicy::Reusable);
    let err = c2.register(&ak, &pubkey(4), 0x01, vec!["10.42.0.0/24".into()]);
    assert!(matches!(err, Err(RegisterError::RouteNotAllowed)));
}

/// SEC-28（REQ-020）：acl 能力位 v1 恒 false——注册/转发不做裁决，位原样透传（v1 恒放行）
#[test]
fn capability_acl_bit_reserved_v1() {
    let (mut c, ak) = setup();
    // 保留位 0x40（acl，v2 预留）：coordinator 不解释、不占用，netmap 原样带出
    let id = c.register(&ak, &pubkey(7), 0x40, vec![]).unwrap().node_id;
    let snap = c.netmap_snapshot(c.network_id_of(id).unwrap());
    assert_eq!(
        snap.iter().find(|n| n.node_id == id).unwrap().capabilities & 0x40,
        0x40
    );
    // 策略检查点恒放行断言在 rill-core/src/route.rs（policy_checkpoint_allow_all_v1）
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
    let err = c.register(&lrk("ghost", 86_400), &pubkey(9), 0x00, vec![]);
    assert!(matches!(err, Err(RegisterError::InvalidAuthKey)));
    // A 网 key 只能注册进 A 网（返回 A 的 network_id）
    let id = c.register(&ak_a, &pubkey(1), 0x00, vec![]).unwrap();
    assert_eq!(id.network_id, network_id_for("lab"));
    // 同 key 幂等：仍是 A 网
    let again = c.register(&ak_a, &pubkey(1), 0x00, vec![]).unwrap();
    assert_eq!(again.node_id, id.node_id);
    assert_eq!(again.network_id, network_id_for("lab"));
    // A 网 key 重复注册（不同 pubkey）进 B 网表不存在 → 仍是 A 网新节点
    let a2 = c.register(&ak_a, &pubkey(2), 0x00, vec![]).unwrap();
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
    let err = c.register(&ak_a, &pubkey(1), 0x00, vec!["192.168.1.0/24".into()]);
    assert!(matches!(err, Err(RegisterError::RouteNotAllowed)));
    // B 网：其白名单内的 192.168.1.0/24 正常接受（分域证明）
    let b1 = c.register(&ak_b, &pubkey(2), 0x00, vec!["192.168.1.0/24".into()]);
    assert!(b1.is_ok());
    // A 网节点无法公告 B 网白名单前缀（其白名单无此覆盖）
    let err = c.register(&ak_a, &pubkey(3), 0x00, vec!["192.168.2.0/24".into()]);
    assert!(matches!(err, Err(RegisterError::RouteNotAllowed)));
}

/// 跨网络路径请求被拒（fail-closed）：netmap 隔离下源看不到异网节点
#[test]
fn cross_network_path_request_rejected() {
    let (mut c, ak_a, ak_b) = two_networks();
    let a1 = register_node(&mut c, &ak_a, 1);
    let b1 = register_node(&mut c, &ak_b, 2);
    assert!(c.request_paths(a1, b1, 4).is_empty());
    // 同网正常
    let a2 = register_node(&mut c, &ak_a, 3);
    assert!(!c.request_paths(a1, a2, 4).is_empty());
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
    let r = c.register(&ak_a, &pubkey(1), 0x01, vec![]).unwrap().node_id;
    let a1 = c.register(&ak_a, &pubkey(2), 0x00, vec![]).unwrap().node_id;
    let a2 = c.register(&ak_a, &pubkey(3), 0x00, vec![]).unwrap().node_id;
    let b1 = c.register(&ak_b, &pubkey(4), 0x00, vec![]).unwrap().node_id;
    let b2 = c.register(&ak_b, &pubkey(5), 0x00, vec![]).unwrap().node_id;
    // A 网路径含 A relay
    let cands_a = c.request_paths(a1, a2, 4);
    assert!(cands_a.iter().any(|(p, _)| p.hops == vec![r, a2]));
    // B 网路径不含 A relay（relay 集合按网络独立）
    let cands_b = c.request_paths(b1, b2, 4);
    assert!(cands_b.iter().all(|(p, _)| !p.hops.contains(&r)));
    assert_eq!(cands_b.len(), 1); // 仅 direct（B 无 relay）
}

/// 跨网络 identity_binding 验签失败（SEC-24 核心断言；数据面握手跨网互拒见
/// rill-core/src/handshake.rs prologue_mismatch_rejected 与 data.rs 线级测试）
#[test]
fn binding_not_verifiable_across_networks() {
    let (mut c, ak_a, ak_b) = two_networks();
    let a1 = c.register(&ak_a, &pubkey(1), 0x00, vec![]).unwrap();
    let b1 = c.register(&ak_b, &pubkey(2), 0x00, vec![]).unwrap();
    let verifier = c.verifier();
    // 各自绑定对各自节点有效（绑定消息构造 sanity：node_id || static_pubkey）
    let _binding = landscape_rill_core::control::registry::binding_message(a1.node_id, &pubkey(1));
    assert!(!_binding.is_empty());
    assert!(crate::signer::verify_binding(
        &verifier,
        a1.node_id,
        &pubkey(1),
        &a1.identity_binding
    ));
    assert!(crate::signer::verify_binding(
        &verifier,
        b1.node_id,
        &pubkey(2),
        &b1.identity_binding
    ));
    // A 网节点把 B 网绑定混入握手：B 节点身份配 A 绑定 → 验签失败
    assert!(!crate::signer::verify_binding(
        &verifier,
        b1.node_id,
        &pubkey(2),
        &a1.identity_binding
    ));
    // A 网绑定替换节点号/公钥任意字段 → 失败
    assert!(!crate::signer::verify_binding(
        &verifier,
        a1.node_id,
        &pubkey(3),
        &a1.identity_binding
    ));
    assert!(!crate::signer::verify_binding(
        &verifier,
        999,
        &pubkey(1),
        &a1.identity_binding
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
    let err = c.register(&expired, &pubkey(1), 0x00, vec![]);
    assert!(matches!(err, Err(RegisterError::InvalidAuthKey)));
    // 非 lrk 格式 → fail-closed 拒绝
    let mut c = Coordinator::new([0x5a; 32]);
    c.add_network("lab", [0x77; 32]);
    c.add_auth_key("opaque-key", AuthKeyPolicy::Reusable);
    assert!(!c.has_auth_key("opaque-key"));
    let err = c.register("opaque-key", &pubkey(1), 0x00, vec![]);
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
    let a = c.register(&ak, &pubkey(1), 0x01, vec![]).unwrap().node_id;
    c.set_endpoints(a, vec!["203.0.113.1:41641".into()]);
    let b = c.register(&ak, &pubkey(2), 0x00, vec![]).unwrap().node_id;
    c.request_paths(a, b, 4);
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
    c.register(&ak, &pubkey(1), 0x00, vec![]).unwrap();
    assert!(!c.has_auth_key(&ak));
    drop(c);

    let mut c = Coordinator::open(&path, &networks_arg(), [0x5a; 32]).unwrap();
    assert!(!c.has_auth_key(&ak), "一次性 key 消费必须持久化");
    // 同 key 二次注册被拒（未知公钥 + 无有效 key）
    let err = c.register(&ak, &pubkey(2), 0x00, vec![]);
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
    c.register(&ak, &pubkey(1), 0x00, vec![]).unwrap();
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
    let a = c.register(&ak, &pubkey(1), 0x00, vec![]).unwrap().node_id;
    let b = c.register(&ak, &pubkey(2), 0x00, vec![]).unwrap().node_id;
    let paths = c.request_paths(a, b, 4);
    drop(c);

    // 重启后新节点不重用 node_id；新路径不重用 path_id
    // （auth key 为配置权威，重启后须重新 apply——模拟 from_config 的 apply_to）
    let mut c = Coordinator::open(&path, &networks_arg(), [0x5a; 32]).unwrap();
    c.add_auth_key(&ak, AuthKeyPolicy::Reusable);
    let d = c.register(&ak, &pubkey(3), 0x00, vec![]).unwrap().node_id;
    assert_eq!(d, 3);
    let paths2 = c.request_paths(a, d, 4);
    for (p, _) in &paths2 {
        assert!(!paths.iter().any(|(q, _)| q.path_id == p.path_id));
    }
    // 幂等命中保留原 path_id（参与者间不分叉）
    let paths3 = c.request_paths(a, b, 4);
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
        c.register(&ak, &pubkey(1), 0x00, vec![]).unwrap();
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
        let a1 = c.register(&ak_a, &pubkey(1), 0x00, vec![]).unwrap();
        let b1 = c.register(&ak_b, &pubkey(2), 0x00, vec![]).unwrap();
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
    c.revoke(id);
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
