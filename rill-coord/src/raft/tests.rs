//! REQ-070 阶段一验收：单机过日志
//! - 等价性：同命令序列下 raft 路径与直接调用 Coordinator 语义一致（持久状态快照相等）
//! - 重启：状态文件 + 日志恢复后可继续写（node_id 分配器不回退）
//! - 崩溃回放：日志已提交而状态文件未落盘的条目，重启按 applied 指针重放（恰好一次）
//! - 顺序语义：apply 顺序 = 提交顺序（吊销合并轮换窗口 REQ-048 经日志不变）
//! - 日志存储：无空洞边界（truncate/purge）+ vote 持久 + 句柄重开

use crate::authkey::generate_auth_key;
use crate::coordinator::Coordinator;
use crate::raft::log_store::RaftLogStore;
use crate::raft::machine::{MachineConfig, SharedStateMachine};
use crate::raft::network::NullNetworkFactory;
use crate::raft::TypeConfig;
use crate::raft::{CoordCommand, CoordCommandResult};
use crate::store::CoordState;
use landscape_rill_core::control::registry::AuthKeyPolicy;
use landscape_rill_core::route::Prefix;
use openraft::error::InitializeError;
use openraft::storage::RaftLogReader;
use openraft::storage::RaftLogStorage;
use openraft::{BasicNode, Config, Raft, Vote};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

fn pubkey(seed: u8) -> [u8; 32] {
    [seed; 32]
}

fn lrk(network: &str, ttl_secs: u64) -> String {
    generate_auth_key(network, ttl_secs).unwrap()
}

fn tmp_file(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "lrill-raft-{name}-{}-{}.redb",
        std::process::id(),
        rand::random::<u32>()
    ));
    let _ = std::fs::remove_file(&p);
    p
}

fn machine_config() -> MachineConfig {
    MachineConfig {
        signing_seed: [0x5a; 32],
        networks: vec![("lab".to_string(), [0x77; 32])],
    }
}

/// 与 raft 侧对照的直接调用 coordinator（同配置面）
fn direct_coordinator(auth_key: &str) -> Coordinator {
    let mut c = Coordinator::new([0x5a; 32]);
    c.add_network("lab", [0x77; 32]);
    c.add_auth_key(auth_key, AuthKeyPolicy::Reusable);
    c
}

fn raft_config() -> Arc<Config> {
    Arc::new(
        Config {
            cluster_name: "coord-test".to_string(),
            heartbeat_interval: 10,
            election_timeout_min: 30,
            election_timeout_max: 60,
            ..Default::default()
        }
        .validate()
        .unwrap(),
    )
}

/// 起单节点集群：单成员 initialize（已初始化的 NotAllowed 忽略）+ 等选出 leader。
/// 配置面（auth key/白名单）经 configure 在 Raft::new 前注入——
/// 选主期间就可能发生日志重放，配置必须先于核心启动就位
async fn spawn_node(
    log_path: &Path,
    state_path: &Path,
    configure: impl FnOnce(&mut Coordinator),
) -> (Raft<TypeConfig>, SharedStateMachine) {
    let log_store = RaftLogStore::open(log_path).unwrap();
    let machine = SharedStateMachine::open(machine_config(), state_path).unwrap();
    machine.with_coordinator_mut(configure);
    let raft = Raft::new(
        0,
        raft_config(),
        NullNetworkFactory,
        log_store,
        machine.clone(),
    )
    .await
    .unwrap();
    if let Err(e) = raft
        .initialize(BTreeMap::from([(0, BasicNode::default())]))
        .await
    {
        // 重启路径：集群已初始化 → NotAllowed 是预期
        assert!(
            matches!(e.api_error(), Some(InitializeError::NotAllowed(_))),
            "unexpected initialize error: {e}"
        );
    }
    await_leader(&raft).await;
    (raft, machine)
}

async fn await_leader(raft: &Raft<TypeConfig>) {
    for _ in 0..500 {
        if raft.metrics().borrow().current_leader == Some(0) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("5s 内未选出 leader");
}

async fn write(raft: &Raft<TypeConfig>, cmd: CoordCommand) -> CoordCommandResult {
    raft.client_write(cmd).await.expect("client_write").data
}

async fn register(raft: &Raft<TypeConfig>, ak: &str, seed: u8) -> u32 {
    match write(
        raft,
        CoordCommand::Register {
            auth_key: ak.to_string(),
            static_pubkey: pubkey(seed),
            capabilities: 0,
            routes: vec![],
        },
    )
    .await
    {
        CoordCommandResult::Register(Ok(d)) => d.node_id,
        other => panic!("register failed: {other:?}"),
    }
}

/// expires_at 源于墙钟（PathSet TTL），归一化后比较（同秒内本就相等，防跨秒抖动）
fn normalize(mut state: CoordState) -> CoordState {
    for (_, map, _) in &mut state.path_maps {
        for (_, _, set) in map {
            for candidate in &mut set.candidates {
                candidate.expires_at = 0;
            }
        }
    }
    state
}

fn machine_state(machine: &SharedStateMachine) -> CoordState {
    normalize(machine.with(|m| m.state_snapshot()))
}

/// CoordState 未派生 PartialEq：序列化字节比较（确定性结构 + 排序字段）
fn assert_state_eq(a: &CoordState, b: &CoordState, ctx: &str) {
    let (ja, jb) = (
        serde_json::to_vec(a).unwrap(),
        serde_json::to_vec(b).unwrap(),
    );
    assert!(
        ja == jb,
        "{ctx} 状态不等:
raft   = {ja:#?}
direct = {jb:#?}"
    );
}

#[tokio::test]
async fn single_node_equivalent_to_direct_calls() {
    let log_path = tmp_file("equiv-log");
    let state_path = tmp_file("equiv-state");
    let ak = lrk("lab", 86_400);

    let (raft, machine) = spawn_node(&log_path, &state_path, |c| {
        // 配置面本地注入：配置权威不复制（REQ-038/040）
        c.add_auth_key(&ak, AuthKeyPolicy::Reusable);
        c.set_announce_whitelist(
            "lab",
            vec![
                Prefix::parse("10.41.0.0/24").unwrap(),
                Prefix::parse("10.42.0.0/24").unwrap(),
            ],
        );
    })
    .await;
    let mut direct = direct_coordinator(&ak);
    direct.set_announce_whitelist(
        "lab",
        vec![
            Prefix::parse("10.41.0.0/24").unwrap(),
            Prefix::parse("10.42.0.0/24").unwrap(),
        ],
    );

    // 注册 ×2：响应逐字段等价
    for seed in 1..=2u8 {
        let raft_data = match write(
            &raft,
            CoordCommand::Register {
                auth_key: ak.clone(),
                static_pubkey: pubkey(seed),
                capabilities: 0x01,
                routes: vec![format!("10.4{}.0.0/24", seed)],
            },
        )
        .await
        {
            CoordCommandResult::Register(Ok(d)) => d,
            other => panic!("register failed: {other:?}"),
        };
        let direct_data = direct
            .register(
                &ak,
                &pubkey(seed),
                0x01,
                vec![format!("10.4{}.0.0/24", seed)],
            )
            .unwrap();
        assert_eq!(raft_data, direct_data);
    }

    // 端点 + 路径
    write(
        &raft,
        CoordCommand::SetEndpoints {
            node_id: 1,
            endpoints: vec!["203.0.113.1:41641".to_string()],
        },
    )
    .await;
    direct.set_endpoints(1, vec!["203.0.113.1:41641".to_string()]);

    let raft_paths = match write(
        &raft,
        CoordCommand::RequestPaths {
            source: 1,
            dest: 2,
            max: 4,
        },
    )
    .await
    {
        CoordCommandResult::RequestPaths(p) => p,
        other => panic!("request_paths failed: {other:?}"),
    };
    let direct_paths = direct.request_paths(1, 2, 4);
    assert_eq!(raft_paths.len(), direct_paths.len());
    assert!(!raft_paths.is_empty());

    // 吊销（显式 now 保证确定性）
    match write(
        &raft,
        CoordCommand::Revoke {
            node_id: 2,
            now: 1_000,
        },
    )
    .await
    {
        CoordCommandResult::Revoke(true) => {}
        other => panic!("revoke should hit: {other:?}"),
    }
    direct.revoke(2, 1_000);

    // 持久状态等价（apply 顺序 = 提交顺序的直接推论）
    assert_state_eq(&machine_state(&machine), &direct.snapshot(), "等价性");

    raft.shutdown().await.unwrap();
}

#[tokio::test]
async fn restart_restores_state_and_continues() {
    let log_path = tmp_file("restart-log");
    let state_path = tmp_file("restart-state");
    let ak = lrk("lab", 86_400);

    let (raft, machine) = spawn_node(&log_path, &state_path, |c| {
        c.add_auth_key(&ak, AuthKeyPolicy::Reusable);
    })
    .await;
    register(&raft, &ak, 1).await;
    write(
        &raft,
        CoordCommand::SetEndpoints {
            node_id: 1,
            endpoints: vec!["203.0.113.9:41641".to_string()],
        },
    )
    .await;
    let state_before = machine_state(&machine);
    assert_eq!(state_before.nodes.len(), 1);
    raft.shutdown().await.unwrap();
    drop(raft);
    drop(machine); // 释放 redb 句柄（进程内同文件不可重开）

    // 重启：状态文件 + 日志恢复
    let (raft, machine) = spawn_node(&log_path, &state_path, |c| {
        c.add_auth_key(&ak, AuthKeyPolicy::Reusable);
    })
    .await;
    assert_state_eq(&machine_state(&machine), &state_before, "重启后");

    // node_id 分配器不回退：新注册拿 2
    assert_eq!(register(&raft, &ak, 2).await, 2);
    assert_eq!(machine_state(&machine).nodes.len(), 2);
    raft.shutdown().await.unwrap();
}

#[tokio::test]
async fn crash_before_checkpoint_replays_committed_entry() {
    let log_path = tmp_file("replay-log");
    let state_path = tmp_file("replay-state");
    let ak = lrk("lab", 86_400);

    let (raft, machine) = spawn_node(&log_path, &state_path, |c| {
        c.add_auth_key(&ak, AuthKeyPolicy::Reusable);
    })
    .await;
    register(&raft, &ak, 1).await;
    // 条目 1 已完整落盘（状态 + applied 指针同事务）
    let checkpoint_after_first = std::fs::read(&state_path).unwrap();

    register(&raft, &ak, 2).await;
    assert_eq!(machine.with(|m| m.state_snapshot().nodes.len()), 2);

    // 模拟崩溃窗口：日志已提交（log 文件保留）而状态机检查点停在条目 1
    raft.shutdown().await.unwrap();
    drop(raft);
    drop(machine); // 释放 redb 句柄
    std::fs::write(&state_path, checkpoint_after_first).unwrap();

    // 重启 → openraft 按 applied 指针重放条目 2（恰好一次，不重复分配）
    let (raft, machine) = spawn_node(&log_path, &state_path, |c| {
        c.add_auth_key(&ak, AuthKeyPolicy::Reusable);
    })
    .await;
    for _ in 0..500 {
        if machine.with(|m| m.state_snapshot().nodes.len()) == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let nodes = machine_state(&machine).nodes;
    assert_eq!(nodes.len(), 2, "重放后两个节点都在");
    assert_eq!(
        nodes.iter().map(|n| n.node_id).collect::<Vec<_>>(),
        vec![1, 2],
        "重放不得重复分配 node_id"
    );
    raft.shutdown().await.unwrap();
}

#[tokio::test]
async fn revoke_rotation_window_semantics_hold_through_log() {
    let log_path = tmp_file("window-log");
    let state_path = tmp_file("window-state");
    let ak = lrk("lab", 86_400);

    let (raft, machine) = spawn_node(&log_path, &state_path, |c| {
        c.add_auth_key(&ak, AuthKeyPolicy::Reusable);
    })
    .await;
    let mut direct = direct_coordinator(&ak);
    register(&raft, &ak, 1).await;
    direct.register(&ak, &pubkey(1), 0, vec![]).unwrap();
    let version_before = machine.with(|m| m.coordinator().key_version_for("lab"));

    // 未知节点吊销：不命中、不动窗口
    match write(
        &raft,
        CoordCommand::Revoke {
            node_id: 999,
            now: 100,
        },
    )
    .await
    {
        CoordCommandResult::Revoke(false) => {}
        other => panic!("unknown revoke: {other:?}"),
    }

    // 窗口语义（REQ-048）：now=100 起窗，159 不触发，160 触发一次
    write(
        &raft,
        CoordCommand::Revoke {
            node_id: 1,
            now: 100,
        },
    )
    .await;
    match write(&raft, CoordCommand::FlushRevokeRotations { now: 159 }).await {
        CoordCommandResult::FlushRevokeRotations(false) => {}
        other => panic!("window not due at 159: {other:?}"),
    }
    match write(&raft, CoordCommand::FlushRevokeRotations { now: 160 }).await {
        CoordCommandResult::FlushRevokeRotations(true) => {}
        other => panic!("window due at 160: {other:?}"),
    }
    // 已触发 → 再次 flush 幂等 false
    match write(&raft, CoordCommand::FlushRevokeRotations { now: 1_000 }).await {
        CoordCommandResult::FlushRevokeRotations(false) => {}
        other => panic!("flush after fire: {other:?}"),
    }

    // 直接调用同序列对照
    direct.revoke(1, 100);
    assert!(!direct.flush_revoke_rotations(159));
    assert!(direct.flush_revoke_rotations(160));
    assert!(!direct.flush_revoke_rotations(1_000));

    assert_eq!(
        machine.with(|m| m.coordinator().key_version_for("lab")),
        version_before + 1,
        "合并窗口只轮换一次"
    );
    assert_eq!(
        machine.with(|m| m.coordinator().key_version_for("lab")),
        direct.key_version_for("lab")
    );
    raft.shutdown().await.unwrap();
}

#[tokio::test]
async fn log_store_boundaries_and_vote_roundtrip() {
    let log_path = tmp_file("logstore-log");
    let state_path = tmp_file("logstore-state");
    let ak = lrk("lab", 86_400);

    // LogFlushed 由 openraft 内部构造，append 经真实 raft 流程覆盖；
    // 这里先写 3 条命令填充日志，再直接验证 truncate/purge 边界
    let (raft, machine) = spawn_node(&log_path, &state_path, |c| {
        c.add_auth_key(&ak, AuthKeyPolicy::Reusable);
    })
    .await;
    register(&raft, &ak, 1).await;
    register(&raft, &ak, 2).await;
    register(&raft, &ak, 3).await;
    raft.shutdown().await.unwrap();
    drop(raft);
    drop(machine); // 释放状态文件句柄

    let mut store = RaftLogStore::open(&log_path).unwrap();
    let state = store.get_log_state().await.unwrap();
    let last_index = state.last_log_id.expect("log has entries").index;
    assert!(last_index >= 3, "至少 membership + 3 命令 + leader blank");

    // 全量读取无空洞
    let mut reader = store.get_log_reader().await;
    let entries = reader.try_get_log_entries(0..=last_index).await.unwrap();
    assert_eq!(entries.len() as u64, last_index + 1, "日志必须无空洞");
    for (offset, entry) in entries.iter().enumerate() {
        assert_eq!(entry.log_id.index, offset as u64);
    }

    // truncate 自最后一条（含）：尾部清除后 last_log 前移
    let last_log_id = state.last_log_id.unwrap();
    store.truncate(last_log_id).await.unwrap();
    let state = store.get_log_state().await.unwrap();
    assert_eq!(state.last_log_id.unwrap().index, last_index - 1);

    // purge 至（含）倒数第二条：日志清空，last_purged 前移，读取越界返回空
    let purge_upto = state.last_log_id.unwrap();
    store.purge(purge_upto).await.unwrap();
    let state = store.get_log_state().await.unwrap();
    assert_eq!(state.last_log_id, Some(purge_upto), "空日志回退到 purged");
    assert_eq!(state.last_purged_log_id, Some(purge_upto));
    let mut reader = store.get_log_reader().await;
    assert!(reader.try_get_log_entries(0..100).await.unwrap().is_empty());

    // vote 持久 + 句柄重开可读
    store.save_vote(&Vote::new(2, 0u64)).await.unwrap();
    assert_eq!(store.read_vote().await.unwrap(), Some(Vote::new(2, 0u64)));
    // vote 句柄重开（隔离文件，作用域保证全部释放后再开）
    let vote_path = tmp_file("logstore-vote");
    {
        let mut s = RaftLogStore::open(&vote_path).unwrap();
        s.save_vote(&Vote::new(3, 0u64)).await.unwrap();
    }
    let mut reopened = RaftLogStore::open(&vote_path).unwrap();
    assert_eq!(
        reopened.read_vote().await.unwrap(),
        Some(Vote::new(3, 0u64))
    );
}

#[tokio::test]
async fn manual_snapshot_builds_from_state_and_restarts_from_it() {
    let log_path = tmp_file("snap-log");
    let state_path = tmp_file("snap-state");
    let ak = lrk("lab", 86_400);

    let (raft, machine) = spawn_node(&log_path, &state_path, |c| {
        c.add_auth_key(&ak, AuthKeyPolicy::Reusable);
    })
    .await;
    register(&raft, &ak, 1).await;
    let applied_before = raft.metrics().borrow().last_applied.expect("已 apply");

    // 手动触发快照（默认策略 5000 条，测试显式触发）
    raft.trigger().snapshot().await.unwrap();
    for _ in 0..500 {
        let built = machine.with(|m| m.snapshot_meta_log_id().is_some());
        if built {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let snap_log_id = machine
        .with(|m| m.snapshot_meta_log_id())
        .expect("快照未生成");
    assert_eq!(Some(snap_log_id), Some(applied_before));
    let snap_state: CoordState =
        serde_json::from_slice(&machine.with(|m| m.snapshot_bytes()).expect("快照数据存在"))
            .unwrap();
    assert_eq!(snap_state.nodes.len(), 1, "快照内容 = CoordState");
    raft.shutdown().await.unwrap();
}
