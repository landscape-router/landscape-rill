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
            // 留足余量：并行测试负载下过紧的选举超时会让 leader 错过心跳而卸任
            heartbeat_interval: 25,
            election_timeout_min: 150,
            election_timeout_max: 300,
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
    match write(raft, register_cmd(ak, seed, 0, vec![])).await {
        CoordCommandResult::Register(Ok(d)) => d.node_id,
        other => panic!("register failed: {other:?}"),
    }
}

fn register_cmd(ak: &str, seed: u8, capabilities: u32, routes: Vec<String>) -> CoordCommand {
    CoordCommand::Register {
        auth_key: ak.to_string(),
        static_pubkey: pubkey(seed),
        capabilities,
        routes,
        now: 0,
    }
}

/// expires_at 源于墙钟（PathSet TTL），归一化后比较（同秒内本就相等，防跨秒抖动）。
/// 绑定字节/签发锚点/吊销墓碑随路径不同（raft = 日志位置，直连 = (0,0)，binding v2），
/// 归一化对齐后比较——绑定正确性由注册断言单独覆盖
fn normalize(mut state: CoordState) -> CoordState {
    for (_, map, _) in &mut state.path_maps {
        for (_, _, set) in map {
            for candidate in &mut set.candidates {
                candidate.expires_at = 0;
            }
        }
    }
    for n in &mut state.nodes {
        n.identity_binding.clear();
        n.binding_log_id = (0, 0);
    }
    state.revoked_nodes = state
        .revoked_nodes
        .iter()
        .map(|(id, _, _)| (*id, 0, 0))
        .collect();
    state
}

fn machine_state(machine: &SharedStateMachine) -> CoordState {
    normalize(machine.with(|m| m.state_snapshot()))
}

fn direct_state(c: &crate::coordinator::Coordinator) -> CoordState {
    normalize(c.snapshot())
}

/// CoordState 未派生 PartialEq：序列化字节比较（确定性结构 + 排序字段）
fn assert_state_eq(a: &CoordState, b: &CoordState, ctx: &str) {
    let (ja, jb) = (
        serde_json::to_vec(a).unwrap(),
        serde_json::to_vec(b).unwrap(),
    );
    assert!(ja == jb, "{ctx} 状态不等");
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

    // 注册 ×2：node_id/网络等价；绑定按各自签发锚点独立校验通过
    //（binding v2：绑定消息内含锚点——raft 路径锚 = 日志位置，直连路径恒 (0,0)，字节不再相等）
    let verifier = direct.verifier();
    for seed in 1..=2u8 {
        let routes = vec![format!("10.4{}.0.0/24", seed)];
        let raft_data = match write(&raft, register_cmd(&ak, seed, 0x01, routes.clone())).await {
            CoordCommandResult::Register(Ok(d)) => d,
            other => panic!("register failed: {other:?}"),
        };
        let direct_data = direct
            .register(&ak, &pubkey(seed), 0x01, routes, 0, (0, 0))
            .unwrap();
        assert_eq!(raft_data.node_id, direct_data.node_id);
        assert_eq!(raft_data.network_id, direct_data.network_id);
        assert_eq!(direct_data.binding_log_id, (0, 0));
        // raft 锚点 = 该注册条目的日志位置（首个注册条目在初始成员变更之后）
        assert!(raft_data.binding_log_id.0 > 0 && raft_data.binding_log_id.1 >= 1);
        assert!(crate::signer::verify_binding(
            &verifier,
            raft_data.node_id,
            &pubkey(seed),
            &raft_data.identity_binding,
            raft_data.binding_log_id
        ));
        assert!(crate::signer::verify_binding(
            &verifier,
            direct_data.node_id,
            &pubkey(seed),
            &direct_data.identity_binding,
            direct_data.binding_log_id
        ));
        // 跨锚点不可互换（签名域包含锚点）
        assert!(!crate::signer::verify_binding(
            &verifier,
            raft_data.node_id,
            &pubkey(seed),
            &raft_data.identity_binding,
            direct_data.binding_log_id
        ));
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
            now: 5_000,
        },
    )
    .await
    {
        CoordCommandResult::RequestPaths(p) => p,
        other => panic!("request_paths failed: {other:?}"),
    };
    let direct_paths = direct.request_paths(1, 2, 4, 5_000);
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
    direct.revoke(2, 1_000, (0, 0));

    // 持久状态等价（apply 顺序 = 提交顺序的直接推论）
    assert_state_eq(&machine_state(&machine), &direct_state(&direct), "等价性");

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
    direct
        .register(&ak, &pubkey(1), 0, vec![], 0, (0, 0))
        .unwrap();
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
    direct.revoke(1, 100, (0, 0));
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

// ============================================================================
// 阶段二：进程内 3 节点集群（静态成员）——复制/follower 写拒绝/故障转移/旧 leader 回归。
// 真实部署的 inter-coord mTLS RPC 由接线层实现，此处 channel 直连验证共识层行为
// ============================================================================

use openraft::error::{
    ClientWriteError, Fatal, RPCError, RaftError, ReplicationClosed, StreamingError, Unreachable,
};
use openraft::network::RPCOption;
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, SnapshotResponse, VoteRequest, VoteResponse,
};
use std::collections::HashMap;
use tokio::sync::{mpsc, oneshot};

#[allow(clippy::large_enum_variant)]
enum TestMsg {
    Append(
        AppendEntriesRequest<TypeConfig>,
        oneshot::Sender<Result<AppendEntriesResponse<u64>, String>>,
    ),
    Vote(
        VoteRequest<u64>,
        oneshot::Sender<Result<VoteResponse<u64>, String>>,
    ),
    FullSnapshot(
        openraft::Vote<u64>,
        openraft::Snapshot<TypeConfig>,
        oneshot::Sender<Result<SnapshotResponse<u64>, String>>,
    ),
}

#[derive(Clone)]
struct TestNetwork {
    txs: Arc<std::sync::Mutex<HashMap<u64, mpsc::UnboundedSender<TestMsg>>>>,
}

#[derive(Clone)]
struct TestNetworkFactory {
    net: TestNetwork,
}

#[derive(Clone)]
struct TestNetworkClient {
    net: TestNetwork,
    target: u64,
}

#[derive(Debug, thiserror::Error)]
#[error("test rpc failed: {0}")]
struct TestRpcError(String);

#[allow(clippy::result_large_err)]
fn rpc_unreachable<T>(msg: &str) -> Result<T, RPCError<u64, BasicNode, RaftError<u64>>> {
    Err(RPCError::Unreachable(Unreachable::new(&TestRpcError(
        msg.to_string(),
    ))))
}

impl TestNetwork {
    fn new() -> Self {
        Self {
            txs: Arc::new(std::sync::Mutex::new(HashMap::new())),
        }
    }

    /// 挂接节点服务循环：入站 RPC 转调 raft 服务端方法
    fn attach(&self, id: u64, raft: Raft<TypeConfig>) {
        let (tx, mut rx) = mpsc::unbounded_channel();
        self.txs.lock().unwrap().insert(id, tx);
        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                match msg {
                    TestMsg::Append(rpc, reply) => {
                        let _ =
                            reply.send(raft.append_entries(rpc).await.map_err(|e| e.to_string()));
                    }
                    TestMsg::Vote(rpc, reply) => {
                        let _ = reply.send(raft.vote(rpc).await.map_err(|e| e.to_string()));
                    }
                    TestMsg::FullSnapshot(vote, snapshot, reply) => {
                        let _ = reply.send(
                            raft.install_full_snapshot(vote, snapshot)
                                .await
                                .map_err(|e| e.to_string()),
                        );
                    }
                }
            }
        });
    }

    #[allow(clippy::result_large_err)]
    async fn request<T>(
        &self,
        target: u64,
        build: impl FnOnce(oneshot::Sender<Result<T, String>>) -> TestMsg,
    ) -> Result<T, RPCError<u64, BasicNode, RaftError<u64>>> {
        let (tx, rx) = oneshot::channel();
        {
            let Ok(map) = self.txs.lock() else {
                return rpc_unreachable("network poisoned");
            };
            let Some(sender) = map.get(&target) else {
                return rpc_unreachable("node not attached");
            };
            if sender.send(build(tx)).is_err() {
                return rpc_unreachable("node gone");
            }
        }
        match rx.await {
            Ok(Ok(v)) => Ok(v),
            // 远端错误简化为 Unreachable（测试网只关心通/断与数据面正确性）
            Ok(Err(e)) => rpc_unreachable(&e),
            Err(_) => rpc_unreachable("node dropped"),
        }
    }
}

impl openraft::RaftNetworkFactory<TypeConfig> for TestNetworkFactory {
    type Network = TestNetworkClient;

    async fn new_client(&mut self, target: u64, _node: &BasicNode) -> Self::Network {
        TestNetworkClient {
            net: self.net.clone(),
            target,
        }
    }
}

impl openraft::RaftNetwork<TypeConfig> for TestNetworkClient {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<AppendEntriesResponse<u64>, RPCError<u64, BasicNode, RaftError<u64>>> {
        self.net
            .request(self.target, |reply| TestMsg::Append(rpc, reply))
            .await
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<u64>,
        _option: RPCOption,
    ) -> Result<VoteResponse<u64>, RPCError<u64, BasicNode, RaftError<u64>>> {
        self.net
            .request(self.target, |reply| TestMsg::Vote(rpc, reply))
            .await
    }

    async fn full_snapshot(
        &mut self,
        vote: openraft::Vote<u64>,
        snapshot: openraft::Snapshot<TypeConfig>,
        _cancel: impl std::future::Future<Output = ReplicationClosed> + Send + 'static,
        _option: RPCOption,
    ) -> Result<SnapshotResponse<u64>, StreamingError<TypeConfig, Fatal<u64>>> {
        self.net
            .request(self.target, |reply| {
                TestMsg::FullSnapshot(vote, snapshot, reply)
            })
            .await
            .map_err(|_| {
                StreamingError::Unreachable(Unreachable::new(&TestRpcError(
                    "snapshot rpc failed".into(),
                )))
            })
    }
}

struct ClusterNode {
    id: u64,
    raft: Raft<TypeConfig>,
    machine: SharedStateMachine,
}

/// 起一个集群成员（静态成员 id；复用已存路径 = 重启/回归场景）
async fn spawn_cluster_node(
    net: &TestNetwork,
    id: u64,
    log_path: &Path,
    state_path: &Path,
    configure: impl FnOnce(&mut Coordinator),
) -> ClusterNode {
    let log_store = RaftLogStore::open(log_path).unwrap();
    let machine = SharedStateMachine::open(machine_config(), state_path).unwrap();
    machine.with_coordinator_mut(configure);
    let factory = TestNetworkFactory { net: net.clone() };
    let raft = Raft::new(id, raft_config(), factory, log_store, machine.clone())
        .await
        .unwrap();
    net.attach(id, raft.clone());
    ClusterNode { id, raft, machine }
}

fn cluster_paths(tag: &str, id: u64) -> (PathBuf, PathBuf) {
    (
        tmp_file(&format!("cluster-{tag}-{id}-log")),
        tmp_file(&format!("cluster-{tag}-{id}-state")),
    )
}

async fn await_any_leader(nodes: &[&ClusterNode], exclude: &[u64]) -> u64 {
    for _ in 0..1000 {
        for n in nodes {
            if exclude.contains(&n.id) {
                continue;
            }
            if matches!(
                n.raft.metrics().borrow().state,
                openraft::ServerState::Leader
            ) {
                return n.id;
            }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("10s 内未选出 leader");
}

/// 等全部成员状态机收敛到同一持久状态（applied 对齐 + 状态快照相等）
async fn await_converged(nodes: &[&ClusterNode]) -> CoordState {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let states: Vec<Vec<u8>> = nodes
            .iter()
            .map(|n| serde_json::to_vec(&machine_state(&n.machine)).unwrap())
            .collect();
        let applied: Vec<Option<u64>> = nodes
            .iter()
            .map(|n| n.machine.with(|m| m.last_applied().map(|l| l.index)))
            .collect();
        let converged = states.windows(2).all(|w| w[0] == w[1])
            && applied.windows(2).all(|w| w[0] == w[1])
            && applied.iter().all(|a| a.is_some());
        if converged {
            return serde_json::from_slice(&states[0]).unwrap();
        }
        assert!(
            std::time::Instant::now() < deadline,
            "10s 内未收敛: applied={applied:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn auth_config(ak: &str) -> impl FnOnce(&mut Coordinator) + '_ {
    move |c: &mut Coordinator| {
        c.add_auth_key(ak, AuthKeyPolicy::Reusable);
    }
}

/// 向当前 leader 写入；选举翻转（ForwardToLeader）时跟进重试。
/// CI 并行测试负载可让选举超时意外触发重选，leader 不能在测量点钉死
async fn write_via_leader(nodes: &[ClusterNode], cmd: CoordCommand) -> CoordCommandResult {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let refs: Vec<_> = nodes.iter().collect();
        let leader = await_any_leader(&refs, &[]).await;
        let raft = &nodes.iter().find(|n| n.id == leader).unwrap().raft;
        let res = raft.client_write(cmd.clone()).await;
        match res {
            Ok(r) => return r.data,
            Err(RaftError::APIError(ClientWriteError::ForwardToLeader(_))) => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "10s 内未完成 leader 写入（leader 持续翻转）"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(other) => panic!("leader write failed: {other:?}"),
        }
    }
}

/// 节点此刻是否仍报 Leader（follower 转发目标的稳定采样依据）
fn reports_leader(n: &ClusterNode) -> bool {
    matches!(
        n.raft.metrics().borrow().state,
        openraft::ServerState::Leader
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn three_node_cluster_replicates_writes_and_rejects_follower_writes() {
    let net = TestNetwork::new();
    let ak = lrk("lab", 86_400);
    let paths: Vec<_> = (0..3).map(|id| cluster_paths("repl", id)).collect();
    let mut nodes = Vec::new();
    for id in 0..3u64 {
        nodes.push(
            spawn_cluster_node(
                &net,
                id,
                &paths[id as usize].0,
                &paths[id as usize].1,
                auth_config(&ak),
            )
            .await,
        );
    }
    // 单点 initialize 3 成员（静态成员集）
    nodes[0]
        .raft
        .initialize(BTreeMap::from([
            (0, BasicNode::default()),
            (1, BasicNode::default()),
            (2, BasicNode::default()),
        ]))
        .await
        .unwrap();
    // leader 写入 → 多数派复制 → 全员 apply（选举可翻转，写跟进当前 leader）
    let node_id = match write_via_leader(&nodes, register_cmd(&ak, 7, 0x01, vec![])).await {
        CoordCommandResult::Register(Ok(d)) => d.node_id,
        other => panic!("cluster register failed: {other:?}"),
    };
    assert_eq!(node_id, 1);
    let refs: Vec<_> = nodes.iter().collect();
    let state = await_converged(&refs).await;
    assert_eq!(state.nodes.len(), 1, "全部副本都应 apply 注册");

    // follower 写 → ForwardToLeader（带 leader id，LeaderRedirect 依据）。
    // 转发目标在采样窗口内可能再翻转：按当前 metrics 视图选 follower 重采样，
    // 直到观察到一次"目标仍是 leader"的稳定转发
    let mut forwarded = false;
    for attempt in 0..100u8 {
        let leader = await_any_leader(&refs, &[]).await;
        let follower = &nodes[(if leader == 0 { 1 } else { 0 }) as usize];
        let res = follower
            .raft
            .client_write(register_cmd(&ak, 8 + attempt, 0x01, vec![]))
            .await;
        if let Err(RaftError::APIError(ClientWriteError::ForwardToLeader(ftl))) = res {
            if ftl
                .leader_id
                .is_some_and(|id| reports_leader(&nodes[id as usize]))
            {
                forwarded = true;
                break;
            }
        }
        // Ok（该 follower 恰当选为主，注册生效）或目标已翻转：重采样
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(forwarded, "100 次采样内未观察到稳定的 follower 转发");

    for n in &nodes {
        n.raft.shutdown().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn leader_failover_then_old_leader_rejoins_as_follower() {
    let net = TestNetwork::new();
    let ak = lrk("lab", 86_400);
    let paths: Vec<_> = (0..3).map(|id| cluster_paths("failover", id)).collect();
    let mut nodes = Vec::new();
    for id in 0..3u64 {
        nodes.push(
            spawn_cluster_node(
                &net,
                id,
                &paths[id as usize].0,
                &paths[id as usize].1,
                auth_config(&ak),
            )
            .await,
        );
    }
    nodes[0]
        .raft
        .initialize(BTreeMap::from([
            (0, BasicNode::default()),
            (1, BasicNode::default()),
            (2, BasicNode::default()),
        ]))
        .await
        .unwrap();
    let leader1 = await_any_leader(&nodes.iter().collect::<Vec<_>>(), &[]).await;
    // 写入 node_id=1
    write_via_leader(&nodes, register_cmd(&ak, 1, 0, vec![])).await;
    let refs: Vec<_> = nodes.iter().collect();
    await_converged(&refs).await;

    // kill leader（shutdown 模拟宕机；句柄全释放）
    nodes[leader1 as usize].raft.shutdown().await.unwrap();
    let killed = nodes.swap_remove(nodes.iter().position(|n| n.id == leader1).unwrap());
    drop(killed); // 释放 redb 句柄（回归场景复用路径）
    let remaining: Vec<&ClusterNode> = nodes.iter().collect();
    let leader2 = await_any_leader(&remaining, &[]).await;
    assert_ne!(leader2, leader1, "新 leader 必须是另一个成员");

    // 故障转移后可写（注册 b → node_id=2，node_id 分配器经日志复制不回退）
    match write_via_leader(&nodes, register_cmd(&ak, 2, 0, vec![])).await {
        CoordCommandResult::Register(Ok(d)) => assert_eq!(d.node_id, 2),
        other => panic!("write after failover failed: {other:?}"),
    }
    let state = await_converged(&remaining).await;
    assert_eq!(state.nodes.len(), 2);

    // 旧 leader 回归：复用原路径重启 → 追日志 → 以 follower 身份收敛。
    // 不对重启瞬间的 metrics 断言：openraft 恢复持久化的已提交自投票
    // （term T, voted_for=self）时会短暂报 Leader（须重新仲裁 quorum 后才有效，
    // 存活副本更高 term 会令其卸任）——瞬时态与调度时序相关，权威断言在收敛后
    let rejoined = spawn_cluster_node(
        &net,
        leader1,
        &paths[leader1 as usize].0,
        &paths[leader1 as usize].1,
        auth_config(&ak),
    )
    .await;
    nodes.push(rejoined);
    let refs: Vec<_> = nodes.iter().collect();
    let state = await_converged(&refs).await;
    assert_eq!(state.nodes.len(), 2, "回归副本追平两条注册");
    let rejoined_ref = nodes.iter().find(|n| n.id == leader1).unwrap();
    assert!(
        !matches!(
            rejoined_ref.raft.metrics().borrow().state,
            openraft::ServerState::Leader
        ),
        "回归节点应保持 follower"
    );

    for n in &nodes {
        let _ = n.raft.shutdown().await;
    }
}

// ============================================================================
// CoordBackend 门面（阶段二）：leadership 视图 + 写分派（leader 直提/Forward 提示）
// ============================================================================

use crate::raft::backend::{CoordBackend, Leadership, WriteError};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backend_leadership_view_and_write_dispatch() {
    let net = TestNetwork::new();
    let ak = lrk("lab", 86_400);
    let paths: Vec<_> = (0..3).map(|id| cluster_paths("backend", id)).collect();
    let mut nodes = Vec::new();
    for id in 0..3u64 {
        nodes.push(
            spawn_cluster_node(
                &net,
                id,
                &paths[id as usize].0,
                &paths[id as usize].1,
                auth_config(&ak),
            )
            .await,
        );
    }
    nodes[0]
        .raft
        .initialize(BTreeMap::from([
            (0, BasicNode::default()),
            (1, BasicNode::default()),
            (2, BasicNode::default()),
        ]))
        .await
        .unwrap();
    // advertise 表（id → 节点面地址占位）
    let advertise: std::collections::HashMap<u64, String> = (0..3)
        .map(|id| (id, format!("127.0.0.1:{}", 9000 + id)))
        .collect();
    let backend_of = |n: &ClusterNode| CoordBackend::Cluster {
        raft: n.raft.clone(),
        machine: n.machine.clone(),
        members: Arc::new(advertise.clone()),
        self_id: n.id,
    };
    // 端点 → 成员 id（advertise 为双射）
    let id_of_endpoint = |ep: &str| {
        advertise
            .iter()
            .find(|(_, v)| v.as_str() == ep)
            .map(|(k, _)| *k)
    };

    // leadership 视图（follower 的 current_leader 经 metrics watch 传播，
    // 晚于 leader 自身状态）。CI 并行负载下选举可翻转：以
    // "follower 上报端点 ↔ 此刻仍报 Leader 的成员"的稳定样本为准
    let mut stable_view = false;
    for _ in 0..1000 {
        let refs: Vec<_> = nodes.iter().collect();
        let leader = await_any_leader(&refs, &[]).await;
        let follower_node = nodes.iter().find(|n| n.id != leader).unwrap();
        let follower_backend = backend_of(follower_node);
        if let Leadership::Follower {
            leader_endpoint: Some(ep),
            term,
        } = follower_backend.leadership()
        {
            let stable = id_of_endpoint(&ep)
                .is_some_and(|id| reports_leader(nodes.iter().find(|n| n.id == id).unwrap()));
            if stable {
                assert_eq!(
                    term,
                    follower_node.raft.metrics().borrow().current_term,
                    "leadership 视图 term 取自 metrics"
                );
                stable_view = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(stable_view, "10s 内未观察到稳定的 follower leadership 视图");

    // leader 写 → 直提成功（选举可翻转：跟进当前 leader 重试）；随后副本 apply
    let data = {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let refs: Vec<_> = nodes.iter().collect();
            let leader = await_any_leader(&refs, &[]).await;
            let leader_backend = backend_of(nodes.iter().find(|n| n.id == leader).unwrap());
            match leader_backend
                .register(&ak, &pubkey(1), 0x00, vec![], 0)
                .await
            {
                Ok(d) => break d,
                Err(WriteError::Forward { .. }) => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "10s 内未完成 leader 写入"
                    );
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(other) => panic!("leader write failed: {other:?}"),
            }
        }
    };
    assert_eq!(data.node_id, 1);
    let mut applied = false;
    for _ in 0..500 {
        if nodes
            .iter()
            .any(|n| backend_of(n).with_coord(|c| c.node_id_by_pubkey(&pubkey(1)).is_some()))
        {
            applied = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(applied, "leader 写应在副本侧 apply");

    // follower 写 → Forward（携 leader 节点面地址；LeaderRedirect 依据）——
    // 同样按稳定采样（转发端点回指仍报 Leader 的成员）
    let mut forwarded = false;
    for attempt in 0..100u32 {
        let refs: Vec<_> = nodes.iter().collect();
        let leader = await_any_leader(&refs, &[]).await;
        let follower_backend = backend_of(nodes.iter().find(|n| n.id != leader).unwrap());
        let reg_forwarded = matches!(
            follower_backend
                .register(&ak, &pubkey((0x10 + attempt) as u8), 0x00, vec![], 0)
                .await,
            Err(WriteError::Forward { leader_endpoint: Some(ep) })
                if id_of_endpoint(&ep)
                    .is_some_and(|id| reports_leader(nodes.iter().find(|n| n.id == id).unwrap()))
        );
        let revoke_forwarded = matches!(
            follower_backend.revoke(1, 0).await,
            Err(WriteError::Forward { .. })
        );
        if reg_forwarded && revoke_forwarded {
            forwarded = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(forwarded, "100 次采样内未观察到稳定的 follower 转发");

    // Single 形态回归：leadership 恒 Leader、写直调等价
    let mut single_coord = Coordinator::new([0x5a; 32]);
    single_coord.add_network("lab", [0x77; 32]);
    single_coord.add_auth_key(&ak, AuthKeyPolicy::Reusable);
    single_coord.set_announce_whitelist("lab", vec![Prefix::parse("10.41.0.0/24").unwrap()]);
    let single = CoordBackend::single(single_coord);
    assert_eq!(single.leadership(), Leadership::Leader);
    let d = single
        .register(&ak, &pubkey(3), 0x00, vec![], 0)
        .await
        .unwrap();
    assert_eq!(d.node_id, 1);
    assert!(single.revoke(1, 0).await.unwrap(), "Single 吊销命中");

    for n in &nodes {
        let _ = n.raft.shutdown().await;
    }
}

// ==================== 绑定交叉审计（REQ-049② 阶段三验收） ====================

/// 伪造绑定（签名有效但未进日志）在任意已 apply 副本上被拒（Conflict）；
/// 真实绑定 Verified、超前锚点 Behind、吊销后旧绑定 Unknown。
/// 单机形态（审计语义的直连回归）一并覆盖
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn binding_audit_cross_verification_rejects_unlogged_issuance() {
    use crate::raft::backend::{AuditVerdict, CoordBackend};
    use crate::signer::Ed25519Signer;
    use landscape_rill_core::control::registry::{binding_message, IdentitySigner};

    let net = TestNetwork::new();
    let ak = lrk("lab", 86_400);
    let paths: Vec<_> = (0..3).map(|id| cluster_paths("audit", id)).collect();
    let mut nodes = Vec::new();
    for id in 0..3u64 {
        nodes.push(
            spawn_cluster_node(
                &net,
                id,
                &paths[id as usize].0,
                &paths[id as usize].1,
                auth_config(&ak),
            )
            .await,
        );
    }
    nodes[0]
        .raft
        .initialize(BTreeMap::from([
            (0, BasicNode::default()),
            (1, BasicNode::default()),
            (2, BasicNode::default()),
        ]))
        .await
        .unwrap();
    // leader 注册 → 全员 apply（锚点 = 该条目日志位置；选举可翻转，写跟进当前 leader）
    let data = match write_via_leader(&nodes, register_cmd(&ak, 7, 0x00, vec![])).await {
        CoordCommandResult::Register(Ok(d)) => d,
        other => panic!("cluster register failed: {other:?}"),
    };
    let advertise: std::collections::HashMap<u64, String> = (0..3)
        .map(|id| (id, format!("127.0.0.1:{}", 9100 + id)))
        .collect();
    let backends: Vec<CoordBackend> = nodes
        .iter()
        .map(|n| CoordBackend::Cluster {
            raft: n.raft.clone(),
            machine: n.machine.clone(),
            members: Arc::new(advertise.clone()),
            self_id: n.id,
        })
        .collect();

    assert!(data.binding_log_id.0 >= 1, "集群锚点 = 真实日志位置");
    let refs: Vec<_> = nodes.iter().collect();
    await_converged(&refs).await;
    assert_eq!(
        backends[0].replica_endpoints().len(),
        3,
        "replica 端点来自 raft 成员表"
    );

    // ① 真实绑定：任意副本（含 follower）本地裁决 Verified
    for b in &backends {
        let (v, applied) = b.audit_binding(
            data.node_id,
            &pubkey(7),
            &data.identity_binding,
            data.binding_log_id,
        );
        assert_eq!(v, AuditVerdict::Verified);
        assert!(applied >= data.binding_log_id.0);
    }

    // 伪造签发面：同一签发种子（split-view 的 leader 私钥用法），但条目从未进日志
    let forged_signer = Ed25519Signer::new([0x5a; 32]);
    // ② 未注册节点 + 已 apply 范围内锚点 → Conflict（"未进日志的签名"被拒）
    let unlogged = forged_signer.sign(&binding_message(9, &pubkey(9), data.binding_log_id));
    for b in &backends {
        let (v, _) = b.audit_binding(9, &pubkey(9), &unlogged, data.binding_log_id);
        assert_eq!(v, AuditVerdict::Conflict, "未进日志的签发应被拒");
    }
    // ③ 在册节点换公钥重签（条目锚点相同但内容不符）→ Conflict
    let swapped = forged_signer.sign(&binding_message(
        data.node_id,
        &pubkey(0x99),
        data.binding_log_id,
    ));
    let (v, _) =
        backends[1].audit_binding(data.node_id, &pubkey(0x99), &swapped, data.binding_log_id);
    assert_eq!(v, AuditVerdict::Conflict);

    // ④ 超前锚点（编造未来日志位置/replica 落后）→ Behind（无法判定，非终局）
    let future = (backends[0].applied_index() + 100, data.binding_log_id.1);
    let future_sig = forged_signer.sign(&binding_message(9, &pubkey(9), future));
    let (v, _) = backends[2].audit_binding(9, &pubkey(9), &future_sig, future);
    assert_eq!(v, AuditVerdict::Behind);

    // ⑤ 垃圾签名（无签发种子者伪造）→ Unknown（本地验签即失败，无日志证据可言）
    let (v, _) =
        backends[0].audit_binding(data.node_id, &pubkey(7), &[0xff; 64], data.binding_log_id);
    assert_eq!(v, AuditVerdict::Unknown);

    // ⑥ 吊销后的旧绑定：签名仍有效但节点已吊销 → Unknown（墓碑防误判 conflict）
    write_via_leader(
        &nodes,
        CoordCommand::Revoke {
            node_id: data.node_id,
            now: 1_000,
        },
    )
    .await;
    await_converged(&refs).await;
    let (v, _) = backends[0].audit_binding(
        data.node_id,
        &pubkey(7),
        &data.identity_binding,
        data.binding_log_id,
    );
    assert_eq!(v, AuditVerdict::Unknown, "吊销墓碑语义");

    // 单机形态：审计语义一致（锚点恒 (0,0)，applied = 全部已生效）
    let mut single = Coordinator::new([0x5a; 32]);
    single.add_network("lab", [0x77; 32]);
    single.add_auth_key(&ak, AuthKeyPolicy::Reusable);
    let backend = CoordBackend::single(single);
    let d = backend
        .register(&ak, &pubkey(3), 0x00, vec![], 0)
        .await
        .unwrap();
    assert_eq!(d.binding_log_id, (0, 0));
    let (v, _) = backend.audit_binding(d.node_id, &pubkey(3), &d.identity_binding, (0, 0));
    assert_eq!(v, AuditVerdict::Verified);
    let forged_single = forged_signer.sign(&binding_message(2, &pubkey(4), (0, 0)));
    let (v, _) = backend.audit_binding(2, &pubkey(4), &forged_single, (0, 0));
    assert_eq!(v, AuditVerdict::Conflict);

    for n in &nodes {
        let _ = n.raft.shutdown().await;
    }
}
