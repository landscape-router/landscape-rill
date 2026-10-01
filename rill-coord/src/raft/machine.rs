//! Raft 状态机适配器（REQ-070 阶段一）：apply 分派到 Coordinator 既有写方法
//!
//! Coordinator 保持 I/O-free：本层以 `store: None` 模式持有它（内部 persist 变 no-op），
//! apply 批次结束后由本层统一落盘——状态快照 + last_applied + last_membership
//! 在状态文件**同一事务**原子写（恰好一次 apply：崩溃要么三者齐回退、要么齐生效，
//! 重启由 openraft 按 applied 指针补放，无双重 apply 窗口）。

use super::{de_io_err, CoordCommand, CoordCommandResult, TypeConfig};
use crate::coordinator::Coordinator;
use crate::store::{CoordState, CoordStore, StoreError};
use openraft::storage::RaftSnapshotBuilder;
use openraft::storage::RaftStateMachine;
use openraft::BasicNode;
use openraft::Entry;
use openraft::EntryPayload;
use openraft::LogId;
use openraft::Snapshot;
use openraft::SnapshotMeta;
use openraft::StorageError;
use openraft::StoredMembership;
use std::path::Path;
use std::sync::{Arc, RwLock};

/// 状态文件扩展键（与状态快照同事务写）
const APPLIED_KEY: &str = "raft_last_applied";
const MEMBERSHIP_KEY: &str = "raft_last_membership";

/// 状态机构造配置：签名种子 + 网络集合（配置面，非共识内容）
#[derive(Clone)]
pub struct MachineConfig {
    pub signing_seed: [u8; 32],
    pub networks: Vec<(String, [u8; 32])>,
}

/// 状态机内部态：openraft 核心任务与快照构建任务并发访问 → 共享锁包裹
pub struct CoordStateMachine {
    config: MachineConfig,
    coordinator: Coordinator,
    /// None = 纯内存（重放测试），apply 不落盘
    store: Option<CoordStore>,
    last_applied: Option<LogId<u64>>,
    last_membership: StoredMembership<u64, BasicNode>,
    current_snapshot: Option<Snapshot<TypeConfig>>,
}

/// 进 Raft::new 的共享句柄；调用方（测试/阶段二 server）留克隆读状态
#[derive(Clone)]
pub struct SharedStateMachine {
    inner: Arc<RwLock<CoordStateMachine>>,
}

impl CoordStateMachine {
    /// 纯内存（无状态文件）：配合日志重放测试
    pub fn in_memory(config: MachineConfig) -> Self {
        Self {
            coordinator: fresh_coordinator(&config),
            config,
            store: None,
            last_applied: None,
            last_membership: StoredMembership::default(),
            current_snapshot: None,
        }
    }

    /// 打开状态文件：恢复 CoordState + raft 应用指针；文件不存在 = 首启
    pub fn open(config: MachineConfig, state_path: &Path) -> Result<Self, StoreError> {
        let store = CoordStore::open(state_path)?;
        let mut machine = Self::in_memory(config);
        if let Some(state) = store.load()? {
            machine.coordinator.restore_state(&state)?;
        }
        machine.last_applied = store
            .load_extra(APPLIED_KEY)?
            .map(|bytes| serde_json::from_slice(&bytes))
            .transpose()
            .map_err(|e| StoreError::Corrupt(format!("raft applied deserialize failed: {e}")))?
            .flatten();
        machine.last_membership = store
            .load_extra(MEMBERSHIP_KEY)?
            .map(|bytes| serde_json::from_slice(&bytes))
            .transpose()
            .map_err(|e| StoreError::Corrupt(format!("raft membership deserialize failed: {e}")))?
            .unwrap_or_default();
        machine.store = Some(store);
        Ok(machine)
    }

    /// 状态快照 + 应用指针单事务落盘
    fn checkpoint(&self) -> Result<(), StoreError> {
        let Some(store) = &self.store else {
            return Ok(());
        };
        let applied = serde_json::to_vec(&self.last_applied)
            .map_err(|e| StoreError::Corrupt(format!("applied serialize failed: {e}")))?;
        let membership = serde_json::to_vec(&self.last_membership)
            .map_err(|e| StoreError::Corrupt(format!("membership serialize failed: {e}")))?;
        store.save_with_extras(
            &self.coordinator.snapshot(),
            &[(APPLIED_KEY, applied), (MEMBERSHIP_KEY, membership)],
        )
    }

    fn apply_command(&mut self, cmd: CoordCommand) -> CoordCommandResult {
        match cmd {
            CoordCommand::Register {
                auth_key,
                static_pubkey,
                capabilities,
                routes,
                now,
            } => CoordCommandResult::Register(self.coordinator.register(
                &auth_key,
                &static_pubkey,
                capabilities,
                routes,
                now,
            )),
            CoordCommand::Revoke { node_id, now } => {
                let known = self.coordinator.static_pubkey_of(node_id).is_some();
                self.coordinator.revoke(node_id, now);
                CoordCommandResult::Revoke(known)
            }
            CoordCommand::SetEndpoints { node_id, endpoints } => {
                self.coordinator.set_endpoints(node_id, endpoints);
                CoordCommandResult::SetEndpoints
            }
            CoordCommand::RequestPaths {
                source,
                dest,
                max,
                now,
            } => CoordCommandResult::RequestPaths(
                self.coordinator.request_paths(source, dest, max, now),
            ),
            CoordCommand::RotateMasterKey {
                network,
                new_master_key,
            } => {
                self.coordinator.rotate_master_key(&network, new_master_key);
                CoordCommandResult::RotateMasterKey
            }
            CoordCommand::FlushRevokeRotations { now } => CoordCommandResult::FlushRevokeRotations(
                self.coordinator.flush_revoke_rotations(now),
            ),
        }
    }
}

fn fresh_coordinator(config: &MachineConfig) -> Coordinator {
    let mut coordinator = Coordinator::new(config.signing_seed);
    for (name, master_key) in &config.networks {
        coordinator.add_network(name, *master_key);
    }
    coordinator
}

fn store_err(e: StoreError) -> StorageError<u64> {
    StorageError::IO {
        source: openraft::StorageIOError::write_state_machine(openraft::AnyError::new(&e)),
    }
}

impl SharedStateMachine {
    pub fn in_memory(config: MachineConfig) -> Self {
        Self {
            inner: Arc::new(RwLock::new(CoordStateMachine::in_memory(config))),
        }
    }

    pub fn open(config: MachineConfig, state_path: &Path) -> Result<Self, StoreError> {
        Ok(Self {
            inner: Arc::new(RwLock::new(CoordStateMachine::open(config, state_path)?)),
        })
    }

    /// 共享读（测试断言 / 阶段二只读查询）
    pub fn with<R>(&self, f: impl FnOnce(&CoordStateMachine) -> R) -> R {
        f(&self.inner.read().unwrap())
    }

    /// 配置面本地变更（SIGHUP 路径，REQ-038/040：配置权威不复制，各 replica 本地生效；
    /// 仅供配置面方法使用，持久写必须走日志）
    pub fn with_coordinator_mut<R>(&self, f: impl FnOnce(&mut Coordinator) -> R) -> R {
        let mut inner = self.inner.write().unwrap();
        f(&mut inner.coordinator)
    }
}

impl CoordStateMachine {
    /// 供测试断言的协调器视图
    pub fn coordinator(&self) -> &Coordinator {
        &self.coordinator
    }

    /// 持久状态快照（确定性排序，等价比较用）
    pub fn state_snapshot(&self) -> CoordState {
        self.coordinator.snapshot()
    }

    /// 当前快照元数据覆盖到的日志位置（测试断言用）
    pub fn snapshot_meta_log_id(&self) -> Option<openraft::LogId<u64>> {
        self.current_snapshot
            .as_ref()
            .and_then(|s| s.meta.last_log_id)
    }

    /// raft 应用指针（收敛性断言用）
    pub fn last_applied(&self) -> Option<openraft::LogId<u64>> {
        self.last_applied
    }

    /// 当前快照数据字节（CoordState 序列化，测试断言用）
    pub fn snapshot_bytes(&self) -> Option<Vec<u8>> {
        self.current_snapshot
            .as_ref()
            .map(|s| (*s.snapshot).clone())
    }
}

impl RaftStateMachine<TypeConfig> for SharedStateMachine {
    type SnapshotBuilder = CoordSnapshotBuilder;

    async fn applied_state(
        &mut self,
    ) -> Result<(Option<LogId<u64>>, StoredMembership<u64, BasicNode>), StorageError<u64>> {
        let inner = self.inner.read().unwrap();
        Ok((inner.last_applied, inner.last_membership.clone()))
    }

    async fn apply<I>(&mut self, entries: I) -> Result<Vec<CoordCommandResult>, StorageError<u64>>
    where
        I: IntoIterator<Item = Entry<TypeConfig>> + Send,
        I::IntoIter: Send,
    {
        let mut results = Vec::new();
        {
            let mut inner = self.inner.write().unwrap();
            for entry in entries {
                inner.last_applied = Some(entry.log_id);
                match entry.payload {
                    EntryPayload::Blank => results.push(CoordCommandResult::Noop),
                    EntryPayload::Normal(cmd) => results.push(inner.apply_command(cmd)),
                    EntryPayload::Membership(membership) => {
                        inner.last_membership =
                            StoredMembership::new(Some(entry.log_id), membership);
                        results.push(CoordCommandResult::Noop);
                    }
                }
            }
            inner.checkpoint().map_err(store_err)?;
        }
        Ok(results)
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        CoordSnapshotBuilder {
            shared: self.clone(),
        }
    }

    async fn begin_receiving_snapshot(&mut self) -> Result<Box<Vec<u8>>, StorageError<u64>> {
        Ok(Box::new(Vec::new()))
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<u64, BasicNode>,
        snapshot: Box<Vec<u8>>,
    ) -> Result<(), StorageError<u64>> {
        let state: CoordState = serde_json::from_slice(&snapshot).map_err(de_io_err)?;
        let mut inner = self.inner.write().unwrap();
        let mut coordinator = fresh_coordinator(&inner.config);
        coordinator.restore_state(&state).map_err(store_err)?;
        inner.coordinator = coordinator;
        inner.last_applied = meta.last_log_id;
        inner.last_membership = meta.last_membership.clone();
        inner.current_snapshot = Some(Snapshot {
            meta: meta.clone(),
            snapshot,
        });
        inner.checkpoint().map_err(store_err)?;
        Ok(())
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<Snapshot<TypeConfig>>, StorageError<u64>> {
        Ok(self.inner.read().unwrap().current_snapshot.clone())
    }
}

/// 快照构建：CoordState 序列化字节即快照数据（与状态文件同格式，重启恢复复用同一路径）
pub struct CoordSnapshotBuilder {
    shared: SharedStateMachine,
}

impl RaftSnapshotBuilder<TypeConfig> for CoordSnapshotBuilder {
    async fn build_snapshot(&mut self) -> Result<Snapshot<TypeConfig>, StorageError<u64>> {
        let mut inner = self.shared.inner.write().unwrap();
        let bytes = serde_json::to_vec(&inner.coordinator.snapshot()).map_err(super::ser_io_err)?;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let meta = SnapshotMeta {
            last_log_id: inner.last_applied,
            last_membership: inner.last_membership.clone(),
            snapshot_id: format!(
                "snapshot-{}-{}",
                inner.last_applied.map(|log_id| log_id.index).unwrap_or(0),
                nanos
            ),
        };
        let snapshot = Snapshot {
            meta,
            snapshot: Box::new(bytes),
        };
        inner.current_snapshot = Some(snapshot.clone());
        Ok(snapshot)
    }
}
