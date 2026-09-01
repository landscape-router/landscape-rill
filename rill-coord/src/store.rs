//! coordinator 持久化存储（REQ-037，CONTROL_PLANE §4.1）
//!
//! 后端 redb（Rust 原生、单文件、无 C 依赖）：持久状态整快照原子写（单键）。
//! - 持久类：节点注册表/身份绑定、一次性 auth key 消费 tombstone、netmap/key 版本、
//!   端点表、PathMap 与 path_id 分配器
//! - 软状态（last_seen/离线/路径健康）与派生（key_dst/key_path）不落盘
//! - 损坏/不一致 → 拒绝启动（fail-closed，不猜测重建）；写入失败不中断数据面（§4.3），
//!   记日志留 durability 缺口

use crate::path_service::PathSet;
use landscape_rill_core::control::registry::NodeEntry;
use redb::{Database, ReadableDatabase, TableDefinition};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const STATE_SCHEMA: u32 = 2;

const STATE_TABLE: TableDefinition<&'static str, &[u8]> = TableDefinition::new("coord_state");
const STATE_KEY: &str = "state";

/// 每网络 PathMap 持久化条目：(network_id, PathMap, path_seq)
pub type NetworkPathMap = (u32, Vec<(u32, u32, PathSet)>, u64);

/// 持久状态快照（全部确定性 Vec，restore 时重建索引）
/// schema v2（2026-09-01，CONTROL_PLANE §1.5 多网络）：key 版本 / PathMap / relay 列表
/// 按网络分组（主密钥与路径域独立）；node_id 全局唯一（跨网络不冲突）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordState {
    pub schema: u32,
    pub next_node_id: u32,
    pub nodes: Vec<NodeEntry>,
    pub consumed_one_time_keys: Vec<String>,
    pub netmap_version: u64,
    /// (network_id, key_version)：每网络独立
    pub key_versions: Vec<(u32, u32)>,
    pub endpoints: Vec<(u32, Vec<String>)>,
    /// (network_id, PathMap, path_seq)：每网络独立
    pub path_maps: Vec<NetworkPathMap>,
    /// (network_id, relay_list)：RTT 排序结果落盘（CONNECTIVITY §5）
    pub relay_lists: Vec<(u32, Vec<String>)>,
}

#[derive(Debug, thiserror::Error, landscape_rill_macro::ErrorId)]
pub enum StoreError {
    #[error("store io error: {0}")]
    #[error_id("coord.store.io")]
    Io(#[from] std::io::Error),
    #[error("store backend error: {0}")]
    #[error_id("coord.store.redb")]
    Redb(#[from] redb::Error),
    /// 文件内容非法（损坏/篡改/未来版本）
    #[error("corrupt store: {0}")]
    #[error_id("coord.store.corrupt")]
    Corrupt(String),
    /// 语义不一致（拒绝启动，不猜测重建）
    #[error("inconsistent store: {0}")]
    #[error_id("coord.store.inconsistent")]
    Inconsistent(String),
}

impl From<redb::DatabaseError> for StoreError {
    fn from(e: redb::DatabaseError) -> Self {
        StoreError::Redb(e.into())
    }
}

impl From<redb::StorageError> for StoreError {
    fn from(e: redb::StorageError) -> Self {
        StoreError::Redb(e.into())
    }
}

impl From<redb::TransactionError> for StoreError {
    fn from(e: redb::TransactionError) -> Self {
        StoreError::Redb(e.into())
    }
}

impl From<redb::TableError> for StoreError {
    fn from(e: redb::TableError) -> Self {
        StoreError::Redb(e.into())
    }
}

impl From<redb::CommitError> for StoreError {
    fn from(e: redb::CommitError) -> Self {
        StoreError::Redb(e.into())
    }
}

pub struct CoordStore {
    db: Database,
}

impl CoordStore {
    /// 打开（或创建）存储文件；文件损坏/目录不可写 → Err（fail-closed）
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let db = Database::create(path)?;
        // 存储含身份绑定与 key 消费状态，权限收紧 0600（教训 KC-02）
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(Self { db })
    }

    /// 整快照原子写（redb 事务）
    pub fn save(&self, state: &CoordState) -> Result<(), StoreError> {
        let json = serde_json::to_vec(state)
            .map_err(|e| StoreError::Corrupt(format!("state serialize failed: {e}")))?;
        let wtx = self.db.begin_write()?;
        {
            let mut table = wtx.open_table(STATE_TABLE)?;
            table.insert(STATE_KEY, json.as_slice())?;
        }
        wtx.commit()?;
        Ok(())
    }

    /// 读取快照；无记录 = 空状态（首次启动）
    pub fn load(&self) -> Result<Option<CoordState>, StoreError> {
        let rtx = self.db.begin_read()?;
        let table = match rtx.open_table(STATE_TABLE) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let Some(guard) = table.get(STATE_KEY)? else {
            return Ok(None);
        };
        let state: CoordState = serde_json::from_slice(guard.value())
            .map_err(|e| StoreError::Corrupt(format!("state deserialize failed: {e}")))?;
        if state.schema != STATE_SCHEMA {
            return Err(StoreError::Inconsistent(format!(
                "schema={} incompatible (current {})",
                state.schema, STATE_SCHEMA
            )));
        }
        Ok(Some(state))
    }
}
