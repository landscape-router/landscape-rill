//! Raft 日志存储（REQ-070 阶段一）：日志条目/vote/清理指针落 redb 独立文件
//!
//! 正确性约束（openraft storage-v2 契约）：
//! - 日志无空洞：append 只追加、truncate/purge 按界清理
//! - 写 IO 串行：openraft 在核心任务内串行调用（&mut self），天然满足
//! - vote 先于返回落盘：redb commit 即持久

#![allow(clippy::result_large_err)] // openraft StorageError 体积较大（外部类型）

use super::TypeConfig;
use super::{de_io_err, redb_io_err, ser_io_err};
use openraft::storage::LogFlushed;
use openraft::storage::RaftLogReader;
use openraft::storage::RaftLogStorage;
use openraft::Entry;
use openraft::LogId;
use openraft::LogState;
use openraft::StorageError;
use openraft::Vote;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use std::fmt::Debug;
use std::ops::RangeBounds;
use std::path::Path;
use std::sync::Arc;

/// 日志条目表：log index → 序列化 Entry（serde_json，与状态文件风格一致）
const LOG_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("raft_log");
/// 元数据表：vote / last_purged_log_id
const META_TABLE: TableDefinition<&'static str, &[u8]> = TableDefinition::new("raft_meta");
const VOTE_KEY: &str = "vote";
const PURGED_KEY: &str = "last_purged";

/// RaftLogStorage 实现：openraft 核心任务持有（写串行），Clone 供重启复用句柄
#[derive(Clone)]
pub struct RaftLogStore {
    db: Arc<Database>,
}

/// 复制流日志读取器：只读句柄，与写路径共享同一 redb 文件
#[derive(Clone)]
pub struct RaftLogReadHandle {
    db: Arc<Database>,
}

impl RaftLogStore {
    /// 打开（或创建）日志文件；损坏 → Err（fail-closed）
    pub fn open(path: &Path) -> Result<Self, StorageError<u64>> {
        let db = Database::create(path).map_err(redb_io_err)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(Self { db: Arc::new(db) })
    }

    fn read_meta<T: serde::de::DeserializeOwned>(
        &self,
        key: &'static str,
    ) -> Result<Option<T>, StorageError<u64>> {
        let rtx = self.db.begin_read().map_err(redb_io_err)?;
        let table = match rtx.open_table(META_TABLE) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(redb_io_err(e)),
        };
        match table.get(key).map_err(redb_io_err)? {
            Some(guard) => {
                let v: T = serde_json::from_slice(guard.value()).map_err(de_io_err)?;
                Ok(Some(v))
            }
            None => Ok(None),
        }
    }
}

impl RaftLogStorage<TypeConfig> for RaftLogStore {
    type LogReader = RaftLogReadHandle;

    async fn get_log_state(&mut self) -> Result<LogState<TypeConfig>, StorageError<u64>> {
        let last_purged: Option<LogId<u64>> = self.read_meta(PURGED_KEY)?;
        let rtx = self.db.begin_read().map_err(redb_io_err)?;
        let table = match rtx.open_table(LOG_TABLE) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => {
                return Ok(LogState {
                    last_purged_log_id: last_purged,
                    last_log_id: None,
                })
            }
            Err(e) => return Err(redb_io_err(e)),
        };
        // 无空洞时最后一条即最大 index
        let last = match table.last().map_err(redb_io_err)? {
            Some((_, guard)) => {
                let entry: Entry<TypeConfig> =
                    serde_json::from_slice(guard.value()).map_err(de_io_err)?;
                Some(entry.log_id)
            }
            None => None,
        };
        // 契约：无条目时 last_log_id 回退到 last_purged（不产生 None↔Some 跳变）
        let last_log_id = last.or(last_purged);
        Ok(LogState {
            last_purged_log_id: last_purged,
            last_log_id,
        })
    }

    async fn get_log_reader(&mut self) -> Self::LogReader {
        RaftLogReadHandle {
            db: Arc::clone(&self.db),
        }
    }

    async fn save_vote(&mut self, vote: &Vote<u64>) -> Result<(), StorageError<u64>> {
        let bytes = serde_json::to_vec(vote).map_err(ser_io_err)?;
        let wtx = self.db.begin_write().map_err(redb_io_err)?;
        {
            let mut table = wtx.open_table(META_TABLE).map_err(redb_io_err)?;
            table
                .insert(VOTE_KEY, bytes.as_slice())
                .map_err(redb_io_err)?;
        }
        wtx.commit().map_err(redb_io_err)?; // commit 返回即落盘（vote 持久先于返回）
        Ok(())
    }

    async fn read_vote(&mut self) -> Result<Option<Vote<u64>>, StorageError<u64>> {
        self.read_meta(VOTE_KEY)
    }

    async fn append<I>(
        &mut self,
        entries: I,
        callback: LogFlushed<TypeConfig>,
    ) -> Result<(), StorageError<u64>>
    where
        I: IntoIterator<Item = Entry<TypeConfig>> + Send,
        I::IntoIter: Send,
    {
        let serialized: Vec<(u64, Vec<u8>)> = entries
            .into_iter()
            .map(|e| {
                let index = e.log_id.index;
                let bytes = serde_json::to_vec(&e).map_err(ser_io_err)?;
                Ok((index, bytes))
            })
            .collect::<Result<Vec<_>, StorageError<u64>>>()?;
        let wtx = self.db.begin_write().map_err(redb_io_err)?;
        {
            let mut table = wtx.open_table(LOG_TABLE).map_err(redb_io_err)?;
            for (index, bytes) in &serialized {
                table
                    .insert(*index, bytes.as_slice())
                    .map_err(redb_io_err)?;
            }
        }
        wtx.commit().map_err(redb_io_err)?;
        // redb commit 已持久，回调即通知 flush 完成
        callback.log_io_completed(Ok(()));
        Ok(())
    }

    async fn truncate(&mut self, log_id: LogId<u64>) -> Result<(), StorageError<u64>> {
        let wtx = self.db.begin_write().map_err(redb_io_err)?;
        {
            let mut table = wtx.open_table(LOG_TABLE).map_err(redb_io_err)?;
            let stale: Vec<u64> = table
                .range(log_id.index..)
                .map_err(redb_io_err)?
                .map(|res| res.map(|(k, _)| k.value()))
                .collect::<Result<_, _>>()
                .map_err(redb_io_err)?;
            for index in stale {
                table.remove(index).map_err(redb_io_err)?;
            }
        }
        wtx.commit().map_err(redb_io_err)?;
        Ok(())
    }

    async fn purge(&mut self, log_id: LogId<u64>) -> Result<(), StorageError<u64>> {
        let bytes = serde_json::to_vec(&log_id).map_err(ser_io_err)?;
        let wtx = self.db.begin_write().map_err(redb_io_err)?;
        {
            let mut log = wtx.open_table(LOG_TABLE).map_err(redb_io_err)?;
            let stale: Vec<u64> = log
                .range(..=log_id.index)
                .map_err(redb_io_err)?
                .map(|res| res.map(|(k, _)| k.value()))
                .collect::<Result<_, _>>()
                .map_err(redb_io_err)?;
            for index in stale {
                log.remove(index).map_err(redb_io_err)?;
            }
            let mut meta = wtx.open_table(META_TABLE).map_err(redb_io_err)?;
            meta.insert(PURGED_KEY, bytes.as_slice())
                .map_err(redb_io_err)?;
        }
        wtx.commit().map_err(redb_io_err)?;
        Ok(())
    }
}

impl RaftLogReader<TypeConfig> for RaftLogReadHandle {
    async fn try_get_log_entries<RB>(
        &mut self,
        range: RB,
    ) -> Result<Vec<Entry<TypeConfig>>, StorageError<u64>>
    where
        RB: RangeBounds<u64> + Clone + Send + Debug,
    {
        let rtx = self.db.begin_read().map_err(redb_io_err)?;
        let table = match rtx.open_table(LOG_TABLE) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(redb_io_err(e)),
        };
        let mut out = Vec::new();
        for res in table.range(range).map_err(redb_io_err)? {
            let (_, guard) = res.map_err(redb_io_err)?;
            out.push(serde_json::from_slice(guard.value()).map_err(de_io_err)?);
        }
        Ok(out)
    }
}

/// 存储本体实现读取（RaftLogStorage: RaftLogReader 约束），委托只读句柄
impl RaftLogReader<TypeConfig> for RaftLogStore {
    async fn try_get_log_entries<RB>(
        &mut self,
        range: RB,
    ) -> Result<Vec<Entry<TypeConfig>>, StorageError<u64>>
    where
        RB: RangeBounds<u64> + Clone + Send + Debug,
    {
        RaftLogReadHandle {
            db: Arc::clone(&self.db),
        }
        .try_get_log_entries(range)
        .await
    }
}
