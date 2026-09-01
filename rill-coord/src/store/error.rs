//! 存储域错误（redb 后端，损坏/不一致 fail-closed，REQ-037）

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
