//! Raft 复制层（REQ-070）
//!
//! openraft 0.9：全部持久写操作过共识日志（apply 顺序 = 提交顺序），
//! Coordinator 仍是 I/O-free 核心，本层只做 adapter：
//! - [log_store]：Raft 日志/vote 落 redb（独立文件）
//! - [machine]：RaftStateMachine 适配器，apply 分派到 Coordinator 既有方法；
//!   状态快照 + raft 应用指针在状态文件同事务原子写（恰好一次 apply 语义）
//! - [backend]：Single/Cluster 写路径门面（server/管理面统一入口，
//!   领导权视图驱动 LeaderRedirect，CONTROL_PLANE §3.6）
//! - [network]：单机/测试占位网络层（集群形态 = rill-mesh::control::raft_rpc mTLS）
//!
//! 边界：
//! - 配置面（auth key/白名单/ACL/relay list/网络集合）仍走配置文件 + SIGHUP，
//!   不过日志——配置权威不复制（REQ-038/040）；集群部署要求各副本 signing_seed/
//!   networks 配置一致（身份绑定验签一致性）
//! - 软状态（liveness/telemetry/echo/path 事件缓存）replica 本地，不过日志
//! - 写命令 now 显式线程化（auth key 过期判定/PathSet TTL 的确定性重放）
//!
//! 版本：v0.2（2026-10-01）

pub mod backend;
pub mod log_store;
pub mod machine;
pub mod network;

#[cfg(test)]
mod tests;

use crate::coordinator::RegisterData;
use crate::path_service::PathCandidate;
use landscape_rill_core::control::registry::RegisterError;
use landscape_rill_core::crypto::KEY_DST_LEN;
use openraft::raft::responder::OneshotResponder;
use openraft::AnyError;
use openraft::BasicNode;
use openraft::Entry;
use openraft::StorageIOError;
use openraft::TokioRuntime;
use openraft::{RaftTypeConfig, StorageError};
use serde::{Deserialize, Serialize};

/// coord 集群 TypeConfig：NodeId = 部署静态成员 id；快照数据 = CoordState 序列化字节。
/// serde 派生满足 openraft 泛型线格式的 C: Serialize/Deserialize 边界（inter-coord RPC）
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct TypeConfig;

impl RaftTypeConfig for TypeConfig {
    type D = CoordCommand;
    type R = CoordCommandResult;
    type NodeId = u64;
    type Node = BasicNode;
    type Entry = Entry<Self>;
    type SnapshotData = Vec<u8>;
    type AsyncRuntime = TokioRuntime;
    type Responder = OneshotResponder<Self>;
}

/// 过日志的写命令（C::D）。now 显式内嵌（代码库风格），apply 确定性重放
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoordCommand {
    Register {
        auth_key: String,
        static_pubkey: [u8; 32],
        capabilities: u32,
        routes: Vec<String>,
        now: u64,
    },
    Revoke {
        node_id: u32,
        now: u64,
    },
    SetEndpoints {
        node_id: u32,
        /// 本地接口地址（公网准入判定基准，REQ-062）
        local: Vec<String>,
        /// echo 回显地址（coordinator 视角观察值）
        seen: Vec<String>,
    },
    RequestPaths {
        source: u32,
        dest: u32,
        max: u32,
        now: u64,
    },
    /// relay roster 落位（REQ-062）：leader 视角提案（liveness/RTT/准入输入），
    /// apply 侧确定性执行（集合替换 + 收窄撤销 + 集合变化才 bump netmap）
    SetRelayRoster {
        network_id: u32,
        roster: Vec<u32>,
        now: u64,
    },
    RotateMasterKey {
        network: String,
        new_master_key: [u8; 32],
    },
    /// 事件驱动评估点（心跳/吊销入口）触发，不另起后台任务
    FlushRevokeRotations {
        now: u64,
    },
}

/// apply 结果（C::R）：内存态回给提案方，不落日志。
/// Noop = Blank/Membership 条目（openraft 要求每条日志条目恰一个结果）
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CoordCommandResult {
    Noop,
    Register(Result<RegisterData, RegisterError>),
    /// 吊销是否命中（未知/已吊销 node_id = false）
    Revoke(bool),
    SetEndpoints,
    RequestPaths(Vec<(PathCandidate, [u8; KEY_DST_LEN])>),
    /// 集合（无序）是否变化（netmap bump 已在 apply 内完成）
    SetRelayRoster(bool),
    RotateMasterKey,
    FlushRevokeRotations(bool),
}

/// 序列化失败 → 写侧 IO 错误（serde 边界统一收口）
pub(crate) fn ser_io_err(e: impl std::error::Error + 'static) -> StorageError<u64> {
    StorageError::IO {
        source: StorageIOError::write(AnyError::new(&e)),
    }
}

/// 反序列化失败 → 读侧 IO 错误
pub(crate) fn de_io_err(e: impl std::error::Error + 'static) -> StorageError<u64> {
    StorageError::IO {
        source: StorageIOError::read(AnyError::new(&e)),
    }
}

/// redb 错误 → 写侧 IO 错误
pub(crate) fn redb_io_err(e: impl std::error::Error + 'static) -> StorageError<u64> {
    StorageError::IO {
        source: StorageIOError::write(AnyError::new(&e)),
    }
}
