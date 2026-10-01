//! 写路径单一门面（REQ-070 阶段二）：CoordinatorServer/管理面对 Coordinator 的
//! 全部访问经本枚举分派——
//! - Single：单机形态，直接调用（行为与既有完全一致）
//! - Cluster：持久写经日志提案（apply 后生效，多数派复制）；读走本副本已 apply
//!   状态（v1 本地读语义）；配置面/软状态本地变更（with_coord_mut）
//!
//! 领导权（CONTROL_PLANE §3.6 LeaderRedirect）：follower 收到节点连接时由调用方
//! 据领导权视图重定向。

use crate::coordinator::{Coordinator, RegisterData};
use crate::path_service::PathCandidate;
use crate::raft::machine::SharedStateMachine;
use crate::raft::{CoordCommand, CoordCommandResult, TypeConfig};
use landscape_rill_core::control::registry::RegisterError;
use landscape_rill_core::crypto::KEY_DST_LEN;
use openraft::error::ClientWriteError;
use openraft::Raft;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// 本副本领导权视图：follower 携带可提示的 leader 端点（选举中 = None）
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Leadership {
    Leader,
    Follower {
        leader_endpoint: Option<String>,
        /// 当前任期（LeaderRedirect 线格式携带，节点可丢弃过期重定向）
        term: u64,
    },
}

/// 写路径错误：Local = 业务拒绝（单机同型）；Forward = 非主（携 leader 提示）；
/// Raft = 共识层致命错误（字符串化——调用方只区分"不可写"）
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteError<E> {
    Local(E),
    Forward { leader_endpoint: Option<String> },
    Raft(String),
}

/// 提案错误（仅 Forward/Raft 可达）→ 任意业务错误型的写错误
impl WriteError<std::convert::Infallible> {
    fn into_err<E>(self) -> WriteError<E> {
        match self {
            WriteError::Local(i) => match i {},
            WriteError::Forward { leader_endpoint } => WriteError::Forward { leader_endpoint },
            WriteError::Raft(s) => WriteError::Raft(s),
        }
    }
}

/// 静态成员表（id → 对外 raft RPC 地址），leader 提示用
pub type Members = Arc<HashMap<u64, String>>;

#[derive(Clone)]
pub enum CoordBackend {
    /// 单机形态：Coordinator 由外部串行化（server 互斥锁）
    Single(Arc<Mutex<Coordinator>>),
    Cluster {
        raft: Raft<TypeConfig>,
        machine: SharedStateMachine,
        members: Members,
        self_id: u64,
    },
}

impl CoordBackend {
    pub fn single(coordinator: Coordinator) -> Self {
        Self::Single(Arc::new(Mutex::new(coordinator)))
    }

    /// 本地读（集群 = 本副本已 apply 状态；闭包 I/O-free，锁为叶级）
    pub fn with_coord<R>(&self, f: impl FnOnce(&Coordinator) -> R) -> R {
        match self {
            Self::Single(c) => f(&c.lock().unwrap()),
            Self::Cluster { machine, .. } => machine.with(|m| f(m.coordinator())),
        }
    }

    /// 配置面/软状态本地写（SIGHUP 重载、心跳、遥测、relay RTT——不过日志）
    pub fn with_coord_mut<R>(&self, f: impl FnOnce(&mut Coordinator) -> R) -> R {
        match self {
            Self::Single(c) => f(&mut c.lock().unwrap()),
            Self::Cluster { machine, .. } => machine.with_coordinator_mut(f),
        }
    }

    /// 领导权视图：Single 恒 Leader；Cluster 看 openraft metrics
    pub fn leadership(&self) -> Leadership {
        match self {
            Self::Single(_) => Leadership::Leader,
            Self::Cluster {
                raft,
                members,
                self_id,
                ..
            } => {
                let metrics = raft.metrics();
                let m = metrics.borrow();
                match m.current_leader {
                    Some(id) if id == *self_id => Leadership::Leader,
                    Some(id) => Leadership::Follower {
                        leader_endpoint: members.get(&id).cloned(),
                        term: m.current_term,
                    },
                    None => Leadership::Follower {
                        leader_endpoint: None,
                        term: m.current_term,
                    },
                }
            }
        }
    }

    /// 提案 + 结果解包；ForwardToLeader 映射为端点提示
    async fn propose(
        &self,
        cmd: CoordCommand,
    ) -> Result<CoordCommandResult, WriteError<std::convert::Infallible>> {
        let Self::Cluster { raft, members, .. } = self else {
            unreachable!("single mode dispatches without propose")
        };
        let res = raft.client_write(cmd).await.map_err(|e| match e {
            openraft::error::RaftError::APIError(ClientWriteError::ForwardToLeader(ftl)) => {
                WriteError::<std::convert::Infallible>::Forward {
                    leader_endpoint: ftl.leader_id.and_then(|id| members.get(&id).cloned()),
                }
            }
            other => WriteError::Raft(other.to_string()),
        })?;
        Ok(res.data)
    }

    /// 持久写：注册准入（单机直接调用 / 集群过日志）
    pub async fn register(
        &self,
        auth_key: &str,
        static_pubkey: &[u8; 32],
        capabilities: u32,
        routes: Vec<String>,
        now: u64,
    ) -> Result<RegisterData, WriteError<RegisterError>> {
        match self {
            Self::Single(_) => self
                .with_coord_mut(|c| c.register(auth_key, static_pubkey, capabilities, routes, now))
                .map_err(WriteError::Local),
            Self::Cluster { .. } => match self
                .propose(CoordCommand::Register {
                    auth_key: auth_key.to_string(),
                    static_pubkey: *static_pubkey,
                    capabilities,
                    routes,
                    now,
                })
                .await
            {
                Ok(CoordCommandResult::Register(r)) => r.map_err(WriteError::Local),
                Ok(other) => Err(WriteError::Raft(format!("unexpected result: {other:?}"))),
                Err(e) => Err(e.into_err()),
            },
        }
    }

    /// 持久写：吊销（返回是否命中；判定与 machine apply 同型——条目存在即命中）
    pub async fn revoke(&self, node_id: u32, now: u64) -> Result<bool, WriteError<bool>> {
        match self {
            Self::Single(_) => Ok(self.with_coord_mut(|c| {
                let hit = c.static_pubkey_of(node_id).is_some();
                c.revoke(node_id, now);
                hit
            })),
            Self::Cluster { .. } => match self.propose(CoordCommand::Revoke { node_id, now }).await
            {
                Ok(CoordCommandResult::Revoke(hit)) => Ok(hit),
                Ok(other) => Err(WriteError::Raft(format!("unexpected result: {other:?}"))),
                Err(e) => Err(e.into_err()),
            },
        }
    }

    /// 持久写：端点上报
    pub async fn set_endpoints(
        &self,
        node_id: u32,
        endpoints: Vec<String>,
    ) -> Result<(), WriteError<()>> {
        match self {
            Self::Single(_) => {
                self.with_coord_mut(|c| c.set_endpoints(node_id, endpoints));
                Ok(())
            }
            Self::Cluster { .. } => match self
                .propose(CoordCommand::SetEndpoints { node_id, endpoints })
                .await
            {
                Ok(CoordCommandResult::SetEndpoints) => Ok(()),
                Ok(other) => Err(WriteError::Raft(format!("unexpected result: {other:?}"))),
                Err(e) => Err(e.into_err()),
            },
        }
    }

    /// 持久写：路径请求（返回候选集；调用方现不消费结果，保留形状）
    pub async fn request_paths(
        &self,
        source: u32,
        dest: u32,
        max: u32,
        now: u64,
    ) -> Result<Vec<(PathCandidate, [u8; KEY_DST_LEN])>, WriteError<()>> {
        match self {
            Self::Single(_) => Ok(self.with_coord_mut(|c| c.request_paths(source, dest, max, now))),
            Self::Cluster { .. } => match self
                .propose(CoordCommand::RequestPaths {
                    source,
                    dest,
                    max,
                    now,
                })
                .await
            {
                Ok(CoordCommandResult::RequestPaths(v)) => Ok(v),
                Ok(other) => Err(WriteError::Raft(format!("unexpected result: {other:?}"))),
                Err(e) => Err(e.into_err()),
            },
        }
    }

    /// 持久写：显式主密钥轮换
    pub async fn rotate_master_key(
        &self,
        network: &str,
        new_master_key: [u8; 32],
    ) -> Result<(), WriteError<()>> {
        match self {
            Self::Single(_) => {
                self.with_coord_mut(|c| c.rotate_master_key(network, new_master_key));
                Ok(())
            }
            Self::Cluster { .. } => match self
                .propose(CoordCommand::RotateMasterKey {
                    network: network.to_string(),
                    new_master_key,
                })
                .await
            {
                Ok(CoordCommandResult::RotateMasterKey) => Ok(()),
                Ok(other) => Err(WriteError::Raft(format!("unexpected result: {other:?}"))),
                Err(e) => Err(e.into_err()),
            },
        }
    }

    /// 持久写：合并轮换窗口冲刷（返回是否发生轮换）
    pub async fn flush_revoke_rotations(&self, now: u64) -> Result<bool, WriteError<bool>> {
        match self {
            Self::Single(_) => Ok(self.with_coord_mut(|c| c.flush_revoke_rotations(now))),
            Self::Cluster { .. } => {
                match self
                    .propose(CoordCommand::FlushRevokeRotations { now })
                    .await
                {
                    Ok(CoordCommandResult::FlushRevokeRotations(r)) => Ok(r),
                    Ok(other) => Err(WriteError::Raft(format!("unexpected result: {other:?}"))),
                    Err(e) => Err(e.into_err()),
                }
            }
        }
    }
}
