//! Raft 网络层占位（单机过日志形态）：无对端 RPC，全部方法不可达。
//! 集群形态的 inter-coord mTLS RPC 在 rill-mesh::control::raft_rpc（REQ-070 阶段二）；
//! 本模块保留给单机/测试装置（写路径仍过日志，复制面不启用）

#![allow(clippy::result_large_err)] // openraft RPCError 体积较大（外部类型）

use super::TypeConfig;
use openraft::error::{Fatal, RPCError, RaftError, ReplicationClosed, StreamingError, Unreachable};
use openraft::network::RPCOption;
use openraft::raft::AppendEntriesRequest;
use openraft::raft::AppendEntriesResponse;
use openraft::raft::SnapshotResponse;
use openraft::raft::VoteRequest;
use openraft::raft::VoteResponse;
use openraft::{BasicNode, RaftNetwork, RaftNetworkFactory, Snapshot, Vote};

/// 工厂与连接同体：单机集群下 openraft 不会调用任何 RPC 方法
#[derive(Clone, Default)]
pub struct NullNetworkFactory;

#[derive(Clone, Default)]
pub struct NullNetwork;

#[derive(Debug, thiserror::Error)]
#[error("single-node cluster: peer RPC unreachable (inter-coord network arrives in phase 2)")]
struct PeerUnreachable;

impl RaftNetworkFactory<TypeConfig> for NullNetworkFactory {
    type Network = NullNetwork;

    async fn new_client(&mut self, _target: u64, _node: &BasicNode) -> Self::Network {
        NullNetwork
    }
}

fn unreachable<T>() -> Result<T, RPCError<u64, BasicNode, RaftError<u64>>> {
    Err(RPCError::Unreachable(Unreachable::new(&PeerUnreachable)))
}

impl RaftNetwork<TypeConfig> for NullNetwork {
    async fn append_entries(
        &mut self,
        _rpc: AppendEntriesRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<AppendEntriesResponse<u64>, RPCError<u64, BasicNode, RaftError<u64>>> {
        unreachable()
    }

    async fn vote(
        &mut self,
        _rpc: VoteRequest<u64>,
        _option: RPCOption,
    ) -> Result<VoteResponse<u64>, RPCError<u64, BasicNode, RaftError<u64>>> {
        unreachable()
    }

    async fn full_snapshot(
        &mut self,
        _vote: Vote<u64>,
        _snapshot: Snapshot<TypeConfig>,
        _cancel: impl std::future::Future<Output = ReplicationClosed> + Send + 'static,
        _option: RPCOption,
    ) -> Result<SnapshotResponse<u64>, StreamingError<TypeConfig, Fatal<u64>>> {
        Err(StreamingError::Unreachable(Unreachable::new(
            &PeerUnreachable,
        )))
    }
}
