//! 副本间 raft RPC 传输（REQ-070 阶段二，CONTROL_PLANE §1.2/§6 mTLS）：
//! openraft 网络/服务端适配——serde_json 载荷走长度前缀帧（复用 framing 层，
//! 上限 MAX_MESSAGE_LEN），TLS 1.3 双向认证（客户端证书必带，CA 预置）。
//! 静态成员：target id → 配置地址（BasicNode.addr 由接线层注入）。

use crate::control::BoxResult;
use crate::framing::{read_frame, write_frame};
use landscape_rill_coord::raft::TypeConfig;
use openraft::error::{RPCError, RaftError, ReplicationClosed, StreamingError, Unreachable};
use openraft::network::{RPCOption, RaftNetwork, RaftNetworkFactory};
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, SnapshotResponse, VoteRequest, VoteResponse,
};
use openraft::{BasicNode, Snapshot, SnapshotMeta, Vote};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use serde::{Deserialize, Serialize};

use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// raft RPC 请求（帧载荷 = serde_json）
#[derive(Debug, Serialize, Deserialize)]
pub enum RaftRpcRequest {
    Append(AppendEntriesRequest<TypeConfig>),
    Vote(VoteRequest<u64>),
    /// full_snapshot（generic-snapshot-data：整快照一次送达，收端 install）。
    /// Snapshot<C> 本体无 serde 派生——meta + data 拆开传输、两端重组
    InstallSnapshot {
        vote: Vote<u64>,
        meta: SnapshotMeta<u64, BasicNode>,
        data: Vec<u8>,
    },
}

/// raft RPC 应答（Error = 收端 raft 调用失败的字符串化）
#[derive(Debug, Serialize, Deserialize)]
pub enum RaftRpcResponse {
    Append(AppendEntriesResponse<u64>),
    Vote(VoteResponse<u64>),
    Snapshot(SnapshotResponse<u64>),
    Error(String),
}

/// 副本间 mTLS 材料（本副本证书 = 客户端+服务端两用；对端验证 CA）
#[derive(Clone)]
pub struct RaftTlsMaterial {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    pub ca_pem: Vec<u8>,
}

/// mTLS 服务端（客户端证书必带——无证书/非本 CA 签发 = 握手失败，fail-closed）
fn mtls_acceptor(m: &RaftTlsMaterial) -> BoxResult<TlsAcceptor> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(&m.ca_pem) {
        roots.add(cert?)?;
    }
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots)).build()?;
    let certs: Vec<_> = CertificateDer::pem_slice_iter(&m.cert_pem).collect::<Result<_, _>>()?;
    let key = PrivateKeyDer::pem_slice_iter(&m.key_pem)
        .next()
        .transpose()?
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "no key"))?;
    let config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// mTLS 客户端（携带本副本证书，验证对端 against CA）
fn mtls_connector(m: &RaftTlsMaterial) -> BoxResult<TlsConnector> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(&m.ca_pem) {
        roots.add(cert?)?;
    }
    let certs: Vec<_> = CertificateDer::pem_slice_iter(&m.cert_pem).collect::<Result<_, _>>()?;
    let key = PrivateKeyDer::pem_slice_iter(&m.key_pem)
        .next()
        .transpose()?
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "no key"))?;
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(certs, key)?;
    Ok(TlsConnector::from(Arc::new(config)))
}

/// raft RPC 服务端循环：accept（mTLS）→ 逐帧分派到本副本 raft 实例。
/// 单连接串行处理（raft RPC 天然按序）；坏帧以 Error 应答后断连
pub async fn serve_raft_rpc(
    raft: openraft::Raft<TypeConfig>,
    listener: tokio::net::TcpListener,
    material: RaftTlsMaterial,
) -> BoxResult<()> {
    let acceptor = mtls_acceptor(&material)?;
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("[coord] raft rpc accept failed: {e}");
                continue;
            }
        };
        let raft = raft.clone();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let mut tls = match acceptor.accept(tcp).await {
                Ok(t) => t,
                Err(e) => {
                    tracing::debug!("[coord] raft rpc tls handshake failed from {peer}: {e}");
                    return;
                }
            };
            loop {
                let body = match read_frame(&mut tls).await {
                    Ok(b) => b,
                    Err(_) => break, // 对端关闭 → 断连（openraft 客户端自会重连）
                };
                let req: RaftRpcRequest = match serde_json::from_slice(&body) {
                    Ok(r) => r,
                    Err(e) => {
                        let reply = serde_json::to_vec(&RaftRpcResponse::Error(format!(
                            "bad rpc frame: {e}"
                        )))
                        .unwrap_or_default();
                        let _ = write_frame(&mut tls, &reply).await;
                        break;
                    }
                };
                let resp = match req {
                    RaftRpcRequest::Append(rpc) => raft
                        .append_entries(rpc)
                        .await
                        .map(RaftRpcResponse::Append)
                        .map_err(|e| e.to_string()),
                    RaftRpcRequest::Vote(rpc) => raft
                        .vote(rpc)
                        .await
                        .map(RaftRpcResponse::Vote)
                        .map_err(|e| e.to_string()),
                    RaftRpcRequest::InstallSnapshot { vote, meta, data } => raft
                        .install_full_snapshot(
                            vote,
                            Snapshot {
                                meta,
                                snapshot: Box::new(data),
                            },
                        )
                        .await
                        .map(RaftRpcResponse::Snapshot)
                        .map_err(|e| e.to_string()),
                };
                let out = match resp {
                    Ok(r) => serde_json::to_vec(&r),
                    Err(msg) => serde_json::to_vec(&RaftRpcResponse::Error(msg)),
                };
                if write_frame(&mut tls, &out.unwrap_or_default())
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
    }
}

/// 传输失败统一为 Unreachable（openraft 对 Unreachable 走退避重试）
#[allow(clippy::result_large_err)]
fn rpc_unreachable<T>(ctx: &str) -> Result<T, RPCError<u64, BasicNode, RaftError<u64>>> {
    Err(RPCError::Unreachable(Unreachable::new(
        &std::io::Error::other(ctx),
    )))
}

/// 已认证单连接（按需建立；断连即弃，下次调用重连）。
/// 成员地址 host:port（host 可为 DNS 名——容器部署服务名解析）
struct PeerConn {
    host: String,
    port: u16,
    material: RaftTlsMaterial,
    stream: Option<TlsStream<TcpStream>>,
}

impl PeerConn {
    fn parse_addr(addr: &str) -> std::io::Result<(String, u16)> {
        let (host, port) = addr.rsplit_once(':').ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "member addr needs host:port",
            )
        })?;
        Ok((
            host.to_string(),
            port.parse::<u16>()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?,
        ))
    }

    async fn call(&mut self, req: &RaftRpcRequest) -> std::io::Result<RaftRpcResponse> {
        if self.stream.is_none() {
            let connector = mtls_connector(&self.material)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            let tcp = TcpStream::connect((self.host.as_str(), self.port)).await?;
            let name = rustls_pki_types::ServerName::try_from(self.host.clone())
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
            self.stream = Some(connector.connect(name, tcp).await?);
        }
        let stream = self.stream.as_mut().expect("just ensured");
        let body = serde_json::to_vec(req)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        if write_frame(stream, &body).await.is_err() {
            self.stream = None;
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "rpc write failed",
            ));
        }
        match read_frame(stream).await {
            Ok(reply) => serde_json::from_slice(&reply).map_err(|e| {
                self.stream = None;
                std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
            }),
            Err(e) => {
                self.stream = None; // 任何 IO 失败弃连，下次调用重连
                Err(e)
            }
        }
    }
}

/// openraft 网络工厂：静态成员（BasicNode.addr = 配置地址）
#[derive(Clone)]
pub struct RaftTlsNetworkFactory {
    material: RaftTlsMaterial,
}

impl RaftTlsNetworkFactory {
    pub fn new(material: RaftTlsMaterial) -> Self {
        Self { material }
    }
}

impl RaftNetworkFactory<TypeConfig> for RaftTlsNetworkFactory {
    type Network = RaftTlsNetwork;

    async fn new_client(&mut self, _target: u64, node: &BasicNode) -> Self::Network {
        let (host, port) = PeerConn::parse_addr(&node.addr).expect("validated at config load");
        RaftTlsNetwork {
            conn: PeerConn {
                host,
                port,
                material: self.material.clone(),
                stream: None,
            },
        }
    }
}

pub struct RaftTlsNetwork {
    conn: PeerConn,
}

impl RaftTlsNetwork {
    /// 超时取 RPCOption hard_ttl（openraft 按心跳/选主节奏构造）；超时 = 不可达
    async fn call_with_ttl(
        &mut self,
        req: &RaftRpcRequest,
        ttl: std::time::Duration,
    ) -> Result<RaftRpcResponse, String> {
        match tokio::time::timeout(ttl, self.conn.call(req)).await {
            Ok(Ok(resp)) => Ok(resp),
            Ok(Err(e)) => Err(e.to_string()),
            Err(_) => Err("rpc timeout".to_string()),
        }
    }
}

impl RaftNetwork<TypeConfig> for RaftTlsNetwork {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<TypeConfig>,
        option: RPCOption,
    ) -> Result<AppendEntriesResponse<u64>, RPCError<u64, BasicNode, RaftError<u64>>> {
        match self
            .call_with_ttl(&RaftRpcRequest::Append(rpc), option.hard_ttl())
            .await
        {
            Ok(RaftRpcResponse::Append(r)) => Ok(r),
            Ok(RaftRpcResponse::Error(e)) => rpc_unreachable(&format!("append rejected: {e}")),
            Ok(other) => rpc_unreachable(&format!("append rpc mismatched reply: {other:?}")),
            Err(e) => rpc_unreachable(&format!("append rpc failed: {e}")),
        }
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<u64>,
        option: RPCOption,
    ) -> Result<VoteResponse<u64>, RPCError<u64, BasicNode, RaftError<u64>>> {
        match self
            .call_with_ttl(&RaftRpcRequest::Vote(rpc), option.hard_ttl())
            .await
        {
            Ok(RaftRpcResponse::Vote(r)) => Ok(r),
            Ok(RaftRpcResponse::Error(e)) => rpc_unreachable(&format!("vote rejected: {e}")),
            Ok(other) => rpc_unreachable(&format!("vote rpc mismatched reply: {other:?}")),
            Err(e) => rpc_unreachable(&format!("vote rpc failed: {e}")),
        }
    }

    async fn full_snapshot(
        &mut self,
        vote: Vote<u64>,
        snapshot: Snapshot<TypeConfig>,
        _cancel: impl std::future::Future<Output = ReplicationClosed> + Send + 'static,
        option: RPCOption,
    ) -> Result<SnapshotResponse<u64>, StreamingError<TypeConfig, openraft::error::Fatal<u64>>>
    {
        let req = RaftRpcRequest::InstallSnapshot {
            vote,
            meta: snapshot.meta,
            data: *snapshot.snapshot,
        };
        match self.call_with_ttl(&req, option.hard_ttl()).await {
            Ok(RaftRpcResponse::Snapshot(r)) => Ok(r),
            Ok(RaftRpcResponse::Error(e)) => Err(snapshot_unreachable(e)),
            Ok(other) => Err(snapshot_unreachable(format!("{other:?}"))),
            Err(e) => Err(snapshot_unreachable(e)),
        }
    }
}

fn snapshot_unreachable(
    ctx: impl std::fmt::Display,
) -> StreamingError<TypeConfig, openraft::error::Fatal<u64>> {
    StreamingError::Unreachable(Unreachable::new(&std::io::Error::other(ctx.to_string())))
}

#[cfg(test)]
#[path = "raft_rpc_tests.rs"]
mod tests;
