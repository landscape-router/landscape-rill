//! 控制面服务端（coordinator 线格式胶水）：TLS accept + 信封分派 + 快照/路径推送

use crate::control::codec::{envelope_body, read_envelope, write_msg};
use crate::control::BoxResult;
use landscape_rill_coord::config::CoordConfig;
use landscape_rill_coord::coordinator::Coordinator;
use landscape_rill_core::rate::{RateCounter, RATE_SUMMARY_PERIOD};
use landscape_rill_proto::wire::control::*;
use quick_protobuf::{BytesReader, MessageRead};
use std::borrow::Cow;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

/// 单连接挑战状态（重连认证，CONTROL_PLANE §3.9）
struct ChallengeState {
    eph_priv: [u8; 32],
    nonce: Vec<u8>,
    issued_at: u64,
}

impl ChallengeState {
    fn new() -> Self {
        Self {
            eph_priv: rand::random::<[u8; 32]>(),
            nonce: rand::random::<[u8; 16]>().to_vec(),
            issued_at: unix_seconds(),
        }
    }
}

pub fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn netmap_push_message(coordinator: &Coordinator) -> NetmapPush<'static> {
    let entries = coordinator
        .netmap_snapshot()
        .into_iter()
        .map(|info| NetmapEntry {
            node_id: info.node_id,
            network_id: info.network_id,
            static_pubkey: Cow::Owned(info.static_pubkey.to_vec()),
            endpoints: info.endpoints.into_iter().map(Cow::Owned).collect(),
            capabilities: info.capabilities,
            routes: info.routes.into_iter().map(Cow::Owned).collect(),
            protocol_version: info.protocol_version,
        })
        .collect();
    NetmapPush {
        version: coordinator.netmap_version(),
        entries,
        relay_list: coordinator
            .relay_list()
            .iter()
            .map(|s| Cow::Owned(s.clone()))
            .collect(),
    }
}

fn key_dist_message(coordinator: &Coordinator, node_id: u32) -> Option<Vec<u8>> {
    let data = coordinator.key_dist(node_id)?;
    let msg = KeyDist {
        to_node_id: data.to_node_id,
        key: Cow::Owned(data.key.to_vec()),
        key_version: data.key_version,
        broadcast_key: Cow::Owned(data.broadcast_key.to_vec()),
    };
    Some(envelope_body(&msg))
}

pub struct CoordinatorServer {
    pub coordinator: Coordinator,
    /// 注册拒绝计数（LOGGING §5：周期摘要；run_coord 周期取走打印）
    pub register_rejected: RateCounter,
}

impl CoordinatorServer {
    pub fn new(master_key: [u8; 32], signing_seed: [u8; 32]) -> Self {
        Self {
            coordinator: Coordinator::new(master_key, signing_seed),
            register_rejected: RateCounter::new(RATE_SUMMARY_PERIOD),
        }
    }

    /// 管理面库 API（REQ-038，CONTROL_PLANE §3.12）：从配置构造（auth keys + 白名单）；
    /// 配置 storage_path 时打开持久化存储（REQ-037），损坏/不一致 → Err（fail-closed）
    pub fn from_config(cfg: &CoordConfig) -> BoxResult<Self> {
        let coordinator = match &cfg.storage_path {
            Some(path) => {
                Coordinator::open(std::path::Path::new(path), cfg.master_key, cfg.signing_seed)?
            }
            None => Coordinator::new(cfg.master_key, cfg.signing_seed),
        };
        let mut server = Self {
            coordinator,
            register_rejected: RateCounter::new(RATE_SUMMARY_PERIOD),
        };
        cfg.apply_to(&mut server.coordinator);
        Ok(server)
    }

    /// 管理面库 API（REQ-038）：配置重载（SIGHUP）入口，增量收敛、不中断在途连接
    pub fn apply_config(&mut self, cfg: &CoordConfig) {
        cfg.apply_to(&mut self.coordinator);
    }

    /// 注册成功/挑战通过后：全量 netmap + 逐节点 key_dst + 广播密钥（v1 全量互连）
    async fn push_snapshot<W: AsyncWriteExt + Unpin>(&self, stream: &mut W) -> BoxResult<()> {
        let push = netmap_push_message(&self.coordinator);
        write_msg(stream, MsgType::NETMAP_PUSH, &envelope_body(&push)).await?;
        let node_ids: Vec<u32> = self
            .coordinator
            .netmap_snapshot()
            .into_iter()
            .map(|n| n.node_id)
            .collect();
        for node_id in node_ids {
            if let Some(body) = key_dist_message(&self.coordinator, node_id) {
                write_msg(stream, MsgType::KEY_DIST, &body).await?;
            }
        }
        if let Some(body) = key_dist_message(&self.coordinator, 0xFFFF_FFFF) {
            write_msg(stream, MsgType::KEY_DIST, &body).await?;
        }
        Ok(())
    }

    pub async fn handle_connection(
        &mut self,
        stream: &mut tokio_rustls::server::TlsStream<TcpStream>,
    ) -> BoxResult<()> {
        let mut state = ConnectionState::default();
        loop {
            let (msg_type, body) = read_envelope(stream).await?;
            self.handle_message(&mut state, stream, msg_type, &body)
                .await?;
        }
    }

    /// 单消息处理（连接循环按消息粒度持锁；共享 coordinator 多连接场景由调用方保证互斥）。
    /// ConnectionState 保存单连接状态（注册归属/挑战），由调用方维护。
    pub async fn handle_message(
        &mut self,
        state: &mut ConnectionState,
        stream: &mut tokio_rustls::server::TlsStream<TcpStream>,
        msg_type: MsgType,
        body: &[u8],
    ) -> BoxResult<()> {
        match msg_type {
            MsgType::REGISTER => {
                let mut reader = BytesReader::from_bytes(body);
                let req = RegisterRequest::from_reader(&mut reader, body)?;
                let mut pubkey = [0u8; 32];
                pubkey.copy_from_slice(req.static_pubkey.as_ref());
                let routes: Vec<String> = if req.routes.is_empty() {
                    req.hostname
                        .as_ref()
                        .split(',')
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                        .collect()
                } else {
                    req.routes.iter().map(|r| r.to_string()).collect()
                };
                match self.coordinator.register(
                    req.auth_key.as_ref(),
                    &pubkey,
                    req.capabilities,
                    routes,
                ) {
                    Ok(data) => {
                        self.coordinator
                            .set_protocol_version(data.node_id, req.protocol_version);
                        let resp = RegisterResponse {
                            node_id: data.node_id,
                            network_id: data.network_id,
                            identity_binding: Cow::Owned(data.identity_binding),
                            leader_redirect: None,
                        };
                        write_msg(stream, MsgType::REGISTER_RESPONSE, &envelope_body(&resp))
                            .await?;
                        state.registered = Some(data.node_id);
                        self.coordinator.heartbeat(data.node_id, unix_seconds());
                        self.push_snapshot(stream).await?;
                        state.challenge = None;
                    }
                    Err(landscape_rill_core::control::registry::RegisterError::InvalidAuthKey) => {
                        // 可能的重连：auth key 失效（一次性已消费）+ 公钥已知 → 挑战认证
                        match self.coordinator.node_id_by_pubkey(&pubkey) {
                            Some(_node_id) => {
                                let ch = ChallengeState::new();
                                let msg = Challenge {
                                    eph_pub: Cow::Owned(
                                        x25519_dalek::PublicKey::from(
                                            &x25519_dalek::StaticSecret::from(ch.eph_priv),
                                        )
                                        .to_bytes()
                                        .to_vec(),
                                    ),
                                    nonce: Cow::Borrowed(&ch.nonce),
                                    issued_at: ch.issued_at,
                                };
                                write_msg(stream, MsgType::CHALLENGE, &envelope_body(&msg)).await?;
                                state.challenge = Some(ch);
                            }
                            None => {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::PermissionDenied,
                                    "unknown pubkey",
                                )
                                .into())
                            }
                        }
                    }
                    Err(e) => {
                        // 逐条输出 → 周期摘要（LOGGING §5；run_coord 打印）
                        self.register_rejected.tick();
                        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e).into());
                    }
                }
            }
            MsgType::CHALLENGE_ACK => {
                let mut reader = BytesReader::from_bytes(body);
                let ack = ChallengeAck::from_reader(&mut reader, body)?;
                let node_id = ack.node_id;
                let Some(entry_pub) = self.coordinator.static_pubkey_of(node_id) else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "unknown node in challenge ack",
                    )
                    .into());
                };
                let Some(ch) = state.challenge.as_ref() else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "unexpected challenge ack",
                    )
                    .into());
                };
                let ok = landscape_rill_core::control::challenge::verify_tag(
                    &entry_pub,
                    &ch.eph_priv,
                    &ch.nonce,
                    node_id,
                    ack.tag.as_ref(),
                ) && landscape_rill_core::control::challenge::within_window(
                    ch.issued_at,
                    unix_seconds(),
                    30,
                );
                if !ok {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "challenge failed",
                    )
                    .into());
                }
                state.registered = Some(node_id);
                self.coordinator.heartbeat(node_id, unix_seconds());
                self.push_snapshot(stream).await?;
                state.challenge = None;
            }
            MsgType::HEARTBEAT => {
                let mut reader = BytesReader::from_bytes(body);
                let _ = Heartbeat::from_reader(&mut reader, body)?;
                if let Some(node_id) = state.registered {
                    self.coordinator.heartbeat(node_id, unix_seconds());
                    // 周期收敛：端点/离线等软状态随心跳广播（v1 无增量推送）
                    self.push_snapshot(stream).await?;
                    // 路径事件推送（v1.5，CONTROL_PLANE §3.11）：PathUpdate/PathWithdraw
                    self.push_path_events(stream, node_id).await?;
                    let lease = Lease {
                        granted: true,
                        expires_at: unix_seconds() + 60,
                    };
                    write_msg(stream, MsgType::LEASE, &envelope_body(&lease)).await?;
                }
            }
            MsgType::PATH_REQUEST => {
                let mut reader = BytesReader::from_bytes(body);
                let req = PathRequest::from_reader(&mut reader, body)?;
                let Some(source) = state.registered else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "path request before registration",
                    )
                    .into());
                };
                let _ = self.coordinator.request_paths(
                    source,
                    req.destination_node_id,
                    req.max_candidates,
                );
                // 响应不下发：路径集事件走心跳推送通道（push_path_events），
                // 与 NETMAP/LEASE 同批次写入——即时写回在并发下不可靠
            }
            MsgType::PATH_PROBE
            | MsgType::PATH_PROBE_RESPONSE
            | MsgType::PATH_UPDATE
            | MsgType::PATH_WITHDRAW => {
                // 节点↔节点 PathProbe 走数据面语义（活性由数据面心跳承担，v1.5）；
                // PathUpdate/PathWithdraw 为 coordinator → 节点单向推送，不收
                let _ = body;
            }
            MsgType::ENDPOINT_REPORT => {
                let mut reader = BytesReader::from_bytes(body);
                let report = EndpointReport::from_reader(&mut reader, body)?;
                if let Some(node_id) = state.registered {
                    let endpoints: Vec<String> =
                        report.endpoints.iter().map(|s| s.to_string()).collect();
                    if !endpoints.is_empty() {
                        self.coordinator.set_endpoints(node_id, endpoints);
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// 心跳推送：该节点（source 身份）的未推送路径事件（PathUpdate/PathWithdraw）
    async fn push_path_events<W: AsyncWriteExt + Unpin>(
        &mut self,
        stream: &mut W,
        source: u32,
    ) -> BoxResult<()> {
        let events = self.coordinator.take_path_events(source);
        for event in events {
            match event {
                landscape_rill_coord::path_service::PathEvent::Update {
                    source: src,
                    dest,
                    set,
                } => {
                    let msg = PathUpdate {
                        destination_node_id: dest,
                        candidates: set
                            .candidates
                            .iter()
                            .map(|c| CandidatePath {
                                path_id: c.path_id,
                                path_epoch: c.path_epoch,
                                hops: Cow::Owned(crate::control::hops_bytes(&c.hops)),
                                expires_at: c.expires_at,
                                key_path: Cow::Owned(
                                    self.coordinator
                                        .key_path_for(c.path_id, c.path_epoch)
                                        .to_vec(),
                                ),
                            })
                            .collect(),
                        path_version: set.version,
                        source_node_id: src,
                    };
                    write_msg(stream, MsgType::PATH_UPDATE, &envelope_body(&msg)).await?;
                }
                landscape_rill_coord::path_service::PathEvent::Withdraw { dest, path_id } => {
                    let msg = PathWithdraw {
                        destination_node_id: dest,
                        path_id,
                        path_version: 0,
                    };
                    write_msg(stream, MsgType::PATH_WITHDRAW, &envelope_body(&msg)).await?;
                }
            }
        }
        Ok(())
    }
}

/// 单连接状态：注册归属 + 重连挑战（由连接循环维护，与 coordinator 互斥解耦）
#[derive(Default)]
pub struct ConnectionState {
    pub registered: Option<u32>,
    challenge: Option<ChallengeState>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::client::{MeshClient, MeshLegConfig};
    use crate::control::codec::read_envelope;
    use crate::control::tls::{client_tls_stream, server_tls_stream};
    use crate::framing;
    use landscape_rill_coord::signer::verify_binding;
    use landscape_rill_core::control::registry::AuthKeyPolicy;

    fn ca_pair() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut params = rcgen::CertificateParams::new(vec!["coord.test".into()]).unwrap();
        params
            .subject_alt_names
            .push(rcgen::SanType::IpAddress("127.0.0.1".parse().unwrap()));
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let ca = params.self_signed(&key_pair).unwrap();
        (
            ca.pem().into_bytes(),
            ca.pem().into_bytes(),
            key_pair.serialize_pem().into_bytes(),
        )
    }

    #[tokio::test]
    async fn register_over_tls_loopback() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (ca_cert, cert, key) = ca_pair();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let master = [0x11; 32];
        let seed = [0x22; 32];
        let ak_loop = landscape_rill_coord::authkey::generate_auth_key("lab", 3600).unwrap();
        let ak_server = ak_loop.clone();
        let server = tokio::spawn(async move {
            let mut listener = listener;
            let mut tls = server_tls_stream(&mut listener, &cert, &key).await.unwrap();
            let mut server = CoordinatorServer::new(master, seed);
            server
                .coordinator
                .add_auth_key(&ak_server, AuthKeyPolicy::OneTime);
            server.handle_connection(&mut tls).await.unwrap();
        });

        let host = addr.ip().to_string();
        let mut tls = client_tls_stream(&host, addr.port(), &ca_cert)
            .await
            .unwrap();
        let client = MeshClient::new([0x33; 32]);
        let config = MeshLegConfig {
            coordinator_host: host,
            coordinator_port: addr.port(),
            auth_key: ak_loop.clone(),
            static_key: [0x33; 32],
            capabilities: 0x01,
            announce_routes: vec![],
        };
        let reg = client.register_request(&config);
        framing::write_frame(&mut tls, &reg).await.unwrap();
        let (mt, body) = read_envelope(&mut tls).await.unwrap();
        assert_eq!(mt, MsgType::REGISTER_RESPONSE);
        let mut reader = BytesReader::from_bytes(&body);
        let resp = RegisterResponse::from_reader(&mut reader, &body).unwrap();
        assert_eq!(resp.node_id, 1);
        assert_eq!(resp.network_id, 1);
        let (mt2, body2) =
            tokio::time::timeout(std::time::Duration::from_secs(2), read_envelope(&mut tls))
                .await
                .expect("timeout waiting for second message")
                .unwrap();
        assert_eq!(mt2, MsgType::NETMAP_PUSH);
        let mut reader2 = BytesReader::from_bytes(&body2);
        let push = NetmapPush::from_reader(&mut reader2, &body2).unwrap();
        assert_eq!(push.entries.len(), 1);
        assert_eq!(push.entries[0].node_id, 1);
        drop(server);
    }

    #[test]
    fn binding_verifies_with_ed25519() {
        use landscape_rill_core::control::registry::IdentitySigner;
        let signer = landscape_rill_coord::signer::Ed25519Signer::new([0x99; 32]);
        let msg = landscape_rill_core::control::registry::binding_message(7, &[0x42; 32]);
        let sig = signer.sign(&msg);
        assert!(verify_binding(&signer.verifier(), 7, &[0x42; 32], &sig));
    }
}
