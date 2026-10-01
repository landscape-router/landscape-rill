//! 控制面客户端（runtime 驱动：注册 → 事件循环；断线由调用方重连）

use crate::control::codec::{envelope_bytes, read_envelope_buf};
use crate::control::tls::client_tls_stream;
use crate::control::{BoxResult, PROTOCOL_VERSION};
use crate::framing;
use landscape_rill_core::control::acl::{
    AclAction, AclPolicy as CoreAclPolicy, AclRule, AclSubject,
};
use landscape_rill_core::control::session::{ClientSession, SessionState};
use landscape_rill_proto::wire::control::*;
use quick_protobuf::{BytesReader, MessageRead};
use std::borrow::Cow;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tracing::error;

pub struct MeshLegConfig {
    pub coordinator_host: String,
    pub coordinator_port: u16,
    pub auth_key: String,
    pub static_key: [u8; 32],
    pub capabilities: u32,
    pub announce_routes: Vec<String>,
}

#[derive(Debug)]
pub enum MeshEvent {
    Netmap {
        version: u64,
    },
    Revoked {
        node_id: u32,
    },
    KeyDist {
        to_node_id: u32,
        key: Vec<u8>,
        key_version: u32,
    },
}

pub struct MeshClient {
    session: ClientSession,
    static_key: [u8; 32],
}

impl MeshClient {
    pub fn new(static_key: [u8; 32]) -> Self {
        Self {
            session: ClientSession::new(),
            static_key,
        }
    }

    /// 重连场景：以已注册的 node_id 恢复会话（挑战 tag 计算需要）
    pub fn with_node_id(static_key: [u8; 32], node_id: u32) -> Self {
        let mut client = Self::new(static_key);
        client.session.restore(node_id);
        client
    }

    pub fn static_pubkey(&self) -> [u8; 32] {
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(self.static_key)).to_bytes()
    }

    pub fn state(&self) -> &SessionState {
        self.session.state()
    }

    pub fn session_mut(&mut self) -> &mut ClientSession {
        &mut self.session
    }

    pub fn register_request(&self, config: &MeshLegConfig) -> Vec<u8> {
        let msg = RegisterRequest {
            auth_key: Cow::Borrowed(&config.auth_key),
            static_pubkey: Cow::Owned(self.static_pubkey().to_vec()),
            capabilities: config.capabilities,
            protocol_version: PROTOCOL_VERSION,
            hostname: Cow::Borrowed(""),
            os: Cow::Borrowed(""),
            routes: config
                .announce_routes
                .iter()
                .map(|r| Cow::Borrowed(r.as_str()))
                .collect(),
            // 构建版本元数据（REQ-052/CONTROL_PLANE §3.1）：可选，coordinator 仅展示
            version: Cow::Owned(env!("CARGO_PKG_VERSION").to_string()),
        };
        envelope_bytes(MsgType::REGISTER, &msg)
    }

    pub fn challenge_ack(&self, challenge: &Challenge<'_>) -> Vec<u8> {
        // node_id 取 Challenge 消息携带值（REQ-057）：注册响应丢失的 Fresh 态
        // 客户端尚不知道自己的 node_id，由服务端解析下发；重连场景与已知值一致
        let node_id = challenge.node_id;
        let mut eph_pub = [0u8; 32];
        eph_pub.copy_from_slice(challenge.eph_pub.as_ref());
        let tag = landscape_rill_core::control::challenge::compute_tag(
            &self.static_key,
            &eph_pub,
            challenge.nonce.as_ref(),
            node_id,
        );
        let ack = ChallengeAck {
            node_id,
            tag: Cow::Owned(tag.to_vec()),
        };
        envelope_bytes(MsgType::CHALLENGE_ACK, &ack)
    }

    /// 心跳（REQ-052）：遥测载荷可选（区间计数上报即清零；无数据时空载荷）
    pub fn heartbeat(&self, telemetry: Option<TelemetryPayload>) -> Vec<u8> {
        envelope_bytes(MsgType::HEARTBEAT, &Heartbeat { telemetry })
    }

    /// 路径请求（v1.5，CONTROL_PLANE §3.11）：请求本节点 → dest 的候选路径集
    pub fn path_request(&self, destination_node_id: u32) -> Vec<u8> {
        let msg = PathRequest {
            destination_node_id,
            max_candidates: 4,
        };
        envelope_bytes(MsgType::PATH_REQUEST, &msg)
    }

    /// BGP 动态路由上报（REQ-065，CONTROL_PLANE §3.17）：增量
    /// announced = (prefix, next_hop)；坐标端做覆盖域/数量/抖动门控
    pub fn route_sync(&self, announced: Vec<(String, String)>, withdrawn: Vec<String>) -> Vec<u8> {
        let msg = RouteSync {
            announced: announced
                .into_iter()
                .map(|(prefix, next_hop)| RouteDyn {
                    prefix: Cow::Owned(prefix),
                    next_hop: Cow::Owned(next_hop),
                })
                .collect(),
            withdrawn: withdrawn.into_iter().map(Cow::Owned).collect(),
        };
        envelope_bytes(MsgType::ROUTE_SYNC, &msg)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetmapNode {
    pub node_id: u32,
    pub network_id: u32,
    pub static_pubkey: [u8; 32],
    pub endpoints: Vec<String>,
    pub capabilities: u32,
    pub routes: Vec<String>,
    /// 协议版本（v2 路径能力协商）
    pub protocol_version: u32,
    /// 可达性标记（CTL-11）：租约超时 = true，节点路由表据此撤销其公告
    pub offline: bool,
    /// 身份绑定 + 签发锚点（REQ-049②）：对 netmap 条目交叉审计的输入
    pub identity_binding: Vec<u8>,
    pub binding_log_id: (u64, u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetmapData {
    pub version: u64,
    pub entries: Vec<NetmapNode>,
    /// 激活 relay roster（REQ-062）：有序 node_id（顺序 = 挂靠优先级）；端点查条目
    pub relay_roster: Vec<u32>,
    /// 网络级 ACL 策略（REQ-045，CONTROL_PLANE §3.10）；None = 未启用（v1 全放行）
    pub acl: Option<CoreAclPolicy>,
    /// raft 副本端点（绑定审计目标，REQ-049②）；单机 = 空
    pub replica_endpoints: Vec<String>,
}

/// 线格式策略 → rill-core 策略（REQ-045）：主体 "node:<id>"/"group:<name>"/"any"。
/// 恶形规则逐条跳过（coordinator 是鉴权权威、配置加载已校验，恶形只可能来自
/// 版本偏差），enabled 语义始终荣誉——解码缺憾不得静默关闭 default-deny
fn acl_from_wire(p: &AclPolicy) -> CoreAclPolicy {
    let subject = |s: &str| match s.strip_prefix("node:") {
        Some(id) => id.parse().ok().map(AclSubject::Node),
        None => match s.strip_prefix("group:") {
            Some(name) if !name.is_empty() => Some(AclSubject::Group(name.to_string())),
            _ if s == "any" => Some(AclSubject::Any),
            _ => None,
        },
    };
    CoreAclPolicy {
        enabled: p.enabled,
        rules: p
            .rules
            .iter()
            .filter_map(|r| {
                let prefix = landscape_rill_core::route::Prefix::parse(&r.prefix).ok()?;
                let subjects = r
                    .subjects
                    .iter()
                    .filter_map(|s| subject(s))
                    .collect::<Vec<_>>();
                // 全部主体恶形 = 规则永远不命中，跳过等价；保留部分合法主体
                if subjects.is_empty() && !r.subjects.is_empty() {
                    return None;
                }
                Some(AclRule {
                    subjects,
                    prefix,
                    action: if r.deny {
                        AclAction::Deny
                    } else {
                        AclAction::Allow
                    },
                })
            })
            .collect(),
        groups: p
            .groups
            .iter()
            .map(|g| {
                // 4B 大端序列（同 CandidatePath.hops 惯例）；截尾残字节忽略
                let ids = g
                    .node_ids
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .map(|c| u32::from_be_bytes(*c))
                    .collect();
                (g.name.to_string(), ids)
            })
            .collect(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlEvent {
    Registered {
        node_id: u32,
        network_id: u32,
        identity_binding: Vec<u8>,
        /// 签发锚点 (log_index, term)（binding v2，REQ-049②）；单机 = (0, 0)
        binding_log_id: (u64, u64),
    },
    Netmap(NetmapData),
    KeyDist {
        to_node_id: u32,
        key: Vec<u8>,
        key_version: u32,
        broadcast_key: Vec<u8>,
    },
    Lease {
        granted: bool,
        expires_at: u64,
    },
    Challenge {
        ack: Vec<u8>,
    },
    Revoked {
        node_id: u32,
    },
    /// 候选路径集（PathResponse/PathUpdate，v1.5 CONTROL_PLANE §3.11）
    Paths {
        destination_node_id: u32,
        candidates: Vec<PathCandidateMsg>,
        version: u64,
        /// 路径发起方：= 自己时路径可写入发送路径表；否则仅 key_path 授权
        source_node_id: u32,
    },
    /// 路径撤销（PathWithdraw）
    PathWithdrawn {
        destination_node_id: u32,
        path_id: u64,
    },
    /// 主重定向（§3.6，Raft 期）：follower 应答；节点重连 leader_endpoint
    /// （空端点 = 选主中，退避重试原地址）
    LeaderRedirect {
        leader_endpoint: String,
        raft_term: u64,
    },
    /// 全网动态路由表（RouteMap，REQ-065 CONTROL_PLANE §3.17）：版本变化时全量下发
    RouteMap {
        version: u64,
        /// (prefix, 源 node_id, next_hop)
        entries: Vec<(String, u32, String)>,
    },
}

/// 路径候选（control 层消息载体 → runtime 注入 MeshData）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathCandidateMsg {
    pub path_id: u64,
    pub path_epoch: u32,
    pub hops: Vec<u32>,
    pub expires_at: u64,
    pub key_path: Vec<u8>,
}

pub struct ControlSession {
    client: MeshClient,
    stream: TlsStream<TcpStream>,
    /// 持久接收缓冲：run loop select! 会取消在途 read_event future，
    /// 部分进度留在缓冲里续读（framing::read_frame_buf，取消安全）
    rbuf: bytes::BytesMut,
}

impl ControlSession {
    /// 连接 + 初始注册（一次调用完成 REGISTER 发送；事件随后由 read_event 消费）。
    /// previous_node_id：重连时传上次注册的 node_id（幂等注册/挑战路径）。
    pub async fn connect(
        host: &str,
        port: u16,
        ca_cert_pem: &[u8],
        config: &MeshLegConfig,
        previous_node_id: Option<u32>,
    ) -> BoxResult<Self> {
        let stream = client_tls_stream(host, port, ca_cert_pem).await?;
        let client = match previous_node_id {
            Some(node_id) => MeshClient::with_node_id(config.static_key, node_id),
            None => MeshClient::new(config.static_key),
        };
        let mut session = Self {
            client,
            stream,
            rbuf: bytes::BytesMut::with_capacity(4096),
        };
        session
            .send_envelope(&session.client.register_request(config))
            .await?;
        Ok(session)
    }

    pub fn client(&self) -> &MeshClient {
        &self.client
    }

    pub fn client_mut(&mut self) -> &mut MeshClient {
        &mut self.client
    }

    pub async fn send_envelope(&mut self, envelope: &[u8]) -> std::io::Result<()> {
        framing::write_frame(&mut self.stream, envelope).await
    }

    /// 优雅关闭（SIGTERM 收尾）：发 TLS close_notify，对端立即感知而非等 TCP 超时
    pub async fn close(&mut self) -> std::io::Result<()> {
        self.stream.shutdown().await
    }

    pub fn heartbeat_envelope(&self, telemetry: Option<TelemetryPayload>) -> Vec<u8> {
        self.client.heartbeat(telemetry)
    }

    /// 端点上报（数据面 UDP 地址；注册后/地址变化时发送，服务端并入 netmap）。
    /// 分列上报（REQ-062）：本地接口地址（公网准入基准）+ echo 回显 seen 地址
    pub fn endpoint_report_envelope(&self, local: Vec<String>, seen: Vec<String>) -> Vec<u8> {
        let msg = EndpointReport {
            endpoints: local.into_iter().map(Cow::Owned).collect(),
            seen: seen.into_iter().map(Cow::Owned).collect(),
        };
        envelope_bytes(MsgType::ENDPOINT_REPORT, &msg)
    }

    /// BGP 动态路由上报（REQ-065，CONTROL_PLANE §3.17）：增量
    /// announced = (prefix, next_hop)；坐标端做覆盖域/数量/抖动门控
    pub fn route_sync_envelope(
        &self,
        announced: Vec<(String, String)>,
        withdrawn: Vec<String>,
    ) -> Vec<u8> {
        self.client.route_sync(announced, withdrawn)
    }

    /// 读取一个控制面事件（阻塞读；io 错误 = 断线，调用方重连）。
    /// 取消安全（缓冲续读）：调用方 run loop 的 select! 随时丢弃在途 future
    pub async fn read_event(&mut self) -> std::io::Result<ControlEvent> {
        let (msg_type, body) = read_envelope_buf(&mut self.stream, &mut self.rbuf).await?;
        match msg_type {
            MsgType::REGISTER_RESPONSE => {
                let resp = RegisterResponseOwned::try_from(body).map_err(decoding_err)?;
                let node_id = resp.proto().node_id;
                let network_id = resp.proto().network_id;
                let identity_binding = resp.proto().identity_binding.to_vec();
                self.client
                    .session_mut()
                    .handle(
                        landscape_rill_core::control::session::SessionEvent::RegisterOk { node_id },
                    )
                    .map_err(io_err)?;
                Ok(ControlEvent::Registered {
                    node_id,
                    network_id,
                    identity_binding,
                    binding_log_id: (resp.proto().raft_log_index, resp.proto().raft_term),
                })
            }
            MsgType::NETMAP_PUSH => {
                let owned = NetmapPushOwned::try_from(body).map_err(decoding_err)?;
                let entries = owned
                    .proto()
                    .entries
                    .iter()
                    .map(|e| {
                        let mut static_pubkey = [0u8; 32];
                        static_pubkey.copy_from_slice(e.static_pubkey.as_ref());
                        NetmapNode {
                            node_id: e.node_id,
                            network_id: e.network_id,
                            static_pubkey,
                            endpoints: e.endpoints.iter().map(|s| s.to_string()).collect(),
                            capabilities: e.capabilities,
                            routes: e.routes.iter().map(|s| s.to_string()).collect(),
                            protocol_version: e.protocol_version,
                            offline: e.offline,
                            identity_binding: e.identity_binding.to_vec(),
                            binding_log_id: (e.raft_log_index, e.raft_term),
                        }
                    })
                    .collect();
                Ok(ControlEvent::Netmap(NetmapData {
                    version: owned.proto().version,
                    entries,
                    relay_roster: owned.proto().relay_roster.to_vec(),
                    acl: owned.proto().acl.as_ref().map(acl_from_wire),
                    replica_endpoints: owned
                        .proto()
                        .replica_endpoints
                        .iter()
                        .map(|s| s.to_string())
                        .collect(),
                }))
            }
            MsgType::KEY_DIST => {
                let owned = KeyDistOwned::try_from(body).map_err(decoding_err)?;
                Ok(ControlEvent::KeyDist {
                    to_node_id: owned.proto().to_node_id,
                    key: owned.proto().key.to_vec(),
                    key_version: owned.proto().key_version,
                    broadcast_key: owned.proto().broadcast_key.to_vec(),
                })
            }
            MsgType::LEASE => {
                let mut reader = BytesReader::from_bytes(&body);
                let lease = Lease::from_reader(&mut reader, &body).map_err(decoding_err)?;
                Ok(ControlEvent::Lease {
                    granted: lease.granted,
                    expires_at: lease.expires_at,
                })
            }
            MsgType::CHALLENGE => {
                let owned = ChallengeOwned::try_from(body).map_err(decoding_err)?;
                let challenge = Challenge {
                    eph_pub: Cow::Borrowed(owned.proto().eph_pub.as_ref()),
                    nonce: Cow::Borrowed(owned.proto().nonce.as_ref()),
                    issued_at: owned.proto().issued_at,
                    node_id: owned.proto().node_id,
                };
                let ack = self.client.challenge_ack(&challenge);
                Ok(ControlEvent::Challenge { ack })
            }
            MsgType::REVOKE => {
                let mut reader = BytesReader::from_bytes(&body);
                let revoke = Revoke::from_reader(&mut reader, &body).map_err(decoding_err)?;
                Ok(ControlEvent::Revoked {
                    node_id: revoke.node_id,
                })
            }
            MsgType::PATH_RESPONSE | MsgType::PATH_UPDATE => {
                let owned = match PathResponseOwned::try_from(body) {
                    Ok(o) => o,
                    Err(e) => {
                        error!("[node] PATH parse failed: {:?}", e);
                        return Err(decoding_err(e));
                    }
                };
                let candidates = owned
                    .proto()
                    .candidates
                    .iter()
                    .map(|c| PathCandidateMsg {
                        path_id: c.path_id,
                        path_epoch: c.path_epoch,
                        hops: crate::control::hops_to_vec(&c.hops),
                        expires_at: c.expires_at,
                        key_path: c.key_path.to_vec(),
                    })
                    .collect();
                Ok(ControlEvent::Paths {
                    destination_node_id: owned.proto().destination_node_id,
                    candidates,
                    version: owned.proto().path_version,
                    source_node_id: owned.proto().source_node_id,
                })
            }
            MsgType::PATH_WITHDRAW => {
                let mut reader = BytesReader::from_bytes(&body);
                let w = PathWithdraw::from_reader(&mut reader, &body).map_err(decoding_err)?;
                Ok(ControlEvent::PathWithdrawn {
                    destination_node_id: w.destination_node_id,
                    path_id: w.path_id,
                })
            }
            MsgType::PATH_PROBE | MsgType::PATH_PROBE_RESPONSE => {
                // v1.5：路径活性由数据面心跳承担，PathProbe 消息族协议已定义、运行时未启用
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unexpected path probe on control connection",
                ))
            }
            MsgType::LEADER_REDIRECT => {
                let mut reader = BytesReader::from_bytes(&body);
                let r = LeaderRedirect::from_reader(&mut reader, &body).map_err(decoding_err)?;
                Ok(ControlEvent::LeaderRedirect {
                    leader_endpoint: r.leader_endpoint.into_owned(),
                    raft_term: r.raft_term,
                })
            }
            MsgType::ROUTE_MAP => {
                let owned = RouteMapOwned::try_from(body).map_err(decoding_err)?;
                let entries = owned
                    .proto()
                    .entries
                    .iter()
                    .map(|e| (e.prefix.to_string(), e.node_id, e.next_hop.to_string()))
                    .collect();
                Ok(ControlEvent::RouteMap {
                    version: owned.proto().version,
                    entries,
                })
            }
            other => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unexpected control message {:?}", other),
            )),
        }
    }
}

/// 绑定交叉审计（REQ-049②，CONTROL_PLANE §3.16）：向任一副本发起独立
/// AUDIT_REQUEST（单连接单请求，不注册）。返回 (verdict, applied_index)；
/// verdict 取值见 AUDIT_VERDICT_* 常量
pub async fn audit_binding(
    host: &str,
    port: u16,
    ca_cert_pem: &[u8],
    node_id: u32,
    static_pubkey: &[u8; 32],
    binding: &[u8],
    anchor: (u64, u64),
) -> BoxResult<(u32, u64)> {
    use crate::control::codec::envelope_bytes;
    let mut stream = client_tls_stream(host, port, ca_cert_pem).await?;
    let req = AuditRequest {
        node_id,
        static_pubkey: Cow::Borrowed(static_pubkey.as_slice()),
        binding: Cow::Borrowed(binding),
        raft_log_index: anchor.0,
        raft_term: anchor.1,
    };
    framing::write_frame(&mut stream, &envelope_bytes(MsgType::AUDIT_REQUEST, &req)).await?;
    let mut rbuf = bytes::BytesMut::with_capacity(512);
    let (msg_type, body) = read_envelope_buf(&mut stream, &mut rbuf).await?;
    if msg_type != MsgType::AUDIT_RESPONSE {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unexpected audit reply {:?}", msg_type),
        )));
    }
    let mut reader = BytesReader::from_bytes(&body);
    let resp = AuditResponse::from_reader(&mut reader, &body).map_err(decoding_err)?;
    Ok((resp.verdict, resp.applied_index))
}

fn decoding_err(e: impl std::fmt::Debug) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{:?}", e))
}

fn io_err(e: landscape_rill_core::control::session::SessionError) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, e)
}
