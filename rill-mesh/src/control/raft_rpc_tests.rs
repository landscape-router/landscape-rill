//! control/raft_rpc.rs 集成测试（REQ-070 阶段二）：
//! 真实 mTLS TCP 上的 3 副本集群 + CoordinatorServer 接线——
//! - 选主收敛、注册经多数派复制（follower 本地读可见）
//! - follower 节点面 REGISTER → LeaderRedirect（携带 leader 节点面地址）
//! - 节点按重定向重连 leader 完成完整注册流（挑战/PoP/netmap）

use crate::control::client::{MeshClient, MeshLegConfig};
use crate::control::codec::read_envelope;
use crate::control::tls::{client_tls_stream, server_tls_stream};
use crate::framing;
use landscape_rill_coord::authkey::generate_auth_key;
use landscape_rill_coord::config::CoordConfig;
use landscape_rill_coord::raft::backend::Leadership;
use landscape_rill_proto::wire::control::*;
use quick_protobuf::{BytesReader, MessageRead};

/// 测试 CA + 3 张双用途（ServerAuth+ClientAuth）叶子证书（SAN 127.0.0.1）
/// (CA pem, [(cert pem, key pem) × 3])
type TestPki = (Vec<u8>, Vec<(Vec<u8>, Vec<u8>)>);

fn test_pki() -> TestPki {
    let mut ca_params = rcgen::CertificateParams::new(vec![]).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let issuer = rcgen::Issuer::new(ca_params, &ca_key);
    let mut leaves = Vec::new();
    for _ in 0..3 {
        let mut params = rcgen::CertificateParams::new(vec!["127.0.0.1".into()]).unwrap();
        params
            .subject_alt_names
            .push(rcgen::SanType::IpAddress("127.0.0.1".parse().unwrap()));
        params.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &issuer).unwrap();
        leaves.push((cert.pem().into_bytes(), key.serialize_pem().into_bytes()));
    }
    (ca.pem().into_bytes(), leaves)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cluster_leader_elects_follower_redirects_and_write_replicates() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (ca_pem, leaves) = test_pki();
    let ak = generate_auth_key("lab", 3600).unwrap();

    // 三副本配置：raft RPC 端口 + 节点面端口各自临时 bind 探明
    let mut raft_ports = Vec::new();
    let mut node_listeners = Vec::new();
    for _ in 0..3 {
        let rpc = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        raft_ports.push(rpc.local_addr().unwrap().port());
        drop(rpc);
        node_listeners.push(tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap());
    }
    let node_addrs: Vec<std::net::SocketAddr> = node_listeners
        .iter()
        .map(|l| l.local_addr().unwrap())
        .collect();

    let mut servers = Vec::new();
    for id in 0..3u64 {
        let dir = std::env::temp_dir().join(format!(
            "lrill-ha-{}-{}",
            std::process::id(),
            rand_path_suffix()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        let ca_path = dir.join("ca.pem");
        std::fs::write(&cert_path, &leaves[id as usize].0).unwrap();
        std::fs::write(&key_path, &leaves[id as usize].1).unwrap();
        std::fs::write(&ca_path, &ca_pem).unwrap();
        let storage = dir.join("coord.redb");
        let members: Vec<String> = (0..3u64)
            .map(|m| {
                format!(
                    "{{\"id\": {m}, \"addr\": \"127.0.0.1:{}\", \"advertise\": \"127.0.0.1:{}\"}}",
                    raft_ports[m as usize],
                    node_addrs[m as usize].port()
                )
            })
            .collect();
        let cfg_text = format!(
            r#"{{
  "listen_addr": "{node}",
  "tls_cert_path": "{cert}",
  "tls_key_path": "{key}",
  "signing_seed": "{seed}",
  "storage_path": "{storage}",
  "networks": [
    {{ "name": "lab", "master_key": "{master}", "auth_keys": [{{ "key": "{ak}", "policy": "reusable" }}], "announce_whitelist": ["10.0.0.0/8"] }}
  ],
  "cluster": {{
    "node_id": {id},
    "raft_listen_addr": "127.0.0.1:{raft_port}",
    "members": [{members}],
    "ca_cert_path": "{ca}"
  }}
}}"#,
            node = node_addrs[id as usize],
            cert = cert_path.display(),
            key = key_path.display(),
            seed = "22".repeat(32),
            storage = storage.display(),
            master = "11".repeat(32),
            ak = ak,
            id = id,
            raft_port = raft_ports[id as usize],
            members = members.join(","),
            ca = ca_path.display(),
        );
        let cfg = CoordConfig::parse(&cfg_text).unwrap();
        let server = crate::control::server::CoordinatorServer::from_config_cluster(&cfg)
            .await
            .unwrap();
        servers.push(std::sync::Arc::new(tokio::sync::Mutex::new(server)));
    }

    // 节点面 accept 循环（全部副本；leader 服务注册流、follower 服务重定向）
    for (i, server) in servers.iter().enumerate() {
        let mut listener = node_listeners.remove(0);
        let cert = leaves[i].0.clone();
        let key = leaves[i].1.clone();
        let srv = server.clone();
        tokio::spawn(async move {
            loop {
                let Ok(mut tls) = server_tls_stream(&mut listener, &cert, &key).await else {
                    continue;
                };
                let srv = srv.clone();
                tokio::spawn(async move {
                    let _ = srv.lock().await.handle_connection(&mut tls).await;
                });
            }
        });
    }

    // follower 节点面 REGISTER → LEADER_REDIRECT（leader 节点面地址）。
    // CI 并行负载下选举可翻转（follower 的 leader 视图可为空/滞后）：
    // 以"重定向端点回指仍自认 Leader 的成员"的稳定样本为准
    let client = MeshClient::new([0x33; 32]);
    let leg = MeshLegConfig {
        coordinator_host: "127.0.0.1".into(),
        coordinator_port: 0,
        auth_key: ak.clone(),
        static_key: [0x33; 32],
        capabilities: 0x00,
        announce_routes: vec![],
    };
    let (leader_idx, leader_endpoint) = async {
        for _ in 0..500 {
            for f in 0..servers.len() {
                let ep = match servers[f].lock().await.coordinator.leadership() {
                    Leadership::Follower {
                        leader_endpoint: Some(ep),
                        ..
                    } => ep,
                    _ => continue,
                };
                let Some(t) = node_addrs
                    .iter()
                    .position(|a| a.port().to_string() == ep.rsplit(':').next().unwrap())
                else {
                    continue;
                };
                if !matches!(
                    servers[t].lock().await.coordinator.leadership(),
                    Leadership::Leader
                ) {
                    continue;
                }
                // 该 follower 此刻有健康 leader 视图：探 REGISTER 验证重定向
                let mut tls = client_tls_stream("127.0.0.1", node_addrs[f].port(), &ca_pem)
                    .await
                    .unwrap();
                framing::write_frame(&mut tls, &client.register_request(&leg))
                    .await
                    .unwrap();
                let Ok((mt, body)) = read_envelope(&mut tls).await else {
                    drop(tls);
                    continue;
                };
                drop(tls);
                if mt != MsgType::LEADER_REDIRECT {
                    continue;
                }
                let mut reader = BytesReader::from_bytes(&body);
                let redirect = LeaderRedirect::from_reader(&mut reader, &body).unwrap();
                if redirect.leader_endpoint == ep {
                    return (t, ep);
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("10s 内未采到稳定的 follower 重定向");
    }
    .await;

    // 节点按重定向重连 leader → 完整注册流（挑战/PoP/REGISTER_RESPONSE）。
    // 目标在窗口内可能卸任再重定向：按链跟进（客户端重定向语义）
    let mut target = leader_endpoint.clone();
    let mut registered = false;
    for _hop in 0..10 {
        let port: u16 = target.rsplit(':').next().unwrap().parse().unwrap();
        let mut tls = client_tls_stream("127.0.0.1", port, &ca_pem).await.unwrap();
        framing::write_frame(&mut tls, &client.register_request(&leg))
            .await
            .unwrap();
        let (mt, body) = read_envelope(&mut tls).await.unwrap();
        match mt {
            MsgType::LEADER_REDIRECT => {
                let mut reader = BytesReader::from_bytes(&body);
                let redirect = LeaderRedirect::from_reader(&mut reader, &body).unwrap();
                assert!(!redirect.leader_endpoint.is_empty(), "重定向链端点为空");
                target = redirect.leader_endpoint.to_string();
                drop(tls);
                continue;
            }
            MsgType::CHALLENGE => {
                let owned = ChallengeOwned::try_from(body).unwrap();
                assert_eq!(owned.proto().node_id, 0, "新建类挑战 node_id=0");
                let ack = client.challenge_ack(&Challenge {
                    eph_pub: std::borrow::Cow::Borrowed(owned.proto().eph_pub.as_ref()),
                    nonce: std::borrow::Cow::Borrowed(owned.proto().nonce.as_ref()),
                    issued_at: owned.proto().issued_at,
                    node_id: owned.proto().node_id,
                });
                framing::write_frame(&mut tls, &ack).await.unwrap();
                let (mt, body) = read_envelope(&mut tls).await.unwrap();
                assert_eq!(mt, MsgType::REGISTER_RESPONSE);
                let mut reader = BytesReader::from_bytes(&body);
                let resp = RegisterResponse::from_reader(&mut reader, &body).unwrap();
                assert_eq!(resp.node_id, 1);
                registered = true;
                break;
            }
            other => panic!("注册流意外消息: {other:?}"),
        }
    }
    assert!(registered, "10 跳重定向内未完成注册");

    // 多数派复制：follower 本地读在秒级窗口内看到注册（心跳驱动 apply 推进）
    let follower_idx = (leader_idx + 1) % servers.len();
    let mut replicated = false;
    for _ in 0..300 {
        let seen = servers[follower_idx]
            .lock()
            .await
            .coordinator
            .with_coord(|c| c.node_id_by_pubkey(&client.static_pubkey()))
            .is_some();
        if seen {
            replicated = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(replicated, "follower 应经复制看到注册条目");
}

fn rand_path_suffix() -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    std::time::SystemTime::now().hash(&mut h);
    h.finish()
}
