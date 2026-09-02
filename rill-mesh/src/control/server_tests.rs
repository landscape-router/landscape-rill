//! control/server.rs 单元测试（CTL-13/17/18/19/20 + REQ-047/REQ-057/REQ-060）

use super::*;
use crate::control::client::{MeshClient, MeshLegConfig};
use crate::control::codec::envelope_bytes;
use crate::control::codec::read_envelope;
use crate::control::tls::{client_tls_stream, server_tls_stream};
use crate::control::PROTOCOL_VERSION;
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
    let owned = answer_challenge(&mut tls, &client).await;
    assert_eq!(
        owned.proto().node_id,
        0,
        "新建类挑战 node_id=0（身份在 PoP 后的准入时分配）"
    );
    let (mt, body) = read_envelope(&mut tls).await.unwrap();
    assert_eq!(mt, MsgType::REGISTER_RESPONSE);
    let mut reader = BytesReader::from_bytes(&body);
    let resp = RegisterResponse::from_reader(&mut reader, &body).unwrap();
    assert_eq!(resp.node_id, 1);
    assert_eq!(
        resp.network_id,
        landscape_rill_coord::domain::network_id_for("lab")
    );
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
    assert!(
        !push.entries[0].offline,
        "在线节点可达性标记为 false（CTL-11 wire 贯通）"
    );
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

// ==================== 控制面限速/准入（REQ-047，SEC-19/SEC-20） ====================

fn bad_leg_config(auth_key: &str, seed: u8) -> MeshLegConfig {
    MeshLegConfig {
        coordinator_host: String::new(),
        coordinator_port: 0,
        auth_key: auth_key.into(),
        static_key: [seed; 32],
        capabilities: 0x01,
        announce_routes: vec![],
    }
}

/// 读取 CHALLENGE 并回 ack（REQ-060：所有注册先过挑战）；返回挑战内容供断言
async fn answer_challenge<RW>(tls: &mut RW, client: &MeshClient) -> ChallengeOwned
where
    RW: tokio::io::AsyncReadExt + tokio::io::AsyncWriteExt + Unpin,
{
    let (mt, body) = read_envelope(tls).await.unwrap();
    assert_eq!(mt, MsgType::CHALLENGE, "注册必须先收到挑战（REQ-060）");
    let owned = ChallengeOwned::try_from(body).unwrap();
    let challenge = Challenge {
        eph_pub: Cow::Borrowed(owned.proto().eph_pub.as_ref()),
        nonce: Cow::Borrowed(owned.proto().nonce.as_ref()),
        issued_at: owned.proto().issued_at,
        node_id: owned.proto().node_id,
    };
    let ack = client.challenge_ack(&challenge);
    framing::write_frame(tls, &ack).await.unwrap();
    owned
}

/// 连接级消息限速（REQ-047）：桶空 → 断连该连接（SEC-19 速率维度）
#[tokio::test]
async fn conn_message_flood_disconnects() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (ca_cert, cert, key) = ca_pair();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let master = [0x11; 32];
    let seed = [0x22; 32];
    let server = tokio::spawn(async move {
        let mut listener = listener;
        let mut tls = server_tls_stream(&mut listener, &cert, &key).await.unwrap();
        let mut server = CoordinatorServer::new(master, seed);
        let r = server.handle_connection(&mut tls).await;
        assert!(r.is_err(), "消息洪泛超桶容量必须断连");
        // 推进 1s 摘要窗口（LOGGING §5）取计数
        let later = std::time::Instant::now() + RATE_SUMMARY_PERIOD;
        assert!(server.rate_limited.poll(later).unwrap_or(0) >= 1);
    });
    let host = addr.ip().to_string();
    let mut tls = client_tls_stream(&host, addr.port(), &ca_cert)
        .await
        .unwrap();
    let client = MeshClient::new([0x44; 32]);
    // 未注册心跳 = 无操作消息：纯测连接级限速
    for _ in 0..(CONN_MSG_CAPACITY as usize + 10) {
        framing::write_frame(&mut tls, &client.heartbeat())
            .await
            .unwrap();
    }
    let r = read_envelope(&mut tls).await;
    assert!(r.is_err(), "服务端断连后客户端应读到 EOF");
    server.await.unwrap();
}

/// auth key 爆破锁定（REQ-047/SEC-20）：连续失败（未知 key + 未知 pubkey）
/// 达阈值 → 源 IP 锁定，后续连接注册直接拒绝
#[tokio::test]
async fn register_failures_lockout_after_repeated_bad_keys() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (ca_cert, cert, key) = ca_pair();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let master = [0x11; 32];
    let seed = [0x22; 32];
    let server = tokio::spawn(async move {
        let mut listener = listener;
        let mut server = CoordinatorServer::new(master, seed);
        for _ in 0..=REGISTER_LOCKOUT_FAILS {
            let mut tls = server_tls_stream(&mut listener, &cert, &key).await.unwrap();
            assert!(server.handle_connection(&mut tls).await.is_err());
        }
        let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        assert!(server.register_locked(ip, std::time::Instant::now()));
    });
    let host = addr.ip().to_string();
    for i in 0..=REGISTER_LOCKOUT_FAILS {
        let mut tls = client_tls_stream(&host, addr.port(), &ca_cert)
            .await
            .unwrap();
        // 每次不同未知 pubkey + 垃圾 key：全部走失败路径（无挑战资格）
        let client = MeshClient::new([0x50 + i as u8; 32]);
        let reg = client.register_request(&bad_leg_config("lrk-lab-0-badbadbad", 0x50 + i as u8));
        framing::write_frame(&mut tls, &reg).await.unwrap();
        assert!(
            read_envelope(&mut tls).await.is_err(),
            "失败/锁定注册都应被断连"
        );
    }
    server.await.unwrap();
}

/// 心跳超频忽略（REQ-047）：间隔不足 → 零成本跳过（无快照/LEASE 推送），
/// 正常心跳（≥ 最小间隔）照常处理
#[tokio::test]
async fn heartbeat_overspeed_ignored() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (ca_cert, cert, key) = ca_pair();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let master = [0x11; 32];
    let seed = [0x22; 32];
    let ak = landscape_rill_coord::authkey::generate_auth_key("lab", 3600).unwrap();
    let ak_server = ak.clone();
    let server = tokio::spawn(async move {
        let mut listener = listener;
        let mut tls = server_tls_stream(&mut listener, &cert, &key).await.unwrap();
        let mut server = CoordinatorServer::new(master, seed);
        server
            .coordinator
            .add_auth_key(&ak_server, AuthKeyPolicy::Reusable);
        let _ = server.handle_connection(&mut tls).await;
    });
    let host = addr.ip().to_string();
    let mut tls = client_tls_stream(&host, addr.port(), &ca_cert)
        .await
        .unwrap();
    let client = MeshClient::new([0x33; 32]);
    let reg = client.register_request(&bad_leg_config(&ak, 0x33));
    framing::write_frame(&mut tls, &reg).await.unwrap();
    answer_challenge(&mut tls, &client).await;
    // 消费注册响应 + 初始快照（NETMAP_PUSH + KEY_DIST）
    assert_eq!(
        read_envelope(&mut tls).await.unwrap().0,
        MsgType::REGISTER_RESPONSE
    );
    while read_envelope(&mut tls).await.unwrap().0 != MsgType::KEY_DIST {}
    // 心跳 1（首个，间隔充分）→ 快照 + LEASE 推送
    framing::write_frame(&mut tls, &client.heartbeat())
        .await
        .unwrap();
    while read_envelope(&mut tls).await.unwrap().0 != MsgType::LEASE {}
    // 心跳 2（紧随其后，< 最小间隔）→ 忽略：无任何推送
    framing::write_frame(&mut tls, &client.heartbeat())
        .await
        .unwrap();
    let r = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        read_envelope(&mut tls),
    )
    .await;
    assert!(r.is_err(), "超频心跳不应产生推送");
    drop(tls);
    let _ = server.await;
}

/// REQ-057/060：首注册（新建类，key 消费在 PoP 后）→ 响应丢弃等价重启 →
/// 重发已消费 key 进恢复类 → 挑战携带 node_id → 按消息 node_id 计算 tag →
/// 验证通过按条目补发 REGISTER_RESPONSE（同 node_id，无新注册）
#[tokio::test]
async fn register_ack_loss_challenge_recovery() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (ca_cert, cert, key) = ca_pair();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let master = [0x11; 32];
    let seed = [0x22; 32];
    let ak_loop = landscape_rill_coord::authkey::generate_auth_key("lab", 3600).unwrap();
    let ak_server = ak_loop.clone();
    let coordinator = std::sync::Arc::new(tokio::sync::Mutex::new({
        let mut server = CoordinatorServer::new(master, seed);
        server
            .coordinator
            .add_auth_key(&ak_server, AuthKeyPolicy::OneTime);
        server
    }));
    let cert_key = cert;
    let server = tokio::spawn(async move {
        let mut listener = listener;
        for _ in 0..2 {
            let mut tls = server_tls_stream(&mut listener, &cert_key, &key)
                .await
                .unwrap();
            let mut server = coordinator.lock().await;
            let _ = server.handle_connection(&mut tls).await;
        }
    });
    let host = addr.ip().to_string();

    // 连接 1：正常注册消费 one-time key；客户端读走响应后丢弃会话
    let mut tls1 = client_tls_stream(&host, addr.port(), &ca_cert)
        .await
        .unwrap();
    let c1 = MeshClient::new([0x33; 32]);
    let config = MeshLegConfig {
        coordinator_host: host.clone(),
        coordinator_port: addr.port(),
        auth_key: ak_loop.clone(),
        static_key: [0x33; 32],
        capabilities: 0x01,
        announce_routes: vec![],
    };
    framing::write_frame(&mut tls1, &c1.register_request(&config))
        .await
        .unwrap();
    answer_challenge(&mut tls1, &c1).await;
    let (mt, _body) = read_envelope(&mut tls1).await.unwrap();
    assert_eq!(mt, MsgType::REGISTER_RESPONSE);
    drop(tls1);

    // 连接 2：Fresh 客户端（同静态密钥 = ack 丢失/重启等价）重发同一已消费 key
    // → 恢复类（pubkey 命中）：仍须挑战，验证通过按条目恢复原身份
    let mut tls2 = client_tls_stream(&host, addr.port(), &ca_cert)
        .await
        .unwrap();
    let c2 = MeshClient::new([0x33; 32]);
    framing::write_frame(&mut tls2, &c2.register_request(&config))
        .await
        .unwrap();
    let (mt2, body2) = read_envelope(&mut tls2).await.unwrap();
    assert_eq!(mt2, MsgType::CHALLENGE);
    let mut reader2 = BytesReader::from_bytes(&body2);
    let ch = Challenge::from_reader(&mut reader2, &body2).unwrap();
    assert_eq!(ch.node_id, 1, "挑战必须携带服务端解析的 node_id");
    let ack = c2.challenge_ack(&ch);
    framing::write_frame(&mut tls2, &ack).await.unwrap();
    let (mt3, body3) = read_envelope(&mut tls2).await.unwrap();
    assert_eq!(mt3, MsgType::REGISTER_RESPONSE, "挑战通过后补发注册响应");
    let mut reader3 = BytesReader::from_bytes(&body3);
    let resp = RegisterResponse::from_reader(&mut reader3, &body3).unwrap();
    assert_eq!(resp.node_id, 1, "恢复保持原 node_id，无新注册");
    assert_eq!(
        resp.network_id,
        landscape_rill_coord::domain::network_id_for("lab")
    );
    assert!(!resp.identity_binding.is_empty());
    drop(tls2);
    server.await.unwrap();
}

/// REQ-057：坏 tag → 挑战失败断连（持有证明不通过）
#[tokio::test]
async fn register_ack_loss_challenge_bad_tag_rejected() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (ca_cert, cert, key) = ca_pair();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let ak_loop = landscape_rill_coord::authkey::generate_auth_key("lab", 3600).unwrap();
    let ak_server = ak_loop.clone();
    let coordinator = std::sync::Arc::new(tokio::sync::Mutex::new({
        let mut server = CoordinatorServer::new([0x11; 32], [0x22; 32]);
        server
            .coordinator
            .add_auth_key(&ak_server, AuthKeyPolicy::OneTime);
        server
    }));
    let server = tokio::spawn(async move {
        let mut listener = listener;
        for _ in 0..2 {
            let mut tls = server_tls_stream(&mut listener, &cert, &key).await.unwrap();
            let mut server = coordinator.lock().await;
            let _ = server.handle_connection(&mut tls).await;
        }
    });
    let host = addr.ip().to_string();

    let mut tls1 = client_tls_stream(&host, addr.port(), &ca_cert)
        .await
        .unwrap();
    let c1 = MeshClient::new([0x33; 32]);
    let config = MeshLegConfig {
        coordinator_host: host.clone(),
        coordinator_port: addr.port(),
        auth_key: ak_loop.clone(),
        static_key: [0x33; 32],
        capabilities: 0x01,
        announce_routes: vec![],
    };
    framing::write_frame(&mut tls1, &c1.register_request(&config))
        .await
        .unwrap();
    answer_challenge(&mut tls1, &c1).await;
    let (mt, _) = read_envelope(&mut tls1).await.unwrap();
    assert_eq!(mt, MsgType::REGISTER_RESPONSE);
    drop(tls1);

    let mut tls2 = client_tls_stream(&host, addr.port(), &ca_cert)
        .await
        .unwrap();
    let c2 = MeshClient::new([0x33; 32]);
    framing::write_frame(&mut tls2, &c2.register_request(&config))
        .await
        .unwrap();
    let (mt2, body2) = read_envelope(&mut tls2).await.unwrap();
    assert_eq!(mt2, MsgType::CHALLENGE);
    let mut reader2 = BytesReader::from_bytes(&body2);
    let ch = Challenge::from_reader(&mut reader2, &body2).unwrap();
    let bad = ChallengeAck {
        node_id: ch.node_id,
        tag: Cow::Owned(vec![0u8; 32]),
    };
    framing::write_frame(&mut tls2, &envelope_bytes(MsgType::CHALLENGE_ACK, &bad))
        .await
        .unwrap();
    let r = read_envelope(&mut tls2).await;
    assert!(r.is_err(), "坏 tag 必须断连");
    drop(tls2);
    server.await.unwrap();
}

/// REQ-057：已消费 key + 不同 pubkey → unknown pubkey 拒绝（tombstone
/// 对第二身份语义不变，persist 场景阶段 4 断言保持）
#[tokio::test]
async fn register_consumed_key_different_pubkey_rejected() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (ca_cert, cert, key) = ca_pair();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let ak_loop = landscape_rill_coord::authkey::generate_auth_key("lab", 3600).unwrap();
    let ak_server = ak_loop.clone();
    let coordinator = std::sync::Arc::new(tokio::sync::Mutex::new({
        let mut server = CoordinatorServer::new([0x11; 32], [0x22; 32]);
        server
            .coordinator
            .add_auth_key(&ak_server, AuthKeyPolicy::OneTime);
        server
    }));
    let server = tokio::spawn(async move {
        let mut listener = listener;
        for _ in 0..2 {
            let mut tls = server_tls_stream(&mut listener, &cert, &key).await.unwrap();
            let mut server = coordinator.lock().await;
            let _ = server.handle_connection(&mut tls).await;
        }
    });
    let host = addr.ip().to_string();

    let mut tls1 = client_tls_stream(&host, addr.port(), &ca_cert)
        .await
        .unwrap();
    let c1 = MeshClient::new([0x33; 32]);
    let config1 = MeshLegConfig {
        coordinator_host: host.clone(),
        coordinator_port: addr.port(),
        auth_key: ak_loop.clone(),
        static_key: [0x33; 32],
        capabilities: 0x01,
        announce_routes: vec![],
    };
    framing::write_frame(&mut tls1, &c1.register_request(&config1))
        .await
        .unwrap();
    answer_challenge(&mut tls1, &c1).await;
    let (mt, _) = read_envelope(&mut tls1).await.unwrap();
    assert_eq!(mt, MsgType::REGISTER_RESPONSE);
    drop(tls1);

    // 不同静态密钥的身份复用同一 key：pubkey 未命中 → 新建类 key 只读校验
    // 失败（已消费 = 不在册）→ 拒绝（tombstone 语义不变）
    let mut tls2 = client_tls_stream(&host, addr.port(), &ca_cert)
        .await
        .unwrap();
    let c2 = MeshClient::new([0x44; 32]);
    let config2 = MeshLegConfig {
        coordinator_host: host.clone(),
        coordinator_port: addr.port(),
        auth_key: ak_loop.clone(),
        static_key: [0x44; 32],
        capabilities: 0x01,
        announce_routes: vec![],
    };
    framing::write_frame(&mut tls2, &c2.register_request(&config2))
        .await
        .unwrap();
    let r = read_envelope(&mut tls2).await;
    assert!(r.is_err(), "unknown pubkey 必须断连");
    drop(tls2);
    server.await.unwrap();
}

// ==================== 注册挑战统一（REQ-060，CTL-20） ====================

/// REQ-060 恢复类对抗：有效 reusable key + 受害者 pubkey（公开）+ 精确复制
/// caps/routes → 仍须挑战；无私钥 → tag 必败，身份与 binding 不发放
#[tokio::test]
async fn register_resume_with_valid_key_still_requires_pop() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (ca_cert, cert, key) = ca_pair();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let ak_loop = landscape_rill_coord::authkey::generate_auth_key("lab", 3600).unwrap();
    let ak_server = ak_loop.clone();
    let coordinator = std::sync::Arc::new(tokio::sync::Mutex::new({
        let mut server = CoordinatorServer::new([0x11; 32], [0x22; 32]);
        server
            .coordinator
            .add_auth_key(&ak_server, AuthKeyPolicy::Reusable);
        server
    }));
    let coord_check = coordinator.clone();
    let server = tokio::spawn(async move {
        let mut listener = listener;
        for _ in 0..2 {
            let mut tls = server_tls_stream(&mut listener, &cert, &key).await.unwrap();
            let mut server = coordinator.lock().await;
            let _ = server.handle_connection(&mut tls).await;
        }
    });
    let host = addr.ip().to_string();

    // 受害者正常注册（caps=0x01）
    let mut tls1 = client_tls_stream(&host, addr.port(), &ca_cert)
        .await
        .unwrap();
    let c1 = MeshClient::new([0x33; 32]);
    let config = MeshLegConfig {
        coordinator_host: host.clone(),
        coordinator_port: addr.port(),
        auth_key: ak_loop.clone(),
        static_key: [0x33; 32],
        capabilities: 0x01,
        announce_routes: vec![],
    };
    framing::write_frame(&mut tls1, &c1.register_request(&config))
        .await
        .unwrap();
    answer_challenge(&mut tls1, &c1).await;
    assert_eq!(
        read_envelope(&mut tls1).await.unwrap().0,
        MsgType::REGISTER_RESPONSE
    );
    drop(tls1);

    // 攻击者：持同一有效 key，REGISTER 自报受害者 pubkey + 精确 caps/routes
    let mut tls2 = client_tls_stream(&host, addr.port(), &ca_cert)
        .await
        .unwrap();
    let attacker_key = [0x44; 32];
    let victim_pubkey =
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([0x33u8; 32])).to_bytes();
    let spoof = RegisterRequest {
        auth_key: Cow::Owned(ak_loop.clone()),
        static_pubkey: Cow::Owned(victim_pubkey.to_vec()),
        capabilities: 0x01,
        protocol_version: PROTOCOL_VERSION,
        hostname: Cow::Borrowed(""),
        os: Cow::Borrowed(""),
        routes: Vec::new(),
    };
    framing::write_frame(&mut tls2, &envelope_bytes(MsgType::REGISTER, &spoof))
        .await
        .unwrap();
    let (mt2, body2) = read_envelope(&mut tls2).await.unwrap();
    assert_eq!(mt2, MsgType::CHALLENGE, "恢复类：key 有效也必须先证持有");
    let mut reader2 = BytesReader::from_bytes(&body2);
    let ch = Challenge::from_reader(&mut reader2, &body2).unwrap();
    assert_eq!(ch.node_id, 1, "挑战绑定服务端解析的受害者身份");
    // 攻击者以自己的私钥构造 tag（服务端按受害者存储 pubkey 验证 → 必败）
    let attacker = MeshClient::new(attacker_key);
    framing::write_frame(&mut tls2, &attacker.challenge_ack(&ch))
        .await
        .unwrap();
    assert!(
        read_envelope(&mut tls2).await.is_err(),
        "无私钥不得通过恢复挑战"
    );
    drop(tls2);
    server.await.unwrap();
    // 身份与凭据无扰动
    let srv = coord_check.lock().await;
    assert_eq!(
        srv.coordinator.node_id_by_pubkey(&victim_pubkey),
        Some(1),
        "受害者身份未被夺取或漂移"
    );
}

/// REQ-060 新建类：key 消费后置于 PoP——挑战未通过（连接丢弃）前 key 不消费，
/// 同 key 仍可再次进入挑战；PoP 通过后才准入分配身份
#[tokio::test]
async fn register_one_time_key_consumed_only_after_pop() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (ca_cert, cert, key) = ca_pair();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let ak_loop = landscape_rill_coord::authkey::generate_auth_key("lab", 3600).unwrap();
    let ak_server = ak_loop.clone();
    let coordinator = std::sync::Arc::new(tokio::sync::Mutex::new({
        let mut server = CoordinatorServer::new([0x11; 32], [0x22; 32]);
        server
            .coordinator
            .add_auth_key(&ak_server, AuthKeyPolicy::OneTime);
        server
    }));
    let server = tokio::spawn(async move {
        let mut listener = listener;
        for _ in 0..2 {
            let mut tls = server_tls_stream(&mut listener, &cert, &key).await.unwrap();
            let mut server = coordinator.lock().await;
            let _ = server.handle_connection(&mut tls).await;
        }
    });
    let host = addr.ip().to_string();

    // 连接 1：REGISTER → 挑战（node_id=0）→ 不应答直接丢弃
    let mut tls1 = client_tls_stream(&host, addr.port(), &ca_cert)
        .await
        .unwrap();
    let c1 = MeshClient::new([0x33; 32]);
    let config = MeshLegConfig {
        coordinator_host: host.clone(),
        coordinator_port: addr.port(),
        auth_key: ak_loop.clone(),
        static_key: [0x33; 32],
        capabilities: 0x01,
        announce_routes: vec![],
    };
    framing::write_frame(&mut tls1, &c1.register_request(&config))
        .await
        .unwrap();
    let (mt, body) = read_envelope(&mut tls1).await.unwrap();
    assert_eq!(mt, MsgType::CHALLENGE);
    let mut reader = BytesReader::from_bytes(&body);
    let ch = Challenge::from_reader(&mut reader, &body).unwrap();
    assert_eq!(ch.node_id, 0, "新建类挑战不携带身份（尚未分配）");
    drop(tls1);

    // 连接 2：同 key 同密钥对 → key 未被消费，仍进挑战；PoP 通过后准入
    let mut tls2 = client_tls_stream(&host, addr.port(), &ca_cert)
        .await
        .unwrap();
    let c2 = MeshClient::new([0x33; 32]);
    framing::write_frame(&mut tls2, &c2.register_request(&config))
        .await
        .unwrap();
    let owned = answer_challenge(&mut tls2, &c2).await;
    assert_eq!(owned.proto().node_id, 0);
    let (mt3, _body3) = read_envelope(&mut tls2).await.unwrap();
    assert_eq!(mt3, MsgType::REGISTER_RESPONSE, "PoP 通过后才准入发放身份");
    drop(tls2);
    server.await.unwrap();
}

/// REQ-060 恢复类：幂等比对后置——PoP 通过但 capabilities 变更 → 拒绝，
/// 原身份不随重注册漂移
#[tokio::test]
async fn register_resume_caps_mismatch_rejected_after_pop() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (ca_cert, cert, key) = ca_pair();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let ak_loop = landscape_rill_coord::authkey::generate_auth_key("lab", 3600).unwrap();
    let ak_server = ak_loop.clone();
    let coordinator = std::sync::Arc::new(tokio::sync::Mutex::new({
        let mut server = CoordinatorServer::new([0x11; 32], [0x22; 32]);
        server
            .coordinator
            .add_auth_key(&ak_server, AuthKeyPolicy::Reusable);
        server
    }));
    let server = tokio::spawn(async move {
        let mut listener = listener;
        for _ in 0..2 {
            let mut tls = server_tls_stream(&mut listener, &cert, &key).await.unwrap();
            let mut server = coordinator.lock().await;
            let _ = server.handle_connection(&mut tls).await;
        }
    });
    let host = addr.ip().to_string();

    let mut tls1 = client_tls_stream(&host, addr.port(), &ca_cert)
        .await
        .unwrap();
    let c1 = MeshClient::new([0x33; 32]);
    let config = MeshLegConfig {
        coordinator_host: host.clone(),
        coordinator_port: addr.port(),
        auth_key: ak_loop.clone(),
        static_key: [0x33; 32],
        capabilities: 0x01,
        announce_routes: vec![],
    };
    framing::write_frame(&mut tls1, &c1.register_request(&config))
        .await
        .unwrap();
    answer_challenge(&mut tls1, &c1).await;
    assert_eq!(
        read_envelope(&mut tls1).await.unwrap().0,
        MsgType::REGISTER_RESPONSE
    );
    drop(tls1);

    // 同密钥对（PoP 可过）但 caps 变更 → 恢复完成前拒绝
    let mut tls2 = client_tls_stream(&host, addr.port(), &ca_cert)
        .await
        .unwrap();
    let changed = MeshLegConfig {
        capabilities: 0x03,
        ..config
    };
    framing::write_frame(&mut tls2, &c1.register_request(&changed))
        .await
        .unwrap();
    let (mt2, body2) = read_envelope(&mut tls2).await.unwrap();
    assert_eq!(mt2, MsgType::CHALLENGE);
    let mut reader2 = BytesReader::from_bytes(&body2);
    let ch = Challenge::from_reader(&mut reader2, &body2).unwrap();
    framing::write_frame(&mut tls2, &c1.challenge_ack(&ch))
        .await
        .unwrap();
    assert!(
        read_envelope(&mut tls2).await.is_err(),
        "caps/routes 变更须在 PoP 后拒绝"
    );
    drop(tls2);
    server.await.unwrap();
}

// ==================== 预认证解析语料（REQ-059，SEC-08） ====================

/// 预认证入口语料骨架（TLS 之上）：closure 自行建立 TLS 连接并注入字节，
/// 服务端 handle_connection 必须以 Err 断连（ca_cert 统一由本骨架生成传递）
async fn assert_preauth_reject<F, Fut>(client: F)
where
    F: FnOnce(String, u16, Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (ca_cert, cert, key) = ca_pair();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut listener = listener;
        let mut tls = server_tls_stream(&mut listener, &cert, &key).await.unwrap();
        let mut server = CoordinatorServer::new([0x11; 32], [0x22; 32]);
        assert!(
            server.handle_connection(&mut tls).await.is_err(),
            "预认证垃圾输入必须断连"
        );
    });
    let host = addr.ip().to_string();
    client(host.clone(), addr.port(), ca_cert.clone()).await;
    let r = tokio::time::timeout(std::time::Duration::from_secs(2), server).await;
    assert!(r.is_ok(), "服务端未在垃圾输入后断连（host={host}）");
    r.unwrap().unwrap();
}

/// 三级预认证语料：超长帧声明 / 垃圾信封 / REGISTER 垃圾消息体——
/// 长度校验先于 body 分配，全部 Err 收场、不 panic（CONTROL_PLANE §3.13 时机纪律）
#[tokio::test]
async fn preauth_garbage_inputs_rejected() {
    // ① 超长帧声明：只发 4B 头、无 body——长度校验必须先于读取/分配
    assert_preauth_reject(|host, port, ca| async move {
        let mut tls = client_tls_stream(&host, port, &ca).await.unwrap();
        tls.write_all(&(framing::MAX_MESSAGE_LEN + 1).to_be_bytes())
            .await
            .unwrap();
    })
    .await;

    // ② 垃圾信封：合法长度前缀 + 非信封字节 → bad envelope
    assert_preauth_reject(|host, port, ca| async move {
        let mut tls = client_tls_stream(&host, port, &ca).await.unwrap();
        let garbage: Vec<u8> = (0..48usize).map(|i| (i * 37 + 11) as u8).collect();
        framing::write_frame(&mut tls, &garbage).await.unwrap();
    })
    .await;

    // ③ REGISTER 垃圾消息体：准入闸门通过后 protobuf 解码失败 → Err（不 panic）
    assert_preauth_reject(|host, port, ca| async move {
        let mut tls = client_tls_stream(&host, port, &ca).await.unwrap();
        write_msg(&mut tls, MsgType::REGISTER, &[0xFF; 24])
            .await
            .unwrap();
    })
    .await;
}
