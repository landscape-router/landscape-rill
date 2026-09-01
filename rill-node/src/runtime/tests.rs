use super::*;
use landscape_rill_core::control::registry::AuthKeyPolicy;
use landscape_rill_mesh::control::{server_tls_stream, CoordinatorServer};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

fn coord_ca() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let _ = rustls::crypto::ring::default_provider().install_default();
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

/// 唯一 CA 路径（并行测试互不覆盖）
fn unique_ca_path() -> String {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("/tmp/landscape-test-ca-{}-{}.pem", std::process::id(), n)
}

/// 启动共享 coordinator（每连接独立任务，注册表共享）
async fn start_coord() -> (String, String) {
    let (ca, cert, key) = coord_ca();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let master = [0x11; 32];
    let seed = [0x22; 32];
    let server = Arc::new(Mutex::new(CoordinatorServer::new(master, seed)));
    let ak = auth_test_key();
    server
        .lock()
        .await
        .coordinator
        .add_auth_key(&ak, AuthKeyPolicy::Reusable);
    server.lock().await.coordinator.set_announce_whitelist(
        "lab",
        vec![landscape_rill_core::route::Prefix::parse("10.0.0.0/8").unwrap()],
    );
    let srv = server.clone();
    tokio::spawn(async move {
        let mut listener = listener;
        loop {
            let mut tls = server_tls_stream(&mut listener, &cert, &key).await.unwrap();
            let srv = srv.clone();
            tokio::spawn(async move {
                // 按消息粒度持锁（避免长连接互斥死锁）
                let mut conn = landscape_rill_mesh::control::ConnectionState::default();
                loop {
                    let (msg_type, body) =
                        match landscape_rill_mesh::control::read_envelope(&mut tls).await {
                            Ok(v) => v,
                            Err(_) => break,
                        };
                    let mut guard = srv.lock().await;
                    if guard
                        .handle_message(&mut conn, &mut tls, msg_type, &body)
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            });
        }
    });
    let ca_path = unique_ca_path();
    std::fs::write(&ca_path, &ca).unwrap();
    (format!("https://127.0.0.1:{}", addr.port()), ca_path)
}

fn node_config(url: &str, ca_path: &str, seed: u8, routes: Vec<String>) -> Config {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x22; 32]);
    Config {
        coordinator_url: url.into(),
        auth_key: auth_test_key(),
        static_key_seed: [seed; 32],
        capabilities: 0x01,
        announce_routes: routes,
        coord_signing_pubkey: VerifyingKey::from(&signing_key).to_bytes(),
        ca_cert_path: ca_path.into(),
        udp_echo_addr: None,
        coord: None,
    }
}

/// 与 start_coord 共享的 key（测试专用；生成一次全局复用，24h 有效）
fn auth_test_key() -> String {
    static KEY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    KEY.get_or_init(|| landscape_rill_coord::authkey::generate_auth_key("lab", 86_400).unwrap())
        .clone()
}

fn v4_packet(dst: [u8; 4]) -> Vec<u8> {
    let mut p = vec![0u8; 20];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&20u16.to_be_bytes());
    p[9] = 17;
    p[12..16].copy_from_slice(&[10, 0, 0, 1]);
    p[16..20].copy_from_slice(&dst);
    p
}

/// IPv6 组播包（ND solicited-node 形态，dst=ff02::1:ffxx:xxxx）
fn v6_multicast_packet(dst: [u8; 16]) -> Vec<u8> {
    let mut p = vec![0u8; 40];
    p[0] = 0x60;
    p[6] = 58;
    p[8..24].copy_from_slice(&[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    p[24..40].copy_from_slice(&dst);
    p
}

/// 测试用短心跳（端点收敛快）
fn fast_opts() -> NodeOptions {
    NodeOptions {
        heartbeat_interval: Duration::from_millis(300),
        data_heartbeat_interval: Duration::from_secs(3600),
        data_heartbeat_misses: 99,
        ..NodeOptions::default()
    }
}

/// 泵到全部节点满足条件（控制面/数据面/定时器交替；每次泵带超时——无事件时立即继续）
async fn pump_until_all<F: FnMut(&mut Node) -> bool>(
    nodes: &mut [&mut Node],
    label: &str,
    mut cond: F,
) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        assert!(
            Instant::now() < deadline,
            "pump_until_all timeout [{}]",
            label
        );
        for node in nodes.iter_mut() {
            let _ = tokio::time::timeout(Duration::from_millis(100), node.pump_control()).await;
            let _ = tokio::time::timeout(Duration::from_millis(100), node.pump_mesh()).await;
            node.pump_timers().await;
        }
        if nodes.iter_mut().all(|n| cond(n)) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// 反复触发 A→B 懒握手直到会话建立（端点随心跳收敛后重试自然成功）
async fn establish_session(a: &mut Node, b: &mut Node, packet: &[u8], peer: u32) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        assert!(Instant::now() < deadline, "establish_session timeout");
        let _ = a.pump_lan_packet(packet).await;
        let _ = tokio::time::timeout(Duration::from_millis(100), a.pump_mesh()).await;
        let _ = tokio::time::timeout(Duration::from_millis(100), b.pump_mesh()).await;
        let _ = tokio::time::timeout(Duration::from_millis(100), a.pump_control()).await;
        let _ = tokio::time::timeout(Duration::from_millis(100), b.pump_control()).await;
        if a.has_session(peer) && b.has_session(a.node_id().unwrap()) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn e2e_register_netmap_keydist_handshake_data() {
    let (url, ca) = start_coord().await;
    let mut a = Node::new(
        node_config(&url, &ca, 1, vec!["10.0.0.0/24".into()]),
        fast_opts(),
    )
    .await
    .unwrap();
    let mut b = Node::new(
        node_config(&url, &ca, 2, vec!["10.0.0.0/24".into()]),
        fast_opts(),
    )
    .await
    .unwrap();

    a.connect_control().await.unwrap();
    b.connect_control().await.unwrap();

    // 注册 + netmap（含路由公告）+ keydist + 端点上报（随心跳收敛）
    pump_until_all(&mut [&mut a, &mut b], "registered", |n| n.registered()).await;
    pump_until_all(&mut [&mut a, &mut b], "keydst2", |n| n.mesh.has_key_dst(2)).await;
    pump_until_all(&mut [&mut a, &mut b], "keydst1", |n| n.mesh.has_key_dst(1)).await;
    pump_until_all(&mut [&mut a, &mut b], "routes", |n| {
        !n.engine
            .lookup(&"10.0.0.2".parse::<IpAddr>().unwrap())
            .is_empty()
    })
    .await;

    // A → B：懒握手 → 加密帧 → B 解密
    let packet = v4_packet([10, 0, 0, 2]);
    establish_session(&mut a, &mut b, &packet, 2).await;
    assert_eq!(
        a.pump_lan_packet(&packet).await,
        LanOutcome::Sent { peer: 2 }
    );
    let payload = b.pump_mesh().await.expect("B 应收到解密载荷");
    assert_eq!(payload, packet);

    // 反向
    establish_session(&mut b, &mut a, &packet, 1).await;
    assert_eq!(
        b.pump_lan_packet(&packet).await,
        LanOutcome::Sent { peer: 1 }
    );
    let payload = a.pump_mesh().await.expect("A 应收到解密载荷");
    assert_eq!(payload, packet);
}

#[tokio::test]
async fn multicast_flooded_across_nodes() {
    let (url, ca) = start_coord().await;
    let mut a = Node::new(
        node_config(&url, &ca, 1, vec!["10.0.0.0/24".into()]),
        fast_opts(),
    )
    .await
    .unwrap();
    let mut b = Node::new(
        node_config(&url, &ca, 2, vec!["10.0.0.0/24".into()]),
        fast_opts(),
    )
    .await
    .unwrap();
    a.connect_control().await.unwrap();
    b.connect_control().await.unwrap();
    pump_until_all(&mut [&mut a, &mut b], "registered", |n| n.registered()).await;
    pump_until_all(&mut [&mut a, &mut b], "broadcast_key", |n| {
        n.broadcast_key.is_some()
    })
    .await;
    pump_until_all(&mut [&mut a, &mut b], "endpoints", |n| {
        let peer = if n.node_id() == Some(1) { 2 } else { 1 };
        n.mesh.endpoint(peer).is_some()
    })
    .await;

    // IPv6 组播（ND NS）→ 泛洪（不走路由表，无需会话）
    let ns = v6_multicast_packet([
        0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0x00, 0x00, 0x02,
    ]);
    assert_eq!(
        a.pump_lan_packet(&ns).await,
        LanOutcome::Flooded { peers: 1 }
    );
    assert_eq!(b.pump_mesh().await.expect("B 应收到广播解密载荷"), ns);
}

#[tokio::test]
async fn data_heartbeat_misses_drop_session() {
    let (url, ca) = start_coord().await;
    let mut a = Node::new(
        node_config(&url, &ca, 1, vec!["10.0.0.0/24".into()]),
        fast_opts(),
    )
    .await
    .unwrap();
    let mut b = Node::new(
        node_config(&url, &ca, 2, vec!["10.0.0.0/24".into()]),
        fast_opts(),
    )
    .await
    .unwrap();
    a.connect_control().await.unwrap();
    b.connect_control().await.unwrap();
    pump_until_all(&mut [&mut a, &mut b], "registered", |n| n.registered()).await;
    pump_until_all(&mut [&mut a, &mut b], "keydst2", |n| n.mesh.has_key_dst(2)).await;
    pump_until_all(&mut [&mut a, &mut b], "routes", |n| {
        !n.engine
            .lookup(&"10.0.0.2".parse::<IpAddr>().unwrap())
            .is_empty()
    })
    .await;

    let packet = v4_packet([10, 0, 0, 2]);
    establish_session(&mut a, &mut b, &packet, 2).await;

    // B 不再泵（收不到心跳）→ A 侧 3 次 miss 后拆会话
    a.opts.data_heartbeat_interval = Duration::from_millis(50);
    a.opts.data_heartbeat_misses = 3;
    a.peer_heartbeats.insert(2, 0);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        assert!(Instant::now() < deadline, "session drop timeout");
        a.pump_timers().await;
        if !a.has_session(2) {
            break;
        }
    }
    assert!(!a.has_session(2));
}

#[test]
fn config_rejects_missing_trust_anchors() {
    let mut c = node_config("https://coord.test:8443", "/tmp/x.pem", 1, vec![]);
    c.coord_signing_pubkey = [0; 32];
    assert!(c.validate().is_err());
    c.coord_signing_pubkey = [7; 32];
    c.ca_cert_path = "".into();
    assert!(c.validate().is_err());
}
