use super::*;
use crate::config::DataTransport;
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
    let (url, ca, _server) = start_coord_with_handle().await;
    (url, ca)
}

/// 同 start_coord，保留服务端句柄（测试中改策略/白名单用）
async fn start_coord_with_handle() -> (String, String, Arc<Mutex<CoordinatorServer>>) {
    let (ca, cert, key) = coord_ca();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let master = [0x11; 32];
    let seed = [0x22; 32];
    let server = Arc::new(Mutex::new(CoordinatorServer::new(master, seed)));
    {
        // 控制面限速参数测试放大（REQ-047）：主机测试 300ms 心跳泵 + localhost 共源
        let mut s = server.lock().await;
        s.heartbeat_min_interval = Duration::from_millis(100);
        s.register_limiter = landscape_rill_core::rate::SourceRateLimiter::new(100.0, 100);
    }
    let ak = auth_test_key();
    server
        .lock()
        .await
        .coordinator
        .with_coord_mut(|c| c.add_auth_key(&ak, AuthKeyPolicy::Reusable));
    server.lock().await.coordinator.with_coord_mut(|c| {
        c.set_announce_whitelist(
            "lab",
            vec![landscape_rill_core::route::Prefix::parse("10.0.0.0/8").unwrap()],
        )
    });
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
    (
        format!("https://127.0.0.1:{}", addr.port()),
        ca_path,
        server,
    )
}

fn node_config(url: &str, ca_path: &str, seed: u8, routes: Vec<String>) -> Config {
    node_config_caps(url, ca_path, seed, routes, 0x21)
}

fn node_config_caps(url: &str, ca_path: &str, seed: u8, routes: Vec<String>, caps: u32) -> Config {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x22; 32]);
    Config {
        coordinator_url: url.into(),
        auth_key: auth_test_key(),
        static_key_seed: [seed; 32],
        capabilities: caps,
        announce_routes: routes,
        coord_signing_pubkey: VerifyingKey::from(&signing_key).to_bytes(),
        ca_cert_path: ca_path.into(),
        udp_echo_addr: None,
        data_transport: DataTransport::default(),
        coord: None,
        dn42: None,
        ts2021: None,
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

/// REQ-035/CTL-14：未 opt-in 节点 keydist 不带 broadcast_key，
/// 本地 LAN 组播不泛洪（无 key 无法构建广播帧）
#[tokio::test]
async fn broadcast_opt_out_node_gets_no_key_and_no_flood() {
    let (url, ca) = start_coord().await;
    let mut a = Node::new(
        node_config_caps(&url, &ca, 1, vec!["10.0.0.0/24".into()], 0x01),
        fast_opts(),
    )
    .await
    .unwrap();
    a.connect_control().await.unwrap();
    pump_until_all(&mut [&mut a], "registered", |n| n.registered()).await;
    // keydist 已消费（自身 key 到位）但 broadcast_key 不出现
    pump_until_all(&mut [&mut a], "keydst", |n| n.mesh.has_key_dst(1)).await;
    assert!(a.broadcast_key.is_none());
    let ns = v6_multicast_packet([
        0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0x00, 0x00, 0x02,
    ]);
    assert_eq!(
        a.pump_lan_packet(&ns).await,
        LanOutcome::Flooded { peers: 0 }
    );
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

// ==================== probe 发送侧限速/退避（CN-01，REQ-046） ====================

/// 无协调器节点：pump_probes 只依赖 node_id + 端点表，控制面不需要
async fn bare_node(seed: u8) -> Node {
    let mut n = Node::new(
        node_config("https://coord.test:8443", "/tmp/x.pem", seed, vec![]),
        fast_opts(),
    )
    .await
    .unwrap();
    n.node_id = Some(seed as u32);
    n
}

/// 全局发送令牌桶（CN-01）：候选端点再多，单轮发送量 ≤ 突发容量
#[tokio::test]
async fn probe_send_bucket_bounds_burst() {
    let mut a = bare_node(1).await;
    let eps: Vec<SocketAddr> = (20000..20040)
        .map(|p| format!("127.0.0.1:{p}").parse().unwrap())
        .collect();
    a.mesh.set_endpoints(2, eps);
    // 越过 PROBE_PERIOD 的合成时刻驱动（last_probe 初始化为 now）
    a.pump_probes(Instant::now() + probe::PROBE_PERIOD * 2)
        .await;
    assert_eq!(
        a.mesh.probe_pending_len(),
        probe::PROBE_SEND_CAPACITY as usize,
        "桶容量耗尽后不再发送"
    );
}

/// 指数退避（CN-01）：无响应端点 miss 翻倍退避；PONG 确认即清零
#[tokio::test]
async fn probe_backoff_exponential_and_reset() {
    let mut a = bare_node(1).await;
    let ep: SocketAddr = "127.0.0.1:20300".parse().unwrap();
    a.mesh.set_endpoint(2, ep);
    let t0 = Instant::now() + probe::PROBE_PERIOD * 2;
    a.pump_probes(t0).await;
    assert_eq!(a.mesh.probe_pending_len(), 1);

    // 无 PONG → 下一周期在途探测转为退避（miss=1 → 60s），退避期内不发
    let t1 = t0 + probe::PROBE_PERIOD;
    a.pump_probes(t1).await;
    assert_eq!(a.mesh.probe_pending_len(), 0, "退避期内不发");
    let (_, due1) = *a.probe_backoff.get(&ep).unwrap();
    assert_eq!(due1, t1 + probe::PROBE_PERIOD * 2);

    // 到期恢复发送 → 再无响应 → miss=2 → 120s
    a.pump_probes(due1).await;
    assert_eq!(a.mesh.probe_pending_len(), 1);
    let t3 = due1 + probe::PROBE_PERIOD;
    a.pump_probes(t3).await;
    let (miss3, due3) = *a.probe_backoff.get(&ep).unwrap();
    assert_eq!((miss3, due3), (2, t3 + probe::PROBE_PERIOD * 4));

    // PONG 确认 → 退避清零（下周期可立即探测）
    a.handle_probe_pong(2, ep, Vec::new()).await;
    assert!(!a.probe_backoff.contains_key(&ep));
}

// ==================== 控制面限速/准入（REQ-047） ====================

/// 待发路径请求上限（REQ-047）：饱和丢弃，重复 dest 幂等
#[tokio::test]
async fn path_request_pending_capped() {
    let mut a = bare_node(1).await;
    for dest in 0..(PATH_REQUEST_PENDING_MAX as u32 + 10) {
        a.request_paths_for(dest);
    }
    assert_eq!(a.pending_path_requests.len(), PATH_REQUEST_PENDING_MAX);
    // 重复 dest 不增长
    a.request_paths_for(0);
    assert_eq!(a.pending_path_requests.len(), PATH_REQUEST_PENDING_MAX);
}

// ==================== ts2021 腿接线（TS2021_LEG §3.3.2） ====================

/// ts2021 测试 peer（node key = seed 填充；id = hex 形态）
fn ts_peer(seed: u8, allowed: &[&str]) -> ts2021::Ts2021Peer {
    ts2021::Ts2021Peer {
        id: format!("{seed:02x}").repeat(32),
        nid: i64::from(seed),
        key: [seed; 32],
        endpoints: vec![],
        allowed_ips: allowed.iter().map(|s| s.to_string()).collect(),
    }
}

fn ts_lookup(node: &Node, dst: &str) -> Vec<(RouteSource, String)> {
    node.engine
        .lookup(&dst.parse().unwrap())
        .into_iter()
        .map(|(e, _)| {
            (
                e.source,
                match &e.via {
                    RouteVia::Tailnet(id) => id.clone(),
                    other => format!("{:?}", other),
                },
            )
        })
        .collect()
}

#[tokio::test]
async fn ts2021_netmap_routes_injected_and_replaced() {
    let (url, ca) = start_coord().await;
    let mut node = Node::new(node_config(&url, &ca, 3, vec![]), fast_opts())
        .await
        .unwrap();
    let (leg, th) = ts2021::Ts2021Leg::test_leg();
    node.ts2021 = Some(leg);
    let p1 = ts_peer(1, &["100.64.0.2/32", "10.99.0.0/24", "0.0.0.0/0"]);
    let id1 = p1.id.clone();
    th.events
        .send(ts2021::Ts2021Event::Netmap { peers: vec![p1] })
        .await
        .unwrap();
    node.pump_ts2021().await;
    // /32 与子网路由进 LPM（Tailnet via）；默认路由（exit 方向）排除
    assert_eq!(
        ts_lookup(&node, "100.64.0.2"),
        vec![(RouteSource::Tailnet, id1.clone())]
    );
    assert_eq!(
        ts_lookup(&node, "10.99.0.9"),
        vec![(RouteSource::Tailnet, id1.clone())]
    );
    assert!(ts_lookup(&node, "8.8.8.8").is_empty());
    // 全量替换：peer 消失 → 路由与镜像清空
    th.events
        .send(ts2021::Ts2021Event::Netmap { peers: vec![] })
        .await
        .unwrap();
    node.pump_ts2021().await;
    assert!(ts_lookup(&node, "100.64.0.2").is_empty());
    assert!(ts_lookup(&node, "10.99.0.9").is_empty());
    assert!(!node.ts2021.as_ref().unwrap().has_peer(&id1));
}

#[tokio::test]
async fn lan_packet_to_tailnet_goes_outbound() {
    let (url, ca) = start_coord().await;
    let mut node = Node::new(node_config(&url, &ca, 3, vec![]), fast_opts())
        .await
        .unwrap();
    let (leg, mut th) = ts2021::Ts2021Leg::test_leg();
    node.ts2021 = Some(leg);
    let id = ts_peer(7, &["100.64.0.7/32"]).id;
    th.events
        .send(ts2021::Ts2021Event::Netmap {
            peers: vec![ts_peer(7, &["100.64.0.7/32"])],
        })
        .await
        .unwrap();
    node.pump_ts2021().await;
    let pkt = v4_packet([100, 64, 0, 7]);
    let outcome = node.pump_lan_packet(&pkt).await;
    assert_eq!(outcome, LanOutcome::SentTailnet { peer: id });
    // 出站通道收到原包（peer 匹配/封装在数据面任务内）
    assert_eq!(th.outbound.recv().await.unwrap(), pkt);
}

#[tokio::test]
async fn tailnet_ingress_transits_to_mesh_and_reflection_dropped() {
    let (url, ca) = start_coord().await;
    let mut a = Node::new(node_config(&url, &ca, 1, vec![]), fast_opts())
        .await
        .unwrap();
    let mut b = Node::new(
        node_config(&url, &ca, 2, vec!["10.7.0.0/24".into()]),
        fast_opts(),
    )
    .await
    .unwrap();
    let (leg, mut th) = ts2021::Ts2021Leg::test_leg();
    a.ts2021 = Some(leg);
    th.events
        .send(ts2021::Ts2021Event::Netmap {
            peers: vec![ts_peer(9, &["100.64.0.9/32"])],
        })
        .await
        .unwrap();
    a.pump_ts2021().await;
    // a↔b mesh 会话（b 公告 10.7.0.0/24 → a 引擎 Mesh 路由）
    a.connect_control().await.unwrap();
    b.connect_control().await.unwrap();
    pump_until_all(&mut [&mut a, &mut b], "registered", |n| n.registered()).await;
    let b_id = b.node_id().unwrap();
    let a_id = a.node_id().unwrap();
    // keydist + 路由公告 + 端点收敛（定时器节奏），随后懒握手
    let dst: IpAddr = "10.7.0.5".parse().unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        assert!(Instant::now() < deadline, "route convergence timeout");
        for n in [&mut a, &mut b] {
            let _ = tokio::time::timeout(Duration::from_millis(100), n.pump_control()).await;
            let _ = tokio::time::timeout(Duration::from_millis(100), n.pump_mesh()).await;
            n.pump_timers().await;
        }
        if a.mesh.has_key_dst(b_id) && b.mesh.has_key_dst(a_id) && !a.engine.lookup(&dst).is_empty()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let probe = v4_packet([10, 7, 0, 5]);
    establish_session(&mut a, &mut b, &probe, b_id).await;
    // tailnet 入站 dst 命中 mesh 路由 → subnet router 转发（mesh 帧）
    let pkt = v4_packet([10, 7, 0, 5]);
    // tailnet 入站明文 → 泵裁决 → mesh 转发（subnet router 语义）
    th.plaintext.send(pkt.clone()).await.unwrap();
    a.pump_ts2021().await;
    let got = tokio::time::timeout(Duration::from_millis(500), b.pump_mesh()).await;
    assert_eq!(
        got.expect("mesh frame timeout"),
        Some(bytes::Bytes::from(pkt.clone()))
    );
    // 反射防护：tailnet 入站 dst = tailnet peer 地址 → 丢弃（不回 tailnet、不进 mesh）
    let refl = v4_packet([100, 64, 0, 9]);
    th.plaintext.send(refl).await.unwrap();
    a.pump_ts2021().await;
    match tokio::time::timeout(Duration::from_millis(200), b.pump_mesh()).await {
        // 无后续帧 = 反射包未进 mesh（超时 = 空队列，通过）
        Err(_) => {}
        Ok(ev) => panic!("reflection leaked to mesh: {ev:?}"),
    }
    assert!(th.outbound.try_recv().is_err(), "反射包不得回 tailnet 出站");
}

// ==================== ACL 前缀级裁决（REQ-045，SEC-28/31） ====================

/// 目标节点解密后裁决：主体命中 allow → 投递；策略收紧（组员变更）→
/// default-deny，经 netmap 原子切换收敛后拒投递（会话不受影响）
#[tokio::test]
async fn acl_prefix_rules_enforced_at_target_node() {
    use landscape_rill_core::control::acl::{AclAction, AclPolicy, AclRule, AclSubject};

    let lab_policy = |members: Vec<u32>| {
        let mut groups = std::collections::HashMap::new();
        groups.insert("friends".to_string(), members);
        AclPolicy {
            enabled: true,
            rules: vec![AclRule {
                subjects: vec![AclSubject::Group("friends".into())],
                prefix: landscape_rill_core::route::Prefix::parse("10.7.0.0/24").unwrap(),
                action: AclAction::Allow,
            }],
            groups,
        }
    };
    let (url, ca, server) = start_coord_with_handle().await;
    // a 先注册（node_id=1 确定），随后 b 公告 10.7.0.0/24
    server
        .lock()
        .await
        .coordinator
        .with_coord_mut(|c| c.set_acl_policy("lab", lab_policy(vec![1])));
    let mut a = Node::new(node_config(&url, &ca, 1, vec![]), fast_opts())
        .await
        .unwrap();
    let mut b = Node::new(
        node_config(&url, &ca, 2, vec!["10.7.0.0/24".into()]),
        fast_opts(),
    )
    .await
    .unwrap();
    a.connect_control().await.unwrap();
    pump_until_all(&mut [&mut a], "a registered", |n| n.registered()).await;
    let a_id = a.node_id().unwrap();
    assert_eq!(a_id, 1, "首注册 node_id=1（策略主体引用）");
    b.connect_control().await.unwrap();
    pump_until_all(&mut [&mut b], "b registered", |n| n.registered()).await;
    let b_id = b.node_id().unwrap();

    // keydist/路由收敛 + 懒握手（a → dst 10.7.0.5 经 b）
    let dst: IpAddr = "10.7.0.5".parse().unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        assert!(Instant::now() < deadline, "route convergence timeout");
        for n in [&mut a, &mut b] {
            let _ = tokio::time::timeout(Duration::from_millis(100), n.pump_control()).await;
            let _ = tokio::time::timeout(Duration::from_millis(100), n.pump_mesh()).await;
            n.pump_timers().await;
        }
        if a.mesh.has_key_dst(b_id) && b.mesh.has_key_dst(a_id) && !a.engine.lookup(&dst).is_empty()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // 策略经 netmap 到达两端（注册推送即携带）
    assert_eq!(a.acl, lab_policy(vec![1]));
    assert_eq!(b.acl, lab_policy(vec![1]));

    let probe = v4_packet([10, 7, 0, 5]);
    establish_session(&mut a, &mut b, &probe, b_id).await;

    // ① 主体命中（a ∈ friends）+ 前缀命中 → 目标侧投递
    let pkt = v4_packet([10, 7, 0, 5]);
    let _ = a.pump_lan_packet(&pkt).await;
    let got = tokio::time::timeout(Duration::from_millis(500), b.pump_mesh()).await;
    assert_eq!(
        got.expect("allowed frame timeout"),
        Some(bytes::Bytes::from(pkt))
    );

    // ② 策略收紧：friends 除名 → default-deny；netmap 原子切换收敛后拒投递
    let tightened = lab_policy(vec![]);
    server
        .lock()
        .await
        .coordinator
        .with_coord_mut(|c| c.set_acl_policy("lab", tightened.clone()));
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        assert!(Instant::now() < deadline, "acl convergence timeout");
        for n in [&mut a, &mut b] {
            let _ = tokio::time::timeout(Duration::from_millis(100), n.pump_control()).await;
            // 心跳由定时器泵驱动（无心跳 = 无快照推送 = 策略不收敛）
            n.pump_timers().await;
        }
        if a.acl == tightened && b.acl == tightened {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let pkt = v4_packet([10, 7, 0, 5]);
    let _ = a.pump_lan_packet(&pkt).await;
    // 静默窗内持续泵：非 Data 事件（心跳等）合法路过，出现载荷即拒绝失效
    let quiet_until = Instant::now() + Duration::from_millis(400);
    loop {
        if Instant::now() >= quiet_until {
            break; // 窗口静默 = 拒绝生效
        }
        if let Ok(Some(payload)) =
            tokio::time::timeout(Duration::from_millis(50), b.pump_mesh()).await
        {
            panic!("denied frame delivered: {} bytes", payload.len());
        }
    }
    // 会话仍在（拒绝只丢载荷，不拆隧道）
    assert!(a.has_session(b_id));
    assert!(b.has_session(a_id));
}

/// 节点侧租约看门狗（REQ-070 开放问题 6，CONTROL_PLANE §5.2）：
/// 真实租约流记账（心跳 → LEASE 应答）；逾期 → pump_timers 断开控制会话；
/// 未到期 / granted=false 不动作
#[tokio::test]
async fn lease_watchdog_drops_expired_session() {
    let (url, ca) = start_coord().await;
    let mut node = Node::new(
        node_config(&url, &ca, 7, vec!["10.0.0.0/24".into()]),
        fast_opts(),
    )
    .await
    .unwrap();
    node.connect_control().await.unwrap();

    // 真实租约：心跳应答 LEASE(granted, +60s) → 记账
    pump_until_all(&mut [&mut node], "lease granted", |n| {
        n.lease_expires_at.is_some()
    })
    .await;
    assert!(node.lease_expires_at.unwrap() > unix_now());

    // 未到期：看门狗不动作（新会话重置语义见 connect_control 内 None 复位）
    node.pump_timers().await;
    assert!(node.control.is_some());

    // 逾期：静默僵死兜底 → 断开（后续走既有重连退避）
    node.lease_expires_at = Some(unix_now() - 1);
    node.pump_timers().await;
    assert!(node.control.is_none(), "逾期租约应断开控制会话");
    assert!(node.lease_expires_at.is_none());

    // granted=false 不记账：拒租由 coordinator 主动断开，看门狗只兜底静默僵死
    node.connect_control().await.unwrap();
    node.handle_control_event(ControlEvent::Lease {
        granted: false,
        expires_at: unix_now() - 1,
    })
    .await
    .unwrap();
    node.pump_timers().await;
    assert!(node.control.is_some(), "拒租不触发看门狗");
}

/// SIGTERM 优雅收尾（REQ-070 开放问题 8）：停机信号 → close_notify 后
/// 会话关闭且不可再写；graceful_shutdown 清空控制会话
#[tokio::test]
async fn sigterm_shutdown_closes_control_session() {
    let (url, ca) = start_coord().await;
    let (tx, rx) = tokio::sync::watch::channel(false);
    let mut opts = fast_opts();
    opts.shutdown = Some(rx);
    let mut node = Node::new(node_config(&url, &ca, 8, vec!["10.0.0.0/24".into()]), opts)
        .await
        .unwrap();
    node.connect_control().await.unwrap();

    // close_notify 语义：关闭后写失败（对端可立即感知，非半开残留）
    node.control
        .as_mut()
        .unwrap()
        .close()
        .await
        .expect("close_notify send");
    let mut stale = node.control.take().unwrap();
    assert!(
        stale.send_envelope(&[0u8; 8]).await.is_err(),
        "close_notify 后写应失败"
    );

    // 停机信号 → graceful_shutdown 收尾（控制会话置空）
    node.connect_control().await.unwrap();
    assert!(!node.is_shutting_down());
    tx.send(true).unwrap();
    assert!(node.is_shutting_down());
    node.graceful_shutdown().await;
    assert!(node.control.is_none());
}

/// 控制面连接不阻塞数据面（§4.3，ha e2e 实证缺陷回归）：failover 重连对端
/// 可达性悬置（死 IP 的 SYN/ARP 超时、慢 TLS）可达秒级——连接在后台任务执行、
/// run loop 分片持续服务 mesh。慢协调者（接受 TCP 但 TLS 握手永不开始）连接
/// 悬挂窗口内，对端发起懒握手仍须能得到应答
#[tokio::test]
async fn data_plane_alive_while_control_connect_stalls() {
    let (url, ca) = start_coord().await;
    let mut a = Node::new(
        node_config(&url, &ca, 9, vec!["10.0.0.0/24".into()]),
        fast_opts(),
    )
    .await
    .unwrap();
    let mut b = Node::new(
        node_config(&url, &ca, 10, vec!["10.0.0.0/24".into()]),
        fast_opts(),
    )
    .await
    .unwrap();
    a.connect_control().await.unwrap();
    b.connect_control().await.unwrap();
    pump_until_all(&mut [&mut a, &mut b], "registered", |n| n.registered()).await;
    let a_id = a.node_id().unwrap();
    // 端点收敛（B 须已知 A 的 mesh 地址才能直发握手）
    pump_until_all(&mut [&mut a, &mut b], "endpoints", |n| {
        let peer = if n.node_id() == Some(a_id) {
            n.node_id().unwrap() + 1
        } else {
            a_id
        };
        n.mesh.endpoint(peer).is_some()
    })
    .await;

    // 慢协调者：接受 TCP 并持有连接，TLS 握手永不开始（客户端 connect 悬挂）
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let slow_port = listener.local_addr().unwrap().port();
    let slow_hit = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let hit = slow_hit.clone();
    tokio::spawn(async move {
        let mut held = Vec::new();
        let listener = listener;
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                break;
            };
            hit.store(true, std::sync::atomic::Ordering::Relaxed);
            held.push(sock); // 持有不关闭：不完成 TLS 也不发 EOF
        }
    });

    // A 断线重连指向慢协调者 → 连接悬挂；B 同时发起懒握手
    a.cfg.coordinator_url = format!("https://127.0.0.1:{}", slow_port);
    a.control = None;
    tokio::spawn(a.run());

    let packet = v4_packet([10, 0, 0, 2]);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        assert!(
            Instant::now() < deadline,
            "慢连接窗口内 B→A 懒握手未完成（控制面连接阻塞了数据面）"
        );
        let _ = b.pump_lan_packet(&packet).await;
        let _ = tokio::time::timeout(Duration::from_millis(100), b.pump_mesh()).await;
        if b.has_session(a_id) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // 让慢协调者任务有机会标记（current_thread 运行时需让出）
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        slow_hit.load(std::sync::atomic::Ordering::Relaxed),
        "前置失效：连接未真正悬挂在慢协调者上"
    );
}
