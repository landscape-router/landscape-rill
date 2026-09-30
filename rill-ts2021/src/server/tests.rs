//! ts2021 服务端集成测试（REQ-068）：**用客户端协议栈本身**对服务端做端到端验证
//! （裸 TCP 直驱，TLS/官方客户端路径由 e2e 覆盖）——同库客户端/服务端对照 +
//! headscale 抓帧参照（netmap 字段集）双保险。

use crate::controlhttp;
use crate::derp::DerpClient;
use crate::server::{registry, NetmapCtx, Ts2021Server};
use crate::tailcfg::{self, MapResponse};
use crate::ts2021::{self, ControlClient};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};

const AUTH_KEY: &str = "lrk-lab-0-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// 测试服务端：随机密钥直构状态 + accept 循环（每连接一任务）
async fn spawn_server(whitelist: &[String]) -> (u16, Arc<Ts2021Server>) {
    spawn_server_opts(whitelist, false).await
}

async fn spawn_server_opts(whitelist: &[String], allow_exit: bool) -> (u16, Arc<Ts2021Server>) {
    let (noise_priv, _) = ts2021::generate_keypair().unwrap();
    let derp_priv = crypto_box::SecretKey::from(rand::random::<[u8; 32]>());
    let derp_pub = *crypto_box::PublicKey::from(&derp_priv).as_bytes();
    let server = Arc::new(Ts2021Server {
        registry: std::sync::Mutex::new(registry::Registry::new(
            vec![AUTH_KEY.to_owned()],
            registry::RoutesWhitelist::parse(whitelist, allow_exit).unwrap(),
        )),
        ctx: NetmapCtx {
            user: "ts".into(),
            dns_domain: "lab".into(),
            domain: "lrill-ts".into(),
            derp_region: 1,
            derp_hostname: "lrill-ts".into(),
            derp_port: 8443,
        },
        noise_priv,
        derp_priv,
        derp_pub,
        derp_hub: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let srv = server.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            let srv = srv.clone();
            tokio::spawn(async move { crate::server::serve_connection(tcp, srv).await });
        }
    });
    (port, server)
}

/// 客户端全链路：/key 预取 → 升级 → Noise → early payload → h2 → register
async fn connect_and_register(
    port: u16,
    machine_key: &[u8; 32],
    node_key: &[u8; 32],
    hostname: &str,
    auth_key: &str,
) -> std::io::Result<ControlClient> {
    let host = format!("127.0.0.1:{port}");
    let tcp = TcpStream::connect(&host).await?;
    let control_key =
        controlhttp::fetch_control_key(tcp, &host, tailcfg::CURRENT_CAP_VERSION).await?;
    let tcp = TcpStream::connect(&host).await?;
    let stream = controlhttp::upgrade(tcp, &host, machine_key, &control_key, 1).await?;
    let mut client = ts2021::connect(stream).await?;
    let resp = client.register(node_key, auth_key, hostname, &host).await?;
    if !resp.is_success() {
        return Err(std::io::Error::other(format!(
            "register rejected: {}",
            resp.error
        )));
    }
    Ok(client)
}

/// /key 端点：Noise 公钥可预取且与握手机器密钥闭环
#[tokio::test]
async fn key_endpoint_serves_noise_pub() {
    let (port, server) = spawn_server(&[]).await;
    let host = format!("127.0.0.1:{port}");
    let tcp = TcpStream::connect(&host).await.unwrap();
    let key = controlhttp::fetch_control_key(tcp, &host, tailcfg::CURRENT_CAP_VERSION)
        .await
        .unwrap();
    assert_eq!(key, server.noise_pub());
}

/// 注册准入 + 全量 netmap：合法 auth key 注册成功、坏 key 拒绝（Error 载荷）、
/// 双节点互见 + 地址分配 + 已审批路由进对端 AllowedIPs
#[tokio::test]
async fn register_and_full_netmap() {
    let (port, _server) = spawn_server(&["10.42.0.0/24".to_owned()]).await;
    let host = format!("127.0.0.1:{port}");
    let (m1, _) = ts2021::generate_keypair().unwrap();
    let (m2, _) = ts2021::generate_keypair().unwrap();
    let (_, n1) = ts2021::generate_keypair().unwrap();
    let (_, n2) = ts2021::generate_keypair().unwrap();

    let mut a = connect_and_register(port, &m1, &n1, "node-a", AUTH_KEY)
        .await
        .unwrap();
    // 坏 auth key：200 + Error（客户端 is_success 判定失败）
    let tcp = TcpStream::connect(&host).await.unwrap();
    let ck = controlhttp::fetch_control_key(tcp, &host, 1).await.unwrap();
    let tcp = TcpStream::connect(&host).await.unwrap();
    let stream = controlhttp::upgrade(tcp, &host, &m2, &ck, 1).await.unwrap();
    let mut probe = ts2021::connect(stream).await.unwrap();
    let resp = probe
        .register(&n2, "tskey-bogus", "evil", &host)
        .await
        .unwrap();
    assert!(!resp.is_success());
    assert!(resp.error.contains("auth key"));

    let mut b = connect_and_register(port, &m2, &n2, "node-b", AUTH_KEY)
        .await
        .unwrap();
    // a 广播路由（Lite 更新携带 Hostinfo.RoutableIPs）
    b.map_endpoints_update(
        &n2,
        &[7u8; 32],
        "node-b",
        &host,
        &["10.9.9.9:1".to_owned()],
        None,
        &["10.42.0.0/24".to_owned()],
    )
    .await
    .unwrap();

    // a 的全量 netmap：见 b + 白名单路由 + DERPMap
    let map = a.map(&n1, &[3u8; 32], "node-a", &host, None).await.unwrap();
    assert_eq!(map.self_ipv4(), Some("100.64.0.1".parse().unwrap()));
    let peers = map.peers.as_ref().expect("peers present");
    assert_eq!(peers.len(), 1);
    let p = &peers[0];
    assert_eq!(p.nid, Some(2));
    assert_eq!(p.node_key().unwrap(), n2);
    assert!(p.allowed_ips.contains(&"100.64.0.2/32".to_owned()));
    assert!(p.allowed_ips.contains(&"10.42.0.0/24".to_owned()));
    let dn = map.derp_node().expect("derp map");
    assert_eq!(dn.hostname, "lrill-ts");
    assert_eq!(dn.port, 8443);
    assert_eq!(dn.region_id, 1);
}

/// 增量推送（REQ-068 核心）：持有流上 peer 注册 → PeersChanged；删除 → PeersRemoved；
/// keepalive 帧不透出（next_netmap 内部跳过）
#[tokio::test]
async fn held_stream_receives_delta_frames() {
    let (port, server) = spawn_server(&[]).await;
    let host = format!("127.0.0.1:{port}");
    let (m1, _) = ts2021::generate_keypair().unwrap();
    let (m2, _) = ts2021::generate_keypair().unwrap();
    let (_, n1) = ts2021::generate_keypair().unwrap();
    let (_, n2) = ts2021::generate_keypair().unwrap();

    let mut a = connect_and_register(port, &m1, &n1, "node-a", AUTH_KEY)
        .await
        .unwrap();
    let mut stream = a
        .map_stream(&n1, &[1u8; 32], "node-a", &host, &[], None)
        .await
        .unwrap();
    let full = stream.next_netmap().await.unwrap();
    assert!(full.peers.as_ref().unwrap().is_empty());

    // b 注册 → a 的持有流收到 PeersChanged（无 Node 的增量帧）
    let _b = connect_and_register(port, &m2, &n2, "node-b", AUTH_KEY)
        .await
        .unwrap();
    let delta = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next_netmap())
        .await
        .expect("delta within 5s")
        .unwrap();
    assert!(delta.node.is_none(), "增量帧不带 Node");
    let changed = delta.peers_changed.as_ref().expect("PeersChanged");
    assert_eq!(changed.len(), 1);
    assert_eq!(changed[0].nid, Some(2));
    assert_eq!(changed[0].node_key().unwrap(), n2);
    assert!(delta.peers_removed.is_none());

    // 删除（e2e 注入同路径）→ PeersRemoved
    assert!(server.registry.lock().unwrap().evict("node-b"));
    let removed = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next_netmap())
        .await
        .expect("removal within 5s")
        .unwrap();
    assert_eq!(removed.peers_removed.as_deref(), Some(&[2i64][..]));
}

/// Lite 更新的路由覆写语义（tailscaled 同源）：RoutableIPs 变化 → 增量帧刷新
/// 对端 AllowedIPs；白名单外路由被丢弃
#[tokio::test]
async fn lite_update_routes_overwrite_and_whitelist_drop() {
    let (port, _server) = spawn_server_opts(&["10.42.0.0/24".to_owned()], true).await;
    let host = format!("127.0.0.1:{port}");
    let (m1, _) = ts2021::generate_keypair().unwrap();
    let (m2, _) = ts2021::generate_keypair().unwrap();
    let (_, n1) = ts2021::generate_keypair().unwrap();
    let (_, n2) = ts2021::generate_keypair().unwrap();

    let mut a = connect_and_register(port, &m1, &n1, "node-a", AUTH_KEY)
        .await
        .unwrap();
    let mut b = connect_and_register(port, &m2, &n2, "node-b", AUTH_KEY)
        .await
        .unwrap();
    let mut stream = a
        .map_stream(&n1, &[1u8; 32], "node-a", &host, &[], None)
        .await
        .unwrap();
    let _ = stream.next_netmap().await.unwrap();

    // b 广播：白名单内 10.42/24 + 白名单外 10.99/24 + exit 0.0.0.0/0（显式放行）
    b.map_endpoints_update(
        &n2,
        &[7u8; 32],
        "node-b",
        &host,
        &[],
        None,
        &[
            "10.42.0.0/24".to_owned(),
            "10.99.0.0/24".to_owned(),
            "0.0.0.0/0".to_owned(),
        ],
    )
    .await
    .unwrap();
    let delta = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next_netmap())
        .await
        .expect("route delta within 5s")
        .unwrap();
    let changed = delta.peers_changed.as_ref().expect("PeersChanged");
    let ips = &changed[0].allowed_ips;
    assert!(ips.contains(&"10.42.0.0/24".to_owned()));
    assert!(ips.contains(&"0.0.0.0/0".to_owned()));
    assert!(
        !ips.iter().any(|i| i.starts_with("10.99.")),
        "白名单外路由被丢弃"
    );
}

/// 未注册 node key 的 map 请求 → 401（服务端重启后客户端重注册自愈路径）
#[tokio::test]
async fn unknown_node_map_rejected() {
    let (port, _server) = spawn_server(&[]).await;
    let host = format!("127.0.0.1:{port}");
    let (m1, _) = ts2021::generate_keypair().unwrap();
    let (_, n1) = ts2021::generate_keypair().unwrap();
    let (_, stranger) = ts2021::generate_keypair().unwrap();
    let mut a = connect_and_register(port, &m1, &n1, "node-a", AUTH_KEY)
        .await
        .unwrap();
    let err = a
        .map_stream(&stranger, &[1u8; 32], "ghost", &host, &[], None)
        .await
        .err()
        .expect("map for unknown node rejected");
    assert!(err.to_string().contains("401"));
}

/// DERP 中继：双客户端同服务器注册，A→B 密文中继（源 node key 标注）
#[tokio::test]
async fn derp_relay_between_clients() {
    let (port, server) = spawn_server(&[]).await;
    let (a_priv, a_pub) = ts2021::generate_keypair().unwrap();
    let (b_priv, b_pub) = ts2021::generate_keypair().unwrap();
    let host = format!("127.0.0.1:{port}");
    let a = DerpClient::connect(
        TcpStream::connect(&host).await.unwrap(),
        &host,
        a_pub,
        a_priv,
    )
    .await
    .unwrap();
    let b = DerpClient::connect(
        TcpStream::connect(&host).await.unwrap(),
        &host,
        b_pub,
        b_priv,
    )
    .await
    .unwrap();
    let _ = server; // 状态经 Arc 共享
    let mut a = a;
    let mut b = b;
    // WG 密文占位（中继不解析载荷）
    a.send(&b_pub, &[0x01, 0x02, 0x03, 0x04]).await.unwrap();
    let got = tokio::time::timeout(std::time::Duration::from_secs(5), b.recv())
        .await
        .expect("relay within 5s")
        .unwrap();
    assert_eq!(got.source, a_pub);
    assert_eq!(got.data, vec![0x01, 0x02, 0x03, 0x04]);
}

/// 服务端噪声响应侧与客户端互操作（进程内连接对：帧逐字节走完整栈）
#[tokio::test]
async fn full_stack_over_plain_tcp() {
    let (port, _server) = spawn_server(&[]).await;
    let host = format!("127.0.0.1:{port}");
    let (m1, _) = ts2021::generate_keypair().unwrap();
    let (_, n1) = ts2021::generate_keypair().unwrap();
    // 预取 + 升级 + 注册 + map 全链路（连接级回归：含 early payload 读取）
    let mut a = connect_and_register(port, &m1, &n1, "solo", AUTH_KEY)
        .await
        .unwrap();
    let map = a.map(&n1, &[9u8; 32], "solo", &host, None).await.unwrap();
    assert_eq!(map.self_ipv4(), Some("100.64.0.1".parse().unwrap()));
    assert!(map.peers.as_ref().unwrap().is_empty());
}

fn _unused(m: &MapResponse) -> bool {
    m.has_netmap_data()
}
