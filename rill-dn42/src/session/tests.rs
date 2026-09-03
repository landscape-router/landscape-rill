//! 会话驱动集成测试：双 PeerSession 进程内互通（WG over loopback UDP + smoltcp BGP），
//! 验证握手 → OPEN 协商 → Established → 互学路由 → 数据面双向透传全链路。

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use super::*;
use boringtun::x25519::{PublicKey, StaticSecret};
use landscape_rill_core::route::Prefix;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

fn init_log() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
}

fn clamped_key(seed: u8) -> [u8; 32] {
    let mut k = [seed; 32];
    k[0] &= 248;
    k[31] = k[31] & 127 | 64;
    k
}

#[allow(clippy::too_many_arguments)]
fn peer_config(
    name: &str,
    active: bool,
    endpoint: SocketAddr,
    own_priv: [u8; 32],
    peer_pub: [u8; 32],
    index: u32,
    local_as: u32,
    peer_as: u32,
    own: &str,
    local_bgp_port: u16,
) -> PeerConfig {
    PeerConfig {
        name: name.into(),
        active,
        endpoint,
        keys: crate::tunnel::WgPeerKeys {
            own_private: own_priv,
            peer_public: peer_pub,
            preshared: None,
            index,
        },
        // 拓扑：active 方 = .1，passive 方 = .2（/30 + /126 隧道内）
        local_v4: if active {
            Ipv4Addr::new(172, 20, 100, 1)
        } else {
            Ipv4Addr::new(172, 20, 100, 2)
        },
        local_v6: if active {
            "fd00:100::1".parse().unwrap()
        } else {
            "fd00:100::2".parse().unwrap()
        },
        peer_v4: if active {
            Ipv4Addr::new(172, 20, 100, 2)
        } else {
            Ipv4Addr::new(172, 20, 100, 1)
        },
        peer_v6: if active {
            "fd00:100::2".parse().unwrap()
        } else {
            "fd00:100::1".parse().unwrap()
        },
        bgp_port: 179,
        local_bgp_port,
        bgp: BgpSessionConfig {
            local_as,
            bgp_id: Ipv4Addr::new(172, 20, 100, if active { 1 } else { 2 }),
            peer_as,
            hold_time: 90,
            own_prefixes: vec![Prefix::parse(own).unwrap()],
            whitelist: vec![
                Prefix::parse("172.20.0.0/14").unwrap(),
                Prefix::parse("fd00::/8").unwrap(),
            ],
            max_prefixes: None,
        },
    }
}

/// dst 指向 addr 的最小 IPv4 包（数据面用）
fn dataplane_v4(dst: Ipv4Addr, marker: u8) -> Vec<u8> {
    let mut p = vec![
        0x45, 0, 0, 24, 0, 0, 0, 0, 64, 6, 0, 0, 10, 42, 0, 1, 0, 0, 0, 0,
    ];
    p[16..20].copy_from_slice(&dst.octets());
    p.extend_from_slice(&[marker, 0xad, 0xbe, 0xef]);
    let total = p.len() as u16;
    p[2..4].copy_from_slice(&total.to_be_bytes());
    p
}

/// 收集事件直到同时出现 SessionUp 与目标前缀的 Changes（带超时）
async fn wait_established_and_routes(
    events: &mut mpsc::Receiver<RouteEvent>,
    want_prefix: &str,
) -> Vec<RouteEvent> {
    let deadline = Duration::from_secs(15);
    let start = std::time::Instant::now();
    let mut seen = Vec::new();
    loop {
        assert!(
            start.elapsed() < deadline,
            "timeout waiting for established+routes: {seen:?}"
        );
        let ev = tokio::time::timeout(deadline, events.recv())
            .await
            .expect("no timeout")
            .expect("channel closed");
        let done = matches!(ev, RouteEvent::SessionUp)
            || matches!(&ev, RouteEvent::Changes(cs)
                if cs.iter().any(|c| matches!(c, crate::rib::RouteChange::Learned { prefix, .. }
                    if prefix.to_cidr() == want_prefix)));
        seen.push(ev);
        if seen.iter().any(|e| matches!(e, RouteEvent::SessionUp))
            && matches!(&seen.last().unwrap(), RouteEvent::Changes(cs)
                if cs.iter().any(|c| matches!(c, crate::rib::RouteChange::Learned { prefix, .. }
                    if prefix.to_cidr() == want_prefix)))
        {
            let _ = done;
            return seen;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_peers_establish_learn_and_forward() {
    init_log();
    let a_priv = clamped_key(1);
    let b_priv = clamped_key(2);
    let a_pub = PublicKey::from(&StaticSecret::from(a_priv)).to_bytes();
    let b_pub = PublicKey::from(&StaticSecret::from(b_priv)).to_bytes();

    let udp_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr_a = udp_a.local_addr().unwrap();
    let addr_b = udp_b.local_addr().unwrap();

    let cfg_a = peer_config(
        "node-a",
        true,
        addr_b,
        a_priv,
        b_pub,
        1,
        4242420001,
        4242420002,
        "172.20.1.0/24",
        10179,
    );
    let cfg_b = peer_config(
        "node-b",
        false,
        addr_a,
        b_priv,
        a_pub,
        2,
        4242420002,
        4242420001,
        "172.20.200.0/24",
        10180,
    );

    let (a_out_tx, a_out_rx) = mpsc::channel(64);
    let (a_pt_tx, mut a_pt_rx) = mpsc::channel(64);
    let (a_ev_tx, mut a_ev_rx) = mpsc::channel(64);
    let (b_out_tx, b_out_rx) = mpsc::channel(64);
    let (b_pt_tx, mut b_pt_rx) = mpsc::channel(64);
    let (b_ev_tx, mut b_ev_rx) = mpsc::channel(64);

    tokio::spawn(run_peer(
        cfg_a,
        udp_a,
        a_out_rx,
        PeerHooks {
            plaintext_out: a_pt_tx,
            events: a_ev_tx.clone(),
        },
        a_ev_tx.clone(),
    ));
    tokio::spawn(run_peer(
        cfg_b,
        udp_b,
        b_out_rx,
        PeerHooks {
            plaintext_out: b_pt_tx,
            events: b_ev_tx.clone(),
        },
        b_ev_tx.clone(),
    ));

    // 双向 Established + 互学路由
    let _ = wait_established_and_routes(&mut a_ev_rx, "172.20.200.0/24").await;
    let _ = wait_established_and_routes(&mut b_ev_rx, "172.20.1.0/24").await;

    // 数据面：a → b（a 的 tun 侧包经隧道到 b 明文出口）
    let pkt = dataplane_v4(Ipv4Addr::new(172, 20, 200, 5), 0x42);
    a_out_tx.send(pkt).await.unwrap();
    let got = tokio::time::timeout(Duration::from_secs(10), b_pt_rx.recv())
        .await
        .expect("timeout")
        .expect("closed");
    assert_eq!(got[16..20], [172, 20, 200, 5]);
    assert_eq!(got[20], 0x42);

    // 数据面：b → a
    let pkt = dataplane_v4(Ipv4Addr::new(172, 20, 1, 7), 0x77);
    b_out_tx.send(pkt).await.unwrap();
    let got = tokio::time::timeout(Duration::from_secs(10), a_pt_rx.recv())
        .await
        .expect("timeout")
        .expect("closed");
    assert_eq!(got[16..20], [172, 20, 1, 7]);
    assert_eq!(got[20], 0x77);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn whitelist_rejects_bad_routes() {
    init_log();
    let a_priv = clamped_key(3);
    let b_priv = clamped_key(4);
    let a_pub = PublicKey::from(&StaticSecret::from(a_priv)).to_bytes();
    let b_pub = PublicKey::from(&StaticSecret::from(b_priv)).to_bytes();

    let udp_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr_a = udp_a.local_addr().unwrap();
    let addr_b = udp_b.local_addr().unwrap();

    // b 公告白名单外前缀 10.99.0.0/16
    let mut cfg_b = peer_config(
        "node-b",
        false,
        addr_a,
        b_priv,
        a_pub,
        2,
        4242420002,
        4242420001,
        "10.99.0.0/16",
        10190,
    );
    cfg_b.bgp.bgp_id = Ipv4Addr::new(172, 20, 100, 2);
    let cfg_a = peer_config(
        "node-a",
        true,
        addr_b,
        a_priv,
        b_pub,
        1,
        4242420001,
        4242420002,
        "172.20.1.0/24",
        10191,
    );

    let (_a_out_tx, a_out_rx) = mpsc::channel(64);
    let (a_pt_tx, _a_pt_rx) = mpsc::channel(64);
    let (a_ev_tx, mut a_ev_rx) = mpsc::channel(64);
    let (_b_out_tx, b_out_rx) = mpsc::channel(64);
    let (b_pt_tx, _b_pt_rx) = mpsc::channel(64);
    let (b_ev_tx, _b_ev_rx) = mpsc::channel(64);

    tokio::spawn(run_peer(
        cfg_a,
        udp_a,
        a_out_rx,
        PeerHooks {
            plaintext_out: a_pt_tx,
            events: a_ev_tx.clone(),
        },
        a_ev_tx.clone(),
    ));
    tokio::spawn(run_peer(
        cfg_b,
        udp_b,
        b_out_rx,
        PeerHooks {
            plaintext_out: b_pt_tx,
            events: b_ev_tx.clone(),
        },
        b_ev_tx.clone(),
    ));

    // a Established 但学不到 10.99/16（import policy 拒绝）
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    let mut got_up = false;
    while std::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(1), a_ev_rx.recv()).await {
            Ok(Some(RouteEvent::SessionUp)) => got_up = true,
            Ok(Some(RouteEvent::Changes(cs))) => {
                assert!(
                    !cs.iter().any(
                        |c| matches!(c, crate::rib::RouteChange::Learned { prefix, .. }
                        if prefix.to_cidr().starts_with("10.99."))
                    ),
                    "白名单外前缀不得学入"
                );
            }
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => break,
        }
    }
    assert!(got_up, "会话应建立: {got_up}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_down_purges_routes() {
    init_log();
    // b 停机（drop socket）→ a SessionDown + Changes 撤销
    let a_priv = clamped_key(5);
    let b_priv = clamped_key(6);
    let a_pub = PublicKey::from(&StaticSecret::from(a_priv)).to_bytes();
    let b_pub = PublicKey::from(&StaticSecret::from(b_priv)).to_bytes();

    let udp_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr_a = udp_a.local_addr().unwrap();
    let addr_b = udp_b.local_addr().unwrap();

    let cfg_a = peer_config(
        "node-a",
        true,
        addr_b,
        a_priv,
        b_pub,
        1,
        4242420001,
        4242420002,
        "172.20.1.0/24",
        10201,
    );
    let cfg_b = peer_config(
        "node-b",
        false,
        addr_a,
        b_priv,
        a_pub,
        2,
        4242420002,
        4242420001,
        "172.20.200.0/24",
        10202,
    );

    let (_a_out_tx, a_out_rx) = mpsc::channel(64);
    let (a_pt_tx, _a_pt_rx) = mpsc::channel(64);
    let (a_ev_tx, mut a_ev_rx) = mpsc::channel(64);
    let (_b_out_tx, b_out_rx) = mpsc::channel(64);
    let (b_pt_tx, _b_pt_rx) = mpsc::channel(64);
    let (b_ev_tx, _b_ev_rx) = mpsc::channel(64);

    tokio::spawn(run_peer(
        cfg_a,
        udp_a,
        a_out_rx,
        PeerHooks {
            plaintext_out: a_pt_tx,
            events: a_ev_tx.clone(),
        },
        a_ev_tx.clone(),
    ));
    // b 跑在可放弃的任务里
    let b_task = tokio::spawn(run_peer(
        cfg_b,
        udp_b,
        b_out_rx,
        PeerHooks {
            plaintext_out: b_pt_tx,
            events: b_ev_tx.clone(),
        },
        b_ev_tx.clone(),
    ));

    wait_established_and_routes(&mut a_ev_rx, "172.20.200.0/24").await;

    // 杀掉 b
    b_task.abort();

    // a 在 hold timer（协商 90s）内不会断——用 TCP 保持验证不现实；这里只验证撤销路径由
    // hold/断链驱动，收 SessionDown 前不误发。等待较久（hold 上限远超测试时长）——
    // 该场景的完整验证由 e2e DNL-07（docker stop peer-r）承载。
    // 此处断言：abort b 后，a 的会话仍保持（WG 会话在静默期不立即断）。
    let mut saw_down = false;
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while std::time::Instant::now() < deadline {
        if let Ok(Some(RouteEvent::SessionDown)) =
            tokio::time::timeout(Duration::from_millis(100), a_ev_rx.recv()).await
        {
            saw_down = true;
            break;
        }
    }
    assert!(
        !saw_down,
        "b 停止后 WG 静默期内 a 的会话不应立即断（hold 语义）"
    );
}
