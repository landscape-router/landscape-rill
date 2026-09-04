use super::*;
use landscape_rill_core::crypto::{derive_key_dst, KEY_DST_LEN};
use landscape_rill_core::frame::{build_frame, packet_type, TAG_LEN, VERSION};
use landscape_rill_core::handshake::{BINDING_LEN, SESSION_KEY_LEN};
use tokio::net::UdpSocket;

const MASTER: [u8; 32] = [0x42; 32];
const NETWORK_ID: u32 = 0x0000_0001;

fn node_key(node_id: u32) -> [u8; KEY_DST_LEN] {
    derive_key_dst(&MASTER, node_id)
}

fn ctx(id: u8) -> HandshakeContext {
    HandshakeContext {
        network_id: NETWORK_ID,
        version: VERSION,
        local_static: [id; SESSION_KEY_LEN],
        identity_binding: [0x5a; BINDING_LEN].to_vec(),
    }
}

/// 私钥 [id; 32] 的 X25519 公钥（netmap/身份绑定携带的是公钥）
fn peer_static(id: u8) -> [u8; 32] {
    use x25519_dalek::{PublicKey, StaticSecret};
    PublicKey::from(&StaticSecret::from([id; 32])).to_bytes()
}

fn verifier(node_id: u32, static_pubkey: &[u8; 32], _binding: &[u8]) -> bool {
    static_pubkey == &peer_static(node_id as u8)
}

fn frame_from(from: u32, to: u32, payload: &[u8], ttl: u8, seq: u32) -> Vec<u8> {
    let header = MeshFrameHeader {
        to_node_id: to,
        from_node_id: from,
        seq,
        ttl,
        ..Default::default()
    };
    build_frame(&header, &node_key(to), &[0x24; 32], 0x1234_5678, payload).unwrap()
}

async fn setup_pair() -> (MeshData, MeshData) {
    let mut a = MeshData::bind("127.0.0.1:0".parse().unwrap(), 1)
        .await
        .unwrap();
    let mut b = MeshData::bind("127.0.0.1:0".parse().unwrap(), 2)
        .await
        .unwrap();
    wire_pair(&mut a, &mut b).await;
    (a, b)
}

/// TCP 兜底 underlay 节点对（REQ-054：帧字节跨传输一致，配对注入逻辑同 UDP）
async fn setup_pair_tcp() -> (MeshData, MeshData) {
    let mut a = MeshData::bind_underlay(
        Underlay::Tcp(
            TcpTransport::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap(),
        ),
        1,
    )
    .await
    .unwrap();
    let mut b = MeshData::bind_underlay(
        Underlay::Tcp(
            TcpTransport::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap(),
        ),
        2,
    )
    .await
    .unwrap();
    wire_pair(&mut a, &mut b).await;
    (a, b)
}

async fn wire_pair(a: &mut MeshData, b: &mut MeshData) {
    let a_addr = a.local_addr().unwrap();
    let b_addr = b.local_addr().unwrap();
    for id in [1u32, 2] {
        a.set_key_dst(id, node_key(id));
        b.set_key_dst(id, node_key(id));
    }
    a.set_handshake_context(ctx(1));
    b.set_handshake_context(ctx(2));
    a.set_peer_static(2, peer_static(2));
    b.set_peer_static(1, peer_static(1));
    a.set_binding_verifier(verifier);
    b.set_binding_verifier(verifier);
    a.set_endpoint(2, b_addr);
    b.set_endpoint(1, a_addr);
}

/// 从独立 socket 向节点注入原始字节（模拟 WAN 入包；underlay 重构后
/// MeshData 不再暴露内部 socket）
async fn inject(node: &MeshData, bytes: &[u8]) {
    let s = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    s.send_to(bytes, node.local_addr().unwrap()).await.unwrap();
}

#[tokio::test]
async fn full_handshake_and_data_roundtrip() {
    let (mut a, mut b) = setup_pair().await;
    let msg1 = a.initiate_handshake(2).unwrap().unwrap();
    a.send_to_node(2, &msg1).await.unwrap();
    assert_eq!(
        b.handle_incoming().await.unwrap(),
        IncomingEvent::Responded { peer: 1 }
    );
    assert_eq!(
        a.handle_incoming().await.unwrap(),
        IncomingEvent::Established { peer: 2 }
    );
    assert_eq!(
        b.handle_incoming().await.unwrap(),
        IncomingEvent::Established { peer: 1 }
    );
    assert!(a.has_session(2) && b.has_session(1));

    let (frame, hop) = a.build_data_frame(2, b"hello mesh", 0).unwrap();
    a.send_to_node_hop(2, hop, &frame).await.unwrap();
    assert_eq!(
        b.handle_incoming().await.unwrap(),
        IncomingEvent::Data {
            from: 1,
            payload: b"hello mesh".to_vec().into()
        }
    );

    let (frame, hop) = b.build_data_frame(1, b"reply", 0).unwrap();
    b.send_to_node_hop(1, hop, &frame).await.unwrap();
    assert_eq!(
        a.handle_incoming().await.unwrap(),
        IncomingEvent::Data {
            from: 2,
            payload: b"reply".to_vec().into()
        }
    );
}

#[tokio::test]
async fn initiate_handshake_idempotent_after_session() {
    let (mut a, mut b) = setup_pair().await;
    let msg1 = a.initiate_handshake(2).unwrap().unwrap();
    a.send_to_node(2, &msg1).await.unwrap();
    assert_eq!(
        b.handle_incoming().await.unwrap(),
        IncomingEvent::Responded { peer: 1 }
    );
    assert_eq!(
        a.handle_incoming().await.unwrap(),
        IncomingEvent::Established { peer: 2 }
    );
    assert_eq!(
        b.handle_incoming().await.unwrap(),
        IncomingEvent::Established { peer: 1 }
    );
    assert_eq!(a.initiate_handshake(2).unwrap(), None);
}

#[tokio::test]
async fn handshake_redirect_rejected() {
    let (mut a, mut b) = setup_pair().await;
    a.set_peer_static(3, peer_static(3));
    a.set_key_dst(3, node_key(3));
    let msg1 = a.initiate_handshake(3).unwrap().unwrap();

    let h = MeshFrameHeader::decode(&msg1).unwrap();
    let payload = frame_payload(&msg1).unwrap();
    let mut redirected = h.clone();
    redirected.to_node_id = 2;
    let frame = build_handshake_frame(&redirected, &node_key(2), payload);

    a.send_to_node(2, &frame).await.unwrap();
    assert_eq!(
        b.handle_incoming().await.unwrap(),
        IncomingEvent::Rejected {
            peer: 1,
            reason: HandshakeError::WrongTarget
        }
    );
}

#[tokio::test]
async fn bad_binding_rejected_over_wire() {
    let (mut a, mut b) = setup_pair().await;
    b.set_binding_verifier(|_, _, _| false);
    let msg1 = a.initiate_handshake(2).unwrap().unwrap();
    a.send_to_node(2, &msg1).await.unwrap();
    assert_eq!(
        b.handle_incoming().await.unwrap(),
        IncomingEvent::Responded { peer: 1 }
    );
    assert_eq!(
        a.handle_incoming().await.unwrap(),
        IncomingEvent::Established { peer: 2 }
    );
    assert_eq!(
        b.handle_incoming().await.unwrap(),
        IncomingEvent::Rejected {
            peer: 1,
            reason: HandshakeError::BadBinding
        }
    );
    assert!(a.has_session(2));
    assert!(!b.has_session(1));
}

#[tokio::test]
async fn prologue_mismatch_rejected_over_wire() {
    // B 网络不同：msg1 无加密可读、B 回 msg2，A 在 msg2 解密时失败（AEAD AAD=h 含 prologue）
    let (mut a, mut b) = setup_pair().await;
    let mut ctx_b = ctx(2);
    ctx_b.network_id = 0x0000_0002;
    b.set_handshake_context(ctx_b);
    let msg1 = a.initiate_handshake(2).unwrap().unwrap();
    a.send_to_node(2, &msg1).await.unwrap();
    assert_eq!(
        b.handle_incoming().await.unwrap(),
        IncomingEvent::Responded { peer: 1 }
    );
    match a.handle_incoming().await.unwrap() {
        IncomingEvent::Rejected {
            peer: 2,
            reason: HandshakeError::Noise(_),
        } => {}
        other => panic!("expected Noise rejection, got {:?}", other),
    }
    assert!(!a.has_session(2));
    assert!(!b.has_session(1));
}

#[tokio::test]
async fn msg2_without_initiator_rejected() {
    let (mut a, mut b) = setup_pair().await;
    let header = MeshFrameHeader {
        to_node_id: 2,
        from_node_id: 1,
        ..Default::default()
    };
    let junk = [0u8; MSG2_PAYLOAD_LEN];
    let frame = build_handshake_frame(&header, &node_key(2), &junk);
    a.send_to_node(2, &frame).await.unwrap();
    assert_eq!(
        b.handle_incoming().await.unwrap(),
        IncomingEvent::Rejected {
            peer: 1,
            reason: HandshakeError::WrongStep
        }
    );
}

#[tokio::test]
async fn heartbeat_roundtrip() {
    let (mut a, mut b) = setup_pair().await;
    let msg1 = a.initiate_handshake(2).unwrap().unwrap();
    a.send_to_node(2, &msg1).await.unwrap();
    assert_eq!(
        b.handle_incoming().await.unwrap(),
        IncomingEvent::Responded { peer: 1 }
    );
    assert_eq!(
        a.handle_incoming().await.unwrap(),
        IncomingEvent::Established { peer: 2 }
    );
    assert_eq!(
        b.handle_incoming().await.unwrap(),
        IncomingEvent::Established { peer: 1 }
    );

    let hb = a.build_heartbeat_frame(2).unwrap();
    a.send_to_node(2, &hb).await.unwrap();
    assert_eq!(
        b.handle_incoming().await.unwrap(),
        IncomingEvent::Heartbeat { from: 1 }
    );
}

#[tokio::test]
async fn heartbeat_before_session_rejected() {
    let mut a = MeshData::bind("127.0.0.1:0".parse().unwrap(), 1)
        .await
        .unwrap();
    assert_eq!(
        a.build_heartbeat_frame(2).unwrap_err(),
        SendError::NoSession
    );
    assert_eq!(
        a.build_data_frame(2, b"x", 0).unwrap_err(),
        SendError::NoSession
    );
}

#[tokio::test]
async fn tampered_data_frame_dropped() {
    let (mut a, mut b) = setup_pair().await;
    let msg1 = a.initiate_handshake(2).unwrap().unwrap();
    a.send_to_node(2, &msg1).await.unwrap();
    assert_eq!(
        b.handle_incoming().await.unwrap(),
        IncomingEvent::Responded { peer: 1 }
    );
    assert_eq!(
        a.handle_incoming().await.unwrap(),
        IncomingEvent::Established { peer: 2 }
    );
    assert_eq!(
        b.handle_incoming().await.unwrap(),
        IncomingEvent::Established { peer: 1 }
    );

    let mut frame = a.build_data_frame(2, b"payload", 0).unwrap().0;
    let n = frame.len();
    frame[n - 1] ^= 0xff;
    a.send_to_node(2, &frame).await.unwrap();
    assert_eq!(
        b.handle_incoming().await.unwrap(),
        IncomingEvent::Dropped {
            reason: DropReason::Aead
        }
    );
}

#[tokio::test]
async fn replayed_data_frame_dropped() {
    let (mut a, mut b) = setup_pair().await;
    let msg1 = a.initiate_handshake(2).unwrap().unwrap();
    a.send_to_node(2, &msg1).await.unwrap();
    assert_eq!(
        b.handle_incoming().await.unwrap(),
        IncomingEvent::Responded { peer: 1 }
    );
    assert_eq!(
        a.handle_incoming().await.unwrap(),
        IncomingEvent::Established { peer: 2 }
    );
    assert_eq!(
        b.handle_incoming().await.unwrap(),
        IncomingEvent::Established { peer: 1 }
    );

    let frame = a.build_data_frame(2, b"payload", 0).unwrap().0;
    a.send_to_node(2, &frame).await.unwrap();
    assert_eq!(
        b.handle_incoming().await.unwrap(),
        IncomingEvent::Data {
            from: 1,
            payload: b"payload".to_vec().into()
        }
    );
    a.send_to_node(2, &frame).await.unwrap();
    assert_eq!(
        b.handle_incoming().await.unwrap(),
        IncomingEvent::Dropped {
            reason: DropReason::Replay
        }
    );
}

#[tokio::test]
async fn data_without_session_dropped() {
    let mut a = MeshData::bind("127.0.0.1:0".parse().unwrap(), 1)
        .await
        .unwrap();
    let mut b = MeshData::bind("127.0.0.1:0".parse().unwrap(), 2)
        .await
        .unwrap();
    let b_addr = b.local_addr().unwrap();
    a.set_key_dst(2, node_key(2));
    b.set_key_dst(2, node_key(2));
    a.set_endpoint(2, b_addr);

    let frame = frame_from(1, 2, b"payload", 64, 0);
    a.send_to_node(2, &frame).await.unwrap();
    assert_eq!(
        b.handle_incoming().await.unwrap(),
        IncomingEvent::Dropped {
            reason: DropReason::NoSession
        }
    );
}

// ==================== probe 体系（CONNECTIVITY §2/§4，CON-03/CON-08） ====================

/// 互探：A 向 B 发 PING（to=B）→ B 自动回 PONG → A 侧 nonce 匹配确认
#[tokio::test]
async fn probe_ping_replies_pong_and_matches() {
    use crate::probe::{probe_type, ProbePacket};
    let mut a = MeshData::bind("127.0.0.1:0".parse().unwrap(), 1)
        .await
        .unwrap();
    let mut b = MeshData::bind("127.0.0.1:0".parse().unwrap(), 2)
        .await
        .unwrap();
    let b_addr = b.local_addr().unwrap();
    // A 发送 PING → B 收帧（handle_incoming 分派到 probe）→ 自动回 PONG
    let nonce = a.send_probe_ping(b_addr, 1, 2).await.unwrap();
    let ev = b.handle_incoming().await.unwrap();
    assert!(matches!(ev, IncomingEvent::ProbePing { from: 1 }));
    // B 回 PONG 已发出 → A 收帧 → nonce 匹配确认
    let ev = a.handle_incoming().await.unwrap();
    match ev {
        IncomingEvent::ProbePong {
            from,
            endpoint,
            payload,
        } => {
            assert_eq!(from, 2);
            assert_eq!(endpoint, b_addr);
            assert!(payload.is_empty());
        }
        other => panic!("expected ProbePong, got {:?}", other),
    }
    // PONG 已确认（nonce 已消费）；重复 PONG → 丢弃
    let dup = ProbePacket::pong(&ProbePacket::ping(1, 2, nonce), Vec::new());
    inject(&a, &dup.encode()).await;
    let ev = a.handle_incoming().await.unwrap();
    assert!(matches!(
        ev,
        IncomingEvent::Dropped {
            reason: DropReason::UnknownProtocol
        }
    ));
    let _ = probe_type::PING;
}

/// coordinator 回显（CONNECTIVITY §2）：PONG 携带 seen 地址载荷
#[tokio::test]
async fn probe_echo_pong_carries_seen_addr() {
    use crate::probe::ProbePacket;
    let mut node = MeshData::bind("127.0.0.1:0".parse().unwrap(), 1)
        .await
        .unwrap();
    // 模拟 coordinator：对 to=0（回显标记）的 PING 回带载荷的 PONG
    let nonce = node
        .send_probe_ping(node.local_addr().unwrap(), 1, 0)
        .await
        .unwrap();
    let ping = ProbePacket::ping(1, crate::probe::NODE_ID_COORDINATOR, nonce);
    let pong = ProbePacket::pong(&ping, b"203.0.113.9:41641".to_vec());
    inject(&node, &pong.encode()).await;
    // 先消费自己发出的 PING（to=0 不回 PONG）
    let ev = node.handle_incoming().await.unwrap();
    assert!(matches!(ev, IncomingEvent::ProbePing { from: 1 }));
    let ev = node.handle_incoming().await.unwrap();
    match ev {
        IncomingEvent::ProbePong { payload, .. } => {
            assert_eq!(payload, b"203.0.113.9:41641");
        }
        other => panic!("expected ProbePong, got {:?}", other),
    }
}

/// 端口分派（CON-08）：非帧非 probe 字节 → UnknownProtocol 丢弃
#[tokio::test]
async fn unknown_protocol_dropped() {
    let mut node = MeshData::bind("127.0.0.1:0".parse().unwrap(), 1)
        .await
        .unwrap();
    let garbage = b"\x80not-a-frame-not-a-probe";
    inject(&node, garbage).await;
    let ev = node.handle_incoming().await.unwrap();
    assert!(matches!(
        ev,
        IncomingEvent::Dropped {
            reason: DropReason::UnknownProtocol
        }
    ));
}

/// 预认证分派语料（REQ-059 / SEC-08，CONNECTIVITY §2.1 / FRAME_HEADER §5.1）：
/// 全首字节值域 + probe 全 type 值域 + 随机洪泛——收端只产出合法事件、不 panic
#[tokio::test]
async fn preauth_dispatch_fuzz_corpus() {
    let mut node = MeshData::bind("127.0.0.1:0".parse().unwrap(), 1)
        .await
        .unwrap();

    // 全首字节值域：0x01..=0x0F 走帧路径（Version/Short/NoKeyDst 拒绝，非 UnknownProtocol），
    // 其余非 magic → UnknownProtocol
    for first in 0..=255u8 {
        let mut pkt = vec![first; 40];
        pkt[1..].iter_mut().enumerate().for_each(|(i, b)| {
            *b = (i * 31 + 7) as u8;
        });
        inject(&node, &pkt).await;
        let ev = node.handle_incoming().await.unwrap();
        match first {
            b if (0x01..=0x0F).contains(&b) => match ev {
                IncomingEvent::Dropped { reason } => {
                    assert_ne!(reason, DropReason::UnknownProtocol);
                }
                other => panic!("帧路径首字节 {b:#x} 产出预期外事件: {other:?}"),
            },
            _ => assert!(matches!(
                ev,
                IncomingEvent::Dropped {
                    reason: DropReason::UnknownProtocol
                }
            )),
        }
    }

    // probe 路径：全 type 值域（PING 对己 → ProbePing 事件；其余 → 丢弃）
    for t in 0..=255u8 {
        let mut pkt = vec![0u8; 17 + 8];
        pkt[..4].copy_from_slice(&crate::probe::PROBE_MAGIC);
        pkt[4] = t;
        pkt[5..].iter_mut().enumerate().for_each(|(i, b)| {
            *b = (i * 13 + 3) as u8;
        });
        inject(&node, &pkt).await;
        let ev = node.handle_incoming().await.unwrap();
        assert!(
            matches!(
                ev,
                IncomingEvent::ProbePing { .. } | IncomingEvent::Dropped { .. }
            ),
            "probe type {t} 产出预期外事件"
        );
    }

    // 随机洪泛：任意长度随机字节 → 恒 Ok、不 panic
    let mut s: u64 = 0xD15A_0006;
    let mut pkt = [0u8; 200];
    for _ in 0..500 {
        let len = (xorshift(&mut s) % 201) as usize;
        for b in pkt[..len].iter_mut() {
            *b = xorshift(&mut s) as u8;
        }
        inject(&node, &pkt[..len]).await;
        let _ = node.handle_incoming().await.unwrap();
    }
}

fn xorshift(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

/// 发给他人的 PING → 不回 PONG（互探目标定向）
#[tokio::test]
async fn probe_ping_foreign_target_not_replied() {
    use crate::probe::ProbePacket;
    let mut a = MeshData::bind("127.0.0.1:0".parse().unwrap(), 1)
        .await
        .unwrap();
    let mut b = MeshData::bind("127.0.0.1:0".parse().unwrap(), 2)
        .await
        .unwrap();
    // A 收到发给节点 3 的 PING（B 与 A 无关）→ B 不应收到 PONG 之外的任何帧
    let ping = ProbePacket::ping(3, 3, 55).encode();
    inject(&a, &ping).await;
    let ev = a.handle_incoming().await.unwrap();
    assert!(matches!(ev, IncomingEvent::ProbePing { from: 3 }));
    // A 不应自动回任何东西：直接检查 b 的 socket 无入帧（对 A 本地环回，回包会到 a 自己）
    // 用 timeout 收帧验证没有回复（PONG 会打到 a 的本地地址）
    let r = tokio::time::timeout(std::time::Duration::from_millis(200), b.handle_incoming()).await;
    assert!(r.is_err(), "收到预期外的回复帧");
}

/// PONG 生成按源限速（SEC-26/REQ-046）：同源 PING 超突发容量后不再回 PONG
#[tokio::test]
async fn pong_generation_rate_limited_per_source() {
    let mut a = MeshData::bind("127.0.0.1:0".parse().unwrap(), 1)
        .await
        .unwrap();
    let mut b = MeshData::bind("127.0.0.1:0".parse().unwrap(), 2)
        .await
        .unwrap();
    let b_addr = b.local_addr().unwrap();
    // 容量 20：前 20 个 PING 各回一个 PONG（a 消费 PONG，nonce 不积压）
    for _ in 0..PONG_CAPACITY {
        assert!(a.send_probe_ping(b_addr, 1, 2).await.is_some());
        let _ = b.handle_incoming().await.unwrap();
        let _ = a.handle_incoming().await.unwrap();
    }
    // 第 21 个 PING：事件仍上报，但 PONG 被限速 → a 侧 200ms 无包
    assert!(a.send_probe_ping(b_addr, 1, 2).await.is_some());
    assert!(matches!(
        b.handle_incoming().await.unwrap(),
        IncomingEvent::ProbePing { from: 1 }
    ));
    let r = tokio::time::timeout(std::time::Duration::from_millis(200), a.handle_incoming()).await;
    assert!(r.is_err(), "PONG 应被按源限速抑制");
}

/// 在途 probe 并发上限（CN-01/REQ-046）：pending 达上限拒绝新发送，drain 后恢复
#[tokio::test]
async fn probe_pending_cap_rejects_new_sends() {
    let mut a = MeshData::bind("127.0.0.1:0".parse().unwrap(), 1)
        .await
        .unwrap();
    let target: std::net::SocketAddr = "127.0.0.1:20999".parse().unwrap();
    for _ in 0..PROBE_MAX_PENDING {
        assert!(a.send_probe_ping(target, 1, 2).await.is_some());
    }
    assert_eq!(a.probe_pending_len(), PROBE_MAX_PENDING);
    assert!(
        a.send_probe_ping(target, 1, 2).await.is_none(),
        "超并发上限应拒绝"
    );
    // 周期 drain（退避推进用）后恢复可发
    assert_eq!(a.take_pending_probes().len(), PROBE_MAX_PENDING);
    assert!(a.send_probe_ping(target, 1, 2).await.is_some());
}

#[tokio::test]
async fn unsupported_type_dropped() {
    let mut a = MeshData::bind("127.0.0.1:0".parse().unwrap(), 1)
        .await
        .unwrap();
    let mut b = MeshData::bind("127.0.0.1:0".parse().unwrap(), 2)
        .await
        .unwrap();
    let b_addr = b.local_addr().unwrap();
    a.set_key_dst(2, node_key(2));
    b.set_key_dst(2, node_key(2));
    a.set_endpoint(2, b_addr);

    let header = MeshFrameHeader {
        packet_type: packet_type::CONTROL,
        to_node_id: 2,
        from_node_id: 1,
        ..Default::default()
    };
    let mut frame = vec![0u8; HEADER_LEN + 4];
    let mut h = header.clone();
    h.len = 4;
    let ai = h.auth_input();
    h.route_mac = landscape_rill_core::crypto::route_mac(&node_key(2), &ai);
    h.encode(&mut frame);
    frame[HEADER_LEN..].copy_from_slice(b"ctrl");
    a.send_to_node(2, &frame).await.unwrap();
    assert_eq!(
        b.handle_incoming().await.unwrap(),
        IncomingEvent::Dropped {
            reason: DropReason::UnsupportedType
        }
    );
}

#[tokio::test]
async fn forward_through_relay() {
    let mut relay = MeshData::bind("127.0.0.1:0".parse().unwrap(), 2)
        .await
        .unwrap();
    let mut b = MeshData::bind("127.0.0.1:0".parse().unwrap(), 3)
        .await
        .unwrap();
    let b_addr = b.local_addr().unwrap();

    relay.set_key_dst(3, node_key(3));
    relay.set_endpoint(3, b_addr);
    b.set_key_dst(3, node_key(3));

    let frame = frame_from(1, 3, b"payload", 64, 1);
    inject(&relay, &frame).await;
    let (_, mut recv) = relay.recv_frame().await.unwrap();
    assert_eq!(
        relay.relay(&mut recv).await,
        RelayOutcome::Forwarded { to: 3 }
    );
    let (_, mut recv2) = b.recv_frame().await.unwrap();
    assert_eq!(recv2[3], 63);
    let delivered = b.relay(&mut recv2).await;
    match delivered {
        RelayOutcome::Delivered { from } => {
            assert_eq!(from, 1);
        }
        other => panic!("expected delivered, got {:?}", other),
    }
}

#[tokio::test]
async fn tampered_frame_dropped() {
    let mut relay = MeshData::bind("127.0.0.1:0".parse().unwrap(), 2)
        .await
        .unwrap();
    relay.set_key_dst(3, node_key(3));
    let mut frame = frame_from(1, 3, b"payload", 64, 1);
    frame[8] ^= 0x01;
    assert_eq!(
        relay.relay(&mut frame).await,
        RelayOutcome::Dropped {
            reason: DropReason::BadRouteMac
        }
    );
}

// ==================== 路径数据面（CONTROL_PLANE §3.11 / FRAME_HEADER §9） ====================

fn path_key(_path_id: u64) -> [u8; KEY_DST_LEN] {
    [0x77; 32] // 测试用 key_path（真实 = derive_key_path）
}

#[tokio::test]
async fn path_data_frame_roundtrip_via_direct_path() {
    let (mut a, mut b) = setup_pair().await;
    // 完整握手
    let msg1 = a.initiate_handshake(2).unwrap().unwrap();
    a.send_to_node(2, &msg1).await.unwrap();
    assert_eq!(
        b.handle_incoming().await.unwrap(),
        IncomingEvent::Responded { peer: 1 }
    );
    assert_eq!(
        a.handle_incoming().await.unwrap(),
        IncomingEvent::Established { peer: 2 }
    );
    assert_eq!(
        b.handle_incoming().await.unwrap(),
        IncomingEvent::Established { peer: 1 }
    );
    // 路径注入（direct：hops=[2]）
    let path = PathEntry {
        path_id: 0x100,
        path_epoch: 1,
        hops: vec![2],
        expires_at: unix_seconds() + 3600,
    };
    a.set_paths(2, vec![path.clone()]);
    a.set_key_path(0x100, path_key(0x100));
    b.set_key_path(0x100, path_key(0x100));
    // 路径数据帧（path_id 非零）
    let (frame, first_hop) = a.build_data_frame(2, b"hello path", 0x1234).unwrap();
    assert_eq!(first_hop, Some(2));
    assert_eq!(frame.len(), HEADER_LEN + 10 + TAG_LEN);
    assert_eq!(MeshFrameHeader::decode(&frame).unwrap().version, VERSION);
    assert_eq!(MeshFrameHeader::decode(&frame).unwrap().path_id, 0x100);
    a.send_to_node_hop(2, first_hop, &frame).await.unwrap();
    // B 收帧：path_id 选 key_path 校验 + 解密
    match b.handle_incoming().await.unwrap() {
        IncomingEvent::Data { from, payload } => {
            assert_eq!(from, 1);
            assert_eq!(payload.as_ref(), b"hello path");
        }
        other => panic!("expected data, got {:?}", other),
    }
}

#[tokio::test]
async fn path_frame_without_key_path_dropped() {
    // path_id 无对应 key_path → NoKeyDst（fail-closed）
    let (mut a, mut b) = setup_pair().await;
    let msg1 = a.initiate_handshake(2).unwrap().unwrap();
    a.send_to_node(2, &msg1).await.unwrap();
    let _ = b.handle_incoming().await.unwrap();
    let _ = a.handle_incoming().await.unwrap();
    let _ = b.handle_incoming().await.unwrap();
    let path = PathEntry {
        path_id: 0x200,
        path_epoch: 1,
        hops: vec![2],
        expires_at: unix_seconds() + 3600,
    };
    a.set_paths(2, vec![path]);
    a.set_key_path(0x200, path_key(0x200));
    // B 无 key_path(0x200)
    let (frame, hop) = a.build_data_frame(2, b"secret", 1).unwrap();
    a.send_to_node_hop(2, hop, &frame).await.unwrap();
    match b.handle_incoming().await.unwrap() {
        IncomingEvent::Dropped {
            reason: DropReason::NoKeyDst,
        } => {}
        other => panic!("expected NoKeyDst drop, got {:?}", other),
    }
}

#[tokio::test]
async fn path_frame_forwarded_through_relay_path() {
    // A(1) → R(3) → B(2)：路径帧经 relay 按路径转发（key_path 校验）
    // 握手直连（真实场景 netmap 全量互连）；数据面走 relay 路径
    let mut a = MeshData::bind("127.0.0.1:0".parse().unwrap(), 1)
        .await
        .unwrap();
    let mut r = MeshData::bind("127.0.0.1:0".parse().unwrap(), 3)
        .await
        .unwrap();
    let mut b = MeshData::bind("127.0.0.1:0".parse().unwrap(), 2)
        .await
        .unwrap();
    let a_addr = a.local_addr().unwrap();
    let r_addr = r.local_addr().unwrap();
    let b_addr = b.local_addr().unwrap();
    for id in [1u32, 2, 3] {
        a.set_key_dst(id, node_key(id));
        r.set_key_dst(id, node_key(id));
        b.set_key_dst(id, node_key(id));
    }
    a.set_handshake_context(ctx(1));
    r.set_handshake_context(ctx(3));
    b.set_handshake_context(ctx(2));
    a.set_peer_static(2, peer_static(2));
    b.set_peer_static(1, peer_static(1));
    a.set_binding_verifier(verifier);
    b.set_binding_verifier(verifier);
    a.set_endpoint(2, b_addr);
    b.set_endpoint(1, a_addr);
    // A 的路径首跳 = R（relay 路径发送端点）
    a.set_endpoint(3, r_addr);
    // R 的转发表：知道 B 的端点
    r.set_endpoint(2, b_addr);
    // 握手直连 A↔B
    let msg1 = a.initiate_handshake(2).unwrap().unwrap();
    a.send_to_node(2, &msg1).await.unwrap();
    assert_eq!(
        b.handle_incoming().await.unwrap(),
        IncomingEvent::Responded { peer: 1 }
    );
    assert_eq!(
        a.handle_incoming().await.unwrap(),
        IncomingEvent::Established { peer: 2 }
    );
    assert_eq!(
        b.handle_incoming().await.unwrap(),
        IncomingEvent::Established { peer: 1 }
    );
    // 路径注入：A → B 经 R（hops=[3,2]）；R 持有同路径做转发
    let path = PathEntry {
        path_id: 0x300,
        path_epoch: 1,
        hops: vec![3, 2],
        expires_at: unix_seconds() + 3600,
    };
    for node in [&mut a, &mut r, &mut b] {
        node.set_key_path(0x300, path_key(0x300));
    }
    a.set_paths(2, vec![path.clone()]);
    r.set_paths(2, vec![path.clone()]);
    // A 发路径帧（首跳 = R）
    let (frame, first_hop) = a.build_data_frame(2, b"via relay", 0xabc).unwrap();
    assert_eq!(first_hop, Some(3));
    assert_eq!(MeshFrameHeader::decode(&frame).unwrap().version, VERSION);
    a.send_to_node_hop(2, first_hop, &frame).await.unwrap();
    // R 校验 key_path 并转发到 B
    let (_, mut rcv4) = r.recv_frame().await.unwrap();
    assert_eq!(r.relay(&mut rcv4).await, RelayOutcome::Forwarded { to: 2 });
    // B 收帧解密
    match b.handle_incoming().await.unwrap() {
        IncomingEvent::Data { from, payload } => {
            assert_eq!(from, 1);
            assert_eq!(payload.as_ref(), b"via relay");
        }
        other => panic!("expected data, got {:?}", other),
    }
}

/// CON-06：非主路径（在用中继路径）死亡 → 心跳 miss 落到实际选用路径 → 切换
#[tokio::test]
async fn path_miss_peer_misses_used_path_not_only_main() {
    let mut m = MeshData::bind("127.0.0.1:0".parse().unwrap(), 1)
        .await
        .unwrap();
    // 候选：direct(10) + viaB(11) + viaD(12)
    m.path_table.insert(
        2,
        vec![
            PathEntry {
                path_id: 10,
                path_epoch: 1,
                hops: vec![2],
                expires_at: 0,
            },
            PathEntry {
                path_id: 11,
                path_epoch: 1,
                hops: vec![1, 2],
                expires_at: 0,
            },
            PathEntry {
                path_id: 12,
                path_epoch: 1,
                hops: vec![3, 2],
                expires_at: 0,
            },
        ],
    );
    for pid in [10u64, 11, 12] {
        m.set_key_path(pid, [pid as u8; 32]);
    }
    // 主路径（direct）已死：miss ×3 → 排除
    for _ in 0..PATH_HEALTH_MISS_LIMIT {
        m.path_miss_peer(2);
    }
    // 此时选用 pool[0] = viaB（pick 记录 last_sent_path）
    let used = m.pick_path(2, 0).unwrap();
    assert_eq!(used.path_id, 11);
    // viaB 死亡：心跳 miss ×3 —— 只 miss 主路径的话 viaB 永远健康（卡死），
    // 修复后同时 miss 实际选用路径（viaB）→ 剩 viaD
    for _ in 0..PATH_HEALTH_MISS_LIMIT {
        m.path_miss_peer(2);
    }
    let switched = m.pick_path(2, 0).unwrap();
    assert_eq!(switched.path_id, 12, "在用中继路径死亡后必须切到下一候选");
}

#[tokio::test]
async fn pick_path_switches_on_health_miss() {
    // 快速切换（CONTROL_PLANE §3.11）：主路径 miss 达阈值 → flow hash 选备用
    let mut a = MeshData::bind("127.0.0.1:0".parse().unwrap(), 1)
        .await
        .unwrap();
    let p1 = PathEntry {
        path_id: 1,
        path_epoch: 1,
        hops: vec![2],
        expires_at: unix_seconds() + 3600,
    };
    let p2 = PathEntry {
        path_id: 2,
        path_epoch: 1,
        hops: vec![3, 2],
        expires_at: unix_seconds() + 3600,
    };
    a.set_key_path(1, path_key(1));
    a.set_key_path(2, path_key(2));
    a.set_paths(2, vec![p1.clone(), p2.clone()]);
    // 健康时：flow hash 0 → 路径 1
    let picked = a.pick_path(2, 0).unwrap();
    assert_eq!(picked.path_id, 1);
    // 主路径 miss 达阈值 → 切备用
    for _ in 0..PATH_HEALTH_MISS_LIMIT {
        a.path_miss_peer(2);
    }
    let picked = a.pick_path(2, 0).unwrap();
    assert_eq!(picked.path_id, 2);
    // 收包恢复 → 主路径回归
    a.path_ok_peer(2);
    let picked = a.pick_path(2, 0).unwrap();
    assert_eq!(picked.path_id, 1);
}

#[tokio::test]
async fn relayed_ingress_misses_direct_path() {
    // 经中继到达的帧（UDP 发送者 = relay）：直连路径 miss 递增（中继帧不续命
    // 直连），中继路径 ok——不对称拓扑下响应方也能收敛到中继路径
    let mut a = MeshData::bind("127.0.0.1:0".parse().unwrap(), 1)
        .await
        .unwrap();
    let mut b = MeshData::bind("127.0.0.1:0".parse().unwrap(), 2)
        .await
        .unwrap();
    a.set_endpoint(2, b.local_addr().unwrap());
    b.set_endpoint(1, a.local_addr().unwrap());
    a.set_key_dst(1, node_key(1)); // 自身 key_dst（relay 路由校验用）
    let direct = PathEntry {
        path_id: 1,
        path_epoch: 1,
        hops: vec![3],
        expires_at: unix_seconds() + 3600,
    };
    let relayed = PathEntry {
        path_id: 2,
        path_epoch: 1,
        hops: vec![2, 3],
        expires_at: unix_seconds() + 3600,
    };
    a.set_key_path(1, path_key(1));
    a.set_key_path(2, path_key(2));
    a.set_paths(3, vec![direct, relayed]);
    // 直连预置 miss 2 次（距阈值差 1）
    a.path_miss_peer(3);
    a.path_miss_peer(3); // 节点 3 的 msg1 由中继 b 转发到 a（帧头 from=3，UDP 发送者=2）
    let header = MeshFrameHeader {
        to_node_id: 1,
        from_node_id: 3,
        ..Default::default()
    };
    let frame = build_handshake_frame(&header, &node_key(1), &[0u8; MSG1_PAYLOAD_LEN]);
    b.send_to_node(1, &frame).await.unwrap();
    let _ = a.handle_incoming().await.unwrap();
    // 入站跳=2：直连 miss 达阈值被剔除 → flow hash 选中继路径
    assert_eq!(a.pick_path(3, 0).unwrap().path_id, 2);
}

#[tokio::test]
async fn direct_ingress_resets_path_health() {
    // 直连到达的帧（UDP 发送者 = 源节点）：全部路径健康恢复，主路径回归
    let mut a = MeshData::bind("127.0.0.1:0".parse().unwrap(), 1)
        .await
        .unwrap();
    let mut b = MeshData::bind("127.0.0.1:0".parse().unwrap(), 2)
        .await
        .unwrap();
    a.set_endpoint(3, b.local_addr().unwrap()); // b 充当节点 3 的端点
    b.set_endpoint(1, a.local_addr().unwrap());
    a.set_key_dst(1, node_key(1)); // 自身 key_dst（relay 路由校验用）
    let direct = PathEntry {
        path_id: 1,
        path_epoch: 1,
        hops: vec![3],
        expires_at: unix_seconds() + 3600,
    };
    let relayed = PathEntry {
        path_id: 2,
        path_epoch: 1,
        hops: vec![2, 3],
        expires_at: unix_seconds() + 3600,
    };
    a.set_key_path(1, path_key(1));
    a.set_key_path(2, path_key(2));
    a.set_paths(3, vec![direct, relayed]);
    for _ in 0..PATH_HEALTH_MISS_LIMIT {
        a.path_miss_peer(3);
    }
    assert_eq!(a.pick_path(3, 0).unwrap().path_id, 2); // 直连已剔除
                                                       // 节点 3 直接发来帧（UDP 发送者 = 3 的端点）
    let header = MeshFrameHeader {
        to_node_id: 1,
        from_node_id: 3,
        ..Default::default()
    };
    let frame = build_handshake_frame(&header, &node_key(1), &[0u8; MSG1_PAYLOAD_LEN]);
    b.send_to_node(1, &frame).await.unwrap();
    let _ = a.handle_incoming().await.unwrap();
    // 直连路径恢复 → 主路径回归
    assert_eq!(a.pick_path(3, 0).unwrap().path_id, 1);
}

#[tokio::test]
async fn miss_endpoint_rotates_send_order() {
    // 多端点节点：黑洞端点 miss 后置 → 发送轮换到活性好的端点
    let mut a = MeshData::bind("127.0.0.1:0".parse().unwrap(), 1)
        .await
        .unwrap();
    let ep1 = UdpSocket::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .await
        .unwrap();
    let ep2 = UdpSocket::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .await
        .unwrap();
    let a1 = ep1.local_addr().unwrap();
    let a2 = ep2.local_addr().unwrap();
    a.set_endpoints(2, vec![a1, a2]);
    let mut buf = [0u8; 8];
    // 活性相同 → 原顺序第一个（ep1）
    a.send_to_node_hop(2, Some(2), b"m1").await.unwrap();
    let (n, _) = ep1.recv_from(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"m1");
    // 黑洞 miss（上次发送无响应）→ 下次发送轮换到 ep2
    a.miss_endpoint(2);
    a.send_to_node_hop(2, Some(2), b"m2").await.unwrap();
    let (n, _) = ep2.recv_from(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"m2");
}

#[tokio::test]
async fn expired_path_skipped() {
    let mut a = MeshData::bind("127.0.0.1:0".parse().unwrap(), 1)
        .await
        .unwrap();
    let expired = PathEntry {
        path_id: 9,
        path_epoch: 1,
        hops: vec![2],
        expires_at: 1, // 已过期
    };
    a.set_key_path(9, path_key(9));
    a.set_paths(2, vec![expired]);
    assert!(a.pick_path(2, 0).is_none());
}

#[tokio::test]
async fn ttl_expired_dropped() {
    let mut relay = MeshData::bind("127.0.0.1:0".parse().unwrap(), 2)
        .await
        .unwrap();
    relay.set_key_dst(3, node_key(3));
    let mut frame = frame_from(1, 3, b"payload", 0, 1);
    assert_eq!(
        relay.relay(&mut frame).await,
        RelayOutcome::Dropped {
            reason: DropReason::TtlExpired
        }
    );
}

#[tokio::test]
async fn no_endpoint_dropped() {
    let mut relay = MeshData::bind("127.0.0.1:0".parse().unwrap(), 2)
        .await
        .unwrap();
    relay.set_key_dst(3, node_key(3));
    let mut frame = frame_from(1, 3, b"payload", 64, 1);
    assert_eq!(
        relay.relay(&mut frame).await,
        RelayOutcome::Dropped {
            reason: DropReason::NoEndpoint
        }
    );
}

#[tokio::test]
async fn short_frame_dropped() {
    let mut relay = MeshData::bind("127.0.0.1:0".parse().unwrap(), 2)
        .await
        .unwrap();
    assert_eq!(
        relay.relay(&mut [0u8; 10]).await,
        RelayOutcome::Dropped {
            reason: DropReason::Short
        }
    );
}

#[tokio::test]
async fn delivered_to_self() {
    let mut node = MeshData::bind("127.0.0.1:0".parse().unwrap(), 3)
        .await
        .unwrap();
    node.set_key_dst(3, node_key(3));
    let mut frame = frame_from(1, 3, b"payload", 64, 1);
    match node.relay(&mut frame).await {
        RelayOutcome::Delivered { from, .. } => assert_eq!(from, 1),
        other => panic!("expected delivered, got {:?}", other),
    }
}

#[tokio::test]
async fn bad_version_dropped() {
    let mut relay = MeshData::bind("127.0.0.1:0".parse().unwrap(), 2)
        .await
        .unwrap();
    relay.set_key_dst(3, node_key(3));
    let mut frame = frame_from(1, 3, b"payload", 64, 1);
    frame[0] = 0x03; // 非法版本（合法值仅 0x01）
    assert_eq!(
        relay.relay(&mut frame).await,
        RelayOutcome::Dropped {
            reason: DropReason::BadVersion
        }
    );
}

#[tokio::test]
async fn frame_shorter_than_header_rejected() {
    let mut relay = MeshData::bind("127.0.0.1:0".parse().unwrap(), 2)
        .await
        .unwrap();
    let frame = frame_from(1, 3, b"payload", 64, 1);
    let mut short = frame[..HEADER_LEN - 1].to_vec(); // < 42B
    short[0] = VERSION; // 版本字节合法仍按短帧拒绝
    assert_eq!(
        relay.relay(&mut short).await,
        RelayOutcome::Dropped {
            reason: DropReason::Short
        }
    );
}

#[tokio::test]
async fn send_to_unknown_node_returns_false() {
    let mut a = MeshData::bind("127.0.0.1:0".parse().unwrap(), 1)
        .await
        .unwrap();
    let frame = frame_from(1, 9, b"payload", 64, 1);
    assert!(!a.send_to_node(9, &frame).await.unwrap());
}

fn broadcast_key() -> [u8; 32] {
    derive_key_dst(&MASTER, 0xFFFF_FFFF)
}

async fn broadcast_setup(ids: &[u32]) -> Vec<MeshData> {
    let mut nodes = Vec::new();
    for id in ids {
        nodes.push(
            MeshData::bind("127.0.0.1:0".parse().unwrap(), *id)
                .await
                .unwrap(),
        );
    }
    let addrs: Vec<(u32, SocketAddr)> = nodes
        .iter()
        .map(|n| (n.self_node_id, n.local_addr().unwrap()))
        .collect();
    for node in nodes.iter_mut() {
        node.set_broadcast_key(broadcast_key());
        for (peer, addr) in &addrs {
            if *peer == node.self_node_id {
                continue;
            }
            node.set_endpoint(*peer, *addr);
            // 默认全 opt-in（REQ-035 泛洪目标过滤的正例基线）
            node.set_peer_capabilities(*peer, 0x21);
        }
    }
    nodes
}

#[tokio::test]
async fn broadcast_roundtrip_delivered() {
    let mut nodes = broadcast_setup(&[1, 2]).await;
    let payload = b"nd multicast ns";
    let frame = nodes[0].build_broadcast_frame(payload).unwrap();
    nodes[0].send_to_node(2, &frame).await.unwrap();
    assert_eq!(
        nodes[1].handle_incoming().await.unwrap(),
        IncomingEvent::Broadcast {
            from: 1,
            payload: payload.to_vec().into()
        }
    );
}

#[tokio::test]
async fn broadcast_before_key_dropped() {
    let mut a = MeshData::bind("127.0.0.1:0".parse().unwrap(), 1)
        .await
        .unwrap();
    assert_eq!(
        a.build_broadcast_frame(b"x").unwrap_err(),
        SendError::NoKeyDst
    );
}

#[tokio::test]
async fn broadcast_replay_dropped() {
    // relay 去重（30s）只挡短期重复；重放窗口挡去重过期后的旧帧重注入
    let mut nodes = broadcast_setup(&[1, 2]).await;
    let frame = nodes[0].build_broadcast_frame(b"payload").unwrap();
    let mut buf = BytesMut::from(&frame[..]);
    assert!(matches!(
        nodes[1].handle_broadcast_frame(1, &mut buf),
        IncomingEvent::Broadcast { from: 1, .. }
    ));
    let mut buf2 = BytesMut::from(&frame[..]);
    assert_eq!(
        nodes[1].handle_broadcast_frame(1, &mut buf2),
        IncomingEvent::Dropped {
            reason: DropReason::Replay
        }
    );
}

#[tokio::test]
async fn broadcast_relay_floods_to_all_except_source() {
    let mut nodes = broadcast_setup(&[1, 2, 3]).await;
    let mut frame = nodes[0].build_broadcast_frame(b"hello all").unwrap();
    nodes[0].send_to_node(2, &frame).await.unwrap();
    let outcome = nodes[1].relay(&mut frame).await;
    match outcome {
        RelayOutcome::Flooded {
            from, forwarded, ..
        } => {
            assert_eq!(from, 1);
            assert_eq!(forwarded, vec![3]);
        }
        other => panic!("expected flood, got {:?}", other),
    }
    assert_eq!(
        nodes[2].handle_incoming().await.unwrap(),
        IncomingEvent::Broadcast {
            from: 1,
            payload: b"hello all".to_vec().into()
        }
    );
}

#[tokio::test]
async fn broadcast_relay_no_echo_to_source() {
    let mut nodes = broadcast_setup(&[1, 2, 3]).await;
    let mut frame = nodes[0].build_broadcast_frame(b"hello").unwrap();
    nodes[0].send_to_node(2, &frame).await.unwrap();
    let outcome = nodes[1].relay(&mut frame).await;
    match outcome {
        RelayOutcome::Flooded { forwarded, .. } => assert!(!forwarded.contains(&1)),
        other => panic!("expected flood, got {:?}", other),
    }
}

#[tokio::test]
async fn broadcast_relay_dedup_drops_repeat() {
    let mut nodes = broadcast_setup(&[1, 2]).await;
    let mut frame = nodes[0].build_broadcast_frame(b"hello").unwrap();
    nodes[0].send_to_node(2, &frame).await.unwrap();
    assert!(matches!(
        nodes[1].relay(&mut frame).await,
        RelayOutcome::Flooded { .. }
    ));
    nodes[0].send_to_node(2, &frame).await.unwrap();
    assert_eq!(
        nodes[1].relay(&mut frame).await,
        RelayOutcome::Dropped {
            reason: DropReason::Duplicate
        }
    );
}

#[tokio::test]
async fn broadcast_self_origin_dropped() {
    let mut nodes = broadcast_setup(&[1, 2]).await;
    let mut frame = nodes[0].build_broadcast_frame(b"loop").unwrap();
    assert_eq!(
        nodes[0].relay(&mut frame).await,
        RelayOutcome::Dropped {
            reason: DropReason::Duplicate
        }
    );
}

#[tokio::test]
async fn broadcast_ttl_zero_dropped() {
    let mut nodes = broadcast_setup(&[1, 2]).await;
    let mut frame = nodes[0].build_broadcast_frame(b"x").unwrap();
    frame[3] = 0;
    let mut b = MeshData::bind("127.0.0.1:0".parse().unwrap(), 3)
        .await
        .unwrap();
    b.set_broadcast_key(broadcast_key());
    assert_eq!(
        b.relay(&mut frame).await,
        RelayOutcome::Dropped {
            reason: DropReason::TtlExpired
        }
    );
}

#[tokio::test]
async fn broadcast_wrong_type_dropped() {
    let _nodes = broadcast_setup(&[1, 2]).await;
    // 单播载荷伪装 to=广播保留值：type≠广播 → 广播路径拒绝
    let mut b = MeshData::bind("127.0.0.1:0".parse().unwrap(), 2)
        .await
        .unwrap();
    b.set_broadcast_key(broadcast_key());
    let header = MeshFrameHeader {
        packet_type: packet_type::UNICAST,
        to_node_id: BROADCAST_NODE_ID,
        from_node_id: 1,
        ..Default::default()
    };
    let mut frame = build_frame(&header, &[0x24; 32], &[0x24; 32], 0, b"x").unwrap();
    assert_eq!(
        b.relay(&mut frame).await,
        RelayOutcome::Dropped {
            reason: DropReason::UnsupportedType
        }
    );
}

#[tokio::test]
async fn broadcast_tampered_route_mac_dropped() {
    let mut nodes = broadcast_setup(&[1, 2]).await;
    let mut frame = nodes[0].build_broadcast_frame(b"x").unwrap();
    frame[8] ^= 0x01;
    assert_eq!(
        nodes[1].relay(&mut frame).await,
        RelayOutcome::Dropped {
            reason: DropReason::BadRouteMac
        }
    );
}

#[tokio::test]
async fn broadcast_no_key_dropped() {
    let mut nodes = broadcast_setup(&[1, 2]).await;
    let mut frame = nodes[0].build_broadcast_frame(b"x").unwrap();
    let mut no_key = MeshData::bind("127.0.0.1:0".parse().unwrap(), 3)
        .await
        .unwrap();
    assert_eq!(
        no_key.relay(&mut frame).await,
        RelayOutcome::Dropped {
            reason: DropReason::NoKeyDst
        }
    );
}

#[tokio::test]
async fn flood_sends_to_all_peers() {
    let mut nodes = broadcast_setup(&[1, 2, 3]).await;
    let sent = nodes[0].flood(b"multicast frame").await;
    assert_eq!(sent, 2);
    assert!(matches!(
        nodes[1].handle_incoming().await.unwrap(),
        IncomingEvent::Broadcast { from: 1, payload: ref p } if p.as_ref() == b"multicast frame"
    ));
    assert!(matches!(
        nodes[2].handle_incoming().await.unwrap(),
        IncomingEvent::Broadcast { from: 1, .. }
    ));
}

/// REQ-035/FRM-08：泛洪只达 opt-in 端点——未 opt-in 与无能力记录（fail-closed）
/// 的端点不发送
#[tokio::test]
async fn flood_targets_only_opt_in_peers() {
    let mut nodes = broadcast_setup(&[1, 2, 3, 4]).await;
    // node 3 未 opt-in（仅 relay 位）；node 4 抹掉能力记录（fail-closed 路径）
    nodes[0].set_peer_capabilities(3, 0x01);
    nodes[0].remove_peer_capabilities(4);
    assert_eq!(nodes[0].flood_targets(1), vec![2]);
    assert_eq!(nodes[0].flood(b"opt-in only").await, 1);
    assert!(matches!(
        nodes[1].handle_incoming().await.unwrap(),
        IncomingEvent::Broadcast { from: 1, .. }
    ));
}

/// REQ-035/FRM-08：转发侧同样过滤——relay 泛洪不发给未 opt-in / 无记录端点
#[tokio::test]
async fn relay_flood_targets_only_opt_in_peers() {
    let mut nodes = broadcast_setup(&[1, 2, 3, 4, 5]).await;
    nodes[1].set_peer_capabilities(3, 0x01);
    nodes[1].remove_peer_capabilities(4);
    let mut frame = nodes[0].build_broadcast_frame(b"via relay").unwrap();
    nodes[0].send_to_node(2, &frame).await.unwrap();
    match nodes[1].relay(&mut frame).await {
        RelayOutcome::Flooded { forwarded, .. } => assert_eq!(forwarded, vec![5]),
        other => panic!("expected flood, got {:?}", other),
    }
    assert!(matches!(
        nodes[4].handle_incoming().await.unwrap(),
        IncomingEvent::Broadcast { from: 1, .. }
    ));
}

#[tokio::test]
async fn flood_skips_self_endpoint() {
    let mut nodes = broadcast_setup(&[1, 2]).await;
    let (a_addr, b_addr) = (
        nodes[0].local_addr().unwrap(),
        nodes[1].local_addr().unwrap(),
    );
    nodes[1].set_endpoint(1, a_addr);
    nodes[1].set_endpoint(2, b_addr);
    let sent = nodes[1].flood(b"self test").await;
    assert_eq!(sent, 1);
    assert_eq!(nodes[1].endpoint_table.len(), 2);
}

#[test]
fn token_bucket_refills_and_exhausts() {
    let mut bucket = TokenBucket::new(10.0, 2);
    assert!(bucket.take());
    assert!(bucket.take());
    assert!(!bucket.take());
    std::thread::sleep(Duration::from_millis(300));
    assert!(bucket.take());
}

#[tokio::test]
async fn flood_rate_limited_when_exhausted() {
    let mut nodes = broadcast_setup(&[1, 2]).await;
    nodes[0].flood_bucket = TokenBucket::new(0.0, 0);
    assert_eq!(nodes[0].flood(b"x").await, 0);
}

#[tokio::test]
async fn drop_stats_attribution_and_summary_filter() {
    // LOG-02：丢帧计数归因（仅已知 peer 记 per-peer，未知/伪造 node_id 落全局桶）
    // + 摘要输出过滤（0 不输出、无计数时 poll 返回 None）
    let mut m = MeshData::bind("127.0.0.1:0".parse().unwrap(), 7)
        .await
        .unwrap();
    // peer 1 注入 key_dst（已知 peer）；999 不在表内（伪造 node_id）
    m.set_key_dst(1, node_key(1));
    m.note_drop(Some(1));
    m.note_drop(Some(1));
    m.note_drop(Some(999));
    m.note_drop(None);
    // RateCounter 周期末出报告：等待一个周期后再 poll
    std::thread::sleep(DROP_STATS_PERIOD + Duration::from_millis(10));

    let (per_peer, global) = m.poll_drop_stats().expect("本周期有计数");
    assert_eq!(per_peer, vec![(1u32, 2u64)]);
    assert_eq!(global, 2);
    // 下一周期无丢帧 → poll 返回 Some(0) 被过滤 → None（0 不输出）
    assert!(m.poll_drop_stats().is_none());
    // 过期清零后旧 per-peer 桶从表内剔除（has_pending 为 false → retain 清理）
    assert!(m.drop_stats.is_empty());
}

#[tokio::test]
async fn oversize_datagram_dropped_then_normal_ok() {
    let (mut a, mut b) = setup_pair().await;
    let b_addr = b.local_addr().unwrap();
    let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    // 超长（≥ MAX_FRAME）→ 内核截断 → 显式丢弃（REQ-053），不影响后续帧
    sender.send_to(&[0x01u8; 4096], b_addr).await.unwrap();
    assert!(b.recv_frame().await.is_err());
    // 正常帧照常处理
    let msg1 = a.initiate_handshake(2).unwrap().unwrap();
    a.send_to_node(2, &msg1).await.unwrap();
    assert_eq!(
        b.handle_incoming().await.unwrap(),
        IncomingEvent::Responded { peer: 1 }
    );
}

// ==================== underlay 传输（REQ-054） ====================

/// TCP 兜底档全路径：握手 + 数据往返 + 帧/probe 共存一条流
/// （REQ-054 验收：帧字节跨传输一致，行为与 UDP 档对齐）
#[tokio::test]
async fn tcp_underlay_handshake_data_and_probe() {
    let (mut a, mut b) = setup_pair_tcp().await;
    // 惰性 connect：首帧触发建连，握手照常
    let msg1 = a.initiate_handshake(2).unwrap().unwrap();
    a.send_to_node(2, &msg1).await.unwrap();
    assert_eq!(
        b.handle_incoming().await.unwrap(),
        IncomingEvent::Responded { peer: 1 }
    );
    assert_eq!(
        a.handle_incoming().await.unwrap(),
        IncomingEvent::Established { peer: 2 }
    );
    assert_eq!(
        b.handle_incoming().await.unwrap(),
        IncomingEvent::Established { peer: 1 }
    );
    // 数据往返
    let (frame, hop) = a.build_data_frame(2, b"via-tcp", 0x42).unwrap();
    assert!(hop.is_none()); // 直连（无路径表）
    a.send_to_node_hop(2, hop, &frame).await.unwrap();
    match b.handle_incoming().await.unwrap() {
        IncomingEvent::Data { from, payload } => {
            assert_eq!(from, 1);
            assert_eq!(payload.as_ref(), b"via-tcp");
        }
        other => panic!("expected data, got {:?}", other),
    }
    // probe 与帧共存（REQ-054 决策 3：首字节分类，同流互不干扰）
    let nonce = a
        .send_probe_ping(b.local_addr().unwrap(), 1, 2)
        .await
        .unwrap();
    assert_eq!(
        b.handle_incoming().await.unwrap(),
        IncomingEvent::ProbePing { from: 1 }
    );
    match a.handle_incoming().await.unwrap() {
        IncomingEvent::ProbePong {
            from,
            endpoint,
            payload,
        } => {
            assert_eq!(from, 2);
            assert!(payload.is_empty());
            // PONG 源 = TCP 连接对端地址（回包走缓存的同一条连接）
            assert_eq!(endpoint.ip().to_string(), "127.0.0.1");
        }
        other => panic!("expected ProbePong, got {:?}", other),
    }
    let _ = nonce;
}

/// relay 侧端点择优（默认路径分支，REQ-054 决策 6）：
/// 首选端点 miss 高 → 置后，转发命中健康端点
#[tokio::test]
async fn relay_default_path_forward_prefers_healthy_endpoint() {
    let mut relay = MeshData::bind("127.0.0.1:0".parse().unwrap(), 2)
        .await
        .unwrap();
    let bad = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let good = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    relay.set_key_dst(3, node_key(3));
    relay.set_endpoints(
        3,
        vec![bad.local_addr().unwrap(), good.local_addr().unwrap()],
    );
    // 首选端点活性差 → order_endpoints 置后
    relay
        .endpoint_health
        .insert((3, bad.local_addr().unwrap()), 5);

    let mut frame = frame_from(1, 3, b"payload", 64, 1);
    assert_eq!(
        relay.relay(&mut frame).await,
        RelayOutcome::Forwarded { to: 3 }
    );
    // good 收到（TTL 已原地递减），bad 无包
    let mut buf = [0u8; 2048];
    let (n, from) = good.recv_from(&mut buf).await.unwrap();
    assert_eq!(from, relay.local_addr().unwrap());
    assert_eq!(&buf[..n], &frame[..]);
    assert!(tokio::time::timeout(
        std::time::Duration::from_millis(200),
        bad.recv_from(&mut buf)
    )
    .await
    .is_err());
}

/// relay 侧端点择优（路径 path_next_hop 分支，REQ-054 决策 6）：
/// 路径后继的多端点按活性排序转发
#[tokio::test]
async fn relay_path_forward_prefers_healthy_endpoint() {
    let mut relay = MeshData::bind("127.0.0.1:0".parse().unwrap(), 3)
        .await
        .unwrap();
    let bad = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let good = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    relay.set_key_path(0x300, path_key(0x300));
    relay.set_endpoints(
        2,
        vec![bad.local_addr().unwrap(), good.local_addr().unwrap()],
    );
    relay
        .endpoint_health
        .insert((2, bad.local_addr().unwrap()), 5);
    relay.set_paths(
        2,
        vec![PathEntry {
            path_id: 0x300,
            path_epoch: 1,
            hops: vec![3, 2],
            expires_at: unix_seconds() + 3600,
        }],
    );

    let header = MeshFrameHeader {
        to_node_id: 2,
        from_node_id: 1,
        path_id: 0x300,
        seq: 1,
        ttl: 64,
        ..Default::default()
    };
    let mut frame = build_frame(
        &header,
        &path_key(0x300),
        &[0x24; 32],
        0x1234_5678,
        b"payload",
    )
    .unwrap();
    assert_eq!(
        relay.relay(&mut frame).await,
        RelayOutcome::Forwarded { to: 2 }
    );
    let mut buf = [0u8; 2048];
    let (n, _) = good.recv_from(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], &frame[..]);
    assert!(tokio::time::timeout(
        std::time::Duration::from_millis(200),
        bad.recv_from(&mut buf)
    )
    .await
    .is_err());
}

/// 流式断线信号回喂（REQ-054 决策 7）：TCP connect 失败 →
/// send 报错 + 端点 miss 递增（后续发送置后该端点）
#[tokio::test]
async fn tcp_send_failure_feeds_endpoint_miss() {
    let dead = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = dead.local_addr().unwrap();
    drop(dead);
    let mut a = MeshData::bind_underlay(
        Underlay::Tcp(
            TcpTransport::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap(),
        ),
        1,
    )
    .await
    .unwrap();
    a.set_endpoints(2, vec![dead_addr]);
    assert!(a.send_to_node_hop(2, None, b"\x01junk").await.is_err());
    assert_eq!(a.endpoint_health.get(&(2, dead_addr)), Some(&1));
}

/// 直连活性推断（REQ-054 决策 5 入站证据复用）：
/// 帧经中继到达 → 发送方直连端点 miss，回包排序让位中继兜底端点；
/// 直连帧到达 → miss 清零自愈
#[tokio::test]
async fn relayed_ingress_demotes_direct_endpoints() {
    let mut a = MeshData::bind("127.0.0.1:0".parse().unwrap(), 1)
        .await
        .unwrap();
    let b = UdpSocket::bind("127.0.0.1:0").await.unwrap(); // 中继节点 3 的端点
    let c_direct = UdpSocket::bind("127.0.0.1:0").await.unwrap(); // c(2) 的直连端点
    let b_ep = b.local_addr().unwrap();
    let c_ep = c_direct.local_addr().unwrap();
    a.set_key_dst(1, node_key(1)); // 自身路由密钥（Delivered 校验用）
    a.set_endpoints(3, vec![b_ep]); // b 的端点
                                    // c 的端点表 = 直连 ++ 中继兜底（apply_relay_endpoints 效果，直连在前）
    a.set_endpoints(2, vec![c_ep, b_ep]);

    // 帧从 c(2) 发给 a(1)，经 b 的端点到达（ingress=3 ≠ from=2 → 降级直连）
    let frame = frame_from(2, 1, b"x", 64, 1);
    b.send_to(&frame, a.local_addr().unwrap()).await.unwrap();
    let _ = a.handle_incoming().await.unwrap(); // Delivered → 降级（分派结果无关紧要）
    assert_eq!(a.endpoint_health.get(&(2, c_ep)), Some(&1));
    assert_eq!(a.endpoint_health.get(&(2, b_ep)), None); // 中继端点不受累

    // 发送排序：回包让位中继兜底端点（b 收到，c 直连端点无包）
    a.send_to_node_hop(2, None, b"\x01reply").await.unwrap();
    let mut buf = [0u8; 64];
    let (n, _) = b.recv_from(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"\x01reply");
    assert!(tokio::time::timeout(
        std::time::Duration::from_millis(200),
        c_direct.recv_from(&mut buf)
    )
    .await
    .is_err());

    // 直连帧到达 → 自愈（miss 清零，排序回归直连优先）
    let frame2 = frame_from(2, 1, b"y", 64, 2);
    c_direct
        .send_to(&frame2, a.local_addr().unwrap())
        .await
        .unwrap();
    let _ = a.handle_incoming().await.unwrap();
    assert_eq!(a.endpoint_health.get(&(2, c_ep)), Some(&0));
}

/// 中继转发表（非自源路径）：中继无发送路径表，仅持 forward_paths
/// （自己是 hops 参与者的其他源路径）+ key_path → 按 path_id 转发成功。
/// 此前转发只查发送表 → 中继永远 NoEndpoint（e2e probe CON-04 断链根因）
#[tokio::test]
async fn relay_forwards_via_forward_table() {
    let mut relay = MeshData::bind("127.0.0.1:0".parse().unwrap(), 3)
        .await
        .unwrap();
    let dest = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dest_ep = dest.local_addr().unwrap();
    relay.set_key_path(0x300, path_key(0x300));
    relay.set_endpoints(2, vec![dest_ep]);
    // 注意：无 set_paths（源是节点 4，不是自己）——只有转发表
    relay.set_forward_path(PathEntry {
        path_id: 0x300,
        path_epoch: 1,
        hops: vec![4, 3, 2],
        expires_at: unix_seconds() + 3600,
    });

    let header = MeshFrameHeader {
        to_node_id: 2,
        from_node_id: 4,
        path_id: 0x300,
        seq: 1,
        ttl: 64,
        ..Default::default()
    };
    let mut frame = build_frame(&header, &path_key(0x300), &[0x24; 32], 0x1234_5678, b"p").unwrap();
    assert_eq!(
        relay.relay(&mut frame).await,
        RelayOutcome::Forwarded { to: 2 }
    );
    let mut buf = [0u8; 2048];
    let (n, _) = dest.recv_from(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], &frame[..]);
}

#[tokio::test]
async fn relay_owner_map_disambiguates_fallback_endpoints() {
    // probe e2e 复现：中继兜底端点并入多个 peer 候选列表（apply_relay_endpoints）
    // 后，按地址扫描归属会把经 d 中继到达的帧归给死中继 b（端点出现在 b 的
    // 列表里）→ apply_ingress_health 永远 ok 经 b 的路径 → 回包持续选中死路径。
    // 修复：netmap relay 列表的 node_id 构成精确归属表，反查优先命中。
    let mut a = MeshData::bind("127.0.0.1:0".parse().unwrap(), 1)
        .await
        .unwrap();
    let mut d = MeshData::bind("127.0.0.1:0".parse().unwrap(), 2)
        .await
        .unwrap();
    let d_ep = d.local_addr().unwrap();
    d.set_endpoint(1, a.local_addr().unwrap());
    // 污染形态：死中继 b(4) 的候选列表混入 d 的兜底端点；d(2) 自己的表也含它
    a.set_endpoints(4, vec![d_ep]);
    a.set_endpoints(2, vec![d_ep]);
    a.set_relay_owners(HashMap::from([(d_ep, 2)]));
    a.set_key_dst(1, node_key(1));
    let direct = PathEntry {
        path_id: 10,
        path_epoch: 1,
        hops: vec![3],
        expires_at: unix_seconds() + 3600,
    };
    let via_dead = PathEntry {
        path_id: 11,
        path_epoch: 1,
        hops: vec![4, 3],
        expires_at: unix_seconds() + 3600,
    };
    let via_d = PathEntry {
        path_id: 12,
        path_epoch: 1,
        hops: vec![2, 3],
        expires_at: unix_seconds() + 3600,
    };
    a.set_key_path(10, path_key(10));
    a.set_key_path(11, path_key(11));
    a.set_key_path(12, path_key(12));
    a.set_paths(3, vec![direct, via_dead, via_d]);
    // 归属反查：经 d 到达的帧必须归到 d（2），不能因污染列表归给 b（4）
    assert_eq!(a.endpoint_owner_preferring(d_ep, 3), Some(2));
    assert_eq!(a.endpoint_owner(d_ep), Some(2));
    // c(3) 的帧连续经 d 到达 → 直连/经 b 路径 miss 达阈值剔除，仅剩经 d 路径
    let header = MeshFrameHeader {
        to_node_id: 1,
        from_node_id: 3,
        ..Default::default()
    };
    let frame = build_handshake_frame(&header, &node_key(1), &[0u8; MSG1_PAYLOAD_LEN]);
    for _ in 0..PATH_HEALTH_MISS_LIMIT {
        d.send_to_node(1, &frame).await.unwrap();
        let _ = a.handle_incoming().await.unwrap();
    }
    assert_eq!(a.pick_path(3, 0).unwrap().path_id, 12);
    // 经 d 路径保持健康（到达即 ok），不经 miss 重置
    assert_eq!(a.pick_path(3, u64::MAX).unwrap().path_id, 12);
}

/// 1↔3 手工建会话（wire_pair 是 1↔2 专用；本测试需要 dest=3）
async fn wire_pair_1_3(a: &mut MeshData, c: &mut MeshData) {
    let a_addr = a.local_addr().unwrap();
    let c_addr = c.local_addr().unwrap();
    for id in [1u32, 3] {
        a.set_key_dst(id, node_key(id));
        c.set_key_dst(id, node_key(id));
    }
    a.set_handshake_context(ctx(1));
    c.set_handshake_context(ctx(3));
    a.set_peer_static(3, peer_static(3));
    c.set_peer_static(1, peer_static(1));
    a.set_binding_verifier(verifier);
    c.set_binding_verifier(verifier);
    a.set_endpoint(3, c_addr);
    c.set_endpoint(1, a_addr);
}

#[tokio::test]
async fn path_send_targets_first_hop_owned_endpoints_only() {
    // 相位锁定修复（probe CI）：首跳候选列表混入其他中继的兜底端点时，
    // 路径帧必须跳过（非参与者无法转发 → 必丢）；默认路径帧保留兜底语义。
    // 修复前 last-used 轮换让回包相位锁定在兜底死端点（心跳存活、路径帧全灭）
    let mut a = MeshData::bind("127.0.0.1:0".parse().unwrap(), 1)
        .await
        .unwrap();
    let mut c = MeshData::bind("127.0.0.1:0".parse().unwrap(), 3)
        .await
        .unwrap();
    wire_pair_1_3(&mut a, &mut c).await;
    let msg1 = a.initiate_handshake(3).unwrap().unwrap();
    a.send_to_node(3, &msg1).await.unwrap();
    let _ = c.handle_incoming().await.unwrap();
    let _ = a.handle_incoming().await.unwrap();
    let _ = c.handle_incoming().await.unwrap();
    assert!(a.has_session(3));
    // 首跳 4 的候选列表：d(2) 的兜底端点排前 + b(4) 自有端点；b/d 用裸 socket
    let b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let d = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let b_ep = b.local_addr().unwrap();
    let d_ep = d.local_addr().unwrap();
    a.set_endpoints(4, vec![d_ep, b_ep]);
    a.set_relay_owners(HashMap::from([(d_ep, 2u32), (b_ep, 4u32)]));
    a.set_key_path(0x21, path_key(0x21));
    a.set_paths(
        3,
        vec![PathEntry {
            path_id: 0x21,
            path_epoch: 1,
            hops: vec![4, 3],
            expires_at: unix_seconds() + 3600,
        }],
    );
    // 路径数据帧：必发往 b(4) 自有端点，兜底端点 d 不收
    let (frame, first_hop) = a.build_data_frame(3, b"ping", 7).unwrap();
    assert_eq!(first_hop, Some(4));
    assert!(a.send_to_node_hop(3, first_hop, &frame).await.unwrap());
    let mut buf = [0u8; 2048];
    let (n, _) = tokio::time::timeout(Duration::from_secs(1), b.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf[..n], &frame[..]);
    assert!(d.try_recv(&mut buf).is_err());
    // 默认路径对照：同一首跳的心跳帧仍可用兜底端点（last-used 轮换到 d）
    let hb = a.build_heartbeat_frame(3).unwrap();
    assert!(a.send_to_node_hop(3, Some(4), &hb).await.unwrap());
    let _ = tokio::time::timeout(Duration::from_secs(1), d.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert!(b.try_recv(&mut buf).is_err());
}

#[tokio::test]
async fn relay_forward_skips_fallback_endpoints() {
    // 中继转发侧同理：下一跳候选混入其他中继兜底端点时，路径帧只发自有端点
    let mut relay = MeshData::bind("127.0.0.1:0".parse().unwrap(), 4)
        .await
        .unwrap();
    let dest = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let other = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dest_ep = dest.local_addr().unwrap();
    let other_ep = other.local_addr().unwrap();
    relay.set_key_path(0x31, path_key(0x31));
    // 污染形态：下一跳 3 的候选里混入其他中继(2)的兜底端点且排前
    relay.set_endpoints(3, vec![other_ep, dest_ep]);
    relay.set_relay_owners(HashMap::from([(other_ep, 2u32)]));
    relay.set_forward_path(PathEntry {
        path_id: 0x31,
        path_epoch: 1,
        hops: vec![1, 4, 3],
        expires_at: unix_seconds() + 3600,
    });
    let header = MeshFrameHeader {
        to_node_id: 3,
        from_node_id: 1,
        path_id: 0x31,
        seq: 1,
        ttl: 64,
        ..Default::default()
    };
    let mut frame = build_frame(&header, &path_key(0x31), &[0x24; 32], 0x1234_5678, b"p").unwrap();
    assert_eq!(
        relay.relay(&mut frame).await,
        RelayOutcome::Forwarded { to: 3 }
    );
    let mut buf = [0u8; 2048];
    let (n, _) = tokio::time::timeout(Duration::from_secs(1), dest.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf[..n], &frame[..]);
    assert!(other.try_recv(&mut buf).is_err());
}

// ==================== 节点遥测（REQ-052/CONTROL_PLANE §3.15） ====================

#[tokio::test]
async fn telemetry_interval_counts_and_reset() {
    // 区间计数语义（LOG-02）：tx 归业务终点、rx 归发送方；上报即清零，
    // 下区间不含旧值；peers 按 node_id 排序输出确定
    let (mut a, mut b) = setup_pair().await;
    let msg1 = a.initiate_handshake(2).unwrap().unwrap();
    a.send_to_node(2, &msg1).await.unwrap();
    assert_eq!(
        b.handle_incoming().await.unwrap(),
        IncomingEvent::Responded { peer: 1 }
    );

    let tele = a.take_telemetry();
    assert_eq!(tele.peers.len(), 1);
    assert_eq!(tele.peers[0].node_id, 2);
    assert_eq!(tele.peers[0].tx_frames, 1);
    assert_eq!(tele.peers[0].tx_bytes, msg1.len() as u64);
    assert_eq!(tele.peers[0].rx_frames, 0);

    let tele_b = b.take_telemetry();
    assert_eq!(tele_b.peers.len(), 1);
    assert_eq!(tele_b.peers[0].node_id, 1);
    assert_eq!(tele_b.peers[0].rx_frames, 1);
    assert_eq!(tele_b.peers[0].rx_bytes, msg1.len() as u64);

    // 上报即清零：下区间不含旧值
    assert!(a.take_telemetry().peers.is_empty());
    assert!(b.take_telemetry().peers.is_empty());
}

#[tokio::test]
async fn telemetry_drop_attribution_and_global_bucket() {
    // 丢帧归因计数（§3.15 内容 2）：已知 peer → per-peer；伪造/未知 → 全局桶
    let mut m = MeshData::bind("127.0.0.1:0".parse().unwrap(), 7)
        .await
        .unwrap();
    m.set_key_dst(1, node_key(1));
    m.note_drop(Some(1));
    m.note_drop(Some(1));
    m.note_drop(Some(999));
    m.note_drop(None);

    let tele = m.take_telemetry();
    assert_eq!(tele.drop_global, 2);
    assert_eq!(
        tele.drops,
        vec![landscape_rill_proto::wire::control::TelemetryDrop {
            node_id: 1,
            count: 2
        }]
    );
    // 取走即清零
    assert_eq!(m.take_telemetry().drop_global, 0);
}

#[tokio::test]
async fn telemetry_direct_pair_rtt_recorded_on_pong() {
    // 直连确认对（§3.15 内容 3）：probe 发送时间簿记，PONG 匹配 → RTT 记录
    let (mut a, b) = setup_pair().await;
    let b_addr = b.local_addr().unwrap();
    let nonce = a.send_probe_ping(b_addr, 1, 2).await.expect("pending 未满");
    let ping = crate::probe::ProbePacket::ping(1, 2, nonce);
    let pong = crate::probe::ProbePacket::pong(&ping, Vec::new());
    let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sender
        .send_to(&pong.encode(), a.local_addr().unwrap())
        .await
        .unwrap();
    assert!(matches!(
        a.handle_incoming().await.unwrap(),
        IncomingEvent::ProbePong { from: 2, .. }
    ));
    let tele = a.take_telemetry();
    assert_eq!(tele.direct.len(), 1);
    assert_eq!(tele.direct[0].node_id, 2);
    assert_eq!(tele.direct[0].endpoint, b_addr.to_string());
    // RTT 非负即可（同进程回环 < 1ms 也合法）
    let _ = tele.direct[0].rtt_ms;
    // 取走即清零
    assert!(a.take_telemetry().direct.is_empty());
}
