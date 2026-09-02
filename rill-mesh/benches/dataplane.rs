//! L2 环回数据面基准（docs/perf.md §1）：真实 UDP socket 全链路。
//! ping-pong（握手后双向每往返）/ relay 转发每包 / 广播送达每包。
//! A/B 约束：仅用 REQ-053 前后签名未变的公开 API（不用 recv_frame）；
//! setup 助手与 data/tests.rs 同构（cfg(test) 模块对 bench 不可见）。

use criterion::{criterion_group, criterion_main, Criterion};
use landscape_rill_core::crypto::derive_key_dst;
use landscape_rill_core::frame::{build_frame, MeshFrameHeader};
use landscape_rill_core::handshake::{HandshakeContext, BINDING_LEN, SESSION_KEY_LEN};
use landscape_rill_mesh::data::{IncomingEvent, MeshData};
use tokio::net::UdpSocket;
use tokio::runtime::Runtime;

const MASTER: [u8; 32] = [0x42; 32];
const NETWORK_ID: u32 = 0x0000_0001;
const BKEY: [u8; 32] = [0x77; 32];

fn node_key(node_id: u32) -> [u8; 32] {
    derive_key_dst(&MASTER, node_id)
}

fn ctx(id: u8) -> HandshakeContext {
    HandshakeContext {
        network_id: NETWORK_ID,
        version: landscape_rill_core::frame::VERSION,
        local_static: [id; SESSION_KEY_LEN],
        identity_binding: [0x5a; BINDING_LEN].to_vec(),
    }
}

fn peer_static(id: u8) -> [u8; 32] {
    use x25519_dalek::{PublicKey, StaticSecret};
    PublicKey::from(&StaticSecret::from([id; 32])).to_bytes()
}

fn verifier(node_id: u32, static_pubkey: &[u8; 32], _binding: &[u8]) -> bool {
    static_pubkey == &peer_static(node_id as u8)
}

fn rt() -> Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// a(1) ↔ b(2) 真握手至 Established
async fn established_pair() -> (MeshData, MeshData) {
    let mut a = MeshData::bind("127.0.0.1:0".parse().unwrap(), 1)
        .await
        .unwrap();
    let mut b = MeshData::bind("127.0.0.1:0".parse().unwrap(), 2)
        .await
        .unwrap();
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

    let msg1 = a.initiate_handshake(2).unwrap().unwrap();
    a.send_to_node(2, &msg1).await.unwrap();
    match b.handle_incoming().await.unwrap() {
        IncomingEvent::Responded { .. } => {}
        e => panic!("unexpected: {e:?}"),
    }
    match a.handle_incoming().await.unwrap() {
        IncomingEvent::Established { .. } => {}
        e => panic!("unexpected: {e:?}"),
    }
    match b.handle_incoming().await.unwrap() {
        IncomingEvent::Established { .. } => {}
        e => panic!("unexpected: {e:?}"),
    }
    (a, b)
}

fn bench_ping_pong(c: &mut Criterion) {
    let runtime = rt();
    let (mut a, mut b) = runtime.block_on(established_pair());
    let payload = vec![0x5au8; 1400];
    c.bench_function("dataplane/ping_pong_1400B", |bencher| {
        bencher.iter(|| {
            runtime.block_on(async {
                let (frame, hop) = a.build_data_frame(2, &payload, 0).unwrap();
                a.send_to_node_hop(2, hop, &frame).await.unwrap();
                match b.handle_incoming().await.unwrap() {
                    IncomingEvent::Data { .. } => {}
                    e => panic!("unexpected: {e:?}"),
                }
                let (frame, hop) = b.build_data_frame(1, &payload, 0).unwrap();
                b.send_to_node_hop(1, hop, &frame).await.unwrap();
                match a.handle_incoming().await.unwrap() {
                    IncomingEvent::Data { .. } => {}
                    e => panic!("unexpected: {e:?}"),
                }
            })
        })
    });
}

/// relay 节点转发路径：injector → r(handle_incoming → Relayed)。
/// 单播转发无 seq 状态，同一帧可重复注入；b 侧不收（内核静默丢弃），
/// 单独测量 r 的用户态转发成本（REQ-053 ③ 的直接对象）。
fn bench_relay_forward(c: &mut Criterion) {
    let runtime = rt();
    let (mut r, injector, r_addr) = runtime.block_on(async {
        let mut r = MeshData::bind("127.0.0.1:0".parse().unwrap(), 2)
            .await
            .unwrap();
        let b = MeshData::bind("127.0.0.1:0".parse().unwrap(), 3)
            .await
            .unwrap();
        let b_addr = b.local_addr().unwrap();
        r.set_key_dst(3, node_key(3));
        r.set_endpoint(3, b_addr);
        let r_addr = r.local_addr().unwrap();
        let injector = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        (r, injector, r_addr)
    });
    let payload = vec![0x5au8; 1400];
    let header = MeshFrameHeader {
        to_node_id: 3,
        from_node_id: 1,
        ttl: 64,
        ..Default::default()
    };
    let frame = build_frame(&header, &node_key(3), &[0x24; 32], 0x1234_5678, &payload).unwrap();
    c.bench_function("dataplane/relay_forward_1400B", |bencher| {
        bencher.iter(|| {
            runtime.block_on(async {
                injector.send_to(&frame, r_addr).await.unwrap();
                match r.handle_incoming().await.unwrap() {
                    IncomingEvent::Relayed { .. } => {}
                    e => panic!("unexpected: {e:?}"),
                }
            })
        })
    });
}

/// 广播送达：每次迭代新 seq（绕开重放窗口），b 全链
/// （recv + route_mac + 重放/去重 + 泛洪簿记 + 解密）。
/// 令牌桶只影响 b 的再泛洪（端点仅 a=源，跳过），不影响送达。
fn bench_broadcast_deliver(c: &mut Criterion) {
    let runtime = rt();
    let (mut a, mut b) = runtime.block_on(established_pair());
    a.set_broadcast_key(BKEY);
    b.set_broadcast_key(BKEY);
    let payload = vec![0x5au8; 1400];
    c.bench_function("dataplane/broadcast_deliver_1400B", |bencher| {
        bencher.iter(|| {
            runtime.block_on(async {
                let frame = a.build_broadcast_frame(&payload).unwrap();
                a.send_to_node(2, &frame).await.unwrap();
                match b.handle_incoming().await.unwrap() {
                    IncomingEvent::Broadcast { .. } => {}
                    e => panic!("unexpected: {e:?}"),
                }
            })
        })
    });
}

criterion_group!(
    benches,
    bench_ping_pong,
    bench_relay_forward,
    bench_broadcast_deliver
);
criterion_main!(benches);
