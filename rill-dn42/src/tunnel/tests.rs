//! 隧道封装测试：双 WgTunnel 在进程内完成完整 WG 握手并双向传数据
//! （验证密钥配置与 encapsulate/decapsulate 使用模式，无 socket 依赖）。

use std::collections::VecDeque;
use std::net::IpAddr;

use super::*;
use boringtun::x25519::{PublicKey, StaticSecret};

fn clamped_key(seed: u8) -> [u8; 32] {
    let mut k = [seed; 32];
    // WG 私钥需 clamp（e[0] & 248, e[31] & 127 | 64）
    k[0] &= 248;
    k[31] = k[31] & 127 | 64;
    k
}

fn pair(a_priv: [u8; 32], b_priv: [u8; 32]) -> (WgTunnel, WgTunnel) {
    let a_pub = PublicKey::from(&StaticSecret::from(a_priv)).to_bytes();
    let b_pub = PublicKey::from(&StaticSecret::from(b_priv)).to_bytes();
    (
        WgTunnel::new(WgPeerKeys {
            own_private: a_priv,
            peer_public: b_pub,
            preshared: None,
            index: 1,
        }),
        WgTunnel::new(WgPeerKeys {
            own_private: b_priv,
            peer_public: a_pub,
            preshared: None,
            index: 2,
        }),
    )
}

fn payload_v4(seq: u8) -> Vec<u8> {
    // 最小 IPv4 包（version/ihl + 总长，内容不重要——boringtun 透传明文）
    let mut p = vec![
        0x45, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0, 10, 42, 0, 1, 10, 43, 0, 1,
    ];
    p.extend_from_slice(&[0xde, 0xad, seq, 0xef]);
    let total = p.len() as u16;
    p[2..4].copy_from_slice(&total.to_be_bytes());
    p
}

/// 模拟 UDP 管道：把 sender 待发队列依次喂给 receiver，直到双队列为空
fn feed(
    sender_out: &mut VecDeque<Vec<u8>>,
    receiver: &mut WgTunnel,
    receiver_out: &mut VecDeque<Vec<u8>>,
    receiver_got: &mut Vec<Vec<u8>>,
) {
    while let Some(d) = sender_out.pop_front() {
        let o = receiver.decapsulate(None::<IpAddr>, &d);
        receiver_out.extend(o.to_send);
        if let Some(p) = o.plaintext {
            receiver_got.push(p);
        }
    }
}

fn quiesce(
    a: &mut WgTunnel,
    b: &mut WgTunnel,
    mut a_w: VecDeque<Vec<u8>>,
    mut b_w: VecDeque<Vec<u8>>,
) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let (mut a_got, mut b_got) = (vec![], vec![]);
    for _ in 0..10 {
        feed(&mut a_w, b, &mut b_w, &mut b_got);
        feed(&mut b_w, a, &mut a_w, &mut a_got);
        if a_w.is_empty() && b_w.is_empty() {
            break;
        }
    }
    (a_got, b_got)
}

#[test]
fn full_handshake_and_bidirectional_data() {
    let (mut a, mut b) = pair(clamped_key(1), clamped_key(2));

    // a 侧首个包：无会话 → boringtun 内部排队 + 触发握手发起
    let packet = payload_v4(0);
    let wire = a.encapsulate(&packet);
    assert_eq!(wire.len(), 1, "首包应产出握手发起（包本身入内部队列）");

    let (a_got, b_got) = quiesce(&mut a, &mut b, wire.into(), VecDeque::new());
    assert!(a_got.is_empty());
    assert_eq!(
        b_got,
        vec![packet.clone()],
        "握手完成后排队的首包应恰好送达一次"
    );

    // 会话已建立：a 直接封装
    let wire = a.encapsulate(&payload_v4(1));
    assert_eq!(wire.len(), 1, "会话建立后 encapsulate 直出数据包");
    let (_, b_got) = quiesce(&mut a, &mut b, wire.into(), VecDeque::new());
    assert_eq!(b_got, vec![payload_v4(1)]);

    // 反向：b → a
    let wire = b.encapsulate(&payload_v4(2));
    assert_eq!(wire.len(), 1);
    let (a_got, _) = quiesce(&mut a, &mut b, VecDeque::new(), wire.into());
    assert_eq!(a_got, vec![payload_v4(2)]);
}

#[test]
fn handshake_via_ensure_initiated_and_timers_silent_when_idle() {
    let (mut a, mut b) = pair(clamped_key(1), clamped_key(2));

    // 空闲新隧道：update_timers 不主动发起（boringtun 语义），ensure_initiated 触发
    assert!(a.update_timers().is_empty());
    assert!(!a.session_established());
    let init = a.ensure_initiated();
    assert_eq!(init.len(), 1, "ensure_initiated 应产出握手发起");

    let (a_got, b_got) = quiesce(&mut a, &mut b, init.into(), VecDeque::new());
    assert!(b_got.is_empty() && a_got.is_empty(), "纯握手无数据包");
    assert!(a.session_established() && b.session_established());

    // 握手完成后定时器静默（不 panic、不无限产出）
    for _ in 0..3 {
        assert!(a.update_timers().is_empty());
        assert!(b.update_timers().is_empty());
    }
}

#[test]
fn pre_session_queue_flushes_in_order_after_handshake() {
    let (mut a, mut b) = pair(clamped_key(1), clamped_key(2));
    // 会话建立前灌 10 个包（boringtun 内部队列深度 256，全部保留）
    let mut wires: VecDeque<Vec<u8>> = VecDeque::new();
    for i in 0..10u8 {
        wires.extend(a.encapsulate(&payload_v4(i)));
    }
    assert!(!wires.is_empty(), "首包触发握手发起");
    let (_, b_got) = quiesce(&mut a, &mut b, wires, VecDeque::new());
    let seqs: Vec<u8> = b_got.iter().map(|p| p[22]).collect();
    assert_eq!(seqs, (0..10u8).collect::<Vec<u8>>(), "队列按序全部送达");
}

#[test]
fn wrong_key_peer_fails_closed() {
    let a_priv = clamped_key(1);
    let b_priv = clamped_key(2);
    let stranger_priv = clamped_key(3);
    let b_pub = PublicKey::from(&StaticSecret::from(b_priv)).to_bytes();
    let a_pub = PublicKey::from(&StaticSecret::from(a_priv)).to_bytes();

    // stranger 冒充 b 与 a 配对，但 a 只认 b 的公钥
    let mut a = WgTunnel::new(WgPeerKeys {
        own_private: a_priv,
        peer_public: b_pub,
        preshared: None,
        index: 1,
    });
    let mut stranger = WgTunnel::new(WgPeerKeys {
        own_private: stranger_priv,
        peer_public: a_pub,
        preshared: None,
        index: 3,
    });

    let init = stranger.ensure_initiated();
    assert_eq!(init.len(), 1);
    // a 校验 init 失败（MAC 用冒充者静态公钥计算）→ 不回包、不建会话
    let mut stranger_w: VecDeque<Vec<u8>> = init.into();
    let mut a_w: VecDeque<Vec<u8>> = VecDeque::new();
    let mut a_got = vec![];
    feed(&mut stranger_w, &mut a, &mut a_w, &mut a_got);
    feed(&mut a_w, &mut stranger, &mut stranger_w, &mut Vec::new());
    assert!(a_got.is_empty(), "冒充者永远拿不到明文会话");
    assert!(!a.session_established());
    // stranger 封装的数据包 a 一律解不开
    let wire = stranger.encapsulate(&payload_v4(9));
    for d in wire {
        let o = a.decapsulate(None::<IpAddr>, &d);
        assert!(o.plaintext.is_none());
    }
}
