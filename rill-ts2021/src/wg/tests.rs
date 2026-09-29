//! wg 数据面单测：boringtun 双隧道互推握手与会话（协议栈自洽），ICMP 构造/解析往返。
//! 互推模式与 rill-dn42 tunnel tests 同构（quiesce 双向投喂直至队列排空）。

use super::{icmp_echo_request, parse_icmp_echo, IcmpEcho, WgTunnel};
use std::collections::VecDeque;
use std::net::Ipv4Addr;

fn keypair(seed: u8) -> [u8; 32] {
    // WG 私钥需 clamp（e[0] & 248, e[31] & 127 | 64）——同 dn42 tunnel tests
    let mut k = [seed; 32];
    k[0] &= 248;
    k[31] = k[31] & 127 | 64;
    k
}

fn pub_of(secret_bytes: &[u8; 32]) -> [u8; 32] {
    let secret = boringtun::x25519::StaticSecret::from(*secret_bytes);
    *boringtun::x25519::PublicKey::from(&secret).as_bytes()
}

/// 最小 IPv4 包（boringtun 透传明文，内容仅需头格式合法）
fn payload_v4(byte: u8) -> Vec<u8> {
    let mut p = vec![
        0x45, 0, 0, 24, 0, 0, 0, 0, 64, 6, 0, 0, 10, 42, 0, 1, 10, 43, 0, 1,
    ];
    p.extend_from_slice(&[0xde, 0xad, byte, 0xef]);
    let total = p.len() as u16;
    p[2..4].copy_from_slice(&total.to_be_bytes());
    p
}

/// 双向投喂直至队列为空，返回对端收到的明文
fn quiesce(
    a: &mut WgTunnel,
    b: &mut WgTunnel,
    mut a_w: VecDeque<Vec<u8>>,
    mut b_w: VecDeque<Vec<u8>>,
) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let (mut a_got, mut b_got) = (vec![], vec![]);
    for _ in 0..10 {
        while let Some(d) = a_w.pop_front() {
            let o = b.decapsulate(None, &d);
            b_w.extend(o.to_send);
            if let Some(p) = o.plaintext {
                b_got.push(p);
            }
        }
        while let Some(d) = b_w.pop_front() {
            let o = a.decapsulate(None, &d);
            a_w.extend(o.to_send);
            if let Some(p) = o.plaintext {
                a_got.push(p);
            }
        }
        if a_w.is_empty() && b_w.is_empty() {
            break;
        }
    }
    (a_got, b_got)
}

#[test]
fn wg_handshake_and_bidirectional_data() {
    let a_priv = keypair(1);
    let b_priv = keypair(2);
    let mut a = WgTunnel::new(&a_priv, &pub_of(&b_priv), 1);
    let mut b = WgTunnel::new(&b_priv, &pub_of(&a_priv), 2);

    // A 首包：产出握手发起（包入内部队列），quiesce 完成三次握手 + 队列冲刷
    let packet = payload_v4(1);
    let wire = a.encapsulate(&packet);
    assert_eq!(wire.len(), 1, "首包应产出握手发起");
    let (_, b_got) = quiesce(&mut a, &mut b, wire.into(), VecDeque::new());
    assert_eq!(b_got, vec![packet], "握手后排队首包应恰好送达");

    // 会话建立后双向直发
    let wire = a.encapsulate(&payload_v4(2));
    let (_, b_got) = quiesce(&mut a, &mut b, wire.into(), VecDeque::new());
    assert_eq!(b_got, vec![payload_v4(2)]);
    let wire = b.encapsulate(&payload_v4(3));
    let (a_got, _) = quiesce(&mut a, &mut b, VecDeque::new(), wire.into());
    assert_eq!(a_got, vec![payload_v4(3)]);
}

#[test]
fn icmp_echo_request_and_reply_roundtrip() {
    let src = Ipv4Addr::new(100, 64, 0, 1);
    let dst = Ipv4Addr::new(100, 64, 0, 2);
    let req = icmp_echo_request(src, dst, 0x5211, 7, b"lrill-ping");

    // 对端视角：应识别为 echo request 并产出反向应答包
    match parse_icmp_echo(&req) {
        IcmpEcho::Request {
            src: got_src,
            reply,
        } => {
            assert_eq!(got_src, src);
            // 应答包回到发起方视角：type 0、id/seq 匹配
            match parse_icmp_echo(&reply) {
                IcmpEcho::Reply { ident, seq } => {
                    assert_eq!((ident, seq), (0x5211, 7));
                }
                other => panic!("want Reply, got {other:?}"),
            }
        }
        other => panic!("want Request, got {other:?}"),
    }
}

/// Internet checksum 校验：含 checksum 字段在内的全 16 位字求和应为 0xFFFF
fn checksum_ok(data: &[u8]) -> bool {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if data.len() % 2 == 1 {
        sum += (data[data.len() - 1] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum == 0xFFFF
}

#[test]
fn icmp_reply_checksums_are_kernel_valid() {
    // 对端内核会校验并静默丢弃坏 checksum 的 echo reply（ping 显示 100% 丢包），
    // 必须按内核标准校验 IP 头与 ICMP 两处 checksum
    let src = Ipv4Addr::new(100, 64, 0, 2);
    let dst = Ipv4Addr::new(100, 64, 0, 1);
    let req = icmp_echo_request(src, dst, 0x5211, 9, b"lrill-ts2021");
    let IcmpEcho::Request { reply, .. } = parse_icmp_echo(&req) else {
        panic!("want Request");
    };
    assert_eq!(reply[20], 0, "应答 ICMP type 应为 0");
    assert!(checksum_ok(&reply[..20]), "IP header checksum 应有效");
    assert!(checksum_ok(&reply[20..]), "ICMP checksum 应有效");
}

#[test]
fn icmp_rejects_non_icmp() {
    assert!(matches!(parse_icmp_echo(&[0u8; 10]), IcmpEcho::Other));
    let mut not_icmp = icmp_echo_request(
        Ipv4Addr::new(1, 2, 3, 4),
        Ipv4Addr::new(5, 6, 7, 8),
        1,
        1,
        b"x",
    );
    not_icmp[9] = 17; // proto → udp
    assert!(matches!(parse_icmp_echo(&not_icmp), IcmpEcho::Other));
}
