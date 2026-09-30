//! MTU 策略 / MSS clamping / PTB 构造（ROUTE_ENGINE §6，v1 定稿）：
//! 不做帧内分片，tun0 保守静态 MTU；TCP SYN 改写 MSS，大包以伪造 PTB 通知源端。
//! 纯函数无 I/O（I/O-free core 风格），构造/改写结果的校验和按内核标准单测覆盖。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// mesh 封装开销（§6.1，定义在 rill-mesh——帧格式归 mesh 持有）：
/// 42B 帧头 + 16B tag + 8B UDP + 20B IP；IPv6 底网 +20B
pub use landscape_rill_mesh::data::ENCAP_OVERHEAD_V4 as MESH_ENCAP_OVERHEAD_V4;
pub use landscape_rill_mesh::data::ENCAP_OVERHEAD_V6 as MESH_ENCAP_OVERHEAD_V6;
/// dn42 / ts2021（WireGuard）封装开销估算（§6.1）
pub const WG_ENCAP_OVERHEAD_V4: u16 = 48;
pub const WG_ENCAP_OVERHEAD_V6: u16 = 68;

/// 物理出口 MTU 假设（保守静态的基准；v1 不做运行时出口发现）
pub const DEFAULT_EGRESS_MTU: u16 = 1500;

/// tun0 保守静态 MTU（§6.2）：物理出口 − 最大封装开销（取 mesh/IPv6 最坏值），
/// 一条安全值所有路径都通；动态 per-dst PMTU 缓存留 v2
pub const TUN_CONSERVATIVE_MTU: u16 = DEFAULT_EGRESS_MTU - MESH_ENCAP_OVERHEAD_V6;

/// 封装后总长是否超过出口 MTU（mesh 腿）
pub fn mesh_frame_fits(inner_len: usize, underlay_v6: bool, egress_mtu: u16) -> bool {
    let overhead = if underlay_v6 {
        MESH_ENCAP_OVERHEAD_V6
    } else {
        MESH_ENCAP_OVERHEAD_V4
    };
    (inner_len as u16).saturating_add(overhead) <= egress_mtu
}

// ==================== MSS clamping ====================

/// TCP SYN 的 MSS 选项压到安全值（§6.2）：覆盖绝大多数流量，零协议改动。
/// 非 SYN / 无 MSS 选项 / 已低于安全值 → 不动（返回 false）。
/// `mtu` = 本侧安全内层 MTU（如 TUN_CONSERVATIVE_MTU）；v4 MSS ≤ mtu−40，v6 ≤ mtu−60。
/// 校验和按 RFC 1624 增量更新。
pub fn clamp_mss(pkt: &mut [u8], mtu: u16) -> bool {
    let Some(l4) = l4_offset(pkt) else {
        return false;
    };
    // SYN / SYN-ACK 都带 MSS，都要压；非 SYN 不动
    if l4 + 20 > pkt.len() || !is_tcp_syn(pkt) {
        return false;
    }
    let doff = (pkt[l4 + 12] as usize >> 4) * 4;
    if doff < 20 || l4 + doff > pkt.len() {
        return false;
    }
    let max_mss = match pkt[0] >> 4 {
        4 => mtu.saturating_sub(40),
        6 => mtu.saturating_sub(60),
        _ => return false,
    };
    let mut mss_at = None;
    let mut i = l4 + 20;
    while i + 1 < l4 + doff {
        match pkt[i] {
            0 => break,  // EOL
            1 => i += 1, // NOP
            k => {
                let len = pkt[i + 1] as usize;
                if len < 2 || i + len > l4 + doff {
                    break;
                }
                if k == 2 && len == 4 {
                    mss_at = Some(i);
                }
                i += len;
            }
        }
    }
    let Some(at) = mss_at else {
        return false;
    };
    let old = u16::from_be_bytes([pkt[at + 2], pkt[at + 3]]);
    if old <= max_mss {
        return false;
    }
    pkt[at + 2..at + 4].copy_from_slice(&max_mss.to_be_bytes());
    // TCP 校验和增量更新（RFC 1624 eqn-3）：HC' = ~(~HC + ~m + m')
    let ck_at = l4 + 16;
    let hc = u16::from_be_bytes([pkt[ck_at], pkt[ck_at + 1]]);
    let hc = !ones_complement_add(!hc, ones_complement_add(!old, max_mss));
    pkt[ck_at..ck_at + 2].copy_from_slice(&hc.to_be_bytes());
    true
}

/// SYN 候选预检（调用方避免逐包拷贝）：v4/v6 + TCP + SYN 置位
pub fn is_tcp_syn(pkt: &[u8]) -> bool {
    let Some(l4) = l4_offset(pkt) else {
        return false;
    };
    pkt.len() >= l4 + 14 && pkt[l3_proto(pkt)] == 6 && pkt[l4 + 13] & 0x02 != 0
}

/// 16 位反码加法（含折叠）
fn ones_complement_add(a: u16, b: u16) -> u16 {
    let mut s = a as u32 + b as u32;
    while s >> 16 != 0 {
        s = (s & 0xffff) + (s >> 16);
    }
    s as u16
}

fn l3_proto(pkt: &[u8]) -> usize {
    match pkt[0] >> 4 {
        4 => 9,
        _ => 6, // IPv6 next header
    }
}

/// 传输层起始偏移（v4 IHL / v6 固定 40；扩展头不在 v1 处理范围）
fn l4_offset(pkt: &[u8]) -> Option<usize> {
    match pkt[0] >> 4 {
        4 => {
            let ihl = (pkt[0] & 0x0f) as usize * 4;
            (ihl >= 20 && pkt.len() >= ihl).then_some(ihl)
        }
        6 => (pkt.len() >= 40).then_some(40),
        _ => None,
    }
}

// ==================== PTB 构造（ICMP/ICMPv6） ====================

/// 伪造 PTB（§6.2 实现要点）：**源地址 = 被封装包的目标地址**（ICMP 语义要求），
/// 发往被封装包的源端（写 tun0 → LAN 侧主机据此收缩 PMTU）。
/// `next_hop_mtu` = 内层可用 MTU（出口 PMTU − 封装开销，或保守值兜底）。
pub fn build_ptb(inner: &[u8], next_hop_mtu: u16) -> Option<Vec<u8>> {
    match inner.first()? >> 4 {
        4 => build_ptb_v4(inner, next_hop_mtu),
        6 => build_ptb_v6(inner, next_hop_mtu),
        _ => None,
    }
}

fn build_ptb_v4(inner: &[u8], next_hop_mtu: u16) -> Option<Vec<u8>> {
    let (src, dst) = (v4_dst(inner)?, v4_src(inner)?);
    let ihl = (inner[0] & 0x0f) as usize * 4;
    let quote_len = (ihl + 8).min(inner.len());
    let total_len = 20 + 8 + quote_len;
    let mut pkt = vec![0u8; total_len];
    // 外层 IPv4 头
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[4..6].copy_from_slice(&0x5211u16.to_be_bytes()); // id
    pkt[8] = 64; // ttl
    pkt[9] = 1; // ICMP
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst.octets());
    // ICMP：type 3 code 4（frag needed / DF set）
    pkt[20] = 3;
    pkt[21] = 4;
    pkt[20 + 6..20 + 8].copy_from_slice(&next_hop_mtu.to_be_bytes());
    pkt[20 + 8..].copy_from_slice(&inner[..quote_len]);
    let ck = checksum16(&pkt[20..]);
    pkt[20 + 2..20 + 4].copy_from_slice(&ck.to_be_bytes());
    let ip_ck = checksum16(&pkt[..20]);
    pkt[10..12].copy_from_slice(&ip_ck.to_be_bytes());
    Some(pkt)
}

fn build_ptb_v6(inner: &[u8], next_hop_mtu: u16) -> Option<Vec<u8>> {
    let (src, dst) = (v6_dst(inner)?, v6_src(inner)?);
    // 引文按最小 IPv6 MTU 截断（RFC 4443：不超 1280 − 40 − 8）
    let quote_len = inner.len().min(1280 - 40 - 8);
    let payload_len = 8 + quote_len;
    let mut pkt = vec![0u8; 40 + payload_len];
    pkt[0] = 0x60; // version 6（vec 零初始化，必须显式置——否则内核按非 IPv6 丢弃）
    pkt[4..6].copy_from_slice(&(payload_len as u16).to_be_bytes());
    pkt[6] = 58; // ICMPv6
    pkt[7] = 255; // hop limit：RFC 4443 §2.4 错误报文按 255 发送（接收侧校验友好）
    pkt[8..24].copy_from_slice(&src.octets());
    pkt[24..40].copy_from_slice(&dst.octets());
    // ICMPv6 type 2（Packet Too Big）code 0；MTU 字段 32 位（RFC 4443 §3.2）
    pkt[40] = 2;
    pkt[44..48].copy_from_slice(&(next_hop_mtu as u32).to_be_bytes());
    pkt[48..].copy_from_slice(&inner[..quote_len]);
    let ck = icmpv6_checksum(&pkt[..40], &pkt[40..]);
    pkt[42..44].copy_from_slice(&ck.to_be_bytes());
    Some(pkt)
}

/// 标准 16 位校验和（结果为写入字段的反码值；校验时含字段求和 = 0xFFFF）
fn checksum16(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !sum as u16
}

/// ICMPv6 校验和（伪头部：src + dst + 上层长度 + next header 58）
fn icmpv6_checksum(ip6_header: &[u8], icmp: &[u8]) -> u16 {
    let mut buf = Vec::with_capacity(40 + 8 + icmp.len());
    buf.extend_from_slice(&ip6_header[8..40]); // src + dst
    buf.extend_from_slice(&(icmp.len() as u32).to_be_bytes());
    buf.extend_from_slice(&[0, 0, 0, 58]);
    buf.extend_from_slice(icmp);
    checksum16(&buf)
}

fn v4_src(p: &[u8]) -> Option<Ipv4Addr> {
    (p.len() >= 20).then(|| Ipv4Addr::new(p[12], p[13], p[14], p[15]))
}

fn v4_dst(p: &[u8]) -> Option<Ipv4Addr> {
    (p.len() >= 20).then(|| Ipv4Addr::new(p[16], p[17], p[18], p[19]))
}

fn v6_src(p: &[u8]) -> Option<Ipv6Addr> {
    let o = <[u8; 16]>::try_from(p.get(8..24)?).ok()?;
    Some(Ipv6Addr::from(o))
}

fn v6_dst(p: &[u8]) -> Option<Ipv6Addr> {
    let o = <[u8; 16]>::try_from(p.get(24..40)?).ok()?;
    Some(Ipv6Addr::from(o))
}

/// 内层包 src/dst（PTB 的收发两端）
pub fn endpoints(inner: &[u8]) -> Option<(IpAddr, IpAddr)> {
    match inner.first()? >> 4 {
        4 => Some((v4_src(inner)?.into(), v4_dst(inner)?.into())),
        6 => Some((v6_src(inner)?.into(), v6_dst(inner)?.into())),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造带 MSS 选项的 TCP SYN（含正确 IP/TCP 校验和）
    fn syn_packet(v6: bool, mss: u16) -> Vec<u8> {
        let (ip_len, tcp_off) = if v6 { (40, 40) } else { (20, 20) };
        let mut p = vec![0u8; tcp_off + 24];
        if v6 {
            p[0] = 0x60;
            p[4..6].copy_from_slice(&24u16.to_be_bytes());
            p[6] = 6;
            p[8..24].copy_from_slice(&[0x20; 16]);
            p[24..40].copy_from_slice(&[0x21; 16]);
        } else {
            p[0] = 0x45;
            p[2..4].copy_from_slice(&((ip_len + 24) as u16).to_be_bytes());
            p[9] = 6;
            p[12..16].copy_from_slice(&[10, 42, 0, 1]);
            p[16..20].copy_from_slice(&[10, 43, 0, 1]);
        }
        let t = tcp_off;
        p[t + 13] = 0x02; // SYN
                          // MSS 选项（data offset = 6 → TCP 头 24B）
        p[t + 12] = 6 << 4;
        p[t + 20] = 2; // MSS
        p[t + 21] = 4;
        p[t + 22..t + 24].copy_from_slice(&mss.to_be_bytes());
        fix_tcp_checksum(&mut p, v6);
        p
    }

    /// 全量重算 TCP 校验和（伪头部）
    fn fix_tcp_checksum(p: &mut [u8], v6: bool) {
        let t = if v6 { 40 } else { 20 };
        p[t + 16..t + 18].copy_from_slice(&[0, 0]);
        let mut buf = Vec::new();
        if v6 {
            buf.extend_from_slice(&p[8..40]);
            buf.extend_from_slice(&((p.len() - t) as u32).to_be_bytes());
            buf.extend_from_slice(&[0, 0, 0, 6]);
        } else {
            buf.extend_from_slice(&p[12..20]);
            buf.extend_from_slice(&[0, 6]);
            buf.extend_from_slice(&((p.len() - t) as u16).to_be_bytes());
        }
        buf.extend_from_slice(&p[t..]);
        let ck = checksum16(&buf);
        p[t + 16..t + 18].copy_from_slice(&ck.to_be_bytes());
    }

    fn tcp_checksum_ok(p: &[u8], v6: bool) -> bool {
        let t = if v6 { 40 } else { 20 };
        let mut buf = Vec::new();
        if v6 {
            buf.extend_from_slice(&p[8..40]);
            buf.extend_from_slice(&((p.len() - t) as u32).to_be_bytes());
            buf.extend_from_slice(&[0, 0, 0, 6]);
        } else {
            buf.extend_from_slice(&p[12..20]);
            buf.extend_from_slice(&[0, 6]);
            buf.extend_from_slice(&((p.len() - t) as u16).to_be_bytes());
        }
        buf.extend_from_slice(&p[t..]);
        checksum16(&buf) == 0
    }

    #[test]
    fn conservative_mtu_matches_design_table() {
        // §6.1/§6.2：1500 − mesh IPv6 最坏开销 106 = 1394
        assert_eq!(MESH_ENCAP_OVERHEAD_V4, 86);
        assert_eq!(MESH_ENCAP_OVERHEAD_V6, 106);
        assert_eq!(WG_ENCAP_OVERHEAD_V4, 48);
        assert_eq!(TUN_CONSERVATIVE_MTU, 1394);
        assert!(!mesh_frame_fits(1395, true, 1500));
        assert!(mesh_frame_fits(1394, true, 1500));
        assert!(mesh_frame_fits(1394, false, 1500)); // v4 开销 86：1480 ≤ 1500
        assert!(mesh_frame_fits(1314, false, 1400)); // 1400 出口：1400−86=1314
        assert!(!mesh_frame_fits(1315, false, 1400));
        assert!(!mesh_frame_fits(1394, true, 1400)); // v6 底网 1400 放不下
    }

    #[test]
    fn clamp_mss_v4_syn_rewrites_and_keeps_checksum() {
        let mut p = syn_packet(false, 1380);
        assert!(clamp_mss(&mut p, TUN_CONSERVATIVE_MTU));
        let t = 20usize;
        assert_eq!(u16::from_be_bytes([p[t + 22], p[t + 23]]), 1354);
        assert!(tcp_checksum_ok(&p, false), "增量更新后校验和必须仍有效");
    }

    #[test]
    fn clamp_mss_v6_syn() {
        let mut p = syn_packet(true, 1380);
        assert!(clamp_mss(&mut p, TUN_CONSERVATIVE_MTU));
        assert_eq!(u16::from_be_bytes([p[40 + 22], p[40 + 23]]), 1334);
        assert!(tcp_checksum_ok(&p, true));
    }

    #[test]
    fn clamp_mss_leaves_small_and_non_syn_alone() {
        let mut small = syn_packet(false, 1300);
        assert!(!clamp_mss(&mut small, TUN_CONSERVATIVE_MTU));
        let mut nosyn = syn_packet(false, 1460);
        nosyn[33] = 0x10; // ACK 而非 SYN
        assert!(!clamp_mss(&mut nosyn, TUN_CONSERVATIVE_MTU));
        // 预检与 clamp 判定一致：SYN 命中，非 SYN / 非 IP 不命中
        assert!(is_tcp_syn(&syn_packet(true, 1380)));
        assert!(!is_tcp_syn(&nosyn));
        assert!(!is_tcp_syn(&[0x45u8; 8]));
    }

    #[test]
    fn ptb_v4_structure_and_checksums() {
        let inner = syn_packet(false, 1380); // src 10.42.0.1 dst 10.43.0.1
        let ptb = build_ptb(&inner, 1314).unwrap();
        assert_eq!(ptb[0] >> 4, 4);
        assert_eq!(ptb[9], 1); // ICMP
                               // 源 = 内层 dst，目的 = 内层 src（§6.2 实现要点）
        assert_eq!(&ptb[12..16], &[10, 43, 0, 1]);
        assert_eq!(&ptb[16..20], &[10, 42, 0, 1]);
        assert_eq!(ptb[20], 3);
        assert_eq!(ptb[21], 4); // frag needed
        assert_eq!(u16::from_be_bytes([ptb[26], ptb[27]]), 1314);
        assert_eq!(checksum16(&ptb[..20]), 0, "IP 头校验和有效");
        assert_eq!(checksum16(&ptb[20..]), 0, "ICMP 校验和有效");
        // 引文 = 内层 IP 头 + 8B
        assert_eq!(&ptb[28..28 + 20], &inner[..20]);
        assert_eq!(endpoints(&inner).unwrap().1.to_string(), "10.43.0.1");
    }

    #[test]
    fn ptb_v6_structure_and_checksum() {
        let inner = syn_packet(true, 1380);
        let ptb = build_ptb(&inner, 1314).unwrap();
        assert_eq!(ptb[0] >> 4, 6, "version 必须为 6（否则内核不入栈）");
        assert_eq!(ptb[6], 58);
        assert_eq!(&ptb[8..24], &[0x21; 16]); // 源 = 内层 dst
        assert_eq!(&ptb[24..40], &[0x20; 16]); // 目的 = 内层 src
        assert_eq!((ptb[40], ptb[41]), (2, 0)); // Packet Too Big
        assert_eq!(u32::from_be_bytes(ptb[44..48].try_into().unwrap()), 1314);
        assert_eq!(icmpv6_checksum(&ptb[..40], &ptb[40..]), 0);
    }
}
