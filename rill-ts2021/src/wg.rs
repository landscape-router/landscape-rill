//! WG 数据面（TS2021_LEG §3.3，v1 DERP-only 的直连部分）：boringtun 每 peer 一条用户态
//! 会话 + 最小 IPv4/ICMP 读写（探针用，无 TUN）。封装参考 rill-dn42 tunnel（同构实现，
//! 两腿各自持有，避免跨 leg 依赖）。
//! 注意：boringtun 产出的 WG 报文与 tailscaled 互操作（内核 WG），握手/会话语义同 WireGuard。

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use std::net::Ipv4Addr;

/// 封装后上限：数据包 ≤ 65535 + WG 开销
const MAX_WG_PACKET: usize = 65535 + 148;

pub struct WgTunnel {
    tunn: Tunn,
}

/// decapsulate 产物：明文 IP 包 + 需发回的传输字节
#[derive(Debug, Default)]
pub struct DecapOutcome {
    pub plaintext: Option<Vec<u8>>,
    pub to_send: Vec<Vec<u8>>,
}

impl WgTunnel {
    pub fn new(own_private: &[u8; 32], peer_public: &[u8; 32], index: u32) -> Self {
        let secret = StaticSecret::from(*own_private);
        let public = PublicKey::from(*peer_public);
        Self {
            tunn: Tunn::new(secret, public, None, None, index, None),
        }
    }

    /// 明文 IP 包 → WG 传输字节；无会话时触发握手发起
    pub fn encapsulate(&mut self, packet: &[u8]) -> Vec<Vec<u8>> {
        let mut dst = vec![0u8; packet.len() + 64];
        match self.tunn.encapsulate(packet, &mut dst) {
            TunnResult::WriteToNetwork(bytes) => vec![bytes.to_vec()],
            _ => self.ensure_initiated(),
        }
    }

    /// UDP 数据报 → 明文包 + 待发字节（重复调用直至 Done）
    pub fn decapsulate(&mut self, src: Option<std::net::IpAddr>, datagram: &[u8]) -> DecapOutcome {
        let mut out = DecapOutcome::default();
        let mut dst = vec![0u8; MAX_WG_PACKET];
        let mut first = true;
        loop {
            let result = if first {
                first = false;
                self.tunn.decapsulate(src, datagram, &mut dst)
            } else {
                self.tunn.decapsulate(src, &[], &mut dst)
            };
            match result {
                TunnResult::Done => break,
                TunnResult::Err(e) => {
                    // 解析失败/无会话：丢弃（fail-closed）；错误形态经 LRILL_DEBUG 观测
                    if std::env::var("LRILL_DEBUG").is_ok() {
                        eprintln!("[dbg] wg decap err: {e:?} ({}B)", datagram.len());
                    }
                    break;
                }
                TunnResult::WriteToNetwork(bytes) => out.to_send.push(bytes.to_vec()),
                TunnResult::WriteToTunnelV4(bytes, _) | TunnResult::WriteToTunnelV6(bytes, _) => {
                    out.plaintext = Some(bytes.to_vec())
                }
            }
        }
        out
    }

    /// 周期定时器：握手重试、keepalive、rekey（驱动约 1s 一调）
    pub fn update_timers(&mut self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut dst = vec![0u8; MAX_WG_PACKET];
        loop {
            match self.tunn.update_timers(&mut dst) {
                TunnResult::Done => break,
                TunnResult::Err(_) => break,
                TunnResult::WriteToNetwork(bytes) => out.push(bytes.to_vec()),
                _ => break,
            }
        }
        out
    }

    /// 会话未建立且握手未在途时发起握手
    pub fn ensure_initiated(&mut self) -> Vec<Vec<u8>> {
        let mut dst = vec![0u8; MAX_WG_PACKET];
        match self.tunn.format_handshake_initiation(&mut dst, false) {
            TunnResult::WriteToNetwork(bytes) => vec![bytes.to_vec()],
            _ => vec![],
        }
    }

    pub fn session_established(&self) -> bool {
        self.tunn.stats().0.is_some()
    }
}

// ---------- 最小 IPv4/ICMP（探针专用，无 TUN 栈） ----------

fn checksum16(data: &[u8]) -> u16 {
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
    !(sum as u16)
}

/// ICMP echo request（IPv4 头 + ICMP 头 + payload）
pub fn icmp_echo_request(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    ident: u16,
    seq: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut icmp = Vec::with_capacity(8 + payload.len());
    icmp.push(8); // type: echo request
    icmp.push(0);
    icmp.extend_from_slice(&[0, 0]); // checksum 占位
    icmp.extend_from_slice(&ident.to_be_bytes());
    icmp.extend_from_slice(&seq.to_be_bytes());
    icmp.extend_from_slice(payload);
    let ck = checksum16(&icmp);
    icmp[2..4].copy_from_slice(&ck.to_be_bytes());

    let total_len = 20 + icmp.len();
    let mut ip = Vec::with_capacity(total_len);
    ip.push(0x45); // v4, ihl 5
    ip.push(0); // tos
    ip.extend_from_slice(&(total_len as u16).to_be_bytes());
    ip.extend_from_slice(&[0, 0]); // id
    ip.extend_from_slice(&[0x40, 0]); // don't fragment
    ip.push(64); // ttl
    ip.push(1); // proto icmp
    ip.extend_from_slice(&[0, 0]); // checksum 占位
    ip.extend_from_slice(&src.octets());
    ip.extend_from_slice(&dst.octets());
    let ck = checksum16(&ip);
    ip[10..12].copy_from_slice(&ck.to_be_bytes());
    ip.extend_from_slice(&icmp);
    ip
}

/// 解析明文 IP 包：echo request（type 8）→ 供应答；echo reply（type 0）→ 匹配 id/seq
#[derive(Debug)]
pub enum IcmpEcho {
    Request { src: Ipv4Addr, reply: Vec<u8> },
    Reply { ident: u16, seq: u16 },
    Other,
}

pub fn parse_icmp_echo(packet: &[u8]) -> IcmpEcho {
    if packet.len() < 28 || packet[0] >> 4 != 4 {
        return IcmpEcho::Other;
    }
    let proto = packet[9];
    if proto != 1 {
        return IcmpEcho::Other;
    }
    let ihl = (packet[0] & 0x0F) as usize * 4;
    if packet.len() < ihl + 8 {
        return IcmpEcho::Other;
    }
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let icmp = &packet[ihl..];
    let icmp_type = icmp[0];
    let ident = u16::from_be_bytes([icmp[4], icmp[5]]);
    let seq = u16::from_be_bytes([icmp[6], icmp[7]]);
    match icmp_type {
        8 => {
            // 应答：src/dst 互换、type 8→0、重算两处校验和。
            // ICMP 校验和字段必须先清零：带着请求侧旧值求和会得到常数 0x0800，
            // 内核校验失败静默丢弃（对端 ping 显示 100% 丢包）。
            let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
            let mut reply = packet[ihl..].to_vec();
            reply[0] = 0;
            reply[2] = 0;
            reply[3] = 0;
            let ck = checksum16(&reply);
            reply[2..4].copy_from_slice(&ck.to_be_bytes());
            let mut ip = Vec::with_capacity(20 + reply.len());
            ip.extend_from_slice(&packet[..10]);
            ip.extend_from_slice(&[0, 0]); // checksum 占位
            ip.extend_from_slice(&dst.octets()); // 应答源 = 请求目的
            ip.extend_from_slice(&src.octets()); // 应答目的 = 请求源
            let ck = checksum16(&ip);
            ip[10..12].copy_from_slice(&ck.to_be_bytes());
            ip.extend_from_slice(&reply);
            IcmpEcho::Request { src, reply: ip }
        }
        0 => IcmpEcho::Reply { ident, seq },
        _ => IcmpEcho::Other,
    }
}

#[cfg(test)]
mod tests;
