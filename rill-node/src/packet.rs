use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportProto {
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
    Other(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketInfo {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub proto: TransportProto,
    pub total_len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketError {
    NotIp,
    Truncated,
}

pub fn parse_packet(buf: &[u8]) -> Result<PacketInfo, PacketError> {
    if buf.is_empty() {
        return Err(PacketError::NotIp);
    }
    match buf[0] >> 4 {
        4 => parse_v4(buf),
        6 => parse_v6(buf),
        _ => Err(PacketError::NotIp),
    }
}

fn parse_v4(buf: &[u8]) -> Result<PacketInfo, PacketError> {
    if buf.len() < 20 {
        return Err(PacketError::Truncated);
    }
    let ihl = (buf[0] & 0x0f) as usize * 4;
    if ihl < 20 || buf.len() < ihl {
        return Err(PacketError::Truncated);
    }
    let src = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
    let dst = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);
    let proto = proto_from_u8(buf[9]);
    let total_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    Ok(PacketInfo {
        src: IpAddr::V4(src),
        dst: IpAddr::V4(dst),
        proto,
        total_len,
    })
}

fn parse_v6(buf: &[u8]) -> Result<PacketInfo, PacketError> {
    if buf.len() < 40 {
        return Err(PacketError::Truncated);
    }
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&buf[8..24]);
    dst.copy_from_slice(&buf[24..40]);
    let proto = proto_from_u8(buf[6]);
    let total_len = 40 + u16::from_be_bytes([buf[4], buf[5]]) as usize;
    Ok(PacketInfo {
        src: IpAddr::V6(Ipv6Addr::from(src)),
        dst: IpAddr::V6(Ipv6Addr::from(dst)),
        proto,
        total_len,
    })
}

fn proto_from_u8(v: u8) -> TransportProto {
    match v {
        6 => TransportProto::Tcp,
        17 => TransportProto::Udp,
        1 => TransportProto::Icmp,
        58 => TransportProto::Icmpv6,
        other => TransportProto::Other(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4_packet(proto: u8) -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&20u16.to_be_bytes());
        p[9] = proto;
        p[12..16].copy_from_slice(&[10, 0, 0, 1]);
        p[16..20].copy_from_slice(&[10, 0, 0, 2]);
        p
    }

    #[test]
    fn v4_udp() {
        let info = parse_packet(&v4_packet(17)).unwrap();
        assert_eq!(info.src, "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(info.dst, "10.0.0.2".parse::<IpAddr>().unwrap());
        assert_eq!(info.proto, TransportProto::Udp);
        assert_eq!(info.total_len, 20);
    }

    #[test]
    fn v4_tcp_with_options() {
        let mut p = v4_packet(6);
        p[0] = 0x46;
        p.resize(24, 0);
        p[2..4].copy_from_slice(&24u16.to_be_bytes());
        let info = parse_packet(&p).unwrap();
        assert_eq!(info.proto, TransportProto::Tcp);
        assert_eq!(info.total_len, 24);
    }

    #[test]
    fn v6_icmpv6() {
        let mut p = vec![0u8; 40];
        p[0] = 0x60;
        p[6] = 58;
        p[8] = 0xfd;
        p[24] = 0xfd;
        p[39] = 0x02;
        let info = parse_packet(&p).unwrap();
        assert_eq!(info.src, IpAddr::V6("fd00::".parse().unwrap()));
        assert_eq!(info.proto, TransportProto::Icmpv6);
        assert_eq!(info.total_len, 40);
    }

    #[test]
    fn fail_closed_on_junk() {
        assert_eq!(parse_packet(&[]), Err(PacketError::NotIp));
        assert_eq!(parse_packet(&[0x00; 4]), Err(PacketError::NotIp));
        assert_eq!(parse_packet(&[0x45; 4]), Err(PacketError::Truncated));
        assert_eq!(parse_packet(&[0x60; 10]), Err(PacketError::Truncated));
        let mut bad = v4_packet(17);
        bad.truncate(10);
        assert_eq!(parse_packet(&bad), Err(PacketError::Truncated));
    }
}
