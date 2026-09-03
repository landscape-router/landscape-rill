//! eBGP-lite 线格式 codec（自研必须集，DN42_LEG §3/§7：RFC 4271 / 4760 MP-BGP / 6793 4B ASN /
//! 2918 route refresh）。错误只经 Result 返回，畸形输入零 panic（对齐 REQ-059 风格）。

#[cfg(test)]
mod tests;

use std::net::{IpAddr, Ipv4Addr};

use landscape_rill_core::route::Prefix;

pub const BGP_VERSION: u8 = 4;
pub const HEADER_LEN: usize = 19;
pub const MAX_MSG_LEN: usize = 4096;
/// AS_TRANS（RFC 6793）：>65535 的 ASN 在 2B 字段/AS_PATH 中的占位
pub const AS_TRANS: u16 = 23456;

pub const TYPE_OPEN: u8 = 1;
pub const TYPE_UPDATE: u8 = 2;
pub const TYPE_NOTIFICATION: u8 = 3;
pub const TYPE_KEEPALIVE: u8 = 4;
pub const TYPE_ROUTE_REFRESH: u8 = 5;

pub const AFI_IPV4: u16 = 1;
pub const AFI_IPV6: u16 = 2;
pub const SAFI_UNICAST: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, landscape_rill_macro::ErrorId)]
pub enum WireError {
    #[error("bad marker")]
    #[error_id("dn42.wire.bad_marker")]
    BadMarker,
    #[error("bad length {0}")]
    #[error_id("dn42.wire.bad_length")]
    BadLength(u16),
    #[error("truncated message")]
    #[error_id("dn42.wire.truncated")]
    Truncated,
    #[error("malformed OPEN")]
    #[error_id("dn42.wire.bad_open")]
    BadOpen,
    #[error("malformed UPDATE")]
    #[error_id("dn42.wire.bad_update")]
    BadUpdate,
    #[error("unrecognized well-known attribute {0}")]
    #[error_id("dn42.wire.unknown_well_known")]
    UnknownWellKnown(u8),
    #[error("message too long")]
    #[error_id("dn42.wire.too_long")]
    TooLong,
    #[error("unsupported message type {0}")]
    #[error_id("dn42.wire.bad_type")]
    BadType(u8),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Open(OpenMsg),
    Update(UpdateMsg),
    Notification(NotificationMsg),
    Keepalive,
    RouteRefresh(RouteRefreshMsg),
}

impl Message {
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), WireError> {
        let body_start = out.len();
        out.extend_from_slice(&[0xffu8; HEADER_LEN]);
        let ty = match self {
            Message::Open(m) => {
                out.push(BGP_VERSION);
                let my_as = if m.as4 > u16::MAX as u32 {
                    AS_TRANS
                } else {
                    m.as4 as u16
                };
                out.extend_from_slice(&my_as.to_be_bytes());
                out.extend_from_slice(&m.hold_time.to_be_bytes());
                out.extend_from_slice(&m.bgp_id.octets());
                let mut caps = Vec::new();
                for cap in &m.capabilities {
                    cap.encode(&mut caps);
                }
                if caps.len() > 255 {
                    return Err(WireError::TooLong);
                }
                // Optional Parameters：单个 type=2（Capabilities）参数承载全部能力（RFC 5492）
                out.push((caps.len() + 2) as u8);
                out.push(2);
                out.push(caps.len() as u8);
                out.extend_from_slice(&caps);
                TYPE_OPEN
            }
            Message::Update(m) => {
                // v4 NLRI 字段只承载 IPv4 unicast（其他地址族必须走 MP_REACH/MP_UNREACH）
                if m.withdrawn.iter().any(|p| !p.v4) || m.announced.iter().any(|p| !p.v4) {
                    return Err(WireError::BadUpdate);
                }
                let mut w = Vec::new();
                for p in &m.withdrawn {
                    write_nlri(&mut w, p);
                }
                if w.len() > u16::MAX as usize {
                    return Err(WireError::TooLong);
                }
                out.extend_from_slice(&(w.len() as u16).to_be_bytes());
                out.extend_from_slice(&w);
                let mut attrs = Vec::new();
                for attr in &m.attrs {
                    write_attr(&mut attrs, attr)?;
                }
                if attrs.len() > u16::MAX as usize {
                    return Err(WireError::TooLong);
                }
                out.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
                out.extend_from_slice(&attrs);
                for p in &m.announced {
                    write_nlri(out, p);
                }
                TYPE_UPDATE
            }
            Message::Notification(m) => {
                out.push(m.code);
                out.push(m.subcode);
                out.extend_from_slice(&m.data);
                TYPE_NOTIFICATION
            }
            Message::Keepalive => TYPE_KEEPALIVE,
            Message::RouteRefresh(m) => {
                out.extend_from_slice(&m.afi.to_be_bytes());
                out.push(0);
                out.push(m.safi);
                TYPE_ROUTE_REFRESH
            }
        };
        let total = out.len() - body_start;
        if total > MAX_MSG_LEN {
            out.truncate(body_start);
            return Err(WireError::TooLong);
        }
        out[body_start + 16..body_start + 18].copy_from_slice(&(total as u16).to_be_bytes());
        out[body_start + 18] = ty;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenMsg {
    pub as4: u32,
    pub hold_time: u16,
    pub bgp_id: Ipv4Addr,
    pub capabilities: Vec<Capability>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    MpBgp { afi: u16, safi: u8 },
    RouteRefresh,
    FourOctetAs(u32),
}

pub const CAP_MP_BGP: u8 = 1;
pub const CAP_ROUTE_REFRESH: u8 = 2;
pub const CAP_FOUR_OCTET_AS: u8 = 65;

impl Capability {
    fn encode(&self, out: &mut Vec<u8>) {
        match *self {
            Capability::MpBgp { afi, safi } => {
                out.extend_from_slice(&[CAP_MP_BGP, 4]);
                out.extend_from_slice(&afi.to_be_bytes());
                out.push(0);
                out.push(safi);
            }
            Capability::RouteRefresh => out.extend_from_slice(&[CAP_ROUTE_REFRESH, 0]),
            Capability::FourOctetAs(asn) => {
                out.extend_from_slice(&[CAP_FOUR_OCTET_AS, 4]);
                out.extend_from_slice(&asn.to_be_bytes());
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateMsg {
    /// IPv4 unicast WITHDRAWN Routes（RFC 4271 头部字段；其他地址族走 MpUnreach）
    pub withdrawn: Vec<Prefix>,
    pub attrs: Vec<PathAttr>,
    /// IPv4 unicast NLRI（其他地址族走 MpReach）
    pub announced: Vec<Prefix>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathAttr {
    Origin(u8),
    /// AS_PATH（attr 2，2B 编码，>65535 以 AS_TRANS 占位——真实值在 As4Path）
    AsPath(Vec<Segment>),
    /// AS4_PATH（attr 17，4B 编码，RFC 6793）
    As4Path(Vec<Segment>),
    NextHop(Ipv4Addr),
    /// 只携带不解释（DN42_LEG §3）
    Communities(Vec<u32>),
    MpReach {
        afi: u16,
        safi: u8,
        next_hop: IpAddr,
        nlri: Vec<Prefix>,
    },
    MpUnreach {
        afi: u16,
        safi: u8,
        nlri: Vec<Prefix>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    pub set: bool,
    pub asns: Vec<u32>,
}

pub const AS_SET: u8 = 1;
pub const AS_SEQUENCE: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationMsg {
    pub code: u8,
    pub subcode: u8,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteRefreshMsg {
    pub afi: u16,
    pub safi: u8,
}

/// 增量帧读取器：feed 任意分片，产出完整 Message。
/// marker/长度字段到即校验（fail-closed，垃圾不无界缓冲）。
#[derive(Debug, Default)]
pub struct FrameReader {
    buf: Vec<u8>,
}

impl FrameReader {
    pub fn feed(&mut self, data: &[u8], out: &mut Vec<Message>) -> Result<(), WireError> {
        self.buf.extend_from_slice(data);
        loop {
            if self.buf.len() < HEADER_LEN {
                return Ok(());
            }
            if self.buf[..16].iter().any(|&b| b != 0xff) {
                return Err(WireError::BadMarker);
            }
            let len = u16::from_be_bytes([self.buf[16], self.buf[17]]);
            if !(HEADER_LEN as u16..=MAX_MSG_LEN as u16).contains(&len) {
                return Err(WireError::BadLength(len));
            }
            let len = len as usize;
            if self.buf.len() < len {
                return Ok(());
            }
            out.push(decode(&self.buf[..len])?);
            self.buf.drain(..len);
        }
    }
}

/// 解码一条完整 BGP 消息（buf 必须恰好含一帧）
pub fn decode(buf: &[u8]) -> Result<Message, WireError> {
    if buf.len() < HEADER_LEN {
        return Err(WireError::Truncated);
    }
    if buf[..16].iter().any(|&b| b != 0xff) {
        return Err(WireError::BadMarker);
    }
    let len = u16::from_be_bytes([buf[16], buf[17]]);
    if len as usize != buf.len() {
        return Err(WireError::BadLength(len));
    }
    let body = &buf[HEADER_LEN..];
    match buf[18] {
        TYPE_KEEPALIVE => Ok(Message::Keepalive),
        TYPE_OPEN => decode_open(body),
        TYPE_UPDATE => decode_update(body),
        TYPE_NOTIFICATION => Ok(Message::Notification(NotificationMsg {
            code: body.first().copied().ok_or(WireError::Truncated)?,
            subcode: body.get(1).copied().ok_or(WireError::Truncated)?,
            data: body.get(2..).unwrap_or(&[]).to_vec(),
        })),
        TYPE_ROUTE_REFRESH => {
            if body.len() != 4 {
                return Err(WireError::Truncated);
            }
            Ok(Message::RouteRefresh(RouteRefreshMsg {
                afi: u16::from_be_bytes([body[0], body[1]]),
                safi: body[3],
            }))
        }
        ty => Err(WireError::BadType(ty)),
    }
}

fn decode_open(body: &[u8]) -> Result<Message, WireError> {
    if body.len() < 10 {
        return Err(WireError::Truncated);
    }
    let my_as = u16::from_be_bytes([body[1], body[2]]) as u32;
    let hold_time = u16::from_be_bytes([body[3], body[4]]);
    let bgp_id = Ipv4Addr::new(body[5], body[6], body[7], body[8]);
    let opt_len = body[9] as usize;
    if body.len() < 10 + opt_len {
        return Err(WireError::Truncated);
    }
    let mut as4 = my_as;
    let mut capabilities = Vec::new();
    let mut rest = &body[10..10 + opt_len];
    while !rest.is_empty() {
        // Optional Parameter：type(1) len(1) value；type 2 = Capabilities（RFC 5492）
        if rest.len() < 2 {
            return Err(WireError::BadOpen);
        }
        let plen = rest[1] as usize;
        if rest.len() < 2 + plen {
            return Err(WireError::BadOpen);
        }
        let (value, tail) = rest.split_at(2 + plen);
        if value[0] == 2 {
            let mut caps = &value[2..];
            while !caps.is_empty() {
                if caps.len() < 2 {
                    return Err(WireError::BadOpen);
                }
                let clen = caps[1] as usize;
                if caps.len() < 2 + clen {
                    return Err(WireError::BadOpen);
                }
                let (cvalue, ctail) = caps.split_at(2 + clen);
                match cvalue[0] {
                    CAP_MP_BGP if cvalue.len() == 6 => {
                        capabilities.push(Capability::MpBgp {
                            afi: u16::from_be_bytes([cvalue[2], cvalue[3]]),
                            safi: cvalue[5],
                        });
                    }
                    CAP_ROUTE_REFRESH if clen == 0 => capabilities.push(Capability::RouteRefresh),
                    CAP_FOUR_OCTET_AS if cvalue.len() == 6 => {
                        let asn = u32::from_be_bytes([cvalue[2], cvalue[3], cvalue[4], cvalue[5]]);
                        capabilities.push(Capability::FourOctetAs(asn));
                        as4 = asn;
                    }
                    _ => {} // 未知 capability 跳过（RFC 5492 §4）
                }
                caps = ctail;
            }
        }
        rest = tail;
    }
    Ok(Message::Open(OpenMsg {
        as4,
        hold_time,
        bgp_id,
        capabilities,
    }))
}

fn decode_update(body: &[u8]) -> Result<Message, WireError> {
    if body.len() < 4 {
        return Err(WireError::Truncated);
    }
    let wlen = u16::from_be_bytes([body[0], body[1]]) as usize;
    if body.len() < 2 + wlen + 2 {
        return Err(WireError::Truncated);
    }
    let withdrawn = read_nlris(&body[2..2 + wlen], true)?;
    let alen = u16::from_be_bytes([body[2 + wlen], body[3 + wlen]]) as usize;
    if body.len() < 2 + wlen + 2 + alen {
        return Err(WireError::Truncated);
    }
    let attrs = decode_attrs(&body[4 + wlen..4 + wlen + alen])?;
    let announced = read_nlris(&body[4 + wlen + alen..], true)?;
    Ok(Message::Update(UpdateMsg {
        withdrawn,
        attrs,
        announced,
    }))
}

fn decode_attrs(mut buf: &[u8]) -> Result<Vec<PathAttr>, WireError> {
    let mut attrs = Vec::new();
    let mut communities: Vec<u32> = Vec::new();
    while !buf.is_empty() {
        if buf.len() < 2 {
            return Err(WireError::Truncated);
        }
        let flags = buf[0];
        let ty = buf[1];
        let ext = flags & 0x10 != 0;
        let hdr = if ext { 4 } else { 3 };
        if buf.len() < hdr {
            return Err(WireError::Truncated);
        }
        let len = if ext {
            u16::from_be_bytes([buf[2], buf[3]]) as usize
        } else {
            buf[2] as usize
        };
        if buf.len() < hdr + len {
            return Err(WireError::Truncated);
        }
        let value = &buf[hdr..hdr + len];
        match (ty, flags & 0x80 != 0) {
            (1, _) if value.len() == 1 => attrs.push(PathAttr::Origin(value[0])),
            (2, _) => {
                // AS_PATH 编码宽窄由会话协商决定（RFC 6793：4B-capable 会话为
                // 4 字节编码且无 AS4_PATH；老会话为 2 字节 + AS_TRANS）——
                // 解码无会话上下文，以"恰好消费完属性值"自检，4B 优先
                let segs = decode_segments_exact(value, true)
                    .or_else(|_| decode_segments_exact(value, false))?;
                attrs.push(PathAttr::AsPath(segs));
            }
            (3, _) if value.len() == 4 => {
                attrs.push(PathAttr::NextHop(Ipv4Addr::new(
                    value[0], value[1], value[2], value[3],
                )));
            }
            (8, _) => {
                if !value.len().is_multiple_of(4) {
                    return Err(WireError::BadUpdate);
                }
                for c in value.as_chunks::<4>().0 {
                    communities.push(u32::from_be_bytes(*c));
                }
            }
            (14, _) => attrs.push(decode_mp_reach(value)?),
            (15, _) => attrs.push(decode_mp_unreach(value)?),
            (17, _) => {
                let segs = decode_segments_exact(value, true)?;
                attrs.push(PathAttr::As4Path(segs));
            }
            // 未知属性：Optional 可跳过；well-known 必须识别（RFC 4271 §4.3）
            (_, true) => {}
            (ty, false) => return Err(WireError::UnknownWellKnown(ty)),
        }
        buf = &buf[hdr + len..];
    }
    if !communities.is_empty() {
        attrs.push(PathAttr::Communities(communities));
    }
    Ok(attrs)
}

/// 严格解码：所有段恰好消费完属性值，否则 Err（宽窄自检依据）
fn decode_segments_exact(mut buf: &[u8], wide: bool) -> Result<Vec<Segment>, WireError> {
    let mut segs = Vec::new();
    while !buf.is_empty() {
        if buf.len() < 2 {
            return Err(WireError::Truncated);
        }
        let set = buf[0] == AS_SET;
        let count = buf[1] as usize;
        let asn_len = if wide { 4 } else { 2 };
        if buf.len() < 2 + count * asn_len {
            return Err(WireError::Truncated);
        }
        let mut asns = Vec::with_capacity(count);
        for c in buf[2..2 + count * asn_len].chunks_exact(asn_len) {
            let asn = if wide {
                u32::from_be_bytes([c[0], c[1], c[2], c[3]])
            } else {
                u16::from_be_bytes([c[0], c[1]]) as u32
            };
            asns.push(asn);
        }
        segs.push(Segment { set, asns });
        buf = &buf[2 + count * asn_len..];
    }
    Ok(segs)
}

fn decode_mp_reach(v: &[u8]) -> Result<PathAttr, WireError> {
    if v.len() < 3 {
        return Err(WireError::Truncated);
    }
    let afi = u16::from_be_bytes([v[0], v[1]]);
    let safi = v[2];
    let v4 = afi == AFI_IPV4;
    if v.len() < 4 {
        return Err(WireError::Truncated);
    }
    let nh_len = v[3] as usize;
    if v.len() < 4 + nh_len + 1 {
        return Err(WireError::Truncated);
    }
    let nh_bytes = &v[4..4 + nh_len];
    let next_hop = decode_next_hop(nh_bytes)?;
    let nlri = read_nlris(&v[5 + nh_len..], v4)?;
    Ok(PathAttr::MpReach {
        afi,
        safi,
        next_hop,
        nlri,
    })
}

fn decode_mp_unreach(v: &[u8]) -> Result<PathAttr, WireError> {
    if v.len() < 3 {
        return Err(WireError::Truncated);
    }
    let afi = u16::from_be_bytes([v[0], v[1]]);
    let safi = v[2];
    let nlri = read_nlris(&v[3..], afi == AFI_IPV4)?;
    Ok(PathAttr::MpUnreach { afi, safi, nlri })
}

/// NEXT_HOP：v4 4B；v6 16B 或 32B（global + link-local，取 global，RFC 4760 §3）；
/// v6 内嵌 IPv4-mapped（::ffff:a.b.c.d，FRR 对 v4 NLRI 的常见编码）归一为 v4
fn decode_next_hop(bytes: &[u8]) -> Result<IpAddr, WireError> {
    match bytes.len() {
        4 => Ok(IpAddr::V4(Ipv4Addr::new(
            bytes[0], bytes[1], bytes[2], bytes[3],
        ))),
        16 | 32 => {
            let mut bits = [0u8; 16];
            bits.copy_from_slice(&bytes[..16]);
            if bits[..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff] {
                return Ok(IpAddr::V4(Ipv4Addr::new(
                    bits[12], bits[13], bits[14], bits[15],
                )));
            }
            Ok(IpAddr::V6(std::net::Ipv6Addr::from(bits)))
        }
        _ => Err(WireError::BadUpdate),
    }
}

fn read_nlris(mut buf: &[u8], v4: bool) -> Result<Vec<Prefix>, WireError> {
    let mut out = Vec::new();
    while !buf.is_empty() {
        let bits = buf[0];
        let max = if v4 { 32 } else { 128 };
        if bits as usize > max {
            return Err(WireError::BadUpdate);
        }
        let octets = bits as usize / 8 + usize::from(!bits.is_multiple_of(8));
        if buf.len() < 1 + octets {
            return Err(WireError::Truncated);
        }
        let mut pbits = [0u8; 16];
        pbits[..octets].copy_from_slice(&buf[1..1 + octets]);
        // 尾部位归零（存储即规范形态，与 ROUTE_ENGINE §9 一致）
        if octets * 8 > bits as usize {
            let rem = bits as usize % 8;
            pbits[octets - 1] &= 0xffu8 << (8 - rem);
        }
        out.push(Prefix {
            bits: pbits,
            len: bits,
            v4,
        });
        buf = &buf[1 + octets..];
    }
    Ok(out)
}

fn write_nlri(out: &mut Vec<u8>, p: &Prefix) {
    out.push(p.len);
    let octets = p.len as usize / 8 + usize::from(!p.len.is_multiple_of(8));
    let n = if p.v4 { 4 } else { 16 };
    out.extend_from_slice(&p.bits[..octets.min(n)]);
}

fn write_attr(out: &mut Vec<u8>, attr: &PathAttr) -> Result<(), WireError> {
    let mut value = Vec::new();
    let (ty, optional) = match attr {
        PathAttr::Origin(o) => {
            value.push(*o);
            (1, false)
        }
        PathAttr::AsPath(segs) => {
            // 4B-capable 会话（FSM capability 门禁）用 4 字节编码，无 AS_TRANS 占位
            write_segments(&mut value, segs, true);
            (2, false)
        }
        PathAttr::As4Path(segs) => {
            write_segments(&mut value, segs, true);
            (17, true)
        }
        PathAttr::NextHop(ip) => {
            value.extend_from_slice(&ip.octets());
            (3, false)
        }
        PathAttr::Communities(cs) => {
            for c in cs {
                value.extend_from_slice(&c.to_be_bytes());
            }
            (8, true)
        }
        PathAttr::MpReach {
            afi,
            safi,
            next_hop,
            nlri,
        } => {
            value.extend_from_slice(&afi.to_be_bytes());
            value.push(*safi);
            match *next_hop {
                IpAddr::V4(ip) => {
                    value.push(4);
                    value.extend_from_slice(&ip.octets());
                }
                IpAddr::V6(ip) => {
                    value.push(16);
                    value.extend_from_slice(&ip.octets());
                }
            }
            value.push(0);
            for p in nlri {
                if p.v4 {
                    return Err(WireError::BadUpdate);
                }
                write_nlri(&mut value, p);
            }
            (14, true)
        }
        PathAttr::MpUnreach { afi, safi, nlri } => {
            value.extend_from_slice(&afi.to_be_bytes());
            value.push(*safi);
            for p in nlri {
                if p.v4 {
                    return Err(WireError::BadUpdate);
                }
                write_nlri(&mut value, p);
            }
            (15, true)
        }
    };
    // AS4_PATH 需 optional transitive（RFC 6793 §2；非 transitive 按畸形处理）
    let flags = if matches!(attr, PathAttr::As4Path(_)) {
        0xC0
    } else if optional {
        0x80
    } else {
        0x40
    };
    if value.len() > 255 {
        out.extend_from_slice(&[flags | 0x10, ty]);
        out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    } else {
        out.extend_from_slice(&[flags, ty, value.len() as u8]);
    }
    out.extend_from_slice(&value);
    Ok(())
}

fn write_segments(out: &mut Vec<u8>, segs: &[Segment], wide: bool) {
    for seg in segs {
        out.push(if seg.set { AS_SET } else { AS_SEQUENCE });
        out.push(seg.asns.len() as u8);
        for asn in &seg.asns {
            if wide {
                out.extend_from_slice(&asn.to_be_bytes());
            } else if *asn > u16::MAX as u32 {
                out.extend_from_slice(&AS_TRANS.to_be_bytes());
            } else {
                out.extend_from_slice(&(*asn as u16).to_be_bytes());
            }
        }
    }
}
