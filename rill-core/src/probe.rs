//! probe 小包编解码（CONNECTIVITY §2/§4，独立于 34B 帧）
//!
//! 线格式：`magic(4B) + type(1B) + from_node_id(4B) + to_node_id(4B) + nonce(4B) [+ payload]`
//! - 不走 34B 帧转发路径（会话建立前使用，route_mac 链条不存在）；不经中继转发
//! - PING（请求）无认证（有意设计，§4.3 安全边界可接受）；PONG 回显 nonce 匹配确认
//! - coordinator UDP 回显（STUN 式，§2）：PONG 携带 payload = seen 地址（"ip:port" UTF-8）
//! - node_id = 0 表示 coordinator/未注册身份（节点互探用对方真实 id）
//! - 解析 fail-closed：长度严格校验，非法输入一律丢弃（CN-02）

pub const PROBE_MAGIC: [u8; 4] = *b"LPRB";
/// 固定头长（不含 payload）：magic 4 + type 1 + from 4 + to 4 + nonce 4
pub const PROBE_HEADER_LEN: usize = 17;
/// 响应载荷上限（seen 地址串；超长丢弃）
pub const PROBE_PAYLOAD_MAX: usize = 128;

/// 随机 nonce（PONG 匹配；调用方持 pending 状态）
pub fn random_nonce() -> u32 {
    rand::random::<u32>()
}

pub mod probe_type {
    /// 请求（ping）
    pub const PING: u8 = 0x01;
    /// 响应（pong）
    pub const PONG: u8 = 0x02;
}

/// coordinator 回显请求的 to_node_id 标记（0 = 未注册身份）
pub const NODE_ID_COORDINATOR: u32 = 0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbePacket {
    pub packet_type: u8,
    pub from_node_id: u32,
    pub to_node_id: u32,
    pub nonce: u32,
    /// PONG 回显 seen 地址（"ip:port"）；互探 PONG 为空
    pub payload: Vec<u8>,
}

impl ProbePacket {
    pub fn ping(from: u32, to: u32, nonce: u32) -> Self {
        Self {
            packet_type: probe_type::PING,
            from_node_id: from,
            to_node_id: to,
            nonce,
            payload: Vec::new(),
        }
    }

    pub fn pong(ping: &ProbePacket, payload: Vec<u8>) -> Self {
        Self {
            packet_type: probe_type::PONG,
            from_node_id: ping.to_node_id,
            to_node_id: ping.from_node_id,
            nonce: ping.nonce,
            payload,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PROBE_HEADER_LEN + self.payload.len());
        out.extend_from_slice(&PROBE_MAGIC);
        out.push(self.packet_type);
        out.extend_from_slice(&self.from_node_id.to_be_bytes());
        out.extend_from_slice(&self.to_node_id.to_be_bytes());
        out.extend_from_slice(&self.nonce.to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// 解析（fail-closed）：magic 不匹配 / 长度不足 / 载荷超限 → None
    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < PROBE_HEADER_LEN || buf[..4] != PROBE_MAGIC {
            return None;
        }
        let payload = &buf[PROBE_HEADER_LEN..];
        if payload.len() > PROBE_PAYLOAD_MAX {
            return None;
        }
        Some(Self {
            packet_type: buf[4],
            from_node_id: u32::from_be_bytes(buf[5..9].try_into().ok()?),
            to_node_id: u32::from_be_bytes(buf[9..13].try_into().ok()?),
            nonce: u32::from_be_bytes(buf[13..17].try_into().ok()?),
            payload: payload.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_roundtrip() {
        let p = ProbePacket::ping(7, 9, 0xdead_beef);
        let buf = p.encode();
        assert_eq!(buf.len(), PROBE_HEADER_LEN);
        assert_eq!(ProbePacket::decode(&buf).unwrap(), p);
    }

    #[test]
    fn pong_roundtrip_with_payload() {
        let ping = ProbePacket::ping(7, 0, 42);
        let pong = ProbePacket::pong(&ping, b"203.0.113.5:41641".to_vec());
        let buf = pong.encode();
        assert_eq!(ProbePacket::decode(&buf).unwrap(), pong);
        assert_eq!(
            ProbePacket::decode(&buf).unwrap().payload,
            b"203.0.113.5:41641"
        );
        // pong 回填 from/to（回声地址的发送者）
        assert_eq!(pong.from_node_id, 0);
        assert_eq!(pong.to_node_id, 7);
    }

    #[test]
    fn decode_fail_closed() {
        assert!(ProbePacket::decode(b"").is_none());
        assert!(ProbePacket::decode(b"XXXX").is_none());
        // magic 不匹配（即使够长）
        assert!(ProbePacket::decode(&[0u8; PROBE_HEADER_LEN]).is_none());
        // 长度不足
        let mut buf = ProbePacket::ping(1, 2, 3).encode();
        buf.truncate(PROBE_HEADER_LEN - 1);
        assert!(ProbePacket::decode(&buf).is_none());
        // 载荷超限
        let mut p = ProbePacket::ping(1, 2, 3);
        p.payload = vec![0u8; PROBE_PAYLOAD_MAX + 1];
        assert!(ProbePacket::decode(&p.encode()).is_none());
    }

    #[test]
    fn coordinator_marker() {
        assert_eq!(NODE_ID_COORDINATOR, 0);
        let p = ProbePacket::ping(5, NODE_ID_COORDINATOR, 1);
        let d = ProbePacket::decode(&p.encode()).unwrap();
        assert_eq!(d.to_node_id, 0);
    }
}
