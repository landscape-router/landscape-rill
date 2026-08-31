use crate::crypto::{self, AeadError};

pub const HEADER_LEN: usize = 34;
pub const TAG_LEN: usize = 16;
pub const VERSION: u8 = 0x01;
pub const NODE_ID_LEN: usize = 4;
pub const ROUTE_MAC_LEN: usize = 16;
pub const AUTH_INPUT_LEN: usize = 18;

pub const BROADCAST_NODE_ID: u32 = 0xFFFF_FFFF;

pub mod packet_type {
    pub const UNICAST: u8 = 0x01;
    pub const HANDSHAKE: u8 = 0x02;
    pub const HEARTBEAT: u8 = 0x03;
    pub const CONTROL: u8 = 0x04;
    pub const BROADCAST: u8 = 0xFF;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshFrameHeader {
    pub version: u8,
    pub packet_type: u8,
    pub flags: u8,
    pub ttl: u8,
    pub to_node_id: u32,
    pub from_node_id: u32,
    pub seq: u32,
    pub len: u16,
    pub route_mac: [u8; ROUTE_MAC_LEN],
}

impl Default for MeshFrameHeader {
    fn default() -> Self {
        Self {
            version: VERSION,
            packet_type: packet_type::UNICAST,
            flags: 0,
            ttl: 64,
            to_node_id: 0,
            from_node_id: 0,
            seq: 0,
            len: 0,
            route_mac: [0u8; ROUTE_MAC_LEN],
        }
    }
}

impl MeshFrameHeader {
    pub fn encode(&self, out: &mut [u8]) {
        assert!(out.len() >= HEADER_LEN);
        out[0] = self.version;
        out[1] = self.packet_type;
        out[2] = self.flags;
        out[3] = self.ttl;
        out[4..8].copy_from_slice(&self.to_node_id.to_be_bytes());
        out[8..12].copy_from_slice(&self.from_node_id.to_be_bytes());
        out[12..16].copy_from_slice(&self.seq.to_be_bytes());
        out[16..18].copy_from_slice(&self.len.to_be_bytes());
        out[18..34].copy_from_slice(&self.route_mac);
    }

    pub fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        if buf.len() < HEADER_LEN {
            return Err(DecodeError::Truncated);
        }
        let to_node_id = u32::from_be_bytes(buf[4..8].try_into().unwrap());
        let from_node_id = u32::from_be_bytes(buf[8..12].try_into().unwrap());
        let seq = u32::from_be_bytes(buf[12..16].try_into().unwrap());
        let len = u16::from_be_bytes(buf[16..18].try_into().unwrap());
        let mut route_mac = [0u8; ROUTE_MAC_LEN];
        route_mac.copy_from_slice(&buf[18..34]);
        Ok(Self {
            version: buf[0],
            packet_type: buf[1],
            flags: buf[2],
            ttl: buf[3],
            to_node_id,
            from_node_id,
            seq,
            len,
            route_mac,
        })
    }

    pub fn auth_input(&self) -> [u8; AUTH_INPUT_LEN] {
        let mut out = [0u8; AUTH_INPUT_LEN];
        out[0] = self.version;
        out[1] = self.packet_type;
        out[2] = self.flags;
        out[3] = 0;
        out[4..8].copy_from_slice(&self.to_node_id.to_be_bytes());
        out[8..12].copy_from_slice(&self.from_node_id.to_be_bytes());
        out[12..16].copy_from_slice(&self.seq.to_be_bytes());
        out[16..18].copy_from_slice(&self.len.to_be_bytes());
        out
    }
}

pub fn build_frame(
    header: &MeshFrameHeader,
    key_dst: &[u8],
    session_key: &[u8; 32],
    salt: u32,
    payload: &[u8],
) -> Result<Vec<u8>, AeadError> {
    let mut h = header.clone();
    h.len = (payload.len() + TAG_LEN) as u16;
    h.route_mac = crypto::route_mac(key_dst, &h.auth_input());
    let ciphertext = crypto::seal(session_key, salt, h.seq as u64, &h.auth_input(), payload)?;
    let mut out = vec![0u8; HEADER_LEN + ciphertext.len()];
    h.encode(&mut out);
    out[HEADER_LEN..].copy_from_slice(&ciphertext);
    Ok(out)
}

/// 握手帧构建（无 AEAD，FRAME_HEADER §2.4）：len = 载荷长度（无 TAG）。
/// route_mac 与数据帧同路径校验——握手帧不经转发路径认证，转发节点只需按 to_node_id 转发。
pub fn build_handshake_frame(header: &MeshFrameHeader, key_dst: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut h = header.clone();
    h.packet_type = packet_type::HANDSHAKE;
    h.len = payload.len() as u16;
    h.route_mac = crypto::route_mac(key_dst, &h.auth_input());
    let mut out = vec![0u8; HEADER_LEN + payload.len()];
    h.encode(&mut out);
    out[HEADER_LEN..].copy_from_slice(payload);
    out
}

/// 提取帧载荷（按帧头 len 截取，含长度校验；数据帧 len 含 TAG）
pub fn frame_payload(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < HEADER_LEN {
        return None;
    }
    let len = u16::from_be_bytes(frame[16..18].try_into().unwrap()) as usize;
    if frame.len() < HEADER_LEN + len {
        return None;
    }
    Some(&frame[HEADER_LEN..HEADER_LEN + len])
}

pub fn open_frame(
    frame: &[u8],
    key_dst: &[u8],
    session_key: &[u8; 32],
    salt: u32,
) -> Result<(MeshFrameHeader, Vec<u8>), OpenError> {
    if frame.len() < HEADER_LEN {
        return Err(OpenError::Decode(DecodeError::Truncated));
    }
    let header = MeshFrameHeader::decode(frame).map_err(OpenError::Decode)?;
    if header.version != VERSION {
        return Err(OpenError::Version);
    }
    let auth_input = header.auth_input();
    if crypto::route_mac(key_dst, &auth_input) != header.route_mac {
        return Err(OpenError::RouteMac);
    }
    let expected = HEADER_LEN + header.len as usize;
    if frame.len() < expected {
        return Err(OpenError::TruncatedPayload);
    }
    let payload = crypto::open(
        session_key,
        salt,
        header.seq as u64,
        &auth_input,
        &frame[HEADER_LEN..expected],
    )
    .map_err(OpenError::Aead)?;
    Ok((header, payload))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    Truncated,
}

#[derive(Debug, PartialEq, Eq)]
pub enum OpenError {
    Decode(DecodeError),
    Version,
    RouteMac,
    TruncatedPayload,
    Aead(AeadError),
}

pub struct ReplayWindow {
    base: u64,
    bitmap: [u64; 16],
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self {
            base: 0,
            bitmap: [0u64; 16],
        }
    }

    pub fn check_and_mark(&mut self, seq: u32) -> bool {
        let seq = seq as u64;
        if seq < self.base {
            return false;
        }
        if seq >= self.base + 1024 {
            let advance = (seq - self.base + 1) - 1024;
            self.base += advance;
            self.bitmap = [0u64; 16];
        }
        let slot = (seq - self.base) as usize;
        let word = slot / 64;
        let bit = 1u64 << (slot % 64);
        if self.bitmap[word] & bit != 0 {
            return false;
        }
        self.bitmap[word] |= bit;
        true
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;

    const KEY_DST: [u8; 32] = [0x11; 32];
    const SESSION: [u8; 32] = [0x22; 32];
    const SALT: u32 = 0xdead_beef;

    fn sample_header() -> MeshFrameHeader {
        MeshFrameHeader {
            to_node_id: 0x0000_0002,
            from_node_id: 0x0000_0001,
            seq: 7,
            ..Default::default()
        }
    }

    #[test]
    fn header_roundtrip() {
        let h = sample_header();
        let mut buf = [0u8; HEADER_LEN];
        h.encode(&mut buf);
        let d = MeshFrameHeader::decode(&buf).unwrap();
        assert_eq!(h, d);
    }

    #[test]
    fn header_decode_truncated() {
        let h = sample_header();
        let mut buf = [0u8; HEADER_LEN];
        h.encode(&mut buf);
        for cut in 0..HEADER_LEN {
            assert_eq!(
                MeshFrameHeader::decode(&buf[..cut]),
                Err(DecodeError::Truncated)
            );
        }
    }

    #[test]
    fn frame_roundtrip() {
        let payload = b"hello mesh";
        let frame = build_frame(&sample_header(), &KEY_DST, &SESSION, SALT, payload).unwrap();
        let (h, out) = open_frame(&frame, &KEY_DST, &SESSION, SALT).unwrap();
        assert_eq!(h.to_node_id, 2);
        assert_eq!(h.len as usize, payload.len() + TAG_LEN);
        assert_eq!(out, payload);
    }

    #[test]
    fn route_mac_rejects_tamper() {
        let payload = b"payload";
        let mut frame = build_frame(&sample_header(), &KEY_DST, &SESSION, SALT, payload).unwrap();
        frame[8] ^= 0x01;
        assert_eq!(
            open_frame(&frame, &KEY_DST, &SESSION, SALT).unwrap_err(),
            OpenError::RouteMac
        );
    }

    #[test]
    fn ttl_change_still_valid() {
        let payload = b"payload";
        let frame = build_frame(&sample_header(), &KEY_DST, &SESSION, SALT, payload).unwrap();
        let mut frame = frame;
        frame[3] = 0x7f;
        assert!(open_frame(&frame, &KEY_DST, &SESSION, SALT).is_ok());
    }

    #[test]
    fn aead_rejects_payload_tamper() {
        let payload = b"payload";
        let frame = build_frame(&sample_header(), &KEY_DST, &SESSION, SALT, payload).unwrap();
        let mut frame = frame;
        let n = frame.len();
        frame[n - 1] ^= 0xff;
        assert!(open_frame(&frame, &KEY_DST, &SESSION, SALT).is_err());
    }

    #[test]
    fn aead_rejects_wrong_session_key() {
        let payload = b"payload";
        let frame = build_frame(&sample_header(), &KEY_DST, &SESSION, SALT, payload).unwrap();
        let wrong = [0x33; 32];
        assert!(open_frame(&frame, &KEY_DST, &wrong, SALT).is_err());
    }

    #[test]
    fn aead_rejects_wrong_salt() {
        let payload = b"payload";
        let frame = build_frame(&sample_header(), &KEY_DST, &SESSION, SALT, payload).unwrap();
        assert!(open_frame(&frame, &KEY_DST, &SESSION, SALT ^ 1).is_err());
    }

    #[test]
    fn frame_truncated_payload_rejected() {
        let payload = b"payload";
        let frame = build_frame(&sample_header(), &KEY_DST, &SESSION, SALT, payload).unwrap();
        assert_eq!(
            open_frame(&frame[..HEADER_LEN + 2], &KEY_DST, &SESSION, SALT).unwrap_err(),
            OpenError::TruncatedPayload
        );
    }

    #[test]
    fn version_mismatch_rejected() {
        let payload = b"payload";
        let frame = build_frame(&sample_header(), &KEY_DST, &SESSION, SALT, payload).unwrap();
        let mut frame = frame;
        frame[0] = 0x02;
        assert_eq!(
            open_frame(&frame, &KEY_DST, &SESSION, SALT).unwrap_err(),
            OpenError::Version
        );
    }

    #[test]
    fn replay_window_accepts_new_sequence() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_mark(0));
        assert!(w.check_and_mark(1));
        assert!(w.check_and_mark(1023));
        assert!(!w.check_and_mark(0));
        assert!(!w.check_and_mark(1));
        assert!(w.check_and_mark(1024));
        assert!(w.check_and_mark(2048));
        assert!(!w.check_and_mark(1024));
    }

    #[test]
    fn key_dst_derivation() {
        let a = crypto::derive_key_dst(&[0x42; 32], 5);
        let b = crypto::derive_key_dst(&[0x42; 32], 6);
        let c = crypto::derive_key_dst(&[0x42; 32], 5);
        assert_eq!(a, c);
        assert_ne!(a, b);
        assert_ne!(crypto::derive_key_dst(&[0x43; 32], 5), a);
    }

    #[test]
    fn route_mac_deterministic_and_distinct() {
        let ai = sample_header().auth_input();
        let mac = crypto::route_mac(&KEY_DST, &ai);
        assert_eq!(mac.len(), ROUTE_MAC_LEN);
        assert_eq!(crypto::route_mac(&KEY_DST, &ai), mac);
        let mut tampered = ai;
        tampered[0] ^= 1;
        assert_ne!(crypto::route_mac(&KEY_DST, &tampered), mac);
        assert_ne!(crypto::route_mac(&[0x55; 32], &ai), mac);
    }
}
