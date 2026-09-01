use crate::crypto::{self, AeadError};

pub const HEADER_LEN: usize = 34;
pub const HEADER_LEN_V2: usize = 42;
pub const TAG_LEN: usize = 16;
/// v1 帧头协议版本（34B，隐式 path_id=0）
pub const VERSION: u8 = 0x01;
/// v2 帧头协议版本（42B，固定 8B path_id，FRAME_HEADER §9 / CONTROL_PLANE §3.11）
pub const VERSION2: u8 = 0x02;
pub const NODE_ID_LEN: usize = 4;
pub const ROUTE_MAC_LEN: usize = 16;
pub const PATH_ID_LEN: usize = 8;
/// v1 认证输入：帧头[0..18]（ttl 置零）
pub const AUTH_INPUT_LEN: usize = 18;
/// v2 认证输入：帧头[0..18]（ttl 置零）|| path_id（8B）
pub const AUTH_INPUT_LEN_V2: usize = 26;
/// v2 route_mac 起始偏移（path_id 之后）
pub const ROUTE_MAC_OFFSET_V2: usize = 26;

pub const BROADCAST_NODE_ID: u32 = 0xFFFF_FFFF;

/// path_id = 0 = 默认路径 = 现有 key_dst 语义（v1 兼容回退）
pub const PATH_ID_DEFAULT: u64 = 0;

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
    /// v2 帧头字段（8B）；v1 帧头恒为 0（隐式默认路径）
    pub path_id: u64,
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
            path_id: PATH_ID_DEFAULT,
            route_mac: [0u8; ROUTE_MAC_LEN],
        }
    }
}

/// 帧头总长（按版本：v1 = 34B，v2 = 42B）
pub fn header_len(version: u8) -> usize {
    if version == VERSION2 {
        HEADER_LEN_V2
    } else {
        HEADER_LEN
    }
}

impl MeshFrameHeader {
    pub fn encode(&self, out: &mut [u8]) {
        assert!(out.len() >= header_len(self.version));
        out[0] = self.version;
        out[1] = self.packet_type;
        out[2] = self.flags;
        out[3] = self.ttl;
        out[4..8].copy_from_slice(&self.to_node_id.to_be_bytes());
        out[8..12].copy_from_slice(&self.from_node_id.to_be_bytes());
        out[12..16].copy_from_slice(&self.seq.to_be_bytes());
        out[16..18].copy_from_slice(&self.len.to_be_bytes());
        if self.version == VERSION2 {
            out[18..26].copy_from_slice(&self.path_id.to_be_bytes());
            out[26..42].copy_from_slice(&self.route_mac);
        } else {
            out[18..34].copy_from_slice(&self.route_mac);
        }
    }

    pub fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        if buf.is_empty() {
            return Err(DecodeError::Truncated);
        }
        let version = buf[0];
        let hlen = header_len(version);
        if buf.len() < hlen {
            return Err(DecodeError::Truncated);
        }
        let to_node_id = u32::from_be_bytes(buf[4..8].try_into().unwrap());
        let from_node_id = u32::from_be_bytes(buf[8..12].try_into().unwrap());
        let seq = u32::from_be_bytes(buf[12..16].try_into().unwrap());
        let len = u16::from_be_bytes(buf[16..18].try_into().unwrap());
        let (path_id, route_mac) = if version == VERSION2 {
            let path_id = u64::from_be_bytes(buf[18..26].try_into().unwrap());
            let mut rm = [0u8; ROUTE_MAC_LEN];
            rm.copy_from_slice(&buf[26..42]);
            (path_id, rm)
        } else {
            let mut rm = [0u8; ROUTE_MAC_LEN];
            rm.copy_from_slice(&buf[18..34]);
            (PATH_ID_DEFAULT, rm)
        };
        Ok(Self {
            version,
            packet_type: buf[1],
            flags: buf[2],
            ttl: buf[3],
            to_node_id,
            from_node_id,
            seq,
            len,
            path_id,
            route_mac,
        })
    }

    /// 认证输入：帧头[0..18]（ttl 置零）|| path_id（v2 才含）。返回 (字节, 长度)。
    /// route_mac 与 AEAD AAD 共用（FRAME_HEADER §2.2/§3.1）。
    pub fn auth_input(&self) -> ([u8; AUTH_INPUT_LEN_V2], usize) {
        let mut out = [0u8; AUTH_INPUT_LEN_V2];
        out[0] = self.version;
        out[1] = self.packet_type;
        out[2] = self.flags;
        out[3] = 0;
        out[4..8].copy_from_slice(&self.to_node_id.to_be_bytes());
        out[8..12].copy_from_slice(&self.from_node_id.to_be_bytes());
        out[12..16].copy_from_slice(&self.seq.to_be_bytes());
        out[16..18].copy_from_slice(&self.len.to_be_bytes());
        if self.version == VERSION2 {
            out[18..26].copy_from_slice(&self.path_id.to_be_bytes());
            (out, AUTH_INPUT_LEN_V2)
        } else {
            (out, AUTH_INPUT_LEN)
        }
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
    let (ai, ai_len) = h.auth_input();
    h.route_mac = crypto::route_mac(key_dst, &ai[..ai_len]);
    let ciphertext = crypto::seal(session_key, salt, h.seq as u64, &ai[..ai_len], payload)?;
    let hlen = header_len(h.version);
    let mut out = vec![0u8; hlen + ciphertext.len()];
    h.encode(&mut out);
    out[hlen..].copy_from_slice(&ciphertext);
    Ok(out)
}

/// 握手帧构建（无 AEAD，FRAME_HEADER §2.4）：len = 载荷长度（无 TAG）。
/// 握手帧恒为 v1 帧头 + key_dst（路径是已建会话后的数据面概念）。
pub fn build_handshake_frame(header: &MeshFrameHeader, key_dst: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut h = header.clone();
    h.version = VERSION;
    h.path_id = PATH_ID_DEFAULT;
    h.packet_type = packet_type::HANDSHAKE;
    h.len = payload.len() as u16;
    let (ai, ai_len) = h.auth_input();
    h.route_mac = crypto::route_mac(key_dst, &ai[..ai_len]);
    let mut out = vec![0u8; HEADER_LEN + payload.len()];
    h.encode(&mut out);
    out[HEADER_LEN..].copy_from_slice(payload);
    out
}

/// 提取帧载荷（按帧头 len 截取，含长度校验；数据帧 len 含 TAG）
pub fn frame_payload(frame: &[u8]) -> Option<&[u8]> {
    if frame.is_empty() {
        return None;
    }
    let hlen = header_len(frame[0]);
    if frame.len() < hlen {
        return None;
    }
    let len = u16::from_be_bytes(frame[16..18].try_into().unwrap()) as usize;
    if frame.len() < hlen + len {
        return None;
    }
    Some(&frame[hlen..hlen + len])
}

pub fn open_frame(
    frame: &[u8],
    key_dst: &[u8],
    session_key: &[u8; 32],
    salt: u32,
) -> Result<(MeshFrameHeader, Vec<u8>), OpenError> {
    if frame.is_empty() {
        return Err(OpenError::Decode(DecodeError::Truncated));
    }
    let header = MeshFrameHeader::decode(frame).map_err(OpenError::Decode)?;
    if header.version != VERSION && header.version != VERSION2 {
        return Err(OpenError::Version);
    }
    let (ai, ai_len) = header.auth_input();
    if crypto::route_mac(key_dst, &ai[..ai_len]) != header.route_mac {
        return Err(OpenError::RouteMac);
    }
    let hlen = header_len(header.version);
    let expected = hlen + header.len as usize;
    if frame.len() < expected {
        return Err(OpenError::TruncatedPayload);
    }
    let payload = crypto::open(
        session_key,
        salt,
        header.seq as u64,
        &ai[..ai_len],
        &frame[hlen..expected],
    )
    .map_err(OpenError::Aead)?;
    Ok((header, payload))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, landscape_rill_macro::ErrorId)]
#[error_id(crate_path = "crate")]
pub enum DecodeError {
    #[error("truncated frame")]
    #[error_id("frame.decode.truncated")]
    Truncated,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error, landscape_rill_macro::ErrorId)]
#[error_id(crate_path = "crate")]
pub enum OpenError {
    #[error("frame decode error: {0}")]
    #[error_id("frame.open.decode")]
    Decode(DecodeError),
    #[error("unsupported frame version")]
    #[error_id("frame.open.version")]
    Version,
    #[error("route mac mismatch")]
    #[error_id("frame.open.route_mac")]
    RouteMac,
    #[error("truncated payload")]
    #[error_id("frame.open.truncated_payload")]
    TruncatedPayload,
    #[error("aead error")]
    #[error_id("frame.open.aead")]
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
    const KEY_PATH: [u8; 32] = [0x55; 32];
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

    fn sample_v2_header() -> MeshFrameHeader {
        MeshFrameHeader {
            version: VERSION2,
            to_node_id: 0x0000_0002,
            from_node_id: 0x0000_0001,
            seq: 7,
            path_id: 0x1234_5678_9abc_def0,
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
    fn header_v2_roundtrip() {
        let h = sample_v2_header();
        let mut buf = [0u8; HEADER_LEN_V2];
        h.encode(&mut buf);
        let d = MeshFrameHeader::decode(&buf).unwrap();
        assert_eq!(h, d);
        assert_eq!(d.path_id, 0x1234_5678_9abc_def0);
        // 字段偏移校验：path_id 在 18..26，route_mac 在 26..42
        assert_eq!(&buf[18..26], &0x1234_5678_9abc_def0u64.to_be_bytes());
    }

    #[test]
    fn header_v1_decode_in_v2_buffer_rejected() {
        let h = sample_v2_header();
        let mut buf = [0u8; HEADER_LEN_V2];
        h.encode(&mut buf);
        // 只给 34B：按 v2 版本号应截断
        assert_eq!(
            MeshFrameHeader::decode(&buf[..HEADER_LEN]),
            Err(DecodeError::Truncated)
        );
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
        assert_eq!(frame.len(), HEADER_LEN + payload.len() + TAG_LEN);
    }

    #[test]
    fn frame_v2_roundtrip_with_key_path() {
        let payload = b"hello path";
        let frame = build_frame(&sample_v2_header(), &KEY_PATH, &SESSION, SALT, payload).unwrap();
        assert_eq!(frame.len(), HEADER_LEN_V2 + payload.len() + TAG_LEN);
        // path_id=0 回退 key_dst 也能解（默认路径语义）
        let (h, out) = open_frame(&frame, &KEY_PATH, &SESSION, SALT).unwrap();
        assert_eq!(h.path_id, 0x1234_5678_9abc_def0);
        assert_eq!(out, payload);
        // key_path 错误 → RouteMac 拒绝
        assert_eq!(
            open_frame(&frame, &KEY_DST, &SESSION, SALT).unwrap_err(),
            OpenError::RouteMac
        );
    }

    #[test]
    fn frame_v2_path_id_zero_falls_back_to_key_dst() {
        // v2 帧头 path_id=0 = 默认路径 = key_dst 语义（CONTROL_PLANE §3.11）
        let mut h = sample_v2_header();
        h.path_id = PATH_ID_DEFAULT;
        let payload = b"default path";
        let frame = build_frame(&h, &KEY_DST, &SESSION, SALT, payload).unwrap();
        let (out_h, out) = open_frame(&frame, &KEY_DST, &SESSION, SALT).unwrap();
        assert_eq!(out_h.path_id, 0);
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
    fn route_mac_v2_rejects_path_id_tamper() {
        let payload = b"payload";
        let frame = build_frame(&sample_v2_header(), &KEY_PATH, &SESSION, SALT, payload).unwrap();
        let mut frame = frame;
        frame[18] ^= 0x01; // 篡改 path_id
        assert_eq!(
            open_frame(&frame, &KEY_PATH, &SESSION, SALT).unwrap_err(),
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
        // v2 同样
        let f2 = build_frame(&sample_v2_header(), &KEY_PATH, &SESSION, SALT, payload).unwrap();
        let mut f2 = f2;
        f2[3] = 0x01;
        assert!(open_frame(&f2, &KEY_PATH, &SESSION, SALT).is_ok());
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
        frame[0] = 0x03;
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
    fn key_path_derivation() {
        let k1 = crypto::derive_key_path(&[0x42; 32], 7, 1);
        let k2 = crypto::derive_key_path(&[0x42; 32], 7, 2);
        let k3 = crypto::derive_key_path(&[0x42; 32], 8, 1);
        assert_eq!(k1, crypto::derive_key_path(&[0x42; 32], 7, 1));
        assert_ne!(k1, k2);
        assert_ne!(k1, k3);
        assert_ne!(k1, crypto::derive_key_dst(&[0x42; 32], 5));
    }

    #[test]
    fn route_mac_deterministic_and_distinct() {
        let (ai, len) = sample_header().auth_input();
        let mac = crypto::route_mac(&KEY_DST, &ai[..len]);
        assert_eq!(mac.len(), ROUTE_MAC_LEN);
        assert_eq!(crypto::route_mac(&KEY_DST, &ai[..len]), mac);
        let mut tampered = ai;
        tampered[0] ^= 1;
        assert_ne!(crypto::route_mac(&KEY_DST, &tampered[..len]), mac);
        assert_ne!(crypto::route_mac(&[0x55; 32], &ai[..len]), mac);
        // v2 auth_input 含 path_id：26B
        let (ai2, len2) = sample_v2_header().auth_input();
        assert_eq!(len2, AUTH_INPUT_LEN_V2);
        assert_eq!(&ai2[18..26], &sample_v2_header().path_id.to_be_bytes());
    }
}
