pub mod error;
pub use error::{DecodeError, OpenError};

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

/// 帧头字段偏移（FRAME_HEADER §2）。encode/decode/auth_input/frame_payload/
/// 转发 TTL 递减共用，golden vectors 逐字节钉死绝对布局。
pub mod off {
    pub const VERSION: usize = 0;
    pub const PACKET_TYPE: usize = 1;
    pub const FLAGS: usize = 2;
    pub const TTL: usize = 3;
    pub const TO_NODE: usize = 4;
    pub const FROM_NODE: usize = 8;
    pub const SEQ: usize = 12;
    pub const LEN: usize = 16;
    /// v2 专属：path_id 起始（v1 此处是 route_mac）
    pub const PATH_ID_V2: usize = 18;
    pub const ROUTE_MAC_V1: usize = 18;
    pub const ROUTE_MAC_V2: usize = 26;
}

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
        out[off::VERSION] = self.version;
        out[off::PACKET_TYPE] = self.packet_type;
        out[off::FLAGS] = self.flags;
        out[off::TTL] = self.ttl;
        out[off::TO_NODE..off::FROM_NODE].copy_from_slice(&self.to_node_id.to_be_bytes());
        out[off::FROM_NODE..off::SEQ].copy_from_slice(&self.from_node_id.to_be_bytes());
        out[off::SEQ..off::LEN].copy_from_slice(&self.seq.to_be_bytes());
        out[off::LEN..off::PATH_ID_V2].copy_from_slice(&self.len.to_be_bytes());
        if self.version == VERSION2 {
            out[off::PATH_ID_V2..off::ROUTE_MAC_V2].copy_from_slice(&self.path_id.to_be_bytes());
            out[off::ROUTE_MAC_V2..HEADER_LEN_V2].copy_from_slice(&self.route_mac);
        } else {
            out[off::ROUTE_MAC_V1..HEADER_LEN].copy_from_slice(&self.route_mac);
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
        let to_node_id = u32::from_be_bytes(buf[off::TO_NODE..off::FROM_NODE].try_into().unwrap());
        let from_node_id = u32::from_be_bytes(buf[off::FROM_NODE..off::SEQ].try_into().unwrap());
        let seq = u32::from_be_bytes(buf[off::SEQ..off::LEN].try_into().unwrap());
        let len = u16::from_be_bytes(buf[off::LEN..off::PATH_ID_V2].try_into().unwrap());
        let (path_id, route_mac) = if version == VERSION2 {
            let path_id =
                u64::from_be_bytes(buf[off::PATH_ID_V2..off::ROUTE_MAC_V2].try_into().unwrap());
            let mut rm = [0u8; ROUTE_MAC_LEN];
            rm.copy_from_slice(&buf[off::ROUTE_MAC_V2..HEADER_LEN_V2]);
            (path_id, rm)
        } else {
            let mut rm = [0u8; ROUTE_MAC_LEN];
            rm.copy_from_slice(&buf[off::ROUTE_MAC_V1..HEADER_LEN]);
            (PATH_ID_DEFAULT, rm)
        };
        Ok(Self {
            version,
            packet_type: buf[off::PACKET_TYPE],
            flags: buf[off::FLAGS],
            ttl: buf[off::TTL],
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
        out[off::VERSION] = self.version;
        out[off::PACKET_TYPE] = self.packet_type;
        out[off::FLAGS] = self.flags;
        out[off::TTL] = 0;
        out[off::TO_NODE..off::FROM_NODE].copy_from_slice(&self.to_node_id.to_be_bytes());
        out[off::FROM_NODE..off::SEQ].copy_from_slice(&self.from_node_id.to_be_bytes());
        out[off::SEQ..off::LEN].copy_from_slice(&self.seq.to_be_bytes());
        out[off::LEN..off::PATH_ID_V2].copy_from_slice(&self.len.to_be_bytes());
        if self.version == VERSION2 {
            out[off::PATH_ID_V2..off::ROUTE_MAC_V2].copy_from_slice(&self.path_id.to_be_bytes());
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
    let hlen = header_len(h.version);
    // 单缓冲组装（REQ-053）：头+载荷一次分配，载荷拷入后原地加密
    let mut out = vec![0u8; hlen + payload.len() + TAG_LEN];
    h.encode(&mut out);
    out[hlen..hlen + payload.len()].copy_from_slice(payload);
    crypto::seal_in_place(
        session_key,
        salt,
        h.seq as u64,
        &ai[..ai_len],
        &mut out[hlen..],
        payload.len(),
    )?;
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
    let len = u16::from_be_bytes(frame[off::LEN..off::PATH_ID_V2].try_into().unwrap()) as usize;
    if frame.len() < hlen + len {
        return None;
    }
    Some(&frame[hlen..hlen + len])
}

/// 转发路径原地 TTL 递减（FRAME_HEADER §4：ttl 不参与认证，转发不重签 route_mac）。
/// 调用方保证 ttl ≥ 1（wrap 语义与原 `out[3] -= 1` 一致）。
pub fn decrement_ttl(frame: &mut [u8]) {
    if !frame.is_empty() {
        frame[off::TTL] = frame[off::TTL].wrapping_sub(1);
    }
}

/// open_frame / open_frame_in_place 共享的帧校验（REQ-053）：
/// 解码帧头 + 版本/route_mac/长度校验，返回载荷区间 [hlen, hlen+len)。
fn validate_frame(
    frame: &[u8],
    key_dst: &[u8],
) -> Result<(MeshFrameHeader, usize, usize), OpenError> {
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
    let end = hlen + header.len as usize;
    if frame.len() < end {
        return Err(OpenError::TruncatedPayload);
    }
    Ok((header, hlen, end))
}

/// 原地解密入口（REQ-053）：在 frame 缓冲上直接解密，载荷借用返回（零拷贝）。
pub fn open_frame_in_place<'a>(
    frame: &'a mut [u8],
    key_dst: &[u8],
    session_key: &[u8; 32],
    salt: u32,
) -> Result<(MeshFrameHeader, &'a mut [u8]), OpenError> {
    let (header, hlen, end) = validate_frame(frame, key_dst)?;
    let (ai, ai_len) = header.auth_input();
    let pt_len = crypto::open_in_place(
        session_key,
        salt,
        header.seq as u64,
        &ai[..ai_len],
        &mut frame[hlen..end],
        end - hlen,
    )
    .map_err(OpenError::Aead)?;
    Ok((header, &mut frame[hlen..hlen + pt_len]))
}

pub fn open_frame(
    frame: &[u8],
    key_dst: &[u8],
    session_key: &[u8; 32],
    salt: u32,
) -> Result<(MeshFrameHeader, Vec<u8>), OpenError> {
    let (header, hlen, end) = validate_frame(frame, key_dst)?;
    let (ai, ai_len) = header.auth_input();
    let payload = crypto::open(
        session_key,
        salt,
        header.seq as u64,
        &ai[..ai_len],
        &frame[hlen..end],
    )
    .map_err(OpenError::Aead)?;
    Ok((header, payload))
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

    // ---- golden vectors（FRAME_HEADER §2 绝对布局钉死；对称漂移不可能无声通过）----

    /// 手工按规范推定的期望字节：字段取互异值防偏移互换
    fn golden_header_v1() -> MeshFrameHeader {
        MeshFrameHeader {
            version: VERSION,
            packet_type: 0x03,
            flags: 0xAB,
            ttl: 0x2A,
            to_node_id: 0x1122_3344,
            from_node_id: 0x5566_7788,
            seq: 0x99AA_BBC0,
            len: 0xDDEE,
            path_id: PATH_ID_DEFAULT,
            route_mac: [0xA5; ROUTE_MAC_LEN],
        }
    }

    /// v1 共享前缀 [0..18]（v2 相同，仅 version 字节不同）
    const GOLDEN_PREFIX: [u8; 18] = [
        0x01, 0x03, 0xAB, 0x2A, // version, packet_type, flags, ttl
        0x11, 0x22, 0x33, 0x44, // to_node_id
        0x55, 0x66, 0x77, 0x88, // from_node_id
        0x99, 0xAA, 0xBB, 0xC0, // seq
        0xDD, 0xEE, // len
    ];

    #[test]
    fn golden_v1_header_bytes() {
        let h = golden_header_v1();
        let mut buf = [0u8; HEADER_LEN];
        h.encode(&mut buf);
        assert_eq!(&buf[..18], &GOLDEN_PREFIX);
        assert_eq!(&buf[18..34], &[0xA5; ROUTE_MAC_LEN]);
        assert_eq!(buf.len(), 34);
        // decode 还原
        let d = MeshFrameHeader::decode(&buf).unwrap();
        assert_eq!(d, h);
    }

    #[test]
    fn golden_v2_header_bytes() {
        let h = MeshFrameHeader {
            version: VERSION2,
            path_id: 0x1234_5678_9ABC_DEF0,
            route_mac: [0x5A; ROUTE_MAC_LEN],
            ..golden_header_v1()
        };
        let mut buf = [0u8; HEADER_LEN_V2];
        h.encode(&mut buf);
        let mut prefix = GOLDEN_PREFIX;
        prefix[0] = 0x02;
        assert_eq!(&buf[..18], &prefix);
        assert_eq!(&buf[18..26], &0x1234_5678_9ABC_DEF0u64.to_be_bytes());
        assert_eq!(&buf[26..42], &[0x5A; ROUTE_MAC_LEN]);
        assert_eq!(buf.len(), 42);
        assert_eq!(MeshFrameHeader::decode(&buf).unwrap(), h);
    }

    #[test]
    fn golden_auth_input_bytes() {
        // auth_input = 帧头 [0..18]（ttl 置零）|| path_id（v2），route_mac 不参与
        let h = golden_header_v1();
        let (ai, len) = h.auth_input();
        assert_eq!(len, AUTH_INPUT_LEN);
        let mut expect = GOLDEN_PREFIX;
        expect[3] = 0;
        assert_eq!(&ai[..len], &expect);

        let h2 = MeshFrameHeader {
            version: VERSION2,
            path_id: 0x1234_5678_9ABC_DEF0,
            ..golden_header_v1()
        };
        let (ai2, len2) = h2.auth_input();
        assert_eq!(len2, AUTH_INPUT_LEN_V2);
        let mut expect2 = [0u8; AUTH_INPUT_LEN_V2];
        expect2[..18].copy_from_slice(&expect);
        expect2[0] = 0x02;
        expect2[18..26].copy_from_slice(&0x1234_5678_9ABC_DEF0u64.to_be_bytes());
        assert_eq!(&ai2[..len2], &expect2);
    }

    #[test]
    fn golden_len_offset_in_frame_payload() {
        // frame_payload 从 off::LEN(16..18) 取长度：len=0xDDEE 的帧载荷不足应拒绝
        let h = golden_header_v1();
        let mut buf = [0u8; HEADER_LEN + 4];
        h.encode(&mut buf);
        assert_eq!(frame_payload(&buf), None);
        buf[16..18].copy_from_slice(&4u16.to_be_bytes());
        assert_eq!(frame_payload(&buf), Some(&buf[34..38][..]));
    }

    #[test]
    fn decrement_ttl_wraps_and_ignores_empty() {
        let mut frame = [0x01u8, 0x03, 0xAB, 0x2A];
        decrement_ttl(&mut frame);
        assert_eq!(frame[3], 0x29);
        let mut empty: [u8; 0] = [];
        decrement_ttl(&mut empty);
    }

    // ---- crypto in-place 对拍与帧级零拷贝入口（REQ-053）----

    #[test]
    fn seal_in_place_parity_with_vec_api() {
        let pt = b"parity payload";
        let ct_vec = crypto::seal(&SESSION, SALT, 42, b"aad", pt).unwrap();
        let mut buf = vec![0u8; pt.len() + crypto::TAG_LEN + 8];
        buf[..pt.len()].copy_from_slice(pt);
        let n = crypto::seal_in_place(&SESSION, SALT, 42, b"aad", &mut buf, pt.len()).unwrap();
        assert_eq!(n, ct_vec.len());
        assert_eq!(&buf[..n], &ct_vec[..]);
        // 缓冲不足 → 错误而非 panic
        let mut tight = vec![0u8; pt.len() + crypto::TAG_LEN];
        assert!(
            crypto::seal_in_place(&SESSION, SALT, 42, b"aad", &mut tight, pt.len() + 1).is_err()
        );
    }

    #[test]
    fn open_in_place_parity_with_vec_api() {
        let pt = b"parity payload";
        let ct = crypto::seal(&SESSION, SALT, 7, b"aad", pt).unwrap();
        let mut buf = ct.clone();
        let n = crypto::open_in_place(&SESSION, SALT, 7, b"aad", &mut buf, ct.len()).unwrap();
        assert_eq!(n, pt.len());
        assert_eq!(&buf[..n], &pt[..]);
        assert_eq!(crypto::open(&SESSION, SALT, 7, b"aad", &ct).unwrap(), pt);
        // 篡改 → 拒绝
        let mut bad = ct.clone();
        let ct_len = bad.len();
        bad[ct_len - 1] ^= 0xff;
        assert!(crypto::open_in_place(&SESSION, SALT, 7, b"aad", &mut bad, ct_len).is_err());
    }

    #[test]
    fn open_frame_in_place_parity_with_open_frame() {
        let payload = b"in-place hello";
        let frame = build_frame(&sample_header(), &KEY_DST, &SESSION, SALT, payload).unwrap();
        let (h, pt) = open_frame(&frame, &KEY_DST, &SESSION, SALT).unwrap();
        let mut buf = frame.clone();
        let (h2, pt2) = open_frame_in_place(&mut buf, &KEY_DST, &SESSION, SALT).unwrap();
        assert_eq!(h, h2);
        assert_eq!(pt, pt2);
        assert_eq!(pt2, payload);
        // v2 同样
        let f2 = build_frame(&sample_v2_header(), &KEY_PATH, &SESSION, SALT, payload).unwrap();
        let mut b2 = f2.clone();
        let (_, p2) = open_frame_in_place(&mut b2, &KEY_PATH, &SESSION, SALT).unwrap();
        assert_eq!(p2, payload);
    }

    #[test]
    fn open_frame_in_place_rejects_bad_key() {
        let payload = b"x";
        let frame = build_frame(&sample_header(), &KEY_DST, &SESSION, SALT, payload).unwrap();
        let mut buf = frame;
        assert_eq!(
            open_frame_in_place(&mut buf, &[0x66; 32], &SESSION, SALT).unwrap_err(),
            OpenError::RouteMac
        );
    }

    // ---- 预认证解析语料（REQ-059 / SEC-08，FRAME_HEADER §5.1）----
    // 随机与变形输入只允许经 Result/Option 返回，任何入口不得 panic

    fn xorshift(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    #[test]
    fn preauth_parse_fuzz_corpus() {
        let mut s: u64 = 0x5EED_0001;
        let mut buf = [0u8; 96];
        for _ in 0..2000 {
            // 家族 A：纯随机字节（任意长度）
            let len = (xorshift(&mut s) % 97) as usize;
            for b in buf[..len].iter_mut() {
                *b = xorshift(&mut s) as u8;
            }
            let _ = MeshFrameHeader::decode(&buf[..len]);
            let _ = frame_payload(&buf[..len]);
            let _ = open_frame(&buf[..len], &KEY_DST, &SESSION, SALT);

            // 家族 B：合法帧变形（1..=8 处字节翻转；翻转 ttl 可能仍通过——合法）
            let mut frame =
                build_frame(&sample_header(), &KEY_DST, &SESSION, SALT, b"payload").unwrap();
            let flips = 1 + (xorshift(&mut s) % 8) as usize;
            for _ in 0..flips {
                let pos = xorshift(&mut s) as usize % frame.len();
                frame[pos] ^= (xorshift(&mut s) as u8) | 1;
            }
            let _ = open_frame(&frame, &KEY_DST, &SESSION, SALT);
        }

        // 家族 C：版本字节全值域 × 截断长度全值域
        let mut hbuf = [0u8; HEADER_LEN_V2];
        sample_v2_header().encode(&mut hbuf);
        for v in 0..=255u8 {
            hbuf[0] = v;
            for cut in 0..=HEADER_LEN_V2 {
                let _ = MeshFrameHeader::decode(&hbuf[..cut]);
            }
        }
    }
}
