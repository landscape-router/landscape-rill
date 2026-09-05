pub mod error;
mod wire;
pub use error::{DecodeError, OpenError};

use crate::crypto::{self, AeadError};

pub const HEADER_LEN: usize = 42;
pub const TAG_LEN: usize = 16;
/// 帧头协议版本（42B，固定 8B path_id；FRAME_HEADER §2.1）
pub const VERSION: u8 = 0x01;
pub const NODE_ID_LEN: usize = 4;
pub const ROUTE_MAC_LEN: usize = 16;
pub const PATH_ID_LEN: usize = 8;
/// 认证输入：帧头[0..18]（ttl 置零）|| path_id（8B）
pub const AUTH_INPUT_LEN: usize = 26;

pub const BROADCAST_NODE_ID: u32 = 0xFFFF_FFFF;

/// path_id = 0 = 默认路径（key_dst 直连语义）
pub const PATH_ID_DEFAULT: u64 = 0;

/// 帧头字段绝对偏移(FRAME_HEADER §2.1)。实现已走 wire::WireHeader 视图
/// (offset_of! 断言与此处互检);本模块仅供 golden 测试钉布局与文档对照。
pub mod off {
    pub const VERSION: usize = 0;
    pub const PACKET_TYPE: usize = 1;
    pub const FLAGS: usize = 2;
    pub const TTL: usize = 3;
    pub const TO_NODE: usize = 4;
    pub const FROM_NODE: usize = 8;
    pub const SEQ: usize = 12;
    pub const LEN: usize = 16;
    pub const PATH_ID: usize = 18;
    pub const ROUTE_MAC: usize = 26;
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
    /// 0 = 默认路径（key_dst）；非 0 = 显式路径（key_path）
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

impl MeshFrameHeader {
    pub fn encode(&self, out: &mut [u8]) {
        assert!(out.len() >= HEADER_LEN);
        wire::WireHeader::from(self).write_into(out);
    }

    /// 解码不校验 version 字节（宽容解析）；版本白名单由 validate_frame/relay 强制
    pub fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self::from(wire::WireHeader::parse(buf)?))
    }

    /// 认证输入：帧头[0..18]（ttl 置零）|| path_id。
    /// route_mac 与 AEAD AAD 共用（FRAME_HEADER §2.2/§3.1）。
    pub fn auth_input(&self) -> [u8; AUTH_INPUT_LEN] {
        wire::WireHeader::from(self).auth_input()
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
    let ai = h.auth_input();
    h.route_mac = crypto::route_mac(key_dst, &ai);
    // 单缓冲组装（REQ-053）：头+载荷一次分配，载荷拷入后原地加密
    let mut out = vec![0u8; HEADER_LEN + payload.len() + TAG_LEN];
    h.encode(&mut out);
    out[HEADER_LEN..HEADER_LEN + payload.len()].copy_from_slice(payload);
    crypto::seal_in_place(
        session_key,
        salt,
        h.seq as u64,
        &ai,
        &mut out[HEADER_LEN..],
        payload.len(),
    )?;
    Ok(out)
}

/// 握手帧构建（无 AEAD，FRAME_HEADER §2.4）：len = 载荷长度（无 TAG）。
/// 默认路径交付（key_dst，path_id=0）——路径是已建会话后的数据面概念。
pub fn build_handshake_frame(header: &MeshFrameHeader, key_dst: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut h = header.clone();
    h.path_id = PATH_ID_DEFAULT;
    h.packet_type = packet_type::HANDSHAKE;
    h.len = payload.len() as u16;
    let ai = h.auth_input();
    h.route_mac = crypto::route_mac(key_dst, &ai);
    let mut out = vec![0u8; HEADER_LEN + payload.len()];
    h.encode(&mut out);
    out[HEADER_LEN..].copy_from_slice(payload);
    out
}

/// 提取帧载荷（按帧头 len 截取，含长度校验；数据帧 len 含 TAG）
pub fn frame_payload(frame: &[u8]) -> Option<&[u8]> {
    wire::WireHeader::split(frame).map(|(_, payload)| payload)
}

/// 转发路径原地 TTL 递减（FRAME_HEADER §4：ttl 不参与认证，转发不重签 route_mac）。
/// 调用方保证 ttl ≥ 1（wrap 语义保持）。
pub fn decrement_ttl(frame: &mut [u8]) {
    wire::WireHeader::decrement_ttl(frame);
}

/// open_frame / open_frame_in_place 共享的帧校验（REQ-053）：
/// 解码帧头 + 版本/route_mac/长度校验，返回载荷区间 [hlen, hlen+len)。
fn validate_frame(
    frame: &[u8],
    key_dst: &[u8],
) -> Result<(MeshFrameHeader, usize, usize), OpenError> {
    let w = wire::WireHeader::parse(frame).map_err(OpenError::Decode)?;
    if w.version != VERSION {
        return Err(OpenError::Version);
    }
    let ai = w.auth_input();
    if crypto::route_mac(key_dst, &ai) != w.route_mac {
        return Err(OpenError::RouteMac);
    }
    let end = HEADER_LEN + w.len.get() as usize;
    if frame.len() < end {
        return Err(OpenError::TruncatedPayload);
    }
    Ok((MeshFrameHeader::from(w), HEADER_LEN, end))
}

/// 原地解密入口（REQ-053）：在 frame 缓冲上直接解密，载荷借用返回（零拷贝）。
pub fn open_frame_in_place<'a>(
    frame: &'a mut [u8],
    key_dst: &[u8],
    session_key: &[u8; 32],
    salt: u32,
) -> Result<(MeshFrameHeader, &'a mut [u8]), OpenError> {
    let (header, hlen, end) = validate_frame(frame, key_dst)?;
    let ai = header.auth_input();
    let pt_len = crypto::open_in_place(
        session_key,
        salt,
        header.seq as u64,
        &ai,
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
    let ai = header.auth_input();
    let payload = crypto::open(session_key, salt, header.seq as u64, &ai, &frame[hlen..end])
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

    /// 默认路径头（path_id=0，key_dst）
    fn sample_header() -> MeshFrameHeader {
        MeshFrameHeader {
            to_node_id: 0x0000_0002,
            from_node_id: 0x0000_0001,
            seq: 7,
            ..Default::default()
        }
    }

    /// 显式路径头（path_id≠0，key_path）
    fn sample_path_header() -> MeshFrameHeader {
        MeshFrameHeader {
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
        assert_eq!(d.path_id, PATH_ID_DEFAULT);
    }

    #[test]
    fn header_path_roundtrip() {
        let h = sample_path_header();
        let mut buf = [0u8; HEADER_LEN];
        h.encode(&mut buf);
        let d = MeshFrameHeader::decode(&buf).unwrap();
        assert_eq!(h, d);
        assert_eq!(d.path_id, 0x1234_5678_9abc_def0);
        // 字段偏移校验：path_id 在 18..26，route_mac 在 26..42
        assert_eq!(&buf[18..26], &0x1234_5678_9abc_def0u64.to_be_bytes());
    }

    #[test]
    fn short_buffer_rejected() {
        let h = sample_path_header();
        let mut buf = [0u8; HEADER_LEN];
        h.encode(&mut buf);
        // 不足 42B（含旧 34B 长度）一律截断
        assert_eq!(
            MeshFrameHeader::decode(&buf[..HEADER_LEN - PATH_ID_LEN]),
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
    fn frame_path_roundtrip_with_key_path() {
        let payload = b"hello path";
        let frame = build_frame(&sample_path_header(), &KEY_PATH, &SESSION, SALT, payload).unwrap();
        assert_eq!(frame.len(), HEADER_LEN + payload.len() + TAG_LEN);
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
    fn frame_default_path_uses_key_dst() {
        // path_id=0 = 默认路径 = key_dst 语义（CONTROL_PLANE §3.11）
        let mut h = sample_path_header();
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
    fn route_mac_path_rejects_path_id_tamper() {
        let payload = b"payload";
        let frame = build_frame(&sample_path_header(), &KEY_PATH, &SESSION, SALT, payload).unwrap();
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
        // 路径帧同样
        let fp = build_frame(&sample_path_header(), &KEY_PATH, &SESSION, SALT, payload).unwrap();
        let mut fp = fp;
        fp[3] = 0x01;
        assert!(open_frame(&fp, &KEY_PATH, &SESSION, SALT).is_ok());
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
        // 0x02 = 已退役的旧布局版本字节，与其它非法值同等拒绝
        for v in [0x00u8, 0x02, 0x03, 0xFF] {
            let mut frame = frame.clone();
            frame[0] = v;
            assert_eq!(
                open_frame(&frame, &KEY_DST, &SESSION, SALT).unwrap_err(),
                OpenError::Version
            );
        }
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
        let ai = sample_header().auth_input();
        let mac = crypto::route_mac(&KEY_DST, &ai);
        assert_eq!(mac.len(), ROUTE_MAC_LEN);
        assert_eq!(crypto::route_mac(&KEY_DST, &ai), mac);
        let mut tampered = ai;
        tampered[0] ^= 1;
        assert_ne!(crypto::route_mac(&KEY_DST, &tampered), mac);
        assert_ne!(crypto::route_mac(&[0x55; 32], &ai), mac);
        // path_id 纳入认证输入（18..26）
        let ai_path = sample_path_header().auth_input();
        assert_eq!(
            &ai_path[18..26],
            &sample_path_header().path_id.to_be_bytes()
        );
        assert_ne!(ai_path, ai);
    }

    // ---- golden vectors（FRAME_HEADER §2.1 绝对布局钉死；对称漂移不可能无声通过）----

    /// 手工按规范推定的期望字节：字段取互异值防偏移互换
    fn golden_header() -> MeshFrameHeader {
        MeshFrameHeader {
            version: VERSION,
            packet_type: 0x03,
            flags: 0xAB,
            ttl: 0x2A,
            to_node_id: 0x1122_3344,
            from_node_id: 0x5566_7788,
            seq: 0x99AA_BBC0,
            len: 0xDDEE,
            path_id: 0x1234_5678_9ABC_DEF0,
            route_mac: [0xA5; ROUTE_MAC_LEN],
        }
    }

    /// 帧头共享前缀 [0..18]
    const GOLDEN_PREFIX: [u8; 18] = [
        0x01, 0x03, 0xAB, 0x2A, // version, packet_type, flags, ttl
        0x11, 0x22, 0x33, 0x44, // to_node_id
        0x55, 0x66, 0x77, 0x88, // from_node_id
        0x99, 0xAA, 0xBB, 0xC0, // seq
        0xDD, 0xEE, // len
    ];

    #[test]
    fn golden_header_bytes() {
        let h = golden_header();
        let mut buf = [0u8; HEADER_LEN];
        h.encode(&mut buf);
        assert_eq!(&buf[..18], &GOLDEN_PREFIX);
        assert_eq!(&buf[18..26], &0x1234_5678_9ABC_DEF0u64.to_be_bytes());
        assert_eq!(&buf[26..42], &[0xA5; ROUTE_MAC_LEN]);
        assert_eq!(buf.len(), 42);
        // decode 还原
        assert_eq!(MeshFrameHeader::decode(&buf).unwrap(), h);
    }

    #[test]
    fn golden_auth_input_bytes() {
        // auth_input = 帧头 [0..18]（ttl 置零）|| path_id，route_mac 不参与
        let ai = golden_header().auth_input();
        let mut expect = [0u8; AUTH_INPUT_LEN];
        expect[..18].copy_from_slice(&GOLDEN_PREFIX);
        expect[3] = 0;
        expect[18..26].copy_from_slice(&0x1234_5678_9ABC_DEF0u64.to_be_bytes());
        assert_eq!(ai, expect);
    }

    #[test]
    fn golden_len_offset_in_frame_payload() {
        // frame_payload 从 off::LEN(16..18) 取长度：len=0xDDEE 的帧载荷不足应拒绝
        let h = golden_header();
        let mut buf = [0u8; HEADER_LEN + 4];
        h.encode(&mut buf);
        assert_eq!(frame_payload(&buf), None);
        buf[16..18].copy_from_slice(&4u16.to_be_bytes());
        assert_eq!(frame_payload(&buf), Some(&buf[42..46][..]));
    }

    #[test]
    fn decrement_ttl_wraps_and_ignores_truncated() {
        // ≥42B:正常递减;ttl=0 wrap 到 0xFF(调用方保证 ttl ≥ 1)
        let mut frame = [0u8; HEADER_LEN];
        frame[off::TTL] = 7;
        decrement_ttl(&mut frame);
        assert_eq!(frame[off::TTL], 6);
        frame[off::TTL] = 0;
        decrement_ttl(&mut frame);
        assert_eq!(frame[off::TTL], 0xFF);
        // 不足整头(含空):忽略不 panic(CN-02;旧实现会 panic 或误改字节)
        let mut short = [0x01u8, 0x03, 0xAB, 0x2A];
        decrement_ttl(&mut short);
        assert_eq!(short, [0x01, 0x03, 0xAB, 0x2A]);
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
        // 路径帧同样
        let fp = build_frame(&sample_path_header(), &KEY_PATH, &SESSION, SALT, payload).unwrap();
        let mut fb = fp.clone();
        let (_, p2) = open_frame_in_place(&mut fb, &KEY_PATH, &SESSION, SALT).unwrap();
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
        let mut hbuf = [0u8; HEADER_LEN];
        sample_path_header().encode(&mut hbuf);
        for v in 0..=255u8 {
            hbuf[0] = v;
            for cut in 0..=HEADER_LEN {
                let _ = MeshFrameHeader::decode(&hbuf[..cut]);
            }
        }
    }
}
