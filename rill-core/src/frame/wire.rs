//! 42B 帧头线格式视图(zerocopy;FRAME_HEADER §2.1)。
//!
//! `WireHeader` 是帧字节缓冲的借用视图,承载全部字节级操作;
//! `MeshFrameHeader` 是所属域结构,两者经 `From` 互转。
//! 布局由 `repr(C, packed)` 声明 + `offset_of!` 断言钉死,与 golden vectors 互检。

use core::mem::{offset_of, size_of};

use zerocopy::byteorder::big_endian::{U16, U32, U64};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use super::error::DecodeError;
use super::{off, MeshFrameHeader, AUTH_INPUT_LEN, HEADER_LEN, ROUTE_MAC_LEN};

/// 42B 帧头线格式视图(FRAME_HEADER §2.1;path_id 位于偏移 18,非对齐 → packed)
#[derive(Debug, Clone, Copy, KnownLayout, Immutable, FromBytes, IntoBytes, Unaligned)]
#[repr(C, packed)]
pub(super) struct WireHeader {
    pub version: u8,
    pub packet_type: u8,
    pub flags: u8,
    pub ttl: u8,
    pub to_node_id: U32,
    pub from_node_id: U32,
    pub seq: U32,
    pub len: U16,
    pub path_id: U64,
    pub route_mac: [u8; ROUTE_MAC_LEN],
}

// 结构体声明即布局权威;绝对偏移与 off 模块互检(FRAME_HEADER §2.1)
const _: () = assert!(size_of::<WireHeader>() == HEADER_LEN);
const _: () = assert!(offset_of!(WireHeader, version) == off::VERSION);
const _: () = assert!(offset_of!(WireHeader, packet_type) == off::PACKET_TYPE);
const _: () = assert!(offset_of!(WireHeader, flags) == off::FLAGS);
const _: () = assert!(offset_of!(WireHeader, ttl) == off::TTL);
const _: () = assert!(offset_of!(WireHeader, to_node_id) == off::TO_NODE);
const _: () = assert!(offset_of!(WireHeader, from_node_id) == off::FROM_NODE);
const _: () = assert!(offset_of!(WireHeader, seq) == off::SEQ);
const _: () = assert!(offset_of!(WireHeader, len) == off::LEN);
const _: () = assert!(offset_of!(WireHeader, path_id) == off::PATH_ID);
const _: () = assert!(offset_of!(WireHeader, route_mac) == off::ROUTE_MAC);

impl WireHeader {
    /// 解析帧头视图(宽容:仅要求 ≥42B;版本白名单由 validate_frame/relay 强制)
    pub(super) fn parse(buf: &[u8]) -> Result<&Self, DecodeError> {
        Self::ref_from_prefix(buf)
            .map(|(h, _)| h)
            .map_err(|_| DecodeError::Truncated)
    }

    /// 精确写入 HEADER_LEN 字节(调用方保证 out 长度充足)
    pub(super) fn write_into(&self, out: &mut [u8]) {
        let _ = self.write_to(&mut out[..HEADER_LEN]);
    }

    /// 帧头视图 + 按头内 len 截取的载荷(数据帧 len 含 TAG)
    pub(super) fn split(buf: &[u8]) -> Option<(&Self, &[u8])> {
        let (h, rest) = Self::ref_from_prefix(buf).ok()?;
        Some((h, rest.get(..h.len.get() as usize)?))
    }

    /// 原地 TTL 递减(FRAME_HEADER §4:ttl 不参与认证,转发不重签 route_mac)。
    /// 不足整头长度时忽略(CN-02:解析路径不 panic)。
    pub(super) fn decrement_ttl(buf: &mut [u8]) {
        if let Ok((h, _)) = Self::mut_from_prefix(buf) {
            h.ttl = h.ttl.wrapping_sub(1);
        }
    }

    /// 认证输入 = 线字节 [0..AUTH_INPUT_LEN] 且 ttl 置零(FRAME_HEADER §2.2/§3.3)
    pub(super) fn auth_input(&self) -> [u8; AUTH_INPUT_LEN] {
        let mut out = [0u8; AUTH_INPUT_LEN];
        out.copy_from_slice(&self.as_bytes()[..AUTH_INPUT_LEN]);
        out[off::TTL] = 0;
        out
    }
}

impl From<&WireHeader> for MeshFrameHeader {
    fn from(w: &WireHeader) -> Self {
        Self {
            version: w.version,
            packet_type: w.packet_type,
            flags: w.flags,
            ttl: w.ttl,
            to_node_id: w.to_node_id.get(),
            from_node_id: w.from_node_id.get(),
            seq: w.seq.get(),
            len: w.len.get(),
            path_id: w.path_id.get(),
            route_mac: w.route_mac,
        }
    }
}

impl From<&MeshFrameHeader> for WireHeader {
    fn from(h: &MeshFrameHeader) -> Self {
        Self {
            version: h.version,
            packet_type: h.packet_type,
            flags: h.flags,
            ttl: h.ttl,
            to_node_id: U32::new(h.to_node_id),
            from_node_id: U32::new(h.from_node_id),
            seq: U32::new(h.seq),
            len: U16::new(h.len),
            path_id: U64::new(h.path_id),
            route_mac: h.route_mac,
        }
    }
}
