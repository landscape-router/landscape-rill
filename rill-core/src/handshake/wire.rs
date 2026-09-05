//! 握手载荷线格式视图(zerocopy;FRAME_HEADER §2.3/§2.4)。
//!
//! msg2 为纯 Noise 消息体,无布局字段,不设视图。
//! 解析 fail-closed:ref_from_bytes 精确长度 + 布局校验(CN-02/CN-05:预认证路径不 panic)。

use core::mem::size_of;

use zerocopy::byteorder::big_endian::U32;
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

use super::error::HandshakeError;
use super::{BINDING_LEN, MSG1_BODY_LEN, MSG1_PAYLOAD_LEN, MSG3_BODY_LEN, MSG3_PAYLOAD_LEN};

/// msg1 帧载荷视图:目标 node_id(4B) + Noise 消息体(32B)
#[derive(Debug, Clone, Copy, KnownLayout, Immutable, FromBytes, Unaligned)]
#[repr(C, packed)]
pub(super) struct WireMsg1 {
    pub target: U32,
    pub body: [u8; MSG1_BODY_LEN],
}

const _: () = assert!(size_of::<WireMsg1>() == MSG1_PAYLOAD_LEN);

impl WireMsg1 {
    /// 精确长度解析(长度/布局不符 → MalformedPayload)
    pub(super) fn parse(buf: &[u8]) -> Result<&Self, HandshakeError> {
        Self::ref_from_bytes(buf).map_err(|_| HandshakeError::MalformedPayload)
    }
}

/// msg3 帧载荷视图:身份绑定(64B) + 会话盐(4B) + Noise 消息体(64B)
#[derive(Debug, Clone, Copy, KnownLayout, Immutable, FromBytes, Unaligned)]
#[repr(C, packed)]
pub(super) struct WireMsg3 {
    pub binding: [u8; BINDING_LEN],
    pub salt: U32,
    pub body: [u8; MSG3_BODY_LEN],
}

const _: () = assert!(size_of::<WireMsg3>() == MSG3_PAYLOAD_LEN);

impl WireMsg3 {
    /// 精确长度解析(长度/布局不符 → MalformedPayload)
    pub(super) fn parse(buf: &[u8]) -> Result<&Self, HandshakeError> {
        Self::ref_from_bytes(buf).map_err(|_| HandshakeError::MalformedPayload)
    }
}
