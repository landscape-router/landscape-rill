//! 数据面错误：丢弃原因 + 发送错误

use landscape_rill_core::handshake::HandshakeError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    BadVersion,
    BadRouteMac,
    TtlExpired,
    NoEndpoint,
    NoKeyDst,
    Short,
    NoSession,
    Aead,
    Replay,
    UnsupportedType,
    Duplicate,
    RateLimited,
    /// 非 42B 帧且非 probe（CONNECTIVITY §2.1 分派失败）
    UnknownProtocol,
}

#[derive(Debug, PartialEq, thiserror::Error, landscape_rill_macro::ErrorId)]
pub enum SendError {
    #[error("no session with peer")]
    #[error_id("mesh.send.no_session")]
    NoSession,
    #[error("no key material for destination")]
    #[error_id("mesh.send.no_key_dst")]
    NoKeyDst,
    #[error("no send context")]
    #[error_id("mesh.send.no_context")]
    NoContext,
    #[error("no peer binding")]
    #[error_id("mesh.send.no_peer_binding")]
    NoPeerBinding,
    #[error(transparent)]
    #[error_id(transparent)]
    Handshake(#[from] HandshakeError),
    #[error("aead failure")]
    #[error_id("mesh.send.aead")]
    Aead,
}
