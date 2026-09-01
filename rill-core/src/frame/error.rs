//! 帧域错误（解码/开启）

use crate::crypto::AeadError;

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
