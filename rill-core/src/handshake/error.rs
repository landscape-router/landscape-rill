//! 握手域错误（Noise 状态机 + 会话帧开启）

use crate::frame::OpenError as FrameOpenError;

#[derive(Debug, PartialEq, thiserror::Error, landscape_rill_macro::ErrorId)]
#[error_id(crate_path = "crate")]
pub enum HandshakeError {
    #[error(transparent)]
    #[error_id("handshake.noise")]
    Noise(snow::Error),
    #[error("malformed handshake payload")]
    #[error_id("handshake.malformed_payload")]
    MalformedPayload,
    #[error("handshake targeted at wrong node")]
    #[error_id("handshake.wrong_target")]
    WrongTarget,
    #[error("invalid identity binding")]
    #[error_id("handshake.bad_binding")]
    BadBinding,
    #[error("peer static key mismatch")]
    #[error_id("handshake.peer_static_mismatch")]
    PeerStaticMismatch,
    #[error("wrong handshake step")]
    #[error_id("handshake.wrong_step")]
    WrongStep,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error, landscape_rill_macro::ErrorId)]
#[error_id(crate_path = "crate")]
pub enum OpenError {
    #[error("frame decode error")]
    #[error_id("handshake.open.decode")]
    Decode,
    #[error("unsupported frame version")]
    #[error_id("handshake.open.version")]
    Version,
    #[error("route mac mismatch")]
    #[error_id("handshake.open.route_mac")]
    RouteMac,
    #[error("truncated payload")]
    #[error_id("handshake.open.truncated_payload")]
    TruncatedPayload,
    #[error("aead error")]
    #[error_id("handshake.open.aead")]
    Aead,
    #[error("replayed frame")]
    #[error_id("handshake.open.replay")]
    Replay,
}

impl From<FrameOpenError> for OpenError {
    fn from(e: FrameOpenError) -> Self {
        match e {
            FrameOpenError::Decode(_) => OpenError::Decode,
            FrameOpenError::Version => OpenError::Version,
            FrameOpenError::RouteMac => OpenError::RouteMac,
            FrameOpenError::TruncatedPayload => OpenError::TruncatedPayload,
            FrameOpenError::Aead(_) => OpenError::Aead,
        }
    }
}
