//! 传输帧域错误（长度前缀帧，控制面 TCP）

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, landscape_rill_macro::ErrorId)]
pub enum FrameError {
    #[error("message too long")]
    #[error_id("mesh.frame.too_long")]
    TooLong,
    #[error("truncated frame")]
    #[error_id("mesh.frame.truncated")]
    Truncated,
}
