//! 加密域错误

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("aead error")]
pub struct AeadError;

impl crate::error::ErrorId for AeadError {
    fn error_id(&self) -> &'static str {
        "crypto.aead"
    }
    fn error_args(&self) -> crate::error::ErrorArgs {
        crate::error::args(&[])
    }
}
