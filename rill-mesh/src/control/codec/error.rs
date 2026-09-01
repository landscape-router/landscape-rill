//! 信封域错误（protobuf Envelope 编解码）

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, landscape_rill_macro::ErrorId)]
pub enum EnvelopeError {
    #[error("envelope decode failed")]
    #[error_id("mesh.envelope.decode")]
    Decode,
}
