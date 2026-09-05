//! controlbase 域错误（纯逻辑；IO 胶水层映射为 io::Error，对齐 mesh control client 约定）

#[derive(Debug, PartialEq, thiserror::Error, landscape_rill_macro::ErrorId)]
pub enum ControlbaseError {
    #[error(transparent)]
    #[error_id("ts2021.controlbase.noise")]
    Noise(snow::Error),
    #[error("malformed frame")]
    #[error_id("ts2021.controlbase.malformed_frame")]
    MalformedFrame,
    #[error("wrong handshake step")]
    #[error_id("ts2021.controlbase.wrong_step")]
    WrongStep,
    #[error("server error: {0}")]
    #[error_id("ts2021.controlbase.server_error")]
    ServerError(String),
    #[error("cipher state desynced")]
    #[error_id("ts2021.controlbase.desync")]
    Desync,
}
