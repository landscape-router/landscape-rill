//! 配置域错误（解析/校验，加载即校验 fail-closed，REQ-038）

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct ConfigError(pub String);

impl landscape_rill_core::error::ErrorId for ConfigError {
    fn error_id(&self) -> &'static str {
        "coord.config"
    }
    fn error_args(&self) -> landscape_rill_core::error::ErrorArgs {
        landscape_rill_core::error::args(&[])
    }
}

impl From<serde_json::Error> for ConfigError {
    fn from(e: serde_json::Error) -> Self {
        ConfigError(format!("json parse failed: {e}"))
    }
}
