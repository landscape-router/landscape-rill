//! auth key 域错误（格式解析/校验，CONTROL_PLANE §6 / REQ-043）

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, landscape_rill_macro::ErrorId)]
pub enum AuthKeyError {
    #[error("auth key must start with lrk-")]
    #[error_id("coord.auth_key.bad_prefix")]
    BadPrefix,
    #[error("auth key format must be lrk-<network>-<expiry>-<secret>")]
    #[error_id("coord.auth_key.bad_format")]
    BadFormat,
    #[error("invalid network segment (lowercase alphanumeric, no dashes)")]
    #[error_id("coord.auth_key.bad_network")]
    BadNetwork,
    #[error("invalid expiry segment (decimal unix seconds, 0 = never expires)")]
    #[error_id("coord.auth_key.bad_expiry")]
    BadExpiry,
    #[error("invalid auth key secret length")]
    #[error_id("coord.auth_key.bad_secret_len")]
    BadSecretLen,
    #[error("invalid auth key secret characters")]
    #[error_id("coord.auth_key.bad_secret")]
    BadSecret,
}
