//! 路由域错误（前缀解析）

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, landscape_rill_macro::ErrorId)]
#[error_id(crate_path = "crate")]
pub enum PrefixError {
    #[error("invalid CIDR prefix")]
    #[error_id("route.prefix.bad_cidr")]
    BadCidr,
}
