//! 节点配置域错误（校验，加载即校验 fail-closed）

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, landscape_rill_macro::ErrorId)]
pub enum ConfigError {
    #[error("coordinator url is empty")]
    #[error_id("node.config.empty_coordinator_url")]
    EmptyCoordinatorUrl,
    #[error("coordinator url must be https")]
    #[error_id("node.config.non_https_coordinator_url")]
    NonHttpsCoordinatorUrl,
    #[error("auth key is empty")]
    #[error_id("node.config.empty_auth_key")]
    EmptyAuthKey,
    #[error("invalid route: {0}")]
    #[error_id("node.config.invalid_route")]
    InvalidRoute(String),
    #[error("missing coordinator signing pubkey")]
    #[error_id("node.config.missing_signing_pubkey")]
    MissingSigningPubkey,
    #[error("ca cert path is empty")]
    #[error_id("node.config.empty_ca_cert_path")]
    EmptyCaCertPath,
    #[error("missing master key")]
    #[error_id("node.config.missing_master_key")]
    MissingMasterKey,
    #[error("missing signing seed")]
    #[error_id("node.config.missing_signing_seed")]
    MissingSigningSeed,
    #[error("invalid listen addr")]
    #[error_id("node.config.invalid_listen_addr")]
    InvalidListenAddr,
}
