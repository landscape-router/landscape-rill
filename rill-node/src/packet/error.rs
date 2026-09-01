//! 包解析域错误（LAN 侧原始 IP 包）

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, landscape_rill_macro::ErrorId)]
pub enum PacketError {
    #[error("not an IP packet")]
    #[error_id("node.packet.not_ip")]
    NotIp,
    #[error("truncated IP packet")]
    #[error_id("node.packet.truncated")]
    Truncated,
}
