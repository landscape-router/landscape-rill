#![deny(unsafe_code)]

/// 边界 I/O 结果别名（ERROR_ID §2.2）：统一 `Box<dyn Error + Send + Sync>`
pub type BoxResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub mod config;
pub mod packet;
pub mod runtime;
pub mod tun;
