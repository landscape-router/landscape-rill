//! mesh 控制面（CONTROL_PLANE）：客户端会话 / coordinator 服务端 / 信封编解码 / TLS
//!
//! - [codec]：proto envelope ↔ 线格式帧（长度前缀帧见 [crate::framing]）
//! - [tls]：客户端/服务端 TLS 流建立
//! - [client]：MeshClient + ControlSession（节点侧注册与事件消费）
//! - [server]：CoordinatorServer（coordinator 侧消息分派与推送）

pub mod client;
mod codec;
pub mod server;
pub mod tls;

pub use client::{ControlEvent, ControlSession, MeshClient, MeshEvent, MeshLegConfig, NetmapData};
pub use codec::{
    envelope_body, envelope_bytes, parse_envelope, read_envelope, write_msg, EnvelopeError,
};
pub use server::{ConnectionState, CoordinatorServer};
pub use tls::{client_tls_stream, server_tls_accept, server_tls_acceptor, server_tls_stream};

pub const PROTOCOL_VERSION: u32 = 2;
pub const CHALLENGE_NONCE_LEN: usize = 16;

/// 边界 I/O 结果别名（ERROR_ID §2.2）：统一 `Box<dyn Error + Send + Sync>`
pub(crate) type BoxResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// hops → bytes（每 node_id 4B 大端；avoid quick-protobuf packed fixed32 对齐缺陷）
pub fn hops_bytes(hops: &[u32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(hops.len() * 4);
    for h in hops {
        out.extend_from_slice(&h.to_be_bytes());
    }
    out
}

/// bytes → hops（4B 大端）
pub fn hops_to_vec(hops: &[u8]) -> Vec<u32> {
    let (full, rem) = hops.as_chunks::<4>();
    debug_assert!(rem.is_empty());
    full.iter().map(|c| u32::from_be_bytes(*c)).collect()
}
