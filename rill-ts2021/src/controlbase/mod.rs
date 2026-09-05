//! controlbase：ts2021 控制面基础传输（TS2021_LEG §2 安全层）。
//! Noise IK（Curve25519 + ChaChaPoly + BLAKE2s），协议串/帧格式对齐
//! tailscale control/controlbase（v1.102.2 核对）。
//! 纯逻辑状态机 + wire codec，无 IO 类型；stream.rs 为 tokio 胶水（NoiseStream）。

pub mod error;
mod handshake;
pub mod stream;
#[cfg(test)]
pub(crate) mod tests;
mod wire;

pub use error::ControlbaseError;
pub use handshake::{ClientHandshake, Session};
pub use stream::{handshake, NoiseStream};
