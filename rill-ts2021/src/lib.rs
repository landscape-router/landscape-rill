#![deny(unsafe_code)]

//! ts2021 接入腿：tailscale 兼容控制面客户端（TS2021_LEG）。
//! 分层对齐 tailscale 协议栈：controlbase（Noise IK 安全层）→ controlhttp（升级）
//! → ts2021（HTTP/2 会话 + tailcfg JSON）。

pub mod base64;
pub mod controlbase;
pub mod controlhttp;
pub mod tailcfg;
pub mod ts2021;
