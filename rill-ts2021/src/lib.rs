#![deny(unsafe_code)]

//! ts2021 接入腿：tailscale 兼容控制面客户端 + 自研服务端（TS2021_LEG）。
//! 分层对齐 tailscale 协议栈：controlbase（Noise IK 安全层）→ controlhttp（升级）
//! → ts2021（HTTP/2 会话 + tailcfg JSON）；server（REQ-068）为同一套协议的
//! 响应侧（/key + 升级 + register/map + 内嵌 DERP），替换 headscale。

pub mod base64;
pub mod controlbase;
pub mod controlhttp;
pub mod derp;
pub mod server;
pub mod tailcfg;
pub mod ts2021;
pub mod wg;
