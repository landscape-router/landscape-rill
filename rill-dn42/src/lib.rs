#![deny(unsafe_code)]

//! dn42 接入（DN42_LEG）：boringtun 隧道管理 + 自研 eBGP-lite + import/export 过滤策略。
//! 设计：docs/design/legs/dn42.md。

pub mod fsm;
pub mod policy;
pub mod rib;
pub mod session;
pub mod tunnel;
pub mod wire;
