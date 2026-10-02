//! 注册能力位（CONTROL_PLANE §3.1）：节点自愿声明，coordinator 侧策略消费。
//! 全部常量的唯一家（mesh/node/coord 共用；此前散落 core/coord 两处）。
//! relay/exit = 角色类能力（网络准入再裁决，能力位只是必要条件）；
//! broadcast/acl = 协议类能力（对端行为前提）。

/// 能力位：relay（自愿中继，CONNECTIVITY §5 / CONTROL_PLANE §3.1）
pub const CAPABILITY_RELAY: u32 = 0x01;

/// 能力位：exit（自愿 mesh 出口，ROUTE_ENGINE §5 / REQ-071；
/// 网络准入 exits.allow 裁决——能力位 ∧ 授权集才进 netmap exit 标记）
pub const CAPABILITY_EXIT: u32 = 0x08;

/// 能力位：broadcast（L2 广播/组播泛洪 opt-in，CONTROL_PLANE §3.1 / FRAME_HEADER §2.6）
pub const CAPABILITY_BROADCAST: u32 = 0x20;

/// 能力位：ACL（策略网络注册前提，REQ-045）
pub const CAPABILITY_ACL: u32 = 0x40;
