//! eBGP FSM（I/O 无关，DN42_LEG §3）：事件进 / 动作出，纯逻辑零 I/O。
//! 状态机按 RFC 4271 简化到单跳 eBGP 实际需要的路径；connect-retry 等连接时机由驱动层负责，
//! FSM 只管协议状态与响应。

#[cfg(test)]
mod tests;

use std::net::Ipv4Addr;
use std::time::Duration;

use crate::wire::{
    Capability, Message, NotificationMsg, OpenMsg, UpdateMsg, AFI_IPV4, AFI_IPV6, SAFI_UNICAST,
};

/// NOTIFICATION 错误码（RFC 4271）
pub const ERR_MESSAGE_HEADER: u8 = 1;
pub const ERR_OPEN: u8 = 2;
pub const ERR_UPDATE: u8 = 3;
pub const ERR_HOLD_TIMER: u8 = 4;
pub const ERR_FSM: u8 = 5;
pub const ERR_CEASE: u8 = 6;
/// OPEN 子码（RFC 4271 / RFC 5492）
pub const SUB_UNSUPPORTED_VERSION: u8 = 1;
pub const SUB_BAD_PEER_AS: u8 = 2;
pub const SUB_BAD_BGP_ID: u8 = 3;
pub const SUB_UNSUPPORTED_CAPABILITY: u8 = 7;
/// Cease 子码（RFC 4486）
pub const SUB_MAX_PREFIXES: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Idle,
    Connect,
    OpenSent,
    OpenConfirm,
    Established,
}

#[derive(Debug, Clone)]
pub struct LocalConfig {
    pub as4: u32,
    pub bgp_id: Ipv4Addr,
    /// 我方建议 hold time（秒）；协商取双方较小值，任一方为 0 = 不用 hold timer
    pub hold_time: u16,
    /// 期望的 peer ASN（eBGP 固定邻居）；None = 不校验
    pub peer_as4: Option<u32>,
}

impl Default for LocalConfig {
    fn default() -> Self {
        Self {
            as4: 0,
            bgp_id: Ipv4Addr::UNSPECIFIED,
            hold_time: 90,
            peer_as4: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Send(Message),
    /// 发完队列即关闭连接（NOTIFICATION 后）
    Close,
}

#[derive(Debug, Clone)]
pub struct BgpFsm {
    state: State,
    local: LocalConfig,
    /// 协商后的 hold time（0 = 无 hold/keepalive）；未协商前为我方建议值
    negotiated_hold: u16,
}

impl BgpFsm {
    pub fn new(local: LocalConfig) -> Self {
        let negotiated_hold = local.hold_time;
        Self {
            state: State::Idle,
            local,
            negotiated_hold,
        }
    }

    pub fn state(&self) -> State {
        self.state
    }

    /// 协商后的 hold time（秒；0 = 对端/我方禁用 hold timer）
    pub fn negotiated_hold(&self) -> u16 {
        self.negotiated_hold
    }

    /// keepalive 间隔 = hold/3（hold 为 0 时返回 None，即不周期发送）
    pub fn keepalive_interval(&self) -> Option<Duration> {
        if self.negotiated_hold == 0 {
            None
        } else {
            Some(Duration::from_secs((self.negotiated_hold / 3).max(1) as u64))
        }
    }

    /// 驱动层发起连接（Idle → Connect；TCP 建立时机在驱动）
    pub fn start(&mut self) -> State {
        self.state = State::Connect;
        self.state
    }

    /// TCP 连接建立（主动拨号成功或被动 accept）
    pub fn on_tcp_established(&mut self) -> Vec<Action> {
        match self.state {
            State::Connect | State::Idle => {
                self.state = State::OpenSent;
                self.negotiated_hold = self.local.hold_time;
                let open = OpenMsg {
                    as4: self.local.as4,
                    hold_time: self.local.hold_time,
                    bgp_id: self.local.bgp_id,
                    capabilities: vec![
                        Capability::MpBgp {
                            afi: AFI_IPV4,
                            safi: SAFI_UNICAST,
                        },
                        Capability::MpBgp {
                            afi: AFI_IPV6,
                            safi: SAFI_UNICAST,
                        },
                        Capability::RouteRefresh,
                        Capability::FourOctetAs(self.local.as4),
                    ],
                };
                vec![Action::Send(Message::Open(open))]
            }
            State::OpenSent | State::OpenConfirm | State::Established => {
                self.notify_fsm_error("duplicate TCP establish")
            }
        }
    }

    /// TCP 断开：任何状态 → Idle（重连时机归驱动）
    pub fn on_tcp_closed(&mut self) {
        self.state = State::Idle;
    }

    pub fn on_hold_timer(&mut self) -> Vec<Action> {
        match self.state {
            State::OpenConfirm | State::Established => {
                let a = self.notify(ERR_HOLD_TIMER, 0, "hold timer expired");
                self.state = State::Idle;
                vec![a, Action::Close]
            }
            _ => vec![],
        }
    }

    pub fn on_message(&mut self, msg: Message) -> Vec<Action> {
        match msg {
            Message::Open(open) => self.on_open(open),
            Message::Keepalive => self.on_keepalive(),
            Message::Update(update) => self.on_update(update),
            Message::Notification(_) => {
                // 对端拒绝/关会话：直接收场，不回包
                self.state = State::Idle;
                vec![Action::Close]
            }
            Message::RouteRefresh(_) => {
                // Established 内合法：重发自家前缀由驱动处理（action 层不带状态）
                if self.state == State::Established {
                    vec![]
                } else {
                    self.notify_fsm_error("route refresh outside Established")
                }
            }
        }
    }

    fn on_open(&mut self, open: OpenMsg) -> Vec<Action> {
        if self.state != State::OpenSent {
            return self.notify_fsm_error("unexpected OPEN");
        }
        // 版本（RFC 4271 §4.2：version 协商只有 4，不一致即拒）
        if open.hold_time > 0 && open.hold_time < 3 {
            // hold < 3s 无法保证 keepalive ≥ 1s 节奏，按不可接受处理
            let a = self.notify(ERR_OPEN, 6, "unacceptable hold time");
            self.state = State::Idle;
            return vec![a, Action::Close];
        }
        if let Some(expect) = self.local.peer_as4 {
            if open.as4 != expect {
                let a = self.notify(ERR_OPEN, SUB_BAD_PEER_AS, "bad peer AS");
                self.state = State::Idle;
                return vec![a, Action::Close];
            }
        }
        if open.bgp_id.is_unspecified() {
            let a = self.notify(ERR_OPEN, SUB_BAD_BGP_ID, "bad BGP identifier");
            self.state = State::Idle;
            return vec![a, Action::Close];
        }
        // 能力协商：4B ASN、MP-BGP、route refresh 缺一不可用（DN42_LEG §4.2）
        let mut has_mp = false;
        let mut has_as4 = false;
        let mut has_rr = false;
        for cap in &open.capabilities {
            match cap {
                Capability::MpBgp {
                    afi,
                    safi: SAFI_UNICAST,
                } if *afi == AFI_IPV4 || *afi == AFI_IPV6 => has_mp = true,
                Capability::FourOctetAs(_) => has_as4 = true,
                Capability::RouteRefresh => has_rr = true,
                _ => {}
            }
        }
        if !has_mp || !has_as4 || !has_rr {
            let a = self.notify(
                ERR_OPEN,
                SUB_UNSUPPORTED_CAPABILITY,
                "missing required capability (4B AS / MP-BGP / route refresh)",
            );
            self.state = State::Idle;
            return vec![a, Action::Close];
        }
        self.negotiated_hold = if self.local.hold_time == 0 || open.hold_time == 0 {
            0
        } else {
            self.local.hold_time.min(open.hold_time)
        };
        self.state = State::OpenConfirm;
        vec![Action::Send(Message::Keepalive)]
    }

    fn on_keepalive(&mut self) -> Vec<Action> {
        match self.state {
            State::OpenConfirm => {
                self.state = State::Established;
                vec![]
            }
            State::Established => vec![], // hold timer 重置由驱动按消息到达处理
            _ => self.notify_fsm_error("unexpected KEEPALIVE"),
        }
    }

    fn on_update(&mut self, _update: UpdateMsg) -> Vec<Action> {
        if self.state != State::Established {
            return self.notify_fsm_error("UPDATE outside Established");
        }
        // NLRI 交给调用方（policy/RIB 在会话层串联）；UPDATE 到达本身重置 hold timer
        vec![]
    }

    /// 会话层主动关闭（吊销/管理操作）：Cease
    pub fn cease(&mut self) -> Vec<Action> {
        self.state = State::Idle;
        vec![Action::Send(Message::Notification(NotificationMsg {
            code: ERR_CEASE,
            subcode: 0,
            data: vec![],
        }))]
    }

    /// max-prefix 超限关会话（DN42_LEG §4，import policy 的会话级防线）
    pub fn notify_max_prefix(&mut self) -> Vec<Action> {
        self.state = State::Idle;
        vec![
            Action::Send(Message::Notification(NotificationMsg {
                code: ERR_CEASE,
                subcode: SUB_MAX_PREFIXES,
                data: vec![],
            })),
            Action::Close,
        ]
    }

    /// 协议错误收场：NOTIFICATION(FSM error) + 关连接
    fn notify_fsm_error(&mut self, why: &str) -> Vec<Action> {
        let a = self.notify(ERR_FSM, 1, why);
        self.state = State::Idle;
        vec![a, Action::Close]
    }

    fn notify(&self, code: u8, subcode: u8, _why: &str) -> Action {
        Action::Send(Message::Notification(NotificationMsg {
            code,
            subcode,
            data: vec![],
        }))
    }
}
