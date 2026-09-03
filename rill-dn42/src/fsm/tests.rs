//! FSM 测试：状态迁移、协商、对抗路径（错误 NOTIFICATION + 收场）。

use std::net::Ipv4Addr;

use super::*;
use crate::wire::{
    Capability, Message, NotificationMsg, OpenMsg, RouteRefreshMsg, AFI_IPV4, SAFI_UNICAST,
};
use landscape_rill_core::route::Prefix;

fn local() -> LocalConfig {
    LocalConfig {
        as4: 4242420001,
        bgp_id: Ipv4Addr::new(172, 20, 100, 1),
        hold_time: 90,
        peer_as4: Some(4242420002),
    }
}

fn peer_open(hold: u16) -> OpenMsg {
    OpenMsg {
        as4: 4242420002,
        hold_time: hold,
        bgp_id: Ipv4Addr::new(172, 20, 200, 1),
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
            Capability::FourOctetAs(4242420002),
        ],
    }
}

fn established() -> BgpFsm {
    let mut fsm = BgpFsm::new(local());
    fsm.start();
    let acts = fsm.on_tcp_established();
    assert!(matches!(&acts[0], Action::Send(Message::Open(_))));
    let acts = fsm.on_message(Message::Open(peer_open(90)));
    assert!(matches!(&acts[0], Action::Send(Message::Keepalive)));
    fsm.on_message(Message::Keepalive);
    assert_eq!(fsm.state(), State::Established);
    fsm
}

#[test]
fn happy_path_to_established() {
    let mut fsm = BgpFsm::new(local());
    assert_eq!(fsm.state(), State::Idle);
    assert_eq!(fsm.start(), State::Connect);
    let acts = fsm.on_tcp_established();
    assert_eq!(fsm.state(), State::OpenSent);
    assert!(matches!(&acts[0], Action::Send(Message::Open(open))
        if open.as4 == 4242420001
            && open.hold_time == 90
            && open.capabilities.len() == 4));
    // OPEN：协商 hold = min(90, 60) = 60，回 KEEPALIVE → OpenConfirm
    let acts = fsm.on_message(Message::Open(peer_open(60)));
    assert_eq!(fsm.state(), State::OpenConfirm);
    assert!(matches!(&acts[0], Action::Send(Message::Keepalive)));
    assert_eq!(fsm.negotiated_hold(), 60);
    assert_eq!(fsm.keepalive_interval(), Some(Duration::from_secs(20)));
    // KEEPALIVE → Established
    let acts = fsm.on_message(Message::Keepalive);
    assert!(acts.is_empty());
    assert_eq!(fsm.state(), State::Established);
}

#[test]
fn hold_time_zero_disables_timers() {
    let mut cfg = local();
    cfg.hold_time = 0;
    let mut fsm = BgpFsm::new(cfg);
    fsm.start();
    fsm.on_tcp_established();
    fsm.on_message(Message::Open(peer_open(90)));
    assert_eq!(fsm.negotiated_hold(), 0);
    assert_eq!(fsm.keepalive_interval(), None);
    fsm.on_message(Message::Keepalive);
    assert_eq!(fsm.state(), State::Established);
}

#[test]
fn reject_unsupported_version_and_hold_lt3() {
    // hold < 3 不可接受（OPEN 子码 6）
    let mut fsm = BgpFsm::new(local());
    fsm.start();
    fsm.on_tcp_established();
    let mut open = peer_open(2);
    open.as4 = 4242420002;
    let acts = fsm.on_message(Message::Open(open));
    assert_eq!(fsm.state(), State::Idle);
    assert!(matches!(
        &acts[..],
        [
            Action::Send(Message::Notification(NotificationMsg {
                code: 2,
                subcode: 6,
                ..
            })),
            Action::Close
        ]
    ));
}

#[test]
fn reject_bad_peer_as() {
    let mut fsm = BgpFsm::new(local());
    fsm.start();
    fsm.on_tcp_established();
    let mut open = peer_open(90);
    open.as4 = 65001; // 非配置邻居 ASN
    open.capabilities
        .retain(|c| !matches!(c, Capability::FourOctetAs(_)));
    open.capabilities.push(Capability::FourOctetAs(65001));
    let acts = fsm.on_message(Message::Open(open));
    assert!(matches!(
        &acts[..],
        [
            Action::Send(Message::Notification(NotificationMsg {
                code: 2,
                subcode: 2,
                ..
            })),
            Action::Close
        ]
    ));
    assert_eq!(fsm.state(), State::Idle);
}

#[test]
fn reject_bad_bgp_id() {
    let mut fsm = BgpFsm::new(local());
    fsm.start();
    fsm.on_tcp_established();
    let mut open = peer_open(90);
    open.bgp_id = Ipv4Addr::UNSPECIFIED;
    let acts = fsm.on_message(Message::Open(open));
    assert!(matches!(
        &acts[..],
        [
            Action::Send(Message::Notification(NotificationMsg {
                code: 2,
                subcode: 3,
                ..
            })),
            Action::Close
        ]
    ));
}

#[test]
fn reject_missing_required_capability() {
    for remove in [0usize, 1, 2] {
        let mut fsm = BgpFsm::new(local());
        fsm.start();
        fsm.on_tcp_established();
        let mut open = peer_open(90);
        // 逐个拿掉 MP-BGP(v4+v6) / RouteRefresh / 4B ASN —— 缺一不可用
        match remove {
            0 => open
                .capabilities
                .retain(|c| !matches!(c, Capability::MpBgp { .. })),
            1 => open
                .capabilities
                .retain(|c| !matches!(c, Capability::RouteRefresh)),
            _ => open
                .capabilities
                .retain(|c| !matches!(c, Capability::FourOctetAs(_))),
        }
        let acts = fsm.on_message(Message::Open(open));
        assert!(
            matches!(
                &acts[..],
                [
                    Action::Send(Message::Notification(NotificationMsg {
                        code: 2,
                        subcode: 7,
                        ..
                    })),
                    Action::Close
                ]
            ),
            "case {remove}"
        );
        assert_eq!(fsm.state(), State::Idle);
    }
}

#[test]
fn hold_timer_expiry_closes_session() {
    let mut fsm = established();
    let acts = fsm.on_hold_timer();
    assert!(matches!(
        &acts[..],
        [
            Action::Send(Message::Notification(NotificationMsg {
                code: 4,
                subcode: 0,
                ..
            })),
            Action::Close
        ]
    ));
    assert_eq!(fsm.state(), State::Idle);
    // Idle 后可重新 start（驱动重连路径）
    assert_eq!(fsm.start(), State::Connect);
}

#[test]
fn update_in_established_is_accepted() {
    let mut fsm = established();
    let update = crate::wire::UpdateMsg {
        withdrawn: vec![],
        attrs: vec![],
        announced: vec![Prefix::parse("172.20.200.0/24").unwrap()],
    };
    let acts = fsm.on_message(Message::Update(update));
    assert!(acts.is_empty());
    assert_eq!(fsm.state(), State::Established);
}

#[test]
fn messages_outside_state_are_fsm_errors() {
    // UPDATE 未到 Established
    let mut fsm = BgpFsm::new(local());
    fsm.start();
    fsm.on_tcp_established();
    let update = crate::wire::UpdateMsg {
        withdrawn: vec![],
        attrs: vec![],
        announced: vec![],
    };
    let acts = fsm.on_message(Message::Update(update));
    assert!(matches!(
        &acts[..],
        [
            Action::Send(Message::Notification(NotificationMsg {
                code: 5,
                subcode: 1,
                ..
            })),
            Action::Close
        ]
    ));
    // KEEPALIVE 在 OpenSent
    let mut fsm = BgpFsm::new(local());
    fsm.start();
    fsm.on_tcp_established();
    let acts = fsm.on_message(Message::Keepalive);
    assert!(matches!(
        &acts[..],
        [
            Action::Send(Message::Notification(NotificationMsg {
                code: 5,
                subcode: 1,
                ..
            })),
            ..
        ]
    ));
    // OPEN 在 Established（重放/对端重启）
    let mut fsm = established();
    let acts = fsm.on_message(Message::Open(peer_open(90)));
    assert!(matches!(
        &acts[..],
        [
            Action::Send(Message::Notification(NotificationMsg {
                code: 5,
                subcode: 1,
                ..
            })),
            ..
        ]
    ));
    // RouteRefresh 在非 Established
    let mut fsm = BgpFsm::new(local());
    fsm.start();
    fsm.on_tcp_established();
    let acts = fsm.on_message(Message::RouteRefresh(RouteRefreshMsg {
        afi: AFI_IPV4,
        safi: 1,
    }));
    assert!(matches!(
        &acts[..],
        [Action::Send(Message::Notification(_)), _]
    ));
}

#[test]
fn notification_received_and_tcp_closed_go_idle() {
    let mut fsm = established();
    let acts = fsm.on_message(Message::Notification(NotificationMsg {
        code: 6,
        subcode: 0,
        data: vec![],
    }));
    assert_eq!(acts, vec![Action::Close]);
    assert_eq!(fsm.state(), State::Idle);

    let mut fsm = established();
    fsm.on_tcp_closed();
    assert_eq!(fsm.state(), State::Idle);
}

#[test]
fn cease_and_max_prefix_close_cleanly() {
    let mut fsm = established();
    let acts = fsm.cease();
    assert!(matches!(&acts[0], Action::Send(Message::Notification(n)) if n.code == 6));
    assert_eq!(fsm.state(), State::Idle);

    let mut fsm = established();
    let acts = fsm.notify_max_prefix();
    assert!(
        matches!(&acts[..], [Action::Send(Message::Notification(n)), Action::Close]
            if n.code == 6 && n.subcode == 1)
    );
    assert_eq!(fsm.state(), State::Idle);
}

#[test]
fn route_refresh_in_established_no_op_to_fsm() {
    let mut fsm = established();
    let acts = fsm.on_message(Message::RouteRefresh(RouteRefreshMsg {
        afi: AFI_IPV6,
        safi: SAFI_UNICAST,
    }));
    assert!(acts.is_empty());
    assert_eq!(fsm.state(), State::Established);
}
