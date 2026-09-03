//! wire codec 测试：RFC golden vectors（字节级）、roundtrip、畸形语料（零 panic）。

use std::net::{IpAddr, Ipv4Addr};

use super::*;
use landscape_rill_core::route::Prefix;

fn p(cidr: &str) -> Prefix {
    Prefix::parse(cidr).unwrap()
}

fn marker() -> Vec<u8> {
    vec![0xffu8; 16] // BGP marker = 全 1（RFC 4271 §4.1）
}

// --- golden vectors（字节级，RFC 4271/4760/6793/2918 逐字节绑定） ---

#[test]
fn golden_keepalive() {
    let mut out = Vec::new();
    Message::Keepalive.encode(&mut out).unwrap();
    let expect = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x00, 0x13, 0x04,
    ];
    assert_eq!(out, expect);
    assert!(matches!(decode(&out).unwrap(), Message::Keepalive));
}

#[test]
fn golden_open_4byte_asn_with_capabilities() {
    let open = OpenMsg {
        as4: 4242420001,
        hold_time: 90,
        bgp_id: Ipv4Addr::new(172, 20, 100, 1),
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
            Capability::FourOctetAs(4242420001),
        ],
    };
    let mut out = Vec::new();
    Message::Open(open.clone()).encode(&mut out).unwrap();
    let expect = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x00, 0x33, 0x01, 0x04, 0x5B, 0xA0, 0x00, 0x5A, 0xAC, 0x14, 0x64, 0x01, 0x16, 0x02,
        0x14, 0x01, 0x04, 0x00, 0x01, 0x00, 0x01, 0x01, 0x04, 0x00, 0x02, 0x00, 0x01, 0x02, 0x00,
        0x41, 0x04, 0xFC, 0xDE, 0x31, 0x21,
    ];
    assert_eq!(out.len(), 51);
    assert_eq!(out, expect);
    match decode(&out).unwrap() {
        Message::Open(got) => {
            // MyAS 字段 = AS_TRANS（>65535），真实 ASN 经 capability 65 恢复
            assert_eq!(got.as4, 4242420001);
            assert_eq!(got.hold_time, 90);
            assert_eq!(got.bgp_id, Ipv4Addr::new(172, 20, 100, 1));
            assert_eq!(got.capabilities, open.capabilities);
        }
        other => panic!("not open: {other:?}"),
    }
}

#[test]
fn golden_open_16bit_asn_no_as_trans() {
    let open = OpenMsg {
        as4: 65001,
        hold_time: 180,
        bgp_id: Ipv4Addr::new(10, 0, 0, 1),
        capabilities: vec![Capability::FourOctetAs(65001)],
    };
    let mut out = Vec::new();
    Message::Open(open).encode(&mut out).unwrap();
    // MyAS 字段 = 0xFDE9（65001 原值，不替换 AS_TRANS）
    assert_eq!(&out[20..22], &[0xFD, 0xE9]);
}

#[test]
fn golden_update_v4_withdraw_and_announce() {
    let update = UpdateMsg {
        withdrawn: vec![p("172.20.100.0/24")],
        attrs: vec![
            PathAttr::Origin(0),
            PathAttr::AsPath(vec![Segment {
                set: false,
                asns: vec![65001],
            }]),
            PathAttr::NextHop(Ipv4Addr::new(172, 20, 100, 2)),
        ],
        announced: vec![p("172.20.200.0/24")],
    };
    let mut out = Vec::new();
    Message::Update(update).encode(&mut out).unwrap();
    // AS_PATH 4B-capable 会话 = 4 字节编码（RFC 6793，attr len 06，总长 51）
    let expect = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x00, 0x33, 0x02, 0x00, 0x04, 0x18, 0xAC, 0x14, 0x64, 0x00, 0x14, 0x40, 0x01, 0x01,
        0x00, 0x40, 0x02, 0x06, 0x02, 0x01, 0x00, 0x00, 0xFD, 0xE9, 0x40, 0x03, 0x04, 0xAC, 0x14,
        0x64, 0x02, 0x18, 0xAC, 0x14, 0xC8,
    ];
    assert_eq!(out, expect);
    match decode(&out).unwrap() {
        Message::Update(got) => {
            assert_eq!(got.withdrawn, vec![p("172.20.100.0/24")]);
            assert_eq!(got.announced, vec![p("172.20.200.0/24")]);
            assert_eq!(
                got.attrs,
                vec![
                    PathAttr::Origin(0),
                    PathAttr::AsPath(vec![Segment {
                        set: false,
                        asns: vec![65001]
                    }]),
                    PathAttr::NextHop(Ipv4Addr::new(172, 20, 100, 2)),
                ]
            );
        }
        other => panic!("not update: {other:?}"),
    }
}

#[test]
fn golden_update_mp_reach_v6() {
    let update = UpdateMsg {
        withdrawn: vec![],
        attrs: vec![PathAttr::MpReach {
            afi: AFI_IPV6,
            safi: SAFI_UNICAST,
            next_hop: "fd00::1:2".parse().unwrap(),
            nlri: vec![p("fd00:100::/48")],
        }],
        announced: vec![],
    };
    let mut out = Vec::new();
    Message::Update(update).encode(&mut out).unwrap();
    let expect = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x00, 0x36, 0x02, 0x00, 0x00, 0x00, 0x1F, 0x80, 0x0E, 0x1C, 0x00, 0x02, 0x01, 0x10,
        0xFD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x02, 0x00, 0x30, 0xFD, 0x00, 0x01, 0x00, 0x00, 0x00,
    ];
    assert_eq!(out, expect);
    match decode(&out).unwrap() {
        Message::Update(got) => assert_eq!(
            got.attrs,
            vec![PathAttr::MpReach {
                afi: AFI_IPV6,
                safi: SAFI_UNICAST,
                next_hop: "fd00::1:2".parse().unwrap(),
                nlri: vec![p("fd00:100::/48")],
            }]
        ),
        other => panic!("not update: {other:?}"),
    }
}

#[test]
fn golden_end_of_rib() {
    // EOR = 空 UPDATE（withdrawn=0 attrs=0 nlri=0）
    let update = UpdateMsg {
        withdrawn: vec![],
        attrs: vec![],
        announced: vec![],
    };
    let mut out = Vec::new();
    Message::Update(update).encode(&mut out).unwrap();
    let expect = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x00, 0x17, 0x02, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(out, expect);
}

#[test]
fn golden_notification_and_route_refresh() {
    let mut out = Vec::new();
    Message::Notification(NotificationMsg {
        code: 6,
        subcode: 3,
        data: vec![],
    })
    .encode(&mut out)
    .unwrap();
    let expect = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x00, 0x15, 0x03, 0x06, 0x03,
    ];
    assert_eq!(out, expect);
    let got = decode(&out).unwrap();
    assert_eq!(
        got,
        Message::Notification(NotificationMsg {
            code: 6,
            subcode: 3,
            data: vec![]
        })
    );

    let mut out = Vec::new();
    Message::RouteRefresh(RouteRefreshMsg {
        afi: AFI_IPV6,
        safi: SAFI_UNICAST,
    })
    .encode(&mut out)
    .unwrap();
    let expect = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x00, 0x17, 0x05, 0x00, 0x02, 0x00, 0x01,
    ];
    assert_eq!(out, expect);
    assert_eq!(
        decode(&out).unwrap(),
        Message::RouteRefresh(RouteRefreshMsg {
            afi: AFI_IPV6,
            safi: SAFI_UNICAST
        })
    );
}

// --- 语义细节 ---

#[test]
fn as_path_4byte_encoding_on_capable_session() {
    let update = UpdateMsg {
        withdrawn: vec![],
        attrs: vec![PathAttr::AsPath(vec![Segment {
            set: false,
            asns: vec![4242420001],
        }])],
        announced: vec![p("10.99.0.0/24")],
    };
    let mut out = Vec::new();
    Message::Update(update).encode(&mut out).unwrap();
    // RFC 6793：4B-capable 会话 AS_PATH 直接 4 字节编码（FRR 互操作实测同此），
    // roundtrip 无 AS_TRANS 占位
    match decode(&out).unwrap() {
        Message::Update(got) => {
            assert_eq!(
                got.attrs[0],
                PathAttr::AsPath(vec![Segment {
                    set: false,
                    asns: vec![4242420001],
                }])
            );
        }
        other => panic!("not update: {other:?}"),
    }
}

#[test]
fn as_path_narrow_fallback_for_2byte_attributes() {
    // 2 字节编码的 AS_PATH（老会话形态）须仍可解析（宽解非精确消费 → 回退窄解）
    let mut msg = marker();
    let attrs = [0x40, 0x02, 0x04, 0x02, 0x01, 0xFD, 0xE9];
    let mut body = 0u16.to_be_bytes().to_vec();
    body.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
    body.extend_from_slice(&attrs);
    msg.extend_from_slice(&(19 + body.len() as u16).to_be_bytes());
    msg.push(TYPE_UPDATE);
    msg.extend_from_slice(&body);
    match decode(&msg).unwrap() {
        Message::Update(got) => assert_eq!(
            got.attrs[0],
            PathAttr::AsPath(vec![Segment {
                set: false,
                asns: vec![65001]
            }])
        ),
        other => panic!("not update: {other:?}"),
    }
}

#[test]
fn mp_reach_v6_with_link_local_takes_global() {
    // 32B next hop = global + link-local（RFC 4760 §3），取前 16B global
    let mut value = vec![0, 2, 1, 32];
    value.extend_from_slice(&[0xfd; 16]);
    value.extend_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    value.push(0);
    value.push(128);
    value.extend_from_slice(&[0xfd; 16]);
    // extended length 标志（0x10）+ optional（0x80）
    let mut attrs = vec![0x90, 14];
    attrs.extend_from_slice(&(value.len() as u16).to_be_bytes());
    attrs.extend_from_slice(&value);
    let mut msg = marker();
    let mut body = 0u16.to_be_bytes().to_vec();
    body.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
    body.extend_from_slice(&attrs);
    msg.extend_from_slice(&(19 + body.len() as u16).to_be_bytes());
    msg.push(TYPE_UPDATE);
    msg.extend_from_slice(&body);
    match decode(&msg).unwrap() {
        Message::Update(got) => assert_eq!(
            got.attrs[0],
            PathAttr::MpReach {
                afi: AFI_IPV6,
                safi: SAFI_UNICAST,
                next_hop: "fdfd:fdfd:fdfd:fdfd:fdfd:fdfd:fdfd:fdfd".parse().unwrap(),
                nlri: vec![p("fdfd:fdfd:fdfd:fdfd:fdfd:fdfd:fdfd:fdfd/128")],
            }
        ),
        other => panic!("not update: {other:?}"),
    }
}

#[test]
fn mp_reach_ipv4_mapped_next_hop_normalized() {
    // FRR 对 v4 NLRI 经 MP_REACH 常发 ::ffff:a.b.c.d —— 归一为 v4
    let mp = [
        0, 1, 1, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 172, 20, 100, 2, 0, 24, 172, 20, 200,
    ];
    let mut attrs = vec![0x80, 14, mp.len() as u8];
    attrs.extend_from_slice(&mp);
    let mut msg = marker();
    let mut body = 0u16.to_be_bytes().to_vec();
    body.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
    body.extend_from_slice(&attrs);
    msg.extend_from_slice(&(19 + body.len() as u16).to_be_bytes());
    msg.push(TYPE_UPDATE);
    msg.extend_from_slice(&body);
    match decode(&msg).unwrap() {
        Message::Update(got) => assert_eq!(
            got.attrs[0],
            PathAttr::MpReach {
                afi: AFI_IPV4,
                safi: SAFI_UNICAST,
                next_hop: IpAddr::V4(Ipv4Addr::new(172, 20, 100, 2)),
                nlri: vec![p("172.20.200.0/24")],
            }
        ),
        other => panic!("not update: {other:?}"),
    }
}

#[test]
fn unknown_optional_attribute_skipped_well_known_rejected() {
    let base = |attr: Vec<u8>| {
        let mut msg = marker();
        let mut body = 0u16.to_be_bytes().to_vec();
        body.extend_from_slice(&(attr.len() as u16).to_be_bytes());
        body.extend_from_slice(&attr);
        msg.extend_from_slice(&(19 + body.len() as u16).to_be_bytes());
        msg.push(TYPE_UPDATE);
        msg.extend_from_slice(&body);
        decode(&msg)
    };
    // 未知 optional (0x80, type 99) → 跳过
    let ok = base(vec![0x80, 99, 2, 0xaa, 0xbb]).unwrap();
    assert!(matches!(ok, Message::Update(_)));
    // 未知 well-known (0x40, type 99) → 拒绝
    assert!(matches!(
        base(vec![0x40, 99, 2, 0xaa, 0xbb]),
        Err(WireError::UnknownWellKnown(99))
    ));
}

#[test]
fn encode_rejects_v6_in_v4_nlri_fields() {
    let update = UpdateMsg {
        withdrawn: vec![],
        attrs: vec![],
        announced: vec![p("fd00::/8")],
    };
    let mut out = Vec::new();
    assert!(matches!(
        Message::Update(update).encode(&mut out),
        Err(WireError::BadUpdate)
    ));
}

#[test]
fn extended_length_attribute_roundtrip() {
    // 单属性值 > 255B（100 个 ASN 的 AS_SEQUENCE）：flags 需 ext 标志（0x10）+ 2B 长度
    let asns: Vec<u32> = (65001..65101).collect();
    let update = UpdateMsg {
        withdrawn: vec![],
        attrs: vec![PathAttr::AsPath(vec![Segment {
            set: false,
            asns: asns.clone(),
        }])],
        announced: vec![p("10.99.0.0/24")],
    };
    let mut out = Vec::new();
    Message::Update(update).encode(&mut out).unwrap();
    // attr 头：flags 0x40 | 0x10（well-known + extended length）,type 2
    let pos = out.windows(2).position(|w| w == [0x50, 0x02]).unwrap();
    assert_eq!(out[pos + 2..pos + 4], [0x01, 0x92]); // len = 0x0192 = 402 > 255
    match decode(&out).unwrap() {
        Message::Update(got) => assert_eq!(
            got.attrs[0],
            PathAttr::AsPath(vec![Segment { set: false, asns }])
        ),
        other => panic!("not update: {other:?}"),
    }
}

#[test]
fn oversized_message_rejected_with_too_long() {
    // NLRI 塞到超过 4096 上限：每个 /24 NLRI 4B，2000 条 ≈ 8KB body
    let announced: Vec<Prefix> = (0..2000u32)
        .map(|i| p(&format!("10.{}.{}.0/24", i / 256, i % 256)))
        .collect();
    let update = UpdateMsg {
        withdrawn: vec![],
        attrs: vec![PathAttr::Origin(0), PathAttr::NextHop(Ipv4Addr::LOCALHOST)],
        announced,
    };
    let mut out = Vec::new();
    assert!(matches!(
        Message::Update(update).encode(&mut out),
        Err(WireError::TooLong)
    ));
}

#[test]
fn frame_reader_reassembles_split_messages() {
    let mut wire = Vec::new();
    Message::Keepalive.encode(&mut wire).unwrap();
    Message::Notification(NotificationMsg {
        code: 6,
        subcode: 3,
        data: vec![1, 2, 3],
    })
    .encode(&mut wire)
    .unwrap();
    let mut reader = FrameReader::default();
    let mut out = Vec::new();
    // 逐字节喂入（最碎分片）
    for b in &wire {
        reader.feed(std::slice::from_ref(b), &mut out).unwrap();
    }
    assert_eq!(out.len(), 2);
    assert_eq!(out[0], Message::Keepalive);
    assert_eq!(
        out[1],
        Message::Notification(NotificationMsg {
            code: 6,
            subcode: 3,
            data: vec![1, 2, 3]
        })
    );
    // 同帧内多消息 + 帧后半段留缓冲（keepalive 19B 已完整，notification 缺尾）
    let mut out = Vec::new();
    let mut reader = FrameReader::default();
    reader.feed(&wire[..30], &mut out).unwrap();
    assert_eq!(out.len(), 1);
    reader.feed(&wire[30..], &mut out).unwrap();
    assert_eq!(out.len(), 2);
}

// --- 畸形语料：任何输入不 panic，错误只经 Result（SEC-08 同型断言） ---

fn corpus() -> Vec<Vec<u8>> {
    let mut v: Vec<Vec<u8>> = Vec::new();
    let mut wire = Vec::new();
    Message::Open(OpenMsg {
        as4: 4242420001,
        hold_time: 90,
        bgp_id: Ipv4Addr::new(172, 20, 100, 1),
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
            Capability::FourOctetAs(4242420001),
        ],
    })
    .encode(&mut wire)
    .unwrap();
    Message::Update(UpdateMsg {
        withdrawn: vec![p("172.20.100.0/24")],
        attrs: vec![
            PathAttr::Origin(0),
            PathAttr::AsPath(vec![Segment {
                set: false,
                asns: vec![65001],
            }]),
            PathAttr::NextHop(Ipv4Addr::new(172, 20, 100, 2)),
            PathAttr::MpReach {
                afi: AFI_IPV6,
                safi: SAFI_UNICAST,
                next_hop: "fd00::1:2".parse().unwrap(),
                nlri: vec![p("fd00:100::/48")],
            },
            PathAttr::Communities(vec![0xfd00_0001, 0xffff_fffb]),
        ],
        announced: vec![p("172.20.200.0/24")],
    })
    .encode(&mut wire)
    .unwrap();
    // 1. 截断：每个有效消息的每个前缀
    for n in 0..wire.len() {
        v.push(wire[..n].to_vec());
    }
    // 2. 每字节位翻转
    for i in 0..wire.len() {
        let mut m = wire.clone();
        m[i] ^= 0xff;
        v.push(m);
    }
    // 3. 长度字段攻击：0 / 过大 / 超声明
    for len in [0u16, 1, 18, 4097, 65535] {
        let mut m = vec![0u8; 32];
        m[16..18].copy_from_slice(&len.to_be_bytes());
        m[18] = TYPE_UPDATE;
        v.push(m);
    }
    let mut over = wire.clone();
    over[16..18].copy_from_slice(&65535u16.to_be_bytes());
    v.push(over);
    let mut short = wire.clone();
    short.truncate(30);
    short[16..18].copy_from_slice(&(wire.len() as u16).to_be_bytes());
    v.push(short);
    // 4. marker 破坏
    let mut bad_marker = wire.clone();
    bad_marker[7] = 1;
    v.push(bad_marker);
    // 5. 未知消息类型 / NLRI 超长
    let mut bad_ty = vec![0xffu8; 19];
    bad_ty[18] = 99;
    v.push(bad_ty);
    let mut long_nlri = marker();
    long_nlri.extend_from_slice(&[0, 25, 2, 0, 0, 0, 0, 33, 0xAC]);
    v.push(long_nlri);
    // 6. 属性长度攻击（extended 长度声明远超实际，截断）
    let mut bad_attr = marker();
    bad_attr.extend_from_slice(&[0, 27, 2, 0, 0, 0, 4, 0x50, 0x01, 0xFF, 0x00]);
    v.push(bad_attr);
    v
}

#[test]
fn malformed_corpus_never_panics() {
    for input in corpus() {
        // decode 整帧
        let _ = decode(&input);
        // FrameReader 分片喂入（1/2/3 字节粒度）
        for chunk in [1usize, 2, 3] {
            let mut reader = FrameReader::default();
            let mut out = Vec::new();
            let result = input
                .chunks(chunk)
                .try_for_each(|c| reader.feed(c, &mut out));
            assert!(result.is_ok() || result.is_err());
        }
    }
}

#[test]
fn frame_reader_fails_closed_on_garbage() {
    let mut reader = FrameReader::default();
    let mut out = Vec::new();
    let mut garbage = vec![0xaau8; 100];
    garbage[16..18].copy_from_slice(&25u16.to_be_bytes());
    garbage[18] = TYPE_KEEPALIVE;
    assert!(matches!(
        reader.feed(&garbage, &mut out),
        Err(WireError::BadMarker)
    ));
    let mut reader = FrameReader::default();
    let mut out = Vec::new();
    let mut huge = marker();
    huge.extend_from_slice(&65535u16.to_be_bytes());
    huge.push(TYPE_KEEPALIVE);
    assert!(matches!(
        reader.feed(&huge, &mut out),
        Err(WireError::BadLength(65535))
    ));
}

#[test]
fn roundtrip_all_message_kinds() {
    let msgs = vec![
        Message::Open(OpenMsg {
            as4: 4242420001,
            hold_time: 90,
            bgp_id: Ipv4Addr::new(172, 20, 100, 1),
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
                Capability::FourOctetAs(4242420001),
            ],
        }),
        Message::Update(UpdateMsg {
            withdrawn: vec![p("172.20.100.0/24"), p("0.0.0.0/0")],
            attrs: vec![
                PathAttr::Origin(2),
                // wire 语义：4B-capable 会话 AS_PATH 直接 4 字节编码，roundtrip 精确
                PathAttr::AsPath(vec![
                    Segment {
                        set: false,
                        asns: vec![65001, 4242420002],
                    },
                    Segment {
                        set: true,
                        asns: vec![64512],
                    },
                ]),
                PathAttr::As4Path(vec![
                    Segment {
                        set: false,
                        asns: vec![65001, 4242420002],
                    },
                    Segment {
                        set: true,
                        asns: vec![64512],
                    },
                ]),
                PathAttr::NextHop(Ipv4Addr::new(172, 20, 100, 2)),
                PathAttr::MpReach {
                    afi: AFI_IPV6,
                    safi: SAFI_UNICAST,
                    next_hop: "fd00::1:2".parse().unwrap(),
                    nlri: vec![p("fd00:100::/48"), p("fd42:d42::/64")],
                },
                PathAttr::MpUnreach {
                    afi: AFI_IPV6,
                    safi: SAFI_UNICAST,
                    nlri: vec![p("fd00:200::/48")],
                },
                // decode 规范化：多次 Communities 合并、置于尾部（只携带不解释）
                PathAttr::Communities(vec![0xfd00_0001, 0xffff_fffb]),
            ],
            announced: vec![p("172.20.200.0/24")],
        }),
        Message::Notification(NotificationMsg {
            code: 6,
            subcode: 3,
            data: vec![9, 9],
        }),
        Message::Keepalive,
        Message::RouteRefresh(RouteRefreshMsg {
            afi: AFI_IPV4,
            safi: SAFI_UNICAST,
        }),
    ];
    for m in msgs {
        let mut wire = Vec::new();
        m.encode(&mut wire).unwrap();
        assert_eq!(decode(&wire).unwrap(), m);
    }
}
