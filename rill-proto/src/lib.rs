#![deny(unsafe_code)]

// pb-rs 生成代码（proto/ → OUT_DIR，不入库；mod.rs 含 pub mod control;）
pub mod wire {
    #![allow(unsafe_code)]
    include!(concat!(env!("OUT_DIR"), "/mod.rs"));
}

#[cfg(test)]
mod tests {
    use super::wire::control::{Heartbeat, RegisterRequest, TelemetryPayload, TelemetryPeer};
    use quick_protobuf::{BytesReader, MessageRead, MessageWrite, Writer};
    use std::borrow::Cow;

    #[test]
    fn register_request_roundtrip() {
        let msg = RegisterRequest {
            auth_key: Cow::Borrowed("preauth-key-123"),
            static_pubkey: Cow::Owned(vec![0x42; 32]),
            capabilities: 0x0d,
            protocol_version: 1,
            hostname: Cow::Borrowed("edge-1"),
            os: Cow::Borrowed("linux"),
            routes: vec![Cow::Borrowed("10.0.0.0/24")],
            version: Cow::Borrowed("lrill 0.1.0"),
        };
        let mut out = Vec::new();
        let mut writer = Writer::new(&mut out);
        msg.write_message(&mut writer).unwrap();
        let owned = super::wire::control::RegisterRequestOwned::try_from(out).unwrap();
        let parsed = owned.proto();
        assert_eq!(parsed.auth_key, "preauth-key-123");
        assert_eq!(&*parsed.static_pubkey, &[0x42; 32]);
        assert_eq!(parsed.capabilities, 0x0d);
        assert_eq!(parsed.protocol_version, 1);
        assert_eq!(parsed.hostname, "edge-1");
        assert_eq!(parsed.os, "linux");
        assert_eq!(parsed.version, "lrill 0.1.0");
    }

    #[test]
    fn heartbeat_telemetry_roundtrip_and_backward_compat() {
        // REQ-052/§3.15：遥测载荷 optional——带载荷编解码 roundtrip；
        // 旧节点空 Heartbeat（无字段字节）解析 = telemetry None（向后兼容）
        let msg = Heartbeat {
            telemetry: Some(TelemetryPayload {
                peers: vec![TelemetryPeer {
                    node_id: 7,
                    tx_frames: 1,
                    tx_bytes: 2,
                    rx_frames: 3,
                    rx_bytes: 4,
                }],
                drop_global: 5,
                drops: vec![],
                direct: vec![],
            }),
        };
        let mut out = Vec::new();
        let mut writer = Writer::new(&mut out);
        msg.write_message(&mut writer).unwrap();
        let mut reader = BytesReader::from_bytes(&out);
        let parsed = Heartbeat::from_reader(&mut reader, &out).unwrap();
        let t = parsed.telemetry.unwrap();
        assert_eq!(t.peers[0].node_id, 7);
        assert_eq!((t.peers[0].tx_frames, t.peers[0].rx_bytes), (1, 4));
        assert_eq!(t.drop_global, 5);

        let empty: Vec<u8> = Vec::new();
        let mut reader = BytesReader::from_bytes(&empty);
        let legacy = Heartbeat::from_reader(&mut reader, &empty).unwrap();
        assert!(legacy.telemetry.is_none(), "旧节点空载荷 = None");
    }
}
