#![deny(unsafe_code)]

// pb-rs 生成代码（proto/ → OUT_DIR，不入库；mod.rs 含 pub mod control;）
pub mod wire {
    #![allow(unsafe_code)]
    include!(concat!(env!("OUT_DIR"), "/mod.rs"));
}

#[cfg(test)]
mod tests {
    use super::wire::control::RegisterRequest;
    use quick_protobuf::{MessageWrite, Writer};
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
    }
}
