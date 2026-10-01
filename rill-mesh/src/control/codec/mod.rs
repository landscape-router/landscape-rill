//! 控制面信封编解码（CONTROL_PLANE §3）：proto envelope ↔ 线格式帧

use crate::framing;
use landscape_rill_proto::wire::control::{Envelope, EnvelopeOwned, MsgType};
use quick_protobuf::{MessageWrite, Writer};
use std::borrow::Cow;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub fn envelope_bytes<T: MessageWrite>(msg_type: MsgType, msg: &T) -> Vec<u8> {
    let mut body = Vec::new();
    {
        let mut writer = Writer::new(&mut body);
        msg.write_message(&mut writer).unwrap();
    }
    let envelope = Envelope {
        msg_type,
        body: Cow::Owned(body),
    };
    let mut out = Vec::new();
    {
        let mut writer = Writer::new(&mut out);
        envelope.write_message(&mut writer).unwrap();
    }
    out
}

pub mod error;
pub use error::EnvelopeError;

pub fn parse_envelope(body: &[u8]) -> Result<(MsgType, Vec<u8>), EnvelopeError> {
    let owned = EnvelopeOwned::try_from(body.to_vec()).map_err(|_| EnvelopeError::Decode)?;
    Ok((owned.proto().msg_type, owned.proto().body.to_vec()))
}

pub fn envelope_body<T: MessageWrite>(msg: &T) -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut writer = Writer::new(&mut out);
        msg.write_message(&mut writer).unwrap();
    }
    out
}

pub async fn write_msg<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    msg_type: MsgType,
    body: &[u8],
) -> std::io::Result<()> {
    let envelope = Envelope {
        msg_type,
        body: Cow::Borrowed(body),
    };
    let mut out = Vec::new();
    {
        let mut w = Writer::new(&mut out);
        envelope
            .write_message(&mut w)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    }
    framing::write_frame(writer, &out).await
}

pub async fn read_envelope<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> std::io::Result<(MsgType, Vec<u8>)> {
    let body = framing::read_frame(reader).await?;
    parse_envelope(&body)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad envelope"))
}

/// 缓冲式读信封（取消安全，framing::read_frame_buf）：字节落在持久缓冲，
/// select! 取消在途读 future 不丢进度——节点 run loop 多路分派专用
pub async fn read_envelope_buf<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    buf: &mut bytes::BytesMut,
) -> std::io::Result<(MsgType, Vec<u8>)> {
    let body = framing::read_frame_buf(reader, buf).await?;
    parse_envelope(&body)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad envelope"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use landscape_rill_proto::wire::control::RegisterRequest;
    use quick_protobuf::{BytesReader, MessageRead};

    #[test]
    fn envelope_roundtrip() {
        let msg = RegisterRequest {
            auth_key: Cow::Borrowed("ak"),
            static_pubkey: Cow::Owned(vec![0x42; 32]),
            capabilities: 0x01,
            protocol_version: crate::control::PROTOCOL_VERSION,
            hostname: Cow::Borrowed(""),
            os: Cow::Borrowed(""),
            routes: vec![],
            version: Cow::Borrowed(""),
        };
        let bytes = envelope_bytes(MsgType::REGISTER, &msg);
        let (mt, inner) = parse_envelope(&bytes).unwrap();
        assert_eq!(mt, MsgType::REGISTER);
        let mut reader = BytesReader::from_bytes(&inner);
        let parsed = RegisterRequest::from_reader(&mut reader, &inner).unwrap();
        assert_eq!(parsed.auth_key, "ak");
        assert_eq!(parsed.capabilities, 0x01);
    }

    // ---- REQ-065：RouteSync/RouteMap 编解码（批量/增量/空）----

    #[test]
    fn route_sync_roundtrip_batch_incremental_empty() {
        use crate::control::client::MeshClient;
        use landscape_rill_proto::wire::control::RouteSync;
        let client = MeshClient::new([1; 32]);
        // 批量公告
        let bytes = client.route_sync(
            vec![
                ("172.20.100.0/24".into(), "172.20.100.2".into()),
                ("fd42:1::/48".into(), "fd00:100::2".into()),
            ],
            vec![],
        );
        let (mt, inner) = parse_envelope(&bytes).unwrap();
        assert_eq!(mt, MsgType::ROUTE_SYNC);
        let mut reader = BytesReader::from_bytes(&inner);
        let sync = RouteSync::from_reader(&mut reader, &inner).unwrap();
        assert_eq!(sync.announced.len(), 2);
        assert_eq!(sync.announced[0].prefix, "172.20.100.0/24");
        assert_eq!(sync.announced[1].next_hop, "fd00:100::2");
        assert!(sync.withdrawn.is_empty());
        // 增量（公告 + 撤销并存）
        let bytes = client.route_sync(
            vec![("10.1.0.0/24".into(), "10.1.0.1".into())],
            vec!["172.20.100.0/24".into()],
        );
        let (_, inner) = parse_envelope(&bytes).unwrap();
        let mut reader = BytesReader::from_bytes(&inner);
        let sync = RouteSync::from_reader(&mut reader, &inner).unwrap();
        assert_eq!(sync.announced.len(), 1);
        assert_eq!(sync.withdrawn, vec![Cow::Borrowed("172.20.100.0/24")]);
        // 空载荷（合法：窗口冲刷无可报）
        let bytes = client.route_sync(vec![], vec![]);
        let (_, inner) = parse_envelope(&bytes).unwrap();
        let mut reader = BytesReader::from_bytes(&inner);
        let sync = RouteSync::from_reader(&mut reader, &inner).unwrap();
        assert!(sync.announced.is_empty() && sync.withdrawn.is_empty());
    }

    #[test]
    fn route_map_roundtrip() {
        use landscape_rill_proto::wire::control::{RouteMap, RouteMapEntry, RouteMapOwned};
        let msg = RouteMap {
            version: 7,
            entries: vec![RouteMapEntry {
                prefix: Cow::Borrowed("172.20.100.0/24"),
                node_id: 3,
                next_hop: Cow::Borrowed("172.20.100.2"),
            }],
        };
        let bytes = envelope_bytes(MsgType::ROUTE_MAP, &msg);
        let (mt, inner) = parse_envelope(&bytes).unwrap();
        assert_eq!(mt, MsgType::ROUTE_MAP);
        let owned = RouteMapOwned::try_from(inner).unwrap();
        assert_eq!(owned.proto().version, 7);
        assert_eq!(owned.proto().entries.len(), 1);
        assert_eq!(owned.proto().entries[0].node_id, 3);
        assert_eq!(owned.proto().entries[0].prefix, "172.20.100.0/24");
        assert_eq!(owned.proto().entries[0].next_hop, "172.20.100.2");
    }

    // ---- 预认证解析语料（REQ-059 / SEC-08，CONTROL_PLANE §3.13）----
    // 定头两级解析（长度前缀 + Envelope 定头）对随机/变形输入只经 Result 返回

    fn xorshift(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    fn sample_envelope() -> Vec<u8> {
        let mut out = Vec::new();
        let mut w = Writer::new(&mut out);
        Envelope {
            msg_type: MsgType::HEARTBEAT,
            body: Cow::Borrowed(&[0x7u8; 8]),
        }
        .write_message(&mut w)
        .unwrap();
        out
    }

    #[test]
    fn parse_envelope_fuzz_corpus() {
        let mut s: u64 = 0xE4C0_0004;
        let mut buf = [0u8; 128];
        for _ in 0..2000 {
            // 纯随机字节
            let len = (xorshift(&mut s) % 129) as usize;
            for b in buf[..len].iter_mut() {
                *b = xorshift(&mut s) as u8;
            }
            let _ = parse_envelope(&buf[..len]);
        }
        // 合法 envelope 变形（1..=4 处翻转）
        let valid = sample_envelope();
        for _ in 0..2000 {
            let mut m = valid.clone();
            let flips = 1 + (xorshift(&mut s) % 4) as usize;
            for _ in 0..flips {
                let pos = xorshift(&mut s) as usize % m.len();
                m[pos] ^= (xorshift(&mut s) as u8) | 1;
            }
            let _ = parse_envelope(&m);
        }
    }

    #[tokio::test]
    async fn read_envelope_fuzz_corpus() {
        use crate::framing::MAX_MESSAGE_LEN;
        use tokio::io::duplex;
        let mut s: u64 = 0xD07_0005;
        for _ in 0..200 {
            let (mut a, mut b) = duplex(4096);
            // 超长帧声明 → InvalidData（先于 body 分配）
            let declared = MAX_MESSAGE_LEN + 1;
            framing::write_declared_len(&mut a, declared).await.unwrap();
            assert!(read_envelope(&mut b).await.is_err());
            // 帧内随机字节：Ok（合法信封）或 Err（坏信封）——只要求不 panic
            let n = (xorshift(&mut s) % 64) as usize;
            let garbage: Vec<u8> = (0..n).map(|_| xorshift(&mut s) as u8).collect();
            framing::write_frame(&mut a, &garbage).await.unwrap();
            let _ = read_envelope(&mut b).await;
        }
    }
}
