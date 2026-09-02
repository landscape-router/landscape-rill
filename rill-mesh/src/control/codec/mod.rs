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
        };
        let bytes = envelope_bytes(MsgType::REGISTER, &msg);
        let (mt, inner) = parse_envelope(&bytes).unwrap();
        assert_eq!(mt, MsgType::REGISTER);
        let mut reader = BytesReader::from_bytes(&inner);
        let parsed = RegisterRequest::from_reader(&mut reader, &inner).unwrap();
        assert_eq!(parsed.auth_key, "ak");
        assert_eq!(parsed.capabilities, 0x01);
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
