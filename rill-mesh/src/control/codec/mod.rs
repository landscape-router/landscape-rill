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
}
