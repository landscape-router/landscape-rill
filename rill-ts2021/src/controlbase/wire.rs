//! 帧格式（对齐 tailscale control/controlbase/messages.go、conn.go）：
//! initiation  = 2B 版本(BE) + 1B 类型 + 2B 长度 + 96B Noise 消息体 = 101B
//! response    = 1B 类型 + 2B 长度 + 48B Noise 消息体 = 51B
//! record      = 1B 类型 + 2B 长度 + 密文（总长 ≤ 4096）
//! error       = 1B 类型 + 2B 长度 + 明文提示（未认证，仅公共提示）

use super::error::ControlbaseError;

pub const MSG_TYPE_INITIATION: u8 = 1;
pub const MSG_TYPE_RESPONSE: u8 = 2;
pub const MSG_TYPE_ERROR: u8 = 3;
pub const MSG_TYPE_RECORD: u8 = 4;

pub const INITIATION_HEADER_LEN: usize = 5;
pub const HEADER_LEN: usize = 3;

pub const INITIATION_NOISE_BODY_LEN: usize = 96;
pub const INITIATION_FRAME_LEN: usize = INITIATION_HEADER_LEN + INITIATION_NOISE_BODY_LEN;
pub const RESPONSE_NOISE_BODY_LEN: usize = 48;
pub const RESPONSE_FRAME_LEN: usize = HEADER_LEN + RESPONSE_NOISE_BODY_LEN;

/// 帧总长上限（含帧头，tailscale maxMessageSize）
pub const MAX_MESSAGE_SIZE: usize = 4096;
pub const MAX_CIPHERTEXT_SIZE: usize = MAX_MESSAGE_SIZE - HEADER_LEN;
pub const AEAD_TAG_LEN: usize = 16;
pub const MAX_PLAINTEXT_SIZE: usize = MAX_CIPHERTEXT_SIZE - AEAD_TAG_LEN;

pub struct FrameHeader {
    pub msg_type: u8,
    pub length: usize,
}

/// 3B 通用帧头解析（response/record/error），长度合法性由调用方按类型裁决
pub fn parse_header(header: &[u8]) -> Result<FrameHeader, ControlbaseError> {
    let &[msg_type, hi, lo, ..] = header else {
        return Err(ControlbaseError::MalformedFrame);
    };
    Ok(FrameHeader {
        msg_type,
        length: u16::from_be_bytes([hi, lo]) as usize,
    })
}

/// initiation 帧：5B 头 + 96B Noise 消息体（e(32) + s(48) + 空 payload tag(16)）
pub fn encode_initiation(
    version: u16,
    noise_body: &[u8; INITIATION_NOISE_BODY_LEN],
) -> [u8; INITIATION_FRAME_LEN] {
    let mut out = [0u8; INITIATION_FRAME_LEN];
    out[..2].copy_from_slice(&version.to_be_bytes());
    out[2] = MSG_TYPE_INITIATION;
    out[3..5].copy_from_slice(&(INITIATION_NOISE_BODY_LEN as u16).to_be_bytes());
    out[5..].copy_from_slice(noise_body);
    out
}

/// record 帧头：类型固定 RECORD，长度 = 密文长（含 tag）
pub fn encode_record_header(ciphertext_len: usize) -> [u8; HEADER_LEN] {
    [
        MSG_TYPE_RECORD,
        (ciphertext_len >> 8) as u8,
        ciphertext_len as u8,
    ]
}

/// record 帧头解析：类型必须为 RECORD，长度不超单帧上限（防未裁剪长度分配）
pub fn parse_record_header(header: &[u8]) -> Result<usize, ControlbaseError> {
    let h = parse_header(header)?;
    if h.msg_type != MSG_TYPE_RECORD || h.length > MAX_CIPHERTEXT_SIZE {
        return Err(ControlbaseError::MalformedFrame);
    }
    Ok(h.length)
}
