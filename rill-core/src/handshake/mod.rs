//! Noise_XX 握手状态机与会话（FRAME_HEADER §2.3/§2.4 强制规格）
//!
//! 纯逻辑模块：无 tokio/io/网络类型，只做字节进出。帧头/传输在 legs/mesh 胶水层。
//! - 握手载荷布局：msg1 = 目标 node_id(4B) + Noise 消息体；msg3 = 身份绑定(64B) + 会话盐(4B) + Noise 消息体
//! - prologue = network_id(4B) || 帧头协议版本(1B)，防跨网络/跨版本会话混淆
//! - 双保险：msg1 目标校验（防重定向）+ msg3 身份绑定验证/发起方交叉验证（防冒充）
//! - 会话密钥：snow split 输出 (k1, k2)，k1 = 发起方→响应方，k2 = 响应方→发起方
//! - rekey：显式触发（定时/控制面事件），旧 rx 密钥保留 5s 残留期，双重放窗口并存

pub mod error;
pub use error::{HandshakeError, OpenError};

use crate::frame::{open_frame, MeshFrameHeader, OpenError as FrameOpenError, ReplayWindow};
use hkdf::Hkdf;
use sha2::Sha256;
use snow::{Builder, HandshakeState};
use std::time::{Duration, Instant};

pub const SESSION_KEY_LEN: usize = 32;
pub const NODE_ID_LEN: usize = 4;
pub const SALT_LEN: usize = 4;
pub const BINDING_LEN: usize = 64;
pub const PROLOGUE_LEN: usize = 5;
pub const REKEY_INFO: &[u8] = b"mesh-rekey-v1";
pub const SESSION_INFO: &[u8] = b"mesh-session-v1";
pub const REKEY_RESIDUE: Duration = Duration::from_secs(5);

pub const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_SHA256";

/// Noise 消息体长度（XX 模式，snow 0.10 线格式实测：空载荷也带尾 tag 16B）
/// msg1 = e(32)；msg2 = e(32) + s(32+16) + 空载荷 tag(16) = 96；msg3 = s(48) + 空载荷 tag(16) = 64
pub const MSG1_BODY_LEN: usize = 32;
pub const MSG2_BODY_LEN: usize = 96;
pub const MSG3_BODY_LEN: usize = 64;

/// 帧载荷长度（不含帧头）：msg1 = 目标(4) + 体(32)；msg3 = 绑定(64) + 盐(4) + 体(64)
pub const MSG1_PAYLOAD_LEN: usize = NODE_ID_LEN + MSG1_BODY_LEN;
pub const MSG2_PAYLOAD_LEN: usize = MSG2_BODY_LEN;
pub const MSG3_PAYLOAD_LEN: usize = BINDING_LEN + SALT_LEN + MSG3_BODY_LEN;

pub fn prologue(network_id: u32, version: u8) -> [u8; PROLOGUE_LEN] {
    let mut out = [0u8; PROLOGUE_LEN];
    out[..NODE_ID_LEN].copy_from_slice(&network_id.to_be_bytes());
    out[NODE_ID_LEN] = version;
    out
}

fn noise_params() -> Result<snow::params::NoiseParams, HandshakeError> {
    NOISE_PATTERN.parse().map_err(HandshakeError::Noise)
}

/// 将 split 原始密钥与握手哈希绑定（HKDF salt = h）。
/// snow 的 split 实现不把 handshake hash 折进会话密钥（Noise rev 33 之前的语义）——
/// 不绑定则 prologue（network_id/版本）不影响会话密钥，跨网络/跨版本混淆防护被绕过。
/// 绑定后：prologue 不同 → h 不同 → 会话密钥不同 → 传输层解密失败（安全属性在传输层成立）。
fn bind_transcript(
    split_key: &[u8; SESSION_KEY_LEN],
    handshake_hash: &[u8],
) -> [u8; SESSION_KEY_LEN] {
    let mut out = [0u8; SESSION_KEY_LEN];
    Hkdf::<Sha256>::new(Some(handshake_hash), split_key)
        .expand(SESSION_INFO, &mut out)
        .expect("hkdf expand");
    out
}

/// 会话密钥：salt 由发起方生成随 msg3 携带；tx/rx 按方向独立
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionKeys {
    pub salt: u32,
    pub tx_key: [u8; SESSION_KEY_LEN],
    pub rx_key: [u8; SESSION_KEY_LEN],
}

/// 节点侧握手上下文（MeshData 注入；数据字段，无 IO）
#[derive(Debug, Clone)]
pub struct HandshakeContext {
    pub network_id: u32,
    pub version: u8,
    pub local_static: [u8; SESSION_KEY_LEN],
    pub identity_binding: Vec<u8>,
}

/// 发起方握手状态机
pub struct HandshakeInitiator {
    state: HandshakeState,
    target_node_id: u32,
    identity_binding: Vec<u8>,
    salt: u32,
    expected_peer_static: [u8; SESSION_KEY_LEN],
    sent_msg1: bool,
    sent_msg3: bool,
}

impl HandshakeInitiator {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        local_static: &[u8; SESSION_KEY_LEN],
        network_id: u32,
        version: u8,
        target_node_id: u32,
        identity_binding: &[u8],
        salt: u32,
        expected_peer_static: &[u8; SESSION_KEY_LEN],
    ) -> Result<Self, HandshakeError> {
        if identity_binding.len() != BINDING_LEN {
            return Err(HandshakeError::MalformedPayload);
        }
        let state = Builder::new(noise_params()?)
            .prologue(&prologue(network_id, version))
            .map_err(HandshakeError::Noise)?
            .local_private_key(local_static)
            .map_err(HandshakeError::Noise)?
            .build_initiator()
            .map_err(HandshakeError::Noise)?;
        Ok(Self {
            state,
            target_node_id,
            identity_binding: identity_binding.to_vec(),
            salt,
            expected_peer_static: *expected_peer_static,
            sent_msg1: false,
            sent_msg3: false,
        })
    }

    pub fn target(&self) -> u32 {
        self.target_node_id
    }

    /// msg1 帧载荷：目标 node_id(4B) + Noise 第一条消息体
    pub fn write_msg1(&mut self) -> Result<Vec<u8>, HandshakeError> {
        if self.sent_msg1 {
            return Err(HandshakeError::WrongStep);
        }
        let mut body = [0u8; MSG1_BODY_LEN + crate::frame::TAG_LEN];
        let n = self
            .state
            .write_message(&[], &mut body)
            .map_err(HandshakeError::Noise)?;
        self.sent_msg1 = true;
        let mut out = Vec::with_capacity(MSG1_PAYLOAD_LEN);
        out.extend_from_slice(&self.target_node_id.to_be_bytes());
        out.extend_from_slice(&body[..n]);
        Ok(out)
    }

    /// 接收 msg2，返回 msg3 帧载荷：身份绑定(64B) + 会话盐(4B) + Noise 第三条消息体
    pub fn read_msg2(&mut self, payload: &[u8]) -> Result<Vec<u8>, HandshakeError> {
        if !self.sent_msg1 || self.sent_msg3 {
            return Err(HandshakeError::WrongStep);
        }
        if payload.len() != MSG2_PAYLOAD_LEN {
            return Err(HandshakeError::MalformedPayload);
        }
        self.state
            .read_message(payload, &mut [])
            .map_err(HandshakeError::Noise)?;
        let mut body = [0u8; MSG3_BODY_LEN + crate::frame::TAG_LEN];
        let n = self
            .state
            .write_message(&[], &mut body)
            .map_err(HandshakeError::Noise)?;
        self.sent_msg3 = true;
        let mut out = Vec::with_capacity(MSG3_PAYLOAD_LEN);
        out.extend_from_slice(&self.identity_binding);
        out.extend_from_slice(&self.salt.to_be_bytes());
        out.extend_from_slice(&body[..n]);
        Ok(out)
    }

    /// msg3 发送完成后：交叉验证响应方静态公钥（§2.3 第二道防线），split 出会话密钥。
    /// 静态验证只发生在握手完成时，不发生在 msg2（§2.4）。
    pub fn finish(&mut self) -> Result<SessionKeys, HandshakeError> {
        if !self.sent_msg3 {
            return Err(HandshakeError::WrongStep);
        }
        let remote_static: [u8; SESSION_KEY_LEN] = match self.state.get_remote_static() {
            Some(rs) if rs.len() == SESSION_KEY_LEN => rs.try_into().unwrap(),
            _ => return Err(HandshakeError::PeerStaticMismatch),
        };
        if remote_static != self.expected_peer_static {
            return Err(HandshakeError::PeerStaticMismatch);
        }
        let h = self.state.get_handshake_hash().to_vec();
        let (k1, k2) = self.state.dangerously_get_raw_split();
        Ok(SessionKeys {
            salt: self.salt,
            tx_key: bind_transcript(&k1, &h),
            rx_key: bind_transcript(&k2, &h),
        })
    }
}

/// 响应方握手状态机
pub struct HandshakeResponder {
    state: HandshakeState,
    self_node_id: u32,
    read_msg1: bool,
    sent_msg2: bool,
}

impl HandshakeResponder {
    pub fn new(
        local_static: &[u8; SESSION_KEY_LEN],
        network_id: u32,
        version: u8,
        self_node_id: u32,
    ) -> Result<Self, HandshakeError> {
        let state = Builder::new(noise_params()?)
            .prologue(&prologue(network_id, version))
            .map_err(HandshakeError::Noise)?
            .local_private_key(local_static)
            .map_err(HandshakeError::Noise)?
            .build_responder()
            .map_err(HandshakeError::Noise)?;
        Ok(Self {
            state,
            self_node_id,
            read_msg1: false,
            sent_msg2: false,
        })
    }

    /// 接收 msg1：载荷内目标 node_id ≠ 自己 → 拒绝（§2.3 第一道防线，防重定向）
    pub fn read_msg1(&mut self, payload: &[u8]) -> Result<(), HandshakeError> {
        if self.read_msg1 {
            return Err(HandshakeError::WrongStep);
        }
        if payload.len() != MSG1_PAYLOAD_LEN {
            return Err(HandshakeError::MalformedPayload);
        }
        let target = u32::from_be_bytes(payload[..NODE_ID_LEN].try_into().unwrap());
        if target != self.self_node_id {
            return Err(HandshakeError::WrongTarget);
        }
        self.state
            .read_message(&payload[NODE_ID_LEN..], &mut [])
            .map_err(HandshakeError::Noise)?;
        self.read_msg1 = true;
        Ok(())
    }

    /// msg2 帧载荷：Noise 第二条消息体（此阶段不做静态公钥验证，见 §2.4）
    pub fn write_msg2(&mut self) -> Result<Vec<u8>, HandshakeError> {
        if !self.read_msg1 || self.sent_msg2 {
            return Err(HandshakeError::WrongStep);
        }
        let mut body = [0u8; MSG2_BODY_LEN + crate::frame::TAG_LEN];
        let n = self
            .state
            .write_message(&[], &mut body)
            .map_err(HandshakeError::Noise)?;
        self.sent_msg2 = true;
        Ok(body[..n].to_vec())
    }

    /// 接收 msg3：校验发起方身份绑定（coordinator 签发 `node_id ⇔ 静态公钥`）。
    /// 绑定校验由 verify 注入（持 coordinator 公钥）——绑定中的静态公钥必须与
    /// Noise 握手实际使用的静态公钥一致（防绑定拷贝冒充），本模块与签名算法解耦。
    pub fn read_msg3<F>(
        &mut self,
        payload: &[u8],
        claimed_node_id: u32,
        verify: F,
    ) -> Result<SessionKeys, HandshakeError>
    where
        F: Fn(u32, &[u8; SESSION_KEY_LEN], &[u8]) -> bool,
    {
        if !self.sent_msg2 {
            return Err(HandshakeError::WrongStep);
        }
        if payload.len() != MSG3_PAYLOAD_LEN {
            return Err(HandshakeError::MalformedPayload);
        }
        let binding = &payload[..BINDING_LEN];
        let salt = u32::from_be_bytes(
            payload[BINDING_LEN..BINDING_LEN + SALT_LEN]
                .try_into()
                .unwrap(),
        );
        self.state
            .read_message(&payload[BINDING_LEN + SALT_LEN..], &mut [])
            .map_err(HandshakeError::Noise)?;
        let remote_static: [u8; SESSION_KEY_LEN] = match self.state.get_remote_static() {
            Some(rs) if rs.len() == SESSION_KEY_LEN => rs.try_into().unwrap(),
            _ => return Err(HandshakeError::BadBinding),
        };
        if !verify(claimed_node_id, &remote_static, binding) {
            return Err(HandshakeError::BadBinding);
        }
        let h = self.state.get_handshake_hash().to_vec();
        let (k1, k2) = self.state.dangerously_get_raw_split();
        Ok(SessionKeys {
            salt,
            tx_key: bind_transcript(&k2, &h),
            rx_key: bind_transcript(&k1, &h),
        })
    }
}

fn rekey_chain(key: &[u8; SESSION_KEY_LEN]) -> [u8; SESSION_KEY_LEN] {
    let mut out = [0u8; SESSION_KEY_LEN];
    Hkdf::<Sha256>::new(None, key)
        .expand(REKEY_INFO, &mut out)
        .expect("hkdf expand");
    out
}

struct OldRx {
    key: [u8; SESSION_KEY_LEN],
    window: ReplayWindow,
    expires_at: Instant,
}

/// 已建立会话：逐对独立密钥 + 方向计数器 + 重放窗口 + rekey 双窗口
pub struct Session {
    peer_node_id: u32,
    keys: SessionKeys,
    tx_counter: u32,
    rx_window: ReplayWindow,
    old_rx: Option<OldRx>,
}

impl Session {
    pub fn new(peer_node_id: u32, keys: SessionKeys) -> Self {
        Self {
            peer_node_id,
            keys,
            tx_counter: 0,
            rx_window: ReplayWindow::new(),
            old_rx: None,
        }
    }

    pub fn peer(&self) -> u32 {
        self.peer_node_id
    }

    pub fn keys(&self) -> &SessionKeys {
        &self.keys
    }

    /// 取下一帧 seq（方向计数器，不重用）
    pub fn next_seq(&mut self) -> u32 {
        let seq = self.tx_counter;
        self.tx_counter = self.tx_counter.wrapping_add(1);
        seq
    }

    /// AEAD 解密收尾：route_mac 校验（relay 已做一遍，此处兜底）+ 解密 + 重放窗口。
    /// rekey 后旧 rx 密钥在残留期内并存（在途/乱序旧包可解），过期销毁。
    pub fn open(
        &mut self,
        frame: &[u8],
        key_dst: &[u8],
        now: Instant,
    ) -> Result<(MeshFrameHeader, Vec<u8>), OpenError> {
        match open_frame(frame, key_dst, &self.keys.rx_key, self.keys.salt) {
            Ok((h, p)) => {
                if self.rx_window.check_and_mark(h.seq) {
                    Ok((h, p))
                } else {
                    Err(OpenError::Replay)
                }
            }
            Err(FrameOpenError::Aead(_)) => {
                let Some(old) = &mut self.old_rx else {
                    return Err(OpenError::Aead);
                };
                if now >= old.expires_at {
                    self.old_rx = None;
                    return Err(OpenError::Aead);
                }
                match open_frame(frame, key_dst, &old.key, self.keys.salt) {
                    Ok((h, p)) => {
                        if old.window.check_and_mark(h.seq) {
                            Ok((h, p))
                        } else {
                            Err(OpenError::Replay)
                        }
                    }
                    Err(_) => Err(OpenError::Aead),
                }
            }
            Err(e) => Err(e.into()),
        }
    }

    /// 显式 rekey（24h 定时 / 控制面事件触发）：两方向同时切到链下一把密钥。
    /// 旧 rx 密钥保留 REKEY_RESIDUE 残留期（双窗口并存），过期销毁。
    pub fn rekey(&mut self, now: Instant) {
        let old = OldRx {
            key: self.keys.rx_key,
            window: std::mem::take(&mut self.rx_window),
            expires_at: now + REKEY_RESIDUE,
        };
        self.keys.tx_key = rekey_chain(&self.keys.tx_key);
        self.keys.rx_key = rekey_chain(&self.keys.rx_key);
        self.rx_window = ReplayWindow::new();
        self.old_rx = Some(old);
    }
}

#[cfg(test)]
mod tests;
