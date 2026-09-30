//! 客户端握手状态机与会话（纯逻辑，无 IO）。
//! 映射 tailscale controlbase：prologue = "Tailscale Control Protocol v{版本}"，
//! IK 前置消息 `<- s`（服务端静态 = control key）由 snow remote_public_key 承载；
//! msg1 Noise 体 96B（e32 + s48 + 空 payload tag16），msg2 48B（e32 + 空 payload tag16）。

use super::error::ControlbaseError;
use super::wire;
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit};
use snow::{Builder, HandshakeState};

/// tailscale 控制协议的 Noise 实例（TS2021_LEG §2.1）
pub const NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
const PROTOCOL_VERSION_PREFIX: &[u8] = b"Tailscale Control Protocol v";
/// tailscale invalidNonce（^uint64(0)）：到达即拒用（cipher exhausted）
const INVALID_NONCE: u64 = u64::MAX;

/// transport record AEAD：12B nonce = 4B 零 + 8B BE 计数（tailscale conn.go 同布局；
/// 注意 snow 内部 cipher 为 Noise 规范 LE 编码，与 Go 互操作必须 BE，故 transport 层
/// 经 dangerously_get_raw_split 取密钥后用 chacha20poly1305 直接实现）
fn record_nonce(counter: u64) -> [u8; 12] {
    let mut nb = [0u8; 12];
    nb[4..].copy_from_slice(&counter.to_be_bytes());
    nb
}

fn record_cipher(key: &[u8; 32]) -> ChaCha20Poly1305 {
    ChaCha20Poly1305::new(key.into())
}

/// prologue 混入握手哈希：绑定协议版本（与帧头明文版本交叉验证，防跨版本混淆）
pub fn protocol_version_prologue(version: u16) -> Vec<u8> {
    let mut out = PROTOCOL_VERSION_PREFIX.to_vec();
    out.extend_from_slice(version.to_string().as_bytes());
    out
}

/// 发起方握手状态机：write_initiation 产 msg1 帧，complete 收 msg2 帧出会话。
/// 状态一次性：complete 之后不可复用（WrongStep）。
pub struct ClientHandshake {
    state: Option<HandshakeState>,
    control_key: [u8; 32],
    version: u16,
    init_written: bool,
}

impl ClientHandshake {
    pub fn new(
        machine_key: &[u8; 32],
        control_key: &[u8; 32],
        version: u16,
    ) -> Result<Self, ControlbaseError> {
        let state = Builder::new(NOISE_PATTERN.parse().map_err(ControlbaseError::Noise)?)
            .prologue(&protocol_version_prologue(version))
            .map_err(ControlbaseError::Noise)?
            .remote_public_key(control_key)
            .map_err(ControlbaseError::Noise)?
            .local_private_key(machine_key)
            .map_err(ControlbaseError::Noise)?
            .build_initiator()
            .map_err(ControlbaseError::Noise)?;
        Ok(Self {
            state: Some(state),
            control_key: *control_key,
            version,
            init_written: false,
        })
    }

    /// msg1 initiation 帧（101B）
    pub fn write_initiation(
        &mut self,
    ) -> Result<[u8; wire::INITIATION_FRAME_LEN], ControlbaseError> {
        if self.init_written {
            return Err(ControlbaseError::WrongStep);
        }
        let state = self.state.as_mut().ok_or(ControlbaseError::WrongStep)?;
        let mut body = [0u8; wire::INITIATION_NOISE_BODY_LEN];
        let n = state
            .write_message(&[], &mut body)
            .map_err(ControlbaseError::Noise)?;
        if n != body.len() {
            return Err(ControlbaseError::MalformedFrame);
        }
        self.init_written = true;
        Ok(wire::encode_initiation(self.version, &body))
    }

    /// 处理服务端响应帧（51B response 或 error 帧），完成握手
    pub fn complete(&mut self, frame: &[u8]) -> Result<Session, ControlbaseError> {
        if !self.init_written {
            return Err(ControlbaseError::WrongStep);
        }
        let mut state = self.state.take().ok_or(ControlbaseError::WrongStep)?;
        let header = wire::parse_header(frame)?;
        match header.msg_type {
            wire::MSG_TYPE_RESPONSE => {
                if frame.len() != wire::RESPONSE_FRAME_LEN
                    || header.length != wire::RESPONSE_NOISE_BODY_LEN
                {
                    return Err(ControlbaseError::MalformedFrame);
                }
                state
                    .read_message(&frame[wire::HEADER_LEN..], &mut [])
                    .map_err(ControlbaseError::Noise)?;
            }
            wire::MSG_TYPE_ERROR => {
                // 未认证的公共提示，仅透传
                let text = String::from_utf8_lossy(&frame[wire::HEADER_LEN..]).into_owned();
                return Err(ControlbaseError::ServerError(text));
            }
            _ => return Err(ControlbaseError::MalformedFrame),
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(state.get_handshake_hash());
        // k1 = 发起方→响应方（client tx），k2 = 响应方→发起方（client rx）
        let (k1, k2) = state.dangerously_get_raw_split();
        Ok(Session {
            tx_cipher: record_cipher(&k1),
            rx_cipher: record_cipher(&k2),
            version: self.version,
            handshake_hash: hash,
            peer: self.control_key,
            tx_nonce: 0,
            rx_nonce: 0,
            rx_failed: false,
        })
    }
}

/// 已建立的 controlbase 会话：record 收发（chunking + AEAD + 防重放由 nonce 序列承担）。
/// nonce 显式管理（tailscale 同设计）：tx/rx 独立计数从 0 起，到达 INVALID_NONCE 拒用。
/// rx 侧一旦解密失败即失步（无法重同步），此后所有 open 恒拒（Desync）。
#[derive(Debug)]
pub struct Session {
    tx_cipher: ChaCha20Poly1305,
    rx_cipher: ChaCha20Poly1305,
    version: u16,
    handshake_hash: [u8; 32],
    peer: [u8; 32],
    tx_nonce: u64,
    rx_nonce: u64,
    rx_failed: bool,
}

impl Session {
    /// 明文加密为 record 帧（超长自动分帧，每帧明文 ≤ MAX_PLAINTEXT_SIZE）
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, ControlbaseError> {
        let overhead_per_frame = wire::HEADER_LEN + wire::AEAD_TAG_LEN;
        let frames = plaintext.len() / wire::MAX_PLAINTEXT_SIZE + 1;
        let mut out = Vec::with_capacity(plaintext.len() + frames * overhead_per_frame);
        for chunk in plaintext.chunks(wire::MAX_PLAINTEXT_SIZE) {
            if self.tx_nonce == INVALID_NONCE {
                return Err(ControlbaseError::Desync);
            }
            let ct = self
                .tx_cipher
                .encrypt(&record_nonce(self.tx_nonce).into(), chunk)
                .map_err(|_| ControlbaseError::MalformedFrame)?;
            self.tx_nonce += 1;
            out.extend_from_slice(&wire::encode_record_header(ct.len()));
            out.extend_from_slice(&ct);
        }
        Ok(out)
    }

    /// 解析并解密一条 record 帧（含 3B 帧头）；空载荷记录合法（返回空 Vec）
    pub fn open(&mut self, frame: &[u8]) -> Result<Vec<u8>, ControlbaseError> {
        if self.rx_failed {
            return Err(ControlbaseError::Desync);
        }
        let header = wire::parse_record_header(frame).inspect_err(|_| self.rx_failed = true)?;
        if frame.len() != wire::HEADER_LEN + header {
            self.rx_failed = true;
            return Err(ControlbaseError::MalformedFrame);
        }
        if header < wire::AEAD_TAG_LEN {
            self.rx_failed = true;
            return Err(ControlbaseError::MalformedFrame);
        }
        if self.rx_nonce == INVALID_NONCE {
            self.rx_failed = true;
            return Err(ControlbaseError::Desync);
        }
        match self.rx_cipher.decrypt(
            &record_nonce(self.rx_nonce).into(),
            &frame[wire::HEADER_LEN..],
        ) {
            Ok(plaintext) => {
                self.rx_nonce += 1;
                Ok(plaintext)
            }
            Err(_) => {
                // 解密失败 = 与对端失步，会话不可恢复（fail-closed）
                self.rx_failed = true;
                Err(ControlbaseError::Desync)
            }
        }
    }

    /// 测试用：主动产出一条零载荷 record（合法；tailscale Read 循环可跳过）
    #[cfg(test)]
    pub(crate) fn seal_empty_record(&mut self) -> Vec<u8> {
        let ct = self
            .tx_cipher
            .encrypt(&record_nonce(self.tx_nonce).into(), &[][..])
            .unwrap();
        self.tx_nonce += 1;
        let mut out = vec![wire::MSG_TYPE_RECORD];
        out.extend_from_slice(&(ct.len() as u16).to_be_bytes());
        out.extend_from_slice(&ct);
        out
    }

    /// Noise 握手哈希（上层会话绑定用，如 ts2021 early payload）
    pub fn handshake_hash(&self) -> &[u8; 32] {
        &self.handshake_hash
    }

    /// 按方向直接从 raw 密钥构造会话（服务端侧：tx = k2，rx = k1）
    pub(crate) fn from_raw_keys(tx_key: [u8; 32], rx_key: [u8; 32], version: u16) -> Self {
        Self {
            tx_cipher: record_cipher(&tx_key),
            rx_cipher: record_cipher(&rx_key),
            version,
            handshake_hash: [0u8; 32],
            peer: [0u8; 32],
            tx_nonce: 0,
            rx_nonce: 0,
            rx_failed: false,
        }
    }

    pub fn protocol_version(&self) -> u16 {
        self.version
    }

    /// 对端长身份公钥（client 侧 = control key；服务端 Session 为机器公钥）
    pub fn peer(&self) -> &[u8; 32] {
        &self.peer
    }

    /// 服务端侧写入机器公钥（Session::from_raw_keys 置零后的补齐）
    pub(crate) fn set_peer(&mut self, peer: [u8; 32]) {
        self.peer = peer;
    }
}

/// 响应方握手状态机（REQ-068 服务端）：收 msg1 帧出 msg2 帧 + 会话 + 客户端机器公钥。
/// prologue 版本取 initiation 帧头明文（tailscale Server 同源），故状态在 respond 时才建。
pub struct ServerHandshake {
    control_key_priv: [u8; 32],
}

impl ServerHandshake {
    pub fn new(control_key_priv: &[u8; 32]) -> Self {
        Self {
            control_key_priv: *control_key_priv,
        }
    }

    /// 处理 initiation 帧（101B）→ (response 帧 51B, 会话, 客户端机器公钥)
    pub fn respond(
        self,
        init_frame: &[u8],
    ) -> Result<(Vec<u8>, Session, [u8; 32]), ControlbaseError> {
        if init_frame.len() != wire::INITIATION_FRAME_LEN {
            return Err(ControlbaseError::MalformedFrame);
        }
        let version = u16::from_be_bytes([init_frame[0], init_frame[1]]);
        let header = wire::parse_header(&init_frame[2..])?;
        if header.msg_type != wire::MSG_TYPE_INITIATION
            || header.length != wire::INITIATION_NOISE_BODY_LEN
        {
            return Err(ControlbaseError::MalformedFrame);
        }
        let mut state = Builder::new(NOISE_PATTERN.parse().map_err(ControlbaseError::Noise)?)
            .prologue(&protocol_version_prologue(version))
            .map_err(ControlbaseError::Noise)?
            .local_private_key(&self.control_key_priv)
            .map_err(ControlbaseError::Noise)?
            .build_responder()
            .map_err(ControlbaseError::Noise)?;
        // initiation 帧头 5B（2B 版本 + 1B 类型 + 2B 长度），Noise 体从偏移 5 起
        state
            .read_message(&init_frame[wire::INITIATION_HEADER_LEN..], &mut [])
            .map_err(ControlbaseError::Noise)?;
        let machine = state
            .get_remote_static()
            .and_then(|s| <[u8; 32]>::try_from(s).ok())
            .ok_or(ControlbaseError::MalformedFrame)?;
        let mut body = [0u8; wire::RESPONSE_NOISE_BODY_LEN];
        let n = state
            .write_message(&[], &mut body)
            .map_err(ControlbaseError::Noise)?;
        if n != body.len() {
            return Err(ControlbaseError::MalformedFrame);
        }
        // 服务端朝向：tx = k2，rx = k1（k1 = 发起方→响应方）
        let (k1, k2) = state.dangerously_get_raw_split();
        let mut session = Session::from_raw_keys(k2, k1, version);
        session.set_peer(machine);
        let resp = wire::encode_response(&body);
        Ok((resp.to_vec(), session, machine))
    }
}
