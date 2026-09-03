//! boringtun 隧道封装（DN42_LEG §2/§5）：每 peer 一条用户态 WG 会话，明文包直接进用户态栈，
//! 不建内核网卡。本模块零 I/O——UDP 收发由 session 驱动完成。

#[cfg(test)]
mod tests;

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};

/// 封装后上限：数据包 ≤ 65535 + WG 开销；预留充分余量
const MAX_WG_PACKET: usize = 65535 + 148;

#[derive(Debug, Clone)]
pub struct WgPeerKeys {
    /// 本端静态私钥（节点级，wg genkey 格式的 32B 原始值）
    pub own_private: [u8; 32],
    /// 对端静态公钥
    pub peer_public: [u8; 32],
    /// 可选 pre-shared key
    pub preshared: Option<[u8; 32]>,
    /// 会话索引（节点内每 peer 唯一，boringtun 内部用途）
    pub index: u32,
}

#[derive(Debug, Default)]
pub struct DecapOutcome {
    /// 解密出的明文 IP 包（数据面）
    pub plaintext: Option<Vec<u8>>,
    /// 需经 UDP 发回的传输字节（握手响应/cookie/keepalive）
    pub to_send: Vec<Vec<u8>>,
}

pub struct WgTunnel {
    tunn: Tunn,
}

impl WgTunnel {
    pub fn new(keys: WgPeerKeys) -> Self {
        let secret = StaticSecret::from(keys.own_private);
        let public = PublicKey::from(keys.peer_public);
        Self {
            tunn: Tunn::new(secret, public, keys.preshared, None, keys.index, None),
        }
    }

    /// 明文 IP 包 → WG 传输字节。
    /// 无会话时：包进入 boringtun 内部队列（深度 256，超出丢弃），并触发握手发起。
    pub fn encapsulate(&mut self, packet: &[u8]) -> Vec<Vec<u8>> {
        let mut dst = vec![0u8; packet.len() + 64];
        match self.tunn.encapsulate(packet, &mut dst) {
            TunnResult::WriteToNetwork(bytes) => vec![bytes.to_vec()],
            _ => self.ensure_initiated(),
        }
    }

    /// UDP 数据报 → 明文包 + 待发字节。重复调用直至 Done（boringtun 约定：
    /// 空数据报 = 续冲队列）。
    pub fn decapsulate(&mut self, src: Option<std::net::IpAddr>, datagram: &[u8]) -> DecapOutcome {
        let mut out = DecapOutcome::default();
        let mut dst = vec![0u8; MAX_WG_PACKET];
        let mut first = true;
        loop {
            let result = if first {
                first = false;
                self.tunn.decapsulate(src, datagram, &mut dst)
            } else {
                self.tunn.decapsulate(src, &[], &mut dst)
            };
            match result {
                TunnResult::Done => break,
                TunnResult::Err(_) => break, // 解析失败/无会话：丢弃（fail-closed）
                TunnResult::WriteToNetwork(bytes) => out.to_send.push(bytes.to_vec()),
                TunnResult::WriteToTunnelV4(bytes, _) | TunnResult::WriteToTunnelV6(bytes, _) => {
                    out.plaintext = Some(bytes.to_vec())
                }
            }
        }
        out
    }

    /// 周期定时器（驱动层约 1s 一调）：握手重试、持久 keepalive、rekey
    pub fn update_timers(&mut self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut dst = vec![0u8; MAX_WG_PACKET];
        loop {
            match self.tunn.update_timers(&mut dst) {
                TunnResult::Done => break,
                TunnResult::Err(_) => break,
                TunnResult::WriteToNetwork(bytes) => out.push(bytes.to_vec()),
                _ => break,
            }
        }
        out
    }

    /// 会话未建立且握手未在途时发起握手（在途则交给 update_timers 重试）
    pub fn ensure_initiated(&mut self) -> Vec<Vec<u8>> {
        let mut dst = vec![0u8; MAX_WG_PACKET];
        match self.tunn.format_handshake_initiation(&mut dst, false) {
            TunnResult::WriteToNetwork(bytes) => vec![bytes.to_vec()],
            _ => vec![],
        }
    }

    /// 会话是否已建立（调试/可观测用）
    pub fn session_established(&self) -> bool {
        self.tunn.stats().0.is_some()
    }
}
