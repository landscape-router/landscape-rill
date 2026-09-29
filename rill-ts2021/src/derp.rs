//! DERP 客户端（TS2021_LEG §3.3：v1 数据面 DERP-only，REQ-021）。
//! 协议对齐 tailscale derp/derp.go + derphttp（v1.101.0-pre）：
//! TLS 上 GET /derp 升级（Upgrade: DERP）→ 服务器问候帧（magic + derp 公钥）→
//! FrameClientInfo（nacl box）→ 收发 FrameRecvPacket / FrameSendPacket。
//! box 为 Go nacl/box 布局：nonce(24) || tag(16) || ciphertext。

use crypto_box::{
    aead::{Aead, Payload},
    Nonce, SalsaBox,
};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const FRAME_SERVER_KEY: u8 = 0x01;
pub const FRAME_CLIENT_INFO: u8 = 0x02;
pub const FRAME_SERVER_INFO: u8 = 0x03;
pub const FRAME_SEND_PACKET: u8 = 0x04;
pub const FRAME_RECV_PACKET: u8 = 0x05;
pub const FRAME_KEEP_ALIVE: u8 = 0x06;
pub const FRAME_PING: u8 = 0x12;
pub const FRAME_PONG: u8 = 0x13;

/// derp.Magic："DERP🔑"（8B）
const DERP_MAGIC: [u8; 8] = [0x44, 0x45, 0x52, 0x50, 0xf0, 0x9f, 0x94, 0x91];
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;
const MAX_FRAME: usize = 1024 * 1024;

pub struct ReceivedPacket {
    pub source: [u8; 32],
    pub data: Vec<u8>,
}

/// nacl box（Go nacl/box 兼容）：nonce || tag || ciphertext
fn nacl_box_seal(box_: &SalsaBox, nonce: &[u8; NONCE_LEN], msg: &[u8]) -> io::Result<Vec<u8>> {
    // CryptoBox 的 AEAD 输出已是 nacl 布局（tag || ct），直接前置 nonce 即与 Go nacl/box 一致
    let boxed = box_
        .encrypt(Nonce::from_slice(nonce), Payload { msg, aad: &[] })
        .map_err(|_| io::Error::other("derp box seal failed"))?;
    let mut out = Vec::with_capacity(NONCE_LEN + boxed.len());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&boxed);
    Ok(out)
}

async fn read_frame<IO>(io: &mut IO) -> io::Result<(u8, Vec<u8>)>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let mut hdr = [0u8; 5];
    io.read_exact(&mut hdr).await?;
    let len = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "derp frame too large",
        ));
    }
    let mut payload = vec![0u8; len];
    io.read_exact(&mut payload).await?;
    Ok((hdr[0], payload))
}

async fn write_frame<IO>(io: &mut IO, t: u8, payload: &[u8]) -> io::Result<()>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(t);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    io.write_all(&frame).await?;
    io.flush().await
}

/// DERP 客户端连接：在既有 TLS 流上握手，随后收发 WireGuard 包帧
pub struct DerpClient<IO> {
    io: IO,
    client_pub: [u8; 32],
}

impl<IO: AsyncRead + AsyncWrite + Unpin> DerpClient<IO> {
    pub async fn connect(
        mut io: IO,
        host: &str,
        client_pub: [u8; 32],
        client_priv: [u8; 32],
    ) -> io::Result<Self> {
        let request = format!(
            "GET /derp HTTP/1.1\r\nHost: {host}\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n"
        );
        io.write_all(request.as_bytes()).await?;

        // 101 响应头
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            io.read_exact(&mut byte).await?;
            head.push(byte[0]);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
            if head.len() > 16 * 1024 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "derp upgrade head too large",
                ));
            }
        }
        let head = String::from_utf8_lossy(&head).into_owned();
        let status_line = head.lines().next().unwrap_or_default();
        if status_line.split_whitespace().nth(1) != Some("101") {
            return Err(io::Error::other(format!(
                "derp upgrade rejected: {status_line}"
            )));
        }

        // 服务器问候：magic(8B) + derp 公钥(32B)
        let (t, payload) = read_frame(&mut io).await?;
        if t != FRAME_SERVER_KEY
            || payload.len() < DERP_MAGIC.len() + KEY_LEN
            || payload[..DERP_MAGIC.len()] != DERP_MAGIC
        {
            return Err(io::Error::other("invalid derp server greeting"));
        }
        let mut server_key = [0u8; KEY_LEN];
        server_key.copy_from_slice(&payload[DERP_MAGIC.len()..DERP_MAGIC.len() + KEY_LEN]);

        let box_ = SalsaBox::new(
            &crypto_box::PublicKey::from(server_key),
            &crypto_box::SecretKey::from(client_priv),
        );

        // FrameClientInfo：clientPub(32) + nonce(24) + box(json)
        let info = serde_json::json!({"Version": 2, "CanAckPings": true});
        let nonce = rand::random::<[u8; NONCE_LEN]>();
        let boxed = nacl_box_seal(&box_, &nonce, info.to_string().as_bytes())?;
        let mut payload = Vec::with_capacity(KEY_LEN + boxed.len());
        payload.extend_from_slice(&client_pub);
        payload.extend_from_slice(&boxed);
        write_frame(&mut io, FRAME_CLIENT_INFO, &payload).await?;

        Ok(Self { io, client_pub })
    }

    /// 发送 WG 包给目标节点（dst = 对端 node key）
    pub async fn send(&mut self, dst: &[u8; 32], pkt: &[u8]) -> io::Result<()> {
        let mut payload = Vec::with_capacity(KEY_LEN + pkt.len());
        payload.extend_from_slice(dst);
        payload.extend_from_slice(pkt);
        write_frame(&mut self.io, FRAME_SEND_PACKET, &payload).await
    }

    /// 读取下一份数据包；keepalive/serverinfo/ping 等控制帧内部处理（ping 自动回 pong）
    pub async fn recv(&mut self) -> io::Result<ReceivedPacket> {
        loop {
            let (t, payload) = {
                let (t, payload) = read_frame(&mut self.io).await?;
                if std::env::var("LRILL_DEBUG").is_ok() {
                    eprintln!("[dbg] derp frame t={t} len={}", payload.len());
                }
                (t, payload)
            };
            match t {
                FRAME_RECV_PACKET => {
                    if payload.len() < KEY_LEN {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "short derp packet frame",
                        ));
                    }
                    let mut source = [0u8; KEY_LEN];
                    source.copy_from_slice(&payload[..KEY_LEN]);
                    return Ok(ReceivedPacket {
                        source,
                        data: payload[KEY_LEN..].to_vec(),
                    });
                }
                FRAME_PING => {
                    if payload.len() >= 8 {
                        write_frame(&mut self.io, FRAME_PONG, &payload[..8]).await?;
                    }
                }
                FRAME_SERVER_INFO | FRAME_KEEP_ALIVE | FRAME_PONG => {}
                _ => {}
            }
        }
    }

    /// 周期 keepalive（NAT 维持）
    pub async fn keepalive(&mut self) -> io::Result<()> {
        write_frame(&mut self.io, FRAME_KEEP_ALIVE, &[]).await
    }

    pub fn client_pub(&self) -> &[u8; 32] {
        &self.client_pub
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tailcfg::hex;

    /// 解封（与 seal 同布局；仅测试用）
    fn nacl_box_open(box_: &SalsaBox, boxed: &[u8]) -> io::Result<Vec<u8>> {
        const TAG_LEN: usize = 16;
        if boxed.len() < NONCE_LEN + TAG_LEN {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "short box"));
        }
        box_.decrypt(
            Nonce::from_slice(&boxed[..NONCE_LEN]),
            Payload {
                msg: &boxed[NONCE_LEN..],
                aad: &[],
            },
        )
        .map_err(|_| io::Error::other("derp box open failed"))
    }

    /// 与 Go nacl/box 交叉验证（boxtest 参考实现，同密钥/nonce/明文）
    #[tokio::test]
    async fn nacl_box_go_compat() {
        let client_priv: [u8; 32] = [
            0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x41,
        ];
        let server_pub: [u8; 32] = [
            0x57, 0xdb, 0x4b, 0x35, 0x9f, 0x23, 0xae, 0x5e, 0x14, 0x6e, 0x4e, 0x25, 0x12, 0x05,
            0x67, 0x04, 0x72, 0x25, 0x06, 0x34, 0x8c, 0x15, 0x0c, 0x14, 0x75, 0x3d, 0x0c, 0x93,
            0x3d, 0x04, 0xd4, 0x21,
        ];
        let nonce = [0u8; NONCE_LEN];
        let msg = br#"{"Version":2,"CanAckPings":true}"#;
        let sk = crypto_box::SecretKey::from(client_priv);
        let box_ = SalsaBox::new(&crypto_box::PublicKey::from(server_pub), &sk);
        let boxed = nacl_box_seal(&box_, &nonce, msg).unwrap();
        let go_box = "db5e0b97543b6f45ef16f0211af0a49d7e82eaa878c095349bca0051d48ef9896a53953e22889d4611585a554cc49bdb";
        assert_eq!(
            hex(&boxed[24..]),
            go_box,
            "box (tag||ct) 应与 Go nacl/box 一致"
        );
        assert_eq!(&boxed[..24], &nonce[..]);
        let opened = nacl_box_open(&box_, &boxed).unwrap();
        assert_eq!(opened, msg);
    }
}
