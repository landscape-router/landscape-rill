//! ts2021 会话层（TS2021_LEG §2/§3.1）：early payload 读取 + HTTP/2 客户端 +
//! /machine/register（JSON over HTTP/2，对齐 tailscale ts2021 + headscale 0.29.3）。
//! 握手顺序：controlbase 完成 → 读 early payload → HTTP/2 prior-knowledge → POST。

use crate::controlbase::NoiseStream;
use crate::tailcfg::{register_request_json, EarlyNoise, RegisterResponse};
use bytes::Bytes;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::task::JoinHandle;

/// early payload 引导头（headscale noise.go：5B 不会被误认为 HTTP/2 帧的 magic + 4B BE 长度）
const EARLY_PAYLOAD_MAGIC: [u8; 5] = [0xff, 0xff, 0xff, b'T', b'S'];
const MAX_EARLY_PAYLOAD_LEN: usize = 64 * 1024;

pub struct ControlClient {
    send_request: h2::client::SendRequest<Bytes>,
    /// h2 连接驱动任务（drop 即终止）
    driver: JoinHandle<()>,
    /// 服务端引导信息（NodeKeyChallenge，v1 仅存证）
    pub early_noise: EarlyNoise,
}

fn h2_err(e: h2::Error) -> io::Error {
    io::Error::other(e)
}

/// 在已升级的 Noise 流上建立 ts2021 会话。
pub async fn connect<IO>(mut stream: NoiseStream<IO>) -> io::Result<ControlClient>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let early_noise = read_early_payload(&mut stream).await?;
    let (send_request, connection) = h2::client::handshake(stream).await.map_err(h2_err)?;
    let driver = tokio::spawn(async move {
        // 连接生命周期随 ControlClient；驱动结束（对端关闭/错误）不影响已完成的请求
        let _ = connection.await;
    });
    Ok(ControlClient {
        send_request,
        driver,
        early_noise,
    })
}

impl Drop for ControlClient {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

/// 读 early payload（经 NoiseStream 明文流重组，服务端分多次 record 写出）
async fn read_early_payload<IO>(stream: &mut NoiseStream<IO>) -> io::Result<EarlyNoise>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let mut head = [0u8; 9];
    stream.read_exact(&mut head).await?;
    if head[..5] != EARLY_PAYLOAD_MAGIC {
        return Err(io::Error::other("bad early payload magic"));
    }
    let len = u32::from_be_bytes(head[5..9].try_into().expect("9B head")) as usize;
    if len > MAX_EARLY_PAYLOAD_LEN {
        return Err(io::Error::other("early payload too large"));
    }
    let mut json = vec![0u8; len];
    stream.read_exact(&mut json).await?;
    serde_json::from_slice(&json).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

impl ControlClient {
    /// POST /machine/register（auth key 预授权路径，REQ-021/TS2021_LEG §3.2）。
    /// `host` 作为请求 :authority（如 "headscale:8080"）。
    pub async fn register(
        &mut self,
        node_key: &[u8; 32],
        auth_key: &str,
        hostname: &str,
        host: &str,
    ) -> io::Result<RegisterResponse> {
        let body = register_request_json(node_key, auth_key, hostname);
        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri(format!("https://{host}/machine/register"))
            .header("content-type", "application/json")
            .body(())
            .expect("static request builder");
        let (response, mut req_stream) = self
            .send_request
            .clone()
            .ready()
            .await
            .map_err(h2_err)?
            .send_request(request, false)
            .map_err(h2_err)?;
        req_stream
            .send_data(Bytes::from(body), true)
            .map_err(h2_err)?;
        let response = response.await.map_err(h2_err)?;
        let status = response.status();
        let body = collect_body(response.into_body()).await?;
        if !status.is_success() {
            return Err(io::Error::other(format!(
                "register rejected: {status}: {}",
                String::from_utf8_lossy(&body)
            )));
        }
        serde_json::from_slice(&body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

async fn collect_body(mut body: h2::RecvStream) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(h2_err)?;
        let n = chunk.len();
        out.extend_from_slice(&chunk);
        body.flow_control().release_capacity(n).map_err(h2_err)?;
        if out.len() > 1024 * 1024 {
            return Err(io::Error::other("register response too large"));
        }
    }
    Ok(out)
}

/// snow 派生 x25519 密钥对（machine key / node key 生成；协议实现共用 snow，避免引入新 RNG 依赖）
pub fn generate_keypair() -> io::Result<([u8; 32], [u8; 32])> {
    let params = "Noise_XX_25519_ChaChaPoly_SHA256"
        .parse()
        .map_err(io::Error::other)?;
    let kp = snow::Builder::new(params)
        .generate_keypair()
        .map_err(io::Error::other)?;
    let private: [u8; 32] = kp
        .private
        .try_into()
        .map_err(|_| io::Error::other("bad key len"))?;
    let public: [u8; 32] = kp
        .public
        .try_into()
        .map_err(|_| io::Error::other("bad key len"))?;
    Ok((private, public))
}

#[cfg(test)]
mod tests;
