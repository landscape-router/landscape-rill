//! ts2021 会话层（TS2021_LEG §2/§3.1）：early payload 读取 + HTTP/2 客户端 +
//! /machine/register（JSON over HTTP/2，对齐 tailscale ts2021 + headscale 0.29.3）。
//! 握手顺序：controlbase 完成 → 读 early payload → HTTP/2 prior-knowledge → POST。

use crate::controlbase::NoiseStream;
use crate::tailcfg::{
    map_endpoints_update_json, map_request_json, register_request_json, EarlyNoise, MapResponse,
    RegisterResponse,
};
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
    /// POST JSON 到 control 路径，返回 (status, body bytes)
    async fn post_json(&mut self, host: &str, path: &str, body: Vec<u8>) -> io::Result<Vec<u8>> {
        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri(format!("https://{host}{path}"))
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
                "{path} rejected: {status}: {}",
                String::from_utf8_lossy(&body)
            )));
        }
        Ok(body)
    }

    /// POST /machine/map（Stream=true 长轮询）：读首个含 netmap 的 MapResponse。
    /// 线格式：每帧 = 4B LE 长度头（headscale writeMap reservedResponseHeaderSize）+ JSON；
    /// keepalive 帧跳过。headscale 0.29 对 Stream=false 不回 body（poll.go serve），
    /// 完整 netmap 仅长轮询下发。
    /// Lite 端点更新（Stream=false + OmitPeers=true）：上报本端 UDP 端点，服务端回 200 空 body
    #[allow(clippy::too_many_arguments)]
    pub async fn map_endpoints_update(
        &mut self,
        node_key: &[u8; 32],
        disco_key: &[u8; 32],
        hostname: &str,
        host: &str,
        endpoints: &[String],
        preferred_derp: Option<u16>,
        routable_ips: &[String],
    ) -> io::Result<()> {
        let body = map_endpoints_update_json(
            node_key,
            disco_key,
            hostname,
            endpoints,
            preferred_derp,
            routable_ips,
        );
        self.post_json(host, "/machine/map", body).await?;
        Ok(())
    }

    pub async fn map(
        &mut self,
        node_key: &[u8; 32],
        disco_key: &[u8; 32],
        hostname: &str,
        host: &str,
        preferred_derp: Option<u16>,
    ) -> io::Result<MapResponse> {
        let mut stream = self
            .map_stream(node_key, disco_key, hostname, host, &[], preferred_derp)
            .await?;
        // 首个含 Node 的全量 netmap（keepalive 帧跳过）
        stream.next_netmap().await
    }

    /// POST /machine/map（Stream=true 长轮询）为持续流：服务端经同一响应体推送
    /// 后续 netmap 变更帧（每帧 = 4B LE 长度头 + JSON；keepalive 帧无 Node）。
    /// 调用方持流轮询 `next_netmap`；RoutableIPs 变更时丢弃流重发请求
    /// （Hostinfo 只在新 MapRequest 生效，TS2021_LEG §3.3.2）
    pub async fn map_stream(
        &mut self,
        node_key: &[u8; 32],
        disco_key: &[u8; 32],
        hostname: &str,
        host: &str,
        routable_ips: &[String],
        preferred_derp: Option<u16>,
    ) -> io::Result<MapStream> {
        let body = map_request_json(
            node_key,
            disco_key,
            hostname,
            &[],
            true,
            preferred_derp,
            routable_ips,
        );
        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri(format!("https://{host}/machine/map"))
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
        if !status.is_success() {
            return Err(io::Error::other(format!("map rejected: {status}")));
        }
        Ok(MapStream {
            reader: BodyReader {
                body: response.into_body(),
                cur: Bytes::new(),
            },
        })
    }

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

/// 长轮询响应体读取：h2 分块 → 连续字节流（帧头/帧体 read_exact）
struct BodyReader {
    body: h2::RecvStream,
    cur: Bytes,
}

impl BodyReader {
    async fn read_exact(&mut self, out: &mut [u8]) -> io::Result<()> {
        let mut filled = 0;
        while filled < out.len() {
            if self.cur.is_empty() {
                match self.body.data().await {
                    Some(c) => {
                        let c = c.map_err(h2_err)?;
                        let n = c.len();
                        self.body
                            .flow_control()
                            .release_capacity(n)
                            .map_err(h2_err)?;
                        self.cur = c;
                    }
                    None => {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "map long-poll closed mid-frame",
                        ))
                    }
                }
            }
            let n = (out.len() - filled).min(self.cur.len());
            out[filled..filled + n].copy_from_slice(&self.cur[..n]);
            let _ = n;
            let taken = self.cur.split_to(n);
            filled += n;
            let _ = taken;
        }
        Ok(())
    }
}

const MAX_MAP_FRAME: usize = 1024 * 1024;

/// 长轮询响应流（`map_stream` 产物）：逐帧读取，keepalive 帧跳过
pub struct MapStream {
    reader: BodyReader,
}

impl MapStream {
    /// 读下一帧完整 netmap（无 Node 的 keepalive 帧内部跳过）；
    /// Err = 流断开（调用方重建长轮询）
    pub async fn next_netmap(&mut self) -> io::Result<MapResponse> {
        loop {
            let mut len_buf = [0u8; 4];
            self.reader.read_exact(&mut len_buf).await?;
            let len = u32::from_le_bytes(len_buf) as usize;
            if len > MAX_MAP_FRAME {
                return Err(io::Error::other("map frame too large"));
            }
            let mut json = vec![0u8; len];
            self.reader.read_exact(&mut json).await?;
            let map: MapResponse = serde_json::from_slice(&json)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            if std::env::var("LRILL_DEBUG").is_ok() {
                let v: serde_json::Value = serde_json::from_slice(&json).unwrap_or_default();
                eprintln!(
                    "[dbg] map frame keys: {:?}",
                    v.as_object().map(|o| o.keys().cloned().collect::<Vec<_>>())
                );
                eprintln!(
                    "[dbg] DERPMap: {}",
                    v.get("DERPMap")
                        .map(|d| d.to_string())
                        .unwrap_or_default()
                        .chars()
                        .take(400)
                        .collect::<String>()
                );
            }
            if map.node.is_some() {
                return Ok(map);
            }
        }
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

fn from_hex64(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut k = [0u8; 32];
    for (i, pair) in s.as_bytes().chunks(2).enumerate() {
        let hi = (pair[0] as char).to_digit(16)? as u8;
        let lo = (pair[1] as char).to_digit(16)? as u8;
        k[i] = hi << 4 | lo;
    }
    Some(k)
}

/// 机器私钥持久化（TSL-10）：文件存在即读（hex），否则生成并以 0600 落盘（create_new 防并发覆写）。
/// 重启复用同一 machine key → 服务端节点身份稳定（node key 每次新生成 = 轮换路径）。
pub fn load_or_create_machine_key(path: &std::path::Path) -> io::Result<[u8; 32]> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    match std::fs::read_to_string(path) {
        Ok(s) => from_hex64(s.trim())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "machine key file corrupt")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let (privk, _) = generate_keypair()?;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?;
            f.write_all(crate::tailcfg::hex(&privk).as_bytes())?;
            Ok(privk)
        }
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests;
