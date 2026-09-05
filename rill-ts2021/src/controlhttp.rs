//! controlhttp：HTTPS 连接升级（TS2021_LEG §2 传输层，对齐 tailscale control/controlhttp）。
//! 客户端 POST /ts2021，Upgrade: tailscale-control-protocol，msg1 经 base64 放入
//! X-Tailscale-Handshake 头（v1.101+ 线格式）；101 后同一流转裸 Noise，服务端依次发出
//! msg2 与 early payload（后者由上层 ts2021 读取）。

use crate::base64;
use crate::controlbase::stream::{finish_handshake, NoiseStream};
use crate::controlbase::{ClientHandshake, ControlbaseError};
use crate::tailcfg::{self, OverTLSPublicKeyResponse};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const UPGRADE_PATH: &str = "/ts2021";
pub const UPGRADE_VALUE: &str = "tailscale-control-protocol";
pub const HANDSHAKE_HEADER: &str = "X-Tailscale-Handshake";
pub const KEY_PATH: &str = "/key";

/// 响应头读取上限（防未裁剪长度累积）
const MAX_HEAD_LEN: usize = 16 * 1024;

/// GET /key?v=<capver>（TLS 流上）：预取服务端 Noise 公钥（官方客户端同路径）。
/// 独立连接使用（一次性请求，Content-Length 分帧）。
pub async fn fetch_control_key<IO>(mut io: IO, host: &str, version: u16) -> io::Result<[u8; 32]>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let request = format!("GET {KEY_PATH}?v={version} HTTP/1.1\r\nHost: {host}\r\n\r\n");
    io.write_all(request.as_bytes()).await?;
    let head = read_http_head(&mut io).await?;
    let status_line = head.lines().next().unwrap_or_default();
    if status_line.split_whitespace().nth(1) != Some("200") {
        return Err(io::Error::other(format!("/key rejected: {status_line}")));
    }
    let content_len = head
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case("content-length")
                .then(|| v.trim().parse::<usize>().ok())?
        })
        .ok_or_else(|| io::Error::other("/key response missing content-length"))?;
    let mut body = vec![0u8; content_len];
    io.read_exact(&mut body).await?;
    let parsed: OverTLSPublicKeyResponse =
        serde_json::from_slice(&body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    tailcfg::parse_machine_public(&parsed.public_key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// 在既有流（TLS 之后）上完成 controlhttp 升级 + controlbase 握手。
/// `host` 仅用于 HTTP Host 头。
pub async fn upgrade<IO>(
    mut io: IO,
    host: &str,
    machine_key: &[u8; 32],
    control_key: &[u8; 32],
    version: u16,
) -> io::Result<NoiseStream<IO>>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let mut hs = ClientHandshake::new(machine_key, control_key, version)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let init = hs
        .write_initiation()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let request = format!(
        "POST {UPGRADE_PATH} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Upgrade: {UPGRADE_VALUE}\r\n\
         Connection: upgrade\r\n\
         {HANDSHAKE_HEADER}: {}\r\n\
         Content-Length: 0\r\n\
         \r\n",
        base64::encode(&init),
    );
    io.write_all(request.as_bytes()).await?;

    let head = read_http_head(&mut io).await?;
    let status_line = head.lines().next().unwrap_or_default();
    if status_line.split_whitespace().nth(1) != Some("101") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("controlhttp upgrade rejected: {status_line}"),
        ));
    }
    if !head
        .to_ascii_lowercase()
        .contains(&format!("upgrade: {UPGRADE_VALUE}"))
    {
        return Err(io::Error::other(
            "controlhttp server switched to unexpected protocol",
        ));
    }

    let session = finish_handshake(&mut io, &mut hs).await?;
    Ok(NoiseStream::new(io, session))
}

/// 读到 HTTP 头块结束（\r\n\r\n）
async fn read_http_head<IO>(io: &mut IO) -> io::Result<String>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        io.read_exact(&mut byte).await?;
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            return Ok(String::from_utf8_lossy(&head).into_owned());
        }
        if head.len() > MAX_HEAD_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                ControlbaseError::MalformedFrame,
            ));
        }
    }
}
