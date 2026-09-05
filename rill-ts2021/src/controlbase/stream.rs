//! tokio 胶水：在 AsyncRead + AsyncWrite 流上跑 controlbase 握手，
//! 并提供 NoiseStream（record 帧透明封装的 AsyncRead/AsyncWrite，
//! 供上层 HTTP/2 直接使用）。纯逻辑（握手状态机/帧编解码）在本模块之外；
//! 此处只做字节搬运、分帧与错误映射（域错误 → io::Error(InvalidData)，
//! 对齐 mesh control client 约定）。

use super::error::ControlbaseError;
use super::handshake::{ClientHandshake, Session};
use super::wire;
use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

fn controlbase_err(e: ControlbaseError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

/// 在既有流（TLS 升级后的 controlhttp 流）上执行客户端握手。
/// 服务端错误帧（type=3）以 ServerError 文本进入 io::Error。
pub async fn handshake<IO>(
    io_stream: &mut IO,
    machine_key: &[u8; 32],
    control_key: &[u8; 32],
    version: u16,
) -> io::Result<Session>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let mut hs =
        ClientHandshake::new(machine_key, control_key, version).map_err(controlbase_err)?;
    let init = hs.write_initiation().map_err(controlbase_err)?;
    io_stream.write_all(&init).await?;
    finish_handshake(io_stream, &mut hs).await
}

/// 读服务端响应帧并完成握手（msg1 已发出；controlhttp 与裸流路径共用）
pub(crate) async fn finish_handshake<IO>(
    io_stream: &mut IO,
    hs: &mut ClientHandshake,
) -> io::Result<Session>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let mut header = [0u8; wire::HEADER_LEN];
    io_stream.read_exact(&mut header).await?;
    let h = wire::parse_header(&header).map_err(controlbase_err)?;
    // response/error 帧长受单帧上限约束，防止未裁剪长度分配
    if wire::HEADER_LEN + h.length > wire::MAX_MESSAGE_SIZE {
        return Err(controlbase_err(ControlbaseError::MalformedFrame));
    }
    match h.msg_type {
        wire::MSG_TYPE_RESPONSE => {
            if h.length != wire::RESPONSE_NOISE_BODY_LEN {
                return Err(controlbase_err(ControlbaseError::MalformedFrame));
            }
            let mut frame = Vec::with_capacity(wire::RESPONSE_FRAME_LEN);
            frame.extend_from_slice(&header);
            frame.resize(wire::RESPONSE_FRAME_LEN, 0);
            io_stream.read_exact(&mut frame[wire::HEADER_LEN..]).await?;
            hs.complete(&frame).map_err(controlbase_err)
        }
        wire::MSG_TYPE_ERROR => {
            let mut text = vec![0u8; h.length];
            io_stream.read_exact(&mut text).await?;
            Err(controlbase_err(ControlbaseError::ServerError(
                String::from_utf8_lossy(&text).into_owned(),
            )))
        }
        _ => Err(controlbase_err(ControlbaseError::MalformedFrame)),
    }
}

enum RxStage {
    Header,
    Body,
}

struct RxState {
    plain: Vec<u8>,
    pos: usize,
    stage: RxStage,
    hdr: [u8; 3],
    hdr_fill: usize,
    frame: Vec<u8>,
    frame_fill: usize,
    eof: bool,
}

struct TxState {
    /// 已加密待写出的 record 字节
    pending: Vec<u8>,
    pos: usize,
}

/// 已握手会话的流封装：record 帧对上层透明（明文连续可读，写入自动分帧加密）。
/// rx 侧解密失败即失步，此后读写恒错（fail-closed）。
pub struct NoiseStream<IO> {
    io: IO,
    session: Session,
    rx: RxState,
    tx: TxState,
}

impl<IO> std::fmt::Debug for NoiseStream<IO> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoiseStream").finish_non_exhaustive()
    }
}

impl<IO> NoiseStream<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(io: IO, session: Session) -> Self {
        Self {
            io,
            session,
            rx: RxState {
                plain: Vec::new(),
                pos: 0,
                stage: RxStage::Header,
                hdr: [0u8; 3],
                hdr_fill: 0,
                frame: Vec::new(),
                frame_fill: 0,
                eof: false,
            },
            tx: TxState {
                pending: Vec::new(),
                pos: 0,
            },
        }
    }

    pub fn session(&self) -> &Session {
        &self.session
    }

    fn poll_fill_rx(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            match self.rx.stage {
                RxStage::Header => {
                    while self.rx.hdr_fill < wire::HEADER_LEN {
                        let mut r = ReadBuf::new(&mut self.rx.hdr[self.rx.hdr_fill..]);
                        match Pin::new(&mut self.io).poll_read(cx, &mut r) {
                            Poll::Ready(Ok(())) => {
                                let n = r.filled().len();
                                if n == 0 {
                                    if self.rx.hdr_fill == 0 {
                                        // 帧边界处对端关闭 = 干净 EOF
                                        self.rx.eof = true;
                                        return Poll::Ready(Ok(()));
                                    }
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::UnexpectedEof,
                                        "truncated record header",
                                    )));
                                }
                                self.rx.hdr_fill += n;
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                    let body_len =
                        wire::parse_record_header(&self.rx.hdr).map_err(controlbase_err)?;
                    self.rx.frame = vec![0u8; wire::HEADER_LEN + body_len];
                    self.rx.frame[..wire::HEADER_LEN].copy_from_slice(&self.rx.hdr);
                    self.rx.frame_fill = wire::HEADER_LEN;
                    self.rx.stage = RxStage::Body;
                }
                RxStage::Body => {
                    while self.rx.frame_fill < self.rx.frame.len() {
                        let mut r = ReadBuf::new(&mut self.rx.frame[self.rx.frame_fill..]);
                        match Pin::new(&mut self.io).poll_read(cx, &mut r) {
                            Poll::Ready(Ok(())) => {
                                let n = r.filled().len();
                                if n == 0 {
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::UnexpectedEof,
                                        "truncated record body",
                                    )));
                                }
                                self.rx.frame_fill += n;
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                    let frame = std::mem::take(&mut self.rx.frame);
                    let plaintext = self.session.open(&frame).map_err(controlbase_err)?;
                    self.rx.plain = plaintext;
                    self.rx.pos = 0;
                    self.rx.stage = RxStage::Header;
                    self.rx.hdr_fill = 0;
                    // 循环回到 Header/交付阶段；空载荷 record 自然跳过
                    if self.rx.plain.is_empty() {
                        continue;
                    }
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl<IO> AsyncRead for NoiseStream<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.rx.pos >= this.rx.plain.len() && !this.rx.eof {
            ready!(this.poll_fill_rx(cx))?;
        }
        if this.rx.pos >= this.rx.plain.len() {
            // eof 或解密后仍无数据（对端关闭）
            return Poll::Ready(Ok(()));
        }
        let n = buf.remaining().min(this.rx.plain.len() - this.rx.pos);
        buf.put_slice(&this.rx.plain[this.rx.pos..this.rx.pos + n]);
        this.rx.pos += n;
        if this.rx.pos == this.rx.plain.len() {
            this.rx.plain.clear();
            this.rx.pos = 0;
        }
        Poll::Ready(Ok(()))
    }
}

impl<IO> AsyncWrite for NoiseStream<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = self.get_mut();
        let sealed = this.session.seal(buf).map_err(controlbase_err)?;
        this.tx.pending.extend_from_slice(&sealed);
        match AsyncWrite::poll_flush(Pin::new(this), cx) {
            Poll::Ready(r) => Poll::Ready(r.map(|()| buf.len())),
            Poll::Pending => Poll::Ready(Ok(buf.len())),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        while this.tx.pos < this.tx.pending.len() {
            let n = ready!(Pin::new(&mut this.io).poll_write(cx, &this.tx.pending[this.tx.pos..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "noise stream inner write returned 0",
                )));
            }
            this.tx.pos += n;
        }
        this.tx.pending.clear();
        this.tx.pos = 0;
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(AsyncWrite::poll_flush(Pin::new(this), cx))?;
        Pin::new(&mut this.io).poll_shutdown(cx)
    }
}
