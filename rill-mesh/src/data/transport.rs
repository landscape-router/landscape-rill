//! underlay 传输抽象（REQ-054）：报文语义 trait + 裸 UDP/真 TCP 兜底两档。
//! 帧字节跨传输逐字节一致——流式仅外覆 2B BE 长度前缀，帧与 probe 靠
//! 首字节分类共存一条流；身份在帧头（"只信任帧"），连接管理（惰性 connect、
//! 断线移除重连）全部是实现内部细节，对 MeshData 只暴露报文原语。

use bytes::{Bytes, BytesMut};
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, Mutex as AsyncMutex};
use tracing::debug;

/// 连接表容量上限：超限整体清空（对端重连为惰性 connect，连接风暴有界）
pub const MAX_TCP_CONNS: usize = 1024;

/// 报文语义传输接缝（REQ-054 决策 1）：buffer 传参与 REQ-053 的 BytesMut 对齐。
/// recv 约定：入口 buf 为空，返回时恰好追加一个报文（帧或 probe）；
/// 超长报文显式 `InvalidData`（调用方计全局丢帧桶）。
pub trait UnderlayTransport: Send + Sync + 'static {
    /// 发送一个报文到 addr；连接式传输内部惰性建连，
    /// 发送失败即返回错误（喂端点 miss 机器，REQ-054 决策 7）
    fn send_frame(
        &self,
        addr: SocketAddr,
        buf: &[u8],
    ) -> impl Future<Output = io::Result<usize>> + Send;
    fn recv_frame(
        &mut self,
        buf: &mut BytesMut,
    ) -> impl Future<Output = io::Result<SocketAddr>> + Send;
    fn local_endpoint(&self) -> io::Result<SocketAddr>;
}

// ==================== 裸 UDP（默认档） ====================

pub struct UdpTransport {
    socket: UdpSocket,
}

impl UdpTransport {
    pub async fn bind(bind: SocketAddr) -> io::Result<Self> {
        Ok(Self {
            socket: UdpSocket::bind(bind).await?,
        })
    }
}

impl UnderlayTransport for UdpTransport {
    async fn send_frame(&self, addr: SocketAddr, buf: &[u8]) -> io::Result<usize> {
        self.socket.send_to(buf, addr).await
    }

    async fn recv_frame(&mut self, buf: &mut BytesMut) -> io::Result<SocketAddr> {
        buf.reserve(super::MAX_FRAME);
        let (n, from) = self.socket.recv_buf_from(buf).await?;
        // 超长报文被内核截断 → 丢弃（显式错误，调用方计全局桶）
        if n >= super::MAX_FRAME {
            buf.clear();
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "frame exceeds MAX_FRAME",
            ));
        }
        Ok(from)
    }

    fn local_endpoint(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}

// ==================== 真 TCP（UDP 封禁兜底档） ====================

/// TCP 连接表：addr → 写半。出站连接以拨号地址为键；入站连接以对端
/// 临时源地址为键（回包命中缓存的入站连接，NAT 后也可达）。
type ConnTable = Arc<Mutex<HashMap<SocketAddr, Arc<AsyncMutex<tokio::net::tcp::OwnedWriteHalf>>>>>;

pub struct TcpTransport {
    /// 绑定的本地监听端点（listener 本体由 accept 任务持有，随任务生命周期）
    local: SocketAddr,
    conns: ConnTable,
    /// 入站报文队列（accept/reader 任务 → recv_frame）
    rx: mpsc::Receiver<(SocketAddr, Bytes)>,
    tx: mpsc::Sender<(SocketAddr, Bytes)>,
}

impl TcpTransport {
    pub async fn bind(bind: SocketAddr) -> io::Result<Self> {
        let listener = TcpListener::bind(bind).await?;
        let local = listener.local_addr()?;
        let (tx, rx) = mpsc::channel::<(SocketAddr, Bytes)>(256);
        let conns: ConnTable = Arc::default();
        let accept_conns = conns.clone();
        let accept_tx = tx.clone();
        // accept 循环：入站连接注册写半 + 起 reader（帧/probe 共流分帧）
        tokio::spawn(async move {
            loop {
                let Ok((stream, peer)) = listener.accept().await else {
                    break;
                };
                let (rd, wr) = stream.into_split();
                let _ = insert_conn(&accept_conns, peer, wr);
                tokio::spawn(read_conn(rd, peer, accept_tx.clone()));
            }
        });
        Ok(Self {
            local,
            conns,
            rx,
            tx,
        })
    }
}

fn insert_conn(
    table: &ConnTable,
    addr: SocketAddr,
    wr: tokio::net::tcp::OwnedWriteHalf,
) -> Arc<AsyncMutex<tokio::net::tcp::OwnedWriteHalf>> {
    let half = Arc::new(AsyncMutex::new(wr));
    let mut t = table.lock().unwrap();
    if t.len() >= MAX_TCP_CONNS {
        t.clear();
    }
    t.insert(addr, half.clone());
    half
}

/// 单连接 reader：循环读 2B 长度前缀 + 报文体。EOF/前缀越界 → 断开。
async fn read_conn(
    mut rd: tokio::net::tcp::OwnedReadHalf,
    addr: SocketAddr,
    tx: mpsc::Sender<(SocketAddr, Bytes)>,
) {
    let mut prefix = [0u8; 2];
    loop {
        if rd.read_exact(&mut prefix).await.is_err() {
            break;
        }
        let len = u16::from_be_bytes(prefix) as usize;
        if len == 0 || len > super::MAX_FRAME {
            debug!("[tcp-underlay] 前缀越界（{}B），断开 {}", len, addr);
            break;
        }
        let mut pkt = vec![0u8; len];
        if rd.read_exact(&mut pkt).await.is_err() {
            break;
        }
        if tx.send((addr, Bytes::from(pkt))).await.is_err() {
            break;
        }
    }
}

impl UnderlayTransport for TcpTransport {
    async fn send_frame(&self, addr: SocketAddr, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() || buf.len() > u16::MAX as usize {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad frame len"));
        }
        // 查缓存连接 → 未命中惰性 connect（无退避：失败交给调用方 miss 机器）。
        // 并发首发同一 addr 可能重复建连，后插入者覆盖——前者写半被弃，
        // 对端读侧 EOF 重连即可，代价可忽略
        let existing = self.conns.lock().unwrap().get(&addr).cloned();
        let half = match existing {
            Some(h) => h,
            None => {
                let stream = TcpStream::connect(addr).await?;
                let (rd, wr) = stream.into_split();
                tokio::spawn(read_conn(rd, addr, self.tx.clone()));
                insert_conn(&self.conns, addr, wr)
            }
        };
        let mut w = half.lock().await;
        let sent = async {
            w.write_all(&(buf.len() as u16).to_be_bytes()).await?;
            w.write_all(buf).await
        }
        .await;
        match sent {
            Ok(()) => Ok(buf.len()),
            // 断线信号回喂（REQ-054 决策 7）：移除死连接，下次发送重连
            Err(e) => {
                self.conns.lock().unwrap().remove(&addr);
                Err(e)
            }
        }
    }

    async fn recv_frame(&mut self, buf: &mut BytesMut) -> io::Result<SocketAddr> {
        // 流式兜底档：从内部队列拷入调用方缓冲（UDP 档保持直写零拷贝）
        match self.rx.recv().await {
            Some((addr, pkt)) => {
                buf.extend_from_slice(&pkt);
                Ok(addr)
            }
            None => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "tcp underlay closed",
            )),
        }
    }

    fn local_endpoint(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }
}

// ==================== 传输谱系（REQ-054 决策 4） ====================

/// v1 传输谱系：裸 UDP（默认）/ 真 TCP 兜底；XDP 伪装（REQ-055）后续并入
pub enum Underlay {
    Udp(UdpTransport),
    Tcp(TcpTransport),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnderlayKind {
    Udp,
    Tcp,
}

impl Underlay {
    pub fn kind(&self) -> UnderlayKind {
        match self {
            Self::Udp(_) => UnderlayKind::Udp,
            Self::Tcp(_) => UnderlayKind::Tcp,
        }
    }
}

impl UnderlayTransport for Underlay {
    async fn send_frame(&self, addr: SocketAddr, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Udp(u) => u.send_frame(addr, buf).await,
            Self::Tcp(t) => t.send_frame(addr, buf).await,
        }
    }

    async fn recv_frame(&mut self, buf: &mut BytesMut) -> io::Result<SocketAddr> {
        match self {
            Self::Udp(u) => u.recv_frame(buf).await,
            Self::Tcp(t) => t.recv_frame(buf).await,
        }
    }

    fn local_endpoint(&self) -> io::Result<SocketAddr> {
        match self {
            Self::Udp(u) => u.local_endpoint(),
            Self::Tcp(t) => t.local_endpoint(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 任意可分类报文（首字节 0x01 = 帧路径）；内容对传输层不透明
    fn sample_frame(n: usize) -> Vec<u8> {
        (0..n)
            .map(|i| if i == 0 { 0x01 } else { (i % 251) as u8 })
            .collect()
    }

    #[tokio::test]
    async fn udp_datagram_is_bare_frame_bytes() {
        // 帧字节断言（REQ-054 决策 3）：UDP 报文 = 帧本体，无任何前缀
        let frame = sample_frame(96);
        let ua = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let mut ub = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let b_ep = ub.local_endpoint().unwrap();
        ua.send_frame(b_ep, &frame).await.unwrap();
        let mut buf = BytesMut::new();
        let from = ub.recv_frame(&mut buf).await.unwrap();
        assert_eq!(from, ua.local_endpoint().unwrap());
        assert_eq!(&buf[..], &frame[..]);
    }

    #[tokio::test]
    async fn tcp_wire_is_length_prefixed_frame_bytes() {
        // 帧字节断言（REQ-054 决策 3）：TCP 线上 = 2B BE 长度前缀 + 帧本体
        let frame = sample_frame(128);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ep = listener.local_addr().unwrap();
        let t = TcpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        t.send_frame(ep, &frame).await.unwrap();
        let (mut sock, peer) = listener.accept().await.unwrap();
        let mut wire = vec![0u8; 2 + frame.len()];
        sock.read_exact(&mut wire).await.unwrap();
        assert_eq!(&wire[..2], &(frame.len() as u16).to_be_bytes());
        assert_eq!(&wire[2..], &frame[..]);
        // 对端 remote = 出站连接的临时源口（非发送方监听口）
        assert!(peer.ip().is_loopback());
    }

    #[tokio::test]
    async fn tcp_transport_pair_roundtrip_both_directions() {
        let mut a = TcpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let mut b = TcpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let (a_ep, b_ep) = (a.local_endpoint().unwrap(), b.local_endpoint().unwrap());
        // a → b：惰性 connect 命中 b 的监听
        let f1 = sample_frame(64);
        a.send_frame(b_ep, &f1).await.unwrap();
        let mut buf = BytesMut::new();
        let from = b.recv_frame(&mut buf).await.unwrap();
        // 源地址 = a 出站连接的临时口（连接表键），非 a 的监听口
        assert!(from.ip().is_loopback());
        assert_eq!(&buf[..], &f1[..]);
        // b → a：反向拨号 a 的监听
        let f2 = sample_frame(48);
        b.send_frame(a_ep, &f2).await.unwrap();
        let mut buf2 = BytesMut::new();
        a.recv_frame(&mut buf2).await.unwrap();
        assert_eq!(&buf2[..], &f2[..]);
        // 连接缓存：同目标二次发送复用连接（a 的连接表非空即可证）
        a.send_frame(b_ep, &f1).await.unwrap();
        let mut buf3 = BytesMut::new();
        b.recv_frame(&mut buf3).await.unwrap();
        assert_eq!(&buf3[..], &f1[..]);
    }

    #[tokio::test]
    async fn tcp_connect_refused_and_bad_len_error() {
        let t = TcpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        // 端口无监听 → connect 拒绝 → 显式错误（喂 miss 机器）
        let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_ep = dead.local_addr().unwrap();
        drop(dead);
        assert!(t.send_frame(dead_ep, b"x").await.is_err());
        // 空报文 / 超 u16 长度 → InvalidInput
        assert!(t.send_frame(dead_ep, &[]).await.is_err());
        let big = sample_frame(70000);
        assert!(t.send_frame(dead_ep, &big).await.is_err());
    }
}
