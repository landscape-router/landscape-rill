use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MAX_MESSAGE_LEN: u32 = 1 << 20;

pub mod error;
pub use error::FrameError;

pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>, std::io::Error> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_MESSAGE_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            FrameError::TooLong,
        ));
    }
    let mut body = vec![0u8; len as usize];
    reader.read_exact(&mut body).await?;
    Ok(body)
}

/// 缓冲式收帧（CONTROL_PLANE §3 帧格式不变；取消安全变体）。
/// read_exact 的部分进度随 future 一起被丢弃——调用方 run loop 的 select!
/// 随时取消在途读 future，字节一旦从流中读出即丢失 → 流位置错位 → 后续
/// 把帧体当长度前缀读（"message too long"）。此变体把字节直接追进调用方
/// 持久缓冲（read_buf），取消后下次调用从缓冲续读，零丢失
pub async fn read_frame_buf<R: AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut BytesMut,
) -> Result<Vec<u8>, std::io::Error> {
    loop {
        if buf.len() >= 4 {
            let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
            if len > MAX_MESSAGE_LEN {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    FrameError::TooLong,
                ));
            }
            let total = 4 + len as usize;
            if buf.len() >= total {
                let body = buf[4..total].to_vec();
                buf.advance(total);
                return Ok(body);
            }
        }
        let n = reader.read_buf(buf).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "frame truncated",
            ));
        }
    }
}

pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    body: &[u8],
) -> Result<(), std::io::Error> {
    if body.len() as u64 > u32::MAX as u64 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            FrameError::TooLong,
        ));
    }
    writer.write_all(&(body.len() as u32).to_be_bytes()).await?;
    writer.write_all(body).await?;
    writer.flush().await
}

/// 手写长度前缀的唯一合法入口（畸形/预认证语料专用）：u32 宽度在此钉死，
/// 传 u64/u16 直接编译失败，杜绝宽度错配使流错位、read_exact 永久阻塞
pub async fn write_declared_len<W: AsyncWrite + Unpin>(
    writer: &mut W,
    declared: u32,
) -> Result<(), std::io::Error> {
    writer.write_all(&declared.to_be_bytes()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::duplex;

    #[tokio::test]
    async fn frame_roundtrip() {
        let (mut a, mut b) = duplex(1024);
        let payload = vec![0x42; 300];
        let value = payload.clone();
        let writer = tokio::spawn(async move {
            write_frame(&mut a, &value).await.unwrap();
        });
        let body = read_frame(&mut b).await.unwrap();
        writer.await.unwrap();
        assert_eq!(body, payload);
    }

    // ---- 取消安全（CONTROL_PLANE §3）：select! 丢弃部分进度的读 future 后，
    // 已读字节必须留在持久缓冲里供下次续读，不得随 future 丢掉 ----

    #[tokio::test]
    async fn buffered_read_survives_cancellation_mid_frame() {
        let (mut a, mut b) = duplex(1024);
        // 只送长度前缀前 3 字节 → 读 future 必然停在 Pending 且已有部分进度
        a.write_all(&[0x00, 0x00, 0x00]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        let mut buf = BytesMut::new();
        {
            let f = read_frame_buf(&mut b, &mut buf);
            tokio::pin!(f);
            tokio::select! {
                biased;
                r = &mut f => panic!("incomplete frame must not complete: {r:?}"),
                _ = tokio::task::yield_now() => {}
            }
        }
        // 取消丢 future 后补齐（第 4 前缀字节 + 帧体），续读必须还原完整帧
        a.write_all(&[0x0a]).await.unwrap();
        a.write_all(&[0x41; 10]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        let body = read_frame_buf(&mut b, &mut buf).await.unwrap();
        assert_eq!(body, vec![0x41; 10]);
    }

    #[tokio::test]
    async fn buffered_read_holds_second_frame_after_first() {
        let (mut a, mut b) = duplex(1024);
        let mut buf = BytesMut::new();
        write_frame(&mut a, &[0x41; 4]).await.unwrap();
        write_frame(&mut a, &[0x42; 6]).await.unwrap();
        assert_eq!(
            read_frame_buf(&mut b, &mut buf).await.unwrap(),
            vec![0x41; 4]
        );
        assert_eq!(
            read_frame_buf(&mut b, &mut buf).await.unwrap(),
            vec![0x42; 6]
        );
        assert!(buf.is_empty());
    }

    #[tokio::test]
    async fn buffered_read_rejects_oversize_and_eof() {
        let (mut a, mut b) = duplex(64);
        let mut buf = BytesMut::new();
        write_declared_len(&mut a, MAX_MESSAGE_LEN + 1)
            .await
            .unwrap();
        assert_eq!(
            read_frame_buf(&mut b, &mut buf).await.unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
        let (mut c, mut d) = duplex(64);
        let mut buf2 = BytesMut::new();
        write_declared_len(&mut c, 8).await.unwrap();
        c.write_all(&[0u8; 3]).await.unwrap();
        drop(c);
        assert_eq!(
            read_frame_buf(&mut d, &mut buf2).await.unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    }

    #[tokio::test]
    async fn oversize_rejected() {
        let (mut a, mut b) = duplex(1024);
        write_declared_len(&mut a, u32::MAX).await.unwrap();
        a.write_all(&[0u8; 8]).await.unwrap();
        let err = read_frame(&mut b).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn truncated_rejected() {
        let (mut a, mut b) = duplex(1024);
        write_declared_len(&mut a, 64).await.unwrap();
        a.write_all(&[0u8; 16]).await.unwrap();
        drop(a);
        let err = read_frame(&mut b).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn declared_len_writes_u32_prefix() {
        let (mut a, mut b) = duplex(64);
        write_declared_len(&mut a, 0x0102_0304).await.unwrap();
        drop(a);
        let mut wire = Vec::new();
        b.read_to_end(&mut wire).await.unwrap();
        assert_eq!(wire, [0x01, 0x02, 0x03, 0x04]);
    }

    // ---- 预认证解析语料（REQ-059 / SEC-08）----
    // 长度校验必须先于 body 读取/分配：超长声明只消费 4B 头即拒绝

    fn xorshift(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    #[tokio::test]
    async fn read_frame_fuzz_corpus() {
        let mut s: u64 = 0xF3A9_0003;
        for _ in 0..300 {
            let (mut a, mut b) = duplex(1024);
            // 超长声明：无 body 字节也必须 InvalidData（而非 EOF/分配）
            let declared = MAX_MESSAGE_LEN + 1 + (xorshift(&mut s) as u32 % 1000);
            write_declared_len(&mut a, declared).await.unwrap();
            let err = read_frame(&mut b).await.unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
            // 合法声明（≥1）+ body 截断 → EOF
            let declared = 1 + (xorshift(&mut s) as u32 % 64);
            write_declared_len(&mut a, declared).await.unwrap();
            drop(a);
            let err = read_frame(&mut b).await.unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
        }
        // 合法小帧往返不受语料影响
        let (mut a, mut b) = duplex(1024);
        write_frame(&mut a, &[0x42; 100]).await.unwrap();
        assert_eq!(read_frame(&mut b).await.unwrap(), vec![0x42; 100]);
    }
}
