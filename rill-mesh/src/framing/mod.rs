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
