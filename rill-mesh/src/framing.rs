use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MAX_MESSAGE_LEN: u32 = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, landscape_rill_macro::ErrorId)]
pub enum FrameError {
    #[error("message too long")]
    #[error_id("mesh.frame.too_long")]
    TooLong,
    #[error("truncated frame")]
    #[error_id("mesh.frame.truncated")]
    Truncated,
}

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
        a.write_all(&(u32::MAX).to_be_bytes()).await.unwrap();
        a.write_all(&[0u8; 8]).await.unwrap();
        let err = read_frame(&mut b).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn truncated_rejected() {
        let (mut a, mut b) = duplex(1024);
        a.write_all(&64u32.to_be_bytes()).await.unwrap();
        a.write_all(&[0u8; 16]).await.unwrap();
        drop(a);
        let err = read_frame(&mut b).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }
}
