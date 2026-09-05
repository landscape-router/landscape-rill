//! 标准 base64（RFC 4648 带填充），用于 X-Tailscale-Handshake 头。
//! 自研以避免引入依赖（REQ-044 依赖最小化）；编解码互为对照测试。

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid base64 input")]
pub struct Base64Error;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

pub fn decode(s: &str) -> Result<Vec<u8>, Base64Error> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return Err(Base64Error);
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for (i, quad) in bytes.chunks(4).enumerate() {
        let is_last = i + 1 == bytes.len() / 4;
        let pad = quad.iter().filter(|&&c| c == b'=').count();
        // '=' 只能出现在末组结尾（1 或 2 个）
        if pad > 2
            || (!is_last && pad > 0)
            || (is_last && pad > 0 && quad[4 - pad..].iter().any(|&c| c != b'='))
        {
            return Err(Base64Error);
        }
        let mut n: u32 = 0;
        for &c in &quad[..4 - pad] {
            let v = match c {
                b'A'..=b'Z' => (c - b'A') as u32,
                b'a'..=b'z' => (c - b'a' + 26) as u32,
                b'0'..=b'9' => (c - b'0' + 52) as u32,
                b'+' => 62,
                b'/' => 63,
                _ => return Err(Base64Error),
            };
            n = (n << 6) | v;
        }
        n <<= 6 * pad as u32;
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vectors() {
        assert_eq!(encode(b""), "");
        assert_eq!(encode(b"f"), "Zg==");
        assert_eq!(encode(b"fo"), "Zm8=");
        assert_eq!(encode(b"foo"), "Zm9v");
        assert_eq!(encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(decode("Zg==").unwrap(), b"f");
        assert_eq!(decode("Zm9vYmFy").unwrap(), b"foobar");
    }

    #[test]
    fn roundtrip_binary() {
        for len in [0usize, 1, 2, 3, 96, 101] {
            let data: Vec<u8> = (0..len).map(|i| (i * 37 % 256) as u8).collect();
            assert_eq!(decode(&encode(&data)).unwrap(), data, "len={len}");
        }
    }

    #[test]
    fn rejects_malformed() {
        assert!(decode("A").is_err()); // 长度非 4 倍数
        assert!(decode("ABCD").is_ok());
        assert!(decode("AB=D").is_err()); // '=' 位置非法
        assert!(decode("ABC=ABCD").is_err()); // 中间组带填充
        assert!(decode("AB!D").is_err()); // 非法字符
    }
}
