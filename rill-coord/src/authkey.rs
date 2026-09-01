//! lrk auth key 格式（CONTROL_PLANE §6，REQ-036 + REQ-043）
//!
//! `lrk-<network>-<expiry>-<secret>`：expiry = 十进制 unix 秒（0 = 永不过期），
//! 解析即知过期（admission 时 coordinator 校验，嵌入时间仅 advisory）。
//! network 段规范：小写字母/数字，非空，**不含连字符**（段分隔符冲突）。

pub const AUTH_KEY_PREFIX: &str = "lrk-";
pub const AUTH_KEY_SECRET_LEN: usize = 32;
/// 32B → base32 无填充 = 52 字符（256 bits / 5 = 51.2 → 进位 52）
pub const AUTH_KEY_SECRET_CHARS: usize = 52;
/// `lrill authkey` 默认有效期（REQ-043）：auth key 仅入场令牌，短命是特性
pub const AUTH_KEY_DEFAULT_TTL_SECS: u64 = 24 * 3600;

const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() * 8).div_ceil(5));
    let mut buffer: u64 = 0;
    let mut bits: u32 = 0;
    for &b in data {
        buffer = (buffer << 8) | b as u64;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(BASE32_ALPHABET[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(BASE32_ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut buffer: u64 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    for c in s.bytes() {
        let v = BASE32_ALPHABET.iter().position(|&a| a == c)? as u64;
        buffer = (buffer << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    // 无填充规范：尾部不足一字节的残留位必须全零
    if bits > 0 && buffer & ((1 << bits) - 1) != 0 {
        return None;
    }
    Some(out)
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, landscape_rill_macro::ErrorId)]
pub enum AuthKeyError {
    #[error("auth key must start with lrk-")]
    #[error_id("coord.auth_key.bad_prefix")]
    BadPrefix,
    #[error("auth key format must be lrk-<network>-<expiry>-<secret>")]
    #[error_id("coord.auth_key.bad_format")]
    BadFormat,
    #[error("invalid network segment (lowercase alphanumeric, no dashes)")]
    #[error_id("coord.auth_key.bad_network")]
    BadNetwork,
    #[error("invalid expiry segment (decimal unix seconds, 0 = never expires)")]
    #[error_id("coord.auth_key.bad_expiry")]
    BadExpiry,
    #[error("invalid auth key secret length")]
    #[error_id("coord.auth_key.bad_secret_len")]
    BadSecretLen,
    #[error("invalid auth key secret characters")]
    #[error_id("coord.auth_key.bad_secret")]
    BadSecret,
}

/// network 段规范：小写字母/数字，非空，**不含连字符**（段分隔符为 `-`，
/// 含连字符的网络名在 `lrk-<network>-...` 下无法无损解析，REQ-043 收紧）
pub fn validate_network(network: &str) -> Result<(), AuthKeyError> {
    if network.is_empty()
        || !network
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
    {
        return Err(AuthKeyError::BadNetwork);
    }
    Ok(())
}

/// 生成 `lrk-<network>-<expiry>-<secret>`（32B CSPRNG → base32）。纯本地，不依赖 master_key。
/// `ttl_secs = 0` = 永不过期（expiry 段写 0）；否则 expiry = now + ttl。
pub fn generate_auth_key(network: &str, ttl_secs: u64) -> Result<String, AuthKeyError> {
    validate_network(network)?;
    let expiry = if ttl_secs == 0 {
        0
    } else {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
            .saturating_add(ttl_secs)
    };
    let secret: [u8; AUTH_KEY_SECRET_LEN] = rand::random();
    Ok(format!(
        "{}{}-{}-{}",
        AUTH_KEY_PREFIX,
        network,
        expiry,
        base32_encode(&secret)
    ))
}

/// 解析并校验 auth key，返回 (network, expiry_unix, secret)；`expiry = 0` = 永不过期
pub fn parse_auth_key(key: &str) -> Result<(&str, u64, &str), AuthKeyError> {
    let rest = key
        .strip_prefix(AUTH_KEY_PREFIX)
        .ok_or(AuthKeyError::BadPrefix)?;
    let (network, tail) = rest.split_once('-').ok_or(AuthKeyError::BadFormat)?;
    let (expiry, secret) = tail.split_once('-').ok_or(AuthKeyError::BadFormat)?;
    validate_network(network)?;
    let expiry = expiry.parse::<u64>().map_err(|_| AuthKeyError::BadExpiry)?;
    if secret.len() != AUTH_KEY_SECRET_CHARS {
        return Err(AuthKeyError::BadSecretLen);
    }
    let decoded = base32_decode(secret).ok_or(AuthKeyError::BadSecret)?;
    if decoded.len() != AUTH_KEY_SECRET_LEN {
        return Err(AuthKeyError::BadSecretLen);
    }
    Ok((network, expiry, secret))
}

/// 是否已过期（`expiry = 0` = 永不过期）。解析失败视为未过期（格式问题由 admission 拒绝）
pub fn is_expired(key: &str, now: u64) -> bool {
    match parse_auth_key(key) {
        Ok((_, expiry, _)) => expiry != 0 && now > expiry,
        Err(_) => false,
    }
}

/// CLI 时长解析：`<num><s|m|h|d>`（如 30m / 12h / 7d）；`0` = 永不过期
pub fn parse_duration(s: &str) -> Result<u64, AuthKeyError> {
    if s == "0" {
        return Ok(0);
    }
    let (num, unit) = s.split_at(s.len() - 1);
    let num: u64 = num.parse().map_err(|_| AuthKeyError::BadExpiry)?;
    let mult = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        _ => return Err(AuthKeyError::BadExpiry),
    };
    Ok(num.saturating_mul(mult))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_parse_roundtrip() {
        let key = generate_auth_key("lab", 3600).unwrap();
        assert!(key.starts_with("lrk-lab-"));
        let (net, expiry, secret) = parse_auth_key(&key).unwrap();
        assert_eq!(net, "lab");
        assert_eq!(secret.len(), 52);
        assert!(expiry > 1_700_000_000); // 当前 unix 秒量级
                                         // 永不过期（ttl=0）
        let never = generate_auth_key("lab", 0).unwrap();
        assert_eq!(parse_auth_key(&never).unwrap().1, 0);
        assert!(!is_expired(&never, u64::MAX));
    }

    #[test]
    fn parse_rejects_bad_keys() {
        assert_eq!(
            parse_auth_key("tskey-auth-abc").unwrap_err(),
            AuthKeyError::BadPrefix
        );
        assert_eq!(
            parse_auth_key("lrk-nosecret").unwrap_err(),
            AuthKeyError::BadFormat
        );
        assert_eq!(
            parse_auth_key("lrk-BadNet-0-AAAA").unwrap_err(),
            AuthKeyError::BadNetwork
        );
        // network 含连字符（段分隔符冲突）：按首个 `-` 切分后 expiry 段无法解析 → 拒绝
        assert_eq!(
            parse_auth_key("lrk-lab-x-0-AAAA").unwrap_err(),
            AuthKeyError::BadExpiry
        );
        assert_eq!(
            validate_network("lab-x").unwrap_err(),
            AuthKeyError::BadNetwork
        );
        // expiry 段非法
        assert_eq!(
            parse_auth_key(&format!("lrk-lab-abc-{}", "A".repeat(52))).unwrap_err(),
            AuthKeyError::BadExpiry
        );
        assert_eq!(
            parse_auth_key(&format!("lrk-lab--{}", "A".repeat(52))).unwrap_err(),
            AuthKeyError::BadExpiry
        );
        // 缺 expiry 段 / expiry 段非数字
        let short = format!("lrk-lab-{}", "A".repeat(52));
        assert_eq!(parse_auth_key(&short).unwrap_err(), AuthKeyError::BadFormat);
        let short = format!("lrk-lab-{}-{}", "A".repeat(10), "A".repeat(10));
        assert_eq!(parse_auth_key(&short).unwrap_err(), AuthKeyError::BadExpiry);
        // 非法 base32 字符
        let bad = format!("lrk-lab-0-{}{}", "A".repeat(51), "1");
        assert_eq!(parse_auth_key(&bad).unwrap_err(), AuthKeyError::BadSecret);
    }

    #[test]
    fn expired_key_parses_and_checks() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let key = format!("lrk-lab-{}-{}", now + 100, "A".repeat(52));
        assert!(!is_expired(&key, now));
        assert!(is_expired(&key, now + 200));
        // 解析失败视为未过期（admission 层格式校验拒绝）
        assert!(!is_expired("not-a-key", now));
    }

    #[test]
    fn parse_duration_units() {
        assert_eq!(parse_duration("0").unwrap(), 0);
        assert_eq!(parse_duration("30s").unwrap(), 30);
        assert_eq!(parse_duration("5m").unwrap(), 300);
        assert_eq!(parse_duration("12h").unwrap(), 43200);
        assert_eq!(parse_duration("7d").unwrap(), 604800);
        assert!(parse_duration("5x").is_err());
        assert!(parse_duration("h").is_err());
        assert!(parse_duration("abc").is_err());
    }

    #[test]
    fn base32_roundtrip() {
        let data: [u8; 32] = rand::random();
        let enc = base32_encode(&data);
        assert_eq!(enc.len(), 52);
        assert_eq!(base32_decode(&enc).unwrap(), data.to_vec());
        // 篡改最后一个字符（低 4 位残留位非零）→ 解码拒绝
        let mut s = enc.clone().into_bytes();
        let last = s[51];
        let flipped = match last {
            b'A' => b'C',
            b'Q' => b'C',
            other => {
                let v = BASE32_ALPHABET.iter().position(|&a| a == other).unwrap();
                BASE32_ALPHABET[(v + 1) % 32]
            }
        };
        s[51] = flipped;
        assert!(base32_decode(std::str::from_utf8(&s).unwrap()).is_none());
    }
}
