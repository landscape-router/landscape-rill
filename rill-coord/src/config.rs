//! coordinator 管理面配置（REQ-038 / REQ-036，CONTROL_PLANE §3.12/§6）
//!
//! 配置与执行分离：本模块只做解析与校验（加载即校验，fail-closed）；
//! 生效走 `apply_to`（库 API，函数调用），CLI/未来管理面为薄调用层。
//! 变更生效 = SIGHUP 重载：重新 parse/validate 后再次 apply_to（增量收敛）。

use crate::coordinator::Coordinator;
use landscape_rill_core::control::registry::{AuthKeyPolicy, AuthKeySpec};
use landscape_rill_core::error::ErrorId;
use landscape_rill_core::route::Prefix;
use serde::Deserialize;
use std::net::SocketAddr;

pub const AUTH_KEY_PREFIX: &str = "lrk-";
pub const AUTH_KEY_SECRET_LEN: usize = 32;
/// 32B → base32 无填充 = 52 字符（256 bits / 5 = 51.2 → 进位 52）
pub const AUTH_KEY_SECRET_CHARS: usize = 52;
/// `lrill authkey` 默认有效期（REQ-043）：auth key 仅入场令牌，短命是特性
pub const AUTH_KEY_DEFAULT_TTL_SECS: u64 = 24 * 3600;

// ============================================================================
// lrk auth key 格式（CONTROL_PLANE §6，REQ-036 + REQ-043）：
// `lrk-<network>-<expiry>-<secret>`，expiry = 十进制 unix 秒（0 = 永不过期），
// 解析即知过期（admission 时 coordinator 校验，嵌入时间仅 advisory）
// ============================================================================

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

// ============================================================================
// CoordConfig（解析 + 校验 + 应用）
// ============================================================================

#[derive(Debug, Clone, Deserialize)]
pub struct CoordConfig {
    /// 网络标识（auth key 归域绑定，CONTROL_PLANE §1.5）
    pub network: String,
    pub listen_addr: String,
    pub tls_cert_path: String,
    pub tls_key_path: String,
    #[serde(with = "hex32")]
    pub master_key: [u8; 32],
    #[serde(with = "hex32")]
    pub signing_seed: [u8; 32],
    #[serde(default)]
    pub auth_keys: Vec<AuthKeyConfig>,
    /// 允许公告的前缀集合；空 = 拒绝一切公告（fail-closed）
    #[serde(default)]
    pub announce_whitelist: Vec<String>,
    /// 持久化存储文件（REQ-037，CONTROL_PLANE §4.1）；None = 纯内存（重启丢失注册）。
    /// 仅启动时读取，SIGHUP 重载不更换存储文件。
    #[serde(default)]
    pub storage_path: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthKeyConfig {
    pub key: String,
    /// onetime | reusable
    #[serde(default = "default_policy")]
    pub policy: String,
    #[serde(default)]
    pub tag: Option<String>,
    // 过期时间内嵌在 key 自身（REQ-043），配置不再持有
}

fn default_policy() -> String {
    "reusable".into()
}

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct ConfigError(String);

impl ErrorId for ConfigError {
    fn error_id(&self) -> &'static str {
        "coord.config"
    }
    fn error_args(&self) -> landscape_rill_core::error::ErrorArgs {
        landscape_rill_core::error::args(&[])
    }
}

impl From<serde_json::Error> for ConfigError {
    fn from(e: serde_json::Error) -> Self {
        ConfigError(format!("json parse failed: {e}"))
    }
}

impl CoordConfig {
    /// 从 JSON 文本解析（加载即校验，fail-closed：任何非法配置拒绝启动）
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let cfg: CoordConfig =
            serde_json::from_str(text).map_err(|e| ConfigError(e.to_string()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn load(path: &std::path::Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| ConfigError(format!("read {}: {e}", path.display())))?;
        Self::parse(&text)
    }

    /// 校验（fail-closed）：必填字段、auth key 格式/归域、白名单前缀合法 + 长度边界
    pub fn validate(&self) -> Result<(), ConfigError> {
        validate_network(&self.network).map_err(|e| ConfigError(e.to_string()))?;
        self.listen_addr
            .parse::<SocketAddr>()
            .map_err(|_| ConfigError(format!("invalid listen_addr: {}", self.listen_addr)))?;
        for ak in &self.auth_keys {
            let (net, _, _) = parse_auth_key(&ak.key).map_err(|e| ConfigError(e.to_string()))?;
            if net != self.network {
                return Err(ConfigError(format!(
                    "auth key network mismatch: key={net} config network={}",
                    self.network
                )));
            }
            if ak.policy != "onetime" && ak.policy != "reusable" {
                return Err(ConfigError(format!("invalid policy: {}", ak.policy)));
            }
        }
        for w in &self.announce_whitelist {
            Prefix::parse(w).map_err(|_| ConfigError(format!("invalid whitelist prefix: {w}")))?;
        }
        if let Some(p) = &self.storage_path {
            if p.trim().is_empty() {
                return Err(ConfigError("storage_path is empty".into()));
            }
        }
        Ok(())
    }

    /// 应用到 Coordinator（库 API，函数调用生效；增量收敛：auth key 增删、白名单替换）
    pub fn apply_to(&self, coord: &mut Coordinator) {
        for ak in &self.auth_keys {
            let policy = match ak.policy.as_str() {
                "onetime" => AuthKeyPolicy::OneTime,
                _ => AuthKeyPolicy::Reusable,
            };
            coord.add_auth_key_spec(
                &ak.key,
                AuthKeySpec {
                    policy,
                    tag: ak.tag.clone(),
                },
            );
        }
        for existing in coord.auth_key_list() {
            if !self.auth_keys.iter().any(|ak| ak.key == existing) {
                coord.remove_auth_key(&existing);
            }
        }
        let whitelist: Vec<Prefix> = self
            .announce_whitelist
            .iter()
            .map(|w| Prefix::parse(w).expect("validated"))
            .collect();
        coord.set_announce_whitelist(whitelist);
    }
}

// ============================================================================
// hex32（[u8; 32] ⇄ 64 字符 hex，无第三方 hex crate）
// ============================================================================

mod hex32 {
    use super::*;

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let bytes = decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes (64 hex chars)"))
    }

    fn decode(s: &str) -> Result<Vec<u8>, String> {
        if !s.len().is_multiple_of(2) {
            return Err("odd hex length".into());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_config() -> String {
        format!(
            r#"{{
  "network": "lab",
  "listen_addr": "0.0.0.0:8443",
  "tls_cert_path": "/t/crt.pem",
  "tls_key_path": "/t/key.pem",
  "master_key": "{}",
  "signing_seed": "{}",
  "auth_keys": [{{ "key": "{}", "policy": "onetime" }}],
  "announce_whitelist": ["10.0.0.0/8", "fd00:2::/32"]
}}"#,
            "11".repeat(32),
            "22".repeat(32),
            generate_auth_key("lab", 3600).unwrap()
        )
    }

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

    #[test]
    fn config_parse_and_validate() {
        let cfg = CoordConfig::parse(&valid_config()).unwrap();
        assert_eq!(cfg.network, "lab");
        assert_eq!(cfg.auth_keys.len(), 1);
        assert_eq!(cfg.announce_whitelist.len(), 2);
    }

    #[test]
    fn config_rejects_network_mismatch() {
        let text = valid_config().replace("\"network\": \"lab\"", "\"network\": \"other\"");
        let err = CoordConfig::parse(&text).unwrap_err();
        assert!(err.to_string().contains("auth key network mismatch"));
    }

    #[test]
    fn config_rejects_bad_policy() {
        let text = valid_config().replace("\"policy\": \"onetime\"", "\"policy\": \"root\"");
        let err = CoordConfig::parse(&text).unwrap_err();
        assert!(err.to_string().contains("invalid policy"));
    }

    #[test]
    fn config_accepts_wide_whitelist() {
        // 白名单是允许集合，可含更宽前缀（公告边界由注册校验，§3.8）
        let text = valid_config().replace("\"10.0.0.0/8\"", "\"0.0.0.0/0\"");
        assert!(CoordConfig::parse(&text).is_ok());
        let text = valid_config().replace("\"10.0.0.0/8\"", "\"bad-cidr\"");
        assert!(CoordConfig::parse(&text).is_err());
    }

    #[test]
    fn config_missing_master_key_rejected() {
        let text = valid_config().replace(&format!("\"{}\",", "11".repeat(32)), "");
        assert!(CoordConfig::parse(&text).is_err());
    }

    #[test]
    fn apply_to_syncs_auth_keys_and_whitelist() {
        let cfg = CoordConfig::parse(&valid_config()).unwrap();
        let mut coord = Coordinator::new([0x33; 32], [0x44; 32]);
        cfg.apply_to(&mut coord);
        assert_eq!(coord.auth_key_list().len(), 1);
        assert_eq!(
            coord.announce_whitelist(),
            vec!["10.0.0.0/8", "fd00:2::/32"]
        );
        // 再应用一次（幂等）；移除 key 后收敛
        cfg.apply_to(&mut coord);
        assert_eq!(coord.auth_key_list().len(), 1);
        let empty = CoordConfig {
            auth_keys: vec![],
            ..cfg.clone()
        };
        empty.apply_to(&mut coord);
        assert!(coord.auth_key_list().is_empty());
    }
}
