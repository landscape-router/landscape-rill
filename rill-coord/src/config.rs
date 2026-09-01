//! coordinator 管理面配置（REQ-038 / REQ-036，CONTROL_PLANE §3.12/§6）
//!
//! 配置与执行分离：本模块只做解析与校验（加载即校验，fail-closed）；
//! 生效走 `apply_to`（库 API，函数调用），CLI/未来管理面为薄调用层。
//! 变更生效 = SIGHUP 重载：重新 parse/validate 后再次 apply_to（增量收敛）。
//! lrk auth key 格式见 [`authkey`](crate::authkey)。

use crate::authkey::{parse_auth_key, validate_network};
use crate::coordinator::Coordinator;
use landscape_rill_core::control::registry::{AuthKeyPolicy, AuthKeySpec};
use landscape_rill_core::error::ErrorId;
use landscape_rill_core::route::Prefix;
use serde::Deserialize;
use std::net::SocketAddr;

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
    use crate::authkey::generate_auth_key;

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
