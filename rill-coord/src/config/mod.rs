//! coordinator 管理面配置（REQ-038 / REQ-036，CONTROL_PLANE §3.12/§6）
//!
//! 配置与执行分离：本模块只做解析与校验（加载即校验，fail-closed）；
//! 生效走 `apply_to`（库 API，函数调用），CLI/未来管理面为薄调用层。
//! 变更生效 = SIGHUP 重载：重新 parse/validate 后再次 apply_to（增量收敛）。
//! lrk auth key 格式见 [`authkey`](crate::authkey)。
//! 多网络（CONTROL_PLANE §1.5，2026-09-01）：`networks` 列表定义隔离网络
//! （每网络独立主密钥 / auth key 空间 / 前缀白名单；network_id = fnv1a(name) 确定性散列）。

use crate::authkey::{parse_auth_key, validate_network};
use crate::coordinator::Coordinator;
use crate::domain::network_id_for;
use landscape_rill_core::control::registry::{AuthKeyPolicy, AuthKeySpec};
use landscape_rill_core::route::Prefix;
use serde::Deserialize;
use std::net::SocketAddr;

pub mod error;
pub use error::ConfigError;

// ============================================================================
// CoordConfig（解析 + 校验 + 应用）
// ============================================================================

#[derive(Debug, Clone, Deserialize)]
pub struct CoordConfig {
    pub listen_addr: String,
    pub tls_cert_path: String,
    pub tls_key_path: String,
    #[serde(with = "hex32")]
    pub signing_seed: [u8; 32],
    /// 持久化存储文件（REQ-037，CONTROL_PLANE §4.1）；None = 纯内存（重启丢失注册）。
    /// 仅启动时读取，SIGHUP 重载不更换存储文件。
    #[serde(default)]
    pub storage_path: Option<String>,
    /// UDP 数据面监听地址（CONNECTIVITY §2：coordinator 回显 + relay RTT 探测）。
    /// None = 与 listen_addr 同地址（TCP 8443 ↔ UDP 8443 协议区分）。
    #[serde(default)]
    pub udp_listen_addr: Option<String>,
    /// 隔离网络列表（CONTROL_PLANE §1.5）：每网络独立主密钥 / auth key 空间 / 白名单
    #[serde(default)]
    pub networks: Vec<NetworkConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NetworkConfig {
    /// 网络标识（auth key 归域绑定；network_id = fnv1a(name)）
    pub name: String,
    #[serde(with = "hex32")]
    pub master_key: [u8; 32],
    #[serde(default)]
    pub auth_keys: Vec<AuthKeyConfig>,
    /// 允许公告的前缀集合；空 = 拒绝一切公告（fail-closed）
    #[serde(default)]
    pub announce_whitelist: Vec<String>,
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

    /// 校验（fail-closed）：必填字段、网络唯一性、auth key 格式/归域、白名单前缀合法 + 长度边界
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.listen_addr
            .parse::<SocketAddr>()
            .map_err(|_| ConfigError(format!("invalid listen_addr: {}", self.listen_addr)))?;
        if self.networks.is_empty() {
            return Err(ConfigError("networks must not be empty".into()));
        }
        let mut seen_names = std::collections::HashSet::new();
        let mut seen_ids = std::collections::HashSet::new();
        for net in &self.networks {
            validate_network(&net.name).map_err(|e| ConfigError(e.to_string()))?;
            if !seen_names.insert(net.name.clone()) {
                return Err(ConfigError(format!("duplicate network name: {}", net.name)));
            }
            let network_id = network_id_for(&net.name);
            if !seen_ids.insert(network_id) {
                return Err(ConfigError(format!(
                    "network_id collision (fnv1a): {} / 换名",
                    net.name
                )));
            }
            for ak in &net.auth_keys {
                let (net_name, _, _) =
                    parse_auth_key(&ak.key).map_err(|e| ConfigError(e.to_string()))?;
                // 归域（CONTROL_PLANE §1.5）：key 内嵌网络必须等于所在网络段
                if net_name != net.name {
                    return Err(ConfigError(format!(
                        "auth key network mismatch: key={net_name} network segment={}",
                        net.name
                    )));
                }
                if ak.policy != "onetime" && ak.policy != "reusable" {
                    return Err(ConfigError(format!("invalid policy: {}", ak.policy)));
                }
            }
            for w in &net.announce_whitelist {
                Prefix::parse(w)
                    .map_err(|_| ConfigError(format!("invalid whitelist prefix: {w}")))?;
            }
        }
        if let Some(p) = &self.storage_path {
            if p.trim().is_empty() {
                return Err(ConfigError("storage_path is empty".into()));
            }
        }
        if let Some(addr) = &self.udp_listen_addr {
            addr.parse::<SocketAddr>()
                .map_err(|_| ConfigError(format!("invalid udp_listen_addr: {addr}")))?;
        }
        Ok(())
    }

    /// 应用到 Coordinator（库 API，函数调用生效；按网络增量收敛：auth key 增删、白名单替换）。
    /// 前提：Coordinator 已按本配置的 networks 建域（new + add_network 或 open）。
    pub fn apply_to(&self, coord: &mut Coordinator) {
        for net in &self.networks {
            for ak in &net.auth_keys {
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
            for existing in coord.auth_key_list_for(&net.name) {
                if !net.auth_keys.iter().any(|ak| ak.key == existing) {
                    coord.remove_auth_key(&existing);
                }
            }
            let whitelist: Vec<Prefix> = net
                .announce_whitelist
                .iter()
                .map(|w| Prefix::parse(w).expect("validated"))
                .collect();
            coord.set_announce_whitelist(&net.name, whitelist);
        }
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
  "listen_addr": "0.0.0.0:8443",
  "tls_cert_path": "/t/crt.pem",
  "tls_key_path": "/t/key.pem",
  "signing_seed": "{}",
  "networks": [
    {{
      "name": "lab",
      "master_key": "{}",
      "auth_keys": [{{ "key": "{}", "policy": "onetime" }}],
      "announce_whitelist": ["10.0.0.0/8", "fd00:2::/32"]
    }}
  ]
}}"#,
            "22".repeat(32),
            "11".repeat(32),
            generate_auth_key("lab", 3600).unwrap()
        )
    }

    #[test]
    fn config_parse_and_validate() {
        let cfg = CoordConfig::parse(&valid_config()).unwrap();
        assert_eq!(cfg.networks.len(), 1);
        assert_eq!(cfg.networks[0].name, "lab");
        assert_eq!(cfg.networks[0].auth_keys.len(), 1);
        assert_eq!(cfg.networks[0].announce_whitelist.len(), 2);
    }

    #[test]
    fn config_rejects_network_mismatch() {
        let text = valid_config().replace("\"name\": \"lab\"", "\"name\": \"other\"");
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
    fn config_empty_networks_rejected() {
        let text = format!(
            r#"{{
  "listen_addr": "0.0.0.0:8443",
  "tls_cert_path": "/t/crt.pem",
  "tls_key_path": "/t/key.pem",
  "signing_seed": "{}",
  "networks": []
}}"#,
            "22".repeat(32)
        );
        let err = CoordConfig::parse(&text).unwrap_err();
        assert!(err.to_string().contains("networks must not be empty"));
    }

    #[test]
    fn config_duplicate_network_rejected() {
        // 同名单网络段 → 拒绝
        let net = format!(
            r#"{{
        "name": "lab",
        "master_key": "{}",
        "auth_keys": [],
        "announce_whitelist": []
      }}"#,
            "33".repeat(32)
        );
        let text = format!(
            r#"{{
  "listen_addr": "0.0.0.0:8443",
  "tls_cert_path": "/t/crt.pem",
  "tls_key_path": "/t/key.pem",
  "signing_seed": "{}",
  "networks": [{net}]
}}"#,
            "22".repeat(32)
        );
        // 两份 lab → duplicate
        let dup = text.replace(&net.clone(), &format!("{net}, {net}"));
        assert!(CoordConfig::parse(&dup).is_err());
    }

    #[test]
    fn config_multi_network_ok() {
        let ka = generate_auth_key("lab", 3600).unwrap();
        let kb = generate_auth_key("work", 3600).unwrap();
        let text = format!(
            r#"{{
  "listen_addr": "0.0.0.0:8443",
  "tls_cert_path": "/t/crt.pem",
  "tls_key_path": "/t/key.pem",
  "signing_seed": "{}",
  "networks": [
    {{ "name": "lab", "master_key": "{}", "auth_keys": [{{ "key": "{ka}", "policy": "reusable" }}], "announce_whitelist": ["10.0.0.0/8"] }},
    {{ "name": "work", "master_key": "{}", "auth_keys": [{{ "key": "{kb}", "policy": "reusable" }}], "announce_whitelist": ["192.168.0.0/16"] }}
  ]
}}"#,
            "22".repeat(32),
            "11".repeat(32),
            "44".repeat(32)
        );
        let cfg = CoordConfig::parse(&text).unwrap();
        assert_eq!(cfg.networks.len(), 2);
        // 跨网络 key 放错段 → 拒绝
        let bad = text.replace(&format!("\"key\": \"{kb}\""), &format!("\"key\": \"{ka}\""));
        assert!(CoordConfig::parse(&bad).is_err());
    }

    #[test]
    fn apply_to_syncs_auth_keys_and_whitelist() {
        let cfg = CoordConfig::parse(&valid_config()).unwrap();
        let mut coord = Coordinator::new([0x44; 32]);
        for net in &cfg.networks {
            coord.add_network(&net.name, net.master_key);
        }
        cfg.apply_to(&mut coord);
        assert_eq!(coord.auth_key_list().len(), 1);
        assert_eq!(
            coord.announce_whitelist("lab"),
            vec!["10.0.0.0/8", "fd00:2::/32"]
        );
        // 再应用一次（幂等）；移除 key 后收敛
        cfg.apply_to(&mut coord);
        assert_eq!(coord.auth_key_list().len(), 1);
        let empty = CoordConfig {
            networks: vec![NetworkConfig {
                name: "lab".into(),
                master_key: [0x11; 32],
                auth_keys: vec![],
                announce_whitelist: vec![],
            }],
            ..cfg.clone()
        };
        empty.apply_to(&mut coord);
        assert!(coord.auth_key_list().is_empty());
    }
}
