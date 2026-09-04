use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

pub const DEFAULT_COORD_PORT: u16 = 8443;
pub const DEFAULT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);
pub const DEFAULT_LEASE_THRESHOLD: Duration = Duration::from_secs(60);
pub const DEFAULT_SESSION_REKEY_HOURS: u64 = 24;

/// 数据面 underlay 传输（REQ-054）：Udp 默认；Tcp 为 UDP 封禁兜底
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DataTransport {
    #[default]
    Udp,
    Tcp,
}

impl DataTransport {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "udp" => Some(Self::Udp),
            "tcp" => Some(Self::Tcp),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub coordinator_url: String,
    pub auth_key: String,
    pub static_key_seed: [u8; 32],
    pub capabilities: u32,
    pub announce_routes: Vec<String>,
    /// coordinator 签名公钥（Ed25519 32B）：身份绑定验证信任锚，管理面预置（与自签 CA 同哲学）
    pub coord_signing_pubkey: [u8; 32],
    /// TLS 信任锚 CA 证书路径（内网部署形态；公网 PKI 留 webpki-roots）
    pub ca_cert_path: String,
    /// coordinator UDP 回显目标（CONNECTIVITY §2，"host:port" 允许主机名）；
    /// None = 按 coordinator_url 推导（coordinator 默认 TCP/UDP 同端口）
    pub udp_echo_addr: Option<String>,
    /// 数据面 underlay 传输（REQ-054）：v1 全网统一（UDP 默认 / TCP 兜底）
    pub data_transport: DataTransport,
    pub coord: Option<CoordConfig>,
    /// dn42 接入（DN42_LEG）：None = 未启用
    pub dn42: Option<Dn42Config>,
}

impl Config {
    /// 从 coordinator_url 推导 UDP 回显目标 "host:port"（`https://host[:port]`，缺省 8443）
    pub fn coord_echo_target(url: &str) -> String {
        let rest = url.strip_prefix("https://").unwrap_or(url);
        match rest.rsplit_once(':') {
            Some((_, p)) if p.parse::<u16>().is_ok() => rest.to_string(),
            _ => format!("{rest}:{DEFAULT_COORD_PORT}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoordConfig {
    pub listen_addr: SocketAddr,
    pub master_key: [u8; 32],
    pub signing_seed: [u8; 32],
}

pub mod dn42;
pub mod error;
pub use dn42::{Dn42Config, Dn42PeerConfig};
pub use error::ConfigError;

impl Config {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.coordinator_url.is_empty() {
            return Err(ConfigError::EmptyCoordinatorUrl);
        }
        if !self.coordinator_url.starts_with("https://") {
            return Err(ConfigError::NonHttpsCoordinatorUrl);
        }
        if self.auth_key.is_empty() {
            return Err(ConfigError::EmptyAuthKey);
        }
        if self.coord_signing_pubkey == [0u8; 32] {
            return Err(ConfigError::MissingSigningPubkey);
        }
        if self.ca_cert_path.is_empty() {
            return Err(ConfigError::EmptyCaCertPath);
        }
        for route in &self.announce_routes {
            let prefix = landscape_rill_core::route::Prefix::parse(route);
            if prefix.is_err() {
                return Err(ConfigError::InvalidRoute(route.clone()));
            }
        }
        if let Some(coord) = &self.coord {
            if coord.master_key == [0u8; 32] {
                return Err(ConfigError::MissingMasterKey);
            }
            if coord.signing_seed == [0u8; 32] {
                return Err(ConfigError::MissingSigningSeed);
            }
        }
        if let Some(dn42) = &self.dn42 {
            dn42.validate().map_err(ConfigError::InvalidDn42)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct DnsEntry {
    ips: Vec<std::net::IpAddr>,
    next_try: std::time::Instant,
    attempt: u32,
    base_delay: Duration,
    max_delay: Duration,
}

#[derive(Debug, Default)]
pub struct DnsCache {
    entries: HashMap<String, DnsEntry>,
}

impl DnsCache {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    pub fn resolve(&mut self, host: &str) -> Option<Vec<std::net::IpAddr>> {
        match self.entries.get_mut(host) {
            Some(e) => {
                if std::time::Instant::now() < e.next_try && !e.ips.is_empty() {
                    return Some(e.ips.clone());
                }
                None
            }
            None => None,
        }
    }

    pub fn record_success(&mut self, host: &str, ips: Vec<std::net::IpAddr>) {
        let entry = self.entries.entry(host.to_string()).or_insert(DnsEntry {
            ips: Vec::new(),
            next_try: std::time::Instant::now(),
            attempt: 0,
            base_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(300),
        });
        entry.ips = ips;
        entry.attempt = 0;
        entry.next_try = std::time::Instant::now() + entry.base_delay;
    }

    pub fn record_failure(&mut self, host: &str) -> Duration {
        let entry = self.entries.entry(host.to_string()).or_insert(DnsEntry {
            ips: Vec::new(),
            next_try: std::time::Instant::now(),
            attempt: 0,
            base_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(300),
        });
        entry.attempt += 1;
        entry.ips.clear();
        let backoff = entry
            .base_delay
            .checked_mul(1u32 << entry.attempt.min(10))
            .unwrap_or(entry.max_delay)
            .min(entry.max_delay);
        entry.next_try = std::time::Instant::now() + backoff;
        backoff
    }

    pub fn next_retry(&self, host: &str) -> Option<Duration> {
        self.entries.get(host).map(|e| {
            e.next_try
                .saturating_duration_since(std::time::Instant::now())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use landscape_rill_core::route::Prefix;

    fn valid_config() -> Config {
        Config {
            coordinator_url: "https://coord.example.com:8443".into(),
            auth_key: "tskey-auth-abc".into(),
            static_key_seed: [1; 32],
            capabilities: 0x01,
            announce_routes: vec![],
            coord_signing_pubkey: [7; 32],
            ca_cert_path: "/etc/landscape/ca.pem".into(),
            udp_echo_addr: None,
            data_transport: DataTransport::Udp,
            coord: None,
            dn42: None,
        }
    }

    #[test]
    fn valid_config_passes() {
        assert_eq!(valid_config().validate(), Ok(()));
    }

    #[test]
    fn empty_or_bad_url_rejected() {
        let mut c = valid_config();
        c.coordinator_url = "".into();
        assert_eq!(c.validate(), Err(ConfigError::EmptyCoordinatorUrl));
        c.coordinator_url = "http://coord.example.com".into();
        assert_eq!(c.validate(), Err(ConfigError::NonHttpsCoordinatorUrl));
        c.coordinator_url = "ftp://x".into();
        assert_eq!(c.validate(), Err(ConfigError::NonHttpsCoordinatorUrl));
    }

    #[test]
    fn empty_auth_key_rejected() {
        let mut c = valid_config();
        c.auth_key = "".into();
        assert_eq!(c.validate(), Err(ConfigError::EmptyAuthKey));
    }

    #[test]
    fn missing_signing_pubkey_or_ca_rejected() {
        let mut c = valid_config();
        c.coord_signing_pubkey = [0; 32];
        assert_eq!(c.validate(), Err(ConfigError::MissingSigningPubkey));
        c.coord_signing_pubkey = [7; 32];
        c.ca_cert_path = "".into();
        assert_eq!(c.validate(), Err(ConfigError::EmptyCaCertPath));
    }

    #[test]
    fn bad_announce_route_rejected() {
        let mut c = valid_config();
        c.announce_routes = vec!["not-a-cidr".into()];
        assert_eq!(
            c.validate(),
            Err(ConfigError::InvalidRoute("not-a-cidr".into()))
        );
        c.announce_routes = vec!["10.0.0.0/24".into()];
        assert_eq!(c.validate(), Ok(()));
        assert_eq!(Prefix::parse(&c.announce_routes[0]).unwrap().len(), 24);
    }

    #[test]
    fn coord_all_zero_keys_rejected() {
        let mut c = valid_config();
        c.coord = Some(CoordConfig {
            listen_addr: "0.0.0.0:8443".parse().unwrap(),
            master_key: [0; 32],
            signing_seed: [1; 32],
        });
        assert_eq!(c.validate(), Err(ConfigError::MissingMasterKey));
        c.coord.as_mut().unwrap().master_key = [2; 32];
        c.coord.as_mut().unwrap().signing_seed = [0; 32];
        assert_eq!(c.validate(), Err(ConfigError::MissingSigningSeed));
        c.coord.as_mut().unwrap().signing_seed = [3; 32];
        assert_eq!(c.validate(), Ok(()));
    }

    #[test]
    fn dns_cache_hit_until_retry() {
        let mut cache = DnsCache::new();
        assert_eq!(cache.resolve("coord.example.com"), None);
        let ip: std::net::IpAddr = "203.0.113.1".parse().unwrap();
        cache.record_success("coord.example.com", vec![ip]);
        assert_eq!(cache.resolve("coord.example.com"), Some(vec![ip]));
        let backoff = cache.record_failure("coord.example.com");
        assert_eq!(backoff, Duration::from_secs(2));
        assert_eq!(cache.resolve("coord.example.com"), None);
    }

    #[test]
    fn dns_backoff_capped() {
        let mut cache = DnsCache::new();
        let mut last = Duration::from_secs(1);
        for _ in 0..20 {
            last = cache.record_failure("coord.example.com");
        }
        assert_eq!(last, Duration::from_secs(300));
    }
}
