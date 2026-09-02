//! 状态端点视图与认证原语（REQ-051/CONTROL_PLANE §3.14；遥测视图 REQ-052/§3.15）。
//! I/O-free：快照构建与密码校验无网络/无锁；HTTP 层在 rilld（薄路由 + 认证中间件）。
//! 红线（§3.14）：密钥材料一律不出——master_key/signing_seed/TLS 私钥只显示指纹，
//! auth key 前缀脱敏，secret 段永不输出。

use crate::authkey::parse_auth_key;
use crate::coordinator::{Coordinator, NodeInfo};
use hmac::{Hmac, KeyInit, Mac};
use serde::Serialize;
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// 遥测视图（REQ-052）：rill-mesh 心跳处理将 proto 载荷转换为此处普通结构
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct PeerTrafficView {
    pub node_id: u32,
    pub tx_frames: u64,
    pub tx_bytes: u64,
    pub rx_frames: u64,
    pub rx_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DirectPairView {
    pub node_id: u32,
    pub endpoint: String,
    pub rtt_ms: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DropView {
    pub node_id: u32,
    pub count: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TelemetryView {
    pub peers: Vec<PeerTrafficView>,
    pub drop_global: u64,
    pub drops: Vec<DropView>,
    pub direct: Vec<DirectPairView>,
    /// coordinator 侧接收打点（不信任节点时钟）
    pub updated_at: u64,
}

// ---------------------------------------------------------------------------
// 管理密码哈希（PBKDF2-HMAC-SHA256，§3.14 认证）
// ---------------------------------------------------------------------------

/// 迭代下限（fail-closed：弱配置拒绝启动/拒绝加载）
pub const PBKDF2_MIN_ITERATIONS: u32 = 10_000;
/// 盐长度下限（§3.14：盐 ≥16B）
pub const PBKDF2_MIN_SALT: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusAuthError(pub String);

impl std::fmt::Display for StatusAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "status auth: {}", self.0)
    }
}

impl std::error::Error for StatusAuthError {}

/// `pbkdf2-sha256$<iter>$<salt_hex>$<hash_hex>`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordHash {
    pub iterations: u32,
    pub salt: Vec<u8>,
    pub hash: Vec<u8>,
}

impl PasswordHash {
    pub fn parse(s: &str) -> Result<Self, StatusAuthError> {
        let bad = || StatusAuthError("bad password hash format".into());
        let rest = s.strip_prefix("pbkdf2-sha256$").ok_or_else(bad)?;
        let mut it = rest.split('$');
        let iterations: u32 = it.next().ok_or_else(bad)?.parse().map_err(|_| bad())?;
        let salt_hex = it.next().ok_or_else(bad)?;
        let hash_hex = it.next().ok_or_else(bad)?;
        if it.next().is_some() {
            return Err(bad());
        }
        let decode = |h: &str| {
            (0..h.len() / 2)
                .map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16))
                .collect::<Result<Vec<u8>, _>>()
                .map_err(|_| StatusAuthError("bad hex".into()))
        };
        let salt = decode(salt_hex)?;
        let hash = decode(hash_hex)?;
        if iterations < PBKDF2_MIN_ITERATIONS {
            return Err(StatusAuthError(format!(
                "iterations below minimum {PBKDF2_MIN_ITERATIONS}"
            )));
        }
        if salt.len() < PBKDF2_MIN_SALT {
            return Err(StatusAuthError(format!(
                "salt below minimum {PBKDF2_MIN_SALT} bytes"
            )));
        }
        if hash.len() != 32 {
            return Err(StatusAuthError("hash must be 32 bytes".into()));
        }
        Ok(Self {
            iterations,
            salt,
            hash,
        })
    }

    /// 常数时间比较（§3.14）：比较时长不泄漏前缀匹配位置
    pub fn verify(&self, password: &str) -> bool {
        let derived = pbkdf2_sha256(
            password.as_bytes(),
            &self.salt,
            self.iterations,
            self.hash.len(),
        );
        constant_time_eq(&derived, &self.hash)
    }
}

/// PBKDF2-HMAC-SHA256（RFC 2898；dkLen ≤ 32*n 的朴素实现，n = ceil(dkLen/32)）
pub fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32, dk_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(dk_len);
    for block in 1..=(dk_len.div_ceil(32)) as u32 {
        let mut mac =
            <Hmac<Sha256> as KeyInit>::new_from_slice(password).expect("hmac accepts any key");
        mac.update(salt);
        mac.update(&block.to_be_bytes());
        let mut u = mac.finalize().into_bytes();
        let mut acc = u;
        for _ in 1..iterations {
            let mut mac =
                <Hmac<Sha256> as KeyInit>::new_from_slice(password).expect("hmac accepts any key");
            mac.update(&u);
            u = mac.finalize().into_bytes();
            for (a, x) in acc.iter_mut().zip(u.iter()) {
                *a ^= x;
            }
        }
        out.extend_from_slice(&acc);
    }
    out.truncate(dk_len);
    out
}

/// 常数时间字节数组比较
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let diff = a
        .iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y));
    diff == 0
}

// ---------------------------------------------------------------------------
// 快照视图（§3.14 内容组 1-6）
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct RelayStatus {
    pub endpoint: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct NetworkStatus {
    pub name: String,
    pub network_id: u32,
    pub nodes_online: usize,
    pub nodes_offline: usize,
    pub netmap_version: u64,
    pub relays: Vec<RelayStatus>,
    pub announce_whitelist: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NodeStatus {
    pub node_id: u32,
    pub network: String,
    pub pubkey_fingerprint: String,
    pub capabilities: u32,
    pub routes: Vec<String>,
    pub endpoints: Vec<String>,
    pub online: bool,
    pub last_seen_age_secs: Option<u64>,
    pub protocol_version: u32,
    pub build_version: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthKeyStatus {
    /// 前缀脱敏（secret 段永不输出）
    pub key_masked: String,
    pub network: String,
    pub policy: String,
    pub tag: Option<String>,
    pub consumed: bool,
    /// unix 秒；None = 永不过期
    pub expires_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CounterStatus {
    pub register_rejects: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CoordSelfStatus {
    pub control_addr: String,
    pub status_addr: Option<String>,
    /// "memory" 或 "redb:<path>"
    pub storage: String,
    pub uptime_secs: u64,
    /// SIGHUP 重载结果历史（追加截尾，进程内）
    pub reload_log: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NodeTelemetryStatus {
    pub node_id: u32,
    pub updated_at: u64,
    pub peers: Vec<PeerTrafficView>,
    pub drop_global: u64,
    pub drops: Vec<DropView>,
    pub direct: Vec<DirectPairView>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StatusSnapshot {
    pub generated_at: u64,
    pub networks: Vec<NetworkStatus>,
    pub nodes: Vec<NodeStatus>,
    pub auth_keys: Vec<AuthKeyStatus>,
    pub counters: CounterStatus,
    pub coord: CoordSelfStatus,
    pub telemetry: Vec<NodeTelemetryStatus>,
}

/// 进程级事实（rilld 持有；不在 Coordinator 内）
#[derive(Debug, Clone)]
pub struct CoordRuntimeMeta {
    pub control_addr: String,
    pub status_addr: Option<String>,
    /// None = 纯内存
    pub storage_path: Option<String>,
    pub started_at_unix: u64,
    pub now_unix: u64,
    pub reload_log: Vec<String>,
}

pub struct StatusView;

impl StatusView {
    /// 全网只读快照（I/O-free，单测覆盖多网络/离线/已消费分支）
    pub fn snapshot(coord: &Coordinator, meta: &CoordRuntimeMeta) -> StatusSnapshot {
        let networks: Vec<String> = coord.network_names();
        let offline: std::collections::HashSet<u32> =
            coord.offline_nodes().iter().copied().collect();

        let mut nodes = Vec::new();
        let mut net_status = Vec::new();
        for name in &networks {
            let network_id = crate::domain::network_id_for(name);
            let entries: Vec<NodeInfo> = coord.netmap_snapshot(network_id);
            let online = entries.iter().filter(|e| !e.offline).count();
            let total_offline = entries.iter().filter(|e| e.offline).count();
            net_status.push(NetworkStatus {
                name: name.clone(),
                network_id,
                nodes_online: online,
                nodes_offline: total_offline,
                netmap_version: coord.netmap_version(),
                relays: coord
                    .relay_list_for(network_id)
                    .iter()
                    .map(|e| RelayStatus {
                        endpoint: e.clone(),
                    })
                    .collect(),
                announce_whitelist: coord.announce_whitelist(name),
            });
            for e in entries {
                nodes.push(NodeStatus {
                    node_id: e.node_id,
                    network: name.clone(),
                    pubkey_fingerprint: fingerprint(&e.static_pubkey),
                    capabilities: e.capabilities,
                    routes: e.routes.clone(),
                    endpoints: e.endpoints.clone(),
                    online: !offline.contains(&e.node_id),
                    last_seen_age_secs: coord
                        .last_seen_of(e.node_id)
                        .map(|t| meta.now_unix.saturating_sub(t)),
                    protocol_version: e.protocol_version,
                    build_version: coord.build_version(e.node_id).map(str::to_string),
                });
            }
        }

        let mut auth_keys = Vec::new();
        for name in &networks {
            let mut consumed: std::collections::HashSet<String> =
                coord.consumed_one_time_keys_for(name).into_iter().collect();
            let specs = coord.auth_key_specs_for(name);
            let mut keys: Vec<AuthKeyStatus> = specs
                .into_iter()
                .map(|(key, spec)| {
                    let is_consumed = consumed.contains(&key);
                    consumed.remove(&key);
                    let expiry =
                        parse_auth_key(&key).ok().and_then(
                            |(_, e, _)| {
                                if e == 0 {
                                    None
                                } else {
                                    Some(e)
                                }
                            },
                        );
                    AuthKeyStatus {
                        key_masked: mask_key(&key),
                        network: name.clone(),
                        policy: format!("{:?}", spec.policy),
                        tag: spec.tag,
                        consumed: is_consumed,
                        expires_at: expiry,
                    }
                })
                .collect();
            // 消费 tombstone 不在配置 key 集合中的也展示（重启后 reload 场景）
            for key in consumed {
                auth_keys.push(AuthKeyStatus {
                    key_masked: mask_key(&key),
                    network: name.clone(),
                    policy: "OneTime".into(),
                    tag: None,
                    consumed: true,
                    expires_at: parse_auth_key(&key)
                        .ok()
                        .and_then(|(_, e, _)| (e != 0).then_some(e)),
                });
            }
            auth_keys.append(&mut keys);
        }
        auth_keys.sort_by(|a, b| a.key_masked.cmp(&b.key_masked));

        let telemetry = coord
            .telemetry_all()
            .into_iter()
            .map(|(node_id, t)| NodeTelemetryStatus {
                node_id,
                updated_at: t.updated_at,
                peers: t.peers.clone(),
                drop_global: t.drop_global,
                drops: t.drops.clone(),
                direct: t.direct.clone(),
            })
            .collect();

        StatusSnapshot {
            generated_at: meta.now_unix,
            networks: net_status,
            nodes,
            auth_keys,
            counters: CounterStatus {
                register_rejects: coord.register_rejects(),
            },
            coord: CoordSelfStatus {
                control_addr: meta.control_addr.clone(),
                status_addr: meta.status_addr.clone(),
                storage: match &meta.storage_path {
                    Some(p) => format!("redb:{p}"),
                    None => "memory".into(),
                },
                uptime_secs: meta.now_unix.saturating_sub(meta.started_at_unix),
                reload_log: meta.reload_log.clone(),
            },
            telemetry,
        }
    }
}

/// 公钥指纹（sha256 前 8 字节 hex；红线：只出指纹不出材料）
fn fingerprint(pubkey: &[u8; 32]) -> String {
    let d = Sha256::digest(pubkey);
    let hex: String = d[..8].iter().map(|b| format!("{b:02x}")).collect();
    format!("sha256:{hex}")
}

/// key 脱敏：`lrk-<network>-<expiry>-…` + 末 4 位（secret 段不输出）
fn mask_key(key: &str) -> String {
    if key.len() <= 8 {
        return "…".into();
    }
    format!("{}…{}", &key[..key.len() - 12], &key[key.len() - 4..])
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASS: &str = "correct horse battery staple";

    fn hash_of(s: &str) -> String {
        let salt: Vec<u8> = (0..16).collect();
        let d = pbkdf2_sha256(s.as_bytes(), &salt, 10_000, 32);
        let salt_hex: String = salt.iter().map(|b| format!("{b:02x}")).collect();
        let hash_hex: String = d.iter().map(|b| format!("{b:02x}")).collect();
        format!("pbkdf2-sha256$10000${salt_hex}${hash_hex}")
    }

    #[test]
    fn password_hash_roundtrip_and_reject() {
        let h = PasswordHash::parse(&hash_of(PASS)).unwrap();
        assert!(h.verify(PASS));
        assert!(!h.verify("wrong"));
        assert!(!h.verify(""));
    }

    #[test]
    fn password_hash_parse_fail_closed() {
        // 弱参数 / 坏格式一律拒绝（fail-closed）
        assert!(PasswordHash::parse("plaintext").is_err());
        assert!(PasswordHash::parse("pbkdf2-sha256$1$aabb$00").is_err());
        assert!(
            PasswordHash::parse(&format!("pbkdf2-sha256$1000${}$00", "ab".repeat(16))).is_err()
        );
        assert!(
            PasswordHash::parse(&hash_of(PASS).replace("pbkdf2-sha256", "pbkdf2-sha1")).is_err()
        );
        let h = PasswordHash::parse(&hash_of(PASS)).unwrap();
        assert!(h.iterations >= PBKDF2_MIN_ITERATIONS);
        assert!(h.salt.len() >= PBKDF2_MIN_SALT);
    }

    #[test]
    fn mask_never_shows_secret_tail() {
        let key = "lrk-net1-0-deadbeefcafeb0ba";
        let m = mask_key(key);
        assert!(!m.contains("deadbeef"));
        assert!(m.ends_with("b0ba"));
    }
}
