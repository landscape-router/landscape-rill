use crate::route::Prefix;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const NODE_ID_LEN: usize = 4;
pub const STATIC_PUBKEY_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthKeyPolicy {
    OneTime,
    Reusable,
}

/// auth key 生命周期配置（REQ-036）：策略 + 可读标签。
/// 过期时间内嵌在 key 自身（REQ-043，`lrk-<network>-<expiry>-<secret>`），由
/// Coordinator 注册时解析校验（admission-time），注册表按不透明字符串处理。
/// 网络维度由 key 自身携带（CONTROL_PLANE §1.5 归域）：一个 Registry 实例 = 一个网络。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthKeySpec {
    pub policy: AuthKeyPolicy,
    pub tag: Option<String>,
}

impl AuthKeySpec {
    pub fn simple(policy: AuthKeyPolicy) -> Self {
        Self { policy, tag: None }
    }
}

/// 注册条目（持久化状态，REQ-037；CONTROL_PLANE §4.1）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeEntry {
    pub node_id: u32,
    pub network_id: u32,
    pub static_pubkey: [u8; STATIC_PUBKEY_LEN],
    pub capabilities: u32,
    pub routes: Vec<String>,
    pub identity_binding: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, landscape_rill_macro::ErrorId)]
#[error_id(crate_path = "crate")]
pub enum RegisterError {
    #[error("invalid auth key")]
    #[error_id("control.register.invalid_auth_key")]
    InvalidAuthKey,
    #[error("static pubkey mismatch")]
    #[error_id("control.register.pubkey_mismatch")]
    PubkeyMismatch,
    /// 公告前缀不在白名单 / 违反前缀长度边界（CONTROL_PLANE §3.8，REQ-038）
    #[error("announced route not allowed")]
    #[error_id("control.register.route_not_allowed")]
    RouteNotAllowed,
    /// 公告前缀格式非法
    #[error("malformed route announcement")]
    #[error_id("control.register.bad_route")]
    BadRoute,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegisterOutcome {
    NewNode(u32),
    Existing(u32),
}

/// 单个网络的注册表（CONTROL_PLANE §1.5 分域：auth key 空间 / 条目 / 白名单按网络独立）。
/// node_id 由调用方全局分配（coordinator 持全局计数器），跨网络不冲突
/// （Directory/Liveness 按 node_id 键控，全局唯一是前置条件）。
pub struct Registry {
    entries: HashMap<u32, NodeEntry>,
    pubkeys: HashMap<[u8; STATIC_PUBKEY_LEN], u32>,
    auth_keys: HashMap<String, AuthKeySpec>,
    /// 一次性 auth key 消费记录（持久化 tombstone：重启/重载不复活，REQ-037）
    consumed_one_time: Vec<String>,
    announce_whitelist: Vec<Prefix>,
    network_id: u32,
}

/// 前缀长度边界（CONTROL_PLANE §3.8）：IPv4 < /8、IPv6 < /32 拒绝
fn route_len_ok(p: &Prefix) -> bool {
    if p.v4 {
        p.len >= 8
    } else {
        p.len >= 32
    }
}

impl Registry {
    pub fn new(network_id: u32) -> Self {
        Self {
            entries: HashMap::new(),
            pubkeys: HashMap::new(),
            auth_keys: HashMap::new(),
            consumed_one_time: Vec::new(),
            announce_whitelist: Vec::new(),
            network_id,
        }
    }

    pub fn network_id(&self) -> u32 {
        self.network_id
    }

    pub fn add_auth_key(&mut self, key: &str, policy: AuthKeyPolicy) {
        self.add_auth_key_spec(key, AuthKeySpec::simple(policy));
    }

    pub fn add_auth_key_spec(&mut self, key: &str, spec: AuthKeySpec) {
        // 已消费的一次性 key 保持吊销（重启/SIGHUP 重载均不复活，REQ-037）
        if self.consumed_one_time.iter().any(|k| k == key) {
            return;
        }
        self.auth_keys.insert(key.to_string(), spec);
    }

    pub fn remove_auth_key(&mut self, key: &str) {
        self.auth_keys.remove(key);
    }

    pub fn has_auth_key(&self, key: &str) -> bool {
        self.auth_keys.contains_key(key)
    }

    pub fn auth_key_list(&self) -> Vec<String> {
        self.auth_keys.keys().cloned().collect()
    }

    /// 白名单为空 = 拒绝一切公告（fail-closed，CONTROL_PLANE §3.12）
    pub fn set_announce_whitelist(&mut self, whitelist: Vec<Prefix>) {
        self.announce_whitelist = whitelist;
    }

    pub fn announce_whitelist(&self) -> &[Prefix] {
        &self.announce_whitelist
    }

    /// 校验公告前缀（REQ-038）：白名单覆盖 + 长度边界
    pub fn check_announce_routes(&self, routes: &[String]) -> Result<(), RegisterError> {
        for route in routes {
            let prefix = Prefix::parse(route).map_err(|_| RegisterError::BadRoute)?;
            if !route_len_ok(&prefix) {
                return Err(RegisterError::RouteNotAllowed);
            }
            if !self
                .announce_whitelist
                .iter()
                .any(|allowed| prefix.is_covered_by(allowed))
            {
                return Err(RegisterError::RouteNotAllowed);
            }
        }
        Ok(())
    }

    /// 注册（admission）：auth key 查表 → pubkey 幂等/冲突 → 白名单校验 → 插入。
    /// `node_id` 由调用方分配（全局唯一）；归域（auth key 网络 = 本 Registry 网络）由
    /// 调用方在解析 key 后选择 Registry 实例完成（CONTROL_PLANE §1.5）。
    pub fn register(
        &mut self,
        auth_key: &str,
        static_pubkey: &[u8; STATIC_PUBKEY_LEN],
        capabilities: u32,
        routes: Vec<String>,
        node_id: u32,
        signer: &dyn IdentitySigner,
    ) -> Result<RegisterOutcome, RegisterError> {
        let spec = self
            .auth_keys
            .get(auth_key)
            .ok_or(RegisterError::InvalidAuthKey)?;
        if let Some(existing) = self.pubkeys.get(static_pubkey) {
            let node_id = *existing;
            let entry = self.entries.get(&node_id).unwrap();
            if entry.capabilities == capabilities && entry.routes == routes {
                return Ok(RegisterOutcome::Existing(node_id));
            }
            return Err(RegisterError::PubkeyMismatch);
        }
        self.check_announce_routes(&routes)?;
        let binding = signer.sign(&binding_message(node_id, static_pubkey));
        let entry = NodeEntry {
            node_id,
            network_id: self.network_id,
            static_pubkey: *static_pubkey,
            capabilities,
            routes,
            identity_binding: binding,
        };
        self.entries.insert(node_id, entry);
        self.pubkeys.insert(*static_pubkey, node_id);
        if spec.policy == AuthKeyPolicy::OneTime {
            self.auth_keys.remove(auth_key);
            self.consumed_one_time.push(auth_key.to_string());
        }
        Ok(RegisterOutcome::NewNode(node_id))
    }

    pub fn entry(&self, node_id: u32) -> Option<&NodeEntry> {
        self.entries.get(&node_id)
    }

    pub fn revoke(&mut self, node_id: u32) {
        if let Some(entry) = self.entries.remove(&node_id) {
            self.pubkeys.remove(&entry.static_pubkey);
        }
    }

    pub fn entries(&self) -> impl Iterator<Item = &NodeEntry> {
        self.entries.values()
    }

    pub fn node_id_by_pubkey(&self, static_pubkey: &[u8; 32]) -> Option<u32> {
        self.pubkeys.get(static_pubkey).copied()
    }

    /// 已消费的一次性 auth key（持久化 tombstone）
    pub fn consumed_one_time_keys(&self) -> &[String] {
        &self.consumed_one_time
    }

    /// 恢复持久化状态（REQ-037）：一致性校验由调用方 fail-closed 完成
    pub fn restore(&mut self, entries: Vec<NodeEntry>, consumed: Vec<String>) {
        self.entries.clear();
        self.pubkeys.clear();
        for e in entries {
            self.pubkeys.insert(e.static_pubkey, e.node_id);
            self.entries.insert(e.node_id, e);
        }
        self.consumed_one_time = consumed;
    }
}

pub fn binding_message(node_id: u32, static_pubkey: &[u8; STATIC_PUBKEY_LEN]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(NODE_ID_LEN + STATIC_PUBKEY_LEN);
    msg.extend_from_slice(&node_id.to_be_bytes());
    msg.extend_from_slice(static_pubkey);
    msg
}

pub trait IdentitySigner {
    fn sign(&self, msg: &[u8]) -> Vec<u8>;
    fn verify(&self, msg: &[u8], binding: &[u8]) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct XorSigner {
        key: u8,
    }

    impl IdentitySigner for XorSigner {
        fn sign(&self, msg: &[u8]) -> Vec<u8> {
            msg.iter().map(|b| b ^ self.key).collect()
        }
        fn verify(&self, msg: &[u8], binding: &[u8]) -> bool {
            binding == self.sign(msg).as_slice()
        }
    }

    fn key(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    #[test]
    fn register_new_and_idempotent() {
        let mut reg = Registry::new(0x0000_0001);
        let signer = XorSigner { key: 0x5a };
        reg.add_auth_key("ak-1", AuthKeyPolicy::OneTime);
        reg.set_announce_whitelist(vec![Prefix::parse("10.0.0.0/8").unwrap()]);
        let out1 = reg
            .register(
                "ak-1",
                &key(1),
                0x0d,
                vec!["10.0.0.0/24".into()],
                1,
                &signer,
            )
            .unwrap();
        assert_eq!(out1, RegisterOutcome::NewNode(1));
        let out2 = reg
            .register(
                "ak-1",
                &key(1),
                0x0d,
                vec!["10.0.0.0/24".into()],
                1,
                &signer,
            )
            .unwrap_err();
        assert_eq!(out2, RegisterError::InvalidAuthKey);
    }

    #[test]
    fn reusable_auth_key_registers_multiple_nodes() {
        let mut reg = Registry::new(1);
        let signer = XorSigner { key: 0x5a };
        reg.add_auth_key("ak-r", AuthKeyPolicy::Reusable);
        let a = reg
            .register("ak-r", &key(1), 0, vec![], 1, &signer)
            .unwrap();
        let b = reg
            .register("ak-r", &key(2), 0, vec![], 2, &signer)
            .unwrap();
        assert_eq!(a, RegisterOutcome::NewNode(1));
        assert_eq!(b, RegisterOutcome::NewNode(2));
        let idem = reg
            .register("ak-r", &key(1), 0, vec![], 1, &signer)
            .unwrap();
        assert_eq!(idem, RegisterOutcome::Existing(1));
    }

    #[test]
    fn same_pubkey_different_capabilities_rejected() {
        let mut reg = Registry::new(1);
        let signer = XorSigner { key: 0x5a };
        reg.add_auth_key("ak-r", AuthKeyPolicy::Reusable);
        reg.register("ak-r", &key(1), 0x01, vec![], 1, &signer)
            .unwrap();
        let err = reg
            .register("ak-r", &key(1), 0x02, vec![], 1, &signer)
            .unwrap_err();
        assert_eq!(err, RegisterError::PubkeyMismatch);
    }

    #[test]
    fn invalid_auth_key_rejected() {
        let mut reg = Registry::new(1);
        let signer = XorSigner { key: 0x5a };
        let err = reg
            .register("nope", &key(1), 0, vec![], 1, &signer)
            .unwrap_err();
        assert_eq!(err, RegisterError::InvalidAuthKey);
    }

    #[test]
    fn revoke_removes_entry() {
        let mut reg = Registry::new(1);
        let signer = XorSigner { key: 0x5a };
        reg.add_auth_key("ak-1", AuthKeyPolicy::OneTime);
        let node_id = match reg
            .register("ak-1", &key(1), 0, vec![], 1, &signer)
            .unwrap()
        {
            RegisterOutcome::NewNode(id) => id,
            _ => panic!("expected new node"),
        };
        assert!(reg.entry(node_id).is_some());
        reg.revoke(node_id);
        assert!(reg.entry(node_id).is_none());
        reg.add_auth_key("ak-2", AuthKeyPolicy::OneTime);
        let out = reg
            .register("ak-2", &key(1), 0, vec![], 2, &signer)
            .unwrap();
        match out {
            RegisterOutcome::NewNode(id) => assert_ne!(id, node_id),
            _ => panic!("expected new node"),
        }
    }

    #[test]
    fn binding_verifies() {
        let mut reg = Registry::new(1);
        let signer = XorSigner { key: 0x5a };
        reg.add_auth_key("ak-1", AuthKeyPolicy::OneTime);
        let node_id = match reg
            .register("ak-1", &key(1), 0, vec![], 1, &signer)
            .unwrap()
        {
            RegisterOutcome::NewNode(id) => id,
            _ => panic!("expected new node"),
        };
        let entry = reg.entry(node_id).unwrap();
        assert!(signer.verify(
            &binding_message(entry.node_id, &entry.static_pubkey),
            &entry.identity_binding
        ));
        assert!(!signer.verify(&binding_message(2, &key(1)), &entry.identity_binding));
    }

    #[test]
    fn whitelist_rejects_outside_routes() {
        let mut reg = Registry::new(1);
        let signer = XorSigner { key: 0x5a };
        reg.add_auth_key("ak-r", AuthKeyPolicy::Reusable);
        reg.set_announce_whitelist(vec![Prefix::parse("10.0.0.0/8").unwrap()]);
        let err = reg
            .register(
                "ak-r",
                &key(1),
                0,
                vec!["192.168.1.0/24".into()],
                1,
                &signer,
            )
            .unwrap_err();
        assert_eq!(err, RegisterError::RouteNotAllowed);
    }

    #[test]
    fn whitelist_accepts_subnet_of_allowance() {
        let mut reg = Registry::new(1);
        let signer = XorSigner { key: 0x5a };
        reg.add_auth_key("ak-r", AuthKeyPolicy::Reusable);
        reg.set_announce_whitelist(vec![
            Prefix::parse("10.0.0.0/8").unwrap(),
            Prefix::parse("fd00::/8").unwrap(),
        ]);
        let out = reg
            .register(
                "ak-r",
                &key(1),
                0,
                vec!["10.42.0.0/24".into(), "fd00:2::/64".into()],
                1,
                &signer,
            )
            .unwrap();
        assert_eq!(out, RegisterOutcome::NewNode(1));
    }

    #[test]
    fn whitelist_fail_closed_when_empty() {
        let mut reg = Registry::new(1);
        let signer = XorSigner { key: 0x5a };
        reg.add_auth_key("ak-r", AuthKeyPolicy::Reusable);
        let err = reg
            .register("ak-r", &key(1), 0, vec!["10.0.0.0/24".into()], 1, &signer)
            .unwrap_err();
        assert_eq!(err, RegisterError::RouteNotAllowed);
    }

    #[test]
    fn whitelist_rejects_short_prefix() {
        let mut reg = Registry::new(1);
        let signer = XorSigner { key: 0x5a };
        reg.add_auth_key("ak-r", AuthKeyPolicy::Reusable);
        reg.set_announce_whitelist(vec![Prefix::parse("0.0.0.0/0").unwrap()]);
        let err = reg
            .register("ak-r", &key(1), 0, vec!["0.0.0.0/0".into()], 1, &signer)
            .unwrap_err();
        assert_eq!(err, RegisterError::RouteNotAllowed);
        let err = reg
            .register("ak-r", &key(1), 0, vec!["fd00::/16".into()], 1, &signer)
            .unwrap_err();
        assert_eq!(err, RegisterError::RouteNotAllowed);
    }

    #[test]
    fn bad_route_rejected() {
        let mut reg = Registry::new(1);
        let signer = XorSigner { key: 0x5a };
        reg.add_auth_key("ak-r", AuthKeyPolicy::Reusable);
        reg.set_announce_whitelist(vec![Prefix::parse("10.0.0.0/8").unwrap()]);
        let err = reg
            .register("ak-r", &key(1), 0, vec!["not-a-cidr".into()], 1, &signer)
            .unwrap_err();
        assert_eq!(err, RegisterError::BadRoute);
    }

    #[test]
    fn remove_auth_key_revokes() {
        let mut reg = Registry::new(1);
        reg.add_auth_key("ak-r", AuthKeyPolicy::Reusable);
        assert!(reg.has_auth_key("ak-r"));
        reg.remove_auth_key("ak-r");
        assert!(!reg.has_auth_key("ak-r"));
    }

    #[test]
    fn prefix_covered_by() {
        let a = Prefix::parse("10.42.0.0/24").unwrap();
        assert!(a.is_covered_by(&Prefix::parse("10.0.0.0/8").unwrap()));
        assert!(!a.is_covered_by(&Prefix::parse("10.42.0.0/25").unwrap()));
        assert!(a.is_covered_by(&a));
        let v6 = Prefix::parse("fd00:2::/64").unwrap();
        assert!(v6.is_covered_by(&Prefix::parse("fd00::/8").unwrap()));
        assert!(!v6.is_covered_by(&Prefix::parse("fe80::/8").unwrap()));
    }
}
