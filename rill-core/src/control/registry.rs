use crate::route::Prefix;
use std::collections::HashMap;

pub const NODE_ID_LEN: usize = 4;
pub const STATIC_PUBKEY_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthKeyPolicy {
    OneTime,
    Reusable,
}

/// auth key 完整生命周期配置（REQ-036）：策略 + 可读标签 + 过期时间
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthKeySpec {
    pub policy: AuthKeyPolicy,
    pub tag: Option<String>,
    /// unix 秒；过期后注册返回 InvalidAuthKey
    pub expires_at: Option<u64>,
}

impl AuthKeySpec {
    pub fn simple(policy: AuthKeyPolicy) -> Self {
        Self {
            policy,
            tag: None,
            expires_at: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NodeEntry {
    pub node_id: u32,
    pub network_id: u32,
    pub static_pubkey: [u8; STATIC_PUBKEY_LEN],
    pub capabilities: u32,
    pub routes: Vec<String>,
    pub identity_binding: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegisterError {
    InvalidAuthKey,
    PubkeyMismatch,
    /// 公告前缀不在白名单 / 违反前缀长度边界（CONTROL_PLANE §3.8，REQ-038）
    RouteNotAllowed,
    /// 公告前缀格式非法
    BadRoute,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegisterOutcome {
    NewNode(u32),
    Existing(u32),
}

pub struct Registry {
    entries: HashMap<u32, NodeEntry>,
    pubkeys: HashMap<[u8; STATIC_PUBKEY_LEN], u32>,
    auth_keys: HashMap<String, AuthKeySpec>,
    announce_whitelist: Vec<Prefix>,
    network_id: u32,
    next_node_id: u32,
}

/// 前缀长度边界（CONTROL_PLANE §3.8）：IPv4 < /8、IPv6 < /32 拒绝
fn route_len_ok(p: &Prefix) -> bool {
    if p.v4 {
        p.len >= 8
    } else {
        p.len >= 32
    }
}

fn now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Registry {
    pub fn new(network_id: u32) -> Self {
        Self {
            entries: HashMap::new(),
            pubkeys: HashMap::new(),
            auth_keys: HashMap::new(),
            announce_whitelist: Vec::new(),
            network_id,
            next_node_id: 1,
        }
    }

    pub fn add_auth_key(&mut self, key: &str, policy: AuthKeyPolicy) {
        self.add_auth_key_spec(key, AuthKeySpec::simple(policy));
    }

    pub fn add_auth_key_spec(&mut self, key: &str, spec: AuthKeySpec) {
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

    pub fn register(
        &mut self,
        auth_key: &str,
        static_pubkey: &[u8; STATIC_PUBKEY_LEN],
        capabilities: u32,
        routes: Vec<String>,
        signer: &dyn IdentitySigner,
    ) -> Result<RegisterOutcome, RegisterError> {
        let spec = self
            .auth_keys
            .get(auth_key)
            .ok_or(RegisterError::InvalidAuthKey)?;
        if let Some(exp) = spec.expires_at {
            if now_seconds() > exp {
                return Err(RegisterError::InvalidAuthKey);
            }
        }
        if let Some(node_id) = self.pubkeys.get(static_pubkey) {
            let node_id = *node_id;
            let entry = self.entries.get(&node_id).unwrap();
            if entry.capabilities == capabilities && entry.routes == routes {
                return Ok(RegisterOutcome::Existing(node_id));
            }
            return Err(RegisterError::PubkeyMismatch);
        }
        self.check_announce_routes(&routes)?;
        let node_id = self.next_node_id;
        self.next_node_id += 1;
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
            .register("ak-1", &key(1), 0x0d, vec!["10.0.0.0/24".into()], &signer)
            .unwrap();
        assert_eq!(out1, RegisterOutcome::NewNode(1));
        let out2 = reg
            .register("ak-1", &key(1), 0x0d, vec!["10.0.0.0/24".into()], &signer)
            .unwrap_err();
        assert_eq!(out2, RegisterError::InvalidAuthKey);
    }

    #[test]
    fn reusable_auth_key_registers_multiple_nodes() {
        let mut reg = Registry::new(1);
        let signer = XorSigner { key: 0x5a };
        reg.add_auth_key("ak-r", AuthKeyPolicy::Reusable);
        let a = reg.register("ak-r", &key(1), 0, vec![], &signer).unwrap();
        let b = reg.register("ak-r", &key(2), 0, vec![], &signer).unwrap();
        assert_eq!(a, RegisterOutcome::NewNode(1));
        assert_eq!(b, RegisterOutcome::NewNode(2));
        let idem = reg.register("ak-r", &key(1), 0, vec![], &signer).unwrap();
        assert_eq!(idem, RegisterOutcome::Existing(1));
    }

    #[test]
    fn same_pubkey_different_capabilities_rejected() {
        let mut reg = Registry::new(1);
        let signer = XorSigner { key: 0x5a };
        reg.add_auth_key("ak-r", AuthKeyPolicy::Reusable);
        reg.register("ak-r", &key(1), 0x01, vec![], &signer)
            .unwrap();
        let err = reg
            .register("ak-r", &key(1), 0x02, vec![], &signer)
            .unwrap_err();
        assert_eq!(err, RegisterError::PubkeyMismatch);
    }

    #[test]
    fn invalid_auth_key_rejected() {
        let mut reg = Registry::new(1);
        let signer = XorSigner { key: 0x5a };
        let err = reg
            .register("nope", &key(1), 0, vec![], &signer)
            .unwrap_err();
        assert_eq!(err, RegisterError::InvalidAuthKey);
    }

    #[test]
    fn revoke_removes_entry() {
        let mut reg = Registry::new(1);
        let signer = XorSigner { key: 0x5a };
        reg.add_auth_key("ak-1", AuthKeyPolicy::OneTime);
        let node_id = match reg.register("ak-1", &key(1), 0, vec![], &signer).unwrap() {
            RegisterOutcome::NewNode(id) => id,
            _ => panic!("expected new node"),
        };
        assert!(reg.entry(node_id).is_some());
        reg.revoke(node_id);
        assert!(reg.entry(node_id).is_none());
        reg.add_auth_key("ak-2", AuthKeyPolicy::OneTime);
        let out = reg.register("ak-2", &key(1), 0, vec![], &signer).unwrap();
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
        let node_id = match reg.register("ak-1", &key(1), 0, vec![], &signer).unwrap() {
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
            .register("ak-r", &key(1), 0, vec!["192.168.1.0/24".into()], &signer)
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
            .register("ak-r", &key(1), 0, vec!["10.0.0.0/24".into()], &signer)
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
            .register("ak-r", &key(1), 0, vec!["0.0.0.0/0".into()], &signer)
            .unwrap_err();
        assert_eq!(err, RegisterError::RouteNotAllowed);
        let err = reg
            .register("ak-r", &key(1), 0, vec!["fd00::/16".into()], &signer)
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
            .register("ak-r", &key(1), 0, vec!["not-a-cidr".into()], &signer)
            .unwrap_err();
        assert_eq!(err, RegisterError::BadRoute);
    }

    #[test]
    fn expired_auth_key_rejected() {
        let mut reg = Registry::new(1);
        let signer = XorSigner { key: 0x5a };
        reg.add_auth_key_spec(
            "ak-exp",
            AuthKeySpec {
                policy: AuthKeyPolicy::Reusable,
                tag: Some("ci".into()),
                expires_at: Some(1),
            },
        );
        let err = reg
            .register("ak-exp", &key(1), 0, vec![], &signer)
            .unwrap_err();
        assert_eq!(err, RegisterError::InvalidAuthKey);
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
