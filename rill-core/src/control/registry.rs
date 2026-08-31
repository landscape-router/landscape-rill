use std::collections::HashMap;

pub const NODE_ID_LEN: usize = 4;
pub const STATIC_PUBKEY_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthKeyPolicy {
    OneTime,
    Reusable,
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegisterOutcome {
    NewNode(u32),
    Existing(u32),
}

pub struct Registry {
    entries: HashMap<u32, NodeEntry>,
    pubkeys: HashMap<[u8; STATIC_PUBKEY_LEN], u32>,
    auth_keys: HashMap<String, AuthKeyPolicy>,
    network_id: u32,
    next_node_id: u32,
}

impl Registry {
    pub fn new(network_id: u32) -> Self {
        Self {
            entries: HashMap::new(),
            pubkeys: HashMap::new(),
            auth_keys: HashMap::new(),
            network_id,
            next_node_id: 1,
        }
    }

    pub fn add_auth_key(&mut self, key: &str, policy: AuthKeyPolicy) {
        self.auth_keys.insert(key.to_string(), policy);
    }

    pub fn remove_auth_key(&mut self, key: &str) {
        self.auth_keys.remove(key);
    }

    pub fn register(
        &mut self,
        auth_key: &str,
        static_pubkey: &[u8; STATIC_PUBKEY_LEN],
        capabilities: u32,
        routes: Vec<String>,
        signer: &dyn IdentitySigner,
    ) -> Result<RegisterOutcome, RegisterError> {
        let policy = self
            .auth_keys
            .get(auth_key)
            .ok_or(RegisterError::InvalidAuthKey)?;
        if let Some(node_id) = self.pubkeys.get(static_pubkey) {
            let node_id = *node_id;
            let entry = self.entries.get(&node_id).unwrap();
            if entry.capabilities == capabilities && entry.routes == routes {
                return Ok(RegisterOutcome::Existing(node_id));
            }
            return Err(RegisterError::PubkeyMismatch);
        }
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
        if *policy == AuthKeyPolicy::OneTime {
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
}
