use crate::signer::Ed25519Signer;
use landscape_rill_core::control::registry::{AuthKeyPolicy, NodeEntry, RegisterError, Registry};
use landscape_rill_core::crypto::{derive_key_dst, KEY_DST_LEN};
use std::collections::HashMap;

pub const BROADCAST_KEY_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterData {
    pub node_id: u32,
    pub network_id: u32,
    pub identity_binding: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyDistData {
    pub to_node_id: u32,
    pub key: [u8; KEY_DST_LEN],
    pub key_version: u32,
    pub broadcast_key: [u8; BROADCAST_KEY_LEN],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeInfo {
    pub node_id: u32,
    pub network_id: u32,
    pub static_pubkey: [u8; 32],
    pub capabilities: u32,
    pub routes: Vec<String>,
    pub endpoints: Vec<String>,
    pub offline: bool,
}

pub struct Coordinator {
    registry: Registry,
    signer: Ed25519Signer,
    master_key: [u8; 32],
    netmap_version: u64,
    key_version: u32,
    last_seen: HashMap<u32, u64>,
    endpoints: HashMap<u32, Vec<String>>,
    relay_list: Vec<String>,
    offline: Vec<u32>,
}

impl Coordinator {
    pub fn new(master_key: [u8; 32], signing_seed: [u8; 32]) -> Self {
        Self {
            registry: Registry::new(0x0000_0001),
            signer: Ed25519Signer::new(signing_seed),
            master_key,
            netmap_version: 0,
            key_version: 1,
            last_seen: HashMap::new(),
            endpoints: HashMap::new(),
            relay_list: Vec::new(),
            offline: Vec::new(),
        }
    }

    pub fn add_auth_key(&mut self, key: &str, policy: AuthKeyPolicy) {
        self.registry.add_auth_key(key, policy);
    }

    pub fn register(
        &mut self,
        auth_key: &str,
        static_pubkey: &[u8; 32],
        capabilities: u32,
        routes: Vec<String>,
    ) -> Result<RegisterData, RegisterError> {
        let outcome =
            self.registry.register(auth_key, static_pubkey, capabilities, routes, &self.signer)?;
        let node_id = match outcome {
            landscape_rill_core::control::registry::RegisterOutcome::NewNode(id) => {
                self.netmap_version += 1;
                id
            }
            landscape_rill_core::control::registry::RegisterOutcome::Existing(id) => id,
        };
        let entry = self.registry.entry(node_id).unwrap();
        Ok(RegisterData {
            node_id: entry.node_id,
            network_id: entry.network_id,
            identity_binding: entry.identity_binding.clone(),
        })
    }

    pub fn key_dist(&self, node_id: u32) -> Option<KeyDistData> {
        self.registry.entry(node_id).map(|_| KeyDistData {
            to_node_id: node_id,
            key: derive_key_dst(&self.master_key, node_id),
            key_version: self.key_version,
            broadcast_key: derive_key_dst(&self.master_key, 0xFFFF_FFFF),
        })
    }

    pub fn set_endpoints(&mut self, node_id: u32, endpoints: Vec<String>) {
        self.endpoints.insert(node_id, endpoints);
        self.netmap_version += 1;
    }

    pub fn set_relay_list(&mut self, relay_list: Vec<String>) {
        self.relay_list = relay_list;
        self.netmap_version += 1;
    }

    pub fn netmap_snapshot(&self) -> Vec<NodeInfo> {
        let offline: Vec<u32> = self.offline.clone();
        self.registry
            .entries()
            .map(|e: &NodeEntry| NodeInfo {
                node_id: e.node_id,
                network_id: e.network_id,
                static_pubkey: e.static_pubkey,
                capabilities: e.capabilities,
                routes: e.routes.clone(),
                endpoints: self.endpoints.get(&e.node_id).cloned().unwrap_or_default(),
                offline: offline.contains(&e.node_id),
            })
            .collect()
    }

    pub fn netmap_version(&self) -> u64 {
        self.netmap_version
    }

    pub fn relay_list(&self) -> &[String] {
        &self.relay_list
    }

    pub fn heartbeat(&mut self, node_id: u32, now: u64) {
        self.last_seen.insert(node_id, now);
        self.offline.retain(|id| *id != node_id);
    }

    pub fn mark_offline(&mut self, node_id: u32) {
        if self.registry.entry(node_id).is_some() && !self.offline.contains(&node_id) {
            self.offline.push(node_id);
            self.netmap_version += 1;
        }
    }

    pub fn offline_nodes(&self) -> &[u32] {
        &self.offline
    }

    pub fn revoke(&mut self, node_id: u32) {
        if self.registry.entry(node_id).is_some() {
            self.registry.revoke(node_id);
            self.last_seen.remove(&node_id);
            self.endpoints.remove(&node_id);
            self.offline.retain(|id| *id != node_id);
            self.key_version += 1;
            self.netmap_version += 1;
        }
    }

    pub fn rotate_master_key(&mut self, new_master_key: [u8; 32]) {
        self.master_key = new_master_key;
        self.key_version += 1;
    }

    pub fn key_version(&self) -> u32 {
        self.key_version
    }

    /// 按静态公钥定位已注册节点（重连挑战路径：auth key 失效 + 公钥已知 → 发起挑战）
    pub fn node_id_by_pubkey(&self, static_pubkey: &[u8; 32]) -> Option<u32> {
        self.registry.node_id_by_pubkey(static_pubkey)
    }

    /// 节点静态公钥（挑战验证用）
    pub fn static_pubkey_of(&self, node_id: u32) -> Option<[u8; 32]> {
        self.registry.entry(node_id).map(|e| e.static_pubkey)
    }

    pub fn verifier(&self) -> ed25519_dalek::VerifyingKey {
        self.signer.verifier()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pubkey(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    fn setup() -> Coordinator {
        let mut c = Coordinator::new([0x77; 32], [0x5a; 32]);
        c.add_auth_key("ak-1", AuthKeyPolicy::Reusable);
        c
    }

    fn register_node(c: &mut Coordinator, seed: u8) -> u32 {
        c.register("ak-1", &pubkey(seed), 0x01, vec![]).unwrap().node_id
    }

    #[test]
    fn register_and_netmap() {
        let mut c = setup();
        let v0 = c.netmap_version();
        let id = register_node(&mut c, 1);
        assert_eq!(id, 1);
        assert_eq!(c.netmap_version(), v0 + 1);
        let snap = c.netmap_snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].node_id, 1);
        assert_eq!(snap[0].static_pubkey, pubkey(1));
    }

    #[test]
    fn register_idempotent_no_version_bump() {
        let mut c = setup();
        let v0 = c.netmap_version();
        register_node(&mut c, 1);
        let v1 = c.netmap_version();
        assert_eq!(v1, v0 + 1);
        let out = c.register("ak-1", &pubkey(1), 0x01, vec![]).unwrap();
        assert_eq!(out.node_id, 1);
        assert_eq!(c.netmap_version(), v1);
    }

    #[test]
    fn key_dist_deterministic_per_node() {
        let mut c = setup();
        let id = register_node(&mut c, 1);
        let k1 = c.key_dist(id).unwrap();
        let k2 = c.key_dist(id).unwrap();
        assert_eq!(k1, k2);
        assert_ne!(k1.key, derive_key_dst(&[0x77; 32], 2));
        assert_eq!(k1.key_version, 1);
        assert_eq!(k1.to_node_id, id);
        assert_eq!(k1.broadcast_key, derive_key_dst(&[0x77; 32], 0xFFFF_FFFF));
    }

    #[test]
    fn key_dist_unknown_node_none() {
        let c = setup();
        assert!(c.key_dist(99).is_none());
    }

    #[test]
    fn revoke_removes_and_bumps_versions() {
        let mut c = setup();
        let id = register_node(&mut c, 1);
        let nv = c.netmap_version();
        let kv = c.key_version();
        c.revoke(id);
        assert_eq!(c.netmap_snapshot().len(), 0);
        assert_eq!(c.netmap_version(), nv + 1);
        assert_eq!(c.key_version(), kv + 1);
        assert!(c.key_dist(id).is_none());
    }

    #[test]
    fn rotate_master_key_changes_keys() {
        let mut c = setup();
        let id = register_node(&mut c, 1);
        let before = c.key_dist(id).unwrap();
        c.rotate_master_key([0x99; 32]);
        let after = c.key_dist(id).unwrap();
        assert_ne!(before.key, after.key);
        assert_eq!(after.key_version, before.key_version + 1);
    }

    #[test]
    fn heartbeat_and_offline() {
        let mut c = setup();
        let id = register_node(&mut c, 1);
        c.heartbeat(id, 100);
        assert!(c.offline_nodes().is_empty());
        c.mark_offline(id);
        assert_eq!(c.offline_nodes(), &[1]);
        assert!(c.netmap_snapshot()[0].offline);
        c.heartbeat(id, 200);
        assert!(c.offline_nodes().is_empty());
        assert!(!c.netmap_snapshot()[0].offline);
    }

    #[test]
    fn endpoints_enter_netmap() {
        let mut c = setup();
        let id = register_node(&mut c, 1);
        c.set_endpoints(id, vec!["203.0.113.1:41641".into()]);
        let snap = c.netmap_snapshot();
        assert_eq!(snap[0].endpoints, vec!["203.0.113.1:41641"]);
    }
}
