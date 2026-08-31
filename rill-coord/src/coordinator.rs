use crate::path_service::{PathCandidate, PathEvent, PathService};
use crate::signer::Ed25519Signer;
use landscape_rill_core::control::registry::{
    AuthKeyPolicy, AuthKeySpec, NodeEntry, RegisterError, Registry,
};
use landscape_rill_core::crypto::{derive_key_dst, derive_key_path, KEY_DST_LEN};
use landscape_rill_core::route::Prefix;
use std::collections::HashMap;

pub const BROADCAST_KEY_LEN: usize = 32;
/// 能力位：relay（自愿中继，CONNECTIVITY §5 / CONTROL_PLANE §3.1）
pub const CAPABILITY_RELAY: u32 = 0x01;

fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

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
    /// 协议版本（v2 路径能力协商；v1 节点恒 1）
    pub protocol_version: u32,
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
    /// 路径服务（v1.5，CONTROL_PLANE §3.11）
    paths: PathService,
    /// 节点协议版本（v2 路径能力协商，netmap 带出）
    protocol_versions: HashMap<u32, u32>,
}

impl Coordinator {
    pub fn new(master_key: [u8; 32], signing_seed: [u8; 32]) -> Self {
        let mut coord = Self {
            registry: Registry::new(0x0000_0001),
            signer: Ed25519Signer::new(signing_seed),
            master_key,
            netmap_version: 0,
            key_version: 1,
            last_seen: HashMap::new(),
            endpoints: HashMap::new(),
            relay_list: Vec::new(),
            offline: Vec::new(),
            paths: PathService::new(),
            protocol_versions: HashMap::new(),
        };
        coord.sync_relays();
        coord
    }

    /// relay 节点集合 = 能力位含 relay 的节点（voluntary opt-in，CONNECTIVITY §5）
    fn sync_relays(&mut self) {
        let relays: Vec<u32> = self
            .registry
            .entries()
            .filter(|e| e.capabilities & CAPABILITY_RELAY != 0)
            .map(|e| e.node_id)
            .collect();
        self.paths.set_relays(relays);
    }

    pub fn set_protocol_version(&mut self, node_id: u32, version: u32) {
        self.protocol_versions.insert(node_id, version);
    }

    pub fn protocol_version(&self, node_id: u32) -> u32 {
        self.protocol_versions.get(&node_id).copied().unwrap_or(1)
    }

    pub fn add_auth_key(&mut self, key: &str, policy: AuthKeyPolicy) {
        self.registry.add_auth_key(key, policy);
    }

    /// 管理面库 API（REQ-038/REQ-036）：auth key 完整规格（过期/tag）
    pub fn add_auth_key_spec(&mut self, key: &str, spec: AuthKeySpec) {
        self.registry.add_auth_key_spec(key, spec);
    }

    pub fn remove_auth_key(&mut self, key: &str) {
        self.registry.remove_auth_key(key);
    }

    pub fn has_auth_key(&self, key: &str) -> bool {
        self.registry.has_auth_key(key)
    }

    /// 当前已配置的全部 auth key（apply 增量收敛用）
    pub fn auth_key_list(&self) -> Vec<String> {
        self.registry.auth_key_list()
    }

    /// 管理面库 API（REQ-038）：前缀公告白名单（fail-closed：空 = 拒绝一切公告）
    pub fn set_announce_whitelist(&mut self, whitelist: Vec<Prefix>) {
        self.registry.set_announce_whitelist(whitelist);
    }

    pub fn announce_whitelist(&self) -> Vec<String> {
        self.registry
            .announce_whitelist()
            .iter()
            .map(|p| p.to_cidr())
            .collect()
    }

    pub fn register(
        &mut self,
        auth_key: &str,
        static_pubkey: &[u8; 32],
        capabilities: u32,
        routes: Vec<String>,
    ) -> Result<RegisterData, RegisterError> {
        let outcome =
            self.registry
                .register(auth_key, static_pubkey, capabilities, routes, &self.signer)?;
        let node_id = match outcome {
            landscape_rill_core::control::registry::RegisterOutcome::NewNode(id) => {
                self.netmap_version += 1;
                self.sync_relays(); // relay 候选随新节点注册更新（relay 位 opt-in）
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

    // ==================== 路径服务（v1.5，CONTROL_PLANE §3.11） ====================

    /// PathRequest 处理：构造候选路径集（直连 + 经 relay），返回 (候选, key_path)
    pub fn request_paths(
        &mut self,
        source: u32,
        dest: u32,
        max: u32,
    ) -> Vec<(PathCandidate, [u8; KEY_DST_LEN])> {
        let now = unix_seconds();
        self.paths
            .request(source, dest, max, now)
            .iter()
            .map(|c| {
                let key_path = derive_key_path(&self.master_key, c.path_id, c.path_epoch);
                (c.clone(), key_path)
            })
            .collect()
    }

    /// 心跳推送：取走该节点（source 身份）的未推送路径事件
    pub fn take_path_events(&mut self, source: u32) -> Vec<PathEvent> {
        self.paths.take_events(source)
    }

    /// PathUpdate 推送用：按路径重新派生 key_path（只发路径参与者）
    pub fn key_path_for(&self, path_id: u64, path_epoch: u32) -> [u8; KEY_DST_LEN] {
        derive_key_path(&self.master_key, path_id, path_epoch)
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
                protocol_version: self.protocol_version(e.node_id),
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
            self.protocol_versions.remove(&node_id);
            // 路径联动：撤销所有涉及该节点的路径（源/目的/中继）
            self.paths.withdraw_node(node_id);
            self.key_version += 1;
            self.netmap_version += 1;
            self.sync_relays();
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
        c.register("ak-1", &pubkey(seed), 0x01, vec![])
            .unwrap()
            .node_id
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
    fn relay_list_follows_registration() {
        let mut c = setup();
        c.add_auth_key("ak-2", AuthKeyPolicy::Reusable);
        c.add_auth_key("ak-3", AuthKeyPolicy::Reusable);
        let relay = c
            .register("ak-1", &pubkey(1), 0x01, vec![])
            .unwrap()
            .node_id;
        let src = c
            .register("ak-2", &pubkey(2), 0x00, vec![])
            .unwrap()
            .node_id;
        let dst = c
            .register("ak-3", &pubkey(3), 0x00, vec![])
            .unwrap()
            .node_id;
        let cands = c.request_paths(src, dst, 4);
        assert!(cands.iter().any(|(p, _)| p.hops == vec![relay, dst]));
        assert_eq!(cands.len(), 2); // direct + relay
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
