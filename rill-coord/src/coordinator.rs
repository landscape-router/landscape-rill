use crate::path_service::{PathCandidate, PathEvent, PathService};
use crate::signer::Ed25519Signer;
use crate::store::{CoordState, CoordStore, StoreError, STATE_SCHEMA};
use landscape_rill_core::control::registry::{
    AuthKeyPolicy, AuthKeySpec, NodeEntry, RegisterError, Registry,
};
use landscape_rill_core::crypto::{derive_key_dst, derive_key_path, KEY_DST_LEN};
use landscape_rill_core::route::Prefix;
use std::collections::{HashMap, HashSet};
use std::path::Path;

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
    /// 持久化存储（REQ-037）；None = 纯内存（重启丢失注册）
    store: Option<CoordStore>,
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
            store: None,
        };
        coord.sync_relays();
        coord
    }

    /// 打开（或创建）持久化存储并恢复状态；损坏/不一致 → Err（fail-closed，REQ-037）
    pub fn open(
        path: &Path,
        master_key: [u8; 32],
        signing_seed: [u8; 32],
    ) -> Result<Self, StoreError> {
        let store = CoordStore::open(path)?;
        let mut coord = Self::new(master_key, signing_seed);
        if let Some(state) = store.load()? {
            coord.restore_state(&state)?;
        }
        coord.store = Some(store);
        coord.sync_relays();
        Ok(coord)
    }

    /// 恢复持久状态（语义校验 fail-closed：不猜测重建）
    fn restore_state(&mut self, state: &CoordState) -> Result<(), StoreError> {
        let max_node = state.nodes.iter().map(|n| n.node_id).max().unwrap_or(0);
        if state.next_node_id == 0 || state.next_node_id <= max_node {
            return Err(StoreError::Inconsistent(format!(
                "next_node_id={} 与节点表最大 id={} 不一致",
                state.next_node_id, max_node
            )));
        }
        let mut seen_ids = HashSet::new();
        let mut seen_pubkeys = HashSet::new();
        for n in &state.nodes {
            if !seen_ids.insert(n.node_id) {
                return Err(StoreError::Inconsistent(format!(
                    "节点表含重复 node_id={}",
                    n.node_id
                )));
            }
            if !seen_pubkeys.insert(n.static_pubkey) {
                return Err(StoreError::Inconsistent(format!(
                    "节点表含重复公钥 node_id={}",
                    n.node_id
                )));
            }
        }
        let mut path_map = HashMap::new();
        for (s, d, set) in &state.path_map {
            if path_map.insert((*s, *d), set.clone()).is_some() {
                return Err(StoreError::Inconsistent(format!(
                    "路径表含重复 (source={s}, dest={d})"
                )));
            }
        }
        self.registry.restore(
            state.nodes.clone(),
            state.next_node_id,
            state.consumed_one_time_keys.clone(),
        );
        self.netmap_version = state.netmap_version;
        self.key_version = state.key_version;
        self.endpoints = state.endpoints.iter().cloned().collect();
        self.paths.restore(path_map, state.path_seq);
        Ok(())
    }

    /// 持久状态快照（确定性排序）
    fn snapshot(&self) -> CoordState {
        let mut nodes: Vec<NodeEntry> = self.registry.entries().cloned().collect();
        nodes.sort_by_key(|n| n.node_id);
        let mut endpoints: Vec<(u32, Vec<String>)> = self
            .endpoints
            .iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        endpoints.sort_by_key(|(k, _)| *k);
        let (path_map, path_seq) = self.paths.persistent();
        CoordState {
            schema: STATE_SCHEMA,
            next_node_id: self.registry.next_node_id(),
            nodes,
            consumed_one_time_keys: self.registry.consumed_one_time_keys().to_vec(),
            netmap_version: self.netmap_version,
            key_version: self.key_version,
            endpoints,
            path_map,
            path_seq,
        }
    }

    /// 写穿透持久化（仅在配置存储时生效）；写入失败不中断数据面，留日志缺口
    fn persist(&self) {
        let Some(store) = &self.store else {
            return;
        };
        if let Err(e) = store.save(&self.snapshot()) {
            eprintln!("[coord] persist failed (state not durable): {e}");
        }
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
        // 过期时间内嵌在 key 自身（REQ-043）：admission 时解析校验；
        // 解析失败 = 非法 key（fail-closed）。格式知识在 rill-coord，注册表按不透明字符串处理。
        let parsed =
            crate::config::parse_auth_key(auth_key).map_err(|_| RegisterError::InvalidAuthKey)?;
        if parsed.1 != 0 && unix_seconds() > parsed.1 {
            return Err(RegisterError::InvalidAuthKey);
        }
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
        self.persist();
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
        self.persist();
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
        let out = self
            .paths
            .request(source, dest, max, now)
            .iter()
            .map(|c| {
                let key_path = derive_key_path(&self.master_key, c.path_id, c.path_epoch);
                (c.clone(), key_path)
            })
            .collect();
        // path_id 分配器与 PathMap 变更需落盘（重启不重用 path_id）
        self.persist();
        out
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
            self.persist();
        }
    }

    pub fn rotate_master_key(&mut self, new_master_key: [u8; 32]) {
        self.master_key = new_master_key;
        self.key_version += 1;
        self.persist();
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

    /// lrk 格式 auth key（REQ-043 起注册校验要求可解析 + 未过期）
    fn lrk(ttl_secs: u64) -> String {
        crate::config::generate_auth_key("lab", ttl_secs).unwrap()
    }

    fn setup() -> (Coordinator, String) {
        let ak = lrk(86_400);
        let mut c = Coordinator::new([0x77; 32], [0x5a; 32]);
        c.add_auth_key(&ak, AuthKeyPolicy::Reusable);
        (c, ak)
    }

    fn register_node(c: &mut Coordinator, ak: &str, seed: u8) -> u32 {
        c.register(ak, &pubkey(seed), 0x01, vec![]).unwrap().node_id
    }

    #[test]
    fn register_and_netmap() {
        let (mut c, ak) = setup();
        let v0 = c.netmap_version();
        let id = register_node(&mut c, &ak, 1);
        assert_eq!(id, 1);
        assert_eq!(c.netmap_version(), v0 + 1);
        let snap = c.netmap_snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].node_id, 1);
        assert_eq!(snap[0].static_pubkey, pubkey(1));
    }

    #[test]
    fn register_idempotent_no_version_bump() {
        let (mut c, ak) = setup();
        let v0 = c.netmap_version();
        register_node(&mut c, &ak, 1);
        let v1 = c.netmap_version();
        assert_eq!(v1, v0 + 1);
        let out = c.register(&ak, &pubkey(1), 0x01, vec![]).unwrap();
        assert_eq!(out.node_id, 1);
        assert_eq!(c.netmap_version(), v1);
    }

    #[test]
    fn relay_list_follows_registration() {
        let (mut c, ak) = setup();
        let relay = c.register(&ak, &pubkey(1), 0x01, vec![]).unwrap().node_id;
        let src = c.register(&ak, &pubkey(2), 0x00, vec![]).unwrap().node_id;
        let dst = c.register(&ak, &pubkey(3), 0x00, vec![]).unwrap().node_id;
        let cands = c.request_paths(src, dst, 4);
        assert!(cands.iter().any(|(p, _)| p.hops == vec![relay, dst]));
        assert_eq!(cands.len(), 2); // direct + relay
    }

    #[test]
    fn key_dist_deterministic_per_node() {
        let (mut c, ak) = setup();
        let id = register_node(&mut c, &ak, 1);
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
        let (c, _ak) = setup();
        assert!(c.key_dist(99).is_none());
    }

    #[test]
    fn revoke_removes_and_bumps_versions() {
        let (mut c, ak) = setup();
        let id = register_node(&mut c, &ak, 1);
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
        let (mut c, ak) = setup();
        let id = register_node(&mut c, &ak, 1);
        let before = c.key_dist(id).unwrap();
        c.rotate_master_key([0x99; 32]);
        let after = c.key_dist(id).unwrap();
        assert_ne!(before.key, after.key);
        assert_eq!(after.key_version, before.key_version + 1);
    }

    #[test]
    fn heartbeat_and_offline() {
        let (mut c, ak) = setup();
        let id = register_node(&mut c, &ak, 1);
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
        let (mut c, ak) = setup();
        let id = register_node(&mut c, &ak, 1);
        c.set_endpoints(id, vec!["203.0.113.1:41641".into()]);
        let snap = c.netmap_snapshot();
        assert_eq!(snap[0].endpoints, vec!["203.0.113.1:41641"]);
    }

    // ==================== 持久化（REQ-037） ====================

    #[test]
    fn expired_key_rejected_at_admission() {
        // REQ-043：过期内嵌 key，注册时（admission）拒绝；挑战恢复路径不受影响
        let now = unix_seconds();
        let expired = format!("lrk-lab-{}-{}", now - 1, "A".repeat(52));
        let mut c = Coordinator::new([0x77; 32], [0x5a; 32]);
        c.add_auth_key(&expired, AuthKeyPolicy::Reusable);
        assert!(c.has_auth_key(&expired)); // 过期 key 可配置（inert），admission 时拒绝
        let err = c.register(&expired, &pubkey(1), 0x00, vec![]);
        assert!(matches!(err, Err(RegisterError::InvalidAuthKey)));
        // 非 lrk 格式 → fail-closed 拒绝
        let mut c = Coordinator::new([0x77; 32], [0x5a; 32]);
        c.add_auth_key("opaque-key", AuthKeyPolicy::Reusable);
        let err = c.register("opaque-key", &pubkey(1), 0x00, vec![]);
        assert!(matches!(err, Err(RegisterError::InvalidAuthKey)));
    }

    fn tmp_db(name: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "lrill-{name}-{}-{}.redb",
            std::process::id(),
            rand::random::<u32>()
        ));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn persist_roundtrip_restores_full_state() {
        let ak = lrk(86_400);

        let path = tmp_db("roundtrip");
        let mut c = Coordinator::open(&path, [0x77; 32], [0x5a; 32]).unwrap();
        c.add_auth_key(&ak, AuthKeyPolicy::Reusable);
        let a = c.register(&ak, &pubkey(1), 0x01, vec![]).unwrap().node_id;
        c.set_endpoints(a, vec!["203.0.113.1:41641".into()]);
        let b = c.register(&ak, &pubkey(2), 0x00, vec![]).unwrap().node_id;
        c.request_paths(a, b, 4);
        drop(c);

        let c = Coordinator::open(&path, [0x77; 32], [0x5a; 32]).unwrap();
        assert_eq!(c.netmap_version(), 3); // 注册 a + 端点 + 注册 b
        assert_eq!(c.key_version(), 1);
        assert_eq!(c.netmap_snapshot().len(), 2);
        let mut snap = c.netmap_snapshot();
        snap.sort_by_key(|n| n.node_id);
        assert_eq!(snap[0].node_id, 1);
        assert_eq!(snap[0].static_pubkey, pubkey(1));
        assert_eq!(snap[1].node_id, 2);
        assert_eq!(snap[0].endpoints, vec!["203.0.113.1:41641"]);
        // 身份绑定恢复（签名确定性，可直接比对）
        assert!(c.key_dist(a).is_some());
        assert!(c.node_id_by_pubkey(&pubkey(1)) == Some(a));
        drop(c);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn one_time_consumption_survives_restart() {
        let ak = lrk(86_400);

        let path = tmp_db("onetime");
        let mut c = Coordinator::open(&path, [0x77; 32], [0x5a; 32]).unwrap();
        c.add_auth_key(&ak, AuthKeyPolicy::OneTime);
        c.register(&ak, &pubkey(1), 0x00, vec![]).unwrap();
        assert!(!c.has_auth_key(&ak));
        drop(c);

        let mut c = Coordinator::open(&path, [0x77; 32], [0x5a; 32]).unwrap();
        assert!(!c.has_auth_key(&ak), "一次性 key 消费必须持久化");
        // 同 key 二次注册被拒（未知公钥 + 无有效 key）
        let err = c.register(&ak, &pubkey(2), 0x00, vec![]);
        assert!(matches!(err, Err(RegisterError::InvalidAuthKey)));
        drop(c);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn consumed_key_not_revived_by_reload() {
        let ak = lrk(86_400);

        // SIGHUP 重载（config 重新 apply）不复活已消费的一次性 key
        let path = tmp_db("reload");
        let mut c = Coordinator::open(&path, [0x77; 32], [0x5a; 32]).unwrap();
        c.add_auth_key(&ak, AuthKeyPolicy::OneTime);
        c.register(&ak, &pubkey(1), 0x00, vec![]).unwrap();
        drop(c);

        let mut c = Coordinator::open(&path, [0x77; 32], [0x5a; 32]).unwrap();
        c.add_auth_key(&ak, AuthKeyPolicy::OneTime);
        assert!(!c.has_auth_key(&ak), "重载不得复活已消费 key");
        drop(c);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn node_and_path_ids_monotonic_across_restart() {
        let ak = lrk(86_400);

        let path = tmp_db("ids");
        let mut c = Coordinator::open(&path, [0x77; 32], [0x5a; 32]).unwrap();
        c.add_auth_key(&ak, AuthKeyPolicy::Reusable);
        let a = c.register(&ak, &pubkey(1), 0x00, vec![]).unwrap().node_id;
        let b = c.register(&ak, &pubkey(2), 0x00, vec![]).unwrap().node_id;
        let paths = c.request_paths(a, b, 4);
        drop(c);

        // 重启后新节点不重用 node_id；新路径不重用 path_id
        // （auth key 为配置权威，重启后须重新 apply——模拟 from_config 的 apply_to）
        let mut c = Coordinator::open(&path, [0x77; 32], [0x5a; 32]).unwrap();
        c.add_auth_key(&ak, AuthKeyPolicy::Reusable);
        let d = c.register(&ak, &pubkey(3), 0x00, vec![]).unwrap().node_id;
        assert_eq!(d, 3);
        let paths2 = c.request_paths(a, d, 4);
        for (p, _) in &paths2 {
            assert!(!paths.iter().any(|(q, _)| q.path_id == p.path_id));
        }
        // 幂等命中保留原 path_id（参与者间不分叉）
        let paths3 = c.request_paths(a, b, 4);
        assert_eq!(paths3.len(), paths.len());
        assert!(paths3
            .iter()
            .zip(&paths)
            .all(|(p, q)| p.0.path_id == q.0.path_id));
        drop(c);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn corrupt_store_fails_closed() {
        let path = tmp_db("corrupt");
        {
            let c = Coordinator::open(&path, [0x77; 32], [0x5a; 32]).unwrap();
            drop(c);
        }
        std::fs::write(&path, b"not a redb file at all").unwrap();
        assert!(Coordinator::open(&path, [0x77; 32], [0x5a; 32]).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn inconsistent_state_fails_closed() {
        let ak = lrk(86_400);

        // next_node_id 与节点表不一致 → 拒绝启动（不猜测重建）
        let path = tmp_db("inconsistent");
        {
            let mut c = Coordinator::open(&path, [0x77; 32], [0x5a; 32]).unwrap();
            c.add_auth_key(&ak, AuthKeyPolicy::Reusable);
            c.register(&ak, &pubkey(1), 0x00, vec![]).unwrap();
            drop(c);
        }
        // 篡改快照：把 next_node_id 改回 1（与已注册 node 1 冲突）
        let store = crate::store::CoordStore::open(&path).unwrap();
        let mut state = store.load().unwrap().unwrap();
        state.next_node_id = 1;
        store.save(&state).unwrap();
        assert!(Coordinator::open(&path, [0x77; 32], [0x5a; 32]).is_err());
        let _ = std::fs::remove_file(&path);
    }
}
