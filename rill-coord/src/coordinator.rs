//! coordinator 权威角色门面（CONTROL_PLANE）
//!
//! 域拆分（子结构提取，2026-09-01）：registry（admission，rill-core）/ signer /
//! [liveness]（活性）/ [directory]（目录）/ [keys]（密钥）/ [path_service]（路径）/
//! [store]（持久化）。本文件只做**跨域编排**（register/revoke/netmap_snapshot/
//! sync_relays）与持久化 glue（snapshot/restore/persist）；单域逻辑在各域文件。
//! 多网络隔离（CONTROL_PLANE §1.5，2026-09-01）：每网络一个 [domain](crate::domain::
//! NetworkDomain)（registry/主密钥/路径/relay 列表独立）；node_id 全局唯一分配。

use crate::directory::Directory;
use crate::domain::{network_id_for, NetworkDomain};
use crate::liveness::Liveness;
use crate::path_service::{PathCandidate, PathEvent, PathSet};
use crate::signer::Ed25519Signer;
use crate::store::{CoordState, CoordStore, StoreError, STATE_SCHEMA};
use landscape_rill_core::control::registry::{
    AuthKeyPolicy, AuthKeySpec, NodeEntry, RegisterError, RegisterOutcome,
};
use landscape_rill_core::crypto::KEY_DST_LEN;
use landscape_rill_core::error::format_chain;
use landscape_rill_core::route::Prefix;
use std::collections::HashSet;
use std::path::Path;
use tracing::{error, warn};

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
    pub broadcast_key: [u8; KEY_DST_LEN],
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
    /// 网络隔离域（CONTROL_PLANE §1.5）：每网络 registry/主密钥/路径/relay 独立
    domains: Vec<NetworkDomain>,
    signer: Ed25519Signer,
    liveness: Liveness,
    directory: Directory,
    /// 全局 node_id 分配器（跨网络唯一；Directory/Liveness 按 node_id 键控）
    next_node_id: u32,
    /// 持久化存储（REQ-037）；None = 纯内存（重启丢失注册）
    store: Option<CoordStore>,
}

impl Coordinator {
    pub fn new(signing_seed: [u8; 32]) -> Self {
        Self {
            domains: Vec::new(),
            signer: Ed25519Signer::new(signing_seed),
            liveness: Liveness::new(),
            directory: Directory::new(),
            next_node_id: 1,
            store: None,
        }
    }

    /// 注册网络域（network_id = fnv1a(name) 确定性散列；重名/散列碰撞由配置校验拦截）
    pub fn add_network(&mut self, name: &str, master_key: [u8; 32]) -> u32 {
        let network_id = network_id_for(name);
        self.domains
            .push(NetworkDomain::new(name, network_id, master_key));
        network_id
    }

    /// 打开（或创建）持久化存储并恢复状态；损坏/不一致 → Err（fail-closed，REQ-037）。
    /// `networks`：网络名 → 主密钥（与配置一致；恢复时按 network_id 分组归域）
    pub fn open(
        path: &Path,
        networks: &[(String, [u8; 32])],
        signing_seed: [u8; 32],
    ) -> Result<Self, StoreError> {
        let store = CoordStore::open(path)?;
        let mut coord = Self::new(signing_seed);
        for (name, master_key) in networks {
            coord.add_network(name, *master_key);
        }
        if let Some(state) = store.load()? {
            coord.restore_state(&state)?;
        }
        coord.store = Some(store);
        coord.sync_all_relays();
        Ok(coord)
    }

    // ==================== 域查找 ====================

    fn domain_by_name(&self, name: &str) -> Option<&NetworkDomain> {
        self.domains.iter().find(|d| d.name == name)
    }

    fn domain_by_name_mut(&mut self, name: &str) -> Option<&mut NetworkDomain> {
        self.domains.iter_mut().find(|d| d.name == name)
    }

    fn domain_by_network_id(&self, network_id: u32) -> Option<&NetworkDomain> {
        self.domains.iter().find(|d| d.network_id == network_id)
    }

    fn domain_of_node(&self, node_id: u32) -> Option<&NetworkDomain> {
        let network_id = self
            .domains
            .iter()
            .find_map(|d| d.registry.entry(node_id))
            .map(|e| e.network_id)?;
        self.domain_by_network_id(network_id)
    }

    fn domain_of_node_mut(&mut self, node_id: u32) -> Option<&mut NetworkDomain> {
        let network_id = self
            .domains
            .iter()
            .find_map(|d| d.registry.entry(node_id))
            .map(|e| e.network_id)?;
        self.domains.iter_mut().find(|d| d.network_id == network_id)
    }

    /// relay 节点集合同步（每网络独立；能力位含 relay 的节点，voluntary opt-in）
    fn sync_all_relays(&mut self) {
        for d in &mut self.domains {
            d.sync_relays();
        }
    }

    /// 恢复持久状态（语义校验 fail-closed：不猜测重建）
    fn restore_state(&mut self, state: &CoordState) -> Result<(), StoreError> {
        let max_node = state.nodes.iter().map(|n| n.node_id).max().unwrap_or(0);
        if state.next_node_id == 0 || state.next_node_id <= max_node {
            return Err(StoreError::Inconsistent(format!(
                "next_node_id={} inconsistent with max node id={}",
                state.next_node_id, max_node
            )));
        }
        let mut seen_ids = HashSet::new();
        let mut seen_pubkeys = HashSet::new();
        for n in &state.nodes {
            if !seen_ids.insert(n.node_id) {
                return Err(StoreError::Inconsistent(format!(
                    "duplicate node_id={} in node table",
                    n.node_id
                )));
            }
            if !seen_pubkeys.insert(n.static_pubkey) {
                return Err(StoreError::Inconsistent(format!(
                    "duplicate pubkey node_id={}",
                    n.node_id
                )));
            }
            if self.domain_by_network_id(n.network_id).is_none() {
                return Err(StoreError::Inconsistent(format!(
                    "node_id={} belongs to unconfigured network_id={}",
                    n.node_id, n.network_id
                )));
            }
        }
        self.next_node_id = state.next_node_id;
        for domain in &mut self.domains {
            let domain_nodes: Vec<NodeEntry> = state
                .nodes
                .iter()
                .filter(|n| n.network_id == domain.network_id)
                .cloned()
                .collect();
            // 一次性 auth key 消费 tombstone 按 key 内嵌网络归域（CONTROL_PLANE §1.5）
            let consumed: Vec<String> = state
                .consumed_one_time_keys
                .iter()
                .filter(|k| {
                    crate::authkey::parse_auth_key(k)
                        .map(|(net, _, _)| net == domain.name)
                        .unwrap_or(false)
                })
                .cloned()
                .collect();
            domain.registry.restore(domain_nodes, consumed);
            let key_version = state
                .key_versions
                .iter()
                .find(|(id, _)| *id == domain.network_id)
                .map(|(_, v)| *v)
                .ok_or_else(|| {
                    StoreError::Inconsistent(format!(
                        "network_id={} missing key_version in store",
                        domain.network_id
                    ))
                })?;
            domain.keys.restore_version(key_version);
            if let Some((_, map, seq)) = state
                .path_maps
                .iter()
                .find(|(id, _, _)| *id == domain.network_id)
            {
                let mut path_map = std::collections::HashMap::new();
                for (s, d, set) in map {
                    if path_map.insert((*s, *d), set.clone()).is_some() {
                        return Err(StoreError::Inconsistent(format!(
                            "duplicate path entry (source={s}, dest={d})"
                        )));
                    }
                }
                domain.paths.restore(path_map, *seq);
            }
            if let Some((_, list)) = state
                .relay_lists
                .iter()
                .find(|(id, _)| *id == domain.network_id)
            {
                domain.relay_list = list.clone();
            }
        }
        self.directory.restore(
            state.netmap_version,
            state.endpoints.iter().cloned().collect(),
        );
        Ok(())
    }

    /// 持久状态快照（确定性排序）
    fn snapshot(&self) -> CoordState {
        let mut nodes: Vec<NodeEntry> = self
            .domains
            .iter()
            .flat_map(|d| d.registry.entries().cloned())
            .collect();
        nodes.sort_by_key(|n| n.node_id);
        let mut endpoints: Vec<(u32, Vec<String>)> = self
            .directory
            .endpoints_all()
            .iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        endpoints.sort_by_key(|(k, _)| *k);
        let mut key_versions: Vec<(u32, u32)> = self
            .domains
            .iter()
            .map(|d| (d.network_id, d.keys.version()))
            .collect();
        key_versions.sort_by_key(|(id, _)| *id);
        type NetworkPathMap = (u32, Vec<(u32, u32, PathSet)>, u64);
        let mut path_maps: Vec<NetworkPathMap> = self
            .domains
            .iter()
            .map(|d| {
                let (map, seq) = d.paths.persistent();
                (d.network_id, map, seq)
            })
            .collect();
        path_maps.sort_by_key(|(id, _, _)| *id);
        let mut relay_lists: Vec<(u32, Vec<String>)> = self
            .domains
            .iter()
            .map(|d| (d.network_id, d.relay_list.clone()))
            .collect();
        relay_lists.sort_by_key(|(id, _)| *id);
        let mut consumed: Vec<String> = self
            .domains
            .iter()
            .flat_map(|d| d.registry.consumed_one_time_keys().iter().cloned())
            .collect();
        consumed.sort();
        CoordState {
            schema: STATE_SCHEMA,
            next_node_id: self.next_node_id,
            nodes,
            consumed_one_time_keys: consumed,
            netmap_version: self.directory.netmap_version(),
            key_versions,
            endpoints,
            path_maps,
            relay_lists,
        }
    }

    /// 写穿透持久化（仅在配置存储时生效）；写入失败不中断数据面，留日志缺口
    fn persist(&self) {
        let Some(store) = &self.store else {
            return;
        };
        if let Err(e) = store.save(&self.snapshot()) {
            error!(
                "[coord] persist failed (state not durable): {}",
                format_chain(&e)
            );
        }
    }

    pub fn set_protocol_version(&mut self, node_id: u32, version: u32) {
        self.directory.set_protocol_version(node_id, version);
    }

    pub fn protocol_version(&self, node_id: u32) -> u32 {
        self.directory.protocol_version(node_id)
    }

    /// 节点所属网络（server 按节点网络过滤 netmap/relay 列表）
    pub fn network_id_of(&self, node_id: u32) -> Option<u32> {
        self.domain_of_node(node_id).map(|d| d.network_id)
    }

    // ==================== 管理面库 API（REQ-038/REQ-036） ====================

    /// auth key 归域（CONTROL_PLANE §1.5）：key 内嵌网络 → 该网络的 registry。
    /// 网络不存在/解析失败 → 拒绝（fail-closed；配置加载已拦截，此处是库 API 防线）。
    pub fn add_auth_key(&mut self, key: &str, policy: AuthKeyPolicy) -> bool {
        self.add_auth_key_spec(key, AuthKeySpec::simple(policy))
    }

    pub fn add_auth_key_spec(&mut self, key: &str, spec: AuthKeySpec) -> bool {
        let Some((network, _, _)) = crate::authkey::parse_auth_key(key).ok() else {
            warn!("[coord] add_auth_key: unparseable key (rejected)");
            return false;
        };
        let Some(domain) = self.domain_by_name_mut(network) else {
            warn!("[coord] add_auth_key: unknown network '{network}' (rejected)");
            return false;
        };
        domain.registry.add_auth_key_spec(key, spec);
        true
    }

    pub fn remove_auth_key(&mut self, key: &str) {
        if let Ok((network, _, _)) = crate::authkey::parse_auth_key(key) {
            if let Some(domain) = self.domain_by_name_mut(network) {
                domain.registry.remove_auth_key(key);
            }
        }
    }

    pub fn has_auth_key(&self, key: &str) -> bool {
        self.domains.iter().any(|d| d.registry.has_auth_key(key))
    }

    /// 当前已配置的全部 auth key（apply 增量收敛用；按网络归集）
    pub fn auth_key_list(&self) -> Vec<String> {
        self.domains
            .iter()
            .flat_map(|d| d.registry.auth_key_list())
            .collect()
    }

    /// 某网络已配置的 auth key（SIGHUP 重载按网络收敛用）
    pub fn auth_key_list_for(&self, network: &str) -> Vec<String> {
        self.domain_by_name(network)
            .map(|d| d.registry.auth_key_list())
            .unwrap_or_default()
    }

    /// 管理面库 API（REQ-038）：前缀公告白名单（fail-closed：空 = 拒绝一切公告），按网络分域
    pub fn set_announce_whitelist(&mut self, network: &str, whitelist: Vec<Prefix>) {
        if let Some(domain) = self.domain_by_name_mut(network) {
            domain.registry.set_announce_whitelist(whitelist);
        }
    }

    pub fn announce_whitelist(&self, network: &str) -> Vec<String> {
        self.domain_by_name(network)
            .map(|d| {
                d.registry
                    .announce_whitelist()
                    .iter()
                    .map(|p| p.to_cidr())
                    .collect()
            })
            .unwrap_or_default()
    }

    // ==================== 注册 / 密钥下发 ====================

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
            crate::authkey::parse_auth_key(auth_key).map_err(|_| RegisterError::InvalidAuthKey)?;
        if parsed.1 != 0 && unix_seconds() > parsed.1 {
            return Err(RegisterError::InvalidAuthKey);
        }
        // 归域（CONTROL_PLANE §1.5）：注册即归域——key 内嵌网络必须存在，只可能进入该网络
        if !self.domains.iter().any(|d| d.name == parsed.0) {
            return Err(RegisterError::InvalidAuthKey);
        }
        // node_id 全局分配：注册失败（校验在插入前）不推进计数器，无空洞
        let tentative = self.next_node_id;
        let signer = &self.signer;
        let outcome = {
            let domain = self
                .domains
                .iter_mut()
                .find(|d| d.name == parsed.0)
                .unwrap();
            domain.registry.register(
                auth_key,
                static_pubkey,
                capabilities,
                routes,
                tentative,
                signer,
            )
        };
        let node_id = match outcome {
            Ok(RegisterOutcome::NewNode(id)) => {
                self.next_node_id += 1;
                self.directory.bump_netmap(); // relay 候选随新节点注册更新（relay 位 opt-in）
                let domain = self
                    .domains
                    .iter_mut()
                    .find(|d| d.name == parsed.0)
                    .unwrap();
                domain.sync_relays();
                id
            }
            Ok(RegisterOutcome::Existing(id)) => id,
            Err(e) => return Err(e),
        };
        let entry = self
            .domain_of_node(node_id)
            .and_then(|d| d.registry.entry(node_id))
            .unwrap();
        self.persist();
        Ok(RegisterData {
            node_id: entry.node_id,
            network_id: entry.network_id,
            identity_binding: entry.identity_binding.clone(),
        })
    }

    pub fn key_dist(&self, node_id: u32) -> Option<KeyDistData> {
        let domain = self.domain_of_node(node_id)?;
        Some(KeyDistData {
            to_node_id: node_id,
            key: domain.keys.key_for(node_id),
            key_version: domain.keys.version(),
            broadcast_key: domain.keys.broadcast_key(),
        })
    }

    pub fn set_endpoints(&mut self, node_id: u32, endpoints: Vec<String>) {
        self.directory.set_endpoints(node_id, endpoints);
        self.persist();
    }

    // ==================== 路径服务（v1.5，CONTROL_PLANE §3.11） ====================

    /// PathRequest 处理：构造候选路径集（直连 + 经 relay），返回 (候选, key_path)。
    /// 跨网络路径请求 → 空集（fail-closed：netmap 隔离下源本就看不到异网节点）。
    pub fn request_paths(
        &mut self,
        source: u32,
        dest: u32,
        max: u32,
    ) -> Vec<(PathCandidate, [u8; KEY_DST_LEN])> {
        let (Some(sd), Some(dd)) = (self.domain_of_node(source), self.domain_of_node(dest)) else {
            return Vec::new();
        };
        if sd.network_id != dd.network_id {
            return Vec::new();
        }
        let network_id = sd.network_id;
        let now = unix_seconds();
        let out = self
            .domains
            .iter_mut()
            .find(|d| d.network_id == network_id)
            .map(|d| {
                d.paths
                    .request(source, dest, max, now)
                    .iter()
                    .map(|c| {
                        let key_path = d.keys.key_path_for(c.path_id, c.path_epoch);
                        (c.clone(), key_path)
                    })
                    .collect()
            })
            .unwrap_or_default();
        // path_id 分配器与 PathMap 变更需落盘（重启不重用 path_id）
        self.persist();
        out
    }

    /// 心跳推送：取走该节点（source 身份）的未推送路径事件（按节点所属网络）
    pub fn take_path_events(&mut self, source: u32) -> Vec<PathEvent> {
        let Some(domain) = self.domain_of_node_mut(source) else {
            return Vec::new();
        };
        domain.paths.take_events(source)
    }

    /// PathUpdate 推送用：按路径重新派生 key_path（只发路径参与者；密钥按源网络主密钥）
    pub fn key_path_for(&self, source: u32, path_id: u64, path_epoch: u32) -> [u8; KEY_DST_LEN] {
        self.domain_of_node(source)
            .map(|d| d.keys.key_path_for(path_id, path_epoch))
            .unwrap_or([0u8; KEY_DST_LEN])
    }

    /// 管理面库 API：relay 列表设置（按网络分域；RTT 排序见 echo 探测链路）
    pub fn set_relay_list(&mut self, network: &str, relay_list: Vec<String>) {
        if let Some(domain) = self.domain_by_name_mut(network) {
            domain.relay_list = relay_list;
        }
    }

    // ==================== netmap 快照 ====================

    /// 网络隔离（SEC-21/CTL-09）：只返回指定网络的条目
    pub fn netmap_snapshot(&self, network_id: u32) -> Vec<NodeInfo> {
        self.domains
            .iter()
            .filter(|d| d.network_id == network_id)
            .flat_map(|d| d.registry.entries())
            .map(|e: &NodeEntry| NodeInfo {
                node_id: e.node_id,
                network_id: e.network_id,
                static_pubkey: e.static_pubkey,
                capabilities: e.capabilities,
                routes: e.routes.clone(),
                endpoints: self.directory.endpoints_of(e.node_id).to_vec(),
                offline: self.liveness.is_offline(e.node_id),
                protocol_version: self.directory.protocol_version(e.node_id),
            })
            .collect()
    }

    pub fn netmap_version(&self) -> u64 {
        self.directory.netmap_version()
    }

    pub fn relay_list_for(&self, network_id: u32) -> &[String] {
        self.domain_by_network_id(network_id)
            .map(|d| d.relay_list.as_slice())
            .unwrap_or(&[])
    }

    pub fn heartbeat(&mut self, node_id: u32, now: u64) {
        self.liveness.heartbeat(node_id, now);
    }

    pub fn mark_offline(&mut self, node_id: u32) {
        let known = self
            .domains
            .iter()
            .any(|d| d.registry.entry(node_id).is_some());
        if known && self.liveness.mark_offline(node_id) {
            self.directory.bump_netmap();
        }
    }

    pub fn offline_nodes(&self) -> &[u32] {
        self.liveness.offline_nodes()
    }

    pub fn revoke(&mut self, node_id: u32) {
        let revoked = self
            .domains
            .iter_mut()
            .find(|d| d.registry.entry(node_id).is_some())
            .map(|d| {
                d.registry.revoke(node_id);
                self.liveness.remove(node_id);
                self.directory.remove_node(node_id);
                // 路径联动：撤销所有涉及该节点的路径（源/目的/中继）
                d.paths.withdraw_node(node_id);
                d.keys.bump_version();
                self.directory.bump_netmap();
                d.sync_relays();
            })
            .is_some();
        if revoked {
            self.persist();
        }
    }

    /// 主密钥轮换（按网络；SIGHUP/管理面入口）
    pub fn rotate_master_key(&mut self, network: &str, new_master_key: [u8; 32]) {
        if let Some(domain) = self.domain_by_name_mut(network) {
            domain.keys.rotate(new_master_key);
            self.persist();
        }
    }

    pub fn key_version_for(&self, network: &str) -> u32 {
        self.domain_by_name(network)
            .map(|d| d.keys.version())
            .unwrap_or(0)
    }

    /// 按静态公钥定位已注册节点（重连挑战路径：auth key 失效 + 公钥已知 → 发起挑战）
    pub fn node_id_by_pubkey(&self, static_pubkey: &[u8; 32]) -> Option<u32> {
        self.domains
            .iter()
            .find_map(|d| d.registry.node_id_by_pubkey(static_pubkey))
    }

    /// 节点静态公钥（挑战验证用）
    pub fn static_pubkey_of(&self, node_id: u32) -> Option<[u8; 32]> {
        self.domain_of_node(node_id)
            .and_then(|d| d.registry.entry(node_id))
            .map(|e| e.static_pubkey)
    }

    pub fn verifier(&self) -> ed25519_dalek::VerifyingKey {
        self.signer.verifier()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authkey::generate_auth_key;

    fn pubkey(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    /// lrk 格式 auth key（REQ-043 起注册校验要求可解析 + 未过期）
    fn lrk(network: &str, ttl_secs: u64) -> String {
        generate_auth_key(network, ttl_secs).unwrap()
    }

    /// 单网络 coordinator（默认 lab）
    fn setup() -> (Coordinator, String) {
        let ak = lrk("lab", 86_400);
        let mut c = Coordinator::new([0x5a; 32]);
        c.add_network("lab", [0x77; 32]);
        c.add_auth_key(&ak, AuthKeyPolicy::Reusable);
        (c, ak)
    }

    /// 双网络 coordinator（lab + work，SEC-21~25/CTL-09 用）
    fn two_networks() -> (Coordinator, String, String) {
        let ak_a = lrk("lab", 86_400);
        let ak_b = lrk("work", 86_400);
        let mut c = Coordinator::new([0x5a; 32]);
        c.add_network("lab", [0x77; 32]);
        c.add_network("work", [0x88; 32]);
        c.add_auth_key(&ak_a, AuthKeyPolicy::Reusable);
        c.add_auth_key(&ak_b, AuthKeyPolicy::Reusable);
        (c, ak_a, ak_b)
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
        let nid = c.network_id_of(id).unwrap();
        let snap = c.netmap_snapshot(nid);
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
    fn key_dist_unknown_node_none() {
        let (c, _ak) = setup();
        assert!(c.key_dist(99).is_none());
    }

    #[test]
    fn revoke_removes_and_bumps_versions() {
        let (mut c, ak) = setup();
        let id = register_node(&mut c, &ak, 1);
        let nid = c.network_id_of(id).unwrap();
        let nv = c.netmap_version();
        let kv = c.key_version_for("lab");
        c.revoke(id);
        assert_eq!(c.netmap_snapshot(nid).len(), 0);
        assert_eq!(c.netmap_version(), nv + 1);
        assert_eq!(c.key_version_for("lab"), kv + 1);
        assert!(c.key_dist(id).is_none());
    }

    #[test]
    fn rotate_master_key_changes_keys() {
        let (mut c, ak) = setup();
        let id = register_node(&mut c, &ak, 1);
        let before = c.key_dist(id).unwrap();
        c.rotate_master_key("lab", [0x99; 32]);
        let after = c.key_dist(id).unwrap();
        assert_ne!(before.key, after.key);
        assert_eq!(after.key_version, before.key_version + 1);
    }

    #[test]
    fn heartbeat_and_offline_enters_netmap() {
        let (mut c, ak) = setup();
        let id = register_node(&mut c, &ak, 1);
        c.heartbeat(id, 100);
        assert!(c.offline_nodes().is_empty());
        c.mark_offline(id);
        assert_eq!(c.offline_nodes(), &[1]);
        let nid = c.network_id_of(id).unwrap();
        assert!(c.netmap_snapshot(nid)[0].offline);
        c.heartbeat(id, 200);
        assert!(c.offline_nodes().is_empty());
        assert!(!c.netmap_snapshot(nid)[0].offline);
    }

    #[test]
    fn endpoints_enter_netmap() {
        let (mut c, ak) = setup();
        let id = register_node(&mut c, &ak, 1);
        c.set_endpoints(id, vec!["203.0.113.1:41641".into()]);
        let nid = c.network_id_of(id).unwrap();
        let snap = c.netmap_snapshot(nid);
        assert_eq!(snap[0].endpoints, vec!["203.0.113.1:41641"]);
    }

    /// CTL-10（REQ-008）：白名单内公告并入 netmap；白名单外/过短前缀 → RouteNotAllowed（不部分采纳）
    #[test]
    fn announce_routes_enter_netmap_and_whitelist_gates() {
        let ak = lrk("lab", 86_400);
        let mut c = Coordinator::new([0x5a; 32]);
        c.add_network("lab", [0x77; 32]);
        c.add_auth_key(&ak, AuthKeyPolicy::Reusable);
        c.set_announce_whitelist(
            "lab",
            vec![
                Prefix::parse("10.0.0.0/8").unwrap(),
                Prefix::parse("fd00::/8").unwrap(),
            ],
        );
        // 白名单内公告 → 注册成功 + 进入 netmap
        let id = c
            .register(
                &ak,
                &pubkey(1),
                0x01,
                vec!["10.42.0.0/24".into(), "fd00:2::/64".into()],
            )
            .unwrap()
            .node_id;
        let snap = c.netmap_snapshot(c.network_id_of(id).unwrap());
        assert_eq!(
            snap.iter().find(|n| n.node_id == id).unwrap().routes,
            vec!["10.42.0.0/24", "fd00:2::/64"]
        );
        // 白名单外公告 → 整批拒绝（不部分采纳）
        let err = c.register(
            &ak,
            &pubkey(2),
            0x01,
            vec!["10.42.0.0/24".into(), "172.16.0.0/12".into()],
        );
        assert!(matches!(err, Err(RegisterError::RouteNotAllowed)));
        // 过短前缀（IPv4 < /8）→ 拒绝
        let err = c.register(&ak, &pubkey(3), 0x01, vec!["10.0.0.0/7".into()]);
        assert!(matches!(err, Err(RegisterError::RouteNotAllowed)));
        // 空白名单 = fail-closed（拒绝一切公告）
        let mut c2 = Coordinator::new([0x5a; 32]);
        c2.add_network("lab", [0x77; 32]);
        c2.add_auth_key(&ak, AuthKeyPolicy::Reusable);
        let err = c2.register(&ak, &pubkey(4), 0x01, vec!["10.42.0.0/24".into()]);
        assert!(matches!(err, Err(RegisterError::RouteNotAllowed)));
    }

    /// SEC-28（REQ-020）：acl 能力位 v1 恒 false——注册/转发不做裁决，位原样透传（v1 恒放行）
    #[test]
    fn capability_acl_bit_reserved_v1() {
        let (mut c, ak) = setup();
        // 保留位 0x40（acl，v2 预留）：coordinator 不解释、不占用，netmap 原样带出
        let id = c.register(&ak, &pubkey(7), 0x40, vec![]).unwrap().node_id;
        let snap = c.netmap_snapshot(c.network_id_of(id).unwrap());
        assert_eq!(
            snap.iter().find(|n| n.node_id == id).unwrap().capabilities & 0x40,
            0x40
        );
        // 策略检查点恒放行断言在 rill-core/src/route.rs（policy_checkpoint_allow_all_v1）
    }

    // ==================== 多网络隔离（SEC-21~25/CTL-09，CONTROL_PLANE §1.5） ====================

    /// SEC-21/CTL-09：netmap 按网络过滤——A 网条目不进 B 网快照
    #[test]
    fn netmap_isolated_per_network() {
        let (mut c, ak_a, ak_b) = two_networks();
        let a1 = register_node(&mut c, &ak_a, 1);
        let a2 = register_node(&mut c, &ak_a, 2);
        let b1 = register_node(&mut c, &ak_b, 3);
        let net_a = c.network_id_of(a1).unwrap();
        let net_b = c.network_id_of(b1).unwrap();
        assert_ne!(net_a, net_b);
        let snap_a = c.netmap_snapshot(net_a);
        assert_eq!(snap_a.len(), 2);
        assert!(snap_a.iter().all(|n| n.node_id == a1 || n.node_id == a2));
        let snap_b = c.netmap_snapshot(net_b);
        assert_eq!(snap_b.len(), 1);
        assert_eq!(snap_b[0].node_id, b1);
        // 条目 network_id 恒为本网络（联邦钩子语义）
        assert!(snap_a.iter().all(|n| n.network_id == net_a));
    }

    /// SEC-23：auth key 归域——A 网 key 进 B 网（网络名不存在/不匹配）→ 拒绝
    #[test]
    fn auth_key_scoped_to_network() {
        let (mut c, ak_a, _ak_b) = two_networks();
        // 网络不存在（key 内嵌未配置网络）→ 拒绝
        let err = c.register(&lrk("ghost", 86_400), &pubkey(9), 0x00, vec![]);
        assert!(matches!(err, Err(RegisterError::InvalidAuthKey)));
        // A 网 key 只能注册进 A 网（返回 A 的 network_id）
        let id = c.register(&ak_a, &pubkey(1), 0x00, vec![]).unwrap();
        assert_eq!(id.network_id, network_id_for("lab"));
        // 同 key 幂等：仍是 A 网
        let again = c.register(&ak_a, &pubkey(1), 0x00, vec![]).unwrap();
        assert_eq!(again.node_id, id.node_id);
        assert_eq!(again.network_id, network_id_for("lab"));
        // A 网 key 重复注册（不同 pubkey）进 B 网表不存在 → 仍是 A 网新节点
        let a2 = c.register(&ak_a, &pubkey(2), 0x00, vec![]).unwrap();
        assert_eq!(a2.network_id, network_id_for("lab"));
    }

    /// SEC-22：key_dst 按网络主密钥派生——A 网节点 key 与 B 网不同，跨网伪造必失配
    #[test]
    fn key_dst_isolated_per_network() {
        let (mut c, ak_a, ak_b) = two_networks();
        let a1 = register_node(&mut c, &ak_a, 1);
        let a2 = register_node(&mut c, &ak_a, 2);
        let b1 = register_node(&mut c, &ak_b, 3);
        let ka1 = c.key_dist(a1).unwrap();
        let ka2 = c.key_dist(a2).unwrap();
        let kb1 = c.key_dist(b1).unwrap();
        // 同网络同 node_id 语义：不同 node 不同 key（KDF(主密钥, node_id)）
        assert_ne!(ka1.key, ka2.key);
        // 跨网络即使 node_id 相同也不得同 key（主密钥独立）
        assert_ne!(ka1.key, kb1.key);
        // 广播密钥按网络独立
        let b2 = register_node(&mut c, &ak_b, 4);
        let kb2 = c.key_dist(b2).unwrap();
        assert_eq!(ka1.broadcast_key, ka2.broadcast_key);
        assert_eq!(kb1.broadcast_key, kb2.broadcast_key);
        assert_ne!(ka1.broadcast_key, kb1.broadcast_key);
    }

    /// SEC-25：前缀公告白名单按网络分域——A 网白名单不影响 B 网
    #[test]
    fn whitelist_isolated_per_network() {
        let ak_a = lrk("lab", 86_400);
        let ak_b = lrk("work", 86_400);
        let mut c = Coordinator::new([0x5a; 32]);
        c.add_network("lab", [0x77; 32]);
        c.add_network("work", [0x88; 32]);
        c.add_auth_key(&ak_a, AuthKeyPolicy::Reusable);
        c.add_auth_key(&ak_b, AuthKeyPolicy::Reusable);
        c.set_announce_whitelist("lab", vec![Prefix::parse("10.0.0.0/8").unwrap()]);
        c.set_announce_whitelist("work", vec![Prefix::parse("192.168.0.0/16").unwrap()]);
        // A 网：白名单外前缀拒绝
        let err = c.register(&ak_a, &pubkey(1), 0x00, vec!["192.168.1.0/24".into()]);
        assert!(matches!(err, Err(RegisterError::RouteNotAllowed)));
        // B 网：其白名单内的 192.168.1.0/24 正常接受（分域证明）
        let b1 = c.register(&ak_b, &pubkey(2), 0x00, vec!["192.168.1.0/24".into()]);
        assert!(b1.is_ok());
        // A 网节点无法公告 B 网白名单前缀（其白名单无此覆盖）
        let err = c.register(&ak_a, &pubkey(3), 0x00, vec!["192.168.2.0/24".into()]);
        assert!(matches!(err, Err(RegisterError::RouteNotAllowed)));
    }

    /// 跨网络路径请求被拒（fail-closed）：netmap 隔离下源看不到异网节点
    #[test]
    fn cross_network_path_request_rejected() {
        let (mut c, ak_a, ak_b) = two_networks();
        let a1 = register_node(&mut c, &ak_a, 1);
        let b1 = register_node(&mut c, &ak_b, 2);
        assert!(c.request_paths(a1, b1, 4).is_empty());
        // 同网正常
        let a2 = register_node(&mut c, &ak_a, 3);
        assert!(!c.request_paths(a1, a2, 4).is_empty());
    }

    /// 每网络独立 relay 集合：A 网 relay 不进 B 网路径候选
    #[test]
    fn relays_isolated_per_network() {
        let ak_a = lrk("lab", 86_400);
        let ak_b = lrk("work", 86_400);
        let mut c = Coordinator::new([0x5a; 32]);
        c.add_network("lab", [0x77; 32]);
        c.add_network("work", [0x88; 32]);
        c.add_auth_key(&ak_a, AuthKeyPolicy::Reusable);
        c.add_auth_key(&ak_b, AuthKeyPolicy::Reusable);
        // A 网 relay（capabilities 0x01）注册
        let r = c.register(&ak_a, &pubkey(1), 0x01, vec![]).unwrap().node_id;
        let a1 = c.register(&ak_a, &pubkey(2), 0x00, vec![]).unwrap().node_id;
        let a2 = c.register(&ak_a, &pubkey(3), 0x00, vec![]).unwrap().node_id;
        let b1 = c.register(&ak_b, &pubkey(4), 0x00, vec![]).unwrap().node_id;
        let b2 = c.register(&ak_b, &pubkey(5), 0x00, vec![]).unwrap().node_id;
        // A 网路径含 A relay
        let cands_a = c.request_paths(a1, a2, 4);
        assert!(cands_a.iter().any(|(p, _)| p.hops == vec![r, a2]));
        // B 网路径不含 A relay（relay 集合按网络独立）
        let cands_b = c.request_paths(b1, b2, 4);
        assert!(cands_b.iter().all(|(p, _)| !p.hops.contains(&r)));
        assert_eq!(cands_b.len(), 1); // 仅 direct（B 无 relay）
    }

    /// 跨网络 identity_binding 验签失败（SEC-24 核心断言；数据面握手跨网互拒见
    /// rill-core/src/handshake.rs prologue_mismatch_rejected 与 data.rs 线级测试）
    #[test]
    fn binding_not_verifiable_across_networks() {
        let (mut c, ak_a, ak_b) = two_networks();
        let a1 = c.register(&ak_a, &pubkey(1), 0x00, vec![]).unwrap();
        let b1 = c.register(&ak_b, &pubkey(2), 0x00, vec![]).unwrap();
        let verifier = c.verifier();
        // 各自绑定对各自节点有效（绑定消息构造 sanity：node_id || static_pubkey）
        let _binding =
            landscape_rill_core::control::registry::binding_message(a1.node_id, &pubkey(1));
        assert!(!_binding.is_empty());
        assert!(crate::signer::verify_binding(
            &verifier,
            a1.node_id,
            &pubkey(1),
            &a1.identity_binding
        ));
        assert!(crate::signer::verify_binding(
            &verifier,
            b1.node_id,
            &pubkey(2),
            &b1.identity_binding
        ));
        // A 网节点把 B 网绑定混入握手：B 节点身份配 A 绑定 → 验签失败
        assert!(!crate::signer::verify_binding(
            &verifier,
            b1.node_id,
            &pubkey(2),
            &a1.identity_binding
        ));
        // A 网绑定替换节点号/公钥任意字段 → 失败
        assert!(!crate::signer::verify_binding(
            &verifier,
            a1.node_id,
            &pubkey(3),
            &a1.identity_binding
        ));
        assert!(!crate::signer::verify_binding(
            &verifier,
            999,
            &pubkey(1),
            &a1.identity_binding
        ));
    }

    // ==================== 持久化（REQ-037） ====================

    #[test]
    fn expired_key_rejected_at_admission() {
        // REQ-043：过期内嵌 key，注册时（admission）拒绝；挑战恢复路径不受影响
        let now = unix_seconds();
        let expired = format!("lrk-lab-{}-{}", now - 1, "A".repeat(52));
        let mut c = Coordinator::new([0x5a; 32]);
        c.add_network("lab", [0x77; 32]);
        c.add_auth_key(&expired, AuthKeyPolicy::Reusable);
        assert!(c.has_auth_key(&expired)); // 过期 key 可配置（inert），admission 时拒绝
        let err = c.register(&expired, &pubkey(1), 0x00, vec![]);
        assert!(matches!(err, Err(RegisterError::InvalidAuthKey)));
        // 非 lrk 格式 → fail-closed 拒绝
        let mut c = Coordinator::new([0x5a; 32]);
        c.add_network("lab", [0x77; 32]);
        c.add_auth_key("opaque-key", AuthKeyPolicy::Reusable);
        assert!(!c.has_auth_key("opaque-key"));
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

    fn networks_arg() -> Vec<(String, [u8; 32])> {
        vec![("lab".to_string(), [0x77; 32])]
    }

    #[test]
    fn persist_roundtrip_restores_full_state() {
        let ak = lrk("lab", 86_400);

        let path = tmp_db("roundtrip");
        let mut c = Coordinator::open(&path, &networks_arg(), [0x5a; 32]).unwrap();
        c.add_auth_key(&ak, AuthKeyPolicy::Reusable);
        let a = c.register(&ak, &pubkey(1), 0x01, vec![]).unwrap().node_id;
        c.set_endpoints(a, vec!["203.0.113.1:41641".into()]);
        let b = c.register(&ak, &pubkey(2), 0x00, vec![]).unwrap().node_id;
        c.request_paths(a, b, 4);
        drop(c);

        let c = Coordinator::open(&path, &networks_arg(), [0x5a; 32]).unwrap();
        let net_a = c.network_id_of(a).unwrap();
        assert_eq!(c.netmap_version(), 3); // 注册 a + 端点 + 注册 b
        assert_eq!(c.key_version_for("lab"), 1);
        assert_eq!(c.netmap_snapshot(net_a).len(), 2);
        let mut snap = c.netmap_snapshot(net_a);
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
        let ak = lrk("lab", 86_400);

        let path = tmp_db("onetime");
        let mut c = Coordinator::open(&path, &networks_arg(), [0x5a; 32]).unwrap();
        c.add_auth_key(&ak, AuthKeyPolicy::OneTime);
        c.register(&ak, &pubkey(1), 0x00, vec![]).unwrap();
        assert!(!c.has_auth_key(&ak));
        drop(c);

        let mut c = Coordinator::open(&path, &networks_arg(), [0x5a; 32]).unwrap();
        assert!(!c.has_auth_key(&ak), "一次性 key 消费必须持久化");
        // 同 key 二次注册被拒（未知公钥 + 无有效 key）
        let err = c.register(&ak, &pubkey(2), 0x00, vec![]);
        assert!(matches!(err, Err(RegisterError::InvalidAuthKey)));
        drop(c);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn consumed_key_not_revived_by_reload() {
        let ak = lrk("lab", 86_400);

        // SIGHUP 重载（config 重新 apply）不复活已消费的一次性 key
        let path = tmp_db("reload");
        let mut c = Coordinator::open(&path, &networks_arg(), [0x5a; 32]).unwrap();
        c.add_auth_key(&ak, AuthKeyPolicy::OneTime);
        c.register(&ak, &pubkey(1), 0x00, vec![]).unwrap();
        drop(c);

        let mut c = Coordinator::open(&path, &networks_arg(), [0x5a; 32]).unwrap();
        c.add_auth_key(&ak, AuthKeyPolicy::OneTime);
        assert!(!c.has_auth_key(&ak), "重载不得复活已消费 key");
        drop(c);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn node_and_path_ids_monotonic_across_restart() {
        let ak = lrk("lab", 86_400);

        let path = tmp_db("ids");
        let mut c = Coordinator::open(&path, &networks_arg(), [0x5a; 32]).unwrap();
        c.add_auth_key(&ak, AuthKeyPolicy::Reusable);
        let a = c.register(&ak, &pubkey(1), 0x00, vec![]).unwrap().node_id;
        let b = c.register(&ak, &pubkey(2), 0x00, vec![]).unwrap().node_id;
        let paths = c.request_paths(a, b, 4);
        drop(c);

        // 重启后新节点不重用 node_id；新路径不重用 path_id
        // （auth key 为配置权威，重启后须重新 apply——模拟 from_config 的 apply_to）
        let mut c = Coordinator::open(&path, &networks_arg(), [0x5a; 32]).unwrap();
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
            let c = Coordinator::open(&path, &networks_arg(), [0x5a; 32]).unwrap();
            drop(c);
        }
        std::fs::write(&path, b"not a redb file at all").unwrap();
        assert!(Coordinator::open(&path, &networks_arg(), [0x5a; 32]).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn inconsistent_state_fails_closed() {
        let ak = lrk("lab", 86_400);

        // next_node_id 与节点表不一致 → 拒绝启动（不猜测重建）
        let path = tmp_db("inconsistent");
        {
            let mut c = Coordinator::open(&path, &networks_arg(), [0x5a; 32]).unwrap();
            c.add_auth_key(&ak, AuthKeyPolicy::Reusable);
            c.register(&ak, &pubkey(1), 0x00, vec![]).unwrap();
            drop(c);
        }
        // 篡改快照：把 next_node_id 改回 1（与已注册 node 1 冲突）
        let store = crate::store::CoordStore::open(&path).unwrap();
        let mut state = store.load().unwrap().unwrap();
        state.next_node_id = 1;
        store.save(&state).unwrap();
        assert!(Coordinator::open(&path, &networks_arg(), [0x5a; 32]).is_err());
        let _ = std::fs::remove_file(&path);
    }

    /// 多网络持久化：跨重启归域恢复（nodes/consumed/key_version/path 按网络分组）
    #[test]
    fn persist_roundtrip_two_networks() {
        let ak_a = lrk("lab", 86_400);
        let ak_b = lrk("work", 86_400);

        let path = tmp_db("twonet");
        {
            let mut c = Coordinator::open(&path, &two_networks_arg(), [0x5a; 32]).unwrap();
            c.add_auth_key(&ak_a, AuthKeyPolicy::Reusable);
            c.add_auth_key(&ak_b, AuthKeyPolicy::Reusable);
            let a1 = c.register(&ak_a, &pubkey(1), 0x00, vec![]).unwrap();
            let b1 = c.register(&ak_b, &pubkey(2), 0x00, vec![]).unwrap();
            c.rotate_master_key("lab", [0x99; 32]);
            drop(a1);
            drop(b1);
        }
        let c = Coordinator::open(&path, &two_networks_arg(), [0x5a; 32]).unwrap();
        let net_a = c.network_id_of(1).unwrap();
        let net_b = c.network_id_of(2).unwrap();
        assert_ne!(net_a, net_b);
        // 每网络恢复自己的条目
        assert_eq!(c.netmap_snapshot(net_a).len(), 1);
        assert_eq!(c.netmap_snapshot(net_b).len(), 1);
        // 每网络独立 key 版本：lab 轮换过（v2），work 未动（v1）
        assert_eq!(c.key_version_for("lab"), 2);
        assert_eq!(c.key_version_for("work"), 1);
        drop(c);
        let _ = std::fs::remove_file(&path);
    }

    fn two_networks_arg() -> Vec<(String, [u8; 32])> {
        vec![
            ("lab".to_string(), [0x77; 32]),
            ("work".to_string(), [0x88; 32]),
        ]
    }
}
