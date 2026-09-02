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
/// 能力位：broadcast（L2 广播/组播泛洪 opt-in，CONTROL_PLANE §3.1 / FRAME_HEADER §2.6）
pub const CAPABILITY_BROADCAST: u32 = 0x20;

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
    /// 按需下发（REQ-035）：仅接收节点能力位含 broadcast 时携带
    pub broadcast_key: Option<[u8; KEY_DST_LEN]>,
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

    /// keydist（CONTROL_PLANE §3.3）：broadcast_key 按接收节点能力位按需下发（REQ-035）
    pub fn key_dist(&self, node_id: u32) -> Option<KeyDistData> {
        let domain = self.domain_of_node(node_id)?;
        let capabilities = domain.registry.entry(node_id)?.capabilities;
        Some(KeyDistData {
            to_node_id: node_id,
            key: domain.keys.key_for(node_id),
            key_version: domain.keys.version(),
            broadcast_key: (capabilities & CAPABILITY_BROADCAST != 0)
                .then(|| domain.keys.broadcast_key()),
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

    /// relay 探测目标（CONNECTIVITY §5：可达性验证 + RTT 测量）：某网络
    /// relay 能力节点及其已上报端点。返回 (node_id, endpoints)。
    pub fn relay_probe_targets(&self, network_id: u32) -> Vec<(u32, Vec<String>)> {
        let Some(domain) = self.domain_by_network_id(network_id) else {
            return Vec::new();
        };
        domain
            .registry
            .entries()
            .filter(|e| e.capabilities & CAPABILITY_RELAY != 0)
            .map(|e| (e.node_id, self.directory.endpoints_of(e.node_id).to_vec()))
            .collect()
    }

    /// RTT 排序结果落位（按网络分域）：PathService relay 集合按实测 RTT 排序
    /// （路径候选顺序 = 挂靠优先级，CONNECTIVITY §5）；relay_list 由 set_relay_list 落位
    pub fn set_relay_order(&mut self, network: &str, ordered_node_ids: Vec<u32>) {
        if let Some(domain) = self.domain_by_name_mut(network) {
            domain.paths.set_relays(ordered_node_ids);
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

    /// 身份绑定签名（REQ-057：挑战通过后补发 REGISTER_RESPONSE 用）
    pub fn identity_binding_of(&self, node_id: u32) -> Option<Vec<u8>> {
        self.domain_of_node(node_id)
            .and_then(|d| d.registry.entry(node_id))
            .map(|e| e.identity_binding.clone())
    }

    /// auth key 只读校验（REQ-060 新建类挑战前置）：格式/过期/归域/注册表存在；
    /// 不消费——消费只发生在 PoP 通过后的注册准入
    pub fn auth_key_admissible(&self, auth_key: &str) -> bool {
        let Ok(parsed) = crate::authkey::parse_auth_key(auth_key) else {
            return false;
        };
        if parsed.1 != 0 && unix_seconds() > parsed.1 {
            return false;
        }
        self.domains
            .iter()
            .any(|d| d.name == parsed.0 && d.registry.contains_auth_key(auth_key))
    }

    /// 恢复类幂等比对（REQ-060，PoP 之后调用）：REGISTER 的 capabilities/routes
    /// 与存储条目一致才允许按原身份恢复；不一致 = 注册信息变更，拒绝
    pub fn resume_matches(&self, node_id: u32, capabilities: u32, routes: &[String]) -> bool {
        self.domain_of_node(node_id)
            .and_then(|d| d.registry.entry(node_id))
            .map(|e| e.capabilities == capabilities && e.routes == routes)
            .unwrap_or(false)
    }

    pub fn verifier(&self) -> ed25519_dalek::VerifyingKey {
        self.signer.verifier()
    }
}

#[cfg(test)]
mod tests;
