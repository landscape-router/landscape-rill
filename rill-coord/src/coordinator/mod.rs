//! coordinator 权威角色门面（CONTROL_PLANE）
//!
//! 域拆分（子结构提取，2026-09-01）：registry（admission，rill-core）/ signer /
//! [liveness]（活性）/ [directory]（目录）/ [keys]（密钥）/ [path_service]（路径）/
//! [store]（持久化）。本文件只做**跨域编排**（register/revoke/netmap_snapshot/
//! relay roster）与持久化 glue（snapshot/restore/persist）；单域逻辑在各域文件。
//! 多网络隔离（CONTROL_PLANE §1.5，2026-09-01）：每网络一个 [domain](crate::domain::
//! NetworkDomain)（registry/主密钥/路径/relay roster 独立）；node_id 全局唯一分配。

use crate::directory::Directory;
use crate::domain::{network_id_for, NetworkDomain};
use crate::liveness::Liveness;
use crate::path_service::{PathCandidate, PathEvent, PathSet};
use crate::signer::Ed25519Signer;
use crate::status::TelemetryView;
use crate::store::{CoordState, CoordStore, StoreError, STATE_SCHEMA};
use landscape_rill_core::control::acl::AclPolicy;
use landscape_rill_core::control::registry::{
    AuthKeyPolicy, AuthKeySpec, NodeEntry, RegisterError, RegisterOutcome,
};
use landscape_rill_core::crypto::KEY_DST_LEN;
use landscape_rill_core::error::format_chain;
use landscape_rill_core::route::Prefix;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::collections::HashSet;
use std::path::Path;
use tracing::{error, info, warn};

/// 能力位：relay（自愿中继，CONNECTIVITY §5 / CONTROL_PLANE §3.1）
pub const CAPABILITY_RELAY: u32 = 0x01;
/// 能力位：broadcast（L2 广播/组播泛洪 opt-in，CONTROL_PLANE §3.1 / FRAME_HEADER §2.6）
pub const CAPABILITY_BROADCAST: u32 = 0x20;
/// 吊销合并轮换窗口（REQ-048，CONTROL_PLANE §5.5）：窗口内多次吊销共享一次全网轮换
pub const REVOKE_ROTATION_WINDOW_SECS: u64 = 60;
pub use landscape_rill_core::control::acl::CAPABILITY_ACL;

fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterData {
    pub node_id: u32,
    pub network_id: u32,
    pub identity_binding: Vec<u8>,
    /// 签发日志锚点 (log_index, term)（binding v2，REQ-049②）；单机直连 = (0, 0)
    pub binding_log_id: (u64, u64),
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
    /// 身份绑定签名 + 签发锚点（REQ-049②）：随 netmap 下发供交叉审计
    pub identity_binding: Vec<u8>,
    pub binding_log_id: (u64, u64),
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
    /// 节点遥测快照（REQ-052/CONTROL_PLANE §3.15）：latest-wins，软状态不落盘
    telemetry: HashMap<u32, TelemetryView>,
    /// 注册拒绝累计（REQ-051 安全计数器，§3.14 内容组 4）
    register_rejects: u64,
    /// 吊销墓碑 node_id → (log_index, term)（REQ-049②）：registry 吊销即删条目，
    /// 墓碑保留"吊销于哪个日志位置"，审计时不把已吊销节点的旧绑定误判 conflict
    revoked: HashMap<u32, (u64, u64)>,
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
            telemetry: HashMap::new(),
            register_rejects: 0,
            revoked: HashMap::new(),
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

    fn domain_by_network_id_mut(&mut self, network_id: u32) -> Option<&mut NetworkDomain> {
        self.domains.iter_mut().find(|d| d.network_id == network_id)
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

    /// 恢复持久状态（语义校验 fail-closed：不猜测重建）
    pub(crate) fn restore_state(&mut self, state: &CoordState) -> Result<(), StoreError> {
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
            if let Some((_, roster)) = state
                .relay_rosters
                .iter()
                .find(|(id, _)| *id == domain.network_id)
            {
                // roster 恢复 + PathService relay 集同步（REQ-062：单一落位入口语义）
                domain.apply_roster(roster.clone());
            }
            if let Some((_, deadline)) = state
                .pending_revoke_rotations
                .iter()
                .find(|(id, _)| *id == domain.network_id)
            {
                domain.keys.restore_revoke_rotation(*deadline);
            }
        }
        self.directory.restore(
            state.netmap_version,
            state
                .endpoints
                .iter()
                .cloned()
                .map(|(id, local, seen)| (id, crate::directory::NodeEndpoints { local, seen }))
                .collect(),
        );
        self.revoked = state
            .revoked_nodes
            .iter()
            .map(|(id, index, term)| (*id, (*index, *term)))
            .collect();
        Ok(())
    }

    /// 持久状态快照（确定性排序）
    pub(crate) fn snapshot(&self) -> CoordState {
        let mut nodes: Vec<NodeEntry> = self
            .domains
            .iter()
            .flat_map(|d| d.registry.entries().cloned())
            .collect();
        nodes.sort_by_key(|n| n.node_id);
        let mut endpoints: Vec<(u32, Vec<String>, Vec<String>)> = self
            .directory
            .endpoints_all()
            .iter()
            .map(|(k, v)| (*k, v.local.clone(), v.seen.clone()))
            .collect();
        endpoints.sort_by_key(|(k, _, _)| *k);
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
        let mut relay_rosters: Vec<(u32, Vec<u32>)> = self
            .domains
            .iter()
            .map(|d| (d.network_id, d.roster.clone()))
            .collect();
        relay_rosters.sort_by_key(|(id, _)| *id);
        let mut pending_revoke_rotations: Vec<(u32, u64)> = self
            .domains
            .iter()
            .filter_map(|d| {
                d.keys
                    .pending_revoke_rotation()
                    .map(|deadline| (d.network_id, deadline))
            })
            .collect();
        pending_revoke_rotations.sort_by_key(|(id, _)| *id);
        let mut consumed: Vec<String> = self
            .domains
            .iter()
            .flat_map(|d| d.registry.consumed_one_time_keys().iter().cloned())
            .collect();
        consumed.sort();
        let mut revoked_nodes: Vec<(u32, u64, u64)> = self
            .revoked
            .iter()
            .map(|(id, (index, term))| (*id, *index, *term))
            .collect();
        revoked_nodes.sort_unstable();
        CoordState {
            schema: STATE_SCHEMA,
            next_node_id: self.next_node_id,
            nodes,
            consumed_one_time_keys: consumed,
            netmap_version: self.directory.netmap_version(),
            key_versions,
            endpoints,
            path_maps,
            relay_rosters,
            pending_revoke_rotations,
            revoked_nodes,
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

    /// 构建版本（REQ-052）：可选元数据，仅状态端点展示
    pub fn set_build_version(&mut self, node_id: u32, version: String) {
        self.directory.set_build_version(node_id, version);
    }

    pub fn build_version(&self, node_id: u32) -> Option<&str> {
        self.directory.build_version(node_id)
    }

    /// 遥测快照入库（REQ-052/CONTROL_PLANE §3.15）：latest-wins，直接覆盖旧值；
    /// updated_at 由 coordinator 侧打点（不信任节点时钟）
    pub fn store_telemetry(&mut self, node_id: u32, mut view: TelemetryView) {
        view.updated_at = unix_seconds();
        self.telemetry.insert(node_id, view);
    }

    /// 全量遥测快照（状态端点 §3.14 观察面）：node_id 升序，输出确定
    pub fn telemetry_all(&self) -> Vec<(u32, &TelemetryView)> {
        let mut v: Vec<(u32, &TelemetryView)> =
            self.telemetry.iter().map(|(k, t)| (*k, t)).collect();
        v.sort_by_key(|(id, _)| *id);
        v
    }

    /// 注册拒绝累计（§3.14 内容组 4）
    pub fn register_rejects(&self) -> u64 {
        self.register_rejects
    }

    /// 网络名列表（§3.14 内容组 1；插入序 = 配置序）
    pub fn network_names(&self) -> Vec<String> {
        self.domains.iter().map(|d| d.name.clone()).collect()
    }

    /// auth key 台账条目（§3.14 内容组 3）：key + 规格；调用方做脱敏/剩余有效期
    pub fn auth_key_specs_for(&self, network: &str) -> Vec<(String, AuthKeySpec)> {
        self.domain_by_name(network)
            .map(|d| d.registry.auth_key_specs().collect())
            .unwrap_or_default()
    }

    /// 已消费一次性 key tombstone（§3.14 内容组 3）
    pub fn consumed_one_time_keys_for(&self, network: &str) -> Vec<String> {
        self.domain_by_name(network)
            .map(|d| d.registry.consumed_one_time_keys().to_vec())
            .unwrap_or_default()
    }

    /// 节点 last_seen（unix 秒；None = 从未见/重启后未知）
    pub fn last_seen_of(&self, node_id: u32) -> Option<u64> {
        self.liveness.last_seen_of(node_id)
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

    /// ACL 策略（REQ-045，CONTROL_PLANE §3.10）：按网络分域设置；
    /// 变更 bump netmap 版本（策略随 netmap 原子下发，version 一版本两用，
    /// 节点侧下一心跳快照即收敛）
    pub fn set_acl_policy(&mut self, network: &str, policy: AclPolicy) {
        if let Some(domain) = self.domain_by_name_mut(network) {
            domain.acl = policy;
            self.directory.bump_netmap();
        }
    }

    /// 按网络号取 ACL 策略（netmap 装配用）
    pub fn acl_policy_of(&self, network_id: u32) -> AclPolicy {
        self.domains
            .iter()
            .find(|d| d.network_id == network_id)
            .map(|d| d.acl.clone())
            .unwrap_or_default()
    }

    // ==================== 注册 / 密钥下发 ====================

    pub fn register(
        &mut self,
        auth_key: &str,
        static_pubkey: &[u8; 32],
        capabilities: u32,
        routes: Vec<String>,
        now: u64,
        issuance: (u64, u64),
    ) -> Result<RegisterData, RegisterError> {
        // 注册拒绝计数（REQ-051 §3.14 内容组 4）：任何 Err 路径收口统计
        let r = self.register_inner(auth_key, static_pubkey, capabilities, routes, now, issuance);
        if r.is_err() {
            self.register_rejects = self.register_rejects.saturating_add(1);
        }
        r
    }

    fn register_inner(
        &mut self,
        auth_key: &str,
        static_pubkey: &[u8; 32],
        capabilities: u32,
        routes: Vec<String>,
        now: u64,
        issuance: (u64, u64),
    ) -> Result<RegisterData, RegisterError> {
        // 过期时间内嵌在 key 自身（REQ-043）：admission 时解析校验；
        // 解析失败 = 非法 key（fail-closed）。格式知识在 rill-coord，注册表按不透明字符串处理。
        let parsed =
            crate::authkey::parse_auth_key(auth_key).map_err(|_| RegisterError::InvalidAuthKey)?;
        if parsed.1 != 0 && now > parsed.1 {
            return Err(RegisterError::InvalidAuthKey);
        }
        // 归域（CONTROL_PLANE §1.5）：注册即归域——key 内嵌网络必须存在，只可能进入该网络
        if !self.domains.iter().any(|d| d.name == parsed.0) {
            return Err(RegisterError::InvalidAuthKey);
        }
        // ACL fail-closed（REQ-045）：网络开启策略后，无 acl 能力位的节点拒绝注册
        // （防最弱环节绕过目标侧裁决；幂等重注册同受约束——能力位是注册字段）
        if let Some(domain) = self.domains.iter().find(|d| d.name == parsed.0) {
            if domain.acl.enabled && capabilities & CAPABILITY_ACL == 0 {
                return Err(RegisterError::AclCapabilityRequired);
            }
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
                issuance,
                signer,
            )
        };
        let node_id = match outcome {
            Ok(RegisterOutcome::NewNode(id)) => {
                self.next_node_id += 1;
                self.directory.bump_netmap();
                // REQ-062：注册不再自动进 relay 集——能力位只是必要条件，
                // 选用须走 roster 提案/落位（公网准入 + RTT 健康 + 名额）
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
            binding_log_id: entry.binding_log_id,
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

    pub fn set_endpoints(&mut self, node_id: u32, local: Vec<String>, seen: Vec<String>) {
        self.directory.set_endpoints(node_id, local, seen);
        self.persist();
    }

    // ==================== 路径服务（v1.5，CONTROL_PLANE §3.11） ====================

    /// PathRequest 处理：构造候选路径集（直连 + 经 relay），返回 (候选, key_path)。
    /// now 显式传入（REQ-070：raft 重放确定性；TTL 以此计）
    /// 跨网络路径请求 → 空集（fail-closed：netmap 隔离下源本就看不到异网节点）。
    pub fn request_paths(
        &mut self,
        source: u32,
        dest: u32,
        max: u32,
        now: u64,
    ) -> Vec<(PathCandidate, [u8; KEY_DST_LEN])> {
        let (Some(sd), Some(dd)) = (self.domain_of_node(source), self.domain_of_node(dest)) else {
            return Vec::new();
        };
        if sd.network_id != dd.network_id {
            return Vec::new();
        }
        let network_id = sd.network_id;
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

    // ==================== relay roster（REQ-062，CONNECTIVITY §5） ====================

    /// roster 硬约束落位（SIGHUP/apply_to；配置权威，不触发重算——提案在 RTT 轮/重载入口）
    pub fn set_relay_constraints(&mut self, network: &str, cfg: crate::config::RelayRosterConfig) {
        if let Some(domain) = self.domain_by_name_mut(network) {
            domain.relay_cfg = cfg;
        }
    }

    /// 最近一轮 RTT 结果（leader 视角软状态，不落盘）：Some = 命中（miss 清零），
    /// None = 未响应（miss+1，进入退出滞回计数）。只喂提案输入，不改 roster
    pub fn record_relay_rtt_round(&mut self, network_id: u32, results: &[(u32, Option<u64>)]) {
        let Some(domain) = self.domain_by_network_id_mut(network_id) else {
            return;
        };
        for &(node, rtt) in results {
            match rtt {
                Some(ms) => {
                    domain.relay_rtt.insert(node, ms);
                    domain.relay_miss.insert(node, 0);
                }
                None => {
                    let miss = domain.relay_miss.get(&node).copied().unwrap_or(0) + 1;
                    domain.relay_miss.insert(node, miss);
                }
            }
        }
    }

    /// roster 提案（模式 C 自动策划，纯函数不动状态）：
    /// 能力位（必要）∩ ¬exclude ∩ 在线 ∩（公网准入 ∨ include 兜底）∧
    /// 已测得 RTT（新注册不自动进）∧ 连续 miss < 退出阈值（滞回防名单抖动）；
    /// RTT 升序截 max_size（include 追加不计名额——硬约束 > 软上限）。
    /// 输入含 leader 本地软状态（liveness/RTT/端点）——落位经 apply_relay_roster
    /// 过日志，副本重放确定性不受影响
    pub fn propose_relay_roster(&self, network_id: u32) -> Vec<u32> {
        let Some(domain) = self.domain_by_network_id(network_id) else {
            return Vec::new();
        };
        let cfg = &domain.relay_cfg;
        let eligible = |e: &NodeEntry| {
            e.capabilities & CAPABILITY_RELAY != 0
                && !cfg.exclude.contains(&e.node_id)
                && !self.liveness.is_offline(e.node_id)
        };
        let rtt_of = |node: u32| domain.relay_rtt.get(&node).copied().unwrap_or(u64::MAX);
        let measured_healthy = |node: u32| {
            domain.relay_rtt.contains_key(&node)
                && domain.relay_miss.get(&node).copied().unwrap_or(0)
                    < crate::domain::RELAY_EXIT_MISS_ROUNDS
        };
        // 自动策划：公网准入 + 已测得 + 健康
        let mut auto: Vec<u32> = domain
            .registry
            .entries()
            .filter(|e| eligible(e))
            .filter(|e| self.directory.public_direct(e.node_id) && measured_healthy(e.node_id))
            .map(|e| e.node_id)
            .collect();
        auto.sort_by_key(|&n| (rtt_of(n), n));
        auto.truncate(cfg.max_size);
        // include 兜底：公网判定失败（NAT 后/1:1 NAT）仍强制纳入；不占自动名额
        let mut roster = auto;
        for e in domain.registry.entries().filter(|e| eligible(e)) {
            if cfg.include.contains(&e.node_id)
                && !roster.contains(&e.node_id)
                && measured_healthy(e.node_id)
            {
                roster.push(e.node_id);
            }
        }
        roster.sort_by_key(|&n| (rtt_of(n), n));
        roster
    }

    /// roster 落位（apply 侧唯一入口；raft 过日志的确定性重放）。
    /// 移出的 relay → 中继角色路径撤销（全参与者事件）；新增 relay → 既有
    /// 路径集补员（幂等命中的集不会自愈，须显式扩充）；集合变化才 bump netmap
    /// （顺序变化不 bump——路径候选序经服务端请求即时生效，netmap 侧懒传播）
    pub fn apply_relay_roster(&mut self, network_id: u32, roster: Vec<u32>, now: u64) -> bool {
        let Some(domain) = self.domain_by_network_id_mut(network_id) else {
            return false;
        };
        let dropped: Vec<u32> = domain
            .roster
            .iter()
            .filter(|r| !roster.contains(r))
            .copied()
            .collect();
        let changed = domain.apply_roster(roster);
        for node in dropped {
            domain.paths.withdraw_relay(node);
        }
        domain.paths.expand_relay_candidates(now);
        let name = domain.name.clone();
        let roster_now = domain.roster.clone();
        if changed {
            self.directory.bump_netmap();
        }
        self.persist();
        info!(
            "[coord] relay roster applied: network={} changed={} roster={:?}",
            name, changed, roster_now
        );
        changed
    }

    /// 激活 relay roster（netmap/状态端点用；顺序 = 挂靠优先级）
    pub fn relay_roster_for(&self, network_id: u32) -> &[u32] {
        self.domain_by_network_id(network_id)
            .map(|d| d.roster.as_slice())
            .unwrap_or(&[])
    }

    /// relay 探测目标（CONNECTIVITY §5：可达性验证 + RTT 测量）：relay 能力
    /// 节点（exclude 剔除——roster 恒不可入，探测无意义）及其已上报端点
    pub fn relay_probe_targets(&self, network_id: u32) -> Vec<(u32, Vec<String>)> {
        let Some(domain) = self.domain_by_network_id(network_id) else {
            return Vec::new();
        };
        domain
            .registry
            .entries()
            .filter(|e| e.capabilities & CAPABILITY_RELAY != 0)
            .filter(|e| !domain.relay_cfg.exclude.contains(&e.node_id))
            .map(|e| (e.node_id, self.directory.merged_endpoints_of(e.node_id)))
            .collect()
    }

    /// 节点合并端点（本地 ++ seen；状态端点展示用）
    pub fn node_endpoints_merged(&self, node_id: u32) -> Vec<String> {
        self.directory.merged_endpoints_of(node_id)
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
                endpoints: self.directory.merged_endpoints_of(e.node_id),
                offline: self.liveness.is_offline(e.node_id),
                protocol_version: self.directory.protocol_version(e.node_id),
                // 绑定随 netmap 下发（REQ-049②）：节点可对 netmap 条目与握手对端做交叉审计
                identity_binding: e.identity_binding.clone(),
                binding_log_id: e.binding_log_id,
            })
            .collect()
    }

    pub fn netmap_version(&self) -> u64 {
        self.directory.netmap_version()
    }

    pub fn heartbeat(&mut self, node_id: u32, now: u64) -> bool {
        // 吊销合并轮换到期评估（REQ-048）：先于快照推送——本周期推送即带新版本
        self.flush_revoke_rotations(now);
        // 离线扫描（CTL-11）：挂在本调用（每次心跳/注册完成处理）上——事件驱动，
        // 无后台任务。租约超时者标记离线、恢复者清除，转移发生即递增 netmap
        // 版本（下一次心跳推送即携带撤销/恢复后的路由）。返回是否发生该节点的
        // 离线 → 在线恢复转移
        let was_offline = self.liveness.is_offline(node_id);
        self.liveness.heartbeat(node_id, now);
        let newly_offline = self.liveness.sweep(now);
        let transitioned = was_offline || !newly_offline.is_empty();
        if transitioned {
            self.directory.bump_netmap();
        }
        was_offline
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

    /// 领导权接管时重置活性软状态（REQ-070 阶段二，§5.2）：last_seen/offline
    /// 只在处理心跳的副本本地维护（不进 raft 日志），新主继承的是旧主时代的
    /// 陈旧快照——直接沿用会把在线节点立即扫成离线（netmap 撤路由 → 数据面
    /// 断流，违背 §4.3 failover 期间数据面不中断）。接管 = 给全体已知节点一份
    /// 新租约；接管后静默超过一个租约窗口的节点由 sweep 重新判离线
    pub fn reset_liveness_on_takeover(&mut self, now: u64) {
        for entry in self.domains.iter().flat_map(|d| d.registry.entries()) {
            self.liveness.heartbeat(entry.node_id, now);
        }
        self.directory.bump_netmap();
    }

    pub fn offline_nodes(&self) -> &[u32] {
        self.liveness.offline_nodes()
    }

    pub fn revoke(&mut self, node_id: u32, now: u64, log_id: (u64, u64)) {
        self.flush_revoke_rotations(now);
        let revoked = self
            .domains
            .iter_mut()
            .find(|d| d.registry.entry(node_id).is_some())
            .map(|d| {
                d.registry.revoke(node_id);
                self.liveness.remove(node_id);
                self.directory.remove_node(node_id);
                self.telemetry.remove(&node_id);
                // 路径联动：撤销所有涉及该节点的路径（源/目的/中继）
                d.paths.withdraw_node(node_id);
                // roster 联动（REQ-062）：吊销节点移出 roster（registry/roster 皆
                // raft 态，apply 侧确定性收口）；PathService relay 集同步
                if d.roster.contains(&node_id) {
                    d.roster.retain(|r| *r != node_id);
                    d.paths.set_relays(d.roster.clone());
                }
                // REQ-048：吊销即时语义不变（移除/Withdraw/netmap 即时），
                // 轮换进合并窗口，批次末一次生效
                d.keys
                    .arm_revoke_rotation(now + REVOKE_ROTATION_WINDOW_SECS);
                self.directory.bump_netmap();
            })
            .is_some();
        if revoked {
            // 吊销墓碑（REQ-049②）：跨域全局 node_id 键控
            self.revoked.insert(node_id, log_id);
            self.persist();
        }
    }

    /// 到期的吊销合并轮换统一生效（REQ-048，CONTROL_PLANE §5.5）。评估点 =
    /// 事件驱动（心跳/注册后心跳/吊销入口），与租约扫描同模式，无后台任务。
    pub fn flush_revoke_rotations(&mut self, now: u64) -> bool {
        let mut rotated = false;
        for d in &mut self.domains {
            if d.keys.take_revoke_rotation(now) {
                info!(
                    "[coord] revoke batch rotation applied: network={} key_version={}",
                    d.name,
                    d.keys.version()
                );
                rotated = true;
            }
        }
        if rotated {
            self.persist();
        }
        rotated
    }

    /// 主密钥轮换（按网络；SIGHUP/管理面入口）。REQ-048：显式轮换立即生效，
    /// 并吸收挂起的合并窗口（轮换已发生，批次不再额外 bump）
    pub fn rotate_master_key(&mut self, network: &str, new_master_key: [u8; 32]) {
        if let Some(domain) = self.domain_by_name_mut(network) {
            domain.keys.rotate(new_master_key);
            domain.keys.clear_revoke_rotation();
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

    /// 签发日志锚点（binding v2，REQ-049②）
    pub fn binding_log_id_of(&self, node_id: u32) -> Option<(u64, u64)> {
        self.domain_of_node(node_id)
            .and_then(|d| d.registry.entry(node_id))
            .map(|e| e.binding_log_id)
    }

    /// 注册表条目只读视图（审计读取：公钥/绑定/锚点三元组，REQ-049②）
    pub fn node_entry(
        &self,
        node_id: u32,
    ) -> Option<&landscape_rill_core::control::registry::NodeEntry> {
        self.domain_of_node(node_id)
            .and_then(|d| d.registry.entry(node_id))
    }

    /// 吊销墓碑（REQ-049②）：node_id → 吊销日志位置
    pub fn revocation_of(&self, node_id: u32) -> Option<(u64, u64)> {
        self.revoked.get(&node_id).copied()
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
