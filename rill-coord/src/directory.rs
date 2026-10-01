//! 节点目录域：端点表/netmap 版本/协议版本（CONTROL_PLANE §3.1/§3.2）
//!
//! endpoints/protocol_versions 为持久类（REQ-037 整快照落盘）；
//! netmap_version 为变更序号（节点注册/端点变更时递增，全量下发去重依据）。
//! 端点分列存储（REQ-062）：本地接口地址 + echo 回显 seen 地址——
//! 公网准入判定（seen ∈ 本地 = 直连公网）用，netmap 下发合并展示。

use std::collections::HashMap;

#[derive(Debug, Default, Clone)]
pub struct NodeEndpoints {
    /// 本地接口地址（节点自报，准入判定基准）
    pub local: Vec<String>,
    /// echo 回显地址（coordinator 视角观察值）
    pub seen: Vec<String>,
}

impl NodeEndpoints {
    /// netmap 下发用合并视图（本地 ++ seen 去重，保序）
    pub fn merged(&self) -> Vec<String> {
        let mut out = self.local.clone();
        for s in &self.seen {
            if !out.contains(s) {
                out.push(s.clone());
            }
        }
        out
    }
}

#[derive(Debug, Default)]
pub struct Directory {
    netmap_version: u64,
    endpoints: HashMap<u32, NodeEndpoints>,
    protocol_versions: HashMap<u32, u32>,
    /// 构建版本元数据（REQ-052/CONTROL_PLANE §3.1）：仅展示用，不参与协商
    build_versions: HashMap<u32, String>,
}

impl Directory {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn netmap_version(&self) -> u64 {
        self.netmap_version
    }

    pub fn bump_netmap(&mut self) {
        self.netmap_version += 1;
    }

    pub fn set_endpoints(&mut self, node_id: u32, local: Vec<String>, seen: Vec<String>) {
        self.endpoints
            .insert(node_id, NodeEndpoints { local, seen });
        self.bump_netmap();
    }

    /// netmap 条目端点（合并视图：本地 ++ seen 去重；对端按可达性选用）
    pub fn merged_endpoints_of(&self, node_id: u32) -> Vec<String> {
        self.endpoints
            .get(&node_id)
            .map(NodeEndpoints::merged)
            .unwrap_or_default()
    }

    /// 分列端点（准入判定/持久化用）
    pub fn node_endpoints(&self, node_id: u32) -> Option<&NodeEndpoints> {
        self.endpoints.get(&node_id)
    }

    /// 公网准入判定（REQ-062）：echo seen 地址 ∈ 本地接口地址集合 → 直连公网；
    /// 无 seen 记录（未做 echo/TCP 档）或不相交（NAT 后）→ false
    pub fn public_direct(&self, node_id: u32) -> bool {
        let Some(e) = self.endpoints.get(&node_id) else {
            return false;
        };
        let local_ips: Vec<&str> = e
            .local
            .iter()
            .map(|s| s.rsplit_once(':').map(|(ip, _)| ip).unwrap_or(s))
            .collect();
        e.seen.iter().any(|s| {
            let ip = s.rsplit_once(':').map(|(ip, _)| ip).unwrap_or(s);
            local_ips.contains(&ip)
        })
    }

    /// 恢复持久化快照（REQ-037）：版本与端点表（不递增版本）
    pub fn restore(&mut self, netmap_version: u64, endpoints: HashMap<u32, NodeEndpoints>) {
        self.netmap_version = netmap_version;
        self.endpoints = endpoints;
    }

    pub fn endpoints_all(&self) -> &HashMap<u32, NodeEndpoints> {
        &self.endpoints
    }

    pub fn set_protocol_version(&mut self, node_id: u32, version: u32) {
        self.protocol_versions.insert(node_id, version);
    }

    /// 节点协议版本（v2 路径能力协商；v1 节点恒 1）
    pub fn protocol_version(&self, node_id: u32) -> u32 {
        self.protocol_versions.get(&node_id).copied().unwrap_or(1)
    }

    /// 构建版本（REQ-052，可选元数据；仅状态端点展示）
    pub fn set_build_version(&mut self, node_id: u32, version: String) {
        self.build_versions.insert(node_id, version);
    }

    pub fn build_version(&self, node_id: u32) -> Option<&str> {
        self.build_versions.get(&node_id).map(|v| v.as_str())
    }

    /// 节点吊销/移除时清理目录状态（netmap 版本递增由调用方编排）
    pub fn remove_node(&mut self, node_id: u32) {
        self.endpoints.remove(&node_id);
        self.protocol_versions.remove(&node_id);
        self.build_versions.remove(&node_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_enter_directory_with_bump() {
        let mut d = Directory::new();
        let v0 = d.netmap_version();
        d.set_endpoints(1, vec!["203.0.113.1:41641".into()], vec![]);
        assert_eq!(d.netmap_version(), v0 + 1);
        let e = d.node_endpoints(1).unwrap();
        assert_eq!(e.local, &["203.0.113.1:41641"]);
        assert_eq!(e.merged(), vec!["203.0.113.1:41641"]);
        assert!(d.node_endpoints(99).is_none());
        d.remove_node(1);
        assert!(d.node_endpoints(1).is_none());
    }

    /// 公网准入判定（REQ-062 验收 ②）：seen ∈ 本地 → 直连公网；NAT 后 → 排除
    #[test]
    fn public_admission_by_seen_in_local() {
        let mut d = Directory::new();
        // 直连公网：seen 与本地接口同 IP
        d.set_endpoints(
            1,
            vec!["203.0.113.1:41641".into()],
            vec!["203.0.113.1:41641".into()],
        );
        assert!(d.public_direct(1));
        // NAT 后：本地私网地址，seen 为映射公网地址
        d.set_endpoints(
            2,
            vec!["192.168.1.5:41641".into()],
            vec!["198.51.100.7:52010".into()],
        );
        assert!(!d.public_direct(2));
        // 未做 echo（无 seen 记录）→ 无法证明直连公网
        d.set_endpoints(3, vec!["203.0.113.3:41641".into()], vec![]);
        assert!(!d.public_direct(3));
        // 无记录
        assert!(!d.public_direct(99));
    }

    #[test]
    fn merged_view_dedups_local_plus_seen() {
        let mut d = Directory::new();
        d.set_endpoints(
            1,
            vec!["10.0.0.1:5000".into(), "192.168.1.5:5000".into()],
            vec!["203.0.113.9:5000".into(), "10.0.0.1:5000".into()],
        );
        assert_eq!(
            d.node_endpoints(1).unwrap().merged(),
            vec!["10.0.0.1:5000", "192.168.1.5:5000", "203.0.113.9:5000"]
        );
        // 端口无关准入：seen 端口被 NAT 改写但 IP 同 = 直连
        d.set_endpoints(
            2,
            vec!["203.0.113.2:41641".into()],
            vec!["203.0.113.2:9".into()],
        );
        assert!(d.public_direct(2));
    }

    #[test]
    fn protocol_version_roundtrip() {
        let mut d = Directory::new();
        assert_eq!(d.protocol_version(1), 1, "v1 节点恒 1");
        d.set_protocol_version(1, 2);
        assert_eq!(d.protocol_version(1), 2);
        d.remove_node(1);
        assert_eq!(d.protocol_version(1), 1);
    }
}
