//! 节点目录域：端点表/relay 列表/netmap 版本/协议版本（CONTROL_PLANE §3.1/§3.2）
//!
//! endpoints/relay_list/protocol_versions 为持久类（REQ-037 整快照落盘）；
//! netmap_version 为变更序号（节点注册/端点/relay 变更时递增，全量下发去重依据）。

use std::collections::HashMap;

#[derive(Debug, Default)]
pub struct Directory {
    netmap_version: u64,
    endpoints: HashMap<u32, Vec<String>>,
    relay_list: Vec<String>,
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

    pub fn set_endpoints(&mut self, node_id: u32, endpoints: Vec<String>) {
        self.endpoints.insert(node_id, endpoints);
        self.bump_netmap();
    }

    pub fn endpoints_of(&self, node_id: u32) -> &[String] {
        self.endpoints
            .get(&node_id)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    pub fn set_relay_list(&mut self, relay_list: Vec<String>) {
        self.relay_list = relay_list;
        self.bump_netmap();
    }

    pub fn relay_list(&self) -> &[String] {
        &self.relay_list
    }

    /// 恢复持久化快照（REQ-037）：版本与端点表（不递增版本）
    pub fn restore(&mut self, netmap_version: u64, endpoints: HashMap<u32, Vec<String>>) {
        self.netmap_version = netmap_version;
        self.endpoints = endpoints;
    }

    pub fn endpoints_all(&self) -> &HashMap<u32, Vec<String>> {
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
        d.set_endpoints(1, vec!["203.0.113.1:41641".into()]);
        assert_eq!(d.netmap_version(), v0 + 1);
        assert_eq!(d.endpoints_of(1), &["203.0.113.1:41641"]);
        assert!(d.endpoints_of(99).is_empty());
        d.remove_node(1);
        assert!(d.endpoints_of(1).is_empty());
    }

    #[test]
    fn relay_list_and_protocol_version() {
        let mut d = Directory::new();
        let v0 = d.netmap_version();
        d.set_relay_list(vec!["r1.example".into()]);
        assert_eq!(d.netmap_version(), v0 + 1);
        assert_eq!(d.relay_list(), &["r1.example"]);
        assert_eq!(d.protocol_version(1), 1, "v1 节点恒 1");
        d.set_protocol_version(1, 2);
        assert_eq!(d.protocol_version(1), 2);
        d.remove_node(1);
        assert_eq!(d.protocol_version(1), 1);
    }
}
