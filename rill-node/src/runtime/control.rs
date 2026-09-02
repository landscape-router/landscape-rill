//! 控制面事件接线：注册/netmap/keydist/路径事件 → 数据面状态应用

use super::*;

impl Node {
    pub(super) async fn handle_control_event(&mut self, ev: ControlEvent) -> BoxResult<()> {
        match ev {
            ControlEvent::Registered {
                node_id,
                network_id,
                identity_binding,
            } => {
                self.node_id = Some(node_id);
                self.network_id = network_id;
                self.mesh.set_self_node_id(node_id);
                info!(
                    "[node] registered: node_id={} network_id={}",
                    node_id, network_id
                );
                let ctx = HandshakeContext {
                    network_id,
                    version: VERSION,
                    local_static: self.cfg.static_key_seed,
                    identity_binding,
                };
                self.mesh.set_handshake_context(ctx);
                let vk = VerifyingKey::from_bytes(&self.cfg.coord_signing_pubkey)?;
                self.mesh
                    .set_binding_verifier(move |node_id, static_pubkey, binding| {
                        landscape_rill_coord::signer::verify_binding(
                            &vk,
                            node_id,
                            static_pubkey,
                            binding,
                        )
                    });
                // 端点上报：数据面 UDP 地址（本机各接口 IP + echo seen 地址）→ coordinator 并入 netmap
                self.report_endpoints().await;
            }
            ControlEvent::Netmap(netmap) => {
                // 挑战通过后服务端重推 netmap：Reconnecting → ChallengeOk
                if let Some(control) = self.control.as_mut() {
                    if matches!(control.client().state(), SessionState::Reconnecting { .. }) {
                        let _ = control
                            .client_mut()
                            .session_mut()
                            .handle(SessionEvent::ChallengeOk);
                    }
                }
                self.apply_netmap(&netmap);
                info!(
                    "[node] netmap v{}: {} entries, {} routes, endpoints: {:?}",
                    netmap.version,
                    netmap.entries.len(),
                    netmap.entries.iter().map(|e| e.routes.len()).sum::<usize>(),
                    netmap
                        .entries
                        .iter()
                        .map(|e| (e.node_id, e.endpoints.clone()))
                        .collect::<Vec<_>>()
                );
            }
            ControlEvent::KeyDist {
                to_node_id,
                key,
                key_version,
                broadcast_key,
            } => {
                if key.len() == 32 {
                    let mut k = [0u8; 32];
                    k.copy_from_slice(&key);
                    self.mesh.set_key_dst(to_node_id, k);
                    self.key_versions.insert(to_node_id, key_version);
                }
                // 广播密钥随每条 KeyDist 携带（网络级共享，FRAME_HEADER §2.6）
                if broadcast_key.len() == 32 {
                    let mut b = [0u8; 32];
                    b.copy_from_slice(&broadcast_key);
                    self.broadcast_key = Some(b);
                    self.mesh.set_broadcast_key(b);
                }
            }
            ControlEvent::Lease { granted, .. } => {
                let _ = granted;
            }
            ControlEvent::Challenge { ack } => {
                if let Some(control) = self.control.as_mut() {
                    control.send_envelope(&ack).await?;
                }
            }
            ControlEvent::Revoked { node_id } => {
                self.mesh.drop_session(node_id);
                self.mesh.remove_peer_static(node_id);
                self.mesh.remove_key_dst(node_id);
                self.mesh.remove_endpoint(node_id);
                self.mesh.remove_paths_for(node_id);
                self.engine.remove_mesh_node(node_id);
                self.netmap_peers.remove(&node_id);
                self.peer_heartbeats.remove(&node_id);
                if let Some(control) = self.control.as_mut() {
                    let _ = control
                        .client_mut()
                        .session_mut()
                        .handle(SessionEvent::Revoked { node_id });
                }
            }
            ControlEvent::Paths {
                destination_node_id,
                candidates,
                source_node_id,
                ..
            } => {
                // key_path 全部注入（路径级授权，CONTROL_PLANE §3.11.5：参与者校验/转发用）
                for c in &candidates {
                    if c.key_path.len() == 32 {
                        let mut kp = [0u8; 32];
                        kp.copy_from_slice(&c.key_path);
                        self.mesh.set_key_path(c.path_id, kp);
                    }
                }
                // 发送路径表只写自己发起的路径（source = 自己）；作为 dest/relay
                // 参与者收到的其他源路径仅注入 key_path（覆盖会污染发送选择表），
                // 其中自己是 hops 参与者的写入转发路径表（中继查表用，按 path_id）
                if source_node_id == self.node_id.unwrap_or(u32::MAX) {
                    let entries: Vec<PathEntry> = candidates
                        .iter()
                        .map(|c| PathEntry {
                            path_id: c.path_id,
                            path_epoch: c.path_epoch,
                            hops: c.hops.clone(),
                            expires_at: c.expires_at,
                        })
                        .collect();
                    self.mesh.set_paths(destination_node_id, entries);
                    // 已收敛：该 dest 的请求不再重发
                    self.pending_path_requests
                        .retain(|d| *d != destination_node_id);
                } else if let Some(me) = self.node_id {
                    for c in &candidates {
                        if c.hops.contains(&me) {
                            self.mesh.set_forward_path(PathEntry {
                                path_id: c.path_id,
                                path_epoch: c.path_epoch,
                                hops: c.hops.to_vec(),
                                expires_at: c.expires_at,
                            });
                        }
                    }
                }
                debug!(
                    "[node] paths to {} (src {}) {:?} (kp: {:?})",
                    destination_node_id,
                    source_node_id,
                    candidates
                        .iter()
                        .map(|c| (c.path_id, c.hops.clone()))
                        .collect::<Vec<_>>(),
                    candidates
                        .iter()
                        .map(|c| (c.path_id, c.key_path.len()))
                        .collect::<Vec<_>>()
                );
            }
            ControlEvent::PathWithdrawn {
                destination_node_id,
                path_id,
            } => {
                self.mesh.withdraw_path(destination_node_id, path_id);
                debug!(
                    "[node] path withdrawn {} -> {}",
                    destination_node_id, path_id
                );
            }
        }
        Ok(())
    }

    /// netmap 全量替换语义（CONTROL_PLANE §3.2）：peer 静态公钥/端点/mesh 路由重建。
    /// relay 列表（netmap 权威）全量替换 → 挂靠候选重建（CONNECTIVITY §5）。
    pub(super) fn apply_netmap(&mut self, netmap: &NetmapData) {
        let mut fresh: HashSet<u32> = HashSet::new();
        self.engine.reset_mesh_routes();
        let mut peer_endpoints: HashMap<u32, Vec<SocketAddr>> = HashMap::new();
        for entry in &netmap.entries {
            if Some(entry.node_id) == self.node_id {
                continue;
            }
            fresh.insert(entry.node_id);
            self.mesh
                .set_peer_static(entry.node_id, entry.static_pubkey);
            let mut addrs: Vec<SocketAddr> = Vec::new();
            for ep in &entry.endpoints {
                if let Ok(addr) = ep.parse::<SocketAddr>() {
                    addrs.push(addr);
                }
            }
            peer_endpoints.insert(entry.node_id, addrs.clone());
            self.mesh.set_endpoints(entry.node_id, addrs);
            for route in &entry.routes {
                if let Ok(prefix) = landscape_rill_core::route::Prefix::parse(route) {
                    self.engine.insert(RouteEntry {
                        prefix,
                        source: RouteSource::Mesh,
                        via: RouteVia::Mesh(entry.node_id),
                        metric: None,
                    });
                }
            }
            // v2 peer（protocol_version >= 2）：请求候选路径（v1.5，CONTROL_PLANE §3.11）
            if entry.protocol_version >= 2 {
                self.request_paths_for(entry.node_id);
            }
        }
        for stale in self.netmap_peers.difference(&fresh) {
            self.mesh.remove_peer_static(*stale);
            self.mesh.remove_endpoint(*stale);
            self.mesh.drop_session(*stale);
            self.mesh.remove_paths_for(*stale);
            self.engine.remove_mesh_node(*stale);
        }
        self.netmap_peers = fresh;
        self.peer_endpoints = peer_endpoints;
        // relay 列表：netmap 权威全量替换；归属节点按 netmap 端点匹配解析
        // （relay_list 为端点串，须定位节点才能定向互探）
        let netmap_endpoints: HashMap<SocketAddr, u32> = netmap
            .entries
            .iter()
            .flat_map(|e| {
                e.endpoints
                    .iter()
                    .filter_map(|ep| ep.parse::<SocketAddr>().ok().map(|a| (a, e.node_id)))
            })
            .collect();
        // relay 列表：netmap 权威全量替换；归属节点按 netmap 端点匹配解析。
        // 挂靠确认是本地状态：成员关系随 netmap 重建，已确认端点保持确认
        // （否则每次 netmap 刷新重置，30s 探测周期内确认窗口过短，
        // v1 中继兜底端点反复被冲掉，CON-04 兜底无法收敛）
        let new_relays: Vec<RelayEntry> = netmap
            .relay_list
            .iter()
            .filter_map(|ep| ep.parse::<SocketAddr>().ok())
            .map(|endpoint| RelayEntry {
                endpoint,
                node_id: netmap_endpoints.get(&endpoint).copied(),
                confirmed: self
                    .relays
                    .iter()
                    .any(|r| r.endpoint == endpoint && r.confirmed),
            })
            .collect();
        self.relays = new_relays;
        if !self.relays.is_empty() {
            debug!("[node] relay candidates: {:?}", self.relays);
        }
        // netmap 重建直连端点表后立即重放已确认中继兜底端点（不等下个探测周期）
        self.apply_relay_endpoints();
    }

    /// 登记待发路径请求（netmap 全量替换每次都会触发，幂等：重复请求 = 刷新路径集）。
    /// 上限 PATH_REQUEST_PENDING_MAX（REQ-047：防大规模 netmap 内存放大；饱和丢弃，
    /// 未登记 dest 随下个 netmap/心跳重触发）
    pub(super) fn request_paths_for(&mut self, dest: u32) {
        self.path_requested.insert(dest);
        if !self.pending_path_requests.contains(&dest)
            && self.pending_path_requests.len() < PATH_REQUEST_PENDING_MAX
        {
            self.pending_path_requests.push(dest);
        }
    }
}
