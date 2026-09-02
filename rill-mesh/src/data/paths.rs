//! v2 路径面（CONTROL_PLANE §3.11 节点侧）：路径表 + key_path 表 +
//! 路径/端点两级活性（miss 计数、入站跳归属、发送排序）

use super::*;

impl MeshData {
    /// key_path 注入（PathResponse 签发，只发路径参与者）；轮换 = 同 path_id 覆盖
    pub fn set_key_path(&mut self, path_id: u64, key: [u8; 32]) {
        self.key_path_table.insert(path_id, key);
    }

    pub fn remove_key_path(&mut self, path_id: u64) {
        self.key_path_table.remove(&path_id);
        self.path_health.remove(&path_id);
    }

    pub fn has_key_path(&self, path_id: u64) -> bool {
        self.key_path_table.contains_key(&path_id)
    }

    /// 候选路径集注入（PathResponse/PathUpdate）；同 dest 全量替换。
    /// key_path 生命周期由 withdraw_path/remove_paths_for 管理（不在此清理——
    /// 跨 dest 的全局清理会误删其他路径集的授权密钥）。
    pub fn set_paths(&mut self, dest: u32, paths: Vec<PathEntry>) {
        self.path_table.insert(dest, paths);
    }

    /// 转发路径注入（非自源、自己是 hops 参与者的路径）：中继查表用，
    /// 不进发送选择表（path_table 只装 source = 自己的路径）
    pub fn set_forward_path(&mut self, path: PathEntry) {
        self.forward_paths.insert(path.path_id, path);
    }

    /// PathWithdraw：移除某路径；空集时移除该 dest 的路径表
    pub fn withdraw_path(&mut self, dest: u32, path_id: u64) {
        self.remove_key_path(path_id);
        self.forward_paths.remove(&path_id);
        if let Some(paths) = self.path_table.get_mut(&dest) {
            paths.retain(|p| p.path_id != path_id);
            if paths.is_empty() {
                self.path_table.remove(&dest);
            }
        }
    }

    pub fn paths_for(&self, dest: u32) -> Option<&Vec<PathEntry>> {
        self.path_table.get(&dest)
    }

    /// 吊销联动：清空该 dest 的全部路径（runtime Revoked 事件）
    pub fn remove_paths_for(&mut self, dest: u32) {
        if let Some(paths) = self.path_table.remove(&dest) {
            for p in paths {
                self.key_path_table.remove(&p.path_id);
                self.path_health.remove(&p.path_id);
            }
        }
    }

    /// flow hash 选路径（每目标 2~4 候选）：首选未过期、有 key_path 的路径；
    /// 主路径健康 miss 达阈值 → 切备用（快速切换）。
    pub fn pick_path(&mut self, dest: u32, flow_hash: u64) -> Option<PathEntry> {
        let now = unix_seconds();
        let paths = self.path_table.get(&dest)?;
        let live: Vec<&PathEntry> = paths
            .iter()
            .filter(|p| !p.expired(now) && self.key_path_table.contains_key(&p.path_id))
            .collect();
        if live.is_empty() {
            return None;
        }
        // 主路径 = 有序候选第一条；flow hash 仅在候选健康时做负载
        let healthy: Vec<&PathEntry> = live
            .iter()
            .copied()
            .filter(|p| {
                self.path_health.get(&p.path_id).copied().unwrap_or(0) < PATH_HEALTH_MISS_LIMIT
            })
            .collect();
        // 全候选 miss 耗尽 → 按 miss 升序（最不坏的优先，稳定排序保持候选序）：
        // 心跳走最可能可用的路径，收包侧 ingress 健康恢复形成闭环（避免死锁在更坏路径）
        let pool: Vec<&PathEntry> = if healthy.is_empty() {
            let mut by_health = live.clone();
            by_health.sort_by_key(|p| self.path_health.get(&p.path_id).copied().unwrap_or(0));
            by_health
        } else {
            healthy
        };
        let idx = (flow_hash as usize) % pool.len();
        let chosen = pool[idx].clone();
        // 记录实际选用（心跳 miss 定位；非主路径死亡时驱动切换，CON-06）
        self.last_sent_path.insert(dest, chosen.path_id);
        Some(chosen)
    }

    /// 路径活性上报：健康 miss 清零 / 累计（runtime 按数据面心跳/PathProbe 喂）
    pub fn path_miss(&mut self, path_id: u64) {
        let miss = self.path_health.entry(path_id).or_insert(0);
        *miss = miss.saturating_add(1);
    }

    pub fn path_ok(&mut self, path_id: u64) {
        self.path_health.insert(path_id, 0);
    }

    /// peer 级：数据面心跳 miss → 主路径（候选第一条）+ 实际选用路径 miss。
    /// 只 miss 主路径不够：主路径已死、在用中继路径死亡时（CON-06 故障切换），
    /// 心跳 miss 落不到在用路径上会永远卡死（收包侧 ingress 更新也无——无帧到达）。
    pub fn path_miss_peer(&mut self, dest: u32) {
        if let Some(paths) = self.path_table.get(&dest).cloned() {
            if let Some(main) = paths.first() {
                self.path_miss(main.path_id);
            }
        }
        if let Some(used) = self.last_sent_path.get(&dest).copied() {
            self.path_miss(used);
        }
    }

    /// peer 级：收包成功 → 该 peer 全部路径健康恢复
    pub fn path_ok_peer(&mut self, dest: u32) {
        if let Some(paths) = self.path_table.get(&dest).cloned() {
            for p in paths {
                self.path_ok(p.path_id);
            }
        }
    }

    /// 逐路径活性（v1.5）：按帧实际到达的上一跳更新——首跳 == 入站跳的路径
    /// ok，其余 miss。直连帧（入站 == 源节点）全 ok；经中继的帧证明中继路径
    /// 存活、直连路径死亡，避免收到中继帧误重置直连 miss（不对称拓扑快速切换）。
    pub(super) fn apply_ingress_health(&mut self, from: u32) {
        let Some(ingress) = self.ingress_hop.get(&from).copied() else {
            return;
        };
        let Some(paths) = self.path_table.get(&from).cloned() else {
            return;
        };
        for p in paths {
            let hop0 = p.hops.first().copied().unwrap_or(from);
            if hop0 == ingress {
                self.path_ok(p.path_id);
            } else {
                self.path_miss(p.path_id);
            }
        }
    }

    /// 中继端点归属注入（netmap relay 列表权威全量替换；runtime apply_netmap 调用）
    pub fn set_relay_owners(&mut self, owners: HashMap<SocketAddr, u32>) {
        self.relay_endpoint_owner = owners;
    }

    /// 路径健康快照（观测用）：dest 候选路径的 (path_id, miss) 列表
    pub fn path_health_snapshot(&self, dest: u32) -> Vec<(u64, u32)> {
        self.path_table
            .get(&dest)
            .map(|paths| {
                paths
                    .iter()
                    .map(|p| {
                        (
                            p.path_id,
                            self.path_health.get(&p.path_id).copied().unwrap_or(0),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// 端点归属反查：UDP 发送者地址 → 节点（NAT 改写等未匹配场景 = None）。
    /// 中继端点以权威归属表为准——兜底端点并入了多个 peer 的候选列表，
    /// 扫描端点表会命中第三方列表（PROBE 复现：经 d 中继的帧被归给死中继 b，
    /// apply_ingress_health 永远 ok 经 b 的路径 → 回包黑洞不收敛）
    pub(super) fn endpoint_owner(&self, addr: SocketAddr) -> Option<u32> {
        if let Some(&id) = self.relay_endpoint_owner.get(&addr) {
            return Some(id);
        }
        self.endpoint_table
            .iter()
            .find_map(|(id, addrs)| addrs.contains(&addr).then_some(*id))
    }

    /// 端点归属反查（ingress 判定用，优先非 from 的归属）：
    /// 中继兜底端点会同时出现在 from 的候选列表与中继自己的表内
    /// （HashMap 遍历序不定）——经中继到达的帧必须归到中继名下，
    /// 否则误判直连、活性降级失效
    pub(super) fn endpoint_owner_preferring(&self, addr: SocketAddr, pref_not: u32) -> Option<u32> {
        if let Some(&id) = self.relay_endpoint_owner.get(&addr) {
            if id != pref_not {
                return Some(id);
            }
        }
        let mut fallback = None;
        for (id, addrs) in &self.endpoint_table {
            if addrs.contains(&addr) {
                if *id != pref_not {
                    return Some(*id);
                }
                fallback = Some(*id);
            }
        }
        fallback
    }

    /// 直连端点降级（v1 入站证据）：帧经中继到达 → 发送方自身端点 miss+1。
    /// 只降级归属该节点的端点（端点表内混入的中继兜底端点不受累——
    /// 归属判定用 preferring 语义排除兜底二义）
    pub(super) fn demote_direct_endpoints(&mut self, from: u32) {
        let direct: Vec<SocketAddr> = self
            .endpoint_table
            .get(&from)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|a| self.endpoint_owner_preferring(*a, from) == Some(from))
            .collect();
        for addr in direct {
            let m = self.endpoint_health.entry((from, addr)).or_insert(0);
            *m = m.saturating_add(1);
        }
    }

    /// 发送端点排序：活性 miss 少优先；同活性时上次未用的优先（轮换尝试，
    /// 避免黑洞端点被反复选中）
    pub(super) fn order_endpoints(&self, hop: u32, dest: u32, addrs: &mut [SocketAddr]) {
        let last = self.last_sent_endpoint.get(&dest).copied();
        addrs.sort_by_key(|a| {
            (
                self.endpoint_health.get(&(hop, *a)).copied().unwrap_or(0),
                Some(*a) == last,
            )
        });
    }

    /// 端点级活性 miss：上次对该目标实际使用的端点 miss+1（UDP 黑洞端点
    /// 逐个排除，与 path_miss_peer 同源驱动）
    pub fn miss_endpoint(&mut self, dest: u32) {
        let Some(addr) = self.last_sent_endpoint.get(&dest).copied() else {
            return;
        };
        let Some(owner) = self.endpoint_owner(addr) else {
            return;
        };
        let m = self.endpoint_health.entry((owner, addr)).or_insert(0);
        *m = m.saturating_add(1);
    }

    /// 收帧：来源端点活性恢复（入站帧证明该端点可达）
    pub(super) fn note_endpoint_ok(&mut self, owner: u32, addr: SocketAddr) {
        if let Some(m) = self.endpoint_health.get_mut(&(owner, addr)) {
            *m = 0;
        }
    }

    /// probe 确认（CONNECTIVITY §4.1）：互探 PONG 证明该端点可达 → 活性恢复
    pub fn note_probe_ok(&mut self, addr: SocketAddr) {
        if let Some(owner) = self.endpoint_owner(addr) {
            self.note_endpoint_ok(owner, addr);
        }
    }

    /// 当前端点表（互探用：对全部 peer 候选端点发 PING，CONNECTIVITY §4）
    pub fn peer_endpoints(&self) -> Vec<(u32, Vec<SocketAddr>)> {
        self.endpoint_table
            .iter()
            .map(|(id, addrs)| (*id, addrs.clone()))
            .collect()
    }
}
