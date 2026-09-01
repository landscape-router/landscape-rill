//! probe 引擎（CONNECTIVITY §2/§4/§5）：echo 探测、互探、
//! 中继挂靠确认与 v1 回退端点表

use super::*;

/// 挂靠中继条目（CONNECTIVITY §5）：端点 + 归属节点（netmap 端点匹配）+ 确认状态。
/// confirmed = 节点侧 probe 确认可达（CON-04 挂靠）；v1 帧端点表追加为回退候选
#[derive(Debug, Clone)]
pub(crate) struct RelayEntry {
    pub endpoint: SocketAddr,
    pub node_id: Option<u32>,
    pub confirmed: bool,
}

/// probe 周期（CONNECTIVITY §2：探测 30s + 网络变更触发；v1 仅周期）
pub(crate) const PROBE_PERIOD: Duration = Duration::from_secs(30);

impl Node {
    /// probe 响应处理（CONNECTIVITY §2/§4/§5）：
    /// - 载荷非空 = coordinator 回显 seen 地址 → 候选端点补充 + 重报
    /// - 载荷空 = 互探确认（端点可达性恢复）/ 中继挂靠确认（v1 回退端点追加）
    pub(super) async fn handle_probe_pong(
        &mut self,
        _from: u32,
        endpoint: SocketAddr,
        payload: Vec<u8>,
    ) {
        if !payload.is_empty() {
            let Ok(addr) = String::from_utf8(payload).map(|s| s.parse::<SocketAddr>()) else {
                return;
            };
            let Ok(addr) = addr else {
                return;
            };
            info!("[node] echo confirmed: {}", addr);
            if !self.echoed_endpoints.contains(&addr) {
                self.echoed_endpoints.push(addr);
                self.report_endpoints().await;
            }
            return;
        }
        // 互探确认：端点活性恢复（直连路径持续可达）
        self.mesh.note_probe_ok(endpoint);
        if let Some(relay) = self.relays.iter_mut().find(|r| r.endpoint == endpoint) {
            if !relay.confirmed {
                relay.confirmed = true;
                info!(
                    "[node] relay attached: {} (node {:?})",
                    endpoint, relay.node_id
                );
                self.apply_relay_endpoints();
            }
        } else {
            debug!("[node] probe confirmed direct via {}", endpoint);
        }
    }

    /// 中继挂靠（CONNECTIVITY §5，CON-04）：v1 帧端点表 = 直连端点 ++ 确认中继端点
    /// （直连 miss 轮转自然落到中继；miss_endpoint 逐个排除）
    pub(super) fn apply_relay_endpoints(&mut self) {
        let relays: Vec<SocketAddr> = self
            .relays
            .iter()
            .filter(|r| r.confirmed)
            .map(|r| r.endpoint)
            .collect();
        let peers: Vec<(u32, Vec<SocketAddr>)> = self.peer_endpoints.clone().into_iter().collect();
        for (peer, mut direct) in peers {
            for r in &relays {
                if !direct.contains(r) {
                    direct.push(*r);
                }
            }
            self.mesh.set_endpoints(peer, direct);
        }
    }

    /// probe 周期（CONNECTIVITY §2/§4/§5，PROBE_PERIOD）：
    /// ① coordinator UDP 回显（STUN 式：发现 NAT 后公网映射）
    /// ② 对全部 peer 候选端点互探（直连确认，CON-03）
    /// ③ 未确认中继端点探测（挂靠确认，CON-04）
    pub(super) async fn pump_probes(&mut self, now: Instant) {
        if now.duration_since(self.last_probe) < PROBE_PERIOD {
            return;
        }
        self.last_probe = now;
        let Some(id) = self.node_id else {
            return;
        };
        if let Some((host, port)) = self.echo_target.clone() {
            let Some(echo_ip) = tokio::net::lookup_host((host.as_str(), port))
                .await
                .ok()
                .and_then(|mut it| it.next())
                .map(|a| a.ip())
            else {
                debug!("[node] echo target unresolved: {host}:{port}");
                return;
            };
            let _ = self
                .mesh
                .send_probe_ping(SocketAddr::new(echo_ip, port), id, 0)
                .await;
        }
        let peers = self.mesh.peer_endpoints();
        for (peer, endpoints) in peers {
            for ep in endpoints {
                let _ = self.mesh.send_probe_ping(ep, id, peer).await;
            }
        }
        for relay in self.relays.iter().filter(|r| !r.confirmed) {
            if let Some(node_id) = relay.node_id {
                let _ = self.mesh.send_probe_ping(relay.endpoint, id, node_id).await;
            }
        }
    }

    /// 端点通告（注册后 / echo 结果变化时）：本地接口 IP ++ echo seen 地址
    pub(super) async fn report_endpoints(&mut self) {
        let Some(control) = self.control.as_mut() else {
            return;
        };
        let Ok(addr) = self.mesh.local_addr() else {
            return;
        };
        let mut eps: Vec<String> = self
            .advertise_ips
            .iter()
            .map(|ip| SocketAddr::new(*ip, addr.port()).to_string())
            .collect();
        for echoed in &self.echoed_endpoints {
            let s = echoed.to_string();
            if !eps.contains(&s) {
                eps.push(s);
            }
        }
        if eps.is_empty() {
            eps.push(addr.to_string());
        }
        debug!("[node] endpoint report: {:?}", eps);
        let report = control.endpoint_report_envelope(eps);
        let _ = control.send_envelope(&report).await;
    }
}
