//! 默认路由（exit）解析（ROUTE_ENGINE §5/§8，REQ-071）：
//! LPM 未命中后的兜底链，独立于 LPM 表——/0 不入前缀公告（§5 边界），
//! exit 候选是节点级标记而非前缀。v1 静态偏好序（§8"竞争优先级"）；
//! WAN 恒为隐式末位兜底（解析返回 None = 走本地 WAN/丢弃），不可配置。

use super::RouteVia;

/// 默认路由来源（偏好序元素；WAN 不是来源——恒为解析失败的兜底）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExitSource {
    /// ts2021 exit peer（tailnet netmap 0/0 广播方，TSL exit 使用方向）
    Tailnet,
    /// mesh exit 节点（netmap exit 标记，REQ-071）
    Mesh,
}

impl ExitSource {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "tailnet" => Some(Self::Tailnet),
            "mesh" => Some(Self::Mesh),
            _ => None,
        }
    }
}

/// 默认路由解析器（I/O-free；候选由 runtime 从 netmap 喂入）。
/// 无环不变量（E2E-07）：mesh exit 节点自身剪除 Mesh 源——出口互为默认
/// 路由会成环（A→B→A…TTL 耗尽），出口的未命中流量只走 Tailnet/WAN
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DefaultRouteResolver {
    /// 节点静态偏好序（§8 v1；空 = 不启用任何 exit，行为 = 纯 WAN）
    preference: Vec<ExitSource>,
    /// mesh exit 候选（netmap exit 标记 ∧ 在线 ∧ 非自身；netmap 序稳定）
    mesh_exits: Vec<u32>,
    /// tailnet exit 候选（ts2021 netmap 0/0 peer id）
    tailnet_exits: Vec<String>,
    /// 自身是 mesh exit（netmap 自身条目标记）
    self_exit: bool,
}

impl DefaultRouteResolver {
    pub fn new(preference: Vec<ExitSource>) -> Self {
        Self {
            preference,
            ..Default::default()
        }
    }

    pub fn preference(&self) -> &[ExitSource] {
        &self.preference
    }

    /// mesh exit 候选全量替换（apply_netmap 调用；self_exit = 自身条目标记）
    pub fn set_mesh_exits(&mut self, exits: Vec<u32>, self_exit: bool) {
        self.mesh_exits = exits;
        self.self_exit = self_exit;
    }

    /// tailnet exit 候选全量替换（ts2021 netmap 事件调用）
    pub fn set_tailnet_exits(&mut self, peers: Vec<String>) {
        self.tailnet_exits = peers;
    }

    /// 解析默认路由：偏好序内首个有可达候选的来源；全空/全不可达 = None
    /// （WAN 兜底，由调用方写 TUN/内核）。同源多候选按序取首个可达
    /// （多出口冗余，与 §2 多 via 语义同构）
    pub fn resolve(&self, reachable: &dyn Fn(&RouteVia) -> bool) -> Option<RouteVia> {
        for source in &self.preference {
            // 无环不变量：出口节点不再经 mesh exit 转发
            if *source == ExitSource::Mesh && self.self_exit {
                continue;
            }
            let candidates: Vec<RouteVia> = match source {
                ExitSource::Tailnet => self
                    .tailnet_exits
                    .iter()
                    .map(|id| RouteVia::Tailnet(id.clone()))
                    .collect(),
                ExitSource::Mesh => self
                    .mesh_exits
                    .iter()
                    .map(|id| RouteVia::Mesh(*id))
                    .collect(),
            };
            if let Some(via) = candidates.into_iter().find(|v| reachable(v)) {
                return Some(via);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_preference_resolves_none() {
        // 缺省 = 不启用任何 exit（行为不变，纯 WAN 兜底）
        let r = DefaultRouteResolver::default();
        assert_eq!(r.resolve(&|_| true), None);
    }

    #[test]
    fn preference_order_adjudicates_competition() {
        // §8 v1：静态偏好序裁决 tailnet/mesh 竞争（两序各自胜出）
        let mut a = DefaultRouteResolver::new(vec![ExitSource::Tailnet, ExitSource::Mesh]);
        a.set_tailnet_exits(vec!["peer-x".into()]);
        a.set_mesh_exits(vec![7], false);
        assert_eq!(
            a.resolve(&|_| true),
            Some(RouteVia::Tailnet("peer-x".into()))
        );

        let mut b = DefaultRouteResolver::new(vec![ExitSource::Mesh, ExitSource::Tailnet]);
        b.set_tailnet_exits(vec!["peer-x".into()]);
        b.set_mesh_exits(vec![7], false);
        assert_eq!(b.resolve(&|_| true), Some(RouteVia::Mesh(7)));
    }

    #[test]
    fn exhausted_source_falls_through_to_next() {
        // 首选源候选全不可达 → 顺延次选（WAN 之外的最后一级 exit 冗余）
        let mut r = DefaultRouteResolver::new(vec![ExitSource::Tailnet, ExitSource::Mesh]);
        r.set_tailnet_exits(vec!["peer-x".into()]);
        r.set_mesh_exits(vec![1, 2], false);
        assert_eq!(
            r.resolve(&|via| !matches!(via, RouteVia::Tailnet(_))),
            Some(RouteVia::Mesh(1))
        );
        // mesh 多候选内亦按序取首个可达
        assert_eq!(
            r.resolve(&|via| !matches!(via, RouteVia::Tailnet(_) | RouteVia::Mesh(1))),
            Some(RouteVia::Mesh(2))
        );
        // 全不可达 = None（WAN 兜底）
        assert_eq!(r.resolve(&|_| false), None);
    }

    #[test]
    fn self_exit_skips_mesh_source() {
        // 无环不变量（E2E-07）：出口节点自身不经 mesh exit 转发——
        // 首选 Mesh 时直接落到次选，避免出口互投成环
        let mut r = DefaultRouteResolver::new(vec![ExitSource::Mesh, ExitSource::Tailnet]);
        r.set_mesh_exits(vec![5], true);
        r.set_tailnet_exits(vec!["peer-y".into()]);
        assert_eq!(
            r.resolve(&|_| true),
            Some(RouteVia::Tailnet("peer-y".into()))
        );
        // 非出口节点不受影响
        r.set_mesh_exits(vec![5], false);
        assert_eq!(r.resolve(&|_| true), Some(RouteVia::Mesh(5)));
    }
}
