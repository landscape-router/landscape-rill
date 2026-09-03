# REQ-065 dn42 逐条路由动态上报（RouteMap）

> 类型：需求 ｜ 状态：📌 proposed ｜ 优先级：P3 ｜ 依赖：REQ-015 ｜ 提出：2026-09-03

## 动机

v1 形态（DN42_LEG §7 ③/④）：ext 节点仅公告**聚合网段**（172.20/14、fd00::/8）且只在注册时静态携带。代价：BGP 断而节点在线期间聚合仍在，流量到 ext 后死在本地（LPM miss 丢弃）；多 ext 出口只能按**节点级**可达性（租约）分流，无法按**前缀级**真实可达性分流。逐条上报把 BGP 真实可达性带进控制面，前缀级故障收敛与多 ext 真分流才成立。该信息与 v1.5 路径服务（CONTROL_PLANE §3.11，PathMap 与 netmap 分离）同族——动态"怎么到"不应塞进静态"谁存在"的 netmap。

## 决策摘要（建议默认值）

1. **RouteUpdate 消息族**（控制面新消息族，组空间按 §3.10 Policy 同模式预留）：`RouteSync { announced[], withdrawn[] }` 增量上报（每条 = 前缀 + NEXT_HOP），客户端 BGP LocRib 变更经防抖窗口合并后上报
2. **RouteMap = 服务端聚合的"前缀 → ext 节点"表**，与 netmap 分离（PathMap 同哲学）；独立版本空间，**不 bump netmap version**（路由抖动不污染节点拓扑版本）；下发 = 变更后全量推送 RouteMap
3. **防抖**：客户端批处理窗口（建议 5s）合并增量；服务端每节点消息速率上限（沿 REQ-047 语义）；同前缀震荡阻尼（建议 10min 内 3 次 → 阻尼）
4. **服务端第二道闸**：per-node 动态路由数上限（缺省镜像节点 max_prefixes 配置）；覆盖域校验（每条必须被该节点聚合公告域覆盖，如 ⊆ 172.20/14 ∪ fd00::/8）——节点侧 import policy 之外的协调者强制
5. **生命周期**：BGP 会话断 → 该节点全部动态路由随下一窗口撤销；节点离线（租约超时）→ 同步移除
6. **与聚合公告并存**：聚合（DN42_LEG §7 ③）保留为 fallback 兜底——消费端路由引擎同前缀 LPM 精确命中天然优先于聚合（ROUTE_ENGINE §2），逐条缺失/撤销时回落聚合语义（ROUTE_ENGINE §4 链）
7. **服务端不做 best-path**：多 ext 前缀冲突由消费端路由引擎多 via 语义处理（ROUTE_ENGINE §2），服务端只聚合

## 非目标

- transit 角色（把学到的 dn42 路由重公告给 dn42 peer，DN42_LEG §4.1 v2 不变）
- WAN 规模表压缩（dn42 量级数千条以内，全量推送足够；不做增量同步协议）
- 前缀级 ACL（沿 ACL v2 / 路径级授权另行演进，REQ-020）

## 开放问题（立项评审拍板）

1. 分发通道：RouteMap 独立消息/版本空间（建议，隔离抖动）vs 复用 netmap `routes[]` 字段
2. 批处理窗口与阻尼参数缺省值（建议 5s / 10min 内 3 次）
3. 逐条稳定后聚合公告是否退化为"仅节点离线兜底"（建议保留双轨一个版本周期再收敛）
4. 与 v1.5 路径服务的实现节奏（RouteMap 先行 vs 同批）

## 验收标准（草案）

- 单测：RouteSync 编解码（批量/增量/空）；RouteMap 聚合 latest-wins + 会话断/离线清理；防抖窗口合并；服务端上限与覆盖域拒绝
- e2e：双 ext + FRR——一端 BGP 撤销前缀，内部节点在批处理窗口内切换到另一 ext（前缀级真分流）；BGP 会话断 → 该 ext 动态路由全部撤销
- 压测：每秒 N 条路由变动下控制面消息速率有界（REQ-047 语义），netmap version 不逐条膨胀
- 回归：RouteMap 缺失/清空时聚合公告兜底路径仍可达（ROUTE_ENGINE §4 链）

## 关联

- 依赖：REQ-015（已 merged → DN42_LEG；eBGP-lite + import policy 为上报数据源）
- 关联：REQ-034（v1.5 路径服务，RouteMap 与 PathMap 同批评估）、REQ-047（控制面速率上限）、REQ-038（配置即权威）、ROUTE_ENGINE §2/§4（多 via 与 fallback 链）、DN42_LEG §7（聚合公告 = 本需求兜底，M2 先行）
