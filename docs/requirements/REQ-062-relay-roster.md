# REQ-062 relay 池策划（roster）

> 类型：需求 ｜ 状态：✅ merged ｜ 提出：2026-09-02 ｜ 合并：2026-10-01
> 去向：CONTROL_PLANE §3.11（relay roster 段）/§3.2/§3.4/§3.12/§3.14 ｜ 验收场景：CTL-25 ｜ lessons：CN-03/CN-05（中继挂靠复核触发点）

## 动机

`NetworkDomain::sync_relays` 现状 = 能力位一挂即进 PathService relay 集合（"愿意 = 被用"），coord 没有选择权；`set_relay_order` 传子集只是排序 API 的副作用，且下一次注册会被 `sync_relays` 全量冲回。relay 数量预期几十（联邦后全网更多，但按 REQ-061 定论图按域隔离），需要显式的缩放阀门与控制面。netmap 的 `relay_list` 现为端点字符串列表（DERP map 等价物），语义不足以承载"激活名单 + 优先级"。

## 决策摘要

1. **roster = node_id 有序激活名单**（netmap `relay_list` 字段升级为 `relay_roster`，repeated fixed32），顺序 = 挂靠优先级（RTT 升序）；节点按 node_id 从 netmap 条目直取 relay 端点
2. **双资格**：能力位 `relay`（必要条件）∩ roster（coordinator 选用）——不在 roster 的能力位节点不进任何候选路径（无 key_path 签发 = 停用而非吊销）；注册/端点上报不再自动改 relay 集（单一写者 = roster 落位）
3. **生成模式 C**：自动策划（在线健康 + RTT 升序 + 公网准入——echo seen IP ∈ 本地接口地址集合）+ 配置硬约束（`include`/`exclude`/`max_size`，默认 8；SIGHUP 热更新即时重提）
4. **迟滞**：进入需 ≥1 次 RTT 测量；退出 = 连续 3 轮 RTT miss 或离线（include 不豁免离线）
5. **公网判定数据源**：EndpointReport 本地/回显地址分列上报（proto `seen` 字段）；判定失败（1:1 NAT 等）→ `include` 兜底
6. **raft 语义**：roster 落位经 raft 日志命令（提案读 leader 软状态，apply 确定性、集合变化才 bump netmap）
7. **生命周期联动**：撤销/roster 收窄的 Withdraw/Update 推送范围 = 全部 hops 参与者（修原 withdraw_node 只推 source 的缝隙）；roster 扩充对幂等命中的既有路径集显式补员

## 去向

- **CONTROL_PLANE §3.11**：relay roster 段（机制权威：双资格/策划/迟滞/raft 语义/事件扇出/补员）
- **CONTROL_PLANE §3.2/§3.4**：`relay_roster` 字段 + endpoints 合并视图 + EndpointReport 分列上报
- **CONTROL_PLANE §3.12**：`networks[].relay { include, exclude, max_size }` 约束段 + SIGHUP 联动
- **CONTROL_PLANE §3.14**：状态端点 relay roster 视图
- **CONNECTIVITY §5/§6**：RTT 探测轮供 roster、中继失联/下线行为对齐
- 验收场景：CTL-25（[tests/mesh/control-plane.md](../tests/mesh/control-plane.md)）
