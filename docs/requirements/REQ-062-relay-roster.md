# REQ-062 relay 池策划（roster）

> 类型：需求 ｜ 状态：📌 proposed ｜ 优先级：P3 ｜ 依赖：REQ-034 ｜ 提出：2026-09-02

## 动机

`NetworkDomain::sync_relays` 现状 = 能力位一挂即进 PathService relay 集合（"愿意 = 被用"），coord 没有选择权；`set_relay_order` 传子集只是排序 API 的副作用，且下一次注册会被 `sync_relays` 全量冲回。relay 数量预期几十（联邦后全网更多，但按 REQ-061 定论图按域隔离），需要显式的缩放阀门与控制面。netmap 的 `relay_list` 现为端点字符串列表（DERP map 等价物），语义不足以承载"激活名单 + 优先级"。

## 决策摘要（建议默认值）

1. **roster = node_id 有序激活名单**（netmap `relay_list` 字段升级），顺序 = 挂靠优先级（RTT/策略排序）
2. **双资格**：能力位 `relay`（节点自愿，必要条件）∩ roster（coord 选用，充分条件）——不在 roster 的能力位节点不进任何候选路径（无 key_path 签发 = 无业务流量，效果上是停用而非吊销）
3. **生成模式 C**：自动策划（在线健康 + RTT 排序 + 公网准入）+ 配置硬约束（`include` / `exclude` / `max_size`，REQ-038 配置即权威哲学）
4. **公网准入判定**：coord 回显 seen 地址 ∈ 节点上报的本地接口地址集合 → 直连公网；否则排除出 relay 池。EndpointReport 需拆分本地地址与回显地址分列上报（proto 小改）
5. **修 `sync_relays`**：注册/吊销触发的 relay 集合重算不再自动全量进 PathService；PathService relay 集 = roster
6. 判定失败/边缘情况（1:1 NAT 等）→ 配置 `include` 兜底
7. **生命周期联动**：撤销/过期/roster 变更 → Update/Withdraw 事件推送范围 = **全部 hops 参与者**（source/dest/hops 内 relay）——修现有 `withdraw_node` 只推 source 的缝隙（relay/dest 持失效 key_path 直至 TTL 3600s，路径级 ACL 的撤销语义在参与者侧失效窗口）；pending 容量语义沿 REQ-047

## 非目标

- NAT1/受限锥/对称 NAT 准入（推迟为下一个目标：NAT1 需异 IP 双 vantage 观测判别，同 IP 双端口测不出过滤行为差异）
- 内部 relay 全家（uplink/top-K 保活/TCP 兜底/上游代报——推迟）
- relay↔relay RTT 真值（v1 用 coord 代理值）

## 开放问题（立项评审拍板）

1. `max_size` 缺省值（建议 8~10：几十 willing relay 策划后的合理图规模）
2. 自动策划进出 roster 的滞回参数（防健康抖动导致名单抖动）
3. roster 变更与 netmap 版本联动节奏（每次变更 bump 还是随心跳周期合并）

## 验收标准（草案）

- roster 交集语义单测（能力位 ∩ roster；exclude 优先于自动策划；include 兜底判定失败节点）
- 公网判定单测（seen ∈ 本地地址 → 准入；NAT 后 → 排除）
- `sync_relays` 修正单测（新注册 relay 能力位节点不自动进 PathService）
- 生命周期联动单测：撤销源/目的/中间 relay 后，其余参与者在下次心跳收到 Withdraw/Update 且本地 key_path/forward_paths 移除
- e2e relay 场景回归（roster 收窄后路径仍可用）

## 关联

- 依赖：REQ-034（已 merged → CONTROL_PLANE §3.11；PathService relay 集语义）
- 关联：REQ-038（配置权威 + SIGHUP 重载模式）、REQ-061（roster 为多跳图的输入）、REQ-007（coord 回显，公网判定数据源）
