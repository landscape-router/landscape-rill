# REQ-061 多跳中继链（路径候选生成扩展）

> 类型：需求 ｜ 状态：📌 proposed ｜ 优先级：P5 ｜ 依赖：REQ-034 ｜ 提出：2026-09-02

## 动机

PathService 候选生成现状只产生深度 ≤2 的路径（direct + 单 relay，`PathService::request`），而多跳所需的底层机制已全部就绪：wire 上 `CandidatePath.hops` 为变长 bytes、数据面 `path_next_node` 按"hops 中后继"转发（任意深度可用）、TTL 默认 64、key_path/route_mac 与跳数无关。缺的只有候选生成与参与者下发两块。单 relay 路径在中继故障或跨地域拓扑下没有备用拓扑深度；relay 数量预期几十（roster 策划后更少，REQ-062），两跳枚举成本可忽略。

## 决策摘要（建议默认值）

1. **候选生成**：直连 + 1-relay + 2-relay 链，**中继跳上限 2**（hops 含 dest ≤3）；候选总数仍 clamp 2~4，顺序 = 挂靠优先级
2. **relay 子图**：本网 roster（REQ-062 落地前可先用现有 relay 集开发，互不阻塞）；边 = netmap 公网端点（v1 仅公网 relay，内部 relay 推迟）
3. **选择算法**：有界枚举 O(R²) + RTT 代理排序（coord↔relay RTT 之和）+ **贪心 node-disjoint**——按 RTT 排序选路径，跳过与已选候选共享中间节点的下一条（避免 failover 假备份）
4. **参与者下发收紧**：PathUpdate/key_path 只发 hops 实际经过者（修 `push_to_participants` 现状推给网络全部 relay 的过度下发，对齐 §3.11.5 最小权限）；撤销/过期的生命周期联动（Withdraw 推全部参与者）由 REQ-062 承载
5. **I/O-free**：枚举/选择为纯函数（rill-core 或 PathService 内纯逻辑），**不引入图算法库**（pathfinding/petgraph 均不需要——有界枚举 ~50 行）
6. **联邦定论**（设计定论，实现挂 v2）：图按网络域隔离（`domain.paths` per-domain），bridge 是唯一跨域边——跨联邦 relay 增长不改变单网图规模
7. **挂账**：relay↔relay RTT 真值（v1 用 coord 代理值，roster 排序已编码偏好）

## 非目标

- 内部 relay（NAT 后 relay 的 uplink/top-K 保活/TCP 兜底通道/上游代报——推迟，传输标注等归 REQ-054 已合并的 underlay 谱系）
- NAT 分类准入（→ REQ-062，v1 仅公网）
- per-node 路径策略（禁走/必走某 relay，独立需求另立）
- 图算法库引入（Yen/Suurballe 仅在无界跳数需求出现时再评估）

## 开放问题（立项评审拍板）

1. 中继跳上限 2 是否合适（约束 = TTL 充裕 vs 时延叠加与排查复杂度）
2. RTT 代理排序的权重形式（求和 vs 最大跳）
3. 参与者集合随路径集变更的 PathUpdate version 语义（现有 version++ 全量替换预期覆盖，需确认）

## 验收标准（草案）

- 候选形状/上限/贪心不相交/参与者集合单测（含：两跳链中间 relay 收到且只收到自己参与的候选的 key_path）
- e2e relay 场景扩展两跳链转发（v2 帧 path_id 逐跳转发断言）
- 现有单 relay 候选与心跳推送回归全绿

## 关联

- 依赖：REQ-034（已 merged → CONTROL_PLANE §3.11 / FRAME_HEADER §9；PathService/路径消息族/v2 帧已落地）
- 关联：REQ-062（roster 为图输入；062 落地后池子自动收窄）
