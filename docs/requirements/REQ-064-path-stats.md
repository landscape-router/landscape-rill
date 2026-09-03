# REQ-064 逐路径统计与 PathProbe 激活

> 类型：需求 ｜ 状态：📌 proposed ｜ 优先级：P3 ｜ 依赖：REQ-034 ｜ 提出：2026-09-02

## 动机

路径选择（`pick_path`）与 failover 目前只有 miss 计数粗粒度健康，无 per-path 性能测量。v2 帧头携带 `path_id` + 会话 seq，被动统计零成本可做（接收侧按 path_id 分桶记 seq gap = 每路径丢包/乱序/延迟代理）。PathProbe 消息族协议已定义（MsgType 15/16）但运行时未启用——且其传输通道是真空：协议定义在 control.proto（Envelope 族），设计语义为节点↔节点，但节点间唯一的 Envelope 通道是各自的 coord TLS 连接，收到即报错（`unexpected path probe on control connection`）。空闲候选路径无数据流量，被动统计覆盖不到，需要活跃探测。REQ-052 遥测已落地心跳搭载通道（CONTROL_PLANE §3.15），为统计远端上报提供现成载体。

## 决策摘要（建议默认值）

1. **被动统计（本地优先）**：接收侧按 (peer, path_id) 分桶——seq gap = 丢包/乱序计数，到达间隔 = 延迟代理；本地喂 `pick_path` 择优与 miss 机器（统计仅 advisory，不改变 failover 语义）
2. **PathProbe 激活**：空闲候选路径周期活跃探测（探活 + RTT 真值，弥补 REQ-061 挂账的 relay↔relay RTT 代理值）
3. **通道建议默认值 = 数据面帧新增 `packet_type::PATH_PROBE`**：骑 key_path/route_mac 认证、免会话（握手帧同款"route_mac 即认证"模型），按路径首跳发出；probe 响应沿同路径返回
4. **限速纪律沿 REQ-046**：PATH_PROBE 虽有 route_mac 认证（威胁模型弱于无认证 probe），仍延续发送侧限速 + 退避、响应按源限速——活性探测可被已认证成员滥用为放大/能耗攻击面
5. **远端上报**：经 REQ-052 心跳搭载扩展 per-path_id 桶（区间值语义同 §3.15）——本 REQ 为新建需求扩展载荷，不修改 REQ-052 已合并设计；coord 聚合快照经 REQ-051 状态端点展示
6. **与 REQ-052 分工**：052 = per-endpoint 直连对（可达性矩阵）；064 = per-path_id 路径桶（路径质量）——两层粒度互补不重叠

## 非目标

- coord 侧路径调度（统计 advisory，路径决策仍在节点侧）
- 遥测时序存储（§3.15 边界：只保留最新快照）
- 主动带宽探测（path MTU / 容量测量）

## 开放问题（立项评审拍板）

1. **PathProbe 通道三选一**：数据面帧 `packet_type`（建议默认）vs 经 coord 中转（control Envelope 转发语义——需给 coord 加数据面中转行为，违背面分离）vs probe 小包扩展 path 字段（无认证模型与 CONNECTIVITY §4.2 一致，但与帧路径两套逻辑）
2. 统计窗口/衰减参数（喂 pick_path 的分数形式）
3. seq 回绕对 gap 统计的影响（会话 rekey 周期 vs u32 seq 空间）

## 验收标准（草案）

- 统计桶单测：构造丢包/乱序序列，(peer, path_id) 分桶计数正确；窗口衰减正确
- PathProbe 单测：免会话 route_mac 认证、非法 probe 丢弃、RTT 计算、发送侧限速/退避与响应按源限速（REQ-046 纪律）
- 空闲路径活性：无数据流量路径的探活驱动 miss 恢复/劣化（单测）
- 上报 e2e：心跳载荷含 per-path 桶、coord 快照可见（状态端点断言）

## 关联

- 依赖：REQ-034（已 merged → CONTROL_PLANE §3.11 / FRAME_HEADER §9；v2 path_id 与路径健康）
- 关联：REQ-052（已 merged → CONTROL_PLANE §3.15；心跳搭载通道）、REQ-051（已 merged；状态端点展示）、REQ-061（多跳候选提供统计对象）、REQ-063（统计驱动双发触发/退出）
