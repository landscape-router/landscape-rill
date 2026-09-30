# REQ-067 MapResponse 增量 peer 帧解析与应用

- 类型：需求
- 状态：✅ merged
- 提出日期：2026-09-30
- 合并日期：2026-09-30
- 去向：TS2021_LEG §3.3.2
- 验收场景：TSL-11（tests/legs/ts2021.md）

## 动机

headscale 0.29 长轮询流在初始全量 netmap 之后以增量帧推送 peer 变更（`PeersChanged`/`PeersChangedPatch`/`PeersRemoved`），我方 `MapResponse` 只解析 `Peers` 全量集合，增量帧被未知字段静默丢弃——对端漫游/重启后端点与 AllowedIPs 永不更新、节点删除后会话泄漏（DERP 兜底掩盖 UDP 路径退化，长稳运行显性化）。

## 决策摘要

控制侧维持数字 node ID 键控的 netmap 快照作合并基线：全量帧重建、增量帧合并后统一走 `Netmap` 事件 + `SetPeers` 下发（merge_sessions 保活语义一致）；hex(node key) 仍是 WG 会话身份，node key 轮换 = 同 nid 整条替换（旧删新建）；增量帧不触发 Lite/DERP（避免对端 online 抖动放大服务端写放大）。

- lessons 复核（合并时）：FS-01/FS-02（握手/会话触发点——key 轮换走旧删新建，无跨 peer 密钥复用）
