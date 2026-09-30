# REQ-067 MapResponse 增量 peer 帧解析与应用

- 类型：需求
- 状态：📌 proposed
- 优先级：P2
- 依赖：—
- 提出日期：2026-09-30
- 合并日期：—
- 去向：—
- 验收场景：TSL-04/TSL-10（tests/legs/ts2021.md，合并时补专项场景）

## 动机

ts2021_runtime e2e 排障（2026-09-30）实证：headscale 0.29 长轮询流在初始全量 netmap 之后，后续帧以**增量 peer 帧**推送变更——`PeersChanged`（全条目 upsert）、`PeersChangedPatch`（字段级 patch）、`PeersRemoved`（节点删除，载荷为数字 node ID）。我方 `MapResponse`（rill-ts2021/src/tailcfg.rs）只解析 `Peers` 全量集合，增量帧按未知字段静默丢弃，产生三类 stale：

- **端点 stale**：对端 Lite 更新/漫游后的新端点永不生效，数据面持续向死地址发 UDP（现网被 DERP 双路兜底掩盖——UDP 路径退化不可见，直连质量 silently 降级）
- **AllowedIPs stale**：对端路由变更（审批传播/撤销）后的前缀更新不生效，cryptokey 路由错判
- **节点残留**：对端 node key 轮换（重启）或删除后，旧 peer 条目与会话不清理（`NetPeer` 未解析数字 node ID，`PeersRemoved` 无从关联）

e2e 目前全绿的原因：场景内全量 `Peers` 重放频率高（REQ-066 同期修复的 merge_sessions 正是重放路径）且 DERP 承载数据面；长稳运行（对端漫游/重启/下线）下缺口显性化。

## 验收草案

1. **解码**：`MapResponse` 解析 `PeersChanged` / `PeersRemoved`；`NetPeer` 增加数字 node ID 解析（`PeersRemoved` 关联用）；`PeersChangedPatch` 至少应用 `Endpoints` 字段，其余字段显式忽略（计数观测，不静默）
2. **合并语义**：按 hex(node key) upsert，在场 peer 保留既有 WgTunnel（与全量重放 merge_sessions 同语义，避免杀活会话——REKEY_AFTER 90s 黑洞）；`PeersRemoved` 删除 peer 条目并拆除会话；node key 轮换 = 旧条目消失新条目出现，按删除+新增处理
3. **单测**：帧解码（缺省 vs 存在坍缩语义）+ 合并语义（upsert 保活 / removed 清理 / patch 端点生效 / key 轮换迁移）
4. **e2e**：node-c 重启（node key 轮换，Lite/增量帧路径）后 rill-ext 侧 peer 条目迁移、WG 会话经增量帧重建、ping 恢复——不重注册
5. 合并时执行 lessons 复核触发点检查，行为落档 TS2021_LEG §3.3.2
