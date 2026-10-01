# REQ-065 dn42 逐条路由动态上报（RouteMap）

> 类型：需求 ｜ 状态：✅ merged ｜ 提出：2026-09-03 ｜ 合并：2026-10-01
> 去向：CONTROL_PLANE §3.17 · DN42_LEG §5/§7 · ROUTE_ENGINE §3/§6.3 ｜ 验收场景：DNL-16 ｜ lessons：RT-01（自指跳过）+ RT-02（用户态唯一真相）+ CP-04（离线/吊销清理）

## 动机

v1 形态（DN42_LEG §7 ③/④）：ext 节点仅公告**聚合网段**（172.20/14、fd00::/8）且只在注册时静态携带。代价：BGP 断而节点在线期间聚合仍在，流量到 ext 后死在本地（LPM miss 丢弃）；多 ext 出口只能按**节点级**可达性（租约）分流，无法按**前缀级**真实可达性分流。逐条上报把 BGP 真实可达性带进控制面，前缀级故障收敛与多 ext 真分流才成立。该信息与 v1.5 路径服务（PathMap 与 netmap 分离）同族——动态"怎么到"不应塞进静态"谁存在"的 netmap。

## 决策摘要

`RouteSync { announced[], withdrawn[] }` 增量上报（每条 = 前缀 + NEXT_HOP），客户端 5s 防抖窗口合并 + 重注册全量重报；`RouteMap` = 服务端聚合"前缀 → ext 节点"表，独立版本空间（不 bump netmap version）随心跳全量推送；服务端三道闸（覆盖域 ⊆ 注册聚合 / per-node 2000 / 翻转阻尼 3 次·10min，稳态重报不算）；多 ext 同前缀多条并存不做 best-path（消费端多 via 裁决）；聚合公告保留双轨兜底（逐条缺失/撤销回落聚合语义，一个版本周期后评估收敛）；RouteMap = leader 本地软状态（不进 raft，可由节点重上报重建）。

## 去向

- CONTROL_PLANE §3.17（消息族/三道闸/生命周期/状态边界）
- DN42_LEG §5/§6/§7 v0.6（接口与决策记录）
- ROUTE_ENGINE §3/§6.3 v0.6（来源优先级链 `LAN > mesh > dyn-dn42 > dn42 > tailnet`）
- 验收：DNL-16（[../tests/legs/dn42.md](../tests/legs/dn42.md)）

## Lessons 复核

- RT-01：公告前缀自指——RouteMap 消费端跳过自身贡献条目（node_id == me 不入表），自身路径走本地 BGP（source=Dn42 更高优先）
- RT-02：路由真相唯一——RouteMap 只注入用户态引擎，不改内核路由表
- CP-04：陈旧节点残留——离线/吊销/netmap 消失三入口清理该节点 DynDn42 路由（withdraw_node + 节点侧即时清理，不等下一次 RouteMap 推送）
