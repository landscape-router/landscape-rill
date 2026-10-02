# 路由引擎验证（routing）

> 统一 LPM 表、优先级、fallback、MTU、前缀公告边界的验收场景。
> 设计规范：ROUTE_ENGINE（[../design/routing/route-engine.md](../design/routing/route-engine.md)）。

## RTE-01 四接入路由注入

- 关联 REQ：REQ-023
- 测试层：单测 + 集成 + e2e
- 状态：`已覆盖`（2026-10-02）
- 证据：rill-core/src/route/、rill-node/src/runtime/control.rs、rill-node/src/runtime/dn42.rs、rill-node/src/runtime/ts2021.rs
- 说明：四接入注入闭环——mesh `routes[]`（netmap 联动）、dn42（BGP 学习 → `RouteSource::Dn42`，DNL-03）、tailnet（ts2021 netmap 路由注入与全量替换，TSL-05 单测 `ts2021_netmap_routes_injected_and_replaced`）、本地 Direct

## RTE-02 LPM 最长前缀优先

- 关联 REQ：REQ-023
- 测试层：单测
- 状态：`已覆盖`
- 证据：rill-core/src/route/
- 说明：len 降序查找、Prefix 归一化存储

## RTE-03 等长冲突消解

- 关联 REQ：REQ-023
- 测试层：单测
- 状态：`已覆盖`
- 证据：rill-core/src/route/
- 说明：source 优先级升序（LAN > mesh > dn42 > tailnet）

## RTE-04 多网关冗余

- 关联 REQ：REQ-023
- 测试层：单测
- 状态：`已覆盖`
- 证据：rill-core/src/route/
- 说明：同前缀同源多 via 全返回；故障切换（reachable 谓词）单测闭环

## RTE-05 dn42 fallback 链

- 关联 REQ：REQ-023
- 测试层：单测 + e2e
- 状态：`已覆盖`（2026-10-02）
- 证据：rill-core/src/route/、e2e/scenarios/dn42.sh
- 说明：fallback 链语义（lookup_best + reachable 谓词）单测闭环；跨腿链路 e2e——DNL-14 无 dn42 腿节点借道 mesh 出口双向 transit、DNL-16 前缀级切换/会话断全撤/聚合兜底回归

## RTE-06 exit 语义

- 关联 REQ：REQ-005 / REQ-021
- 测试层：集成 + e2e
- 状态：`部分覆盖`（2026-10-02）
- 证据：e2e/ts2021_register/run.sh、e2e/ts2021_runtime/run.sh
- 缺口：ts2021 exit 使用/被用作已闭环（TSL-06/07）；**mesh exit WAN 透传不 NAT 未实现**（E2E-05 依赖；/0 不入前缀公告，走 exit 语义）

## RTE-07 MTU/PTB

- 关联 REQ：REQ-009
- 测试层：单测 + e2e
- 状态：`已覆盖`
- 证据：rill-node/src/packet/mtu.rs、e2e/scenarios/mtu.sh
- 说明：6 单测（clamp/PTB 构造）；1400 底座上 MSS clamp 生效（mss 1342 = 1394−40−12 timestamps）、DF 大包 PTB 回馈 v4/v6（next-hop mtu = 1314 = 1400−86）、PTB 后小包连通

## RTE-08 前缀公告边界

- 关联 REQ：REQ-008 / REQ-014
- 测试层：单测 + e2e
- 状态：`部分覆盖`
- 证据：rill-core/src/control/registry.rs、rill-coord/src/coordinator/
- 缺口：过短前缀不进前缀公告已闭环（CTL-10）；"过短前缀走 exit 语义"依赖 mesh exit（RTE-06 待实现）

## 验收断言

- [x] RTE-01：四接入路由统一进 LPM 表（mesh/dn42/tailnet/本地均已闭环）
- [x] RTE-02：具体前缀命中优先于粗粒度前缀
- [x] RTE-03：等长按来源优先级取路
- [x] RTE-04：首选停机 → 自动切次选
- [x] RTE-05：dn42 直连断 → mesh 出口 → 丢弃（单测 + DNL-14/16 跨腿 e2e）
- [ ] RTE-06：exit 透传/使用/被用作语义（ts2021 已闭环；mesh exit WAN 待实现）
- [x] RTE-07：大包不黑洞、MSS clamping 生效、PTB 透传（mtu 场景通过）
- [ ] RTE-08：过短前缀不混入公告（已闭环 CTL-10）；走 exit 语义待 mesh exit
