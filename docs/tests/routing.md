# 路由引擎验证（routing）

> 统一 LPM 表、优先级、fallback、MTU、前缀公告边界的验收场景。
> 设计规范：ROUTE_ENGINE（[../design/routing/route-engine.md](../design/routing/route-engine.md)）。

## RTE-01 四接入路由注入

- 关联 REQ：REQ-023
- 测试层：单测 + 集成
- 状态：`部分覆盖`
- 证据：rill-core/src/route.rs
- 缺口：mesh `routes[]` 注入已闭环；dn42 BGP / ts2021 路由 / 本地路由注入未实现（依赖接入实现）

## RTE-02 LPM 最长前缀优先

- 关联 REQ：REQ-023
- 测试层：单测
- 状态：`已覆盖`
- 证据：rill-core/src/route.rs
- 说明：len 降序查找、Prefix 归一化存储

## RTE-03 等长冲突消解

- 关联 REQ：REQ-023
- 测试层：单测
- 状态：`已覆盖`
- 证据：rill-core/src/route.rs
- 说明：source 优先级升序（LAN > mesh > dn42 > tailnet）

## RTE-04 多网关冗余

- 关联 REQ：REQ-023
- 测试层：单测
- 状态：`已覆盖`
- 证据：rill-core/src/route.rs
- 说明：同前缀同源多 via 全返回；故障切换（reachable 谓词）单测闭环

## RTE-05 dn42 fallback 链

- 关联 REQ：REQ-023
- 测试层：单测 + e2e
- 状态：`部分覆盖`
- 证据：rill-core/src/route.rs
- 缺口：fallback 链语义已实现（lookup_best + reachable）；dn42 接入实际链路未验证（依赖 DNL-07）

## RTE-06 exit 语义

- 关联 REQ：REQ-005 / REQ-021
- 测试层：集成 + e2e
- 状态：`待补充`
- 证据：—
- 缺口：mesh exit 透传不 NAT / ts2021 exit 使用与被用作未实现（依赖接入实现）

## RTE-07 MTU/PTB

- 关联 REQ：REQ-009
- 测试层：e2e
- 状态：`待补充`
- 证据：—
- 缺口：tun0 保守静态 MTU + MSS clamping + ICMP/ICMPv6 PTB 透传未验证

## RTE-08 前缀公告边界

- 关联 REQ：REQ-008 / REQ-014
- 测试层：单测 + e2e
- 状态：`部分覆盖`
- 证据：rill-core/src/control/registry.rs、rill-coord/src/coordinator.rs
- 缺口：过短前缀不进前缀公告已闭环（CTL-10）；"过短前缀走 exit 语义"依赖 exit（P3，RTE-06）

## 验收断言

- [ ] RTE-01：四接入路由统一进 LPM 表（mesh 已闭环，其余待接入实现）
- [x] RTE-02：具体前缀命中优先于粗粒度前缀
- [x] RTE-03：等长按来源优先级取路
- [x] RTE-04：首选停机 → 自动切次选
- [ ] RTE-05：dn42 直连断 → mesh 出口 → 丢弃（fallback 链核心已实现，链路待验证）
- [ ] RTE-06：exit 透传/使用/被用作语义（待实现）
- [ ] RTE-07：大包不黑洞、MSS clamping 生效、PTB 透传（待验证）
- [ ] RTE-08：过短前缀不混入公告（已闭环，CTL-10）；走 exit 语义待实现（P3）
