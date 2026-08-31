# 跨接入集成验证（integration）

> 多接入联动的端到端场景——各子系统单测之外，验证"手机/mesh/dn42/tailnet/WAN"之间的真实联动。
> 环境方案与容器拓扑见 [../e2e/README.md](../e2e/README.md)。

## E2E-01 手机 → mesh 内资源（双向）

- 关联 REQ：REQ-012 / REQ-031
- 测试层：docker e2e
- 状态：`部分覆盖`
- 证据：e2e/run_e2e.sh
- 缺口：rill 节点互 ping 已闭环（FRM-10）；**手机侧（官方客户端）接入 mesh 资源未验证**
- 说明：手机访问 rill 节点 A 背后 LAN：请求到达 A 侧设备，A 回包经回程路由（tailnet 前缀公告）回到手机；双向 ping/HTTP 通

## E2E-02 手机 → 互联网

- 关联 REQ：REQ-012
- 测试层：docker e2e
- 状态：`待补充`
- 证据：—
- 缺口：依赖 TSL-04/TSL-05（自研客户端 + subnet router）
- 说明：手机流量 → rill ext 节点 → tun0 → WAN NAT → 互联网；回程对称

## E2E-03 手机 → dn42 空间

- 关联 REQ：REQ-012
- 测试层：docker e2e
- 状态：`待补充`
- 证据：—
- 缺口：依赖 DNL-02/DNL-03（eBGP 会话与路由学习）
- 说明：手机访问 dn42 前缀：rill ext 节点引擎裁决 dn42 接入 → boringtun 隧道 → dn42 peer

## E2E-04 rill 节点 → dn42 空间

- 关联 REQ：REQ-012
- 测试层：docker e2e
- 状态：`待补充`
- 证据：—
- 缺口：依赖 DNL-03 + RTE-05
- 说明：内部 rill 节点 → rill ext 节点（dn42 精确路由或 fallback）→ dn42 隧道；隧道断 → 经 mesh 出口 fallback

## E2E-05 rill 节点 → 互联网（mesh exit）

- 关联 REQ：REQ-005 / REQ-012
- 测试层：docker e2e
- 状态：`待补充`
- 证据：—
- 缺口：mesh exit 透传路径未实现（依赖 RTE-06）
- 说明：经 mesh 出口节点透传 → WAN NAT（透传不 NAT，回程经 WAN NAT 映射）

## E2E-06 多rill ext 节点冗余

- 关联 REQ：REQ-012
- 测试层：docker e2e
- 状态：`待补充`
- 证据：—
- 缺口：核心语义（同源多 via + fallback）已单测闭环（RTE-04）；容器级双边缘切换未验证
- 说明：同一 LAN 两个rill ext 节点公告：一个停机 → 路由引擎切另一个

## E2E-07 tailnet exit 竞争

- 关联 REQ：REQ-012 / REQ-021
- 测试层：docker e2e
- 状态：`待补充`
- 证据：—
- 缺口：依赖 TSL-06/RTE-06
- 说明：同时配置 mesh exit 与 tailnet exit：按静态优先级裁决，切换无环路

## E2E-08 全链路 MTU

- 关联 REQ：REQ-009 / REQ-012
- 测试层：docker e2e
- 状态：`待补充`
- 证据：—
- 缺口：依赖 RTE-07 链路验证
- 说明：手机 ↔ mesh 内资源大包（1500）双向通（MSS clamping + PTB 全程生效）

## 验收断言

- [ ] E2E-01：手机 → mesh 内资源双向 ping/HTTP 通（手机侧待验证）
- [ ] E2E-02：手机 → 互联网回程对称（待实现）
- [ ] E2E-03：手机 → dn42 前缀可达（待实现）
- [ ] E2E-04：rill 节点 → dn42 + 断链 fallback（待实现）
- [ ] E2E-05：mesh exit 透传 + WAN NAT 回程（待实现）
- [ ] E2E-06：双边缘冗余切换（核心单测已闭环，容器级待验证）
- [ ] E2E-07：exit 竞争按优先级裁决、无环路（待实现）
- [ ] E2E-08：全链路 1500 大包双向通（待验证）
