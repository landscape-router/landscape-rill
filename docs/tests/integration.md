# 跨接入集成验证（integration）

> 多接入联动的端到端场景——各子系统单测之外，验证"手机/mesh/dn42/tailnet/WAN"之间的真实联动。
> 环境方案与容器拓扑见 [../e2e/README.md](../e2e/README.md)。

## E2E-01 手机 → mesh 内资源（双向）

- 关联 REQ：REQ-012 / REQ-031
- 测试层：docker e2e
- 状态：`已覆盖`（2026-10-02）
- 证据：e2e/ts2021_runtime/run.sh
- 说明：TSL-05——官方 tailscaled（node-c，`--accept-routes`）ping 通 mesh 资源（rill-b 公告的 10.42.0.0/24）与 rill-ext 自家 LAN，完整路径 tailscale0 → WG(DERP) → 解包 → 引擎 Mesh 路由 → mesh 帧 → land0 内核应答 → 回程 mesh → tailnet /32；"手机"以官方 tailscaled 容器替身，真机 UI smoke 独立挂 TSL-02/03

## E2E-02 手机 → 互联网

- 关联 REQ：REQ-012
- 测试层：docker e2e
- 状态：`已覆盖`（2026-10-02）
- 证据：e2e/ts2021_register/run.sh、e2e/ts2021_runtime/run.sh
- 说明：自托管 e2e 边界内以独立 docker 网段网关替身"互联网"——exit 使用（官方 exit node + nftables MASQUERADE + conntrack 回程）与被用作（rill-ext 出口 land0 转发 + MASQUERADE）双向闭环；真实互联网 smoke 属 TSL-02/03 真机项

## E2E-03 手机 → dn42 空间

- 关联 REQ：REQ-012
- 测试层：docker e2e
- 状态：`待补充`
- 证据：—
- 缺口：tailnet→dn42 转发边集已实现（forward_transit `(Dn42, Tailnet)` 臂）；缺 ts2021 + dn42 组合组网的 e2e 场景
- 说明：手机访问 dn42 前缀：rill ext 节点引擎裁决 dn42 接入 → boringtun 隧道 → dn42 peer

## E2E-04 rill 节点 → dn42 空间

- 关联 REQ：REQ-012
- 测试层：docker e2e
- 状态：`已覆盖`（2026-10-02）
- 证据：e2e/scenarios/dn42.sh
- 说明：无 dn42 腿的 node-b 借道 node-a 出口双向 transit（DNL-14）；peer 故障前缀级切换、会话断全撤、聚合兜底回归（DNL-16）——含"隧道断 → 经 mesh 出口 fallback"链路

## E2E-05 rill 节点 → 互联网（mesh exit）

- 关联 REQ：REQ-005 / REQ-012
- 测试层：docker e2e
- 状态：`待补充`
- 证据：—
- 缺口：mesh exit WAN 透传路径未实现（/0 不入前缀公告，走 exit 语义；ROUTE_ENGINE §5）
- 说明：经 mesh 出口节点透传 → WAN NAT（透传不 NAT，回程经 WAN NAT 映射）

## E2E-06 多rill ext 节点冗余

- 关联 REQ：REQ-012
- 测试层：docker e2e
- 状态：`待补充`
- 证据：—
- 缺口：核心语义（同源多 via + reachable fallback）已单测闭环（RTE-04）；容器级双边缘切换未验证（direct 场景变体可补）
- 说明：同一 LAN 两个rill ext 节点公告：一个停机 → 路由引擎切另一个

## E2E-07 tailnet exit 竞争

- 关联 REQ：REQ-012 / REQ-021
- 测试层：docker e2e
- 状态：`待补充`
- 证据：—
- 缺口：tailnet exit 双向已闭环（TSL-06/07）；竞争裁决依赖 mesh exit（RTE-06）落地
- 说明：同时配置 mesh exit 与 tailnet exit：按静态优先级裁决，切换无环路

## E2E-08 全链路 MTU

- 关联 REQ：REQ-009 / REQ-012
- 测试层：docker e2e
- 状态：`待补充`
- 证据：—
- 缺口：mesh 段已闭环（RTE-07 / mtu.sh）；tailnet 段（WG/DERP 封装）大包断言未补
- 说明：手机 ↔ mesh 内资源大包（1500）双向通（MSS clamping + PTB 全程生效）

## 验收断言

- [x] E2E-01：手机 → mesh 内资源双向 ping 通（官方 tailscaled 替身，TSL-05；真机 smoke 挂 TSL-02/03）
- [x] E2E-02：手机 → 互联网回程对称（docker 网段替身，TSL-06/07）
- [ ] E2E-03：手机 → dn42 前缀可达（tailnet+dn42 组合 e2e 待补）
- [x] E2E-04：rill 节点 → dn42 + 断链 fallback（DNL-14/16）
- [ ] E2E-05：mesh exit 透传 + WAN NAT 回程（mesh exit WAN 未实现）
- [ ] E2E-06：双边缘冗余切换（容器级待验证；核心单测已闭环）
- [ ] E2E-07：exit 竞争按优先级裁决、无环路（依赖 mesh exit）
- [ ] E2E-08：全链路 1500 大包双向通（tailnet 段断言待补）
