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
- 状态：`已覆盖`（2026-10-02）
- 证据：e2e/ts2021_dn42/run.sh
- 说明：ts2021×dn42 组合拓扑——node-c（官方 tailscaled `--accept-routes`）→ WG(ts2021) → rill-ext 引擎裁决（`transit tailnet->dn42` 转发边日志实证）→ boringtun → peer-r（内核 WG + FRR，eBGP Established）；ping 172.20.100.2（隧道地址）+ 172.20.100.100（BGP network 172.20.100.0/24 承载地址）双向通；dn42 前缀经 rill-ext 静态 advertise_routes 广播进 tailnet（TS2021_LEG §3.3.2 配置静态前缀）+ tsrv 白名单审批（localNets 前置）；回程走 TUN 回环桥接（dn42→tailnet 不在 v1 边集，transit 落空写 TUN → 内核 100.64.0.0/10 → land0 → LAN 泵 → ts2021 腿）

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
- 状态：`已覆盖`（2026-10-02）
- 证据：e2e/scenarios/dual_edge.sh
- 说明：node-a/node-c 同前缀（10.42.0.0/24 + fd00:2::/64）同 tun IP 双公告（active-backup）——ingress 归属计数判定活跃边缘（双向验证：a 活跃/c 活跃两轮均过）；停活跃边缘 → 租约过期（LEASE_EXPIRY_SECS=60，netmap 版本递增 = CTL-11 离线转移证据）→ 离线条目路由撤销 → 引擎切 standby（ingress 增长 + ping 恢复，实测 ~96s）；切换后 IPv4/IPv6 稳定，node-b 全程无重启/重注册（软状态收敛）

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
- 状态：`已覆盖`（2026-10-02）
- 证据：e2e/scenarios/mtu.sh、e2e/ts2021_runtime/run.sh
- 说明：mesh 段闭环（mtu.sh/RTE-07：MSS clamp 双向 mss:1354 + DF 超限伪造 PTB v4/v6 next-hop 1314 + PTB 后不扰会话）；tailnet 段闭环（ts2021_runtime E2E-08 断言：DF 整包 @ tailscale0 MTU 上限 1280 双向穿透 WG + 转发边 + mesh 全链，payload 1252 全程无 PTB）——"1500 级"大包受手机侧 tailscale0 MTU=1280 物理约束（超限在手机内核本地拒收，不产生在线碎片），自托管替身边界内的诚实上限

## 验收断言

- [x] E2E-01：手机 → mesh 内资源双向 ping 通（官方 tailscaled 替身，TSL-05；真机 smoke 挂 TSL-02/03）
- [x] E2E-02：手机 → 互联网回程对称（docker 网段替身，TSL-06/07）
- [x] E2E-03：手机 → dn42 前缀可达（ts2021_dn42 组合场景：BGP 学习 + 转发边 + 回程桥接）
- [x] E2E-04：rill 节点 → dn42 + 断链 fallback（DNL-14/16）
- [ ] E2E-05：mesh exit 透传 + WAN NAT 回程（mesh exit WAN 未实现）
- [x] E2E-06：双边缘冗余切换（dual_edge：租约过期撤销 + 引擎切 standby 收敛）
- [ ] E2E-07：exit 竞争按优先级裁决、无环路（依赖 mesh exit）
- [x] E2E-08：全链路大包双向通（mesh 段 MSS clamp/PTB + tailnet 段 DF@tailscale0 上限整包）
