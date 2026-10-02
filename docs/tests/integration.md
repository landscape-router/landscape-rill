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

- 关联 REQ：REQ-005 / REQ-012 / REQ-071
- 测试层：docker e2e
- 状态：`已覆盖`（2026-10-02）
- 证据：e2e/scenarios/exit_wan.sh
- 说明：node-c（能力位 0x08 纯 exit）双挂 inet 网充当 WAN 出口（192.168.247.0/24，inet 主机 .100，内核 land0↔eth_inet 转发 + 显式回程路由无 SNAT）；node-b `default_route_preference=["mesh"]` 三阶段：①准入 fail-closed（能力位声明而 exits.allow 空 → 引擎 no route 丢弃，非内核无路由）②SIGHUP 运行时授权（从 c 注册日志解析 node_id 重写 coord.json——注册顺序竞态下确定性授权）→ netmap exit 标记（版本 bump）→ 双栈借道（c ingress 计数增长 = 转发证据）③出口停机 → 租约过期（netmap 版本再 bump）→ 解析器候选清空 → 双栈回退丢弃（链末位语义）

## E2E-06 多rill ext 节点冗余

- 关联 REQ：REQ-012
- 测试层：docker e2e
- 状态：`已覆盖`（2026-10-02）
- 证据：e2e/scenarios/dual_edge.sh
- 说明：node-a/node-c 同前缀（10.42.0.0/24 + fd00:2::/64）同 tun IP 双公告（active-backup）——ingress 归属计数判定活跃边缘（双向验证：a 活跃/c 活跃两轮均过）；停活跃边缘 → 租约过期（LEASE_EXPIRY_SECS=60，netmap 版本递增 = CTL-11 离线转移证据）→ 离线条目路由撤销 → 引擎切 standby（ingress 增长 + ping 恢复，实测 ~96s）；切换后 IPv4/IPv6 稳定，node-b 全程无重启/重注册（软状态收敛）

## E2E-07 tailnet exit 竞争

- 关联 REQ：REQ-012 / REQ-021 / REQ-071
- 测试层：docker e2e
- 状态：`已覆盖`（2026-10-02）
- 证据：e2e/ts2021_runtime/run.sh
- 说明：rill-b 加 ts2021 腿（偏好 `["tailnet","mesh"]`+ 子网路由成员：ts2021 advertise 自家 LAN 10.42.0.0/24——tailnet 侧源受理性前提）+ rill-x（mesh 出口，能力位 0x08，extnet 双挂 MASQUERADE）。三阶段：①tailnet exit 独占承载（rill-ext /0 广播，mesh 出口未授权；出站显式 peer——exit 方向 dst 不落在对端具体前缀内，dst 匹配无法表达）②SIGHUP 授权 mesh exit → 双候选下偏好裁决仍走 tailnet（双出口 MASQUERADE 计数器对照：rill-ext 增长、rill-x 恒 0——先等 rill-b 收到 netmap exit 标记再下结论，防空洞断言）③停 rill-ext + marker 驱逐（PeersRemoved 增量）→ 解析器顺延 mesh exit 承载（rill-x 计数器转正 + ping 收敛，无环路）。首两轮排障闭环两个产品缺陷：跨腿互转环（ROUTE_ENGINE §3 本机前缀落位 + 汇总门控 advertise_mesh_routes）与回程源约束（accepts_source，LPM 顺延 mesh 经 ext 回程）

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
- [x] E2E-05：mesh exit 透传 + 回程（fail-closed 准入 → 授权双栈借道 → 停机回退丢弃，exit_wan/REQ-071）
- [x] E2E-06：双边缘冗余切换（dual_edge：租约过期撤销 + 引擎切 standby 收敛）
- [x] E2E-07：exit 竞争按优先级裁决、无环路（ts2021_runtime E2E-07 三阶段，REQ-071）
- [x] E2E-08：全链路大包双向通（mesh 段 MSS clamp/PTB + tailnet 段 DF@tailscale0 上限整包）
