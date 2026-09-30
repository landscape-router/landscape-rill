# 租户/网络边界验证（tenancy）

> 覆盖 CONTROL_PLANE §1.5（多网络隔离）、§3.10（ACL 策略层）、§7（联邦钩子）与 CONNECTIVITY §2.2（反射放大）。
> 拓扑：单 coordinator + 网络 A 两节点 + 网络 B 两节点（跨网络容器）；SEC-31 用 direct 拓扑 + 开启策略的 lab 网络。

## SEC-21 netmap 隔离

- 关联 REQ：REQ-010
- 测试层：docker e2e + 单测
- 状态：`已覆盖`
- 证据：e2e/run_e2e.sh、rill-coord/src/coordinator/
- 说明：网络 A 节点收不到 B 的 netmap 条目；`network_id` 恒为本网络（netmap_snapshot 按网络过滤，server 推送按注册节点网络取值）；断言测试 `netmap_isolated_per_network`

## SEC-22 key_dst 隔离

- 关联 REQ：REQ-010
- 测试层：docker e2e + 单测
- 状态：`已覆盖`
- 证据：e2e/mesh/tenancy/forge.py、e2e/run_e2e.sh、rill-coord/src/coordinator/
- 说明：A 节点用 B 网络 key 伪造 route_mac → 转发节点校验失败（BadRouteMac 丢弃；正对照证明 drop 因密钥不匹配）；主密钥按网络独立（KDF 分域）；断言测试 `key_dst_isolated_per_network`

## SEC-23 auth key 越权

- 关联 REQ：REQ-010
- 测试层：docker e2e + 单测
- 状态：`已覆盖`
- 证据：e2e/run_e2e.sh、rill-coord/src/coordinator/、rill-coord/src/config/
- 说明：归域在协议上结构性阻断——auth key 内嵌网络（REQ-043），注册即归域（key 的网络必须存在且只进该网络 registry）；配置层 key 放错网络段拒绝启动；未知网络 key 注册被拒；断言测试 `auth_key_scoped_to_network`/`config_rejects_network_mismatch`

## SEC-24 身份绑定越权

- 关联 REQ：REQ-010
- 测试层：单测（集成）
- 状态：`已覆盖`
- 证据：rill-coord/src/coordinator/、rill-core/src/handshake/、rill-mesh/src/data/
- 说明：**覆盖层调整（2026-09-01）**：e2e 容器内无法注入携带外网绑定的 Noise 握手（需实现完整恶意客户端，且 netmap 隔离已结构性阻断攻击面——A 拿不到 B 的端点）；改为直接验证生产验签路径 `verify_binding`（外网绑定/篡改节点号/公钥任一字段 → 失败）+ 跨网握手 prologue 拒绝（线级）

## SEC-25 前缀公告越权

- 关联 REQ：REQ-010
- 测试层：单测
- 状态：`已覆盖`
- 证据：rill-coord/src/coordinator/
- 说明：白名单按网络分域——A 网白名单不影响 B 网；A 网节点公告 B 网白名单前缀被拒（RouteNotAllowed）；断言测试 `whitelist_isolated_per_network`

## SEC-26 反射放大（coordinator 回显 + 节点 PONG）

- 关联 REQ：REQ-017 / REQ-046
- 测试层：docker e2e + 单测
- 状态：`已覆盖`
- 证据：e2e/run_e2e.sh、rill-coord/src/echo.rs、rill-core/src/rate.rs、rill-mesh/src/data/dispatch.rs
- 说明：伪造源地址灌 probe → 按源 IP 令牌桶限速生效（默认 10/s 突发 20；probe 场景宿主灌 200 包 → coord `echo rate-limited` 摘要）；响应 ≈ 请求大小（PONG 仅回显 seen 地址/空载荷，放大因子 ~1:1）；节点 PONG 生成侧同值按源限速（REQ-046，`pong_limiter`——同源超突发容量后 PONG 被抑制）；单测 `limiter_allows_burst_then_blocks`（rill-core）/`echo_rejects_non_echo_or_garbage`/`pong_generation_rate_limited_per_source`

## SEC-27 联邦边界（v2 预置断言）

- 关联 REQ：REQ-007
- 测试层：集成（v2）
- 状态：`待补充`
- 证据：—
- 说明：远端端点只下发到桥节点（断言检查，v2 联邦实现时展开）

## SEC-28 ACL 策略层（v1 断言保留 + 前缀级实现，REQ-045）

- 关联 REQ：REQ-020 / REQ-045
- 测试层：单测（断言 + 语义）
- 状态：`已覆盖`
- 证据：rill-core/src/control/acl.rs、rill-core/src/route/、rill-coord/src/coordinator/、rill-coord/src/config/、rill-mesh/src/control/、rill-node/src/runtime/
- 说明：**v1 断言保留**——`enabled=false`/无 acl 段 = 行为与 v1 完全一致（策略检查点恒放行 route.rs policy_checkpoint_allow_all_v1；acl 位未启用时 coordinator 不解释、netmap 原样透传 capability_acl_bit_reserved_v1）。**前缀级实现断言（REQ-045）**——裁决引擎单测（disabled 全放行/无规则全拒/first-match/组与节点主体/未知组不命中/非 IP 拒）；fail-closed 准入（网络开启后无 acl 位注册拒 `acl_enabled_register_without_bit_rejected`，幂等同约束）；配置加载即校验（端口字段 `deny_unknown_fields` 报错/未知组/恶形主体/前缀/动作）；策略随 netmap 下发 + 变更 bump 版本（`acl_policy_change_bumps_netmap_version`）+ 线格式往返（server_tests `netmap_push_embeds_acl_policy`）；运行时集成（允许投递 → 组员除名 → netmap 收敛后拒投递、会话保活，`acl_prefix_rules_enforced_at_target_node`）

## SEC-31 ACL 前缀级 e2e（default-deny + 原子切换）

- 关联 REQ：REQ-045
- 测试层：docker e2e（`MESH_E2E_SCENARIO=acl`，CI e2e-mesh matrix）
- 状态：`已覆盖`
- 证据：e2e/setup.sh、e2e/scenarios/acl.sh、.github/workflows/e2e-mesh.yml
- 说明：direct 拓扑 + lab 网络开启策略（组 mesh={a,b}）。阶段 1：放行前缀双向可达（b→a IPv4+IPv6；**e2e 实证 ping 双向流语义**——回包 dst = 发起方源前缀，同样过目标侧裁决，放行须覆盖双方源前缀）+ 无规则仲裁前缀 default-deny（a→172.21.5.1 拒绝，node-b 日志实收 `acl denied`——解密后裁决证据强于不可达）；阶段 2：SIGHUP 补放行仲裁前缀 → 心跳快照（≤10s）收敛后可达（netmap 原子切换）；IPv6 ND 组播泛洪不受策略影响（广播豁免，L2 无 L3 目标）

## 验收断言

- [x] SEC-21：A 的 netmap 只含 A 网络条目（e2e tenancy 阶段 1）
- [x] SEC-22：跨网络伪造 route_mac 校验失败（e2e forge 正/负对照）
- [x] SEC-23：跨网络 auth key 注册被拒（e2e ghost 网络 key + 配置层归域校验）
- [x] SEC-24：跨网络身份绑定验签失败（集成：verify_binding + 跨网握手 prologue）
- [x] SEC-25：跨网络白名单公告被拒（单测：白名单分域）
- [x] SEC-26：反射放大被限速收敛（probe 场景 rate-limited 摘要 + 单测）
- [ ] SEC-27：普通节点不持有远端端点（v2）
- [x] SEC-28：v1 断言保留（未启用 = 行为不变）+ 前缀级裁决/准入/配置 fail-closed（REQ-045）
- [x] SEC-31：default-deny + SIGHUP 原子切换 e2e（acl 场景，REQ-045）
