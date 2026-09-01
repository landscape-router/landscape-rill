# 租户/网络边界验证（tenancy）

> 覆盖 CONTROL_PLANE §1.5（多网络隔离）、§7（联邦钩子）与 CONNECTIVITY §2.2（反射放大）。
> 拓扑：单 coordinator + 网络 A 两节点 + 网络 B 两节点（跨网络容器）。

## SEC-21 netmap 隔离

- 关联 REQ：REQ-010
- 测试层：docker e2e + 单测
- 状态：`已覆盖`
- 证据：e2e/run_e2e.sh、rill-coord/src/coordinator.rs
- 说明：网络 A 节点收不到 B 的 netmap 条目；`network_id` 恒为本网络（netmap_snapshot 按网络过滤，server 推送按注册节点网络取值）；断言测试 `netmap_isolated_per_network`

## SEC-22 key_dst 隔离

- 关联 REQ：REQ-010
- 测试层：docker e2e + 单测
- 状态：`已覆盖`
- 证据：e2e/mesh/tenancy/forge.py、e2e/run_e2e.sh、rill-coord/src/coordinator.rs
- 说明：A 节点用 B 网络 key 伪造 route_mac → 转发节点校验失败（BadRouteMac 丢弃；正对照证明 drop 因密钥不匹配）；主密钥按网络独立（KDF 分域）；断言测试 `key_dst_isolated_per_network`

## SEC-23 auth key 越权

- 关联 REQ：REQ-010
- 测试层：docker e2e + 单测
- 状态：`已覆盖`
- 证据：e2e/run_e2e.sh、rill-coord/src/coordinator.rs、rill-coord/src/config.rs
- 说明：归域在协议上结构性阻断——auth key 内嵌网络（REQ-043），注册即归域（key 的网络必须存在且只进该网络 registry）；配置层 key 放错网络段拒绝启动；未知网络 key 注册被拒；断言测试 `auth_key_scoped_to_network`/`config_rejects_network_mismatch`

## SEC-24 身份绑定越权

- 关联 REQ：REQ-010
- 测试层：单测（集成）
- 状态：`已覆盖`
- 证据：rill-coord/src/coordinator.rs、rill-core/src/handshake.rs、rill-mesh/src/data.rs
- 说明：**覆盖层调整（2026-09-01）**：e2e 容器内无法注入携带外网绑定的 Noise 握手（需实现完整恶意客户端，且 netmap 隔离已结构性阻断攻击面——A 拿不到 B 的端点）；改为直接验证生产验签路径 `verify_binding`（外网绑定/篡改节点号/公钥任一字段 → 失败）+ 跨网握手 prologue 拒绝（线级）

## SEC-25 前缀公告越权

- 关联 REQ：REQ-010
- 测试层：单测
- 状态：`已覆盖`
- 证据：rill-coord/src/coordinator.rs
- 说明：白名单按网络分域——A 网白名单不影响 B 网；A 网节点公告 B 网白名单前缀被拒（RouteNotAllowed）；断言测试 `whitelist_isolated_per_network`

## SEC-26 反射放大（coordinator 回显）

- 关联 REQ：REQ-017
- 测试层：docker e2e
- 状态：`待补充`
- 证据：—
- 缺口：coordinator UDP 回显探测未实现（依赖 CON-01，probe 体系阶段），限速语义随之待验证
- 说明：伪造源地址灌 probe → 按源地址限速生效；响应 ≈ 请求大小

## SEC-27 联邦边界（v2 预置断言）

- 关联 REQ：REQ-007
- 测试层：集成（v2）
- 状态：`待补充`
- 证据：—
- 说明：远端端点只下发到桥节点（断言检查，v2 联邦实现时展开）

## SEC-28 ACL v2 预留（v1 断言）

- 关联 REQ：REQ-020
- 测试层：单测（断言）
- 状态：`已覆盖`
- 证据：rill-core/src/route.rs、rill-coord/src/coordinator.rs
- 说明：策略检查点存在且恒放行（route.rs policy_checkpoint_allow_all_v1）；`acl` 能力位（0x40）v1 恒 false——coordinator 不解释、不占用，netmap 原样透传（coordinator.rs capability_acl_bit_reserved_v1）；v1 行为 = 全端口可达语义不变

## 验收断言

- [x] SEC-21：A 的 netmap 只含 A 网络条目（e2e tenancy 阶段 1）
- [x] SEC-22：跨网络伪造 route_mac 校验失败（e2e forge 正/负对照）
- [x] SEC-23：跨网络 auth key 注册被拒（e2e ghost 网络 key + 配置层归域校验）
- [x] SEC-24：跨网络身份绑定验签失败（集成：verify_binding + 跨网握手 prologue）
- [x] SEC-25：跨网络白名单公告被拒（单测：白名单分域）
- [ ] SEC-26：反射放大被限速收敛（probe 体系阶段）
- [ ] SEC-27：普通节点不持有远端端点（v2）
- [x] SEC-28：v1 断言——`acl` 位（0x40）恒 false（coordinator 不解释不占用）、策略检查点恒放行（route.rs）
