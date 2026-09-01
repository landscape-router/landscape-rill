# 租户/网络边界验证（tenancy）

> 覆盖 CONTROL_PLANE §1.5（多网络隔离）、§7（联邦钩子）与 CONNECTIVITY §2.2（反射放大）。
> 拓扑：单 coordinator + 网络 A 两节点 + 网络 B 两节点（跨网络容器）。

## SEC-21 netmap 隔离

- 关联 REQ：REQ-010
- 测试层：docker e2e
- 状态：`待补充`
- 证据：—
- 缺口：多网络分域实现未落地（同 CTL-09）
- 说明：网络 A 节点收不到 B 的 netmap 条目；`network_id` 恒为本网络

## SEC-22 key_dst 隔离

- 关联 REQ：REQ-010
- 测试层：docker e2e
- 状态：`待补充`
- 证据：—
- 缺口：跨网络 key 派生（主密钥独立）与伪造拒绝未验证
- 说明：A 节点用 B 网络 key 伪造 route_mac → 转发节点校验失败

## SEC-23 auth key 越权

- 关联 REQ：REQ-010
- 测试层：docker e2e
- 状态：`待补充`
- 证据：—
- 缺口：归域校验未实现（auth key 绑定网络）
- 说明：A 网络的 auth key 注册进 B → 拒绝

## SEC-24 身份绑定越权

- 关联 REQ：REQ-010
- 测试层：docker e2e
- 状态：`待补充`
- 证据：—
- 缺口：依赖多网络实现
- 说明：A 节点把 B 节点绑定混入握手 → 绑定签名验证失败

## SEC-25 前缀公告越权

- 关联 REQ：REQ-010
- 测试层：docker e2e
- 状态：`待补充`
- 证据：—
- 缺口：白名单按网络分域未实现（依赖 CTL-10）
- 说明：A 网络节点公告 B 网络白名单前缀 → 拒绝

## SEC-26 反射放大（coordinator 回显）

- 关联 REQ：REQ-017
- 测试层：docker e2e
- 状态：`待补充`
- 证据：—
- 缺口：coordinator UDP 回显探测未实现（依赖 CON-01），限速语义随之待验证
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

- [ ] SEC-21：A 的 netmap 只含 A 网络条目（待实现）
- [ ] SEC-22：跨网络伪造 route_mac 校验失败（待实现）
- [ ] SEC-23：跨网络 auth key 注册被拒（待实现）
- [ ] SEC-24：跨网络身份绑定验签失败（待实现）
- [ ] SEC-25：跨网络白名单公告被拒（待实现）
- [ ] SEC-26：反射放大被限速收敛（待实现）
- [ ] SEC-27：普通节点不持有远端端点（v2）
- [x] SEC-28：v1 断言——`acl` 位（0x40）恒 false（coordinator 不解释不占用）、策略检查点恒放行（route.rs）
