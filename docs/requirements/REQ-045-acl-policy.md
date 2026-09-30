# REQ-045 ACL v2 策略层（前缀级先行）

> 类型：需求 ｜ 状态：✅ merged ｜ 提出日期：2026-09-01 ｜ 合并日期：2026-09-30
> 去向：CONTROL_PLANE §3.10 ｜ 验收场景：SEC-28（升级）/ SEC-31（新增，e2e `acl`）

## 动机

v1 全端口可达 = "会员制"隐式信任：认证一次，任意成员可达任意前缀任意端口。REQ-020 只预留了接入钩子（检查点/能力位/消息族空间/version 两用），策略本体（模型/下发/裁决语义/组）未设计。本需求补上授权层：零信任式逐请求授权。

## 决策摘要

1. 策略模型：有序规则 first-match-wins；`subject（node:<id> / group:<名> / any）→ object（前缀）→ action（allow/deny）`；无匹配 = deny
2. 开关 = 网络级（`networks[].acl.enabled`，coordinator 权威，随 netmap 原子切换）；`enabled=false` = v1 行为不变
3. fail-closed 准入：网络开启后无 `acl`（0x40）能力位的注册拒绝；非 IP 载荷无法提取目标 = 拒
4. 下发 = 内嵌 NetmapPush（version 一版本两用，REQ-020③ 既定；否决独立 PolicyPush）
5. 裁决点 = 目标节点解密后（AEAD 会话即源认证，CN-04 天然满足）；发送侧检查非权威，v1 不实现
6. 主体粒度 = 节点；组 = 管理面标签（config 打标，规则字符串引用）
7. 分阶段：前缀级先行（无状态）；端口级字段未实现前一律加载报错（`deny_unknown_fields`）
8. 广播/组播不在前缀级裁决范围（L2 无 L3 目标，IPv6 ND 依赖；端口级阶段一并评估）——合并时实现侧补充

## 合并备注

- 线格式 `AclGroup.node_ids` 用 4B 大端 bytes 序列（同 CandidatePath.hops 惯例）：`repeated fixed32` 触发 quick-protobuf 0.8.1 `read_packed_fixed` 非对齐 transmute UB（读侧任意偏移）
- e2e 实证：ping 双向流语义（回包 dst = 发起方源前缀，放行须覆盖双方源前缀）；SIGHUP 策略切换经心跳快照 ≤10s 收敛
- lessons 复核触发点对照：CN-04（策略覆盖全部路径——解密后裁决天然满足）、KC-04（白名单/配置校验不静默失效——加载即校验）
