# REQ-045 ACL v2 策略层（前缀级先行）

> 类型：需求 ｜ 状态：📌 proposed ｜ 优先级：P2 ｜ 依赖：— ｜ 提出：2026-09-01

## 动机

v1 全端口可达 = "会员制"隐式信任：认证一次，任意成员可达任意前缀任意端口。REQ-020 只预留了接入钩子（检查点/能力位/消息族空间/version 两用），策略本体（模型/下发/裁决语义/组）未设计。本需求补上授权层：零信任式逐请求授权。

## 决策摘要（建议默认值）

1. 策略模型：有序规则列表 first-match-wins；`subject（node_id 列表 / group:标签 / any）→ object（前缀）→ action（allow/deny）`
2. 开关 = 网络级（`networks[].acl.enabled`，coordinator 权威，随 netmap 原子切换）；`enabled=false` = v1 行为不变；开启后 **default-deny**（未匹配即拒）
3. fail-closed：网络开启后，能力位不带 `acl`（0x40）的节点注册拒绝（防最弱环节绕过）
4. 下发：内嵌 NetmapPush（version 一版本两用，REQ-020③ 既定；否决独立 PolicyPush——避免独立版本号与一致性窗口）
5. 裁决点 = 目标节点解密后（AEAD 会话即源认证，直连/中继/多跳全覆盖，CN-04 天然满足）；中继不做明文 ID 过滤（可伪造）；发送侧检查仅为快速失败优化，非权威
6. 主体粒度 = 节点（tun0 可信边界既定，LAN 设备不做区分；伪造 `from_node_id` 无法通过 AEAD，源不可冒充）
7. 组 = 管理面标签（config 给 node_id 打标，策略引用；协议/netmap 线格式不动）；加密强隔离留 key_path 路径授权（CONTROL_PLANE §3.11.6 既有）
8. 分阶段：第一阶段前缀级（无状态，不引入 L4 状态，合 ROUTE_ENGINE §3 透传哲学）；端口级第二阶段（L4 解析 + 回程豁免表）；端口级未实现前 config 出现端口字段一律报错拒绝（fail-closed，防"以为受控实际没有"）

## 验收标准（草案）

- `enabled=false`：行为与 v1 完全一致，现有测试零改动通过
- `enabled=true` 且无规则：成员间全部拒绝（default-deny）
- `enabled=true` + allow 规则：subject 命中放行、未命中拒绝；直连与中继两路径同策略生效
- 伪造 `from_node_id` 的帧被拒（AEAD 会话对端不匹配）
- 网络开启后，无 `acl` 能力位的节点注册被拒
- 端口级未实现阶段，config 含端口字段 → 加载报错
- 验收场景：SEC-28 升级（v1 断言保留）+ 新增场景（合并时落 tests/）

## 关联

- 前置（已 merged）：REQ-020（钩子预留）、REQ-038（管理面 config 形态）
- 升级路径：CONTROL_PLANE §3.11.6 路径级授权（组隔离加密强版本）
- 教训对照：CN-04（策略覆盖全部路径 + 加密绑定）
