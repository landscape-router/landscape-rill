# REQ-048 批量吊销合并轮换

> 类型：需求 ｜ 状态：📌 proposed ｜ 优先级：P2 ｜ 依赖：— ｜ 提出：2026-09-01

## 动机

v1 吊销 = 主密钥更换 + `key_version++`（CONTROL_PLANE §5.4/§5.5；key_dst 为确定性 KDF，不换主密钥则无新密钥）→ 全网 KeyDist 重下发 + 相关节点对 Noise rekey。吊销在密钥材料层面是全网粒度。

成员高流动场景（如离职率高的组织）连续踢 N 人 = N 次全网轮换：每次全网密钥切换 + 宽限期 + rekey 风暴，运维开销随成员流动性线性放大。密钥级精细撤销（key_path 单路径撤销）要等 v2 数据面（P4，§3.11.5）；v1/v1.5 期间需要低成本缓解。

## 决策摘要（建议默认值）

1. **轮换合并窗口**：Revoke 触发的全网 key 轮换加 debounce 窗口（建议默认 60s，实现时定）；窗口内多次 Revoke 共享同一次主密钥更换 + `key_version++`，批次末统一生效
2. **吊销即时性不回退**（SEC-16 语义保留）：Revoke 下发、netmap 移除、重连挑战失败、路径 Withdraw（REQ-034 联动）均即时；合并的只是密钥轮换动作
3. **显式 rotate_master_key**（安全事件手动轮换）不走合并窗口，立即执行
4. **边界**：合并只把 O(N) 次轮换摊销为 O(1)，不改变"撤销 = 全网影响面"的粒度本质（粒度收窄 = v2 key_path）

## 验收标准（草案）

- 窗口内 N 次吊销 → 1 次 `key_version++` / 1 次全网 KeyDist
- 被吊销节点即时不可重连、旧会话作废（SEC-16 断言保留）
- 窗口外的吊销各自触发轮换；手动 rotate_master_key 不被合并延迟
- 验收场景：SEC-16 扩展 + 新增场景（合并时落 tests/security/control-plane-attacks.md）

## 关联

- 前置（已 merged）：REQ-022 / REQ-024（吊销语义与 coord 实现落档）
- 升级路径：CONTROL_PLANE §3.11.5 key_path 单路径撤销（v2）；REQ-034 路径撤销联动已落地（路径粒度撤销不受本窗口影响）
