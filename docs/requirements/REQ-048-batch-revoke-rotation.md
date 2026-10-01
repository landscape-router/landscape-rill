# REQ-048 批量吊销合并轮换

- 类型：需求
- 状态：✅ merged
- 提出日期：2026-09-01
- 合并日期：2026-10-01
- 去向：CONTROL_PLANE §5.5
- 验收场景：SEC-32（tests/security/control-plane-attacks.md）

## 动机

v1 吊销 = 全网密钥轮换（`key_version++` → 全网 KeyDist 重下发 + 相关节点对 Noise rekey）。成员高流动场景（如离职率高的组织）连续踢 N 人 = N 次全网轮换 + 宽限期 + rekey 风暴，运维开销随流动性线性放大。密钥级精细撤销（key_path 单路径）要等 v2 数据面（§3.11.5）；v1/v1.5 期间需要低成本缓解。

## 决策摘要

Revoke 触发的全网轮换加 60s 固定合并窗口：首条吊销定窗，窗口内多次吊销共享一次 `key_version++`，批次末统一生效（事件驱动评估，deadline 落盘重启自愈）；吊销即时语义不回退（SEC-16 不变）；显式 `rotate_master_key` 不走窗口（立即生效并吸收挂起窗口）。v1 吊销轮换 = 版本空间递增，主密钥材料更换仍仅显式 rotate（配置权威）。

- lessons 复核（合并时）：KC-06（吊销键仍为 node_id，未引入编码键）、AO-07（吊销即时生效语义保留）
