# REQ-057 注册响应丢失的挑战恢复（one-time key 幂等恢复）

> 类型：缺陷 ｜ 状态：📌 proposed ｜ 优先级：P2 ｜ 依赖：无（与 REQ-056 独立，e2e 场景共享） ｜ 提出：2026-09-02

## 动机

one-time auth key 在注册成功即刻消费并持久化 tombstone（rill-core/src/control/registry.rs:191-193，先于响应写出）。若 REGISTER_RESPONSE 在途中丢失，客户端处于 Fresh 态（`Registered` 事件未触发，node_id 未知），重试链路为：

```
重发 REGISTER(同 key, pubkey)
→ registry 查表 InvalidAuthKey（tombstone 遮蔽 pubkey 幂等路径，:170 先于 :171）
→ 服务端挑战分支（server.rs:314-345，为此场景设计，不计失败锁定）
→ 客户端 challenge_ack 无 node_id 填 0（client.rs:89-91）
→ 服务端按自报 node_id 反查 static_pubkey_of(0) → 查无 → PermissionDenied
→ 断线 → （叠加 REQ-056 缺陷）热循环
```

**恢复机制已存在但在最需要它的场景恰好不可用**：身份解析依赖客户端自报 node_id，而 node_id 正是丢失的东西。结果是一次 ack 丢失 = 该节点永久无法注册（只能人工换 key），CI 中即 persist 场景永久失败。

## 决策摘要（建议默认值）

对标业界标准形态（Tailscale：一次性 join token + 密钥对持有证明恢复；Stripe 幂等键重放 + 重试者认证）：

1. **ChallengeState 绑定触发 REGISTER 的 pubkey**（rill-mesh/src/control/server.rs）：服务端发起挑战时 pubkey 已在作用域内；验证时按**存储的 pubkey** 解析身份，不再信任自报 node_id
2. **Challenge 消息增 `node_id` 字段**（crate <2.x，wire 可改）：客户端用它计算 tag 并 `RegisterOk{node_id}` 写入会话——Fresh 态恢复后客户端真正持有自己的 node_id。node_id 非机密（netmap 本就下发），tag 的安全锚是 static 私钥持有证明
3. **安全性不变式**：
   - 零新增暴露（不触碰 registry 查表顺序——`Existing` 路径无持有证明的既有缺口不扩大，另案处理）
   - 恢复路径带认证（挑战 tag = X25519 DH + HMAC 持有证明，强于重放）
   - tombstone 对第二身份语义不变：同 key + 异 pubkey → "unknown pubkey" 拒绝（persist 场景阶段 4 断言保持）
   - 进程重启同样覆盖：身份锚是密钥对不是内存状态，新进程重发同 key 即进挑战分支

## 非目标

- registry `Existing` 路径补私钥持有证明（pubkey 冒充的既有缺口，独立安全议题另立）
- coord 主动重发响应 / 注册响应持久化重放
- 客户端 node_id 落盘（挑战恢复已覆盖）

## 开放问题（立项评审拍板）

1. **故障注入开关的位置**：e2e recover 场景需要 coord「丢弃首个 REGISTER_RESPONSE」——server 层 env-gated 开关 vs 测试专用构造注入（倾向后者，避免生产二进制带 e2e 钩子）
2. **挑战窗口内重复触发**：同一节点在挑战未完成时再连一条发 REGISTER，`state.challenge` 按连接隔离是否足够（当前 per-connection state，预期无跨连接泄漏，评审确认）

## 验收标准（草案）

- rill-mesh 单测：Fresh 态（无 node_id）收到带 node_id 的 Challenge → tag 计算正确 + RegisterOk 写入会话
- rill-mesh 单测：服务端按存储 pubkey 解析身份验证 tag；tag 错误 / 窗口外拒绝
- rill-mesh 单测：同 key 异 pubkey 重放 → 拒绝（unknown pubkey，不计锁定路径不变）
- e2e **recover** 场景（与 REQ-056 共享）：coord 注入丢弃首个 REGISTER_RESPONSE → 客户端断线退避重连（间隔断言 ≥1s，验收 REQ-056）→ 挑战恢复拿到原 node_id → mesh 收敛、无新注册（node_id 不变）
