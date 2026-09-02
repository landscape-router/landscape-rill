# REQ-057 注册响应丢失的挑战恢复（one-time key 幂等恢复）

> 类型：缺陷 ｜ 状态：✅ merged ｜ 提出：2026-09-02 ｜ 合并：2026-09-02
> 去向：CONTROL_PLANE §3.9/§5.1 ｜ 验收场景：CTL-19 ｜ lessons：CP-02（身份解析以服务端存储为准，不信任自报 node_id）

## 动机

one-time key 注册成功即刻消费+持久化（先于响应写出）。REGISTER_RESPONSE 丢失后客户端处于 Fresh 态（node_id 未知），重试进挑战分支但 challenge_ack 无 node_id 填 0，服务端按自报 0 反查查无 → 拒绝 → 死循环。**恢复机制已存在但在最需要它的场景恰好不可用**：身份解析依赖客户端自报 node_id，而那正是丢失的东西——一次 ack 丢失 = 节点永久无法注册。

## 决策摘要

ChallengeState 绑定触发 REGISTER 的 pubkey，身份按服务端存储解析；Challenge 消息增 `node_id` 字段（crate <2.x，wire 可改）——客户端用它计算 tag 并 RegisterOk 写入会话。安全性：零新增暴露（不触碰 registry 查表顺序）、恢复带私钥持有证明（强于重放）、tombstone 对第二身份语义不变、进程重启同样覆盖（身份锚是密钥对不是内存状态）。对标 Tailscale 一次性 join token + machine key 持有证明恢复。e2e 故障注入走 coord env 开关（仅 e2e 文档化）。

## 验收标准（已落地，2026-09-02）

- 单测：ack-loss 挑战恢复（原 node_id + 补发 REGISTER_RESPONSE + binding 非空）/ 坏 tag 断连 / 同 key 异 pubkey 拒——rill-mesh/src/control/server.rs
- e2e recover：注入丢弃首响应 → 退避重连 → 挑战恢复无新注册 → a↔b 双栈通；persist 阶段 3 断言 node_id 一致 + coord "challenge ok" 证据
- CI：e2e-mesh 八场景全绿（run 33668466083）
