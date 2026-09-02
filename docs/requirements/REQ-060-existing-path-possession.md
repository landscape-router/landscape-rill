# REQ-060 Existing 路径注册持有证明（挑战统一）

> 类型：需求 ｜ 状态：📌 proposed ｜ 优先级：P1 ｜ 依赖：— ｜ 提出：2026-09-02

## 动机

REQ-057 收口时明确标注的另案：挑战恢复只在 Fresh 分支（未知 pubkey）触发，**Existing 分支（已知 pubkey 的幂等重注册）无任何持有证明**——`registry.rs` 的 Existing 路径仅比对 capabilities/routes 字节，认证后直接发放 node_id 与 identity_binding。

重验结论（2026-09-02）：缺口真实但威胁模型收敛为**成员间横向**——利用需同时持有①同网络有效 reusable auth key（成员凭据）②受害者 pubkey（公开）③精确匹配的 capabilities/routes（不匹配即拒）；收益上限为受害者网络视图（netmap push）与 opt-in 广播密钥泄露；数据面不可冒用（noise 握手需 static 私钥）、binding 不受污染（coord Ed25519 签发）。

尽管当前风险有界，"**身份恢复必须证明私钥持有**"应是显式设计不变量而非实现巧合：与 REQ-058 同理，当前实现安全属隐式安全，缺一条硬规则约束未来演进（联邦 v2 条目交换、租户模型扩展等任何引入新身份恢复路径的改动）。修复成本极低——REQ-057 的挑战机制天然兼容（验证锚定服务端存储身份，攻击者无私钥必败）。

## 决策摘要（建议默认值）

1. **触发条件统一**：凡 REGISTER 且本连接未证明 static key 持有 → 服务端回 Challenge；Fresh（未知 pubkey）与 Existing（已知 pubkey）同规则。控制面 TLS 连接建立不等于身份证明
2. **验证锚定存储身份**：挑战验证对象是服务端存储的 pubkey（REQ-057 的 `ChallengeState{node_id, pubkey}` 语义原样复用）——客户端自报内容不影响验证目标
3. **验证通过统一走补发 REGISTER_RESPONSE**：幂等语义不变（capabilities/routes 一致 → 原 node_id；不一致仍拒绝）；Fresh 与 Existing 后续处理归一
4. **代价声明**：幂等重注册（进程重启/重连）多一次 RTT——低频路径，可接受
5. **wire 零改动**：Challenge/ChallengeAck 消息与客户端 challenge_ack 逻辑（REQ-057 已改为依赖消息内 node_id）完全复用

## 验收标准（草案）

- 对抗单测：持有效 reusable key + 受害者已知 pubkey + 精确匹配 capabilities/routes 的 Existing REGISTER → 服务端回 Challenge；错误签名/无私钥 → 永不获得 node_id 与 identity_binding（不发 REGISTER_RESPONSE）
- 正当恢复单测：私钥持有者 Existing 重注册 → 挑战通过 → 补发 REGISTER_RESPONSE，node_id 与绑定不变（扩展现有 REQ-057 harness 至 Existing 分支）
- e2e 回归：persist 场景 node-c 重启恢复（现走 Existing 路径，改为先挑战）行为不回退；recover/direct/relay 全绿

## 关联

- 设计锚点：CONTROL_PLANE §3.9（Challenge/ChallengeAck）、§3.1（RegisterRequest/RegisterResponse）
- 关联 REQ：REQ-057（merged——本项为其明确标注的另案收口，机制完全复用）
- lessons：CP-02（节点 ID 冲突的架构规避 = pubkey 查表优先；本项补齐其持有证明半边）
- 提出背景：REQ-057 落地时重验（2026-09-02），同日与 REQ-058/059 同批立项
