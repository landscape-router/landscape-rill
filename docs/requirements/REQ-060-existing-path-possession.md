# REQ-060 Existing 路径注册持有证明（挑战统一）

> 类型：需求 ｜ 状态：✅ merged ｜ 提出：2026-09-02 ｜ 合并：2026-09-02
> 去向：CONTROL_PLANE §2/§3.1/§3.9/§5.1 ｜ 验收场景：CTL-20 ｜ lessons：CP-02（身份权威在服务端存储——挑战验证锚定存储 pubkey，不信任自报）、CP-05（重连路径状态机——统一触发覆盖恢复路径，退避语义不变）

## 动机

REQ-057 收口时明确标注的另案：挑战恢复只在 Fresh 分支（未知 pubkey）触发，**Existing 分支（已知 pubkey 的幂等重注册）无任何持有证明**——Existing 路径仅比对 capabilities/routes 字节，认证后直接发放 node_id 与 identity_binding。

重验结论（2026-09-02）：缺口真实但威胁模型收敛为**成员间横向**——利用需同时持有①同网络有效 reusable auth key（成员凭据）②受害者 pubkey（公开）③精确匹配的 capabilities/routes（不匹配即拒）；收益上限为受害者网络视图（netmap push）与 opt-in 广播密钥泄露；数据面不可冒用（noise 握手需 static 私钥）、binding 不受污染（coord Ed25519 签发）。"身份恢复必须证明私钥持有"应是显式设计不变量而非实现巧合（REQ-058 同款教训：隐式安全随演进失效——联邦 v2、REQ-048 轮换等任何复用重注册语义的特性都会无声继承）。

## 决策摘要

实施范围经用户拍板取 **B（统一全挑战）**：凡 REGISTER 且本连接未证明持有 → 一律挑战，**含首次注册（新建类）**——"无持有证明不发身份"无例外，顺带阻断公钥抢注（squatting）。分两类完成语义：恢复类（pubkey 命中）验证后做幂等比对、按条目回响应、不校验 key 有效性；新建类（pubkey 未命中）key 只读校验后挑战，验证通过才执行完整准入（一次性 key 消费后置于 PoP）。caps/routes 比对后置到 PoP 之后（消除认证前配置比对 oracle）。wire 零改动（Challenge.node_id 复用 REQ-057 字段，新建类填 0）；代价：每次首注册/重注册 +1 RTT（低频路径，可接受）。机制完全复用 REQ-057（ChallengeState 绑定存储 pubkey，X25519 DH 挑战 + HMAC tag）。

## 验收标准（已落地，2026-09-02）

- 单测：恢复类对抗（有效 reusable key + 受害者 pubkey + 精确 caps/routes → 挑战 → 无私钥 tag 必败，身份无扰动）/ 新建类 PoP 前置（挑战未通过 key 不消费，通过后才准入）/ 幂等比对后置（caps 变更 PoP 后拒绝）——rill-mesh/src/control/server.rs
- e2e：direct/relay/persist/recover 本地全绿；CI e2e-mesh 八场景全绿（run 33679179273）
- CI：check + e2e-mesh 双绿（同 run）
