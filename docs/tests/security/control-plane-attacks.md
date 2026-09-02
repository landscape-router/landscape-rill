# 控制面对抗验证（control-plane-attacks）

> 覆盖 CONTROL_PLANE §2（TLS 信任锚/版本协商/重连认证）、§6（安全模型）、FRAME_HEADER §2.4（握手规格）。
> 拓扑：coordinator + 节点容器 + 伪 coordinator 容器。

## SEC-12 伪 coordinator 钓鱼

- 关联 REQ：REQ-017
- 测试层：docker e2e
- 状态：`待补充`
- 证据：—
- 缺口：容器级复验（TLS 信任锚校验逻辑已实现：自签 CA 预置/公网 PKI，见 rill-mesh/src/control/）
- 说明：无有效证书/未预置 CA → TLS 验证失败拒绝连接；auth key 不泄露

## SEC-13 auth key 复用/过期

- 关联 REQ：REQ-004
- 测试层：单测
- 状态：`已覆盖`
- 证据：rill-core/src/control/registry.rs
- 说明：一次性 key 二次注册被拒；吊销联动（Revoke 后相关 key 失效）

## SEC-14 重连认证（X25519 静态 DH 挑战）

- 关联 REQ：REQ-018 / REQ-022
- 测试层：单测 + e2e
- 状态：`已覆盖`
- 证据：rill-core/src/control/challenge.rs
- 说明：合法节点构造合法 tag 通过；无静态私钥者无法构造；验证方用推导 eph_pub（不回信声称值）

## SEC-15 重放 challenge

- 关联 REQ：REQ-018 / REQ-022
- 测试层：单测
- 状态：`部分覆盖`
- 证据：rill-core/src/control/challenge.rs
- 缺口：时间窗口语义核心已闭环；容器级重放复验待补

## SEC-16 吊销立即生效

- 关联 REQ：REQ-022 / REQ-024
- 测试层：单测 + e2e
- 状态：`已覆盖`
- 证据：rill-core/src/control/revoke.rs、rill-coord/src/coordinator/
- 说明：重连挑战验签失败（注册表已移除）；既有会话触发 Noise rekey 作废；netmap 条目移除

## SEC-17 版本不兼容

- 关联 REQ：REQ-013
- 测试层：单测 + 集成
- 状态：`部分覆盖`
- 证据：rill-core/src/handshake/
- 缺口：握手层 prologue 版本不匹配拒绝已闭环（跨网络/跨版本互不相认）；**控制面首消息版本协商未实现**
- 说明：明确报错（非静默失败）、不进入半工作状态

## SEC-18 租约欺骗

- 关联 REQ：REQ-004
- 测试层：docker e2e
- 状态：`待补充`
- 证据：—
- 缺口：伪造心跳延长他人在线状态的容器级验证（心跳随已认证 TLS 会话内发送，伪造应失败）

## SEC-19 畸形控制消息

- 关联 REQ：REQ-017 / REQ-047
- 测试层：单测
- 状态：`部分覆盖`
- 证据：rill-mesh/src/framing/、rill-mesh/src/control/server.rs
- 缺口：帧长上限 1MB/truncated/oversize 拒绝已闭环；连接级消息限速（速率维度）已闭环（REQ-047，断连 + 其他连接不受影响，单测 `conn_message_flood_disconnects`）；随机洪泛 fuzz 待补
- 说明：解析失败断开该连接、coordinator 进程不 panic、其他连接不受影响

## SEC-20 auth key 爆破

- 关联 REQ：REQ-004 / REQ-047
- 测试层：单测
- 状态：`已覆盖`
- 证据：rill-mesh/src/control/server.rs、rill-coord/src/coordinator/
- 说明：连续失败（未知 key + 未知 pubkey）≥5 → 源 IP 递增锁定（30s×2ⁿ 封顶 1h，成功清零、挑战路径不计失败），锁定期间注册一律拒绝（单测 `register_failures_lockout_after_repeated_bad_keys`）；错误响应统一措辞——不可解析/过期/未知网络/已消费一律 `InvalidAuthKey`（单测 `expired_key_rejected_at_admission`，无信息泄露）；per-源 IP 注册限速 0.5/s 突发 5（CONTROL_PLANE §3.13）

## SEC-29 控制面消息限速与准入配额

- 关联 REQ：REQ-047
- 测试层：单测
- 状态：`已覆盖`
- 证据：rill-mesh/src/control/server.rs、rill-node/src/runtime/、rill-coord/src/path_service.rs
- 说明：连接级令牌桶（20/s 突发 40，桶空断连单连接隔离）；心跳超频忽略（< 5s 间隔零成本跳过——无快照/LEASE 推送，租约语义不变）；PathRequest pending 上限（节点 256 / coordinator per-source 1024 饱和丢弃，取走后恢复）；单测 `conn_message_flood_disconnects` / `heartbeat_overspeed_ignored` / `path_request_pending_capped` / `pending_events_capped_per_source`

## SEC-30 吊销键规范化对抗（重编码绑定绕过）

- 关联 REQ：REQ-058
- 测试层：单测
- 状态：`待补充`
- 证据：—
- 缺口：吊销后以重编码/变形签名绑定尝试入网 → 拒绝语义不变（吊销按 node_id 生效，与编码无关）；pubkey 单字节翻转查无；换 signer 重签 binding 不影响身份解析与幂等判定

## 验收断言

- [ ] SEC-12：伪 coordinator 拒绝连接、auth key 不泄露、日志明确报信任锚失败（容器级）
- [x] SEC-13：一次性 key 二次使用被拒、吊销联动
- [x] SEC-14：DH 挑战闭环、无私钥者无法构造 tag
- [ ] SEC-15：重放旧 challenge 被拒（时间窗口 + 一次性临时密钥，容器级复验待补）
- [x] SEC-16：吊销立即生效（重连失败、旧会话作废、条目移除）
- [ ] SEC-17：版本不兼容明确报错（控制面首消息协商待实现）
- [ ] SEC-18：伪造心跳无法延长在线状态（容器级）
- [ ] SEC-19：畸形消息不 panic、单连接隔离（fuzz 待补；限速断连已闭环）
- [x] SEC-20：错误 auth key 限速锁定且无信息泄露（递增锁定 + 统一措辞 InvalidAuthKey）
- [x] SEC-29：连接级限速断连、心跳超频忽略、PathRequest pending 上限（REQ-047）
- [ ] SEC-30：重编码绑定无法绕过吊销（键规范化，REQ-058）
