# 控制面对抗验证（control-plane-attacks）

> 覆盖 CONTROL_PLANE §2（TLS 信任锚/版本协商/重连认证）、§6（安全模型）、FRAME_HEADER §2.4（握手规格）。
> 拓扑：coordinator + 节点容器 + 伪 coordinator（宿主 rogue TLS，网段可达性与容器等价）。

## SEC-12 伪 coordinator 钓鱼

- 关联 REQ：REQ-017
- 测试层：docker e2e
- 状态：`已覆盖`（2026-10-02）
- 证据：rill-mesh/src/control/tls.rs、e2e/scenarios/coord_attacks.sh
- 说明：node-c 被钓鱼指向宿主 rogue TLS（自签证书，SAN 仿冒 DNS:coord + 网关 IP）——
  TLS 尝试发生（rogue 连接计数 ≥2）但节点证书验证失败即断连：rogue 应用层收到零字节
  （auth key 不泄露）、node-c 永不注册（重连退避摘要 `control connect failed`）、
  真 coordinator 与 a/b 不受影响

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
- 状态：`已覆盖`（2026-10-02）
- 证据：rill-core/src/control/challenge.rs
- 说明：重放旧 challenge 被拒（时间窗口 + 一次性临时密钥）——单测
  window_boundary / wrong_nonce_rejected / wrong_eph_priv_rejected / wrong_node_id_rejected
  覆盖窗口边界与 tag 绑定语义；容器级重放结构性不可达：控制消息只在已认证 TLS 会话内
  传输（rustls 拒绝记录重放），challenge 临时密钥按连接一次性签发

## SEC-16 吊销立即生效

- 关联 REQ：REQ-022 / REQ-024
- 测试层：单测 + e2e
- 状态：`已覆盖`
- 证据：rill-core/src/control/revoke.rs、rill-coord/src/coordinator/
- 说明：重连挑战验签失败（注册表已移除）；既有会话触发 Noise rekey 作废；netmap 条目移除

## SEC-17 版本不兼容

- 关联 REQ：REQ-013
- 测试层：单测 + 集成
- 状态：`已覆盖`（2026-10-02）
- 证据：rill-core/src/handshake/、rill-mesh/src/control/server.rs、rill-mesh/src/control/server_tests.rs
- 说明：握手层 prologue 版本不匹配拒绝已闭环（跨网络/跨版本互不相认）；控制面首消息版本协商（CONTROL_PLANE §2）——REGISTER 携带 `protocol_version` 不匹配即明确报错断连（`protocol version mismatch: client X server Y`），不进半工作状态、不计入 auth key 失败锁定（升级节点非攻击者）；单测 `register_rejects_protocol_version_mismatch`（新旧两个方向 + 无锁定）

## SEC-18 租约欺骗

- 关联 REQ：REQ-004
- 测试层：docker e2e
- 状态：`已覆盖`（2026-10-02）
- 证据：rill-mesh/src/control/server.rs、e2e/scenarios/coord_attacks.sh
- 说明：心跳以**连接注册态**归因（`state.registered`），新 TLS 连接无身份 →
  未注册连接灌 HEARTBEAT 为无操作（coord 存活、数据面不变）；node-a 停机 +
  持续伪造心跳（110s 窗口）→ 租约照常 60s 过期、b→a ping 断——伪造无法延长在线状态

## SEC-19 畸形控制消息

- 关联 REQ：REQ-017 / REQ-047
- 测试层：单测 + docker e2e
- 状态：`已覆盖`（2026-10-02）
- 证据：rill-mesh/src/framing/、rill-mesh/src/control/server.rs、rill-mesh/src/control/server_tests.rs、e2e/scenarios/preauth_flood.sh
- 说明：帧长上限 1MB/truncated/oversize 拒绝；连接级消息限速（REQ-047，断连 +
  其他连接不受影响，单测 `conn_message_flood_disconnects`）；确定性 fuzz 语料
  （REQ-059：parse/read/dispatch envelope 语料，随机/变形/截断不 panic）；e2e
  容器级随机洪泛（裸 TCP 垃圾 + TLS 后超长帧/垃圾信封/垃圾 REGISTER 体 → coord
  断连不崩、闸门摘要正常）

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
- 状态：`已覆盖`
- 证据：rill-core/src/control/registry.rs
- 说明：单测 identity_lookup_uses_raw_pubkey_bytes（pubkey 单字节翻转查无，binding 锚定原始字节）+ binding_bytes_not_a_registry_key（换 signer 重签 binding 不影响身份解析与幂等判定；吊销按 node_id 生效，原/重编码绑定一律查无）——吊销键 = node_id，与编码无关

## SEC-32 批量吊销合并轮换（REQ-048）

- 关联 REQ：REQ-048 / REQ-022
- 测试层：单测
- 状态：`已覆盖`
- 证据：rill-coord/src/keys.rs、rill-coord/src/coordinator/tests.rs
- 说明：窗口内 N 次吊销 → 1 次 key_version++（首条定窗不延期）；吊销即时性不回退（条目移除/netmap bump/路径 Withdraw 即时，轮换批次末生效）；窗口外吊销各自轮换；显式 rotate_master_key 立即生效并吸收挂起窗口；deadline 落盘重启自愈（事件驱动点评估，无后台任务）

## 验收断言

- [x] SEC-12：伪 coordinator 拒绝连接、auth key 不泄露（rogue 应用层零字节，容器级）
- [x] SEC-13：一次性 key 二次使用被拒、吊销联动
- [x] SEC-14：DH 挑战闭环、无私钥者无法构造 tag
- [x] SEC-15：重放旧 challenge 被拒（窗口 + 一次性临时密钥单测；TLS 会话内传输结构性防重放）
- [x] SEC-16：吊销立即生效（重连失败、旧会话作废、条目移除；轮换合并窗口不回退即时性，REQ-048）
- [x] SEC-32：批量吊销合并轮换（N 吊销 → 1 轮换；即时语义不变；手动轮换旁路；重启自愈，REQ-048）
- [x] SEC-17：版本不兼容明确报错（握手 prologue + 控制面首消息版本协商均闭环）
- [x] SEC-18：伪造心跳无法延长在线状态（未注册无操作 + 停机续命失败，容器级）
- [x] SEC-19：畸形消息不 panic、单连接隔离（fuzz 语料 + 容器级随机洪泛 + 限速断连）
- [x] SEC-20：错误 auth key 限速锁定且无信息泄露（递增锁定 + 统一措辞 InvalidAuthKey）
- [x] SEC-29：连接级限速断连、心跳超频忽略、PathRequest pending 上限（REQ-047）
- [x] SEC-30：重编码绑定无法绕过吊销（键规范化，REQ-058）
