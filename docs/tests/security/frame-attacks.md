# 帧层对抗验证（frame-attacks）

> 覆盖 FRAME_HEADER §3/§5 的安全声明。拓扑：≥2 节点 + 1 个非成员攻击者容器 + 1 个成员攻击者容器。

## SEC-01 非成员帧头篡改

- 关联 REQ：REQ-016 / REQ-017
- 测试层：docker e2e
- 状态：`待补充`
- 证据：—
- 缺口：容器级复验（核心单测已覆盖校验逻辑，见 SEC-05 说明）
- 说明：攻击者截获/改写帧头字段（to/from/seq/len）→ 转发节点 route_mac 校验失败丢弃

## SEC-02 非成员伪造完整帧头

- 关联 REQ：REQ-016 / REQ-017
- 测试层：docker e2e
- 状态：`待补充`
- 证据：—
- 缺口：容器级复验（无 key_dst 无法生成合法 route_mac 的核心语义已由 FRM-02 单测覆盖）

## SEC-03 成员伪造 from_node_id（数据帧）

- 关联 REQ：REQ-016
- 测试层：docker e2e
- 状态：`待补充`
- 证据：—
- 缺口：成员伪装 A 发往 B 的容器级复验；核心语义（AEAD 解密失败丢弃）由单测覆盖

## SEC-04 成员篡改 in-flight 帧头并重算 route_mac

- 关联 REQ：REQ-016
- 测试层：docker e2e
- 状态：`待补充`
- 证据：—
- 缺口：容器级复验（AAD 破坏 → 目的端 AEAD 失败的核心语义已由 FRM-02 单测覆盖）

## SEC-05 重放攻击

- 关联 REQ：REQ-029
- 测试层：单测（主机已闭环）
- 状态：`已覆盖`
- 证据：rill-core/src/handshake/、rill-mesh/src/data/
- 说明：session_roundtrip_and_replay_rejected / rekey_dual_window_semantics / replayed_data_frame_dropped

## SEC-06 rekey 交叠

- 关联 REQ：REQ-029
- 测试层：单测（主机已闭环）
- 状态：`已覆盖`
- 证据：rill-core/src/handshake/
- 说明：rekey_dual_window_semantics（新钥立即生效/旧钥残留内可解/过期丢弃/窗口各自滑动）

## SEC-07 明文注入

- 关联 REQ：REQ-014 / REQ-017 / REQ-046
- 测试层：单测 + 集成
- 状态：`已覆盖`
- 证据：rill-mesh/src/framing/、rill-mesh/src/data/
- 说明：端口分派（CONNECTIVITY §2.1）：首字节 `0x01..=0x0F` → 34B 帧、probe magic（LPRB）→ probe、都不匹配 → 丢弃（fail-closed，CN-02）；单测 `unknown_protocol_dropped`（CON-08）

## SEC-08 解析鲁棒性（fail-closed）

- 关联 REQ：REQ-017
- 测试层：单测（fuzz 待补）
- 状态：`部分覆盖`
- 证据：rill-core/src/frame/、rill-mesh/src/data/
- 缺口：截断/越界拒绝已闭环；随机字节洪泛 fuzz 与容器级复验待补

## SEC-09 握手重定向

- 关联 REQ：REQ-016 / REQ-029
- 测试层：单测（主机已闭环）
- 状态：`已覆盖`
- 证据：rill-core/src/handshake/、rill-mesh/src/data/
- 说明：msg1_wrong_target_rejected / handshake_redirect_rejected

## SEC-10 握手冒充（身份绑定）

- 关联 REQ：REQ-016 / REQ-029
- 测试层：单测（主机已闭环）
- 状态：`已覆盖`
- 证据：rill-core/src/handshake/、rill-mesh/src/data/
- 说明：bad_binding_rejected / binding_static_must_match_noise_static / bad_binding_rejected_over_wire；跨网络/跨版本混淆 prologue_mismatch_rejected

## SEC-11 垃圾 AEAD 洪泛

- 关联 REQ：REQ-017
- 测试层：docker e2e
- 状态：`待补充`
- 证据：—
- 缺口：成员向目的端灌未知会话密文的容器级验证；接收端限速生效验证

## 验收断言

- [ ] SEC-01：篡改帧头被转发节点丢弃，目的端无感知（容器级）
- [ ] SEC-02：无 key_dst 无法伪造合法 route_mac（容器级）
- [ ] SEC-03：成员伪装源被目的端 AEAD 拦截（容器级）
- [ ] SEC-04：重算 route_mac 的篡改帧被目的端 AEAD 拦截（容器级）
- [x] SEC-05：重放窗口拦截（含 rekey 残留期双窗口）
- [x] SEC-06：rekey 交叠 5s 窗口语义
- [x] SEC-07：非帧/非 probe 字节丢弃（端口分派 fail-closed，CON-08）
- [ ] SEC-08：畸形输入不 panic（fuzz 待补）
- [x] SEC-09：握手重定向拒绝（msg1 目标校验）
- [x] SEC-10：身份绑定验证拒绝冒充 + prologue 混淆拒绝
- [ ] SEC-11：垃圾 AEAD 洪泛被限速丢弃（容器级）
