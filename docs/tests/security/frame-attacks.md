# 帧层对抗验证（frame-attacks）

> 覆盖 FRAME_HEADER §3/§5 的安全声明。拓扑：≥2 节点 + 攻击者注入（宿主进程，
> 网段可达性与容器等价）：非成员 = 无密钥材料；成员 = 持 key_dst
> （由主密钥派生，与 KeyDist 下发材料等价）。注入器：e2e/mesh/tenancy/forge.py。

## SEC-01 非成员帧头篡改

- 关联 REQ：REQ-016 / REQ-017
- 测试层：单测 + docker e2e
- 状态：`已覆盖`（2026-10-02）
- 证据：rill-core/src/frame/、e2e/scenarios/frame_attacks.sh、e2e/mesh/tenancy/forge.py
- 说明：在途篡改模型 = 正确 key 构帧后翻转 from_node_id 字节且不重算 route_mac →
  帧头与 route_mac 绑定破坏 → 目的端 `dropped frame: BadRouteMac`（容器级）；
  核心语义单测 route_mac_rejects_tamper / route_mac_path_rejects_path_id_tamper

## SEC-02 非成员伪造完整帧头

- 关联 REQ：REQ-016 / REQ-017
- 测试层：单测 + docker e2e
- 状态：`已覆盖`（2026-10-02）
- 证据：rill-core/src/frame/、rill-mesh/src/data/、e2e/scenarios/frame_attacks.sh、e2e/mesh/tenancy/forge.py
- 说明：random key 伪造（无 key_dst 无法生成合法 route_mac）→ 送达路径（to=本节点）
  与转发路径（to=他节点，转发节点以 key_dst(to) 校验）均 `dropped frame: BadRouteMac`；
  核心语义（FRM-02 单测）+ 跨网密钥分域负对照（tenancy SEC-22）

## SEC-03 成员伪造 from_node_id（数据帧）

- 关联 REQ：REQ-016
- 测试层：单测 + docker e2e
- 状态：`已覆盖`（2026-10-02）
- 证据：rill-mesh/src/data/、e2e/scenarios/frame_attacks.sh
- 说明：成员（持 key_dst 等价材料）伪造 from=受害者：route_mac 合法（正对照——
  BadRouteMac 计数不增长）→ 越过转发面校验 → 目的端会话层拦截
  （`dropped frame: Aead|NoSession|Replay`，载荷 AEAD 无法伪造）；
  握手层冒充单测 bad_binding_rejected_over_wire

## SEC-04 成员篡改 in-flight 帧头并重算 route_mac

- 关联 REQ：REQ-016
- 测试层：单测 + docker e2e
- 状态：`已覆盖`（2026-10-02）
- 证据：rill-core/src/frame/、e2e/scenarios/frame_attacks.sh
- 说明：持 key_dst 者可重算 route_mac 骗过转发面（文档化的有限破坏：转发面 DoS 等价），
  但 AAD = 帧头[0..18]+path_id 与 AEAD 绑定 → 目的端解密失败拦截——容器级以
  正确 key + 垃圾密文注入断言（会话层计数增长 + BadRouteMac 不增长）

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
- 说明：端口分派（CONNECTIVITY §2.1）：首字节 `0x01..=0x0F` → 42B 帧、probe magic（LPRB）→ probe、都不匹配 → 丢弃（fail-closed，CN-02）；单测 `unknown_protocol_dropped`（CON-08）

## SEC-08 解析鲁棒性（fail-closed）

- 关联 REQ：REQ-017 / REQ-059
- 测试层：单测（确定性 fuzz 语料）+ docker e2e
- 状态：`已覆盖`
- 证据：rill-core/src/frame/、rill-core/src/probe.rs、rill-mesh/src/framing/、rill-mesh/src/control/codec/、rill-mesh/src/data/tests.rs、rill-mesh/src/control/server_tests.rs、e2e/scenarios/preauth_flood.sh
- 说明：预认证解析入口（帧头 decode / open_frame / probe decode / 信封定头）按 REQ-059 只做固定头字段级解析；确定性语料 preauth_parse_fuzz_corpus / decode_fuzz_corpus / read_frame_fuzz_corpus / parse_envelope_fuzz_corpus / read_envelope_fuzz_corpus / preauth_dispatch_fuzz_corpus / preauth_garbage_inputs_rejected——随机/变形/截断输入不 panic、错误只经 Result/Option 返回；e2e 未认证洪泛下容器存活、丢帧摘要出现（fail-closed）、已认证流量收敛

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
- 状态：`已覆盖`（2026-10-02）
- 证据：e2e/scenarios/frame_attacks.sh、e2e/mesh/tenancy/forge.py
- 说明：成员向目的端灌 2000 帧未知会话密文（route_mac 合法、载荷垃圾）→ 逐帧
  计数丢弃（会话层计数增长）、三容器存活不 panic、洪泛后已认证流量双栈收敛；
  连接/注册面的限速隔离另见 SEC-20/SEC-29（REQ-047）

## 验收断言

- [x] SEC-01：篡改帧头被转发节点丢弃，目的端无感知（容器级）
- [x] SEC-02：无 key_dst 无法伪造合法 route_mac（容器级，送达+转发路径）
- [x] SEC-03：成员伪装源被目的端 AEAD 拦截（容器级）
- [x] SEC-04：重算 route_mac 的篡改帧被目的端 AEAD 拦截（容器级）
- [x] SEC-05：重放窗口拦截（含 rekey 残留期双窗口）
- [x] SEC-06：rekey 交叠 5s 窗口语义
- [x] SEC-07：非帧/非 probe 字节丢弃（端口分派 fail-closed，CON-08）
- [x] SEC-08：畸形输入不 panic（fuzz 语料 + e2e 洪泛，REQ-059）
- [x] SEC-09：握手重定向拒绝（msg1 目标校验）
- [x] SEC-10：身份绑定验证拒绝冒充 + prologue 混淆拒绝
- [x] SEC-11：垃圾 AEAD 洪泛逐帧丢弃、进程存活、已认证流量收敛（容器级）
