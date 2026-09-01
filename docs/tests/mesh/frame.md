# mesh 数据面验证（frame）

> 帧头/握手/会话/广播/转发路径的功能验证。对抗场景见 [../security/frame-attacks.md](../security/frame-attacks.md)。
> 设计规范：FRAME_HEADER（[../../design/mesh/frame-header.md](../../design/mesh/frame-header.md)）。

## FRM-01 帧头编解码与字段语义

- 关联 REQ：REQ-001 / REQ-002
- 测试层：单测
- 状态：`已覆盖`
- 证据：rill-core/src/frame/
- 说明：帧头 roundtrip、固定 34B、多字节字段大端、XDP 固定偏移

## FRM-02 route_mac 认证（篡改拒绝/ttl 置零）

- 关联 REQ：REQ-002 / REQ-003
- 测试层：单测 + 集成
- 状态：`已覆盖`
- 证据：rill-core/src/crypto/、rill-mesh/src/data/
- 说明：双 siphash-2-4 官方向量交叉验证；篡改任一认证字段拒绝；ttl 递减后转发仍可校验

## FRM-03 AEAD 载荷认证

- 关联 REQ：REQ-001 / REQ-017
- 测试层：单测
- 状态：`已覆盖`
- 证据：rill-core/src/frame/、rill-core/src/handshake/
- 说明：AAD/密钥/盐错误拒绝、fail-closed 截断拒绝

## FRM-04 握手流程（Noise_XX 全规格）

- 关联 REQ：REQ-001 / REQ-029
- 测试层：单测 + 集成
- 状态：`已覆盖`
- 证据：rill-core/src/handshake/
- 说明：msg1 目标校验/msg3 身份绑定交叉验证/prologue 混淆拒绝/密钥对称/无发起方 msg2 拒绝

## FRM-05 重放窗口与会话计数

- 关联 REQ：REQ-002
- 测试层：单测
- 状态：`已覆盖`
- 证据：rill-core/src/frame/、rill-core/src/handshake/
- 说明：seq 重放拦截、方向计数器不重用

## FRM-06 rekey 双窗口交叠

- 关联 REQ：REQ-011 / REQ-029
- 测试层：单测
- 状态：`已覆盖`
- 证据：rill-core/src/handshake/
- 说明：新钥立即生效/旧钥 5s 残留内可解/过期销毁/双窗口各自滑动

## FRM-07 心跳帧（数据面 keepalive）

- 关联 REQ：REQ-014 / REQ-017
- 测试层：单测 + 集成
- 状态：`已覆盖`
- 证据：rill-mesh/src/data/
- 说明：AEAD 空载荷、仅已建会话对、3 次 miss 拆会话

## FRM-08 广播泛洪（opt-in/去重/限速）

- 关联 REQ：REQ-032 / REQ-035
- 测试层：单测 + e2e
- 状态：`部分覆盖`
- 证据：rill-mesh/src/data/、e2e/run_e2e.sh
- 缺口：**广播 opt-in（REQ-035）实现待落地**——keydist 按需下发 broadcast_key、泛洪目标收窄未实现；当前仅为 v0.7 全量下发语义
- 说明：去重 30s、ttl 不向源回泛、令牌桶 64/16/s、组播指纹防再泛洪已闭环

## FRM-09 数据面转发路径 relay()

- 关联 REQ：REQ-028
- 测试层：单测 + 回环集成
- 状态：`已覆盖`
- 证据：rill-mesh/src/data/
- 说明：A→relay→B 转发、ttl 递减不重签、丢弃原因 fail-closed（BadVersion/BadRouteMac/TtlExpired/NoEndpoint/NoKeyDst/Short）

## FRM-10 IPv6 双栈 mesh e2e

- 关联 REQ：REQ-032
- 测试层：docker e2e
- 状态：`已覆盖`
- 证据：e2e/run_e2e.sh
- 说明：双栈前缀公告、ping + ping6 0% 丢包；单播无需 ND（POINTOPOINT TUN）

## FRM-11 编排全链路主机测试

- 关联 REQ：REQ-030
- 测试层：单测（pump 驱动）
- 状态：`已覆盖`
- 证据：rill-node/src/runtime/
- 说明：TLS 注册→netmap→keydist→端点上报→心跳收敛→懒握手→加密帧双向；数据面心跳 3 次 miss 拆会话

## 验收断言

- [x] FRM-01：帧头 roundtrip 与固定偏移断言成立
- [x] FRM-02：篡改任何认证字段（ttl 除外）即拒绝；ttl 置零参与认证
- [x] FRM-03：AAD/密钥错误解密失败，截断输入 fail-closed
- [x] FRM-04：msg1 目标 node_id 校验 + msg3 绑定交叉验证 + prologue 混淆拒绝
- [x] FRM-05：seq 重放窗口拦截，回绕语义正确
- [x] FRM-06：rekey 双窗口 5s 交叠语义（残留内可解、过期丢弃）
- [x] FRM-07：心跳仅会话对、AEAD 空载荷、3 次 miss 拆会话
- [ ] FRM-08：未 opt-in 节点不收 broadcast_key；泛洪只达 opt-in 端点（REQ-035 待落地）
- [x] FRM-09：转发路径丢弃原因显式化，ttl 递减不重签
- [x] FRM-10：IPv4 + IPv6 全链路 0% 丢包
- [x] FRM-11：注册→握手→加密帧全链路主机闭环
