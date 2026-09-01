# mesh 控制面验证（control-plane）

> 注册/netmap/keydist/租约/吊销/租户/重连的验收场景。
> 设计规范：CONTROL_PLANE（[../../design/mesh/control-plane.md](../../design/mesh/control-plane.md)）。

## CTL-01 节点注册（auth key 预授权）

- 关联 REQ：REQ-004 / REQ-024 / REQ-027
- 测试层：单测 + 集成 + e2e
- 状态：`已覆盖`
- 证据：rill-core/src/control/registry.rs、rill-mesh/src/control.rs、e2e/run_e2e.sh
- 说明：注册返回 node_id + 身份绑定签名；重复注册幂等（同 auth key + 同公钥返回相同结果）

## CTL-02 auth key 一次性/可复用语义

- 关联 REQ：REQ-004
- 测试层：单测
- 状态：`已覆盖`
- 证据：rill-core/src/control/registry.rs

## CTL-03 netmap 全量推送 + 版本号

- 关联 REQ：REQ-004
- 测试层：单测 + e2e
- 状态：`已覆盖`
- 证据：rill-coord/src/coordinator.rs
- 说明：新节点加入后 version++，所有节点收敛到同一版本；幂等重注册不 bump

## CTL-04 断线重连补偿

- 关联 REQ：REQ-004 / REQ-030
- 测试层：单测 + e2e
- 状态：`已覆盖`
- 证据：rill-node/src/runtime.rs
- 说明：重连传上次 node_id 走幂等注册或挑战；netmap/keydist 全量补偿

## CTL-05 心跳/租约离线判定

- 关联 REQ：REQ-004
- 测试层：单测 + e2e
- 状态：`已覆盖`
- 证据：rill-coord/src/coordinator.rs、rill-node/src/runtime.rs
- 说明：超租约标记离线（条目保留），复活恢复在线；随心跳周期重推 netmap/keydist

## CTL-06 key_dst 分发

- 关联 REQ：REQ-004
- 测试层：单测
- 状态：`已覆盖`
- 证据：rill-coord/src/coordinator.rs
- 说明：按 to_node_id 下发；节点不可推导主密钥（改包尝试失败）

## CTL-07 key_dst 轮换（宽限期）

- 关联 REQ：REQ-004
- 测试层：单测
- 状态：`部分覆盖`
- 证据：rill-coord/src/coordinator.rs
- 缺口：**节点侧新旧密钥宽限期并存语义待传输层落地**（全网轮换 = 主密钥更换 + key_version++ 已实现）

## CTL-08 吊销 + 全网轮换

- 关联 REQ：REQ-024
- 测试层：单测 + e2e
- 状态：`已覆盖`
- 证据：rill-coord/src/coordinator.rs、rill-core/src/control/revoke.rs
- 说明：条目移除 + netmap_version++ + key_version++；被吊销节点无法再通信（含旧会话密钥）

## CTL-09 租户隔离（多网络）

- 关联 REQ：REQ-010
- 测试层：单测（核心）
- 状态：`待补充`
- 证据：—
- 缺口：多网络分域实现（network_id/独立主密钥/auth key 归域）未落地；跨网伪造 route_mac 无验证
- 说明：实现后联动 SEC-21 ~ SEC-25 对抗断言

## CTL-10 前缀公告白名单

- 关联 REQ：REQ-008
- 测试层：单测 + e2e
- 状态：`待补充`
- 证据：—
- 缺口：coordinator 白名单校验（管理面形态见 REQ-038）未实现；目前为注册携带公告
- 说明：routes[] 内嵌 netmap 与多网关冗余语义已落地（e2e 前缀公告）；白名单/过短前缀拒绝待补

## CTL-11 离线自动撤销公告

- 关联 REQ：REQ-008
- 测试层：单测
- 状态：`待补充`
- 证据：—
- 缺口：离线撤销语义未验证

## CTL-12 Raft 主切换（P2）

- 关联 REQ：REQ-004
- 测试层：集成（P2）
- 状态：`待补充`
- 证据：—
- 说明：LeaderRedirect → 幂等重注册（node_id/绑定不变）→ 软状态重建；openraft 未接入

## CTL-13 重连认证（X25519 DH 挑战）

- 关联 REQ：REQ-013 / REQ-014 / REQ-018 / REQ-022
- 测试层：单测 + e2e
- 状态：`已覆盖`
- 证据：rill-core/src/control/challenge.rs
- 说明：合法 tag 通过/无静态私钥构造失败/nonce 时间窗口防重放/吊销自然生效

## CTL-14 广播 opt-in keydist

- 关联 REQ：REQ-035
- 测试层：单测 + e2e
- 状态：`待补充`
- 证据：—
- 缺口：keydist 按能力位按需下发 broadcast_key 未实现（REQ-035 实现待落地）

## CTL-15 路径服务（v1.5 + v2 数据面）

- 关联 REQ：REQ-034
- 测试层：单测 + docker e2e
- 状态：`已覆盖`
- 证据：rill-core/src/frame.rs、rill-core/src/crypto.rs、rill-coord/src/path_service.rs、rill-mesh/src/data.rs、rill-mesh/src/control.rs、e2e/run_e2e.sh、e2e/setup.sh、e2e/mesh/relay/docker-compose.yaml
- 缺口：PathProbe 消息族运行时未启用（活性由数据面心跳承担，协议已定义）

## CTL-16 coordinator 持久化（REQ-037）

- 关联 REQ：REQ-037
- 测试层：单测 + docker e2e
- 状态：`已覆盖`
- 证据：rill-coord/src/store.rs、rill-coord/src/coordinator.rs、e2e/run_e2e.sh、e2e/setup.sh、e2e/mesh/persist/docker-compose.yaml
- 说明：redb 快照整写；损坏/不一致 fail-closed；一次性 key 消费 tombstone 跨重启存活

## CTL-17 auth key 内嵌过期时间（REQ-043）

- 关联 REQ：REQ-043
- 测试层：单测
- 状态：`已覆盖`
- 证据：rill-coord/src/config.rs、rill-coord/src/coordinator.rs、rilld/src/main.rs
- 说明：过期时间嵌入 key 自身（advisory），admission 时 coordinator 校验；节点侧仅告警不阻断（挑战恢复路径不受影响）

## 验收断言

- [x] CTL-01：注册幂等、身份绑定签名可验证
- [x] CTL-02：一次性 key 二次注册被拒；可复用 key 按生命周期生效
- [x] CTL-03：版本收敛、幂等注册不 bump
- [x] CTL-04：断线重连全量补偿一致
- [x] CTL-05：离线标记与复活恢复、心跳周期重推
- [x] CTL-06：key_dst 按目的派生且主密钥不可推导
- [ ] CTL-07：新旧密钥宽限期并存、旧版本过期作废（节点侧待落地）
- [x] CTL-08：吊销后条目移除、全网轮换、旧会话作废
- [ ] CTL-09：同 coordinator 两网络互不可见、key_dst 互不通用、auth key 归域（待实现）
- [ ] CTL-10：白名单内公告并入 netmap、白名单外拒绝、过短前缀拒绝（待实现）
- [ ] CTL-11：离线后 routes[] 随可达性撤销（待实现）
- [ ] CTL-12：主切换幂等重注册、软状态重建（P2）
- [x] CTL-13：DH 挑战闭环、时间窗口防重放
- [ ] CTL-14：未 opt-in 节点 keydist 不带 broadcast_key（待实现）
- [x] CTL-15：Path* 消息族 + 候选路径（直连 + relay，幂等）/flow hash 选择/主路径 miss 快速切换/key_path 参与者全量签发/吊销联动撤销/path_id=0 回退 key_dst（v2 帧头 42B 纳入 route_mac 与 AAD）
  - relay docker e2e：a—b—c 线形（b 双网卡，a↔c 无直连可达性），直连候选 miss → 快速切换经 b 中继建立会话 + 数据双向（e2e/mesh/relay/，b 日志 relayed frame 为证据）
- [x] CTL-16：coordinator 持久化——单测（roundtrip 恢复/一次性 key 消费存活/node_id+path_id 单调/损坏与不一致 fail-closed/重载不复活）+ docker e2e（coord 重启 → a↔b 恢复、node-c 挑战重连无新注册、node-d 复用已消费 key 被拒，e2e/mesh/persist/）
- [x] CTL-17：auth key 内嵌过期——parse 层（格式/过期段/永不过期/时长解析）+ 注册时（admission）过期 key 拒绝 + 非 lrk 格式 fail-closed + 未过期注册不受影响 + `lrill authkey --ttl` 默认 24h
