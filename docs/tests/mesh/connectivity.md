# mesh 连通性验证（connectivity）

> 端点探测/直连/中继/keepalive 的验收场景。
> 设计规范：CONNECTIVITY（[../../design/mesh/connectivity.md](../../design/mesh/connectivity.md)）。

## CON-01 coordinator UDP 回显探测

- 关联 REQ：REQ-007
- 测试层：docker e2e
- 状态：`待补充`
- 证据：—
- 缺口：coordinator UDP 回显探测未实现（候选端点集合 = 本地接口 ∪ 回显地址 ∪ 中继地址）

## CON-02 端点上报与传播

- 关联 REQ：REQ-007
- 测试层：单测 + e2e
- 状态：`部分覆盖`
- 证据：rill-mesh/src/control/、rill-coord/src/coordinator.rs
- 缺口：EndpointReport 消息与端点上报入 netmap 已实现；探测触发（周期 30s + 网络变更）链路未验证

## CON-03 直连互探（公网/锥形 NAT）

- 关联 REQ：REQ-007
- 测试层：docker e2e
- 状态：`待补充`
- 证据：—
- 缺口：probe 小包（magic + node_id + nonce）互探机制未实现

## CON-04 中继兜底（对称 NAT）

- 关联 REQ：REQ-007
- 测试层：docker e2e
- 状态：`待补充`
- 证据：—
- 缺口：直连失败自动切中继的挂靠链路未实现（单播帧转发路径本身已闭环，见 FRM-09）

## CON-05 三层中继模型

- 关联 REQ：REQ-007
- 测试层：docker e2e
- 状态：`待补充`
- 证据：—
- 缺口：relay 列表构建（可达性验证 + RTT 测量）、自愿节点 opt-in 纳入未实现

## CON-06 中继故障切换

- 关联 REQ：REQ-007
- 测试层：docker e2e
- 状态：`待补充`
- 证据：—
- 缺口：挂靠中继失联检测与切换未实现

## CON-07 数据面 keepalive 回退

- 关联 REQ：REQ-014
- 测试层：单测 + e2e
- 状态：`已覆盖`
- 证据：rill-mesh/src/data.rs、rill-node/src/runtime.rs
- 说明：心跳 3 次 miss 拆会话已闭环；**回退中继路径**（事件驱动切换）未验证

## CON-08 端口分派

- 关联 REQ：REQ-014
- 测试层：单测 + 集成
- 状态：`部分覆盖`
- 证据：rill-mesh/src/data.rs、rill-mesh/src/framing.rs
- 缺口：34B 帧/握手帧分派已闭环；probe magic 分派未实现（依赖 CON-03）

## CON-09 联邦边界（v2）

- 关联 REQ：REQ-007
- 测试层：集成（v2）
- 状态：`待补充`
- 证据：—
- 说明：远端端点只下发到桥节点的预置断言（v2 联邦实现时展开）

## 验收断言

- [ ] CON-01：节点探测收到 seen 地址回显；候选端点集合完整（待实现）
- [ ] CON-02：端点变化上报后 netmap 更新、转发表收敛
- [ ] CON-03：互探后确认可达、流量走直连（待实现）
- [ ] CON-04：对称 NAT 下自动切中继、流量经中继可达（待实现）
- [ ] CON-05：三层中继（coordinator 兜底/自愿节点/独立 relay）生效（待实现）
- [ ] CON-06：挂靠中继停机 → 切换下一个，流量不中断（待实现）
- [x] CON-07：keepalive 判定失效（3 次 miss）；中继回退路径待验证
- [x] CON-08：帧/probe/乱入字节分派正确（probe 分派待实现）
- [ ] CON-09：普通节点不持有远端端点（v2）
