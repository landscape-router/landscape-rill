# mesh 连通性验证（connectivity）

> 端点探测/直连/中继/keepalive 的验收场景。
> 设计规范：CONNECTIVITY（[../../design/mesh/connectivity.md](../../design/mesh/connectivity.md)）。

## CON-01 coordinator UDP 回显探测

- 关联 REQ：REQ-007
- 测试层：docker e2e + 单测
- 状态：`已覆盖`
- 证据：e2e/run_e2e.sh、rill-coord/src/echo.rs、rilld/src/coord_run.rs
- 说明：coordinator UDP 数据面端口（默认与 TCP 同端口）回显 seen 地址（STUN 式）；节点周期 PING（to=0 标记）→ PONG 载荷 seen 地址 → 候选端点补充 + EndpointReport 重报（e2e `echo confirmed`）；候选端点集合 = 本地接口 ∪ 回显地址 ∪ 中继地址

## CON-02 端点上报与传播

- 关联 REQ：REQ-007
- 测试层：单测 + e2e
- 状态：`已覆盖`
- 证据：rill-mesh/src/control/、rill-coord/src/coordinator/、e2e/run_e2e.sh
- 说明：EndpointReport 消息与端点上报入 netmap 已实现；探测触发链路（echo 结果变化 → 重报）随 CON-01 覆盖（probe 场景 endpoint report 含 seen 地址）；周期 30s（PROBE_PERIOD）

## CON-03 直连互探（公网/锥形 NAT）

- 关联 REQ：REQ-007
- 测试层：docker e2e + 单测
- 状态：`已覆盖`
- 证据：e2e/run_e2e.sh、rill-core/src/probe.rs、rill-mesh/src/data/
- 说明：probe 小包（magic 4B + type 1B + from/to node_id + nonce 4B，独立于 34B 帧）互探；双方对全部候选端点发 PING，PONG nonce 匹配确认 → 端点活性恢复（e2e `probe confirmed direct via`）；单测 `probe_ping_replies_pong_and_matches`

## CON-04 中继兜底（对称 NAT）

- 关联 REQ：REQ-007
- 测试层：docker e2e
- 状态：`已覆盖`
- 证据：e2e/run_e2e.sh、e2e/mesh/probe/、e2e/mesh/relay/、rill-node/src/runtime/
- 说明：直连失败自动切中继：v2 帧走路径候选（PathService relay 路径 + 挂靠确认），v1 帧端点表追加确认中继端点（直连 miss 轮转回落，`apply_relay_endpoints`）；probe 场景 c→a 经 b 中继 + relay 场景回归

## CON-05 三层中继模型

- 关联 REQ：REQ-007
- 测试层：docker e2e + 单测
- 状态：`已覆盖`
- 证据：e2e/run_e2e.sh、rilld/src/coord_run.rs、rill-coord/src/coordinator/
- 说明：relay 列表构建（coordinator 周期向各网 relay 能力节点端点发 PING 测 RTT → 排序写入 relay_list 随 netmap 下发 + PathService relay 顺序 = 挂靠优先级）；自愿节点 opt-in（能力位 relay=0x01）纳入；coordinator 兼任 echo/RTT 探测方（e2e `relay rtt` 日志 + 节点 `relay candidates`）；独立 relay 部署（层③）协议零改动，挂账

## CON-06 中继故障切换

- 关联 REQ：REQ-007
- 测试层：docker e2e + 单测
- 状态：`已覆盖`
- 证据：e2e/run_e2e.sh、rill-mesh/src/data/
- 说明：挂靠中继失联 → 切换下一候选：心跳 miss 落到**实际选用路径**（`last_sent_path`，非仅主路径——在用中继死亡不再卡死）+ 全候选 miss 耗尽时按 miss 升序选（最不坏优先，收包恢复闭环）；e2e `docker stop node-b` → c→a 经 node-d 恢复；单测 `path_miss_peer_misses_used_path_not_only_main`

## CON-07 数据面 keepalive 回退

- 关联 REQ：REQ-014
- 测试层：单测 + e2e
- 状态：`已覆盖`
- 证据：rill-mesh/src/data/、rill-node/src/runtime/
- 说明：心跳 3 次 miss 拆会话已闭环；**回退中继路径**（事件驱动切换）未验证

## CON-08 端口分派

- 关联 REQ：REQ-014
- 测试层：单测 + 集成
- 状态：`已覆盖`
- 证据：rill-mesh/src/data/、rill-core/src/probe.rs
- 说明：数据面 UDP 端口按首字节分派：`0x01..=0x0F` → 34B 帧（version 值域）；probe magic（LPRB）→ probe；都不匹配 → 丢弃（fail-closed，CN-02）；单测 `unknown_protocol_dropped`

## CON-09 联邦边界（v2）

- 关联 REQ：REQ-007
- 测试层：集成（v2）
- 状态：`待补充`
- 证据：—
- 说明：远端端点只下发到桥节点的预置断言（v2 联邦实现时展开）

## CON-10 probe 强制限速/退避（CN-01）

- 关联 REQ：REQ-046
- 测试层：单测
- 状态：`已覆盖`
- 证据：rill-node/src/runtime/、rill-mesh/src/data/、rill-core/src/rate.rs
- 说明：发送侧三件套默认强制开启——全局令牌桶（10/s 突发 20，单轮发送 ≤ 容量）、每端点指数退避（周期开始 drain 在途探测，无响应 miss+1 → `30s×2^miss` 封顶 300s，PONG 确认清零）、在途并发上限 64（超限拒绝新发送）；PONG 生成按源限速（10/s 突发 20，SEC-26 节点侧）；单测 `probe_send_bucket_bounds_burst` / `probe_backoff_exponential_and_reset` / `probe_pending_cap_rejects_new_sends` / `pong_generation_rate_limited_per_source`

## 验收断言

- [x] CON-01：节点探测收到 seen 地址回显；候选端点集合完整（probe 场景 `echo confirmed`）
- [x] CON-02：端点变化上报后 netmap 更新、转发表收敛（echo 重报链路随 CON-01 覆盖）
- [x] CON-03：互探后确认可达、流量走直连（`probe confirmed direct via`）
- [x] CON-04：对称 NAT 下自动切中继、流量经中继可达（c→a 经 b，`relayed frame`）
- [x] CON-05：relay 列表 RTT 排序 + 自愿节点 opt-in 纳入（层③ 独立 relay 协议零改动挂账）
- [x] CON-06：挂靠中继停机 → 切换下一个，流量不中断（stop b → 经 d 恢复）
- [x] CON-07：keepalive 判定失效（3 次 miss）；中继回退路径已验证（CON-04/06）
- [x] CON-08：帧/probe/乱入字节分派正确（首字节分派 + fail-closed）
- [ ] CON-09：普通节点不持有远端端点（v2）
- [x] CON-10：强制限速默认开启、指数退避、并发上限收敛（CN-01 三复核点）
