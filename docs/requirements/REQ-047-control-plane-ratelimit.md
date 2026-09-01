# REQ-047 控制面消息限速与准入配额

> 类型：需求 ｜ 状态：📌 proposed ｜ 优先级：P1 ｜ 依赖：— ｜ 提出：2026-09-01

## 动机

CONTROL_PLANE（v0.7）全文无控制面消息级限速/配额：Register（§3.1）、Heartbeat（§3.4）、PathRequest（§3.11）均无频率约束——数据面广播帧有令牌桶（FRAME_HEADER §2.6，64/16/s），控制面反而空白。

具体风险：

1. **auth key 爆破**：SEC-20 挂账（按源限速/锁定未实现、错误响应措辞未验证）
2. **注册风暴**：泄露的可复用 auth key 疯狂 Register 不同公钥 → 大量 node_id 分配，污染注册表与持久化存储（redb 快照整写放大）
3. **消息洪泛**：被攻破节点在 TLS 长连接上高频 Heartbeat/PathRequest/任意 Envelope——SEC-19 只有 1MB 帧上限与解析失败断连，无速率维度

同类产品的事故形态（大量设备心跳类消息打瘫控制面）根因即控制面消息缺乏限速；本 REQ 补齐控制面的速率维度。

## 决策摘要（建议默认值）

1. **连接级消息速率**：per-TLS 连接令牌桶（Envelope 消息速率上限，超限断连——复用 SEC-19 单连接隔离语义，其他连接不受影响、进程不 panic）
2. **Register 准入限速**：per-source IP 注册频率令牌桶 + auth key 验证失败递增锁定（指数退避/临时拒绝）
3. **错误响应统一措辞**：InvalidAuthKey 不区分不存在/已消费/过期（防爆破信息泄露）
4. **心跳超频**：超出约定周期的心跳直接忽略（无状态、零成本），last_seen/租约语义不变
5. **PathRequest 频率与 pending 上限**：幂等已挡重复分配，补 pending 队列大小上限（防内存放大）
6. 参数与心跳间隔/租约阈值同批定为常量（config 风格），默认值实现时定

## 验收标准（草案）

- SEC-20 落地：auth key 爆破被限速锁定、错误响应无信息泄露
- 单连接消息洪泛 → 断连、coordinator 不 panic、其他连接不受影响（SEC-19 扩展）
- 可复用 key + 不同公钥风暴 → 注册被限速拒绝，node_id 分配不放大
- 超频心跳被忽略，租约判定与离线标记语义不变
- 验收场景：SEC-20 + 新增场景（合并时落 tests/security/control-plane-attacks.md）

## 关联

- 教训对照：CN-03（共享资源侧限速）
- 关联缺口：SEC-19（部分覆盖，补速率维度）、SEC-20（待实现）
- 复用：rill-core TokenBucket（与广播/probe 令牌桶同源）
