# REQ-047 控制面消息限速与准入配额

> 类型：需求 ｜ 状态：✅ merged ｜ 提出：2026-09-01 ｜ 合并：2026-09-01 ｜ 去向：CONTROL_PLANE §3.13（§5.2 联动） ｜ 验收场景：SEC-20 / SEC-29

## 动机

CONTROL_PLANE（v0.7）全文无控制面消息级限速/配额：Register（§3.1）、Heartbeat（§3.4）、PathRequest（§3.11）均无频率约束——数据面广播帧有令牌桶（FRAME_HEADER §2.6，64/16/s），控制面反而空白。

具体风险：

1. **auth key 爆破**：SEC-20 挂账（按源限速/锁定未实现、错误响应措辞未验证）
2. **注册风暴**：泄露的可复用 auth key 疯狂 Register 不同公钥 → 大量 node_id 分配，污染注册表与持久化存储（redb 快照整写放大）
3. **消息洪泛**：被攻破节点在 TLS 长连接上高频 Heartbeat/PathRequest/任意 Envelope——SEC-19 只有 1MB 帧上限与解析失败断连，无速率维度

同类产品的事故形态（大量设备心跳类消息打瘫控制面）根因即控制面消息缺乏限速；本 REQ 补齐控制面的速率维度。

## 决策摘要

连接级消息速率（per-TLS 连接令牌桶 20/s 突发 40，超限断连——复用 SEC-19 单连接隔离）+ Register 准入限速（per-源 IP 0.5/s 突发 5）与 auth key 失败递增锁定（≥5 次锁 30s×2ⁿ 封顶 1h，成功清零、挑战路径不计失败）+ 心跳超频忽略（最小间隔 5s，零成本跳过、租约语义不变）+ PathRequest pending 上限（节点 256 / coordinator per-source 1024 饱和丢弃）+ 错误响应统一措辞（InvalidAuthKey 不区分失败原因——实现时确认原已闭环，补断言）。复用 rill-core TokenBucket/SourceRateLimiter（与 REQ-046 同源）。

- 教训对照：CN-03（共享资源侧限速——已落档）
