# REQ-056 控制面重连退避（ReconnectPolicy）

> 类型：缺陷 ｜ 状态：✅ merged ｜ 提出：2026-09-02 ｜ 合并：2026-09-02
> 去向：CONTROL_PLANE §2 ｜ 验收场景：CTL-18 ｜ lessons：CP-05（退避/上限/防抖三查：时间封顶 300s 编译期常量，次数上限/可配置待需求出现）

## 动机

CI persist 偶发事故的放大器：coord 瞬态 accept 后断流，客户端「连上后断开」路径零退避立即重连（~80ms 热循环），且 bare TCP 建立即重置退避（半开连接 ≠ 恢复）——烧穿 REQ-047 连接限速并耗尽注册窗口。退避 sleep 绕过 select 轮转还导致失败摘要静默，排查可观测性为零。

## 决策摘要

无 I/O 的 ReconnectPolicy 状态机（connect / registered / disconnect 三事件驱动，仿 probe_backoff 先例）；退避覆盖连接失败与连上后断开两类，1s→300s 指数；**退避重置条件收紧为 Registered 事件**；退避等待分片调度（100ms 片轮转 pump_timers），失败摘要持续输出。

## 验收标准（已落地，2026-09-02）

- 单测：ReconnectPolicy 三测（指数封顶 300s / Registered 重置 / 连上不重置）——rill-node/src/runtime/reconnect.rs
- e2e recover：重连间隔 1055-2026ms（断言 ≥900ms）、无热循环（connected 计数恰为 2）、退避期间失败摘要持续输出
- CI：e2e-mesh 八场景全绿（run 33668466083），direct/relay/persist/probe 无回归
