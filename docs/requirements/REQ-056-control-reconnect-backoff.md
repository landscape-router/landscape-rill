# REQ-056 控制面重连退避（ReconnectPolicy）

> 类型：缺陷 ｜ 状态：📌 proposed ｜ 优先级：P2 ｜ 依赖：无 ｜ 提出：2026-09-02

## 动机

2026-09-02 CI persist 偶发事故（run 33655492659，重跑绿）定位到的客户端放大器：coord 因瞬态原因 accept 后立刻断流，客户端进入 ~80ms 间隔的零退避重连热循环，烧穿 REQ-047 连接限速并耗尽 40s 注册窗口。两层缺陷（rill-node/src/runtime/mod.rs）：

1. **断线不退避**：主循环 read-Err 只清 `control = None`（:487），直接回到循环头立即重连——退避只施加在「连接失败」路径（:462-468）
2. **退避重置条件过松**：`connect_control()` 返回 Ok（bare TCP/TLS 建立）即重置退避（:461）——半开连接 ≠ 恢复，连上即断的循环永远吃不到退避

附带发现：退避 sleep 发生在 `continue` 路径上，绕过 select 轮转 → `pump_timers`/失败摘要周期静默（事故日志「爆发后无声」的成因），排查时可观测性为零。

## 决策摘要（建议默认值）

1. **ReconnectPolicy 无 I/O 状态机**（rill-node 内，仿 `probe_backoff` 先例）：`connect` / `registered` / `disconnect` 三事件驱动，产出下次重连等待时长
2. **退避重置条件收紧**：从「TCP/TLS 连上」改为「**Registered 事件**」——注册成功才算恢复；未注册成功的断线保留退避进度
3. **断线路径纳入退避**：read-Err 后同样 1s→300s 指数退避（`RECONNECT_INITIAL_BACKOFF`/`RECONNECT_MAX_BACKOFF` 常量复用），首次断线即 1s，不影响正常故障切换速度

## 非目标

- 控制面 keepalive / 空闲探测（连接假死检测另案）
- 客户端 node_id 持久化到磁盘（→ REQ-057 的挑战恢复已覆盖重启场景）
- 退避 jitter（单客户端场景无雷暴同步问题）

## 开放问题（立项评审拍板）

1. **退避等待的调度位置**：维持 `continue` 路径 sleep（简单但摘要静默），还是把等待纳入 select 轮转（失败摘要持续输出，代价是主循环结构变化）
2. **半开连接的注册超时**：连上但迟迟收不到 REGISTER_RESPONSE 时是否主动断开重连（当前依赖 TCP 超时，窗口不可控）——可并入本 REQ 或挂账

## 验收标准（草案）

- ReconnectPolicy 单测：连上即断 → 重连间隔 ≥ 初始退避（1s）；`registered` 后断线 → 退避从头计；连续失败指数增长且封顶 300s
- 事件序列单测：`connect → disconnect` 循环 N 次不重置退避进度
- 现有 mesh 单测 + persist e2e 保持稳定绿；探针 e2e（direct/relay/probe）不回归
