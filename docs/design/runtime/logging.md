# 日志治理设计（LOGGING）

> daemon 日志的框架、级别、格式、存储与高频事件摘要——运维基线的日志治理部分（REQ-039 / 教训 AO-04）。
> 版本：v1.3（2026-09-01 修订：§2/§4 配置优先级引用 CONTROL_PLANE §3.12 通用约定）｜ 相关需求：REQ-039

## 1. 范围与边界

日志分两轨，边界是结构性的（代码上由 subscriber 初始化位置保证）：

| 形态 | 走向 | 框架 |
|---|---|---|
| 长期运行 daemon（`lrill run`，systemd unit / 容器 ENTRYPOINT 调用） | tracing 结构化日志 → stderr（可追加文件） | tracing + tracing-subscriber |
| 一次性 CLI 子命令（`pubkey` / `authkey` / `up` / `down` / `status`） | 直接 stdout/stderr 输出，**不经过日志框架** | 无 |

边界的意义（§6）：CLI 产物（auth key 等）不进日志框架，红线是架构保证而非调用习惯。

级别语义（站点选择见 src 实现）：

- `error`：持久性故障（persist failed、coord fatal、配置重载失败、协议解析失败）
- `warn`：高频失败的周期摘要（§5）+ 低频可预期事件（auth key 过期/非法、无 mesh 路由）
- `info`：生命周期事件（监听启动、注册、会话建立、中继转发、netmap 摘要、SIGHUP 重载）
- `debug`：明细（端点上报、路径表变化）

## 2. 级别配置

配置优先级遵循 **CONTROL_PLANE §3.12 通用约定：CLI 显式 > 环境变量 > 默认值**：

- 级别：`lrill run --log-level <off|error|warn|info|debug>` > `RUST_LOG`（EnvFilter 表达式）> 默认 `info`
- CLI 显式指定时 `RUST_LOG` 被完全覆盖（含 target 级过滤）；`--log-level` 仅支持简单级别
- 生效性：级别在 daemon 启动时生效，改动需重启 daemon（无运行时重载）；生效性验证见 tests LOG-01

## 3. 格式契约

- 文本行式：`<timestamp> <LEVEL> <module>: <message>`，无 ANSI 转义（非 TTY）
- 消息文本保留 `[coord]` / `[node]` 角色前缀
- **e2e 断言文本稳定**：`registered:` / `relayed frame` / `session established` / `control connected` 等消息文本是 e2e/run_e2e.sh grep 契约，不得改写

## 4. 存储

- **默认 stderr**：委托 supervisor——systemd 由 journald 捕获（`journalctl -u lrill.service`）、容器由 docker log driver 捕获（`docker logs`）；容量上限由 supervisor 配置
- **可选文件**：`lrill run --log-file <path>` > `LRILL_LOG_FILE` > 默认无（优先级同 §2）；tracing-appender 按天轮转（`<prefix>.<YYYY-MM-DD>`），保留最近 7 个文件，非阻塞写入；文件模式同时保留 stderr 输出。文件数量/大小轮转是框架职责，应用不自定义

## 5. 高频事件周期摘要（AO-04）

高频失败/攻击噪声**不逐条输出**，事件进入显式计数器，固定周期输出摘要：

- 计数：事件发生 → `RateCounter::tick()`（ril-core `rate.rs`，纯逻辑）；摘要周期默认 `RATE_SUMMARY_PERIOD = 1s`
- 输出：每周期 `poll()` 取走计数，**>0 才打印**，输出率严格有界（每站点每周期 ≤1 条）；信息不丢失（全部计数，仅延迟聚合）
- 归因：per-peer 计数（仅已知 peer——持有转发密钥/已建会话；伪造 node_id 进全局桶，防 HashMap 膨胀）+ 全局桶（无法归因的畸形包）
- 站点：
  - 数据面丢帧（`frame dropped`）：ril-mesh `MeshData::poll_drop_stats`，handle_incoming 收口计数（节点 + coordinator 角色共用）
  - 握手拒绝（`handshake rejected`）：ril-node `Node::rejected_stats`（per-peer）
  - 控制面重连失败（`control connect failed`）：ril-node `Node::connect_failed`（退避 1s→300s 逻辑不变）
  - coord 侧（`accept failed` / `register rejected`）：`run_coord` 周期 interval 分支输出
- 实现：`RateCounter`（ril-core/src/rate.rs）＋ 各调用点持有；无日志框架层过滤机制

## 6. 红线：auth key 不落日志

- auth key 只经 CLI stdout 输出（`lrill authkey`，REQ-036/REQ-043）；daemon 日志不包含 auth key 明文（告警消息不嵌入 key 值）
- 结构性保证：CLI 输出不经日志框架（§1）；依赖 REQ-036、教训 AO-01/AO-02

## 7. 决策记录

- 2026-09-01（REQ-039 merge）：选型 tracing（tokio 生态标准）；存储双轨（委托 supervisor + 可选自写文件轮转）；高频事件改为周期计数器摘要（§5，教训 AO-04）
- 2026-09-01（§2/§4 修订）：配置优先级统一为 CLI 显式 > 环境变量 > 默认值（`--log-level` > `RUST_LOG`；`--log-file` > `LRILL_LOG_FILE`）；同日该约定提升为通用约定（CONTROL_PLANE §3.12），配置文件路径纳入（`run [config]` > `LRILL_CONFIG` > 默认）
- 2026-09-01（§5 修订）：否决日志框架层透明限速（Layer 门控 + 聚合上报线程）——丢弃语义破坏排查、全局窗口饿死其他站点、机制复杂；改为调用点显式 `RateCounter`（设计对齐，AGENTS.md Design Alignment）
- 实现级决定：subscriber 只在 `rilld/src/main.rs` run_daemon 初始化（`rilld/src/logging.rs`）；`rill-core` 保持 I/O 无关，不引入 tracing；库 crate（rill-node / rill-mesh / rill-coord）仅用 tracing facade 宏；`RateCounter` 在 rill-core（纯逻辑）
- 供应链（cargo audit）与可复现构建部分拆出 REQ-044
