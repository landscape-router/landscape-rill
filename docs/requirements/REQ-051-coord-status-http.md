# REQ-051 coord 只读状态端点（HTTPS + 管理密码）

> 类型：需求 ｜ 状态：✅ merged ｜ 提出：2026-09-01 ｜ 合并：2026-09-02
> 去向：CONTROL_PLANE §3.14 ｜ 验收场景：ADM-07 ｜ lessons：CP-01（RPC 无认证泄漏）、KC-02（密钥明文落盘）、AO-02（WebUI 不持持久配置）

## 动机

coordinator 是中心化权威（CONTROL_PLANE §1），但运行态只能翻日志：节点表/在线状态/auth key 台账/安全计数器均无即时视图。REQ-038 已定稿"配置与执行分离"（配置文件唯一权威 + 库 API 执行面 + SIGHUP 重载），本需求补齐**观察面**：coord 进程内开只读 HTTPS JSON 端点。写操作不进端点（仍走配置文件 + SIGHUP），WebUI 写边界不变（REQ-040）。

- **传输**：复用 coord TLS 证书的 HTTPS 只读端点；独立 `status.listen_addr`；仅 GET /status，无写路由；HTTP 层 axum（运维基线豁免 REQ-044 张力）
- **认证**（day one，教训 CP-01）：
  - 管理密码 Bearer（`Authorization: Bearer <password>`）
  - 配置存 PBKDF2-HMAC-SHA256（盐 + 哈希，复用现有 sha2/hmac，零新依赖）；明文密码禁止落盘（教训 KC-02）
  - 常数时间比较；认证失败按源限速（令牌桶，复用 rate.rs），超限 429
  - `status` 段启用而无有效密码哈希 → 拒绝启动（fail-closed，同 ADM-01）
- **密码轮换**：改配置 + SIGHUP 增量生效（ADM-03 同机制）；多 coordinator（Raft 期）落地前 = 各副本配置文件各自保持一致，字段设计不阻碍日后迁入复制存储
- **内容**（admin 全网视图，多网络全量）：
  1. 网络概览：网络名/network_id、节点数（在线/离线/总）、netmap_version、relay 列表（RTT 排序）、announce 白名单
  2. 节点表：node_id、公钥指纹、capabilities、公告前缀、最近端点、在线状态 + last_seen age、协议版本
  3. auth key 台账：前缀脱敏、归域 network、policy、tag、一次性 key 消费状态、剩余有效期
  4. 安全计数器：echo 限速摘要、注册拒绝计数
  5. coord 自身：监听地址、存储模式（纯内存/redb 路径）、uptime、重载结果历史
  - 红线：密钥材料（master_key/signing_seed/TLS 私钥）一律不输出，只显示"已配置 + 指纹"
- **实现取向**：HTTP 层引入 axum/hyper（与 REQ-044 依赖最小化挂账的张力明示：接受该依赖，观察面属运维基线）；查询逻辑为 rill-coord 内 I/O-free 快照方法（单测覆盖），HTTP 层保持薄

- **CONTROL_PLANE §3.14**：端点行为权威描述（认证/限速/轮换/内容/红线）
- 验收场景：ADM-07（[tests/admin.md](../tests/admin.md)）
