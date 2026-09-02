# mesh 连通性设计（CONNECTIVITY）

> 端点发现、直连验证、中继兜底——mesh 接入的"DERP 等价物"专题。
> 34B 帧头的转发语义见 FRAME_HEADER；端点传播进 netmap 见 CONTROL_PLANE §3.2。
> 版本：v0.5（2026-09-02 修订：REQ-059——§2.1 认证前最小解析/资源分配后置纪律显式化）｜ 相关需求：REQ-007 / REQ-014 / REQ-017 / REQ-028 / REQ-046 / REQ-059

## 1. 问题与目标

34B 帧的转发依据是 `to_node_id → UDP 端点` 表，需要三块拼图：

1. **端点探测**：NAT 后面的节点看不到自己的公网映射
2. **端点传播**：探测结果上报、经 netmap 下发
3. **中继兜底**：直连打不通（对称 NAT/CGNAT）时的转发通道

目标：节点间**尽可能直连**（延迟/带宽最优），打不通时**自动中继兜底**，全程对上层无感。

## 2. 端点探测（coordinator UDP 回显）

- coordinator 监听 UDP 数据面端口；节点发探测请求，coordinator **回显 seen 地址**（STUN 式，零额外组件）
- **候选端点集合** = 本地接口地址 ∪ coordinator 回显地址 ∪ 中继地址
- 探测周期（建议 30s）+ 网络变更触发（接口变化/漫游）
- 结果上报进 netmap `endpoints[]`（CONTROL_PLANE §3.2）

### 2.1 数据面端口分派（probe vs 34B 帧）

节点数据面 UDP 端口同时承载 34B 帧与 probe 小包，按**首字节**分派：

- `0x01..=0x0F` → 34B 帧（帧头 `version` 值域，FRAME_HEADER §2.1）
- 其余 → probe（首 4B 匹配 `magic`，§4.2）；不匹配两者 → 丢弃

分派规则在 XDP/用户态转发入口统一实现。**解析 fail-closed（强制要求）**：所有网络输入（帧头/载荷/probe/握手消息）解析**禁止 panic/unwrap**，长度严格校验，非法输入一律丢弃——这是防 panic DoS 的实现安全基线（验证见 [tests/security/](../../tests/security/README.md)）。

**预认证解析纪律（REQ-059，FRAME_HEADER §5.1 同规则）**：分派与 probe 头解析属"固定头字段级别"——这是认证（route_mac / AEAD / 握手）通过前允许的全部解析；probe 载荷定长上限（128B，超长丢弃），任何富结构反序列化都不得发生在认证之前。资源分配后置：PONG 回包按源限速（§4.3）、在途探测表硬上限（§4.3 CN-01）、认证失败路径除读缓冲外零持久分配。限速（REQ-046）管速率，本规则管时机，互不替代；预认证解析入口纳入 fuzz 语料验收（SEC-08）。

### 2.2 反射放大防护（coordinator 回显）

probe 请求无认证（有意设计），伪造源地址可让 coordinator 向受害者回显（放大因子 ~1:1，威胁低但存在）：

- coordinator 回显**按源地址限速**（令牌桶/每源 IP 速率上限）
- 响应不携带任何敏感信息（仅回显 seen 地址），放大因子小，限速后风险收敛

## 3. 端点传播

- netmap 全量推送（v1），变更即全量（版本号 CAS）
- **relay 列表**（DERP map 等价物）随 netmap 一并下发（§5）
- 联邦边界（v2）：远端端点只下发到桥节点，不向普通节点扩散（信息暴露可控）

## 4. 直连验证（disco 式简化）

### 4.1 流程

```
从 netmap 获取对方候选端点列表
  → 双方同时向对方所有候选端点发送 probe（专用小包）
  → 收到 probe-response 且 nonce 匹配 → 该端点确认可达
  → 挂靠直连；全部失败 → 走中继
```

### 4.2 probe 包（独立于 34B 帧）

```
probe = magic(4B) + 类型(1B: 请求/响应) + from_node_id(4B) + to_node_id(4B) + nonce(4B)
```

- **不走 34B 帧转发路径**：探测发生在会话建立前，route_mac 验证链条不存在
- 不经中继转发，直接发送到候选端点（含中继地址本身）
- 探测仅验证可达性，不携带任何流量

### 4.3 安全（强制限速，REQ-046/CN-01）

probe 无认证为有意设计（会话建立前无认证链可用，§4.2），因此限速**不是可选项而是默认强制**——探测量无上界时行为特征与扫描/攻击无法区分（CN-01：被 IDS/风控误判、正常节点被误伤），且无强制限速时可借 probe 机制做反射放大与行为特征污染。

| 攻击 | 后果 | 防护/边界 |
|---|---|---|
| 伪造 probe-response | 诱导错误的直连决策 | 伤害上限为 DoS；真实流量是 AEAD 封装的 34B 帧，攻击者读不了也注入不了 |
| 伪造 probe 洪泛（驱动响应面） | 反射放大（SEC-26） | **PONG 生成按源限速**（10/s、突发 20，与 §2.2 coordinator 回显同值、同一 `SourceRateLimiter`）；响应 ≈ 请求大小，限速后收敛 |
| 探测行为被误判攻击（CN-01） | 正常节点被 IDS/风控误伤/封禁 | **发送侧强制限速 + 指数退避 + 并发上限**：全局令牌桶（10/s、突发 20）——单轮探测量 ≤ 突发容量；每端点无响应 miss+1 → 下次探测 `30s × 2^miss`（封顶 300s），PONG 确认即清零；在途 probe 上限 64（超限拒绝新发送，非清空） |
| 诱导直连到攻击者端点 | 攻击者收到封装帧 | 无法解密（AEAD），无法注入有效流量 |

指数退避推进机制：probe 发送只发生在节点探测周期内，周期开始时仍在途（无 PONG 确认）的探测即视为上轮失败——转入端点退避，失败按退避重试而非并发轰炸。

## 5. 中继（三层模型）

| 层 | 承担者 | 作用 | 协议改动 |
|---|---|---|---|
| ① 兜底 | **coordinator 兼任**（v1 强制） | 保证至少一个可用中继 | 零 |
| ② 扩容 | **自愿节点**（`capabilities.relay` 自愿位，opt-in） | 分担带宽/延迟 | 零（位已预留） |
| ③ 可选 | 独立 relay 部署（未来） | 专业中继节点 | 零 |

- 中继 = 34B 帧转发节点（FRAME_HEADER §4 语义：读明文帧头 → route_mac 校验 → 查表 → 重写外层地址），**转发不是能力问题而是意愿问题**，任何持 key_dst + 端点表的节点都能转发
- 自愿节点 opt-in 原则：中继消耗节点主人的带宽/CPU，默认关闭
- **coordinator 汇总**：收集自愿 relay（可达性验证：UDP 回显测试 + RTT 测量），构建 relay 列表随 netmap 下发
- **挂靠选择**：节点按 RTT/优先级排序逐个尝试，失败切下一个

### 5.1 滥用防护

- 恶意节点伪装 relay：中继不可信是既定信任模型（极限是丢包，读不了/注入不了）
- 带宽放大：relay 侧速率限制（令牌桶）——通用限速策略（v0.3 为广播泛洪设计；广播 v0.7 已激活并自带发送/转发共用令牌桶（FRAME_HEADER §2.6），中继流量复用同一策略）

## 6. 故障切换与端点更新

| 事件 | 行为 |
|---|---|
| 挂靠中继失联 | 检测超时 → 切换 relay 列表下一个 |
| 直连端点失效 | **数据面 keepalive**（帧头 `type=心跳`：节点对之间周期活性探测，建议 5s；连续 N 次（建议 3 次）无响应判定失效 → 回退中继路径）。与控制面心跳（节点↔coordinator 租约，CONTROL_PLANE §3.4）是两套机制 |
| 节点端点变化 | 上报 coordinator → netmap 全量 → 全网转发表更新 |
| 自愿 relay 下线 | relay 列表更新（netmap 变更），挂靠节点切换 |

## 7. 与既有文档的关系

- **FRAME_HEADER.md**：零改动——probe 是独立小包；中继转发语义已内含 §4
- **CONTROL_PLANE.md**：§3.2 微更新——`endpoints[]` 上报机制 + relay 列表下发

## 8. 决策记录

| 日期 | 决策 |
|---|---|
| 2026-09-02 | **REQ-059：预认证解析纪律显式化（§2.1）**：分派与 probe 头解析 = 认证前允许的全部解析（固定头字段级别，probe 载荷 128B 上限）；资源分配后置（PONG 按源限速、在途表上限、认证失败零持久分配）；与 REQ-046 限速叠加（速率 vs 时机）；fuzz 语料验收（SEC-08）。实现已满足，规则由隐式升级为显式（lessons CN-05） |
| 2026-09-01 | **REQ-046：probe 强制限速/退避（§4.3 "可选限速" → 强制，落实 CN-01）**：①**发送侧三件套**（rill-node runtime/probe.rs）：全局令牌桶 10/s 突发 20（桶空本轮不发）+ 每端点指数退避（周期开始 drain 在途探测，仍 pending = 上轮无响应 → miss+1 → `30s×2^miss` 封顶 300s；PONG 确认清零）+ 在途并发上限 64（rill-mesh `send_probe_ping` 超限拒绝，替换原 1024 清空）；②**PONG 生成按源限速**（SEC-26 节点侧，rill-mesh dispatch `pong_limiter`）：10/s 突发 20，与 coordinator 回显同值；③`EchoLimiter` 泛化为 rill-core `SourceRateLimiter`（echo 与 PONG 共用，后续 REQ-047 Register 按源限速同源复用） |
| 2026-08-15 | 端点探测 = coordinator UDP 回显（STUN 式，零额外组件）；直连 v1 = 简单互探（专用 probe 小包）+ 中继兜底，不做对称 NAT 打洞；中继 = 三层模型（coordinator 兜底 + 自愿节点 opt-in 扩容 + 独立 relay 可选），全部零协议改动 |
| 2026-09-01 | **probe 体系实现落档（CON-01/03/04/05/06/08 + SEC-26）**：①**probe 线格式**（rill-core/src/probe.rs）：`magic("LPRB") + type(PING/PONG) + from_node_id + to_node_id + nonce`，`to_node_id=0` = coordinator 回显标记；PONG 可携带载荷（echo 的 seen 地址 "ip:port"）；解析 fail-closed（CN-02）；②**端口分派**（data.rs handle_incoming）：首字节 `0x01..=0x0F` → 34B 帧，magic 匹配 → probe，都不匹配 → 丢弃；③**coordinator UDP 数据面**（rilld run_coord_udp，默认与 TCP 同端口）：echo（按源 IP 令牌桶 10/s 突发 20，SEC-26）+ relay RTT 排序（30s 周期向各网 relay 端点 PING 测 RTT → relay_list 排序随 netmap 下发 + PathService relay 顺序 = 挂靠优先级）；④**节点侧**（runtime pump_probes，30s 周期）：echo（结果并入 EndpointReport 重报）+ 对全部 peer 候选端点互探（PONG 匹配 → 端点活性恢复）+ relay 探测（确认 → `apply_relay_endpoints`：v1 帧端点表 = 直连 ++ 确认中继，miss 轮转回落）；⑤**CON-06 故障切换修复**：心跳 miss 同时落到**实际选用路径**（`last_sent_path`——只 miss 主路径时在用中继死亡会卡死）+ 全候选 miss 耗尽时按 miss 升序选（最不坏优先，收包恢复闭环）；⑥echo 目标 = coordinator_url 推导（host:port 允许主机名，每周期 DNS 解析），可用 `udp_echo_addr` 显式覆盖 |
| 2026-08-15 | **数据面转发路径实现（legs/mesh/data.rs 落档，FRAME_HEADER §4 语义落地）**：`MeshData` = UDP socket + key_dst 表（KeyDist 应用）+ 端点表（netmap endpoints 应用）；`relay()` 顺序 = 帧头解析 → version 校验 → route_mac 校验（key_dst 按 to_node_id）→ 目标为自己则交付上层 / ttl==0 丢弃 / 查端点表 → **ttl 递减后直接转发，不重签 route_mac**（§3.1 语义验证，测试断言转发后帧仍可校验）；丢弃原因显式化（BadVersion/BadRouteMac/TtlExpired/NoEndpoint/NoKeyDst/Short，fail-closed）；目的节点交付返回给上层（AEAD 解密属会话层，握手后接线）；**回环 UDP 集成测试**：A→relay→B 转发、ttl 递减、篡改/版本/短帧/无端点/无密钥丢弃、送达自身 |
