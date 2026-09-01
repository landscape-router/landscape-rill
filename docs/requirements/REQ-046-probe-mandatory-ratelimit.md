# REQ-046 probe 体系实现与强制限速/退避

> 类型：需求 ｜ 状态：📌 proposed ｜ 优先级：P1 ｜ 依赖：— ｜ 提出：2026-09-01

## 动机

probe 体系设计已定稿（CONNECTIVITY §2/§2.1/§4，REQ-007/REQ-014/REQ-017）但实现挂账：CON-01（coordinator UDP 回显探测）、CON-03/CON-08（probe magic 分派）待实现，SEC-07/SEC-26 验证全待补充——netmap `endpoints[]` 上报依赖回显探测闭环。

设计滞后于教训：CONNECTIVITY §4.3 把 probe 洪泛防护写为"**可选**限速"，而教训 CN-01 明确要求"**强制**限速 + 指数退避（不是可选项）"——探测量 = 候选端点数 × 频率不收敛时，行为特征与扫描/攻击无法区分（被 IDS/风控误判，正常节点被误伤）。且 probe 无认证为有意设计（§4.3，会话建立前无认证链可用），无强制限速时恶意成员/伪造源地址者可借 probe 机制做反射放大（coordinator 回显）与行为特征污染。

实现已起步：probe 编解码（rill-core）、coordinator 回显 + 按源令牌桶（rill-coord）已具备雏形；本 REQ 收口剩余部分（端口分派接线、互探发送侧限速/退避、e2e 验收证据）。

## 决策摘要（建议默认值）

1. **实现 probe 全链**（CONNECTIVITY §2/§2.1/§4 语义落地）：
   - coordinator UDP 回显：STUN 式 seen 地址回显，周期 30s + 网络变更触发，结果上报 netmap `endpoints[]`
   - 数据面端口分派：首字节 `0x01..=0x0F` → 34B 帧；其余匹配 probe magic；两者不匹配 → 丢弃（fail-closed 基线沿用 §2.1：禁止 panic/unwrap、长度严格校验）
   - 直连互探：PING/PONG + nonce 匹配确认端点可达（§4.1 流程）
2. **限速/退避升级为强制默认开启**（设计变更：§4.3 "可选限速" → 强制，落实 CN-01）：
   - coordinator 回显按源 IP 令牌桶（§2.2 既有设计；建议默认 10/s、容量 20）
   - 互探发送侧：强制限速 + 指数退避 + 并发上限——探测量必须有上界，失败按退避重试而非并发轰炸
   - PONG 生成侧按源限速（防反射放大，SEC-26）

## 验收标准（草案）

- CON-01：coordinator 回显闭环（seen 地址回显、`endpoints[]` 上报进 netmap）
- CON-03 / CON-08：帧/probe/乱入字节三分派正确
- SEC-07：非帧/非 probe 字节丢弃
- SEC-26：伪造源地址灌 probe → 按源限速生效，响应 ≈ 请求大小（反射放大被限速收敛）
- CN-01 复核点闭环：强制限速默认开启、指数退避、并发上限收敛
- 验收场景：CON-01 / CON-03 / CON-08、SEC-07 / SEC-26（合并时落 tests/）

## 关联

- 前置（已 merged）：REQ-007（连通性定稿）、REQ-014（端口分派）、REQ-017（回显按源限速）
- 教训对照：CN-01（限速升级为强制）、CN-02（fail-closed 解析）
- 复用：rill-core TokenBucket（与广播令牌桶同源）
