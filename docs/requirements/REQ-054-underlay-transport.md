# REQ-054 数据面 underlay 传输抽象（trait 与真 TCP 兜底）

> 类型：决策 ｜ 状态：📌 proposed ｜ 优先级：P2 ｜ 依赖：REQ-053 ｜ 提出：2026-09-01

## 动机

数据面当前只会裸 UDP：协议指纹明显（首字节 0x01/0x02 + 固定 34B/42B 布局），UDP 被 QoS（限速/降优先级/封禁）时全网失能，无伪装也无逃生通道。

1. **传输单一**：`MeshData` 直连 `UdpSocket`（触点已由 REQ-053 收拢为私有原语），换传输 = 改核心代码
2. **无兜底**：UDP 被完全封禁的网络（企业/校园白名单式）下 mesh 整体不可用
3. **REQ-053 止步于函数级接缝**：其决策 6 收拢 WAN 触点但"不引入 trait"——本 REQ 在其之上把收拢后的原语抽成显式传输接缝

## 决策摘要（建议默认值）

1. **报文语义 trait**（落在 rill-mesh/src/data/，rill-core 保持 I/O-free）：v1 形态为 `send_frame(addr, buf)` / `recv_frame(buf) -> addr` / `local_endpoint()`，buffer 传参与 053 的 BytesMut 对齐；流式实现内部加长度前缀分帧解决流/报文失配。连接式传输的连接建立、惰性 connect、断线重连、缓冲管理 v1 均为实现内部细节；trait 按当前需求最小化，后续需求出现再演进
2. **身份在帧头**：线上身份由帧头（from_node/to_node/path_id）承载，每帧信任来自 route_mac/AEAD 而非传输层或对端连接状态（"只信任帧"）。传输实现内部状态（连接对象、流表等）为私有细节，v1 线上无节点/连接编号；path_id 语义为授权凭证，与传输层活性状态生命周期不同，实现内部不以 path_id 索引连接（避免授权轮换与传输重连耦合）
3. **帧字节跨传输一致（验收断言）**：各传输上帧本体逐字节相同（含首字节分类标签 0x01..=0x0F / "LPRB"）；流式仅外覆长度前缀；帧与 probe 可共存一条流，靠首字节分类区分。053 golden vectors 因此天然覆盖所有传输
4. **传输谱系全景**（落地范围见关联）：

   | 档 | 形态 | 对抗目标 | 代价 |
   |---|---|---|---|
   | 裸 UDP（默认） | UdpSocket | — | 指纹明显 |
   | 伪装 TCP | XDP 标志 + AF_XDP 无栈 | 协议分类式 UDP QoS | 见 REQ-055 |
   | 真 TCP（本 REQ） | TcpStream + 长度分帧 | UDP 全封兜底 | HOL |
   | WS/QUIC（远期） | 用户态栈 | 深度 DPI / CDN 穿透 | 真 TLS/QUIC 开销 |

5. **relay 链路择优泛化**：端点 → 链路 = (后继节点, 地址, 传输)；同后继多链路按 RTT/丢包择优，评估 = 缓存 + 周期刷新 + 滞回（不逐帧评估）；统计源复用 probe RTT + 入站帧健康（REQ-034 机制），不新增专用心跳。path_id 定路线（coordinator 授权），链路选择是本地自由度，两层解耦
6. **relay 择优缺口修复**：relay 转发侧端点选择现固定取 `.first()`（v1 直连分支与 v2 `path_next_hop` 均是），未走 `order_endpoints` 择优——与传输抽象无关的现有差距，随本 REQ 一并修
7. **流式断线信号回喂**：连接式传输的 send 失败喂进 endpoint_health/miss 机器（流式链路由推断升级为实报，现有机制不变）

## 非目标

- 控制面传输抽象（codec 已泛型 AsyncRead/AsyncWrite）
- 传输层线上身份/编号字段（v1 线上身份以帧头为准，如后续需求出现再评估）
- XDP 伪装传输（→ REQ-055，依赖本 REQ）
- WS/QUIC 传输（远期，届时另立）
- coord UDP echo 第三路径改造（挂账，见开放问题 2 的交互）
- 协议兼容包袱（crate 未 2.x，线格式可改）

## 开放问题（立项评审拍板）

1. **netmap 端点模型扩展**：端点需带传输标注（真 TCP 落地即需：节点如何得知对端开了 TCP 端口）——端点标注字段 vs probe 协议扩展发现 vs 约定端口派生
2. **非 UDP 传输的公网端点发现**：coord UDP echo 学不到 TCP 传输的 NAT 映射。候选：probe ride 该传输 + coord 对应端口开 echo ／ 控制面注册响应带 seen endpoint（NAT 对数据/控制端口开的洞未必同址）
3. **TCP 实现的连接生命周期**：惰性 connect 时机、空闲超时、重连退避与 miss 机器的联动节奏

## 验收标准（草案）

- trait 落地，裸 UDP 实现行为不变：现有单测 + e2e direct/relay 全绿，golden vectors 不变
- 真 TCP 传输跑通 e2e direct；帧字节与 UDP 逐字节一致（仅多长度前缀，有断言）
- relay 侧端点选择走择优（v1/v2 分支，缺口修复有单测）
- 同后继多端点/多传输下，劣化链路被置后、恢复后回归（单测）
- TCP 链路断线后 send 失败驱动 miss/健康状态迁移（单测）

## 关联

- 依赖：REQ-053（已 merged → FRAME_HEADER §2.2/§8；触点收拢后 trait 抽取为机械操作，本 REQ 延伸其决策 6，由函数级接缝进为显式 trait）
- 衍生：REQ-055（XDP 伪装 TCP，依赖本 REQ 的 trait 与链路模型）
- 路线图：可提前独立落地（不占 P4 排期）
- 复用：REQ-034 端点健康/路径活性、probe RTT、REQ-053 BytesMut/golden vectors
