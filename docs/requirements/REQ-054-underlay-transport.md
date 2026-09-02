# REQ-054 数据面 underlay 传输抽象（trait 与真 TCP 兜底）

> 类型：决策 ｜ 状态：✅ merged ｜ 提出：2026-09-01 ｜ 合并：2026-09-02
> 去向：FRAME_HEADER §2.8/§8 ｜ 验收场景：CON-11 ｜ lessons：CN-03（共享节点不认证——"只信任帧"沿既定信任模型）

## 动机

数据面当前只会裸 UDP：协议指纹明显（首字节 0x01/0x02 + 固定 34B/42B 布局），UDP 被 QoS（限速/降优先级/封禁）时全网失能，无伪装也无逃生通道。

1. **传输单一**：`MeshData` 直连 `UdpSocket`（触点已由 REQ-053 收拢为私有原语），换传输 = 改核心代码
2. **无兜底**：UDP 被完全封禁的网络（企业/校园白名单式）下 mesh 整体不可用
3. **REQ-053 止步于函数级接缝**：其决策 6 收拢 WAN 触点但"不引入 trait"——本 REQ 在其之上把收拢后的原语抽成显式传输接缝

## 决策摘要

1. **报文语义 trait**（rill-mesh，rill-core 保持 I/O-free）：`send_frame / recv_frame / local_endpoint`，buffer 传参与 053 BytesMut 对齐；连接管理为实现内部细节
2. **身份在帧头（只信任帧）**：线上身份由帧头承载，信任来自 route_mac/AEAD 而非传输层或连接状态
3. **帧字节跨传输一致**：UDP 裸帧 / 真 TCP 仅外覆 2B 长度前缀；帧与 probe 靠首字节分类共存一条流；053 golden vectors 天然覆盖所有传输
4. **传输谱系**：裸 UDP（默认）→ 真 TCP（兜底）→ 伪装 TCP（REQ-055）→ WS/QUIC（远期）
5. **relay 链路择优**：端点选择统一 `order_endpoints`，修复固定 `.first()` 缺口；传输维度并入链路自由度
6. **断线信号回喂**：TCP send 失败喂端点 miss/健康机器
7. **开放问题实际形态**：netmap 端点不带传输标注（传输档 = 节点配置、v1 全网同档）；TCP NAT 公网端点发现挂账

## 去向

- **FRAME_HEADER §2.8**：underlay 传输线格式（UDP 裸帧 / 真 TCP 2B 前缀）
- **FRAME_HEADER §8**：trait 接缝 / 只信任帧 / 链路择优 / 断线回喂实现级决定
- **CONNECTIVITY §8**：relay 链路择优泛化 + 断线回喂决策记录
- 验收场景：CON-11（[tests/mesh/connectivity.md](../tests/mesh/connectivity.md)）
