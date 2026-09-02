# REQ-055 XDP 伪装 TCP 传输（无栈 QoS 规避）

> 类型：决策 ｜ 状态：📌 proposed ｜ 优先级：P4 ｜ 依赖：REQ-054 ｜ 提出：2026-09-01

## 动机

REQ-054 的真 TCP 兜底解决"UDP 被封"，但两类场景覆盖不了：

1. **UDP 被降级/限速而非封禁**（协议分类式 QoS）：真 TCP 内核栈的重传/队头阻塞使时延吞吐劣化，且无零拷贝收益
2. **P4 XDP 快速路径**：REQ-053 已为其预留 WAN 接缝；伪装 TCP 传输是 XDP 的首个承载——中间盒视角合法 TCP 头，两端 eBPF 截获进 AF_XDP，内核栈无感知

## 决策摘要（建议默认值）

1. **伪装传输与 XDP 传输为同一实现**：纯用户态无栈伪装不可行（对端内核对无监听端口的"TCP"包回 RST）；标志位仅供两端自家 eBPF 识别，命中 → XDP_REDIRECT 进 AF_XDP，收发绕过内核协议栈
2. **无握手定位（接受）**：不仿真 TCP 握手——过不了 conntrack 状态防火墙（无 SYN 历史）；该场景退 REQ-054 真 TCP 档，对抗协议分类式 QoS 足够
3. **头部合理性**：eBPF 侧维护逐流 seq 递增、合法 checksum（中间盒会校验）；流状态为实现私有数据（沿用 REQ-054 身份在帧头的设计）
4. **两端对等前提**：对端需运行 rill + 同款 eBPF（CAP_BPF/CAP_NET_ADMIN）；Linux-only；e2e Docker veth 以 generic XDP 模式验证

## 非目标

- TCP 握手仿真 / 完整用户态 TCP 栈（当前评估复杂度大于收益，需求变化可再评估）
- 状态防火墙穿透（conntrack 场景由 REQ-054 真 TCP 档覆盖）
- Windows/macOS（AF_XDP 为 Linux 机制）
- native XDP 驱动验证（e2e 以 generic 模式为验收环境）

## 开放问题

1. **标志位设计**：TCP option 暗号 vs seq 低位 magic（eBPF 匹配成本 / DPI 可见性 / 与真实流量碰撞率）
2. **伪装端点的公网发现**：REQ-054 开放问题 2 的特化——XDP 实现可从 AF_XDP 收包自学习对端地址，与 coord echo 扩展二选一
3. **AF_XDP 缓冲模型**：UMEM 注册/复用与 REQ-053 BytesMut 接缝的衔接

## 验收标准（草案）

- eBPF 标志识别 + AF_XDP 收发跑通：e2e veth generic 模式 direct 场景
- 抓包验证：对外线格式为合法 TCP（checksum/seq 校验通过，工具断言）
- 无标志的正常 TCP 流量不受影响（eBPF 旁路正确性）
- 裸 UDP 与真 TCP 传输回归全绿（多传输并存）

## 关联

- 依赖：REQ-054（trait 与链路模型；身份在帧头设计沿用）
- 路线图：P4（XDP 快速路径首个承载）
- 复用：REQ-053 WAN 接缝、golden vectors（帧字节一致断言沿用）
