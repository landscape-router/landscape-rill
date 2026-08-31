# landscape-rill 架构总览（ARCHITECTURE）

> 定位：多腿边缘节点的整体架构。数据面帧头见 FRAME_HEADER，控制面见 CONTROL_PLANE，腿设计见 TS2021_LEG / DN42_LEG，转发决策见 ROUTE_ENGINE。
> 版本：v0.1（2026-08-15）｜ 相关需求：REQ-005 / REQ-006 / REQ-019 / REQ-030

## 1. 定位与形态

**单 TUN 的用户态路由器/网关节点**：

- 唯一网卡接口 tun0 = **LAN 侧**（内网设备/本机应用接入）
- 用户态转发栈是所有流量的汇合点：决定走哪条腿、封装成什么、发往哪里
- 目标 IP 不属于管理 LAN → 出 **WAN 网卡**，WAN 侧 NAT 兜底（因此 mesh exit 可以仅透传不做 NAT）
- 明确否决的形态：多 TUN 网卡模型（tailscaled 式每腿一网卡）、内核策略路由 + 内核 WireGuard

## 2. 总体架构

```
┌────────────────────────── landscape-rill ──────────────────────────┐
│                                                                      │
│   tun0（LAN 侧）◄───────► 路由策略引擎（LPM + 优先级 + fallback）       │
│                              │                                       │
│        ┌─────────────────────┼─────────────────────┐                 │
│        ▼                     ▼                     ▼                 │
│   ┌──────────┐        ┌──────────┐         ┌──────────────┐          │
│   │ mesh 腿   │        │ dn42 腿   │         │ ts2021 腿     │          │
│   │ 34B 帧     │        │ boringtun │         │ 自研客户端     │          │
│   │ 自研控制面  │        │ + eBGP    │         │ + boringtun WG│          │
│   │ (coordinator)│      │ (boringtun)│        │ + subnet router│         │
│   └──────────┘        └──────────┘         └──────────────┘          │
│        │                   │                     │                   │
│        ▼                   ▼                     ▼                   │
│   mesh 节点           dn42 peers        自建控制面(headscale→自研)     │
│                                        ◄── 手机官方 app（WG 数据面）    │
│                                        官方 tailnet（备份出口）        │
│                                                                      │
│   eth0（WAN 侧，NAT 兜底）                                            │
└──────────────────────────────────────────────────────────────────────┘
```

## 3. 四条腿明细

| 腿 | 控制面 | 数据面 | 身份 | 信任域 |
|---|---|---|---|---|
| **mesh** | 自研 coordinator（CONTROL_PLANE） | 34B 帧头自研封装（FRAME_HEADER），多跳转发 | node_id 4B + Noise 静态密钥 + coordinator 签名绑定 | 中心化权威，只信自家签名 |
| **dn42** | 无（BGP 对等互联） | boringtun WireGuard 隧道（每 peer 一条） | ASN + 前缀（registry 记录） | 无信任 + 强过滤 + 断链 |
| **ts2021（自建）** | headscale（过渡）→ 自研服务端 | boringtun WireGuard，手机官方 app 数据面 | machine key / node key / auth key | 自建控制面 + 官方客户端 |
| **ts2021（官方）** | 官方控制面 | boringtun WireGuard + DERP 中继 | 同上 | 官方信任域（备份出口） |

## 4. 双数据面分工（核心设计）

- **兼容数据面（WireGuard）**：面向官方客户端（手机/平板）。手机不认识 34B 帧头，只能做"叶子客户端"：`手机 ⇄ 边缘节点（boringtun WG 端点）`。
- **内网数据面（34B 帧）**：mesh 节点之间的内部通道（XDP 友好、中继优化、联邦预留），与官方客户端完全解耦。
- 边缘节点是**双数据面网关**：手机流量经 WG 进入后，由路由策略引擎决定走本地处理、mesh 帧转发、还是出 WAN。

## 5. 控制面关系（浅结合）

- **coordinator**（mesh 控制面，自研协议）与 **ts2021 服务端**（headscale 兼容）**同进程、协议独立、可共享存储**——浅结合。
- 边缘节点以 **ts2021 客户端身份**再挂入自建 tailnet（一个节点两个身份：mesh 节点 + tailnet 节点）。
- 深结合（双协议共享注册表、node_id ⇄ tailnet 节点映射）为 v2 演进方向。

## 6. 关键数据流示例

**手机访问 mesh 内资源**：
```
手机(官方app) --WG--> 边缘节点 boringtun 端点
  → 解包 → 路由策略引擎：dst 属 mesh 前缀
  → 经 mesh 34B 帧转发到目标节点（或本地处理）
```

**手机访问互联网**：
```
手机 → 边缘节点 → 引擎：dst 非 LAN/mesh/dn42/tailnet
  → tun0（LAN 侧语义）→ 内核 → WAN 网卡 → NAT
```

**dn42 流量（仅边缘持有）**：
```
内部节点 → mesh 帧 → 边缘节点 → 引擎：dst ∈ dn42 空间
  → dn42 腿（boringtun 隧道）→ eBGP 选路 → dn42 peer
```

**exit 语义**：
- mesh exit：经 mesh 帧送到出口节点，出口节点**仅透传**（不 NAT，WAN NAT 兜底）
- ts2021 exit：非本网流量经 tailnet exit node（自建或官方）转发

## 7. 组件依赖（crate 内模块草案）

```
landscape-rill
├── tun           TUN 驱动 + 包读写
├── route         LPM 路由表 + 优先级 + fallback（ROUTE_ENGINE.md）
├── legs/
│   ├── mesh      控制面客户端 + 34B 帧收发（依赖 control/ + frame/）
│   ├── dn42      boringtun 隧道管理 + eBGP-lite
│   └── ts2021    控制客户端 + WG 会话 + subnet router + DERP 客户端
├── control      （mesh）coordinator 客户端协议栈
├── frame        34B 帧头编解码 + route_mac + AEAD
└── coord         coordinator 角色（可选运行：单机 → openraft）
```

**核心模块 I/O 无关约定**（WASI/浏览器决策，REQ-019）：`frame`、`control`、`route` 三个纯逻辑模块**禁止混入 tokio/io/网络类型**——只做数据进出（字节/消息结构），socket/TUN/定时器全部在 `tun`/`legs`/外层胶水实现。将来若做 Web 终端（wasm32）或嵌入式，只需为这三个模块加宿主绑定层，零重构。

## 8. 非目标

- 不做多 TUN 模型、不做内核路由依赖（用户态决策）
- 不做完整 BGP（dn42 最小集）
- 不做 disco/NAT 打洞（v1 走 DERP）
- 不做去中心化控制面（远期方向）
