# landscape-rill

> 多接入 rill ext 节点:基于 Rust 的**单 TUN 用户态路由器/网关**。

`landscape-rill` 是 landscape 工作区的路由核心。一个 rill ext 节点同时接入多条 overlay 网络("接入",leg),转发决策由**用户态路由策略引擎**完成——不做内核 WireGuard,不做多 TUN 网卡模型。

## 特性

- **mesh 接入** —— 自建 overlay 网络:自研控制面(coordinator)+ 34B 帧数据面
- **ts2021 接入**(P2)—— tailscale 兼容控制协议;headscale 过渡 → 自研服务端;官方客户端 app 以 WireGuard 叶子客户端接入
- **dn42 接入**(P2)—— boringtun + Rust eBGP-lite
- **路由策略引擎** —— LPM + 固定来源优先级(`LAN > mesh > dn42 > tailnet`)+ fallback
- **tun0 = LAN 侧;WAN NAT 兜底** —— mesh exit 透传不 NAT
- **I/O 无关核心**(`rill-core`)—— 纯逻辑,wasm32/嵌入式零重构可移植

## 当前进度

P0 完成(官方 Tailscale app 经 headscale 入网端到端实证,REQ-033),P1 mesh 骨架大部落地(REQ-022~REQ-032,核心模块 121+ 单测、docker e2e、IPv6 双栈),P2 接入推进中。

## 目标架构

```
┌──────────────────── landscape-rill rill ext 节点 ──────────────┐
│  ts2021 客户端接入(自研,URL 可配:自建服务 / 官方 tailnet)         │
│    ├─► 自建控制服务器(headscale 过渡 → 自研服务端)◄── 手机官方 app  │
│    ├─► 官方 tailnet(备份出口)                                    │
│    └─ WireGuard (boringtun) ⇄ 官方客户端节点;subnet router 广播     │
│  mesh 接入(自研控制面 + 34B 帧数据面)⇄ rill 节点                   │
│  dn42 接入(boringtun + Rust eBGP-lite)⇄ dn42 peers                │
│  路由策略引擎(LPM + 优先级 + fallback)                            │
│  tun0 = LAN 侧;WAN NAT 兜底                                        │
└───────────────────────────────────────────────────────────────────┘
```

## 工程目录

```
landscape-rill/                  # cargo workspace
├── rill-proto/                  # protobuf schema + 生成代码(发布名 landscape-rill-proto)
├── rill-core/                   # ★ I/O 无关纯逻辑(crypto / frame / handshake / route / control)
├── rill-coord/                  # coordinator 角色(coordinator.rs + Ed25519 signer.rs)
├── rill-mesh/                   # mesh 接入(control TLS + data UDP + framing)
├── rill-node/                   # 节点角色胶水(config / tun / packet / runtime)
├── rilld/                       # lrill 二进制(CLI 入口)
├── e2e/                         # 容器验证(docker compose + 断言)
└── docs/                        # 需求 → 设计 → 测试 文档体系
```

## 构建与测试

```bash
# release 二进制(e2e / 部署共用)
./scripts/build.sh

# mesh e2e:CA/证书 → 配置 → 起容器 → mesh ping 断言(IPv4 + IPv6)
./e2e/run_e2e.sh
```

## 文档

文档为需求驱动演进体系:`docs/requirements/`(为什么/何时)→ `docs/design/`(权威行为)→ `docs/tests/`(验收)→ `e2e/ci`(证据)。

- 入口阅读:[docs/CONTEXT.md](docs/CONTEXT.md) —— 术语、信任模型、路线图
- 文档中心:[docs/README.md](docs/README.md) —— 阅读路线 + 三张图
- 设计(短名注册,如 `FRAME_HEADER §2.6`):[docs/design/README.md](docs/design/README.md)
- 本文档英文版:[README.md](README.md)

## 路线图

| 阶段 | 内容 |
|---|---|
| P0 | headscale + derper 部署,官方 app 入网端到端 —— **已完成(REQ-033)** |
| P1 | mesh 骨架:crate 落地 + mesh 接入(单 coordinator + 34B 帧)—— **大部完成** |
| v1.5 | 路径服务(控制面):Path\* 消息族、快速切换、路径生命周期 |
| P2 | 接入:ts2021 客户端接入 + dn42 接入(eBGP-lite) |
| P3 | 融合与自研:路由引擎完善、exit 语义、自研 ts2021 服务端、Raft |
| P4 | 性能与联邦:XDP 快速路径、DNS 统一、联邦 v2、path_id 数据面 |

## 许可证

LGPL-3.0-only —— 见 [LICENSE](LICENSE)。
