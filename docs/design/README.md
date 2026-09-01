# landscape-rill 系统设计（design）

> 系统行为的**权威描述**（唯一内容载体）。需求/动机见 [../requirements/README.md](../requirements/README.md)，验收见 [../tests/README.md](../tests/README.md)。
> 版本：v1.1（2026-08-30 重构：分域目录 + 短名注册；§3 目录树：proto 拆分为独立 rill-proto crate，生成代码改 OUT_DIR 不入库）

## 1. 域地图

| 域 | 文件 | 短名 | 内容 |
|---|---|---|---|
| 总览 | [architecture.md](./architecture.md) | `ARCHITECTURE` | 整体架构、双数据面、数据流、非目标 |
| mesh | [mesh/frame-header.md](./mesh/frame-header.md) | `FRAME_HEADER` | 34B 帧头、握手/心跳/广播规格、密钥体系 |
| mesh | [mesh/control-plane.md](./mesh/control-plane.md) | `CONTROL_PLANE` | 控制面协议、状态模型、安全模型、联邦、路径服务 |
| mesh | [mesh/connectivity.md](./mesh/connectivity.md) | `CONNECTIVITY` | 端点探测、直连验证、三层中继 |
| legs | [legs/ts2021.md](./legs/ts2021.md) | `TS2021_LEG` | ts2021 兼容接入、headscale 过渡、官方客户端接入 |
| legs | [legs/dn42.md](./legs/dn42.md) | `DN42_LEG` | dn42 接入、eBGP-lite、import/export policy |
| routing | [routing/route-engine.md](./routing/route-engine.md) | `ROUTE_ENGINE` | 路由策略引擎、LPM、fallback、MTU、DNS 分类 |
| runtime | [runtime/logging.md](./runtime/logging.md) | `LOGGING` | daemon 日志：框架、级别、格式、存储、限速、红线 |
| runtime | [runtime/errors.md](./runtime/errors.md) | `ERROR_ID` | 错误处理：thiserror 规范、稳定错误 ID、序列化信封 |

## 2. 短名注册（代码注释引用契约）

**代码注释引用格式：`<短名> §<x.y>`**（如 `FRAME_HEADER §2.6`）。短名必须在本表注册；`§x.y` 必须存在于目标文件的编号标题。`ci/check-docs.sh` 校验此契约。

| 短名 | 注册文件 |
|---|---|
| `ARCHITECTURE` | [architecture.md](./architecture.md) |
| `FRAME_HEADER` | [mesh/frame-header.md](./mesh/frame-header.md) |
| `CONTROL_PLANE` | [mesh/control-plane.md](./mesh/control-plane.md) |
| `CONNECTIVITY` | [mesh/connectivity.md](./mesh/connectivity.md) |
| `TS2021_LEG` | [legs/ts2021.md](./legs/ts2021.md) |
| `DN42_LEG` | [legs/dn42.md](./legs/dn42.md) |
| `ROUTE_ENGINE` | [routing/route-engine.md](./routing/route-engine.md) |
| `LOGGING` | [runtime/logging.md](./runtime/logging.md) |
| `ERROR_ID` | [runtime/errors.md](./runtime/errors.md) |

引用规范：
- 只在**协议/安全契约绑定处**引用（常量、线格式、加密语义、安全边界），纯实现逻辑不引
- 文档章节重排时若引用失效，由 check 脚本报错，由改文档者决定改注释还是保留编号
- 反向引用（design → src 实现位置）保持稀疏，只在"决策记录/实现级决定"章节出现

## 3. 工程目录与模块边界

```
landscape-rill/                  # cargo workspace（virtual）
├── rill-proto/                  # protobuf schema + 生成代码（发布名 landscape-rill-proto）
│   ├── proto/control.proto      # protobuf schema（CONTROL_PLANE §3 字段级）
│   ├── build.rs                 # pb-rs 生成（proto/ → OUT_DIR wire 模块，不入库）
│   └── src/lib.rs               # pub mod wire（include! OUT_DIR/mod.rs）
├── rill-macro/                  # derive 宏（发布名 landscape-rill-macro）：ErrorId（ERROR_ID §3）
├── rill-core/                   # ★ I/O 无关纯逻辑（见 §4 边界），发布名 landscape-rill-core
│   └── src/
│       ├── crypto.rs            # HKDF-SHA256 / X25519 / ChaCha20-Poly1305 / route_mac
│       ├── error.rs             # ErrorId trait + ErrorEnvelope（ERROR_ID）
│       ├── frame.rs             # 34B 帧头编解码 + AEAD（FRAME_HEADER）
│       ├── handshake.rs         # Noise_XX 握手状态机与会话（FRAME_HEADER §2.4）
│       ├── route.rs             # LPM 路由表 + fallback（ROUTE_ENGINE）
│       └── control/             # 注册表/吊销/挑战/会话状态机（CONTROL_PLANE）
├── rill-coord/                  # coordinator 角色：coordinator.rs（跨域编排门面）+ authkey.rs
│   │                            # （lrk 格式）+ directory.rs（目录）+ liveness.rs（活性）+
│   │                            # keys.rs（密钥域）+ path_service.rs + signer.rs（Ed25519）+ store.rs
├── rill-mesh/                   # mesh 接入：control/（TLS 客户端/服务端/编解码）+ data.rs（UDP 转发）+ framing.rs
│   └── src/control/             # 控制面：client.rs + server.rs + codec.rs + tls.rs（PROTOCOL_VERSION 等共享项在 mod.rs）
├── rill-node/                   # 节点角色胶水（I/O 侧）
│   └── src/
│       ├── config.rs            # 配置解析（加载即校验、无默认凭据、DNS 缓存+退避）
│       ├── tun.rs               # TUN 驱动
│       ├── packet.rs            # 纯手写 L3 解析
│       └── runtime.rs           # 单线程编排（pump_control/mesh/lan/timers）
├── rilld/                       # 二进制 lrill：CLI 入口（pubkey/run 子命令，REQ-042）
├── e2e/                         # 容器验证（run_e2e.sh + mesh/{direct,relay}/ + p0_tailscale/，见 ../e2e/）
└── docs/                        # 本文档体系
```

### 3.1 模块职责与依赖方向

```
                ┌──────── config / main / runtime（编排，可依赖一切）
                │
      ┌─────────┼──────────┐
      ▼         ▼          ▼
  node/tun  node/packet  legs/mesh
      │         │          │
      └─────────┴──► core ◄┘      （core 内部：crypto ← frame/handshake；control → proto 消息类型 + crypto）
                    │
                  coord ┘          coord 复用 proto 的 wire 消息类型（landscape-rill-proto）
```

- **core/ 被所有 I/O 层依赖，且不得反向依赖**（`#![forbid(unsafe_code)]` 同样适用）
- 依赖边界即编译检查：core/ 的 `use` 中禁止出现 `tokio`、`std::net`、`std::io`（CI lint 强制）

### 3.2 I/O 无关边界（决策：REQ-019）

`core/` 是**纯逻辑**：只做数据进出（字节/消息结构），socket/TUN/定时器全部在 `node/`、`legs/`、外层胶水实现——将来 wasm32/嵌入式只加宿主绑定层，零重构。

| 允许 | 禁止 |
|---|---|
| 字节切片/Vec 进出的函数 | `tokio` / `std::net` / `std::io` 等任何 I/O 类型 |
| 纯数据消息结构（proto wire 类型） | socket、定时器、TUN 引用（类型签名中不得出现） |
| 无状态/显式状态机实现 | 全局可变状态、静态连接 |

## 4. 设计文档规范

- 每个文件头部：版本号 + 最近修改时间 + 相关需求（REQ-NNN 列表）
- 章节用编号标题（`## 2.`、`### 2.6`），供代码注释 `§x.y` 引用
- 行为内容只存在于 design/，REQ stub 与本文档不重复承载内容
