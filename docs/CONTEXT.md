# landscape-rill 前置知识（CONTEXT）

> **新 session 入口文档**：先读本文档恢复设计上下文，再按 §5 文档地图选择后续阅读。
> 本文档记录已收敛的术语、信任模型、外部参考与挂账项，不承载具体协议细节（细节在各设计文档）。
> 版本：v0.2（2026-08-31 修订：节点类型命名定稿——rill 节点 / rill ext 节点 / coord 节点，"腿"中文叫法改为"接入"）

## 1. 项目定位

**landscape-rill** 是 landscape 系列工作区中的 cargo workspace（rill-core / rill-coord / rill-mesh / rill-node / rilld 五 crate，产物二进制 `lrill`），形态是**单 TUN 的用户态路由器/网关节点**：

- 一个 rill ext 节点同时接入多条"接入"（leg）：自建 mesh 网络、dn42、tailscale（自建兼容面 + 官方 tailnet）
- **不做**多 TUN 网卡模型（明确否决内核 WireGuard 多网卡方案）
- 转发决策在**用户态路由策略引擎**中完成；tun0 作为 LAN 侧接口，目标不属于管理 LAN 的流量出 WAN 网卡，WAN 侧 NAT 兜底（mesh exit 因此可透传不 NAT）

**当前阶段：mesh 接入实现闭环**（核心模块 121+ 单测、docker e2e、IPv6 双栈、P0 官方客户端实证，见 requirements/ REQ-022~REQ-033）；文档为需求-设计-验收三层演进体系（[README.md](./README.md)）。

## 2. 需求与决策库

全部已收敛决策（含提出日期与动机）迁移至 [requirements/](./requirements/README.md)（REQ-001~REQ-038、REQ-042、REQ-043 已合并，REQ-039/040/041 挂账中）。状态表按提出日期排序，即原决策时间线视图。

## 3. 目标架构（一图）

```
┌──────────────────── landscape-rill rill ext 节点 ──────────────┐
│  ts2021 客户端接入（自研，URL 可配：自建服务 / 官方 tailnet）        │
│    ├─► 自建控制服务器（headscale 过渡 → 自研服务端）◄── 手机官方 app  │
│    ├─► 官方 tailnet（备份出口）                                    │
│    └─ WireGuard (boringtun) ⇄ 官方客户端节点；subnet router 广播     │
│  mesh 接入（自研控制面 + 34B 帧数据面）⇄ rill 节点                   │
│  dn42 接入（boringtun + Rust eBGP-lite）⇄ dn42 peers                 │
│  路由策略引擎（LPM + 优先级 + fallback）                            │
│  tun0 = LAN 侧；WAN NAT 兜底                                        │
└───────────────────────────────────────────────────────────────────┘
```

## 4. 术语表

| 术语 | 含义 |
|---|---|
| leg（接入） | 一种 overlay 接入方式：mesh / dn42 / ts2021 |
| mesh 模式 | 自建网络：自研控制面（coordinator）+ 自研数据面（34B 帧头） |
| coordinator | mesh 控制面服务器：节点注册、身份绑定签名、key_dst 派生、netmap 权威 |
| rill 节点 | 自研 mesh 协议节点（34B 帧 + 自研控制面），所有节点必具的协议身份 |
| rill ext 节点 | 带外部接入的 rill 节点（dn42 接入 / ts2021 接入为属性标注），即原"边缘节点" |
| coord 节点 | 兼任 coordinator 角色的 rill 节点（能力位 `coordinator`，Raft 期可多个）；独立部署的 coordinator 服务不算节点 |
| 内部节点 | 无外部接入的 rill 节点（形态轴，相对 rill ext 节点） |
| netmap | coordinator 下发的全网拓扑（node_id/公钥/端点/能力，带版本号） |
| key_dst | 转发密钥 `KDF(主密钥, to_node_id)`，route_mac 计算用，按目的派生 |
| broadcast 能力位 | 0x20，L2 广播/组播泛洪 opt-in：keydist 仅向该位节点下发 broadcast_key，泛洪只发该位端点（FRAME_HEADER §2.6 v0.9，CONTROL_PLANE §3.1） |
| 路径服务（Path Service） | v1.5 控制面概念：coordinator 维护路径表（PathMap），节点经 Path\* 消息族请求/接收/撤销候选路径（CONTROL_PLANE §3.11）；v1.5 数据面 34B 帧不变，v2 帧头带 path_id |
| PathMap | 路径表：source/destination/candidate paths/policy/version/expires_at/health——与 netmap（节点是谁）分离，描述节点之间怎么到（CONTROL_PLANE §3.11） |
| path_id | 8B 路径标识（v2 帧头字段，34B→42B）；`path_id = 0` = 默认路径 = 现有 key_dst 语义（v1 兼容回退）；纳入 route_mac 与 AEAD AAD（FRAME_HEADER §9） |
| key_path | 路径授权密钥 `KDF(主密钥, path_id, path_epoch)`，按路径签发、只发路径参与者；v2 route_mac 改用；路径级授权非源认证（CONTROL_PLANE §3.11.5） |
| route_mac | 帧头 16B 轻量认证（双 siphash-2-4），转发节点校验 |
| 桥节点（bridge） | 联邦边界节点：持双方网络密钥，跨界重签 route_mac |
| 联邦（federation） | v2 特性：coordinator 对等互联 + 条目交换/过滤/重签；v1 留三钩子 |
| identity_binding | coordinator 签名 `node_id ⇔ Noise 静态公钥`，防中继 MITM |
| 仅 rill ext 持有 | dn42/tailnet 路由只存在于连接该网络的 rill ext 节点，不进 mesh netmap |
| ts2021 | tailscale 控制协议（Noise + HTTP/2 + tailcfg protobuf） |
| controlbase | ts2021 的 Noise IK 帧层 |
| DERP | tailscale 中继服务器（转发密文，不可解密） |
| boringtun | Cloudflare 的 Rust 用户态 WireGuard 实现 |
| eBGP-lite | 为 dn42 自研的最小 BGP 子集（§DN42_LEG） |
| relay（中继） | 34B 帧转发节点；三层模型：coordinator 兜底 + 自愿节点（relay 位 opt-in）+ 独立部署 |
| probe（探测包） | 直连可达性验证专用小包（magic + node_id + nonce），独立于 34B 帧 |
| 候选端点 | 本地接口地址 ∪ coordinator UDP 回显地址 ∪ 中继地址 |
| 前缀公告（routes[]） | 节点公告自家 LAN/前缀的机制，netmap 条目内嵌，coordinator 白名单校验 |
| 管理面 | coordinator 上的配置面（前缀公告白名单等），v1 形态待定（配置文件/CLI/Web API） |
| 多网络隔离（租户） | 一个 coordinator 服务多个默认互不可见的网络（协议无感，主密钥/密钥空间/netmap 独立）；auth key 绑定网络归域 |
| rekey（会话密钥轮换） | Noise rekey 静默轮换（24h + 控制面联动，双密钥窗口 5s） |
| exit node | 出口节点：非本网流量经它转发出去 |
| subnet router | 把 mesh 前缀/自家 LAN 广播进自建 tailnet 的语义 |

## 5. 文档地图（阅读顺序）

```
docs/README.md（入口：阅读路线 + 三张图）
  ├─► CONTEXT.md（本文档）      前置知识：术语/信任模型/外部参考/路线图
  ├─► requirements/            需求与决策库（REQ stub，入口 README.md）
  ├─► design/                  系统行为权威描述（分域）
  │   ├─► architecture.md      架构总览与数据流
  │   ├─► mesh/                FRAME_HEADER（帧头 v0.9）/ CONTROL_PLANE（v0.5）/ CONNECTIVITY
  │   ├─► legs/                TS2021_LEG / DN42_LEG
  │   └─► routing/             ROUTE_ENGINE
  ├─► tests/                   验收场景与状态（入口 README.md，含验收矩阵）
  │   └─ security/             安全对抗验证（frame/control/tenancy）
  ├─► e2e/                     容器验证环境与脚本说明
  ├─► ci/                      CI 结构与 check-docs.sh
  └─► lessons/                 教训对照（防回归复核表，入口 README.md）
```

## 6. 外部参考

| 资源 | 位置 | 用途 |
|---|---|---|
| Tailscale 官方客户端源码 | `/root/tailscale` | ts2021 协议参照：`control/controlbase/`（Noise 帧）、`control/controlhttp/`（传输）、`control/ts2021/`（会话）、`tailcfg/`（消息）、`derp/`、`disco/` |
| headscale | `https://github.com/juanfont/headscale` | ts2021 服务端参照 + 过渡部署；客户端接入文档 `docs/usage/connect/{android,apple}.md` |
| 关键 crate（候选） | — | boringtun（WG）、snow（Noise）、openraft（P2 Raft）、bgpkit-parser（BGP 线格式解析）、rustls、tokio |
| SCION 文档（借鉴） | `https://docs.scion.org/` | 路径服务/路径段/路径生命周期/逐跳授权思想参照（落地为 CONTROL_PLANE §3.11 路径服务与 key_path 授权） |

## 7. 已验证的关键事实

**官方 Tailscale 客户端支持自定义控制服务器（headscale 兼容服务）**，headscale 官方文档确认：

| 平台 | 入口 |
|---|---|
| Android | 设置 → Accounts → 三点菜单 → `Use an alternate server`（支持 auth key / 网页登录） |
| iOS | 登录界面 → 右上角选项 → `Use custom coordination server` → URL + 凭据 |
| macOS | `tailscale login --login-server <URL>` 或 GUI Debug 菜单 |
| tvOS | 系统设置 → Apps → Tailscale → `ALTERNATE COORDINATION SERVER URL` |

推论：官方客户端数据面是**标准 WireGuard**，不认识 34B 帧头——手机永远只能作为"叶子客户端"经 rill ext 节点接入（WG ⇄ rill ext 节点），这是"双数据面"架构的成因。

## 8. 信任模型要点

- mesh：中心化权威，节点只信自家 coordinator 签名；中继不可信（能做的极限是丢包）
- dn42：**无信任 + 强过滤 + 事后断链**（模仿真实互联网）；恶意 peer 的杀伤范围由 import policy 圈住
- 联邦（v2）：coordinator 双边信任 + 边界过滤 + 条目重签（节点无感知）

## 9. 挂账项与未决问题

**挂账（proposed 需求，已给建议默认值）**：
1. 心跳间隔 / 租约阈值（建议 10s / 60s）——**已落地**（config.rs 常量 DEFAULT_HEARTBEAT_INTERVAL / DEFAULT_LEASE_THRESHOLD，2026-08-15）
2. auth key 格式与生成规范（格式待定，**REQ-036**）——**已定稿（2026-08-31，REQ-036 merged，CONTROL_PLANE §3.12/§6；2026-09-01 REQ-043 修订：格式 `lrk-<network>-<expiry>-<secret>`，过期时间内嵌 key、默认 24h、`lrill authkey --ttl`，`expires_at` 配置字段移除）**：`lrk-<network>-<secret>` + `lrill authkey` 生成子命令；控制面端口号——**默认 8443 已落地**（config.rs DEFAULT_COORD_PORT，TLS 长连接非特权端口）
3. protobuf schema 文件与代码生成（文档为语义级）——**已落地（2026-08-15，2026-08-30 重构为独立 rill-proto crate）**：`rill-proto/proto/control.proto`（CONTROL_PLANE §3 消息字段级）+ build.rs 用 **pb-rs** 生成 → OUT_DIR 的 wire 模块（不入库，`landscape-rill-proto` crate 对外暴露；quick-protobuf 运行时）
4. v1 存储后端（redb / sqlite 候选，**REQ-037**）——**已定稿（2026-08-31，REQ-037 merged，CONTROL_PLANE §4.1）**：redb（Rust 原生、单文件、无 C 依赖；sqlite 否决——数据形态全为主键点查）；持久状态整快照原子写 + 写穿透（register/set_endpoints/request_paths/revoke/rotate_master_key）；一次性 auth key 消费 tombstone 落盘（重启/重载不复活）；损坏/不一致 → 拒绝启动（fail-closed）；`storage_path` 仅启动读取（None = 纯内存）
5. **管理面形态**（前缀公告白名单配置方式，**REQ-038**）——**已定稿（2026-08-31，REQ-038 merged，CONTROL_PLANE §3.12）**：配置文件为唯一权威 + `CoordConfig`（加载即校验，fail-closed）+ 库 API 执行面分离（from_config/apply_config，函数调用生效）+ SIGHUP 重载增量应用；Web API 挂 P3（自研 ts2021 服务端/landscape-webserver 同批，REQ-040 边界自然满足）
6. **运维基线**（P2，**REQ-039**）：cargo audit 进 CI + 依赖最小化（供应链）；日志限速（错误风暴防刷屏）+ **轮转/容量上限 + 级别配置生效性验证**（教训见 lessons/admin-ops/AO-04）
7. **配置解析要求**：配置中域名解析**缓存 + 指数退避**，禁止无背压循环解析——**已落地**（config.rs DnsCache，教训见 lessons/keys-config/KC-03）
8. **WebUI 配置边界**（**REQ-040**）：关键配置只存服务端（coordinator 配置文件/DB），WebUI 不持有持久配置（教训见 lessons/admin-ops/AO-02）

**远期特性（proposed 需求）**：
- **路径服务（v1.5 控制面 / v2 数据面，REQ-034，设计已合并 CONTROL_PLANE §3.11）**：PathMap 与 netmap 分离；PathRequest/PathResponse/PathUpdate/PathWithdraw/PathProbe 消息族；每目标 2~4 候选路径 + flow hash + 快速切换 + 路径生命周期；**v2 帧头固定 8B path_id**（34B→42B，纳入 route_mac/AAD），route_mac 改用 `key_path = KDF(主密钥, path_id, path_epoch)` 按路径签发（`path_id=0` 回退 key_dst，v1 数据面零改动）；**路径集合 = 路径级 ACL**（与 ACL v2 衔接）
- **ACL v2（零信任式逐请求授权，REQ-020，v1 已预留全套钩子）**：coordinator 下发策略（subject=node_id/网络、object=前缀/端口、action），随 netmap 原子下发（version 一版本两用，CONTROL_PLANE §3.2）；裁决点 = 路由引擎 LPM 命中后（ROUTE_ENGINE §2，v1 恒放行）；**源身份约束：只做目标节点侧裁决**（ROUTE_ENGINE §3）；`acl` 能力位已划归（v1 恒 false）；Policy 消息族组空间已预留（§3.10）；管理面形态定稿时纳入策略模型（REQ-038）；验证场景挂账（tests/security/tenancy SEC-28）；**v2 升级路径 = 路径级授权（§3.11.6：签发路径即策略，relay 侧可执法）**；组级隔离开放时 probe/打洞信令需同样门控（否则组间可借直连/打洞绕过 ACL）
- **Web 纯终端（v3 候选，REQ-041）**：浏览器临时设备接入（网吧/他人电脑访问 mesh 资源）——形态 = 轻量代理通道（TLS/WSS/WebTransport）连 rill ext 节点"Web 接入网关"，非 rill 节点协议；实现手段（Rust→wasm32 vs 纯 JS）届时评估；核心模块 I/O 无关约定使其零重构可行

（帧分片已闭环：REQ-009——不做分片，ROUTE_ENGINE §6）

**未决项已全部收敛（REQ-021，2026-08-15）**：
1. **ts2021 接入认证 = 仅 auth key**（自研客户端仅 rill ext 节点形态、无人值守；官方 app 交互登录 = 服务端职责，P0 实证）——TS2021_LEG §3.2
2. **ts2021 数据面 v1 = DERP-only**（手机↔rill ext 流量量小；disco 自研成本高风险大，挂 v2）——TS2021_LEG §3.3
3. **路由冲突消解 = 固定来源优先级 `LAN > mesh > dn42 > tailnet`**（各接入空间天然不重叠；metric 挂 v2）——ROUTE_ENGINE §3
4. **DNS 分类语义 = 分域解析代理**（单点 53 代理按后缀分发：`.mesh` → 控制面名称表、`.dn42` → 172.20.0.53、tailnet → headscale DNS 配置、其余 → 上游；LAN 侧分发机制实现时定）——ROUTE_ENGINE §7

（tailnet 路由传播已定稿：rill ext 节点公告 tailnet 前缀进 mesh，见 ROUTE_ENGINE §3 回程）

## 10. 路线图

| 阶段 | 内容 |
|---|---|
| P0 | 过渡验证：部署 headscale + derper，官方 app 入网端到端（证明"手机直连"可行）——**已完成（REQ-033）** |
| P1 | mesh 骨架：crate 落地（tun + 用户态转发骨架）+ mesh 接入（单 coordinator + 34B 帧）——**大部完成（REQ-022~REQ-032）** |
| v1.5 | 路径服务（控制面）：Path\* 消息族 + 每目标 2~4 候选路径/快速切换 + 路径生命周期 + flow hash（CONTROL_PLANE §3.11，REQ-034）；数据面 34B 帧不变 |
| P2 | 接入：ts2021 客户端接入（连 headscale + subnet router 广播）+ dn42 接入（boringtun + eBGP-lite） |
| P3 | 融合与自研：路由策略引擎完善 + exit 双向语义 + 自研 ts2021 服务端替换 headscale + Raft |
| P4 | 性能与联邦：XDP 快速路径 + DNS 统一 + 联邦 v2 + 帧头 path_id 数据面（v2，§3.11） |

**当前进度：P0 完成（REQ-033 官方客户端入网实证），P1 mesh 骨架大部落地（REQ-022~REQ-032 实现闭环），P2 接入推进中。**
