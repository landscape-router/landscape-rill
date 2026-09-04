# 路由策略引擎（ROUTE_ENGINE）

> landscape-rill 的转发决策核心：单 TUN 汇合点，统一裁决流量走哪条接入。
> 版本：v0.4（2026-09-03 修订：封装开销措辞同步 42B 帧头（MTU 86B，REQ-066））｜ 相关需求：REQ-005 / REQ-008 / REQ-009 / REQ-014 / REQ-017 / REQ-020 / REQ-021 / REQ-023

## 1. 定位

所有流量（南北向 + 东西向）经 tun0 进入用户态栈，由引擎做唯一转发决策：

```
tun0 ◄──────► ROUTE ENGINE ◄──────► legs（mesh / dn42 / ts2021）
                  │
                  └──► WAN（LAN 外目标，NAT 兜底）
```

引擎只做决策，不做封装——决策输出是 `(leg, via)`，封装由对应接入完成。

## 2. 统一 LPM 表

```
路由条目 = (prefix, priority, leg, via)
```

- **最长前缀优先**（LPM 标准语义）
- 等长前缀冲突：按来源优先级消解（见 §3）
- **同一前缀多 via（mesh 多网关冗余）**：允许同一前缀多个 rill 节点公告（CONTROL_PLANE §3.8）；选路按节点 RTT/优先级，故障自动切换（与 §4 fallback 链衔接）
- 每条接入可撤销/更新自己的贡献，引擎负责一致性

**策略裁决点（ACL v2 预留，v1 恒放行）**：转发链固定为 `LPM 命中 → 策略检查 → 封装`——v1 策略 = allow-all（全端口可达语义，见 §3）；**实现时禁止把"查表即放行"写死成单一路径**，v2 在检查点接入 coordinator 下发的 ACL 策略（subject=node_id/网络、object=前缀/端口、action，随 netmap 原子下发，CONTROL_PLANE §3.2）；**v2 升级路径 = 路径级授权**——coordinator 在 PathResponse 签发时按组/网络过滤，路径集合即 ACL，relay 侧校验 key_path 即可执法（CONTROL_PLANE §3.11.6）。

## 3. 四接入路由来源

| 来源 | 贡献的路由 | via |
|---|---|---|
| mesh | netmap 条目 `routes[]`（前缀公告，coordinator 白名单校验，见 CONTROL_PLANE §3.8） | rill 节点（42B 帧） |
| dn42 | BGP 学到的前缀（**仅 rill ext 持有**，不扩散进 mesh）；**多 rill ext 出口**：rill ext 节点将 dn42 空间（172.20/14、fd00::/8）公告进 mesh（白名单，DN42_LEG §2），内部节点 LPM 精确命中 + 多网关冗余 | dn42 隧道（eBGP 选路结果） |
| ts2021 | 100.64/10 CGNAT、tailnet subnet routes、exit 默认路由 | tailnet peer（WG） |
| 本地 | LAN 子网、WAN 默认 | 物理接口 |

**tailnet 回程（定稿）**：rill ext 节点把 tailnet 地址池（如自建 tailnet 的 100.64/10 段）作为 `routes[]` **公告进 mesh**（白名单允许，CONTROL_PLANE §3.8）——rill 节点学到 `tailnet 空间 → rill ext 节点`，手机流量回程精确路由；公告主体是 rill ext 节点（仍是"仅 rill ext 持有"模型）。这是**手机↔mesh 双向可达的必要条件**（手机 → rill ext → mesh 帧 → 节点；节点回包 → rill ext → WG → 手机）。

**全端口可达语义（有意设计）**：公告前缀后，mesh 内对目标网段**全端口可达**（L3 透传的自然结果，如 telnet 1-65535 全通）——这是**有意语义**，与 mesh exit 透传哲学一致（L3 透传、不引入 L4 状态）；ACL/stateful 过滤为 **v2 候选**（管理面控制），v1 不实现。

**源身份约束（v2 设计前提）**：ACL 裁决依赖可靠源身份，而 route_mac **不认证源**（FRAME_HEADER §5：成员可伪造 from_node_id）——v1 唯一能认证源的机制是**点对点 AEAD 会话密钥**（目标节点解密载荷即认证源，握手层身份绑定兜底）。故 **ACL v2 默认在目标节点侧裁决**；中间转发节点无源认证能力，不做 ACL（若 v2 需中间裁决，须先引入逐跳源认证机制，另行设计）。注：v2 路径级授权（CONTROL_PLANE §3.11.6）下 relay 可校验"帧使用的路径是否合法"，但路径内成员仍可伪造 `from_node_id`——源认证仍由 AEAD 兜底，目标节点侧裁决原则不变。

**前缀与 coordinator/relay 端点重叠（闭环）**：节点公告的前缀若与 coordinator/relay 的公网端点地址重叠，无自指/环路风险——单 TUN + 控制面走独立 TLS 通道，公告前缀只进用户态 LPM 表，与物理发包路径（外层 UDP/IP 直接发往端点）解耦，互不干扰。

**封装后外层包直发物理接口（强制路径语义）**：封装完成的外层 UDP 包**直接经物理接口发出，不进入路由引擎**——防止外层目标（如中继公网 IP）落在公告前缀内时被 LPM 卷回 mesh 造成自指循环（教训见 lessons/routing/RT-01/RT-03）。

**tun0 信任边界（LAN 侧设备视为可信）**：tun0 是物理 LAN 的延伸，LAN 内设备可无认证直入 overlay——信任边界在物理/管理面（LAN 是可信网络）；mesh 成员侧逐身份认证 + 吊销；v2 候选：tun0 源白名单（管理面配置允许的源地址）。

**冲突消解（定稿，REQ-021）**：固定来源优先级 `LAN > mesh > dn42 > tailnet`——等长前缀时按此顺序取。依据：各接入地址空间天然不重叠（dn42 172.20/14、tailnet 100.64/10、mesh 自定义段），实际冲突 = 同源多 via（多 rill ext 出口公告同一前缀），已由 §2 多网关冗余机制处理；逐条配置 metric 挂 v2（需要管理语义）。

## 4. Fallback 链

首选接入不可达时按链降级（软路由 vs 固定分流的区别）：

```
例：dn42 空间
  首选：dn42 直连隧道（eBGP 路由）
  次选：经 mesh 边缘出口节点（仅透传）
  最后：丢弃

例：默认路由（互联网）
  首选：tailnet exit node（如配置）
  次选：WAN 直连（NAT 兜底）
```

- 触发条件：接入会话断开、BGP 会话断、netmap 移除、超时
- v1：静态配置的 fallback 链；动态多出口故障切换为 v2

## 5. Exit 语义

**前缀公告边界**：mesh 前缀公告**禁止过短前缀**（IPv4 < /8、IPv6 < /32，CONTROL_PLANE §3.8）——`/0` 之类默认出口必须走 exit 语义，不混入前缀公告：

| 类型 | 机制 | NAT |
|---|---|---|
| mesh exit | 经 42B 帧送到 mesh 出口节点，出口节点仅透传 | 不 NAT（WAN NAT 兜底） |
| ts2021 exit（使用） | 非本网流量封装发往 tailnet exit peer | 出口侧承担 |
| ts2021 exit（被用作） | 解包 → 引擎 → tun0 → WAN | WAN NAT |
| WAN 直连 | 目标非管理 LAN → 出 WAN | 网卡/上游 NAT |

## 6. MTU / 分片 / PMTU（v1 定稿）

### 6.1 链路 MTU 表

| 链路 | 封装开销（IPv4 估算） |
|---|---|
| tun0（LAN 侧） | 0（TUN 设备 MTU，配置决定） |
| mesh 接入 | 42B 帧头 + 16B tag + 8B UDP + 20B IP = **86B**（IPv6 +20B） |
| dn42 / ts2021 接入 | WireGuard 开销 ≈ 48B |

### 6.2 v1 策略（不做分片）

- **不做帧内分片**：42B 帧 `len` 2B 上限维持，分片字段不引入（FRAME_HEADER 决策记录闭环）
- **tun0 MTU = 保守静态**：`物理出口 MTU - 最大封装开销`——一条安全值，所有路径都通；动态 per-dst PMTU 缓存留 v2
- **MSS clamping**：tun0 侧改写 TCP SYN 的 MSS 到安全值——覆盖绝大多数流量，零协议改动
- **ICMP/ICMPv6 PTB 透传**：用户态栈转发 PTB 给 tun0 侧（v1 含 IPv6——IPv6 禁止中间分片，不做则 IPv6 全废）
- 实现要点：伪造 PTB 时**源地址 = 被封装包的目标地址**（ICMP 语义要求）
- UDP 大包无回退机制：PTB 通知源端，应用层自行处理（v1 接受）

## 7. DNS 分类语义（P4 实现，语义已定稿 REQ-021）

**形态：单点分域解析代理**——节点运行本地 DNS 代理（监听 53），按域名后缀/空间分发，未命中任何分域的走上游：

| 域名空间 | 分发目标 | 记录来源 |
|---|---|---|
| mesh 内域名（**后缀 `.mesh`**，私有语义，禁止真实可解析域名） | mesh DNS | 控制面下发的名称表（v1 简化为 coordinator 静态记录） |
| dn42 域名（`.dn42` 等） | dn42 DNS（172.20.0.53 等） | 随 BGP 学习（DN42_LEG §5） |
| tailnet 域名（MagicDNS 语义） | 自建控制面 DNS | headscale 下发的 DNS 配置（MapResponse） |
| 其余 | 上游 DNS（WAN） | 系统配置 |

- LAN 侧设备指向代理的机制（tun0 侧静态配置 vs DHCP 注入）——实现时定
- 语义边界：仅已知分域走对应 DNS；未知后缀一律上游，不泄漏私有域查询

## 8. 未决项

- mesh exit 与 ts2021 exit 的默认路由竞争优先级——v1 静态配置

（冲突消解已定稿：固定优先级 `LAN > mesh > dn42 > tailnet`，见 §3）

（tailnet 路由传播已定稿：rill ext 节点公告 tailnet 前缀进 mesh，见 §3 回程）

## 9. 实现级决定（2026-08-15，core/route 落档，47 单测）

- **LPM 实现 = 线性扫描**（v1 条目规模小，正确性优先；P4 XDP 快速路径时换 eBPF，用户态表语义不变）
- **lookup 排序语义**：`len 降序（最长前缀优先）→ source 优先级升序（LAN > mesh > dn42 > tailnet）`；同前缀同源多 via 全部返回（多网关冗余，按插入序）
- **fallback 链 = lookup_best(addr, reachable 谓词)**：按上述排序逐个询问可达性，第一个可达即选；全部不可达 → None（丢弃）——v1 可达性由调用方（接入会话状态）喂入，静态链语义
- **策略检查点**：`lookup → 调用方 policy 谓词过滤 → 封装`（v1 恒放行 = 全端口可达语义；ACL v2 在此接入，见 §2 策略裁决点）
- **Prefix 归一化**：parse 时按 len 掩码 host 位（存储即规范形态）；`0.0.0.0/0` 合法（WAN 默认路由），禁止过短前缀的校验属于公告流程（coordinator 白名单，CONTROL_PLANE §3.8）而非查表层
