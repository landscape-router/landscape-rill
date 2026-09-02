# Mesh 控制面协议设计（CONTROL_PLANE）

> 本文档定义 `landscape-rill` 中 **mesh 模式**（自建控制面）的控制面协议。
> 数据面帧头设计见 [FRAME_HEADER](./frame-header.md)；本文档是其 §9 接口需求的完整出处。
> 覆盖范围：中心化 coordinator 协议、状态模型、关键流程、安全模型、联邦模型（v2 特性 + v1 钩子）。
> 相关需求：REQ-004 / REQ-008 / REQ-010 / REQ-013 / REQ-014 / REQ-017 / REQ-018 / REQ-020 / REQ-022 / REQ-024 / REQ-025 / REQ-027 / REQ-030 / REQ-034 / REQ-035 / REQ-036 / REQ-037 / REQ-038 / REQ-047 / REQ-056 / REQ-057 / REQ-060

**版本：v0.10（2026-09-02 修订：REQ-056——§2 重连退避语义；REQ-057——§3.9 挑战携带 node_id 与注册响应丢失恢复 + §5.1 恢复流程；REQ-060——§2/§3.1/§3.9/§5.1 挑战统一触发：无持有证明不发身份）**

> 重建说明：v0.1 因工作区回滚丢失 §1.5/§3.8/重连认证/版本协商/能力位表/§5.7 等内容，v0.2 完整恢复并新增 §3.9。
> v0.3 修正：§2/§3.9 重连认证由"Ed25519 签名"改为 **X25519 静态密钥 DH 挑战**（原方案与 Noise 静态密钥 X25519 不兼容）。
> v0.4 新增：§3.11 路径服务与 `key_path` 路径授权（借鉴 SCION Path Service 思想，v1.5 控制面 / v2 数据面）；同步更新 §3.10（路径 = ACL 升级路径）、§4 状态模型、§5.4、§6、§8、§9。
> v0.5 新增：能力位表新增 `broadcast`（0x20）——L2 广播/组播泛洪 opt-in；keydist 按接收节点能力位**按需下发** broadcast_key，未 opt-in 节点不持广播密钥（FRAME_HEADER §2.6 对应语义 v0.9）。

## 1. 架构总览

### 1.1 权威模型：中心化

- coordinator 是以下状态的**唯一权威**：节点注册表（node_id ⇔ 公钥）、身份绑定签名、网络主密钥、吊销列表、netmap 权威版本
- 节点只与自己的 coordinator 通信，**只信任自家 coordinator 的签名**——这是整个信任模型的根
- 与去中心化 full mesh 的本质区别：存在唯一真相源。去中心化不在 v1 范围（§8）

### 1.2 高可用演进路径（P2）

- **v1**：单 coordinator（协议与后端存储解耦，见 §4.1）
- **P2**：openraft 集群（3~5 台、单数），Raft 选举主 coordinator
- 关键原则：**Raft 是 coordinator 内部实现细节，客户端协议零感知**——协议按 §4 的状态模型设计，天然 Raft 兼容（幂等 + 软硬状态分离 + 版本号 CAS）

### 1.3 coordinator 部署

- coordinator 作为 rill 节点的**角色**运行（节点携带 `coordinator` 能力位）；也可独立部署，协议不变
- 控制面流量走独立 TLS 通道（TCP），**不走 mesh 帧**（`type=控制` 在数据面仅为预留，见 FRAME_HEADER §2.1）
- 控制面中断不影响数据面：密钥均在节点本地（§4.3）

### 1.4 与三条接入的关系

- 本协议只管 mesh 接入
- dn42 路由**仅 rill ext 持有**，不进 netmap；内部节点将 dn42 空间指向最近 rill ext 出口
- tailscale 接入独立于本协议（自研 ts2021 客户端，见 TS2021_LEG.md）
- **与 ts2021 服务端（headscale 兼容）的关系**：浅结合——同进程、协议独立、可共享存储；rill ext 节点以 ts2021 客户端身份同时挂入自建 tailnet（双身份）；官方客户端（手机）经 ts2021 服务端接入，数据面走 WireGuard 与 rill ext 节点互联（ARCHITECTURE §6）

### 1.5 多网络隔离（协议无感租户）

一个 coordinator 进程服务多个**默认互不可见**的隔离网络（家庭网/公司网/测试网），**协议消息零改动**（headscale users 模式）：

- 隔离域 = 每网络独立的：`network_id`、**主密钥**（安全硬约束：`key_dst = KDF(网络主密钥, to_node_id)` 必须按网络独立，否则跨网可伪造 route_mac）、auth key 空间、netmap、身份绑定
- 共享：进程、存储、管理面
- **归域**：auth key 生成时绑定网络，注册即归域（§3.1）；节点注册到死只属于一个网络
- netmap 只推本网络条目；key_dst 只发本网络密钥
- 网络间互通 = **联邦**（v2，§7）——网络是联邦的最小单元；默认隔离，互通必须显式建立

## 2. 协议栈与连接

| 层 | 选择 |
|---|---|
| 传输 | TLS 1.3（rustls），TCP 长连接 |
| 消息 | protobuf（语义定义见 §3；schema 文件与代码生成 v1 实现时落地） |
| 端口 | coordinator 配置，默认值 v1 实现时定 |
| 连接 | 双向长连接；节点断线重连（指数退避）；会话为软状态（§4.1） |

连接建立顺序：`TLS → 协议版本协商 → Register → NetmapPush → KeyDist → 心跳维持（复用同一连接）`。

**版本协商（首消息协商）**：TLS 握手后首条消息携带协议版本 + 能力位，双方取交集；不兼容**明确报错**（而非静默失败）；与帧头 `version`（FRAME_HEADER §2.1）相互独立。

**重连认证（X25519 静态密钥 DH 挑战）**：auth key 一次性时首注后即失效，重连必须独立认证；REQ-060 起触发条件统一——**凡 REGISTER 且本连接未证明静态私钥持有，一律挑战（含首次注册）**：TLS 只认证服务端、auth key 只证成员资格，均不构成身份证明；身份发放（新铸或恢复）一律后置于持有证明。不用签名（Noise 静态密钥是 X25519 ECDH 密钥，无法签名），改用**静态密钥持有证明**（DH 挑战）：

```
coordinator 生成临时 X25519 密钥对 (eph_priv, eph_pub)
  → Challenge(eph_pub, nonce, issued_at)
节点：K = X25519(自身静态私钥, eph_pub)          ← 只有持私钥者能算出
  → HMAC 密钥 = HKDF-SHA256(K, salt=nonce, info="challenge")
  → tag = HMAC(HMAC 密钥, node_id || nonce || eph_pub)
  → ChallengeAck(node_id, tag)
coordinator：K' = X25519(eph_priv, 节点静态公钥)   ← 同一个 K
  → 同派生 → 验 tag
```

- **零新增密钥**：复用 Noise 静态密钥（X25519），注册绑定（node_id ⇔ static_pubkey）零改动
- **身份证明强度与签名等价**：只有持有节点静态私钥的实体能构造合法 tag
- 吊销自然生效：注册表移除 → 公钥不存在 → 无法验证；coordinator 临时私钥一次性 + nonce 时间窗口 → 防重放
- 静态私钥 = 节点身份根；丢失走 §5.7 恢复流程

**重连退避（REQ-056）**：断线重连统一指数退避 1s→300s（时间封顶为编译期常量，可配置/次数上限待需求出现——CP-05 三查：退避 ✓ / 上限 ✓ / 防抖 ✓（单飞串行重连，退避期间不发起））。退避覆盖两类失败——**连接失败与「连上后断开」**（read-Err），后者此前零退避立即重连，构成热循环放大器（连上即断 ~80ms 循环，烧穿 §3.13 限速）。**退避重置条件 = 注册成功**（Registered 事件）：bare TCP/TLS 建立不重置——半开连接 ≠ 恢复。退避等待分片调度（100ms 片轮转 pump_timers），失败摘要周期输出不静默（LOGGING §5）。

## 3. 消息定义（语义级）

### 3.1 RegisterRequest / RegisterResponse（注册）

**RegisterRequest**
- `auth_key`：预授权密钥（一次性/可复用，见 §6）——**生成时绑定网络**（§1.5），注册即归域；过期时间内嵌 key（REQ-043），注册时校验
- `static_pubkey`：Noise 静态公钥（32B）
- `capabilities`：能力位（见下表）
- 元数据（可选）：hostname、OS、版本

**能力位清单**：

| 位 | 语义 | 备注 |
|---|---|---|
| `relay` | 自愿承担中继（opt-in） | CONNECTIVITY §5；coordinator 汇总入 relay_list |
| `bridge` | 联邦桥节点（v2 预留） | §7.2 钩子 |
| `coordinator` | 运行 coordinator 角色（节点兼任） | 部署形态，非协议必需 |
| `exit` | 愿意充当 mesh 出口节点 | ROUTE_ENGINE §5 |
| `acl`（v2 预留） | 支持 ACL 策略裁决 | 位已划归，v1 恒 false；实现时不得占用该位 |
| `broadcast` | 接收 L2 广播/组播泛洪（opt-in） | FRAME_HEADER §2.6：keydist **仅向该位节点下发** broadcast_key（未 opt-in 节点不收广播帧、不参与泛洪）；泛洪只发该位端点 |
| 其余 | 预留 | 协议演进使用 |

**RegisterResponse**
- `node_id`：4B，coordinator 唯一分配
- `network_id`：本网络标识（联邦钩子，v1 恒为本地网络）
- `identity_binding`：coordinator 签名 `(node_id || static_pubkey)`——节点持久化，供数据面握手交叉验证（防中继 MITM）
- 非主 coordinator（Raft 期）：以 `LeaderRedirect`（§3.6）替代

**幂等**：相同 `auth_key + static_pubkey` 重复注册返回相同 `node_id` 与绑定。

**身份发放前置（REQ-060）**：新注册（NewNode）与幂等恢复（Existing）一律先经 §3.9 挑战取得持有证明，验证通过后才发放 node_id/绑定并执行准入副作用（白名单校验、node_id 分配、binding 签发、一次性 key 消费）——**无持有证明不发身份，无例外**。闭合成员间横向冒用：auth key（成员资格）+ 公开 pubkey + 配置猜测不再构成身份；公钥抢注（squatting）同被阻断。

### 3.2 NetmapPush（全网拓扑）

- `version`：u64，权威版本号（CAS 语义）；v1 全量推送，增量后置；**同时承载 ACL 策略版本**（v2：策略随 netmap 原子下发，一个版本号两用，幂等/重试机制零新增，§4.2）
- `entries[]`：
  - `node_id`（4B；联邦场景高 8 位 = 网络号，§7.3）
  - `network_id`（联邦钩子；v1 恒为本网络；用于过滤策略与环路预防）
  - `static_pubkey`（32B）
  - `endpoints[]`：UDP 端点（**上报机制**：节点经 coordinator UDP 回显探测，周期 30s + 网络变更触发，见 CONNECTIVITY §2；联邦边界：远端端点只下发到桥节点，不扩散）
  - `capabilities`（含 `relay` 自愿位：节点声明愿当中继，opt-in）
  - `routes[]`：**前缀公告**（节点背后 LAN/前缀，见 §3.8 前缀公告流程）——注册时携带初始公告 + 变更时更新；`routes` 汇总 = rill ext 节点 subnet router 广播进自建 tailnet 的数据源（TS2021_LEG §3.3）
  - 条目签名：本地条目由本 coordinator 签名；联邦条目经过滤后用本 coordinator 私钥**重签**（§7）
- `relay_list`：候选中继列表（DERP map 等价物）——coordinator 兜底 + 自愿节点（可达性验证 + RTT 测量后纳入），随 netmap 下发，见 CONNECTIVITY §5
- 下发时机：注册后全量、拓扑变更后全量、断线重连后补偿全量

### 3.3 KeyDist（转发密钥下发）

- 按 `to_node_id` 下发 `key_dst`（派生自网络主密钥；节点不可推导主密钥）
- 广播密钥（`KDF(主密钥, 0xFFFFFFFF)`）：**按需下发**——仅向能力位含 `broadcast`（0x20）的接收节点携带（§3.1 能力位表）；未 opt-in 节点不持广播密钥（FRAME_HEADER §2.6：无 key 即丢弃，fail-closed）
- 轮换语义：携带密钥版本；`新版本下发 → 宽限期（新旧并存）→ 旧版本过期`
- 下发方式：注册时按需 + 轮换时推送

### 3.4 Heartbeat / Lease（心跳与租约）

- 节点周期发送 Heartbeat（建议默认 10s，v1 实现时定）
- coordinator 维护**软状态** `last_seen`；超过租约阈值（建议默认 60s）判定离线
- 离线判定只影响 netmap 可达性标记，**不删除条目**（避免反复注册）

### 3.5 Revoke（吊销）

- coordinator 吊销节点：下发 Revoke + netmap 移除 + **触发全网 key 轮换**（§5.5）
- 节点本地维护吊销列表（node_id 集合），拒绝与吊销节点的握手/流量

### 3.6 LeaderRedirect（主重定向，Raft 期）

- 非主 coordinator 在注册/心跳响应中返回当前主地址
- 节点重定向重连；重连后按 §5.6 重建软状态

### 3.7 Peer\*（预留，联邦 v2）

- `PeerOpen / PeerExchange / PeerFilter` 等：coordinator 互联消息空间
- 本版**仅预留消息类型，不定义语义**（钩子，见 §7.2）

### 3.8 前缀公告流程（RouteAnnounce 语义）

节点公告自己背后 LAN/前缀，路由注入路由引擎（ROUTE_ENGINE §3）的机制：

- **机制**：`routes[]` 内嵌 netmap 条目——注册时携带初始公告，变更时经控制面更新；coordinator 校验后并入 netmap 全量推送，条目签名已覆盖
- **权限（coordinator 白名单，REQ-038 落地）**：管理面（§3.12）配置允许公告的前缀集合；注册时逐条校验 `routes[]`：**不在白名单 → 整体拒绝**（协议层返回 `RouteNotAllowed`，不部分采纳）；**白名单变更不影响已注册节点**（只拦新注册，v1 无公告变更消息，公告只在注册时携带）
- **前缀长度边界（v1 实现即校验，§3.8 既有语义落地）**：IPv4 `< /8`、IPv6 `< /32` 拒绝（注册层校验，不依赖管理面配置）
- **自身地址校验（防自指）**：公告前缀**禁止包含公告者自身地址**（tun0/物理接口地址）——否则发往自身的流量被封装进 mesh 形成循环（教训见 lessons/routing/RT-01）
- **重复公告**：允许同一前缀多节点公告（多网关冗余），选路由路由引擎处理（ROUTE_ENGINE §2）
- **边界**：禁止过短前缀（IPv4 < /8、IPv6 < /32），默认出口走 exit 语义（ROUTE_ENGINE §5）
- **生命周期**：节点离线 → 随 netmap 可达性标记自动撤销；显式撤销；注册时初始公告

### 3.9 Challenge / ChallengeAck（重连认证）

用于 §2 重连认证流程（auth key 一次性场景下，已注册节点的断线重连身份证明）。**X25519 静态密钥 DH 挑战**（不用 Ed25519 签名——Noise 静态密钥为 X25519 ECDH 密钥，无法签名）：

**Challenge**（coordinator → 节点）
- `eph_pub`：coordinator 一次性临时 X25519 公钥（32B）
- `nonce`：随机值（建议 16B）；`issued_at`：时间戳（服务端校验时间窗口，防重放）
- `node_id`（4B，REQ-057）：恢复类 = 服务端按注册表解析的目标身份（重连场景与客户端已知值一致；**注册响应丢失恢复场景**客户端尚不知道自己的 node_id，由本字段携带）；新建类 = `0`（身份在验证通过后才分配）——node_id 非机密（netmap 本就下发），tag 的安全锚是私钥持有证明
- 触发条件（REQ-060 统一）：凡 REGISTER 且本连接未证明持有 → 一律挑战，分两类完成语义：
  - **恢复类**（pubkey 注册表命中）：Challenge 绑定**存储 pubkey** 与解析 node_id；验证通过后做幂等比对（capabilities/routes 一致 → 按条目回 REGISTER_RESPONSE；不一致 → 拒绝），不走注册准入、不校验 key 有效性（PoP 强于共享 key 的成员资格证明；吊销以条目移除为准——验证时条目须仍在且 pubkey 一致）
  - **新建类**（pubkey 未命中）：key 只读校验（格式/过期/归域）通过即挑战，Challenge 绑定自报 pubkey、node_id=0；验证通过后执行完整注册准入（白名单、分配、binding 签发、一次性 key 消费——**消费后置于 PoP**；准入失败仍 fail-closed，只读校验失败计入失败锁定）

**ChallengeAck**（节点 → coordinator）
- `node_id`（4B）
- `tag`：HMAC 值（32B）——`HMAC密钥 = HKDF-SHA256(X25519(节点静态私钥, eph_pub), salt=nonce, info="challenge")`，对 `(node_id || nonce || eph_pub)` 计算（node_id 取 Challenge 消息携带值，非客户端自报）
- coordinator 用 `X25519(eph_priv, 节点静态公钥)` 得同一 K 派生验证；**身份按挑战状态绑定的 pubkey 解析（服务端存储为准），不信任自报 node_id**（CP-02：ID 权威在服务端）

**安全属性**：只有持节点静态私钥者能构造合法 tag（持有证明，强度等价签名）；nonce 一次性（时间窗口内使用，重放拒绝）；coordinator 临时密钥一次性（eph_priv 用完即弃）；吊销自然生效（注册表移除 → 验签失败）；幂等（验证无副作用，重试安全）。

**注册响应丢失恢复（REQ-057）**：one-time key 消费于准入时持久化（tombstone），响应丢失后客户端（Fresh 态，node_id 未知）重发同一 key 进入恢复（REQ-060 下按 pubkey 命中归类为恢复类）：

```
Register(key, pubkey) → 服务端按 pubkey 查注册表命中 → 恢复类挑战 Challenge(node_id)
    （挑战状态绑定存储 pubkey；不计失败锁定——合法恢复路径）
  → 客户端以消息 node_id 计算 tag + RegisterOk{node_id} 写入会话
  → ChallengeAck → 服务端按存储 pubkey 解析身份验证 tag
  → registered + 重推 netmap → 恢复完成（node_id 与首次注册一致，无新注册）
```

- 身份锚是静态密钥对而非内存状态——**进程重启后重发同一 key 同样恢复**
- tombstone 对第二身份语义不变：同 key 异 pubkey → unknown pubkey 拒绝（计入失败锁定）
- 形态对标：Tailscale（一次性 join token + machine key 持有证明恢复）／Stripe 幂等键（重试者认证后去重）——「key 失效」不是终点判定而是恢复入口的触发信号

### 3.10 Policy\*（预留，ACL v2）

消息族组空间已划归，v1 不定义消息体。v2 语义（对照 ROUTE_ENGINE §2 裁决点）：策略随 **NetmapPush 内嵌**（§3.2 version 承载）或独立 `PolicyPush/PolicyAck` 推送（届时二选一）；策略模型 = subject（node_id/网络）→ object（前缀/端口）→ action（allow/deny）；**只做目标节点侧裁决**（源身份约束，ROUTE_ENGINE §3）；租户内生效（§1.5），规则存储与管理面一致（管理面形态见 REQ-038）。

**升级路径（路径 = ACL）**：v2 引入路径级授权后，策略可在 PathResponse 签发时执行——coordinator"发不发某条路径给你"本身就是策略（§3.11.6）；目标节点侧裁决原则不变（ROUTE_ENGINE §3），relay 侧执法成为可能（校验 key_path 即校验参与资格）。

### 3.11 PathService\*（路径服务，v1.5 控制面引入 / v2 数据面生效）

> 借鉴 SCION Path Service 的设计思想（不引入完整 SCION 协议栈）：**netmap 描述"节点是谁"，PathMap 描述"节点之间怎么到"**。v1.5 数据面仍使用 `to_node_id` + `key_dst`（34B 帧头不变），路径信息只用于本地转发表、备用路径选择与多路径负载；v2 帧头携带 `path_id`，数据面按路径转发与授权（交叉引用见 FRAME_HEADER §9）。

**两类数据分离**

| 数据 | 内容 | 权威 |
|---|---|---|
| NodeMap（现有 netmap，§3.2） | node_id / network_id / static_pubkey / endpoints / capabilities / routes[] / 在线状态 | coordinator |
| PathMap（新增） | source_node_id / destination_node_id / candidate paths / path policy / path version / expires_at / path health | coordinator（v1.5 单机实现，不引入分布式信标） |

**消息族（语义级）**

| 消息 | 方向 | 语义 |
|---|---|---|
| PathRequest | 节点 → coordinator | 请求 source→destination 的候选路径（policy、constraints） |
| PathResponse | coordinator → 节点 | path_id / ordered_hops（或路径引用）/ path_version / expires_at / 路径授权 |
| PathUpdate | coordinator → 节点 | 路径变更（拓扑/健康变化，path_version++） |
| PathWithdraw | coordinator → 节点 | 路径撤销（吊销、过期、联邦取消） |
| PathProbe / PathProbeResponse | 节点 ↔ 节点 | 路径活性/健康探测（对齐数据面心跳与 relay 探测，CONNECTIVITY §6） |

**候选路径与快速切换**

- 每目标缓存 **2~4 条候选路径**；首选路径 + flow hash 负载均衡（v1.5）
- 失效判定：下一跳不可达 / 数据面心跳 miss（CONNECTIVITY §6）/ 路径过期 / PathProbe 失败 → **立即切换备用路径**，不等待控制面收敛
- 路径状态字段：`path_id / path_version / created_at / expires_at / health / revocation_epoch`

**路径生命周期**

- 有效性判定：`now < expires_at && current_epoch >= path_epoch && 未被撤销`
- 自动清理：失效 endpoint 关联路径、拓扑变化后的旧路径、联邦关系取消后的跨网路径、被吊销节点仍持有的旧路径授权
- 路径过期/撤销 → 节点本地路径表删除 + 相关 `key_path` 作废（§3.11.5）

**path_id 与 key_path（v2 数据面）**

- 帧头新增**固定 8B `path_id`**（v2，34B → 42B），**纳入 route_mac 与 AEAD AAD 输入**（防止成员偷换路径字段）
- 路径密钥：`key_path = KDF(网络主密钥, path_id, path_epoch)`；v2 的 route_mac 改用 `key_path` 计算（同 FRAME_HEADER §3.1 的 KDF 派生约定）
- **v1 兼容回退**：`path_id = 0` = 默认路径 = 现有 `key_dst` 语义——v1 帧头不变（隐式 path_id=0），v2 加字段后查表多一个默认分支即可平滑过渡
- coordinator 按路径签发 `key_path`，**只发给路径参与者**（源、途经 relay、目的节点）
- **路径级授权语义**：路径外成员无 `key_path` → 算不出合法 route_mac → 无法向该路径注入/改道流量（对现状的实质加强：现 `key_dst` 全网共享，任何成员可伪造发往任意目的地的帧头）
- **边界**：`key_path` 是路径级授权**不是源认证**——路径内成员仍可伪造 `from_node_id`（信任域从"全网"收窄到"路径参与者"），源认证仍由 AEAD + 握手层身份绑定兜底（FRAME_HEADER §3.1/§2.3）
- **撤销粒度**：吊销一条路径 = 撤销该 `key_path` + `path_version++`，波及范围从"全网"缩到"该路径"
- **不做逐跳 hop key**：单 route_mac 字段约束（一字段一密钥域——验证方必须拿生成时那一把密钥重算），逐跳隔离留联邦 v2 / 帧头多 MAC 演进

**路径 = 路径级 ACL（与 §3.10 衔接）**

- 控制面"发不发某条路径给你"本身即策略：coordinator 在 PathResponse 签发时按组/网络过滤 → **路径集合 = ACL**（单网络多租户组隔离的加密强版本——相比基于明文源/目的 ID 的中继侧组对检查，路径授权加密绑定参与资格，成员无法伪造源字段绕过）
- v1 恒放行的策略检查点（ROUTE_ENGINE §2）在 v2 变为"帧使用的路径是否合法"——relay 侧可执法（校验 key_path），因为路径授权绑定了参与资格
- 组级隔离开放时（v2）：probe/打洞信令与 PathProbe 同样按 (source_groups, destination_groups) 门控（v1 probe 无认证为有意设计，CONNECTIVITY §4.3）

**联邦衔接（v2+）**

- 路径段摘要：跨网只交换边界路径段（远端端点仍只下发桥节点，§7.1 不变）
- 桥节点跨界用**目标网络的 key_path** 重签 route_mac（FRAME_HEADER §3.1 例外扩展：按路径段重签，一次跨界一次重签）

**v1 钩子（零成本）**

- 数据面 v1 **零改动**：path_id 仅控制面语义，34B 帧头不变
- 控制面：Path\* 消息在现有 Envelope 消息族新增 MsgType（§8 待定落地）
- 能力位：不新增；PathService 属 coordinator 侧实现

### 3.12 管理面（v1，REQ-038）

> 管理面 = coordinator 侧的配置权威面（前缀公告白名单 §3.8、auth key 生命周期 §6、策略模型 §3.10 的 v2 载体）。v1 形态定稿：**配置文件为唯一权威 + 库 API 执行面分离**（REQ-038）。

**形态：配置与执行分离**

- **持久权威 = coordinator 本地配置文件**（JSON）；Web API / 管理子命令 v1 不做（无 WebUI 即无配置归属问题，REQ-040 边界自然满足；教训 AO-02 关键配置只存服务端 = 配置文件本身就是服务端）
- **配置层与执行层分离**：`CoordConfig`（解析 + 校验）是独立模块，不依赖运行时；`CoordinatorServer::from_config / apply_config` 为**库 API（函数调用生效）**——其他项目可引入 rill-coord crate 直接以函数调用应用配置（如未来自研 ts2021 服务端、landscape-webserver 管理面），CLI/未来管理面只是薄调用层
- 结构：`CoordConfig { network, listen_addr, tls, master_key, signing_seed, auth_keys[], announce_whitelist[] }`

**演进路径（分层决策，2026-08-31）**：v1 = 配置文件（唯一权威）+ 库 API + SIGHUP 重载；配置来源（文件/HTTP/DB）与执行层（apply_config）解耦，HTTP 管理 API + Web 前端 + 存储后端（REQ-037 redb/sqlite）同批落地时，**文件降级为启动引导（bootstrap）**，WebUI 不持有持久配置（REQ-040 边界，教训 AO-02）；无默认管理员凭据 + 授权模型（AO-03）在 HTTP 形态引入时定稿

**fail-closed + 加载即校验**

- 缺失必填字段（master_key/signing_seed/tls）→ 拒绝启动（**无默认凭据**：配置不存在或不全即 fail-closed）
- 校验项：auth key 格式（§6 规范，含网络归域）、白名单前缀合法（parse + 长度边界 §3.8）、TLS 文件可读
- 任何一项不合法 → 拒绝启动，不降级运行

**变更生效 = SIGHUP 重载（不重启）**

- systemd 形态 `ExecReload=kill -HUP $MAINPID`；进程收到 SIGHUP → 重新解析配置文件 → `apply_config` **增量应用**（auth key 增删、白名单更新），**不中断在途 TLS 连接与已注册节点**
- 重载失败（新配置非法）→ **保持旧配置继续运行** + 日志报错（fail-closed 于启动，容错于重载）

**auth key 生命周期管理（§6 落地，REQ-036 + REQ-043）**

- 生成：`lrill authkey --network <slug> [--ttl <dur>]` 子命令（§1.3 lrill CLI），输出仅 stdout、不落日志（教训 AO-01/AO-02）；**默认有效期 24h**（auth key 仅入场令牌，短命是特性），`--ttl 0` 永不过期
- 增删/吊销：配置文件编辑 + SIGHUP 重载；`apply_config` 增量生效（新 key 可注册、移除的 key 即刻失效）
- **过期（REQ-043）**：过期时间**内嵌在 key 自身**（`lrk-<network>-<expiry>-<secret>`，§6），注册时（admission）校验，过期即 `InvalidAuthKey`；`AuthKeyConfig.expires_at` 字段已移除（key 自过期 = 单一权威）；已过期 key 可在配置中保留（inert，不阻断启动——硬拒绝会卡死已注册节点的挑战恢复）

**lrill CLI（REQ-042）**

- 二进制 `lrill`，子命令：`pubkey <seed>`（Ed25519 公钥工具）/ `run [config]`（前台 daemon，容器/开发形态）/ `authkey`（生成 auth key，§6）/ `up|down|status`（systemd 托管）
- **daemon 托管 = systemd 优先**：`up` 生成并安装 unit 模板 + `systemctl start`；`down`/`status` 走 systemctl；无 systemd 环境 `up/down/status` 明确报错并提示 `lrill run`
- 明确否决：v1 不做自守护 + unix socket（SSH session SIGHUP 坑、多线程 fork 时序、容器 PID1 冲突）；等真实需求出现再开 REQ

**启动参数优先级（通用约定，2026-09-01）**

进程级可配置项统一按 **CLI 显式 > 环境变量 > 默认值** 解析（新增此类配置必须遵循）：

| 配置项 | CLI | 环境变量 | 默认 |
|---|---|---|---|
| 配置文件路径 | `lrill run [config]` | `LRILL_CONFIG` | `/etc/landscape/overlay.json` |
| 日志级别 | `lrill run --log-level` | `RUST_LOG` | `info`（LOGGING §2） |
| 日志文件 | `lrill run --log-file` | `LRILL_LOG_FILE` | 仅 stderr（LOGGING §4） |

配置文件内容（coord 配置字段）不在此链内——配置文件本身是唯一权威（本节）；此约定只管"进程启动时选哪份配置 / 开关怎么设"。

### 3.13 消息限速与准入配额（REQ-047）

控制面消息级限速/配额（数据面广播有令牌桶，控制面此前空白）——三个风险面：auth key 爆破（SEC-20）、注册风暴（可复用 key + 不同公钥 → node_id 分配 + 快照整写放大）、TLS 长连接消息洪泛（SEC-19 只有 1MB 帧上限无速率维度）。

| 机制 | 参数（默认） | 行为 |
|---|---|---|
| **连接级消息速率** | 20/s、突发 40 | per-TLS 连接令牌桶，桶空 → **断连该连接**（复用 SEC-19 单连接隔离，其他连接不受影响、进程不 panic） |
| **Register 准入限速** | per-源 IP 0.5/s、突发 5 | 注册是重操作（node_id 分配 + redb 快照整写），超限拒绝断连 |
| **auth key 失败锁定** | 连续失败 ≥5 → 锁 30s×2ⁿ（封顶 1h） | 递增锁定，成功注册清零；**已知 pubkey 的挑战路径不计失败**（合法重连）；锁定含挑战一律拒绝（严格优先，NAT 共源受害者靠锁过期 + 重连退避恢复） |
| **心跳超频忽略** | 最小间隔 5s（= 心跳间隔/2） | 更近的心跳直接忽略（零成本：不更新 last_seen、不推快照、不回 LEASE），租约/离线判定语义不变（§5.2） |
| **PathRequest pending 上限** | 节点 256 / coordinator per-source 1024 | 饱和丢弃（幂等刷新重建，最终一致）；防大规模 netmap 下的内存放大 |

- **错误响应统一措辞（SEC-20）**：不可解析 / 过期 / 未知网络 / 已消费的 auth key 一律 `InvalidAuthKey`（§3.1，无信息泄露）
- 限速参数为常量（config 风格）；`CoordinatorServer` 暴露字段供测试放大（localhost 共源场景）
- 复用 rill-core `TokenBucket`/`SourceRateLimiter`（与数据面泛洪/probe 限速同源，REQ-046）

## 4. 状态模型（Raft 兼容核心）

### 4.1 三分类

| 类别 | 状态 | 存放 | 主切换后的行为 |
|---|---|---|---|
| **持久** | 节点注册表、身份绑定、网络主密钥、吊销列表、netmap 权威版本、**路径表 PathMap（v1.5，§3.11）** | Raft 日志（v1 单机：redb 快照整写，REQ-037） | 直接可用，零重建 |
| **软状态** | 心跳 `last_seen`、活跃 TLS 会话、**路径健康状态（v1.5）** | 主 coordinator 内存 | 丢失；节点心跳/重连/PathProbe 自动重建 |
| **派生** | `key_dst`、广播密钥、**`key_path`（v2，按 path_id 派生）** | 计算（确定性 KDF） | 新主无需任何写入即可重新下发 |

**v1 单机持久化实现落档（2026-08-31，REQ-037）**：

- **后端 = redb（Rust 原生、单文件、无 C 依赖）**；持久状态整快照原子写（单键，redb 事务）。数据形态全为主键点查，无关系查询需求——sqlite 的关系能力零收益（否决 sqlite）
- **持久范围**：节点注册表（含身份绑定）、**一次性 auth key 消费 tombstone**、`next_node_id`/`netmap_version`/`key_version`、端点表、PathMap + `path_id` 分配器。一次性 key 消费落盘 = 重启/重载（SIGHUP）不复活（消费过的 key 在 `add_auth_key_spec` 恒被拒）
- **auth key 与公告白名单不落盘**（配置为唯一权威，§3.12，重启后由 apply_config 重新注入）
- **写入路径**：全部经 Coordinator 方法写穿透（register / set_endpoints / request_paths / revoke / rotate_master_key，单一写入路径，§4.2 幂等）；写入失败不中断数据面（§4.3），eprintln 留 durability 缺口
- **损坏处理（fail-closed）**：文件损坏 / schema 不兼容 / 语义不一致（next_node_id 冲突、重复 node_id/公钥）→ 拒绝启动，不猜测重建
- **存储文件权限 0600**（含身份绑定与 key 消费状态，教训 KC-02）
- **配置**：`CoordConfig.storage_path`（None = 纯内存）；仅启动时读取，SIGHUP 重载不更换存储文件

### 4.2 幂等性要求（客户端操作全部可重试）

- 重复 Register → 相同结果（同 auth_key + 同公钥）
- 重复 KeyDist 请求 → 相同密钥
- Heartbeat 无状态（仅更新 `last_seen`）
- 持久状态只经单一写入路径（Raft 单点），主切换期间重试不污染状态

### 4.3 控制面中断不影响数据面

- 会话密钥、`key_dst`、身份绑定均在节点本地持久化
- 控制面中断期间：既有节点间流量正常；仅注册/拓扑变更/密钥轮换暂停

## 5. 关键流程状态机

### 5.1 节点加入

```
auth_key 预生成
  → TLS 连接 coordinator
  → Register(auth_key, static_pubkey, capabilities)
  → Challenge/ChallengeAck（持有证明，REQ-060——含首次注册）
  → 校验 auth_key → 分配 node_id → 签发身份绑定
  → NetmapPush(全量, 含自身条目)
  → KeyDist(自身 key_dst；广播密钥 opt-in 时随带)
  → 心跳开始（在线）
```

加入完成后数据面即可与全网互通（身份绑定供数据面握手验证）。

注册响应丢失（key 已消费、ack 未达）时：客户端退避后重发同一 key 进入挑战分支（§3.9 恢复流程），按持有证明取回原 node_id——无需人工换 key（REQ-057）。

### 5.2 心跳与离线

```
周期 Heartbeat → coordinator 更新 last_seen（软状态）
last_seen 超租约 → 标记离线（netmap 可达性变化，条目保留）
节点复活 → 下一次心跳恢复在线标记
```

超频心跳（< §3.13 最小间隔）直接忽略——不更新 last_seen、不推快照、不回 LEASE（零成本），租约/离线判定语义不变。

### 5.3 netmap 同步（含重连）

- 变更（加入/退出/端点迁移/能力变化）→ 全量推送 + `version++`
- **断线重连**：`静态密钥 DH 挑战认证（§2/§3.9）→ 以本地 version 请求补偿`（v1 简化：直接全量）
- 会话状态（last_seen）在重连后重建（软状态）

### 5.4 密钥轮换

```
coordinator 发起（吊销/安全事件/定期）
  → KeyDist(新版本 key_dst)
  → 宽限期（新旧密钥并存）
  → 节点切换新密钥
  → 旧版本过期作废
```

**数据面会话密钥联动**（FRAME_HEADER §6）：控制面事件（吊销/全网 key 轮换/节点静态密钥轮换）触发相关节点对 **Noise rekey**（静默，双密钥窗口 5s）；日常轮换由节点本地定时（24h）触发，不依赖控制面。

**路径级细粒度轮换（v2）**：吊销/轮换单条路径只撤销对应 `key_path` + `path_version++`，不必全网轮换（§3.11.5）；`key_path` 随路径版本派生，旧版本过期自然作废。

### 5.5 吊销

```
coordinator Revoke(node_id)
  → netmap 移除该条目
  → 全网 key 轮换（§5.4）
节点侧：吊销列表更新；相关握手/流量拒绝
```

### 5.6 主 coordinator 切换（Raft 期）

```
选主完成
  → 节点收到 LeaderRedirect（或重试连接至新主）
  → 幂等重注册（返回相同 node_id / 身份绑定）
  → 软状态重建（心跳重置；租约期内视为在线宽限）
  → KeyDist 按需补发
```

### 5.7 节点密钥丢失恢复

```
检测到本地静态密钥对丢失/损坏（或换机）
  → 管理员吊销旧 node_id（Revoke，防旧身份继续被信任）
  → 新 auth key 重新注册（新 node_id + 新身份绑定）
  → netmap 移除旧条目
  → 全网 key 轮换一次（§5.4，清理旧密钥关联）
```

- 不保留 node_id 重绑（避免"允许旧 ID 换新公钥"的管理面特批操作，复杂度不划算）
- 数据面影响：旧会话全部作废，重新握手

## 6. 安全与信任模型

- **auth key 生命周期**：一次性（单次注册即失效）/ 可复用（带 tag）；吊销联动（Revoke 使相关 auth key 失效）
- **auth key 格式（REQ-036 定稿，REQ-043 修订）**：`lrk-<network>-<expiry>-<secret>`——`lrk` 固定前缀（类型标识 + 配置校验拒绝非 `lrk` 开头的键）；`<network>` 为配置声明的网络标识（小写字母数字，**不含连字符**——段分隔符冲突，归域绑定 §1.5）；`<expiry>` = 十进制 unix 秒（**0 = 永不过期**），**解析即知过期**；`<secret>` = 32B CSPRNG → base32（RFC 4648 无填充，52 字符）。格式非法 → 配置加载即拒绝启动；network 段与配置不匹配 → 注册拒绝；**过期在注册时（admission）校验**（嵌入时间仅 advisory，防篡改 key 改长有效期——coordinator 是最终裁决），节点侧启动对过期 key 仅告警不阻断（已注册节点仍可经挑战恢复）。**生成不依赖 master_key**（auth key 是注册凭据非 KDF 派生），`lrill authkey --network <slug> --ttl <dur>` 纯本地生成（默认 24h，`0` = 永不过期），输出仅 stdout（不落日志，教训 AO-01/AO-02）
- **身份绑定签名**：防成员冒充/中继 MITM 的关键——数据面握手双保险：msg1 携带目标 node_id + 接收方校验（FRAME_HEADER §2.3），握手后双方交叉验证 coordinator 签发的绑定
- **边界划分**：控制面管"谁有资格"（身份/密钥），数据面管"包是否合法"（route_mac / AEAD 双层认证）
- **传输安全**：TLS 1.3；coordinator 间 mTLS（P2 Raft 期）
- **TLS 信任锚**：**公网证书为主**（标准 PKI，coordinator 需公网可解析域名 + 有效证书，与 headscale 过渡部署的反代 + Let's Encrypt 形态一致）；内网部署可选**自签 CA 预置**（节点配置预置 coordinator CA 证书，rustls 原生支持）——伪 coordinator 钓鱼 auth key 的防护基础，实现时必配
- **算法 fail-closed**：ChaCha20-Poly1305 / HKDF-SHA256 不可用即**拒绝启动组网，无降级路径**（防降级攻击）；KDF 统一 **HKDF-SHA256**（Noise 规范内建，主密钥/会话/派生共用）
- **信任根**：coordinator 私钥 = 网络信任根；泄露即全网 key 轮换 + 身份绑定重签；**每网络主密钥独立**（§1.5），一个网络的泄露不影响其他网络
- **路径授权密钥**：`key_path` 按路径签发（§3.11.5），信任域从"全网共享 key_dst"收窄为"路径参与者"；泄露影响限于该路径的转发完整性（帧头伪造，AEAD 兜底），可单路径吊销隔离

## 7. 联邦模型（v2 特性，v1 钩子）

### 7.1 模型概述

coordinator 对等互联（双边信任 + 过滤），借鉴 dn42 AS 对等与 XMPP/Matrix 联邦：

- A/B coordinator 建立对等会话（显式信任声明，如互相持有对方 coordinator 公钥）
- B 的 netmap 条目经 A **过滤**后用 **A 的私钥重签**，进入 A 的 netmap——A 的节点只信任自家签名，**客户端协议零感知**
- 数据面：跨网帧经**桥节点**转发；桥节点在边界用目标网络 `key_dst` **重签 route_mac**（FRAME_HEADER §3.1 例外）；端到端 Noise 握手与 AEAD 不受影响（AAD 排除 route_mac）
- 端点信息：远端端点只下发到桥节点，不向普通节点扩散（信息暴露可控）
- 吊销跨网传播：条目撤销 + 相关 `key_dst` 作废，防止被踢节点借联邦通道存活
- 环路预防：条目带 `origin`（network_id），过滤防回流
- 广播跨网：桥节点策略决定（默认不透传）

### 7.2 v1 钩子清单（成本极低，不污染单网路径）

1. netmap 条目带 `network_id` 字段
2. `capabilities` 预留 `bridge` 角色位
3. `Peer*` 消息空间预留（§3.7）

### 7.3 ID 空间

- 4B `node_id` 高 8 位 = 网络号（256 网 × 16M 节点/网）
- 各 coordinator 强制本段内分配；联邦时验证对端条目落在其声明段内（**网段错开只是命名前提**，完整联邦 = 本节全部 + §3.2/§3.3 的配合，见 7.1）

## 8. 非目标与待定

### 非目标（明确不做）

- 去中心化一致性（无中心方案）——远期方向，coordinator 接口预留
- 1000+ 节点规模（需要分区/订阅路由，超出 v1 设计）
- dn42 路由全网同步（仅边缘持有）
- 控制面走数据面帧通道（独立 TLS）
- 增量 netmap（v1 全量 + 版本号，增量后置）
- 帧内分片（34B 帧不分片；MTU 语义由 MSS clamping + ICMP PTB 承担，ROUTE_ENGINE §6）

### 待定（v1 实现时定）

- 心跳间隔 / 租约阈值（建议 10s / 60s）
- 控制面端口号
- **管理面安全要求**（已定）：**无默认管理员凭据**（首次启动强制设置，fail-closed）；配置项**加载即校验**（非法配置拒绝启动）
- protobuf schema 文件与代码生成
- **v1 存储后端已定（2026-08-31，REQ-037，§4.1）：redb 快照整写，storage_path 启动读取**
- **Path\* 消息族落地（v1.5，§3.11）**：Envelope MsgType 扩展 + PathMap 存储形态（与 netmap 同存储后端）；v1 数据面零改动

### 实现级决定（2026-08-15，core/control 落档，对照 §2/§3.9/§5）

- **挑战 tag 实现**（§3.9）：`tag = HMAC-SHA256(derive_challenge_key(X25519(私钥, eph_pub), nonce), node_id(4B BE) || nonce || eph_pub)`；**验证方用自己持有的 eph_priv 推导 eph_pub**（不回信声称值，防字段欺骗）；时间窗口 `now <= issued_at + window`（issued_at 为 coordinator 本地值，非回显）
- **身份绑定 = IdentitySigner trait 注入**：注册表不依赖具体签名算法；`binding = sign(node_id(4B BE) || static_pubkey(32B))`；真实实现（Ed25519）在 coord/ 侧落地时接入，节点侧验证逻辑不变（§3.1 交叉验证语义）
- **coord/ 落档（2026-08-15）**：①**Ed25519Signer**（ed25519-dalek 2.2，verify_strict 防弱密钥篡改，确定性签名，无随机源）；②**KeyDist 派生**：`key = derive_key_dst(master_key, node_id)`、`broadcast_key = derive_key_dst(master_key, 0xFFFFFFFF)`（FRAME_HEADER §3.1 语义落地）；③**全网 key 轮换（§5.4）实现 = 主密钥更换 + key_version++**（key_dst 为确定性 KDF，不换主密钥则无新密钥；节点侧宽限期语义待传输层）；④**吊销（§5.5）**：条目移除 + netmap_version++ + key_version++；⑤**netmap 版本管理**：注册/端点变更/relay 列表变更/离线标记均 `version++`，幂等重注册不 bump；⑥**offline 为显式软状态**（I/O 层租约超时喂 `mark_offline`，心跳复活清除），条目保留（§3.4）
- **传输包络（2026-08-15，legs/mesh 落档）**：TLS 之上 = **4B 大端长度 + Envelope 消息**（`rill-proto/proto/control.proto`：`MsgType` 枚举 10 值 + `Envelope{ msg_type, body }`）；帧长上限 1MB（fail-closed）；控制面连接 = 双向长连接复用（注册/心跳/推送同一连接，§2 连接建立顺序）；消息封包 API（envelope_bytes/write_msg/read_envelope）+ TLS 双向流辅助（客户端预置 CA 路径 = 内网自签 CA 落地；公网 PKI 证书链验证 v1 预留 webpki-roots）；**回环集成测试验证注册全流程**（TLS 双向认证 + Register → RegisterResponse(身份绑定) → NetmapPush(含自身条目)）
- **注册表/吊销/会话状态机**（§4/§5）：Registry（auth key 生命周期：一次性注册后即弃、可复用保留；同 auth_key+同公钥 → 相同 node_id，幂等 §4.2；同公钥不同能力 → 拒绝）、RevokeList（节点本地，握手/流量拒绝依据）、ClientSession（Unregistered → Registered → Reconnecting 状态机；自吊销 → 回 Unregistered；他吊销 → 仅记录；Reconnecting 可经挑战或同 id 幂等重注册恢复）
- **路径服务实现落档（2026-08-31，REQ-034，§3.11）**：①**Path\* 消息族**（proto MsgType 11~16）：PathRequest{ destination_node_id, max_candidates } / PathResponse{ destination, candidates[], path_version } / PathUpdate / PathWithdraw / PathProbe{ path_id, nonce, issued_at } / PathProbeResponse；CandidatePath{ path_id, path_epoch, hops[], expires_at, key_path }；②**PathMap**（rill-coord path_service.rs）：(source,dest) → PathSet{ version, candidates }；**候选 = 直连（hops=[dest]）+ 每条 relay 一条中继路径（hops=[relay, dest]）**，上限 max_candidates clamp(2,4)；relay 集合 = 能力位含 relay（0x01）的节点（netmap 变更同步）；③**幂等**：request() 已有未过期路径集直接返回（不重新分配 path_id——避免参与者间路径分叉）；过期按 PATH_DEFAULT_TTL(3600s) 全过期判定重建；④**key_path 参与者全量下发**：`key_path = KDF(主密钥, path_id, path_epoch)` 随 PathResponse/PathUpdate 推给**全部参与者**（source=选择方、dest=接收校验方、relay=转发校验方）——非参与者无 key_path 无法校验/转发（fail-closed）；⑤**推送机制**：v1 无主动推送通道 → 路径事件挂 pending（按 source 归类），随该节点心跳（HEARTBEAT 处理）取走推送（PathUpdate 全量替换/PathWithdraw 单条撤销）；**PathRequest 不回即时响应**（即时写回在并发下不可靠），路径集以心跳推送通道为权威下发路径，请求方幂等刷新直至收敛；⑥**吊销联动**：revoke(node_id) → 撤销所有涉及路径（源/目的 = 整组 Withdraw；仅中继 = 撤该候选保留其余 Update）；⑦**节点侧**（data.rs PathEntry）：路径表（每目标 2~4 候选）+ key_path_table；flow hash（五元组 FNV-1a）选路径；**路径归属**：PathUpdate/PathResponse 带 `source_node_id`，发送路径表只写自己发起的路径（source=自己），作为 dest/relay 参与者仅注入 key_path（防其他源的路径覆盖污染发送选择表）；⑧**v2 数据面**：42B 帧头（FRAME_HEADER §2.7），path_id 纳入 route_mac 与 AAD；`path_id=0` 回退 key_dst；互操作按 netmap `protocol_version`（注册上报）——v2 对 v1 对端恒发 34B v1 帧；⑨**PathProbe 运行时未启用**（协议已定义，活性由数据面心跳承担，v2 挂起）
- **路径健康落档（2026-08-31，REQ-034，§3.11 快速切换实现）**：①**逐路径入站健康**：收帧按"帧实际到达的上一跳"（UDP 发送者归属节点，直连 = 源节点自身、经中继 = relay 节点）更新路径活性——首跳 == 入站跳的路径 ok（miss 清零）、其余 miss+1；直连帧全路径 ok，经中继的帧证明中继路径存活、直连路径持续 miss（不再"收包全恢复"——中继帧续命直连路径会卡死不对称拓扑切换）；②**端点级活性**：多端点节点（多宿主通告全部）按 `(端点归属, 端点)` 维护 miss，发送排序活性差者置后、同活性轮换上次未用者（UDP 黑洞端点：sendto 成功但包被网关丢弃，无法从收包侧感知，靠无响应信号逐个排除）；③**握手重试驱动 miss**：`HANDSHAKE_RETRY_INTERVAL=2s`——上次握手尝试超时无响应 → 主路径 miss + 端点 miss + 丢弃在途发起状态，下一次调用重新发起 msg1（懒握手在黑洞下永不收敛，重试驱动快速切换收敛）；发起方与响应方均受益：响应方经中继收到重复 msg1 → 入站健康使直连持续 miss → 响应改走中继路径；④**中继日志**：转发节点记录 `relayed frame to <dest>`（e2e 中继证据）
- **多网络隔离落档（2026-09-01，REQ-010，§1.5 实现）**：①**CoordConfig 形态**：`networks: [{ name, master_key, auth_keys, announce_whitelist }]` 列表（breaking，仓库未发布）；扁平 `network/master_key/auth_keys/announce_whitelist` 移除；storage_path/signing_seed/TLS 共享；②**network_id = FNV-1a(name)**（确定性散列，0 保留）：跨重启/重载稳定（配置顺序变化不漂移），碰撞在配置加载时 fail-closed 拒绝；③**NetworkDomain**（rill-coord/src/domain.rs）：每网络独立 Registry（auth key 空间/白名单/条目）+ KeyManager（主密钥独立 → `key_dst = KDF(网络主密钥, node_id)`，跨网伪造 route_mac 必失配）+ PathService（relay 集合/PathMap 按网络独立）+ relay_list；**node_id 全局唯一分配**（跨网络不冲突，Directory/Liveness 按 node_id 键控）；④**归域**：auth key 内嵌网络（REQ-043），admission 按 key 网络选域，未知网络 → InvalidAuthKey（fail-closed）；配置层 key 放错网络段 → 拒绝启动；⑤**netmap 隔离**：`netmap_snapshot(network_id)` 过滤 + server 按注册节点网络推送（netmap/relay 列表/key_dst 全量只含本网）；⑥**路径同网门控**：跨网络 PathRequest → 空集（netmap 隔离下源本就看不到异网节点）；⑦**持久化 schema v2**：nodes 按 network_id 归域恢复、consumed tombstone 按 key 内嵌网络分组、key_versions/path_maps/relay_lists 按网络分组；⑧**覆盖层调整（SEC-24）**：跨网绑定注入 e2e 需完整恶意客户端（Noise 握手）且 netmap 隔离已结构性阻断攻击面 → 直接验证生产验签路径 `verify_binding`（集成）+ 跨网握手 prologue 拒绝（线级）
- **消息限速与准入落档（2026-09-01，REQ-047，§3.13）**：①**连接级限速**（rill-mesh server.rs `ConnectionState.msg_bucket` 20/s 突发 40，桶空断连——handle_message 入口收口，handle_connection 与 rilld 连接循环共用）；②**Register 准入**（`CoordinatorServer.register_limiter` per-源 IP 0.5/s 突发 5 + `register_lockout` 失败锁定 5 次 → 30s×2ⁿ 封顶 1h；源 IP 取 TLS peer addr；成功清零、挑战路径不计失败但锁定期间一律拒绝）；③**心跳超频忽略**（`ConnectionState.last_heartbeat` + `heartbeat_min_interval` 默认 5s——server 字段可配，主机测试 300ms 心跳泵需调小）；④**PathRequest pending 上限**（节点 `pending_path_requests` 256 / rill-coord path_service per-source 1024 饱和丢弃）；⑤**观测**（`rate_limited` RateCounter，run_coord 周期摘要 `control rate-limited`——SEC-20 e2e 证据）；错误措辞统一 InvalidAuthKey 原已闭环（coordinator register admission 全映射）

## 9. 与数据面文档的对照（闭合验证）

| FRAME_HEADER §9 需求 | 本设计出处 |
|---|---|
| 1. 节点注册与 node_id 分配 | §3.1 / §5.1 / §7.3 |
| 2. 身份绑定（签名防 MITM） | §3.1 / §6 |
| 3. 转发密钥分发与轮换 | §3.3 / §5.4 |
| 4. 全网拓扑同步（netmap） | §3.2 / §5.3 |
| 5. 心跳与超时语义 | §3.4 / §5.2 |
| 6. 路径服务与路径授权（v1.5/v2） | §3.11（PathMap/候选路径/生命周期/key_path；帧头 path_id 见 FRAME_HEADER §9 补充） |
