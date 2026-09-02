# 教训对照（lessons）

> 抽象自外部协议实现公开缺陷（安全/可靠性）的教训库，逐一对照 landscape-rill 设计的规避状态。
> 目的：防回归——实现/演进时对照复核。
> 版本：v0.7
> 最近修改：2026-09-02

## 场景目录

| 场景 | 目录 | 覆盖 |
|---|---|---|
| 数据面协议与认证 | [frame-security/](./frame-security/) | 帧头认证/会话密钥/算法 fail-closed/加密路径/入口鉴权 |
| 路由引擎与转发 | [routing/](./routing/) | 自指循环/路由表/公告前缀 |
| 连通性 | [connectivity/](./connectivity/) | 探测/打洞/中继 |
| 控制面与拓扑同步 | [control-plane/](./control-plane/) | 接口认证/ID 分配/级联故障/条目残留 |
| 密钥与配置管理 | [keys-config/](./keys-config/) | KDF/密钥存储/解析背压/配置校验 |
| 管理面与运维 | [admin-ops/](./admin-ops/) | 凭据/持久化配置/授权/日志/审计 |
| 运行时可靠性 | [runtime/](./runtime/) | panic/资源泄漏 |
| 平台适配 | [platform/](./platform/) | 休眠失效/系统配置 |

## 汇总状态表

| ID | 场景 | 问题 | 状态 |
|---|---|---|---|
| [FS-01](./frame-security/FS-01-frame-header-unauth.md) | 数据面 | 帧头零认证，目标可改/明文注入 | ✅ 已落档 |
| [FS-02](./frame-security/FS-02-shared-key-spoofing.md) | 数据面 | 共享网络密钥可互伪、无前向保密 | ✅ 已落档 |
| [FS-03](./frame-security/FS-03-xor-fallback-crypto.md) | 数据面 | 加密后端不可用时静默降级弱加密 | ✅ 已落档 |
| [FS-04](./frame-security/FS-04-crypto-bypass-path.md) | 数据面 | 加密路径旁路（明文模式/代理穿透） | ✅ 已落档（硬规则） |
| [FS-05](./frame-security/FS-05-secure-mode-multihop.md) | 数据面 | 安全机制作为附加模式 → 多跳缺陷 | ✅ 架构规避 |
| [FS-06](./frame-security/FS-06-resolvable-dns-names.md) | 数据面 | 内部名称解析使用真实可解析域名 | ✅ 已落档 |
| [FS-07](./frame-security/FS-07-default-cipher-choice.md) | 数据面 | 默认加密算法选择失当 | ✅ 已落档 |
| [FS-08](./frame-security/FS-08-entry-no-auth.md) | 数据面 | 共享入口无强制鉴权 | ✅ 已落档 |
| [FS-09](./frame-security/FS-09-transport-semantics-bypass.md) | 数据面 | 新增传输通道绕过代理/源地址语义 | ✅ 已落档（硬规则） |
| [RT-01](./routing/RT-01-self-route-loop.md) | 路由 | 公告前缀自指 → 黑洞循环 | ✅ 已落档 |
| [RT-02](./routing/RT-02-routing-table-mismatch.md) | 路由 | 多路由表错乱误删默认路由 | ✅ 架构规避 |
| [RT-03](./routing/RT-03-subnet-covers-relay.md) | 路由 | 子网代理覆盖中继端点 → 循环断链 | ✅ 已落档 |
| [CN-01](./connectivity/CN-01-probe-udp-dos.md) | 连通性 | 探测并发互探被误判 UDP DoS | ✅ 已落档（REQ-046） |
| [CN-02](./connectivity/CN-02-punch-parse-panic.md) | 连通性 | 打洞信令解析 panic 复发 | ✅ 已落档 |
| [CN-03](./connectivity/CN-03-shared-node-no-auth.md) | 连通性 | 共享/中继节点无用户级认证 | ✅ 已落档 |
| [CN-04](./connectivity/CN-04-policy-all-paths.md) | 连通性 | 策略执行未覆盖中继/打洞/直连全部路径 | ✅ 已落档 |
| [CN-05](./connectivity/CN-05-preauth-parse-alloc.md) | 连通性 | 认证前富解析/预认证资源分配 | **需补**：REQ-059 合并时入设计 + fuzz（SEC-08） |
| [CP-01](./control-plane/CP-01-rpc-no-auth-leak.md) | 控制面 | 控制接口无认证信息泄露 | ✅ 已落档 |
| [CP-02](./control-plane/CP-02-duplicate-peer-id.md) | 控制面 | 节点 ID 冲突 | ✅ 架构规避 |
| [CP-03](./control-plane/CP-03-cascade-failure.md) | 控制面 | 初始节点崩溃级联故障 | ✅ 架构规避 |
| [CP-04](./control-plane/CP-04-stale-node-leftover.md) | 控制面 | 失效节点信息残留 | ✅ 架构收益 |
| [CP-05](./control-plane/CP-05-reconnect-loop.md) | 控制面 | 重连无限循环无退避 | ✅ 已落档 |
| [CP-06](./control-plane/CP-06-local-ipc-unauth.md) | 控制面 | 本地 IPC/状态变更端点无认证 | ✅ 架构规避 |
| [KC-01](./keys-config/KC-01-weak-kdf.md) | 密钥配置 | 非加密哈希充当 KDF | ✅ 已落档 |
| [KC-02](./keys-config/KC-02-keys-plaintext-disk.md) | 密钥配置 | 密钥明文落盘 | **需补**：文件权限 600 + 加密存储 |
| [KC-03](./keys-config/KC-03-dns-resolution-backpressure.md) | 密钥配置 | 域名解析无背压 | ✅ 已落档 |
| [KC-04](./keys-config/KC-04-config-silently-ignored.md) | 密钥配置 | 配置静默失效 | ✅ 已落档 |
| [KC-05](./keys-config/KC-05-peer-metadata-config-injection.md) | 密钥配置 | 协商元数据写入本地配置未转义 | **需补**：配置生成实现时转义+回读验证 |
| [KC-06](./keys-config/KC-06-noncanonical-revocation-key.md) | 密钥配置 | 吊销/比对键未规范化 | **需补**：REQ-058 合并时显式入 CONTROL_PLANE |
| [AO-01](./admin-ops/AO-01-default-credentials.md) | 管理面 | 硬编码默认凭据 | ✅ 已落档 |
| [AO-02](./admin-ops/AO-02-client-side-config-storage.md) | 管理面 | 关键配置存客户端本地存储 | ✅ 已落档 |
| [AO-03](./admin-ops/AO-03-admin-api-privesc.md) | 管理面 | 管理接口越权 | **需补**：授权模型 + 越权测试 |
| [AO-04](./admin-ops/AO-04-log-storm.md) | 管理面 | 日志撑爆磁盘 | ✅ 已落档 |
| [AO-05](./admin-ops/AO-05-no-security-audit.md) | 管理面 | 无独立安全审计 | **需补**：P3/P4 挂审计 |
| [AO-06](./admin-ops/AO-06-release-source-consistency.md) | 管理面 | 发布产物与源码不一致 | **需补**：可复现构建 + 一致性校验 |
| [AO-07](./admin-ops/AO-07-admin-action-toctou.md) | 管理面 | 管理操作时序型越权（检查/执行窗口） | **需补**：P3 管理 API 原子授权 + 吊销即时生效 |
| [RM-01](./runtime/RM-01-panic-systemic.md) | 运行时 | 解析路径 panic 系统性复发 | **需补**：实现规范 + 任务隔离 |
| [RM-02](./runtime/RM-02-socket-leak.md) | 运行时 | 连接资源泄漏 → EMFILE | **需补**：生命周期管理 |
| [PF-01](./platform/PF-01-platform-sleep-stale.md) | 平台 | 休眠/网络切换后静默失效 | **需补**：平台生命周期钩子 |
| [PF-02](./platform/PF-02-disables-firewall.md) | 平台 | 运行时改动系统安全配置 | ✅ 架构规避 |
| [PF-03](./platform/PF-03-kernel-driver-dependency.md) | 平台 | 内核驱动依赖 → 蓝屏/日志风暴 | ✅ 架构规避 |
| [PF-04](./platform/PF-04-tun-ready-timeout.md) | 平台 | TUN 就绪依赖硬超时 | **需补**：事件驱动 + 有界重试 |

## 复核触发点（何时回看）

- 设计/新增任何包类型时：复核 **FS-01/FS-04**（不得绕过 AEAD、帧头必须进 AAD）+ **FS-09**（通道不得绕过代理/源地址语义）
- 实现路由引擎（LPM/fallback）时：复核 **RT-01/RT-02/RT-03** + **CN-01**（probe 限速强制）
- 实现前缀公告流程时：复核 **RT-01/RT-03** + **KC-04**（白名单校验不静默失效）
- 实现密钥体系/KDF 时：复核 **FS-02/FS-03/FS-07** + **KC-01** + **KC-02**（密钥存储规范）+ **KC-06**（吊销/比对键规范化）
- 实现握手/会话时：复核 **FS-01/FS-02**（逐对会话密钥 + 身份绑定交叉验证）
- 实现任务框架时：复核 **RM-01**（fail-closed 规范 + 任务隔离）
- 实现控制面连接管理时：复核 **RM-02** + **CP-03**（重连全量补偿）+ **CP-05**（退避 + 上限）
- 实现组级隔离（v2）/打洞时：复核 **CN-04**（策略覆盖中继/打洞/直连全部路径）
- 实现平台适配（macOS/Windows）时：复核 **PF-01/PF-02** + **PF-03**（禁内核驱动）+ **PF-04**（事件驱动就绪）
- 实现 netmap 增量（v2）时：复核 **CP-04**（淘汰策略）
- 实现管理面/WebUI 时：复核 **AO-01/AO-02** + **AO-03**（授权模型）+ **AO-07**（原子授权 + 吊销即时生效）
- 新增本地管理接口/daemon socket/Web API 时：复核 **CP-06**（对端身份验证 + 权限最小化 + 破坏性端点同等鉴权）
- 实现配置生成/元数据落盘时：复核 **KC-05**（转义/白名单 + 回读验证）
- 实现配置解析时：复核 **KC-03**（缓存 + 指数退避）+ **KC-04**
- 实现中继限速/挂靠时：复核 **CN-03** + **CN-05**（预认证最小解析 + 资源分配后置）
- 实现 CI 发布流水线时：复核 **AO-06**（可复现构建 + 产物一致性）
- 路线图规划时：复核 **AO-05**（安全审计）

## 新增 lesson 规范

- **命名**：`<场景前缀>-<序号>-<slug>.md`，场景前缀 = 场景目录名缩写（FS/RT/CN/CP/KC/AO/RM/PF）
- **模板**：

```markdown
# <ID> <短标题>

> 场景：<场景> ｜ 状态：<状态> ｜ 复核时机：<实现阶段>

## 问题（现象）   # 具体场景：拓扑/配置/期望 vs 实际——允许伪配置块
## 原因          # 设计层面的根因
## 正确行为       # 通用规则本体：任何正确实现都必须满足的行为约束（不绑当前设计）
## 复核触发点     # 时机 + 具体检查清单（编号列表）
## 关联验证       # 可选
```

- **场景归属判断**：问题在哪个子系统"咬到"就归哪个场景
- **状态取值**：`✅ 已落档`（规则已进设计文档）/ `✅ 架构规避` / `✅ 架构收益` / `需补：<行动>` / `—`（无关）
- **描述要求**：只写问题本身（现象/原因/正确行为），不写"我们的规避"（规则归属设计文档，避免重复而失真）；场景描述具体到可还原；不引用外部项目名与 issue 编号（关联可在 git 历史追溯）

## 更新记录

| 日期 | 变更 |
|---|---|
| 2026-09-02 | **v0.7**：新增 5 条（CN-05/KC-05/KC-06/CP-06/AO-07）——认证前富解析与预认证分配、协商元数据注入本地配置、吊销/比对键规范化、本地管理接口与状态变更端点鉴权、管理操作时序型越权；同批提出 REQ-058/REQ-059（外部项目公开 advisory 教训吸收批次） |
| 2026-08-30 | **v0.6**：模板升级——全部 37 条重写为「问题（现象）/原因/正确行为/复核触发点」结构，去除"我们的规避"段（规则归属设计文档，避免重复而失真）；场景描述具体化到可还原 |
| 2026-08-30 | **v0.5**：新增 6 条（CN-04/AO-06/FS-09/PF-03/PF-04/CP-05），合计 38 条 |
| 2026-08-30 | **v0.4 重构**：单表 LESSONS.md → docs/lessons/ 场景化拆分（8 场景 32 条），共用模板，来源信息抽象化移除；README 承载场景目录/汇总表/复核触发点/模板规范 |
| 2026-08-15 | v0.3：新增 A 组协议本体缺陷（11 项）、B 组可靠性规范（5 项）、C 组管理面（3 项）；v0.1 需补 5 项全部落档 |
