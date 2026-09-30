# REQ-068 自研 ts2021 服务端（替换 headscale）

- 类型：需求
- 状态：✅ merged
- 提出日期：2026-09-30
- 合并日期：2026-09-30
- 去向：TS2021_LEG §4
- 验收场景：TSL-12（tests/legs/ts2021.md）

## 动机

P3 路线图项（CONTEXT §10：自研 ts2021 服务端替换 headscale）。自建 tailnet 控制面依赖外部 Go 项目 headscale（sqlite/CLI/用户体系 = 过渡负担，且 e2e 需下载外部二进制）；客户端侧协议栈（controlbase/controlhttp/h2/tailcfg/DERP）已全量自研并有实证语义（TSL 系列），服务端是把同一套知识翻到 accept 侧。另外 REQ-067 的增量帧客户端能力没有会中流推送的服务端可验证（headscale 0.29 无中流推送，e2e 只能强制重轮询模拟）——自研服务端让增量路径获得真实生产者。

## 决策摘要

部署形态 = rilld `ts2021_server` 配置段，与 coordinator 同进程可共存、协议独立（ARCHITECTURE §6 浅结合）；端点集 = `/key` + `/ts2021`（Noise 升级）+ h2 `/machine/register`、`/machine/map` + `/derp`（内嵌 DERP，同 TLS 监听复用）；注册 = Noise IK 静态公钥为机器身份 + lrk auth key 准入 + 幂等（node key 轮换保 nid/地址）；netmap 语义对齐 headscale 实证形状（流持有 / Peers 缺省 ≠ 空集 / Hostinfo 覆写广播路由 / Lite 回空 body）；变更推送 = 持有流同流 PeersChanged/PeersRemoved 增量帧（空数组省略；lagged 全量重发自愈），Patch 不实现；子网路由审批 = `routes_whitelist` covered-by 自动批 + `allow_exit` 独立开关（默认路由混入白名单加载即拒）；状态 = v1 内存态（重启客户端重注册自愈），noise/derp 私钥 hex 文件持久化；单 tailnet，ts2021 侧 ACL 不做（mesh 侧 REQ-045 已闭环）；e2e 替换范围 = ts2021_runtime 切自研服务端（官方 tailscaled 保留作对端），ts2021_register / p0_tailscale 保留 headscale 兼容参照。

- lessons 复核（合并时）：FS-01/FS-02（握手/会话触发点——snow AEAD 承载 record 层，无绕过路径；msg2 为 Noise 握手帧不属 AEAD 域）
