# E2E 验证环境（e2e）

> 本地端到端验证的**环境方案**与运行说明。已确认方案：**仅容器**（每节点一容器，OCI 运行时）。
> 场景清单与状态见 [../tests/README.md](../tests/README.md)（验收矩阵）与 [../tests/integration.md](../tests/integration.md)（跨接入联动）。

## 1. 环境方案（仅容器）

- 每节点 = 一个容器（rill ext 节点实例），NAT 场景用额外容器/iptables 模拟
- 依赖：OCI 运行时（docker/podman）+ 容器网络（bridge/macvlan 均可）
- 无容器运行时依赖的开发机阶段（纯协议逻辑）可先用单进程多实例——但正式验证以容器为准

## 2. 容器拓扑（通用）

```
coordinator 容器（单机；P2 起支持 Raft 集群模拟）
  ↓
node-A 容器 ──┐
node-B 容器 ──┼── 容器网络（可注入 NAT 容器模拟家庭/对称 NAT 场景）
node-C 容器 ──┘
```

- 每容器运行 landscape-rill 实例 + 必要的辅助组件（tun 需要容器特权/设备挂载）
- NAT 模拟：容器前置 iptables SNAT/MASQUERADE，或独立 NAT 容器作为中间层
- **mesh 场景（`e2e/mesh/`）**：
  - `direct`：coord + a + b 同网桥，验证 IPv4 + IPv6 双栈 ping（IPv6 走组播泛洪 ND）
  - `relay`：线形 a—b—c（b 双网卡 net1={coord,a,b} net2={coord,b,c}），c 与 a 无直连
    UDP 可达性——compose `ipam` 固定 IP + setup 在 a/c 互加黑洞路由（`/32`）模拟，
    验证直连候选 miss 后快速切换到 relay 路径（经 b），b 日志 `relayed frame` 为中继证据
  - `persist`：coord 持久化（storage_path，REQ-037，CONTROL_PLANE §4.1）——node-c 用
    一次性 auth key 注册（消费落盘）→ `docker restart mesh-coord`（存储文件随容器保留）
    → a↔b 自动恢复 + node-c 走挑战流程重连（无新注册）；node-d 复用同一一次性 key
    必须被拒（compose profile `late` 门控，重启断言阶段再拉起）
  - `log`：日志治理（REQ-039，LOGGING）——`--log-level` 覆盖 `RUST_LOG`、级别过滤、
    `--log-file` 按天轮转 + stderr 双写（e2e/mesh/log/）
  - `reload`：coordinator 配置 SIGHUP 重载（REQ-038，CONTROL_PLANE §3.12）——coord.json
    追加 auth key → HUP → 新 key 生效；写坏配置 → HUP → 重载失败保持旧配置（数据面不受影响）；
    移除 key → HUP → 即刻失效（node-c/d 用 compose profile `late` 门控，随阶段拉起）。
    注意：**bind mount 文件不可用 `sed -i` 修改**（rename 断开 inode，容器仍读旧文件）——
    须临时文件 + `cp` 原址覆盖
  - `probe`：连通性自愈（CONNECTIVITY §2/§4/§5，CON-01/03/04/05/06 + SEC-26）——
    a(net1)—b/d(双网卡 relay)—c(net2)，a↔c 直连黑洞：coordinator UDP 回显（节点
    `echo confirmed`）；宿主灌 echo 洪泛 → coord `echo rate-limited` 摘要；relay RTT
    排序（coord 日志 + 节点 `relay candidates`）；互探确认（`probe confirmed direct via`）；
    c→a 经 b 中继（`relayed frame`）；`docker stop node-b` → 切 node-d（故障切换）
  - `preauth_flood`：预认证洪泛（REQ-059，SEC-08）——direct 拓扑下宿主向 node-a 数据面
    灌 UDP 垃圾（随机字节/变形帧头/probe 全 type），向 coord:8443 灌裸 TCP 垃圾与
    TLS 后超长帧声明/垃圾信封/REGISTER 垃圾消息体；断言三容器存活不 panic、
    node-a 丢帧摘要出现（解析 fail-closed）、洪泛后 b→a 双栈 ping 收敛
    （已认证流量不受影响，认证失败路径零持久分配）
  - `dn42`：dn42 接入互操作（DN42_LEG §7，DNL-01~07）——node-a（lrill dn42 leg，
    无 coordinator）+ peer-r（**内核 WireGuard + FRR**，真实 dn42 peer 形态，专用网段
    192.168.243.0/24；镜像由 setup 以 run+commit 预置）：WG 握手、BGP Established、
    路由学习（LPM 注入 dn42 来源）、tun0→隧道转发、stub 导出、import 白名单负向
    （白名单外前缀已公告但拒收）、WITHDRAW 撤销收敛、会话故障（stop peer-r →
    hold timer 收敛 → SessionDown → 恢复自动重建）、双 peer 故障切换（peer-r2 同前缀
    双公告，profile late 门控）、max-prefix 超限关停循环（借 node 重启改配置）、
    WG 层单点故障（wg-quick down，隔离隧道层）、rogue BGP 畸形输入 fail-closed、
    表规模收敛与半表撤销（402 条 /24，peer-r2 = Bird——双 BGP 实现互操作）
  - `tenancy`：单 coordinator 双网络隔离（CONTROL_PLANE §1.5，SEC-21~25）——lab
    （node-a1/a2）+ work（node-b1/b2）共用一个 coordinator，全部容器同 bridge（隔离是逻辑的）：
    组内双栈互通、跨网络不可达、netmap 各见本网条目；node-d 持未配置网络（ghost）key 注册被拒；
    `e2e/mesh/tenancy/forge.py` 向 node-a2 注入伪造 42B 帧（route_mac 用 work 主密钥派生）
    断言 BadRouteMac 丢弃 + lab 主密钥正对照（越过 route_mac，证明 drop 因密钥不匹配）
- **e2e 容器网段**（RFC 1918，避开 docker 默认池 172.17-172.30 与 CGNAT）：
  - `192.168.240.0/23`：mesh e2e 专用（direct 用 `192.168.240.0/24`，relay 的
    net1/net2 用 `192.168.240.0/24` + `192.168.241.0/24`）
  - `192.168.242.0/24` 起：预留 headscale/ts2021 集成 e2e

## 3. 运行入口（仓库内脚本）

| 脚本 | 覆盖 | 前置条件 |
|---|---|---|
| `e2e/run_e2e.sh` | mesh 全链路入口：`setup.sh` + 场景断言；`MESH_E2E_SCENARIO=direct\|relay\|persist\|log\|reload\|tenancy\|probe\|iperf`（默认 direct） | docker + compose 构建 |

`iperf` 场景（性能基准 L4，见 [../perf.md](../perf.md)）：TUN 隧道 iperf3 双向吞吐，PASS 只判退出码（数值记录 perf.md，不设阈值）。环境变量：`MESH_E2E_TOPOLOGY=relay` 用线形拓扑（经中继，转发优化最灵敏配置）；`MESH_E2E_CPUS=0` 全容器 cpuset 绑单核（资源约束约定见 perf.md §2.2）。
| `e2e/setup.sh` | 初始化：base 镜像/CA/密钥/编译/配置/构建启动/路由与黑洞注入；幂等（开头强制 `cleanup.sh`） | 同上 |
| `e2e/cleanup.sh` | 幂等清理：全部 mesh 场景容器/网络 + `build/`（可重复执行） | 同上 |
| `e2e/p0_tailscale/run_p0.sh` | P0 过渡验证（headscale + 官方客户端入网 + WG 直连） | docker，GitHub/pkgs 可达 |

- 每次运行前 `run_e2e.sh` 重新拷贝二进制（compose build 会使用 build/ 目录旧产物）
- 生产形态（v1.1）：mesh 前缀 → tun0 静态路由由脚本注入，自动化注入挂账
- 无容器运行时依赖的开发机阶段（纯协议逻辑）可先用单进程多实例——但正式验证以容器为准

## 4. 阶段验证目标

| 阶段 | 验证什么 | 状态 |
|---|---|---|
| P0 | headscale + derper 部署、官方 app（iOS/Android）入网端到端 | ✅ 已实证（#31，REQ-033；交互式登录真机挂账） |
| P1 | mesh 骨架：注册/netmap/42B 帧转发/直连+中继/租户隔离 | 🚧 数据面/控制面主机+容器闭环（REQ-022~032）；直连/中继/租户未实现 |
| P2 | 接入：ts2021 客户端接入（subnet router 广播）、dn42 接入（eBGP-lite 会话） | 🚧 dn42 leg 本地闭环 + FRR 互操作 e2e（DNL-01~07，DN42_LEG §7）；ts2021 未开始 |
| P3 | 融合：路由引擎策略/exit 双向/自研 ts2021 服务端/Raft 切换 | ⏳ 未开始 |
| P4 | XDP 快速路径与用户态路径一致性 | ⏳ 未开始 |

## 5. 与 tests/ 的关系

- e2e/ 承载"如何跑"（环境/拓扑/脚本）；tests/ 承载"验什么"（场景/状态/验收断言）
- 容器级场景的状态与缺口在 tests/ 各域文件跟踪，本目录不重复
