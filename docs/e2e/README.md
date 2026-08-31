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

## 3. 运行入口（仓库内脚本）

| 脚本 | 覆盖 | 前置条件 |
|---|---|---|
| `e2e/run_e2e.sh` | mesh 接入全链路（双节点 ping/ping6、IPv6 双栈、泛洪） | docker + compose 构建 |
| `e2e/p0_tailscale/run_p0.sh` | P0 过渡验证（headscale + 官方客户端入网 + WG 直连） | docker，GitHub/pkgs 可达 |

- 每次运行前 `run_e2e.sh` 重新拷贝二进制（compose build 会使用 build/ 目录旧产物）
- 生产形态（v1.1）：mesh 前缀 → tun0 静态路由由脚本注入，自动化注入挂账

## 4. 阶段验证目标

| 阶段 | 验证什么 | 状态 |
|---|---|---|
| P0 | headscale + derper 部署、官方 app（iOS/Android）入网端到端 | ✅ 已实证（#31，REQ-033；交互式登录真机挂账） |
| P1 | mesh 骨架：注册/netmap/34B 帧转发/直连+中继/租户隔离 | 🚧 数据面/控制面主机+容器闭环（REQ-022~032）；直连/中继/租户未实现 |
| P2 | 接入：ts2021 客户端接入（subnet router 广播）、dn42 接入（eBGP-lite 会话） | ⏳ 未开始 |
| P3 | 融合：路由引擎策略/exit 双向/自研 ts2021 服务端/Raft 切换 | ⏳ 未开始 |
| P4 | XDP 快速路径与用户态路径一致性 | ⏳ 未开始 |

## 5. 与 tests/ 的关系

- e2e/ 承载"如何跑"（环境/拓扑/脚本）；tests/ 承载"验什么"（场景/状态/验收断言）
- 容器级场景的状态与缺口在 tests/ 各域文件跟踪，本目录不重复
