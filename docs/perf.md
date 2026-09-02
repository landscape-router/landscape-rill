# 性能基准（perf）

> 数据面/加密路径的性能基线与回归对照。**证据类文档**：不承载行为设计（行为见 [design/](./design/README.md)），不进 REQ 演进流；结果随基准执行回填。
> 版本：v0.1（2026-09-01）

## 1. 基准分层（L1~L4）

| 层 | 位置 | 测什么 | 对应优化（REQ-053） |
|---|---|---|---|
| L1 微基准 | `rill-core/benches/frame.rs` | 帧头编解码 / auth_input / build_frame（64B/1400B 两档）/ open_frame / `seal_in_place` vs naive 参照（旧算法：`to_vec` + 双缓冲组装）/ decrement_ttl | ②⑧ |
| L2 环回数据面 | `rill-mesh/benches/dataplane.rs` | 真实 UDP socket 全链：握手后 ping-pong 每往返 µs、relay 转发每包 µs、广播送达每包 µs | ①③ |
| L3 跨提交 A/B | 手动 worktree 流程（§2.3） | 同一 bench 代码在 REQ-053 前后提交上的对照（真实 before/after） | 全部 |
| L4 全栈吞吐 | `MESH_E2E_SCENARIO=iperf` | 容器 TUN 隧道 iperf3 Mbps：direct/relay 拓扑 × 未约束/单核约束 | 全部（端到端） |

边界声明：
- **TUN 读写在 L1~L3 不可覆盖**（需 `/dev/net/tun` + 特权，bench 环境不可得），仅 L4 覆盖
- 广播泛洪被令牌桶（64/16/s，FRAME_HEADER §2.6）限速，L2 直测 `handle_broadcast_frame` 绕开
- bench 不进 CI（时间基准噪声大），手动执行；回归判定以 L3 同机同约束对照为准

## 2. 复跑方法

### 2.1 L1/L2

```bash
taskset -c 0 cargo bench -p landscape-rill-core    # 微基准
taskset -c 0 cargo bench -p landscape-rill-mesh    # 环回数据面
```

### 2.2 资源约束约定

- 所有基准进程**绑同一核**（`taskset`/`cpuset`），A/B 两侧约束必须一致
- 用 cpuset 绑核，**不用 `--cpus`（CFS 配额）**——节流按 100ms 周期量化，吞吐成台阶、引入方差
- 单核约束 = 目标部署形态（1~2 核边缘盒）的真实画像，同时放大用户态优化的相对可见度

### 2.3 L3 跨提交 A/B

```bash
# 基线 = 0012dca（REQ-053 前），HEAD = 当前实现
git worktree add /tmp/opencode/perf-baseline 0012dca
cd /tmp/opencode/perf-baseline
git checkout HEAD -- rill-core/benches rill-mesh/benches   # 注入同一份 bench 代码
#   并为两个 crate 的 Cargo.toml 加 criterion dev-dep + [[bench]]（见 HEAD 同文件）
taskset -c 0 cargo bench -p landscape-rill-core -p landscape-rill-mesh
# HEAD 侧同参数重跑，对照表回填 §5
```

注意事项：
- bench 代码只用 REQ-053 前后**签名未变**的 API（`handle_incoming`/`send_to_node_hop`/`build_data_frame`/`build_frame`/`open_frame`/`Session::open`），保证基线可编译；`decrement_ttl`/in-place 变体为新增，基线侧跳过（criterion `--exact` 过滤）
- 基线 lock 无 criterion，需网络拉取；registry 不可达时降级用 L1 内置 naive 参照对比

### 2.4 L4 全栈吞吐

```bash
./e2e/run_e2e.sh iperf                        # direct 拓扑，未约束
MESH_E2E_CPUS=0 ./e2e/run_e2e.sh iperf        # 全容器绑单核（cpuset）
MESH_E2E_TOPOLOGY=relay ./e2e/run_e2e.sh iperf  # relay 拓扑（转发优化最灵敏配置）
```

PASS 只判 iperf 退出码（不设吞吐阈值——容器网络/内核路径噪声大）；数值记录进 §5。base 镜像含 iperf3（旧镜像需 `docker rmi mesh-e2e-base` 重建）。

## 3. 环境记录

执行时回填：CPU 型号/核数、内核版本、rustc/criterion 版本、编译 profile（criterion 默认 release + LTO 配置见 benches 源码）、docker 拓扑。

## 4. 结果

> 以下表格随基准执行回填；每次回填更新文档头部日期与 §3 环境。

### L1 微基准（µs/iter，越小越好）

| bench | baseline(0012dca) | HEAD | Δ |
|---|---|---|---|
| 待回填 | — | — | — |

### L2 环回数据面（µs/包，越小越好）

| bench | baseline | HEAD | Δ |
|---|---|---|---|
| 待回填 | — | — | — |

### L4 全栈吞吐（Mbps，越大越好）

| 拓扑/约束 | baseline | HEAD | Δ |
|---|---|---|---|
| 待回填 | — | — | — |

## 5. 重跑时机

数据面 I/O 路径改动（REQ-053 类）、加密实现更换、runtime/tokio 大版本变更、协议 v2 帧头数据面落地（REQ-034 数据面期）。
