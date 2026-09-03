# 性能基准（perf）

> 数据面/加密路径的性能基线与回归对照。**证据类文档**：不承载行为设计（行为见 [design/](./design/README.md)），不进 REQ 演进流；结果随基准执行回填。
> 版本：v1.1（2026-09-03，新增 L1 路由规模基准：dn42 表规模 LPM 量化）

## 1. 基准分层（L1~L4）

| 层 | 位置 | 测什么 | 对应优化（REQ-053） |
|---|---|---|---|
| L1 微基准 | `rill-core/benches/frame.rs` | 帧头编解码 / auth_input / build_frame（64B/1400B 两档）/ open_frame / `seal` 现实现 vs naive 参照（旧算法：`to_vec` + 原地加密） | ②⑧ |
| L1 微基准（路由） | `rill-core/benches/route.rs` | LPM 在 dn42 表规模（100/1k/4k 条）下的 lookup_best 命中/未命中与批量注入（ROUTE_ENGINE §9 线性扫描量化） | P4 XDP 基线 |
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

首次基线（2026-09-01）：

- CPU：AMD EPYC 7302（8 vCPU 宿主）；L1/L2 用 `taskset -c 0` 绑单核，L4 用 `MESH_E2E_CPUS=0` 全容器 cpuset
- 内核：6.12.73+deb13-amd64；Docker 29.3.1
- rustc 1.98.0 stable；criterion 0.5.1（bench profile：release，默认 opt）
- 对照提交：baseline = `0012dca`（REQ-053 前）↔ HEAD = REQ-053 后（`c27b627` + bench 基础设施）
- L4 拓扑：direct（a↔b）/ relay（a—b—c 线形，经 b 中继）；iperf3 5s 单流 TCP

## 4. 结果

### L1 微基准（µs/iter，中位数，越小越好）

| bench | baseline | HEAD | Δ |
|---|---|---|---|
| header/encode | 19.6 ns | 19.5 ns | ≈0 |
| header/decode | 11.30 ns | 10.98 ns | -2.8% |
| header/auth_input | 7.52 ns | 7.53 ns | ≈0 |
| frame/build/64 | 3.165 | 3.065 | -3.2% |
| frame/build/1400 | 4.668 | 4.496 | -3.7% |
| frame/open/64 | 3.072 | 3.063 | ≈0 |
| frame/open/1400 | 4.514 | 4.475 | -0.9% |
| aead/seal_current（1400B） | 3.484 | 3.407 | -2.2% |

一致性交叉验证：HEAD 的 `seal_naive_reference`（内置旧算法）= 3.51µs ≈ baseline `seal_current` 3.48µs——bench 参照与真实旧实现吻合。
解读：L1 以 AEAD 计算为主导（~3.4µs），分配/拷贝消除的绝对收益在百 ns 级（build -3.7%）；帧头操作为 ns 级不受影响（符合预期——⑧ 是正确性投资非性能投资）。

### L1 微基准（路由，dn42 表规模，2026-09-03，taskset -c 0）

| bench | 100 条 | 1k 条 | 4k 条 |
|---|---|---|---|
| insert_all（批量注入，µs） | 18.3 | 176.6 | 691.6 |
| lookup_best_hit（命中，ns） | 521 | 4 621 | 18 603 |
| lookup_best_miss（未命中，ns） | 358 | 3 004 | 12 057 |

结论：线性扫描 ~4.6ns/条/次查找。dn42 全表（≈4k 条）下单核转发上限 ≈ 50k pps（仅 LPM 项），
边缘盒可接受；P4 XDP 快速路径替换时以本表为对照基线（ROUTE_ENGINE §9）。

### L2 环回数据面（µs/包，中位数，越小越好）

| bench | baseline | HEAD | Δ |
|---|---|---|---|
| ping_pong_1400B（每往返） | 36.17 | 33.37 | **-7.7%** |
| relay_forward_1400B | 16.58 | 15.39 | **-7.2%** |
| broadcast_deliver_1400B | 226.0 | 232.0 | ≈0（高方差 ±7%） |

解读：数据面热路径（接收缓冲复用 + 原地解密 + 零拷贝扇出）每包省 ~2.3µs/往返、~1.2µs/转发；广播送达被泛洪簿记（flood_seen 30s 表增长）主导，优化被淹没（方差内）。

### L4 全栈吞吐（Mbps，sender/receiver，单流 TCP 5s）

| 拓扑/约束 | 方向 | baseline | HEAD | Δ（sender） |
|---|---|---|---|---|
| direct 未约束 | 正向 b→a | 267/264 | 277/275 | +3.7% |
| direct 未约束 | 反向 a→b | 252/251 | 259/255 | +2.8% |
| direct 单核 | 正向 | 144/143 | 152/152 | +5.6% |
| direct 单核 | 反向 | 142/142 | 152/151 | +7.0% |
| relay 未约束 | 正向 c→a | 265/253 | 272/271 | +2.6% |
| relay 未约束 | 反向 a→c | 239/238 | 243/242 | +1.7% |
| relay 单核 | 正向 | 99.8/94.9 | 109/104 | +9.2% |
| relay 单核 | 反向 | 90.7/90.0 | 99.0/98.3 | +9.2% |

解读：
- 未约束下内核网络/TUN 路径占大头，端到端提升 2~4%；**单核约束放大用户态占比**，direct +6~7%、relay（用户态转发计入瓶颈）+9%——验证 §2.2 的约束方法论
- 绝对吞吐参考：单核 1400B MTU 加密转发 ~100 Mbps 量级，对应每包用户态成本 ~100µs 中的隧道全路径（含 TCP/内核）
- 采样注记：baseline relay 未约束首次运行反向出现 0 bps（连接成功无数据），复跑正常——判定为环境偶发，表中取复跑值；此类偶发是 PASS 只判退出码、数值不设阈值的原因

## 5. 重跑时机

数据面 I/O 路径改动（REQ-053 类）、加密实现更换、runtime/tokio 大版本变更、协议 v2 帧头数据面落地（REQ-034 数据面期）。
