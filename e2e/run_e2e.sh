#!/usr/bin/env bash
# mesh e2e 入口：setup（含幂等清理）→ scenarios/<name>.sh 断言
#
# 场景（MESH_E2E_SCENARIO，默认 direct；断言实现在 e2e/scenarios/<name>.sh）：
#   direct：coord — node-a（tun0 10.42.0.1/24 + fd00:2::1/64）
#                   — node-b（tun0 10.43.0.1/24 + fd00:3::1/64），同 bridge 网
#           验证：node-b ping node-a（IPv4 + IPv6，IPv6 走组播泛洪 ND，FRAME_HEADER §2.6）
#   relay ：线形 a—b—c（b 双网卡 net1={a,b} net2={b,c}，c 与 a 无直连可达性）
#           验证：c→a 直连候选 miss → 快速切换 relay 路径（经 b，CONTROL_PLANE §3.11）
#           b 日志出现 "relayed frame" 作为中继证据
#   persist：coord 持久化存储（storage_path，REQ-037）——node-c 一次性 key 注册消费 →
#            重启 coord → a↔b 恢复 + node-c 挑战重连（无新注册）→ node-d 复用同一 key 被拒
#   recover：注册响应丢失恢复（REQ-056/057）——coord 注入丢弃首个 REGISTER_RESPONSE →
#            node-a（一次性 key）退避 ≥1s 重连 → 挑战恢复原 node_id（无新注册）→
#            node-b 正常注册 → a↔b 双栈通
#   iperf ：性能场景（docs/perf.md §2.4）——TUN 隧道 iperf3 双向吞吐；
#           MESH_E2E_TOPOLOGY=relay 用线形拓扑（经中继），MESH_E2E_CPUS=0 全容器绑单核
# 环境变量 MESH_E2E_TRANSPORT（默认 udp，REQ-054）：=tcp 时数据面走真 TCP 兜底档
#（帧字节与 UDP 一致，仅外覆 2B 长度前缀）——建议与 direct 场景组合验证。
set -euo pipefail

E2E_DIR="$(cd "$(dirname "$0")" && pwd)"
SCENARIO="${MESH_E2E_SCENARIO:-direct}"

logs() { docker logs "$1" 2>&1; }

trap "$E2E_DIR/cleanup.sh" EXIT

"$E2E_DIR/setup.sh"

# 分派：场景名 → scenarios/<name>.sh（未知名回落 direct，与历史行为一致）。
# 场景脚本在本 shell 内执行（source）：共享 logs/E2E_DIR/set -euo pipefail/trap
SCENARIO_FILE="$E2E_DIR/scenarios/$SCENARIO.sh"
[ -f "$SCENARIO_FILE" ] || SCENARIO_FILE="$E2E_DIR/scenarios/direct.sh"
# shellcheck disable=SC1090
source "$SCENARIO_FILE"
