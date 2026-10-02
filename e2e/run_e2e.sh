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
#   preauth_flood：预认证洪泛（REQ-059/SEC-08）——宿主向 node-a 数据面灌 UDP 垃圾
#            （随机/变形帧头/probe 全 type）、向 coord:8443 灌裸 TCP 垃圾 + TLS 后
#            超长帧/垃圾信封/REGISTER 垃圾消息体 → 三容器存活不 panic、node-a 丢帧
#            摘要出现（fail-closed）、洪泛后 b→a 双栈 ping 收敛（已认证流量不受影响）
#   frame_attacks：帧层对抗容器级复验（SEC-01~04/11）——direct 拓扑 + forge.py 注入：
#            在途篡改 stale-mac / 非成员 random-key（送达+转发路径）→ BadRouteMac；
#            成员（持 key_dst 等价材料）伪造源/重算 mac + 垃圾密文 → 越 route_mac、
#            目的端 AEAD 拦截；2000 帧垃圾 AEAD 洪泛逐帧丢弃、容器存活、ping 收敛
#   coord_attacks：控制面对抗复验（SEC-12/18）——node-c 被钓鱼指向宿主 rogue TLS
#            （连接有、auth key 零泄露、永不注册）；未注册 TLS 连接灌 HEARTBEAT →
#            coord 无操作；node-a 停机 + 持续伪造心跳 → 租约照常过期（ping 断）
#   dual_edge：双边缘冗余（E2E-06）——node-a/c 同前缀同 IP 双公告（active-backup）：
#            ingress 归属判定活跃边缘 → 停机 → 租约过期撤销 → 引擎切 standby 收敛
#   exit_wan：mesh 出口（E2E-05，REQ-071）——node-c（exit 能力位 0x08）双挂 inet 网，
#            node-b default_route_preference=["mesh"] 借道出口：准入 fail-closed
#            （能力位 ∧ exits.allow）→ SIGHUP 运行时授权 → 双栈借道转发（c ingress
#            证据）→ 出口停机租约过期 → 无候选回退丢弃
#   status：只读状态端点（REQ-051/052，CONTROL_PLANE §3.14/§3.15）——direct 拓扑 +
#            coord status 段；认证（401/429/明文拒绝）、内容组齐全（含 REQ-052
#            build_version）、遥测聚合（per-peer 计数 + 直连对 RTT）、SIGHUP 密码
#            轮换（旧 401 新 200 + reload_log）、红线（密码/密钥材料零输出）
#   iperf ：性能场景（docs/perf.md §2.4）——TUN 隧道 iperf3 双向吞吐；
#           MESH_E2E_TOPOLOGY=relay 用线形拓扑（经中继），MESH_E2E_CPUS=0 全容器绑单核
#   dn42  ：dn42 接入互操作（DN42_LEG §7，DNL-01~07）——node-a（lrill dn42 leg，无
#           coordinator）+ peer-r（内核 WG + FRR）：WG 握手、BGP Established、路由
#           学习/撤销/fallback、import 白名单负向、stub 导出、会话故障自动重建
#   mtu   ：MTU 策略（ROUTE_ENGINE §6，RTE-07）——direct 拓扑 + 底网 MTU 1400（tun
#           配置 1420 > 保守值 1394）：MSS clamp 双向（协商 mss:1354）、DF 超限 →
#           伪造 PTB v4/v6（next-hop mtu 1314 = 1400−86）、PTB 后会话不受扰
#   ha    ：coord 3 副本 raft 集群（REQ-070 阶段二，CONTROL_PLANE §3.6）——follower
#           重定向注册 → 停 leader 容器（数据面 ping 不断 + 新 leader 更高 term）→
#           节点重定向链幂等重注册（node_id 不变）→ 旧 leader 重启以 Follower 回归
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
