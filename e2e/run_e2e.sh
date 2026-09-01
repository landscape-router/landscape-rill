#!/usr/bin/env bash
# mesh e2e 入口：setup（含幂等清理）→ 场景断言
#
# 场景（MESH_E2E_SCENARIO，默认 direct）：
#   direct：coord — node-a（tun0 10.42.0.1/24 + fd00:2::1/64）
#                   — node-b（tun0 10.43.0.1/24 + fd00:3::1/64），同 bridge 网
#           验证：node-b ping node-a（IPv4 + IPv6，IPv6 走组播泛洪 ND，FRAME_HEADER §2.6）
#   relay ：线形 a—b—c（b 双网卡 net1={a,b} net2={b,c}，c 与 a 无直连可达性）
#           验证：c→a 直连候选 miss → 快速切换 relay 路径（经 b，CONTROL_PLANE §3.11）
#           b 日志出现 "relayed frame" 作为中继证据
#   persist：coord 持久化存储（storage_path，REQ-037）——node-c 一次性 key 注册消费 →
#            重启 coord → a↔b 恢复 + node-c 挑战重连（无新注册）→ node-d 复用同一 key 被拒
set -euo pipefail

E2E_DIR="$(cd "$(dirname "$0")" && pwd)"
SCENARIO="${MESH_E2E_SCENARIO:-direct}"

logs() { docker logs "$1" 2>&1; }

trap "$E2E_DIR/cleanup.sh" EXIT

"$E2E_DIR/setup.sh"

if [ "$SCENARIO" = "persist" ]; then
  # persist 场景（REQ-037，CONTROL_PLANE §4.1）：coord 持久化存储重启恢复
  # 断言：① a↔b 双栈通；② node-c 一次性 key 注册成功（消费落盘）；
  #       ③ 重启 coord 后 a↔b 自动恢复（node-c 走挑战流程，无新注册）；
  #       ④ node-d 复用同一一次性 key → 注册被拒（消费状态已持久化）
  ping_pair() {  # 等待 a↔b 双栈恢复（重启后节点按退避自动重连）
    for i in $(seq 1 40); do
      if docker exec mesh-node-b ping -c1 -W1 10.42.0.1 >/dev/null 2>&1 \
         && docker exec mesh-node-b ping6 -c1 -W1 fd00:2::1 >/dev/null 2>&1; then
        echo "PASS: persist e2e a↔b ping 通（第 ${i} 次尝试）"
        return 0
      fi
      sleep 2
    done
    return 1
  }

  echo "==> 阶段 1/4：a↔b 双栈通"
  ping_pair

  echo "==> 阶段 2/4：node-c 一次性 key 注册（消费）"
  # 注意：grep -q 提前退出会 SIGPIPE docker logs（pipefail 下判 141）→ 统一用 grep -c 计数
  for i in $(seq 1 20); do
    if [ "$(logs mesh-node-c | grep -c 'registered:')" -ge 1 ]; then
      echo "PASS: node-c 一次性 key 注册成功"
      break
    fi
    sleep 2
  done
  if [ "$(logs mesh-node-c | grep -c 'registered:')" -lt 1 ]; then
    echo "FAIL: node-c 未注册"
    echo "--- node-c 日志头 10 行 ---"; logs mesh-node-c | head -10
    echo "--- node-c 日志尾 10 行 ---"; logs mesh-node-c | tail -10
    echo "--- registered 计数 ---"; logs mesh-node-c | grep -c "registered:" || true
    exit 1
  fi

  echo "==> 阶段 3/4：重启 coord（存储文件随容器保留）→ a↔b 自动恢复"
  docker restart mesh-coord >/dev/null
  sleep 2
  ping_pair || {
    echo "FAIL: coord 重启后 a↔b 未恢复"
    echo "--- coord 日志 ---"; logs mesh-coord | tail -20
    echo "--- node-a 日志 ---"; logs mesh-node-a | tail -20
    exit 1
  }
  # node-c 恢复走挑战流程（auth key 已消费），不得出现第二次注册
  if [ "$(logs mesh-node-c | grep -c 'registered:')" -gt 1 ]; then
    echo "FAIL: node-c 重启后重新注册（持久化缺失，注册状态丢失）"
    exit 1
  fi

  echo "==> 阶段 4/4：node-d 复用已消费的一次性 key → 注册必须被拒"
  # 注意：注册被拒是服务端静默断连（客户端只记 control connected，不记 connect failed）——
  # 断言对象是"到达 coord 且从未注册成功"，而非 connect failed
  docker compose -f "$E2E_DIR/mesh/persist/docker-compose.yaml" --profile late up -d node-d >/dev/null
  for i in $(seq 1 20); do
    if [ "$(logs mesh-node-d | grep -c 'registered:')" -ge 1 ]; then
      echo "FAIL: node-d 用已消费的一次性 key 注册成功（消费状态未持久化）"
      exit 1
    fi
    if [ "$(logs mesh-node-d | grep -c 'control connected')" -ge 1 ]; then
      echo "PASS: node-d 到达 coord 但注册被拒（一次性 key 消费已持久化），持续重连中"
      exit 0
    fi
    sleep 2
  done
  echo "FAIL: node-d 未观察到到达 coord（40s 内）"
  echo "--- node-d 日志 ---"; logs mesh-node-d | tail -20
  exit 1
fi

if [ "$SCENARIO" = "relay" ]; then
  # 快速切换窗口：直连候选 miss ×3（PATH_HEALTH_MISS_LIMIT，5s 心跳）≈ 15~30s
  for i in $(seq 1 40); do
    if docker exec mesh-node-c ping -c1 -W1 10.42.0.1 >/dev/null 2>&1; then
      relayed=$(logs mesh-node-b | grep -c "relayed frame" || true)
      if [ "$relayed" -ge 1 ]; then
        echo "PASS: relay e2e ping 通（第 ${i} 次尝试，经 node-b 中继，relay 转发日志 ${relayed} 条）"
        docker exec mesh-node-c ping -c3 10.42.0.1
        exit 0
      fi
      echo "（ping 通但未见 relay 转发日志，继续等待路径切换）"
    fi
    sleep 2
  done
  echo "FAIL: relay 场景 ping 不通"
  echo "--- coord 日志 ---";  logs mesh-coord | tail -20
  echo "--- node-a 日志 ---"; logs mesh-node-a | tail -20
  echo "--- node-b 日志 ---"; logs mesh-node-b | tail -20
  echo "--- node-c 日志 ---"; logs mesh-node-c | tail -20
  exit 1
fi

for i in $(seq 1 20); do
  if docker exec mesh-node-b ping -c1 -W1 10.42.0.1 >/dev/null 2>&1 \
     && docker exec mesh-node-b ping6 -c1 -W1 fd00:2::1 >/dev/null 2>&1; then
    echo "PASS: mesh e2e ping 通（第 ${i} 次尝试，IPv4 + IPv6 双栈）"
    docker exec mesh-node-b ping -c3 10.42.0.1
    docker exec mesh-node-b ping6 -c3 fd00:2::1
    exit 0
  fi
  sleep 2
done

echo "FAIL: ping 不通"
echo "--- coord 日志 ---";  logs mesh-coord | tail -20
echo "--- node-a 日志 ---"; logs mesh-node-a | tail -20
echo "--- node-b 日志 ---"; logs mesh-node-b | tail -20
exit 1
