  # probe 场景（CONNECTIVITY §2/§4/§5，CON-01/03/04/05/06 + SEC-26）：
  # 拓扑：a(net1) — b/d(双网卡自愿 relay) — c(net2)，a↔c 直连黑洞
  # 断言：
  # ① CON-01 coordinator UDP 回显：节点收到 echo confirmed（seen 地址）
  # ② SEC-26 反射放大限速：宿主灌 echo 洪泛 → coord 周期摘要 echo rate-limited
  # ③ CON-05 relay 列表构建：coord 日志 relay rtt 排序；节点持有 relay candidates
  # ④ CON-03 直连互探确认：节点日志 probe confirmed direct via
  # ⑤ CON-04 中继兜底：c→a 经 b 可达（b 日志 relayed frame）
  # ⑥ CON-06 中继故障切换：docker stop node-b → c→a 仍可达（经 d 中继）
  logs() { docker logs "$1" 2>&1; }
  ping_ca() {
    docker exec mesh-node-c ping -c1 -W1 10.42.0.1 >/dev/null 2>&1
  }
  wait_log() {  # $1=容器 $2=模式 $3=次数(默认1) $4=循环上限(默认40)
    local c="$1" pat="$2" want="${3:-1}" n="${4:-40}" i=0
    while [ "$(logs $c | grep -c "$pat" || true)" -lt "$want" ]; do
      i=$((i+1)); [ "$i" -ge "$n" ] && return 1
      sleep 2
    done
    return 0
  }

  echo "==> probe 阶段 1/6：注册 + CON-01 coordinator UDP 回显"
  for c in mesh-node-a mesh-node-b mesh-node-c mesh-node-d; do
    wait_log $c 'registered:' 1 30 || { echo "FAIL: $c 未注册"; logs $c | tail -10; exit 1; }
  done
  echo "PASS: 四节点全部注册"
  # echo 周期 30s：节点发 PING(to=0) → coordinator 回显 seen 地址
  wait_log mesh-node-a 'echo confirmed:' 1 30 || {
    echo "FAIL: node-a 未收到 coordinator UDP 回显（CON-01）"
    logs mesh-node-a | grep -E 'echo|probe|dropped' | tail -10
    logs mesh-coord | tail -10
    exit 1
  }
  echo "PASS: CON-01——coordinator UDP 回显（echo confirmed）"

  echo "==> probe 阶段 2/6：SEC-26 反射放大限速（echo 洪泛 → rate-limited 摘要）"
  # 洪泛目标 = coord 容器 UDP 8443（宿主直达容器固定 IP）；限速 10/s 突发 20，
  # 200 包瞬间灌入 → 大部分被限速（amplification 收敛）
  python3 - <<'PYEOF'
import socket, struct, sys
ip = "192.168.240.10"
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for i in range(200):
    pkt = b"LPRB" + bytes([1]) + struct.pack(">III", 999, 0, i)
    sock.sendto(pkt, (ip, 8443))
PYEOF
  wait_log mesh-coord 'echo rate-limited:' 1 15 || {
    echo "FAIL: coordinator 未输出 echo rate-limited 摘要（SEC-26 限速失效）"
    logs mesh-coord | tail -10
    exit 1
  }
  echo "PASS: SEC-26——echo 洪泛被限速（rate-limited 摘要出现）"

  echo "==> probe 阶段 3/6：CON-05 relay 列表构建（RTT 排序 + 节点挂靠候选）"
  wait_log mesh-coord 'relay rtt' 1 20 || {
    echo "FAIL: coordinator 未输出 relay RTT 排序日志（CON-05）"
    logs mesh-coord | tail -10
    exit 1
  }
  logs mesh-coord | grep 'relay rtt' | tail -2
  wait_log mesh-node-c 'relay candidates' 1 20 || {
    echo "FAIL: node-c 未持有 relay 挂靠候选"
    logs mesh-node-c | grep -E 'relay|netmap' | tail -10
    exit 1
  }
  echo "PASS: CON-05——relay 列表 RTT 排序下发 + 节点持有挂靠候选"

  echo "==> probe 阶段 4/6：CON-03 直连互探确认 + CON-04 中继兜底"
  wait_log mesh-node-c 'probe confirmed direct via' 1 40 || {
    echo "FAIL: node-c 无互探确认日志（CON-03）"
    logs mesh-node-c | grep -E 'probe|relay' | tail -10
    exit 1
  }
  echo "PASS: CON-03——直连互探确认（probe confirmed direct via）"
  for i in $(seq 1 40); do
    if ping_ca; then
      if [ "$(logs mesh-node-b | grep -c 'relayed frame' || true)" -ge 1 ]; then
        echo "PASS: CON-04——c→a 经 node-b 中继可达（relayed frame）"
        docker exec mesh-node-c ping -c3 10.42.0.1 || true
        break
      fi
    fi
    sleep 2
    [ "$i" = "40" ] && {
      echo "FAIL: c→a 中继兜底未通（CON-04）"
      echo "--- node-c 日志 ---"; logs mesh-node-c | grep -E 'relay|probe|dropped|path|frame|session' | tail -20
      echo "--- node-b 日志 ---"; logs mesh-node-b | grep -E 'relay|dropped|frame' | tail -10
      echo "--- node-a 日志 ---"; logs mesh-node-a | grep -E 'route|path|frame|session|dropped|send' | tail -20
      echo "--- node-d 日志 ---"; logs mesh-node-d | grep -E 'relay|dropped|frame' | tail -10
      exit 1
    }
  done

  echo "==> probe 阶段 5/6：CON-06 中继故障切换（stop node-b → 经 d 中继仍可达）"
  docker stop mesh-node-b >/dev/null
  sleep 5
  ok=0
  for i in $(seq 1 40); do
    if ping_ca; then
      if [ "$(logs mesh-node-d | grep -c 'relayed frame' || true)" -ge 1 ]; then
        ok=1
        echo "PASS: CON-06——node-b 停机后 c→a 经 node-d 中继仍可达（故障切换）"
        docker exec mesh-node-c ping -c3 10.42.0.1 || true
        break
      fi
    fi
    sleep 2
  done
  [ "$ok" = "1" ] || {
    echo "FAIL: node-b 停机后 c→a 不可达（CON-06 故障切换失效）"
    echo "--- node-c 日志 ---"; logs mesh-node-c | grep -E 'relay|probe|dropped|path' | tail -10
    echo "--- node-d 日志 ---"; logs mesh-node-d | tail -10
    exit 1
  }
  echo "==> probe 场景全部通过"
  exit 0
