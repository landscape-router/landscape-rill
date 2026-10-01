  # probe 场景（CONNECTIVITY §2/§4/§5，CON-01/03/04/05/06 + SEC-26 + REQ-062 + REQ-064）：
  # 拓扑：a(net1) — b/d(双网卡自愿 relay) — c(net2)，a↔c 直连黑洞
  # 断言：
  # ① CON-01 coordinator UDP 回显：节点收到 echo confirmed（seen 地址）
  # ② SEC-26 反射放大限速：宿主灌 echo 洪泛 → coord 周期摘要 echo rate-limited
  # ③ CON-05 relay roster 构建：coord RTT 轮 → roster 落位（b+d）；节点持有 relay candidates
  # ④ CON-03 直连互探确认：节点日志 probe confirmed direct via
  # ⑤ CON-04 中继兜底：c→a 经 b 可达（b 日志 relayed frame）
  # ⑥ REQ-062 roster 收窄：SIGHUP exclude node-d → roster 仅剩 b，路径仍可用
  # ⑦ CON-06 中继故障切换：exclude 移除（roster 恢复 b+d）→ stop node-b → 经 d 中继仍可达
  # ⑧ REQ-064 空闲候选路径 PATH_PROBE：c 对 a 的空闲中继路径测得 RTT
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
  node_id_of() {  # $1=容器 → 注册分派的 node_id
    logs "$1" | grep -o 'registered: node_id=[0-9]*' | head -1 | grep -o '[0-9]*$'
  }
  roster_has() {  # $1=node_id → 最近一次 roster 落位是否含该节点
    logs mesh-coord | grep 'relay roster applied' | tail -1 \
      | grep -o 'roster=\[[0-9, ]*\]' | grep -o '[0-9]\+' | grep -qx "$1"
  }
  relay_count() { logs "$1" | grep -c 'relayed frame' || true; }
  set_exclude() {  # $1=node_id（空串 = 移除 exclude）→ coord.json lab 网段 + SIGHUP
    python3 - "$E2E_DIR/build/coord.json" "$1" <<'PYEOF'
import json, sys
path, excl = sys.argv[1], sys.argv[2]
with open(path) as f:
    cfg = json.load(f)
for net in cfg["coord"]["networks"]:
    if net["name"] == "lab":
        if excl:
            net["relay"] = {"exclude": [int(excl)]}
        else:
            net.pop("relay", None)
with open(path + ".tmp", "w") as f:
    json.dump(cfg, f, indent=2)
PYEOF
    # cp 原址覆盖保留 inode（sed -i 的 rename 会断开 bind mount）
    cp "$E2E_DIR/build/coord.json.tmp" "$E2E_DIR/build/coord.json"
    rm -f "$E2E_DIR/build/coord.json.tmp"
    docker kill -s HUP mesh-coord >/dev/null
  }

  echo "==> probe 阶段 1/8：注册 + CON-01 coordinator UDP 回显"
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

  echo "==> probe 阶段 2/8：SEC-26 反射放大限速（echo 洪泛 → rate-limited 摘要）"
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

  echo "==> probe 阶段 3/8：CON-05 relay roster 构建（RTT 轮 → 落位 b+d）"
  wait_log mesh-coord 'relay rtt' 1 20 || {
    echo "FAIL: coordinator 未输出 relay RTT 轮日志（CON-05）"
    logs mesh-coord | tail -10
    exit 1
  }
  logs mesh-coord | grep 'relay rtt round' | tail -2
  wait_log mesh-coord 'relay roster applied' 1 20 || {
    echo "FAIL: coordinator 未输出 roster 落位日志（REQ-062）"
    logs mesh-coord | grep -E 'rtt|roster' | tail -10
    exit 1
  }
  B_ID=$(node_id_of mesh-node-b)
  D_ID=$(node_id_of mesh-node-d)
  if roster_has "$B_ID" && roster_has "$D_ID"; then
    echo "PASS: roster 落位含 b($B_ID)+d($D_ID)"
  else
    echo "FAIL: roster 未同时纳入 b($B_ID)/d($D_ID)"
    logs mesh-coord | grep 'relay roster applied' | tail -3
    logs mesh-coord | grep 'relay rtt round' | tail -3
    exit 1
  fi
  wait_log mesh-node-c 'relay candidates' 1 20 || {
    echo "FAIL: node-c 未持有 relay 挂靠候选"
    logs mesh-node-c | grep -E 'relay|netmap' | tail -10
    exit 1
  }
  echo "PASS: CON-05——roster 经 netmap 下发 + 节点持有挂靠候选"

  echo "==> probe 阶段 4/8：CON-03 直连互探确认 + CON-04 中继兜底"
  wait_log mesh-node-c 'probe confirmed direct via' 1 40 || {
    echo "FAIL: node-c 无互探确认日志（CON-03）"
    logs mesh-node-c | grep -E 'probe|relay' | tail -10
    exit 1
  }
  echo "PASS: CON-03——直连互探确认（probe confirmed direct via）"
  for i in $(seq 1 40); do
    if ping_ca; then
      if [ "$(relay_count mesh-node-b)" -ge 1 ]; then
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

  echo "==> probe 阶段 5/8：REQ-064 空闲候选路径 PATH_PROBE（RTT 测得）"
  # c 持 a 的多候选（direct + 经 b/d 中继）：在用之外的中继路径无数据流量，
  # 泵周期 PATH_PROBE 沿路径首跳探活、响应沿同路径返回 → RTT 落桶（debug 日志）
  wait_log mesh-node-c 'path probe rtt:' 1 45 || {
    echo "FAIL: node-c 无 PATH_PROBE RTT 日志（REQ-064 激活失败）"
    echo "--- node-c 日志 ---"; logs mesh-node-c | grep -E 'path probe|paths|relay' | tail -10
    echo "--- node-b 日志 ---"; logs mesh-node-b | grep -E 'path probe|dropped' | tail -5
    exit 1
  }
  logs mesh-node-c | grep 'path probe rtt' | tail -2
  echo "PASS: REQ-064——空闲中继路径 PATH_PROBE RTT 测得"

  echo "==> probe 阶段 6/8：REQ-062 roster 收窄（SIGHUP exclude node-d → 仅 b）"
  B_RELAYED_BEFORE=$(relay_count mesh-node-b)
  set_exclude "$D_ID"
  narrowed=0
  for i in $(seq 1 20); do
    if roster_has "$B_ID" && ! roster_has "$D_ID"; then narrowed=1; break; fi
    sleep 2
  done
  if [ "$narrowed" != "1" ]; then
    echo "FAIL: exclude node-d($D_ID) 后 roster 未收窄"
    logs mesh-coord | grep -E 'roster|reloaded|reload' | tail -5
    exit 1
  fi
  echo "PASS: roster 收窄（d=$D_ID 移出，仅剩 b=$B_ID）"
  # 收窄后路径仍可用（REQ-062 验收⑤）：c→a 继续经 b 中继
  ok=0
  for i in $(seq 1 30); do
    if ping_ca && [ "$(relay_count mesh-node-b)" -gt "$B_RELAYED_BEFORE" ]; then ok=1; break; fi
    sleep 2
  done
  if [ "$ok" != "1" ]; then
    echo "FAIL: roster 收窄后 c→a 经 node-b 不可用（REQ-062 验收⑤）"
    echo "--- coord 日志 ---"; logs mesh-coord | grep -E 'roster|rtt' | tail -5
    echo "--- node-c 日志 ---"; logs mesh-node-c | grep -E 'relay|path|withdraw|frame|dropped' | tail -15
    exit 1
  fi
  echo "PASS: 收窄后 c→a 仍经 node-b 中继可用（REQ-062 验收⑤）"

  echo "==> probe 阶段 7/8：roster 恢复（b+d）+ CON-06 中继故障切换"
  set_exclude ""
  restored=0
  for i in $(seq 1 20); do
    if roster_has "$B_ID" && roster_has "$D_ID"; then restored=1; break; fi
    sleep 2
  done
  if [ "$restored" != "1" ]; then
    echo "FAIL: 移除 exclude 后 roster 未恢复 b($B_ID)+d($D_ID)"
    logs mesh-coord | grep -E 'roster|reloaded|reload' | tail -5
    exit 1
  fi
  echo "PASS: roster 恢复（b+d 双 relay）"
  D_RELAYED_BEFORE=$(relay_count mesh-node-d)
  docker stop mesh-node-b >/dev/null
  sleep 5
  ok=0
  for i in $(seq 1 40); do
    if ping_ca; then
      if [ "$(relay_count mesh-node-d)" -gt "$D_RELAYED_BEFORE" ]; then
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
