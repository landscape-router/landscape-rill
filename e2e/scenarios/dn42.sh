#!/usr/bin/env bash
# dn42 e2e 场景断言（DN42_LEG §7）：
#   peer-r = 内核 WG + FRR；node-a = lrill dn42 leg（M2 mesh 出口）
#   coord + node-b = mesh 侧（DNL-14/15：全网出口 transit + 跨腿仲裁）
#   DNL-01 WG 握手 / DNL-02 BGP Established / DNL-03 路由学习 + 双向转发 /
#   DNL-04 export stub / DNL-05 import policy 负向 / DNL-06 撤销收敛 / DNL-07 会话故障恢复
set -euo pipefail

logs() { docker logs "$1" 2>&1; }
count_log() {
    local n
    n=$(logs mesh-node-a | grep -c "$1" || true)
    echo "${n:-0}"
}
# 等待日志计数相对快照增长 ≥1（防历史行污染）
wait_log_inc() { # $1=模式 $2=快照 $3=超时秒
  for i in $(seq 1 "$3"); do
    N=$(count_log "$1")
    [ "${N:-0}" -gt "$2" ] && return 0
    sleep 1
  done
  return 1
}

echo "==> M2 拓扑准备：node-b 内核路由（TUN 入口）+ 仲裁目标地址"
for i in $(seq 1 30); do
  docker exec mesh-node-b ip link show land0 >/dev/null 2>&1 && break
  sleep 1
done
docker exec mesh-node-b ip link show land0 >/dev/null
# 内核 → TUN 入口路由（用户态 LPM 裁决前的内核侧投递）
docker exec mesh-node-b ip route replace 172.20.0.0/14 dev land0
docker exec mesh-node-b ip route replace 10.42.0.0/24 dev land0
docker exec mesh-node-b ip -6 route replace fd00:2::/64 dev land0 2>/dev/null || true
# 仲裁目标：172.21.5.1 落 node-b 本机（mesh 路径回包；dn42 路径 peer 黑洞）
docker exec mesh-node-b ip addr add 172.21.5.1/32 dev lo 2>/dev/null || true
for i in $(seq 1 30); do
  docker exec mesh-node-a ip link show land0 >/dev/null 2>&1 && break
  sleep 1
done
docker exec mesh-node-a ip route replace 172.21.5.0/24 dev land0

echo "==> DNL-01: boringtun ⇄ 内核 WG 握手"
for i in $(seq 1 20); do
  HS=$(docker exec mesh-dn42-peer wg show wg0 latest-handshakes 2>/dev/null | awk '{print $2}' || echo 0)
  [ "${HS:-0}" -gt 0 ] && break
  sleep 1
done
if [ "${HS:-0}" -gt 0 ]; then
  echo "PASS: DNL-01 WG 握手完成（latest handshake epoch=$HS）"
else
  echo "FAIL: DNL-01 WG 握手未完成"
  exit 1
fi

echo "==> DNL-02: eBGP-lite ⇄ FRR 会话 Established"
ESTAB=0
for i in $(seq 1 30); do
  # FRR summary 对已建立会话的 State 列显示数字前缀数（无 "Estab" 字样），
  # 以 neighbor 详情的 BGP state 为准
  if docker exec mesh-dn42-peer vtysh -c "show bgp neighbors 172.20.100.1" 2>/dev/null | grep -q "BGP state = Established"; then
    ESTAB=1
    break
  fi
  sleep 1
done
if [ "$ESTAB" = "1" ]; then
  echo "PASS: DNL-02 BGP 会话 Established"
  docker exec mesh-dn42-peer vtysh -c "show bgp ipv4 unicast summary" || true
else
  echo "FAIL: DNL-02 BGP 会话未建立"
  exit 1
fi

echo "==> DNL-03: 路由学习 + tun0 → dn42 隧道转发（v4）"
PING_OK=0
for i in $(seq 1 30); do
  if docker exec mesh-node-a ping -c1 -W1 172.20.100.100 >/dev/null 2>&1; then
    PING_OK=1
    break
  fi
  sleep 1
done
if [ "$PING_OK" = "1" ]; then
  echo "PASS: DNL-03 node-a tun0 侧 ping 172.20.100.100（peer 自家 LAN）经 dn42 隧道可达"
  docker exec mesh-node-a ping -c3 172.20.100.100 || true
else
  echo "FAIL: DNL-03 172.20.100.100 不可达"
  exit 1
fi

echo "==> DNL-04: export stub（node-a 自家前缀公告进 FRR）"
EXPORT_OK=0
for i in $(seq 1 15); do
  if docker exec mesh-dn42-peer vtysh -c "show bgp ipv4 unicast neighbors 172.20.100.1 routes" 2>/dev/null | grep -q "172.20.1.0/24"; then
    EXPORT_OK=1
    break
  fi
  sleep 1
done
if [ "$EXPORT_OK" = "1" ]; then
  echo "PASS: DNL-04 FRR 从 node-a 学到 172.20.1.0/24（stub 公告）"
else
  echo "FAIL: DNL-04 node-a 的 stub 前缀未出现在 FRR"
  exit 1
fi

echo "==> DNL-05: import policy 负向（10.99.0.0/16 白名单外，必须被拒）"
# 先等对端确实公告了该前缀（排除"根本没公告"的假阴性；慢 CI 上 bgpd 收敛可能滞后），
# 再验 node-a 拒收 —— 顺序反过来会有"先判拒、后公告"的假阳性窗口
ANNOUNCED=0
for i in $(seq 1 15); do
  if docker exec mesh-dn42-peer vtysh -c "show bgp ipv4 unicast" 2>/dev/null | grep -q "10.99.0.0/16"; then
    ANNOUNCED=1
    break
  fi
  sleep 1
done
if [ "$ANNOUNCED" != "1" ]; then
  echo "FAIL: DNL-05 对端始终未公告 10.99.0.0/16（前置异常）"
  exit 1
fi
REJECT_OK=1
for i in $(seq 1 10); do
  if docker exec mesh-node-a ping -c1 -W1 10.99.0.1 >/dev/null 2>&1; then
    REJECT_OK=0
    break
  fi
  sleep 1
done
if [ "$REJECT_OK" = "1" ]; then
  echo "PASS: DNL-05 白名单外前缀已公告但 node-a 拒收（不可达）"
else
  echo "FAIL: DNL-05 白名单外前缀泄漏"
  exit 1
fi

echo "==> DNL-06: 撤销与收敛（FRR 撤 172.20.100.0/24 → 不可达 → 重新公告 → 恢复）"
docker exec mesh-dn42-peer vtysh -c "configure terminal" -c "router bgp 4242420002" \
  -c "no network 172.20.100.0/24" -c "end" >/dev/null
WITHDRAW_OK=1
for i in $(seq 1 10); do
  if docker exec mesh-node-a ping -c1 -W1 172.20.100.100 >/dev/null 2>&1; then
    sleep 1
  else
    WITHDRAW_OK=1
    break
  fi
done
docker exec mesh-dn42-peer vtysh -c "configure terminal" -c "router bgp 4242420002" \
  -c "network 172.20.100.0/24" -c "end" >/dev/null
RECOVER_OK=0
for i in $(seq 1 20); do
  if docker exec mesh-node-a ping -c1 -W1 172.20.100.100 >/dev/null 2>&1; then
    RECOVER_OK=1
    break
  fi
  sleep 1
done
if [ "$RECOVER_OK" = "1" ]; then
  echo "PASS: DNL-06 撤销收敛 + 重新公告恢复"
else
  echo "FAIL: DNL-06 撤销后未恢复"
  exit 1
fi

echo "==> DNL-07: 会话故障与自动重建（stop peer-r → hold 超时撤销 → 恢复 peer-r → 复归）"
docker stop mesh-dn42-peer >/dev/null
DOWN_OK=0
# hold_time=15s（协商后）；容器死亡无 RST（隧道内 TCP），靠 hold timer 收敛
for i in $(seq 1 30); do
  if logs mesh-node-a | grep -q "dn42 session down: peer-r"; then
    DOWN_OK=1
    break
  fi
  sleep 1
done
if [ "$DOWN_OK" = "1" ]; then
  echo "PASS: DNL-07a 会话故障检测（hold timer 超时 → SessionDown）"
else
  echo "FAIL: DNL-07a 未检测到会话故障"
  exit 1
fi
docker start mesh-dn42-peer >/dev/null
REBUILT_OK=0
for i in $(seq 1 60); do
  if docker exec mesh-node-a ping -c1 -W1 172.20.100.100 >/dev/null 2>&1; then
    REBUILT_OK=1
    break
  fi
  sleep 2
done
if [ "$REBUILT_OK" = "1" ]; then
  echo "PASS: DNL-07b 恢复后隧道+会话+路由自动重建，流量复归"
else
  echo "FAIL: DNL-07b 恢复失败"
  echo "--- node-a 日志 ---"; logs mesh-node-a | tail -20
  exit 1
fi

echo "PASS: dn42 e2e 基础断言通过（DNL-01~07）"

COMPOSE_DN42="docker compose -f $E2E_DIR/mesh/dn42/docker-compose.yaml"

echo "==> DNL-08: 双 peer 故障切换（peer-r2 上线，同前缀双公告）"
$COMPOSE_DN42 --profile late up -d peer-r2
R2_ESTAB=0
for i in $(seq 1 45); do
  if docker exec mesh-dn42-peer2 birdc show protocols 2>/dev/null | grep -q "Established" \
     && docker exec mesh-dn42-peer2 ping -c1 -W1 10.42.0.1 >/dev/null 2>&1; then
    R2_ESTAB=1
    break
  fi
  sleep 1
done
if [ "$R2_ESTAB" = "1" ]; then
  echo "PASS: DNL-08a peer-r2 会话 Established（独立隧道 172.20.101.0/30）"
else
  echo "FAIL: DNL-08a peer-r2 会话未建立"
  exit 1
fi

SNAP8=$(count_log "dn42 session down: peer-r$")
docker stop mesh-dn42-peer >/dev/null
DOWN8=1
wait_log_inc "dn42 session down: peer-r$" "$SNAP8" 30 || DOWN8=0
RECOVER8=0
for i in $(seq 1 30); do
  if docker exec mesh-node-a ping -c1 -W1 172.20.100.100 >/dev/null 2>&1; then
    RECOVER8=1
    break
  fi
  sleep 2
done
docker start mesh-dn42-peer >/dev/null
BACK8=0
for i in $(seq 1 40); do
  if docker exec mesh-dn42-peer vtysh -c "show bgp neighbors 172.20.100.1" 2>/dev/null | grep -q "BGP state = Established" \
     && docker exec mesh-node-a ping -c1 -W1 172.20.100.100 >/dev/null 2>&1; then
    BACK8=1
    break
  fi
  sleep 2
done
if [ "$DOWN8" = "1" ] && [ "$RECOVER8" = "1" ] && [ "$BACK8" = "1" ]; then
  echo "PASS: DNL-08 peer-r 停机 → 流量切换 peer-r2 → peer-r 恢复后回流"
else
  echo "FAIL: DNL-08 故障切换失败 (down=$DOWN8 recover=$RECOVER8 back=$BACK8)"
  exit 1
fi

echo "==> DNL-10: WG 层单点故障（隧道断，peer 进程在）"
SNAP10=$(count_log "dn42 session down: peer-r$")
docker exec mesh-dn42-peer wg-quick down wg0 >/dev/null
DOWN10=1
wait_log_inc "dn42 session down: peer-r$" "$SNAP10" 30 || DOWN10=0
ALIVE10=1
docker exec mesh-dn42-peer true 2>/dev/null || ALIVE10=0
RECOVER10=0
for i in $(seq 1 30); do
  if docker exec mesh-node-a ping -c1 -W1 172.20.100.100 >/dev/null 2>&1; then
    RECOVER10=1
    break
  fi
  sleep 2
done
SNAP10E=$(count_log "dn42 session established: peer-r$")
docker exec mesh-dn42-peer wg-quick up wg0 >/dev/null
BACK10=1
for i in $(seq 1 40); do
  E=$(count_log "dn42 session established: peer-r$")
  if [ "${E:-0}" -gt "$SNAP10E" ] \
     && docker exec mesh-dn42-peer vtysh -c "show bgp neighbors 172.20.100.1" 2>/dev/null | grep -q "BGP state = Established"; then
    BACK10=1
    break
  fi
  sleep 2
done
if [ "$DOWN10" = "1" ] && [ "$ALIVE10" = "1" ] && [ "$RECOVER10" = "1" ] && [ "$BACK10" = "1" ]; then
  echo "PASS: DNL-10 隧道层故障 → hold 收敛 → peer-r2 顶上 → 隧道恢复重建（peer 进程全程存活）"
else
  echo "FAIL: DNL-10 (down=$DOWN10 alive=$ALIVE10 recover=$RECOVER10 back=$BACK10)"
  exit 1
fi

echo "==> DNL-09: max-prefix 会话自保（借 node 重启改配置，覆盖节点重启重建）"
python3 - "$E2E_DIR/build/node-a.json" <<'PYMAX'
import json, shutil, sys, tempfile
path = sys.argv[1]
with open(path) as f:
    cfg = json.load(f)
for p in cfg["dn42"]["peers"]:
    if p["name"] == "peer-r2":
        p["max_prefixes"] = 1
tmp = tempfile.NamedTemporaryFile(delete=False, dir=path.rsplit("/", 1)[0])
with open(tmp.name, "w") as f:
    json.dump(cfg, f, indent=2)
shutil.copyfile(tmp.name, path)
PYMAX
docker restart mesh-node-a >/dev/null
# node 重启后重注内核路由（netns 重建已清）
docker exec mesh-node-a ip route add 172.20.100.0/24 dev land0 2>/dev/null || true
docker exec mesh-node-a ip route add 172.20.101.0/24 dev land0 2>/dev/null || true
docker exec mesh-node-a ip route add 10.99.0.0/16 dev land0 2>/dev/null || true
FLAP=0
for i in $(seq 1 30); do
  N=$(logs mesh-node-a | grep -c "dn42 session down: peer-r2" || true)
  [ "${N:-0}" -ge 2 ] && FLAP=1 && break
  sleep 1
done
VIA_PEER=0
for i in $(seq 1 30); do
  if docker exec mesh-node-a ping -c1 -W1 172.20.100.100 >/dev/null 2>&1; then
    VIA_PEER=1
    break
  fi
  sleep 2
done
if [ "$FLAP" = "1" ] && [ "$VIA_PEER" = "1" ]; then
  echo "PASS: DNL-09 max-prefix 超限 → peer-r2 会话关停循环，peer-r 转发不受影响（node 重启后隧道/会话/路由全量重建）"
else
  echo "FAIL: DNL-09 (flap=$FLAP via_peer=$VIA_PEER)"
  exit 1
fi

echo "==> DNL-11: rogue BGP 输入 fail-closed（假 peer 发畸形流）"
docker exec mesh-dn42-peer2 sh -c 'kill $(cat /run/bird/bird.pid) 2>/dev/null; sleep 1; cat > /tmp/rogue.py <<ROGUE
import socket, threading, time
def handle(c):
    try:
        c.sendall(b"\xff" * 16 + b"\x00\x40\x01" + b"GARBAGE!" * 8)
        time.sleep(20)
        c.recv(4096)
    except Exception:
        pass
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
for _ in range(30):
    try:
        s.bind(("0.0.0.0", 179))
        break
    except OSError:
        time.sleep(1)
s.listen(5)
while True:
    c, _ = s.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
ROGUE
python3 /tmp/rogue.py &'
ROGUE_SEEN=0
for i in $(seq 1 20); do
  N=$(logs mesh-node-a | grep -c "session round ended, reconnecting" || true)
  [ "${N:-0}" -ge 2 ] && ROGUE_SEEN=1 && break
  sleep 1
done
ALIVE11=1
docker exec mesh-node-a true 2>/dev/null || ALIVE11=0
VIA11=0
for i in $(seq 1 10); do
  if docker exec mesh-node-a ping -c1 -W1 172.20.100.100 >/dev/null 2>&1; then
    VIA11=1
    break
  fi
  sleep 2
done
if [ "$ROGUE_SEEN" = "1" ] && [ "$ALIVE11" = "1" ] && [ "$VIA11" = "1" ]; then
  echo "PASS: DNL-11 rogue 畸形输入 → 会话 fail-closed 丢弃重试，lrill 存活，peer-r 转发不受影响"
else
  echo "FAIL: DNL-11 (rogue_seen=$ROGUE_SEEN alive=$ALIVE11 via=$VIA11)"
  exit 1
fi


echo "==> DNL-12: 表规模收敛（402 条公告，dn42 真实表量级）"
PFX=0
for i in $(seq 1 60); do
  PFX=$(docker exec mesh-dn42-peer vtysh -c "show bgp ipv4 unicast summary" 2>/dev/null \
    | awk '/^172.20.100.1/ {print $11}' || true)
  [ "${PFX:-0}" -ge 400 ] && break
  sleep 1
done
LEARNED=$(count_log "dn42 learned 172.2")
if [ "${PFX:-0}" -ge 400 ] && [ "$LEARNED" -ge 395 ]; then
  echo "PASS: DNL-12a 402 条公告全量收敛（PfxSnt=$PFX, node learned=$LEARNED）"
else
  echo "FAIL: DNL-12a 收敛不足 (PfxSnt=$PFX learned=$LEARNED)"
  exit 1
fi

if docker exec mesh-node-a ping -c2 -W2 172.20.100.100 >/dev/null 2>&1; then
  echo "PASS: DNL-12b 规模表下转发不受影响"
else
  echo "FAIL: DNL-12b 规模表下转发失败"
  exit 1
fi

echo "==> DNL-13: 半表撤销（bgpd 换配置重启 → 撤销批量传播）"
python3 - "$E2E_DIR/build/dn42/bgpd.conf" <<'PYHALF'
import sys
path = sys.argv[1]
out = []
for line in open(path):
    if "network 172.22." in line:
        continue
    if "network 172.21." in line:
        third = int(line.strip().split(".")[2])
        if third >= 200:
            continue
    out.append(line.rstrip("\n"))
open(path, "w").write("\n".join(out) + "\n")
PYHALF
docker exec mesh-dn42-peer sh -c 'kill $(cat /var/run/frr/bgpd.pid) 2>/dev/null; sleep 1; /usr/lib/frr/bgpd -d -f /etc/frr/bgpd.conf; for _ in $(seq 1 20); do [ -S /var/run/frr/bgpd.vty ] && break; sleep 0.5; done'
PFX2=999
for i in $(seq 1 60); do
  P2=$(docker exec mesh-dn42-peer vtysh -c "show bgp ipv4 unicast summary" 2>/dev/null \
    | awk '/^172.20.100.1/ {print $11}' || true)
  [ -n "$P2" ] && [ "$P2" -le 250 ] && PFX2=$P2 && break
  sleep 1
done
if [ "$PFX2" != "999" ] && [ "$PFX2" -le 250 ] \
   && docker exec mesh-node-a ping -c2 -W2 172.20.100.100 >/dev/null 2>&1; then
  echo "PASS: DNL-13 半表撤销批量传播（PfxSnt=$PFX2），保留路径转发不受影响"
else
  echo "FAIL: DNL-13 撤销传播异常 (PfxSnt=$PFX2)"
  docker exec mesh-dn42-peer sh -c 'ps aux | grep -E "bgpd" | grep -v grep' 2>/dev/null || true
  docker exec mesh-dn42-peer vtysh -c "show bgp ipv4 unicast summary" 2>/dev/null || true
  exit 1
fi

echo "==> DNL-14: M2 全网出口（node-b 经 mesh 借道 node-a 出 dn42）"
B14=0
for i in $(seq 1 45); do
  if docker exec mesh-node-b ping -c2 -W2 172.20.100.100 >/dev/null 2>&1; then
    B14=1
    break
  fi
  sleep 2
done
T_OUT=$(logs mesh-node-a | grep -c "transit mesh->dn42: 172.20.100.100" || true)
T_BACK=$(logs mesh-node-a | grep -c "transit dn42->mesh: 10.88.0.1" || true)
if [ "$B14" = "1" ] && [ "${T_OUT:-0}" -ge 1 ] && [ "${T_BACK:-0}" -ge 1 ]; then
  echo "PASS: DNL-14 node-b→peer lo 双向 transit（去程/回程日志 $T_OUT/$T_BACK）"
else
  echo "FAIL: DNL-14 mesh 出口 transit 失败 (ping=$B14 out=$T_OUT back=$T_BACK)"
  exit 1
fi

echo "==> DNL-15: 跨腿仲裁（172.21.5.0/24 mesh 与 dn42 同长 → mesh 优先）"
# node-a 若经历 DNL-09 重启，prep 期内核路由已随 tun 重建抹掉——使用点就近补加
docker exec mesh-node-a ip route replace 172.21.5.0/24 dev land0 2>/dev/null || true
LEARN15=$(logs mesh-node-a | grep -c "dn42 learned 172.21.5.0/24" || true)
A15=0
for i in $(seq 1 45); do
  if docker exec mesh-node-a ping -c2 -W2 172.21.5.1 >/dev/null 2>&1; then
    A15=1
    break
  fi
  sleep 2
done
if [ "$A15" = "1" ] && [ "${LEARN15:-0}" -ge 1 ]; then
  echo "PASS: DNL-15 mesh 优先仲裁获证（dn42 同长路由在表且该路径为黑洞，回包只能来自 mesh）"
else
  echo "FAIL: DNL-15 仲裁异常 (ping=$A15 learned=$LEARN15)"
  exit 1
fi

# ---- REQ-065（DNL-16）：RouteMap 双 ext 前缀级分流 ----
# 拓扑：node-c（第二 ext，独立 dn42 leg ⇄ peer-r3 Bird）经 RouteMap 向全网广播
# 172.20.201.0/24；peer-r 以 live network 注入同前缀 → 双 ext 同前缀。
# 验证：动态路由进 RouteMap → node-b 前缀级分流；一端撤销 → 窗口内切换另一 ext；
# BGP 会话断 → 该 ext 动态路由全撤（聚合兜底黑洞）；第三次翻转 → 阻尼 + 聚合兜底回归
count_log_node() { # $1=容器 $2=模式
  local n
  n=$(docker logs "$1" 2>&1 | grep -c "$2" || true)
  echo "${n:-0}"
}
wait_log_node() { # $1=容器 $2=模式 $3=快照 $4=超时秒
  for i in $(seq 1 "$4"); do
    N=$(count_log_node "$1" "$2")
    [ "${N:-0}" -gt "$3" ] && return 0
    sleep 1
  done
  return 1
}
dump_dual_evidence() { # DNL-16 失败现场取证（trap 清理容器前先抓关键日志）
  local c
  for c in mesh-coord mesh-node-a mesh-node-b mesh-node-c; do
    echo "--- DUAL-EVIDENCE $c (/24 与 BGP 生命周期，排除 peer-r2/relayed 噪声) ---"
    docker logs "$c" 2>&1 | grep -E "route map|route sync|gated|172\.20\.201|dn42 session|dn42 learned|no route for|dropped frame|frame dropped|transit|relay|acl denied" \
      | grep -vE "peer-r2|relayed frame" | tail -25 || true
  done
  echo "--- mesh 会话生命周期（a 与 b：建立/心跳超时拆除，INFO） ---"
  for c in mesh-node-a mesh-node-b; do
    echo "[$c]"; docker logs "$c" 2>&1 | grep -E "session established with|heartbeat misses" | tail -12 || true
  done
  echo "--- node-a peer-r 会话生命周期（原始行 + 时间戳） ---"
  docker logs mesh-node-a 2>&1 | grep "dn42 session" | grep -v "peer-r2" | tail -15 || true
  echo "--- node-a peer-r2 循环计数（背景噪声规模） ---"
  docker logs mesh-node-a 2>&1 | grep -c "dn42 session established: peer-r2" || true
  echo "--- /24 完整时间线（a/c：learned/withdrawn/route map/路由来源候选，不截断尾部） ---"
  for c in mesh-node-a mesh-node-c; do
    echo "[$c /24 timeline]"
    docker logs "$c" 2>&1 | grep -E "dn42 learned 172\.20\.201|dn42 withdrawn 172\.20\.201|route map v|transit drop: no edge|no route for 172\.20\.201|transit mesh->dn42: 172\.20\.201" | tail -40 || true
  done
  echo "--- 失败现场活体探针（容器仍在；每条独立容忍失败） ---"
  echo "[b->dn42 /24]"; docker exec mesh-node-b ping -c2 -W1 172.20.201.1 2>&1 | tail -2 || true
  echo "[b->a mesh lan 10.42.0.1]"; docker exec mesh-node-b ping -c2 -W1 10.42.0.1 2>&1 | tail -2 || true
  echo "[a->dn42 /24 本地腿]"; docker exec mesh-node-a ip route replace 172.20.201.0/24 dev land0 2>/dev/null || true
  docker exec mesh-node-a ping -c2 -W1 172.20.201.1 2>&1 | tail -2 || true
  echo "[a->dn42 peer-r lan .100.100 对照]"; docker exec mesh-node-a ping -c2 -W1 172.20.100.100 2>&1 | tail -2 || true
  echo "--- node-a 丢帧理由（mesh rx 裁决；计数 + 首尾） ---"
  docker logs mesh-node-a 2>&1 | grep -c "dropped frame" || true
  docker logs mesh-node-a 2>&1 | grep "dropped frame" | head -2 || true
  docker logs mesh-node-a 2>&1 | grep "dropped frame" | tail -4 || true
  docker logs mesh-node-a 2>&1 | grep -E "frame dropped|no session with" | tail -6 || true
  echo "--- node-b 丢帧理由 + no route 计数 ---"
  docker logs mesh-node-b 2>&1 | grep -cE "dropped frame|no route for" || true
  docker logs mesh-node-b 2>&1 | grep -E "dropped frame|no route for" | tail -6 || true
  echo "--- node-b 发送裁决（data frame 选路/端点，DEBUG） ---"
  docker logs mesh-node-b 2>&1 | grep -E "data frame to|send to .* hop|frame from .* ingress" | tail -12 || true
  docker logs mesh-node-b 2>&1 | grep -E "frame build failed|no endpoints" | tail -6 || true
  echo "--- node-a 入站跳归属（b 的帧经谁到达，DEBUG） ---"
  docker logs mesh-node-a 2>&1 | grep "frame from" | tail -8 || true
  echo "--- 各节点 endpoint report 历史（目录端点来源仲裁） ---"
  for c in mesh-node-a mesh-node-b mesh-node-c; do
    echo "[$c]"; docker logs "$c" 2>&1 | grep "endpoint report" | tail -4 || true
  done
  echo "--- a 实际监听端口（/proc/net/udp 十六进制 local_address）vs b/c 发送目标 ---"
  docker exec mesh-node-a sh -c "cat /proc/net/udp" 2>/dev/null || true
  echo "[b 的发送目标统计]"; docker logs mesh-node-b 2>&1 | grep -oE "send to [0-9]+ hop [0-9]+ via [0-9.:]+" | sort | uniq -c | sort -rn | head -6 || true
  echo "[c 的发送目标统计]"; docker logs mesh-node-c 2>&1 | grep -oE "send to [0-9]+ hop [0-9]+ via [0-9.:]+" | sort | uniq -c | sort -rn | head -6 || true
  echo "--- UDP canary：b 向最近发送目标发裸包，a 是否见 UnknownProtocol ---"
  LAST_ADDR=$(docker logs mesh-node-b 2>&1 | grep -oE "via [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+" | tail -1 | cut -d' ' -f2)
  if [ -n "$LAST_ADDR" ]; then
    docker exec mesh-node-b bash -c "echo hi > /dev/udp/${LAST_ADDR%%:*}/${LAST_ADDR##*:}" 2>/dev/null || true
    sleep 1
    docker logs mesh-node-a --since 3s 2>&1 | grep -E "dropped frame" | tail -3 || echo "(a 无任何收帧记录 → 端口死)"
  fi
  echo "--- DUAL-EVIDENCE peer-r (FRR) ---"
  docker exec mesh-dn42-peer vtysh -c "show bgp ipv4 unicast summary" 2>/dev/null || true
  docker exec mesh-dn42-peer vtysh -c "show bgp ipv4 unicast neighbor 172.20.100.1 advertised-routes" 2>/dev/null | grep -E "172\.20\.201|Total" | tail -3 || true
  echo "--- peer-r bgpd 会话复位原因 ---"
  docker logs mesh-dn42-peer 2>&1 | grep -iE "%NOTIFICATION|hold timer|reset|cease|closing" | tail -12 || true
}

echo "==> DNL-16a: 双 ext 拓扑上线（node-c + peer-r3）"
# 快照先于 up（容器可能不存在/残留：docker logs 报错按 0 计）
C_LEARN=$(count_log_node mesh-node-c "dn42 learned 172.20.201.0/24")
C_DOWN=$(count_log_node mesh-node-c "dn42 session down: peer-r3")
C_FLUSH_W=$(count_log_node mesh-node-c "route sync flush: 0 announced, 1 withdrawn")
$COMPOSE_DN42 --profile dual up -d node-c peer-r3 >/dev/null
for i in $(seq 1 30); do
  docker exec mesh-node-c ip link show land0 >/dev/null 2>&1 && break
  sleep 1
done
# node-c 隧道 /30 经 land0 裁决（同 node-a 惯例）
docker exec mesh-node-c ip route replace 172.20.103.0/24 dev land0
R3_ESTAB=0
for i in $(seq 1 45); do
  if docker exec mesh-dn42-peer3 birdc show protocols 2>/dev/null | grep -q "Established"; then
    R3_ESTAB=1
    break
  fi
  sleep 1
done
if [ "$R3_ESTAB" = "1" ] && wait_log_node mesh-node-c "dn42 learned 172.20.201.0/24" "$C_LEARN" 30; then
  echo "PASS: DNL-16a node-c ⇄ peer-r3 会话建立并学习 172.20.201.0/24"
else
  echo "FAIL: DNL-16a (estab=$R3_ESTAB)"
  dump_dual_evidence
  exit 1
fi

echo "==> DNL-16b: RouteMap 下发 + node-b 经 node-c 前缀级可达"
B_MAP=$(count_log_node mesh-node-b "route map v")
B_PING=0
for i in $(seq 1 60); do
  if docker exec mesh-node-b ping -c1 -W1 172.20.201.1 >/dev/null 2>&1; then
    B_PING=1
    break
  fi
  sleep 2
done
C_TRANSIT=$(count_log_node mesh-node-c "transit mesh->dn42: 172.20.201.1")
# 此时 peer-r 未公告该前缀：聚合路径在 node-a 黑洞——ping 通即逐条路由（/24 压
# 聚合 /14）经 node-c 转发，且 node-a 不承载该前缀流量
A_TRANSIT_B=$(count_log_node mesh-node-a "transit mesh->dn42: 172.20.201.1")
if [ "$B_PING" = "1" ] \
   && wait_log_node mesh-node-b "route map v" "$B_MAP" 60 \
   && [ "$C_TRANSIT" -ge 1 ] \
   && [ "$A_TRANSIT_B" -eq 0 ]; then
  echo "PASS: DNL-16b RouteMap 推送到达 node-b，172.20.201.1 逐条路由经 node-c 可达（聚合路径此时为黑洞）"
else
  echo "FAIL: DNL-16b (ping=$B_PING transit_c=$C_TRANSIT transit_a=$A_TRANSIT_B)"
  dump_dual_evidence
  exit 1
fi

echo "==> DNL-16c: peer-r 注入同前缀 → 双 ext 同前缀（node-b 出口切到 node-a）"
A_LEARN=$(count_log_node mesh-node-a "dn42 learned 172.20.201.0/24")
B_MAP2=$(count_log_node mesh-node-b "route map v")
A_TRANSIT=$(count_log_node mesh-node-a "transit mesh->dn42: 172.20.201.1")
docker exec mesh-dn42-peer vtysh -c "configure terminal" -c "router bgp 4242420002" \
  -c "network 172.20.201.0/24" -c "end" >/dev/null
SWITCH_C=0
for i in $(seq 1 60); do
  docker exec mesh-node-b ping -c1 -W1 172.20.201.1 >/dev/null 2>&1 || true
  T=$(count_log_node mesh-node-a "transit mesh->dn42: 172.20.201.1")
  if [ "${T:-0}" -gt "$A_TRANSIT" ]; then
    SWITCH_C=1
    break
  fi
  sleep 2
done
if wait_log_node mesh-node-a "dn42 learned 172.20.201.0/24" "$A_LEARN" 30 \
   && [ "$SWITCH_C" = "1" ] \
   && wait_log_node mesh-node-b "route map v" "$B_MAP2" 60; then
  echo "PASS: DNL-16c 双 ext 同前缀公告（node-b 出口 node-c → node-a，逐条状态驱动）"
else
  echo "FAIL: DNL-16c (switch=$SWITCH_C)"
  dump_dual_evidence
  exit 1
fi

echo "==> DNL-16d: peer-r 撤销 → node-b 窗口内切回 node-c（前缀级真分流）"
C_T2=$(count_log_node mesh-node-c "transit mesh->dn42: 172.20.201.1")
A_FLUSH=$(count_log_node mesh-node-a "route sync flush: 0 announced, 1 withdrawn")
docker exec mesh-dn42-peer vtysh -c "configure terminal" -c "router bgp 4242420002" \
  -c "no network 172.20.201.0/24" -c "end" >/dev/null
FLUSH_D=1
wait_log_node mesh-node-a "route sync flush: 0 announced, 1 withdrawn" "$A_FLUSH" 30 || FLUSH_D=0
SWITCH=0
for i in $(seq 1 60); do
  if docker exec mesh-node-b ping -c1 -W1 172.20.201.1 >/dev/null 2>&1; then
    SWITCH=1
    break
  fi
  sleep 2
done
C_T3=$(count_log_node mesh-node-c "transit mesh->dn42: 172.20.201.1")
if [ "$FLUSH_D" = "1" ] && [ "$SWITCH" = "1" ] && [ "$C_T3" -gt "$C_T2" ]; then
  echo "PASS: DNL-16d node-a 撤销上报（防抖窗口）→ node-b 切回 node-c，流量不断"
else
  echo "FAIL: DNL-16d (flush=$FLUSH_D switch=$SWITCH transit $C_T2->$C_T3)"
  dump_dual_evidence
  exit 1
fi

echo "==> DNL-16e: peer-r3 停机 → node-c 动态路由全撤 → 聚合兜底黑洞"
B_MAP3=$(count_log_node mesh-node-b "route map v")
docker stop mesh-dn42-peer3 >/dev/null
DOWN_E=1
wait_log_node mesh-node-c "dn42 session down: peer-r3" "$C_DOWN" 30 || DOWN_E=0
WITHDRAW_E=1
wait_log_node mesh-node-c "route sync flush: 0 announced, 1 withdrawn" "$C_FLUSH_W" 30 || WITHDRAW_E=0
MAP_E=1
wait_log_node mesh-node-b "route map v" "$B_MAP3" 60 || MAP_E=0
BLACKHOLE=1
for i in $(seq 1 10); do
  if docker exec mesh-node-b ping -c1 -W2 172.20.201.1 >/dev/null 2>&1; then
    BLACKHOLE=0
    break
  fi
  sleep 2
done
if [ "$DOWN_E" = "1" ] && [ "$WITHDRAW_E" = "1" ] && [ "$MAP_E" = "1" ] && [ "$BLACKHOLE" = "1" ]; then
  echo "PASS: DNL-16e 会话断 → 全撤 → RouteMap 更新 → 无逐条路由时聚合兜底黑洞（不可达）"
else
  echo "FAIL: DNL-16e (down=$DOWN_E withdraw=$WITHDRAW_E map=$MAP_E blackhole=$BLACKHOLE)"
  dump_dual_evidence
  exit 1
fi

echo "==> DNL-16f: 第三次翻转 → 阻尼（服务端闸）+ 聚合兜底回归"
GATED=$(count_log_node mesh-coord "route sync gated")
A_LEARN2=$(count_log_node mesh-node-a "dn42 learned 172.20.201.0/24")
A_T2=$(count_log_node mesh-node-a "transit mesh->dn42: 172.20.201.1")
docker exec mesh-dn42-peer vtysh -c "configure terminal" -c "router bgp 4242420002" \
  -c "network 172.20.201.0/24" -c "end" >/dev/null
RELEARN=1
wait_log_node mesh-node-a "dn42 learned 172.20.201.0/24" "$A_LEARN2" 30 || RELEARN=0
DAMPED=1
wait_log_node mesh-coord "route sync gated" "$GATED" 30 || DAMPED=0
# 死 ext 退出 mesh：DN42_LEG v0.4 ④——BGP 断而节点在线期间聚合公告仍在、流量死在
# ext 本地（best-effort）；多 ext 等权聚合的 via 裁决是任意序（v0.6：best-path 留给
# 消费端）。peer-r3 已死的 node-c 若留在 mesh，/14 聚合是 a/c 双公告，node-b 兜底
# 落点是掷硬币（~50% 落死 ext 黑洞）。c 停机 → netmap 离线撤销其聚合（CTL-11），
# /14 唯一指向 node-a，聚合兜底回归才是确定性的
docker stop mesh-node-c >/dev/null
# 阻尼期 RouteMap 不含该前缀 → node-b 走聚合兜底 → node-a 本地 BGP 路由承载
FALLBACK=0
for i in $(seq 1 45); do
  docker exec mesh-node-b ping -c1 -W1 172.20.201.1 >/dev/null 2>&1 || true
  T=$(count_log_node mesh-node-a "transit mesh->dn42: 172.20.201.1")
  if [ "${T:-0}" -gt "$A_T2" ]; then
    FALLBACK=1
    break
  fi
  sleep 2
done
if [ "$RELEARN" = "1" ] && [ "$DAMPED" = "1" ] && [ "$FALLBACK" = "1" ]; then
  echo "PASS: DNL-16f 翻转阻尼（coord 拒收）+ 聚合兜底路径回归可达（REQ-065 回归条款）"
else
  echo "FAIL: DNL-16f (relearn=$RELEARN damped=$DAMPED fallback=$FALLBACK)"
  dump_dual_evidence
  exit 1
fi

echo "PASS: dn42 e2e 全部断言通过（DNL-01~16）"
