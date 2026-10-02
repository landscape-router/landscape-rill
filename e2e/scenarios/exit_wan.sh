# exit_wan 场景（E2E-05 mesh 出口，REQ-071，ROUTE_ENGINE §5/§8）：
# 拓扑：node-c（capabilities=0x08 纯 exit）双挂 mesh + inet（192.168.247.0/24，主机 .100）；
# node-b default_route_preference=["mesh"]，内核 inet 前缀路由指向 land0（裁决进引擎）
# 断言：
# ① 准入 fail-closed：能力位已声明但 exits.allow 空 → b ping inet 失败
#   （解析器无候选 → 引擎 no route 丢弃，非内核无路由）
# ② SIGHUP 运行时授权 allow:[c_id]（node_id 注册顺序竞态 → 从 c 日志运行时发现）
#   → netmap exit 标记（版本 bump）→ b 借道 c 双栈通（c ingress 增长 = 转发证据）
# ③ 出口停机 → 租约过期（60s）→ netmap 离线 → 解析器候选清空 → ping 断
#   （无其他 exit 兜底，§4 链末位回退；netmap 版本再次 bump = 离线转移证据）

ingress_count() { logs "$1" | grep -c 'frame from .* ingress' || true; }
netmap_ver() { logs mesh-node-b | grep 'netmap v' | tail -1 | sed 's/.*netmap v\([0-9]*\):.*/\1/'; }

echo "==> exit_wan 阶段 1/3：注册 + 准入 fail-closed 基线"
# 注册等待不用 grep -q（SIGPIPE 竞态，dual_edge 同教训）：全量 grep
for c in mesh-node-a mesh-node-b mesh-node-c; do
  for i in $(seq 1 30); do
    if logs $c | grep 'registered:' >/dev/null; then break; fi
    sleep 2
    [ "$i" = "30" ] && { echo "FAIL: $c 未注册"; logs $c | tail -10; exit 1; }
  done
done
# b 必须已收到首版 netmap（fail-closed 判定的前提：裁决材料已就位）
for i in $(seq 1 15); do [ -n "$(netmap_ver)" ] && break; sleep 2; done
[ -n "$(netmap_ver)" ] || { echo "FAIL: node-b 未收到 netmap"; logs mesh-node-b | tail -10; exit 1; }
leaked=0
for i in $(seq 1 5); do
  docker exec mesh-node-b ping -c1 -W1 192.168.247.100 >/dev/null 2>&1 && leaked=1
  sleep 1
done
[ "$leaked" = "0" ] || {
  echo "FAIL: exits.allow 空时 b ping inet 竟通（准入未 fail-closed 或绕过 mesh）"
  exit 1
}
logs mesh-node-b | grep 'no route for 192.168.247.100' >/dev/null || {
  echo "FAIL: ping 断但无引擎 no route 裁决日志（可能断在内核路由而非准入）"
  logs mesh-node-b | tail -10; exit 1
}
echo "PASS: fail-closed——能力位声明而未授权，b→inet 被引擎丢弃（no route）"

echo "==> exit_wan 阶段 2/3：SIGHUP 运行时授权 → b 借道出口双栈通"
# sed -n 全量读（无早退管道）；首个 registered: 行 = 原 node_id（id 不可变）
C_ID=$(logs mesh-node-c | grep 'registered:' | sed -n '1s/.*node_id=\([0-9]*\).*/\1/p')
[ -n "$C_ID" ] || { echo "FAIL: 无法从 node-c 日志解析 node_id"; exit 1; }
V1=$(netmap_ver)
BASE_C=$(ingress_count mesh-node-c)
# sed -i 走 rename 断 bind mount inode：写临时文件后 cp 原址覆盖（reload 同教训）
python3 - "$E2E_DIR/build/coord.json" "$C_ID" <<'PYEOF'
import json, sys
path, cid = sys.argv[1], int(sys.argv[2])
with open(path) as f:
    cfg = json.load(f)
for net in cfg["coord"]["networks"]:
    if net["name"] == "lab":
        net["exits"] = {"allow": [cid]}
with open(path + ".tmp", "w") as f:
    json.dump(cfg, f, indent=2)
PYEOF
cp "$E2E_DIR/build/coord.json.tmp" "$E2E_DIR/build/coord.json"
rm -f "$E2E_DIR/build/coord.json.tmp"
docker kill -s HUP mesh-coord >/dev/null
reloaded=1
for i in $(seq 1 20); do
  if [ "$(logs mesh-coord | grep -c 'config reloaded')" -ge 1 ]; then reloaded=0; break; fi
  sleep 1
done
[ "$reloaded" = "0" ] || { echo "FAIL: SIGHUP 重载未生效"; logs mesh-coord | tail -10; exit 1; }
ok=0
for i in $(seq 1 30); do
  docker exec mesh-node-b ping -c1 -W2 192.168.247.100 >/dev/null 2>&1 && { ok=1; break; }
  sleep 2
done
[ "$ok" = "1" ] || {
  echo "FAIL: 授权后 b→inet v4 不通"
  echo "--- coord 日志尾 ---"; logs mesh-coord | tail -10
  echo "--- node-b 日志尾 ---"; logs mesh-node-b | tail -15
  exit 1
}
ok6=0
for i in $(seq 1 15); do
  docker exec mesh-node-b ping6 -c1 -W2 fd00:247::100 >/dev/null 2>&1 && { ok6=1; break; }
  sleep 2
done
[ "$ok6" = "1" ] || { echo "FAIL: 授权后 b→inet v6 不通"; logs mesh-node-b | tail -15; exit 1; }
C=$(ingress_count mesh-node-c)
V2=$(netmap_ver)
[ "$C" -gt "$BASE_C" ] || {
  echo "FAIL: node-c 无 ingress 增长（流量可能未经出口转发）"
  exit 1
}
[ "$V2" -gt "$V1" ] || {
  echo "FAIL: 授权生效但 netmap 版本未 bump（v$V1→v$V2——set_exit_allow 未触发生效集变更？）"
  exit 1
}
echo "PASS: 授权（allow:[$C_ID]）→ netmap v$V1→v$V2 → b 借道 node-c 双栈通（ingress Δ$((C - BASE_C))）"

echo "==> exit_wan 阶段 3/3：出口停机 → 租约过期 → 无候选回退丢弃"
V3=$(netmap_ver)
docker stop mesh-node-c >/dev/null
# 租约过期（LEASE_EXPIRY_SECS=60）→ netmap 离线撤销 → 解析器候选清空；
# 到期前 ping 仍通（fail 计数清零），3 连断才判定收敛
fail=0
for i in $(seq 1 75); do
  if ! docker exec mesh-node-b ping -c1 -W1 192.168.247.100 >/dev/null 2>&1; then
    fail=$((fail + 1)); [ "$fail" -ge 3 ] && break
  else
    fail=0
  fi
  sleep 2
done
V4=$(netmap_ver)
[ "$fail" -ge 3 ] || {
  echo "FAIL: 出口停机后 b→inet 未断（离线转移未发生？netmap v$V3→v$V4）"
  exit 1
}
# ping 断先于租约过期（b 对既有会话直发 → 黑洞）——离线转移（60s 租约 +
# push 延迟）在断流之后才落 netmap，单独等版本增长（CTL-11 离线证据）
bumped=0
for i in $(seq 1 60); do
  V4=$(netmap_ver)
  [ "$V4" -gt "$V3" ] && { bumped=1; break; }
  sleep 2
done
[ "$bumped" = "1" ] || {
  echo "FAIL: ping 已断但 netmap 版本未增长（v$V3→v$V4——租约过期离线转移未发生？）"
  exit 1
}
docker exec mesh-node-b ping6 -c1 -W1 fd00:247::100 >/dev/null 2>&1 && {
  echo "FAIL: 出口停机后 v6 仍通"
  exit 1
}
echo "PASS: 出口停机 → 租约过期（netmap v$V3→v$V4）→ 解析器无候选 → 双栈丢弃"
echo "PASS: exit_wan 全部断言通过（E2E-05）"
