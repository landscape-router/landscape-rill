# dual_edge 场景（E2E-06 多 rill ext 节点冗余，容器级）：
# 拓扑：node-a/node-c 双边缘公告同前缀 10.42.0.0/24（tun 同 IP 10.42.0.1，active-backup）
# 断言：
# ① 基线：node-b ping 10.42.0.1 经单一边缘承载（ingress 归属计数判定活跃方）
# ② 活跃边缘停机 → 租约过期（60s）→ netmap 离线撤销 → 引擎切另一边缘
#    （ping 收敛 + 新边缘 ingress 计数增长 + 旧边缘不再增长）
# ③ 冗余切换全程 node-b 无需重启/重注册（软状态收敛）
ingress_count() { logs "$1" | grep -c 'frame from .* ingress' || true; }

echo "==> dual_edge 阶段 1/3：三节点注册 + 基线（活跃边缘归属判定）"
# 注册等待不用 grep -q：debug 级日志大，-q 首匹配即退出 → docker logs 侧 SIGPIPE
# 竞态下整管道 141 → break 不触发（ts2021 run.sh 同教训）；全量 grep 无此竞态
for c in mesh-node-a mesh-node-b mesh-node-c; do
  for i in $(seq 1 30); do
    if logs $c | grep 'registered:' >/dev/null; then break; fi
    sleep 2
    [ "$i" = "30" ] && { echo "FAIL: $c 未注册"; logs $c | tail -10; exit 1; }
  done
done
BASE_A=$(ingress_count mesh-node-a)
BASE_C=$(ingress_count mesh-node-c)
ok=0
for i in $(seq 1 20); do
  docker exec mesh-node-b ping -c1 -W1 10.42.0.1 >/dev/null 2>&1 && { ok=1; break; }
  sleep 2
done
[ "$ok" = "1" ] || { echo "FAIL: 基线 b→10.42.0.1 不通"; exit 1; }
sleep 2
A=$(ingress_count mesh-node-a); C=$(ingress_count mesh-node-c)
DA=$((A - BASE_A)); DC=$((C - BASE_C))
if [ "$DA" -gt "$DC" ]; then
  ACTIVE=mesh-node-a; STANDBY=mesh-node-c
elif [ "$DC" -gt "$DA" ]; then
  ACTIVE=mesh-node-c; STANDBY=mesh-node-a
else
  echo "FAIL: 无法判定活跃边缘（aΔ=$DA cΔ=$DC——b 的流量未落到任一边缘？）"
  logs mesh-node-b | tail -10
  exit 1
fi
STOP_BASE=$(ingress_count "$STANDBY")
echo "PASS: 基线可达，活跃边缘 = $ACTIVE（ingress Δa=$DA Δc=$DC），standby = $STANDBY"

echo "==> dual_edge 阶段 2/3：停活跃边缘 → 引擎切 standby"
# 租约过期证据（CTL-11）：离线转移递增 netmap 版本——切换收敛后版本必须已增长
netmap_ver() { logs mesh-node-b | grep 'netmap v' | tail -1 | sed 's/.*netmap v\([0-9]*\):.*/\1/'; }
V_BEFORE=$(netmap_ver)
docker stop "$ACTIVE" >/dev/null
# 租约过期（LEASE_EXPIRY_SECS=60）→ netmap 离线撤销 → 剩余唯一 via；b 重试 ping 直至收敛
ok=0
for i in $(seq 1 75); do
  docker exec mesh-node-b ping -c1 -W1 10.42.0.1 >/dev/null 2>&1 || { sleep 2; continue; }
  # ping 通且确实经 standby（其 ingress 增长）才算切换完成
  if [ "$(ingress_count "$STANDBY")" -gt "$STOP_BASE" ]; then ok=1; break; fi
  sleep 2
done
V_AFTER=$(netmap_ver)
[ "$ok" = "1" ] || {
  echo "FAIL: 停 $ACTIVE 后未切换到 $STANDBY（ping 或 ingress 未收敛；netmap v$V_BEFORE→v$V_AFTER）"
  echo "--- $STANDBY 日志尾 ---"; logs "$STANDBY" | tail -15
  echo "--- node-b 日志尾 ---"; logs mesh-node-b | tail -15
  exit 1
}
[ "$V_AFTER" -gt "$V_BEFORE" ] || {
  echo "FAIL: 切换收敛但 netmap 版本未增长（v$V_BEFORE→v$V_AFTER）——租约过期离线转移（CTL-11）未发生？"
  exit 1
}
echo "PASS: $ACTIVE 停机 → 租约过期（netmap v$V_BEFORE→v$V_AFTER）→ 流量切 $STANDBY（ingress 增长），ping 恢复"

echo "==> dual_edge 阶段 3/3：切换后稳定 + IPv6 同路径"
docker exec mesh-node-b ping -c3 -W1 10.42.0.1 >/dev/null 2>&1 || { echo "FAIL: 切换后 IPv4 不稳定"; exit 1; }
for i in $(seq 1 15); do
  docker exec mesh-node-b ping6 -c1 -W1 fd00:2::1 >/dev/null 2>&1 && { echo "PASS: dual_edge 全部断言通过（E2E-06）"; exit 0; }
  sleep 2
done
echo "FAIL: 切换后 IPv6 不通"
logs "$STANDBY" | tail -15
exit 1
