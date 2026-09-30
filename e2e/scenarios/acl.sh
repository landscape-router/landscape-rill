# acl 场景（REQ-045，SEC-31，CONTROL_PLANE §3.10）：前缀级 ACL e2e——
# 阶段 1：放行前缀双向可达（b→a IPv4/IPv6；回包 dst = 发起方源前缀，同过裁决）
#         + 无规则仲裁前缀 default-deny（a→172.21.5.1 拒绝，目标节点日志
#           实收 "acl denied"——比不可达更强的解密后裁决证据）
# 阶段 2：coord.json 补放行 172.21.5.0/24 → SIGHUP → netmap 原子切换收敛后可达
#（裁决点 = 目标节点解密后：直连/中继同策略；广播豁免 = IPv6 ND 组播泛洪不受扰）

# 仲裁目标（同 dn42 场景惯例）：node-b lo 承载 172.21.5.1；node-a 侧内核路由
# 指到 land0（mesh 前缀 → land0 触发懒握手，同 setup 7.7 注入语义）
docker exec mesh-node-b ip addr add 172.21.5.1/32 dev lo 2>/dev/null || true
docker exec mesh-node-a ip route replace 172.21.5.0/24 dev land0 2>/dev/null || true

echo "==> acl 阶段 1/2：放行前缀双向可达 + 无规则前缀 default-deny"
allowed=1
for i in $(seq 1 30); do
  if docker exec mesh-node-b ping -c1 -W1 10.42.0.1 >/dev/null 2>&1 \
     && docker exec mesh-node-b ping6 -c1 -W1 fd00:2::1 >/dev/null 2>&1; then
    allowed=0
    break
  fi
  sleep 2
done
[ "$allowed" -eq 0 ] || {
  echo "FAIL: 放行前缀 ping 不通（策略误伤 allow 规则）"
  logs mesh-coord | tail -10; logs mesh-node-a | tail -10; logs mesh-node-b | tail -10
  exit 1
}
echo "PASS: 放行前缀双向可达（b→a IPv4 + IPv6）"

denied_ok=0
for i in $(seq 1 15); do
  if docker exec mesh-node-a ping -c1 -W1 172.21.5.1 >/dev/null 2>&1; then
    echo "FAIL: 无规则前缀 ping 成功（default-deny 失效）"
    logs mesh-node-b | tail -10
    exit 1
  fi
  # 目标节点侧拒绝证据（比不可达更强：解密后裁决命中）
  if [ "$(logs mesh-node-b | grep -c 'acl denied')" -ge 1 ]; then
    denied_ok=1
    break
  fi
  sleep 2
done
[ "$denied_ok" -eq 1 ] || {
  echo "FAIL: 未观察到 node-b 日志 'acl denied'（拒绝归因缺失）"
  logs mesh-node-b | tail -10
  exit 1
}
echo "PASS: 无规则前缀 default-deny（node-b 实收拒绝：acl denied）"

echo "==> acl 阶段 2/2：SIGHUP 补放行 172.21.5.0/24 → netmap 原子切换收敛"
cp "$E2E_DIR/build/.acl_open.json" "$E2E_DIR/build/coord.json"
docker kill -s HUP mesh-coord >/dev/null
reloaded=1
for i in $(seq 1 20); do
  if [ "$(logs mesh-coord | grep -c 'config reloaded')" -ge 1 ]; then
    reloaded=0
    break
  fi
  sleep 1
done
[ "$reloaded" -eq 0 ] || { echo "FAIL: SIGHUP 重载未生效"; logs mesh-coord | tail -10; exit 1; }
opened=1
for i in $(seq 1 30); do
  if docker exec mesh-node-a ping -c1 -W1 172.21.5.1 >/dev/null 2>&1; then
    opened=0
    break
  fi
  sleep 2
done
[ "$opened" -eq 0 ] || {
  echo "FAIL: 补放行后 172.21.5.1 仍不可达（策略切换未收敛）"
  logs mesh-coord | tail -10; logs mesh-node-a | tail -10; logs mesh-node-b | tail -10
  exit 1
}
echo "PASS: 补放行后收敛可达（心跳快照 ≤10s 节奏）"
echo "PASS: acl 场景全过——前缀级 allow/default-deny + SIGHUP 原子切换（REQ-045）"
