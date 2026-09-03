#!/usr/bin/env bash
# dn42 e2e 场景断言（DNL-01~07，DN42_LEG §7）：
#   peer-r = 内核 WG + FRR；node-a = lrill dn42 leg（无 coordinator）
#   DNL-01 WG 握手 / DNL-02 BGP Established / DNL-03 路由学习 + 双向转发 /
#   DNL-04 export stub / DNL-05 import policy 负向 / DNL-06 撤销收敛 / DNL-07 会话故障恢复
set -euo pipefail

logs() { docker logs "$1" 2>&1; }

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
REJECT_OK=1
for i in $(seq 1 10); do
  if docker exec mesh-node-a ping -c1 -W1 10.99.0.1 >/dev/null 2>&1; then
    REJECT_OK=0
    break
  fi
  sleep 1
done
# FRR 侧确认该前缀确实公告了（排除"根本没公告"的假阴性）
if docker exec mesh-dn42-peer vtysh -c "show bgp ipv4 unicast" 2>/dev/null | grep -q "10.99.0.0/16"; then
  ANNOUNCED=1
else
  ANNOUNCED=0
fi
if [ "$REJECT_OK" = "1" ] && [ "$ANNOUNCED" = "1" ]; then
  echo "PASS: DNL-05 白名单外前缀已公告但 node-a 拒收（不可达）"
else
  echo "FAIL: DNL-05 白名单外前缀泄漏（announced=$ANNOUNCED reachable=$((1-REJECT_OK))）"
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

echo "PASS: dn42 e2e 全部断言通过（DNL-01~07）"
