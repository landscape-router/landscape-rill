#!/bin/bash
# peer-r 启动：内核 WG 隧道（wg-quick）→ FRR 双守护（zebra + bgpd）
set -euo pipefail

wg-quick up /etc/wireguard/wg0.conf

# 172.20.100.0/24 = peer-r "自家 LAN"（lo 承载 172.20.100.100，供 BGP network 与
# ping 目标；注意隧道 /30 的 .1/.2 不得与本网段本地地址重叠）
ip addr add 172.20.100.100/24 dev lo 2>/dev/null || true
# 10.99.0.0/16 = 白名单外前缀（DNL-05 负向断言：本端可达，node-a 必须拒绝）
ip route add blackhole 10.99.0.0/16 2>/dev/null || true
# 172.20.200.0/24 = peer-r2 的第二条公告（DNL-09 max-prefix 触发用）
ip route add blackhole 172.20.200.0/24 2>/dev/null || true

if [ "$(hostname)" = "peer-r" ]; then
  # DNL-12 规模公告的 RIB 支撑路由（bgpd network 依赖 RIB 命中）
  for i in $(seq 0 399); do
    if [ "$i" -lt 256 ]; then
      ip route add blackhole "172.21.$i.0/24" 2>/dev/null || true
    else
      ip route add blackhole "172.22.$((i - 256)).0/24" 2>/dev/null || true
    fi
  done
fi

# BGP 守护：peer-r = FRR（zebra + bgpd），peer-r2 = Bird（双实现互操作，DN42_LEG §7）
if [ "$(hostname)" = "peer-r2" ]; then
  mkdir -p /run/bird
  bird -c /etc/bird/bird.conf
  for _ in $(seq 1 20); do
    [ -S /run/bird/bird.ctl ] && break
    sleep 0.5
  done
else
  mkdir -p /var/run/frr /var/log/frr
  chown -R frr:frr /var/run/frr /var/log/frr /etc/frr 2>/dev/null || true
  /usr/lib/frr/zebra -d
  /usr/lib/frr/bgpd -d -f /etc/frr/bgpd.conf
  for _ in $(seq 1 20); do
    [ -S /var/run/frr/bgpd.vty ] && break
    sleep 0.5
  done
fi

exec sleep infinity
