#!/bin/bash
# peer-r 启动：内核 WG 隧道（wg-quick）→ FRR 双守护（zebra + bgpd）
set -euo pipefail

wg-quick up /etc/wireguard/wg0.conf

# 172.20.100.0/24 = peer-r "自家 LAN"（lo 承载 172.20.100.100，供 BGP network 与
# ping 目标；注意隧道 /30 的 .1/.2 不得与本网段本地地址重叠）
ip addr add 172.20.100.100/24 dev lo 2>/dev/null || true
# 10.99.0.0/16 = 白名单外前缀（DNL-05 负向断言：本端可达，node-a 必须拒绝）
ip route add blackhole 10.99.0.0/16 2>/dev/null || true

mkdir -p /var/run/frr /var/log/frr
chown -R frr:frr /var/run/frr /var/log/frr /etc/frr 2>/dev/null || true

/usr/lib/frr/zebra -d
/usr/lib/frr/bgpd -d -f /etc/frr/bgpd.conf

# bgpd 就绪探测（vty socket 出现）
for _ in $(seq 1 20); do
  [ -S /var/run/frr/bgpd.vty ] && break
  sleep 0.5
done

exec sleep infinity
