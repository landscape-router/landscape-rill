#!/bin/sh
# rill-ext（mesh 节点 + ts2021 腿）容器入口：内核参与项就位后 exec lrill
#   - ip_forward / rp_filter=0：exit 被用作（TSL-07）的内核转发前提
#   - MASQUERADE：tailnet 源流量出 extnet 口改写源地址（回程 conntrack 反 NAT）
#   - 100.64.0.0/10 → land0：tailnet 目标回包交还用户态（ts2021 出站路径）
# land0 由 lrill 启动后创建，回程路由在后台循环中注入
set -e

echo 1 > /proc/sys/net/ipv4/ip_forward
echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter
for i in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 > "$i"; done

EXT_IF=$(ip -o addr | awk '$4 ~ /^192\.168\.245\./{print $2}' | head -1)
iptables -t nat -A POSTROUTING -o "$EXT_IF" -s 100.64.0.0/10 -j MASQUERADE
# mesh 源（rill-b 经 tailnet exit 借道，E2E-07）：MASQUERADE 计数器 = 承载证据
iptables -t nat -A POSTROUTING -o "$EXT_IF" -s 10.42.0.0/24 -j MASQUERADE

(
  for i in $(seq 1 120); do
    if ip link show land0 >/dev/null 2>&1; then
      ip route add 100.64.0.0/10 dev land0 2>/dev/null \
        || ip route replace 100.64.0.0/10 dev land0
      break
    fi
    sleep 1
  done
) &

exec /usr/local/bin/lrill run /etc/landscape/overlay.json
