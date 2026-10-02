#!/bin/sh
# rill-x（mesh 出口节点，E2E-07，REQ-071）容器入口：内核参与项就位后 exec lrill
#   - ip_forward：land0↔eth_ext 转发前提
#   - MASQUERADE（10.42.0.0/24 源）：出口 WAN NAT（ROUTE_ENGINE §5：mesh exit 不 NAT，
#     WAN NAT 兜底——extnet 网关无回程路由，conntrack 反 NAT 承担回程）；
#     计数器增量 = 承载证据（与 rill-ext 的 tailnet 出口计数器对照 = 偏好裁决证据）
#   - 10.42.0.0/24 → land0：de-NAT 回程交还用户态（mesh 帧 → rill-b）
set -e

echo 1 > /proc/sys/net/ipv4/ip_forward

EXT_IF=$(ip -o addr | awk '$4 ~ /^192\.168\.245\./{print $2}' | head -1)
iptables -t nat -A POSTROUTING -o "$EXT_IF" -s 10.42.0.0/24 -j MASQUERADE

(
  for i in $(seq 1 120); do
    if ip link show land0 >/dev/null 2>&1; then
      ip route add 10.42.0.0/24 dev land0 2>/dev/null \
        || ip route replace 10.42.0.0/24 dev land0
      break
    fi
    sleep 1
  done
) &

exec /usr/local/bin/lrill run /etc/landscape/overlay.json
