#!/bin/sh
# rill-ext（ts2021 腿 + dn42 腿）容器入口：
#   100.64.0.0/10 → land0：dn42→tailnet 回程——转发边集不含该对（lan.rs
#   dn42→tailnet 无边），transit 落空写 TUN 后由内核经 land0 交还用户态，
#   LAN 泵按 Tailnet 路由送 ts2021 腿。land0 由 lrill 启动后创建，路由后台注入
set -e

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
