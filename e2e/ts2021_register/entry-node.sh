#!/bin/sh
# 官方 Tailscale 客户端容器入口：tailscaled（内核 TUN）+ tailscale up（auth key 入网自建 headscale）
# --tun 参数是设备名（默认 tailscale0），不是 /dev/net/tun 路径
set -e

mkdir -p /var/lib/tailscale /var/run/tailscale

# TS_ADVERTISE_EXIT=1：作为 exit node（e2e 断言 lrill 经此转发非本网流量，TSL-06）
# 需在 tailscaled 启动前开内核转发（v6 不开则一直报 "IP forwarding is disabled"）
# TS_ADVERTISE_ROUTE（run.sh 注入的独立网络子网）：exit node 的 0.0.0.0/0 过滤会
# 剔除 RFC1918（guest-wifi 语义），docker 网段全是 RFC1918 —— 目标子网需显式路由广播才放行
EXIT_FLAGS="--advertise-exit-node"
if [ -n "${TS_ADVERTISE_ROUTE:-}" ]; then
  EXIT_FLAGS="$EXIT_FLAGS --advertise-routes=$TS_ADVERTISE_ROUTE"
fi
if [ "${TS_ADVERTISE_EXIT:-0}" = "1" ]; then
  # 镜像无 procps/sysctl，直接写 /proc/sys
  echo 1 > /proc/sys/net/ipv4/ip_forward
  echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
else
  EXIT_FLAGS=""
fi

tailscaled --tun=tailscale0 --state=/var/lib/tailscale/tailscaled.state \
    --socket=/var/run/tailscale/tailscaled.sock &

for i in $(seq 1 30); do
  tailscale --socket=/var/run/tailscale/tailscaled.sock up \
      --login-server="https://headscale:8080" --authkey="$TS_AUTHKEY" \
      --hostname="$TS_HOSTNAME" --accept-dns=false --accept-routes $EXIT_FLAGS && break
  sleep 2
done

tailscale --socket=/var/run/tailscale/tailscaled.sock status
sleep infinity
