#!/bin/sh
# 官方 Tailscale 客户端容器入口：tailscaled（内核 TUN）+ tailscale up（auth key 入网自建 headscale）
# --tun 参数是设备名（默认 tailscale0），不是 /dev/net/tun 路径
set -e

mkdir -p /var/lib/tailscale /var/run/tailscale
tailscaled --tun=tailscale0 --state=/var/lib/tailscale/tailscaled.state \
    --socket=/var/run/tailscale/tailscaled.sock &

for i in $(seq 1 30); do
  tailscale --socket=/var/run/tailscale/tailscaled.sock up \
      --login-server="https://headscale:8080" --authkey="$TS_AUTHKEY" \
      --hostname="$TS_HOSTNAME" --accept-dns=false --accept-routes && break
  sleep 2
done

tailscale --socket=/var/run/tailscale/tailscaled.sock status
sleep infinity
