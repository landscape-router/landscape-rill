#!/bin/sh
# lrill 自研 ts2021 客户端容器入口：注册（auth key）→ 长轮询 netmap → WG ping 唯一 peer
# → 打印 PEER_PING_OK 后常驻应答对端 echo（供 node-c 反向 ping 断言）
# --state：machine key 持久（重启身份稳定，node key 每次轮换）
set -e

# exit 转发目标（TSL-06）：由 run.sh 注入 —— 独立 docker 网络的网关地址。
# 不能用本网段地址：tailscaled 对 0.0.0.0/0 做 shrink（剔除本机直连网段，guest-wifi 语义），
# 同网段目标会被 exit 侧 tstun 包过滤丢弃。
EXIT_ARGS=""
[ -n "${TS_EXIT_TARGET:-}" ] && EXIT_ARGS="--ping-exit $TS_EXIT_TARGET"

for i in $(seq 1 10); do
  if ts2021-probe \
      --host headscale:8080 \
      --authkey "$TS_AUTHKEY" \
      --ca /usr/local/share/ca-certificates/ts2021-ca.crt \
      --hostname lrill-ts2021 \
      --state /var/lib/lrill/machine.key \
      --ping-peer $EXIT_ARGS; then
    sleep infinity
  fi
  echo "retry in 3s"; sleep 3
done
echo "LRILL_TS2021_FAILED"
exit 1
