#!/bin/sh
# lrill 自研 ts2021 客户端容器入口：注册（auth key）→ 长轮询 netmap → WG ping 唯一 peer
# → 打印 PEER_PING_OK 后常驻应答对端 echo（供 node-c 反向 ping 断言）
set -e

for i in $(seq 1 10); do
  if ts2021-probe \
      --host headscale:8080 \
      --authkey "$TS_AUTHKEY" \
      --ca /usr/local/share/ca-certificates/ts2021-ca.crt \
      --hostname lrill-ts2021 \
      --ping-peer; then
    sleep infinity
  fi
  echo "retry in 3s"; sleep 3
done
echo "LRILL_TS2021_FAILED"
exit 1
