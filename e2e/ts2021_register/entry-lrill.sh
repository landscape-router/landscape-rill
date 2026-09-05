#!/bin/sh
# lrill 自研 ts2021 客户端容器入口：/key 预取 → controlhttp 升级 → Noise IK → register
# 服务端公钥经 /key 端点预取（官方客户端同路径），CA 经 --ca 显式加载
set -e

for i in $(seq 1 10); do
  if ts2021-register \
      --host headscale:8080 \
      --authkey "$TS_AUTHKEY" \
      --ca /usr/local/share/ca-certificates/ts2021-ca.crt \
      --hostname lrill-ts2021; then
    echo "LRILL_REGISTER_OK"
    sleep infinity
  fi
  echo "retry in 3s"; sleep 3
done
echo "LRILL_REGISTER_FAILED"
exit 1
