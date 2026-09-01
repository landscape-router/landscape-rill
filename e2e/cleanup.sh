#!/usr/bin/env bash
# mesh e2e 幂等清理：停止/删除全部场景容器与网络 + 清空 build/（下次 setup 从零生成）
# 可重复执行；无残留时也返回 0（幂等前提，setup.sh 启动前强制调用）
set -uo pipefail

E2E_DIR="$(cd "$(dirname "$0")" && pwd)"

# 全部 mesh 场景 compose（direct + relay + persist）；down 不存在的 compose 无副作用。
# 注意：compose down 默认不清理 profile 门控服务（persist 的 node-d），须带 --profile 再下
for f in "$E2E_DIR"/mesh/*/docker-compose.yaml; do
  [ -f "$f" ] || continue
  docker compose -f "$f" down -v --remove-orphans >/dev/null 2>&1 || true
  docker compose -f "$f" --profile late down -v --remove-orphans >/dev/null 2>&1 || true
done

# 构建产物（CA/密钥/证书/二进制拷贝）随配置一起清，保证 setup 幂等重建
# 注意：不清理 .cache/——CI 中 build job artifact 落地目录，setup 开头 cleanup 必须先保留它
rm -rf "$E2E_DIR/build"
echo "==> cleanup: 容器/网络/build 已清理"
