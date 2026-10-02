#!/usr/bin/env bash
# 编译 release 二进制（e2e / 部署共用）。注入确定性开关（REQ-050）：
# 路径重映射（panic 路径不随 checkout 位置变）+ SOURCE_DATE_EPOCH 锚定 commit 时间，
# 同 commit 双构建位级一致（验收：scripts/verify-repro.sh）
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# 确定性注入（REQ-050）：工作区/registry/OUT_DIR 路径重映射——第三项最关键：
# build script 产物路径（如 proto 生成文件）进 panic Location，target 目录名
# 不同即泄漏进二进制并经链接器哈希序扩散成全文差异。rustc 重映射为后写优先
# （last-match-wins），故更长的 target 前缀须置尾，否则被工作区前缀先吞。
# 开关必须无条件：registry 重映射曾按目录存在性门控——冷 runner 首建时目录
# 尚不存在 → 首建无此旗标、次建有 → 双构建必不一致（CI 独有，本机恒过）
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT_DIR/target}"
REGISTRY_DIR="${CARGO_HOME:-$HOME/.cargo}/registry"
FLAGS="--remap-path-prefix=${ROOT_DIR}=/build --remap-path-prefix=${TARGET_DIR}=/build-target --remap-path-prefix=${REGISTRY_DIR}=/cargo-registry"
export RUSTFLAGS="${RUSTFLAGS:-} ${FLAGS}"

if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
  SOURCE_DATE_EPOCH=$(git -C "$ROOT_DIR" log -1 --pretty=%ct 2>/dev/null || date +%s)
  export SOURCE_DATE_EPOCH
fi

cargo build --release --manifest-path "$ROOT_DIR/Cargo.toml"
