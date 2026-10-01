#!/usr/bin/env bash
# AO-06 复核（REQ-050 验收③）：二进制中的域名/URL 字符串必须有源码出处——
# 仓库源码、依赖源码（cargo registry）或显式允许清单（scripts/audit-allowlist.txt，
# 逐条人工复核后登记）。三者皆无 → FAIL（源码不可见的硬编码外连）。
# 用法：./scripts/audit-binary.sh [二进制路径，默认 target/release/lrill]
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${1:-$ROOT_DIR/target/release/lrill}"
ALLOWLIST="$ROOT_DIR/scripts/audit-allowlist.txt"
REGISTRY="${CARGO_HOME:-$HOME/.cargo}/registry/src"

[ -f "$BIN" ] || { echo "FAIL: 二进制不存在：$BIN"; exit 1; }

# 域名形态：字母数字段 + 常见 TLD；过滤纯数字/版本样段
strings "$BIN" | grep -oE '([a-z][a-z0-9-]{1,62}\.)+(com|net|org|io|dev|cn|xyz|me|app|rs|crate)' \
  | grep -vE '^[0-9.]+$' | sort -u > /tmp/audit-domains.$$

UNKNOWN=0
while IFS= read -r d; do
  [ -z "$d" ] && continue
  if grep -rqF -- "$d" "$ROOT_DIR" --exclude-dir=target --exclude-dir=dist --exclude-dir=.git --exclude-dir=build \
      --include='*.rs' --include='*.toml' --include='*.sh' --include='*.md' --include='*.yaml' --include='*.yml' 2>/dev/null; then
    continue
  fi
  if [ -f "$ALLOWLIST" ] && grep -qxF -- "$d" "$ALLOWLIST"; then
    continue
  fi
  if [ -d "$REGISTRY" ] && grep -rqF -- "$d" "$REGISTRY" 2>/dev/null; then
    echo "  (deps) $d"
    continue
  fi
  echo "  UNKNOWN: $d"
  UNKNOWN=$((UNKNOWN + 1))
done < /tmp/audit-domains.$$
rm -f /tmp/audit-domains.$$

if [ "$UNKNOWN" -gt 0 ]; then
  echo "FAIL: $UNKNOWN 个域名无源码出处（复核后登记 scripts/audit-allowlist.txt 或清除）"
  exit 1
fi
echo "PASS: 二进制无源码不可见的硬编码域名（AO-06）"
