#!/usr/bin/env bash
# REQ-050 可复现构建验收：同 commit 两次独立构建（隔离 target 目录）→ SHA256 比对。
# 一致则产出 dist/（lrill + SHA256SUMS + BUILD.md 构建说明，供发布对账）。
# 用法：./scripts/verify-repro.sh
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BIN=lrill
A="$ROOT_DIR/target/repro-a"
B="$ROOT_DIR/target/repro-b"

echo "==> 双构建（隔离 target：repro-a / repro-b）"
rm -rf "$A" "$B"
CARGO_TARGET_DIR="$A" "$ROOT_DIR/scripts/build.sh" >/dev/null
CARGO_TARGET_DIR="$B" "$ROOT_DIR/scripts/build.sh" >/dev/null

HA=$(sha256sum "$A/release/$BIN" | cut -d' ' -f1)
HB=$(sha256sum "$B/release/$BIN" | cut -d' ' -f1)
echo "build A: $HA"
echo "build B: $HB"
if [ "$HA" != "$HB" ]; then
  echo "FAIL: 同 commit 双构建哈希不一致（REQ-050 验收不过）"
  exit 1
fi
echo "PASS: 双构建位级一致"

COMMIT=$(git -C "$ROOT_DIR" rev-parse HEAD)
TOOLCHAIN=$(rustc --version)
DIST="$ROOT_DIR/dist"
rm -rf "$DIST"
mkdir -p "$DIST"
cp "$A/release/$BIN" "$DIST/"
(
  cd "$DIST"
  sha256sum "$BIN" >SHA256SUMS
  cat >BUILD.md <<EOF
# 构建说明（REQ-050 产物对账）

- commit: $COMMIT
- 工具链: $TOOLCHAIN
- 双构建哈希一致: $HA（scripts/verify-repro.sh 验收通过）

复现步骤：

\`\`\`bash
git checkout $COMMIT
./scripts/verify-repro.sh   # 产出 dist/lrill + dist/SHA256SUMS
sha256sum dist/lrill        # 应等于 SHA256SUMS 所载
\`\`\`

构建注入的确定性开关见 scripts/build.sh（--remap-path-prefix + SOURCE_DATE_EPOCH）。
EOF
)
echo "==> dist/ 产物就绪：lrill + SHA256SUMS + BUILD.md"
