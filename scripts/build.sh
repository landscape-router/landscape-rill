#!/usr/bin/env bash
# 编译 release 二进制（e2e / 部署共用）
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cargo build --release --manifest-path "$ROOT_DIR/Cargo.toml"
