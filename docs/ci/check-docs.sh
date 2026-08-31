#!/usr/bin/env bash
# docs 一致性检查（从仓库根运行：./docs/ci/check-docs.sh）
# 规则见 docs/ci/README.md。全部通过退出 0，任一失败退出 1。
set -u

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DOCS="$ROOT/docs"
fail=0

error() { printf '%-12s %s\n' "ERROR" "$1"; fail=1; }

# ---------- 1. 场景 ID 唯一 ----------
ids="$(grep -rhoE '^## [A-Z0-9]{3,4}-[0-9]+' "$DOCS"/tests --include='*.md' 2>/dev/null | awk '{print $2}')"
dup="$(printf '%s\n' "$ids" | sort | uniq -d)"
if [ -n "$dup" ]; then
  error "tests/ 场景 ID 重复：$(printf '%s' "$dup" | tr '\n' ' ')"
fi

# ---------- 2. tests/ 引用的 REQ-NNN 必须存在 ----------
req_refs="$(grep -rhoE 'REQ-[0-9]{3}' "$DOCS"/tests --include='*.md' 2>/dev/null | sort -u)"
for r in $req_refs; do
  if [ ! -f "$DOCS/requirements/${r}.md" ] && ! ls "$DOCS/requirements/${r}-"*.md >/dev/null 2>&1; then
    error "$r 被 tests/ 引用但 requirements/ 中不存在"
  fi
done

# ---------- 3. merged 的 REQ 必须有去向且可解析 ----------
for f in "$DOCS"/requirements/REQ-*.md; do
  [ -f "$f" ] || continue
  state="$(grep -oE '状态：[^|｜]+' "$f" | head -1)"
  case "$state" in
    *merged*)
      dest="$(grep -oE '去向：[^|｜]+' "$f" | head -1 | sed 's/^去向：//')"
      if [ -z "$dest" ]; then
        error "$(basename "$f") 状态 merged 但缺少去向指针"
        continue
      fi
      # 取第一个去向（分隔符：空格斜杠空格 / 全角空格）
      item="$(printf '%s' "$dest" | sed 's/  */ /g' | awk -F' / ' '{print $1}')"
      case "$item" in
        e2e/*|design/*|tests/*|requirements/*|lessons/*|ci/*)
          # docs-relative 路径去向（如 e2e/README、design/README）
          p="${item%% *}"
          [ -f "$DOCS/$p.md" ] || error "$(basename "$f") 去向文件不存在：docs/$p.md"
          continue
          ;;
      esac
      short="$(printf '%s' "$item" | awk '{print $1}')"
      [ -n "$short" ] || continue
      reg="$(grep -E '^\| `'"$short"'` \|' "$DOCS/design/README.md" | head -1)"
      if [ -z "$reg" ]; then
        error "$(basename "$f") 去向短名 $short 未注册于 design/README.md"
        continue
      fi
      sec="$(printf '%s' "$item" | grep -oE '§[0-9]+(\.[0-9]+)?' | head -1 | tr -d '§')"
      if [ -n "$sec" ]; then
        file="$(printf '%s' "$reg" | sed -E 's/.*\]\(\.\/([^)]+)\).*/\1/')"
        if ! grep -qE "^#+[[:space:]]+${sec//./\.}\b" "$DOCS/design/$file" 2>/dev/null; then
          error "$(basename "$f") 去向 $short §$sec 章节不存在（$file）"
        fi
      fi
      ;;
  esac
done

# ---------- 3.5 proposed 的 REQ 必须有优先级 ----------
for f in "$DOCS"/requirements/REQ-*.md; do
  [ -f "$f" ] || continue
  state="$(grep -oE '状态：[^|｜]+' "$f" | head -1)"
  case "$state" in
    *proposed*)
      pri="$(grep -oE '优先级：P[0-9]' "$f" | head -1)"
      if [ -z "$pri" ]; then
        error "$(basename "$f") 状态 proposed 但缺少优先级字段（P0/P1/P2）"
      fi
      ;;
  esac
done

# ---------- 3.6 proposed 的依赖引用必须存在 ----------
for f in "$DOCS"/requirements/REQ-*.md; do
  [ -f "$f" ] || continue
  state="$(grep -oE '状态：[^|｜]+' "$f" | head -1)"
  case "$state" in
    *proposed*)
      for dep in $(grep -oE '依赖：[^|｜]+' "$f" | head -1 | grep -oE 'REQ-[0-9]{3}' | sort -u); do
        if [ ! -f "$DOCS/requirements/${dep}.md" ] && ! ls "$DOCS/requirements/${dep}-"*.md >/dev/null 2>&1; then
          error "$(basename "$f") 依赖 $dep 不存在"
        fi
      done
      ;;
  esac
done

# ---------- 4. 已覆盖场景必须有存在的证据文件 ----------
# 证据字段格式：`- 证据：<路径>、<路径>`（仓库根相对；分隔符为 、 或 ,）
tmp="$(mktemp)"
grep -rhA6 '状态：`已覆盖`' "$DOCS"/tests --include='*.md' 2>/dev/null | \
  grep -oE '^\- 证据：.*' | sed 's/^- 证据：//' | tr '、,' '\n\n' | \
  sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | sort -u > "$tmp"
while IFS= read -r ev; do
  [ -n "$ev" ] || continue
  if [ ! -e "$ROOT/$ev" ]; then
    error "已覆盖场景的证据文件不存在：$ev"
  fi
done < "$tmp"
rm -f "$tmp"

# ---------- 5. src/ 注释短名契约 ----------
# 匹配 `<短名> §x.y`，短名须注册，章节标题须存在于目标文件
cmds="$(grep -rhoE '\b(ARCHITECTURE|FRAME_HEADER|CONTROL_PLANE|CONNECTIVITY|TS2021_LEG|DN42_LEG|ROUTE_ENGINE) §[0-9]+(\.[0-9]+)?' "$ROOT"/rill-core/src "$ROOT"/rill-coord/src "$ROOT"/rill-mesh/src "$ROOT"/rill-node/src "$ROOT"/rilld/src --include='*.rs' 2>/dev/null | sort -u)"
while IFS= read -r c; do
  [ -n "$c" ] || continue
  short="$(printf '%s' "$c" | awk '{print $1}')"
  sec="$(printf '%s' "$c" | grep -oE '§[0-9]+(\.[0-9]+)?' | tr -d '§')"
  reg="$(grep -E '^\| `'"$short"'` \|' "$DOCS/design/README.md" | head -1)"
  if [ -z "$reg" ]; then
    error "src/ 注释引用短名 $short 未注册于 design/README.md"
    continue
  fi
  file="$(printf '%s' "$reg" | sed -E 's/.*\]\(\.\/([^)]+)\).*/\1/')"
  if ! grep -qE "^#+[[:space:]]+${sec//./\.}\b" "$DOCS/design/$file" 2>/dev/null; then
    error "src/ 注释 $c 引用章节不存在（$file 无 §$sec）"
  fi
done <<< "$cmds"

# ---------- 6. docs/ 内相对链接完整性 ----------
links="$(grep -rhoE '\]\([^)]*\.md\)' "$DOCS" --include='*.md' 2>/dev/null | sed -E 's/^\]\(//;s/\)$//' | grep -v '^http' | sort -u)"
for link in $links; do
  target="${link%%#*}"
  case "$target" in
    ./*|../*) ;;
    *) continue ;;
  esac
  while IFS= read -r src; do
    [ -n "$src" ] || continue
    if ! ( cd "$(dirname "$src")" && [ -e "$target" ] ); then
      error "断链：$src → $target"
    fi
  done < <(grep -rlF "]($target)" "$DOCS" --include='*.md' 2>/dev/null)
done

if [ "$fail" -eq 0 ]; then
  echo "check-docs.sh: 全部通过"
fi
exit "$fail"
