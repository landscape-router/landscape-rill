# CI 与文档一致性（ci）

> 本目录承载：CI 结构说明 + `check-docs.sh` 一致性检查。

## 1. CI 结构（workflow 按场景分文件，已落地）

**约定：一个 e2e 场景目录 = 一个 workflow 文件**（与 `e2e/` 目录结构一一对应；mesh 场景为 `e2e/mesh/{direct,relay}/` 子目录，后续 ts2021/dn42 接入 e2e 各加一个文件）。单元测试属代码侧校验，归 `check.yml`，不单独建 workflow。

| workflow | 内容 | 触发 | required |
|---|---|---|---|
| `check.yml` | fmt / clippy(`-D warnings`) / `cargo test --workspace` / cargo audit / `ci/check-docs.sh` | PR + push | 是 |
| `e2e-mesh.yml` | `build` job 编译一次：编译 cache（`~/.cargo` + `target`，内容键 `cargo-<os>-<rustc 版本>-<ISO 周>-<Cargo.lock hash>`，失效时机确定）加速增量编译 → release 二进制进 artifact → `mesh` job 七场景 matrix 并行（`needs: build` 下载 artifact，`E2E_SKIP_BUILD=1` 不再编译；每场景一 job，`fail-fast=false`）：direct（coord + node-a/b，IPv4+IPv6 ping）、relay（a—b—c 线形经 b 中继）、persist（REQ-037）、log（REQ-039）、reload（REQ-038 SIGHUP 重载）、tenancy（CONTROL_PLANE §1.5 双网络隔离 + forge.py 跨网伪造注入，SEC-21~25）、probe（CONNECTIVITY §2/§4/§5 回显/互探/relay RTT 排序/挂靠与故障切换 + SEC-26 限速），`MESH_E2E_SCENARIO` 取矩阵值 | PR + push main + workflow_dispatch | 否 |
| `e2e-p0-tailscale.yml` | `e2e/p0_tailscale/run_p0.sh`（官方客户端入网，低频） | 仅 workflow_dispatch | 否 |

- 工具链 **stable**（`dtolnay/rust-toolchain@stable` + `Swatinem/rust-cache`）；本地格式统一以 stable rustfmt 为准（nightly 与其一致，`cargo fmt` 前注意 rustup override）
- **含 cargo audit**（REQ-044 供应链审计部分落地；依赖最小化与可复现构建随 REQ-044 剩余部分推迟至 release 阶段）
- **e2e-mesh 编译 cache 失效时机（确定性，无回退）**：内容键 `cargo-<os>-<rustc 版本>-<ISO 周 %G-%V>-<Cargo.lock hash>`——`Cargo.lock` 变更、rustc stable 升级或**周旋转**（键内 ISO 周变化，缓存寿命严格 ≤7 天，即使持续访问）→ 键变 → 旧 cache 永久失效（全量重编一次，时机可预期）；源码变更不失效（cargo 指纹保证增量重编正确性）；同键条目已存在时 save 为 no-op；旋转产生的旧条目由 GitHub 内置规则回收（7 天未访问淘汰 + 仓库总量 10GB 超限 LRU）
- e2e 不设 required（成本高，低频/手动路径）

## 2. check-docs.sh 检查规则

1. **场景 ID 唯一**：tests/ 中 `## <PREFIX>-NN` 无重复
2. **REQ 引用存在**：tests/ 矩阵与各场景关联的 REQ-NNN 必须存在于 requirements/
3. **merged 必有去向**：状态为 merged 的 REQ stub 必须含 `去向：<短名> §<x.y>`，且短名注册、章节标题存在
4. **proposed 必有优先级**：状态为 proposed 的 REQ 必须含 `优先级：P0/P1/P2`
5. **proposed 依赖存在**：状态为 proposed 的 REQ 的 `依赖` 字段引用的 REQ-NNN 必须存在于 requirements/
6. **已覆盖必有证据**：状态为 `已覆盖` 的场景必须引用存在的证据文件
7. **注释短名契约**：各 crate 源码注释中的 `<短名> §<x.y>` 必须注册于 design/README.md 且章节存在
8. **链接完整性**：docs/ 内相对 .md 链接全部可解析
9. **error_id 唯一**：`#[error_id("...")]` 全局去重（ERROR_ID §3.1：ID 复用会引发 i18n 键冲突）

## 3. 使用

```sh
./docs/ci/check-docs.sh     # 从仓库根运行
```

退出码非 0 时按消息逐条修复；规则 3/7 的章节校验按文档编号标题（`### 2.6 ...`）匹配。
