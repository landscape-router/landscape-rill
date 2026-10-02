# 构建发布与产物对账（RELEASE）

> 可复现构建（同 commit 双构建位级一致）与发布产物对账（哈希 + 构建说明）——发布工程契约（REQ-050，教训 AO-06）。
> 版本：v1.2（§2.1 确定性开关改无条件常量——目录存在性门控在冷 runner 首建翻车；v1.1 为 target 重映射决定项 + last-match-wins）｜ 最近修改：2026-10-01 ｜ 相关需求：[REQ-050](../../requirements/REQ-050-reproducible-build.md)

## 1. 范围与边界

- 覆盖：release 二进制（`lrill`）的构建确定性、双构建哈希验收、发布产物（`dist/`）与二进制外连审计
- 不覆盖：多平台交叉构建矩阵、签名体系（无密钥基础设施依赖，哈希 + 构建说明即对账凭证）；依赖供应链审计归 REQ-044

## 2. 构建确定性

### 2.1 确定性开关（scripts/build.sh）

所有 release 构建（e2e / 部署共用同一入口）默认注入：

- `--remap-path-prefix=<工作区>=/build`、`--remap-path-prefix=<CARGO_HOME>/registry=/cargo-registry`、`--remap-path-prefix=<CARGO_TARGET_DIR>=/build-target`：panic 路径不随 checkout 位置、宿主 cargo 路径与 target 目录名变化——第三项是双构建验收的决定项：build script 生成文件（如 proto 生成 .rs）的 OUT_DIR 路径经 panic Location 渗入二进制，隔离 target 目录名不同即不一致，且经链接器字符串表哈希序扩散成全文差异。**多个重映射为后写优先（last-match-wins），更长的 target 前缀必须排在最后**，否则被工作区前缀先改写而失效。开关必须无条件常量：曾按 `CARGO_HOME/registry` 目录存在性门控 registry 重映射——冷 runner 首建时目录尚不存在（首次 cargo build 才创建），首建无旗标/次建有，双构建必不一致且仅冷环境可复现
- `SOURCE_DATE_EPOCH=git log -1 --pretty=%ct`：时间锚定 commit 时间（缺 git 环境时回落当前时间，此时构建仍同机确定但跨机不确定）

调用方已设 `RUSTFLAGS` / `SOURCE_DATE_EPOCH` 时追加不覆盖。

### 2.2 输入固定

- 依赖：`Cargo.lock` 提交进库（同 commit 即同依赖版本）
- 工具链：CI 固定 stable（`dtolnay/rust-toolchain@stable`）；本地复现以 `BUILD.md` 记录的工具链版本为准
- 不确定性余项：工具链版本漂移（跨升级不保证位级一致，属"构建环境差异须可解释"条款）

## 3. 产物对账（dist/）

`scripts/verify-repro.sh`：同 commit 两次独立构建（隔离 `CARGO_TARGET_DIR`）→ SHA256 比对，一致则产出：

- `lrill`：二进制
- `SHA256SUMS`：哈希清单
- `BUILD.md`：commit、工具链版本、复现步骤（`git checkout <commit> && ./scripts/verify-repro.sh`）

对账路径：用户以同 commit 源码自行构建，比对本地哈希与发布 `SHA256SUMS`。

## 4. 二进制外连审计（AO-06）

`scripts/audit-binary.sh`：提取二进制中域名形态字符串，逐一核对出处——仓库源码、依赖源码（cargo registry）、显式允许清单（`scripts/audit-allowlist.txt`，逐条人工复核登记）。三者皆无 → 失败（源码不可见的硬编码外连，AO-06 复核点）。

边界：依赖二进制段（registry 有源但未必本地解包）在无 registry 缓存时退化为允许清单裁决。

## 5. CI（.github/workflows/repro.yml）

仅 main 触发（两次 release 构建成本高，不进 PR 门禁；PR 侧由 check.yml 覆盖）：双构建比对 + AO-06 审计 + `dist/` 上传 artifact。

## 6. 决策记录/实现级决定

- 2026-10-01（v1.0）：确定性开关收敛在 `scripts/build.sh` 单入口（e2e/发布共用），不引入独立构建配置面；签名体系暂缓（哈希 + 构建说明即满足对账验收）；审计允许清单制而非全量硬编码比对（依赖噪声不可全消除）。
