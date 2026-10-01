# REQ-050 可复现构建与发布产物一致性

> 类型：需求 ｜ 状态：✅ merged ｜ 提出：2026-09-01 ｜ 合并：2026-10-01
> 去向：RELEASE §2/§3/§4 ｜ 验收场景：ADM-09 ｜ lessons：AO-06（发布源码一致性）

## 动机

自 REQ-044 拆出：可复现构建与产物一致性是**发布工程**问题（教训 AO-06：发布二进制与开源源码不一致、外连源码中查不到的硬编码默认服务器/域名——用户无法审计"我跑的东西是否等于我看到的代码"）。验收维度（构建确定性 + 产物对账）与依赖供应链审计（REQ-044）不同，拆分以保证单一可验收行为。

## 决策摘要

确定性开关收敛在 `scripts/build.sh` 单入口（e2e/发布共用）：`--remap-path-prefix`（工作区 + cargo registry + target 目录）+ `SOURCE_DATE_EPOCH` 锚 commit 时间；依赖 `Cargo.lock` 提交固定。验收 = `scripts/verify-repro.sh` 同 commit 双构建（隔离 target）SHA256 比对，一致即产出 `dist/`（lrill + SHA256SUMS + BUILD.md 复现说明）——签名体系暂缓（无密钥基础设施依赖，哈希 + 构建说明即对账凭证）。AO-06 审计 = `scripts/audit-binary.sh` 域名出处三源核对（仓库源码/依赖源码/允许清单）。CI `repro.yml` 仅 main 触发（成本不进 PR 门禁）。

## 去向

- RELEASE §2（构建确定性）/ §3（产物对账）/ §4（二进制外连审计）
- 验收：ADM-09（[../tests/admin.md](../tests/admin.md)）

## Lessons 复核（AO-06 发布源码一致性）

- AO-06 复核点①"发布二进制与源码一致"：双构建哈希验收 + BUILD.md 复现步骤（用户可独立对账）
- AO-06 复核点②"硬编码默认服务器/域名"：audit-binary.sh 出处核对，无源出处的域名构建失败（允许清单逐条人工复核登记）
