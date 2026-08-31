# 需求与决策库（requirements）

> 系统行为的**变更记录**：每条需求/决策何时提出、为何提出、是否已合并进 design/。
> **内容只存在于 design/，本文档各条目不重复承载行为内容**——合并后即 stub（动机 + 指针）。

## 1. 生命周期

```
proposed（提出：日期 + 动机 + 验收草案）
   ├─► merged（合并：内容搬入 design，stub 瘦身留动机+指针）
   ├─► rejected（拒绝：附原因）
   └─► superseded（被 REQ-NNN 取代）
```

- **状态取值**：`📌 proposed`（未合并，含"建议默认值"以推动收敛）/ `✅ merged`（已合并）/ `❌ rejected` / `↩️ superseded`
- **优先级**（仅 proposed 阶段）：`P0/P1/P2` = 期望落地阶段，与 CONTEXT §10 路线图对齐；**merged 时移除**（与 stub 瘦身一致，历史优先级无意义）
- **依赖**（仅 proposed 阶段）：前置 REQ 列表（`依赖：REQ-038`，可多个；`—` = 无）——排序依据：依赖未合并则本项无法独立验收；**merged 时移除**（合并后关联由 `去向` 同章节表达）
- **一条需求 = 一个可验收的行为变更**：写不出验收标准就不是需求
- **合并动作 = 内容搬家**：行为内容写入 design/ 对应章节并标注 REQ，stub 只留动机/决策摘要/指针
- **验收**：由 tests/ 场景跟踪，CI 持续绿即验收（验收断言在 tests/ 场景文件尾部）

## 2. 命名与模板

- 文件名：`REQ-NNN-slug.md`（NNN 递增，slug 英文短横线）
- 头部字段：`类型`（需求/决策）、`状态`、`优先级`（仅 proposed：P0/P1/P2，与路线图阶段对齐）、`依赖`（仅 proposed：前置 REQ，`—` = 无）、`提出日期`、`合并日期`、`去向`（merged 必填：`<短名> §x.y`）、`验收场景`（tests/ 场景 ID）
- 新增需求流程见 [../AGENTS.md](../../AGENTS.md)

## 3. 需求状态表（proposed 按优先级，merged 按提出日期 = 决策时间线）

| REQ | 类型 | 状态 | 优先级 | 提出 | 去向 |
|---|---|---|---|---|---|
| [REQ-037](./REQ-037.md) | 决策 | 📌 proposed | P1 | 08-15 | — |
| [REQ-039](./REQ-039.md) | 需求 | 📌 proposed | P1 | 08-15 | — |
| [REQ-040](./REQ-040.md) | 需求 | 📌 proposed | P2 | 08-15 | — |
| [REQ-041](./REQ-041.md) | 需求 | 📌 proposed | P2 | 08-15 | — |
| [REQ-001](./REQ-001.md) | 决策 | ✅ merged | — | 08-13 | FRAME_HEADER §2 |
| [REQ-002](./REQ-002.md) | 决策 | ✅ merged | — | 08-15 | FRAME_HEADER §2.1/§3.1 |
| [REQ-003](./REQ-003.md) | 决策 | ✅ merged | — | 08-15 | FRAME_HEADER §3.1/§2.1 |
| [REQ-004](./REQ-004.md) | 决策 | ✅ merged | — | 08-15 | CONTROL_PLANE §1/§3.2/§3.4~§3.7/§4/§5/§7 |
| [REQ-005](./REQ-005.md) | 决策 | ✅ merged | — | 08-15 | ARCHITECTURE / ROUTE_ENGINE §1/§3/§5 / DN42_LEG |
| [REQ-006](./REQ-006.md) | 决策 | ✅ merged | — | 08-15 | TS2021_LEG §1/§2/§3.1/§4/§5 / ARCHITECTURE §6 |
| [REQ-007](./REQ-007.md) | 决策 | ✅ merged | — | 08-15 | CONNECTIVITY §2/§3/§4/§5 |
| [REQ-008](./REQ-008.md) | 需求 | ✅ merged | — | 08-15 | CONTROL_PLANE §3.8 / ROUTE_ENGINE §3 |
| [REQ-009](./REQ-009.md) | 决策 | ✅ merged | — | 08-15 | ROUTE_ENGINE §6 |
| [REQ-010](./REQ-010.md) | 需求 | ✅ merged | — | 08-15 | CONTROL_PLANE §1.5 |
| [REQ-011](./REQ-011.md) | 决策 | ✅ merged | — | 08-15 | FRAME_HEADER §2.4/§6 |
| [REQ-012](./REQ-012.md) | 决策 | ✅ merged | — | 08-15 | e2e/README |
| [REQ-013](./REQ-013.md) | 决策 | ✅ merged | — | 08-15 | CONTROL_PLANE §2/§5.7 |
| [REQ-014](./REQ-014.md) | 决策 | ✅ merged | — | 08-15 | CONTROL_PLANE §3.9 / ROUTE_ENGINE §3 / CONNECTIVITY §2.1/§6 |
| [REQ-015](./REQ-015.md) | 需求 | ✅ merged | — | 08-15 | DN42_LEG |
| [REQ-016](./REQ-016.md) | 决策 | ✅ merged | — | 08-15 | FRAME_HEADER §2.3/§5 |
| [REQ-017](./REQ-017.md) | 决策 | ✅ merged | — | 08-15 | FRAME_HEADER §2.4/§2.5 / CONTROL_PLANE §6 / CONNECTIVITY §2.2 / ROUTE_ENGINE §7 |
| [REQ-018](./REQ-018.md) | 决策 | ✅ merged | — | 08-15 | CONTROL_PLANE §2/§3.9 |
| [REQ-019](./REQ-019.md) | 决策 | ✅ merged | — | 08-15 | ARCHITECTURE §8 / design/README §3.2 |
| [REQ-020](./REQ-020.md) | 决策 | ✅ merged | — | 08-15 | CONTROL_PLANE §3.10 / ROUTE_ENGINE §2/§3 |
| [REQ-021](./REQ-021.md) | 决策 | ✅ merged | — | 08-15 | TS2021_LEG §3.2/§3.3 / ROUTE_ENGINE §3/§7 |
| [REQ-022](./REQ-022.md) | 决策 | ✅ merged | — | 08-15 | CONTROL_PLANE §8 |
| [REQ-023](./REQ-023.md) | 决策 | ✅ merged | — | 08-15 | ROUTE_ENGINE §4/§9 |
| [REQ-024](./REQ-024.md) | 决策 | ✅ merged | — | 08-15 | CONTROL_PLANE §8 |
| [REQ-025](./REQ-025.md) | 决策 | ✅ merged | — | 08-15 | CONTROL_PLANE §8 |
| [REQ-026](./REQ-026.md) | 决策 | ✅ merged | — | 08-15 | design/README §3 |
| [REQ-027](./REQ-027.md) | 决策 | ✅ merged | — | 08-15 | CONTROL_PLANE §8 |
| [REQ-028](./REQ-028.md) | 决策 | ✅ merged | — | 08-15 | CONNECTIVITY §8 / FRAME_HEADER §4 |
| [REQ-029](./REQ-029.md) | 决策 | ✅ merged | — | 08-15 | FRAME_HEADER §2.4 |
| [REQ-030](./REQ-030.md) | 决策 | ✅ merged | — | 08-15 | CONTROL_PLANE §8 / ARCHITECTURE |
| [REQ-031](./REQ-031.md) | 决策 | ✅ merged | — | 08-15 | e2e/README |
| [REQ-036](./REQ-036.md) | 需求 | ✅ merged | — | 08-15 | CONTROL_PLANE §3.12/§6 |
| [REQ-038](./REQ-038.md) | 需求 | ✅ merged | — | 08-15 | CONTROL_PLANE §3.12 |
| [REQ-032](./REQ-032.md) | 需求 | ✅ merged | — | 08-16 | FRAME_HEADER §2.6/§3.1 |
| [REQ-033](./REQ-033.md) | 需求 | ✅ merged | — | 08-16 | TS2021_LEG §6 |
| [REQ-034](./REQ-034.md) | 需求 | ✅ merged | — | 08-30 | CONTROL_PLANE §3.11 / FRAME_HEADER §9 |
| [REQ-035](./REQ-035.md) | 需求 | ✅ merged | — | 08-30 | CONTROL_PLANE §3.1/§3.3 / FRAME_HEADER §2.6 |
| [REQ-042](./REQ-042-lrill-cli.md) | 需求 | ✅ merged | — | 08-30 | CONTROL_PLANE §3.12 |

## 4. 维护规则

- **merged 后 stub 只可改指针**（章节移动时），内容变更一律在 design/ 完成
- 新增 REQ 时：proposed 条目按 `优先级 → 提出日期` 插入表首；合并时移除优先级与依赖、更新状态与去向；`ci/check-docs.sh` 校验 merged 必有去向指针、proposed 的依赖引用存在
- 历史：本库由原 CONTEXT.md 决策时间线（#1-#33）与挂账项迁移而来，条目保留原始日期
