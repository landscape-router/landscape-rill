# 验收与测试设计（tests）

> 验收场景与状态跟踪——每条场景带稳定 ID、覆盖状态、证据；验收断言在场景文件尾部。
> 设计规范见 [../design/README.md](../design/README.md)，环境方案与运行见 [../e2e/README.md](../e2e/README.md)。

## 1. 状态四档

| 状态 | 含义 |
|---|---|
| `已覆盖` | 现有自动化测试/脚本包含直接断言（CI 持续绿即验收） |
| `部分覆盖` | 只验证了部分结果、部分环境或较低层逻辑 |
| `待补充` | 没有能够直接证明该场景的测试 |
| `低频 smoke` | 只抽样验证外部系统兼容性，不作普通发布门禁 |

> 状态只表示"测试是否证明该行为"，不表示"功能是否实现"。状态由 **AI 经 `gh` 确认 CI 后更新**，人工可读、证据可复核。

## 2. 场景文档模板

```markdown
## <ID> <短标题>

- 关联 REQ：REQ-NNN（可多个）
- 测试层：单测 / 集成 / docker e2e / 低频 smoke
- 状态：`待补充`
- 证据：测试文件或脚本路径（已覆盖必填）
- 缺口：缺少的覆盖（可选）
- 说明：附加上下文（可选）

#### 验收断言（文件尾部汇总）
- [ ] ...
```

## 3. 场景索引

| 域 | 文件 | 场景 ID |
|---|---|---|
| mesh 帧头/握手/广播 | [mesh/frame.md](./mesh/frame.md) | `FRM-01` ~ `FRM-11` |
| mesh 控制面 | [mesh/control-plane.md](./mesh/control-plane.md) | `CTL-01` ~ `CTL-15` |
| mesh 连通性 | [mesh/connectivity.md](./mesh/connectivity.md) | `CON-01` ~ `CON-09` |
| ts2021 接入 | [legs/ts2021.md](./legs/ts2021.md) | `TSL-01` ~ `TSL-10` |
| dn42 接入 | [legs/dn42.md](./legs/dn42.md) | `DNL-01` ~ `DNL-07` |
| 路由引擎 | [routing.md](./routing.md) | `RTE-01` ~ `RTE-08` |
| 帧层对抗 | [security/frame-attacks.md](./security/frame-attacks.md) | `SEC-01` ~ `SEC-11` |
| 控制面对抗 | [security/control-plane-attacks.md](./security/control-plane-attacks.md) | `SEC-12` ~ `SEC-20` |
| 租户边界 | [security/tenancy.md](./security/tenancy.md) | `SEC-21` ~ `SEC-28` |
| 管理面与配置 | [admin.md](./admin.md) | `ADM-01` ~ `ADM-06` |
| 跨接入联动 | [integration.md](./integration.md) | `E2E-01` ~ `E2E-08` |

## 4. 验收矩阵（REQ ↔ 场景 ↔ 状态 ↔ 证据）

| REQ | 场景 | 状态 | 证据/CI |
|---|---|---|---|
| REQ-001 | FRM-01 / FRM-04 | 已覆盖 | rill-core/src/frame.rs、rill-core/src/handshake.rs |
| REQ-002 | FRM-02 | 已覆盖 | rill-core/src/crypto.rs、rill-mesh/src/data.rs |
| REQ-003 | FRM-02 | 已覆盖 | rill-mesh/src/data.rs |
| REQ-004 | CTL-01 | 已覆盖 | rill-mesh/src/control.rs、e2e/run_e2e.sh |
| REQ-005 | E2E-05 | 待补充 | — |
| REQ-006 | TSL-01 | 已覆盖 | e2e/p0_tailscale/run_p0.sh |
| REQ-007 | CON-01 ~ CON-06 | 待补充 | — |
| REQ-008 | CTL-10 / CTL-11 | 待补充 | — |
| REQ-009 | RTE-07 | 待补充 | — |
| REQ-010 | CTL-09 / SEC-21 ~ SEC-25 | 待补充 | — |
| REQ-011 | FRM-06 | 已覆盖 | rill-core/src/handshake.rs |
| REQ-012 | E2E-01 ~ E2E-08 | 待补充 | — |
| REQ-013 | CTL-13 | 已覆盖 | rill-core/src/control/ |
| REQ-014 | CTL-13 / CON-07 / CON-08 / RTE-08 | 部分覆盖 | — |
| REQ-015 | DNL-01 ~ DNL-07 | 待补充 | — |
| REQ-016 | SEC-03 / SEC-04 / SEC-09 / SEC-10 | 部分覆盖 | — |
| REQ-017 | SEC-01 / SEC-02 / FRM-07 | 部分覆盖 | — |
| REQ-018 | CTL-13 | 已覆盖 | rill-core/src/control/challenge.rs |
| REQ-019 | — | — | — |
| REQ-020 | SEC-28 | 待补充 | — |
| REQ-021 | TSL-01 ~ TSL-10 | 部分覆盖 | — |
| REQ-022 | CTL-13 / SEC-16 | 已覆盖 | rill-core/src/control/ |
| REQ-023 | RTE-01 ~ RTE-04 | 已覆盖 | rill-core/src/route.rs |
| REQ-024 | CTL-01 / CTL-08 | 已覆盖 | rill-coord/src/ |
| REQ-025 | — | — | rill-node/src/config.rs |
| REQ-026 | — | — | rill-node/src/ |
| REQ-027 | CTL-01 | 已覆盖 | rill-mesh/src/control.rs |
| REQ-028 | FRM-09 | 已覆盖 | rill-mesh/src/data.rs |
| REQ-029 | FRM-04 / FRM-06 / SEC-05 ~ SEC-10 | 已覆盖 | rill-core/src/handshake.rs |
| REQ-030 | FRM-11 | 已覆盖 | rill-node/src/runtime.rs |
| REQ-031 | E2E-01 / FRM-10 | 已覆盖 | e2e/run_e2e.sh |
| REQ-032 | FRM-08 / FRM-10 | 部分覆盖 | e2e/run_e2e.sh |
| REQ-033 | TSL-01 | 已覆盖 | e2e/p0_tailscale/run_p0.sh |
| REQ-034 | CTL-15 | 已覆盖 | rill-core/src/frame.rs、rill-coord/src/path_service.rs、rill-mesh/src/data.rs、e2e/run_e2e.sh、e2e/mesh/relay/ |
| REQ-035 | FRM-08 / CTL-14 | 待补充 | — |
| REQ-036 | ADM-04 / ADM-05 | 已覆盖 | rill-coord/src/config.rs、rill-core/src/control/registry.rs |
| REQ-037 | — | 📌 proposed（无验收场景） | — |
| REQ-038 | ADM-01 / ADM-02 | 已覆盖 | rill-coord/src/config.rs、rill-core/src/control/registry.rs、e2e/run_e2e.sh |
| REQ-038 | ADM-03 | 部分覆盖 | rilld/src/main.rs（SIGHUP 重载手动验证，未自动化） |
| REQ-039 | — | 📌 proposed（无验收场景） | — |
| REQ-040 | — | 📌 proposed（无验收场景） | — |
| REQ-041 | — | 📌 proposed（无验收场景） | — |
| REQ-042 | ADM-06 | 部分覆盖 | e2e/Dockerfile、e2e/run_e2e.sh、rilld/src/main.rs |

## 5. 维护规则

- 新增场景：ID 域内递增，不重复使用；一条 merged 需求至少对应一个场景
- 状态更新：AI 经 `gh run watch` 确认 CI 结果后更新状态与证据；**已覆盖必须有存在的证据文件**
- 验收断言在场景文件**尾部**汇总（随行为变更一起 diff）
- `ci/check-docs.sh` 校验：ID 唯一、REQ 引用存在、已覆盖有证据
