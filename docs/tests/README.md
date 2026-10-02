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
| mesh 帧头/握手/广播 | [mesh/frame.md](./mesh/frame.md) | `FRM-01` ~ `FRM-12` |
| mesh 控制面 | [mesh/control-plane.md](./mesh/control-plane.md) | `CTL-01` ~ `CTL-26` |
| mesh 连通性 | [mesh/connectivity.md](./mesh/connectivity.md) | `CON-01` ~ `CON-11` |
| ts2021 接入 | [legs/ts2021.md](./legs/ts2021.md) | `TSL-01` ~ `TSL-12` |
| dn42 接入 | [legs/dn42.md](./legs/dn42.md) | `DNL-01` ~ `DNL-16` |
| 路由引擎 | [routing.md](./routing.md) | `RTE-01` ~ `RTE-08` |
| 帧层对抗 | [security/frame-attacks.md](./security/frame-attacks.md) | `SEC-01` ~ `SEC-11` |
| 控制面对抗 | [security/control-plane-attacks.md](./security/control-plane-attacks.md) | `SEC-12` ~ `SEC-20` / `SEC-29` / `SEC-30` / `SEC-32` |
| 租户边界 | [security/tenancy.md](./security/tenancy.md) | `SEC-21` ~ `SEC-28` / `SEC-31` |
| 管理面与配置 | [admin.md](./admin.md) | `ADM-01` ~ `ADM-09` |
| 日志治理 | [admin.md](./admin.md) | `LOG-01` ~ `LOG-03` |
| 跨接入联动 | [integration.md](./integration.md) | `E2E-01` ~ `E2E-08` |

## 4. 验收矩阵（REQ ↔ 场景 ↔ 状态 ↔ 证据）

| REQ | 场景 | 状态 | 证据/CI |
|---|---|---|---|
| REQ-001 | FRM-01 / FRM-04 | 已覆盖 | rill-core/src/frame/、rill-core/src/handshake/ |
| REQ-002 | FRM-02 | 已覆盖 | rill-core/src/crypto/、rill-mesh/src/data/ |
| REQ-003 | FRM-02 | 已覆盖 | rill-mesh/src/data/ |
| REQ-004 | CTL-01 | 已覆盖 | rill-mesh/src/control/、e2e/run_e2e.sh |
| REQ-005 | E2E-05 | 待补充 | mesh exit WAN 透传未实现（RTE-06） |
| REQ-006 | TSL-01 | 已覆盖 | e2e/p0_tailscale/run_p0.sh |
| REQ-007 | CON-01 ~ CON-06 | 已覆盖 | e2e/run_e2e.sh、e2e/mesh/probe/、rill-core/src/probe.rs、rill-coord/src/echo.rs、rilld/src/coord_run.rs |
| REQ-008 | CTL-10 / CTL-11 | 已覆盖 | rill-core/src/control/registry.rs、rill-coord/src/liveness.rs、rill-coord/src/coordinator/、rill-node/src/runtime/control.rs |
| REQ-009 | RTE-07 | 已覆盖 | rill-node/src/packet/mtu.rs、e2e/scenarios/mtu.sh |
| REQ-010 | CTL-09 / SEC-21 ~ SEC-25 | 已覆盖 | e2e/run_e2e.sh、e2e/mesh/tenancy/、rill-coord/src/domain.rs、rill-coord/src/coordinator/ |
| REQ-011 | FRM-06 | 已覆盖 | rill-core/src/handshake/ |
| REQ-012 | E2E-01 ~ E2E-08 | 部分覆盖 | E2E-01/02/04 经 TSL-05、TSL-06/07、DNL-14/16 覆盖（e2e/ts2021_*、e2e/scenarios/dn42.sh）；E2E-03/05~08 待补 |
| REQ-013 | CTL-13 | 已覆盖 | rill-core/src/control/ |
| REQ-014 | CTL-13 / CON-07 / CON-08 / RTE-08 | 部分覆盖 | rill-mesh/src/data/、rill-core/src/probe.rs（CON-08 已闭环；RTE-08 exit 语义待 mesh exit） |
| REQ-015 | DNL-01 ~ DNL-16 | 已覆盖 | rill-dn42/src/、rill-node/src/runtime/dn42.rs、e2e/mesh/dn42/、e2e/scenarios/dn42.sh |
| REQ-016 | SEC-03 / SEC-04 / SEC-09 / SEC-10 | 部分覆盖 | SEC-09/10 单测已闭环（rill-core/src/handshake/）；SEC-03/04 容器级复验待补 |
| REQ-017 | SEC-01 / SEC-02 / FRM-07 | 部分覆盖 | SEC-05/07/08 单测已闭环（rill-mesh/src/data/、rill-core/src/frame/）；SEC-01/02/11 容器级复验待补 |
| REQ-018 | CTL-13 | 已覆盖 | rill-core/src/control/challenge.rs |
| REQ-019 | — | — | — |
| REQ-020 | SEC-28 | 已覆盖 | rill-core/src/route/、rill-coord/src/coordinator/ |
| REQ-021 | TSL-01 ~ TSL-12 | 部分覆盖 | TSL-04~08/10~12 已闭环（e2e/ts2021_register、e2e/ts2021_runtime）；TSL-02/03/09 真机/官方 infra 挂账 |
| REQ-022 | CTL-13 / SEC-16 | 已覆盖 | rill-core/src/control/ |
| REQ-023 | RTE-01 ~ RTE-04 | 已覆盖 | rill-core/src/route/ |
| REQ-024 | CTL-01 / CTL-08 | 已覆盖 | rill-coord/src/ |
| REQ-025 | — | — | rill-node/src/config/ |
| REQ-026 | — | — | rill-node/src/ |
| REQ-027 | CTL-01 | 已覆盖 | rill-mesh/src/control/ |
| REQ-028 | FRM-09 | 已覆盖 | rill-mesh/src/data/ |
| REQ-029 | FRM-04 / FRM-06 / SEC-05 ~ SEC-10 | 已覆盖 | rill-core/src/handshake/ |
| REQ-030 | FRM-11 | 已覆盖 | rill-node/src/runtime/ |
| REQ-031 | E2E-01 / FRM-10 | 已覆盖 | e2e/run_e2e.sh、e2e/ts2021_runtime（E2E-01 手机侧替身） |
| REQ-032 | FRM-08 / FRM-10 | 已覆盖 | e2e/run_e2e.sh、[mesh/frame.md](./mesh/frame.md) |
| REQ-033 | TSL-01 | 已覆盖 | e2e/p0_tailscale/run_p0.sh |
| REQ-034 | CTL-15 | 已覆盖 | rill-core/src/frame/、rill-coord/src/path_service.rs、rill-mesh/src/data/、e2e/run_e2e.sh、e2e/mesh/relay/ |
| REQ-035 | FRM-08 / CTL-14 | 已覆盖 | rill-coord/src/coordinator/、rill-mesh/src/data/、rill-node/src/runtime/、e2e/setup.sh |
| REQ-036 | ADM-04 / ADM-05 | 已覆盖 | rill-coord/src/config/、rill-core/src/control/registry.rs |
| REQ-037 | CTL-16 | 已覆盖 | rill-coord/src/store/、rill-coord/src/coordinator/、e2e/run_e2e.sh、e2e/mesh/persist/ |
| REQ-038 | ADM-01 / ADM-02 | 已覆盖 | rill-coord/src/config/、rill-core/src/control/registry.rs、e2e/run_e2e.sh |
| REQ-038 | ADM-03 | 已覆盖 | rilld/src/main.rs、e2e/run_e2e.sh、e2e/mesh/reload/ |
| REQ-039 | LOG-01 / LOG-02 / LOG-03 | 已覆盖 | rilld/src/logging.rs、rill-core/src/rate.rs、rill-mesh/src/data/、e2e/mesh/log/ |
| REQ-040 | — | 📌 proposed（无验收场景） | — |
| REQ-041 | — | 📌 proposed（无验收场景） | — |
| REQ-042 | ADM-06 | 部分覆盖 | e2e/Dockerfile、e2e/run_e2e.sh、rilld/src/main.rs（systemd 托管自动化缺环境） |
| REQ-043 | CTL-17 | 已覆盖 | rill-coord/src/config/、rill-coord/src/coordinator/、rilld/src/main.rs |
| REQ-044 | — | 📌 proposed（无验收场景；尾款 = release 阶段依赖最小化） | — |
| REQ-045 | SEC-28 / SEC-31 | 已覆盖 | rill-core/src/control/acl.rs、rill-coord/src/config/、rill-coord/src/coordinator/、rill-mesh/src/control/、rill-node/src/runtime/、e2e/scenarios/acl.sh |
| REQ-046 | SEC-07 / SEC-26 / CON-10 | 已覆盖 | rill-node/src/runtime/、rill-mesh/src/data/、rill-core/src/rate.rs、rill-core/src/probe.rs、e2e/run_e2e.sh（probe 场景） |
| REQ-047 | SEC-20 / SEC-29 | 已覆盖 | rill-mesh/src/control/server.rs、rill-node/src/runtime/、rill-coord/src/path_service.rs、rilld/src/coord_run.rs |
| REQ-048 | SEC-32 | 已覆盖 | rill-coord/src/keys.rs、rill-coord/src/coordinator/ |
| REQ-049 | — | 📌 proposed（②已随 REQ-070 阶段三覆盖 CTL-24；①③未落地） | — |
| REQ-050 | ADM-09 | 已覆盖 | scripts/verify-repro.sh、.github/workflows/repro.yml（main） |
| REQ-051 | ADM-07 | 已覆盖 | rill-coord/src/status.rs、rilld/src/coord_run.rs、e2e/mesh/status/、e2e/scenarios/status.sh |
| REQ-069 | ADM-08 | 已覆盖 | rilld/src/status_http.rs、e2e/scenarios/status.sh |
| REQ-070 | CTL-12 / CTL-22 / CTL-23 / CTL-24 | 已覆盖（三阶段：单机过日志 + 3 副本集群 + binding v2 交叉审计） | rill-coord/src/raft/、e2e/scenarios/ha.sh、e2e/mesh/ha/ |
| REQ-052 | CTL-21 | 已覆盖 | rill-mesh/src/data/、rill-coord/src/coordinator/、rill-coord/src/status.rs、e2e/scenarios/status.sh |
| REQ-053 | FRM-12 | 已覆盖 | rill-core/src/frame/、rill-mesh/src/data/tests.rs |
| REQ-054 | CON-11 | 已覆盖 | rill-mesh/src/data/、rill-node/src/runtime/、e2e/run_e2e.sh（MESH_E2E_TRANSPORT=tcp） |
| REQ-055 | — | 📌 proposed（无验收场景） | — |
| REQ-061 | — | 📌 proposed（无验收场景） | — |
| REQ-062 | CTL-25 | 已覆盖 | rill-coord/src/coordinator/、rill-coord/src/path_service.rs、rill-coord/src/directory.rs、rilld/src/coord_run.rs、e2e/scenarios/relay.sh、e2e/scenarios/probe.sh |
| REQ-063 | — | 📌 proposed（无验收场景） | — |
| REQ-064 | CTL-26 | 已覆盖 | rill-coord/src/path_service.rs、rill-mesh/src/data/、e2e/scenarios/probe.sh |
| REQ-065 | DNL-16 | 已覆盖 | rill-coord/src/route_map.rs、rill-node/src/runtime/route_report.rs、rill-node/src/runtime/control.rs、e2e/scenarios/dn42.sh |
| REQ-067 | TSL-11 | 已覆盖 | rill-ts2021/src/tailcfg.rs、rill-node/src/runtime/ts2021.rs、e2e/ts2021_runtime/run.sh |
| REQ-068 | TSL-12（ts2021-leg）+ ts2021_runtime e2e 切自研服务端 | ✅ 已覆盖 | CI：e2e-ts2021 |
| REQ-056 | CTL-18 | 已覆盖 | rill-node/src/runtime/reconnect.rs、e2e/mesh/recover/、e2e/scenarios/recover.sh |
| REQ-057 | CTL-19 | 已覆盖 | rill-core/src/control/、rill-mesh/src/control/、rill-coord/src/coordinator/、e2e/scenarios/recover.sh |
| REQ-058 | SEC-30 | 已覆盖 | rill-core/src/control/registry.rs、e2e/scenarios/recover.sh |
| REQ-059 | SEC-08 | 已覆盖 | rill-core/src/frame/、rill-mesh/src/data/、e2e/mesh/preauth_flood/、e2e/scenarios/preauth_flood.sh |
| REQ-060 | CTL-20 | 已覆盖 | rill-coord/src/coordinator/、rill-mesh/src/control/、e2e/scenarios/recover.sh |
| REQ-066 | FRM-12 | 已覆盖 | rill-core/src/frame/、rill-mesh/src/data/tests.rs |

## 5. 维护规则

- 新增场景：ID 域内递增，不重复使用；一条 merged 需求至少对应一个场景
- 状态更新：AI 经 `gh run watch` 确认 CI 结果后更新状态与证据；**已覆盖必须有存在的证据文件**
- 验收断言在场景文件**尾部**汇总（随行为变更一起 diff）
- `ci/check-docs.sh` 校验：ID 唯一、REQ 引用存在、已覆盖有证据
