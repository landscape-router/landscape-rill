# CI 与文档一致性（ci）

> 本目录承载：CI 结构说明 + `check-docs.sh` 一致性检查。

## 1. CI 结构（当前无 workflow，规划）

| 层 | 入口 | 频率 |
|---|---|---|
| Rust 单元测试 | `cargo test`（fmt/clippy 同批） | PR / push |
| 文档一致性 | `ci/check-docs.sh` | PR / push |
| docker e2e | `e2e/run_e2e.sh` | push / 手动 |
| P0 过渡验证 | `e2e/p0_tailscale/run_p0.sh` | 手动 / 低频 |

验收状态更新约定：**AI 经 `gh run watch` 确认 CI 结果后更新 tests/ 场景状态与证据列**（CI 持续绿即验收），人工可读、证据可复核。

## 2. check-docs.sh 检查规则

1. **场景 ID 唯一**：tests/ 中 `## <PREFIX>-NN` 无重复
2. **REQ 引用存在**：tests/ 矩阵与各场景关联的 REQ-NNN 必须存在于 requirements/
3. **merged 必有去向**：状态为 merged 的 REQ stub 必须含 `去向：<短名> §<x.y>`，且短名注册、章节标题存在
4. **proposed 必有优先级**：状态为 proposed 的 REQ 必须含 `优先级：P0/P1/P2`
5. **proposed 依赖存在**：状态为 proposed 的 REQ 的 `依赖` 字段引用的 REQ-NNN 必须存在于 requirements/
6. **已覆盖必有证据**：状态为 `已覆盖` 的场景必须引用存在的证据文件
7. **注释短名契约**：各 crate 源码注释中的 `<短名> §<x.y>` 必须注册于 design/README.md 且章节存在
8. **链接完整性**：docs/ 内相对 .md 链接全部可解析

## 3. 使用

```sh
./docs/ci/check-docs.sh     # 从仓库根运行
```

退出码非 0 时按消息逐条修复；规则 3/7 的章节校验按文档编号标题（`### 2.6 ...`）匹配。
