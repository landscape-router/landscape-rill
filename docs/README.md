# landscape-rill 文档中心

> 多接入 rill ext 节点（单 TUN 用户态路由器）的规格、需求与验收。本文档是入口：先看阅读路线，再按需进各目录。

## 阅读路线（新 session 入口）

1. **[CONTEXT.md](./CONTEXT.md)**——前置知识：项目定位、术语表、信任模型、路线图、文档地图（决策时间线已迁移为 [requirements/](./requirements/README.md)）
2. **[design/](./design/README.md)**——系统行为权威描述（分域）：架构、mesh 协议、接入、路由引擎
3. **[requirements/](./requirements/README.md)**——需求/决策库：每条需求何时提出、是否已合并进 design
4. **[tests/](./tests/README.md)**——验收场景与状态（四档）、验收矩阵、验收断言
5. **[perf.md](./perf.md)**——性能基线与回归对照（证据类：基准分层 L1~L4、复跑方法、A/B 结果）
6. **[e2e/](./e2e/README.md)**——全链路容器验证环境与脚本说明
7. **[ci/](./ci/README.md)**——CI 结构与一致性检查（`ci/check-docs.sh`）
8. **[lessons/](./lessons/README.md)**——外部缺陷教训库（防回归复核表，独立于演进体系）

## 三张图怎么用

| 图 | 位置 | 回答什么问题 |
|---|---|---|
| 需求状态表 | [requirements/README](./requirements/README.md) | 系统行为从哪些需求/决策来？哪些还挂着没定？ |
| spec 地图 | [design/README](./design/README.md) | 某子系统行为写在哪？短名（如 `FRAME_HEADER §2.6`）指向哪个文件？ |
| 验收矩阵 | [tests/README](./tests/README.md) | 每条行为是否已落地、是否已验收、证据在哪？ |

## 演进工作流（新增/修改行为）

```
提出：requirements/REQ-NNN（proposed + 验收标准草案）
  → 合并：内容搬入 design/ 对应章节（stub 瘦身留动机+指针）
  → 验收：tests/ 补场景（待补充）→ 实现 → CI 绿（gh 确认）→ 更新状态+证据
  → 校验：改动后运行 ci/check-docs.sh
```

详见 [AGENTS.md](../AGENTS.md) 与 [ci/README.md](./ci/README.md)。

## 版本规范

- 所有设计/需求/测试文档头部含版本号与最近修改时间（日级精度，如 2026-08-30）
- 变更历史不入文档，git 记录为准
