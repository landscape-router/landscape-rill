# REQ-070 coordinator Raft 高可用集群

> 类型：需求 ｜ 状态：✅ merged ｜ 提出：2026-10-01 ｜ 合并：2026-10-01
> 去向：CONTROL_PLANE §1.2/§3.6/§5.6/§3.16 ｜ 验收场景：CTL-12 / CTL-22 / CTL-23 / CTL-24 ｜ lessons：CP-03/CP-05

## 动机

coordinator 是单点：进程重启丢软状态（v1 自愈：节点重连/心跳重建），但宕机期间注册/吊销/路径全不可用。CONTROL_PLANE §4 状态模型从第一天按 Raft 兼容设计（持久/软/派生三分类 + 写路径单一 + 客户端操作幂等），§1.2/§3.6/§5.6 预留了演进路径（LeaderRedirect/软状态重建/KeyDist 补发）。引入 Raft 附带解锁 REQ-049 ②层（签发溯源：netmap/身份绑定绑定 log index/term，交叉验证检测 split-view）。

## 决策摘要

1. **openraft 0.9**（依赖最小化张力明示豁免——同 axum 口径，REQ-044）：Coordinator 作为状态机，全部写方法经日志提案 → 按序 apply；读路径 v1 留 leader 本地（ReadIndex 线性化读推迟）
2. **分阶段**：阶段一单机过日志（行为等价回归门槛）→ 阶段二 3 副本静态成员集群（`cluster` 配置段；副本间 mTLS；follower 写拒绝回 LeaderRedirect；leader 宕机选新主 + 幂等重注册 + 接管软状态重置 + KeyDist 按需补发；连接建立后台化保 failover 窗口数据面零停摆）→ 阶段三 binding v2 签发锚点 + 交叉审计（REQ-049②，§3.16）
3. **静态成员**：变更 = 改配置 + 按序重启；动态 add/remove learner 不做；多 coordinator_url 维持单 URL（重定向链已提供 failover 端点学习）
4. **节点侧配套**：租约看门狗（granted LEASE 记账，静默僵死主动断开）+ SIGTERM 优雅退出（close_notify + 500ms 宽限 exit(0) 兜底）
5. 日志/快照存储于 redb 之上（不引第二存储引擎）；状态快照 + last_applied + membership 同事务原子写（恰好一次 apply）

## 去向

- **CONTROL_PLANE §1.2**：静态成员集群形态与 mTLS
- **CONTROL_PLANE §3.6**：LeaderRedirect（写拒绝 + leader 提示；审计端点例外）
- **CONTROL_PLANE §5.6**：主切换流程（接管软状态重置/重连分片/连接建立后台化/数据面不中断）
- **CONTROL_PLANE §3.16**：binding v2 签发锚点与交叉审计
- 验收场景：CTL-22（单机过日志）、CTL-12（进程内 3 副本）、CTL-23（ha e2e 五阶段）、CTL-24（交叉审计）
