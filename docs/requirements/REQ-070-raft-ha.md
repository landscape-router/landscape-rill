# REQ-070 coordinator Raft 高可用集群

> 类型：需求 ｜ 状态：📌 proposed ｜ 优先级：P3 ｜ 依赖：REQ-037 ｜ 提出：2026-10-01
> （方向已确认：引入 Raft，openraft 为候选库——CONTEXT §8 关键 crate 候选）

## 动机

coordinator 是单点：进程重启丢软状态（v1 自愈：节点重连/心跳重建），但宕机期间注册/吊销/路径全不可用。CONTROL_PLANE §4 状态模型从第一天按 Raft 兼容设计（持久/软/派生三分类 + 写路径单一 + 客户端操作幂等），§1.2/§3.6/§5.6 预留了演进路径（LeaderRedirect/软状态重建/KeyDist 补发）。用户已确认引入 Raft；附带解锁 REQ-049 ②层（签发溯源：netmap/身份绑定绑定 log index/term，交叉验证检测 split-view）。

## 决策摘要（分阶段落地）

1. **openraft**（CONTEXT §8 候选；依赖最小化张力明示豁免——同 axum 豁免口径，REQ-044）：Coordinator 作为状态机，全部写方法（register/revoke/set_endpoints/request_paths/rotate_master_key/flush_revoke_rotations）经日志提案 → 按序 apply；读路径 v1 留 leader 本地（单写者一致性已足，ReadIndex 线性化读推迟）
2. **阶段一（单机过日志）**：openraft 单节点集群，写路径改经提案/apply——行为等价回归（现有 453 测试全绿为门槛），日志/快照存储实现于 redb 之上（不引第二存储引擎）
3. **阶段二（3 副本集群）**：静态成员配置（`cluster` 配置段：peer 地址列表）；副本间 mTLS（§1.2）；follower 收到节点连接 → LeaderRedirect（§3.6）；leader 宕机 → 剩余节点选出新主，节点重连幂等重注册（§5.6）+ 软状态重建 + KeyDist 按需补发
4. **阶段三（REQ-049 ②层）**：netmap/身份绑定签名绑定 (log_index, term)；节点可向任意副本交叉验证 → 定向伪造可检测
5. **写路径时延预算**：注册/吊销等交互路径经多数派提交（v1 同城/低 RTT 假设；跨域联邦仍 v2 话题，不受本需求影响）

## 开放问题（各阶段立项评审拍板）

1. ~~openraft 版本与 storage trait 对接细节~~ **已定（阶段一落地）**：openraft 0.9.25（features：serde/storage-v2/generic-snapshot-data），RaftLogStorage/RaftStateMachine v2 trait；日志/vote 独立 redb 文件（键 = log index），快照数据 = CoordState 序列化字节（与状态文件同格式）；状态快照 + last_applied + last_membership 在状态文件**同事务**原子写（恰好一次 apply）；~~
2. 成员变更（静态 vs 动态 add/remove learner）——v1 建议：静态配置 + 重启变更
3. 拓扑探测/echo（RTT 排序 relay_list）在副本间是否复制（软状态倾向：各副本本地跑）
4. status/admin 端点（REQ-051/069）在 follower 上的语义：只读代理到 leader or 本地陈旧快照
5. （阶段二遗留）register/request_paths 内部取墙钟（auth key 过期判定 / PathSet TTL expires_at）——跨副本确定性需线程化 now 参数（单机重放按同秒粒度收敛，测试已按归一化比较）

## 验收标准（草案）

- 阶段一：全部现有测试语义等价通过；写操作产生日志条目（apply 顺序 = 提交顺序）——**✅ 已覆盖（CTL-22，rill-coord/src/raft/tests.rs：等价/重启/崩溃重放恰好一次/REQ-048 窗口/日志边界/手动快照）**
- 阶段二 e2e：3 副本——follower 直连返回 LeaderRedirect；kill leader 后 ≤ 选主超时内新主可写；旧 leader 回归为 follower；节点全程数据面不中断（§4.3）、重连后软状态重建
- 阶段二：持久状态经多数派复制（任一副本单独存活可恢复全量注册表）
- 阶段三：伪造 netmap（未进日志的签名）交叉验证被拒
- 回归：REQ-048 合并轮换窗口、REQ-047 限速、REQ-045 ACL 在日志复制下语义不变

## 关联

- 依赖：REQ-037（已 merged → CONTROL_PLANE §4.1；持久快照格式与写穿透）
- 关联：REQ-049（②层基座）、REQ-069（写端点复用单一写路径）、CONTROL_PLANE §1.2/§3.6/§5.6/§6（mTLS/重定向/切换/信任模型）
