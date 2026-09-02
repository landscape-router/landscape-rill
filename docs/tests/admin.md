# 管理面与配置验证（admin）

> 管理面（配置与执行分离）、auth key、lrill CLI 的验收场景。
> 设计规范：CONTROL_PLANE §3.12（[../design/mesh/control-plane.md](../design/mesh/control-plane.md)）。

## ADM-01 配置加载即校验（fail-closed）

- 关联 REQ：REQ-038
- 测试层：单测
- 状态：`已覆盖`
- 证据：rill-coord/src/config/

## ADM-02 前缀公告白名单

- 关联 REQ：REQ-038
- 测试层：单测 + docker e2e
- 状态：`已覆盖`
- 证据：rill-core/src/control/registry.rs、e2e/run_e2e.sh
- 缺口：白名单变更后新注册按新白名单裁决的集成验证

## ADM-03 配置重载（SIGHUP 增量生效）

- 关联 REQ：REQ-038
- 测试层：集成 + docker e2e
- 状态：`已覆盖`
- 证据：rilld/src/main.rs、e2e/run_e2e.sh、e2e/mesh/reload/
- 说明：e2e reload 场景四阶段——①基线 a↔b 双栈通；②coord.json 追加 auth key → SIGHUP → 新 key 注册成功（增量生效）；③写坏配置 → SIGHUP → 日志 "reload failed, keeping old config" + 数据面不受影响；④移除 key → SIGHUP → 即刻失效（新节点注册被拒）。注：bind mount 配置文件不可用 `sed -i` 修改（rename 断 inode，容器仍读旧文件），须临时文件 + cp 原址覆盖

## ADM-04 auth key 格式与生成

- 关联 REQ：REQ-036
- 测试层：单测 + CLI
- 状态：`已覆盖`
- 证据：rill-coord/src/config/、rilld/src/main.rs

## ADM-05 auth key 生命周期（过期/吊销闭环）

- 关联 REQ：REQ-036
- 测试层：单测 + 集成
- 状态：`已覆盖`
- 证据：rill-core/src/control/registry.rs、rill-coord/src/config/

## ADM-06 lrill CLI 与 daemon 托管

- 关联 REQ：REQ-042
- 测试层：CLI + docker e2e
- 状态：`部分覆盖`
- 证据：e2e/Dockerfile、e2e/run_e2e.sh、rilld/src/main.rs
- 缺口：up/down/status（systemd 托管）无自动化测试（需真 systemd 环境）；无 systemd 报错提示未自动化验证

## LOG-01 daemon 日志级别配置生效性

- 关联 REQ：REQ-039
- 测试层：CLI + docker e2e
- 状态：`已覆盖`
- 证据：rilld/src/logging.rs、e2e/mesh/log/docker-compose.yaml、e2e/run_e2e.sh
- 说明：优先级 CLI > env > 默认——`--log-level debug` 覆盖 `RUST_LOG=error`（debug 明细出现）；仅 `RUST_LOG=error` 时 info 级（`registered:`）不出；默认 `info` 时 `endpoint report`（debug）不出

## LOG-02 高频事件周期摘要

- 关联 REQ：REQ-039
- 测试层：单测 + 集成
- 状态：`已覆盖`
- 证据：rill-core/src/rate.rs、rill-mesh/src/data/
- 说明：RateCounter tick/poll 周期语义（rate.rs 单测）；丢帧收口计数 per-peer/全局桶归因、伪造 node_id 不落 per-peer（data.rs drop_stats_attribution_and_summary_filter）；摘要输出 ≤1 条/s、0 不输出

## LOG-03 文件轮转与容量上限

- 关联 REQ：REQ-039
- 测试层：CLI + docker e2e
- 状态：`已覆盖`
- 证据：rilld/src/logging.rs、e2e/mesh/log/docker-compose.yaml、e2e/run_e2e.sh
- 说明：`lrill run --log-file <path>` > `LRILL_LOG_FILE` > 默认无；生成按天轮转文件（`<prefix>.<YYYY-MM-DD>`）、保留最多 7 个、stderr 仍输出（双写）

## ADM-07 coord 只读状态端点（HTTPS + 管理密码）

- 关联 REQ：REQ-051
- 测试层：单测 + docker e2e
- 状态：`已覆盖`
- 证据：rill-coord/src/status.rs、rill-coord/src/coordinator/tests.rs、e2e/scenarios/status.sh
- 说明：无密码/错密码 → 401；同源高频错密码 → 429（按源限速）；SIGHUP 轮换密码旧拒新通；https 可达、明文 HTTP 被拒；快照方法与 coord 内存态一致（多网络/离线节点/一次性 key 已消费分支）；`status` 启用而密码哈希缺失/非法 → 拒绝启动；红线：密钥材料只出"已配置 + 指纹"。CI：e2e-mesh status（run 33697089991）

#### 验收断言（文件尾部汇总）

- [x] ADM-01：缺失必填/格式非法配置 → 拒绝启动（fail-closed，无默认凭据）
- [x] ADM-02：白名单外公告 → RegisterError::RouteNotAllowed（不部分采纳）；白名单内 → 注册成功；`/8` 以下 IPv4、`/32` 以下 IPv6 → 拒绝；白名单变更不影响已注册节点
- [x] ADM-03：SIGHUP 重载后新 auth key 可注册、移除 key 即刻失效、重载失败保持旧配置 + 日志报错 + 数据面不中断（e2e reload 场景）
- [x] ADM-04：`lrk-<network>-<base32>` 生成/解析/校验正确；非 lrk 前缀与 network 不匹配被拒；生成不落日志
- [x] ADM-05：reusable 带 expires_at 过期即 InvalidAuthKey；onetime 注册即弃；配置移除 + 重载 = 吊销闭环
- [ ] ADM-06：`lrill --help` 展示 pubkey/run/authkey/up/down/status；up/down/status 走 systemctl；无 systemd 明确报错提示 `lrill run`；Dockerfile ENTRYPOINT = `lrill run`（部分未自动化）
- [x] ADM-07：状态端点认证/限速/轮换/快照一致性 + fail-closed（REQ-051，状态：`已覆盖`）
- [x] LOG-01：RUST_LOG 级别生效性（debug 明细出现 / 默认 info 不出现）；CLI > env > 默认优先级
- [x] LOG-02：RateCounter 周期语义（tick 计数 / poll 周期返回并清零 / 0 不输出）；丢帧 per-peer 归因 + 伪造 node_id 落全局桶；摘要 ≤1 条/s
- [x] LOG-03：--log-file 按天轮转 + 保留上限 + stderr 双写
