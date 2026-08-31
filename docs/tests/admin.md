# 管理面与配置验证（admin）

> 管理面（配置与执行分离）、auth key、lrill CLI 的验收场景。
> 设计规范：CONTROL_PLANE §3.12（[../design/mesh/control-plane.md](../design/mesh/control-plane.md)）。

## ADM-01 配置加载即校验（fail-closed）

- 关联 REQ：REQ-038
- 测试层：单测
- 状态：`已覆盖`
- 证据：rill-coord/src/config.rs

## ADM-02 前缀公告白名单

- 关联 REQ：REQ-038
- 测试层：单测 + docker e2e
- 状态：`已覆盖`
- 证据：rill-core/src/control/registry.rs、e2e/run_e2e.sh
- 缺口：白名单变更后新注册按新白名单裁决的集成验证

## ADM-03 配置重载（SIGHUP 增量生效）

- 关联 REQ：REQ-038
- 测试层：集成
- 状态：`部分覆盖`
- 证据：rilld/src/main.rs
- 缺口：SIGHUP 重载集成测试未自动化（手动验证：重载成功增量生效 / 重载失败保持旧配置）；tokio Signal 首次 poll 才注册监听的启动窗口有注释说明

## ADM-04 auth key 格式与生成

- 关联 REQ：REQ-036
- 测试层：单测 + CLI
- 状态：`已覆盖`
- 证据：rill-coord/src/config.rs、rilld/src/main.rs

## ADM-05 auth key 生命周期（过期/吊销闭环）

- 关联 REQ：REQ-036
- 测试层：单测 + 集成
- 状态：`已覆盖`
- 证据：rill-core/src/control/registry.rs、rill-coord/src/config.rs

## ADM-06 lrill CLI 与 daemon 托管

- 关联 REQ：REQ-042
- 测试层：CLI + docker e2e
- 状态：`部分覆盖`
- 证据：e2e/Dockerfile、e2e/run_e2e.sh、rilld/src/main.rs
- 缺口：up/down/status（systemd 托管）无自动化测试（需真 systemd 环境）；无 systemd 报错提示未自动化验证

#### 验收断言（文件尾部汇总）

- [x] ADM-01：缺失必填/格式非法配置 → 拒绝启动（fail-closed，无默认凭据）
- [x] ADM-02：白名单外公告 → RegisterError::RouteNotAllowed（不部分采纳）；白名单内 → 注册成功；`/8` 以下 IPv4、`/32` 以下 IPv6 → 拒绝；白名单变更不影响已注册节点
- [ ] ADM-03：SIGHUP 重载后新 auth key 可注册、移除 key 即刻失效、白名单变更对新注册生效；重载失败保持旧配置 + 日志报错（手动验证，未自动化）
- [x] ADM-04：`lrk-<network>-<base32>` 生成/解析/校验正确；非 lrk 前缀与 network 不匹配被拒；生成不落日志
- [x] ADM-05：reusable 带 expires_at 过期即 InvalidAuthKey；onetime 注册即弃；配置移除 + 重载 = 吊销闭环
- [ ] ADM-06：`lrill --help` 展示 pubkey/run/authkey/up/down/status；up/down/status 走 systemctl；无 systemd 明确报错提示 `lrill run`；Dockerfile ENTRYPOINT = `lrill run`（部分未自动化）
