# REQ-042 lrill CLI 与 daemon 托管（二进制改名 + clap 子命令）

> 类型：需求 ｜ 状态：📌 proposed ｜ 优先级：P0 ｜ 依赖：— ｜ 提出：2026-08-30

## 动机

现状 CLI 为手写 args 解析（`landscape-rill --pubkey <seed>` / `landscape-rill [config]`），无子命令结构、无守护进程控制面。目标：最终产物为 `lrill`，用户用 `lrill` 控制节点（tailscale/wg-quick 形态）。workspace 重构（REQ 提出时已随结构落地：`[[bin]] name = "lrill"` + clap 骨架）。

## 决策摘要（方向）

- 二进制名 `landscape-rill` → **`lrill`**；包名 `landscape-rill`（bin crate 目录 `rilld/`）不变
- CLI 用 **clap 4（derive）**：子命令骨架 `pubkey <seed>`（Ed25519 公钥工具）与 `run [config]`（前台 daemon，容器/开发形态）
- **daemon 托管 = systemd 优先**：`lrill up/down/status` 走 systemctl（unit 模板生成/安装），日志、自启、崩溃重启归服务管理器；**无 systemd 场景 = 前台 `lrill run`**（容器 ENTRYPOINT、开发）
- 明确否决：v1 不做自守护 + unix socket（SSH session 退出即 SIGHUP 的坑、多线程 fork 时序、容器 PID1 生命周期冲突）；等"非 systemd 环境需要状态查询/精细控制"的真实需求出现再开 REQ（tailscale localapi 风格）
- 管理面形态（REQ-038）与 `lrill` 命令的关系：REQ-038 定稿时纳入

## 验收标准（草案）

- 产物名 `lrill`；`lrill --help` 展示 `pubkey`/`run` 子命令
- `lrill pubkey <seed_hex>` 输出 Ed25519 公钥（与旧 `--pubkey` 一致）；非法 seed 非零退出
- `lrill run [config]` 行为与旧二进制等价（缺省 /etc/landscape/overlay.json；node/coord 双角色）
- `lrill up` 生成并安装 systemd unit + 启动；`lrill down` 停止；`lrill status` 显示运行状态（无 systemd 时明确报错并提示 `lrill run`）
- 容器形态：ENTRYPOINT 用 `lrill run`（e2e/run_e2e.sh + Dockerfile 证据）
