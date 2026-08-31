# REQ-042 lrill CLI 与 daemon 托管（二进制改名 + clap 子命令）

> 类型：需求 ｜ 状态：✅ merged ｜ 提出：2026-08-30 ｜ 合并：2026-08-31 ｜ 去向：CONTROL_PLANE §3.12 ｜ 验收场景：ADM-06

## 动机

现状 CLI 为手写 args 解析，无子命令结构、无守护进程控制面。目标：最终产物为 `lrill`，用户用 `lrill` 控制节点（tailscale/wg-quick 形态）。

## 决策摘要

二进制 `lrill` + clap 4（derive）：`pubkey <seed>` / `run [config]`（前台 daemon，容器/开发形态）/ `authkey`（生成，REQ-036）/ `up|down|status`（systemd 托管，unit 模板生成安装，无 systemd 报错提示 `lrill run`）。**daemon 托管 = systemd 优先**；明确否决 v1 自守护 + unix socket。执行面 = 薄调用层（配置与执行分离见 §3.12）。
