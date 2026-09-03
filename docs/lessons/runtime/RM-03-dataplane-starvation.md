# RM-03 数据面随控制面退避停摆

> 场景：运行时可靠性 ｜ 状态：需补 ｜ 复核时机：接入（leg）落地 / 主循环改动时

## 问题（现象）

主循环把控制面重连放在 select 之前：`connect_control` 失败 → 整段退避 sleep 内不进 select，
tun 读写 / mesh 事件 / dn42 leg 事件全部无人服务。控制面不可用越久，数据面饿死越久——
dn42-only 形态（无 coordinator）下数据面**永久停摆**；direct/relay 形态下 coord 瞬态不可达
也会造成分钟级转发中断。

## 原因

- 控制面可用性被隐式当作数据面前置条件——"单 TUN 汇合点、转发决策在用户态"的架构下
  数据面生命周期本不依赖控制面（mesh exit 语义、dn42 leg 均无 coordinator 参与）
- 退避等待（REQ-056）最初只轮转 pump_timers，未覆盖 I/O 服务
- leg 事件/明文走 channel，若泵只在主循环 select 分支里跑，任何主循环阻塞都变成 leg 阻塞

## 正确行为

- **数据面服务与控制面重连解耦**：退避等待分片内持续服务 tun 读 / mesh 事件 / leg 事件
  （`sleep_with_timers` 片内带超时读 tun + pump_dn42）
- leg 事件/明文 drain 为非阻塞（try_recv），挂在统一 100ms 节奏上
- 新增接入（leg）时必须回答："控制面完全不可用时，本 leg 的转发是否照常工作？"

## 复核触发点

接入（leg）落地 / 主循环改动时：

1. 控制面退避/断连路径上，tun 读、mesh 事件、各 leg 事件是否仍有消费方？
2. leg 的路由事件若延迟泵入，转发是否仍收敛（无永久黑洞）？

## 关联验证

docs/tests/legs/dn42.md（DNL-03：dn42-only 形态无 coordinator，转发可用即本教训的行为证明）
