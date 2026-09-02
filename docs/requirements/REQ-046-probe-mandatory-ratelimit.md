# REQ-046 probe 体系实现与强制限速/退避

> 类型：需求 ｜ 状态：✅ merged ｜ 提出：2026-09-01 ｜ 合并：2026-09-01 ｜ 去向：CONNECTIVITY §2.1/§2.2/§4.3 ｜ 验收场景：SEC-07 / SEC-26 / CON-10

## 动机

probe 体系设计已定稿（CONNECTIVITY §2/§2.1/§4，REQ-007/REQ-014/REQ-017）但实现挂账：CON-01（coordinator UDP 回显探测）、CON-03/CON-08（probe magic 分派）待实现，SEC-07/SEC-26 验证全待补充——netmap `endpoints[]` 上报依赖回显探测闭环。

设计滞后于教训：CONNECTIVITY §4.3 把 probe 洪泛防护写为"**可选**限速"，而教训 CN-01 明确要求"**强制**限速 + 指数退避（不是可选项）"——探测量 = 候选端点数 × 频率不收敛时，行为特征与扫描/攻击无法区分（被 IDS/风控误判，正常节点被误伤）。且 probe 无认证为有意设计（§4.3，会话建立前无认证链可用），无强制限速时恶意成员/伪造源地址者可借 probe 机制做反射放大（coordinator 回显）与行为特征污染。

## 决策摘要

实现 probe 全链（coordinator UDP 回显 + 端口分派 + 直连互探，落 CONNECTIVITY §2/§2.1/§4）；限速/退避升级为强制默认开启（§4.3 "可选限速" → 强制）：coordinator 回显按源 IP 令牌桶（§2.2）、互探发送侧强制限速（全局令牌桶 10/s 突发 20）+ 指数退避（30s×2^miss 封顶 300s）+ 在途并发上限 64、PONG 生成侧按源限速（10/s 突发 20，防反射放大）；`EchoLimiter` 泛化为 rill-core `SourceRateLimiter` 供 echo/PONG 共用。

- 教训对照：CN-01（限速升级为强制——已落档）、CN-02（fail-closed 解析）
