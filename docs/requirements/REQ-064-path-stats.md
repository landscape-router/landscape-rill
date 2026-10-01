# REQ-064 逐路径统计与 PathProbe 激活

> 类型：需求 ｜ 状态：✅ merged ｜ 提出：2026-09-02 ｜ 合并：2026-10-01
> 去向：CONTROL_PLANE §3.11（统计与探活段）/§3.15 · FRAME_HEADER §2.7/§2.1 ｜ 验收场景：CTL-26 ｜ lessons：FS-01/FS-04/FS-09（新增包类型触发）+ CN-01（探活限速）

## 动机

路径选择（`pick_path`）与 failover 只有 miss 计数粗粒度健康，无 per-path 性能测量；v2 帧头携带 `path_id` + 会话 seq，接收侧被动统计零成本可做。空闲候选路径无数据流量、被动统计覆盖不到，需要活跃探测；协议原有 PathProbe 消息族（control Envelope）通道不可达（节点间唯一 Envelope 通道是各自 coord 连接，收到即报错）。REQ-052 心跳遥测已提供现成上报载体。

## 决策摘要

被动统计接收侧 `(peer, path_id)` 分桶（seq gap = 丢包/乱序，EWMA 千分比）；PathProbe 走**数据面帧 `packet_type 0x05`**（三选一的默认建议：骑 key_path/route_mac 认证、免会话，握手帧同模型），响应沿同路径反向；限速纪律沿 REQ-046（发送侧全局桶 + 在途上限、响应按源限速）；统计仅 advisory（只排序健康池，不改 miss/切换语义）；上报经 §3.15 paths 字段（仅携带有效区间）。开放问题裁定：①数据面帧；②EWMA 1/4 权重/无帧冷却 ×3/4；③seq 回绕按 wrapping diff 前向距离 < 2³¹ 判定。

## 去向

- CONTROL_PLANE §3.11（统计与探活段）+ §3.15（paths 字段）
- FRAME_HEADER §2.7（PATH_PROBE 帧规格）/ §2.1（type 0x05、flags bit0）
- 验收：CTL-26（[../tests/mesh/control-plane.md](../tests/mesh/control-plane.md)）

## Lessons 复核（新增包类型触发）

- FS-01：路由依据全部经 route_mac 认证域；载荷 nonce 不进 MAC——在途篡改仅等效丢帧（响应不匹配即弃），无能力放大
- FS-04：免会话仅限探活帧；数据/心跳仍走逐对 AEAD，无加密旁路开关
- FS-09：不新增传输通道——同帧路径同 underlay（选择数据面帧而非 probe 小包扩展的理由之一）
- CN-01：发送侧全局令牌桶 + 在途上限饱和拒绝 + 响应按源限速（REQ-046 纪律）
