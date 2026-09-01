# REQ-053 数据面 I/O 优化（缓冲复用与拷贝消除）

> 类型：决策 ｜ 状态：✅ merged ｜ 提出：2026-09-01 ｜ 合并：2026-09-01 ｜ 去向：FRAME_HEADER §2.2/§8 ｜ 验收场景：FRM-12

## 动机

数据面热路径是"朴素 Vec 直给"风格，每包存在可避免的分配与拷贝：UDP `recv_frame` 每包 64KB 零初始化分配、TUN 每包分配（零复用）；单播发送 4 次 memcpy / 3 次堆分配（`seal` 的 `to_vec` + `build_frame` 组装）；relay/broadcast 为 TTL 递减 1 字节做整帧 `to_vec()`；帧头偏移魔法数字散落，roundtrip 测试测不出 encode/decode 对称漂移。

## 决策摘要

`bytes` 缓冲复用（`MeshData`/TUN 内部 `BytesMut`，公共签名不变）+ crypto 原地化（`seal_in_place`/`open_in_place`，旧接口保留薄封装；AEAD 失败不改动缓冲——先验 tag 后解密，rekey 兜底依赖）+ 转发原地 ttl-1 零拷贝扇出 + MAX_FRAME 接收上限（超长显式丢弃）+ golden vectors 钉死帧格式 + WAN socket 触点收拢为函数级接缝（P4 XDP 快速路径预留，明确不引入 trait、不引入 zerocopy crate）。

- 教训对照：FS-01（帧头仍全量进 AAD——in-place 不改认证输入，golden vectors 钉死）、FS-04（无绕过 AEAD 的路径——in-place 实现与旧接口对拍等价）
