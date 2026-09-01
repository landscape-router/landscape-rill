# REQ-053 数据面 I/O 优化（缓冲复用与拷贝消除）

> 类型：决策 ｜ 状态：📌 proposed ｜ 优先级：P1 ｜ 依赖：— ｜ 提出：2026-09-01

## 动机

数据面热路径是"朴素 Vec 直给"风格，每包存在可避免的分配与拷贝：

1. **读侧零复用**：UDP `recv_frame` 每包 `vec![0u8; 65535]`（64KB 零初始化 + 分配），TUN `read_packet` 每包分配 mtu+4，用完即弃
2. **加密与组装多付拷贝**：`crypto::seal` 的 `plaintext.to_vec()` + `build_frame` 的 `copy_from_slice` 组装——单播发送方向 4 次 memcpy / 3 次堆分配（其中 2 次为内核边界拷贝不可避免）
3. **转发路径整帧拷贝**：relay/broadcast 为 TTL 递减 1 字节做整帧 `to_vec()`（广播路径 2 次）
4. **帧头格式无绝对绑定**：偏移魔法数字散落（encode/decode/auth_input/frame_payload/relay 的 `out[3]`），roundtrip 测试测不出 encode/decode 对称漂移

## 决策摘要（建议默认值）

1. **引入 `bytes`（唯一新直接依赖，Cargo.lock 已有）**：`MeshData`/TUN 内部持有 `BytesMut` 跨包复用，UDP 用 `recv_buf_from`、TUN 用 `read_buf`（免零初始化），`split().freeze()` 产出 `Bytes` 零拷贝移交下游；公共 API 签名不变（缓冲为内部字段）
2. **crypto 增 in-place 接口**：`seal_into`/`open_into`（调用方提供缓冲）；`build_frame` 单缓冲组装（头+载荷一次分配后原地加密）；`open_frame_in_place` 在接收缓冲上原地解密；旧 `seal`/`open`/`open_frame` 保留为薄封装
3. **relay/broadcast 原地 TTL**：freeze 前 `decrement_ttl` 原地递减（rill-core 辅助函数），扇出用 `Bytes::slice`——消除转发路径整帧拷贝
4. **MAX_FRAME 常量**：接收缓冲按 MTU(1420)+v2 帧头(42)+TAG(16)+余量分配；超长包显式丢弃并计入丢帧计数（原为静默截断后解析失败丢弃，净效果相同，语义更清晰）
5. **帧头格式钉死**：偏移常量集中定义 + golden vector 测试（v1 34B / v2 42B / auth_input 18B/26B 绝对字节），与 FRAME_HEADER §2 逐字节绑定
6. **WAN I/O 收敛为函数级接缝**：全部 socket 触点收拢为 `MeshData` 私有原语（不引入 trait），为 P4 XDP 快速路径预留机械抽取点

## 非目标

- **zerocopy crate**：帧头版本化布局（v1/v2）+ `auth_input` 变体（ttl 置零前缀）需三层类型才能表达，收益不覆盖依赖成本；格式钉死由偏移常量 + golden vectors 达成
- **AF_XDP / io_uring / sendmmsg / GSO**：P4 "XDP 快速路径"的前置工作；需重写 underlay 网络栈，且 e2e 的 Docker veth 环境无零拷贝收益
- **parse_envelope 双拷贝消除、TCP 帧 gather write**：收益小，可后续单独处理

## 验收标准（草案）

- golden vectors：v1/v2 帧头与 auth_input 的 encode 输出、decode 还原与 FRAME_HEADER §2 规范逐字节一致
- 超长包（> MAX_FRAME）被显式丢弃并计数，不 panic、不影响后续帧接收
- 发送/接收方向用户态拷贝各 4→2 次，每包堆分配 3→≈0（评审确认，现有单测全绿）
- 现有全部单测 + e2e（direct / relay）全绿

## 关联

- 路线图：P4（XDP 快速路径，本 REQ 的 WAN 接缝为其预留）
- 复用：tokio `io-util`（`recv_buf_from` / `read_buf`）
