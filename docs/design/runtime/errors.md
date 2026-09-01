# 错误处理设计（ERROR_ID）

> 错误类型定义、稳定错误 ID 与序列化信封——统一错误处理契约（thiserror + ErrorId + ErrorEnvelope）。
> 版本：v1.2（2026-09-01 修订：§2.2 边界 `BoxResult` 别名、§2.3 错误链展开；§5 移除权威清单）｜ 相关需求：无（实现级约定，随 REQ-044 运维基线方向对齐）

## 1. 范围与边界

错误处理三件套：

- **thiserror**：所有错误类型 `#[derive(thiserror::Error)]`，Display = 人类可读消息（英文，i18n fallback 文本）
- **ErrorId trait + derive**：每个错误变体带稳定 ID（i18n 键），由 `landscape-rill-macro`（目录 `rill-macro/`）的 `#[derive(ErrorId)]` 生成；变体缺 `#[error_id(...)]` 编译报错
- **ErrorEnvelope**：`{id, args, message}` 序列化形状（serde）

边界：

- 控制面错误仍以**断连**表达（无错误响应消息）；错误 ID 是设计契约，供未来序列化出口（CLI JSON、控制面错误字段、管理面）使用
- `DropReason`（丢帧归因）不是 Result 错误，无 ID
- 高层 I/O 扇入仍用 `Box<dyn Error>` / `std::io::Error`（§2.2），不引入 anyhow

## 2. 错误类型规范

### 2.1 thiserror 定义

- 全部错误枚举 `#[derive(Debug, ..., thiserror::Error)]`，Display 消息统一英文
- 嵌套错误用 `#[error(transparent)]`（如 `HandshakeError::Noise(snow::Error)`、`SendError::Handshake` 委托）
- 外部错误转换用 `#[from]`（如 `StoreError::Redb(#[from] redb::Error)`）；局部 From impl 委托 `#[from]` 变体（外部错误类型非 `#[from]` 目标时保留手写，如 redb 子类型）

### 2.2 边界转换

- I/O 接口统一 `std::io::Error`：`io::Error::new(kind, e)` 直接携带错误对象（错误已实现 `Error + Send + Sync`），不做 `format!("{:?}")` 字符串化
- 高层扇入统一 `BoxResult<T>` 别名（`Box<dyn Error + Send + Sync>`）：`rill-node` lib.rs 与 `rill-mesh` control.rs 为 `pub`/`pub(crate)` 导出，`rilld` 为二进制内私有；不允许混用裸 `Box<dyn Error>`（不含 Send+Sync）

### 2.3 错误链展开

- 日志打印错误时 `{e}` 只显示顶层 Display，`#[source]` 链路丢失
- 统一用 `landscape_rill_core::error::format_chain(&e)` 展开为单行 `outer: inner: ...`（daemon fatal/reload/persist 等诊断点）
- 传输层仍用 `io::Error` 携带源错误（`io::Error::source()` 保留链），仅展示层展开

## 3. ErrorId 契约

所有错误类型实现 `landscape_rill_core::error::ErrorId`（trait 与信封承载于 rill-core，保持 I/O 无关）。

### 3.1 error_id

`fn error_id(&self) -> &'static str`：稳定 ID，客户端 i18n 键（§5 命名规范；权威清单在代码 `#[error_id("...")]` 处）。**ID 一经发布不可改写**（可新增变体、不可修改/复用既有 ID）。

### 3.2 error_args

`fn error_args(&self) -> ErrorArgs`（`serde_json::Value` 别名）：翻译插值参数。生成规则：

- 无字段变体 → `{}`
- 无名变体 → `{"0": <字段0>.to_string(), ...}`
- 命名变体 → `{"<字段名>": <字段>.to_string(), ...}`

### 3.3 to_public_message

默认 = Display 文本；携带内部敏感细节的错误可覆盖隐藏（redaction）。

### 3.4 透明委托

`#[error_id(transparent)]` 变体（单字段 `#[from]` 且内层实现 ErrorId）——id/args/message 全部委托内层（如 `SendError::Handshake` 表现为 `handshake.*`）。

### 3.5 强制齐全

derive 宏要求每个非透明变体带 `#[error_id("...")]`，缺失编译报错（同 landscape `LdApiError` 模式）。

## 4. ErrorEnvelope 序列化形状

```json
{ "id": "control.register.route_not_allowed", "args": {}, "message": "announced route not allowed" }
```

- `id`：error_id 字符串
- `args`：error_args JSON 对象
- `message`：to_public_message（i18n fallback 文本）

当前无序列化出口（§1），`to_envelope()` 为消费方契约；形状变更需走协议级评审。

## 5. ID 命名规范

`<模块>.<类型>.<变体>` 全小写蛇形：

- 模块前缀：`crypto` / `frame` / `handshake` / `route` / `control`（core）；`coord`；`mesh`；`node`
- 类型 = 错误类型名去 `Error` 后缀蛇形；变体 = 变体名蛇形
- 透明委托变体无 ID（继承内层）
- **代码即权威清单**：ID 只存在错误类型定义处（`#[error_id("...")]`），文档不维护逐条清单

## 6. 决策记录

- 2026-09-01（本版）：引入 thiserror（16 个错误类型全量转换，Display 全部英文）；错误 ID 机制照搬 landscape 项目 `LdApiError` 模式（derive 宏 + 变体 `#[error_id("...")]`，新 crate `landscape-rill-macro`）；args 用 serde_json::Value；`to_envelope()` 设计契约先行（当前无序列化出口）；`StoreError::Redb` 改 `#[from] redb::Error` 保留 source 链；不引入 anyhow（高层 `Box<dyn Error>` 不变）
- 2026-09-01（§5 修订）：否决文档维护逐条 ID 清单（双重维护，代码扫描即得）——只保留命名规范，代码 `#[error_id("...")]` 为权威；check-docs.sh 规则 7 强制 ID 全局唯一
- 2026-09-01（§2 修订）：边界签名统一 `BoxResult<T>`（`Box<dyn Error + Send + Sync>`，mesh/node/rilld 三处别名，杜绝混用裸 Box）；新增 `format_chain` 错误链展开（daemon 诊断点）
- 实现级决定：trait/信封在 rill-core（I/O 无关，`rill-core/src/error.rs`）；宏 crate 仅构建期依赖；消费方错误 crate 不依赖 serde_json（args 经 `ErrorArgs` 别名 + `args()` 助手生成）；`AeadError`（unit struct）/ `coord ConfigError`（tuple struct）为手写 impl（宏仅支持枚举）
