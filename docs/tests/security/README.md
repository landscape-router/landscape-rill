# 安全对抗验证（security）

> 对抗场景清单——补功能测试之外的攻击面验证（对应 FRAME_HEADER §2.3/§2.4/§5、CONTROL_PLANE §6、CONNECTIVITY §2 的实现安全要求）。
> 容器拓扑见 [../README.md](../README.md) 与 [../../e2e/README.md](../../e2e/README.md)。所有解析路径的 fail-closed 行为（禁 panic/unwrap）为强制验证项。

## 目录索引

| 文件 | 场景 ID | 覆盖 |
|---|---|---|
| [frame-attacks.md](./frame-attacks.md) | `SEC-01` ~ `SEC-11` | 帧头篡改、route_mac 伪造（非成员/成员）、重放、注入、解析鲁棒性 |
| [control-plane-attacks.md](./control-plane-attacks.md) | `SEC-12` ~ `SEC-20` | 握手重定向/冒充、伪 coordinator 钓鱼、auth key 滥用、重连 DH 挑战 |
| [tenancy.md](./tenancy.md) | `SEC-21` ~ `SEC-28` | 租户越权、跨网络密钥隔离、反射放大 |

## 通过标准总则

- 所有攻击场景：预期行为 = **丢弃/拒绝/断开**，且**进程不 panic、会话不崩溃、合法流量不受影响**
- 解析路径：畸形输入不 panic、不 unwrap、长度越界即丢弃（fail-closed）
