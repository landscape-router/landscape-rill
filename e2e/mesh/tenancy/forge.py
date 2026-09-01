#!/usr/bin/env python3
"""SEC-22 跨网络伪造 route_mac 注入（CONNECTIVITY §2.1 / FRAME_HEADER §2.2 语义）。

向目标节点 UDP 数据面端口注入一枚 34B v1 帧：route_mac 用指定主密钥派生。
- 负对照（wrong key）：用 work 网络主密钥伪造 → 目标节点必须 BadRouteMac 丢弃
- 正对照（correct key）：用 lab 网络主密钥（正确）→ 越过 route_mac，死在会话层
  （Aead/Replay/NoSession）——证明 drop 确因密钥不匹配而非脚本 bug

注意：本脚本是测试工具，重复 crypto.rs 派生逻辑（HKDF-SHA256 + siphash-2-4）；
如 crypto 演进（info/派生方式变更），正对照断言会兜住（正确 key 帧也将 BadRouteMac）。
"""
import hashlib
import hmac
import socket
import struct
import sys

MAGIC_LEN = 0  # 帧注入：非 probe，直接 34B 帧
HEADER_LEN = 34
TAG_LEN = 16
VERSION = 0x01
PACKET_TYPE_UNICAST = 0x01


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out = b""
    t = b""
    i = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


def derive_key_dst(master_key: bytes, to_node_id: int) -> bytes:
    info = b"key_dst" + struct.pack(">I", to_node_id)
    return hkdf_expand(hkdf_extract(b"\x00" * 32, master_key), info, 32)


def derive_sip_key(key_dst: bytes, index: int) -> bytes:
    return hkdf_expand(
        hkdf_extract(b"\x00" * 32, key_dst), b"sipkey" + bytes([index]), 32
    )[:16]


def siphash_2_4(key: bytes, data: bytes) -> int:
    k0 = struct.unpack("<Q", key[0:8])[0]
    k1 = struct.unpack("<Q", key[8:16])[0]
    v0 = 0x736F6D6570736575 ^ k0
    v1 = 0x646F72616E646F6D ^ k1
    v2 = 0x6C7967656E657261 ^ k0
    v3 = 0x7465646279746573 ^ k1

    def sip_round():
        nonlocal v0, v1, v2, v3
        v0 = (v0 + v1) & 0xFFFFFFFFFFFFFFFF
        v1 = ((v1 << 13) | (v1 >> 51)) & 0xFFFFFFFFFFFFFFFF
        v1 ^= v0
        v0 = ((v0 << 32) | (v0 >> 32)) & 0xFFFFFFFFFFFFFFFF
        v2 = (v2 + v3) & 0xFFFFFFFFFFFFFFFF
        v3 = ((v3 << 16) | (v3 >> 48)) & 0xFFFFFFFFFFFFFFFF
        v3 ^= v2
        v0 = (v0 + v3) & 0xFFFFFFFFFFFFFFFF
        v3 = ((v3 << 21) | (v3 >> 43)) & 0xFFFFFFFFFFFFFFFF
        v3 ^= v0
        v2 = (v2 + v1) & 0xFFFFFFFFFFFFFFFF
        v1 = ((v1 << 17) | (v1 >> 47)) & 0xFFFFFFFFFFFFFFFF
        v1 ^= v2
        v2 = ((v2 << 32) | (v2 >> 32)) & 0xFFFFFFFFFFFFFFFF

    b = (len(data) & 0xFF) << 56
    i = 0
    while i + 8 <= len(data):
        m = struct.unpack("<Q", data[i : i + 8])[0]
        v3 ^= m
        sip_round()
        sip_round()
        v0 ^= m
        i += 8
    for j, byte in enumerate(data[i:]):
        b |= byte << (8 * j)
    v3 ^= b
    sip_round()
    sip_round()
    v0 ^= b
    v2 ^= 0xFF
    for _ in range(4):
        sip_round()
    return (v0 ^ v1 ^ v2 ^ v3) & 0xFFFFFFFFFFFFFFFF


def route_mac(key_dst: bytes, auth_input: bytes) -> bytes:
    k1 = derive_sip_key(key_dst, 0)
    k2 = derive_sip_key(key_dst, 1)
    return struct.pack(
        "<QQ",
        siphash_2_4(k1, auth_input),
        siphash_2_4(k2, auth_input),
    )


def build_frame(
    master_key: bytes,
    to_node_id: int,
    from_node_id: int,
    seq: int,
    ttl: int,
) -> bytes:
    payload = b"SEC-22-forged-frame\x00\x00\x00\x00\x00"  # 无意义载荷（死在 route_mac）
    hlen_field = len(payload) + TAG_LEN
    # v1 认证输入 = 帧头[0..18] ttl 置零
    auth_input = (
        bytes([VERSION, PACKET_TYPE_UNICAST, 0x00, 0x00])
        + struct.pack(">I", to_node_id)
        + struct.pack(">I", from_node_id)
        + struct.pack(">I", seq)
        + struct.pack(">H", hlen_field)
    )
    mac = route_mac(derive_key_dst(master_key, to_node_id), auth_input)
    header = (
        bytes([VERSION, PACKET_TYPE_UNICAST, 0x00, ttl])
        + struct.pack(">I", to_node_id)
        + struct.pack(">I", from_node_id)
        + struct.pack(">I", seq)
        + struct.pack(">H", hlen_field)
        + mac
    )
    assert len(header) == HEADER_LEN, f"header={len(header)}"
    return header + payload


def main() -> int:
    if len(sys.argv) != 8:
        print(
            "usage: forge.py <target-ip> <target-port> <from_node_id> <to_node_id> "
            "<master-key-hex> <seq> <ttl>",
            file=sys.stderr,
        )
        return 2
    target_ip, target_port, from_id, to_id, key_hex, seq, ttl = sys.argv[1:]
    frame = build_frame(
        bytes.fromhex(key_hex),
        int(to_id),
        int(from_id),
        int(seq),
        int(ttl),
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(frame, (target_ip, int(target_port)))
    print(f"forged frame sent: to_node={to_id} from_node={from_id} len={len(frame)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
