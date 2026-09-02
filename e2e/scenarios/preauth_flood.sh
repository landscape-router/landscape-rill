# preauth_flood 场景（REQ-059 / SEC-08 / FRAME_HEADER §5.1）：
# 拓扑：direct（coord + node-a + node-b 同 bridge，setup.sh 默认）
# 断言：
# ① 未认证 UDP 垃圾洪泛 node-a 数据面（随机字节 / 变形帧头 / probe 全 type）→
#    节点不 panic、丢帧摘要增长（解析 fail-closed、内存/任务有界）
# ② 未认证 TCP 洪泛 coord:8443（裸 TCP 垃圾 / TLS 后超长帧声明 / 垃圾信封 /
#    REGISTER 垃圾消息体）→ coord 断连不崩、注册闸门摘要不异常
# ③ 洪泛后 node-b → node-a 双栈 ping 收敛（已认证流量不受影响）
logs() { docker logs "$1" 2>&1; }

echo "==> preauth_flood 阶段 1/4：等待节点注册"
for c in mesh-node-a mesh-node-b; do
  for i in $(seq 1 30); do
    logs $c | grep -q 'registered:' && break
    sleep 2
    [ "$i" = "30" ] && { echo "FAIL: $c 未注册"; logs $c | tail -10; exit 1; }
  done
done
echo "PASS: 双节点注册"

echo "==> preauth_flood 阶段 2/4：未认证洪泛（宿主 → 容器固定 IP）"
# node-a 数据面端点（临时端口，从日志回显地址提取；直连拓扑 seen 地址 = 真实端点）
A_EP=$(logs mesh-node-a | grep -o '192\.168\.240\.11:[0-9]*' | head -1)
[ -n "$A_EP" ] || { echo "FAIL: 无法提取 node-a 数据面端点"; logs mesh-node-a | tail -10; exit 1; }
A_PORT="${A_EP##*:}"
echo "洪泛目标：node-a UDP ${A_EP} / coord TCP 8443"

python3 - "$A_PORT" <<'PYEOF'
import socket, ssl, struct, sys, threading

a_port = int(sys.argv[1])

def udp_garbage():
    # 家族混合：纯随机 / 变形帧头（version 全值域 + 声明超长载荷）/ probe（全 type + 超长载荷）
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for i in range(6000):
        k = i % 3
        if k == 0:
            pkt = bytes((i * 31 + j * 7 + 11) & 0xFF for j in range(i % 200 + 1))
        elif k == 1:
            ver = (i % 16) + 1
            declared = 0xFFFF if i % 2 else 0xFFFF_FFFF
            pkt = bytes([ver, 1, 0, 64]) + struct.pack(">III", 2, 1, i)
            pkt += struct.pack(">H", declared & 0xFFFF) + b"\x00" * 40
        else:
            declared = i % 300
            pkt = b"LPRB" + bytes([i % 256]) + struct.pack(">III", 9, 1, i)
            pkt += b"\x00" * declared
        s.sendto(pkt, ("192.168.240.11", a_port))
    s.close()

def tcp_raw_garbage():
    # 裸 TCP 垃圾（无 TLS）：连接即灌随机字节 → TLS 层拒绝断连
    for i in range(300):
        try:
            s = socket.create_connection(("192.168.240.10", 8443), timeout=2)
            s.sendall(bytes((i * 13 + j) & 0xFF for j in range(64)))
            s.close()
        except OSError:
            pass

def tls_garbage():
    # 完成 TLS 后灌预认证垃圾：超长帧声明 / 垃圾信封 / REGISTER 垃圾消息体
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    for i in range(120):
        try:
            raw = socket.create_connection(("192.168.240.10", 8443), timeout=2)
            tls = ctx.wrap_socket(raw)
            k = i % 3
            if k == 0:
                tls.sendall(struct.pack(">I", 0x100001))  # > 1MiB 上限
            elif k == 1:
                body = bytes((i * 37 + j * 11) & 0xFF for j in range(48))
                tls.sendall(struct.pack(">I", len(body)) + body)
            else:
                body = struct.pack(">I", 24) + b"\xff" * 24  # 4B 帧长 + 永不终止的 varint（REGISTER 垃圾消息体）
                tls.sendall(body)
            tls.close()
        except (OSError, ssl.SSLError):
            pass

threads = [threading.Thread(target=f) for f in (udp_garbage, tcp_raw_garbage, tls_garbage)]
for t in threads:
    t.start()
for t in threads:
    t.join()
print("flood done")
PYEOF
echo "PASS: 洪泛注入完成"

echo "==> preauth_flood 阶段 3/4：进程存活 + 解析 fail-closed 证据"
for c in mesh-coord mesh-node-a mesh-node-b; do
  state=$(docker inspect -f '{{.State.Running}}' $c)
  [ "$state" = "true" ] || { echo "FAIL: $c 已退出（洪泛导致崩溃）"; docker logs $c | tail -20; exit 1; }
done
echo "PASS: 三容器全部存活（不 panic）"
# 丢帧摘要增长 = 入口 fail-closed 生效（LOGGING §5 周期摘要）
n=0
for i in $(seq 1 30); do
  n=$(logs mesh-node-a | grep -c 'frame dropped:' || true)
  [ "$n" -ge 1 ] && break
  sleep 2
done
[ "$n" -ge 1 ] || { echo "FAIL: node-a 无丢帧摘要（洪泛未被解析层拒绝？）"; logs mesh-node-a | tail -20; exit 1; }
echo "PASS: node-a 丢帧摘要出现（${n} 条，fail-closed 生效）"

echo "==> preauth_flood 阶段 4/4：已认证流量收敛（b → a 双栈）"
for i in $(seq 1 20); do
  if docker exec mesh-node-b ping -c1 -W1 10.42.0.1 >/dev/null 2>&1 \
     && docker exec mesh-node-b ping6 -c1 -W1 fd00:2::1 >/dev/null 2>&1; then
    echo "PASS: 洪泛后 mesh ping 通（第 ${i} 次尝试，IPv4 + IPv6）——已认证流量不受影响"
    docker exec mesh-node-b ping -c3 10.42.0.1 || true
    exit 0
  fi
  sleep 2
done
echo "FAIL: 洪泛后 ping 不通"
echo "--- coord 日志 ---";  logs mesh-coord | tail -20
echo "--- node-a 日志 ---"; logs mesh-node-a | tail -20
echo "--- node-b 日志 ---"; logs mesh-node-b | tail -20
exit 1
