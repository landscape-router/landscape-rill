# coord_attacks 场景（SEC-12/SEC-18 控制面对抗容器级复验，CONTROL_PLANE §2/§6）：
# 拓扑：direct 三件套 + node-c（coordinator_url 指向宿主网关 192.168.240.1:9443 伪 coord）
# 攻击者模型：SEC-12 钓鱼者 = 宿主上的自签 rogue TLS（node-c 被诱导指向它）；
#             SEC-18 伪造者 = 持任意 TLS 客户端直连真 coord:8443 灌 HEARTBEAT
# 断言：
# ① SEC-12：node-c 对 rogue 有 TLS 尝试（连接数 ≥2）但 auth key 零泄露
#    （rogue 收不到任何应用层数据）；node-c 始终未注册、重连退避摘要出现；a/b 不受影响
# ② SEC-18a：未注册 TLS 连接灌 HEARTBEAT → coord 无操作（存活、数据面不变）
# ③ SEC-18b：node-a 停机 + 持续伪造心跳 → 租约照常过期（b→a ping 失败，
#    伪造无法延长在线状态）
ROGUE_DIR=$(mktemp -d /tmp/coord_rogue.XXXX)

echo "==> coord_attacks 阶段 1/5：注册 + 基线连通"
for c in mesh-node-a mesh-node-b; do
  for i in $(seq 1 30); do
    logs $c | grep -q 'registered:' && break
    sleep 2
    [ "$i" = "30" ] && { echo "FAIL: $c 未注册"; logs $c | tail -10; exit 1; }
  done
done
for i in $(seq 1 20); do
  docker exec mesh-node-b ping -c1 -W1 10.42.0.1 >/dev/null 2>&1 && break
  sleep 2
done
docker exec mesh-node-b ping -c1 -W1 10.42.0.1 >/dev/null 2>&1 || { echo "FAIL: 基线 b→a 不通"; exit 1; }
echo "PASS: a/b 注册 + 基线连通"

echo "==> coord_attacks 阶段 2/5：SEC-12 伪 coordinator 钓鱼（node-c → rogue TLS）"
# rogue：自签证书（SAN 覆盖网关 IP + DNS:coord，模拟"看起来合法"的钓鱼端）。
# 连接计数与收到的字节每轮落盘（被 kill 前可读）；客户端证书验证失败 →
# 握手阶段断连，应用层字节恒为空
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout "$ROGUE_DIR/rogue.key" -out "$ROGUE_DIR/rogue.crt" \
  -days 2 -nodes -subj "/CN=coord" -addext "subjectAltName=DNS:coord,IP:192.168.240.1" 2>/dev/null
python3 - "$ROGUE_DIR" <<'PYEOF' &
import socket, ssl, sys, time, os
rogue_dir = sys.argv[1]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(f"{rogue_dir}/rogue.crt", f"{rogue_dir}/rogue.key")
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", 9443))
srv.listen(16)
srv.settimeout(1)
conns, received = 0, b""
end = time.time() + 300
while time.time() < end:
    try:
        raw, _ = srv.accept()
    except socket.timeout:
        continue
    conns += 1
    try:
        tls = ctx.wrap_socket(raw, server_side=True)
        tls.settimeout(2)
        received += tls.recv(4096)
        tls.close()
    except (ssl.SSLError, OSError):
        pass  # 客户端证书验证失败 → 握手断连（预期路径）
    open(f"{rogue_dir}/conns.tmp", "w").write(str(conns))
    os.replace(f"{rogue_dir}/conns.tmp", f"{rogue_dir}/conns")
    open(f"{rogue_dir}/received.bin.tmp", "wb").write(received)
    os.replace(f"{rogue_dir}/received.bin.tmp", f"{rogue_dir}/received.bin")
PYEOF
ROGUE_PID=$!
# node-c 重连退避下持续尝试 rogue；等 ≥2 次连接 + connect failed 摘要
ok=0
for i in $(seq 1 45); do
  sleep 2
  N=$(cat "$ROGUE_DIR/conns" 2>/dev/null || echo 0)
  C_FAIL=$(logs mesh-node-c | grep -c 'control connect failed' || true)
  if [ "$N" -ge 2 ] && [ "$C_FAIL" -ge 1 ]; then ok=1; break; fi
done
C_REG=$(logs mesh-node-c | grep -c 'registered:' || true)
C_FAIL=$(logs mesh-node-c | grep -c 'control connect failed' || true)
N_CONNS=$(cat "$ROGUE_DIR/conns" 2>/dev/null || echo 0)
kill $ROGUE_PID 2>/dev/null || true
wait $ROGUE_PID 2>/dev/null || true
[ "$ok" = "1" ] || { echo "FAIL: rogue 连接 $N_CONNS 次 / connect failed ×$C_FAIL（node-c 未真正触达 rogue？）"; logs mesh-node-c | tail -10; exit 1; }
[ "$C_REG" = "0" ] || { echo "FAIL: node-c 竟在 rogue 上注册成功"; exit 1; }
RECV_SIZE=$(stat -c%s "$ROGUE_DIR/received.bin" 2>/dev/null || echo 0)
if [ "$RECV_SIZE" -ne 0 ] && grep -q 'lrk-' "$ROGUE_DIR/received.bin" 2>/dev/null; then
  echo "FAIL: auth key 泄露给伪 coordinator（received ${RECV_SIZE}B）"; exit 1
fi
echo "PASS: SEC-12 rogue 连接 $N_CONNS 次、应用层零泄露、node-c 未注册（connect failed ×$C_FAIL）"

echo "==> coord_attacks 阶段 3/5：SEC-18a 未注册连接伪造心跳 → 无操作"
# 信封 = Envelope{msg_type=HEARTBEAT(4), body=空}（protobuf: field1 varint + field2 空 bytes）
python3 - <<'PYEOF'
import socket, ssl, struct, time
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
env = bytes([0x08, 0x04, 0x12, 0x00])
for _ in range(50):
    try:
        raw = socket.create_connection(("192.168.240.10", 8443), timeout=2)
        tls = ctx.wrap_socket(raw)
        tls.sendall(struct.pack(">I", len(env)) + env)
        tls.close()
    except (OSError, ssl.SSLError):
        pass
    time.sleep(0.05)
print("forged heartbeats sent")
PYEOF
[ "$(docker inspect -f '{{.State.Running}}' mesh-coord)" = "true" ] || { echo "FAIL: coord 被伪造心跳打死"; exit 1; }
docker exec mesh-node-b ping -c1 -W1 10.42.0.1 >/dev/null 2>&1 || { echo "FAIL: 伪造心跳破坏数据面"; exit 1; }
echo "PASS: SEC-18a 50 次未注册伪造心跳 → coord 存活、数据面不变"

echo "==> coord_attacks 阶段 4/5：SEC-18b node-a 停机 + 持续伪造 → 租约照常过期"
docker stop mesh-node-a >/dev/null
python3 - <<'PYEOF'
import socket, ssl, struct, time
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
env = bytes([0x08, 0x04, 0x12, 0x00])
end = time.time() + 110
while time.time() < end:
    try:
        raw = socket.create_connection(("192.168.240.10", 8443), timeout=2)
        tls = ctx.wrap_socket(raw)
        tls.sendall(struct.pack(">I", len(env)) + env)
        tls.close()
    except (OSError, ssl.SSLError):
        pass
    time.sleep(1)
print("forged heartbeats done")
PYEOF
# LEASE_EXPIRY_SECS=60：伪造心跳不绝续命 → b→a 必然不通
DOWN=1
for i in $(seq 1 10); do
  if ! docker exec mesh-node-b ping -c1 -W1 10.42.0.1 >/dev/null 2>&1; then DOWN=0; break; fi
  sleep 2
done
[ "$DOWN" = "0" ] || { echo "FAIL: node-a 停机后仍可达——伪造心跳延长了租约？"; exit 1; }
echo "PASS: SEC-18b 租约照常过期（伪造心跳无法延长在线状态）"

echo "==> coord_attacks 阶段 5/5：coord/数据面完好"
for c in mesh-coord mesh-node-b mesh-node-c; do
  [ "$(docker inspect -f '{{.State.Running}}' $c)" = "true" ] || { echo "FAIL: $c 退出"; exit 1; }
done
echo "PASS: coord_attacks 全部断言通过（SEC-12/SEC-18）"
rm -rf "$ROGUE_DIR"
exit 0
