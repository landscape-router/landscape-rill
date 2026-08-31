#!/usr/bin/env bash
# mesh e2e：CA/证书/密钥生成 → 配置文件 → 构建镜像 → 起容器 → mesh ping 断言
#
# 拓扑：coord（TLS 控制面 + keydist）— node-a（tun0 10.42.0.1/24 + fd00:2::1/64）
#      — node-b（tun0 10.43.0.1/24 + fd00:3::1/64）
# 验证：node-b 内 ping 10.42.0.1 / ping6 fd00:2::1 经 mesh 帧到达 node-a
#       （IPv6 走组播泛洪 ND：NS 泛洪 → 内核应答 NA，FRAME_HEADER §2.6）。
#
# 内核最小参与：mesh 前缀指向 tun0 的静态路由由本脚本注入（生产 = runtime v1.1 自动注入）。
set -euo pipefail

E2E_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$E2E_DIR/.." && pwd)"
BUILD_DIR="$E2E_DIR/build"
COMPOSE="docker compose -f $E2E_DIR/docker-compose.yaml"
OVERLAY="$ROOT_DIR/target/release/lrill"

hex() { openssl rand -hex 32; }

echo "==> 0/6 预置 base 镜像（iproute2/iputils-ping；环境 DNS 受限需 --dns 引导）"
E2E_DNS="${MESH_E2E_DNS:-$(awk '/nameserver/{print $2; exit}' /etc/resolv.conf)}"
if ! docker image inspect mesh-e2e-base >/dev/null 2>&1; then
  docker run --dns "$E2E_DNS" debian:bookworm-slim sh -c \
    "apt-get update && apt-get install -y --no-install-recommends \
       iproute2 iputils-ping ca-certificates && rm -rf /var/lib/apt/lists/*"
  docker commit "$(docker ps -lq)" mesh-e2e-base
fi

echo "==> 1/6 生成 CA 与服务端证书"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$BUILD_DIR/ca.key" -out "$BUILD_DIR/ca.pem" \
    -days 30 -nodes -subj "/CN=mesh-e2e-ca" 2>/dev/null

openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$BUILD_DIR/coord.key" -out "$BUILD_DIR/coord.csr" \
    -nodes -subj "/CN=coord" 2>/dev/null

cat > "$BUILD_DIR/coord.ext" <<'EOF'
subjectAltName = DNS:coord, IP:127.0.0.1
EOF
openssl x509 -req -in "$BUILD_DIR/coord.csr" -CA "$BUILD_DIR/ca.pem" -CAkey "$BUILD_DIR/ca.key" \
    -CAcreateserial -out "$BUILD_DIR/coord.crt" -days 30 \
    -extfile "$BUILD_DIR/coord.ext" 2>/dev/null

echo "==> 2/6 生成密钥与信任锚"
MASTER_KEY=$(hex)
SIGNING_SEED=$(hex)
NODE_A_KEY=$(hex)
NODE_B_KEY=$(hex)

echo "==> 3/6 编译二进制"
"$ROOT_DIR/scripts/build.sh"
cp "$ROOT_DIR/target/release/lrill" "$BUILD_DIR/lrill"
COORD_PUBKEY=$("$OVERLAY" pubkey "$SIGNING_SEED")

echo "==> 4/6 生成配置"
gen_node_config() {  # $1=文件 $2=节点密钥 $3=IPv4地址 $4=IPv6地址 $5=公告前缀数组(JSON) $6=auth_key
  cat > "$BUILD_DIR/$1" <<EOF
{
  "coordinator_url": "https://coord:8443",
  "auth_key": "$6",
  "static_key_seed": "$2",
  "capabilities": 1,
  "announce_routes": $5,
  "coord_signing_pubkey": "$COORD_PUBKEY",
  "ca_cert_path": "/etc/landscape/ca.pem",
  "tun": { "name": "land0", "mtu": 1420, "address4": "$3", "address6": "$4" }
}
EOF
}

gen_node_config node-a.json "$NODE_A_KEY" "10.42.0.1/24" "fd00:2::1/64" '["10.42.0.0/24", "fd00:2::/64"]' "ak-node-a"
gen_node_config node-b.json "$NODE_B_KEY" "10.43.0.1/24" "fd00:3::1/64" '["10.43.0.0/24", "fd00:3::/64"]' "ak-node-b"

cat > "$BUILD_DIR/coord.json" <<EOF
{
  "coord": {
    "listen_addr": "0.0.0.0:8443",
    "master_key": "$MASTER_KEY",
    "signing_seed": "$SIGNING_SEED",
    "tls_cert_path": "/etc/landscape/coord.crt",
    "tls_key_path": "/etc/landscape/coord.key",
    "auth_keys": [
      { "key": "ak-node-a", "policy": "reusable" },
      { "key": "ak-node-b", "policy": "reusable" }
    ]
  }
}
EOF

echo "==> 5/6 构建并启动"
$COMPOSE build -q
$COMPOSE up -d --force-recreate

cleanup() { $COMPOSE down -v >/dev/null 2>&1 || true; }
trap cleanup EXIT

logs() { docker logs "$1" 2>&1; }

echo "==> 6/6 等待注册 + 注入 mesh 路由 + ping/ping6 断言"
for _ in $(seq 1 30); do
  logs mesh-coord | grep -q "listening" && break
  sleep 1
done
sleep 3

# 内核最小参与：mesh 前缀 → tun0（生产由 runtime 自动注入）
docker exec mesh-node-a ip route add 10.43.0.0/24 dev land0 2>/dev/null || true
docker exec mesh-node-b ip route add 10.42.0.0/24 dev land0 2>/dev/null || true
docker exec mesh-node-a ip -6 route add fd00:3::/64 dev land0 2>/dev/null || true
docker exec mesh-node-b ip -6 route add fd00:2::/64 dev land0 2>/dev/null || true

for i in $(seq 1 20); do
  if docker exec mesh-node-b ping -c1 -W1 10.42.0.1 >/dev/null 2>&1 \
     && docker exec mesh-node-b ping6 -c1 -W1 fd00:2::1 >/dev/null 2>&1; then
    echo "PASS: mesh e2e ping 通（第 ${i} 次尝试，IPv4 + IPv6 双栈）"
    docker exec mesh-node-b ping -c3 10.42.0.1
    docker exec mesh-node-b ping6 -c3 fd00:2::1
    exit 0
  fi
  sleep 2
done

echo "FAIL: ping 不通"
echo "--- coord 日志 ---";  logs mesh-coord | tail -20
echo "--- node-a 日志 ---"; logs mesh-node-a | tail -20
echo "--- node-b 日志 ---"; logs mesh-node-b | tail -20
exit 1
