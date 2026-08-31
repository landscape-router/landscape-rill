#!/usr/bin/env bash
# P0 过渡验证：自建 headscale + derper（内嵌）+ 官方 Tailscale 客户端入网端到端
#
# 拓扑：headscale（自签 TLS + 内嵌 DERP）— node-c / node-d（官方 tailscaled，auth key 入网）
# 验证：node-c ping node-d 的 tailnet IP（100.64/10）——官方客户端 ⇄ 自建 ts2021 兼容控制面全链路。
#
# 手机 app（iOS/Android）与 tailscaled 同协议栈；交互式登录（网页/OAuth）为服务端职责，
# 本脚本用 auth key 路径实证协议兼容性（TS2021_LEG §3.2/§6）。
set -euo pipefail

E2E_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$E2E_DIR/../../.." && pwd)"
BUILD_DIR="$E2E_DIR/build"
COMPOSE="docker compose -f $E2E_DIR/docker-compose.yaml"
HEADSCALE_VER="${P0_HEADSCALE_VER:-0.29.3}"
TAILSCALE_VER="${P0_TAILSCALE_VER:-1.102.2}"

echo "==> 0/7 预置 base 镜像（依赖 mesh-e2e-base：iproute2/iputils-ping/ca-certificates）"
E2E_DNS="${MESH_E2E_DNS:-$(awk '/nameserver/{print $2; exit}' /etc/resolv.conf)}"
if ! docker image inspect mesh-e2e-base >/dev/null 2>&1; then
  docker run --dns "$E2E_DNS" debian:bookworm-slim sh -c \
    "apt-get update && apt-get install -y --no-install-recommends \
       iproute2 iputils-ping ca-certificates && rm -rf /var/lib/apt/lists/*"
  docker commit "$(docker ps -lq)" mesh-e2e-base
fi

echo "==> 1/7 下载 headscale + tailscale 二进制（build/ 缓存）"
mkdir -p "$BUILD_DIR/headscale-config"
[ -f "$BUILD_DIR/headscale" ] || \
  curl -sL -o "$BUILD_DIR/headscale" \
  "https://github.com/juanfont/headscale/releases/download/v${HEADSCALE_VER}/headscale_${HEADSCALE_VER}_linux_amd64"
if [ ! -d "$BUILD_DIR/tailscale_${TAILSCALE_VER}_amd64" ]; then
  curl -sL -o "$BUILD_DIR/tailscale.tgz" \
    "https://pkgs.tailscale.com/stable/tailscale_${TAILSCALE_VER}_amd64.tgz"
  tar xzf "$BUILD_DIR/tailscale.tgz" -C "$BUILD_DIR"
fi
cp "$E2E_DIR/entry-node.sh" "$BUILD_DIR/entry-node.sh"
cp "$E2E_DIR/Dockerfile" "$BUILD_DIR/Dockerfile"

echo "==> 2/7 生成 CA 与 headscale 证书"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$BUILD_DIR/ca.key" -out "$BUILD_DIR/ca.pem" \
    -days 30 -nodes -subj "/CN=p0-e2e-ca" 2>/dev/null

openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$BUILD_DIR/server.key" -out "$BUILD_DIR/server.csr" \
    -nodes -subj "/CN=headscale" 2>/dev/null

cat > "$BUILD_DIR/server.ext" <<'EOF'
subjectAltName = DNS:headscale, IP:127.0.0.1
EOF
openssl x509 -req -in "$BUILD_DIR/server.csr" -CA "$BUILD_DIR/ca.pem" -CAkey "$BUILD_DIR/ca.key" \
    -CAcreateserial -out "$BUILD_DIR/server.crt" -days 30 \
    -extfile "$BUILD_DIR/server.ext" 2>/dev/null

echo "==> 3/7 生成 headscale 配置（自签 TLS + 内嵌 DERP + ACL 放行）"
cp "$BUILD_DIR/ca.pem" "$BUILD_DIR/headscale-config/ca.pem"
cp "$BUILD_DIR/server.crt" "$BUILD_DIR/headscale-config/server.crt"
cp "$BUILD_DIR/server.key" "$BUILD_DIR/headscale-config/server.key"

cat > "$BUILD_DIR/headscale-config/policy.hujson" <<'EOF'
{
  "acls": [
    { "action": "accept", "src": ["*"], "dst": ["*:*"] }
  ]
}
EOF

cat > "$BUILD_DIR/headscale-config/config.yaml" <<EOF
server_url: https://headscale:8080
listen_addr: 0.0.0.0:8080
metrics_listen_addr: 127.0.0.1:9090
noise:
  private_key_path: /var/lib/headscale/noise_private.key
prefixes:
  v4: 100.64.0.0/10
  v6: fd7a:115c:a1e0::/48
  allocation: sequential
derp:
  server:
    enabled: true
    region_id: 999
    region_code: "p0"
    region_name: "P0 Embedded DERP"
    verify_clients: false
    stun_listen_addr: "0.0.0.0:3478"
    private_key_path: /var/lib/headscale/derp_server_private.key
    automatically_add_embedded_derp_region: true
  urls: []
  paths: []
  auto_update_enabled: false
database:
  type: sqlite
  sqlite:
    path: /var/lib/headscale/db.sqlite
tls_cert_path: /etc/headscale/server.crt
tls_key_path: /etc/headscale/server.key
policy:
  mode: file
  path: /etc/headscale/policy.hujson
dns:
  magic_dns: false
  base_domain: p0.ts
  override_local_dns: false
unix_socket: /var/run/headscale/headscale.sock
logtail:
  enabled: false
EOF

echo "==> 4/7 构建镜像 + 启动 headscale"
$COMPOSE build -q
$COMPOSE up -d --force-recreate headscale
for i in $(seq 1 30); do
  docker exec p0-headscale headscale version >/dev/null 2>&1 && \
    docker exec p0-headscale headscale nodes list >/dev/null 2>&1 && break
  sleep 1
done
sleep 3

echo "==> 5/7 创建用户 + preauth key"
docker exec p0-headscale headscale users create p0 >/dev/null 2>&1 || true
P0_UID=$(docker exec p0-headscale headscale users list | sed 's/\x1b\[[0-9;]*m//g' | grep "p0" | cut -d'|' -f1 | tr -d ' ' | head -1)
echo "user p0 id=$P0_UID"
TS_AUTHKEY=$(docker exec p0-headscale headscale preauthkeys create --user "$P0_UID" --reusable)
echo "authkey=$TS_AUTHKEY"
export TS_AUTHKEY

cleanup() { $COMPOSE down -v >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "==> 6/7 启动官方客户端节点（auth key 入网）"
$COMPOSE up -d --force-recreate node-c node-d
for i in $(seq 1 30); do
  NODES=$(docker exec p0-headscale headscale nodes list 2>/dev/null | grep -c "online" || true)
  [ "$NODES" -ge 2 ] && break
  sleep 2
done
docker exec p0-headscale headscale nodes list

echo "==> 7/7 ping 断言（node-c → node-d tailnet IP）"
NODE_D_IP=$(docker exec p0-headscale headscale nodes list | sed 's/\x1b\[[0-9;]*m//g' | grep "node-d" | grep -oE "100\.64\.[0-9]+\.[0-9]+" | head -1 || true)
echo "node-d tailnet ip: $NODE_D_IP"
[ -n "$NODE_D_IP" ] || { echo "FAIL: node-d 未拿到 tailnet IP"; exit 1; }

for i in $(seq 1 20); do
  if docker exec p0-node-c ping -c1 -W1 "$NODE_D_IP" >/dev/null 2>&1; then
    echo "PASS: 官方客户端经自建 headscale 入网互通（第 ${i} 次尝试）"
    docker exec p0-node-c ping -c3 "$NODE_D_IP"
    echo "--- node-c status ---"
    docker exec p0-node-c tailscale status
    exit 0
  fi
  sleep 2
done

echo "FAIL: node-c ping node-d 不通"
echo "--- headscale 日志 ---";  docker logs p0-headscale 2>&1 | tail -15
echo "--- node-c 日志 ---";     docker logs p0-node-c 2>&1 | tail -10
echo "--- node-d 日志 ---";     docker logs p0-node-d 2>&1 | tail -10
exit 1
