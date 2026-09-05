#!/usr/bin/env bash
# ts2021 接入 e2e（TSL-04 控制面）：自研 lrill 客户端 + 官方 tailscaled 经自建 headscale 双节点入网
#
# 拓扑：headscale（自签 TLS + 内嵌 DERP）— lrill（ts2021-register 探针）/ node-c（官方 tailscaled）
# 验证：lrill 全链路（TLS → GET /key → controlhttp 升级 → Noise IK → early payload →
# HTTP/2 → /machine/register，auth key 预授权）注册成功；headscale 节点表出现双节点同 user。
# 数据面互通（WG ping）为下一里程碑（TS2021_LEG §3.3，boringtun + DERP）。
set -euo pipefail

E2E_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$E2E_DIR/../.." && pwd)"
BUILD_DIR="$E2E_DIR/build"
COMPOSE="docker compose -f $E2E_DIR/docker-compose.yaml"
HEADSCALE_VER="${TS2021_HEADSCALE_VER:-0.29.3}"
TAILSCALE_VER="${TS2021_TAILSCALE_VER:-1.102.2}"

echo "==> 0/8 预置 base 镜像（依赖 mesh-e2e-base：iproute2/iputils-ping/ca-certificates）"
E2E_DNS="${MESH_E2E_DNS:-$(awk '$1=="nameserver" && $2 !~ /^(127\.|::1$)/{print $2; exit}' /etc/resolv.conf)}"
[ -n "$E2E_DNS" ] || E2E_DNS="1.1.1.1"  # 宿主仅 loopback stub（CI）时回退公共 DNS
if ! docker image inspect mesh-e2e-base >/dev/null 2>&1; then
  docker run --dns "$E2E_DNS" debian:trixie-slim sh -c \
    "apt-get update && apt-get install -y --no-install-recommends \
       iproute2 iputils-ping ca-certificates && rm -rf /var/lib/apt/lists/*"
  docker commit "$(docker ps -lq)" mesh-e2e-base
fi

echo "==> 1/8 下载 headscale + tailscale 二进制（build/ 缓存）"
mkdir -p "$BUILD_DIR/headscale-config"
[ -f "$BUILD_DIR/headscale" ] || \
  curl -sL -o "$BUILD_DIR/headscale" \
  "https://github.com/juanfont/headscale/releases/download/v${HEADSCALE_VER}/headscale_${HEADSCALE_VER}_linux_amd64"
if [ ! -d "$BUILD_DIR/tailscale_${TAILSCALE_VER}_amd64" ]; then
  curl -sL -o "$BUILD_DIR/tailscale.tgz" \
    "https://pkgs.tailscale.com/stable/tailscale_${TAILSCALE_VER}_amd64.tgz"
  tar xzf "$BUILD_DIR/tailscale.tgz" -C "$BUILD_DIR"
fi

echo "==> 2/8 构建 lrill ts2021-register（release）"
if [ "${E2E_SKIP_BUILD:-0}" != "1" ]; then
  (cd "$ROOT_DIR" && cargo build --release -p landscape-rill-ts2021 --bin ts2021-register)
fi
cp "$ROOT_DIR/target/release/ts2021-register" "$BUILD_DIR/ts2021-register"
cp "$E2E_DIR/entry-node.sh" "$E2E_DIR/entry-lrill.sh" "$E2E_DIR/Dockerfile" "$BUILD_DIR/"

echo "==> 3/8 生成 CA 与 headscale 证书"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$BUILD_DIR/ca.key" -out "$BUILD_DIR/ca.pem" \
    -days 30 -nodes -subj "/CN=ts2021-e2e-ca" 2>/dev/null

openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$BUILD_DIR/server.key" -out "$BUILD_DIR/server.csr" \
    -nodes -subj "/CN=headscale" 2>/dev/null

cat > "$BUILD_DIR/server.ext" <<'EOF'
subjectAltName = DNS:headscale, IP:127.0.0.1
EOF
openssl x509 -req -in "$BUILD_DIR/server.csr" -CA "$BUILD_DIR/ca.pem" -CAkey "$BUILD_DIR/ca.key" \
    -CAcreateserial -out "$BUILD_DIR/server.crt" -days 30 \
    -extfile "$BUILD_DIR/server.ext" 2>/dev/null

echo "==> 4/8 生成 headscale 配置（自签 TLS + 内嵌 DERP）"
cp "$BUILD_DIR/ca.pem" "$BUILD_DIR/headscale-config/ca.pem"
cp "$BUILD_DIR/server.crt" "$BUILD_DIR/headscale-config/server.crt"
cp "$BUILD_DIR/server.key" "$BUILD_DIR/headscale-config/server.key"

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
    region_code: "ts2021"
    region_name: "TS2021 E2E DERP"
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
dns:
  magic_dns: false
  base_domain: ts2021.ts
  override_local_dns: false
unix_socket: /var/run/headscale/headscale.sock
logtail:
  enabled: false
EOF

cleanup() { $COMPOSE down -v >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "==> 5/8 构建镜像 + 启动 headscale"
$COMPOSE build -q
$COMPOSE up -d --force-recreate headscale
for i in $(seq 1 30); do
  docker exec ts2021-headscale headscale version >/dev/null 2>&1 && \
    docker exec ts2021-headscale headscale nodes list >/dev/null 2>&1 && break
  sleep 1
done
sleep 3

echo "==> 6/8 创建用户 + preauth key（reusable，lrill 与 node-c 共用）"
docker exec ts2021-headscale headscale users create ts2021 >/dev/null 2>&1 || true
USER_ID=$(docker exec ts2021-headscale headscale users list | sed 's/\x1b\[[0-9;]*m//g' | grep "ts2021" | cut -d'|' -f1 | tr -d ' ' | head -1)
echo "user ts2021 id=$USER_ID"
TS_AUTHKEY=$(docker exec ts2021-headscale headscale preauthkeys create --user "$USER_ID" --reusable)
echo "authkey=$TS_AUTHKEY"
export TS_AUTHKEY

echo "==> 7/8 启动 lrill（自研客户端）+ node-c（官方 tailscaled）"
$COMPOSE up -d --force-recreate lrill node-c

echo "==> 8/8 断言：headscale 节点表出现 lrill-ts2021 与 node-c"
ok=""
for i in $(seq 1 30); do
  NODES=$(docker exec ts2021-headscale headscale nodes list 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g')
  if echo "$NODES" | grep -q "lrill-ts2021" && echo "$NODES" | grep -q "node-c"; then
    ok=yes; break
  fi
  sleep 2
done
docker exec ts2021-headscale headscale nodes list || true

if [ "$ok" != "yes" ]; then
  echo "FAIL: 双节点未全部注册"
  echo "--- headscale 日志 ---"; docker logs ts2021-headscale 2>&1 | tail -15
  echo "--- lrill 日志 ---";    docker logs ts2021-lrill 2>&1 | tail -20
  echo "--- node-c 日志 ---";   docker logs ts2021-node-c 2>&1 | tail -10
  exit 1
fi

echo "PASS: lrill（自研 ts2021 客户端）经 headscale 注册成功，官方 tailscaled 同 tailnet 入网"
docker logs ts2021-lrill 2>&1 | grep -A8 '^{' | head -14 || true
