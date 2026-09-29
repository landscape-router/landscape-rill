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

echo "==> 2/8 构建 lrill ts2021-probe（release）"
if [ "${E2E_SKIP_BUILD:-0}" != "1" ]; then
  (cd "$ROOT_DIR" && cargo build --release -p landscape-rill-ts2021 --bin ts2021-probe)
fi
cp "$ROOT_DIR/target/release/ts2021-probe" "$BUILD_DIR/ts2021-probe"
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

cleanup() {
  $COMPOSE down -v >/dev/null 2>&1 || true
  docker network rm ts2021exit >/dev/null 2>&1 || true
}
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

# exit 转发目标（TSL-06）：独立 docker 网络（node-c 不接入）的网关。
# 目标不能在本网段：tailscaled 对 0.0.0.0/0 广播做 shrink（剔除本机直连网段与 RFC1918，
# guest-wifi 语义），docker 网段全是 RFC1918 —— 目标子网需 node-c 显式子网广播 + headscale 审批
docker network inspect ts2021exit >/dev/null 2>&1 || docker network create ts2021exit >/dev/null
EXIT_NET=$(docker network inspect ts2021exit --format '{{range .IPAM.Config}}{{.Gateway}} {{.Subnet}}{{end}}')
export TS_EXIT_TARGET="${EXIT_NET%% *}"
export TS_ADVERTISE_ROUTE="${EXIT_NET##* }"
echo "exit target=$TS_EXIT_TARGET subnet=$TS_ADVERTISE_ROUTE"

echo "==> 7/8 启动 lrill（自研客户端）+ node-c（官方 tailscaled，advertise-exit-node + 目标子网）"
$COMPOSE up -d --force-recreate lrill node-c

echo "==> 7.5/8 审批 node-c 路由（exit 0.0.0.0/0 + ::/0 + 目标子网，headscale 侧放行）"
for i in $(seq 1 30); do
  ROUTES=$(docker exec ts2021-headscale headscale nodes list-routes 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g')
  echo "$ROUTES" | grep -q "0.0.0.0/0" && break
  sleep 2
done
NODE_C_ID=$(docker exec ts2021-headscale headscale nodes list 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' \
  | grep "node-c" | awk -F'|' '{gsub(/ /, "", $1); print $1}' | head -1)
docker exec ts2021-headscale headscale nodes approve-routes -i "$NODE_C_ID" \
  -r "0.0.0.0/0,::/0,$TS_ADVERTISE_ROUTE" >/dev/null 2>&1 || true

echo "==> 8/8 断言：双节点注册 + lrill WG ping node-c + node-c 反向 ping lrill + exit 转发"
ok=""
for i in $(seq 1 45); do
  if docker logs ts2021-lrill 2>&1 | grep -q "PEER_PING_OK"; then
    ok=yes; break
  fi
  sleep 2
done
docker exec ts2021-headscale headscale nodes list || true
NODES=$(docker exec ts2021-headscale headscale nodes list 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g')
if [ -z "$(echo "$NODES" | grep "lrill-ts2021")" ] || [ -z "$(echo "$NODES" | grep "node-c")" ]; then
  echo "FAIL: 双节点未全部注册"
  echo "--- headscale 日志 ---"; docker logs ts2021-headscale 2>&1 | tail -15
  echo "--- lrill 日志 ---";    docker logs ts2021-lrill 2>&1 | tail -25
  echo "--- node-c 日志 ---";   docker logs ts2021-node-c 2>&1 | tail -10
  exit 1
fi

if [ "$ok" != "yes" ]; then
  echo "FAIL: lrill 未完成 WG ping peer"
  echo "--- lrill 日志 ---";  docker logs ts2021-lrill 2>&1 | tail -25
  echo "--- node-c 日志 ---"; docker logs ts2021-node-c 2>&1 | tail -10
  exit 1
fi

# 反向断言：官方 tailscaled ping lrill 的 tailnet IP（lrill 常驻应答 echo）
LRILL_IP=$(echo "$NODES" | grep "lrill-ts2021" | grep -oE "100\.64\.[0-9]+\.[0-9]+" | head -1)
echo "lrill tailnet ip: $LRILL_IP（node-c 反向 ping）"
REV_OK=""
for i in $(seq 1 15); do
  if docker exec ts2021-node-c ping -c1 -W2 "$LRILL_IP" >/dev/null 2>&1; then
    REV_OK=yes; break
  fi
  sleep 2
done
if [ "$REV_OK" != "yes" ]; then
  echo "FAIL: node-c 反向 ping lrill 不通（$LRILL_IP）"
  docker exec ts2021-node-c ping -c3 -W2 "$LRILL_IP" || true
  echo "--- lrill 日志 ---"
  docker logs ts2021-lrill 2>&1 | tail -20
  echo "--- node-c 日志 ---"; docker logs ts2021-node-c 2>&1 | tail -15
  exit 1
fi
docker exec ts2021-node-c ping -c3 "$LRILL_IP" || true

# exit 断言（TSL-06）：lrill 经 node-c（exit node）转发 ping 独立网络网关（MASQUERADE + 回程）
EXIT_OK=""
for i in $(seq 1 45); do
  if docker logs ts2021-lrill 2>&1 | grep -q "EXIT_PING_OK"; then
    EXIT_OK=yes; break
  fi
  sleep 2
done
if [ "$EXIT_OK" != "yes" ]; then
  echo "FAIL: lrill 经 exit node(node-c) 转发 ping 外部地址不通"
  echo "--- lrill 日志 ---"; docker logs ts2021-lrill 2>&1 | tail -20
  echo "--- node-c 路由 ---"; docker exec ts2021-headscale headscale nodes list-routes 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' || true
  exit 1
fi

# 重启断言（TSL-10）：machine key 持久 → 节点身份稳定（ID 不变、无重复注册）；
# node key 每次轮换 → 注册更新后数据面重建（再次 PEER_PING_OK）
node_id() {
  docker exec ts2021-headscale headscale nodes list 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' \
    | grep "lrill-ts2021" | awk -F'|' '{gsub(/ /, "", $1); print $1}' | head -1
}
ID_BEFORE=$(node_id)
PINGS_BEFORE=$(docker logs ts2021-lrill 2>&1 | grep -c PEER_PING_OK)
docker restart ts2021-lrill >/dev/null
ok2=""
for i in $(seq 1 45); do
  if [ "$(docker logs ts2021-lrill 2>&1 | grep -c PEER_PING_OK)" -gt "$PINGS_BEFORE" ]; then
    ok2=yes; break
  fi
  sleep 2
done
if [ "$ok2" != "yes" ]; then
  echo "FAIL: lrill 重启后数据面未重建（node key 轮换路径）"
  echo "--- lrill 日志 ---"; docker logs ts2021-lrill 2>&1 | tail -20
  exit 1
fi
NODES2=$(docker exec ts2021-headscale headscale nodes list 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g')
ROWS2=$(echo "$NODES2" | grep -c "lrill-ts2021")
ID_AFTER=$(node_id)
if [ "$ROWS2" != "1" ] || [ "$ID_BEFORE" != "$ID_AFTER" ]; then
  echo "FAIL: 重启后节点身份不稳定 rows=$ROWS2 id $ID_BEFORE -> $ID_AFTER"
  echo "$NODES2"
  exit 1
fi

echo "PASS: lrill（自研 ts2021 客户端）经 headscale 入网，与官方 tailscaled 双向 WG ping + exit 转发互通（重启身份稳定）"
docker logs ts2021-lrill 2>&1 | grep -E "REGISTER_OK|WG_PEER|PEER_PING_OK" | head -5 || true
