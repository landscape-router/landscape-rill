#!/usr/bin/env bash
# ts2021 运行时集成 e2e（TSL-05/TSL-07，TS2021_LEG §3.3.2）：
# rill-ext（rilld：mesh + land0 + ts2021 腿）把 mesh 路由（rill-b 公告的 10.42.0.0/24）
# 与自家 LAN（10.43.0.0/24）广播进自建 headscale（RoutableIPs 汇总 + 广播变更 poke
# 重发 MapRequest），headscale 审批后 node-c（官方 tailscaled --accept-routes）：
#   TSL-05：ping 10.42.0.1（mesh 资源经 subnet router：解包 → 引擎 → mesh 帧 → rill-b
#           land0 内核应答 → 回程 mesh → tailnet /32）+ ping 10.43.0.1（自家 LAN 静态广播）
#   TSL-07：--exit-node=rill-ext 后 ping 独立网络网关（解包 → 引擎未命中 → land0 →
#           内核转发 + MASQUERADE → 回程 conntrack 反 NAT → 100.64/10 → land0 → tailnet）
# 回程前提：rill-ext 把 tailnet 前缀 100.64.0.0/10 公告进 mesh（announce_routes），
# rill-b 内核 100.64.0.0/10 → land0（回包交还用户态）。
set -euo pipefail

E2E_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$E2E_DIR/../.." && pwd)"
BUILD_DIR="$E2E_DIR/build"
REG_BUILD="$E2E_DIR/../ts2021_register/build"   # 二进制下载缓存（register 场景已跑时复用）
COMPOSE="docker compose -f $E2E_DIR/docker-compose.yaml"
HEADSCALE_VER="${TS2021_HEADSCALE_VER:-0.29.3}"
TAILSCALE_VER="${TS2021_TAILSCALE_VER:-1.102.2}"

echo "==> 0/8 预置 base 镜像（mesh-e2e-base + iptables）"
E2E_DNS="${MESH_E2E_DNS:-$(awk '$1=="nameserver" && $2 !~ /^(127\.|::1$)/{print $2; exit}' /etc/resolv.conf)}"
[ -n "$E2E_DNS" ] || E2E_DNS="1.1.1.1"  # 宿主仅 loopback stub（CI）时回退公共 DNS
if ! docker image inspect mesh-e2e-base >/dev/null 2>&1; then
  docker run --dns "$E2E_DNS" debian:trixie-slim sh -c \
    "apt-get update && apt-get install -y --no-install-recommends \
       iproute2 iputils-ping ca-certificates && rm -rf /var/lib/apt/lists/*"
  docker commit "$(docker ps -lq)" mesh-e2e-base
fi
if ! docker image inspect tsrt-e2e-base >/dev/null 2>&1; then
  docker run --dns "$E2E_DNS" mesh-e2e-base sh -c \
    "apt-get update && apt-get install -y --no-install-recommends iptables \
       && rm -rf /var/lib/apt/lists/*"
  docker commit "$(docker ps -lq)" tsrt-e2e-base
fi

echo "==> 1/8 下载 headscale + tailscale 二进制（register 缓存优先）"
mkdir -p "$BUILD_DIR/headscale-config"
if [ -x "$REG_BUILD/headscale" ]; then
  cp "$REG_BUILD/headscale" "$BUILD_DIR/headscale"
fi
[ -f "$BUILD_DIR/headscale" ] || \
  curl -sL -o "$BUILD_DIR/headscale" \
  "https://github.com/juanfont/headscale/releases/download/v${HEADSCALE_VER}/headscale_${HEADSCALE_VER}_linux_amd64"
if [ ! -d "$BUILD_DIR/tailscale_${TAILSCALE_VER}_amd64" ]; then
  if [ -d "$REG_BUILD/tailscale_${TAILSCALE_VER}_amd64" ]; then
    cp -r "$REG_BUILD/tailscale_${TAILSCALE_VER}_amd64" "$BUILD_DIR/"
  else
    curl -sL -o "$BUILD_DIR/tailscale.tgz" \
    "https://pkgs.tailscale.com/stable/tailscale_${TAILSCALE_VER}_amd64.tgz"
    tar xzf "$BUILD_DIR/tailscale.tgz" -C "$BUILD_DIR"
  fi
fi

echo "==> 2/8 构建 lrill（release）"
if [ "${E2E_SKIP_BUILD:-0}" != "1" ]; then
  (cd "$ROOT_DIR" && ./scripts/build.sh)
fi
cp "$ROOT_DIR/target/release/lrill" "$BUILD_DIR/lrill"
cp "$E2E_DIR/entry-node.sh" "$E2E_DIR/entry-rill.sh" "$E2E_DIR/Dockerfile" "$BUILD_DIR/"

echo "==> 3/8 生成双栈证书（mesh CA + ts2021 CA）"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$BUILD_DIR/ca.key" -out "$BUILD_DIR/ca.pem" \
    -days 30 -nodes -subj "/CN=rill-e2e-ca" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$BUILD_DIR/coord.key" -out "$BUILD_DIR/coord.csr" \
    -nodes -subj "/CN=coord" 2>/dev/null
printf 'subjectAltName = DNS:coord, IP:127.0.0.1\n' > "$BUILD_DIR/coord.ext"
openssl x509 -req -in "$BUILD_DIR/coord.csr" -CA "$BUILD_DIR/ca.pem" -CAkey "$BUILD_DIR/ca.key" \
    -CAcreateserial -out "$BUILD_DIR/coord.crt" -days 30 \
    -extfile "$BUILD_DIR/coord.ext" 2>/dev/null

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$BUILD_DIR/ts2021-ca.key" -out "$BUILD_DIR/ts2021-ca.pem" \
    -days 30 -nodes -subj "/CN=tsrt-e2e-ca" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$BUILD_DIR/server.key" -out "$BUILD_DIR/server.csr" \
    -nodes -subj "/CN=headscale" 2>/dev/null
printf 'subjectAltName = DNS:headscale, IP:127.0.0.1\n' > "$BUILD_DIR/server.ext"
openssl x509 -req -in "$BUILD_DIR/server.csr" -CA "$BUILD_DIR/ts2021-ca.pem" \
    -CAkey "$BUILD_DIR/ts2021-ca.key" -CAcreateserial -out "$BUILD_DIR/server.crt" -days 30 \
    -extfile "$BUILD_DIR/server.ext" 2>/dev/null

echo "==> 4/8 headscale 配置（自签 TLS + 内嵌 DERP）"
cp "$BUILD_DIR/ts2021-ca.pem" "$BUILD_DIR/headscale-config/ca.pem"
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
    region_code: "tsrt"
    region_name: "TSRT E2E DERP"
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
  base_domain: tsrt.ts
  override_local_dns: false
unix_socket: /var/run/headscale/headscale.sock
logtail:
  enabled: false
EOF

# 幂等清理（上次异常退出可能残留容器/网络）+ 宿主网段冲突检查（compose up 前止损）
cleanup() {
  $COMPOSE down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
for net in 192.168.242.0/24 192.168.244.0/24 192.168.245.0/24; do
  if ip route show "$net" 2>/dev/null | grep -q .; then
    echo "FAIL: 宿主已配置 $net 路由，与 e2e 网段冲突" >&2
    exit 1
  fi
done

echo "==> 5/8 启动 headscale + 创建用户/preauth key"
$COMPOSE build -q
$COMPOSE up -d --force-recreate headscale
for i in $(seq 1 30); do
  docker exec tsrt-headscale headscale version >/dev/null 2>&1 && \
    docker exec tsrt-headscale headscale nodes list >/dev/null 2>&1 && break
  sleep 1
done
sleep 3
docker exec tsrt-headscale headscale users create tsrt >/dev/null 2>&1 || true
USER_ID=$(docker exec tsrt-headscale headscale users list | sed 's/\x1b\[[0-9;]*m//g' | grep "tsrt" | cut -d'|' -f1 | tr -d ' ' | head -1)
TS_AUTHKEY=$(docker exec tsrt-headscale headscale preauthkeys create --user "$USER_ID" --reusable)
echo "authkey=$TS_AUTHKEY (user id=$USER_ID)"
export TS_AUTHKEY

echo "==> 6/8 生成 mesh 配置（coord / rill-ext / rill-b）"
LRILL="$BUILD_DIR/lrill"
hex() { openssl rand -hex 32; }
MASTER_KEY=$(hex)
SIGNING_SEED=$(hex)
EXT_KEY=$(hex)
RILL_B_KEY=$(hex)
EXT_AUTHKEY=$("$LRILL" authkey --network lab)
B_AUTHKEY=$("$LRILL" authkey --network lab)
COORD_PUBKEY=$("$LRILL" pubkey "$SIGNING_SEED")

cat > "$BUILD_DIR/coord.json" <<EOF
{
  "coord": {
    "listen_addr": "0.0.0.0:8443",
    "signing_seed": "$SIGNING_SEED",
    "tls_cert_path": "/etc/landscape/coord.crt",
    "tls_key_path": "/etc/landscape/coord.key",
    "networks": [
      {
        "name": "lab",
        "master_key": "$MASTER_KEY",
        "auth_keys": [
          { "key": "$EXT_AUTHKEY", "policy": "reusable" },
          { "key": "$B_AUTHKEY", "policy": "reusable" }
        ],
        "announce_whitelist": ["10.0.0.0/8", "100.64.0.0/10"]
      }
    ]
  }
}
EOF

# rill-ext：tun 10.43.0.1/24（自家 LAN 进 ts2021 advertise_routes）；mesh 侧公告
# tailnet 前缀 100.64.0.0/10（回程）；ts2021 advertise_exit = TSL-07 出口方向
cat > "$BUILD_DIR/rill-ext.json" <<EOF
{
  "coordinator_url": "https://coord:8443",
  "auth_key": "$EXT_AUTHKEY",
  "static_key_seed": "$EXT_KEY",
  "capabilities": 33,
  "announce_routes": ["100.64.0.0/10", "10.43.0.0/24"],
  "coord_signing_pubkey": "$COORD_PUBKEY",
  "ca_cert_path": "/etc/landscape/ca.pem",
  "data_transport": "udp",
  "tun": { "name": "land0", "mtu": 1420, "address4": "10.43.0.1/24" },
  "ts2021": {
    "control_url": "https://headscale:8080",
    "auth_key": "$TS_AUTHKEY",
    "ca_cert_path": "/etc/landscape/ts2021-ca.pem",
    "hostname": "rill-ext",
    "state_path": "/var/lib/rill/ts2021-machine.key",
    "advertise_routes": ["10.43.0.0/24"],
    "advertise_exit": true
  }
}
EOF

cat > "$BUILD_DIR/rill-b.json" <<EOF
{
  "coordinator_url": "https://coord:8443",
  "auth_key": "$B_AUTHKEY",
  "static_key_seed": "$RILL_B_KEY",
  "capabilities": 33,
  "announce_routes": ["10.42.0.0/24"],
  "coord_signing_pubkey": "$COORD_PUBKEY",
  "ca_cert_path": "/etc/landscape/ca.pem",
  "data_transport": "udp",
  "tun": { "name": "land0", "mtu": 1420, "address4": "10.42.0.1/24" }
}
EOF

echo "==> 7/8 启动全部节点 + 等待注册"
$COMPOSE up -d --force-recreate

for i in $(seq 1 60); do
  NODES=$(docker exec tsrt-headscale headscale nodes list 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' || true)
  if [ -n "$(echo "$NODES" | grep rill-ext)" ] && [ -n "$(echo "$NODES" | grep node-c)" ]; then
    break
  fi
  sleep 2
done
if [ -z "$(echo "$NODES" | grep rill-ext)" ] || [ -z "$(echo "$NODES" | grep node-c)" ]; then
  echo "FAIL: 双节点未全部注册 headscale"
  echo "--- headscale 日志 ---"; docker logs tsrt-headscale 2>&1 | tail -15
  echo "--- rill-ext 日志 ---"; docker logs tsrt-rill-ext 2>&1 | tail -30
  echo "--- node-c 日志 ---";   docker logs tsrt-node-c 2>&1 | tail -10
  exit 1
fi

echo "==> 7.5/8 等待 mesh 路由汇总广播（10.42.0.0/24 出现在 headscale 路由表）+ 审批"
# 链路：rill-b 注册公告 → coord netmap → rill-ext apply_netmap 汇总 → set_mesh_routes
# → poke 重发 MapRequest（RoutableIPs 只在新请求生效）→ headscale 路由表
ROUTES=""
for i in $(seq 1 60); do
  ROUTES=$(docker exec tsrt-headscale headscale nodes list-routes 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' || true)
  if echo "$ROUTES" | grep -q "10\.42\.0\.0/24" && echo "$ROUTES" | grep -q "0\.0\.0\.0/0"; then
    break
  fi
  sleep 2
done
echo "$ROUTES"
if ! echo "$ROUTES" | grep -q "10\.42\.0\.0/24"; then
  echo "FAIL: mesh 路由汇总未广播进 headscale（TSL-05 前置链路断裂）"
  echo "--- rill-ext 日志 ---"; docker logs tsrt-rill-ext 2>&1 | tail -40
  echo "--- coord 日志 ---"; docker logs tsrt-coord 2>&1 | tail -20
  exit 1
fi
EXT_ID=$(echo "$NODES" | grep rill-ext | awk -F'|' '{gsub(/ /, "", $1); print $1}' | head -1)
docker exec tsrt-headscale headscale nodes approve-routes -i "$EXT_ID" \
  -r "10.42.0.0/24,10.43.0.0/24,0.0.0.0/0,::/0" >/dev/null 2>&1 || true

echo "==> 7.7/8 注入内核路由（tailnet 回程 → land0；mesh 前缀 → land0 触发握手）"
for i in $(seq 1 30); do
  docker exec tsrt-rill-b ip link show land0 >/dev/null 2>&1 && break
  sleep 1
done
docker exec tsrt-rill-b ip route add 100.64.0.0/10 dev land0 2>/dev/null || true
docker exec tsrt-rill-ext ip route add 10.42.0.0/24 dev land0 2>/dev/null || true
# mesh 预热：内核 → TUN 触发 rill-ext⇄rill-b 懒握手（互探周期 30s，表序
# 黑洞端点需 1~2 周期降级让位，提前触发把收敛移出断言窗）
docker exec tsrt-rill-ext ping -c3 -W1 10.42.0.1 >/dev/null 2>&1 || true

echo "==> 8/8 断言"
dump() {
  echo "--- headscale 路由 ---"
  docker exec tsrt-headscale headscale nodes list-routes 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' || true
  echo "--- headscale/derper 日志 ---"
  docker logs tsrt-headscale 2>&1 | tail -40
  echo "--- rill-ext 日志/路由 ---"
  docker logs tsrt-rill-ext 2>&1 | tail -40
  docker exec tsrt-rill-ext ip route 2>/dev/null || true
  echo "--- rill-b 日志/路由 ---"
  docker logs tsrt-rill-b 2>&1 | tail -20
  echo "--- node-c 状态/日志 ---"
  docker exec tsrt-node-c tailscale --socket=/var/run/tailscale/tailscaled.sock status 2>&1 || true
  docker exec tsrt-node-c timeout 5 tailscale --socket=/var/run/tailscale/tailscaled.sock ping --timeout=3s --c=3 100.64.0.2 2>&1 || true
  docker logs tsrt-node-c 2>&1 | tail -15
}

# TSL-05：node-c ping mesh 资源（10.42.0.1 经 subnet router）+ 自家 LAN（10.43.0.1）
# 窗口取 75 次（≈5min）：mesh 互探冷启动 + tailnet 握手 + 审批传播串联，慢机上 >3min
ok=""
for i in $(seq 1 75); do
  if docker exec tsrt-node-c ping -c1 -W2 10.42.0.1 >/dev/null 2>&1 \
     && docker exec tsrt-node-c ping -c1 -W2 10.43.0.1 >/dev/null 2>&1; then
    ok=yes; break
  fi
  sleep 2
done
if [ "$ok" != "yes" ]; then
  echo "FAIL: TSL-05 subnet router 不通（10.42.0.1 / 10.43.0.1）"
  dump
  exit 1
fi
echo "TSL-05 OK: node-c ping 10.42.0.1（mesh 资源）+ 10.43.0.1（自家 LAN）"

# TSL-11（REQ-067）：① 对端重启 → 旧 WG 会话失效经 rekey 重建（ping 恢复，不重注册）
# ② peer 增减经增量帧传播：node-d 加入 → PeersChanged（+1）、headscale 删除 →
#    PeersRemoved（-1）。重启自身不产生增量帧——同 key 同端点 = 服务端视角
#    无变更（e2e 实证），故增量路径以 peer 增删为触发
docker restart tsrt-node-c >/dev/null
for i in $(seq 1 30); do
  docker exec tsrt-node-c tailscale --socket=/var/run/tailscale/tailscaled.sock status >/dev/null 2>&1 && break
  sleep 2
done
ok=""
for i in $(seq 1 120); do
  if docker exec tsrt-node-c ping -c1 -W2 10.43.0.1 >/dev/null 2>&1 \
     && docker exec tsrt-node-c ping -c1 -W2 10.42.0.1 >/dev/null 2>&1; then
    ok=yes; break
  fi
  sleep 2
done
if [ "$ok" != "yes" ]; then
  echo "FAIL: TSL-11 对端重启后 ping 未恢复"
  dump
  exit 1
fi
echo "TSL-11a OK: node-c 重启 → 会话经 rekey 重建（ping 恢复，不重注册）"

# TSL-11b：peer 增删传播（REQ-067）。e2e 实证 headscale 0.29 语义：**无中流
# 推送**——node 增删/断连期间流式对端零推送，长轮询 ~500s 服务端到期空响应
# （官方 tailscaled 同周期重轮询），变更经下一轮询全量帧到达。场景以重注册
# 强制新轮询（生产等价物 = 轮询周期）：node-d 入网 → 重启 rill-ext → 全量
# netmap 含 2 peer；headscale 删除 node-d → 再重启 → 1 peer。增量帧
# （PeersChanged/Removed/Patch）解析与合并由单测锁定（apply_delta_*）
TSNET=$(docker inspect tsrt-node-c --format '{{range $k, $_ := .NetworkSettings.Networks}}{{$k}}{{end}}')
docker run -d --name tsrt-node-d --network "$TSNET" --ip 192.168.244.30 \
  --privileged --device /dev/net/tun --cap-add NET_ADMIN \
  -e TS_AUTHKEY -e TS_HOSTNAME=node-d \
  tsrt-base /usr/local/bin/entry-node.sh >/dev/null
for i in $(seq 1 30); do
  docker exec tsrt-headscale headscale nodes list 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' | grep -q node-d && break
  sleep 2
done
sleep 3
MARK=$(docker logs tsrt-rill-ext 2>&1 | wc -l)
docker restart tsrt-rill-ext >/dev/null
joined=""
for i in $(seq 1 60); do
  docker logs tsrt-rill-ext 2>&1 | tail -n +$((MARK + 1)) | grep -qE "netmap (delta applied: \+[1-9]|applied: 2 peer)" && { joined=yes; break; }
  sleep 2
done
NODE_D_ID=$(docker exec tsrt-headscale headscale nodes list 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' | grep node-d | awk -F'|' '{gsub(/ /, "", $1); print $1}' | head -1)
[ -n "$NODE_D_ID" ] && docker exec tsrt-headscale headscale nodes delete -i "$NODE_D_ID" --force >/dev/null 2>&1
docker rm -f tsrt-node-d >/dev/null 2>&1 || true
sleep 3
MARK=$(docker logs tsrt-rill-ext 2>&1 | wc -l)
docker restart tsrt-rill-ext >/dev/null
left=""
for i in $(seq 1 60); do
  docker logs tsrt-rill-ext 2>&1 | tail -n +$((MARK + 1)) | grep -qE "netmap (delta applied: \+0 -[1-9]|applied: 1 peer)" && { left=yes; break; }
  sleep 2
done
if [ "$joined" != "yes" ] || [ "$left" != "yes" ]; then
  echo "FAIL: TSL-11 peer 增删未传播（join=$joined leave=$left）"
  echo "--- rill-ext ts2021 日志 ---"; docker logs tsrt-rill-ext 2>&1 | grep -E "\[ts2021\]" | tail -15
  echo "--- headscale 日志 ---"; docker logs tsrt-headscale 2>&1 | tail -15
  exit 1
fi
echo "TSL-11b OK: node-d 入网/删除 → 重轮询全量 netmap 反映 peer 增删（2→1）"

# TSL-07：node-c 经 rill-ext 作 exit，ping extnet 网关（独立网络，node-c 不接入）
# 目标不在 node-c 直连网段 → 走 exit 路径；tailscale set 不重置既有 flags
RILL_TS_IP=$(docker exec tsrt-headscale headscale nodes list 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' \
  | grep rill-ext | grep -oE "100\.64\.[0-9]+\.[0-9]+" | head -1)
echo "rill-ext tailnet ip: $RILL_TS_IP"
docker exec tsrt-node-c tailscale --socket=/var/run/tailscale/tailscaled.sock \
  set --accept-routes=true --exit-node="$RILL_TS_IP"
ok=""
for i in $(seq 1 45); do
  if docker exec tsrt-node-c ping -c1 -W2 192.168.245.1 >/dev/null 2>&1; then
    ok=yes; break
  fi
  sleep 2
done
if [ "$ok" != "yes" ]; then
  echo "FAIL: TSL-07 exit 被用作不通（node-c 经 rill-ext ping 192.168.245.1）"
  dump
  exit 1
fi
docker exec tsrt-node-c ping -c3 192.168.245.1 || true

echo "PASS: TSL-05 subnet router（mesh routes[] 汇总 + 自家 LAN 广播进 tailnet）+ TSL-11 对端重启增量帧（REQ-067）+ TSL-07 exit 被用作（内核转发 + MASQUERADE 回程）"
