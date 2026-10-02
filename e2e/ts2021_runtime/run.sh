#!/usr/bin/env bash
# ts2021 运行时集成 e2e（TSL-05/TSL-07/TSL-11，TS2021_LEG §3.3.2/§4，REQ-068）：
# 控制面换自研 ts2021 服务端（tsrv = lrill ts2021_server 段：Noise 控制面 + 白名单
# 自动审批 + 内嵌 DERP），官方 tailscaled（node-c/node-d）作为协议兼容实证接入。
# rill-ext（rilld：mesh + land0 + ts2021 腿）把 mesh 路由（rill-b 公告的 10.42.0.0/24）
# 与自家 LAN（10.43.0.0/24）广播进 tsrv（RoutableIPs 汇总 + 广播变更 poke 重发
# MapRequest），白名单自动审批后 node-c（官方 tailscaled --accept-routes）：
#   TSL-05：ping 10.42.0.1（mesh 资源经 subnet router）+ ping 10.43.0.1（自家 LAN）
#   E2E-08：tailnet 段大包——DF @ tailscale0 MTU 上限整包双向通（mesh 段由 mtu.sh 闭环）
#   TSL-07：--exit-node=rill-ext 后 ping 独立网络网关（allow_exit 放行的 0.0.0.0/0）
#   TSL-11：node-d 入网 → rill-ext 持有流收到 PeersChanged（+1，无重轮询/重启）；
#           驱逐 node-d（e2e 注入 marker）→ PeersRemoved（-1）——REQ-068 增量推送实证
#   E2E-07（REQ-071/REQ-012，收尾阶段）：rill-b 加 ts2021 腿（偏好 tailnet>mesh；
#   子网路由成员——ts2021 advertise 自家 LAN，tailnet 侧源受理性前提）
#   + rill-x（mesh 出口，extnet 双挂）——tailnet exit 独占承载 → 授权 mesh exit 后
#   偏好裁决仍走 tailnet（双出口 MASQUERADE 计数器对照）→ 驱逐 rill-ext（tailnet
#   候选摘除）→ 解析器顺延 mesh exit 承载（切换收敛，无环路）
# 回程前提：rill-ext 把 tailnet 前缀 100.64.0.0/10 公告进 mesh（announce_routes），
# rill-b 内核 100.64.0.0/10 → land0（回包交还用户态）。
set -euo pipefail

E2E_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$E2E_DIR/../.." && pwd)"
BUILD_DIR="$E2E_DIR/build"
REG_BUILD="$E2E_DIR/../ts2021_register/build"   # 二进制下载缓存（register 场景已跑时复用）
COMPOSE="docker compose -f $E2E_DIR/docker-compose.yaml"
TAILSCALE_VER="${TS2021_TAILSCALE_VER:-1.102.2}"
TSRV="tsrt-tsrv"

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

echo "==> 1/8 下载 tailscale 二进制（register 缓存优先）"
# cp -r 的目标目录必须已存在，否则包内容被平铺进 build/ 而非子目录，
# Dockerfile 的 tailscale_*/ 通配 COPY 会静默落空（chmod 才暴露）
mkdir -p "$BUILD_DIR"
if [ ! -d "$BUILD_DIR/tailscale_${TAILSCALE_VER}_amd64" ]; then
  if [ -d "$REG_BUILD/tailscale_${TAILSCALE_VER}_amd64" ]; then
    cp -r "$REG_BUILD/tailscale_${TAILSCALE_VER}_amd64" "$BUILD_DIR/"
  else
    curl -sL -o "$BUILD_DIR/tailscale.tgz" \
    "https://pkgs.tailscale.com/stable/tailscale_${TAILSCALE_VER}_amd64.tgz"
    tar xzf "$BUILD_DIR/tailscale.tgz" -C "$BUILD_DIR"
  fi
fi
# BuildKit 对未命中的 COPY 通配静默跳过，这里显式把关二进制落位
[ -f "$BUILD_DIR/tailscale_${TAILSCALE_VER}_amd64/tailscaled" ] && \
[ -f "$BUILD_DIR/tailscale_${TAILSCALE_VER}_amd64/tailscale" ] || {
  echo "FAIL: tailscale 二进制未落位到 build/tailscale_${TAILSCALE_VER}_amd64/" >&2
  exit 1
}

echo "==> 2/8 构建 lrill（release）"
if [ "${E2E_SKIP_BUILD:-0}" != "1" ]; then
  (cd "$ROOT_DIR" && ./scripts/build.sh)
fi
cp "$ROOT_DIR/target/release/lrill" "$BUILD_DIR/lrill"
cp "$E2E_DIR/entry-node.sh" "$E2E_DIR/entry-rill.sh" "$E2E_DIR/entry-exit.sh" "$E2E_DIR/Dockerfile" "$BUILD_DIR/"

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
    -nodes -subj "/CN=tsrv" 2>/dev/null
printf 'subjectAltName = DNS:tsrv, IP:127.0.0.1\n' > "$BUILD_DIR/server.ext"
openssl x509 -req -in "$BUILD_DIR/server.csr" -CA "$BUILD_DIR/ts2021-ca.pem" \
    -CAkey "$BUILD_DIR/ts2021-ca.key" -CAcreateserial -out "$BUILD_DIR/server.crt" -days 30 \
    -extfile "$BUILD_DIR/server.ext" 2>/dev/null

echo "==> 4/8 tsrv 配置（自研 ts2021 服务端：lrk 准入 + 白名单自动审批 + allow_exit）"
LRILL="$BUILD_DIR/lrill"
TS_AUTHKEY=$("$LRILL" authkey --network tsrt --ttl 0)
export TS_AUTHKEY
cat > "$BUILD_DIR/tsrv.json" <<EOF
{
  "ts2021_server": {
    "network": "tsrt",
    "hostname": "tsrv",
    "listen_addr": "0.0.0.0:8080",
    "tls_cert_path": "/etc/landscape/server.crt",
    "tls_key_path": "/etc/landscape/server.key",
    "noise_key_path": "/var/lib/rill/ts2021-noise.key",
    "derp_key_path": "/var/lib/rill/ts2021-derp.key",
    "auth_keys": ["$TS_AUTHKEY"],
    "routes_whitelist": ["10.42.0.0/24", "10.43.0.0/24"],
    "allow_exit": true
  }
}
EOF

# 幂等清理（上次异常退出可能残留容器/网络）+ 宿主网段冲突检查（compose up 前止损）
cleanup() {
  $COMPOSE down -v >/dev/null 2>&1 || true
  docker rm -f tsrt-node-d >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
for net in 192.168.242.0/24 192.168.244.0/24 192.168.245.0/24; do
  if ip route show "$net" 2>/dev/null | grep -q .; then
    echo "FAIL: 宿主已配置 $net 路由，与 e2e 网段冲突" >&2
    exit 1
  fi
done

echo "==> 5/8 启动 tsrv（自研 ts2021 服务端）"
$COMPOSE build
$COMPOSE up -d --force-recreate tsrv
# 成功标志位判收：`grep -q && break` 在 pipefail 下有 SIGPIPE 隐患（grep 提前退出
# → docker logs 141 → break 不触发），且循环后再探一次会撞 docker 日志传播延迟
# （listening 已写但未可见 → 误判 FAIL，CI run 36865796734）
tsrv_ok=0
for i in $(seq 1 30); do
  if docker logs "$TSRV" 2>&1 | grep -q "ts2021-server.*listening"; then
    tsrv_ok=1
    break
  fi
  sleep 1
done
if [ "$tsrv_ok" != 1 ]; then
  echo "FAIL: tsrv 未监听"
  docker logs "$TSRV" 2>&1 | tail -20
  exit 1
fi

echo "==> 6/8 生成 mesh 配置（coord / rill-ext / rill-b）"
hex() { openssl rand -hex 32; }
MASTER_KEY=$(hex)
SIGNING_SEED=$(hex)
EXT_KEY=$(hex)
RILL_B_KEY=$(hex)
RILL_X_KEY=$(hex)
EXT_AUTHKEY=$("$LRILL" authkey --network lab)
B_AUTHKEY=$("$LRILL" authkey --network lab)
X_AUTHKEY=$("$LRILL" authkey --network lab)
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
          { "key": "$B_AUTHKEY", "policy": "reusable" },
          { "key": "$X_AUTHKEY", "policy": "reusable" }
        ],
        "announce_whitelist": ["10.0.0.0/8", "100.64.0.0/10"],
        "exits": { "allow": [] }
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
    "control_url": "https://tsrv:8080",
    "auth_key": "$TS_AUTHKEY",
    "ca_cert_path": "/etc/landscape/ts2021-ca.pem",
    "hostname": "rill-ext",
    "state_path": "/var/lib/rill/ts2021-machine.key",
    "advertise_routes": ["10.43.0.0/24"],
    "advertise_exit": true,
    "advertise_mesh_routes": true
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
  "default_route_preference": ["tailnet", "mesh"],
  "tun": { "name": "land0", "mtu": 1420, "address4": "10.42.0.1/24" },
  "ts2021": {
    "control_url": "https://tsrv:8080",
    "auth_key": "$TS_AUTHKEY",
    "ca_cert_path": "/etc/landscape/ts2021-ca.pem",
    "hostname": "rill-b",
    "state_path": "/var/lib/rill/ts2021-machine.key",
    "advertise_routes": ["10.42.0.0/24"]
  }
}
EOF

# rill-x（E2E-07 mesh 出口）：能力位 0x08 纯 exit；extnet 双挂（entry-exit.sh
# 置 ip_forward + MASQUERADE）；coord exits.allow 初始空（阶段 b SIGHUP 授权）
cat > "$BUILD_DIR/rill-x.json" <<EOF
{
  "coordinator_url": "https://coord:8443",
  "auth_key": "$X_AUTHKEY",
  "static_key_seed": "$RILL_X_KEY",
  "capabilities": 8,
  "announce_routes": [],
  "coord_signing_pubkey": "$COORD_PUBKEY",
  "ca_cert_path": "/etc/landscape/ca.pem",
  "data_transport": "udp",
  "tun": { "name": "land0", "mtu": 1420, "address4": "10.44.0.1/24" }
}
EOF

echo "==> 7/8 启动全部节点 + 等待注册（tsrv 日志为注册观测面）"
$COMPOSE up -d --force-recreate

for i in $(seq 1 60); do
  NODES=$(docker logs "$TSRV" 2>&1 || true)
  if [ -n "$(echo "$NODES" | grep "host=rill-ext")" ] && [ -n "$(echo "$NODES" | grep "host=node-c")" ]; then
    break
  fi
  sleep 2
done
if [ -z "$(echo "$NODES" | grep "host=rill-ext")" ] || [ -z "$(echo "$NODES" | grep "host=node-c")" ]; then
  echo "FAIL: 双节点未全部注册 tsrv（官方 tailscaled 与自研服务端互通断言前置）"
  echo "--- tsrv 日志 ---"; docker logs "$TSRV" 2>&1 | tail -30
  echo "--- rill-ext 日志 ---"; docker logs tsrt-rill-ext 2>&1 | tail -30
  echo "--- node-c 日志 ---";   docker logs tsrt-node-c 2>&1 | tail -15
  exit 1
fi

echo "==> 7.5/8 等待路由白名单自动审批（10.42.0.0/24 mesh 汇总 + 0.0.0.0/0 exit）"
# 链路：rill-b 注册公告 → coord netmap → rill-ext apply_netmap 汇总 → set_mesh_routes
# → poke 重发 MapRequest（RoutableIPs 只在新请求生效）→ tsrv 白名单过滤即批准
# （rill-b 自家 LAN 也广播——子网路由成员；断言按"存在性"而非最后一行，
# 两条审批行谁后到不定）
ROUTES=""
for i in $(seq 1 60); do
  ROUTES=$(docker logs "$TSRV" 2>&1 | grep "routes approved" || true)
  if echo "$ROUTES" | grep -q "10\.42\.0\.0/24" && echo "$ROUTES" | grep -q "0\.0\.0\.0/0"; then
    break
  fi
  ROUTES=""
  sleep 2
done
echo "$ROUTES"
if [ -z "$ROUTES" ] || ! echo "$ROUTES" | grep -q "10\.42\.0\.0/24"; then
  echo "FAIL: mesh 路由汇总未广播进 tsrv（TSL-05 前置链路断裂）"
  echo "--- rill-ext 日志 ---"; docker logs tsrt-rill-ext 2>&1 | tail -40
  echo "--- coord 日志 ---"; docker logs tsrt-coord 2>&1 | tail -20
  exit 1
fi

echo "==> 7.7/8 注入内核路由（tailnet 回程 → land0；mesh 前缀 → land0 触发握手）"
for i in $(seq 1 30); do
  docker exec tsrt-rill-b ip link show land0 >/dev/null 2>&1 && break
  sleep 1
done
docker exec tsrt-rill-b ip route add 100.64.0.0/10 dev land0 2>/dev/null || true
docker exec tsrt-rill-ext ip route add 10.42.0.0/24 dev land0 2>/dev/null || true
# E2E-07：extnet 前缀 → land0（否则 rill-b 内核默认路由经宿主网桥直达 extnet，绕过裁决）
docker exec tsrt-rill-b ip route add 192.168.245.0/24 dev land0 2>/dev/null || true
# mesh 预热：内核 → TUN 触发 rill-ext⇄rill-b 懒握手（互探周期 30s，表序
# 黑洞端点需 1~2 周期降级让位，提前触发把收敛移出断言窗）
docker exec tsrt-rill-ext ping -c3 -W1 10.42.0.1 >/dev/null 2>&1 || true

echo "==> 8/8 断言"
dump() {
  echo "--- tsrv（自研 ts2021 服务端）日志 ---"
  docker logs "$TSRV" 2>&1 | tail -40
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
# 窗口取 75 次（≈5min）：mesh 互探冷启动 + tailnet 握手串联，慢机上 >3min
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

# E2E-08 tailnet 段大包（REQ-009/012）：整链 DF @ 手机侧上限。上限由官方
# tailscale0 MTU（1280）决定——"1500 级大包"在手机内核即被本地拒收，能进入
# 隧道的最大整包就是该 MTU；断言取实际上限整包 DF 双向穿透（WG 段 1280+60、
# mesh 段 1280+86 均低于 1500 底网，全程无需 PTB）。mesh 段 MSS clamp/PTB
# 语义已由 mtu.sh（RTE-07）容器级闭环；TCP MSS 在手机侧由内核按 tailscale0
# MTU 自derive，mesh→LAN 侧压 MSS 由 write_lan 承担（RTE-07 已验）
TS_MTU=$(docker exec tsrt-node-c ip link show tailscale0 | grep -o 'mtu [0-9]*' | grep -o '[0-9]*$')
BIGPAY=$((TS_MTU - 28))
if ! docker exec tsrt-node-c ping -c3 -W3 -M do -s "$BIGPAY" 10.42.0.1 >/dev/null 2>&1; then
  echo "FAIL: E2E-08 tailnet 段大包不通（DF ${TS_MTU}B = tailscale0 上限整包）"
  dump
  exit 1
fi
echo "E2E-08 OK: tailnet 段大包 DF 整包 ${TS_MTU}B 双向通（payload $BIGPAY，全程无 PTB）"

# TSL-11a（REQ-067）：对端重启 → 旧 WG 会话失效经 rekey 重建（ping 恢复，不重注册）
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

# TSL-11b（REQ-068 增量推送）：持有流上 peer 增删 = 增量帧实时到达，
# 不强制重轮询/重启（headscale 0.29 无中流推送，自研服务端补齐）。
# node-d（官方 tailscaled）入网 → tsrv 广播 PeersChanged → rill-ext 持有流
# 收到增量帧（"netmap delta applied: +1"）；marker 文件驱逐 node-d →
# PeersRemoved（"+0 -1"）。e2e 注入：env RILL_E2E_TS2021_EVICT_NODE + marker
TSNET=$(docker inspect tsrt-node-c --format '{{range $k, $_ := .NetworkSettings.Networks}}{{$k}}{{end}}')
MARK=$(docker logs tsrt-rill-ext 2>&1 | wc -l)
docker run -d --name tsrt-node-d --network "$TSNET" --ip 192.168.244.30 \
  --privileged --device /dev/net/tun --cap-add NET_ADMIN \
  -e TS_AUTHKEY -e TS_HOSTNAME=node-d \
  tsrt-base /usr/local/bin/entry-node.sh >/dev/null
joined=""
for i in $(seq 1 60); do
  docker logs tsrt-rill-ext 2>&1 | tail -n +$((MARK + 1)) | grep -qE "netmap delta applied: \+[1-9]" && { joined=yes; break; }
  sleep 2
done
evicted=""
if [ "$joined" = "yes" ]; then
  MARK2=$(docker logs tsrt-rill-ext 2>&1 | wc -l)
  docker exec "$TSRV" touch /tmp/rill-e2e-evict/node-d
  for i in $(seq 1 30); do
    docker logs tsrt-rill-ext 2>&1 | tail -n +$((MARK2 + 1)) | grep -qE "netmap delta applied: \+0 -[1-9]" && { evicted=yes; break; }
    sleep 2
  done
fi
docker rm -f tsrt-node-d >/dev/null 2>&1 || true
if [ "$joined" != "yes" ] || [ "$evicted" != "yes" ]; then
  echo "FAIL: TSL-11b 持有流增量推送未生效（join=$joined evict=$evicted）"
  echo "--- rill-ext ts2021 日志 ---"; docker logs tsrt-rill-ext 2>&1 | grep -E "\[ts2021\]" | tail -15
  echo "--- tsrv 日志 ---"; docker logs "$TSRV" 2>&1 | tail -20
  exit 1
fi
echo "TSL-11b OK: node-d 入网/驱逐 → rill-ext 持有流增量帧（+1 / -1，无重轮询）"

# TSL-07：node-c 经 rill-ext 作 exit，ping extnet 网关（独立网络，node-c 不接入）
# 目标不在 node-c 直连网段 → 走 exit 路径；tailscale set 不重置既有 flags
RILL_TS_IP=$(docker logs "$TSRV" 2>&1 | grep "host=rill-ext" | grep -oE "100\.64\.[0-9]+\.[0-9]+" | head -1)
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

# ---- E2E-07（REQ-071/REQ-012，ROUTE_ENGINE §5.1）：tailnet/mesh exit 竞争 ----
# 证据基座 = 双出口各自的 MASQUERADE 规则计数器（承载归属唯一判据，无日志级别依赖）：
# rill-ext 规则源 10.42.0.0/24（tailnet 出口借道）/ rill-x 规则源 10.42.0.0/24（mesh 出口）
masq_pkts() {  # $1=容器 $2=规则源段
  docker exec "$1" iptables -t nat -L POSTROUTING -nvx 2>/dev/null \
    | awk -v src="$2" '$3=="MASQUERADE" && $8==src{s+=$1} END{print s+0}'
}
b_netmap_ver() { docker logs tsrt-rill-b 2>&1 | grep 'netmap v' | tail -1 | sed 's/.*netmap v\([0-9]*\):.*/\1/'; }

echo "==> E2E-07 阶段 a：tailnet exit 独占承载（mesh 出口未授权，唯一候选）"
for i in $(seq 1 60); do
  docker logs "$TSRV" 2>&1 | grep "host=rill-b" >/dev/null && break
  sleep 2
done
docker logs "$TSRV" 2>&1 | grep "host=rill-b" >/dev/null || {
  echo "FAIL: E2E-07 rill-b 的 ts2021 腿未注册"
  dump; exit 1
}
ok=""
for i in $(seq 1 75); do
  docker exec tsrt-rill-b ping -c1 -W2 192.168.245.1 >/dev/null 2>&1 && { ok=yes; break; }
  sleep 2
done
[ "$ok" = "yes" ] || { echo "FAIL: E2E-07 阶段 a tailnet exit 借道不通（rill-b → 192.168.245.1）"; dump; exit 1; }
A_EXT=$(masq_pkts tsrt-rill-ext "10.42.0.0/24")
A_X=$(masq_pkts tsrt-rill-x "10.42.0.0/24")
[ "$A_EXT" -gt 0 ] || { echo "FAIL: rill-ext MASQ 计数未增长（tailnet 出口未承载）"; exit 1; }
[ "$A_X" -eq 0 ] || { echo "FAIL: mesh 出口未授权却被承载（MASQ=${A_X}——准入未 fail-closed？）"; exit 1; }
echo "E2E-07a OK: tailnet exit 独占承载（rill-ext MASQ=${A_EXT}，rill-x=0）"

echo "==> E2E-07 阶段 b：授权 mesh exit → 双候选下偏好裁决仍走 tailnet"
X_ID=$(docker logs tsrt-rill-x 2>&1 | grep 'registered:' | sed -n '1s/.*node_id=\([0-9]*\).*/\1/p')
[ -n "$X_ID" ] || { echo "FAIL: rill-x 未注册 mesh"; docker logs tsrt-rill-x 2>&1 | tail -10; exit 1; }
V1=$(b_netmap_ver)
python3 - "$BUILD_DIR/coord.json" "$X_ID" <<'PYX'
import json, sys
path, xid = sys.argv[1], int(sys.argv[2])
cfg = json.load(open(path))
for net in cfg["coord"]["networks"]:
    if net["name"] == "lab":
        net["exits"] = {"allow": [xid]}
open(path + ".tmp", "w").write(json.dumps(cfg, indent=2))
PYX
cp "$BUILD_DIR/coord.json.tmp" "$BUILD_DIR/coord.json"
rm -f "$BUILD_DIR/coord.json.tmp"
docker kill -s HUP tsrt-coord >/dev/null
reloaded=0
for i in $(seq 1 20); do
  n=$(docker logs tsrt-coord 2>&1 | grep -c 'config reloaded')
  [ "$n" -ge 1 ] && { reloaded=1; break; }
  sleep 1
done
[ "$reloaded" = "1" ] || { echo "FAIL: coord SIGHUP 重载未生效"; docker logs tsrt-coord 2>&1 | tail -10; exit 1; }
# rill-b 必须先收到 exit 标记（netmap bump）再下裁决结论，否则"未分流"是空洞断言
bumped=0
for i in $(seq 1 30); do
  [ "$(b_netmap_ver)" -gt "$V1" ] && { bumped=1; break; }
  sleep 2
done
[ "$bumped" = "1" ] || { echo "FAIL: 授权后 rill-b 未收到 netmap bump（exit 标记未下发）"; exit 1; }
ok=""
for i in $(seq 1 30); do
  docker exec tsrt-rill-b ping -c1 -W2 192.168.245.1 >/dev/null 2>&1 && { ok=yes; break; }
  sleep 2
done
[ "$ok" = "yes" ] || { echo "FAIL: 双候选下 ping 不通"; exit 1; }
docker exec tsrt-rill-b ping -c3 -W2 192.168.245.1 >/dev/null 2>&1 || true
B_EXT=$(masq_pkts tsrt-rill-ext "10.42.0.0/24")
B_X=$(masq_pkts tsrt-rill-x "10.42.0.0/24")
[ "$B_EXT" -gt "$A_EXT" ] || { echo "FAIL: 双候选下 tailnet 出口未承载（偏好裁决失效？rill-ext ${A_EXT}→${B_EXT}）"; exit 1; }
[ "$B_X" -eq "$A_X" ] || { echo "FAIL: 双候选下流量被 mesh exit 分流（rill-x ${A_X}→${B_X}——偏好序未压制次序源）"; exit 1; }
echo "E2E-07b OK: 偏好裁决——双候选下 tailnet 承载（rill-ext ${A_EXT}→${B_EXT}，rill-x 恒 ${B_X}）"

echo "==> E2E-07 阶段 c：摘除 tailnet 候选（停 rill-ext + 驱逐）→ 解析器顺延 mesh exit"
# 停容器断流（防再注册回摆）+ marker 驱逐（确定性 PeersRemoved，不依赖死亡检测）
C_X_BASE=$(masq_pkts tsrt-rill-x "10.42.0.0/24")
MARK=$(docker logs tsrt-rill-b 2>&1 | wc -l)
docker stop tsrt-rill-ext >/dev/null
docker exec "$TSRV" touch /tmp/rill-e2e-evict/rill-ext
removed=""
for i in $(seq 1 30); do
  docker logs tsrt-rill-b 2>&1 | tail -n +$((MARK + 1)) | grep -qE "netmap delta applied: .*-[1-9]" && { removed=yes; break; }
  sleep 2
done
[ "$removed" = "yes" ] || {
  echo "FAIL: rill-b 未收到 rill-ext 摘除增量（tailnet 候选未清）"
  docker logs tsrt-rill-b 2>&1 | grep ts2021 | tail -10; exit 1
}
ok=""
for i in $(seq 1 60); do
  docker exec tsrt-rill-b ping -c1 -W2 192.168.245.1 >/dev/null 2>&1 && { ok=yes; break; }
  sleep 2
done
C_X=$(masq_pkts tsrt-rill-x "10.42.0.0/24")
{ [ "$ok" = "yes" ] && [ "$C_X" -gt "$C_X_BASE" ]; } || {
  echo "FAIL: 切换未收敛到 mesh exit（ping=$ok，rill-x MASQ ${C_X_BASE}→${C_X}）"
  dump; exit 1
}
echo "E2E-07c OK: tailnet 候选摘除 → mesh exit 承载（rill-x MASQ ${C_X_BASE}→${C_X}），切换收敛无环路"

echo "PASS: TSL-05 subnet router（自研 ts2021 服务端：mesh routes[] 汇总 + 自家 LAN 广播）+ E2E-08 tailnet 段大包（DF @ MTU 上限双向）+ TSL-11 持有流增量推送（+1/-1，REQ-068）+ TSL-07 exit 被用作（allow_exit 审批 + 内核转发回程）+ E2E-07 exit 竞争（偏好裁决 + 顺延切换，REQ-071）"
