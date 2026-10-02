#!/usr/bin/env bash
# ts2021×dn42 组合 e2e（E2E-03，REQ-012“手机 → dn42 空间”）：
# 拓扑 = ts2021_runtime 的 tailnet 侧（自研 tsrv + 官方 tailscaled node-c）
#       + dn42 场景的 peer-r（内核 WG + FRR），rill-ext 同时持 ts2021 腿与 dn42 腿。
# 断言：
#   E2E-03：node-c（--accept-routes）ping 172.20.100.2（peer-r 隧道地址）与
#           172.20.100.100（BGP network 172.20.100.0/24 的承载地址）双向通；
#           转发边证据 = rill-ext 日志 "transit tailnet->dn42"；
#           广播链证据 = tsrv "routes approved" 含 172.20.100.0/24
# 回程：dn42→tailnet 不在 v1 边集——transit 落空写 TUN，经内核 100.64.0.0/10 →
#       land0 回环交还用户态，LAN 泵按 Tailnet 路由送 ts2021 腿（entry-rill.sh）
set -euo pipefail

E2E_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$E2E_DIR/../.." && pwd)"
BUILD_DIR="$E2E_DIR/build"
RT_BUILD="$E2E_DIR/../ts2021_runtime/build"  # tailscale 二进制缓存（runtime 场景已跑时复用）
COMPOSE="docker compose -f $E2E_DIR/docker-compose.yaml"
TAILSCALE_VER="${TS2021_TAILSCALE_VER:-1.102.2}"
TSRV="tsd-tsrv"

echo "==> 0/7 预置 base 镜像（mesh-e2e-base + iptables + dn42 peer 镜像）"
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
# peer-r 镜像（内核 WG + FRR；与 mesh dn42 场景同模式 run+commit）
if ! docker image inspect mesh-dn42-peer-img >/dev/null 2>&1; then
  PEER_CID=$(docker run --dns "$E2E_DNS" -d debian:trixie-slim sleep infinity)
  docker exec "$PEER_CID" sh -c \
    "apt-get update && apt-get install -y --no-install-recommends \
       frr wireguard-tools iproute2 iputils-ping bash && rm -rf /var/lib/apt/lists/*"
  docker cp "$E2E_DIR/../mesh/dn42/peer/entrypoint.sh" "$PEER_CID:/entrypoint.sh"
  docker commit "$PEER_CID" mesh-dn42-peer-img
  docker rm -f "$PEER_CID" >/dev/null
fi

echo "==> 1/7 下载 tailscale 二进制（runtime 缓存优先）"
# cp -r 的目标目录必须已存在，否则包内容被平铺进 build/（ts2021_runtime 同教训）
mkdir -p "$BUILD_DIR"
if [ ! -d "$BUILD_DIR/tailscale_${TAILSCALE_VER}_amd64" ]; then
  if [ -d "$RT_BUILD/tailscale_${TAILSCALE_VER}_amd64" ]; then
    cp -r "$RT_BUILD/tailscale_${TAILSCALE_VER}_amd64" "$BUILD_DIR/"
  else
    curl -sL -o "$BUILD_DIR/tailscale.tgz" \
    "https://pkgs.tailscale.com/stable/tailscale_${TAILSCALE_VER}_amd64.tgz"
    tar xzf "$BUILD_DIR/tailscale.tgz" -C "$BUILD_DIR"
  fi
fi
[ -f "$BUILD_DIR/tailscale_${TAILSCALE_VER}_amd64/tailscaled" ] && \
[ -f "$BUILD_DIR/tailscale_${TAILSCALE_VER}_amd64/tailscale" ] || {
  echo "FAIL: tailscale 二进制未落位到 build/tailscale_${TAILSCALE_VER}_amd64/" >&2
  exit 1
}

echo "==> 2/7 构建 lrill（release）"
if [ "${E2E_SKIP_BUILD:-0}" != "1" ]; then
  (cd "$ROOT_DIR" && ./scripts/build.sh)
fi
cp "$ROOT_DIR/target/release/lrill" "$BUILD_DIR/lrill"
cp "$E2E_DIR/entry-node.sh" "$E2E_DIR/entry-rill.sh" "$E2E_DIR/Dockerfile" "$BUILD_DIR/"

echo "==> 3/7 生成双栈证书（mesh CA + ts2021 CA）"
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
    -days 30 -nodes -subj "/CN=tsd-e2e-ca" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$BUILD_DIR/server.key" -out "$BUILD_DIR/server.csr" \
    -nodes -subj "/CN=tsrv" 2>/dev/null
printf 'subjectAltName = DNS:tsrv, IP:127.0.0.1\n' > "$BUILD_DIR/server.ext"
openssl x509 -req -in "$BUILD_DIR/server.csr" -CA "$BUILD_DIR/ts2021-ca.pem" \
    -CAkey "$BUILD_DIR/ts2021-ca.key" -CAcreateserial -out "$BUILD_DIR/server.crt" -days 30 \
    -extfile "$BUILD_DIR/server.ext" 2>/dev/null

echo "==> 4/7 tsrv 配置（dn42 前缀白名单自动审批）"
LRILL="$BUILD_DIR/lrill"
TS_AUTHKEY=$("$LRILL" authkey --network tsd --ttl 0)
export TS_AUTHKEY
cat > "$BUILD_DIR/tsrv.json" <<EOF
{
  "ts2021_server": {
    "network": "tsd",
    "hostname": "tsrv",
    "listen_addr": "0.0.0.0:8080",
    "tls_cert_path": "/etc/landscape/server.crt",
    "tls_key_path": "/etc/landscape/server.key",
    "noise_key_path": "/var/lib/rill/ts2021-noise.key",
    "derp_key_path": "/var/lib/rill/ts2021-derp.key",
    "auth_keys": ["$TS_AUTHKEY"],
    "routes_whitelist": ["172.20.100.0/24"],
    "allow_exit": false
  }
}
EOF

echo "==> 5/7 生成 mesh / dn42 密钥与配置"
hex() { openssl rand -hex 32; }
MASTER_KEY=$(hex)
SIGNING_SEED=$(hex)
EXT_KEY=$(hex)
EXT_AUTHKEY=$("$LRILL" authkey --network lab)
COORD_PUBKEY=$("$LRILL" pubkey "$SIGNING_SEED")

# WG 密钥先行：peer-r 私钥/公钥 + rill-ext 公钥（static_key_seed clamp 后
# wg pubkey 派生，mesh dn42 场景同法）——rill-ext.json 生成时即需 peer 公钥
PEER_R_PRIV=$(docker run --rm mesh-dn42-peer-img wg genkey)
PEER_R_PUB=$(printf '%s' "$PEER_R_PRIV" | docker run --rm -i mesh-dn42-peer-img wg pubkey)
SEED_B64=$(printf '%s' "$EXT_KEY" | python3 -c '
import base64, sys
seed = bytes.fromhex(sys.stdin.read().strip())
seed = bytes([seed[0] & 248]) + seed[1:31] + bytes([seed[31] & 127 | 64])
print(base64.b64encode(seed).decode())
')
NODE_WG_PUB=$(printf '%s' "$SEED_B64" | docker run --rm -i mesh-dn42-peer-img wg pubkey)

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
        "auth_keys": [ { "key": "$EXT_AUTHKEY", "policy": "reusable" } ],
        "announce_whitelist": ["100.64.0.0/10"]
      }
    ]
  }
}
EOF

# rill-ext：mesh 注册（tailnet 前缀回程公告）+ ts2021 腿（静态广播 dn42 前缀，
# TS2021_LEG §3.3.2“配置静态前缀”）+ dn42 腿（eBGP-lite 对 FRR）
cat > "$BUILD_DIR/rill-ext.json" <<EOF
{
  "coordinator_url": "https://coord:8443",
  "auth_key": "$EXT_AUTHKEY",
  "static_key_seed": "$EXT_KEY",
  "capabilities": 0,
  "announce_routes": ["100.64.0.0/10"],
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
    "advertise_routes": ["172.20.100.0/24"]
  },
  "dn42": {
    "local_as": 4242420001,
    "bgp_id": "172.20.100.1",
    "hold_time": 15,
    "own_prefixes": ["172.20.1.0/24"],
    "announce_to_mesh": false,
    "peers": [
      {
        "name": "peer-r",
        "endpoint": "192.168.246.14:51820",
        "public_key": "$PEER_R_PUB",
        "local_v4": "172.20.100.1",
        "local_v6": "fd00:100::1",
        "peer_v4": "172.20.100.2",
        "peer_v6": "fd00:100::2",
        "peer_as": 4242420002,
        "bgp_port": 179,
        "local_bgp_port": 179,
        "whitelist": ["172.20.0.0/14"],
        "max_prefixes": 100
      }
    ]
  }
}
EOF

# peer-r 隧道：AllowedIPs 含 100.64.0.0/10（手机回程能按 wg0 路由送回 rill-ext）
cat > "$BUILD_DIR/wg0.conf" <<WGEOF
[Interface]
PrivateKey = $PEER_R_PRIV
Address = 172.20.100.2/30
Address = fd00:100::2/126
ListenPort = 51820

[Peer]
PublicKey = $NODE_WG_PUB
AllowedIPs = 172.20.100.1/32, fd00:100::1/128, 100.64.0.0/10
WGEOF

cat > "$BUILD_DIR/bgpd.conf" <<BGPEOF
hostname peer-r
password zebra
log syslog
router bgp 4242420002
 bgp router-id 172.20.100.2
 no bgp ebgp-requires-policy
 timers bgp 5 15
 neighbor 172.20.100.1 remote-as 4242420001
 address-family ipv4 unicast
  network 172.20.100.0/24
  neighbor 172.20.100.1 activate
 exit-address-family
!
BGPEOF

cat > "$BUILD_DIR/zebra.conf" <<ZEBEOF
hostname peer-r
log syslog
ZEBEOF

# 幂等清理 + 宿主网段冲突检查（compose up 前止损）
cleanup() {
  $COMPOSE down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
if ip route show 192.168.246.0/24 2>/dev/null | grep -q .; then
  echo "FAIL: 宿主已配置 192.168.246.0/24 路由，与 e2e 网段冲突" >&2
  exit 1
fi

echo "==> 6/7 启动全部容器 + 等待注册/审批/BGP"
$COMPOSE build
$COMPOSE up -d --force-recreate

tsrv_ok=0
for i in $(seq 1 30); do
  if docker logs "$TSRV" 2>&1 | grep -q "ts2021-server.*listening"; then tsrv_ok=1; break; fi
  sleep 1
done
[ "$tsrv_ok" = 1 ] || { echo "FAIL: tsrv 未监听"; docker logs "$TSRV" 2>&1 | tail -20; exit 1; }

NODES=""
for i in $(seq 1 60); do
  NODES=$(docker logs "$TSRV" 2>&1 || true)
  if [ -n "$(echo "$NODES" | grep "host=rill-ext")" ] && [ -n "$(echo "$NODES" | grep "host=node-c")" ]; then
    break
  fi
  sleep 2
done
if [ -z "$(echo "$NODES" | grep "host=rill-ext")" ] || [ -z "$(echo "$NODES" | grep "host=node-c")" ]; then
  echo "FAIL: 双节点未全部注册 tsrv"
  docker logs "$TSRV" 2>&1 | tail -20
  docker logs tsd-rill-ext 2>&1 | tail -20
  exit 1
fi

# dn42 前缀广播审批（localNets 前置：未广播的前缀手机侧直接丢弃，ts2021.md 实证）
ROUTES=""
for i in $(seq 1 60); do
  ROUTES=$(docker logs "$TSRV" 2>&1 | grep "routes approved" | tail -1 || true)
  if echo "$ROUTES" | grep -q "172\.20\.100\.0/24"; then break; fi
  sleep 2
done
echo "$ROUTES"
if ! echo "$ROUTES" | grep -q "172\.20\.100\.0/24"; then
  echo "FAIL: dn42 前缀未广播/未审批（172.20.100.0/24）"
  docker logs tsd-rill-ext 2>&1 | tail -30
  exit 1
fi

# BGP Established（eBGP-lite ⇄ FRR）：rill 侧 info 日志为准
bgp_ok=0
for i in $(seq 1 45); do
  if docker logs tsd-rill-ext 2>&1 | grep -q "dn42 session established: peer-r"; then bgp_ok=1; break; fi
  sleep 2
done
[ "$bgp_ok" = 1 ] || {
  echo "FAIL: BGP 会话未 Established（rill-ext ⇄ peer-r）"
  docker logs tsd-rill-ext 2>&1 | grep -E "dn42|transit" | tail -20
  docker exec tsd-peer-r vtysh -c "show bgp summary" 2>&1 | tail -10 || true
  exit 1
}
echo "BGP Established: rill-ext(4242420001) ⇄ peer-r(4242420002)"

echo "==> 7/7 断言（E2E-03 手机 → dn42 空间）"
dump() {
  echo "--- rill-ext 日志（dn42/transit）---"
  docker logs tsd-rill-ext 2>&1 | grep -E "\[dn42\]|dn42 session|transit" | tail -20
  echo "--- rill-ext 引擎路由 ---"
  docker logs tsd-rill-ext 2>&1 | grep -E "route|172.20.100" | tail -10
  echo "--- peer-r BGP/WG ---"
  docker exec tsd-peer-r vtysh -c "show bgp neighbors 172.20.100.1" 2>&1 | grep -E "BGP state|Prefix" | head -4 || true
  docker exec tsd-peer-r wg show 2>&1 | tail -6 || true
  echo "--- node-c 路由/状态 ---"
  docker exec tsd-node-c ip route 2>/dev/null || true
  docker exec tsd-node-c ip route show table 52 2>/dev/null || true
  docker exec tsd-node-c tailscale --socket=/var/run/tailscale/tailscaled.sock status 2>&1 || true
  echo "--- tsrv 日志尾 ---"
  docker logs "$TSRV" 2>&1 | tail -20
  docker logs tsd-node-c 2>&1 | tail -10
}

# 前置：手机侧内核路由已收敛——官方 tailscaled 把 accept-routes 装进 table 52
#（ip rule 策略路由），主表不含；不能 grep 主表（首版教训）
route_ok=0
for i in $(seq 1 30); do
  if docker exec tsd-node-c ip route show table 52 2>/dev/null | grep -q "172.20.100.0/24"; then route_ok=1; break; fi
  sleep 2
done
[ "$route_ok" = 1 ] || { echo "FAIL: node-c 未获得 172.20.100.0/24 路由（table 52）"; dump; exit 1; }

# ① 隧道地址（.2 = peer-r WG 内网）② BGP network 承载地址（.100 = peer-r lo）
ok=""
for i in $(seq 1 60); do
  if docker exec tsd-node-c ping -c1 -W2 172.20.100.2 >/dev/null 2>&1 \
     && docker exec tsd-node-c ping -c1 -W2 172.20.100.100 >/dev/null 2>&1; then
    ok=yes; break
  fi
  sleep 2
done
if [ "$ok" != "yes" ]; then
  echo "FAIL: E2E-03 node-c → dn42 不通（172.20.100.2 / 172.20.100.100）"
  dump
  exit 1
fi
echo "E2E-03 OK: node-c ping 172.20.100.2（隧道地址）+ 172.20.100.100（BGP network 承载）"

# 转发边证据：tailnet→dn42 transit 实际发生（去程方向）
if ! docker logs tsd-rill-ext 2>&1 | grep -q "transit tailnet->dn42"; then
  echo "FAIL: 未见 transit tailnet->dn42 日志（转发边证据缺失——通了但未走预期边？）"
  dump
  exit 1
fi
docker logs tsd-rill-ext 2>&1 | grep "transit tailnet->dn42" | tail -2

# 稳定性复验（回程 TUN 回环桥接不抖动）
docker exec tsd-node-c ping -c3 -W2 172.20.100.100 >/dev/null 2>&1 \
  || { echo "FAIL: E2E-03 复验 ping 不稳定"; dump; exit 1; }

echo "PASS: E2E-03 手机 → dn42 空间（官方 tailscaled → 自研 ts2021 → rill-ext 引擎裁决 → boringtun → 内核 WG/FRR peer，双向通 + 转发边证据）"
