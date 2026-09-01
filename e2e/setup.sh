#!/usr/bin/env bash
# mesh e2e 初始化：base 镜像 → CA/证书 → 密钥/信任锚 → 编译 → 配置 → 构建启动 → 路由/黑洞注入
# 幂等：开头强制 cleanup（容器/网络/build 全清），可重复执行；断言逻辑在 run_e2e.sh
set -euo pipefail

E2E_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$E2E_DIR/.." && pwd)"
BUILD_DIR="$E2E_DIR/build"
SCENARIO="${MESH_E2E_SCENARIO:-direct}"
COMPOSE="docker compose -f $E2E_DIR/mesh/direct/docker-compose.yaml"
OVERLAY="$BUILD_DIR/lrill"

hex() { openssl rand -hex 32; }

# 幂等前提：启动前必清理
"$E2E_DIR/cleanup.sh"

# 场景选择：relay 用线形拓扑（b 双网卡）；persist 用四节点拓扑（coord 持久化，REQ-037）；
# log 用日志验收拓扑（同 direct，节点日志启动参数不同，LOGGING §2/§4）；
# reload 用 SIGHUP 重载拓扑（同 direct，node-c/d profile late 门控，REQ-038）；
# tenancy 用双网络拓扑（lab + work 各两节点，单 coordinator，CONTROL_PLANE §1.5）
if [ "$SCENARIO" = "relay" ]; then
  COMPOSE="docker compose -f $E2E_DIR/mesh/relay/docker-compose.yaml"
elif [ "$SCENARIO" = "persist" ]; then
  COMPOSE="docker compose -f $E2E_DIR/mesh/persist/docker-compose.yaml"
elif [ "$SCENARIO" = "log" ]; then
  COMPOSE="docker compose -f $E2E_DIR/mesh/log/docker-compose.yaml"
elif [ "$SCENARIO" = "reload" ]; then
  COMPOSE="docker compose -f $E2E_DIR/mesh/reload/docker-compose.yaml"
elif [ "$SCENARIO" = "tenancy" ]; then
  COMPOSE="docker compose -f $E2E_DIR/mesh/tenancy/docker-compose.yaml"
fi

echo "==> 0/6 预置 base 镜像（iproute2/iputils-ping；环境 DNS 受限需 --dns 引导）"
E2E_DNS="${MESH_E2E_DNS:-$(awk '$1=="nameserver" && $2 !~ /^(127\.|::1$)/{print $2; exit}' /etc/resolv.conf)}"
[ -n "$E2E_DNS" ] || E2E_DNS="1.1.1.1"  # 宿主仅 loopback stub（CI）时回退公共 DNS
if ! docker image inspect mesh-e2e-base >/dev/null 2>&1; then
  docker run --dns "$E2E_DNS" debian:trixie-slim sh -c \
    "apt-get update && apt-get install -y --no-install-recommends \
       iproute2 iputils-ping ca-certificates && rm -rf /var/lib/apt/lists/*"
  docker commit "$(docker ps -lq)" mesh-e2e-base
fi

echo "==> 1/6 生成 CA 与服务端证书"
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
NODE_C_KEY=$(hex)
NODE_D_KEY=$(hex)

echo "==> 3/6 编译二进制"
if [ "${E2E_SKIP_BUILD:-0}" = "1" ]; then
  # CI 复用 build job 产物（matrix 各 job 不重复编译）；.cache 不被开头 cleanup 清掉
  [ -f "$E2E_DIR/.cache/lrill" ] || {
    echo "FAIL: E2E_SKIP_BUILD=1 但 e2e/.cache/lrill 不存在" >&2
    exit 1
  }
  # actions/download-artifact 解包丢失可执行位，须恢复
  cp "$E2E_DIR/.cache/lrill" "$BUILD_DIR/lrill"
  chmod +x "$BUILD_DIR/lrill"
else
  "$ROOT_DIR/scripts/build.sh"
  cp "$ROOT_DIR/target/release/lrill" "$BUILD_DIR/lrill"
fi
COORD_PUBKEY=$("$OVERLAY" pubkey "$SIGNING_SEED")

echo "==> 4/6 生成配置"
# lrk auth key（REQ-036）：生成即归域绑定 network（CONTROL_PLANE §1.5）
NODE_A_AUTHKEY=$("$OVERLAY" authkey --network lab)
NODE_B_AUTHKEY=$("$OVERLAY" authkey --network lab)
NODE_C_AUTHKEY=$("$OVERLAY" authkey --network lab)
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

gen_node_config node-a.json "$NODE_A_KEY" "10.42.0.1/24" "fd00:2::1/64" '["10.42.0.0/24", "fd00:2::/64"]' "$NODE_A_AUTHKEY"
gen_node_config node-b.json "$NODE_B_KEY" "10.43.0.1/24" "fd00:3::1/64" '["10.43.0.0/24", "fd00:3::/64"]' "$NODE_B_AUTHKEY"
gen_node_config node-c.json "$NODE_C_KEY" "10.44.0.1/24" "fd00:4::1/64" '["10.44.0.0/24", "fd00:4::/64"]' "$NODE_C_AUTHKEY"

# 多网络配置（CONTROL_PLANE §1.5）：networks 列表，每网络独立主密钥/auth key 空间/白名单
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
          { "key": "$NODE_A_AUTHKEY", "policy": "reusable" },
          { "key": "$NODE_B_AUTHKEY", "policy": "reusable" },
          { "key": "$NODE_C_AUTHKEY", "policy": "reusable" }
        ],
        "announce_whitelist": ["10.0.0.0/8", "fd00::/8"]
      }
    ]
  }
}
EOF

if [ "$SCENARIO" = "persist" ]; then
  # 持久化场景（REQ-037）：coord 落盘存储 + node-c 一次性 key（消费状态须跨重启存活）；
  # node-d 复用同一 key → 重启后注册必须被拒
  cat > "$BUILD_DIR/coord.json" <<EOF
{
  "coord": {
    "listen_addr": "0.0.0.0:8443",
    "signing_seed": "$SIGNING_SEED",
    "tls_cert_path": "/etc/landscape/coord.crt",
    "tls_key_path": "/etc/landscape/coord.key",
    "storage_path": "/root/coord.redb",
    "networks": [
      {
        "name": "lab",
        "master_key": "$MASTER_KEY",
        "auth_keys": [
          { "key": "$NODE_A_AUTHKEY", "policy": "reusable" },
          { "key": "$NODE_B_AUTHKEY", "policy": "reusable" },
          { "key": "$NODE_C_AUTHKEY", "policy": "onetime" }
        ],
        "announce_whitelist": ["10.0.0.0/8", "fd00::/8"]
      }
    ]
  }
}
EOF
  gen_node_config node-c.json "$NODE_C_KEY" "10.44.0.1/24" "fd00:4::1/64" '["10.44.0.0/24", "fd00:4::/64"]' "$NODE_C_AUTHKEY"
  gen_node_config node-d.json "$NODE_D_KEY" "10.45.0.1/24" "fd00:5::1/64" '["10.45.0.0/24", "fd00:5::/64"]' "$NODE_C_AUTHKEY"
fi

if [ "$SCENARIO" = "reload" ]; then
  # reload 场景（REQ-038）：初始只配置 node-a/b 的 auth key；node-c/d 复用 K_C（生成但不入配置），
  # 场景内按阶段修改 coord.json + SIGHUP 断言增量生效/失败保旧
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
          { "key": "$NODE_A_AUTHKEY", "policy": "reusable" },
          { "key": "$NODE_B_AUTHKEY", "policy": "reusable" }
        ],
        "announce_whitelist": ["10.0.0.0/8", "fd00::/8"]
      }
    ]
  }
}
EOF
  gen_node_config node-c.json "$NODE_C_KEY" "10.44.0.1/24" "fd00:4::1/64" '["10.44.0.0/24", "fd00:4::/64"]' "$NODE_C_AUTHKEY"
  gen_node_config node-d.json "$NODE_D_KEY" "10.45.0.1/24" "fd00:5::1/64" '["10.45.0.0/24", "fd00:5::/64"]' "$NODE_C_AUTHKEY"
  echo "$NODE_C_AUTHKEY" > "$BUILD_DIR/.reload_kx"
fi

if [ "$SCENARIO" = "tenancy" ]; then
  # tenancy 场景（CONTROL_PLANE §1.5，SEC-21~25/CTL-09）：单 coordinator 双网络隔离
  # lab（node-a1/a2）+ work（node-b1/b2）；node-d（late）持 ghost 网络 key → 注册被拒
  WORK_KEY=$(hex)
  NODE_A1_KEY=$(hex); NODE_A2_KEY=$(hex); NODE_B1_KEY=$(hex); NODE_B2_KEY=$(hex)
  A1_AK=$("$OVERLAY" authkey --network lab)
  A2_AK=$("$OVERLAY" authkey --network lab)
  B1_AK=$("$OVERLAY" authkey --network work)
  B2_AK=$("$OVERLAY" authkey --network work)
  GHOST_AK=$("$OVERLAY" authkey --network ghost)
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
          { "key": "$A1_AK", "policy": "reusable" },
          { "key": "$A2_AK", "policy": "reusable" }
        ],
        "announce_whitelist": ["10.0.0.0/8", "fd00::/8"]
      },
      {
        "name": "work",
        "master_key": "$WORK_KEY",
        "auth_keys": [
          { "key": "$B1_AK", "policy": "reusable" },
          { "key": "$B2_AK", "policy": "reusable" }
        ],
        "announce_whitelist": ["10.0.0.0/8", "fd00::/8"]
      }
    ]
  }
}
EOF
  gen_node_config node-a1.json "$NODE_A1_KEY" "10.42.0.1/24" "fd00:2::1/64" '["10.42.0.0/24", "fd00:2::/64"]' "$A1_AK"
  gen_node_config node-a2.json "$NODE_A2_KEY" "10.43.0.1/24" "fd00:3::1/64" '["10.43.0.0/24", "fd00:3::/64"]' "$A2_AK"
  gen_node_config node-b1.json "$NODE_B1_KEY" "10.52.0.1/24" "fd00:5::1/64" '["10.52.0.0/24", "fd00:5::/64"]' "$B1_AK"
  gen_node_config node-b2.json "$NODE_B2_KEY" "10.53.0.1/24" "fd00:6::1/64" '["10.53.0.0/24", "fd00:6::/64"]' "$B2_AK"
  gen_node_config node-d.json "$NODE_D_KEY" "10.54.0.1/24" "fd00:7::1/64" '["10.54.0.0/24", "fd00:7::/64"]' "$GHOST_AK"
  # SEC-22 伪造帧注入：记录两网主密钥（forge.py 用）
  echo "$MASTER_KEY" > "$BUILD_DIR/.tenancy_lab_key"
  echo "$WORK_KEY" > "$BUILD_DIR/.tenancy_work_key"
fi

if [ "$SCENARIO" = "relay" ]; then
  # 宿主若已配置 e2e 网段路由则与容器网段冲突（须在 compose up 前检查，
  # 否则 docker 网桥自身路由会命中；ip route get 命中默认路由不可用）
  if ip route show 192.168.240.0/24 | grep -q . || ip route show 192.168.241.0/24 | grep -q .; then
    echo "FAIL: 宿主已配置 192.168.240.0/23 路由，与 e2e 网段冲突" >&2
    exit 1
  fi
fi

echo "==> 5/6 构建并启动"
$COMPOSE build -q
if [ "$SCENARIO" = "persist" ] || [ "$SCENARIO" = "reload" ] || [ "$SCENARIO" = "tenancy" ]; then
  # compose build 默认跳过 profile 门控服务（persist/reload/tenancy 的 late 节点）——
  # 须显式带 profile 构建，否则后续 up 会复用旧镜像（证书/二进制陈旧导致 BadSignature）
  $COMPOSE --profile late build -q
fi
$COMPOSE up -d --force-recreate

echo "==> 6/6 等待注册 + 注入 mesh 路由/黑洞（场景: $SCENARIO）"
for _ in $(seq 1 30); do
  docker logs mesh-coord 2>/dev/null | grep -q "listening" && break
  sleep 1
done
sleep 3

# 内核最小参与：mesh 前缀 → tun0（生产由 runtime 自动注入）
# direct 场景：a↔b；relay 场景：a↔c（经 b 中继）；tenancy 场景：a1↔a2、b1↔b2（组内）
if [ "$SCENARIO" = "relay" ]; then
  docker exec mesh-node-a ip route add 10.44.0.0/24 dev land0 2>/dev/null || true
  docker exec mesh-node-c ip route add 10.42.0.0/24 dev land0 2>/dev/null || true
  docker exec mesh-node-a ip -6 route add fd00:4::/64 dev land0 2>/dev/null || true
  docker exec mesh-node-c ip -6 route add fd00:2::/64 dev land0 2>/dev/null || true
  # 模拟"c↔a 无直连 UDP 可达性"（docker host ip_forward 会在网桥间路由，须主动隔离）：
  # 固定 IP（compose ipam）：a=192.168.240.11 / c=192.168.241.31，互加黑洞路由，只黑这两个 /32
  docker exec mesh-node-c ip route add blackhole 192.168.240.11/32 2>/dev/null || true
  docker exec mesh-node-a ip route add blackhole 192.168.241.31/32 2>/dev/null || true
elif [ "$SCENARIO" = "tenancy" ]; then
  # 组内互达（lab：a1↔a2；work：b1↔b2）；跨网络路由故意不注入（隔离断言依赖）
  docker exec mesh-node-a1 ip route add 10.43.0.0/24 dev land0 2>/dev/null || true
  docker exec mesh-node-a2 ip route add 10.42.0.0/24 dev land0 2>/dev/null || true
  docker exec mesh-node-b1 ip route add 10.53.0.0/24 dev land0 2>/dev/null || true
  docker exec mesh-node-b2 ip route add 10.52.0.0/24 dev land0 2>/dev/null || true
  docker exec mesh-node-a1 ip -6 route add fd00:3::/64 dev land0 2>/dev/null || true
  docker exec mesh-node-a2 ip -6 route add fd00:2::/64 dev land0 2>/dev/null || true
  docker exec mesh-node-b1 ip -6 route add fd00:6::/64 dev land0 2>/dev/null || true
  docker exec mesh-node-b2 ip -6 route add fd00:5::/64 dev land0 2>/dev/null || true
else
  docker exec mesh-node-a ip route add 10.43.0.0/24 dev land0 2>/dev/null || true
  docker exec mesh-node-b ip route add 10.42.0.0/24 dev land0 2>/dev/null || true
  docker exec mesh-node-a ip -6 route add fd00:3::/64 dev land0 2>/dev/null || true
  docker exec mesh-node-b ip -6 route add fd00:2::/64 dev land0 2>/dev/null || true
fi

echo "==> setup 完成（场景: $SCENARIO）"
