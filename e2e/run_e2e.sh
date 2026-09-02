#!/usr/bin/env bash
# mesh e2e 入口：setup（含幂等清理）→ 场景断言
#
# 场景（MESH_E2E_SCENARIO，默认 direct）：
#   direct：coord — node-a（tun0 10.42.0.1/24 + fd00:2::1/64）
#                   — node-b（tun0 10.43.0.1/24 + fd00:3::1/64），同 bridge 网
#           验证：node-b ping node-a（IPv4 + IPv6，IPv6 走组播泛洪 ND，FRAME_HEADER §2.6）
#   relay ：线形 a—b—c（b 双网卡 net1={a,b} net2={b,c}，c 与 a 无直连可达性）
#           验证：c→a 直连候选 miss → 快速切换 relay 路径（经 b，CONTROL_PLANE §3.11）
#           b 日志出现 "relayed frame" 作为中继证据
#   persist：coord 持久化存储（storage_path，REQ-037）——node-c 一次性 key 注册消费 →
#            重启 coord → a↔b 恢复 + node-c 挑战重连（无新注册）→ node-d 复用同一 key 被拒
#   iperf ：性能场景（docs/perf.md §2.4）——TUN 隧道 iperf3 双向吞吐；
#           MESH_E2E_TOPOLOGY=relay 用线形拓扑（经中继），MESH_E2E_CPUS=0 全容器绑单核
# 环境变量 MESH_E2E_TRANSPORT（默认 udp，REQ-054）：=tcp 时数据面走真 TCP 兜底档
#（帧字节与 UDP 一致，仅外覆 2B 长度前缀）——建议与 direct 场景组合验证。
set -euo pipefail

E2E_DIR="$(cd "$(dirname "$0")" && pwd)"
SCENARIO="${MESH_E2E_SCENARIO:-direct}"

logs() { docker logs "$1" 2>&1; }

trap "$E2E_DIR/cleanup.sh" EXIT

"$E2E_DIR/setup.sh"

if [ "$SCENARIO" = "persist" ]; then
  # persist 场景（REQ-037，CONTROL_PLANE §4.1）：coord 持久化存储重启恢复
  # 断言：① a↔b 双栈通；② node-c 一次性 key 注册成功（消费落盘）；
  #       ③ 重启 coord 后 a↔b 自动恢复（node-c 走挑战流程，无新注册）；
  #       ④ node-d 复用同一一次性 key → 注册被拒（消费状态已持久化）
  ping_pair() {  # 等待 a↔b 双栈恢复（重启后节点按退避自动重连）
    for i in $(seq 1 40); do
      if docker exec mesh-node-b ping -c1 -W1 10.42.0.1 >/dev/null 2>&1 \
         && docker exec mesh-node-b ping6 -c1 -W1 fd00:2::1 >/dev/null 2>&1; then
        echo "PASS: persist e2e a↔b ping 通（第 ${i} 次尝试）"
        return 0
      fi
      sleep 2
    done
    return 1
  }

  echo "==> 阶段 1/4：a↔b 双栈通"
  ping_pair

  echo "==> 阶段 2/4：node-c 一次性 key 注册（消费）"
  # 注意：grep -q 提前退出会 SIGPIPE docker logs（pipefail 下判 141）→ 统一用 grep -c 计数
  for i in $(seq 1 20); do
    if [ "$(logs mesh-node-c | grep -c 'registered:')" -ge 1 ]; then
      echo "PASS: node-c 一次性 key 注册成功"
      break
    fi
    sleep 2
  done
  if [ "$(logs mesh-node-c | grep -c 'registered:')" -lt 1 ]; then
    echo "FAIL: node-c 未注册"
    echo "--- node-c 日志头 10 行 ---"; logs mesh-node-c | head -10
    echo "--- node-c 日志尾 10 行 ---"; logs mesh-node-c | tail -10
    echo "--- registered 计数 ---"; logs mesh-node-c | grep -c "registered:" || true
    exit 1
  fi

  echo "==> 阶段 3/4：重启 coord（存储文件随容器保留）→ a↔b 自动恢复"
  docker restart mesh-coord >/dev/null
  sleep 2
  ping_pair || {
    echo "FAIL: coord 重启后 a↔b 未恢复"
    echo "--- coord 日志 ---"; logs mesh-coord | tail -20
    echo "--- node-a 日志 ---"; logs mesh-node-a | tail -20
    exit 1
  }
  # node-c 恢复走挑战流程（auth key 已消费），不得出现第二次注册
  if [ "$(logs mesh-node-c | grep -c 'registered:')" -gt 1 ]; then
    echo "FAIL: node-c 重启后重新注册（持久化缺失，注册状态丢失）"
    exit 1
  fi

  echo "==> 阶段 4/4：node-d 复用已消费的一次性 key → 注册必须被拒"
  # 注意：注册被拒是服务端静默断连（客户端只记 control connected，不记 connect failed）——
  # 断言对象是"到达 coord 且从未注册成功"，而非 connect failed
  docker compose -f "$E2E_DIR/mesh/persist/docker-compose.yaml" --profile late up -d node-d >/dev/null
  for i in $(seq 1 20); do
    if [ "$(logs mesh-node-d | grep -c 'registered:')" -ge 1 ]; then
      echo "FAIL: node-d 用已消费的一次性 key 注册成功（消费状态未持久化）"
      exit 1
    fi
    if [ "$(logs mesh-node-d | grep -c 'control connected')" -ge 1 ]; then
      echo "PASS: node-d 到达 coord 但注册被拒（一次性 key 消费已持久化），持续重连中"
      exit 0
    fi
    sleep 2
  done
  echo "FAIL: node-d 未观察到到达 coord（40s 内）"
  echo "--- node-d 日志 ---"; logs mesh-node-d | tail -20
  exit 1
fi

if [ "$SCENARIO" = "relay" ]; then
  # 快速切换窗口：直连候选 miss ×3（PATH_HEALTH_MISS_LIMIT，5s 心跳）≈ 15~30s
  for i in $(seq 1 40); do
    if docker exec mesh-node-c ping -c1 -W1 10.42.0.1 >/dev/null 2>&1; then
      relayed=$(logs mesh-node-b | grep -c "relayed frame" || true)
      if [ "$relayed" -ge 1 ]; then
        echo "PASS: relay e2e ping 通（第 ${i} 次尝试，经 node-b 中继，relay 转发日志 ${relayed} 条）"
        docker exec mesh-node-c ping -c3 10.42.0.1 || true
        exit 0
      fi
      echo "（ping 通但未见 relay 转发日志，继续等待路径切换）"
    fi
    sleep 2
  done
  echo "FAIL: relay 场景 ping 不通"
  echo "--- coord 日志 ---";  logs mesh-coord | tail -20
  echo "--- node-a 日志 ---"; logs mesh-node-a | tail -20
  echo "--- node-b 日志 ---"; logs mesh-node-b | tail -20
  echo "--- node-c 日志 ---"; logs mesh-node-c | tail -20
  exit 1
fi

if [ "$SCENARIO" = "log" ]; then
  # log 场景（LOGGING §2/§4 验收，LOG-01/LOG-03）：
  # ① node-a：--log-level debug 覆盖 RUST_LOG=error → debug 明细（endpoint report）出现；
  # ② node-b：仅 RUST_LOG=error → info 级（registered:）不出现；
  # ③ node-a --log-file /tmp/lrill → 按天轮转文件生成 + stderr 双写
  for i in $(seq 1 30); do
    if [ "$(logs mesh-node-a | grep -c 'registered:')" -ge 1 ]; then
      break
    fi
    sleep 2
  done
  if [ "$(logs mesh-node-a | grep -c 'registered:')" -lt 1 ]; then
    echo "FAIL: node-a 未注册（log 场景基础前提）"
    echo "--- node-a 日志尾 10 行 ---"; logs mesh-node-a | tail -10
    exit 1
  fi
  if [ "$(logs mesh-node-a | grep -c 'endpoint report')" -lt 1 ]; then
    echo "FAIL: --log-level debug 未覆盖 RUST_LOG=error（debug 明细未出现）"
    exit 1
  fi
  echo "PASS: --log-level debug 覆盖 RUST_LOG=error（debug 明细出现）"
  if [ "$(logs mesh-node-b | grep -c 'registered:')" -ge 1 ]; then
    echo "FAIL: RUST_LOG=error 下 info 级（registered:）仍出现"
    exit 1
  fi
  echo "PASS: RUST_LOG=error 过滤 info 级（registered: 不出现）"
  logfile=$(docker exec mesh-node-a sh -c 'ls /tmp/lrill.*' 2>/dev/null | head -1 || true)
  if [ -z "$logfile" ]; then
    echo "FAIL: --log-file 未生成按天轮转文件（预期 /tmp/lrill.<YYYY-MM-DD>）"
    exit 1
  fi
  if [ "$(docker exec mesh-node-a sh -c "wc -l < $logfile" 2>/dev/null || echo 0)" -lt 1 ]; then
    echo "FAIL: 轮转文件为空（$logfile）"
    exit 1
  fi
  echo "PASS: --log-file 按天轮转文件生成（$logfile）"
  if [ "$(logs mesh-node-a | grep -c 'registered:')" -ge 1 ]; then
    echo "PASS: stderr 双写（docker logs 可见 registered:）"
    exit 0
  fi
  echo "FAIL: --log-file 模式下 stderr 无输出"
  exit 1
fi

if [ "$SCENARIO" = "reload" ]; then
  # reload 场景（REQ-038，CONTROL_PLANE §3.12，ADM-03）：coord.json + SIGHUP 增量生效
  # 阶段 1：基线 a↔b 双栈通（重载不中断在途连接/数据面）
  # 阶段 2：coord.json 追加 K_C → SIGHUP → node-c（late，K_C）注册成功（新 key 生效）
  # 阶段 3：coord.json 写坏 → SIGHUP → 重载失败保持旧配置（日志报错）+ a↔b 仍通
  # 阶段 4：coord.json 还原（无 K_C）→ SIGHUP → node-d（late，复用 K_C）注册被拒（移除即刻失效）
  KX="$(cat "$E2E_DIR/build/.reload_kx")"
  RELOAD_COMPOSE="docker compose -f $E2E_DIR/mesh/reload/docker-compose.yaml"
  ping_pair() {
    for i in $(seq 1 40); do
      if docker exec mesh-node-b ping -c1 -W1 10.42.0.1 >/dev/null 2>&1 \
         && docker exec mesh-node-b ping6 -c1 -W1 fd00:2::1 >/dev/null 2>&1; then
        return 0
      fi
      sleep 2
    done
    return 1
  }
  wait_reload() {  # $1=期望日志模式（config reloaded / reload failed）
    for i in $(seq 1 20); do
      if [ "$(logs mesh-coord | grep -c "$1")" -ge 1 ]; then
        return 0
      fi
      sleep 1
    done
    echo "FAIL: 未观察到 coord 日志 '$1'"
    logs mesh-coord | tail -10
    return 1
  }

  echo "==> reload 阶段 1/4：基线 a↔b 双栈通"
  ping_pair || { echo "FAIL: 基线 ping 不通"; logs mesh-coord | tail -10; exit 1; }
  echo "PASS: 基线 a↔b 双栈通"

  echo "==> reload 阶段 2/4：追加 K_C → SIGHUP → 新 auth key 可注册"
  cp "$E2E_DIR/build/coord.json" "$E2E_DIR/build/.reload_base.json"
  # 注意：sed -i 走 rename，会断开 bind mount 的 inode（容器仍读旧文件）——
  # 必须 sed 到临时文件后 cp 原址覆盖（保留 inode）
  sed "/\"auth_keys\": \[/a\\      { \"key\": \"$KX\", \"policy\": \"reusable\" }," \
    "$E2E_DIR/build/coord.json" > "$E2E_DIR/build/coord.json.tmp"
  cp "$E2E_DIR/build/coord.json.tmp" "$E2E_DIR/build/coord.json"
  rm -f "$E2E_DIR/build/coord.json.tmp"
  docker kill -s HUP mesh-coord >/dev/null
  wait_reload "config reloaded"
  echo "PASS: SIGHUP 重载成功（config reloaded）"
  $RELOAD_COMPOSE --profile late up -d node-c >/dev/null
  for i in $(seq 1 20); do
    if [ "$(logs mesh-node-c | grep -c 'registered:')" -ge 1 ]; then
      echo "PASS: 新 auth key（K_C）经重载生效，node-c 注册成功"
      break
    fi
    sleep 2
  done
  if [ "$(logs mesh-node-c | grep -c 'registered:')" -lt 1 ]; then
    echo "FAIL: node-c 未注册（新 key 未生效）"
    logs mesh-node-c | tail -10
    exit 1
  fi

  echo "==> reload 阶段 3/4：写坏配置 → SIGHUP → 重载失败保持旧配置"
  printf 'this is not json\n' > "$E2E_DIR/build/coord.json"
  docker kill -s HUP mesh-coord >/dev/null
  wait_reload "reload failed, keeping old config"
  echo "PASS: 重载失败保持旧配置（日志报错）"
  ping_pair || { echo "FAIL: 重载失败后数据面中断"; exit 1; }
  echo "PASS: 重载失败不中断在途连接（a↔b 仍通）"

  echo "==> reload 阶段 4/4：还原配置（无 K_C）→ SIGHUP → 移除的 key 即刻失效"
  cp "$E2E_DIR/build/.reload_base.json" "$E2E_DIR/build/coord.json"
  docker kill -s HUP mesh-coord >/dev/null
  wait_reload "config reloaded"
  $RELOAD_COMPOSE --profile late up -d node-d >/dev/null
  for i in $(seq 1 20); do
    if [ "$(logs mesh-node-d | grep -c 'registered:')" -ge 1 ]; then
      echo "FAIL: node-d 用已移除的 auth key 注册成功"
      exit 1
    fi
    if [ "$(logs mesh-node-d | grep -c 'control connected')" -ge 1 ]; then
      echo "PASS: 移除的 auth key 即刻失效（node-d 到达 coord 但注册被拒）"
      exit 0
    fi
    sleep 2
  done
  echo "FAIL: node-d 未观察到到达 coord（40s 内）"
  logs mesh-node-d | tail -10
  exit 1
fi

if [ "$SCENARIO" = "tenancy" ]; then
  # tenancy 场景（CONTROL_PLANE §1.5，SEC-21~25/CTL-09）：单 coordinator 双网络（lab/work）
  # 断言：
  # ① SEC-21/CTL-09 netmap 隔离：a1 只看到 2 条目（a1+a2），b1 只看到 2 条目（b1+b2）
  # ② 组内双栈通（lab：a1↔a2；work：b1↔b2）
  # ③ 跨网络不可达（a1 ping b1 LAN 前缀无路由）
  # ④ SEC-23：node-d 持 ghost 网络 key → 到达 coord 但注册被拒
  # ⑤ SEC-22：forge.py 注入——work 主密钥伪造帧 → a2 BadRouteMac 丢弃；
  #            lab 主密钥（正确 key）帧 → 越过 route_mac（不新增 BadRouteMac）
  TENC="$E2E_DIR/mesh/tenancy"
  ping_pair() {  # $1=容器 $2=IPv4 $3=IPv6(可空)
    for i in $(seq 1 40); do
      if docker exec "$1" ping -c1 -W1 "$2" >/dev/null 2>&1; then
        if [ -n "${3:-}" ]; then
          docker exec "$1" ping6 -c1 -W1 "$3" >/dev/null 2>&1 || continue
        fi
        return 0
      fi
      sleep 2
    done
    return 1
  }

  echo "==> tenancy 阶段 1/5：四节点注册 + netmap 隔离（SEC-21/CTL-09）"
  for c in mesh-node-a1 mesh-node-a2 mesh-node-b1 mesh-node-b2; do
    ok=0
    for i in $(seq 1 30); do
      if [ "$(logs $c | grep -c 'registered:')" -ge 1 ]; then
        ok=1; break
      fi
      sleep 2
    done
    [ "$ok" = "1" ] || { echo "FAIL: $c 未注册"; logs $c | tail -10; exit 1; }
  done
  echo "PASS: 四节点全部注册"
  # netmap 条目数：a1/a2 见 2 条（本网），b1/b2 见 2 条（本网）——若分域失效为 4 条
  for c in mesh-node-a1 mesh-node-a2; do
    if [ "$(logs $c | grep -c 'netmap v.*: 2 entries')" -lt 1 ]; then
      echo "FAIL: $c 未收到本网 netmap（预期 2 条目）"
      logs $c | grep 'netmap v' | tail -5
      exit 1
    fi
  done
  for c in mesh-node-b1 mesh-node-b2; do
    if [ "$(logs $c | grep -c 'netmap v.*: 2 entries')" -lt 1 ]; then
      echo "FAIL: $c 未收到本网 netmap（预期 2 条目）"
      logs $c | grep 'netmap v' | tail -5
      exit 1
    fi
  done
  echo "PASS: netmap 按网络隔离（各网只见本网 2 条目）"

  echo "==> tenancy 阶段 2/5：组内互通（lab：a1↔a2；work：b1↔b2）"
  ping_pair mesh-node-a2 10.42.0.1 fd00:2::1 || { echo "FAIL: a2→a1 不通"; exit 1; }
  ping_pair mesh-node-a1 10.43.0.1 fd00:3::1 || { echo "FAIL: a1→a2 不通"; exit 1; }
  ping_pair mesh-node-b2 10.52.0.1 fd00:5::1 || { echo "FAIL: b2→b1 不通"; exit 1; }
  ping_pair mesh-node-b1 10.53.0.1 fd00:6::1 || { echo "FAIL: b1→b2 不通"; exit 1; }
  echo "PASS: 两组内双栈互通"

  echo "==> tenancy 阶段 3/5：跨网络不可达（无路由/无 netmap 条目）"
  if docker exec mesh-node-a1 ping -c1 -W1 10.52.0.1 >/dev/null 2>&1; then
    echo "FAIL: a1 可达 b1 的 LAN（跨网络隔离失效）"
    exit 1
  fi
  if docker exec mesh-node-b1 ping -c1 -W1 10.42.0.1 >/dev/null 2>&1; then
    echo "FAIL: b1 可达 a1 的 LAN（跨网络隔离失效）"
    exit 1
  fi
  echo "PASS: 跨网络不可达（A/B 互不可见）"

  echo "==> tenancy 阶段 4/5：SEC-23 auth key 归域——ghost 网络 key 注册被拒"
  docker compose -f "$TENC/docker-compose.yaml" --profile late up -d node-d >/dev/null
  for i in $(seq 1 20); do
    if [ "$(logs mesh-node-d | grep -c 'registered:')" -ge 1 ]; then
      echo "FAIL: node-d 用未配置网络（ghost）的 key 注册成功（归域失效）"
      exit 1
    fi
    if [ "$(logs mesh-node-d | grep -c 'control connected')" -ge 1 ]; then
      echo "PASS: node-d 到达 coord 但注册被拒（未知网络 auth key）"
      break
    fi
    sleep 2
  done
  if [ "$(logs mesh-node-d | grep -c 'control connected')" -lt 1 ]; then
    echo "FAIL: node-d 未观察到到达 coord（40s 内）"
    logs mesh-node-d | tail -10
    exit 1
  fi

  echo "==> tenancy 阶段 5/5：SEC-22 跨网伪造 route_mac（forge.py 注入，正/负对照）"
  A1_ID=$(logs mesh-node-a1 | grep -o 'registered: node_id=[0-9]*' | tail -1 | cut -d= -f2)
  A2_ID=$(logs mesh-node-a2 | grep -o 'registered: node_id=[0-9]*' | tail -1 | cut -d= -f2)
  A2_EP=$(logs mesh-node-a2 | grep -o '192\.168\.240\.12:[0-9]*' | head -1)
  [ -n "$A1_ID" ] && [ -n "$A2_ID" ] && [ -n "$A2_EP" ] || {
    echo "FAIL: 无法从日志提取注入参数（a1=$A1_ID a2=$A2_ID ep=$A2_EP）"
    logs mesh-node-a2 | grep -E 'registered:|endpoint report' | tail -5
    exit 1
  }
  echo "注入参数：from=a1#$A1_ID to=a2#$A2_ID target=$A2_EP"
  A2_IP="${A2_EP%:*}"; A2_PORT="${A2_EP##*:}"
  LAB_KEY="$(cat "$E2E_DIR/build/.tenancy_lab_key")"
  WORK_KEY="$(cat "$E2E_DIR/build/.tenancy_work_key")"
  before=$(logs mesh-node-a2 | grep -c 'dropped frame: BadRouteMac' || true)
  # 负对照：work（错误网络）主密钥伪造 → 必须 BadRouteMac 丢弃
  python3 "$TENC/forge.py" "$A2_IP" "$A2_PORT" "$A1_ID" "$A2_ID" "$WORK_KEY" 999990 64
  ok=0
  for i in $(seq 1 10); do
    after=$(logs mesh-node-a2 | grep -c 'dropped frame: BadRouteMac' || true)
    if [ "$after" -gt "$before" ]; then ok=1; break; fi
    sleep 1
  done
  if [ "$ok" != "1" ]; then
    echo "FAIL: 跨网伪造帧未被 BadRouteMac 丢弃（隔离/密钥分域失效）"
    logs mesh-node-a2 | grep 'dropped frame' | tail -5
    exit 1
  fi
  echo "PASS: 负对照——work 主密钥伪造帧 → BadRouteMac 丢弃"
  # 正对照：lab（正确网络）主密钥 → 越过 route_mac（BadRouteMac 计数不得高于负对照后）
  # 注：比较基准 = mid（负对照后的计数），before 已被负对照自身 +1
  mid=$(logs mesh-node-a2 | grep -c 'dropped frame: BadRouteMac' || true)
  python3 "$TENC/forge.py" "$A2_IP" "$A2_PORT" "$A1_ID" "$A2_ID" "$LAB_KEY" 999991 64
  sleep 2
  after=$(logs mesh-node-a2 | grep -c 'dropped frame: BadRouteMac' || true)
  if [ "$after" -gt "$mid" ]; then
    echo "FAIL: 正确 key 帧也被 BadRouteMac 丢弃（注入脚本 crypto 失配，断言失去意义）"
    logs mesh-node-a2 | grep -E 'dropped frame|registered:' | tail -15
    exit 1
  fi
  echo "PASS: 正对照——正确 key 帧越过 route_mac（死在会话层，非 BadRouteMac）"
  # 注入不破坏数据面
  ping_pair mesh-node-a1 10.43.0.1 || { echo "FAIL: 注入后 a1→a2 中断"; exit 1; }
  echo "PASS: 注入后数据面不受影响"
  echo "==> tenancy 场景全部通过"
  exit 0
fi

if [ "$SCENARIO" = "probe" ]; then
  # probe 场景（CONNECTIVITY §2/§4/§5，CON-01/03/04/05/06 + SEC-26）：
  # 拓扑：a(net1) — b/d(双网卡自愿 relay) — c(net2)，a↔c 直连黑洞
  # 断言：
  # ① CON-01 coordinator UDP 回显：节点收到 echo confirmed（seen 地址）
  # ② SEC-26 反射放大限速：宿主灌 echo 洪泛 → coord 周期摘要 echo rate-limited
  # ③ CON-05 relay 列表构建：coord 日志 relay rtt 排序；节点持有 relay candidates
  # ④ CON-03 直连互探确认：节点日志 probe confirmed direct via
  # ⑤ CON-04 中继兜底：c→a 经 b 可达（b 日志 relayed frame）
  # ⑥ CON-06 中继故障切换：docker stop node-b → c→a 仍可达（经 d 中继）
  logs() { docker logs "$1" 2>&1; }
  ping_ca() {
    docker exec mesh-node-c ping -c1 -W1 10.42.0.1 >/dev/null 2>&1
  }
  wait_log() {  # $1=容器 $2=模式 $3=次数(默认1) $4=循环上限(默认40)
    local c="$1" pat="$2" want="${3:-1}" n="${4:-40}" i=0
    while [ "$(logs $c | grep -c "$pat" || true)" -lt "$want" ]; do
      i=$((i+1)); [ "$i" -ge "$n" ] && return 1
      sleep 2
    done
    return 0
  }

  echo "==> probe 阶段 1/6：注册 + CON-01 coordinator UDP 回显"
  for c in mesh-node-a mesh-node-b mesh-node-c mesh-node-d; do
    wait_log $c 'registered:' 1 30 || { echo "FAIL: $c 未注册"; logs $c | tail -10; exit 1; }
  done
  echo "PASS: 四节点全部注册"
  # echo 周期 30s：节点发 PING(to=0) → coordinator 回显 seen 地址
  wait_log mesh-node-a 'echo confirmed:' 1 30 || {
    echo "FAIL: node-a 未收到 coordinator UDP 回显（CON-01）"
    logs mesh-node-a | grep -E 'echo|probe|dropped' | tail -10
    logs mesh-coord | tail -10
    exit 1
  }
  echo "PASS: CON-01——coordinator UDP 回显（echo confirmed）"

  echo "==> probe 阶段 2/6：SEC-26 反射放大限速（echo 洪泛 → rate-limited 摘要）"
  # 洪泛目标 = coord 容器 UDP 8443（宿主直达容器固定 IP）；限速 10/s 突发 20，
  # 200 包瞬间灌入 → 大部分被限速（amplification 收敛）
  python3 - <<'PYEOF'
import socket, struct, sys
ip = "192.168.240.10"
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for i in range(200):
    pkt = b"LPRB" + bytes([1]) + struct.pack(">III", 999, 0, i)
    sock.sendto(pkt, (ip, 8443))
PYEOF
  wait_log mesh-coord 'echo rate-limited:' 1 15 || {
    echo "FAIL: coordinator 未输出 echo rate-limited 摘要（SEC-26 限速失效）"
    logs mesh-coord | tail -10
    exit 1
  }
  echo "PASS: SEC-26——echo 洪泛被限速（rate-limited 摘要出现）"

  echo "==> probe 阶段 3/6：CON-05 relay 列表构建（RTT 排序 + 节点挂靠候选）"
  wait_log mesh-coord 'relay rtt' 1 20 || {
    echo "FAIL: coordinator 未输出 relay RTT 排序日志（CON-05）"
    logs mesh-coord | tail -10
    exit 1
  }
  logs mesh-coord | grep 'relay rtt' | tail -2
  wait_log mesh-node-c 'relay candidates' 1 20 || {
    echo "FAIL: node-c 未持有 relay 挂靠候选"
    logs mesh-node-c | grep -E 'relay|netmap' | tail -10
    exit 1
  }
  echo "PASS: CON-05——relay 列表 RTT 排序下发 + 节点持有挂靠候选"

  echo "==> probe 阶段 4/6：CON-03 直连互探确认 + CON-04 中继兜底"
  wait_log mesh-node-c 'probe confirmed direct via' 1 40 || {
    echo "FAIL: node-c 无互探确认日志（CON-03）"
    logs mesh-node-c | grep -E 'probe|relay' | tail -10
    exit 1
  }
  echo "PASS: CON-03——直连互探确认（probe confirmed direct via）"
  for i in $(seq 1 40); do
    if ping_ca; then
      if [ "$(logs mesh-node-b | grep -c 'relayed frame' || true)" -ge 1 ]; then
        echo "PASS: CON-04——c→a 经 node-b 中继可达（relayed frame）"
        docker exec mesh-node-c ping -c3 10.42.0.1 || true
        break
      fi
    fi
    sleep 2
    [ "$i" = "40" ] && {
      echo "FAIL: c→a 中继兜底未通（CON-04）"
      echo "--- node-c 日志 ---"; logs mesh-node-c | grep -E 'relay|probe|dropped|path|frame|session' | tail -20
      echo "--- node-b 日志 ---"; logs mesh-node-b | grep -E 'relay|dropped|frame' | tail -10
      exit 1
    }
  done

  echo "==> probe 阶段 5/6：CON-06 中继故障切换（stop node-b → 经 d 中继仍可达）"
  docker stop mesh-node-b >/dev/null
  sleep 5
  ok=0
  for i in $(seq 1 40); do
    if ping_ca; then
      if [ "$(logs mesh-node-d | grep -c 'relayed frame' || true)" -ge 1 ]; then
        ok=1
        echo "PASS: CON-06——node-b 停机后 c→a 经 node-d 中继仍可达（故障切换）"
        docker exec mesh-node-c ping -c3 10.42.0.1 || true
        break
      fi
    fi
    sleep 2
  done
  [ "$ok" = "1" ] || {
    echo "FAIL: node-b 停机后 c→a 不可达（CON-06 故障切换失效）"
    echo "--- node-c 日志 ---"; logs mesh-node-c | grep -E 'relay|probe|dropped|path' | tail -10
    echo "--- node-d 日志 ---"; logs mesh-node-d | tail -10
    exit 1
  }
  echo "==> probe 场景全部通过"
  exit 0
fi

if [ "$SCENARIO" = "iperf" ]; then
  # iperf 场景（docs/perf.md §2.4）：direct 拓扑默认；MESH_E2E_TOPOLOGY=relay 线形拓扑经中继
  #（relay 是转发优化最灵敏配置）。PASS 只判退出码——吞吐数值记录 docs/perf.md §4，不设阈值。
  TOPO="${MESH_E2E_TOPOLOGY:-direct}"
  if [ "$TOPO" = "relay" ]; then CLIENT=mesh-node-c; else CLIENT=mesh-node-b; fi
  docker exec mesh-node-a iperf3 --version >/dev/null 2>&1 || {
    echo "FAIL: 镜像缺 iperf3——重建 base：docker rmi mesh-e2e-base 后重跑（setup 会重装）" >&2
    exit 1
  }
  ok=0
  for i in $(seq 1 30); do
    if docker exec "$CLIENT" ping -c1 -W1 10.42.0.1 >/dev/null 2>&1; then ok=1; break; fi
    sleep 2
  done
  [ "$ok" = "1" ] || { echo "FAIL: iperf 前提——$CLIENT ping 10.42.0.1 不通"; exit 1; }
  docker exec -d mesh-node-a iperf3 -s
  sleep 1
  echo "==> iperf3（拓扑: $TOPO）正向 $CLIENT → 10.42.0.1（5s）"
  docker exec "$CLIENT" iperf3 -c 10.42.0.1 -t 5 || exit 1
  echo "==> iperf3（拓扑: $TOPO）反向 10.42.0.1 → $CLIENT（-R，5s）"
  docker exec "$CLIENT" iperf3 -c 10.42.0.1 -t 5 -R || exit 1
  echo "PASS: iperf3 双向完成（数值记录 docs/perf.md §4）"
  exit 0
fi

for i in $(seq 1 20); do
  if docker exec mesh-node-b ping -c1 -W1 10.42.0.1 >/dev/null 2>&1 \
     && docker exec mesh-node-b ping6 -c1 -W1 fd00:2::1 >/dev/null 2>&1; then
    echo "PASS: mesh e2e ping 通（第 ${i} 次尝试，IPv4 + IPv6 双栈）"
    docker exec mesh-node-b ping -c3 10.42.0.1 || true
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
