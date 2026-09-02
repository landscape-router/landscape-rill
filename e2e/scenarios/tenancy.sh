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
