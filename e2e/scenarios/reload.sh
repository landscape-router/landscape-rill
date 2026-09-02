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
