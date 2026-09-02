  # recover 场景（REQ-056/057）：注入丢弃首个 REGISTER_RESPONSE（注册已消费）
  # 断言：① coord 武装 + 丢弃各一次；② node-a 恢复 = 恰好 1 次 registered（挑战
  #       恢复原 node_id，无新注册）；③ 恰好 2 次 control connected 且间隔 ≥0.9s
  #       （REQ-056 退避，无热循环）；④ node-b 正常注册后 a↔b 双栈通
  echo "==> 阶段 1/3：node-a 首注册响应被注入丢弃 → 退避重连挑战恢复"
  for i in $(seq 1 30); do
    if [ "$(logs mesh-node-a | grep -c 'registered:')" -ge 1 ]; then
      echo "PASS: node-a 挑战恢复完成（第 ${i} 次轮询）"
      break
    fi
    sleep 2
  done
  if [ "$(logs mesh-node-a | grep -c 'registered:')" -lt 1 ]; then
    echo "FAIL: node-a 未在 60s 内恢复"
    echo "--- coord 日志尾 20 行 ---"; logs mesh-coord | tail -20
    echo "--- node-a 日志尾 20 行 ---"; logs mesh-node-a | tail -20
    exit 1
  fi

  if [ "$(logs mesh-coord | grep -c 'e2e injection armed')" -ne 1 ] \
     || [ "$(logs mesh-coord | grep -c 'first REGISTER_RESPONSE dropped')" -ne 1 ]; then
    echo "FAIL: 注入未按预期发生（武装/丢弃各一次）"
    echo "--- coord 日志 ---"; logs mesh-coord | grep -c "e2e injection" || true
    exit 1
  fi

  reg_count=$(logs mesh-node-a | grep -c 'registered:')
  if [ "$reg_count" -ne 1 ]; then
    echo "FAIL: node-a registered 计数 = $reg_count（挑战恢复不得产生新注册）"
    exit 1
  fi

  conn_count=$(logs mesh-node-a | grep -c 'control connected')
  if [ "$conn_count" -ne 2 ]; then
    echo "FAIL: node-a control connected 计数 = $conn_count（应为 2：首次被丢弃 + 恢复连接，无热循环）"
    echo "--- node-a 连接日志 ---"; logs mesh-node-a | grep "control connected"
    exit 1
  fi
  # REQ-056：两次连接间隔 ≥0.9s（断线退避 1s + 握手耗时）
  t1=$(docker logs -t mesh-node-a 2>&1 | grep 'control connected' | sed -n 1p | awk '{print $1}')
  t2=$(docker logs -t mesh-node-a 2>&1 | grep 'control connected' | sed -n 2p | awk '{print $1}')
  n1=$(date -d "$t1" +%s%N); n2=$(date -d "$t2" +%s%N)
  gap_ms=$(( (n2 - n1) / 1000000 ))
  if [ "$gap_ms" -lt 900 ]; then
    echo "FAIL: 重连间隔 ${gap_ms}ms < 900ms（退避未生效，热循环）"
    exit 1
  fi
  echo "PASS: 退避重连间隔 ${gap_ms}ms ≥ 900ms；恢复无新注册（node_id 保持）"

  echo "==> 阶段 2/3：node-b 正常注册"
  docker compose -f "$E2E_DIR/mesh/recover/docker-compose.yaml" --profile late up -d node-b >/dev/null
  # late 容器在 setup 路由注入时不存在——补注 mesh 前缀路由（内核最小参与，同 setup 第 6 步）
  docker exec mesh-node-b ip route add 10.42.0.0/24 dev land0 2>/dev/null || true
  docker exec mesh-node-b ip -6 route add fd00:2::/64 dev land0 2>/dev/null || true
  for i in $(seq 1 20); do
    if [ "$(logs mesh-node-b | grep -c 'registered:')" -ge 1 ]; then
      echo "PASS: node-b 正常注册"
      break
    fi
    sleep 2
  done
  if [ "$(logs mesh-node-b | grep -c 'registered:')" -lt 1 ]; then
    echo "FAIL: node-b 未注册"
    echo "--- node-b 日志尾 20 行 ---"; logs mesh-node-b | tail -20
    exit 1
  fi

  echo "==> 阶段 3/3：a↔b 双栈通（mesh 收敛）"
  for i in $(seq 1 40); do
    if docker exec mesh-node-b ping -c1 -W1 10.42.0.1 >/dev/null 2>&1 \
       && docker exec mesh-node-b ping6 -c1 -W1 fd00:2::1 >/dev/null 2>&1; then
      echo "PASS: recover e2e a↔b ping 通（第 ${i} 次尝试）"
      exit 0
    fi
    sleep 2
  done
  echo "FAIL: a↔b 未连通"
  echo "--- node-a 日志尾 20 行 ---"; logs mesh-node-a | tail -20
  echo "--- node-b 日志尾 20 行 ---"; logs mesh-node-b | tail -20
  exit 1
