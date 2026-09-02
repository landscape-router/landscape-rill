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
  # node-c 恢复走挑战流程（auth key 已消费）：挑战成功会补发 REGISTER_RESPONSE
  # （REQ-057 恢复语义），"registered:" 计数不再区分新旧注册——断言改为
  # node_id 全一致（新注册也不换 id，但配合阶段 4 的 key 拒绝构成完整证据）
  # + coord 侧挑战成功日志
  c_ids=$(logs mesh-node-c | grep -o 'registered: node_id=[0-9]*' | sort -u | wc -l)
  if [ "$c_ids" -ne 1 ]; then
    echo "FAIL: node-c 出现多个 node_id（注册状态不一致）"
    logs mesh-node-c | grep 'registered:' || true
    exit 1
  fi
  for i in $(seq 1 20); do
    if [ "$(logs mesh-coord | grep -c 'challenge ok')" -ge 1 ]; then
      echo "PASS: node-c 挑战重连（coord 证据：$(logs mesh-coord | grep -c 'challenge ok') 次）"
      break
    fi
    sleep 2
  done
  if [ "$(logs mesh-coord | grep -c 'challenge ok')" -lt 1 ]; then
    echo "FAIL: coord 无挑战成功日志（node-c 未走挑战恢复）"
    echo "--- coord 日志尾 20 行 ---"; logs mesh-coord | tail -20
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
