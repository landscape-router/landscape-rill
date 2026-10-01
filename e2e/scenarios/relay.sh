  # REQ-062：relay 不再随注册自动启用——coordinator RTT 轮（30s 周期）策划
  # roster 后经 netmap 下发。先等 roster 落位日志，再进 ping 轮询
  logs() { docker logs "$1" 2>&1; }
  relay_id=$(logs mesh-node-b | grep -o 'registered: node_id=[0-9]*' | head -1 | grep -o '[0-9]*$')
  roster_hit=0
  for i in $(seq 1 40); do
    last=$(logs mesh-coord | grep 'relay roster applied' | tail -1 || true)
    if [ -n "$last" ] && echo "$last" | grep -o 'roster=\[[0-9, ]*\]' | grep -o '[0-9]\+' | grep -qx "$relay_id"; then
      echo "PASS: roster 落位（node-b=$relay_id 进 roster，RTT 策划路径生效）"
      echo "  $last"
      roster_hit=1
      break
    fi
    sleep 2
  done
  [ "$roster_hit" = "1" ] || {
    echo "FAIL: relay roster 未落位（node-b=$relay_id）"
    echo "--- coord 日志 ---"; logs mesh-coord | grep -E 'roster|rtt|endpoint' | tail -10
    echo "--- node-b 日志 ---"; logs mesh-node-b | grep -E 'endpoint|report' | tail -5
    exit 1
  }

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
