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
