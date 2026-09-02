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
