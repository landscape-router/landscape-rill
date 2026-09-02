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
