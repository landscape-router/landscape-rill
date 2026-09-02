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
