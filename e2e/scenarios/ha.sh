# ha 场景（REQ-070 阶段二，CONTROL_PLANE §3.6/§5.6）：coord 3 副本 raft 集群
# 断言：① 选主收敛（唯一 Leader）+ follower 重定向（≥1 节点 "leader redirect:"）
#       + a↔b 双栈通；
#       ② 停 leader 容器：ping 持续无中断（数据面不经 coord）+ 存活副本选出
#       新 Leader（term 严格递增）；
#       ③ 节点经重定向链重注册（node_id 不变，幂等；配置面 coord 存活的节点
#       必然完成——配置面 coord 即 leader 的节点等待阶段 4 回归后恢复）；
#       ④ 旧 leader 容器重启 → 以 Follower 回归（已知现任 leader）；
#       ⑤ a↔b 双栈仍通 + 两节点 node_id 全程唯一
COORDS=(mesh-coord1 mesh-coord2 mesh-coord3)

raft_state_lines() { logs "$1" | grep '\[coord\] raft node_id='; }

current_leader() {  # 最后一条 raft state 行为 Leader 的副本（收敛后恰一个）
  local c last
  for c in "${COORDS[@]}"; do
    last=$(raft_state_lines "$c" | tail -1 || true)
    if echo "$last" | grep -q 'state=Leader'; then echo "$c"; return 0; fi
  done
  return 1
}

ping_pair() {  # 等待 a↔b 双栈通（failover 后节点数据面不中断，此为回归护栏）
  for i in $(seq 1 40); do
    if docker exec mesh-node-b ping -c1 -W1 10.42.0.1 >/dev/null 2>&1 \
       && docker exec mesh-node-b ping6 -c1 -W1 fd00:2::1 >/dev/null 2>&1; then
      echo "PASS: ha e2e a↔b ping 通（第 ${i} 次尝试）"
      return 0
    fi
    sleep 2
  done
  return 1
}

registered_ids() {  # 节点历史注册 node_id 去重计数（幂等注册 → 恒 1）
  logs "$1" | grep -o 'registered: node_id=[0-9]*' | sort -u | wc -l
}

echo "==> 阶段 1/5：选主收敛 + follower 重定向注册"
LEADER=""
for i in $(seq 1 45); do
  LEADER=$(current_leader) && break
  sleep 2
done
if [ -z "$LEADER" ]; then
  echo "FAIL: 90s 内未选出 Leader"
  for c in "${COORDS[@]}"; do echo "--- $c ---"; raft_state_lines "$c" | tail -5; done
  exit 1
fi
echo "PASS: Leader 收敛（$LEADER）"
for i in $(seq 1 45); do
  redirects=$(( $(logs mesh-node-a | grep -c 'leader redirect:' || true) \
               + $(logs mesh-node-b | grep -c 'leader redirect:' || true) ))
  if [ "$redirects" -ge 1 ] \
     && [ "$(logs mesh-node-a | grep -c 'registered:')" -ge 1 ] \
     && [ "$(logs mesh-node-b | grep -c 'registered:')" -ge 1 ]; then
    echo "PASS: follower 重定向（合计 ${redirects} 次）+ 双节点注册完成"
    break
  fi
  sleep 2
done
redirects=$(( $(logs mesh-node-a | grep -c 'leader redirect:' || true) \
             + $(logs mesh-node-b | grep -c 'leader redirect:' || true) ))
if [ "$redirects" -lt 1 ] \
   || [ "$(logs mesh-node-a | grep -c 'registered:')" -lt 1 ] \
   || [ "$(logs mesh-node-b | grep -c 'registered:')" -lt 1 ]; then
  echo "FAIL: 重定向/注册未完成（redirects=${redirects}）"
  echo "--- node-a 日志尾 15 行 ---"; logs mesh-node-a | tail -15
  echo "--- node-b 日志尾 15 行 ---"; logs mesh-node-b | tail -15
  exit 1
fi
ping_pair || {
  echo "FAIL: a↔b 未通"
  echo "--- node-a 日志尾 20 行 ---"; logs mesh-node-a | tail -20
  exit 1
}

echo "==> 阶段 2/5：停 leader（$LEADER）——数据面不受影响 + 存活副本选出新 Leader"
A_REG_BEFORE=$(logs mesh-node-a | grep -c 'registered:' || true)
B_REG_BEFORE=$(logs mesh-node-b | grep -c 'registered:' || true)
PRE_TERM=$(raft_state_lines "$LEADER" | grep -o 'term=[0-9]*' | tail -1 | cut -d= -f2 || true)
docker stop "$LEADER" >/dev/null
ok=1
for i in $(seq 1 5); do
  docker exec mesh-node-b ping -c1 -W1 10.42.0.1 >/dev/null 2>&1 || ok=0
  docker exec mesh-node-b ping6 -c1 -W1 fd00:2::1 >/dev/null 2>&1 || ok=0
  sleep 1
done
if [ "$ok" != 1 ]; then
  echo "FAIL: leader 停机窗口内 ping 丢失（数据面被控制面故障波及）"
  exit 1
fi
echo "PASS: 停机窗口 5×双栈 ping 无一丢失"
SURVIVORS=()
for c in "${COORDS[@]}"; do
  if [ "$c" != "$LEADER" ]; then SURVIVORS+=("$c"); fi
done
NEW_LEADER=""
NEW_TERM=0
for i in $(seq 1 45); do
  for c in "${SURVIVORS[@]}"; do
    if echo "$(raft_state_lines "$c" | tail -1 || true)" | grep -q 'state=Leader'; then
      NEW_LEADER="$c"; break 2
    fi
  done
  sleep 2
done
NEW_TERM=$(raft_state_lines "$NEW_LEADER" | grep 'state=Leader' | tail -1 \
  | grep -o 'term=[0-9]*' | cut -d= -f2 || true)
if [ -z "$NEW_LEADER" ] || [ -z "$PRE_TERM" ] || [ "$NEW_TERM" -le "$PRE_TERM" ]; then
  echo "FAIL: 新 Leader 未选出或 term 未递增（new=${NEW_LEADER:-无} term=${NEW_TERM:-?} pre=$PRE_TERM）"
  for c in "${SURVIVORS[@]}"; do echo "--- $c ---"; raft_state_lines "$c" | tail -5; done
  exit 1
fi
echo "PASS: failover 完成（$LEADER(term $PRE_TERM) → $NEW_LEADER(term $NEW_TERM)）"

echo "==> 阶段 3/5：节点经重定向链重注册（node_id 不变）"
# 配置面 coord 存活的节点必然完成重注册：会话随 leader 停机断开 → 重连配置地址
#（follower）→ LEADER_REDIRECT → 新 leader 挑战重注册（同 node_id，§5.6 幂等）
regrew=0
for i in $(seq 1 45); do
  a_now=$(logs mesh-node-a | grep -c 'registered:' || true)
  b_now=$(logs mesh-node-b | grep -c 'registered:' || true)
  if [ "$a_now" -gt "$A_REG_BEFORE" ] || [ "$b_now" -gt "$B_REG_BEFORE" ]; then
    regrew=1; break
  fi
  sleep 2
done
if [ "$regrew" != 1 ]; then
  echo "FAIL: failover 后无节点完成重注册"
  echo "--- node-a 日志尾 15 行 ---"; logs mesh-node-a | tail -15
  echo "--- node-b 日志尾 15 行 ---"; logs mesh-node-b | tail -15
  exit 1
fi
if [ "$(registered_ids mesh-node-a)" -ne 1 ] || [ "$(registered_ids mesh-node-b)" -ne 1 ]; then
  echo "FAIL: node_id 漂移（a=$(registered_ids mesh-node-a) b=$(registered_ids mesh-node-b) 个不同 id）"
  logs mesh-node-a | grep 'registered:' || true
  logs mesh-node-b | grep 'registered:' || true
  exit 1
fi
echo "PASS: 重定向链重注册（node_id 不变）"

echo "==> 阶段 4/5：旧 leader 重启 → 以 Follower 回归"
docker start "$LEADER" >/dev/null
NEW_ID=${NEW_LEADER#mesh-coord}
rejoined=0
for i in $(seq 1 45); do
  if echo "$(raft_state_lines "$LEADER" | tail -1)" \
     | grep -q "state=Follower leader=Some($NEW_ID)"; then
    rejoined=1; break
  fi
  sleep 2
done
if [ "$rejoined" != 1 ]; then
  echo "FAIL: $LEADER 未以 Follower 回归（期待 leader=Some($NEW_ID)）"
  echo "--- $LEADER 日志尾 20 行 ---"; raft_state_lines "$LEADER" | tail -5
  echo "--- $LEADER 原始日志尾 20 行 ---"; logs "$LEADER" | tail -20
  exit 1
fi
echo "PASS: $LEADER 回归 Follower（leader=Some($NEW_ID)）"

echo "==> 阶段 5/5：终态回归（a↔b 双栈通 + node_id 全程唯一）"
ping_pair || {
  echo "FAIL: 回归后 a↔b 未恢复"
  exit 1
}
if [ "$(registered_ids mesh-node-a)" -ne 1 ] || [ "$(registered_ids mesh-node-b)" -ne 1 ]; then
  echo "FAIL: 终态 node_id 漂移"
  exit 1
fi
echo "PASS: ha e2e 全部断言通过（重定向/failover/幂等重注册/Follower 回归）"
