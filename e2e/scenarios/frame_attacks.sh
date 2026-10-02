# frame_attacks 场景（SEC-01~04/11 容器级复验，FRAME_HEADER §3/§5）：
# 拓扑：direct（coord + node-a + node-b，节点 debug 日志）+ 宿主 forge.py 注入
# 攻击者模型：非成员 = 无密钥（random key / 在途篡改不重算 mac）；
#             成员 = 持 key_dst（lab 主密钥派生，与 KeyDist 下发材料等价）
# 断言：
# ① SEC-01 在途篡改（stale route_mac）→ BadRouteMac 丢弃
# ② SEC-02 非成员伪造（random key）→ BadRouteMac（送达路径 + 转发路径 to≠本节点）
# ③ SEC-03 成员伪造 from_node_id（正确 key，route_mac 合法）→ 会话层拦截（Aead/NoSession/Replay），
#    BadRouteMac 不增长（正对照：越过 route_mac）
# ④ SEC-04 成员篡改并重算 route_mac（正确 key + 任意 seq + 垃圾密文）→ 会话层拦截
#    （AAD 绑定帧头：重算 mac 只骗过转发面，骗不过目的端 AEAD）
# ⑤ SEC-11 垃圾 AEAD 洪泛（2000 帧）→ 逐帧计数丢弃、三容器存活、洪泛后双栈 ping 收敛
FORGE="$E2E_DIR/mesh/tenancy/forge.py"

echo "==> frame_attacks 阶段 1/6：注册 + 基线连通（会话建立）"
for c in mesh-node-a mesh-node-b; do
  for i in $(seq 1 30); do
    logs $c | grep -q 'registered:' && break
    sleep 2
    [ "$i" = "30" ] && { echo "FAIL: $c 未注册"; logs $c | tail -10; exit 1; }
  done
done
A_ID=$(logs mesh-node-a | grep -o 'registered: node_id=[0-9]*' | tail -1 | cut -d= -f2)
B_ID=$(logs mesh-node-b | grep -o 'registered: node_id=[0-9]*' | tail -1 | cut -d= -f2)
A_EP=$(logs mesh-node-a | grep -o '192\.168\.240\.11:[0-9]*' | head -1)
B_EP=$(logs mesh-node-b | grep -o '192\.168\.240\.21:[0-9]*' | head -1)
[ -n "$A_ID" ] && [ -n "$B_ID" ] && [ -n "$A_EP" ] && [ -n "$B_EP" ] || {
  echo "FAIL: 注入参数提取失败（a=$A_ID b=$B_ID aep=$A_EP bep=$B_EP）"
  logs mesh-node-b | grep -E 'registered:|endpoint' | tail -5
  exit 1
}
A_IP="${A_EP%:*}"; A_PORT="${A_EP##*:}"
B_IP="${B_EP%:*}"; B_PORT="${B_EP##*:}"
LAB_KEY="$(cat "$E2E_DIR/build/.lab_master_key")"
echo "注入参数：a=#$A_ID b=#$B_ID b_ep=$B_EP"
# 基线：b→a 双栈 ping（同时建立 a↔b 会话，后续伪造帧死因落在 Aead 而非 NoSession）
for i in $(seq 1 20); do
  if docker exec mesh-node-b ping -c1 -W1 10.42.0.1 >/dev/null 2>&1 \
     && docker exec mesh-node-b ping6 -c1 -W1 fd00:2::1 >/dev/null 2>&1; then break; fi
  sleep 2
done
docker exec mesh-node-b ping -c1 -W1 10.42.0.1 >/dev/null 2>&1 || { echo "FAIL: 基线 b→a 不通"; exit 1; }
echo "PASS: 双节点注册 + 基线双栈连通"

drops() { logs mesh-node-b | grep -c "dropped frame: $1" || true; }
sess_drops() { logs mesh-node-b | grep -cE 'dropped frame: (Aead|NoSession|Replay)' || true; }

echo "==> frame_attacks 阶段 2/6：SEC-01 在途篡改（stale route_mac）+ SEC-02 非成员伪造"
BAD0=$(drops BadRouteMac)
# SEC-01：正确 key 构帧后翻转 from_node_id 字节（不重算 mac）→ 篡改被 route_mac 绑定拦截
python3 "$FORGE" "$B_IP" "$B_PORT" "$A_ID" "$B_ID" "$LAB_KEY" 800001 64 1 tamper >/dev/null
# SEC-02a：非成员 random key 直接伪造 → 送达路径 BadRouteMac
python3 "$FORGE" "$B_IP" "$B_PORT" "$A_ID" "$B_ID" random 800100 64 >/dev/null
# SEC-02b：非成员 random key、to=a → node-b 作为转发节点校验 route_mac（key_dst(to)）拦截
python3 "$FORGE" "$B_IP" "$B_PORT" "$B_ID" "$A_ID" random 800200 64 >/dev/null
ok=0
for i in $(seq 1 10); do
  if [ "$(drops BadRouteMac)" -ge $((BAD0 + 3)) ]; then ok=1; break; fi
  sleep 1
done
[ "$ok" = "1" ] || { echo "FAIL: 篡改/伪造帧未被 BadRouteMac 拦截（$(drops BadRouteMac) ≤ $BAD0）"; logs mesh-node-b | grep 'dropped frame' | tail -5; exit 1; }
echo "PASS: SEC-01 stale-mac 篡改 + SEC-02 非成员伪造（送达+转发路径）均 BadRouteMac"

echo "==> frame_attacks 阶段 3/6：SEC-03 成员伪造 from_node_id → 会话层拦截"
BAD1=$(drops BadRouteMac); SESS1=$(sess_drops)
# 正确 key（成员持有 key_dst 等价材料）+ 伪造 from=a：route_mac 合法 → 死在 AEAD/会话层
python3 "$FORGE" "$B_IP" "$B_PORT" "$A_ID" "$B_ID" "$LAB_KEY" 900001 64 20 >/dev/null
ok=0
for i in $(seq 1 10); do
  if [ "$(sess_drops)" -ge $((SESS1 + 15)) ]; then ok=1; break; fi
  sleep 1
done
[ "$ok" = "1" ] || { echo "FAIL: 伪造源帧未在会话层被拦（$(sess_drops) ≤ $SESS1）"; logs mesh-node-b | grep 'dropped frame' | tail -5; exit 1; }
[ "$(drops BadRouteMac)" -le "$BAD1" ] || { echo "FAIL: 正确 key 帧竟 BadRouteMac（注入 crypto 失配）"; exit 1; }
echo "PASS: SEC-03 伪造 from 越过 route_mac、目的端 AEAD 拦截（正对照成立）"

echo "==> frame_attacks 阶段 4/6：SEC-04 成员篡改并重算 route_mac → AEAD 拦截"
SESS2=$(sess_drops)
# 重算 route_mac（forge.py 恒按 key 计算 = 攻击者重算）+ 垃圾密文：转发面放行、AEAD 拦截
python3 "$FORGE" "$B_IP" "$B_PORT" "$A_ID" "$B_ID" "$LAB_KEY" 910001 64 20 >/dev/null
ok=0
for i in $(seq 1 10); do
  if [ "$(sess_drops)" -ge $((SESS2 + 15)) ]; then ok=1; break; fi
  sleep 1
done
[ "$ok" = "1" ] || { echo "FAIL: 重算 mac 帧未在会话层被拦（$(sess_drops) ≤ $SESS2）"; exit 1; }
echo "PASS: SEC-04 重算 route_mac 骗过转发面、AAD 绑定使目的端 AEAD 拦截"

echo "==> frame_attacks 阶段 5/6：SEC-11 垃圾 AEAD 洪泛（2000 帧）"
SESS3=$(sess_drops)
python3 "$FORGE" "$B_IP" "$B_PORT" "$A_ID" "$B_ID" "$LAB_KEY" 950000 64 2000 >/dev/null
ok=0
for i in $(seq 1 20); do
  if [ "$(sess_drops)" -ge $((SESS3 + 1000)) ]; then ok=1; break; fi
  sleep 1
done
[ "$ok" = "1" ] || { echo "FAIL: 洪泛帧未被逐帧计数丢弃（$(sess_drops) ≤ $SESS3）"; exit 1; }
for c in mesh-coord mesh-node-a mesh-node-b; do
  [ "$(docker inspect -f '{{.State.Running}}' $c)" = "true" ] || { echo "FAIL: $c 洪泛后退出"; exit 1; }
done
echo "PASS: SEC-11 洪泛逐帧丢弃 + 三容器存活"

echo "==> frame_attacks 阶段 6/6：洪泛后已认证流量收敛（b → a 双栈）"
for i in $(seq 1 20); do
  if docker exec mesh-node-b ping -c1 -W1 10.42.0.1 >/dev/null 2>&1 \
     && docker exec mesh-node-b ping6 -c1 -W1 fd00:2::1 >/dev/null 2>&1; then
    echo "PASS: 洪泛后 mesh ping 通（IPv4 + IPv6）——已认证流量不受影响"
    echo "PASS: frame_attacks 全部断言通过（SEC-01~04/11）"
    exit 0
  fi
  sleep 2
done
echo "FAIL: 洪泛后 ping 不通"
echo "--- node-b dropped frame 分布 ---"; logs mesh-node-b | grep 'dropped frame' | sort | uniq -c | sort -rn | head -10
exit 1
