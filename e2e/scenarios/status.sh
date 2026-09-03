  # status 场景（REQ-051/052，CONTROL_PLANE §3.14/§3.15，ADM-07/CTL-21）：
  # 拓扑同 direct + coord 启用 status（0.0.0.0:9444，宿主直达 192.168.240.10）
  # 断言：
  # ① 注册收敛 + b→a ping（遥测流量源）
  # ② 认证：无/错密码 401；同源高频错密码 429（按源限速）；明文 HTTP 在 TLS 层被拒
  # ③ 正确密码 200：内容组齐全（networks/nodes/auth_keys/counters/coord/telemetry）
  #    + 节点 build_version（REQ-052 RegisterRequest.version）
  # ④ 遥测聚合：per-peer 收发计数 > 0、直连确认对非空（probe RTT，latest-wins）
  # ⑤ SIGHUP 密码轮换：旧密码即刻 401、新密码 200、reload_log 记录 ok（内容组 5）
  # ⑥ 重载失败：坏配置 → SIGHUP → reload_log 记录 failed + 保持旧配置（密码仍可用）
  # ⑦ 红线：明文密码/master_key/signing_seed 不出现在响应；轮换/失败重载后数据面不受影响
  STATUS_URL="https://coord:9444/status"
  STATUS_IP="192.168.240.10"
  CA="$E2E_DIR/build/ca.pem"
  CURL_BASE=(curl -s --cacert "$CA" --resolve "coord:9444:$STATUS_IP")
  code_with() {  # $1=Authorization 头（空 = 不带）
    if [ -n "$1" ]; then
      "${CURL_BASE[@]}" -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $1" "$STATUS_URL"
    else
      "${CURL_BASE[@]}" -o /dev/null -w '%{http_code}' "$STATUS_URL"
    fi
  }
  wait_coord_status() {  # 端点可达（TLS 握手成功，任意状态码）
    for i in $(seq 1 30); do
      c=$(code_with "" || true)
      [ "$c" != "000" ] && return 0
      sleep 2
    done
    return 1
  }
  wait_registered() {
    for i in $(seq 1 30); do
      if [ "$(logs mesh-node-a | grep -c 'registered:')" -ge 1 ] \
         && [ "$(logs mesh-node-b | grep -c 'registered:')" -ge 1 ]; then
        return 0
      fi
      sleep 2
    done
    return 1
  }
  fetch_status() {
    "${CURL_BASE[@]}" -H "Authorization: Bearer e2e-status-pass-1" "$STATUS_URL"
  }

  echo "==> status 阶段 1/7：注册收敛 + 数据面 ping（遥测流量源）"
  wait_registered || { echo "FAIL: 节点未注册"; logs mesh-node-a | tail -10; exit 1; }
  for i in $(seq 1 20); do
    if docker exec mesh-node-b ping -c1 -W1 10.42.0.1 >/dev/null 2>&1; then
      echo "PASS: 注册收敛 + b→a IPv4 ping 通"
      break
    fi
    [ "$i" -ge 20 ] && { echo "FAIL: ping 不通"; exit 1; }
    sleep 2
  done

  echo "==> status 阶段 2/7：认证面（401 / 429 / 明文拒绝）"
  wait_coord_status || { echo "FAIL: status 端点不可达"; logs mesh-coord | tail -10; exit 1; }
  [ "$(code_with "")" = "401" ] || { echo "FAIL: 无密码应 401，got $(code_with "")"; exit 1; }
  [ "$(code_with "wrong-pass")" = "401" ] || { echo "FAIL: 错密码应 401"; exit 1; }
  echo "PASS: 无/错密码 401"
  # 同源高频错密码 → 429（突发 10 + 5/s；30 连发必然击穿）
  python3 - "$STATUS_IP" <<'PYEOF'
import http.client, ssl, sys
ctx = ssl._create_unverified_context()
codes = []
for _ in range(30):
    c = http.client.HTTPSConnection(sys.argv[1], 9444, context=ctx, timeout=5)
    c.request("GET", "/status", headers={"Authorization": "Bearer wrong"})
    codes.append(c.getresponse().status)
    c.close()
assert 429 in codes, f"no 429 in {codes}"
assert codes.count(401) > 0, f"no 401 in {codes}"
print(f"PASS: 认证失败限速命中（401 x{codes.count(401)}, 429 x{codes.count(429)}）")
PYEOF
  if curl -s -m 5 "http://$STATUS_IP:9444/status" >/dev/null 2>&1; then
    echo "FAIL: 明文 HTTP 不应得到 HTTP 响应（TLS 层须拒绝）"
    exit 1
  fi
  echo "PASS: 明文 HTTP 在 TLS 握手层被拒"

  echo "==> status 阶段 3/7：正确密码 200 + 内容组齐全"
  # 限速桶排空（容量 10 + 5/s 补充；洪泛后须等窗口恢复）
  sleep 5
  BODY=$(fetch_status)
  python3 - "$BODY" <<'PYEOF'
import json, sys
d = json.loads(sys.argv[1])
# 内容组 1-6 齐全
for group in ("networks", "nodes", "auth_keys", "counters", "coord", "telemetry"):
    assert group in d, f"missing group {group}"
assert d["networks"] and d["networks"][0]["name"] == "lab"
assert d["counters"]["register_rejects"] == 0
# 节点表：指纹 + 在线 + build_version（REQ-052）
assert len(d["nodes"]) >= 2
for n in d["nodes"]:
    assert n["pubkey_fingerprint"].startswith("sha256:")
    assert n["online"], f"node {n['node_id']} offline"
    assert n["build_version"], "build_version missing (REQ-052)"
# coord 自身
assert d["coord"]["storage"] == "memory"
assert d["coord"]["status_addr"] == "0.0.0.0:9444"
assert d["coord"]["uptime_secs"] > 0
print("PASS: 内容组 1-6 齐全（含 build_version/指纹/在线分支）")
PYEOF
  # 红线（⑥）：密码/密钥材料零输出
  if echo "$BODY" | grep -qE 'e2e-status-pass-[12]|"master_key"|"signing_seed"'; then
    echo "FAIL: 红线——响应泄漏密码或密钥材料"
    exit 1
  fi
  echo "PASS: 红线——明文密码/master_key/signing_seed 零输出"

  echo "==> status 阶段 4/7：遥测聚合（per-peer 计数 + 直连确认对）"
  python3 - "$STATUS_IP" <<'PYEOF'
import http.client, ssl, sys, time
ctx = ssl._create_unverified_context()
def fetch():
    c = http.client.HTTPSConnection(sys.argv[1], 9444, context=ctx, timeout=5)
    c.request("GET", "/status", headers={"Authorization": "Bearer e2e-status-pass-1"})
    body = c.getresponse().read()
    c.close()
    return json.loads(body)
import json
deadline = time.time() + 60
peers_ok = direct_ok = False
while time.time() < deadline and not (peers_ok and direct_ok):
    d = fetch()
    tele = d["telemetry"]
    peers_ok = any(
        any(p["tx_frames"] > 0 or p["rx_frames"] > 0 for p in t["peers"]) for t in tele
    )
    direct_ok = any(t["direct"] for t in tele)
    if peers_ok and direct_ok:
        break
    time.sleep(3)
assert peers_ok, f"per-peer 流量计数未出现: {json.dumps(tele)[:400]}"
assert direct_ok, "直连确认对未出现（probe RTT 未上报）"
rtts = [p["rtt_ms"] for t in tele for p in t["direct"]]
print(f"PASS: 遥测聚合 latest-wins（per-peer 计数 > 0，直连对 RTT={rtts}ms）")
PYEOF

  echo "==> status 阶段 5/7：SIGHUP 密码轮换（旧密码即刻 401）"
  cp "$E2E_DIR/build/coord.json.rotated" "$E2E_DIR/build/coord.json"
  docker kill -s HUP mesh-coord >/dev/null
  for i in $(seq 1 20); do
    if [ "$(logs mesh-coord | grep -c 'password rotated')" -ge 1 ]; then
      break
    fi
    sleep 1
  done
  [ "$(code_with "e2e-status-pass-1")" = "401" ] || { echo "FAIL: 旧密码应即刻 401"; exit 1; }
  echo "PASS: 旧密码即刻 401"
  # 新密码 200 + reload_log 记录 ok（内容组 5）
  NEW=$(curl -s --cacert "$CA" --resolve "coord:9444:$STATUS_IP" \
    -H "Authorization: Bearer e2e-status-pass-2" "$STATUS_URL")
  python3 - "$NEW" <<'PYEOF'
import json, sys
d = json.loads(sys.argv[1])
assert any("ok" in r for r in d["coord"]["reload_log"]), d["coord"]["reload_log"]
print("PASS: 新密码 200 + reload_log 记录 ok（重载历史）")
PYEOF

  echo "==> status 阶段 6/7：重载失败 → reload_log 记录 failed + 保持旧配置"
  printf 'this is not json\n' > "$E2E_DIR/build/coord.json"
  docker kill -s HUP mesh-coord >/dev/null
  for i in $(seq 1 20); do
    if [ "$(logs mesh-coord | grep -c 'reload failed, keeping old config')" -ge 1 ]; then
      break
    fi
    sleep 1
  done
  [ "$(logs mesh-coord | grep -c 'reload failed, keeping old config')" -ge 1 ] \
    || { echo "FAIL: 未观察到 reload failed 日志"; logs mesh-coord | tail -10; exit 1; }
  sleep 2
  AFTER_FAIL=$(curl -s --cacert "$CA" --resolve "coord:9444:$STATUS_IP" \
    -H "Authorization: Bearer e2e-status-pass-2" "$STATUS_URL")
  python3 - "$AFTER_FAIL" <<'PYEOF'
import json, sys
d = json.loads(sys.argv[1])
log = d["coord"]["reload_log"]
assert any(r.startswith("failed") for r in log), f"missing failed entry: {log}"
assert any(r.startswith("ok") for r in log), f"missing ok entry: {log}"
print("PASS: reload_log 同时记录 ok 与 failed（重载历史完整）")
PYEOF
  [ "$(code_with "e2e-status-pass-2")" = "200" ] \
    || { echo "FAIL: 失败重载后旧配置应保持服务（pass-2 仍 200）"; exit 1; }
  echo "PASS: 失败重载保持旧配置（认证不中断）"

  echo "==> status 阶段 7/7：轮换/失败重载后数据面不受影响"
  docker exec mesh-node-b ping -c2 10.42.0.1 >/dev/null 2>&1 \
    || { echo "FAIL: 轮换后 ping 不通（SIGHUP 不应中断数据面）"; exit 1; }
  echo "PASS: SIGHUP 轮换不中断数据面（a↔b 仍通）"
