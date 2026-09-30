# MTU 场景（ROUTE_ENGINE §6，RTE-07）：底网 1400 + tun 配置 1420（> 保守值 1394）
# ① 基线小包通 ② MSS clamp 双向生效（慢速 iperf3，两侧 ss 协商 mss:1354 = 1394−40）
# ③ DF 超限 → 伪造 PTB v4/v6（next-hop mtu 1314 = 1400 − 86 封装开销；
#    underlay 为 v4 网桥，v6 内层同样按 86 扣）④ PTB 后会话不受扰
fail() {
  echo "FAIL: $1"
  for c in mesh-node-a mesh-node-b; do
    echo "--- $c 日志 ---"
    logs "$c" | tail -20
  done
  exit 1
}

# ① 基线小包 ping（会话建立 + 小帧可通）
ok=0
for i in $(seq 1 30); do
  if docker exec mesh-node-b ping -c1 -W1 10.42.0.1 >/dev/null 2>&1; then ok=1; break; fi
  sleep 2
done
[ "$ok" = "1" ] || fail "基线小包 ping 不通"
echo "PASS: ① 基线小包 ping 通"

# ② MSS clamp：-l 64 小块 + 2K 限速（分段远小于 MSS → 不触发 PTB，协商值全程稳定），
# 两侧轮询。SYN 携带 1354（1394−40）；ss 显示内核有效 mss = 1354−12（TCP
# timestamps 选项）= 1342（未压时为 1368−12 = 1356，可区分）。
# 双向断言：client 侧 1342 证明 server SYN-ACK 被压，server 侧 1342 证明 client SYN 被压
docker exec -d mesh-node-a iperf3 -s -1
docker exec -d mesh-node-b sh -c 'iperf3 -c 10.42.0.1 -l 64 -b 2K -t 30 > /tmp/iperf-mtu.log 2>&1'
ok_a=0
ok_b=0
for i in $(seq 1 15); do
  docker exec mesh-node-b ss -tni dst 10.42.0.1 | grep -q 'mss:1342' && ok_b=1
  docker exec mesh-node-a ss -tni dst 10.43.0.1 | grep -q 'mss:1342' && ok_a=1
  [ "$ok_a" = "1" ] && [ "$ok_b" = "1" ] && break
  sleep 1
done
[ "$ok_b" = "1" ] || fail "node-b 侧未见协商 mss:1342（SYN MSS 未压到 1394−40）"
[ "$ok_a" = "1" ] || fail "node-a 侧未见协商 mss:1342（client SYN 未被压）"
echo "PASS: ② MSS clamp 双向生效（两侧协商 mss:1342 = 1394−40−12 timestamps）"

# ③ PTB v4：DF + 1380B 载荷（内层 1408B，+86 = 1494 > 1400 出口）→ EMSGSIZE →
#    伪造 PTB（src = 内层 dst 10.42.0.1），ping 报 Frag needed + mtu 1314
PTB_OUT=$(docker exec mesh-node-b ping -c2 -W2 -M do -s 1380 10.42.0.1 2>&1 || true)
echo "$PTB_OUT"
echo "$PTB_OUT" | grep -qi "frag needed" || fail "未收到 ICMP frag needed（PTB v4）"
echo "$PTB_OUT" | grep -q "1314" || fail "PTB v4 next-hop MTU 非 1314（1400−86）"
echo "PASS: ③ PTB v4（Frag needed, mtu=1314）"

# ③' PTB v6：内层 1408B IPv6（underlay 仍 v4 开销 86）→ ICMPv6 Packet Too Big 1314
PTB6_OUT=$(docker exec mesh-node-b ping -c2 -W2 -M do -s 1360 fd00:2::1 2>&1 || true)
echo "$PTB6_OUT"
echo "$PTB6_OUT" | grep -qi "too big" || fail "未收到 ICMPv6 Packet Too Big"
echo "$PTB6_OUT" | grep -q "1314" || fail "PTB v6 next-hop MTU 非 1314"
echo "PASS: ③' PTB v6（Packet Too Big, mtu=1314）"

# ④ PTB 后基线不受扰（伪造 PTB 只影响对应流，不扰动 mesh 会话）
sleep 2
docker exec mesh-node-b ping -c2 -W2 10.42.0.1 >/dev/null 2>&1 \
  || fail "PTB 后小包 ping 不通（会话被扰动）"
echo "PASS: ④ PTB 后基线 ping 正常"
echo "PASS: mtu 场景全部断言通过（RTE-07）"
exit 0
