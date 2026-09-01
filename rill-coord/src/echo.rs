//! coordinator UDP 回显（CONNECTIVITY §2，STUN 式零额外组件）
//!
//! 纯逻辑（I/O-free）：socket 在 rilld 接线，本模块只做**限速判定 + 响应构建**。
//! - 节点发 probe PING（to_node_id=0 回显标记），coordinator 回 PONG 携带 seen 地址
//! - 反射放大防护（§2.2/SEC-26）：按源 IP 令牌桶限速（放大因子 ~1:1，限速后收敛）
//! - 解析 fail-closed：非法输入一律不回（CN-02）

use landscape_rill_core::probe::{probe_type, ProbePacket, NODE_ID_COORDINATOR};
use landscape_rill_core::rate::TokenBucket;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

/// 默认限速：每源 IP 每秒 10 个回显（容量 20 突发）
pub const ECHO_RATE_PER_SEC: f64 = 10.0;
pub const ECHO_CAPACITY: u32 = 20;

/// 按源 IP 的令牌桶集合（反射放大防护，CONNECTIVITY §2.2）
#[derive(Debug)]
pub struct EchoLimiter {
    buckets: HashMap<IpAddr, TokenBucket>,
    rate_per_sec: f64,
    capacity: u32,
}

impl EchoLimiter {
    pub fn new(rate_per_sec: f64, capacity: u32) -> Self {
        Self {
            buckets: HashMap::new(),
            rate_per_sec,
            capacity,
        }
    }

    /// 该源地址是否允许本次回显（限速判定）
    pub fn allow(&mut self, src: IpAddr) -> bool {
        let bucket = self
            .buckets
            .entry(src)
            .or_insert_with(|| TokenBucket::new(self.rate_per_sec, self.capacity));
        bucket.take()
    }

    /// 清理空桶（防伪造源地址洪泛撑爆状态；周期调用）
    pub fn prune(&mut self) {
        // 令牌桶无"空判定"API，直接周期性重建（源地址集合小，重建成本可忽略）
        if self.buckets.len() > 4096 {
            self.buckets.clear();
        }
    }
}

/// 构建回显响应：probe PING（to=回显标记）→ PONG 携带 seen 地址（"ip:port"）。
/// 非法输入 / 非回显请求 → None（fail-closed，不回任何东西）。
pub fn echo_response(request: &[u8], seen: SocketAddr) -> Option<Vec<u8>> {
    let ping = ProbePacket::decode(request)?;
    if ping.packet_type != probe_type::PING || ping.to_node_id != NODE_ID_COORDINATOR {
        return None;
    }
    let pong = ProbePacket::pong(&ping, seen.to_string().into_bytes());
    Some(pong.encode())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seen_addr() -> SocketAddr {
        "203.0.113.5:41641".parse().unwrap()
    }

    #[test]
    fn echo_roundtrip_builds_pong_with_seen_addr() {
        let req = ProbePacket::ping(7, NODE_ID_COORDINATOR, 42).encode();
        let resp = echo_response(&req, seen_addr()).unwrap();
        let pong = ProbePacket::decode(&resp).unwrap();
        assert_eq!(pong.packet_type, probe_type::PONG);
        assert_eq!(pong.nonce, 42);
        assert_eq!(pong.to_node_id, 7);
        assert_eq!(pong.payload, seen_addr().to_string().into_bytes());
    }

    #[test]
    fn echo_rejects_non_echo_or_garbage() {
        // 互探 PING（to=真实节点）→ 不回
        let ping = ProbePacket::ping(7, 9, 1).encode();
        assert!(echo_response(&ping, seen_addr()).is_none());
        // 垃圾字节 → 不回
        assert!(echo_response(b"garbage", seen_addr()).is_none());
        assert!(echo_response(&[], seen_addr()).is_none());
        // 截断的 probe → 不回
        let mut p = ProbePacket::ping(7, NODE_ID_COORDINATOR, 1).encode();
        p.truncate(5);
        assert!(echo_response(&p, seen_addr()).is_none());
    }

    #[test]
    fn limiter_allows_burst_then_blocks() {
        let mut limiter = EchoLimiter::new(10.0, 3);
        let src: IpAddr = "203.0.113.7".parse().unwrap();
        assert!(limiter.allow(src));
        assert!(limiter.allow(src));
        assert!(limiter.allow(src));
        assert!(!limiter.allow(src), "突发容量 3 已耗尽");
        assert!(!limiter.allow(src));
        // 不同源地址独立限速
        let other: IpAddr = "203.0.113.8".parse().unwrap();
        assert!(limiter.allow(other));
    }
}
