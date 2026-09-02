//! 限速与周期计数（CONNECTIVITY §2.2/§4.3/§5.1 / LOGGING §5）
//!
//! - [`TokenBucket`]：令牌桶限速（泛洪抑制、probe 发送/PONG 按源限速）
//! - [`SourceRateLimiter`]：按源地址的令牌桶集合（反射放大防护）
//! - [`RateCounter`]：事件计数 + 固定周期摘要输出（高频失败摘要，输出率严格有界）

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// 周期摘要默认周期（LOGGING §5）：高频事件每周期最多 1 条摘要
pub const RATE_SUMMARY_PERIOD: Duration = Duration::from_secs(1);

/// 令牌桶（CONNECTIVITY §2.2 回显限速 / FRAME_HEADER §2.6 泛洪限速）
#[derive(Debug)]
pub struct TokenBucket {
    capacity: u32,
    rate_per_sec: f64,
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    pub fn new(rate_per_sec: f64, capacity: u32) -> Self {
        Self {
            capacity,
            rate_per_sec,
            tokens: capacity as f64,
            last: Instant::now(),
        }
    }

    /// 尝试取一个令牌；桶空返回 false
    pub fn take(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate_per_sec).min(self.capacity as f64);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// 按源地址的令牌桶集合（CONNECTIVITY §2.2/§4.3 反射放大防护）：
/// coordinator 回显、节点 PONG 生成共用；无认证小包的响应面必须有上界
#[derive(Debug)]
pub struct SourceRateLimiter {
    buckets: HashMap<IpAddr, TokenBucket>,
    rate_per_sec: f64,
    capacity: u32,
}

impl SourceRateLimiter {
    pub fn new(rate_per_sec: f64, capacity: u32) -> Self {
        Self {
            buckets: HashMap::new(),
            rate_per_sec,
            capacity,
        }
    }

    /// 该源地址是否允许本次响应（限速判定）
    pub fn allow(&mut self, src: IpAddr) -> bool {
        let bucket = self
            .buckets
            .entry(src)
            .or_insert_with(|| TokenBucket::new(self.rate_per_sec, self.capacity));
        bucket.take()
    }

    /// 清理桶表（防伪造源地址洪泛撑爆状态；周期调用）
    pub fn prune(&mut self) {
        // 令牌桶无"空判定"API，超阈值直接重建（源地址集合小，重建成本可忽略）
        if self.buckets.len() > 4096 {
            self.buckets.clear();
        }
    }
}

/// 事件计数 + 周期摘要
#[derive(Debug, Clone)]
pub struct RateCounter {
    period: Duration,
    window_start: Instant,
    count: u64,
}

impl RateCounter {
    pub fn new(period: Duration) -> Self {
        Self {
            period,
            window_start: Instant::now(),
            count: 0,
        }
    }

    /// 事件发生：计数 +1
    pub fn tick(&mut self) {
        self.count += 1;
    }

    /// 周期到 → 返回本周期计数并清零；周期未到 → None
    pub fn poll(&mut self, now: Instant) -> Option<u64> {
        if now.duration_since(self.window_start) < self.period {
            return None;
        }
        self.window_start = now;
        Some(std::mem::take(&mut self.count))
    }

    /// 是否还有未取走的计数（清理长周期无事件的 entry 用）
    pub fn has_pending(&self) -> bool {
        self.count > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_limiter_allows_burst_then_blocks_per_source() {
        let mut limiter = SourceRateLimiter::new(10.0, 3);
        let src: IpAddr = "203.0.113.7".parse().unwrap();
        assert!(limiter.allow(src));
        assert!(limiter.allow(src));
        assert!(limiter.allow(src));
        assert!(!limiter.allow(src), "突发容量 3 已耗尽");
        // 不同源地址独立限速
        let other: IpAddr = "203.0.113.8".parse().unwrap();
        assert!(limiter.allow(other));
    }

    #[test]
    fn source_limiter_prune_rebuilds_on_overflow() {
        let mut limiter = SourceRateLimiter::new(10.0, 1);
        for i in 0..4097 {
            let ip: IpAddr = format!("10.0.{}.{}", i / 256 % 256, i % 256)
                .parse()
                .unwrap();
            limiter.allow(ip);
            limiter.prune();
        }
        assert!(limiter.buckets.is_empty(), "超阈值后重建");
    }

    #[test]
    fn tick_counts_and_poll_reports_per_period() {
        let period = Duration::from_secs(1);
        let mut rc = RateCounter::new(period);
        let t0 = Instant::now();
        rc.tick();
        rc.tick();
        assert_eq!(rc.poll(t0), None);
        assert_eq!(rc.poll(t0 + period), Some(2));
        // poll 推进窗口锚：周期未到 → None；清零后下一周期从 0 重新累计
        assert_eq!(rc.poll(t0 + period + Duration::from_millis(1)), None);
        assert_eq!(rc.poll(t0 + period * 2), Some(0));
        assert_eq!(rc.poll(t0 + period * 2 + Duration::from_millis(1)), None);
        rc.tick();
        assert_eq!(rc.poll(t0 + period * 3), Some(1));
    }
}
