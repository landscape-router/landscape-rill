//! 周期计数器（LOGGING §5）：事件计数 + 固定周期摘要输出
//!
//! 语义：事件只计数不逐条输出；poll 每周期返回累计数（0 由调用方决定不打印），
//! 输出率严格有界（每计数器每周期 ≤1 行）。与日志框架解耦，纯逻辑可单测。

use std::time::{Duration, Instant};

/// 周期摘要默认周期（LOGGING §5）：高频事件每周期最多 1 条摘要
pub const RATE_SUMMARY_PERIOD: Duration = Duration::from_secs(1);

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
