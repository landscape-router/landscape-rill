//! 控制面重连退避（REQ-056 / CONTROL_PLANE §2）
//!
//! 事件驱动状态机：`connect`（TCP/TLS 建立，不重置）/ `registered`（注册成功，
//! 唯一的重置判定——半开连接 ≠ 恢复）/ `disconnect`（断线或连接失败，推进退避）。
//! 连接失败与「连上后断开」统一走 `disconnect`：后者此前零退避立即重连，
//! 构成热循环放大器。

use std::time::Duration;

pub const RECONNECT_INITIAL_BACKOFF: Duration = Duration::from_secs(1);
pub const RECONNECT_MAX_BACKOFF: Duration = Duration::from_secs(300);

#[derive(Debug)]
pub struct ReconnectPolicy {
    backoff: Duration,
}

impl ReconnectPolicy {
    pub fn new() -> Self {
        Self {
            backoff: RECONNECT_INITIAL_BACKOFF,
        }
    }

    /// TCP/TLS 建立：无操作（不重置退避进度）
    pub fn on_connect(&mut self) {}

    /// 注册成功：退避重置
    pub fn on_registered(&mut self) {
        self.backoff = RECONNECT_INITIAL_BACKOFF;
    }

    /// 断线/连接失败：返回本次等待时长并指数推进（封顶 300s）
    pub fn on_disconnect(&mut self) -> Duration {
        let wait = self.backoff;
        self.backoff = (self.backoff * 2).min(RECONNECT_MAX_BACKOFF);
        wait
    }
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disconnect_advances_exponentially_and_caps() {
        let mut p = ReconnectPolicy::new();
        assert_eq!(p.on_disconnect(), Duration::from_secs(1));
        assert_eq!(p.on_disconnect(), Duration::from_secs(2));
        assert_eq!(p.on_disconnect(), Duration::from_secs(4));
        for _ in 0..20 {
            p.on_disconnect();
        }
        assert_eq!(p.on_disconnect(), RECONNECT_MAX_BACKOFF);
    }

    #[test]
    fn registered_resets_backoff() {
        let mut p = ReconnectPolicy::new();
        p.on_disconnect();
        p.on_disconnect();
        p.on_registered();
        assert_eq!(p.on_disconnect(), Duration::from_secs(1));
    }

    #[test]
    fn connect_does_not_reset_backoff() {
        let mut p = ReconnectPolicy::new();
        p.on_disconnect();
        p.on_disconnect();
        p.on_connect();
        assert_eq!(p.on_disconnect(), Duration::from_secs(4));
    }
}
