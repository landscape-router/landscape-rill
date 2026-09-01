//! daemon 日志初始化（LOGGING §2/§4）
//!
//! 边界：仅 `lrill run`（daemon）初始化 subscriber；CLI 子命令直接 stdout/stderr，
//! 不进日志框架（LOGGING §1）——auth key 不落日志红线因此是结构性的（LOGGING §6）。
//!
//! 配置优先级（LOGGING §2/§4）：CLI 显式 > 环境变量 > 默认值——
//! - 级别：`--log-level` > `RUST_LOG` > 默认 `info`
//! - 文件输出：`--log-file` > `LRILL_LOG_FILE` > 默认仅 stderr
//!
//! 存储：默认 stderr（systemd 由 journald 捕获、容器由 docker log driver 捕获）；
//! 文件模式用 tracing-appender 按天轮转（保留 7 个，容量/轮转是框架职责）。
//! 高频事件不逐条输出：调用点用 rill-core `RateCounter` 计数，周期摘要打印（LOGGING §5）。

use std::io;
use std::path::{Path, PathBuf};

use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::prelude::*;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer, Registry};

/// 默认日志级别（LOGGING §2）
pub const DEFAULT_LOG_LEVEL: &str = "info";
/// 文件输出环境变量（LOGGING §4）
pub const LOG_FILE_ENV: &str = "LRILL_LOG_FILE";

/// 级别选择（LOGGING §2）：CLI > RUST_LOG > 默认
fn select_filter(cli_level: Option<LevelFilter>, rust_log: Option<String>) -> EnvFilter {
    match cli_level {
        Some(level) => EnvFilter::new(level.to_string()),
        None => match rust_log {
            Some(expr) => {
                EnvFilter::try_new(expr).unwrap_or_else(|_| EnvFilter::new(DEFAULT_LOG_LEVEL))
            }
            None => EnvFilter::new(DEFAULT_LOG_LEVEL),
        },
    }
}

/// 文件输出选择（LOGGING §4）：CLI > LRILL_LOG_FILE > 默认无
fn select_log_file(cli: Option<PathBuf>) -> Option<PathBuf> {
    cli.or_else(|| std::env::var_os(LOG_FILE_ENV).map(PathBuf::from))
}

/// 初始化 daemon 日志（仅 `lrill run` 调用；LOGGING §2/§4）
pub fn init_logging(
    log_level: Option<LevelFilter>,
    log_file: Option<PathBuf>,
) -> Result<(), String> {
    let filter = select_filter(log_level, std::env::var("RUST_LOG").ok());
    let log_file = select_log_file(log_file);
    // 默认 stderr（systemd/journald、容器/docker log driver 捕获）；文件模式追加输出
    let fmt = tracing_subscriber::fmt::layer().with_ansi(false);
    let fmt: Box<dyn Layer<Registry> + Send + Sync> = match log_file.as_deref() {
        Some(path) => {
            let dir = path.parent().unwrap_or_else(|| Path::new("."));
            let prefix = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| "lrill".into());
            let appender = tracing_appender::rolling::RollingFileAppender::builder()
                .rotation(tracing_appender::rolling::Rotation::DAILY)
                .max_log_files(7)
                .filename_prefix(&prefix)
                .build(dir)
                .map_err(|e| format!("log file {}: {e}", path.display()))?;
            let (writer, guard) = tracing_appender::non_blocking(appender);
            // guard 必须存活到进程结束；daemon 常驻，直接泄漏
            Box::leak(Box::new(guard));
            Box::new(fmt.with_writer(writer))
        }
        None => Box::new(fmt.with_writer(io::stderr)),
    };
    Registry::default().with(fmt).with(filter).init();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn level_priority_cli_over_env_over_default() {
        // CLI 显式 > RUST_LOG
        let f = select_filter(Some(LevelFilter::DEBUG), Some("error".into()));
        assert_eq!(f.max_level_hint(), Some(LevelFilter::DEBUG));
        // RUST_LOG > 默认
        let f = select_filter(None, Some("warn".into()));
        assert_eq!(f.max_level_hint(), Some(LevelFilter::WARN));
        // 默认 info
        let f = select_filter(None, None);
        assert_eq!(f.max_level_hint(), Some(LevelFilter::INFO));
        // CLI 显式指定时 RUST_LOG 完全被覆盖（含 target 级过滤）
        let f = select_filter(Some(LevelFilter::ERROR), Some("debug".into()));
        assert_eq!(f.max_level_hint(), Some(LevelFilter::ERROR));
    }

    #[test]
    fn env_filter_level_hint_survives() {
        // EnvFilter 的 max_level_hint 与 LevelFilter 对应（上述断言的前提）
        let f = EnvFilter::new("debug");
        assert_eq!(f.max_level_hint(), Some(LevelFilter::DEBUG));
    }

    #[test]
    fn file_priority_cli_over_env() {
        // 环境变量注入与读取用本测试的原子锁串行化，避免并行测试互相污染
        static LOCK: AtomicUsize = AtomicUsize::new(0);
        while LOCK.swap(1, Ordering::Acquire) != 0 {
            std::hint::spin_loop();
        }
        std::env::set_var(LOG_FILE_ENV, "/tmp/env-log");
        // CLI 显式 > env
        assert_eq!(
            select_log_file(Some(PathBuf::from("/tmp/cli-log"))),
            Some(PathBuf::from("/tmp/cli-log"))
        );
        // env > 默认
        assert_eq!(select_log_file(None), Some(PathBuf::from("/tmp/env-log")));
        std::env::remove_var(LOG_FILE_ENV);
        // 默认无
        assert_eq!(select_log_file(None), None);
        LOCK.store(0, Ordering::Release);
    }
}
