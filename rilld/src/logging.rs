//! daemon 日志初始化（LOGGING §2/§4）
//!
//! 边界：仅 `lrill run`（daemon）初始化 subscriber；CLI 子命令直接 stdout/stderr，
//! 不进日志框架（LOGGING §1）——auth key 不落日志红线因此是结构性的（LOGGING §6）。
//!
//! 存储：默认 stderr（systemd 由 journald 捕获、容器由 docker log driver 捕获）；
//! `--log-file <path>` 追加 tracing-appender 按天轮转文件（保留 7 个，容量/轮转是框架职责）。
//! 高频事件不逐条输出：调用点用 rill-core `RateCounter` 计数，周期摘要打印（LOGGING §5）。

use std::io;
use std::path::Path;

use tracing_subscriber::prelude::*;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer, Registry};

/// 初始化 daemon 日志（仅 `lrill run` 调用；LOGGING §2/§4）
pub fn init_logging(log_file: Option<&Path>) -> Result<(), String> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    // 默认 stderr（systemd/journald、容器/docker log driver 捕获）；--log-file 追加文件
    let fmt = tracing_subscriber::fmt::layer().with_ansi(false);
    let fmt: Box<dyn Layer<Registry> + Send + Sync> = match log_file {
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
