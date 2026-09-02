//! 只读状态端点 HTTP 层（REQ-051/CONTROL_PLANE §3.14）：
//! axum 薄路由 + Bearer 认证中间件 + TLS accept 循环。
//! 查询逻辑在 rill-coord::status::StatusView（I/O-free 快照，单测覆盖）。

use crate::BoxResult;
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use axum::Router;
use landscape_rill_coord::status::{CoordRuntimeMeta, PasswordHash, StatusView};
use landscape_rill_core::rate::SourceRateLimiter;
use landscape_rill_mesh::control::server_tls_acceptor;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, RwLock};
use tracing::{info, warn};

/// 认证失败限速（§3.14：按源限速，超限 429；成功不限）——
/// 与 §3.13 回显同值：无认证面的响应必须有上界
const AUTH_FAIL_RATE_PER_SEC: f64 = 5.0;
const AUTH_FAIL_CAPACITY: u32 = 10;
/// 重载历史截尾长度
const RELOAD_LOG_CAP: usize = 20;

pub struct StatusState {
    pub server: Arc<Mutex<landscape_rill_mesh::control::CoordinatorServer>>,
    pub control_addr: String,
    pub status_addr: String,
    pub storage_path: Option<String>,
    pub started_at_unix: u64,
    /// 管理密码哈希（SIGHUP 轮换写入口）
    pub auth: RwLock<PasswordHash>,
    /// 认证失败按源限速
    pub auth_failures: Mutex<SourceRateLimiter>,
    /// SIGHUP 重载结果历史（§3.14 内容组 5）
    pub reload_log: Mutex<Vec<String>>,
}

impl StatusState {
    pub fn new(
        server: Arc<Mutex<landscape_rill_mesh::control::CoordinatorServer>>,
        control_addr: String,
        status_addr: String,
        storage_path: Option<String>,
        password_hash: PasswordHash,
    ) -> Self {
        Self {
            server,
            control_addr,
            status_addr,
            storage_path,
            started_at_unix: now_unix(),
            auth: RwLock::new(password_hash),
            auth_failures: Mutex::new(SourceRateLimiter::new(
                AUTH_FAIL_RATE_PER_SEC,
                AUTH_FAIL_CAPACITY,
            )),
            reload_log: Mutex::new(Vec::new()),
        }
    }

    /// SIGHUP 密码轮换（ADM-03 同机制：热更新不重启，旧密码即刻 401）
    pub async fn rotate_password(&self, new_hash: PasswordHash) {
        *self.auth.write().await = new_hash;
        info!("[status] password rotated (SIGHUP)");
    }

    /// 重载结果入历史（成功/失败都记录，REQ-051）
    pub async fn note_reload(&self, ok: bool, detail: String) {
        let mut log = self.reload_log.lock().await;
        log.push(format!("{} {}", if ok { "ok" } else { "failed" }, detail));
        let len = log.len();
        if len > RELOAD_LOG_CAP {
            log.drain(..len - RELOAD_LOG_CAP);
        }
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 状态端点任务：TLS accept 循环（明文 HTTP 在 TLS 握手层被拒，§3.14 传输）。
/// 每连接注入对端地址扩展（认证失败按源限速的源标识）
pub async fn run_status_server(
    listener: TcpListener,
    cert_pem: Vec<u8>,
    key_pem: Vec<u8>,
    state: Arc<StatusState>,
) -> BoxResult<()> {
    let acceptor = server_tls_acceptor(&cert_pem, &key_pem)?;
    let router = Router::new()
        .route("/status", get(status_handler))
        .with_state(state);
    info!("[status] endpoint listening on {}", listener.local_addr()?);
    loop {
        let (tcp, peer) = listener.accept().await?;
        let Ok(tls) = acceptor.clone().accept(tcp).await else {
            warn!("[status] tls handshake failed (plaintext or bad client)");
            continue;
        };
        let svc = hyper_util::service::TowerToHyperService::new(
            router.clone().layer(axum::Extension(peer)),
        );
        tokio::spawn(async move {
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(hyper_util::rt::TokioIo::new(tls), svc)
                .await;
        });
    }
}

async fn status_handler(
    State(state): State<Arc<StatusState>>,
    Extension(peer): Extension<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    // Bearer 提取（常数时间比较在 PasswordHash::verify 内）
    let bearer = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let supplied = match bearer {
        Some(p) => p.to_string(),
        None => return unauthorized(&state, peer).await,
    };
    let hash = state.auth.read().await.clone();
    if !hash.verify(&supplied) {
        return unauthorized(&state, peer).await;
    }
    // 成功不限速；快照在 coord 锁内构建（I/O-free，微秒级）
    let guard = state.server.lock().await;
    let meta = CoordRuntimeMeta {
        control_addr: state.control_addr.clone(),
        status_addr: Some(state.status_addr.clone()),
        storage_path: state.storage_path.clone(),
        started_at_unix: state.started_at_unix,
        now_unix: now_unix(),
        reload_log: state.reload_log.lock().await.clone(),
    };
    let snap = StatusView::snapshot(&guard.coordinator, &meta);
    Json(snap).into_response()
}

/// 认证失败路径：同源高频 → 429，否则 401（§3.14）
async fn unauthorized(state: &StatusState, peer: SocketAddr) -> Response {
    let allow = state.auth_failures.lock().await.allow(peer.ip());
    if !allow {
        warn!("[status] auth rate limited: {}", peer.ip());
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    StatusCode::UNAUTHORIZED.into_response()
}

/// 启动入口（由 coord_run 调用）：bind + spawn；配置已 validate 过（fail-closed 在 parse 层）
pub async fn spawn_status_server(
    config: &landscape_rill_coord::config::StatusConfig,
    cert_pem: Vec<u8>,
    key_pem: Vec<u8>,
    state: Arc<StatusState>,
) -> BoxResult<()> {
    let addr: SocketAddr = config.listen_addr.parse().expect("validated");
    let listener = TcpListener::bind(addr).await?;
    tokio::spawn(async move {
        if let Err(e) = run_status_server(listener, cert_pem, key_pem, state).await {
            warn!("[status] endpoint stopped: {}", e);
        }
    });
    Ok(())
}
