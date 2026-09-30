//! ts2021 服务端控制面（REQ-068，TS2021_LEG §4）：Noise 流上 HTTP/2 服务，
//! 路由 /machine/register（auth key 准入 + 幂等注册）与 /machine/map
//! （Lite 端点更新回 200 空；Stream=true 长轮询持有 + 全量初始帧 +
//! 增量推送 PeersChanged/PeersRemoved + keepalive；Compress="zstd" 时
//! 帧体 zstd 封装——官方客户端严格解码，无明文透传）。

use super::netmap;
use super::registry::{Event, NodeEntry};
use super::Ts2021Server;
use bytes::Bytes;
use std::future::poll_fn;
use std::io;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::broadcast::error::RecvError;
use tokio::time::Duration;
use tracing::{info, warn};

/// map 长轮询 keepalive 周期（headscale 0.29 同量级；客户端跳过无 peer 帧）
const KEEPALIVE_PERIOD: Duration = Duration::from_secs(60);
const MAX_REQUEST_BODY: usize = 64 * 1024;

/// Noise 升级完成后的控制面服务：h2 accept 循环，每请求独立任务——
/// 长轮询流阻塞单请求不影响同连接后续请求（客户端 Lite 更新与长轮询并发复用连接）
pub async fn serve_control<IO>(
    stream: crate::controlbase::NoiseStream<IO>,
    server: Arc<Ts2021Server>,
    machine: [u8; 32],
) -> io::Result<()>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut conn = h2::server::handshake(stream)
        .await
        .map_err(io::Error::other)?;
    while let Some(Ok((request, respond))) = conn.accept().await {
        let server = server.clone();
        tokio::spawn(async move {
            let mut respond = respond;
            let path = request.uri().path().to_owned();
            match path.as_str() {
                "/machine/register" => handle_register(request, respond, &server, machine).await,
                "/machine/map" => handle_map(request, respond, &server, machine).await,
                _ => {
                    let _ = respond.send_response(not_found(), true);
                }
            }
        });
    }
    Ok(())
}

fn not_found() -> http::Response<()> {
    http::Response::builder()
        .status(404)
        .body(())
        .expect("static response builder")
}

fn empty_response(status: u16) -> http::Response<()> {
    http::Response::builder()
        .status(status)
        .body(())
        .expect("static response builder")
}

fn json_response(status: u16) -> http::Response<()> {
    http::Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(())
        .expect("static response builder")
}

/// 单发 JSON 响应（send_response 只承载头且不得置 end_of_stream，
/// 否则流即关闭、send_data 落空 → 客户端拿到空 body）
async fn respond_json(respond: &mut h2::server::SendResponse<Bytes>, status: u16, body: Vec<u8>) {
    if let Ok(mut send) = respond.send_response(json_response(status), false) {
        let _ = send.send_data(Bytes::from(body), true);
    }
}

async fn collect_body(mut body: h2::RecvStream) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(io::Error::other)?;
        let n = chunk.len();
        out.extend_from_slice(&chunk);
        body.flow_control()
            .release_capacity(n)
            .map_err(io::Error::other)?;
        if out.len() > MAX_REQUEST_BODY {
            return Err(io::Error::other("request body too large"));
        }
    }
    Ok(out)
}

async fn handle_register(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    server: &Arc<Ts2021Server>,
    machine: [u8; 32],
) {
    let payload = match collect_body(request.into_body()).await {
        Ok(p) => p,
        Err(e) => {
            warn!("[ts2021-server] register body read failed: {e}");
            let _ = respond.send_response(empty_response(400), true);
            return;
        }
    };
    let v: serde_json::Value = match serde_json::from_slice(&payload) {
        Ok(v) => v,
        Err(_) => {
            respond_json(
                &mut respond,
                200,
                netmap::register_response_err("malformed RegisterRequest"),
            )
            .await;
            return;
        }
    };
    // 200 + Error 载荷（两类客户端都按 Error 字段判定；HTTP 错误码只在传输层异常用）
    let respond_err = |respond: &mut h2::server::SendResponse<Bytes>, msg: &str| {
        // 错误响应体小（单帧），send_data 不经容量管理（首帧窗口必然充足）
        if let Ok(mut send) = respond.send_response(json_response(200), false) {
            let _ = send.send_data(Bytes::from(netmap::register_response_err(msg)), true);
        }
    };
    let Some(node_key) = v
        .pointer("/NodeKey")
        .and_then(|s| s.as_str())
        .and_then(|s| crate::tailcfg::parse_node_public(s).ok())
    else {
        respond_err(&mut respond, "invalid NodeKey");
        return;
    };
    let auth_key = v
        .pointer("/Auth/AuthKey")
        .and_then(|s| s.as_str())
        .unwrap_or("");
    let hostname = v
        .pointer("/Hostinfo/Hostname")
        .and_then(|s| s.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("unnamed")
        .to_owned();
    // 先取结果再 match：scrutinee 临时 MutexGuard 不能跨 match 臂的 await 存活
    let result = server
        .registry
        .lock()
        .unwrap()
        .register(machine, node_key, &hostname, auth_key);
    match result {
        Ok(_nid) => {
            respond_json(&mut respond, 200, netmap::register_response_ok(&server.ctx)).await;
        }
        Err(e) => {
            info!("[ts2021-server] register rejected: {e}");
            respond_err(&mut respond, &e.to_string());
        }
    }
}

struct MapRequest {
    node_key: [u8; 32],
    disco_key: Option<[u8; 32]>,
    endpoints: Vec<String>,
    routable_ips: Vec<String>,
    preferred_derp: Option<u16>,
    stream: bool,
    /// Compress="zstd"（官方客户端 1.102 起无条件携带：帧体严格 zstd 解码）
    compress: bool,
}

fn parse_map_request(body: &[u8]) -> Option<MapRequest> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    let node_key = crate::tailcfg::parse_node_public(v.get("NodeKey")?.as_str()?).ok()?;
    let disco_key = v
        .get("DiscoKey")
        .and_then(|s| s.as_str())
        .and_then(|s| crate::tailcfg::parse_disco_public(s).ok());
    let strings = |ptr: &str| {
        v.pointer(ptr)
            .and_then(|e| e.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|s| s.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    };
    let preferred_derp = v
        .pointer("/Hostinfo/NetInfo/PreferredDERP")
        .and_then(|d| d.as_u64())
        .and_then(|d| u16::try_from(d).ok());
    Some(MapRequest {
        node_key,
        disco_key,
        endpoints: strings("/Endpoints"),
        routable_ips: strings("/Hostinfo/RoutableIPs"),
        preferred_derp,
        // Stream=false + OmitPeers=true = Lite；两者都 false（headscale 0.29 不回 body）
        stream: v.get("Stream").and_then(|b| b.as_bool()).unwrap_or(false),
        compress: v.get("Compress").and_then(|s| s.as_str()) == Some("zstd"),
    })
}

async fn handle_map(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    server: &Arc<Ts2021Server>,
    machine: [u8; 32],
) {
    let payload = match collect_body(request.into_body()).await {
        Ok(p) => p,
        Err(e) => {
            warn!("[ts2021-server] map body read failed: {e}");
            let _ = respond.send_response(empty_response(400), true);
            return;
        }
    };
    let Some(m) = parse_map_request(&payload) else {
        let _ = respond.send_response(empty_response(400), true);
        return;
    };
    // 身份核验：MapRequest 的 node key 必须属于本连接机器（防跨机器冒用）。
    // 服务端重启后注册表为空（v1 内存态）→ 401，客户端重注册自愈
    let nid = {
        let reg = server.registry.lock().unwrap();
        reg.node_by_key(&m.node_key)
            .filter(|nid| reg.get(*nid).is_some_and(|e| e.machine == machine))
    };
    let Some(nid) = nid else {
        tracing::debug!("[ts2021-server] map for unknown node key → 401 (client re-registers)");
        let _ = respond.send_response(empty_response(401), true);
        return;
    };
    server.registry.lock().unwrap().apply_map_update(
        nid,
        m.disco_key,
        m.endpoints,
        m.routable_ips,
        m.preferred_derp,
    );
    if !m.stream {
        // Lite 更新 / 无流请求：headscale 语义 = 200 空 body
        let _ = respond.send_response(empty_response(200), true);
        return;
    }
    // Stream=true：长轮询持有（同流推送后续帧）
    let response = empty_response(200);
    let mut send = match respond.send_response(response, false) {
        Ok(s) => s,
        Err(_) => return,
    };
    let _ = serve_long_poll(&mut send, server, nid, m.compress).await;
    // 发送失败/流断开 = 客户端离线：标记并广播（在线状态推导自流在场，headscale 同源）
    server.registry.lock().unwrap().mark_online(nid, false);
}

/// 长轮询流主体：初始全量帧 → 事件增量帧 + 周期 keepalive
async fn serve_long_poll(
    send: &mut h2::SendStream<Bytes>,
    server: &Arc<Ts2021Server>,
    nid: i64,
    compress: bool,
) -> io::Result<()> {
    let initial = {
        let mut reg = server.registry.lock().unwrap();
        let self_entry = reg.get(nid).expect("registered");
        let peers: Vec<NodeEntry> = reg
            .snapshot()
            .into_iter()
            .filter(|e| e.nid != nid)
            .collect();
        reg.mark_online(nid, true);
        netmap::full_frame(&self_entry, &peers, &server.ctx, unix_now(), compress)
    };
    send_frame(send, initial).await?;
    info!("[ts2021-server] map stream open: nid={nid} compress={compress}");
    let mut events = server.registry.lock().unwrap().subscribe();
    let mut keepalive = tokio::time::interval(KEEPALIVE_PERIOD);
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            ev = events.recv() => match ev {
                Ok(Event::Delta { changed, removed }) => {
                    // 接收者自身条目不出现在其增量帧（self 更新对自身无意义）
                    let changed: Vec<i64> = changed.into_iter().filter(|c| *c != nid).collect();
                    if changed.is_empty() && removed.is_empty() {
                        continue;
                    }
                    let entries: Vec<NodeEntry> = {
                        let reg = server.registry.lock().unwrap();
                        changed.iter().filter_map(|c| reg.get(*c)).collect()
                    };
                    send_frame(send, netmap::delta_frame(&entries, &removed, &server.ctx, unix_now(), compress))
                        .await?;
                }
                Err(RecvError::Lagged(n)) => {
                    // 事件滞后（消费太慢）：全量帧自愈（增量合并基线重建）
                    warn!("[ts2021-server] map stream lagged by {n}, resending full netmap");
                    let (self_entry, peers) = snapshot_except(server, nid);
                    send_frame(send, netmap::full_frame(&self_entry, &peers, &server.ctx, unix_now(), compress))
                        .await?;
                }
                Err(RecvError::Closed) => return Ok(()),
            },
            _ = keepalive.tick() => {
                send_frame(send, netmap::keepalive_frame(unix_now(), compress)).await?;
            }
        }
    }
}

fn snapshot_except(server: &Arc<Ts2021Server>, nid: i64) -> (NodeEntry, Vec<NodeEntry>) {
    let reg = server.registry.lock().unwrap();
    let self_entry = reg.get(nid).expect("registered");
    let peers = reg
        .snapshot()
        .into_iter()
        .filter(|e| e.nid != nid)
        .collect();
    (self_entry, peers)
}

/// 帧写入（h2 流控容量感知：reserve → poll_capacity → send_data）
async fn send_frame(send: &mut h2::SendStream<Bytes>, frame: Vec<u8>) -> io::Result<()> {
    let mut buf = Bytes::from(frame);
    while !buf.is_empty() {
        send.reserve_capacity(buf.len());
        let n = poll_fn(|cx| send.poll_capacity(cx))
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "h2 stream closed"))?
            .map_err(io::Error::other)?
            .min(buf.len());
        let chunk = buf.split_to(n);
        send.send_data(chunk, false).map_err(io::Error::other)?;
    }
    Ok(())
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
