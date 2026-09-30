//! ts2021 入网探针（TSL-04，e2e lrill 侧入口）：
//! TLS → GET /key → controlhttp 升级 → Noise IK → register（auth key）
//! → /machine/map 长轮询拉 netmap → boringtun WG 会话 ping 唯一 peer
//! → 成功打印 PEER_PING_OK；可选经 exit peer 转发 ping 非本网地址（EXIT_PING_OK，
//! TSL-06）；随后常驻应答对端 ICMP echo（供反向 ping 断言）。
//!
//! 用法：
//!   ts2021-probe --host <host:port> --authkey <key> --ca <ca.pem>
//!                [--hostname <name>] [--state <machine.key>] [--ping-peer]
//!                [--ping-exit <ipv4>]（经 peer 转发，peer 需为已审批 exit node）

use landscape_rill_ts2021::controlhttp;
use landscape_rill_ts2021::tailcfg::{RegisterResponse, CURRENT_CAP_VERSION};
use landscape_rill_ts2021::ts2021;
use landscape_rill_ts2021::wg::{icmp_echo_request, parse_icmp_echo, IcmpEcho, WgTunnel};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, ServerName};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::Mutex as AsyncMutex;
use tokio_rustls::client::TlsStream;
type Derp = landscape_rill_ts2021::derp::DerpClient<TlsStream<tokio::net::TcpStream>>;

const PING_IDENT: u16 = 0x5211;
const EXIT_PING_IDENT: u16 = 0x5212;
const PING_ATTEMPTS: u32 = 45;
const MAP_RETRIES: u32 = 30;

fn arg_value(name: &str) -> String {
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == name {
            return args.next().unwrap_or_else(|| panic!("{name} 缺值"));
        }
    }
    panic!("缺少参数 {name}");
}

fn arg_opt(name: &str) -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

/// 无值标志（如 --ping-peer）
fn arg_flag(name: &str) -> bool {
    std::env::args().any(|a| a == name)
}

fn main() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    match rt.block_on(run()) {
        Ok(resp) => {
            println!("{}", serde_json::to_string_pretty(&resp).expect("json"));
            if resp.is_success() {
                std::process::exit(0);
            }
            eprintln!("注册被拒绝: {}", resp.error);
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("FAIL: {e}");
            std::process::exit(1);
        }
    }
}

async fn run() -> Result<RegisterResponse, Box<dyn std::error::Error + Send + Sync>> {
    let host = arg_value("--host");
    let authkey = arg_value("--authkey");
    let ca_path = arg_value("--ca");
    let hostname = arg_opt("--hostname").unwrap_or_else(|| "lrill-ts2021".to_owned());
    let ping_peer = arg_flag("--ping-peer");
    let ping_exit: Option<Ipv4Addr> = arg_opt("--ping-exit").and_then(|s| s.parse().ok());

    // TLS 信任锚：自签 CA（e2e 预生成；官方客户端无跳过校验开关，同 P0 语义）
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter(&ca_path)? {
        roots.add(cert?)?;
    }
    let tls_config = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let connector = tokio_rustls::TlsConnector::from(tls_config);

    let (hostname_label, _port) = host
        .rsplit_once(':')
        .map(|(h, p)| (h.to_owned(), p.to_owned()))
        .unwrap_or((host.clone(), "443".to_owned()));
    let server_name = ServerName::try_from(hostname_label.clone())?;

    // 连接 1：GET /key 预取服务端 Noise 公钥
    let tcp = tokio::net::TcpStream::connect(&host).await?;
    let control_key = controlhttp::fetch_control_key(
        connector.connect(server_name.clone(), tcp).await?,
        &host,
        CURRENT_CAP_VERSION,
    )
    .await?;

    // 连接 2：controlhttp 升级 + Noise IK + register
    // machine key 可持久（--state，重启身份稳定）；node key 每次新生成 = 轮换路径
    let machine_key = match arg_opt("--state") {
        Some(p) => {
            let path = std::path::PathBuf::from(p);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            ts2021::load_or_create_machine_key(&path)?
        }
        None => ts2021::generate_keypair()?.0,
    };
    let (node_priv, node_pub) = ts2021::generate_keypair()?;
    let (_disco_priv, disco_pub) = ts2021::generate_keypair()?;
    if std::env::var("LRILL_DEBUG").is_ok() {
        let boringtun_pub =
            *boringtun::x25519::PublicKey::from(&boringtun::x25519::StaticSecret::from(node_priv))
                .as_bytes();
        eprintln!(
            "[dbg] node_pub(reg)={} boringtun_pub={}",
            landscape_rill_ts2021::tailcfg::hex(&node_pub),
            landscape_rill_ts2021::tailcfg::hex(&boringtun_pub)
        );
    }
    let tcp = tokio::net::TcpStream::connect(&host).await?;
    let stream = controlhttp::upgrade(
        connector.connect(server_name, tcp).await?,
        &host,
        &machine_key,
        &control_key,
        CURRENT_CAP_VERSION,
    )
    .await?;
    let mut client = ts2021::connect(stream).await?;
    let resp = client
        .register(&node_pub, &authkey, &hostname, &host)
        .await?;
    println!("REGISTER_OK {}", resp.machine_authorized);

    if !ping_peer {
        return Ok(resp);
    }

    // 长轮询拉 netmap（对端未注册完成时重试）+ 取 DERPMap
    let mut peer = None;
    let mut self_v4 = None;
    let mut derp_node = None;
    for _ in 0..MAP_RETRIES {
        let map = client
            .map(&node_pub, &disco_pub, &hostname, &host, None)
            .await?;
        derp_node = map.derp_node();
        if let Some(p) = map.peers.as_ref().and_then(|ps| ps.first()) {
            if p.first_ipv4().is_some() {
                self_v4 = map.self_ipv4();
                peer = Some(p.clone());
                break;
            }
        }
        println!("netmap 无可用 peer，2s 后重试");
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
    let peer = peer.ok_or("netmap 迟迟无可用 peer")?;
    let self_v4: Ipv4Addr = self_v4.ok_or("netmap 缺本节点 v4 地址")?;
    let peer_key = peer.node_key()?;
    let target = peer.first_ipv4().expect("checked above");
    let derp_node = derp_node.ok_or("netmap 缺 DERPMap")?;
    println!(
        "WG_PEER {target} derp={}:{} region={}",
        derp_node.hostname, derp_node.port, derp_node.region_id
    );

    // DERP 连接（数据面 v1：DERP-only，REQ-021；node-c 的响应也经此返回）
    let derp_tcp =
        tokio::net::TcpStream::connect((derp_node.hostname.as_str(), derp_node.port)).await?;
    let derp_tls = connector
        .connect(ServerName::try_from(derp_node.hostname.clone())?, derp_tcp)
        .await?;
    let derp_host = format!("{}:{}", derp_node.hostname, derp_node.port);
    let derp = Arc::new(AsyncMutex::new(
        // DERP 客户端身份 = node key（tailscaled 同源：derp 按 node key 注册/路由）
        landscape_rill_ts2021::derp::DerpClient::connect(derp_tls, &derp_host, node_pub, node_priv)
            .await?,
    ));
    println!("DERP_CONNECTED {}", derp_host);

    // Lite 更新：上报 UDP 端点 + PreferredDERP（对端 netmap 获得 HomeDERP，反向可达）
    let udp = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    let probe_sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    probe_sock.connect(&host).await?;
    let local_ip = probe_sock.local_addr()?.ip();
    let endpoints = vec![format!("{local_ip}:{}", udp.local_addr()?.port())];
    client
        .map_endpoints_update(
            &node_pub,
            &disco_pub,
            &hostname,
            &host,
            &endpoints,
            Some(derp_node.region_id),
            &[],
        )
        .await?;

    // 对端直连端点（可选；DERP 为主路径）
    let peer_endpoint: Option<SocketAddr> = peer.endpoints.first().and_then(|e| e.parse().ok());
    ping_peer_flow(
        &node_priv,
        PeerFlow {
            peer_key,
            self_v4,
            target,
            peer_endpoint,
            exit_target: ping_exit,
        },
        derp,
        Arc::new(udp),
    )
    .await?;
    Ok(resp)
}

/// WG 会话参数（对端密钥/地址/端点 + exit 目标）
struct PeerFlow {
    peer_key: [u8; 32],
    self_v4: Ipv4Addr,
    target: Ipv4Addr,
    peer_endpoint: Option<SocketAddr>,
    exit_target: Option<Ipv4Addr>,
}

/// WG 会话（DERP + 直连 UDP 双路）：定时器驱动 + 收包（应答 echo request /
/// 匹配 echo reply），ping 通后可选经 exit peer 转发 ping 外部地址，随后常驻。
async fn ping_peer_flow(
    node_priv: &[u8; 32],
    flow: PeerFlow,
    derp: Arc<AsyncMutex<Derp>>,
    udp: Arc<tokio::net::UdpSocket>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let PeerFlow {
        peer_key,
        self_v4,
        target,
        peer_endpoint,
        exit_target,
    } = flow;
    let peer_key: &'static [u8; 32] = Box::leak(Box::new(peer_key));
    let tunn = Arc::new(Mutex::new(WgTunnel::new(node_priv, peer_key, 1)));
    let got_reply = Arc::new(AtomicBool::new(false));
    let got_exit = Arc::new(AtomicBool::new(false));
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();

    // 双路发送：直连 UDP（对端端点已知时）+ DERP
    async fn send_wg(
        udp: &tokio::net::UdpSocket,
        derp: &AsyncMutex<Derp>,
        peer_key: &[u8; 32],
        endpoint: Option<SocketAddr>,
        b: &[u8],
    ) {
        if let Some(ep) = endpoint {
            let _ = udp.send_to(b, ep).await;
        }
        let _ = derp.lock().await.send(peer_key, b).await;
    }

    // echo reply 按 ident 分派（直连 ping / exit 转发 ping）
    fn dispatch_reply(ident: u16, got_reply: &AtomicBool, got_exit: &AtomicBool) {
        match ident {
            PING_IDENT => got_reply.store(true, Ordering::SeqCst),
            EXIT_PING_IDENT => got_exit.store(true, Ordering::SeqCst),
            _ => {}
        }
    }

    // 发起握手（双路）
    let init = tunn.lock().unwrap().ensure_initiated();
    for b in &init {
        send_wg(&udp, &derp, peer_key, peer_endpoint, b).await;
    }

    // DERP 收发任务：排空发送队列 → boringtun 定时器 → 带超时收包（循环）。
    // 单所有权持有 derp，避免 recv 持锁跨 await 阻塞发送路径。
    let task_tunn = tunn.clone();
    let task_reply = got_reply.clone();
    let task_exit = got_exit.clone();
    let task_tx = tx.clone();
    let task_udp = udp.clone();
    tokio::spawn(async move {
        let udp = &*task_udp;
        loop {
            // 1. 冲待发队列（握手/重传/应答）
            while let Ok(b) = rx.try_recv() {
                send_wg(udp, &derp, peer_key, peer_endpoint, &b).await;
            }
            // 2. boringtun 定时器（握手重试/keepalive/rekey）
            let out = task_tunn.lock().unwrap().update_timers();
            for b in out {
                send_wg(udp, &derp, peer_key, peer_endpoint, &b).await;
            }
            // 3. 收包（1s 超时后回 1）
            let pkt = match tokio::time::timeout(
                std::time::Duration::from_secs(1),
                derp.lock().await.recv(),
            )
            .await
            {
                Ok(Ok(p)) => p,
                Ok(Err(e)) => {
                    eprintln!("[dbg] derp recv err: {e}");
                    return;
                }
                Err(_) => continue,
            };
            let outcome = task_tunn.lock().unwrap().decapsulate(None, &pkt.data);
            if std::env::var("LRILL_DEBUG").is_ok() {
                eprintln!(
                    "[dbg] derp pkt src={}.. to_send={} pt={:?}",
                    &landscape_rill_ts2021::tailcfg::hex(&pkt.source)[..12],
                    outcome.to_send.len(),
                    outcome.plaintext.as_ref().map(|p| p.len())
                );
            }
            for b in outcome.to_send {
                let _ = task_tx.send(b);
            }
            if let Some(packet) = outcome.plaintext {
                match parse_icmp_echo(&packet) {
                    IcmpEcho::Request { reply, .. } => {
                        let wg = task_tunn.lock().unwrap().encapsulate(&reply);
                        if std::env::var("LRILL_DEBUG").is_ok() {
                            eprintln!(
                                "[dbg] echo req {}B -> {} reply frame(s)",
                                reply.len(),
                                wg.len()
                            );
                        }
                        for b in wg {
                            let _ = task_tx.send(b);
                        }
                    }
                    IcmpEcho::Reply { ident, .. } => {
                        dispatch_reply(ident, &task_reply, &task_exit);
                    }
                    IcmpEcho::Other => {}
                }
            }
        }
    });

    // UDP 收包任务（直连路径）
    let udp_tunn = tunn.clone();
    let udp_reply = got_reply.clone();
    let udp_exit = got_exit.clone();
    let _udp_tx = tx.clone();
    let udp_sock = udp.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535 + 148];
        loop {
            let (n, src_addr) = match udp_sock.recv_from(&mut buf).await {
                Ok(x) => x,
                Err(_) => continue,
            };
            let outcome = udp_tunn.lock().unwrap().decapsulate(None, &buf[..n]);
            for b in outcome.to_send {
                let _ = udp_sock.send_to(&b, src_addr).await;
            }
            if let Some(packet) = outcome.plaintext {
                match parse_icmp_echo(&packet) {
                    IcmpEcho::Request { reply, .. } => {
                        let wg = udp_tunn.lock().unwrap().encapsulate(&reply);
                        for b in wg {
                            let _ = udp_sock.send_to(&b, src_addr).await;
                        }
                    }
                    IcmpEcho::Reply { ident, .. } => {
                        dispatch_reply(ident, &udp_reply, &udp_exit);
                    }
                    IcmpEcho::Other => {}
                }
            }
        }
    });

    // 周期发 echo request 直至对应 flag 置位（每次 10×200ms 观察窗）
    async fn ping_until(
        tunn: &Arc<Mutex<WgTunnel>>,
        tx: &tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        ident: u16,
        payload: &[u8],
        got: &AtomicBool,
    ) -> Result<u16, String> {
        for seq in 1..=PING_ATTEMPTS as u16 {
            let req = icmp_echo_request(src, dst, ident, seq, payload);
            for b in tunn.lock().unwrap().encapsulate(&req) {
                let _ = tx.send(b);
            }
            for _ in 0..10 {
                if got.load(Ordering::SeqCst) {
                    return Ok(seq);
                }
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
        }
        Err(format!("ping {dst} 超时（{PING_ATTEMPTS} 次尝试）"))
    }

    let seq = ping_until(
        &tunn,
        &tx,
        self_v4,
        target,
        PING_IDENT,
        b"lrill-ts2021",
        &got_reply,
    )
    .await
    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
    println!("PEER_PING_OK {target} seq={seq}");

    // exit 使用（TSL-06）：非本网目的经同一 peer 会话转发（peer = 已审批 exit node）
    if let Some(exit_dst) = exit_target {
        match ping_until(
            &tunn,
            &tx,
            self_v4,
            exit_dst,
            EXIT_PING_IDENT,
            b"lrill-exit",
            &got_exit,
        )
        .await
        {
            Ok(seq) => println!("EXIT_PING_OK {exit_dst} seq={seq}"),
            Err(_) => eprintln!("EXIT_PING_FAIL {exit_dst}"),
        }
    }

    // 常驻：应答对端反向 ping（entry 脚本断言 node-c ping 本节点）
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
    }
}
