//! ts2021 注册一致性探针（TSL-04 控制面验收用，e2e 场景的 lrill 侧入口）：
//! TLS → GET /key 取服务端 Noise 公钥 → controlhttp 升级（Noise IK）→ early payload
//! → HTTP/2 → /machine/register。成功（Error 为空且无 AuthURL）打印响应 JSON 并退出 0。
//!
//! 用法：
//!   ts2021-register --host <host:port> --authkey <key> --ca <ca.pem> [--hostname <name>]

use landscape_rill_ts2021::controlhttp;
use landscape_rill_ts2021::tailcfg::{RegisterResponse, CURRENT_CAP_VERSION};
use landscape_rill_ts2021::ts2021;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, ServerName};
use std::sync::Arc;

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
    let (machine_key, _) = ts2021::generate_keypair()?;
    let (_, node_key) = ts2021::generate_keypair()?;
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
        .register(&node_key, &authkey, &hostname, &host)
        .await?;
    Ok(resp)
}
