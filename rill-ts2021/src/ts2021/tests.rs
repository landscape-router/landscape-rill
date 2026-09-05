//! ts2021 会话层测试：进程内对照服务端（字面量 HTTP 头 + noise 握手 + early payload
//! 分片 record + h2 server），全链路验证 controlhttp 升级 → ts2021 connect → register。

use super::{connect, generate_keypair};
use crate::base64;
use crate::controlbase::stream::NoiseStream;
use crate::controlbase::tests::{control_key_pub, TestServer};
use crate::controlhttp;
use crate::tailcfg::CURRENT_CAP_VERSION;
use bytes::Bytes;
use tokio::io::duplex;
use tokio::io::DuplexStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const HOST: &str = "headscale:8080";

async fn read_http_head(io: &mut DuplexStream) -> String {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        io.read_exact(&mut byte).await.unwrap();
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            return String::from_utf8_lossy(&head).into_owned();
        }
    }
}

/// 对照服务端：校验升级请求头 → noise 握手 → early payload（分 3 条 record，同 headscale
/// 三次 Write）→ h2 server 响应 /machine/register。返回解析出的 RegisterRequest JSON。
async fn serve_register(mut server_io: DuplexStream) -> serde_json::Value {
    let head = read_http_head(&mut server_io).await;
    assert!(head.starts_with("POST /ts2021 HTTP/1.1\r\n"));
    assert!(head.contains("Host: headscale:8080\r\n"));
    assert!(head.contains("Upgrade: tailscale-control-protocol\r\n"));
    assert!(head.contains("Connection: upgrade\r\n"));
    assert!(head.contains("Content-Length: 0\r\n"));
    let init_b64 = head
        .lines()
        .find_map(|l| l.strip_prefix("X-Tailscale-Handshake: "))
        .expect("handshake header");
    let init = base64::decode(init_b64).expect("base64 init");

    server_io
        .write_all(
            b"HTTP/1.1 101 Switching Protocols\r\n\
              Upgrade: tailscale-control-protocol\r\n\
              Connection: upgrade\r\n\r\n",
        )
        .await
        .unwrap();

    let mut s = TestServer::new();
    let resp = s.respond(&init).expect("noise handshake");
    server_io.write_all(&resp).await.unwrap();
    let (server_session, _) = s.finish();
    // 服务端同样经 NoiseStream（h2 字节必须过 Noise）
    let mut server_stream = NoiseStream::new(server_io, server_session);

    let early_json = br#"{"nodeKeyChallenge":"challengekey:e2e"}"#;
    // 三次 Write = 三条 record，与 headscale 服务端一致；客户端按明文流重组
    server_stream
        .write_all(&super::EARLY_PAYLOAD_MAGIC)
        .await
        .unwrap();
    server_stream
        .write_all(&(early_json.len() as u32).to_be_bytes())
        .await
        .unwrap();
    server_stream.write_all(early_json).await.unwrap();

    let mut conn = h2::server::handshake(server_stream).await.unwrap();
    let (request, mut respond) = conn.accept().await.unwrap().unwrap();
    assert_eq!(request.method(), http::Method::POST);
    assert_eq!(request.uri().path(), "/machine/register");
    let mut body = request.into_body();
    let mut req_body = Vec::new();
    while let Some(chunk) = body.data().await {
        req_body.extend_from_slice(&chunk.unwrap());
    }
    let reg: serde_json::Value = serde_json::from_slice(&req_body).unwrap();

    let response = http::Response::builder().status(200).body(()).unwrap();
    let mut send = respond.send_response(response, false).unwrap();
    send.send_data(
        Bytes::from_static(
            br#"{"User":{"id":"1"},"Login":{},"NodeKeyExpired":false,"MachineAuthorized":true,"AuthURL":"","Error":""}"#,
        ),
        true,
    )
    .unwrap();
    // 继续驱动连接把响应刷出到 NoiseStream（h2 出站数据仅在 poll 时写出）；
    // 客户端收到响应后关连接，此处随之结束
    let _ = conn.accept().await;
    reg
}

#[tokio::test]
async fn full_register_flow() {
    let (client_io, server_io) = duplex(256 * 1024);
    let server = tokio::spawn(serve_register(server_io));

    let (machine_priv, _) = generate_keypair().unwrap();
    let (_, node_pub) = generate_keypair().unwrap();
    let control_key = control_key_pub();

    let stream = controlhttp::upgrade(
        client_io,
        HOST,
        &machine_priv,
        &control_key,
        CURRENT_CAP_VERSION,
    )
    .await
    .unwrap();
    let mut client = connect(stream).await.unwrap();
    assert!(!client.early_noise.node_key_challenge.is_empty());

    let resp = client
        .register(&node_pub, "lrk-test-key", "lrill-e2e", HOST)
        .await
        .unwrap();
    assert!(resp.is_success(), "error={}", resp.error);
    assert!(resp.machine_authorized);

    // 先关客户端（驱动终止 → 流 EOF），服务端的 accept 驱动才会结束
    drop(client);
    let reg = server.await.unwrap();
    assert_eq!(reg["Version"], CURRENT_CAP_VERSION);
    assert_eq!(reg["Auth"]["AuthKey"], "lrk-test-key");
    assert_eq!(reg["Hostinfo"]["Hostname"], "lrill-e2e");
    let node_key = reg["NodeKey"].as_str().unwrap();
    assert!(node_key.starts_with("nodekey:") && node_key.len() == "nodekey:".len() + 64);
}

#[tokio::test]
async fn upgrade_rejects_non_101() {
    let (client_io, mut server_io) = duplex(1024);
    let server = tokio::spawn(async move {
        let head = read_http_head(&mut server_io).await;
        assert!(head.contains("X-Tailscale-Handshake: "));
        server_io
            .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
    });
    let (machine_priv, _) = generate_keypair().unwrap();
    let err = controlhttp::upgrade(
        client_io,
        HOST,
        &machine_priv,
        &control_key_pub(),
        CURRENT_CAP_VERSION,
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("400"), "err={err}");
    server.await.unwrap();
}
