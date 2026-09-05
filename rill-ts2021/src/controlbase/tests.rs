//! controlbase 单测：帧布局字节级断言 + 独立服务端实现对照（防同源编解码偏差互相掩盖）
//! + 会话语义（chunking/毒化/一次性）+ tokio conn 胶水。

use super::error::ControlbaseError;
use super::handshake::{protocol_version_prologue, ClientHandshake, Session, NOISE_PATTERN};
use super::stream::NoiseStream;
use super::wire;
use snow::{Builder, HandshakeState};
use tokio::io::duplex;
use tokio::io::DuplexStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub(crate) const MACHINE_KEY: [u8; 32] = [7u8; 32];
const CONTROL_KEY_PRIV: [u8; 32] = [9u8; 32];

pub(crate) fn control_key_pub() -> [u8; 32] {
    use x25519_dalek::{PublicKey, StaticSecret};
    let secret = StaticSecret::from(CONTROL_KEY_PRIV);
    *PublicKey::from(&secret).as_bytes()
}

/// 测试用服务端：帧组装用字面量字节（不经 wire.rs），独立对照客户端解析。
/// 版本取自 initiation 帧头明文混入 prologue（tailscale Server 语义）。
pub(crate) struct TestServer {
    state: Option<HandshakeState>,
}

impl TestServer {
    pub(crate) fn new() -> Self {
        Self { state: None }
    }

    pub(crate) fn respond(&mut self, init_frame: &[u8]) -> Result<Vec<u8>, ControlbaseError> {
        assert_eq!(init_frame.len(), 101);
        let version = u16::from_be_bytes([init_frame[0], init_frame[1]]);
        assert_eq!(init_frame[2], 1);
        assert_eq!(&init_frame[3..5], &[0u8, 96]);
        let mut state = Builder::new(NOISE_PATTERN.parse().unwrap())
            .prologue(&protocol_version_prologue(version))
            .unwrap()
            .local_private_key(&CONTROL_KEY_PRIV)
            .unwrap()
            .build_responder()
            .unwrap();
        state
            .read_message(&init_frame[5..], &mut [])
            .map_err(ControlbaseError::Noise)?;
        let mut body = [0u8; 48];
        let n = state
            .write_message(&[], &mut body)
            .map_err(ControlbaseError::Noise)?;
        assert_eq!(n, 48);
        self.state = Some(state);
        let mut resp = Vec::with_capacity(51);
        resp.push(2u8);
        resp.extend_from_slice(&48u16.to_be_bytes());
        resp.extend_from_slice(&body);
        Ok(resp)
    }

    /// 服务端朝向会话（tx = k2，rx = k1）+ 握手哈希（进传输态前取出）
    pub(crate) fn finish(self) -> (Session, [u8; 32]) {
        let mut hash = [0u8; 32];
        let mut state = self.state.expect("handshake not completed");
        hash.copy_from_slice(state.get_handshake_hash());
        let (k1, k2) = state.dangerously_get_raw_split();
        (Session::from_raw_keys(k2, k1, 1), hash)
    }
}

fn client_session(control_key: &[u8; 32], version: u16) -> (ClientHandshake, [u8; 101]) {
    let mut hs = ClientHandshake::new(&MACHINE_KEY, control_key, version).unwrap();
    let init = hs.write_initiation().unwrap();
    (hs, init)
}

fn established_session() -> (Session, Session) {
    let (mut hs, init) = client_session(&control_key_pub(), 1);
    let mut server = TestServer::new();
    let resp = server.respond(&init).unwrap();
    (hs.complete(&resp).unwrap(), server.finish().0)
}

#[test]
fn prologue_format() {
    assert_eq!(
        protocol_version_prologue(1),
        b"Tailscale Control Protocol v1"
    );
    assert_eq!(
        protocol_version_prologue(65535),
        b"Tailscale Control Protocol v65535"
    );
}

#[test]
fn initiation_frame_layout() {
    let (_, init) = client_session(&control_key_pub(), 1);
    assert_eq!(init.len(), 101);
    assert_eq!(&init[..5], &[0u8, 1, 1, 0, 96]);
}

#[test]
fn handshake_roundtrip_and_directions() {
    let ck = control_key_pub();
    let (mut hs, init) = client_session(&ck, 1);
    let mut server = TestServer::new();
    let resp = server.respond(&init).unwrap();

    let mut client = hs.complete(&resp).unwrap();
    assert_eq!(client.peer(), &ck);
    assert_eq!(client.protocol_version(), 1);
    let (mut server_t, server_hash) = server.finish();

    // 握手哈希两侧一致（上层 early payload 绑定用）
    assert_eq!(client.handshake_hash(), &server_hash);

    // 方向：client→server 走 c1，server→client 走 c2
    let c2s = client.seal(b"client>server").unwrap();
    assert_eq!(server_t.open(&c2s).unwrap(), b"client>server");
    let s2c = server_t.seal(b"server>client").unwrap();
    assert_eq!(client.open(&s2c).unwrap(), b"server>client");
}

#[test]
fn handshake_binds_declared_version() {
    // 版本绑定语义：prologue 用帧头明文版本（tailscale Server 同源）。
    // 篡改帧头版本字节 → 服务端按被篡改版本混入 prologue → msg1 tag 校验失败。
    let (_, mut init) = client_session(&control_key_pub(), 1);
    init[1] = 2; // v1 → v2（服务端将按 v2 建 prologue）
    let mut server = TestServer::new();
    assert!(server.respond(&init).is_err());
}

#[test]
fn handshake_rejects_tampered_initiation() {
    let (_, mut init) = client_session(&control_key_pub(), 1);
    init[100] ^= 0x01; // 翻转尾 tag 一字节
    let mut server = TestServer::new();
    assert!(server.respond(&init).is_err());
}

#[test]
fn complete_rejects_server_error_frame() {
    let (mut hs, _) = client_session(&control_key_pub(), 1);
    let err_frame = [3u8, 0, 4, b'n', b'o', b'p', b'e'];
    match hs.complete(&err_frame) {
        Err(ControlbaseError::ServerError(msg)) => assert_eq!(msg, "nope"),
        other => panic!("want ServerError, got {other:?}"),
    }
}

#[test]
fn complete_rejects_bad_response() {
    // 类型未知
    let (mut hs, _) = client_session(&control_key_pub(), 1);
    assert!(matches!(
        hs.complete(&[9u8, 0, 0]),
        Err(ControlbaseError::MalformedFrame)
    ));

    // 类型对但长度不符（response 必须恰 48B 体）
    let (mut hs, _) = client_session(&control_key_pub(), 1);
    assert!(matches!(
        hs.complete(&[2u8, 0, 47]),
        Err(ControlbaseError::MalformedFrame)
    ));
}

#[test]
fn handshake_wrong_step() {
    // 未发 initiation 就 complete
    let mut hs = ClientHandshake::new(&MACHINE_KEY, &control_key_pub(), 1).unwrap();
    assert!(matches!(
        hs.complete(&[2u8, 0, 48]),
        Err(ControlbaseError::WrongStep)
    ));

    // 完成后不可复用
    let (mut hs, init) = client_session(&control_key_pub(), 1);
    let mut server = TestServer::new();
    let resp = server.respond(&init).unwrap();
    hs.complete(&resp).unwrap();
    assert!(matches!(
        hs.complete(&resp),
        Err(ControlbaseError::WrongStep)
    ));
}

#[test]
fn write_initiation_is_one_shot() {
    let mut hs = ClientHandshake::new(&MACHINE_KEY, &control_key_pub(), 1).unwrap();
    hs.write_initiation().unwrap();
    assert!(matches!(
        hs.write_initiation(),
        Err(ControlbaseError::WrongStep)
    ));
}

#[test]
fn record_chunking_boundaries() {
    for (pt_len, want_frames) in [(4077usize, 1usize), (4078, 2), (10_000, 3)] {
        let (mut client, mut server_t) = established_session();
        let plaintext: Vec<u8> = (0..pt_len).map(|i| i as u8).collect();
        let sealed = client.seal(&plaintext).unwrap();

        // 帧边界逐一校验后重组
        let mut got = Vec::new();
        let mut rest = &sealed[..];
        let mut frames = 0;
        while !rest.is_empty() {
            let len = wire::parse_record_header(rest).unwrap();
            got.extend_from_slice(&server_t.open(&rest[..3 + len]).unwrap());
            rest = &rest[3 + len..];
            frames += 1;
        }
        assert_eq!(frames, want_frames, "pt_len={pt_len}");
        assert_eq!(got, plaintext, "pt_len={pt_len}");
    }
}

#[test]
fn seal_empty_writes_nothing_open_accepts_zero_length() {
    // 发送侧：空明文不产生字节（tailscale Write 同语义）
    let (mut client, mut server_t) = established_session();
    assert!(client.seal(&[]).unwrap().is_empty());

    // 接收侧：零载荷 record 合法（tailscale Read 循环跳过）
    let zero = server_t.seal_empty_record();
    assert_eq!(zero.len(), 3 + 16);
    assert!(client.open(&zero).unwrap().is_empty());
}

#[test]
fn open_rejects_oversize_then_poisons() {
    let (mut client, mut server_t) = established_session();
    let oversized = [4u8, 0x0F, 0xFE]; // 4094 > 4093
    assert_eq!(
        client.open(&oversized),
        Err(ControlbaseError::MalformedFrame)
    );
    // 失步后即使合法帧也恒拒（fail-closed，无法重同步）
    let good = server_t.seal(b"x").unwrap();
    assert_eq!(client.open(&good), Err(ControlbaseError::Desync));
}

#[test]
fn open_rejects_wrong_type_and_short_length() {
    // record 长度 < tag（防下溢 panic）
    let (mut client, _) = established_session();
    assert!(matches!(
        client.open(&[4u8, 0, 5]),
        Err(ControlbaseError::MalformedFrame)
    ));

    // 非 record 类型
    let (mut client, _) = established_session();
    assert!(matches!(
        client.open(&[5u8, 0, 16]),
        Err(ControlbaseError::MalformedFrame)
    ));

    // 头体不符
    let (mut client, _) = established_session();
    assert!(matches!(
        client.open(&[4u8, 0, 16]),
        Err(ControlbaseError::MalformedFrame)
    ));
}

#[test]
fn open_poisoned_after_aead_failure() {
    let (mut client, mut server_t) = established_session();
    let mut frame = server_t.seal(b"hello").unwrap();
    let last = frame.len() - 1;
    frame[last] ^= 0x01;
    assert_eq!(client.open(&frame), Err(ControlbaseError::Desync));
    let good = server_t.seal(b"again").unwrap();
    assert_eq!(client.open(&good), Err(ControlbaseError::Desync));
}

// ---------- NoiseStream（tokio 胶水） ----------

async fn read_record_frame(io: &mut DuplexStream) -> Vec<u8> {
    let mut header = [0u8; 3];
    io.read_exact(&mut header).await.unwrap();
    let len = u16::from_be_bytes([header[1], header[2]]) as usize;
    let mut frame = header.to_vec();
    frame.resize(3 + len, 0);
    io.read_exact(&mut frame[3..]).await.unwrap();
    frame
}

#[tokio::test]
async fn stream_full_exchange() {
    let ck = control_key_pub();
    let (mut client_io, mut server_io) = duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut init = [0u8; 101];
        server_io.read_exact(&mut init).await.unwrap();
        let mut s = TestServer::new();
        let resp = s.respond(&init).unwrap();
        server_io.write_all(&resp).await.unwrap();
        let (mut t, _) = s.finish();
        // 读客户端一条 → 回一条 + 空载荷一条（空 record 对上层透明）
        let frame = read_record_frame(&mut server_io).await;
        assert_eq!(t.open(&frame).unwrap(), b"ping");
        server_io.write_all(&t.seal_empty_record()).await.unwrap();
        server_io
            .write_all(&t.seal(b"pong").unwrap())
            .await
            .unwrap();
    });

    let session = super::stream::handshake(&mut client_io, &MACHINE_KEY, &ck, 1)
        .await
        .unwrap();
    let mut stream = NoiseStream::new(client_io, session);
    stream.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 16];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"pong");
    server.await.unwrap();
}

#[tokio::test]
async fn stream_chunks_large_write() {
    let ck = control_key_pub();
    let (mut client_io, mut server_io) = duplex(256 * 1024);
    let plaintext: Vec<u8> = (0..10_000usize).map(|i| i as u8).collect();
    let server = tokio::spawn(async move {
        let mut init = [0u8; 101];
        server_io.read_exact(&mut init).await.unwrap();
        let mut s = TestServer::new();
        let resp = s.respond(&init).unwrap();
        server_io.write_all(&resp).await.unwrap();
        let (mut t, _) = s.finish();
        // 跨 record 重组：逐帧读到满足长度
        let mut got = Vec::new();
        while got.len() < 10_000 {
            let frame = read_record_frame(&mut server_io).await;
            got.extend_from_slice(&t.open(&frame).unwrap());
        }
        got
    });

    let session = super::stream::handshake(&mut client_io, &MACHINE_KEY, &ck, 1)
        .await
        .unwrap();
    let mut stream = NoiseStream::new(client_io, session);
    stream.write_all(&plaintext).await.unwrap();
    assert_eq!(server.await.unwrap(), plaintext);
}

#[tokio::test]
async fn stream_eof_after_peer_close() {
    let ck = control_key_pub();
    let (mut client_io, mut server_io) = duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut init = [0u8; 101];
        server_io.read_exact(&mut init).await.unwrap();
        let mut s = TestServer::new();
        let resp = s.respond(&init).unwrap();
        server_io.write_all(&resp).await.unwrap();
        let (mut t, _) = s.finish();
        server_io.write_all(&t.seal(b"bye").unwrap()).await.unwrap();
        // server_io drop → EOF
    });
    let session = super::stream::handshake(&mut client_io, &MACHINE_KEY, &ck, 1)
        .await
        .unwrap();
    let mut stream = NoiseStream::new(client_io, session);
    let mut buf = [0u8; 8];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"bye");
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(n, 0, "对端关闭后应读到 EOF");
    server.await.unwrap();
}

#[tokio::test]
async fn stream_handshake_server_error() {
    let (mut client_io, mut server_io) = duplex(1024);
    let server = tokio::spawn(async move {
        let mut init = [0u8; 101];
        server_io.read_exact(&mut init).await.unwrap();
        server_io.write_all(&[3u8, 0, 11]).await.unwrap();
        server_io.write_all(b"who are you").await.unwrap();
    });
    let err = super::stream::handshake(&mut client_io, &MACHINE_KEY, &control_key_pub(), 1)
        .await
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("who are you"));
    server.await.unwrap();
}

#[tokio::test]
async fn stream_read_rejects_illegal_header() {
    let (mut client_io, mut server_io) = duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut init = [0u8; 101];
        server_io.read_exact(&mut init).await.unwrap();
        let mut s = TestServer::new();
        let resp = s.respond(&init).unwrap();
        server_io.write_all(&resp).await.unwrap();
        server_io.write_all(&[9u8, 0xFF, 0xFF]).await.unwrap();
    });
    let session = super::stream::handshake(&mut client_io, &MACHINE_KEY, &control_key_pub(), 1)
        .await
        .unwrap();
    let mut stream = NoiseStream::new(client_io, session);
    let mut buf = [0u8; 8];
    let err = stream.read(&mut buf).await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    server.await.unwrap();
}
