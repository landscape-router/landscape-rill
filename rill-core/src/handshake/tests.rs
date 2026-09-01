use super::*;
use crate::crypto::derive_key_dst;
use crate::frame::{build_frame, VERSION};
use std::time::Duration;

const NETWORK_ID: u32 = 0x0000_0001;
const KEY_DST: [u8; 32] = [0x42; 32];

/// 私钥（用作 local_static；[id; 32] 经 X25519 标量 clamping）
fn keys(id: u8) -> [u8; 32] {
    [id; 32]
}

/// 私钥 [id; 32] 对应的公钥（netmap/身份绑定携带的是公钥）
fn peer_static(id: u8) -> [u8; 32] {
    use x25519_dalek::{PublicKey, StaticSecret};
    PublicKey::from(&StaticSecret::from([id; 32])).to_bytes()
}

fn binding() -> Vec<u8> {
    [0x5a; BINDING_LEN].to_vec()
}

fn verify(claimed: u32, static_pubkey: &[u8; 32], _binding: &[u8]) -> bool {
    claimed == 1 && static_pubkey == &peer_static(1)
}

/// 完整三方流程（A 发起 → B 响应），返回双方会话密钥
fn run_handshake() -> (SessionKeys, SessionKeys) {
    let salt = 0x1234_5678;
    let mut initiator = HandshakeInitiator::new(
        &keys(1),
        NETWORK_ID,
        VERSION,
        2,
        &binding(),
        salt,
        &peer_static(2),
    )
    .unwrap();
    let mut responder = HandshakeResponder::new(&keys(2), NETWORK_ID, VERSION, 2).unwrap();

    let msg1 = initiator.write_msg1().unwrap();
    responder.read_msg1(&msg1).unwrap();
    let msg2 = responder.write_msg2().unwrap();
    let msg3 = initiator.read_msg2(&msg2).unwrap();
    let init_keys = initiator.finish().unwrap();
    let resp_keys = responder.read_msg3(&msg3, 1, verify).unwrap();
    (init_keys, resp_keys)
}

fn make_session_frame(keys: &SessionKeys, seq: u32, payload: &[u8]) -> Vec<u8> {
    let header = MeshFrameHeader {
        to_node_id: 2,
        from_node_id: 1,
        seq,
        ..Default::default()
    };
    build_frame(
        &header,
        &derive_key_dst(&KEY_DST, 2),
        &keys.tx_key,
        keys.salt,
        payload,
    )
    .unwrap()
}

#[test]
fn keys_symmetric_and_salt_shared() {
    let (init_keys, resp_keys) = run_handshake();
    assert_eq!(init_keys.salt, resp_keys.salt);
    assert_eq!(init_keys.tx_key, resp_keys.rx_key);
    assert_eq!(init_keys.rx_key, resp_keys.tx_key);
    assert_ne!(init_keys.tx_key, init_keys.rx_key);
}

#[test]
fn msg1_wrong_target_rejected() {
    let mut initiator = HandshakeInitiator::new(
        &keys(1),
        NETWORK_ID,
        VERSION,
        3,
        &binding(),
        1,
        &peer_static(2),
    )
    .unwrap();
    let mut responder = HandshakeResponder::new(&keys(2), NETWORK_ID, VERSION, 2).unwrap();
    let msg1 = initiator.write_msg1().unwrap();
    assert_eq!(
        responder.read_msg1(&msg1).unwrap_err(),
        HandshakeError::WrongTarget
    );
}

#[test]
fn msg1_tampered_rejected() {
    // msg1 的 e 为明文、无 MAC（Noise XX 固有）；篡改在 msg2 解密时暴露（Decrypt）
    let mut initiator = HandshakeInitiator::new(
        &keys(1),
        NETWORK_ID,
        VERSION,
        2,
        &binding(),
        1,
        &peer_static(2),
    )
    .unwrap();
    let mut responder = HandshakeResponder::new(&keys(2), NETWORK_ID, VERSION, 2).unwrap();
    let mut msg1 = initiator.write_msg1().unwrap();
    msg1[NODE_ID_LEN] ^= 0x01;
    responder.read_msg1(&msg1).unwrap();
    let msg2 = responder.write_msg2().unwrap();
    assert!(matches!(
        initiator.read_msg2(&msg2).unwrap_err(),
        HandshakeError::Noise(snow::Error::Decrypt)
    ));
}

#[test]
fn malformed_msg1_rejected() {
    let mut responder = HandshakeResponder::new(&keys(2), NETWORK_ID, VERSION, 2).unwrap();
    assert_eq!(
        responder.read_msg1(&[0u8; 4]).unwrap_err(),
        HandshakeError::MalformedPayload
    );
}

#[test]
fn bad_binding_rejected() {
    let salt = 1u32;
    let mut initiator =
        HandshakeInitiator::new(&keys(1), NETWORK_ID, VERSION, 2, &binding(), salt, &keys(2))
            .unwrap();
    let mut responder = HandshakeResponder::new(&keys(2), NETWORK_ID, VERSION, 2).unwrap();
    let msg1 = initiator.write_msg1().unwrap();
    responder.read_msg1(&msg1).unwrap();
    let msg2 = responder.write_msg2().unwrap();
    let msg3 = initiator.read_msg2(&msg2).unwrap();
    assert_eq!(
        responder.read_msg3(&msg3, 1, |_, _, _| false).unwrap_err(),
        HandshakeError::BadBinding
    );
}

#[test]
fn binding_static_must_match_noise_static() {
    let salt = 1u32;
    let mut initiator = HandshakeInitiator::new(
        &keys(1),
        NETWORK_ID,
        VERSION,
        2,
        &binding(),
        salt,
        &peer_static(2),
    )
    .unwrap();
    let mut responder = HandshakeResponder::new(&keys(2), NETWORK_ID, VERSION, 2).unwrap();
    let msg1 = initiator.write_msg1().unwrap();
    responder.read_msg1(&msg1).unwrap();
    let msg2 = responder.write_msg2().unwrap();
    let msg3 = initiator.read_msg2(&msg2).unwrap();
    assert_eq!(
        responder
            .read_msg3(&msg3, 1, |claimed, static_pubkey, _| {
                claimed == 1 && static_pubkey == &peer_static(9)
            })
            .unwrap_err(),
        HandshakeError::BadBinding
    );
}

#[test]
fn initiator_peer_static_mismatch_rejected() {
    let salt = 1u32;
    let mut initiator = HandshakeInitiator::new(
        &keys(1),
        NETWORK_ID,
        VERSION,
        2,
        &binding(),
        salt,
        &peer_static(9),
    )
    .unwrap();
    let mut responder = HandshakeResponder::new(&keys(2), NETWORK_ID, VERSION, 2).unwrap();
    let msg1 = initiator.write_msg1().unwrap();
    responder.read_msg1(&msg1).unwrap();
    let msg2 = responder.write_msg2().unwrap();
    initiator.read_msg2(&msg2).unwrap();
    assert_eq!(
        initiator.finish().unwrap_err(),
        HandshakeError::PeerStaticMismatch
    );
}

#[test]
fn prologue_mismatch_rejected() {
    // prologue（network_id/版本）经 AEAD AAD=h 在 msg2 解密时暴露——跨网络/跨版本握手互不相认
    let salt = 1u32;
    let mut initiator = HandshakeInitiator::new(
        &keys(1),
        NETWORK_ID,
        VERSION,
        2,
        &binding(),
        salt,
        &peer_static(2),
    )
    .unwrap();
    let mut responder = HandshakeResponder::new(&keys(2), 0x0000_0002, VERSION, 2).unwrap();
    let msg1 = initiator.write_msg1().unwrap();
    responder.read_msg1(&msg1).unwrap();
    let msg2 = responder.write_msg2().unwrap();
    assert!(matches!(
        initiator.read_msg2(&msg2).unwrap_err(),
        HandshakeError::Noise(snow::Error::Decrypt)
    ));
}

#[test]
fn wrong_step_rejected() {
    let mut initiator = HandshakeInitiator::new(
        &keys(1),
        NETWORK_ID,
        VERSION,
        2,
        &binding(),
        1,
        &peer_static(2),
    )
    .unwrap();
    assert_eq!(initiator.finish().unwrap_err(), HandshakeError::WrongStep);
    assert_eq!(initiator.write_msg1().unwrap().len(), MSG1_PAYLOAD_LEN);
    assert_eq!(
        initiator.write_msg1().unwrap_err(),
        HandshakeError::WrongStep
    );
}

#[test]
fn msg3_tampered_rejected() {
    let mut initiator = HandshakeInitiator::new(
        &keys(1),
        NETWORK_ID,
        VERSION,
        2,
        &binding(),
        1,
        &peer_static(2),
    )
    .unwrap();
    let mut responder = HandshakeResponder::new(&keys(2), NETWORK_ID, VERSION, 2).unwrap();
    let msg1 = initiator.write_msg1().unwrap();
    responder.read_msg1(&msg1).unwrap();
    let msg2 = responder.write_msg2().unwrap();
    let mut msg3 = initiator.read_msg2(&msg2).unwrap();
    let n = msg3.len();
    msg3[n - 1] ^= 0xff;
    assert!(matches!(
        responder.read_msg3(&msg3, 1, |_, _, _| true).unwrap_err(),
        HandshakeError::Noise(_)
    ));
}

#[test]
fn session_roundtrip_and_replay_rejected() {
    let (init_keys, resp_keys) = run_handshake();
    let init_session = Session::new(1, init_keys);
    let mut resp_session = Session::new(2, resp_keys);
    let now = Instant::now();

    let frame = make_session_frame(init_session.keys(), 0, b"hello");
    let (h, payload) = resp_session
        .open(&frame, &derive_key_dst(&KEY_DST, 2), now)
        .unwrap();
    assert_eq!(h.from_node_id, 1);
    assert_eq!(payload, b"hello");

    assert_eq!(
        resp_session
            .open(&frame, &derive_key_dst(&KEY_DST, 2), now)
            .unwrap_err(),
        OpenError::Replay
    );
}

#[test]
fn session_payload_tamper_rejected() {
    let (init_keys, resp_keys) = run_handshake();
    let init_session = Session::new(1, init_keys);
    let mut resp_session = Session::new(2, resp_keys);
    let now = Instant::now();

    let mut frame = make_session_frame(init_session.keys(), 0, b"hello");
    let n = frame.len();
    frame[n - 1] ^= 0xff;
    assert_eq!(
        resp_session
            .open(&frame, &derive_key_dst(&KEY_DST, 2), now)
            .unwrap_err(),
        OpenError::Aead
    );
}

#[test]
fn rekey_dual_window_semantics() {
    let (init_keys, resp_keys) = run_handshake();
    let mut init_session = Session::new(1, init_keys);
    let mut resp_session = Session::new(2, resp_keys);
    let t0 = Instant::now();

    let before = make_session_frame(init_session.keys(), 0, b"before");
    assert_eq!(
        resp_session
            .open(&before, &derive_key_dst(&KEY_DST, 2), t0)
            .unwrap()
            .1,
        b"before"
    );

    init_session.rekey(t0);
    resp_session.rekey(t0);

    let after = make_session_frame(init_session.keys(), 0, b"after");
    assert_eq!(
        resp_session
            .open(
                &after,
                &derive_key_dst(&KEY_DST, 2),
                t0 + Duration::from_secs(1)
            )
            .unwrap()
            .1,
        b"after"
    );

    let stray = make_session_frame(&init_keys, 5, b"stray");
    assert_eq!(
        resp_session
            .open(
                &stray,
                &derive_key_dst(&KEY_DST, 2),
                t0 + Duration::from_secs(2)
            )
            .unwrap()
            .1,
        b"stray"
    );

    assert_eq!(
        resp_session
            .open(
                &stray,
                &derive_key_dst(&KEY_DST, 2),
                t0 + Duration::from_secs(6)
            )
            .unwrap_err(),
        OpenError::Aead
    );
}

#[test]
fn rekey_both_sides_continue_traffic() {
    let (init_keys, resp_keys) = run_handshake();
    let mut init_session = Session::new(1, init_keys);
    let mut resp_session = Session::new(2, resp_keys);
    let t0 = Instant::now();

    init_session.rekey(t0);
    resp_session.rekey(t0);

    for i in 0u8..3 {
        let frame = make_session_frame(init_session.keys(), i as u32, &[i]);
        assert_eq!(
            resp_session
                .open(&frame, &derive_key_dst(&KEY_DST, 2), t0)
                .unwrap()
                .1,
            vec![i]
        );
    }
}

#[test]
fn seq_monotonic_across_rekey() {
    let (init_keys, _) = run_handshake();
    let mut session = Session::new(1, init_keys);
    assert_eq!(session.next_seq(), 0);
    assert_eq!(session.next_seq(), 1);
    session.rekey(Instant::now());
    assert_eq!(session.next_seq(), 2);
}

#[test]
fn next_seq_wraps_without_reuse() {
    let (init_keys, _) = run_handshake();
    let mut session = Session::new(1, init_keys);
    for _ in 0..100 {
        session.next_seq();
    }
    let last = session.next_seq();
    assert_ne!(session.next_seq(), last);
}
