pub mod error;
pub use error::AeadError;

use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

pub const KEY_DST_LEN: usize = 32;
pub const SIP_KEY_LEN: usize = 16;
pub const TAG_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;

pub const CHALLENGE_INFO: &[u8] = b"challenge";

fn sip_round(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = v1.rotate_left(13);
    *v1 ^= *v0;
    *v0 = v0.rotate_left(32);
    *v2 = v2.wrapping_add(*v3);
    *v3 = v3.rotate_left(16);
    *v3 ^= *v2;
    *v0 = v0.wrapping_add(*v3);
    *v3 = v3.rotate_left(21);
    *v3 ^= *v0;
    *v2 = v2.wrapping_add(*v1);
    *v1 = v1.rotate_left(17);
    *v1 ^= *v2;
    *v2 = v2.rotate_left(32);
}

pub fn siphash_2_4(key: &[u8; SIP_KEY_LEN], data: &[u8]) -> u64 {
    let k0 = u64::from_le_bytes(key[0..8].try_into().unwrap());
    let k1 = u64::from_le_bytes(key[8..16].try_into().unwrap());
    let mut v0 = 0x736f_6d65_7073_6575 ^ k0;
    let mut v1 = 0x646f_7261_6e64_6f6d ^ k1;
    let mut v2 = 0x6c79_6765_6e65_7261 ^ k0;
    let mut v3 = 0x7465_6462_7974_6573 ^ k1;
    let mut b = (data.len() as u64) << 56;
    let mut i = 0;
    while i + 8 <= data.len() {
        let m = u64::from_le_bytes(data[i..i + 8].try_into().unwrap());
        v3 ^= m;
        for _ in 0..2 {
            sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        }
        v0 ^= m;
        i += 8;
    }
    for (j, &byte) in data[i..].iter().enumerate() {
        b |= (byte as u64) << (8 * j);
    }
    v3 ^= b;
    for _ in 0..2 {
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    }
    v0 ^= b;
    v2 ^= 0xff;
    for _ in 0..4 {
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    }
    v0 ^ v1 ^ v2 ^ v3
}

pub fn derive_key_dst(master_key: &[u8], to_node_id: u32) -> [u8; KEY_DST_LEN] {
    let mut info = Vec::with_capacity(8);
    info.extend_from_slice(b"key_dst");
    info.extend_from_slice(&to_node_id.to_be_bytes());
    let mut out = [0u8; KEY_DST_LEN];
    Hkdf::<Sha256>::new(None, master_key)
        .expand(&info, &mut out)
        .expect("hkdf expand");
    out
}

/// 路径授权密钥（CONTROL_PLANE §3.11.5）：KDF(主密钥, path_id, path_epoch)
/// v2 route_mac 改用；按路径签发、只发路径参与者。
pub fn derive_key_path(master_key: &[u8], path_id: u64, path_epoch: u32) -> [u8; KEY_DST_LEN] {
    let mut info = Vec::with_capacity(20);
    info.extend_from_slice(b"key_path");
    info.extend_from_slice(&path_id.to_be_bytes());
    info.extend_from_slice(&path_epoch.to_be_bytes());
    let mut out = [0u8; KEY_DST_LEN];
    Hkdf::<Sha256>::new(None, master_key)
        .expand(&info, &mut out)
        .expect("hkdf expand");
    out
}

pub fn derive_sip_key(key_dst: &[u8], index: u8) -> [u8; SIP_KEY_LEN] {
    let mut info = Vec::with_capacity(7);
    info.extend_from_slice(b"sipkey");
    info.push(index);
    let mut out = [0u8; KEY_DST_LEN];
    Hkdf::<Sha256>::new(None, key_dst)
        .expand(&info, &mut out)
        .expect("hkdf expand");
    out[..SIP_KEY_LEN].try_into().unwrap()
}

pub fn route_mac(key_dst: &[u8], auth_input: &[u8]) -> [u8; 16] {
    let k1 = derive_sip_key(key_dst, 0);
    let k2 = derive_sip_key(key_dst, 1);
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&siphash_2_4(&k1, auth_input).to_le_bytes());
    out[8..].copy_from_slice(&siphash_2_4(&k2, auth_input).to_le_bytes());
    out
}

/// 原地加密（REQ-053）：加密 `buf[..pt_len]`，tag 追加写入其后 TAG_LEN 字节。
/// 要求 `buf.len() >= pt_len + TAG_LEN`，返回密文总长。
pub fn seal_in_place(
    session_key: &[u8; 32],
    salt: u32,
    counter: u64,
    aad: &[u8],
    buf: &mut [u8],
    pt_len: usize,
) -> Result<usize, AeadError> {
    if buf.len() < pt_len || buf.len() - pt_len < TAG_LEN {
        return Err(AeadError);
    }
    let cipher = ChaCha20Poly1305::new_from_slice(session_key).unwrap();
    let (msg, tag_buf) = buf.split_at_mut(pt_len);
    let tag = cipher
        .encrypt_inout_detached(&Nonce::from(nonce(salt, counter)), aad, msg.into())
        .map_err(|_| AeadError)?;
    tag_buf[..TAG_LEN].copy_from_slice(tag.as_slice());
    Ok(pt_len + TAG_LEN)
}

/// 原地解密（REQ-053）：密文在 `buf[..ct_len]`（尾 TAG_LEN 字节为 tag），
/// 明文就地写回，返回明文长度。
pub fn open_in_place(
    session_key: &[u8; 32],
    salt: u32,
    counter: u64,
    aad: &[u8],
    buf: &mut [u8],
    ct_len: usize,
) -> Result<usize, AeadError> {
    if buf.len() < ct_len || ct_len < TAG_LEN {
        return Err(AeadError);
    }
    let pt_len = ct_len - TAG_LEN;
    let cipher = ChaCha20Poly1305::new_from_slice(session_key).unwrap();
    let (msg, rest) = buf.split_at_mut(pt_len);
    let tag = chacha20poly1305::Tag::try_from(&rest[..TAG_LEN]).expect("tag len checked");
    cipher
        .decrypt_inout_detached(&Nonce::from(nonce(salt, counter)), aad, msg.into(), &tag)
        .map_err(|_| AeadError)?;
    Ok(pt_len)
}

pub fn seal(
    session_key: &[u8; 32],
    salt: u32,
    counter: u64,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, AeadError> {
    let mut out = vec![0u8; plaintext.len() + TAG_LEN];
    out[..plaintext.len()].copy_from_slice(plaintext);
    seal_in_place(session_key, salt, counter, aad, &mut out, plaintext.len())?;
    Ok(out)
}

pub fn open(
    session_key: &[u8; 32],
    salt: u32,
    counter: u64,
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, AeadError> {
    let mut out = ciphertext.to_vec();
    let n = open_in_place(session_key, salt, counter, aad, &mut out, ciphertext.len())?;
    out.truncate(n);
    Ok(out)
}

pub fn nonce(salt: u32, counter: u64) -> [u8; NONCE_LEN] {
    let mut out = [0u8; NONCE_LEN];
    out[..4].copy_from_slice(&salt.to_be_bytes());
    out[4..].copy_from_slice(&counter.to_be_bytes());
    out
}

pub fn derive_challenge_key(shared_secret: &[u8], nonce: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(Some(nonce), shared_secret)
        .expand(&[], &mut out)
        .expect("hkdf expand");
    out
}

pub fn x25519_shared(static_priv: &[u8; 32], peer_pub: &[u8; 32]) -> [u8; 32] {
    StaticSecret::from(*static_priv)
        .diffie_hellman(&PublicKey::from(*peer_pub))
        .to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn siphash_2_4_vectors() {
        let mut key = [0u8; 16];
        for (i, k) in key.iter_mut().enumerate() {
            *k = i as u8;
        }
        let mut data = [0u8; 32];
        for (i, d) in data.iter_mut().enumerate() {
            *d = i as u8;
        }
        assert_eq!(siphash_2_4(&key, &data), 0x7127_512f_72f2_7cce);
        assert_eq!(siphash_2_4(&key, &data[..0]), 0x726f_db47_dd0e_0e31);
        assert_eq!(siphash_2_4(&key, &data[..1]), 0x74f8_39c5_93dc_67fd);
    }

    #[test]
    fn x25519_rfc7748_vector() {
        let a = hex_literal("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let b = hex_literal("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let a_pub = hex_literal("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        let b_pub = hex_literal("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let shared =
            hex_literal("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        assert_eq!(x25519_shared(&a, &b_pub), shared);
        assert_eq!(x25519_shared(&b, &a_pub), shared);
        assert_eq!(PublicKey::from(&StaticSecret::from(a)).to_bytes(), a_pub);
        assert_eq!(PublicKey::from(&StaticSecret::from(b)).to_bytes(), b_pub);
    }

    fn hex_literal(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }
}
