use crate::crypto::{derive_challenge_key, x25519_shared};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

pub const TAG_LEN: usize = 32;
pub const NONCE_LEN: usize = 16;
pub const EPH_PUB_LEN: usize = 32;

type HmacSha256 = Hmac<Sha256>;

pub fn compute_tag(
    node_static_priv: &[u8; 32],
    eph_pub: &[u8; EPH_PUB_LEN],
    nonce: &[u8],
    node_id: u32,
) -> [u8; TAG_LEN] {
    let shared = x25519_shared(node_static_priv, eph_pub);
    let mac_key = derive_challenge_key(&shared, nonce);
    let mut mac = HmacSha256::new_from_slice(&mac_key).expect("hmac key");
    mac.update(&node_id.to_be_bytes());
    mac.update(nonce);
    mac.update(eph_pub);
    mac.finalize().into_bytes().into()
}

pub fn verify_tag(
    node_static_pub: &[u8; 32],
    eph_priv: &[u8; 32],
    nonce: &[u8],
    node_id: u32,
    tag: &[u8],
) -> bool {
    let shared = x25519_shared(eph_priv, node_static_pub);
    let mac_key = derive_challenge_key(&shared, nonce);
    let mut mac = HmacSha256::new_from_slice(&mac_key).expect("hmac key");
    mac.update(&node_id.to_be_bytes());
    mac.update(nonce);
    mac.update(eph_pub_from_priv(eph_priv).as_slice());
    mac.verify_slice(tag).is_ok()
}

fn eph_pub_from_priv(eph_priv: &[u8; 32]) -> [u8; 32] {
    x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*eph_priv)).to_bytes()
}

pub fn within_window(issued_at: u64, now: u64, window: u64) -> bool {
    now <= issued_at.saturating_add(window)
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::{PublicKey, StaticSecret};

    fn pub_of(priv_key: &[u8; 32]) -> [u8; 32] {
        PublicKey::from(&StaticSecret::from(*priv_key)).to_bytes()
    }

    fn rand_key(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    #[test]
    fn tag_roundtrip_verifies() {
        let node_priv = rand_key(1);
        let node_pub = pub_of(&node_priv);
        let eph_priv = rand_key(2);
        let eph_pub = pub_of(&eph_priv);
        let nonce = [0xab; NONCE_LEN];
        let node_id = 0x0000_0007;
        let tag = compute_tag(&node_priv, &eph_pub, &nonce, node_id);
        assert!(verify_tag(&node_pub, &eph_priv, &nonce, node_id, &tag));
    }

    #[test]
    fn wrong_nonce_rejected() {
        let node_priv = rand_key(1);
        let node_pub = pub_of(&node_priv);
        let eph_priv = rand_key(2);
        let eph_pub = pub_of(&eph_priv);
        let tag = compute_tag(&node_priv, &eph_pub, &[0xab; NONCE_LEN], 7);
        assert!(!verify_tag(&node_pub, &eph_priv, &[0xcd; NONCE_LEN], 7, &tag));
    }

    #[test]
    fn wrong_node_id_rejected() {
        let node_priv = rand_key(1);
        let node_pub = pub_of(&node_priv);
        let eph_priv = rand_key(2);
        let eph_pub = pub_of(&eph_priv);
        let nonce = [0xab; NONCE_LEN];
        let tag = compute_tag(&node_priv, &eph_pub, &nonce, 7);
        assert!(!verify_tag(&node_pub, &eph_priv, &nonce, 8, &tag));
        assert!(!verify_tag(&node_pub, &eph_priv, &nonce, 6, &tag));
    }

    #[test]
    fn wrong_eph_priv_rejected() {
        let node_priv = rand_key(1);
        let node_pub = pub_of(&node_priv);
        let eph_priv = rand_key(2);
        let eph_pub = pub_of(&eph_priv);
        let nonce = [0xab; NONCE_LEN];
        let tag = compute_tag(&node_priv, &eph_pub, &nonce, 7);
        let wrong_eph = rand_key(3);
        assert!(!verify_tag(&node_pub, &wrong_eph, &nonce, 7, &tag));
    }

    #[test]
    fn tampered_tag_rejected() {
        let node_priv = rand_key(1);
        let node_pub = pub_of(&node_priv);
        let eph_priv = rand_key(2);
        let eph_pub = pub_of(&eph_priv);
        let nonce = [0xab; NONCE_LEN];
        let mut tag = compute_tag(&node_priv, &eph_pub, &nonce, 7);
        tag[0] ^= 0x01;
        assert!(!verify_tag(&node_pub, &eph_priv, &nonce, 7, &tag));
    }

    #[test]
    fn window_boundary() {
        assert!(within_window(100, 110, 10));
        assert!(within_window(100, 100, 0));
        assert!(!within_window(100, 111, 10));
        assert!(within_window(u64::MAX, u64::MAX, 10));
    }
}
