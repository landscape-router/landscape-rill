use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use landscape_rill_core::control::registry::{binding_message, IdentitySigner};

pub const BINDING_SIG_LEN: usize = 64;

pub struct Ed25519Signer {
    signing_key: SigningKey,
}

impl Ed25519Signer {
    pub fn new(seed: [u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&seed),
        }
    }

    pub fn verifier(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
}

impl IdentitySigner for Ed25519Signer {
    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.signing_key.sign(msg).to_bytes().to_vec()
    }

    fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        let Ok(sig) = Signature::from_slice(sig) else {
            return false;
        };
        VerifyingKey::from(&self.signing_key)
            .verify_strict(msg, &sig)
            .is_ok()
    }
}

/// binding v2（REQ-049②）：验证 `node_id ⇔ 静态公钥 ⇔ 签发锚点 (log_index, term)` 绑定签名
pub fn verify_binding(
    verifier: &VerifyingKey,
    node_id: u32,
    static_pubkey: &[u8; 32],
    binding: &[u8],
    issuance: (u64, u64),
) -> bool {
    let Ok(sig) = Signature::from_slice(binding) else {
        return false;
    };
    verifier
        .verify_strict(&binding_message(node_id, static_pubkey, issuance), &sig)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let signer = Ed25519Signer::new([0x11; 32]);
        let msg = binding_message(7, &[0x42; 32], (3, 1));
        let sig = signer.sign(&msg);
        assert_eq!(sig.len(), BINDING_SIG_LEN);
        assert!(signer.verify(&msg, &sig));
    }

    #[test]
    fn tampered_message_rejected() {
        let signer = Ed25519Signer::new([0x11; 32]);
        let msg = binding_message(7, &[0x42; 32], (3, 1));
        let sig = signer.sign(&msg);
        let mut tampered = msg.clone();
        tampered[0] ^= 1;
        assert!(!signer.verify(&tampered, &sig));
    }

    #[test]
    fn wrong_node_id_rejected() {
        let signer = Ed25519Signer::new([0x11; 32]);
        let msg = binding_message(7, &[0x42; 32], (3, 1));
        let sig = signer.sign(&msg);
        assert!(verify_binding(
            &signer.verifier(),
            7,
            &[0x42; 32],
            &sig,
            (3, 1)
        ));
        assert!(!verify_binding(
            &signer.verifier(),
            8,
            &[0x42; 32],
            &sig,
            (3, 1)
        ));
        assert!(!verify_binding(
            &signer.verifier(),
            7,
            &[0x43; 32],
            &sig,
            (3, 1)
        ));
    }

    #[test]
    fn wrong_anchor_rejected() {
        // 签发锚点参与签名域：锚点不符（伪造/挪用其他日志位置的绑定）→ 验签失败
        let signer = Ed25519Signer::new([0x11; 32]);
        let msg = binding_message(7, &[0x42; 32], (3, 1));
        let sig = signer.sign(&msg);
        assert!(!verify_binding(
            &signer.verifier(),
            7,
            &[0x42; 32],
            &sig,
            (4, 1)
        ));
        assert!(!verify_binding(
            &signer.verifier(),
            7,
            &[0x42; 32],
            &sig,
            (3, 2)
        ));
        assert!(!verify_binding(
            &signer.verifier(),
            7,
            &[0x42; 32],
            &sig,
            (0, 0)
        ));
    }

    #[test]
    fn different_key_rejected() {
        let a = Ed25519Signer::new([0x11; 32]);
        let b = Ed25519Signer::new([0x22; 32]);
        let msg = binding_message(7, &[0x42; 32], (3, 1));
        let sig = a.sign(&msg);
        assert!(!b.verify(&msg, &sig));
    }

    #[test]
    fn garbage_signature_rejected() {
        let signer = Ed25519Signer::new([0x11; 32]);
        let msg = binding_message(7, &[0x42; 32], (3, 1));
        assert!(!signer.verify(&msg, &[0xff; 10]));
    }
}
