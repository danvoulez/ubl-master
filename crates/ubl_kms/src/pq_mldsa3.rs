//! Feature-gated Post-Quantum signature stubs (ML-DSA3 / Dilithium3 family).
//!
//! This module is intentionally non-cryptographic for now.
//! It defines the wire/API shape for dual-sign rollout while PQ libs are evaluated.

use crate::SigningKey;

/// Wire shape for a future ML-DSA3 signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqSignatureStub {
    pub alg: &'static str,
    pub sig_b64url: String,
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum PqStubError {
    #[error("pq_mldsa3 is a stub; real signing backend is not linked")]
    Unsupported,
    #[error("invalid pq stub signature format")]
    InvalidFormat,
}

/// Build a dual-sign payload:
/// - always emits the production Ed25519 signature
/// - emits `None` for PQ until a real ML-DSA3 provider is linked
pub fn dual_sign_bytes_with_stub(
    sk: &SigningKey,
    raw: &[u8],
    domain: &str,
) -> (String, Option<PqSignatureStub>) {
    let ed25519 = crate::sign_bytes(sk, raw, domain);
    (ed25519, None)
}

/// Placeholder verifier for future PQ signatures.
pub fn verify_pq_stub_signature(
    _raw: &[u8],
    _domain: &str,
    _sig: &str,
) -> Result<bool, PqStubError> {
    Err(PqStubError::Unsupported)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dual_sign_keeps_ed25519_and_no_pq_yet() {
        let sk = crate::generate_signing_key();
        let (ed_sig, pq) = dual_sign_bytes_with_stub(&sk, b"hello", crate::domain::RECEIPT);
        assert!(ed_sig.starts_with("ed25519:"));
        assert!(pq.is_none());
    }

    #[test]
    fn pq_verify_stub_returns_unsupported() {
        let err = verify_pq_stub_signature(b"x", crate::domain::RECEIPT, "mldsa3:abc").unwrap_err();
        assert_eq!(err, PqStubError::Unsupported);
    }
}
