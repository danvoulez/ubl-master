//! UBL KMS — Key Management Service
//!
//! Owns all Ed25519 signing/verification for UBL.
//! Signs over canonical NRF-1 bytes (not raw JSON) with domain separation.
//!
//! Solves:
//! - H1: Signing key from env (`SIGNING_KEY_HEX`)
//! - H7: Signature domain separation (`"ubl-receipt/v1"`, etc.)

use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

#[cfg(feature = "pq_mldsa3")]
pub mod pq_mldsa3;

// Re-export key types so downstream crates don't need ed25519_dalek directly
pub use ed25519_dalek::{SigningKey as Ed25519SigningKey, VerifyingKey as Ed25519VerifyingKey};
#[cfg(feature = "pq_mldsa3")]
pub use pq_mldsa3::{dual_sign_bytes_with_stub, verify_pq_stub_signature, PqSignatureStub};

const BASE64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;
const ED25519_PUB_MULTICODEC: [u8; 2] = [0xED, 0x01];

#[derive(Debug, thiserror::Error)]
pub enum KmsError {
    #[error("SIGNING_KEY_HEX not set")]
    EnvNotSet,
    #[error("SIGNING_KEY_HEX must be 64 hex chars (32 bytes): {0}")]
    BadHex(String),
    #[error("NRF encoding failed: {0}")]
    Nrf(String),
    #[error("signature verification failed")]
    VerifyFailed,
    #[error("invalid signature format: {0}")]
    BadSignature(String),
}

/// Domain strings for signature separation (ARCHITECTURE.md §7.4).
pub mod domain {
    pub const RECEIPT: &str = "ubl-receipt/v1";
    pub const RB_VM: &str = "ubl-rb-vm/v1";
    pub const CAPSULE: &str = "ubl-capsule/v1";
    pub const CHIP: &str = "ubl-chip/v1";
    pub const CAPABILITY: &str = "ubl-capability/v1";
}

/// Load an Ed25519 signing key from the `SIGNING_KEY_HEX` environment variable.
/// Returns `KmsError::EnvNotSet` if the variable is absent.
pub fn signing_key_from_env() -> Result<SigningKey, KmsError> {
    let hex_str = std::env::var("SIGNING_KEY_HEX").map_err(|_| KmsError::EnvNotSet)?;
    signing_key_from_hex(&hex_str)
}

/// Parse a 64-char hex string into an Ed25519 signing key.
pub fn signing_key_from_hex(hex_str: &str) -> Result<SigningKey, KmsError> {
    let bytes = hex::decode(hex_str.trim()).map_err(|e| KmsError::BadHex(e.to_string()))?;
    if bytes.len() != 32 {
        return Err(KmsError::BadHex(format!(
            "got {} bytes, need 32",
            bytes.len()
        )));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    Ok(SigningKey::from_bytes(&seed))
}

/// Generate a random Ed25519 signing key (for testing / bootstrap).
pub fn generate_signing_key() -> SigningKey {
    SigningKey::generate(&mut rand::rngs::OsRng)
}

/// Derive the verifying (public) key from a signing key.
pub fn verifying_key(sk: &SigningKey) -> VerifyingKey {
    sk.verifying_key()
}

/// Derive a `did:key:z...` DID from a verifying key.
pub fn did_from_verifying_key(vk: &VerifyingKey) -> String {
    if std::env::var("UBL_DIDKEY_FORMAT")
        .map(|v| v.eq_ignore_ascii_case("strict"))
        .unwrap_or(false)
    {
        did_from_verifying_key_strict(vk)
    } else {
        format!("did:key:z{}", bs58::encode(vk.to_bytes()).into_string())
    }
}

/// Derive strict `did:key:z...` using multicodec-ed25519-pub prefix (0xED01).
pub fn did_from_verifying_key_strict(vk: &VerifyingKey) -> String {
    let mut prefixed = Vec::with_capacity(2 + vk.as_bytes().len());
    prefixed.extend_from_slice(&ED25519_PUB_MULTICODEC);
    prefixed.extend_from_slice(vk.as_bytes());
    format!("did:key:z{}", bs58::encode(prefixed).into_string())
}

/// Parse a `did:key:z...` DID into an Ed25519 verifying key.
pub fn verifying_key_from_did(did: &str) -> Result<VerifyingKey, KmsError> {
    if let Ok(vk) = verifying_key_from_did_strict(did) {
        return Ok(vk);
    }

    // Compat fallback: payload is raw 32-byte key bytes.
    let encoded = did
        .strip_prefix("did:key:z")
        .ok_or_else(|| KmsError::BadSignature("did must start with 'did:key:z'".into()))?;

    let key_bytes = bs58::decode(encoded)
        .into_vec()
        .map_err(|e| KmsError::BadSignature(format!("invalid did:key base58: {}", e)))?;

    if key_bytes.len() != 32 {
        return Err(KmsError::BadSignature(format!(
            "did:key must decode to 32 bytes, got {}",
            key_bytes.len()
        )));
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&key_bytes);
    VerifyingKey::from_bytes(&arr)
        .map_err(|e| KmsError::BadSignature(format!("invalid ed25519 public key: {}", e)))
}

/// Parse strict multicodec `did:key` (must be `z` multibase + `0xED01` prefix).
pub fn verifying_key_from_did_strict(did: &str) -> Result<VerifyingKey, KmsError> {
    let encoded = did
        .strip_prefix("did:key:z")
        .ok_or_else(|| KmsError::BadSignature("did must start with 'did:key:z'".into()))?;

    let bytes = bs58::decode(encoded)
        .into_vec()
        .map_err(|e| KmsError::BadSignature(format!("invalid did:key base58: {}", e)))?;

    if bytes.len() != 34 {
        return Err(KmsError::BadSignature(format!(
            "strict did:key must decode to 34 bytes, got {}",
            bytes.len()
        )));
    }
    if bytes[0..2] != ED25519_PUB_MULTICODEC {
        return Err(KmsError::BadSignature(
            "unsupported multicodec; expected ed25519-pub (0xED01)".to_string(),
        ));
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes[2..]);
    VerifyingKey::from_bytes(&arr)
        .map_err(|e| KmsError::BadSignature(format!("invalid ed25519 public key: {}", e)))
}

/// Derive the key ID (`did:key:z...#ed25519`) from a verifying key.
pub fn kid_from_verifying_key(vk: &VerifyingKey) -> String {
    format!("{}#ed25519", did_from_verifying_key(vk))
}

/// Sign canonical NRF-1 bytes of a JSON value with domain separation.
///
/// The signed message is: `domain || NRF-1(value)`.
/// Returns `"ed25519:<base64url>"`.
pub fn sign_canonical(
    sk: &SigningKey,
    value: &serde_json::Value,
    domain: &str,
) -> Result<String, KmsError> {
    let nrf_bytes =
        ubl_ai_nrf1::nrf::to_nrf1_bytes(value).map_err(|e| KmsError::Nrf(e.to_string()))?;
    let msg = domain_message(domain, &nrf_bytes);
    let sig: Signature = sk.sign(&msg);
    Ok(format!("ed25519:{}", BASE64.encode(sig.to_bytes())))
}

/// Sign raw bytes with domain separation.
///
/// The signed message is: `domain || raw_bytes`.
/// Returns `"ed25519:<base64url>"`.
pub fn sign_bytes(sk: &SigningKey, raw: &[u8], domain: &str) -> String {
    let msg = domain_message(domain, raw);
    let sig: Signature = sk.sign(&msg);
    format!("ed25519:{}", BASE64.encode(sig.to_bytes()))
}

/// Verify a signature over canonical NRF-1 bytes with domain separation.
///
/// `sig_str` must be in `"ed25519:<base64url>"` format.
pub fn verify_canonical(
    vk: &VerifyingKey,
    value: &serde_json::Value,
    domain: &str,
    sig_str: &str,
) -> Result<bool, KmsError> {
    let nrf_bytes =
        ubl_ai_nrf1::nrf::to_nrf1_bytes(value).map_err(|e| KmsError::Nrf(e.to_string()))?;
    let msg = domain_message(domain, &nrf_bytes);
    verify_raw(vk, &msg, sig_str)
}

/// Verify a signature over raw bytes.
///
/// `sig_str` must be in `"ed25519:<base64url>"` format.
pub fn verify_bytes(
    vk: &VerifyingKey,
    raw: &[u8],
    domain: &str,
    sig_str: &str,
) -> Result<bool, KmsError> {
    let msg = domain_message(domain, raw);
    verify_raw(vk, &msg, sig_str)
}

fn verify_raw(vk: &VerifyingKey, msg: &[u8], sig_str: &str) -> Result<bool, KmsError> {
    let b64 = sig_str
        .strip_prefix("ed25519:")
        .ok_or_else(|| KmsError::BadSignature("must start with 'ed25519:'".into()))?;
    let sig_bytes = BASE64
        .decode(b64)
        .map_err(|e| KmsError::BadSignature(e.to_string()))?;
    let sig =
        Signature::from_slice(&sig_bytes).map_err(|e| KmsError::BadSignature(e.to_string()))?;
    Ok(vk.verify(msg, &sig).is_ok())
}

/// Build the domain-separated message: `domain_bytes || payload_bytes`.
fn domain_message(domain: &str, payload: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(domain.len() + payload.len());
    msg.extend_from_slice(domain.as_bytes());
    msg.extend_from_slice(payload);
    msg
}

/// Compute the BLAKE3 CID of a verifying key's bytes (for key identification).
pub fn key_cid(vk: &VerifyingKey) -> String {
    let hash = blake3::hash(vk.as_bytes());
    format!("b3:{}", hex::encode(hash.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_keypair() -> (SigningKey, VerifyingKey) {
        let sk = generate_signing_key();
        let vk = verifying_key(&sk);
        (sk, vk)
    }

    #[test]
    fn sign_and_verify_canonical_roundtrip() {
        let (sk, vk) = test_keypair();
        let value = json!({"@type": "ubl/test", "amount": 42});
        let sig = sign_canonical(&sk, &value, domain::RECEIPT).unwrap();
        assert!(sig.starts_with("ed25519:"));
        let ok = verify_canonical(&vk, &value, domain::RECEIPT, &sig).unwrap();
        assert!(ok, "valid signature must verify");
    }

    #[test]
    fn wrong_domain_fails_verification() {
        let (sk, vk) = test_keypair();
        let value = json!({"test": true});
        let sig = sign_canonical(&sk, &value, domain::RECEIPT).unwrap();
        let ok = verify_canonical(&vk, &value, domain::RB_VM, &sig).unwrap();
        assert!(!ok, "wrong domain must fail verification");
    }

    #[test]
    fn wrong_key_fails_verification() {
        let (sk, _vk) = test_keypair();
        let (_, other_vk) = test_keypair();
        let value = json!({"test": true});
        let sig = sign_canonical(&sk, &value, domain::CHIP).unwrap();
        let ok = verify_canonical(&other_vk, &value, domain::CHIP, &sig).unwrap();
        assert!(!ok, "wrong key must fail verification");
    }

    #[test]
    fn tampered_value_fails_verification() {
        let (sk, vk) = test_keypair();
        let value = json!({"amount": 100});
        let sig = sign_canonical(&sk, &value, domain::RECEIPT).unwrap();
        let tampered = json!({"amount": 999});
        let ok = verify_canonical(&vk, &tampered, domain::RECEIPT, &sig).unwrap();
        assert!(!ok, "tampered value must fail verification");
    }

    #[test]
    fn sign_and_verify_bytes_roundtrip() {
        let (sk, vk) = test_keypair();
        let data = b"hello world";
        let sig = sign_bytes(&sk, data, domain::CAPSULE);
        let ok = verify_bytes(&vk, data, domain::CAPSULE, &sig).unwrap();
        assert!(ok);
    }

    #[test]
    fn signing_key_from_hex_valid() {
        let hex_str = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff";
        let sk = signing_key_from_hex(hex_str).unwrap();
        let vk = verifying_key(&sk);
        // Sign something to prove it works
        let sig = sign_bytes(&sk, b"test", domain::RECEIPT);
        assert!(verify_bytes(&vk, b"test", domain::RECEIPT, &sig).unwrap());
    }

    #[test]
    fn signing_key_from_hex_bad_length() {
        let result = signing_key_from_hex("aabb");
        assert!(result.is_err());
    }

    #[test]
    fn signing_key_from_hex_bad_chars() {
        let result = signing_key_from_hex("zzzz");
        assert!(result.is_err());
    }

    #[test]
    fn signing_key_from_env_missing() {
        // Don't set the env var — should fail
        std::env::remove_var("SIGNING_KEY_HEX");
        let result = signing_key_from_env();
        assert!(result.is_err());
    }

    #[test]
    fn did_and_kid_format() {
        let (_, vk) = test_keypair();
        let did = did_from_verifying_key(&vk);
        assert!(did.starts_with("did:key:z"));
        let kid = kid_from_verifying_key(&vk);
        assert!(kid.ends_with("#ed25519"));
        assert!(kid.starts_with("did:key:z"));
    }

    #[test]
    fn verifying_key_from_did_roundtrip() {
        let (_, vk) = test_keypair();
        let did = did_from_verifying_key(&vk);
        let parsed = verifying_key_from_did(&did).unwrap();
        assert_eq!(parsed.to_bytes(), vk.to_bytes());
    }

    #[test]
    fn didkey_multicodec_vectors_pass() {
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let vk = verifying_key(&sk);
        let strict_did = did_from_verifying_key_strict(&vk);

        let strict_parsed = verifying_key_from_did_strict(&strict_did).unwrap();
        assert_eq!(strict_parsed.to_bytes(), vk.to_bytes());

        // Compat parser also accepts strict vectors.
        let compat_parsed = verifying_key_from_did(&strict_did).unwrap();
        assert_eq!(compat_parsed.to_bytes(), vk.to_bytes());
    }

    #[test]
    fn verifying_key_from_did_rejects_invalid_prefix() {
        let err = verifying_key_from_did("did:web:example.com").unwrap_err();
        assert!(matches!(err, KmsError::BadSignature(_)));
    }

    #[test]
    fn key_cid_deterministic() {
        let (_, vk) = test_keypair();
        let c1 = key_cid(&vk);
        let c2 = key_cid(&vk);
        assert_eq!(c1, c2);
        assert!(c1.starts_with("b3:"));
    }

    #[test]
    fn bad_signature_format_rejected() {
        let (_, vk) = test_keypair();
        let value = json!({"test": true});
        // Missing prefix
        let result = verify_canonical(&vk, &value, domain::RECEIPT, "not-ed25519:abc");
        assert!(result.is_err());
        // Bad base64
        let result = verify_canonical(&vk, &value, domain::RECEIPT, "ed25519:!!!invalid!!!");
        assert!(result.is_err());
    }

    #[test]
    fn null_stripping_determinism() {
        let (sk, vk) = test_keypair();
        // These two should produce the same canonical form (null stripped)
        let v1 = json!({"a": 1, "b": null});
        let v2 = json!({"a": 1});
        let sig = sign_canonical(&sk, &v1, domain::CHIP).unwrap();
        let ok = verify_canonical(&vk, &v2, domain::CHIP, &sig).unwrap();
        assert!(ok, "null-stripped values must produce same canonical bytes");
    }
}
