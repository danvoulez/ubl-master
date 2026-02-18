//! UBL Canon — single canonical path for CID/sign/verify.
//!
//! All cryptographic operations in upper layers should flow through NRF bytes.

use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use std::fmt;
use thiserror::Error;

const BASE64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

pub mod domains {
    pub const RECEIPT: &str = "ubl/receipt/v1";
    pub const RICH_URL: &str = "ubl/rich-url/v1";
    pub const RB_VM: &str = "ubl-rb-vm/v1";
    pub const CAPABILITY: &str = "ubl-capability/v1";
    pub const RUNTIME_ATTESTATION: &str = "ubl/runtime-attestation/v1";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoMode {
    CompatV1,
    HashFirstV2,
}

#[derive(Debug, Error)]
pub enum CanonError {
    #[error("NRF encoding failed: {0}")]
    Nrf(String),
    #[error("invalid signature format: {0}")]
    Signature(String),
}

/// Encode JSON value to canonical NRF bytes.
pub fn to_nrf_bytes(value: &serde_json::Value) -> Result<Vec<u8>, CanonError> {
    ubl_ai_nrf1::to_nrf1_bytes(value).map_err(|e| CanonError::Nrf(e.to_string()))
}

/// Compute canonical CID (`b3:<hex>` over NRF bytes).
pub fn cid_of(value: &serde_json::Value) -> Result<String, CanonError> {
    let nrf = to_nrf_bytes(value)?;
    Ok(format!("b3:{}", hex::encode(blake3::hash(&nrf).as_bytes())))
}

/// Canonical fingerprint for payload bucketing and canon-aware controls.
///
/// Computed as `BLAKE3(NRF-1(payload))`. Cosmetic JSON differences
/// (key order, whitespace) produce the same fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CanonFingerprint {
    /// Hex-encoded BLAKE3 hash of canonical NRF-1 bytes.
    pub hash: String,
    /// `@type` anchor, if present.
    pub at_type: String,
    /// `@ver` anchor, if present.
    pub at_ver: String,
    /// `@world` anchor, if present.
    pub at_world: String,
}

impl CanonFingerprint {
    /// Compute canonical fingerprint from a chip body.
    ///
    /// Returns `None` if canonical encoding fails.
    pub fn from_chip_body(body: &serde_json::Value) -> Option<Self> {
        let nrf_bytes = to_nrf_bytes(body).ok()?;
        let hash = blake3::hash(&nrf_bytes);

        Some(Self {
            hash: hex::encode(hash.as_bytes()),
            at_type: body
                .get("@type")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            at_ver: body
                .get("@ver")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            at_world: body
                .get("@world")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
        })
    }

    /// Stable key format: `@type|@ver|@world|hash`.
    pub fn rate_key(&self) -> String {
        format!(
            "{}|{}|{}|{}",
            self.at_type, self.at_ver, self.at_world, self.hash
        )
    }
}

impl fmt::Display for CanonFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.hash.len() < 12 {
            return write!(f, "canon:{}", self.hash);
        }
        write!(
            f,
            "canon:{}…{}",
            &self.hash[..8],
            &self.hash[self.hash.len() - 4..]
        )
    }
}

/// Sign canonical NRF payload with v1 compatibility mode.
pub fn sign_domain_v1(
    value: &serde_json::Value,
    domain: &str,
    sk: &SigningKey,
) -> Result<String, CanonError> {
    let nrf = to_nrf_bytes(value)?;
    Ok(sign_raw_v1(&nrf, domain, sk))
}

/// Verify canonical NRF payload with v1 compatibility mode.
pub fn verify_domain_v1(
    value: &serde_json::Value,
    domain: &str,
    vk: &VerifyingKey,
    sig: &str,
) -> Result<bool, CanonError> {
    let nrf = to_nrf_bytes(value)?;
    verify_raw_v1(&nrf, domain, vk, sig)
}

/// Sign raw bytes with v1 mode (`domain || payload`).
pub fn sign_raw_v1(payload: &[u8], domain: &str, sk: &SigningKey) -> String {
    let mut msg = Vec::with_capacity(domain.len() + payload.len());
    msg.extend_from_slice(domain.as_bytes());
    msg.extend_from_slice(payload);
    let sig = sk.sign(&msg);
    format!("ed25519:{}", BASE64.encode(sig.to_bytes()))
}

/// Verify raw bytes with v1 mode (`domain || payload`).
pub fn verify_raw_v1(
    payload: &[u8],
    domain: &str,
    vk: &VerifyingKey,
    sig: &str,
) -> Result<bool, CanonError> {
    let mut msg = Vec::with_capacity(domain.len() + payload.len());
    msg.extend_from_slice(domain.as_bytes());
    msg.extend_from_slice(payload);
    verify_signature(vk, &msg, sig)
}

/// Sign canonical NRF payload with v2 hash-first mode (`blake3(domain||payload)`).
pub fn sign_domain_v2_hash_first(
    value: &serde_json::Value,
    domain: &str,
    sk: &SigningKey,
) -> Result<String, CanonError> {
    let nrf = to_nrf_bytes(value)?;
    Ok(sign_raw_v2_hash_first(&nrf, domain, sk))
}

/// Verify canonical NRF payload with v2 hash-first mode (`blake3(domain||payload)`).
pub fn verify_domain_v2_hash_first(
    value: &serde_json::Value,
    domain: &str,
    vk: &VerifyingKey,
    sig: &str,
) -> Result<bool, CanonError> {
    let nrf = to_nrf_bytes(value)?;
    verify_raw_v2_hash_first(&nrf, domain, vk, sig)
}

/// Sign raw bytes with v2 hash-first mode.
pub fn sign_raw_v2_hash_first(payload: &[u8], domain: &str, sk: &SigningKey) -> String {
    let mut msg = Vec::with_capacity(domain.len() + payload.len());
    msg.extend_from_slice(domain.as_bytes());
    msg.extend_from_slice(payload);
    let digest = blake3::hash(&msg);
    let sig = sk.sign(digest.as_bytes());
    format!("ed25519:{}", BASE64.encode(sig.to_bytes()))
}

/// Verify raw bytes with v2 hash-first mode.
pub fn verify_raw_v2_hash_first(
    payload: &[u8],
    domain: &str,
    vk: &VerifyingKey,
    sig: &str,
) -> Result<bool, CanonError> {
    let mut msg = Vec::with_capacity(domain.len() + payload.len());
    msg.extend_from_slice(domain.as_bytes());
    msg.extend_from_slice(payload);
    let digest = blake3::hash(&msg);
    verify_signature(vk, digest.as_bytes(), sig)
}

fn verify_signature(vk: &VerifyingKey, message: &[u8], sig: &str) -> Result<bool, CanonError> {
    let b64 = sig
        .strip_prefix("ed25519:")
        .ok_or_else(|| CanonError::Signature("missing 'ed25519:' prefix".to_string()))?;
    let sig_bytes = BASE64
        .decode(b64)
        .map_err(|e| CanonError::Signature(e.to_string()))?;
    let sig =
        Signature::from_slice(&sig_bytes).map_err(|e| CanonError::Signature(e.to_string()))?;
    Ok(vk.verify(message, &sig).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use proptest::prelude::*;
    use serde_json::json;

    #[test]
    fn cid_is_nrf_stable() {
        let a = json!({"b":2,"a":1});
        let b = json!({"a":1,"b":2});
        let c1 = cid_of(&a).unwrap();
        let c2 = cid_of(&b).unwrap();
        assert_eq!(c1, c2);
    }

    #[test]
    fn v1_sign_verify_roundtrip() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let vk = sk.verifying_key();
        let v = json!({"@type":"ubl/test","ok":true});
        let sig = sign_domain_v1(&v, domains::RECEIPT, &sk).unwrap();
        assert!(verify_domain_v1(&v, domains::RECEIPT, &vk, &sig).unwrap());
    }

    #[test]
    fn v2_sign_verify_roundtrip() {
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let vk = sk.verifying_key();
        let v = json!({"@type":"ubl/test","ok":true});
        let sig = sign_domain_v2_hash_first(&v, domains::RECEIPT, &sk).unwrap();
        assert!(verify_domain_v2_hash_first(&v, domains::RECEIPT, &vk, &sig).unwrap());
    }

    #[test]
    fn canon_fingerprint_deterministic() {
        let body = json!({
            "@type": "ubl/user",
            "@ver": "1.0",
            "@world": "a/acme/t/prod",
            "@id": "alice",
            "name": "Alice"
        });
        let fp1 = CanonFingerprint::from_chip_body(&body).unwrap();
        let fp2 = CanonFingerprint::from_chip_body(&body).unwrap();
        assert_eq!(fp1.hash, fp2.hash);
        assert_eq!(fp1.at_type, "ubl/user");
        assert_eq!(fp1.at_world, "a/acme/t/prod");
    }

    #[test]
    fn canon_fingerprint_ignores_key_order() {
        let body1 = json!({
            "@type": "ubl/user",
            "@ver": "1.0",
            "@world": "a/x/t/y",
            "@id": "a",
            "name": "Alice"
        });
        let body2 = json!({
            "name": "Alice",
            "@id": "a",
            "@world": "a/x/t/y",
            "@ver": "1.0",
            "@type": "ubl/user"
        });
        let fp1 = CanonFingerprint::from_chip_body(&body1).unwrap();
        let fp2 = CanonFingerprint::from_chip_body(&body2).unwrap();
        assert_eq!(fp1.hash, fp2.hash);
    }

    #[test]
    fn canon_fingerprint_rate_key_format() {
        let body = json!({
            "@type": "ubl/token",
            "@ver": "2.0",
            "@world": "a/acme/t/prod",
            "@id": "tok1"
        });
        let fp = CanonFingerprint::from_chip_body(&body).unwrap();
        let key = fp.rate_key();
        assert!(key.starts_with("ubl/token|2.0|a/acme/t/prod|"));
        assert_eq!(key.matches('|').count(), 3);
    }

    proptest! {
        #[test]
        fn cid_is_independent_of_object_insertion_order(
            entries in proptest::collection::btree_map("[a-z]{1,8}", -1000i64..1000, 1..16)
        ) {
            let mut forward = serde_json::Map::new();
            for (k, v) in entries.iter() {
                forward.insert(k.clone(), serde_json::json!(v));
            }

            let mut reverse = serde_json::Map::new();
            for (k, v) in entries.iter().rev() {
                reverse.insert(k.clone(), serde_json::json!(v));
            }

            let cid_forward = cid_of(&serde_json::Value::Object(forward)).unwrap();
            let cid_reverse = cid_of(&serde_json::Value::Object(reverse)).unwrap();
            prop_assert_eq!(cid_forward, cid_reverse);
        }

        #[test]
        fn signature_fails_after_payload_bitflip_v1(payload in proptest::collection::vec(any::<u8>(), 1..128)) {
            let sk = SigningKey::from_bytes(&[17u8; 32]);
            let vk = sk.verifying_key();
            let sig = sign_raw_v1(&payload, domains::RECEIPT, &sk);

            let mut tampered = payload.clone();
            tampered[0] ^= 0x01;

            prop_assert!(verify_raw_v1(&payload, domains::RECEIPT, &vk, &sig).unwrap());
            prop_assert!(!verify_raw_v1(&tampered, domains::RECEIPT, &vk, &sig).unwrap());
        }

        #[test]
        fn signature_fails_after_payload_bitflip_v2(payload in proptest::collection::vec(any::<u8>(), 1..128)) {
            let sk = SigningKey::from_bytes(&[23u8; 32]);
            let vk = sk.verifying_key();
            let sig = sign_raw_v2_hash_first(&payload, domains::RECEIPT, &sk);

            let mut tampered = payload.clone();
            tampered[0] ^= 0x01;

            prop_assert!(verify_raw_v2_hash_first(&payload, domains::RECEIPT, &vk, &sig).unwrap());
            prop_assert!(!verify_raw_v2_hash_first(&tampered, domains::RECEIPT, &vk, &sig).unwrap());
        }

        #[test]
        fn domain_separation_is_enforced_v1(payload in proptest::collection::vec(any::<u8>(), 0..128)) {
            let sk = SigningKey::from_bytes(&[31u8; 32]);
            let vk = sk.verifying_key();
            let sig = sign_raw_v1(&payload, domains::RECEIPT, &sk);

            prop_assert!(verify_raw_v1(&payload, domains::RECEIPT, &vk, &sig).unwrap());
            prop_assert!(!verify_raw_v1(&payload, domains::RICH_URL, &vk, &sig).unwrap());
        }

        #[test]
        fn cid_matches_blake3_of_nrf_bytes(
            entries in proptest::collection::btree_map("[a-z]{1,8}", -10_000i64..10_000, 1..24)
        ) {
            let mut obj = serde_json::Map::new();
            for (k, v) in entries {
                obj.insert(k, serde_json::json!(v));
            }
            let value = serde_json::Value::Object(obj);
            let cid = cid_of(&value).unwrap();
            let nrf = to_nrf_bytes(&value).unwrap();
            let expected = format!("b3:{}", hex::encode(blake3::hash(&nrf).as_bytes()));
            prop_assert_eq!(cid, expected);
        }

        #[test]
        fn sign_raw_v1_is_deterministic_for_same_input(payload in proptest::collection::vec(any::<u8>(), 0..256)) {
            let sk = SigningKey::from_bytes(&[41u8; 32]);
            let sig1 = sign_raw_v1(&payload, domains::RB_VM, &sk);
            let sig2 = sign_raw_v1(&payload, domains::RB_VM, &sk);
            prop_assert_eq!(sig1, sig2);
        }

        #[test]
        fn sign_raw_v2_is_deterministic_for_same_input(payload in proptest::collection::vec(any::<u8>(), 0..256)) {
            let sk = SigningKey::from_bytes(&[43u8; 32]);
            let sig1 = sign_raw_v2_hash_first(&payload, domains::RB_VM, &sk);
            let sig2 = sign_raw_v2_hash_first(&payload, domains::RB_VM, &sk);
            prop_assert_eq!(sig1, sig2);
        }

        #[test]
        fn cross_mode_verification_fails(payload in proptest::collection::vec(any::<u8>(), 1..128)) {
            let sk = SigningKey::from_bytes(&[47u8; 32]);
            let vk = sk.verifying_key();
            let sig_v1 = sign_raw_v1(&payload, domains::RECEIPT, &sk);
            let sig_v2 = sign_raw_v2_hash_first(&payload, domains::RECEIPT, &sk);

            prop_assert!(!verify_raw_v2_hash_first(&payload, domains::RECEIPT, &vk, &sig_v1).unwrap());
            prop_assert!(!verify_raw_v1(&payload, domains::RECEIPT, &vk, &sig_v2).unwrap());
        }

        #[test]
        fn signature_bitflip_is_rejected_v1(payload in proptest::collection::vec(any::<u8>(), 1..128)) {
            let sk = SigningKey::from_bytes(&[53u8; 32]);
            let vk = sk.verifying_key();
            let sig = sign_raw_v1(&payload, domains::RICH_URL, &sk);
            let b64 = sig.strip_prefix("ed25519:").unwrap();
            let mut sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(b64).unwrap();
            sig_bytes[0] ^= 0x01;
            let tampered = format!(
                "ed25519:{}",
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig_bytes)
            );
            prop_assert!(!verify_raw_v1(&payload, domains::RICH_URL, &vk, &tampered).unwrap());
        }
    }
}
