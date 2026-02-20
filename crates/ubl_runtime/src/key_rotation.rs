//! Key rotation chip support (`ubl/key.rotate`).

use serde_json::{json, Value};
use ubl_kms::Ed25519SigningKey as SigningKey;

#[derive(Debug, thiserror::Error)]
pub enum KeyRotationError {
    #[error("invalid chip type: expected ubl/key.rotate")]
    InvalidType,
    #[error("missing field: {0}")]
    MissingField(&'static str),
    #[error("invalid field: {0}")]
    InvalidField(String),
    #[error("canon error: {0}")]
    Canon(String),
}

#[derive(Debug, Clone)]
pub struct KeyRotateRequest {
    pub old_did: String,
    pub old_kid: String,
    pub reason: Option<String>,
}

#[derive(Debug, Clone)]
pub struct KeyRotationMaterial {
    pub old_did: String,
    pub old_kid: String,
    pub new_did: String,
    pub new_kid: String,
    pub new_key_cid: String,
}

impl KeyRotateRequest {
    pub fn parse(body: &Value) -> Result<Self, KeyRotationError> {
        let chip_type = body.get("@type").and_then(|v| v.as_str());
        if chip_type != Some("ubl/key.rotate") {
            return Err(KeyRotationError::InvalidType);
        }

        let old_did = body
            .get("old_did")
            .and_then(|v| v.as_str())
            .ok_or(KeyRotationError::MissingField("old_did"))?;
        if !old_did.starts_with("did:key:z") {
            return Err(KeyRotationError::InvalidField(
                "old_did must be did:key:z...".to_string(),
            ));
        }

        let old_kid = body
            .get("old_kid")
            .and_then(|v| v.as_str())
            .ok_or(KeyRotationError::MissingField("old_kid"))?;
        if !old_kid.starts_with(old_did) || !old_kid.contains('#') {
            return Err(KeyRotationError::InvalidField(
                "old_kid must match old_did and include fragment".to_string(),
            ));
        }

        let reason = body
            .get("reason")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        Ok(Self {
            old_did: old_did.to_string(),
            old_kid: old_kid.to_string(),
            reason,
        })
    }
}

/// GAP-15: derive the new signing key for a rotation chip (runtime-only).
/// Uses the same deterministic derivation as `derive_material` so the key is
/// reproducible from `(chip_body, runtime_signing_seed)` alone.
pub fn derive_new_signing_key(
    body: &Value,
    runtime_signing_seed: &[u8; 32],
) -> Result<SigningKey, KeyRotationError> {
    let chip_cid = ubl_canon::cid_of(body).map_err(|e| KeyRotationError::Canon(e.to_string()))?;
    let digest = blake3::keyed_hash(
        runtime_signing_seed,
        format!("ubl/key.rotate/v1\0{}", chip_cid).as_bytes(),
    );
    let mut seed = [0u8; 32];
    seed.copy_from_slice(digest.as_bytes());
    Ok(SigningKey::from_bytes(&seed))
}

pub fn derive_material(
    req: &KeyRotateRequest,
    body: &Value,
    runtime_signing_seed: &[u8; 32],
) -> Result<KeyRotationMaterial, KeyRotationError> {
    let chip_cid = ubl_canon::cid_of(body).map_err(|e| KeyRotationError::Canon(e.to_string()))?;
    let digest = blake3::keyed_hash(
        runtime_signing_seed,
        format!("ubl/key.rotate/v1\0{}", chip_cid).as_bytes(),
    );
    let mut seed = [0u8; 32];
    seed.copy_from_slice(digest.as_bytes());
    let sk = SigningKey::from_bytes(&seed);
    let vk = sk.verifying_key();

    Ok(KeyRotationMaterial {
        old_did: req.old_did.clone(),
        old_kid: req.old_kid.clone(),
        new_did: ubl_kms::did_from_verifying_key(&vk),
        new_kid: ubl_kms::kid_from_verifying_key(&vk),
        new_key_cid: ubl_kms::key_cid(&vk),
    })
}

pub fn mapping_chip(
    world: &str,
    rotation_chip_cid: &str,
    rotation_receipt_cid: &str,
    reason: Option<&str>,
    material: &KeyRotationMaterial,
) -> Value {
    let map_id = format!(
        "keymap-{}",
        hex::encode(
            blake3::hash(
                format!(
                    "{}|{}|{}",
                    material.old_kid, material.new_kid, rotation_chip_cid
                )
                .as_bytes()
            )
            .as_bytes()
        )
    );

    json!({
        "@type": "ubl/key.map",
        "@id": map_id,
        "@ver": "1.0",
        "@world": world,
        "old_did": material.old_did,
        "old_kid": material.old_kid,
        "new_did": material.new_did,
        "new_kid": material.new_kid,
        "new_key_cid": material.new_key_cid,
        "rotation_chip_cid": rotation_chip_cid,
        "rotation_receipt_cid": rotation_receipt_cid,
        "reason": reason.unwrap_or("unspecified"),
        "algorithm": "Ed25519",
        "created_at": chrono::Utc::now().to_rfc3339(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_key_rotate_body() {
        let body = json!({
            "@type":"ubl/key.rotate",
            "@id":"rot-1",
            "@ver":"1.0",
            "@world":"a/acme/t/prod",
            "old_did":"did:key:zOldDid",
            "old_kid":"did:key:zOldDid#ed25519",
            "reason":"routine"
        });
        let req = KeyRotateRequest::parse(&body).unwrap();
        assert_eq!(req.old_kid, "did:key:zOldDid#ed25519");
    }

    #[test]
    fn derive_material_is_deterministic() {
        let body = json!({
            "@type":"ubl/key.rotate",
            "@id":"rot-1",
            "@ver":"1.0",
            "@world":"a/acme/t/prod",
            "old_did":"did:key:zOldDid",
            "old_kid":"did:key:zOldDid#ed25519"
        });
        let req = KeyRotateRequest::parse(&body).unwrap();
        let seed = [42u8; 32];
        let m1 = derive_material(&req, &body, &seed).unwrap();
        let m2 = derive_material(&req, &body, &seed).unwrap();
        assert_eq!(m1.new_kid, m2.new_kid);
        assert_eq!(m1.new_did, m2.new_did);
    }
}
