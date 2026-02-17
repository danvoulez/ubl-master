//! Runtime certification and self-attestation (PS3 / F1).

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use ubl_kms::Ed25519SigningKey as SigningKey;
use ubl_receipt::RuntimeInfo;

const SELF_ATTEST_DOMAIN_ENV: &str = "UBL_SIGN_DOMAIN_RUNTIME_ATTESTATION";

#[derive(Debug, thiserror::Error)]
pub enum RuntimeCertError {
    #[error("signature error: {0}")]
    Signature(String),
    #[error("did key parse error: {0}")]
    DidKey(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfAttestation {
    #[serde(rename = "@type")]
    pub attestation_type: String,
    #[serde(rename = "@ver")]
    pub ver: String,
    pub issued_at: String,
    pub did: String,
    pub kid: String,
    pub runtime_hash: String,
    pub runtime: RuntimeInfo,
    pub sig: String,
}

impl SelfAttestation {
    /// Build + sign runtime self-attestation from the currently running binary metadata.
    pub fn issue(
        runtime: RuntimeInfo,
        did: &str,
        kid: &str,
        sk: &SigningKey,
    ) -> Result<Self, RuntimeCertError> {
        let mut att = Self {
            attestation_type: "ubl/runtime.attestation".to_string(),
            ver: "1.0".to_string(),
            issued_at: Utc::now().to_rfc3339(),
            did: did.to_string(),
            kid: kid.to_string(),
            runtime_hash: runtime.runtime_hash().to_string(),
            runtime,
            sig: String::new(),
        };
        let payload = att.payload_value();
        let domain = domain_from_env();
        att.sig = ubl_canon::sign_domain_v1(&payload, &domain, sk)
            .map_err(|e| RuntimeCertError::Signature(e.to_string()))?;
        Ok(att)
    }

    /// Verify attestation signature + runtime hash consistency.
    pub fn verify(&self) -> Result<bool, RuntimeCertError> {
        if self.runtime_hash != self.runtime.runtime_hash() {
            return Ok(false);
        }
        let vk = ubl_kms::verifying_key_from_did(&self.did)
            .map_err(|e| RuntimeCertError::DidKey(e.to_string()))?;
        let payload = self.payload_value();
        let domain = domain_from_env();
        ubl_canon::verify_domain_v1(&payload, &domain, &vk, &self.sig)
            .map_err(|e| RuntimeCertError::Signature(e.to_string()))
    }

    fn payload_value(&self) -> serde_json::Value {
        json!({
            "@type": self.attestation_type,
            "@ver": self.ver,
            "issued_at": self.issued_at,
            "did": self.did,
            "kid": self.kid,
            "runtime_hash": self.runtime_hash,
            "runtime": self.runtime,
        })
    }
}

fn domain_from_env() -> String {
    std::env::var(SELF_ATTEST_DOMAIN_ENV)
        .unwrap_or_else(|_| ubl_canon::domains::RUNTIME_ATTESTATION.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_attestation_sign_and_verify_ok() {
        let sk = ubl_kms::generate_signing_key();
        let vk = sk.verifying_key();
        let did = ubl_kms::did_from_verifying_key(&vk);
        let kid = ubl_kms::kid_from_verifying_key(&vk);
        let rt = RuntimeInfo::new("b3:runtime", "0.1.0").with_cert("slsa", "b3:slsa");

        let att = SelfAttestation::issue(rt, &did, &kid, &sk).unwrap();
        assert!(att.verify().unwrap());
    }

    #[test]
    fn self_attestation_bitflip_fails_verify() {
        let sk = ubl_kms::generate_signing_key();
        let vk = sk.verifying_key();
        let did = ubl_kms::did_from_verifying_key(&vk);
        let kid = ubl_kms::kid_from_verifying_key(&vk);
        let rt = RuntimeInfo::new("b3:runtime", "0.1.0");

        let mut att = SelfAttestation::issue(rt, &did, &kid, &sk).unwrap();
        att.runtime_hash = "b3:tampered".to_string();
        assert!(!att.verify().unwrap());
    }
}
