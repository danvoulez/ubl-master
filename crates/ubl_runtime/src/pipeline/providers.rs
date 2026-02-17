use rb_vm::canon::CanonProvider;
use rb_vm::types::Cid as VmCid;
use rb_vm::{CasProvider, SignProvider};
use std::collections::HashMap;
use std::sync::Arc;
use ubl_kms::Ed25519SigningKey as SigningKey;

pub(super) struct PipelineCas {
    store: HashMap<String, Vec<u8>>,
}

impl PipelineCas {
    pub(super) fn new() -> Self {
        Self {
            store: HashMap::new(),
        }
    }
}

impl CasProvider for PipelineCas {
    fn put(&mut self, bytes: &[u8]) -> VmCid {
        let hash = blake3::hash(bytes);
        let cid = format!("b3:{}", hex::encode(hash.as_bytes()));
        self.store.insert(cid.clone(), bytes.to_vec());
        VmCid(cid)
    }

    fn get(&self, cid: &VmCid) -> Option<Vec<u8>> {
        self.store.get(&cid.0).cloned()
    }
}

pub(super) struct PipelineSigner {
    pub(super) signing_key: Arc<SigningKey>,
    pub(super) kid: String,
}

impl SignProvider for PipelineSigner {
    fn sign_jws(&self, payload: &[u8]) -> Vec<u8> {
        let sig_str = ubl_kms::sign_bytes(&self.signing_key, payload, ubl_kms::domain::RB_VM);
        // Return raw signature bytes (strip "ed25519:" prefix and decode base64)
        sig_str
            .strip_prefix("ed25519:")
            .map(|b64| {
                base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, b64)
                    .unwrap_or_else(|_| vec![0u8; 64])
            })
            .unwrap_or_else(|| vec![0u8; 64])
    }

    fn kid(&self) -> String {
        self.kid.clone()
    }
}

/// Pipeline canonicalization — delegates to full ρ (RhoCanon).
/// Enforces: NFC strings, null stripping, key sorting, BOM rejection.
pub(super) struct PipelineCanon;

impl CanonProvider for PipelineCanon {
    fn canon(&self, v: serde_json::Value) -> serde_json::Value {
        rb_vm::RhoCanon.canon(v)
    }
}
