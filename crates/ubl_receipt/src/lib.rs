pub mod pipeline_types;
pub mod unified;

use anyhow::Result;
use base64::Engine;
use chrono::Utc;
use cid::Cid;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use serde_json::json;

// Re-export pipeline types for UBL MASTER
pub use pipeline_types::{
    AdvisoryBody, ChipIntent, Decision, KnockBody, OperationResult, PolicyTraceEntry, RbResult,
    UblReceiptType, WaReceiptBody, WfReceiptBody,
};
pub use unified::{
    BuildMeta, CryptoMode, PipelineStage, ReceiptError, RuntimeInfo, StageExecution,
    UnifiedReceipt, VerifyMode, VerifyReport,
};

// Re-export leaf newtypes for downstream crates
pub use ubl_types;

lazy_static! {
    static ref SIGNING_KEY: SigningKey = {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(
            &hex::decode("11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff")
                .unwrap(),
        );
        SigningKey::from_bytes(&bytes)
    };
    pub static ref VERIFYING_KEY: VerifyingKey = SIGNING_KEY.verifying_key();
    pub static ref ISSUER_DID: String = format!(
        "did:key:z{}",
        bs58::encode(VERIFYING_KEY.to_bytes()).into_string()
    );
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RuntimeAttestation {
    pub tee: String,
    pub measurement: String,
    pub attestation_doc: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Receipt {
    pub receipt_version: String,
    pub cid: String,
    pub cid_codec: String,
    pub mh: String,
    pub size: usize,
    pub issued_at: String,
    pub issuer: String,
    pub runtime: RuntimeAttestation,
}

pub async fn issue_receipt(cid: &Cid, bytes_len: usize) -> Result<String> {
    let receipt = Receipt {
        receipt_version: "1".into(),
        cid: cid.to_string(),
        cid_codec: "raw".into(),
        mh: "blake3".into(),
        size: bytes_len,
        issued_at: Utc::now().to_rfc3339(),
        issuer: ISSUER_DID.clone(),
        runtime: RuntimeAttestation {
            tee: "mock".into(),
            measurement: "deadbeefcafebabe".into(),
            attestation_doc: base64::engine::general_purpose::STANDARD.encode("mock-attestation"),
        },
    };
    let header = json!({
        "alg": "EdDSA",
        "kid": format!("{}#ed25519", *ISSUER_DID),
        "typ": "JWT",
    });
    let header_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
    let payload_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&receipt)?);
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = SIGNING_KEY.sign(signing_input.as_bytes());
    let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes());
    let jws = format!("{header_b64}.{payload_b64}.{sig_b64}");
    ubl_ledger::put_receipt(cid, jws.as_bytes()).await?;
    Ok(jws)
}

pub async fn get_receipt(cid: &Cid) -> Option<String> {
    ubl_ledger::get_receipt(cid)
        .await
        .and_then(|b| String::from_utf8(b).ok())
}
