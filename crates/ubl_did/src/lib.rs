use serde_json::json;
use ubl_receipt::ISSUER_DID;

pub fn runtime_did_document() -> serde_json::Value {
    let multibase = format!(
        "z{}",
        bs58::encode(&ubl_receipt::VERIFYING_KEY.to_bytes()).into_string()
    );
    json!({
        "id": ISSUER_DID.as_str(),
        "verificationMethod": [
            {
                "id": format!("{}#ed25519", *ISSUER_DID),
                "type": "Ed25519VerificationKey2020",
                "controller": ISSUER_DID.as_str(),
                "publicKeyMultibase": multibase,
            }
        ],
        "assertionMethod": [
            format!("{}#ed25519", *ISSUER_DID)
        ]
    })
}

pub fn resolve_did_or_cid(id: &str, base_url: &str) -> serde_json::Value {
    if let Some(cid) = id.strip_prefix("did:cid:") {
        let url = format!("{base_url}/cid/{cid}");
        json!({
            "id": id,
            "alsoKnownAs": [url],
            "links": [url],
        })
    } else {
        json!({ "id": id })
    }
}
