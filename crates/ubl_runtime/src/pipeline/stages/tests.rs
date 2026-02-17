use super::super::*;
use crate::policy_loader::InMemoryPolicyStorage;
use serde_json::json;

fn allow_request() -> ChipRequest {
    ChipRequest {
        chip_type: "ubl/document".to_string(),
        body: json!({
            "@type": "ubl/document",
            "@id": "stage-doc-1",
            "@ver": "1.0",
            "@world": "a/demo/t/main",
            "title": "Stage test document"
        }),
        parents: vec![],
        operation: Some("create".to_string()),
    }
}

fn deny_request() -> ChipRequest {
    ChipRequest {
        chip_type: "evil/hack".to_string(),
        body: json!({
            "@type": "evil/hack",
            "@id": "denied-1",
            "@ver": "1.0",
            "@world": "a/demo/t/main"
        }),
        parents: vec![],
        operation: Some("create".to_string()),
    }
}

#[tokio::test]
async fn stage_write_ahead_emits_valid_receipt() {
    let pipeline = UblPipeline::new(Box::new(InMemoryPolicyStorage::new()));
    let req = allow_request();

    let wa = pipeline.stage_write_ahead(&req).await.unwrap();
    assert_eq!(wa.receipt_type, "ubl/wa");
    assert!(wa.body_cid.as_str().starts_with("b3:"));
    assert_eq!(wa.body["ghost"], json!(true));
    assert!(!wa.body["nonce"].as_str().unwrap_or("").is_empty());
}

#[tokio::test]
async fn stage_check_allow_and_deny_paths() {
    let pipeline = UblPipeline::new(Box::new(InMemoryPolicyStorage::new()));

    let allow = pipeline.stage_check(&allow_request()).await.unwrap();
    assert!(matches!(allow.decision, Decision::Allow));
    assert!(!allow.short_circuited);
    assert!(!allow.trace.is_empty());

    let deny = pipeline.stage_check(&deny_request()).await.unwrap();
    assert!(matches!(deny.decision, Decision::Deny));
    assert!(deny.short_circuited);
    assert!(!deny.trace.is_empty());
}

#[tokio::test]
async fn stage_transition_emits_vm_signature_and_payload_cid() {
    let pipeline = UblPipeline::new(Box::new(InMemoryPolicyStorage::new()));
    let req = allow_request();
    let check = pipeline.stage_check(&req).await.unwrap();

    let tr = pipeline.stage_transition(&req, &check).await.unwrap();
    assert_eq!(tr.receipt_type, "ubl/transition");
    assert!(tr.body_cid.as_str().starts_with("b3:"));
    assert!(!tr.body["vm_sig"].as_str().unwrap_or("").is_empty());
    assert!(!tr.body["vm_sig_payload_cid"]
        .as_str()
        .unwrap_or("")
        .is_empty());
    assert!(tr.body["vm_state"]["fuel_used"].as_u64().is_some());
}

#[tokio::test]
async fn stage_write_finished_links_wa_and_tr_receipts() {
    let pipeline = UblPipeline::new(Box::new(InMemoryPolicyStorage::new()));
    let req = allow_request();
    let wa = pipeline.stage_write_ahead(&req).await.unwrap();
    let check = pipeline.stage_check(&req).await.unwrap();
    let tr = pipeline.stage_transition(&req, &check).await.unwrap();

    let wf = pipeline
        .stage_write_finished(&req, &wa, &tr, &check)
        .await
        .unwrap();
    assert_eq!(wf.receipt_type, "ubl/wf");
    assert_eq!(wf.body["wa_cid"], json!(wa.body_cid.as_str()));
    assert_eq!(wf.body["tr_cid"], json!(tr.body_cid.as_str()));
    assert_eq!(wf.body["decision"], json!("Allow"));
}
