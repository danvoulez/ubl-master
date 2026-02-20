use super::super::*;
use crate::policy_loader::InMemoryPolicyStorage;
use base64::Engine as _;
use ring::digest;
use serde_json::json;

fn parsed_request(request: &ChipRequest) -> ParsedChipRequest<'_> {
    ParsedChipRequest::parse(request).expect("request should parse")
}

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
    let parsed = parsed_request(&req);

    let wa = pipeline.stage_write_ahead(&parsed).await.unwrap();
    assert_eq!(wa.receipt_type, "ubl/wa");
    assert!(wa.body_cid.as_str().starts_with("b3:"));
    assert_eq!(wa.body["ghost"], json!(true));
    assert!(!wa.body["nonce"].as_str().unwrap_or("").is_empty());
}

#[tokio::test]
async fn stage_check_allow_and_deny_paths() {
    let pipeline = UblPipeline::new(Box::new(InMemoryPolicyStorage::new()));

    let allow_req = allow_request();
    let allow = pipeline
        .stage_check(&parsed_request(&allow_req))
        .await
        .unwrap();
    assert!(matches!(allow.decision, Decision::Allow));
    assert!(!allow.short_circuited);
    assert!(!allow.trace.is_empty());

    let deny_req = deny_request();
    let deny = pipeline
        .stage_check(&parsed_request(&deny_req))
        .await
        .unwrap();
    assert!(matches!(deny.decision, Decision::Deny));
    assert!(deny.short_circuited);
    assert!(!deny.trace.is_empty());
}

#[tokio::test]
async fn stage_transition_emits_vm_signature_and_payload_cid() {
    let pipeline = UblPipeline::new(Box::new(InMemoryPolicyStorage::new()));
    let req = allow_request();
    let parsed = parsed_request(&req);
    let check = pipeline.stage_check(&parsed).await.unwrap();

    let tr = pipeline.stage_transition(&parsed, &check).await.unwrap();
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
async fn stage_transition_executes_inline_wasm_adapter() {
    let pipeline = UblPipeline::new(Box::new(InMemoryPolicyStorage::new()));
    let mut req = allow_request();
    let module = wat::parse_str(
        r#"
        (module
          (memory (export "memory") 1 1)
          (func (export "ubl_adapter_v1") (param i32 i32) (result i32)
            local.get 1))
        "#,
    )
    .unwrap();
    let hash = digest::digest(&digest::SHA256, &module);
    req.body["adapter"] = json!({
        "wasm_sha256": hex::encode(hash.as_ref()),
        "abi_version": "1.0",
        "wasm_b64": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&module),
        "fuel_budget": 50_000
    });

    let parsed = parsed_request(&req);
    let check = pipeline.stage_check(&parsed).await.unwrap();
    let tr = pipeline.stage_transition(&parsed, &check).await.unwrap();

    assert_eq!(tr.body["vm_state"]["adapter_executed"], json!(true));
    assert_eq!(
        tr.body["vm_state"]["adapter_module_source"],
        json!("inline:adapter.wasm_b64")
    );
    assert_eq!(
        tr.body["vm_state"]["adapter_output_cid"],
        tr.body["input_cid"]
    );
    assert!(
        tr.body["vm_state"]["adapter_fuel_used"]
            .as_u64()
            .unwrap_or(0)
            > 0
    );
}

#[tokio::test]
async fn stage_transition_rejects_wasm_hash_mismatch() {
    let pipeline = UblPipeline::new(Box::new(InMemoryPolicyStorage::new()));
    let mut req = allow_request();
    let module = wat::parse_str(
        r#"
        (module
          (memory (export "memory") 1 1)
          (func (export "ubl_adapter_v1") (param i32 i32) (result i32)
            local.get 1))
        "#,
    )
    .unwrap();
    req.body["adapter"] = json!({
        "wasm_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
        "abi_version": "1.0",
        "wasm_b64": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&module)
    });

    let parsed = parsed_request(&req);
    let check = pipeline.stage_check(&parsed).await.unwrap();
    let err = pipeline
        .stage_transition(&parsed, &check)
        .await
        .unwrap_err();
    assert!(matches!(err, PipelineError::InvalidChip(_)));
}

#[tokio::test]
async fn stage_write_finished_links_wa_and_tr_receipts() {
    let pipeline = UblPipeline::new(Box::new(InMemoryPolicyStorage::new()));
    let req = allow_request();
    let parsed = parsed_request(&req);
    let wa = pipeline.stage_write_ahead(&parsed).await.unwrap();
    let check = pipeline.stage_check(&parsed).await.unwrap();
    let tr = pipeline.stage_transition(&parsed, &check).await.unwrap();

    let wf = pipeline
        .stage_write_finished(&parsed, &wa, &tr, &check, 123)
        .await
        .unwrap();
    assert_eq!(wf.receipt_type, "ubl/wf");
    assert_eq!(wf.body["wa_cid"], json!(wa.body_cid.as_str()));
    assert_eq!(wf.body["tr_cid"], json!(tr.body_cid.as_str()));
    assert_eq!(wf.body["decision"], json!("Allow"));
    assert_eq!(wf.body["duration_ms"], json!(123));
}
