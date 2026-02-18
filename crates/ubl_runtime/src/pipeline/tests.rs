use super::*;
use crate::policy_loader::InMemoryPolicyStorage;
use crate::transition_registry::TrBytecodeProfile;
use serde_json::json;

fn signed_capability(action: &str, audience: &str, sk: &SigningKey) -> serde_json::Value {
    let did = ubl_kms::did_from_verifying_key(&sk.verifying_key());
    let mut payload = serde_json::json!({
        "action": action,
        "audience": audience,
        "issued_by": did,
        "issued_at": chrono::Utc::now().checked_sub_signed(chrono::Duration::minutes(1)).unwrap().to_rfc3339(),
        "expires_at": chrono::Utc::now().checked_add_signed(chrono::Duration::hours(1)).unwrap().to_rfc3339(),
    });
    let sig = ubl_kms::sign_canonical(sk, &payload, ubl_kms::domain::CAPABILITY).unwrap();
    payload["signature"] = serde_json::json!(sig);
    payload
}

#[tokio::test]
async fn pipeline_allow_flow_with_real_vm() {
    let storage = InMemoryPolicyStorage::new();
    let pipeline = UblPipeline::new(Box::new(storage));

    let request = ChipRequest {
        chip_type: "ubl/document".to_string(),
        body: json!({
            "@type": "ubl/document",
            "@id": "alice-001",
            "@ver": "1.0",
            "@world": "a/demo/t/main",
            "title": "Test Document"
        }),
        parents: vec![],
        operation: Some("create".to_string()),
    };

    let result = pipeline.process_chip(request).await.unwrap();

    // Decision must be Allow (genesis allows ubl/document)
    assert!(matches!(result.decision, Decision::Allow));

    // Chain must have 3 CIDs: WA, TR, WF
    assert_eq!(result.chain.len(), 3, "chain: WA + TR + WF");
    for cid in &result.chain {
        assert!(cid.starts_with("b3:"), "all CIDs must be BLAKE3: {}", cid);
    }

    // TR receipt must contain real VM data (not placeholder)
    let tr_body = &result.chain[1]; // TR CID
    assert!(tr_body.starts_with("b3:"), "TR CID is real BLAKE3");

    // WF receipt body must have decision
    let wf_body = &result.final_receipt.body;
    assert_eq!(wf_body["decision"], "Allow");
    assert!(!wf_body["short_circuited"].as_bool().unwrap());
}

#[tokio::test]
async fn pipeline_deny_flow_skips_vm() {
    let storage = InMemoryPolicyStorage::new();
    let pipeline = UblPipeline::new(Box::new(storage));

    // Genesis policy denies unknown types
    let request = ChipRequest {
        chip_type: "evil/hack".to_string(),
        body: json!({
            "@type": "evil/hack",
            "@id": "x",
            "@ver": "1.0",
            "@world": "a/x/t/y"
        }),
        parents: vec![],
        operation: Some("create".to_string()),
    };

    let result = pipeline.process_chip(request).await.unwrap();

    assert!(matches!(result.decision, Decision::Deny));
    // Chain should have WA + "no-tr" + WF (VM never ran)
    assert_eq!(result.chain[1], "no-tr", "TR must be skipped on deny");
}

#[tokio::test]
async fn pipeline_tr_receipt_has_vm_state() {
    let storage = InMemoryPolicyStorage::new();
    let pipeline = UblPipeline::new(Box::new(storage));

    let request = ChipRequest {
        chip_type: "ubl/document".to_string(),
        body: json!({
            "@type": "ubl/document",
            "@id": "bob",
            "@ver": "1.0",
            "@world": "a/app/t/ten"
        }),
        parents: vec![],
        operation: Some("create".to_string()),
    };

    let result = pipeline.process_chip(request).await.unwrap();

    // Find the TR receipt in the chain (index 1 is the TR CID)
    // The WF body contains the full trace
    let wf = &result.final_receipt.body;
    assert!(wf["tr_cid"].is_string(), "WF must reference TR CID");
    let tr_cid = wf["tr_cid"].as_str().unwrap();
    assert!(tr_cid.starts_with("b3:"), "TR CID must be BLAKE3");
}

#[tokio::test]
async fn same_input_same_receipt_vm() {
    std::env::set_var(
        "SIGNING_KEY_HEX",
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    );
    let request = ChipRequest {
        chip_type: "ubl/document".to_string(),
        body: json!({
            "@type": "ubl/document",
            "@id": "same-input",
            "@ver": "1.0",
            "@world": "a/app/t/ten"
        }),
        parents: vec![],
        operation: Some("create".to_string()),
    };

    let p1 = UblPipeline::new(Box::new(InMemoryPolicyStorage::new()));
    let r1 = p1.process_chip(request.clone()).await.unwrap();

    let p2 = UblPipeline::new(Box::new(InMemoryPolicyStorage::new()));
    let r2 = p2.process_chip(request).await.unwrap();

    // WA/WF include nonce and vary, but TR VM receipt is deterministic for same chip input.
    assert_eq!(r1.chain[1], r2.chain[1]);
    std::env::remove_var("SIGNING_KEY_HEX");
}

#[test]
fn runtime_self_attestation_is_signed_and_verifiable() {
    let pipeline = UblPipeline::new(Box::new(InMemoryPolicyStorage::new()));
    let att = pipeline.runtime_self_attestation().unwrap();
    assert_eq!(
        att.runtime_hash,
        pipeline.runtime_info().runtime_hash().to_string()
    );
    assert!(att.verify().unwrap());
}

#[tokio::test]
async fn key_rotate_requires_capability() {
    use ubl_chipstore::{ChipStore, InMemoryBackend};

    let policy_storage = InMemoryPolicyStorage::new();
    let backend = Arc::new(InMemoryBackend::new());
    let chip_store = Arc::new(ChipStore::new(backend));
    let pipeline = UblPipeline::with_chip_store(Box::new(policy_storage), chip_store);

    let old_sk = ubl_kms::generate_signing_key();
    let old_vk = old_sk.verifying_key();
    let old_did = ubl_kms::did_from_verifying_key(&old_vk);
    let old_kid = ubl_kms::kid_from_verifying_key(&old_vk);

    let request = ChipRequest {
        chip_type: "ubl/key.rotate".to_string(),
        body: json!({
            "@type":"ubl/key.rotate",
            "@id":"rot-missing-cap",
            "@ver":"1.0",
            "@world":"a/acme/t/prod",
            "old_did": old_did,
            "old_kid": old_kid,
            "reason": "compromise"
        }),
        parents: vec![],
        operation: Some("create".to_string()),
    };

    let err = pipeline.process_chip(request).await.unwrap_err();
    assert!(matches!(err, PipelineError::InvalidChip(_)));
    assert!(err.to_string().contains("key.rotate capability"));
}

#[tokio::test]
async fn key_rotate_persists_mapping_and_replay_is_stable() {
    use ubl_chipstore::{ChipQuery, ChipStore, InMemoryBackend};

    let policy_storage = InMemoryPolicyStorage::new();
    let backend = Arc::new(InMemoryBackend::new());
    let chip_store = Arc::new(ChipStore::new(backend));
    let pipeline = UblPipeline::with_chip_store(Box::new(policy_storage), chip_store.clone());

    let old_sk = ubl_kms::generate_signing_key();
    let old_vk = old_sk.verifying_key();
    let old_did = ubl_kms::did_from_verifying_key(&old_vk);
    let old_kid = ubl_kms::kid_from_verifying_key(&old_vk);

    let cap_sk = ubl_kms::generate_signing_key();
    let cap = signed_capability("key:rotate", "a/acme", &cap_sk);

    let request = ChipRequest {
        chip_type: "ubl/key.rotate".to_string(),
        body: json!({
            "@type":"ubl/key.rotate",
            "@id":"rot-1",
            "@ver":"1.0",
            "@world":"a/acme/t/prod",
            "old_did": old_did,
            "old_kid": old_kid,
            "reason": "routine",
            "@cap": cap
        }),
        parents: vec![],
        operation: Some("create".to_string()),
    };

    let first = pipeline.process_chip(request.clone()).await.unwrap();
    assert!(matches!(first.decision, Decision::Allow));
    assert!(!first.replayed);

    let mappings = chip_store
        .query(&ChipQuery {
            chip_type: Some("ubl/key.map".to_string()),
            tags: vec![format!("old_kid:{}", old_kid)],
            created_after: None,
            created_before: None,
            executor_did: None,
            limit: None,
            offset: None,
        })
        .await
        .unwrap();
    assert_eq!(mappings.total_count, 1);
    let map = &mappings.chips[0].chip_data;
    assert_eq!(map["old_kid"].as_str(), Some(old_kid.as_str()));
    assert!(map["new_kid"].as_str().is_some());
    assert_ne!(map["new_kid"].as_str(), Some(old_kid.as_str()));

    let second = pipeline.process_chip(request).await.unwrap();
    assert!(second.replayed);

    let mappings_after = chip_store
        .query(&ChipQuery {
            chip_type: Some("ubl/key.map".to_string()),
            tags: vec![format!("old_kid:{}", old_kid)],
            created_after: None,
            created_before: None,
            executor_did: None,
            limit: None,
            offset: None,
        })
        .await
        .unwrap();
    assert_eq!(mappings_after.total_count, 1);
}

#[tokio::test]
async fn audit_report_requires_capability() {
    let pipeline = UblPipeline::new(Box::new(InMemoryPolicyStorage::new()));
    let request = ChipRequest {
        chip_type: "audit/report.request.v1".to_string(),
        body: json!({
            "@type":"audit/report.request.v1",
            "@id":"audit-report-1",
            "@ver":"1.0",
            "@world":"a/acme/t/prod",
            "name":"daily",
            "window":"5m",
            "format":"ndjson"
        }),
        parents: vec![],
        operation: Some("create".to_string()),
    };
    let err = pipeline.process_chip(request).await.unwrap_err();
    assert!(matches!(err, PipelineError::InvalidChip(_)));
    assert!(err.to_string().to_lowercase().contains("capability"));
}

#[tokio::test]
async fn audit_report_generates_dataset_artifact_and_links_in_wf() {
    use ubl_chipstore::{ChipStore, InMemoryBackend};

    let backend = Arc::new(InMemoryBackend::new());
    let chip_store = Arc::new(ChipStore::new(backend));
    let pipeline =
        UblPipeline::with_chip_store(Box::new(InMemoryPolicyStorage::new()), chip_store.clone());

    let seed_request = ChipRequest {
        chip_type: "ubl/document".to_string(),
        body: json!({
            "@type":"ubl/document",
            "@id":"seed-doc-1",
            "@ver":"1.0",
            "@world":"a/acme/t/prod",
            "title":"seed for audit"
        }),
        parents: vec![],
        operation: Some("create".to_string()),
    };
    let seed = pipeline.process_chip(seed_request).await.unwrap();
    assert!(matches!(seed.decision, Decision::Allow));

    let cap_sk = ubl_kms::generate_signing_key();
    let cap = signed_capability("audit:report", "a/acme", &cap_sk);
    let report_request = ChipRequest {
        chip_type: "audit/report.request.v1".to_string(),
        body: json!({
            "@type":"audit/report.request.v1",
            "@id":"audit-report-ok-1",
            "@ver":"1.0",
            "@world":"a/acme/t/prod",
            "name":"daily",
            "window":"5m",
            "format":"ndjson",
            "@cap": cap
        }),
        parents: vec![],
        operation: Some("create".to_string()),
    };

    let result = pipeline.process_chip(report_request).await.unwrap();
    assert!(matches!(result.decision, Decision::Allow));

    let dataset_cid = result.final_receipt.body["artifacts"]["dataset"]
        .as_str()
        .expect("WF artifacts.dataset must be present");
    assert!(dataset_cid.starts_with("b3:"));

    let dataset = chip_store
        .get_chip(dataset_cid)
        .await
        .expect("dataset lookup should succeed")
        .expect("dataset artifact should exist in ChipStore");
    assert_eq!(dataset.chip_type, "ubl/audit.dataset.v1");
    assert_eq!(dataset.chip_data["@world"], json!("a/acme/t/prod"));
    assert_eq!(dataset.chip_data["line_count"], json!(1));
}

#[tokio::test]
async fn audit_snapshot_overlap_is_rejected() {
    use ubl_chipstore::{ChipStore, InMemoryBackend};

    let backend = Arc::new(InMemoryBackend::new());
    let chip_store = Arc::new(ChipStore::new(backend));
    let pipeline = UblPipeline::with_chip_store(Box::new(InMemoryPolicyStorage::new()), chip_store);

    let cap_sk = ubl_kms::generate_signing_key();
    let cap = signed_capability("audit:snapshot", "a/acme", &cap_sk);

    let first = ChipRequest {
        chip_type: "audit/ledger.snapshot.request.v1".to_string(),
        body: json!({
            "@type":"audit/ledger.snapshot.request.v1",
            "@id":"snap-1",
            "@ver":"1.0",
            "@world":"a/acme/t/prod",
            "range":{"start":"2026-02-18T00:00:00Z","end":"2026-02-18T01:00:00Z"},
            "@cap": cap
        }),
        parents: vec![],
        operation: Some("create".to_string()),
    };
    let first_result = pipeline.process_chip(first).await.unwrap();
    assert!(matches!(first_result.decision, Decision::Allow));

    let cap2 = signed_capability("audit:snapshot", "a/acme", &cap_sk);
    let second = ChipRequest {
        chip_type: "audit/ledger.snapshot.request.v1".to_string(),
        body: json!({
            "@type":"audit/ledger.snapshot.request.v1",
            "@id":"snap-2",
            "@ver":"1.0",
            "@world":"a/acme/t/prod",
            "range":{"start":"2026-02-18T00:30:00Z","end":"2026-02-18T01:30:00Z"},
            "@cap": cap2
        }),
        parents: vec![],
        operation: Some("create".to_string()),
    };
    let err = pipeline.process_chip(second).await.unwrap_err();
    assert!(matches!(err, PipelineError::InvalidChip(_)));
    assert!(err.to_string().to_lowercase().contains("snapshot overlap"));
}

#[tokio::test]
async fn audit_snapshot_generates_manifest_artifacts_and_links_in_wf() {
    use ubl_chipstore::{ChipStore, InMemoryBackend};

    let backend = Arc::new(InMemoryBackend::new());
    let chip_store = Arc::new(ChipStore::new(backend));
    let pipeline =
        UblPipeline::with_chip_store(Box::new(InMemoryPolicyStorage::new()), chip_store.clone());

    let cap_sk = ubl_kms::generate_signing_key();
    let cap = signed_capability("audit:snapshot", "a/acme", &cap_sk);
    let request = ChipRequest {
        chip_type: "audit/ledger.snapshot.request.v1".to_string(),
        body: json!({
            "@type":"audit/ledger.snapshot.request.v1",
            "@id":"snap-artifacts-1",
            "@ver":"1.0",
            "@world":"a/acme/t/prod",
            "range":{"start":"1970-01-01T00:00:00Z","end":"2999-01-01T00:00:00Z"},
            "@cap": cap
        }),
        parents: vec![],
        operation: Some("create".to_string()),
    };

    let result = pipeline.process_chip(request).await.unwrap();
    assert!(matches!(result.decision, Decision::Allow));

    let artifacts = result.final_receipt.body["artifacts"]
        .as_object()
        .expect("WF artifacts must exist");
    let manifest_cid = artifacts
        .get("manifest")
        .and_then(|v| v.as_str())
        .expect("manifest CID missing");
    let histograms_cid = artifacts
        .get("histograms")
        .and_then(|v| v.as_str())
        .expect("histograms CID missing");
    let sketches_cid = artifacts
        .get("sketches")
        .and_then(|v| v.as_str())
        .expect("sketches CID missing");
    assert!(manifest_cid.starts_with("b3:"));
    assert!(histograms_cid.starts_with("b3:"));
    assert!(sketches_cid.starts_with("b3:"));

    let manifest_chip = chip_store
        .get_chip(manifest_cid)
        .await
        .unwrap()
        .expect("manifest chip must exist");
    assert_eq!(manifest_chip.chip_type, "ubl/audit.snapshot.manifest.v1");
}

#[tokio::test]
async fn ledger_compact_generates_rollup_artifact() {
    use ubl_chipstore::{ChipStore, InMemoryBackend};

    let backend = Arc::new(InMemoryBackend::new());
    let chip_store = Arc::new(ChipStore::new(backend));
    let pipeline =
        UblPipeline::with_chip_store(Box::new(InMemoryPolicyStorage::new()), chip_store.clone());

    let cap_sk = ubl_kms::generate_signing_key();
    let snap_cap = signed_capability("audit:snapshot", "a/acme", &cap_sk);
    let snapshot_req = ChipRequest {
        chip_type: "audit/ledger.snapshot.request.v1".to_string(),
        body: json!({
            "@type":"audit/ledger.snapshot.request.v1",
            "@id":"snap-for-compact-1",
            "@ver":"1.0",
            "@world":"a/acme/t/prod",
            "range":{"start":"1970-01-01T00:00:00Z","end":"2999-01-01T00:00:00Z"},
            "@cap": snap_cap
        }),
        parents: vec![],
        operation: Some("create".to_string()),
    };
    let snapshot = pipeline.process_chip(snapshot_req).await.unwrap();

    let tmp = tempfile::tempdir().unwrap();
    std::env::set_var("UBL_LEDGER_BASE_DIR", tmp.path());
    let seg_rel_path = "segments/seg-1.ndjson";
    let seg_abs_path = tmp.path().join(seg_rel_path);
    std::fs::create_dir_all(seg_abs_path.parent().unwrap()).unwrap();
    let seg_content = b"{\"a\":1}\n{\"a\":2}\n{\"a\":3}";
    std::fs::write(&seg_abs_path, seg_content).unwrap();
    let seg_sha = {
        use ring::digest;
        let hash = digest::digest(&digest::SHA256, seg_content);
        hex::encode(hash.as_ref())
    };

    let compact_cap = signed_capability("ledger:compact", "a/acme", &cap_sk);
    let compact_req = ChipRequest {
        chip_type: "ledger/segment.compact.v1".to_string(),
        body: json!({
            "@type":"ledger/segment.compact.v1",
            "@id":"compact-1",
            "@ver":"1.0",
            "@world":"a/acme/t/prod",
            "range":{"start":"2026-02-18T00:00:00Z","end":"2026-02-18T00:10:00Z"},
            "snapshot_ref": snapshot.receipt.receipt_cid.as_str(),
            "source_segments":[{"path":seg_rel_path,"sha256":seg_sha,"lines":3}],
            "mode":"delete_with_rollup",
            "@cap": compact_cap
        }),
        parents: vec![],
        operation: Some("create".to_string()),
    };

    let compact = pipeline.process_chip(compact_req).await.unwrap();
    assert!(matches!(compact.decision, Decision::Allow));

    let rollup_cid = compact.final_receipt.body["artifacts"]["rollup_index"]
        .as_str()
        .expect("WF artifacts.rollup_index must exist");
    let rollup_chip = chip_store
        .get_chip(rollup_cid)
        .await
        .unwrap()
        .expect("rollup chip must exist");
    assert_eq!(rollup_chip.chip_type, "ubl/ledger.compaction.rollup.v1");
    assert!(
        !seg_abs_path.exists(),
        "segment file must be removed by delete_with_rollup"
    );
    std::env::remove_var("UBL_LEDGER_BASE_DIR");
}

#[tokio::test]
async fn audit_advisory_requires_subject_receipt() {
    use ubl_chipstore::{ChipStore, InMemoryBackend};

    let backend = Arc::new(InMemoryBackend::new());
    let chip_store = Arc::new(ChipStore::new(backend));
    let pipeline = UblPipeline::with_chip_store(Box::new(InMemoryPolicyStorage::new()), chip_store);

    let cap_sk = ubl_kms::generate_signing_key();
    let cap = signed_capability("audit:advisory", "a/acme", &cap_sk);

    let request = ChipRequest {
        chip_type: "audit/advisory.request.v1".to_string(),
        body: json!({
            "@type":"audit/advisory.request.v1",
            "@id":"adv-1",
            "@ver":"1.0",
            "@world":"a/acme/t/prod",
            "subject":{"kind":"report","receipt_cid":"b3:missing"},
            "inputs":{"dataset_cid":"b3:data"},
            "policy_cid":"b3:policy",
            "@cap": cap
        }),
        parents: vec![],
        operation: Some("create".to_string()),
    };
    let err = pipeline.process_chip(request).await.unwrap_err();
    assert!(matches!(err, PipelineError::InvalidChip(_)));
    assert!(err.to_string().contains("subject receipt not found"));
}

#[tokio::test]
async fn audit_advisory_generates_json_and_markdown_artifacts() {
    use ubl_chipstore::{ChipStore, InMemoryBackend};

    let backend = Arc::new(InMemoryBackend::new());
    let chip_store = Arc::new(ChipStore::new(backend));
    let pipeline =
        UblPipeline::with_chip_store(Box::new(InMemoryPolicyStorage::new()), chip_store.clone());

    let cap_sk = ubl_kms::generate_signing_key();
    let report_cap = signed_capability("audit:report", "a/acme", &cap_sk);
    let report_req = ChipRequest {
        chip_type: "audit/report.request.v1".to_string(),
        body: json!({
            "@type":"audit/report.request.v1",
            "@id":"audit-report-for-advisory-1",
            "@ver":"1.0",
            "@world":"a/acme/t/prod",
            "window":"5m",
            "format":"ndjson",
            "@cap": report_cap
        }),
        parents: vec![],
        operation: Some("create".to_string()),
    };
    let report = pipeline.process_chip(report_req).await.unwrap();

    let advisory_cap = signed_capability("audit:advisory", "a/acme", &cap_sk);
    let advisory_req = ChipRequest {
        chip_type: "audit/advisory.request.v1".to_string(),
        body: json!({
            "@type":"audit/advisory.request.v1",
            "@id":"adv-ok-1",
            "@ver":"1.0",
            "@world":"a/acme/t/prod",
            "subject":{"kind":"report","receipt_cid": report.receipt.receipt_cid.as_str()},
            "inputs":{"dataset_cid":"b3:example"},
            "policy_cid":"b3:policy",
            "style":"concise",
            "lang":"en",
            "@cap": advisory_cap
        }),
        parents: vec![],
        operation: Some("create".to_string()),
    };

    let advisory = pipeline.process_chip(advisory_req).await.unwrap();
    assert!(matches!(advisory.decision, Decision::Allow));

    let advisory_json_cid = advisory.final_receipt.body["artifacts"]["advisory_json"]
        .as_str()
        .expect("advisory_json CID missing");
    let advisory_md_cid = advisory.final_receipt.body["artifacts"]["advisory_markdown"]
        .as_str()
        .expect("advisory_markdown CID missing");
    let advisory_json_chip = chip_store
        .get_chip(advisory_json_cid)
        .await
        .unwrap()
        .expect("advisory json artifact must exist");
    let advisory_md_chip = chip_store
        .get_chip(advisory_md_cid)
        .await
        .unwrap()
        .expect("advisory markdown artifact must exist");
    assert_eq!(advisory_json_chip.chip_type, "ubl/audit.advisory.result.v1");
    assert_eq!(advisory_md_chip.chip_type, "ubl/audit.advisory.markdown.v1");
}

#[test]
fn tr_profile_selection_by_chip_type() {
    let registry = TransitionRegistry::default();
    assert_eq!(
        TransitionRegistry::default_profile_for("ubl/document"),
        TrBytecodeProfile::PassV1
    );
    assert_eq!(
        TransitionRegistry::default_profile_for("ubl/token"),
        TrBytecodeProfile::AuditV1
    );
    assert_eq!(
        TransitionRegistry::default_profile_for("ubl/payment"),
        TrBytecodeProfile::NumericV1
    );
    let resolved = registry
        .resolve("ubl/token", &json!({"@type":"ubl/token"}))
        .unwrap();
    assert_eq!(resolved.profile, TrBytecodeProfile::AuditV1);
}

#[test]
fn resolve_transition_bytecode_prefers_chip_override() {
    let registry = TransitionRegistry::default();
    let request = ChipRequest {
        chip_type: "ubl/document".to_string(),
        body: json!({
            "@type": "ubl/document",
            "@id": "override-bytecode",
            "@ver": "1.0",
            "@world": "a/app/t/ten",
            "@tr": {
                "bytecode_hex": "1200020000100000"
            }
        }),
        parents: vec![],
        operation: Some("create".to_string()),
    };

    let resolved = registry.resolve(&request.chip_type, &request.body).unwrap();
    assert_eq!(resolved.source, "chip:@tr.bytecode_hex");
    assert_eq!(
        resolved.bytecode,
        vec![0x12, 0x00, 0x02, 0x00, 0x00, 0x10, 0x00, 0x00]
    );
}

#[test]
fn wasm_adapter_hash_and_abi_verified() {
    let good = json!({
        "adapter": {
            "wasm_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "abi_version": "1.0"
        }
    });
    assert!(AdapterRuntimeInfo::parse_optional(&good).unwrap().is_some());

    let bad_hash = json!({
        "adapter": {
            "wasm_sha256": "not-hex",
            "abi_version": "1.0"
        }
    });
    assert!(matches!(
        AdapterRuntimeInfo::parse_optional(&bad_hash),
        Err(PipelineError::InvalidChip(_))
    ));

    let bad_abi = json!({
        "adapter": {
            "wasm_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "abi_version": "2.0"
        }
    });
    assert!(matches!(
        AdapterRuntimeInfo::parse_optional(&bad_abi),
        Err(PipelineError::InvalidChip(_))
    ));
}

#[tokio::test]
async fn policy_trace_has_rb_votes() {
    let storage = InMemoryPolicyStorage::new();
    let pipeline = UblPipeline::new(Box::new(storage));

    // ALLOW path — genesis policy has RBs that vote
    let request = ChipRequest {
        chip_type: "ubl/document".to_string(),
        body: json!({
            "@type": "ubl/document",
            "@id": "trace-test",
            "@ver": "1.0",
            "@world": "a/app/t/ten"
        }),
        parents: vec![],
        operation: Some("create".to_string()),
    };

    let result = pipeline.process_chip(request).await.unwrap();
    assert!(matches!(result.decision, Decision::Allow));

    let wf = &result.final_receipt.body;
    let trace = wf["policy_trace"].as_array().unwrap();
    assert!(!trace.is_empty(), "policy_trace must have entries");

    // Each trace entry should have rb_results with individual votes
    let first = &trace[0];
    assert!(first["policy_id"].is_string());
    let rbs = first["rb_results"].as_array().unwrap();
    assert!(
        !rbs.is_empty(),
        "rb_results must expose individual RB votes"
    );

    // Each RB result should have rb_id, decision, reason
    let rb = &rbs[0];
    assert!(rb["rb_id"].is_string());
    assert!(rb["decision"].is_string());
    assert!(rb["reason"].is_string());
}

#[tokio::test]
async fn deny_trace_has_rb_votes() {
    let storage = InMemoryPolicyStorage::new();
    let pipeline = UblPipeline::new(Box::new(storage));

    // DENY path — evil type triggers genesis deny
    let request = ChipRequest {
        chip_type: "evil/hack".to_string(),
        body: json!({
            "@type": "evil/hack",
            "@id": "x",
            "@ver": "1.0",
            "@world": "a/x/t/y"
        }),
        parents: vec![],
        operation: Some("create".to_string()),
    };

    let result = pipeline.process_chip(request).await.unwrap();
    assert!(matches!(result.decision, Decision::Deny));

    let wf = &result.final_receipt.body;
    let trace = wf["policy_trace"].as_array().unwrap();
    assert!(!trace.is_empty());

    // The deny trace should show which RB denied
    let deny_entry = &trace[trace.len() - 1];
    assert_eq!(deny_entry["result"], "Deny");
    let rbs = deny_entry["rb_results"].as_array().unwrap();
    assert!(!rbs.is_empty(), "deny trace must show which RB denied");
}

#[tokio::test]
async fn pipeline_rejects_missing_world() {
    let storage = InMemoryPolicyStorage::new();
    let pipeline = UblPipeline::new(Box::new(storage));

    let request = ChipRequest {
        chip_type: "ubl/document".to_string(),
        body: json!({
            "@type": "ubl/document",
            "@id": "no-world",
            "@ver": "1.0"
        }),
        parents: vec![],
        operation: Some("create".to_string()),
    };

    let err = pipeline.process_chip(request).await.unwrap_err();
    assert!(matches!(err, PipelineError::InvalidChip(_)));
    assert!(err.to_string().contains("@world"));
}

#[tokio::test]
async fn pipeline_rejects_invalid_world_format() {
    let storage = InMemoryPolicyStorage::new();
    let pipeline = UblPipeline::new(Box::new(storage));

    let request = ChipRequest {
        chip_type: "ubl/document".to_string(),
        body: json!({
            "@type": "ubl/document",
            "@id": "bad-world",
            "@ver": "1.0",
            "@world": "not-a-valid-world"
        }),
        parents: vec![],
        operation: Some("create".to_string()),
    };

    let err = pipeline.process_chip(request).await.unwrap_err();
    assert!(matches!(err, PipelineError::InvalidChip(_)));
}

#[tokio::test]
async fn pipeline_wa_has_nonce_and_kid() {
    let storage = InMemoryPolicyStorage::new();
    let event_bus = Arc::new(EventBus::new());
    let pipeline = UblPipeline::with_event_bus(Box::new(storage), event_bus.clone());
    let mut rx = event_bus.subscribe();

    let request = ChipRequest {
        chip_type: "ubl/document".to_string(),
        body: json!({
            "@type": "ubl/document",
            "@id": "nonce-test",
            "@ver": "1.0",
            "@world": "a/app/t/ten"
        }),
        parents: vec![],
        operation: Some("create".to_string()),
    };

    let _result = pipeline.process_chip(request).await.unwrap();

    // WA event is first
    let wa_event = rx.try_recv().unwrap();
    assert_eq!(wa_event.pipeline_stage, "wa");

    // WA metadata must contain nonce and kid
    let nonce = wa_event.metadata.get("nonce").and_then(|v| v.as_str());
    assert!(nonce.is_some(), "WA receipt must have nonce");
    assert_eq!(
        nonce.unwrap().len(),
        32,
        "nonce must be 32 hex chars (16 bytes)"
    );

    let kid = wa_event.metadata.get("kid").and_then(|v| v.as_str());
    assert!(kid.is_some(), "WA receipt must have kid");
}

#[tokio::test]
async fn pipeline_nonces_are_unique() {
    let storage = InMemoryPolicyStorage::new();
    let pipeline = UblPipeline::new(Box::new(storage));

    let mut nonces = std::collections::HashSet::new();
    for i in 0..10 {
        let request = ChipRequest {
            chip_type: "ubl/document".to_string(),
            body: json!({
                "@type": "ubl/document",
                "@id": format!("doc-{}", i),
                "@ver": "1.0",
                "@world": "a/app/t/ten"
            }),
            parents: vec![],
            operation: Some("create".to_string()),
        };
        let result = pipeline.process_chip(request).await.unwrap();
        // Extract nonce from WA receipt body (it's in the chain)
        let wa_cid = &result.chain[0];
        assert!(
            nonces.insert(wa_cid.clone()),
            "WA CIDs must be unique (nonce ensures this)"
        );
    }
    assert_eq!(nonces.len(), 10);
}

#[tokio::test]
async fn chipstore_persists_after_allow() {
    use ubl_chipstore::{ChipStore, InMemoryBackend};

    let policy_storage = InMemoryPolicyStorage::new();
    let backend = Arc::new(InMemoryBackend::new());
    let chip_store = Arc::new(ChipStore::new(backend.clone()));
    let pipeline = UblPipeline::with_chip_store(Box::new(policy_storage), chip_store.clone());

    let request = ChipRequest {
        chip_type: "ubl/document".to_string(),
        body: json!({
            "@type": "ubl/document",
            "@id": "persist-test",
            "@ver": "1.0",
            "@world": "a/app/t/ten",
            "title": "Test Document"
        }),
        parents: vec![],
        operation: Some("create".to_string()),
    };

    let result = pipeline.process_chip(request).await.unwrap();
    assert!(matches!(result.decision, Decision::Allow));

    // Chip should be persisted in the store
    // Compute the expected CID
    let chip_body = json!({
        "@type": "ubl/document",
        "@id": "persist-test",
        "@ver": "1.0",
        "@world": "a/app/t/ten",
        "title": "Test Document"
    });
    let nrf = ubl_ai_nrf1::to_nrf1_bytes(&chip_body).unwrap();
    let expected_cid = ubl_ai_nrf1::compute_cid(&nrf).unwrap();

    let stored = chip_store.get_chip(&expected_cid).await.unwrap();
    assert!(stored.is_some(), "chip must be persisted after allow");
    let stored = stored.unwrap();
    assert_eq!(stored.chip_type, "ubl/document");
    assert_eq!(
        stored.receipt_cid.as_str(),
        result.receipt.receipt_cid.as_str()
    );

    let by_receipt = chip_store
        .get_chip_by_receipt_cid(result.receipt.receipt_cid.as_str())
        .await
        .unwrap();
    assert!(
        by_receipt.is_some(),
        "receipt_cid lookup must resolve stored chip"
    );
}

#[tokio::test]
async fn chipstore_not_called_on_deny() {
    use ubl_chipstore::{ChipStore, InMemoryBackend};

    let policy_storage = InMemoryPolicyStorage::new();
    let backend = Arc::new(InMemoryBackend::new());
    let chip_store = Arc::new(ChipStore::new(backend.clone()));
    let pipeline = UblPipeline::with_chip_store(Box::new(policy_storage), chip_store.clone());

    let request = ChipRequest {
        chip_type: "evil/hack".to_string(),
        body: json!({
            "@type": "evil/hack",
            "@id": "x",
            "@ver": "1.0",
            "@world": "a/x/t/y"
        }),
        parents: vec![],
        operation: Some("create".to_string()),
    };

    let result = pipeline.process_chip(request).await.unwrap();
    assert!(matches!(result.decision, Decision::Deny));

    // Denied chips should NOT be stored
    let query = ubl_chipstore::ChipQuery {
        chip_type: Some("evil/hack".to_string()),
        tags: vec![],
        created_after: None,
        created_before: None,
        executor_did: None,
        limit: None,
        offset: None,
    };
    let found = chip_store.query(&query).await.unwrap();
    assert_eq!(found.total_count, 0, "denied chips must not be persisted");
}

#[tokio::test]
async fn event_bus_receives_pipeline_events() {
    let storage = InMemoryPolicyStorage::new();
    let event_bus = Arc::new(EventBus::new());
    let pipeline = UblPipeline::with_event_bus(Box::new(storage), event_bus.clone());

    let mut rx = event_bus.subscribe();

    let request = ChipRequest {
        chip_type: "ubl/document".to_string(),
        body: json!({
            "@type": "ubl/document",
            "@id": "eve",
            "@ver": "1.0",
            "@world": "a/app/t/ten"
        }),
        parents: vec![],
        operation: Some("create".to_string()),
    };

    let _result = pipeline.process_chip(request).await.unwrap();

    // Should have received WA, TR, WF events
    let count = event_bus.event_count().await;
    assert!(
        count >= 3,
        "expected at least 3 events (WA+TR+WF), got {}",
        count
    );

    // First event should be WA
    let wa_event = rx.try_recv().unwrap();
    assert_eq!(wa_event.pipeline_stage, "wa");
}

#[tokio::test]
async fn stage_events_have_canonical_fields() {
    let storage = InMemoryPolicyStorage::new();
    let event_bus = Arc::new(EventBus::new());
    let pipeline = UblPipeline::with_event_bus(Box::new(storage), event_bus.clone());
    let mut rx = event_bus.subscribe();

    let request = ChipRequest {
        chip_type: "ubl/document".to_string(),
        body: json!({
            "@type": "ubl/document",
            "@id": "canonical-evt",
            "@ver": "1.0",
            "@world": "a/app/t/ten"
        }),
        parents: vec![],
        operation: Some("create".to_string()),
    };

    let _result = pipeline.process_chip(request).await.unwrap();

    // Collect all events
    let mut events = vec![];
    while let Ok(ev) = rx.try_recv() {
        events.push(ev);
    }
    assert!(events.len() >= 3, "need WA+TR+WF, got {}", events.len());

    // Every event must have canonical fields
    for ev in &events {
        assert!(
            ev.world.is_some(),
            "stage {} missing world",
            ev.pipeline_stage
        );
        assert_eq!(ev.world.as_deref(), Some("a/app/t/ten"));
        assert!(
            ev.actor.is_some(),
            "stage {} missing actor",
            ev.pipeline_stage
        );
        assert!(
            ev.actor.as_ref().unwrap().starts_with("did:key:"),
            "actor must be a DID"
        );
        assert!(
            ev.binary_hash.is_some(),
            "stage {} missing binary_hash",
            ev.pipeline_stage
        );
        assert!(
            ev.output_cid.is_some(),
            "stage {} missing output_cid",
            ev.pipeline_stage
        );
        assert!(
            ev.latency_ms.is_some(),
            "stage {} missing latency_ms",
            ev.pipeline_stage
        );
    }

    // WA has no input_cid (it's the first stage)
    let wa = events.iter().find(|e| e.pipeline_stage == "wa").unwrap();
    assert!(wa.input_cid.is_none(), "WA should have no input_cid");

    // TR has input_cid = WA output
    let tr = events.iter().find(|e| e.pipeline_stage == "tr").unwrap();
    assert!(tr.input_cid.is_some(), "TR must have input_cid");
    assert_eq!(
        tr.input_cid.as_deref(),
        wa.output_cid.as_deref(),
        "TR input = WA output"
    );

    // WF has input_cid = TR output
    let wf = events.iter().find(|e| e.pipeline_stage == "wf").unwrap();
    assert!(wf.input_cid.is_some(), "WF must have input_cid");
    assert_eq!(
        wf.input_cid.as_deref(),
        tr.output_cid.as_deref(),
        "WF input = TR output"
    );
    assert_eq!(wf.decision.as_deref(), Some("allow"));
}

#[tokio::test]
async fn unified_receipt_has_all_stages_on_allow() {
    let storage = InMemoryPolicyStorage::new();
    let pipeline = UblPipeline::new(Box::new(storage));

    let request = ChipRequest {
        chip_type: "ubl/document".to_string(),
        body: json!({
            "@type": "ubl/document",
            "@id": "unified-test",
            "@ver": "1.0",
            "@world": "a/app/t/ten"
        }),
        parents: vec![],
        operation: Some("create".to_string()),
    };

    let result = pipeline.process_chip(request).await.unwrap();
    let r = &result.receipt;

    // Must have 4 stages: WA, CHECK, TR, WF
    assert_eq!(r.stage_count(), 4);
    assert!(r.has_stage(PipelineStage::WriteAhead));
    assert!(r.has_stage(PipelineStage::Check));
    assert!(r.has_stage(PipelineStage::Transition));
    assert!(r.has_stage(PipelineStage::WriteFinished));

    // Receipt CID must be set
    assert!(
        r.receipt_cid.as_str().starts_with("b3:"),
        "receipt_cid must be BLAKE3"
    );
    assert_eq!(r.id, r.receipt_cid.as_str(), "@id must equal receipt_cid");

    // Envelope anchors
    assert_eq!(r.receipt_type, "ubl/receipt");
    assert_eq!(r.world.as_str(), "a/app/t/ten");
    assert_eq!(r.ver, "1.0");

    // Auth tokens present on every stage
    for stage in &r.stages {
        assert!(
            stage.auth_token.starts_with("hmac:"),
            "stage {:?} missing auth_token",
            stage.stage
        );
    }

    // Decision is Allow
    assert_eq!(r.decision, Decision::Allow);
}

#[tokio::test]
async fn unified_receipt_deny_has_wf_and_no_tr() {
    let storage = InMemoryPolicyStorage::new();
    let pipeline = UblPipeline::new(Box::new(storage));

    let request = ChipRequest {
        chip_type: "evil/hack".to_string(),
        body: json!({
            "@type": "evil/hack",
            "@id": "x",
            "@ver": "1.0",
            "@world": "a/x/t/y"
        }),
        parents: vec![],
        operation: Some("create".to_string()),
    };

    let result = pipeline.process_chip(request).await.unwrap();
    let r = &result.receipt;

    // Deny path: WA + CHECK + WF (no TR)
    assert_eq!(r.stage_count(), 3);
    assert!(r.has_stage(PipelineStage::WriteAhead));
    assert!(r.has_stage(PipelineStage::Check));
    assert!(!r.has_stage(PipelineStage::Transition));
    assert!(r.has_stage(PipelineStage::WriteFinished));

    assert_eq!(r.decision, Decision::Deny);
    assert!(r.effects["deny_reason"].is_string());
}

#[tokio::test]
async fn unified_receipt_check_stage_has_policy_trace() {
    let storage = InMemoryPolicyStorage::new();
    let pipeline = UblPipeline::new(Box::new(storage));

    let request = ChipRequest {
        chip_type: "ubl/document".to_string(),
        body: json!({
            "@type": "ubl/document",
            "@id": "trace-unified",
            "@ver": "1.0",
            "@world": "a/app/t/ten"
        }),
        parents: vec![],
        operation: Some("create".to_string()),
    };

    let result = pipeline.process_chip(request).await.unwrap();
    let r = &result.receipt;

    // CHECK stage should have policy_trace with RB votes
    let check_stage = r
        .stages
        .iter()
        .find(|s| s.stage == PipelineStage::Check)
        .unwrap();
    assert!(
        !check_stage.policy_trace.is_empty(),
        "CHECK stage must have policy trace"
    );
    assert!(
        !check_stage.policy_trace[0].rb_results.is_empty(),
        "policy trace must have RB votes"
    );
}

#[tokio::test]
async fn unified_receipt_tr_stage_has_fuel() {
    let storage = InMemoryPolicyStorage::new();
    let pipeline = UblPipeline::new(Box::new(storage));

    let request = ChipRequest {
        chip_type: "ubl/document".to_string(),
        body: json!({
            "@type": "ubl/document",
            "@id": "fuel-test",
            "@ver": "1.0",
            "@world": "a/app/t/ten"
        }),
        parents: vec![],
        operation: Some("create".to_string()),
    };

    let result = pipeline.process_chip(request).await.unwrap();
    let r = &result.receipt;

    let tr_stage = r
        .stages
        .iter()
        .find(|s| s.stage == PipelineStage::Transition)
        .unwrap();
    assert!(
        tr_stage.fuel_used.is_some(),
        "TR stage must record fuel_used"
    );
    assert!(
        tr_stage.output_cid.is_some(),
        "TR stage must have output_cid"
    );
}

#[tokio::test]
async fn bootstrap_genesis_stores_chip_in_chipstore() {
    use ubl_chipstore::{ChipStore, InMemoryBackend};

    let policy_storage = InMemoryPolicyStorage::new();
    let backend = Arc::new(InMemoryBackend::new());
    let chip_store = Arc::new(ChipStore::new(backend.clone()));
    let pipeline = UblPipeline::with_chip_store(Box::new(policy_storage), chip_store.clone());

    let genesis_cid = pipeline.bootstrap_genesis().await.unwrap();

    // Genesis CID must be deterministic and start with b3:
    assert!(genesis_cid.starts_with("b3:"));
    assert_eq!(genesis_cid, crate::genesis::genesis_chip_cid());

    // Must be stored in ChipStore
    let stored = chip_store.get_chip(&genesis_cid).await.unwrap();
    assert!(
        stored.is_some(),
        "Genesis chip must be in ChipStore after bootstrap"
    );

    let chip = stored.unwrap();
    assert_eq!(chip.chip_type, "ubl/policy.genesis");
    assert_eq!(
        chip.receipt_cid.as_str(),
        genesis_cid,
        "Genesis is self-signed: receipt_cid == chip_cid"
    );
    assert_eq!(
        chip.execution_metadata.executor_did.as_str(),
        "did:key:genesis"
    );
    assert!(chip.execution_metadata.reproducible);
}

#[tokio::test]
async fn bootstrap_genesis_is_idempotent() {
    use ubl_chipstore::{ChipStore, InMemoryBackend};

    let policy_storage = InMemoryPolicyStorage::new();
    let backend = Arc::new(InMemoryBackend::new());
    let chip_store = Arc::new(ChipStore::new(backend.clone()));
    let pipeline = UblPipeline::with_chip_store(Box::new(policy_storage), chip_store.clone());

    let cid1 = pipeline.bootstrap_genesis().await.unwrap();
    let cid2 = pipeline.bootstrap_genesis().await.unwrap();

    assert_eq!(cid1, cid2, "Idempotent: same CID on repeated bootstrap");
}

#[tokio::test]
async fn bootstrap_genesis_without_chipstore_returns_cid() {
    let policy_storage = InMemoryPolicyStorage::new();
    let pipeline = UblPipeline::new(Box::new(policy_storage));

    // Even without ChipStore, bootstrap should return the genesis CID
    let genesis_cid = pipeline.bootstrap_genesis().await.unwrap();
    assert!(genesis_cid.starts_with("b3:"));
}

#[tokio::test]
async fn advisory_engine_produces_post_wf_chip() {
    use crate::advisory::AdvisoryEngine;
    use ubl_chipstore::{ChipStore, InMemoryBackend};

    let policy_storage = InMemoryPolicyStorage::new();
    let backend = Arc::new(InMemoryBackend::new());
    let chip_store = Arc::new(ChipStore::new(backend.clone()));
    let mut pipeline = UblPipeline::with_chip_store(Box::new(policy_storage), chip_store.clone());

    let engine = Arc::new(AdvisoryEngine::new(
        "b3:test-passport".to_string(),
        "test-model".to_string(),
        "a/test/t/test".to_string(),
    ));
    pipeline.set_advisory_engine(engine);

    let request = ChipRequest {
        chip_type: "ubl/document".to_string(),
        body: json!({
            "@type": "ubl/document",
            "@id": "adv-test",
            "@ver": "1.0",
            "@world": "a/test/t/test",
            "id": "adv-test"
        }),
        parents: vec![],
        operation: Some("create".to_string()),
    };

    let result = pipeline.process_chip(request).await.unwrap();
    assert!(matches!(result.decision, Decision::Allow));

    // Give the spawned advisory task time to complete
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Query ChipStore for advisory chips
    let query = ubl_chipstore::ChipQuery {
        chip_type: Some("ubl/advisory".to_string()),
        tags: vec![],
        created_after: None,
        created_before: None,
        executor_did: None,
        limit: Some(10),
        offset: None,
    };
    let results = chip_store.query(&query).await.unwrap();
    assert!(
        results.total_count >= 1,
        "At least one advisory chip should be stored (post-CHECK or post-WF)"
    );

    let adv_chip = &results.chips[0];
    assert_eq!(adv_chip.chip_type, "ubl/advisory");
    assert_eq!(adv_chip.chip_data["passport_cid"], "b3:test-passport");
}

#[tokio::test]
async fn advisory_engine_fires_on_deny() {
    use crate::advisory::AdvisoryEngine;
    use ubl_chipstore::{ChipStore, InMemoryBackend};

    let policy_storage = InMemoryPolicyStorage::new();
    let backend = Arc::new(InMemoryBackend::new());
    let chip_store = Arc::new(ChipStore::new(backend.clone()));
    let mut pipeline = UblPipeline::with_chip_store(Box::new(policy_storage), chip_store.clone());

    let engine = Arc::new(AdvisoryEngine::new(
        "b3:test-passport".to_string(),
        "test-model".to_string(),
        "a/test/t/test".to_string(),
    ));
    pipeline.set_advisory_engine(engine);

    // This should be denied by genesis (evil type)
    let request = ChipRequest {
        chip_type: "evil/hack".to_string(),
        body: json!({
            "@type": "evil/hack",
            "@id": "bad",
            "@ver": "1.0",
            "@world": "a/test/t/test",
            "id": "bad"
        }),
        parents: vec![],
        operation: Some("create".to_string()),
    };

    let result = pipeline.process_chip(request).await.unwrap();
    assert!(matches!(result.decision, Decision::Deny));

    // Give the spawned advisory task time to complete
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Post-CHECK advisory should fire even on deny
    let query = ubl_chipstore::ChipQuery {
        chip_type: Some("ubl/advisory".to_string()),
        tags: vec![],
        created_after: None,
        created_before: None,
        executor_did: None,
        limit: Some(10),
        offset: None,
    };
    let results = chip_store.query(&query).await.unwrap();
    assert!(
        results.total_count >= 1,
        "Post-CHECK advisory should fire on deny"
    );

    let adv_chip = &results.chips[0];
    assert_eq!(adv_chip.chip_data["action"], "explain_check");
}

// ══════════════════════════════════════════════════════════════
// Onboarding Integration Tests — full dependency chain
// ══════════════════════════════════════════════════════════════

/// Helper: create a pipeline with ChipStore for onboarding tests.
fn onboarding_pipeline() -> (UblPipeline, Arc<ubl_chipstore::ChipStore>) {
    use ubl_chipstore::{ChipStore, InMemoryBackend};

    let policy_storage = InMemoryPolicyStorage::new();
    let backend = Arc::new(InMemoryBackend::new());
    let chip_store = Arc::new(ChipStore::new(backend));
    let pipeline = UblPipeline::with_chip_store(Box::new(policy_storage), chip_store.clone());
    (pipeline, chip_store)
}

/// Helper: create a valid @cap for testing.
fn test_cap(action: &str, audience: &str) -> serde_json::Value {
    let sk = ubl_kms::generate_signing_key();
    let vk = ubl_kms::verifying_key(&sk);
    let issued_by = ubl_kms::did_from_verifying_key(&vk);
    let payload = json!({
        "action": action,
        "audience": audience,
        "issued_by": issued_by,
        "issued_at": "2025-01-01T00:00:00Z",
        "expires_at": "2099-12-31T23:59:59Z",
    });
    let signature = ubl_kms::sign_canonical(&sk, &payload, ubl_kms::domain::CAPABILITY)
        .expect("test capability must sign");
    json!({
        "action": payload["action"],
        "audience": payload["audience"],
        "issued_by": payload["issued_by"],
        "issued_at": payload["issued_at"],
        "expires_at": payload["expires_at"],
        "signature": signature,
    })
}

/// Helper: compute CID for a chip body.
fn chip_cid(body: &serde_json::Value) -> String {
    let nrf = ubl_ai_nrf1::to_nrf1_bytes(body).unwrap();
    ubl_ai_nrf1::compute_cid(&nrf).unwrap()
}

/// Helper: submit a chip and assert Allow.
async fn submit_allow(
    pipeline: &UblPipeline,
    chip_type: &str,
    body: serde_json::Value,
) -> PipelineResult {
    let request = ChipRequest {
        chip_type: chip_type.to_string(),
        body,
        parents: vec![],
        operation: Some("create".to_string()),
    };
    let result = pipeline.process_chip(request).await.unwrap();
    assert!(
        matches!(result.decision, Decision::Allow),
        "expected Allow for {}",
        chip_type
    );
    result
}

/// Helper: submit a chip and assert it fails with a specific error variant.
async fn submit_expect_err(
    pipeline: &UblPipeline,
    chip_type: &str,
    body: serde_json::Value,
) -> PipelineError {
    let request = ChipRequest {
        chip_type: chip_type.to_string(),
        body,
        parents: vec![],
        operation: Some("create".to_string()),
    };
    pipeline.process_chip(request).await.unwrap_err()
}

#[tokio::test]
async fn onboarding_full_flow_app_to_token() {
    let (pipeline, _store) = onboarding_pipeline();

    // 1. Register app (requires registry:init cap)
    let app_body = json!({
        "@type": "ubl/app",
        "@id": "app-acme",
        "@ver": "1.0",
        "@world": "a/acme",
        "slug": "acme",
        "display_name": "Acme Corp",
        "owner_did": "did:key:z6MkOwner",
        "@cap": test_cap("registry:init", "a/acme")
    });
    submit_allow(&pipeline, "ubl/app", app_body.clone()).await;

    // 2. Register first user (requires registry:init cap for first user)
    let user_body = json!({
        "@type": "ubl/user",
        "@id": "user-alice",
        "@ver": "1.0",
        "@world": "a/acme",
        "did": "did:key:z6MkAlice",
        "display_name": "Alice",
        "@cap": test_cap("registry:init", "a/acme")
    });
    let user_cid = chip_cid(&user_body);
    submit_allow(&pipeline, "ubl/user", user_body).await;

    // 3. Create tenant (depends on app + creator user)
    let tenant_body = json!({
        "@type": "ubl/tenant",
        "@id": "tenant-eng",
        "@ver": "1.0",
        "@world": "a/acme",
        "slug": "engineering",
        "display_name": "Engineering Circle",
        "creator_cid": user_cid
    });
    let tenant_cid = chip_cid(&tenant_body);
    submit_allow(&pipeline, "ubl/tenant", tenant_body).await;

    // 4. Create membership (depends on user + tenant, requires membership:grant cap)
    let membership_body = json!({
        "@type": "ubl/membership",
        "@id": "mem-alice-eng",
        "@ver": "1.0",
        "@world": format!("a/acme/t/engineering"),
        "user_cid": user_cid,
        "tenant_cid": tenant_cid,
        "role": "admin",
        "@cap": test_cap("membership:grant", "a/acme")
    });
    submit_allow(&pipeline, "ubl/membership", membership_body).await;

    // 5. Create token (depends on user)
    let token_body = json!({
        "@type": "ubl/token",
        "@id": "tok-alice-1",
        "@ver": "1.0",
        "@world": "a/acme",
        "user_cid": user_cid,
        "scope": ["read", "write"],
        "expires_at": "2027-12-31T23:59:59Z",
        "kid": "did:key:z6MkAlice#v0"
    });
    submit_allow(&pipeline, "ubl/token", token_body).await;
}

#[tokio::test]
async fn onboarding_user_without_app_fails() {
    let (pipeline, _store) = onboarding_pipeline();

    // Try to register user without an app — should fail with DependencyMissing
    let user_body = json!({
        "@type": "ubl/user",
        "@id": "user-orphan",
        "@ver": "1.0",
        "@world": "a/nonexistent",
        "did": "did:key:z6MkOrphan",
        "display_name": "Orphan"
    });
    let err = submit_expect_err(&pipeline, "ubl/user", user_body).await;
    assert!(
        matches!(err, PipelineError::DependencyMissing(_)),
        "expected DependencyMissing, got: {}",
        err
    );
    assert!(err.to_string().contains("nonexistent"));
}

#[tokio::test]
async fn onboarding_tenant_without_user_fails() {
    let (pipeline, _store) = onboarding_pipeline();

    // Register app first
    let app_body = json!({
        "@type": "ubl/app",
        "@id": "app-acme2",
        "@ver": "1.0",
        "@world": "a/acme2",
        "slug": "acme2",
        "display_name": "Acme 2",
        "owner_did": "did:key:z6MkOwner",
        "@cap": test_cap("registry:init", "a/acme2")
    });
    submit_allow(&pipeline, "ubl/app", app_body).await;

    // Try to create tenant with a non-existent creator_cid
    let tenant_body = json!({
        "@type": "ubl/tenant",
        "@id": "tenant-bad",
        "@ver": "1.0",
        "@world": "a/acme2",
        "slug": "bad-circle",
        "display_name": "Bad Circle",
        "creator_cid": "b3:nonexistent_user_cid"
    });
    let err = submit_expect_err(&pipeline, "ubl/tenant", tenant_body).await;
    assert!(
        matches!(err, PipelineError::DependencyMissing(_)),
        "expected DependencyMissing, got: {}",
        err
    );
}

#[tokio::test]
async fn onboarding_membership_without_tenant_fails() {
    let (pipeline, _store) = onboarding_pipeline();

    // Register app + user
    let app_body = json!({
        "@type": "ubl/app", "@id": "app-m", "@ver": "1.0", "@world": "a/mtest",
        "slug": "mtest", "display_name": "MTest", "owner_did": "did:key:z6MkOwner",
        "@cap": test_cap("registry:init", "a/mtest")
    });
    submit_allow(&pipeline, "ubl/app", app_body).await;

    let user_body = json!({
        "@type": "ubl/user", "@id": "user-m", "@ver": "1.0", "@world": "a/mtest",
        "did": "did:key:z6MkUser", "display_name": "User M",
        "@cap": test_cap("registry:init", "a/mtest")
    });
    let user_cid = chip_cid(&user_body);
    submit_allow(&pipeline, "ubl/user", user_body).await;

    // Try membership with non-existent tenant (has cap but missing tenant)
    let mem_body = json!({
        "@type": "ubl/membership", "@id": "mem-bad", "@ver": "1.0",
        "@world": "a/mtest/t/ghost",
        "user_cid": user_cid,
        "tenant_cid": "b3:nonexistent_tenant",
        "role": "member",
        "@cap": test_cap("membership:grant", "a/mtest")
    });
    let err = submit_expect_err(&pipeline, "ubl/membership", mem_body).await;
    assert!(
        matches!(err, PipelineError::DependencyMissing(_)),
        "expected DependencyMissing, got: {}",
        err
    );
}

#[tokio::test]
async fn onboarding_token_without_user_fails() {
    let (pipeline, _store) = onboarding_pipeline();

    // Token with non-existent user
    let token_body = json!({
        "@type": "ubl/token", "@id": "tok-bad", "@ver": "1.0", "@world": "a/ghost",
        "user_cid": "b3:nonexistent_user",
        "scope": ["read"],
        "expires_at": "2027-01-01T00:00:00Z",
        "kid": "did:key:z6Mk#v0"
    });
    let err = submit_expect_err(&pipeline, "ubl/token", token_body).await;
    assert!(
        matches!(err, PipelineError::DependencyMissing(_)),
        "expected DependencyMissing, got: {}",
        err
    );
}

#[tokio::test]
async fn onboarding_duplicate_app_slug_rejected() {
    let (pipeline, _store) = onboarding_pipeline();

    let app_body = json!({
        "@type": "ubl/app", "@id": "app-dup1", "@ver": "1.0", "@world": "a/duptest",
        "slug": "duptest", "display_name": "Dup Test", "owner_did": "did:key:z6MkOwner",
        "@cap": test_cap("registry:init", "a/duptest")
    });
    submit_allow(&pipeline, "ubl/app", app_body.clone()).await;

    // Second app with same slug — should be rejected
    let app_body2 = json!({
        "@type": "ubl/app", "@id": "app-dup2", "@ver": "1.0", "@world": "a/duptest",
        "slug": "duptest", "display_name": "Dup Test 2", "owner_did": "did:key:z6MkOwner2",
        "@cap": test_cap("registry:init", "a/duptest")
    });
    let err = submit_expect_err(&pipeline, "ubl/app", app_body2).await;
    assert!(
        matches!(err, PipelineError::InvalidChip(_)),
        "expected InvalidChip for dup slug, got: {}",
        err
    );
    assert!(err.to_string().contains("duptest"));
}

#[tokio::test]
async fn onboarding_revoke_then_re_register_app() {
    let (pipeline, _store) = onboarding_pipeline();

    // Register app + user (need user as actor for revoke)
    let app_body = json!({
        "@type": "ubl/app", "@id": "app-rev", "@ver": "1.0", "@world": "a/revtest",
        "slug": "revtest", "display_name": "Rev Test", "owner_did": "did:key:z6MkOwner",
        "@cap": test_cap("registry:init", "a/revtest")
    });
    let app_cid = chip_cid(&app_body);
    submit_allow(&pipeline, "ubl/app", app_body).await;

    let user_body = json!({
        "@type": "ubl/user", "@id": "user-rev", "@ver": "1.0", "@world": "a/revtest",
        "did": "did:key:z6MkAdmin", "display_name": "Admin",
        "@cap": test_cap("registry:init", "a/revtest")
    });
    let user_cid = chip_cid(&user_body);
    submit_allow(&pipeline, "ubl/user", user_body).await;

    // Revoke the app (requires revoke:execute cap)
    let revoke_body = json!({
        "@type": "ubl/revoke", "@id": "rev-app", "@ver": "1.0", "@world": "a/revtest",
        "target_cid": app_cid,
        "reason": "Decommissioned",
        "actor_cid": user_cid,
        "@cap": test_cap("revoke:execute", "a/revtest")
    });
    submit_allow(&pipeline, "ubl/revoke", revoke_body).await;

    // Re-register with same slug should now succeed (old one is revoked)
    let app_body2 = json!({
        "@type": "ubl/app", "@id": "app-rev2", "@ver": "1.0", "@world": "a/revtest",
        "slug": "revtest", "display_name": "Rev Test Reborn", "owner_did": "did:key:z6MkOwner2",
        "@cap": test_cap("registry:init", "a/revtest")
    });
    submit_allow(&pipeline, "ubl/app", app_body2).await;
}

#[tokio::test]
async fn onboarding_revoke_user_blocks_dependent_token() {
    let (pipeline, _store) = onboarding_pipeline();

    // Full setup: app + user
    let app_body = json!({
        "@type": "ubl/app", "@id": "app-rt", "@ver": "1.0", "@world": "a/rtoken",
        "slug": "rtoken", "display_name": "RToken", "owner_did": "did:key:z6MkOwner",
        "@cap": test_cap("registry:init", "a/rtoken")
    });
    submit_allow(&pipeline, "ubl/app", app_body).await;

    let user_body = json!({
        "@type": "ubl/user", "@id": "user-rt", "@ver": "1.0", "@world": "a/rtoken",
        "did": "did:key:z6MkUser", "display_name": "User RT",
        "@cap": test_cap("registry:init", "a/rtoken")
    });
    let user_cid = chip_cid(&user_body);
    submit_allow(&pipeline, "ubl/user", user_body).await;

    // Register a second user to act as revoker (not first user, no cap needed)
    let admin_body = json!({
        "@type": "ubl/user", "@id": "admin-rt", "@ver": "1.0", "@world": "a/rtoken",
        "did": "did:key:z6MkAdmin", "display_name": "Admin RT"
    });
    let admin_cid = chip_cid(&admin_body);
    submit_allow(&pipeline, "ubl/user", admin_body).await;

    // Revoke the user (requires revoke:execute cap)
    let revoke_body = json!({
        "@type": "ubl/revoke", "@id": "rev-user", "@ver": "1.0", "@world": "a/rtoken",
        "target_cid": user_cid,
        "reason": "Account suspended",
        "actor_cid": admin_cid,
        "@cap": test_cap("revoke:execute", "a/rtoken")
    });
    submit_allow(&pipeline, "ubl/revoke", revoke_body).await;

    // Now try to create a token for the revoked user — should fail
    let token_body = json!({
        "@type": "ubl/token", "@id": "tok-revoked", "@ver": "1.0", "@world": "a/rtoken",
        "user_cid": user_cid,
        "scope": ["read"],
        "expires_at": "2027-01-01T00:00:00Z",
        "kid": "did:key:z6MkUser#v0"
    });
    let err = submit_expect_err(&pipeline, "ubl/token", token_body).await;
    assert!(
        matches!(err, PipelineError::DependencyMissing(_)),
        "expected DependencyMissing for revoked user, got: {}",
        err
    );
    assert!(err.to_string().contains("revoked"));
}

#[tokio::test]
async fn onboarding_invalid_body_rejected_before_dependency_check() {
    let (pipeline, _store) = onboarding_pipeline();

    // ubl/user missing required "did" field — should fail at body validation, not dependency check
    let bad_user = json!({
        "@type": "ubl/user", "@id": "bad", "@ver": "1.0", "@world": "a/acme",
        "display_name": "No DID"
    });
    let err = submit_expect_err(&pipeline, "ubl/user", bad_user).await;
    assert!(
        matches!(err, PipelineError::InvalidChip(_)),
        "expected InvalidChip, got: {}",
        err
    );
    assert!(err.to_string().contains("did"));
}

#[tokio::test]
async fn onboarding_non_onboarding_type_skips_validation() {
    let (pipeline, _store) = onboarding_pipeline();

    // ubl/document is not an onboarding type — should pass without dependency checks
    let doc_body = json!({
        "@type": "ubl/document", "@id": "doc-1", "@ver": "1.0", "@world": "a/any/t/any",
        "title": "Hello World"
    });
    submit_allow(&pipeline, "ubl/document", doc_body).await;
}

#[tokio::test]
async fn idempotent_replay_returns_cached_result() {
    let storage = InMemoryPolicyStorage::new();
    let pipeline = UblPipeline::new(Box::new(storage));

    let body = json!({
        "@type": "ubl/document",
        "@id": "idem-001",
        "@ver": "1.0",
        "@world": "a/test/t/dev",
        "title": "Idempotency test"
    });

    // First submission — fresh execution
    let r1 = submit_allow(&pipeline, "ubl/document", body.clone()).await;
    assert!(!r1.replayed, "first submission should not be replayed");
    assert!(!r1.receipt.receipt_cid.as_str().is_empty());

    // Second submission — same (@type, @ver, @world, @id) → cached replay
    let r2 = submit_allow(&pipeline, "ubl/document", body.clone()).await;
    assert!(r2.replayed, "second submission should be replayed");
    assert_eq!(
        r2.receipt.receipt_cid, r1.receipt.receipt_cid,
        "replayed receipt_cid must match original"
    );
    assert_eq!(r2.chain, r1.chain, "replayed chain must match original");
}

#[tokio::test]
async fn idempotent_replay_different_id_is_fresh() {
    let storage = InMemoryPolicyStorage::new();
    let pipeline = UblPipeline::new(Box::new(storage));

    let body1 = json!({
        "@type": "ubl/document", "@id": "a", "@ver": "1.0", "@world": "a/x/t/y",
        "title": "First"
    });
    let body2 = json!({
        "@type": "ubl/document", "@id": "b", "@ver": "1.0", "@world": "a/x/t/y",
        "title": "Second"
    });

    let r1 = submit_allow(&pipeline, "ubl/document", body1).await;
    let r2 = submit_allow(&pipeline, "ubl/document", body2).await;

    assert!(!r1.replayed);
    assert!(!r2.replayed);
    assert_ne!(
        r1.receipt.receipt_cid, r2.receipt.receipt_cid,
        "different @id → different execution"
    );
}

#[tokio::test]
async fn strict_idempotency_requires_type_ver_world_id() {
    let storage = InMemoryPolicyStorage::new();
    let pipeline = UblPipeline::new(Box::new(storage));

    let request = ChipRequest {
        chip_type: "ubl/document".to_string(),
        body: json!({
            "@type": "ubl/document",
            "@ver": "1.0",
            "@world": "a/x/t/y",
            "title": "missing id"
        }),
        parents: vec![],
        operation: Some("create".to_string()),
    };

    let err = pipeline.process_chip(request).await.unwrap_err();
    assert!(matches!(err, PipelineError::InvalidChip(_)));
    assert!(err.to_string().contains("strict idempotency anchors"));
}
