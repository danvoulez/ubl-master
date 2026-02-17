use serde_json::json;

#[test]
fn cid_equivalence_nrf_across_components() {
    let value = json!({
        "@type": "ubl/test",
        "@id": "cid-eq-1",
        "@ver": "1.0",
        "@world": "a/acme/t/prod",
        "nested": {"b": 2, "a": 1},
    });

    let via_canon = ubl_canon::cid_of(&value).expect("canon cid");
    let nrf = ubl_ai_nrf1::to_nrf1_bytes(&value).expect("nrf bytes");
    let via_nrf = ubl_ai_nrf1::compute_cid(&nrf).expect("nrf cid");

    assert_eq!(via_canon, via_nrf);
}

#[test]
fn no_custom_sort_key_paths() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let pipeline_file = {
        let legacy = root.join("src/pipeline.rs");
        if legacy.exists() {
            legacy
        } else {
            root.join("src/pipeline/mod.rs")
        }
    };
    let files = [
        root.join("src/rich_url.rs"),
        pipeline_file,
        root.join("../ubl_receipt/src/unified.rs"),
    ];

    let banned = ["sort_keys", "sort-keys", "canonical_json_bytes("];
    for file in files {
        let body = std::fs::read_to_string(&file)
            .unwrap_or_else(|e| panic!("failed to read {}: {}", file.display(), e));
        for pattern in banned {
            assert!(
                !body.contains(pattern),
                "found banned canonicalization pattern '{}' in {}",
                pattern,
                file.display()
            );
        }
    }
}
