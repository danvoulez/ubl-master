use std::sync::Arc;
use std::time::Instant;

use serde_json::json;
use ubl_chipstore::{ChipQuery, ChipStore, ExecutionMetadata, SledBackend};
use ubl_types::Did as TypedDid;

fn metadata() -> ExecutionMetadata {
    ExecutionMetadata {
        runtime_version: "load-test".to_string(),
        execution_time_ms: 1,
        fuel_consumed: 1,
        policies_applied: vec![],
        executor_did: TypedDid::new_unchecked("did:key:zLoadTest"),
        reproducible: true,
    }
}

/// Manual evidence test for M3:
/// - dataset size: 100k chips
/// - index-backed selective query should be faster than scan-only query
#[tokio::test]
#[ignore = "expensive load validation (100k dataset)"]
async fn load_validation_100k_indexed_query_beats_scan() {
    let store = ChipStore::new(Arc::new(SledBackend::in_memory().expect("sled backend")));

    const TOTAL: usize = 100_000;
    const TARGET_PASSPORT: &str = "b3:passport-hot";
    let mut expected_target_count = 0usize;

    for i in 0..TOTAL {
        let is_target = i % 500 == 0; // ~200 hits in 100k
        if is_target {
            expected_target_count += 1;
        }
        let passport = if is_target {
            TARGET_PASSPORT
        } else {
            "b3:passport-cold"
        };
        let chip = json!({
            "@type": "ubl/advisory",
            "@id": format!("adv-{}", i),
            "@ver": "1.0",
            "@world": "a/load/t/prod",
            "passport_cid": passport,
            "action": "observe",
            "confidence_bp": 9500
        });

        let receipt_cid = format!("b3:{:064x}", i + 1);
        store
            .store_executed_chip(chip, receipt_cid, metadata())
            .await
            .expect("store chip");
    }

    let indexed_query = ChipQuery {
        chip_type: Some("ubl/advisory".to_string()),
        tags: vec![format!("passport_cid:{}", TARGET_PASSPORT)],
        created_after: None,
        created_before: None,
        executor_did: None,
        limit: None,
        offset: None,
    };

    let scan_query = ChipQuery {
        chip_type: None,
        tags: vec![],
        created_after: Some("1970-01-01T00:00:00Z".to_string()),
        created_before: None,
        executor_did: None,
        limit: None,
        offset: None,
    };

    let t_indexed = Instant::now();
    let indexed_result = store.query(&indexed_query).await.expect("indexed query");
    let indexed_elapsed = t_indexed.elapsed();

    let t_scan = Instant::now();
    let _scan_result = store.query(&scan_query).await.expect("scan query");
    let scan_elapsed = t_scan.elapsed();

    assert_eq!(indexed_result.total_count, expected_target_count);
    assert!(
        indexed_elapsed < scan_elapsed,
        "indexed query should be faster than scan query (indexed={:?}, scan={:?})",
        indexed_elapsed,
        scan_elapsed
    );
}
