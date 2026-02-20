//! M2 — Cross-Platform Canonical CID Golden Vectors
//!
//! These tests load `kats/golden/canon_v1.json` and assert that every
//! (input, expected_cid) pair produces the exact same bytes and CID on
//! every supported platform: Linux, macOS, Windows, x86_64, aarch64.
//!
//! If any test here fails, canon is broken. Do not adjust expected_cid
//! values to make the test pass — fix the encoding instead.
//!
//! The golden file is the single source of truth. Adding new vectors:
//!   1. Add the entry to the gen_golden example
//!   2. Run `cargo run --example gen_golden -p ubl_ai_nrf1 > kats/golden/canon_v1.json`
//!   3. Commit both the example change and the updated JSON
//!
//! PF-01 contract: same canonical input → same bytes → same CID, forever.

use std::path::PathBuf;
use ubl_ai_nrf1::nrf::{cid_from_nrf_bytes, encode_to_vec, json_to_nrf};

fn golden_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap() // crates/
        .parent()
        .unwrap() // repo root
        .join("kats")
        .join("golden")
        .join("canon_v1.json")
}

#[derive(serde::Deserialize)]
struct GoldenFile {
    vectors: std::collections::BTreeMap<String, GoldenEntry>,
}

#[derive(serde::Deserialize)]
struct GoldenEntry {
    input: serde_json::Value,
    expected_cid: String,
}

fn compute_cid(v: &serde_json::Value) -> Result<String, String> {
    let nrf = json_to_nrf(v).map_err(|e| format!("json_to_nrf: {e}"))?;
    let bytes = encode_to_vec(&nrf).map_err(|e| format!("encode_to_vec: {e}"))?;
    Ok(cid_from_nrf_bytes(&bytes))
}

fn load_golden() -> GoldenFile {
    let path = golden_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Cannot read golden file {}: {e}", path.display()));
    serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("Cannot parse golden file: {e}"))
}

/// Run every vector in the golden file.
/// This is intentionally a single test so CI reports one clear pass/fail
/// with a detailed per-vector breakdown on failure.
#[test]
fn golden_canon_all_vectors() {
    let file = load_golden();
    let mut failures: Vec<String> = Vec::new();

    for (name, entry) in &file.vectors {
        match compute_cid(&entry.input) {
            Ok(got) => {
                if got != entry.expected_cid {
                    failures.push(format!(
                        "\n  [{name}]\n    expected: {}\n    got:      {}\n    input:    {}",
                        entry.expected_cid,
                        got,
                        serde_json::to_string(&entry.input).unwrap()
                    ));
                }
            }
            Err(e) => {
                failures.push(format!(
                    "\n  [{name}] encoding failed: {e}\n    input: {}",
                    serde_json::to_string(&entry.input).unwrap()
                ));
            }
        }
    }

    if !failures.is_empty() {
        panic!(
            "Golden CID failures on platform={}/{} ({} of {} vectors failed):\n{}",
            std::env::consts::OS,
            std::env::consts::ARCH,
            failures.len(),
            file.vectors.len(),
            failures.join("")
        );
    }

    // Print confirmation (visible with --nocapture)
    eprintln!(
        "✅ All {} golden vectors match on {}/{}",
        file.vectors.len(),
        std::env::consts::OS,
        std::env::consts::ARCH
    );
}

/// Verify the previously-locked hello_world CID from nrf.rs unit tests.
/// Belt-and-suspenders: if this diverges from golden_canon_all_vectors,
/// something is very wrong with the test setup itself.
#[test]
fn golden_hello_world_cid_locked() {
    let input = serde_json::json!({"hello": "world", "n": 42});
    let got = compute_cid(&input).expect("should not fail");
    assert_eq!(
        got,
        "b3:fd38c071ca3e1ede2a135645677d5326bbf91fb9cfe56a36f2d54636b75e7cd2",
        "Locked CID for {{hello:world,n:42}} diverged — canon is broken"
    );
}

/// Key-order invariance: same content, different insertion order → same CID.
/// This is the core canon promise. Verified independently of the golden file.
#[test]
fn golden_key_order_invariance() {
    let abc = serde_json::json!({"a": 1, "b": 2, "c": 3});
    let cba = serde_json::json!({"c": 3, "b": 2, "a": 1});
    let bac = serde_json::json!({"b": 2, "a": 1, "c": 3});

    let cid_abc = compute_cid(&abc).unwrap();
    let cid_cba = compute_cid(&cba).unwrap();
    let cid_bac = compute_cid(&bac).unwrap();

    assert_eq!(cid_abc, cid_cba, "abc vs cba mismatch");
    assert_eq!(cid_abc, cid_bac, "abc vs bac mismatch");
}

/// Null stripping: {a:null, b:1} and {b:1} must produce the same CID.
/// Absence == null in NRF-1 canon.
#[test]
fn golden_null_stripping_same_as_absent() {
    let with_null = serde_json::json!({"a": null, "b": 1});
    let without   = serde_json::json!({"b": 1});
    assert_eq!(
        compute_cid(&with_null).unwrap(),
        compute_cid(&without).unwrap(),
        "null value must produce same CID as absent key"
    );
}

/// All-null object == empty object (everything stripped).
#[test]
fn golden_all_null_equals_empty() {
    let all_null = serde_json::json!({"x": null, "y": null, "z": null});
    let empty    = serde_json::json!({});
    assert_eq!(
        compute_cid(&all_null).unwrap(),
        compute_cid(&empty).unwrap(),
        "all-null object must equal empty object"
    );
}

/// NFC/NFD divergence: NFD must be REJECTED, not silently normalized.
/// This is the strict ρ contract — the pipeline normalizes at input boundary,
/// but json_to_nrf (used for CID computation) enforces strict NFC.
#[test]
fn golden_nfd_rejected() {
    let nfd = "e\u{0301}"; // NFD: e + combining acute accent
    let input = serde_json::json!({"s": nfd});
    assert!(
        json_to_nrf(&input).is_err(),
        "NFD string must be rejected at canon layer"
    );
}

/// NFC accepted: U+00E9 is the precomposed form of é.
#[test]
fn golden_nfc_accepted() {
    let nfc = "\u{00e9}"; // NFC: precomposed é
    let input = serde_json::json!({"s": nfc});
    assert!(json_to_nrf(&input).is_ok(), "NFC string must be accepted");
}

/// Cross-vector: all unique inputs must produce unique CIDs.
/// A collision here would be catastrophic — the registry would deduplicate
/// distinct chips.
#[test]
fn golden_no_cid_collisions() {
    let file = load_golden();
    let mut seen: std::collections::HashMap<String, String> = std::collections::HashMap::new();

    for (name, entry) in &file.vectors {
        let got = match compute_cid(&entry.input) {
            Ok(c) => c,
            Err(_) => continue, // skip reject-expected vectors
        };

        // Only check for collisions among structurally-distinct inputs
        // (multiple_nulls == empty_object intentionally — both hash to empty map)
        let input_str = serde_json::to_string(&entry.input).unwrap();
        if let Some(prev_name) = seen.get(&got) {
            // Verify it's actually the same canonical content, not a true collision
            let prev_input = file.vectors[prev_name].input.clone();
            let prev_nrf = json_to_nrf(&prev_input);
            let curr_nrf = json_to_nrf(&entry.input);
            if let (Ok(p), Ok(c)) = (prev_nrf, curr_nrf) {
                assert_eq!(
                    p, c,
                    "CID collision between '{prev_name}' and '{name}' with different canonical content!\n  cid: {got}\n  prev input: {}\n  curr input: {input_str}",
                    serde_json::to_string(&file.vectors[prev_name].input).unwrap()
                );
            }
        } else {
            seen.insert(got, name.clone());
        }
    }
}
