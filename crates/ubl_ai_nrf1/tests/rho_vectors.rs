//! H13 — ρ test vectors from ubl-ultimate-main
//! Tests canon edge cases: scalars, Unicode NFC/NFD, key ordering,
//! nested objects, floats (reject), nulls-vs-absence, large objects, weird strings.
//!
//! Vectors live in `kats/rho_vectors/*.json` at repo root.

use std::path::PathBuf;
use ubl_ai_nrf1::nrf::{cid_from_nrf_bytes, encode_to_vec, json_to_nrf};

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap() // crates/
        .parent()
        .unwrap() // repo root
        .join("kats")
        .join("rho_vectors")
}

fn load(name: &str) -> serde_json::Value {
    let path = vectors_dir().join(name);
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {}", path.display(), e));
    serde_json::from_str(&data)
        .unwrap_or_else(|e| panic!("failed to parse {}: {}", path.display(), e))
}

fn canon_cid(v: &serde_json::Value) -> String {
    let nrf = json_to_nrf(v).expect("json_to_nrf failed");
    let bytes = encode_to_vec(&nrf).expect("encode failed");
    cid_from_nrf_bytes(&bytes)
}

// ── 00: Empty object ────────────────────────────────────────────

#[test]
fn rho_00_empty_object() {
    let v = load("00_empty.json");
    let nrf = json_to_nrf(&v).expect("empty object must be accepted");
    let bytes = encode_to_vec(&nrf).unwrap();
    let cid = cid_from_nrf_bytes(&bytes);
    assert!(cid.starts_with("b3:"), "CID must have b3: prefix");
    // Determinism: same input → same CID
    assert_eq!(cid, canon_cid(&v));
}

// ── 01: Scalars (int, bool, null) ───────────────────────────────

#[test]
fn rho_01_scalars_ints_and_bools() {
    let v = load("01_scalars.json");
    // Contains u64 max (18446744073709551615) which overflows i64 → must reject
    // Also contains i64::MIN which is valid
    // serde_json parses 18446744073709551615 as u64, not i64 → json_to_nrf rejects
    let result = json_to_nrf(&v);
    assert!(
        result.is_err(),
        "u64 overflow must be rejected (no floats, i64 only)"
    );
}

#[test]
fn rho_01_scalars_valid_subset() {
    // Test the valid parts individually
    let v = serde_json::json!({"t": true, "f": false, "n": null, "i": 42, "neg": -100});
    let nrf = json_to_nrf(&v).expect("valid scalars must be accepted");
    let bytes = encode_to_vec(&nrf).unwrap();
    // null stripped from map → only t, f, i, neg remain
    let decoded = ubl_ai_nrf1::nrf::decode_from_slice(&bytes).unwrap();
    if let ubl_ai_nrf1::nrf::NrfValue::Map(m) = &decoded {
        assert_eq!(m.len(), 4, "null value 'n' must be stripped");
        assert!(!m.contains_key("n"));
    } else {
        panic!("expected Map");
    }
}

// ── 02: Strings with control chars ──────────────────────────────

#[test]
fn rho_02_strings_with_control_chars_rejected() {
    let v = load("02_strings_basic.json");
    // Contains \n and \t which are control chars (U+000A, U+0009) → rejected by ρ
    let result = json_to_nrf(&v);
    assert!(
        result.is_err(),
        "strings with control chars (\\n, \\t) must be rejected"
    );
}

// ── 03: Unicode NFC (valid) ─────────────────────────────────────

#[test]
fn rho_03_unicode_nfc_accepted() {
    let v = load("03_unicode_nfc.json");
    let nrf = json_to_nrf(&v).expect("NFC string 'Café' must be accepted");
    let bytes = encode_to_vec(&nrf).unwrap();
    let cid = cid_from_nrf_bytes(&bytes);
    assert!(cid.starts_with("b3:"));
    // Determinism
    assert_eq!(cid, canon_cid(&v));
}

// ── 04: Unicode NFD (must reject) ───────────────────────────────

#[test]
fn rho_04_unicode_nfd_rejected() {
    let v = load("04_unicode_nfd.json");
    let result = json_to_nrf(&v);
    // NFD "Café" (e + combining acute) must be rejected
    assert!(result.is_err(), "NFD string must be rejected (NotNFC)");
}

// ── 05+06: Key ordering determinism ─────────────────────────────

#[test]
fn rho_05_06_key_order_produces_same_cid() {
    let a = load("05_key_order_a.json");
    let b = load("06_key_order_b.json");
    let cid_a = canon_cid(&a);
    let cid_b = canon_cid(&b);
    assert_eq!(
        cid_a, cid_b,
        "same keys in different order must produce identical CID"
    );
}

#[test]
fn rho_05_keys_sorted_in_output() {
    let v = load("05_key_order_a.json");
    let nrf = json_to_nrf(&v).unwrap();
    if let ubl_ai_nrf1::nrf::NrfValue::Map(m) = &nrf {
        let keys: Vec<&String> = m.keys().collect();
        assert_eq!(keys, vec!["a", "b", "c"], "keys must be sorted ascending");
    } else {
        panic!("expected Map");
    }
}

// ── 07: Arrays with nested structures ───────────────────────────

#[test]
fn rho_07_arrays_nested() {
    let v = load("07_arrays.json");
    let nrf = json_to_nrf(&v).expect("arrays with nested objects must be accepted");
    let bytes = encode_to_vec(&nrf).unwrap();
    // Roundtrip
    let decoded = ubl_ai_nrf1::nrf::decode_from_slice(&bytes).unwrap();
    assert_eq!(nrf, decoded, "nested array must roundtrip exactly");
}

// ── 08: Deep nesting ────────────────────────────────────────────

#[test]
fn rho_08_deep_nesting() {
    let v = load("08_nested.json");
    let nrf = json_to_nrf(&v).expect("deep nesting must be accepted");
    let bytes = encode_to_vec(&nrf).unwrap();
    let decoded = ubl_ai_nrf1::nrf::decode_from_slice(&bytes).unwrap();
    assert_eq!(nrf, decoded, "deep nesting must roundtrip exactly");
    // CID determinism
    assert_eq!(canon_cid(&v), canon_cid(&v));
}

// ── 09: Floats (common) — must reject ───────────────────────────

#[test]
fn rho_09_floats_common_rejected() {
    let v = load("09_floats_common.json");
    let result = json_to_nrf(&v);
    assert!(result.is_err(), "floats must be rejected (i64 only)");
}

// ── 10: Floats (edge) — must reject ────────────────────────────

#[test]
fn rho_10_floats_edge_rejected() {
    let v = load("10_floats_edge.json");
    let result = json_to_nrf(&v);
    assert!(result.is_err(), "edge-case floats must be rejected");
}

// ── 11: Nulls vs absence ───────────────────────────────────────

#[test]
fn rho_11_nulls_stripped_from_map() {
    let v = load("11_nulls_vs_absence.json");
    // {"have":null,"miss":"ok"} → null stripped → only "miss" remains
    let nrf = json_to_nrf(&v).expect("null-containing map must be accepted");
    if let ubl_ai_nrf1::nrf::NrfValue::Map(m) = &nrf {
        assert_eq!(m.len(), 1, "null value must be stripped from map");
        assert!(!m.contains_key("have"), "'have':null must be absent");
        assert!(m.contains_key("miss"), "'miss':'ok' must be present");
    } else {
        panic!("expected Map");
    }
}

// ── 12: Large object (100 keys) ────────────────────────────────

#[test]
fn rho_12_large_object_deterministic() {
    let v = load("12_large_obj.json");
    let cid1 = canon_cid(&v);
    let cid2 = canon_cid(&v);
    assert_eq!(cid1, cid2, "large object CID must be deterministic");
    // Verify all 100 keys survived and are sorted
    let nrf = json_to_nrf(&v).unwrap();
    if let ubl_ai_nrf1::nrf::NrfValue::Map(m) = &nrf {
        assert_eq!(m.len(), 100, "all 100 keys must be present");
        let keys: Vec<&String> = m.keys().collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted, "keys must be in sorted order");
    } else {
        panic!("expected Map");
    }
}

// ── 13: Weird strings ──────────────────────────────────────────

#[test]
fn rho_13_weird_strings_accepted() {
    let v = load("13_str_weird.json");
    let nrf = json_to_nrf(&v).expect("weird but valid strings must be accepted");
    let bytes = encode_to_vec(&nrf).unwrap();
    let decoded = ubl_ai_nrf1::nrf::decode_from_slice(&bytes).unwrap();
    assert_eq!(nrf, decoded, "weird strings must roundtrip exactly");
}

// ── Cross-vector: all valid vectors produce unique CIDs ────────

#[test]
fn rho_valid_vectors_unique_cids() {
    let valid_files = [
        "00_empty.json",
        "03_unicode_nfc.json",
        "05_key_order_a.json",
        "07_arrays.json",
        "08_nested.json",
        "12_large_obj.json",
        "13_str_weird.json",
    ];
    let cids: Vec<String> = valid_files.iter().map(|f| canon_cid(&load(f))).collect();
    // All CIDs must be unique
    for i in 0..cids.len() {
        for j in (i + 1)..cids.len() {
            assert_ne!(
                cids[i], cids[j],
                "CID collision between {} and {}",
                valid_files[i], valid_files[j]
            );
        }
    }
}
