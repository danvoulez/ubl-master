use serde_json::json;
use ubl_ai_nrf1::nrf::{cid_from_nrf_bytes, encode_to_vec, json_to_nrf};

fn cid(v: &serde_json::Value) -> String {
    let nrf = json_to_nrf(v).expect("json_to_nrf failed");
    let bytes = encode_to_vec(&nrf).expect("encode failed");
    cid_from_nrf_bytes(&bytes)
}

fn main() {
    let cafe = "Café";       // NFC: U+00E9
    let cjk  = "日本語";
    let crab  = "🦀";

    let vectors: Vec<(&str, serde_json::Value)> = vec![
        ("empty_object",      json!({})),
        ("single_int",        json!({"n": 42})),
        ("single_string",     json!({"s": "hello"})),
        ("bool_true",         json!({"v": true})),
        ("bool_false",        json!({"v": false})),
        ("nfc_cafe",          json!({"x": cafe})),
        ("null_stripped",     json!({"a": null, "b": 1})),
        ("key_order_abc",     json!({"c": 3, "a": 1, "b": 2})),
        ("nested",            json!({"outer": {"inner": 99}})),
        ("array_ints",        json!({"arr": [1, 2, 3]})),
        ("array_with_null",   json!({"arr": [null, 1, null]})),
        ("mixed_types",       json!({"i": -1, "b": true, "s": "ok", "n": 0})),
        ("deep_nesting",      json!({"l1": {"l2": {"l3": {"l4": "leaf"}}}})),
        ("unicode_emoji",     json!({"e": crab})),
        ("unicode_cjk",       json!({"k": cjk})),
        ("empty_string",      json!({"s": ""})),
        ("empty_array",       json!({"a": []})),
        ("large_int",         json!({"n": i64::MAX})),
        ("min_int",           json!({"n": i64::MIN})),
        ("zero",              json!({"n": 0})),
        ("multiple_nulls",    json!({"a": null, "b": null, "c": null})),
        ("nested_arrays",     json!({"m": [[1, 2], [3, 4]]})),
        ("canonical_chip",    json!({"@type": "ubl/user", "@id": "b3:aabbcc", "@ver": "1.0", "@world": "a/acme/t/prod", "email": "alice@acme.com"})),
        ("canonical_receipt", json!({"@type": "ubl/wf",   "@id": "b3:ddeeff", "@ver": "1.0", "@world": "a/acme/t/prod", "decision": "allow"})),
        ("hello_world_stable",json!({"hello": "world", "n": 42})),
    ];

    let mut entries = serde_json::Map::new();
    for (name, val) in &vectors {
        let c = cid(val);
        entries.insert(name.to_string(), json!({
            "description": name,
            "input": val,
            "expected_cid": c
        }));
    }

    let doc = json!({
        "_version": "1",
        "_description": "UBL NRF-1 Canonical CID Golden Vectors — BLAKE3. If any CID changes, canon broke.",
        "_platform_note": "CIDs must be identical on Linux, macOS, and Windows. Any divergence is a critical determinism failure.",
        "vectors": entries
    });

    println!("{}", serde_json::to_string_pretty(&doc).unwrap());
}
