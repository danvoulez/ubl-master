//! KNOCK stage — first gate in the pipeline.
//!
//! Validates raw input before anything touches WA/CHECK/TR/WF.
//! KNOCK failures return errors immediately (no receipt produced).
//!
//! Checks:
//! 1. Body size ≤ MAX_BODY_BYTES (1 MB)
//! 2. JSON nesting depth ≤ MAX_DEPTH (32)
//! 3. Array length ≤ MAX_ARRAY_LEN (10_000)
//! 4. No duplicate keys
//! 5. Valid UTF-8 (enforced by serde_json, but we check raw bytes too)
//! 6. Required anchors: @type, @world
//! 7. No raw floats (UNC-1 §3/§6: use @num atoms instead)

use serde_json::Value;
use std::collections::HashSet;

pub const MAX_BODY_BYTES: usize = 1_048_576; // 1 MB
pub const MAX_DEPTH: usize = 32;
pub const MAX_ARRAY_LEN: usize = 10_000;

#[derive(Debug, thiserror::Error)]
pub enum KnockError {
    #[error("KNOCK-001: body too large ({0} bytes, max {MAX_BODY_BYTES})")]
    BodyTooLarge(usize),
    #[error("KNOCK-002: nesting depth exceeds {MAX_DEPTH}")]
    DepthExceeded,
    #[error("KNOCK-003: array length {0} exceeds {MAX_ARRAY_LEN}")]
    ArrayTooLong(usize),
    #[error("KNOCK-004: duplicate key {0:?}")]
    DuplicateKey(String),
    #[error("KNOCK-005: invalid UTF-8 in body")]
    InvalidUtf8,
    #[error("KNOCK-006: missing required anchor {0:?}")]
    MissingAnchor(&'static str),
    #[error("KNOCK-007: body is not a JSON object")]
    NotObject,
    #[error("KNOCK-008: raw float in payload violates UNC-1 — use @num atoms: {0}")]
    RawFloat(String),
}

/// Validate raw bytes before JSON parsing.
/// Call this on the raw HTTP body before `serde_json::from_slice`.
pub fn knock_raw(bytes: &[u8]) -> Result<(), KnockError> {
    // 1. Size limit
    if bytes.len() > MAX_BODY_BYTES {
        return Err(KnockError::BodyTooLarge(bytes.len()));
    }

    // 2. Valid UTF-8
    if std::str::from_utf8(bytes).is_err() {
        return Err(KnockError::InvalidUtf8);
    }

    Ok(())
}

/// Validate parsed JSON value for structural limits and required anchors.
pub fn knock_parsed(value: &Value) -> Result<(), KnockError> {
    let obj = value.as_object().ok_or(KnockError::NotObject)?;

    // Required anchors
    if !obj.contains_key("@type") {
        return Err(KnockError::MissingAnchor("@type"));
    }
    if !obj.contains_key("@world") {
        return Err(KnockError::MissingAnchor("@world"));
    }

    // Structural checks (depth, array length, duplicate keys)
    check_depth(value, 0)?;
    check_arrays(value)?;

    // UNC-1 §6: reject raw floats — must use @num atoms
    check_no_floats(value)?;

    Ok(())
}

/// Full KNOCK: raw bytes → parse → structural validation.
/// Returns the parsed Value on success.
pub fn knock(bytes: &[u8]) -> Result<Value, KnockError> {
    knock_raw(bytes)?;

    // Parse JSON (also validates UTF-8 at serde level)
    let value: Value = serde_json::from_slice(bytes).map_err(|_| KnockError::InvalidUtf8)?;

    knock_parsed(&value)?;

    // Check for duplicate keys (requires re-scanning raw bytes)
    check_duplicate_keys(bytes)?;

    Ok(value)
}

fn check_depth(value: &Value, depth: usize) -> Result<(), KnockError> {
    if depth > MAX_DEPTH {
        return Err(KnockError::DepthExceeded);
    }
    match value {
        Value::Object(map) => {
            for v in map.values() {
                check_depth(v, depth + 1)?;
            }
        }
        Value::Array(arr) => {
            for v in arr {
                check_depth(v, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// UNC-1 §3/§6: raw JSON floats are never canonical.
/// Numbers must be i64/u64 integers or @num atoms (objects).
fn check_no_floats(value: &Value) -> Result<(), KnockError> {
    match value {
        Value::Number(n) => {
            if !n.is_i64() && !n.is_u64() {
                return Err(KnockError::RawFloat(format!("{}", n)));
            }
        }
        Value::Array(arr) => {
            for v in arr {
                check_no_floats(v)?;
            }
        }
        Value::Object(map) => {
            for v in map.values() {
                check_no_floats(v)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn check_arrays(value: &Value) -> Result<(), KnockError> {
    match value {
        Value::Array(arr) => {
            if arr.len() > MAX_ARRAY_LEN {
                return Err(KnockError::ArrayTooLong(arr.len()));
            }
            for v in arr {
                check_arrays(v)?;
            }
        }
        Value::Object(map) => {
            for v in map.values() {
                check_arrays(v)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Detect duplicate keys by scanning raw JSON bytes.
/// serde_json silently takes the last value for duplicate keys,
/// so we need a separate check.
fn check_duplicate_keys(bytes: &[u8]) -> Result<(), KnockError> {
    // Use serde_json::from_slice into a raw Value and walk it.
    // Since serde_json deduplicates, we compare key counts in raw vs parsed.
    // A simpler approach: use a streaming tokenizer.
    // For MVP, we do a recursive descent on the raw string.
    let s = std::str::from_utf8(bytes).map_err(|_| KnockError::InvalidUtf8)?;
    scan_object_keys(s)
}

/// Scan JSON string for duplicate keys at each object level.
fn scan_object_keys(s: &str) -> Result<(), KnockError> {
    let bytes = s.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'{' {
            i += 1;
            let mut keys = HashSet::new();
            let mut depth = 0;
            let mut in_string = false;
            let mut escape = false;

            while i < bytes.len() {
                let b = bytes[i];

                if escape {
                    escape = false;
                    i += 1;
                    continue;
                }

                if b == b'\\' && in_string {
                    escape = true;
                    i += 1;
                    continue;
                }

                if b == b'"' {
                    if !in_string && depth == 0 {
                        // Start of a key at this object level — extract it
                        let key_start = i + 1;
                        i += 1;
                        // Find end of string
                        while i < bytes.len() {
                            if bytes[i] == b'\\' {
                                i += 2;
                                continue;
                            }
                            if bytes[i] == b'"' {
                                break;
                            }
                            i += 1;
                        }
                        let key_end = i;
                        if key_end > key_start {
                            let key = &s[key_start..key_end];
                            // Check if next non-ws char is ':'
                            let mut j = i + 1;
                            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                                j += 1;
                            }
                            if j < bytes.len() && bytes[j] == b':' {
                                // This is a key
                                if !keys.insert(key.to_string()) {
                                    return Err(KnockError::DuplicateKey(key.to_string()));
                                }
                            }
                        }
                    } else {
                        in_string = !in_string;
                    }
                    i += 1;
                    continue;
                }

                if !in_string {
                    if b == b'{' || b == b'[' {
                        depth += 1;
                    } else if b == b'}' || b == b']' {
                        if depth == 0 {
                            break; // end of this object
                        }
                        depth -= 1;
                    }
                }

                i += 1;
            }
        }
        i += 1;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn valid_chip() -> Vec<u8> {
        serde_json::to_vec(&json!({
            "@type": "ubl/user",
            "@id": "alice",
            "@ver": "1.0",
            "@world": "a/app/t/ten",
            "email": "alice@acme.com"
        }))
        .unwrap()
    }

    #[test]
    fn knock_accepts_valid_chip() {
        let bytes = valid_chip();
        let value = knock(&bytes).unwrap();
        assert_eq!(value["@type"], "ubl/user");
    }

    #[test]
    fn knock_rejects_oversized_body() {
        let big = vec![b' '; MAX_BODY_BYTES + 1];
        let err = knock_raw(&big).unwrap_err();
        assert!(matches!(err, KnockError::BodyTooLarge(_)));
    }

    #[test]
    fn knock_rejects_invalid_utf8() {
        let bad = vec![0xFF, 0xFE, 0x00];
        let err = knock_raw(&bad).unwrap_err();
        assert!(matches!(err, KnockError::InvalidUtf8));
    }

    #[test]
    fn knock_rejects_missing_type() {
        let bytes = serde_json::to_vec(&json!({
            "@id": "x",
            "@world": "a/x/t/y"
        }))
        .unwrap();
        let err = knock(&bytes).unwrap_err();
        assert!(matches!(err, KnockError::MissingAnchor("@type")));
    }

    #[test]
    fn knock_rejects_missing_world() {
        let bytes = serde_json::to_vec(&json!({
            "@type": "ubl/user",
            "@id": "x"
        }))
        .unwrap();
        let err = knock(&bytes).unwrap_err();
        assert!(matches!(err, KnockError::MissingAnchor("@world")));
    }

    #[test]
    fn knock_rejects_non_object() {
        let bytes = b"[1,2,3]";
        let err = knock(bytes).unwrap_err();
        assert!(matches!(err, KnockError::NotObject));
    }

    #[test]
    fn knock_rejects_deep_nesting() {
        // Build JSON with depth > MAX_DEPTH
        let mut s = String::new();
        for _ in 0..MAX_DEPTH + 2 {
            s.push_str(r#"{"a":"#);
        }
        s.push('1');
        for _ in 0..MAX_DEPTH + 2 {
            s.push('}');
        }
        // This won't have @type/@world, so wrap it
        let wrapped = format!(r#"{{"@type":"ubl/test","@world":"a/x/t/y","deep":{}}}"#, s);
        let err = knock(wrapped.as_bytes()).unwrap_err();
        assert!(matches!(err, KnockError::DepthExceeded));
    }

    #[test]
    fn knock_rejects_huge_array() {
        let arr: Vec<i32> = (0..MAX_ARRAY_LEN as i32 + 1).collect();
        let obj = json!({
            "@type": "ubl/test",
            "@world": "a/x/t/y",
            "data": arr
        });
        let bytes = serde_json::to_vec(&obj).unwrap();
        let err = knock(&bytes).unwrap_err();
        assert!(matches!(err, KnockError::ArrayTooLong(_)));
    }

    #[test]
    fn knock_rejects_duplicate_keys() {
        // Manually construct JSON with duplicate keys
        let raw = br#"{"@type":"ubl/test","@world":"a/x/t/y","name":"a","name":"b"}"#;
        let err = knock(raw).unwrap_err();
        assert!(matches!(err, KnockError::DuplicateKey(_)));
        if let KnockError::DuplicateKey(k) = err {
            assert_eq!(k, "name");
        }
    }

    #[test]
    fn knock_allows_same_key_in_nested_objects() {
        // "name" appears in both outer and inner — that's fine
        let raw = br#"{"@type":"ubl/test","@world":"a/x/t/y","name":"a","inner":{"name":"b"}}"#;
        let value = knock(raw).unwrap();
        assert_eq!(value["name"], "a");
        assert_eq!(value["inner"]["name"], "b");
    }

    #[test]
    fn knock_at_exact_size_limit() {
        // Body exactly at limit should pass raw check
        let padding = vec![b' '; MAX_BODY_BYTES];
        assert!(knock_raw(&padding).is_ok());
    }

    #[test]
    fn knock_rejects_raw_float_unc1() {
        let bytes = serde_json::to_vec(&json!({
            "@type": "ubl/test",
            "@world": "a/x/t/y",
            "amount": 12.34
        }))
        .unwrap();
        let err = knock(&bytes).unwrap_err();
        assert!(matches!(err, KnockError::RawFloat(_)));
    }

    #[test]
    fn knock_rejects_nested_float_unc1() {
        let bytes = serde_json::to_vec(&json!({
            "@type": "ubl/test",
            "@world": "a/x/t/y",
            "data": {"price": 9.99}
        }))
        .unwrap();
        let err = knock(&bytes).unwrap_err();
        assert!(matches!(err, KnockError::RawFloat(_)));
    }

    #[test]
    fn knock_accepts_integers_and_num_atoms() {
        // Integers are fine; @num objects are fine (they're objects, not floats)
        let bytes = serde_json::to_vec(&json!({
            "@type": "ubl/test",
            "@world": "a/x/t/y",
            "count": 42,
            "price": {"@num": "dec/1", "m": "1234", "s": 2}
        }))
        .unwrap();
        assert!(knock(&bytes).is_ok());
    }
}
