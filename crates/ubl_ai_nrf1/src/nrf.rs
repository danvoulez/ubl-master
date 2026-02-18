// NRF-1.1 canonical encoding and CID
use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::{Cursor, Read};
use unicode_normalization::UnicodeNormalization;

pub const MAGIC: [u8; 4] = [0x6e, 0x72, 0x66, 0x31];
const TAG_NULL: u8 = 0x00;
const TAG_FALSE: u8 = 0x01;
const TAG_TRUE: u8 = 0x02;
const TAG_INT64: u8 = 0x03;
const TAG_STRING: u8 = 0x04;
const TAG_BYTES: u8 = 0x05;
const TAG_ARRAY: u8 = 0x06;
const TAG_MAP: u8 = 0x07;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NrfValue {
    Null,
    Bool(bool),
    Int(i64),
    String(String),
    Bytes(Vec<u8>),
    Array(Vec<NrfValue>),
    Map(BTreeMap<String, NrfValue>),
}

pub fn encode_to_vec(value: &NrfValue) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&MAGIC);
    encode_value(value, &mut buf)?;
    Ok(buf)
}

fn encode_value(value: &NrfValue, buf: &mut Vec<u8>) -> Result<()> {
    match value {
        NrfValue::Null => buf.push(TAG_NULL),
        NrfValue::Bool(false) => buf.push(TAG_FALSE),
        NrfValue::Bool(true) => buf.push(TAG_TRUE),
        NrfValue::Int(i) => {
            buf.push(TAG_INT64);
            buf.extend_from_slice(&i.to_be_bytes());
        }
        NrfValue::String(s) => {
            buf.push(TAG_STRING);
            encode_varint32(s.len() as u32, buf);
            buf.extend_from_slice(s.as_bytes());
        }
        NrfValue::Bytes(b) => {
            buf.push(TAG_BYTES);
            encode_varint32(b.len() as u32, buf);
            buf.extend_from_slice(b);
        }
        NrfValue::Array(arr) => {
            buf.push(TAG_ARRAY);
            encode_varint32(arr.len() as u32, buf);
            for item in arr {
                encode_value(item, buf)?;
            }
        }
        NrfValue::Map(map) => {
            buf.push(TAG_MAP);
            encode_varint32(map.len() as u32, buf);
            for (k, v) in map {
                encode_value(&NrfValue::String(k.clone()), buf)?;
                encode_value(v, buf)?;
            }
        }
    }
    Ok(())
}

fn encode_varint32(mut n: u32, buf: &mut Vec<u8>) {
    loop {
        let mut byte = (n & 0x7f) as u8;
        n >>= 7;
        if n != 0 {
            byte |= 0x80;
            buf.push(byte);
        } else {
            buf.push(byte);
            break;
        }
    }
}

pub fn decode_from_slice(bytes: &[u8]) -> Result<NrfValue> {
    let mut cursor = Cursor::new(bytes);
    let mut magic = [0u8; 4];
    cursor.read_exact(&mut magic)?;
    if magic != MAGIC {
        bail!("InvalidMagic");
    }
    let value = decode_value(&mut cursor)?;
    if cursor.position() != bytes.len() as u64 {
        bail!("TrailingData");
    }
    Ok(value)
}

fn decode_value<R: Read>(r: &mut R) -> Result<NrfValue> {
    let mut tag = [0u8; 1];
    r.read_exact(&mut tag)?;
    match tag[0] {
        TAG_NULL => Ok(NrfValue::Null),
        TAG_FALSE => Ok(NrfValue::Bool(false)),
        TAG_TRUE => Ok(NrfValue::Bool(true)),
        TAG_INT64 => {
            let mut buf = [0u8; 8];
            r.read_exact(&mut buf)?;
            Ok(NrfValue::Int(i64::from_be_bytes(buf)))
        }
        TAG_STRING => {
            let len = decode_varint32(r)?;
            let mut buf = vec![0u8; len as usize];
            r.read_exact(&mut buf)?;
            let s = String::from_utf8(buf).context("InvalidUTF8")?;
            if s.chars().any(|c| c == '\u{feff}') {
                bail!("BOMPresent");
            }
            if s.nfc().collect::<String>() != s {
                bail!("NotNFC");
            }
            Ok(NrfValue::String(s))
        }
        TAG_BYTES => {
            let len = decode_varint32(r)?;
            let mut buf = vec![0u8; len as usize];
            r.read_exact(&mut buf)?;
            Ok(NrfValue::Bytes(buf))
        }
        TAG_ARRAY => {
            let count = decode_varint32(r)?;
            let mut arr = Vec::with_capacity(count as usize);
            for _ in 0..count {
                arr.push(decode_value(r)?);
            }
            Ok(NrfValue::Array(arr))
        }
        TAG_MAP => {
            let count = decode_varint32(r)?;
            let mut map = BTreeMap::new();
            for _ in 0..count {
                let key = match decode_value(r)? {
                    NrfValue::String(s) => s,
                    _ => bail!("NonStringKey"),
                };
                if map.contains_key(&key) {
                    bail!("DuplicateKey({key})");
                }
                let value = decode_value(r)?;
                map.insert(key, value);
            }
            Ok(NrfValue::Map(map))
        }
        _ => bail!("InvalidTypeTag({})", tag[0]),
    }
}

fn decode_varint32<R: Read>(r: &mut R) -> Result<u32> {
    let mut result = 0u32;
    let mut shift = 0;
    let mut bytes_read = 0;
    loop {
        let mut byte = [0u8; 1];
        r.read_exact(&mut byte)?;
        bytes_read += 1;
        let b = byte[0];
        result |= ((b & 0x7f) as u32) << shift;
        if (b & 0x80) == 0 {
            break;
        }
        shift += 7;
        if shift > 28 || bytes_read > 5 {
            bail!("NonMinimalVarint");
        }
    }
    if bytes_read > 1 && (result >> (7 * (bytes_read - 1))) == 0 {
        bail!("NonMinimalVarint");
    }
    Ok(result)
}

pub fn json_to_nrf(value: &Value) -> Result<NrfValue> {
    match value {
        Value::Null => Ok(NrfValue::Null),
        Value::Bool(b) => Ok(NrfValue::Bool(*b)),
        Value::Number(n) => {
            if n.is_i64() {
                Ok(NrfValue::Int(n.as_i64().unwrap()))
            } else {
                bail!("Number must be i64");
            }
        }
        Value::String(s) => {
            if s.chars().any(|c| c == '\u{feff}') {
                bail!("BOMPresent");
            }
            if s.chars().any(|c| ('\u{0000}'..='\u{001f}').contains(&c)) {
                bail!("ControlCharPresent");
            }
            if s.nfc().collect::<String>() != *s {
                bail!("NotNFC");
            }
            Ok(NrfValue::String(s.clone()))
        }
        Value::Array(arr) => {
            let mut items = Vec::with_capacity(arr.len());
            for v in arr {
                items.push(json_to_nrf(v)?);
            }
            Ok(NrfValue::Array(items))
        }
        Value::Object(map) => {
            let mut bt = BTreeMap::new();
            for (k, v) in map {
                if k.chars().any(|c| c == '\u{feff}') {
                    bail!("BOMPresent in key");
                }
                if k.chars().any(|c| ('\u{0000}'..='\u{001f}').contains(&c)) {
                    bail!("ControlCharPresent in key");
                }
                if k.nfc().collect::<String>() != *k {
                    bail!("NotNFC in key");
                }
                // ρ rule: null values stripped from maps (absence ≠ null)
                if v.is_null() {
                    continue;
                }
                let nrf_val = json_to_nrf(v)?;
                if bt.insert(k.clone(), nrf_val).is_some() {
                    bail!("DuplicateKey({k})");
                }
            }
            Ok(NrfValue::Map(bt))
        }
    }
}

/// Compute BLAKE3 hash of NRF-1 bytes, return as `b3:` + lowercase hex (64 chars).
pub fn cid_from_nrf_bytes(bytes: &[u8]) -> String {
    let hash = blake3::hash(bytes);
    format!("b3:{}", hex::encode(hash.as_bytes()))
}

// Public API for chip compilation
#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    #[error("Invalid format: {0}")]
    InvalidFormat(String),
    #[error("NRF encoding error: {0}")]
    NrfError(#[from] anyhow::Error),
}

/// Convert JSON to NRF-1 bytes
pub fn to_nrf1_bytes(json: &serde_json::Value) -> Result<Vec<u8>, CompileError> {
    let nrf_value = json_to_nrf(json)?;
    let bytes = encode_to_vec(&nrf_value)?;
    Ok(bytes)
}

/// Compute CID from NRF-1 bytes — BLAKE3, `b3:` prefix, lowercase hex.
pub fn compute_cid(nrf_bytes: &[u8]) -> Result<String, CompileError> {
    Ok(cid_from_nrf_bytes(nrf_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::json;

    // ── Roundtrip: every type must survive encode→decode ──────────

    #[test]
    fn roundtrip_null() {
        let v = NrfValue::Null;
        assert_eq!(v, decode_from_slice(&encode_to_vec(&v).unwrap()).unwrap());
    }

    #[test]
    fn roundtrip_bool_true() {
        let v = NrfValue::Bool(true);
        assert_eq!(v, decode_from_slice(&encode_to_vec(&v).unwrap()).unwrap());
    }

    #[test]
    fn roundtrip_bool_false() {
        let v = NrfValue::Bool(false);
        assert_eq!(v, decode_from_slice(&encode_to_vec(&v).unwrap()).unwrap());
    }

    #[test]
    fn roundtrip_int_zero() {
        let v = NrfValue::Int(0);
        assert_eq!(v, decode_from_slice(&encode_to_vec(&v).unwrap()).unwrap());
    }

    #[test]
    fn roundtrip_int_positive() {
        let v = NrfValue::Int(i64::MAX);
        assert_eq!(v, decode_from_slice(&encode_to_vec(&v).unwrap()).unwrap());
    }

    #[test]
    fn roundtrip_int_negative() {
        let v = NrfValue::Int(i64::MIN);
        assert_eq!(v, decode_from_slice(&encode_to_vec(&v).unwrap()).unwrap());
    }

    #[test]
    fn roundtrip_string() {
        let v = NrfValue::String("hello world".into());
        assert_eq!(v, decode_from_slice(&encode_to_vec(&v).unwrap()).unwrap());
    }

    #[test]
    fn roundtrip_string_empty() {
        let v = NrfValue::String(String::new());
        assert_eq!(v, decode_from_slice(&encode_to_vec(&v).unwrap()).unwrap());
    }

    #[test]
    fn roundtrip_string_unicode() {
        let v = NrfValue::String("日本語テスト 🦀".into());
        assert_eq!(v, decode_from_slice(&encode_to_vec(&v).unwrap()).unwrap());
    }

    #[test]
    fn roundtrip_bytes() {
        let v = NrfValue::Bytes(vec![0x00, 0xff, 0xde, 0xad]);
        assert_eq!(v, decode_from_slice(&encode_to_vec(&v).unwrap()).unwrap());
    }

    #[test]
    fn roundtrip_bytes_empty() {
        let v = NrfValue::Bytes(vec![]);
        assert_eq!(v, decode_from_slice(&encode_to_vec(&v).unwrap()).unwrap());
    }

    #[test]
    fn roundtrip_array() {
        let v = NrfValue::Array(vec![
            NrfValue::Int(1),
            NrfValue::String("two".into()),
            NrfValue::Bool(true),
            NrfValue::Null,
        ]);
        assert_eq!(v, decode_from_slice(&encode_to_vec(&v).unwrap()).unwrap());
    }

    #[test]
    fn roundtrip_array_empty() {
        let v = NrfValue::Array(vec![]);
        assert_eq!(v, decode_from_slice(&encode_to_vec(&v).unwrap()).unwrap());
    }

    #[test]
    fn roundtrip_map() {
        let mut m = BTreeMap::new();
        m.insert("alpha".into(), NrfValue::Int(1));
        m.insert("beta".into(), NrfValue::String("two".into()));
        let v = NrfValue::Map(m);
        assert_eq!(v, decode_from_slice(&encode_to_vec(&v).unwrap()).unwrap());
    }

    #[test]
    fn roundtrip_nested() {
        let mut inner = BTreeMap::new();
        inner.insert("x".into(), NrfValue::Int(42));
        let v = NrfValue::Map(BTreeMap::from([
            ("arr".into(), NrfValue::Array(vec![NrfValue::Map(inner)])),
            ("flag".into(), NrfValue::Bool(false)),
        ]));
        assert_eq!(v, decode_from_slice(&encode_to_vec(&v).unwrap()).unwrap());
    }

    // ── Golden vector: exact bytes for known input ────────────────

    #[test]
    fn golden_vector_hello_world() {
        let v = NrfValue::Map(BTreeMap::from([
            ("hello".into(), NrfValue::String("world".into())),
            ("n".into(), NrfValue::Int(42)),
        ]));
        let bytes = encode_to_vec(&v).unwrap();
        // Magic "nrf1"
        assert_eq!(&bytes[0..4], &MAGIC);
        // Tag MAP
        assert_eq!(bytes[4], TAG_MAP);
        // Determinism: same value always produces same bytes
        let bytes2 = encode_to_vec(&v).unwrap();
        assert_eq!(bytes, bytes2, "encoding must be deterministic");
        // CID must be stable
        let cid1 = cid_from_nrf_bytes(&bytes);
        let cid2 = cid_from_nrf_bytes(&bytes2);
        assert_eq!(cid1, cid2);
    }

    #[test]
    fn golden_vector_cid_stability() {
        // Golden CID for {hello:world,n:42} — BLAKE3. If this changes, canon broke.
        let j = json!({"hello":"world","n":42});
        let nrf_val = json_to_nrf(&j).unwrap();
        let bytes = encode_to_vec(&nrf_val).unwrap();
        let cid = cid_from_nrf_bytes(&bytes);
        assert_eq!(
            cid, "b3:fd38c071ca3e1ede2a135645677d5326bbf91fb9cfe56a36f2d54636b75e7cd2",
            "CID for {{hello:world,n:42}} must be stable across builds (BLAKE3)"
        );
    }

    // ── json_to_nrf: ρ enforcement ───────────────────────────────

    #[test]
    fn json_to_nrf_sorts_keys() {
        let j = json!({"z": 1, "a": 2, "m": 3});
        let nrf = json_to_nrf(&j).unwrap();
        if let NrfValue::Map(m) = &nrf {
            let keys: Vec<&String> = m.keys().collect();
            assert_eq!(keys, vec!["a", "m", "z"], "keys must be sorted");
        } else {
            panic!("expected Map");
        }
    }

    #[test]
    fn json_to_nrf_rejects_float() {
        let j = json!(std::f64::consts::PI);
        let err = json_to_nrf(&j);
        assert!(err.is_err(), "floats must be rejected");
        assert!(err.unwrap_err().to_string().contains("i64"));
    }

    #[test]
    fn json_to_nrf_rejects_bom_in_value() {
        let j = json!("\u{feff}hello");
        let err = json_to_nrf(&j);
        assert!(err.is_err(), "BOM in string value must be rejected");
    }

    #[test]
    fn json_to_nrf_rejects_bom_in_key() {
        let j = json!({"\u{feff}key": "val"});
        let err = json_to_nrf(&j);
        assert!(err.is_err(), "BOM in map key must be rejected");
    }

    #[test]
    fn json_to_nrf_rejects_non_nfc_value() {
        // U+00E9 (é) is NFC. U+0065 U+0301 (e + combining acute) is NFD.
        let nfd_str = "e\u{0301}"; // NFD form
        let j = Value::String(nfd_str.to_string());
        let err = json_to_nrf(&j);
        assert!(err.is_err(), "non-NFC string must be rejected");
    }

    #[test]
    fn json_to_nrf_accepts_nfc_string() {
        let nfc_str = "\u{00e9}"; // é in NFC
        let j = Value::String(nfc_str.to_string());
        let nrf = json_to_nrf(&j).unwrap();
        assert_eq!(nrf, NrfValue::String(nfc_str.to_string()));
    }

    #[test]
    fn json_to_nrf_null_array_nested() {
        let j = json!({"a": [null, true, 99, "x"]});
        let nrf = json_to_nrf(&j).unwrap();
        let bytes = encode_to_vec(&nrf).unwrap();
        let decoded = decode_from_slice(&bytes).unwrap();
        assert_eq!(nrf, decoded, "nested structure must roundtrip exactly");
    }

    // ── Canon hardening: control chars + null stripping ────────

    #[test]
    fn json_to_nrf_rejects_control_char_in_value() {
        let j = json!("hello\u{0000}world");
        let err = json_to_nrf(&j);
        assert!(err.is_err(), "null byte in string must be rejected");
        assert!(err.unwrap_err().to_string().contains("ControlChar"));
    }

    #[test]
    fn json_to_nrf_rejects_tab_in_value() {
        let j = json!("hello\tworld");
        let err = json_to_nrf(&j);
        assert!(err.is_err(), "tab (U+0009) in string must be rejected");
    }

    #[test]
    fn json_to_nrf_rejects_newline_in_value() {
        let j = json!("hello\nworld");
        let err = json_to_nrf(&j);
        assert!(err.is_err(), "newline (U+000A) in string must be rejected");
    }

    #[test]
    fn json_to_nrf_rejects_control_char_in_key() {
        let mut map = serde_json::Map::new();
        map.insert("bad\u{001f}key".to_string(), json!(1));
        let j = Value::Object(map);
        let err = json_to_nrf(&j);
        assert!(err.is_err(), "control char in key must be rejected");
        assert!(err.unwrap_err().to_string().contains("ControlChar"));
    }

    #[test]
    fn json_to_nrf_null_stripping_in_map() {
        let j = json!({"a": null, "b": 1, "c": null});
        let nrf = json_to_nrf(&j).unwrap();
        if let NrfValue::Map(m) = &nrf {
            assert_eq!(m.len(), 1, "null values must be stripped from maps");
            assert!(m.contains_key("b"));
            assert!(!m.contains_key("a"));
            assert!(!m.contains_key("c"));
        } else {
            panic!("expected Map");
        }
    }

    #[test]
    fn json_to_nrf_null_stripping_all_null_map() {
        let j = json!({"x": null, "y": null});
        let nrf = json_to_nrf(&j).unwrap();
        if let NrfValue::Map(m) = &nrf {
            assert_eq!(m.len(), 0, "all-null map must become empty map");
        } else {
            panic!("expected Map");
        }
    }

    #[test]
    fn json_to_nrf_null_preserved_in_array() {
        let j = json!([null, 1, null]);
        let nrf = json_to_nrf(&j).unwrap();
        if let NrfValue::Array(arr) = &nrf {
            assert_eq!(arr.len(), 3, "nulls in arrays must be preserved");
            assert_eq!(arr[0], NrfValue::Null);
            assert_eq!(arr[2], NrfValue::Null);
        } else {
            panic!("expected Array");
        }
    }

    // ── Decode: rejection of invalid bytes ───────────────────────

    #[test]
    fn decode_rejects_bad_magic() {
        let err = decode_from_slice(&[0x00, 0x00, 0x00, 0x00, TAG_NULL]);
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("InvalidMagic"));
    }

    #[test]
    fn decode_rejects_trailing_data() {
        let mut bytes = encode_to_vec(&NrfValue::Null).unwrap();
        bytes.push(0xFF); // trailing garbage
        let err = decode_from_slice(&bytes);
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("TrailingData"));
    }

    #[test]
    fn decode_rejects_unknown_tag() {
        let mut bytes = MAGIC.to_vec();
        bytes.push(0xFE); // invalid tag
        let err = decode_from_slice(&bytes);
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("InvalidTypeTag"));
    }

    #[test]
    fn decode_rejects_truncated_int() {
        let mut bytes = MAGIC.to_vec();
        bytes.push(TAG_INT64);
        bytes.extend_from_slice(&[0x00, 0x00]); // only 2 of 8 bytes
        let err = decode_from_slice(&bytes);
        assert!(err.is_err(), "truncated int must fail");
    }

    #[test]
    fn decode_rejects_bom_in_string() {
        // Manually encode a string with BOM
        let mut bytes = MAGIC.to_vec();
        bytes.push(TAG_STRING);
        let s = "\u{feff}bad";
        encode_varint32(s.len() as u32, &mut bytes);
        bytes.extend_from_slice(s.as_bytes());
        let err = decode_from_slice(&bytes);
        assert!(err.is_err(), "BOM in decoded string must be rejected");
    }

    // ── CID determinism ──────────────────────────────────────────

    #[test]
    fn cid_deterministic_for_same_bytes() {
        let bytes = encode_to_vec(&NrfValue::Int(12345)).unwrap();
        let c1 = cid_from_nrf_bytes(&bytes);
        let c2 = cid_from_nrf_bytes(&bytes);
        assert_eq!(c1, c2);
        assert!(c1.starts_with("b3:"), "CID must use b3: prefix (BLAKE3)");
    }

    #[test]
    fn cid_different_for_different_bytes() {
        let b1 = encode_to_vec(&NrfValue::Int(1)).unwrap();
        let b2 = encode_to_vec(&NrfValue::Int(2)).unwrap();
        assert_ne!(cid_from_nrf_bytes(&b1), cid_from_nrf_bytes(&b2));
    }

    // ── Map key ordering in encoding ─────────────────────────────

    #[test]
    fn map_encoding_is_sorted() {
        // BTreeMap guarantees sorted keys, but verify the bytes are identical
        // regardless of insertion order (BTreeMap handles this, but let's prove it)
        let mut m1 = BTreeMap::new();
        m1.insert("z".into(), NrfValue::Int(1));
        m1.insert("a".into(), NrfValue::Int(2));
        let mut m2 = BTreeMap::new();
        m2.insert("a".into(), NrfValue::Int(2));
        m2.insert("z".into(), NrfValue::Int(1));
        let b1 = encode_to_vec(&NrfValue::Map(m1)).unwrap();
        let b2 = encode_to_vec(&NrfValue::Map(m2)).unwrap();
        assert_eq!(b1, b2, "map encoding must be key-sorted and deterministic");
    }

    proptest! {
        #[test]
        fn cid_is_invariant_under_object_insertion_order(
            entries in proptest::collection::btree_map("[a-z]{1,8}", -10_000i64..10_000, 1..16)
        ) {
            let mut forward = serde_json::Map::new();
            for (k, v) in &entries {
                forward.insert(k.clone(), json!(*v));
            }

            let mut reverse = serde_json::Map::new();
            for (k, v) in entries.iter().rev() {
                reverse.insert(k.clone(), json!(*v));
            }

            let bytes_forward = to_nrf1_bytes(&Value::Object(forward)).unwrap();
            let bytes_reverse = to_nrf1_bytes(&Value::Object(reverse)).unwrap();
            prop_assert_eq!(&bytes_forward, &bytes_reverse);
            prop_assert_eq!(compute_cid(&bytes_forward).unwrap(), compute_cid(&bytes_reverse).unwrap());
        }

        #[test]
        fn map_null_stripping_matches_explicit_removal(
            entries in proptest::collection::btree_map("[a-z]{1,8}", proptest::option::of(-10_000i64..10_000), 1..16)
        ) {
            let mut with_nulls = serde_json::Map::new();
            let mut stripped = serde_json::Map::new();

            for (k, v) in entries {
                match v {
                    Some(n) => {
                        with_nulls.insert(k.clone(), json!(n));
                        stripped.insert(k, json!(n));
                    }
                    None => {
                        with_nulls.insert(k, Value::Null);
                    }
                }
            }

            let bytes_with_nulls = to_nrf1_bytes(&Value::Object(with_nulls)).unwrap();
            let bytes_stripped = to_nrf1_bytes(&Value::Object(stripped)).unwrap();
            prop_assert_eq!(bytes_with_nulls, bytes_stripped);
        }

        #[test]
        fn rejects_control_chars_in_values(
            control in 0u8..=31u8,
            prefix in "[a-zA-Z0-9]{0,8}",
            suffix in "[a-zA-Z0-9]{0,8}",
        ) {
            let s = format!("{prefix}{}{suffix}", char::from(control));
            let err = json_to_nrf(&Value::String(s));
            prop_assert!(err.is_err());
            prop_assert!(err.unwrap_err().to_string().contains("ControlChar"));
        }

        #[test]
        fn rejects_control_chars_in_keys(
            control in 0u8..=31u8,
            key_suffix in "[a-z]{0,6}"
        ) {
            let key = format!("k{}{}", char::from(control), key_suffix);
            let mut map = serde_json::Map::new();
            map.insert(key, json!(1));
            let err = json_to_nrf(&Value::Object(map));
            prop_assert!(err.is_err());
            prop_assert!(err.unwrap_err().to_string().contains("ControlChar"));
        }

        #[test]
        fn rejects_non_nfc_strings(
            prefix in "[a-z]{0,6}",
            suffix in "[a-z]{0,6}",
        ) {
            let nfd = format!("{prefix}e\u{0301}{suffix}");
            let err = json_to_nrf(&Value::String(nfd));
            prop_assert!(err.is_err());
            prop_assert!(err.unwrap_err().to_string().contains("NotNFC"));
        }
    }
}
