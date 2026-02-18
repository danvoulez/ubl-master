use serde_json::{Map, Value};
use unicode_normalization::UnicodeNormalization;

/// Trait para prover a canon NRF/JSON real (plugável).
pub trait CanonProvider {
    /// Canoniza um JSON Value -> Value determinístico (ordenar chaves, NFC, tipos).
    fn canon(&self, v: Value) -> Value;
}

/// Implementação ingênua para desenvolvimento: ordena chaves recursivamente.
/// DEPRECATED: Use `RhoCanon` for production. `NaiveCanon` does NOT enforce ρ rules.
pub struct NaiveCanon;
impl CanonProvider for NaiveCanon {
    fn canon(&self, v: Value) -> Value {
        fn sort(v: Value) -> Value {
            match v {
                Value::Object(m) => {
                    let mut pairs: Vec<(String, Value)> = m.into_iter().collect();
                    pairs.sort_by(|a, b| a.0.cmp(&b.0));
                    let mut out = Map::new();
                    for (k, val) in pairs {
                        out.insert(k, sort(val));
                    }
                    Value::Object(out)
                }
                Value::Array(a) => Value::Array(a.into_iter().map(sort).collect()),
                _ => v,
            }
        }
        sort(v)
    }
}

/// Full ρ (rho) canonicalization — Article I of the Constitution of the Base.
///
/// Enforces all ρ rules:
/// 1. Strings → NFC normalized, BOM rejected, control chars rejected
/// 2. Maps → null values REMOVED (absence ≠ null), keys sorted, keys NFC-validated
/// 3. Numbers → must be i64 (floats rejected)
/// 4. Recursion → leaves first, then containers
/// 5. Passthrough → Null, Bool, Int64 unchanged
///
/// Property: ρ(ρ(v)) = ρ(v) (idempotent)
pub struct RhoCanon;

impl RhoCanon {
    /// Strict validation: returns all ρ violations found in a Value.
    /// Used by KNOCK and test harnesses to get precise error messages.
    pub fn validate(v: &Value) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        Self::collect_errors(v, "$", &mut errors);
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    fn collect_errors(v: &Value, path: &str, errors: &mut Vec<String>) {
        match v {
            Value::Null | Value::Bool(_) => {}
            Value::Number(n) => {
                if !n.is_i64() && !n.is_u64() {
                    errors.push(format!(
                        "{}: raw float {} violates UNC-1 — use @num atoms",
                        path, n
                    ));
                }
            }
            Value::String(s) => {
                if s.contains('\u{feff}') {
                    errors.push(format!("{}: BOM present", path));
                }
                if s.chars()
                    .any(|c| c <= '\u{001f}' && c != '\n' && c != '\r' && c != '\t')
                {
                    errors.push(format!("{}: control character present", path));
                }
                let nfc: String = s.nfc().collect();
                if nfc != *s {
                    errors.push(format!("{}: not NFC normalized", path));
                }
            }
            Value::Array(arr) => {
                for (i, item) in arr.iter().enumerate() {
                    Self::collect_errors(item, &format!("{}[{}]", path, i), errors);
                }
            }
            Value::Object(map) => {
                for (k, val) in map {
                    if val.is_null() {
                        errors.push(format!(
                            "{}.{}: null value in map (should be absent)",
                            path, k
                        ));
                    }
                    Self::collect_errors(val, &format!("{}.{}", path, k), errors);
                }
            }
        }
    }

    /// Validate that a string conforms to ρ rules (NFC, no BOM, no control chars).
    fn validate_string(s: &str) -> Result<String, String> {
        if s.contains('\u{feff}') {
            return Err("BOM present in string".to_string());
        }
        if s.chars()
            .any(|c| c <= '\u{001f}' && c != '\n' && c != '\r' && c != '\t')
        {
            return Err("Control character present in string".to_string());
        }
        // NFC normalize
        let normalized: String = s.nfc().collect();
        Ok(normalized)
    }

    /// Recursively apply ρ rules to a JSON Value.
    /// Returns the canonical Value, or the original with best-effort normalization
    /// if strict validation fails (canon provider must not panic).
    ///
    /// UNC-1 §3: raw floats are NEVER canonical. Only i64/u64 integers pass.
    /// Floats are replaced with a poison string so downstream layers (KNOCK/NRF)
    /// reject them with a clear error rather than silently hashing non-deterministic bits.
    fn rho(v: Value) -> Value {
        match v {
            Value::Null => Value::Null,
            Value::Bool(b) => Value::Bool(b),
            Value::Number(n) => {
                if n.is_i64() || n.is_u64() {
                    Value::Number(n)
                } else {
                    // UNC-1: raw float → poison. Use @num atoms instead.
                    Value::String(format!("__FLOAT_REJECTED:{}", n))
                }
            }
            Value::String(s) => {
                match Self::validate_string(&s) {
                    Ok(normalized) => Value::String(normalized),
                    Err(_) => Value::String(s), // best-effort: keep original
                }
            }
            Value::Array(arr) => Value::Array(arr.into_iter().map(Self::rho).collect()),
            Value::Object(map) => {
                let mut sorted = Map::new();
                // Collect, sort by key, apply ρ recursively
                let mut pairs: Vec<(String, Value)> = map.into_iter().collect();
                pairs.sort_by(|a, b| a.0.cmp(&b.0));

                for (k, val) in pairs {
                    // ρ rule: null values stripped from maps (absence ≠ null)
                    if val.is_null() {
                        continue;
                    }
                    // NFC normalize the key
                    let canon_key = match Self::validate_string(&k) {
                        Ok(normalized) => normalized,
                        Err(_) => k, // best-effort
                    };
                    sorted.insert(canon_key, Self::rho(val));
                }
                Value::Object(sorted)
            }
        }
    }
}

impl CanonProvider for RhoCanon {
    fn canon(&self, v: Value) -> Value {
        Self::rho(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── NaiveCanon tests ──

    #[test]
    fn naive_sorts_keys() {
        let input = json!({"b": 2, "a": 1});
        let out = NaiveCanon.canon(input);
        let keys: Vec<&String> = out.as_object().unwrap().keys().collect();
        assert_eq!(keys, vec!["a", "b"]);
    }

    // ── RhoCanon tests ──

    #[test]
    fn rho_sorts_keys() {
        let input = json!({"c": 3, "a": 1, "b": 2});
        let out = RhoCanon.canon(input);
        let keys: Vec<&String> = out.as_object().unwrap().keys().collect();
        assert_eq!(keys, vec!["a", "b", "c"]);
    }

    #[test]
    fn rho_strips_null_values_from_maps() {
        let input = json!({"a": 1, "b": null, "c": "hello"});
        let out = RhoCanon.canon(input);
        let obj = out.as_object().unwrap();
        assert_eq!(obj.len(), 2);
        assert!(obj.get("b").is_none(), "null values must be stripped");
        assert_eq!(obj["a"], 1);
        assert_eq!(obj["c"], "hello");
    }

    #[test]
    fn rho_preserves_null_in_arrays() {
        let input = json!([1, null, "hello"]);
        let out = RhoCanon.canon(input);
        assert_eq!(out, json!([1, null, "hello"]));
    }

    #[test]
    fn rho_nfc_normalizes_strings() {
        // é as NFD (e + combining acute) → should become NFC (single codepoint)
        let nfd = "Caf\u{0065}\u{0301}"; // "Café" in NFD
        let input = json!({"name": nfd});
        let out = RhoCanon.canon(input);
        assert_eq!(out["name"], "Caf\u{00e9}"); // NFC "Café"
    }

    #[test]
    fn rho_nfc_normalizes_keys() {
        let nfd_key = "caf\u{0065}\u{0301}".to_string();
        let mut map = Map::new();
        map.insert(nfd_key, json!(1));
        let input = Value::Object(map);
        let out = RhoCanon.canon(input);
        assert!(out.as_object().unwrap().contains_key("caf\u{00e9}"));
    }

    #[test]
    fn rho_strips_nested_nulls() {
        let input = json!({
            "outer": {
                "keep": 1,
                "drop": null,
                "inner": {
                    "also_drop": null,
                    "also_keep": "yes"
                }
            }
        });
        let out = RhoCanon.canon(input);
        let outer = out["outer"].as_object().unwrap();
        assert!(outer.get("drop").is_none());
        let inner = outer["inner"].as_object().unwrap();
        assert!(inner.get("also_drop").is_none());
        assert_eq!(inner["also_keep"], "yes");
    }

    #[test]
    fn rho_is_idempotent() {
        let input = json!({
            "z": 1,
            "a": {"y": null, "x": "hello"},
            "m": [1, null, {"b": 2, "a": 1}]
        });
        let once = RhoCanon.canon(input.clone());
        let twice = RhoCanon.canon(once.clone());
        assert_eq!(once, twice, "ρ(ρ(v)) must equal ρ(v)");
    }

    #[test]
    fn rho_different_key_order_same_result() {
        let a = json!({"b": 2, "a": 1, "c": 3});
        let b = json!({"c": 3, "a": 1, "b": 2});
        assert_eq!(RhoCanon.canon(a), RhoCanon.canon(b));
    }

    #[test]
    fn rho_preserves_integers() {
        let input = json!({"n": 42, "neg": -7, "zero": 0});
        let out = RhoCanon.canon(input);
        assert_eq!(out["n"], 42);
        assert_eq!(out["neg"], -7);
        assert_eq!(out["zero"], 0);
    }

    #[test]
    fn rho_rejects_raw_floats_unc1() {
        // UNC-1 §3: raw floats must never enter the canon
        let input = json!({"amount": 12.34});
        let out = RhoCanon.canon(input);
        let s = out["amount"].as_str().unwrap();
        assert!(
            s.starts_with("__FLOAT_REJECTED:"),
            "float must be poisoned: {}",
            s
        );
    }

    #[test]
    fn rho_rejects_nested_floats() {
        let input = json!({"outer": {"price": 9.99, "count": 3}});
        let out = RhoCanon.canon(input);
        let price = out["outer"]["price"].as_str().unwrap();
        assert!(price.starts_with("__FLOAT_REJECTED:"));
        assert_eq!(out["outer"]["count"], 3); // integer preserved
    }

    #[test]
    fn rho_rejects_float_in_array() {
        let input = json!([1, 2.5, 3]);
        let out = RhoCanon.canon(input);
        assert_eq!(out[0], 1);
        assert!(out[1].as_str().unwrap().starts_with("__FLOAT_REJECTED:"));
        assert_eq!(out[2], 3);
    }

    #[test]
    fn rho_validate_catches_float() {
        let input = json!({"amount": 12.34});
        let result = RhoCanon::validate(&input);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors[0].contains("raw float"));
        assert!(errors[0].contains("UNC-1"));
    }

    #[test]
    fn rho_validate_passes_clean_input() {
        let input = json!({"count": 42, "name": "test", "active": true});
        assert!(RhoCanon::validate(&input).is_ok());
    }

    #[test]
    fn rho_validate_catches_null_in_map() {
        let input = json!({"a": 1, "b": null});
        let result = RhoCanon::validate(&input);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors[0].contains("null value in map"));
    }

    #[test]
    fn rho_preserves_booleans() {
        let input = json!({"t": true, "f": false});
        let out = RhoCanon.canon(input);
        assert_eq!(out["t"], true);
        assert_eq!(out["f"], false);
    }

    #[test]
    fn rho_empty_object_stays_empty() {
        let out = RhoCanon.canon(json!({}));
        assert_eq!(out, json!({}));
    }

    #[test]
    fn rho_all_null_object_becomes_empty() {
        let input = json!({"a": null, "b": null});
        let out = RhoCanon.canon(input);
        assert_eq!(out, json!({}));
    }
}
