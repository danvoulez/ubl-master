use serde_json::{Map, Value};

/// Trait para prover a canon NRF/JSON real (plugável).
pub trait CanonProvider {
    /// Canoniza um JSON Value -> Value determinístico (ordenar chaves, NFC, tipos).
    fn canon(&self, v: Value) -> Value;
}

/// Implementação ingênua para desenvolvimento: ordena chaves recursivamente.
pub struct NaiveCanon;
impl CanonProvider for NaiveCanon {
    fn canon(&self, v: Value) -> Value {
        fn sort(v: Value) -> Value {
            match v {
                Value::Object(m) => {
                    // ordena por chave e aplica recursão
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
