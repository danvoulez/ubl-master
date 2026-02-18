//! Rigid idempotency for command chips.
//!
//! Per the "ato oficial" §P0.1:
//! - Key = `(@type, @ver, @world, @id)` extracted from chip body.
//! - On replay, return the **same receipt/output** — no re-execution.
//! - Lookup happens in Gate/Pipeline before TR/WF.
//!
//! The store is in-memory (HashMap behind RwLock). Production deployments
//! can swap in a persistent backend via the `IdempotencyBackend` trait.

use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// The four-part idempotency key for command chips.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct IdempotencyKey {
    pub at_type: String,
    pub at_ver: String,
    pub at_world: String,
    pub at_id: String,
}

impl IdempotencyKey {
    /// Extract idempotency key from a chip body.
    /// Returns `None` if any of the four fields is missing (non-command chip).
    pub fn from_chip_body(body: &Value) -> Option<Self> {
        let at_type = body.get("@type")?.as_str()?;
        let at_ver = body.get("@ver")?.as_str()?;
        let at_world = body.get("@world")?.as_str()?;
        let at_id = body.get("@id")?.as_str()?;

        if at_type.is_empty() || at_id.is_empty() {
            return None;
        }

        Some(Self {
            at_type: at_type.to_string(),
            at_ver: at_ver.to_string(),
            at_world: at_world.to_string(),
            at_id: at_id.to_string(),
        })
    }

    /// Canonical string representation for logging/metrics.
    pub fn to_string_key(&self) -> String {
        format!(
            "{}|{}|{}|{}",
            self.at_type, self.at_ver, self.at_world, self.at_id
        )
    }

    /// Stable durable key used by persistent idempotency backends.
    /// Format: `blake3_hex(@type|@ver|@world|@id)`.
    pub fn to_durable_key(&self) -> String {
        let digest = blake3::hash(self.to_string_key().as_bytes());
        hex::encode(digest.as_bytes())
    }
}

impl std::fmt::Display for IdempotencyKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "({}, {}, {}, {})",
            self.at_type, self.at_ver, self.at_world, self.at_id
        )
    }
}

/// Cached pipeline result for idempotent replay.
#[derive(Debug, Clone)]
pub struct CachedResult {
    /// The receipt CID from the original execution.
    pub receipt_cid: String,
    /// The full pipeline result JSON (serialized PipelineResult).
    pub response_json: Value,
    /// The decision string ("Allow" or "Deny").
    pub decision: String,
    /// Chain of CIDs from the original execution.
    pub chain: Vec<String>,
    /// Timestamp of original execution.
    pub created_at: String,
}

/// In-memory idempotency store.
#[derive(Clone)]
pub struct IdempotencyStore {
    entries: Arc<RwLock<HashMap<IdempotencyKey, CachedResult>>>,
}

impl IdempotencyStore {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Check if a result exists for this key.
    pub async fn get(&self, key: &IdempotencyKey) -> Option<CachedResult> {
        let entries = self.entries.read().await;
        entries.get(key).cloned()
    }

    /// Store a result for this key.
    pub async fn put(&self, key: IdempotencyKey, result: CachedResult) {
        let mut entries = self.entries.write().await;
        entries.insert(key, result);
    }

    /// Check if a key exists without cloning the result.
    pub async fn contains(&self, key: &IdempotencyKey) -> bool {
        let entries = self.entries.read().await;
        entries.contains_key(key)
    }

    /// Number of cached entries.
    pub async fn len(&self) -> usize {
        let entries = self.entries.read().await;
        entries.len()
    }

    /// Whether there are no cached entries.
    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }

    /// Prune entries older than the given duration.
    pub async fn prune_older_than(&self, max_age: std::time::Duration) {
        let cutoff = chrono::Utc::now() - chrono::Duration::from_std(max_age).unwrap_or_default();
        let cutoff_str = cutoff.to_rfc3339();
        let mut entries = self.entries.write().await;
        entries.retain(|_, v| v.created_at > cutoff_str);
    }
}

impl Default for IdempotencyStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn extract_key_from_valid_chip() {
        let body = json!({
            "@type": "ubl/user",
            "@ver": "1.0",
            "@world": "a/acme/t/prod",
            "@id": "alice-001"
        });
        let key = IdempotencyKey::from_chip_body(&body).unwrap();
        assert_eq!(key.at_type, "ubl/user");
        assert_eq!(key.at_ver, "1.0");
        assert_eq!(key.at_world, "a/acme/t/prod");
        assert_eq!(key.at_id, "alice-001");
    }

    #[test]
    fn missing_field_returns_none() {
        // Missing @id
        let body = json!({
            "@type": "ubl/user",
            "@ver": "1.0",
            "@world": "a/acme/t/prod"
        });
        assert!(IdempotencyKey::from_chip_body(&body).is_none());

        // Missing @ver
        let body = json!({
            "@type": "ubl/user",
            "@world": "a/acme/t/prod",
            "@id": "alice"
        });
        assert!(IdempotencyKey::from_chip_body(&body).is_none());
    }

    #[test]
    fn empty_type_returns_none() {
        let body = json!({
            "@type": "",
            "@ver": "1.0",
            "@world": "a/acme/t/prod",
            "@id": "alice"
        });
        assert!(IdempotencyKey::from_chip_body(&body).is_none());
    }

    #[test]
    fn same_fields_same_key() {
        let body1 = json!({"@type": "ubl/user", "@ver": "1.0", "@world": "a/x/t/y", "@id": "a"});
        let body2 = json!({"@type": "ubl/user", "@ver": "1.0", "@world": "a/x/t/y", "@id": "a", "extra": "ignored"});
        let k1 = IdempotencyKey::from_chip_body(&body1).unwrap();
        let k2 = IdempotencyKey::from_chip_body(&body2).unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn different_id_different_key() {
        let body1 = json!({"@type": "ubl/user", "@ver": "1.0", "@world": "a/x/t/y", "@id": "a"});
        let body2 = json!({"@type": "ubl/user", "@ver": "1.0", "@world": "a/x/t/y", "@id": "b"});
        let k1 = IdempotencyKey::from_chip_body(&body1).unwrap();
        let k2 = IdempotencyKey::from_chip_body(&body2).unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn to_string_key_format() {
        let key = IdempotencyKey {
            at_type: "ubl/user".into(),
            at_ver: "1.0".into(),
            at_world: "a/acme/t/prod".into(),
            at_id: "alice".into(),
        };
        assert_eq!(key.to_string_key(), "ubl/user|1.0|a/acme/t/prod|alice");
    }

    #[tokio::test]
    async fn store_put_and_get() {
        let store = IdempotencyStore::new();
        let key = IdempotencyKey {
            at_type: "ubl/user".into(),
            at_ver: "1.0".into(),
            at_world: "a/x/t/y".into(),
            at_id: "alice".into(),
        };
        let cached = CachedResult {
            receipt_cid: "b3:abc123".into(),
            response_json: json!({"decision": "Allow"}),
            decision: "Allow".into(),
            chain: vec!["b3:wa".into(), "b3:tr".into(), "b3:wf".into()],
            created_at: chrono::Utc::now().to_rfc3339(),
        };

        assert!(!store.contains(&key).await);
        store.put(key.clone(), cached.clone()).await;
        assert!(store.contains(&key).await);

        let got = store.get(&key).await.unwrap();
        assert_eq!(got.receipt_cid, "b3:abc123");
        assert_eq!(got.decision, "Allow");
        assert_eq!(got.chain.len(), 3);
    }

    #[tokio::test]
    async fn store_len() {
        let store = IdempotencyStore::new();
        assert_eq!(store.len().await, 0);

        for i in 0..5 {
            let key = IdempotencyKey {
                at_type: "ubl/user".into(),
                at_ver: "1.0".into(),
                at_world: "a/x/t/y".into(),
                at_id: format!("user-{}", i),
            };
            store
                .put(
                    key,
                    CachedResult {
                        receipt_cid: format!("b3:{}", i),
                        response_json: json!({}),
                        decision: "Allow".into(),
                        chain: vec![],
                        created_at: chrono::Utc::now().to_rfc3339(),
                    },
                )
                .await;
        }
        assert_eq!(store.len().await, 5);
    }

    #[tokio::test]
    async fn duplicate_put_overwrites() {
        let store = IdempotencyStore::new();
        let key = IdempotencyKey {
            at_type: "ubl/user".into(),
            at_ver: "1.0".into(),
            at_world: "a/x/t/y".into(),
            at_id: "alice".into(),
        };

        store
            .put(
                key.clone(),
                CachedResult {
                    receipt_cid: "b3:first".into(),
                    response_json: json!({}),
                    decision: "Allow".into(),
                    chain: vec![],
                    created_at: chrono::Utc::now().to_rfc3339(),
                },
            )
            .await;

        // Same key, different result — should overwrite
        store
            .put(
                key.clone(),
                CachedResult {
                    receipt_cid: "b3:second".into(),
                    response_json: json!({}),
                    decision: "Deny".into(),
                    chain: vec![],
                    created_at: chrono::Utc::now().to_rfc3339(),
                },
            )
            .await;

        let got = store.get(&key).await.unwrap();
        assert_eq!(got.receipt_cid, "b3:second");
        assert_eq!(store.len().await, 1);
    }

    #[tokio::test]
    async fn replay_returns_same_result() {
        let store = IdempotencyStore::new();

        let body = json!({
            "@type": "ubl/token",
            "@ver": "1.0",
            "@world": "a/acme/t/prod",
            "@id": "tok-001"
        });

        let key = IdempotencyKey::from_chip_body(&body).unwrap();
        let original = CachedResult {
            receipt_cid: "b3:original_receipt".into(),
            response_json: json!({"status": "success", "receipt_cid": "b3:original_receipt"}),
            decision: "Allow".into(),
            chain: vec!["b3:wa1".into(), "b3:tr1".into(), "b3:wf1".into()],
            created_at: chrono::Utc::now().to_rfc3339(),
        };

        store.put(key.clone(), original).await;

        // "Replay" — same chip body, extract same key
        let body_replay = json!({
            "@type": "ubl/token",
            "@ver": "1.0",
            "@world": "a/acme/t/prod",
            "@id": "tok-001",
            "extra_field": "should be ignored for key"
        });
        let replay_key = IdempotencyKey::from_chip_body(&body_replay).unwrap();
        assert_eq!(key, replay_key);

        let cached = store.get(&replay_key).await.unwrap();
        assert_eq!(cached.receipt_cid, "b3:original_receipt");
        assert_eq!(cached.chain.len(), 3);
    }
}
