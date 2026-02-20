//! UBL ChipStore - Content-Addressable Storage for Chips
//!
//! The ChipStore is the persistent layer where all executed chips and their receipts
//! are stored using CIDs as primary keys. This creates an immutable, verifiable
//! storage system where every piece of data can be cryptographically verified.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use ubl_types::{Cid as TypedCid, Did as TypedDid};

pub mod backends;
pub mod indexing;
pub mod query;

/// Re-export for convenience
pub use backends::*;
pub use indexing::*;
pub use query::*;

/// A stored chip with its metadata and receipt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredChip {
    pub cid: TypedCid,
    pub chip_type: String,
    pub chip_data: serde_json::Value,
    pub receipt_cid: TypedCid,
    pub created_at: String,
    pub execution_metadata: ExecutionMetadata,
    pub tags: Vec<String>,
    pub related_chips: Vec<String>, // CIDs of related chips
}

/// Metadata about chip execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionMetadata {
    pub runtime_version: String,
    pub execution_time_ms: i64,
    pub fuel_consumed: u64,
    pub policies_applied: Vec<String>,
    pub executor_did: TypedDid,
    pub reproducible: bool,
}

/// Query criteria for searching chips
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChipQuery {
    pub chip_type: Option<String>,
    pub tags: Vec<String>,
    pub created_after: Option<String>,
    pub created_before: Option<String>,
    pub executor_did: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

/// Result of a chip query
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResult {
    pub chips: Vec<StoredChip>,
    pub total_count: usize,
    pub has_more: bool,
}

/// Trait for different storage backends
#[async_trait]
pub trait ChipStoreBackend: Send + Sync {
    /// Store a chip with its CID as key
    async fn put_chip(&self, chip: &StoredChip) -> Result<(), ChipStoreError>;

    /// Retrieve a chip by CID
    async fn get_chip(&self, cid: &str) -> Result<Option<StoredChip>, ChipStoreError>;

    /// Retrieve a chip by its receipt CID.
    async fn get_chip_by_receipt_cid(
        &self,
        receipt_cid: &str,
    ) -> Result<Option<StoredChip>, ChipStoreError>;

    /// Check if a chip exists
    async fn exists(&self, cid: &str) -> Result<bool, ChipStoreError>;

    /// Query chips by criteria
    async fn query_chips(&self, query: &ChipQuery) -> Result<QueryResult, ChipStoreError>;

    /// Get all chips of a specific type
    async fn get_chips_by_type(&self, chip_type: &str) -> Result<Vec<StoredChip>, ChipStoreError>;

    /// Get chips related to a specific chip
    async fn get_related_chips(&self, cid: &str) -> Result<Vec<StoredChip>, ChipStoreError>;

    /// Delete a chip (admin operation - breaks immutability guarantee!)
    async fn delete_chip(&self, cid: &str) -> Result<(), ChipStoreError>;

    /// Rebuild secondary indexes from stored chips.
    async fn rebuild_indexes(&self) -> Result<(), ChipStoreError>;

    /// Full scan of all stored chips from primary storage.
    async fn scan_all(&self) -> Result<Vec<StoredChip>, ChipStoreError>;
}

/// The main ChipStore interface
pub struct ChipStore {
    backend: Arc<dyn ChipStoreBackend>,
    indexer: Arc<indexing::ChipIndexer>,
}

impl ChipStore {
    /// Create a new ChipStore with the given backend
    pub fn new(backend: Arc<dyn ChipStoreBackend>) -> Self {
        Self {
            backend: backend.clone(),
            indexer: Arc::new(indexing::ChipIndexer::new(backend)),
        }
    }

    /// Create a ChipStore and rebuild in-memory indexes from persisted chips.
    pub async fn new_with_rebuild(
        backend: Arc<dyn ChipStoreBackend>,
    ) -> Result<Self, ChipStoreError> {
        let indexer = Arc::new(indexing::ChipIndexer::new(backend.clone()));
        indexer.rebuild_indexes().await?;
        Ok(Self { backend, indexer })
    }

    /// Store a chip after execution
    pub async fn store_executed_chip(
        &self,
        chip_data: serde_json::Value,
        receipt_cid: String,
        metadata: ExecutionMetadata,
    ) -> Result<String, ChipStoreError> {
        // Compute CID for the chip data
        let nrf1_bytes = ubl_ai_nrf1::to_nrf1_bytes(&chip_data)
            .map_err(|e| ChipStoreError::Serialization(e.to_string()))?;
        let cid_str = ubl_ai_nrf1::compute_cid(&nrf1_bytes)
            .map_err(|e| ChipStoreError::Serialization(e.to_string()))?;
        let cid = TypedCid::new_unchecked(&cid_str);
        let receipt_cid = TypedCid::new_unchecked(receipt_cid);

        // Extract chip type and tags
        let chip_type = chip_data
            .get("@type")
            .and_then(|t| t.as_str())
            .unwrap_or("unknown")
            .to_string();

        let tags = self.extract_tags(&chip_data, &chip_type);
        let related_chips = self.extract_relationships(&chip_data);

        let stored_chip = StoredChip {
            cid,
            chip_type,
            chip_data,
            receipt_cid,
            created_at: chrono::Utc::now().to_rfc3339(),
            execution_metadata: metadata,
            tags,
            related_chips,
        };

        // Store the chip
        self.backend.put_chip(&stored_chip).await?;

        // Update indexes
        self.indexer.index_chip(&stored_chip).await?;

        Ok(cid_str)
    }

    /// Retrieve a chip by CID
    pub async fn get_chip(&self, cid: &str) -> Result<Option<StoredChip>, ChipStoreError> {
        self.backend.get_chip(cid).await
    }

    /// Retrieve a chip by receipt CID.
    pub async fn get_chip_by_receipt_cid(
        &self,
        receipt_cid: &str,
    ) -> Result<Option<StoredChip>, ChipStoreError> {
        self.backend.get_chip_by_receipt_cid(receipt_cid).await
    }

    /// Check if a chip exists
    pub async fn exists(&self, cid: &str) -> Result<bool, ChipStoreError> {
        self.backend.exists(cid).await
    }

    /// Query chips with criteria
    pub async fn query(&self, query: &ChipQuery) -> Result<QueryResult, ChipStoreError> {
        self.backend.query_chips(query).await
    }

    /// Get all chips of a specific type
    pub async fn get_chips_by_type(
        &self,
        chip_type: &str,
    ) -> Result<Vec<StoredChip>, ChipStoreError> {
        self.backend.get_chips_by_type(chip_type).await
    }

    /// Get all customers (example business logic)
    pub async fn get_customers(&self) -> Result<Vec<StoredChip>, ChipStoreError> {
        self.backend
            .get_chips_by_type("ubl/customer.register")
            .await
    }

    /// Rebuild backend indexes from primary storage.
    pub async fn rebuild_indexes(&self) -> Result<(), ChipStoreError> {
        self.backend.rebuild_indexes().await?;
        self.indexer.rebuild_indexes().await
    }

    /// Get customer by email (example index lookup)
    pub async fn get_customer_by_email(
        &self,
        email: &str,
    ) -> Result<Option<StoredChip>, ChipStoreError> {
        let query = ChipQuery {
            chip_type: Some("ubl/customer.register".to_string()),
            tags: vec![format!("email:{}", email)],
            created_after: None,
            created_before: None,
            executor_did: None,
            limit: Some(1),
            offset: None,
        };

        let result = self.query(&query).await?;
        Ok(result.chips.into_iter().next())
    }

    /// Extract tags from chip data for indexing
    fn extract_tags(&self, chip_data: &serde_json::Value, chip_type: &str) -> Vec<String> {
        let mut tags = vec![format!("type:{}", chip_type)];

        // Extract common direct fields as tags.
        for field in [
            "email",
            "id",
            "slug",
            "status",
            "target_cid",
            "passport_cid",
            "actor_cid",
            "user_cid",
            "tenant_cid",
            "creator_cid",
            "app_cid",
            "old_did",
            "old_kid",
            "new_did",
            "new_kid",
            "rotation_chip_cid",
            "rotation_receipt_cid",
        ] {
            if let Some(value) = chip_data.get(field).and_then(|v| v.as_str()) {
                tags.push(format!("{}:{}", field, value));
            }
        }

        // Anchored identity fields.
        if let Some(id) = chip_data.get("@id").and_then(|v| v.as_str()) {
            tags.push(format!("id:{}", id));
        }
        if let Some(world) = chip_data.get("@world").and_then(|v| v.as_str()) {
            tags.push(format!("world:{}", world));
            let parts: Vec<&str> = world.split('/').collect();
            if parts.len() >= 2 && parts[0] == "a" && !parts[1].is_empty() {
                tags.push(format!("app:{}", parts[1]));
            }
            if parts.len() == 4 && parts[2] == "t" && !parts[3].is_empty() {
                tags.push(format!("tenant:{}", parts[3]));
            }
        }

        // Extract date tags
        if let Some(date) = chip_data.get("date").and_then(|v| v.as_str()) {
            if let Ok(parsed_date) = chrono::DateTime::parse_from_rfc3339(date) {
                let date_str = parsed_date.format("%Y-%m-%d").to_string();
                tags.push(format!("date:{}", date_str));
            }
        }

        tags
    }

    /// Extract relationships to other chips
    fn extract_relationships(&self, chip_data: &serde_json::Value) -> Vec<String> {
        let mut related = Vec::new();

        // Look for CID references in the data
        self.extract_cids_recursive(chip_data, &mut related);

        related
    }

    /// Recursively extract CIDs from nested data
    fn extract_cids_recursive(&self, value: &serde_json::Value, cids: &mut Vec<String>) {
        match value {
            serde_json::Value::String(s) => {
                if s.starts_with("b3:") {
                    cids.push(s.clone());
                }
            }
            serde_json::Value::Object(obj) => {
                for val in obj.values() {
                    self.extract_cids_recursive(val, cids);
                }
            }
            serde_json::Value::Array(arr) => {
                for val in arr {
                    self.extract_cids_recursive(val, cids);
                }
            }
            _ => {}
        }
    }
}

/// ChipStore errors
#[derive(Debug, thiserror::Error)]
pub enum ChipStoreError {
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Backend error: {0}")]
    Backend(String),
    #[error("Not found: {0}")]
    NotFound(String),
    #[error("Invalid CID: {0}")]
    InvalidCid(String),
    #[error("Index error: {0}")]
    Index(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Arc;

    fn test_metadata() -> ExecutionMetadata {
        ExecutionMetadata {
            runtime_version: "test-runtime".to_string(),
            execution_time_ms: 7,
            fuel_consumed: 42,
            policies_applied: vec!["p0".to_string()],
            executor_did: TypedDid::new_unchecked("did:key:zTestExecutor"),
            reproducible: true,
        }
    }

    fn test_chip() -> serde_json::Value {
        json!({
            "@type": "ubl/test",
            "@id": "chip-1",
            "@ver": "1.0",
            "@world": "a/test/t/dev",
            "status": "ok"
        })
    }

    #[tokio::test]
    async fn in_memory_lookup_by_receipt_cid() {
        let store = ChipStore::new(Arc::new(InMemoryBackend::new()));
        let receipt_cid = "b3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        let cid = store
            .store_executed_chip(test_chip(), receipt_cid.to_string(), test_metadata())
            .await
            .expect("store chip");

        let found = store
            .get_chip_by_receipt_cid(receipt_cid)
            .await
            .expect("lookup by receipt cid");

        let found = found.expect("chip exists");
        assert_eq!(found.cid.as_str(), cid);
        assert_eq!(found.receipt_cid.as_str(), receipt_cid);
    }

    #[tokio::test]
    async fn sled_lookup_by_receipt_cid() {
        let store = ChipStore::new(Arc::new(SledBackend::in_memory().expect("sled backend")));
        let receipt_cid = "b3:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

        let cid = store
            .store_executed_chip(test_chip(), receipt_cid.to_string(), test_metadata())
            .await
            .expect("store chip");

        let found = store
            .get_chip_by_receipt_cid(receipt_cid)
            .await
            .expect("lookup by receipt cid");

        let found = found.expect("chip exists");
        assert_eq!(found.cid.as_str(), cid);
        assert_eq!(found.receipt_cid.as_str(), receipt_cid);
    }

    #[tokio::test]
    async fn lookup_missing_receipt_cid_returns_none() {
        let store = ChipStore::new(Arc::new(InMemoryBackend::new()));
        let found = store
            .get_chip_by_receipt_cid(
                "b3:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            )
            .await
            .expect("lookup should succeed");
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn query_by_target_cid_tag_returns_revocation() {
        let store = ChipStore::new(Arc::new(InMemoryBackend::new()));
        let revoke = json!({
            "@type": "ubl/revoke",
            "@id": "rev-1",
            "@ver": "1.0",
            "@world": "a/test/t/dev",
            "target_cid": "b3:target123",
            "actor_cid": "b3:user123"
        });
        store
            .store_executed_chip(
                revoke,
                "b3:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_string(),
                test_metadata(),
            )
            .await
            .expect("store revoke chip");

        let result = store
            .query(&ChipQuery {
                chip_type: Some("ubl/revoke".to_string()),
                tags: vec!["target_cid:b3:target123".to_string()],
                created_after: None,
                created_before: None,
                executor_did: None,
                limit: Some(10),
                offset: None,
            })
            .await
            .expect("query revoke by target tag");

        assert_eq!(result.total_count, 1);
        assert_eq!(result.chips[0].chip_type, "ubl/revoke");
    }

    #[tokio::test]
    async fn sled_rebuilds_indexes_on_reopen() {
        let mut path = std::env::temp_dir();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        path.push(format!(
            "ubl_chipstore_idx_{}_{}",
            std::process::id(),
            nonce
        ));
        let path_str = path.to_string_lossy().to_string();

        {
            let store = ChipStore::new(Arc::new(SledBackend::new(&path_str).expect("open sled")));
            let advisory = json!({
                "@type": "ubl/advisory",
                "@id": "adv-1",
                "@ver": "1.0",
                "@world": "a/acme/t/prod",
                "passport_cid": "b3:passport123",
                "action": "observe"
            });
            store
                .store_executed_chip(
                    advisory,
                    "b3:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                        .to_string(),
                    test_metadata(),
                )
                .await
                .expect("store advisory chip");
        }

        {
            let store = ChipStore::new(Arc::new(SledBackend::new(&path_str).expect("reopen sled")));
            let result = store
                .query(&ChipQuery {
                    chip_type: Some("ubl/advisory".to_string()),
                    tags: vec!["passport_cid:b3:passport123".to_string()],
                    created_after: None,
                    created_before: None,
                    executor_did: None,
                    limit: Some(10),
                    offset: None,
                })
                .await
                .expect("query advisory by passport tag");
            assert_eq!(result.total_count, 1);
            assert_eq!(result.chips[0].chip_type, "ubl/advisory");

            let app_scoped = store
                .query(&ChipQuery {
                    chip_type: Some("ubl/advisory".to_string()),
                    tags: vec!["app:acme".to_string(), "tenant:prod".to_string()],
                    created_after: None,
                    created_before: None,
                    executor_did: None,
                    limit: Some(10),
                    offset: None,
                })
                .await
                .expect("query advisory by world tags");
            assert_eq!(app_scoped.total_count, 1);
        }

        let _ = std::fs::remove_dir_all(&path);
    }
}
