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
        let chip_type = chip_data.get("@type")
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

    /// Check if a chip exists
    pub async fn exists(&self, cid: &str) -> Result<bool, ChipStoreError> {
        self.backend.exists(cid).await
    }

    /// Query chips with criteria
    pub async fn query(&self, query: &ChipQuery) -> Result<QueryResult, ChipStoreError> {
        self.backend.query_chips(query).await
    }

    /// Get all chips of a specific type
    pub async fn get_chips_by_type(&self, chip_type: &str) -> Result<Vec<StoredChip>, ChipStoreError> {
        self.backend.get_chips_by_type(chip_type).await
    }

    /// Get all customers (example business logic)
    pub async fn get_customers(&self) -> Result<Vec<StoredChip>, ChipStoreError> {
        self.backend.get_chips_by_type("ubl/customer.register").await
    }

    /// Get customer by email (example index lookup)
    pub async fn get_customer_by_email(&self, email: &str) -> Result<Option<StoredChip>, ChipStoreError> {
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

        // Extract common fields as tags
        if let Some(email) = chip_data.get("email").and_then(|v| v.as_str()) {
            tags.push(format!("email:{}", email));
        }

        if let Some(id) = chip_data.get("id").and_then(|v| v.as_str()) {
            tags.push(format!("id:{}", id));
        }

        if let Some(status) = chip_data.get("status").and_then(|v| v.as_str()) {
            tags.push(format!("status:{}", status));
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

/// Re-export for convenience
pub use backends::*;
pub use indexing::*;
pub use query::*;