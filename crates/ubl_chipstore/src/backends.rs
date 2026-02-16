//! Storage backends for ChipStore

use crate::{ChipStoreBackend, ChipStoreError, StoredChip, ChipQuery, QueryResult};
use async_trait::async_trait;
use serde_json;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// In-memory backend for development and testing
pub struct InMemoryBackend {
    chips: Arc<RwLock<HashMap<String, StoredChip>>>,
}

impl InMemoryBackend {
    pub fn new() -> Self {
        Self {
            chips: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for InMemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ChipStoreBackend for InMemoryBackend {
    async fn put_chip(&self, chip: &StoredChip) -> Result<(), ChipStoreError> {
        let mut chips = self.chips.write().await;
        chips.insert(chip.cid.clone(), chip.clone());
        Ok(())
    }

    async fn get_chip(&self, cid: &str) -> Result<Option<StoredChip>, ChipStoreError> {
        let chips = self.chips.read().await;
        Ok(chips.get(cid).cloned())
    }

    async fn exists(&self, cid: &str) -> Result<bool, ChipStoreError> {
        let chips = self.chips.read().await;
        Ok(chips.contains_key(cid))
    }

    async fn query_chips(&self, query: &ChipQuery) -> Result<QueryResult, ChipStoreError> {
        let chips = self.chips.read().await;
        let mut results: Vec<StoredChip> = chips
            .values()
            .filter(|chip| self.matches_query(chip, query))
            .cloned()
            .collect();

        // Sort by creation time (newest first)
        results.sort_by(|a, b| b.created_at.cmp(&a.created_at));

        let total_count = results.len();
        let offset = query.offset.unwrap_or(0);
        let limit = query.limit.unwrap_or(100);

        // Apply pagination
        let paginated_results: Vec<StoredChip> = results
            .into_iter()
            .skip(offset)
            .take(limit)
            .collect();

        let has_more = offset + paginated_results.len() < total_count;

        Ok(QueryResult {
            chips: paginated_results,
            total_count,
            has_more,
        })
    }

    async fn get_chips_by_type(&self, chip_type: &str) -> Result<Vec<StoredChip>, ChipStoreError> {
        let chips = self.chips.read().await;
        let results: Vec<StoredChip> = chips
            .values()
            .filter(|chip| chip.chip_type == chip_type)
            .cloned()
            .collect();
        Ok(results)
    }

    async fn get_related_chips(&self, cid: &str) -> Result<Vec<StoredChip>, ChipStoreError> {
        let chips = self.chips.read().await;

        if let Some(chip) = chips.get(cid) {
            let mut related = Vec::new();
            for related_cid in &chip.related_chips {
                if let Some(related_chip) = chips.get(related_cid) {
                    related.push(related_chip.clone());
                }
            }
            Ok(related)
        } else {
            Ok(Vec::new())
        }
    }

    async fn delete_chip(&self, cid: &str) -> Result<(), ChipStoreError> {
        let mut chips = self.chips.write().await;
        chips.remove(cid);
        Ok(())
    }
}

impl InMemoryBackend {
    fn matches_query(&self, chip: &StoredChip, query: &ChipQuery) -> bool {
        // Check chip type
        if let Some(ref chip_type) = query.chip_type {
            if chip.chip_type != *chip_type {
                return false;
            }
        }

        // Check tags
        if !query.tags.is_empty() {
            let has_all_tags = query.tags.iter().all(|tag| chip.tags.contains(tag));
            if !has_all_tags {
                return false;
            }
        }

        // Check date range
        if let Some(ref after) = query.created_after {
            if chip.created_at <= *after {
                return false;
            }
        }

        if let Some(ref before) = query.created_before {
            if chip.created_at >= *before {
                return false;
            }
        }

        // Check executor
        if let Some(ref executor_did) = query.executor_did {
            if chip.execution_metadata.executor_did != *executor_did {
                return false;
            }
        }

        true
    }
}

/// Sled (embedded database) backend
pub struct SledBackend {
    db: sled::Db,
}

impl SledBackend {
    pub fn new(path: &str) -> Result<Self, ChipStoreError> {
        let db = sled::open(path)
            .map_err(|e| ChipStoreError::Backend(format!("Failed to open sled DB: {}", e)))?;
        Ok(Self { db })
    }

    pub fn in_memory() -> Result<Self, ChipStoreError> {
        let db = sled::Config::new()
            .temporary(true)
            .open()
            .map_err(|e| ChipStoreError::Backend(format!("Failed to create in-memory sled DB: {}", e)))?;
        Ok(Self { db })
    }
}

#[async_trait]
impl ChipStoreBackend for SledBackend {
    async fn put_chip(&self, chip: &StoredChip) -> Result<(), ChipStoreError> {
        let serialized = serde_json::to_vec(chip)
            .map_err(|e| ChipStoreError::Serialization(e.to_string()))?;

        self.db
            .insert(chip.cid.as_bytes(), serialized)
            .map_err(|e| ChipStoreError::Backend(e.to_string()))?;

        Ok(())
    }

    async fn get_chip(&self, cid: &str) -> Result<Option<StoredChip>, ChipStoreError> {
        if let Some(data) = self.db
            .get(cid.as_bytes())
            .map_err(|e| ChipStoreError::Backend(e.to_string()))?
        {
            let chip: StoredChip = serde_json::from_slice(&data)
                .map_err(|e| ChipStoreError::Serialization(e.to_string()))?;
            Ok(Some(chip))
        } else {
            Ok(None)
        }
    }

    async fn exists(&self, cid: &str) -> Result<bool, ChipStoreError> {
        Ok(self.db
            .contains_key(cid.as_bytes())
            .map_err(|e| ChipStoreError::Backend(e.to_string()))?)
    }

    async fn query_chips(&self, query: &ChipQuery) -> Result<QueryResult, ChipStoreError> {
        let mut results = Vec::new();

        // Scan all entries (not optimal, but works for now)
        // TODO: Implement proper indexing for production
        for result in self.db.iter() {
            let (_key, value) = result.map_err(|e| ChipStoreError::Backend(e.to_string()))?;
            let chip: StoredChip = serde_json::from_slice(&value)
                .map_err(|e| ChipStoreError::Serialization(e.to_string()))?;

            if self.matches_query(&chip, query) {
                results.push(chip);
            }
        }

        // Sort by creation time (newest first)
        results.sort_by(|a, b| b.created_at.cmp(&a.created_at));

        let total_count = results.len();
        let offset = query.offset.unwrap_or(0);
        let limit = query.limit.unwrap_or(100);

        // Apply pagination
        let paginated_results: Vec<StoredChip> = results
            .into_iter()
            .skip(offset)
            .take(limit)
            .collect();

        let has_more = offset + paginated_results.len() < total_count;

        Ok(QueryResult {
            chips: paginated_results,
            total_count,
            has_more,
        })
    }

    async fn get_chips_by_type(&self, chip_type: &str) -> Result<Vec<StoredChip>, ChipStoreError> {
        let query = ChipQuery {
            chip_type: Some(chip_type.to_string()),
            tags: vec![],
            created_after: None,
            created_before: None,
            executor_did: None,
            limit: None,
            offset: None,
        };
        let result = self.query_chips(&query).await?;
        Ok(result.chips)
    }

    async fn get_related_chips(&self, cid: &str) -> Result<Vec<StoredChip>, ChipStoreError> {
        if let Some(chip) = self.get_chip(cid).await? {
            let mut related = Vec::new();
            for related_cid in &chip.related_chips {
                if let Some(related_chip) = self.get_chip(related_cid).await? {
                    related.push(related_chip);
                }
            }
            Ok(related)
        } else {
            Ok(Vec::new())
        }
    }

    async fn delete_chip(&self, cid: &str) -> Result<(), ChipStoreError> {
        self.db
            .remove(cid.as_bytes())
            .map_err(|e| ChipStoreError::Backend(e.to_string()))?;
        Ok(())
    }
}

impl SledBackend {
    fn matches_query(&self, chip: &StoredChip, query: &ChipQuery) -> bool {
        // Same logic as InMemoryBackend
        // Check chip type
        if let Some(ref chip_type) = query.chip_type {
            if chip.chip_type != *chip_type {
                return false;
            }
        }

        // Check tags
        if !query.tags.is_empty() {
            let has_all_tags = query.tags.iter().all(|tag| chip.tags.contains(tag));
            if !has_all_tags {
                return false;
            }
        }

        // Check date range
        if let Some(ref after) = query.created_after {
            if chip.created_at <= *after {
                return false;
            }
        }

        if let Some(ref before) = query.created_before {
            if chip.created_at >= *before {
                return false;
            }
        }

        // Check executor
        if let Some(ref executor_did) = query.executor_did {
            if chip.execution_metadata.executor_did != *executor_did {
                return false;
            }
        }

        true
    }
}