//! Indexing system for efficient chip queries

use crate::{ChipStoreBackend, ChipStoreError, StoredChip};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Index for efficient chip lookups
pub struct ChipIndexer {
    backend: Arc<dyn ChipStoreBackend>,
    // In-memory indexes for fast lookups
    type_index: Arc<RwLock<HashMap<String, HashSet<String>>>>, // chip_type -> CIDs
    tag_index: Arc<RwLock<HashMap<String, HashSet<String>>>>,  // tag -> CIDs
    executor_index: Arc<RwLock<HashMap<String, HashSet<String>>>>, // executor_did -> CIDs
}

impl ChipIndexer {
    pub fn new(backend: Arc<dyn ChipStoreBackend>) -> Self {
        Self {
            backend,
            type_index: Arc::new(RwLock::new(HashMap::new())),
            tag_index: Arc::new(RwLock::new(HashMap::new())),
            executor_index: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Index a newly stored chip
    pub async fn index_chip(&self, chip: &StoredChip) -> Result<(), ChipStoreError> {
        // Index by type
        {
            let mut type_index = self.type_index.write().await;
            type_index
                .entry(chip.chip_type.clone())
                .or_insert_with(HashSet::new)
                .insert(chip.cid.clone());
        }

        // Index by tags
        {
            let mut tag_index = self.tag_index.write().await;
            for tag in &chip.tags {
                tag_index
                    .entry(tag.clone())
                    .or_insert_with(HashSet::new)
                    .insert(chip.cid.clone());
            }
        }

        // Index by executor
        {
            let mut executor_index = self.executor_index.write().await;
            executor_index
                .entry(chip.execution_metadata.executor_did.clone())
                .or_insert_with(HashSet::new)
                .insert(chip.cid.clone());
        }

        Ok(())
    }

    /// Get CIDs for chips of a specific type
    pub async fn get_cids_by_type(&self, chip_type: &str) -> Result<Vec<String>, ChipStoreError> {
        let type_index = self.type_index.read().await;
        Ok(type_index
            .get(chip_type)
            .map(|cids| cids.iter().cloned().collect())
            .unwrap_or_default())
    }

    /// Get CIDs for chips with a specific tag
    pub async fn get_cids_by_tag(&self, tag: &str) -> Result<Vec<String>, ChipStoreError> {
        let tag_index = self.tag_index.read().await;
        Ok(tag_index
            .get(tag)
            .map(|cids| cids.iter().cloned().collect())
            .unwrap_or_default())
    }

    /// Get CIDs for chips executed by a specific executor
    pub async fn get_cids_by_executor(&self, executor_did: &str) -> Result<Vec<String>, ChipStoreError> {
        let executor_index = self.executor_index.read().await;
        Ok(executor_index
            .get(executor_did)
            .map(|cids| cids.iter().cloned().collect())
            .unwrap_or_default())
    }

    /// Find intersection of CIDs across multiple criteria
    pub async fn find_intersection(
        &self,
        chip_type: Option<&str>,
        tags: &[String],
        executor_did: Option<&str>,
    ) -> Result<Vec<String>, ChipStoreError> {
        let mut result_cids: Option<HashSet<String>> = None;

        // Filter by chip type
        if let Some(chip_type) = chip_type {
            let type_cids = self.get_cids_by_type(chip_type).await?;
            let type_cids_set: HashSet<String> = type_cids.into_iter().collect();

            result_cids = Some(match result_cids {
                None => type_cids_set,
                Some(existing) => existing.intersection(&type_cids_set).cloned().collect(),
            });
        }

        // Filter by tags
        for tag in tags {
            let tag_cids = self.get_cids_by_tag(tag).await?;
            let tag_cids_set: HashSet<String> = tag_cids.into_iter().collect();

            result_cids = Some(match result_cids {
                None => tag_cids_set,
                Some(existing) => existing.intersection(&tag_cids_set).cloned().collect(),
            });
        }

        // Filter by executor
        if let Some(executor_did) = executor_did {
            let executor_cids = self.get_cids_by_executor(executor_did).await?;
            let executor_cids_set: HashSet<String> = executor_cids.into_iter().collect();

            result_cids = Some(match result_cids {
                None => executor_cids_set,
                Some(existing) => existing.intersection(&executor_cids_set).cloned().collect(),
            });
        }

        Ok(result_cids.unwrap_or_default().into_iter().collect())
    }

    /// Remove chip from indexes (for deletion)
    pub async fn remove_from_indexes(&self, chip: &StoredChip) -> Result<(), ChipStoreError> {
        // Remove from type index
        {
            let mut type_index = self.type_index.write().await;
            if let Some(cids) = type_index.get_mut(&chip.chip_type) {
                cids.remove(&chip.cid);
                if cids.is_empty() {
                    type_index.remove(&chip.chip_type);
                }
            }
        }

        // Remove from tag indexes
        {
            let mut tag_index = self.tag_index.write().await;
            for tag in &chip.tags {
                if let Some(cids) = tag_index.get_mut(tag) {
                    cids.remove(&chip.cid);
                    if cids.is_empty() {
                        tag_index.remove(tag);
                    }
                }
            }
        }

        // Remove from executor index
        {
            let mut executor_index = self.executor_index.write().await;
            if let Some(cids) = executor_index.get_mut(&chip.execution_metadata.executor_did) {
                cids.remove(&chip.cid);
                if cids.is_empty() {
                    executor_index.remove(&chip.execution_metadata.executor_did);
                }
            }
        }

        Ok(())
    }

    /// Rebuild all indexes from storage
    pub async fn rebuild_indexes(&self) -> Result<(), ChipStoreError> {
        // Clear existing indexes
        {
            let mut type_index = self.type_index.write().await;
            type_index.clear();
        }
        {
            let mut tag_index = self.tag_index.write().await;
            tag_index.clear();
        }
        {
            let mut executor_index = self.executor_index.write().await;
            executor_index.clear();
        }

        // TODO: Implement full scan and rebuild
        // This would require a way to iterate over all chips in the backend
        // For now, indexes are built incrementally as chips are added

        Ok(())
    }
}