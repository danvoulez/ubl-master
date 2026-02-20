//! Indexing system for efficient chip queries

use crate::{ChipStoreBackend, ChipStoreError, StoredChip};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use ubl_types::Cid as TypedCid;

/// Index for efficient chip lookups
pub struct ChipIndexer {
    backend: Arc<dyn ChipStoreBackend>,
    // In-memory indexes for fast lookups
    type_index: Arc<RwLock<HashMap<String, HashSet<TypedCid>>>>, // chip_type -> CIDs
    tag_index: Arc<RwLock<HashMap<String, HashSet<TypedCid>>>>,  // tag -> CIDs
    executor_index: Arc<RwLock<HashMap<String, HashSet<TypedCid>>>>, // executor_did -> CIDs
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

    pub async fn new_with_rebuild(
        backend: Arc<dyn ChipStoreBackend>,
    ) -> Result<Self, ChipStoreError> {
        let indexer = Self::new(backend);
        indexer.rebuild_indexes().await?;
        Ok(indexer)
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
                .entry(chip.execution_metadata.executor_did.as_str().to_string())
                .or_insert_with(HashSet::new)
                .insert(chip.cid.clone());
        }

        Ok(())
    }

    /// Get CIDs for chips of a specific type
    pub async fn get_cids_by_type(&self, chip_type: &str) -> Result<Vec<TypedCid>, ChipStoreError> {
        let type_index = self.type_index.read().await;
        Ok(type_index
            .get(chip_type)
            .map(|cids| cids.iter().cloned().collect())
            .unwrap_or_default())
    }

    /// Get CIDs for chips with a specific tag
    pub async fn get_cids_by_tag(&self, tag: &str) -> Result<Vec<TypedCid>, ChipStoreError> {
        let tag_index = self.tag_index.read().await;
        Ok(tag_index
            .get(tag)
            .map(|cids| cids.iter().cloned().collect())
            .unwrap_or_default())
    }

    /// Get CIDs for chips executed by a specific executor
    pub async fn get_cids_by_executor(
        &self,
        executor_did: &str,
    ) -> Result<Vec<TypedCid>, ChipStoreError> {
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
    ) -> Result<Vec<TypedCid>, ChipStoreError> {
        let mut result_cids: Option<HashSet<TypedCid>> = None;

        // Filter by chip type
        if let Some(chip_type) = chip_type {
            let type_cids = self.get_cids_by_type(chip_type).await?;
            let type_cids_set: HashSet<TypedCid> = type_cids.into_iter().collect();

            result_cids = Some(match result_cids {
                None => type_cids_set,
                Some(existing) => existing.intersection(&type_cids_set).cloned().collect(),
            });
        }

        // Filter by tags
        for tag in tags {
            let tag_cids = self.get_cids_by_tag(tag).await?;
            let tag_cids_set: HashSet<TypedCid> = tag_cids.into_iter().collect();

            result_cids = Some(match result_cids {
                None => tag_cids_set,
                Some(existing) => existing.intersection(&tag_cids_set).cloned().collect(),
            });
        }

        // Filter by executor
        if let Some(executor_did) = executor_did {
            let executor_cids = self.get_cids_by_executor(executor_did).await?;
            let executor_cids_set: HashSet<TypedCid> = executor_cids.into_iter().collect();

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
            let did_key = chip.execution_metadata.executor_did.as_str().to_string();
            if let Some(cids) = executor_index.get_mut(&did_key) {
                cids.remove(&chip.cid);
                if cids.is_empty() {
                    executor_index.remove(&did_key);
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

        let chips = self.backend.scan_all().await?;
        for chip in &chips {
            self.index_chip(chip).await?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ExecutionMetadata, InMemoryBackend};
    use serde_json::json;
    use ubl_types::Did as TypedDid;

    fn make_chip(cid: &str, receipt_cid: &str, chip_type: &str, tag: &str) -> StoredChip {
        StoredChip {
            cid: TypedCid::new_unchecked(cid),
            chip_type: chip_type.to_string(),
            chip_data: json!({
                "@type": chip_type,
                "@id": "test-chip",
                "@ver": "1.0",
                "@world": "a/test/t/dev"
            }),
            receipt_cid: TypedCid::new_unchecked(receipt_cid),
            created_at: chrono::Utc::now().to_rfc3339(),
            execution_metadata: ExecutionMetadata {
                runtime_version: "test-runtime".to_string(),
                execution_time_ms: 1,
                fuel_consumed: 1,
                policies_applied: vec!["p0".to_string()],
                executor_did: TypedDid::new_unchecked("did:key:zIndexer"),
                reproducible: true,
            },
            tags: vec![tag.to_string()],
            related_chips: vec![],
        }
    }

    #[tokio::test]
    async fn rebuild_indexes_scans_backend_data() {
        let backend = Arc::new(InMemoryBackend::new());
        backend
            .put_chip(&make_chip(
                "b3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "b3:1111111111111111111111111111111111111111111111111111111111111111",
                "ubl/advisory",
                "passport_cid:b3:passport-a",
            ))
            .await
            .expect("store chip a");
        backend
            .put_chip(&make_chip(
                "b3:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "b3:2222222222222222222222222222222222222222222222222222222222222222",
                "ubl/advisory",
                "passport_cid:b3:passport-b",
            ))
            .await
            .expect("store chip b");

        let indexer = ChipIndexer::new(backend);
        assert!(indexer
            .get_cids_by_type("ubl/advisory")
            .await
            .expect("empty before rebuild")
            .is_empty());

        indexer.rebuild_indexes().await.expect("rebuild");
        let cids = indexer
            .get_cids_by_type("ubl/advisory")
            .await
            .expect("lookup by type");
        assert_eq!(cids.len(), 2);
    }

    #[tokio::test]
    async fn new_with_rebuild_populates_indexes() {
        let backend = Arc::new(InMemoryBackend::new());
        backend
            .put_chip(&make_chip(
                "b3:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "b3:3333333333333333333333333333333333333333333333333333333333333333",
                "ubl/report",
                "status:ok",
            ))
            .await
            .expect("store chip");

        let indexer = ChipIndexer::new_with_rebuild(backend)
            .await
            .expect("new+rebuild");
        let cids = indexer
            .get_cids_by_tag("status:ok")
            .await
            .expect("lookup by tag");
        assert_eq!(cids.len(), 1);
    }
}
