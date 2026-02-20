//! Storage backends for ChipStore

use crate::{ChipQuery, ChipStoreBackend, ChipStoreError, QueryResult, StoredChip};
use async_trait::async_trait;
use serde_json;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use ubl_types::Cid as TypedCid;

/// In-memory backend for development and testing
pub struct InMemoryBackend {
    chips: Arc<RwLock<HashMap<TypedCid, StoredChip>>>,
    receipt_index: Arc<RwLock<HashMap<TypedCid, TypedCid>>>, // receipt_cid -> chip_cid
    type_index: Arc<RwLock<HashMap<String, HashSet<TypedCid>>>>, // chip_type -> chip_cids
    tag_index: Arc<RwLock<HashMap<String, HashSet<TypedCid>>>>, // tag -> chip_cids
    executor_index: Arc<RwLock<HashMap<String, HashSet<TypedCid>>>>, // executor_did -> chip_cids
}

impl InMemoryBackend {
    pub fn new() -> Self {
        Self {
            chips: Arc::new(RwLock::new(HashMap::new())),
            receipt_index: Arc::new(RwLock::new(HashMap::new())),
            type_index: Arc::new(RwLock::new(HashMap::new())),
            tag_index: Arc::new(RwLock::new(HashMap::new())),
            executor_index: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn index_chip(&self, chip: &StoredChip) {
        {
            let mut type_index = self.type_index.write().await;
            type_index
                .entry(chip.chip_type.clone())
                .or_insert_with(HashSet::new)
                .insert(chip.cid.clone());
        }
        {
            let mut tag_index = self.tag_index.write().await;
            for tag in &chip.tags {
                tag_index
                    .entry(tag.clone())
                    .or_insert_with(HashSet::new)
                    .insert(chip.cid.clone());
            }
        }
        {
            let mut executor_index = self.executor_index.write().await;
            executor_index
                .entry(chip.execution_metadata.executor_did.as_str().to_string())
                .or_insert_with(HashSet::new)
                .insert(chip.cid.clone());
        }
    }

    async fn remove_chip_from_indexes(&self, chip: &StoredChip) {
        {
            let mut type_index = self.type_index.write().await;
            if let Some(cids) = type_index.get_mut(&chip.chip_type) {
                cids.remove(&chip.cid);
                if cids.is_empty() {
                    type_index.remove(&chip.chip_type);
                }
            }
        }
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
        {
            let mut executor_index = self.executor_index.write().await;
            let key = chip.execution_metadata.executor_did.as_str().to_string();
            if let Some(cids) = executor_index.get_mut(&key) {
                cids.remove(&chip.cid);
                if cids.is_empty() {
                    executor_index.remove(&key);
                }
            }
        }
    }

    async fn candidate_cids_from_indexes(
        &self,
        query: &ChipQuery,
    ) -> Result<Option<HashSet<TypedCid>>, ChipStoreError> {
        if query.chip_type.is_none() && query.tags.is_empty() && query.executor_did.is_none() {
            return Ok(None);
        }

        let mut candidates: Option<HashSet<TypedCid>> = None;

        if let Some(ref chip_type) = query.chip_type {
            let set = {
                let type_index = self.type_index.read().await;
                type_index.get(chip_type).cloned().unwrap_or_default()
            };
            candidates = Some(intersect_sets(candidates, set));
        }

        for tag in &query.tags {
            let set = {
                let tag_index = self.tag_index.read().await;
                tag_index.get(tag).cloned().unwrap_or_default()
            };
            candidates = Some(intersect_sets(candidates, set));
        }

        if let Some(ref executor_did) = query.executor_did {
            let set = {
                let executor_index = self.executor_index.read().await;
                executor_index
                    .get(executor_did)
                    .cloned()
                    .unwrap_or_default()
            };
            candidates = Some(intersect_sets(candidates, set));
        }

        Ok(Some(candidates.unwrap_or_default()))
    }
}

impl Default for InMemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

/// Filesystem backend (JSON per chip CID).
///
/// Storage layout:
/// - `{root}/chips/{cid_sanitized}.json`
pub struct FsBackend {
    root: PathBuf,
}

impl FsBackend {
    pub fn new<P: AsRef<Path>>(root: P) -> Result<Self, ChipStoreError> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(root.join("chips"))
            .map_err(|e| ChipStoreError::Backend(format!("FsBackend init: {}", e)))?;
        Ok(Self { root })
    }

    fn chips_dir(&self) -> PathBuf {
        self.root.join("chips")
    }

    fn chip_path(&self, cid: &str) -> PathBuf {
        self.chips_dir().join(format!("{}.json", sanitize_cid(cid)))
    }

    fn load_chip_by_cid(&self, cid: &str) -> Result<Option<StoredChip>, ChipStoreError> {
        let path = self.chip_path(cid);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(&path)
            .map_err(|e| ChipStoreError::Backend(format!("FsBackend read: {}", e)))?;
        let chip: StoredChip = serde_json::from_slice(&bytes)
            .map_err(|e| ChipStoreError::Serialization(e.to_string()))?;
        Ok(Some(chip))
    }

    fn iter_all_chips(&self) -> Result<Vec<StoredChip>, ChipStoreError> {
        let mut chips = Vec::new();
        let entries = std::fs::read_dir(self.chips_dir())
            .map_err(|e| ChipStoreError::Backend(format!("FsBackend read_dir: {}", e)))?;
        for entry in entries {
            let entry = entry
                .map_err(|e| ChipStoreError::Backend(format!("FsBackend dir entry: {}", e)))?;
            let path = entry.path();
            if path.extension().and_then(|x| x.to_str()) != Some("json") {
                continue;
            }
            let bytes = std::fs::read(&path)
                .map_err(|e| ChipStoreError::Backend(format!("FsBackend read: {}", e)))?;
            let chip: StoredChip = serde_json::from_slice(&bytes)
                .map_err(|e| ChipStoreError::Serialization(e.to_string()))?;
            chips.push(chip);
        }
        Ok(chips)
    }
}

#[async_trait]
impl ChipStoreBackend for FsBackend {
    async fn put_chip(&self, chip: &StoredChip) -> Result<(), ChipStoreError> {
        let serialized =
            serde_json::to_vec(chip).map_err(|e| ChipStoreError::Serialization(e.to_string()))?;
        let path = self.chip_path(chip.cid.as_str());
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serialized)
            .map_err(|e| ChipStoreError::Backend(format!("FsBackend write tmp: {}", e)))?;
        std::fs::rename(&tmp, &path)
            .map_err(|e| ChipStoreError::Backend(format!("FsBackend rename: {}", e)))?;
        Ok(())
    }

    async fn get_chip(&self, cid: &str) -> Result<Option<StoredChip>, ChipStoreError> {
        self.load_chip_by_cid(cid)
    }

    async fn get_chip_by_receipt_cid(
        &self,
        receipt_cid: &str,
    ) -> Result<Option<StoredChip>, ChipStoreError> {
        for chip in self.iter_all_chips()? {
            if chip.receipt_cid.as_str() == receipt_cid {
                return Ok(Some(chip));
            }
        }
        Ok(None)
    }

    async fn exists(&self, cid: &str) -> Result<bool, ChipStoreError> {
        Ok(self.chip_path(cid).exists())
    }

    async fn query_chips(&self, query: &ChipQuery) -> Result<QueryResult, ChipStoreError> {
        let mut chips: Vec<StoredChip> = self
            .iter_all_chips()?
            .into_iter()
            .filter(|chip| matches_query(chip, query))
            .collect();
        Ok(apply_pagination(&mut chips, query))
    }

    async fn get_chips_by_type(&self, chip_type: &str) -> Result<Vec<StoredChip>, ChipStoreError> {
        let mut chips: Vec<StoredChip> = self
            .iter_all_chips()?
            .into_iter()
            .filter(|chip| chip.chip_type == chip_type)
            .collect();
        chips.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(chips)
    }

    async fn get_related_chips(&self, cid: &str) -> Result<Vec<StoredChip>, ChipStoreError> {
        if let Some(chip) = self.load_chip_by_cid(cid)? {
            let mut out = Vec::new();
            for related in chip.related_chips {
                if let Some(found) = self.load_chip_by_cid(&related)? {
                    out.push(found);
                }
            }
            Ok(out)
        } else {
            Ok(Vec::new())
        }
    }

    async fn delete_chip(&self, cid: &str) -> Result<(), ChipStoreError> {
        let path = self.chip_path(cid);
        if path.exists() {
            std::fs::remove_file(path)
                .map_err(|e| ChipStoreError::Backend(format!("FsBackend delete: {}", e)))?;
        }
        Ok(())
    }

    async fn rebuild_indexes(&self) -> Result<(), ChipStoreError> {
        // FS backend does full scans; no persisted secondary indexes to rebuild.
        Ok(())
    }

    async fn scan_all(&self) -> Result<Vec<StoredChip>, ChipStoreError> {
        self.iter_all_chips()
    }
}

/// S3-compatible backend (local emulation for now).
///
/// Uses the same semantics as object storage with `bucket/prefix`, backed by `FsBackend`.
pub struct S3Backend {
    bucket: String,
    prefix: String,
    fs: FsBackend,
}

impl S3Backend {
    pub fn new(bucket: &str, prefix: &str) -> Result<Self, ChipStoreError> {
        let local_root = std::env::var("UBL_CHIPSTORE_S3_LOCAL_ROOT")
            .unwrap_or_else(|_| "./data/chipstore-s3".to_string());
        let fs = FsBackend::new(
            PathBuf::from(local_root)
                .join(sanitize_component(bucket))
                .join(sanitize_component(prefix)),
        )?;
        Ok(Self {
            bucket: bucket.to_string(),
            prefix: prefix.to_string(),
            fs,
        })
    }

    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    pub fn prefix(&self) -> &str {
        &self.prefix
    }
}

#[async_trait]
impl ChipStoreBackend for S3Backend {
    async fn put_chip(&self, chip: &StoredChip) -> Result<(), ChipStoreError> {
        self.fs.put_chip(chip).await
    }

    async fn get_chip(&self, cid: &str) -> Result<Option<StoredChip>, ChipStoreError> {
        self.fs.get_chip(cid).await
    }

    async fn get_chip_by_receipt_cid(
        &self,
        receipt_cid: &str,
    ) -> Result<Option<StoredChip>, ChipStoreError> {
        self.fs.get_chip_by_receipt_cid(receipt_cid).await
    }

    async fn exists(&self, cid: &str) -> Result<bool, ChipStoreError> {
        self.fs.exists(cid).await
    }

    async fn query_chips(&self, query: &ChipQuery) -> Result<QueryResult, ChipStoreError> {
        self.fs.query_chips(query).await
    }

    async fn get_chips_by_type(&self, chip_type: &str) -> Result<Vec<StoredChip>, ChipStoreError> {
        self.fs.get_chips_by_type(chip_type).await
    }

    async fn get_related_chips(&self, cid: &str) -> Result<Vec<StoredChip>, ChipStoreError> {
        self.fs.get_related_chips(cid).await
    }

    async fn delete_chip(&self, cid: &str) -> Result<(), ChipStoreError> {
        self.fs.delete_chip(cid).await
    }

    async fn rebuild_indexes(&self) -> Result<(), ChipStoreError> {
        self.fs.rebuild_indexes().await
    }

    async fn scan_all(&self) -> Result<Vec<StoredChip>, ChipStoreError> {
        self.fs.scan_all().await
    }
}

#[async_trait]
impl ChipStoreBackend for InMemoryBackend {
    async fn put_chip(&self, chip: &StoredChip) -> Result<(), ChipStoreError> {
        {
            let mut chips = self.chips.write().await;
            chips.insert(chip.cid.clone(), chip.clone());
        }
        {
            let mut receipt_index = self.receipt_index.write().await;
            receipt_index.insert(chip.receipt_cid.clone(), chip.cid.clone());
        }
        self.index_chip(chip).await;
        Ok(())
    }

    async fn get_chip(&self, cid: &str) -> Result<Option<StoredChip>, ChipStoreError> {
        let chips = self.chips.read().await;
        let key = TypedCid::new_unchecked(cid);
        Ok(chips.get(&key).cloned())
    }

    async fn get_chip_by_receipt_cid(
        &self,
        receipt_cid: &str,
    ) -> Result<Option<StoredChip>, ChipStoreError> {
        let chip_cid = {
            let receipt_index = self.receipt_index.read().await;
            let receipt_key = TypedCid::new_unchecked(receipt_cid);
            receipt_index.get(&receipt_key).cloned()
        };

        match chip_cid {
            Some(cid) => {
                let chips = self.chips.read().await;
                Ok(chips.get(&cid).cloned())
            }
            None => Ok(None),
        }
    }

    async fn exists(&self, cid: &str) -> Result<bool, ChipStoreError> {
        let chips = self.chips.read().await;
        let key = TypedCid::new_unchecked(cid);
        Ok(chips.contains_key(&key))
    }

    async fn query_chips(&self, query: &ChipQuery) -> Result<QueryResult, ChipStoreError> {
        let candidate_cids = self.candidate_cids_from_indexes(query).await?;
        let chips = self.chips.read().await;
        let mut results: Vec<StoredChip> = match candidate_cids {
            Some(cids) => cids
                .iter()
                .filter_map(|cid| chips.get(cid))
                .filter(|chip| matches_query(chip, query))
                .cloned()
                .collect(),
            None => chips
                .values()
                .filter(|chip| matches_query(chip, query))
                .cloned()
                .collect(),
        };

        Ok(apply_pagination(&mut results, query))
    }

    async fn get_chips_by_type(&self, chip_type: &str) -> Result<Vec<StoredChip>, ChipStoreError> {
        let cids = {
            let type_index = self.type_index.read().await;
            type_index.get(chip_type).cloned().unwrap_or_default()
        };
        let chips = self.chips.read().await;
        let mut results: Vec<StoredChip> = cids
            .iter()
            .filter_map(|cid| chips.get(cid))
            .cloned()
            .collect();
        results.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(results)
    }

    async fn get_related_chips(&self, cid: &str) -> Result<Vec<StoredChip>, ChipStoreError> {
        let chips = self.chips.read().await;
        let key = TypedCid::new_unchecked(cid);

        if let Some(chip) = chips.get(&key) {
            let mut related = Vec::new();
            for related_cid in &chip.related_chips {
                let rkey = TypedCid::new_unchecked(related_cid);
                if let Some(related_chip) = chips.get(&rkey) {
                    related.push(related_chip.clone());
                }
            }
            Ok(related)
        } else {
            Ok(Vec::new())
        }
    }

    async fn delete_chip(&self, cid: &str) -> Result<(), ChipStoreError> {
        let removed_chip = {
            let mut chips = self.chips.write().await;
            let key = TypedCid::new_unchecked(cid);
            chips.remove(&key)
        };
        if let Some(chip) = removed_chip {
            let mut receipt_index = self.receipt_index.write().await;
            receipt_index.remove(&chip.receipt_cid);
            drop(receipt_index);
            self.remove_chip_from_indexes(&chip).await;
        }
        Ok(())
    }

    async fn rebuild_indexes(&self) -> Result<(), ChipStoreError> {
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

        let chips_snapshot: Vec<StoredChip> = {
            let chips = self.chips.read().await;
            chips.values().cloned().collect()
        };
        for chip in &chips_snapshot {
            self.index_chip(chip).await;
        }
        Ok(())
    }

    async fn scan_all(&self) -> Result<Vec<StoredChip>, ChipStoreError> {
        let chips = self.chips.read().await;
        Ok(chips.values().cloned().collect())
    }
}

/// Sled (embedded database) backend
pub struct SledBackend {
    db: sled::Db,
    receipt_index: sled::Tree,
    type_index: sled::Tree,
    tag_index: sled::Tree,
    executor_index: sled::Tree,
}

impl SledBackend {
    pub fn new(path: &str) -> Result<Self, ChipStoreError> {
        let db = sled::open(path)
            .map_err(|e| ChipStoreError::Backend(format!("Failed to open sled DB: {}", e)))?;
        let receipt_index = db
            .open_tree("receipt_index")
            .map_err(|e| ChipStoreError::Backend(format!("Failed to open receipt index: {}", e)))?;
        let type_index = db
            .open_tree("type_index")
            .map_err(|e| ChipStoreError::Backend(format!("Failed to open type index: {}", e)))?;
        let tag_index = db
            .open_tree("tag_index")
            .map_err(|e| ChipStoreError::Backend(format!("Failed to open tag index: {}", e)))?;
        let executor_index = db.open_tree("executor_index").map_err(|e| {
            ChipStoreError::Backend(format!("Failed to open executor index: {}", e))
        })?;
        let backend = Self {
            db,
            receipt_index,
            type_index,
            tag_index,
            executor_index,
        };
        backend.rebuild_indexes()?;
        Ok(backend)
    }

    pub fn in_memory() -> Result<Self, ChipStoreError> {
        let db = sled::Config::new().temporary(true).open().map_err(|e| {
            ChipStoreError::Backend(format!("Failed to create in-memory sled DB: {}", e))
        })?;
        let receipt_index = db
            .open_tree("receipt_index")
            .map_err(|e| ChipStoreError::Backend(format!("Failed to open receipt index: {}", e)))?;
        let type_index = db
            .open_tree("type_index")
            .map_err(|e| ChipStoreError::Backend(format!("Failed to open type index: {}", e)))?;
        let tag_index = db
            .open_tree("tag_index")
            .map_err(|e| ChipStoreError::Backend(format!("Failed to open tag index: {}", e)))?;
        let executor_index = db.open_tree("executor_index").map_err(|e| {
            ChipStoreError::Backend(format!("Failed to open executor index: {}", e))
        })?;
        let backend = Self {
            db,
            receipt_index,
            type_index,
            tag_index,
            executor_index,
        };
        backend.rebuild_indexes()?;
        Ok(backend)
    }

    fn rebuild_indexes(&self) -> Result<(), ChipStoreError> {
        self.receipt_index
            .clear()
            .map_err(|e| ChipStoreError::Backend(e.to_string()))?;
        self.type_index
            .clear()
            .map_err(|e| ChipStoreError::Backend(e.to_string()))?;
        self.tag_index
            .clear()
            .map_err(|e| ChipStoreError::Backend(e.to_string()))?;
        self.executor_index
            .clear()
            .map_err(|e| ChipStoreError::Backend(e.to_string()))?;

        for entry in self.db.iter() {
            let (_cid, value) = entry.map_err(|e| ChipStoreError::Backend(e.to_string()))?;
            let chip: StoredChip = serde_json::from_slice(&value)
                .map_err(|e| ChipStoreError::Serialization(e.to_string()))?;
            self.receipt_index
                .insert(
                    chip.receipt_cid.as_str().as_bytes(),
                    chip.cid.as_str().as_bytes(),
                )
                .map_err(|e| ChipStoreError::Backend(e.to_string()))?;
            self.add_chip_to_indexes(&chip)?;
        }

        Ok(())
    }

    fn add_chip_to_indexes(&self, chip: &StoredChip) -> Result<(), ChipStoreError> {
        self.add_index_entry(&self.type_index, &chip.chip_type, chip.cid.as_str())?;
        for tag in &chip.tags {
            self.add_index_entry(&self.tag_index, tag, chip.cid.as_str())?;
        }
        self.add_index_entry(
            &self.executor_index,
            chip.execution_metadata.executor_did.as_str(),
            chip.cid.as_str(),
        )?;
        Ok(())
    }

    fn remove_chip_from_indexes(&self, chip: &StoredChip) -> Result<(), ChipStoreError> {
        self.remove_index_entry(&self.type_index, &chip.chip_type, chip.cid.as_str())?;
        for tag in &chip.tags {
            self.remove_index_entry(&self.tag_index, tag, chip.cid.as_str())?;
        }
        self.remove_index_entry(
            &self.executor_index,
            chip.execution_metadata.executor_did.as_str(),
            chip.cid.as_str(),
        )?;
        Ok(())
    }

    fn add_index_entry(
        &self,
        tree: &sled::Tree,
        key: &str,
        cid: &str,
    ) -> Result<(), ChipStoreError> {
        tree.insert(index_composite_key(key, cid), &[])
            .map_err(|e| ChipStoreError::Backend(e.to_string()))?;
        Ok(())
    }

    fn remove_index_entry(
        &self,
        tree: &sled::Tree,
        key: &str,
        cid: &str,
    ) -> Result<(), ChipStoreError> {
        tree.remove(index_composite_key(key, cid))
            .map_err(|e| ChipStoreError::Backend(e.to_string()))?;
        Ok(())
    }

    fn read_index_set(
        &self,
        tree: &sled::Tree,
        key: &str,
    ) -> Result<HashSet<String>, ChipStoreError> {
        let prefix = index_prefix(key);
        let mut values = HashSet::new();
        for item in tree.scan_prefix(&prefix) {
            let (raw_key, _) = item.map_err(|e| ChipStoreError::Backend(e.to_string()))?;
            if raw_key.len() < prefix.len() {
                continue;
            }
            let suffix = &raw_key[prefix.len()..];
            let cid = std::str::from_utf8(suffix).map_err(|e| {
                ChipStoreError::Backend(format!("Invalid index CID UTF-8 for key '{}': {}", key, e))
            })?;
            values.insert(cid.to_string());
        }
        Ok(values)
    }

    fn load_chip_by_cid(&self, cid: &str) -> Result<Option<StoredChip>, ChipStoreError> {
        let Some(data) = self
            .db
            .get(cid.as_bytes())
            .map_err(|e| ChipStoreError::Backend(e.to_string()))?
        else {
            return Ok(None);
        };
        let chip: StoredChip = serde_json::from_slice(&data)
            .map_err(|e| ChipStoreError::Serialization(e.to_string()))?;
        Ok(Some(chip))
    }

    fn scan_all_chips(&self) -> Result<Vec<StoredChip>, ChipStoreError> {
        let mut chips = Vec::new();
        for item in self.db.iter() {
            let (_cid, value) = item.map_err(|e| ChipStoreError::Backend(e.to_string()))?;
            let chip: StoredChip = serde_json::from_slice(&value)
                .map_err(|e| ChipStoreError::Serialization(e.to_string()))?;
            chips.push(chip);
        }
        Ok(chips)
    }

    fn candidate_cids_from_indexes(
        &self,
        query: &ChipQuery,
    ) -> Result<Option<HashSet<String>>, ChipStoreError> {
        if query.chip_type.is_none() && query.tags.is_empty() && query.executor_did.is_none() {
            return Ok(None);
        }

        let mut candidates: Option<HashSet<String>> = None;

        if let Some(ref chip_type) = query.chip_type {
            let set = self.read_index_set(&self.type_index, chip_type)?;
            candidates = Some(intersect_sets(candidates, set));
        }

        for tag in &query.tags {
            let set = self.read_index_set(&self.tag_index, tag)?;
            candidates = Some(intersect_sets(candidates, set));
        }

        if let Some(ref executor_did) = query.executor_did {
            let set = self.read_index_set(&self.executor_index, executor_did)?;
            candidates = Some(intersect_sets(candidates, set));
        }

        Ok(Some(candidates.unwrap_or_default()))
    }
}

#[async_trait]
impl ChipStoreBackend for SledBackend {
    async fn put_chip(&self, chip: &StoredChip) -> Result<(), ChipStoreError> {
        let serialized =
            serde_json::to_vec(chip).map_err(|e| ChipStoreError::Serialization(e.to_string()))?;

        self.db
            .insert(chip.cid.as_str().as_bytes(), serialized)
            .map_err(|e| ChipStoreError::Backend(e.to_string()))?;

        self.receipt_index
            .insert(
                chip.receipt_cid.as_str().as_bytes(),
                chip.cid.as_str().as_bytes(),
            )
            .map_err(|e| ChipStoreError::Backend(e.to_string()))?;
        self.add_chip_to_indexes(chip)?;

        Ok(())
    }

    async fn get_chip(&self, cid: &str) -> Result<Option<StoredChip>, ChipStoreError> {
        self.load_chip_by_cid(cid)
    }

    async fn get_chip_by_receipt_cid(
        &self,
        receipt_cid: &str,
    ) -> Result<Option<StoredChip>, ChipStoreError> {
        let maybe_chip_cid = self
            .receipt_index
            .get(receipt_cid.as_bytes())
            .map_err(|e| ChipStoreError::Backend(e.to_string()))?;

        let Some(chip_cid) = maybe_chip_cid else {
            return Ok(None);
        };

        let chip_cid_str = std::str::from_utf8(chip_cid.as_ref())
            .map_err(|e| ChipStoreError::Backend(format!("Invalid receipt index UTF-8: {}", e)))?;
        self.get_chip(chip_cid_str).await
    }

    async fn exists(&self, cid: &str) -> Result<bool, ChipStoreError> {
        Ok(self
            .db
            .contains_key(cid.as_bytes())
            .map_err(|e| ChipStoreError::Backend(e.to_string()))?)
    }

    async fn query_chips(&self, query: &ChipQuery) -> Result<QueryResult, ChipStoreError> {
        let mut results = Vec::new();
        if let Some(candidate_cids) = self.candidate_cids_from_indexes(query)? {
            for cid in candidate_cids {
                if let Some(chip) = self.load_chip_by_cid(&cid)? {
                    if matches_query(&chip, query) {
                        results.push(chip);
                    }
                }
            }
        } else {
            for result in self.db.iter() {
                let (_key, value) = result.map_err(|e| ChipStoreError::Backend(e.to_string()))?;
                let chip: StoredChip = serde_json::from_slice(&value)
                    .map_err(|e| ChipStoreError::Serialization(e.to_string()))?;
                if matches_query(&chip, query) {
                    results.push(chip);
                }
            }
        }
        Ok(apply_pagination(&mut results, query))
    }

    async fn get_chips_by_type(&self, chip_type: &str) -> Result<Vec<StoredChip>, ChipStoreError> {
        let mut results = Vec::new();
        for cid in self.read_index_set(&self.type_index, chip_type)? {
            if let Some(chip) = self.load_chip_by_cid(&cid)? {
                if chip.chip_type == chip_type {
                    results.push(chip);
                }
            }
        }
        results.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(results)
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
        if let Some(chip) = self.get_chip(cid).await? {
            self.receipt_index
                .remove(chip.receipt_cid.as_str().as_bytes())
                .map_err(|e| ChipStoreError::Backend(e.to_string()))?;
            self.remove_chip_from_indexes(&chip)?;
        }

        self.db
            .remove(cid.as_bytes())
            .map_err(|e| ChipStoreError::Backend(e.to_string()))?;
        Ok(())
    }

    async fn rebuild_indexes(&self) -> Result<(), ChipStoreError> {
        SledBackend::rebuild_indexes(self)
    }

    async fn scan_all(&self) -> Result<Vec<StoredChip>, ChipStoreError> {
        self.scan_all_chips()
    }
}

fn apply_pagination(results: &mut Vec<StoredChip>, query: &ChipQuery) -> QueryResult {
    results.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    let total_count = results.len();
    let offset = query.offset.unwrap_or(0);
    let limit = query.limit.unwrap_or(100);
    let paginated_results: Vec<StoredChip> = results.drain(..).skip(offset).take(limit).collect();
    let has_more = offset + paginated_results.len() < total_count;
    QueryResult {
        chips: paginated_results,
        total_count,
        has_more,
    }
}

fn matches_query(chip: &StoredChip, query: &ChipQuery) -> bool {
    if let Some(ref chip_type) = query.chip_type {
        if chip.chip_type != *chip_type {
            return false;
        }
    }

    if !query.tags.is_empty() {
        let has_all_tags = query.tags.iter().all(|tag| chip.tags.contains(tag));
        if !has_all_tags {
            return false;
        }
    }

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

    if let Some(ref executor_did) = query.executor_did {
        if chip.execution_metadata.executor_did.as_str() != executor_did.as_str() {
            return false;
        }
    }

    true
}

fn intersect_sets<T: std::cmp::Eq + std::hash::Hash + Clone>(
    current: Option<HashSet<T>>,
    next: HashSet<T>,
) -> HashSet<T> {
    match current {
        Some(existing) => existing.intersection(&next).cloned().collect(),
        None => next,
    }
}

fn index_prefix(key: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(key.len() + 1);
    out.extend_from_slice(key.as_bytes());
    out.push(0);
    out
}

fn index_composite_key(key: &str, cid: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(key.len() + cid.len() + 1);
    out.extend_from_slice(key.as_bytes());
    out.push(0);
    out.extend_from_slice(cid.as_bytes());
    out
}

fn sanitize_component(input: &str) -> String {
    input
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '/' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn sanitize_cid(cid: &str) -> String {
    cid.replace(':', "_")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ChipStore, ExecutionMetadata};
    use serde_json::json;
    use std::sync::Arc;
    use std::sync::OnceLock;
    use tokio::sync::Mutex;
    use ubl_types::Did as TypedDid;

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn test_metadata() -> ExecutionMetadata {
        ExecutionMetadata {
            runtime_version: "test-runtime".to_string(),
            execution_time_ms: 5,
            fuel_consumed: 11,
            policies_applied: vec!["p0".to_string()],
            executor_did: TypedDid::new_unchecked("did:key:zTestExecutor"),
            reproducible: true,
        }
    }

    #[tokio::test]
    async fn sled_rebuild_indexes_recovers_from_index_loss() {
        let mut path = std::env::temp_dir();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        path.push(format!(
            "ubl_chipstore_rebuild_{}_{}",
            std::process::id(),
            nonce
        ));
        let path_str = path.to_string_lossy().to_string();

        let backend = Arc::new(SledBackend::new(&path_str).expect("open sled"));
        let store = ChipStore::new(backend.clone());
        store
            .store_executed_chip(
                json!({
                    "@type": "ubl/advisory",
                    "@id": "adv-rebuild",
                    "@ver": "1.0",
                    "@world": "a/rebuild/t/prod",
                    "passport_cid": "b3:passport-rebuild"
                }),
                "b3:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string(),
                test_metadata(),
            )
            .await
            .expect("store advisory");

        let query = ChipQuery {
            chip_type: Some("ubl/advisory".to_string()),
            tags: vec!["passport_cid:b3:passport-rebuild".to_string()],
            created_after: None,
            created_before: None,
            executor_did: None,
            limit: Some(10),
            offset: None,
        };

        let before = store.query(&query).await.expect("query before index loss");
        assert_eq!(before.total_count, 1);

        backend
            .type_index
            .clear()
            .expect("clear type index for corruption test");
        backend
            .tag_index
            .clear()
            .expect("clear tag index for corruption test");
        backend
            .executor_index
            .clear()
            .expect("clear executor index for corruption test");

        let broken = store
            .query(&query)
            .await
            .expect("query while indexes are empty");
        assert_eq!(broken.total_count, 0);

        store
            .rebuild_indexes()
            .await
            .expect("rebuild indexes from primary data");

        let recovered = store.query(&query).await.expect("query after rebuild");
        assert_eq!(recovered.total_count, 1);

        let _ = std::fs::remove_dir_all(&path);
    }

    #[tokio::test]
    async fn fs_backend_roundtrip() {
        let mut path = std::env::temp_dir();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        path.push(format!("ubl_chipstore_fs_{}_{}", std::process::id(), nonce));
        let backend = Arc::new(FsBackend::new(&path).expect("fs backend"));
        let store = ChipStore::new(backend);

        let receipt_cid = "b3:1111111111111111111111111111111111111111111111111111111111111111";
        let cid = store
            .store_executed_chip(
                json!({
                    "@type": "ubl/document",
                    "@id": "fs-1",
                    "@ver": "1.0",
                    "@world": "a/fs/t/prod",
                    "status": "ok"
                }),
                receipt_cid.to_string(),
                test_metadata(),
            )
            .await
            .expect("store");

        let by_cid = store.get_chip(&cid).await.expect("get by cid");
        assert!(by_cid.is_some());
        let by_receipt = store
            .get_chip_by_receipt_cid(receipt_cid)
            .await
            .expect("get by receipt");
        assert!(by_receipt.is_some());

        let _ = std::fs::remove_dir_all(path);
    }

    #[tokio::test]
    async fn s3_backend_local_emulation_roundtrip() {
        let _guard = env_lock().lock().await;
        let mut root = std::env::temp_dir();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        root.push(format!(
            "ubl_chipstore_s3_local_{}_{}",
            std::process::id(),
            nonce
        ));
        std::env::set_var("UBL_CHIPSTORE_S3_LOCAL_ROOT", &root);

        let bucket = format!("bucket-{}", nonce);
        let prefix = "tenant/prod";
        let backend = Arc::new(S3Backend::new(&bucket, prefix).expect("s3 backend"));
        assert_eq!(backend.bucket(), bucket);
        assert_eq!(backend.prefix(), prefix);
        let store = ChipStore::new(backend);

        let receipt_cid = "b3:2222222222222222222222222222222222222222222222222222222222222222";
        let cid = store
            .store_executed_chip(
                json!({
                    "@type": "ubl/advisory",
                    "@id": "s3-1",
                    "@ver": "1.0",
                    "@world": "a/s3/t/prod",
                    "status": "ok"
                }),
                receipt_cid.to_string(),
                test_metadata(),
            )
            .await
            .expect("store");
        assert!(store.exists(&cid).await.expect("exists"));
        assert!(store
            .get_chip_by_receipt_cid(receipt_cid)
            .await
            .expect("lookup")
            .is_some());

        std::env::remove_var("UBL_CHIPSTORE_S3_LOCAL_ROOT");
        let _ = std::fs::remove_dir_all(root);
    }
}
