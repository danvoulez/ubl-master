use anyhow::Result;

/// Minimal CAS (Content-Addressable Storage) abstraction.
///
/// All blobs are addressed by BLAKE3 CID (`b3:<hex>`).
/// The default implementation is an in-memory HashMap suitable for tests.
pub trait CasStore: Send + Sync {
    /// Store raw bytes; return the `b3:<hex>` CID.
    fn put(&mut self, data: &[u8]) -> Result<String>;
    /// Retrieve bytes by CID.
    fn get(&self, cid: &str) -> Result<Vec<u8>>;
    /// Return true if the CID is present.
    fn has(&self, cid: &str) -> bool;
}

/// Compute the BLAKE3 CID for arbitrary bytes.
pub fn blake3_cid(data: &[u8]) -> String {
    let hash = blake3::hash(data);
    format!("b3:{}", hash.to_hex())
}

// ---------------------------------------------------------------------------
// In-memory implementation (useful for tests and CLI dry-runs)
// ---------------------------------------------------------------------------

use std::collections::HashMap;

/// An in-memory CAS store — not persisted across restarts.
#[derive(Default)]
pub struct MemCasStore {
    blobs: HashMap<String, Vec<u8>>,
}

impl CasStore for MemCasStore {
    fn put(&mut self, data: &[u8]) -> Result<String> {
        let cid = blake3_cid(data);
        self.blobs
            .entry(cid.clone())
            .or_insert_with(|| data.to_vec());
        Ok(cid)
    }

    fn get(&self, cid: &str) -> Result<Vec<u8>> {
        self.blobs
            .get(cid)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("CAS miss: {}", cid))
    }

    fn has(&self, cid: &str) -> bool {
        self.blobs.contains_key(cid)
    }
}

// ---------------------------------------------------------------------------
// State store — keyed by section_id
// ---------------------------------------------------------------------------

use ubl_book_types::SectionState;

/// Persists and retrieves `SectionState` chips.
///
/// The default impl is an in-memory HashMap. A real impl would write
/// NDJSON to disk or push to a UBL EventStore.
pub trait StateStore: Send + Sync {
    fn load(&self, section_id: &str) -> Option<SectionState>;
    fn save(&mut self, state: &SectionState) -> Result<()>;
    /// Return all section states for a project.
    fn all(&self, project_id: &str) -> Vec<SectionState>;
}

#[derive(Default)]
pub struct MemStateStore {
    states: HashMap<String, SectionState>,
}

impl StateStore for MemStateStore {
    fn load(&self, section_id: &str) -> Option<SectionState> {
        self.states.get(section_id).cloned()
    }

    fn save(&mut self, state: &SectionState) -> Result<()> {
        self.states.insert(state.section_id.clone(), state.clone());
        Ok(())
    }

    fn all(&self, project_id: &str) -> Vec<SectionState> {
        self.states
            .values()
            .filter(|s| s.project_id == project_id)
            .cloned()
            .collect()
    }
}
