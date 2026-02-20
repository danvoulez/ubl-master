/// File-system backed CAS and State stores.
///
/// Layout (under `base_dir`):
/// ```
/// <base_dir>/
///   cas/
///     b3_<hex64>.bin      ← content-addressed blobs
///   state/
///     <section_id_urlsafe>.json   ← one JSON file per section state
/// ```
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

use ubl_book_engine::store::{blake3_cid, CasStore, StateStore};
use ubl_book_types::SectionState;

// ---------------------------------------------------------------------------
// FsCasStore
// ---------------------------------------------------------------------------

pub struct FsCasStore {
    cas_dir: PathBuf,
}

impl FsCasStore {
    pub fn new(base_dir: &Path) -> Result<Self> {
        let cas_dir = base_dir.join("cas");
        std::fs::create_dir_all(&cas_dir)?;
        Ok(Self { cas_dir })
    }

    fn cid_to_path(&self, cid: &str) -> PathBuf {
        // "b3:abc123..." → "b3_abc123...bin"
        let filename = cid.replace(':', "_") + ".bin";
        self.cas_dir.join(filename)
    }
}

impl CasStore for FsCasStore {
    fn put(&mut self, data: &[u8]) -> Result<String> {
        let cid = blake3_cid(data);
        let path = self.cid_to_path(&cid);
        if !path.exists() {
            std::fs::write(&path, data)
                .with_context(|| format!("CAS write: {}", path.display()))?;
        }
        Ok(cid)
    }

    fn get(&self, cid: &str) -> Result<Vec<u8>> {
        let path = self.cid_to_path(cid);
        std::fs::read(&path).with_context(|| format!("CAS read: {}", path.display()))
    }

    fn has(&self, cid: &str) -> bool {
        self.cid_to_path(cid).exists()
    }
}

// ---------------------------------------------------------------------------
// FsStateStore
// ---------------------------------------------------------------------------

pub struct FsStateStore {
    state_dir: PathBuf,
}

impl FsStateStore {
    pub fn new(base_dir: &Path) -> Result<Self> {
        let state_dir = base_dir.join("state");
        std::fs::create_dir_all(&state_dir)?;
        Ok(Self { state_dir })
    }

    fn section_path(&self, section_id: &str) -> PathBuf {
        // Replace path separators so section ids are safe filenames
        let filename = section_id.replace('/', "__") + ".json";
        self.state_dir.join(filename)
    }
}

impl StateStore for FsStateStore {
    fn load(&self, section_id: &str) -> Option<SectionState> {
        let path = self.section_path(section_id);
        let data = std::fs::read_to_string(&path).ok()?;
        serde_json::from_str(&data).ok()
    }

    fn save(&mut self, state: &SectionState) -> Result<()> {
        let path = self.section_path(&state.section_id);
        let json = serde_json::to_string_pretty(state)?;
        std::fs::write(&path, json).with_context(|| format!("State write: {}", path.display()))?;
        Ok(())
    }

    fn all(&self, project_id: &str) -> Vec<SectionState> {
        let entries = match std::fs::read_dir(&self.state_dir) {
            Ok(e) => e,
            Err(_) => return vec![],
        };

        entries
            .filter_map(|e| {
                let path = e.ok()?.path();
                if path.extension()?.to_str()? != "json" {
                    return None;
                }
                let data = std::fs::read_to_string(&path).ok()?;
                let state: SectionState = serde_json::from_str(&data).ok()?;
                if state.project_id == project_id {
                    Some(state)
                } else {
                    None
                }
            })
            .collect()
    }
}
