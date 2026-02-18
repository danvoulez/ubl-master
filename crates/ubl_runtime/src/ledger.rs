//! Append-only NDJSON audit ledger.
//!
//! Every pipeline event (receipt created, ghost created/promoted/expired)
//! is appended as a single JSON line to `{base_dir}/{app}/{tenant}/receipts.ndjson`.
//!
//! Ledger failures are warn-logged, never block the pipeline.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Events that get written to the ledger.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LedgerEvent {
    ReceiptCreated,
    GhostCreated,
    GhostPromoted,
    GhostExpired,
}

/// A single ledger entry (one NDJSON line).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerEntry {
    pub ts: String,
    pub event: LedgerEvent,
    pub app: String,
    pub tenant: String,
    pub chip_cid: String,
    pub receipt_cid: String,
    pub decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

/// Trait for ledger backends.
#[async_trait::async_trait]
pub trait LedgerWriter: Send + Sync {
    async fn append(&self, entry: &LedgerEntry) -> Result<(), LedgerError>;
}

#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    #[error("IO error: {0}")]
    Io(String),
    #[error("Serialization error: {0}")]
    Serialization(String),
}

// ── NullLedger (no-op fallback) ──────────────────────────────────

/// No-op ledger — used when no ledger module is configured.
pub struct NullLedger;

#[async_trait::async_trait]
impl LedgerWriter for NullLedger {
    async fn append(&self, _entry: &LedgerEntry) -> Result<(), LedgerError> {
        Ok(())
    }
}

// ── NdjsonLedger (filesystem) ────────────────────────────────────

/// Append-only NDJSON ledger writing to the local filesystem.
/// File layout: `{base_dir}/{app}/{tenant}/receipts.ndjson`
pub struct NdjsonLedger {
    base_dir: PathBuf,
    lock: Arc<Mutex<()>>,
}

impl NdjsonLedger {
    pub fn new(base_dir: impl Into<PathBuf>) -> Self {
        Self {
            base_dir: base_dir.into(),
            lock: Arc::new(Mutex::new(())),
        }
    }

    fn ledger_path(&self, app: &str, tenant: &str) -> PathBuf {
        self.base_dir.join(app).join(tenant).join("receipts.ndjson")
    }
}

#[async_trait::async_trait]
impl LedgerWriter for NdjsonLedger {
    async fn append(&self, entry: &LedgerEntry) -> Result<(), LedgerError> {
        let path = self.ledger_path(&entry.app, &entry.tenant);

        // Serialize to single JSON line
        let mut line =
            serde_json::to_string(entry).map_err(|e| LedgerError::Serialization(e.to_string()))?;
        line.push('\n');

        // Atomic append under lock
        let _guard = self.lock.lock().await;

        // Ensure parent dirs exist
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| LedgerError::Io(e.to_string()))?;
        }

        // Append
        tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await
            .map_err(|e| LedgerError::Io(e.to_string()))?
            .write_all(line.as_bytes())
            .await
            .map_err(|e| LedgerError::Io(e.to_string()))?;

        Ok(())
    }
}

// Need this for the write_all call
use tokio::io::AsyncWriteExt;

// ── InMemoryLedger (for testing) ─────────────────────────────────

/// In-memory ledger for testing — stores entries in a Vec.
pub struct InMemoryLedger {
    entries: Arc<Mutex<Vec<LedgerEntry>>>,
}

impl InMemoryLedger {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub async fn entries(&self) -> Vec<LedgerEntry> {
        self.entries.lock().await.clone()
    }

    pub async fn count(&self) -> usize {
        self.entries.lock().await.len()
    }
}

impl Default for InMemoryLedger {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl LedgerWriter for InMemoryLedger {
    async fn append(&self, entry: &LedgerEntry) -> Result<(), LedgerError> {
        self.entries.lock().await.push(entry.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry() -> LedgerEntry {
        LedgerEntry {
            ts: "2025-02-15T14:00:00Z".to_string(),
            event: LedgerEvent::ReceiptCreated,
            app: "acme".to_string(),
            tenant: "prod".to_string(),
            chip_cid: "b3:abc123".to_string(),
            receipt_cid: "b3:def456".to_string(),
            decision: "Allow".to_string(),
            did: Some("did:key:z123".to_string()),
            kid: Some("did:key:z123#v0".to_string()),
        }
    }

    #[tokio::test]
    async fn null_ledger_is_noop() {
        let ledger = NullLedger;
        assert!(ledger.append(&sample_entry()).await.is_ok());
    }

    #[tokio::test]
    async fn in_memory_ledger_stores_entries() {
        let ledger = InMemoryLedger::new();
        ledger.append(&sample_entry()).await.unwrap();
        ledger.append(&sample_entry()).await.unwrap();
        assert_eq!(ledger.count().await, 2);
    }

    #[tokio::test]
    async fn ndjson_ledger_writes_to_file() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = NdjsonLedger::new(dir.path());

        let entry = sample_entry();
        ledger.append(&entry).await.unwrap();
        ledger.append(&entry).await.unwrap();

        let path = dir.path().join("acme").join("prod").join("receipts.ndjson");
        let contents = tokio::fs::read_to_string(&path).await.unwrap();
        let lines: Vec<&str> = contents.trim().split('\n').collect();
        assert_eq!(lines.len(), 2);

        // Each line is valid JSON
        let parsed: LedgerEntry = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(parsed.app, "acme");
        assert_eq!(parsed.event, LedgerEvent::ReceiptCreated);
    }

    #[tokio::test]
    async fn ndjson_ledger_creates_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = NdjsonLedger::new(dir.path());

        let mut entry = sample_entry();
        entry.app = "new-app".to_string();
        entry.tenant = "new-tenant".to_string();
        ledger.append(&entry).await.unwrap();

        let path = dir
            .path()
            .join("new-app")
            .join("new-tenant")
            .join("receipts.ndjson");
        assert!(path.exists());
    }

    #[test]
    fn entry_serializes_to_single_line() {
        let entry = sample_entry();
        let json = serde_json::to_string(&entry).unwrap();
        assert!(!json.contains('\n'), "NDJSON entry must be single line");
        assert!(json.contains("receipt_created"));
    }

    #[test]
    fn entry_omits_none_fields() {
        let mut entry = sample_entry();
        entry.did = None;
        entry.kid = None;
        let json = serde_json::to_string(&entry).unwrap();
        assert!(!json.contains("did"));
        assert!(!json.contains("kid"));
    }
}
