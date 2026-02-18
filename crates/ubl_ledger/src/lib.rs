//! UBL Ledger storage adapter.
//!
//! Backends:
//! - `ledger_mem` (default): process-local in-memory map (fast tests/dev)
//! - `ledger_ndjson`: append-only NDJSON file for simple persistence

use cid::Cid;

#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    #[error("Not found")]
    NotFound,
    #[error("Storage error: {0}")]
    Storage(String),
}

#[cfg(feature = "ledger_ndjson")]
mod imp {
    use super::*;
    use serde::{Deserialize, Serialize};
    use std::io::ErrorKind;
    use std::path::PathBuf;
    use std::sync::OnceLock;
    use tokio::io::AsyncWriteExt;
    use tokio::sync::Mutex;

    const DEFAULT_LEDGER_PATH: &str = "./data/ubl_ledger.ndjson";

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct NdjsonRecord {
        kind: String,
        cid: String,
        data_hex: String,
    }

    fn ledger_path() -> PathBuf {
        std::env::var("UBL_LEDGER_NDJSON_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_LEDGER_PATH))
    }

    fn append_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    async fn append_record(kind: &str, cid: &str, data: &[u8]) -> Result<(), LedgerError> {
        // Guard append writes to keep NDJSON line integrity under concurrency.
        let _guard = append_lock().lock().await;
        let path = ledger_path();
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| LedgerError::Storage(e.to_string()))?;
        }

        let record = NdjsonRecord {
            kind: kind.to_string(),
            cid: cid.to_string(),
            data_hex: hex::encode(data),
        };
        let line =
            serde_json::to_string(&record).map_err(|e| LedgerError::Storage(e.to_string()))?;

        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await
            .map_err(|e| LedgerError::Storage(e.to_string()))?;
        file.write_all(line.as_bytes())
            .await
            .map_err(|e| LedgerError::Storage(e.to_string()))?;
        file.write_all(b"\n")
            .await
            .map_err(|e| LedgerError::Storage(e.to_string()))?;
        file.flush()
            .await
            .map_err(|e| LedgerError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn find_record(kind: &str, cid: &str) -> Result<Option<Vec<u8>>, LedgerError> {
        let path = ledger_path();
        let content = match tokio::fs::read_to_string(path).await {
            Ok(content) => content,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(LedgerError::Storage(e.to_string())),
        };

        let mut found: Option<Vec<u8>> = None;
        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let record: NdjsonRecord =
                serde_json::from_str(line).map_err(|e| LedgerError::Storage(e.to_string()))?;
            if record.kind == kind && record.cid == cid {
                let bytes = hex::decode(&record.data_hex)
                    .map_err(|e| LedgerError::Storage(e.to_string()))?;
                found = Some(bytes);
            }
        }
        Ok(found)
    }

    pub async fn store_chip(cid: &str, data: &[u8]) -> Result<(), LedgerError> {
        append_record("chip", cid, data).await
    }

    pub async fn get_chip(cid: &str) -> Result<Vec<u8>, LedgerError> {
        find_record("chip", cid).await?.ok_or(LedgerError::NotFound)
    }

    pub async fn put_receipt(cid: &Cid, data: &[u8]) -> Result<(), LedgerError> {
        append_record("receipt", &cid.to_string(), data).await
    }

    pub async fn get_receipt(cid: &Cid) -> Option<Vec<u8>> {
        find_record("receipt", &cid.to_string())
            .await
            .ok()
            .flatten()
    }
}

#[cfg(not(feature = "ledger_ndjson"))]
mod imp {
    use super::*;
    use std::collections::HashMap;
    use std::sync::OnceLock;
    use tokio::sync::RwLock;

    fn chip_store() -> &'static RwLock<HashMap<String, Vec<u8>>> {
        static CHIPS: OnceLock<RwLock<HashMap<String, Vec<u8>>>> = OnceLock::new();
        CHIPS.get_or_init(|| RwLock::new(HashMap::new()))
    }

    fn receipt_store() -> &'static RwLock<HashMap<String, Vec<u8>>> {
        static RECEIPTS: OnceLock<RwLock<HashMap<String, Vec<u8>>>> = OnceLock::new();
        RECEIPTS.get_or_init(|| RwLock::new(HashMap::new()))
    }

    pub async fn store_chip(cid: &str, data: &[u8]) -> Result<(), LedgerError> {
        chip_store()
            .write()
            .await
            .insert(cid.to_string(), data.to_vec());
        Ok(())
    }

    pub async fn get_chip(cid: &str) -> Result<Vec<u8>, LedgerError> {
        chip_store()
            .read()
            .await
            .get(cid)
            .cloned()
            .ok_or(LedgerError::NotFound)
    }

    pub async fn put_receipt(cid: &Cid, data: &[u8]) -> Result<(), LedgerError> {
        receipt_store()
            .write()
            .await
            .insert(cid.to_string(), data.to_vec());
        Ok(())
    }

    pub async fn get_receipt(cid: &Cid) -> Option<Vec<u8>> {
        receipt_store().read().await.get(&cid.to_string()).cloned()
    }
}

pub use imp::{get_chip, get_receipt, put_receipt, store_chip};

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::OnceLock;
    use tokio::sync::Mutex;

    fn test_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    struct EnvPathGuard {
        path: PathBuf,
    }

    impl EnvPathGuard {
        fn new() -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let path = std::env::temp_dir().join(format!(
                "ubl_ledger_test_{}_{}.ndjson",
                std::process::id(),
                nanos
            ));
            std::env::set_var("UBL_LEDGER_NDJSON_PATH", &path);
            Self { path }
        }
    }

    impl Drop for EnvPathGuard {
        fn drop(&mut self) {
            std::env::remove_var("UBL_LEDGER_NDJSON_PATH");
            let _ = std::fs::remove_file(&self.path);
        }
    }

    #[tokio::test]
    async fn chip_roundtrip_store_and_get() {
        let _serial = test_lock().lock().await;
        let _env = EnvPathGuard::new();
        let cid = "b3:test-chip";
        let payload = b"chip-bytes";
        store_chip(cid, payload).await.unwrap();
        let got = get_chip(cid).await.unwrap();
        assert_eq!(got, payload);
    }

    #[tokio::test]
    async fn receipt_roundtrip_store_and_get() {
        let _serial = test_lock().lock().await;
        let _env = EnvPathGuard::new();
        let cid =
            Cid::try_from("bafkreigh2akiscaildc2as7mhl4f7z6do4xqjmf3k3t4gws2j6f3u2z7i4").unwrap();
        let payload = b"receipt-jws";
        put_receipt(&cid, payload).await.unwrap();
        let got = get_receipt(&cid).await.unwrap();
        assert_eq!(got, payload);
    }
}
