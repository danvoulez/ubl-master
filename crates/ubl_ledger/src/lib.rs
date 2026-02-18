//! UBL Ledger - S3/Garage storage adapter

use cid::Cid;
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

#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    #[error("Not found")]
    NotFound,
    #[error("Storage error: {0}")]
    Storage(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn chip_roundtrip_store_and_get() {
        let cid = "b3:test-chip";
        let payload = b"chip-bytes";
        store_chip(cid, payload).await.unwrap();
        let got = get_chip(cid).await.unwrap();
        assert_eq!(got, payload);
    }

    #[tokio::test]
    async fn receipt_roundtrip_store_and_get() {
        let cid =
            Cid::try_from("bafkreigh2akiscaildc2as7mhl4f7z6do4xqjmf3k3t4gws2j6f3u2z7i4").unwrap();
        let payload = b"receipt-jws";
        put_receipt(&cid, payload).await.unwrap();
        let got = get_receipt(&cid).await.unwrap();
        assert_eq!(got, payload);
    }
}
