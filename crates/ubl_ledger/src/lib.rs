//! UBL Ledger - S3/Garage storage adapter

use cid::Cid;

// Placeholder - will be implemented in Phase 4
pub async fn store_chip(_cid: &str, _data: &[u8]) -> Result<(), LedgerError> {
    Ok(())
}

pub async fn get_chip(_cid: &str) -> Result<Vec<u8>, LedgerError> {
    Ok(vec![])
}

pub async fn put_receipt(_cid: &Cid, _data: &[u8]) -> Result<(), LedgerError> {
    Ok(())
}

pub async fn get_receipt(_cid: &Cid) -> Option<Vec<u8>> {
    None
}

#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    #[error("Not found")]
    NotFound,
    #[error("Storage error: {0}")]
    Storage(String),
}
