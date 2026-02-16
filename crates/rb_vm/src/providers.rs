use crate::types::Cid;

pub trait CasProvider {
    /// Put bytes, return CID (b3:... or cidv1:... depending on build)
    fn put(&mut self, bytes: &[u8]) -> Cid;
    /// Get bytes by CID. Deterministic store interface.
    fn get(&self, cid: &Cid) -> Option<Vec<u8>>;
}

pub trait SignProvider {
    /// Deterministic, no timestamp. Returns JWS bytes.
    fn sign_jws(&self, payload_nrf_bytes: &[u8]) -> Vec<u8>;
    /// Current key id (kid) for headers
    fn kid(&self) -> String;
}

pub mod cas_fs;
pub mod sign_env;
