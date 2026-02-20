//! UBL AI-NRF1 — Canonical binary encoding (NRF‑1.1) + CID (BLAKE3)
//! Enhanced for UBL MASTER with Chip-as-Code support and Universal Envelope.

pub mod chip_format;
pub mod envelope;
pub mod nrf;

// Re-export key types and functions
pub use chip_format::{
    normalize_numbers_to_unc1, ChipFile, ChipMetadata, CompiledChip, F64ImportMode, PolicyRef,
};
pub use envelope::{EnvelopeError, UblEnvelope};
pub use nrf::{
    compute_cid, normalize_as_set, normalize_for_input, normalize_timestamp, to_nrf1_bytes,
    CompileError,
};
