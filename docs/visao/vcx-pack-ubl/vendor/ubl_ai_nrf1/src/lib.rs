//! UBL AI-NRF1 — Canonical binary encoding (NRF‑1.1) + CID (BLAKE3)
//! Enhanced for UBL MASTER with Chip-as-Code support and Universal Envelope.

pub mod nrf;
pub mod chip_format;
pub mod envelope;

// Re-export key types and functions
pub use chip_format::{ChipFile, ChipMetadata, CompiledChip, PolicyRef};
pub use nrf::{to_nrf1_bytes, compute_cid, CompileError};
pub use envelope::{UblEnvelope, EnvelopeError};
