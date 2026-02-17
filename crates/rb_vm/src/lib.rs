//! RB-VM (MVP) - deterministic stack VM for Fractal
//!
//! Goals (MVP):
//! - No-IO by construction (except CAS + Sign providers)
//! - Deterministic execution with fuel metering
//! - TLV bytecode format
//! - Minimal opcode set aligned with Fractal lower layer canon

pub mod canon;
pub mod disasm;
pub mod exec;
pub mod opcode;
pub mod providers;
pub mod tlv;
pub mod types;

pub use canon::RhoCanon;
pub use disasm::disassemble;
pub use exec::{CasProvider, ExecError, Fuel, SignProvider, TraceStep, Vm, VmConfig, VmOutcome};
pub use opcode::Opcode;
pub use types::{Cid, RcPayload, Value};
