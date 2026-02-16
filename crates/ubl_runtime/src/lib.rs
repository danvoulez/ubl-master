//! UBL Runtime - WA→TR→WF Pipeline for UBL MASTER
//!
//! This is the core of the UBL MASTER system, implementing the deterministic
//! pipeline that processes every chip through the same 5-stage flow.

pub mod reasoning_bit;
pub mod circuit;
pub mod policy_bit;
pub mod pipeline;
pub mod genesis;
pub mod policy_loader;
pub mod knock;
pub mod error_response;
pub mod ledger;
pub mod event_bus;
pub mod llm_observer;

pub use reasoning_bit::{ReasoningBit, Decision, Expression};
pub use circuit::{Circuit, CompositionMode, AggregationMode};
pub use policy_bit::{PolicyBit, PolicyScope};
pub use pipeline::{UblPipeline, PipelineResult};

// Re-export receipt types for convenience
pub use ubl_receipt::{
    WaReceiptBody, WfReceiptBody, PolicyTraceEntry, RbResult
};