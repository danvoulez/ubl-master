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
pub mod ai_passport;
pub mod advisory;
pub mod wasm_adapter;
pub mod rich_url;
pub mod auth;
pub mod rate_limit;
pub mod policy_lock;
pub mod idempotency;
pub mod capability;
pub mod manifest;
pub mod meta_chip;

pub use reasoning_bit::{ReasoningBit, Decision, Expression};
pub use circuit::{Circuit, CompositionMode, AggregationMode};
pub use policy_bit::{PolicyBit, PolicyScope};
pub use pipeline::{UblPipeline, PipelineResult};

// Re-export receipt types for convenience
pub use ubl_receipt::{
    WaReceiptBody, WfReceiptBody, PolicyTraceEntry, RbResult
};
pub use ai_passport::AiPassport;
pub use advisory::{Advisory, AdvisoryEngine, AdvisoryHook};
pub use wasm_adapter::{AdapterRegistry, AdapterRegistration, WasmExecutor, SandboxConfig};
pub use auth::{
    AppRegistration, UserIdentity, TenantCircle, Membership,
    SessionToken, Revocation, Role, WorldScope, PermissionContext,
    AuthError, ONBOARDING_TYPES, is_onboarding_type, validate_onboarding_chip,
};