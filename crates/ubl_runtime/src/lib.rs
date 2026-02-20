//! UBL Runtime - WA→TR→WF Pipeline for UBL MASTER
//!
//! This is the core of the UBL MASTER system, implementing the deterministic
//! pipeline that processes every chip through the same 5-stage flow.

pub mod advisory;
pub mod ai_passport;
pub mod audit_chip;
pub mod auth;
pub mod capability;
pub mod circuit;
pub mod durable_store;
pub mod error_response;
pub mod event_bus;
pub mod genesis;
pub mod idempotency;
pub mod key_rotation;
pub mod knock;
pub mod ledger;
pub mod llm_observer;
pub mod manifest;
pub mod meta_chip;
pub mod outbox_dispatcher;
pub mod pipeline;
pub mod policy_bit;
pub mod policy_loader;
pub mod policy_lock;
pub mod rate_limit;
pub mod reasoning_bit;
pub mod rich_url;
pub mod runtime_cert;
pub mod silicon_chip;
pub mod transition_registry;
pub mod wasm_adapter;

pub use circuit::{AggregationMode, Circuit, CompositionMode};
pub use pipeline::{PipelineResult, UblPipeline};
pub use policy_bit::{PolicyBit, PolicyScope};
pub use reasoning_bit::{Decision, Expression, ReasoningBit};

// Re-export receipt types for convenience
pub use advisory::{Advisory, AdvisoryEngine, AdvisoryHook};
pub use ai_passport::AiPassport;
pub use auth::{
    is_onboarding_type, validate_onboarding_chip, AppRegistration, AuthEngine, AuthError,
    AuthValidationError, Membership, PermissionContext, Revocation, Role, SessionToken,
    TenantCircle, UserIdentity, WorldScope, ONBOARDING_TYPES,
};
pub use runtime_cert::SelfAttestation;
pub use silicon_chip::{
    is_silicon_type, CompileTarget, ConditionSpec, HalProfile, SiliconBitBody, SiliconChipBody,
    SiliconCircuitBody, SiliconCompileBody, SiliconError, SiliconRequest, SILICON_TYPES,
    TYPE_SILICON_BIT, TYPE_SILICON_CHIP, TYPE_SILICON_CIRCUIT, TYPE_SILICON_COMPILE,
};
pub use ubl_receipt::{PolicyTraceEntry, RbResult, WaReceiptBody, WfReceiptBody};
pub use wasm_adapter::{
    AdapterRegistration, AdapterRegistry, SandboxConfig, WasmExecutor, WasmtimeExecutor,
};
