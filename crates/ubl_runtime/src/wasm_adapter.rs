//! WASM Adapter Framework — sandboxed external effects in the TR stage.
//!
//! WASM adapters run for chips that require external effects (email, payment, etc.).
//! They receive NRF-1 bytes in and return NRF-1 bytes out. No other I/O.
//!
//! Constraints (ARCHITECTURE.md §9):
//! - No filesystem access
//! - No clock (frozen WA timestamp injected)
//! - No network (all I/O via injected CAS artifacts)
//! - Memory limit: 64 MB per execution
//! - Fuel shared with RB-VM budget
//! - Module hash pinned in receipt `rt` field
//!
//! See ARCHITECTURE.md §9.1–§9.3.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Maximum memory a WASM module may use (64 MB).
pub const WASM_MEMORY_LIMIT_BYTES: usize = 64 * 1024 * 1024;

/// Default fuel budget for WASM execution (shared with RB-VM).
pub const WASM_DEFAULT_FUEL: u64 = 100_000;

/// The ABI contract: NRF-1 bytes in → NRF-1 bytes out.
#[derive(Debug, Clone)]
pub struct WasmInput {
    /// NRF-1 encoded chip body
    pub nrf1_bytes: Vec<u8>,
    /// CID of the input chip
    pub chip_cid: String,
    /// Frozen WA timestamp (no clock access inside WASM)
    pub frozen_timestamp: String,
    /// Fuel budget for this execution
    pub fuel_limit: u64,
}

/// Result of a WASM adapter execution.
#[derive(Debug, Clone)]
pub struct WasmOutput {
    /// NRF-1 encoded result
    pub nrf1_bytes: Vec<u8>,
    /// CID of the output
    pub output_cid: String,
    /// Effects produced (e.g. "email.sent", "payment.charged")
    pub effects: Vec<String>,
    /// Fuel consumed
    pub fuel_consumed: u64,
}

/// Sandbox constraints enforced on every WASM execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    /// Maximum memory in bytes
    pub memory_limit: usize,
    /// Fuel limit (shared with RB-VM)
    pub fuel_limit: u64,
    /// Whether filesystem access is allowed (always false)
    pub allow_fs: bool,
    /// Whether network access is allowed (always false)
    pub allow_network: bool,
    /// Whether clock access is allowed (always false — use frozen timestamp)
    pub allow_clock: bool,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            memory_limit: WASM_MEMORY_LIMIT_BYTES,
            fuel_limit: WASM_DEFAULT_FUEL,
            allow_fs: false,
            allow_network: false,
            allow_clock: false,
        }
    }
}

/// Errors from WASM adapter execution.
#[derive(Debug, Clone)]
pub enum WasmError {
    /// Module failed to compile
    CompileError(String),
    /// Execution exceeded fuel limit
    FuelExhausted { limit: u64, consumed: u64 },
    /// Execution exceeded memory limit
    MemoryExceeded { limit: usize },
    /// Module produced invalid output (not valid NRF-1)
    InvalidOutput(String),
    /// Module not found in registry
    ModuleNotFound(String),
    /// ABI version mismatch
    AbiMismatch { expected: String, got: String },
    /// Generic runtime error
    Runtime(String),
}

impl std::fmt::Display for WasmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WasmError::CompileError(e) => write!(f, "WASM compile error: {}", e),
            WasmError::FuelExhausted { limit, consumed } => write!(
                f,
                "WASM fuel exhausted: limit={}, consumed={}",
                limit, consumed
            ),
            WasmError::MemoryExceeded { limit } => {
                write!(f, "WASM memory exceeded: limit={} bytes", limit)
            }
            WasmError::InvalidOutput(e) => write!(f, "WASM invalid output: {}", e),
            WasmError::ModuleNotFound(cid) => write!(f, "WASM module not found: {}", cid),
            WasmError::AbiMismatch { expected, got } => {
                write!(f, "WASM ABI mismatch: expected {}, got {}", expected, got)
            }
            WasmError::Runtime(e) => write!(f, "WASM runtime error: {}", e),
        }
    }
}

impl std::error::Error for WasmError {}

/// Trait for WASM execution backends.
///
/// Implementations can use wasmtime, wasmer, or any other WASM runtime.
/// The sandbox constraints MUST be enforced by the implementation.
pub trait WasmExecutor: Send + Sync {
    /// Execute a WASM module with the given input and sandbox config.
    fn execute(
        &self,
        module_bytes: &[u8],
        input: &WasmInput,
        sandbox: &SandboxConfig,
    ) -> Result<WasmOutput, WasmError>;
}

const WASM_ENTRYPOINT_V1: &str = "ubl_adapter_v1";

#[derive(Default)]
pub struct WasmtimeExecutor;

struct WasmtimeStoreState {
    limits: wasmtime::StoreLimits,
}

impl WasmtimeExecutor {
    fn engine() -> Result<wasmtime::Engine, WasmError> {
        let mut cfg = wasmtime::Config::new();
        cfg.consume_fuel(true);
        wasmtime::Engine::new(&cfg).map_err(|e| WasmError::CompileError(e.to_string()))
    }
}

impl WasmExecutor for WasmtimeExecutor {
    fn execute(
        &self,
        module_bytes: &[u8],
        input: &WasmInput,
        sandbox: &SandboxConfig,
    ) -> Result<WasmOutput, WasmError> {
        if sandbox.allow_fs || sandbox.allow_network || sandbox.allow_clock {
            return Err(WasmError::Runtime(
                "unsafe sandbox flags are not supported for WASM adapters".to_string(),
            ));
        }

        let engine = Self::engine()?;
        let module = wasmtime::Module::new(&engine, module_bytes)
            .map_err(|e| WasmError::CompileError(e.to_string()))?;

        // Explicitly reject WASI imports: adapters are pure NRF-1 transforms.
        if module.imports().any(|import| {
            import.module() == "wasi_snapshot_preview1" || import.module().starts_with("wasi:")
        }) {
            return Err(WasmError::Runtime(
                "WASI imports are not allowed in adapter modules".to_string(),
            ));
        }

        let limits = wasmtime::StoreLimitsBuilder::new()
            .memory_size(sandbox.memory_limit)
            .build();
        let mut store = wasmtime::Store::new(&engine, WasmtimeStoreState { limits });
        store.limiter(|state| &mut state.limits);
        store
            .set_fuel(sandbox.fuel_limit)
            .map_err(|e| WasmError::Runtime(format!("set_fuel: {}", e)))?;

        let linker = wasmtime::Linker::new(&engine);
        let instance = linker
            .instantiate(&mut store, &module)
            .map_err(|e| WasmError::Runtime(e.to_string()))?;

        let memory = instance.get_memory(&mut store, "memory").ok_or_else(|| {
            WasmError::InvalidOutput("module must export linear memory as `memory`".to_string())
        })?;

        let func = instance
            .get_typed_func::<(i32, i32), i32>(&mut store, WASM_ENTRYPOINT_V1)
            .map_err(|e| WasmError::AbiMismatch {
                expected: format!("export fn {}(i32, i32) -> i32", WASM_ENTRYPOINT_V1),
                got: e.to_string(),
            })?;

        if input.nrf1_bytes.len() > sandbox.memory_limit {
            return Err(WasmError::MemoryExceeded {
                limit: sandbox.memory_limit,
            });
        }
        if input.nrf1_bytes.len() > i32::MAX as usize {
            return Err(WasmError::InvalidOutput(
                "input too large for ABI i32 length".to_string(),
            ));
        }

        let current_size = memory.data_size(&store);
        let required_size = input.nrf1_bytes.len();
        if current_size < required_size {
            let growth_bytes = required_size - current_size;
            let pages = growth_bytes.div_ceil(65_536);
            memory
                .grow(&mut store, pages as u64)
                .map_err(|_| WasmError::MemoryExceeded {
                    limit: sandbox.memory_limit,
                })?;
        }

        let post_grow_size = memory.data_size(&store);
        if post_grow_size > sandbox.memory_limit {
            return Err(WasmError::MemoryExceeded {
                limit: sandbox.memory_limit,
            });
        }

        memory
            .write(&mut store, 0, &input.nrf1_bytes)
            .map_err(|e| WasmError::Runtime(format!("memory write: {}", e)))?;

        let output_len = match func.call(&mut store, (0, input.nrf1_bytes.len() as i32)) {
            Ok(v) => v,
            Err(e) => {
                if let Ok(remaining) = store.get_fuel() {
                    if remaining == 0 {
                        return Err(WasmError::FuelExhausted {
                            limit: sandbox.fuel_limit,
                            consumed: sandbox.fuel_limit,
                        });
                    }
                }
                return Err(WasmError::Runtime(e.to_string()));
            }
        };

        if output_len < 0 {
            return Err(WasmError::InvalidOutput(
                "module returned negative output length".to_string(),
            ));
        }
        let output_len = output_len as usize;
        if output_len > memory.data_size(&store) {
            return Err(WasmError::InvalidOutput(format!(
                "module returned output length {} beyond memory size {}",
                output_len,
                memory.data_size(&store)
            )));
        }

        let mut out = vec![0u8; output_len];
        memory
            .read(&mut store, 0, &mut out)
            .map_err(|e| WasmError::Runtime(format!("memory read: {}", e)))?;

        ubl_ai_nrf1::nrf::decode_from_slice(&out)
            .map_err(|e| WasmError::InvalidOutput(format!("not valid NRF-1: {}", e)))?;
        let output_cid =
            ubl_ai_nrf1::compute_cid(&out).map_err(|e| WasmError::InvalidOutput(e.to_string()))?;

        let fuel_remaining = store.get_fuel().unwrap_or(0);
        let fuel_consumed = sandbox.fuel_limit.saturating_sub(fuel_remaining);

        Ok(WasmOutput {
            nrf1_bytes: out,
            output_cid,
            effects: Vec::new(),
            fuel_consumed,
        })
    }
}

/// A registered WASM adapter — a chip of type `ubl/adapter`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterRegistration {
    /// CID of the WASM module binary in CAS
    pub wasm_cid: String,
    /// SHA-256 hash of the WASM binary (for receipt pinning)
    pub wasm_sha256: String,
    /// ABI version (must be "1.0")
    pub abi_version: String,
    /// Fuel budget for this adapter
    pub fuel_budget: u64,
    /// Capabilities this adapter provides (e.g. ["email.send"])
    pub capabilities: Vec<String>,
    /// Human-readable description
    pub description: String,
}

impl AdapterRegistration {
    /// Parse an adapter registration from a `ubl/adapter` chip body.
    pub fn from_chip_body(body: &Value) -> Result<Self, WasmError> {
        let wasm_cid = body
            .get("wasm_cid")
            .and_then(|v| v.as_str())
            .ok_or_else(|| WasmError::Runtime("Missing wasm_cid".into()))?
            .to_string();

        let wasm_sha256 = body
            .get("wasm_sha256")
            .and_then(|v| v.as_str())
            .ok_or_else(|| WasmError::Runtime("Missing wasm_sha256".into()))?
            .to_string();

        let abi_version = body
            .get("abi_version")
            .and_then(|v| v.as_str())
            .unwrap_or("1.0")
            .to_string();

        if abi_version != "1.0" {
            return Err(WasmError::AbiMismatch {
                expected: "1.0".into(),
                got: abi_version,
            });
        }

        let fuel_budget = body
            .get("fuel_budget")
            .and_then(|v| v.as_u64())
            .unwrap_or(WASM_DEFAULT_FUEL);

        let capabilities = body
            .get("capabilities")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let description = body
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        Ok(Self {
            wasm_cid,
            wasm_sha256,
            abi_version,
            fuel_budget,
            capabilities,
            description,
        })
    }

    /// Produce the canonical chip body for this adapter registration.
    pub fn to_chip_body(&self, id: &str, world: &str) -> Value {
        json!({
            "@type": "ubl/adapter",
            "@id": id,
            "@ver": "1.0",
            "@world": world,
            "wasm_cid": self.wasm_cid,
            "wasm_sha256": self.wasm_sha256,
            "abi_version": self.abi_version,
            "fuel_budget": self.fuel_budget,
            "capabilities": self.capabilities,
            "description": self.description,
        })
    }

    /// Verify that the actual WASM binary matches the registered hash.
    pub fn verify_module(&self, wasm_bytes: &[u8]) -> Result<(), WasmError> {
        let actual_hash = sha256_hex(wasm_bytes);
        if actual_hash != self.wasm_sha256 {
            return Err(WasmError::CompileError(format!(
                "Module hash mismatch: expected {}, got {}",
                self.wasm_sha256, actual_hash
            )));
        }
        Ok(())
    }
}

/// Compute SHA-256 hex digest of bytes (for module pinning).
fn sha256_hex(bytes: &[u8]) -> String {
    use ring::digest;
    let hash = digest::digest(&digest::SHA256, bytes);
    hex::encode(hash.as_ref())
}

/// Runtime info for the receipt `rt` field — pins the WASM module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmRuntimeInfo {
    /// "wasm/1.0"
    pub runtime_version: String,
    /// SHA-256 of the WASM module binary
    pub module_sha256: String,
    /// CID of the WASM module in CAS
    pub module_cid: String,
    /// Fuel consumed
    pub fuel_consumed: u64,
    /// Memory peak (bytes)
    pub memory_peak: usize,
    /// Whether execution was deterministic
    pub deterministic: bool,
}

/// In-memory adapter registry — maps capability names to adapter registrations.
pub struct AdapterRegistry {
    adapters: std::collections::HashMap<String, AdapterRegistration>,
}

impl AdapterRegistry {
    pub fn new() -> Self {
        Self {
            adapters: std::collections::HashMap::new(),
        }
    }

    /// Register an adapter for a set of capabilities.
    pub fn register(&mut self, registration: AdapterRegistration) {
        for cap in &registration.capabilities {
            self.adapters.insert(cap.clone(), registration.clone());
        }
    }

    /// Look up an adapter by capability.
    pub fn find_by_capability(&self, capability: &str) -> Option<&AdapterRegistration> {
        self.adapters.get(capability)
    }

    /// List all registered capabilities.
    pub fn capabilities(&self) -> Vec<String> {
        self.adapters.keys().cloned().collect()
    }

    /// Number of registered adapters.
    pub fn len(&self) -> usize {
        self.adapters.len()
    }

    pub fn is_empty(&self) -> bool {
        self.adapters.is_empty()
    }
}

impl Default for AdapterRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sandbox_config_defaults_are_secure() {
        let cfg = SandboxConfig::default();
        assert_eq!(cfg.memory_limit, 64 * 1024 * 1024);
        assert_eq!(cfg.fuel_limit, 100_000);
        assert!(!cfg.allow_fs);
        assert!(!cfg.allow_network);
        assert!(!cfg.allow_clock);
    }

    #[test]
    fn adapter_registration_from_chip_body() {
        let body = json!({
            "@type": "ubl/adapter",
            "@id": "email-sendgrid-v1",
            "@ver": "1.0",
            "@world": "a/acme/t/prod",
            "wasm_cid": "b3:abc123",
            "wasm_sha256": "deadbeef",
            "abi_version": "1.0",
            "fuel_budget": 50000,
            "capabilities": ["email.send"],
            "description": "SendGrid email adapter"
        });

        let reg = AdapterRegistration::from_chip_body(&body).unwrap();
        assert_eq!(reg.wasm_cid, "b3:abc123");
        assert_eq!(reg.wasm_sha256, "deadbeef");
        assert_eq!(reg.abi_version, "1.0");
        assert_eq!(reg.fuel_budget, 50_000);
        assert_eq!(reg.capabilities, vec!["email.send"]);
    }

    #[test]
    fn adapter_registration_rejects_bad_abi() {
        let body = json!({
            "wasm_cid": "b3:abc",
            "wasm_sha256": "dead",
            "abi_version": "2.0"
        });

        let err = AdapterRegistration::from_chip_body(&body).unwrap_err();
        assert!(matches!(err, WasmError::AbiMismatch { .. }));
    }

    #[test]
    fn adapter_registration_roundtrip() {
        let reg = AdapterRegistration {
            wasm_cid: "b3:module123".into(),
            wasm_sha256: "abcdef1234567890".into(),
            abi_version: "1.0".into(),
            fuel_budget: 75_000,
            capabilities: vec!["email.send".into(), "sms.send".into()],
            description: "Multi-channel adapter".into(),
        };

        let body = reg.to_chip_body("adapter-1", "a/acme/t/prod");
        assert_eq!(body["@type"], "ubl/adapter");
        assert_eq!(body["wasm_cid"], "b3:module123");

        let parsed = AdapterRegistration::from_chip_body(&body).unwrap();
        assert_eq!(parsed.wasm_cid, reg.wasm_cid);
        assert_eq!(parsed.capabilities.len(), 2);
    }

    #[test]
    fn adapter_registry_lookup() {
        let mut registry = AdapterRegistry::new();

        let reg = AdapterRegistration {
            wasm_cid: "b3:email".into(),
            wasm_sha256: "hash1".into(),
            abi_version: "1.0".into(),
            fuel_budget: 50_000,
            capabilities: vec!["email.send".into()],
            description: "Email".into(),
        };
        registry.register(reg);

        assert!(registry.find_by_capability("email.send").is_some());
        assert!(registry.find_by_capability("sms.send").is_none());
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn verify_module_hash() {
        let wasm_bytes = b"fake wasm module bytes";
        let hash = sha256_hex(wasm_bytes);

        let reg = AdapterRegistration {
            wasm_cid: "b3:test".into(),
            wasm_sha256: hash.clone(),
            abi_version: "1.0".into(),
            fuel_budget: 50_000,
            capabilities: vec![],
            description: "test".into(),
        };

        assert!(reg.verify_module(wasm_bytes).is_ok());
        assert!(reg.verify_module(b"different bytes").is_err());
    }

    #[test]
    fn wasm_runtime_info_serializes() {
        let info = WasmRuntimeInfo {
            runtime_version: "wasm/1.0".into(),
            module_sha256: "abc123".into(),
            module_cid: "b3:module".into(),
            fuel_consumed: 42_000,
            memory_peak: 1024 * 1024,
            deterministic: true,
        };

        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["runtime_version"], "wasm/1.0");
        assert_eq!(json["fuel_consumed"], 42_000);
        assert_eq!(json["deterministic"], true);
    }

    #[test]
    fn sha256_hex_is_deterministic() {
        let a = sha256_hex(b"hello");
        let b = sha256_hex(b"hello");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64); // 32 bytes = 64 hex chars
    }

    #[test]
    fn wasmtime_executor_roundtrip_identity_module() {
        let module = wat::parse_str(
            r#"
            (module
              (memory (export "memory") 1 1)
              (func (export "ubl_adapter_v1") (param i32 i32) (result i32)
                local.get 1))
            "#,
        )
        .unwrap();

        let input_json = json!({
            "@type": "ubl/payment",
            "amount": {"@num":"dec/1","m":"1250","s":2}
        });
        let input_bytes = ubl_ai_nrf1::to_nrf1_bytes(&input_json).unwrap();
        let input = WasmInput {
            nrf1_bytes: input_bytes.clone(),
            chip_cid: "b3:input".into(),
            frozen_timestamp: "2026-02-17T00:00:00Z".into(),
            fuel_limit: 10_000,
        };
        let sandbox = SandboxConfig {
            fuel_limit: 10_000,
            ..Default::default()
        };

        let exec = WasmtimeExecutor;
        let out = exec.execute(&module, &input, &sandbox).unwrap();

        assert_eq!(out.nrf1_bytes, input_bytes);
        assert_eq!(
            out.output_cid,
            ubl_ai_nrf1::compute_cid(&input_bytes).unwrap()
        );
        assert!(out.fuel_consumed > 0);
    }

    #[test]
    fn wasmtime_executor_rejects_invalid_nrf_output() {
        let module = wat::parse_str(
            r#"
            (module
              (memory (export "memory") 1 1)
              (func (export "ubl_adapter_v1") (param i32 i32) (result i32)
                i32.const 0
                i32.const 0
                i32.store8
                i32.const 1))
            "#,
        )
        .unwrap();
        let input = WasmInput {
            nrf1_bytes: ubl_ai_nrf1::to_nrf1_bytes(&json!({"ok":true})).unwrap(),
            chip_cid: "b3:input".into(),
            frozen_timestamp: "2026-02-17T00:00:00Z".into(),
            fuel_limit: 10_000,
        };
        let exec = WasmtimeExecutor;
        let err = exec
            .execute(&module, &input, &SandboxConfig::default())
            .unwrap_err();
        assert!(matches!(err, WasmError::InvalidOutput(_)));
    }

    #[test]
    fn wasmtime_executor_reports_fuel_exhaustion() {
        let module = wat::parse_str(
            r#"
            (module
              (memory (export "memory") 1 1)
              (func (export "ubl_adapter_v1") (param i32 i32) (result i32)
                (loop
                  br 0)
                i32.const 0))
            "#,
        )
        .unwrap();
        let input = WasmInput {
            nrf1_bytes: ubl_ai_nrf1::to_nrf1_bytes(&json!({"ok":true})).unwrap(),
            chip_cid: "b3:input".into(),
            frozen_timestamp: "2026-02-17T00:00:00Z".into(),
            fuel_limit: 50,
        };
        let sandbox = SandboxConfig {
            fuel_limit: 50,
            ..Default::default()
        };

        let exec = WasmtimeExecutor;
        let err = exec.execute(&module, &input, &sandbox).unwrap_err();
        assert!(matches!(err, WasmError::FuelExhausted { .. }));
    }

    #[test]
    fn wasmtime_executor_rejects_missing_entrypoint() {
        let module = wat::parse_str(
            r#"
            (module
              (memory (export "memory") 1 1)
              (func (export "not_adapter") (param i32 i32) (result i32)
                i32.const 0))
            "#,
        )
        .unwrap();
        let input = WasmInput {
            nrf1_bytes: ubl_ai_nrf1::to_nrf1_bytes(&json!({"ok":true})).unwrap(),
            chip_cid: "b3:input".into(),
            frozen_timestamp: "2026-02-17T00:00:00Z".into(),
            fuel_limit: 10_000,
        };

        let exec = WasmtimeExecutor;
        let err = exec
            .execute(&module, &input, &SandboxConfig::default())
            .unwrap_err();
        assert!(matches!(err, WasmError::AbiMismatch { .. }));
    }
}
