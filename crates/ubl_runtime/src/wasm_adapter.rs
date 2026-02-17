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
}
