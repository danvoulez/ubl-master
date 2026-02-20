//! Silicon Power Chips — `ubl/silicon.*` chip family
//!
//! Implements the Chip-as-Code model from Paper VI and Paper B:
//!   > "A computer is not defined by its hardware but by the protocol it follows.
//!     A billion policy decisions, wired in series and parallel, IS a chip.
//!     That chip fits in a text file. Hardware is just one of many backends."
//!
//! The math: 1 Policy Bit ≈ 10⁶ silicon gates → 200M-gate ASIC ≈ 50KB of text.
//!
//! Four chip types:
//!   `ubl/silicon.bit`     — semantic transistor (atomic policy decision)
//!   `ubl/silicon.circuit` — semantic IC (wired graph of bits)
//!   `ubl/silicon.chip`    — full TDLN-chip (composed circuits + HAL profile)
//!   `ubl/silicon.compile` — compilation request → rb_vm TLV bytecode

use serde::{Deserialize, Serialize};
use serde_json::Value;
use ubl_chipstore::ChipStore;

use crate::circuit::{AggregationMode, CompositionMode};
use crate::reasoning_bit::{Decision, Expression};

// ── Type constants ────────────────────────────────────────────────────────────

pub const TYPE_SILICON_BIT: &str = "ubl/silicon.bit";
pub const TYPE_SILICON_CIRCUIT: &str = "ubl/silicon.circuit";
pub const TYPE_SILICON_CHIP: &str = "ubl/silicon.chip";
pub const TYPE_SILICON_COMPILE: &str = "ubl/silicon.compile";

pub const SILICON_TYPES: &[&str] = &[
    TYPE_SILICON_BIT,
    TYPE_SILICON_CIRCUIT,
    TYPE_SILICON_CHIP,
    TYPE_SILICON_COMPILE,
];

/// True iff the given `@type` is a silicon chip family type.
pub fn is_silicon_type(chip_type: &str) -> bool {
    SILICON_TYPES.contains(&chip_type)
}

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum SiliconError {
    #[error("missing field: {0}")]
    MissingField(String),
    #[error("invalid field: {0}")]
    InvalidField(String),
    #[error("bit CID not found: {0}")]
    BitNotFound(String),
    #[error("bit CID has wrong type (expected ubl/silicon.bit): {0}")]
    BitTypeMismatch(String),
    #[error("circuit CID not found: {0}")]
    CircuitNotFound(String),
    #[error("circuit CID has wrong type (expected ubl/silicon.circuit): {0}")]
    CircuitTypeMismatch(String),
    #[error("chip CID not found: {0}")]
    ChipNotFound(String),
    #[error("chip CID has wrong type (expected ubl/silicon.chip): {0}")]
    ChipTypeMismatch(String),
    #[error("unsupported compile target: {0}")]
    UnsupportedTarget(String),
    #[error("compile error: {0}")]
    CompileError(String),
    #[error("chipstore required for silicon validation")]
    ChipStoreRequired,
    #[error("chipstore error: {0}")]
    ChipStore(String),
    #[error("cyclic chip graph detected at CID: {0}")]
    CyclicChipGraph(String),
}

impl From<ubl_chipstore::ChipStoreError> for SiliconError {
    fn from(e: ubl_chipstore::ChipStoreError) -> Self {
        SiliconError::ChipStore(e.to_string())
    }
}

// ── Condition spec (JSON-serializable Expression) ─────────────────────────────

/// JSON-serializable form of `reasoning_bit::Expression`.
/// Maps 1:1 to the existing Expression enum — bidirectional conversion.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ConditionSpec {
    Always { value: bool },
    ContextHas { key: String },
    ContextEquals { key: String, value: Value },
    BodySizeLte { limit: usize },
    TypeEquals { chip_type: String },
    And { conditions: Vec<ConditionSpec> },
    Or { conditions: Vec<ConditionSpec> },
    Not { condition: Box<ConditionSpec> },
}

impl ConditionSpec {
    /// Convert to the runtime `Expression` used by `ReasoningBit::evaluate`.
    pub fn to_expression(&self) -> Expression {
        match self {
            ConditionSpec::Always { value } => Expression::Always(*value),
            ConditionSpec::ContextHas { key } => Expression::ContextHas(key.clone()),
            ConditionSpec::ContextEquals { key, value } => {
                Expression::ContextEquals(key.clone(), value.clone())
            }
            ConditionSpec::BodySizeLte { limit } => Expression::BodySizeLte(*limit),
            ConditionSpec::TypeEquals { chip_type } => Expression::TypeEquals(chip_type.clone()),
            ConditionSpec::And { conditions } => {
                Expression::And(conditions.iter().map(|c| c.to_expression()).collect())
            }
            ConditionSpec::Or { conditions } => {
                Expression::Or(conditions.iter().map(|c| c.to_expression()).collect())
            }
            ConditionSpec::Not { condition } => {
                Expression::Not(Box::new(condition.to_expression()))
            }
        }
    }

    /// Parse from a JSON value. Accepts both the tagged `{"op":"always","value":true}` form
    /// and the legacy compact form used in tests (`{"Always": true}`).
    pub fn from_value(v: &Value) -> Result<Self, SiliconError> {
        // Try tagged form first (op field present)
        if let Some(op) = v.get("op").and_then(Value::as_str) {
            return Self::parse_tagged(op, v);
        }
        // Try legacy compact form: {"Always": true}, {"ContextEquals": ["key", val]}, etc.
        if let Some(obj) = v.as_object() {
            if let Some(val) = obj.get("Always") {
                let b = val.as_bool().ok_or_else(|| {
                    SiliconError::InvalidField("Always value must be bool".to_string())
                })?;
                return Ok(ConditionSpec::Always { value: b });
            }
            if let Some(key) = obj.get("ContextHas").and_then(Value::as_str) {
                return Ok(ConditionSpec::ContextHas {
                    key: key.to_string(),
                });
            }
            if let Some(arr) = obj.get("ContextEquals").and_then(Value::as_array) {
                if arr.len() != 2 {
                    return Err(SiliconError::InvalidField(
                        "ContextEquals must be [key, value]".to_string(),
                    ));
                }
                let key = arr[0].as_str().ok_or_else(|| {
                    SiliconError::InvalidField("ContextEquals key must be string".to_string())
                })?;
                return Ok(ConditionSpec::ContextEquals {
                    key: key.to_string(),
                    value: arr[1].clone(),
                });
            }
            if let Some(n) = obj.get("BodySizeLte").and_then(Value::as_u64) {
                return Ok(ConditionSpec::BodySizeLte { limit: n as usize });
            }
            if let Some(t) = obj.get("TypeEquals").and_then(Value::as_str) {
                return Ok(ConditionSpec::TypeEquals {
                    chip_type: t.to_string(),
                });
            }
            if let Some(conditions) = obj.get("And").and_then(Value::as_array) {
                let parsed: Result<Vec<_>, _> =
                    conditions.iter().map(ConditionSpec::from_value).collect();
                return Ok(ConditionSpec::And { conditions: parsed? });
            }
            if let Some(conditions) = obj.get("Or").and_then(Value::as_array) {
                let parsed: Result<Vec<_>, _> =
                    conditions.iter().map(ConditionSpec::from_value).collect();
                return Ok(ConditionSpec::Or { conditions: parsed? });
            }
            if let Some(inner) = obj.get("Not") {
                return Ok(ConditionSpec::Not {
                    condition: Box::new(ConditionSpec::from_value(inner)?),
                });
            }
        }
        Err(SiliconError::InvalidField(
            "condition must have 'op' field or be a legacy compact object".to_string(),
        ))
    }

    fn parse_tagged(op: &str, v: &Value) -> Result<Self, SiliconError> {
        match op {
            "always" => {
                let value = v
                    .get("value")
                    .and_then(Value::as_bool)
                    .ok_or_else(|| SiliconError::MissingField("condition.value".to_string()))?;
                Ok(ConditionSpec::Always { value })
            }
            "context_has" => {
                let key = v
                    .get("key")
                    .and_then(Value::as_str)
                    .ok_or_else(|| SiliconError::MissingField("condition.key".to_string()))?
                    .to_string();
                Ok(ConditionSpec::ContextHas { key })
            }
            "context_equals" => {
                let key = v
                    .get("key")
                    .and_then(Value::as_str)
                    .ok_or_else(|| SiliconError::MissingField("condition.key".to_string()))?
                    .to_string();
                let value = v
                    .get("value")
                    .cloned()
                    .ok_or_else(|| SiliconError::MissingField("condition.value".to_string()))?;
                Ok(ConditionSpec::ContextEquals { key, value })
            }
            "body_size_lte" => {
                let limit = v
                    .get("limit")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| SiliconError::MissingField("condition.limit".to_string()))?
                    as usize;
                Ok(ConditionSpec::BodySizeLte { limit })
            }
            "type_equals" => {
                let chip_type = v
                    .get("chip_type")
                    .and_then(Value::as_str)
                    .ok_or_else(|| SiliconError::MissingField("condition.chip_type".to_string()))?
                    .to_string();
                Ok(ConditionSpec::TypeEquals { chip_type })
            }
            "and" => {
                let conditions = v
                    .get("conditions")
                    .and_then(Value::as_array)
                    .ok_or_else(|| SiliconError::MissingField("condition.conditions".to_string()))?;
                let parsed: Result<Vec<_>, _> =
                    conditions.iter().map(ConditionSpec::from_value).collect();
                Ok(ConditionSpec::And { conditions: parsed? })
            }
            "or" => {
                let conditions = v
                    .get("conditions")
                    .and_then(Value::as_array)
                    .ok_or_else(|| SiliconError::MissingField("condition.conditions".to_string()))?;
                let parsed: Result<Vec<_>, _> =
                    conditions.iter().map(ConditionSpec::from_value).collect();
                Ok(ConditionSpec::Or { conditions: parsed? })
            }
            "not" => {
                let inner = v
                    .get("condition")
                    .ok_or_else(|| SiliconError::MissingField("condition.condition".to_string()))?;
                Ok(ConditionSpec::Not {
                    condition: Box::new(ConditionSpec::from_value(inner)?),
                })
            }
            other => Err(SiliconError::InvalidField(format!(
                "unknown condition op: {}",
                other
            ))),
        }
    }
}

// ── SiliconBitBody ────────────────────────────────────────────────────────────

/// Body of a `ubl/silicon.bit` chip — the semantic transistor.
///
/// ```json
/// {
///   "id": "P_IsAdmin",
///   "name": "Is Admin Role",
///   "condition": {"op": "context_equals", "key": "body.role", "value": "admin"},
///   "on_true": "allow",
///   "on_false": "deny",
///   "requires_context": ["body.role"]
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiliconBitBody {
    pub id: String,
    pub name: String,
    pub condition: ConditionSpec,
    pub on_true: Decision,
    pub on_false: Decision,
    pub requires_context: Vec<String>,
}

// ── SiliconCircuitBody ────────────────────────────────────────────────────────

/// Body of a `ubl/silicon.circuit` chip — wired graph of bit CIDs.
///
/// ```json
/// {
///   "id": "C_PaymentAuth",
///   "name": "Payment Authorization",
///   "bits": ["b3:<cid-of-P_IsAdmin>", "b3:<cid-of-P_HasBalance>"],
///   "composition": "Sequential",
///   "aggregator": "All"
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiliconCircuitBody {
    pub id: String,
    pub name: String,
    /// CIDs of `ubl/silicon.bit` chips.
    pub bits: Vec<String>,
    pub composition: String,
    pub aggregator: String,
}

impl SiliconCircuitBody {
    pub fn composition_mode(&self) -> Result<CompositionMode, SiliconError> {
        match self.composition.to_lowercase().as_str() {
            "sequential" => Ok(CompositionMode::Sequential),
            "parallel" => Ok(CompositionMode::Parallel),
            other => Err(SiliconError::InvalidField(format!(
                "composition must be Sequential|Parallel, got '{}'",
                other
            ))),
        }
    }

    pub fn aggregation_mode(&self) -> Result<AggregationMode, SiliconError> {
        match self.aggregator.to_lowercase().as_str() {
            "all" => Ok(AggregationMode::All),
            "any" => Ok(AggregationMode::Any),
            "majority" => Ok(AggregationMode::Majority),
            "first_decisive" | "firstdecisive" => Ok(AggregationMode::FirstDecisive),
            other => {
                // K-of-N: "k_of_n:3:5" or "3of5"
                if let Some(rest) = other.strip_prefix("k_of_n:") {
                    let parts: Vec<&str> = rest.split(':').collect();
                    if parts.len() == 2 {
                        if let (Ok(k), Ok(n)) = (parts[0].parse(), parts[1].parse()) {
                            return Ok(AggregationMode::KofN { k, n });
                        }
                    }
                }
                Err(SiliconError::InvalidField(format!(
                    "aggregator must be All|Any|Majority|FirstDecisive|k_of_n:K:N, got '{}'",
                    other
                )))
            }
        }
    }
}

// ── HalProfile ────────────────────────────────────────────────────────────────

/// Hardware Abstraction Layer profile — declares execution targets and unit system.
/// Mirrors the `hal` block from the LogLine silicon-to-user canon pack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HalProfile {
    /// e.g. "HAL/v0/cpu" | "HAL/v0/cpu-gpu"
    pub profile: String,
    /// Execution backends: ["rb_vm/v1", "wasm32", "verilog@*"]
    pub targets: Vec<String>,
    pub deterministic: bool,
    pub timebase_ns: Option<u64>,
    pub energy_unit: Option<String>,
    pub cost_unit: Option<String>,
}

impl HalProfile {
    pub fn from_value(v: &Value) -> Result<Self, SiliconError> {
        let profile = v
            .get("profile")
            .and_then(Value::as_str)
            .ok_or_else(|| SiliconError::MissingField("hal.profile".to_string()))?
            .to_string();
        let targets = v
            .get("targets")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(Value::as_str)
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default();
        let deterministic = v
            .get("deterministic")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        let timebase_ns = v.get("timebase_ns").and_then(Value::as_u64);
        let energy_unit = v
            .get("energy_unit")
            .and_then(Value::as_str)
            .map(String::from);
        let cost_unit = v
            .get("cost_unit")
            .and_then(Value::as_str)
            .map(String::from);
        Ok(HalProfile {
            profile,
            targets,
            deterministic,
            timebase_ns,
            energy_unit,
            cost_unit,
        })
    }
}

// ── SiliconChipBody ───────────────────────────────────────────────────────────

/// Body of a `ubl/silicon.chip` chip — the full ~50KB TDLN-Chip.
///
/// ```json
/// {
///   "id": "CHIP_PaymentProcessor",
///   "name": "Payment Processor v1",
///   "circuits": ["b3:<cid-of-C_PaymentAuth>"],
///   "hal": {"profile": "HAL/v0/cpu", "targets": ["rb_vm/v1"], "deterministic": true},
///   "version": "1.0"
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiliconChipBody {
    pub id: String,
    pub name: String,
    /// CIDs of `ubl/silicon.circuit` chips.
    pub circuits: Vec<String>,
    pub hal: HalProfile,
    pub version: String,
}

// ── CompileTarget ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompileTarget {
    /// rb_vm TLV bytecode (the only supported target in Phase 1).
    RbVm,
}

impl CompileTarget {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_lowercase().as_str() {
            "rb_vm" | "rb_vm/v1" | "rbvm" => Some(Self::RbVm),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RbVm => "rb_vm/v1",
        }
    }
}

// ── SiliconCompileBody ────────────────────────────────────────────────────────

/// Body of a `ubl/silicon.compile` chip — compilation request.
///
/// ```json
/// {
///   "chip_cid": "b3:<cid-of-CHIP_PaymentProcessor>",
///   "target": "rb_vm"
/// }
/// ```
#[derive(Debug, Clone)]
pub struct SiliconCompileBody {
    pub chip_cid: String,
    pub target: CompileTarget,
}

// ── SiliconRequest (parsed union) ─────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum SiliconRequest {
    Bit(SiliconBitBody),
    Circuit(SiliconCircuitBody),
    Chip(SiliconChipBody),
    Compile(SiliconCompileBody),
}

// ── Parsing ───────────────────────────────────────────────────────────────────

/// Parse the body JSON into a typed `SiliconRequest` without touching the ChipStore.
pub fn parse_silicon(chip_type: &str, body: &Value) -> Result<SiliconRequest, SiliconError> {
    match chip_type {
        TYPE_SILICON_BIT => Ok(SiliconRequest::Bit(parse_bit(body)?)),
        TYPE_SILICON_CIRCUIT => Ok(SiliconRequest::Circuit(parse_circuit(body)?)),
        TYPE_SILICON_CHIP => Ok(SiliconRequest::Chip(parse_chip(body)?)),
        TYPE_SILICON_COMPILE => Ok(SiliconRequest::Compile(parse_compile(body)?)),
        other => Err(SiliconError::InvalidField(format!(
            "not a silicon chip type: {}",
            other
        ))),
    }
}

fn parse_bit(body: &Value) -> Result<SiliconBitBody, SiliconError> {
    let id = req_str(body, "id")?;
    let name = req_str(body, "name")?;
    let condition_val = body
        .get("condition")
        .ok_or_else(|| SiliconError::MissingField("condition".to_string()))?;
    let condition = ConditionSpec::from_value(condition_val)?;
    let on_true = parse_decision(body, "on_true")?;
    let on_false = parse_decision(body, "on_false")?;
    let requires_context = body
        .get("requires_context")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(String::from)
                .collect()
        })
        .unwrap_or_default();
    Ok(SiliconBitBody {
        id,
        name,
        condition,
        on_true,
        on_false,
        requires_context,
    })
}

fn parse_circuit(body: &Value) -> Result<SiliconCircuitBody, SiliconError> {
    let id = req_str(body, "id")?;
    let name = req_str(body, "name")?;
    let bits = body
        .get("bits")
        .and_then(Value::as_array)
        .ok_or_else(|| SiliconError::MissingField("bits".to_string()))?
        .iter()
        .enumerate()
        .map(|(i, v)| {
            v.as_str()
                .ok_or_else(|| SiliconError::InvalidField(format!("bits[{}] must be string", i)))
                .map(String::from)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if bits.is_empty() {
        return Err(SiliconError::InvalidField(
            "bits cannot be empty".to_string(),
        ));
    }
    for (i, cid) in bits.iter().enumerate() {
        if !cid.starts_with("b3:") {
            return Err(SiliconError::InvalidField(format!(
                "bits[{}] must be a CID (b3:...)",
                i
            )));
        }
    }
    let composition = req_str(body, "composition")?;
    let aggregator = req_str(body, "aggregator")?;

    // Validate composition/aggregation modes are known
    let circuit = SiliconCircuitBody {
        id,
        name,
        bits,
        composition,
        aggregator,
    };
    circuit.composition_mode()?;
    circuit.aggregation_mode()?;
    Ok(circuit)
}

fn parse_chip(body: &Value) -> Result<SiliconChipBody, SiliconError> {
    let id = req_str(body, "id")?;
    let name = req_str(body, "name")?;
    let circuits = body
        .get("circuits")
        .and_then(Value::as_array)
        .ok_or_else(|| SiliconError::MissingField("circuits".to_string()))?
        .iter()
        .enumerate()
        .map(|(i, v)| {
            v.as_str()
                .ok_or_else(|| {
                    SiliconError::InvalidField(format!("circuits[{}] must be string", i))
                })
                .map(String::from)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if circuits.is_empty() {
        return Err(SiliconError::InvalidField(
            "circuits cannot be empty".to_string(),
        ));
    }
    for (i, cid) in circuits.iter().enumerate() {
        if !cid.starts_with("b3:") {
            return Err(SiliconError::InvalidField(format!(
                "circuits[{}] must be a CID (b3:...)",
                i
            )));
        }
    }
    let hal = body
        .get("hal")
        .ok_or_else(|| SiliconError::MissingField("hal".to_string()))?;
    let hal = HalProfile::from_value(hal)?;
    let version = body
        .get("version")
        .and_then(Value::as_str)
        .unwrap_or("1.0")
        .to_string();
    Ok(SiliconChipBody {
        id,
        name,
        circuits,
        hal,
        version,
    })
}

fn parse_compile(body: &Value) -> Result<SiliconCompileBody, SiliconError> {
    let chip_cid = req_str(body, "chip_cid")?;
    if !chip_cid.starts_with("b3:") {
        return Err(SiliconError::InvalidField(
            "chip_cid must be a CID (b3:...)".to_string(),
        ));
    }
    let target_str = body
        .get("target")
        .and_then(Value::as_str)
        .unwrap_or("rb_vm");
    let target = CompileTarget::parse(target_str)
        .ok_or_else(|| SiliconError::UnsupportedTarget(target_str.to_string()))?;
    Ok(SiliconCompileBody { chip_cid, target })
}

// ── CHECK validation ──────────────────────────────────────────────────────────

/// Validate a silicon chip at the CHECK stage. For circuit/chip/compile types,
/// verifies that all referenced CIDs exist in the ChipStore with the correct type.
pub async fn validate_for_check(
    chip_type: &str,
    body: &Value,
    chip_store: Option<&ChipStore>,
) -> Result<SiliconRequest, SiliconError> {
    let parsed = parse_silicon(chip_type, body)?;

    match &parsed {
        SiliconRequest::Bit(_) => {
            // Structural validation only — no cross-references to verify.
        }
        SiliconRequest::Circuit(circuit) => {
            let store = chip_store.ok_or(SiliconError::ChipStoreRequired)?;
            for cid in &circuit.bits {
                // bits[] may reference ubl/silicon.bit OR ubl/silicon.chip (recursive DAG).
                let found_type = verify_chip_type(store, cid, TYPE_SILICON_BIT, |c| {
                    SiliconError::BitNotFound(c.to_string())
                })
                .await
                .map_err(|_| SiliconError::BitNotFound(cid.clone()))?;
                if found_type != TYPE_SILICON_BIT && found_type != TYPE_SILICON_CHIP {
                    return Err(SiliconError::InvalidField(format!(
                        "circuit bits[{}] must be ubl/silicon.bit or ubl/silicon.chip, got '{}'",
                        cid, found_type
                    )));
                }
            }
        }
        SiliconRequest::Chip(chip) => {
            let store = chip_store.ok_or(SiliconError::ChipStoreRequired)?;
            for cid in &chip.circuits {
                verify_chip_type(store, cid, TYPE_SILICON_CIRCUIT, |c| {
                    SiliconError::CircuitNotFound(c.to_string())
                })
                .await
                .map_err(|_| SiliconError::CircuitNotFound(cid.clone()))
                .and_then(|found_type| {
                    if found_type != TYPE_SILICON_CIRCUIT {
                        Err(SiliconError::CircuitTypeMismatch(cid.clone()))
                    } else {
                        Ok(())
                    }
                })?;
            }
        }
        SiliconRequest::Compile(compile) => {
            let store = chip_store.ok_or(SiliconError::ChipStoreRequired)?;
            verify_chip_type(store, &compile.chip_cid, TYPE_SILICON_CHIP, |c| {
                SiliconError::ChipNotFound(c.to_string())
            })
            .await
            .map_err(|_| SiliconError::ChipNotFound(compile.chip_cid.clone()))
            .and_then(|found_type| {
                if found_type != TYPE_SILICON_CHIP {
                    Err(SiliconError::ChipTypeMismatch(compile.chip_cid.clone()))
                } else {
                    Ok(())
                }
            })?;
        }
    }

    Ok(parsed)
}

/// Look up a chip by CID and return its `@type`. Returns `Err` if not found.
async fn verify_chip_type(
    store: &ChipStore,
    cid: &str,
    _expected_type: &str,
    not_found: impl Fn(&str) -> SiliconError,
) -> Result<String, SiliconError> {
    let stored = store
        .get_chip(cid)
        .await
        .map_err(SiliconError::from)?
        .ok_or_else(|| not_found(cid))?;
    Ok(stored.chip_type)
}

// ── Compiler ──────────────────────────────────────────────────────────────────

/// A resolved bit loaded from ChipStore for compilation.
#[derive(Debug, Clone)]
pub struct ResolvedBit {
    pub cid: String,
    pub body: SiliconBitBody,
}

/// A node within a resolved circuit — either a leaf bit or an inlined sub-chip.
///
/// `SubChip` carries the fully-resolved circuit graph of the referenced chip.
/// During compilation the sub-chip's conditions are inlined into the parent's
/// bytecode stream (the outermost `PushInput + EmitRc` terminator is only
/// emitted once, at the top of the outermost chip).
#[derive(Debug, Clone)]
pub enum ResolvedNode {
    Bit(ResolvedBit),
    SubChip(Vec<ResolvedCircuit>),
}

/// A resolved circuit loaded from ChipStore for compilation.
#[derive(Debug, Clone)]
pub struct ResolvedCircuit {
    pub cid: String,
    pub body: SiliconCircuitBody,
    /// Ordered list of nodes (bits or inlined sub-chips).
    pub nodes: Vec<ResolvedNode>,
}

/// Load all circuits and their bits from the ChipStore, ready for compilation.
///
/// Supports recursive chip references: a circuit's `bits` array may contain
/// CIDs of `ubl/silicon.bit` OR `ubl/silicon.chip`.  Sub-chip graphs are
/// resolved recursively.  Cycle detection is enforced via the `visiting` set —
/// any chip CID that appears while it is still being resolved returns
/// `SiliconError::CyclicChipGraph`.
pub async fn resolve_chip_graph(
    chip: &SiliconChipBody,
    store: &ChipStore,
) -> Result<Vec<ResolvedCircuit>, SiliconError> {
    let mut visiting = std::collections::HashSet::new();
    resolve_chip_graph_inner(chip, store, &mut visiting).await
}

fn resolve_chip_graph_inner<'a>(
    chip: &'a SiliconChipBody,
    store: &'a ChipStore,
    visiting: &'a mut std::collections::HashSet<String>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<ResolvedCircuit>, SiliconError>> + Send + 'a>> {
    Box::pin(async move {
    let mut resolved_circuits = Vec::new();
    for circuit_cid in &chip.circuits {
        let circuit_stored = store
            .get_chip(circuit_cid)
            .await
            .map_err(SiliconError::from)?
            .ok_or_else(|| SiliconError::CircuitNotFound(circuit_cid.clone()))?;
        let circuit_body = parse_circuit(&circuit_stored.chip_data)?;

        let mut nodes = Vec::new();
        for entry_cid in &circuit_body.bits {
            let entry_stored = store
                .get_chip(entry_cid)
                .await
                .map_err(SiliconError::from)?
                .ok_or_else(|| SiliconError::BitNotFound(entry_cid.clone()))?;

            match entry_stored.chip_type.as_str() {
                TYPE_SILICON_BIT => {
                    let bit_body = parse_bit(&entry_stored.chip_data)?;
                    nodes.push(ResolvedNode::Bit(ResolvedBit {
                        cid: entry_cid.clone(),
                        body: bit_body,
                    }));
                }
                TYPE_SILICON_CHIP => {
                    // Recursive chip reference — resolve its graph, inlining it.
                    if !visiting.insert(entry_cid.clone()) {
                        return Err(SiliconError::CyclicChipGraph(entry_cid.clone()));
                    }
                    let sub_chip_body =
                        match parse_silicon(TYPE_SILICON_CHIP, &entry_stored.chip_data)? {
                            SiliconRequest::Chip(c) => c,
                            _ => return Err(SiliconError::ChipTypeMismatch(entry_cid.clone())),
                        };
                    let sub_circuits =
                        resolve_chip_graph_inner(&sub_chip_body, store, visiting).await?;
                    visiting.remove(entry_cid);
                    nodes.push(ResolvedNode::SubChip(sub_circuits));
                }
                other => {
                    return Err(SiliconError::InvalidField(format!(
                        "circuit bits[{}] has unsupported type '{}'; expected bit or chip",
                        entry_cid, other
                    )));
                }
            }
        }

        resolved_circuits.push(ResolvedCircuit {
            cid: circuit_cid.clone(),
            body: circuit_body,
            nodes,
        });
    }
    Ok(resolved_circuits)
    }) // end Box::pin
}

/// Compile a silicon chip graph to rb_vm TLV bytecode.
///
/// Phase 1 scope (linear execution only, no JMP):
///   - Always(true)               → ConstI64(1) + AssertTrue
///   - Always(false)              → ConstI64(0) + AssertTrue  (always DENYs)
///   - BodySizeLte(n)             → ConstI64(n) size-comparison sequence
///   - And(exprs)                 → each sub-expression compiled sequentially
///   - Sequential/All circuits    → all bits chained, all must pass
///   - Closes with EmitRc
///
/// Or / Any / Parallel / KofN → returns CompileError (Phase 2, requires JMP).
/// Compile a silicon chip graph to rb_vm TLV bytecode.
///
/// Phase 2 supports all composition modes:
///   Sequential/All  — each bit inline-asserts (short-circuit on DENY)
///   Sequential/Any  — bits compiled to Bool, folded with BoolOr, then AssertTrue
///   Sequential/Majority — bits to I64 (BoolToI64), summed, compared to majority
///   Sequential/KofN — bits to I64, summed, compared to k
///   Sequential/FirstDecisive — alias for Any (first non-Allow outcome wins)
///   Parallel/All    — all bits to Bool, folded with BoolAnd, AssertTrue
///   Parallel/Any    — all bits to Bool, folded with BoolOr, AssertTrue
///   Parallel/Majority / KofN — same as Sequential counterparts
///
/// Conditions compiled to real opcodes (no more pass-through stubs):
///   ContextEquals, TypeEquals → JsonGetKeyBytes + EqBytes
///   ContextHas                → JsonHasKey
///   BodySizeLte               → PushBodySize + ConstI64 + CmpI64(LE)
///   Or / Not / And (nested)   → BoolOr / BoolNot / BoolAnd on Bool stack
pub fn compile_chip_to_rb_vm(circuits: &[ResolvedCircuit]) -> Result<Vec<u8>, SiliconError> {
    let mut code: Vec<u8> = Vec::new();
    compile_circuits_inner(circuits, &mut code)?;
    // Terminate: PushInput(0) + EmitRc (outermost level only).
    code.extend(tlv_instr(0x12, &0u16.to_be_bytes())); // PushInput(0)
    code.extend(tlv_instr(0x10, &[])); // EmitRc
    Ok(code)
}

/// Compile circuits into `code` without appending the final `PushInput + EmitRc`.
/// Called recursively for inlined sub-chips (SubChip nodes).
fn compile_circuits_inner(
    circuits: &[ResolvedCircuit],
    code: &mut Vec<u8>,
) -> Result<(), SiliconError> {
    for resolved_circuit in circuits {
        let composition = resolved_circuit.body.composition_mode()?;
        let aggregation = resolved_circuit.body.aggregation_mode()?;

        // Flatten nodes to bits: SubChip nodes are compiled inline (their
        // conditions are emitted into the current stream; the parent circuit's
        // aggregation wraps them like any other bit).
        let bits = collect_bits(&resolved_circuit.nodes, code, composition.clone(), aggregation.clone())?;

        // `collect_bits` for SubChip nodes with non-All/non-Sequential modes
        // already emits a single Bool onto the stack representing the sub-chip.
        // For pure-bit circuits, `bits` contains the flat list.
        // If collect_bits handled everything (returned None), skip aggregation here.
        if let Some(bits) = bits {
            if bits.is_empty() {
                return Err(SiliconError::CompileError(
                    "circuit has no bits".to_string(),
                ));
            }

            match (composition, aggregation) {
                (CompositionMode::Sequential, AggregationMode::All)
                | (CompositionMode::Sequential, AggregationMode::FirstDecisive) => {
                    for bit in &bits {
                        code.extend(compile_condition(&bit.body.condition, &bit.body.on_false)?);
                    }
                }

                (_, AggregationMode::Any) => {
                    for bit in &bits {
                        code.extend(compile_to_bool(&bit.body.condition)?);
                    }
                    for _ in 0..bits.len().saturating_sub(1) {
                        code.extend(tlv_instr(0x28, &[])); // BoolOr
                    }
                    code.extend(tlv_instr(0x09, &[])); // AssertTrue
                }

                (_, AggregationMode::Majority) => {
                    let n = bits.len();
                    let threshold = (n / 2) as i64;
                    for bit in &bits {
                        code.extend(compile_to_bool(&bit.body.condition)?);
                        code.extend(tlv_instr(0x2A, &[])); // BoolToI64
                    }
                    for _ in 0..n.saturating_sub(1) {
                        code.extend(tlv_instr(0x05, &[])); // AddI64
                    }
                    code.extend(tlv_instr(0x01, &(threshold + 1).to_be_bytes())); // ConstI64(n/2+1)
                    code.extend(tlv_instr(0x08, &[5u8])); // CmpI64(GE)
                    code.extend(tlv_instr(0x09, &[])); // AssertTrue
                }

                (_, AggregationMode::KofN { k, .. }) => {
                    let n = bits.len();
                    let k_val = k as i64;
                    for bit in &bits {
                        code.extend(compile_to_bool(&bit.body.condition)?);
                        code.extend(tlv_instr(0x2A, &[])); // BoolToI64
                    }
                    for _ in 0..n.saturating_sub(1) {
                        code.extend(tlv_instr(0x05, &[])); // AddI64
                    }
                    code.extend(tlv_instr(0x01, &k_val.to_be_bytes())); // ConstI64(k)
                    code.extend(tlv_instr(0x08, &[5u8])); // CmpI64(GE)
                    code.extend(tlv_instr(0x09, &[])); // AssertTrue
                }

                (CompositionMode::Parallel, AggregationMode::All)
                | (CompositionMode::Parallel, AggregationMode::FirstDecisive) => {
                    for bit in &bits {
                        code.extend(compile_to_bool(&bit.body.condition)?);
                    }
                    for _ in 0..bits.len().saturating_sub(1) {
                        code.extend(tlv_instr(0x29, &[])); // BoolAnd
                    }
                    code.extend(tlv_instr(0x09, &[])); // AssertTrue
                }

                (CompositionMode::Conditional(_), AggregationMode::All)
                | (CompositionMode::Conditional(_), AggregationMode::FirstDecisive) => {
                    for bit in &bits {
                        code.extend(compile_condition(&bit.body.condition, &bit.body.on_false)?);
                    }
                }
            }
        }
    }
    Ok(())
}

/// Collect leaf bits from a node list.
///
/// For circuits that contain only `Bit` nodes this returns the flat list and
/// the caller does the aggregation.
///
/// For `SubChip` nodes the sub-chip's circuits are compiled inline: the result
/// on the stack is a single Bool (the sub-chip pass/fail).  When all nodes are
/// SubChips — or a mix — we compile each into a Bool and fold with the
/// circuit's aggregation, returning `None` to signal that aggregation was
/// already emitted.
///
/// Simple case (all Bit): returns `Some(bits)`.
/// Mixed / SubChip case: emits code directly, returns `None`.
fn collect_bits<'a>(
    nodes: &'a [ResolvedNode],
    code: &mut Vec<u8>,
    composition: CompositionMode,
    aggregation: AggregationMode,
) -> Result<Option<Vec<&'a ResolvedBit>>, SiliconError> {
    // Fast path: all Bit nodes — no recursion needed.
    if nodes.iter().all(|n| matches!(n, ResolvedNode::Bit(_))) {
        let bits = nodes
            .iter()
            .filter_map(|n| if let ResolvedNode::Bit(b) = n { Some(b) } else { None })
            .collect();
        return Ok(Some(bits));
    }

    // Mixed / SubChip path: compile each node to a Bool, fold with aggregation.
    if nodes.is_empty() {
        return Err(SiliconError::CompileError(
            "circuit has no nodes".to_string(),
        ));
    }

    let n = nodes.len();
    for node in nodes {
        match node {
            ResolvedNode::Bit(bit) => {
                code.extend(compile_to_bool(&bit.body.condition)?);
            }
            ResolvedNode::SubChip(sub_circuits) => {
                // Compile sub-chip inline — it pushes a Bool result.
                // We wrap its Sequential/All stream in a BoolAnd fold:
                // the sub-chip either passes (all AssertTrue survive) or
                // we treat it as a single Bool by compiling via inner helper
                // and catching deny via a dedicated sub-compile path.
                //
                // Simplest correct model: compile sub-chip to bytecode,
                // then inline it as a Bool via a fresh buffer and note that
                // sub-chip compilation ends with PushInput+EmitRc which we
                // strip, then evaluate all bits as Bools and fold.
                compile_subchip_as_bool(sub_circuits, code)?;
            }
        }
    }

    // Fold n Bools → 1 Bool → AssertTrue according to aggregation.
    match aggregation {
        AggregationMode::All | AggregationMode::FirstDecisive => {
            for _ in 0..n.saturating_sub(1) {
                code.extend(tlv_instr(0x29, &[])); // BoolAnd
            }
            code.extend(tlv_instr(0x09, &[])); // AssertTrue
        }
        AggregationMode::Any => {
            for _ in 0..n.saturating_sub(1) {
                code.extend(tlv_instr(0x28, &[])); // BoolOr
            }
            code.extend(tlv_instr(0x09, &[])); // AssertTrue
        }
        AggregationMode::Majority => {
            for i in 0..n {
                code.extend(tlv_instr(0x2A, &[])); // BoolToI64
                if i > 0 {
                    code.extend(tlv_instr(0x05, &[])); // AddI64
                }
            }
            let threshold = ((n / 2) + 1) as i64;
            code.extend(tlv_instr(0x01, &threshold.to_be_bytes())); // ConstI64
            code.extend(tlv_instr(0x08, &[5u8])); // CmpI64(GE)
            code.extend(tlv_instr(0x09, &[])); // AssertTrue
        }
        AggregationMode::KofN { k, .. } => {
            for i in 0..n {
                code.extend(tlv_instr(0x2A, &[])); // BoolToI64
                if i > 0 {
                    code.extend(tlv_instr(0x05, &[])); // AddI64
                }
            }
            let k_val = k as i64;
            code.extend(tlv_instr(0x01, &k_val.to_be_bytes())); // ConstI64(k)
            code.extend(tlv_instr(0x08, &[5u8])); // CmpI64(GE)
            code.extend(tlv_instr(0x09, &[])); // AssertTrue
        }
    }

    // Signal: aggregation was emitted inline; caller skips its own aggregation.
    let _ = composition; // composition is honoured implicitly by the fold above
    Ok(None)
}

/// Compile a sub-chip's circuits as a single Bool pushed onto the stack.
///
/// Strategy: compile every bit across all sub-circuits as Bools, fold them
/// with BoolAnd (sub-chip passes only if ALL its conditions pass), leave the
/// final Bool on the stack for the parent circuit's aggregation.
fn compile_subchip_as_bool(
    sub_circuits: &[ResolvedCircuit],
    code: &mut Vec<u8>,
) -> Result<(), SiliconError> {
    // Collect all leaf bits from the sub-chip (recursively for nested sub-chips).
    let mut all_bools: Vec<u8> = Vec::new();
    let mut bool_count: usize = 0;

    for sub_circuit in sub_circuits {
        for node in &sub_circuit.nodes {
            let mut node_code = Vec::new();
            emit_node_as_bool(node, &mut node_code, &mut bool_count)?;
            all_bools.extend(node_code);
        }
    }

    if bool_count == 0 {
        // Empty sub-chip — treat as always-true (pass-through).
        all_bools.extend(tlv_instr(0x26, &[1u8])); // PushBool(true)
        bool_count = 1;
    }

    code.extend(all_bools);

    // Fold bool_count Bools → 1 Bool via BoolAnd (sub-chip = All of its bits).
    for _ in 0..bool_count.saturating_sub(1) {
        code.extend(tlv_instr(0x29, &[])); // BoolAnd
    }

    Ok(())
}

/// Emit a single `ResolvedNode` as a Bool onto the stack, incrementing `count`.
fn emit_node_as_bool(
    node: &ResolvedNode,
    code: &mut Vec<u8>,
    count: &mut usize,
) -> Result<(), SiliconError> {
    match node {
        ResolvedNode::Bit(bit) => {
            code.extend(compile_to_bool(&bit.body.condition)?);
            *count += 1;
        }
        ResolvedNode::SubChip(sub_circuits) => {
            let mut inner: Vec<u8> = Vec::new();
            let mut inner_count: usize = 0;
            for sub_circuit in sub_circuits {
                for inner_node in &sub_circuit.nodes {
                    emit_node_as_bool(inner_node, &mut inner, &mut inner_count)?;
                }
            }
            if inner_count == 0 {
                inner.extend(tlv_instr(0x26, &[1u8])); // PushBool(true)
                inner_count = 1;
            }
            code.extend(inner);
            for _ in 0..inner_count.saturating_sub(1) {
                code.extend(tlv_instr(0x29, &[])); // BoolAnd
            }
            *count += 1;
        }
    }
    Ok(())
}

// ── gate_compile ──────────────────────────────────────────────────────────────

/// Load a `ubl/silicon.chip` from ChipStore and compile it to rb_vm TLV bytecode.
///
/// Used by the `@silicon_gate` live enforcement at CHECK stage.
/// The returned bytecode, when run with the incoming chip body NRF-encoded as
/// input CID 0, enforces the gate's conditions against that chip body.
/// Compilation is deterministic: same chip CID → same bytecode every time.
pub async fn gate_compile(
    gate_chip_cid: &str,
    chip_store: &ChipStore,
) -> Result<Vec<u8>, SiliconError> {
    // Load the gate chip from ChipStore.
    let stored = chip_store
        .get_chip(gate_chip_cid)
        .await
        .map_err(SiliconError::from)?
        .ok_or_else(|| SiliconError::ChipNotFound(gate_chip_cid.to_string()))?;
    if stored.chip_type != TYPE_SILICON_CHIP {
        return Err(SiliconError::ChipTypeMismatch(gate_chip_cid.to_string()));
    }

    // Parse the chip body (chip_data is the flat chip JSON).
    let chip_body = match parse_silicon(TYPE_SILICON_CHIP, &stored.chip_data)? {
        SiliconRequest::Chip(c) => c,
        _ => return Err(SiliconError::ChipTypeMismatch(gate_chip_cid.to_string())),
    };

    // Resolve full circuit+bit graph from ChipStore.
    let circuits = resolve_chip_graph(&chip_body, chip_store).await?;

    // Compile to TLV bytecode (deterministic).
    compile_chip_to_rb_vm(&circuits)
}

// ── compile_to_bool ────────────────────────────────────────────────────────────

/// Compile a `ConditionSpec` to TLV opcodes that push a `Bool` on the stack.
/// No assertion — used for boolean composition (Or, Not, And nesting, Parallel).
fn compile_to_bool(cond: &ConditionSpec) -> Result<Vec<u8>, SiliconError> {
    let mut code = Vec::new();
    match cond {
        ConditionSpec::Always { value } => {
            // PushBool(value)
            code.extend(tlv_instr(0x26, &[if *value { 1u8 } else { 0u8 }])); // PushBool
        }
        ConditionSpec::ContextHas { key } => {
            // PushInput(0) → CasGet → JsonNormalize → JsonHasKey(key) → Bool
            code.extend(tlv_instr(0x12, &0u16.to_be_bytes())); // PushInput(0)
            code.extend(tlv_instr(0x0C, &[])); // CasGet
            code.extend(tlv_instr(0x03, &[])); // JsonNormalize
            code.extend(tlv_instr(0x23, key.as_bytes())); // JsonHasKey(key)
        }
        ConditionSpec::ContextEquals { key, value } => {
            // Extract the expected value as a UTF-8 string for comparison.
            // JSON strings are compared as-is; other JSON types use their Display repr.
            let expected = if let Some(s) = value.as_str() {
                s.as_bytes().to_vec()
            } else {
                value.to_string().into_bytes()
            };
            // PushInput(0) → CasGet → JsonNormalize → JsonGetKeyBytes(key)
            // → ConstBytes(expected) → EqBytes → Bool
            code.extend(tlv_instr(0x12, &0u16.to_be_bytes())); // PushInput(0)
            code.extend(tlv_instr(0x0C, &[])); // CasGet
            code.extend(tlv_instr(0x03, &[])); // JsonNormalize
            code.extend(tlv_instr(0x22, key.as_bytes())); // JsonGetKeyBytes(key)
            code.extend(tlv_instr(0x02, &expected)); // ConstBytes(expected)
            code.extend(tlv_instr(0x24, &[])); // EqBytes
        }
        ConditionSpec::TypeEquals { chip_type } => {
            // Same as ContextEquals on the "@type" field.
            let expected = chip_type.as_bytes().to_vec();
            code.extend(tlv_instr(0x12, &0u16.to_be_bytes())); // PushInput(0)
            code.extend(tlv_instr(0x0C, &[])); // CasGet
            code.extend(tlv_instr(0x03, &[])); // JsonNormalize
            code.extend(tlv_instr(0x22, b"@type")); // JsonGetKeyBytes("@type")
            code.extend(tlv_instr(0x02, &expected)); // ConstBytes(chip_type)
            code.extend(tlv_instr(0x24, &[])); // EqBytes
        }
        ConditionSpec::BodySizeLte { limit } => {
            // PushBodySize → ConstI64(limit) → CmpI64(LE) → Bool
            code.extend(tlv_instr(0x25, &[])); // PushBodySize
            code.extend(tlv_instr(0x01, &(*limit as i64).to_be_bytes())); // ConstI64(limit)
            code.extend(tlv_instr(0x08, &[3u8])); // CmpI64(LE)
        }
        ConditionSpec::And { conditions } => {
            if conditions.is_empty() {
                code.extend(tlv_instr(0x26, &[1u8])); // PushBool(true) — vacuous And
            } else {
                for sub in conditions {
                    code.extend(compile_to_bool(sub)?);
                }
                for _ in 0..conditions.len().saturating_sub(1) {
                    code.extend(tlv_instr(0x29, &[])); // BoolAnd
                }
            }
        }
        ConditionSpec::Or { conditions } => {
            if conditions.is_empty() {
                code.extend(tlv_instr(0x26, &[0u8])); // PushBool(false) — vacuous Or
            } else {
                for sub in conditions {
                    code.extend(compile_to_bool(sub)?);
                }
                for _ in 0..conditions.len().saturating_sub(1) {
                    code.extend(tlv_instr(0x28, &[])); // BoolOr
                }
            }
        }
        ConditionSpec::Not { condition } => {
            code.extend(compile_to_bool(condition)?);
            code.extend(tlv_instr(0x27, &[])); // BoolNot
        }
    }
    Ok(code)
}

// ── compile_condition ──────────────────────────────────────────────────────────

/// Compile a condition to TLV opcodes that DENY if the condition fails.
/// Internally uses `compile_to_bool` for all non-trivial cases.
fn compile_condition(cond: &ConditionSpec, on_false: &Decision) -> Result<Vec<u8>, SiliconError> {
    let mut code = compile_to_bool(cond)?;
    if matches!(on_false, Decision::Deny) {
        code.extend(tlv_instr(0x09, &[])); // AssertTrue → DENY if Bool is false
    } else {
        // on_false = Allow or Require: condition is informational; discard result.
        code.extend(tlv_instr(0x11, &[])); // Drop
    }
    Ok(code)
}

// ── TLV encoding helper ───────────────────────────────────────────────────────

/// Encode one TLV instruction: [opcode_byte][2-byte-BE-length][payload].
fn tlv_instr(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(3 + payload.len());
    out.push(opcode);
    let len = payload.len() as u16;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

// ── Utility helpers ───────────────────────────────────────────────────────────

fn req_str(body: &Value, field: &str) -> Result<String, SiliconError> {
    body.get(field)
        .and_then(Value::as_str)
        .map(String::from)
        .ok_or_else(|| SiliconError::MissingField(field.to_string()))
}

fn parse_decision(body: &Value, field: &str) -> Result<Decision, SiliconError> {
    let s = body
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| SiliconError::MissingField(field.to_string()))?;
    match s.to_lowercase().as_str() {
        "allow" => Ok(Decision::Allow),
        "deny" => Ok(Decision::Deny),
        "require" => Ok(Decision::Require),
        other => Err(SiliconError::InvalidField(format!(
            "{} must be allow|deny|require, got '{}'",
            field, other
        ))),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── parse_bit ──────────────────────────────────────────────────────────────

    #[test]
    fn parse_bit_always_allow() {
        let body = json!({
            "id": "P_Always",
            "name": "Always Allow",
            "condition": {"op": "always", "value": true},
            "on_true": "allow",
            "on_false": "deny",
            "requires_context": []
        });
        let bit = parse_bit(&body).unwrap();
        assert_eq!(bit.id, "P_Always");
        assert!(matches!(bit.on_true, Decision::Allow));
        assert!(matches!(bit.on_false, Decision::Deny));
        assert!(matches!(bit.condition, ConditionSpec::Always { value: true }));
    }

    #[test]
    fn parse_bit_context_equals_tagged() {
        let body = json!({
            "id": "P_IsAdmin",
            "name": "Is Admin",
            "condition": {"op": "context_equals", "key": "body.role", "value": "admin"},
            "on_true": "allow",
            "on_false": "deny",
            "requires_context": ["body.role"]
        });
        let bit = parse_bit(&body).unwrap();
        assert!(matches!(bit.condition, ConditionSpec::ContextEquals { .. }));
    }

    #[test]
    fn parse_bit_legacy_compact_form() {
        let body = json!({
            "id": "P_Legacy",
            "name": "Legacy",
            "condition": {"Always": true},
            "on_true": "allow",
            "on_false": "deny",
            "requires_context": []
        });
        let bit = parse_bit(&body).unwrap();
        assert!(matches!(bit.condition, ConditionSpec::Always { value: true }));
    }

    #[test]
    fn parse_bit_missing_id_errors() {
        let body = json!({
            "name": "No ID",
            "condition": {"op": "always", "value": true},
            "on_true": "allow",
            "on_false": "deny"
        });
        let err = parse_bit(&body).unwrap_err();
        assert!(err.to_string().contains("missing field: id"));
    }

    #[test]
    fn parse_bit_invalid_decision_errors() {
        let body = json!({
            "id": "P_Bad",
            "name": "Bad",
            "condition": {"op": "always", "value": true},
            "on_true": "maybe",
            "on_false": "deny"
        });
        let err = parse_bit(&body).unwrap_err();
        assert!(err.to_string().contains("on_true"));
    }

    // ── parse_circuit ──────────────────────────────────────────────────────────

    #[test]
    fn parse_circuit_valid() {
        let body = json!({
            "id": "C_Auth",
            "name": "Auth Gate",
            "bits": ["b3:aaaa", "b3:bbbb"],
            "composition": "Sequential",
            "aggregator": "All"
        });
        let circuit = parse_circuit(&body).unwrap();
        assert_eq!(circuit.bits.len(), 2);
        assert!(matches!(
            circuit.composition_mode().unwrap(),
            CompositionMode::Sequential
        ));
        assert!(matches!(
            circuit.aggregation_mode().unwrap(),
            AggregationMode::All
        ));
    }

    #[test]
    fn parse_circuit_empty_bits_errors() {
        let body = json!({
            "id": "C_Empty",
            "name": "Empty",
            "bits": [],
            "composition": "Sequential",
            "aggregator": "All"
        });
        let err = parse_circuit(&body).unwrap_err();
        assert!(err.to_string().contains("bits cannot be empty"));
    }

    #[test]
    fn parse_circuit_invalid_cid_errors() {
        let body = json!({
            "id": "C_Bad",
            "name": "Bad",
            "bits": ["not-a-cid"],
            "composition": "Sequential",
            "aggregator": "All"
        });
        let err = parse_circuit(&body).unwrap_err();
        assert!(err.to_string().contains("CID"));
    }

    #[test]
    fn parse_circuit_invalid_composition_errors() {
        let body = json!({
            "id": "C_Bad",
            "name": "Bad",
            "bits": ["b3:abc"],
            "composition": "zigzag",
            "aggregator": "All"
        });
        let err = parse_circuit(&body).unwrap_err();
        assert!(err.to_string().contains("composition"));
    }

    // ── parse_chip ─────────────────────────────────────────────────────────────

    #[test]
    fn parse_chip_valid() {
        let body = json!({
            "id": "CHIP_Pay",
            "name": "Payment Processor",
            "circuits": ["b3:cccc"],
            "hal": {
                "profile": "HAL/v0/cpu",
                "targets": ["rb_vm/v1"],
                "deterministic": true
            },
            "version": "1.0"
        });
        let chip = parse_chip(&body).unwrap();
        assert_eq!(chip.circuits.len(), 1);
        assert_eq!(chip.hal.profile, "HAL/v0/cpu");
        assert!(chip.hal.deterministic);
    }

    #[test]
    fn parse_chip_missing_hal_errors() {
        let body = json!({
            "id": "CHIP_NoHal",
            "name": "No HAL",
            "circuits": ["b3:cccc"],
            "version": "1.0"
        });
        let err = parse_chip(&body).unwrap_err();
        assert!(err.to_string().contains("hal"));
    }

    // ── parse_compile ──────────────────────────────────────────────────────────

    #[test]
    fn parse_compile_valid() {
        let body = json!({
            "chip_cid": "b3:dddd",
            "target": "rb_vm"
        });
        let compile = parse_compile(&body).unwrap();
        assert_eq!(compile.chip_cid, "b3:dddd");
        assert_eq!(compile.target, CompileTarget::RbVm);
    }

    #[test]
    fn parse_compile_unsupported_target_errors() {
        let body = json!({
            "chip_cid": "b3:dddd",
            "target": "fpga_virtex9"
        });
        let err = parse_compile(&body).unwrap_err();
        assert!(err.to_string().contains("unsupported compile target"));
    }

    #[test]
    fn parse_compile_bad_cid_errors() {
        let body = json!({
            "chip_cid": "sha256:not-blake3",
            "target": "rb_vm"
        });
        let err = parse_compile(&body).unwrap_err();
        assert!(err.to_string().contains("CID"));
    }

    // ── compile_chip_to_rb_vm ──────────────────────────────────────────────────

    #[test]
    fn compile_always_true_produces_bytecode() {
        let bit = SiliconBitBody {
            id: "P_Always".to_string(),
            name: "Always".to_string(),
            condition: ConditionSpec::Always { value: true },
            on_true: Decision::Allow,
            on_false: Decision::Deny,
            requires_context: vec![],
        };
        let circuit = ResolvedCircuit {
            cid: "b3:test".to_string(),
            body: SiliconCircuitBody {
                id: "C_Test".to_string(),
                name: "Test".to_string(),
                bits: vec!["b3:test".to_string()],
                composition: "Sequential".to_string(),
                aggregator: "All".to_string(),
            },
            nodes: vec![ResolvedNode::Bit(ResolvedBit {
                cid: "b3:test".to_string(),
                body: bit,
            })],
        };
        let bytecode = compile_chip_to_rb_vm(&[circuit]).unwrap();
        assert!(!bytecode.is_empty());
        // Should contain ConstI64(1) + AssertTrue + PushInput(0) + EmitRc
        assert!(bytecode.len() >= 4 * 3); // at minimum 4 TLV instructions × 3 bytes each
    }

    #[test]
    fn compile_always_false_deny_produces_bytecode() {
        let bit = SiliconBitBody {
            id: "P_AlwaysDeny".to_string(),
            name: "Always Deny".to_string(),
            condition: ConditionSpec::Always { value: false },
            on_true: Decision::Allow,
            on_false: Decision::Deny,
            requires_context: vec![],
        };
        let circuit = ResolvedCircuit {
            cid: "b3:test".to_string(),
            body: SiliconCircuitBody {
                id: "C_Test".to_string(),
                name: "Test".to_string(),
                bits: vec!["b3:test".to_string()],
                composition: "Sequential".to_string(),
                aggregator: "All".to_string(),
            },
            nodes: vec![ResolvedNode::Bit(ResolvedBit {
                cid: "b3:test".to_string(),
                body: bit,
            })],
        };
        let bytecode = compile_chip_to_rb_vm(&[circuit]).unwrap();
        assert!(!bytecode.is_empty());
    }

    #[test]
    fn compile_parallel_any_circuit_succeeds() {
        // Phase 2: Parallel + Any is fully supported via Bool-stack fold.
        let bit = SiliconBitBody {
            id: "P_A".to_string(),
            name: "A".to_string(),
            condition: ConditionSpec::Always { value: true },
            on_true: Decision::Allow,
            on_false: Decision::Deny,
            requires_context: vec![],
        };
        let circuit = ResolvedCircuit {
            cid: "b3:test".to_string(),
            body: SiliconCircuitBody {
                id: "C_Parallel".to_string(),
                name: "Parallel".to_string(),
                bits: vec!["b3:test".to_string()],
                composition: "Parallel".to_string(),
                aggregator: "Any".to_string(),
            },
            nodes: vec![ResolvedNode::Bit(ResolvedBit {
                cid: "b3:test".to_string(),
                body: bit,
            })],
        };
        let bytecode = compile_chip_to_rb_vm(&[circuit]).unwrap();
        assert!(!bytecode.is_empty());
        // Must end with EmitRc (0x10)
        assert!(bytecode.windows(3).any(|w| w[0] == 0x10));
    }

    #[test]
    fn is_silicon_type_recognizes_all_types() {
        assert!(is_silicon_type("ubl/silicon.bit"));
        assert!(is_silicon_type("ubl/silicon.circuit"));
        assert!(is_silicon_type("ubl/silicon.chip"));
        assert!(is_silicon_type("ubl/silicon.compile"));
        assert!(!is_silicon_type("ubl/user"));
        assert!(!is_silicon_type("ubl/payment"));
    }

    #[test]
    fn condition_to_expression_roundtrip() {
        let spec = ConditionSpec::And {
            conditions: vec![
                ConditionSpec::Always { value: true },
                ConditionSpec::BodySizeLte { limit: 1024 },
            ],
        };
        let expr = spec.to_expression();
        assert!(matches!(expr, Expression::And(_)));
    }

    #[test]
    fn tlv_instr_encodes_correctly() {
        let instr = tlv_instr(0x01, &42i64.to_be_bytes());
        assert_eq!(instr[0], 0x01); // opcode
        assert_eq!(u16::from_be_bytes([instr[1], instr[2]]), 8); // payload length = 8
        assert_eq!(instr.len(), 11); // 1 + 2 + 8
    }

    // ── recursive DAG tests ────────────────────────────────────────────────────

    /// Build a store containing two chips wired as a DAG:
    ///   chip_outer → circuit_outer → [bit_outer, chip_inner]
    ///   chip_inner → circuit_inner → [bit_inner]
    ///
    /// chip_outer's circuit references chip_inner as a sub-chip.
    /// Both inner and outer bits are Always(true).
    /// The compiled bytecode should pass (all conditions true).
    #[tokio::test]
    async fn gate_compile_recursive_chip_dag() {
        use std::sync::Arc;
        use ubl_chipstore::{ChipStore, ExecutionMetadata, InMemoryBackend};
        use ubl_types::Did as TypedDid;

        let backend = Arc::new(InMemoryBackend::new());
        let store = ChipStore::new(backend);
        let meta = || ExecutionMetadata {
            runtime_version: "test".to_string(),
            execution_time_ms: 0,
            fuel_consumed: 0,
            policies_applied: vec![],
            executor_did: TypedDid::new_unchecked("did:key:test"),
            reproducible: true,
        };

        // ── inner chip ──────────────────────────────────────────────────────
        let inner_bit_data = serde_json::json!({
            "@type": TYPE_SILICON_BIT,
            "@world": "a/test/t/dev",
            "id": "BIT_inner",
            "name": "Inner Bit",
            "condition": {"op": "always", "value": true},
            "on_true": "allow",
            "on_false": "deny",
            "requires_context": []
        });
        let inner_bit_cid = store
            .store_executed_chip(inner_bit_data, "b3:fake_inner_bit".to_string(), meta())
            .await
            .unwrap();

        let inner_circuit_data = serde_json::json!({
            "@type": TYPE_SILICON_CIRCUIT,
            "@world": "a/test/t/dev",
            "id": "C_inner",
            "name": "Inner Circuit",
            "bits": [inner_bit_cid],
            "composition": "Sequential",
            "aggregator": "All"
        });
        let inner_circuit_cid = store
            .store_executed_chip(inner_circuit_data, "b3:fake_inner_circuit".to_string(), meta())
            .await
            .unwrap();

        let inner_chip_data = serde_json::json!({
            "@type": TYPE_SILICON_CHIP,
            "@world": "a/test/t/dev",
            "id": "CHIP_inner",
            "name": "Inner Chip",
            "circuits": [inner_circuit_cid],
            "hal": {"profile": "HAL/v0/cpu", "targets": ["rb_vm/v1"], "deterministic": true},
            "version": "1.0"
        });
        let inner_chip_cid = store
            .store_executed_chip(inner_chip_data, "b3:fake_inner_chip".to_string(), meta())
            .await
            .unwrap();

        // ── outer chip ──────────────────────────────────────────────────────
        let outer_bit_data = serde_json::json!({
            "@type": TYPE_SILICON_BIT,
            "@world": "a/test/t/dev",
            "id": "BIT_outer",
            "name": "Outer Bit",
            "condition": {"op": "always", "value": true},
            "on_true": "allow",
            "on_false": "deny",
            "requires_context": []
        });
        let outer_bit_cid = store
            .store_executed_chip(outer_bit_data, "b3:fake_outer_bit".to_string(), meta())
            .await
            .unwrap();

        // circuit references both a plain bit and the inner chip (DAG node)
        let outer_circuit_data = serde_json::json!({
            "@type": TYPE_SILICON_CIRCUIT,
            "@world": "a/test/t/dev",
            "id": "C_outer",
            "name": "Outer Circuit",
            "bits": [outer_bit_cid, inner_chip_cid],
            "composition": "Sequential",
            "aggregator": "All"
        });
        let outer_circuit_cid = store
            .store_executed_chip(outer_circuit_data, "b3:fake_outer_circuit".to_string(), meta())
            .await
            .unwrap();

        let outer_chip_data = serde_json::json!({
            "@type": TYPE_SILICON_CHIP,
            "@world": "a/test/t/dev",
            "id": "CHIP_outer",
            "name": "Outer Chip",
            "circuits": [outer_circuit_cid],
            "hal": {"profile": "HAL/v0/cpu", "targets": ["rb_vm/v1"], "deterministic": true},
            "version": "1.0"
        });
        let outer_chip_cid = store
            .store_executed_chip(outer_chip_data, "b3:fake_outer_chip".to_string(), meta())
            .await
            .unwrap();

        // compile the outer chip — must resolve the DAG without error
        let bytecode = gate_compile(&outer_chip_cid, &store).await.unwrap();
        assert!(!bytecode.is_empty());
        // must terminate with EmitRc (0x10)
        assert!(bytecode.windows(3).any(|w| w[0] == 0x10));
        // two calls should produce identical bytecode (determinism)
        let bytecode2 = gate_compile(&outer_chip_cid, &store).await.unwrap();
        assert_eq!(bytecode, bytecode2);
    }

    // ── gate_compile tests ─────────────────────────────────────────────────────

    /// Build a populated in-memory ChipStore with a silicon.chip that has a
    /// single Always-condition bit.  Returns (store, chip_cid).
    async fn build_gate_store(always_value: bool) -> (ChipStore, String) {
        use std::sync::Arc;
        use ubl_chipstore::{ChipStore, ExecutionMetadata, InMemoryBackend};
        use ubl_types::Did as TypedDid;

        let backend = Arc::new(InMemoryBackend::new());
        let store = ChipStore::new(backend);
        let meta = ExecutionMetadata {
            runtime_version: "test".to_string(),
            execution_time_ms: 0,
            fuel_consumed: 0,
            policies_applied: vec![],
            executor_did: TypedDid::new_unchecked("did:key:test"),
            reproducible: true,
        };

        // silicon.bit
        let bit_data = serde_json::json!({
            "@type": TYPE_SILICON_BIT,
            "@world": "a/test/t/dev",
            "id": "P_Gate",
            "name": "Gate",
            "condition": {"op": "always", "value": always_value},
            "on_true": "allow",
            "on_false": "deny",
            "requires_context": []
        });
        let bit_cid = store
            .store_executed_chip(bit_data, "b3:fake_bit_receipt".to_string(), meta.clone())
            .await
            .unwrap();

        // silicon.circuit
        let circuit_data = serde_json::json!({
            "@type": TYPE_SILICON_CIRCUIT,
            "@world": "a/test/t/dev",
            "id": "C_Gate",
            "name": "Gate Circuit",
            "bits": [bit_cid],
            "composition": "Sequential",
            "aggregator": "All"
        });
        let circuit_cid = store
            .store_executed_chip(
                circuit_data,
                "b3:fake_circuit_receipt".to_string(),
                meta.clone(),
            )
            .await
            .unwrap();

        // silicon.chip
        let chip_data = serde_json::json!({
            "@type": TYPE_SILICON_CHIP,
            "@world": "a/test/t/dev",
            "id": "CHIP_Gate",
            "name": "Gate Chip",
            "circuits": [circuit_cid],
            "hal": {"profile": "HAL/v0/cpu", "targets": ["rb_vm/v1"], "deterministic": true},
            "version": "1.0"
        });
        let chip_cid = store
            .store_executed_chip(chip_data, "b3:fake_chip_receipt".to_string(), meta)
            .await
            .unwrap();

        (store, chip_cid)
    }

    #[tokio::test]
    async fn gate_compile_always_allow_produces_bytecode() {
        let (store, chip_cid) = build_gate_store(true).await;
        let bytecode = gate_compile(&chip_cid, &store).await.unwrap();
        assert!(!bytecode.is_empty());
        // Must terminate with EmitRc (0x10)
        assert!(bytecode.windows(3).any(|w| w[0] == 0x10));
    }

    #[tokio::test]
    async fn gate_compile_missing_chip_errors() {
        use std::sync::Arc;
        use ubl_chipstore::{ChipStore, InMemoryBackend};

        let backend = Arc::new(InMemoryBackend::new());
        let store = ChipStore::new(backend);
        let err = gate_compile("b3:nonexistent", &store).await.unwrap_err();
        assert!(matches!(err, SiliconError::ChipNotFound(_)));
    }

    #[tokio::test]
    async fn gate_compile_type_mismatch_errors() {
        use std::sync::Arc;
        use ubl_chipstore::{ChipStore, ExecutionMetadata, InMemoryBackend};
        use ubl_types::Did as TypedDid;

        let backend = Arc::new(InMemoryBackend::new());
        let store = ChipStore::new(backend);
        let meta = ExecutionMetadata {
            runtime_version: "test".to_string(),
            execution_time_ms: 0,
            fuel_consumed: 0,
            policies_applied: vec![],
            executor_did: TypedDid::new_unchecked("did:key:test"),
            reproducible: true,
        };

        // Store a silicon.bit, then pass its CID to gate_compile (which expects a chip).
        let bit_data = serde_json::json!({
            "@type": TYPE_SILICON_BIT,
            "@world": "a/test/t/dev",
            "id": "P_Wrong",
            "name": "Wrong",
            "condition": {"op": "always", "value": true},
            "on_true": "allow",
            "on_false": "deny",
            "requires_context": []
        });
        let bit_cid = store
            .store_executed_chip(bit_data, "b3:receipt".to_string(), meta)
            .await
            .unwrap();
        let err = gate_compile(&bit_cid, &store).await.unwrap_err();
        assert!(matches!(err, SiliconError::ChipTypeMismatch(_)));
    }

    #[tokio::test]
    async fn gate_compile_allow_bytecode_is_deterministic() {
        // Same chip body → same bytecode CID every call.
        let (store, chip_cid) = build_gate_store(true).await;
        let bc1 = gate_compile(&chip_cid, &store).await.unwrap();
        let bc2 = gate_compile(&chip_cid, &store).await.unwrap();
        assert_eq!(bc1, bc2);
    }
}
