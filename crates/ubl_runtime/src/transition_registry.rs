//! Transition Registry — deterministic TR bytecode selection by chip type.
//!
//! Resolution order (first match wins):
//! 1) chip override: `@tr.bytecode_hex`
//! 2) chip override: `@tr.profile`
//! 3) env map: `UBL_TR_BYTECODE_MAP_JSON`
//! 4) env map: `UBL_TR_PROFILE_MAP_JSON`
//! 5) built-in default profile by `@type`

use serde_json::Value;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrBytecodeProfile {
    PassV1,
    AuditV1,
    NumericV1,
    /// Silicon bit/circuit/chip: passthrough + store definition in CAS.
    SiliconDefinitionV1,
    /// Silicon compile: full compilation to rb_vm bytecode.
    SiliconCompileV1,
}

impl TrBytecodeProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PassV1 => "pass_v1",
            Self::AuditV1 => "audit_v1",
            Self::NumericV1 => "numeric_v1",
            Self::SiliconDefinitionV1 => "silicon_definition_v1",
            Self::SiliconCompileV1 => "silicon_compile_v1",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "pass_v1" | "pass" => Some(Self::PassV1),
            "audit_v1" | "audit" => Some(Self::AuditV1),
            "numeric_v1" | "numeric" | "num_v1" | "num" => Some(Self::NumericV1),
            "silicon_definition_v1" | "silicon_definition" | "silicon_def" => {
                Some(Self::SiliconDefinitionV1)
            }
            "silicon_compile_v1" | "silicon_compile" => Some(Self::SiliconCompileV1),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TransitionResolution {
    pub bytecode: Vec<u8>,
    pub source: String,
    pub profile: TrBytecodeProfile,
}

#[derive(Debug, thiserror::Error)]
pub enum TransitionRegistryError {
    #[error("invalid hex bytecode: {0}")]
    InvalidHex(String),
    #[error("invalid profile: {0}")]
    InvalidProfile(String),
    #[error("invalid registry config: {0}")]
    InvalidConfig(String),
}

#[derive(Debug, Clone, Default)]
pub struct TransitionRegistry {
    bytecode_overrides: HashMap<String, Vec<u8>>,
    profile_overrides: HashMap<String, TrBytecodeProfile>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ChipTrDirective {
    BytecodeHex(String),
    Profile(TrBytecodeProfile),
}

impl TransitionRegistry {
    pub fn from_env() -> Result<Self, TransitionRegistryError> {
        let mut registry = Self::default();

        if let Ok(raw) = std::env::var("UBL_TR_BYTECODE_MAP_JSON") {
            let map: Value = serde_json::from_str(&raw)
                .map_err(|e| TransitionRegistryError::InvalidConfig(e.to_string()))?;
            let obj = map.as_object().ok_or_else(|| {
                TransitionRegistryError::InvalidConfig("bytecode map must be object".to_string())
            })?;
            for (chip_type, hex_raw) in obj {
                let hex_raw = hex_raw.as_str().ok_or_else(|| {
                    TransitionRegistryError::InvalidConfig(format!(
                        "bytecode for '{}' must be string",
                        chip_type
                    ))
                })?;
                registry
                    .bytecode_overrides
                    .insert(chip_type.clone(), parse_hex_bytecode(hex_raw)?);
            }
        }

        if let Ok(raw) = std::env::var("UBL_TR_PROFILE_MAP_JSON") {
            let map: Value = serde_json::from_str(&raw)
                .map_err(|e| TransitionRegistryError::InvalidConfig(e.to_string()))?;
            let obj = map.as_object().ok_or_else(|| {
                TransitionRegistryError::InvalidConfig("profile map must be object".to_string())
            })?;
            for (chip_type, profile_raw) in obj {
                let profile_raw = profile_raw.as_str().ok_or_else(|| {
                    TransitionRegistryError::InvalidConfig(format!(
                        "profile for '{}' must be string",
                        chip_type
                    ))
                })?;
                let profile = TrBytecodeProfile::parse(profile_raw).ok_or_else(|| {
                    TransitionRegistryError::InvalidProfile(profile_raw.to_string())
                })?;
                registry
                    .profile_overrides
                    .insert(chip_type.clone(), profile);
            }
        }

        Ok(registry)
    }

    pub fn default_profile_for(chip_type: &str) -> TrBytecodeProfile {
        match chip_type {
            // Onboarding/security-sensitive flows use explicit audit profile.
            "ubl/app" | "ubl/user" | "ubl/tenant" | "ubl/membership" | "ubl/token"
            | "ubl/revoke" | "ubl/key.rotate" => TrBytecodeProfile::AuditV1,
            // Money-like flows default to numeric profile.
            "ubl/payment" | "ubl/invoice" | "ubl/settlement" | "ubl/quote" => {
                TrBytecodeProfile::NumericV1
            }
            // Silicon definition chips: store the definition, emit receipt.
            "ubl/silicon.bit" | "ubl/silicon.circuit" | "ubl/silicon.chip" => {
                TrBytecodeProfile::SiliconDefinitionV1
            }
            // Silicon compile chip: compilation is handled in stage_transition.
            "ubl/silicon.compile" => TrBytecodeProfile::SiliconCompileV1,
            _ => TrBytecodeProfile::PassV1,
        }
    }

    pub fn build_profile_bytecode(profile: TrBytecodeProfile) -> Vec<u8> {
        match profile {
            TrBytecodeProfile::PassV1 => {
                let mut code = Vec::new();
                code.extend(tlv_instr(0x12, &0u16.to_be_bytes())); // PushInput(0)
                code.extend(tlv_instr(0x10, &[])); // EmitRc
                code
            }
            TrBytecodeProfile::AuditV1 => {
                let mut code = Vec::new();
                code.extend(tlv_instr(0x12, &0u16.to_be_bytes())); // PushInput(0)
                code.extend(tlv_instr(0x14, &[])); // Dup
                code.extend(tlv_instr(0x11, &[])); // Drop
                code.extend(tlv_instr(0x10, &[])); // EmitRc
                code
            }
            TrBytecodeProfile::NumericV1 => {
                let mut code = Vec::new();
                code.extend(tlv_instr(0x12, &0u16.to_be_bytes())); // PushInput(0)
                code.extend(tlv_instr(0x0C, &[])); // CasGet
                code.extend(tlv_instr(0x03, &[])); // JsonNormalize
                code.extend(tlv_instr(0x04, &[])); // JsonValidate
                code.extend(tlv_instr(0x13, b"amount")); // JsonGetKey("amount")
                code.extend(tlv_instr(0x1E, &1_000_000u64.to_be_bytes())); // NumToRat(limit_den=1e6)
                code.extend(tlv_instr(0x1D, &[0, 0, 0, 2, 0])); // NumToDec(scale=2, HALF_EVEN)
                code.extend(tlv_instr(0x0D, &[])); // SetRcBody
                code.extend(tlv_instr(0x12, &0u16.to_be_bytes())); // PushInput(0)
                code.extend(tlv_instr(0x0E, &[])); // AttachProof
                code.extend(tlv_instr(0x10, &[])); // EmitRc
                code
            }
            // Silicon definition: normalize, hash, store in CAS, attach proof, emit receipt.
            // The CAS store proves the definition is content-addressed (CID = BLAKE3 of NRF-1).
            TrBytecodeProfile::SiliconDefinitionV1 => {
                let mut code = Vec::new();
                code.extend(tlv_instr(0x12, &0u16.to_be_bytes())); // PushInput(0)
                code.extend(tlv_instr(0x0C, &[])); // CasGet
                code.extend(tlv_instr(0x03, &[])); // JsonNormalize
                code.extend(tlv_instr(0x0B, &[])); // CasPut — store normalized definition
                code.extend(tlv_instr(0x11, &[])); // Drop (CAS CID off stack)
                code.extend(tlv_instr(0x12, &0u16.to_be_bytes())); // PushInput(0)
                code.extend(tlv_instr(0x0E, &[])); // AttachProof — attach input CID as proof
                code.extend(tlv_instr(0x10, &[])); // EmitRc
                code
            }
            // Silicon compile: stage_transition handles actual compilation.
            // This bytecode is a passthrough — the real work happens in execute_silicon_compile_transition.
            TrBytecodeProfile::SiliconCompileV1 => {
                let mut code = Vec::new();
                code.extend(tlv_instr(0x12, &0u16.to_be_bytes())); // PushInput(0)
                code.extend(tlv_instr(0x10, &[])); // EmitRc
                code
            }
        }
    }

    pub fn resolve(
        &self,
        chip_type: &str,
        body: &Value,
    ) -> Result<TransitionResolution, TransitionRegistryError> {
        if let Some(directive) = parse_chip_tr_directive(body)? {
            return Ok(match directive {
                ChipTrDirective::BytecodeHex(hex_raw) => TransitionResolution {
                    bytecode: parse_hex_bytecode(&hex_raw)?,
                    source: "chip:@tr.bytecode_hex".to_string(),
                    profile: TrBytecodeProfile::PassV1,
                },
                ChipTrDirective::Profile(profile) => TransitionResolution {
                    bytecode: Self::build_profile_bytecode(profile),
                    source: "chip:@tr.profile".to_string(),
                    profile,
                },
            });
        }

        if let Some(bytecode) = self.bytecode_overrides.get(chip_type) {
            return Ok(TransitionResolution {
                bytecode: bytecode.clone(),
                source: "env:UBL_TR_BYTECODE_MAP_JSON".to_string(),
                profile: TrBytecodeProfile::PassV1,
            });
        }

        let profile = self
            .profile_overrides
            .get(chip_type)
            .copied()
            .unwrap_or_else(|| Self::default_profile_for(chip_type));

        Ok(TransitionResolution {
            bytecode: Self::build_profile_bytecode(profile),
            source: if self.profile_overrides.contains_key(chip_type) {
                "env:UBL_TR_PROFILE_MAP_JSON".to_string()
            } else {
                format!("profile:{}", profile.as_str())
            },
            profile,
        })
    }
}

fn tlv_instr(op: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(3 + payload.len());
    out.push(op);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn parse_hex_bytecode(raw: &str) -> Result<Vec<u8>, TransitionRegistryError> {
    let compact: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
    hex::decode(compact).map_err(|e| TransitionRegistryError::InvalidHex(e.to_string()))
}

fn parse_chip_tr_directive(
    body: &Value,
) -> Result<Option<ChipTrDirective>, TransitionRegistryError> {
    let Some(tr) = body.get("@tr") else {
        return Ok(None);
    };
    let tr = tr
        .as_object()
        .ok_or_else(|| TransitionRegistryError::InvalidConfig("@tr must be object".to_string()))?;

    let bytecode_hex = tr.get("bytecode_hex").and_then(|v| v.as_str());
    let profile_raw = tr.get("profile").and_then(|v| v.as_str());

    match (bytecode_hex, profile_raw) {
        (Some(_), Some(_)) => Err(TransitionRegistryError::InvalidConfig(
            "@tr.bytecode_hex and @tr.profile are mutually exclusive".to_string(),
        )),
        (Some(hex_raw), None) => Ok(Some(ChipTrDirective::BytecodeHex(hex_raw.to_string()))),
        (None, Some(profile_raw)) => {
            let profile = TrBytecodeProfile::parse(profile_raw)
                .ok_or_else(|| TransitionRegistryError::InvalidProfile(profile_raw.to_string()))?;
            Ok(Some(ChipTrDirective::Profile(profile)))
        }
        (None, None) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn default_profile_selection() {
        assert_eq!(
            TransitionRegistry::default_profile_for("ubl/document"),
            TrBytecodeProfile::PassV1
        );
        assert_eq!(
            TransitionRegistry::default_profile_for("ubl/token"),
            TrBytecodeProfile::AuditV1
        );
        assert_eq!(
            TransitionRegistry::default_profile_for("ubl/key.rotate"),
            TrBytecodeProfile::AuditV1
        );
        assert_eq!(
            TransitionRegistry::default_profile_for("ubl/payment"),
            TrBytecodeProfile::NumericV1
        );
    }

    #[test]
    fn resolve_prefers_chip_bytecode_override() {
        let registry = TransitionRegistry::default();
        let body = json!({
            "@tr": {"bytecode_hex": "1200020000100000"}
        });

        let resolved = registry.resolve("ubl/document", &body).unwrap();
        assert_eq!(resolved.source, "chip:@tr.bytecode_hex");
        assert_eq!(
            resolved.bytecode,
            vec![0x12, 0x00, 0x02, 0x00, 0x00, 0x10, 0x00, 0x00]
        );
    }

    #[test]
    fn resolve_uses_profile_when_no_override() {
        let registry = TransitionRegistry::default();
        let body = json!({"@type":"ubl/document"});
        let resolved = registry.resolve("ubl/document", &body).unwrap();
        assert_eq!(resolved.profile, TrBytecodeProfile::PassV1);
        assert!(resolved.source.starts_with("profile:"));
    }

    #[test]
    fn resolve_defaults_to_numeric_profile_for_payment() {
        let registry = TransitionRegistry::default();
        let body = json!({"@type":"ubl/payment","amount":{"@num":"dec/1","m":"123","s":2}});
        let resolved = registry.resolve("ubl/payment", &body).unwrap();
        assert_eq!(resolved.profile, TrBytecodeProfile::NumericV1);
        assert!(
            resolved.bytecode.contains(&0x1D),
            "NumToDec opcode expected"
        );
        assert!(
            resolved.bytecode.contains(&0x1E),
            "NumToRat opcode expected"
        );
    }

    #[test]
    fn resolve_rejects_conflicting_chip_directive() {
        let registry = TransitionRegistry::default();
        let body = json!({
            "@tr": {
                "bytecode_hex": "1200020000100000",
                "profile": "audit_v1"
            }
        });

        let err = registry.resolve("ubl/document", &body).unwrap_err();
        assert!(matches!(err, TransitionRegistryError::InvalidConfig(_)));
    }
}
