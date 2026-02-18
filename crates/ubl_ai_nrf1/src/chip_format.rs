//! Chip-as-Code format support
//!
//! Supports compilation from YAML .chip files to NRF-1 binary format
//! as specified in the UBL MASTER BLUEPRINT.

use crate::{to_nrf1_bytes, CompileError};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum F64ImportMode {
    Reject,
    Bnd,
}

impl F64ImportMode {
    pub fn from_env() -> Self {
        match std::env::var("F64_IMPORT_MODE") {
            Ok(v) if v.eq_ignore_ascii_case("bnd") => Self::Bnd,
            _ => Self::Reject,
        }
    }
}

/// A .chip file in YAML format (Chip-as-Code)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChipFile {
    /// Chip type (e.g., "ubl/user", "ubl/policy")
    #[serde(rename = "@type")]
    pub chip_type: String,

    /// Version of the chip format
    #[serde(rename = "@ver")]
    pub version: String,

    /// Metadata for the chip
    pub metadata: ChipMetadata,

    /// The actual chip body/payload
    pub body: serde_json::Value,

    /// Optional policy reference
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicyRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChipMetadata {
    /// Logical ID for the chip
    pub id: String,

    /// Tags for categorization
    #[serde(default)]
    pub tags: Vec<String>,

    /// Human-readable description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Parent chip CIDs
    #[serde(default)]
    pub parents: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRef {
    /// Policy to check against
    pub check: String,
}

/// Compiled chip ready for signing and storage
#[derive(Debug, Clone)]
pub struct CompiledChip {
    /// NRF-1 binary representation
    pub nrf1_bytes: Vec<u8>,
    /// Computed CID
    pub cid: String,
    /// Original chip type
    pub chip_type: String,
    /// Logical ID
    pub logical_id: String,
}

impl ChipFile {
    /// Load a ChipFile from YAML string
    pub fn from_yaml(yaml: &str) -> Result<Self, CompileError> {
        serde_yaml::from_str(yaml)
            .map_err(|e| CompileError::InvalidFormat(format!("YAML parse error: {}", e)))
    }

    /// Convert ChipFile to JSON (canonical intermediate form)
    pub fn to_json(&self) -> Result<serde_json::Value, CompileError> {
        // Merge metadata into body for canonical form
        let mut canonical_body = self.body.clone();

        // Ensure body is an object
        let body_obj = canonical_body
            .as_object_mut()
            .ok_or_else(|| CompileError::InvalidFormat("Body must be a JSON object".to_string()))?;

        // Add required fields
        body_obj.insert(
            "@type".to_string(),
            serde_json::Value::String(self.chip_type.clone()),
        );
        body_obj.insert(
            "id".to_string(),
            serde_json::Value::String(self.metadata.id.clone()),
        );

        // Add parents if present
        if !self.metadata.parents.is_empty() {
            body_obj.insert(
                "parents".to_string(),
                serde_json::Value::Array(
                    self.metadata
                        .parents
                        .iter()
                        .map(|s| serde_json::Value::String(s.clone()))
                        .collect(),
                ),
            );
        }

        // Add tags if present
        if !self.metadata.tags.is_empty() {
            body_obj.insert(
                "tags".to_string(),
                serde_json::Value::Array(
                    self.metadata
                        .tags
                        .iter()
                        .map(|s| serde_json::Value::String(s.clone()))
                        .collect(),
                ),
            );
        }

        Ok(canonical_body)
    }

    /// Compile ChipFile to NRF-1 binary
    pub fn compile(&self) -> Result<CompiledChip, CompileError> {
        // Convert to canonical JSON
        let mut canonical_json = self.to_json()?;

        normalize_numbers_to_unc1(&mut canonical_json, F64ImportMode::from_env())?;

        let require_unc1 = std::env::var("REQUIRE_UNC1_NUMERIC")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if require_unc1 {
            assert_no_numeric_literals(&canonical_json, "$")?;
        }

        // Convert to NRF-1 bytes
        let nrf1_bytes = to_nrf1_bytes(&canonical_json)?;

        // Add magic header (0xF2) for chip format
        let mut final_bytes = vec![0xF2]; // Magic byte for UBL chip
        final_bytes.push(0x01); // Version 1
        final_bytes.push(self.chip_type_code()); // Type code
        final_bytes.extend(nrf1_bytes);

        // Compute CID
        let cid = crate::compute_cid(&final_bytes)?;

        Ok(CompiledChip {
            nrf1_bytes: final_bytes,
            cid,
            chip_type: self.chip_type.clone(),
            logical_id: self.metadata.id.clone(),
        })
    }

    /// Get type code for binary header
    fn chip_type_code(&self) -> u8 {
        match self.chip_type.as_str() {
            "ubl/user" => 0x10,
            "ubl/app" => 0x11,
            "ubl/tenant" => 0x12,
            "ubl/policy" => 0x13,
            "ubl/token" => 0x14,
            "ubl/invite" => 0x15,
            "ubl/ai.passport" => 0x16,
            "ubl/wasm.module" => 0x17,
            _ => 0xFF, // Unknown type
        }
    }
}

/// Normalize raw floating-point numbers into UNC-1 `@num` atoms according to migration mode.
///
/// `Reject`: returns an error if a raw float is found.
/// `Bnd`: converts every raw float into `@num: "bnd/1"` via IEEE-754 boundary mapping.
pub fn normalize_numbers_to_unc1(
    value: &mut serde_json::Value,
    mode: F64ImportMode,
) -> Result<(), CompileError> {
    match value {
        serde_json::Value::Number(n) => {
            if n.is_i64() || n.is_u64() {
                return Ok(());
            }
            let raw = n.to_string();
            match mode {
                F64ImportMode::Reject => Err(CompileError::InvalidFormat(format!(
                    "raw float '{}' violates UNC-1; use @num atom",
                    raw
                ))),
                F64ImportMode::Bnd => {
                    let f = n.as_f64().ok_or_else(|| {
                        CompileError::InvalidFormat(format!(
                            "raw float '{}' cannot be represented as f64",
                            raw
                        ))
                    })?;
                    let bnd = ubl_unc1::from_f64_bits(f.to_bits())
                        .map_err(|e| CompileError::InvalidFormat(format!("UNC-1 import: {}", e)))?;
                    *value = serde_json::to_value(&bnd)
                        .map_err(|e| CompileError::InvalidFormat(format!("UNC-1 encode: {}", e)))?;
                    Ok(())
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                normalize_numbers_to_unc1(item, mode)?;
            }
            Ok(())
        }
        serde_json::Value::Object(map) => {
            if map.contains_key("@num") {
                return Ok(());
            }
            for item in map.values_mut() {
                normalize_numbers_to_unc1(item, mode)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn assert_no_numeric_literals(value: &serde_json::Value, path: &str) -> Result<(), CompileError> {
    match value {
        serde_json::Value::Number(_) => Err(CompileError::InvalidFormat(format!(
            "numeric literal not allowed at {} when REQUIRE_UNC1_NUMERIC=true",
            path
        ))),
        serde_json::Value::Array(arr) => {
            for (idx, item) in arr.iter().enumerate() {
                assert_no_numeric_literals(item, &format!("{}[{}]", path, idx))?;
            }
            Ok(())
        }
        serde_json::Value::Object(map) => {
            if map.contains_key("@num") {
                return Ok(());
            }
            for (k, item) in map {
                assert_no_numeric_literals(item, &format!("{}.{}", path, k))?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_USER_CHIP: &str = r#"
"@type": ubl/user
"@ver": "1.0"

metadata:
  id: "alice"
  tags: ["env:prod", "role:admin"]
  description: "Alice - System Administrator"
  parents: ["b3:tenant-cid"]

body:
  email: "alice@acme.com"
  name: "Alice Cooper"
  preferences:
    theme: "dark"
    language: "en"

policy:
  check: "admin.validation.v1"
"#;

    #[test]
    fn parse_chip_file() {
        let chip = ChipFile::from_yaml(SAMPLE_USER_CHIP).unwrap();
        assert_eq!(chip.chip_type, "ubl/user");
        assert_eq!(chip.metadata.id, "alice");
        assert_eq!(chip.metadata.tags.len(), 2);
        assert!(chip.policy.is_some());
    }

    #[test]
    fn chip_to_canonical_json() {
        let chip = ChipFile::from_yaml(SAMPLE_USER_CHIP).unwrap();
        let json = chip.to_json().unwrap();

        assert_eq!(json["@type"], "ubl/user");
        assert_eq!(json["id"], "alice");
        assert_eq!(json["email"], "alice@acme.com");
        assert!(json["parents"].is_array());
        assert!(json["tags"].is_array());
    }

    #[test]
    fn compile_chip_deterministic() {
        let chip = ChipFile::from_yaml(SAMPLE_USER_CHIP).unwrap();

        let compiled1 = chip.compile().unwrap();
        let compiled2 = chip.compile().unwrap();

        // Must be deterministic
        assert_eq!(compiled1.nrf1_bytes, compiled2.nrf1_bytes);
        assert_eq!(compiled1.cid, compiled2.cid);
        assert!(compiled1.cid.starts_with("b3:"));
    }

    #[test]
    fn chip_has_magic_header() {
        let chip = ChipFile::from_yaml(SAMPLE_USER_CHIP).unwrap();
        let compiled = chip.compile().unwrap();

        // Check magic header
        assert_eq!(compiled.nrf1_bytes[0], 0xF2); // Magic
        assert_eq!(compiled.nrf1_bytes[1], 0x01); // Version
        assert_eq!(compiled.nrf1_bytes[2], 0x10); // User type code
    }

    #[test]
    fn normalize_numbers_reject_mode_blocks_raw_float() {
        let mut v = serde_json::json!({"amount": 12.34});
        let err = normalize_numbers_to_unc1(&mut v, F64ImportMode::Reject).unwrap_err();
        assert!(err.to_string().contains("raw float"));
    }

    #[test]
    fn normalize_numbers_bnd_mode_converts_raw_float() {
        let mut v = serde_json::json!({"amount": 12.34});
        normalize_numbers_to_unc1(&mut v, F64ImportMode::Bnd).unwrap();
        assert_eq!(v["amount"]["@num"], "bnd/1");
    }
}
