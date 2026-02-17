//! Chip-as-Code format support
//!
//! Supports compilation from YAML .chip files to NRF-1 binary format
//! as specified in the UBL MASTER BLUEPRINT.

use crate::{to_nrf1_bytes, CompileError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
        let canonical_json = self.to_json()?;

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
}
