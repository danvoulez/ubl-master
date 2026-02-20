//! Manifest generator (P2.8) — produces OpenAPI, MCP tool, and WebMCP manifests
//! from the gate's registered chip types and routes.
//!
//! All manifests are generated at startup and served as static JSON.
//! They describe the same surface in three formats:
//! - OpenAPI 3.1 for HTTP clients
//! - MCP tool manifest for AI agents (JSON-RPC tools)
//! - WebMCP manifest for browser-based MCP clients

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// A registered chip type that the gate accepts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChipTypeSpec {
    /// The @type value (e.g. "ubl/app", "ubl/user")
    pub chip_type: String,
    /// Human-readable description
    pub description: String,
    /// Required fields in the chip body (besides @type, @ver, @world, @id)
    pub required_fields: Vec<FieldSpec>,
    /// Optional fields
    pub optional_fields: Vec<FieldSpec>,
    /// Required capability action (if any)
    pub required_cap: Option<String>,
}

/// A field in a chip body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldSpec {
    pub name: String,
    pub field_type: String,
    pub description: String,
}

/// The gate's full API surface for manifest generation.
#[derive(Debug, Clone)]
pub struct GateManifest {
    pub base_url: String,
    pub version: String,
    pub chip_types: Vec<ChipTypeSpec>,
}

impl Default for GateManifest {
    fn default() -> Self {
        Self {
            base_url: "https://gate.ubl.agency".to_string(),
            version: "1.0.0".to_string(),
            chip_types: default_chip_types(),
        }
    }
}

/// Default chip types known to the gate.
pub fn default_chip_types() -> Vec<ChipTypeSpec> {
    vec![
        ChipTypeSpec {
            chip_type: "ubl/app".into(),
            description: "Register a new application".into(),
            required_fields: vec![
                FieldSpec {
                    name: "slug".into(),
                    field_type: "string".into(),
                    description: "Unique app slug".into(),
                },
                FieldSpec {
                    name: "display_name".into(),
                    field_type: "string".into(),
                    description: "Display name".into(),
                },
                FieldSpec {
                    name: "owner_did".into(),
                    field_type: "string".into(),
                    description: "Owner DID".into(),
                },
            ],
            optional_fields: vec![],
            required_cap: Some("registry:init".into()),
        },
        ChipTypeSpec {
            chip_type: "ubl/user".into(),
            description: "Register a user (first user requires cap)".into(),
            required_fields: vec![
                FieldSpec {
                    name: "did".into(),
                    field_type: "string".into(),
                    description: "User DID".into(),
                },
                FieldSpec {
                    name: "display_name".into(),
                    field_type: "string".into(),
                    description: "Display name".into(),
                },
            ],
            optional_fields: vec![],
            required_cap: None,
        },
        ChipTypeSpec {
            chip_type: "ubl/tenant".into(),
            description: "Create a tenant (circle/workspace)".into(),
            required_fields: vec![
                FieldSpec {
                    name: "slug".into(),
                    field_type: "string".into(),
                    description: "Tenant slug".into(),
                },
                FieldSpec {
                    name: "display_name".into(),
                    field_type: "string".into(),
                    description: "Display name".into(),
                },
                FieldSpec {
                    name: "creator_cid".into(),
                    field_type: "string".into(),
                    description: "CID of creating user".into(),
                },
            ],
            optional_fields: vec![],
            required_cap: None,
        },
        ChipTypeSpec {
            chip_type: "ubl/membership".into(),
            description: "Grant membership to a user in a tenant".into(),
            required_fields: vec![
                FieldSpec {
                    name: "user_cid".into(),
                    field_type: "string".into(),
                    description: "CID of user".into(),
                },
                FieldSpec {
                    name: "tenant_cid".into(),
                    field_type: "string".into(),
                    description: "CID of tenant".into(),
                },
                FieldSpec {
                    name: "role".into(),
                    field_type: "string".into(),
                    description: "Role (admin, member, viewer)".into(),
                },
            ],
            optional_fields: vec![],
            required_cap: Some("membership:grant".into()),
        },
        ChipTypeSpec {
            chip_type: "ubl/token".into(),
            description: "Issue an access token for a user".into(),
            required_fields: vec![
                FieldSpec {
                    name: "user_cid".into(),
                    field_type: "string".into(),
                    description: "CID of user".into(),
                },
                FieldSpec {
                    name: "scope".into(),
                    field_type: "array".into(),
                    description: "Token scopes".into(),
                },
                FieldSpec {
                    name: "expires_at".into(),
                    field_type: "string".into(),
                    description: "RFC-3339 expiration".into(),
                },
                FieldSpec {
                    name: "kid".into(),
                    field_type: "string".into(),
                    description: "Key ID".into(),
                },
            ],
            optional_fields: vec![],
            required_cap: None,
        },
        ChipTypeSpec {
            chip_type: "ubl/revoke".into(),
            description: "Revoke any chip by CID".into(),
            required_fields: vec![
                FieldSpec {
                    name: "target_cid".into(),
                    field_type: "string".into(),
                    description: "CID of chip to revoke".into(),
                },
                FieldSpec {
                    name: "actor_cid".into(),
                    field_type: "string".into(),
                    description: "CID of revoking user".into(),
                },
                FieldSpec {
                    name: "reason".into(),
                    field_type: "string".into(),
                    description: "Revocation reason".into(),
                },
            ],
            optional_fields: vec![],
            required_cap: Some("revoke:execute".into()),
        },
        ChipTypeSpec {
            chip_type: "ubl/key.rotate".into(),
            description: "Rotate signing key material under admin policy".into(),
            required_fields: vec![
                FieldSpec {
                    name: "old_did".into(),
                    field_type: "string".into(),
                    description: "Current DID being rotated".into(),
                },
                FieldSpec {
                    name: "old_kid".into(),
                    field_type: "string".into(),
                    description: "Current key id being rotated".into(),
                },
            ],
            optional_fields: vec![FieldSpec {
                name: "reason".into(),
                field_type: "string".into(),
                description: "Rotation reason".into(),
            }],
            required_cap: Some("key:rotate".into()),
        },
        ChipTypeSpec {
            chip_type: "ubl/document".into(),
            description: "Submit a document for attestation".into(),
            required_fields: vec![],
            optional_fields: vec![
                FieldSpec {
                    name: "content".into(),
                    field_type: "string".into(),
                    description: "Document content".into(),
                },
                FieldSpec {
                    name: "content_cid".into(),
                    field_type: "string".into(),
                    description: "CID of external content".into(),
                },
            ],
            required_cap: None,
        },
        ChipTypeSpec {
            chip_type: "audit/report.request.v1".into(),
            description: "Request an on-demand audit report from aggregated views".into(),
            required_fields: vec![
                FieldSpec {
                    name: "name".into(),
                    field_type: "string".into(),
                    description: "Report name".into(),
                },
                FieldSpec {
                    name: "format".into(),
                    field_type: "string".into(),
                    description: "Output format: ndjson|csv|pdf".into(),
                },
            ],
            optional_fields: vec![
                FieldSpec {
                    name: "window".into(),
                    field_type: "string".into(),
                    description: "Relative window (e.g. 5m, 24h)".into(),
                },
                FieldSpec {
                    name: "range".into(),
                    field_type: "object".into(),
                    description: "Closed range with start/end RFC-3339".into(),
                },
            ],
            required_cap: Some("audit:report".into()),
        },
        ChipTypeSpec {
            chip_type: "audit/ledger.snapshot.request.v1".into(),
            description: "Create a pre-compaction ledger snapshot and evidence manifest".into(),
            required_fields: vec![FieldSpec {
                name: "range".into(),
                field_type: "object".into(),
                description: "Closed range with start/end RFC-3339".into(),
            }],
            optional_fields: vec![],
            required_cap: Some("audit:snapshot".into()),
        },
        ChipTypeSpec {
            chip_type: "ledger/segment.compact.v1".into(),
            description: "Compact ledger segments after snapshot validation".into(),
            required_fields: vec![
                FieldSpec {
                    name: "range".into(),
                    field_type: "object".into(),
                    description: "Range to compact".into(),
                },
                FieldSpec {
                    name: "snapshot_ref".into(),
                    field_type: "string".into(),
                    description: "Snapshot CID or receipt CID".into(),
                },
                FieldSpec {
                    name: "source_segments".into(),
                    field_type: "array".into(),
                    description: "Source segment descriptors".into(),
                },
                FieldSpec {
                    name: "mode".into(),
                    field_type: "string".into(),
                    description: "archive_then_delete or delete_with_rollup".into(),
                },
            ],
            optional_fields: vec![],
            required_cap: Some("ledger:compact".into()),
        },
        ChipTypeSpec {
            chip_type: "audit/advisory.request.v1".into(),
            description: "Request deterministic LLM advisory over aggregate audit artifacts".into(),
            required_fields: vec![
                FieldSpec {
                    name: "subject".into(),
                    field_type: "object".into(),
                    description: "Subject receipt reference".into(),
                },
                FieldSpec {
                    name: "policy_cid".into(),
                    field_type: "string".into(),
                    description: "Policy CID for SLO evaluation".into(),
                },
            ],
            optional_fields: vec![FieldSpec {
                name: "inputs".into(),
                field_type: "object".into(),
                description: "Aggregate input CIDs (dataset/histograms/hll)".into(),
            }],
            required_cap: Some("audit:advisory".into()),
        },
    ]
}

impl GateManifest {
    /// Generate OpenAPI 3.1 specification.
    pub fn to_openapi(&self) -> Value {
        let mut paths = serde_json::Map::new();

        // POST /v1/chips
        let mut chip_schemas = serde_json::Map::new();
        for ct in &self.chip_types {
            chip_schemas.insert(ct.chip_type.replace('/', "_"), self.chip_type_to_schema(ct));
        }

        paths.insert("/v1/chips".into(), json!({
            "post": {
                "operationId": "createChip",
                "summary": "Submit a chip through the KNOCK→WA→CHECK→TR→WF pipeline",
                "requestBody": {
                    "required": true,
                    "content": {
                        "application/json": {
                            "schema": {
                                "oneOf": self.chip_types.iter().map(|ct| {
                                    json!({"$ref": format!("#/components/schemas/{}", ct.chip_type.replace('/', "_"))})
                                }).collect::<Vec<_>>()
                            }
                        }
                    }
                },
                "responses": {
                    "200": { "description": "Pipeline result with receipt" },
                    "400": { "description": "KNOCK validation failure" },
                    "403": { "description": "Policy denied" },
                    "409": { "description": "Replay detected or dependency conflict" },
                    "422": { "description": "Invalid chip" },
                    "429": { "description": "Rate limit exceeded" },
                    "500": { "description": "Internal error" }
                }
            }
        }));

        // GET /v1/chips/{cid}
        paths.insert(
            "/v1/chips/{cid}".into(),
            json!({
                "get": {
                    "operationId": "getChip",
                    "summary": "Retrieve a chip by CID (ETag/If-None-Match supported)",
                    "parameters": [{
                        "name": "cid",
                        "in": "path",
                        "required": true,
                        "schema": { "type": "string", "pattern": "^b3:" }
                    }],
                    "responses": {
                        "200": { "description": "Chip data", "headers": {
                            "ETag": { "schema": { "type": "string" } },
                            "Cache-Control": { "schema": { "type": "string" } }
                        }},
                        "304": { "description": "Not Modified (ETag match)" },
                        "404": { "description": "Chip not found" }
                    }
                }
            }),
        );

        // GET /v1/cas/{cid}
        paths.insert(
            "/v1/cas/{cid}".into(),
            json!({
                "get": {
                    "operationId": "getCasObject",
                    "summary": "Retrieve a CAS object by CID (alias of /v1/chips/{cid})",
                    "parameters": [{
                        "name": "cid",
                        "in": "path",
                        "required": true,
                        "schema": { "type": "string", "pattern": "^b3:" }
                    }],
                    "responses": {
                        "200": { "description": "CAS object", "headers": {
                            "ETag": { "schema": { "type": "string" } },
                            "Cache-Control": { "schema": { "type": "string" } }
                        }},
                        "304": { "description": "Not Modified (ETag match)" },
                        "404": { "description": "Object not found" }
                    }
                }
            }),
        );

        // GET /v1/chips/{cid}/verify
        paths.insert(
            "/v1/chips/{cid}/verify".into(),
            json!({
                "get": {
                    "operationId": "verifyChip",
                    "summary": "Verify chip integrity by recomputing CID",
                    "parameters": [{
                        "name": "cid", "in": "path", "required": true,
                        "schema": { "type": "string" }
                    }],
                    "responses": {
                        "200": { "description": "Verification result" },
                        "404": { "description": "Chip not found" }
                    }
                }
            }),
        );

        // GET /v1/runtime/attestation
        paths.insert(
            "/v1/runtime/attestation".into(),
            json!({
                "get": {
                    "operationId": "getRuntimeAttestation",
                    "summary": "Get signed runtime self-attestation for the running gate instance",
                    "responses": {
                        "200": { "description": "Runtime self-attestation" },
                        "500": { "description": "Attestation generation failed" }
                    }
                }
            }),
        );

        // GET /v1/receipts/{cid}
        paths.insert(
            "/v1/receipts/{cid}".into(),
            json!({
                "get": {
                    "operationId": "getReceipt",
                    "summary": "Retrieve persisted raw receipt JSON by receipt CID",
                    "parameters": [{
                        "name": "cid", "in": "path", "required": true,
                        "schema": { "type": "string", "pattern": "^b3:" }
                    }],
                    "responses": {
                        "200": { "description": "Receipt JSON", "headers": {
                            "ETag": { "schema": { "type": "string" } },
                            "Cache-Control": { "schema": { "type": "string" } }
                        }},
                        "304": { "description": "Not Modified (ETag match)" },
                        "404": { "description": "Receipt not found" },
                        "503": { "description": "Receipt store unavailable" }
                    }
                }
            }),
        );

        // GET /v1/receipts/{cid}/trace
        paths.insert(
            "/v1/receipts/{cid}/trace".into(),
            json!({
                "get": {
                    "operationId": "getReceiptTrace",
                    "summary": "Retrieve policy trace for a receipt",
                    "parameters": [{
                        "name": "cid", "in": "path", "required": true,
                        "schema": { "type": "string" }
                    }],
                    "responses": {
                        "200": { "description": "Receipt trace" },
                        "404": { "description": "Receipt not found" }
                    }
                }
            }),
        );

        // GET /v1/receipts/{cid}/narrate
        paths.insert(
            "/v1/receipts/{cid}/narrate".into(),
            json!({
                "get": {
                    "operationId": "narrateReceipt",
                    "summary": "Generate deterministic on-demand narration for a receipt",
                    "parameters": [
                        {
                            "name": "cid", "in": "path", "required": true,
                            "schema": { "type": "string" }
                        },
                        {
                            "name": "persist", "in": "query", "required": false,
                            "schema": { "type": "boolean" }
                        }
                    ],
                    "responses": {
                        "200": { "description": "Narration response" },
                        "404": { "description": "Receipt not found" }
                    }
                }
            }),
        );

        json!({
            "openapi": "3.1.0",
            "info": {
                "title": "UBL Gate API",
                "version": self.version,
                "description": "Universal Business Ledger — every action is a chip, every output is a receipt."
            },
            "servers": [{ "url": self.base_url }],
            "paths": paths,
            "components": {
                "schemas": chip_schemas
            }
        })
    }

    /// Generate MCP tool manifest (JSON-RPC tools for AI agents).
    pub fn to_mcp_manifest(&self) -> Value {
        let mut tools = Vec::new();

        // ubl.deliver — submit a chip
        tools.push(json!({
            "name": "ubl.deliver",
            "description": "Submit a chip through the UBL pipeline (KNOCK→WA→CHECK→TR→WF). Returns a receipt.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "chip": {
                        "type": "object",
                        "description": "The chip body (must include @type, @ver, @world, @id)",
                    }
                },
                "required": ["chip"]
            }
        }));
        // MCP canonical alias
        tools.push(json!({
            "name": "ubl.chip.submit",
            "description": "Submit a chip through the UBL pipeline (KNOCK→WA→CHECK→TR→WF). Returns a receipt.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "chip": {
                        "type": "object",
                        "description": "The chip body (must include @type, @ver, @world, @id)",
                    }
                },
                "required": ["chip"]
            }
        }));

        // ubl.query — get a chip by CID
        tools.push(json!({
            "name": "ubl.query",
            "description": "Retrieve a chip by its content-addressed CID.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "cid": { "type": "string", "description": "Content ID (b3:...)" }
                },
                "required": ["cid"]
            }
        }));
        tools.push(json!({
            "name": "ubl.chip.get",
            "description": "Retrieve a chip by its content-addressed CID.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "cid": { "type": "string", "description": "Content ID (b3:...)" }
                },
                "required": ["cid"]
            }
        }));

        // ubl.receipt — get persisted receipt by CID
        tools.push(json!({
            "name": "ubl.receipt",
            "description": "Retrieve a persisted receipt by its receipt CID.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "cid": { "type": "string", "description": "Receipt CID to fetch" }
                },
                "required": ["cid"]
            }
        }));

        // ubl.verify — verify chip integrity
        tools.push(json!({
            "name": "ubl.verify",
            "description": "Verify a chip's integrity by recomputing its CID from stored content.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "cid": { "type": "string", "description": "Content ID to verify" }
                },
                "required": ["cid"]
            }
        }));
        tools.push(json!({
            "name": "ubl.chip.verify",
            "description": "Verify a chip's integrity by recomputing its CID from stored content.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "cid": { "type": "string", "description": "Content ID to verify" }
                },
                "required": ["cid"]
            }
        }));

        // registry.listTypes — list registered chip types
        tools.push(json!({
            "name": "registry.listTypes",
            "description": "List all registered chip types and their schemas.",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        }));

        // ubl.narrate — deterministic receipt narration
        tools.push(json!({
            "name": "ubl.narrate",
            "description": "Generate deterministic narration for a receipt CID.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "cid": { "type": "string", "description": "Receipt CID" },
                    "persist": { "type": "boolean", "description": "Persist narration advisory chip" }
                },
                "required": ["cid"]
            }
        }));
        tools.push(json!({
            "name": "ubl.receipt.trace",
            "description": "Fetch receipt trace metadata by receipt CID.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "cid": { "type": "string", "description": "Receipt CID" }
                },
                "required": ["cid"]
            }
        }));
        tools.push(json!({
            "name": "ubl.cid",
            "description": "Compute CID from canonical NRF-1 bytes for a JSON value.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "value": { "type": "object", "description": "JSON value to canonicalize and hash" }
                }
            }
        }));
        tools.push(json!({
            "name": "ubl.rb.execute",
            "description": "Execute RB-VM bytecode and return deterministic execution outcome.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "bytecode_hex": { "type": "string", "description": "TLV bytecode as hex string" },
                    "fuel_limit": { "type": "integer", "description": "Optional VM fuel limit" }
                },
                "required": ["bytecode_hex"]
            }
        }));

        json!({
            "name": "ubl-gate",
            "version": self.version,
            "description": "Universal Business Ledger — content-addressed chip pipeline with receipts",
            "tools": tools
        })
    }

    /// Generate WebMCP manifest (browser-based MCP discovery).
    pub fn to_webmcp_manifest(&self) -> Value {
        json!({
            "schema_version": "1.0",
            "name": "ubl-gate",
            "description": "Universal Business Ledger Gate",
            "base_url": self.base_url,
            "version": self.version,
            "capabilities": {
                "tools": true,
                "resources": true,
                "prompts": false
            },
            "tools": [
                {
                    "name": "ubl.deliver",
                    "method": "POST",
                    "path": "/v1/chips",
                    "content_type": "application/json",
                    "description": "Submit a chip through the pipeline"
                },
                {
                    "name": "ubl.query",
                    "method": "GET",
                    "path": "/v1/chips/{cid}",
                    "description": "Retrieve a chip by CID (supports ETag)"
                },
                {
                    "name": "ubl.receipt",
                    "method": "GET",
                    "path": "/v1/receipts/{cid}",
                    "description": "Retrieve raw persisted receipt by CID (supports ETag)"
                },
                {
                    "name": "ubl.verify",
                    "method": "GET",
                    "path": "/v1/chips/{cid}/verify",
                    "description": "Verify chip integrity"
                },
                {
                    "name": "ubl.trace",
                    "method": "GET",
                    "path": "/v1/receipts/{cid}/trace",
                    "description": "Get receipt policy trace"
                },
                {
                    "name": "ubl.narrate",
                    "method": "GET",
                    "path": "/v1/receipts/{cid}/narrate",
                    "description": "Generate deterministic receipt narration"
                }
            ],
            "resources": [
                {
                    "name": "chip",
                    "uri_template": "/v1/chips/{cid}",
                    "description": "A content-addressed chip",
                    "mime_type": "application/json"
                },
                {
                    "name": "cas",
                    "uri_template": "/v1/cas/{cid}",
                    "description": "A content-addressed object from CAS",
                    "mime_type": "application/json"
                },
                {
                    "name": "receipt",
                    "uri_template": "/v1/receipts/{cid}",
                    "description": "A persisted pipeline receipt",
                    "mime_type": "application/json"
                }
            ],
            "chip_types": self.chip_types.iter().map(|ct| {
                json!({
                    "type": ct.chip_type,
                    "description": ct.description,
                    "required_cap": ct.required_cap,
                })
            }).collect::<Vec<_>>()
        })
    }

    /// Helper: convert a ChipTypeSpec to a JSON Schema object.
    fn chip_type_to_schema(&self, ct: &ChipTypeSpec) -> Value {
        let mut properties = serde_json::Map::new();
        let mut required = vec![
            "@type".to_string(),
            "@id".to_string(),
            "@ver".to_string(),
            "@world".to_string(),
        ];

        properties.insert(
            "@type".into(),
            json!({"type": "string", "const": ct.chip_type}),
        );
        properties.insert("@id".into(), json!({"type": "string"}));
        properties.insert("@ver".into(), json!({"type": "string"}));
        properties.insert(
            "@world".into(),
            json!({"type": "string", "pattern": "^a/[^/]+(/t/[^/]+)?$"}),
        );

        if ct.required_cap.is_some() {
            properties.insert(
                "@cap".into(),
                json!({
                    "type": "object",
                    "description": "Required capability",
                    "properties": {
                        "action": { "type": "string" },
                        "audience": { "type": "string" },
                        "issued_by": { "type": "string" },
                        "issued_at": { "type": "string", "format": "date-time" },
                        "expires_at": { "type": "string", "format": "date-time" },
                        "signature": { "type": "string" }
                    },
                    "required": ["action", "audience", "issued_by", "signature"]
                }),
            );
            required.push("@cap".to_string());
        }

        for field in &ct.required_fields {
            properties.insert(
                field.name.clone(),
                json!({
                    "type": field.field_type,
                    "description": field.description
                }),
            );
            required.push(field.name.clone());
        }

        for field in &ct.optional_fields {
            properties.insert(
                field.name.clone(),
                json!({
                    "type": field.field_type,
                    "description": field.description
                }),
            );
        }

        json!({
            "type": "object",
            "description": ct.description,
            "properties": properties,
            "required": required
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_chip_types_has_all_core_types() {
        let types = default_chip_types();
        let names: Vec<&str> = types.iter().map(|t| t.chip_type.as_str()).collect();
        assert!(names.contains(&"ubl/app"));
        assert!(names.contains(&"ubl/user"));
        assert!(names.contains(&"ubl/tenant"));
        assert!(names.contains(&"ubl/membership"));
        assert!(names.contains(&"ubl/token"));
        assert!(names.contains(&"ubl/revoke"));
        assert!(names.contains(&"ubl/key.rotate"));
        assert!(names.contains(&"ubl/document"));
    }

    #[test]
    fn openapi_has_correct_version() {
        let m = GateManifest::default();
        let spec = m.to_openapi();
        assert_eq!(spec["openapi"], "3.1.0");
        assert_eq!(spec["info"]["title"], "UBL Gate API");
        assert_eq!(spec["info"]["version"], "1.0.0");
    }

    #[test]
    fn openapi_has_all_paths() {
        let m = GateManifest::default();
        let spec = m.to_openapi();
        let paths = spec["paths"].as_object().unwrap();
        assert!(paths.contains_key("/v1/chips"));
        assert!(paths.contains_key("/v1/chips/{cid}"));
        assert!(paths.contains_key("/v1/cas/{cid}"));
        assert!(paths.contains_key("/v1/chips/{cid}/verify"));
        assert!(paths.contains_key("/v1/runtime/attestation"));
        assert!(paths.contains_key("/v1/receipts/{cid}"));
        assert!(paths.contains_key("/v1/receipts/{cid}/trace"));
        assert!(paths.contains_key("/v1/receipts/{cid}/narrate"));
    }

    #[test]
    fn openapi_chip_schemas_exist() {
        let m = GateManifest::default();
        let spec = m.to_openapi();
        let schemas = spec["components"]["schemas"].as_object().unwrap();
        assert!(schemas.contains_key("ubl_app"));
        assert!(schemas.contains_key("ubl_user"));
        assert!(schemas.contains_key("ubl_membership"));
    }

    #[test]
    fn openapi_app_schema_requires_cap() {
        let m = GateManifest::default();
        let spec = m.to_openapi();
        let app_schema = &spec["components"]["schemas"]["ubl_app"];
        let required = app_schema["required"].as_array().unwrap();
        let required_strs: Vec<&str> = required.iter().map(|v| v.as_str().unwrap()).collect();
        assert!(required_strs.contains(&"@cap"), "ubl/app must require @cap");
        assert!(required_strs.contains(&"slug"));
    }

    #[test]
    fn openapi_user_schema_no_cap() {
        let m = GateManifest::default();
        let spec = m.to_openapi();
        let user_schema = &spec["components"]["schemas"]["ubl_user"];
        let required = user_schema["required"].as_array().unwrap();
        let required_strs: Vec<&str> = required.iter().map(|v| v.as_str().unwrap()).collect();
        assert!(
            !required_strs.contains(&"@cap"),
            "ubl/user should not require @cap in schema"
        );
    }

    #[test]
    fn openapi_get_chip_has_etag() {
        let m = GateManifest::default();
        let spec = m.to_openapi();
        let get_chip = &spec["paths"]["/v1/chips/{cid}"]["get"];
        let headers = &get_chip["responses"]["200"]["headers"];
        assert!(headers.get("ETag").is_some());
        assert!(headers.get("Cache-Control").is_some());
    }

    #[test]
    fn mcp_manifest_has_tools() {
        let m = GateManifest::default();
        let mcp = m.to_mcp_manifest();
        assert_eq!(mcp["name"], "ubl-gate");
        let tools = mcp["tools"].as_array().unwrap();
        let tool_names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert!(tool_names.contains(&"ubl.deliver"));
        assert!(tool_names.contains(&"ubl.query"));
        assert!(tool_names.contains(&"ubl.receipt"));
        assert!(tool_names.contains(&"ubl.verify"));
        assert!(tool_names.contains(&"registry.listTypes"));
        assert!(tool_names.contains(&"ubl.narrate"));
    }

    #[test]
    fn mcp_deliver_has_input_schema() {
        let m = GateManifest::default();
        let mcp = m.to_mcp_manifest();
        let tools = mcp["tools"].as_array().unwrap();
        let deliver = tools.iter().find(|t| t["name"] == "ubl.deliver").unwrap();
        assert!(deliver["inputSchema"]["properties"]["chip"].is_object());
        let required = deliver["inputSchema"]["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v == "chip"));
    }

    #[test]
    fn webmcp_manifest_structure() {
        let m = GateManifest::default();
        let wm = m.to_webmcp_manifest();
        assert_eq!(wm["schema_version"], "1.0");
        assert_eq!(wm["name"], "ubl-gate");
        assert!(wm["capabilities"]["tools"].as_bool().unwrap());
        assert!(wm["capabilities"]["resources"].as_bool().unwrap());
    }

    #[test]
    fn webmcp_has_tools_and_resources() {
        let m = GateManifest::default();
        let wm = m.to_webmcp_manifest();
        let tools = wm["tools"].as_array().unwrap();
        assert!(tools.len() >= 4);
        let resources = wm["resources"].as_array().unwrap();
        assert!(!resources.is_empty());
        assert!(tools.iter().any(|t| t["name"] == "ubl.receipt"));
        assert!(resources.iter().any(|r| r["name"] == "receipt"));
        assert!(resources.iter().any(|r| r["name"] == "cas"));
    }

    #[test]
    fn webmcp_lists_chip_types() {
        let m = GateManifest::default();
        let wm = m.to_webmcp_manifest();
        let types = wm["chip_types"].as_array().unwrap();
        assert!(types.len() >= 8);
        let type_names: Vec<&str> = types.iter().map(|t| t["type"].as_str().unwrap()).collect();
        assert!(type_names.contains(&"ubl/app"));
        assert!(type_names.contains(&"ubl/revoke"));
        assert!(type_names.contains(&"ubl/key.rotate"));
        assert!(type_names.contains(&"audit/report.request.v1"));
    }

    #[test]
    fn custom_base_url() {
        let m = GateManifest {
            base_url: "https://custom.example.com".into(),
            version: "2.0.0".into(),
            chip_types: default_chip_types(),
        };
        let spec = m.to_openapi();
        assert_eq!(spec["servers"][0]["url"], "https://custom.example.com");
        assert_eq!(spec["info"]["version"], "2.0.0");

        let wm = m.to_webmcp_manifest();
        assert_eq!(wm["base_url"], "https://custom.example.com");
    }

    #[test]
    fn all_three_manifests_are_valid_json() {
        let m = GateManifest::default();
        let openapi = m.to_openapi();
        let mcp = m.to_mcp_manifest();
        let webmcp = m.to_webmcp_manifest();

        // All should serialize to string and back without loss
        let s1 = serde_json::to_string(&openapi).unwrap();
        let _: Value = serde_json::from_str(&s1).unwrap();

        let s2 = serde_json::to_string(&mcp).unwrap();
        let _: Value = serde_json::from_str(&s2).unwrap();

        let s3 = serde_json::to_string(&webmcp).unwrap();
        let _: Value = serde_json::from_str(&s3).unwrap();
    }
}
