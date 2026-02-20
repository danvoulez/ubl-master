# Reference Sources (Official)

`docs/reference/*.md` was intentionally removed to avoid drift.
Reference contracts are now source-of-truth artifacts exported or defined by Rust code.

## API

- Runtime endpoint: `GET /openapi.json`
- Source generator: `crates/ubl_runtime/src/manifest.rs` (`GateManifest::to_openapi`)
- Rust export binary: `cargo run -p ubl_runtime --bin export_reference_json`

## Errors

- Source of truth: `crates/ubl_runtime/src/error_response.rs` (`ErrorCode`, category/http/mcp mappings)
- Rust export binary: `cargo run -p ubl_runtime --bin export_reference_json`

## Configuration

- Source of truth: environment-variable reads in runtime/gate crates:
  - `services/ubl_gate/src/main.rs`
  - `crates/ubl_runtime/src/pipeline/mod.rs`
  - `crates/ubl_runtime/src/rich_url.rs`
  - `crates/ubl_runtime/src/durable_store.rs`
  - `crates/ubl_runtime/src/transition_registry.rs`

## Numerics (UNC-1)

- JSON Schema contract: `schemas/unc-1.schema.json`
- Canon spec narrative: `docs/canon/UNC-1.md`
- VM numeric opcodes: `docs/vm/OPCODES_NUM.md`
