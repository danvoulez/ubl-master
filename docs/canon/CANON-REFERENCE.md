# Canon Reference (Exhaustive)

**Status**: active  
**Owner**: Core Runtime  
**Last reviewed**: 2026-02-20

This document is the full canonical registry for UBL.
It is declarative, exhaustive by topic, and references normative docs, code, and validation evidence.

## 1) Envelope Canon

- **Invariant**: Every canonical artifact carries `@id`, `@type`, `@ver`, `@world`.
- **Order attention**: `@type` and `@id` ordering rules must remain stable where declared.
- **Normative**: `ARCHITECTURE.md` (canon/envelope sections).
- **Code**: `crates/ubl_ai_nrf1/src/nrf.rs`, `crates/ubl_ai_nrf1/src/chip_format.rs`.
- **Validation**: `crates/ubl_ai_nrf1/tests/` + KAT suites.

## 2) RHO Canon (Structural Normalization)

- **Invariant**:
  - Unicode NFC.
  - Deterministic key ordering.
  - Null stripping from maps.
  - Rejection of malformed/control/BOM cases per canon rules.
- **Normative**: `ARCHITECTURE.md` + task evidence entries.
- **Code**: `crates/rb_vm/src/canon.rs`.
- **Validation**: `kats/rho_vectors/`, `crates/ubl_ai_nrf1/tests/rho_vectors.rs`.

## 3) NRF-1 Byte Canon

- **Invariant**: Canonical bytes are the hash/sign substrate.
- **CID rule**: same canonical input -> same NRF-1 bytes -> same `b3:` chip CID.
- **Normative**: `ARCHITECTURE.md` (Canon & CID contract).
- **Code**: `crates/ubl_ai_nrf1/src/nrf.rs`.
- **Validation**: KATs in `kats/`, runtime and VM tests.

## 4) CID and Hash Canon

- **Invariant**: BLAKE3 canonical path for chip CID contracts.
- **Boundary**:
  - Chip CID: content-deterministic.
  - Receipt CID: execution/event-specific.
- **Normative**: `ARCHITECTURE.md` PF-01/PF-02.
- **Code**: `crates/ubl_ai_nrf1/`, `crates/ubl_receipt/`.
- **Validation**: determinism tests in `rb_vm`, runtime integration tests.

## 5) UNC-1 Numeric Canon

- **Invariant**: no raw IEEE-754 in canonical payload path.
- **Atoms**: `int/1`, `dec/1`, `rat/1`, `bnd/1`.
- **Schema contract**: `schemas/unc-1.schema.json`.
- **Narrative spec**: `docs/canon/UNC-1.md`.
- **VM semantics**: `docs/vm/OPCODES_NUM.md`.
- **Code**: `crates/ubl_unc1/`, `crates/ubl_ai_nrf1/src/chip_format.rs`, `crates/ubl_runtime/src/knock.rs`.
- **Validation**: `kats/unc1/`, numeric opcode tests in `crates/rb_vm/tests/num_opcodes.rs`.

## 6) JSON Contract and Order Discipline

- **Invariant**: JSON payload contracts must not contradict schema and canonicalization rules.
- **Attention point**: changing field shape/order semantics requires coordinated update of:
  - schema files in `schemas/`
  - canonical spec docs in `docs/canon/`
  - parser/normalizer code in runtime/nrf/canon modules
  - KATs/tests.
- **Primary schema**: `schemas/unc-1.schema.json`.

## 7) RB-VM Canon

- **Invariant**: deterministic execution only.
- **No-go**: heuristic or nondeterministic opcode semantics.
- **Opcode canon**: `docs/vm/OPCODES_NUM.md` + VM tables in architecture.
- **Code**: `crates/rb_vm/`.
- **Validation**: VM law/property suites under `crates/rb_vm/tests/`.

## 8) Fuel Canon

- **Invariant**: fuel must remain deterministic and auditable.
- **Impact**: opcode/fuel table changes affect reproducibility/version compatibility.
- **Normative**: `ARCHITECTURE.md` acceptance and VM sections.
- **Code**: `crates/rb_vm/`, runtime transition path.

## 9) Pipeline Canon

- **Invariant**: `KNOCK -> WA -> CHECK -> TR -> WF`.
- **No-go**: state mutation outside pipeline/receipt chain.
- **Normative**: `ARCHITECTURE.md` pipeline sections.
- **Code**: `crates/ubl_runtime/src/pipeline/`.

## 10) Time Canon

- **Invariant**:
  - content canonicalization is time-independent;
  - execution proof can carry time/nonce/runtime context.
- **No-go**: wall-clock leakage into chip CID substrate.
- **Normative**: PF-01/PF-02 in `ARCHITECTURE.md`.

## 11) Policy Canon

- **Invariant**: policy context is explicit/immutable per receipt scope.
- **Lock discipline**: policy lock/rollout checks must remain verifiable.
- **Normative**: `ROLLOUT_P0_TO_P1.md`, architecture policy sections.
- **Code**: `crates/ubl_runtime/src/policy_lock.rs`.

## 12) Receipt and Auth-Chain Canon

- **Invariant**: receipts are authoritative execution proof; auth chain integrity is enforced.
- **Normative**: `ARCHITECTURE.md`, `CERTIFIED_RUNTIME.md`, `SECURITY.md`.
- **Code**: `crates/ubl_receipt/src/unified.rs`, `services/ubl_gate/src/main.rs` verification path.

## 13) Crypto Domain Canon

- **Invariant**: domain-separated signatures and strict verification semantics.
- **Normative**: `SECURITY.md`.
- **Code**: `crates/ubl_kms/`, `crates/ubl_runtime/src/rich_url.rs`, `crates/ubl_receipt/src/unified.rs`.

## 14) Error Canon

- **Invariant**: error codes, categories, HTTP/MCP mappings are code-level contracts.
- **Source of truth**: `crates/ubl_runtime/src/error_response.rs`.
- **No-go**: adding/modifying public error behavior without contract review.

## 15) API Contract Canon

- **Invariant**: official API contract is runtime-exported OpenAPI.
- **Source of truth**:
  - endpoint: `/openapi.json`
  - generator: `crates/ubl_runtime/src/manifest.rs`.
- **MCP/WebMCP**: same source module (`manifest.rs`).

## 16) Canon Evidence Registry

- **KATs**: `kats/` (`rho_vectors`, `unc1`, and related suites).
- **Runtime/VM tests**: `crates/rb_vm/tests/`, runtime tests under `crates/ubl_runtime/`.
- **Release/readiness evidence**: `docs/lifecycle/RELEASE_READINESS.md`.

## 17) Canon Change Protocol

A change touching canon must update all affected layers in one PR:

1. Normative source(s) (`ARCHITECTURE.md`, `docs/canon/*`, schema/spec docs).
2. Implementation source(s) (runtime/VM/NRF/receipt/security paths).
3. Evidence (KATs/tests).
4. Indexing (`docs/INDEX.md`, root `START-HERE.md` if needed).

If one of these four is missing, canon drift risk is high.
