# UBL MASTER — Unified Task List

**Status**: Single source of truth for all work — done, in progress, and planned
**Date**: February 20, 2026
**Spec**: [ARCHITECTURE.md](./ARCHITECTURE.md) — engineering source of truth
**Docs Index**: [docs/INDEX.md](./docs/INDEX.md)

---

## Completed Work

### Foundation Sprints (S1–S4)

_Note: test counts in this section are historical snapshots at sprint completion. Use the measured table below for current totals._

- [x] **S1 — Canon + CID**: NRF-1.1 encoding, CID computation, Universal Envelope, `ublx` CLI, type code table (64 tests in `ubl_ai_nrf1`)
- [x] **S2 — RB-VM + Policy**: Real TR stage execution via rb_vm, fuel ceiling (1M units), unified `Decision` enum, nonce/anti-replay (16-byte hex), policy lockfile (33 tests in `rb_vm`)
- [x] **S3 — Receipts + Storage + Gate**: `UnifiedReceipt` with HMAC-BLAKE3 auth chain (11 tests), ChipStore wired into pipeline WF, `NdjsonLedger` (6 tests), KNOCK stage (11 tests), canonical `UblError` responses (8 tests), gate rewrite with real ChipStore lookups, genesis bootstrap (idempotent, self-signed)
- [x] **S4 — WASM + URLs + EventBus**: WASM adapter ABI (NRF→WASM→NRF), adapter registry, Rich URL generation, event bus with idempotency, `ublx explain`

### Post-Sprint Work

- [x] **PS1 — AI Passport**: `ubl/ai.passport` chip type, advisory wiring, gate endpoints for advisories and passport verification
- [x] **PS2 — Auth as Pipeline**: `auth.rs` with 8 onboarding chip types, body validation via `from_chip_body`, dependency chain enforcement at CHECK, drift endpoints removed (34 unit + 10 integration tests)
- [x] **Onboarding**: Full lifecycle `ubl/app` → `ubl/user` → `ubl/tenant` → `ubl/membership` → `ubl/token` → `ubl/revoke` + `ubl/worldscope` + `ubl/role`. Dependency chain enforced. `DependencyMissing` (409) error code. 141 total tests in `ubl_runtime`.
- [x] **ARCHITECTURE.md maintenance (rev 2→4)**: Added §0 Protocol Stack (8-layer table), updated §1 evolution table, rewrote §2 crate map, removed BLOCKERs from §5.2/§5.3, updated §16 to evidence-based current state, updated §17 tech debt
- [x] **Policy documents**: `P0_GENESIS_POLICY.json`, `P1_POLICY_UPDATE.json`, `ROLLOUT_P0_TO_P1.md`

### Test Counts (measured on February 20, 2026)

Method: `cargo test -p <crate> -- --list` (unit + integration test harness totals)

| Crate | Tests |
|---|---|
| `rb_vm` | 79 |
| `ubl_receipt` | 22 |
| `ubl_runtime` | 352 |
| `ubl_ai_nrf1` | 108 |
| `ubl_kms` | 16 |
| `ubl_unc1` | 57 |
| `ubl_chipstore` | 10 |
| `ubl_types` | 24 |
| `ubl_gate` | 21 |
| **Total (measured set)** | **689** |

---

## Resolved — Critical

| # | Task | Location | Notes |
|---|---|---|---|
| C1 | **Fix `mh: "sha2-256"` metadata label** | `ubl_receipt/src/lib.rs:62` | ✅ Done. Changed `mh: "sha2-256"` → `mh: "blake3"`. One-line fix. |
| C2 | **Fix 4 chip_format test failures** | `ubl_ai_nrf1::chip_format` | ✅ Done. Tests were already passing (4/4) — stale report from earlier sprint. |
| C3 | **Error code enum complete** | `ubl_runtime::error_response` | ✅ Done. Added 8 `ErrorCode` variants (`FUEL_EXHAUSTED`, `TYPE_MISMATCH`, `STACK_UNDERFLOW`, `CAS_NOT_FOUND`, `REPLAY_DETECTED`, `CANON_ERROR`, `SIGN_ERROR`, `STORAGE_ERROR`) + 8 matching `PipelineError` variants. Wired `ExecError` → specific `PipelineError` in `stage_transition`. `ReplayDetected` used for nonce replay. HTTP mappings: VM errors→422, replay→409, storage→500. `is_vm_error()` helper. 19 error_response tests (was 8). |

---

## Resolved — Hardening & Features

| # | Task | Notes |
|---|---|---|
| H1 | **Signing key from env** | Done via H14 (`ubl_kms`). `signing_key_from_env()` loads from `SIGNING_KEY_HEX`. Legacy `ubl_receipt` still hardcoded — migrate callers. |
| H7 | **Signature domain separation** | Done via H14 (`ubl_kms`). `domain::RECEIPT`, `RB_VM`, `CAPSULE`, `CHIP`. Legacy `ubl_receipt` signing still lacks domain — migrate. |
| H13 | **ρ test vectors** | 14 JSON edge-case files in `kats/rho_vectors/`. 16 integration tests in `crates/ubl_ai_nrf1/tests/rho_vectors.rs`. |
| H14 | **`ubl_kms` crate** | `sign_canonical`, `verify_canonical`, `signing_key_from_env()`, domain separation, DID/KID derivation. 16 tests. |
| H15 | **Prometheus `/metrics`** | Counters + histogram on gate. `GET /metrics`. |
| F8 | **Chip verification endpoint** | `GET /v1/chips/:cid/verify` — recomputes CID, checks receipt, returns `ubl/chip.verification`. |
| F11 | **Makefile** | Targets: `build`, `test`, `fmt`, `fmt-check`, `lint`, `check`, `kat`, `gate`, `clean`. |
| F12 | **`ublx disasm`** | `rb_vm::disasm` module (8 tests) + `ublx disasm` subcommand (hex or file). |
| H11 | **`RuntimeInfo` + `BuildMeta` in receipt** | `RuntimeInfo::capture()` hashes binary at startup (BLAKE3), `BuildMeta` records rustc/os/arch/profile/git. `rt` field on `UnifiedReceipt` (optional, omitted when None). Wired into `UblPipeline` — every receipt carries runtime provenance. PF-01 determinism contract added to ARCHITECTURE.md. 7 new tests (18 total in ubl_receipt). |
| H12 | **Opcode byte conflict** | Already resolved — ARCHITECTURE.md §4.4 table already matches code (Dup=0x14, Swap=0x15, VerifySig=0x16). Stale tasklist entry. |
| H2 | **Real DID resolution** | All 5 `"did:key:placeholder"` occurrences replaced. `UblPipeline` now derives `did:key:z...` and `kid` from Ed25519 signing key via `ubl_kms`. Key loaded from `SIGNING_KEY_HEX` env or auto-generated for dev. `PipelineSigner` uses real `ubl_kms::sign_bytes` with `RB_VM` domain separation. Zero placeholder DIDs remain. |
| H3 | **`NaiveCanon` → full ρ** | `RhoCanon` in `rb_vm/src/canon.rs` implements full ρ rules: NFC normalization, BOM rejection, control char rejection, null stripping from maps, key sorting, recursive. Idempotent: ρ(ρ(v))=ρ(v). **UNC-1 §3/§6 aligned**: raw floats poisoned by ρ, rejected at KNOCK (KNOCK-008), mapped to `KNOCK_RAW_FLOAT` error code (400). `RhoCanon::validate()` for strict mode. `PipelineCanon` delegates to `RhoCanon`. 19 canon tests, 3 KNOCK float tests, 1 error_response test. |
| H8 | **Rate limiting** | `rate_limit.rs` in `ubl_runtime`. Sliding-window per-key limiter. `GateRateLimiter` composite: per-DID (100/min), per-tenant (1000/min), per-IP (10/min). Check order: IP→tenant→DID. `prune()` for memory cleanup. 13 tests. |
| H9 | **UNC-1 core ops** | Full `ubl_unc1` crate: `add/sub/mul/div` with INT→DEC→RAT→BND promotion, `to_dec` (6 rounding modes incl. banker’s), `to_rat` (continued fraction with denominator limit), `from_f64_bits` (IEEE-754 frontier → exact BND interval), `compare`, BND interval arithmetic, unit enforcement, serde roundtrips. 57 tests. |
| H10 | **Policy lockfile** | `policy_lock.rs` in `ubl_runtime`. `PolicyLock` struct with YAML parse/serialize, `pin()`, `verify()` against loaded policies. Detects mismatches, missing, and extra policies. `LockVerification` with `Display`. 11 tests. |
| PR-A P0.1 | **Rigid idempotency** | `idempotency.rs` — `IdempotencyStore` keyed by `(@type,@ver,@world,@id)`. Replay returns cached `receipt_cid`. Wired into `process_chip`. 10 tests. |
| PR-A P0.2 | **Canon-aware rate limit** | `rate_limit.rs` — `CanonFingerprint` (BLAKE3 of NRF-1 bytes) + `CanonRateLimiter`. Cosmetic JSON variations hit same bucket. 7 new tests (20 total rate_limit). |
| PR-A P0.3 | **Secure bootstrap (capability)** | `capability.rs` — `Capability` struct with action/audience/expiration/signature. `ubl/app` requires `cap.registry:init`, first `ubl/user` requires `cap.registry:init`. Wired into `check_onboarding_dependencies`. 15 tests. |
| PR-A P0.4 | **Receipts-as-AuthZ** | `ubl/membership` requires `cap.membership:grant`, `ubl/revoke` requires `cap.revoke:execute`. Validates audience/scope/expiration. Wired into pipeline CHECK stage. |
| PR-B P1.5 | **Canonical stage events** | `ReceiptEvent` extended with `input_cid`, `output_cid`, `binary_hash`, `build_meta`, `world`, `actor`, `latency_ms`. Enriched in `publish_receipt_event`. CID chain: WA→TR→WF. 1 integration test. |
| PR-B P1.6 | **ETag/cache for read-only queries** | `GET /v1/chips/:cid`, `GET /v1/cas/:cid`, and `GET /v1/receipts/:cid` return `ETag` = CID and immutable cache headers. `If-None-Match` → 304 Not Modified. |
| PR-B P1.7 | **Unified error taxonomy** | 4 new `ErrorCode` variants (`Unauthorized`/401, `NotFound`/404, `TooManyRequests`/429, `Unavailable`/503). `category()` → 8 categories (BadInput, Unauthorized, Forbidden, NotFound, Conflict, TooManyRequests, Internal, Unavailable). `mcp_code()` → JSON-RPC 2.0 error codes. 7 new tests (27 total error_response). |
| PR-C P2.8 | **Manifest generator** | `manifest.rs` — `GateManifest` produces OpenAPI 3.1, MCP tool manifest, WebMCP manifest from registered chip types. Gate serves `/openapi.json`, `/mcp/manifest`, `/.well-known/webmcp.json`. 14 tests. |
| PR-C P2.9 | **MCP server proxy** | `POST /mcp/rpc` — JSON-RPC 2.0 handler with `tools/list` + `tools/call`. Dispatches to `ubl.deliver`, `ubl.query`, `ubl.receipt`, `ubl.verify`, `registry.listTypes`. Uses `mcp_code()` for error mapping. |
| PR-C P2.10 | **Meta-chips for type registration** | `meta_chip.rs` — `ubl/meta.register` (mandatory KATs, reserved prefix check, KAT @type validation), `ubl/meta.describe`, `ubl/meta.deprecate`. 16 tests. |
| W1 | **SledBackend wired into gate** | Gate uses `SledBackend` at `./data/chips` instead of `InMemoryBackend`. Persistent chip storage across restarts. |
| W2 | **NdjsonLedger wired into pipeline** | `NdjsonLedger` at `./data/ledger` appended after WF. Audit trail per `{app}/{tenant}/receipts.ndjson`. |
| W3 | **Idempotent replay returns 200** | `process_chip` returns `Ok(PipelineResult { replayed: true })` with cached receipt instead of `Err(ReplayDetected)`. Gate returns `X-UBL-Replay: true` header. `UnifiedReceipt::from_json()` added. 2 new tests. |
| PF-02 | **Determinism boundary codified** | ARCHITECTURE.md §15.1: chip CID = deterministic (canonical content), receipt CID = contextually unique (time, nonce, RuntimeInfo). Never compare receipt CIDs for content equality. |

---

## Operational Priorities (no speculative milestones)

This document tracks implemented work and concrete backlog only. Dated windows, synthetic gates, and fixed-duration stability claims were removed to avoid inventing planning constraints not tied to code evidence.

Current priorities:

- Keep determinism evidence fresh (`kats/`, property tests, and CI reproducibility checks).
- Keep trust-chain hardening explicit (capability verification, auth-chain verification, key lifecycle).
- Continue parse-once typed boundaries in runtime paths where raw JSON handling still exists.
- Keep observability and release readiness tied to measurable artifacts (`/metrics`, traces, runbooks, readiness checks).

---

## Open — Hardening the Base (0 remaining)

| # | Task | Location | Notes |
|---|---|---|---|
| H4 | **P0→P1 rollout automation** | `ROLLOUT_P0_TO_P1.md` | ✅ Done. Added `scripts/rollout_p0_p1_check.sh` + `make rollout-check` preflight with runtime hash allowlist validation, activation_time lead-window checks, signature quorum checks, core type coverage checks, and explicit break-glass mode/reporting (`docs/ops/ROLLOUT_AUTOMATION.md`). |
| H5 | **Newtype pattern** | All crates | ✅ Done. `ubl_types` crate with `Cid`, `Did`, `Kid`, `Nonce`, `ChipType`, `World` newtypes (24 tests). Migrated `StoredChip.cid`/`receipt_cid` → `TypedCid`, `ExecutionMetadata.executor_did` → `TypedDid`, `UnifiedReceipt` fields (`world`/`did`/`kid`/`nonce`/`receipt_cid`/`prev_receipt_cid`), `PipelineReceipt.body_cid` → `TypedCid`. Serde-transparent wire compat preserved. |
| H6 | **Parse, Don't Validate** | Pipeline + chip types | ✅ Done. Pipeline now enforces typed request parse once (`@type/@id/@world` + body object), with stages consuming `ParsedChipRequest` instead of re-validating raw request bodies. |

---

## Open — Next Features

| # | Task | Priority | Notes |
|---|---|---|---|
| F1 | **PS3 — Runtime certification** | ✅ Done | `RuntimeInfo` extended with `runtime_hash` + `certs`, signed `SelfAttestation` (`ubl_runtime::runtime_cert`) verifies against DID key, runtime metadata attached to receipts, and gate endpoint `GET /v1/runtime/attestation` exposed in OpenAPI. Future: `runtime-llm`, `runtime-wasm`, `runtime-tee` modules. |
| F2 | **PS4 — Structured tracing** | ✅ Done | Runtime and gate migrated to `tracing` with per-stage structured spans and operational logging path for SLO/incident workflows. |
| F3 | **PS5 — LLM Observer narration** | ✅ Done | Added deterministic on-demand narration endpoint `GET /v1/receipts/:cid/narrate` (optional `persist=true` stores `ubl/advisory` with hook `on_demand`) and MCP tool `ubl.narrate`. |
| F4 | **Property-based testing** | ✅ Done | Proptest expansion completed in `ubl_canon` + `ubl_unc1` + `ubl_ai_nrf1` (CID/sign invariants, cross-mode/domain checks, numeric edge behavior, and canon edge generators for order/null-stripping/Unicode-control/NFC constraints). |
| F5 | **UNC-1 numeric opcodes** | ✅ Done | Implemented in `rb_vm` (`0x17..0x21`) with coverage in `crates/rb_vm/tests/num_opcodes.rs`. |
| F6 | **UNC-1 KNOCK validation** | ✅ Done | KNOCK now validates strict `@num` atoms, rejects malformed numeric atoms (`KNOCK-009`), and preserves raw-float rejection path (`KNOCK-008`). |
| F7 | **UNC-1 migration flags** | ✅ Done | Added rollout flags `REQUIRE_UNC1_NUMERIC` and `F64_IMPORT_MODE=bnd|reject`; added `normalize_numbers_to_unc1(...)` in `ubl_ai_nrf1::chip_format` compile flow. |
| F9 | **Key rotation as chip** | ✅ Done | `ubl/key.rotate` implemented with typed payload validation, mandatory `key:rotate` capability check, deterministic Ed25519 material derivation during TR, and persisted `ubl/key.map` old→new mapping in ChipStore. Includes replay-safe flow tests. |
| F10 | **CAS backends for ChipStore** | ✅ Done | Added `FsBackend` and `S3Backend` (S3-compatible local emulation) with roundtrip tests and no regression on existing backends. |
| F13 | **Post-quantum signature stubs** | ✅ Done | Added feature-gated `ubl_kms::pq_mldsa3` stub module (`--features pq_mldsa3`) with dual-sign API shape and tests. |

---

## Protocol Horizons (future — after base is solid)

These are not tasks yet. They become tasks when the base hardening items (H1–H15) and critical items (C1–C3) are resolved.

### Money Protocol

New chip types: `ubl/payment`, `ubl/invoice`, `ubl/settlement`, `ubl/escrow`. Transfers require `human_2ofN` quorum via autonomia matrix. Double-entry by construction. Audit trail = receipt chain. Reconciliation = CID comparison.

### Media Protocol (VCX-Core)

Video as content-addressed hash-graph of 64×64 tiles. Editing = manifest rewrite (zero recompression). Certified Runtime as deterministic video editor. LLMs curate by reading NRF-1 manifests, not decoding pixels. Full spec in `docs/visao/VCX-Core.md`. See also `CERTIFIED_RUNTIME.md`.

### Document Protocol

`ubl/document`, `ubl/signature`, `ubl/notarization`. Notarization as a chip. Witnessing as a chip. Every document version is a CID with a receipt.

### Federation Protocol

Inter-UBL communication via chip exchange. Cross-organization policy propagation. Global chip addressing.

### MCP Server (Model Context Protocol)

JSON-RPC over WebSocket server exposing UBL tools to LLMs and external integrations. Critical for real-world adoption — lets any MCP-compatible client (Claude, Cursor, custom agents) interact with UBL natively.

**Tools to expose:**

- `ubl.chip.submit` — submit a chip (KNOCK→WA→CHECK→TR→WF), return receipt
- `ubl.chip.get` — retrieve chip by CID
- `ubl.chip.verify` — recompute and verify chip integrity
- `ubl.receipt.trace` — get full policy trace for a receipt
- `ubl.kats.run` — run KAT suite, return pass/fail
- `ubl.schemas.list` / `ubl.schemas.get` — list and retrieve JSON schemas
- `ubl.rb.execute` — execute RB-VM bytecode with payload, return verdict
- `ubl.cid` — compute CID for arbitrary canonical JSON

**Architecture:** Thin WebSocket layer over existing `UblPipeline` + `ChipStore`. TLS optional (dev: self-signed, prod: real certs). Token/JWT auth. Rate limiting per token. Fuel/timeout per request. All responses are canonical JSON.

**Reference:** `ubl-ultimate-main/mcp/server/` has a working (rough) implementation with TLS, JWT/OIDC, JWKS, rate limiting via `governor`, and per-message timeouts. Not copy-worthy as-is (compile errors, mixed concerns), but the tool dispatch pattern and security layering are good starting points.

---

## Reference Documents

| File | Purpose | Status |
|---|---|---|
| `ARCHITECTURE.md` | Engineering spec + protocol stack (source of truth) | ✅ Current (rev 4) |
| `TASKLIST.md` | This file — unified task tracking | ✅ Current |
| `README.md` | Repo README and quick start | ✅ Updated |
| `GOVERNANCE.md` | Project/process governance | ✅ New root canonical entry |
| `SECURITY.md` | Signature/verification trust model | ✅ New root canonical entry |
| `docs/INDEX.md` | Documentation entrypoint and ownership map | ✅ New canonical index |
| `docs/STANDARDS.md` | Documentation standards and metadata policy | ✅ New |
| `ROLLOUT_P0_TO_P1.md` | Bootstrap sequence P0→P1 | ✅ Valid + automated checks |
| `CERTIFIED_RUNTIME.md` | Certified Runtime roles and RACI | ✅ Valid reference |
| `docs/visao/MANIFESTO_DA_REINVENCAO.md` | Vision, horizons, and consolidated roadmap | ✅ New canonical vision source |
| `/openapi.json` + `crates/ubl_runtime/src/manifest.rs` | API and MCP contract source | ✅ Active source |
| `docs/reference/README.md` | Runtime/gate reference source map | ✅ New |
| `crates/ubl_runtime/src/error_response.rs` | Canonical error taxonomy source | ✅ Active source |
| `docs/security/CRYPTO_TRUST_MODEL.md` | Compatibility pointer to `SECURITY.md` | ✅ Kept for link stability |
| `docs/lifecycle/RELEASE_READINESS.md` | Release gate checklist and evidence | ✅ New |
| `docs/changelog/CHANGELOG.md` | Documentation and release change log | ✅ New |
| `docs/archive/2026-02/` | Archived superseded docs | ✅ Historical only |
| `docs/visao/VCX-Core.md` | VCX-Core living spec — media protocol | ✅ Valid (deferred) |
| `P0_GENESIS_POLICY.json` | Genesis policy | ✅ Valid |
| `P1_POLICY_UPDATE.json` | First policy update | ✅ Valid |
| `docs/canon/UNC-1.md` | UNC-1 Numeric Canon spec (INT/DEC/RAT/BND + units) | ✅ New |
| `kats/unc1/unc1_kats.v1.json` | Known Answer Tests for UNC-1 | ✅ New |
| `schemas/unc-1.schema.json` | UNC-1 machine-readable contract | ✅ Active source |
| `docs/vm/OPCODES_NUM.md` | UNC-1 opcode spec for RB-VM | ✅ New |
| `docs/migration/UNC1_MIGRATION.md` | UNC-1 migration phases and flags | ✅ New |

---

*The pattern is always the same: define `@type`s, write policies, maybe add a WASM adapter. The pipeline, gate, receipts, and registry are already there. That's the leverage.*
