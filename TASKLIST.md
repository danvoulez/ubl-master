# UBL MASTER — Unified Task List

**Status**: Single source of truth for all work — done, in progress, and planned
**Date**: February 16, 2026
**Spec**: [ARCHITECTURE.md](./ARCHITECTURE.md) — engineering source of truth

---

## Completed Work

### Foundation Sprints (S1–S4)

- [x] **S1 — Canon + CID**: NRF-1.1 encoding, CID computation, Universal Envelope, `ublx` CLI, type code table (64 tests in `ubl_ai_nrf1`)
- [x] **S2 — RB-VM + Policy**: Real TR stage execution via rb_vm, fuel ceiling (1M units), unified `Decision` enum, nonce/anti-replay (16-byte hex), policy lockfile (33 tests in `rb_vm`)
- [x] **S3 — Receipts + Storage + Gate**: `UnifiedReceipt` with HMAC-BLAKE3 auth chain (11 tests), ChipStore wired into pipeline WF, `NdjsonLedger` (6 tests), KNOCK stage (11 tests), canonical `UblError` responses (8 tests), gate rewrite with real ChipStore lookups, genesis bootstrap (idempotent, self-signed)
- [x] **S4 — WASM + URLs + EventBus**: WASM adapter ABI (NRF→WASM→NRF), adapter registry, Rich URL generation, event bus with idempotency, `ublx explain`

### Post-Sprint Work

- [x] **PS1 — AI Passport**: `ubl/ai.passport` chip type, advisory wiring, gate endpoints for advisories and passport verification
- [x] **PS2 — Auth as Pipeline**: `auth.rs` with 8 onboarding chip types, body validation via `from_chip_body`, dependency chain enforcement at CHECK, drift endpoints removed (34 unit + 10 integration tests)
- [x] **Onboarding**: Full lifecycle `ubl/app` → `ubl/user` → `ubl/tenant` → `ubl/membership` → `ubl/token` → `ubl/revoke` + `ubl/worldscope` + `ubl/role`. Dependency chain enforced. `DependencyMissing` (409) error code. 141 total tests in `ubl_runtime`.
- [x] **ARCHITECTURE.md rev 2**: Added §0 Protocol Stack (8-layer table), updated §1 evolution table, rewrote §2 crate map, removed BLOCKERs from §5.2/§5.3, rewrote §16 as Build History & Roadmap with Protocol Horizons, updated §17 tech debt
- [x] **Policy documents**: `P0_genesis_policy.json`, `P1_policy_update.json`, `ROLLOUT_P0_to_P1.md`

### Test Counts (current — post PR-A/B/C)

| Crate | Tests |
|---|---|
| `rb_vm` | 60 (33 exec + 8 disasm + 19 canon) |
| `ubl_receipt` | 18 |
| `ubl_runtime` | 250 (was 180; +10 idempotency, +7 canon rate_limit, +15 capability, +1 stage events, +7 error taxonomy, +14 manifest, +16 meta_chip) |
| `ubl_ai_nrf1` | 85 (69 unit + 16 rho_vectors) |
| `ubl_kms` | 13 |
| `ubl_unc1` | 33 |
| **Total** | **~459** |

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
| H14 | **`ubl_kms` crate** | `sign_canonical`, `verify_canonical`, `signing_key_from_env()`, domain separation, DID/KID derivation. 13 tests. |
| H15 | **Prometheus `/metrics`** | Counters + histogram on gate. `GET /metrics`. |
| F8 | **Chip verification endpoint** | `GET /v1/chips/:cid/verify` — recomputes CID, checks receipt, returns `ubl/chip.verification`. |
| F11 | **Makefile** | Targets: `build`, `test`, `fmt`, `fmt-check`, `lint`, `check`, `kat`, `gate`, `clean`. |
| F12 | **`ublx disasm`** | `rb_vm::disasm` module (8 tests) + `ublx disasm` subcommand (hex or file). |
| H11 | **`RuntimeInfo` + `BuildMeta` in receipt** | `RuntimeInfo::capture()` hashes binary at startup (BLAKE3), `BuildMeta` records rustc/os/arch/profile/git. `rt` field on `UnifiedReceipt` (optional, omitted when None). Wired into `UblPipeline` — every receipt carries runtime provenance. PF-01 determinism contract added to ARCHITECTURE.md. 7 new tests (18 total in ubl_receipt). |
| H12 | **Opcode byte conflict** | Already resolved — ARCHITECTURE.md §4.4 table already matches code (Dup=0x14, Swap=0x15, VerifySig=0x16). Stale tasklist entry. |
| H2 | **Real DID resolution** | All 5 `"did:key:placeholder"` occurrences replaced. `UblPipeline` now derives `did:key:z...` and `kid` from Ed25519 signing key via `ubl_kms`. Key loaded from `SIGNING_KEY_HEX` env or auto-generated for dev. `PipelineSigner` uses real `ubl_kms::sign_bytes` with `RB_VM` domain separation. Zero placeholder DIDs remain. |
| H3 | **`NaiveCanon` → full ρ** | `RhoCanon` in `rb_vm/src/canon.rs` implements full ρ rules: NFC normalization, BOM rejection, control char rejection, null stripping from maps, key sorting, recursive. Idempotent: ρ(ρ(v))=ρ(v). **UNC-1 §3/§6 aligned**: raw floats poisoned by ρ, rejected at KNOCK (KNOCK-008), mapped to `KNOCK_RAW_FLOAT` error code (400). `RhoCanon::validate()` for strict mode. `PipelineCanon` delegates to `RhoCanon`. 19 canon tests, 3 KNOCK float tests, 1 error_response test. |
| H8 | **Rate limiting** | `rate_limit.rs` in `ubl_runtime`. Sliding-window per-key limiter. `GateRateLimiter` composite: per-DID (100/min), per-tenant (1000/min), per-IP (10/min). Check order: IP→tenant→DID. `prune()` for memory cleanup. 13 tests. |
| H9 | **UNC-1 core ops** | Full `ubl_unc1` crate: `add/sub/mul/div` with INT→DEC→RAT→BND promotion, `to_dec` (6 rounding modes incl. banker’s), `to_rat` (continued fraction with denominator limit), `from_f64_bits` (IEEE-754 frontier → exact BND interval), `compare`, BND interval arithmetic, unit enforcement, serde roundtrips. 33 tests. |
| H10 | **Policy lockfile** | `policy_lock.rs` in `ubl_runtime`. `PolicyLock` struct with YAML parse/serialize, `pin()`, `verify()` against loaded policies. Detects mismatches, missing, and extra policies. `LockVerification` with `Display`. 11 tests. |
| PR-A P0.1 | **Rigid idempotency** | `idempotency.rs` — `IdempotencyStore` keyed by `(@type,@ver,@world,@id)`. Replay returns cached `receipt_cid`. Wired into `process_chip`. 10 tests. |
| PR-A P0.2 | **Canon-aware rate limit** | `rate_limit.rs` — `CanonFingerprint` (BLAKE3 of NRF-1 bytes) + `CanonRateLimiter`. Cosmetic JSON variations hit same bucket. 7 new tests (20 total rate_limit). |
| PR-A P0.3 | **Secure bootstrap (capability)** | `capability.rs` — `Capability` struct with action/audience/expiration/signature. `ubl/app` requires `cap.registry:init`, first `ubl/user` requires `cap.registry:init`. Wired into `check_onboarding_dependencies`. 15 tests. |
| PR-A P0.4 | **Receipts-as-AuthZ** | `ubl/membership` requires `cap.membership:grant`, `ubl/revoke` requires `cap.revoke:execute`. Validates audience/scope/expiration. Wired into pipeline CHECK stage. |
| PR-B P1.5 | **Canonical stage events** | `ReceiptEvent` extended with `input_cid`, `output_cid`, `binary_hash`, `build_meta`, `world`, `actor`, `latency_ms`. Enriched in `publish_receipt_event`. CID chain: WA→TR→WF. 1 integration test. |
| PR-B P1.6 | **ETag/cache for read-only queries** | `GET /v1/chips/:cid` returns `ETag` = CID, `Cache-Control: public, max-age=31536000, immutable`. `If-None-Match` → 304 Not Modified. |
| PR-B P1.7 | **Unified error taxonomy** | 4 new `ErrorCode` variants (`Unauthorized`/401, `NotFound`/404, `TooManyRequests`/429, `Unavailable`/503). `category()` → 8 categories (BadInput, Unauthorized, Forbidden, NotFound, Conflict, TooManyRequests, Internal, Unavailable). `mcp_code()` → JSON-RPC 2.0 error codes. 7 new tests (27 total error_response). |
| PR-C P2.8 | **Manifest generator** | `manifest.rs` — `GateManifest` produces OpenAPI 3.1, MCP tool manifest, WebMCP manifest from registered chip types. Gate serves `/openapi.json`, `/mcp/manifest`, `/.well-known/webmcp.json`. 14 tests. |
| PR-C P2.9 | **MCP server proxy** | `POST /mcp/rpc` — JSON-RPC 2.0 handler with `tools/list` + `tools/call`. Dispatches to `ubl.deliver`, `ubl.query`, `ubl.verify`, `registry.listTypes`. Uses `mcp_code()` for error mapping. |
| PR-C P2.10 | **Meta-chips for type registration** | `meta_chip.rs` — `ubl/meta.register` (mandatory KATs, reserved prefix check, KAT @type validation), `ubl/meta.describe`, `ubl/meta.deprecate`. 16 tests. |

---

## Open — Hardening the Base (3 remaining)

| # | Task | Location | Notes |
|---|---|---|---|
| H4 | **P0→P1 rollout automation** | `ROLLOUT_P0_to_P1.md` | Sequence designed, not yet automated. Need: runtime_hash validation, activation_time window, break-glass. |
| H5 | **Newtype pattern** | All crates | `String` and `Vec<u8>` used directly for CIDs, DIDs, etc. Should adopt `Cid`, `Did`, `ChipBody` newtypes. |
| H6 | **Parse, Don't Validate** | Pipeline + chip types | `auth.rs` does this well (`from_chip_body`). Rest of pipeline still uses raw `serde_json::Value`. Adopt progressively. |

---

## Open — Next Features (7 remaining)

| # | Task | Priority | Notes |
|---|---|---|---|
| F1 | **PS3 — Runtime certification** | Medium | `RuntimeInfo` struct (`binary_hash`, `env`, `certs`), `SelfAttestation` reports actual binary hash, `runtime_hash` in receipts. Depends on H11. Future: `runtime-llm`, `runtime-wasm`, `runtime-tee` modules. |
| F2 | **PS4 — Structured tracing** | Medium | Replace `eprintln!` with `tracing` crate. Structured spans per pipeline stage. Metrics: chips/sec, fuel/chip, deny rate, p99 latency. |
| F3 | **PS5 — LLM Observer narration** | Low | LLM Observer narrates receipt chains on demand. Already has event bus hooks — needs formatting and endpoint. |
| F4 | **Property-based testing** | Low | Add proptest for canon edge cases (Unicode, ordering, decimal, null-stripping). |
| F5 | **UNC-1 numeric opcodes** | Medium | `num.add`, `num.mul`, `num.to_dec`, `num.from_f64_bits`, `num.compare`, etc. for rb_vm. Depends on H9 (UNC-1 core ops). Byte assignments 0x17+ available. See `docs/vm/opcodes_num.md`. |
| F6 | **UNC-1 KNOCK validation** | Medium | Reject raw `float`, `NaN/Inf`, malformed `@num` objects at KNOCK stage. Add `normalize_numbers_to_unc1(json)` step in `chip_format.rs` before `to_nrf1_bytes`. |
| F7 | **UNC-1 migration flags** | Low | Gate flags `REQUIRE_UNC1_NUMERIC`, `F64_IMPORT_MODE=bnd\|reject`. Compat phase first, then enforce. See `docs/migration/unc1_migration.md`. |
| F9 | **Key rotation as chip** | Medium | `ubl/key.rotate` chip type. Generates new Ed25519 keypair, emits receipt proving rotation, stores old→new mapping. Admin-only policy. Pattern from `ubl-ultimate-main/services/registry-api/src/admin.rs`. |
| F10 | **CAS backends for ChipStore** | Low | Add `CasBackend` trait with `Fs(PathBuf)` and `S3 { bucket, prefix }` variants alongside existing in-memory + sled. Pattern from `ubl-ultimate-main/services/registry-api/src/cas.rs`. |
| F13 | **Post-quantum signature stubs** | Low | Feature-gated `pq_mldsa3` module for ML-DSA3 (Dilithium3) dual-signing alongside Ed25519. Stub now, real when NIST PQC libraries stabilize. |

---

## Protocol Horizons (future — after base is solid)

These are not tasks yet. They become tasks when the base hardening items (H1–H15) and critical items (C1–C3) are resolved.

### Money Protocol

New chip types: `ubl/payment`, `ubl/invoice`, `ubl/settlement`, `ubl/escrow`. Transfers require `human_2ofN` quorum via autonomia matrix. Double-entry by construction. Audit trail = receipt chain. Reconciliation = CID comparison.

### Media Protocol (VCX-Core)

Video as content-addressed hash-graph of 64×64 tiles. Editing = manifest rewrite (zero recompression). Certified Runtime as deterministic video editor. LLMs curate by reading NRF-1 manifests, not decoding pixels. Full spec in `VCX-Core`. See also `Addendum_Certified_Runtime.md`.

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

## Reference Documents (root)

| File | Purpose | Status |
|---|---|---|
| `ARCHITECTURE.md` | Engineering spec + protocol stack (source of truth) | ✅ Current (rev 2) |
| `TASKLIST.md` | This file — unified task tracking | ✅ Current |
| `README.md` | Repo README and quick start | Needs update |
| `ROLLOUT_P0_to_P1.md` | Bootstrap sequence P0→P1 | ✅ Valid (not yet automated) |
| `Addendum_Certified_Runtime.md` | Certified Runtime roles and RACI | ✅ Valid reference |
| `Manifesto_de_Reinvencao_BIG.md` | Reinvention manifesto (PT) — axioms, threats, architecture | ✅ Valid reference |
| `Checklist_Operacional_Reinvencao_BIG.md` | Operational checklist (PT) — decision framework, compliance | ✅ Valid reference |
| `Checklist_PATCH_Runtime.md` | Runtime requirements (PT) — 7 items, most implemented | ✅ Valid reference |
| `ROADMAP_DECADE.md` | Long-term vision (speculative) | Needs revision to match 8-layer stack |
| `VCX-Core` | VCX-Core living spec — media protocol | ✅ Valid (deferred) |
| `P0_genesis_policy.json` | Genesis policy | ✅ Valid |
| `P1_policy_update.json` | First policy update | ✅ Valid |
| `UNC-1.md` | UNC-1 Numeric Canon spec (INT/DEC/RAT/BND + units) | ✅ New |
| `schemas/unc-1.schema.json` | JSON Schema for UNC-1 numeric atoms | ✅ New |
| `kats/unc1/unc1_kats.v1.json` | Known Answer Tests for UNC-1 | ✅ New |
| `docs/reference/numerics.md` | UNC-1 reference guide | ✅ New |
| `docs/vm/opcodes_num.md` | UNC-1 opcode spec for RB-VM | ✅ New |
| `docs/migration/unc1_migration.md` | UNC-1 migration phases and flags | ✅ New |

---

*The pattern is always the same: define `@type`s, write policies, maybe add a WASM adapter. The pipeline, gate, receipts, and registry are already there. That's the leverage.*
