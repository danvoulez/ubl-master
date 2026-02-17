# UBL MASTER — Unified Task List

**Status**: Single source of truth for all work — done, in progress, and planned
**Date**: February 17, 2026
**Spec**: [ARCHITECTURE.md](./ARCHITECTURE.md) — engineering source of truth
**Docs Index**: [docs/INDEX.md](./docs/INDEX.md)

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
- [x] **Policy documents**: `P0_GENESIS_POLICY.json`, `P1_POLICY_UPDATE.json`, `ROLLOUT_P0_TO_P1.md`

### Test Counts (current — post wiring session)

| Crate | Tests |
|---|---|
| `rb_vm` | 60 (33 exec + 8 disasm + 19 canon) |
| `ubl_receipt` | 18 |
| `ubl_types` | 24 |
| `ubl_runtime` | 252 (was 250; +2 idempotent replay) |
| `ubl_ai_nrf1` | 85 (69 unit + 16 rho_vectors) |
| `ubl_kms` | 13 |
| `ubl_unc1` | 33 |
| **Total** | **485** |

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
| W1 | **SledBackend wired into gate** | Gate uses `SledBackend` at `./data/chips` instead of `InMemoryBackend`. Persistent chip storage across restarts. |
| W2 | **NdjsonLedger wired into pipeline** | `NdjsonLedger` at `./data/ledger` appended after WF. Audit trail per `{app}/{tenant}/receipts.ndjson`. |
| W3 | **Idempotent replay returns 200** | `process_chip` returns `Ok(PipelineResult { replayed: true })` with cached receipt instead of `Err(ReplayDetected)`. Gate returns `X-UBL-Replay: true` header. `UnifiedReceipt::from_json()` added. 2 new tests. |
| PF-02 | **Determinism boundary codified** | ARCHITECTURE.md §15.1: chip CID = deterministic (canonical content), receipt CID = contextually unique (time, nonce, RuntimeInfo). Never compare receipt CIDs for content equality. |

---

## Execution Path — February 17, 2026 → "Achieved"

This section is additive and does not remove any existing items above. It is the operating plan from **today (February 17, 2026)** until the project reaches "Achieved."

### Definition of "Achieved"

"Achieved" means all five gates below are green and stable for one full release window (30 consecutive days):

- [ ] **G1 — Security trust chain closed**: capability signatures are cryptographically verified, receipt stage secret is managed (not hardcoded), and receipt auth chain verification is correct and enforced.
- [ ] **G2 — Determinism proven**: canonicalization is uniform across all CID/sign paths and reproducibility KATs pass on Linux + macOS in CI.
- [ ] **G3 — Data path scales**: no critical API path depends on full-store scans; indexed lookups exist for high-traffic queries.
- [ ] **G4 — Runtime operable**: structured tracing, dashboards, alerts, and incident/runbook coverage are in place.
- [ ] **G5 — Real workload live**: one production workflow runs under SLO with measured reliability and auditability.

### Timeline With Exit Criteria

| Window | Milestone | Must Finish | Exit Proof |
|---|---|---|---|
| **Feb 17, 2026 → Mar 14, 2026** | **M1 — Trust Baseline** | Capability signature verification (hardening of PR-A P0.3), remove hardcoded stage secret (`STAGE_SECRET`), correct and enforce `verify_auth_chain()`, segment-safe capability audience matching, strict RFC-3339 expiration checks. | Security tests include forge/fail cases; no hardcoded secrets in runtime receipt auth path. |
| **Mar 15, 2026 → Apr 18, 2026** | **M2 — Determinism Contract** | Canonicalize VM receipt emission path (remove non-canonical JSON hash/sign path), complete Parse-Don't-Validate expansion (H6) on critical chip types, add cross-platform determinism CI matrix and golden vectors. | Same chip vectors produce same chip CID across CI platforms; receipt semantics match PF-02 policy. |
| **Apr 19, 2026 → May 23, 2026** | **M3 — Indexed Storage Plane** | Replace scan-based ChipStore query paths with indexes (`chip_type`, `receipt_cid`, revocation target, tags, executor DID), implement rebuild tooling, remove endpoint-level scan dependencies for receipt/verify paths. | Load test evidence (target dataset >= 100k chips) shows bounded lookup latency and no O(n) hot-path scans. |
| **May 24, 2026 → Jun 27, 2026** | **M4 — Certified Runtime Operations** | Deliver PS3 (F1 Runtime certification), PS4 (F2 structured tracing), SLO dashboards and alerting, failure drills and recovery playbook. | On-call runbook validated in drill; runtime provenance present in receipts; p95/p99 latency and error metrics visible. |
| **Jun 28, 2026 → Aug 15, 2026** | **M5 — First Production Slice** | Launch one end-to-end workflow (single domain), enforce policy rollout automation (H4), complete post-launch hardening fixes, publish acceptance report against G1–G5. | 30-day stability window with SLO met, incident log reviewed, and "Achieved" gates all checked. |

### Net-New Work Items Added Today (Feb 17, 2026)

| ID | Task | Priority | Status |
|---|---|---|---|
| N1 | **Cryptographic capability verification** | Critical | Done |
| N2 | **Receipt stage secret management (env/KMS + rotation)** | Critical | Done |
| N3 | **Fix + enforce receipt auth chain verification semantics** | Critical | Done |
| N4 | **Canonicalize VM `EmitRc` payload hash/sign path** | High | Done |
| N5 | **Segment-safe audience matching (`@cap.audience` vs `@world`)** | High | Done |
| N6 | **Strict RFC-3339 token/cap expiration parsing and checks** | High | Done |
| N7 | **Indexed receipt lookup path for gate endpoints** | High | Done |

### Existing Backlog Alignment (No Task Loss)

| Existing ID | Phase | Notes |
|---|---|---|
| H4 (P0→P1 rollout automation) | M5 | Required for controlled production transition. |
| H6 (Parse, Don't Validate) | M2 | Move critical chip flow to typed parsing first. |
| F1 (Runtime certification) | M4 | Core deliverable for "Certified Runtime." |
| F2 (Structured tracing) | M4 | Required for operability gate G4. |
| F4 (Property testing) | M2 | Supports determinism/confidence proof. |
| F5/F6/F7 (UNC-1 runtime/migration) | M2 → M4 | Keep behind migration flags until deterministic baseline is locked. |
| F9 (Key rotation as chip) | M4 | Complements N2 secret lifecycle. |
| F10 (CAS backends) | Post-M5 | Keep after "Achieved" unless production workload demands earlier. |
| F13 (PQ signature stubs) | Post-M5 | Keep feature-gated and non-blocking for initial achievement gate. |

---

## Open — Hardening the Base (2 remaining)

| # | Task | Location | Notes |
|---|---|---|---|
| H4 | **P0→P1 rollout automation** | `ROLLOUT_P0_TO_P1.md` | ✅ Done. Added `scripts/rollout_p0_p1_check.sh` + `make rollout-check` preflight with runtime hash allowlist validation, activation_time lead-window checks, signature quorum checks, core type coverage checks, and explicit break-glass mode/reporting (`docs/ops/ROLLOUT_AUTOMATION.md`). |
| H5 | **Newtype pattern** | All crates | ✅ Done. `ubl_types` crate with `Cid`, `Did`, `Kid`, `Nonce`, `ChipType`, `World` newtypes (24 tests). Migrated `StoredChip.cid`/`receipt_cid` → `TypedCid`, `ExecutionMetadata.executor_did` → `TypedDid`, `UnifiedReceipt` fields (`world`/`did`/`kid`/`nonce`/`receipt_cid`/`prev_receipt_cid`), `PipelineReceipt.body_cid` → `TypedCid`. Serde-transparent wire compat preserved. |
| H6 | **Parse, Don't Validate** | Pipeline + chip types | `auth.rs` does this well (`from_chip_body`). Rest of pipeline still uses raw `serde_json::Value`. Adopt progressively. |

---

## Open — Next Features (7 remaining)

| # | Task | Priority | Notes |
|---|---|---|---|
| F1 | **PS3 — Runtime certification** | ✅ Done | `RuntimeInfo` extended with `runtime_hash` + `certs`, signed `SelfAttestation` (`ubl_runtime::runtime_cert`) verifies against DID key, runtime metadata attached to receipts, and gate endpoint `GET /v1/runtime/attestation` exposed in OpenAPI. Future: `runtime-llm`, `runtime-wasm`, `runtime-tee` modules. |
| F2 | **PS4 — Structured tracing** | Medium | Replace `eprintln!` with `tracing` crate. Structured spans per pipeline stage. Metrics: chips/sec, fuel/chip, deny rate, p99 latency. |
| F3 | **PS5 — LLM Observer narration** | ✅ Done | Added deterministic on-demand narration endpoint `GET /v1/receipts/:cid/narrate` (optional `persist=true` stores `ubl/advisory` with hook `on_demand`) and MCP tool `ubl.narrate`. |
| F4 | **Property-based testing** | Low | Add proptest for canon edge cases (Unicode, ordering, decimal, null-stripping). |
| F5 | **UNC-1 numeric opcodes** | Medium | `num.add`, `num.mul`, `num.to_dec`, `num.from_f64_bits`, `num.compare`, etc. for rb_vm. Depends on H9 (UNC-1 core ops). Byte assignments 0x17+ available. See `docs/vm/OPCODES_NUM.md`. |
| F6 | **UNC-1 KNOCK validation** | Medium | Reject raw `float`, `NaN/Inf`, malformed `@num` objects at KNOCK stage. Add `normalize_numbers_to_unc1(json)` step in `chip_format.rs` before `to_nrf1_bytes`. |
| F7 | **UNC-1 migration flags** | Low | Gate flags `REQUIRE_UNC1_NUMERIC`, `F64_IMPORT_MODE=bnd\|reject`. Compat phase first, then enforce. See `docs/migration/UNC1_MIGRATION.md`. |
| F9 | **Key rotation as chip** | ✅ Done | `ubl/key.rotate` implemented with typed payload validation, mandatory `key:rotate` capability check, deterministic Ed25519 material derivation during TR, and persisted `ubl/key.map` old→new mapping in ChipStore. Includes replay-safe flow tests. |
| F10 | **CAS backends for ChipStore** | Low | Add `CasBackend` trait with `Fs(PathBuf)` and `S3 { bucket, prefix }` variants alongside existing in-memory + sled. Pattern from `ubl-ultimate-main/services/registry-api/src/cas.rs`. |
| F13 | **Post-quantum signature stubs** | Low | Feature-gated `pq_mldsa3` module for ML-DSA3 (Dilithium3) dual-signing alongside Ed25519. Stub now, real when NIST PQC libraries stabilize. |

---

## Protocol Horizons (future — after base is solid)

These are not tasks yet. They become tasks when the base hardening items (H1–H15) and critical items (C1–C3) are resolved.

### Money Protocol

New chip types: `ubl/payment`, `ubl/invoice`, `ubl/settlement`, `ubl/escrow`. Transfers require `human_2ofN` quorum via autonomia matrix. Double-entry by construction. Audit trail = receipt chain. Reconciliation = CID comparison.

### Media Protocol (VCX-Core)

Video as content-addressed hash-graph of 64×64 tiles. Editing = manifest rewrite (zero recompression). Certified Runtime as deterministic video editor. LLMs curate by reading NRF-1 manifests, not decoding pixels. Full spec in `VCX-Core`. See also `ADDENDUM_CERTIFIED_RUNTIME.md`.

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
| `ARCHITECTURE.md` | Engineering spec + protocol stack (source of truth) | ✅ Current (rev 3) |
| `TASKLIST.md` | This file — unified task tracking | ✅ Current |
| `README.md` | Repo README and quick start | ✅ Updated |
| `docs/INDEX.md` | Documentation entrypoint and ownership map | ✅ New canonical index |
| `docs/STANDARDS.md` | Documentation standards and metadata policy | ✅ New |
| `ROLLOUT_P0_TO_P1.md` | Bootstrap sequence P0→P1 | ✅ Valid + automated checks |
| `ADDENDUM_CERTIFIED_RUNTIME.md` | Certified Runtime roles and RACI | ✅ Valid reference |
| `docs/reference/API.md` | API and MCP endpoints | ✅ New |
| `docs/reference/CONFIG.md` | Environment/config reference | ✅ New |
| `docs/reference/ERRORS.md` | Canonical error taxonomy | ✅ New |
| `docs/security/CRYPTO_TRUST_MODEL.md` | Signature/verification trust model | ✅ New |
| `docs/lifecycle/RELEASE_READINESS.md` | Release gate checklist and evidence | ✅ New |
| `docs/changelog/CHANGELOG.md` | Documentation and release change log | ✅ New |
| `docs/archive/2026-02/` | Archived superseded docs | ✅ Historical only |
| `VCX-Core` | VCX-Core living spec — media protocol | ✅ Valid (deferred) |
| `P0_GENESIS_POLICY.json` | Genesis policy | ✅ Valid |
| `P1_POLICY_UPDATE.json` | First policy update | ✅ Valid |
| `UNC-1.md` | UNC-1 Numeric Canon spec (INT/DEC/RAT/BND + units) | ✅ New |
| `schemas/unc-1.schema.json` | JSON Schema for UNC-1 numeric atoms | ✅ New |
| `kats/unc1/unc1_kats.v1.json` | Known Answer Tests for UNC-1 | ✅ New |
| `docs/reference/NUMERICS.md` | UNC-1 reference guide | ✅ New |
| `docs/vm/OPCODES_NUM.md` | UNC-1 opcode spec for RB-VM | ✅ New |
| `docs/migration/UNC1_MIGRATION.md` | UNC-1 migration phases and flags | ✅ New |

---

*The pattern is always the same: define `@type`s, write policies, maybe add a WASM adapter. The pipeline, gate, receipts, and registry are already there. That's the leverage.*
