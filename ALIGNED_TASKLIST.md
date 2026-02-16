# UBL MASTER — ALIGNED TASKLIST

**Status**: Aligned with ARCHITECTURE.md — ready for Sprint 1
**Date**: February 15, 2026
**Spec**: See [ARCHITECTURE.md](./ARCHITECTURE.md) for all locked decisions and engineering principles
**Goal**: 4 sprints × 2 weeks → foundation complete

---

## Codebase Reality Check

| Crate | Status | Notes |
|---|---|---|
| `ubl_ai_nrf1` | ✅ Working | **Bug**: uses SHA2-256 but prints `b3:` prefix. Must migrate to BLAKE3. |
| `rb_vm` | ✅ Working | Most mature crate. 19 opcodes, fuel metering, 10 Laws, 633-line test suite. |
| `ubl_runtime` | ⚠️ Partial | Pipeline runs WA→CHECK→TR→WF but TR is a **placeholder** — rb_vm not invoked. |
| `ubl_receipt` | ⚠️ Partial | Separate WA/WF receipt structs. No unified evolution. Hardcoded signing key. |
| `ubl_chipstore` | ⚠️ Partial | InMemory + Sled backends, indexing, query builder — **not wired into pipeline**. |
| `ubl_ledger` | ❌ Stub | Every function returns `Ok(())` or `None`. Nothing persists. |
| `ubl_did` | ✅ Minimal | DID doc generation works. |
| `ubl_config` | ✅ Trivial | `BASE_URL` from env. |
| `ubl_cli` | ✅ Working | `ublx verify` and `ublx build` for .chip files. |
| `ubl_gate` | ⚠️ Partial | Axum on :4000. POST works (placeholder TR). GET chips is stub. |
| `logline` | ✅ Working | Structured text parser/serializer (from TDLN) — Layer 2 renderer. |

**Two `Decision` enums** exist (`ubl_runtime::reasoning_bit::Decision` and `ubl_receipt::pipeline_types::Decision`) — must unify.

---

## Sprint 1 — Canon + CID + Universal Envelope (Weeks 1–2)

**Goal**: Lock the canonical encoding. Every CID uses BLAKE3. Universal Envelope is the base format for everything. `ublx` becomes the verification tool.

**Ref**: ARCHITECTURE.md §3 (Canon & NRF-1), §3.2 (Two-Layer Canon + Universal Envelope)

### S1.1 — Fix CID hash: SHA2-256 → BLAKE3

- [ ] Replace SHA2-256 with BLAKE3 in `ubl_ai_nrf1::compute_cid`
- [ ] Verify CID format: `b3:` + lowercase hex, 64 chars, 32 bytes
- [ ] Update all golden CID test vectors
- [ ] Confirm `rb_vm` and `ubl_ai_nrf1` produce identical CIDs for same input

### S1.2 — Canon hardening

- [ ] Add `NrfValue::Decimal(i128, u8)` with `scale=9, range ±10^29`; overflow = DENY
- [ ] Reject duplicate JSON keys in `json_to_nrf` (currently silently deduplicates via BTreeMap)
- [ ] Reject control characters `\u0000`–`\u001F` in source strings
- [ ] Reject unpaired Unicode surrogates
- [ ] Enforce null-stripping: `{"a": null}` → `{}`
- [ ] Publish NRF-1 type code table (ARCHITECTURE.md §3.4)

### S1.3 — Universal Envelope

- [ ] Define `UblEnvelope` struct: `@type`, `@id`, `@ver`, `@world` — the four mandatory anchors
- [ ] `@type` always serialized as first key, `@id` always second (LLM grounding rule)
- [ ] Implement `json_from_nrf1()` — deterministic Layer 1 (Anchored JSON) derivation from bytecode
- [ ] Validate: every chip, receipt, event, error must carry all four anchors
- [ ] Add tests: envelope round-trip, missing anchor = DENY, key ordering

### S1.4 — CLI enhancements

- [ ] Add `ublx cid <file>` — compute and print CID
- [ ] Add proptest suite for Unicode/ordering/decimal edge cases
- [ ] Add `ublx explain` stub (prints chip metadata + policies)

### S1 Acceptance

- `ublx cid` on same file across 3 machines → identical output
- All `rb_vm` law tests pass with BLAKE3 CIDs
- Every JSON output from the gate carries `@type`, `@id`, `@ver`, `@world`
- proptest finds no canon violations in 10K iterations

---

## Sprint 2 — RB-VM Integration + Policy ROM (Weeks 3–4)

**Goal**: Wire rb_vm into the pipeline. Lock policy resolution. Kill the placeholder TR stage. Define `@world` scoping.

**Ref**: ARCHITECTURE.md §4 (RB-VM), §5.3 (Pipeline Integration), §6 (Policy), §7.1 (@world)

### S2.1 — Wire rb_vm into pipeline

- [ ] Replace `rb_vm: Arc<Box<dyn Any>>` in `UblPipeline` with typed VM integration
- [ ] Implement real `stage_transition` that decodes TLV bytecode and executes via `Vm`
- [ ] Pass chip body as CAS input, collect `VmOutcome` (rc_cid, fuel_used, steps)
- [ ] Enforce fuel ceiling: 1,000,000 units per TR (ARCHITECTURE.md §4.3)
- [ ] Map `ExecError` variants to canonical error codes (ARCHITECTURE.md §12.2)

### S2.2 — Unify Decision enum

- [ ] Delete `ubl_receipt::pipeline_types::Decision`
- [ ] Re-export `ubl_runtime::reasoning_bit::Decision` everywhere
- [ ] Remove manual mapping in `stage_write_finished`

### S2.3 — Anti-replay & identity

- [ ] Add `nonce` field to WA receipts: `BLAKE3(did || tenant_id || counter)`
- [ ] Add `kid` field: `did:key:z...#vN` format
- [ ] Reject WA with nonce ≤ last-seen for (did, tenant) pair
- [ ] Replace hardcoded `"did:key:placeholder"` with real DID from auth/env
- [ ] Replace hardcoded `SIGNING_KEY` in `ubl_receipt` with env-loaded key

### S2.4 — `@world` scoping

- [ ] Implement `@world` resolution from authenticated DID membership
- [ ] Freeze `@world` into WA receipt — immutable after that point
- [ ] Reject chips referencing CIDs from a different `@world` (unless cross-world policy allows)
- [ ] Genesis policy at `@world = "a/_system/t/_genesis"`

### S2.5 — Policy lockfile

- [ ] Implement `policy.lock` file format (YAML, CID set per level)
- [ ] TR stage verifies loaded policy CIDs match lockfile; divergence = DENY
- [ ] Add `ublx policy lock` command to generate lockfile from .chip ancestry

### S2.6 — New opcodes

- [ ] `VerifySig` (0x14): Ed25519 verify with domain separation (`"ubl-rb-vm/v1"`)
- [ ] `Dup` (0x17): duplicate top of stack
- [ ] `Swap` (0x18): swap top two values

### S2 Acceptance

- POST /v1/chips executes real bytecode in TR stage (not placeholder JSON)
- Fuel exhaustion returns `FUEL_EXHAUSTED` error with receipt
- Same chip + same input → identical WF receipt CID (determinism across runs)
- Nonce replay is rejected with `REPLAY_DETECTED`
- `@world` is present in every receipt and enforced at the gate

---

## Sprint 3 — Unified Receipt + Storage + Gate (Weeks 5–6)

**Goal**: Single evolving receipt. Chips persist. GET works. Errors are canonical. Fractal policy model wired.

**Ref**: ARCHITECTURE.md §5.2 (Unified Receipt), §6.4 (Fractal Policy), §8 (Storage), §12 (Errors)

### S3.1 — Unified Receipt

- [ ] Implement `UnifiedReceipt` struct with `stages: Vec<StageExecution>` (ARCHITECTURE.md §5.2)
- [ ] Receipt follows Universal Envelope: `@type` first, `@id` second, all four anchors
- [ ] Each stage appends to receipt; CID recomputed after each append
- [ ] Auth chain: `auth_token = HMAC-BLAKE3(stage_secret, prev_cid || stage_name)`
- [ ] WF `receipt_cid` is the final canonical CID
- [ ] Migrate `PipelineResult` to return `UnifiedReceipt`

### S3.2 — Fractal policy wiring

- [ ] Genesis chip as root PolicyBit — self-signed, inserted at gate startup
- [ ] Policy loader: walk chip ancestry (genesis→app→tenant→chip), collect circuits
- [ ] Evaluate circuit chain at CHECK: first DENY short-circuits
- [ ] Policy trace in receipt exposes individual RB votes
- [ ] Replace hardcoded validation in `create_chip` with genesis RBs

### S3.3 — ChipStore integration

- [ ] Add `Arc<ChipStore>` field to `UblPipeline`
- [ ] Call `store_executed_chip()` in WF stage after receipt creation
- [ ] Wire `ChipStore` into `ubl_gate` via shared state
- [ ] Implement real `GET /v1/chips/:cid` with ChipStore lookup
- [ ] Add `GET /v1/receipts/:cid/trace` for policy trace rendering

### S3.4 — Ledger implementation

- [ ] Replace `ubl_ledger` stubs with real filesystem/S3 backend
- [ ] Append-only NDJSON audit log per (app, tenant)
- [ ] Receipt and ghost lifecycle events persisted
- [ ] Ledger failures warn-logged, never block pipeline

### S3.5 — KNOCK stage & input validation

- [ ] Add KNOCK stage before WA: validate size (1MB), depth (32), array length (10K)
- [ ] Reject duplicate JSON keys at KNOCK
- [ ] Reject invalid UTF-8 at KNOCK
- [ ] Reject missing `@type` field at KNOCK
- [ ] Reject missing `@world` at KNOCK

### S3.6 — Canonical error responses

- [ ] Implement error JSON with Universal Envelope (`@type: "ubl/error"`) + `code`, `message`, `link`, `details`
- [ ] Map all pipeline errors to stable error code enum (ARCHITECTURE.md §12.2)
- [ ] Errors reaching WF produce DENY receipt with full `policy_trace`
- [ ] KNOCK failures return HTTP 400 without receipt

### S3.7 — Timing & observability fields

- [ ] Replace hardcoded `duration_ms: 50` with real elapsed time measurement
- [ ] Add `fuel_used`, `rb_count`, `artifact_cids` to WF receipt body

### S3 Acceptance

- Single receipt evolves WA→CHECK→TR→WF with auth chain
- Genesis policy evaluates real RBs at CHECK stage
- `GET /v1/chips/:cid` returns stored chip after POST
- `ublx verify <wf_receipt>` recomputes and matches CID
- KNOCK rejects oversized/malformed input before WA
- Error responses follow Universal Envelope

---

## Sprint 4 — LLM Engine + WASM + URLs + Observability (Weeks 7–8)

**Goal**: LLM Engine with AI Passport. External effects via WASM. Portable URLs. Production observability.

**Ref**: ARCHITECTURE.md §9 (WASM), §10 (Events), §11 (LLM Engine), §13 (Rich URLs)

### S4.1 — LLM Engine: AI Passport + Advisory

- [ ] Implement `ubl/ai.passport` chip type (model, provider, rights, duties, scope, signing_key)
- [ ] Implement `ubl/advisory` chip type (passport_cid, action, input_cid, output, confidence)
- [ ] Advisory receipts signed by passport key, follow Universal Envelope
- [ ] LLM hook points: post-CHECK narration, post-WF classification (non-blocking)
- [ ] Advisory chips stored and indexed but never block pipeline

### S4.2 — WASM adapter framework

- [ ] Define ABI: NRF-1 bytes in → NRF-1 bytes out
- [ ] Implement sandbox: no FS, no clock (frozen WA timestamp), no network
- [ ] Memory limit: 64 MB per execution
- [ ] Fuel shared with RB-VM budget
- [ ] Pin `sha256(wasm_module)` in receipt `rt` field
- [ ] Implement `ubl/adapter` chip type for adapter registry

### S4.3 — Rich URLs

- [ ] Implement hosted URL format: `https://{host}/{app}/{tenant}/receipts/{id}.json#cid=...&did=...&sig=...`
- [ ] Implement URL signing with domain `"ubl-url/v1"`
- [ ] Implement `ubl://` self-contained URL for QR (max 2KB)
- [ ] Add `ublx url <receipt_cid>` command to generate URL
- [ ] Offline verification: fetch → recompute CID → verify sig

### S4.4 — EventBus hardening

- [ ] Add `schema_version: "1.0"` to all events
- [ ] Events follow Universal Envelope (`@type: "ubl/event"`)
- [ ] Add `idempotency_key` = `receipt_cid` (exactly-once by CID)
- [ ] Add `fuel_used`, `rb_count`, `artifact_cids` to event metadata

### S4.5 — CLI completion

- [ ] `ublx explain wf::<cid>` — print RB tree with PASS/DENY/REQUIRE per node
- [ ] Receipt fixture generator for integration testing
- [ ] `ublx search` — query ChipStore by type, tag, date range

### S4 Acceptance

- AI Passport chip created through the gate, advisory receipts signed and stored
- WASM adapter executes in sandbox, receipt includes module hash
- Rich URL verifies offline without server access
- Events have schema version, idempotency key, and Universal Envelope
- `ublx explain` renders full policy trace tree

---

## Post-Sprint — First App: AI Passport Service

**Depends on**: S1–S4 complete

### AI Passport end-to-end

- [ ] Register LLM identity via `ubl/ai.passport` chip
- [ ] LLM performs advisory action → `ubl/advisory` receipt with passport_cid
- [ ] Query advisory history by passport_cid
- [ ] Verify advisory chain: who judged, when, what input, what output
- [ ] `ublx verify` on advisory receipt chain

### Auth as pipeline

- [ ] `ubl/user` chip for human registration (through the gate)
- [ ] `ubl/token` chip for session creation (through the gate)
- [ ] Permission = policy evaluation at CHECK, not middleware

### Runtime certification

- [ ] `RuntimeInfo` in receipt: `binary_sha256`, `env`, `certs`
- [ ] `SelfAttestation` reports actual binary hash
- [ ] Future: `runtime-llm`, `runtime-wasm`, `runtime-tee` modules

### Enhanced observability

- [ ] Structured logging via `tracing` crate (replace `eprintln!`)
- [ ] Metrics: chips/sec, fuel/chip, deny rate, p99 latency
- [ ] LLM Observer narrates receipt chains on demand

---

## Definition of Done

### Foundation complete when:

- [ ] BLAKE3 CIDs everywhere (no SHA2-256)
- [ ] Universal Envelope (`@type`, `@id`, `@ver`, `@world`) on every artifact
- [ ] rb_vm executes real bytecode in TR stage
- [ ] Unified receipt evolves through all stages with auth chain
- [ ] Fractal policy: genesis→app→tenant→chip RB evaluation at CHECK
- [ ] ChipStore persists every processed chip
- [ ] `GET /v1/chips/:cid` returns stored chips
- [ ] KNOCK validates input before WA
- [ ] Canonical error responses on all failure paths
- [ ] Nonce anti-replay on WA receipts
- [ ] `@world` scoping enforced
- [ ] `ublx verify` matches WF receipt CID
- [ ] All `rb_vm` law tests pass
- [ ] Single `Decision` enum across codebase

### Acceptance criteria:

- Same input on 3 different machines → identical WF bytes
- Opcode cost table is stable; change = new VM version
- Offline reexecution with `chips/` + `receipts/` reconstructs state bit-for-bit
- New policy only applies when `policy_cid` changes
- *If you can tell the story, you can build the chip*

---

## Decisions Locked (see ARCHITECTURE.md)

| Decision | Value |
|---|---|
| Hash | BLAKE3, 32 bytes |
| CID | `b3:` + lowercase hex, 64 chars |
| Universal Envelope | `@type` (first), `@id` (second), `@ver`, `@world` — on everything |
| Strings | NFC, BOM rejected, `\u0000`–`\u001F` prohibited |
| Numbers | `i64` only; decimals: `base10, scale=9, range ±10^29` |
| Null | Stripped from maps (absence ≠ null) |
| Key order | Unicode code point ascending, post-NFC |
| Fuel ceiling | 1,000,000 units per TR |
| Signature | Ed25519 with domain separation |
| `kid` format | `did:key:z...#vN`, N monotonic |
| `@world` format | `a/{app}/t/{tenant}` |
| LLM role | Accountable Advisor — signs its work, never overrides pipeline |

---

**Next action**: Begin Sprint 1 — fix `compute_cid` to use BLAKE3