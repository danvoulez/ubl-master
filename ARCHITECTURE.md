# UBL MASTER — Architecture & Engineering Specification

**Status**: Living document — engineering source of truth
**Date**: February 15, 2026

> **Universal Business Leverage** leverages the best of determinism with the best of the stochasticism of LLMs — both comfortable and at maximum potential, with limits expressed by clear rules.

The machine layer (NRF-1, BLAKE3, RB-VM) is absolutely deterministic: same input → same bytes → same CID → same receipt, forever. The LLM layer operates above it with full creative latitude — but grounded by the Universal Envelope (`@type`, `@id`, `@ver`, `@world`) and bounded by policies compiled into bytecode. Neither side is constrained to be the other. Determinism doesn't try to be creative. LLMs don't try to be precise. The system is the interface where both do what they're best at.

### Engineering Principles

- **All Rust, always.** Native Rust solutions only. No shelling out, no FFI unless absolutely unavoidable. The ecosystem is rich enough.
- **Research before implementing.** Before writing any component, search the web. This industry evolves by the minute. Someone may have solved it better, and their solution may fit the pipeline. The question is always: *does this fit in canon JSON → canon bytecode → pipeline → gate?* If yes, adopt it. If no, build it.
- **Everything through the pipeline.** No side channels. Every action is a chip, every chip goes through KNOCK→WA→CHECK→TR→WF, every output is a receipt. If it can't be expressed as a chip flowing through the gate, it doesn't belong in the system.
- **The gate is the only entry point.** Nothing bypasses `ubl_gate`. Not admin tools, not debug endpoints, not migrations. If it mutates state, it's a chip.
- **Auth is the pipeline.** There is no separate auth system. Registration = `ubl/user` chip. Login = `ubl/token` chip. Permission = policy evaluation at CHECK. Blocking or permitting people is exactly what the pipeline does — it's just a policy on a chip type.
- **One pipeline, many services.** Attestation, witnessing, notarization, proofing, documentation — all are the same pipeline with different `@type`s and different policies. One copy of the gate served over HTTPS handles all of them. The commercial surface is configuration, not code.
- **The LLM is an Accountable Advisor.** The LLM judges, sorts, suggests, routes, narrates — but the pipeline decides. The LLM *signs its work* via `ubl/advisory` receipts. Judged wrong? That LLM. Write it down, move on. It has rights (advise, read context, suggest) and duties (sign, be traceable, be accountable). The first app is **AI Passport** (`ubl/ai.passport`) — an LLM's identity, rights, and duties as a chip.
- **Leverage = Pipeline × Engine.** `UBL = Deterministic Pipeline × LLM Engine`. Determinism provides proof, enforcement, verification. The LLM Engine provides understanding, advice, judgment. Neither alone is sufficient. The product is greater than the sum.
- **Software as Story.** The receipt chain is a narrative. Each receipt is a sentence, the chain is a paragraph, the chip's lifecycle is a chapter. Design principle: *if you can tell the story, you can build the chip. If you can't tell the story, you don't understand the feature yet.*
- **Ghost is an open question.** Three interpretations exist: (a) any DENY at any stage, (b) allowed in but failed during execution, (c) something else. The architecture doesn't depend on settling this now. Every stage receipts. Every receipt is evidence. The `ghost` flag is metadata whose precise semantics will be refined as we build.

---

## 1. Origin and Evolution

This system descends from the **UBL Master Blueprint v2.0** (Chip-as-Code & Registry-First). The Blueprint established four invariant laws (Canon, Determinism, Identity/Scope, Receipt-is-State), the Chip-as-Code model, the fractal RB→Circuit→Policy hierarchy, and the WA→TR→WF pipeline.

The Rust codebase implemented these ideas but **evolved significantly** from the original spec:

| Blueprint Concept | What the Code Actually Does | Gap |
|---|---|---|
| **BLAKE3 everywhere** | `ubl_ai_nrf1` uses SHA2-256 but prints `b3:` prefix | Bug — must fix |
| **5 stages**: KNOCK→WA→TR→EXECUTE→WF | **4 stages**: WA→CHECK→TR→WF. KNOCK is implicit, EXECUTE merged into TR, CHECK added as explicit policy stage | Intentional simplification; KNOCK needs to become explicit |
| **RB-VM opcodes**: PUSH, POP, DUP, SWAP, AND, OR, JMP_IF, FEATURE, SEAL, DECIDE | **19 TLV opcodes**: JSON-oriented (JsonNormalize, CasPut/Get, SetRcBody, EmitRc). No JMP, no FEATURE, no SEAL, no DECIDE | Deliberate redesign — linear execution, no jumps, receipt-native |
| **Policy as bytecode chip** with `imports` field | PolicyBit/Circuit/ReasoningBit in Rust structs with Expression DSL. No bytecode compilation, no imports lockfile | Richer model but not yet compiled to bytecode |
| **S3 key layout**: `a/{app}/t/{tenant}/chips/{cid}` | `FsCas` with hash-sharded paths; `ubl_ledger` is stub (all no-ops) | S3 layout designed but not implemented |
| **Double-Read** (cache + canonical path) | Single path only — no caching layer | Future optimization |
| **Newtype pattern** (Cid, ChipBody, UserId) | `String` and `Vec<u8>` used directly | Should adopt |
| **Parse, Don't Validate** | Mixed — some structs enforce validity, some use raw `serde_json::Value` | Should adopt progressively |
| **Structured logging** (tracing) | `eprintln!` and basic event bus | Should adopt |
| **LLM Advisory at KNOCK** (Gate σ) | LLM Observer consumes events post-pipeline, never at KNOCK | Correct — advisory stays off critical path |
| **Receipt as nested JSON** (wa/transition/wf) | Separate `PipelineReceipt` per stage, flat structure | Must evolve to unified receipt |
| **Proptest for canon** | Unit tests only, no property-based testing | Must add |

The four Laws remain **inviolable**. Everything else is implementation detail that evolved.

---

## 2. Crate Map (as-built)

| Crate | Role | Status |
|---|---|---|
| `ubl_ai_nrf1` | NRF-1.1 canonical encoding, CID, Chip-as-Code | ✅ Working (**Bug**: SHA2-256 with `b3:` prefix — must migrate to BLAKE3) |
| `rb_vm` | Deterministic stack VM, TLV bytecode, fuel metering | ✅ Working (10 Laws tested, 633-line test suite) |
| `ubl_runtime` | WA→TR→WF pipeline, RB/Circuit/Policy, EventBus, LLM Observer | ⚠️ Pipeline runs but TR stage is placeholder |
| `ubl_receipt` | Receipt structs, JWS signing, pipeline receipt types | ⚠️ Separate WA/WF receipts, no unified evolution |
| `ubl_chipstore` | CAS storage, InMemory + Sled backends, indexing, query builder | ⚠️ Complete but **not wired into pipeline** |
| `ubl_ledger` | S3/Garage storage adapter | ❌ Stub — all functions are no-ops |
| `ubl_did` | DID document generation, `did:cid:` resolution | ✅ Minimal but functional |
| `ubl_config` | `BASE_URL` from env | ✅ Trivial |
| `ubl_cli` | `ublx verify` / `ublx build` for .chip files | ✅ Working |
| `ubl_gate` | Axum HTTP gateway on :4000 | ⚠️ Runs but GET chips is stub |
| `logline` | Structured text parser/serializer (from TDLN) — Layer 2 renderer | ✅ Working (full roundtrip, tokenizer, AST, builder) |

### 2.1 What Works End-to-End Today

```text
POST /v1/chips → WA (ghost) → CHECK (genesis policy) → TR (placeholder) → WF (receipt)
```

What does NOT work: TR doesn't invoke rb_vm. Chips aren't stored. Receipts aren't persisted. No unified receipt evolution. No rich URLs.

---

## 3. Canon & NRF-1 (Law I)

### 3.1 Decisions — LOCKED

| Decision | Value | Rationale |
|---|---|---|
| **Hash** | BLAKE3, 32 bytes | Fast, parallel, no length-extension. `rb_vm` already uses it. |
| **CID format** | `b3:` + lowercase hex, 64 chars | `b3:a1b2c3...` (32 bytes = 64 hex chars) |
| **Strings** | NFC normalized, BOM rejected | Already enforced in `ubl_ai_nrf1::nrf.rs` |
| **Prohibited chars** | `\u0000`–`\u001F` in source YAML | Escape required in NRF string encoding |
| **Surrogates** | Reject unpaired surrogates | Invalid UTF-8 → DENY at KNOCK |
| **Numbers** | `i64` only (no floats) | Already enforced — `json_to_nrf` rejects non-integer numbers |
| **Decimals** | `base10, scale=9, range ±10^29` | New `NrfValue::Decimal(i128, u8)` — overflow = DENY at WA |
| **Null vs absence** | Null values REMOVED from maps | Absence ≠ null; `{"a": null}` canonicalizes to `{}` |
| **Map key order** | Strict Unicode code point ascending, post-NFC | Already uses `BTreeMap` in `nrf.rs` |
| **Duplicate keys** | Reject (DENY) | Must fail at parse, not silently deduplicate |

### 3.2 Two-Layer Canonical Representation

Every chip exists in two canonical forms. Both are deterministic; one is for machines, the other is for LLMs and humans.

**Layer 0 — Machine Canon (NRF-1 bytecode)**

The deterministic binary encoding. This is what gets hashed → CID, signed, and stored. One byte per type tag. No ambiguity. The CID is derived exclusively from this layer.

**Layer 1 — LLM Canon (Anchored JSON)**

A minimal, flat JSON derived deterministically from the bytecode. Designed for LLM consumption without requiring computation. Mandatory anchor fields prevent drift:

```json
{"@id":"b3:a1b2...","@type":"ubl/user","@ver":"1.0","@world":"a/acme/t/prod","body":{"email":"bob@acme.com","theme":"dark"}}
```

Rules:
- **Flat**: Minimal nesting (max 2 levels in body). No deep trees.
- **Anchored**: `@id` (CID), `@type`, `@ver`, `@world` (app/tenant scope) are always present at the top. These ground the LLM — it always knows *what* it's reading, *which version*, and *where* it lives.
- **Low overhead**: No pretty-printing, no comments, no trailing commas. One line per chip.
- **Deterministic**: `LLM_Canon(chip) = json_from_nrf1(nrf1_bytes)`. Same bytecode → same JSON → always.
- **Read-only contract**: The LLM reads this form. To write, it produces this form, which gets compiled to NRF-1 bytecode and verified.

The three-layer canonical stack:

```
Layer 0: NRF-1 bytecode     → Machine (hash, sign, store)
Layer 1: Anchored JSON       → LLM (read, write, reason)
Layer 2: LogLine             → Human (debug, audit, observe) — future
```

All three are deterministic derivations of the same data. Layer 0 is truth. Layer 1 is derived. Layer 2 is rendered. The `logline` crate (from TDLN, already built) is the renderer for Layer 2 — but human-facing representation is ultimately UI, not text. Layer 2 is deferred.

Key rule for Layer 1: `@type` is always the **first key**, `@id` always **second**. LLMs read left-to-right; first token = grounding.

**Universal Envelope Rule**: The anchored JSON is not just for chips — it is the base format for **everything** in the system. Chips, receipts, events, API responses, error payloads, policy traces — all share the same minimum fields:

```json
{"@id":"...","@type":"...","@ver":"...","@world":"..."}
```

Different types add fields on top (`body`, `stages`, `decision`, `error`, `trace`, etc.) but **no message may have fewer than these four anchors**. This means:

- A **receipt** is `{"@id":"b3:...","@type":"ubl/wf","@ver":"1.0","@world":"a/acme/t/prod","stages":[...],"decision":"allow",...}`
- An **event** is `{"@id":"b3:...","@type":"ubl/event","@ver":"1.0","@world":"a/acme/t/prod","event_type":"receipt.created",...}`
- An **error** is `{"@id":"b3:...","@type":"ubl/error","@ver":"1.0","@world":"a/acme/t/prod","code":"POLICY_DENIED",...}`
- A **policy** is `{"@id":"b3:...","@type":"ubl/policy","@ver":"1.0","@world":"a/acme/t/prod","rules":[...],...}`

One format. Always anchored. Always parseable by the same code. An LLM reading any UBL artifact always sees the same four fields first and immediately knows what it is, what version, and where it belongs.

### 3.3 CID Migration: SHA2-256 → BLAKE3

**Current state**: `ubl_ai_nrf1::compute_cid` uses SHA2-256 multihash but returns `b3:` prefix — **this is a bug**.

**Fix**: Replace SHA2-256 with BLAKE3 in `compute_cid`. The `rb_vm` already uses BLAKE3 via `blake3::hash()`. After migration, one hash function everywhere.

```
cid = "b3:" + hex::encode(blake3::hash(nrf1_bytes).as_bytes())
```

### 3.4 NRF-1 Header Type Codes

| Code | Type | Stage |
|---|---|---|
| `0x10` | Chip (generic) | — |
| `0x11` | WA Receipt | Stage 1 |
| `0x12` | TR Receipt | Stage 3 |
| `0x13` | WF Receipt | Stage 4 |
| `0x14` | Policy | — |
| `0x15` | Advisory | — |
| `0x16` | Knock | Stage 0 |
| `0x17` | Ghost | WBE |
| `0x18` | Unified Receipt | Future |

Flags byte (reserved): bit 0 = ghost, bit 1 = signed, bits 2-7 = reserved.

---

## 4. RB-VM (Law II)

### 4.1 Current State

`rb_vm` is the most mature crate. It implements a deterministic stack VM with:
- **19 opcodes** in TLV (Type-Length-Value) bytecode format
- **Fuel metering** — 1 unit per opcode, configurable limit
- **No-IO by construction** — only `CasProvider` and `SignProvider` traits
- **Ghost mode** — same execution, flagged in receipt
- **10 Laws** verified by 633 lines of tests with golden CIDs

### 4.2 Opcode Table — LOCKED

| Byte | Opcode | Fuel | Stack Effect | Payload |
|---|---|---|---|---|
| `0x01` | `ConstI64` | 1 | → i64 | 8 bytes BE |
| `0x02` | `ConstBytes` | 1 | → bytes | N bytes |
| `0x03` | `JsonNormalize` | 1 | bytes → json | — |
| `0x04` | `JsonValidate` | 1 | json → json | — |
| `0x05` | `AddI64` | 1 | i64, i64 → i64 | — |
| `0x06` | `SubI64` | 1 | i64, i64 → i64 | — |
| `0x07` | `MulI64` | 1 | i64, i64 → i64 | — |
| `0x08` | `CmpI64` | 1 | i64, i64 → bool | 1 byte op |
| `0x09` | `AssertTrue` | 1 | bool → ∅ | — |
| `0x0A` | `HashBlake3` | 1 | bytes → bytes | — |
| `0x0B` | `CasPut` | 1 | bytes → cid | — |
| `0x0C` | `CasGet` | 1 | cid → bytes | — |
| `0x0D` | `SetRcBody` | 1 | json → ∅ | — |
| `0x0E` | `AttachProof` | 1 | cid → ∅ | — |
| `0x0F` | `SignDefault` | 1 | (no-op, signing at EmitRc) | — |
| `0x10` | `EmitRc` | 1 | → (terminates) | — |
| `0x11` | `Drop` | 1 | a → ∅ | — |
| `0x12` | `PushInput` | 1 | → cid | 2 bytes BE index |
| `0x13` | `JsonGetKey` | 1 | json → i64 | UTF-8 key |

### 4.3 Decisions — LOCKED

| Decision | Value | Rationale |
|---|---|---|
| **Fuel ceiling per TR** | 1,000,000 units | Prevents runaway; DENY if exceeded |
| **Cost model** | 1 unit/opcode (MVP) | Future: weighted by opcode class |
| **Types** | `i64`, `bool`, `bytes`, `cid`, `json`, `unit` | No implicit conversions — type mismatch = DENY |
| **Halting** | No JMP/LOOP opcodes | Fuel-bounded linear execution only |
| **Signature domain** | `"ubl-rb-vm/v1"` context string | Prevents cross-domain replay |
| **Arithmetic overflow** | Saturating (`saturating_add/sub/mul`) | Already implemented |

### 4.4 Planned Opcodes (next iteration)

| Byte | Opcode | Purpose |
|---|---|---|
| `0x14` | `VerifySig` | Verify Ed25519 signature with domain separation |
| `0x15` | `DecimalAdd` | Base-10 decimal arithmetic |
| `0x16` | `DecimalCmp` | Base-10 decimal comparison |
| `0x17` | `Dup` | Duplicate top of stack |
| `0x18` | `Swap` | Swap top two stack values |

---

## 5. Pipeline (WA→TR→WF)

### 5.1 Stage Flow

```
KNOCK → WA (ghost) → CHECK (policy) → TR (rb_vm) → WF (final receipt)
  │         │              │               │              │
  │         │              │               │              └─ Store in ChipStore
  │         │              │               └─ Execute bytecode, emit RC
  │         │              └─ Evaluate policy chain (genesis→app→tenant→chip)
  │         └─ Create ghost record, freeze time, assign policy_cid
  └─ Validate input size/depth, rate limit, assign nonce
```

### 5.2 Unified Receipt (BLOCKER — not yet implemented)

**Current**: Separate `PipelineReceipt` per stage with independent CIDs.

**Target**: Single `UnifiedReceipt` that evolves through stages. Its JSON form follows the Universal Envelope (`@type` first, `@id` second, all four anchors present) — the receipt is just another chip that an LLM can read without special-casing:

```rust
struct UnifiedReceipt {
    v: u32,                           // Schema version
    t: String,                        // RFC-3339 UTC
    did: String,                      // Issuer DID
    subject: Option<String>,          // Subject DID
    kid: String,                      // Key ID: did:key:z...#vN
    nonce: String,                    // Anti-replay (see §6.2)
    stages: Vec<StageExecution>,      // Append-only
    decision: Decision,               // Current decision state
    effects: serde_json::Value,       // Side-effects record
    rt: RuntimeInfo,                  // binary_sha256, env, certs
    prev_receipt_cid: Option<String>, // Chain linkage
    receipt_cid: String,              // b3:hash(NRF(self_without_sig))
    sig: String,                      // Ed25519 JWS detached
}

struct StageExecution {
    stage: PipelineStage,             // WA, CHECK, TR, WF
    timestamp: String,                // RFC-3339 UTC
    input_cid: String,                // What entered this stage
    output_cid: Option<String>,       // What this stage produced
    fuel_used: Option<u64>,           // For TR stage
    policy_trace: Vec<PolicyTraceEntry>, // For CHECK stage
    signature: String,                // Stage executor signature
    auth_token: String,               // HMAC proving stage N authorizes stage N+1
}
```

**Auth chain**: Each stage computes `auth_token = HMAC-BLAKE3(stage_secret, prev_stage_cid || stage_name)`. Next stage verifies before executing.

**CID evolution**: `receipt_cid` recomputed after each stage append. The WF `receipt_cid` is the final canonical CID.

### 5.3 rb_vm Pipeline Integration (BLOCKER — not yet implemented)

**Current**: `UblPipeline.rb_vm` is `Arc<Box<dyn Any>>` with value `"placeholder-vm"`. The TR stage returns hardcoded JSON.

**Target**: TR stage creates a `Vm` instance, decodes the chip's TLV bytecode, and executes it:

```rust
async fn stage_transition(&self, request: &ChipRequest, ...) -> Result<PipelineReceipt, PipelineError> {
    let chip_bytes = get_chip_bytecode(request)?;
    let code = tlv::decode_stream(&chip_bytes)?;
    let mut vm = Vm::new(cfg, cas, &signer, canon, input_cids);
    let outcome = vm.run(&code)?;
    // outcome.rc_cid, outcome.fuel_used, outcome.steps → into receipt
}
```

### 5.4 Input Validation (KNOCK stage)

| Check | Limit | Action |
|---|---|---|
| Max chip size | 1 MB | DENY at KNOCK |
| Max receipt size | 1 MB | DENY at WF |
| Max JSON depth | 32 levels | DENY at KNOCK |
| Max array length | 10,000 elements | DENY at KNOCK |
| Duplicate keys | 0 allowed | DENY at KNOCK |
| Cost per byte | 1 fuel unit per 1KB | Added to TR fuel budget |

---

## 6. Policy Model

### 6.1 Composition Hierarchy

```
Genesis Policy (immutable, self-signed)
  └─ App Policy (per application)
       └─ Tenant Policy (per tenant within app)
            └─ Chip Policy (per chip type)
```

Evaluation order: genesis first (most general), chip-specific last. First DENY short-circuits.

### 6.2 Policy ROM

- `policy_cid` is **immutable** once written into a WA receipt
- Policy migration: deploy new policy chip → update app/tenant config to reference new `policy_cid` → new chips use new policy; old receipts remain valid under old policy
- **No retroactive policy changes** — a receipt's `policy_cid` is its law forever

### 6.3 Policy Imports & Lockfile

**Current**: Policies resolved at runtime via `PolicyLoader.load_policy_chain()`.

**Target**: Compile-time resolution with lockfile:

```yaml
# policy.lock
genesis: b3:abc123...
app/acme: b3:def456...
tenant/acme-prod: b3:789abc...
```

TR stage verifies lockfile CIDs match loaded policies. Divergence = DENY.

### 6.4 RB → Circuit → PolicyBit (the fractal)

The policy model is fractal — the same pattern at every scale:

```
Layer 0:  Reasoning Bit (RB)     — atomic decision: ALLOW/DENY/REQUIRE
Layer 1:  Circuit                 — graph of RBs wired together
Layer 2:  PolicyBit               — composition of Circuits into governance
Layer 3+: PolicyBits compose further (fractal)
```

A Reasoning Bit is a transistor. A Circuit is an integrated circuit. A PolicyBit is a board. Boards compose into systems. Same pattern, every level.

- **ReasoningBit**: Atomic decision unit with `Expression` condition language. Evaluates to Allow/Deny/Require. Every RB produces a receipt proving its decision.
- **Circuit**: Composes RBs with `CompositionMode` (Sequential/Parallel/Conditional) and `AggregationMode` (All/Any/Majority/KofN/FirstDecisive). A Circuit produces a composed receipt.
- **PolicyBit**: Groups circuits with a `PolicyScope` (chip types, operations, level). The PolicyBit produces the final governance receipt.

K-of-N: The policy trace must expose individual RB votes. `SEAL` markers identify which RBs are audit anchors.

The genesis chip is the root PolicyBit — the first board in the system. Every other policy inherits from it.

---

## 7. Identity, Scope & Replay Prevention

### 7.1 `@world` — The Scope Anchor

Every chip lives in a world. The `@world` field in the Universal Envelope is the logical address:

```
@world = "a/{app}/t/{tenant}"
```

- `a/acme/t/prod` — the production tenant of the Acme app
- `a/acme/t/dev` — the dev tenant of the same app
- `a/lab512/t/dev` — LAB 512's dev environment

Rules:
- A chip **cannot reference** chips in a different `@world` unless the policy explicitly allows cross-world reads.
- The gate resolves `@world` from the authenticated DID's membership. No world in the request = DENY at KNOCK.
- `@world` is frozen into the WA receipt and cannot change after that point.
- The genesis policy lives at `@world = "a/_system/t/_genesis"` — the root world.

### 7.2 DID & Key Management

| Decision | Value |
|---|---|
| DID method | `did:key:z...` (Ed25519 public key, base58-btc) |
| Key ID format | `did:key:z...#vN` where N is monotonically increasing |
| Key rotation | New `kid` published as `ubl/key.rotate` chip; old kid valid for verification of past receipts |
| Signing curve | Ed25519 (RFC 8032) |

### 7.3 Anti-Replay

**Current**: No nonce or sequence number in receipts.

**Target**: Each WA receipt includes a `nonce` field:

```
nonce = BLAKE3(did || tenant_id || monotonic_counter)
```

- Counter is per-key, per-tenant, monotonically increasing
- Gate rejects WA with nonce ≤ last-seen nonce for that (did, tenant) pair
- Anti-replay window: 5 minutes for clock skew tolerance

### 7.4 Signature Domain Separation

All signatures include a context prefix to prevent cross-domain replay:

| Context | Domain String |
|---|---|
| Receipt signing | `"ubl-receipt/v1"` |
| RB-VM signing | `"ubl-rb-vm/v1"` |
| Policy signing | `"ubl-policy/v1"` |
| URL signing | `"ubl-url/v1"` |

Format: `sig = Ed25519.sign(key, domain_string || BLAKE3(payload))`

---

## 8. Storage

### 8.1 ChipStore (as-built, not wired)

`ubl_chipstore` provides:
- `ChipStoreBackend` trait with `InMemoryBackend` and `SledBackend`
- `ChipIndexer` with in-memory indexes (type, tag, executor)
- `ChipQueryBuilder` with sorting, pagination, filtering
- `CommonQueries` for customers, payments, audit trails

**Integration point**: `UblPipeline` must accept `Arc<ChipStore>` and call `store_executed_chip()` in the WF stage.

### 8.2 Ledger Key Layout (S3/Garage)

```
{root}/{prefix[0:2]}/{prefix[2:4]}/{full_cid}
```

Example: `cas/a1/b2/b3:a1b2c3d4e5f6...`

- GET is O(1) by CID
- Idempotent writes (content-addressed)
- `FsCas` in `rb_vm` already implements this with BLAKE3

### 8.3 Ledger (stub — needs implementation)

`ubl_ledger` currently returns no-ops. Target:
- S3-compatible object storage (Garage/MinIO for self-hosted)
- Append-only NDJSON audit log per (app, tenant)
- Receipt and ghost lifecycle events

---

## 9. WASM Adapters

### 9.1 Execution Model

WASM adapters run in the TR stage for chips that require external effects (email, payment, etc.).

| Constraint | Value |
|---|---|
| No filesystem | WASI FS disabled |
| No clock | `clock_time_get` returns frozen WA timestamp |
| No network | All I/O via injected CAS artifacts |
| Memory limit | 64 MB per execution |
| Fuel limit | Shared with RB-VM fuel budget |
| Module pinning | `sha256(wasm_module)` recorded in receipt `rt` field |

### 9.2 ABI

```
Input:  NRF-1 bytes (chip body + context)
Output: NRF-1 bytes (result + effects)
```

The adapter receives a single NRF-1 encoded input and must return a single NRF-1 encoded output. No other I/O.

### 9.3 Adapter Registry

Each adapter is a chip of type `ubl/adapter`:
```yaml
ubl_chip: "1.0"
metadata:
  type: "ubl/adapter"
  id: "email-sendgrid-v1"
body:
  wasm_cid: "b3:..."        # CID of the WASM module
  wasm_sha256: "..."         # SHA-256 of the WASM binary
  abi_version: "1.0"
  fuel_budget: 100000
  capabilities: ["email.send"]
```

---

## 10. EventBus & Observability

### 10.1 Event Schema

```json
{
  "schema_version": "1.0",
  "event_type": "ubl.receipt.created",
  "receipt_cid": "b3:...",
  "receipt_type": "ubl/wf",
  "decision": "allow",
  "duration_ms": 42,
  "timestamp": "2026-02-15T12:00:00Z",
  "pipeline_stage": "wf",
  "idempotency_key": "b3:...",
  "metadata": { ... }
}
```

- **Idempotency key** = `receipt_cid` (exactly-once by CID)
- **Schema version** field for forward compatibility
- Topic: `ubl.receipts` on Iggy message broker

### 10.2 Observability Fields in Receipts

Every WF receipt must include:
- `fuel_used`: Total fuel consumed in TR
- `rb_count`: Number of reasoning bits evaluated
- `artifact_cids`: List of CIDs produced during execution
- `policy_trace`: Full RB vote breakdown

### 10.3 LLM Observer (as-built)

Consumes events from Iggy, performs mock AI analysis. Stays **outside the critical path** — advisory only, never blocks pipeline.

---

## 11. LLM Engine

The LLM operates beside the pipeline, not inside it. It is an **Accountable Advisor** — it acts in the world and signs what it did.

### 11.1 Hook Points

| Stage | LLM Role | Binding? |
|---|---|---|
| Pre-KNOCK | Semantic triage: "does this look like what the user intended?" | No — advisory only |
| Post-CHECK | Explain denial: "policy X rejected because..." | No — narration |
| Post-TR | Summarize execution: "this chip did X, consumed Y fuel" | No — narration |
| Post-WF | Route/classify: "this receipt belongs in category Z" | No — suggestion |
| On-demand | Audit storytelling: "here's what happened in this receipt chain" | No — narration |

The LLM never overrides an RB decision. It never produces a CID. It never touches the receipt chain directly.

### 11.2 `ubl/advisory` Receipt

Every LLM action produces a `ubl/advisory` chip — signed by the LLM's AI Passport key, following the Universal Envelope:

```json
{"@type":"ubl/advisory","@id":"b3:...","@ver":"1.0","@world":"a/acme/t/prod","passport_cid":"b3:...","action":"classify","input_cid":"b3:...","output":{"category":"compliance","confidence":0.92},"model":"gpt-4","seed":0}
```

Advisory receipts are stored, indexed, and auditable — but never block the pipeline.

### 11.3 AI Passport (`ubl/ai.passport`)

The first app. An LLM's identity, rights, and duties as a chip:

```json
{"@type":"ubl/ai.passport","@id":"b3:...","@ver":"1.0","@world":"a/acme/t/prod","model":"gpt-4","provider":"openai","rights":["advise","classify","narrate"],"duties":["sign","trace","account"],"scope":["a/acme/*"],"fuel_limit":100000,"signing_key":"did:key:z..."}
```

The passport enters the registry through the same door as everything else — POST /v1/chips.

---

## 12. Error Model

### 12.1 Canonical Error Response

```json
{
  "error": true,
  "code": "POLICY_DENIED",
  "message": "Genesis policy: chip body exceeds 1MB limit",
  "receipt_cid": "b3:...",
  "link": "/v1/receipts/b3:.../trace",
  "details": {
    "policy_id": "genesis",
    "rb_id": "size_limit",
    "limit": 1048576,
    "actual": 2097152
  }
}
```

### 12.2 Error Code Enum — LOCKED

| Code | Meaning | Stage |
|---|---|---|
| `INVALID_INPUT` | Malformed JSON, size exceeded, depth exceeded | KNOCK |
| `CANON_ERROR` | NRF-1 encoding failure, BOM, invalid Unicode | KNOCK/WA |
| `POLICY_DENIED` | Policy evaluation returned DENY | CHECK |
| `FUEL_EXHAUSTED` | TR execution exceeded fuel limit | TR |
| `TYPE_MISMATCH` | RB-VM type error | TR |
| `STACK_UNDERFLOW` | RB-VM stack underflow | TR |
| `CAS_NOT_FOUND` | CasGet on missing CID | TR |
| `SIGN_ERROR` | Signature generation/verification failure | WF |
| `STORAGE_ERROR` | ChipStore/Ledger write failure | WF |
| `INTERNAL_ERROR` | Unexpected system error | Any |
| `REPLAY_DETECTED` | Nonce reuse detected | WA |

### 12.3 Error → Receipt Mapping

Every error that reaches WF produces a DENY receipt with full `policy_trace`. Errors before WA (KNOCK failures) return HTTP 400 without a receipt.

---

## 13. Rich URLs

### 13.1 Format

```
https://{host}/{app}/{tenant}/receipts/{receipt_id}.json
  #cid={receipt_cid}
  &did={issuer_did}
  &rt={binary_sha256}
  &sig={url_signature}
```

### 13.2 Offline Verification

A rich URL contains enough information to:
1. Fetch the receipt JSON from the URL path
2. Recompute `b3:hash(NRF(receipt_body))` and verify it matches `cid`
3. Verify `sig` against `did` public key with domain `"ubl-url/v1"`
4. Verify `rt` matches the expected runtime binary hash

### 13.3 Self-Contained URLs (for QR/mobile)

For offline use, the chip data can be embedded:

```
ubl://{base64url(compressed_chip)}?cid={cid}&sig={sig}
```

Max URL length: 2KB (QR code limit). Larger chips use the hosted URL format.

---

## 14. Security & DoS

### 14.1 Size Limits

| Resource | Limit |
|---|---|
| Chip body (WA input) | 1 MB |
| Receipt (WF output) | 1 MB |
| URL (self-contained) | 2 KB |
| JSON depth | 32 levels |
| Array length | 10,000 elements |
| Map keys | 1,000 per object |
| String length | 1 MB |

### 14.2 Rate Limiting

- Per-DID: 100 chips/minute
- Per-tenant: 1,000 chips/minute
- Per-IP (unauthenticated): 10 chips/minute
- Fuel cost per byte: 1 unit per 1KB of input

### 14.3 Cold Path Rejection

KNOCK stage rejects early (before WA) on:
- Oversized body
- Excessive nesting depth
- Duplicate JSON keys
- Invalid UTF-8
- Missing required fields (`@type`)

---

## 15. Acceptance Criteria

### 15.1 Determinism

> Same input on 3 different machines → identical WF receipt bytes, identical CID.

Verified by: `rb_vm` golden CID tests + pipeline integration tests.

### 15.2 Opcode Cost Stability

> Changing opcode costs = new VM version. Old receipts remain valid under old cost table.

### 15.3 Offline Reconstruction

> Given only `chips/` and `receipts/` directories, `ublx verify` reconstructs and verifies every receipt bit-for-bit.

### 15.4 Policy Immutability

> A receipt's `policy_cid` is its law forever. New policy = new CID = new chips only.

---

## 16. MVP Sprint Plan (4 × 2 weeks)

### S1 — Canon + CID + CLI (Weeks 1-2)

**Goal**: Lock the canonical encoding and make `ublx` the verification tool.

- Fix `compute_cid` to use BLAKE3 (not SHA2-256)
- Add `NrfValue::Decimal(i128, u8)` with scale=9
- Reject duplicate JSON keys in `json_to_nrf`
- Reject control characters `\u0000`–`\u001F` in strings
- Add `ublx cid <file>` command
- Add proptest for Unicode/ordering/decimal edge cases
- Publish NRF-1 type code table (§2.3)

### S2 — RB-VM + Policy ROM (Weeks 3-4)

**Goal**: Wire rb_vm into the pipeline and lock policy resolution.

- Replace `Arc<Box<dyn Any>>` in `UblPipeline` with real `Vm` integration
- Implement TR stage that decodes TLV and executes via `rb_vm`
- Add fuel ceiling (1M units) enforcement
- Add `VerifySig` opcode with domain separation
- Implement policy lockfile (compile-time CID set)
- Unify `Decision` enum (one definition, re-exported)
- Add nonce/anti-replay to WA receipts

### S3 — Gate + Receipts + Storage (Weeks 5-6)

**Goal**: Unified receipt, persistent storage, end-to-end flow.

- Implement `UnifiedReceipt` with stage evolution (§4.2)
- Wire `ChipStore` into pipeline WF stage
- Implement `ubl_ledger` with real S3/filesystem backend
- Add canonical error responses (§10.1)
- Implement KNOCK stage input validation (§4.4)
- Add `GET /v1/chips/:cid` with real ChipStore lookup
- Add `GET /v1/receipts/:cid/trace` for policy trace rendering
- Test: `ublx verify` matches WF output

### S4 — WASM Adapters + EventBus + URLs (Weeks 7-8)

**Goal**: External effects, observability, portable URLs.

- Define WASM adapter ABI (NRF→WASM→NRF)
- Implement adapter registry (`ubl/adapter` chip type)
- Pin WASM module hash in receipt `rt` field
- Add `schema_version` and idempotency key to events
- Implement Rich URL generation (§11.1)
- Implement `ubl://` self-contained URLs for QR (§11.3)
- Add `ublx explain wf::<cid>` command
- Build minimal receipt search (by CID, type, date range)

---

## 17. Known Technical Debt

| Item | Location | Severity | Status |
|---|---|---|---|
| SHA2-256 used instead of BLAKE3 | `ubl_ai_nrf1::compute_cid` | 🔴 Critical — CID mismatch with rb_vm | **OPEN** |
| ~~Two `Decision` enums~~ | ~~`ubl_runtime` vs `ubl_receipt`~~ | ~~🟡 Confusing~~ | ✅ Fixed S2.2 — unified to `ubl_receipt::Decision` |
| ~~TR stage is placeholder~~ | ~~`pipeline.rs`~~ | ~~🔴 Critical~~ | ✅ Fixed S2.1 — real rb_vm execution |
| Hardcoded signing key | `ubl_receipt::SIGNING_KEY` | 🟡 Dev only — must load from env | **OPEN** |
| ~~`ubl_ledger` is all no-ops~~ | ~~`ubl_ledger::lib.rs`~~ | ~~🔴 Critical~~ | ✅ Fixed S3.4 — `NdjsonLedger` + `InMemoryLedger` |
| ~~ChipStore not in pipeline~~ | ~~`UblPipeline`~~ | ~~🔴 Critical~~ | ✅ Fixed S3.3 — `Arc<ChipStore>` persists at WF |
| ~~No nonce/anti-replay~~ | ~~WA receipts~~ | ~~🟡 Replay possible~~ | ✅ Fixed S2.3 — 16-byte hex nonce |
| Placeholder DIDs | `"did:key:placeholder"` in WA stage | 🟡 Must come from auth | **OPEN** |
| `NaiveCanon` in rb_vm | Sorts keys but doesn't do full ρ | 🟡 Must delegate to `ubl_ai_nrf1` | **OPEN** |
| ~~Hardcoded duration_ms~~ | ~~`50` in WF stage~~ | ~~🟢 Minor~~ | ✅ Fixed S3.7 — real `Instant::now()` timing |

---

*This document is the engineering source of truth. Code that contradicts it is a bug. Decisions marked LOCKED require a new document version to change.*

*UBL is a protocol, not a product pitch. It proposes a better way to do deterministic computation with LLM intelligence — and it should be used and appreciated on its merits. Real things get huge by being right, not by being forced.*
