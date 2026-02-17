# UBL MASTER — Full Pragmatic Tasklist

**Updated:** February 17, 2026  
**Built from:** `TASKLIST.md` + current repo reality (tests/lint/scan)

---

## 0) Status Legend

- ✅ `(x)` Done
- 🟨 `( )` Active / Next
- ⬜ `( )` Not started
- 🧭 `( )` Deferred (after base is solid)

---

## 1) Snapshot Scorecard

- ✅ `(x)` Core delivery complete: deterministic pipeline, receipts, storage, gate, onboarding, manifests, MCP proxy
- ✅ `(x)` Test baseline strong: **544 core-crate tests passing**
- 🟨 `( )` Main gap: production-slice evidence (30-day window) + remaining feature backlog
- 🟨 `( )` Main objective: move from “working system” to “achieved system” with production proof

---

## 2) Completed Work (Keep, Protect, Don’t Regress)

### Foundation + Platform

- ✅ `(x)` S1 Canon + CID (NRF-1.1, CID, envelope, CLI)
- ✅ `(x)` S2 RB-VM + policy + fuel + anti-replay
- ✅ `(x)` S3 Unified receipts + ChipStore + gate + genesis bootstrap
- ✅ `(x)` S4 WASM adapter + rich URLs + event bus
- ✅ `(x)` PS1 AI Passport
- ✅ `(x)` PS2 Auth as Pipeline
- ✅ `(x)` Full onboarding chain (`ubl/app` → `ubl/revoke` + scopes/roles)
- ✅ `(x)` ARCHITECTURE rev2 alignment
- ✅ `(x)` Policy docs (`P0_GENESIS_POLICY.json`, `P1_POLICY_UPDATE.json`, rollout doc)

### Resolved Critical IDs

- ✅ `(x)` C1 metadata hash label fixed to BLAKE3
- ✅ `(x)` C2 chip_format failures confirmed resolved
- ✅ `(x)` C3 error taxonomy and mappings expanded/wired

### Resolved Hardening / Features IDs

- ✅ `(x)` H1 signing key from env
- ✅ `(x)` H2 placeholder DID replacement with real derivation
- ✅ `(x)` H3 full ρ canon behavior
- ✅ `(x)` H5 newtypes (`ubl_types`) migrated through core structures
- ✅ `(x)` H7 signature domain separation (`ubl_kms`)
- ✅ `(x)` H8 rate limiting
- ✅ `(x)` H9 UNC-1 core numeric ops
- ✅ `(x)` H10 policy lockfile
- ✅ `(x)` H11 runtime/build metadata in receipts
- ✅ `(x)` H12 opcode conflict resolved
- ✅ `(x)` H13 rho vectors
- ✅ `(x)` H14 `ubl_kms` crate
- ✅ `(x)` H15 Prometheus `/metrics`
- ✅ `(x)` F8 chip verify endpoint
- ✅ `(x)` F11 Makefile targets
- ✅ `(x)` F12 disassembler + CLI command
- ✅ `(x)` PR-A P0.1 rigid idempotency
- ✅ `(x)` PR-A P0.2 canon-aware rate limits
- ✅ `(x)` PR-A P0.3 secure bootstrap (capability scaffold)
- ✅ `(x)` PR-A P0.4 receipts-as-authz rules
- ✅ `(x)` PR-B P1.5 canonical stage events
- ✅ `(x)` PR-B P1.6 ETag/cache on reads
- ✅ `(x)` PR-B P1.7 unified error taxonomy
- ✅ `(x)` PR-C P2.8 manifest generator
- ✅ `(x)` PR-C P2.9 MCP server proxy
- ✅ `(x)` PR-C P2.10 meta-chip type registration
- ✅ `(x)` W1 sled backend in gate
- ✅ `(x)` W2 ndjson ledger in pipeline
- ✅ `(x)` W3 replay returns cached success result
- ✅ `(x)` PF-02 determinism boundary codified

---

## 3) Critical Path to “Achieved” (This Is The Real Work)

### Phase M1 — Trust Baseline (Now → March 14, 2026)

- ✅ `(x)` N1 cryptographic capability verification (real signature verify, not non-empty string)
- ✅ `(x)` N2 receipt stage secret management (env/KMS + rotation path)
- ✅ `(x)` N3 fix and enforce receipt auth-chain verification semantics
- ✅ `(x)` N5 segment-safe audience matching (`@cap.audience` vs `@world`)
- ✅ `(x)` N6 strict RFC-3339 expiration parse/check for token/capability time

### Phase M2 — Determinism Contract (March 15 → April 18, 2026)

- ✅ `(x)` N4 canonicalize VM `EmitRc` hash/sign path
- ✅ `(x)` P0 cryptographic closure: `UnifiedReceipt.finalize_and_sign` + `verify_signature`
- ✅ `(x)` P0 TR signature persistence: `vm_sig` + `vm_sig_payload_cid` linked into receipt
- ✅ `(x)` P0 canon unification: `ubl_canon` NRF-only CID/sign/verify in critical paths
- ✅ `(x)` P0 rich URL real verify (CID + DID signature + `rt_hash`) with shadow/strict modes
- ✅ `(x)` P0/P1 TR bytecode registry: `transition_registry` (`@tr` override + env maps + profile defaults)
- ✅ `(x)` H6 Parse-Don’t-Validate expansion in critical runtime paths (typed request parse for `@type/@id/@world`, typed onboarding dependency checks, adapter parse)
- 🟨 `( )` F4 property testing expansion (canon + numeric edge cases) — started with proptests in `ubl_canon` + `ubl_unc1`
- ✅ `(x)` Cross-platform reproducibility CI matrix (Linux + macOS) — `.github/workflows/repro-matrix.yml`

### Phase M3 — Indexed Data Plane (April 19 → May 23, 2026)

- ✅ `(x)` N7 indexed receipt lookup path for gate endpoints
- ✅ `(x)` Replace scan-heavy store queries with indexes (`chip_type`, `receipt_cid`, revoke target, tags, executor DID)
- ✅ `(x)` Index rebuild tooling + corruption recovery tests (backend `rebuild_indexes` + recovery test after index loss)
- ✅ `(x)` Load validation with large chip volume (no O(n) hot-path behavior) — `ubl_chipstore` 100k ignored load test + manual run (`~31s`)

### Phase M4 — Runtime Operations (May 24 → June 27, 2026)

- ✅ `(x)` P0 durability boundary: SQLite transactional commit (`receipts + idempotency + outbox`)
- ✅ `(x)` P0 durable idempotency: replay survives restart
- ✅ `(x)` P0 outbox dispatcher: claim/ack/nack + retry/backoff workers
- ✅ `(x)` F1 PS3 runtime certification implementation (`RuntimeInfo` now carries `runtime_hash` + `certs`; signed `SelfAttestation` implemented in `ubl_runtime::runtime_cert`; gate endpoint `GET /v1/runtime/attestation` + OpenAPI path)
- ✅ `(x)` F2 PS4 structured tracing and stage spans (runtime + gate moved to `tracing`; per-stage pipeline logs wired)
- ✅ `(x)` Alerting/SLO dashboard + incident drill runbook (`ops/prometheus/ubl-alerts.yml`, `ops/grafana/ubl-slo-dashboard.json`, `docs/ops/INCIDENT_RUNBOOK.md`)
- ✅ `(x)` F9 key rotation as chip (`ubl/key.rotate` with typed validation + `key:rotate` capability, deterministic key material derivation in TR, and persisted `ubl/key.map` old→new mapping)

### Phase M5 — Production Slice (June 28 → August 15, 2026)

- ✅ `(x)` H4 automate P0→P1 rollout mechanics (`scripts/rollout_p0_p1_check.sh` + `make rollout-check`; validates runtime hash allowlist, activation window, quorum, and break-glass mode)
- 🟨 `( )` Launch one narrow production workflow end-to-end — canary harness implemented (`scripts/production_slice_canary.sh`, `make prod-slice-canary`, `docs/ops/PRODUCTION_SLICE_CANARY.md`), pending live 30-day operation evidence
- ⬜ `( )` Hold 30-day stability window with SLO compliance
- ⬜ `( )` Publish “Achieved” acceptance review against gates

---

## 4) Open Feature Backlog (After Critical Path or In Parallel If Cheap)

- ✅ `(x)` F3 LLM Observer narration endpoint/productization (`GET /v1/receipts/:cid/narrate` + optional advisory persistence + MCP tool `ubl.narrate`)
- ✅ `(x)` F5 UNC-1 numeric opcodes in RB-VM (`0x17..0x21` + coverage in `crates/rb_vm/tests/num_opcodes.rs`)
- ⬜ `( )` F6 UNC-1 strict KNOCK validation path
- ⬜ `( )` F7 UNC-1 migration flags rollout
- ⬜ `( )` F10 CAS backends (`Fs`/`S3`) for ChipStore
- ⬜ `( )` F13 PQ signature stubs (feature-gated)

---

## 5) Deferred Horizons (Not Blocking “Achieved”)

- 🧭 `( )` Money Protocol
- 🧭 `( )` Media Protocol (VCX-Core)
- 🧭 `( )` Document Protocol
- 🧭 `( )` Federation Protocol
- 🧭 `( )` Expanded MCP ecosystem tooling

---

## 6) Exit Gates (Project Is “Achieved” Only If All Checked)

- ⬜ `( )` G1 Security trust chain closed
- ⬜ `( )` G2 Determinism proven across platforms
- ⬜ `( )` G3 Indexed/scalable data path in production
- ⬜ `( )` G4 Runtime operational maturity (tracing/SLO/alerts/runbooks)
- ⬜ `( )` G5 One real workload running stably for 30 days

---

## 7) Practical Rule of Execution

- Keep shipping, but never skip trust primitives.
- Security + determinism + data-path indexing are not optional polish.
- If a task does not improve G1–G5, deprioritize it.
