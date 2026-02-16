# UBL MASTER

**Universal Business Leverage** — A deterministic fractal architecture for universal chip processing.

All Rust. Everything through the pipeline. The gate is the only entry point.

## What is UBL?

UBL is a **protocol stack** — eight layers that turn any domain into a deterministic, auditable, LLM-augmented system. Every action is a chip, every chip goes through the pipeline, every output is a receipt.

- **Chips** — the atomic unit of every action, fact, and intent
- **Pipeline** — KNOCK &rarr; WA &rarr; CHECK &rarr; TR &rarr; WF deterministic engine
- **Policy Gates** — governance as code (genesis, quorum, dependency chains)
- **Runtime** — certified executor, arbiter, notary
- **Receipts** — proof of everything (UnifiedReceipt with HMAC-BLAKE3 auth chain)
- **Registry** — CID/DID identity, ChipStore, append-only ledger
- **Protocols** — domain-specific chip vocabularies (Auth, Money, Media, Advisory)
- **Products** — configuration on top of protocols (AI Passport, Notarization, Video editor)

You never write a new system. You write a new `@type`, a new policy, and the leverage is already there.

## Quick Start

```bash
# Build the entire workspace
cargo build --workspace

# Run all tests (~255 across rb_vm, ubl_receipt, ubl_runtime, ubl_ai_nrf1, ubl_ledger)
cargo test --workspace

# Start the gate server (port 4000)
cargo run -p ubl_gate
```

### Try the API

```bash
# Create a user chip (should ALLOW)
curl -s -X POST http://localhost:4000/v1/chips \
  -H "Content-Type: application/json" \
  -d '{
    "@type": "ubl/user",
    "@id": "alice",
    "@ver": "1.0",
    "@world": "a/acme/t/prod",
    "email": "alice@acme.com"
  }' | jq .

# Try a malicious chip (should DENY)
curl -s -X POST http://localhost:4000/v1/chips \
  -H "Content-Type: application/json" \
  -d '{
    "@type": "evil/malware",
    "@id": "bad",
    "@ver": "1.0",
    "@world": "a/acme/t/prod",
    "script": "<script>alert(1)</script>"
  }' | jq .

# Retrieve a stored chip by CID
curl -s http://localhost:4000/v1/chips/b3:abc123... | jq .

# Get the policy trace for a receipt
curl -s http://localhost:4000/v1/receipts/b3:abc123.../trace | jq .
```

## Architecture

```
KNOCK  →  WA     →  CHECK   →  TR      →  WF
Parse     Ghost     Policy     RB-VM      Final
Input     Record    Eval       Execute    Receipt
                                            │
                              ChipStore ◄───┘
```

Every stage appends to a single **Unified Receipt** — a chip that evolves through the pipeline with HMAC-BLAKE3 auth chain linking each stage cryptographically.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full specification.

## Workspace Structure

```
ubl-master/
├── crates/
│   ├── rb_vm/            # RB-VM — stack-based bytecode VM for policy execution
│   ├── ubl_ai_nrf1/      # NRF-1.1 canonical encoding, BLAKE3 CIDs
│   ├── ubl_runtime/      # Core pipeline: KNOCK→WA→CHECK→TR→WF
│   ├── ubl_receipt/      # Receipt types, Unified Receipt, policy trace
│   ├── ubl_chipstore/    # Content-addressable chip storage (in-memory, sled)
│   ├── ubl_unc1/         # UNC-1 numeric canon (int/dec/rat/bnd + units)
│   ├── ubl_kms/          # Key Management — Ed25519 sign/verify over canonical NRF-1
│   ├── ubl_cli/          # ublx command-line tool (verify, cid, explain, disasm, ...)
│   ├── ubl_config/       # Configuration management
│   ├── ubl_did/          # DID identity (stub)
│   └── ubl_ledger/       # Ledger (NdjsonLedger, InMemoryLedger)
├── services/
│   └── ubl_gate/         # HTTP API gateway (axum)
├── logline/              # LogLine narrative engine
├── scripts/              # CI helper scripts
├── schemas/              # JSON Schemas (UNC-1, etc.)
├── kats/                 # Known Answer Tests (UNC-1, rho_vectors, etc.)
├── docs/                 # Reference docs, VM opcodes, migration guides
├── specs/                # Example chip and policy files
├── .github/workflows/    # CI pipeline (mirrors KNOCK→WA→TR→WF)
├── ARCHITECTURE.md       # Full system specification (source of truth)
├── UNC-1.md              # UNC-1 Numeric Canon spec
├── TASKLIST.md           # Unified task tracking (done + pending + horizons)
├── Makefile              # Standard targets: build, test, fmt, lint, kat, gate
└── ROADMAP_DECADE.md     # Long-term vision
```

## Key Concepts

### Pipeline Stages

| Stage | Purpose | Output |
|-------|---------|--------|
| **KNOCK** | Validate raw input (size, depth, UTF-8, required fields) | Parsed `Value` or reject |
| **WA** | Create ghost record, freeze time, assign nonce | `WaReceiptBody` |
| **CHECK** | Evaluate policy chain (genesis &rarr; app &rarr; tenant &rarr; chip) | `Decision` + policy trace |
| **TR** | Execute RB-VM bytecode | `TrReceiptBody` with fuel accounting |
| **WF** | Finalize receipt, store chip | `WfReceiptBody` + `UnifiedReceipt` |

### Genesis Policy

The genesis chip is the root PolicyBit. It is **self-signed** (`receipt_cid == chip_cid`) and bootstrapped into ChipStore at startup. It enforces:

- Valid `@type` prefixes (`ubl/`, `app/`, `tenant/`)
- Required `@id` field
- Body size &le; 1 MB
- Basic content security (no script injection)

### Unified Receipt

A single JSON document that evolves through all pipeline stages:

- `stages[]` — append-only array of `StageExecution` records
- `receipt_cid` — recomputed after each stage (BLAKE3 of NRF-1.1 encoding)
- Auth chain: `HMAC-BLAKE3(secret, prev_cid || stage_name)` links stages
- The receipt IS a chip — an LLM can read it without special-casing

### Policy Model (Fractal)

```
Layer 0:  Reasoning Bit (RB)     — atomic ALLOW/DENY/REQUIRE
Layer 1:  Circuit                 — graph of RBs
Layer 2:  PolicyBit               — composition of Circuits
Layer 3+: PolicyBits compose further (fractal)
```

Evaluation order: genesis first, chip-specific last. First DENY short-circuits.

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v1/chips` | Process raw bytes through full KNOCK&rarr;WF pipeline |
| `GET` | `/v1/chips/:cid` | Retrieve a stored chip by CID |
| `GET` | `/v1/receipts/:cid/trace` | Get the policy trace for a receipt |
| `GET` | `/healthz` | Health check |

## Test Counts

| Crate | Tests |
|-------|-------|
| `rb_vm` | 33 |
| `ubl_receipt` | 11 |
| `ubl_runtime` | 141 |
| `ubl_ai_nrf1` | 64 |
| `ubl_ledger` | 6 |
| **Total** | **~255** |

## Development Status

**Done:**
- Full KNOCK&rarr;WA&rarr;CHECK&rarr;TR&rarr;WF pipeline with real RB-VM execution
- Genesis policy self-signed and bootstrapped at startup
- Unified Receipt with HMAC-BLAKE3 auth chain and per-RB policy trace
- ChipStore integration (in-memory and sled backends), wired into pipeline WF
- Canonical error responses (`UblError` with Universal Envelope, stable codes)
- Anti-replay (16-byte hex nonce)
- `@world` scoping (`a/{app}/t/{tenant}`)
- NDJSON ledger for receipt persistence
- In-process EventBus (tokio broadcast)
- CI workflow mirroring the pipeline stages
- **Auth as Pipeline**: 8 onboarding chip types (`ubl/app`, `ubl/user`, `ubl/tenant`, `ubl/membership`, `ubl/token`, `ubl/revoke`, `ubl/worldscope`, `ubl/role`) with dependency chain enforcement
- **AI Passport**: LLM identity, rights, duties as a chip. Advisory wiring and gate endpoints.
- **P0/P1 Policy**: Genesis policy + policy update with 2-of-N quorum design

**Next — Hardening the Base:**
- SHA2-256 → BLAKE3 migration
- Real DID resolution (replace placeholder DIDs)
- Runtime self-attestation (`runtime_hash`)
- Structured tracing (replace `eprintln!`)
- P0→P1 rollout automation

**Protocol Horizons** (after base is solid): Money, Media (VCX-Core), Documents, Federation

See [TASKLIST.md](TASKLIST.md) for the full breakdown.

## License

All rights reserved. &copy; [danvoulez](https://github.com/danvoulez)