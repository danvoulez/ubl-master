# UBL MASTER

**Universal Business Leverage** — A deterministic fractal architecture for universal chip processing.

All Rust. Everything through the pipeline. The gate is the only entry point.

## What is UBL?

UBL is an **autopoietic governance system** — it validates external chips using the same fractal architecture that governs itself. Every action is a chip, every chip goes through the pipeline, every output is a receipt.

- **Reasoning Bits** (RBs) &rarr; **Circuits** &rarr; **PolicyBits** &rarr; **Systems**
- **KNOCK &rarr; WA &rarr; CHECK &rarr; TR &rarr; WF** pipeline
- **NRF-1.1** canonical encoding with BLAKE3 content-addressed CIDs
- **Genesis Policy** — self-signed root chip, bootstrapped at startup

## Quick Start

```bash
# Build the entire workspace
cargo build --workspace

# Run all tests (~103 across rb_vm, ubl_receipt, ubl_runtime)
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
│   ├── ubl_cli/          # ublx command-line tool
│   ├── ubl_config/       # Configuration management
│   ├── ubl_did/          # DID identity (stub)
│   └── ubl_ledger/       # Ledger abstraction (stub)
├── services/
│   └── ubl_gate/         # HTTP API gateway (axum)
├── logline/              # LogLine narrative engine
├── scripts/              # CI helper scripts
├── specs/                # Example chip and policy files
├── .github/workflows/    # CI pipeline (mirrors KNOCK→WA→TR→WF)
├── ARCHITECTURE.md       # Full system specification
├── ALIGNED_TASKLIST.md   # Sprint task tracking
└── ROADMAP_DECADE.md     # Long-term roadmap
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
| `ubl_runtime` | 59 |
| **Total** | **103+** |

## Development Status

**Done:**
- Full KNOCK&rarr;WA&rarr;CHECK&rarr;TR&rarr;WF pipeline with real RB-VM execution
- Genesis policy self-signed and bootstrapped at startup
- Unified Receipt with auth chain and per-RB policy trace
- ChipStore integration (in-memory and sled backends)
- Canonical error responses (`UblError` with stable codes)
- Anti-replay (nonce-based)
- `@world` scoping (`a/{app}/t/{tenant}`)
- NDJSON ledger for receipt persistence
- In-process EventBus (tokio broadcast)
- CI workflow mirroring the pipeline stages

**Next (Sprint 4):**
- AI Passport advisory receipts
- WASM adapter framework
- Rich URLs with offline verification
- CLI completion (`ublx explain`, `ublx search`)

## License

All rights reserved. &copy; [danvoulez](https://github.com/danvoulez)