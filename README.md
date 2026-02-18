# UBL MASTER

Deterministic chip-processing runtime with cryptographic receipts, policy enforcement, and operational rollout controls.

## What This Repo Contains

- Rust workspace implementing the full gate pipeline: `KNOCK -> WA -> CHECK -> TR -> WF`
- Unified receipt model with stage chain + signature verification
- Durable commit boundary (SQLite): `receipts + idempotency + outbox`
- Rich URL verification (shadow/strict)
- Runtime self-attestation, metrics, manifests, and MCP proxy endpoints

## Quick Start

```bash
cargo build --workspace
cargo test --workspace
cargo run -p ubl_gate
```

Gate default: `http://localhost:4000`

## Primary Endpoints

- `POST /v1/chips`
- `GET /v1/chips/:cid`
- `GET /v1/chips/:cid/verify`
- `GET /v1/receipts/:cid/trace`
- `GET /v1/receipts/:cid/narrate`
- `GET /v1/runtime/attestation`
- `GET /metrics`
- `GET /openapi.json`
- `POST /mcp/rpc`

## Documentation Entry Point

Start here: `docs/INDEX.md`

Key docs:

- `ARCHITECTURE.md` (normative architecture)
- `TASKLIST.md` (execution status)
- `ROLLOUT_P0_TO_P1.md` (rollout sequence)
- `docs/reference/API.md` (HTTP + MCP surface)
- `docs/reference/CONFIG.md` (env flags)
- `docs/reference/ERRORS.md` (error taxonomy)
- `docs/security/CRYPTO_TRUST_MODEL.md` (signature/verification model)
- `docs/ops/INCIDENT_RUNBOOK.md` (operational response)

## Development Notes

- Prefer deterministic, canonical paths for CID/sign/verify (`ubl_canon`, NRF).
- Treat docs as code: update relevant docs in the same PR as behavior changes.
- Archive superseded strategy/checklist docs under `docs/archive/` instead of deleting.

## Security Notes

- Production signature path is Ed25519 (receipt/runtime attestations).
- PQ dual-sign (`ML-DSA3`) is feature-gated as a rollout stub (`ubl_kms/pq_mldsa3`):
  API/wire shape is present, and PQ signature currently returns `None` until backend integration is completed.
