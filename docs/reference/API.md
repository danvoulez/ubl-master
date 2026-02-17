# API Reference (Gate)

**Status**: active
**Owner**: Gate
**Last reviewed**: 2026-02-17

Base local address: `http://localhost:4000`

## Core Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/healthz` | Liveness probe. |
| `POST` | `/v1/chips` | Main pipeline entrypoint (KNOCK->WA->CHECK->TR->WF). |
| `GET` | `/v1/chips/:cid` | Retrieve stored chip by CID (supports ETag/304). |
| `GET` | `/v1/chips/:cid/verify` | Recompute and verify chip integrity. |
| `GET` | `/v1/receipts/:cid/trace` | Policy trace for a receipt. |
| `GET` | `/v1/receipts/:cid/narrate` | Deterministic narrative rendering, optional persistence. |

## Runtime / Advisory Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/v1/runtime/attestation` | Signed runtime self-attestation. |
| `GET` | `/v1/passports/:cid/advisories` | List advisories for passport CID. |
| `GET` | `/v1/advisories/:cid/verify` | Verify advisory signature/integrity. |

## Observability and Manifests

| Method | Path | Description |
|---|---|---|
| `GET` | `/metrics` | Prometheus metrics endpoint. |
| `GET` | `/openapi.json` | OpenAPI 3.1 manifest. |
| `GET` | `/mcp/manifest` | MCP tool manifest. |
| `GET` | `/.well-known/webmcp.json` | WebMCP manifest. |
| `POST` | `/mcp/rpc` | JSON-RPC MCP tools endpoint. |

## Response Notes

1. `POST /v1/chips` is idempotent on canonical identity tuple and can return replay.
2. Replayed responses include header `X-UBL-Replay: true`.
3. Error envelope follows `docs/reference/ERRORS.md`.
