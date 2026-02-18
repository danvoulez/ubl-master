# API Reference (Gate)

**Status**: active
**Owner**: Gate
**Last reviewed**: 2026-02-18

Base local address: `http://localhost:4000`

## Core Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/healthz` | Liveness probe. |
| `POST` | `/v1/chips` | Main pipeline entrypoint (KNOCK->WA->CHECK->TR->WF). |
| `GET` | `/v1/chips/:cid` | Retrieve stored chip by CID (supports ETag/304). |
| `GET` | `/v1/cas/:cid` | Alias to retrieve CAS object by CID (same behavior as `/v1/chips/:cid`). |
| `GET` | `/v1/chips/:cid/verify` | Recompute and verify chip integrity. |
| `GET` | `/v1/receipts/:cid` | Retrieve persisted raw receipt JSON (supports ETag/304). |
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
| `GET` | `/console` | Askama+HTMX operational console page (live KPIs + recent events). |
| `GET` | `/console/receipt/:cid` | Receipt-focused console page with trace/narrate links. |
| `GET` | `/registry` | Askama+HTMX registry observability page. |
| `POST` | `/registry/_kat_test` | HTMX partial endpoint that executes selected registry KAT and returns inline result HTML. |
| `GET` | `/v1/events` | SSE stream (history + live) with filters (`world`, `stage`, `decision`, `code`, `type`, `actor`, `since`, `limit`). |
| `GET` | `/v1/events/search` | Read-only paged search over persisted Event Hub data. |
| `GET` | `/v1/advisor/tap` | SSE aggregated advisor frames (sanitized, windowed). |
| `GET` | `/v1/advisor/snapshots` | On-demand advisor snapshot for a time window. |
| `GET` | `/v1/registry/types` | Materialized registry list from `ubl/meta.*` chips. |
| `GET` | `/v1/registry/types/:chip_type` | Registry detail for one type. |
| `GET` | `/v1/registry/types/:chip_type/versions/:ver` | Registry detail for one type version. |
| `GET` | `/metrics` | Prometheus metrics endpoint. |
| `GET` | `/openapi.json` | OpenAPI 3.1 manifest. |
| `GET` | `/mcp/manifest` | MCP tool manifest. |
| `GET` | `/.well-known/webmcp.json` | WebMCP manifest. |
| `POST` | `/mcp/rpc` | JSON-RPC MCP tools endpoint. |

## Response Notes

1. `POST /v1/chips` is idempotent on canonical identity tuple and can return replay.
2. Replayed responses include header `X-UBL-Replay: true`.
3. Error envelope follows `docs/reference/ERRORS.md`.
