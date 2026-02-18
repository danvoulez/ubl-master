# EVENT HUB

## Scope
- Read-only observability layer for pipeline and registry events.
- Does not introduce new mutation paths; `POST /v1/chips` remains the only write contract.

## Event Envelope
- Canonical payload emitted and persisted:
  - `@type`: `ubl/event`
  - `@ver`: `1.0.0`
  - `@id`: deterministic event id (`receipt_cid + stage + io cids`)
  - `@world`, `source`, `stage`, `when`
  - `chip`, `receipt`, `perf`, `actor`, `artifacts`, `runtime`, `labels`

## Storage
- Backed by `crates/ubl_eventstore` (Sled).
- Trees:
  - `events`
  - `idx_time`
  - `idx_world`
  - `idx_stage`
  - `idx_type`
  - `idx_decision`
  - `idx_code`
  - `idx_actor`
- Supports `rebuild_indexes()` for index recovery.

## Runtime Configuration
- `UBL_EVENTSTORE_ENABLED=true|false` (default: `true`)
- `UBL_EVENTSTORE_PATH=./data/events` (default path)

## Endpoints
- `GET /v1/events`
  - SSE stream with replay of indexed history plus live events.
  - Filters: `world`, `stage`, `decision`, `code`, `type`, `actor`, `since`, `limit`.
  - Heartbeat every 10s.
- `GET /v1/events/search`
  - Paged read query over persisted events.
  - Filters: `world`, `stage`, `decision`, `code`, `type`, `actor`, `from`, `to`, `page_key`, `limit`.
- `GET /v1/advisor/tap`
  - SSE aggregated frames for advisor/LLM consumption.
  - Filters: `world`, `window` (`5m`, `30s`, etc), `interval_ms` (1000..5000), `limit`.
- `GET /v1/advisor/snapshots`
  - On-demand aggregated snapshot over a time window.
  - Filters: `world`, `window`, `limit`.
- `GET /v1/registry/types`
- `GET /v1/registry/types/:chip_type`
- `GET /v1/registry/types/:chip_type/versions/:ver`
  - Registry observability views materialized from `ubl/meta.register`, `ubl/meta.describe`, `ubl/meta.deprecate`.
- `GET /console`
- `GET /console/receipt/:cid`
- `GET /registry`
  - Askama + HTMX UI pages consuming the same read-only endpoints.
  - Registry type page includes "Testar KAT" action, posting to `/registry/_kat_test` and showing result inline.

## Metrics
- `ubl_events_ingested_total{stage,world}`
- `ubl_events_stream_clients{world}`
- `ubl_events_stream_dropped_total{reason}`
