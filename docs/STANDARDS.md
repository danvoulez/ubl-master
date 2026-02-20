# Documentation Standards

**Status**: active
**Owner**: Repo Maintainer
**Last reviewed**: 2026-02-17

## Purpose

Define how documentation is authored, reviewed, and maintained so the repo stays professional and non-contradictory.

## Rules

1. One source of truth per topic.
2. Every document must include metadata header:
   - `Status`: `draft`, `active`, `deprecated`, or `archived`
   - `Owner`
   - `Last reviewed` (ISO date)
3. Operational or security behavior must be verifiable from code/tests.
4. Historical context is allowed, but normative behavior must be explicit.
5. If behavior changes, update docs in the same PR.

## Required Header Template

```md
**Status**: active
**Owner**: <team or role>
**Last reviewed**: YYYY-MM-DD
```

## Status Semantics

- `draft`: incomplete; not authoritative.
- `active`: authoritative for the topic.
- `deprecated`: still valid for legacy context; has replacement.
- `archived`: historical only; not to be used for implementation decisions.

## Language and Style

- Primary language: English.
- Keep Portuguese legacy docs only when needed for origin/history and mark them `archived`.
- Use concrete paths and exact env names.
- Avoid aspirational claims without a measurable gate.

## CI/Review Checks

1. No broken relative links in active docs.
2. No duplicate "source of truth" claims for same topic.
3. New env var must be reflected in official Rust reference sources (`docs/reference/README.md` pointers + code).
4. New public error code must be updated in `crates/ubl_runtime/src/error_response.rs` mappings.
5. API endpoint changes must be reflected in runtime OpenAPI export (`/openapi.json` from `GateManifest`).
