# Error Taxonomy

**Status**: active
**Owner**: Runtime
**Last reviewed**: 2026-02-17

Source: `crates/ubl_runtime/src/error_response.rs`.

## Contracted Errors (required for clients)

| Code | HTTP | Category | Produces receipt |
|---|---:|---|---|
| `invalid_signature` | 400 | BadInput | yes |
| `runtime_hash_mismatch` | 400 | BadInput | yes |
| `idempotency_conflict` | 409 | Conflict | yes |
| `durable_commit_failed` | 500 | Internal | yes |

## KNOCK Errors (pre-pipeline)

- `KNOCK_BODY_TOO_LARGE` (400)
- `KNOCK_DEPTH_EXCEEDED` (400)
- `KNOCK_ARRAY_TOO_LONG` (400)
- `KNOCK_DUPLICATE_KEY` (400)
- `KNOCK_INVALID_UTF8` (400)
- `KNOCK_MISSING_ANCHOR` (400)
- `KNOCK_NOT_OBJECT` (400)
- `KNOCK_RAW_FLOAT` (400)

No receipt is produced for KNOCK errors.

## Pipeline/Runtime Errors

- `POLICY_DENIED` (403)
- `INVALID_CHIP` (422)
- `DEPENDENCY_MISSING` (409)
- `FUEL_EXHAUSTED` (422)
- `TYPE_MISMATCH` (422)
- `STACK_UNDERFLOW` (422)
- `CAS_NOT_FOUND` (422)
- `REPLAY_DETECTED` (409)
- `CANON_ERROR` (422)
- `SIGN_ERROR` (422)
- `STORAGE_ERROR` (500)
- `INTERNAL_ERROR` (500)
- `UNAUTHORIZED` (401)
- `NOT_FOUND` (404)
- `TOO_MANY_REQUESTS` (429)
- `UNAVAILABLE` (503)

## Response Envelope

```json
{
  "@type": "ubl/error",
  "@id": "...",
  "@ver": "1.0",
  "@world": "a/<app>/t/<tenant>",
  "code": "invalid_signature",
  "message": "...",
  "link": "..."
}
```
