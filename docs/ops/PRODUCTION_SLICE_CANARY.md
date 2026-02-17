# Production Slice Canary (M5)

## Goal

Run one narrow end-to-end workflow continuously and capture SLO evidence:
- submit chip
- trace receipt
- verify chip integrity
- narrate receipt

Workflow used:
- `document_attestation_canary` (`ubl/document`)

## Command

```bash
make prod-slice-canary
```

Environment overrides:

```bash
BASE_URL="http://127.0.0.1:4000" ITERATIONS=50 make prod-slice-canary
```

Output report:
- `./data/production_slice_report.json`

## Pass criteria per run

- `success_count == iterations`
- `error_count == 0`
- `latency_ms.p99 <= 1000`
- `latency_ms.p95 <= 250`

## Notes

- Canary optionally persists narration advisories (`persist=true` default in script).
- Script exits non-zero if any iteration fails, so it is CI/scheduler-friendly.
- Use this output as input evidence for G5 over the 30-day window.
