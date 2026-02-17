# Release Readiness

**Status**: active
**Owner**: Core Runtime + Ops
**Last reviewed**: 2026-02-17

A release is ready only when all gates below are green.

## Gate Checklist

- [ ] G1 Security trust chain closed
  - receipt signatures verify offline
  - rich URL verification behavior matches environment mode
  - stage auth chain secret is configured (no implicit dev secret in prod)
- [ ] G2 Determinism proven
  - canonical CID/sign paths are NRF-only
  - determinism tests and KATs pass in CI
- [ ] G3 Data path scalable
  - no scan-based hot path for receipt/chip lookups
  - index rebuild/recovery tested
- [ ] G4 Runtime operable
  - tracing + metrics + alerting wired
  - outbox pending/retry monitored
  - incident runbook validated
- [ ] G5 Production slice stable
  - canary workflow run completed
  - SLO targets met for 30 consecutive days

## Required Evidence Artifacts

1. CI test run URL or artifact set.
2. Metrics snapshot from `/metrics` plus dashboard export.
3. Rollout preflight output (`make rollout-check`).
4. Incident drill notes (`docs/ops/INCIDENT_RUNBOOK.md`).
5. Canary report (`docs/ops/PRODUCTION_SLICE_CANARY.md`).
