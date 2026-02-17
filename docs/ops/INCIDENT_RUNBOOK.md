# UBL Gate Incident Runbook (M4)

## Scope

Operational runbook for `ubl_gate` covering:
- SLO breach response
- outbox/idempotency incidents
- crypto/canon verification incidents
- runtime attestation checks

Artifacts:
- Alerts: `ops/prometheus/ubl-alerts.yml`
- Dashboard: `ops/grafana/ubl-slo-dashboard.json`

## SLO Targets

- Availability: `99.9%` monthly
- Pipeline latency:
  - p95 `< 250ms`
  - p99 `< 1s`
- Error ratio: `< 2%` (excluding explicit policy denies if tracked separately)

## First 10 Minutes

1. Confirm active alerts in Alertmanager.
2. Open Grafana dashboard `UBL Gate SLO Dashboard`.
3. Check:
   - p99 latency panel
   - error rate panel
   - outbox pending and retry panels
   - crypto/canon health panel
4. Classify incident type:
   - availability
   - latency
   - correctness (signature/canon/runtime hash)
   - durability (outbox/idempotency)

## Triage Commands

```bash
# Health
curl -sS http://localhost:4000/healthz

# Metrics snapshot
curl -sS http://localhost:4000/metrics | rg '^ubl_'

# Runtime self-attestation check
curl -sS http://localhost:4000/v1/runtime/attestation | jq .
```

## Playbooks

### 1) Gate Down (`UblGateDown`)

1. Restart service process/container.
2. Verify `/healthz` and `/metrics`.
3. Confirm `up{job="ubl-gate"} == 1`.
4. If restart fails, roll back to last known good release.

### 2) High p99 (`UblPipelineP99LatencyHigh`)

1. Check `ubl_outbox_pending` and `ubl_outbox_retry_total`.
2. Check request rate (`ubl_chips_total`) for traffic spike.
3. If outbox backlog is high:
   - increase `UBL_OUTBOX_WORKERS` temporarily
   - inspect SQLite locks / IO saturation
4. If policy/VM path regressed:
   - inspect recent deploy diff
   - revert rollout flags for strict modes if needed

### 3) High Error Rate (`UblPipelineErrorRateHigh`)

1. Inspect `ubl_errors_total` by code.
2. If mostly validation/input errors:
   - coordinate with client teams (bad payload wave).
3. If internal/storage errors:
   - check disk space, SQLite health, and recent deployment.
4. If `invalid_signature`/`runtime_hash_mismatch` increases:
   - run crypto incident playbook below.

### 4) Outbox Backlog / Retry Spike

1. Verify DB reachable and writable.
2. Check worker count (`UBL_OUTBOX_WORKERS`).
3. Confirm unknown event types are not flooding retries.
4. Drain backlog; track metric recovery:
   - `ubl_outbox_pending` trending down
   - `ubl_outbox_retry_total` flattening

### 5) Crypto or Canon Divergence

1. Identify component/mode labels on:
   - `ubl_crypto_verify_fail_total`
   - `ubl_canon_divergence_total`
2. Switch affected scope to safer mode if needed:
   - rich URL `shadow`
   - keep dual-verify until fixed
3. Capture failing payload + receipt for offline reproduce.
4. Block promote-to-strict until mismatch is zero for 24h.

## Runtime Certification Check

Use runtime attestation endpoint and validate:
- `attestation.runtime_hash == attestation.runtime.runtime_hash`
- `verified == true`
- `attestation.did` and `kid` belong to current runtime signer

Escalate immediately if attestation verification fails across replicas.

## Failure Drill (Weekly)

1. Inject one synthetic outbox failure.
2. Confirm alert triggers and runbook execution time `< 15min`.
3. Validate replay safety by re-submitting same chip id (`replayed=true`).
4. Record:
   - detection time
   - mitigation time
   - residual impact

## Exit Criteria

Incident is resolved when all are true:
- Triggering alert cleared for 15 minutes.
- p99 and error ratio back inside SLO.
- Outbox backlog is stable/downward.
- No ongoing crypto/canon divergence increases.
