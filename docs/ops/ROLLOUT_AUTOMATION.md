# Rollout P0 → P1 Automation (H4)

## What this adds

Automated preflight gate for P0→P1 activation:
- runtime hash allowlist validation (`P0.runtime_allowlist`)
- `activation_time` lead-window enforcement
- signature quorum checks (count + unique signers)
- break-glass mode for emergency fallback to P0

Script:
- `scripts/rollout_p0_p1_check.sh`

## Quick start

```bash
RUNTIME_HASH="sha256:rt-PROD-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" \
make rollout-check
```

The command writes:
- `./data/rollout_report.json`

and exits non-zero if rollout checks fail (except in break-glass mode).

## Direct usage

```bash
bash scripts/rollout_p0_p1_check.sh \
  --p0 P0_GENESIS_POLICY.json \
  --p1 P1_POLICY_UPDATE.json \
  --runtime-hash "sha256:rt-PROD-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" \
  --min-lead-seconds 1800 \
  --report-file ./data/rollout_report.json
```

## Flags

- `--runtime-hash`: runtime hash to validate against P0 allowlist (required)
- `--expected-parent-cid`: optional parent CID lock check for P1
- `--min-lead-seconds`: minimum activation lead window
- `--now`: deterministic clock override for CI/rehearsal
- `--allow-placeholder-signatures`: dev-only; ignores placeholder sigs in template JSON
- `--break-glass`: force break-glass mode (emergency fallback path)
- `--break-glass-reason`: reason code in report

## Break-glass example

```bash
bash scripts/rollout_p0_p1_check.sh \
  --runtime-hash "sha256:rt-PROD-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" \
  --break-glass \
  --break-glass-reason "bootstrap.break_glass.manual_override" \
  --report-file ./data/rollout_break_glass_report.json
```

## Expected reason codes

- `runtime.hash_not_allowed`
- `p1.activation_window_invalid`
- `policy.quorum_not_met`
- `p1.core_types_missing`
- `p1.parent_mismatch`
- `policy.placeholder_signature_present`
