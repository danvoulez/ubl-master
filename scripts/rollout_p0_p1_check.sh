#!/usr/bin/env bash
set -euo pipefail

P0_FILE="P0_GENESIS_POLICY.json"
P1_FILE="P1_POLICY_UPDATE.json"
RUNTIME_HASH=""
EXPECTED_PARENT_CID=""
MIN_LEAD_SECONDS=300
NOW_OVERRIDE=""
BREAK_GLASS=false
BREAK_GLASS_REASON="bootstrap.break_glass"
ALLOW_PLACEHOLDER_SIGNATURES=false
REPORT_FILE=""

usage() {
  cat <<'EOF'
Usage:
  scripts/rollout_p0_p1_check.sh [options]

Options:
  --p0 <file>                         P0 policy file (default: P0_GENESIS_POLICY.json)
  --p1 <file>                         P1 update file (default: P1_POLICY_UPDATE.json)
  --runtime-hash <sha256:...>         Runtime hash to validate against P0 allowlist (required)
  --expected-parent-cid <b3:...>      Optional expected P1 parent CID
  --min-lead-seconds <n>              Minimum activation lead time in seconds (default: 300)
  --now <RFC3339>                     Override "now" time (for deterministic CI checks)
  --break-glass                       Enable emergency fallback mode (P0 only)
  --break-glass-reason <code>         Reason code for break-glass
  --allow-placeholder-signatures      Allow PLACEHOLDER signatures (dev only)
  --report-file <path>                Optional path to write JSON report
  -h, --help                          Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --p0) P0_FILE="${2:-}"; shift 2 ;;
    --p1) P1_FILE="${2:-}"; shift 2 ;;
    --runtime-hash) RUNTIME_HASH="${2:-}"; shift 2 ;;
    --expected-parent-cid) EXPECTED_PARENT_CID="${2:-}"; shift 2 ;;
    --min-lead-seconds) MIN_LEAD_SECONDS="${2:-}"; shift 2 ;;
    --now) NOW_OVERRIDE="${2:-}"; shift 2 ;;
    --break-glass) BREAK_GLASS=true; shift ;;
    --break-glass-reason) BREAK_GLASS_REASON="${2:-}"; shift 2 ;;
    --allow-placeholder-signatures) ALLOW_PLACEHOLDER_SIGNATURES=true; shift ;;
    --report-file) REPORT_FILE="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ -z "$RUNTIME_HASH" ]]; then
  echo "missing --runtime-hash" >&2
  exit 2
fi

if [[ ! -f "$P0_FILE" ]]; then
  echo "P0 file not found: $P0_FILE" >&2
  exit 2
fi
if [[ ! -f "$P1_FILE" ]]; then
  echo "P1 file not found: $P1_FILE" >&2
  exit 2
fi

parse_epoch() {
  local ts="$1"
  if date -d "$ts" +%s >/dev/null 2>&1; then
    date -d "$ts" +%s
  elif date -j -f "%Y-%m-%dT%H:%M:%SZ" "$ts" +%s >/dev/null 2>&1; then
    date -j -f "%Y-%m-%dT%H:%M:%SZ" "$ts" +%s
  elif date -j -f "%Y-%m-%dT%H:%M:%S%z" "$ts" +%s >/dev/null 2>&1; then
    date -j -f "%Y-%m-%dT%H:%M:%S%z" "$ts" +%s
  else
    return 1
  fi
}

if ! jq empty "$P0_FILE" >/dev/null 2>&1; then
  echo "invalid JSON in $P0_FILE" >&2
  exit 2
fi
if ! jq empty "$P1_FILE" >/dev/null 2>&1; then
  echo "invalid JSON in $P1_FILE" >&2
  exit 2
fi

if [[ -n "$NOW_OVERRIDE" ]]; then
  NOW_EPOCH="$(parse_epoch "$NOW_OVERRIDE" || true)"
  if [[ -z "$NOW_EPOCH" ]]; then
    echo "invalid --now value: $NOW_OVERRIDE" >&2
    exit 2
  fi
  NOW_RFC3339="$NOW_OVERRIDE"
else
  NOW_EPOCH="$(date -u +%s)"
  NOW_RFC3339="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
fi

ACTIVATION_TIME="$(jq -r '.activation_time // empty' "$P1_FILE")"
ACTIVATION_EPOCH=""
if [[ -n "$ACTIVATION_TIME" ]]; then
  ACTIVATION_EPOCH="$(parse_epoch "$ACTIVATION_TIME" || true)"
fi

RUNTIME_OK=false
if jq -e --arg rh "$RUNTIME_HASH" '.runtime_allowlist // [] | index($rh) != null' "$P0_FILE" >/dev/null; then
  RUNTIME_OK=true
fi

P0_TYPE_OK=false
if jq -e '.["@type"] == "policy/genesis"' "$P0_FILE" >/dev/null; then
  P0_TYPE_OK=true
fi

P1_TYPE_OK=false
if jq -e '.["@type"] == "policy/update"' "$P1_FILE" >/dev/null; then
  P1_TYPE_OK=true
fi

PARENT_OK=true
if [[ -n "$EXPECTED_PARENT_CID" ]]; then
  if ! jq -e --arg p "$EXPECTED_PARENT_CID" '.parent == $p' "$P1_FILE" >/dev/null; then
    PARENT_OK=false
  fi
fi

LEAD_OK=false
LEAD_SECONDS=-1
if [[ -n "$ACTIVATION_EPOCH" ]]; then
  LEAD_SECONDS=$((ACTIVATION_EPOCH - NOW_EPOCH))
  if [[ "$LEAD_SECONDS" -ge "$MIN_LEAD_SECONDS" ]]; then
    LEAD_OK=true
  fi
fi

QUORUM="$(jq -r '.trust_root.quorum.threshold // 0' "$P0_FILE")"
SIG_COUNT="$(jq -r '.signatures // [] | length' "$P1_FILE")"
SIG_UNIQUE_BY="$(jq -r '[.signatures[]?.by] | unique | length' "$P1_FILE")"
QUORUM_OK=false
if [[ "$SIG_COUNT" -ge "$QUORUM" && "$SIG_UNIQUE_BY" -ge "$QUORUM" ]]; then
  QUORUM_OK=true
fi

PLACEHOLDER_SIG_COUNT="$(jq -r '[.signatures[]? | select((.sig // "") | test("PLACEHOLDER"))] | length' "$P1_FILE")"
PLACEHOLDER_OK=true
if [[ "$PLACEHOLDER_SIG_COUNT" -gt 0 && "$ALLOW_PLACEHOLDER_SIGNATURES" != true ]]; then
  PLACEHOLDER_OK=false
fi

CORE_TYPES_MISSING_JSON="$(
  jq -n --slurpfile p1 "$P1_FILE" '
    ["ubl/app","ubl/user","ubl/tenant","ubl/membership","ubl/token","ubl/revoke"]
    | map(select((($p1[0].diff["permit_types+"] // []) | index(.)) | not))
  '
)"
CORE_TYPES_MISSING_COUNT="$(echo "$CORE_TYPES_MISSING_JSON" | jq 'length')"
CORE_TYPES_OK=false
if [[ "$CORE_TYPES_MISSING_COUNT" -eq 0 ]]; then
  CORE_TYPES_OK=true
fi

FAILURES=()
if [[ "$P0_TYPE_OK" != true ]]; then FAILURES+=("p0.type_invalid"); fi
if [[ "$P1_TYPE_OK" != true ]]; then FAILURES+=("p1.type_invalid"); fi
if [[ "$RUNTIME_OK" != true ]]; then FAILURES+=("runtime.hash_not_allowed"); fi
if [[ "$PARENT_OK" != true ]]; then FAILURES+=("p1.parent_mismatch"); fi
if [[ "$LEAD_OK" != true ]]; then FAILURES+=("p1.activation_window_invalid"); fi
if [[ "$QUORUM_OK" != true ]]; then FAILURES+=("policy.quorum_not_met"); fi
if [[ "$PLACEHOLDER_OK" != true ]]; then FAILURES+=("policy.placeholder_signature_present"); fi
if [[ "$CORE_TYPES_OK" != true ]]; then FAILURES+=("p1.core_types_missing"); fi

APPROVED=true
MODE="normal"
if [[ "$BREAK_GLASS" == true ]]; then
  MODE="break_glass"
  APPROVED=true
else
  if [[ "${#FAILURES[@]}" -gt 0 ]]; then
    APPROVED=false
  fi
fi

FAILURES_JSON="[]"
if [[ "${#FAILURES[@]}" -gt 0 ]]; then
  FAILURES_JSON="$(printf '%s\n' "${FAILURES[@]}" | jq -R . | jq -s .)"
fi

REPORT="$(jq -n \
  --arg mode "$MODE" \
  --arg now "$NOW_RFC3339" \
  --arg runtime_hash "$RUNTIME_HASH" \
  --arg activation_time "$ACTIVATION_TIME" \
  --argjson min_lead_seconds "$MIN_LEAD_SECONDS" \
  --argjson lead_seconds "$LEAD_SECONDS" \
  --argjson approved "$APPROVED" \
  --argjson runtime_ok "$RUNTIME_OK" \
  --argjson lead_ok "$LEAD_OK" \
  --argjson quorum_ok "$QUORUM_OK" \
  --argjson placeholder_ok "$PLACEHOLDER_OK" \
  --argjson core_types_ok "$CORE_TYPES_OK" \
  --argjson failures "$FAILURES_JSON" \
  --argjson core_types_missing "$CORE_TYPES_MISSING_JSON" \
  --arg break_glass_reason "$BREAK_GLASS_REASON" \
  '{
    mode: $mode,
    approved: $approved,
    now: $now,
    runtime_hash: $runtime_hash,
    activation_time: $activation_time,
    checks: {
      runtime_hash_allowed: $runtime_ok,
      activation_window_ok: $lead_ok,
      min_lead_seconds: $min_lead_seconds,
      lead_seconds: $lead_seconds,
      quorum_ok: $quorum_ok,
      signatures_placeholder_ok: $placeholder_ok,
      core_types_ok: $core_types_ok,
      core_types_missing: $core_types_missing
    },
    failures: $failures,
    break_glass: {
      enabled: ($mode == "break_glass"),
      reason: $break_glass_reason
    }
  }'
)"

if [[ -n "$REPORT_FILE" ]]; then
  mkdir -p "$(dirname "$REPORT_FILE")"
  echo "$REPORT" > "$REPORT_FILE"
fi

echo "$REPORT"

if [[ "$BREAK_GLASS" == true ]]; then
  exit 0
fi

if [[ "$APPROVED" != true ]]; then
  exit 1
fi
