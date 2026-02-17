#!/usr/bin/env bash
set -euo pipefail

BASE_URL="http://127.0.0.1:4000"
ITERATIONS=20
WORLD="a/canary/t/prod"
REPORT_FILE=""
PERSIST_NARRATION=true

usage() {
  cat <<'EOF'
Usage:
  scripts/production_slice_canary.sh [options]

Options:
  --base-url <url>         Gate base URL (default: http://127.0.0.1:4000)
  --iterations <n>         Number of canary chips to submit (default: 20)
  --world <a/...>          World scope for test chips (default: a/canary/t/prod)
  --report-file <path>     Optional output JSON report path
  --no-persist-narration   Do not persist narration advisories
  -h, --help               Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --base-url) BASE_URL="${2:-}"; shift 2 ;;
    --iterations) ITERATIONS="${2:-}"; shift 2 ;;
    --world) WORLD="${2:-}"; shift 2 ;;
    --report-file) REPORT_FILE="${2:-}"; shift 2 ;;
    --no-persist-narration) PERSIST_NARRATION=false; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

if ! [[ "$ITERATIONS" =~ ^[0-9]+$ ]] || [[ "$ITERATIONS" -le 0 ]]; then
  echo "--iterations must be a positive integer" >&2
  exit 2
fi

curl -fsS "$BASE_URL/healthz" >/dev/null

latencies_ms=()
errors=()
success_count=0

for ((i=1; i<=ITERATIONS; i++)); do
  chip_id="canary-$(date -u +"%Y%m%dT%H%M%SZ")-$i"
  chip="$(jq -n \
    --arg id "$chip_id" \
    --arg world "$WORLD" \
    --arg note "production-slice-canary" \
    '{
      "@type":"ubl/document",
      "@id":$id,
      "@ver":"1.0",
      "@world":$world,
      "content":"Canary document",
      "note":$note
    }'
  )"

  post_resp="$(curl -sS \
    -w '\n%{http_code}\n%{time_total}\n' \
    -H 'Content-Type: application/json' \
    --data "$chip" \
    "$BASE_URL/v1/chips")"

  post_http="$(printf '%s\n' "$post_resp" | tail -n 2 | head -n 1)"
  post_secs="$(printf '%s\n' "$post_resp" | tail -n 1)"
  post_body="$(printf '%s\n' "$post_resp" | sed '$d' | sed '$d')"
  post_ms="$(awk -v s="$post_secs" 'BEGIN { printf "%.3f", s * 1000 }')"
  latencies_ms+=("$post_ms")

  if [[ "$post_http" != "200" ]]; then
    errors+=("post_http:$chip_id:$post_http")
    continue
  fi

  decision="$(echo "$post_body" | jq -r '.decision // ""' 2>/dev/null || true)"
  receipt_cid="$(echo "$post_body" | jq -r '.receipt_cid // ""' 2>/dev/null || true)"
  if [[ "$decision" != "Allow" || -z "$receipt_cid" || "$receipt_cid" == "null" ]]; then
    errors+=("post_semantics:$chip_id")
    continue
  fi

  trace_http="$(curl -sS -o /tmp/ubl_trace_"$$".json -w '%{http_code}' "$BASE_URL/v1/receipts/$receipt_cid/trace")"
  if [[ "$trace_http" != "200" ]]; then
    errors+=("trace_http:$chip_id:$trace_http")
    rm -f /tmp/ubl_trace_"$$".json
    continue
  fi
  chip_cid="$(jq -r '.chip_cid // ""' /tmp/ubl_trace_"$$".json 2>/dev/null || true)"
  rm -f /tmp/ubl_trace_"$$".json
  if [[ -z "$chip_cid" || "$chip_cid" == "null" ]]; then
    errors+=("trace_semantics:$chip_id")
    continue
  fi

  verify_http="$(curl -sS -o /tmp/ubl_verify_"$$".json -w '%{http_code}' "$BASE_URL/v1/chips/$chip_cid/verify")"
  if [[ "$verify_http" != "200" ]]; then
    errors+=("verify_http:$chip_id:$verify_http")
    rm -f /tmp/ubl_verify_"$$".json
    continue
  fi
  verified="$(jq -r '.verified // false' /tmp/ubl_verify_"$$".json 2>/dev/null || true)"
  rm -f /tmp/ubl_verify_"$$".json
  if [[ "$verified" != "true" ]]; then
    errors+=("verify_semantics:$chip_id")
    continue
  fi

  narrate_url="$BASE_URL/v1/receipts/$receipt_cid/narrate"
  if [[ "$PERSIST_NARRATION" == true ]]; then
    narrate_url="$narrate_url?persist=true"
  fi
  narrate_http="$(curl -sS -o /tmp/ubl_narrate_"$$".json -w '%{http_code}' "$narrate_url")"
  if [[ "$narrate_http" != "200" ]]; then
    errors+=("narrate_http:$chip_id:$narrate_http")
    rm -f /tmp/ubl_narrate_"$$".json
    continue
  fi
  narration_type="$(jq -r '.narration["@type"] // ""' /tmp/ubl_narrate_"$$".json 2>/dev/null || true)"
  rm -f /tmp/ubl_narrate_"$$".json
  if [[ "$narration_type" != "ubl/advisory.narration" ]]; then
    errors+=("narrate_semantics:$chip_id")
    continue
  fi

  success_count=$((success_count + 1))
done

count="${#latencies_ms[@]}"
if [[ "$count" -gt 0 ]]; then
  mean_ms="$(printf '%s\n' "${latencies_ms[@]}" | awk '{sum+=$1} END{if(NR==0) print 0; else printf "%.3f", sum/NR}')"
  p95_ms="$(printf '%s\n' "${latencies_ms[@]}" | sort -n | awk '{a[NR]=$1} END{if(NR==0){print 0}else{idx=int(0.95*NR+0.999999); if(idx<1)idx=1; if(idx>NR)idx=NR; printf "%.3f", a[idx]}}')"
  p99_ms="$(printf '%s\n' "${latencies_ms[@]}" | sort -n | awk '{a[NR]=$1} END{if(NR==0){print 0}else{idx=int(0.99*NR+0.999999); if(idx<1)idx=1; if(idx>NR)idx=NR; printf "%.3f", a[idx]}}')"
else
  mean_ms="0"
  p95_ms="0"
  p99_ms="0"
fi

error_count="${#errors[@]}"
success_rate="$(awk -v ok="$success_count" -v total="$ITERATIONS" 'BEGIN { if (total==0) print 0; else printf "%.6f", ok/total }')"

errors_json="[]"
if [[ "$error_count" -gt 0 ]]; then
  errors_json="$(printf '%s\n' "${errors[@]}" | jq -R . | jq -s .)"
fi

report="$(jq -n \
  --arg now "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
  --arg base_url "$BASE_URL" \
  --arg world "$WORLD" \
  --argjson iterations "$ITERATIONS" \
  --argjson success_count "$success_count" \
  --argjson error_count "$error_count" \
  --argjson success_rate "$success_rate" \
  --argjson p95_ms "$p95_ms" \
  --argjson p99_ms "$p99_ms" \
  --argjson mean_ms "$mean_ms" \
  --argjson errors "$errors_json" \
  '{
    "@type":"ubl/production-slice.report",
    generated_at: $now,
    workflow: "document_attestation_canary",
    base_url: $base_url,
    world: $world,
    iterations: $iterations,
    success_count: $success_count,
    error_count: $error_count,
    success_rate: $success_rate,
    latency_ms: {
      mean: $mean_ms,
      p95: $p95_ms,
      p99: $p99_ms
    },
    errors: $errors
  }'
)"

if [[ -n "$REPORT_FILE" ]]; then
  mkdir -p "$(dirname "$REPORT_FILE")"
  echo "$report" > "$REPORT_FILE"
fi

echo "$report"

if [[ "$success_count" -lt "$ITERATIONS" ]]; then
  exit 1
fi

