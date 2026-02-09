#!/usr/bin/env bash
# Check FAC review status for a PR.
# Usage:
#   bash check-review.sh <PR_NUMBER|PR_URL>

set -euo pipefail

INPUT="${1:-}"
STATE_FILE="${HOME}/.apm2/review_state.json"
EVENTS_FILE="${HOME}/.apm2/review_events.ndjson"
PULSE_DIR="${HOME}/.apm2/review_pulses"

if [[ -n "$INPUT" && "$INPUT" =~ ^https?://github.com/.+/pull/[0-9]+$ ]]; then
  PR_FILTER="$(echo "$INPUT" | awk -F/ '{print $NF}')"
elif [[ -n "$INPUT" && "$INPUT" =~ ^[0-9]+$ ]]; then
  PR_FILTER="$INPUT"
else
  PR_FILTER=""
fi

if [[ -t 1 ]]; then
  GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
else
  GREEN=''; RED=''; YELLOW=''; CYAN=''; NC=''
fi

echo "=== FAC Review Status ==="
if [[ -n "$PR_FILTER" ]]; then
  echo "PR filter: #${PR_FILTER}"
fi
echo ""

echo "--- Active Review State (${STATE_FILE}) ---"
if [[ ! -f "$STATE_FILE" ]]; then
  echo "  State file not found."
else
  if command -v jq >/dev/null 2>&1; then
    if [[ -n "$PR_FILTER" ]]; then
      jq -r --argjson pr "$PR_FILTER" '
        .reviewers
        | to_entries
        | map(select((.value.pr_number // 0) == $pr or ((.value.pr_url // "") | test("/pull/" + ($pr|tostring) + "$"))))
        | if length == 0 then "  (no active entries for filter)"
          else .[] | "  \(.value.review_type // "unknown") key=\(.key): pid=\(.value.pid) model=\(.value.model // "n/a") backend=\(.value.backend // "codex") sha=\(.value.head_sha // "n/a") restarts=\(.value.restart_count // 0) log=\(.value.log_file // "n/a")"
          end
      ' "$STATE_FILE"
    else
      jq -r '
        .reviewers
        | to_entries
        | if length == 0 then "  (no active entries)"
          else .[] | "  \(.value.review_type // "unknown") key=\(.key): pid=\(.value.pid) model=\(.value.model // "n/a") backend=\(.value.backend // "codex") sha=\(.value.head_sha // "n/a") restarts=\(.value.restart_count // 0) log=\(.value.log_file // "n/a")"
          end
      ' "$STATE_FILE"
    fi
  else
    echo "  jq not available; raw state:"
    sed 's/^/  /' "$STATE_FILE"
  fi
fi
echo ""

echo "--- Pulse Files ---"
if [[ -n "$PR_FILTER" ]]; then
  for review_type in security quality; do
    f="${PULSE_DIR}/pr${PR_FILTER}_review_pulse_${review_type}.json"
    legacy_f="${HOME}/.apm2/review_pulse_${review_type}.json"
    if [[ ! -f "$f" && -f "$legacy_f" ]]; then
      f="$legacy_f"
    fi
    label="$(basename "$f" .json)"
    if [[ -f "$f" ]]; then
      if command -v jq >/dev/null 2>&1; then
        sha="$(jq -r '.head_sha // "unknown"' "$f")"
        ts="$(jq -r '.written_at // "unknown"' "$f")"
        echo "  ${label}: head_sha=${sha} written_at=${ts}"
      else
        echo "  ${label}: present"
      fi
    else
      echo "  pr${PR_FILTER}_review_pulse_${review_type}: missing"
    fi
  done
else
  if [[ -d "$PULSE_DIR" ]]; then
    ls -1 "$PULSE_DIR"/pr*_review_pulse_*.json 2>/dev/null | tail -n 20 | sed 's/^/  /' || echo "  (no pulse files)"
  else
    echo "  (no pulse directory at ${PULSE_DIR})"
  fi
fi
echo ""

echo "--- Recent Review Events (${EVENTS_FILE}) ---"
if [[ ! -f "$EVENTS_FILE" ]]; then
  echo "  Event file not found."
else
  if command -v jq >/dev/null 2>&1; then
    if [[ -n "$PR_FILTER" ]]; then
      tail -n 200 "$EVENTS_FILE" \
        | jq -c --argjson pr "$PR_FILTER" 'select(.pr_number == $pr)' \
        | tail -n 20 \
        | jq -r '
            . as $e
            | "  [\($e.ts // "n/a")] \($e.event // "n/a") type=\($e.review_type // "n/a") seq=\($e.seq // 0) sha=\($e.head_sha // "n/a") model=\($e.model // "") backend=\($e.backend // "") verdict=\($e.verdict // "") reason=\($e.reason // "")"
          '
    else
      tail -n 20 "$EVENTS_FILE" \
        | jq -r '
            . as $e
            | "  [\($e.ts // "n/a")] \($e.event // "n/a") pr=#\($e.pr_number // 0) type=\($e.review_type // "n/a") seq=\($e.seq // 0) sha=\($e.head_sha // "n/a") model=\($e.model // "") backend=\($e.backend // "") verdict=\($e.verdict // "") reason=\($e.reason // "")"
          '
    fi
  else
    echo "  jq not available; raw tail:"
    tail -n 20 "$EVENTS_FILE" | sed 's/^/  /'
  fi
fi
echo ""

echo "--- Quick Health ---"
if [[ -f "$STATE_FILE" ]] && command -v jq >/dev/null 2>&1; then
  pids="$(jq -r '.reviewers | to_entries[]?.value.pid // empty' "$STATE_FILE" || true)"
  if [[ -z "$pids" ]]; then
    echo "  ${YELLOW}No active reviewer processes${NC}"
  else
    while IFS= read -r pid; do
      if [[ -z "$pid" ]]; then
        continue
      fi
      if kill -0 "$pid" >/dev/null 2>&1; then
        echo "  ${GREEN}PID ${pid} alive${NC}"
      else
        echo "  ${RED}PID ${pid} not running${NC}"
      fi
    done <<< "$pids"
  fi
else
  echo "  Health probe unavailable (state file or jq missing)."
fi

echo ""
echo "=== End FAC Review Status ==="
