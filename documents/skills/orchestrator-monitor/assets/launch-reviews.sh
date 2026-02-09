#!/usr/bin/env bash
# Launch FAC review orchestration for a PR.
# Usage:
#   bash launch-reviews.sh <PR_NUMBER|PR_URL> [SCRATCHPAD_DIR]
#
# Primary path:
#   apm2 fac review dispatch <PR_URL> --type all
#   apm2 fac review project --pr <PR_NUMBER> ... (1Hz projection window)
# Fallback path:
#   direct codex/gemini parallel invocation when apm2 is unavailable.

set -euo pipefail

INPUT="${1:?Usage: launch-reviews.sh <PR_NUMBER|PR_URL> [SCRATCHPAD_DIR]}"
SCRATCHPAD="${2:-/tmp/apm2-review-scratchpad}"
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
EVENTS_FILE="${HOME}/.apm2/review_events.ndjson"

if [[ "$INPUT" =~ ^https?://github.com/.+/pull/[0-9]+$ ]]; then
  PR_URL="$INPUT"
  PR_NUMBER="$(echo "$PR_URL" | awk -F/ '{print $NF}')"
elif [[ "$INPUT" =~ ^[0-9]+$ ]]; then
  REPO_SLUG="$(gh repo view --json nameWithOwner --jq .nameWithOwner 2>/dev/null || echo guardian-intelligence/apm2)"
  PR_NUMBER="$INPUT"
  PR_URL="https://github.com/${REPO_SLUG}/pull/${PR_NUMBER}"
else
  echo "ERROR: first arg must be PR number or PR URL"
  exit 1
fi

mkdir -p "${HOME}/.apm2"
mkdir -p "$SCRATCHPAD"

echo "Launching FAC review sequence for PR #${PR_NUMBER}"
echo "  PR_URL: ${PR_URL}"
echo "  Events: ${EVENTS_FILE}"

tail_pid=""
if [[ -f "$EVENTS_FILE" ]]; then
  tail -n 0 -F "$EVENTS_FILE" | sed 's/^/[review-event] /' &
  tail_pid=$!
fi

cleanup_tail() {
  if [[ -n "$tail_pid" ]]; then
    kill "$tail_pid" >/dev/null 2>&1 || true
  fi
}
trap cleanup_tail EXIT

HEAD_SHA=""
if command -v gh >/dev/null 2>&1; then
  HEAD_SHA="$(gh pr view "$PR_NUMBER" --json headRefOid --jq '.headRefOid' 2>/dev/null || true)"
fi

run_projection_window() {
  local -a fac_bin=("$@")
  local dispatch_json
  local dispatch_epoch
  local after_seq=0
  local terminal_failure=0

  if ! command -v jq >/dev/null 2>&1; then
    echo "ERROR: jq is required for FAC projection output"
    return 1
  fi

  if [[ -n "$HEAD_SHA" ]]; then
    dispatch_json=$("${fac_bin[@]}" fac --json review dispatch "$PR_URL" --type all --expected-head-sha "$HEAD_SHA")
  else
    dispatch_json=$("${fac_bin[@]}" fac --json review dispatch "$PR_URL" --type all)
  fi

  dispatch_epoch=$(jq -r '.dispatch_epoch // 0' <<<"$dispatch_json")
  if [[ "$dispatch_epoch" == "0" ]]; then
    echo "ERROR: dispatch did not return a valid dispatch_epoch"
    return 1
  fi

  jq -r '.results[] | "dispatch review_type=\(.review_type) mode=\(.mode)" +
    (if .unit then " unit=\(.unit)" else "" end) +
    (if .pid then " pid=\(.pid|tostring)" else "" end)' <<<"$dispatch_json"

  for _ in $(seq 1 30); do
    local project_json
    if [[ -n "$HEAD_SHA" ]]; then
      project_json=$("${fac_bin[@]}" fac --json review project \
        --pr "$PR_NUMBER" \
        --head-sha "$HEAD_SHA" \
        --since-epoch "$dispatch_epoch" \
        --after-seq "$after_seq")
    else
      project_json=$("${fac_bin[@]}" fac --json review project \
        --pr "$PR_NUMBER" \
        --since-epoch "$dispatch_epoch" \
        --after-seq "$after_seq")
    fi

    if [[ -z "$project_json" ]] || ! jq -e . >/dev/null 2>&1 <<<"$project_json"; then
      now=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
      echo "ts=${now} security=unknown quality=unknown events=-"
      sleep 1
      continue
    fi

    jq -r --arg now "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" '.line // ("ts=" + $now + " security=unknown quality=unknown events=-")' <<<"$project_json"
    jq -r '.errors[]? | "ERROR ts=\(.ts) event=\(.event) review=\(.review_type) seq=\(.seq) detail=\(.detail)"' <<<"$project_json"

    next_seq=$(jq -r '.last_seq // 0' <<<"$project_json")
    if [[ "$next_seq" =~ ^[0-9]+$ ]]; then
      after_seq="$next_seq"
    fi

    if jq -e '.terminal_failure == true' >/dev/null 2>&1 <<<"$project_json"; then
      terminal_failure=1
      break
    fi

    sleep 1
  done

  if [[ "$terminal_failure" -ne 0 ]]; then
    echo "ERROR: terminal reviewer failure detected during projection window"
    return 1
  fi
}

if command -v apm2 >/dev/null 2>&1; then
  run_projection_window apm2
  exit $?
fi

if command -v cargo >/dev/null 2>&1; then
  cargo build --locked -p apm2-cli >/dev/null
  run_projection_window "${REPO_ROOT}/target/debug/apm2"
  exit $?
fi

echo "WARN: apm2/apm2-cli unavailable, falling back to direct CLI review execution."
SEC_PROMPT="${SCRATCHPAD}/security_pr${PR_NUMBER}.md"
QUAL_PROMPT="${SCRATCHPAD}/quality_pr${PR_NUMBER}.md"
envsubst '${PR_URL}' < "${REPO_ROOT}/documents/reviews/SECURITY_REVIEW_PROMPT.md" > "$SEC_PROMPT"
envsubst '${PR_URL}' < "${REPO_ROOT}/documents/reviews/CODE_QUALITY_PROMPT.md" > "$QUAL_PROMPT"

if command -v codex >/dev/null 2>&1; then
  codex exec --model gpt-5.3-codex --dangerously-bypass-approvals-and-sandbox --json - < "$SEC_PROMPT" &
  sec_pid=$!
  codex exec --model gpt-5.3-codex --dangerously-bypass-approvals-and-sandbox --json - < "$QUAL_PROMPT" &
  qual_pid=$!
  wait "$sec_pid"
  wait "$qual_pid"
  exit $?
fi

if command -v gemini >/dev/null 2>&1; then
  gemini -m gemini-3.0-flash-preview -y -o stream-json -p "$(cat "$SEC_PROMPT")" &
  sec_pid=$!
  gemini -m gemini-3.0-flash-preview -y -o stream-json -p "$(cat "$QUAL_PROMPT")" &
  qual_pid=$!
  wait "$sec_pid"
  wait "$qual_pid"
  exit $?
fi

echo "ERROR: no usable review executor found (apm2, cargo, codex, gemini)."
exit 1
