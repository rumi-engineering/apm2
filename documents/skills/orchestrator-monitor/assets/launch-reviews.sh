#!/usr/bin/env bash
# Launch FAC review orchestration for a PR.
# Usage:
#   bash launch-reviews.sh <PR_NUMBER|PR_URL> [SCRATCHPAD_DIR]
#
# Primary path:
#   apm2 fac review run <PR_URL> --type all
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

if command -v apm2 >/dev/null 2>&1; then
  apm2 fac review run "$PR_URL" --type all
  exit $?
fi

if command -v cargo >/dev/null 2>&1; then
  cargo run -p apm2-cli -- fac review run "$PR_URL" --type all
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
  gemini -m gemini-2.5-flash -y -o stream-json -p "$(cat "$SEC_PROMPT")" &
  sec_pid=$!
  gemini -m gemini-2.5-flash -y -o stream-json -p "$(cat "$QUAL_PROMPT")" &
  qual_pid=$!
  wait "$sec_pid"
  wait "$qual_pid"
  exit $?
fi

echo "ERROR: no usable review executor found (apm2, cargo, codex, gemini)."
exit 1
