#!/usr/bin/env bash
# Check review status for a PR — log sizes, process status, and verdict extraction
# Usage: bash check-review.sh <PR_NUMBER> [SCRATCHPAD_DIR]

set -euo pipefail

PR_NUMBER="${1:?Usage: check-review.sh <PR_NUMBER> [SCRATCHPAD_DIR]}"
SCRATCHPAD="${2:-/tmp/claude-1000/-home-ubuntu-Projects-apm2/scratchpad}"

SEC_LOG="${SCRATCHPAD}/security_pr${PR_NUMBER}_output.log"
QUAL_LOG="${SCRATCHPAD}/quality_pr${PR_NUMBER}_output.log"

echo "=== Review Status for PR #${PR_NUMBER} ==="
echo ""

for REVIEW_TYPE in security quality; do
  LOG="${SCRATCHPAD}/${REVIEW_TYPE}_pr${PR_NUMBER}_output.log"
  echo "--- ${REVIEW_TYPE^^} review ---"

  if [[ ! -f "$LOG" ]]; then
    echo "  Log file: NOT FOUND"
    echo ""
    continue
  fi

  LINES=$(wc -l < "$LOG")
  SIZE=$(du -h "$LOG" | cut -f1)
  echo "  Log file: ${LINES} lines (${SIZE})"

  # Check if codex process is still running for this log
  RUNNING=$(ps aux | grep codex | grep -v grep | wc -l)
  if [[ $RUNNING -gt 0 ]]; then
    echo "  Process: RUNNING (${RUNNING} codex processes active)"
  else
    echo "  Process: FINISHED"
  fi

  # Try to extract verdict from log tail
  VERDICT=$(grep -i -E '(PASS|FAIL|APPROVED|REJECTED|BLOCKER|verdict|conclusion)' "$LOG" 2>/dev/null | tail -5)
  if [[ -n "$VERDICT" ]]; then
    echo "  Verdict indicators:"
    echo "$VERDICT" | sed 's/^/    /'
  else
    echo "  Verdict: NOT YET AVAILABLE"
  fi
  echo ""
done

echo "=== End Review Status ==="
