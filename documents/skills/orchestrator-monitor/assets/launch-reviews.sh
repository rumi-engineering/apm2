#!/usr/bin/env bash
# Launch security + quality Codex reviews for a PR
# Usage: bash launch-reviews.sh <PR_NUMBER> [SCRATCHPAD_DIR]
#
# Prepares review prompts via envsubst and launches both reviews in background.
# Falls back to Gemini CLI if codex is rate-limited.

set -euo pipefail

PR_NUMBER="${1:?Usage: launch-reviews.sh <PR_NUMBER> [SCRATCHPAD_DIR]}"
SCRATCHPAD="${2:-/tmp/claude-1000/-home-ubuntu-Projects-apm2/scratchpad}"
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || echo /home/ubuntu/Projects/apm2)"

export PR_URL="https://github.com/guardian-intelligence/apm2/pull/${PR_NUMBER}"

mkdir -p "$SCRATCHPAD"

echo "Preparing review prompts for PR #${PR_NUMBER}..."

# Generate review prompts (PR URL is injected into prompt templates).
envsubst '${PR_URL}' < "${REPO_ROOT}/documents/reviews/SECURITY_REVIEW_PROMPT.md" \
  > "${SCRATCHPAD}/security_pr${PR_NUMBER}.md"
envsubst '${PR_URL}' < "${REPO_ROOT}/documents/reviews/CODE_QUALITY_PROMPT.md" \
  > "${SCRATCHPAD}/quality_pr${PR_NUMBER}.md"

# Launch security review
echo "Launching security review..."
codex exec -m gpt-5.3-codex --dangerously-bypass-approvals-and-sandbox - \
  < "${SCRATCHPAD}/security_pr${PR_NUMBER}.md" \
  > "${SCRATCHPAD}/security_pr${PR_NUMBER}_output.log" 2>&1 &
SEC_PID=$!

# Launch quality review
echo "Launching quality review..."
codex exec -m gpt-5.3-codex --dangerously-bypass-approvals-and-sandbox - \
  < "${SCRATCHPAD}/quality_pr${PR_NUMBER}.md" \
  > "${SCRATCHPAD}/quality_pr${PR_NUMBER}_output.log" 2>&1 &
QUAL_PID=$!

echo ""
echo "Reviews launched for PR #${PR_NUMBER}:"
echo "  Security: PID ${SEC_PID} -> ${SCRATCHPAD}/security_pr${PR_NUMBER}_output.log"
echo "  Quality:  PID ${QUAL_PID} -> ${SCRATCHPAD}/quality_pr${PR_NUMBER}_output.log"
echo ""
echo "Monitor with:"
echo "  bash ${REPO_ROOT}/.claude/skills/orchestrator-monitor/assets/check-review.sh ${PR_NUMBER} ${SCRATCHPAD}"
