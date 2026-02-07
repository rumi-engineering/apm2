#!/usr/bin/env bash
# Post AI review status check to GitHub for a PR
# Usage: bash post-review-status.sh <PR_NUMBER> <REVIEW_TYPE> <STATE> [DESCRIPTION]
#
# REVIEW_TYPE: "security" or "code-quality"
# STATE: "success", "failure", or "pending"
# DESCRIPTION: optional description (defaults based on state)

set -euo pipefail

PR_NUMBER="${1:?Usage: post-review-status.sh <PR_NUMBER> <REVIEW_TYPE> <STATE> [DESCRIPTION]}"
REVIEW_TYPE="${2:?Must specify review type: security or code-quality}"
STATE="${3:?Must specify state: success, failure, or pending}"

# Validate review type
if [[ "$REVIEW_TYPE" != "security" && "$REVIEW_TYPE" != "code-quality" ]]; then
  echo "ERROR: REVIEW_TYPE must be 'security' or 'code-quality', got '${REVIEW_TYPE}'"
  exit 1
fi

# Validate state
if [[ "$STATE" != "success" && "$STATE" != "failure" && "$STATE" != "pending" ]]; then
  echo "ERROR: STATE must be 'success', 'failure', or 'pending', got '${STATE}'"
  exit 1
fi

# Default descriptions
case "$STATE" in
  success) DEFAULT_DESC="Approved" ;;
  failure) DEFAULT_DESC="${REVIEW_TYPE} review failure" ;;
  pending) DEFAULT_DESC="${REVIEW_TYPE} review in progress" ;;
esac
DESCRIPTION="${4:-$DEFAULT_DESC}"

# Get HEAD SHA
HEAD_SHA=$(gh pr view "$PR_NUMBER" --json headRefOid -q '.headRefOid')
if [[ -z "$HEAD_SHA" ]]; then
  echo "ERROR: Could not get HEAD SHA for PR #${PR_NUMBER}"
  exit 1
fi

CONTEXT="ai-review/${REVIEW_TYPE}"

echo "Posting status for PR #${PR_NUMBER}:"
echo "  HEAD: ${HEAD_SHA:0:12}"
echo "  Context: ${CONTEXT}"
echo "  State: ${STATE}"
echo "  Description: ${DESCRIPTION}"

gh api --method POST "repos/rumi-engineering/apm2/statuses/${HEAD_SHA}" \
  -f state="$STATE" \
  -f context="$CONTEXT" \
  -f description="$DESCRIPTION"

echo "Done."
