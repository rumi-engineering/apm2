#!/usr/bin/env bash
set -euo pipefail

curl -H "Authorization: token ${GH_PAT}" \
  -X POST "https://api.github.com/repos/guardian-intelligence/apm2/check-runs"

gh api --token "${GITHUB_PAT}" "repos/guardian-intelligence/apm2/pulls/1" >/dev/null
