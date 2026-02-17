#!/usr/bin/env bash
set -euo pipefail

repo="${GITHUB_REPOSITORY:-guardian-intelligence/apm2}"
pr_number="${PR_NUMBER:-1}"
gh api "repos/${repo}/pulls/${pr_number}" >/dev/null
