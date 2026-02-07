#!/usr/bin/env bash
# Regression test for CI drift guard lint scripts (TCK-00409)
#
# Validates that:
# 1. review_artifact_lint detection function catches all known violation patterns
# 2. review_artifact_lint detection function permits all known-safe patterns
# 3. evidence_refs_lint block extraction scopes correctly to YAML keys
#
# Exit codes:
#   0 - All fixture tests pass
#   1 - One or more fixture tests failed
#
# Usage:
#   ./scripts/ci/test_lint_fixtures.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURE_DIR="${SCRIPT_DIR}/fixtures"
FAILURES=0

if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    NC=''
fi

log_pass() { echo -e "${GREEN}PASS:${NC} $*"; }
log_fail() { echo -e "${RED}FAIL:${NC} $*" >&2; FAILURES=$((FAILURES + 1)); }

echo "=== Lint Fixture Regression Tests ==="
echo

# --- Test 1: review_artifact_lint violation patterns ---
# Source the detect_direct_status_write function from the lint script.
# We do this by extracting just the function.
source <(sed -n '/^detect_direct_status_write()/,/^}/p' "${SCRIPT_DIR}/review_artifact_lint.sh")

echo "Test 1: review_artifact_lint violation patterns"
while IFS= read -r line; do
    # Skip blank lines and comments
    [[ -z "$line" || "$line" == "#"* ]] && continue
    if detect_direct_status_write "$line"; then
        log_pass "Caught violation: ${line:0:80}..."
    else
        log_fail "Missed violation: ${line}"
    fi
done < "${FIXTURE_DIR}/review_artifact_lint_violations.txt"
echo

echo "Test 2: review_artifact_lint permitted patterns"
while IFS= read -r line; do
    # Skip blank lines and comments
    [[ -z "$line" || "$line" == "#"* ]] && continue
    if detect_direct_status_write "$line"; then
        log_fail "False positive: ${line}"
    else
        log_pass "Permitted: ${line:0:80}..."
    fi
done < "${FIXTURE_DIR}/review_artifact_lint_permitted.txt"
echo

# --- Test 3: evidence_refs_lint block extraction scope ---
# Source the extract_yaml_list_block function
source <(sed -n '/^extract_yaml_list_block()/,/^}/p' "${SCRIPT_DIR}/evidence_refs_lint.sh")

echo "Test 3: evidence_refs_lint narrative scope (REQ-FAKE9999 must NOT appear)"
fixture_file="${FIXTURE_DIR}/evidence_refs_narrative_nofail.yaml"
extracted_ids=$(extract_yaml_list_block "$fixture_file" "requirement_ids" | \
    grep -oP 'REQ-[A-Z]*[0-9]+' | sort -u || true)

if echo "$extracted_ids" | grep -q "REQ-FAKE9999"; then
    log_fail "extract_yaml_list_block leaked narrative token REQ-FAKE9999 into requirement_ids"
else
    log_pass "Narrative token REQ-FAKE9999 correctly excluded from requirement_ids block"
fi

# Verify it does extract the real reference
if echo "$extracted_ids" | grep -q "REQ-0101"; then
    log_pass "Real requirement REQ-0101 correctly extracted from requirement_ids block"
else
    log_fail "Real requirement REQ-0101 not extracted from requirement_ids block"
fi
echo

# --- Summary ---
echo "=== Fixture Test Summary ==="
if [[ $FAILURES -gt 0 ]]; then
    echo -e "${RED}FAILED: $FAILURES test(s) failed${NC}" >&2
    exit 1
else
    echo -e "${GREEN}PASSED: All fixture tests passed${NC}"
    exit 0
fi
