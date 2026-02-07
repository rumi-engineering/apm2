#!/usr/bin/env bash
# Regression test for CI drift guard lint scripts (TCK-00409)
#
# Validates that:
# 1. review_artifact_lint detection function catches all known violation patterns
# 2. review_artifact_lint detection function permits all known-safe patterns
# 3. evidence_refs_lint block extraction scopes correctly to YAML keys
# 4. test_refs_lint path extraction handles YAML comments and quoted scalars
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

# --- Test 4: test_refs_lint path extraction handles YAML comments and quoted scalars ---
echo "Test 4: test_refs_lint path extraction edge cases"

# Helper: extract path from a YAML list line using the same logic as test_refs_lint.sh
extract_ref_path() {
    local line="$1"
    echo "$line" | \
        sed 's/ #.*$//' | \
        sed -n "s/^[[:space:]]*- [[:space:]]*[\"']\{0,1\}\([^\"']*\)[\"']\{0,1\}[[:space:]]*$/\1/p"
}

# Test 4a: Entry with trailing comment
test_input_comment='    - "crates/foo/src/bar.rs" # this is a test'
result_comment=$(extract_ref_path "$test_input_comment")
if [[ "$result_comment" == "crates/foo/src/bar.rs" ]]; then
    log_pass "Trailing YAML comment stripped: extracted '$result_comment'"
else
    log_fail "Trailing YAML comment NOT stripped: expected 'crates/foo/src/bar.rs', got '$result_comment'"
fi

# Test 4b: Entry with single quotes
test_input_squote="    - 'crates/foo/src/bar.rs'"
result_squote=$(extract_ref_path "$test_input_squote")
if [[ "$result_squote" == "crates/foo/src/bar.rs" ]]; then
    log_pass "Single-quoted scalar handled: extracted '$result_squote'"
else
    log_fail "Single-quoted scalar NOT handled: expected 'crates/foo/src/bar.rs', got '$result_squote'"
fi

# Test 4c: Entry with double quotes (baseline)
test_input_dquote='    - "crates/foo/src/bar.rs"'
result_dquote=$(extract_ref_path "$test_input_dquote")
if [[ "$result_dquote" == "crates/foo/src/bar.rs" ]]; then
    log_pass "Double-quoted scalar handled: extracted '$result_dquote'"
else
    log_fail "Double-quoted scalar NOT handled: expected 'crates/foo/src/bar.rs', got '$result_dquote'"
fi

# Test 4d: Single-quoted entry with trailing comment
test_input_squote_comment="    - 'crates/foo/src/bar.rs' # another comment"
result_squote_comment=$(extract_ref_path "$test_input_squote_comment")
if [[ "$result_squote_comment" == "crates/foo/src/bar.rs" ]]; then
    log_pass "Single-quoted + comment handled: extracted '$result_squote_comment'"
else
    log_fail "Single-quoted + comment NOT handled: expected 'crates/foo/src/bar.rs', got '$result_squote_comment'"
fi

# Test 4e: Bare path (no quotes)
test_input_bare='    - crates/foo/src/bar.rs'
result_bare=$(extract_ref_path "$test_input_bare")
if [[ "$result_bare" == "crates/foo/src/bar.rs" ]]; then
    log_pass "Bare path handled: extracted '$result_bare'"
else
    log_fail "Bare path NOT handled: expected 'crates/foo/src/bar.rs', got '$result_bare'"
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
