#!/usr/bin/env bash
# Regression test for CI drift guard lint scripts (TCK-00409)
#
# Validates that:
# 1. review_artifact_lint detection function catches all known violation patterns
# 2. review_artifact_lint detection function permits all known-safe patterns
# 3. evidence_refs_lint block extraction scopes correctly to YAML keys
# 4. test_refs_lint path extraction handles YAML comments and quoted scalars
# 5. ticket ref validation detects broken requirement_ref / artifact_ref
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
# Source helper functions and detect_direct_status_write from the lint script.
# strip_comments and flatten_stream are needed by the file-level check functions.
source <(sed -n '/^strip_comments()/,/^}/p' "${SCRIPT_DIR}/review_artifact_lint.sh")
source <(sed -n '/^flatten_stream()/,/^}/p' "${SCRIPT_DIR}/review_artifact_lint.sh")
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

# --- Test 2b: review_artifact_lint primary gate (file-level ai-review/security literal) ---
echo "Test 2b: review_artifact_lint primary gate (stream-level ai-review/security detection)"
# Provide stub log_error for the sourced function (it uses log_error internally)
log_error() { :; }
# strip_comments and flatten_stream already sourced above
source <(sed -n '/^check_file_for_security_literal()/,/^}/p' "${SCRIPT_DIR}/review_artifact_lint.sh")

# Test 2b-i: File containing ai-review/security literal in non-comment code -> MUST FAIL
violation_fixture="${FIXTURE_DIR}/review_file_literal_violation.md"
if check_file_for_security_literal "$violation_fixture" "review_file_literal_violation.md"; then
    log_pass "Primary gate caught ai-review/security literal in non-exempt file"
else
    log_fail "Primary gate missed ai-review/security literal in non-exempt file: $(basename "$violation_fixture")"
fi

# Test 2b-ii: File that does NOT contain ai-review/security anywhere -> MUST PASS
permitted_fixture="${FIXTURE_DIR}/review_file_literal_permitted.md"
if check_file_for_security_literal "$permitted_fixture" "review_file_literal_permitted.md"; then
    log_fail "Primary gate false positive on file without ai-review/security: $(basename "$permitted_fixture")"
else
    log_pass "Primary gate correctly permits file without ai-review/security literal"
fi

# Test 2b-iii: SECURITY_REVIEW_PROMPT.md is always exempt -> MUST PASS
if check_file_for_security_literal "$violation_fixture" "SECURITY_REVIEW_PROMPT.md"; then
    log_fail "Primary gate not exempting SECURITY_REVIEW_PROMPT.md"
else
    log_pass "Primary gate correctly exempts SECURITY_REVIEW_PROMPT.md"
fi

# Test 2b-iv: Split-token construction (bypass vector) -> MUST FAIL
split_token_fixture="${FIXTURE_DIR}/review_file_split_token_violation.md"
if check_file_for_security_literal "$split_token_fixture" "review_file_split_token_violation.md"; then
    log_pass "Primary gate caught split-token ai-review + security construction"
else
    log_fail "Primary gate missed split-token ai-review + security construction: $(basename "$split_token_fixture")"
fi

# Remove stub log_error so it doesn't shadow real log functions
unset -f log_error
echo

# --- Test 2c: review_artifact_lint file-level API prohibition ---
echo "Test 2c: review_artifact_lint file-level API prohibition (detect_forbidden_api_usage)"
# Provide stub log_error for the sourced function
log_error() { :; }
source <(sed -n '/^detect_forbidden_api_usage()/,/^}/p' "${SCRIPT_DIR}/review_artifact_lint.sh")

# Test 2c-i: File with gh api call in non-comment code -> MUST FAIL
# (reuse the literal violation fixture which has "gh api" in it)
if detect_forbidden_api_usage "$violation_fixture" "review_file_literal_violation.md"; then
    log_pass "API prohibition caught gh api in non-exempt file"
else
    log_fail "API prohibition missed gh api in non-exempt file: $(basename "$violation_fixture")"
fi

# Test 2c-ii: File without any API calls -> MUST PASS
if detect_forbidden_api_usage "$permitted_fixture" "review_file_literal_permitted.md"; then
    log_fail "API prohibition false positive on file without API calls: $(basename "$permitted_fixture")"
else
    log_pass "API prohibition correctly permits file without API calls"
fi

# Test 2c-iii: CODE_QUALITY_PROMPT.md with legacy ai-review/code-quality gh api -> MUST FAIL
# (TCK-00432: ai-review/* allowlist removed; all gh api calls are now forbidden)
cq_known_good="${FIXTURE_DIR}/review_cq_known_good_permitted.md"
if detect_forbidden_api_usage "$cq_known_good" "CODE_QUALITY_PROMPT.md"; then
    log_pass "API prohibition correctly catches legacy ai-review/code-quality gh api calls"
else
    log_fail "API prohibition missed legacy ai-review/code-quality gh api calls (allowlist should be removed)"
fi

# Test 2c-iv: CODE_QUALITY_PROMPT.md with EXTRA gh api call beyond allowlist -> MUST FAIL
# (the extra gh api targeting ai-review/security is NOT in the allowlist)
cq_extra_api="${FIXTURE_DIR}/review_cq_extra_api_violation.md"
if detect_forbidden_api_usage "$cq_extra_api" "CODE_QUALITY_PROMPT.md"; then
    log_pass "API prohibition caught extra gh api in CODE_QUALITY_PROMPT.md beyond allowlist"
else
    log_fail "API prohibition missed extra gh api in CODE_QUALITY_PROMPT.md beyond allowlist"
fi

# Test 2c-v: CODE_QUALITY_PROMPT.md with split-token ai-review/security -> MUST FAIL
# (the split-token construction includes "gh api" which remains after stripping known-good lines)
cq_split_token="${FIXTURE_DIR}/review_cq_split_token_violation.md"
if detect_forbidden_api_usage "$cq_split_token" "CODE_QUALITY_PROMPT.md"; then
    log_pass "API prohibition caught split-token bypass in CODE_QUALITY_PROMPT.md"
else
    log_fail "API prohibition missed split-token bypass in CODE_QUALITY_PROMPT.md"
fi

# Remove stub log_error
unset -f log_error
echo

# --- Test 2d: cross-category exec detection (CODE_QUALITY must not invoke security-review-exec) ---
echo "Test 2d: review_artifact_lint cross-category exec detection (detect_cross_category_exec)"
log_error() { :; }
source <(sed -n '/^detect_cross_category_exec()/,/^}/p' "${SCRIPT_DIR}/review_artifact_lint.sh")

# Test 2d-i: CODE_QUALITY file containing security-review-exec -> MUST FAIL
cross_cat_fixture="${FIXTURE_DIR}/review_file_cross_category_violation.md"
cross_cat_found=0
while IFS= read -r fixture_line; do
    if detect_cross_category_exec "$fixture_line" "CODE_QUALITY_PROMPT.md"; then
        cross_cat_found=1
        break
    fi
done < "$cross_cat_fixture"
if [[ $cross_cat_found -eq 1 ]]; then
    log_pass "Cross-category exec caught security-review-exec in CODE_QUALITY context"
else
    log_fail "Cross-category exec missed security-review-exec in CODE_QUALITY context"
fi

# Test 2d-ii: SECURITY_REVIEW file containing security-review-exec -> MUST PASS (permitted)
cross_cat_found=0
while IFS= read -r fixture_line; do
    if detect_cross_category_exec "$fixture_line" "SECURITY_REVIEW_PROMPT.md"; then
        cross_cat_found=1
        break
    fi
done < "$cross_cat_fixture"
if [[ $cross_cat_found -eq 0 ]]; then
    log_pass "Cross-category exec correctly permits security-review-exec in SECURITY_REVIEW context"
else
    log_fail "Cross-category exec false positive on security-review-exec in SECURITY_REVIEW context"
fi

# Test 2d-iii: CODE_QUALITY line without security-review-exec -> MUST PASS (no violation)
if detect_cross_category_exec "cargo xtask review --pr 123 --type code-quality" "CODE_QUALITY_PROMPT.md"; then
    log_fail "Cross-category exec false positive on CODE_QUALITY line without security-review-exec"
else
    log_pass "Cross-category exec correctly permits CODE_QUALITY line without security-review-exec"
fi

unset -f log_error
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

# --- Test 5: ticket ref validation ---
echo "Test 5: ticket ref validation (requirement_ref / artifact_ref)"

REPO_ROOT="$(git rev-parse --show-toplevel)"

# Helper: validate a single ref from a fixture YAML file.
# Extracts the file path, strips #anchor, and checks if the file exists.
validate_ticket_ref() {
    local fixture="$1"
    local ref_key="$2"  # "requirement_ref" or "artifact_ref"
    local expect="$3"   # "valid", "broken", or "traversal"

    local has_broken=0
    local has_traversal=0
    while IFS= read -r ref_line; do
        local ref_path
        ref_path=$(echo "$ref_line" | sed -n "s/.*${ref_key}:[[:space:]]*\"\{0,1\}\([^\"#]*\).*/\1/p")
        if [[ -n "$ref_path" ]]; then
            ref_path="${ref_path%"${ref_path##*[![:space:]]}"}"
            # Check containment (mirrors evidence_refs_lint.sh logic)
            local resolved
            resolved="$(realpath -m "${REPO_ROOT}/${ref_path}")"
            if [[ "$resolved" != "${REPO_ROOT}"/* ]]; then
                has_traversal=1
                continue
            fi
            if [[ ! -f "${REPO_ROOT}/${ref_path}" ]]; then
                has_broken=1
            fi
        fi
    done < <(grep "${ref_key}:" "$fixture" 2>/dev/null || true)

    if [[ "$expect" == "valid" ]]; then
        if [[ $has_broken -eq 0 ]] && [[ $has_traversal -eq 0 ]]; then
            log_pass "Valid fixture ${ref_key} refs all resolve: $(basename "$fixture")"
        else
            log_fail "Valid fixture ${ref_key} ref unexpectedly broken: $(basename "$fixture")"
        fi
    elif [[ "$expect" == "traversal" ]]; then
        if [[ $has_traversal -eq 1 ]]; then
            log_pass "Path traversal correctly detected in ${ref_key}: $(basename "$fixture")"
        else
            log_fail "Path traversal NOT detected in ${ref_key}: $(basename "$fixture")"
        fi
    else
        if [[ $has_broken -eq 1 ]]; then
            log_pass "Broken fixture ${ref_key} refs correctly detected: $(basename "$fixture")"
        else
            log_fail "Broken fixture ${ref_key} refs not detected: $(basename "$fixture")"
        fi
    fi
}

# Test 5a: Valid ticket refs should all resolve
validate_ticket_ref "${FIXTURE_DIR}/ticket_refs_valid.yaml" "requirement_ref" "valid"
validate_ticket_ref "${FIXTURE_DIR}/ticket_refs_valid.yaml" "artifact_ref" "valid"

# Test 5b: Broken ticket refs should be detected
validate_ticket_ref "${FIXTURE_DIR}/ticket_refs_broken.yaml" "requirement_ref" "broken"
validate_ticket_ref "${FIXTURE_DIR}/ticket_refs_broken.yaml" "artifact_ref" "broken"

# Test 5c: Path traversal refs should be detected
validate_ticket_ref "${FIXTURE_DIR}/ticket_refs_traversal.yaml" "requirement_ref" "traversal"
validate_ticket_ref "${FIXTURE_DIR}/ticket_refs_traversal.yaml" "artifact_ref" "traversal"
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
