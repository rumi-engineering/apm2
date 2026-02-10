#!/usr/bin/env bash
# Regression fixtures for FAC preflight authorization policy (TCK-00442).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURE_DIR="${SCRIPT_DIR}/fixtures/fac_preflight"
CREDENTIAL_FIXTURE_DIR="${SCRIPT_DIR}/fixtures/credential_hardening"
PREFLIGHT_SCRIPT="${SCRIPT_DIR}/fac_preflight_authorization.sh"
POLICY_FIXTURE="${FIXTURE_DIR}/trust_policy_main_only.json"
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

run_preflight() {
    local fixture_path="$1"
    local policy_fixture="${2:-${POLICY_FIXTURE}}"
    env -u GH_TOKEN -u GH_PAT -u GITHUB_PAT -u APM2_GITHUB_PAT -u APM2_FAC_PAT \
        APM2_PREFLIGHT_EVENT_NAME="pull_request_target" \
        APM2_PREFLIGHT_EVENT_PATH="${fixture_path}" \
        APM2_PREFLIGHT_REPOSITORY="guardian-intelligence/apm2" \
        APM2_PREFLIGHT_ACTOR="ci-test" \
        APM2_PREFLIGHT_REF_NAME="main" \
        APM2_PREFLIGHT_TRUST_POLICY_PATH="${policy_fixture}" \
        APM2_CREDENTIAL_HARDENING_CMDLINE_PATH="${CREDENTIAL_FIXTURE_DIR}/cmdline_safe.txt" \
        GITHUB_TOKEN="ghs_fac_fixture_token_123456789012345678901234567890" \
            "${PREFLIGHT_SCRIPT}"
}

expect_pass() {
    local test_name="$1"
    local fixture_path="$2"
    local policy_fixture="${3:-${POLICY_FIXTURE}}"

    set +e
    local output
    output="$(run_preflight "${fixture_path}" "${policy_fixture}" 2>&1)"
    local status=$?
    set -e

    if [[ ${status} -ne 0 ]]; then
        log_fail "${test_name}: expected success, got exit=${status}"
        echo "${output}" >&2
        return
    fi

    if ! grep -q 'fac-preflight: check=overall decision=ALLOW' <<<"${output}"; then
        log_fail "${test_name}: missing overall ALLOW decision line"
        echo "${output}" >&2
        return
    fi

    log_pass "${test_name}"
}

expect_fail() {
    local test_name="$1"
    local fixture_path="$2"
    local expected_reason="$3"
    local policy_fixture="${4:-${POLICY_FIXTURE}}"

    set +e
    local output
    output="$(run_preflight "${fixture_path}" "${policy_fixture}" 2>&1)"
    local status=$?
    set -e

    if [[ ${status} -eq 0 ]]; then
        log_fail "${test_name}: expected failure, got success"
        echo "${output}" >&2
        return
    fi

    if ! grep -q "reason=${expected_reason}" <<<"${output}"; then
        log_fail "${test_name}: expected reason=${expected_reason}"
        echo "${output}" >&2
        return
    fi

    if ! grep -q 'fac-preflight: check=overall decision=DENY' <<<"${output}"; then
        log_fail "${test_name}: missing overall DENY decision line"
        echo "${output}" >&2
        return
    fi

    log_pass "${test_name}"
}

echo "=== FAC Preflight Authorization Fixtures (TCK-00442) ==="
echo

expect_pass "OWNER association allowed" "${FIXTURE_DIR}/event_owner_allowed.json"
expect_pass "MEMBER association allowed" "${FIXTURE_DIR}/event_member_allowed.json"
expect_pass "COLLABORATOR association allowed" "${FIXTURE_DIR}/event_collaborator_allowed.json"

expect_fail "Unknown association denied" \
    "${FIXTURE_DIR}/event_unknown_association_denied.json" \
    "unauthorized_author_association"
expect_fail "Fork without trust grant denied" \
    "${FIXTURE_DIR}/event_fork_without_grant_denied.json" \
    "fork_without_trust_grant"
expect_fail "Non-main base ref denied" \
    "${FIXTURE_DIR}/event_non_main_base_denied.json" \
    "untrusted_base_ref"
expect_fail "Policy missing credential posture denied" \
    "${FIXTURE_DIR}/event_owner_allowed.json" \
    "invalid_policy_schema" \
    "${FIXTURE_DIR}/trust_policy_missing_credential_posture.json"

echo
if [[ ${FAILURES} -gt 0 ]]; then
    echo -e "${RED}FAC preflight fixture tests failed: ${FAILURES}${NC}" >&2
    exit 1
fi

echo -e "${GREEN}All FAC preflight fixture tests passed.${NC}"
exit 0
