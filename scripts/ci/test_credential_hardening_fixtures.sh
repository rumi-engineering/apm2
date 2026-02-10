#!/usr/bin/env bash
# Regression fixtures for FAC credential hardening (TCK-00445).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURE_DIR="${SCRIPT_DIR}/fixtures/credential_hardening"
HARDENING_SCRIPT="${SCRIPT_DIR}/credential_hardening.sh"
FAILURES=0

VALID_TOKEN="ghs_fac_fixture_token_123456789012345678901234567890"
LEAK_TOKEN="ghs_leak_fixture_token_123456789012345678901234567890"
PAT_TOKEN="github_pat_fixture_token_123456789012345678901234567890"

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

run_cmd() {
    set +e
    local output
    output="$("$@" 2>&1)"
    local status=$?
    set -e
    printf '%s\n' "${output}"
    return "${status}"
}

expect_runtime_pass() {
    local test_name="$1"
    shift
    local output=''

    if ! output="$(run_cmd "$@")"; then
        log_fail "${test_name}: expected success"
        echo "${output}" >&2
        return
    fi

    if ! grep -q 'fac-credential: check=overall decision=ALLOW' <<<"${output}"; then
        log_fail "${test_name}: missing overall ALLOW"
        echo "${output}" >&2
        return
    fi

    log_pass "${test_name}"
}

expect_runtime_fail() {
    local test_name="$1"
    local expected_reason="$2"
    shift 2
    local output=''

    set +e
    output="$(run_cmd "$@")"
    local status=$?
    set -e

    if [[ ${status} -eq 0 ]]; then
        log_fail "${test_name}: expected failure"
        echo "${output}" >&2
        return
    fi

    if ! grep -q "reason=${expected_reason}" <<<"${output}"; then
        log_fail "${test_name}: expected reason=${expected_reason}"
        echo "${output}" >&2
        return
    fi

    if ! grep -q 'fac-credential: check=overall decision=DENY' <<<"${output}"; then
        log_fail "${test_name}: missing overall DENY"
        echo "${output}" >&2
        return
    fi

    log_pass "${test_name}"
}

echo "=== FAC Credential Hardening Fixtures (TCK-00445) ==="
echo

echo "Test 1: runtime posture checks"
expect_runtime_pass "Valid github_token posture allowed" \
    env -u GH_TOKEN -u GH_PAT -u GITHUB_PAT -u APM2_GITHUB_PAT -u APM2_FAC_PAT \
        APM2_FAC_CREDENTIAL_SOURCE="github_token" \
        APM2_CREDENTIAL_HARDENING_STAGE="projection" \
        APM2_CREDENTIAL_HARDENING_CMDLINE_PATH="${FIXTURE_DIR}/cmdline_safe.txt" \
        GITHUB_TOKEN="${VALID_TOKEN}" \
        "${HARDENING_SCRIPT}" runtime

expect_runtime_fail "Missing credential source denied" \
    "missing_credential_source" \
    env -u GH_TOKEN -u GH_PAT -u GITHUB_PAT -u APM2_GITHUB_PAT -u APM2_FAC_PAT \
        APM2_CREDENTIAL_HARDENING_CMDLINE_PATH="${FIXTURE_DIR}/cmdline_safe.txt" \
        GITHUB_TOKEN="${VALID_TOKEN}" \
        "${HARDENING_SCRIPT}" runtime

expect_runtime_fail "Unsupported credential source denied" \
    "unsupported_credential_source" \
    env -u GH_TOKEN -u GH_PAT -u GITHUB_PAT -u APM2_GITHUB_PAT -u APM2_FAC_PAT \
        APM2_FAC_CREDENTIAL_SOURCE="auto" \
        APM2_CREDENTIAL_HARDENING_CMDLINE_PATH="${FIXTURE_DIR}/cmdline_safe.txt" \
        GITHUB_TOKEN="${VALID_TOKEN}" \
        "${HARDENING_SCRIPT}" runtime

expect_runtime_fail "Missing GITHUB_TOKEN denied" \
    "missing_github_token" \
    env -u GH_TOKEN -u GH_PAT -u GITHUB_PAT -u APM2_GITHUB_PAT -u APM2_FAC_PAT \
        APM2_FAC_CREDENTIAL_SOURCE="github_token" \
        APM2_CREDENTIAL_HARDENING_CMDLINE_PATH="${FIXTURE_DIR}/cmdline_safe.txt" \
        "${HARDENING_SCRIPT}" runtime

expect_runtime_fail "Mismatched GH_TOKEN denied" \
    "ambiguous_token_values" \
    env -u GH_PAT -u GITHUB_PAT -u APM2_GITHUB_PAT -u APM2_FAC_PAT \
        APM2_FAC_CREDENTIAL_SOURCE="github_token" \
        APM2_CREDENTIAL_HARDENING_CMDLINE_PATH="${FIXTURE_DIR}/cmdline_safe.txt" \
        GITHUB_TOKEN="${VALID_TOKEN}" \
        GH_TOKEN="ghs_different_fac_fixture_token_12345678901234567890123456" \
        "${HARDENING_SCRIPT}" runtime

expect_runtime_fail "PAT token source denied" \
    "disallowed_token_type" \
    env -u GH_TOKEN -u GH_PAT -u GITHUB_PAT -u APM2_GITHUB_PAT -u APM2_FAC_PAT \
        APM2_FAC_CREDENTIAL_SOURCE="github_token" \
        APM2_CREDENTIAL_HARDENING_CMDLINE_PATH="${FIXTURE_DIR}/cmdline_safe.txt" \
        GITHUB_TOKEN="${PAT_TOKEN}" \
        "${HARDENING_SCRIPT}" runtime

expect_runtime_fail "PAT environment variable denied" \
    "disallowed_pat_env_var" \
    env -u GH_TOKEN -u GITHUB_PAT -u APM2_GITHUB_PAT -u APM2_FAC_PAT \
        APM2_FAC_CREDENTIAL_SOURCE="github_token" \
        APM2_CREDENTIAL_HARDENING_CMDLINE_PATH="${FIXTURE_DIR}/cmdline_safe.txt" \
        GITHUB_TOKEN="${VALID_TOKEN}" \
        GH_PAT="${PAT_TOKEN}" \
        "${HARDENING_SCRIPT}" runtime
echo

echo "Test 2: argv leakage checks"
expect_runtime_fail "Token flag in argv denied" \
    "insecure_token_flag_in_argv" \
    env -u GH_TOKEN -u GH_PAT -u GITHUB_PAT -u APM2_GITHUB_PAT -u APM2_FAC_PAT \
        APM2_FAC_CREDENTIAL_SOURCE="github_token" \
        APM2_CREDENTIAL_HARDENING_CMDLINE_PATH="${FIXTURE_DIR}/cmdline_token_flag.txt" \
        GITHUB_TOKEN="${VALID_TOKEN}" \
        "${HARDENING_SCRIPT}" runtime

expect_runtime_fail "PAT literal in argv denied" \
    "pat_literal_in_argv" \
    env -u GH_TOKEN -u GH_PAT -u GITHUB_PAT -u APM2_GITHUB_PAT -u APM2_FAC_PAT \
        APM2_FAC_CREDENTIAL_SOURCE="github_token" \
        APM2_CREDENTIAL_HARDENING_CMDLINE_PATH="${FIXTURE_DIR}/cmdline_pat_literal.txt" \
        GITHUB_TOKEN="${VALID_TOKEN}" \
        "${HARDENING_SCRIPT}" runtime

set +e
runtime_output="$(env -u GH_TOKEN -u GH_PAT -u GITHUB_PAT -u APM2_GITHUB_PAT -u APM2_FAC_PAT \
    APM2_FAC_CREDENTIAL_SOURCE="github_token" \
    APM2_CREDENTIAL_HARDENING_CMDLINE_PATH="${FIXTURE_DIR}/cmdline_value_leak.txt" \
    GITHUB_TOKEN="${LEAK_TOKEN}" \
    "${HARDENING_SCRIPT}" runtime 2>&1)"
runtime_status=$?
set -e
if [[ ${runtime_status} -eq 0 ]]; then
    log_fail "Credential value in argv denied: expected failure"
    echo "${runtime_output}" >&2
elif ! grep -q 'reason=credential_value_in_argv' <<<"${runtime_output}"; then
    log_fail "Credential value in argv denied: missing expected reason"
    echo "${runtime_output}" >&2
elif grep -Fq "${LEAK_TOKEN}" <<<"${runtime_output}"; then
    log_fail "Credential value leaked into logs during denial"
    echo "${runtime_output}" >&2
else
    log_pass "Credential value in argv denied without log leakage"
fi
echo

echo "Test 3: PAT drift lint checks"
expect_runtime_pass "Lint passes on safe fixture" \
    "${HARDENING_SCRIPT}" lint "${FIXTURE_DIR}/lint_safe.sh"

expect_runtime_fail "Lint blocks PAT drift fixture" \
    "lint_violations_detected" \
    "${HARDENING_SCRIPT}" lint "${FIXTURE_DIR}/lint_pat_violation.sh"

expect_runtime_pass "Lint passes FAC production surfaces" \
    "${HARDENING_SCRIPT}" lint \
    .github/workflows/forge-admission-cycle.yml \
    scripts/ci/fac_preflight_authorization.sh
echo

if [[ ${FAILURES} -gt 0 ]]; then
    echo -e "${RED}Credential hardening fixture tests failed: ${FAILURES}${NC}" >&2
    exit 1
fi

echo -e "${GREEN}All credential hardening fixture tests passed.${NC}"
exit 0
