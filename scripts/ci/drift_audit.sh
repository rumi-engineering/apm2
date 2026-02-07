#!/usr/bin/env bash
# Repo-local drift audit command (TCK-00409)
#
# Generates a deterministic drift report by running all CI drift guard checks.
# Provides a single pass/fail output suitable for local development and CI.
#
# Exit codes:
#   0 - All drift guards pass
#   1 - One or more drift guards failed
#   2 - Script error
#
# Usage:
#   ./scripts/ci/drift_audit.sh

set -euo pipefail

if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BOLD=''
    NC=''
fi

log_error() { echo -e "${RED}ERROR:${NC} $*" >&2; }
log_warn() { echo -e "${YELLOW}WARN:${NC} $*" >&2; }
log_info() { echo -e "${GREEN}INFO:${NC} $*"; }
log_header() { echo -e "${BOLD}$*${NC}"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FAILURES=0
CHECKS_RUN=0
RESULTS=()

run_check() {
    local name="$1"
    local script="$2"
    CHECKS_RUN=$((CHECKS_RUN + 1))

    log_header "[$CHECKS_RUN] Running: $name"
    echo "---"

    if bash "$script" 2>&1; then
        RESULTS+=("PASS: $name")
    else
        RESULTS+=("FAIL: $name")
        FAILURES=$((FAILURES + 1))
    fi
    echo
}

log_header "============================================="
log_header "  APM2 Drift Audit Report"
log_header "  Generated: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
log_header "  Commit:    $(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
log_header "============================================="
echo

# Run all drift guard checks
run_check "Evidence/Requirement Reference Integrity" "${SCRIPT_DIR}/evidence_refs_lint.sh"
run_check "Test/Source Reference Integrity" "${SCRIPT_DIR}/test_refs_lint.sh"
run_check "Proto Enum Drift Detection" "${SCRIPT_DIR}/proto_enum_drift.sh"
run_check "Review Artifact Integrity" "${SCRIPT_DIR}/review_artifact_lint.sh"
run_check "Legacy IPC Guard" "${SCRIPT_DIR}/legacy_ipc_guard.sh"
run_check "Lint Fixture Regression Tests" "${SCRIPT_DIR}/test_lint_fixtures.sh"

# Summary
log_header "============================================="
log_header "  Drift Audit Summary"
log_header "============================================="
echo
for result in "${RESULTS[@]}"; do
    if [[ "$result" == PASS:* ]]; then
        log_info "$result"
    else
        log_error "$result"
    fi
done
echo
log_header "Checks run: $CHECKS_RUN"
log_header "Passed:     $((CHECKS_RUN - FAILURES))"
log_header "Failed:     $FAILURES"
echo

if [[ $FAILURES -gt 0 ]]; then
    log_error "=== DRIFT AUDIT FAILED: $FAILURES check(s) failed ==="
    exit 1
else
    log_info "=== DRIFT AUDIT PASSED: All $CHECKS_RUN checks passed ==="
    exit 0
fi
