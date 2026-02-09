#!/usr/bin/env bash
# Local CI orchestrator: executes the full CI check surface in a single run.
# Intended to be wrapped once by run_bounded_tests.sh for outer cgroup limits.

set -euo pipefail

if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    NC=''
fi

log_info() { echo -e "${GREEN}INFO:${NC} $*"; }
log_warn() { echo -e "${YELLOW}WARN:${NC} $*"; }
log_error() { echo -e "${RED}ERROR:${NC} $*" >&2; }

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "${REPO_ROOT}"

RUN_ID="${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}"
LOG_ROOT="${REPO_ROOT}/target/ci/orchestrator_logs"
RUN_STAMP="${RUN_ID}-$(date -u +%Y%m%dT%H%M%SZ)"
LOG_DIR="${LOG_ROOT}/${RUN_STAMP}"
LCOV_PATH="target/ci/lcov.info"

mkdir -p "${LOG_DIR}"
mkdir -p target/ci

declare -a CHECK_ORDER=()
declare -A CHECK_LOG=()
declare -A CHECK_CMD=()
declare -A CHECK_STATUS=()
OVERALL_FAILED=0

record_check_start() {
    local id="$1"
    local cmd="$2"
    CHECK_ORDER+=("${id}")
    CHECK_LOG["${id}"]="${LOG_DIR}/${id}.log"
    CHECK_CMD["${id}"]="${cmd}"
}

record_check_end() {
    local id="$1"
    local rc="$2"
    if [[ "${rc}" -eq 0 ]]; then
        CHECK_STATUS["${id}"]="PASS"
        log_info "END   [${id}] PASS"
    else
        CHECK_STATUS["${id}"]="FAIL(${rc})"
        OVERALL_FAILED=1
        log_error "END   [${id}] FAIL (${rc})"
    fi
}

run_serial_check() {
    local id="$1"
    local cmd="$2"
    local logfile="${LOG_DIR}/${id}.log"

    record_check_start "${id}" "${cmd}"
    log_info "START [${id}] ${cmd}"

    set +e
    (
        set -euo pipefail
        cd "${REPO_ROOT}"
        bash -lc "${cmd}"
    ) > >(tee "${logfile}") 2>&1
    local rc=$?
    set -e

    record_check_end "${id}" "${rc}"
}

run_parallel_group() {
    local group_name="$1"
    shift
    local -a entries=("$@")
    local -a ids=()
    local -a pids=()

    log_info "=== Parallel Group: ${group_name} ==="

    local entry id cmd logfile
    for entry in "${entries[@]}"; do
        id="${entry%%::*}"
        cmd="${entry#*::}"
        logfile="${LOG_DIR}/${id}.log"

        record_check_start "${id}" "${cmd}"
        log_info "START [${id}] ${cmd}"

        (
            set -euo pipefail
            cd "${REPO_ROOT}"
            bash -lc "${cmd}"
        ) > >(tee "${logfile}") 2>&1 &

        ids+=("${id}")
        pids+=("$!")
    done

    local i rc
    for i in "${!ids[@]}"; do
        set +e
        wait "${pids[$i]}"
        rc=$?
        set -e
        record_check_end "${ids[$i]}" "${rc}"
    done
}

print_summary() {
    echo
    log_info "=== CI Summary ==="
    echo "Logs: ${LOG_DIR}"
    local id status
    for id in "${CHECK_ORDER[@]}"; do
        status="${CHECK_STATUS[${id}]:-UNKNOWN}"
        printf '  %-30s %-10s %s\n' "${id}" "${status}" "${CHECK_LOG[${id}]}"
    done
}

print_failure_tails() {
    local id status
    for id in "${CHECK_ORDER[@]}"; do
        status="${CHECK_STATUS[${id}]:-UNKNOWN}"
        if [[ "${status}" == FAIL* ]]; then
            echo
            log_warn "=== Failure Tail: ${id} ==="
            tail -n 160 "${CHECK_LOG[${id}]}" || true
        fi
    done
}

log_info "=== Local CI Orchestrator ==="
log_info "Repo root: ${REPO_ROOT}"
log_info "Run ID: ${RUN_ID}"
log_info "Log dir: ${LOG_DIR}"

# Bootstrap once for full-suite execution.
run_serial_check "bootstrap" "
missing=()
for cmd in cargo rustc git protoc rg jq timeout systemd-run rustup; do
    if ! command -v \"\${cmd}\" >/dev/null 2>&1; then
        missing+=(\"\${cmd}\")
    fi
done

if [[ \${#missing[@]} -gt 0 ]]; then
    echo \"Missing required host tools: \${missing[*]}\"
    echo \"Provision this self-hosted machine once; CI does not run apt installs per job.\"
    exit 1
fi

if ! command -v cargo-nextest >/dev/null 2>&1; then cargo install cargo-nextest --locked; fi
if ! command -v cargo-deny >/dev/null 2>&1; then cargo install cargo-deny --locked; fi
if ! command -v cargo-audit >/dev/null 2>&1; then cargo install cargo-audit --locked; fi
if ! command -v cargo-llvm-cov >/dev/null 2>&1; then cargo install cargo-llvm-cov --locked; fi

if ! rustup toolchain list | rg -q '^1\\.85(\\.0)?($|-)'; then
    rustup toolchain install 1.85 --profile minimal --no-self-update
fi

if ! rustup component list --toolchain nightly-2025-12-01 --installed | rg -q '^llvm-tools-preview'; then
    rustup component add --toolchain nightly-2025-12-01 llvm-tools-preview
fi
"

if [[ "${CHECK_STATUS[bootstrap]:-}" != "PASS" ]]; then
    print_summary
    print_failure_tails
    log_error "Bootstrap preflight failed."
    exit 1
fi

if [[ "${APM2_CI_DRY_RUN:-0}" == "1" ]]; then
    run_serial_check "dry_run" "printf '%s\n' 'dry-run requested; full check surface skipped'"
    print_summary
    exit 0
fi

# Fast static checks in parallel.
run_parallel_group "static-guardrails" \
    "test_safety_guard::./scripts/ci/test_safety_guard.sh" \
    "legacy_ipc_guard::./scripts/ci/legacy_ipc_guard.sh" \
    "evidence_refs_lint::./scripts/ci/evidence_refs_lint.sh" \
    "test_refs_lint::./scripts/ci/test_refs_lint.sh" \
    "proto_enum_drift::./scripts/ci/proto_enum_drift.sh" \
    "review_artifact_lint::./scripts/ci/review_artifact_lint.sh" \
    "status_write_cmd_lint::./scripts/lint/no_direct_status_write_commands.sh" \
    "safety_proof_coverage::./scripts/ci/safety_proof_coverage.sh"

# Build/lint/doc/test surface (restored, none removed).
run_serial_check "rustfmt" "cargo fmt --all --check"
run_serial_check "proto_verify" "cargo build -p apm2-daemon && git diff --exit-code crates/apm2-daemon/src/protocol/apm2.daemon.v1.rs"
run_serial_check "clippy" "cargo clippy --workspace --all-targets --all-features -- -D warnings"
run_serial_check "doc" "RUSTDOCFLAGS=-D warnings cargo doc --workspace --no-deps --all-features"
run_serial_check "workspace_integrity_snapshot" "./scripts/ci/workspace_integrity_guard.sh snapshot --snapshot-file target/ci/workspace_integrity.snapshot.tsv"
run_serial_check "bounded_test_runner" "cargo nextest run --workspace --all-features --config-file .config/nextest.toml --profile ci"
run_serial_check "workspace_integrity_guard" "./scripts/ci/workspace_integrity_guard.sh verify --snapshot-file target/ci/workspace_integrity.snapshot.tsv"
run_serial_check "bounded_doctests" "cargo test --doc --workspace --all-features"
run_serial_check "test_vectors" "cargo test --package apm2-core --features test_vectors canonicalization"
run_serial_check "msrv_check" "cargo +1.85 check --workspace --all-features"
run_serial_check "cargo_deny" "cargo deny check all"
run_serial_check "cargo_audit" "cargo audit --ignore RUSTSEC-2023-0089"
run_serial_check "coverage" "cargo llvm-cov --workspace --all-features --lcov --output-path ${LCOV_PATH}"
run_serial_check "guardrail_fixtures" "./scripts/ci/test_guardrail_fixtures.sh"
run_serial_check "release_build" "cargo build --workspace --release"

print_summary

if [[ "${OVERALL_FAILED}" -ne 0 ]]; then
    print_failure_tails
    log_error "Local CI orchestrator failed."
    exit 1
fi

log_info "Local CI orchestrator passed."
exit 0
