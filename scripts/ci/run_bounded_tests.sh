#!/usr/bin/env bash
# CI wrapper: bounded test execution with cgroup/systemd enforcement
# (TCK-00410)
#
# Default command:
#   cargo nextest run --workspace --all-features --config-file .config/nextest.toml --profile ci
#
# Exit codes:
#   0 - Command completed successfully within limits
#   1 - Command failed, timed out, or limit setup failed
#   2 - Script/configuration error

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

log_error() { echo -e "${RED}ERROR:${NC} $*" >&2; }
log_warn() { echo -e "${YELLOW}WARN:${NC} $*" >&2; }
log_info() { echo -e "${GREEN}INFO:${NC} $*"; }

usage() {
    cat <<'USAGE'
Usage:
  ./scripts/ci/run_bounded_tests.sh [options] [-- command args...]

Options:
  --timeout-seconds N         Hard wall timeout (default: 900)
  --kill-after-seconds N      SIGTERM -> SIGKILL escalation delay (default: 20)
  --memory-max VALUE          systemd MemoryMax (default: 4G)
  --pids-max N                systemd TasksMax (default: 1536)
  --cpu-quota VALUE           systemd CPUQuota (default: 200%)
  --allow-timeout-fallback    Allow fallback to GNU timeout when systemd-run is unavailable
  -h, --help                  Show help

Environment:
  APM2_CI_ALLOW_TIMEOUT_FALLBACK=1 allows timeout-only fallback mode.
USAGE
}

TIMEOUT_SECONDS=900
KILL_AFTER_SECONDS=20
MEMORY_MAX='4G'
PIDS_MAX=1536
CPU_QUOTA='200%'
ALLOW_TIMEOUT_FALLBACK="${APM2_CI_ALLOW_TIMEOUT_FALLBACK:-0}"

declare -a COMMAND=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --timeout-seconds)
            shift
            [[ $# -gt 0 ]] || { log_error "--timeout-seconds requires a value"; exit 2; }
            TIMEOUT_SECONDS="$1"
            ;;
        --kill-after-seconds)
            shift
            [[ $# -gt 0 ]] || { log_error "--kill-after-seconds requires a value"; exit 2; }
            KILL_AFTER_SECONDS="$1"
            ;;
        --memory-max)
            shift
            [[ $# -gt 0 ]] || { log_error "--memory-max requires a value"; exit 2; }
            MEMORY_MAX="$1"
            ;;
        --pids-max)
            shift
            [[ $# -gt 0 ]] || { log_error "--pids-max requires a value"; exit 2; }
            PIDS_MAX="$1"
            ;;
        --cpu-quota)
            shift
            [[ $# -gt 0 ]] || { log_error "--cpu-quota requires a value"; exit 2; }
            CPU_QUOTA="$1"
            ;;
        --allow-timeout-fallback)
            ALLOW_TIMEOUT_FALLBACK=1
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --)
            shift
            COMMAND=("$@")
            break
            ;;
        *)
            log_error "Unknown argument: $1"
            usage
            exit 2
            ;;
    esac
    shift
done

if [[ ${#COMMAND[@]} -eq 0 ]]; then
    COMMAND=(
        cargo nextest run
        --workspace
        --all-features
        --config-file .config/nextest.toml
        --profile ci
    )
fi

for numeric in "${TIMEOUT_SECONDS}" "${KILL_AFTER_SECONDS}" "${PIDS_MAX}"; do
    if ! [[ "${numeric}" =~ ^[0-9]+$ ]] || [[ "${numeric}" -eq 0 ]]; then
        log_error "Numeric limits must be positive integers."
        exit 2
    fi
done

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "${REPO_ROOT}"

run_with_timeout_fallback() {
    if ! command -v timeout >/dev/null 2>&1; then
        log_error "GNU timeout is required for fallback mode."
        return 1
    fi

    log_warn "Running in timeout fallback mode (no cgroup limits)."
    log_warn "Set up systemd-run on the runner for full containment."
    timeout \
        --signal=TERM \
        --kill-after="${KILL_AFTER_SECONDS}s" \
        "${TIMEOUT_SECONDS}s" \
        "${COMMAND[@]}"
}

run_with_systemd_scope_inner() {
    local scope_mode="$1"
    shift
    if ! command -v systemd-run >/dev/null 2>&1; then
        log_error "systemd-run not available."
        return 127
    fi

    local unit="apm2-ci-bounded-${GITHUB_RUN_ID:-local}-${RANDOM}-$$"
    local -a mode_flag=()
    if [[ "${scope_mode}" == "user" ]]; then
        mode_flag=(--user)
    fi

    log_info "Starting bounded command in transient systemd unit (${scope_mode}): ${unit}"
    systemd-run \
        "${mode_flag[@]}" \
        --quiet \
        --wait \
        --collect \
        --unit "${unit}" \
        --property "MemoryAccounting=yes" \
        --property "CPUAccounting=yes" \
        --property "TasksAccounting=yes" \
        --property "MemoryMax=${MEMORY_MAX}" \
        --property "TasksMax=${PIDS_MAX}" \
        --property "CPUQuota=${CPU_QUOTA}" \
        --property "RuntimeMaxSec=${TIMEOUT_SECONDS}s" \
        --property "KillSignal=SIGTERM" \
        --property "TimeoutStopSec=${KILL_AFTER_SECONDS}s" \
        --property "FinalKillSignal=SIGKILL" \
        --property "SendSIGKILL=yes" \
        --property "KillMode=control-group" \
        -- \
        "${COMMAND[@]}"
}

run_with_systemd_scope() {
    set +e
    run_with_systemd_scope_inner user
    local user_status=$?
    set -e
    if [[ ${user_status} -eq 0 ]]; then
        return 0
    fi
    log_warn "systemd-run --user failed with status ${user_status}, trying system scope."

    set +e
    run_with_systemd_scope_inner system
    local system_status=$?
    set -e
    if [[ ${system_status} -eq 0 ]]; then
        return 0
    fi

    return "${system_status}"
}

log_info "=== Bounded Test Runner (TCK-00410) ==="
log_info "Repo root: ${REPO_ROOT}"
log_info "Timeout: ${TIMEOUT_SECONDS}s"
log_info "Kill-after: ${KILL_AFTER_SECONDS}s"
log_info "MemoryMax: ${MEMORY_MAX}"
log_info "TasksMax: ${PIDS_MAX}"
log_info "CPUQuota: ${CPU_QUOTA}"
log_info "Command: ${COMMAND[*]}"
echo

# When timeout fallback is explicitly allowed, skip systemd-run entirely.
# GitHub-hosted runners lack the D-Bus session and polkit policy that
# systemd-run --user/--system requires, so attempting it wastes time and
# introduces fragile set -e interactions.
if [[ "${ALLOW_TIMEOUT_FALLBACK}" == "1" ]]; then
    log_warn "APM2_CI_ALLOW_TIMEOUT_FALLBACK=1: skipping systemd-run, using GNU timeout."
    run_with_timeout_fallback
    fallback_status=$?
    if [[ ${fallback_status} -eq 0 ]]; then
        log_info "Fallback command completed successfully."
        exit 0
    fi
    log_error "Fallback command failed with exit code ${fallback_status}."
    exit 1
fi

# Check for cgroup v2 support (fail-closed without fallback).
if [[ ! -f /sys/fs/cgroup/cgroup.controllers ]]; then
    log_error "cgroup v2 controllers file not found at /sys/fs/cgroup/cgroup.controllers (fail-closed)."
    exit 1
fi

set +e
run_with_systemd_scope
status=$?
set -e

if [[ ${status} -eq 0 ]]; then
    log_info "Bounded command completed successfully."
    exit 0
fi

log_error "systemd-run execution failed with exit code ${status}."
log_error "Fail-closed: bounded execution requires systemd-run + cgroup enforcement."
log_error "Set APM2_CI_ALLOW_TIMEOUT_FALLBACK=1 for timeout-only mode."
exit 1
