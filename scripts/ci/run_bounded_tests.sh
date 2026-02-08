#!/usr/bin/env bash
# CI wrapper: bounded test execution with cgroup/systemd enforcement
# (TCK-00410)
#
# Requires systemd-run --user with a functioning D-Bus user session.
# The self-hosted runner service must have XDG_RUNTIME_DIR and
# DBUS_SESSION_BUS_ADDRESS set (see 20-user-bus.conf drop-in).
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
  --allow-timeout-fallback    Break-glass: skip systemd-run and use timeout only
  -h, --help                  Show help

Environment:
  APM2_CI_ALLOW_TIMEOUT_FALLBACK=1  Break-glass: skip systemd-run, use GNU
                                    timeout only (no cgroup limits). Not for
                                    CI — only for local debugging.
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

log_info "=== Bounded Test Runner (TCK-00410) ==="
log_info "Repo root: ${REPO_ROOT}"
log_info "Timeout: ${TIMEOUT_SECONDS}s"
log_info "Kill-after: ${KILL_AFTER_SECONDS}s"
log_info "MemoryMax: ${MEMORY_MAX}"
log_info "TasksMax: ${PIDS_MAX}"
log_info "CPUQuota: ${CPU_QUOTA}"
log_info "Command: ${COMMAND[*]}"
echo

# -------------------------------------------------------------------
# Break-glass: timeout-only mode (no cgroup enforcement)
# Only for local debugging — CI must never set this.
# -------------------------------------------------------------------
if [[ "${ALLOW_TIMEOUT_FALLBACK}" == "1" ]]; then
    log_warn "APM2_CI_ALLOW_TIMEOUT_FALLBACK=1: break-glass mode, no cgroup limits."
    if ! command -v timeout >/dev/null 2>&1; then
        log_error "GNU timeout not found."
        exit 1
    fi
    timeout --signal=TERM --kill-after="${KILL_AFTER_SECONDS}s" \
        "${TIMEOUT_SECONDS}s" "${COMMAND[@]}"
    exit $?
fi

# -------------------------------------------------------------------
# Primary path: systemd-run --user with full cgroup enforcement
# -------------------------------------------------------------------

# Normalize user-runtime defaults when runner service does not export them.
if [[ -z "${XDG_RUNTIME_DIR:-}" ]]; then
    export XDG_RUNTIME_DIR="/run/user/$(id -u)"
fi
if [[ -z "${DBUS_SESSION_BUS_ADDRESS:-}" ]]; then
    export DBUS_SESSION_BUS_ADDRESS="unix:path=${XDG_RUNTIME_DIR}/bus"
fi

# Preflight: verify the user bus is reachable.
if [[ ! -S "${XDG_RUNTIME_DIR}/bus" ]]; then
    log_error "User D-Bus socket not found at ${XDG_RUNTIME_DIR}/bus"
    log_error "Ensure loginctl enable-linger is set and the runner service has"
    log_error "Environment=XDG_RUNTIME_DIR=/run/user/$(id -u) in its drop-in."
    exit 1
fi

if ! command -v systemd-run >/dev/null 2>&1; then
    log_error "systemd-run not found on PATH."
    exit 1
fi

# Quick smoke test: can we create a transient user unit?
if ! systemd-run --user --quiet --wait --collect -- true 2>/dev/null; then
    log_error "systemd-run --user preflight failed."
    log_error "Check that user@$(id -u).service is running and the bus socket is accessible."
    exit 1
fi

if [[ ! -f /sys/fs/cgroup/cgroup.controllers ]]; then
    log_error "cgroup v2 controllers not found (fail-closed)."
    exit 1
fi

log_info "Preflight passed: systemd-run --user is functional."

UNIT="apm2-ci-bounded-${GITHUB_RUN_ID:-local}-${RANDOM}-$$"

# Preserve selected caller environment in the transient unit.
declare -a SETENV_ARGS=()
for var_name in \
    GITHUB_RUN_ID \
    GITHUB_RUN_ATTEMPT \
    APM2_CI_DRY_RUN \
    APM2_CI_TARGET_DIR \
    CARGO_TERM_COLOR \
    CARGO_INCREMENTAL \
    RUSTFLAGS \
    RUST_BACKTRACE; do
    if [[ -n "${!var_name:-}" ]]; then
        SETENV_ARGS+=(--setenv "${var_name}=${!var_name}")
    fi
done

log_info "Starting bounded command in transient user unit: ${UNIT}"
systemd-run \
    --user \
    --pipe \
    --quiet \
    --wait \
    --collect \
    --working-directory "${REPO_ROOT}" \
    "${SETENV_ARGS[@]}" \
    --unit "${UNIT}" \
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
status=$?

if [[ ${status} -eq 0 ]]; then
    log_info "Bounded command completed successfully."
else
    log_error "Bounded command failed with exit code ${status}."
fi
exit "${status}"
