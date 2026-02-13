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
  --timeout-seconds N         Hard wall timeout (default: 600, max: 600)
  --kill-after-seconds N      SIGTERM -> SIGKILL escalation delay (default: 20)
  --heartbeat-seconds N       Heartbeat interval while command runs (default: 10)
  --memory-max VALUE          systemd MemoryMax (default: 48G)
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

MAX_TIMEOUT_SECONDS=600
TEST_TIMEOUT_SLA_MESSAGE="Bounded FAC test timeout is fixed at 600s for all runs."

TIMEOUT_SECONDS=600
KILL_AFTER_SECONDS=20
HEARTBEAT_SECONDS=10
MEMORY_MAX='48G'
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
        --heartbeat-seconds)
            shift
            [[ $# -gt 0 ]] || { log_error "--heartbeat-seconds requires a value"; exit 2; }
            HEARTBEAT_SECONDS="$1"
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

for numeric in "${TIMEOUT_SECONDS}" "${KILL_AFTER_SECONDS}" "${HEARTBEAT_SECONDS}" "${PIDS_MAX}"; do
    if ! [[ "${numeric}" =~ ^[0-9]+$ ]] || [[ "${numeric}" -eq 0 ]]; then
        log_error "Numeric limits must be positive integers."
        exit 2
    fi
done

if (( TIMEOUT_SECONDS > MAX_TIMEOUT_SECONDS )); then
    log_error "--timeout-seconds cannot exceed ${MAX_TIMEOUT_SECONDS}."
    log_error "${TEST_TIMEOUT_SLA_MESSAGE}"
    exit 2
fi

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "${REPO_ROOT}"

log_info "=== Bounded Test Runner (TCK-00410) ==="
log_info "Repo root: ${REPO_ROOT}"
log_info "Timeout: ${TIMEOUT_SECONDS}s"
log_info "Kill-after: ${KILL_AFTER_SECONDS}s"
log_info "Heartbeat: every ${HEARTBEAT_SECONDS}s"
log_info "MemoryMax: ${MEMORY_MAX}"
log_info "TasksMax: ${PIDS_MAX}"
log_info "CPUQuota: ${CPU_QUOTA}"
log_info "Command: ${COMMAND[*]}"
log_info "Test timeout policy: ${TEST_TIMEOUT_SLA_MESSAGE}"
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

format_bytes_best_effort() {
    local value="$1"
    if [[ "${value}" =~ ^[0-9]+$ ]] && [[ "${value}" -gt 0 ]] && command -v numfmt >/dev/null 2>&1; then
        numfmt --to=iec --suffix=B "${value}" 2>/dev/null || echo "${value}"
        return
    fi
    echo "${value}"
}

emit_heartbeat() {
    local elapsed_secs="$1"
    local tick="$2"
    local active_state="unknown"
    local sub_state="unknown"
    local memory_current="unknown"
    local tasks_current="unknown"

    if unit_show="$(systemctl --user show \
        "${UNIT}" \
        --property=ActiveState \
        --property=SubState \
        --property=MemoryCurrent \
        --property=TasksCurrent \
        2>/dev/null)"; then
        while IFS='=' read -r key value; do
            case "${key}" in
                ActiveState) active_state="${value:-unknown}" ;;
                SubState) sub_state="${value:-unknown}" ;;
                MemoryCurrent) memory_current="${value:-unknown}" ;;
                TasksCurrent) tasks_current="${value:-unknown}" ;;
            esac
        done <<<"${unit_show}"
    fi

    local memory_display
    memory_display="$(format_bytes_best_effort "${memory_current}")"

    log_info "HEARTBEAT unit=${UNIT} tick=${tick} elapsed=${elapsed_secs}s state=${active_state}/${sub_state} tasks=${tasks_current} memory_current=${memory_display} memory_max=${MEMORY_MAX}"
}

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
    "${COMMAND[@]}" &
runner_pid=$!
start_epoch="$(date +%s)"
next_heartbeat_epoch="$((start_epoch + HEARTBEAT_SECONDS))"

while kill -0 "${runner_pid}" 2>/dev/null; do
    now_epoch="$(date +%s)"
    if (( now_epoch >= next_heartbeat_epoch )); then
        elapsed="$((now_epoch - start_epoch))"
        tick="$((elapsed / HEARTBEAT_SECONDS))"
        emit_heartbeat "${elapsed}" "${tick}"
        while (( next_heartbeat_epoch <= now_epoch )); do
            next_heartbeat_epoch="$((next_heartbeat_epoch + HEARTBEAT_SECONDS))"
        done
    fi
    sleep 1
done

if wait "${runner_pid}"; then
    status=0
else
    status="$?"
fi

if [[ ${status} -ne 0 ]]; then
    result="unknown"
    memory_peak="unknown"
    exec_main_code="unknown"
    exec_main_status="unknown"
    if unit_show="$(systemctl --user show \
        "${UNIT}" \
        --property=Result \
        --property=MemoryPeak \
        --property=ExecMainCode \
        --property=ExecMainStatus \
        2>/dev/null)"; then
        while IFS='=' read -r key value; do
            case "${key}" in
                Result) result="${value:-unknown}" ;;
                MemoryPeak) memory_peak="${value:-unknown}" ;;
                ExecMainCode) exec_main_code="${value:-unknown}" ;;
                ExecMainStatus) exec_main_status="${value:-unknown}" ;;
            esac
        done <<<"${unit_show}"
    else
        log_warn "Failed to query post-mortem diagnostics for ${UNIT}."
    fi

    memory_peak_display="$(format_bytes_best_effort "${memory_peak}")"

    # systemd may report timeout while stopping the unit after the main command
    # already exited successfully. Treat this as success with warning.
    if [[ "${result}" == "timeout" && "${exec_main_code}" == "1" && "${exec_main_status}" == "0" ]]; then
        log_warn "Bounded command hit unit stop timeout after main process exit 0; treating as success."
        {
            echo "DIAGNOSTIC: bounded unit timeout during teardown (main process exited cleanly)"
            printf '  unit:             %s\n' "${UNIT}"
            printf '  result:           %s\n' "${result}"
            printf '  exec_main_code:   %s\n' "${exec_main_code}"
            printf '  exec_main_status: %s\n' "${exec_main_status}"
            printf '  memory_peak:      %s\n' "${memory_peak_display}"
            printf '  memory_max:       %s\n' "${MEMORY_MAX}"
            printf '  timeout_seconds:  %s\n' "${TIMEOUT_SECONDS}"
            printf '  verdict:          %s\n' "pass_with_warning"
        } >&2
        status=0
    else
        log_error "Bounded command failed with exit code ${status}."
        {
            echo "DIAGNOSTIC: bounded unit failed"
            printf '  unit:             %s\n' "${UNIT}"
            printf '  result:           %s\n' "${result}"
            printf '  exec_main_code:   %s\n' "${exec_main_code}"
            printf '  exec_main_status: %s\n' "${exec_main_status}"
            printf '  memory_peak:      %s\n' "${memory_peak_display}"
            printf '  memory_max:       %s\n' "${MEMORY_MAX}"
            printf '  timeout_seconds:  %s\n' "${TIMEOUT_SECONDS}"
        } >&2
        if [[ "${result}" == "timeout" ]]; then
            echo "${TEST_TIMEOUT_SLA_MESSAGE}" >&2
        fi
    fi

    if ! systemctl --user reset-failed "${UNIT}" >/dev/null 2>&1; then
        log_warn "Failed to clear failed state for ${UNIT}."
    fi
fi

if [[ ${status} -eq 0 ]]; then
    log_info "Bounded command completed successfully."
fi

exit "${status}"
