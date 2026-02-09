#!/usr/bin/env bash
# CI guardrail: tracked workspace integrity check around test execution
# (TCK-00410)
#
# Modes:
#   guard   (default): snapshot -> run command -> verify
#   snapshot: produce a tracked-file manifest
#   verify: compare current tracked state to a baseline manifest
#
# Exit codes:
#   0 - Integrity preserved (or snapshot written)
#   1 - Integrity violation detected / guarded command failed
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
  # Guard mode (default)
  ./scripts/ci/workspace_integrity_guard.sh \
    [--repo-root PATH] \
    [--snapshot-file PATH] \
    [--allowlist PATH] \
    -- <command> [args...]

  # Snapshot mode
  ./scripts/ci/workspace_integrity_guard.sh snapshot \
    [--repo-root PATH] \
    [--snapshot-file PATH]

  # Verify mode
  ./scripts/ci/workspace_integrity_guard.sh verify \
    [--repo-root PATH] \
    [--snapshot-file PATH] \
    [--allowlist PATH]

Allowlist format (verify/guard mode):
  - One path per line, relative to repo root.
  - Blank lines and # comments are ignored.
USAGE
}

hash_file() {
    local path="$1"

    # Symlink safety: hash the link target path string, not dereferenced content.
    # This prevents unbounded reads if a symlink points to /dev/zero or similar.
    if [[ -L "${path}" ]]; then
        readlink "${path}" | sha256sum | awk '{print $1}'
        return
    fi

    # Per-file timeout prevents unbounded reads on special/huge files.
    if command -v sha256sum >/dev/null 2>&1; then
        timeout 5s sha256sum "${path}" | awk '{print $1}'
        return
    fi
    if command -v shasum >/dev/null 2>&1; then
        timeout 5s shasum -a 256 "${path}" | awk '{print $1}'
        return
    fi
    log_error "No SHA-256 tool found (sha256sum or shasum required)."
    exit 2
}

read_allowlist() {
    local allowlist_path="$1"
    if [[ -z "${allowlist_path}" ]]; then
        return
    fi
    if [[ ! -f "${allowlist_path}" ]]; then
        log_error "Allowlist file not found: ${allowlist_path}"
        exit 2
    fi
    mapfile -t ALLOWED_PATHS < <(
        sed -e 's/[[:space:]]*$//' "${allowlist_path}" | grep -Ev '^[[:space:]]*($|#)' || true
    )
}

is_path_allowlisted() {
    local path="$1"
    local allowed
    for allowed in "${ALLOWED_PATHS[@]:-}"; do
        if [[ "${allowed}" == "${path}" ]]; then
            return 0
        fi
    done
    return 1
}

generate_manifest() {
    local repo_root="$1"
    local output_file="$2"
    local tmp_file
    tmp_file="$(mktemp)"

    (
        cd "${repo_root}"
        if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
            log_error "Not a git worktree: ${repo_root}"
            exit 2
        fi

        while IFS= read -r -d '' tracked; do
            local_hash='MISSING'
            local_mode='000000'

            if [[ -e "${tracked}" ]]; then
                local_hash="$(hash_file "${tracked}")"
                # Linux runner target (OVH self-hosted). Hex mode keeps output stable.
                local_mode="$(stat -c '%f' "${tracked}" 2>/dev/null || echo '000000')"
            fi

            printf '%s\t%s\t%s\n' "${tracked}" "${local_hash}" "${local_mode}"
        done < <(git ls-files -z)
    ) | sort > "${tmp_file}"

    mkdir -p "$(dirname "${output_file}")"
    mv "${tmp_file}" "${output_file}"
}

collect_changed_paths() {
    local baseline="$1"
    local current="$2"
    awk -F'\t' '
        NR==FNR { old[$1]=$2 "\t" $3; next }
        { cur[$1]=$2 "\t" $3 }
        END {
            for (p in old) {
                if (!(p in cur) || old[p] != cur[p]) {
                    print p
                }
            }
            for (p in cur) {
                if (!(p in old)) {
                    print p
                }
            }
        }
    ' "${baseline}" "${current}" | sort -u
}

verify_manifest() {
    local repo_root="$1"
    local snapshot_file="$2"
    local allowlist_path="$3"

    if [[ ! -f "${snapshot_file}" ]]; then
        log_error "Snapshot file not found: ${snapshot_file}"
        exit 2
    fi

    read_allowlist "${allowlist_path}"

    local current_manifest
    current_manifest="$(mktemp)"
    generate_manifest "${repo_root}" "${current_manifest}"

    local changed
    changed="$(collect_changed_paths "${snapshot_file}" "${current_manifest}")"
    rm -f "${current_manifest}"

    if [[ -z "${changed}" ]]; then
        log_info "Workspace integrity verified: no tracked mutations detected."
        return 0
    fi

    local violations=0
    while IFS= read -r path; do
        [[ -z "${path}" ]] && continue
        if is_path_allowlisted "${path}"; then
            continue
        fi
        if [[ ${violations} -eq 0 ]]; then
            log_error "Tracked workspace mutations detected after test execution:"
        fi
        log_error "  ${path}"
        violations=$((violations + 1))
    done <<< "${changed}"

    if [[ ${violations} -gt 0 ]]; then
        log_error "Workspace integrity guard failed (fail-closed)."
        return 1
    fi

    log_warn "Only allowlisted tracked mutations were detected."
    return 0
}

MODE='guard'
if [[ $# -gt 0 ]]; then
    case "$1" in
        snapshot|verify|guard)
            MODE="$1"
            shift
            ;;
    esac
fi

REPO_ROOT=''
SNAPSHOT_FILE=''
ALLOWLIST_PATH=''
declare -a GUARDED_COMMAND=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --repo-root)
            shift
            [[ $# -gt 0 ]] || { log_error "--repo-root requires a value"; exit 2; }
            REPO_ROOT="$1"
            ;;
        --snapshot-file)
            shift
            [[ $# -gt 0 ]] || { log_error "--snapshot-file requires a value"; exit 2; }
            SNAPSHOT_FILE="$1"
            ;;
        --allowlist)
            shift
            [[ $# -gt 0 ]] || { log_error "--allowlist requires a value"; exit 2; }
            ALLOWLIST_PATH="$1"
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --)
            shift
            GUARDED_COMMAND=("$@")
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

if [[ -z "${REPO_ROOT}" ]]; then
    REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
fi
REPO_ROOT="$(cd "${REPO_ROOT}" && pwd)"

if [[ -z "${SNAPSHOT_FILE}" ]]; then
    SNAPSHOT_FILE="${REPO_ROOT}/target/ci/workspace_integrity.snapshot.tsv"
fi

log_info "=== Workspace Integrity Guard (TCK-00410) ==="
log_info "Mode: ${MODE}"
log_info "Repo root: ${REPO_ROOT}"
log_info "Snapshot file: ${SNAPSHOT_FILE}"
if [[ -n "${ALLOWLIST_PATH}" ]]; then
    log_info "Allowlist: ${ALLOWLIST_PATH}"
fi
echo

case "${MODE}" in
    snapshot)
        generate_manifest "${REPO_ROOT}" "${SNAPSHOT_FILE}"
        log_info "Snapshot written: ${SNAPSHOT_FILE}"
        exit 0
        ;;
    verify)
        verify_manifest "${REPO_ROOT}" "${SNAPSHOT_FILE}" "${ALLOWLIST_PATH}"
        exit $?
        ;;
    guard)
        if [[ ${#GUARDED_COMMAND[@]} -eq 0 ]]; then
            log_error "Guard mode requires a command after '--'."
            usage
            exit 2
        fi

        generate_manifest "${REPO_ROOT}" "${SNAPSHOT_FILE}"
        log_info "Baseline snapshot captured."
        echo

        set +e
        (
            cd "${REPO_ROOT}"
            "${GUARDED_COMMAND[@]}"
        )
        command_status=$?
        set -e

        if [[ ${command_status} -ne 0 ]]; then
            log_error "Guarded command failed with exit code ${command_status}."
        fi

        set +e
        verify_manifest "${REPO_ROOT}" "${SNAPSHOT_FILE}" "${ALLOWLIST_PATH}"
        verify_status=$?
        set -e

        if [[ ${command_status} -ne 0 || ${verify_status} -ne 0 ]]; then
            exit 1
        fi

        exit 0
        ;;
    *)
        log_error "Unknown mode: ${MODE}"
        exit 2
        ;;
esac
