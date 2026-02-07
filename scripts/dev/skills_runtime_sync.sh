#!/usr/bin/env bash

set -euo pipefail

usage() {
    cat <<'USAGE'
Usage: skills_runtime_sync.sh [sync] [--check] [--verbose]

Materialize documents/skills into a per-worktree runtime directory and keep
.claude/skills pointed at the runtime path.

Modes:
  sync (default)  Sync source skills and update .claude/skills symlink.
  --check         Verify runtime and symlink are up to date; exit non-zero on drift.

Flags:
  --verbose       Print additional diagnostics.
USAGE
}

log() {
    if [[ "${VERBOSE}" -eq 1 ]]; then
        printf '[skills-sync] %s\n' "$*"
    fi
}

warn() {
    printf '[skills-sync] %s\n' "$*" >&2
}

die() {
    warn "ERROR: $*"
    exit 1
}

require_cmd() {
    local cmd_name="$1"
    if ! command -v "${cmd_name}" >/dev/null 2>&1; then
        die "Required command not found: ${cmd_name}"
    fi
}

hash_string() {
    local value="$1"

    if command -v sha256sum >/dev/null 2>&1; then
        printf '%s' "${value}" | sha256sum | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        printf '%s' "${value}" | shasum -a 256 | awk '{print $1}'
    elif command -v openssl >/dev/null 2>&1; then
        printf '%s' "${value}" | openssl dgst -sha256 -r | awk '{print $1}'
    else
        die "No SHA-256 hash command available (sha256sum/shasum/openssl)"
    fi
}

canonical_path() {
    local path="$1"
    if command -v realpath >/dev/null 2>&1; then
        realpath "${path}"
        return
    fi

    if command -v python3 >/dev/null 2>&1; then
        python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "${path}"
        return
    fi

    die "No canonical path resolver found (realpath/python3)"
}

is_hex_id() {
    local value="$1"
    [[ "${value}" =~ ^[0-9a-f]{64}$ ]]
}

assert_under_root() {
    local root="$1"
    local path="$2"

    case "${path}" in
        "${root}"/*) ;;
        *)
            die "Path escapes expected root: path=${path}, root=${root}"
            ;;
    esac
}

ensure_skills_symlink() {
    local claude_dir="${WORKTREE_ROOT}/.claude"
    local link_path="${claude_dir}/skills"
    local runtime_real
    local tmp_link

    runtime_real="$(canonical_path "${RUNTIME_DIR}")"
    assert_under_root "${GLOBAL_ROOT}" "${runtime_real}"

    mkdir -p "${claude_dir}"

    if [[ -e "${link_path}" && ! -L "${link_path}" ]]; then
        local backup_path
        backup_path="${claude_dir}/skills.backup.$(date +%Y%m%d%H%M%S).$$"
        mv "${link_path}" "${backup_path}"
        warn "Moved existing non-symlink ${link_path} to ${backup_path}"
    fi

    tmp_link="${claude_dir}/.skills.link.$$"
    rm -f "${tmp_link}"
    ln -s "${runtime_real}" "${tmp_link}"
    mv -Tf "${tmp_link}" "${link_path}"

    log "Linked ${link_path} -> ${runtime_real}"
}

sync_runtime() {
    local tmp_dir
    local backup_dir=""

    tmp_dir="$(mktemp -d "${RUNTIME_PARENT}/.${WORKTREE_ID}.tmp.XXXXXX")"

    cleanup_sync() {
        local status="$?"

        if [[ -n "${tmp_dir}" && -d "${tmp_dir}" ]]; then
            rm -rf "${tmp_dir}"
        fi

        if [[ "${status}" -ne 0 && -n "${backup_dir}" && -e "${backup_dir}" && ! -e "${RUNTIME_DIR}" ]]; then
            mv "${backup_dir}" "${RUNTIME_DIR}" || true
        fi

        return "${status}"
    }

    trap cleanup_sync EXIT

    rsync -a --delete "${SOURCE_SKILLS_DIR}/" "${tmp_dir}/"

    if [[ -e "${RUNTIME_DIR}" || -L "${RUNTIME_DIR}" ]]; then
        backup_dir="${RUNTIME_PARENT}/.${WORKTREE_ID}.bak.$$"
        rm -rf "${backup_dir}"
        mv "${RUNTIME_DIR}" "${backup_dir}"
    fi

    mv "${tmp_dir}" "${RUNTIME_DIR}"
    tmp_dir=""

    if [[ -n "${backup_dir}" && -e "${backup_dir}" ]]; then
        rm -rf "${backup_dir}"
    fi

    trap - EXIT

    ensure_skills_symlink
}

check_runtime() {
    local claude_link="${WORKTREE_ROOT}/.claude/skills"
    local drift=0

    if [[ ! -d "${RUNTIME_DIR}" ]]; then
        warn "Runtime directory missing: ${RUNTIME_DIR}"
        drift=1
    else
        local rsync_output
        rsync_output="$(rsync -an --delete --out-format='%i %n' "${SOURCE_SKILLS_DIR}/" "${RUNTIME_DIR}/")"
        if [[ -n "${rsync_output}" ]]; then
            warn "Runtime skills drift detected: ${RUNTIME_DIR}"
            if [[ "${VERBOSE}" -eq 1 ]]; then
                printf '%s\n' "${rsync_output}" >&2
            fi
            drift=1
        fi
    fi

    if [[ ! -L "${claude_link}" ]]; then
        warn "Expected symlink missing: ${claude_link}"
        drift=1
    elif [[ -d "${RUNTIME_DIR}" ]]; then
        local runtime_real
        local link_real
        runtime_real="$(canonical_path "${RUNTIME_DIR}")"
        link_real="$(canonical_path "${claude_link}")"

        if [[ "${link_real}" != "${runtime_real}" ]]; then
            warn "Symlink target drift: ${claude_link} -> ${link_real}, expected ${runtime_real}"
            drift=1
        fi
    fi

    if [[ "${drift}" -ne 0 ]]; then
        return 1
    fi

    log "Runtime skills are up to date"
    return 0
}

MODE="sync"
VERBOSE=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        sync)
            MODE="sync"
            ;;
        --check)
            MODE="check"
            ;;
        --verbose|-v)
            VERBOSE=1
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            die "Unknown argument: $1"
            ;;
    esac
    shift
done

require_cmd git
require_cmd rsync
require_cmd mkdir
require_cmd mv
require_cmd ln
require_cmd awk

WORKTREE_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [[ -z "${WORKTREE_ROOT}" ]]; then
    die "Not inside a git worktree"
fi
WORKTREE_ROOT="$(canonical_path "${WORKTREE_ROOT}")"

SOURCE_SKILLS_DIR="${WORKTREE_ROOT}/documents/skills"
if [[ ! -d "${SOURCE_SKILLS_DIR}" ]]; then
    die "Source skills directory not found: ${SOURCE_SKILLS_DIR}"
fi

REMOTE_URL="$(git -C "${WORKTREE_ROOT}" remote get-url origin 2>/dev/null || true)"
REPO_SEED="${REMOTE_URL}"
if [[ -z "${REPO_SEED}" ]]; then
    REPO_SEED="${WORKTREE_ROOT}"
fi

REPO_ID="$(hash_string "${REPO_SEED}")"
WORKTREE_ID="$(hash_string "${WORKTREE_ROOT}")"

is_hex_id "${REPO_ID}" || die "Invalid repo_id hash output"
is_hex_id "${WORKTREE_ID}" || die "Invalid worktree_id hash output"

STATE_HOME="${XDG_STATE_HOME:-${HOME}/.local/state}"
GLOBAL_ROOT="${STATE_HOME}/apm2/skills"
RUNTIME_PARENT="${GLOBAL_ROOT}/${REPO_ID}"
RUNTIME_DIR="${RUNTIME_PARENT}/${WORKTREE_ID}"

mkdir -p "${RUNTIME_PARENT}"
GLOBAL_ROOT="$(canonical_path "${GLOBAL_ROOT}")"
RUNTIME_PARENT="$(canonical_path "${RUNTIME_PARENT}")"
RUNTIME_DIR="${RUNTIME_PARENT}/${WORKTREE_ID}"

assert_under_root "${GLOBAL_ROOT}" "${RUNTIME_PARENT}"
assert_under_root "${GLOBAL_ROOT}" "${RUNTIME_DIR}"

log "repo_id=${REPO_ID}"
log "worktree_id=${WORKTREE_ID}"
log "source=${SOURCE_SKILLS_DIR}"
log "runtime=${RUNTIME_DIR}"

if [[ "${MODE}" == "check" ]]; then
    check_runtime
else
    sync_runtime
fi
