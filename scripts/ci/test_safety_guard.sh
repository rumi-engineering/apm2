#!/usr/bin/env bash
# CI guardrail: fail-closed detection of dangerous test patterns (TCK-00410)
#
# Blocks destructive test signatures before execution:
# - destructive filesystem operations
# - unbounded shell execution patterns
# - unsafe recursive deletion commands
#
# Exit codes:
#   0 - No violations detected
#   1 - Violations detected
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
  ./scripts/ci/test_safety_guard.sh [--allowlist PATH] [PATH ...]

Behavior:
  - Without PATH arguments, scans test-oriented files in the repository.
  - With PATH arguments, scans those files/directories only.

Allowlist format (one entry per line):
  RULE_ID|path
  RULE_ID|path:line
  *|path
  *|path:line
  RULE_ID|re:<bash-regex>

Example:
  TSG004|crates/apm2-core/tests/safe_shell_wrapper.rs:88
  *|re:^TSG006\|scripts/ci/.*
USAGE
}

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
DEFAULT_ALLOWLIST="${REPO_ROOT}/scripts/ci/test_safety_allowlist.txt"
ALLOWLIST_PATH="${DEFAULT_ALLOWLIST}"

declare -a TARGETS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --allowlist)
            shift
            if [[ $# -eq 0 ]]; then
                log_error "--allowlist requires a path"
                exit 2
            fi
            ALLOWLIST_PATH="$1"
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --)
            shift
            TARGETS+=("$@")
            break
            ;;
        *)
            TARGETS+=("$1")
            ;;
    esac
    shift
done

if ! command -v rg >/dev/null 2>&1; then
    log_error "ripgrep (rg) is required."
    exit 2
fi

if [[ ! -f "${ALLOWLIST_PATH}" ]]; then
    log_error "Allowlist file not found (fail-closed): ${ALLOWLIST_PATH}"
    exit 2
fi

mapfile -t ALLOWLIST_ENTRIES < <(sed -e 's/[[:space:]]*$//' "${ALLOWLIST_PATH}" | grep -Ev '^[[:space:]]*($|#)' || true)

declare -a RULE_IDS=(
    "TSG001"
    "TSG002"
    "TSG003"
    "TSG004"
    "TSG005"
    "TSG006"
    "TSG007"
    "TSG008"
    "TSG009"
)

declare -a RULE_PATTERNS=(
    'rm[[:space:]]+-[[:alnum:]-]*r[[:alnum:]-]*f[[:space:]]+(/|~|[$][{]?HOME[}]?)'
    'rm[[:space:]]+-[[:alnum:]-]*r[[:alnum:]-]*f[[:space:]]+([$][{]?PWD[}]?|[.][.])'
    'std::fs::remove_dir_all[[:space:]]*[(][[:space:]]*("(/|~)|std::env::var[[:space:]]*[(][[:space:]]*"HOME")'
    'std::fs::remove_file[[:space:]]*[(][[:space:]]*("(/|~)|std::env::var[[:space:]]*[(][[:space:]]*"HOME")'
    'Command::new[[:space:]]*[(][[:space:]]*"(sh|bash|zsh)"[[:space:]]*[)][[:space:]]*[.][[:space:]]*arg[[:space:]]*[(][[:space:]]*"-c"'
    'Command::new[[:space:]]*[(][[:space:]]*"rm"[[:space:]]*[)].*(-rf|-fr|-r[[:space:]]+-f|-f[[:space:]]+-r)'
    'git[[:space:]]+clean[[:space:]]+-fdx'
    'rm[[:space:]]+-[[:alnum:]-]*r[[:alnum:]-]*f[[:space:]]+("|'"'"')[[:space:]]*/[[:space:]]*("|'"'"')'
    'rm[[:space:]]+-[[:alnum:]-]*r[[:alnum:]-]*f[[:space:]]+("|'"'"')[[:space:]]*~[[:space:]]*("|'"'"')'
)

declare -a RULE_DESCRIPTIONS=(
    "recursive delete targeting root/home"
    "recursive delete targeting current/parent workspace"
    "absolute-path recursive delete via std::fs::remove_dir_all"
    "absolute-path file delete via std::fs::remove_file"
    "unbounded shell execution via Command::new(<shell>).arg(\"-c\")"
    "shelling out to recursive rm command construction"
    "destructive git clean of entire working tree"
    "recursive delete targeting quoted root path"
    "recursive delete targeting quoted home path"
)

# Multiline rules that require rg -U (multiline mode).
# These detect Rust Command::new patterns split across lines.
declare -a ML_RULE_IDS=(
    "TSG005M"
    "TSG006M"
)

declare -a ML_RULE_PATTERNS=(
    'Command::new\s*\(\s*"(sh|bash|zsh)"\s*\)\s*\n\s*\.\s*arg\s*\(\s*"-c"'
    'Command::new\s*\(\s*"rm"\s*\)\s*\n\s*\.arg\s*\(\s*"(-rf|-fr|-r)"\s*\)'
)

declare -a ML_RULE_DESCRIPTIONS=(
    "multiline unbounded shell execution via Command::new(<shell>).arg(\"-c\")"
    "multiline shelling out to recursive rm command construction"
)

is_allowlisted() {
    local rule_id="$1"
    local file="$2"
    local line="$3"
    local text="$4"
    local key="${file}:${line}"
    local payload="${rule_id}|${key}|${text}"

    local entry
    for entry in "${ALLOWLIST_ENTRIES[@]}"; do
        local entry_rule='*'
        local entry_selector="$entry"

        if [[ "$entry" == *"|"* ]]; then
            entry_rule="${entry%%|*}"
            entry_selector="${entry#*|}"
        fi

        if [[ "${entry_rule}" != "*" && "${entry_rule}" != "${rule_id}" ]]; then
            continue
        fi

        if [[ "${entry_selector}" == re:* ]]; then
            local expr="${entry_selector#re:}"
            if [[ "${payload}" =~ ${expr} ]]; then
                return 0
            fi
            continue
        fi

        if [[ "${entry_selector}" == "${file}" || "${entry_selector}" == "${key}" ]]; then
            return 0
        fi
    done

    return 1
}

is_scannable_file() {
    local file="$1"
    case "${file}" in
        *.rs|*.sh|*.bash|*.zsh|*.py) return 0 ;;
        *) return 1 ;;
    esac
}

collect_default_targets() {
    local file
    while IFS= read -r file; do
        file="${file#./}"

        if [[ "${file}" == "scripts/ci/test_safety_guard.sh" ]] || \
           [[ "${file}" == "scripts/ci/test_guardrail_fixtures.sh" ]] || \
           [[ "${file}" == scripts/ci/fixtures/* ]]; then
            continue
        fi

        if [[ "${file}" =~ (^|/)(tests?|testdata|fixtures)/ ]] || \
           [[ "${file}" =~ (^|/)(test_.*|.*_test)\.(rs|sh|bash|zsh|py)$ ]] || \
           [[ "${file}" =~ ^scripts/ci/test_.*\.sh$ ]]; then
            printf '%s\n' "${file}"
        fi
    done < <(rg --files . --glob '*.rs' --glob '*.sh' --glob '*.bash' --glob '*.zsh' --glob '*.py' | sort)

    # Also scan src/ Rust files that contain #[cfg(test)] modules.
    # Tests embedded in src/ via #[cfg(test)] are a common Rust pattern and
    # must not escape the safety net.
    while IFS= read -r file; do
        file="${file#./}"
        printf '%s\n' "${file}"
    done < <(rg --files-with-matches '#\[cfg\(test\)\]' --glob '*/src/**/*.rs' . 2>/dev/null | sort)
}

collect_from_target() {
    local target="$1"

    if [[ ! -e "${target}" ]]; then
        log_error "Target does not exist: ${target}"
        exit 2
    fi

    if [[ -f "${target}" ]]; then
        if is_scannable_file "${target}"; then
            printf '%s\n' "${target}"
        fi
        return
    fi

    local file
    while IFS= read -r file; do
        file="${file#./}"
        printf '%s\n' "${file}"
    done < <(rg --files "${target}" --glob '*.rs' --glob '*.sh' --glob '*.bash' --glob '*.zsh' --glob '*.py' | sort)
}

cd "${REPO_ROOT}"

declare -a FILES=()
if [[ ${#TARGETS[@]} -eq 0 ]]; then
    mapfile -t FILES < <(collect_default_targets | sort -u)
else
    while IFS= read -r file; do
        FILES+=("${file}")
    done < <(
        for target in "${TARGETS[@]}"; do
            collect_from_target "${target}"
        done | awk 'NF' | sort -u
    )
fi

if [[ ${#FILES[@]} -eq 0 ]]; then
    log_warn "No files matched test safety scan targets."
    exit 0
fi

log_info "=== Test Safety Guard (TCK-00410) ==="
log_info "Scanning ${#FILES[@]} file(s)"
log_info "Using allowlist: ${ALLOWLIST_PATH}"
echo

violations=0

for i in "${!RULE_IDS[@]}"; do
    rule_id="${RULE_IDS[$i]}"
    rule_pattern="${RULE_PATTERNS[$i]}"
    rule_desc="${RULE_DESCRIPTIONS[$i]}"

    while IFS= read -r match; do
        [[ -z "${match}" ]] && continue

        file="${match%%:*}"
        rest="${match#*:}"
        line="${rest%%:*}"
        text="${rest#*:}"

        if is_allowlisted "${rule_id}" "${file}" "${line}" "${text}"; then
            continue
        fi

        ((violations += 1))
        log_error "[${rule_id}] ${file}:${line} ${rule_desc}"
        log_error "  ${text}"
    done < <(rg --with-filename --line-number --no-heading --color never -e "${rule_pattern}" "${FILES[@]}" || true)
done

# --- Multiline scan pass ---
# Detects Rust patterns split across lines (e.g., Command::new("sh")\n  .arg("-c")).
# Uses rg -U for multiline matching. Report the first line of each match.
rust_files=()
for file in "${FILES[@]}"; do
    if [[ "${file}" == *.rs ]]; then
        rust_files+=("${file}")
    fi
done

if [[ ${#rust_files[@]} -gt 0 ]]; then
    for i in "${!ML_RULE_IDS[@]}"; do
        ml_rule_id="${ML_RULE_IDS[$i]}"
        ml_rule_pattern="${ML_RULE_PATTERNS[$i]}"
        ml_rule_desc="${ML_RULE_DESCRIPTIONS[$i]}"

        while IFS= read -r match; do
            [[ -z "${match}" ]] && continue

            file="${match%%:*}"
            rest="${match#*:}"
            line="${rest%%:*}"
            text="${rest#*:}"

            if is_allowlisted "${ml_rule_id}" "${file}" "${line}" "${text}"; then
                continue
            fi

            ((violations += 1))
            log_error "[${ml_rule_id}] ${file}:${line} ${ml_rule_desc}"
            log_error "  ${text}"
        done < <(rg -U --with-filename --line-number --no-heading --color never -e "${ml_rule_pattern}" "${rust_files[@]}" || true)
    done
fi

echo
if [[ ${violations} -gt 0 ]]; then
    log_error "Detected ${violations} unsafe test pattern(s)."
    log_error "Add tightly-scoped entries to scripts/ci/test_safety_allowlist.txt only when justified."
    exit 1
fi

log_info "No unsafe test patterns detected."
exit 0
