#!/usr/bin/env bash
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

CHECKLIST="documents/reviews/RUNTIME_CLOSURE_CHECKLIST.json"
if [[ ! -f "${CHECKLIST}" ]]; then
    log_error "runtime closure checklist missing: ${CHECKLIST}"
    exit 1
fi

if ! jq -e . "${CHECKLIST}" >/dev/null 2>&1; then
    log_error "invalid runtime closure checklist JSON: ${CHECKLIST}"
    exit 1
fi

GATE_ID="$(jq -r '.gate_id' "${CHECKLIST}")"
WAIVER_DIR="$(jq -r '.waiver.directory' "${CHECKLIST}")"

security_qcp_raw="${APM2_SECURITY_QCP:-${SECURITY_QCP:-}}"
security_qcp="$(echo "${security_qcp_raw}" | tr '[:lower:]' '[:upper:]')"
if [[ "${security_qcp}" == "YES" || "${security_qcp}" == "TRUE" || "${security_qcp}" == "1" ]]; then
    log_info "SECURITY/QCP mode enabled via env flag"
fi

BASE_REF="${APM2_DIFF_BASE:-}"
if [[ -z "${BASE_REF}" ]]; then
    if git rev-parse --verify origin/main >/dev/null 2>&1; then
        BASE_REF="$(git merge-base origin/main HEAD)"
    else
        BASE_REF="$(git rev-parse HEAD~1)"
    fi
fi

mapfile -t changed_files < <(git diff --name-only "${BASE_REF}...HEAD")
if [[ ${#changed_files[@]} -eq 0 ]]; then
    log_info "No changed files detected for runtime closure check"
    exit 0
fi

mapfile -t security_modules < <(jq -r '.security_modules[].path' "${CHECKLIST}")
declare -a changed_security_modules=()

for module_path in "${security_modules[@]}"; do
    if printf '%s\n' "${changed_files[@]}" | rg -x --fixed-strings "${module_path}" >/dev/null; then
        changed_security_modules+=("${module_path}")
    fi
done

if [[ ${#changed_security_modules[@]} -eq 0 ]]; then
    log_info "No tracked security module changes detected"
    exit 0
fi

log_warn "Security module changes detected; enforcing runtime closure"
for module_path in "${changed_security_modules[@]}"; do
    log_warn "  - ${module_path}"
done

find_active_waiver() {
    local today waiver_file
    today="$(date -u +%Y-%m-%d)"

    if [[ ! -d "${WAIVER_DIR}" ]]; then
        return 1
    fi

    for waiver_file in "${WAIVER_DIR}"/WVR-*.yaml; do
        [[ -f "${waiver_file}" ]] || continue

        if ! rg -q --fixed-strings "${GATE_ID}" "${waiver_file}"; then
            continue
        fi

        local status_line status expiry_line expiry
        status_line="$(rg --no-filename -m1 '^[[:space:]]*status:[[:space:]]*"?' "${waiver_file}" || true)"
        status="$(echo "${status_line}" | sed -E 's/.*status:[[:space:]]*"?([A-Za-z_]+)"?.*/\1/' | tr '[:lower:]' '[:upper:]')"
        if [[ "${status}" != "ACTIVE" && "${status}" != "APPROVED" ]]; then
            continue
        fi

        expiry_line="$(rg --no-filename -m1 '^[[:space:]]*(expires|expiration_date):[[:space:]]*"?[0-9]{4}-[0-9]{2}-[0-9]{2}"?' "${waiver_file}" || true)"
        if [[ -z "${expiry_line}" ]]; then
            continue
        fi

        expiry="$(echo "${expiry_line}" | sed -E 's/.*:[[:space:]]*"?([0-9]{4}-[0-9]{2}-[0-9]{2})"?.*/\1/')"
        if [[ -z "${expiry}" ]]; then
            continue
        fi

        if [[ "${expiry}" < "${today}" ]]; then
            continue
        fi

        echo "${waiver_file}"
        return 0
    done

    return 1
}

declare -a failures=()

for module_path in "${changed_security_modules[@]}"; do
    mapfile -t required_callsites < <(
        jq -r --arg path "${module_path}" \
            '.security_modules[] | select(.path == $path) | .required_production_callsites[]' \
            "${CHECKLIST}"
    )

    has_callsite_diff=0
    for callsite in "${required_callsites[@]}"; do
        if printf '%s\n' "${changed_files[@]}" | rg -x --fixed-strings "${callsite}" >/dev/null; then
            has_callsite_diff=1
            break
        fi
    done

    if [[ ${has_callsite_diff} -eq 0 ]]; then
        failures+=("${module_path}")
    fi
done

if [[ ${#failures[@]} -eq 0 ]]; then
    log_info "Runtime closure check passed"
    exit 0
fi

if waiver_file="$(find_active_waiver)"; then
    log_warn "Runtime closure violations waived by ${waiver_file}"
    for module_path in "${failures[@]}"; do
        log_warn "  waived missing production callsite diff: ${module_path}"
    done
    exit 0
fi

log_error "Runtime closure violations detected (no active waiver for ${GATE_ID})"
for module_path in "${failures[@]}"; do
    mapfile -t required_callsites < <(
        jq -r --arg path "${module_path}" \
            '.security_modules[] | select(.path == $path) | .required_production_callsites[]' \
            "${CHECKLIST}"
    )
    log_error "  security module changed without production callsite diff: ${module_path}"
    for callsite in "${required_callsites[@]}"; do
        log_error "    required callsite diff: ${callsite}"
    done
done

exit 1
