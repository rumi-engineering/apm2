#!/usr/bin/env bash
# Security gate: ensure unsafe blocks are documented with SAFETY comments.

set -euo pipefail

if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    NC=''
fi

log_info() { echo -e "${GREEN}INFO:${NC} $*"; }
log_error() { echo -e "${RED}ERROR:${NC} $*" >&2; }

log_info "Checking unsafe blocks for SAFETY documentation"

if ! find crates/apm2-core crates/apm2-daemon -name '*.rs' -type f -print -quit | grep -q .; then
    log_info "No Rust files found under crates/apm2-core or crates/apm2-daemon"
    exit 0
fi

MISSING_PROOFS=""
while IFS= read -r -d '' file; do
    unsafe_count=0
    while IFS= read -r hit; do
        [[ "${hit}" =~ ^[0-9]+:[[:space:]]*/// ]] && continue
        [[ "${hit}" =~ ^[0-9]+:[[:space:]]*//! ]] && continue
        unsafe_count=$((unsafe_count + 1))
    done < <(rg -n "unsafe\\s*\\{" "${file}" 2>/dev/null || true)

    proof_count="$(rg -ci "// SAFETY:" "${file}" 2>/dev/null || true)"
    proof_count="${proof_count:-0}"

    if [[ "${unsafe_count}" -eq 0 ]]; then
        continue
    fi

    if [[ "${unsafe_count}" -gt "${proof_count}" ]]; then
        MISSING_PROOFS="${MISSING_PROOFS}\n${file}: ${unsafe_count} unsafe blocks, ${proof_count} SAFETY comments"
    fi
done < <(find crates/apm2-core crates/apm2-daemon -name '*.rs' -type f -print0)

if [[ -n "${MISSING_PROOFS}" ]]; then
    log_error "Files with unsafe blocks missing SAFETY documentation:"
    echo -e "${MISSING_PROOFS}" >&2
    exit 1
fi

log_info "All unsafe blocks have SAFETY documentation"
exit 0
