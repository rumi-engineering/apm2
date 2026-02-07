#!/usr/bin/env bash
# CI drift guard: validate evidence/requirement cross-references (TCK-00409)
#
# Checks that:
# 1. Every requirement_id in evidence artifacts resolves to an existing REQ-*.yaml
# 2. Every evidence_id in requirement files resolves to an existing EVID-*.yaml
#    (requirements with status PROPOSED are allowed forward references)
#
# Known pre-existing broken references are listed in the KNOWN_ISSUES array
# and produce warnings instead of errors. Remove entries as they are fixed.
#
# Exit codes:
#   0 - All references resolve (or are permitted forward/known references)
#   1 - New broken references found
#   2 - Script error
#
# Usage:
#   ./scripts/ci/evidence_refs_lint.sh

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

VIOLATIONS=0
WARNINGS=0
REPO_ROOT="$(git rev-parse --show-toplevel)"
RFC_DIR="${REPO_ROOT}/documents/rfcs"

if [[ ! -d "$RFC_DIR" ]]; then
    log_error "RFC directory not found: ${RFC_DIR} (are you inside the repository?)"
    exit 2
fi

# Known pre-existing broken references (file:ref_id pairs).
# These produce warnings instead of hard failures.
# Remove entries from this list as each reference is fixed.
declare -A KNOWN_ISSUES
KNOWN_ISSUES["RFC-0020/EVID-0101:REQ-0101"]=1

log_info "=== Evidence/Requirement Reference Lint (TCK-00409) ==="
echo

# Collect all existing requirement IDs across all RFCs
declare -A REQ_INDEX
while IFS= read -r req_file; do
    rfc=$(echo "$req_file" | sed -n 's|.*documents/rfcs/\([^/]*\)/.*|\1|p')
    basename_no_ext=$(basename "$req_file" .yaml)
    REQ_INDEX["${rfc}/${basename_no_ext}"]=1
done < <(find "$RFC_DIR" -path '*/requirements/REQ-*.yaml' 2>/dev/null || true)

# Collect all existing evidence IDs across all RFCs
declare -A EVID_INDEX
while IFS= read -r evid_file; do
    rfc=$(echo "$evid_file" | sed -n 's|.*documents/rfcs/\([^/]*\)/.*|\1|p')
    basename_no_ext=$(basename "$evid_file" .yaml)
    basename_no_ext="${basename_no_ext%.md}"
    EVID_INDEX["${rfc}/${basename_no_ext}"]=1
done < <(find "$RFC_DIR" -path '*/evidence_artifacts/EVID-*' 2>/dev/null || true)

# extract_yaml_list_block: given a file and a key name, extract only the YAML
# list items immediately under that key, respecting indentation scope.
# Handles both styles:
#   requirement_ids:          evidence_ids:
#     - "REQ-0101"            - EVID-1001     (items at same indent as key)
# Stops at the next sibling mapping key (non-list line at same or lesser indent).
# IMPORTANT: Only emits actual list-item lines (starting with '-'), not arbitrary
# nested content like narrative text or multiline string continuations.  This
# prevents false positives from tokens appearing in description/notes blocks.
extract_yaml_list_block() {
    local file="$1"
    local key="$2"
    local in_block=0
    local key_indent=-1
    local list_item_indent=-1
    while IFS= read -r line; do
        # Match the target key (e.g. "requirement_ids:")
        if [[ $in_block -eq 0 ]] && [[ "$line" =~ ^([[:space:]]*)${key}: ]]; then
            in_block=1
            key_indent=${#BASH_REMATCH[1]}
            continue
        fi
        if [[ $in_block -eq 1 ]]; then
            # Skip blank lines
            if [[ "$line" =~ ^[[:space:]]*$ ]]; then
                continue
            fi
            # Measure leading whitespace of this line
            local stripped="${line#"${line%%[![:space:]]*}"}"
            local line_indent=$(( ${#line} - ${#stripped} ))
            # If at or less indented than the key, we've left the block
            if [[ $line_indent -le $key_indent ]]; then
                # Exception: list items at the same indent as the key (compact YAML)
                if [[ $line_indent -eq $key_indent ]] && [[ "$stripped" == -* ]]; then
                    echo "$line"
                    continue
                fi
                break  # sibling mapping key or parent scope
            fi
            # More indented than the key — check if this is a list item
            if [[ "$stripped" == -* ]]; then
                # Record the indent level of the first list item we see
                if [[ $list_item_indent -eq -1 ]]; then
                    list_item_indent=$line_indent
                fi
                echo "$line"
                continue
            fi
            # Non-list-item line: if we have established the list item indent
            # and this line is at the same or less indent as list items,
            # it's a sibling mapping key — stop.
            if [[ $list_item_indent -ne -1 ]] && [[ $line_indent -le $list_item_indent ]]; then
                break
            fi
            # Otherwise this line is a continuation of a list item value
            # (e.g., multiline string).  Skip it — do NOT emit non-list content
            # to prevent narrative tokens from leaking into the extracted IDs.
        fi
    done < "$file"
}

# Check 1: Every requirement_id in evidence artifacts resolves to a REQ file
log_info "Checking requirement_ids in evidence artifacts..."
while IFS= read -r evid_file; do
    rfc=$(echo "$evid_file" | sed -n 's|.*documents/rfcs/\([^/]*\)/.*|\1|p')
    evid_basename=$(basename "$evid_file" .yaml)

    # Extract all requirement_ids scoped to the YAML block (not overshooting)
    all_req_ids=$(extract_yaml_list_block "$evid_file" "requirement_ids" | \
        grep -oP 'REQ-[A-Z]*[0-9]+' | sort -u || true)

    for req_id in $all_req_ids; do
        if [[ -z "${REQ_INDEX["${rfc}/${req_id}"]:-}" ]]; then
            known_key="${rfc}/${evid_basename}:${req_id}"
            if [[ -n "${KNOWN_ISSUES["${known_key}"]:-}" ]]; then
                log_warn "Known issue: ${evid_file} references ${req_id} (pre-existing, tracked)"
                WARNINGS=$((WARNINGS + 1))
            else
                log_error "Broken reference: ${evid_file} references ${req_id} but no ${RFC_DIR}/${rfc}/requirements/${req_id}.yaml exists"
                VIOLATIONS=1
            fi
        fi
    done
done < <(find "$RFC_DIR" -path '*/evidence_artifacts/EVID-*.yaml' 2>/dev/null || true)

# Check 2: Every evidence_id in requirement files resolves to an EVID file
# Requirements with status PROPOSED are allowed forward references.
log_info "Checking evidence_ids in requirement files..."
while IFS= read -r req_file; do
    rfc=$(echo "$req_file" | sed -n 's|.*documents/rfcs/\([^/]*\)/.*|\1|p')

    req_status=$(grep -oP '^\s*status:\s*"?\K[A-Z_]+' "$req_file" 2>/dev/null || echo "UNKNOWN")

    # Extract all evidence_ids scoped to the YAML block (not overshooting)
    evid_ids=$(extract_yaml_list_block "$req_file" "evidence_ids" | \
        grep -oP 'EVID-[A-Z]*[0-9]+' | sort -u || true)

    for evid_id in $evid_ids; do
        if [[ -z "${EVID_INDEX["${rfc}/${evid_id}"]:-}" ]]; then
            if [[ "$req_status" == "PROPOSED" ]]; then
                WARNINGS=$((WARNINGS + 1))
            else
                log_error "Broken reference: ${req_file} (status=${req_status}) references ${evid_id} but no ${RFC_DIR}/${rfc}/evidence_artifacts/${evid_id}.yaml exists"
                VIOLATIONS=1
            fi
        fi
    done
done < <(find "$RFC_DIR" -path '*/requirements/REQ-*.yaml' 2>/dev/null || true)

echo
if [[ $WARNINGS -gt 0 ]]; then
    log_warn "${WARNINGS} forward/known reference(s) skipped (allowed)"
fi

if [[ $VIOLATIONS -eq 1 ]]; then
    log_error "=== FAILED: Broken evidence/requirement references detected ==="
    exit 1
else
    log_info "=== PASSED: All evidence/requirement references resolve ==="
    exit 0
fi
