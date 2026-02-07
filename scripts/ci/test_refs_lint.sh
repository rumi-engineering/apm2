#!/usr/bin/env bash
# CI drift guard: validate test path references in evidence artifacts (TCK-00409)
#
# Checks that source_refs in evidence YAML files point to files that actually
# exist in the repository. This catches stale references after file moves or
# deletions.
#
# Exit codes:
#   0 - All test/source references resolve
#   1 - Missing references found
#   2 - Script error
#
# Usage:
#   ./scripts/ci/test_refs_lint.sh

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

log_error() { echo -e "${RED}ERROR:${NC} $*" >&2; }
log_info() { echo -e "${GREEN}INFO:${NC} $*"; }

VIOLATIONS=0
REPO_ROOT="$(git rev-parse --show-toplevel)"
RFC_DIR="${REPO_ROOT}/documents/rfcs"

if [[ ! -d "$RFC_DIR" ]]; then
    log_error "RFC directory not found: ${RFC_DIR} (are you inside the repository?)"
    exit 2
fi

log_info "=== Test/Source Reference Lint (TCK-00409) ==="
echo

# Check source_refs in evidence artifacts point to existing files
log_info "Checking source_refs in evidence artifacts..."
while IFS= read -r evid_file; do
    in_source_refs=0
    while IFS= read -r line; do
        # Detect start of source_refs block
        if [[ "$line" =~ ^[[:space:]]*source_refs: ]]; then
            in_source_refs=1
            continue
        fi
        # If we're in source_refs block, check list items
        if [[ $in_source_refs -eq 1 ]]; then
            # Stop if we hit a non-list key at same/lower indent
            if [[ "$line" =~ ^[[:space:]]*[a-z_]+: ]] && ! [[ "$line" =~ ^[[:space:]]*- ]]; then
                in_source_refs=0
                continue
            fi
            # Extract path from list item (- "path", - 'path', or - path)
            # Steps: strip trailing YAML comments, then remove surrounding quotes
            ref_path=$(echo "$line" | \
                sed 's/ #.*$//' | \
                sed -n "s/^[[:space:]]*- [[:space:]]*[\"']\{0,1\}\([^\"']*\)[\"']\{0,1\}[[:space:]]*$/\1/p")
            if [[ -n "$ref_path" ]]; then
                # Extract just the file path part:
                # - Before any space (section refs like "file.md §3.1")
                # - Strip trailing :line-number ranges (like "file.rs:482-567")
                file_path=$(echo "$ref_path" | awk '{print $1}' | sed 's/:[0-9].*$//')
                if [[ -n "$file_path" ]] && ! [[ "$file_path" =~ ^# ]]; then
                    # Anchor relative paths to REPO_ROOT for consistent resolution
                    if [[ "$file_path" != /* ]]; then
                        anchored_path="${REPO_ROOT}/${file_path}"
                    else
                        anchored_path="$file_path"
                    fi
                    # Validate path is within the repository root (prevent path traversal)
                    resolved="$(realpath -m "$anchored_path")"
                    if [[ "$resolved" != "$REPO_ROOT"/* ]]; then
                        log_error "Path traversal: ${evid_file} references '${file_path}' which is outside repo root"
                        VIOLATIONS=1
                        continue
                    fi
                    if [[ ! -e "$anchored_path" ]]; then
                        log_error "Missing source_ref: ${evid_file} references '${file_path}' which does not exist"
                        VIOLATIONS=1
                    fi
                fi
            fi
        fi
    done < "$evid_file"
done < <(find "$RFC_DIR" -path '*/evidence_artifacts/EVID-*.yaml' 2>/dev/null || true)

echo
if [[ $VIOLATIONS -eq 1 ]]; then
    log_error "=== FAILED: Evidence artifacts reference missing test files/paths ==="
    exit 1
else
    log_info "=== PASSED: All evidence source_refs resolve to existing files ==="
    exit 0
fi
