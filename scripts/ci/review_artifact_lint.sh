#!/usr/bin/env bash
# CI drift guard: validate review artifact integrity (TCK-00409)
#
# Checks that:
# 1. Review prompt files do not contain deprecated direct status-write commands
#    that bypass the approved review gate path
# 2. Review metadata templates require exact PR number and head SHA binding
#
# Exit codes:
#   0 - All review artifacts are compliant
#   1 - Violations found
#   2 - Script error
#
# Usage:
#   ./scripts/ci/review_artifact_lint.sh

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

check_dependencies() {
    if ! command -v find &>/dev/null; then
        log_error "find is required but not installed."
        exit 2
    fi
}

VIOLATIONS=0

REPO_ROOT="$(git rev-parse --show-toplevel)"
REVIEW_DIR="${REPO_ROOT}/documents/reviews"
REVIEW_GATE_DIR="${REPO_ROOT}/.github/review-gate"

if [[ ! -d "$REVIEW_DIR" ]]; then
    log_error "Review directory not found: ${REVIEW_DIR} (are you inside the repository?)"
    exit 2
fi

log_info "=== Review Artifact Integrity Lint (TCK-00409) ==="
echo

check_dependencies

# Check 1: Review prompts must not contain deprecated direct status-write commands.
# The approved path for setting security review statuses is:
#   cargo xtask security-review-exec (approve|deny)
# Direct writes to statuses/check-runs for ai-review/security are deprecated,
# regardless of HTTP client used (gh api, curl, or variable indirection).
# Note: ai-review/code-quality has no xtask equivalent, so `gh api` writes targeting
# that context are permitted.
# Similarly, `gh pr review --approve` bypasses the review gate and is always forbidden.
log_info "Checking for deprecated direct status-write patterns in review scripts..."

# detect_direct_status_write checks whether a logical line (continuations joined)
# contains a forbidden direct GitHub status write.  Returns 0 (true) if the line
# is a violation.
#
# Strategy (content-based): instead of enumerating every HTTP client (gh, curl,
# etc.), we detect violations by the _content_ of the line.  Any line containing
# `ai-review/security` together with a status/check-run write indicator is
# forbidden.  The only blessed path is `cargo xtask security-review-exec`.
#
# For non-security contexts (e.g. ai-review/code-quality), direct `gh api`
# writes to statuses/check-runs with unknown or unspecified context are still
# flagged.  `gh pr review --approve` is always forbidden.
detect_direct_status_write() {
    local line="$1"
    # Skip comment lines
    local stripped="${line#"${line%%[![:space:]]*}"}"
    if [[ "$stripped" == "#"* ]]; then
        return 1
    fi
    # Normalise to lowercase for case-insensitive matching
    local lc="${line,,}"

    # Rule 1: gh pr review --approve is always forbidden
    if [[ "$lc" == *"gh"* && "$lc" == *"pr"* && "$lc" == *"review"* && "$lc" == *"--approve"* ]]; then
        return 0
    fi

    # Rule 2 (content-based): Any line containing ai-review/security AND any
    # write-indicating context (statuses, check-runs, POST, -X POST, -f, --field,
    # --method) is a violation — regardless of the HTTP client used (gh, curl,
    # variable indirection, etc.).
    # Exception: the blessed xtask path is allowed.
    if [[ "$lc" == *"ai-review/security"* ]]; then
        # Allow the blessed xtask path
        if [[ "$lc" == *"cargo"*"xtask"*"security-review-exec"* ]]; then
            return 1
        fi
        # Flag if any status/check-run endpoint or write indicator is present
        if [[ "$lc" == *"statuses"* || "$lc" == *"check-runs"* \
           || "$lc" == *"-x post"* || "$lc" == *"-x "* \
           || "$lc" == *"post"* \
           || "$lc" == *" -f "* || "$lc" == *" --field "* \
           || "$lc" == *" --method "* \
           || "$lc" == *"gh"*"api"* || "$lc" == *"curl"* ]]; then
            return 0  # violation: ai-review/security with write context
        fi
    fi

    # Rule 3: gh api / curl to statuses or check-runs without any ai-review
    # context specified is a violation (unknown context).
    # Exception: lines exclusively targeting ai-review/code-quality are permitted.
    if [[ "$lc" == *"statuses/"* || "$lc" == *"check-runs"* ]]; then
        # Only check lines that use an HTTP client (gh api or curl)
        if [[ "$lc" == *"gh"*"api"* || "$lc" == *"curl"* ]]; then
            if [[ "$lc" == *"ai-review/code-quality"* ]] && [[ "$lc" != *"ai-review/security"* ]]; then
                return 1  # permitted: exclusively code-quality
            fi
            # Already handled security context above in Rule 2, but if it
            # somehow reaches here (e.g. no ai-review context at all), flag it.
            return 0  # violation: unknown or unspecified context
        fi
    fi

    return 1
}

# Also detect cross-category misuse: code-quality prompts must NOT invoke
# security-review-exec (which writes ai-review/security status).
detect_cross_category_exec() {
    local line="$1"
    local file_basename="$2"
    local stripped="${line#"${line%%[![:space:]]*}"}"
    if [[ "$stripped" == "#"* ]]; then
        return 1
    fi
    # CODE_QUALITY prompt must not use security-review-exec
    if [[ "$file_basename" == *"CODE_QUALITY"* ]] && [[ "$line" == *"security-review-exec"* ]]; then
        return 0
    fi
    return 1
}

# join_continuations: read a file and join backslash-continuation lines into
# single logical lines, emitting "original_line_number<TAB>joined_line" for
# each logical line (line_number is where the logical line starts).
join_continuations() {
    local file="$1"
    local accum=""
    local start_num=0
    local num=0
    while IFS= read -r raw || [[ -n "$raw" ]]; do
        num=$((num + 1))
        if [[ -z "$accum" ]]; then
            start_num=$num
        fi
        # Check for trailing backslash (continuation)
        if [[ "$raw" == *'\' ]]; then
            # Strip trailing backslash and accumulate
            accum="${accum}${raw%\\} "
        else
            accum="${accum}${raw}"
            printf '%d\t%s\n' "$start_num" "$accum"
            accum=""
        fi
    done < "$file"
    # Flush any remaining accumulation (file ending with backslash)
    if [[ -n "$accum" ]]; then
        printf '%d\t%s\n' "$start_num" "$accum"
    fi
}

# Primary gate (broad text search): reject any review artifact containing the
# literal string "ai-review/security" UNLESS it is the security review prompt
# itself.  This catches variable indirection, split-line assignments, and any
# other encoding that still contains the literal context name.
# Comment lines (starting with #) are excluded.
log_info "Primary gate: scanning for ai-review/security literal in non-exempt files..."

check_file_for_security_literal() {
    local file="$1"
    local file_basename="$2"
    # The SECURITY_REVIEW_PROMPT.md is the only file permitted to reference
    # the ai-review/security context name.
    if [[ "$file_basename" == "SECURITY_REVIEW_PROMPT.md" ]]; then
        return 1
    fi
    local line_num=0
    while IFS= read -r raw_line; do
        line_num=$((line_num + 1))
        # Skip empty lines
        [[ -z "$raw_line" ]] && continue
        # Skip comment lines (leading whitespace then #)
        local stripped="${raw_line#"${raw_line%%[![:space:]]*}"}"
        [[ "$stripped" == "#"* ]] && continue
        # Case-insensitive check for the literal context string
        local lc="${raw_line,,}"
        if [[ "$lc" == *"ai-review/security"* ]]; then
            log_error "Forbidden ai-review/security literal in non-exempt review artifact:"
            log_error "  ${file}:${line_num}: ${raw_line}"
            log_error "  Only SECURITY_REVIEW_PROMPT.md may reference this context."
            return 0
        fi
    done < "$file"
    return 1
}

while IFS= read -r review_file; do
    file_basename="$(basename "$review_file")"
    if check_file_for_security_literal "$review_file" "$file_basename"; then
        VIOLATIONS=1
    fi
done < <(find "$REVIEW_DIR" -type f \( -name '*.md' -o -name '*.sh' -o -name '*.yaml' -o -name '*.yml' \) 2>/dev/null)

# Defense-in-depth: per-line pattern detection via continuation-joined lines.
# Scan every file in the review directory for direct status writes.
log_info "Defense-in-depth: checking per-line status-write patterns..."
while IFS= read -r review_file; do
    file_basename="$(basename "$review_file")"
    # Process with continuation-joining so multiline commands are caught
    while IFS=$'\t' read -r line_num logical_line; do
        if detect_direct_status_write "$logical_line"; then
            log_error "Deprecated direct status-write bypassing review gate:"
            log_error "  ${review_file}:${line_num}: ${logical_line}"
            log_error "  Use 'cargo xtask security-review-exec (approve|deny)' instead."
            VIOLATIONS=1
        fi
        if detect_cross_category_exec "$logical_line" "$file_basename"; then
            log_error "Cross-category executor misuse:"
            log_error "  ${review_file}:${line_num}: ${logical_line}"
            log_error "  CODE_QUALITY prompt must not invoke security-review-exec (writes ai-review/security context)."
            VIOLATIONS=1
        fi
    done < <(join_continuations "$review_file")
done < <(find "$REVIEW_DIR" -type f \( -name '*.md' -o -name '*.sh' -o -name '*.yaml' -o -name '*.yml' \) 2>/dev/null)

# Check 2: Review prompt metadata templates must require head_sha and pr_number binding.
# Both CODE_QUALITY_PROMPT.md and SECURITY_REVIEW_PROMPT.md must contain
# metadata block constraints that enforce SHA pinning.
log_info "Checking review prompt metadata SHA-pinning constraints..."

REVIEW_PROMPTS=(
    "${REVIEW_DIR}/CODE_QUALITY_PROMPT.md"
    "${REVIEW_DIR}/SECURITY_REVIEW_PROMPT.md"
)

for prompt_file in "${REVIEW_PROMPTS[@]}"; do
    if [[ ! -f "$prompt_file" ]]; then
        log_warn "Review prompt not found: ${prompt_file}"
        continue
    fi

    # Verify the metadata template contains head_sha field AND exact-binding constraint
    if ! grep -q '"head_sha"' "$prompt_file" 2>/dev/null; then
        log_error "Review prompt ${prompt_file} missing head_sha metadata field"
        VIOLATIONS=1
    fi
    if ! grep -q 'head_sha.*MUST.*equal\|head_sha.*MUST.*reviewed_sha\|head_sha.*equal.*reviewed_sha' "$prompt_file" 2>/dev/null; then
        log_error "Review prompt ${prompt_file} missing exact-binding constraint for head_sha (must require equality to reviewed_sha)"
        VIOLATIONS=1
    fi

    # Verify the metadata template contains pr_number field AND exact-binding constraint
    if ! grep -q '"pr_number"' "$prompt_file" 2>/dev/null; then
        log_error "Review prompt ${prompt_file} missing pr_number metadata field"
        VIOLATIONS=1
    fi
    if ! grep -q 'pr_number.*MUST.*equal\|pr_number.*MUST.*match\|pr_number.*exact' "$prompt_file" 2>/dev/null; then
        log_error "Review prompt ${prompt_file} missing exact-binding constraint for pr_number (must require exact match)"
        VIOLATIONS=1
    fi

    # Verify reviewed_sha is assigned from headRefOid
    if ! grep -q 'reviewed_sha.*headRefOid\|Set reviewed_sha = headRefOid' "$prompt_file" 2>/dev/null; then
        log_error "Review prompt ${prompt_file} does not bind reviewed_sha to headRefOid"
        VIOLATIONS=1
    fi

    log_info "  ${prompt_file}: metadata constraints present"
done

# Check 3: trusted-reviewers.json must exist and be valid JSON
log_info "Checking trusted-reviewers.json integrity..."
TRUSTED_REVIEWERS="${REVIEW_GATE_DIR}/trusted-reviewers.json"
if [[ ! -f "$TRUSTED_REVIEWERS" ]]; then
    log_error "Missing trusted-reviewers.json at ${TRUSTED_REVIEWERS}"
    VIOLATIONS=1
else
    if ! python3 -c "import json; json.load(open('${TRUSTED_REVIEWERS}'))" 2>/dev/null; then
        log_error "Invalid JSON in ${TRUSTED_REVIEWERS}"
        VIOLATIONS=1
    else
        log_info "  ${TRUSTED_REVIEWERS}: valid JSON"
    fi
fi

echo
if [[ $VIOLATIONS -eq 1 ]]; then
    log_error "=== FAILED: Review artifact integrity violations found ==="
    exit 1
else
    log_info "=== PASSED: All review artifacts are compliant ==="
    exit 0
fi
