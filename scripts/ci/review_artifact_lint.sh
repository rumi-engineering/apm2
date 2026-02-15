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

# WVR-0004: Defense-in-depth scope limitation
#
# This lint catches common/accidental direct GitHub status writes in review
# artifacts. It is NOT designed to resist adversarial bypass via string
# construction techniques (variable indirection, token splitting, eval,
# process substitution, base64 encoding, etc.).
#
# The hard security gate for review status integrity is the `Review Gate Success`
# commit status context posted by the authorized CI workflow (see
# `.github/workflows/review-gate.yml`), which evaluates machine-readable comment
# artifacts via the Forge Admission Cycle workflow.
#
# Threat model: Review artifacts are authored by trusted CI processes
# (codex reviewers, apm2 fac commands) running in controlled environments.
# An adversary who can modify review artifacts already has CI write access
# and can bypass any shell-level lint. The lint's value is catching
# copy-paste mistakes and accidental regressions, not adversarial bypass.
#
# Waiver: Remaining bypass vectors in pattern matching (split-token
# construction, variable indirection in exempt files) are accepted as
# out-of-scope for this defense-in-depth control.
# See: TCK-00409, review rounds 1-13

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

# Check 1: Review artifacts must not contain direct GitHub API calls.
#
# ALLOWLIST/PROHIBITION APPROACH (TCK-00409 hardening):
# Instead of trying to enumerate all bad patterns (denylist — impossible to
# be exhaustive against token-splitting, variable indirection, etc.), we
# PROHIBIT all direct GitHub API calls in review artifacts.
#
# The approved paths are:
#   - apm2 fac restart — for triggering reviews
#   - apm2 fac review — for review operations
#
# KNOWN-GOOD LINE ALLOWLIST (replaces blanket file exemption):
#   The CAC JSON prompt files use `apm2 fac review` commands exclusively.
#   No review artifact should contain direct gh api calls.
#
# Similarly, `gh pr review --approve` bypasses the review gate and is always
# forbidden in all review artifacts (no exemptions).
log_info "Checking for forbidden direct GitHub API calls in review artifacts..."

# strip_comments: Remove comment lines from file content.
# For .md files: lines starting with optional whitespace then # in code blocks
# For .sh files: lines starting with optional whitespace then #
# For all files: we strip lines where the first non-whitespace char is #
# This is intentionally conservative — inline comments after code are kept,
# which is fine because we want to catch code, not miss it.
strip_comments() {
    local content="$1"
    # Remove lines that are purely comments (first non-whitespace is #)
    echo "$content" | grep -v '^[[:space:]]*#' || true
}

# flatten_stream: Remove newlines and collapse whitespace to produce a single
# character stream.  This defeats line-splitting bypasses entirely.
flatten_stream() {
    local content="$1"
    # Replace newlines with spaces, then collapse multiple spaces.
    # Use sed/awk instead of tr for portability (some systems have
    # non-standard tr implementations).
    printf '%s' "$content" | awk '{printf "%s ", $0}' | sed 's/  */ /g'
}

# detect_forbidden_api_usage: FILE-LEVEL check for forbidden GitHub API calls.
# Takes a file path and basename.  Returns 0 (true) if the file is a violation.
#
# Strategy: strip comments, flatten to a single stream, check for ANY of:
#   - "gh" followed by whitespace then "api" (catches gh api, gh  api, etc.)
#   - "gh" followed by whitespace then "pr" ... "review" ... "--approve"
#   - "curl" combined with "github" or "api.github"
#
# This is an ALLOWLIST approach: review artifacts should NEVER call GitHub
# APIs directly.  The only sanctioned paths are apm2 fac commands.
detect_forbidden_api_usage() {
    local file="$1"
    local file_basename="$2"

    # Read file, strip comments
    local content
    content="$(cat "$file")"
    local stripped
    stripped="$(strip_comments "$content")"

    # Flatten to stream, lowercase
    local stream
    stream="$(flatten_stream "$stripped")"
    local lc="${stream,,}"

    # Rule 1: Forbid "gh pr review --approve" (always, no exemptions)
    # Check on the flattened lowercase stream
    if [[ "$lc" == *"gh"*"pr"*"review"*"--approve"* ]]; then
        log_error "Forbidden gh pr review --approve in review artifact:"
        log_error "  ${file}"
        log_error "  gh pr review --approve bypasses the review gate."
        return 0
    fi

    # Rule 2: Forbid ANY "gh api" call
    # Match "gh" followed by any amount of whitespace then "api"
    # On the flattened stream, whitespace is already collapsed to single spaces
    if [[ "$lc" == *"gh api"* ]] || [[ "$lc" == *"gh  api"* ]]; then
        log_error "Forbidden gh api call in review artifact:"
        log_error "  ${file}"
        log_error "  Review artifacts must not call gh api directly."
        log_error "  Use 'apm2 fac restart' instead."
        return 0
    fi

    # Rule 3: Forbid "curl" combined with GitHub API indicators
    if [[ "$lc" == *"curl"* ]]; then
        if [[ "$lc" == *"github"* ]] || [[ "$lc" == *"api.github"* ]]; then
            log_error "Forbidden curl-to-GitHub call in review artifact:"
            log_error "  ${file}"
            log_error "  Review artifacts must not call GitHub APIs via curl."
            log_error "  Use 'apm2 fac restart' instead."
            return 0
        fi
    fi

    return 1
}

# detect_direct_status_write: LEGACY per-line check, kept as defense-in-depth.
# Now also uses the prohibition approach: any line containing "gh api" or
# "curl" + "github" in a non-exempt context is a violation.
# Returns 0 (true) if the line is a violation.
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

    # Rule 2: ANY "gh api" call is forbidden (allowlist approach).
    # On a single line, match gh followed by whitespace then api.
    if [[ "$lc" =~ gh[[:space:]]+api ]]; then
        return 0
    fi

    # Rule 3: ANY "curl" + "github" combination is forbidden.
    if [[ "$lc" == *"curl"* ]] && [[ "$lc" == *"github"* || "$lc" == *"api.github"* ]]; then
        return 0
    fi

    # Rule 4: ANY reference to statuses/ or check-runs with a write indicator
    # (catches variable-indirected endpoint construction)
    if [[ "$lc" == *"statuses/"* || "$lc" == *"check-runs"* ]]; then
        if [[ "$lc" == *"-f "* || "$lc" == *"--field "* || "$lc" == *"--method"* \
           || "$lc" == *"-x post"* || "$lc" == *"post"* ]]; then
            return 0
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

# Primary gate: reject any review artifact containing the literal string
# "ai-review/security" UNLESS it is the security review prompt itself.
#
# STREAM-LEVEL ANALYSIS (TCK-00409 hardening):
# Instead of line-by-line grep, we strip comments and flatten the entire file
# into a single character stream, then check for the literal.  This defeats
# line-splitting bypasses where the literal is constructed across multiple
# lines or variable assignments.
#
# Additionally, we check for the COMPONENTS "ai-review" and "/security" as
# separate tokens that could be concatenated at runtime.  If both appear in
# non-comment code, that's suspicious enough to flag (defense-in-depth).
log_info "Primary gate: scanning for ai-review/security literal in non-exempt files..."

check_file_for_security_literal() {
    local file="$1"
    local file_basename="$2"
    # SECURITY_REVIEW_PROMPT is permitted to reference the security context.
    if [[ "$file_basename" == "SECURITY_REVIEW_PROMPT.cac.json" ]]; then
        return 1
    fi
    # CODE_QUALITY_PROMPT is a canonical controlled file that legitimately
    # references "ai-review/code-quality" (containing the "ai-review" substring)
    # and discusses security concepts in prose.  It is exempt from the
    # split-token heuristic but NOT from the direct literal check (Check 1
    # below still applies — if it ever contains "ai-review/security" literally,
    # that would be caught).
    local exempt_from_split_token=0
    if [[ "$file_basename" == "CODE_QUALITY_PROMPT.cac.json" ]]; then
        exempt_from_split_token=1
    fi

    # Read file, strip comments, flatten to character stream
    local content
    content="$(cat "$file")"
    local stripped
    stripped="$(strip_comments "$content")"
    local stream
    stream="$(flatten_stream "$stripped")"
    local lc="${stream,,}"

    # Check 1: Direct literal "ai-review/security" in the flattened stream
    if [[ "$lc" == *"ai-review/security"* ]]; then
        local match_info
        match_info=$(grep -ni 'ai-review/security' "$file" | head -1 || echo "(found in flattened stream)")
        log_error "Forbidden ai-review/security literal in non-exempt review artifact:"
        log_error "  ${file}: ${match_info}"
        log_error "  Only SECURITY_REVIEW_PROMPT.cac.json may reference this context."
        return 0
    fi

    # Check 2 (defense-in-depth): Components "ai-review" AND "security" both
    # present in non-comment code.  This catches split-token construction like:
    #   ctx_a="ai-review"; ctx_b="security"; ctx="${ctx_a}/${ctx_b}"
    # where the full literal never appears but both halves do.
    # Note: this is intentionally broad — review artifacts other than the
    # security prompt have no legitimate reason to reference both tokens.
    # Canonical prompt files may be exempt (they reference ai-review/code-quality
    # and discuss security in prose, which is a known-good false positive).
    if [[ $exempt_from_split_token -eq 0 ]] && [[ "$lc" == *"ai-review"* ]] && [[ "$lc" == *"security"* ]]; then
        # Verify this isn't just documentation mentioning "security review"
        # generically — check for assignment/variable patterns or quotes around
        # the tokens, which indicate code, not prose.
        # We flag if "ai-review" appears in a code-like context (quoted, assigned)
        if [[ "$lc" == *'"ai-review'* ]] || [[ "$lc" == *"'ai-review"* ]] \
           || [[ "$lc" == *'=ai-review'* ]] || [[ "$lc" == *'="ai-review'* ]] \
           || [[ "$lc" == *"='ai-review"* ]]; then
            log_error "Suspicious ai-review + security component tokens in non-exempt review artifact:"
            log_error "  ${file}"
            log_error "  Both 'ai-review' and 'security' appear in code context."
            log_error "  This may be split-token construction of the forbidden context."
            log_error "  Only SECURITY_REVIEW_PROMPT.cac.json may reference the security context."
            return 0
        fi
    fi

    return 1
}

while IFS= read -r review_file; do
    file_basename="$(basename "$review_file")"

    # Gate 1: security-literal check (stream-level)
    if check_file_for_security_literal "$review_file" "$file_basename"; then
        VIOLATIONS=1
    fi

    # Gate 2: forbidden API usage check (file-level, stream-based)
    if detect_forbidden_api_usage "$review_file" "$file_basename"; then
        VIOLATIONS=1
    fi

done < <(find "$REVIEW_DIR" -type f \( -name '*.md' -o -name '*.sh' -o -name '*.yaml' -o -name '*.yml' -o -name '*PROMPT*.json' \) 2>/dev/null)

# Defense-in-depth: per-line pattern detection via continuation-joined lines.
# This catches patterns even if the file-level check somehow missed them.
# Uses the prohibition approach: any gh api or curl-to-GitHub is forbidden.
log_info "Defense-in-depth: per-line prohibition check..."
while IFS= read -r review_file; do
    file_basename="$(basename "$review_file")"
    # Process with continuation-joining so multiline commands are caught
    while IFS=$'\t' read -r line_num logical_line; do
        if detect_direct_status_write "$logical_line"; then
            log_error "Forbidden direct GitHub API call in review artifact:"
            log_error "  ${review_file}:${line_num}: ${logical_line}"
            log_error "  Use 'apm2 fac restart' instead."
            VIOLATIONS=1
        fi
        if detect_cross_category_exec "$logical_line" "$file_basename"; then
            log_error "Cross-category executor misuse:"
            log_error "  ${review_file}:${line_num}: ${logical_line}"
            log_error "  CODE_QUALITY prompt must not invoke security-review-exec (writes ai-review/security context)."
            VIOLATIONS=1
        fi
    done < <(join_continuations "$review_file")
done < <(find "$REVIEW_DIR" -type f \( -name '*.md' -o -name '*.sh' -o -name '*.yaml' -o -name '*.yml' -o -name '*PROMPT*.json' \) 2>/dev/null)

# Check 2: Review prompts must enforce CLI-owned identity binding.
#
# TCK-00605 moved SHA/PR binding from prose metadata fields into deterministic
# Rust CLI behavior. Prompt artifacts now must prohibit manual --sha usage and
# require the canonical workspace-binary CLI command path.
log_info "Checking review prompt CLI identity-binding constraints..."

validate_prompt_identity_constraints() {
    local prompt_file="$1"
    python3 - "$prompt_file" <<'PY'
import json
import sys

path = sys.argv[1]

try:
    with open(path, "r", encoding="utf-8") as f:
        doc = json.load(f)
except Exception as exc:
    print(f"invalid JSON: {exc}")
    sys.exit(2)

errors = []
payload = doc.get("payload")
if not isinstance(payload, dict):
    errors.append("missing payload object")
    payload = {}

commands = payload.get("commands")
if not isinstance(commands, dict):
    errors.append("missing payload.commands object")
    commands = {}

constraints = payload.get("constraints")
if not isinstance(constraints, dict):
    errors.append("missing payload.constraints object")
    constraints = {}

expected_prefix = "cargo run -p apm2-cli --"
binary_prefix = commands.get("binary_prefix")
if binary_prefix != expected_prefix:
    errors.append("commands.binary_prefix must equal 'cargo run -p apm2-cli --'")

def require_command(name, prefix, must_include):
    cmd = commands.get(name)
    if not isinstance(cmd, str):
        errors.append(f"commands.{name} must be a string")
        return
    if not cmd.startswith(prefix):
        errors.append(f"commands.{name} must start with '{prefix}'")
    for token in must_include:
        if token not in cmd:
            errors.append(f"commands.{name} must include '{token}'")

require_command("prepare", f"{expected_prefix} fac review prepare", ("--json",))
require_command("finding", f"{expected_prefix} fac review finding", ("--json",))
require_command("verdict", f"{expected_prefix} fac review verdict set", ("--json",))

forbidden_ops = constraints.get("forbidden_operations")
if not isinstance(forbidden_ops, list):
    errors.append("constraints.forbidden_operations must be an array")
    forbidden_text = ""
else:
    forbidden_text = "\n".join(item.lower() for item in forbidden_ops if isinstance(item, str))

if "--sha" not in forbidden_text:
    errors.append("constraints.forbidden_operations must explicitly forbid --sha")
if "auto-derives the sha" not in forbidden_text and "sha is managed by the cli" not in forbidden_text:
    errors.append("constraints.forbidden_operations must declare CLI-managed SHA binding")

invariants = constraints.get("invariants")
invariant_text_fragments = []
if not isinstance(invariants, list):
    errors.append("constraints.invariants must be an array")
else:
    for item in invariants:
        if isinstance(item, str):
            invariant_text_fragments.append(item.lower())
        elif isinstance(item, dict):
            desc = item.get("description")
            if isinstance(desc, str):
                invariant_text_fragments.append(desc.lower())

invariant_text = "\n".join(invariant_text_fragments)
if "sha is managed by the cli" not in invariant_text:
    errors.append("constraints.invariants must include 'SHA is managed by the CLI'")

if errors:
    for err in errors:
        print(err)
    sys.exit(1)
PY
}

REVIEW_PROMPTS=(
    "${REVIEW_DIR}/CODE_QUALITY_PROMPT.cac.json"
    "${REVIEW_DIR}/SECURITY_REVIEW_PROMPT.cac.json"
)

for prompt_file in "${REVIEW_PROMPTS[@]}"; do
    if [[ ! -f "$prompt_file" ]]; then
        log_warn "Review prompt not found: ${prompt_file}"
        continue
    fi

    if prompt_check_output="$(validate_prompt_identity_constraints "$prompt_file" 2>&1)"; then
        log_info "  ${prompt_file}: CLI identity-binding constraints present"
        continue
    fi
    prompt_check_status=$?

    VIOLATIONS=1
    if [[ $prompt_check_status -eq 2 ]]; then
        log_error "Review prompt ${prompt_file} is not valid JSON"
        if [[ -n "$prompt_check_output" ]]; then
            while IFS= read -r line; do
                [[ -n "$line" ]] && log_error "  ${line}"
            done <<< "$prompt_check_output"
        fi
        continue
    fi

    while IFS= read -r line; do
        [[ -n "$line" ]] && log_error "Review prompt ${prompt_file}: ${line}"
    done <<< "$prompt_check_output"
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
