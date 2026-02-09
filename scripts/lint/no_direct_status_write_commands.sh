#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
VIOLATIONS=0

# Restrict scope to executable review prompts.
TARGET_FILES=(
    "$(find "$REPO_ROOT/documents/reviews" -type f -name '*.md' | sort)"
)

# Flatten array entries that may contain newlines from command substitution.
FILES=()
for entry in "${TARGET_FILES[@]}"; do
    while IFS= read -r file; do
        [[ -n "$file" ]] && FILES+=("$file")
    done <<<"$entry"
done

check_logical_line() {
    local file="$1"
    local line_no="$2"
    local line="$3"

    local trimmed="${line#"${line%%[![:space:]]*}"}"
    if [[ "$trimmed" == \#* ]]; then
        return
    fi

    local lc="${line,,}"

    # Fail-closed: flag ANY logical line that mentions both `gh` (as a word
    # boundary) and `/statuses/` regardless of quoting, backticks, flags, or
    # whitespace.  This catches every variant: `gh api`, `gh -R x api`,
    # backtick-wrapped, subshell-embedded, etc.  False positives in comments
    # are already filtered above (line 27).
    if [[ "$lc" =~ (^|[^a-z0-9_-])gh([^a-z0-9_-]|$) ]] && [[ "$lc" == *"/statuses/"* ]]; then
        local rel="${file#"$REPO_ROOT/"}"
        echo "::error file=$rel,line=$line_no::Direct GitHub status-write command string is forbidden in review prompts (TCK-00411)."
        VIOLATIONS=1
    fi
}

check_file() {
    local file="$1"
    local line_no=0
    local logical_start=0
    local logical_line=""

    while IFS= read -r raw || [[ -n "$raw" ]]; do
        line_no=$((line_no + 1))
        if [[ -z "$logical_line" ]]; then
            logical_start="$line_no"
        fi

        if [[ "$raw" == *\\ ]]; then
            logical_line+="${raw%\\} "
            continue
        fi

        logical_line+="$raw"
        check_logical_line "$file" "$logical_start" "$logical_line"
        logical_line=""
    done <"$file"

    if [[ -n "$logical_line" ]]; then
        check_logical_line "$file" "$logical_start" "$logical_line"
    fi
}

for file in "${FILES[@]}"; do
    check_file "$file"
done

if [[ "$VIOLATIONS" -ne 0 ]]; then
    echo "Found forbidden direct status-write command strings."
    exit 1
fi

echo "Status-write command lint passed."
