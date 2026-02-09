#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
TARGET_ROOT="$REPO_ROOT/documents/skills"

if [[ ! -d "$TARGET_ROOT" ]]; then
    echo "Lifecycle instruction lint failed: missing directory $TARGET_ROOT" >&2
    exit 1
fi

mapfile -t FILES < <(find "$TARGET_ROOT" -type f -name '*.md' | sort)

VIOLATIONS=0
MATCHES=0

command_pattern='cargo[[:space:]]+xtask[[:space:]]+(push|review|security-review-exec|commit|aat)([^[:alnum:]_-]|$)'

for file in "${FILES[@]}"; do
    mapfile -t lines <"$file"
    line_count="${#lines[@]}"

    for idx in "${!lines[@]}"; do
        line_no=$((idx + 1))
        line="${lines[$idx]}"

        trimmed="${line#"${line%%[![:space:]]*}"}"
        if [[ "$trimmed" == \#* ]]; then
            continue
        fi

        if [[ "$line" =~ $command_pattern ]]; then
            MATCHES=$((MATCHES + 1))

            start=$((line_no - 3))
            end=$((line_no + 3))
            if ((start < 1)); then
                start=1
            fi
            if ((end > line_count)); then
                end=$line_count
            fi

            annotated=0
            for ((window_line = start; window_line <= end; window_line++)); do
                context="${lines[$((window_line - 1))]}"
                context_lc="${context,,}"
                if [[ "$context_lc" == *"stage-2"* ]] || \
                   [[ "$context_lc" == *"tck-00419"* ]] || \
                   [[ "$context_lc" == *"projection-only"* ]] || \
                   [[ "$context_lc" == *"deprecated"* ]] || \
                   [[ "$context_lc" == *"demotion"* ]]; then
                    annotated=1
                    break
                fi
            done

            if ((annotated == 0)); then
                rel="${file#"$REPO_ROOT/"}"
                echo "::error file=$rel,line=$line_no::Lifecycle command reference requires Stage-2 demotion annotation (TCK-00419 / projection-only / deprecated / demotion)." >&2
                VIOLATIONS=$((VIOLATIONS + 1))
            fi
        fi
    done
done

if ((VIOLATIONS > 0)); then
    echo "Lifecycle instruction lint failed: $VIOLATIONS violation(s) across $MATCHES lifecycle command reference(s)." >&2
    exit 1
fi

echo "Lifecycle instruction lint passed: checked $MATCHES lifecycle command reference(s)."
