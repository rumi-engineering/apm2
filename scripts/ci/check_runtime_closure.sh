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

resolve_review_head_sha() {
    local requested_head resolved_head
    requested_head="${APM2_REVIEW_HEAD_SHA:-${GITHUB_SHA:-HEAD}}"
    if resolved_head="$(git rev-parse --verify "${requested_head}^{commit}" 2>/dev/null)"; then
        echo "${resolved_head}"
    else
        git rev-parse --verify HEAD^{commit}
    fi
}

detect_current_pr_number() {
    local value
    for value in "${APM2_PR_NUMBER:-}" "${PR_NUMBER:-}"; do
        if [[ "${value}" =~ ^[0-9]+$ ]]; then
            echo "${value}"
            return 0
        fi
    done

    if [[ "${GITHUB_REF:-}" =~ ^refs/pull/([0-9]+)/ ]]; then
        echo "${BASH_REMATCH[1]}"
        return 0
    fi

    if [[ -n "${GITHUB_EVENT_PATH:-}" && -f "${GITHUB_EVENT_PATH}" ]]; then
        python3 - "${GITHUB_EVENT_PATH}" <<'PY'
import json
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
try:
    payload = json.loads(path.read_text(encoding="utf-8"))
except Exception:
    sys.exit(0)

pr = payload.get("pull_request") if isinstance(payload, dict) else None
if isinstance(pr, dict):
    number = pr.get("number")
    if number is not None and re.fullmatch(r"\d+", str(number)):
        print(number)
PY
        return 0
    fi

    return 1
}

collect_current_pr_categories() {
    local value raw_buffer label_buffer
    raw_buffer=""

    for value in \
        "${APM2_PR_CATEGORY:-}" \
        "${PR_CATEGORY:-}" \
        "${APM2_PR_CATEGORIES:-}" \
        "${PR_CATEGORIES:-}" \
        "${APM2_PR_LABELS:-}" \
        "${PR_LABELS:-}"; do
        if [[ -n "${value}" ]]; then
            raw_buffer+="${value}"$'\n'
        fi
    done

    if [[ "${security_qcp}" == "YES" || "${security_qcp}" == "TRUE" || "${security_qcp}" == "1" ]]; then
        raw_buffer+=$'SECURITY\nQCP=YES\nSECURITY/QCP=YES\n'
    fi

    if [[ -n "${GITHUB_EVENT_PATH:-}" && -f "${GITHUB_EVENT_PATH}" ]]; then
        label_buffer="$(python3 - "${GITHUB_EVENT_PATH}" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
try:
    payload = json.loads(path.read_text(encoding="utf-8"))
except Exception:
    sys.exit(0)

pull_request = payload.get("pull_request") if isinstance(payload, dict) else None
if not isinstance(pull_request, dict):
    sys.exit(0)

labels = pull_request.get("labels")
if not isinstance(labels, list):
    sys.exit(0)

for label in labels:
    if isinstance(label, dict):
        name = label.get("name")
        if isinstance(name, str):
            print(name)
PY
)"
        if [[ -n "${label_buffer}" ]]; then
            raw_buffer+="${label_buffer}"$'\n'
        fi
    fi

    printf '%s' "${raw_buffer}" \
        | tr ',;' '\n' \
        | awk '
            {
                line = $0
                gsub(/^[[:space:]]+/, "", line)
                gsub(/[[:space:]]+$/, "", line)
                if (length(line) > 0) {
                    print toupper(line)
                }
            }
        ' \
        | sort -u
}

is_waiver_only_commit() {
    local commit_path file_path
    commit_path="$1"

    if ! git rev-parse --verify "${commit_path}^1" >/dev/null 2>&1; then
        return 1
    fi

    mapfile -t changed_commit_files < <(git diff --name-only "${commit_path}^1..${commit_path}")
    if [[ ${#changed_commit_files[@]} -eq 0 ]]; then
        return 1
    fi

    for file_path in "${changed_commit_files[@]}"; do
        if [[ "${file_path}" != documents/work/waivers/* ]]; then
            return 1
        fi
    done

    return 0
}

validate_waiver_binding() {
    local waiver_file output
    waiver_file="$1"

    if output="$(
        python3 - "${waiver_file}" "${ALLOWED_WAIVER_COMMITS_CSV}" "${CURRENT_PR_NUMBER}" "${CURRENT_PR_CATEGORIES_CSV}" "${REVIEW_HEAD_PARENT_SHA}" "${REVIEW_HEAD_IS_WAIVER_ONLY}" <<'PY'
import re
import sys

import yaml


def fail(message: str) -> None:
    print(message)
    raise SystemExit(1)


def normalize_category(value) -> str:
    text = str(value)
    normalized = " ".join(text.strip().upper().split())
    return normalized


waiver_path = sys.argv[1]
allowed_commits = {
    item.strip().lower()
    for item in sys.argv[2].split(",")
    if item.strip()
}
current_pr_number = sys.argv[3].strip()
current_categories = {
    normalize_category(item)
    for item in sys.argv[4].split(",")
    if item.strip()
}
review_head_parent_sha = sys.argv[5].strip().lower()
review_head_is_waiver_only = sys.argv[6].strip().lower() == "yes"

with open(waiver_path, "r", encoding="utf-8") as handle:
    payload = yaml.safe_load(handle) or {}

if not isinstance(payload, dict):
    fail("waiver document must be a YAML mapping")

waiver = payload.get("waiver", payload)
if not isinstance(waiver, dict):
    fail("waiver payload is malformed")

references = waiver.get("references", {})
if not isinstance(references, dict):
    fail("waiver references block is malformed")

commit_sha = references.get("commit_sha")
if not isinstance(commit_sha, str) or not commit_sha.strip():
    fail("missing required references.commit_sha")
commit_sha = commit_sha.strip().lower()
if not re.fullmatch(r"[0-9a-f]{40}", commit_sha):
    fail("references.commit_sha must be a full 40-hex commit SHA")
if commit_sha not in allowed_commits:
    fail("references.commit_sha does not match reviewed HEAD or first parent")
if (
    review_head_parent_sha
    and commit_sha == review_head_parent_sha
    and not review_head_is_waiver_only
):
    fail("parent_sha_waiver_requires_waiver_only_head_commit")

reference_pr_number = references.get("pr_number")
if reference_pr_number is not None:
    reference_pr_number = str(reference_pr_number).strip()
    if not re.fullmatch(r"\d+", reference_pr_number):
        fail("references.pr_number must be numeric")
else:
    reference_pr_number = ""

pr_url = references.get("pr_url")
pr_number_from_url = ""
if isinstance(pr_url, str) and pr_url.strip():
    match = re.search(r"/pull/(\d+)(?:[/?#]|$)", pr_url.strip())
    if match:
        pr_number_from_url = match.group(1)

if reference_pr_number and pr_number_from_url and reference_pr_number != pr_number_from_url:
    fail("references.pr_number does not match PR number encoded in references.pr_url")

effective_pr_number = reference_pr_number or pr_number_from_url
if effective_pr_number:
    if not current_pr_number:
        fail("waiver is PR-bound but current PR number is unavailable")
    if effective_pr_number != current_pr_number:
        fail(
            f"waiver PR binding mismatch (expected PR #{effective_pr_number}, got #{current_pr_number})"
        )

category_values = []
for source in (references, waiver):
    for key in ("category", "pr_category", "categories", "pr_categories"):
        if key not in source:
            continue
        raw = source[key]
        if isinstance(raw, list):
            category_values.extend(raw)
        else:
            category_values.append(raw)

normalized_required_categories = []
for value in category_values:
    if isinstance(value, str):
        split_values = [segment for segment in re.split(r"[,;]", value) if segment.strip()]
        if split_values:
            normalized_required_categories.extend(
                normalize_category(segment) for segment in split_values
            )
            continue
    normalized = normalize_category(value)
    if normalized:
        normalized_required_categories.append(normalized)

if normalized_required_categories:
    if not current_categories:
        fail("waiver category binding present but current PR categories are unavailable")
    missing = [
        category
        for category in normalized_required_categories
        if category not in current_categories
    ]
    if missing:
        fail(
            "waiver category binding mismatch (missing current categories: "
            + ", ".join(missing)
            + ")"
        )

print("ok")
PY
    )"; then
        return 0
    fi

    log_warn "rejecting waiver ${waiver_file}: ${output}"
    return 1
}

REVIEW_HEAD_SHA="$(resolve_review_head_sha)"
REVIEW_HEAD_PARENT_SHA="$(git rev-parse --verify "${REVIEW_HEAD_SHA}^1" 2>/dev/null || true)"
REVIEW_HEAD_IS_WAIVER_ONLY="no"
if [[ -n "${REVIEW_HEAD_PARENT_SHA}" ]] && is_waiver_only_commit "${REVIEW_HEAD_SHA}"; then
    REVIEW_HEAD_IS_WAIVER_ONLY="yes"
fi

declare -a ALLOWED_WAIVER_COMMITS=("${REVIEW_HEAD_SHA}")
if [[ -n "${REVIEW_HEAD_PARENT_SHA}" ]]; then
    ALLOWED_WAIVER_COMMITS+=("${REVIEW_HEAD_PARENT_SHA}")
fi
ALLOWED_WAIVER_COMMITS_CSV="$(IFS=,; echo "${ALLOWED_WAIVER_COMMITS[*]}")"

CURRENT_PR_NUMBER="$(detect_current_pr_number || true)"
mapfile -t CURRENT_PR_CATEGORIES < <(collect_current_pr_categories)
CURRENT_PR_CATEGORIES_CSV="$(IFS=,; echo "${CURRENT_PR_CATEGORIES[*]}")"

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

        if ! validate_waiver_binding "${waiver_file}"; then
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
