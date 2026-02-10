#!/usr/bin/env bash
# FAC workflow preflight authorization gate (TCK-00442).
#
# Enforces trusted workflow context before self-hosted FAC dispatch.
# Emits explicit decision lines in logs for each authorization check.

set -euo pipefail

event_name="${APM2_PREFLIGHT_EVENT_NAME:-${GITHUB_EVENT_NAME:-}}"
event_path="${APM2_PREFLIGHT_EVENT_PATH:-${GITHUB_EVENT_PATH:-}}"
repository="${APM2_PREFLIGHT_REPOSITORY:-${GITHUB_REPOSITORY:-}}"
actor="${APM2_PREFLIGHT_ACTOR:-${GITHUB_ACTOR:-unknown}}"
dispatch_ref="${APM2_PREFLIGHT_REF_NAME:-${GITHUB_REF_NAME:-}}"
policy_path="${APM2_PREFLIGHT_TRUST_POLICY_PATH:-.github/review-gate/workflow-trust-policy.json}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
credential_hardening_script="${APM2_PREFLIGHT_CREDENTIAL_HARDENING_SCRIPT:-${script_dir}/credential_hardening.sh}"

log_decision() {
    local check="$1"
    local decision="$2"
    shift 2
    echo "fac-preflight: check=${check} decision=${decision} $*"
}

deny() {
    local check="$1"
    local reason="$2"
    shift 2 || true
    log_decision "$check" "DENY" "reason=${reason} $*"
    log_decision "overall" "DENY" "reason=${reason}"
    exit 1
}

allow() {
    local check="$1"
    shift
    log_decision "$check" "ALLOW" "$*"
}

contains_exact() {
    local needle="$1"
    shift
    local candidate
    for candidate in "$@"; do
        if [[ "$candidate" == "$needle" ]]; then
            return 0
        fi
    done
    return 1
}

if [[ -z "$event_name" ]]; then
    deny "context" "missing_event_name"
fi
if [[ -z "$event_path" || ! -f "$event_path" ]]; then
    deny "context" "missing_event_path" "event_path=${event_path:-unset}"
fi
if [[ -z "$repository" ]]; then
    deny "context" "missing_repository"
fi
if [[ ! -f "$policy_path" ]]; then
    deny "policy" "missing_policy_file" "policy_path=${policy_path}"
fi

if ! jq -e '
    (.schema // "") == "apm2.fac_workflow_trust_policy.v1" and
    (.allowed_actor_associations | type == "array" and length > 0) and
    (.trusted_base_refs | type == "array" and length > 0) and
    (.trusted_fork_pr_numbers | type == "array") and
    (.trusted_fork_head_repositories | type == "array") and
    (.trusted_fork_labels | type == "array") and
    (.credential_posture | type == "object") and
    ((.credential_posture.projection_credential_source // "") == "github_token") and
    (.credential_posture.allow_personal_access_tokens == false) and
    (.credential_posture.allow_argv_credentials == false)
' "$policy_path" >/dev/null; then
    deny "policy" "invalid_policy_schema" "policy_path=${policy_path}"
fi

readarray -t allowed_associations < <(jq -r '.allowed_actor_associations[]' "$policy_path")
readarray -t trusted_base_refs < <(jq -r '.trusted_base_refs[]' "$policy_path")
readarray -t trusted_fork_pr_numbers < <(jq -r '.trusted_fork_pr_numbers[] | tostring' "$policy_path")
readarray -t trusted_fork_head_repositories < <(jq -r '.trusted_fork_head_repositories[]' "$policy_path")
readarray -t trusted_fork_labels < <(jq -r '.trusted_fork_labels[]' "$policy_path")
credential_source_policy="$(jq -r '.credential_posture.projection_credential_source // empty' "$policy_path")"
allow_pat_policy="$(jq -r '.credential_posture.allow_personal_access_tokens // empty' "$policy_path")"
allow_argv_policy="$(jq -r '.credential_posture.allow_argv_credentials // empty' "$policy_path")"

allow "credential_posture" "source=${credential_source_policy} allow_pat=${allow_pat_policy} allow_argv=${allow_argv_policy}"

if [[ ! -f "${credential_hardening_script}" ]]; then
    deny "credential_posture" "missing_credential_hardening_script" "path=${credential_hardening_script}"
fi

export APM2_FAC_CREDENTIAL_SOURCE="${APM2_FAC_CREDENTIAL_SOURCE:-${credential_source_policy}}"
export APM2_CREDENTIAL_HARDENING_STAGE="${APM2_CREDENTIAL_HARDENING_STAGE:-preflight}"
if ! "${credential_hardening_script}" runtime; then
    deny "credential_posture" "credential_runtime_check_failed"
fi
allow "credential_posture" "runtime_check=passed"

event_json="$(cat "$event_path")"
pr_json=""
pr_number=""

case "$event_name" in
    pull_request_target)
        pr_json="$(jq -c '.pull_request // empty' <<<"$event_json")"
        [[ -n "$pr_json" ]] || deny "context" "missing_pull_request_payload"
        pr_number="$(jq -r '.number // empty' <<<"$pr_json")"
        ;;
    workflow_dispatch)
        pr_number="$(jq -r '.inputs.pr_number // .client_payload.pr_number // empty' <<<"$event_json")"
        if [[ -z "$pr_number" ]]; then
            deny "context" "workflow_dispatch_missing_pr_number"
        fi

        if [[ -n "${APM2_PREFLIGHT_PR_JSON_PATH:-}" ]]; then
            if [[ ! -f "${APM2_PREFLIGHT_PR_JSON_PATH}" ]]; then
                deny "context" "missing_pr_json_override" "path=${APM2_PREFLIGHT_PR_JSON_PATH}"
            fi
            pr_json="$(cat "${APM2_PREFLIGHT_PR_JSON_PATH}")"
        else
            pr_json="$(gh api "repos/${repository}/pulls/${pr_number}" 2>/dev/null || true)"
        fi

        if [[ -z "$pr_json" ]]; then
            deny "context" "workflow_dispatch_pr_lookup_failed" "pr=${pr_number}"
        fi
        ;;
    *)
        deny "context" "unsupported_event" "event=${event_name}"
        ;;
esac

if [[ ! "$pr_number" =~ ^[0-9]+$ ]]; then
    deny "context" "invalid_pr_number" "pr=${pr_number}"
fi

# Allow fixture or caller overrides to pass either a pull_request object
# directly or an event-shaped object with .pull_request embedded.
if jq -e '.pull_request? | type == "object"' <<<"$pr_json" >/dev/null; then
    pr_json="$(jq -c '.pull_request' <<<"$pr_json")"
fi

pr_state="$(jq -r '.state // "open"' <<<"$pr_json")"
if [[ "$pr_state" != "open" ]]; then
    deny "pr_state" "pr_not_open" "pr=${pr_number} state=${pr_state}"
fi
allow "pr_state" "pr=${pr_number} state=${pr_state}"

author_association="$(jq -r '.author_association // empty' <<<"$pr_json")"
if [[ -z "$author_association" ]]; then
    deny "actor_association" "missing_author_association" "pr=${pr_number}"
fi
if contains_exact "$author_association" "${allowed_associations[@]}"; then
    allow "actor_association" "pr=${pr_number} association=${author_association}"
else
    deny "actor_association" "unauthorized_author_association" "pr=${pr_number} association=${author_association}"
fi

base_ref="$(jq -r '.base.ref // empty' <<<"$pr_json")"
if [[ -z "$base_ref" ]]; then
    deny "base_ref" "missing_base_ref" "pr=${pr_number}"
fi
if contains_exact "$base_ref" "${trusted_base_refs[@]}"; then
    allow "base_ref" "pr=${pr_number} base_ref=${base_ref}"
else
    deny "base_ref" "untrusted_base_ref" "pr=${pr_number} base_ref=${base_ref}"
fi

if [[ "$event_name" == "workflow_dispatch" ]]; then
    if [[ -z "$dispatch_ref" ]]; then
        deny "dispatch_ref" "missing_dispatch_ref"
    fi
    if contains_exact "$dispatch_ref" "${trusted_base_refs[@]}"; then
        allow "dispatch_ref" "ref=${dispatch_ref}"
    else
        deny "dispatch_ref" "untrusted_dispatch_ref" "ref=${dispatch_ref}"
    fi

    permission="${APM2_PREFLIGHT_ACTOR_PERMISSION:-}"
    if [[ -z "$permission" ]]; then
        permission="$(gh api "repos/${repository}/collaborators/${actor}/permission" --jq '.permission // empty' 2>/dev/null || true)"
    fi
    case "$permission" in
        admin|maintain|write)
            allow "dispatch_actor" "actor=${actor} permission=${permission}"
            ;;
        *)
            deny "dispatch_actor" "insufficient_actor_permission" "actor=${actor} permission=${permission:-none}"
            ;;
    esac
fi

head_repo_full_name="$(jq -r '.head.repo.full_name // empty' <<<"$pr_json")"
base_repo_full_name="$(jq -r '.base.repo.full_name // empty' <<<"$pr_json")"
head_repo_fork="$(jq -r '.head.repo.fork // empty' <<<"$pr_json")"

if [[ -z "$head_repo_full_name" || -z "$base_repo_full_name" ]]; then
    deny "fork_context" "missing_repo_identity" "head_repo=${head_repo_full_name:-missing} base_repo=${base_repo_full_name:-missing}"
fi

case "$head_repo_fork" in
    true|false)
        is_fork="$head_repo_fork"
        ;;
    "")
        if [[ "$head_repo_full_name" != "$base_repo_full_name" ]]; then
            is_fork="true"
        else
            is_fork="false"
        fi
        ;;
    *)
        deny "fork_context" "ambiguous_fork_flag" "fork=${head_repo_fork}"
        ;;
esac

if [[ "$head_repo_full_name" != "$base_repo_full_name" ]]; then
    is_fork="true"
fi

if [[ "$is_fork" == "true" ]]; then
    trust_grant=""

    if contains_exact "$pr_number" "${trusted_fork_pr_numbers[@]}"; then
        trust_grant="policy:pr_number"
    fi

    if [[ -z "$trust_grant" ]] && contains_exact "$head_repo_full_name" "${trusted_fork_head_repositories[@]}"; then
        trust_grant="policy:head_repo"
    fi

    if [[ -z "$trust_grant" ]]; then
        readarray -t pr_labels < <(jq -r '.labels[]?.name // empty' <<<"$pr_json")
        label=""
        for label in "${pr_labels[@]}"; do
            if contains_exact "$label" "${trusted_fork_labels[@]}"; then
                trust_grant="label:${label}"
                break
            fi
        done
    fi

    if [[ -z "$trust_grant" ]]; then
        deny "fork_trust" "fork_without_trust_grant" "pr=${pr_number} head_repo=${head_repo_full_name}"
    fi

    allow "fork_trust" "pr=${pr_number} fork=true trust_grant=${trust_grant}"
else
    allow "fork_trust" "pr=${pr_number} fork=false"
fi

allow "overall" "event=${event_name} pr=${pr_number} actor=${actor} association=${author_association} base_ref=${base_ref} fork=${is_fork}"
exit 0
