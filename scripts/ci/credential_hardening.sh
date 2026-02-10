#!/usr/bin/env bash
# FAC credential posture hardening gate (TCK-00445).
#
# Enforces fail-closed credential source policy and blocks insecure invocation
# patterns that could leak secrets through process argv.

set -euo pipefail

MODE="${1:-runtime}"
if [[ $# -gt 0 ]]; then
    shift
fi

log_decision() {
    local check="$1"
    local decision="$2"
    shift 2
    echo "fac-credential: check=${check} decision=${decision} $*"
}

deny() {
    local check="$1"
    local reason="$2"
    shift 2 || true
    log_decision "${check}" "DENY" "reason=${reason} $*"
    log_decision "overall" "DENY" "reason=${reason}"
    exit 1
}

allow() {
    local check="$1"
    shift
    log_decision "${check}" "ALLOW" "$*"
}

render_cmdline() {
    local cmdline_path="$1"
    if [[ ! -r "${cmdline_path}" ]]; then
        return 1
    fi

    # /proc/*/cmdline is NUL-delimited; fixtures may be plain text.
    tr '\0' ' ' < "${cmdline_path}" 2>/dev/null | tr '\n' ' '
}

run_runtime_checks() {
    local source="${APM2_FAC_CREDENTIAL_SOURCE:-}"
    local stage="${APM2_CREDENTIAL_HARDENING_STAGE:-unspecified}"
    local github_token="${GITHUB_TOKEN:-}"
    local gh_token="${GH_TOKEN:-}"
    local cmdline_path="${APM2_CREDENTIAL_HARDENING_CMDLINE_PATH:-/proc/$$/cmdline}"
    local cmdline=''
    local pat_env_var=''

    if [[ -z "${source}" ]]; then
        deny "credential_source" "missing_credential_source" "stage=${stage}"
    fi
    case "${source}" in
        github_token)
            allow "credential_source" "source=${source} stage=${stage}"
            ;;
        *)
            deny "credential_source" "unsupported_credential_source" "source=${source}"
            ;;
    esac

    if [[ -z "${github_token}" ]]; then
        deny "credential_value" "missing_github_token" "source=${source}"
    fi

    if [[ -n "${gh_token}" && "${gh_token}" != "${github_token}" ]]; then
        deny "credential_value" "ambiguous_token_values"
    fi

    case "${github_token}" in
        ghs_*)
            allow "credential_value" "token_class=github_actions"
            ;;
        ghp_*|github_pat_*)
            deny "credential_value" "disallowed_token_type"
            ;;
        *)
            deny "credential_value" "unknown_token_format"
            ;;
    esac

    local pat_env_candidates=(
        GH_PAT
        GITHUB_PAT
        APM2_GITHUB_PAT
        APM2_FAC_PAT
        PERSONAL_ACCESS_TOKEN
    )
    for pat_env_var in "${pat_env_candidates[@]}"; do
        if [[ -n "${!pat_env_var:-}" ]]; then
            deny "credential_env" "disallowed_pat_env_var" "var=${pat_env_var}"
        fi
    done
    allow "credential_env" "pat_env=clear"

    if ! cmdline="$(render_cmdline "${cmdline_path}")" || [[ -z "${cmdline}" ]]; then
        deny "argv_surface" "missing_cmdline_context" "path=${cmdline_path}"
    fi

    if [[ "${cmdline}" == *"${github_token}"* ]]; then
        deny "argv_surface" "credential_value_in_argv"
    fi

    if [[ "${cmdline}" =~ (^|[[:space:]])(--token|--github-token|--auth-token|--access-token|--pat)([=[:space:]]|$) ]]; then
        deny "argv_surface" "insecure_token_flag_in_argv"
    fi

    if [[ "${cmdline}" =~ (ghp_[A-Za-z0-9_]{12,}|github_pat_[A-Za-z0-9_]{12,}) ]]; then
        deny "argv_surface" "pat_literal_in_argv"
    fi
    allow "argv_surface" "credential_leak_scan=clear"

    allow "overall" "source=${source} stage=${stage}"
}

run_lint_checks() {
    local violations=0
    local pattern=''
    local matches=''
    local -a scan_paths=()

    if [[ $# -gt 0 ]]; then
        scan_paths=("$@")
    else
        scan_paths=(
            ".github/workflows/forge-admission-cycle.yml"
            "scripts/ci/fac_preflight_authorization.sh"
        )
    fi

    if [[ ${#scan_paths[@]} -eq 0 ]]; then
        deny "lint" "missing_scan_paths"
    fi

    for path in "${scan_paths[@]}"; do
        if [[ ! -e "${path}" ]]; then
            deny "lint" "missing_scan_path" "path=${path}"
        fi
    done

    pattern='\b(GH_PAT|GITHUB_PAT|APM2_GITHUB_PAT|APM2_FAC_PAT|PERSONAL_ACCESS_TOKEN)\b'
    matches="$(rg -n -e "${pattern}" "${scan_paths[@]}" || true)"
    if [[ -n "${matches}" ]]; then
        log_decision "lint_pat_env" "DENY" "rule=deny_pat_env_vars"
        echo "${matches}" >&2
        violations=$((violations + 1))
    else
        allow "lint_pat_env" "rule=deny_pat_env_vars"
    fi

    pattern='(ghp_[A-Za-z0-9_]{12,}|github_pat_[A-Za-z0-9_]{12,})'
    matches="$(rg -n -e "${pattern}" "${scan_paths[@]}" || true)"
    if [[ -n "${matches}" ]]; then
        log_decision "lint_pat_literal" "DENY" "rule=deny_pat_literals"
        echo "${matches}" >&2
        violations=$((violations + 1))
    else
        allow "lint_pat_literal" "rule=deny_pat_literals"
    fi

    pattern='(--token|--github-token|--auth-token|--access-token|--pat)\b'
    matches="$(rg -n -e "${pattern}" "${scan_paths[@]}" || true)"
    if [[ -n "${matches}" ]]; then
        log_decision "lint_argv_flags" "DENY" "rule=deny_token_cli_flags"
        echo "${matches}" >&2
        violations=$((violations + 1))
    else
        allow "lint_argv_flags" "rule=deny_token_cli_flags"
    fi

    pattern='Authorization:[[:space:]]*(token|Bearer)[[:space:]]*\$?\{?[A-Za-z_][A-Za-z0-9_]*\}?'
    matches="$(rg -n -e "${pattern}" "${scan_paths[@]}" || true)"
    if [[ -n "${matches}" ]]; then
        log_decision "lint_auth_header" "DENY" "rule=deny_inline_auth_headers"
        echo "${matches}" >&2
        violations=$((violations + 1))
    else
        allow "lint_auth_header" "rule=deny_inline_auth_headers"
    fi

    if [[ "${violations}" -ne 0 ]]; then
        deny "lint" "lint_violations_detected" "count=${violations}"
    fi

    allow "overall" "mode=lint paths=${#scan_paths[@]}"
}

case "${MODE}" in
    runtime)
        if [[ $# -ne 0 ]]; then
            deny "usage" "runtime_does_not_accept_positional_args"
        fi
        run_runtime_checks
        ;;
    lint)
        run_lint_checks "$@"
        ;;
    *)
        deny "usage" "unsupported_mode" "mode=${MODE}"
        ;;
esac
