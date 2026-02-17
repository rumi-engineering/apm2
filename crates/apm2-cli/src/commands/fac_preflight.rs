use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use clap::ValueEnum;
use regex::Regex;
use serde::Deserialize;
use serde_json::Value;

use crate::commands::fac_secure_io;
use crate::exit_codes::codes as exit_codes;

const FAC_PRECHECK_PREFIX: &str = "fac-credential";
const FAC_AUTH_PREFIX: &str = "fac-preflight";
const DEFAULT_POLICY_PATH: &str = ".github/review-gate/workflow-trust-policy.json";
const DEFAULT_LINT_PATHS: &[&str] = &[".github/workflows/forge-admission-cycle.yml"];
const MAX_CMDLINE_CONTEXT_SIZE: usize = 128 * 1024;
const MAX_LINT_SCAN_FILE_SIZE: usize = 10 * 1024 * 1024;
const MAX_EVENT_JSON_SIZE: usize = 10 * 1024 * 1024;
const MAX_POLICY_JSON_SIZE: usize = 2 * 1024 * 1024;
const MAX_PR_JSON_OVERRIDE_SIZE: usize = 10 * 1024 * 1024;
const PAT_ENV_VARS: &[&str] = &[
    "GH_PAT",
    "GITHUB_PAT",
    "APM2_GITHUB_PAT",
    "APM2_FAC_PAT",
    "PERSONAL_ACCESS_TOKEN",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CredentialMode {
    Runtime,
    Lint,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkflowTrustPolicyV1 {
    schema: String,
    allowed_actor_associations: Vec<String>,
    trusted_base_refs: Vec<String>,
    trusted_fork_pr_numbers: Vec<Value>,
    trusted_fork_head_repositories: Vec<String>,
    trusted_fork_labels: Vec<String>,
    trusted_app_actors: Vec<String>,
    credential_posture: CredentialPosturePolicy,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialPosturePolicy {
    projection_credential_source: String,
    allow_personal_access_tokens: bool,
    allow_argv_credentials: bool,
}

impl WorkflowTrustPolicyV1 {
    fn trusted_pr_numbers(&self) -> BTreeSet<String> {
        self.trusted_fork_pr_numbers
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map_or_else(|| value.to_string(), std::string::ToString::to_string)
            })
            .collect()
    }
}

fn log_decision(prefix: &str, check: &str, decision: &str, details: &str, json_output: bool) {
    if json_output {
        let payload = serde_json::json!({
            "prefix": prefix,
            "check": check,
            "decision": decision,
            "details": details,
        });
        println!("{}", serde_json::to_string(&payload).unwrap_or_default());
        return;
    }
    if details.is_empty() {
        println!("{prefix}: check={check} decision={decision}");
    } else {
        println!("{prefix}: check={check} decision={decision} {details}");
    }
}

fn deny(prefix: &str, check: &str, reason: &str, details: &str, json_output: bool) -> u8 {
    let mut detail = format!("reason={reason}");
    if !details.is_empty() {
        detail.push(' ');
        detail.push_str(details);
    }
    log_decision(prefix, check, "DENY", &detail, json_output);
    log_decision(
        prefix,
        "overall",
        "DENY",
        &format!("reason={reason}"),
        json_output,
    );
    exit_codes::GENERIC_ERROR
}

fn allow(prefix: &str, check: &str, details: &str, json_output: bool) {
    log_decision(prefix, check, "ALLOW", details, json_output);
}

fn render_cmdline(path: &Path) -> Result<String, String> {
    let bytes = fac_secure_io::read_bounded(path, MAX_CMDLINE_CONTEXT_SIZE)
        .map_err(|err| format!("cannot read cmdline context {}: {err}", path.display()))?;
    let rendered = String::from_utf8_lossy(&bytes).replace(['\0', '\n'], " ");
    if rendered.trim().is_empty() {
        return Err("cmdline context is empty".to_string());
    }
    Ok(rendered)
}

fn validate_repository_owner_repo(repository: &str) -> Result<(), String> {
    let re = Regex::new(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$").expect("static repository regex");
    if re.is_match(repository) {
        Ok(())
    } else {
        Err(format!(
            "invalid repository format `{repository}` (expected owner/repo)"
        ))
    }
}

fn validate_actor_name(actor: &str) -> Result<(), String> {
    let re = Regex::new(r"^[A-Za-z0-9_.\-\[\]]+$").expect("static actor regex");
    if !actor.is_empty() && re.is_match(actor) {
        Ok(())
    } else {
        Err(format!("invalid actor `{actor}`"))
    }
}

pub fn run_credential(mode: CredentialMode, paths: &[PathBuf], json_output: bool) -> u8 {
    match mode {
        CredentialMode::Runtime => run_credential_runtime(
            std::env::var("APM2_FAC_CREDENTIAL_SOURCE").ok(),
            std::env::var("APM2_CREDENTIAL_HARDENING_STAGE").ok(),
            std::env::var("APM2_CREDENTIAL_HARDENING_CMDLINE_PATH").ok(),
            json_output,
        ),
        CredentialMode::Lint => run_credential_lint(paths, json_output),
    }
}

pub fn run_credential_runtime(
    source_override: Option<String>,
    stage_override: Option<String>,
    cmdline_override: Option<String>,
    json_output: bool,
) -> u8 {
    let source = source_override.unwrap_or_default();
    let stage = stage_override.unwrap_or_else(|| "unspecified".to_string());
    let github_token = std::env::var("GITHUB_TOKEN").unwrap_or_default();
    let gh_token = std::env::var("GH_TOKEN").unwrap_or_default();
    let cmdline_path =
        cmdline_override.map_or_else(|| PathBuf::from("/proc/self/cmdline"), PathBuf::from);
    let pat_env_values = collect_pat_env_values();

    run_credential_runtime_with_values(
        &source,
        &stage,
        &github_token,
        &gh_token,
        &cmdline_path,
        &pat_env_values,
        json_output,
    )
}

fn collect_pat_env_values() -> BTreeMap<String, String> {
    let mut values = BTreeMap::new();
    for key in PAT_ENV_VARS {
        if let Ok(value) = std::env::var(key) {
            values.insert((*key).to_string(), value);
        }
    }
    values
}

fn run_credential_runtime_with_values(
    source: &str,
    stage: &str,
    github_token: &str,
    gh_token: &str,
    cmdline_path: &Path,
    pat_env_values: &BTreeMap<String, String>,
    json_output: bool,
) -> u8 {
    if source.is_empty() {
        return deny(
            FAC_PRECHECK_PREFIX,
            "credential_source",
            "missing_credential_source",
            &format!("stage={stage}"),
            json_output,
        );
    }
    if source != "github_token" {
        return deny(
            FAC_PRECHECK_PREFIX,
            "credential_source",
            "unsupported_credential_source",
            &format!("source={source}"),
            json_output,
        );
    }
    allow(
        FAC_PRECHECK_PREFIX,
        "credential_source",
        &format!("source={source} stage={stage}"),
        json_output,
    );

    if github_token.is_empty() {
        return deny(
            FAC_PRECHECK_PREFIX,
            "credential_value",
            "missing_github_token",
            &format!("source={source}"),
            json_output,
        );
    }
    if !gh_token.is_empty() && gh_token != github_token {
        return deny(
            FAC_PRECHECK_PREFIX,
            "credential_value",
            "ambiguous_token_values",
            "",
            json_output,
        );
    }
    if github_token.starts_with("ghs_") {
        allow(
            FAC_PRECHECK_PREFIX,
            "credential_value",
            "token_class=github_actions",
            json_output,
        );
    } else if github_token.starts_with("ghp_") || github_token.starts_with("github_pat_") {
        return deny(
            FAC_PRECHECK_PREFIX,
            "credential_value",
            "disallowed_token_type",
            "",
            json_output,
        );
    } else {
        return deny(
            FAC_PRECHECK_PREFIX,
            "credential_value",
            "unknown_token_format",
            "",
            json_output,
        );
    }

    for key in PAT_ENV_VARS {
        if pat_env_values
            .get(*key)
            .is_some_and(|value| !value.is_empty())
        {
            return deny(
                FAC_PRECHECK_PREFIX,
                "credential_env",
                "disallowed_pat_env_var",
                &format!("var={key}"),
                json_output,
            );
        }
    }
    allow(
        FAC_PRECHECK_PREFIX,
        "credential_env",
        "pat_env=clear",
        json_output,
    );

    let Ok(cmdline) = render_cmdline(cmdline_path) else {
        return deny(
            FAC_PRECHECK_PREFIX,
            "argv_surface",
            "missing_cmdline_context",
            &format!("path={}", cmdline_path.display()),
            json_output,
        );
    };
    if cmdline.contains(github_token) {
        return deny(
            FAC_PRECHECK_PREFIX,
            "argv_surface",
            "credential_value_in_argv",
            "",
            json_output,
        );
    }
    let token_flag_re = Regex::new(r"(^|[[:space:]])(--token|--github-token|--auth-token|--access-token|--pat)([=[:space:]]|$)")
        .expect("static regex");
    if token_flag_re.is_match(&cmdline) {
        return deny(
            FAC_PRECHECK_PREFIX,
            "argv_surface",
            "insecure_token_flag_in_argv",
            "",
            json_output,
        );
    }
    let pat_literal_re =
        Regex::new(r"(ghp_[A-Za-z0-9_]{12,}|github_pat_[A-Za-z0-9_]{12,})").expect("static regex");
    if pat_literal_re.is_match(&cmdline) {
        return deny(
            FAC_PRECHECK_PREFIX,
            "argv_surface",
            "pat_literal_in_argv",
            "",
            json_output,
        );
    }
    allow(
        FAC_PRECHECK_PREFIX,
        "argv_surface",
        "credential_leak_scan=clear",
        json_output,
    );
    allow(
        FAC_PRECHECK_PREFIX,
        "overall",
        &format!("source={source} stage={stage}"),
        json_output,
    );
    exit_codes::SUCCESS
}

pub fn run_credential_lint(paths: &[PathBuf], json_output: bool) -> u8 {
    let scan_paths: Vec<PathBuf> = if paths.is_empty() {
        DEFAULT_LINT_PATHS.iter().map(PathBuf::from).collect()
    } else {
        paths.to_vec()
    };
    if scan_paths.is_empty() {
        return deny(
            FAC_PRECHECK_PREFIX,
            "lint",
            "missing_scan_paths",
            "",
            json_output,
        );
    }
    for path in &scan_paths {
        if !path.exists() {
            return deny(
                FAC_PRECHECK_PREFIX,
                "lint",
                "missing_scan_path",
                &format!("path={}", path.display()),
                json_output,
            );
        }
    }

    let mut violations = 0u64;
    let checks: [(&str, &str, &str); 4] = [
        (
            "lint_pat_env",
            r"\b(GH_PAT|GITHUB_PAT|APM2_GITHUB_PAT|APM2_FAC_PAT|PERSONAL_ACCESS_TOKEN)\b",
            "deny_pat_env_vars",
        ),
        (
            "lint_pat_literal",
            r"(ghp_[A-Za-z0-9_]{12,}|github_pat_[A-Za-z0-9_]{12,})",
            "deny_pat_literals",
        ),
        (
            "lint_argv_flags",
            r"(--token|--github-token|--auth-token|--access-token|--pat)\b",
            "deny_token_cli_flags",
        ),
        (
            "lint_auth_header",
            r"Authorization:[[:space:]]*(token|Bearer)[[:space:]]*\$?\{?[A-Za-z_][A-Za-z0-9_]*\}?",
            "deny_inline_auth_headers",
        ),
    ];

    for (check, pattern, rule) in checks {
        let regex = Regex::new(pattern).expect("static regex");
        let matches = match scan_regex_matches(&scan_paths, &regex) {
            Ok(matches) => matches,
            Err(reason) => {
                return deny(
                    FAC_PRECHECK_PREFIX,
                    "lint",
                    "scan_path_read_error",
                    &reason,
                    json_output,
                );
            },
        };
        if matches.is_empty() {
            allow(
                FAC_PRECHECK_PREFIX,
                check,
                &format!("rule={rule}"),
                json_output,
            );
            continue;
        }
        log_decision(
            FAC_PRECHECK_PREFIX,
            check,
            "DENY",
            &format!("rule={rule}"),
            json_output,
        );
        for line in matches {
            eprintln!("{line}");
        }
        violations = violations.saturating_add(1);
    }

    if violations != 0 {
        return deny(
            FAC_PRECHECK_PREFIX,
            "lint",
            "lint_violations_detected",
            &format!("count={violations}"),
            json_output,
        );
    }
    allow(
        FAC_PRECHECK_PREFIX,
        "overall",
        &format!("mode=lint paths={}", scan_paths.len()),
        json_output,
    );
    exit_codes::SUCCESS
}

fn scan_regex_matches(paths: &[PathBuf], regex: &Regex) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for path in paths {
        let text = fac_secure_io::read_bounded_text(path, MAX_LINT_SCAN_FILE_SIZE)
            .map_err(|err| format!("path={} error={err}", path.display()))?;
        for (idx, line) in text.lines().enumerate() {
            if regex.is_match(line) {
                out.push(format!("{}:{}:{}", path.display(), idx + 1, line));
            }
        }
    }
    Ok(out)
}

pub fn run_workflow_authorization(json_output: bool) -> u8 {
    let event_name = std::env::var("APM2_PREFLIGHT_EVENT_NAME")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            std::env::var("GITHUB_EVENT_NAME")
                .ok()
                .filter(|value| !value.trim().is_empty())
        });
    let event_path = std::env::var("APM2_PREFLIGHT_EVENT_PATH")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            std::env::var("GITHUB_EVENT_PATH")
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
        .map(PathBuf::from);
    let repository = std::env::var("APM2_PREFLIGHT_REPOSITORY")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            std::env::var("GITHUB_REPOSITORY")
                .ok()
                .filter(|value| !value.trim().is_empty())
        });
    let actor = std::env::var("APM2_PREFLIGHT_ACTOR")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            std::env::var("GITHUB_ACTOR")
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
        .unwrap_or_else(|| "unknown".to_string());
    let dispatch_ref = std::env::var("APM2_PREFLIGHT_REF_NAME")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            std::env::var("GITHUB_REF_NAME")
                .ok()
                .filter(|value| !value.trim().is_empty())
        });
    let policy_path = std::env::var("APM2_PREFLIGHT_TRUST_POLICY_PATH")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map_or_else(|| PathBuf::from(DEFAULT_POLICY_PATH), PathBuf::from);
    let runtime_stage = std::env::var("APM2_CREDENTIAL_HARDENING_STAGE")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "preflight".to_string());
    let cmdline_path = std::env::var("APM2_CREDENTIAL_HARDENING_CMDLINE_PATH")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map_or_else(|| PathBuf::from("/proc/self/cmdline"), PathBuf::from);
    let pr_json_override_path = std::env::var("APM2_PREFLIGHT_PR_JSON_PATH")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from);
    let github_token = std::env::var("GITHUB_TOKEN").unwrap_or_default();
    let gh_token = std::env::var("GH_TOKEN").unwrap_or_default();
    let pat_env_values = collect_pat_env_values();

    let Some(event_name) = event_name else {
        return deny(
            FAC_AUTH_PREFIX,
            "context",
            "missing_event_name",
            "",
            json_output,
        );
    };
    let Some(event_path) = event_path else {
        return deny(
            FAC_AUTH_PREFIX,
            "context",
            "missing_event_path",
            "event_path=unset",
            json_output,
        );
    };
    let Some(repository) = repository else {
        return deny(
            FAC_AUTH_PREFIX,
            "context",
            "missing_repository",
            "",
            json_output,
        );
    };
    if let Err(reason) = validate_repository_owner_repo(&repository) {
        return deny(
            FAC_AUTH_PREFIX,
            "context",
            "invalid_repository",
            &reason,
            json_output,
        );
    }
    if let Err(reason) = validate_actor_name(&actor) {
        return deny(
            FAC_AUTH_PREFIX,
            "context",
            "invalid_actor",
            &reason,
            json_output,
        );
    }
    let context = WorkflowAuthorizationContext {
        event_name,
        event_path,
        repository,
        actor,
        dispatch_ref,
        policy_path,
        runtime_stage,
        cmdline_path,
        github_token,
        gh_token,
        pat_env_values,
        pr_json_override_path,
        permission_lookup: fetch_actor_permission_via_gh,
    };
    run_workflow_authorization_with_context(&context, json_output)
}

type PermissionLookup = fn(&str, &str) -> Result<String, String>;

#[derive(Debug, Clone)]
struct WorkflowAuthorizationContext {
    event_name: String,
    event_path: PathBuf,
    repository: String,
    actor: String,
    dispatch_ref: Option<String>,
    policy_path: PathBuf,
    runtime_stage: String,
    cmdline_path: PathBuf,
    github_token: String,
    gh_token: String,
    pat_env_values: BTreeMap<String, String>,
    pr_json_override_path: Option<PathBuf>,
    permission_lookup: PermissionLookup,
}

fn run_workflow_authorization_with_context(
    context: &WorkflowAuthorizationContext,
    json_output: bool,
) -> u8 {
    if !context.event_path.is_file() {
        return deny(
            FAC_AUTH_PREFIX,
            "context",
            "missing_event_path",
            &format!("event_path={}", context.event_path.display()),
            json_output,
        );
    }
    if !context.policy_path.is_file() {
        return deny(
            FAC_AUTH_PREFIX,
            "policy",
            "missing_policy_file",
            &format!("policy_path={}", context.policy_path.display()),
            json_output,
        );
    }

    let policy = match load_policy(&context.policy_path) {
        Ok(value) => value,
        Err(reason) => {
            return deny(
                FAC_AUTH_PREFIX,
                "policy",
                "invalid_policy_schema",
                &format!(
                    "policy_path={} detail={reason}",
                    context.policy_path.display()
                ),
                json_output,
            );
        },
    };
    allow(
        FAC_AUTH_PREFIX,
        "credential_posture",
        &format!(
            "source={} allow_pat={} allow_argv={}",
            policy.credential_posture.projection_credential_source,
            policy.credential_posture.allow_personal_access_tokens,
            policy.credential_posture.allow_argv_credentials
        ),
        json_output,
    );

    let runtime_code = run_credential_runtime_with_values(
        &policy.credential_posture.projection_credential_source,
        &context.runtime_stage,
        &context.github_token,
        &context.gh_token,
        &context.cmdline_path,
        &context.pat_env_values,
        json_output,
    );
    if runtime_code != exit_codes::SUCCESS {
        return deny(
            FAC_AUTH_PREFIX,
            "credential_posture",
            "credential_runtime_check_failed",
            "",
            json_output,
        );
    }
    allow(
        FAC_AUTH_PREFIX,
        "credential_posture",
        "runtime_check=passed",
        json_output,
    );

    let event_json = match read_json_file_with_limit(&context.event_path, MAX_EVENT_JSON_SIZE) {
        Ok(value) => value,
        Err(reason) => {
            return deny(
                FAC_AUTH_PREFIX,
                "context",
                "invalid_event_payload",
                &reason,
                json_output,
            );
        },
    };

    let (pr_number, mut pr_json) = match context.event_name.as_str() {
        "pull_request_target" => {
            let Some(pr) = event_json.get("pull_request").cloned() else {
                return deny(
                    FAC_AUTH_PREFIX,
                    "context",
                    "missing_pull_request_payload",
                    "",
                    json_output,
                );
            };
            let pr_number = pr
                .get("number")
                .and_then(Value::as_u64)
                .unwrap_or_default()
                .to_string();
            (pr_number, pr)
        },
        "workflow_dispatch" => {
            let pr_number = event_json
                .pointer("/inputs/pr_number")
                .and_then(Value::as_str)
                .or_else(|| {
                    event_json
                        .pointer("/client_payload/pr_number")
                        .and_then(Value::as_str)
                })
                .map(std::string::ToString::to_string)
                .unwrap_or_default();
            if pr_number.is_empty() {
                return deny(
                    FAC_AUTH_PREFIX,
                    "context",
                    "workflow_dispatch_missing_pr_number",
                    "",
                    json_output,
                );
            }
            let pr_json = match context.pr_json_override_path.as_deref() {
                Some(path) => match read_json_file_with_limit(path, MAX_PR_JSON_OVERRIDE_SIZE) {
                    Ok(value) => value,
                    Err(_) => {
                        return deny(
                            FAC_AUTH_PREFIX,
                            "context",
                            "missing_pr_json_override",
                            &format!("path={}", path.display()),
                            json_output,
                        );
                    },
                },
                None => match fetch_pr_json_via_gh(&context.repository, &pr_number) {
                    Ok(value) => value,
                    Err(_) => {
                        return deny(
                            FAC_AUTH_PREFIX,
                            "context",
                            "workflow_dispatch_pr_lookup_failed",
                            &format!("pr={pr_number}"),
                            json_output,
                        );
                    },
                },
            };
            (pr_number, pr_json)
        },
        _ => {
            return deny(
                FAC_AUTH_PREFIX,
                "context",
                "unsupported_event",
                &format!("event={}", context.event_name),
                json_output,
            );
        },
    };

    if !pr_number.chars().all(|ch| ch.is_ascii_digit()) || pr_number == "0" {
        return deny(
            FAC_AUTH_PREFIX,
            "context",
            "invalid_pr_number",
            &format!("pr={pr_number}"),
            json_output,
        );
    }
    if let Some(inner) = pr_json.get("pull_request").cloned() {
        pr_json = inner;
    }

    let pr_state = pr_json
        .get("state")
        .and_then(Value::as_str)
        .unwrap_or("open");
    if pr_state != "open" {
        return deny(
            FAC_AUTH_PREFIX,
            "pr_state",
            "pr_not_open",
            &format!("pr={pr_number} state={pr_state}"),
            json_output,
        );
    }
    allow(
        FAC_AUTH_PREFIX,
        "pr_state",
        &format!("pr={pr_number} state={pr_state}"),
        json_output,
    );

    let author_association = pr_json
        .get("author_association")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    if author_association.is_empty() {
        return deny(
            FAC_AUTH_PREFIX,
            "actor_association",
            "missing_author_association",
            &format!("pr={pr_number}"),
            json_output,
        );
    }
    let actor_is_trusted_app = policy
        .trusted_app_actors
        .iter()
        .any(|value| value == &context.actor);

    let base_ref = pr_json
        .pointer("/base/ref")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    if base_ref.is_empty() {
        return deny(
            FAC_AUTH_PREFIX,
            "base_ref",
            "missing_base_ref",
            &format!("pr={pr_number}"),
            json_output,
        );
    }
    if !policy
        .trusted_base_refs
        .iter()
        .any(|value| value == &base_ref)
    {
        return deny(
            FAC_AUTH_PREFIX,
            "base_ref",
            "untrusted_base_ref",
            &format!("pr={pr_number} base_ref={base_ref}"),
            json_output,
        );
    }
    allow(
        FAC_AUTH_PREFIX,
        "base_ref",
        &format!("pr={pr_number} base_ref={base_ref}"),
        json_output,
    );

    if context.event_name == "workflow_dispatch" {
        let Some(dispatch_ref) = context.dispatch_ref.as_deref() else {
            return deny(
                FAC_AUTH_PREFIX,
                "dispatch_ref",
                "missing_dispatch_ref",
                "",
                json_output,
            );
        };
        if !policy
            .trusted_base_refs
            .iter()
            .any(|value| value == dispatch_ref)
        {
            return deny(
                FAC_AUTH_PREFIX,
                "dispatch_ref",
                "untrusted_dispatch_ref",
                &format!("ref={dispatch_ref}"),
                json_output,
            );
        }
        allow(
            FAC_AUTH_PREFIX,
            "dispatch_ref",
            &format!("ref={dispatch_ref}"),
            json_output,
        );

        let permission = match (context.permission_lookup)(&context.repository, &context.actor) {
            Ok(permission) => permission,
            Err(err) => {
                return deny(
                    FAC_AUTH_PREFIX,
                    "dispatch_actor",
                    "actor_permission_lookup_failed",
                    &format!("actor={} detail={err}", context.actor),
                    json_output,
                );
            },
        };
        if !matches!(permission.as_str(), "admin" | "maintain" | "write") {
            return deny(
                FAC_AUTH_PREFIX,
                "dispatch_actor",
                "insufficient_actor_permission",
                &format!(
                    "actor={} permission={}",
                    context.actor,
                    if permission.is_empty() {
                        "none"
                    } else {
                        &permission
                    }
                ),
                json_output,
            );
        }
        allow(
            FAC_AUTH_PREFIX,
            "dispatch_actor",
            &format!("actor={} permission={permission}", context.actor),
            json_output,
        );
    }

    let head_repo_full_name = pr_json
        .pointer("/head/repo/full_name")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let base_repo_full_name = pr_json
        .pointer("/base/repo/full_name")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    if head_repo_full_name.is_empty() || base_repo_full_name.is_empty() {
        return deny(
            FAC_AUTH_PREFIX,
            "fork_context",
            "missing_repo_identity",
            &format!("head_repo={head_repo_full_name} base_repo={base_repo_full_name}"),
            json_output,
        );
    }
    let head_repo_fork = pr_json
        .pointer("/head/repo/fork")
        .and_then(Value::as_bool)
        .unwrap_or(head_repo_full_name != base_repo_full_name);
    let is_fork = head_repo_fork || head_repo_full_name != base_repo_full_name;

    if is_fork {
        let trusted_pr_numbers = policy.trusted_pr_numbers();
        let mut trust_grant = if trusted_pr_numbers.contains(&pr_number) {
            Some("policy:pr_number".to_string())
        } else {
            None
        };
        if trust_grant.is_none()
            && policy
                .trusted_fork_head_repositories
                .iter()
                .any(|value| value == &head_repo_full_name)
        {
            trust_grant = Some("policy:head_repo".to_string());
        }
        if trust_grant.is_none() {
            let labels = pr_json
                .get("labels")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            for label in labels {
                let Some(name) = label.get("name").and_then(Value::as_str) else {
                    continue;
                };
                if policy.trusted_fork_labels.iter().any(|value| value == name) {
                    trust_grant = Some(format!("label:{name}"));
                    break;
                }
            }
        }
        let Some(trust_grant) = trust_grant else {
            return deny(
                FAC_AUTH_PREFIX,
                "fork_trust",
                "fork_without_trust_grant",
                &format!("pr={pr_number} head_repo={head_repo_full_name}"),
                json_output,
            );
        };
        allow(
            FAC_AUTH_PREFIX,
            "fork_trust",
            &format!("pr={pr_number} fork=true trust_grant={trust_grant}"),
            json_output,
        );
    } else {
        allow(
            FAC_AUTH_PREFIX,
            "fork_trust",
            &format!("pr={pr_number} fork=false"),
            json_output,
        );
    }

    let association_allowed = policy
        .allowed_actor_associations
        .iter()
        .any(|value| value == &author_association);
    if association_allowed {
        allow(
            FAC_AUTH_PREFIX,
            "actor_association",
            &format!("pr={pr_number} association={author_association}"),
            json_output,
        );
    } else if actor_is_trusted_app && author_association == "NONE" && !is_fork {
        allow(
            FAC_AUTH_PREFIX,
            "actor_association",
            &format!(
                "pr={pr_number} actor={} grant=trusted_app_actor_same_repo_none association={author_association}",
                context.actor
            ),
            json_output,
        );
    } else {
        return deny(
            FAC_AUTH_PREFIX,
            "actor_association",
            "unauthorized_author_association",
            &format!(
                "pr={pr_number} association={author_association} actor={}",
                context.actor
            ),
            json_output,
        );
    }

    allow(
        FAC_AUTH_PREFIX,
        "overall",
        &format!(
            "event={} pr={pr_number} actor={} association={author_association} base_ref={base_ref} fork={is_fork}",
            context.event_name, context.actor
        ),
        json_output,
    );
    exit_codes::SUCCESS
}

fn load_policy(path: &Path) -> Result<WorkflowTrustPolicyV1, String> {
    let bytes = fac_secure_io::read_bounded(path, MAX_POLICY_JSON_SIZE)
        .map_err(|err| format!("cannot read policy {}: {err}", path.display()))?;
    let policy: WorkflowTrustPolicyV1 =
        serde_json::from_slice(&bytes).map_err(|err| format!("invalid JSON: {err}"))?;
    if policy.schema != "apm2.fac_workflow_trust_policy.v1" {
        return Err(format!("unsupported schema {}", policy.schema));
    }
    if policy.allowed_actor_associations.is_empty() || policy.trusted_base_refs.is_empty() {
        return Err("required policy arrays must be non-empty".to_string());
    }
    if policy.credential_posture.projection_credential_source != "github_token"
        || policy.credential_posture.allow_personal_access_tokens
        || policy.credential_posture.allow_argv_credentials
    {
        return Err("credential posture violates required policy".to_string());
    }
    Ok(policy)
}

fn read_json_file_with_limit(path: &Path, max_size: usize) -> Result<Value, String> {
    let bytes = fac_secure_io::read_bounded(path, max_size)
        .map_err(|err| format!("cannot read {}: {err}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|err| format!("invalid JSON {}: {err}", path.display()))
}

fn fetch_pr_json_via_gh(repository: &str, pr_number: &str) -> Result<Value, String> {
    validate_repository_owner_repo(repository)?;
    let output = Command::new("gh")
        .args(["api", &format!("repos/{repository}/pulls/{pr_number}")])
        .output()
        .map_err(|err| format!("failed to invoke gh: {err}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(format!("gh api failed: {stderr}"));
    }
    serde_json::from_slice(&output.stdout).map_err(|err| format!("invalid gh JSON: {err}"))
}

fn fetch_actor_permission_via_gh(repository: &str, actor: &str) -> Result<String, String> {
    validate_repository_owner_repo(repository)?;
    validate_actor_name(actor)?;
    let output = Command::new("gh")
        .args([
            "api",
            &format!("repos/{repository}/collaborators/{actor}/permission"),
            "--jq",
            ".permission // empty",
        ])
        .output()
        .map_err(|err| format!("failed to invoke gh: {err}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(format!("gh permission lookup failed: {stderr}"));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_TOKEN: &str = "ghs_fac_fixture_token_123456789012345678901234567890";
    const LEAK_TOKEN: &str = "ghs_leak_fixture_token_123456789012345678901234567890";
    const PAT_TOKEN: &str = "github_pat_fixture_token_123456789012345678901234567890";

    fn fixture_path(rel: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/fac_preflight")
            .join(rel)
    }

    fn pat_env(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
        entries
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    fn workflow_context(
        event_rel: &str,
        policy_rel: &str,
        actor: &str,
    ) -> WorkflowAuthorizationContext {
        WorkflowAuthorizationContext {
            event_name: "pull_request_target".to_string(),
            event_path: fixture_path(event_rel),
            repository: "guardian-intelligence/apm2".to_string(),
            actor: actor.to_string(),
            dispatch_ref: Some("main".to_string()),
            policy_path: fixture_path(policy_rel),
            runtime_stage: "preflight".to_string(),
            cmdline_path: fixture_path("credential_hardening/cmdline_safe.txt"),
            github_token: VALID_TOKEN.to_string(),
            gh_token: String::new(),
            pat_env_values: BTreeMap::new(),
            pr_json_override_path: None,
            permission_lookup: fetch_actor_permission_via_gh,
        }
    }

    #[allow(clippy::unnecessary_wraps)]
    fn permission_lookup_write(_repository: &str, _actor: &str) -> Result<String, String> {
        Ok("write".to_string())
    }

    #[allow(clippy::unnecessary_wraps)]
    fn permission_lookup_read(_repository: &str, _actor: &str) -> Result<String, String> {
        Ok("read".to_string())
    }

    #[test]
    fn credential_runtime_accepts_valid_posture() {
        let code = run_credential_runtime_with_values(
            "github_token",
            "projection",
            VALID_TOKEN,
            "",
            &fixture_path("credential_hardening/cmdline_safe.txt"),
            &BTreeMap::new(),
            false,
        );
        assert_eq!(code, exit_codes::SUCCESS);
    }

    #[test]
    fn credential_runtime_denies_token_flag_leak() {
        let code = run_credential_runtime_with_values(
            "github_token",
            "projection",
            VALID_TOKEN,
            "",
            &fixture_path("credential_hardening/cmdline_token_flag.txt"),
            &BTreeMap::new(),
            false,
        );
        assert_eq!(code, exit_codes::GENERIC_ERROR);
    }

    #[test]
    fn credential_runtime_denies_missing_source() {
        let code = run_credential_runtime_with_values(
            "",
            "projection",
            VALID_TOKEN,
            "",
            &fixture_path("credential_hardening/cmdline_safe.txt"),
            &BTreeMap::new(),
            false,
        );
        assert_eq!(code, exit_codes::GENERIC_ERROR);
    }

    #[test]
    fn credential_runtime_denies_unsupported_source() {
        let code = run_credential_runtime_with_values(
            "auto",
            "projection",
            VALID_TOKEN,
            "",
            &fixture_path("credential_hardening/cmdline_safe.txt"),
            &BTreeMap::new(),
            false,
        );
        assert_eq!(code, exit_codes::GENERIC_ERROR);
    }

    #[test]
    fn credential_runtime_denies_missing_github_token() {
        let code = run_credential_runtime_with_values(
            "github_token",
            "projection",
            "",
            "",
            &fixture_path("credential_hardening/cmdline_safe.txt"),
            &BTreeMap::new(),
            false,
        );
        assert_eq!(code, exit_codes::GENERIC_ERROR);
    }

    #[test]
    fn credential_runtime_denies_mismatched_gh_token() {
        let code = run_credential_runtime_with_values(
            "github_token",
            "projection",
            VALID_TOKEN,
            "ghs_different_fac_fixture_token_12345678901234567890123456",
            &fixture_path("credential_hardening/cmdline_safe.txt"),
            &BTreeMap::new(),
            false,
        );
        assert_eq!(code, exit_codes::GENERIC_ERROR);
    }

    #[test]
    fn credential_runtime_denies_pat_token_class() {
        let code = run_credential_runtime_with_values(
            "github_token",
            "projection",
            PAT_TOKEN,
            "",
            &fixture_path("credential_hardening/cmdline_safe.txt"),
            &BTreeMap::new(),
            false,
        );
        assert_eq!(code, exit_codes::GENERIC_ERROR);
    }

    #[test]
    fn credential_runtime_denies_pat_env_variable() {
        let code = run_credential_runtime_with_values(
            "github_token",
            "projection",
            VALID_TOKEN,
            "",
            &fixture_path("credential_hardening/cmdline_safe.txt"),
            &pat_env(&[("GH_PAT", PAT_TOKEN)]),
            false,
        );
        assert_eq!(code, exit_codes::GENERIC_ERROR);
    }

    #[test]
    fn credential_runtime_denies_pat_literal_in_argv() {
        let code = run_credential_runtime_with_values(
            "github_token",
            "projection",
            VALID_TOKEN,
            "",
            &fixture_path("credential_hardening/cmdline_pat_literal.txt"),
            &BTreeMap::new(),
            false,
        );
        assert_eq!(code, exit_codes::GENERIC_ERROR);
    }

    #[test]
    fn credential_runtime_denies_credential_value_in_argv() {
        let code = run_credential_runtime_with_values(
            "github_token",
            "projection",
            LEAK_TOKEN,
            "",
            &fixture_path("credential_hardening/cmdline_value_leak.txt"),
            &BTreeMap::new(),
            false,
        );
        assert_eq!(code, exit_codes::GENERIC_ERROR);
    }

    #[test]
    fn credential_lint_accepts_safe_fixture() {
        let code =
            run_credential_lint(&[fixture_path("credential_hardening/lint_safe.txt")], false);
        assert_eq!(code, exit_codes::SUCCESS);
    }

    #[test]
    fn credential_lint_denies_pat_fixture() {
        let code = run_credential_lint(
            &[fixture_path("credential_hardening/lint_pat_violation.txt")],
            false,
        );
        assert_eq!(code, exit_codes::GENERIC_ERROR);
    }

    #[test]
    fn credential_lint_denies_missing_scan_path() {
        let code = run_credential_lint(
            &[fixture_path("credential_hardening/does_not_exist.txt")],
            false,
        );
        assert_eq!(code, exit_codes::GENERIC_ERROR);
    }

    #[test]
    fn credential_lint_denies_non_file_scan_path() {
        let code = run_credential_lint(&[fixture_path("credential_hardening")], false);
        assert_eq!(code, exit_codes::GENERIC_ERROR);
    }

    #[test]
    fn workflow_authorization_allows_owner_fixture() {
        let context = workflow_context(
            "authorization/event_owner_allowed.json",
            "authorization/trust_policy_main_only.json",
            "ci-test",
        );
        let code = run_workflow_authorization_with_context(&context, false);
        assert_eq!(code, exit_codes::SUCCESS);
    }

    #[test]
    fn workflow_authorization_allows_member_fixture() {
        let context = workflow_context(
            "authorization/event_member_allowed.json",
            "authorization/trust_policy_main_only.json",
            "ci-test",
        );
        let code = run_workflow_authorization_with_context(&context, false);
        assert_eq!(code, exit_codes::SUCCESS);
    }

    #[test]
    fn workflow_authorization_allows_collaborator_fixture() {
        let context = workflow_context(
            "authorization/event_collaborator_allowed.json",
            "authorization/trust_policy_main_only.json",
            "ci-test",
        );
        let code = run_workflow_authorization_with_context(&context, false);
        assert_eq!(code, exit_codes::SUCCESS);
    }

    #[test]
    fn workflow_authorization_denies_unknown_association() {
        let context = workflow_context(
            "authorization/event_unknown_association_denied.json",
            "authorization/trust_policy_main_only.json",
            "ci-test",
        );
        let code = run_workflow_authorization_with_context(&context, false);
        assert_eq!(code, exit_codes::GENERIC_ERROR);
    }

    #[test]
    fn workflow_authorization_denies_fork_without_trust_grant() {
        let context = workflow_context(
            "authorization/event_fork_without_grant_denied.json",
            "authorization/trust_policy_main_only.json",
            "ci-test",
        );
        let code = run_workflow_authorization_with_context(&context, false);
        assert_eq!(code, exit_codes::GENERIC_ERROR);
    }

    #[test]
    fn workflow_authorization_denies_non_main_base_ref() {
        let context = workflow_context(
            "authorization/event_non_main_base_denied.json",
            "authorization/trust_policy_main_only.json",
            "ci-test",
        );
        let code = run_workflow_authorization_with_context(&context, false);
        assert_eq!(code, exit_codes::GENERIC_ERROR);
    }

    #[test]
    fn workflow_authorization_allows_trusted_app_actor() {
        let context = workflow_context(
            "authorization/event_trusted_app_actor_allowed.json",
            "authorization/trust_policy_main_only.json",
            "forge-admission-cycle-projector[bot]",
        );
        let code = run_workflow_authorization_with_context(&context, false);
        assert_eq!(code, exit_codes::SUCCESS);
    }

    #[test]
    fn workflow_authorization_denies_trusted_app_actor_on_fork() {
        let context = workflow_context(
            "authorization/event_trusted_app_actor_fork_denied.json",
            "authorization/trust_policy_main_only.json",
            "forge-admission-cycle-projector[bot]",
        );
        let code = run_workflow_authorization_with_context(&context, false);
        assert_eq!(code, exit_codes::GENERIC_ERROR);
    }

    #[test]
    fn workflow_authorization_denies_invalid_policy_schema() {
        let context = workflow_context(
            "authorization/event_owner_allowed.json",
            "authorization/trust_policy_missing_credential_posture.json",
            "ci-test",
        );
        let code = run_workflow_authorization_with_context(&context, false);
        assert_eq!(code, exit_codes::GENERIC_ERROR);
    }

    #[test]
    fn workflow_dispatch_uses_permission_lookup_and_allows_write() {
        let dir = tempfile::tempdir().expect("tempdir");
        let event_path = dir.path().join("event.json");
        let pr_json_path = dir.path().join("pr.json");
        std::fs::write(&event_path, r#"{"inputs":{"pr_number":"42"}}"#).expect("write event");
        std::fs::write(
            &pr_json_path,
            r#"{
  "state":"open",
  "author_association":"OWNER",
  "base":{"ref":"main","repo":{"full_name":"guardian-intelligence/apm2"}},
  "head":{"repo":{"full_name":"guardian-intelligence/apm2","fork":false}},
  "labels":[]
}"#,
        )
        .expect("write pr json");

        let mut context = workflow_context(
            "authorization/event_owner_allowed.json",
            "authorization/trust_policy_main_only.json",
            "ci-test",
        );
        context.event_name = "workflow_dispatch".to_string();
        context.event_path = event_path;
        context.pr_json_override_path = Some(pr_json_path);
        context.permission_lookup = permission_lookup_write;

        let code = run_workflow_authorization_with_context(&context, false);
        assert_eq!(code, exit_codes::SUCCESS);
    }

    #[test]
    fn workflow_dispatch_denies_when_permission_lookup_not_writable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let event_path = dir.path().join("event.json");
        let pr_json_path = dir.path().join("pr.json");
        std::fs::write(&event_path, r#"{"inputs":{"pr_number":"42"}}"#).expect("write event");
        std::fs::write(
            &pr_json_path,
            r#"{
  "state":"open",
  "author_association":"OWNER",
  "base":{"ref":"main","repo":{"full_name":"guardian-intelligence/apm2"}},
  "head":{"repo":{"full_name":"guardian-intelligence/apm2","fork":false}},
  "labels":[]
}"#,
        )
        .expect("write pr json");

        let mut context = workflow_context(
            "authorization/event_owner_allowed.json",
            "authorization/trust_policy_main_only.json",
            "ci-test",
        );
        context.event_name = "workflow_dispatch".to_string();
        context.event_path = event_path;
        context.pr_json_override_path = Some(pr_json_path);
        context.permission_lookup = permission_lookup_read;

        let code = run_workflow_authorization_with_context(&context, false);
        assert_eq!(code, exit_codes::GENERIC_ERROR);
    }

    #[test]
    fn workflow_authorization_denies_oversized_event_payload() {
        let dir = tempfile::tempdir().expect("tempdir");
        let event_path = dir.path().join("event_oversized.json");
        let payload = "x".repeat(MAX_EVENT_JSON_SIZE + 1);
        std::fs::write(&event_path, payload).expect("write oversized event");

        let mut context = workflow_context(
            "authorization/event_owner_allowed.json",
            "authorization/trust_policy_main_only.json",
            "ci-test",
        );
        context.event_path = event_path;
        let code = run_workflow_authorization_with_context(&context, false);
        assert_eq!(code, exit_codes::GENERIC_ERROR);
    }

    #[test]
    fn workflow_authorization_denies_oversized_policy_payload() {
        let dir = tempfile::tempdir().expect("tempdir");
        let policy_path = dir.path().join("policy_oversized.json");
        let payload = "x".repeat(MAX_POLICY_JSON_SIZE + 1);
        std::fs::write(&policy_path, payload).expect("write oversized policy");

        let mut context = workflow_context(
            "authorization/event_owner_allowed.json",
            "authorization/trust_policy_main_only.json",
            "ci-test",
        );
        context.policy_path = policy_path;
        let code = run_workflow_authorization_with_context(&context, false);
        assert_eq!(code, exit_codes::GENERIC_ERROR);
    }
}
