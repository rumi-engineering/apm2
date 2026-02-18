//! Regression tests that enforce fail-closed FAC merge-policy invariants.

use std::collections::BTreeSet;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("resolve repository root")
}

fn read_ruleset_json() -> serde_json::Value {
    let path = repo_root().join(".github/rulesets/protect-main.json");
    let raw = std::fs::read_to_string(&path).expect("read protect-main ruleset");
    serde_json::from_str(&raw).expect("parse protect-main ruleset JSON")
}

fn read_fac_workflow_yaml() -> serde_yaml::Value {
    let path = repo_root().join(".github/workflows/forge-admission-cycle.yml");
    let raw = std::fs::read_to_string(&path).expect("read FAC workflow");
    serde_yaml::from_str(&raw).expect("parse FAC workflow YAML")
}

fn read_fac_push_source() -> String {
    let path = repo_root().join("crates/apm2-cli/src/commands/fac_review/push.rs");
    std::fs::read_to_string(path).expect("read fac push source")
}

fn required_status_contexts(ruleset: &serde_json::Value) -> BTreeSet<String> {
    let rules = ruleset
        .get("rules")
        .and_then(serde_json::Value::as_array)
        .expect("rules array");
    let required_rule = rules
        .iter()
        .find(|rule| {
            rule.get("type").and_then(serde_json::Value::as_str) == Some("required_status_checks")
        })
        .expect("required_status_checks rule");
    let checks = required_rule
        .get("parameters")
        .and_then(|value| value.get("required_status_checks"))
        .and_then(serde_json::Value::as_array)
        .expect("required_status_checks array");

    checks
        .iter()
        .map(|check| {
            check
                .get("context")
                .and_then(serde_json::Value::as_str)
                .expect("status context")
                .to_string()
        })
        .collect()
}

fn strict_required_status_policy(ruleset: &serde_json::Value) -> bool {
    let rules = ruleset
        .get("rules")
        .and_then(serde_json::Value::as_array)
        .expect("rules array");
    let required_rule = rules
        .iter()
        .find(|rule| {
            rule.get("type").and_then(serde_json::Value::as_str) == Some("required_status_checks")
        })
        .expect("required_status_checks rule");
    required_rule
        .get("parameters")
        .and_then(|value| value.get("strict_required_status_checks_policy"))
        .and_then(serde_json::Value::as_bool)
        .expect("strict_required_status_checks_policy bool")
}

fn workflow_has_job(workflow: &serde_yaml::Value, job_name: &str) -> bool {
    let jobs = workflow_jobs(workflow);
    let job_key = serde_yaml::Value::String(job_name.to_string());
    jobs.contains_key(&job_key)
}

fn workflow_jobs(workflow: &serde_yaml::Value) -> &serde_yaml::Mapping {
    workflow
        .get("jobs")
        .and_then(serde_yaml::Value::as_mapping)
        .expect("jobs map")
}

fn workflow_on_value(workflow: &serde_yaml::Value) -> &serde_yaml::Value {
    let root = workflow.as_mapping().expect("workflow root mapping");
    let on_key = serde_yaml::Value::String("on".to_string());
    if let Some(value) = root.get(&on_key) {
        return value;
    }
    // YAML 1.1 may parse bare `on` as boolean true.
    let legacy_on_key = serde_yaml::Value::Bool(true);
    root.get(&legacy_on_key).expect("workflow trigger key `on`")
}

fn workflow_trigger_keys(workflow: &serde_yaml::Value) -> BTreeSet<String> {
    match workflow_on_value(workflow) {
        serde_yaml::Value::String(trigger) => BTreeSet::from([trigger.trim().to_ascii_lowercase()]),
        serde_yaml::Value::Sequence(triggers) => triggers
            .iter()
            .filter_map(serde_yaml::Value::as_str)
            .map(|trigger| trigger.trim().to_ascii_lowercase())
            .collect(),
        serde_yaml::Value::Mapping(triggers) => triggers
            .keys()
            .filter_map(serde_yaml::Value::as_str)
            .map(|trigger| trigger.trim().to_ascii_lowercase())
            .collect(),
        _ => panic!("unsupported workflow trigger shape for `on`"),
    }
}

fn workflow_run_commands(workflow: &serde_yaml::Value) -> Vec<String> {
    let jobs = workflow_jobs(workflow);
    let mut commands = Vec::new();
    for job in jobs.values() {
        let Some(steps) = job.get("steps").and_then(serde_yaml::Value::as_sequence) else {
            continue;
        };
        for step in steps {
            let Some(run) = step.get("run").and_then(serde_yaml::Value::as_str) else {
                continue;
            };
            if !run.trim().is_empty() {
                commands.push(run.to_string());
            }
        }
    }
    commands
}

fn contains_shell_word(command: &str, word: &str) -> bool {
    command
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '-' || ch == '_'))
        .any(|token| token == word)
}

fn command_mentions_any(command: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| command.contains(needle))
}

fn executable_script_lines(command: &str) -> Vec<String> {
    command
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter(|line| !line.starts_with('#'))
        .filter(|line| {
            !line.eq_ignore_ascii_case("then")
                && !line.eq_ignore_ascii_case("fi")
                && !line.starts_with("if ")
                && !line.starts_with("if[")
                && !line.starts_with("elif ")
                && !line.starts_with("else")
        })
        .filter(|line| !line.starts_with("echo "))
        .map(str::to_ascii_lowercase)
        .collect()
}

fn command_runs_fac_computation(command: &str) -> bool {
    executable_script_lines(command).iter().any(|line| {
        let mentions_fac = contains_shell_word(line, "fac");
        if !mentions_fac {
            return false;
        }

        let mentions_apm2_cli = line.contains("apm2-cli");
        let mentions_apm2_binary = contains_shell_word(line, "apm2");
        let direct_apm2_fac = mentions_apm2_cli || mentions_apm2_binary;
        let cargo_runs_apm2_cli =
            line.contains("cargo") && contains_shell_word(line, "run") && mentions_apm2_cli;

        cargo_runs_apm2_cli || direct_apm2_fac
    })
}

fn workflow_permissions(workflow: &serde_yaml::Value) -> &serde_yaml::Mapping {
    workflow
        .get("permissions")
        .and_then(serde_yaml::Value::as_mapping)
        .expect("permissions mapping")
}

fn all_permission_values_read_only(permissions: &serde_yaml::Mapping) -> bool {
    permissions.values().all(|value| {
        value.as_str().is_some_and(|permission| {
            permission.eq_ignore_ascii_case("read") || permission.eq_ignore_ascii_case("read-all")
        })
    })
}

fn workflow_permission_violations(workflow: &serde_yaml::Value) -> Vec<String> {
    let mut violations = Vec::new();
    let top_level_permissions = workflow_permissions(workflow);
    if !all_permission_values_read_only(top_level_permissions) {
        violations.push("permissions".to_string());
    }

    let jobs = workflow_jobs(workflow);
    for (job_name, job_value) in jobs {
        let Some(job_permissions) = job_value.get("permissions") else {
            continue;
        };
        let Some(job_permissions_map) = job_permissions.as_mapping() else {
            violations.push(format!(
                "jobs.{}.permissions",
                job_name.as_str().unwrap_or("<non-string-job>")
            ));
            continue;
        };
        if !all_permission_values_read_only(job_permissions_map) {
            violations.push(format!(
                "jobs.{}.permissions",
                job_name.as_str().unwrap_or("<non-string-job>")
            ));
        }
    }
    violations
}

fn command_intends_github_mutation(command: &str) -> bool {
    let lower = command.to_ascii_lowercase();
    if [
        "gh pr merge",
        "gh pr edit",
        "gh pr comment",
        "gh pr review",
        "gh release create",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
    {
        return true;
    }

    if lower.contains("gh api")
        && command_mentions_any(
            &lower,
            &[
                "--method post",
                "--method=post",
                "--method put",
                "--method=put",
                "--method patch",
                "--method=patch",
                "--method delete",
                "--method=delete",
                "-x post",
                "-xpost",
                "-x put",
                "-xput",
                "-x patch",
                "-xpatch",
                "-x delete",
                "-xdelete",
            ],
        )
    {
        return true;
    }

    if lower.contains("curl")
        && lower.contains("api.github.com")
        && command_mentions_any(
            &lower,
            &[
                "-x post",
                "-xpost",
                "-x put",
                "-xput",
                "-x patch",
                "-xpatch",
                "-x delete",
                "-xdelete",
            ],
        )
    {
        return true;
    }

    false
}

#[test]
fn protect_main_requires_only_fac_status_context() {
    let ruleset = read_ruleset_json();
    let contexts = required_status_contexts(&ruleset);

    let expected = BTreeSet::from(["apm2 / Forge Admission Cycle".to_string()]);
    assert_eq!(contexts, expected);
}

#[test]
fn protect_main_enables_strict_required_status_checks_policy() {
    let ruleset = read_ruleset_json();
    assert!(strict_required_status_policy(&ruleset));
}

#[test]
fn forge_workflow_has_projection_note_job() {
    let workflow = read_fac_workflow_yaml();
    assert!(workflow_has_job(&workflow, "projection-note"));
}

#[test]
fn forge_workflow_permissions_are_read_only_projection() {
    let workflow = read_fac_workflow_yaml();
    let violations = workflow_permission_violations(&workflow);

    assert!(
        violations.is_empty(),
        "projection workflow permissions must stay read-only: {violations:?}"
    );
}

#[test]
fn forge_workflow_does_not_compute_fac_with_rust_binary_or_pr_triggers() {
    let workflow = read_fac_workflow_yaml();
    let triggers = workflow_trigger_keys(&workflow);
    assert!(triggers.contains("workflow_dispatch"));
    assert!(
        !triggers.contains("pull_request"),
        "workflow must not trigger on pull_request"
    );
    assert!(
        !triggers.contains("pull_request_target"),
        "workflow must not trigger on pull_request_target"
    );

    let fac_compute_commands = workflow_run_commands(&workflow)
        .into_iter()
        .filter(|run| command_runs_fac_computation(run))
        .collect::<Vec<_>>();
    assert!(
        fac_compute_commands.is_empty(),
        "workflow must not run FAC computation commands: {fac_compute_commands:?}"
    );
}

#[test]
fn fac_push_does_not_enable_github_auto_merge() {
    let source = read_fac_push_source();
    assert!(
        !source.contains("enable_auto_merge("),
        "fac push must not call GitHub auto-merge enablement"
    );
    assert!(
        !source.contains("gh pr merge --auto"),
        "fac push must not shell out to gh auto-merge path"
    );
}

#[test]
fn forge_workflow_does_not_mutate_github_state() {
    let workflow = read_fac_workflow_yaml();
    let mutating_commands = workflow_run_commands(&workflow)
        .into_iter()
        .filter(|run| command_intends_github_mutation(run))
        .collect::<Vec<_>>();

    assert!(
        mutating_commands.is_empty(),
        "projection workflow must not execute GitHub mutation commands: {mutating_commands:?}"
    );
}
