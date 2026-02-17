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

fn read_fac_workflow_text() -> String {
    let path = repo_root().join(".github/workflows/forge-admission-cycle.yml");
    std::fs::read_to_string(&path).expect("read FAC workflow")
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
    let jobs = workflow
        .get("jobs")
        .and_then(serde_yaml::Value::as_mapping)
        .expect("jobs map");
    let job_key = serde_yaml::Value::String(job_name.to_string());
    jobs.contains_key(&job_key)
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
fn forge_workflow_does_not_compute_fac_with_rust_binary_or_pr_triggers() {
    let workflow = read_fac_workflow_text();
    let lower = workflow.to_ascii_lowercase();

    assert!(lower.contains("workflow_dispatch"));
    assert!(!lower.contains("pull_request_target"));
    assert!(!lower.contains("cargo run --quiet -p apm2-cli"));
    assert!(!lower.contains("fac preflight"));
}
