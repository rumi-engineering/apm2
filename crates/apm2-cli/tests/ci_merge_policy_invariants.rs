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

fn read_fac_push_source() -> String {
    let path = repo_root().join("crates/apm2-cli/src/commands/fac_review/push.rs");
    std::fs::read_to_string(path).expect("read fac push source")
}

fn required_status_contexts(ruleset: &serde_json::Value) -> BTreeSet<String> {
    let checks = required_status_rule_parameters(ruleset)
        .get("required_status_checks")
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

fn required_status_rule_parameters(
    ruleset: &serde_json::Value,
) -> &serde_json::Map<String, serde_json::Value> {
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
        .and_then(serde_json::Value::as_object)
        .expect("required_status_checks parameters")
}

#[test]
fn protect_main_requires_only_fac_status_context() {
    let ruleset = read_ruleset_json();
    let contexts = required_status_contexts(&ruleset);

    let expected = BTreeSet::from(["apm2 / Forge Admission Cycle".to_string()]);
    assert_eq!(contexts, expected);
}

#[test]
fn protect_main_omits_strict_required_status_checks_policy() {
    let ruleset = read_ruleset_json();
    let parameters = required_status_rule_parameters(&ruleset);

    assert!(
        !parameters.contains_key("strict_required_status_checks_policy"),
        "strict_required_status_checks_policy must be omitted from the local ruleset source"
    );
}

#[test]
fn forge_admission_cycle_workflow_is_absent() {
    let workflow = repo_root().join(".github/workflows/forge-admission-cycle.yml");
    assert!(
        !workflow.exists(),
        "legacy projection-only workflow must remain removed"
    );
}

#[test]
fn review_gate_directory_is_absent() {
    let review_gate_dir = repo_root().join(".github/review-gate");
    assert!(
        !review_gate_dir.exists(),
        "legacy .github/review-gate artifacts must remain removed"
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
