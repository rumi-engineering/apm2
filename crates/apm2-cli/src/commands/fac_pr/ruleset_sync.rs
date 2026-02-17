//! `apm2 fac pr ruleset-sync` — synchronize required-status ruleset policy.
//!
//! Local `.github/rulesets/protect-main.json` is authoritative for required
//! status contexts. Live GitHub ruleset state is a projection that must match.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};

use apm2_core::fac::gh_command;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::PrRulesetSyncCliArgs;
use crate::exit_codes::codes as exit_codes;

const DEFAULT_RULESET_FILE: &str = ".github/rulesets/protect-main.json";
const RULESET_SYNC_SCHEMA: &str = "apm2.fac.pr.ruleset_sync.v1";
const MAX_LOCAL_RULESET_FILE_BYTES: usize = 1024 * 1024;
const MAX_GH_API_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
struct RequiredStatusPolicy {
    contexts: BTreeSet<String>,
    strict_required_status_checks_policy: bool,
}

impl RequiredStatusPolicy {
    fn sorted_contexts(&self) -> Vec<String> {
        self.contexts.iter().cloned().collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RulesetSyncOutcome {
    pub ruleset_id: u64,
    pub drift_detected: bool,
    pub changed: bool,
    pub contexts: Vec<String>,
    pub strict_required_status_checks_policy: bool,
}

#[derive(Debug, Serialize)]
struct RulesetSyncResponse {
    schema: String,
    repo: String,
    ruleset_id: u64,
    ruleset_file: String,
    mode: String,
    drift_status: String,
    sync_action: String,
    required_status_contexts: Vec<String>,
    strict_required_status_checks_policy: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct RulesetCatalogEntry {
    id: u64,
    name: String,
    target: String,
}

pub(super) fn run_pr_ruleset_sync(args: &PrRulesetSyncCliArgs, json_output: bool) -> u8 {
    let ruleset_file = match resolve_ruleset_file_path(args.ruleset_file.as_deref()) {
        Ok(path) => path,
        Err(err) => {
            super::output_pr_error(json_output, "pr_ruleset_sync_failed", &err);
            return exit_codes::GENERIC_ERROR;
        },
    };

    let result =
        sync_required_status_ruleset(&args.repo, args.ruleset_id, Some(&ruleset_file), args.check);
    let outcome = match result {
        Ok(outcome) => outcome,
        Err(err) => {
            super::output_pr_error(json_output, "pr_ruleset_sync_failed", &err);
            return exit_codes::GENERIC_ERROR;
        },
    };

    let response = RulesetSyncResponse {
        schema: RULESET_SYNC_SCHEMA.to_string(),
        repo: args.repo.clone(),
        ruleset_id: outcome.ruleset_id,
        ruleset_file: ruleset_file.display().to_string(),
        mode: if args.check { "check" } else { "apply" }.to_string(),
        drift_status: if outcome.drift_detected {
            "drift_detected"
        } else {
            "in_sync"
        }
        .to_string(),
        sync_action: if outcome.changed { "updated" } else { "none" }.to_string(),
        required_status_contexts: outcome.contexts,
        strict_required_status_checks_policy: outcome.strict_required_status_checks_policy,
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&response).unwrap_or_else(|_| "{}".to_string())
    );

    if args.check && outcome.drift_detected {
        return exit_codes::POLICY_DENY;
    }
    exit_codes::SUCCESS
}

pub fn sync_required_status_ruleset(
    repo: &str,
    ruleset_id: Option<u64>,
    ruleset_file: Option<&Path>,
    check_only: bool,
) -> Result<RulesetSyncOutcome, String> {
    let ruleset_file = resolve_ruleset_file_path(ruleset_file)?;
    let desired_policy = read_required_status_policy_from_file(&ruleset_file)?;
    let ruleset_id = match ruleset_id {
        Some(id) => id,
        None => discover_required_status_ruleset_id(repo)?,
    };

    let live_ruleset = fetch_ruleset(repo, ruleset_id)?;
    let live_policy = read_required_status_policy_from_ruleset(
        &live_ruleset,
        &format!("live ruleset {ruleset_id}"),
    )?;

    let drift_detected = live_policy != desired_policy;
    if !drift_detected {
        return Ok(RulesetSyncOutcome {
            ruleset_id,
            drift_detected: false,
            changed: false,
            contexts: desired_policy.sorted_contexts(),
            strict_required_status_checks_policy: desired_policy
                .strict_required_status_checks_policy,
        });
    }
    if check_only {
        return Ok(RulesetSyncOutcome {
            ruleset_id,
            drift_detected: true,
            changed: false,
            contexts: desired_policy.sorted_contexts(),
            strict_required_status_checks_policy: desired_policy
                .strict_required_status_checks_policy,
        });
    }

    let payload = build_ruleset_update_payload(&live_ruleset, &desired_policy)?;
    update_ruleset(repo, ruleset_id, &payload)?;

    let verified_ruleset = fetch_ruleset(repo, ruleset_id)?;
    let verified_policy = read_required_status_policy_from_ruleset(
        &verified_ruleset,
        &format!("verified ruleset {ruleset_id}"),
    )?;
    if verified_policy != desired_policy {
        return Err(format!(
            "ruleset sync verification failed for ruleset {ruleset_id}: live policy still differs from local source of truth"
        ));
    }

    Ok(RulesetSyncOutcome {
        ruleset_id,
        drift_detected: true,
        changed: true,
        contexts: desired_policy.sorted_contexts(),
        strict_required_status_checks_policy: desired_policy.strict_required_status_checks_policy,
    })
}

pub fn load_local_required_status_contexts(
    ruleset_file: Option<&Path>,
) -> Result<Vec<String>, String> {
    let ruleset_file = resolve_ruleset_file_path(ruleset_file)?;
    let policy = read_required_status_policy_from_file(&ruleset_file)?;
    Ok(policy.sorted_contexts())
}

fn resolve_repo_root() -> Result<PathBuf, String> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .map_err(|err| format!("failed to resolve repository root: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "git rev-parse --show-toplevel failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let root = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if root.is_empty() {
        return Err("git returned empty repository root".to_string());
    }
    Ok(PathBuf::from(root))
}

fn resolve_ruleset_file_path(path: Option<&Path>) -> Result<PathBuf, String> {
    let repo_root = resolve_repo_root()?;
    let repo_root_canonical = repo_root.canonicalize().map_err(|err| {
        format!(
            "failed to canonicalize repository root {}: {err}",
            repo_root.display()
        )
    })?;

    let resolved = match path {
        Some(path) if path.is_absolute() => path.to_path_buf(),
        Some(path) => std::env::current_dir()
            .map_err(|err| format!("failed to resolve current working directory: {err}"))?
            .join(path),
        None => repo_root.join(DEFAULT_RULESET_FILE),
    };

    let metadata = std::fs::symlink_metadata(&resolved).map_err(|err| {
        format!(
            "failed to stat local ruleset file {}: {err}",
            resolved.display()
        )
    })?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "local ruleset file must not be a symlink: {}",
            resolved.display()
        ));
    }
    if !metadata.file_type().is_file() {
        return Err(format!(
            "local ruleset file must be a regular file: {}",
            resolved.display()
        ));
    }

    let resolved_canonical = resolved.canonicalize().map_err(|err| {
        format!(
            "failed to canonicalize local ruleset file {}: {err}",
            resolved.display()
        )
    })?;
    if !resolved_canonical.starts_with(&repo_root_canonical) {
        return Err(format!(
            "local ruleset file must stay within repository root {}: {}",
            repo_root_canonical.display(),
            resolved_canonical.display()
        ));
    }

    Ok(resolved_canonical)
}

fn read_required_status_policy_from_file(path: &Path) -> Result<RequiredStatusPolicy, String> {
    let raw = crate::commands::fac_secure_io::read_bounded(path, MAX_LOCAL_RULESET_FILE_BYTES)
        .map_err(|err| format!("failed to read ruleset file {}: {err}", path.display()))?;
    let value: Value = serde_json::from_slice(&raw)
        .map_err(|err| format!("failed to parse ruleset JSON {}: {err}", path.display()))?;
    read_required_status_policy_from_ruleset(&value, &path.display().to_string())
}

fn read_required_status_policy_from_ruleset(
    ruleset: &Value,
    source: &str,
) -> Result<RequiredStatusPolicy, String> {
    let rules = ruleset
        .get("rules")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{source}: missing `rules` array"))?;
    let required_rule = rules
        .iter()
        .find(|rule| rule.get("type").and_then(Value::as_str) == Some("required_status_checks"))
        .ok_or_else(|| format!("{source}: missing `required_status_checks` rule"))?;
    let params = required_rule
        .get("parameters")
        .and_then(Value::as_object)
        .ok_or_else(|| format!("{source}: required_status_checks rule missing parameters"))?;
    let checks = params
        .get("required_status_checks")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{source}: required_status_checks parameters missing checks"))?;
    let mut contexts = BTreeSet::new();
    for check in checks {
        let context = check
            .get("context")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("{source}: required_status_checks entry missing context"))?;
        contexts.insert(context.to_string());
    }
    if contexts.is_empty() {
        return Err(format!("{source}: required_status_checks cannot be empty"));
    }
    let strict = params
        .get("strict_required_status_checks_policy")
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("{source}: missing strict_required_status_checks_policy boolean"))?;

    Ok(RequiredStatusPolicy {
        contexts,
        strict_required_status_checks_policy: strict,
    })
}

fn discover_required_status_ruleset_id(repo: &str) -> Result<u64, String> {
    let catalog = fetch_ruleset_catalog(repo)?;
    if catalog.is_empty() {
        return Err(format!("no rulesets found for repository `{repo}`"));
    }

    let branch_candidates = catalog
        .into_iter()
        .filter(|entry| entry.target.eq_ignore_ascii_case("branch"))
        .collect::<Vec<_>>();
    if branch_candidates.is_empty() {
        return Err(format!(
            "no branch-target rulesets found for repository `{repo}`"
        ));
    }

    let mut required_candidates = Vec::new();
    for entry in branch_candidates {
        let ruleset = fetch_ruleset(repo, entry.id)?;
        if read_required_status_policy_from_ruleset(&ruleset, &format!("live ruleset {}", entry.id))
            .is_ok()
        {
            required_candidates.push((entry, ruleset));
        }
    }
    if required_candidates.is_empty() {
        return Err(format!(
            "no branch ruleset with required_status_checks found for repository `{repo}`"
        ));
    }
    if required_candidates.len() == 1 {
        return Ok(required_candidates[0].0.id);
    }

    let main_candidates = required_candidates
        .into_iter()
        .filter(|(_, ruleset)| ruleset_targets_main_branch(ruleset))
        .collect::<Vec<_>>();
    if main_candidates.len() == 1 {
        return Ok(main_candidates[0].0.id);
    }

    let ambiguous = if main_candidates.is_empty() {
        fetch_ruleset_catalog(repo)?
            .into_iter()
            .filter(|entry| entry.target.eq_ignore_ascii_case("branch"))
            .map(|entry| format!("{} ({})", entry.id, entry.name))
            .collect::<Vec<_>>()
    } else {
        main_candidates
            .into_iter()
            .map(|(entry, _)| format!("{} ({})", entry.id, entry.name))
            .collect::<Vec<_>>()
    };
    Err(format!(
        "ambiguous required-status branch ruleset selection for `{repo}`: {}. pass --ruleset-id explicitly",
        ambiguous.join(", ")
    ))
}

fn ruleset_targets_main_branch(ruleset: &Value) -> bool {
    let includes = ruleset
        .get("conditions")
        .and_then(|value| value.get("ref_name"))
        .and_then(|value| value.get("include"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    includes.iter().any(|item| {
        item.as_str().is_some_and(|value| {
            value.eq_ignore_ascii_case("refs/heads/main") || value == "~DEFAULT_BRANCH"
        })
    })
}

fn parse_bounded_json_response<T: DeserializeOwned>(
    bytes: &[u8],
    max_bytes: usize,
    source: &str,
) -> Result<T, String> {
    if bytes.len() > max_bytes {
        return Err(format!(
            "{source} response too large: {} > {}",
            bytes.len(),
            max_bytes
        ));
    }
    serde_json::from_slice::<T>(bytes)
        .map_err(|err| format!("failed to parse {source} response JSON: {err}"))
}

fn fetch_ruleset_catalog(repo: &str) -> Result<Vec<RulesetCatalogEntry>, String> {
    let endpoint = format!("/repos/{repo}/rulesets");
    let output = gh_command()
        .args(["api", &endpoint])
        .output()
        .map_err(|err| format!("failed to execute gh api for ruleset list: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "gh api failed listing rulesets for `{repo}`: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    parse_bounded_json_response::<Vec<RulesetCatalogEntry>>(
        &output.stdout,
        MAX_GH_API_RESPONSE_BYTES,
        "ruleset list",
    )
}

fn fetch_ruleset(repo: &str, ruleset_id: u64) -> Result<Value, String> {
    let endpoint = format!("/repos/{repo}/rulesets/{ruleset_id}");
    let output = gh_command()
        .args(["api", &endpoint])
        .output()
        .map_err(|err| format!("failed to execute gh api for ruleset {ruleset_id}: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "gh api failed fetching ruleset {ruleset_id}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    parse_bounded_json_response::<Value>(
        &output.stdout,
        MAX_GH_API_RESPONSE_BYTES,
        &format!("ruleset {ruleset_id}"),
    )
}

fn build_ruleset_update_payload(
    live_ruleset: &Value,
    desired_policy: &RequiredStatusPolicy,
) -> Result<Value, String> {
    let live_obj = live_ruleset
        .as_object()
        .ok_or_else(|| "live ruleset JSON root must be an object".to_string())?;

    let mut payload = serde_json::Map::new();
    for field in [
        "name",
        "target",
        "enforcement",
        "conditions",
        "rules",
        "bypass_actors",
    ] {
        let value = live_obj
            .get(field)
            .cloned()
            .ok_or_else(|| format!("live ruleset missing required field `{field}`"))?;
        payload.insert(field.to_string(), value);
    }

    let mut payload_value = Value::Object(payload);
    apply_required_status_policy(&mut payload_value, desired_policy)?;
    Ok(payload_value)
}

fn apply_required_status_policy(
    payload: &mut Value,
    desired_policy: &RequiredStatusPolicy,
) -> Result<(), String> {
    let rules = payload
        .get_mut("rules")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| "ruleset payload missing `rules` array".to_string())?;
    let Some(required_rule) = rules
        .iter_mut()
        .find(|rule| rule.get("type").and_then(Value::as_str) == Some("required_status_checks"))
    else {
        return Err("ruleset payload missing required_status_checks rule".to_string());
    };

    let params = required_rule
        .get_mut("parameters")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "required_status_checks rule missing parameters object".to_string())?;

    let mut existing_checks_by_context = BTreeMap::new();
    if let Some(existing_checks) = params
        .get("required_status_checks")
        .and_then(Value::as_array)
    {
        for check in existing_checks {
            if let Some(context) = check.get("context").and_then(Value::as_str) {
                existing_checks_by_context.insert(context.to_string(), check.clone());
            }
        }
    }

    let mut synced_checks = Vec::with_capacity(desired_policy.contexts.len());
    for context in desired_policy.sorted_contexts() {
        let mut check = existing_checks_by_context
            .remove(&context)
            .unwrap_or_else(|| Value::Object(serde_json::Map::new()));
        if let Some(obj) = check.as_object_mut() {
            obj.insert("context".to_string(), Value::String(context));
        } else {
            check = json!({ "context": context });
        }
        synced_checks.push(check);
    }

    params.insert(
        "required_status_checks".to_string(),
        Value::Array(synced_checks),
    );
    params.insert(
        "strict_required_status_checks_policy".to_string(),
        Value::Bool(desired_policy.strict_required_status_checks_policy),
    );
    Ok(())
}

fn update_ruleset(repo: &str, ruleset_id: u64, payload: &Value) -> Result<(), String> {
    let mut payload_file =
        tempfile::NamedTempFile::new().map_err(|err| format!("tempfile creation failed: {err}"))?;
    let payload_text = serde_json::to_string(payload)
        .map_err(|err| format!("failed to serialize ruleset sync payload: {err}"))?;
    payload_file
        .write_all(payload_text.as_bytes())
        .map_err(|err| format!("failed to write ruleset sync payload: {err}"))?;
    payload_file
        .flush()
        .map_err(|err| format!("failed to flush ruleset sync payload: {err}"))?;

    let endpoint = format!("/repos/{repo}/rulesets/{ruleset_id}");
    let input_path = payload_file.path().display().to_string();
    let output = gh_command()
        .args(["api", "--method", "PUT", &endpoint, "--input", &input_path])
        .output()
        .map_err(|err| {
            format!("failed to execute gh api update for ruleset {ruleset_id}: {err}")
        })?;
    if !output.status.success() {
        return Err(format!(
            "gh api failed updating ruleset {ruleset_id}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::symlink;

    use serde_json::json;
    use tempfile::{NamedTempFile, tempdir};

    use super::{
        MAX_GH_API_RESPONSE_BYTES, MAX_LOCAL_RULESET_FILE_BYTES, RequiredStatusPolicy,
        apply_required_status_policy, build_ruleset_update_payload, parse_bounded_json_response,
        read_required_status_policy_from_file, read_required_status_policy_from_ruleset,
        resolve_ruleset_file_path, ruleset_targets_main_branch,
    };

    #[test]
    fn read_required_status_policy_extracts_contexts_and_strict_flag() {
        let ruleset = json!({
            "rules": [
                {
                    "type": "required_status_checks",
                    "parameters": {
                        "required_status_checks": [
                            { "context": "apm2 / Forge Admission Cycle" }
                        ],
                        "strict_required_status_checks_policy": true
                    }
                }
            ]
        });

        let policy =
            read_required_status_policy_from_ruleset(&ruleset, "fixture").expect("policy parsed");
        assert_eq!(
            policy.sorted_contexts(),
            vec!["apm2 / Forge Admission Cycle".to_string()]
        );
        assert!(policy.strict_required_status_checks_policy);
    }

    #[test]
    fn read_required_status_policy_rejects_empty_context_set() {
        let ruleset = json!({
            "rules": [
                {
                    "type": "required_status_checks",
                    "parameters": {
                        "required_status_checks": [],
                        "strict_required_status_checks_policy": true
                    }
                }
            ]
        });
        let err = read_required_status_policy_from_ruleset(&ruleset, "fixture")
            .expect_err("empty policy must fail");
        assert!(err.contains("cannot be empty"));
    }

    #[test]
    fn apply_required_status_policy_replaces_contexts_and_preserves_existing_check_fields() {
        let mut payload = json!({
            "rules": [
                {
                    "type": "required_status_checks",
                    "parameters": {
                        "required_status_checks": [
                            {
                                "context": "Guardian Intelligence / Barrier",
                                "integration_id": 11
                            },
                            {
                                "context": "apm2 / Forge Admission Cycle",
                                "integration_id": 22
                            }
                        ],
                        "strict_required_status_checks_policy": false,
                        "do_not_enforce_on_create": false
                    }
                },
                {
                    "type": "pull_request",
                    "parameters": {
                        "required_approving_review_count": 0
                    }
                }
            ]
        });

        let desired = RequiredStatusPolicy {
            contexts: std::iter::once("apm2 / Forge Admission Cycle".to_string()).collect(),
            strict_required_status_checks_policy: true,
        };
        apply_required_status_policy(&mut payload, &desired).expect("policy applied");

        let checks = payload["rules"][0]["parameters"]["required_status_checks"]
            .as_array()
            .expect("checks array");
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0]["context"], "apm2 / Forge Admission Cycle");
        assert_eq!(checks[0]["integration_id"], 22);
        assert_eq!(
            payload["rules"][0]["parameters"]["strict_required_status_checks_policy"],
            true
        );
        assert_eq!(
            payload["rules"][0]["parameters"]["do_not_enforce_on_create"],
            false
        );
        assert_eq!(
            payload["rules"][1]["type"].as_str(),
            Some("pull_request"),
            "non-required rules must be preserved"
        );
    }

    #[test]
    fn build_ruleset_update_payload_keeps_put_allowed_fields_only() {
        let live = json!({
            "id": 1234,
            "node_id": "abc",
            "name": "FAC + Barrier Admission",
            "target": "branch",
            "enforcement": "active",
            "conditions": {
                "ref_name": {
                    "include": ["refs/heads/main"],
                    "exclude": []
                }
            },
            "rules": [
                {
                    "type": "required_status_checks",
                    "parameters": {
                        "required_status_checks": [
                            { "context": "Guardian Intelligence / Barrier" }
                        ],
                        "strict_required_status_checks_policy": false
                    }
                }
            ],
            "bypass_actors": []
        });
        let desired = RequiredStatusPolicy {
            contexts: std::iter::once("apm2 / Forge Admission Cycle".to_string()).collect(),
            strict_required_status_checks_policy: true,
        };
        let payload =
            build_ruleset_update_payload(&live, &desired).expect("payload should be generated");

        let obj = payload.as_object().expect("payload object");
        assert!(obj.contains_key("name"));
        assert!(obj.contains_key("target"));
        assert!(obj.contains_key("enforcement"));
        assert!(obj.contains_key("conditions"));
        assert!(obj.contains_key("rules"));
        assert!(obj.contains_key("bypass_actors"));
        assert!(!obj.contains_key("id"));
        assert!(!obj.contains_key("node_id"));
    }

    #[test]
    fn ruleset_targets_main_branch_accepts_default_branch_placeholder() {
        let ruleset = json!({
            "conditions": {
                "ref_name": {
                    "include": ["~DEFAULT_BRANCH"],
                    "exclude": []
                }
            }
        });
        assert!(ruleset_targets_main_branch(&ruleset));
    }

    #[test]
    fn resolve_ruleset_file_path_rejects_outside_repo_root() {
        let temp = NamedTempFile::new().expect("temp file");
        let err =
            resolve_ruleset_file_path(Some(temp.path())).expect_err("outside-repo file must fail");
        assert!(err.contains("must stay within repository root"));
    }

    #[cfg(unix)]
    #[test]
    fn resolve_ruleset_file_path_rejects_symlink() {
        let dir = tempdir().expect("temp dir");
        let target = dir.path().join("target.json");
        let link = dir.path().join("link.json");
        fs::write(&target, "{}").expect("write target");
        symlink(&target, &link).expect("create symlink");

        let err = resolve_ruleset_file_path(Some(&link)).expect_err("symlink must fail");
        assert!(err.contains("must not be a symlink"));
    }

    #[test]
    fn read_required_status_policy_from_file_rejects_oversized_input() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("oversized.json");
        let oversized = vec![b'a'; MAX_LOCAL_RULESET_FILE_BYTES + 1];
        fs::write(&path, oversized).expect("write oversized file");

        let err =
            read_required_status_policy_from_file(&path).expect_err("oversized file must fail");
        assert!(err.contains("too large"));
    }

    #[test]
    fn parse_bounded_json_response_rejects_oversized_payload() {
        let payload = vec![b' '; MAX_GH_API_RESPONSE_BYTES + 1];
        let err = parse_bounded_json_response::<serde_json::Value>(
            &payload,
            MAX_GH_API_RESPONSE_BYTES,
            "fixture",
        )
        .expect_err("oversized payload must fail");
        assert!(err.contains("response too large"));
    }
}
