//! Deterministic per-gate attestation digests for FAC gate reuse.
//!
//! These digests are intentionally fail-closed: missing/unknown inputs should
//! produce cache misses, never false-positive reuse.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::OnceLock;

use apm2_core::determinism::canonicalize_json;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const ATTESTATION_SCHEMA: &str = "apm2.fac.gate_attestation.v1";
const ATTESTATION_DOMAIN: &str = "apm2.fac.gate.attestation/v1";
const POLICY_SCHEMA: &str = "apm2.fac.gate_reuse_policy.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GateResourcePolicy {
    pub quick_mode: bool,
    pub timeout_seconds: Option<u64>,
    pub memory_max: Option<String>,
    pub pids_max: Option<u64>,
    pub cpu_quota: Option<String>,
    pub bounded_runner: bool,
}

impl GateResourcePolicy {
    #[must_use]
    pub fn from_cli(
        quick_mode: bool,
        timeout_seconds: u64,
        memory_max: &str,
        pids_max: u64,
        cpu_quota: &str,
        bounded_runner: bool,
    ) -> Self {
        Self {
            quick_mode,
            timeout_seconds: Some(timeout_seconds),
            memory_max: Some(memory_max.to_string()),
            pids_max: Some(pids_max),
            cpu_quota: Some(cpu_quota.to_string()),
            bounded_runner,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GateAttestation {
    pub schema: String,
    pub sha: String,
    pub gate_name: String,
    pub command_digest: String,
    pub environment_digest: String,
    pub input_digest: String,
    pub resource_digest: String,
    pub policy_digest: String,
    pub attestation_digest: String,
}

#[derive(Debug, Clone, Serialize)]
struct EnvironmentFacts {
    kernel: String,
    rustc_version: String,
    cargo_version: String,
    clippy_version: String,
    nextest_version: String,
    systemd_run_version: String,
    rustfmt_version: String,
    sccache_version: String,
}

#[derive(Debug, Clone, Serialize)]
struct CommandFacts<'a> {
    gate_name: &'a str,
    command: &'a [String],
    env: BTreeMap<String, String>,
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn short_error_context(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw).trim().to_string()
}

fn canonical_json_bytes<T: Serialize>(value: &T) -> Vec<u8> {
    match serde_json::to_string(value) {
        Ok(json) => canonicalize_json(&json)
            .map_or_else(|_| json.into_bytes(), std::string::String::into_bytes),
        Err(err) => format!("serialize_error:{err}").into_bytes(),
    }
}

fn run_cmd_capture(program: &str, args: &[&str]) -> String {
    let output = Command::new(program).args(args).output();
    match output {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).trim().to_string(),
        Ok(out) => {
            let stderr = short_error_context(&out.stderr);
            if stderr.is_empty() {
                "unavailable".to_string()
            } else {
                format!("unavailable:{stderr}")
            }
        },
        Err(_) => "unavailable".to_string(),
    }
}

fn environment_facts() -> &'static EnvironmentFacts {
    static FACTS: OnceLock<EnvironmentFacts> = OnceLock::new();
    FACTS.get_or_init(|| EnvironmentFacts {
        kernel: run_cmd_capture("uname", &["-sr"]),
        rustc_version: run_cmd_capture("rustc", &["--version"]),
        cargo_version: run_cmd_capture("cargo", &["--version"]),
        clippy_version: run_cmd_capture("cargo", &["clippy", "--version"]),
        nextest_version: run_cmd_capture("cargo", &["nextest", "--version"]),
        systemd_run_version: run_cmd_capture("systemd-run", &["--version"]),
        rustfmt_version: run_cmd_capture("rustfmt", &["--version"]),
        sccache_version: run_cmd_capture("sccache", &["--version"]),
    })
}

fn gate_input_paths(gate_name: &str) -> &'static [&'static str] {
    match gate_name {
        "rustfmt" => &[
            "Cargo.toml",
            "Cargo.lock",
            "rustfmt.toml",
            ".cargo/config.toml",
        ],
        "clippy" | "doc" => &["Cargo.toml", "Cargo.lock", ".cargo/config.toml"],
        "test" => &[
            "Cargo.toml",
            "Cargo.lock",
            ".config/nextest.toml",
            "scripts/ci/run_bounded_tests.sh",
            ".cargo/config.toml",
        ],
        "test_safety_guard" => &["scripts/ci/test_safety_guard.sh"],
        "workspace_integrity" => &["scripts/ci/workspace_integrity_guard.sh"],
        "review_artifact_lint" => &["scripts/ci/review_artifact_lint.sh"],
        _ => &[],
    }
}

fn policy_digest() -> String {
    let facts = [
        POLICY_SCHEMA,
        "merge_conflict_gate_always_recompute",
        "require_pass_status",
        "require_attestation_match",
        "require_evidence_digest",
        "quick_receipt_replay_disabled_for_full_runs",
    ];
    let canonical = canonical_json_bytes(&facts);
    sha256_hex(&canonical)
}

/// Exact-match environment variable names included in the command digest.
const ALLOWLISTED_ENV_EXACT: &[&str] = &[
    "CARGO_BUILD_JOBS",
    "CARGO_HOME",
    "CARGO_INCREMENTAL",
    "CARGO_TARGET_DIR",
    "NEXTEST_TEST_THREADS",
    "RUSTC_WRAPPER",
    "RUSTDOCFLAGS",
    "RUSTFLAGS",
    "RUSTUP_TOOLCHAIN",
];

/// Prefix patterns for environment variable names included in the command
/// digest. Any env var whose name starts with one of these prefixes is
/// captured.
const ALLOWLISTED_ENV_PREFIXES: &[&str] = &["SCCACHE_"];

fn command_digest(gate_name: &str, command: &[String]) -> String {
    let mut env_map = BTreeMap::new();

    // Exact-match variables.
    for key in ALLOWLISTED_ENV_EXACT {
        env_map.insert(
            (*key).to_string(),
            std::env::var(key).unwrap_or_else(|_| "unset".to_string()),
        );
    }

    // Prefix-matched variables (sorted deterministically via BTreeMap).
    for (key, value) in std::env::vars() {
        if ALLOWLISTED_ENV_PREFIXES
            .iter()
            .any(|prefix| key.starts_with(prefix))
        {
            env_map.entry(key).or_insert(value);
        }
    }

    let facts = CommandFacts {
        gate_name,
        command,
        env: env_map,
    };
    let canonical = canonical_json_bytes(&facts);
    sha256_hex(&canonical)
}

fn environment_digest() -> String {
    let canonical = canonical_json_bytes(environment_facts());
    sha256_hex(&canonical)
}

fn git_rev_parse(workspace_root: &Path, rev: &str) -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", rev])
        .current_dir(workspace_root)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if value.is_empty() { None } else { Some(value) }
}

fn file_sha256(path: &Path) -> Option<String> {
    let bytes = fs::read(path).ok()?;
    Some(sha256_hex(&bytes))
}

fn input_digest(workspace_root: &Path, gate_name: &str) -> String {
    #[derive(Serialize)]
    struct InputFacts {
        tree: String,
        gate_inputs: Vec<(String, String)>,
    }

    let tree_rev = ["HEAD^", "{", "tree", "}"].concat();
    let tree =
        git_rev_parse(workspace_root, &tree_rev).unwrap_or_else(|| "unavailable_tree".to_string());
    let mut gate_inputs = Vec::new();

    for rel in gate_input_paths(gate_name) {
        let abs = workspace_root.join(rel);
        if !abs.exists() {
            gate_inputs.push(((*rel).to_string(), "missing".to_string()));
            continue;
        }

        let rev_spec = format!("HEAD:{rel}");
        if let Some(blob) = git_rev_parse(workspace_root, &rev_spec) {
            gate_inputs.push(((*rel).to_string(), format!("git_blob:{blob}")));
            continue;
        }

        if let Some(hash) = file_sha256(&abs) {
            gate_inputs.push(((*rel).to_string(), format!("file_sha256:{hash}")));
            continue;
        }

        gate_inputs.push(((*rel).to_string(), "unreadable".to_string()));
    }

    gate_inputs.sort_by(|a, b| a.0.cmp(&b.0));
    let facts = InputFacts { tree, gate_inputs };
    let canonical = canonical_json_bytes(&facts);
    sha256_hex(&canonical)
}

fn resource_digest(policy: &GateResourcePolicy) -> String {
    let canonical = canonical_json_bytes(policy);
    sha256_hex(&canonical)
}

#[must_use]
pub fn short_digest(value: &str) -> String {
    value.chars().take(12).collect()
}

pub fn compute_gate_attestation(
    workspace_root: &Path,
    sha: &str,
    gate_name: &str,
    command: &[String],
    policy: &GateResourcePolicy,
) -> Result<GateAttestation, String> {
    if sha.trim().is_empty() {
        return Err("cannot compute attestation for empty SHA".to_string());
    }
    if gate_name.trim().is_empty() {
        return Err("cannot compute attestation for empty gate name".to_string());
    }
    if command.is_empty() {
        return Err(format!(
            "cannot compute attestation for gate `{gate_name}` with empty command"
        ));
    }

    let command_digest = command_digest(gate_name, command);
    let environment_digest = environment_digest();
    let input_digest = input_digest(workspace_root, gate_name);
    let resource_digest = resource_digest(policy);
    let policy_digest = policy_digest();

    let root_material = format!(
        "{ATTESTATION_DOMAIN}\n{ATTESTATION_SCHEMA}\n{sha}\n{gate_name}\n{command_digest}\n{environment_digest}\n{input_digest}\n{resource_digest}\n{policy_digest}"
    );
    let attestation_digest = sha256_hex(root_material.as_bytes());

    Ok(GateAttestation {
        schema: ATTESTATION_SCHEMA.to_string(),
        sha: sha.to_string(),
        gate_name: gate_name.to_string(),
        command_digest,
        environment_digest,
        input_digest,
        resource_digest,
        policy_digest,
        attestation_digest,
    })
}

pub fn gate_command_for_attestation(
    workspace_root: &Path,
    gate_name: &str,
    test_command_override: Option<&[String]>,
) -> Option<Vec<String>> {
    match gate_name {
        "rustfmt" => Some(vec![
            "cargo".to_string(),
            "fmt".to_string(),
            "--all".to_string(),
            "--check".to_string(),
        ]),
        "clippy" => Some(vec![
            "cargo".to_string(),
            "clippy".to_string(),
            "--workspace".to_string(),
            "--all-targets".to_string(),
            "--all-features".to_string(),
            "--".to_string(),
            "-D".to_string(),
            "warnings".to_string(),
        ]),
        "doc" => Some(vec![
            "cargo".to_string(),
            "doc".to_string(),
            "--workspace".to_string(),
            "--no-deps".to_string(),
        ]),
        "test" => test_command_override.map_or_else(
            || {
                Some(vec![
                    "cargo".to_string(),
                    "test".to_string(),
                    "--workspace".to_string(),
                ])
            },
            |value| Some(value.to_vec()),
        ),
        "test_safety_guard" => {
            let path = workspace_root.join("scripts/ci/test_safety_guard.sh");
            path.exists()
                .then(|| vec!["bash".to_string(), path.to_string_lossy().to_string()])
        },
        "workspace_integrity" => {
            let script = workspace_root.join("scripts/ci/workspace_integrity_guard.sh");
            let snapshot = workspace_root.join("target/ci/workspace_integrity.snapshot.tsv");
            script.exists().then(|| {
                vec![
                    "bash".to_string(),
                    script.to_string_lossy().to_string(),
                    "verify".to_string(),
                    "--snapshot-file".to_string(),
                    snapshot.to_string_lossy().to_string(),
                ]
            })
        },
        "review_artifact_lint" => {
            let path = workspace_root.join("scripts/ci/review_artifact_lint.sh");
            path.exists()
                .then(|| vec!["bash".to_string(), path.to_string_lossy().to_string()])
        },
        MERGE_CONFLICT_GATE_NAME => Some(vec![
            "git".to_string(),
            "merge-tree".to_string(),
            "--name-only".to_string(),
            "--messages".to_string(),
            "origin/main".to_string(),
            "HEAD".to_string(),
        ]),
        _ => None,
    }
}

pub const MERGE_CONFLICT_GATE_NAME: &str = "merge_conflict_main";

#[cfg(test)]
mod tests {
    use serde_json::{Map, Value, json};

    use super::{
        ALLOWLISTED_ENV_EXACT, ALLOWLISTED_ENV_PREFIXES, GateResourcePolicy, canonical_json_bytes,
        command_digest, compute_gate_attestation, environment_facts, gate_command_for_attestation,
        gate_input_paths,
    };

    #[test]
    fn attestation_is_stable_for_same_inputs() {
        let workspace_root = std::env::current_dir().expect("cwd");
        let command =
            gate_command_for_attestation(&workspace_root, "rustfmt", None).expect("command");
        let policy = GateResourcePolicy::from_cli(false, 600, "48G", 1536, "200%", true);

        let one = compute_gate_attestation(
            &workspace_root,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "rustfmt",
            &command,
            &policy,
        )
        .expect("attestation one");
        let two = compute_gate_attestation(
            &workspace_root,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "rustfmt",
            &command,
            &policy,
        )
        .expect("attestation two");

        assert_eq!(one.attestation_digest, two.attestation_digest);
    }

    #[test]
    fn canonical_json_bytes_normalizes_object_key_order() {
        let mut left = Map::new();
        left.insert("b".to_string(), json!(1));
        left.insert("a".to_string(), json!(2));

        let mut right = Map::new();
        right.insert("a".to_string(), json!(2));
        right.insert("b".to_string(), json!(1));

        let left_bytes = canonical_json_bytes(&Value::Object(left));
        let right_bytes = canonical_json_bytes(&Value::Object(right));
        assert_eq!(left_bytes, right_bytes);
    }

    // --- TCK-00523: .cargo/config.toml in gate input paths ---

    #[test]
    fn cargo_config_included_in_rustfmt_gate_inputs() {
        let paths = gate_input_paths("rustfmt");
        assert!(
            paths.contains(&".cargo/config.toml"),
            "rustfmt gate must include .cargo/config.toml; got: {paths:?}"
        );
    }

    #[test]
    fn cargo_config_included_in_clippy_gate_inputs() {
        let paths = gate_input_paths("clippy");
        assert!(
            paths.contains(&".cargo/config.toml"),
            "clippy gate must include .cargo/config.toml; got: {paths:?}"
        );
    }

    #[test]
    fn cargo_config_included_in_doc_gate_inputs() {
        let paths = gate_input_paths("doc");
        assert!(
            paths.contains(&".cargo/config.toml"),
            "doc gate must include .cargo/config.toml; got: {paths:?}"
        );
    }

    #[test]
    fn cargo_config_included_in_test_gate_inputs() {
        let paths = gate_input_paths("test");
        assert!(
            paths.contains(&".cargo/config.toml"),
            "test gate must include .cargo/config.toml; got: {paths:?}"
        );
    }

    // --- TCK-00523: rustfmt + sccache version in environment facts ---

    #[test]
    fn environment_facts_includes_rustfmt_version() {
        let facts = environment_facts();
        // The field must be non-empty (either a real version or "unavailable").
        assert!(
            !facts.rustfmt_version.is_empty(),
            "rustfmt_version must be populated"
        );
    }

    #[test]
    fn environment_facts_includes_sccache_version() {
        let facts = environment_facts();
        // sccache may not be installed; the field is populated regardless
        // ("unavailable" when missing).
        assert!(
            !facts.sccache_version.is_empty(),
            "sccache_version must be populated"
        );
    }

    // --- TCK-00523: extended env allowlist ---

    #[test]
    fn allowlist_contains_required_exact_vars() {
        let required = [
            "CARGO_HOME",
            "CARGO_TARGET_DIR",
            "CARGO_BUILD_JOBS",
            "NEXTEST_TEST_THREADS",
            "RUSTC_WRAPPER",
        ];
        for var in required {
            assert!(
                ALLOWLISTED_ENV_EXACT.contains(&var),
                "ALLOWLISTED_ENV_EXACT must include {var}"
            );
        }
    }

    #[test]
    fn allowlist_contains_sccache_prefix() {
        assert!(
            ALLOWLISTED_ENV_PREFIXES.contains(&"SCCACHE_"),
            "ALLOWLISTED_ENV_PREFIXES must include SCCACHE_"
        );
    }

    #[test]
    fn command_digest_is_deterministic() {
        let gate = "clippy";
        let command = vec!["cargo".to_string(), "clippy".to_string()];
        let d1 = command_digest(gate, &command);
        let d2 = command_digest(gate, &command);
        assert_eq!(d1, d2, "command_digest must be deterministic");
    }

    #[test]
    fn command_digest_differs_for_different_gates() {
        let command = vec!["cargo".to_string(), "build".to_string()];
        let d1 = command_digest("clippy", &command);
        let d2 = command_digest("doc", &command);
        assert_ne!(d1, d2, "command_digest must differ when gate name differs");
    }
}
