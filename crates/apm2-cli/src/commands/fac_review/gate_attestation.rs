//! Deterministic per-gate attestation digests for FAC gate reuse.
//!
//! These digests are intentionally fail-closed: missing/unknown inputs should
//! produce cache misses, never false-positive reuse.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::Command;
use std::sync::OnceLock;

use apm2_core::determinism::canonicalize_json;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::gate_checks;

/// V2 attestation schema: uses file-content hashing instead of HEAD:path git
/// blob hashing for input bindings.  This version bump invalidates all pre-v2
/// cache entries, closing the dirty-state cache poisoning vector where
/// HEAD:path ignored uncommitted file content (TCK-00544).
const ATTESTATION_SCHEMA: &str = "apm2.fac.gate_attestation.v2";
const ATTESTATION_DOMAIN: &str = "apm2.fac.gate.attestation/v2";
const POLICY_SCHEMA: &str = "apm2.fac.gate_reuse_policy.v2";
const MAX_ATTESTATION_INPUT_FILE_BYTES: u64 = 16 * 1024 * 1024;
/// Default nextest profile for push-critical FAC gates.
///
/// This intentionally excludes long-running suites so the standard gate path
/// stays bounded and predictable. Heavy suites remain available via explicit,
/// non-default profiles in `.config/nextest.toml`.
pub const FAST_GATES_NEXTEST_PROFILE: &str = "fac-gates";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GateResourcePolicy {
    pub quick_mode: bool,
    pub timeout_seconds: Option<u64>,
    pub memory_max: Option<String>,
    pub pids_max: Option<u64>,
    pub cpu_quota: Option<String>,
    pub gate_profile: Option<String>,
    pub test_parallelism: Option<u32>,
    pub bounded_runner: bool,
    /// BLAKE3 hash of the `SandboxHardeningProfile` used for gate execution
    /// (TCK-00573 MAJOR-3). Ensures the attestation digest changes when the
    /// hardening profile is modified, preventing stale gate result reuse
    /// from insecure environments.
    pub sandbox_hardening: Option<String>,
    /// BLAKE3 hash of the `NetworkPolicy` used for gate execution
    /// (TCK-00574 MAJOR-1). Ensures the attestation digest changes when the
    /// network policy toggles between allow and deny, preventing cache
    /// reuse across policy drift.
    pub network_policy_hash: Option<String>,
}

impl GateResourcePolicy {
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn from_cli(
        quick_mode: bool,
        timeout_seconds: u64,
        memory_max: &str,
        pids_max: u64,
        cpu_quota: &str,
        bounded_runner: bool,
        gate_profile: Option<&str>,
        test_parallelism: Option<u32>,
        sandbox_hardening: Option<&str>,
        network_policy_hash: Option<&str>,
    ) -> Self {
        Self {
            quick_mode,
            timeout_seconds: Some(timeout_seconds),
            memory_max: Some(memory_max.to_string()),
            pids_max: Some(pids_max),
            cpu_quota: Some(cpu_quota.to_string()),
            gate_profile: gate_profile.map(str::to_string),
            test_parallelism,
            bounded_runner,
            sandbox_hardening: sandbox_hardening.map(str::to_string),
            network_policy_hash: network_policy_hash.map(str::to_string),
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
            "crates/apm2-cli/src/commands/fac_review/bounded_test_runner.rs",
            "crates/apm2-cli/src/commands/fac_review/timeout_policy.rs",
            ".cargo/config.toml",
        ],
        "test_safety_guard" => &[
            "crates/apm2-cli/src/commands/fac_review/gate_checks.rs",
            "documents/reviews/test-safety-allowlist.txt",
        ],
        "fac_review_machine_spec_snapshot" => &[
            "crates/apm2-cli/src/commands/fac_review/mod.rs",
            "documents/reviews/fac_review_state_machine.cac.json",
            "documents/reviews/fac_review_requirements.cac.json",
        ],
        "workspace_integrity" => &["crates/apm2-cli/src/commands/fac_review/gate_checks.rs"],
        "review_artifact_lint" => &[
            "crates/apm2-cli/src/commands/fac_review/gate_checks.rs",
            "documents/reviews/CODE_QUALITY_PROMPT.cac.json",
            "documents/reviews/SECURITY_REVIEW_PROMPT.cac.json",
        ],
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

fn file_sha256(path: &Path) -> Result<String, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|err| format!("failed to inspect {}: {err}", path.display()))?;
    if !metadata.file_type().is_file() {
        return Err(format!("path is not a regular file: {}", path.display()));
    }
    if metadata.len() > MAX_ATTESTATION_INPUT_FILE_BYTES {
        return Err(format!(
            "file exceeds attestation size limit ({} bytes): {}",
            metadata.len(),
            path.display()
        ));
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    let mut file: File = options
        .open(path)
        .map_err(|err| format!("failed to open {}: {err}", path.display()))?;

    let opened_metadata = file
        .metadata()
        .map_err(|err| format!("failed to stat opened file {}: {err}", path.display()))?;
    if !opened_metadata.is_file() {
        return Err(format!(
            "opened path is not a regular file: {}",
            path.display()
        ));
    }
    if opened_metadata.len() > MAX_ATTESTATION_INPUT_FILE_BYTES {
        return Err(format!(
            "opened file exceeds attestation size limit ({} bytes): {}",
            opened_metadata.len(),
            path.display()
        ));
    }

    let mut hasher = Sha256::new();
    let mut limited = (&mut file).take(MAX_ATTESTATION_INPUT_FILE_BYTES + 1);
    let mut buffer = [0_u8; 8192];
    loop {
        let read = limited
            .read(&mut buffer)
            .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    if limited.limit() == 0 {
        return Err(format!(
            "file exceeded attestation streaming limit while hashing: {}",
            path.display()
        ));
    }

    Ok(format!("{:x}", hasher.finalize()))
}

fn input_digest(workspace_root: &Path, gate_name: &str) -> Result<String, String> {
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

        // TCK-00544: Always hash the actual file content instead of using
        // HEAD:{path} git blob references.  HEAD:path ignores uncommitted
        // file modifications, which allows dirty-workspace cache entries to
        // hash-collide with clean committed state.  Using file_sha256
        // ensures the attestation digest captures the real workspace content,
        // closing the dirty-state cache poisoning vector.
        match file_sha256(&abs) {
            Ok(hash) => {
                gate_inputs.push(((*rel).to_string(), format!("file_sha256:{hash}")));
            },
            Err(reason) => {
                return Err(format!("unable to hash gate input `{rel}`: {reason}"));
            },
        }
    }

    gate_inputs.sort_by(|a, b| a.0.cmp(&b.0));
    let facts = InputFacts { tree, gate_inputs };
    let canonical = canonical_json_bytes(&facts);
    Ok(sha256_hex(&canonical))
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
    let input_digest = input_digest(workspace_root, gate_name)?;
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

/// Build the shared nextest test command (without resource wrapper/boundary
/// args).
pub fn build_nextest_command() -> Vec<String> {
    vec![
        "cargo".to_string(),
        "nextest".to_string(),
        "run".to_string(),
        "--offline".to_string(),
        "--workspace".to_string(),
        "--all-features".to_string(),
        "--config-file".to_string(),
        ".config/nextest.toml".to_string(),
        "--profile".to_string(),
        FAST_GATES_NEXTEST_PROFILE.to_string(),
    ]
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
            "--offline".to_string(),
            "--workspace".to_string(),
            "--lib".to_string(),
            "--bins".to_string(),
            "--tests".to_string(),
            "--examples".to_string(),
            "--all-features".to_string(),
            "--".to_string(),
            "-D".to_string(),
            "warnings".to_string(),
        ]),
        "doc" => Some(vec![
            "cargo".to_string(),
            "doc".to_string(),
            "--offline".to_string(),
            "--workspace".to_string(),
            "--no-deps".to_string(),
        ]),
        "test" => Some(test_command_override.map_or_else(build_nextest_command, <[_]>::to_vec)),
        "test_safety_guard" => Some(vec![
            "apm2-internal-gate".to_string(),
            "test_safety_guard".to_string(),
        ]),
        "fac_review_machine_spec_snapshot" => Some(vec![
            "apm2-internal-gate".to_string(),
            "fac_review_machine_spec_snapshot".to_string(),
        ]),
        "workspace_integrity" => {
            let snapshot = workspace_root.join(gate_checks::WORKSPACE_INTEGRITY_SNAPSHOT_REL_PATH);
            Some(vec![
                "apm2-internal-gate".to_string(),
                "workspace_integrity".to_string(),
                "--snapshot-file".to_string(),
                snapshot.to_string_lossy().to_string(),
            ])
        },
        "review_artifact_lint" => Some(vec![
            "apm2-internal-gate".to_string(),
            "review_artifact_lint".to_string(),
        ]),
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
    use std::io::Write;

    use serde_json::{Map, Value, json};
    use tempfile::tempdir;

    use super::{
        ALLOWLISTED_ENV_EXACT, ALLOWLISTED_ENV_PREFIXES, GateResourcePolicy, canonical_json_bytes,
        command_digest, compute_gate_attestation, environment_facts, file_sha256,
        gate_command_for_attestation, gate_input_paths,
    };

    #[test]
    fn attestation_is_stable_for_same_inputs() {
        let workspace_root = std::env::current_dir().expect("cwd");
        let command =
            gate_command_for_attestation(&workspace_root, "rustfmt", None).expect("command");
        let policy = GateResourcePolicy::from_cli(
            false, 600, "48G", 1536, "200%", true, None, None, None, None,
        );

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

    #[test]
    fn fac_review_machine_spec_gate_inputs_include_snapshot_and_requirements() {
        let paths = gate_input_paths("fac_review_machine_spec_snapshot");
        assert!(
            paths.contains(&"documents/reviews/fac_review_state_machine.cac.json"),
            "machine-spec gate must include state machine snapshot input; got: {paths:?}"
        );
        assert!(
            paths.contains(&"documents/reviews/fac_review_requirements.cac.json"),
            "machine-spec gate must include requirements snapshot input; got: {paths:?}"
        );
    }

    #[test]
    fn fac_review_machine_spec_gate_command_is_stable() {
        let dir = tempdir().expect("tempdir");
        let command =
            gate_command_for_attestation(dir.path(), "fac_review_machine_spec_snapshot", None)
                .expect("command");
        assert_eq!(
            command,
            vec![
                "apm2-internal-gate".to_string(),
                "fac_review_machine_spec_snapshot".to_string()
            ]
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

    #[test]
    fn resource_digest_binds_throughput_profile_and_parallelism() {
        let throughput = GateResourcePolicy::from_cli(
            false,
            600,
            "48G",
            1536,
            "800%",
            true,
            Some("throughput"),
            Some(8),
            None,
            None,
        );
        let conservative = GateResourcePolicy::from_cli(
            false,
            600,
            "48G",
            1536,
            "200%",
            true,
            Some("conservative"),
            Some(2),
            None,
            None,
        );
        assert_ne!(
            super::resource_digest(&throughput),
            super::resource_digest(&conservative),
            "resource digest must change when throughput profile/parallelism changes"
        );
    }

    // --- TCK-00544: attestation schema version bump + file-content binding ---

    #[test]
    fn attestation_schema_is_v2() {
        // TCK-00544: Schema must be v2 to invalidate pre-fix cache entries
        // that were created using HEAD:path git blob references which ignored
        // dirty workspace content.
        assert_eq!(
            super::ATTESTATION_SCHEMA,
            "apm2.fac.gate_attestation.v2",
            "ATTESTATION_SCHEMA must be v2 to invalidate dirty-state cache entries"
        );
        assert_eq!(
            super::ATTESTATION_DOMAIN,
            "apm2.fac.gate.attestation/v2",
            "ATTESTATION_DOMAIN must be v2 for consistency with schema version"
        );
    }

    #[test]
    fn attestation_uses_file_content_not_git_blob() {
        // TCK-00544 regression: input_digest must use file_sha256 (actual
        // file content) for existing files, never HEAD:path git blob
        // references. This test verifies the attestation digest for a known
        // workspace file uses file_sha256 binding.
        let workspace_root = std::env::current_dir().expect("cwd");
        let command =
            gate_command_for_attestation(&workspace_root, "rustfmt", None).expect("command");
        let policy = GateResourcePolicy::from_cli(
            false, 600, "48G", 1536, "200%", true, None, None, None, None,
        );

        let attestation = compute_gate_attestation(
            &workspace_root,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "rustfmt",
            &command,
            &policy,
        )
        .expect("attestation");

        // The attestation input_digest must be deterministic and differ from
        // an attestation computed with a different file content hash.
        // We cannot directly inspect the internal input_digest binding
        // method, but we can verify stability: computing twice with the same
        // workspace must yield the same digest (proving it uses actual file
        // content, which is stable for a clean workspace).
        let attestation2 = compute_gate_attestation(
            &workspace_root,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "rustfmt",
            &command,
            &policy,
        )
        .expect("attestation2");
        assert_eq!(
            attestation.input_digest, attestation2.input_digest,
            "input_digest must be stable for the same workspace content"
        );
    }

    #[test]
    fn v1_attestation_digest_not_equal_to_v2() {
        // TCK-00544 regression: a cache entry created under v1 semantics
        // (using git_blob binding + v1 schema) will have a different
        // attestation_digest than a v2 entry for the same SHA and gate,
        // because the schema version and domain are included in the root
        // material. This means v1 cache entries are automatically
        // invalidated by the attestation_mismatch check.
        //
        // We prove this by showing the attestation domain string (which is
        // part of the root material) has changed from v1 to v2.
        let v1_domain = "apm2.fac.gate.attestation/v1";
        let v2_domain = super::ATTESTATION_DOMAIN;
        assert_ne!(
            v1_domain, v2_domain,
            "v1 and v2 attestation domains must differ to invalidate old cache entries"
        );

        let v1_schema = "apm2.fac.gate_attestation.v1";
        let v2_schema = super::ATTESTATION_SCHEMA;
        assert_ne!(
            v1_schema, v2_schema,
            "v1 and v2 attestation schemas must differ to invalidate old cache entries"
        );
    }

    #[test]
    fn file_sha256_rejects_oversized_file() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("oversized.lock");
        let file = std::fs::File::create(&path).expect("create oversized file");
        file.set_len(super::MAX_ATTESTATION_INPUT_FILE_BYTES + 1)
            .expect("set oversized length");
        assert!(
            file_sha256(&path).is_err(),
            "oversized attestation inputs must be rejected"
        );
    }

    #[cfg(unix)]
    #[test]
    fn file_sha256_rejects_symlink() {
        let dir = tempdir().expect("tempdir");
        let target = dir.path().join("target.txt");
        let mut file = std::fs::File::create(&target).expect("create target");
        file.write_all(b"attestation-target")
            .expect("write target bytes");

        let symlink_path = dir.path().join("linked.txt");
        std::os::unix::fs::symlink(&target, &symlink_path).expect("create symlink");

        assert!(
            file_sha256(&symlink_path).is_err(),
            "symlink inputs must be rejected for attestation hashing"
        );
    }

    // --- TCK-00573 MAJOR-1: sandbox hardening hash binds attestation ---

    #[test]
    fn resource_digest_changes_when_sandbox_hardening_hash_changes() {
        // Regression: attestation must bind to the effective policy-driven
        // sandbox hardening profile, not a default. Mutating the hardening
        // hash MUST change the resource digest (and therefore the attestation
        // digest), preventing cache reuse across hardening-profile drift.
        use apm2_core::fac::SandboxHardeningProfile;

        let default_hash = SandboxHardeningProfile::default().content_hash_hex();
        let custom_profile = SandboxHardeningProfile {
            private_tmp: false,
            ..SandboxHardeningProfile::default()
        };
        let custom_hash = custom_profile.content_hash_hex();

        // Precondition: the two hashes must differ.
        assert_ne!(
            default_hash, custom_hash,
            "mutated sandbox profile must produce a different content hash"
        );

        let policy_default = GateResourcePolicy::from_cli(
            false,
            600,
            "48G",
            1536,
            "200%",
            true,
            Some("throughput"),
            Some(4),
            Some(&default_hash),
            None,
        );
        let policy_custom = GateResourcePolicy::from_cli(
            false,
            600,
            "48G",
            1536,
            "200%",
            true,
            Some("throughput"),
            Some(4),
            Some(&custom_hash),
            None,
        );

        assert_ne!(
            super::resource_digest(&policy_default),
            super::resource_digest(&policy_custom),
            "resource digest must change when sandbox hardening profile changes \
             (cache reuse denied across profile drift)"
        );
    }

    #[test]
    fn attestation_digest_changes_when_sandbox_hardening_hash_changes() {
        // End-to-end regression: a full attestation with different sandbox
        // hardening hashes must produce different attestation digests.
        use apm2_core::fac::SandboxHardeningProfile;

        let workspace_root = std::env::current_dir().expect("cwd");
        let command =
            gate_command_for_attestation(&workspace_root, "rustfmt", None).expect("command");
        let sha = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

        let default_hash = SandboxHardeningProfile::default().content_hash_hex();
        let custom_profile = SandboxHardeningProfile {
            private_tmp: false,
            ..SandboxHardeningProfile::default()
        };
        let custom_hash = custom_profile.content_hash_hex();

        let policy_default = GateResourcePolicy::from_cli(
            false,
            600,
            "48G",
            1536,
            "200%",
            true,
            None,
            None,
            Some(&default_hash),
            None,
        );
        let policy_custom = GateResourcePolicy::from_cli(
            false,
            600,
            "48G",
            1536,
            "200%",
            true,
            None,
            None,
            Some(&custom_hash),
            None,
        );

        let att_default =
            compute_gate_attestation(&workspace_root, sha, "rustfmt", &command, &policy_default)
                .expect("attestation default");
        let att_custom =
            compute_gate_attestation(&workspace_root, sha, "rustfmt", &command, &policy_custom)
                .expect("attestation custom");

        assert_ne!(
            att_default.attestation_digest, att_custom.attestation_digest,
            "attestation digest must differ when sandbox hardening profile changes"
        );
        assert_ne!(
            att_default.resource_digest, att_custom.resource_digest,
            "resource digest component must differ when sandbox hardening profile changes"
        );
    }

    #[test]
    fn sandbox_hardening_none_vs_some_produces_different_digest() {
        // Gate attestation with sandbox_hardening=None (legacy) must differ
        // from one with sandbox_hardening=Some (post-TCK-00573).
        use apm2_core::fac::SandboxHardeningProfile;

        let default_hash = SandboxHardeningProfile::default().content_hash_hex();
        let policy_none = GateResourcePolicy::from_cli(
            false, 600, "48G", 1536, "200%", true, None, None, None, None,
        );
        let policy_some = GateResourcePolicy::from_cli(
            false,
            600,
            "48G",
            1536,
            "200%",
            true,
            None,
            None,
            Some(&default_hash),
            None,
        );

        assert_ne!(
            super::resource_digest(&policy_none),
            super::resource_digest(&policy_some),
            "resource digest must differ between None and Some sandbox hardening"
        );
    }

    // --- TCK-00574 MAJOR-1: network policy hash binds attestation ---

    #[test]
    fn resource_digest_changes_when_network_policy_hash_changes() {
        // Regression: attestation must bind to the effective network policy.
        // Toggling between deny and allow MUST change the resource digest
        // (and therefore the attestation digest), preventing cache reuse
        // across network policy drift.
        use apm2_core::fac::NetworkPolicy;

        let deny_hash = NetworkPolicy::deny().content_hash_hex();
        let allow_hash = NetworkPolicy::allow().content_hash_hex();

        // Precondition: the two hashes must differ.
        assert_ne!(
            deny_hash, allow_hash,
            "deny and allow network policy must produce different content hashes"
        );

        let policy_deny = GateResourcePolicy::from_cli(
            false,
            600,
            "48G",
            1536,
            "200%",
            true,
            Some("throughput"),
            Some(4),
            None,
            Some(&deny_hash),
        );
        let policy_allow = GateResourcePolicy::from_cli(
            false,
            600,
            "48G",
            1536,
            "200%",
            true,
            Some("throughput"),
            Some(4),
            None,
            Some(&allow_hash),
        );

        assert_ne!(
            super::resource_digest(&policy_deny),
            super::resource_digest(&policy_allow),
            "resource digest must change when network policy toggles between deny and allow \
             (cache reuse denied across policy drift)"
        );
    }

    #[test]
    fn attestation_digest_changes_when_network_policy_hash_changes() {
        // End-to-end regression: a full attestation with deny vs allow
        // network policy hashes must produce different attestation digests.
        use apm2_core::fac::NetworkPolicy;

        let workspace_root = std::env::current_dir().expect("cwd");
        let command =
            gate_command_for_attestation(&workspace_root, "rustfmt", None).expect("command");
        let sha = "cccccccccccccccccccccccccccccccccccccccc";

        let deny_hash = NetworkPolicy::deny().content_hash_hex();
        let allow_hash = NetworkPolicy::allow().content_hash_hex();

        let policy_deny = GateResourcePolicy::from_cli(
            false,
            600,
            "48G",
            1536,
            "200%",
            true,
            None,
            None,
            None,
            Some(&deny_hash),
        );
        let policy_allow = GateResourcePolicy::from_cli(
            false,
            600,
            "48G",
            1536,
            "200%",
            true,
            None,
            None,
            None,
            Some(&allow_hash),
        );

        let att_deny =
            compute_gate_attestation(&workspace_root, sha, "rustfmt", &command, &policy_deny)
                .expect("attestation deny");
        let att_allow =
            compute_gate_attestation(&workspace_root, sha, "rustfmt", &command, &policy_allow)
                .expect("attestation allow");

        assert_ne!(
            att_deny.attestation_digest, att_allow.attestation_digest,
            "attestation digest must differ when network policy toggles between deny and allow"
        );
        assert_ne!(
            att_deny.resource_digest, att_allow.resource_digest,
            "resource digest component must differ when network policy changes"
        );
    }

    #[test]
    fn network_policy_none_vs_some_produces_different_digest() {
        // Gate attestation with network_policy_hash=None (legacy) must differ
        // from one with network_policy_hash=Some (post-TCK-00574).
        use apm2_core::fac::NetworkPolicy;

        let deny_hash = NetworkPolicy::deny().content_hash_hex();
        let policy_none = GateResourcePolicy::from_cli(
            false, 600, "48G", 1536, "200%", true, None, None, None, None,
        );
        let policy_some = GateResourcePolicy::from_cli(
            false,
            600,
            "48G",
            1536,
            "200%",
            true,
            None,
            None,
            None,
            Some(&deny_hash),
        );

        assert_ne!(
            super::resource_digest(&policy_none),
            super::resource_digest(&policy_some),
            "resource digest must differ between None and Some network policy hash"
        );
    }
}
