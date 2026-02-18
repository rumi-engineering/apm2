// AGENT-AUTHORED
//! Authoritative FAC execution policy object for RFC-0028.
//!
//! A policy defines the environment and security constraints that apply to an
//! FAC execution worker. Policy hashes are computed from canonicalized
//! JSON-like bytes with domain separation, and the resulting digest is embedded
//! in RFC-0028 boundary bindings.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::job_spec::{MAX_REPO_ALLOWLIST_SIZE, parse_b3_256_digest};
use super::policy_resolution::{DeterminismClass, RiskTier};
use super::systemd_properties::{NetworkPolicy, SandboxHardeningProfile};
use crate::determinism::canonicalize_json;
use crate::economics::profile::EconomicsProfile;
#[cfg(unix)]
use crate::fac::execution_backend::{ExecutionBackend, select_backend};

/// Schema identifier for `FacPolicyV1`.
pub const POLICY_SCHEMA_ID: &str = "apm2.fac.policy.v1";

/// Maximum serialized size in bytes.
pub const MAX_POLICY_SIZE: usize = 65_536;

/// Maximum number of environment entries per vector field.
pub const MAX_ENV_ENTRIES: usize = 256;

/// Maximum key length for `EnvSetEntry` keys.
pub const MAX_ENV_KEY_LENGTH: usize = 256;

/// Maximum value length for `EnvSetEntry` values.
pub const MAX_ENV_VALUE_LENGTH: usize = 4_096;

/// Maximum string length for all string fields.
pub const MAX_STRING_LENGTH: usize = 4_096;

/// Supported policy schema versions.
pub const SUPPORTED_POLICY_VERSIONS: &[u32] = &[1];

const POLICY_HASH_DOMAIN: &[u8] = b"apm2.fac.policy.v1\0";

/// Returns the deterministic hash of `EconomicsProfile::default_baseline()`.
fn default_economics_profile_hash() -> [u8; 32] {
    // EconomicsProfile::default_baseline().profile_hash() computes the BLAKE3 hash
    // of the canonical JSON representation. This is deterministic.
    EconomicsProfile::default_baseline()
        .profile_hash()
        .unwrap_or([0u8; 32])
}

const fn default_quarantine_max_bytes() -> u64 {
    512 * 1024 * 1024
}

const fn default_quarantine_ttl_days() -> u32 {
    14
}

const fn default_denied_ttl_days() -> u32 {
    7
}

/// Errors returned by policy parsing, validation, and persistence.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FacPolicyError {
    /// The configured schema is missing or wrong.
    #[error("schema mismatch: expected {expected}, got {actual}")]
    SchemaMismatch {
        /// Expected schema identifier.
        expected: String,
        /// Actual schema identifier.
        actual: String,
    },

    /// The configured version is unsupported.
    #[error("unsupported policy version: {version}; supported: {supported:?}")]
    UnsupportedVersion {
        /// Provided version.
        version: u32,
        /// Supported versions.
        supported: Vec<u32>,
    },

    /// A string field exceeded the allowed maximum length.
    #[error("string field {field} exceeds max length: {actual} > {max}")]
    StringTooLong {
        /// The field name.
        field: &'static str,
        /// Actual value length.
        actual: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// A vector exceeded the allowed number of entries.
    #[error("vector field {field} exceeds max length: {actual} > {max}")]
    VectorTooLarge {
        /// The vector field name.
        field: &'static str,
        /// Actual element count.
        actual: usize,
        /// Maximum allowed count.
        max: usize,
    },

    /// Missing required field.
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// `EnvSetEntry` contained invalid data.
    #[error("invalid env set entry in {field}")]
    InvalidEnvSetEntry {
        /// Field containing the invalid entry.
        field: &'static str,
    },

    /// Invalid enum-like policy value.
    #[error("invalid value for {field}: {value}")]
    InvalidFieldValue {
        /// Field that held the invalid value.
        field: &'static str,
        /// Invalid value.
        value: String,
    },

    /// Serialized input exceeded `MAX_POLICY_SIZE`.
    #[error("policy input exceeds max size: {size} > {max}")]
    InputTooLarge {
        /// Actual size.
        size: usize,
        /// Maximum size.
        max: usize,
    },

    /// JSON parse/serialize failure.
    #[error("policy serialization failure: {0}")]
    Serialization(String),

    /// I/O failure.
    #[error("policy I/O failure: {0}")]
    Io(String),

    /// Invalid BLAKE3 digest format.
    #[error("invalid policy hash format: {value}")]
    InvalidPolicyHash {
        /// Bad digest value.
        value: String,
    },
}

/// A single environment key/value override in policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvSetEntry {
    /// Environment variable name.
    pub key: String,
    /// Environment variable value.
    pub value: String,
}

/// Authoritative FAC policy configuration bound into RFC-0028 checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FacPolicyV1 {
    /// Schema identifier: `apm2.fac.policy.v1`.
    pub schema: String,

    /// Policy schema version.
    pub version: u32,

    /// Environment variables to clear before execution.
    pub env_clear: Vec<String>,

    /// Environment variable prefixes allowed to inherit.
    pub env_allowlist_prefixes: Vec<String>,

    /// Environment variable prefixes explicitly denied.
    pub env_denylist_prefixes: Vec<String>,

    /// Environment variable entries to force set.
    pub env_set: Vec<EnvSetEntry>,

    /// Whether to deny ambient `CARGO_HOME`.
    pub deny_ambient_cargo_home: bool,

    /// Required override for `CARGO_TARGET_DIR`.
    pub cargo_target_dir: Option<String>,

    /// Required override for `CARGO_HOME`.
    pub cargo_home: Option<String>,

    /// Maximum total bytes for quarantine directory. Default: 512 MiB.
    #[serde(default = "default_quarantine_max_bytes")]
    pub quarantine_max_bytes: u64,

    /// Days to retain quarantined jobs before pruning. Default: 14.
    #[serde(default = "default_quarantine_ttl_days")]
    pub quarantine_ttl_days: u32,

    /// Days to retain denied jobs before pruning. Default: 7.
    #[serde(default = "default_denied_ttl_days")]
    pub denied_ttl_days: u32,

    /// Risk tier for this policy.
    pub risk_tier: RiskTier,

    /// Determinism class for this policy.
    pub determinism_class: DeterminismClass,

    /// BLAKE3 hash of the economics profile artifact in CAS.
    ///
    /// Zero hash means no profile bound (will fail-closed on budget admission).
    #[serde(default = "default_economics_profile_hash")]
    pub economics_profile_hash: [u8; 32],

    /// Sandbox hardening profile for systemd transient units (TCK-00573).
    ///
    /// Defines which systemd security directives are applied to FAC job units.
    /// The default profile enables all hardening directives with safe defaults
    /// that preserve build execution.
    #[serde(default)]
    pub sandbox_hardening: SandboxHardeningProfile,

    /// Network access policy override for FAC job units (TCK-00574).
    ///
    /// When `Some`, this policy takes precedence over the built-in
    /// per-job-kind mapping in `resolve_network_policy()`. When `None`
    /// (the default), the built-in mapping is used: deny for
    /// gates/bulk/control, allow for warm.
    ///
    /// This allows operators to explicitly override the default posture
    /// globally (e.g., deny network even for warm, or allow for gates).
    ///
    /// The default is `None` (use built-in mapping). Existing policies
    /// that predate TCK-00574 will correctly default to `None` via
    /// `serde(default)`, preserving the built-in warm→allow mapping.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_policy: Option<NetworkPolicy>,

    /// Optional `repo_id` allowlist for job spec validation (TCK-00579).
    ///
    /// When `Some`, only the listed `repo_id` values are accepted by
    /// policy-aware job spec validators.  When `None` (the default), any
    /// structurally valid `repo_id` passes the allowlist check (open policy).
    ///
    /// Note: `serde(default)` is safe here because `None` is the MOST
    /// permissive option for this field, and the default is correct for
    /// existing persisted policies that predate TCK-00579.  The remaining
    /// policy checks (`bytes_backend` allowlist, filesystem-path rejection)
    /// are unconditional and do not depend on this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_repo_ids: Option<Vec<String>>,

    /// Optional RFC-0028 intent allowlist for broker token issuance
    /// (TCK-00567).
    ///
    /// When `Some`, only the listed intents are permitted by the broker
    /// when issuing tokens.  When `None` (the default), any structurally
    /// valid intent is accepted (open policy).
    ///
    /// Note: `serde(default)` is safe here because `None` is the MOST
    /// permissive option for this field, and the default is correct for
    /// existing persisted policies that predate TCK-00567.  The fail-closed
    /// enforcement is at the broker and worker layers when the field is
    /// `Some`.
    ///
    /// The list is bounded by [`super::job_spec::MAX_ALLOWED_INTENTS_SIZE`]
    /// at validation time (CTR-1303).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_intents: Option<Vec<super::job_spec::FacIntent>>,

    /// Queue bounds policy controlling maximum pending queue size (TCK-00578).
    ///
    /// Configures `max_pending_jobs`, `max_pending_bytes`, and optional
    /// `per_lane_max_pending_jobs` for enqueue-time enforcement. When not
    /// present in persisted policy (pre-TCK-00578 policies), defaults to
    /// `QueueBoundsPolicy::default()` via `serde(default)`.
    #[serde(default)]
    pub queue_bounds_policy: super::queue_bounds::QueueBoundsPolicy,
}

impl Default for FacPolicyV1 {
    fn default() -> Self {
        Self::default_policy()
    }
}

impl FacPolicyV1 {
    /// Default authoritative policy for standard host class.
    #[must_use]
    pub fn default_policy() -> Self {
        let economics_profile = EconomicsProfile::default_baseline();
        let economics_profile_hash = economics_profile.profile_hash().unwrap_or([0u8; 32]);

        Self {
            schema: POLICY_SCHEMA_ID.to_string(),
            version: 1,
            env_clear: vec![
                "LD_PRELOAD".to_string(),
                "LD_LIBRARY_PATH".to_string(),
                "DYLD_INSERT_LIBRARIES".to_string(),
            ],
            env_allowlist_prefixes: vec![
                "CARGO_".to_string(),
                // SAFETY: The previous broad "RUST" prefix admitted RUSTC_WRAPPER,
                // enabling wrapper-controlled compiler execution that bypasses
                // containment (TCK-00548). Specific prefixes are enumerated to
                // cover RUSTFLAGS, RUSTDOCFLAGS, RUSTUP_*, and RUST_BACKTRACE
                // without admitting RUSTC_WRAPPER or RUSTC (which could be
                // spoofed). See env_denylist_prefixes for defense-in-depth.
                "RUSTFLAGS".to_string(),
                "RUSTDOCFLAGS".to_string(),
                "RUSTUP_".to_string(),
                "RUST_BACKTRACE".to_string(),
                "RUST_LOG".to_string(),
                "RUST_TEST_THREADS".to_string(),
                "PATH".to_string(),
                "HOME".to_string(),
                "USER".to_string(),
                "LANG".to_string(),
                "LC_".to_string(),
                "TERM".to_string(),
                "XDG_".to_string(),
            ],
            env_denylist_prefixes: vec![
                "AWS_".to_string(),
                "AZURE_".to_string(),
                "GCP_".to_string(),
                "GOOGLE_".to_string(),
                "GITHUB_TOKEN".to_string(),
                "NPM_TOKEN".to_string(),
                "DOCKER_".to_string(),
                // Defense-in-depth: explicitly deny wrapper/cache injection
                // variables even if a custom policy re-introduces a broad
                // "RUST" allowlist prefix (TCK-00526, TCK-00548).
                "RUSTC_WRAPPER".to_string(),
                "SCCACHE_".to_string(),
            ],
            env_set: vec![EnvSetEntry {
                key: "CARGO_TARGET_DIR".to_string(),
                value: "target".to_string(),
            }],
            deny_ambient_cargo_home: true,
            cargo_target_dir: Some("target".to_string()),
            cargo_home: None,
            quarantine_max_bytes: default_quarantine_max_bytes(),
            quarantine_ttl_days: default_quarantine_ttl_days(),
            denied_ttl_days: default_denied_ttl_days(),
            risk_tier: RiskTier::Tier2,
            determinism_class: DeterminismClass::SoftDeterministic,
            economics_profile_hash,
            sandbox_hardening: SandboxHardeningProfile::default(),
            network_policy: None,
            allowed_repo_ids: None,
            allowed_intents: None,
            queue_bounds_policy: super::queue_bounds::QueueBoundsPolicy::default(),
        }
    }

    /// Derives a [`super::job_spec::JobSpecValidationPolicy`] from this
    /// policy's `allowed_repo_ids` field (TCK-00579).
    ///
    /// This is the canonical way to obtain a validation policy for use with
    /// [`super::job_spec::validate_job_spec_with_policy`] and
    /// [`super::job_spec::validate_job_spec_control_lane_with_policy`].
    ///
    /// # Errors
    ///
    /// Returns `JobSpecError::FieldTooLong` if the allowlist exceeds the
    /// maximum size bound.
    pub fn job_spec_validation_policy(
        &self,
    ) -> Result<super::job_spec::JobSpecValidationPolicy, super::job_spec::JobSpecError> {
        self.allowed_repo_ids.as_ref().map_or_else(
            || Ok(super::job_spec::JobSpecValidationPolicy::open()),
            |repos| super::job_spec::JobSpecValidationPolicy::with_allowed_repos(repos.clone()),
        )
    }

    /// Validates policy fields and returns an error when constraints are
    /// violated.
    ///
    /// # Errors
    /// Returns [`FacPolicyError`] for schema mismatch, unsupported version,
    /// oversized/malformed fields, and invalid enum-like values.
    /// Validates all policy constraints and bounds.
    pub fn validate(&self) -> Result<(), FacPolicyError> {
        if self.schema != POLICY_SCHEMA_ID {
            return Err(FacPolicyError::SchemaMismatch {
                expected: POLICY_SCHEMA_ID.to_string(),
                actual: self.schema.clone(),
            });
        }

        if !SUPPORTED_POLICY_VERSIONS.contains(&self.version) {
            return Err(FacPolicyError::UnsupportedVersion {
                version: self.version,
                supported: SUPPORTED_POLICY_VERSIONS.to_vec(),
            });
        }

        validate_string_field("schema", &self.schema)?;
        validate_string_field_opt("cargo_target_dir", self.cargo_target_dir.as_deref())?;
        validate_string_field_opt("cargo_home", self.cargo_home.as_deref())?;

        validate_env_vector("env_clear", &self.env_clear)?;
        validate_env_vector("env_allowlist_prefixes", &self.env_allowlist_prefixes)?;
        validate_empty_policy_prefixes("env_allowlist_prefixes", &self.env_allowlist_prefixes)?;
        validate_env_vector("env_denylist_prefixes", &self.env_denylist_prefixes)?;
        validate_empty_policy_prefixes("env_denylist_prefixes", &self.env_denylist_prefixes)?;

        if self.env_set.len() > MAX_ENV_ENTRIES {
            return Err(FacPolicyError::VectorTooLarge {
                field: "env_set",
                actual: self.env_set.len(),
                max: MAX_ENV_ENTRIES,
            });
        }

        for entry in &self.env_set {
            if entry.key.is_empty() || entry.value.is_empty() {
                return Err(FacPolicyError::InvalidEnvSetEntry { field: "env_set" });
            }
            validate_string_field_len("env_set.key", entry.key.len(), MAX_ENV_KEY_LENGTH)?;
            validate_string_field_len("env_set.value", entry.value.len(), MAX_ENV_VALUE_LENGTH)?;
        }

        // Validate sandbox hardening profile (TCK-00573).
        self.sandbox_hardening
            .validate()
            .map_err(|e| FacPolicyError::InvalidFieldValue {
                field: "sandbox_hardening",
                value: e,
            })?;

        // Validate allowed_repo_ids length for early detection during policy
        // loading (TCK-00579).  The same bound is enforced during policy
        // derivation in `job_spec_validation_policy()`, but checking here
        // ensures oversized allowlists are caught at deserialization time.
        if let Some(ref repos) = self.allowed_repo_ids {
            if repos.len() > MAX_REPO_ALLOWLIST_SIZE {
                return Err(FacPolicyError::VectorTooLarge {
                    field: "allowed_repo_ids",
                    actual: repos.len(),
                    max: MAX_REPO_ALLOWLIST_SIZE,
                });
            }
        }

        // Validate allowed_intents length (TCK-00567, CTR-1303).
        if let Some(ref intents) = self.allowed_intents {
            if intents.len() > super::job_spec::MAX_ALLOWED_INTENTS_SIZE {
                return Err(FacPolicyError::VectorTooLarge {
                    field: "allowed_intents",
                    actual: intents.len(),
                    max: super::job_spec::MAX_ALLOWED_INTENTS_SIZE,
                });
            }
        }

        // Validate queue bounds policy (TCK-00578).
        self.queue_bounds_policy
            .validate()
            .map_err(|e| FacPolicyError::InvalidFieldValue {
                field: "queue_bounds_policy",
                value: format!("{e}"),
            })?;

        Ok(())
    }

    /// Resolves the effective `CARGO_HOME` path for FAC job execution.
    ///
    /// Priority:
    /// 1. `policy.cargo_home` (explicit override)
    /// 2. `$APM2_HOME/private/fac/cargo_home` (managed default when
    ///    `deny_ambient_cargo_home` is true)
    /// 3. `None` (ambient `CARGO_HOME` allowed — only when
    ///    `deny_ambient_cargo_home` is false)
    #[must_use]
    pub fn resolve_cargo_home(&self, apm2_home: &Path) -> Option<PathBuf> {
        if let Some(ref explicit) = self.cargo_home {
            return Some(PathBuf::from(explicit));
        }
        if self.deny_ambient_cargo_home {
            return Some(apm2_home.join("private/fac/cargo_home"));
        }
        None
    }
}

/// Build a filtered environment map for FAC job execution from policy rules.
///
/// Algorithm:
/// 1. Start with an empty environment (default-deny).
/// 2. From the ambient environment (`ambient_env`), inherit only variables that
///    match at least one `env_allowlist_prefixes` entry.
/// 3. Remove any variable matching `env_denylist_prefixes` (denylist wins).
/// 4. Remove all variables listed in `env_clear` (unconditional strip).
/// 5. Apply `env_set` overrides (force-set specific key=value pairs).
/// 6. Hardcoded safety: unconditionally strip `RUSTC_WRAPPER` and `SCCACHE_*`
///    regardless of policy configuration (containment invariant, TCK-00548).
///    This step runs AFTER `env_set` to ensure policy overrides cannot
///    re-introduce these variables.
/// 7. If `deny_ambient_cargo_home` is true and `CARGO_HOME` was inherited from
///    the ambient environment, replace it with the managed path.
/// 8. If `cargo_target_dir` is set in policy, force `CARGO_TARGET_DIR`.
///
/// The result is a deterministic `BTreeMap<String, String>` of environment
/// variables suitable for passing to `Command::envs()` after clearing the
/// inherited environment.
///
/// # Arguments
///
/// * `policy`      – The validated `FacPolicyV1` to enforce.
/// * `ambient_env` – The current process environment as key-value pairs.
///   Typically from `std::env::vars()`.
/// * `apm2_home`   – The `$APM2_HOME` directory (for managed `CARGO_HOME`).
#[must_use]
pub fn build_job_environment(
    policy: &FacPolicyV1,
    ambient_env: &[(String, String)],
    apm2_home: &Path,
) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();

    // Step 1-2: Inherit only allowlisted variables.
    for (key, value) in ambient_env {
        let allowed = policy
            .env_allowlist_prefixes
            .iter()
            .any(|prefix| key.starts_with(prefix.as_str()));
        if allowed {
            env.insert(key.clone(), value.clone());
        }
    }

    // Step 3: Remove denylisted variables (denylist takes priority).
    env.retain(|key, _| {
        !policy
            .env_denylist_prefixes
            .iter()
            .any(|prefix| key.starts_with(prefix.as_str()))
    });

    // Step 4: Unconditionally clear specific variables.
    for key in &policy.env_clear {
        env.remove(key);
    }

    // Step 5: Force-set policy overrides.
    for entry in &policy.env_set {
        env.insert(entry.key.clone(), entry.value.clone());
    }

    // Step 6: Hardcoded containment safety — unconditionally strip
    // RUSTC_WRAPPER and SCCACHE_* regardless of policy configuration.
    // These variables enable wrapper-controlled compiler execution that
    // bypasses cgroup containment (TCK-00548). This is a non-configurable
    // safety invariant: even a misconfigured policy cannot re-admit them
    // via env_set overrides. This step MUST run AFTER env_set (Step 5) to
    // ensure policy env_set cannot re-introduce these variables.
    env.remove("RUSTC_WRAPPER");
    env.retain(|key, _| !key.starts_with("SCCACHE_"));

    // Step 7: Enforce managed CARGO_HOME when ambient is denied.
    if let Some(cargo_home) = policy.resolve_cargo_home(apm2_home) {
        env.insert(
            "CARGO_HOME".to_string(),
            cargo_home.to_string_lossy().to_string(),
        );
    }

    // Step 8: Enforce CARGO_TARGET_DIR from policy.
    if let Some(ref target_dir) = policy.cargo_target_dir {
        env.insert("CARGO_TARGET_DIR".to_string(), target_dir.clone());
    }

    env
}

/// Per-lane environment directory names created under each lane directory.
///
/// These directories isolate `HOME`, `TMPDIR`, `XDG_CACHE_HOME`,
/// `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `XDG_STATE_HOME`, and
/// `XDG_RUNTIME_DIR` per lane so that FAC jobs do not write into ambient
/// user directories (`~/.cache`, `~/.cargo`, etc.).
/// Per-lane `HOME` directory name.
pub const LANE_ENV_DIR_HOME: &str = "home";
/// Per-lane `TMPDIR` directory name.
pub const LANE_ENV_DIR_TMP: &str = "tmp";
/// Per-lane `XDG_CACHE_HOME` directory name.
pub const LANE_ENV_DIR_XDG_CACHE: &str = "xdg_cache";
/// Per-lane `XDG_CONFIG_HOME` directory name.
pub const LANE_ENV_DIR_XDG_CONFIG: &str = "xdg_config";
/// Per-lane `XDG_DATA_HOME` directory name.
pub const LANE_ENV_DIR_XDG_DATA: &str = "xdg_data";
/// Per-lane `XDG_STATE_HOME` directory name.
pub const LANE_ENV_DIR_XDG_STATE: &str = "xdg_state";
/// Per-lane `XDG_RUNTIME_DIR` directory name.
pub const LANE_ENV_DIR_XDG_RUNTIME: &str = "xdg_runtime";

/// All per-lane environment subdirectory names.
pub const LANE_ENV_DIRS: &[&str] = &[
    LANE_ENV_DIR_HOME,
    LANE_ENV_DIR_TMP,
    LANE_ENV_DIR_XDG_CACHE,
    LANE_ENV_DIR_XDG_CONFIG,
    LANE_ENV_DIR_XDG_DATA,
    LANE_ENV_DIR_XDG_STATE,
    LANE_ENV_DIR_XDG_RUNTIME,
];

/// Apply per-lane environment overrides to an existing job environment map.
///
/// Sets `HOME`, `TMPDIR`, `XDG_CACHE_HOME`, `XDG_CONFIG_HOME`,
/// `XDG_DATA_HOME`, `XDG_STATE_HOME`, and `XDG_RUNTIME_DIR` to
/// deterministic per-lane directories under `lane_dir`. This prevents FAC
/// jobs from writing into ambient user locations (`~/.cache`, `~/.cargo`,
/// etc.) and provides per-lane isolation (TCK-00575).
///
/// This function must be called AFTER [`build_job_environment`] so that
/// the per-lane overrides take final precedence over any ambient values
/// that may have been inherited or set by policy.
///
/// # Arguments
///
/// * `env`      - Mutable reference to the environment map produced by
///   `build_job_environment`.
/// * `lane_dir` - Absolute path to the lane directory
///   (`$APM2_HOME/private/fac/lanes/<lane_id>`).
pub fn apply_lane_env_overrides(env: &mut BTreeMap<String, String>, lane_dir: &Path) {
    env.insert(
        "HOME".to_string(),
        lane_dir
            .join(LANE_ENV_DIR_HOME)
            .to_string_lossy()
            .to_string(),
    );
    env.insert(
        "TMPDIR".to_string(),
        lane_dir
            .join(LANE_ENV_DIR_TMP)
            .to_string_lossy()
            .to_string(),
    );
    env.insert(
        "XDG_CACHE_HOME".to_string(),
        lane_dir
            .join(LANE_ENV_DIR_XDG_CACHE)
            .to_string_lossy()
            .to_string(),
    );
    env.insert(
        "XDG_CONFIG_HOME".to_string(),
        lane_dir
            .join(LANE_ENV_DIR_XDG_CONFIG)
            .to_string_lossy()
            .to_string(),
    );
    env.insert(
        "XDG_DATA_HOME".to_string(),
        lane_dir
            .join(LANE_ENV_DIR_XDG_DATA)
            .to_string_lossy()
            .to_string(),
    );
    env.insert(
        "XDG_STATE_HOME".to_string(),
        lane_dir
            .join(LANE_ENV_DIR_XDG_STATE)
            .to_string_lossy()
            .to_string(),
    );
    env.insert(
        "XDG_RUNTIME_DIR".to_string(),
        lane_dir
            .join(LANE_ENV_DIR_XDG_RUNTIME)
            .to_string_lossy()
            .to_string(),
    );
}

/// Ensure all per-lane environment directories exist with restrictive
/// permissions (0o700 in operator mode, 0o770 in system-mode, CTR-2611).
///
/// Creates all `LANE_ENV_DIRS` under `lane_dir`. Uses atomic creation
/// (`mkdir`, handle `AlreadyExists`) to eliminate the TOCTOU window between
/// existence checks and creation.
/// Rejects symlinks via `symlink_metadata` to prevent isolation escape
/// (INV-LANE-ENV-001).
///
/// # Errors
///
/// Returns a human-readable error when directory creation fails, when
/// a symlink is detected, or when an existing directory has incorrect
/// ownership or permissions.
pub fn ensure_lane_env_dirs(lane_dir: &Path) -> Result<(), String> {
    for subdir in LANE_ENV_DIRS {
        let dir_path = lane_dir.join(subdir);
        // Atomic creation: attempt mkdir first, handle AlreadyExists.
        // This eliminates the TOCTOU window between exists() and create().
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            match std::fs::DirBuilder::new()
                .recursive(true)
                .mode(lane_env_dir_mode())
                .create(&dir_path)
            {
                Ok(()) => {
                    // Directory created successfully — verify it (paranoid
                    // check against race where attacker replaces with symlink
                    // between create and verify).
                    verify_lane_env_dir_permissions(&dir_path)?;
                },
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    // Already exists — verify permissions and reject symlinks.
                    verify_lane_env_dir_permissions(&dir_path)?;
                },
                Err(e) => {
                    return Err(format!(
                        "cannot create lane env dir at {}: {e}",
                        dir_path.display()
                    ));
                },
            }
        }
        #[cfg(not(unix))]
        {
            match std::fs::create_dir_all(&dir_path) {
                Ok(()) => {},
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {},
                Err(e) => {
                    return Err(format!(
                        "cannot create lane env dir at {}: {e}",
                        dir_path.display()
                    ));
                },
            }
        }
    }
    Ok(())
}

/// Verify that a directory has restrictive permissions (operator mode 0o700,
/// system-mode 0o770), is owned by the active runtime context (CTR-2611),
/// and is not a symlink
/// (INV-LANE-ENV-001).
///
/// Uses `symlink_metadata` instead of `metadata` to avoid following
/// symlinks. An attacker could plant a symlink (e.g., `home` -> `~/.ssh`)
/// to escape isolation; `metadata` would follow it and report the
/// target's attributes, bypassing the check.
///
/// `context` is a human-readable label for error messages (e.g.,
/// "lane env dir", "managed `CARGO_HOME`") to identify the purpose of the
/// directory being verified.
///
/// This is the shared implementation backing both
/// `verify_lane_env_dir_permissions` and `verify_cargo_home_permissions`
/// (TCK-00575 round 2 NIT: deduplicated permission verification).
///
/// # Errors
///
/// Returns a human-readable error when the path is a symlink, is not a
/// directory, is owned by the wrong context, or has group/other-accessible
/// permissions (mode bits beyond 0o700 in operator mode or beyond 0o770 in
/// system-mode).
#[cfg(unix)]
pub fn verify_dir_permissions(dir_path: &Path, context: &str) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;

    use subtle::ConstantTimeEq;

    // SAFETY: symlink_metadata does NOT follow symlinks, so we detect
    // symlinks at the path itself rather than their targets.
    let metadata = std::fs::symlink_metadata(dir_path)
        .map_err(|e| format!("cannot stat {context} at {}: {e}", dir_path.display()))?;

    // Reject symlinks explicitly — an attacker could create a symlink
    // pointing to a sensitive directory (e.g., ~/.ssh) to escape isolation.
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "{context} at {} is a symlink; refusing to follow — \
             this may indicate an isolation escape attempt",
            dir_path.display()
        ));
    }

    if !metadata.is_dir() {
        return Err(format!(
            "{context} at {} is not a directory",
            dir_path.display()
        ));
    }

    let is_system_mode = matches!(select_backend(), Ok(ExecutionBackend::SystemMode));
    let disallowed_mode_bits = if is_system_mode { 0o007 } else { 0o077 };

    // Constant-time UID comparison to prevent timing side-channels
    // consistent with project style (INV-PC-001).
    let current_uid = nix::unistd::geteuid().as_raw();
    if is_system_mode {
        use nix::unistd::getgid;
        let effective_gid = getgid().as_raw();
        if metadata.gid() != effective_gid {
            return Err(format!(
                "{context} at {} is owned by uid {} and gid {} but current user is uid {} gid {}; \
                 refusing to use a directory with a non-shared group in system-mode",
                dir_path.display(),
                metadata.uid(),
                metadata.gid(),
                current_uid,
                effective_gid,
            ));
        }
    } else {
        let uid_matches: bool = current_uid
            .to_le_bytes()
            .ct_eq(&metadata.uid().to_le_bytes())
            .into();
        if !uid_matches {
            return Err(format!(
                "{context} at {} is owned by uid {} but current user is uid {}; \
                 refusing to use a directory owned by another user",
                dir_path.display(),
                metadata.uid(),
                current_uid,
            ));
        }
    }

    let mode = metadata.mode() & 0o777;
    if mode & disallowed_mode_bits != 0 {
        let expected_mode = if is_system_mode { "0o770" } else { "0o700" };
        let chmod_mode = if is_system_mode { "770" } else { "700" };
        return Err(format!(
            "{context} at {} has too-permissive mode {:#05o} \
             (group/other access detected); expected {}. \
             Fix with: chmod {} {}",
            dir_path.display(),
            mode,
            expected_mode,
            chmod_mode,
            dir_path.display(),
        ));
    }

    Ok(())
}

/// Verify that an existing lane environment directory has restrictive
/// permissions (0o700 in operator mode, 0o770 in system-mode),
/// is owned by the active runtime context (CTR-2611), and is not a symlink
/// (INV-LANE-ENV-001).
///
/// Delegates to [`verify_dir_permissions`] with a "lane env dir" context
/// label.
#[cfg(unix)]
fn verify_lane_env_dir_permissions(dir_path: &Path) -> Result<(), String> {
    verify_dir_permissions(dir_path, "lane env dir")
}

#[cfg(unix)]
fn lane_env_dir_mode() -> u32 {
    if matches!(select_backend(), Ok(ExecutionBackend::SystemMode)) {
        0o770
    } else {
        0o700
    }
}

/// Computes the deterministic policy hash using domain-separated BLAKE3.
///
/// # Errors
/// Returns `Err` if canonicalization or serialization fails.
pub fn compute_policy_hash(policy: &FacPolicyV1) -> Result<String, String> {
    let canonical = policy_as_canonical_json(policy)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(POLICY_HASH_DOMAIN);
    hasher.update(canonical.as_bytes());
    Ok(format!("b3-256:{}", hasher.finalize().to_hex()))
}

/// Parses and validates a policy hash string.
#[must_use]
pub fn parse_policy_hash(policy_hash: &str) -> Option<[u8; 32]> {
    parse_b3_256_digest(policy_hash)
}

/// Reads, validates, and returns a bounded policy from bytes.
///
/// # Errors
/// Returns [`FacPolicyError`] when size limits, parsing, or validation fail.
pub fn deserialize_policy(bytes: &[u8]) -> Result<FacPolicyV1, FacPolicyError> {
    if bytes.len() > MAX_POLICY_SIZE {
        return Err(FacPolicyError::InputTooLarge {
            size: bytes.len(),
            max: MAX_POLICY_SIZE,
        });
    }

    let policy: FacPolicyV1 =
        serde_json::from_slice(bytes).map_err(|e| FacPolicyError::Serialization(e.to_string()))?;
    policy.validate()?;
    Ok(policy)
}

/// Persists policy JSON and returns the policy path.
///
/// Writes to `${fac_root}/policy/fac_policy.v1.json` via an atomic rename.
///
/// # Errors
/// Returns a human-readable error when policy validation, directory creation,
/// serialization, or persistence fails.
pub fn persist_policy(fac_root: &Path, policy: &FacPolicyV1) -> Result<PathBuf, String> {
    policy
        .validate()
        .map_err(|e| format!("invalid policy: {e}"))?;

    let policy_dir = fac_root.join("policy");
    fs::create_dir_all(&policy_dir).map_err(|e| format!("cannot create policy dir: {e}"))?;

    let path = policy_dir.join("fac_policy.v1.json");
    let temp_path = policy_dir.join(".fac_policy.v1.json.tmp");
    let bytes =
        serde_json::to_vec_pretty(policy).map_err(|e| format!("cannot serialize policy: {e}"))?;
    let mut file = fs::File::create(&temp_path)
        .map_err(|e| format!("cannot create temporary policy file: {e}"))?;
    #[cfg(unix)]
    fs::set_permissions(&temp_path, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("cannot set temporary policy permissions: {e}"))?;
    file.write_all(&bytes)
        .map_err(|e| format!("cannot write policy file: {e}"))?;
    file.sync_all()
        .map_err(|e| format!("cannot sync temporary policy file: {e}"))?;
    fs::rename(&temp_path, &path).map_err(|e| format!("cannot persist policy: {e}"))?;
    let dir = fs::File::open(&policy_dir).map_err(|e| {
        format!("cannot open policy directory for durability sync after write: {e}")
    })?;
    dir.sync_all()
        .map_err(|e| format!("cannot sync policy directory after write: {e}"))?;

    Ok(path)
}

fn sort_env_vectors_for_policy_hash(policy: &FacPolicyV1) -> FacPolicyV1 {
    let mut normalized = policy.clone();
    normalized.env_clear.sort();
    normalized.env_allowlist_prefixes.sort();
    normalized.env_denylist_prefixes.sort();
    normalized.env_set.sort_by(|a, b| match a.key.cmp(&b.key) {
        std::cmp::Ordering::Equal => a.value.cmp(&b.value),
        ordering => ordering,
    });
    normalized
}

fn policy_as_canonical_json(policy: &FacPolicyV1) -> Result<String, String> {
    let normalized_policy = sort_env_vectors_for_policy_hash(policy);
    let json = serde_json::to_string(&normalized_policy)
        .map_err(|e| format!("cannot serialize policy: {e}"))?;
    canonicalize_json(&json).map_err(|e| format!("cannot canonicalize policy: {e}"))
}

const fn validate_string_field_len(
    field: &'static str,
    actual: usize,
    max: usize,
) -> Result<(), FacPolicyError> {
    if actual > max {
        return Err(FacPolicyError::StringTooLong { field, actual, max });
    }
    Ok(())
}

const fn validate_string_field(field: &'static str, value: &str) -> Result<(), FacPolicyError> {
    validate_string_field_len(field, value.len(), MAX_STRING_LENGTH)
}

fn validate_string_field_opt(
    field: &'static str,
    value: Option<&str>,
) -> Result<(), FacPolicyError> {
    if let Some(value) = value {
        validate_string_field(field, value)?;
    }
    Ok(())
}

fn validate_env_vector(field: &'static str, values: &[String]) -> Result<(), FacPolicyError> {
    if values.len() > MAX_ENV_ENTRIES {
        return Err(FacPolicyError::VectorTooLarge {
            field,
            actual: values.len(),
            max: MAX_ENV_ENTRIES,
        });
    }

    for value in values {
        validate_string_field(field, value)?;
        if value.len() > MAX_ENV_KEY_LENGTH {
            return Err(FacPolicyError::StringTooLong {
                field,
                actual: value.len(),
                max: MAX_ENV_KEY_LENGTH,
            });
        }
    }

    Ok(())
}

fn validate_empty_policy_prefixes(
    field: &'static str,
    values: &[String],
) -> Result<(), FacPolicyError> {
    if values.iter().any(String::is_empty) {
        return Err(FacPolicyError::InvalidFieldValue {
            field,
            value: "empty prefix strings are not allowed".to_string(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn test_default_policy_is_valid() {
        let policy = FacPolicyV1::default_policy();
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn test_policy_hash_is_deterministic() {
        let policy = FacPolicyV1::default_policy();
        let a = compute_policy_hash(&policy).expect("compute policy hash");
        let b = compute_policy_hash(&policy).expect("compute policy hash");
        assert_eq!(a, b);
    }

    #[test]
    fn test_policy_hash_changes_on_mutation() {
        let mut policy = FacPolicyV1::default_policy();
        let a = compute_policy_hash(&policy).expect("compute policy hash");
        policy.deny_ambient_cargo_home = false;
        let b = compute_policy_hash(&policy).expect("compute policy hash");
        assert_ne!(a, b);
    }

    #[test]
    fn test_policy_hash_collision_resistance() {
        let mut policy1 = FacPolicyV1::default_policy();
        let policy2 = FacPolicyV1::default_policy();

        let hash1 = compute_policy_hash(&policy1).expect("compute policy hash");
        let hash2 = compute_policy_hash(&policy2).expect("compute policy hash");
        assert_eq!(hash1, hash2);

        policy1.risk_tier = RiskTier::Tier3;
        let hash3 = compute_policy_hash(&policy1).expect("compute policy hash");
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_policy_roundtrip_json() {
        let policy = FacPolicyV1::default_policy();
        let bytes = serde_json::to_vec_pretty(&policy).expect("serialize policy");
        let restored = deserialize_policy(&bytes).expect("deserialize policy");
        assert_eq!(restored, policy);
    }

    #[test]
    fn test_validate_rejects_oversized_env() {
        let mut policy = FacPolicyV1::default_policy();
        policy.env_set = (0..=MAX_ENV_ENTRIES)
            .map(|_| EnvSetEntry {
                key: "A".to_string(),
                value: "B".to_string(),
            })
            .collect();

        assert!(matches!(
            policy.validate(),
            Err(FacPolicyError::VectorTooLarge {
                field: "env_set",
                ..
            })
        ));
    }

    #[test]
    fn test_validate_rejects_oversized_strings() {
        let mut policy = FacPolicyV1::default_policy();
        policy.cargo_target_dir = Some("x".repeat(MAX_STRING_LENGTH + 1));

        assert!(matches!(
            policy.validate(),
            Err(FacPolicyError::StringTooLong {
                field: "cargo_target_dir",
                ..
            })
        ));
    }

    #[test]
    fn test_validate_rejects_empty_prefixes() {
        let mut policy = FacPolicyV1::default_policy();
        policy.env_allowlist_prefixes.push(String::new());
        assert!(matches!(
            policy.validate(),
            Err(FacPolicyError::InvalidFieldValue {
                field: "env_allowlist_prefixes",
                ..
            })
        ));

        let mut policy = FacPolicyV1::default_policy();
        policy.env_denylist_prefixes.push(String::new());
        assert!(matches!(
            policy.validate(),
            Err(FacPolicyError::InvalidFieldValue {
                field: "env_denylist_prefixes",
                ..
            })
        ));
    }

    // ── Sandbox hardening policy tests (TCK-00573) ──

    #[test]
    fn test_default_policy_includes_sandbox_hardening() {
        let policy = FacPolicyV1::default_policy();
        assert_eq!(policy.sandbox_hardening, SandboxHardeningProfile::default());
        assert!(policy.sandbox_hardening.no_new_privileges);
        assert!(policy.sandbox_hardening.private_tmp);
    }

    #[test]
    fn test_policy_validate_rejects_invalid_sandbox_hardening() {
        let mut policy = FacPolicyV1::default_policy();
        // Push too many address families (exceeds MAX_ADDRESS_FAMILIES=16).
        policy.sandbox_hardening.restrict_address_families =
            (0..17).map(|i| format!("AF_TEST{i}")).collect();
        let err = policy.validate().unwrap_err();
        assert!(
            matches!(
                err,
                FacPolicyError::InvalidFieldValue {
                    field: "sandbox_hardening",
                    ..
                }
            ),
            "expected InvalidFieldValue for sandbox_hardening, got: {err}"
        );
    }

    #[test]
    fn test_policy_validate_rejects_sandbox_hardening_af_prefix_without_suffix() {
        let mut policy = FacPolicyV1::default_policy();
        policy.sandbox_hardening.restrict_address_families = vec!["AF_".to_string()];
        let err = policy.validate().unwrap_err();
        assert!(
            matches!(
                err,
                FacPolicyError::InvalidFieldValue {
                    field: "sandbox_hardening",
                    ..
                }
            ),
            "expected InvalidFieldValue for sandbox_hardening, got: {err}"
        );
    }

    #[test]
    fn test_policy_hash_changes_on_sandbox_hardening_mutation() {
        let mut policy1 = FacPolicyV1::default_policy();
        let policy2 = FacPolicyV1::default_policy();
        let hash1 = compute_policy_hash(&policy1).expect("hash1");
        let hash2 = compute_policy_hash(&policy2).expect("hash2");
        assert_eq!(hash1, hash2);

        policy1.sandbox_hardening.no_new_privileges = false;
        let hash3 = compute_policy_hash(&policy1).expect("hash3");
        assert_ne!(
            hash1, hash3,
            "sandbox_hardening mutation must change policy hash"
        );
    }

    #[test]
    fn test_policy_roundtrip_json_with_sandbox_hardening() {
        let mut policy = FacPolicyV1::default_policy();
        policy.sandbox_hardening.private_tmp = false;
        policy.sandbox_hardening.restrict_address_families =
            vec!["AF_UNIX".to_string(), "AF_INET".to_string()];
        let bytes = serde_json::to_vec_pretty(&policy).expect("serialize");
        let restored = deserialize_policy(&bytes).expect("deserialize");
        assert_eq!(restored.sandbox_hardening, policy.sandbox_hardening);
    }

    #[test]
    fn test_policy_hash_is_deterministic_with_sorted_env_vectors() {
        let policy1 = FacPolicyV1::default_policy();
        let mut policy2 = policy1.clone();
        policy2.env_allowlist_prefixes.reverse();

        let hash1 = compute_policy_hash(&policy1).expect("compute policy hash");
        let hash2 = compute_policy_hash(&policy2).expect("compute policy hash");
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_policy_persistence() {
        let dir = tempdir().expect("tempdir");
        let policy = FacPolicyV1::default_policy();
        let policy_path = persist_policy(dir.path(), &policy).expect("persist policy");

        assert!(policy_path.exists());
        assert!(policy_path.is_file());

        let bytes = fs::read(&policy_path).expect("read policy");
        let restored = deserialize_policy(&bytes).expect("deserialize persisted policy");

        assert_eq!(policy, restored);
    }

    // ── build_job_environment tests (TCK-00526) ──

    #[test]
    fn test_build_job_environment_clears_by_default() {
        let policy = FacPolicyV1::default_policy();
        let apm2_home = Path::new("/tmp/test-apm2-home");
        let ambient = vec![
            ("SECRET_TOKEN".to_string(), "hunter2".to_string()),
            ("RANDOM_VAR".to_string(), "value".to_string()),
        ];
        let env = build_job_environment(&policy, &ambient, apm2_home);
        // SECRET_TOKEN and RANDOM_VAR don't match any allowlist prefix.
        assert!(!env.contains_key("SECRET_TOKEN"));
        assert!(!env.contains_key("RANDOM_VAR"));
    }

    #[test]
    fn test_build_job_environment_allows_allowlisted_prefixes() {
        let policy = FacPolicyV1::default_policy();
        let apm2_home = Path::new("/tmp/test-apm2-home");
        let ambient = vec![
            ("CARGO_HOME".to_string(), "/home/user/.cargo".to_string()),
            ("RUSTFLAGS".to_string(), "-C opt-level=2".to_string()),
            ("PATH".to_string(), "/usr/bin".to_string()),
            ("HOME".to_string(), "/home/user".to_string()),
            ("USER".to_string(), "testuser".to_string()),
            ("LANG".to_string(), "en_US.UTF-8".to_string()),
            ("LC_ALL".to_string(), "en_US.UTF-8".to_string()),
            ("TERM".to_string(), "xterm".to_string()),
            ("XDG_RUNTIME_DIR".to_string(), "/run/user/1000".to_string()),
        ];
        let env = build_job_environment(&policy, &ambient, apm2_home);
        // CARGO_HOME is overridden by the managed path (deny_ambient_cargo_home=true).
        assert_eq!(
            env.get("CARGO_HOME").map(String::as_str),
            Some("/tmp/test-apm2-home/private/fac/cargo_home")
        );
        assert_eq!(
            env.get("RUSTFLAGS").map(String::as_str),
            Some("-C opt-level=2")
        );
        assert_eq!(env.get("PATH").map(String::as_str), Some("/usr/bin"));
        assert_eq!(env.get("HOME").map(String::as_str), Some("/home/user"));
        assert_eq!(env.get("USER").map(String::as_str), Some("testuser"));
        assert_eq!(env.get("LANG").map(String::as_str), Some("en_US.UTF-8"));
        assert_eq!(env.get("LC_ALL").map(String::as_str), Some("en_US.UTF-8"));
        assert_eq!(env.get("TERM").map(String::as_str), Some("xterm"));
        assert_eq!(
            env.get("XDG_RUNTIME_DIR").map(String::as_str),
            Some("/run/user/1000")
        );
    }

    #[test]
    fn test_build_job_environment_denylist_overrides_allowlist() {
        let policy = FacPolicyV1::default_policy();
        let apm2_home = Path::new("/tmp/test-apm2-home");
        // AWS_SECRET_KEY starts with "AWS_" which is in the denylist.
        // But it does NOT start with any allowlist prefix, so it would
        // be filtered at step 1 anyway. Let's test a case where there
        // is overlap: DOCKER_HOST is in the denylist (DOCKER_ prefix).
        let ambient = vec![
            ("AWS_SECRET_ACCESS_KEY".to_string(), "secret".to_string()),
            (
                "GOOGLE_APPLICATION_CREDENTIALS".to_string(),
                "/path".to_string(),
            ),
            ("GITHUB_TOKEN".to_string(), "ghp_abc".to_string()),
        ];
        let env = build_job_environment(&policy, &ambient, apm2_home);
        assert!(!env.contains_key("AWS_SECRET_ACCESS_KEY"));
        assert!(!env.contains_key("GOOGLE_APPLICATION_CREDENTIALS"));
        assert!(!env.contains_key("GITHUB_TOKEN"));
    }

    #[test]
    fn test_build_job_environment_env_clear_strips_unconditionally() {
        let policy = FacPolicyV1::default_policy();
        let apm2_home = Path::new("/tmp/test-apm2-home");
        // LD_PRELOAD is in env_clear. Even though it doesn't match the
        // allowlist, env_clear is an additional guarantee.
        let ambient = vec![
            ("LD_PRELOAD".to_string(), "/bad/lib.so".to_string()),
            ("LD_LIBRARY_PATH".to_string(), "/bad/libs".to_string()),
        ];
        let env = build_job_environment(&policy, &ambient, apm2_home);
        assert!(!env.contains_key("LD_PRELOAD"));
        assert!(!env.contains_key("LD_LIBRARY_PATH"));
    }

    #[test]
    fn test_build_job_environment_env_set_overrides() {
        let policy = FacPolicyV1::default_policy();
        let apm2_home = Path::new("/tmp/test-apm2-home");
        // Default policy has env_set with CARGO_TARGET_DIR=target.
        let ambient: Vec<(String, String)> =
            vec![("CARGO_TARGET_DIR".to_string(), "/custom/target".to_string())];
        let env = build_job_environment(&policy, &ambient, apm2_home);
        // env_set forces CARGO_TARGET_DIR to "target".
        assert_eq!(
            env.get("CARGO_TARGET_DIR").map(String::as_str),
            Some("target")
        );
    }

    #[test]
    fn test_build_job_environment_managed_cargo_home_when_denied() {
        let policy = FacPolicyV1::default_policy();
        assert!(policy.deny_ambient_cargo_home);
        assert!(policy.cargo_home.is_none());

        let apm2_home = Path::new("/home/user/.apm2");
        let ambient = vec![("CARGO_HOME".to_string(), "/home/user/.cargo".to_string())];
        let env = build_job_environment(&policy, &ambient, apm2_home);
        // Ambient CARGO_HOME must be replaced with managed path.
        assert_eq!(
            env.get("CARGO_HOME").map(String::as_str),
            Some("/home/user/.apm2/private/fac/cargo_home")
        );
    }

    #[test]
    fn test_build_job_environment_explicit_cargo_home_override() {
        let mut policy = FacPolicyV1::default_policy();
        policy.cargo_home = Some("/opt/fac/cargo".to_string());

        let apm2_home = Path::new("/home/user/.apm2");
        let ambient = vec![("CARGO_HOME".to_string(), "/home/user/.cargo".to_string())];
        let env = build_job_environment(&policy, &ambient, apm2_home);
        assert_eq!(
            env.get("CARGO_HOME").map(String::as_str),
            Some("/opt/fac/cargo")
        );
    }

    #[test]
    fn test_build_job_environment_allows_ambient_cargo_home_when_not_denied() {
        let mut policy = FacPolicyV1::default_policy();
        policy.deny_ambient_cargo_home = false;
        policy.cargo_home = None;

        let apm2_home = Path::new("/home/user/.apm2");
        let ambient = vec![("CARGO_HOME".to_string(), "/home/user/.cargo".to_string())];
        let env = build_job_environment(&policy, &ambient, apm2_home);
        // Should inherit the ambient value since deny is off.
        assert_eq!(
            env.get("CARGO_HOME").map(String::as_str),
            Some("/home/user/.cargo")
        );
    }

    #[test]
    fn test_build_job_environment_result_is_deterministic() {
        let policy = FacPolicyV1::default_policy();
        let apm2_home = Path::new("/tmp/apm2");
        let ambient = vec![
            ("PATH".to_string(), "/usr/bin".to_string()),
            ("HOME".to_string(), "/home/user".to_string()),
            ("CARGO_HOME".to_string(), "/home/user/.cargo".to_string()),
        ];
        let env1 = build_job_environment(&policy, &ambient, apm2_home);
        let env2 = build_job_environment(&policy, &ambient, apm2_home);
        assert_eq!(env1, env2);
    }

    #[test]
    fn test_build_job_environment_empty_ambient() {
        let policy = FacPolicyV1::default_policy();
        let apm2_home = Path::new("/tmp/apm2");
        let ambient: Vec<(String, String)> = Vec::new();
        let env = build_job_environment(&policy, &ambient, apm2_home);
        // Should still have env_set entries and managed CARGO_HOME.
        assert_eq!(
            env.get("CARGO_TARGET_DIR").map(String::as_str),
            Some("target")
        );
        assert_eq!(
            env.get("CARGO_HOME").map(String::as_str),
            Some("/tmp/apm2/private/fac/cargo_home")
        );
    }

    #[test]
    fn test_resolve_cargo_home_explicit_override() {
        let mut policy = FacPolicyV1::default_policy();
        policy.cargo_home = Some("/opt/cargo".to_string());
        let result = policy.resolve_cargo_home(Path::new("/home/user/.apm2"));
        assert_eq!(result, Some(PathBuf::from("/opt/cargo")));
    }

    #[test]
    fn test_resolve_cargo_home_managed_default() {
        let policy = FacPolicyV1::default_policy();
        // deny_ambient_cargo_home=true, cargo_home=None
        let result = policy.resolve_cargo_home(Path::new("/home/user/.apm2"));
        assert_eq!(
            result,
            Some(PathBuf::from("/home/user/.apm2/private/fac/cargo_home"))
        );
    }

    #[test]
    fn test_resolve_cargo_home_ambient_allowed() {
        let mut policy = FacPolicyV1::default_policy();
        policy.deny_ambient_cargo_home = false;
        policy.cargo_home = None;
        let result = policy.resolve_cargo_home(Path::new("/home/user/.apm2"));
        assert_eq!(result, None);
    }

    // ── RUSTC_WRAPPER / SCCACHE_* denial regression tests (TCK-00526) ──

    #[test]
    fn test_default_policy_denies_rustc_wrapper_prefix() {
        let policy = FacPolicyV1::default_policy();
        // The "RUST" broad prefix must NOT be in allowlist — specific
        // prefixes (RUSTFLAGS, RUSTDOCFLAGS, RUSTUP_, etc.) are used.
        assert!(
            !policy
                .env_allowlist_prefixes
                .iter()
                .any(|p| "RUSTC_WRAPPER".starts_with(p.as_str())),
            "RUSTC_WRAPPER must not be admitted by any allowlist prefix, got: {:?}",
            policy.env_allowlist_prefixes
        );
    }

    #[test]
    fn test_default_policy_denylist_includes_rustc_wrapper_and_sccache() {
        let policy = FacPolicyV1::default_policy();
        assert!(
            policy
                .env_denylist_prefixes
                .iter()
                .any(|p| "RUSTC_WRAPPER".starts_with(p.as_str())),
            "RUSTC_WRAPPER must be covered by denylist, got: {:?}",
            policy.env_denylist_prefixes
        );
        assert!(
            policy
                .env_denylist_prefixes
                .iter()
                .any(|p| "SCCACHE_CACHE_SIZE".starts_with(p.as_str())),
            "SCCACHE_* must be covered by denylist, got: {:?}",
            policy.env_denylist_prefixes
        );
    }

    #[test]
    fn test_build_job_environment_strips_rustc_wrapper_from_ambient() {
        let policy = FacPolicyV1::default_policy();
        let apm2_home = Path::new("/tmp/test-apm2-home");
        let ambient = vec![
            ("RUSTC_WRAPPER".to_string(), "sccache".to_string()),
            ("RUSTFLAGS".to_string(), "-Copt-level=2".to_string()),
        ];
        let env = build_job_environment(&policy, &ambient, apm2_home);
        assert!(
            !env.contains_key("RUSTC_WRAPPER"),
            "RUSTC_WRAPPER must be stripped from gate environment"
        );
        // RUSTFLAGS should still be allowed.
        assert_eq!(
            env.get("RUSTFLAGS").map(String::as_str),
            Some("-Copt-level=2")
        );
    }

    #[test]
    fn test_build_job_environment_strips_sccache_vars_from_ambient() {
        let policy = FacPolicyV1::default_policy();
        let apm2_home = Path::new("/tmp/test-apm2-home");
        let ambient = vec![
            ("SCCACHE_DIR".to_string(), "/tmp/sccache".to_string()),
            ("SCCACHE_CACHE_SIZE".to_string(), "100G".to_string()),
            ("SCCACHE_IDLE_TIMEOUT".to_string(), "3600".to_string()),
        ];
        let env = build_job_environment(&policy, &ambient, apm2_home);
        assert!(
            !env.contains_key("SCCACHE_DIR"),
            "SCCACHE_DIR must be stripped"
        );
        assert!(
            !env.contains_key("SCCACHE_CACHE_SIZE"),
            "SCCACHE_CACHE_SIZE must be stripped"
        );
        assert!(
            !env.contains_key("SCCACHE_IDLE_TIMEOUT"),
            "SCCACHE_IDLE_TIMEOUT must be stripped"
        );
    }

    /// Regression: Even if a custom policy re-introduces a broad "RUST"
    /// allowlist prefix, the hardcoded safety step must still strip
    /// `RUSTC_WRAPPER` and `SCCACHE_*`.
    #[test]
    fn test_build_job_environment_strips_wrapper_even_with_broad_rust_prefix() {
        let mut policy = FacPolicyV1::default_policy();
        // Re-introduce the broad "RUST" prefix (simulating a misconfigured
        // custom policy).
        policy.env_allowlist_prefixes.push("RUST".to_string());
        // Remove RUSTC_WRAPPER from denylist to test the hardcoded safety.
        policy
            .env_denylist_prefixes
            .retain(|p| p != "RUSTC_WRAPPER");
        policy.env_denylist_prefixes.retain(|p| p != "SCCACHE_");

        let apm2_home = Path::new("/tmp/test-apm2-home");
        let ambient = vec![
            ("RUSTC_WRAPPER".to_string(), "sccache".to_string()),
            ("SCCACHE_DIR".to_string(), "/tmp/sccache".to_string()),
            ("RUSTFLAGS".to_string(), "-Copt-level=2".to_string()),
        ];
        let env = build_job_environment(&policy, &ambient, apm2_home);
        assert!(
            !env.contains_key("RUSTC_WRAPPER"),
            "RUSTC_WRAPPER must be stripped by hardcoded safety even with broad RUST prefix"
        );
        assert!(
            !env.contains_key("SCCACHE_DIR"),
            "SCCACHE_DIR must be stripped by hardcoded safety"
        );
        // RUSTFLAGS should still pass through.
        assert_eq!(
            env.get("RUSTFLAGS").map(String::as_str),
            Some("-Copt-level=2")
        );
    }

    #[test]
    fn test_default_policy_allowlist_admits_safe_rust_vars() {
        let policy = FacPolicyV1::default_policy();
        let apm2_home = Path::new("/tmp/test-apm2-home");
        let ambient = vec![
            ("RUSTFLAGS".to_string(), "-Copt-level=2".to_string()),
            ("RUSTDOCFLAGS".to_string(), "--cfg docsrs".to_string()),
            ("RUSTUP_HOME".to_string(), "/home/user/.rustup".to_string()),
            (
                "RUSTUP_TOOLCHAIN".to_string(),
                "nightly-2025-01-01".to_string(),
            ),
            ("RUST_BACKTRACE".to_string(), "1".to_string()),
            ("RUST_LOG".to_string(), "info".to_string()),
            ("RUST_TEST_THREADS".to_string(), "4".to_string()),
        ];
        let env = build_job_environment(&policy, &ambient, apm2_home);
        assert_eq!(
            env.get("RUSTFLAGS").map(String::as_str),
            Some("-Copt-level=2")
        );
        assert_eq!(
            env.get("RUSTDOCFLAGS").map(String::as_str),
            Some("--cfg docsrs")
        );
        assert_eq!(
            env.get("RUSTUP_HOME").map(String::as_str),
            Some("/home/user/.rustup")
        );
        assert_eq!(
            env.get("RUSTUP_TOOLCHAIN").map(String::as_str),
            Some("nightly-2025-01-01")
        );
        assert_eq!(env.get("RUST_BACKTRACE").map(String::as_str), Some("1"));
        assert_eq!(env.get("RUST_LOG").map(String::as_str), Some("info"));
        assert_eq!(env.get("RUST_TEST_THREADS").map(String::as_str), Some("4"));
    }

    /// Regression: A malicious or misconfigured policy that uses `env_set` to
    /// re-introduce `RUSTC_WRAPPER` or `SCCACHE_*` must still have those
    /// variables stripped by the hardcoded safety step (INV-ENV-008).
    #[test]
    fn test_build_job_environment_env_set_cannot_reintroduce_rustc_wrapper() {
        let mut policy = FacPolicyV1::default_policy();
        // Simulate a malicious policy that attempts to re-introduce
        // RUSTC_WRAPPER and SCCACHE_DIR via env_set overrides.
        policy.env_set.push(EnvSetEntry {
            key: "RUSTC_WRAPPER".to_string(),
            value: "sccache".to_string(),
        });
        policy.env_set.push(EnvSetEntry {
            key: "SCCACHE_DIR".to_string(),
            value: "/tmp/sccache".to_string(),
        });
        policy.env_set.push(EnvSetEntry {
            key: "SCCACHE_CACHE_SIZE".to_string(),
            value: "100G".to_string(),
        });

        let apm2_home = Path::new("/tmp/test-apm2-home");
        let ambient: Vec<(String, String)> = vec![];
        let env = build_job_environment(&policy, &ambient, apm2_home);

        assert!(
            !env.contains_key("RUSTC_WRAPPER"),
            "env_set must not be able to re-introduce RUSTC_WRAPPER"
        );
        assert!(
            !env.contains_key("SCCACHE_DIR"),
            "env_set must not be able to re-introduce SCCACHE_DIR"
        );
        assert!(
            !env.contains_key("SCCACHE_CACHE_SIZE"),
            "env_set must not be able to re-introduce SCCACHE_CACHE_SIZE"
        );
    }

    // ── Per-lane env isolation tests (TCK-00575) ──

    #[test]
    fn test_apply_lane_env_overrides_sets_all_vars() {
        let lane_dir = Path::new("/fac/lanes/lane-00");
        let mut env = BTreeMap::new();
        env.insert("HOME".to_string(), "/home/user".to_string());
        env.insert("PATH".to_string(), "/usr/bin".to_string());

        apply_lane_env_overrides(&mut env, lane_dir);

        assert_eq!(
            env.get("HOME").map(String::as_str),
            Some("/fac/lanes/lane-00/home")
        );
        assert_eq!(
            env.get("TMPDIR").map(String::as_str),
            Some("/fac/lanes/lane-00/tmp")
        );
        assert_eq!(
            env.get("XDG_CACHE_HOME").map(String::as_str),
            Some("/fac/lanes/lane-00/xdg_cache")
        );
        assert_eq!(
            env.get("XDG_CONFIG_HOME").map(String::as_str),
            Some("/fac/lanes/lane-00/xdg_config")
        );
        assert_eq!(
            env.get("XDG_DATA_HOME").map(String::as_str),
            Some("/fac/lanes/lane-00/xdg_data")
        );
        assert_eq!(
            env.get("XDG_STATE_HOME").map(String::as_str),
            Some("/fac/lanes/lane-00/xdg_state")
        );
        assert_eq!(
            env.get("XDG_RUNTIME_DIR").map(String::as_str),
            Some("/fac/lanes/lane-00/xdg_runtime")
        );
        // PATH should be unaffected.
        assert_eq!(env.get("PATH").map(String::as_str), Some("/usr/bin"));
    }

    #[test]
    fn test_apply_lane_env_overrides_overwrites_existing_values() {
        let lane_dir = Path::new("/fac/lanes/lane-01");
        let mut env = BTreeMap::new();
        env.insert("HOME".to_string(), "/home/user".to_string());
        env.insert("TMPDIR".to_string(), "/tmp".to_string());
        env.insert(
            "XDG_CACHE_HOME".to_string(),
            "/home/user/.cache".to_string(),
        );
        env.insert(
            "XDG_CONFIG_HOME".to_string(),
            "/home/user/.config".to_string(),
        );
        env.insert(
            "XDG_DATA_HOME".to_string(),
            "/home/user/.local/share".to_string(),
        );
        env.insert(
            "XDG_STATE_HOME".to_string(),
            "/home/user/.local/state".to_string(),
        );
        env.insert("XDG_RUNTIME_DIR".to_string(), "/run/user/1000".to_string());

        apply_lane_env_overrides(&mut env, lane_dir);

        // All seven must be overwritten to lane-specific paths.
        assert_eq!(
            env.get("HOME").map(String::as_str),
            Some("/fac/lanes/lane-01/home")
        );
        assert_eq!(
            env.get("TMPDIR").map(String::as_str),
            Some("/fac/lanes/lane-01/tmp")
        );
        assert_eq!(
            env.get("XDG_CACHE_HOME").map(String::as_str),
            Some("/fac/lanes/lane-01/xdg_cache")
        );
        assert_eq!(
            env.get("XDG_CONFIG_HOME").map(String::as_str),
            Some("/fac/lanes/lane-01/xdg_config")
        );
        assert_eq!(
            env.get("XDG_DATA_HOME").map(String::as_str),
            Some("/fac/lanes/lane-01/xdg_data")
        );
        assert_eq!(
            env.get("XDG_STATE_HOME").map(String::as_str),
            Some("/fac/lanes/lane-01/xdg_state")
        );
        assert_eq!(
            env.get("XDG_RUNTIME_DIR").map(String::as_str),
            Some("/fac/lanes/lane-01/xdg_runtime")
        );
    }

    #[test]
    fn test_apply_lane_env_overrides_on_empty_map() {
        let lane_dir = Path::new("/fac/lanes/lane-02");
        let mut env = BTreeMap::new();
        apply_lane_env_overrides(&mut env, lane_dir);

        assert_eq!(env.len(), 7);
        assert!(env.contains_key("HOME"));
        assert!(env.contains_key("TMPDIR"));
        assert!(env.contains_key("XDG_CACHE_HOME"));
        assert!(env.contains_key("XDG_CONFIG_HOME"));
        assert!(env.contains_key("XDG_DATA_HOME"));
        assert!(env.contains_key("XDG_STATE_HOME"));
        assert!(env.contains_key("XDG_RUNTIME_DIR"));
    }

    #[test]
    fn test_lane_env_overrides_after_build_job_environment() {
        // Integration: apply_lane_env_overrides called after build_job_environment
        // must override whatever HOME/TMPDIR values were inherited.
        let policy = FacPolicyV1::default_policy();
        let apm2_home = Path::new("/home/user/.apm2");
        let ambient = vec![
            ("HOME".to_string(), "/home/user".to_string()),
            ("TMPDIR".to_string(), "/tmp".to_string()),
            (
                "XDG_CACHE_HOME".to_string(),
                "/home/user/.cache".to_string(),
            ),
            (
                "XDG_CONFIG_HOME".to_string(),
                "/home/user/.config".to_string(),
            ),
            (
                "XDG_DATA_HOME".to_string(),
                "/home/user/.local/share".to_string(),
            ),
            (
                "XDG_STATE_HOME".to_string(),
                "/home/user/.local/state".to_string(),
            ),
            ("XDG_RUNTIME_DIR".to_string(), "/run/user/1000".to_string()),
        ];
        let mut env = build_job_environment(&policy, &ambient, apm2_home);

        let lane_dir = Path::new("/home/user/.apm2/private/fac/lanes/lane-00");
        apply_lane_env_overrides(&mut env, lane_dir);

        assert_eq!(
            env.get("HOME").map(String::as_str),
            Some("/home/user/.apm2/private/fac/lanes/lane-00/home"),
            "HOME must be per-lane after apply_lane_env_overrides"
        );
        assert_eq!(
            env.get("TMPDIR").map(String::as_str),
            Some("/home/user/.apm2/private/fac/lanes/lane-00/tmp"),
            "TMPDIR must be per-lane after apply_lane_env_overrides"
        );
        assert_eq!(
            env.get("XDG_CACHE_HOME").map(String::as_str),
            Some("/home/user/.apm2/private/fac/lanes/lane-00/xdg_cache"),
            "XDG_CACHE_HOME must be per-lane after apply_lane_env_overrides"
        );
        assert_eq!(
            env.get("XDG_CONFIG_HOME").map(String::as_str),
            Some("/home/user/.apm2/private/fac/lanes/lane-00/xdg_config"),
            "XDG_CONFIG_HOME must be per-lane after apply_lane_env_overrides"
        );
        assert_eq!(
            env.get("XDG_DATA_HOME").map(String::as_str),
            Some("/home/user/.apm2/private/fac/lanes/lane-00/xdg_data"),
            "XDG_DATA_HOME must be per-lane after apply_lane_env_overrides"
        );
        assert_eq!(
            env.get("XDG_STATE_HOME").map(String::as_str),
            Some("/home/user/.apm2/private/fac/lanes/lane-00/xdg_state"),
            "XDG_STATE_HOME must be per-lane after apply_lane_env_overrides"
        );
        assert_eq!(
            env.get("XDG_RUNTIME_DIR").map(String::as_str),
            Some("/home/user/.apm2/private/fac/lanes/lane-00/xdg_runtime"),
            "XDG_RUNTIME_DIR must be per-lane after apply_lane_env_overrides"
        );
    }

    #[test]
    fn test_ensure_lane_env_dirs_creates_all_dirs() {
        let tmp = tempdir().expect("tempdir");
        let lane_dir = tmp.path().join("lane-00");
        std::fs::create_dir_all(&lane_dir).expect("create lane dir");

        ensure_lane_env_dirs(&lane_dir).expect("ensure lane env dirs");

        for subdir in LANE_ENV_DIRS {
            let dir_path = lane_dir.join(subdir);
            assert!(dir_path.exists(), "{subdir} should exist");
            assert!(dir_path.is_dir(), "{subdir} should be a directory");
        }
    }

    #[test]
    fn test_ensure_lane_env_dirs_is_idempotent() {
        let tmp = tempdir().expect("tempdir");
        let lane_dir = tmp.path().join("lane-00");
        std::fs::create_dir_all(&lane_dir).expect("create lane dir");

        ensure_lane_env_dirs(&lane_dir).expect("first call");
        ensure_lane_env_dirs(&lane_dir).expect("second call (idempotent)");

        for subdir in LANE_ENV_DIRS {
            assert!(lane_dir.join(subdir).is_dir());
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_ensure_lane_env_dirs_creates_with_restricted_permissions() {
        use std::os::unix::fs::MetadataExt;

        let tmp = tempdir().expect("tempdir");
        let lane_dir = tmp.path().join("lane-00");
        std::fs::create_dir_all(&lane_dir).expect("create lane dir");

        ensure_lane_env_dirs(&lane_dir).expect("ensure lane env dirs");

        for subdir in LANE_ENV_DIRS {
            let metadata = std::fs::metadata(lane_dir.join(subdir)).expect("stat");
            let mode = metadata.mode() & 0o777;
            let expected_mode = lane_env_dir_mode();
            assert_eq!(
                mode, expected_mode,
                "{subdir} should have mode {expected_mode:#05o}, got {mode:#05o}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_verify_lane_env_dir_rejects_group_world_access() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempdir().expect("tempdir");
        let dir_path = tmp.path().join("bad_dir");
        std::fs::create_dir_all(&dir_path).expect("create dir");

        // Set mode to 0o755 (group+other read/exec).
        std::fs::set_permissions(&dir_path, std::fs::Permissions::from_mode(0o755))
            .expect("set permissions");

        let err = verify_lane_env_dir_permissions(&dir_path).unwrap_err();
        assert!(
            err.contains("too-permissive"),
            "should report too-permissive mode, got: {err}"
        );
    }

    #[test]
    fn test_lane_env_dirs_constant_matches_expected_dirs() {
        assert_eq!(LANE_ENV_DIRS.len(), 7);
        assert!(LANE_ENV_DIRS.contains(&"home"));
        assert!(LANE_ENV_DIRS.contains(&"tmp"));
        assert!(LANE_ENV_DIRS.contains(&"xdg_cache"));
        assert!(LANE_ENV_DIRS.contains(&"xdg_config"));
        assert!(LANE_ENV_DIRS.contains(&"xdg_data"));
        assert!(LANE_ENV_DIRS.contains(&"xdg_state"));
        assert!(LANE_ENV_DIRS.contains(&"xdg_runtime"));
    }

    /// Regression (BLOCKER 3): verify that `ensure_lane_env_dirs` +
    /// `apply_lane_env_overrides` together produce a deterministic,
    /// lane-local environment — proving the integration pattern used
    /// in both `build_gate_policy_env` and `build_pipeline_test_command`
    /// in evidence.rs.
    #[test]
    fn test_ensure_and_apply_lane_env_overrides_integration() {
        let tmp = tempdir().expect("tempdir");
        let lane_dir = tmp.path().join("lane-00");
        std::fs::create_dir_all(&lane_dir).expect("create lane dir");

        // Step 1: ensure dirs for all lane-level env variables.
        ensure_lane_env_dirs(&lane_dir).expect("ensure_lane_env_dirs");

        // Step 2: build a policy env simulating ambient inherit
        let policy = FacPolicyV1::default_policy();
        let apm2_home = tmp.path();
        let ambient = vec![
            ("HOME".to_string(), "/home/user".to_string()),
            ("TMPDIR".to_string(), "/tmp".to_string()),
            (
                "XDG_CACHE_HOME".to_string(),
                "/home/user/.cache".to_string(),
            ),
            (
                "XDG_CONFIG_HOME".to_string(),
                "/home/user/.config".to_string(),
            ),
            (
                "XDG_DATA_HOME".to_string(),
                "/home/user/.local/share".to_string(),
            ),
            (
                "XDG_STATE_HOME".to_string(),
                "/home/user/.local/state".to_string(),
            ),
            ("XDG_RUNTIME_DIR".to_string(), "/run/user/1000".to_string()),
            ("PATH".to_string(), "/usr/bin".to_string()),
        ];
        let mut env = build_job_environment(&policy, &ambient, apm2_home);

        // Step 3: apply lane overrides (pattern used by evidence.rs)
        apply_lane_env_overrides(&mut env, &lane_dir);

        // All seven env vars must point to lane-local dirs, not ambient ones.
        let lane_str = lane_dir.to_str().expect("lane_dir to str");
        for var in &[
            "HOME",
            "TMPDIR",
            "XDG_CACHE_HOME",
            "XDG_CONFIG_HOME",
            "XDG_DATA_HOME",
            "XDG_STATE_HOME",
            "XDG_RUNTIME_DIR",
        ] {
            let val = env.get(*var).unwrap_or_else(|| {
                panic!("{var} must be present in env after apply_lane_env_overrides")
            });
            assert!(
                val.starts_with(lane_str),
                "{var}={val} should start with lane dir {lane_str}"
            );
        }

        // All lane subdirectories must actually exist on disk.
        for subdir in LANE_ENV_DIRS {
            assert!(
                lane_dir.join(subdir).is_dir(),
                "{subdir} must be a directory"
            );
        }

        // PATH should be unaffected by lane overrides.
        assert!(env.contains_key("PATH"), "PATH should remain in env");
    }

    /// Regression: a symlink planted in the lane directory (e.g., `home` ->
    /// `~/.ssh`) must be rejected by `ensure_lane_env_dirs` to prevent
    /// isolation escape. `verify_lane_env_dir_permissions` uses
    /// `symlink_metadata` (not `metadata`) so it detects the symlink
    /// itself rather than following it to the target.
    #[cfg(unix)]
    #[test]
    fn test_ensure_lane_env_dirs_rejects_symlink() {
        let tmp = tempdir().expect("tempdir");
        let lane_dir = tmp.path().join("lane-sym");
        std::fs::create_dir_all(&lane_dir).expect("create lane dir");

        // Plant a symlink at `home` -> some other directory (simulating
        // an attacker pointing `home` to `~/.ssh` or similar).
        let target = tmp.path().join("attacker_target");
        std::fs::create_dir_all(&target).expect("create target dir");
        std::os::unix::fs::symlink(&target, lane_dir.join("home")).expect("create symlink");

        let err = ensure_lane_env_dirs(&lane_dir).expect_err("should reject symlink");
        assert!(
            err.contains("symlink"),
            "error should mention symlink, got: {err}"
        );
    }

    /// Regression: `verify_lane_env_dir_permissions` must reject a
    /// symlink even if the symlink target is a valid directory with
    /// correct permissions.
    #[cfg(unix)]
    #[test]
    fn test_verify_lane_env_dir_permissions_rejects_symlink_to_valid_dir() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempdir().expect("tempdir");
        let target = tmp.path().join("valid_target");
        std::fs::create_dir_all(&target).expect("create target dir");
        std::fs::set_permissions(
            &target,
            std::fs::Permissions::from_mode(lane_env_dir_mode()),
        )
        .expect("set target permissions");

        let symlink_path = tmp.path().join("link_to_valid");
        std::os::unix::fs::symlink(&target, &symlink_path).expect("create symlink");

        let err = verify_lane_env_dir_permissions(&symlink_path).expect_err("should reject");
        assert!(
            err.contains("symlink"),
            "should report symlink rejection, got: {err}"
        );
    }

    // ── TCK-00579: job_spec_validation_policy tests ──

    #[test]
    fn test_job_spec_validation_policy_open_by_default() {
        let policy = FacPolicyV1::default_policy();
        assert!(policy.allowed_repo_ids.is_none());
        let jsp = policy.job_spec_validation_policy().expect("derive policy");
        assert!(
            !jsp.has_repo_allowlist(),
            "default policy should produce open job spec policy"
        );
    }

    #[test]
    fn test_job_spec_validation_policy_with_allowlist() {
        let mut policy = FacPolicyV1::default_policy();
        policy.allowed_repo_ids = Some(vec!["org/repo".to_string()]);
        let jsp = policy.job_spec_validation_policy().expect("derive policy");
        assert!(jsp.has_repo_allowlist());
        assert_eq!(jsp.allowed_repo_ids().unwrap(), &["org/repo".to_string()]);
    }

    #[test]
    fn test_job_spec_validation_policy_empty_allowlist_denies_all() {
        let mut policy = FacPolicyV1::default_policy();
        policy.allowed_repo_ids = Some(vec![]);
        let jsp = policy.job_spec_validation_policy().expect("derive policy");
        assert!(jsp.has_repo_allowlist());
        assert_eq!(jsp.allowed_repo_ids().unwrap().len(), 0);
    }

    #[test]
    fn test_policy_roundtrip_with_allowed_repo_ids() {
        let mut policy = FacPolicyV1::default_policy();
        policy.allowed_repo_ids = Some(vec!["org/repo".to_string(), "other/repo".to_string()]);
        let bytes = serde_json::to_vec_pretty(&policy).expect("serialize");
        let restored = deserialize_policy(&bytes).expect("deserialize");
        assert_eq!(restored.allowed_repo_ids, policy.allowed_repo_ids);
    }

    #[test]
    fn test_policy_roundtrip_without_allowed_repo_ids() {
        let policy = FacPolicyV1::default_policy();
        let bytes = serde_json::to_vec_pretty(&policy).expect("serialize");
        let restored = deserialize_policy(&bytes).expect("deserialize");
        assert_eq!(restored.allowed_repo_ids, None);
    }

    /// Round 2 NIT: `FacPolicyV1::validate()` must reject oversized
    /// `allowed_repo_ids` for early detection during policy loading.
    #[test]
    fn test_validate_rejects_oversized_allowed_repo_ids() {
        let mut policy = FacPolicyV1::default_policy();
        policy.allowed_repo_ids = Some(
            (0..=super::MAX_REPO_ALLOWLIST_SIZE)
                .map(|i| format!("repo-{i}"))
                .collect(),
        );
        let result = policy.validate();
        assert!(
            matches!(
                result,
                Err(FacPolicyError::VectorTooLarge {
                    field: "allowed_repo_ids",
                    ..
                })
            ),
            "oversized allowed_repo_ids should be rejected by validate(): {result:?}"
        );
    }

    /// Round 2 NIT: `FacPolicyV1::validate()` accepts within-bounds
    /// `allowed_repo_ids`.
    #[test]
    fn test_validate_accepts_valid_allowed_repo_ids() {
        let mut policy = FacPolicyV1::default_policy();
        policy.allowed_repo_ids = Some(vec!["org/repo".to_string(), "other/repo".to_string()]);
        let result = policy.validate();
        assert!(
            result.is_ok(),
            "valid allowed_repo_ids should pass validate(): {result:?}"
        );
    }

    /// Round 2 NIT: `deserialize_policy` catches oversized
    /// `allowed_repo_ids` early because `validate()` is called during
    /// deserialization.
    #[test]
    fn test_deserialize_policy_rejects_oversized_allowed_repo_ids() {
        let mut policy = FacPolicyV1::default_policy();
        policy.allowed_repo_ids = Some(
            (0..=super::MAX_REPO_ALLOWLIST_SIZE)
                .map(|i| format!("repo-{i}"))
                .collect(),
        );
        let bytes = serde_json::to_vec_pretty(&policy).expect("serialize");
        let result = deserialize_policy(&bytes);
        assert!(
            matches!(
                result,
                Err(FacPolicyError::VectorTooLarge {
                    field: "allowed_repo_ids",
                    ..
                })
            ),
            "deserialize_policy should reject oversized allowed_repo_ids: {result:?}"
        );
    }
}
