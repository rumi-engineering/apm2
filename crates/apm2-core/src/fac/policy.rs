// AGENT-AUTHORED
//! Authoritative FAC execution policy object for RFC-0028.
//!
//! A policy defines the environment and security constraints that apply to an
//! FAC execution worker. Policy hashes are computed from canonicalized
//! JSON-like bytes with domain separation, and the resulting digest is embedded
//! in RFC-0028 boundary bindings.

use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::job_spec::parse_b3_256_digest;
use super::policy_resolution::{DeterminismClass, RiskTier};
use crate::determinism::canonicalize_json;

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

    /// Risk tier for this policy.
    pub risk_tier: RiskTier,

    /// Determinism class for this policy.
    pub determinism_class: DeterminismClass,
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
                "RUST".to_string(),
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
            ],
            env_set: vec![EnvSetEntry {
                key: "CARGO_TARGET_DIR".to_string(),
                value: "target".to_string(),
            }],
            deny_ambient_cargo_home: true,
            cargo_target_dir: Some("target".to_string()),
            cargo_home: None,
            risk_tier: RiskTier::Tier2,
            determinism_class: DeterminismClass::SoftDeterministic,
        }
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

        Ok(())
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
}
