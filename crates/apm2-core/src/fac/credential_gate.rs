//! Credential gate for FAC workflows (TCK-00596).
//!
//! This module provides a fail-fast credential posture check and a typed
//! credential mount descriptor for FAC execution paths. The gate ensures:
//!
//! - `apm2 fac gates` (local-only) never requires GitHub credentials.
//! - GitHub-facing commands (`fac push`, `fac review run`) fail fast with
//!   actionable errors when credentials are missing.
//! - Secrets never enter job specs, receipts, or log output.
//!
//! # Secret Backend Resolution
//!
//! Credential resolution follows a three-tier fallback chain implemented by
//! [`crate::config::resolve_github_token`]:
//!
//! 1. Environment variable (`GITHUB_TOKEN` / `GH_TOKEN`).
//! 2. Systemd credential directory (`$CREDENTIALS_DIRECTORY/gh-token`).
//! 3. APM2 credential file (`$APM2_HOME/private/creds/gh-token`).
//!
//! This module does NOT re-resolve tokens; it delegates to the existing
//! resolution chain and wraps the result in a typed posture report.
//!
//! # Security Invariants
//!
//! - [INV-CREDGATE-001] `CredentialPosture` never carries raw secret material.
//!   It reports the *source* of resolution, not the secret value itself.
//! - [INV-CREDGATE-002] `require_github_credentials()` returns `Err` with an
//!   actionable remediation message when no credential source is available.
//! - [INV-CREDGATE-003] `CredentialMountV1` carries metadata only (env var
//!   names and file paths). Secret values are resolved and injected at
//!   execution time, never serialized into receipts/logs.
//! - [INV-CREDGATE-004] Missing credentials block only GitHub-facing workflows;
//!   the gate is never called on the `apm2 fac gates` path.

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;

use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};

/// Schema identifier for `CredentialMountV1`.
pub const CREDENTIAL_MOUNT_SCHEMA_ID: &str = "apm2.fac.credential_mount.v1";

/// Maximum number of environment variable mounts in a single credential mount.
pub const MAX_ENV_MOUNTS: usize = 16;

/// Maximum number of file mounts in a single credential mount.
pub const MAX_FILE_MOUNTS: usize = 16;

/// Maximum length of an environment variable name in a credential mount.
pub const MAX_ENV_NAME_LENGTH: usize = 256;

/// Maximum length of a mounted file path in bytes.
pub const MAX_FILE_PATH_LENGTH: usize = 4096;

/// The source from which a credential was resolved.
///
/// This enum is safe to log and serialize because it carries only the
/// *provenance* of the credential, never the secret value itself
/// (INV-CREDGATE-001).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialSource {
    /// Resolved from an environment variable (e.g., `GITHUB_TOKEN`).
    EnvVar {
        /// The name of the environment variable.
        var_name: String,
    },

    /// Resolved from a systemd credential file under `$CREDENTIALS_DIRECTORY`.
    SystemdCredential {
        /// The credential name (e.g., `gh-token`).
        credential_name: String,
    },

    /// Resolved from an APM2 credential file under `$APM2_HOME/private/creds/`.
    Apm2CredentialFile {
        /// The credential file name (e.g., `gh-token`).
        file_name: String,
    },

    /// Resolved from a GitHub App configuration.
    GitHubApp,
}

impl fmt::Display for CredentialSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EnvVar { var_name } => write!(f, "env:{var_name}"),
            Self::SystemdCredential { credential_name } => {
                write!(f, "systemd-credential:{credential_name}")
            },
            Self::Apm2CredentialFile { file_name } => {
                write!(f, "apm2-cred-file:{file_name}")
            },
            Self::GitHubApp => write!(f, "github-app"),
        }
    }
}

/// Credential posture for a specific credential requirement.
///
/// Safe to log and serialize: contains only provenance, never raw secrets
/// (INV-CREDGATE-001).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialPosture {
    /// Human-readable name for this credential (e.g., "github-token").
    pub credential_name: String,

    /// Whether the credential was successfully resolved.
    pub resolved: bool,

    /// The source from which the credential was resolved, if any.
    pub source: Option<CredentialSource>,
}

/// Descriptor for how secrets are mounted into an execution context.
///
/// This type is safe to serialize into receipts and logs because it describes
/// the *shape* of the mount (env var names, file paths) without carrying
/// the secret values themselves (INV-CREDGATE-003).
///
/// # Bounded Collections
///
/// - `env_mounts` is bounded by [`MAX_ENV_MOUNTS`].
/// - `file_mounts` is bounded by [`MAX_FILE_MOUNTS`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialMountV1 {
    /// Schema identifier for forward-compatible parsing.
    /// Must equal [`CREDENTIAL_MOUNT_SCHEMA_ID`].
    pub schema: String,

    /// Environment variable names that will carry secrets at runtime.
    /// Values are NOT included — only the variable names.
    pub env_mounts: Vec<EnvMount>,

    /// File paths where secrets will be available at runtime.
    /// Contents are NOT included — only the paths.
    pub file_mounts: Vec<FileMountDescriptor>,
}

/// An environment variable mount descriptor.
///
/// Describes which env var will carry a secret, and from which source.
/// Does NOT carry the secret value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvMount {
    /// The environment variable name (e.g., `GITHUB_TOKEN`).
    pub env_name: String,

    /// The source from which this credential will be resolved.
    pub source: CredentialSource,
}

/// A file mount descriptor for credential files.
///
/// Describes where a credential file will be available, without
/// carrying the file contents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileMountDescriptor {
    /// The file path where the credential will be available.
    pub path: PathBuf,

    /// The source of the credential.
    pub source: CredentialSource,
}

/// Error returned when required credentials are missing.
#[derive(Debug, Clone, thiserror::Error)]
pub enum CredentialGateError {
    /// GitHub credentials are required but not available.
    #[error(
        "GitHub credentials required but not found. \
         Checked: GITHUB_TOKEN/GH_TOKEN env vars, \
         $CREDENTIALS_DIRECTORY/gh-token (systemd LoadCredential), \
         $APM2_HOME/private/creds/gh-token, \
         github_app.toml (GitHub App). \
         Remediation: export GITHUB_TOKEN=<token>, \
         write token to $APM2_HOME/private/creds/gh-token, \
         add LoadCredential=gh-token:/path/to/token to your systemd unit, \
         or run `apm2 fac pr auth-setup` to configure a GitHub App."
    )]
    GitHubCredentialsMissing,

    /// Credential mount schema is not recognized.
    #[error("credential mount schema mismatch: expected {expected}, got {actual}")]
    InvalidCredentialMountSchema {
        /// Expected schema identifier.
        expected: &'static str,
        /// Actual schema identifier.
        actual: String,
    },

    /// Too many environment mounts in the credential mount.
    #[error("too many env mounts: {count} > {}", MAX_ENV_MOUNTS)]
    TooManyEnvMounts {
        /// The number of env mounts attempted.
        count: usize,
    },

    /// Too many file mounts in the credential mount.
    #[error("too many file mounts: {count} > {}", MAX_FILE_MOUNTS)]
    TooManyFileMounts {
        /// The number of file mounts attempted.
        count: usize,
    },

    /// Environment variable name too long.
    #[error("env var name too long: {length} > {}", MAX_ENV_NAME_LENGTH)]
    EnvNameTooLong {
        /// The length of the env var name.
        length: usize,
    },

    /// File mount path too long.
    #[error("file mount path too long: {length} > {}", MAX_FILE_PATH_LENGTH)]
    FileMountPathTooLong {
        /// The length of the file path.
        length: usize,
    },

    /// Credential source field exceeds bounded length.
    #[error(
        "credential source field {field} too long: {length} > {}",
        MAX_ENV_NAME_LENGTH
    )]
    CredentialSourceFieldTooLong {
        /// The source field name.
        field: &'static str,
        /// The field length.
        length: usize,
    },

    /// A credential mount resolved to no usable credential payload.
    #[error("credential payload unavailable for source {credential_source}")]
    CredentialPayloadUnavailable {
        /// Source identifier associated with the failed payload resolution.
        credential_source: String,
    },
}

/// Check the current GitHub credential posture without resolving the secret
/// value.
///
/// Returns a [`CredentialPosture`] describing whether credentials are available
/// and from which source. The returned value is safe to log and serialize
/// (no secret material).
///
/// This function uses the shared secure token resolution path in
/// `crate::config::resolve_github_token_with_source`, then discards secret
/// material immediately and reports provenance only.
#[must_use]
pub fn check_github_credential_posture() -> CredentialPosture {
    let github_token_source = crate::config::resolve_github_token_with_source("GITHUB_TOKEN")
        .map(|(_token, source)| source);
    if matches!(
        github_token_source,
        Some(crate::config::ResolvedGitHubTokenSource::EnvVar)
    ) {
        return resolved_posture(CredentialSource::EnvVar {
            var_name: "GITHUB_TOKEN".to_string(),
        });
    }

    let gh_token_source =
        crate::config::resolve_github_token_with_source("GH_TOKEN").map(|(_token, source)| source);
    if matches!(
        gh_token_source,
        Some(crate::config::ResolvedGitHubTokenSource::EnvVar)
    ) {
        return resolved_posture(CredentialSource::EnvVar {
            var_name: "GH_TOKEN".to_string(),
        });
    }

    // After env vars, preserve fallback order: systemd credential, then APM2 file.
    for source in [github_token_source, gh_token_source].into_iter().flatten() {
        match source {
            crate::config::ResolvedGitHubTokenSource::EnvVar => {},
            crate::config::ResolvedGitHubTokenSource::SystemdCredential => {
                return resolved_posture(CredentialSource::SystemdCredential {
                    credential_name: "gh-token".to_string(),
                });
            },
            crate::config::ResolvedGitHubTokenSource::Apm2CredentialFile => {
                return resolved_posture(CredentialSource::Apm2CredentialFile {
                    file_name: "gh-token".to_string(),
                });
            },
        }
    }

    // Check GitHub App config
    if crate::github::load_github_app_config().is_some() {
        return resolved_posture(CredentialSource::GitHubApp);
    }

    CredentialPosture {
        credential_name: "github-token".to_string(),
        resolved: false,
        source: None,
    }
}

fn resolved_posture(source: CredentialSource) -> CredentialPosture {
    CredentialPosture {
        credential_name: "github-token".to_string(),
        resolved: true,
        source: Some(source),
    }
}

/// Fail-fast gate: require GitHub credentials to be available.
///
/// Call this at the entry point of GitHub-facing commands (`fac push`,
/// `fac review run`, etc.) to produce an actionable error before
/// attempting any GitHub API operations.
///
/// # Errors
///
/// Returns [`CredentialGateError::GitHubCredentialsMissing`] with
/// detailed remediation instructions if no credential source is available.
pub fn require_github_credentials() -> Result<CredentialPosture, CredentialGateError> {
    let posture = check_github_credential_posture();
    if posture.resolved {
        Ok(posture)
    } else {
        Err(CredentialGateError::GitHubCredentialsMissing)
    }
}

/// Build a [`CredentialMountV1`] descriptor for the current GitHub credential
/// posture.
///
/// This produces a receipt-safe descriptor of how credentials are mounted,
/// without carrying any secret values. Suitable for inclusion in job specs
/// and evidence bundles.
///
/// Returns `None` if no GitHub credentials are available.
#[must_use]
pub fn build_github_credential_mount() -> Option<CredentialMountV1> {
    let posture = check_github_credential_posture();
    if !posture.resolved {
        return None;
    }

    let source = posture.source?;

    let env_mounts = match &source {
        CredentialSource::EnvVar { var_name } => vec![EnvMount {
            env_name: var_name.clone(),
            source: source.clone(),
        }],
        CredentialSource::GitHubApp => Vec::new(),
        // For non-env sources, the credential is typically injected as
        // GITHUB_TOKEN at runtime by the execution backend.
        _ => vec![EnvMount {
            env_name: "GITHUB_TOKEN".to_string(),
            source: source.clone(),
        }],
    };

    let file_mounts = match &source {
        CredentialSource::SystemdCredential { credential_name } => {
            std::env::var("CREDENTIALS_DIRECTORY").map_or_else(
                |_| vec![],
                |cred_dir| {
                    vec![FileMountDescriptor {
                        path: PathBuf::from(cred_dir).join(credential_name),
                        source: source.clone(),
                    }]
                },
            )
        },
        CredentialSource::Apm2CredentialFile { file_name } => crate::github::resolve_apm2_home()
            .map_or_else(Vec::new, |apm2_home| {
                vec![FileMountDescriptor {
                    path: apm2_home.join("private/creds").join(file_name),
                    source: source.clone(),
                }]
            }),
        _ => vec![],
    };

    Some(CredentialMountV1 {
        schema: CREDENTIAL_MOUNT_SCHEMA_ID.to_string(),
        env_mounts,
        file_mounts,
    })
}

/// Apply a validated credential mount to a hardened job environment map.
///
/// This injects runtime credential values into `env` using mount metadata
/// (`env_mounts`) without serializing secret material into receipts.
///
/// # Errors
///
/// Returns an error if:
/// - The mount fails bounds validation.
/// - `env_mounts` requires a credential payload that cannot be resolved.
pub fn apply_credential_mount_to_env(
    mount: &CredentialMountV1,
    env: &mut BTreeMap<String, String>,
    ambient_env: &[(String, String)],
) -> Result<(), CredentialGateError> {
    validate_credential_mount(mount)?;

    if mount.env_mounts.is_empty() {
        return Ok(());
    }

    let primary_source = mount_primary_source(mount).ok_or_else(|| {
        CredentialGateError::CredentialPayloadUnavailable {
            credential_source: "unknown".to_string(),
        }
    })?;
    let token = resolve_mount_token(primary_source, ambient_env).ok_or_else(|| {
        CredentialGateError::CredentialPayloadUnavailable {
            credential_source: primary_source.to_string(),
        }
    })?;

    for env_mount in &mount.env_mounts {
        env.insert(env_mount.env_name.clone(), token.clone());
    }

    // Ensure GITHUB_TOKEN is present as a compatibility alias when mounts
    // provide only GH_TOKEN.
    let has_github_token_mount = mount
        .env_mounts
        .iter()
        .any(|entry| entry.env_name == "GITHUB_TOKEN");
    if !has_github_token_mount {
        env.insert("GITHUB_TOKEN".to_string(), token);
    }

    Ok(())
}

fn mount_primary_source(mount: &CredentialMountV1) -> Option<&CredentialSource> {
    mount
        .env_mounts
        .first()
        .map(|entry| &entry.source)
        .or_else(|| mount.file_mounts.first().map(|entry| &entry.source))
}

fn resolve_mount_token(
    source: &CredentialSource,
    ambient_env: &[(String, String)],
) -> Option<String> {
    match source {
        CredentialSource::EnvVar { var_name } => resolve_ambient_env(ambient_env, var_name),
        CredentialSource::SystemdCredential { .. }
        | CredentialSource::Apm2CredentialFile { .. } => {
            crate::config::resolve_github_token("GITHUB_TOKEN")
                .or_else(|| crate::config::resolve_github_token("GH_TOKEN"))
                .map(|secret| secret.expose_secret().to_string())
        },
        CredentialSource::GitHubApp => None,
    }
}

fn resolve_ambient_env(ambient_env: &[(String, String)], var_name: &str) -> Option<String> {
    ambient_env
        .iter()
        .rev()
        .find(|(key, value)| key == var_name && !value.is_empty())
        .map(|(_, value)| value.clone())
}

/// Validate a [`CredentialMountV1`] for bounded collection sizes.
///
/// # Errors
///
/// Returns an error if any bounds are exceeded.
pub fn validate_credential_mount(mount: &CredentialMountV1) -> Result<(), CredentialGateError> {
    if mount.schema != CREDENTIAL_MOUNT_SCHEMA_ID {
        return Err(CredentialGateError::InvalidCredentialMountSchema {
            expected: CREDENTIAL_MOUNT_SCHEMA_ID,
            actual: mount.schema.clone(),
        });
    }
    if mount.env_mounts.len() > MAX_ENV_MOUNTS {
        return Err(CredentialGateError::TooManyEnvMounts {
            count: mount.env_mounts.len(),
        });
    }
    if mount.file_mounts.len() > MAX_FILE_MOUNTS {
        return Err(CredentialGateError::TooManyFileMounts {
            count: mount.file_mounts.len(),
        });
    }
    for env_mount in &mount.env_mounts {
        if env_mount.env_name.len() > MAX_ENV_NAME_LENGTH {
            return Err(CredentialGateError::EnvNameTooLong {
                length: env_mount.env_name.len(),
            });
        }
        validate_credential_source(&env_mount.source)?;
    }
    for file_mount in &mount.file_mounts {
        let path_len = file_mount.path.as_os_str().len();
        if path_len > MAX_FILE_PATH_LENGTH {
            return Err(CredentialGateError::FileMountPathTooLong { length: path_len });
        }
        validate_credential_source(&file_mount.source)?;
    }
    Ok(())
}

fn validate_credential_source(source: &CredentialSource) -> Result<(), CredentialGateError> {
    match source {
        CredentialSource::EnvVar { var_name } => {
            validate_source_field_length("var_name", var_name.len())
        },
        CredentialSource::SystemdCredential { credential_name } => {
            validate_source_field_length("credential_name", credential_name.len())
        },
        CredentialSource::Apm2CredentialFile { file_name } => {
            validate_source_field_length("file_name", file_name.len())
        },
        CredentialSource::GitHubApp => Ok(()),
    }
}

const fn validate_source_field_length(
    field: &'static str,
    length: usize,
) -> Result<(), CredentialGateError> {
    if length > MAX_ENV_NAME_LENGTH {
        return Err(CredentialGateError::CredentialSourceFieldTooLong { field, length });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_source_display_env_var() {
        let source = CredentialSource::EnvVar {
            var_name: "GITHUB_TOKEN".to_string(),
        };
        assert_eq!(source.to_string(), "env:GITHUB_TOKEN");
    }

    #[test]
    fn credential_source_display_systemd() {
        let source = CredentialSource::SystemdCredential {
            credential_name: "gh-token".to_string(),
        };
        assert_eq!(source.to_string(), "systemd-credential:gh-token");
    }

    #[test]
    fn credential_source_display_apm2_file() {
        let source = CredentialSource::Apm2CredentialFile {
            file_name: "gh-token".to_string(),
        };
        assert_eq!(source.to_string(), "apm2-cred-file:gh-token");
    }

    #[test]
    fn credential_source_display_github_app() {
        assert_eq!(CredentialSource::GitHubApp.to_string(), "github-app");
    }

    #[test]
    fn credential_posture_serialization_does_not_leak_secrets() {
        let posture = CredentialPosture {
            credential_name: "github-token".to_string(),
            resolved: true,
            source: Some(CredentialSource::EnvVar {
                var_name: "GITHUB_TOKEN".to_string(),
            }),
        };
        let json = serde_json::to_string(&posture).unwrap();
        // Verify no secret values in serialized output
        assert!(!json.contains("ghp_"));
        assert!(!json.contains("sk-"));
        assert!(json.contains("\"resolved\":true"));
        assert!(json.contains("GITHUB_TOKEN"));
    }

    #[test]
    fn credential_posture_debug_does_not_leak_secrets() {
        let posture = CredentialPosture {
            credential_name: "github-token".to_string(),
            resolved: true,
            source: Some(CredentialSource::EnvVar {
                var_name: "GITHUB_TOKEN".to_string(),
            }),
        };
        let debug = format!("{posture:?}");
        assert!(!debug.contains("ghp_"));
        assert!(!debug.contains("sk-"));
    }

    #[test]
    fn credential_mount_v1_serialization_does_not_leak_secrets() {
        let mount = CredentialMountV1 {
            schema: "apm2.fac.credential_mount.v1".to_string(),
            env_mounts: vec![EnvMount {
                env_name: "GITHUB_TOKEN".to_string(),
                source: CredentialSource::EnvVar {
                    var_name: "GITHUB_TOKEN".to_string(),
                },
            }],
            file_mounts: vec![],
        };
        let json = serde_json::to_string(&mount).unwrap();
        // Only env var names, no values
        assert!(json.contains("GITHUB_TOKEN"));
        assert!(!json.contains("ghp_"));
    }

    #[test]
    fn validate_credential_mount_accepts_valid() {
        let mount = CredentialMountV1 {
            schema: "apm2.fac.credential_mount.v1".to_string(),
            env_mounts: vec![EnvMount {
                env_name: "GITHUB_TOKEN".to_string(),
                source: CredentialSource::EnvVar {
                    var_name: "GITHUB_TOKEN".to_string(),
                },
            }],
            file_mounts: vec![],
        };
        assert!(validate_credential_mount(&mount).is_ok());
    }

    #[test]
    fn validate_credential_mount_rejects_too_many_env_mounts() {
        let env_mounts: Vec<EnvMount> = (0..=MAX_ENV_MOUNTS)
            .map(|i| EnvMount {
                env_name: format!("VAR_{i}"),
                source: CredentialSource::EnvVar {
                    var_name: format!("VAR_{i}"),
                },
            })
            .collect();
        let mount = CredentialMountV1 {
            schema: "apm2.fac.credential_mount.v1".to_string(),
            env_mounts,
            file_mounts: vec![],
        };
        assert!(matches!(
            validate_credential_mount(&mount),
            Err(CredentialGateError::TooManyEnvMounts { .. })
        ));
    }

    #[test]
    fn validate_credential_mount_rejects_long_env_name() {
        let mount = CredentialMountV1 {
            schema: CREDENTIAL_MOUNT_SCHEMA_ID.to_string(),
            env_mounts: vec![EnvMount {
                env_name: "X".repeat(MAX_ENV_NAME_LENGTH + 1),
                source: CredentialSource::EnvVar {
                    var_name: "X".repeat(MAX_ENV_NAME_LENGTH + 1),
                },
            }],
            file_mounts: vec![],
        };
        assert!(matches!(
            validate_credential_mount(&mount),
            Err(CredentialGateError::EnvNameTooLong { .. })
        ));
    }

    #[test]
    fn validate_credential_mount_rejects_schema_mismatch() {
        let mount = CredentialMountV1 {
            schema: "apm2.fac.credential_mount.v2".to_string(),
            env_mounts: vec![],
            file_mounts: vec![],
        };
        assert!(matches!(
            validate_credential_mount(&mount),
            Err(CredentialGateError::InvalidCredentialMountSchema { .. })
        ));
    }

    #[test]
    fn validate_credential_mount_rejects_too_many_file_mounts() {
        let file_mounts: Vec<FileMountDescriptor> = (0..=MAX_FILE_MOUNTS)
            .map(|i| FileMountDescriptor {
                path: PathBuf::from(format!("/tmp/cred-{i}")),
                source: CredentialSource::SystemdCredential {
                    credential_name: "gh-token".to_string(),
                },
            })
            .collect();
        let mount = CredentialMountV1 {
            schema: "apm2.fac.credential_mount.v1".to_string(),
            env_mounts: vec![],
            file_mounts,
        };
        assert!(matches!(
            validate_credential_mount(&mount),
            Err(CredentialGateError::TooManyFileMounts { .. })
        ));
    }

    #[test]
    fn validate_credential_mount_rejects_long_file_mount_path() {
        let mount = CredentialMountV1 {
            schema: "apm2.fac.credential_mount.v1".to_string(),
            env_mounts: vec![],
            file_mounts: vec![FileMountDescriptor {
                path: PathBuf::from("a".repeat(MAX_FILE_PATH_LENGTH + 1)),
                source: CredentialSource::Apm2CredentialFile {
                    file_name: "gh-token".to_string(),
                },
            }],
        };
        assert!(matches!(
            validate_credential_mount(&mount),
            Err(CredentialGateError::FileMountPathTooLong { .. })
        ));
    }

    #[test]
    fn validate_credential_mount_rejects_long_source_field() {
        let mount = CredentialMountV1 {
            schema: CREDENTIAL_MOUNT_SCHEMA_ID.to_string(),
            env_mounts: vec![EnvMount {
                env_name: "GITHUB_TOKEN".to_string(),
                source: CredentialSource::EnvVar {
                    var_name: "Y".repeat(MAX_ENV_NAME_LENGTH + 1),
                },
            }],
            file_mounts: vec![],
        };
        assert!(matches!(
            validate_credential_mount(&mount),
            Err(CredentialGateError::CredentialSourceFieldTooLong {
                field: "var_name",
                ..
            })
        ));
    }

    #[test]
    fn apply_credential_mount_to_env_injects_alias_for_github_token() {
        let mount = CredentialMountV1 {
            schema: CREDENTIAL_MOUNT_SCHEMA_ID.to_string(),
            env_mounts: vec![EnvMount {
                env_name: "GH_TOKEN".to_string(),
                source: CredentialSource::EnvVar {
                    var_name: "GH_TOKEN".to_string(),
                },
            }],
            file_mounts: vec![],
        };
        let ambient_env = vec![("GH_TOKEN".to_string(), "ghp_example".to_string())];
        let mut env = BTreeMap::new();

        apply_credential_mount_to_env(&mount, &mut env, &ambient_env).expect("mount applied");

        assert_eq!(env.get("GH_TOKEN"), Some(&"ghp_example".to_string()));
        assert_eq!(env.get("GITHUB_TOKEN"), Some(&"ghp_example".to_string()));
    }

    #[test]
    fn apply_credential_mount_to_env_rejects_missing_payload() {
        let mount = CredentialMountV1 {
            schema: CREDENTIAL_MOUNT_SCHEMA_ID.to_string(),
            env_mounts: vec![EnvMount {
                env_name: "GITHUB_TOKEN".to_string(),
                source: CredentialSource::EnvVar {
                    var_name: "GITHUB_TOKEN".to_string(),
                },
            }],
            file_mounts: vec![],
        };
        let mut env = BTreeMap::new();
        let ambient_env = Vec::new();

        assert!(matches!(
            apply_credential_mount_to_env(&mount, &mut env, &ambient_env),
            Err(CredentialGateError::CredentialPayloadUnavailable { .. })
        ));
    }

    #[test]
    fn check_github_credential_posture_returns_structured_result() {
        // This test verifies the function returns a valid CredentialPosture
        // without panicking, regardless of environment state.
        let posture = check_github_credential_posture();
        assert_eq!(posture.credential_name, "github-token");
        // resolved and source depend on the actual environment
    }

    #[test]
    fn require_github_credentials_error_has_remediation() {
        let err = CredentialGateError::GitHubCredentialsMissing;
        let msg = err.to_string();
        // Verify the error message contains actionable remediation
        assert!(msg.contains("GITHUB_TOKEN"));
        assert!(msg.contains("CREDENTIALS_DIRECTORY"));
        assert!(msg.contains("gh-token"));
        assert!(msg.contains("apm2 fac pr auth-setup"));
        assert!(msg.contains("Remediation"));
    }

    #[test]
    fn credential_mount_round_trip() {
        let mount = CredentialMountV1 {
            schema: "apm2.fac.credential_mount.v1".to_string(),
            env_mounts: vec![EnvMount {
                env_name: "GITHUB_TOKEN".to_string(),
                source: CredentialSource::SystemdCredential {
                    credential_name: "gh-token".to_string(),
                },
            }],
            file_mounts: vec![FileMountDescriptor {
                path: PathBuf::from("/run/credentials/apm2-daemon/gh-token"),
                source: CredentialSource::SystemdCredential {
                    credential_name: "gh-token".to_string(),
                },
            }],
        };
        let json = serde_json::to_string(&mount).unwrap();
        let deserialized: CredentialMountV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(mount, deserialized);
    }
}
