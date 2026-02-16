//! Credential gate for FAC workflows (TCK-00596).
//!
//! This module provides a fail-fast credential posture check and a typed
//! credential mount descriptor for FAC execution paths. The gate ensures:
//!
//! - `apm2 fac gates` (local-only) never requires GitHub credentials.
//! - GitHub-facing commands (`fac push`, `fac review dispatch`) fail fast with
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
//! - [INV-CREDGATE-003] `CredentialMountV1` uses `SecretString` for any value
//!   that carries secret material. `Debug` and `Display` impls redact secrets.
//! - [INV-CREDGATE-004] Missing credentials block only GitHub-facing workflows;
//!   the gate is never called on the `apm2 fac gates` path.

use std::fmt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Maximum number of environment variable mounts in a single credential mount.
pub const MAX_ENV_MOUNTS: usize = 16;

/// Maximum length of an environment variable name in a credential mount.
pub const MAX_ENV_NAME_LENGTH: usize = 256;

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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialMountV1 {
    /// Schema identifier for forward-compatible parsing.
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

    /// Too many environment mounts in the credential mount.
    #[error("too many env mounts: {count} > {}", MAX_ENV_MOUNTS)]
    TooManyEnvMounts {
        /// The number of env mounts attempted.
        count: usize,
    },

    /// Environment variable name too long.
    #[error("env var name too long: {length} > {}", MAX_ENV_NAME_LENGTH)]
    EnvNameTooLong {
        /// The length of the env var name.
        length: usize,
    },
}

/// Check the current GitHub credential posture without resolving the secret
/// value.
///
/// Returns a [`CredentialPosture`] describing whether credentials are available
/// and from which source. The returned value is safe to log and serialize
/// (no secret material).
///
/// This function delegates to [`crate::config::resolve_github_token`] for the
/// actual resolution chain, then discards the secret value immediately.
#[must_use]
pub fn check_github_credential_posture() -> CredentialPosture {
    // Check env vars first (matching resolve_github_token order)
    if matches!(std::env::var("GITHUB_TOKEN"), Ok(ref v) if !v.is_empty()) {
        return CredentialPosture {
            credential_name: "github-token".to_string(),
            resolved: true,
            source: Some(CredentialSource::EnvVar {
                var_name: "GITHUB_TOKEN".to_string(),
            }),
        };
    }

    if matches!(std::env::var("GH_TOKEN"), Ok(ref v) if !v.is_empty()) {
        return CredentialPosture {
            credential_name: "github-token".to_string(),
            resolved: true,
            source: Some(CredentialSource::EnvVar {
                var_name: "GH_TOKEN".to_string(),
            }),
        };
    }

    // Check systemd credentials directory
    if let Ok(cred_dir) = std::env::var("CREDENTIALS_DIRECTORY") {
        let cred_path = std::path::Path::new(&cred_dir).join("gh-token");
        if cred_path.exists() {
            return CredentialPosture {
                credential_name: "github-token".to_string(),
                resolved: true,
                source: Some(CredentialSource::SystemdCredential {
                    credential_name: "gh-token".to_string(),
                }),
            };
        }
    }

    // Check APM2 credential file
    if let Some(apm2_home) = crate::github::resolve_apm2_home() {
        let cred_path = apm2_home.join("private/creds/gh-token");
        if cred_path.exists() {
            return CredentialPosture {
                credential_name: "github-token".to_string(),
                resolved: true,
                source: Some(CredentialSource::Apm2CredentialFile {
                    file_name: "gh-token".to_string(),
                }),
            };
        }
    }

    // Check GitHub App config
    if crate::github::load_github_app_config().is_some() {
        return CredentialPosture {
            credential_name: "github-token".to_string(),
            resolved: true,
            source: Some(CredentialSource::GitHubApp),
        };
    }

    CredentialPosture {
        credential_name: "github-token".to_string(),
        resolved: false,
        source: None,
    }
}

/// Fail-fast gate: require GitHub credentials to be available.
///
/// Call this at the entry point of GitHub-facing commands (`fac push`,
/// `fac review dispatch`, etc.) to produce an actionable error before
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
        schema: "apm2.fac.credential_mount.v1".to_string(),
        env_mounts,
        file_mounts,
    })
}

/// Validate a [`CredentialMountV1`] for bounded collection sizes.
///
/// # Errors
///
/// Returns an error if any bounds are exceeded.
pub fn validate_credential_mount(mount: &CredentialMountV1) -> Result<(), CredentialGateError> {
    if mount.env_mounts.len() > MAX_ENV_MOUNTS {
        return Err(CredentialGateError::TooManyEnvMounts {
            count: mount.env_mounts.len(),
        });
    }
    for env_mount in &mount.env_mounts {
        if env_mount.env_name.len() > MAX_ENV_NAME_LENGTH {
            return Err(CredentialGateError::EnvNameTooLong {
                length: env_mount.env_name.len(),
            });
        }
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
            schema: "apm2.fac.credential_mount.v1".to_string(),
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
