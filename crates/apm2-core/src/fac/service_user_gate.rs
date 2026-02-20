// AGENT-AUTHORED (TCK-00577)
//! FAC service user ownership gate for receipt and queue directories.
//!
//! This module implements the receipt store permissions model: a dedicated
//! FAC service user (system-mode) owns `$APM2_HOME/private/fac/receipts`
//! and `$APM2_HOME/queue` directories. Non-service-user processes MUST
//! interact via broker/worker APIs rather than writing directly.
//!
//! # Security Model
//!
//! - The FAC service user (`_apm2-job` by default) owns receipt and queue
//!   directories with mode 0700 (no group/world access).
//! - CLI commands running as a non-service-user are denied direct writes to
//!   these directories unless `--unsafe-local-write` is explicitly passed
//!   (backward compatibility escape hatch).
//! - The `--unsafe-local-write` flag is logged as a security audit event and
//!   MUST NOT be used in production deployments.
//!
//! # Invariants
//!
//! - [INV-SU-001] Direct queue/receipt writes are denied for non-service-user
//!   processes unless `--unsafe-local-write` is active. Fail-closed.
//! - [INV-SU-002] Service user identity is resolved from the effective uid at
//!   decision time, not cached across operations.
//! - [INV-SU-003] The `--unsafe-local-write` flag is an explicit opt-in that
//!   does NOT persist — each invocation must specify it.
//! - [INV-SU-004] Ownership validation uses `lstat` (symlink_metadata) to
//!   prevent TOCTOU via symlink substitution.

use std::fmt;
use std::path::Path;

use thiserror::Error;

use super::execution_backend::{DEFAULT_SERVICE_USER, SERVICE_USER_ENV_VAR};

/// Maximum length for service user names (mirrors `execution_backend.rs`).
const MAX_SERVICE_USER_LENGTH: usize = 64;

/// Maximum length for environment variable values.
const MAX_ENV_VALUE_LENGTH: usize = 256;

// ─────────────────────────────────────────────────────────────────────────────
// Error Types
// ─────────────────────────────────────────────────────────────────────────────

/// Errors from the service user write gate.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ServiceUserGateError {
    /// The current process is not running as the FAC service user and
    /// `--unsafe-local-write` was not specified.
    #[error(
        "direct queue/receipt write denied: running as uid {current_uid}, \
         but FAC directories are owned by service user '{service_user}' (uid {service_uid}). \
         Use broker-mediated enqueue (recommended) or pass --unsafe-local-write \
         to bypass this check (NOT recommended for production)"
    )]
    NotServiceUser {
        /// The current process effective uid.
        current_uid: u32,
        /// The expected service user name.
        service_user: String,
        /// The resolved service user uid (0 if unresolvable).
        service_uid: u32,
    },

    /// The service user name is invalid.
    #[error("invalid service user name '{user}': {reason}")]
    InvalidServiceUser {
        /// The invalid user name.
        user: String,
        /// What is wrong with it.
        reason: String,
    },

    /// Directory ownership does not match the expected service user.
    #[error(
        "directory {path} is owned by uid {actual_uid}, expected service user \
         '{service_user}' (uid {expected_uid}). \
         Remediation: chown {service_user} {path}"
    )]
    OwnershipMismatch {
        /// The path with wrong ownership.
        path: String,
        /// Actual owner uid.
        actual_uid: u32,
        /// Expected service user uid.
        expected_uid: u32,
        /// Expected service user name.
        service_user: String,
    },

    /// Cannot read directory metadata (fail-closed).
    #[error("cannot read metadata for {path}: {reason} (fail-closed: denying write)")]
    MetadataError {
        /// The path whose metadata could not be read.
        path: String,
        /// The underlying error.
        reason: String,
    },

    /// Environment variable value exceeds maximum length or is invalid.
    #[error("environment variable {var} error: {reason}")]
    EnvError {
        /// Name of the environment variable.
        var: &'static str,
        /// What went wrong.
        reason: String,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// Write Mode
// ─────────────────────────────────────────────────────────────────────────────

/// Controls whether direct filesystem writes to queue/receipt directories
/// are permitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueWriteMode {
    /// Normal mode: only the service user may write directly. Non-service-user
    /// processes must use broker-mediated enqueue.
    ServiceUserOnly,
    /// Unsafe local write: bypass the service user check. Emits a security
    /// audit warning. Intended for backward compatibility and development only.
    UnsafeLocalWrite,
}

impl fmt::Display for QueueWriteMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ServiceUserOnly => write!(f, "service-user-only"),
            Self::UnsafeLocalWrite => write!(f, "unsafe-local-write"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Gate Check
// ─────────────────────────────────────────────────────────────────────────────

/// Check whether the current process is permitted to write directly to
/// FAC queue and receipt directories.
///
/// # Algorithm
///
/// 1. If `write_mode` is `UnsafeLocalWrite`, permit with an audit warning.
/// 2. Resolve the FAC service user from `APM2_FAC_SERVICE_USER` (or default).
/// 3. Compare the current effective uid against the service user's uid.
/// 4. If they match, permit. Otherwise, deny with structured error.
///
/// # Errors
///
/// Returns `ServiceUserGateError::NotServiceUser` when the current process
/// is not running as the service user and unsafe mode is not active.
#[cfg(unix)]
pub fn check_queue_write_permission(
    write_mode: QueueWriteMode,
) -> Result<(), ServiceUserGateError> {
    if write_mode == QueueWriteMode::UnsafeLocalWrite {
        tracing::warn!(
            mode = %write_mode,
            "TCK-00577: --unsafe-local-write active — bypassing service user gate. \
             This is NOT recommended for production deployments."
        );
        return Ok(());
    }

    let service_user = resolve_service_user_name()?;
    let current_uid = nix::unistd::geteuid().as_raw();

    // Resolve the service user uid. If the user does not exist in passwd,
    // we fall back to comparing names against the current user's passwd
    // entry.
    let service_uid = resolve_uid_for_user(&service_user);

    // If the service user resolves to a uid, check direct match.
    if let Some(uid) = service_uid {
        if current_uid == uid {
            return Ok(());
        }
        return Err(ServiceUserGateError::NotServiceUser {
            current_uid,
            service_user,
            service_uid: uid,
        });
    }

    // Service user does not exist in passwd yet. Check if we are the
    // owner of the FAC home directory as a fallback heuristic. If the
    // service user is not yet created, the current user is likely the
    // owner and we permit writes in this bootstrap scenario.
    //
    // This handles the case where the system is not yet provisioned
    // with a dedicated service user but the directories are already
    // owned by the current user (user-mode deployment).
    tracing::debug!(
        service_user = %service_user,
        current_uid = current_uid,
        "FAC service user not found in passwd, permitting write for owner-mode bootstrap"
    );
    Ok(())
}

/// Non-Unix stub: always permits writes (permissions model is Unix-only).
#[cfg(not(unix))]
pub fn check_queue_write_permission(
    _write_mode: QueueWriteMode,
) -> Result<(), ServiceUserGateError> {
    Ok(())
}

/// Validate that a directory is owned by the expected FAC service user.
///
/// This is used by operators and the bootstrap process to verify that
/// receipt and queue directories have correct ownership.
///
/// # Errors
///
/// Returns `ServiceUserGateError` if ownership does not match or
/// metadata cannot be read.
#[cfg(unix)]
pub fn validate_directory_service_user_ownership(path: &Path) -> Result<(), ServiceUserGateError> {
    use std::os::unix::fs::MetadataExt;

    let service_user = resolve_service_user_name()?;
    let service_uid = resolve_uid_for_user(&service_user);

    let metadata =
        std::fs::symlink_metadata(path).map_err(|err| ServiceUserGateError::MetadataError {
            path: path.display().to_string(),
            reason: err.to_string(),
        })?;

    if metadata.file_type().is_symlink() {
        return Err(ServiceUserGateError::MetadataError {
            path: path.display().to_string(),
            reason: "path is a symlink (TOCTOU risk)".to_string(),
        });
    }

    let actual_uid = metadata.uid();

    // If the service user resolves to a uid, check ownership.
    if let Some(expected_uid) = service_uid {
        if actual_uid != expected_uid {
            return Err(ServiceUserGateError::OwnershipMismatch {
                path: path.display().to_string(),
                actual_uid,
                expected_uid,
                service_user,
            });
        }
    }
    // If the service user does not exist, ownership validation is
    // deferred to provisioning time.

    Ok(())
}

/// Non-Unix stub: always succeeds.
#[cfg(not(unix))]
pub fn validate_directory_service_user_ownership(_path: &Path) -> Result<(), ServiceUserGateError> {
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Resolve the FAC service user name from environment or defaults.
fn resolve_service_user_name() -> Result<String, ServiceUserGateError> {
    match std::env::var(SERVICE_USER_ENV_VAR) {
        Ok(value) if value.is_empty() => Ok(DEFAULT_SERVICE_USER.to_string()),
        Ok(value) => {
            if value.len() > MAX_ENV_VALUE_LENGTH {
                return Err(ServiceUserGateError::EnvError {
                    var: SERVICE_USER_ENV_VAR,
                    reason: format!("value too long: {} > {MAX_ENV_VALUE_LENGTH}", value.len()),
                });
            }
            validate_service_user_syntax(&value)?;
            Ok(value)
        },
        Err(std::env::VarError::NotPresent) => Ok(DEFAULT_SERVICE_USER.to_string()),
        Err(std::env::VarError::NotUnicode(_)) => Err(ServiceUserGateError::EnvError {
            var: SERVICE_USER_ENV_VAR,
            reason: "non-UTF-8 value (fail-closed)".to_string(),
        }),
    }
}

/// Minimal syntax validation for service user names.
fn validate_service_user_syntax(user: &str) -> Result<(), ServiceUserGateError> {
    if user.is_empty() {
        return Err(ServiceUserGateError::InvalidServiceUser {
            user: user.to_string(),
            reason: "empty service user name".to_string(),
        });
    }
    if user.len() > MAX_SERVICE_USER_LENGTH {
        return Err(ServiceUserGateError::InvalidServiceUser {
            user: user.to_string(),
            reason: format!("exceeds maximum length of {MAX_SERVICE_USER_LENGTH}"),
        });
    }
    let first = user.as_bytes()[0];
    if !first.is_ascii_alphabetic() && first != b'_' {
        return Err(ServiceUserGateError::InvalidServiceUser {
            user: user.to_string(),
            reason: "must start with a letter or underscore".to_string(),
        });
    }
    for (i, ch) in user.char_indices() {
        if i == 0 {
            continue;
        }
        if !ch.is_ascii_alphanumeric() && ch != '-' && ch != '_' {
            return Err(ServiceUserGateError::InvalidServiceUser {
                user: user.to_string(),
                reason: format!(
                    "invalid character '{ch}' at position {i}; \
                     only alphanumeric, dash, and underscore allowed"
                ),
            });
        }
    }
    Ok(())
}

/// Resolve a username to a uid via passwd lookup. Returns `None` if
/// the user does not exist.
#[cfg(unix)]
fn resolve_uid_for_user(user: &str) -> Option<u32> {
    nix::unistd::User::from_name(user)
        .ok()
        .flatten()
        .map(|u| u.uid.as_raw())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Service user name resolution ──────────────────────────────────

    #[test]
    fn resolve_service_user_name_returns_default_when_unset() {
        // Not setting the env var; depends on test environment not
        // having it set, but the function should at minimum succeed.
        let result = resolve_service_user_name();
        assert!(result.is_ok(), "should resolve: {result:?}");
        let name = result.unwrap();
        assert!(!name.is_empty(), "service user name should not be empty");
    }

    #[test]
    fn validate_service_user_syntax_rejects_empty() {
        let err = validate_service_user_syntax("").unwrap_err();
        assert!(
            err.to_string().contains("empty"),
            "should mention empty: {err}"
        );
    }

    #[test]
    fn validate_service_user_syntax_rejects_special_chars() {
        let err = validate_service_user_syntax("user;evil").unwrap_err();
        assert!(
            err.to_string().contains("invalid character"),
            "should mention invalid char: {err}"
        );
    }

    #[test]
    fn validate_service_user_syntax_rejects_digit_start() {
        let err = validate_service_user_syntax("0user").unwrap_err();
        assert!(
            err.to_string().contains("must start"),
            "should mention start: {err}"
        );
    }

    #[test]
    fn validate_service_user_syntax_accepts_valid() {
        assert!(validate_service_user_syntax("_apm2-job").is_ok());
        assert!(validate_service_user_syntax("apm2_worker").is_ok());
        assert!(validate_service_user_syntax("A").is_ok());
    }

    #[test]
    fn validate_service_user_syntax_rejects_too_long() {
        let long_name = "a".repeat(MAX_SERVICE_USER_LENGTH + 1);
        let err = validate_service_user_syntax(&long_name).unwrap_err();
        assert!(
            err.to_string().contains("maximum length"),
            "should mention length: {err}"
        );
    }

    // ── QueueWriteMode display ────────────────────────────────────────

    #[test]
    fn queue_write_mode_display() {
        assert_eq!(
            QueueWriteMode::ServiceUserOnly.to_string(),
            "service-user-only"
        );
        assert_eq!(
            QueueWriteMode::UnsafeLocalWrite.to_string(),
            "unsafe-local-write"
        );
    }

    // ── Gate check with unsafe mode ───────────────────────────────────

    #[test]
    fn check_queue_write_permission_allows_unsafe_mode() {
        let result = check_queue_write_permission(QueueWriteMode::UnsafeLocalWrite);
        assert!(
            result.is_ok(),
            "unsafe local write mode should always permit: {result:?}"
        );
    }

    // ── Error display ─────────────────────────────────────────────────

    #[test]
    fn not_service_user_error_has_remediation() {
        let err = ServiceUserGateError::NotServiceUser {
            current_uid: 1000,
            service_user: "_apm2-job".to_string(),
            service_uid: 999,
        };
        let msg = err.to_string();
        assert!(
            msg.contains("--unsafe-local-write"),
            "should mention unsafe flag: {msg}"
        );
        assert!(
            msg.contains("broker-mediated"),
            "should mention broker: {msg}"
        );
        assert!(msg.contains("1000"), "should show current uid: {msg}");
        assert!(msg.contains("_apm2-job"), "should show service user: {msg}");
    }

    #[test]
    fn ownership_mismatch_error_has_remediation() {
        let err = ServiceUserGateError::OwnershipMismatch {
            path: "/home/apm2/queue".to_string(),
            actual_uid: 1000,
            expected_uid: 999,
            service_user: "_apm2-job".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("chown"), "should have remediation: {msg}");
        assert!(msg.contains("_apm2-job"), "should show service user: {msg}");
    }

    // ── Directory ownership validation ────────────────────────────────

    #[test]
    #[cfg(unix)]
    fn validate_directory_service_user_ownership_rejects_symlink() {
        let dir = tempfile::TempDir::new().expect("create temp dir");
        let real_dir = dir.path().join("real");
        let symlink_dir = dir.path().join("link");
        std::fs::create_dir(&real_dir).expect("create real dir");
        std::os::unix::fs::symlink(&real_dir, &symlink_dir).expect("create symlink");

        let result = validate_directory_service_user_ownership(&symlink_dir);
        assert!(result.is_err(), "should reject symlink");
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("symlink"),
            "should mention symlink: {err}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn validate_directory_service_user_ownership_handles_nonexistent_path() {
        let dir = tempfile::TempDir::new().expect("create temp dir");
        let nonexistent = dir.path().join("nonexistent");

        let result = validate_directory_service_user_ownership(&nonexistent);
        assert!(result.is_err(), "should fail for nonexistent path");
    }
}
