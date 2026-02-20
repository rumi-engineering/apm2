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

    /// The FAC service user could not be resolved to a uid (fail-closed).
    ///
    /// This covers both "user does not exist in passwd" and "passwd lookup
    /// failed with an I/O or system error". In `ServiceUserOnly` mode, an
    /// unresolvable service user is a hard denial — writes are never
    /// permitted when the service user identity cannot be confirmed.
    #[error(
        "service user '{service_user}' could not be resolved to a uid \
         (fail-closed: denying write). Reason: {reason}. \
         Ensure the service user exists or pass --unsafe-local-write to bypass"
    )]
    ServiceUserNotResolved {
        /// The service user name that could not be resolved.
        service_user: String,
        /// Why resolution failed (e.g. "user not found in passwd" or the
        /// underlying system error).
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

    // Resolve the service user uid. Fail-closed: if the user does not
    // exist or lookup errors out, deny writes in ServiceUserOnly mode.
    let service_uid = match resolve_uid_for_user(&service_user) {
        Ok(uid) => uid,
        Err(reason) => {
            // [INV-SU-001] Fail-closed: unresolvable service user
            // is a hard denial. The caller must use UnsafeLocalWrite
            // or broker-mediated enqueue.
            tracing::warn!(
                service_user = %service_user,
                current_uid = current_uid,
                reason = %reason,
                "TCK-00577: service user not resolvable — denying write (fail-closed)"
            );
            return Err(ServiceUserGateError::ServiceUserNotResolved {
                service_user,
                reason,
            });
        },
    };

    if current_uid == service_uid {
        return Ok(());
    }

    Err(ServiceUserGateError::NotServiceUser {
        current_uid,
        service_user,
        service_uid,
    })
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
    let expected_uid = resolve_uid_for_user(&service_user).map_err(|reason| {
        ServiceUserGateError::ServiceUserNotResolved {
            service_user: service_user.clone(),
            reason,
        }
    })?;

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

    if actual_uid != expected_uid {
        return Err(ServiceUserGateError::OwnershipMismatch {
            path: path.display().to_string(),
            actual_uid,
            expected_uid,
            service_user,
        });
    }

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

/// Resolve a username to a uid via passwd lookup.
///
/// Returns `Ok(uid)` if the user exists, `Err(reason)` if the user does
/// not exist or if the lookup itself failed (e.g. NSS/LDAP error). The
/// caller MUST treat `Err` as a hard denial in `ServiceUserOnly` mode
/// to maintain fail-closed semantics.
#[cfg(unix)]
fn resolve_uid_for_user(user: &str) -> Result<u32, String> {
    match nix::unistd::User::from_name(user) {
        Ok(Some(u)) => Ok(u.uid.as_raw()),
        Ok(None) => Err(format!("user '{user}' not found in passwd")),
        Err(e) => Err(format!("passwd lookup failed for '{user}': {e}")),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Service User Identity Resolution (public API)
// ─────────────────────────────────────────────────────────────────────────────

/// Resolved identity of the FAC service user, including UID and primary GID.
///
/// Used by broker-mediated enqueue to set file group ownership so the
/// service-user worker can read broker request files written by non-service
/// users.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceUserIdentity {
    /// The service user name (e.g. `_apm2-job`).
    pub name: String,
    /// The service user's numeric UID.
    pub uid: u32,
    /// The service user's primary GID from `/etc/passwd`.
    pub gid: u32,
}

/// Resolve the FAC service user's full identity (name, UID, GID) via
/// passwd lookup.
///
/// The service user name is determined from `APM2_FAC_SERVICE_USER` (env)
/// or the default (`_apm2-job`). Returns `Err` if the user does not exist
/// or the passwd lookup fails.
///
/// # Errors
///
/// Returns `ServiceUserGateError::ServiceUserNotResolved` if the service
/// user does not exist in the passwd database or if the lookup itself
/// fails (e.g. NSS/LDAP error). Returns `ServiceUserGateError::EnvError`
/// or `ServiceUserGateError::InvalidServiceUser` if the service user name
/// (from environment variable) is invalid.
///
/// # Usage
///
/// Broker-mediated enqueue calls this to obtain the service user's GID,
/// then uses `fchown(fd, -1, gid)` to set the file's group so the worker
/// (running as the service user) can read broker request files written
/// with mode 0640.
#[cfg(unix)]
pub fn resolve_service_user_identity() -> Result<ServiceUserIdentity, ServiceUserGateError> {
    let name = resolve_service_user_name()?;
    match nix::unistd::User::from_name(&name) {
        Ok(Some(u)) => Ok(ServiceUserIdentity {
            name,
            uid: u.uid.as_raw(),
            gid: u.gid.as_raw(),
        }),
        Ok(None) => Err(ServiceUserGateError::ServiceUserNotResolved {
            service_user: name,
            reason: "user not found in passwd".to_string(),
        }),
        Err(e) => Err(ServiceUserGateError::ServiceUserNotResolved {
            service_user: name,
            reason: format!("passwd lookup failed: {e}"),
        }),
    }
}

/// Non-Unix stub: always returns `Err` since the permissions model is
/// Unix-only.
///
/// # Errors
///
/// Always returns `ServiceUserGateError::ServiceUserNotResolved`.
#[cfg(not(unix))]
pub fn resolve_service_user_identity() -> Result<ServiceUserIdentity, ServiceUserGateError> {
    Err(ServiceUserGateError::ServiceUserNotResolved {
        service_user: String::new(),
        reason: "service user identity resolution is Unix-only".to_string(),
    })
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

    // ── Fail-closed: service user not resolvable ──────────────────────

    #[test]
    #[cfg(unix)]
    fn check_queue_write_service_user_only_denies_when_user_not_found() {
        // The default service user `_apm2-job` almost certainly does not
        // exist in test environments. ServiceUserOnly mode must deny.
        let result = check_queue_write_permission(QueueWriteMode::ServiceUserOnly);
        // Two valid outcomes:
        // - Err(ServiceUserNotResolved) if the user does not exist
        // - Err(NotServiceUser) if the user exists but is different
        // - Ok(()) if we happen to be running as the service user (unlikely)
        //
        // We just assert that the default service user `_apm2-job` does
        // not silently permit writes for a non-service-user process.
        // The test user is extremely unlikely to be `_apm2-job`.
        match result {
            Ok(()) => {
                // We must be running as the service user — that is valid.
                let current_uid = nix::unistd::geteuid().as_raw();
                let service_uid = resolve_uid_for_user(DEFAULT_SERVICE_USER);
                assert_eq!(
                    service_uid,
                    Ok(current_uid),
                    "Ok result should only happen when running as service user"
                );
            },
            Err(ref err) => {
                let msg = err.to_string();
                // Must be either NotServiceUser or ServiceUserNotResolved
                assert!(
                    msg.contains("could not be resolved")
                        || msg.contains("direct queue/receipt write denied"),
                    "denial should have a clear reason: {msg}"
                );
            },
        }
    }

    #[test]
    #[cfg(unix)]
    fn resolve_uid_for_nonexistent_user_returns_err() {
        let result = resolve_uid_for_user("__nonexistent_user_tck00577__");
        assert!(
            result.is_err(),
            "nonexistent user should return Err, got: {result:?}"
        );
        let reason = result.unwrap_err();
        assert!(
            reason.contains("not found"),
            "error should mention 'not found': {reason}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn resolve_uid_for_root_returns_zero() {
        // `root` exists on all Unix systems with uid 0.
        let result = resolve_uid_for_user("root");
        assert_eq!(result, Ok(0), "root should resolve to uid 0");
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
    fn service_user_not_resolved_error_has_remediation() {
        let err = ServiceUserGateError::ServiceUserNotResolved {
            service_user: "_apm2-job".to_string(),
            reason: "user not found in passwd".to_string(),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("could not be resolved"),
            "should explain resolution failure: {msg}"
        );
        assert!(
            msg.contains("fail-closed"),
            "should indicate fail-closed: {msg}"
        );
        assert!(
            msg.contains("--unsafe-local-write"),
            "should mention bypass flag: {msg}"
        );
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
    fn validate_directory_service_user_ownership_denies_when_service_user_not_found() {
        // The default service user `_apm2-job` does not exist in test
        // environments. validate_directory_service_user_ownership should
        // fail-closed with ServiceUserNotResolved before even reading
        // directory metadata.
        let dir = tempfile::TempDir::new().expect("create temp dir");
        let real_dir = dir.path().join("real");
        std::fs::create_dir(&real_dir).expect("create real dir");

        let result = validate_directory_service_user_ownership(&real_dir);
        assert!(result.is_err(), "should deny when service user not found");
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("could not be resolved") || msg.contains("not found"),
            "should indicate service user not resolved: {msg}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn validate_directory_service_user_ownership_handles_nonexistent_path() {
        // Even for a nonexistent path, the service user resolution
        // fails-closed first (before metadata read).
        let dir = tempfile::TempDir::new().expect("create temp dir");
        let nonexistent = dir.path().join("nonexistent");

        let result = validate_directory_service_user_ownership(&nonexistent);
        assert!(result.is_err(), "should fail for nonexistent path");
    }

    // ── Service user identity resolution (TCK-00577 round 16) ────────

    /// TCK-00577 round 16: Verify `resolve_service_user_identity` behavior
    /// with the default service user (which typically does not exist in test
    /// environments). We cannot set env vars without unsafe, so we test the
    /// default behavior: the default `_apm2-job` user is unlikely to exist,
    /// so we expect Err. If it does exist (CI environment with the user
    /// provisioned), both uid and gid must be non-zero or the test is still
    /// valid.
    #[test]
    #[cfg(unix)]
    fn resolve_service_user_identity_default_user_behavior() {
        let result = resolve_service_user_identity();
        // Two valid outcomes:
        // 1. Err (ServiceUserNotResolved) — default user does not exist
        // 2. Ok — default user exists; verify fields are populated
        match result {
            Ok(identity) => {
                assert!(!identity.name.is_empty(), "name must not be empty");
                // uid and gid should be valid (just check they're populated)
            },
            Err(ref err) => {
                let msg = err.to_string();
                assert!(
                    msg.contains("could not be resolved") || msg.contains("not found"),
                    "error should indicate user not found: {msg}"
                );
            },
        }
    }

    /// TCK-00577 round 16: Verify `ServiceUserIdentity` struct construction
    /// and field access.
    #[test]
    fn service_user_identity_struct_has_expected_fields() {
        let identity = ServiceUserIdentity {
            name: "test_user".to_string(),
            uid: 1000,
            gid: 1000,
        };
        assert_eq!(identity.name, "test_user");
        assert_eq!(identity.uid, 1000);
        assert_eq!(identity.gid, 1000);
        // Clone + PartialEq + Eq + Debug
        let cloned = identity.clone();
        assert_eq!(identity, cloned);
        assert_eq!(format!("{identity:?}"), format!("{cloned:?}"));
    }
}
