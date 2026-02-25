//! Agent-parseable exit codes per RFC-0018.
//!
//! This module defines deterministic exit codes for CLI commands to enable
//! agent-parseable error handling. Per RFC-0018 CLI Usability Plan, these
//! codes apply uniformly across all agent commands.
//!
//! # Exit Code Categories
//!
//! - **0**: Success
//! - **10-19**: Client-side validation and authorization errors
//! - **20-29**: Daemon communication and protocol errors
//!
//! # Contract References
//!
//! - RFC-0018: CLI Usability Plan
//! - RFC-0032::REQ-0090: CLI dual-socket + protocol client alignment

use crate::client::protocol::ProtocolClientError;

/// Exit code constants per RFC-0018.
pub mod codes {
    /// Success exit code.
    pub const SUCCESS: u8 = 0;

    /// Validation error (invalid args/format).
    ///
    /// Returned when CLI arguments fail local validation before
    /// any daemon communication occurs.
    pub const VALIDATION_ERROR: u8 = 10;

    /// Permission denied (capability/ACL).
    ///
    /// Returned when the daemon rejects a request due to insufficient
    /// permissions or missing capabilities.
    pub const PERMISSION_DENIED: u8 = 11;

    /// Not found (`work_id`/`session_id`/`episode_id`/changeset).
    ///
    /// Returned when a referenced resource does not exist.
    pub const NOT_FOUND: u8 = 12;

    /// Daemon unavailable (socket connect failure).
    ///
    /// Returned when the CLI cannot connect to the daemon socket.
    pub const DAEMON_UNAVAILABLE: u8 = 20;

    /// Protocol error (decode/unknown tag/handshake failure).
    ///
    /// Returned when there is a protocol-level communication error
    /// with the daemon.
    pub const PROTOCOL_ERROR: u8 = 21;

    /// Policy deny (explicit governance/policy rejection).
    ///
    /// Returned when a request is rejected by policy enforcement.
    pub const POLICY_DENY: u8 = 22;

    /// Generic error (fallback for unmapped errors).
    ///
    /// Used when an error does not fit into any specific category.
    pub const GENERIC_ERROR: u8 = 1;
}

/// Maps a `ProtocolClientError` to an appropriate exit code.
///
/// This function implements the RFC-0018 exit code mapping for
/// protocol client errors. The mapping is deterministic to enable
/// agent-parseable error handling.
///
/// # Exit Code Mapping
///
/// | Error Type | Exit Code |
/// |------------|-----------|
/// | `DaemonNotRunning` | 20 (DAEMON_UNAVAILABLE) |
/// | `ConnectionFailed` | 20 (DAEMON_UNAVAILABLE) |
/// | `Timeout` | 20 (DAEMON_UNAVAILABLE) |
/// | `HandshakeFailed` | 21 (PROTOCOL_ERROR) |
/// | `VersionMismatch` | 21 (PROTOCOL_ERROR) |
/// | `ProtocolError` | 21 (PROTOCOL_ERROR) |
/// | `DecodeError` | 21 (PROTOCOL_ERROR) |
/// | `UnexpectedResponse` | 21 (PROTOCOL_ERROR) |
/// | `FrameTooLarge` | 21 (PROTOCOL_ERROR) |
/// | `IoError` | 20 (DAEMON_UNAVAILABLE) |
/// | `DaemonError` | Mapped by error code |
#[must_use]
pub fn map_protocol_error(error: &ProtocolClientError) -> u8 {
    match error {
        // Daemon unavailable (20)
        ProtocolClientError::DaemonNotRunning
        | ProtocolClientError::ConnectionFailed(_)
        | ProtocolClientError::Timeout
        | ProtocolClientError::IoError(_) => codes::DAEMON_UNAVAILABLE,

        // Protocol errors (21)
        ProtocolClientError::HandshakeFailed(_)
        | ProtocolClientError::VersionMismatch { .. }
        | ProtocolClientError::ProtocolError(_)
        | ProtocolClientError::DecodeError(_)
        | ProtocolClientError::UnexpectedResponse(_)
        | ProtocolClientError::FrameTooLarge { .. } => codes::PROTOCOL_ERROR,

        // Daemon errors - map by error code
        ProtocolClientError::DaemonError { code, message: _ } => map_daemon_error_code(code),
    }
}

/// Maps a daemon error code string to an exit code.
///
/// This function parses daemon error codes and maps them to the
/// appropriate RFC-0018 exit codes.
///
/// # Error Code Mapping
///
/// | Error Code | Exit Code |
/// |------------|-----------|
/// | `*NotFound*` | 12 (NOT_FOUND) |
/// | `*PermissionDenied*` | 11 (PERMISSION_DENIED) |
/// | `*PolicyDeny*` / `*PolicyRejected*` | 22 (POLICY_DENY) |
/// | `*Invalid*` / `*Validation*` | 10 (VALIDATION_ERROR) |
/// | Other | 1 (GENERIC_ERROR) |
fn map_daemon_error_code(code: &str) -> u8 {
    let code_lower = code.to_lowercase();

    if code_lower.contains("notfound") || code_lower.contains("not_found") {
        codes::NOT_FOUND
    } else if code_lower.contains("permissiondenied") || code_lower.contains("permission_denied") {
        codes::PERMISSION_DENIED
    } else if code_lower.contains("policydeny")
        || code_lower.contains("policy_deny")
        || code_lower.contains("policyrejected")
        || code_lower.contains("policy_rejected")
    {
        codes::POLICY_DENY
    } else if code_lower.contains("invalid") || code_lower.contains("validation") {
        codes::VALIDATION_ERROR
    } else {
        codes::GENERIC_ERROR
    }
}

/// Returns a human-readable description for an exit code.
///
/// This is useful for CLI help messages and error output.
#[must_use]
#[allow(dead_code)]
pub const fn exit_code_description(code: u8) -> &'static str {
    match code {
        codes::SUCCESS => "success",
        codes::VALIDATION_ERROR => "validation error (invalid args/format)",
        codes::PERMISSION_DENIED => "permission denied (capability/ACL)",
        codes::NOT_FOUND => "not found (resource does not exist)",
        codes::DAEMON_UNAVAILABLE => "daemon unavailable (socket connect failure)",
        codes::PROTOCOL_ERROR => "protocol error (decode/handshake failure)",
        codes::POLICY_DENY => "policy deny (governance rejection)",
        codes::GENERIC_ERROR => "error",
        _ => "unknown error",
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::*;

    #[test]
    fn test_daemon_not_running_exit_code() {
        let error = ProtocolClientError::DaemonNotRunning;
        assert_eq!(map_protocol_error(&error), codes::DAEMON_UNAVAILABLE);
    }

    #[test]
    fn test_connection_failed_exit_code() {
        let error = ProtocolClientError::ConnectionFailed("test".to_string());
        assert_eq!(map_protocol_error(&error), codes::DAEMON_UNAVAILABLE);
    }

    #[test]
    fn test_timeout_exit_code() {
        let error = ProtocolClientError::Timeout;
        assert_eq!(map_protocol_error(&error), codes::DAEMON_UNAVAILABLE);
    }

    #[test]
    fn test_io_error_exit_code() {
        let error = ProtocolClientError::IoError(io::Error::other("test"));
        assert_eq!(map_protocol_error(&error), codes::DAEMON_UNAVAILABLE);
    }

    #[test]
    fn test_handshake_failed_exit_code() {
        let error = ProtocolClientError::HandshakeFailed("test".to_string());
        assert_eq!(map_protocol_error(&error), codes::PROTOCOL_ERROR);
    }

    #[test]
    fn test_version_mismatch_exit_code() {
        let error = ProtocolClientError::VersionMismatch {
            client: 1,
            server: 2,
        };
        assert_eq!(map_protocol_error(&error), codes::PROTOCOL_ERROR);
    }

    #[test]
    fn test_decode_error_exit_code() {
        let error = ProtocolClientError::DecodeError("test".to_string());
        assert_eq!(map_protocol_error(&error), codes::PROTOCOL_ERROR);
    }

    #[test]
    fn test_daemon_error_not_found() {
        let error = ProtocolClientError::DaemonError {
            code: "EpisodeNotFound".to_string(),
            message: "episode not found".to_string(),
        };
        assert_eq!(map_protocol_error(&error), codes::NOT_FOUND);
    }

    #[test]
    fn test_daemon_error_permission_denied() {
        let error = ProtocolClientError::DaemonError {
            code: "PermissionDenied".to_string(),
            message: "access denied".to_string(),
        };
        assert_eq!(map_protocol_error(&error), codes::PERMISSION_DENIED);
    }

    #[test]
    fn test_daemon_error_policy_deny() {
        let error = ProtocolClientError::DaemonError {
            code: "PolicyDeny".to_string(),
            message: "policy rejection".to_string(),
        };
        assert_eq!(map_protocol_error(&error), codes::POLICY_DENY);
    }

    #[test]
    fn test_daemon_error_validation() {
        let error = ProtocolClientError::DaemonError {
            code: "InvalidRequest".to_string(),
            message: "invalid input".to_string(),
        };
        assert_eq!(map_protocol_error(&error), codes::VALIDATION_ERROR);
    }

    #[test]
    fn test_daemon_error_generic() {
        let error = ProtocolClientError::DaemonError {
            code: "InternalError".to_string(),
            message: "something went wrong".to_string(),
        };
        assert_eq!(map_protocol_error(&error), codes::GENERIC_ERROR);
    }

    #[test]
    fn test_exit_code_descriptions() {
        assert_eq!(exit_code_description(codes::SUCCESS), "success");
        assert_eq!(
            exit_code_description(codes::DAEMON_UNAVAILABLE),
            "daemon unavailable (socket connect failure)"
        );
        assert_eq!(
            exit_code_description(codes::PROTOCOL_ERROR),
            "protocol error (decode/handshake failure)"
        );
    }
}
