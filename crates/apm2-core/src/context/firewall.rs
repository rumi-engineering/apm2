// AGENT-AUTHORED
//! Context-aware firewall middleware for file access control.
//!
//! This module implements the [`ContextAwareValidator`] trait and
//! [`DefaultContextFirewall`] middleware that validates file reads against
//! a [`ContextPackManifest`] allowlist.
//!
//! # Security Model
//!
//! The context firewall enforces the OCAP (Object-Capability) security model:
//!
//! 1. **Allowlist-based**: Only files explicitly listed in the manifest can be
//!    read
//! 2. **Content verification**: Optional content hash verification for
//!    integrity
//! 3. **Mode-aware enforcement**: Different [`FirewallMode`] options control
//!    behavior
//! 4. **Audit events**: Denied reads emit [`FirewallDecision`] events for
//!    logging
//! 5. **Denial-of-service protection**: Path length limits prevent memory
//!    exhaustion attacks
//!
//! # Firewall Modes
//!
//! - **Warn**: Log warning, allow read (returns Ok with warning event)
//! - **`SoftFail`**: Return error, allow retry (no session termination)
//! - **`HardFail`**: Return error, flag for session termination
//!
//! # Event Emission Pattern
//!
//! The [`FirewallDecision`] struct serves as the event data structure for audit
//! logging. This module follows the middleware pattern where:
//!
//! - The firewall validates requests and returns [`FirewallDecision`] in the
//!   result/error
//! - The **caller** of `validate_read()` is responsible for emitting events to
//!   an event bus
//! - This separation allows flexible event routing without coupling the
//!   firewall to a specific event system
//!
//! Example integration:
//! ```ignore
//! let result = firewall.validate_read(path, hash);
//! if let Some(event) = result.as_ref().err().and_then(|e| e.event()) {
//!     event_bus.emit(event.clone());
//! }
//! ```
//!
//! # Example
//!
//! ```rust
//! use apm2_core::context::firewall::{
//!     ContextAwareValidator, DefaultContextFirewall, FirewallMode,
//! };
//! use apm2_core::context::{
//!     AccessLevel, ContextPackManifest, ContextPackManifestBuilder,
//!     ManifestEntryBuilder,
//! };
//!
//! // Create a manifest with allowed files
//! let manifest =
//!     ContextPackManifestBuilder::new("manifest-001", "profile-001")
//!         .add_entry(
//!             ManifestEntryBuilder::new("/project/src/main.rs", [0x42; 32])
//!                 .access_level(AccessLevel::Read)
//!                 .build(),
//!         )
//!         .build();
//!
//! // Create firewall in SoftFail mode
//! let firewall =
//!     DefaultContextFirewall::new(&manifest, FirewallMode::SoftFail);
//!
//! // Validate reads
//! let result = firewall.validate_read("/project/src/main.rs", None);
//! assert!(result.is_ok());
//!
//! let result = firewall.validate_read("/etc/passwd", None);
//! assert!(result.is_err());
//! ```

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::manifest::{ContextPackManifest, MAX_PATH_LENGTH, ManifestError};

// =============================================================================
// Constants
// =============================================================================

/// Rule ID for context allowlist denials.
pub const CTX_ALLOWLIST_RULE_ID: &str = "CTX-ALLOWLIST-001";

/// Rule ID for content hash mismatch denials.
pub const CTX_HASH_MISMATCH_RULE_ID: &str = "CTX-HASH-MISMATCH-001";

/// Reason text for allowlist denial.
pub const ALLOWLIST_DENIAL_REASON: &str = "Not in allowlist";

/// Reason text for hash mismatch denial.
pub const HASH_MISMATCH_DENIAL_REASON: &str = "Content hash mismatch";

// =============================================================================
// FirewallMode
// =============================================================================

/// Firewall enforcement mode.
///
/// Controls how the firewall responds to denied read attempts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallMode {
    /// Log warning, allow read.
    ///
    /// Returns `Ok(ValidationResult::Warned)` with a warning event.
    /// The read is permitted but the event should be logged.
    Warn,

    /// Return error, allow retry.
    ///
    /// Returns `Err(ContextFirewallError::AccessDenied)` but does not
    /// flag for session termination. The caller may retry or handle gracefully.
    #[default]
    SoftFail,

    /// Return error, terminate session.
    ///
    /// Returns `Err(ContextFirewallError::AccessDenied)` with
    /// `should_terminate_session: true`. The session should be terminated.
    HardFail,
}

impl std::fmt::Display for FirewallMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Warn => write!(f, "warn"),
            Self::SoftFail => write!(f, "soft_fail"),
            Self::HardFail => write!(f, "hard_fail"),
        }
    }
}

// =============================================================================
// FirewallDecision Event
// =============================================================================

/// Decision outcome for a tool invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ToolDecision {
    /// Tool invocation was allowed.
    Allow,
    /// Tool invocation was denied.
    Deny,
}

impl std::fmt::Display for ToolDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Allow => write!(f, "ALLOW"),
            Self::Deny => write!(f, "DENY"),
        }
    }
}

/// Event emitted when a firewall decision is made.
///
/// This event is generated by the context firewall when a read attempt
/// is denied (or warned in Warn mode). It provides audit information
/// about the denial.
///
/// Note: This struct is named `FirewallDecision` to avoid shadowing
/// `crate::events::ToolDecided` (the Protobuf-generated event type).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallDecision {
    /// The decision outcome (DENY for firewall denials).
    pub decision: ToolDecision,

    /// Rule ID that triggered the decision.
    ///
    /// For context allowlist denials, this is [`CTX_ALLOWLIST_RULE_ID`].
    /// For content hash mismatches, this is [`CTX_HASH_MISMATCH_RULE_ID`].
    pub rule_id: String,

    /// The manifest ID for audit traceability (RFC-0015).
    pub manifest_id: String,

    /// The path that was attempted.
    pub path: String,

    /// Human-readable reason for the decision.
    pub reason: String,
}

impl FirewallDecision {
    /// Creates a new DENY event for an allowlist denial.
    #[must_use]
    pub fn deny_allowlist(manifest_id: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            decision: ToolDecision::Deny,
            rule_id: CTX_ALLOWLIST_RULE_ID.to_string(),
            manifest_id: manifest_id.into(),
            path: path.into(),
            reason: ALLOWLIST_DENIAL_REASON.to_string(),
        }
    }

    /// Creates a new DENY event for a content hash mismatch.
    #[must_use]
    pub fn deny_hash_mismatch(manifest_id: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            decision: ToolDecision::Deny,
            rule_id: CTX_HASH_MISMATCH_RULE_ID.to_string(),
            manifest_id: manifest_id.into(),
            path: path.into(),
            reason: HASH_MISMATCH_DENIAL_REASON.to_string(),
        }
    }

    /// Creates a new DENY event with a custom reason.
    #[must_use]
    pub fn deny_with_reason(
        rule_id: impl Into<String>,
        manifest_id: impl Into<String>,
        path: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            decision: ToolDecision::Deny,
            rule_id: rule_id.into(),
            manifest_id: manifest_id.into(),
            path: path.into(),
            reason: reason.into(),
        }
    }
}

// =============================================================================
// ValidationResult
// =============================================================================

/// Result of a validation operation.
///
/// Indicates whether the read was allowed, denied, or allowed with a warning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationResult {
    /// Read is permitted, no issues.
    Allowed,

    /// Read is denied, event should be logged.
    ///
    /// Contains the [`FirewallDecision`] event for audit logging.
    Denied {
        /// The denial event for logging.
        event: FirewallDecision,
    },

    /// Read is allowed but a warning was generated.
    ///
    /// This occurs in [`FirewallMode::Warn`] mode when a read would
    /// normally be denied. The event should be logged but the read proceeds.
    Warned {
        /// The warning event for logging.
        event: FirewallDecision,
    },
}

impl ValidationResult {
    /// Returns true if the read is allowed (either Allowed or Warned).
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed | Self::Warned { .. })
    }

    /// Returns true if the read is denied.
    #[must_use]
    pub const fn is_denied(&self) -> bool {
        matches!(self, Self::Denied { .. })
    }

    /// Returns the event if one was generated (for Denied or Warned).
    #[must_use]
    pub const fn event(&self) -> Option<&FirewallDecision> {
        match self {
            Self::Allowed => None,
            Self::Denied { event } | Self::Warned { event } => Some(event),
        }
    }
}

// =============================================================================
// ContextFirewallError
// =============================================================================

/// Errors that can occur during context firewall validation.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ContextFirewallError {
    /// Access to the path was denied.
    #[error("access denied: {path} - {reason}")]
    AccessDenied {
        /// The path that was denied.
        path: String,
        /// Reason for denial.
        reason: String,
        /// The denial event for logging.
        event: FirewallDecision,
        /// Whether the session should be terminated (`HardFail` mode).
        should_terminate_session: bool,
    },

    /// Invalid path (contains traversal, null bytes, etc.).
    #[error("invalid path: {0}")]
    InvalidPath(#[from] ManifestError),

    /// Content hash mismatch.
    #[error("content hash mismatch for path: {path}")]
    ContentHashMismatch {
        /// The path with mismatched hash.
        path: String,
        /// The denial event for logging.
        event: FirewallDecision,
        /// Whether the session should be terminated.
        should_terminate_session: bool,
    },

    /// Content hash required but not provided.
    #[error("content hash required for path: {path}")]
    ContentHashRequired {
        /// The path that requires a hash.
        path: String,
    },

    /// Path exceeds maximum length (denial-of-service protection).
    #[error("path exceeds max length: {actual} > {max}")]
    PathTooLong {
        /// Actual length of the path.
        actual: usize,
        /// Maximum allowed length.
        max: usize,
    },
}

impl ContextFirewallError {
    /// Returns true if this error should terminate the session.
    #[must_use]
    pub const fn should_terminate_session(&self) -> bool {
        match self {
            Self::AccessDenied {
                should_terminate_session,
                ..
            }
            | Self::ContentHashMismatch {
                should_terminate_session,
                ..
            } => *should_terminate_session,
            Self::InvalidPath(_) | Self::ContentHashRequired { .. } | Self::PathTooLong { .. } => {
                false
            },
        }
    }

    /// Returns the denial event if one was generated.
    #[must_use]
    pub const fn event(&self) -> Option<&FirewallDecision> {
        match self {
            Self::AccessDenied { event, .. } | Self::ContentHashMismatch { event, .. } => {
                Some(event)
            },
            Self::InvalidPath(_) | Self::ContentHashRequired { .. } | Self::PathTooLong { .. } => {
                None
            },
        }
    }
}

// =============================================================================
// ContextAwareValidator Trait
// =============================================================================

/// Trait for context-aware validation of file reads.
///
/// Implementations validate file read requests against a security policy
/// (typically a [`ContextPackManifest`] allowlist).
#[allow(clippy::result_large_err)] // Error type intentionally carries rich diagnostic info
pub trait ContextAwareValidator {
    /// Validates a file read request.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to validate
    /// * `content_hash` - Optional BLAKE3 hash of the file content for
    ///   integrity verification
    ///
    /// # Returns
    ///
    /// `Ok(ValidationResult)` indicating whether the read is allowed, denied,
    /// or warned. `Err(ContextFirewallError)` for validation failures (denied
    /// reads in `SoftFail`/`HardFail` mode, invalid paths, etc.).
    ///
    /// # Errors
    ///
    /// Returns [`ContextFirewallError::AccessDenied`] if the path is not in the
    /// allowlist (in `SoftFail` or `HardFail` mode).
    /// Returns [`ContextFirewallError::InvalidPath`] if the path is malformed.
    /// Returns [`ContextFirewallError::ContentHashMismatch`] if the content
    /// hash doesn't match.
    /// Returns [`ContextFirewallError::ContentHashRequired`] if a hash is
    /// required but not provided.
    fn validate_read(
        &self,
        path: &str,
        content_hash: Option<&[u8; 32]>,
    ) -> Result<ValidationResult, ContextFirewallError>;
}

// =============================================================================
// DefaultContextFirewall
// =============================================================================

/// Default implementation of the context firewall.
///
/// Validates file reads against a [`ContextPackManifest`] allowlist with
/// configurable enforcement mode.
#[derive(Debug)]
pub struct DefaultContextFirewall<'a> {
    /// Reference to the manifest used for validation.
    manifest: &'a ContextPackManifest,
    /// Enforcement mode.
    mode: FirewallMode,
}

impl<'a> DefaultContextFirewall<'a> {
    /// Creates a new firewall with the given manifest and mode.
    #[must_use]
    pub const fn new(manifest: &'a ContextPackManifest, mode: FirewallMode) -> Self {
        Self { manifest, mode }
    }

    /// Creates a new firewall with default `SoftFail` mode.
    #[must_use]
    pub const fn with_manifest(manifest: &'a ContextPackManifest) -> Self {
        Self::new(manifest, FirewallMode::SoftFail)
    }

    /// Returns the firewall mode.
    #[must_use]
    pub const fn mode(&self) -> FirewallMode {
        self.mode
    }

    /// Returns a reference to the manifest.
    #[must_use]
    pub const fn manifest(&self) -> &'a ContextPackManifest {
        self.manifest
    }

    /// Handles a denial based on the firewall mode.
    #[allow(clippy::result_large_err)] // Error type intentionally carries rich diagnostic info
    fn handle_denial(&self, path: &str) -> Result<ValidationResult, ContextFirewallError> {
        let event = FirewallDecision::deny_allowlist(&self.manifest.manifest_id, path);

        match self.mode {
            FirewallMode::Warn => {
                // Allow with warning
                Ok(ValidationResult::Warned { event })
            },
            FirewallMode::SoftFail => {
                // Deny without session termination
                Err(ContextFirewallError::AccessDenied {
                    path: path.to_string(),
                    reason: ALLOWLIST_DENIAL_REASON.to_string(),
                    event,
                    should_terminate_session: false,
                })
            },
            FirewallMode::HardFail => {
                // Deny with session termination
                Err(ContextFirewallError::AccessDenied {
                    path: path.to_string(),
                    reason: ALLOWLIST_DENIAL_REASON.to_string(),
                    event,
                    should_terminate_session: true,
                })
            },
        }
    }

    /// Handles a content hash mismatch based on the firewall mode.
    #[allow(clippy::result_large_err)] // Error type intentionally carries rich diagnostic info
    fn handle_hash_mismatch(&self, path: &str) -> Result<ValidationResult, ContextFirewallError> {
        let event = FirewallDecision::deny_hash_mismatch(&self.manifest.manifest_id, path);

        match self.mode {
            FirewallMode::Warn => {
                // Allow with warning
                Ok(ValidationResult::Warned { event })
            },
            FirewallMode::SoftFail => {
                // Deny without session termination
                Err(ContextFirewallError::ContentHashMismatch {
                    path: path.to_string(),
                    event,
                    should_terminate_session: false,
                })
            },
            FirewallMode::HardFail => {
                // Deny with session termination
                Err(ContextFirewallError::ContentHashMismatch {
                    path: path.to_string(),
                    event,
                    should_terminate_session: true,
                })
            },
        }
    }
}

impl ContextAwareValidator for DefaultContextFirewall<'_> {
    fn validate_read(
        &self,
        path: &str,
        content_hash: Option<&[u8; 32]>,
    ) -> Result<ValidationResult, ContextFirewallError> {
        // DoS protection: Check path length BEFORE any processing to prevent
        // memory exhaustion attacks via extremely long path strings.
        // This check must happen before normalize_path() is called.
        if path.len() > MAX_PATH_LENGTH {
            return Err(ContextFirewallError::PathTooLong {
                actual: path.len(),
                max: MAX_PATH_LENGTH,
            });
        }

        // Use the manifest's is_allowed method which handles:
        // - Path normalization and validation
        // - Allowlist lookup
        // - Content hash verification (if provided)
        match self.manifest.is_allowed(path, content_hash) {
            Ok(true) => Ok(ValidationResult::Allowed),
            Ok(false) => {
                // Path not in allowlist or hash mismatch
                // Determine which case by checking if path exists
                match self.manifest.get_entry(path) {
                    Ok(Some(_entry)) => {
                        // Path exists but hash mismatch
                        self.handle_hash_mismatch(path)
                    },
                    Ok(None) => {
                        // Path not in allowlist
                        self.handle_denial(path)
                    },
                    Err(e) => Err(ContextFirewallError::InvalidPath(e)),
                }
            },
            Err(ManifestError::ContentHashRequired { path }) => {
                Err(ContextFirewallError::ContentHashRequired { path })
            },
            Err(e) => Err(ContextFirewallError::InvalidPath(e)),
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(missing_docs)]
pub mod tests {
    use super::*;
    use crate::context::{AccessLevel, ContextPackManifestBuilder, ManifestEntryBuilder};

    fn create_test_manifest() -> ContextPackManifest {
        ContextPackManifestBuilder::new("manifest-001", "profile-001")
            .add_entry(
                ManifestEntryBuilder::new("/project/src/main.rs", [0x42; 32])
                    .stable_id("src-main")
                    .access_level(AccessLevel::Read)
                    .build(),
            )
            .add_entry(
                ManifestEntryBuilder::new("/project/README.md", [0xAB; 32])
                    .access_level(AccessLevel::ReadWithZoom)
                    .build(),
            )
            .add_entry(
                ManifestEntryBuilder::new("/project/Cargo.toml", [0xCD; 32])
                    .access_level(AccessLevel::Read)
                    .build(),
            )
            .build()
    }

    // =========================================================================
    // FirewallMode Tests
    // =========================================================================

    #[test]
    fn test_firewall_mode_default() {
        assert_eq!(FirewallMode::default(), FirewallMode::SoftFail);
    }

    #[test]
    fn test_firewall_mode_display() {
        assert_eq!(format!("{}", FirewallMode::Warn), "warn");
        assert_eq!(format!("{}", FirewallMode::SoftFail), "soft_fail");
        assert_eq!(format!("{}", FirewallMode::HardFail), "hard_fail");
    }

    #[test]
    fn test_firewall_mode_serde_roundtrip() {
        for mode in [
            FirewallMode::Warn,
            FirewallMode::SoftFail,
            FirewallMode::HardFail,
        ] {
            let json = serde_json::to_string(&mode).unwrap();
            let recovered: FirewallMode = serde_json::from_str(&json).unwrap();
            assert_eq!(mode, recovered);
        }
    }

    // =========================================================================
    // FirewallDecision Tests
    // =========================================================================

    #[test]
    fn test_firewall_decision_deny_allowlist() {
        let event = FirewallDecision::deny_allowlist("manifest-001", "/etc/passwd");

        assert_eq!(event.decision, ToolDecision::Deny);
        assert_eq!(event.rule_id, CTX_ALLOWLIST_RULE_ID);
        assert_eq!(event.manifest_id, "manifest-001");
        assert_eq!(event.path, "/etc/passwd");
        assert_eq!(event.reason, ALLOWLIST_DENIAL_REASON);
    }

    #[test]
    fn test_firewall_decision_deny_hash_mismatch() {
        let event = FirewallDecision::deny_hash_mismatch("manifest-002", "/project/file.rs");

        assert_eq!(event.decision, ToolDecision::Deny);
        assert_eq!(event.rule_id, CTX_HASH_MISMATCH_RULE_ID);
        assert_eq!(event.manifest_id, "manifest-002");
        assert_eq!(event.path, "/project/file.rs");
        assert_eq!(event.reason, HASH_MISMATCH_DENIAL_REASON);
    }

    #[test]
    fn test_firewall_decision_deny_with_reason() {
        let event = FirewallDecision::deny_with_reason(
            "CUSTOM-RULE-001",
            "manifest-003",
            "/some/path",
            "Custom denial reason",
        );

        assert_eq!(event.decision, ToolDecision::Deny);
        assert_eq!(event.rule_id, "CUSTOM-RULE-001");
        assert_eq!(event.manifest_id, "manifest-003");
        assert_eq!(event.path, "/some/path");
        assert_eq!(event.reason, "Custom denial reason");
    }

    #[test]
    fn test_firewall_decision_serde_roundtrip() {
        let event = FirewallDecision::deny_allowlist("manifest-001", "/test/path");
        let json = serde_json::to_string(&event).unwrap();
        let recovered: FirewallDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(event, recovered);
    }

    #[test]
    fn test_firewall_decision_deny_unknown_fields() {
        let json = r#"{
            "decision": "DENY",
            "rule_id": "CTX-ALLOWLIST-001",
            "manifest_id": "manifest-001",
            "path": "/test/path",
            "reason": "Not in allowlist",
            "unknown_field": "malicious"
        }"#;

        let result: Result<FirewallDecision, _> = serde_json::from_str(json);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown field"),
            "Error should mention unknown field: {err}"
        );
    }

    #[test]
    fn test_tool_decision_display() {
        assert_eq!(format!("{}", ToolDecision::Allow), "ALLOW");
        assert_eq!(format!("{}", ToolDecision::Deny), "DENY");
    }

    // =========================================================================
    // ValidationResult Tests
    // =========================================================================

    #[test]
    fn test_validation_result_allowed() {
        let result = ValidationResult::Allowed;

        assert!(result.is_allowed());
        assert!(!result.is_denied());
        assert!(result.event().is_none());
    }

    #[test]
    fn test_validation_result_denied() {
        let event = FirewallDecision::deny_allowlist("manifest-001", "/test");
        let result = ValidationResult::Denied {
            event: event.clone(),
        };

        assert!(!result.is_allowed());
        assert!(result.is_denied());
        assert_eq!(result.event(), Some(&event));
    }

    #[test]
    fn test_validation_result_warned() {
        let event = FirewallDecision::deny_allowlist("manifest-001", "/test");
        let result = ValidationResult::Warned {
            event: event.clone(),
        };

        assert!(result.is_allowed());
        assert!(!result.is_denied());
        assert_eq!(result.event(), Some(&event));
    }

    // =========================================================================
    // ContextFirewallError Tests
    // =========================================================================

    #[test]
    fn test_error_should_terminate_session() {
        let event = FirewallDecision::deny_allowlist("manifest-001", "/test");

        // AccessDenied with terminate flag
        let err = ContextFirewallError::AccessDenied {
            path: "/test".to_string(),
            reason: "test".to_string(),
            event: event.clone(),
            should_terminate_session: true,
        };
        assert!(err.should_terminate_session());

        // AccessDenied without terminate flag
        let err = ContextFirewallError::AccessDenied {
            path: "/test".to_string(),
            reason: "test".to_string(),
            event: event.clone(),
            should_terminate_session: false,
        };
        assert!(!err.should_terminate_session());

        // ContentHashMismatch with terminate flag
        let err = ContextFirewallError::ContentHashMismatch {
            path: "/test".to_string(),
            event,
            should_terminate_session: true,
        };
        assert!(err.should_terminate_session());

        // InvalidPath never terminates
        let err = ContextFirewallError::InvalidPath(ManifestError::InvalidPath {
            reason: "test".to_string(),
        });
        assert!(!err.should_terminate_session());

        // ContentHashRequired never terminates
        let err = ContextFirewallError::ContentHashRequired {
            path: "/test".to_string(),
        };
        assert!(!err.should_terminate_session());
    }

    #[test]
    fn test_error_event() {
        let event = FirewallDecision::deny_allowlist("manifest-001", "/test");

        let err = ContextFirewallError::AccessDenied {
            path: "/test".to_string(),
            reason: "test".to_string(),
            event: event.clone(),
            should_terminate_session: false,
        };
        assert_eq!(err.event(), Some(&event));

        let err = ContextFirewallError::ContentHashRequired {
            path: "/test".to_string(),
        };
        assert!(err.event().is_none());
    }

    // =========================================================================
    // DefaultContextFirewall Construction Tests
    // =========================================================================

    #[test]
    fn test_firewall_construction() {
        let manifest = create_test_manifest();
        let firewall = DefaultContextFirewall::new(&manifest, FirewallMode::HardFail);

        assert_eq!(firewall.mode(), FirewallMode::HardFail);
        assert_eq!(firewall.manifest().manifest_id, "manifest-001");
    }

    #[test]
    fn test_firewall_with_manifest_default_mode() {
        let manifest = create_test_manifest();
        let firewall = DefaultContextFirewall::with_manifest(&manifest);

        assert_eq!(firewall.mode(), FirewallMode::SoftFail);
    }

    // =========================================================================
    // Allowed Reads Tests
    // =========================================================================

    #[test]
    fn test_allowed_read_in_allowlist() {
        let manifest = create_test_manifest();
        let firewall = DefaultContextFirewall::new(&manifest, FirewallMode::SoftFail);

        let result = firewall.validate_read("/project/src/main.rs", None);
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), ValidationResult::Allowed));
    }

    #[test]
    fn test_allowed_read_with_matching_hash() {
        let manifest = create_test_manifest();
        let firewall = DefaultContextFirewall::new(&manifest, FirewallMode::SoftFail);

        let result = firewall.validate_read("/project/src/main.rs", Some(&[0x42; 32]));
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), ValidationResult::Allowed));
    }

    #[test]
    fn test_allowed_read_with_path_normalization() {
        let manifest = create_test_manifest();
        let firewall = DefaultContextFirewall::new(&manifest, FirewallMode::SoftFail);

        // Path with .. that normalizes to allowed path
        let result = firewall.validate_read("/project/src/../src/main.rs", None);
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), ValidationResult::Allowed));
    }

    // =========================================================================
    // Denied Reads Tests - SoftFail Mode
    // =========================================================================

    #[test]
    fn test_denied_read_not_in_allowlist_soft_fail() {
        let manifest = create_test_manifest();
        let firewall = DefaultContextFirewall::new(&manifest, FirewallMode::SoftFail);

        let result = firewall.validate_read("/etc/passwd", None);
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(matches!(err, ContextFirewallError::AccessDenied { .. }));
        assert!(!err.should_terminate_session());

        if let ContextFirewallError::AccessDenied { event, .. } = err {
            assert_eq!(event.decision, ToolDecision::Deny);
            assert_eq!(event.rule_id, CTX_ALLOWLIST_RULE_ID);
            assert_eq!(event.manifest_id, "manifest-001");
            assert_eq!(event.path, "/etc/passwd");
        }
    }

    #[test]
    fn test_denied_read_hash_mismatch_soft_fail() {
        let manifest = create_test_manifest();
        let firewall = DefaultContextFirewall::new(&manifest, FirewallMode::SoftFail);

        // Wrong hash for existing path
        let result = firewall.validate_read("/project/src/main.rs", Some(&[0xFF; 32]));
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(matches!(
            err,
            ContextFirewallError::ContentHashMismatch { .. }
        ));
        assert!(!err.should_terminate_session());

        // Verify the hash mismatch uses correct rule ID
        if let ContextFirewallError::ContentHashMismatch { event, .. } = err {
            assert_eq!(event.decision, ToolDecision::Deny);
            assert_eq!(event.rule_id, CTX_HASH_MISMATCH_RULE_ID);
            assert_eq!(event.manifest_id, "manifest-001");
            assert_eq!(event.path, "/project/src/main.rs");
            assert_eq!(event.reason, HASH_MISMATCH_DENIAL_REASON);
        }
    }

    // =========================================================================
    // Denied Reads Tests - HardFail Mode
    // =========================================================================

    #[test]
    fn test_denied_read_not_in_allowlist_hard_fail() {
        let manifest = create_test_manifest();
        let firewall = DefaultContextFirewall::new(&manifest, FirewallMode::HardFail);

        let result = firewall.validate_read("/etc/passwd", None);
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(matches!(err, ContextFirewallError::AccessDenied { .. }));
        assert!(err.should_terminate_session());
    }

    #[test]
    fn test_denied_read_hash_mismatch_hard_fail() {
        let manifest = create_test_manifest();
        let firewall = DefaultContextFirewall::new(&manifest, FirewallMode::HardFail);

        let result = firewall.validate_read("/project/src/main.rs", Some(&[0xFF; 32]));
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(matches!(
            err,
            ContextFirewallError::ContentHashMismatch { .. }
        ));
        assert!(err.should_terminate_session());
    }

    // =========================================================================
    // Warn Mode Tests
    // =========================================================================

    #[test]
    fn test_warn_mode_not_in_allowlist() {
        let manifest = create_test_manifest();
        let firewall = DefaultContextFirewall::new(&manifest, FirewallMode::Warn);

        let result = firewall.validate_read("/etc/passwd", None);
        assert!(result.is_ok());

        let validation = result.unwrap();
        assert!(validation.is_allowed());
        assert!(matches!(validation, ValidationResult::Warned { .. }));

        if let ValidationResult::Warned { event } = validation {
            assert_eq!(event.decision, ToolDecision::Deny);
            assert_eq!(event.rule_id, CTX_ALLOWLIST_RULE_ID);
            assert_eq!(event.manifest_id, "manifest-001");
            assert_eq!(event.path, "/etc/passwd");
        }
    }

    #[test]
    fn test_warn_mode_hash_mismatch() {
        let manifest = create_test_manifest();
        let firewall = DefaultContextFirewall::new(&manifest, FirewallMode::Warn);

        let result = firewall.validate_read("/project/src/main.rs", Some(&[0xFF; 32]));
        assert!(result.is_ok());

        let validation = result.unwrap();
        assert!(validation.is_allowed());
        assert!(matches!(validation, ValidationResult::Warned { .. }));

        // Verify the hash mismatch uses correct rule ID in Warn mode
        if let ValidationResult::Warned { event } = validation {
            assert_eq!(event.decision, ToolDecision::Deny);
            assert_eq!(event.rule_id, CTX_HASH_MISMATCH_RULE_ID);
            assert_eq!(event.manifest_id, "manifest-001");
            assert_eq!(event.path, "/project/src/main.rs");
        }
    }

    #[test]
    fn test_warn_mode_allowed_read_no_warning() {
        let manifest = create_test_manifest();
        let firewall = DefaultContextFirewall::new(&manifest, FirewallMode::Warn);

        let result = firewall.validate_read("/project/src/main.rs", None);
        assert!(result.is_ok());

        let validation = result.unwrap();
        assert!(matches!(validation, ValidationResult::Allowed));
        assert!(validation.event().is_none());
    }

    // =========================================================================
    // Content Hash Required Tests
    // =========================================================================

    #[test]
    fn test_content_hash_required_for_read_with_zoom() {
        let manifest = create_test_manifest();
        let firewall = DefaultContextFirewall::new(&manifest, FirewallMode::SoftFail);

        // README.md has ReadWithZoom access level, requires hash
        let result = firewall.validate_read("/project/README.md", None);
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(matches!(
            err,
            ContextFirewallError::ContentHashRequired { .. }
        ));
    }

    #[test]
    fn test_read_with_zoom_allowed_with_hash() {
        let manifest = create_test_manifest();
        let firewall = DefaultContextFirewall::new(&manifest, FirewallMode::SoftFail);

        let result = firewall.validate_read("/project/README.md", Some(&[0xAB; 32]));
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), ValidationResult::Allowed));
    }

    // =========================================================================
    // Invalid Path Tests
    // =========================================================================

    #[test]
    fn test_invalid_path_traversal() {
        let manifest = create_test_manifest();
        let firewall = DefaultContextFirewall::new(&manifest, FirewallMode::SoftFail);

        let result = firewall.validate_read("/project/../../../etc/passwd", None);
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(matches!(err, ContextFirewallError::InvalidPath(_)));
    }

    #[test]
    fn test_invalid_path_null_byte() {
        let manifest = create_test_manifest();
        let firewall = DefaultContextFirewall::new(&manifest, FirewallMode::SoftFail);

        let result = firewall.validate_read("/project/src/main.rs\0.txt", None);
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(matches!(err, ContextFirewallError::InvalidPath(_)));
    }

    // =========================================================================
    // DoS Protection Tests
    // =========================================================================

    #[test]
    fn test_path_too_long_dos_protection() {
        use super::super::manifest::MAX_PATH_LENGTH;

        let manifest = create_test_manifest();
        let firewall = DefaultContextFirewall::new(&manifest, FirewallMode::SoftFail);

        // Create a path that exceeds MAX_PATH_LENGTH
        let long_path = "/".to_string() + &"x".repeat(MAX_PATH_LENGTH + 1);
        assert!(long_path.len() > MAX_PATH_LENGTH);

        let result = firewall.validate_read(&long_path, None);
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                ContextFirewallError::PathTooLong { actual, max }
                if actual == long_path.len() && max == MAX_PATH_LENGTH
            ),
            "Expected PathTooLong error, got {err:?}"
        );

        // Verify DoS protection doesn't terminate session
        assert!(!err.should_terminate_session());
    }

    #[test]
    fn test_path_at_max_length_allowed() {
        use super::super::manifest::MAX_PATH_LENGTH;

        // Create a manifest with a path exactly at MAX_PATH_LENGTH
        // The path must be valid (absolute) and within limits
        let valid_path = "/".to_string() + &"a".repeat(MAX_PATH_LENGTH - 1);
        assert_eq!(valid_path.len(), MAX_PATH_LENGTH);

        let manifest = ContextPackManifestBuilder::new("manifest-001", "profile-001")
            .add_entry(
                ManifestEntryBuilder::new(valid_path.clone(), [0x42; 32])
                    .access_level(AccessLevel::Read)
                    .build(),
            )
            .build();
        let firewall = DefaultContextFirewall::new(&manifest, FirewallMode::SoftFail);

        // Path at exactly max length should be allowed
        let result = firewall.validate_read(&valid_path, None);
        assert!(result.is_ok(), "Path at max length should be allowed");
    }

    // =========================================================================
    // Empty Manifest Tests
    // =========================================================================

    #[test]
    fn test_empty_manifest_denies_all() {
        let manifest = ContextPackManifestBuilder::new("manifest-empty", "profile-001").build();
        let firewall = DefaultContextFirewall::new(&manifest, FirewallMode::SoftFail);

        let result = firewall.validate_read("/any/path", None);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContextFirewallError::AccessDenied { .. }
        ));
    }

    // =========================================================================
    // Mode Behavior Consistency Tests
    // =========================================================================

    #[test]
    fn test_all_modes_allow_valid_reads() {
        let manifest = create_test_manifest();

        for mode in [
            FirewallMode::Warn,
            FirewallMode::SoftFail,
            FirewallMode::HardFail,
        ] {
            let firewall = DefaultContextFirewall::new(&manifest, mode);
            let result = firewall.validate_read("/project/src/main.rs", None);

            assert!(result.is_ok(), "Mode {mode:?} should allow valid reads");
            assert!(matches!(result.unwrap(), ValidationResult::Allowed));
        }
    }

    #[test]
    fn test_all_modes_generate_events_for_denials() {
        let manifest = create_test_manifest();

        for mode in [
            FirewallMode::Warn,
            FirewallMode::SoftFail,
            FirewallMode::HardFail,
        ] {
            let firewall = DefaultContextFirewall::new(&manifest, mode);
            let result = firewall.validate_read("/etc/passwd", None);

            let event = match &result {
                Ok(ValidationResult::Warned { event }) => Some(event),
                Err(err) => err.event(),
                _ => None,
            };

            assert!(
                event.is_some(),
                "Mode {mode:?} should generate event for denial"
            );
            assert_eq!(event.unwrap().decision, ToolDecision::Deny);
        }
    }

    // =========================================================================
    // Edge Case Tests
    // =========================================================================

    #[test]
    fn test_root_path() {
        let manifest = create_test_manifest();
        let firewall = DefaultContextFirewall::new(&manifest, FirewallMode::SoftFail);

        let result = firewall.validate_read("/", None);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContextFirewallError::AccessDenied { .. }
        ));
    }

    #[test]
    fn test_deeply_nested_allowed_path() {
        let manifest = ContextPackManifestBuilder::new("manifest-001", "profile-001")
            .add_entry(
                ManifestEntryBuilder::new("/a/b/c/d/e/f/g/h/i/j/file.rs", [0x42; 32])
                    .access_level(AccessLevel::Read)
                    .build(),
            )
            .build();
        let firewall = DefaultContextFirewall::new(&manifest, FirewallMode::SoftFail);

        let result = firewall.validate_read("/a/b/c/d/e/f/g/h/i/j/file.rs", None);
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), ValidationResult::Allowed));
    }

    #[test]
    fn test_unicode_path() {
        let manifest = ContextPackManifestBuilder::new("manifest-001", "profile-001")
            .add_entry(
                ManifestEntryBuilder::new("/project/src/日本語.rs", [0x42; 32])
                    .access_level(AccessLevel::Read)
                    .build(),
            )
            .build();
        let firewall = DefaultContextFirewall::new(&manifest, FirewallMode::SoftFail);

        // Allowed unicode path
        let result = firewall.validate_read("/project/src/日本語.rs", None);
        assert!(result.is_ok());

        // Non-allowed unicode path
        let result = firewall.validate_read("/project/src/中文.rs", None);
        assert!(result.is_err());
    }
}
