//! Capability manifest and validation for OCAP enforcement.
//!
//! This module implements capability manifests per AD-TOOL-002. Capabilities
//! are sealed references that grant specific tool access with scoped
//! parameters. Capabilities are delegated, not discovered (OCAP enforcement).
//!
//! # Architecture
//!
//! ```text
//! CapabilityManifest
//!     ├── manifest_id: unique identifier
//!     ├── capabilities: Vec<Capability>
//!     ├── delegator_id: who granted these capabilities
//!     ├── created_at: creation timestamp
//!     └── expires_at: optional expiration
//!           │
//!           └── each Capability:
//!                   ├── capability_id: unique within manifest
//!                   ├── tool_class: Read | Write | Execute | ...
//!                   ├── scope: CapabilityScope
//!                   └── risk_tier_required: minimum tier
//! ```
//!
//! # Security Model
//!
//! Per AD-TOOL-002:
//! - Capabilities MUST NOT be discoverable
//! - Only explicit delegation creates capabilities
//! - Sealed references prevent forgery or escalation
//! - All tool requests are validated against the manifest
//!
//! # Contract References
//!
//! - AD-TOOL-002: Capability manifests as sealed references
//! - AD-EPISODE-001: Capability manifest hash in envelope
//! - REQ-TOOL-001: Tool access control requirements
//! - CTR-1303: Bounded collections with MAX_* constants
//! - HOLONIC-BOUNDARY-001: Deterministic time via clock injection

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use prost::Message;
use serde::{Deserialize, Serialize};

use super::envelope::RiskTier;
use super::scope::{CapabilityScope, ScopeError};
// =============================================================================
// Allowlist Resource Limits (TCK-00254)
//
// Per CTR-1303, all Vec fields must have bounded sizes to prevent DoS.
// All MAX_*_ALLOWLIST constants are defined in apm2-core and re-exported via
// tool_class to eliminate duplication (Code Quality Review [MAJOR]).
// =============================================================================
pub use super::tool_class::{
    MAX_SHELL_ALLOWLIST, MAX_SHELL_PATTERN_LEN, MAX_TOOL_ALLOWLIST, MAX_WRITE_ALLOWLIST, ToolClass,
    shell_pattern_matches,
};

// =============================================================================
// Clock Abstraction
//
// Per HOLONIC-BOUNDARY-001, time-dependent operations should use injected
// clocks rather than direct SystemTime access. This enables:
// - Deterministic testing
// - Reproducible audit trails
// - Time-travel debugging
// =============================================================================

/// Trait for clock implementations.
///
/// Per HOLONIC-BOUNDARY-001, this abstraction allows deterministic testing
/// and auditing of time-dependent operations like expiration checks.
pub trait Clock: Send + Sync {
    /// Returns the current Unix timestamp in seconds.
    fn now_secs(&self) -> u64;
}

/// System clock that uses the real system time.
///
/// This is the default clock for production use.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs()
    }
}

/// Fixed clock for testing that returns a constant timestamp.
///
/// This allows deterministic testing of expiration logic.
#[derive(Debug, Clone, Copy)]
pub struct FixedClock {
    /// The fixed timestamp to return.
    pub timestamp: u64,
}

impl FixedClock {
    /// Creates a new fixed clock with the given timestamp.
    #[must_use]
    pub const fn new(timestamp: u64) -> Self {
        Self { timestamp }
    }
}

impl Clock for FixedClock {
    fn now_secs(&self) -> u64 {
        self.timestamp
    }
}

/// Maximum number of capabilities in a manifest.
pub const MAX_CAPABILITIES: usize = 1000;

/// Maximum length for manifest ID.
pub const MAX_MANIFEST_ID_LEN: usize = 256;

/// Maximum length for capability ID.
pub const MAX_CAPABILITY_ID_LEN: usize = 256;

/// Maximum length for actor ID.
pub const MAX_ACTOR_ID_LEN: usize = 256;

/// Error type for capability operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityError {
    /// Too many capabilities in manifest.
    TooManyCapabilities {
        /// Actual count of capabilities.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Manifest ID exceeds maximum length.
    ManifestIdTooLong {
        /// Actual length in bytes.
        len: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Capability ID exceeds maximum length.
    CapabilityIdTooLong {
        /// Actual length in bytes.
        len: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Actor ID exceeds maximum length.
    ActorIdTooLong {
        /// Actual length in bytes.
        len: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Duplicate capability ID.
    DuplicateCapabilityId {
        /// The duplicated ID.
        id: String,
    },

    /// Scope validation failed.
    ScopeValidation(ScopeError),

    /// Manifest has expired.
    ManifestExpired,

    /// Required field is empty.
    EmptyField {
        /// Name of the empty field.
        field: &'static str,
    },

    /// Tool allowlist exceeds maximum size.
    TooManyToolAllowlistEntries {
        /// Actual count.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Write allowlist exceeds maximum size.
    TooManyWriteAllowlistEntries {
        /// Actual count.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Shell allowlist exceeds maximum size.
    TooManyShellAllowlistEntries {
        /// Actual count.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Shell pattern exceeds maximum length.
    ShellPatternTooLong {
        /// Actual length in bytes.
        len: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Path in write allowlist exceeds maximum length.
    WriteAllowlistPathTooLong {
        /// Actual length in bytes.
        len: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Path in write allowlist is not absolute.
    ///
    /// Per CTR-1503, all write paths must be absolute to prevent
    /// path resolution attacks.
    WriteAllowlistPathNotAbsolute {
        /// The path that is not absolute.
        path: String,
    },

    /// Path in write allowlist contains path traversal.
    ///
    /// Per CTR-1503 and CTR-2609, paths must not contain `..` components
    /// to prevent directory escape attacks.
    WriteAllowlistPathTraversal {
        /// The path that contains traversal.
        path: String,
    },
}

impl std::fmt::Display for CapabilityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooManyCapabilities { count, max } => {
                write!(f, "too many capabilities: {count} (max {max})")
            },
            Self::ManifestIdTooLong { len, max } => {
                write!(f, "manifest ID too long: {len} bytes (max {max})")
            },
            Self::CapabilityIdTooLong { len, max } => {
                write!(f, "capability ID too long: {len} bytes (max {max})")
            },
            Self::ActorIdTooLong { len, max } => {
                write!(f, "actor ID too long: {len} bytes (max {max})")
            },
            Self::DuplicateCapabilityId { id } => {
                write!(f, "duplicate capability ID: {id}")
            },
            Self::ScopeValidation(e) => {
                write!(f, "scope validation failed: {e}")
            },
            Self::ManifestExpired => {
                write!(f, "capability manifest has expired")
            },
            Self::EmptyField { field } => {
                write!(f, "required field is empty: {field}")
            },
            Self::TooManyToolAllowlistEntries { count, max } => {
                write!(f, "too many tool allowlist entries: {count} (max {max})")
            },
            Self::TooManyWriteAllowlistEntries { count, max } => {
                write!(f, "too many write allowlist entries: {count} (max {max})")
            },
            Self::TooManyShellAllowlistEntries { count, max } => {
                write!(f, "too many shell allowlist entries: {count} (max {max})")
            },
            Self::ShellPatternTooLong { len, max } => {
                write!(f, "shell pattern too long: {len} bytes (max {max})")
            },
            Self::WriteAllowlistPathTooLong { len, max } => {
                write!(f, "write allowlist path too long: {len} bytes (max {max})")
            },
            Self::WriteAllowlistPathNotAbsolute { path } => {
                write!(f, "write allowlist path is not absolute: {path}")
            },
            Self::WriteAllowlistPathTraversal { path } => {
                write!(f, "write allowlist path contains traversal (..): {path}")
            },
        }
    }
}

impl std::error::Error for CapabilityError {}

impl From<ScopeError> for CapabilityError {
    fn from(e: ScopeError) -> Self {
        Self::ScopeValidation(e)
    }
}

/// Decision result for capability validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityDecision {
    /// Request is allowed by the matched capability.
    Allow {
        /// The capability ID that allowed the request.
        capability_id: String,
    },

    /// Request is denied.
    Deny {
        /// Reason for denial.
        reason: DenyReason,
    },
}

impl CapabilityDecision {
    /// Returns `true` if this is an Allow decision.
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow { .. })
    }

    /// Returns `true` if this is a Deny decision.
    #[must_use]
    pub const fn is_denied(&self) -> bool {
        matches!(self, Self::Deny { .. })
    }
}

/// Reason for capability denial.
///
/// # Security
///
/// Uses `deny_unknown_fields` to prevent field injection attacks when
/// deserializing from untrusted input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum DenyReason {
    /// No capability matches the requested tool class.
    NoMatchingCapability {
        /// The tool class that was requested.
        tool_class: ToolClass,
    },

    /// Path is not allowed by any capability scope.
    PathNotAllowed {
        /// The path that was denied.
        path: String,
    },

    /// Size exceeds capability limits.
    SizeExceeded {
        /// The requested size in bytes.
        requested: u64,
        /// The maximum allowed size.
        max: u64,
    },

    /// Network access denied.
    NetworkNotAllowed {
        /// The target host.
        host: String,
        /// The target port.
        port: u16,
    },

    /// Risk tier is insufficient.
    InsufficientRiskTier {
        /// The minimum required risk tier.
        required: RiskTier,
        /// The actual risk tier.
        actual: RiskTier,
    },

    /// Manifest has expired.
    ManifestExpired,

    /// Request was denied by policy.
    ///
    /// This is distinct from capability denial - policy rules provide
    /// coarse-grained access control independent of capability scopes.
    PolicyDenied {
        /// The policy rule ID that caused the denial.
        rule_id: String,
        /// Human-readable reason for the denial.
        reason: String,
    },

    /// Tool class is not in the manifest's tool allowlist.
    ///
    /// Per TCK-00254, tools must be explicitly allowed in the manifest.
    /// Empty `tool_allowlist` means no tools allowed (fail-closed).
    ToolNotInAllowlist {
        /// The tool class that was denied.
        tool_class: ToolClass,
    },

    /// Write path is not in the manifest's write allowlist.
    ///
    /// Per TCK-00254, write operations must target paths in the allowlist.
    /// Empty `write_allowlist` means no writes allowed (fail-closed).
    WritePathNotInAllowlist {
        /// The path that was denied.
        path: String,
    },

    /// Shell command is not in the manifest's shell allowlist.
    ///
    /// Per TCK-00254, shell commands must match patterns in the allowlist.
    /// Empty `shell_allowlist` means no shell commands allowed (fail-closed).
    ShellCommandNotInAllowlist {
        /// The shell command that was denied.
        command: String,
    },

    /// Write path is required but not provided.
    ///
    /// Per TCK-00254, when `write_allowlist` is configured, the request MUST
    /// include a path for validation. Fail-closed semantics: missing field =
    /// deny.
    WritePathRequired,

    /// Shell command is required but not provided.
    ///
    /// Per TCK-00254, when `shell_allowlist` is configured, the request MUST
    /// include a shell command for validation. Fail-closed semantics: missing
    /// field = deny.
    ShellCommandRequired,
}

impl std::fmt::Display for DenyReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoMatchingCapability { tool_class } => {
                write!(f, "no capability for tool class: {tool_class}")
            },
            Self::PathNotAllowed { path } => {
                write!(f, "path not allowed: {path}")
            },
            Self::SizeExceeded { requested, max } => {
                write!(f, "size exceeded: {requested} bytes (max {max})")
            },
            Self::NetworkNotAllowed { host, port } => {
                write!(f, "network access denied: {host}:{port}")
            },
            Self::InsufficientRiskTier { required, actual } => {
                write!(
                    f,
                    "insufficient risk tier: requires {required:?}, have {actual:?}"
                )
            },
            Self::ManifestExpired => {
                write!(f, "capability manifest has expired")
            },
            Self::PolicyDenied { rule_id, reason } => {
                write!(f, "policy denied by rule {rule_id}: {reason}")
            },
            Self::ToolNotInAllowlist { tool_class } => {
                write!(f, "tool class not in allowlist: {tool_class}")
            },
            Self::WritePathNotInAllowlist { path } => {
                write!(f, "write path not in allowlist: {path}")
            },
            Self::ShellCommandNotInAllowlist { command } => {
                write!(f, "shell command not in allowlist: {command}")
            },
            Self::WritePathRequired => {
                write!(f, "write path required when write_allowlist is configured")
            },
            Self::ShellCommandRequired => {
                write!(
                    f,
                    "shell command required when shell_allowlist is configured"
                )
            },
        }
    }
}

/// A single capability granting access to a tool class with scoped parameters.
///
/// Per AD-TOOL-002, capabilities are sealed references that cannot be
/// forged or escalated. Each capability grants access to a specific tool
/// class within the defined scope.
///
/// # Security
///
/// Uses `deny_unknown_fields` to prevent field injection attacks when
/// deserializing from untrusted input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capability {
    /// Unique identifier for this capability within the manifest.
    pub capability_id: String,

    /// The tool class this capability grants access to.
    pub tool_class: ToolClass,

    /// Scope restrictions for this capability.
    pub scope: CapabilityScope,

    /// Minimum risk tier required to use this capability.
    pub risk_tier_required: RiskTier,
}

impl Capability {
    /// Creates a builder for constructing a capability.
    #[must_use]
    pub fn builder(id: impl Into<String>, tool_class: ToolClass) -> CapabilityBuilder {
        CapabilityBuilder::new(id, tool_class)
    }

    /// Validates the capability structure.
    ///
    /// # Errors
    ///
    /// Returns an error if validation fails.
    pub fn validate(&self) -> Result<(), CapabilityError> {
        if self.capability_id.is_empty() {
            return Err(CapabilityError::EmptyField {
                field: "capability_id",
            });
        }
        if self.capability_id.len() > MAX_CAPABILITY_ID_LEN {
            return Err(CapabilityError::CapabilityIdTooLong {
                len: self.capability_id.len(),
                max: MAX_CAPABILITY_ID_LEN,
            });
        }
        self.scope.validate()?;
        Ok(())
    }

    /// Checks if this capability allows access to the given path.
    #[must_use]
    pub fn allows_path(&self, path: &Path) -> bool {
        self.scope.allows_path(path)
    }

    /// Checks if this capability allows the given read size.
    #[must_use]
    pub const fn allows_read_size(&self, size: u64) -> bool {
        self.scope.allows_read_size(size)
    }

    /// Checks if this capability allows the given write size.
    #[must_use]
    pub const fn allows_write_size(&self, size: u64) -> bool {
        self.scope.allows_write_size(size)
    }

    /// Checks if this capability allows network access to the given host/port.
    #[must_use]
    pub fn allows_network(&self, host: &str, port: u16) -> bool {
        self.scope.allows_network(host, port)
    }

    /// Checks if the given risk tier is sufficient for this capability.
    #[must_use]
    pub const fn risk_tier_sufficient(&self, actual_tier: RiskTier) -> bool {
        actual_tier.tier() >= self.risk_tier_required.tier()
    }
}

/// Internal protobuf representation for `Capability`.
#[derive(Clone, PartialEq, Message)]
struct CapabilityProto {
    #[prost(string, tag = "1")]
    capability_id: String,
    #[prost(uint32, optional, tag = "2")]
    tool_class: Option<u32>,
    #[prost(bytes = "vec", tag = "3")]
    scope_bytes: Vec<u8>,
    #[prost(uint32, optional, tag = "4")]
    risk_tier_required: Option<u32>,
}

impl Capability {
    /// Returns the canonical bytes for this capability.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let proto = CapabilityProto {
            capability_id: self.capability_id.clone(),
            tool_class: Some(u32::from(self.tool_class.value())),
            scope_bytes: self.scope.canonical_bytes(),
            risk_tier_required: Some(u32::from(self.risk_tier_required.tier())),
        };
        proto.encode_to_vec()
    }
}

/// Builder for `Capability`.
#[derive(Debug, Clone)]
pub struct CapabilityBuilder {
    capability_id: String,
    tool_class: ToolClass,
    scope: CapabilityScope,
    risk_tier_required: RiskTier,
}

impl CapabilityBuilder {
    /// Creates a new builder.
    #[must_use]
    pub fn new(id: impl Into<String>, tool_class: ToolClass) -> Self {
        Self {
            capability_id: id.into(),
            tool_class,
            scope: CapabilityScope::default(),
            risk_tier_required: RiskTier::default(),
        }
    }

    /// Sets the scope.
    #[must_use]
    pub fn scope(mut self, scope: CapabilityScope) -> Self {
        self.scope = scope;
        self
    }

    /// Sets the required risk tier.
    #[must_use]
    pub const fn risk_tier(mut self, tier: RiskTier) -> Self {
        self.risk_tier_required = tier;
        self
    }

    /// Builds the capability.
    ///
    /// # Errors
    ///
    /// Returns an error if validation fails.
    pub fn build(self) -> Result<Capability, CapabilityError> {
        let cap = Capability {
            capability_id: self.capability_id,
            tool_class: self.tool_class,
            scope: self.scope,
            risk_tier_required: self.risk_tier_required,
        };
        cap.validate()?;
        Ok(cap)
    }
}

/// Capability manifest containing sealed capability references.
///
/// Per AD-TOOL-002, the manifest:
/// - Contains the complete set of capabilities granted to an episode
/// - Is immutable once created
/// - Is referenced by hash in the episode envelope
/// - Expires at a specified time (optional)
///
/// # TCK-00254 Extensions
///
/// Per RFC-0017, the manifest includes allowlists for tool mediation:
/// - `tool_allowlist`: Allowed tool classes
/// - `write_allowlist`: Allowed filesystem write paths
/// - `shell_allowlist`: Allowed shell command patterns
///
/// # Security
///
/// Uses `deny_unknown_fields` to prevent field injection attacks when
/// deserializing from untrusted input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityManifest {
    /// Unique identifier for this manifest.
    pub manifest_id: String,

    /// The capabilities granted by this manifest.
    pub capabilities: Vec<Capability>,

    /// The actor ID that delegated these capabilities.
    pub delegator_id: String,

    /// When this manifest was created (Unix timestamp in seconds).
    pub created_at: u64,

    /// When this manifest expires (Unix timestamp in seconds).
    /// Zero means no expiration.
    pub expires_at: u64,

    /// Allowlist of tool classes that can be invoked.
    ///
    /// Per REQ-DCP-0002, tool requests are validated against this allowlist
    /// at the daemon layer. Empty means no tools allowed (fail-closed).
    #[serde(default)]
    pub tool_allowlist: Vec<ToolClass>,

    /// Allowlist of filesystem paths that can be written to.
    ///
    /// Per REQ-DCP-0002, write operations are validated against this allowlist.
    /// Paths should be absolute and normalized. Empty means no writes allowed.
    #[serde(default)]
    pub write_allowlist: Vec<PathBuf>,

    /// Allowlist of shell command patterns that can be executed.
    ///
    /// Per REQ-DCP-0002, shell execution requests are validated against this
    /// allowlist. Patterns may use glob syntax. Empty means no shell allowed.
    #[serde(default)]
    pub shell_allowlist: Vec<String>,
}

impl CapabilityManifest {
    /// Creates a builder for constructing a manifest.
    #[must_use]
    pub fn builder(manifest_id: impl Into<String>) -> CapabilityManifestBuilder {
        CapabilityManifestBuilder::new(manifest_id)
    }

    /// Validates the manifest structure.
    ///
    /// # Errors
    ///
    /// Returns an error if validation fails.
    pub fn validate(&self) -> Result<(), CapabilityError> {
        // Check ID lengths
        if self.manifest_id.is_empty() {
            return Err(CapabilityError::EmptyField {
                field: "manifest_id",
            });
        }
        if self.manifest_id.len() > MAX_MANIFEST_ID_LEN {
            return Err(CapabilityError::ManifestIdTooLong {
                len: self.manifest_id.len(),
                max: MAX_MANIFEST_ID_LEN,
            });
        }
        if self.delegator_id.is_empty() {
            return Err(CapabilityError::EmptyField {
                field: "delegator_id",
            });
        }
        if self.delegator_id.len() > MAX_ACTOR_ID_LEN {
            return Err(CapabilityError::ActorIdTooLong {
                len: self.delegator_id.len(),
                max: MAX_ACTOR_ID_LEN,
            });
        }

        // Check capability count (CTR-1303: bounded collections)
        if self.capabilities.len() > MAX_CAPABILITIES {
            return Err(CapabilityError::TooManyCapabilities {
                count: self.capabilities.len(),
                max: MAX_CAPABILITIES,
            });
        }

        // Validate each capability and check for duplicates
        let mut seen_ids = std::collections::HashSet::with_capacity(self.capabilities.len());
        for cap in &self.capabilities {
            cap.validate()?;
            if !seen_ids.insert(&cap.capability_id) {
                return Err(CapabilityError::DuplicateCapabilityId {
                    id: cap.capability_id.clone(),
                });
            }
        }

        // Validate allowlists (TCK-00254: CTR-1303 bounded collections)
        if self.tool_allowlist.len() > MAX_TOOL_ALLOWLIST {
            return Err(CapabilityError::TooManyToolAllowlistEntries {
                count: self.tool_allowlist.len(),
                max: MAX_TOOL_ALLOWLIST,
            });
        }

        if self.write_allowlist.len() > MAX_WRITE_ALLOWLIST {
            return Err(CapabilityError::TooManyWriteAllowlistEntries {
                count: self.write_allowlist.len(),
                max: MAX_WRITE_ALLOWLIST,
            });
        }

        // Validate write allowlist paths (TCK-00254: CTR-1503, CTR-2609)
        for path in &self.write_allowlist {
            let path_len = path.as_os_str().len();
            if path_len > super::scope::MAX_PATH_LEN {
                return Err(CapabilityError::WriteAllowlistPathTooLong {
                    len: path_len,
                    max: super::scope::MAX_PATH_LEN,
                });
            }

            // Per CTR-1503: Paths must be absolute
            if !path.is_absolute() {
                return Err(CapabilityError::WriteAllowlistPathNotAbsolute {
                    path: path.to_string_lossy().to_string(),
                });
            }

            // Per CTR-2609: Reject path traversal (..) to prevent directory escape
            // We check the path string representation for ".." components
            for component in path.components() {
                if matches!(component, std::path::Component::ParentDir) {
                    return Err(CapabilityError::WriteAllowlistPathTraversal {
                        path: path.to_string_lossy().to_string(),
                    });
                }
            }
        }

        if self.shell_allowlist.len() > MAX_SHELL_ALLOWLIST {
            return Err(CapabilityError::TooManyShellAllowlistEntries {
                count: self.shell_allowlist.len(),
                max: MAX_SHELL_ALLOWLIST,
            });
        }

        // Validate shell pattern lengths
        for pattern in &self.shell_allowlist {
            if pattern.len() > MAX_SHELL_PATTERN_LEN {
                return Err(CapabilityError::ShellPatternTooLong {
                    len: pattern.len(),
                    max: MAX_SHELL_PATTERN_LEN,
                });
            }
        }

        Ok(())
    }

    /// Returns `true` if this manifest has expired using the system clock.
    ///
    /// For deterministic testing, use [`Self::is_expired_with_clock`] instead.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.is_expired_with_clock(&SystemClock)
    }

    /// Returns `true` if this manifest has expired using the given clock.
    ///
    /// Per HOLONIC-BOUNDARY-001, this method accepts a clock for deterministic
    /// testing and auditing of expiration logic.
    ///
    /// # Arguments
    ///
    /// * `clock` - The clock to use for determining the current time
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use apm2_daemon::episode::capability::{CapabilityManifest, FixedClock};
    ///
    /// let manifest = /* create manifest with expires_at = 1000 */;
    ///
    /// // Test with a fixed clock before expiration
    /// let clock = FixedClock::new(500);
    /// assert!(!manifest.is_expired_with_clock(&clock));
    ///
    /// // Test with a fixed clock after expiration
    /// let clock = FixedClock::new(1500);
    /// assert!(manifest.is_expired_with_clock(&clock));
    /// ```
    #[must_use]
    pub fn is_expired_with_clock(&self, clock: &dyn Clock) -> bool {
        if self.expires_at == 0 {
            return false;
        }
        clock.now_secs() > self.expires_at
    }

    /// Returns `true` if this manifest has no capabilities.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.capabilities.is_empty()
    }

    /// Returns the number of capabilities in this manifest.
    #[must_use]
    pub fn len(&self) -> usize {
        self.capabilities.len()
    }

    /// Finds capabilities matching the given tool class.
    pub fn find_by_tool_class(&self, tool_class: ToolClass) -> impl Iterator<Item = &Capability> {
        self.capabilities
            .iter()
            .filter(move |c| c.tool_class == tool_class)
    }

    // =========================================================================
    // TCK-00254: Allowlist Enforcement Methods
    // =========================================================================

    /// Returns a reference to the tool allowlist.
    #[must_use]
    pub fn tool_allowlist(&self) -> &[ToolClass] {
        &self.tool_allowlist
    }

    /// Checks if the given tool class is in the tool allowlist.
    ///
    /// Per TCK-00254, returns `false` if the allowlist is empty (fail-closed).
    #[must_use]
    pub fn is_tool_allowed(&self, tool_class: ToolClass) -> bool {
        if self.tool_allowlist.is_empty() {
            // Fail-closed: empty allowlist means nothing is allowed
            return false;
        }
        self.tool_allowlist.contains(&tool_class)
    }

    /// Checks if the given path is in the write allowlist.
    ///
    /// Per TCK-00254, returns `false` if the allowlist is empty (fail-closed).
    /// The path must be a prefix match: `/workspace` allows `/workspace/foo`.
    #[must_use]
    pub fn is_write_path_allowed(&self, path: &Path) -> bool {
        if self.write_allowlist.is_empty() {
            // Fail-closed: empty allowlist means nothing is allowed
            return false;
        }

        // Check if the path starts with any allowed path
        self.write_allowlist.iter().any(|allowed| {
            // Use starts_with for prefix matching
            path.starts_with(allowed)
        })
    }

    /// Checks if the given shell command matches a pattern in the shell
    /// allowlist.
    ///
    /// Per TCK-00254, returns `false` if the allowlist is empty (fail-closed).
    /// Patterns use simple glob matching with `*` as wildcard.
    #[must_use]
    pub fn is_shell_command_allowed(&self, command: &str) -> bool {
        if self.shell_allowlist.is_empty() {
            // Fail-closed: empty allowlist means nothing is allowed
            return false;
        }

        // Check if the command matches any allowed pattern.
        // Uses the shared shell_pattern_matches function from apm2-core to
        // eliminate code duplication (Code Quality Review [MAJOR]).
        self.shell_allowlist
            .iter()
            .any(|pattern| shell_pattern_matches(pattern, command))
    }

    /// Validates a tool request against this manifest.
    ///
    /// This is the main entry point for capability validation. It checks:
    /// 1. Manifest expiration
    /// 2. TCK-00254: Tool allowlist enforcement
    /// 3. TCK-00254: Write allowlist enforcement (for Write operations)
    /// 4. TCK-00254: Shell allowlist enforcement (for Execute operations)
    /// 5. Matching tool class
    /// 6. Path containment (for filesystem operations)
    /// 7. Size limits
    /// 8. Network policy (for network operations)
    /// 9. Risk tier requirements
    ///
    /// # Arguments
    ///
    /// * `request` - The tool request to validate
    ///
    /// # Returns
    ///
    /// `CapabilityDecision::Allow` with the matching capability ID, or
    /// `CapabilityDecision::Deny` with the reason for denial.
    pub fn validate_request(&self, request: &ToolRequest) -> CapabilityDecision {
        // Check expiration first
        if self.is_expired() {
            return CapabilityDecision::Deny {
                reason: DenyReason::ManifestExpired,
            };
        }

        // Delegate to the internal validation logic
        self.validate_request_internal(request)
    }

    /// Validates a tool request with a custom clock for expiration checks.
    ///
    /// Per HOLONIC-BOUNDARY-001, this method accepts a clock for deterministic
    /// testing and auditing.
    pub fn validate_request_with_clock(
        &self,
        request: &ToolRequest,
        clock: &dyn Clock,
    ) -> CapabilityDecision {
        // Check expiration first using the provided clock
        if self.is_expired_with_clock(clock) {
            return CapabilityDecision::Deny {
                reason: DenyReason::ManifestExpired,
            };
        }

        // Delegate to the internal validation logic
        self.validate_request_internal(request)
    }

    /// Internal validation logic without expiration check.
    fn validate_request_internal(&self, request: &ToolRequest) -> CapabilityDecision {
        // TCK-00254: Check tool allowlist (fail-closed)
        if !self.is_tool_allowed(request.tool_class) {
            return CapabilityDecision::Deny {
                reason: DenyReason::ToolNotInAllowlist {
                    tool_class: request.tool_class,
                },
            };
        }

        // TCK-00254: Check write allowlist for Write operations (fail-closed)
        // SECURITY (SEC-SCP-FAC-0020): Always enforce write allowlist check for Write
        // operations. If the allowlist is empty, is_write_path_allowed returns false,
        // correctly implementing fail-closed semantics per DD-004.
        if request.tool_class == ToolClass::Write {
            match &request.path {
                Some(path) => {
                    if !self.is_write_path_allowed(path) {
                        return CapabilityDecision::Deny {
                            reason: DenyReason::WritePathNotInAllowlist {
                                path: path.to_string_lossy().to_string(),
                            },
                        };
                    }
                },
                None => {
                    // SECURITY: Fail-closed - Write requests must provide a path
                    return CapabilityDecision::Deny {
                        reason: DenyReason::WritePathRequired,
                    };
                },
            }
        }

        // TCK-00254: Check shell allowlist for Execute operations (fail-closed)
        // SECURITY (SEC-SCP-FAC-0020): Always enforce shell allowlist check for Execute
        // operations. If the allowlist is empty, is_shell_command_allowed returns
        // false, correctly implementing fail-closed semantics per DD-004.
        if request.tool_class == ToolClass::Execute {
            match &request.shell_command {
                Some(command) => {
                    if !self.is_shell_command_allowed(command) {
                        return CapabilityDecision::Deny {
                            reason: DenyReason::ShellCommandNotInAllowlist {
                                command: command.clone(),
                            },
                        };
                    }
                },
                None => {
                    // SECURITY: Fail-closed - Execute requests must provide a shell_command
                    return CapabilityDecision::Deny {
                        reason: DenyReason::ShellCommandRequired,
                    };
                },
            }
        }

        // Find capabilities matching the tool class
        let matching: Vec<_> = self.find_by_tool_class(request.tool_class).collect();

        if matching.is_empty() {
            return CapabilityDecision::Deny {
                reason: DenyReason::NoMatchingCapability {
                    tool_class: request.tool_class,
                },
            };
        }

        // Try each matching capability
        for cap in matching {
            // Check risk tier
            if !cap.risk_tier_sufficient(request.risk_tier) {
                continue;
            }

            // Check path if applicable
            if let Some(ref path) = request.path {
                if !cap.allows_path(path) {
                    continue;
                }
            }

            // Check size limits if applicable
            if let Some(size) = request.size {
                let size_allowed = match request.tool_class {
                    ToolClass::Read => cap.allows_read_size(size),
                    ToolClass::Write => cap.allows_write_size(size),
                    _ => true,
                };
                if !size_allowed {
                    continue;
                }
            }

            // Check network access if applicable
            if let Some((ref host, port)) = request.network {
                if !cap.allows_network(host, port) {
                    continue;
                }
            }

            // All checks passed
            return CapabilityDecision::Allow {
                capability_id: cap.capability_id.clone(),
            };
        }

        // No capability matched - determine best reason
        if let Some(ref path) = request.path {
            return CapabilityDecision::Deny {
                reason: DenyReason::PathNotAllowed {
                    path: path.to_string_lossy().to_string(),
                },
            };
        }

        if let Some((ref host, port)) = request.network {
            return CapabilityDecision::Deny {
                reason: DenyReason::NetworkNotAllowed {
                    host: host.clone(),
                    port,
                },
            };
        }

        // Fall back to risk tier reason
        if let Some(cap) = self.find_by_tool_class(request.tool_class).next() {
            return CapabilityDecision::Deny {
                reason: DenyReason::InsufficientRiskTier {
                    required: cap.risk_tier_required,
                    actual: request.risk_tier,
                },
            };
        }

        CapabilityDecision::Deny {
            reason: DenyReason::NoMatchingCapability {
                tool_class: request.tool_class,
            },
        }
    }

    /// Computes the BLAKE3 digest of this manifest.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let bytes = self.canonical_bytes();
        blake3::hash(&bytes).into()
    }
}

/// Internal protobuf representation for `CapabilityManifest`.
#[derive(Clone, PartialEq, Message)]
struct CapabilityManifestProto {
    #[prost(string, tag = "1")]
    manifest_id: String,
    #[prost(bytes = "vec", repeated, tag = "2")]
    capability_bytes: Vec<Vec<u8>>,
    #[prost(string, tag = "3")]
    delegator_id: String,
    #[prost(uint64, optional, tag = "4")]
    created_at: Option<u64>,
    #[prost(uint64, optional, tag = "5")]
    expires_at: Option<u64>,
    /// Sorted tool class values for deterministic serialization.
    #[prost(uint32, repeated, tag = "6")]
    tool_allowlist: Vec<u32>,
    /// Sorted write paths for deterministic serialization.
    #[prost(string, repeated, tag = "7")]
    write_allowlist: Vec<String>,
    /// Sorted shell patterns for deterministic serialization.
    #[prost(string, repeated, tag = "8")]
    shell_allowlist: Vec<String>,
}

impl CapabilityManifest {
    /// Returns the canonical bytes for this manifest.
    ///
    /// Per AD-VERIFY-001, capabilities and allowlists are sorted for
    /// determinism.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        // Sort capabilities by ID for deterministic ordering
        let mut sorted_caps: Vec<_> = self.capabilities.iter().collect();
        sorted_caps.sort_by(|a, b| a.capability_id.cmp(&b.capability_id));

        // Sort tool allowlist by value for determinism
        let mut sorted_tools: Vec<u32> = self
            .tool_allowlist
            .iter()
            .map(|t| u32::from(t.value()))
            .collect();
        sorted_tools.sort_unstable();

        // Sort write allowlist paths for determinism
        let mut sorted_write_paths: Vec<String> = self
            .write_allowlist
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect();
        sorted_write_paths.sort_unstable();

        // Sort shell allowlist for determinism
        let mut sorted_shell_patterns: Vec<String> = self.shell_allowlist.clone();
        sorted_shell_patterns.sort_unstable();

        let proto = CapabilityManifestProto {
            manifest_id: self.manifest_id.clone(),
            capability_bytes: sorted_caps.iter().map(|c| c.canonical_bytes()).collect(),
            delegator_id: self.delegator_id.clone(),
            created_at: Some(self.created_at),
            expires_at: Some(self.expires_at),
            tool_allowlist: sorted_tools,
            write_allowlist: sorted_write_paths,
            shell_allowlist: sorted_shell_patterns,
        };
        proto.encode_to_vec()
    }
}

/// Builder for `CapabilityManifest`.
#[derive(Debug, Clone)]
pub struct CapabilityManifestBuilder {
    manifest_id: String,
    capabilities: Vec<Capability>,
    delegator_id: String,
    created_at: u64,
    expires_at: u64,
    tool_allowlist: Vec<ToolClass>,
    write_allowlist: Vec<PathBuf>,
    shell_allowlist: Vec<String>,
}

impl CapabilityManifestBuilder {
    /// Creates a new builder.
    #[must_use]
    pub fn new(manifest_id: impl Into<String>) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        Self {
            manifest_id: manifest_id.into(),
            capabilities: Vec::new(),
            delegator_id: String::new(),
            created_at: now,
            expires_at: 0,
            tool_allowlist: Vec::new(),
            write_allowlist: Vec::new(),
            shell_allowlist: Vec::new(),
        }
    }

    /// Sets the delegator ID.
    #[must_use]
    pub fn delegator(mut self, id: impl Into<String>) -> Self {
        self.delegator_id = id.into();
        self
    }

    /// Adds a capability.
    #[must_use]
    pub fn capability(mut self, cap: Capability) -> Self {
        self.capabilities.push(cap);
        self
    }

    /// Sets the capabilities.
    #[must_use]
    pub fn capabilities(mut self, caps: Vec<Capability>) -> Self {
        self.capabilities = caps;
        self
    }

    /// Sets the creation timestamp.
    #[must_use]
    pub const fn created_at(mut self, timestamp: u64) -> Self {
        self.created_at = timestamp;
        self
    }

    /// Sets the expiration timestamp.
    #[must_use]
    pub const fn expires_at(mut self, timestamp: u64) -> Self {
        self.expires_at = timestamp;
        self
    }

    /// Sets expiration to a duration from now.
    #[must_use]
    pub fn expires_in(mut self, duration: Duration) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        self.expires_at = now + duration.as_secs();
        self
    }

    /// Sets the tool allowlist.
    ///
    /// Per REQ-DCP-0002, only tools in this allowlist can be invoked.
    #[must_use]
    pub fn tool_allowlist(mut self, tools: Vec<ToolClass>) -> Self {
        self.tool_allowlist = tools;
        self
    }

    /// Adds a tool class to the allowlist.
    #[must_use]
    pub fn allow_tool(mut self, tool: ToolClass) -> Self {
        self.tool_allowlist.push(tool);
        self
    }

    /// Sets the write path allowlist.
    ///
    /// Per REQ-DCP-0002, only paths in this allowlist can be written to.
    #[must_use]
    pub fn write_allowlist(mut self, paths: Vec<PathBuf>) -> Self {
        self.write_allowlist = paths;
        self
    }

    /// Adds a path to the write allowlist.
    #[must_use]
    pub fn allow_write_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.write_allowlist.push(path.into());
        self
    }

    /// Sets the shell pattern allowlist.
    ///
    /// Per REQ-DCP-0002, only commands matching patterns in this allowlist
    /// can be executed.
    #[must_use]
    pub fn shell_allowlist(mut self, patterns: Vec<String>) -> Self {
        self.shell_allowlist = patterns;
        self
    }

    /// Adds a shell pattern to the allowlist.
    #[must_use]
    pub fn allow_shell_pattern(mut self, pattern: impl Into<String>) -> Self {
        self.shell_allowlist.push(pattern.into());
        self
    }

    /// Builds the manifest.
    ///
    /// # Errors
    ///
    /// Returns an error if validation fails.
    ///
    /// # Implementation
    ///
    /// Allowlists are sorted during construction to ensure `PartialEq`
    /// consistency with `canonical_bytes()`. This prevents bugs in caching
    /// or deduplication where logically identical manifests would compare
    /// as different due to insertion order.
    pub fn build(mut self) -> Result<CapabilityManifest, CapabilityError> {
        // Sort allowlists for PartialEq consistency with canonical_bytes()
        self.tool_allowlist.sort_by_key(ToolClass::value);
        self.write_allowlist.sort();
        self.shell_allowlist.sort();

        let manifest = CapabilityManifest {
            manifest_id: self.manifest_id,
            capabilities: self.capabilities,
            delegator_id: self.delegator_id,
            created_at: self.created_at,
            expires_at: self.expires_at,
            tool_allowlist: self.tool_allowlist,
            write_allowlist: self.write_allowlist,
            shell_allowlist: self.shell_allowlist,
        };
        manifest.validate()?;
        Ok(manifest)
    }
}

/// Tool request for capability validation.
///
/// This is a simplified representation of a tool request used for
/// capability validation. It extracts the relevant fields from the
/// full protobuf `ToolRequest`.
#[derive(Debug, Clone)]
pub struct ToolRequest {
    /// The tool class being requested.
    pub tool_class: ToolClass,

    /// Optional path for filesystem operations.
    pub path: Option<std::path::PathBuf>,

    /// Optional size for read/write operations.
    pub size: Option<u64>,

    /// Optional network target (host, port).
    pub network: Option<(String, u16)>,

    /// Optional shell command for Execute operations.
    ///
    /// Per TCK-00254, this enables shell allowlist matching.
    /// When `tool_class` is Execute and `shell_allowlist` is configured,
    /// this command must match one of the allowed patterns.
    pub shell_command: Option<String>,

    /// The risk tier of the current episode.
    pub risk_tier: RiskTier,
}

impl ToolRequest {
    /// Creates a new tool request.
    #[must_use]
    pub const fn new(tool_class: ToolClass, risk_tier: RiskTier) -> Self {
        Self {
            tool_class,
            path: None,
            size: None,
            network: None,
            shell_command: None,
            risk_tier,
        }
    }

    /// Sets the path.
    #[must_use]
    pub fn with_path(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.path = Some(path.into());
        self
    }

    /// Sets the size.
    #[must_use]
    pub const fn with_size(mut self, size: u64) -> Self {
        self.size = Some(size);
        self
    }

    /// Sets the network target.
    #[must_use]
    pub fn with_network(mut self, host: impl Into<String>, port: u16) -> Self {
        self.network = Some((host.into(), port));
        self
    }

    /// Sets the shell command for Execute operations.
    ///
    /// Per TCK-00254, when `tool_class` is Execute, this command will be
    /// validated against the manifest's `shell_allowlist`.
    #[must_use]
    pub fn with_shell_command(mut self, command: impl Into<String>) -> Self {
        self.shell_command = Some(command.into());
        self
    }
}

/// Capability validator that wraps a manifest and provides validation.
///
/// Per AD-TOOL-002, the validator integrates with the policy engine
/// to provide OCAP enforcement.
///
/// Per HOLONIC-BOUNDARY-001, the validator supports clock injection for
/// deterministic testing of time-dependent operations.
#[derive(Debug, Clone)]
pub struct CapabilityValidator {
    manifest: CapabilityManifest,
}

impl CapabilityValidator {
    /// Creates a new validator with the given manifest using the system clock.
    ///
    /// For deterministic testing, use [`Self::new_with_clock`] instead.
    ///
    /// # Errors
    ///
    /// Returns an error if the manifest is invalid or expired.
    pub fn new(manifest: CapabilityManifest) -> Result<Self, CapabilityError> {
        Self::new_with_clock(manifest, &SystemClock)
    }

    /// Creates a new validator with the given manifest and clock.
    ///
    /// Per HOLONIC-BOUNDARY-001, this method accepts a clock for deterministic
    /// testing of expiration checks.
    ///
    /// # Errors
    ///
    /// Returns an error if the manifest is invalid or expired.
    pub fn new_with_clock(
        manifest: CapabilityManifest,
        clock: &dyn Clock,
    ) -> Result<Self, CapabilityError> {
        manifest.validate()?;
        if manifest.is_expired_with_clock(clock) {
            return Err(CapabilityError::ManifestExpired);
        }
        Ok(Self { manifest })
    }

    /// Returns a reference to the underlying manifest.
    #[must_use]
    pub const fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }

    /// Validates a tool request.
    #[must_use]
    pub fn validate(&self, request: &ToolRequest) -> CapabilityDecision {
        self.manifest.validate_request(request)
    }

    /// Validates a read request.
    #[must_use]
    pub fn validate_read(&self, path: &Path, size: u64, risk_tier: RiskTier) -> CapabilityDecision {
        let request = ToolRequest::new(ToolClass::Read, risk_tier)
            .with_path(path)
            .with_size(size);
        self.validate(&request)
    }

    /// Validates a write request.
    #[must_use]
    pub fn validate_write(
        &self,
        path: &Path,
        size: u64,
        risk_tier: RiskTier,
    ) -> CapabilityDecision {
        let request = ToolRequest::new(ToolClass::Write, risk_tier)
            .with_path(path)
            .with_size(size);
        self.validate(&request)
    }

    /// Validates an execute request.
    #[must_use]
    pub fn validate_execute(&self, risk_tier: RiskTier) -> CapabilityDecision {
        let request = ToolRequest::new(ToolClass::Execute, risk_tier);
        self.validate(&request)
    }

    /// Validates a network request.
    #[must_use]
    pub fn validate_network(
        &self,
        host: &str,
        port: u16,
        risk_tier: RiskTier,
    ) -> CapabilityDecision {
        let request =
            ToolRequest::new(ToolClass::Network, risk_tier).with_network(host.to_string(), port);
        self.validate(&request)
    }
}

// =============================================================================
// PolicyEngine Integration
//
// Per AD-TOOL-002 step 5, the capability validator integrates with the
// PolicyEngine from apm2_core for unified policy enforcement.
// =============================================================================

/// Error type for manifest loading operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestLoadError {
    /// Content not found in CAS.
    NotFound {
        /// The hash that was not found (hex-encoded).
        hash: String,
    },

    /// Hash mismatch during verification.
    HashMismatch {
        /// Expected hash (hex-encoded).
        expected: String,
        /// Actual hash (hex-encoded).
        actual: String,
    },

    /// Failed to deserialize manifest.
    DeserializationError {
        /// Description of the error.
        message: String,
    },

    /// Manifest validation failed.
    ValidationError(CapabilityError),

    /// CAS storage error.
    StorageError {
        /// Description of the error.
        message: String,
    },
}

impl std::fmt::Display for ManifestLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound { hash } => write!(f, "manifest not found: {hash}"),
            Self::HashMismatch { expected, actual } => {
                write!(f, "hash mismatch: expected {expected}, got {actual}")
            },
            Self::DeserializationError { message } => {
                write!(f, "deserialization failed: {message}")
            },
            Self::ValidationError(e) => write!(f, "validation failed: {e}"),
            Self::StorageError { message } => write!(f, "storage error: {message}"),
        }
    }
}

impl std::error::Error for ManifestLoadError {}

impl From<CapabilityError> for ManifestLoadError {
    fn from(e: CapabilityError) -> Self {
        Self::ValidationError(e)
    }
}

/// Trait for loading capability manifests from content-addressed storage.
///
/// Per AD-TOOL-002, capability manifests are referenced by their BLAKE3 hash
/// in episode envelopes. This trait defines the interface for loading
/// manifests from CAS.
///
/// # Implementation Notes
///
/// Implementations should:
/// 1. Retrieve the serialized manifest by hash from CAS
/// 2. Verify the content hash matches the requested hash
/// 3. Deserialize the manifest
/// 4. Validate the manifest structure
/// 5. Return the validated manifest
///
/// # Example
///
/// ```rust,ignore
/// use apm2_daemon::episode::capability::{ManifestLoader, CapabilityManifest};
///
/// struct MyCasLoader { /* ... */ }
///
/// impl ManifestLoader for MyCasLoader {
///     fn load_manifest(&self, hash: &[u8; 32]) -> Result<CapabilityManifest, ManifestLoadError> {
///         let bytes = self.cas.retrieve(hash)?;
///         let manifest: CapabilityManifest = serde_json::from_slice(&bytes)?;
///         manifest.validate()?;
///         Ok(manifest)
///     }
/// }
/// ```
pub trait ManifestLoader: Send + Sync {
    /// Loads a capability manifest by its content hash.
    ///
    /// # Arguments
    ///
    /// * `hash` - The BLAKE3 hash of the manifest content (32 bytes)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The hash is not found in storage
    /// - The content doesn't match the hash
    /// - Deserialization fails
    /// - Manifest validation fails
    fn load_manifest(&self, hash: &[u8; 32]) -> Result<CapabilityManifest, ManifestLoadError>;

    /// Stores a capability manifest and returns its content hash.
    ///
    /// # Arguments
    ///
    /// * `manifest` - The manifest to store
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Manifest validation fails
    /// - Storage operation fails
    fn store_manifest(&self, manifest: &CapabilityManifest) -> Result<[u8; 32], ManifestLoadError>;

    /// Checks if a manifest with the given hash exists.
    fn manifest_exists(&self, hash: &[u8; 32]) -> bool;
}

/// Policy-integrated capability validator.
///
/// Per AD-TOOL-002 step 5, this validator integrates with the `PolicyEngine`
/// from `apm2_core` to provide unified policy enforcement. The `PolicyEngine`
/// handles coarse-grained policy rules while the `CapabilityValidator` handles
/// fine-grained capability scoping.
///
/// # Architecture
///
/// ```text
/// ToolRequest
///     │
///     ├─────────────────────────────────┐
///     │                                 │
///     ▼                                 ▼
/// PolicyEngine                  CapabilityValidator
/// (coarse rules)                (fine scopes)
///     │                                 │
///     └─────────────────────────────────┘
///                     │
///                     ▼
///              Final Decision
///               (AND logic)
/// ```
///
/// # Security Model
///
/// Both checks must pass for a request to be allowed:
/// 1. `PolicyEngine` evaluates policy rules (`tool_allow`, filesystem, network,
///    etc.)
/// 2. `CapabilityValidator` evaluates capability scopes (paths, sizes,
///    patterns)
///
/// This provides defense-in-depth: even if a policy allows a broad category
/// of operations, capabilities can further restrict to specific paths/sizes.
///
/// # TODO: Full Integration
///
/// The `PolicyEngine` integration is defined as an interface here. Full
/// integration requires:
/// - TCK-XXXXX: Implement `PolicyEngine` adapter for `CapabilityValidator`
/// - TCK-XXXXX: Add `PolicyEngine`-based validation to `EpisodeRuntime`
#[derive(Debug, Clone)]
pub struct PolicyIntegratedValidator<L: ManifestLoader> {
    /// The capability validator for fine-grained scope checks.
    validator: CapabilityValidator,

    /// The manifest loader for CAS-based manifest retrieval.
    /// Note: Wrapped in Option for incremental integration.
    #[allow(dead_code)] // Reserved for future CAS integration
    loader: Option<std::sync::Arc<L>>,
}

impl<L: ManifestLoader> PolicyIntegratedValidator<L> {
    /// Creates a new policy-integrated validator.
    ///
    /// # Arguments
    ///
    /// * `manifest` - The capability manifest to validate against
    /// * `loader` - Optional manifest loader for CAS integration
    ///
    /// # Errors
    ///
    /// Returns an error if the manifest is invalid or expired.
    pub fn new(
        manifest: CapabilityManifest,
        loader: Option<std::sync::Arc<L>>,
    ) -> Result<Self, CapabilityError> {
        let validator = CapabilityValidator::new(manifest)?;
        Ok(Self { validator, loader })
    }

    /// Creates a validator by loading a manifest from CAS.
    ///
    /// # Arguments
    ///
    /// * `hash` - The BLAKE3 hash of the manifest
    /// * `loader` - The manifest loader to use
    ///
    /// # Errors
    ///
    /// Returns an error if loading or validation fails.
    pub fn from_hash(
        hash: &[u8; 32],
        loader: std::sync::Arc<L>,
    ) -> Result<Self, ManifestLoadError> {
        let manifest = loader.load_manifest(hash)?;
        let validator = CapabilityValidator::new(manifest)?;
        Ok(Self {
            validator,
            loader: Some(loader),
        })
    }

    /// Returns a reference to the underlying manifest.
    #[must_use]
    pub const fn manifest(&self) -> &CapabilityManifest {
        self.validator.manifest()
    }

    /// Validates a tool request against capability scopes.
    ///
    /// # Note
    ///
    /// This validates against capability scopes only. For full policy
    /// integration, use `validate_with_policy` (TODO: implement in future
    /// ticket).
    #[must_use]
    pub fn validate(&self, request: &ToolRequest) -> CapabilityDecision {
        self.validator.validate(request)
    }

    /// Validates a read request.
    #[must_use]
    pub fn validate_read(&self, path: &Path, size: u64, risk_tier: RiskTier) -> CapabilityDecision {
        self.validator.validate_read(path, size, risk_tier)
    }

    /// Validates a write request.
    #[must_use]
    pub fn validate_write(
        &self,
        path: &Path,
        size: u64,
        risk_tier: RiskTier,
    ) -> CapabilityDecision {
        self.validator.validate_write(path, size, risk_tier)
    }
}

/// Placeholder manifest loader that always returns `NotFound`.
///
/// This is used when CAS integration is not yet available. It will be
/// replaced with a real implementation in a future ticket.
///
/// # TODO
///
/// - TCK-XXXXX: Implement real CAS-backed `ManifestLoader`
#[derive(Debug, Clone, Default)]
pub struct StubManifestLoader;

impl ManifestLoader for StubManifestLoader {
    fn load_manifest(&self, hash: &[u8; 32]) -> Result<CapabilityManifest, ManifestLoadError> {
        Err(ManifestLoadError::NotFound {
            hash: hex::encode(hash),
        })
    }

    fn store_manifest(
        &self,
        _manifest: &CapabilityManifest,
    ) -> Result<[u8; 32], ManifestLoadError> {
        Err(ManifestLoadError::StorageError {
            message: "stub loader does not support storage".to_string(),
        })
    }

    fn manifest_exists(&self, _hash: &[u8; 32]) -> bool {
        false
    }
}

/// Convenience type alias for validators using the stub loader.
pub type BasicValidator = PolicyIntegratedValidator<StubManifestLoader>;

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn make_read_capability(id: &str, paths: Vec<PathBuf>) -> Capability {
        Capability {
            capability_id: id.to_string(),
            tool_class: ToolClass::Read,
            scope: CapabilityScope {
                root_paths: paths,
                allowed_patterns: Vec::new(),
                size_limits: super::super::scope::SizeLimits::default_limits(),
                network_policy: None,
            },
            risk_tier_required: RiskTier::Tier0,
        }
    }

    fn make_manifest(caps: Vec<Capability>) -> CapabilityManifest {
        // Collect tool classes from capabilities for the allowlist
        let tool_classes: Vec<ToolClass> = caps.iter().map(|c| c.tool_class).collect();
        CapabilityManifest::builder("test-manifest")
            .delegator("test-delegator")
            .capabilities(caps)
            .tool_allowlist(tool_classes)
            .build()
            .unwrap()
    }

    #[test]
    fn test_capability_validation() {
        let cap = make_read_capability("cap-1", vec![PathBuf::from("/workspace")]);
        assert!(cap.validate().is_ok());
    }

    #[test]
    fn test_capability_empty_id() {
        let cap = Capability {
            capability_id: String::new(),
            tool_class: ToolClass::Read,
            scope: CapabilityScope::default(),
            risk_tier_required: RiskTier::Tier0,
        };
        assert!(matches!(
            cap.validate(),
            Err(CapabilityError::EmptyField { .. })
        ));
    }

    #[test]
    fn test_manifest_validation() {
        let manifest = make_manifest(vec![make_read_capability(
            "cap-1",
            vec![PathBuf::from("/workspace")],
        )]);
        assert!(manifest.validate().is_ok());
    }

    #[test]
    fn test_manifest_duplicate_capability_id() {
        let result = CapabilityManifest::builder("test")
            .delegator("delegator")
            .capability(make_read_capability("dup", vec![PathBuf::from("/a")]))
            .capability(make_read_capability("dup", vec![PathBuf::from("/b")]))
            .build();
        assert!(matches!(
            result,
            Err(CapabilityError::DuplicateCapabilityId { .. })
        ));
    }

    #[test]
    fn test_manifest_too_many_capabilities() {
        let caps: Vec<_> = (0..=MAX_CAPABILITIES)
            .map(|i| make_read_capability(&format!("cap-{i}"), vec![PathBuf::from("/workspace")]))
            .collect();
        let result = CapabilityManifest::builder("test")
            .delegator("delegator")
            .capabilities(caps)
            .build();
        assert!(matches!(
            result,
            Err(CapabilityError::TooManyCapabilities { .. })
        ));
    }

    #[test]
    fn test_validate_request_allowed() {
        let manifest = make_manifest(vec![make_read_capability(
            "cap-1",
            vec![PathBuf::from("/workspace")],
        )]);

        let request = ToolRequest::new(ToolClass::Read, RiskTier::Tier0)
            .with_path("/workspace/file.rs")
            .with_size(1024);

        let decision = manifest.validate_request(&request);
        assert!(decision.is_allowed());
    }

    #[test]
    fn test_validate_request_denied_no_capability() {
        // Create manifest with Write in tool_allowlist but no Write capability
        // This tests the capability matching logic (not the tool allowlist)
        let manifest = CapabilityManifest::builder("test-manifest")
            .delegator("test-delegator")
            .capabilities(vec![make_read_capability(
                "cap-1",
                vec![PathBuf::from("/workspace")],
            )])
            .tool_allowlist(vec![ToolClass::Read, ToolClass::Write])
            .write_allowlist(vec![PathBuf::from("/workspace")])
            .build()
            .unwrap();

        let request =
            ToolRequest::new(ToolClass::Write, RiskTier::Tier0).with_path("/workspace/file.rs");

        let decision = manifest.validate_request(&request);
        assert!(decision.is_denied());
        if let CapabilityDecision::Deny { reason } = decision {
            assert!(matches!(reason, DenyReason::NoMatchingCapability { .. }));
        }
    }

    #[test]
    fn test_validate_request_denied_path_not_allowed() {
        let manifest = make_manifest(vec![make_read_capability(
            "cap-1",
            vec![PathBuf::from("/workspace")],
        )]);

        let request = ToolRequest::new(ToolClass::Read, RiskTier::Tier0).with_path("/etc/passwd");

        let decision = manifest.validate_request(&request);
        assert!(decision.is_denied());
        if let CapabilityDecision::Deny { reason } = decision {
            assert!(matches!(reason, DenyReason::PathNotAllowed { .. }));
        }
    }

    #[test]
    fn test_validate_request_denied_expired() {
        let manifest = CapabilityManifest {
            manifest_id: "test".to_string(),
            capabilities: vec![make_read_capability(
                "cap-1",
                vec![PathBuf::from("/workspace")],
            )],
            delegator_id: "delegator".to_string(),
            created_at: 0,
            expires_at: 1, // Expired in 1970
            tool_allowlist: Vec::new(),
            write_allowlist: Vec::new(),
            shell_allowlist: Vec::new(),
        };

        let request = ToolRequest::new(ToolClass::Read, RiskTier::Tier0);

        let decision = manifest.validate_request(&request);
        assert!(decision.is_denied());
        if let CapabilityDecision::Deny { reason } = decision {
            assert!(matches!(reason, DenyReason::ManifestExpired));
        }
    }

    #[test]
    fn test_canonical_bytes_determinism() {
        let manifest1 = CapabilityManifest {
            manifest_id: "test".to_string(),
            capabilities: vec![
                make_read_capability("b", vec![PathBuf::from("/b")]),
                make_read_capability("a", vec![PathBuf::from("/a")]),
            ],
            delegator_id: "delegator".to_string(),
            created_at: 1000,
            expires_at: 2000,
            tool_allowlist: Vec::new(),
            write_allowlist: Vec::new(),
            shell_allowlist: Vec::new(),
        };

        let manifest2 = CapabilityManifest {
            manifest_id: "test".to_string(),
            capabilities: vec![
                make_read_capability("a", vec![PathBuf::from("/a")]),
                make_read_capability("b", vec![PathBuf::from("/b")]),
            ],
            delegator_id: "delegator".to_string(),
            created_at: 1000,
            expires_at: 2000,
            tool_allowlist: Vec::new(),
            write_allowlist: Vec::new(),
            shell_allowlist: Vec::new(),
        };

        // Different order should produce same canonical bytes
        assert_eq!(manifest1.canonical_bytes(), manifest2.canonical_bytes());
        assert_eq!(manifest1.digest(), manifest2.digest());
    }

    #[test]
    fn test_capability_validator() {
        let manifest = make_manifest(vec![make_read_capability(
            "cap-1",
            vec![PathBuf::from("/workspace")],
        )]);

        let validator = CapabilityValidator::new(manifest).unwrap();

        let allowed =
            validator.validate_read(Path::new("/workspace/file.rs"), 1024, RiskTier::Tier0);
        assert!(allowed.is_allowed());

        let denied = validator.validate_read(Path::new("/etc/passwd"), 1024, RiskTier::Tier0);
        assert!(denied.is_denied());
    }

    #[test]
    fn test_risk_tier_enforcement() {
        let cap = Capability {
            capability_id: "high-risk".to_string(),
            tool_class: ToolClass::Execute,
            scope: CapabilityScope::allow_all(),
            risk_tier_required: RiskTier::Tier3,
        };

        // Create manifest with shell_allowlist to allow the test command
        let manifest = CapabilityManifest::builder("test-manifest")
            .delegator("test-delegator")
            .capability(cap)
            .tool_allowlist(vec![ToolClass::Execute])
            .shell_allowlist(vec!["test-cmd".to_string()])
            .build()
            .unwrap();

        // Tier 1 should be denied (insufficient risk tier)
        let request =
            ToolRequest::new(ToolClass::Execute, RiskTier::Tier1).with_shell_command("test-cmd");
        let decision = manifest.validate_request(&request);
        assert!(decision.is_denied());

        // Tier 3 should be allowed
        let request =
            ToolRequest::new(ToolClass::Execute, RiskTier::Tier3).with_shell_command("test-cmd");
        let decision = manifest.validate_request(&request);
        assert!(decision.is_allowed());

        // Tier 4 should also be allowed (higher than required)
        let request =
            ToolRequest::new(ToolClass::Execute, RiskTier::Tier4).with_shell_command("test-cmd");
        let decision = manifest.validate_request(&request);
        assert!(decision.is_allowed());
    }

    #[test]
    fn test_network_capability() {
        let cap = Capability {
            capability_id: "net".to_string(),
            tool_class: ToolClass::Network,
            scope: CapabilityScope {
                root_paths: Vec::new(),
                allowed_patterns: Vec::new(),
                size_limits: super::super::scope::SizeLimits::default_limits(),
                network_policy: Some(super::super::scope::NetworkPolicy {
                    allowed_hosts: vec!["*.example.com".to_string()],
                    allowed_ports: vec![443],
                    require_tls: true,
                }),
            },
            risk_tier_required: RiskTier::Tier0,
        };
        let manifest = make_manifest(vec![cap]);
        let validator = CapabilityValidator::new(manifest).unwrap();

        // Allowed host and port
        let allowed = validator.validate_network("api.example.com", 443, RiskTier::Tier0);
        assert!(allowed.is_allowed());

        // Wrong port
        let denied = validator.validate_network("api.example.com", 80, RiskTier::Tier0);
        assert!(denied.is_denied());

        // Wrong host
        let denied = validator.validate_network("evil.com", 443, RiskTier::Tier0);
        assert!(denied.is_denied());
    }

    // ==========================================================================
    // Clock Injection Tests (HOLONIC-BOUNDARY-001)
    //
    // These tests verify the clock abstraction for deterministic testing of
    // time-dependent operations like expiration checks.
    // ==========================================================================

    #[test]
    fn test_fixed_clock() {
        let clock = FixedClock::new(1000);
        assert_eq!(clock.now_secs(), 1000);

        let clock2 = FixedClock::new(2000);
        assert_eq!(clock2.now_secs(), 2000);
    }

    #[test]
    fn test_is_expired_with_clock_not_expired() {
        let manifest = CapabilityManifest {
            manifest_id: "test".to_string(),
            capabilities: vec![make_read_capability(
                "cap-1",
                vec![PathBuf::from("/workspace")],
            )],
            delegator_id: "delegator".to_string(),
            created_at: 1000,
            expires_at: 2000, // Expires at timestamp 2000
            tool_allowlist: Vec::new(),
            write_allowlist: Vec::new(),
            shell_allowlist: Vec::new(),
        };

        // Clock is before expiration
        let clock = FixedClock::new(1500);
        assert!(
            !manifest.is_expired_with_clock(&clock),
            "manifest should NOT be expired when clock is before expires_at"
        );
    }

    #[test]
    fn test_is_expired_with_clock_expired() {
        let manifest = CapabilityManifest {
            manifest_id: "test".to_string(),
            capabilities: vec![make_read_capability(
                "cap-1",
                vec![PathBuf::from("/workspace")],
            )],
            delegator_id: "delegator".to_string(),
            created_at: 1000,
            expires_at: 2000, // Expires at timestamp 2000
            tool_allowlist: Vec::new(),
            write_allowlist: Vec::new(),
            shell_allowlist: Vec::new(),
        };

        // Clock is after expiration
        let clock = FixedClock::new(2500);
        assert!(
            manifest.is_expired_with_clock(&clock),
            "manifest should be expired when clock is after expires_at"
        );
    }

    #[test]
    fn test_is_expired_with_clock_no_expiration() {
        let manifest = CapabilityManifest {
            manifest_id: "test".to_string(),
            capabilities: vec![make_read_capability(
                "cap-1",
                vec![PathBuf::from("/workspace")],
            )],
            delegator_id: "delegator".to_string(),
            created_at: 1000,
            expires_at: 0, // No expiration
            tool_allowlist: Vec::new(),
            write_allowlist: Vec::new(),
            shell_allowlist: Vec::new(),
        };

        // Should never expire regardless of clock
        let clock = FixedClock::new(u64::MAX);
        assert!(
            !manifest.is_expired_with_clock(&clock),
            "manifest with expires_at=0 should never expire"
        );
    }

    #[test]
    fn test_validator_new_with_clock() {
        let manifest = CapabilityManifest {
            manifest_id: "test".to_string(),
            capabilities: vec![make_read_capability(
                "cap-1",
                vec![PathBuf::from("/workspace")],
            )],
            delegator_id: "delegator".to_string(),
            created_at: 1000,
            expires_at: 2000,
            tool_allowlist: Vec::new(),
            write_allowlist: Vec::new(),
            shell_allowlist: Vec::new(),
        };

        // Should succeed with clock before expiration
        let clock = FixedClock::new(1500);
        let result = CapabilityValidator::new_with_clock(manifest.clone(), &clock);
        assert!(
            result.is_ok(),
            "validator should be created when manifest is not expired"
        );

        // Should fail with clock after expiration
        let clock = FixedClock::new(2500);
        let result = CapabilityValidator::new_with_clock(manifest, &clock);
        assert!(
            matches!(result, Err(CapabilityError::ManifestExpired)),
            "validator creation should fail for expired manifest"
        );
    }

    #[test]
    fn test_validate_request_with_clock() {
        let manifest = CapabilityManifest {
            manifest_id: "test".to_string(),
            capabilities: vec![make_read_capability(
                "cap-1",
                vec![PathBuf::from("/workspace")],
            )],
            delegator_id: "delegator".to_string(),
            created_at: 1000,
            expires_at: 2000,
            tool_allowlist: vec![ToolClass::Read],
            write_allowlist: Vec::new(),
            shell_allowlist: Vec::new(),
        };

        let request = ToolRequest::new(ToolClass::Read, RiskTier::Tier0)
            .with_path("/workspace/file.rs")
            .with_size(1024);

        // Should allow before expiration
        let clock = FixedClock::new(1500);
        let decision = manifest.validate_request_with_clock(&request, &clock);
        assert!(
            decision.is_allowed(),
            "request should be allowed before expiration"
        );

        // Should deny after expiration
        let clock = FixedClock::new(2500);
        let decision = manifest.validate_request_with_clock(&request, &clock);
        assert!(
            decision.is_denied(),
            "request should be denied after expiration"
        );
        if let CapabilityDecision::Deny { reason } = decision {
            assert!(
                matches!(reason, DenyReason::ManifestExpired),
                "denial reason should be ManifestExpired"
            );
        }
    }

    /// Regression test for [MAJOR] Non-deterministic `SystemTime` usage.
    ///
    /// Per HOLONIC-BOUNDARY-001, time-dependent operations should use
    /// injected clocks for deterministic testing and auditing.
    ///
    /// This test verifies that the clock abstraction provides deterministic
    /// behavior for expiration checks.
    #[test]
    fn test_clock_injection_determinism_regression() {
        // Create a manifest that expires at timestamp 1000
        let manifest = CapabilityManifest {
            manifest_id: "determinism-test".to_string(),
            capabilities: vec![make_read_capability("cap", vec![PathBuf::from("/test")])],
            delegator_id: "delegator".to_string(),
            created_at: 0,
            expires_at: 1000,
            tool_allowlist: Vec::new(),
            write_allowlist: Vec::new(),
            shell_allowlist: Vec::new(),
        };

        // Verify behavior is deterministic with fixed clock
        let before_expiry = FixedClock::new(999);
        let at_expiry = FixedClock::new(1000);
        let after_expiry = FixedClock::new(1001);

        // Before expiry: NOT expired
        assert!(
            !manifest.is_expired_with_clock(&before_expiry),
            "DETERMINISM: manifest must NOT be expired at timestamp 999"
        );

        // At expiry boundary: NOT expired (> check, not >=)
        assert!(
            !manifest.is_expired_with_clock(&at_expiry),
            "DETERMINISM: manifest must NOT be expired at timestamp 1000 (boundary)"
        );

        // After expiry: expired
        assert!(
            manifest.is_expired_with_clock(&after_expiry),
            "DETERMINISM: manifest MUST be expired at timestamp 1001"
        );

        // Run the same checks multiple times to verify determinism
        for _ in 0..100 {
            assert!(!manifest.is_expired_with_clock(&before_expiry));
            assert!(!manifest.is_expired_with_clock(&at_expiry));
            assert!(manifest.is_expired_with_clock(&after_expiry));
        }
    }

    // ==========================================================================
    // TCK-00254: Allowlist Tests
    //
    // Per REQ-DCP-0002, these tests verify the tool, write, and shell
    // allowlists for capability manifests.
    // ==========================================================================

    #[test]
    fn test_manifest_with_tool_allowlist() {
        let manifest = CapabilityManifest::builder("test-manifest")
            .delegator("test-delegator")
            .tool_allowlist(vec![ToolClass::Read, ToolClass::Write])
            .build()
            .unwrap();

        assert_eq!(manifest.tool_allowlist.len(), 2);
        assert!(manifest.tool_allowlist.contains(&ToolClass::Read));
        assert!(manifest.tool_allowlist.contains(&ToolClass::Write));
    }

    #[test]
    fn test_manifest_with_write_allowlist() {
        let manifest = CapabilityManifest::builder("test-manifest")
            .delegator("test-delegator")
            .write_allowlist(vec![
                PathBuf::from("/workspace/src"),
                PathBuf::from("/workspace/target"),
            ])
            .build()
            .unwrap();

        assert_eq!(manifest.write_allowlist.len(), 2);
        assert!(
            manifest
                .write_allowlist
                .contains(&PathBuf::from("/workspace/src"))
        );
    }

    #[test]
    fn test_manifest_with_shell_allowlist() {
        let manifest = CapabilityManifest::builder("test-manifest")
            .delegator("test-delegator")
            .shell_allowlist(vec!["cargo *".to_string(), "git status".to_string()])
            .build()
            .unwrap();

        assert_eq!(manifest.shell_allowlist.len(), 2);
        assert!(manifest.shell_allowlist.contains(&"cargo *".to_string()));
    }

    #[test]
    fn test_manifest_builder_allow_methods() {
        let manifest = CapabilityManifest::builder("test-manifest")
            .delegator("test-delegator")
            .allow_tool(ToolClass::Read)
            .allow_tool(ToolClass::Execute)
            .allow_write_path("/workspace")
            .allow_shell_pattern("npm *")
            .build()
            .unwrap();

        assert_eq!(manifest.tool_allowlist.len(), 2);
        assert_eq!(manifest.write_allowlist.len(), 1);
        assert_eq!(manifest.shell_allowlist.len(), 1);
    }

    #[test]
    fn test_manifest_tool_allowlist_too_large() {
        let tools: Vec<ToolClass> = (0..=MAX_TOOL_ALLOWLIST).map(|_| ToolClass::Read).collect();

        let result = CapabilityManifest::builder("test")
            .delegator("delegator")
            .tool_allowlist(tools)
            .build();

        assert!(matches!(
            result,
            Err(CapabilityError::TooManyToolAllowlistEntries { count, max })
            if count == MAX_TOOL_ALLOWLIST + 1 && max == MAX_TOOL_ALLOWLIST
        ));
    }

    #[test]
    fn test_manifest_write_allowlist_too_large() {
        let paths: Vec<PathBuf> = (0..=MAX_WRITE_ALLOWLIST)
            .map(|i| PathBuf::from(format!("/path/{i}")))
            .collect();

        let result = CapabilityManifest::builder("test")
            .delegator("delegator")
            .write_allowlist(paths)
            .build();

        assert!(matches!(
            result,
            Err(CapabilityError::TooManyWriteAllowlistEntries { count, max })
            if count == MAX_WRITE_ALLOWLIST + 1 && max == MAX_WRITE_ALLOWLIST
        ));
    }

    #[test]
    fn test_manifest_shell_allowlist_too_large() {
        let patterns: Vec<String> = (0..=MAX_SHELL_ALLOWLIST)
            .map(|i| format!("cmd{i}"))
            .collect();

        let result = CapabilityManifest::builder("test")
            .delegator("delegator")
            .shell_allowlist(patterns)
            .build();

        assert!(matches!(
            result,
            Err(CapabilityError::TooManyShellAllowlistEntries { count, max })
            if count == MAX_SHELL_ALLOWLIST + 1 && max == MAX_SHELL_ALLOWLIST
        ));
    }

    #[test]
    fn test_manifest_shell_pattern_too_long() {
        let long_pattern = "x".repeat(MAX_SHELL_PATTERN_LEN + 1);

        let result = CapabilityManifest::builder("test")
            .delegator("delegator")
            .shell_allowlist(vec![long_pattern])
            .build();

        assert!(matches!(
            result,
            Err(CapabilityError::ShellPatternTooLong { len, max })
            if len == MAX_SHELL_PATTERN_LEN + 1 && max == MAX_SHELL_PATTERN_LEN
        ));
    }

    #[test]
    fn test_manifest_write_path_too_long() {
        let long_path =
            PathBuf::from("/".to_string() + &"x".repeat(super::super::scope::MAX_PATH_LEN));

        let result = CapabilityManifest::builder("test")
            .delegator("delegator")
            .write_allowlist(vec![long_path])
            .build();

        assert!(matches!(
            result,
            Err(CapabilityError::WriteAllowlistPathTooLong { .. })
        ));
    }

    #[test]
    fn test_canonical_bytes_includes_allowlists() {
        let manifest1 = CapabilityManifest::builder("test")
            .delegator("delegator")
            .created_at(1000)
            .expires_at(2000)
            .tool_allowlist(vec![ToolClass::Read])
            .build()
            .unwrap();

        let manifest2 = CapabilityManifest::builder("test")
            .delegator("delegator")
            .created_at(1000)
            .expires_at(2000)
            .tool_allowlist(vec![ToolClass::Write])
            .build()
            .unwrap();

        // Different tool allowlists should produce different hashes
        assert_ne!(manifest1.canonical_bytes(), manifest2.canonical_bytes());
        assert_ne!(manifest1.digest(), manifest2.digest());
    }

    #[test]
    fn test_canonical_bytes_allowlist_order_determinism() {
        // Same allowlist items in different orders should produce same hash
        let manifest1 = CapabilityManifest::builder("test")
            .delegator("delegator")
            .created_at(1000)
            .expires_at(2000)
            .tool_allowlist(vec![ToolClass::Read, ToolClass::Write, ToolClass::Execute])
            .write_allowlist(vec![
                PathBuf::from("/b"),
                PathBuf::from("/a"),
                PathBuf::from("/c"),
            ])
            .shell_allowlist(vec!["z".to_string(), "a".to_string(), "m".to_string()])
            .build()
            .unwrap();

        let manifest2 = CapabilityManifest::builder("test")
            .delegator("delegator")
            .created_at(1000)
            .expires_at(2000)
            .tool_allowlist(vec![ToolClass::Execute, ToolClass::Read, ToolClass::Write])
            .write_allowlist(vec![
                PathBuf::from("/c"),
                PathBuf::from("/b"),
                PathBuf::from("/a"),
            ])
            .shell_allowlist(vec!["m".to_string(), "z".to_string(), "a".to_string()])
            .build()
            .unwrap();

        // Same content in different order should produce same hash (sorted before
        // hashing)
        assert_eq!(
            manifest1.canonical_bytes(),
            manifest2.canonical_bytes(),
            "canonical bytes should be deterministic regardless of allowlist order"
        );
        assert_eq!(
            manifest1.digest(),
            manifest2.digest(),
            "digest should be deterministic regardless of allowlist order"
        );
    }

    #[test]
    fn test_manifest_with_empty_allowlists_valid() {
        // Empty allowlists should be valid (fail-closed semantics)
        let manifest = CapabilityManifest::builder("test")
            .delegator("delegator")
            .build()
            .unwrap();

        assert!(manifest.tool_allowlist.is_empty());
        assert!(manifest.write_allowlist.is_empty());
        assert!(manifest.shell_allowlist.is_empty());
    }

    #[test]
    fn test_manifest_serde_roundtrip_with_allowlists() {
        let manifest = CapabilityManifest::builder("test-manifest")
            .delegator("test-delegator")
            .created_at(1000)
            .expires_at(2000)
            .tool_allowlist(vec![ToolClass::Read, ToolClass::Write])
            .write_allowlist(vec![PathBuf::from("/workspace")])
            .shell_allowlist(vec!["cargo *".to_string()])
            .build()
            .unwrap();

        // Serialize to JSON
        let json = serde_json::to_string(&manifest).unwrap();

        // Deserialize back
        let recovered: CapabilityManifest = serde_json::from_str(&json).unwrap();

        assert_eq!(manifest.tool_allowlist, recovered.tool_allowlist);
        assert_eq!(manifest.write_allowlist, recovered.write_allowlist);
        assert_eq!(manifest.shell_allowlist, recovered.shell_allowlist);
        assert_eq!(manifest.digest(), recovered.digest());
    }

    // ==========================================================================
    // TCK-00254: Allowlist Enforcement Tests
    //
    // Per Security Review, these tests verify the enforcement of
    // tool_allowlist, write_allowlist, and shell_allowlist.
    // ==========================================================================

    #[test]
    fn test_tool_allowlist_enforcement_allowed() {
        let manifest = CapabilityManifest::builder("test")
            .delegator("delegator")
            .tool_allowlist(vec![ToolClass::Read, ToolClass::Write])
            .capability(make_read_capability(
                "cap-1",
                vec![PathBuf::from("/workspace")],
            ))
            .allow_write_path("/workspace")
            .build()
            .unwrap();

        // Read is in the allowlist
        assert!(manifest.is_tool_allowed(ToolClass::Read));
        assert!(manifest.is_tool_allowed(ToolClass::Write));

        // Execute is not in the allowlist
        assert!(!manifest.is_tool_allowed(ToolClass::Execute));
    }

    #[test]
    fn test_tool_allowlist_enforcement_empty_is_fail_closed() {
        let manifest = CapabilityManifest::builder("test")
            .delegator("delegator")
            // No tool_allowlist set - empty
            .capability(make_read_capability("cap-1", vec![PathBuf::from("/workspace")]))
            .build()
            .unwrap();

        // Empty allowlist means nothing is allowed (fail-closed)
        assert!(!manifest.is_tool_allowed(ToolClass::Read));
        assert!(!manifest.is_tool_allowed(ToolClass::Write));
        assert!(!manifest.is_tool_allowed(ToolClass::Execute));
    }

    #[test]
    fn test_tool_allowlist_enforcement_in_validate_request() {
        let manifest = CapabilityManifest::builder("test")
            .delegator("delegator")
            .tool_allowlist(vec![ToolClass::Read])
            .capability(make_read_capability(
                "cap-1",
                vec![PathBuf::from("/workspace")],
            ))
            .build()
            .unwrap();

        // Read is allowed
        let request =
            ToolRequest::new(ToolClass::Read, RiskTier::Tier0).with_path("/workspace/file.rs");
        let decision = manifest.validate_request(&request);
        assert!(decision.is_allowed());

        // Write is not in tool_allowlist
        let request =
            ToolRequest::new(ToolClass::Write, RiskTier::Tier0).with_path("/workspace/file.rs");
        let decision = manifest.validate_request(&request);
        assert!(decision.is_denied());
        if let CapabilityDecision::Deny { reason } = decision {
            assert!(matches!(reason, DenyReason::ToolNotInAllowlist { .. }));
        }
    }

    #[test]
    fn test_write_allowlist_enforcement_allowed() {
        let manifest = CapabilityManifest::builder("test")
            .delegator("delegator")
            .write_allowlist(vec![
                PathBuf::from("/workspace"),
                PathBuf::from("/tmp/build"),
            ])
            .build()
            .unwrap();

        // Exact match
        assert!(manifest.is_write_path_allowed(Path::new("/workspace")));
        // Subdirectory is allowed (prefix match)
        assert!(manifest.is_write_path_allowed(Path::new("/workspace/src/main.rs")));
        assert!(manifest.is_write_path_allowed(Path::new("/tmp/build/output.o")));

        // Outside allowed paths
        assert!(!manifest.is_write_path_allowed(Path::new("/etc/passwd")));
        assert!(!manifest.is_write_path_allowed(Path::new("/home/user")));
    }

    #[test]
    fn test_write_allowlist_enforcement_empty_is_fail_closed() {
        let manifest = CapabilityManifest::builder("test")
            .delegator("delegator")
            // No write_allowlist set - empty
            .build()
            .unwrap();

        // Empty allowlist means nothing is allowed
        assert!(!manifest.is_write_path_allowed(Path::new("/workspace")));
        assert!(!manifest.is_write_path_allowed(Path::new("/tmp")));
    }

    #[test]
    fn test_write_allowlist_enforcement_in_validate_request() {
        // Create write capability
        let write_cap = Capability {
            capability_id: "write-cap".to_string(),
            tool_class: ToolClass::Write,
            scope: CapabilityScope {
                root_paths: vec![PathBuf::from("/workspace")],
                allowed_patterns: Vec::new(),
                size_limits: super::super::scope::SizeLimits::default_limits(),
                network_policy: None,
            },
            risk_tier_required: RiskTier::Tier0,
        };

        let manifest = CapabilityManifest::builder("test")
            .delegator("delegator")
            .tool_allowlist(vec![ToolClass::Write])
            .write_allowlist(vec![PathBuf::from("/workspace")])
            .capability(write_cap)
            .build()
            .unwrap();

        // Write to allowed path
        let request =
            ToolRequest::new(ToolClass::Write, RiskTier::Tier0).with_path("/workspace/file.rs");
        let decision = manifest.validate_request(&request);
        assert!(decision.is_allowed());

        // Write to disallowed path
        let request = ToolRequest::new(ToolClass::Write, RiskTier::Tier0).with_path("/etc/passwd");
        let decision = manifest.validate_request(&request);
        assert!(decision.is_denied());
        if let CapabilityDecision::Deny { reason } = decision {
            assert!(matches!(reason, DenyReason::WritePathNotInAllowlist { .. }));
        }
    }

    #[test]
    fn test_shell_allowlist_enforcement_allowed() {
        let manifest = CapabilityManifest::builder("test")
            .delegator("delegator")
            .shell_allowlist(vec![
                "cargo *".to_string(),
                "git status".to_string(),
                "npm run *".to_string(),
            ])
            .build()
            .unwrap();

        // Wildcard matching
        assert!(manifest.is_shell_command_allowed("cargo build"));
        assert!(manifest.is_shell_command_allowed("cargo test --release"));
        // Exact match
        assert!(manifest.is_shell_command_allowed("git status"));
        // Wildcard at end
        assert!(manifest.is_shell_command_allowed("npm run test"));

        // Not allowed
        assert!(!manifest.is_shell_command_allowed("rm -rf /"));
        assert!(!manifest.is_shell_command_allowed("git push"));
    }

    #[test]
    fn test_shell_allowlist_enforcement_empty_is_fail_closed() {
        let manifest = CapabilityManifest::builder("test")
            .delegator("delegator")
            // No shell_allowlist set - empty
            .build()
            .unwrap();

        // Empty allowlist means nothing is allowed
        assert!(!manifest.is_shell_command_allowed("ls"));
        assert!(!manifest.is_shell_command_allowed("cargo build"));
    }

    #[test]
    fn test_shell_allowlist_enforcement_in_validate_request() {
        // Create execute capability
        let exec_cap = Capability {
            capability_id: "exec-cap".to_string(),
            tool_class: ToolClass::Execute,
            scope: CapabilityScope::allow_all(),
            risk_tier_required: RiskTier::Tier0,
        };

        let manifest = CapabilityManifest::builder("test")
            .delegator("delegator")
            .tool_allowlist(vec![ToolClass::Execute])
            .shell_allowlist(vec!["cargo *".to_string()])
            .capability(exec_cap)
            .build()
            .unwrap();

        // Allowed shell command
        let request =
            ToolRequest::new(ToolClass::Execute, RiskTier::Tier0).with_shell_command("cargo build");
        let decision = manifest.validate_request(&request);
        assert!(decision.is_allowed());

        // Disallowed shell command
        let request =
            ToolRequest::new(ToolClass::Execute, RiskTier::Tier0).with_shell_command("rm -rf /");
        let decision = manifest.validate_request(&request);
        assert!(decision.is_denied());
        if let CapabilityDecision::Deny { reason } = decision {
            assert!(matches!(
                reason,
                DenyReason::ShellCommandNotInAllowlist { .. }
            ));
        }
    }

    #[test]
    fn test_shell_pattern_matching_various_patterns() {
        // Exact match
        assert!(shell_pattern_matches("ls", "ls"));
        assert!(!shell_pattern_matches("ls", "ls -la"));

        // Wildcard at end
        assert!(shell_pattern_matches("cargo *", "cargo build"));
        assert!(shell_pattern_matches("cargo *", "cargo test --release"));
        assert!(!shell_pattern_matches("cargo *", "npm run"));

        // Wildcard at start
        assert!(shell_pattern_matches("* --version", "cargo --version"));
        assert!(shell_pattern_matches("* --version", "node --version"));

        // Wildcard in middle
        assert!(shell_pattern_matches("git * --amend", "git commit --amend"));

        // Multiple wildcards
        assert!(shell_pattern_matches("*cargo*", "run cargo build"));
        assert!(shell_pattern_matches(
            "git * * -m *",
            "git commit -a -m test"
        ));
    }

    #[test]
    fn test_write_allowlist_path_validation_not_absolute() {
        let result = CapabilityManifest::builder("test")
            .delegator("delegator")
            .write_allowlist(vec![PathBuf::from("relative/path")])
            .build();

        assert!(matches!(
            result,
            Err(CapabilityError::WriteAllowlistPathNotAbsolute { .. })
        ));
    }

    #[test]
    fn test_write_allowlist_path_validation_traversal() {
        let result = CapabilityManifest::builder("test")
            .delegator("delegator")
            .write_allowlist(vec![PathBuf::from("/workspace/../etc")])
            .build();

        assert!(matches!(
            result,
            Err(CapabilityError::WriteAllowlistPathTraversal { .. })
        ));
    }

    #[test]
    fn test_write_allowlist_path_validation_traversal_middle() {
        let result = CapabilityManifest::builder("test")
            .delegator("delegator")
            .write_allowlist(vec![PathBuf::from("/workspace/foo/../bar")])
            .build();

        assert!(matches!(
            result,
            Err(CapabilityError::WriteAllowlistPathTraversal { .. })
        ));
    }

    #[test]
    fn test_tool_request_with_shell_command() {
        let request =
            ToolRequest::new(ToolClass::Execute, RiskTier::Tier0).with_shell_command("cargo build");

        assert_eq!(request.shell_command, Some("cargo build".to_string()));
        assert_eq!(request.tool_class, ToolClass::Execute);
    }

    // =========================================================================
    // TCK-00254: Fail-Closed Semantics Tests
    // =========================================================================

    #[test]
    fn test_execute_without_shell_command_when_allowlist_configured_is_denied() {
        // Create execute capability with shell_allowlist configured
        let exec_cap = Capability {
            capability_id: "exec-cap".to_string(),
            tool_class: ToolClass::Execute,
            scope: CapabilityScope::allow_all(),
            risk_tier_required: RiskTier::Tier0,
        };

        let manifest = CapabilityManifest::builder("test")
            .delegator("delegator")
            .tool_allowlist(vec![ToolClass::Execute])
            .shell_allowlist(vec!["cargo *".to_string()])
            .capability(exec_cap)
            .build()
            .unwrap();

        // Execute request WITHOUT shell_command should be DENIED
        // (fail-closed: missing required field when allowlist is configured)
        let request = ToolRequest::new(ToolClass::Execute, RiskTier::Tier0);
        let decision = manifest.validate_request(&request);

        assert!(decision.is_denied());
        if let CapabilityDecision::Deny { reason } = decision {
            assert!(
                matches!(reason, DenyReason::ShellCommandRequired),
                "expected ShellCommandRequired, got {reason:?}"
            );
        }
    }

    #[test]
    fn test_execute_without_shell_command_when_no_allowlist_is_denied() {
        // SEC-SCP-FAC-0020: Empty shell_allowlist means fail-closed
        // Create execute capability WITHOUT shell_allowlist
        let exec_cap = Capability {
            capability_id: "exec-cap".to_string(),
            tool_class: ToolClass::Execute,
            scope: CapabilityScope::allow_all(),
            risk_tier_required: RiskTier::Tier0,
        };

        let manifest = CapabilityManifest::builder("test")
            .delegator("delegator")
            .tool_allowlist(vec![ToolClass::Execute])
            // No shell_allowlist configured - empty means fail-closed
            .capability(exec_cap)
            .build()
            .unwrap();

        // Execute request WITHOUT shell_command should be DENIED
        // (empty allowlist means nothing is allowed - fail-closed per DD-004)
        let request = ToolRequest::new(ToolClass::Execute, RiskTier::Tier0);
        let decision = manifest.validate_request(&request);

        assert!(decision.is_denied());
        assert!(matches!(
            decision,
            CapabilityDecision::Deny {
                reason: DenyReason::ShellCommandRequired
            }
        ));
    }

    #[test]
    fn test_write_without_path_when_allowlist_configured_is_denied() {
        // Create write capability with write_allowlist configured
        let write_cap = Capability {
            capability_id: "write-cap".to_string(),
            tool_class: ToolClass::Write,
            scope: CapabilityScope::allow_all(),
            risk_tier_required: RiskTier::Tier0,
        };

        let manifest = CapabilityManifest::builder("test")
            .delegator("delegator")
            .tool_allowlist(vec![ToolClass::Write])
            .write_allowlist(vec![PathBuf::from("/workspace")])
            .capability(write_cap)
            .build()
            .unwrap();

        // Write request WITHOUT path should be DENIED
        // (fail-closed: missing required field when allowlist is configured)
        let request = ToolRequest::new(ToolClass::Write, RiskTier::Tier0);
        let decision = manifest.validate_request(&request);

        assert!(decision.is_denied());
        if let CapabilityDecision::Deny { reason } = decision {
            assert!(
                matches!(reason, DenyReason::WritePathRequired),
                "expected WritePathRequired, got {reason:?}"
            );
        }
    }

    #[test]
    fn test_write_without_path_when_no_allowlist_is_denied() {
        // SEC-SCP-FAC-0020: Empty write_allowlist means fail-closed
        // Create write capability WITHOUT write_allowlist
        let write_cap = Capability {
            capability_id: "write-cap".to_string(),
            tool_class: ToolClass::Write,
            scope: CapabilityScope::allow_all(),
            risk_tier_required: RiskTier::Tier0,
        };

        let manifest = CapabilityManifest::builder("test")
            .delegator("delegator")
            .tool_allowlist(vec![ToolClass::Write])
            // No write_allowlist configured - empty means fail-closed
            .capability(write_cap)
            .build()
            .unwrap();

        // Write request WITHOUT path should be DENIED
        // (empty allowlist means nothing is allowed - fail-closed per DD-004)
        let request = ToolRequest::new(ToolClass::Write, RiskTier::Tier0);
        let decision = manifest.validate_request(&request);

        assert!(decision.is_denied());
        assert!(matches!(
            decision,
            CapabilityDecision::Deny {
                reason: DenyReason::WritePathRequired
            }
        ));
    }
}

// =============================================================================
// TCK-00258: Custody Domain Validation (SoD Enforcement)
// =============================================================================

/// Maximum number of custody domains per validation request.
///
/// Per `CTR-1303`, we bound the number of domains to prevent `DoS` via resource
/// exhaustion.
pub const MAX_CUSTODY_DOMAINS_PER_REQUEST: usize = 256;

/// A custody domain identifier.
///
/// Custody domains represent organizational boundaries for key management
/// and conflict-of-interest detection. Keys within the same custody domain
/// share a COI group identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CustodyDomainId(String);

impl CustodyDomainId {
    /// Creates a new custody domain ID.
    ///
    /// # Arguments
    ///
    /// * `id` - The domain identifier string
    ///
    /// # Validation
    ///
    /// The ID must not be empty and must not exceed 256 characters.
    pub fn new(id: impl Into<String>) -> Result<Self, CapabilityError> {
        let id = id.into();
        if id.is_empty() {
            return Err(CapabilityError::EmptyField {
                field: "custody_domain_id",
            });
        }
        if id.len() > MAX_ACTOR_ID_LEN {
            return Err(CapabilityError::ActorIdTooLong {
                len: id.len(),
                max: MAX_ACTOR_ID_LEN,
            });
        }
        Ok(Self(id))
    }

    /// Returns the domain ID as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for CustodyDomainId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for CustodyDomainId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Error type for custody domain validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CustodyDomainError {
    /// Custody domain overlap detected (`SoD` violation).
    Overlap {
        /// The executor's custody domain.
        executor_domain: String,
        /// The author's custody domain that overlaps.
        author_domain: String,
    },

    /// Too many custody domains provided.
    TooManyDomains {
        /// Actual count.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Invalid custody domain ID.
    InvalidDomainId {
        /// The invalid domain ID.
        domain_id: String,
        /// Reason for rejection.
        reason: String,
    },
}

impl std::fmt::Display for CustodyDomainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Overlap {
                executor_domain,
                author_domain,
            } => write!(
                f,
                "custody domain overlap: executor '{executor_domain}' overlaps with author '{author_domain}'"
            ),
            Self::TooManyDomains { count, max } => {
                write!(f, "too many custody domains: {count} (max {max})")
            },
            Self::InvalidDomainId { domain_id, reason } => {
                write!(f, "invalid custody domain ID '{domain_id}': {reason}")
            },
        }
    }
}

impl std::error::Error for CustodyDomainError {}

/// Validates that executor custody domains do not overlap with author custody
/// domains.
///
/// Per REQ-DCP-0006, this function enforces Separation of Duties (`SoD`) by
/// rejecting spawn requests where the executor could be reviewing their own
/// work (self-review attack prevention).
///
/// # Arguments
///
/// * `executor_domains` - Custody domains associated with the executor
/// * `author_domains` - Custody domains associated with the changeset authors
///
/// # Returns
///
/// `Ok(())` if there is no overlap (spawn allowed), or
/// `Err(CustodyDomainError::Overlap)` if overlap is detected.
///
/// # Security
///
/// - Uses constant-time comparison to prevent timing side-channel attacks
/// - Bounds input sizes to prevent `DoS` via resource exhaustion
/// - Returns early on first overlap detected (fail-fast for security)
///
/// # Example
///
/// ```rust
/// use apm2_daemon::episode::capability::{
///     CustodyDomainId, validate_custody_domain_overlap,
/// };
///
/// let executor = vec![CustodyDomainId::new("team-review").unwrap()];
/// let authors = vec![CustodyDomainId::new("team-dev").unwrap()];
///
/// // Non-overlapping domains: allowed
/// assert!(validate_custody_domain_overlap(&executor, &authors).is_ok());
///
/// let executor = vec![CustodyDomainId::new("team-alpha").unwrap()];
/// let authors = vec![CustodyDomainId::new("team-alpha").unwrap()];
///
/// // Overlapping domains: denied
/// assert!(validate_custody_domain_overlap(&executor, &authors).is_err());
/// ```
pub fn validate_custody_domain_overlap(
    executor_domains: &[CustodyDomainId],
    author_domains: &[CustodyDomainId],
) -> Result<(), CustodyDomainError> {
    use subtle::ConstantTimeEq;

    // CTR-1303: Bound input sizes to prevent DoS
    if executor_domains.len() > MAX_CUSTODY_DOMAINS_PER_REQUEST {
        return Err(CustodyDomainError::TooManyDomains {
            count: executor_domains.len(),
            max: MAX_CUSTODY_DOMAINS_PER_REQUEST,
        });
    }
    if author_domains.len() > MAX_CUSTODY_DOMAINS_PER_REQUEST {
        return Err(CustodyDomainError::TooManyDomains {
            count: author_domains.len(),
            max: MAX_CUSTODY_DOMAINS_PER_REQUEST,
        });
    }

    // Check for any overlap between executor and author domains
    // Uses constant-time comparison to prevent timing attacks (RSK-1909)
    for executor_domain in executor_domains {
        for author_domain in author_domains {
            let exec_bytes = executor_domain.as_str().as_bytes();
            let author_bytes = author_domain.as_str().as_bytes();

            // For constant-time comparison, we need equal-length inputs
            // If lengths differ, they can't be equal
            if exec_bytes.len() == author_bytes.len() && bool::from(exec_bytes.ct_eq(author_bytes))
            {
                return Err(CustodyDomainError::Overlap {
                    executor_domain: executor_domain.as_str().to_string(),
                    author_domain: author_domain.as_str().to_string(),
                });
            }
        }
    }

    Ok(())
}

/// Extracts custody domains from a list of actor IDs using a domain resolver.
///
/// Per REQ-DCP-0006, this helper function maps actor IDs to their associated
/// custody domains for `SoD` validation.
///
/// # Arguments
///
/// * `actor_ids` - List of actor identifiers to resolve
/// * `resolver` - Function that maps an actor ID to its custody domains
///
/// # Returns
///
/// A deduplicated list of custody domains associated with the actors.
///
/// # Example
///
/// ```rust
/// use std::collections::HashMap;
///
/// use apm2_daemon::episode::capability::{
///     CustodyDomainId, extract_custody_domains,
/// };
///
/// // Mock resolver: maps actor_id -> domains
/// let domain_map: HashMap<&str, Vec<&str>> =
///     [("alice", vec!["team-alpha"]), ("bob", vec!["team-beta"])]
///         .into_iter()
///         .collect();
///
/// let resolver = |actor_id: &str| -> Vec<CustodyDomainId> {
///     domain_map
///         .get(actor_id)
///         .map(|domains| {
///             domains
///                 .iter()
///                 .filter_map(|d| CustodyDomainId::new(*d).ok())
///                 .collect()
///         })
///         .unwrap_or_default()
/// };
///
/// let actors = vec!["alice".to_string(), "bob".to_string()];
/// let domains = extract_custody_domains(&actors, resolver);
/// assert_eq!(domains.len(), 2);
/// ```
pub fn extract_custody_domains<F>(actor_ids: &[String], resolver: F) -> Vec<CustodyDomainId>
where
    F: Fn(&str) -> Vec<CustodyDomainId>,
{
    use std::collections::HashSet;

    let mut seen = HashSet::new();
    let mut domains = Vec::new();

    for actor_id in actor_ids {
        for domain in resolver(actor_id) {
            // Deduplicate by domain ID string
            if seen.insert(domain.as_str().to_string()) {
                domains.push(domain);
            }
        }
    }

    domains
}

#[cfg(test)]
mod custody_domain_tests {
    use super::*;

    #[test]
    fn test_custody_domain_id_valid() {
        let domain = CustodyDomainId::new("team-alpha").unwrap();
        assert_eq!(domain.as_str(), "team-alpha");
        assert_eq!(format!("{domain}"), "team-alpha");
    }

    #[test]
    fn test_custody_domain_id_empty_rejected() {
        let result = CustodyDomainId::new("");
        assert!(matches!(result, Err(CapabilityError::EmptyField { .. })));
    }

    #[test]
    fn test_custody_domain_id_too_long_rejected() {
        let long_id = "x".repeat(MAX_ACTOR_ID_LEN + 1);
        let result = CustodyDomainId::new(long_id);
        assert!(matches!(
            result,
            Err(CapabilityError::ActorIdTooLong { .. })
        ));
    }

    #[test]
    fn test_validate_non_overlapping_domains() {
        let executor = vec![CustodyDomainId::new("team-review").unwrap()];
        let authors = vec![CustodyDomainId::new("team-dev").unwrap()];

        let result = validate_custody_domain_overlap(&executor, &authors);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_overlapping_domains() {
        let executor = vec![CustodyDomainId::new("team-alpha").unwrap()];
        let authors = vec![CustodyDomainId::new("team-alpha").unwrap()];

        let result = validate_custody_domain_overlap(&executor, &authors);
        assert!(matches!(result, Err(CustodyDomainError::Overlap { .. })));

        if let Err(CustodyDomainError::Overlap {
            executor_domain,
            author_domain,
        }) = result
        {
            assert_eq!(executor_domain, "team-alpha");
            assert_eq!(author_domain, "team-alpha");
        }
    }

    #[test]
    fn test_validate_multiple_domains_with_overlap() {
        // Executor has multiple domains, one overlaps with author
        let executor = vec![
            CustodyDomainId::new("team-review").unwrap(),
            CustodyDomainId::new("team-alpha").unwrap(),
        ];
        let authors = vec![
            CustodyDomainId::new("team-alpha").unwrap(),
            CustodyDomainId::new("team-beta").unwrap(),
        ];

        let result = validate_custody_domain_overlap(&executor, &authors);
        assert!(matches!(
            result,
            Err(CustodyDomainError::Overlap {
                executor_domain,
                author_domain,
            }) if executor_domain == "team-alpha" && author_domain == "team-alpha"
        ));
    }

    #[test]
    fn test_validate_multiple_domains_no_overlap() {
        let executor = vec![
            CustodyDomainId::new("team-review").unwrap(),
            CustodyDomainId::new("team-ops").unwrap(),
        ];
        let authors = vec![
            CustodyDomainId::new("team-dev").unwrap(),
            CustodyDomainId::new("team-qa").unwrap(),
        ];

        let result = validate_custody_domain_overlap(&executor, &authors);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_empty_executor_domains() {
        // Empty executor domains should pass (no overlap possible)
        let executor: Vec<CustodyDomainId> = vec![];
        let authors = vec![CustodyDomainId::new("team-alpha").unwrap()];

        let result = validate_custody_domain_overlap(&executor, &authors);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_empty_author_domains() {
        // Empty author domains should pass (no overlap possible)
        let executor = vec![CustodyDomainId::new("team-alpha").unwrap()];
        let authors: Vec<CustodyDomainId> = vec![];

        let result = validate_custody_domain_overlap(&executor, &authors);
        assert!(result.is_ok());
    }
}
