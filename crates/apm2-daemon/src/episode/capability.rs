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
// Allowlist Resource Limits (TCK-00254, TCK-00314)
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
// TCK-00314: HEF Capability Allowlist Limits
//
// Per RFC-0018, pulse topic and CAS hash allowlists for session access control.
// =============================================================================

/// Maximum number of topics in a session's pulse topic allowlist.
///
/// Per CTR-1303, bounded to prevent denial-of-service. Aligns with RFC-0018
/// `max_total_patterns_per_connection: 64`.
pub const MAX_TOPIC_ALLOWLIST: usize = 64;

/// Maximum length for a topic in the allowlist.
///
/// Per CTR-1303, all string fields must be bounded. Topics follow the
/// RFC-0018 grammar which limits segment lengths.
pub const MAX_TOPIC_LEN: usize = 256;

/// Maximum number of CAS hashes in a session's CAS hash allowlist.
///
/// Per CTR-1303, bounded to prevent denial-of-service. Allows sufficient hashes
/// for diff bundles, snapshots, and review artifacts.
pub const MAX_CAS_HASH_ALLOWLIST: usize = 1024;

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

    // =========================================================================
    // TCK-00314: HEF Capability Allowlist Errors
    // =========================================================================
    /// Topic allowlist exceeds maximum size.
    TooManyTopicAllowlistEntries {
        /// Actual count.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Topic in topic allowlist exceeds maximum length.
    TopicAllowlistEntryTooLong {
        /// Actual length in bytes.
        len: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Topic in topic allowlist is invalid.
    TopicAllowlistEntryInvalid {
        /// The invalid topic.
        topic: String,
        /// The reason for invalidity.
        reason: String,
    },

    /// Topic contains wildcard pattern (Phase 1: wildcards not allowed).
    TopicAllowlistWildcardNotAllowed {
        /// The topic containing wildcards.
        topic: String,
    },

    /// CAS hash allowlist exceeds maximum size.
    TooManyCasHashAllowlistEntries {
        /// Actual count.
        count: usize,
        /// Maximum allowed.
        max: usize,
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
            // TCK-00314: HEF Capability Allowlist Errors
            Self::TooManyTopicAllowlistEntries { count, max } => {
                write!(f, "too many topic allowlist entries: {count} (max {max})")
            },
            Self::TopicAllowlistEntryTooLong { len, max } => {
                write!(f, "topic allowlist entry too long: {len} bytes (max {max})")
            },
            Self::TopicAllowlistEntryInvalid { topic, reason } => {
                write!(f, "invalid topic in allowlist '{topic}': {reason}")
            },
            Self::TopicAllowlistWildcardNotAllowed { topic } => {
                write!(f, "wildcard topic not allowed in Phase 1: {topic}")
            },
            Self::TooManyCasHashAllowlistEntries { count, max } => {
                write!(
                    f,
                    "too many CAS hash allowlist entries: {count} (max {max})"
                )
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
/// # TCK-00314 Extensions
///
/// Per RFC-0018, the manifest includes HEF allowlists:
/// - `topic_allowlist`: Allowed pulse topics for session subscriptions
/// - `cas_hash_allowlist`: Allowed CAS hashes for session reads
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

    // =========================================================================
    // TCK-00314: HEF Capability Allowlists
    // =========================================================================
    /// Allowlist of pulse topics that this session can subscribe to.
    ///
    /// Per RFC-0018, session subscriptions are gated via capability manifest
    /// allowlist. Empty means no topics allowed (fail-closed).
    ///
    /// # Phase 1 Restrictions
    ///
    /// - Only exact topic matches are allowed (no wildcards)
    /// - Topics must follow the RFC-0018 pulse topic grammar
    ///
    /// # Example Topics
    ///
    /// - `work.W-123.events` - Work events for a specific work ID
    /// - `episode.EP-001.lifecycle` - Lifecycle events for an episode
    /// - `ledger.head` - Ledger head updates
    #[serde(default)]
    pub topic_allowlist: Vec<String>,

    /// Allowlist of CAS hashes that this session can read.
    ///
    /// Per RFC-0018, session CAS reads are gated via capability manifest
    /// allowlist. Empty means no CAS reads allowed (fail-closed).
    ///
    /// # Use Cases
    ///
    /// - Diff bundles for review artifacts
    /// - Snapshots for state reconstruction
    /// - Evidence artifacts for audit
    ///
    /// # Note
    ///
    /// CAS writes are not allowlisted (write allowlists are out of scope
    /// per TCK-00314). Operator.sock has full CAS access.
    #[serde(default)]
    pub cas_hash_allowlist: Vec<[u8; 32]>,
}

impl CapabilityManifest {
    /// Creates a builder for constructing a manifest.
    #[must_use]
    pub fn builder(manifest_id: impl Into<String>) -> CapabilityManifestBuilder {
        CapabilityManifestBuilder::new(manifest_id)
    }

    /// Creates a stub manifest from a capability manifest hash.
    ///
    /// # TCK-00287
    ///
    /// This method creates a minimal manifest with the given hash as the ID and
    /// a default permissive tool allowlist for stub/testing purposes. In
    /// production, the full manifest should be obtained from the governance
    /// holon via `PolicyResolver`.
    ///
    /// # Arguments
    ///
    /// * `capability_manifest_hash` - The BLAKE3 hash of the capability
    ///   manifest
    /// * `tool_allowlist` - The list of tool classes allowed for this session
    ///
    /// # Security Note
    ///
    /// This method is intended for the stub implementation path. Production
    /// deployments should populate the manifest from the resolved policy.
    #[must_use]
    pub fn from_hash_with_allowlist(
        capability_manifest_hash: &[u8; 32],
        tool_allowlist: Vec<ToolClass>,
    ) -> Self {
        // TCK-00352 BLOCKER 2 fix: V1 minting requires non-zero expiry.
        // Default to 24 hours from now for stub/fallback manifests so
        // that V1 enforcement is active. Without this, stub manifests
        // cause V1 minting to fail, leaving sessions without V1 scope
        // enforcement (fail-open).
        const DEFAULT_MANIFEST_TTL_SECS: u64 = 86400; // 24 hours

        let manifest_id = format!("M-{}", hex::encode(&capability_manifest_hash[..8]));
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        let expires_at = now + DEFAULT_MANIFEST_TTL_SECS;

        Self {
            manifest_id,
            capabilities: Vec::new(),
            delegator_id: "daemon".to_string(),
            created_at: now,
            expires_at,
            tool_allowlist,
            write_allowlist: Vec::new(),
            shell_allowlist: Vec::new(),
            // TCK-00314: HEF allowlists default to empty (fail-closed)
            topic_allowlist: Vec::new(),
            cas_hash_allowlist: Vec::new(),
        }
    }

    /// Creates a stub manifest from a capability manifest hash with default
    /// tool allowlist.
    ///
    /// # TCK-00287
    ///
    /// This method creates a minimal manifest with an empty tool allowlist
    /// by default (fail-closed).
    ///
    /// # Security Note
    ///
    /// The default allowlist is empty (fail-closed) to ensure no implicit
    /// privileges are granted. Production deployments should use
    /// `from_hash_with_allowlist` with the actual allowlist from the
    /// resolved policy.
    #[must_use]
    pub fn from_hash_with_default_allowlist(capability_manifest_hash: &[u8; 32]) -> Self {
        // Default allowlist for stub implementation
        // Empty by default (fail-closed)
        let tool_allowlist = Vec::new();
        Self::from_hash_with_allowlist(capability_manifest_hash, tool_allowlist)
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

        // TCK-00314: Validate HEF allowlists
        self.validate_topic_allowlist()?;
        self.validate_cas_hash_allowlist()?;

        Ok(())
    }

    /// Validates the topic allowlist (TCK-00314).
    ///
    /// # Phase 1 Restrictions
    ///
    /// - No wildcard patterns allowed
    /// - Topics must follow RFC-0018 grammar
    fn validate_topic_allowlist(&self) -> Result<(), CapabilityError> {
        if self.topic_allowlist.len() > MAX_TOPIC_ALLOWLIST {
            return Err(CapabilityError::TooManyTopicAllowlistEntries {
                count: self.topic_allowlist.len(),
                max: MAX_TOPIC_ALLOWLIST,
            });
        }

        for topic in &self.topic_allowlist {
            // Check length bounds
            if topic.len() > MAX_TOPIC_LEN {
                return Err(CapabilityError::TopicAllowlistEntryTooLong {
                    len: topic.len(),
                    max: MAX_TOPIC_LEN,
                });
            }

            // Phase 1: Reject wildcard patterns
            if topic.contains('*') || topic.contains('>') {
                return Err(CapabilityError::TopicAllowlistWildcardNotAllowed {
                    topic: topic.clone(),
                });
            }

            // Basic topic grammar validation (RFC-0018):
            // - Must not be empty
            // - Must not have consecutive dots
            // - Must not start or end with a dot
            // - Must only contain valid ASCII characters
            if topic.is_empty() {
                return Err(CapabilityError::TopicAllowlistEntryInvalid {
                    topic: topic.clone(),
                    reason: "topic cannot be empty".to_string(),
                });
            }
            if topic.starts_with('.') || topic.ends_with('.') {
                return Err(CapabilityError::TopicAllowlistEntryInvalid {
                    topic: topic.clone(),
                    reason: "topic cannot start or end with a dot".to_string(),
                });
            }
            if topic.contains("..") {
                return Err(CapabilityError::TopicAllowlistEntryInvalid {
                    topic: topic.clone(),
                    reason: "topic cannot have consecutive dots".to_string(),
                });
            }
            if !topic.is_ascii() {
                return Err(CapabilityError::TopicAllowlistEntryInvalid {
                    topic: topic.clone(),
                    reason: "topic must be ASCII".to_string(),
                });
            }
        }

        Ok(())
    }

    /// Validates the CAS hash allowlist (TCK-00314).
    fn validate_cas_hash_allowlist(&self) -> Result<(), CapabilityError> {
        if self.cas_hash_allowlist.len() > MAX_CAS_HASH_ALLOWLIST {
            return Err(CapabilityError::TooManyCasHashAllowlistEntries {
                count: self.cas_hash_allowlist.len(),
                max: MAX_CAS_HASH_ALLOWLIST,
            });
        }
        // Hash values are fixed 32-byte arrays, no further validation needed
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

    // =========================================================================
    // TCK-00314: HEF Allowlist Enforcement Methods
    // =========================================================================

    /// Returns a reference to the topic allowlist.
    #[must_use]
    pub fn topic_allowlist(&self) -> &[String] {
        &self.topic_allowlist
    }

    /// Returns a reference to the CAS hash allowlist.
    #[must_use]
    pub fn cas_hash_allowlist(&self) -> &[[u8; 32]] {
        &self.cas_hash_allowlist
    }

    /// Checks if the given topic is in the topic allowlist.
    ///
    /// Per TCK-00314, returns `false` if the allowlist is empty (fail-closed).
    /// Only exact matches are allowed (Phase 1: no wildcard patterns).
    #[must_use]
    pub fn is_topic_allowed(&self, topic: &str) -> bool {
        if self.topic_allowlist.is_empty() {
            // Fail-closed: empty allowlist means nothing is allowed
            return false;
        }
        self.topic_allowlist.iter().any(|t| t == topic)
    }

    /// Checks if the given CAS hash is in the CAS hash allowlist.
    ///
    /// Per TCK-00314, returns `false` if the allowlist is empty (fail-closed).
    #[must_use]
    pub fn is_cas_hash_allowed(&self, hash: &[u8; 32]) -> bool {
        if self.cas_hash_allowlist.is_empty() {
            // Fail-closed: empty allowlist means nothing is allowed
            return false;
        }
        self.cas_hash_allowlist.iter().any(|h| h == hash)
    }

    /// Converts the topic allowlist to a `TopicAllowlist` for ACL evaluation.
    ///
    /// Per TCK-00314, this method creates a `TopicAllowlist` from the
    /// manifest's `topic_allowlist` field for use with `PulseAclEvaluator`.
    ///
    /// # Returns
    ///
    /// A `TopicAllowlist` containing the manifest's allowed topics.
    /// Returns an empty allowlist if topics are invalid (fail-closed).
    #[must_use]
    pub fn to_topic_allowlist(&self) -> super::super::protocol::pulse_acl::TopicAllowlist {
        use super::super::protocol::pulse_acl::TopicAllowlist;

        if self.topic_allowlist.is_empty() {
            return TopicAllowlist::new();
        }

        // Try to create TopicAllowlist; if any topic is invalid, return empty
        // (fail-closed)
        TopicAllowlist::try_from_iter(self.topic_allowlist.iter().map(String::as_str))
            .unwrap_or_else(|_| TopicAllowlist::new())
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
    // TCK-00314: HEF allowlists
    /// Sorted topic allowlist for deterministic serialization.
    #[prost(string, repeated, tag = "9")]
    topic_allowlist: Vec<String>,
    /// Sorted CAS hash allowlist for deterministic serialization.
    #[prost(bytes = "vec", repeated, tag = "10")]
    cas_hash_allowlist: Vec<Vec<u8>>,
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

        // TCK-00314: Sort HEF allowlists for determinism
        let mut sorted_topics: Vec<String> = self.topic_allowlist.clone();
        sorted_topics.sort_unstable();

        // Sort CAS hashes lexicographically for determinism
        let mut sorted_cas_hashes: Vec<Vec<u8>> =
            self.cas_hash_allowlist.iter().map(|h| h.to_vec()).collect();
        sorted_cas_hashes.sort_unstable();

        let proto = CapabilityManifestProto {
            manifest_id: self.manifest_id.clone(),
            capability_bytes: sorted_caps.iter().map(|c| c.canonical_bytes()).collect(),
            delegator_id: self.delegator_id.clone(),
            created_at: Some(self.created_at),
            expires_at: Some(self.expires_at),
            tool_allowlist: sorted_tools,
            write_allowlist: sorted_write_paths,
            shell_allowlist: sorted_shell_patterns,
            topic_allowlist: sorted_topics,
            cas_hash_allowlist: sorted_cas_hashes,
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
    // TCK-00314: HEF allowlists
    topic_allowlist: Vec<String>,
    cas_hash_allowlist: Vec<[u8; 32]>,
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
            // TCK-00314: HEF allowlists
            topic_allowlist: Vec::new(),
            cas_hash_allowlist: Vec::new(),
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

    // =========================================================================
    // TCK-00314: HEF Allowlist Builder Methods
    // =========================================================================

    /// Sets the topic allowlist for pulse subscriptions.
    ///
    /// Per RFC-0018, session subscriptions are gated via capability manifest.
    #[must_use]
    pub fn topic_allowlist(mut self, topics: Vec<String>) -> Self {
        self.topic_allowlist = topics;
        self
    }

    /// Adds a topic to the allowlist.
    #[must_use]
    pub fn allow_topic(mut self, topic: impl Into<String>) -> Self {
        self.topic_allowlist.push(topic.into());
        self
    }

    /// Sets the CAS hash allowlist for CAS reads.
    ///
    /// Per RFC-0018, session CAS reads are gated via capability manifest.
    #[must_use]
    pub fn cas_hash_allowlist(mut self, hashes: Vec<[u8; 32]>) -> Self {
        self.cas_hash_allowlist = hashes;
        self
    }

    /// Adds a CAS hash to the allowlist.
    #[must_use]
    pub fn allow_cas_hash(mut self, hash: [u8; 32]) -> Self {
        self.cas_hash_allowlist.push(hash);
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
        // TCK-00314: Sort HEF allowlists
        self.topic_allowlist.sort();
        self.cas_hash_allowlist.sort_unstable();

        let manifest = CapabilityManifest {
            manifest_id: self.manifest_id,
            capabilities: self.capabilities,
            delegator_id: self.delegator_id,
            created_at: self.created_at,
            expires_at: self.expires_at,
            tool_allowlist: self.tool_allowlist,
            write_allowlist: self.write_allowlist,
            shell_allowlist: self.shell_allowlist,
            // TCK-00314: HEF allowlists
            topic_allowlist: self.topic_allowlist,
            cas_hash_allowlist: self.cas_hash_allowlist,
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

/// In-memory CAS-backed manifest loader for testing and development.
///
/// This loader stores manifests in memory keyed by their BLAKE3 hash.
/// It implements the full `ManifestLoader` trait with proper hash
/// verification and validation.
///
/// # TCK-00317 Implementation
///
/// Per DOD item 1 (CAS Storage & Hash Loading), this loader:
/// - Stores manifests as CAS artifacts (hash-addressed)
/// - Loads manifests by hash with verification
/// - Validates manifests on load
///
/// # Security Model
///
/// - Manifests are stored with their computed BLAKE3 hash
/// - Load operations verify the hash matches the content
/// - Invalid manifests are rejected on store
///
/// # Thread Safety
///
/// Uses `RwLock` for interior mutability, safe for concurrent access.
#[derive(Debug, Default)]
pub struct InMemoryCasManifestLoader {
    /// Stored manifests keyed by their BLAKE3 hash.
    store: std::sync::RwLock<std::collections::HashMap<[u8; 32], Vec<u8>>>,
}

impl InMemoryCasManifestLoader {
    /// Creates a new empty manifest loader.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a new manifest loader pre-seeded with the canonical reviewer v0
    /// manifest.
    ///
    /// This is the recommended constructor for production use, ensuring the
    /// canonical manifest is always available.
    ///
    /// # TCK-00317
    ///
    /// Per DOD item 1, the reviewer v0 manifest must be stored in CAS and
    /// referenced by hash. This constructor pre-seeds the store with the
    /// canonical manifest.
    #[must_use]
    pub fn with_reviewer_v0_manifest() -> Self {
        let loader = Self::new();
        // Store the canonical reviewer v0 manifest
        let manifest = super::reviewer_manifest::reviewer_v0_manifest();
        // Ignore errors - the canonical manifest should always be valid
        let _ = loader.store_manifest(manifest);
        loader
    }
}

impl ManifestLoader for InMemoryCasManifestLoader {
    fn load_manifest(&self, hash: &[u8; 32]) -> Result<CapabilityManifest, ManifestLoadError> {
        let store = self.store.read().expect("lock poisoned");
        let bytes = store.get(hash).ok_or_else(|| ManifestLoadError::NotFound {
            hash: hex::encode(hash),
        })?;

        // Deserialize from JSON and validate
        let manifest: CapabilityManifest =
            serde_json::from_slice(bytes).map_err(|e| ManifestLoadError::DeserializationError {
                message: e.to_string(),
            })?;

        // Verify the manifest's digest matches the requested hash
        // This ensures the content is authentic even though we store JSON
        let computed_hash = manifest.digest();
        if &computed_hash != hash {
            return Err(ManifestLoadError::HashMismatch {
                expected: hex::encode(hash),
                actual: hex::encode(computed_hash),
            });
        }

        manifest.validate()?;

        Ok(manifest)
    }

    fn store_manifest(&self, manifest: &CapabilityManifest) -> Result<[u8; 32], ManifestLoadError> {
        // Validate before storing
        manifest.validate()?;

        // Compute the canonical hash (same as digest())
        // This ensures consistent hashing with reviewer_v0_manifest_hash()
        let hash_bytes = manifest.digest();

        // Serialize to JSON for storage
        // We use JSON for easy deserialization while using canonical bytes for hashing
        let bytes = serde_json::to_vec(manifest).map_err(|e| ManifestLoadError::StorageError {
            message: format!("serialization failed: {e}"),
        })?;

        // Store using the canonical hash as the key
        let mut store = self.store.write().expect("lock poisoned");
        store.insert(hash_bytes, bytes);

        Ok(hash_bytes)
    }

    fn manifest_exists(&self, hash: &[u8; 32]) -> bool {
        let store = self.store.read().expect("lock poisoned");
        store.contains_key(hash)
    }
}

/// Convenience type alias for validators using the stub loader.
pub type BasicValidator = PolicyIntegratedValidator<StubManifestLoader>;

/// Convenience type alias for validators using the in-memory CAS loader.
pub type CasValidator = PolicyIntegratedValidator<InMemoryCasManifestLoader>;

// =============================================================================
// TCK-00352: CapabilityManifestV1 — Policy-Only Capability Minting
//
// Per TCK-00352, CapabilityManifestV1 can ONLY be minted by the policy
// resolver. Requester surfaces cannot construct this type. The type wraps
// a validated CapabilityManifest with additional security properties:
// - Host restrictions (allowed hosts for network operations)
// - Risk tier ceiling (cannot exceed the tier set by policy)
// - Mandatory expiry enforcement
// - Non-discoverability (no enumeration methods for requesters)
// - Envelope-manifest hash mismatch denial
// =============================================================================

/// Maximum number of allowed hosts in a `CapabilityManifestV1`.
///
/// Per CTR-1303, bounded to prevent denial-of-service.
pub const MAX_MANIFEST_V1_HOSTS: usize = 256;

/// Maximum length for a host restriction entry.
///
/// Per CTR-1303, all string fields must be bounded.
pub const MAX_HOST_RESTRICTION_LEN: usize = 253;

/// Error type for `CapabilityManifestV1` operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestV1Error {
    /// Underlying manifest validation failed.
    ManifestValidation(CapabilityError),

    /// Manifest has no expiry set (fail-closed: expiry is mandatory for V1).
    MissingExpiry,

    /// Risk tier ceiling would widen the resolved tier (laundering attempt).
    RiskTierWidened {
        /// The policy-resolved maximum tier.
        policy_ceiling: RiskTier,
        /// The tier that was attempted.
        attempted: RiskTier,
    },

    /// Scope is overbroad: the manifest grants more than policy allows.
    OverbroadScope {
        /// Description of the overbroad scope.
        reason: String,
    },

    /// Too many host restriction entries.
    TooManyHostRestrictions {
        /// Actual count.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Host restriction entry exceeds maximum length.
    HostRestrictionTooLong {
        /// Actual length in bytes.
        len: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Envelope hash does not match the manifest digest.
    EnvelopeManifestHashMismatch {
        /// Expected hash (from manifest digest, hex-encoded).
        expected: String,
        /// Actual hash (from envelope, hex-encoded).
        actual: String,
    },

    /// Manifest was not minted by the policy resolver.
    NotMintedByPolicy,
}

impl std::fmt::Display for ManifestV1Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ManifestValidation(e) => write!(f, "manifest validation: {e}"),
            Self::MissingExpiry => write!(f, "V1 manifests require a non-zero expiry"),
            Self::RiskTierWidened {
                policy_ceiling,
                attempted,
            } => write!(
                f,
                "risk tier widened: policy ceiling {policy_ceiling:?}, attempted {attempted:?}"
            ),
            Self::OverbroadScope { reason } => write!(f, "overbroad scope: {reason}"),
            Self::TooManyHostRestrictions { count, max } => {
                write!(f, "too many host restrictions: {count} (max {max})")
            },
            Self::HostRestrictionTooLong { len, max } => {
                write!(f, "host restriction too long: {len} bytes (max {max})")
            },
            Self::EnvelopeManifestHashMismatch { expected, actual } => {
                write!(
                    f,
                    "envelope-manifest hash mismatch: expected {expected}, got {actual}"
                )
            },
            Self::NotMintedByPolicy => {
                write!(f, "manifest was not minted by the policy resolver")
            },
        }
    }
}

impl std::error::Error for ManifestV1Error {}

impl From<CapabilityError> for ManifestV1Error {
    fn from(e: CapabilityError) -> Self {
        Self::ManifestValidation(e)
    }
}

/// Sealed proof token that can only be constructed by the policy resolver.
///
/// Per TCK-00352, this type prevents requester surfaces from constructing
/// `CapabilityManifestV1` directly. Only code paths that hold a
/// `PolicyMintToken` can call `CapabilityManifestV1::mint()`.
///
/// # Security
///
/// The constructor is `pub(crate)` so that only daemon-internal code
/// (specifically the `GovernancePolicyResolver` or production wiring in
/// `state.rs`) can create instances. External crates and requester surfaces
/// cannot obtain a `PolicyMintToken`.
#[derive(Debug, Clone, Copy)]
pub struct PolicyMintToken {
    /// Private field to prevent external construction.
    _private: (),
}

impl PolicyMintToken {
    /// Creates a new policy mint token.
    ///
    /// # Security
    ///
    /// This constructor is `pub(crate)` to restrict minting authority to
    /// daemon internals. **Production code MUST NOT call this directly.**
    /// Instead, use [`GovernancePolicyResolver::mint_token()`] to obtain a
    /// token through the authorized governance channel. Direct construction
    /// is reserved for the `GovernancePolicyResolver` implementation and
    /// test code within this module.
    ///
    /// [`GovernancePolicyResolver::mint_token()`]: crate::governance::GovernancePolicyResolver::mint_token
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self { _private: () }
    }
}

/// V1 capability manifest with policy-resolver-only minting.
///
/// Per TCK-00352:
/// - Can ONLY be constructed via [`CapabilityManifestV1::mint()`] which
///   requires a [`PolicyMintToken`] (only obtainable by the policy resolver).
/// - Enforces mandatory expiry (fail-closed: zero expiry is rejected).
/// - Enforces a risk tier ceiling that cannot be widened.
/// - Provides host restriction enforcement for network operations.
/// - Does NOT expose enumeration methods (non-discoverability).
/// - Validates envelope-manifest hash binding.
///
/// # Security Model
///
/// - **No public constructor**: Requesters cannot mint capabilities.
/// - **Non-discoverable**: No method enumerates available capabilities.
/// - **Fail-closed**: Missing or invalid fields deny by default.
/// - **Laundering-resistant**: Risk tier cannot be widened, expiry cannot be
///   removed, scope cannot be broadened beyond policy resolution.
///
/// # Contract References
///
/// - TCK-00352: Policy-only capability minting and broker scope enforcement
/// - AD-TOOL-002: Capability manifests as sealed references
/// - CTR-1303: Bounded collections with `MAX_*` constants
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityManifestV1 {
    /// The underlying validated capability manifest.
    inner: CapabilityManifest,

    /// Risk tier ceiling imposed by the policy resolver.
    ///
    /// No capability in this manifest may grant access above this tier.
    /// Attempts to use capabilities at a tier above the ceiling are denied.
    risk_tier_ceiling: RiskTier,

    /// Allowed hosts for network operations.
    ///
    /// Per TCK-00352, host restrictions are enforced by the broker before
    /// dispatching network tool requests. Empty means no hosts allowed
    /// (fail-closed).
    host_restrictions: Vec<String>,
}

impl CapabilityManifestV1 {
    /// Mints a new `CapabilityManifestV1` from a policy-resolved manifest.
    ///
    /// # Arguments
    ///
    /// * `_token` - Proof that the caller is the policy resolver.
    /// * `manifest` - The underlying capability manifest.
    /// * `risk_tier_ceiling` - Maximum risk tier allowed by policy.
    /// * `host_restrictions` - Allowed hosts for network operations.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestV1Error`] if:
    /// - The manifest fails structural validation.
    /// - The manifest has no expiry set (V1 requires mandatory expiry).
    /// - Any capability's risk tier exceeds the ceiling.
    /// - Host restrictions exceed bounds.
    ///
    /// # Security
    ///
    /// Only callable with a [`PolicyMintToken`], which is `pub(crate)`.
    /// This prevents requester surfaces from minting capabilities.
    pub fn mint(
        _token: PolicyMintToken,
        manifest: CapabilityManifest,
        risk_tier_ceiling: RiskTier,
        host_restrictions: Vec<String>,
    ) -> Result<Self, ManifestV1Error> {
        // Step 1: Validate the underlying manifest structure.
        manifest.validate()?;

        // Step 2: Enforce mandatory expiry (fail-closed).
        if manifest.expires_at == 0 {
            return Err(ManifestV1Error::MissingExpiry);
        }

        // Step 3: Enforce risk tier ceiling — no capability may exceed it.
        for cap in &manifest.capabilities {
            if cap.risk_tier_required.tier() > risk_tier_ceiling.tier() {
                return Err(ManifestV1Error::RiskTierWidened {
                    policy_ceiling: risk_tier_ceiling,
                    attempted: cap.risk_tier_required,
                });
            }
        }

        // Step 4: Validate host restrictions bounds.
        if host_restrictions.len() > MAX_MANIFEST_V1_HOSTS {
            return Err(ManifestV1Error::TooManyHostRestrictions {
                count: host_restrictions.len(),
                max: MAX_MANIFEST_V1_HOSTS,
            });
        }
        for host in &host_restrictions {
            if host.len() > MAX_HOST_RESTRICTION_LEN {
                return Err(ManifestV1Error::HostRestrictionTooLong {
                    len: host.len(),
                    max: MAX_HOST_RESTRICTION_LEN,
                });
            }
        }

        Ok(Self {
            inner: manifest,
            risk_tier_ceiling,
            host_restrictions,
        })
    }

    /// Returns the BLAKE3 digest of the underlying manifest.
    ///
    /// This is the hash that MUST appear in the episode envelope's
    /// `capability_manifest_hash` field.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        self.inner.digest()
    }

    /// Returns the risk tier ceiling imposed by policy.
    #[must_use]
    pub const fn risk_tier_ceiling(&self) -> RiskTier {
        self.risk_tier_ceiling
    }

    /// Returns the manifest ID.
    #[must_use]
    pub fn manifest_id(&self) -> &str {
        &self.inner.manifest_id
    }

    /// Returns the delegator ID.
    #[must_use]
    pub fn delegator_id(&self) -> &str {
        &self.inner.delegator_id
    }

    /// Returns the expiry timestamp (guaranteed non-zero for V1).
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.inner.expires_at
    }

    /// Returns `true` if this manifest has expired.
    #[must_use]
    pub fn is_expired_with_clock(&self, clock: &dyn Clock) -> bool {
        self.inner.is_expired_with_clock(clock)
    }

    /// Returns a reference to the underlying manifest for internal use.
    ///
    /// # Security
    ///
    /// This is `pub(crate)` to prevent requester surfaces from accessing
    /// the raw manifest for enumeration. Only daemon-internal code (e.g.,
    /// the broker) can inspect the manifest contents.
    ///
    /// # Note
    ///
    /// Reserved for broker-level integration where the broker needs to
    /// inspect manifest details for scope enforcement decisions.
    #[must_use]
    #[allow(dead_code)] // Reserved for broker integration in future tickets
    pub(crate) const fn inner(&self) -> &CapabilityManifest {
        &self.inner
    }

    /// Validates a tool request against this V1 manifest, enforcing
    /// broker scope checks including the risk tier ceiling and host
    /// restrictions.
    ///
    /// # Broker Scope Enforcement (TCK-00352)
    ///
    /// Before dispatching a tool request, the broker MUST call this method.
    /// It enforces:
    /// 1. Risk tier ceiling — request tier must not exceed ceiling.
    /// 2. Host restrictions — network requests must target allowed hosts.
    /// 3. All standard manifest checks (tool allowlist, path, size, etc.).
    ///
    /// # Arguments
    ///
    /// * `request` - The tool request to validate.
    /// * `clock` - Clock for expiry checks (HOLONIC-BOUNDARY-001).
    ///
    /// # Returns
    ///
    /// `CapabilityDecision::Allow` or `CapabilityDecision::Deny`.
    #[must_use]
    pub fn validate_request_scoped(
        &self,
        request: &ToolRequest,
        clock: &dyn Clock,
    ) -> CapabilityDecision {
        // Step 1: Check risk tier ceiling (fail-closed).
        if request.risk_tier.tier() > self.risk_tier_ceiling.tier() {
            return CapabilityDecision::Deny {
                reason: DenyReason::InsufficientRiskTier {
                    required: self.risk_tier_ceiling,
                    actual: request.risk_tier,
                },
            };
        }

        // Step 2: Check host restrictions for network requests (fail-closed).
        if let Some((ref host, port)) = request.network {
            if !self.is_host_allowed(host) {
                return CapabilityDecision::Deny {
                    reason: DenyReason::NetworkNotAllowed {
                        host: host.clone(),
                        port,
                    },
                };
            }
        }

        // Step 3: Delegate to the inner manifest's validation with clock.
        self.inner.validate_request_with_clock(request, clock)
    }

    /// Checks whether a host is in the allowed host restrictions.
    ///
    /// Returns `false` if the host list is empty (fail-closed).
    fn is_host_allowed(&self, host: &str) -> bool {
        if self.host_restrictions.is_empty() {
            return false;
        }
        self.host_restrictions.iter().any(|allowed| {
            if allowed.starts_with("*.") {
                // Wildcard domain match: *.example.com matches
                // sub.example.com
                let suffix = &allowed[1..]; // ".example.com"
                host.ends_with(suffix)
                    && host.len() > suffix.len()
                    && host.as_bytes()[host.len() - suffix.len() - 1] != b'.'
            } else {
                host == allowed
            }
        })
    }

    /// Validates that an envelope's `capability_manifest_hash` matches
    /// this manifest's digest.
    ///
    /// Per TCK-00352, if the hash in the envelope does not match the
    /// actual manifest's BLAKE3 digest, actuation MUST be denied.
    ///
    /// # Arguments
    ///
    /// * `envelope_manifest_hash` - The hash from the episode envelope.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestV1Error::EnvelopeManifestHashMismatch`] if the
    /// hashes do not match.
    pub fn verify_envelope_binding(
        &self,
        envelope_manifest_hash: &[u8],
    ) -> Result<(), ManifestV1Error> {
        let expected = self.digest();
        if envelope_manifest_hash.len() != 32 || envelope_manifest_hash != expected {
            return Err(ManifestV1Error::EnvelopeManifestHashMismatch {
                expected: hex::encode(expected),
                actual: hex::encode(envelope_manifest_hash),
            });
        }
        Ok(())
    }
}

/// Policy-resolved scope baseline for strict-subset validation.
///
/// Per Security Review MAJOR 1, cardinality-only checks are insufficient
/// because an attacker can substitute unauthorized entries while keeping
/// the count within bounds. This struct carries the normalized baseline
/// sets that the manifest entries must be strict subsets of.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ScopeBaseline {
    /// Baseline tool classes permitted by policy.
    pub tools: Vec<ToolClass>,
    /// Baseline write paths permitted by policy (normalized).
    pub write_paths: Vec<PathBuf>,
    /// Baseline shell patterns permitted by policy (normalized).
    pub shell_patterns: Vec<String>,
}

/// Validates that a `CapabilityManifest` does not have overbroad scope
/// relative to a policy-resolved baseline.
///
/// Per TCK-00352 Security Review MAJOR 1, this function enforces both
/// cardinality bounds AND strict-subset membership. A manifest that
/// substitutes unauthorized entries while keeping the count within bounds
/// is rejected.
///
/// # Arguments
///
/// * `manifest` - The manifest to validate.
/// * `max_tool_allowlist` - Maximum number of tools policy permits.
/// * `max_write_paths` - Maximum number of write paths policy permits.
/// * `max_shell_patterns` - Maximum number of shell patterns policy permits.
///
/// # Errors
///
/// Returns [`ManifestV1Error::OverbroadScope`] if any allowlist exceeds
/// the policy baseline cardinality.
pub fn validate_manifest_scope_bounds(
    manifest: &CapabilityManifest,
    max_tool_allowlist: usize,
    max_write_paths: usize,
    max_shell_patterns: usize,
) -> Result<(), ManifestV1Error> {
    if manifest.tool_allowlist.len() > max_tool_allowlist {
        return Err(ManifestV1Error::OverbroadScope {
            reason: format!(
                "tool allowlist has {} entries, policy permits at most {}",
                manifest.tool_allowlist.len(),
                max_tool_allowlist
            ),
        });
    }
    if manifest.write_allowlist.len() > max_write_paths {
        return Err(ManifestV1Error::OverbroadScope {
            reason: format!(
                "write allowlist has {} entries, policy permits at most {}",
                manifest.write_allowlist.len(),
                max_write_paths
            ),
        });
    }
    if manifest.shell_allowlist.len() > max_shell_patterns {
        return Err(ManifestV1Error::OverbroadScope {
            reason: format!(
                "shell allowlist has {} entries, policy permits at most {}",
                manifest.shell_allowlist.len(),
                max_shell_patterns
            ),
        });
    }
    Ok(())
}

/// Validates that a `CapabilityManifest` scope is a strict subset of a
/// policy-resolved [`ScopeBaseline`].
///
/// Per TCK-00352 Security Review MAJOR 1, cardinality-only checks allow
/// scope laundering via same-cardinality substitution. This function
/// enforces:
///
/// 1. **Cardinality bounds** -- same as [`validate_manifest_scope_bounds`].
/// 2. **Strict-subset membership** -- every manifest entry must appear in the
///    baseline set. Normalized comparison is used (tool class identity, path
///    canonicalization, string equality for shell patterns).
///
/// # Arguments
///
/// * `manifest` - The manifest to validate.
/// * `baseline` - The policy-resolved baseline sets.
///
/// # Errors
///
/// Returns [`ManifestV1Error::OverbroadScope`] if any allowlist entry is
/// not present in the baseline or exceeds baseline cardinality.
pub fn validate_manifest_scope_subset(
    manifest: &CapabilityManifest,
    baseline: &ScopeBaseline,
) -> Result<(), ManifestV1Error> {
    // Step 1: Cardinality bounds (fail-fast).
    validate_manifest_scope_bounds(
        manifest,
        baseline.tools.len(),
        baseline.write_paths.len(),
        baseline.shell_patterns.len(),
    )?;

    // Step 2: Strict-subset check for tool allowlist.
    for tool in &manifest.tool_allowlist {
        if !baseline.tools.contains(tool) {
            return Err(ManifestV1Error::OverbroadScope {
                reason: format!("tool class {tool:?} is not in the policy baseline set"),
            });
        }
    }

    // Step 3: Strict-subset check for write paths (normalized comparison).
    for path in &manifest.write_allowlist {
        if !baseline.write_paths.iter().any(|bp| bp == path) {
            return Err(ManifestV1Error::OverbroadScope {
                reason: format!(
                    "write path '{}' is not in the policy baseline set",
                    path.display()
                ),
            });
        }
    }

    // Step 4: Strict-subset check for shell patterns.
    for pattern in &manifest.shell_allowlist {
        if !baseline.shell_patterns.iter().any(|bp| bp == pattern) {
            return Err(ManifestV1Error::OverbroadScope {
                reason: format!("shell pattern '{pattern}' is not in the policy baseline set"),
            });
        }
    }

    Ok(())
}

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
            // TCK-00314: HEF allowlists
            topic_allowlist: Vec::new(),
            cas_hash_allowlist: Vec::new(),
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
            // TCK-00314: HEF allowlists
            topic_allowlist: Vec::new(),
            cas_hash_allowlist: Vec::new(),
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
            // TCK-00314: HEF allowlists
            topic_allowlist: Vec::new(),
            cas_hash_allowlist: Vec::new(),
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
            // TCK-00314: HEF allowlists
            topic_allowlist: Vec::new(),
            cas_hash_allowlist: Vec::new(),
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
            // TCK-00314: HEF allowlists
            topic_allowlist: Vec::new(),
            cas_hash_allowlist: Vec::new(),
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
            // TCK-00314: HEF allowlists
            topic_allowlist: Vec::new(),
            cas_hash_allowlist: Vec::new(),
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
            // TCK-00314: HEF allowlists
            topic_allowlist: Vec::new(),
            cas_hash_allowlist: Vec::new(),
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
            // TCK-00314: HEF allowlists
            topic_allowlist: Vec::new(),
            cas_hash_allowlist: Vec::new(),
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
            // TCK-00314: HEF allowlists
            topic_allowlist: Vec::new(),
            cas_hash_allowlist: Vec::new(),
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

// ============================================================================
// TCK-00314: HEF Capability Allowlist Tests
// ============================================================================

#[cfg(test)]
mod hef_allowlist_tests {
    use super::*;

    // ========================================================================
    // Topic Allowlist Tests
    // ========================================================================

    mod topic_allowlist {
        use super::*;

        #[test]
        fn empty_topic_allowlist_fail_closed() {
            let manifest = CapabilityManifest::builder("test")
                .delegator("test")
                .topic_allowlist(vec![])
                .build()
                .unwrap();

            assert!(!manifest.is_topic_allowed("work.W-123.events"));
            assert!(!manifest.is_topic_allowed("ledger.head"));
        }

        #[test]
        fn topic_allowed_when_in_allowlist() {
            let manifest = CapabilityManifest::builder("test")
                .delegator("test")
                .topic_allowlist(vec![
                    "work.W-123.events".to_string(),
                    "ledger.head".to_string(),
                ])
                .build()
                .unwrap();

            assert!(manifest.is_topic_allowed("work.W-123.events"));
            assert!(manifest.is_topic_allowed("ledger.head"));
            assert!(!manifest.is_topic_allowed("work.W-456.events"));
        }

        #[test]
        fn topic_allowlist_exact_match_only() {
            let manifest = CapabilityManifest::builder("test")
                .delegator("test")
                .topic_allowlist(vec!["work.W-123.events".to_string()])
                .build()
                .unwrap();

            // Exact match
            assert!(manifest.is_topic_allowed("work.W-123.events"));

            // Not a prefix match
            assert!(!manifest.is_topic_allowed("work.W-123"));
            assert!(!manifest.is_topic_allowed("work.W-123.events.extra"));
        }

        #[test]
        fn topic_allowlist_rejects_wildcards() {
            let result = CapabilityManifest::builder("test")
                .delegator("test")
                .topic_allowlist(vec!["work.*.events".to_string()])
                .build();

            assert!(matches!(
                result,
                Err(CapabilityError::TopicAllowlistWildcardNotAllowed { .. })
            ));
        }

        #[test]
        fn topic_allowlist_rejects_terminal_wildcard() {
            let result = CapabilityManifest::builder("test")
                .delegator("test")
                .topic_allowlist(vec!["work.W-123.>".to_string()])
                .build();

            assert!(matches!(
                result,
                Err(CapabilityError::TopicAllowlistWildcardNotAllowed { .. })
            ));
        }

        #[test]
        fn topic_allowlist_rejects_empty_topic() {
            let result = CapabilityManifest::builder("test")
                .delegator("test")
                .topic_allowlist(vec![String::new()])
                .build();

            assert!(matches!(
                result,
                Err(CapabilityError::TopicAllowlistEntryInvalid { .. })
            ));
        }

        #[test]
        fn topic_allowlist_rejects_consecutive_dots() {
            let result = CapabilityManifest::builder("test")
                .delegator("test")
                .topic_allowlist(vec!["work..events".to_string()])
                .build();

            assert!(matches!(
                result,
                Err(CapabilityError::TopicAllowlistEntryInvalid { .. })
            ));
        }

        #[test]
        fn topic_allowlist_rejects_leading_dot() {
            let result = CapabilityManifest::builder("test")
                .delegator("test")
                .topic_allowlist(vec![".work.events".to_string()])
                .build();

            assert!(matches!(
                result,
                Err(CapabilityError::TopicAllowlistEntryInvalid { .. })
            ));
        }

        #[test]
        fn topic_allowlist_rejects_trailing_dot() {
            let result = CapabilityManifest::builder("test")
                .delegator("test")
                .topic_allowlist(vec!["work.events.".to_string()])
                .build();

            assert!(matches!(
                result,
                Err(CapabilityError::TopicAllowlistEntryInvalid { .. })
            ));
        }

        #[test]
        fn topic_allowlist_rejects_non_ascii() {
            let result = CapabilityManifest::builder("test")
                .delegator("test")
                .topic_allowlist(vec!["work.événements".to_string()])
                .build();

            assert!(matches!(
                result,
                Err(CapabilityError::TopicAllowlistEntryInvalid { .. })
            ));
        }

        #[test]
        fn topic_allowlist_too_many_entries() {
            let topics: Vec<String> = (0..=MAX_TOPIC_ALLOWLIST)
                .map(|i| format!("topic.{i}"))
                .collect();

            let result = CapabilityManifest::builder("test")
                .delegator("test")
                .topic_allowlist(topics)
                .build();

            assert!(matches!(
                result,
                Err(CapabilityError::TooManyTopicAllowlistEntries { .. })
            ));
        }

        #[test]
        fn topic_allowlist_entry_too_long() {
            let long_topic = format!("topic.{}", "x".repeat(MAX_TOPIC_LEN));

            let result = CapabilityManifest::builder("test")
                .delegator("test")
                .topic_allowlist(vec![long_topic])
                .build();

            assert!(matches!(
                result,
                Err(CapabilityError::TopicAllowlistEntryTooLong { .. })
            ));
        }

        #[test]
        fn to_topic_allowlist_creates_valid_allowlist() {
            let manifest = CapabilityManifest::builder("test")
                .delegator("test")
                .topic_allowlist(vec![
                    "work.W-123.events".to_string(),
                    "ledger.head".to_string(),
                ])
                .build()
                .unwrap();

            let allowlist = manifest.to_topic_allowlist();
            assert_eq!(allowlist.len(), 2);
            assert!(allowlist.contains("work.W-123.events"));
            assert!(allowlist.contains("ledger.head"));
        }
    }

    // ========================================================================
    // CAS Hash Allowlist Tests
    // ========================================================================

    mod cas_hash_allowlist {
        use super::*;

        #[test]
        fn empty_cas_hash_allowlist_fail_closed() {
            let manifest = CapabilityManifest::builder("test")
                .delegator("test")
                .cas_hash_allowlist(vec![])
                .build()
                .unwrap();

            let hash = [0u8; 32];
            assert!(!manifest.is_cas_hash_allowed(&hash));
        }

        #[test]
        fn cas_hash_allowed_when_in_allowlist() {
            let hash1 = [1u8; 32];
            let hash2 = [2u8; 32];
            let hash3 = [3u8; 32];

            let manifest = CapabilityManifest::builder("test")
                .delegator("test")
                .cas_hash_allowlist(vec![hash1, hash2])
                .build()
                .unwrap();

            assert!(manifest.is_cas_hash_allowed(&hash1));
            assert!(manifest.is_cas_hash_allowed(&hash2));
            assert!(!manifest.is_cas_hash_allowed(&hash3));
        }

        #[test]
        fn cas_hash_exact_match_only() {
            let hash = [0xABu8; 32];
            let mut similar_hash = hash;
            similar_hash[0] = 0xCD;

            let manifest = CapabilityManifest::builder("test")
                .delegator("test")
                .cas_hash_allowlist(vec![hash])
                .build()
                .unwrap();

            assert!(manifest.is_cas_hash_allowed(&hash));
            assert!(!manifest.is_cas_hash_allowed(&similar_hash));
        }

        #[test]
        #[allow(clippy::cast_possible_truncation)]
        fn cas_hash_allowlist_too_many_entries() {
            let hashes: Vec<[u8; 32]> = (0..=MAX_CAS_HASH_ALLOWLIST)
                .map(|i| {
                    let mut hash = [0u8; 32];
                    // Safe: i % 256 and (i / 256) % 256 are always in 0..=255
                    hash[0] = (i % 256) as u8;
                    hash[1] = ((i / 256) % 256) as u8;
                    hash
                })
                .collect();

            let result = CapabilityManifest::builder("test")
                .delegator("test")
                .cas_hash_allowlist(hashes)
                .build();

            assert!(matches!(
                result,
                Err(CapabilityError::TooManyCasHashAllowlistEntries { .. })
            ));
        }

        #[test]
        fn cas_hash_allowlist_builder_methods() {
            let hash1 = [1u8; 32];
            let hash2 = [2u8; 32];

            let manifest = CapabilityManifest::builder("test")
                .delegator("test")
                .allow_cas_hash(hash1)
                .allow_cas_hash(hash2)
                .build()
                .unwrap();

            assert!(manifest.is_cas_hash_allowed(&hash1));
            assert!(manifest.is_cas_hash_allowed(&hash2));
        }
    }

    // ========================================================================
    // Canonical Bytes Tests
    // ========================================================================

    mod canonical_bytes {
        use super::*;

        #[test]
        fn canonical_bytes_includes_hef_allowlists() {
            let manifest1 = CapabilityManifest::builder("test")
                .delegator("test")
                .topic_allowlist(vec!["topic.a".to_string()])
                .cas_hash_allowlist(vec![[1u8; 32]])
                .build()
                .unwrap();

            let manifest2 = CapabilityManifest::builder("test")
                .delegator("test")
                .topic_allowlist(vec!["topic.b".to_string()])
                .cas_hash_allowlist(vec![[2u8; 32]])
                .build()
                .unwrap();

            // Different allowlists should produce different bytes
            assert_ne!(manifest1.canonical_bytes(), manifest2.canonical_bytes());
        }

        #[test]
        fn canonical_bytes_sorted_for_determinism() {
            // Create manifests with same allowlists in different order
            let manifest1 = CapabilityManifest::builder("test")
                .delegator("test")
                .topic_allowlist(vec!["topic.a".to_string(), "topic.b".to_string()])
                .cas_hash_allowlist(vec![[1u8; 32], [2u8; 32]])
                .build()
                .unwrap();

            let manifest2 = CapabilityManifest::builder("test")
                .delegator("test")
                .topic_allowlist(vec!["topic.b".to_string(), "topic.a".to_string()])
                .cas_hash_allowlist(vec![[2u8; 32], [1u8; 32]])
                .build()
                .unwrap();

            // Should produce same bytes after sorting
            assert_eq!(manifest1.canonical_bytes(), manifest2.canonical_bytes());
        }
    }
}

// ============================================================================
// InMemoryCasManifestLoader Tests (TCK-00317)
// ============================================================================

#[cfg(test)]
mod cas_loader_tests {
    use std::path::PathBuf;

    use super::*;
    use crate::episode::reviewer_manifest::reviewer_v0_manifest_hash;
    use crate::episode::scope::SizeLimits;

    fn make_read_capability(id: &str, paths: Vec<PathBuf>) -> Capability {
        Capability {
            capability_id: id.to_string(),
            tool_class: ToolClass::Read,
            scope: CapabilityScope {
                root_paths: paths,
                allowed_patterns: Vec::new(),
                size_limits: SizeLimits::default_limits(),
                network_policy: None,
            },
            risk_tier_required: RiskTier::Tier0,
        }
    }

    fn make_manifest(caps: Vec<Capability>) -> CapabilityManifest {
        let tool_classes: Vec<ToolClass> = caps.iter().map(|c| c.tool_class).collect();
        CapabilityManifest::builder("test-manifest")
            .delegator("test-delegator")
            .capabilities(caps)
            .tool_allowlist(tool_classes)
            .build()
            .unwrap()
    }

    #[test]
    fn store_and_load_manifest() {
        let loader = InMemoryCasManifestLoader::new();
        let manifest = make_manifest(vec![make_read_capability(
            "cap-1",
            vec![PathBuf::from("/workspace")],
        )]);

        // Store the manifest
        let hash = loader.store_manifest(&manifest).expect("should store");

        // Load it back
        let retrieved = loader.load_manifest(&hash).expect("should load");

        // Verify it matches
        assert_eq!(retrieved.manifest_id, manifest.manifest_id);
        assert_eq!(retrieved.delegator_id, manifest.delegator_id);
        assert_eq!(retrieved.capabilities.len(), manifest.capabilities.len());
    }

    #[test]
    fn load_nonexistent_returns_not_found() {
        let loader = InMemoryCasManifestLoader::new();
        let fake_hash = [0u8; 32];

        let result = loader.load_manifest(&fake_hash);
        assert!(matches!(result, Err(ManifestLoadError::NotFound { .. })));
    }

    #[test]
    fn manifest_exists_returns_correct_value() {
        let loader = InMemoryCasManifestLoader::new();
        let manifest = make_manifest(vec![make_read_capability(
            "cap-1",
            vec![PathBuf::from("/workspace")],
        )]);

        let fake_hash = [0u8; 32];
        assert!(!loader.manifest_exists(&fake_hash));

        let hash = loader.store_manifest(&manifest).expect("should store");
        assert!(loader.manifest_exists(&hash));
    }

    #[test]
    fn with_reviewer_v0_manifest_preseeds_store() {
        let loader = InMemoryCasManifestLoader::with_reviewer_v0_manifest();

        // The reviewer v0 manifest should be loadable by its hash
        let reviewer_hash = reviewer_v0_manifest_hash();
        assert!(
            loader.manifest_exists(reviewer_hash),
            "reviewer v0 manifest should be pre-seeded"
        );

        let manifest = loader
            .load_manifest(reviewer_hash)
            .expect("should load reviewer v0 manifest");
        assert_eq!(manifest.manifest_id, "reviewer-v0");
    }

    #[test]
    fn hash_is_deterministic() {
        let loader = InMemoryCasManifestLoader::new();
        let manifest = make_manifest(vec![make_read_capability(
            "cap-1",
            vec![PathBuf::from("/workspace")],
        )]);

        let hash1 = loader.store_manifest(&manifest).expect("should store");
        let hash2 = loader.store_manifest(&manifest).expect("should store");

        assert_eq!(
            hash1, hash2,
            "storing same manifest should produce same hash"
        );
    }
}

// ============================================================================
// TCK-00352: CapabilityManifestV1 Tests
//
// Policy-only capability minting, broker scope enforcement, laundering
// negatives, and envelope-manifest hash mismatch denial.
// ============================================================================

#[cfg(test)]
mod manifest_v1_tests {
    use std::path::PathBuf;

    use super::*;
    use crate::episode::scope::SizeLimits;

    /// Helper: creates a `PolicyMintToken` for test use.
    fn test_mint_token() -> PolicyMintToken {
        PolicyMintToken::new()
    }

    /// Helper: creates a `FixedClock` at the given timestamp.
    fn clock_at(secs: u64) -> FixedClock {
        FixedClock::new(secs)
    }

    /// Helper: creates a valid manifest with expiry for V1 minting.
    fn make_valid_v1_manifest() -> CapabilityManifest {
        CapabilityManifest::builder("v1-test")
            .delegator("policy-resolver")
            .created_at(1000)
            .expires_at(2000)
            .capability(
                Capability::builder("cap-read", ToolClass::Read)
                    .scope(CapabilityScope {
                        root_paths: vec![PathBuf::from("/workspace")],
                        allowed_patterns: Vec::new(),
                        size_limits: SizeLimits::default_limits(),
                        network_policy: None,
                    })
                    .risk_tier(RiskTier::Tier1)
                    .build()
                    .unwrap(),
            )
            .tool_allowlist(vec![ToolClass::Read])
            .build()
            .unwrap()
    }

    // ========================================================================
    // Minting Tests
    // ========================================================================

    #[test]
    fn mint_succeeds_with_valid_manifest_and_token() {
        let manifest = make_valid_v1_manifest();
        let result = CapabilityManifestV1::mint(
            test_mint_token(),
            manifest,
            RiskTier::Tier2,
            vec!["api.example.com".to_string()],
        );
        assert!(result.is_ok());
        let v1 = result.unwrap();
        assert_eq!(v1.risk_tier_ceiling(), RiskTier::Tier2);
        assert_eq!(v1.manifest_id(), "v1-test");
        assert_eq!(v1.delegator_id(), "policy-resolver");
        assert_eq!(v1.expires_at(), 2000);
    }

    #[test]
    fn mint_rejected_without_expiry() {
        // Manifest with expires_at = 0 (no expiry)
        let manifest = CapabilityManifest::builder("no-expiry")
            .delegator("policy-resolver")
            .created_at(1000)
            .expires_at(0) // No expiry!
            .tool_allowlist(vec![ToolClass::Read])
            .build()
            .unwrap();

        let result =
            CapabilityManifestV1::mint(test_mint_token(), manifest, RiskTier::Tier2, Vec::new());
        assert!(matches!(result, Err(ManifestV1Error::MissingExpiry)));
    }

    #[test]
    fn mint_rejected_when_capability_exceeds_risk_ceiling() {
        let manifest = CapabilityManifest::builder("over-tier")
            .delegator("policy-resolver")
            .created_at(1000)
            .expires_at(2000)
            .capability(
                Capability::builder("high-risk-cap", ToolClass::Execute)
                    .scope(CapabilityScope::allow_all())
                    .risk_tier(RiskTier::Tier3)
                    .build()
                    .unwrap(),
            )
            .tool_allowlist(vec![ToolClass::Execute])
            .shell_allowlist(vec!["*".to_string()])
            .build()
            .unwrap();

        // Policy ceiling is Tier1, but capability requires Tier3
        let result = CapabilityManifestV1::mint(
            test_mint_token(),
            manifest,
            RiskTier::Tier1, // Ceiling below capability requirement
            Vec::new(),
        );
        assert!(matches!(
            result,
            Err(ManifestV1Error::RiskTierWidened { .. })
        ));

        if let Err(ManifestV1Error::RiskTierWidened {
            policy_ceiling,
            attempted,
        }) = result
        {
            assert_eq!(policy_ceiling, RiskTier::Tier1);
            assert_eq!(attempted, RiskTier::Tier3);
        }
    }

    #[test]
    fn mint_rejected_with_too_many_host_restrictions() {
        let manifest = make_valid_v1_manifest();
        let hosts: Vec<String> = (0..=MAX_MANIFEST_V1_HOSTS)
            .map(|i| format!("host-{i}.example.com"))
            .collect();

        let result =
            CapabilityManifestV1::mint(test_mint_token(), manifest, RiskTier::Tier2, hosts);
        assert!(matches!(
            result,
            Err(ManifestV1Error::TooManyHostRestrictions { .. })
        ));
    }

    #[test]
    fn mint_rejected_with_host_restriction_too_long() {
        let manifest = make_valid_v1_manifest();
        let long_host = "x".repeat(MAX_HOST_RESTRICTION_LEN + 1);

        let result = CapabilityManifestV1::mint(
            test_mint_token(),
            manifest,
            RiskTier::Tier2,
            vec![long_host],
        );
        assert!(matches!(
            result,
            Err(ManifestV1Error::HostRestrictionTooLong { .. })
        ));
    }

    // ========================================================================
    // Non-Discoverability Tests
    // ========================================================================

    // NOTE: The CapabilityManifestV1 type does NOT expose:
    // - .capabilities() — no enumeration of granted capabilities
    // - .tool_allowlist() — no enumeration of allowed tools
    // - .write_allowlist() — no enumeration of writable paths
    // - .shell_allowlist() — no enumeration of shell patterns
    //
    // The only external interface is validate_request_scoped() which
    // returns Allow or Deny, without revealing what IS allowed.
    //
    // inner() is pub(crate) so only daemon code can access it.

    // ========================================================================
    // Broker Scope Enforcement Tests
    // ========================================================================

    #[test]
    fn broker_scope_allows_valid_request() {
        let manifest = make_valid_v1_manifest();
        let v1 = CapabilityManifestV1::mint(
            test_mint_token(),
            manifest,
            RiskTier::Tier2,
            vec!["api.example.com".to_string()],
        )
        .unwrap();

        let request = ToolRequest::new(ToolClass::Read, RiskTier::Tier1)
            .with_path("/workspace/file.rs")
            .with_size(1024);

        let decision = v1.validate_request_scoped(&request, &clock_at(1500));
        assert!(
            decision.is_allowed(),
            "valid scoped request should be allowed"
        );
    }

    #[test]
    fn broker_scope_denies_request_above_risk_ceiling() {
        let manifest = make_valid_v1_manifest();
        let v1 = CapabilityManifestV1::mint(
            test_mint_token(),
            manifest,
            RiskTier::Tier1, // Ceiling at Tier1
            Vec::new(),
        )
        .unwrap();

        // Request at Tier2, above ceiling
        let request =
            ToolRequest::new(ToolClass::Read, RiskTier::Tier2).with_path("/workspace/file.rs");

        let decision = v1.validate_request_scoped(&request, &clock_at(1500));
        assert!(decision.is_denied(), "request above ceiling must be denied");
        if let CapabilityDecision::Deny { reason } = decision {
            assert!(matches!(reason, DenyReason::InsufficientRiskTier { .. }));
        }
    }

    #[test]
    fn broker_scope_denies_network_to_unauthorized_host() {
        // Create manifest with Network capability and host restrictions
        let manifest = CapabilityManifest::builder("net-test")
            .delegator("policy-resolver")
            .created_at(1000)
            .expires_at(2000)
            .capability(
                Capability::builder("net-cap", ToolClass::Network)
                    .scope(CapabilityScope {
                        root_paths: Vec::new(),
                        allowed_patterns: Vec::new(),
                        size_limits: SizeLimits::default_limits(),
                        network_policy: Some(super::super::scope::NetworkPolicy {
                            allowed_hosts: vec!["*.example.com".to_string()],
                            allowed_ports: vec![443],
                            require_tls: true,
                        }),
                    })
                    .risk_tier(RiskTier::Tier1)
                    .build()
                    .unwrap(),
            )
            .tool_allowlist(vec![ToolClass::Network])
            .build()
            .unwrap();

        let v1 = CapabilityManifestV1::mint(
            test_mint_token(),
            manifest,
            RiskTier::Tier2,
            vec!["*.example.com".to_string()], // Only example.com allowed
        )
        .unwrap();

        // Allowed host
        let request = ToolRequest::new(ToolClass::Network, RiskTier::Tier1)
            .with_network("api.example.com", 443);
        let decision = v1.validate_request_scoped(&request, &clock_at(1500));
        assert!(decision.is_allowed(), "allowed host should pass");

        // Denied host — not in host restrictions
        let request =
            ToolRequest::new(ToolClass::Network, RiskTier::Tier1).with_network("evil.com", 443);
        let decision = v1.validate_request_scoped(&request, &clock_at(1500));
        assert!(decision.is_denied(), "unauthorized host must be denied");
        if let CapabilityDecision::Deny { reason } = decision {
            assert!(
                matches!(reason, DenyReason::NetworkNotAllowed { .. }),
                "expected NetworkNotAllowed, got {reason:?}"
            );
        }
    }

    #[test]
    fn broker_scope_denies_expired_manifest() {
        let manifest = make_valid_v1_manifest(); // expires_at = 2000
        let v1 =
            CapabilityManifestV1::mint(test_mint_token(), manifest, RiskTier::Tier2, Vec::new())
                .unwrap();

        // Request at Tier1 to match the capability's risk_tier_required
        let request =
            ToolRequest::new(ToolClass::Read, RiskTier::Tier1).with_path("/workspace/file.rs");

        // Before expiry — should be allowed
        let decision = v1.validate_request_scoped(&request, &clock_at(1500));
        assert!(decision.is_allowed(), "should be valid before expiry");

        // After expiry — should be denied
        let decision = v1.validate_request_scoped(&request, &clock_at(2500));
        assert!(decision.is_denied(), "must deny after expiry");
        if let CapabilityDecision::Deny { reason } = decision {
            assert!(matches!(reason, DenyReason::ManifestExpired));
        }
    }

    #[test]
    fn broker_scope_denies_out_of_scope_path() {
        let manifest = make_valid_v1_manifest();
        let v1 =
            CapabilityManifestV1::mint(test_mint_token(), manifest, RiskTier::Tier2, Vec::new())
                .unwrap();

        let request = ToolRequest::new(ToolClass::Read, RiskTier::Tier1).with_path("/etc/passwd"); // Not in /workspace

        let decision = v1.validate_request_scoped(&request, &clock_at(1500));
        assert!(decision.is_denied(), "out-of-scope path must be denied");
        if let CapabilityDecision::Deny { reason } = decision {
            assert!(matches!(reason, DenyReason::PathNotAllowed { .. }));
        }
    }

    #[test]
    fn broker_scope_denies_tool_not_in_allowlist() {
        let manifest = make_valid_v1_manifest(); // Only Read in allowlist
        let v1 =
            CapabilityManifestV1::mint(test_mint_token(), manifest, RiskTier::Tier2, Vec::new())
                .unwrap();

        let request =
            ToolRequest::new(ToolClass::Write, RiskTier::Tier1).with_path("/workspace/file.rs");

        let decision = v1.validate_request_scoped(&request, &clock_at(1500));
        assert!(decision.is_denied(), "non-allowlisted tool must be denied");
        if let CapabilityDecision::Deny { reason } = decision {
            assert!(matches!(reason, DenyReason::ToolNotInAllowlist { .. }));
        }
    }

    #[test]
    fn broker_scope_empty_host_restrictions_denies_all_network() {
        let manifest = CapabilityManifest::builder("net-empty")
            .delegator("policy-resolver")
            .created_at(1000)
            .expires_at(2000)
            .capability(
                Capability::builder("net-cap", ToolClass::Network)
                    .scope(CapabilityScope {
                        root_paths: Vec::new(),
                        allowed_patterns: Vec::new(),
                        size_limits: SizeLimits::default_limits(),
                        network_policy: Some(super::super::scope::NetworkPolicy {
                            allowed_hosts: vec!["*".to_string()],
                            allowed_ports: vec![443],
                            require_tls: false,
                        }),
                    })
                    .build()
                    .unwrap(),
            )
            .tool_allowlist(vec![ToolClass::Network])
            .build()
            .unwrap();

        let v1 = CapabilityManifestV1::mint(
            test_mint_token(),
            manifest,
            RiskTier::Tier2,
            Vec::new(), // Empty host restrictions!
        )
        .unwrap();

        let request =
            ToolRequest::new(ToolClass::Network, RiskTier::Tier0).with_network("any.host.com", 443);
        let decision = v1.validate_request_scoped(&request, &clock_at(1500));
        assert!(
            decision.is_denied(),
            "empty host restrictions must deny all network requests"
        );
    }

    // ========================================================================
    // Envelope-Manifest Hash Mismatch Tests
    // ========================================================================

    #[test]
    fn envelope_binding_accepts_matching_hash() {
        let manifest = make_valid_v1_manifest();
        let v1 =
            CapabilityManifestV1::mint(test_mint_token(), manifest, RiskTier::Tier2, Vec::new())
                .unwrap();

        let digest = v1.digest();
        assert!(v1.verify_envelope_binding(&digest).is_ok());
    }

    #[test]
    fn envelope_binding_rejects_mismatched_hash() {
        let manifest = make_valid_v1_manifest();
        let v1 =
            CapabilityManifestV1::mint(test_mint_token(), manifest, RiskTier::Tier2, Vec::new())
                .unwrap();

        let wrong_hash = [0xAAu8; 32];
        let result = v1.verify_envelope_binding(&wrong_hash);
        assert!(matches!(
            result,
            Err(ManifestV1Error::EnvelopeManifestHashMismatch { .. })
        ));
    }

    #[test]
    fn envelope_binding_rejects_wrong_length_hash() {
        let manifest = make_valid_v1_manifest();
        let v1 =
            CapabilityManifestV1::mint(test_mint_token(), manifest, RiskTier::Tier2, Vec::new())
                .unwrap();

        // Too short
        let short_hash = [0u8; 16];
        let result = v1.verify_envelope_binding(&short_hash);
        assert!(matches!(
            result,
            Err(ManifestV1Error::EnvelopeManifestHashMismatch { .. })
        ));

        // Too long
        let long_hash = [0u8; 64];
        let result = v1.verify_envelope_binding(&long_hash);
        assert!(matches!(
            result,
            Err(ManifestV1Error::EnvelopeManifestHashMismatch { .. })
        ));
    }

    #[test]
    fn envelope_binding_rejects_empty_hash() {
        let manifest = make_valid_v1_manifest();
        let v1 =
            CapabilityManifestV1::mint(test_mint_token(), manifest, RiskTier::Tier2, Vec::new())
                .unwrap();

        let result = v1.verify_envelope_binding(&[]);
        assert!(matches!(
            result,
            Err(ManifestV1Error::EnvelopeManifestHashMismatch { .. })
        ));
    }

    // ========================================================================
    // Laundering Negative Tests
    // ========================================================================

    #[test]
    fn laundering_widened_risk_tier_denied() {
        // Attempt: Capability requests Tier4, policy ceiling is Tier2
        let manifest = CapabilityManifest::builder("launder-tier")
            .delegator("policy-resolver")
            .created_at(1000)
            .expires_at(2000)
            .capability(
                Capability::builder("high-cap", ToolClass::Read)
                    .scope(CapabilityScope {
                        root_paths: vec![PathBuf::from("/workspace")],
                        allowed_patterns: Vec::new(),
                        size_limits: SizeLimits::default_limits(),
                        network_policy: None,
                    })
                    .risk_tier(RiskTier::Tier4) // Exceeds ceiling
                    .build()
                    .unwrap(),
            )
            .tool_allowlist(vec![ToolClass::Read])
            .build()
            .unwrap();

        let result = CapabilityManifestV1::mint(
            test_mint_token(),
            manifest,
            RiskTier::Tier2, // Policy ceiling
            Vec::new(),
        );
        assert!(
            matches!(result, Err(ManifestV1Error::RiskTierWidened { .. })),
            "widened risk tier must be rejected at mint time"
        );
    }

    #[test]
    fn laundering_missing_expiry_denied() {
        // Attempt: Create manifest without expiry
        let manifest = CapabilityManifest::builder("launder-expiry")
            .delegator("policy-resolver")
            .created_at(1000)
            .expires_at(0) // No expiry!
            .tool_allowlist(vec![ToolClass::Read])
            .build()
            .unwrap();

        let result =
            CapabilityManifestV1::mint(test_mint_token(), manifest, RiskTier::Tier2, Vec::new());
        assert!(
            matches!(result, Err(ManifestV1Error::MissingExpiry)),
            "missing expiry must be rejected at mint time"
        );
    }

    #[test]
    fn laundering_overbroad_tool_scope_denied() {
        let manifest = CapabilityManifest::builder("launder-tools")
            .delegator("policy-resolver")
            .created_at(1000)
            .expires_at(2000)
            .tool_allowlist(vec![
                ToolClass::Read,
                ToolClass::Write,
                ToolClass::Execute,
                ToolClass::Git,
                ToolClass::Network,
            ])
            .build()
            .unwrap();

        // Policy only permits 2 tools
        let result = validate_manifest_scope_bounds(&manifest, 2, 100, 100);
        assert!(
            matches!(result, Err(ManifestV1Error::OverbroadScope { .. })),
            "overbroad tool allowlist must be rejected"
        );
    }

    #[test]
    fn laundering_overbroad_write_paths_denied() {
        let manifest = CapabilityManifest::builder("launder-paths")
            .delegator("policy-resolver")
            .created_at(1000)
            .expires_at(2000)
            .write_allowlist(vec![
                PathBuf::from("/workspace"),
                PathBuf::from("/tmp"),
                PathBuf::from("/var"),
            ])
            .build()
            .unwrap();

        // Policy only permits 1 write path
        let result = validate_manifest_scope_bounds(&manifest, 100, 1, 100);
        assert!(
            matches!(result, Err(ManifestV1Error::OverbroadScope { .. })),
            "overbroad write paths must be rejected"
        );
    }

    #[test]
    fn laundering_overbroad_shell_patterns_denied() {
        let manifest = CapabilityManifest::builder("launder-shell")
            .delegator("policy-resolver")
            .created_at(1000)
            .expires_at(2000)
            .shell_allowlist(vec!["*".to_string(), "cargo *".to_string()])
            .build()
            .unwrap();

        // Policy only permits 0 shell patterns
        let result = validate_manifest_scope_bounds(&manifest, 100, 100, 0);
        assert!(
            matches!(result, Err(ManifestV1Error::OverbroadScope { .. })),
            "overbroad shell patterns must be rejected"
        );
    }

    #[test]
    fn laundering_request_at_runtime_above_ceiling_denied() {
        // Even if the manifest is validly minted, runtime requests above
        // the ceiling are denied.
        let manifest = make_valid_v1_manifest(); // Has Tier1 capability
        let v1 = CapabilityManifestV1::mint(
            test_mint_token(),
            manifest,
            RiskTier::Tier1, // Ceiling at Tier1
            Vec::new(),
        )
        .unwrap();

        // Runtime request at Tier2 (above ceiling)
        let request =
            ToolRequest::new(ToolClass::Read, RiskTier::Tier2).with_path("/workspace/file.rs");
        let decision = v1.validate_request_scoped(&request, &clock_at(1500));
        assert!(
            decision.is_denied(),
            "runtime request above ceiling must be denied"
        );
    }

    #[test]
    fn valid_scope_bounds_accepted() {
        let manifest = CapabilityManifest::builder("valid-scope")
            .delegator("policy-resolver")
            .created_at(1000)
            .expires_at(2000)
            .tool_allowlist(vec![ToolClass::Read])
            .write_allowlist(vec![PathBuf::from("/workspace")])
            .shell_allowlist(vec!["cargo test".to_string()])
            .build()
            .unwrap();

        let result = validate_manifest_scope_bounds(&manifest, 5, 5, 5);
        assert!(result.is_ok(), "valid scope bounds should be accepted");
    }

    // ========================================================================
    // Host Restriction Pattern Tests
    // ========================================================================

    #[test]
    fn host_restriction_wildcard_domain_match() {
        let manifest = make_valid_v1_manifest();
        let v1 = CapabilityManifestV1::mint(
            test_mint_token(),
            manifest,
            RiskTier::Tier2,
            vec!["*.example.com".to_string()],
        )
        .unwrap();

        assert!(v1.is_host_allowed("api.example.com"));
        assert!(v1.is_host_allowed("sub.example.com"));
        assert!(!v1.is_host_allowed("example.com")); // Not a subdomain
        assert!(!v1.is_host_allowed("evil.com"));
        assert!(!v1.is_host_allowed("notexample.com"));
    }

    #[test]
    fn host_restriction_exact_match() {
        let manifest = make_valid_v1_manifest();
        let v1 = CapabilityManifestV1::mint(
            test_mint_token(),
            manifest,
            RiskTier::Tier2,
            vec!["exact.host.com".to_string()],
        )
        .unwrap();

        assert!(v1.is_host_allowed("exact.host.com"));
        assert!(!v1.is_host_allowed("other.host.com"));
        assert!(!v1.is_host_allowed("sub.exact.host.com"));
    }

    #[test]
    fn host_restriction_multiple_entries() {
        let manifest = make_valid_v1_manifest();
        let v1 = CapabilityManifestV1::mint(
            test_mint_token(),
            manifest,
            RiskTier::Tier2,
            vec!["api.github.com".to_string(), "*.internal.corp".to_string()],
        )
        .unwrap();

        assert!(v1.is_host_allowed("api.github.com"));
        assert!(v1.is_host_allowed("svc.internal.corp"));
        assert!(!v1.is_host_allowed("evil.com"));
    }

    // ========================================================================
    // Digest Consistency Tests
    // ========================================================================

    #[test]
    fn v1_digest_matches_inner_manifest_digest() {
        let manifest = make_valid_v1_manifest();
        let expected_digest = manifest.digest();
        let v1 =
            CapabilityManifestV1::mint(test_mint_token(), manifest, RiskTier::Tier2, Vec::new())
                .unwrap();

        assert_eq!(
            v1.digest(),
            expected_digest,
            "V1 digest must match inner manifest digest for envelope binding"
        );
    }

    // ========================================================================
    // TCK-00352 Security Review MAJOR 1: Strict-subset counterexample tests
    //
    // Verify that same-cardinality substitutions are rejected by
    // validate_manifest_scope_subset.
    // ========================================================================

    #[test]
    fn subset_rejects_tool_substitution_same_cardinality() {
        // Baseline: policy permits [Read, Write]
        let baseline = ScopeBaseline {
            tools: vec![ToolClass::Read, ToolClass::Write],
            write_paths: vec![PathBuf::from("/workspace")],
            shell_patterns: vec!["cargo test".to_string()],
        };

        // Manifest substitutes Write with Execute (same count = 2)
        let manifest = CapabilityManifest::builder("launder-subst")
            .delegator("policy-resolver")
            .created_at(1000)
            .expires_at(2000)
            .tool_allowlist(vec![ToolClass::Read, ToolClass::Execute]) // Execute not in baseline!
            .write_allowlist(vec![PathBuf::from("/workspace")])
            .shell_allowlist(vec!["cargo test".to_string()])
            .build()
            .unwrap();

        let result = validate_manifest_scope_subset(&manifest, &baseline);
        assert!(
            matches!(result, Err(ManifestV1Error::OverbroadScope { .. })),
            "same-cardinality tool substitution must be rejected: {result:?}"
        );
    }

    #[test]
    fn subset_rejects_write_path_substitution_same_cardinality() {
        let baseline = ScopeBaseline {
            tools: vec![ToolClass::Read],
            write_paths: vec![PathBuf::from("/workspace")],
            shell_patterns: Vec::new(),
        };

        // Manifest substitutes /workspace with /etc (same count = 1)
        let manifest = CapabilityManifest::builder("launder-path")
            .delegator("policy-resolver")
            .created_at(1000)
            .expires_at(2000)
            .tool_allowlist(vec![ToolClass::Read])
            .write_allowlist(vec![PathBuf::from("/etc")]) // Not in baseline!
            .build()
            .unwrap();

        let result = validate_manifest_scope_subset(&manifest, &baseline);
        assert!(
            matches!(result, Err(ManifestV1Error::OverbroadScope { .. })),
            "same-cardinality write path substitution must be rejected: {result:?}"
        );
    }

    #[test]
    fn subset_rejects_shell_pattern_substitution_same_cardinality() {
        let baseline = ScopeBaseline {
            tools: Vec::new(),
            write_paths: Vec::new(),
            shell_patterns: vec!["cargo test".to_string()],
        };

        // Manifest substitutes "cargo test" with "rm -rf /" (same count = 1)
        let manifest = CapabilityManifest::builder("launder-shell")
            .delegator("policy-resolver")
            .created_at(1000)
            .expires_at(2000)
            .shell_allowlist(vec!["rm -rf /".to_string()]) // Not in baseline!
            .build()
            .unwrap();

        let result = validate_manifest_scope_subset(&manifest, &baseline);
        assert!(
            matches!(result, Err(ManifestV1Error::OverbroadScope { .. })),
            "same-cardinality shell pattern substitution must be rejected: {result:?}"
        );
    }

    #[test]
    fn subset_accepts_valid_subset() {
        let baseline = ScopeBaseline {
            tools: vec![ToolClass::Read, ToolClass::Write, ToolClass::Execute],
            write_paths: vec![PathBuf::from("/workspace"), PathBuf::from("/tmp")],
            shell_patterns: vec!["cargo test".to_string(), "cargo build".to_string()],
        };

        // Manifest uses a strict subset of the baseline
        let manifest = CapabilityManifest::builder("valid-subset")
            .delegator("policy-resolver")
            .created_at(1000)
            .expires_at(2000)
            .tool_allowlist(vec![ToolClass::Read, ToolClass::Write])
            .write_allowlist(vec![PathBuf::from("/workspace")])
            .shell_allowlist(vec!["cargo test".to_string()])
            .build()
            .unwrap();

        let result = validate_manifest_scope_subset(&manifest, &baseline);
        assert!(
            result.is_ok(),
            "valid subset should be accepted: {result:?}"
        );
    }

    // ========================================================================
    // TCK-00352 Security Review MAJOR 2: V1 wiring integration tests
    //
    // Prove that V1 validation is exercised through real request flow:
    // deny on envelope mismatch, scope widening, and unauthorized hosts.
    // ========================================================================

    #[test]
    fn v1_denies_request_with_envelope_hash_mismatch() {
        let manifest = make_valid_v1_manifest();
        let v1 =
            CapabilityManifestV1::mint(test_mint_token(), manifest, RiskTier::Tier2, Vec::new())
                .unwrap();

        // Simulate envelope with wrong hash
        let wrong_hash = [0xFFu8; 32];
        let result = v1.verify_envelope_binding(&wrong_hash);
        assert!(
            matches!(
                result,
                Err(ManifestV1Error::EnvelopeManifestHashMismatch { .. })
            ),
            "envelope-manifest hash mismatch must be denied"
        );
    }

    #[test]
    fn v1_denies_scope_widening_at_request_time() {
        let manifest = make_valid_v1_manifest(); // Tier1 Read-only
        let v1 = CapabilityManifestV1::mint(
            test_mint_token(),
            manifest,
            RiskTier::Tier1, // Ceiling at Tier1
            Vec::new(),
        )
        .unwrap();

        // Request at Tier2 should be denied (scope widening)
        let request =
            ToolRequest::new(ToolClass::Read, RiskTier::Tier2).with_path("/workspace/file.rs");
        let decision = v1.validate_request_scoped(&request, &clock_at(1500));
        assert!(decision.is_denied(), "scope widening must be denied");
        if let CapabilityDecision::Deny { reason } = decision {
            assert!(
                matches!(reason, DenyReason::InsufficientRiskTier { .. }),
                "expected InsufficientRiskTier, got {reason:?}"
            );
        }
    }

    #[test]
    fn v1_denies_unauthorized_host_through_real_flow() {
        let manifest = CapabilityManifest::builder("net-flow")
            .delegator("policy-resolver")
            .created_at(1000)
            .expires_at(2000)
            .capability(
                Capability::builder("net-cap", ToolClass::Network)
                    .scope(CapabilityScope {
                        root_paths: Vec::new(),
                        allowed_patterns: Vec::new(),
                        size_limits: SizeLimits::default_limits(),
                        network_policy: Some(super::super::scope::NetworkPolicy {
                            allowed_hosts: vec!["*.trusted.com".to_string()],
                            allowed_ports: vec![443],
                            require_tls: true,
                        }),
                    })
                    .risk_tier(RiskTier::Tier1)
                    .build()
                    .unwrap(),
            )
            .tool_allowlist(vec![ToolClass::Network])
            .build()
            .unwrap();

        let v1 = CapabilityManifestV1::mint(
            test_mint_token(),
            manifest,
            RiskTier::Tier2,
            vec!["*.trusted.com".to_string()],
        )
        .unwrap();

        // Unauthorized host through the real V1 validation path
        let request = ToolRequest::new(ToolClass::Network, RiskTier::Tier1)
            .with_network("evil-host.attacker.com", 443);
        let decision = v1.validate_request_scoped(&request, &clock_at(1500));
        assert!(decision.is_denied(), "unauthorized host must be denied");
        if let CapabilityDecision::Deny { reason } = decision {
            assert!(
                matches!(reason, DenyReason::NetworkNotAllowed { .. }),
                "expected NetworkNotAllowed, got {reason:?}"
            );
        }

        // Authorized host should pass
        let request = ToolRequest::new(ToolClass::Network, RiskTier::Tier1)
            .with_network("api.trusted.com", 443);
        let decision = v1.validate_request_scoped(&request, &clock_at(1500));
        assert!(decision.is_allowed(), "authorized host should be allowed");
    }

    // ========================================================================
    // MAJOR 1 v3: Scope baseline MUST be independent of candidate manifest
    // ========================================================================

    /// MAJOR 1 v3: A manifest with wider scope than the policy baseline is
    /// rejected. This proves that building the baseline from the manifest
    /// itself (tautological check) is no longer the behavior.
    #[test]
    fn subset_rejects_manifest_with_wider_scope_than_policy_baseline() {
        // Policy baseline only allows Read
        let policy_baseline = ScopeBaseline {
            tools: vec![ToolClass::Read],
            write_paths: vec![PathBuf::from("/workspace")],
            shell_patterns: vec![],
        };

        // Candidate manifest tries to also include Write and Execute
        let wider_manifest = CapabilityManifest::builder("wider-scope")
            .delegator("attacker")
            .created_at(1000)
            .expires_at(2000)
            .tool_allowlist(vec![ToolClass::Read, ToolClass::Write, ToolClass::Execute])
            .write_allowlist(vec![PathBuf::from("/workspace"), PathBuf::from("/etc")])
            .shell_allowlist(vec!["rm -rf /".to_string()])
            .build()
            .unwrap();

        let result = validate_manifest_scope_subset(&wider_manifest, &policy_baseline);
        assert!(
            result.is_err(),
            "manifest with wider scope than policy baseline must be rejected"
        );
        let err = result.unwrap_err();
        match err {
            ManifestV1Error::OverbroadScope { reason } => {
                // The error should indicate the tool allowlist exceeds baseline
                assert!(
                    reason.contains("tool") || reason.contains("write") || reason.contains("shell"),
                    "error reason should indicate which scope dimension exceeded: {reason}"
                );
            },
            other => panic!("expected OverbroadScope error, got: {other:?}"),
        }
    }

    /// MAJOR 1 v3: A manifest that matches the baseline exactly is accepted.
    /// This is the happy path when policy resolver provides the correct
    /// baseline.
    #[test]
    fn subset_accepts_manifest_matching_policy_baseline_exactly() {
        let policy_baseline = ScopeBaseline {
            tools: vec![ToolClass::Read, ToolClass::Git],
            write_paths: vec![],
            shell_patterns: vec![],
        };

        let manifest = CapabilityManifest::builder("exact-match")
            .delegator("policy-resolver")
            .created_at(1000)
            .expires_at(2000)
            .tool_allowlist(vec![ToolClass::Read, ToolClass::Git])
            .build()
            .unwrap();

        let result = validate_manifest_scope_subset(&manifest, &policy_baseline);
        assert!(
            result.is_ok(),
            "manifest matching policy baseline exactly should be accepted: {result:?}"
        );
    }

    /// MAJOR 1 v3: Substitution attack (same cardinality but different tools)
    /// is detected by strict-subset check against an independent baseline.
    #[test]
    fn subset_rejects_substitution_attack_with_independent_baseline() {
        // Policy baseline allows Read and Git
        let policy_baseline = ScopeBaseline {
            tools: vec![ToolClass::Read, ToolClass::Git],
            write_paths: vec![],
            shell_patterns: vec![],
        };

        // Attacker substitutes Git -> Execute (same cardinality of 2)
        let substituted_manifest = CapabilityManifest::builder("substitution")
            .delegator("attacker")
            .created_at(1000)
            .expires_at(2000)
            .tool_allowlist(vec![ToolClass::Read, ToolClass::Execute])
            .build()
            .unwrap();

        let result = validate_manifest_scope_subset(&substituted_manifest, &policy_baseline);
        assert!(
            result.is_err(),
            "substitution attack (Read+Execute vs policy Read+Git) must be rejected"
        );
        let err = result.unwrap_err();
        match err {
            ManifestV1Error::OverbroadScope { reason } => {
                assert!(
                    reason.contains("Execute"),
                    "error should identify the substituted tool class: {reason}"
                );
            },
            other => panic!("expected OverbroadScope error for substitution, got: {other:?}"),
        }
    }
}
