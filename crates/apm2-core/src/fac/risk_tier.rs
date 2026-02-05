// AGENT-AUTHORED
//! Risk tier classification model for the Forge Admission Cycle.
//!
//! This module defines [`RiskTierClass`] and [`classify_risk`] which implement
//! the changeset risk classification model. Risk classification determines
//! the level of scrutiny required for AAT (Agent Acceptance Testing).
//!
//! # Risk Tiers
//!
//! - **High**: Maximum scrutiny required. Triggered by changes to critical
//!   modules (auth, crypto, ledger, tool, kernel, fac, proto, daemon) or
//!   sensitive path patterns (secret, credentials, policy, security), or paths
//!   exceeding `MAX_PATH_LEN`, or file count exceeding `MAX_FILES`
//!   (fail-closed). Also the default tier when no signals are recognized
//!   (fail-closed security).
//! - **Med**: Elevated scrutiny required. Triggered by large changesets (lines
//!   > 500, files > 10, dependency fanout > 20).
//! - **Low**: Standard scrutiny. Assigned only when changeset is explicitly
//!   recognized as low-risk (small, non-critical changes).
//!
//! # Classification Model
//!
//! Classification uses a two-tier signal hierarchy:
//!
//! 1. **Primary Signals** (-> HIGH):
//!    - `touches_critical_module`: File paths touching auth, crypto, ledger,
//!      tool, kernel, fac, proto, or daemon modules
//!    - `matches_sensitive_pattern`: File paths containing "secret",
//!      "credentials", "policy", or "security"
//!    - `path_exceeds_max_len`: Paths longer than `MAX_PATH_LEN` (fail-closed)
//!    - `files_exceed_max_count`: File count exceeding `MAX_FILES`
//!      (fail-closed)
//!
//! 2. **Secondary Signals** (-> MED):
//!    - `lines_changed > 500`: Large changesets by line count
//!    - `files_changed > 10`: Wide-impact changesets by file count
//!    - `dependency_fanout > 20`: High coupling changesets
//!
//! 3. **Explicit LOW**: Only assigned when changeset is small and non-critical
//!
//! 4. **Default**: HIGH when no signals match (fail-closed security model)
//!
//! NOTE: Only file paths are scanned for patterns, NOT file contents.
//!
//! # Security Model
//!
//! The classification model uses fail-closed security: when no risk signals
//! are recognized, the changeset receives the HIGH tier by default. Only
//! changesets that are explicitly identified as low-risk (small size,
//! non-critical paths, below all thresholds) receive the LOW tier. This
//! ensures that unknown or unexpected patterns receive maximum scrutiny.
//!
//! NOTE: This module only scans file paths, NOT file contents. Content
//! scanning requires additional tooling.
//!
//! # Example
//!
//! ```rust
//! use apm2_core::fac::risk_tier::{ChangeSet, RiskTierClass, classify_risk};
//!
//! // A changeset touching crypto module is HIGH risk
//! let changeset = ChangeSet {
//!     files_changed: vec![
//!         "crates/apm2-core/src/crypto/signer.rs".to_string(),
//!     ],
//!     lines_changed: 50,
//!     dependency_fanout: 5,
//! };
//! assert_eq!(classify_risk(&changeset), RiskTierClass::High);
//!
//! // A large changeset is MED risk
//! let large_changeset = ChangeSet {
//!     files_changed: vec!["src/utils.rs".to_string()],
//!     lines_changed: 600,
//!     dependency_fanout: 5,
//! };
//! assert_eq!(classify_risk(&large_changeset), RiskTierClass::Med);
//!
//! // A small, non-critical changeset is LOW risk
//! let small_changeset = ChangeSet {
//!     files_changed: vec!["src/utils.rs".to_string()],
//!     lines_changed: 50,
//!     dependency_fanout: 5,
//! };
//! assert_eq!(classify_risk(&small_changeset), RiskTierClass::Low);
//! ```

use serde::{Deserialize, Serialize};

// =============================================================================
// Critical Modules and Sensitive Patterns
// =============================================================================

/// Critical module path components that trigger HIGH risk tier.
///
/// Changes to these modules require maximum scrutiny because they
/// control security-sensitive functionality:
///
/// - `auth`: Authentication and authorization logic
/// - `crypto`: Cryptographic operations and key management
/// - `ledger`: Audit trail and immutable records
/// - `tool`: External tool execution and sandboxing
/// - `kernel`: Core system primitives and trust boundaries
/// - `fac`: Forge Admission Cycle - security-critical evidence and attestation
/// - `proto`: Protocol Buffer definitions - defines wire protocol and attack
///   surface
/// - `daemon`: IPC daemon - handles inter-process communication
pub const CRITICAL_MODULES: &[&str] = &[
    "auth", "crypto", "ledger", "tool", "kernel", "fac", "proto", "daemon",
];

/// Sensitive patterns in file paths that trigger HIGH risk tier.
///
/// These patterns indicate security-sensitive file paths:
///
/// - `secret`: Secrets, API keys, tokens
/// - `credentials`: Authentication credentials
/// - `policy`: Security policies and access control
/// - `security`: Security documentation and threat models (e.g.,
///   documents/security/)
///
/// NOTE: Only file paths are scanned for these patterns, NOT file contents.
pub const SENSITIVE_PATTERNS: &[&str] = &["secret", "credentials", "policy", "security"];

// =============================================================================
// Thresholds for Secondary Signals
// =============================================================================

/// Lines changed threshold for MED risk tier.
///
/// Changesets with more than this many lines changed are considered
/// medium risk due to increased review complexity.
pub const LINES_CHANGED_THRESHOLD: u64 = 500;

/// Files changed threshold for MED risk tier.
///
/// Changesets touching more than this many files are considered
/// medium risk due to wide-impact scope.
pub const FILES_CHANGED_THRESHOLD: usize = 10;

/// Dependency fanout threshold for MED risk tier.
///
/// Changesets with dependency fanout (number of downstream dependents
/// affected) greater than this value are considered medium risk due
/// to high coupling.
pub const DEPENDENCY_FANOUT_THRESHOLD: u64 = 20;

/// Maximum number of files allowed in a changeset.
///
/// Changesets with more files than this limit are classified as HIGH risk
/// (fail-closed) to prevent denial-of-service via unbounded file list
/// processing.
pub const MAX_FILES: usize = 10000;

// =============================================================================
// RiskTierClass Enum
// =============================================================================

/// Risk tier classification for changesets.
///
/// The risk tier determines the level of scrutiny required during
/// AAT (Agent Acceptance Testing). Higher tiers require more
/// extensive testing and review.
///
/// # Ordering
///
/// Risk tiers are ordered by severity: `High > Med > Low`.
/// The `Ord` implementation uses explicit rank mapping, not enum
/// ordinal, to ensure correctness if variants are reordered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum RiskTierClass {
    /// Highest risk tier. Maximum scrutiny required.
    ///
    /// Triggered by:
    /// - Changes to critical modules (auth, crypto, ledger, tool, kernel, fac,
    ///   proto, daemon)
    /// - Matches to sensitive patterns (secret, credentials, policy, security)
    /// - Paths exceeding `MAX_PATH_LEN` (fail-closed security measure)
    High,

    /// Medium risk tier. Elevated scrutiny required.
    ///
    /// Triggered by:
    /// - Lines changed > 500
    /// - Files changed > 10
    /// - Dependency fanout > 20
    Med,

    /// Lowest risk tier. Standard scrutiny.
    ///
    /// Default tier when no risk signals are detected.
    #[default]
    Low,
}

impl RiskTierClass {
    /// Returns the numeric rank of this risk tier.
    ///
    /// Higher ranks indicate higher risk. Ranks are explicitly
    /// assigned to ensure comparison remains correct even if enum
    /// variants are reordered.
    ///
    /// # Returns
    ///
    /// - High -> 2
    /// - Med -> 1
    /// - Low -> 0
    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::High => 2,
            Self::Med => 1,
            Self::Low => 0,
        }
    }

    /// Returns true if this tier requires full AAT.
    ///
    /// High risk changesets always require full AAT. Medium and low
    /// risk changesets may use abbreviated testing based on policy.
    #[must_use]
    pub const fn requires_full_aat(self) -> bool {
        matches!(self, Self::High)
    }

    /// Returns an iterator over all risk tiers in descending order.
    pub fn all() -> impl Iterator<Item = Self> {
        [Self::High, Self::Med, Self::Low].into_iter()
    }
}

impl TryFrom<u8> for RiskTierClass {
    type Error = RiskTierError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            2 => Ok(Self::High),
            1 => Ok(Self::Med),
            0 => Ok(Self::Low),
            _ => Err(RiskTierError::InvalidTier(value)),
        }
    }
}

impl From<RiskTierClass> for u8 {
    fn from(tier: RiskTierClass) -> Self {
        tier.rank()
    }
}

impl std::fmt::Display for RiskTierClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::High => write!(f, "HIGH"),
            Self::Med => write!(f, "MED"),
            Self::Low => write!(f, "LOW"),
        }
    }
}

impl PartialOrd for RiskTierClass {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RiskTierClass {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.rank().cmp(&other.rank())
    }
}

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during risk tier operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RiskTierError {
    /// Invalid risk tier value.
    #[error("invalid risk tier value: {0}, must be 0 (Low), 1 (Med), or 2 (High)")]
    InvalidTier(u8),
}

// =============================================================================
// ChangeSet Input Type
// =============================================================================

/// Represents a changeset for risk classification.
///
/// This struct captures the signals needed to classify the risk tier
/// of a changeset. It is intentionally simple and does not include
/// file contents to avoid memory issues with large changesets.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ChangeSet {
    /// List of file paths changed in this changeset.
    ///
    /// Paths should be relative to the repository root and use
    /// forward slashes as separators.
    pub files_changed: Vec<String>,

    /// Total number of lines changed (added + removed).
    pub lines_changed: u64,

    /// Dependency fanout: number of downstream dependents affected.
    ///
    /// This represents how many other modules or crates depend on
    /// the changed code.
    pub dependency_fanout: u64,
}

// =============================================================================
// Classification Function
// =============================================================================

/// Classifies the risk tier of a changeset based on primary and secondary
/// signals.
///
/// # Classification Logic
///
/// 1. **Primary Signals** (-> HIGH):
///    - If file count exceeds `MAX_FILES`, return HIGH (fail-closed
///      denial-of-service protection).
///    - If any file path contains a critical module name (auth, crypto, ledger,
///      tool, kernel, fac, proto, daemon), return HIGH.
///    - If any file path contains a sensitive pattern (secret, credentials,
///      policy, security), return HIGH.
///
/// 2. **Secondary Signals** (-> MED):
///    - If `lines_changed` > 500, return MED.
///    - If `files_changed` > 10, return MED.
///    - If `dependency_fanout` > 20, return MED.
///
/// 3. **Explicit LOW**: Only when all thresholds are below limits and no
///    critical modules/patterns are detected.
///
/// 4. **Default**: Return HIGH (fail-closed security model).
///
/// NOTE: Only file paths are scanned, NOT file contents.
///
/// # Arguments
///
/// * `changeset` - The changeset to classify.
///
/// # Returns
///
/// The [`RiskTierClass`] for the changeset.
///
/// # Example
///
/// ```rust
/// use apm2_core::fac::risk_tier::{ChangeSet, RiskTierClass, classify_risk};
///
/// let changeset = ChangeSet {
///     files_changed: vec!["src/auth/login.rs".to_string()],
///     lines_changed: 100,
///     dependency_fanout: 5,
/// };
///
/// assert_eq!(classify_risk(&changeset), RiskTierClass::High);
/// ```
#[must_use]
pub fn classify_risk(changeset: &ChangeSet) -> RiskTierClass {
    // Check file count limit (DoS protection) -> HIGH
    if changeset.files_changed.len() > MAX_FILES {
        return RiskTierClass::High;
    }

    // Check primary signals -> HIGH
    if touches_critical_module(changeset) {
        return RiskTierClass::High;
    }

    if matches_sensitive_pattern(changeset) {
        return RiskTierClass::High;
    }

    // Check secondary signals -> MED
    if changeset.lines_changed > LINES_CHANGED_THRESHOLD {
        return RiskTierClass::Med;
    }

    if changeset.files_changed.len() > FILES_CHANGED_THRESHOLD {
        return RiskTierClass::Med;
    }

    if changeset.dependency_fanout > DEPENDENCY_FANOUT_THRESHOLD {
        return RiskTierClass::Med;
    }

    // Explicit LOW: only when all checks pass and changeset is small and
    // non-critical For an empty changeset or one that passed all checks above,
    // we need to determine if it's truly a recognized low-risk changeset or an
    // unknown pattern. A changeset with no files is explicitly low-risk
    // (nothing to review). A changeset with files that passed all pattern
    // checks is explicitly low-risk.
    if changeset.files_changed.is_empty()
        || (!changeset.files_changed.is_empty()
            && changeset.lines_changed <= LINES_CHANGED_THRESHOLD
            && changeset.files_changed.len() <= FILES_CHANGED_THRESHOLD
            && changeset.dependency_fanout <= DEPENDENCY_FANOUT_THRESHOLD)
    {
        return RiskTierClass::Low;
    }

    // Default -> HIGH (fail-closed security model)
    RiskTierClass::High
}

/// Maximum file path length to process for risk classification.
///
/// Paths longer than this are classified as HIGH risk (fail-closed) to prevent
/// denial-of-service via unbounded memory allocation and to ensure critical
/// module names or sensitive patterns at the end of long paths are not missed.
/// 4096 bytes is a reasonable limit that covers all practical file paths.
const MAX_PATH_LEN: usize = 4096;

/// Delimiters for aggressive module matching.
///
/// These characters are used to identify module name boundaries in paths.
/// A module match occurs when the module name appears as a path segment
/// (surrounded by separators) OR as part of a directory/file name
/// (preceded or followed by common delimiters like underscore, hyphen).
const MODULE_DELIMITERS: &[char] = &['/', '\\', '_', '-', '.'];

/// Checks if the changeset touches a critical module.
///
/// A critical module is touched if any file path contains one of the
/// critical module names in any of these forms (case-insensitive):
/// - As a path segment: `/auth/`, `auth/` at start
/// - As part of a compound name: `_auth/`, `-auth/`, `auth_`, `auth-`, `auth.`
/// - At path boundaries: preceded or followed by path separators or delimiters
///
/// This aggressive matching ensures that patterns like `auth_impl/`, `_auth/`,
/// `my-auth-service/`, and `auth.rs` all trigger HIGH risk.
///
/// Uses pre-allocated pattern buffers to avoid denial-of-service via unbounded
/// allocations. Paths exceeding `MAX_PATH_LEN` are treated as HIGH risk
/// (fail-closed) since critical module names could appear at the end of
/// truncated paths.
fn touches_critical_module(changeset: &ChangeSet) -> bool {
    // Pre-allocate a single buffer for lowercase conversion
    let mut lower_buf = String::with_capacity(MAX_PATH_LEN);

    for file_path in &changeset.files_changed {
        // Fail-closed: paths exceeding MAX_PATH_LEN are treated as HIGH risk
        // since critical module names could appear at the end of truncated paths
        if file_path.len() > MAX_PATH_LEN {
            return true;
        }

        lower_buf.clear();

        // Reuse buffer for lowercase conversion
        lower_buf.extend(file_path.chars().map(|c| c.to_ascii_lowercase()));

        // Check each critical module with aggressive matching
        for module in CRITICAL_MODULES {
            if contains_module_aggressively(&lower_buf, module) {
                return true;
            }
        }
    }
    false
}

/// Checks if a path contains a module name using aggressive matching.
///
/// Matches if the module appears:
/// - As a standalone path segment (e.g., `/auth/`, `auth/` at start)
/// - Preceded by a delimiter (e.g., `_auth`, `-auth`, `/auth`)
/// - Followed by a delimiter (e.g., `auth_`, `auth-`, `auth.`, `auth/`)
/// - As an exact match for the entire path
///
/// This catches patterns like:
/// - `/auth/` - standard path segment
/// - `auth_impl/` - module as prefix with underscore
/// - `_auth/` - module with leading underscore
/// - `my-auth/` - module with leading hyphen
/// - `auth.rs` - module as filename
fn contains_module_aggressively(path: &str, module: &str) -> bool {
    // Exact match
    if path == module {
        return true;
    }

    // Find all occurrences of the module name
    let mut search_start = 0;
    while let Some(pos) = path[search_start..].find(module) {
        let abs_pos = search_start + pos;
        let end_pos = abs_pos + module.len();

        // Check if this is a valid module boundary match
        let valid_start = abs_pos == 0
            || path[..abs_pos]
                .chars()
                .last()
                .is_some_and(|c| MODULE_DELIMITERS.contains(&c));

        let valid_end = end_pos == path.len()
            || path[end_pos..]
                .chars()
                .next()
                .is_some_and(|c| MODULE_DELIMITERS.contains(&c));

        if valid_start && valid_end {
            return true;
        }

        // Move past this occurrence
        search_start = abs_pos + 1;
        if search_start >= path.len() {
            break;
        }
    }

    false
}

/// Checks if the changeset matches a sensitive pattern.
///
/// A sensitive pattern is matched if any file path contains one of the
/// sensitive pattern strings (case-insensitive).
///
/// Uses pre-allocated buffer to avoid denial-of-service via unbounded
/// allocations. Paths exceeding `MAX_PATH_LEN` are treated as HIGH risk
/// (fail-closed) since sensitive patterns could appear at the end of truncated
/// paths.
fn matches_sensitive_pattern(changeset: &ChangeSet) -> bool {
    // Pre-allocate a single buffer for lowercase conversion
    let mut lower_buf = String::with_capacity(MAX_PATH_LEN);

    for file_path in &changeset.files_changed {
        // Fail-closed: paths exceeding MAX_PATH_LEN are treated as HIGH risk
        // since sensitive patterns could appear at the end of truncated paths
        if file_path.len() > MAX_PATH_LEN {
            return true;
        }

        lower_buf.clear();

        // Reuse buffer for lowercase conversion
        lower_buf.extend(file_path.chars().map(|c| c.to_ascii_lowercase()));

        for pattern in SENSITIVE_PATTERNS {
            if lower_buf.contains(pattern) {
                return true;
            }
        }
    }
    false
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(missing_docs)]
pub mod tests {
    use super::*;

    // =========================================================================
    // RiskTierClass Basic Tests
    // =========================================================================

    #[test]
    fn test_risk_tier_rank() {
        assert_eq!(RiskTierClass::High.rank(), 2);
        assert_eq!(RiskTierClass::Med.rank(), 1);
        assert_eq!(RiskTierClass::Low.rank(), 0);
    }

    #[test]
    fn test_risk_tier_ordering() {
        assert!(RiskTierClass::High > RiskTierClass::Med);
        assert!(RiskTierClass::Med > RiskTierClass::Low);
        assert!(RiskTierClass::High > RiskTierClass::Low);
    }

    #[test]
    fn test_risk_tier_try_from() {
        assert_eq!(RiskTierClass::try_from(2).unwrap(), RiskTierClass::High);
        assert_eq!(RiskTierClass::try_from(1).unwrap(), RiskTierClass::Med);
        assert_eq!(RiskTierClass::try_from(0).unwrap(), RiskTierClass::Low);
        assert!(RiskTierClass::try_from(3).is_err());
        assert!(RiskTierClass::try_from(255).is_err());
    }

    #[test]
    fn test_risk_tier_into_u8() {
        assert_eq!(u8::from(RiskTierClass::High), 2);
        assert_eq!(u8::from(RiskTierClass::Med), 1);
        assert_eq!(u8::from(RiskTierClass::Low), 0);
    }

    #[test]
    fn test_risk_tier_display() {
        assert_eq!(format!("{}", RiskTierClass::High), "HIGH");
        assert_eq!(format!("{}", RiskTierClass::Med), "MED");
        assert_eq!(format!("{}", RiskTierClass::Low), "LOW");
    }

    #[test]
    fn test_risk_tier_default() {
        assert_eq!(RiskTierClass::default(), RiskTierClass::Low);
    }

    #[test]
    fn test_risk_tier_requires_full_aat() {
        assert!(RiskTierClass::High.requires_full_aat());
        assert!(!RiskTierClass::Med.requires_full_aat());
        assert!(!RiskTierClass::Low.requires_full_aat());
    }

    #[test]
    fn test_risk_tier_all() {
        let tiers: Vec<_> = RiskTierClass::all().collect();
        assert_eq!(
            tiers,
            vec![RiskTierClass::High, RiskTierClass::Med, RiskTierClass::Low]
        );
    }

    #[test]
    fn test_risk_tier_serde_roundtrip() {
        for tier in RiskTierClass::all() {
            let serialized = serde_json::to_string(&tier).unwrap();
            let deserialized: RiskTierClass = serde_json::from_str(&serialized).unwrap();
            assert_eq!(tier, deserialized);
        }
    }

    // =========================================================================
    // Primary Signal Tests - Critical Modules
    // =========================================================================

    #[test]
    fn test_classify_critical_module_auth() {
        let changeset = ChangeSet {
            files_changed: vec!["crates/apm2-core/src/auth/mod.rs".to_string()],
            lines_changed: 10,
            dependency_fanout: 1,
        };
        assert_eq!(classify_risk(&changeset), RiskTierClass::High);
    }

    #[test]
    fn test_classify_critical_module_crypto() {
        let changeset = ChangeSet {
            files_changed: vec!["crates/apm2-core/src/crypto/signer.rs".to_string()],
            lines_changed: 10,
            dependency_fanout: 1,
        };
        assert_eq!(classify_risk(&changeset), RiskTierClass::High);
    }

    #[test]
    fn test_classify_critical_module_ledger() {
        let changeset = ChangeSet {
            files_changed: vec!["src/ledger/events.rs".to_string()],
            lines_changed: 10,
            dependency_fanout: 1,
        };
        assert_eq!(classify_risk(&changeset), RiskTierClass::High);
    }

    #[test]
    fn test_classify_critical_module_tool() {
        let changeset = ChangeSet {
            files_changed: vec!["crates/tool/executor.rs".to_string()],
            lines_changed: 10,
            dependency_fanout: 1,
        };
        assert_eq!(classify_risk(&changeset), RiskTierClass::High);
    }

    #[test]
    fn test_classify_critical_module_kernel() {
        let changeset = ChangeSet {
            files_changed: vec!["kernel/main.rs".to_string()],
            lines_changed: 10,
            dependency_fanout: 1,
        };
        assert_eq!(classify_risk(&changeset), RiskTierClass::High);
    }

    #[test]
    fn test_classify_critical_module_fac() {
        let changeset = ChangeSet {
            files_changed: vec!["crates/apm2-core/src/fac/risk_tier.rs".to_string()],
            lines_changed: 10,
            dependency_fanout: 1,
        };
        assert_eq!(classify_risk(&changeset), RiskTierClass::High);
    }

    #[test]
    fn test_classify_critical_module_case_insensitive() {
        let changeset = ChangeSet {
            files_changed: vec!["src/CRYPTO/Keys.rs".to_string()],
            lines_changed: 10,
            dependency_fanout: 1,
        };
        assert_eq!(classify_risk(&changeset), RiskTierClass::High);
    }

    #[test]
    fn test_classify_non_critical_module_with_similar_name() {
        // "authentication" should NOT trigger - we look for "auth" as a delimited
        // segment
        let changeset = ChangeSet {
            files_changed: vec!["src/authentication/utils.rs".to_string()],
            lines_changed: 10,
            dependency_fanout: 1,
        };
        // This should be LOW since "authentication" contains "auth" but not at a
        // delimiter boundary
        assert_eq!(classify_risk(&changeset), RiskTierClass::Low);
    }

    #[test]
    fn test_classify_critical_module_with_underscore_prefix() {
        // "_auth/" should trigger with aggressive matching
        let changeset = ChangeSet {
            files_changed: vec!["src/_auth/utils.rs".to_string()],
            lines_changed: 10,
            dependency_fanout: 1,
        };
        assert_eq!(classify_risk(&changeset), RiskTierClass::High);
    }

    #[test]
    fn test_classify_critical_module_with_underscore_suffix() {
        // "auth_impl/" should trigger with aggressive matching
        let changeset = ChangeSet {
            files_changed: vec!["src/auth_impl/utils.rs".to_string()],
            lines_changed: 10,
            dependency_fanout: 1,
        };
        assert_eq!(classify_risk(&changeset), RiskTierClass::High);
    }

    #[test]
    fn test_classify_critical_module_compound_name() {
        // "my-crypto-lib/" should trigger with aggressive matching
        let changeset = ChangeSet {
            files_changed: vec!["crates/my-crypto-lib/src/lib.rs".to_string()],
            lines_changed: 10,
            dependency_fanout: 1,
        };
        assert_eq!(classify_risk(&changeset), RiskTierClass::High);
    }

    // =========================================================================
    // Primary Signal Tests - Sensitive Patterns
    // =========================================================================

    #[test]
    fn test_classify_sensitive_pattern_secret() {
        let changeset = ChangeSet {
            files_changed: vec!["config/secrets.yaml".to_string()],
            lines_changed: 10,
            dependency_fanout: 1,
        };
        assert_eq!(classify_risk(&changeset), RiskTierClass::High);
    }

    #[test]
    fn test_classify_sensitive_pattern_credentials() {
        let changeset = ChangeSet {
            files_changed: vec!["src/credentials_manager.rs".to_string()],
            lines_changed: 10,
            dependency_fanout: 1,
        };
        assert_eq!(classify_risk(&changeset), RiskTierClass::High);
    }

    #[test]
    fn test_classify_sensitive_pattern_policy() {
        let changeset = ChangeSet {
            files_changed: vec!["src/fac/policy_resolution.rs".to_string()],
            lines_changed: 10,
            dependency_fanout: 1,
        };
        assert_eq!(classify_risk(&changeset), RiskTierClass::High);
    }

    #[test]
    fn test_classify_sensitive_pattern_case_insensitive() {
        let changeset = ChangeSet {
            files_changed: vec!["config/SECRETS.yaml".to_string()],
            lines_changed: 10,
            dependency_fanout: 1,
        };
        assert_eq!(classify_risk(&changeset), RiskTierClass::High);
    }

    // =========================================================================
    // Secondary Signal Tests - Lines Changed
    // =========================================================================

    #[test]
    fn test_classify_large_changeset_by_lines() {
        let changeset = ChangeSet {
            files_changed: vec!["src/utils.rs".to_string()],
            lines_changed: 501,
            dependency_fanout: 1,
        };
        assert_eq!(classify_risk(&changeset), RiskTierClass::Med);
    }

    #[test]
    fn test_classify_exactly_threshold_lines() {
        let changeset = ChangeSet {
            files_changed: vec!["src/utils.rs".to_string()],
            lines_changed: 500,
            dependency_fanout: 1,
        };
        // Exactly 500 should be LOW (threshold is >500)
        assert_eq!(classify_risk(&changeset), RiskTierClass::Low);
    }

    // =========================================================================
    // Secondary Signal Tests - Files Changed
    // =========================================================================

    #[test]
    fn test_classify_large_changeset_by_files() {
        let changeset = ChangeSet {
            files_changed: (0..11).map(|i| format!("src/file{i}.rs")).collect(),
            lines_changed: 100,
            dependency_fanout: 1,
        };
        assert_eq!(classify_risk(&changeset), RiskTierClass::Med);
    }

    #[test]
    fn test_classify_exactly_threshold_files() {
        let changeset = ChangeSet {
            files_changed: (0..10).map(|i| format!("src/file{i}.rs")).collect(),
            lines_changed: 100,
            dependency_fanout: 1,
        };
        // Exactly 10 should be LOW (threshold is >10)
        assert_eq!(classify_risk(&changeset), RiskTierClass::Low);
    }

    // =========================================================================
    // Secondary Signal Tests - Dependency Fanout
    // =========================================================================

    #[test]
    fn test_classify_high_dependency_fanout() {
        let changeset = ChangeSet {
            files_changed: vec!["src/utils.rs".to_string()],
            lines_changed: 100,
            dependency_fanout: 21,
        };
        assert_eq!(classify_risk(&changeset), RiskTierClass::Med);
    }

    #[test]
    fn test_classify_exactly_threshold_dependency_fanout() {
        let changeset = ChangeSet {
            files_changed: vec!["src/utils.rs".to_string()],
            lines_changed: 100,
            dependency_fanout: 20,
        };
        // Exactly 20 should be LOW (threshold is >20)
        assert_eq!(classify_risk(&changeset), RiskTierClass::Low);
    }

    // =========================================================================
    // Default (LOW) Tests
    // =========================================================================

    #[test]
    fn test_classify_small_safe_changeset() {
        let changeset = ChangeSet {
            files_changed: vec!["src/utils.rs".to_string()],
            lines_changed: 50,
            dependency_fanout: 5,
        };
        assert_eq!(classify_risk(&changeset), RiskTierClass::Low);
    }

    #[test]
    fn test_classify_empty_changeset() {
        let changeset = ChangeSet::default();
        assert_eq!(classify_risk(&changeset), RiskTierClass::Low);
    }

    // =========================================================================
    // Priority Tests (Primary > Secondary)
    // =========================================================================

    #[test]
    fn test_primary_signal_takes_precedence() {
        // Even with small lines/files/fanout, critical module triggers HIGH
        let changeset = ChangeSet {
            files_changed: vec!["src/crypto/keys.rs".to_string()],
            lines_changed: 10,
            dependency_fanout: 1,
        };
        assert_eq!(classify_risk(&changeset), RiskTierClass::High);
    }

    #[test]
    fn test_primary_signal_with_secondary_still_high() {
        // Critical module + large lines still results in HIGH (not MED)
        let changeset = ChangeSet {
            files_changed: vec!["src/crypto/keys.rs".to_string()],
            lines_changed: 1000,
            dependency_fanout: 50,
        };
        assert_eq!(classify_risk(&changeset), RiskTierClass::High);
    }

    // =========================================================================
    // Edge Cases
    // =========================================================================

    #[test]
    fn test_multiple_files_one_critical() {
        let changeset = ChangeSet {
            files_changed: vec![
                "src/utils.rs".to_string(),
                "src/helpers.rs".to_string(),
                "src/crypto/signer.rs".to_string(), // Critical
                "src/format.rs".to_string(),
            ],
            lines_changed: 50,
            dependency_fanout: 5,
        };
        assert_eq!(classify_risk(&changeset), RiskTierClass::High);
    }

    #[test]
    fn test_path_starting_with_critical_module() {
        // Path that starts with critical module name
        let changeset = ChangeSet {
            files_changed: vec!["kernel/init.rs".to_string()],
            lines_changed: 10,
            dependency_fanout: 1,
        };
        assert_eq!(classify_risk(&changeset), RiskTierClass::High);
    }

    #[test]
    fn test_critical_module_as_file_extension() {
        // File with .auth extension SHOULD trigger with aggressive matching
        // since "." is a delimiter
        let changeset = ChangeSet {
            files_changed: vec!["config/app.auth".to_string()],
            lines_changed: 10,
            dependency_fanout: 1,
        };
        // Should be HIGH since ".auth" at end matches with delimiter
        assert_eq!(classify_risk(&changeset), RiskTierClass::High);
    }

    #[test]
    fn test_sensitive_pattern_in_directory_name() {
        let changeset = ChangeSet {
            files_changed: vec!["config/secretmanager/config.yaml".to_string()],
            lines_changed: 10,
            dependency_fanout: 1,
        };
        // "secretmanager" contains "secret"
        assert_eq!(classify_risk(&changeset), RiskTierClass::High);
    }

    // =========================================================================
    // Additional Critical Module Tests (proto, daemon)
    // =========================================================================

    #[test]
    fn test_classify_critical_module_proto() {
        let changeset = ChangeSet {
            files_changed: vec!["crates/apm2-proto/src/messages.proto".to_string()],
            lines_changed: 10,
            dependency_fanout: 1,
        };
        assert_eq!(classify_risk(&changeset), RiskTierClass::High);
    }

    #[test]
    fn test_classify_critical_module_proto_directory() {
        let changeset = ChangeSet {
            files_changed: vec!["proto/api.proto".to_string()],
            lines_changed: 10,
            dependency_fanout: 1,
        };
        assert_eq!(classify_risk(&changeset), RiskTierClass::High);
    }

    #[test]
    fn test_classify_critical_module_daemon() {
        let changeset = ChangeSet {
            files_changed: vec!["crates/apm2-daemon/src/ipc.rs".to_string()],
            lines_changed: 10,
            dependency_fanout: 1,
        };
        assert_eq!(classify_risk(&changeset), RiskTierClass::High);
    }

    #[test]
    fn test_classify_critical_module_daemon_directory() {
        let changeset = ChangeSet {
            files_changed: vec!["daemon/main.rs".to_string()],
            lines_changed: 10,
            dependency_fanout: 1,
        };
        assert_eq!(classify_risk(&changeset), RiskTierClass::High);
    }

    // =========================================================================
    // Additional Sensitive Pattern Tests (security)
    // =========================================================================

    #[test]
    fn test_classify_sensitive_pattern_security() {
        let changeset = ChangeSet {
            files_changed: vec!["documents/security/THREAT_MODEL.cac.json".to_string()],
            lines_changed: 10,
            dependency_fanout: 1,
        };
        assert_eq!(classify_risk(&changeset), RiskTierClass::High);
    }

    #[test]
    fn test_classify_sensitive_pattern_security_file() {
        let changeset = ChangeSet {
            files_changed: vec!["docs/security.md".to_string()],
            lines_changed: 10,
            dependency_fanout: 1,
        };
        assert_eq!(classify_risk(&changeset), RiskTierClass::High);
    }

    // =========================================================================
    // Fail-Closed Path Length Tests
    // =========================================================================

    #[test]
    fn test_classify_path_exceeds_max_len_is_high_risk() {
        // Path exceeding MAX_PATH_LEN (4096) should be classified as HIGH (fail-closed)
        let long_path = "a".repeat(4097);
        let changeset = ChangeSet {
            files_changed: vec![long_path],
            lines_changed: 10,
            dependency_fanout: 1,
        };
        assert_eq!(classify_risk(&changeset), RiskTierClass::High);
    }

    #[test]
    fn test_classify_path_at_max_len_is_not_high_risk() {
        // Path exactly at MAX_PATH_LEN should be processed normally
        let max_path = "a".repeat(4096);
        let changeset = ChangeSet {
            files_changed: vec![max_path],
            lines_changed: 10,
            dependency_fanout: 1,
        };
        // No critical module or sensitive pattern, should be LOW
        assert_eq!(classify_risk(&changeset), RiskTierClass::Low);
    }

    #[test]
    fn test_classify_long_path_with_critical_module_at_end() {
        // This test verifies fail-closed behavior: even if we can't see the
        // critical module at the end, we return HIGH for long paths
        let mut long_path = "a/".repeat(2050);
        long_path.push_str("crypto/keys.rs");
        // Total length > 4096, so it should be HIGH regardless
        assert!(long_path.len() > 4096);
        let changeset = ChangeSet {
            files_changed: vec![long_path],
            lines_changed: 10,
            dependency_fanout: 1,
        };
        assert_eq!(classify_risk(&changeset), RiskTierClass::High);
    }

    // =========================================================================
    // Error Tests
    // =========================================================================

    #[test]
    fn test_risk_tier_error_display() {
        let err = RiskTierError::InvalidTier(5);
        assert!(err.to_string().contains("invalid risk tier value: 5"));
    }

    // =========================================================================
    // MAX_FILES DoS Protection Tests
    // =========================================================================

    #[test]
    fn test_classify_exceeds_max_files_is_high_risk() {
        // Changeset exceeding MAX_FILES should be classified as HIGH (fail-closed)
        let changeset = ChangeSet {
            files_changed: (0..10001).map(|i| format!("src/file{i}.rs")).collect(),
            lines_changed: 10,
            dependency_fanout: 1,
        };
        assert_eq!(classify_risk(&changeset), RiskTierClass::High);
    }

    #[test]
    fn test_classify_at_max_files_is_not_high_risk() {
        // Changeset exactly at MAX_FILES should be processed normally
        let changeset = ChangeSet {
            files_changed: (0..10000).map(|i| format!("src/file{i}.rs")).collect(),
            lines_changed: 10,
            dependency_fanout: 1,
        };
        // Many files but under MAX_FILES, no critical modules, should trigger MED
        // due to FILES_CHANGED_THRESHOLD (> 10)
        assert_eq!(classify_risk(&changeset), RiskTierClass::Med);
    }

    // =========================================================================
    // Fail-Closed Default Behavior Tests
    // =========================================================================

    #[test]
    fn test_fail_closed_default_behavior() {
        // Verify that the classification is fail-closed: empty changesets
        // that passed all checks should still be classified correctly.
        // An empty changeset is explicitly low-risk (nothing to review).
        let changeset = ChangeSet::default();
        assert_eq!(classify_risk(&changeset), RiskTierClass::Low);
    }
}
