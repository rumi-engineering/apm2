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
//!   modules (auth, crypto, ledger, tool, kernel, fac) or sensitive patterns
//!   (secret, credentials, policy).
//! - **Med**: Elevated scrutiny required. Triggered by large changesets (lines
//!   > 500, files > 10, dependency fanout > 20).
//! - **Low**: Standard scrutiny. Default tier when no risk signals are
//!   detected.
//!
//! # Classification Model
//!
//! Classification uses a two-tier signal hierarchy:
//!
//! 1. **Primary Signals** (-> HIGH):
//!    - `touches_critical_module`: Changes to auth, crypto, ledger, tool,
//!      kernel, or fac modules
//!    - `matches_sensitive_pattern`: Changes containing "secret",
//!      "credentials", or "policy"
//!
//! 2. **Secondary Signals** (-> MED):
//!    - `lines_changed > 500`: Large changesets by line count
//!    - `files_changed > 10`: Wide-impact changesets by file count
//!    - `dependency_fanout > 20`: High coupling changesets
//!
//! 3. **Default**: LOW when no signals match
//!
//! # Security Model
//!
//! The classification model is permissive by default: when no risk signals
//! are detected, the changeset receives the LOW tier. Known risk signals
//! (critical modules, sensitive patterns, size thresholds) escalate to
//! higher tiers. This "fail-open" approach prioritizes developer velocity
//! for routine changes while ensuring elevated scrutiny for known risk
//! indicators.
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
pub const CRITICAL_MODULES: &[&str] = &["auth", "crypto", "ledger", "tool", "kernel", "fac"];

/// Sensitive patterns in file paths or content that trigger HIGH risk tier.
///
/// These patterns indicate security-sensitive data or configuration:
///
/// - `secret`: Secrets, API keys, tokens
/// - `credentials`: Authentication credentials
/// - `policy`: Security policies and access control
pub const SENSITIVE_PATTERNS: &[&str] = &["secret", "credentials", "policy"];

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
    /// - Changes to critical modules (auth, crypto, ledger, tool, kernel, fac)
    /// - Matches to sensitive patterns (secret, credentials, policy)
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
///    - If any file path contains a critical module name (auth, crypto, ledger,
///      tool, kernel), return HIGH.
///    - If any file path contains a sensitive pattern (secret, credentials,
///      policy), return HIGH.
///
/// 2. **Secondary Signals** (-> MED):
///    - If `lines_changed` > 500, return MED.
///    - If `files_changed` > 10, return MED.
///    - If `dependency_fanout` > 20, return MED.
///
/// 3. **Default**: Return LOW.
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

    // Default -> LOW
    RiskTierClass::Low
}

/// Maximum file path length to process for risk classification.
///
/// Paths longer than this are truncated to prevent denial-of-service via
/// unbounded memory allocation. 4096 bytes is a reasonable limit that covers
/// all practical file paths.
const MAX_PATH_LEN: usize = 4096;

/// Pre-computed patterns for critical module matching.
///
/// These are computed at compile time to avoid runtime allocations.
/// Each module has patterns for: /module/, /module., module/, module.
const CRITICAL_MODULE_PATTERNS: &[(&str, &str, &str, &str)] = &[
    ("/auth/", "/auth.", "auth/", "auth."),
    ("/crypto/", "/crypto.", "crypto/", "crypto."),
    ("/ledger/", "/ledger.", "ledger/", "ledger."),
    ("/tool/", "/tool.", "tool/", "tool."),
    ("/kernel/", "/kernel.", "kernel/", "kernel."),
    ("/fac/", "/fac.", "fac/", "fac."),
];

/// Checks if the changeset touches a critical module.
///
/// A critical module is touched if any file path contains one of the
/// critical module names as a path component (case-insensitive).
///
/// Uses pre-allocated pattern buffers to avoid denial-of-service via unbounded
/// allocations.
fn touches_critical_module(changeset: &ChangeSet) -> bool {
    // Pre-allocate a single buffer for lowercase conversion
    let mut lower_buf = String::with_capacity(MAX_PATH_LEN);

    for file_path in &changeset.files_changed {
        lower_buf.clear();

        // Truncate path to prevent denial-of-service via unbounded allocation
        let path_slice = if file_path.len() > MAX_PATH_LEN {
            &file_path[..MAX_PATH_LEN]
        } else {
            file_path.as_str()
        };

        // Reuse buffer for lowercase conversion
        lower_buf.extend(path_slice.chars().map(|c| c.to_ascii_lowercase()));

        for (slash_module_slash, slash_module_dot, module_slash, module_dot) in
            CRITICAL_MODULE_PATTERNS
        {
            if lower_buf.contains(slash_module_slash)
                || lower_buf.contains(slash_module_dot)
                || lower_buf.starts_with(module_slash)
                || lower_buf.starts_with(module_dot)
            {
                return true;
            }
        }

        // Also check exact match with module names
        for module in CRITICAL_MODULES {
            if lower_buf == *module {
                return true;
            }
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
/// allocations.
fn matches_sensitive_pattern(changeset: &ChangeSet) -> bool {
    // Pre-allocate a single buffer for lowercase conversion
    let mut lower_buf = String::with_capacity(MAX_PATH_LEN);

    for file_path in &changeset.files_changed {
        lower_buf.clear();

        // Truncate path to prevent denial-of-service via unbounded allocation
        let path_slice = if file_path.len() > MAX_PATH_LEN {
            &file_path[..MAX_PATH_LEN]
        } else {
            file_path.as_str()
        };

        // Reuse buffer for lowercase conversion
        lower_buf.extend(path_slice.chars().map(|c| c.to_ascii_lowercase()));

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
        // "authentication" should NOT trigger - we look for "/auth/" not just "auth"
        let changeset = ChangeSet {
            files_changed: vec!["src/authentication/utils.rs".to_string()],
            lines_changed: 10,
            dependency_fanout: 1,
        };
        // This should be LOW since "authentication" != "auth"
        assert_eq!(classify_risk(&changeset), RiskTierClass::Low);
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
        // File with .auth extension should NOT trigger (pattern is for directory)
        let changeset = ChangeSet {
            files_changed: vec!["config/app.auth".to_string()],
            lines_changed: 10,
            dependency_fanout: 1,
        };
        // Should be LOW since ".auth" is not "/auth/"
        assert_eq!(classify_risk(&changeset), RiskTierClass::Low);
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
    // Error Tests
    // =========================================================================

    #[test]
    fn test_risk_tier_error_display() {
        let err = RiskTierError::InvalidTier(5);
        assert!(err.to_string().contains("invalid risk tier value: 5"));
    }
}
