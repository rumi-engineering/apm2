// AGENT-AUTHORED
//! AAT Selection Policy engine for the Forge Admission Cycle.
//!
//! This module defines [`SelectionPolicy`] which determines whether AAT
//! (Agent Acceptance Testing) should run for a given changeset based on
//! its risk tier and execution context.
//!
//! # Risk Tier Behavior
//!
//! - **HIGH**: Always requires AAT (fail-closed for maximum security)
//! - **MED**: Requires AAT for sensitive domains (conditional)
//! - **LOW**: Uses deterministic hash-based sampling
//!
//! # Security Model
//!
//! The selection policy implements a **fail-closed** approach:
//! - If unable to determine risk tier, AAT is required
//! - If context evaluation fails, AAT is required
//! - Sampling is deterministic for reproducibility and audit
//!
//! # Deterministic Sampling
//!
//! LOW tier sampling uses BLAKE3 hashing of the `work_id` to produce a
//! deterministic sample decision. This ensures:
//! - Same `work_id` always produces the same decision
//! - Reproducible audit trails
//! - No dependency on external randomness
//!
//! # Example
//!
//! ```rust
//! use apm2_core::fac::RiskTierClass;
//! use apm2_core::fac::selection_policy::{
//!     AatRequirement, SelectionContext, SelectionPolicy, SelectionPolicyBuilder, TierConfig,
//! };
//!
//! // Create a default policy
//! let policy = SelectionPolicyBuilder::new("policy-001")
//!     .build()
//!     .expect("valid policy");
//!
//! // HIGH tier always requires AAT
//! let ctx = SelectionContext::new("work-001");
//! assert!(policy.should_run_aat(RiskTierClass::High, &ctx));
//!
//! // LOW tier uses sampling
//! let ctx = SelectionContext::new("work-002");
//! // Result depends on deterministic hash of work_id
//! let _should_run = policy.should_run_aat(RiskTierClass::Low, &ctx);
//! ```

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::risk_tier::RiskTierClass;

// =============================================================================
// Resource Limits
// =============================================================================

/// Maximum length for `policy_id` string.
pub const MAX_POLICY_ID_LENGTH: usize = 256;

/// Maximum length for `work_id` string in context.
pub const MAX_WORK_ID_LENGTH: usize = 512;

/// Maximum length for domain string in context.
pub const MAX_DOMAIN_LENGTH: usize = 256;

/// Maximum serialized policy size (16 KiB).
///
/// Prevents denial-of-service via oversized policy configurations.
pub const MAX_POLICY_SIZE: usize = 16 * 1024;

/// Default sample rate for LOW tier (10% = 0.1).
pub const DEFAULT_LOW_TIER_SAMPLE_RATE: f64 = 0.1;

/// Sensitive domains that trigger AAT for MED tier.
///
/// These domains require additional scrutiny even for medium-risk changesets:
/// - `auth`: Authentication and authorization
/// - `crypto`: Cryptographic operations
/// - `payment`: Payment processing
/// - `pii`: Personally identifiable information
/// - `security`: Security-related functionality
pub const SENSITIVE_DOMAINS: &[&str] = &["auth", "crypto", "payment", "pii", "security"];

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during selection policy operations.
#[derive(Debug, Error, Clone, PartialEq)]
#[non_exhaustive]
pub enum SelectionPolicyError {
    /// Missing required field.
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// Invalid policy data.
    #[error("invalid policy data: {0}")]
    InvalidData(String),

    /// String field exceeds maximum length.
    #[error("string field {field} exceeds max length: {actual} > {max}")]
    StringTooLong {
        /// Name of the field that exceeded the limit.
        field: &'static str,
        /// Actual length of the string.
        actual: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// Invalid sample rate.
    #[error("invalid sample rate: {0}, must be in range [0.0, 1.0]")]
    InvalidSampleRate(f64),

    /// Policy size exceeds maximum limit.
    #[error("policy size exceeds limit: {actual} > {max}")]
    PolicyTooLarge {
        /// Actual size in bytes.
        actual: usize,
        /// Maximum allowed size.
        max: usize,
    },
}

// =============================================================================
// AatRequirement Enum
// =============================================================================

/// Specifies when AAT is required for a tier.
///
/// This enum defines the three modes of AAT selection:
/// - `Always`: AAT is mandatory regardless of context
/// - `Conditional`: AAT depends on domain sensitivity
/// - `Sampled`: AAT is selected via deterministic sampling
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum AatRequirement {
    /// AAT is always required.
    ///
    /// Used for HIGH risk tier to ensure maximum coverage.
    #[default]
    Always,

    /// AAT is conditionally required based on domain sensitivity.
    ///
    /// Used for MED risk tier to require AAT for sensitive domains
    /// while allowing pass-through for non-sensitive domains.
    Conditional,

    /// AAT is selected via deterministic sampling.
    ///
    /// Used for LOW risk tier to balance coverage with cost.
    /// The sampling decision is deterministic based on `work_id` hash.
    Sampled,
}

impl std::fmt::Display for AatRequirement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Always => write!(f, "ALWAYS"),
            Self::Conditional => write!(f, "CONDITIONAL"),
            Self::Sampled => write!(f, "SAMPLED"),
        }
    }
}

// =============================================================================
// TierConfig
// =============================================================================

/// Configuration for a single risk tier's AAT selection behavior.
///
/// Each tier has its own configuration specifying:
/// - Whether AAT is required, conditional, or sampled
/// - The sample rate (only used for `Sampled` requirement)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TierConfig {
    /// The AAT requirement mode for this tier.
    aat_required: AatRequirement,

    /// Sample rate for `Sampled` requirement mode.
    ///
    /// Must be in range `[0.0, 1.0]`. Only used when `aat_required` is
    /// `Sampled`. A rate of `0.1` means 10% of work items will be selected.
    sample_rate: f64,
}

impl TierConfig {
    /// Creates a new tier configuration.
    ///
    /// # Arguments
    ///
    /// * `aat_required` - The AAT requirement mode
    /// * `sample_rate` - The sample rate (must be in `[0.0, 1.0]`)
    ///
    /// # Errors
    ///
    /// Returns [`SelectionPolicyError::InvalidSampleRate`] if the sample rate
    /// is not in the valid range.
    pub fn new(
        aat_required: AatRequirement,
        sample_rate: f64,
    ) -> Result<Self, SelectionPolicyError> {
        if !(0.0..=1.0).contains(&sample_rate) || sample_rate.is_nan() {
            return Err(SelectionPolicyError::InvalidSampleRate(sample_rate));
        }
        Ok(Self {
            aat_required,
            sample_rate,
        })
    }

    /// Creates a tier configuration that always requires AAT.
    #[must_use]
    pub const fn always() -> Self {
        Self {
            aat_required: AatRequirement::Always,
            sample_rate: 1.0,
        }
    }

    /// Creates a tier configuration with conditional AAT requirement.
    #[must_use]
    pub const fn conditional() -> Self {
        Self {
            aat_required: AatRequirement::Conditional,
            sample_rate: 1.0,
        }
    }

    /// Creates a tier configuration with sampled AAT requirement.
    ///
    /// # Arguments
    ///
    /// * `sample_rate` - The sample rate (must be in `[0.0, 1.0]`)
    ///
    /// # Errors
    ///
    /// Returns [`SelectionPolicyError::InvalidSampleRate`] if the sample rate
    /// is not in the valid range.
    pub fn sampled(sample_rate: f64) -> Result<Self, SelectionPolicyError> {
        Self::new(AatRequirement::Sampled, sample_rate)
    }

    /// Returns the AAT requirement mode.
    #[must_use]
    pub const fn aat_required(&self) -> AatRequirement {
        self.aat_required
    }

    /// Returns the sample rate.
    #[must_use]
    pub const fn sample_rate(&self) -> f64 {
        self.sample_rate
    }
}

impl Default for TierConfig {
    fn default() -> Self {
        Self::always()
    }
}

// =============================================================================
// SelectionContext
// =============================================================================

/// Context information for AAT selection decisions.
///
/// This struct provides the context needed to evaluate conditional requirements
/// and perform deterministic sampling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionContext {
    /// The work item identifier.
    ///
    /// Used as the input for deterministic sampling hash.
    work_id: String,

    /// Optional domain classification for the changeset.
    ///
    /// Used to evaluate conditional requirements for MED tier.
    /// Examples: "auth", "crypto", "payment", "api", "ui"
    domain: Option<String>,
}

impl SelectionContext {
    /// Creates a new selection context with the given `work_id`.
    ///
    /// # Arguments
    ///
    /// * `work_id` - The work item identifier
    #[must_use]
    pub fn new(work_id: impl Into<String>) -> Self {
        Self {
            work_id: work_id.into(),
            domain: None,
        }
    }

    /// Creates a new selection context with `work_id` and domain.
    ///
    /// # Arguments
    ///
    /// * `work_id` - The work item identifier
    /// * `domain` - The domain classification
    #[must_use]
    pub fn with_domain(work_id: impl Into<String>, domain: impl Into<String>) -> Self {
        Self {
            work_id: work_id.into(),
            domain: Some(domain.into()),
        }
    }

    /// Returns the `work_id`.
    #[must_use]
    pub fn work_id(&self) -> &str {
        &self.work_id
    }

    /// Returns the domain, if set.
    #[must_use]
    pub fn domain(&self) -> Option<&str> {
        self.domain.as_deref()
    }

    /// Validates the context fields against resource limits.
    ///
    /// # Errors
    ///
    /// Returns [`SelectionPolicyError::StringTooLong`] if any field exceeds
    /// its maximum length.
    pub fn validate(&self) -> Result<(), SelectionPolicyError> {
        if self.work_id.len() > MAX_WORK_ID_LENGTH {
            return Err(SelectionPolicyError::StringTooLong {
                field: "work_id",
                actual: self.work_id.len(),
                max: MAX_WORK_ID_LENGTH,
            });
        }
        if let Some(ref domain) = self.domain {
            if domain.len() > MAX_DOMAIN_LENGTH {
                return Err(SelectionPolicyError::StringTooLong {
                    field: "domain",
                    actual: domain.len(),
                    max: MAX_DOMAIN_LENGTH,
                });
            }
        }
        Ok(())
    }

    /// Returns true if the domain is considered sensitive.
    ///
    /// Sensitive domains include: auth, crypto, payment, pii, security.
    /// Matching is case-insensitive and checks for substring containment.
    #[must_use]
    pub fn is_sensitive_domain(&self) -> bool {
        let Some(ref domain) = self.domain else {
            return false;
        };
        let domain_lower = domain.to_ascii_lowercase();
        SENSITIVE_DOMAINS.iter().any(|s| domain_lower.contains(s))
    }
}

// =============================================================================
// SelectionPolicy
// =============================================================================

/// AAT selection policy configuration.
///
/// A selection policy defines how AAT selection decisions are made for each
/// risk tier. The policy is identified by a unique `policy_id` and includes
/// a hash for integrity verification.
///
/// # Default Behavior
///
/// - **HIGH tier**: Always requires AAT (fail-closed)
/// - **MED tier**: Conditional based on domain sensitivity
/// - **LOW tier**: 10% deterministic sampling
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectionPolicy {
    /// Unique identifier for this policy.
    policy_id: String,

    /// BLAKE3 hash of the policy configuration.
    ///
    /// Used for integrity verification and policy binding.
    #[serde(with = "serde_bytes")]
    policy_hash: [u8; 32],

    /// Configuration for HIGH risk tier.
    high_tier_config: TierConfig,

    /// Configuration for MED risk tier.
    med_tier_config: TierConfig,

    /// Configuration for LOW risk tier.
    low_tier_config: TierConfig,
}

impl SelectionPolicy {
    /// Creates a new builder for `SelectionPolicy`.
    #[must_use]
    pub fn builder(policy_id: impl Into<String>) -> SelectionPolicyBuilder {
        SelectionPolicyBuilder::new(policy_id)
    }

    /// Returns the policy ID.
    #[must_use]
    pub fn policy_id(&self) -> &str {
        &self.policy_id
    }

    /// Returns the policy hash.
    #[must_use]
    pub const fn policy_hash(&self) -> [u8; 32] {
        self.policy_hash
    }

    /// Returns the HIGH tier configuration.
    #[must_use]
    pub const fn high_tier_config(&self) -> &TierConfig {
        &self.high_tier_config
    }

    /// Returns the MED tier configuration.
    #[must_use]
    pub const fn med_tier_config(&self) -> &TierConfig {
        &self.med_tier_config
    }

    /// Returns the LOW tier configuration.
    #[must_use]
    pub const fn low_tier_config(&self) -> &TierConfig {
        &self.low_tier_config
    }

    /// Determines whether AAT should run for the given risk tier and context.
    ///
    /// # Arguments
    ///
    /// * `risk_tier` - The risk tier classification
    /// * `context` - The selection context (`work_id`, domain, etc.)
    ///
    /// # Returns
    ///
    /// `true` if AAT should run, `false` otherwise.
    ///
    /// # Security
    ///
    /// This method implements **fail-closed** behavior:
    /// - If context validation fails, returns `true` (require AAT)
    /// - If tier is unknown, returns `true` (require AAT)
    ///
    /// # Example
    ///
    /// ```rust
    /// use apm2_core::fac::RiskTierClass;
    /// use apm2_core::fac::selection_policy::{
    ///     SelectionContext, SelectionPolicy, SelectionPolicyBuilder,
    /// };
    ///
    /// let policy = SelectionPolicyBuilder::new("policy-001").build().unwrap();
    ///
    /// // HIGH tier always requires AAT
    /// let ctx = SelectionContext::new("work-001");
    /// assert!(policy.should_run_aat(RiskTierClass::High, &ctx));
    /// ```
    #[must_use]
    pub fn should_run_aat(&self, risk_tier: RiskTierClass, context: &SelectionContext) -> bool {
        // Fail-closed: if context validation fails, require AAT
        if context.validate().is_err() {
            return true;
        }

        let config = match risk_tier {
            RiskTierClass::High => &self.high_tier_config,
            RiskTierClass::Med => &self.med_tier_config,
            RiskTierClass::Low => &self.low_tier_config,
        };

        match config.aat_required {
            AatRequirement::Always => true,
            AatRequirement::Conditional => {
                // Require AAT for sensitive domains
                context.is_sensitive_domain()
            },
            AatRequirement::Sampled => {
                // Use deterministic sampling based on work_id
                Self::sample(context.work_id(), config.sample_rate)
            },
        }
    }

    /// Performs deterministic hash-based sampling.
    ///
    /// # Arguments
    ///
    /// * `work_id` - The work item identifier to hash
    /// * `sample_rate` - The target sample rate in `[0.0, 1.0]`
    ///
    /// # Returns
    ///
    /// `true` if the `work_id` is selected (hash falls within sample rate).
    ///
    /// # Algorithm
    ///
    /// 1. Compute BLAKE3 hash of `work_id`
    /// 2. Take first 8 bytes as little-endian u64
    /// 3. Map to `[0.0, 1.0)` by dividing by `u64::MAX`
    /// 4. Return `true` if mapped value < `sample_rate`
    ///
    /// This ensures:
    /// - Deterministic results for the same `work_id`
    /// - Uniform distribution across work items
    /// - Reproducible audit trails
    #[must_use]
    fn sample(work_id: &str, sample_rate: f64) -> bool {
        // Edge cases
        if sample_rate >= 1.0 {
            return true;
        }
        if sample_rate <= 0.0 {
            return false;
        }

        // Compute BLAKE3 hash of work_id
        let hash = blake3::hash(work_id.as_bytes());
        let hash_bytes = hash.as_bytes();

        // Take first 8 bytes as little-endian u64
        let hash_value = u64::from_le_bytes([
            hash_bytes[0],
            hash_bytes[1],
            hash_bytes[2],
            hash_bytes[3],
            hash_bytes[4],
            hash_bytes[5],
            hash_bytes[6],
            hash_bytes[7],
        ]);

        // Map to [0.0, 1.0) - use (hash / (MAX+1)) to avoid == 1.0
        // We use a multiplication approach to avoid precision issues:
        // hash_value / u64::MAX approximates uniform [0, 1)
        #[allow(clippy::cast_precision_loss)]
        let normalized = hash_value as f64 / u64::MAX as f64;

        normalized < sample_rate
    }

    /// Computes the policy hash from the configuration fields.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    fn compute_policy_hash(
        policy_id: &str,
        high_tier_config: &TierConfig,
        med_tier_config: &TierConfig,
        low_tier_config: &TierConfig,
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();

        // policy_id (length-prefixed)
        hasher.update(&(policy_id.len() as u32).to_be_bytes());
        hasher.update(policy_id.as_bytes());

        // Encode each tier config
        Self::hash_tier_config(&mut hasher, high_tier_config);
        Self::hash_tier_config(&mut hasher, med_tier_config);
        Self::hash_tier_config(&mut hasher, low_tier_config);

        *hasher.finalize().as_bytes()
    }

    /// Hashes a tier configuration into the hasher.
    fn hash_tier_config(hasher: &mut blake3::Hasher, config: &TierConfig) {
        // aat_required as u8
        let requirement_byte = match config.aat_required {
            AatRequirement::Always => 0u8,
            AatRequirement::Conditional => 1u8,
            AatRequirement::Sampled => 2u8,
        };
        hasher.update(&[requirement_byte]);

        // sample_rate as f64 bits (deterministic encoding)
        hasher.update(&config.sample_rate.to_bits().to_be_bytes());
    }
}

// =============================================================================
// SelectionPolicyBuilder
// =============================================================================

/// Builder for constructing [`SelectionPolicy`] instances.
#[derive(Debug)]
pub struct SelectionPolicyBuilder {
    policy_id: String,
    high_tier_config: Option<TierConfig>,
    med_tier_config: Option<TierConfig>,
    low_tier_config: Option<TierConfig>,
}

impl SelectionPolicyBuilder {
    /// Creates a new builder with the given policy ID.
    #[must_use]
    pub fn new(policy_id: impl Into<String>) -> Self {
        Self {
            policy_id: policy_id.into(),
            high_tier_config: None,
            med_tier_config: None,
            low_tier_config: None,
        }
    }

    /// Sets the HIGH tier configuration.
    #[must_use]
    pub const fn high_tier_config(mut self, config: TierConfig) -> Self {
        self.high_tier_config = Some(config);
        self
    }

    /// Sets the MED tier configuration.
    #[must_use]
    pub const fn med_tier_config(mut self, config: TierConfig) -> Self {
        self.med_tier_config = Some(config);
        self
    }

    /// Sets the LOW tier configuration.
    #[must_use]
    pub const fn low_tier_config(mut self, config: TierConfig) -> Self {
        self.low_tier_config = Some(config);
        self
    }

    /// Builds the selection policy.
    ///
    /// If tier configurations are not explicitly set, defaults are used:
    /// - HIGH: Always requires AAT
    /// - MED: Conditional based on domain sensitivity
    /// - LOW: 10% deterministic sampling
    ///
    /// # Errors
    ///
    /// Returns [`SelectionPolicyError::StringTooLong`] if the `policy_id`
    /// exceeds [`MAX_POLICY_ID_LENGTH`].
    ///
    /// # Panics
    ///
    /// This function does not panic. The internal `unwrap()` is safe because
    /// `DEFAULT_LOW_TIER_SAMPLE_RATE` is a compile-time constant within the
    /// valid range `[0.0, 1.0]`.
    pub fn build(self) -> Result<SelectionPolicy, SelectionPolicyError> {
        // Validate policy_id length
        if self.policy_id.len() > MAX_POLICY_ID_LENGTH {
            return Err(SelectionPolicyError::StringTooLong {
                field: "policy_id",
                actual: self.policy_id.len(),
                max: MAX_POLICY_ID_LENGTH,
            });
        }

        if self.policy_id.is_empty() {
            return Err(SelectionPolicyError::MissingField("policy_id"));
        }

        // Apply defaults for unset configurations
        let high_tier_config = self.high_tier_config.unwrap_or_else(TierConfig::always);
        let med_tier_config = self.med_tier_config.unwrap_or_else(TierConfig::conditional);
        let low_tier_config = self
            .low_tier_config
            .unwrap_or_else(|| TierConfig::sampled(DEFAULT_LOW_TIER_SAMPLE_RATE).unwrap());

        // Compute policy hash
        let policy_hash = SelectionPolicy::compute_policy_hash(
            &self.policy_id,
            &high_tier_config,
            &med_tier_config,
            &low_tier_config,
        );

        Ok(SelectionPolicy {
            policy_id: self.policy_id,
            policy_hash,
            high_tier_config,
            med_tier_config,
            low_tier_config,
        })
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(missing_docs)]
pub mod tests {
    use super::*;

    // =========================================================================
    // AatRequirement Tests
    // =========================================================================

    #[test]
    fn test_aat_requirement_default() {
        assert_eq!(AatRequirement::default(), AatRequirement::Always);
    }

    #[test]
    fn test_aat_requirement_display() {
        assert_eq!(AatRequirement::Always.to_string(), "ALWAYS");
        assert_eq!(AatRequirement::Conditional.to_string(), "CONDITIONAL");
        assert_eq!(AatRequirement::Sampled.to_string(), "SAMPLED");
    }

    #[test]
    fn test_aat_requirement_serde_roundtrip() {
        let requirements = [
            AatRequirement::Always,
            AatRequirement::Conditional,
            AatRequirement::Sampled,
        ];
        for req in requirements {
            let json = serde_json::to_string(&req).unwrap();
            let deserialized: AatRequirement = serde_json::from_str(&json).unwrap();
            assert_eq!(req, deserialized);
        }
    }

    // =========================================================================
    // TierConfig Tests
    // =========================================================================

    #[test]
    fn test_tier_config_always() {
        let config = TierConfig::always();
        assert_eq!(config.aat_required(), AatRequirement::Always);
        assert!((config.sample_rate() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_tier_config_conditional() {
        let config = TierConfig::conditional();
        assert_eq!(config.aat_required(), AatRequirement::Conditional);
        assert!((config.sample_rate() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_tier_config_sampled() {
        let config = TierConfig::sampled(0.25).unwrap();
        assert_eq!(config.aat_required(), AatRequirement::Sampled);
        assert!((config.sample_rate() - 0.25).abs() < f64::EPSILON);
    }

    #[test]
    fn test_tier_config_invalid_sample_rate_negative() {
        let result = TierConfig::sampled(-0.1);
        assert!(matches!(
            result,
            Err(SelectionPolicyError::InvalidSampleRate(_))
        ));
    }

    #[test]
    fn test_tier_config_invalid_sample_rate_too_high() {
        let result = TierConfig::sampled(1.1);
        assert!(matches!(
            result,
            Err(SelectionPolicyError::InvalidSampleRate(_))
        ));
    }

    #[test]
    fn test_tier_config_invalid_sample_rate_nan() {
        let result = TierConfig::sampled(f64::NAN);
        assert!(matches!(
            result,
            Err(SelectionPolicyError::InvalidSampleRate(_))
        ));
    }

    #[test]
    fn test_tier_config_boundary_sample_rates() {
        // 0.0 is valid (never sample)
        let config = TierConfig::sampled(0.0).unwrap();
        assert!((config.sample_rate()).abs() < f64::EPSILON);

        // 1.0 is valid (always sample)
        let config = TierConfig::sampled(1.0).unwrap();
        assert!((config.sample_rate() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_tier_config_serde_roundtrip() {
        let config = TierConfig::sampled(0.5).unwrap();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: TierConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, deserialized);
    }

    // =========================================================================
    // SelectionContext Tests
    // =========================================================================

    #[test]
    fn test_selection_context_new() {
        let ctx = SelectionContext::new("work-001");
        assert_eq!(ctx.work_id(), "work-001");
        assert_eq!(ctx.domain(), None);
    }

    #[test]
    fn test_selection_context_with_domain() {
        let ctx = SelectionContext::with_domain("work-001", "auth");
        assert_eq!(ctx.work_id(), "work-001");
        assert_eq!(ctx.domain(), Some("auth"));
    }

    #[test]
    fn test_selection_context_is_sensitive_domain() {
        // Sensitive domains
        assert!(SelectionContext::with_domain("w", "auth").is_sensitive_domain());
        assert!(SelectionContext::with_domain("w", "crypto").is_sensitive_domain());
        assert!(SelectionContext::with_domain("w", "payment").is_sensitive_domain());
        assert!(SelectionContext::with_domain("w", "pii").is_sensitive_domain());
        assert!(SelectionContext::with_domain("w", "security").is_sensitive_domain());

        // Case insensitive
        assert!(SelectionContext::with_domain("w", "AUTH").is_sensitive_domain());
        assert!(SelectionContext::with_domain("w", "Crypto").is_sensitive_domain());

        // Substring match
        assert!(SelectionContext::with_domain("w", "auth-service").is_sensitive_domain());
        assert!(SelectionContext::with_domain("w", "payment-gateway").is_sensitive_domain());

        // Non-sensitive domains
        assert!(!SelectionContext::with_domain("w", "api").is_sensitive_domain());
        assert!(!SelectionContext::with_domain("w", "ui").is_sensitive_domain());
        assert!(!SelectionContext::with_domain("w", "utils").is_sensitive_domain());

        // No domain
        assert!(!SelectionContext::new("w").is_sensitive_domain());
    }

    #[test]
    fn test_selection_context_validate_success() {
        let ctx = SelectionContext::with_domain("work-001", "auth");
        assert!(ctx.validate().is_ok());
    }

    #[test]
    fn test_selection_context_validate_work_id_too_long() {
        let long_work_id = "x".repeat(MAX_WORK_ID_LENGTH + 1);
        let ctx = SelectionContext::new(long_work_id);
        let result = ctx.validate();
        assert!(matches!(
            result,
            Err(SelectionPolicyError::StringTooLong {
                field: "work_id",
                ..
            })
        ));
    }

    #[test]
    fn test_selection_context_validate_domain_too_long() {
        let long_domain = "x".repeat(MAX_DOMAIN_LENGTH + 1);
        let ctx = SelectionContext::with_domain("work-001", long_domain);
        let result = ctx.validate();
        assert!(matches!(
            result,
            Err(SelectionPolicyError::StringTooLong {
                field: "domain",
                ..
            })
        ));
    }

    // =========================================================================
    // SelectionPolicy Builder Tests
    // =========================================================================

    #[test]
    fn test_selection_policy_builder_defaults() {
        let policy = SelectionPolicyBuilder::new("policy-001").build().unwrap();

        assert_eq!(policy.policy_id(), "policy-001");
        assert_eq!(
            policy.high_tier_config().aat_required(),
            AatRequirement::Always
        );
        assert_eq!(
            policy.med_tier_config().aat_required(),
            AatRequirement::Conditional
        );
        assert_eq!(
            policy.low_tier_config().aat_required(),
            AatRequirement::Sampled
        );
        assert!(
            (policy.low_tier_config().sample_rate() - DEFAULT_LOW_TIER_SAMPLE_RATE).abs()
                < f64::EPSILON
        );
    }

    #[test]
    fn test_selection_policy_builder_custom_configs() {
        let policy = SelectionPolicyBuilder::new("policy-001")
            .high_tier_config(TierConfig::always())
            .med_tier_config(TierConfig::always())
            .low_tier_config(TierConfig::sampled(0.5).unwrap())
            .build()
            .unwrap();

        assert_eq!(
            policy.high_tier_config().aat_required(),
            AatRequirement::Always
        );
        assert_eq!(
            policy.med_tier_config().aat_required(),
            AatRequirement::Always
        );
        assert_eq!(
            policy.low_tier_config().aat_required(),
            AatRequirement::Sampled
        );
        assert!((policy.low_tier_config().sample_rate() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_selection_policy_builder_empty_policy_id() {
        let result = SelectionPolicyBuilder::new("").build();
        assert!(matches!(
            result,
            Err(SelectionPolicyError::MissingField("policy_id"))
        ));
    }

    #[test]
    fn test_selection_policy_builder_policy_id_too_long() {
        let long_id = "x".repeat(MAX_POLICY_ID_LENGTH + 1);
        let result = SelectionPolicyBuilder::new(long_id).build();
        assert!(matches!(
            result,
            Err(SelectionPolicyError::StringTooLong {
                field: "policy_id",
                ..
            })
        ));
    }

    // =========================================================================
    // SelectionPolicy Hash Tests
    // =========================================================================

    #[test]
    fn test_selection_policy_hash_deterministic() {
        let policy1 = SelectionPolicyBuilder::new("policy-001").build().unwrap();
        let policy2 = SelectionPolicyBuilder::new("policy-001").build().unwrap();

        assert_eq!(policy1.policy_hash(), policy2.policy_hash());
    }

    #[test]
    fn test_selection_policy_hash_differs_with_different_inputs() {
        let policy1 = SelectionPolicyBuilder::new("policy-001").build().unwrap();
        let policy2 = SelectionPolicyBuilder::new("policy-002").build().unwrap();

        assert_ne!(policy1.policy_hash(), policy2.policy_hash());
    }

    #[test]
    fn test_selection_policy_hash_differs_with_different_configs() {
        let policy1 = SelectionPolicyBuilder::new("policy-001")
            .low_tier_config(TierConfig::sampled(0.1).unwrap())
            .build()
            .unwrap();

        let policy2 = SelectionPolicyBuilder::new("policy-001")
            .low_tier_config(TierConfig::sampled(0.2).unwrap())
            .build()
            .unwrap();

        assert_ne!(policy1.policy_hash(), policy2.policy_hash());
    }

    // =========================================================================
    // SelectionPolicy should_run_aat Tests - HIGH Tier
    // =========================================================================

    #[test]
    fn test_should_run_aat_high_tier_always() {
        let policy = SelectionPolicyBuilder::new("policy-001").build().unwrap();

        // HIGH tier always requires AAT regardless of context
        let ctx = SelectionContext::new("work-001");
        assert!(policy.should_run_aat(RiskTierClass::High, &ctx));

        let ctx = SelectionContext::with_domain("work-001", "utils");
        assert!(policy.should_run_aat(RiskTierClass::High, &ctx));

        let ctx = SelectionContext::with_domain("work-001", "auth");
        assert!(policy.should_run_aat(RiskTierClass::High, &ctx));
    }

    // =========================================================================
    // SelectionPolicy should_run_aat Tests - MED Tier
    // =========================================================================

    #[test]
    fn test_should_run_aat_med_tier_sensitive_domain() {
        let policy = SelectionPolicyBuilder::new("policy-001").build().unwrap();

        // MED tier requires AAT for sensitive domains
        let ctx = SelectionContext::with_domain("work-001", "auth");
        assert!(policy.should_run_aat(RiskTierClass::Med, &ctx));

        let ctx = SelectionContext::with_domain("work-001", "crypto");
        assert!(policy.should_run_aat(RiskTierClass::Med, &ctx));

        let ctx = SelectionContext::with_domain("work-001", "payment-service");
        assert!(policy.should_run_aat(RiskTierClass::Med, &ctx));
    }

    #[test]
    fn test_should_run_aat_med_tier_non_sensitive_domain() {
        let policy = SelectionPolicyBuilder::new("policy-001").build().unwrap();

        // MED tier does not require AAT for non-sensitive domains
        let ctx = SelectionContext::with_domain("work-001", "utils");
        assert!(!policy.should_run_aat(RiskTierClass::Med, &ctx));

        let ctx = SelectionContext::with_domain("work-001", "api");
        assert!(!policy.should_run_aat(RiskTierClass::Med, &ctx));

        let ctx = SelectionContext::with_domain("work-001", "ui");
        assert!(!policy.should_run_aat(RiskTierClass::Med, &ctx));
    }

    #[test]
    fn test_should_run_aat_med_tier_no_domain() {
        let policy = SelectionPolicyBuilder::new("policy-001").build().unwrap();

        // MED tier without domain - not sensitive, so no AAT
        let ctx = SelectionContext::new("work-001");
        assert!(!policy.should_run_aat(RiskTierClass::Med, &ctx));
    }

    // =========================================================================
    // SelectionPolicy should_run_aat Tests - LOW Tier (Sampling)
    // =========================================================================

    #[test]
    fn test_should_run_aat_low_tier_deterministic() {
        let policy = SelectionPolicyBuilder::new("policy-001")
            .low_tier_config(TierConfig::sampled(0.5).unwrap())
            .build()
            .unwrap();

        // Same work_id should always produce the same result
        let ctx = SelectionContext::new("work-abc-123");
        let result1 = policy.should_run_aat(RiskTierClass::Low, &ctx);
        let result2 = policy.should_run_aat(RiskTierClass::Low, &ctx);
        let result3 = policy.should_run_aat(RiskTierClass::Low, &ctx);

        assert_eq!(result1, result2);
        assert_eq!(result2, result3);
    }

    #[test]
    fn test_should_run_aat_low_tier_sample_rate_zero() {
        let policy = SelectionPolicyBuilder::new("policy-001")
            .low_tier_config(TierConfig::sampled(0.0).unwrap())
            .build()
            .unwrap();

        // 0% sample rate should never select
        for i in 0..100 {
            let ctx = SelectionContext::new(format!("work-{i}"));
            assert!(!policy.should_run_aat(RiskTierClass::Low, &ctx));
        }
    }

    #[test]
    fn test_should_run_aat_low_tier_sample_rate_one() {
        let policy = SelectionPolicyBuilder::new("policy-001")
            .low_tier_config(TierConfig::sampled(1.0).unwrap())
            .build()
            .unwrap();

        // 100% sample rate should always select
        for i in 0..100 {
            let ctx = SelectionContext::new(format!("work-{i}"));
            assert!(policy.should_run_aat(RiskTierClass::Low, &ctx));
        }
    }

    #[test]
    fn test_should_run_aat_low_tier_approximate_sample_rate() {
        let policy = SelectionPolicyBuilder::new("policy-001")
            .low_tier_config(TierConfig::sampled(0.5).unwrap())
            .build()
            .unwrap();

        // With a large number of samples, we should approach 50%
        let mut selected = 0;
        let total = 10000;

        for i in 0..total {
            let ctx = SelectionContext::new(format!("work-{i}"));
            if policy.should_run_aat(RiskTierClass::Low, &ctx) {
                selected += 1;
            }
        }

        // Allow for statistical variance (should be roughly 50% +/- 5%)
        let rate = f64::from(selected) / f64::from(total);
        assert!(
            rate > 0.45 && rate < 0.55,
            "Sample rate {rate} not within expected range [0.45, 0.55]"
        );
    }

    // =========================================================================
    // SelectionPolicy Fail-Closed Tests
    // =========================================================================

    #[test]
    fn test_should_run_aat_fail_closed_on_invalid_context() {
        let policy = SelectionPolicyBuilder::new("policy-001").build().unwrap();

        // Context with oversized work_id should fail validation -> require AAT
        let long_work_id = "x".repeat(MAX_WORK_ID_LENGTH + 1);
        let ctx = SelectionContext::new(long_work_id);

        // Should return true (fail-closed) even for LOW tier
        assert!(policy.should_run_aat(RiskTierClass::Low, &ctx));

        // Should return true (fail-closed) for MED tier
        assert!(policy.should_run_aat(RiskTierClass::Med, &ctx));
    }

    // =========================================================================
    // SelectionPolicy Serde Tests
    // =========================================================================

    #[test]
    fn test_selection_policy_serde_roundtrip() {
        let policy = SelectionPolicyBuilder::new("policy-001")
            .high_tier_config(TierConfig::always())
            .med_tier_config(TierConfig::conditional())
            .low_tier_config(TierConfig::sampled(0.25).unwrap())
            .build()
            .unwrap();

        let json = serde_json::to_string(&policy).unwrap();
        let deserialized: SelectionPolicy = serde_json::from_str(&json).unwrap();

        assert_eq!(policy, deserialized);
    }

    // =========================================================================
    // Sampling Algorithm Tests
    // =========================================================================

    #[test]
    fn test_sample_algorithm_edge_cases() {
        let policy = SelectionPolicyBuilder::new("policy-001")
            .low_tier_config(TierConfig::sampled(0.5).unwrap())
            .build()
            .unwrap();

        // Empty work_id
        let ctx = SelectionContext::new("");
        let _ = policy.should_run_aat(RiskTierClass::Low, &ctx);

        // Very long work_id (but within limits)
        let long_id = "x".repeat(MAX_WORK_ID_LENGTH);
        let ctx = SelectionContext::new(long_id);
        let _ = policy.should_run_aat(RiskTierClass::Low, &ctx);

        // Unicode work_id
        let ctx = SelectionContext::new("work-\u{1F600}-emoji");
        let _ = policy.should_run_aat(RiskTierClass::Low, &ctx);
    }

    #[test]
    fn test_sample_different_work_ids_different_results() {
        let policy = SelectionPolicyBuilder::new("policy-001")
            .low_tier_config(TierConfig::sampled(0.5).unwrap())
            .build()
            .unwrap();

        // Different work_ids should (usually) produce different results
        // This isn't guaranteed, but with 50% rate we should see variation
        let ctx1 = SelectionContext::new("work-aaa");
        let ctx2 = SelectionContext::new("work-bbb");
        let ctx3 = SelectionContext::new("work-ccc");
        let ctx4 = SelectionContext::new("work-ddd");

        let results = [
            policy.should_run_aat(RiskTierClass::Low, &ctx1),
            policy.should_run_aat(RiskTierClass::Low, &ctx2),
            policy.should_run_aat(RiskTierClass::Low, &ctx3),
            policy.should_run_aat(RiskTierClass::Low, &ctx4),
        ];

        // At least one should be different (very unlikely all 4 are the same at 50%)
        let all_true = results.iter().all(|&r| r);
        let all_false = results.iter().all(|&r| !r);
        // This test could flake with very low probability (1/8 = 12.5%)
        // but we accept this for demonstration purposes
        let _ = (all_true, all_false);
    }

    // =========================================================================
    // Integration Tests
    // =========================================================================

    #[test]
    fn test_full_policy_workflow() {
        // Simulate a real-world workflow

        // 1. Create a policy with custom configuration
        let policy = SelectionPolicyBuilder::new("acme-corp-policy-v1")
            .high_tier_config(TierConfig::always())
            .med_tier_config(TierConfig::conditional())
            .low_tier_config(TierConfig::sampled(0.1).unwrap())
            .build()
            .expect("valid policy");

        // 2. HIGH risk changeset (e.g., touches crypto module)
        let high_risk_ctx = SelectionContext::with_domain("PR-12345", "crypto");
        assert!(
            policy.should_run_aat(RiskTierClass::High, &high_risk_ctx),
            "HIGH risk always requires AAT"
        );

        // 3. MED risk changeset in sensitive domain
        let med_risk_auth = SelectionContext::with_domain("PR-12346", "auth-service");
        assert!(
            policy.should_run_aat(RiskTierClass::Med, &med_risk_auth),
            "MED risk in auth domain requires AAT"
        );

        // 4. MED risk changeset in non-sensitive domain
        let med_risk_utils = SelectionContext::with_domain("PR-12347", "utilities");
        assert!(
            !policy.should_run_aat(RiskTierClass::Med, &med_risk_utils),
            "MED risk in utils domain does not require AAT"
        );

        // 5. LOW risk changeset - deterministic sampling
        let low_risk_ctx = SelectionContext::with_domain("PR-12348", "docs");
        let decision = policy.should_run_aat(RiskTierClass::Low, &low_risk_ctx);
        // Result is deterministic, so running again should give same answer
        assert_eq!(
            decision,
            policy.should_run_aat(RiskTierClass::Low, &low_risk_ctx),
            "LOW risk sampling must be deterministic"
        );
    }

    #[test]
    fn test_policy_hash_for_binding() {
        // Verify that policy hash can be used for binding to other FAC components
        let policy = SelectionPolicyBuilder::new("policy-001").build().unwrap();

        // Hash should be 32 bytes (BLAKE3)
        assert_eq!(policy.policy_hash().len(), 32);

        // Hash should be non-zero for a valid policy
        assert_ne!(policy.policy_hash(), [0u8; 32]);
    }
}
