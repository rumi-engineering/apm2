// AGENT-AUTHORED
//! Determinism envelope schema for the Forge Admission Cycle.
//!
//! This module defines [`DeterminismEnvelope`] which encapsulates the
//! determinism verification results for AAT (Agent Acceptance Testing) runs.
//! The envelope tracks multiple runs and computes stability digests to detect
//! flakiness.
//!
//! # Security Model
//!
//! The determinism envelope implements a **fail-closed** security posture:
//!
//! - Uses the [`RiskTier`] enum for type-safe exhaustive matching
//! - Stability checking requires explicit confirmation of identical digests
//! - All digests use BLAKE3 for cryptographic integrity (project standard)
//!
//! # Required Run Counts by Risk Tier
//!
//! The `required_run_count` function maps risk tiers to minimum run
//! requirements using the [`RiskTier`] enum:
//!
//! - **Tier4** (highest risk): 3 runs required - maximum scrutiny
//! - **Tier3** (high risk): 3 runs required - elevated scrutiny
//! - **Tier2** (medium risk): 2 runs required - moderate scrutiny
//! - **Tier1** (low risk): 1 run required - baseline verification
//! - **Tier0** (lowest risk): 1 run required - minimal verification
//!
//! [`RiskTier`]: super::policy_resolution::RiskTier
//!
//! # Stability Checking
//!
//! [`check_stability`] compares run digests to determine if all runs produced
//! identical results. This is the core mechanism for detecting flaky tests:
//!
//! - `Stable`: All run digests are identical
//! - `Mismatch`: At least one run digest differs from the others
//!
//! # Example
//!
//! ```rust
//! use apm2_core::fac::determinism::{
//!     DeterminismEnvelope, DeterminismEnvelopeBuilder, check_stability,
//!     compute_stability_digest, required_run_count,
//! };
//! use apm2_core::fac::{DeterminismClass, DeterminismStatus, RiskTier};
//!
//! // Determine required runs for a high-risk change
//! let runs = required_run_count(RiskTier::Tier3);
//! assert_eq!(runs, 3);
//!
//! // Create run digests (simulating 3 identical runs)
//! let run_hash = [0x42; 32];
//! let run_hashes = vec![run_hash, run_hash, run_hash];
//!
//! // Check stability
//! let status = check_stability(&run_hashes);
//! assert_eq!(status, DeterminismStatus::Stable);
//!
//! // Compute stability digest
//! let terminal_evidence_digest = [0x11; 32];
//! let terminal_verifier_outputs_digest = [0x22; 32];
//! let verdict = 1u8; // PASS
//! let stability_digest = compute_stability_digest(
//!     verdict,
//!     &terminal_evidence_digest,
//!     &terminal_verifier_outputs_digest,
//! );
//!
//! // Build envelope
//! let envelope = DeterminismEnvelopeBuilder::new()
//!     .determinism_class(DeterminismClass::FullyDeterministic)
//!     .run_count(3)
//!     .run_receipt_hashes(run_hashes)
//!     .terminal_evidence_digest(terminal_evidence_digest)
//!     .terminal_verifier_outputs_digest(terminal_verifier_outputs_digest)
//!     .stability_digest(stability_digest)
//!     .build()
//!     .expect("valid envelope");
//!
//! assert!(envelope.validate().is_ok());
//! ```

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::aat_receipt::DeterminismStatus;
use super::policy_resolution::{DeterminismClass, RiskTier};

// =============================================================================
// Resource Limits
// =============================================================================

/// Maximum number of run receipt hashes allowed in a determinism envelope.
///
/// This prevents denial-of-service attacks via oversized repeated fields.
/// Aligned with `MAX_RUN_RECEIPT_HASHES` in `aat_receipt.rs`.
pub const MAX_RUN_RECEIPT_HASHES: usize = 256;

/// Maximum run count allowed. This bounds the `run_count` field to prevent
/// resource exhaustion from excessive run requirements.
/// Must be >= `MAX_RUN_RECEIPT_HASHES` to avoid overflow.
pub const MAX_RUN_COUNT: u32 = 256;

// =============================================================================
// Risk Tier Constants
// =============================================================================

/// Risk tier value for LOW risk (minimal scrutiny).
pub const RISK_TIER_LOW: u8 = 0;

/// Risk tier value for MEDIUM risk (elevated scrutiny).
pub const RISK_TIER_MED: u8 = 1;

/// Risk tier value for HIGH risk (maximum scrutiny).
pub const RISK_TIER_HIGH: u8 = 2;

// =============================================================================
// Required Run Counts
// =============================================================================

/// Required run count for Tier4 (highest risk).
pub const REQUIRED_RUNS_TIER4: u32 = 3;

/// Required run count for Tier3 (high risk).
pub const REQUIRED_RUNS_TIER3: u32 = 3;

/// Required run count for Tier2 (medium risk).
pub const REQUIRED_RUNS_TIER2: u32 = 2;

/// Required run count for Tier1 (low risk).
pub const REQUIRED_RUNS_TIER1: u32 = 1;

/// Required run count for Tier0 (lowest risk).
pub const REQUIRED_RUNS_TIER0: u32 = 1;

/// Required run count for HIGH risk tier (legacy alias for Tier3+).
pub const REQUIRED_RUNS_HIGH: u32 = 3;

/// Required run count for MEDIUM risk tier (legacy alias for Tier2).
pub const REQUIRED_RUNS_MED: u32 = 2;

/// Required run count for LOW risk tier (legacy alias for Tier0-1).
pub const REQUIRED_RUNS_LOW: u32 = 1;

/// Default required run count for unknown risk tiers (fail-closed).
pub const REQUIRED_RUNS_DEFAULT: u32 = 3;

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during determinism envelope operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeterminismError {
    /// Missing required field.
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// Invalid data in envelope.
    #[error("invalid envelope data: {0}")]
    InvalidData(String),

    /// Run count does not match run receipt hashes length.
    #[error("run_count ({run_count}) does not match run_receipt_hashes.len() ({hash_count})")]
    RunCountMismatch {
        /// The declared run count.
        run_count: u32,
        /// The actual number of hashes.
        hash_count: usize,
    },

    /// Collection size exceeds limit.
    #[error("collection {field} exceeds limit: {actual} > {max}")]
    CollectionTooLarge {
        /// Name of the field that exceeded the limit.
        field: &'static str,
        /// Actual size.
        actual: usize,
        /// Maximum allowed size.
        max: usize,
    },

    /// Stability digest does not match computed value.
    #[error(
        "stability_digest mismatch: expected hash(verdict, terminal_evidence_digest, terminal_verifier_outputs_digest)"
    )]
    StabilityDigestMismatch,

    /// Zero run count is not allowed.
    #[error("run_count must be at least 1")]
    ZeroRunCount,
}

// =============================================================================
// Core Functions
// =============================================================================

/// Returns the required run count for a given risk tier.
///
/// Uses the [`RiskTier`] enum from policy resolution to ensure type safety
/// and exhaustive handling of all risk tiers.
///
/// # Arguments
///
/// * `risk_tier` - The risk tier enum value
///
/// # Returns
///
/// The minimum number of runs required for the given risk tier:
/// - `Tier0` (lowest risk): 1 run
/// - `Tier1` (low risk): 1 run
/// - `Tier2` (medium risk): 2 runs
/// - `Tier3` (high risk): 3 runs
/// - `Tier4` (highest risk): 3 runs
///
/// # Example
///
/// ```rust
/// use apm2_core::fac::RiskTier;
/// use apm2_core::fac::determinism::required_run_count;
///
/// assert_eq!(required_run_count(RiskTier::Tier0), 1);
/// assert_eq!(required_run_count(RiskTier::Tier1), 1);
/// assert_eq!(required_run_count(RiskTier::Tier2), 2);
/// assert_eq!(required_run_count(RiskTier::Tier3), 3);
/// assert_eq!(required_run_count(RiskTier::Tier4), 3);
/// ```
#[must_use]
pub const fn required_run_count(risk_tier: RiskTier) -> u32 {
    match risk_tier {
        RiskTier::Tier0 => REQUIRED_RUNS_TIER0,
        RiskTier::Tier1 => REQUIRED_RUNS_TIER1,
        RiskTier::Tier2 => REQUIRED_RUNS_TIER2,
        RiskTier::Tier3 => REQUIRED_RUNS_TIER3,
        RiskTier::Tier4 => REQUIRED_RUNS_TIER4,
    }
}

/// Computes the stability digest from its components using BLAKE3.
///
/// The stability digest is defined as:
/// `BLAKE3(verdict || terminal_evidence_digest ||
/// terminal_verifier_outputs_digest)`
///
/// This provides a single hash that captures the "stable" aspects of the
/// AAT result, allowing quick comparison across runs.
///
/// # Arguments
///
/// * `verdict` - The AAT verdict as a u8 (1=PASS, 2=FAIL, 3=`NEEDS_INPUT`)
/// * `terminal_evidence_digest` - Digest of machine-checkable terminal evidence
/// * `terminal_verifier_outputs_digest` - Digest of terminal verifier outputs
///
/// # Returns
///
/// A 32-byte BLAKE3 hash of the concatenated inputs.
///
/// # Example
///
/// ```rust
/// use apm2_core::fac::determinism::compute_stability_digest;
///
/// let verdict = 1u8; // PASS
/// let terminal_evidence_digest = [0x11; 32];
/// let terminal_verifier_outputs_digest = [0x22; 32];
///
/// let digest1 = compute_stability_digest(
///     verdict,
///     &terminal_evidence_digest,
///     &terminal_verifier_outputs_digest,
/// );
/// let digest2 = compute_stability_digest(
///     verdict,
///     &terminal_evidence_digest,
///     &terminal_verifier_outputs_digest,
/// );
///
/// // Same inputs produce same digest
/// assert_eq!(digest1, digest2);
///
/// // Different verdict produces different digest
/// let digest3 = compute_stability_digest(
///     2u8, // FAIL
///     &terminal_evidence_digest,
///     &terminal_verifier_outputs_digest,
/// );
/// assert_ne!(digest1, digest3);
/// ```
#[must_use]
pub fn compute_stability_digest(
    verdict: u8,
    terminal_evidence_digest: &[u8; 32],
    terminal_verifier_outputs_digest: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[verdict]);
    hasher.update(terminal_evidence_digest);
    hasher.update(terminal_verifier_outputs_digest);
    *hasher.finalize().as_bytes()
}

/// Checks stability by comparing run digests to determine if all runs
/// produced identical results.
///
/// This is the core mechanism for detecting flaky tests. All run digests
/// must be byte-for-byte identical for the result to be `Stable`.
///
/// # Arguments
///
/// * `run_receipt_hashes` - Slice of 32-byte hashes from each run
///
/// # Returns
///
/// - [`DeterminismStatus::Stable`] if all run digests are identical (or
///   empty/single)
/// - [`DeterminismStatus::Mismatch`] if any run digest differs
///
/// # Security
///
/// Uses constant-time comparison via `subtle::ConstantTimeEq` to prevent
/// timing side-channel attacks when comparing cryptographic digests.
///
/// # Example
///
/// ```rust
/// use apm2_core::fac::DeterminismStatus;
/// use apm2_core::fac::determinism::check_stability;
///
/// // All identical -> Stable
/// let identical = vec![[0x42; 32], [0x42; 32], [0x42; 32]];
/// assert_eq!(check_stability(&identical), DeterminismStatus::Stable);
///
/// // One differs -> Mismatch
/// let different = vec![[0x42; 32], [0x42; 32], [0x99; 32]];
/// assert_eq!(check_stability(&different), DeterminismStatus::Mismatch);
///
/// // Empty or single -> Stable (vacuously true)
/// assert_eq!(check_stability(&[]), DeterminismStatus::Stable);
/// assert_eq!(check_stability(&[[0x42; 32]]), DeterminismStatus::Stable);
/// ```
#[must_use]
pub fn check_stability(run_receipt_hashes: &[[u8; 32]]) -> DeterminismStatus {
    // Empty or single run is vacuously stable
    if run_receipt_hashes.len() <= 1 {
        return DeterminismStatus::Stable;
    }

    // Compare all hashes to the first one using constant-time comparison
    let first = &run_receipt_hashes[0];
    for hash in &run_receipt_hashes[1..] {
        if !constant_time_eq(first, hash) {
            return DeterminismStatus::Mismatch;
        }
    }

    DeterminismStatus::Stable
}

/// Constant-time byte array comparison to prevent timing attacks.
#[inline]
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    use subtle::ConstantTimeEq;
    bool::from(a.ct_eq(b))
}

// =============================================================================
// DeterminismEnvelope
// =============================================================================

/// Envelope encapsulating determinism verification results for AAT runs.
///
/// The envelope tracks multiple runs and their digests to detect flakiness
/// and ensure reproducibility of AAT results.
///
/// # Fields
///
/// - `determinism_class` - Determinism class enum (`NonDeterministic`,
///   `SoftDeterministic`, `FullyDeterministic`)
/// - `run_count` - Number of AAT runs executed (u32 to match
///   `MAX_RUN_RECEIPT_HASHES`)
/// - `run_receipt_hashes` - Hashes of individual run receipts
/// - `terminal_evidence_digest` - Digest of machine-checkable terminal evidence
/// - `terminal_verifier_outputs_digest` - Digest of terminal verifier outputs
/// - `stability_digest` - Hash of (verdict, `terminal_evidence_digest`,
///   `terminal_verifier_outputs_digest`)
///
/// # Invariants
///
/// - `run_receipt_hashes.len()` MUST equal `run_count`
/// - `run_count` MUST be at least 1
/// - `stability_digest` MUST match computed value from components
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeterminismEnvelope {
    /// Determinism class (`NonDeterministic`, `SoftDeterministic`,
    /// `FullyDeterministic`).
    pub determinism_class: DeterminismClass,

    /// Number of AAT runs executed.
    pub run_count: u32,

    /// Hashes of individual run receipts.
    #[serde(with = "vec_hash_serde")]
    pub run_receipt_hashes: Vec<[u8; 32]>,

    /// Digest of machine-checkable terminal evidence.
    #[serde(with = "serde_bytes")]
    pub terminal_evidence_digest: [u8; 32],

    /// Digest of terminal verifier outputs.
    #[serde(with = "serde_bytes")]
    pub terminal_verifier_outputs_digest: [u8; 32],

    /// Stability digest = hash(verdict, `terminal_evidence_digest`,
    /// `terminal_verifier_outputs_digest`).
    #[serde(with = "serde_bytes")]
    pub stability_digest: [u8; 32],
}

/// Custom serde for Vec<[u8; 32]>.
mod vec_hash_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(hashes: &[[u8; 32]], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let vec_of_vecs: Vec<&[u8]> = hashes.iter().map(<[u8; 32]>::as_slice).collect();
        vec_of_vecs.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec_of_vecs = Vec::<Vec<u8>>::deserialize(deserializer)?;
        vec_of_vecs
            .into_iter()
            .map(|v| {
                if v.len() != 32 {
                    return Err(serde::de::Error::custom(format!(
                        "expected 32 bytes, got {}",
                        v.len()
                    )));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&v);
                Ok(arr)
            })
            .collect()
    }
}

impl DeterminismEnvelope {
    /// Validates all invariants of the envelope.
    ///
    /// # Invariants Checked
    ///
    /// - `run_count` must be at least 1
    /// - `run_receipt_hashes.len()` must equal `run_count`
    /// - `run_receipt_hashes.len()` must not exceed `MAX_RUN_RECEIPT_HASHES`
    /// - `determinism_class` is validated by being a proper enum variant
    ///
    /// # Returns
    ///
    /// `Ok(())` if all validations pass, `Err(DeterminismError)` otherwise.
    ///
    /// # Errors
    ///
    /// Returns various [`DeterminismError`] variants for validation failures.
    pub fn validate(&self) -> Result<(), DeterminismError> {
        // Validate run_count is at least 1
        if self.run_count == 0 {
            return Err(DeterminismError::ZeroRunCount);
        }

        // Validate run_count matches run_receipt_hashes.len()
        if (self.run_count as usize) != self.run_receipt_hashes.len() {
            return Err(DeterminismError::RunCountMismatch {
                run_count: self.run_count,
                hash_count: self.run_receipt_hashes.len(),
            });
        }

        // Validate collection size
        if self.run_receipt_hashes.len() > MAX_RUN_RECEIPT_HASHES {
            return Err(DeterminismError::CollectionTooLarge {
                field: "run_receipt_hashes",
                actual: self.run_receipt_hashes.len(),
                max: MAX_RUN_RECEIPT_HASHES,
            });
        }

        // determinism_class is validated by the type system (DeterminismClass enum)
        // No additional validation needed

        Ok(())
    }

    /// Checks if all runs produced stable (identical) results.
    ///
    /// This is a convenience method that calls [`check_stability`] on the
    /// envelope's run receipt hashes.
    ///
    /// # Returns
    ///
    /// The [`DeterminismStatus`] indicating whether runs were stable.
    #[must_use]
    pub fn check_run_stability(&self) -> DeterminismStatus {
        check_stability(&self.run_receipt_hashes)
    }

    /// Validates that the `stability_digest` matches the computed value.
    ///
    /// # Arguments
    ///
    /// * `verdict` - The AAT verdict as a u8
    ///
    /// # Returns
    ///
    /// `Ok(())` if the stability digest matches, error otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`DeterminismError::StabilityDigestMismatch`] if the stored
    /// `stability_digest` does not match the computed value.
    pub fn validate_stability_digest(&self, verdict: u8) -> Result<(), DeterminismError> {
        let computed = compute_stability_digest(
            verdict,
            &self.terminal_evidence_digest,
            &self.terminal_verifier_outputs_digest,
        );

        if !constant_time_eq(&self.stability_digest, &computed) {
            return Err(DeterminismError::StabilityDigestMismatch);
        }

        Ok(())
    }
}

// =============================================================================
// Builder
// =============================================================================

/// Builder for constructing [`DeterminismEnvelope`] instances with validation.
#[derive(Debug, Default)]
pub struct DeterminismEnvelopeBuilder {
    determinism_class: Option<DeterminismClass>,
    run_count: Option<u32>,
    run_receipt_hashes: Option<Vec<[u8; 32]>>,
    terminal_evidence_digest: Option<[u8; 32]>,
    terminal_verifier_outputs_digest: Option<[u8; 32]>,
    stability_digest: Option<[u8; 32]>,
}

impl DeterminismEnvelopeBuilder {
    /// Creates a new empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the determinism class.
    #[must_use]
    pub const fn determinism_class(mut self, class: DeterminismClass) -> Self {
        self.determinism_class = Some(class);
        self
    }

    /// Sets the run count.
    #[must_use]
    pub const fn run_count(mut self, count: u32) -> Self {
        self.run_count = Some(count);
        self
    }

    /// Sets the run receipt hashes.
    #[must_use]
    pub fn run_receipt_hashes(mut self, hashes: Vec<[u8; 32]>) -> Self {
        self.run_receipt_hashes = Some(hashes);
        self
    }

    /// Sets the terminal evidence digest.
    #[must_use]
    pub const fn terminal_evidence_digest(mut self, digest: [u8; 32]) -> Self {
        self.terminal_evidence_digest = Some(digest);
        self
    }

    /// Sets the terminal verifier outputs digest.
    #[must_use]
    pub const fn terminal_verifier_outputs_digest(mut self, digest: [u8; 32]) -> Self {
        self.terminal_verifier_outputs_digest = Some(digest);
        self
    }

    /// Sets the stability digest.
    #[must_use]
    pub const fn stability_digest(mut self, digest: [u8; 32]) -> Self {
        self.stability_digest = Some(digest);
        self
    }

    /// Builds the envelope, validating all required fields.
    ///
    /// # Errors
    ///
    /// Returns [`DeterminismError::MissingField`] if any required field is not
    /// set. Returns other [`DeterminismError`] variants for validation
    /// failures.
    pub fn build(self) -> Result<DeterminismEnvelope, DeterminismError> {
        let envelope = DeterminismEnvelope {
            determinism_class: self
                .determinism_class
                .ok_or(DeterminismError::MissingField("determinism_class"))?,
            run_count: self
                .run_count
                .ok_or(DeterminismError::MissingField("run_count"))?,
            run_receipt_hashes: self
                .run_receipt_hashes
                .ok_or(DeterminismError::MissingField("run_receipt_hashes"))?,
            terminal_evidence_digest: self
                .terminal_evidence_digest
                .ok_or(DeterminismError::MissingField("terminal_evidence_digest"))?,
            terminal_verifier_outputs_digest: self.terminal_verifier_outputs_digest.ok_or(
                DeterminismError::MissingField("terminal_verifier_outputs_digest"),
            )?,
            stability_digest: self
                .stability_digest
                .ok_or(DeterminismError::MissingField("stability_digest"))?,
        };

        // Validate all invariants
        envelope.validate()?;

        Ok(envelope)
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
    // required_run_count Tests
    // =========================================================================

    #[test]
    fn test_required_run_count_tier0() {
        assert_eq!(required_run_count(RiskTier::Tier0), REQUIRED_RUNS_TIER0);
        assert_eq!(required_run_count(RiskTier::Tier0), 1);
    }

    #[test]
    fn test_required_run_count_tier1() {
        assert_eq!(required_run_count(RiskTier::Tier1), REQUIRED_RUNS_TIER1);
        assert_eq!(required_run_count(RiskTier::Tier1), 1);
    }

    #[test]
    fn test_required_run_count_tier2() {
        assert_eq!(required_run_count(RiskTier::Tier2), REQUIRED_RUNS_TIER2);
        assert_eq!(required_run_count(RiskTier::Tier2), 2);
    }

    #[test]
    fn test_required_run_count_tier3() {
        assert_eq!(required_run_count(RiskTier::Tier3), REQUIRED_RUNS_TIER3);
        assert_eq!(required_run_count(RiskTier::Tier3), 3);
    }

    #[test]
    fn test_required_run_count_tier4() {
        assert_eq!(required_run_count(RiskTier::Tier4), REQUIRED_RUNS_TIER4);
        assert_eq!(required_run_count(RiskTier::Tier4), 3);
    }

    #[test]
    fn test_required_run_count_exhaustive() {
        // Verify all tiers are handled (exhaustive match)
        for tier in [
            RiskTier::Tier0,
            RiskTier::Tier1,
            RiskTier::Tier2,
            RiskTier::Tier3,
            RiskTier::Tier4,
        ] {
            // Should not panic - proves exhaustive handling
            let _ = required_run_count(tier);
        }
    }

    // =========================================================================
    // compute_stability_digest Tests
    // =========================================================================

    #[test]
    fn test_compute_stability_digest_deterministic() {
        let verdict = 1u8;
        let terminal_evidence_digest = [0x11; 32];
        let terminal_verifier_outputs_digest = [0x22; 32];

        let digest1 = compute_stability_digest(
            verdict,
            &terminal_evidence_digest,
            &terminal_verifier_outputs_digest,
        );
        let digest2 = compute_stability_digest(
            verdict,
            &terminal_evidence_digest,
            &terminal_verifier_outputs_digest,
        );

        assert_eq!(digest1, digest2);
    }

    #[test]
    fn test_compute_stability_digest_different_verdict() {
        let terminal_evidence_digest = [0x11; 32];
        let terminal_verifier_outputs_digest = [0x22; 32];

        let digest_pass = compute_stability_digest(
            1,
            &terminal_evidence_digest,
            &terminal_verifier_outputs_digest,
        );
        let digest_fail = compute_stability_digest(
            2,
            &terminal_evidence_digest,
            &terminal_verifier_outputs_digest,
        );

        assert_ne!(digest_pass, digest_fail);
    }

    #[test]
    fn test_compute_stability_digest_different_evidence() {
        let verdict = 1u8;
        let terminal_verifier_outputs_digest = [0x22; 32];

        let digest1 =
            compute_stability_digest(verdict, &[0x11; 32], &terminal_verifier_outputs_digest);
        let digest2 =
            compute_stability_digest(verdict, &[0x99; 32], &terminal_verifier_outputs_digest);

        assert_ne!(digest1, digest2);
    }

    #[test]
    fn test_compute_stability_digest_different_verifier_outputs() {
        let verdict = 1u8;
        let terminal_evidence_digest = [0x11; 32];

        let digest1 = compute_stability_digest(verdict, &terminal_evidence_digest, &[0x22; 32]);
        let digest2 = compute_stability_digest(verdict, &terminal_evidence_digest, &[0x99; 32]);

        assert_ne!(digest1, digest2);
    }

    // =========================================================================
    // check_stability Tests
    // =========================================================================

    #[test]
    fn test_check_stability_empty() {
        assert_eq!(check_stability(&[]), DeterminismStatus::Stable);
    }

    #[test]
    fn test_check_stability_single() {
        assert_eq!(check_stability(&[[0x42; 32]]), DeterminismStatus::Stable);
    }

    #[test]
    fn test_check_stability_identical_two() {
        let hashes = vec![[0x42; 32], [0x42; 32]];
        assert_eq!(check_stability(&hashes), DeterminismStatus::Stable);
    }

    #[test]
    fn test_check_stability_identical_three() {
        let hashes = vec![[0x42; 32], [0x42; 32], [0x42; 32]];
        assert_eq!(check_stability(&hashes), DeterminismStatus::Stable);
    }

    #[test]
    fn test_check_stability_mismatch_first_two() {
        let hashes = vec![[0x42; 32], [0x99; 32]];
        assert_eq!(check_stability(&hashes), DeterminismStatus::Mismatch);
    }

    #[test]
    fn test_check_stability_mismatch_last() {
        let hashes = vec![[0x42; 32], [0x42; 32], [0x99; 32]];
        assert_eq!(check_stability(&hashes), DeterminismStatus::Mismatch);
    }

    #[test]
    fn test_check_stability_mismatch_middle() {
        let hashes = vec![[0x42; 32], [0x99; 32], [0x42; 32]];
        assert_eq!(check_stability(&hashes), DeterminismStatus::Mismatch);
    }

    // =========================================================================
    // DeterminismEnvelope Builder Tests
    // =========================================================================

    fn create_test_envelope() -> DeterminismEnvelope {
        let terminal_evidence_digest = [0x11; 32];
        let terminal_verifier_outputs_digest = [0x22; 32];
        let stability_digest = compute_stability_digest(
            1,
            &terminal_evidence_digest,
            &terminal_verifier_outputs_digest,
        );

        DeterminismEnvelopeBuilder::new()
            .determinism_class(DeterminismClass::FullyDeterministic)
            .run_count(3)
            .run_receipt_hashes(vec![[0x42; 32], [0x42; 32], [0x42; 32]])
            .terminal_evidence_digest(terminal_evidence_digest)
            .terminal_verifier_outputs_digest(terminal_verifier_outputs_digest)
            .stability_digest(stability_digest)
            .build()
            .expect("valid envelope")
    }

    #[test]
    fn test_builder_creates_valid_envelope() {
        let envelope = create_test_envelope();
        assert_eq!(
            envelope.determinism_class,
            DeterminismClass::FullyDeterministic
        );
        assert_eq!(envelope.run_count, 3);
        assert_eq!(envelope.run_receipt_hashes.len(), 3);
    }

    #[test]
    fn test_builder_missing_field() {
        let result = DeterminismEnvelopeBuilder::new()
            .determinism_class(DeterminismClass::FullyDeterministic)
            // Missing other fields
            .build();

        assert!(matches!(result, Err(DeterminismError::MissingField(_))));
    }

    #[test]
    fn test_envelope_validate_success() {
        let envelope = create_test_envelope();
        assert!(envelope.validate().is_ok());
    }

    #[test]
    fn test_envelope_validate_run_count_mismatch() {
        let terminal_evidence_digest = [0x11; 32];
        let terminal_verifier_outputs_digest = [0x22; 32];
        let stability_digest = compute_stability_digest(
            1,
            &terminal_evidence_digest,
            &terminal_verifier_outputs_digest,
        );

        let result = DeterminismEnvelopeBuilder::new()
            .determinism_class(DeterminismClass::FullyDeterministic)
            .run_count(5) // Mismatch: says 5
            .run_receipt_hashes(vec![[0x42; 32], [0x42; 32], [0x42; 32]]) // But only 3
            .terminal_evidence_digest(terminal_evidence_digest)
            .terminal_verifier_outputs_digest(terminal_verifier_outputs_digest)
            .stability_digest(stability_digest)
            .build();

        assert!(matches!(
            result,
            Err(DeterminismError::RunCountMismatch {
                run_count: 5,
                hash_count: 3
            })
        ));
    }

    #[test]
    fn test_envelope_validate_zero_run_count() {
        let terminal_evidence_digest = [0x11; 32];
        let terminal_verifier_outputs_digest = [0x22; 32];
        let stability_digest = compute_stability_digest(
            1,
            &terminal_evidence_digest,
            &terminal_verifier_outputs_digest,
        );

        let result = DeterminismEnvelopeBuilder::new()
            .determinism_class(DeterminismClass::FullyDeterministic)
            .run_count(0)
            .run_receipt_hashes(vec![])
            .terminal_evidence_digest(terminal_evidence_digest)
            .terminal_verifier_outputs_digest(terminal_verifier_outputs_digest)
            .stability_digest(stability_digest)
            .build();

        assert!(matches!(result, Err(DeterminismError::ZeroRunCount)));
    }

    #[test]
    fn test_envelope_validate_collection_too_large() {
        let terminal_evidence_digest = [0x11; 32];
        let terminal_verifier_outputs_digest = [0x22; 32];
        let stability_digest = compute_stability_digest(
            1,
            &terminal_evidence_digest,
            &terminal_verifier_outputs_digest,
        );

        // Create 257 hashes (exceeds MAX_RUN_RECEIPT_HASHES = 256)
        let too_many_hashes: Vec<[u8; 32]> =
            (0..=MAX_RUN_RECEIPT_HASHES).map(|_| [0x42; 32]).collect();

        // Build envelope manually with matching run_count
        let envelope = DeterminismEnvelope {
            determinism_class: DeterminismClass::FullyDeterministic,
            run_count: 257, // Now u32 can hold 257
            run_receipt_hashes: too_many_hashes,
            terminal_evidence_digest,
            terminal_verifier_outputs_digest,
            stability_digest,
        };

        let result = envelope.validate();
        // Should fail on CollectionTooLarge
        assert!(matches!(
            result,
            Err(DeterminismError::CollectionTooLarge { .. })
        ));
    }

    // =========================================================================
    // DeterminismEnvelope Method Tests
    // =========================================================================

    #[test]
    fn test_envelope_check_run_stability_stable() {
        let envelope = create_test_envelope();
        assert_eq!(envelope.check_run_stability(), DeterminismStatus::Stable);
    }

    #[test]
    fn test_envelope_check_run_stability_mismatch() {
        let terminal_evidence_digest = [0x11; 32];
        let terminal_verifier_outputs_digest = [0x22; 32];
        let stability_digest = compute_stability_digest(
            1,
            &terminal_evidence_digest,
            &terminal_verifier_outputs_digest,
        );

        let envelope = DeterminismEnvelopeBuilder::new()
            .determinism_class(DeterminismClass::FullyDeterministic)
            .run_count(3)
            .run_receipt_hashes(vec![[0x42; 32], [0x42; 32], [0x99; 32]]) // Last differs
            .terminal_evidence_digest(terminal_evidence_digest)
            .terminal_verifier_outputs_digest(terminal_verifier_outputs_digest)
            .stability_digest(stability_digest)
            .build()
            .expect("valid envelope");

        assert_eq!(envelope.check_run_stability(), DeterminismStatus::Mismatch);
    }

    #[test]
    fn test_envelope_validate_stability_digest_success() {
        let envelope = create_test_envelope();
        assert!(envelope.validate_stability_digest(1).is_ok()); // verdict = 1 (PASS)
    }

    #[test]
    fn test_envelope_validate_stability_digest_wrong_verdict() {
        let envelope = create_test_envelope();
        // envelope was built with verdict = 1, so verdict = 2 should fail
        assert!(matches!(
            envelope.validate_stability_digest(2),
            Err(DeterminismError::StabilityDigestMismatch)
        ));
    }

    // =========================================================================
    // Serde Tests
    // =========================================================================

    #[test]
    fn test_serde_roundtrip() {
        let envelope = create_test_envelope();

        let json = serde_json::to_string(&envelope).unwrap();
        let deserialized: DeterminismEnvelope = serde_json::from_str(&json).unwrap();

        assert_eq!(envelope, deserialized);
    }

    #[test]
    fn test_serde_deny_unknown_fields() {
        let json = r#"{
            "determinism_class": 2,
            "run_count": 1,
            "run_receipt_hashes": [[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]],
            "terminal_evidence_digest": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "terminal_verifier_outputs_digest": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "stability_digest": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "unknown_field": "should_fail"
        }"#;

        let result: Result<DeterminismEnvelope, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    // =========================================================================
    // Error Display Tests
    // =========================================================================

    #[test]
    fn test_error_display() {
        let err = DeterminismError::MissingField("test_field");
        assert!(err.to_string().contains("missing required field"));

        let err = DeterminismError::RunCountMismatch {
            run_count: 5,
            hash_count: 3,
        };
        assert!(err.to_string().contains("run_count (5)"));
        assert!(err.to_string().contains("(3)"));

        let err = DeterminismError::ZeroRunCount;
        assert!(err.to_string().contains("must be at least 1"));
    }

    // =========================================================================
    // Constants Tests
    // =========================================================================

    #[test]
    fn test_risk_tier_constants() {
        assert_eq!(RISK_TIER_LOW, 0);
        assert_eq!(RISK_TIER_MED, 1);
        assert_eq!(RISK_TIER_HIGH, 2);
    }

    #[test]
    fn test_required_runs_constants() {
        assert_eq!(REQUIRED_RUNS_LOW, 1);
        assert_eq!(REQUIRED_RUNS_MED, 2);
        assert_eq!(REQUIRED_RUNS_HIGH, 3);
        assert_eq!(REQUIRED_RUNS_DEFAULT, 3);
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn test_max_constants() {
        assert_eq!(MAX_RUN_RECEIPT_HASHES, 256);
        assert_eq!(MAX_RUN_COUNT, 256);
        // Ensure MAX_RUN_COUNT >= MAX_RUN_RECEIPT_HASHES to prevent overflow
        // Note: MAX_RUN_RECEIPT_HASHES is 256 which fits in u32
        assert!(MAX_RUN_COUNT >= MAX_RUN_RECEIPT_HASHES as u32);
    }

    // =========================================================================
    // DeterminismClass Type Safety Tests
    // =========================================================================

    #[test]
    fn test_determinism_class_all_variants() {
        // Test all variants work correctly
        for class in [
            DeterminismClass::NonDeterministic,
            DeterminismClass::SoftDeterministic,
            DeterminismClass::FullyDeterministic,
        ] {
            let terminal_evidence_digest = [0x11; 32];
            let terminal_verifier_outputs_digest = [0x22; 32];
            let stability_digest = compute_stability_digest(
                1,
                &terminal_evidence_digest,
                &terminal_verifier_outputs_digest,
            );

            let envelope = DeterminismEnvelopeBuilder::new()
                .determinism_class(class)
                .run_count(1)
                .run_receipt_hashes(vec![[0x42; 32]])
                .terminal_evidence_digest(terminal_evidence_digest)
                .terminal_verifier_outputs_digest(terminal_verifier_outputs_digest)
                .stability_digest(stability_digest)
                .build()
                .expect("valid envelope");

            assert_eq!(envelope.determinism_class, class);
        }
    }
}
