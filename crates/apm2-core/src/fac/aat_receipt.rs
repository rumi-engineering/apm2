// AGENT-AUTHORED
//! AAT gate receipt types for the Forge Admission Cycle.
//!
//! This module defines [`AatGateReceipt`] which is the typed payload for AAT
//! gate results. The payload is stored in CAS and referenced by `payload_hash`
//! from the [`GateReceipt`](super::GateReceipt) envelope.
//!
//! # 22 Required Fields
//!
//! `AatGateReceipt` has 22 required fields grouped into categories:
//!
//! ## View Commitment Binding (1-4)
//! 1. `view_commitment_hash` - Hash binding to view commitment from FAC-00
//! 2. `rcp_manifest_hash` - Hash of the RCP manifest for this profile
//! 3. `rcp_profile_id` - RCP profile identifier
//! 4. `policy_hash` - Policy hash for anti-downgrade verification
//!
//! ## Determinism Tracking (5-13)
//! 5. `determinism_class` - Determinism class (0=non, 1=soft, 2=fully)
//! 6. `determinism_status` - Whether terminal evidence was stable across runs
//! 7. `flake_class` - Classification of flakiness when mismatch occurs
//! 8. `run_count` - Number of AAT runs executed
//! 9. `run_receipt_hashes` - Hashes of individual run receipts
//! 10. `terminal_evidence_digest` - Digest of machine-checkable terminal
//!     evidence
//! 11. `observational_evidence_digest` - Digest of observational evidence
//! 12. `terminal_verifier_outputs_digest` - Digest of terminal verifier outputs
//! 13. `stability_digest` - Hash of verdict + terminal evidence + verifier
//!     outputs
//!
//! ## Verdict (14)
//! 14. `verdict` - AAT outcome (`PASS`, `FAIL`, `NEEDS_INPUT`)
//!
//! ## Evidence Binding (15-19)
//! 15. `transcript_chain_root_hash` - Root hash of the transcript chain
//! 16. `transcript_bundle_hash` - Hash of the transcript bundle in CAS
//! 17. `artifact_manifest_hash` - Hash of the artifact manifest in CAS
//! 18. `terminal_verifier_outputs` - Terminal verifier outputs with predicates
//! 19. `verifier_policy_hash` - Hash of the verifier policy
//!
//! ## Risk Tier (20-21)
//! 20. `selection_policy_id` - Selection policy identifier
//! 21. `risk_tier` - Risk tier for AAT selection
//!
//! ## Attestation (22)
//! 22. `attestation` - Execution environment attestation
//!
//! # Critical Invariants
//!
//! - `run_receipt_hashes.len()` MUST equal `run_count`
//! - At least one `terminal_verifier_output` is required for PASS verdict
//! - All verifier outputs must have `predicate_satisfied == true` for PASS
//!   verdict
//!
//! # Security Model
//!
//! `AatGateReceipt` captures machine-checkable evidence from AAT execution:
//! - Terminal evidence (exit codes, test reports) provides ground truth
//! - Observational evidence (logs, traces) is excluded from determinism
//!   equality
//! - Attestation binds results to verified execution environment
//!
//! # Example
//!
//! ```rust
//! use apm2_core::fac::{
//!     AatAttestation, AatGateReceipt, AatGateReceiptBuilder, AatVerdict, DeterminismClass,
//!     DeterminismStatus, FlakeClass, RiskTier as AatRiskTier, TerminalVerifierOutput,
//! };
//!
//! // Components for stability_digest computation
//! let terminal_evidence_digest = [0x77; 32];
//! let terminal_verifier_outputs_digest = [0x99; 32];
//! let verdict = AatVerdict::Pass;
//! let stability_digest = AatGateReceipt::compute_stability_digest(
//!     verdict,
//!     &terminal_evidence_digest,
//!     &terminal_verifier_outputs_digest,
//! );
//!
//! let receipt = AatGateReceiptBuilder::new()
//!     .view_commitment_hash([0x11; 32])
//!     .rcp_manifest_hash([0x22; 32])
//!     .rcp_profile_id("profile-001")
//!     .policy_hash([0x33; 32])
//!     .determinism_class(DeterminismClass::FullyDeterministic)
//!     .determinism_status(DeterminismStatus::Stable)
//!     .flake_class(FlakeClass::DeterministicFail)
//!     .run_count(3)
//!     .run_receipt_hashes(vec![[0x44; 32], [0x55; 32], [0x66; 32]])
//!     .terminal_evidence_digest(terminal_evidence_digest)
//!     .observational_evidence_digest([0x88; 32])
//!     .terminal_verifier_outputs_digest(terminal_verifier_outputs_digest)
//!     .stability_digest(stability_digest)
//!     .verdict(verdict)
//!     .transcript_chain_root_hash([0xBB; 32])
//!     .transcript_bundle_hash([0xCC; 32])
//!     .artifact_manifest_hash([0xDD; 32])
//!     .terminal_verifier_outputs(vec![TerminalVerifierOutput {
//!         verifier_kind: "exit_code".to_string(),
//!         output_digest: [0xEE; 32],
//!         predicate_satisfied: true,
//!     }])
//!     .verifier_policy_hash([0xFF; 32])
//!     .selection_policy_id("policy-001")
//!     .risk_tier(AatRiskTier::Tier1)
//!     .attestation(AatAttestation {
//!         container_image_digest: [0x01; 32],
//!         toolchain_digests: vec![[0x02; 32]],
//!         runner_identity_key_id: "runner-001".to_string(),
//!         network_policy_profile_hash: [0x03; 32],
//!     })
//!     .build()
//!     .expect("valid receipt");
//!
//! // Validate required fields, stability_digest, and run count invariant
//! assert!(receipt.validate_required_fields().is_ok());
//! ```

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::policy_resolution::{DeterminismClass, RiskTier};
// Re-export proto types for wire format serialization.
pub use crate::events::{
    AatAttestation as AatAttestationProto, AatGateReceipt as AatGateReceiptProto,
    TerminalVerifierOutput as TerminalVerifierOutputProto,
};

// =============================================================================
// Resource Limits
// =============================================================================

/// Maximum number of run receipt hashes allowed in an AAT receipt.
/// This prevents denial-of-service attacks via oversized repeated fields.
pub const MAX_RUN_RECEIPT_HASHES: usize = 256;

/// Maximum number of terminal verifier outputs allowed.
pub const MAX_TERMINAL_VERIFIER_OUTPUTS: usize = 64;

/// Maximum number of toolchain digests in attestation.
pub const MAX_TOOLCHAIN_DIGESTS: usize = 64;

/// Maximum length of any string field.
pub const MAX_STRING_LENGTH: usize = 4096;

// =============================================================================
// Enums
// =============================================================================

/// Determinism status for AAT runs.
///
/// Indicates whether multiple runs produced consistent terminal evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[repr(u8)]
pub enum DeterminismStatus {
    /// All runs produced identical terminal evidence.
    Stable   = 1,
    /// Runs produced different terminal evidence.
    Mismatch = 2,
}

impl DeterminismStatus {
    /// Returns the numeric value of this status.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for DeterminismStatus {
    type Error = AatReceiptError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Stable),
            2 => Ok(Self::Mismatch),
            _ => Err(AatReceiptError::InvalidEnumValue {
                field: "determinism_status",
                value: i32::from(value),
            }),
        }
    }
}

impl TryFrom<i32> for DeterminismStatus {
    type Error = AatReceiptError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Stable),
            2 => Ok(Self::Mismatch),
            _ => Err(AatReceiptError::InvalidEnumValue {
                field: "determinism_status",
                value,
            }),
        }
    }
}

impl std::fmt::Display for DeterminismStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stable => write!(f, "STABLE"),
            Self::Mismatch => write!(f, "MISMATCH"),
        }
    }
}

/// Classification of flakiness when determinism mismatch occurs.
///
/// Used for routing to appropriate quarantine/remediation paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[repr(u8)]
pub enum FlakeClass {
    /// Deterministic failure - consistent FAIL across all runs.
    DeterministicFail = 1,
    /// Flakiness due to test harness issues (e.g., timing, resource
    /// contention).
    HarnessFlake      = 2,
    /// Flakiness due to environment drift (e.g., dependency version mismatch).
    EnvironmentDrift  = 3,
    /// Test-level non-semantic difference (e.g., output format changes).
    TestNonsemantic   = 4,
    /// Code-level non-semantic difference (e.g., timestamps, random IDs).
    CodeNonsemantic   = 5,
    /// Unknown flakiness cause requiring investigation.
    Unknown           = 6,
}

impl FlakeClass {
    /// Returns the numeric value of this class.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for FlakeClass {
    type Error = AatReceiptError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::DeterministicFail),
            2 => Ok(Self::HarnessFlake),
            3 => Ok(Self::EnvironmentDrift),
            4 => Ok(Self::TestNonsemantic),
            5 => Ok(Self::CodeNonsemantic),
            6 => Ok(Self::Unknown),
            _ => Err(AatReceiptError::InvalidEnumValue {
                field: "flake_class",
                value: i32::from(value),
            }),
        }
    }
}

impl TryFrom<i32> for FlakeClass {
    type Error = AatReceiptError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::DeterministicFail),
            2 => Ok(Self::HarnessFlake),
            3 => Ok(Self::EnvironmentDrift),
            4 => Ok(Self::TestNonsemantic),
            5 => Ok(Self::CodeNonsemantic),
            6 => Ok(Self::Unknown),
            _ => Err(AatReceiptError::InvalidEnumValue {
                field: "flake_class",
                value,
            }),
        }
    }
}

impl std::fmt::Display for FlakeClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DeterministicFail => write!(f, "DETERMINISTIC_FAIL"),
            Self::HarnessFlake => write!(f, "HARNESS_FLAKE"),
            Self::EnvironmentDrift => write!(f, "ENVIRONMENT_DRIFT"),
            Self::TestNonsemantic => write!(f, "TEST_NONSEMANTIC"),
            Self::CodeNonsemantic => write!(f, "CODE_NONSEMANTIC"),
            Self::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

/// AAT verdict outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[repr(u8)]
pub enum AatVerdict {
    /// All acceptance criteria passed.
    Pass       = 1,
    /// One or more acceptance criteria failed.
    Fail       = 2,
    /// Additional input required to determine outcome.
    NeedsInput = 3,
}

impl AatVerdict {
    /// Returns the numeric value of this verdict.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for AatVerdict {
    type Error = AatReceiptError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Pass),
            2 => Ok(Self::Fail),
            3 => Ok(Self::NeedsInput),
            _ => Err(AatReceiptError::InvalidEnumValue {
                field: "verdict",
                value: i32::from(value),
            }),
        }
    }
}

impl TryFrom<i32> for AatVerdict {
    type Error = AatReceiptError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Pass),
            2 => Ok(Self::Fail),
            3 => Ok(Self::NeedsInput),
            _ => Err(AatReceiptError::InvalidEnumValue {
                field: "verdict",
                value,
            }),
        }
    }
}

impl std::fmt::Display for AatVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pass => write!(f, "PASS"),
            Self::Fail => write!(f, "FAIL"),
            Self::NeedsInput => write!(f, "NEEDS_INPUT"),
        }
    }
}

// =============================================================================
// Supporting Types
// =============================================================================

/// Output from a terminal verifier.
///
/// Terminal verifiers provide ground truth (exit codes, snapshot diffs, etc.).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalVerifierOutput {
    /// Kind of verifier: `exit_code`, `snapshot_diff`,
    /// `structured_test_report`, `invariant_check`.
    pub verifier_kind: String,

    /// Digest of the verifier output content.
    #[serde(with = "serde_bytes")]
    pub output_digest: [u8; 32],

    /// Whether the machine predicate was satisfied.
    pub predicate_satisfied: bool,
}

/// Attestation metadata for AAT execution environment.
///
/// Provides evidence chain for runtime environment verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AatAttestation {
    /// Digest of the container image used.
    #[serde(with = "serde_bytes")]
    pub container_image_digest: [u8; 32],

    /// Digests of toolchain components.
    #[serde(with = "vec_hash_serde")]
    pub toolchain_digests: Vec<[u8; 32]>,

    /// Identity key ID of the runner.
    pub runner_identity_key_id: String,

    /// Hash of the network policy profile.
    #[serde(with = "serde_bytes")]
    pub network_policy_profile_hash: [u8; 32],
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

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during AAT receipt operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AatReceiptError {
    /// Missing required field.
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// Invalid data in receipt.
    #[error("invalid receipt data: {0}")]
    InvalidData(String),

    /// Invalid enum value.
    #[error("invalid enum value for {field}: {value}")]
    InvalidEnumValue {
        /// Name of the field with invalid value.
        field: &'static str,
        /// The invalid value.
        value: i32,
    },

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

    /// Run count does not match run receipt hashes length.
    #[error("run_count ({run_count}) does not match run_receipt_hashes.len() ({hash_count})")]
    RunCountMismatch {
        /// The declared run count.
        run_count: u32,
        /// The actual number of hashes.
        hash_count: usize,
    },

    /// PASS verdict without terminal verifier outputs.
    #[error("PASS verdict requires at least one terminal_verifier_output")]
    PassVerdictWithoutVerifiers,

    /// PASS verdict with unsatisfied predicate.
    #[error("PASS verdict requires all verifier predicates to be satisfied")]
    PassVerdictUnsatisfiedPredicate,

    /// `stability_digest` does not match computed value.
    #[error(
        "stability_digest mismatch: expected hash(verdict, terminal_evidence_digest, terminal_verifier_outputs_digest)"
    )]
    StabilityDigestMismatch,
}

// =============================================================================
// AatGateReceipt
// =============================================================================

/// Typed payload for AAT gate receipts with 22 required fields.
///
/// This payload is stored in CAS and referenced by `payload_hash` from the
/// [`GateReceipt`](super::GateReceipt) envelope.
///
/// # Invariants
///
/// - `run_receipt_hashes.len()` MUST equal `run_count`
/// - For PASS verdict: at least one `terminal_verifier_output` is required
/// - For PASS verdict: all `predicate_satisfied` must be `true`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AatGateReceipt {
    // ========== View commitment binding (fields 1-4) ==========
    /// Hash binding to view commitment from FAC-00.
    #[serde(with = "serde_bytes")]
    pub view_commitment_hash: [u8; 32],

    /// Hash of the RCP manifest for this profile.
    #[serde(with = "serde_bytes")]
    pub rcp_manifest_hash: [u8; 32],

    /// RCP profile identifier.
    pub rcp_profile_id: String,

    /// Policy hash for anti-downgrade verification.
    #[serde(with = "serde_bytes")]
    pub policy_hash: [u8; 32],

    // ========== Determinism tracking (fields 5-13) ==========
    /// Determinism class (0=non, 1=soft, 2=fully).
    pub determinism_class: DeterminismClass,

    /// Whether terminal evidence was stable across runs.
    pub determinism_status: DeterminismStatus,

    /// Classification of flakiness when mismatch occurs.
    pub flake_class: FlakeClass,

    /// Number of AAT runs executed.
    pub run_count: u32,

    /// Hashes of individual run receipts.
    #[serde(with = "vec_hash_serde")]
    pub run_receipt_hashes: Vec<[u8; 32]>,

    /// Digest of machine-checkable terminal evidence.
    #[serde(with = "serde_bytes")]
    pub terminal_evidence_digest: [u8; 32],

    /// Digest of observational evidence (logs, traces) - excluded from
    /// determinism.
    #[serde(with = "serde_bytes")]
    pub observational_evidence_digest: [u8; 32],

    /// Digest of terminal verifier outputs.
    #[serde(with = "serde_bytes")]
    pub terminal_verifier_outputs_digest: [u8; 32],

    /// Stability digest = hash(verdict, `terminal_evidence_digest`,
    /// `terminal_verifier_outputs_digest`).
    #[serde(with = "serde_bytes")]
    pub stability_digest: [u8; 32],

    // ========== Verdict (field 14) ==========
    /// AAT outcome verdict.
    pub verdict: AatVerdict,

    // ========== Evidence binding (fields 15-19) ==========
    /// Root hash of the transcript chain.
    #[serde(with = "serde_bytes")]
    pub transcript_chain_root_hash: [u8; 32],

    /// Hash of the transcript bundle in CAS.
    #[serde(with = "serde_bytes")]
    pub transcript_bundle_hash: [u8; 32],

    /// Hash of the artifact manifest in CAS.
    #[serde(with = "serde_bytes")]
    pub artifact_manifest_hash: [u8; 32],

    /// Terminal verifier outputs with predicate satisfaction.
    pub terminal_verifier_outputs: Vec<TerminalVerifierOutput>,

    /// Hash of the verifier policy.
    #[serde(with = "serde_bytes")]
    pub verifier_policy_hash: [u8; 32],

    // ========== Risk tier (fields 20-21) ==========
    /// Selection policy identifier.
    pub selection_policy_id: String,

    /// Risk tier for AAT selection.
    pub risk_tier: RiskTier,

    // ========== Attestation (field 22) ==========
    /// Execution environment attestation.
    pub attestation: AatAttestation,
}

impl AatGateReceipt {
    /// Computes the stability digest from its components.
    ///
    /// The stability digest is defined as:
    /// `hash(verdict || terminal_evidence_digest ||
    /// terminal_verifier_outputs_digest)`
    ///
    /// This provides a single hash that captures the "stable" aspects of the
    /// AAT result, allowing quick comparison across runs.
    #[must_use]
    pub fn compute_stability_digest(
        verdict: AatVerdict,
        terminal_evidence_digest: &[u8; 32],
        terminal_verifier_outputs_digest: &[u8; 32],
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&[verdict.as_u8()]);
        hasher.update(terminal_evidence_digest);
        hasher.update(terminal_verifier_outputs_digest);
        *hasher.finalize().as_bytes()
    }

    /// Validates all required fields are present and invariants are satisfied.
    ///
    /// # Invariants Checked
    ///
    /// - `run_receipt_hashes.len()` equals `run_count`
    /// - `stability_digest` matches computed value from components
    /// - For PASS verdict: at least one `terminal_verifier_output` is present
    /// - For PASS verdict: all `predicate_satisfied` are `true`
    /// - All string fields are within length limits
    /// - All collection fields are within size limits
    ///
    /// # Returns
    ///
    /// `Ok(())` if all validations pass, `Err(AatReceiptError)` otherwise.
    ///
    /// # Errors
    ///
    /// Returns various [`AatReceiptError`] variants for validation failures.
    pub fn validate_required_fields(&self) -> Result<(), AatReceiptError> {
        // Validate run_count matches run_receipt_hashes.len()
        if self.run_count as usize != self.run_receipt_hashes.len() {
            return Err(AatReceiptError::RunCountMismatch {
                run_count: self.run_count,
                hash_count: self.run_receipt_hashes.len(),
            });
        }

        // Validate stability_digest matches computed value
        let computed_stability = Self::compute_stability_digest(
            self.verdict,
            &self.terminal_evidence_digest,
            &self.terminal_verifier_outputs_digest,
        );
        if self.stability_digest != computed_stability {
            return Err(AatReceiptError::StabilityDigestMismatch);
        }

        // Validate string lengths
        if self.rcp_profile_id.len() > MAX_STRING_LENGTH {
            return Err(AatReceiptError::StringTooLong {
                field: "rcp_profile_id",
                actual: self.rcp_profile_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if self.selection_policy_id.len() > MAX_STRING_LENGTH {
            return Err(AatReceiptError::StringTooLong {
                field: "selection_policy_id",
                actual: self.selection_policy_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if self.attestation.runner_identity_key_id.len() > MAX_STRING_LENGTH {
            return Err(AatReceiptError::StringTooLong {
                field: "attestation.runner_identity_key_id",
                actual: self.attestation.runner_identity_key_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }

        // Validate collection sizes
        if self.run_receipt_hashes.len() > MAX_RUN_RECEIPT_HASHES {
            return Err(AatReceiptError::CollectionTooLarge {
                field: "run_receipt_hashes",
                actual: self.run_receipt_hashes.len(),
                max: MAX_RUN_RECEIPT_HASHES,
            });
        }
        if self.terminal_verifier_outputs.len() > MAX_TERMINAL_VERIFIER_OUTPUTS {
            return Err(AatReceiptError::CollectionTooLarge {
                field: "terminal_verifier_outputs",
                actual: self.terminal_verifier_outputs.len(),
                max: MAX_TERMINAL_VERIFIER_OUTPUTS,
            });
        }
        if self.attestation.toolchain_digests.len() > MAX_TOOLCHAIN_DIGESTS {
            return Err(AatReceiptError::CollectionTooLarge {
                field: "attestation.toolchain_digests",
                actual: self.attestation.toolchain_digests.len(),
                max: MAX_TOOLCHAIN_DIGESTS,
            });
        }

        // Validate verifier_kind strings
        for output in &self.terminal_verifier_outputs {
            if output.verifier_kind.len() > MAX_STRING_LENGTH {
                return Err(AatReceiptError::StringTooLong {
                    field: "terminal_verifier_outputs[].verifier_kind",
                    actual: output.verifier_kind.len(),
                    max: MAX_STRING_LENGTH,
                });
            }
        }

        // Validate PASS verdict requirements
        if self.verdict == AatVerdict::Pass {
            // Require at least one terminal verifier output for PASS
            if self.terminal_verifier_outputs.is_empty() {
                return Err(AatReceiptError::PassVerdictWithoutVerifiers);
            }
            // All predicates must be satisfied for PASS
            if !self
                .terminal_verifier_outputs
                .iter()
                .all(|o| o.predicate_satisfied)
            {
                return Err(AatReceiptError::PassVerdictUnsatisfiedPredicate);
            }
        }

        Ok(())
    }
}

// =============================================================================
// Builder
// =============================================================================

/// Builder for constructing [`AatGateReceipt`] instances with validation.
#[derive(Debug, Default)]
pub struct AatGateReceiptBuilder {
    view_commitment_hash: Option<[u8; 32]>,
    rcp_manifest_hash: Option<[u8; 32]>,
    rcp_profile_id: Option<String>,
    policy_hash: Option<[u8; 32]>,
    determinism_class: Option<DeterminismClass>,
    determinism_status: Option<DeterminismStatus>,
    flake_class: Option<FlakeClass>,
    run_count: Option<u32>,
    run_receipt_hashes: Option<Vec<[u8; 32]>>,
    terminal_evidence_digest: Option<[u8; 32]>,
    observational_evidence_digest: Option<[u8; 32]>,
    terminal_verifier_outputs_digest: Option<[u8; 32]>,
    stability_digest: Option<[u8; 32]>,
    verdict: Option<AatVerdict>,
    transcript_chain_root_hash: Option<[u8; 32]>,
    transcript_bundle_hash: Option<[u8; 32]>,
    artifact_manifest_hash: Option<[u8; 32]>,
    terminal_verifier_outputs: Option<Vec<TerminalVerifierOutput>>,
    verifier_policy_hash: Option<[u8; 32]>,
    selection_policy_id: Option<String>,
    risk_tier: Option<RiskTier>,
    attestation: Option<AatAttestation>,
}

impl AatGateReceiptBuilder {
    /// Creates a new empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the view commitment hash.
    #[must_use]
    pub const fn view_commitment_hash(mut self, hash: [u8; 32]) -> Self {
        self.view_commitment_hash = Some(hash);
        self
    }

    /// Sets the RCP manifest hash.
    #[must_use]
    pub const fn rcp_manifest_hash(mut self, hash: [u8; 32]) -> Self {
        self.rcp_manifest_hash = Some(hash);
        self
    }

    /// Sets the RCP profile ID.
    #[must_use]
    pub fn rcp_profile_id(mut self, id: impl Into<String>) -> Self {
        self.rcp_profile_id = Some(id.into());
        self
    }

    /// Sets the policy hash.
    #[must_use]
    pub const fn policy_hash(mut self, hash: [u8; 32]) -> Self {
        self.policy_hash = Some(hash);
        self
    }

    /// Sets the determinism class.
    #[must_use]
    pub fn determinism_class(mut self, class: impl Into<DeterminismClass>) -> Self {
        self.determinism_class = Some(class.into());
        self
    }

    /// Sets the determinism status.
    #[must_use]
    pub const fn determinism_status(mut self, status: DeterminismStatus) -> Self {
        self.determinism_status = Some(status);
        self
    }

    /// Sets the flake class.
    #[must_use]
    pub const fn flake_class(mut self, class: FlakeClass) -> Self {
        self.flake_class = Some(class);
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

    /// Sets the observational evidence digest.
    #[must_use]
    pub const fn observational_evidence_digest(mut self, digest: [u8; 32]) -> Self {
        self.observational_evidence_digest = Some(digest);
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

    /// Sets the verdict.
    #[must_use]
    pub const fn verdict(mut self, verdict: AatVerdict) -> Self {
        self.verdict = Some(verdict);
        self
    }

    /// Sets the transcript chain root hash.
    #[must_use]
    pub const fn transcript_chain_root_hash(mut self, hash: [u8; 32]) -> Self {
        self.transcript_chain_root_hash = Some(hash);
        self
    }

    /// Sets the transcript bundle hash.
    #[must_use]
    pub const fn transcript_bundle_hash(mut self, hash: [u8; 32]) -> Self {
        self.transcript_bundle_hash = Some(hash);
        self
    }

    /// Sets the artifact manifest hash.
    #[must_use]
    pub const fn artifact_manifest_hash(mut self, hash: [u8; 32]) -> Self {
        self.artifact_manifest_hash = Some(hash);
        self
    }

    /// Sets the terminal verifier outputs.
    #[must_use]
    pub fn terminal_verifier_outputs(mut self, outputs: Vec<TerminalVerifierOutput>) -> Self {
        self.terminal_verifier_outputs = Some(outputs);
        self
    }

    /// Sets the verifier policy hash.
    #[must_use]
    pub const fn verifier_policy_hash(mut self, hash: [u8; 32]) -> Self {
        self.verifier_policy_hash = Some(hash);
        self
    }

    /// Sets the selection policy ID.
    #[must_use]
    pub fn selection_policy_id(mut self, id: impl Into<String>) -> Self {
        self.selection_policy_id = Some(id.into());
        self
    }

    /// Sets the risk tier.
    #[must_use]
    pub const fn risk_tier(mut self, tier: RiskTier) -> Self {
        self.risk_tier = Some(tier);
        self
    }

    /// Sets the attestation.
    #[must_use]
    pub fn attestation(mut self, attestation: AatAttestation) -> Self {
        self.attestation = Some(attestation);
        self
    }

    /// Builds the receipt, validating all required fields.
    ///
    /// # Errors
    ///
    /// Returns [`AatReceiptError::MissingField`] if any required field is not
    /// set. Returns other [`AatReceiptError`] variants for validation
    /// failures.
    #[allow(clippy::too_many_lines)]
    pub fn build(self) -> Result<AatGateReceipt, AatReceiptError> {
        let receipt = AatGateReceipt {
            view_commitment_hash: self
                .view_commitment_hash
                .ok_or(AatReceiptError::MissingField("view_commitment_hash"))?,
            rcp_manifest_hash: self
                .rcp_manifest_hash
                .ok_or(AatReceiptError::MissingField("rcp_manifest_hash"))?,
            rcp_profile_id: self
                .rcp_profile_id
                .ok_or(AatReceiptError::MissingField("rcp_profile_id"))?,
            policy_hash: self
                .policy_hash
                .ok_or(AatReceiptError::MissingField("policy_hash"))?,
            determinism_class: self
                .determinism_class
                .ok_or(AatReceiptError::MissingField("determinism_class"))?,
            determinism_status: self
                .determinism_status
                .ok_or(AatReceiptError::MissingField("determinism_status"))?,
            flake_class: self
                .flake_class
                .ok_or(AatReceiptError::MissingField("flake_class"))?,
            run_count: self
                .run_count
                .ok_or(AatReceiptError::MissingField("run_count"))?,
            run_receipt_hashes: self
                .run_receipt_hashes
                .ok_or(AatReceiptError::MissingField("run_receipt_hashes"))?,
            terminal_evidence_digest: self
                .terminal_evidence_digest
                .ok_or(AatReceiptError::MissingField("terminal_evidence_digest"))?,
            observational_evidence_digest: self.observational_evidence_digest.ok_or(
                AatReceiptError::MissingField("observational_evidence_digest"),
            )?,
            terminal_verifier_outputs_digest: self.terminal_verifier_outputs_digest.ok_or(
                AatReceiptError::MissingField("terminal_verifier_outputs_digest"),
            )?,
            stability_digest: self
                .stability_digest
                .ok_or(AatReceiptError::MissingField("stability_digest"))?,
            verdict: self
                .verdict
                .ok_or(AatReceiptError::MissingField("verdict"))?,
            transcript_chain_root_hash: self
                .transcript_chain_root_hash
                .ok_or(AatReceiptError::MissingField("transcript_chain_root_hash"))?,
            transcript_bundle_hash: self
                .transcript_bundle_hash
                .ok_or(AatReceiptError::MissingField("transcript_bundle_hash"))?,
            artifact_manifest_hash: self
                .artifact_manifest_hash
                .ok_or(AatReceiptError::MissingField("artifact_manifest_hash"))?,
            terminal_verifier_outputs: self
                .terminal_verifier_outputs
                .ok_or(AatReceiptError::MissingField("terminal_verifier_outputs"))?,
            verifier_policy_hash: self
                .verifier_policy_hash
                .ok_or(AatReceiptError::MissingField("verifier_policy_hash"))?,
            selection_policy_id: self
                .selection_policy_id
                .ok_or(AatReceiptError::MissingField("selection_policy_id"))?,
            risk_tier: self
                .risk_tier
                .ok_or(AatReceiptError::MissingField("risk_tier"))?,
            attestation: self
                .attestation
                .ok_or(AatReceiptError::MissingField("attestation"))?,
        };

        // Validate all invariants
        receipt.validate_required_fields()?;

        Ok(receipt)
    }
}

// =============================================================================
// Proto Message Conversion
// =============================================================================

impl TryFrom<AatGateReceiptProto> for AatGateReceipt {
    type Error = AatReceiptError;

    #[allow(clippy::too_many_lines)]
    fn try_from(proto: AatGateReceiptProto) -> Result<Self, Self::Error> {
        // Validate collection sizes first to prevent DoS
        if proto.run_receipt_hashes.len() > MAX_RUN_RECEIPT_HASHES {
            return Err(AatReceiptError::CollectionTooLarge {
                field: "run_receipt_hashes",
                actual: proto.run_receipt_hashes.len(),
                max: MAX_RUN_RECEIPT_HASHES,
            });
        }
        if proto.terminal_verifier_outputs.len() > MAX_TERMINAL_VERIFIER_OUTPUTS {
            return Err(AatReceiptError::CollectionTooLarge {
                field: "terminal_verifier_outputs",
                actual: proto.terminal_verifier_outputs.len(),
                max: MAX_TERMINAL_VERIFIER_OUTPUTS,
            });
        }

        // Validate string lengths
        if proto.rcp_profile_id.len() > MAX_STRING_LENGTH {
            return Err(AatReceiptError::StringTooLong {
                field: "rcp_profile_id",
                actual: proto.rcp_profile_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if proto.selection_policy_id.len() > MAX_STRING_LENGTH {
            return Err(AatReceiptError::StringTooLong {
                field: "selection_policy_id",
                actual: proto.selection_policy_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }

        // Convert hash fields
        let view_commitment_hash: [u8; 32] =
            proto.view_commitment_hash.try_into().map_err(|_| {
                AatReceiptError::InvalidData("view_commitment_hash must be 32 bytes".into())
            })?;
        let rcp_manifest_hash: [u8; 32] = proto.rcp_manifest_hash.try_into().map_err(|_| {
            AatReceiptError::InvalidData("rcp_manifest_hash must be 32 bytes".into())
        })?;
        let policy_hash: [u8; 32] = proto
            .policy_hash
            .try_into()
            .map_err(|_| AatReceiptError::InvalidData("policy_hash must be 32 bytes".into()))?;
        let terminal_evidence_digest: [u8; 32] =
            proto.terminal_evidence_digest.try_into().map_err(|_| {
                AatReceiptError::InvalidData("terminal_evidence_digest must be 32 bytes".into())
            })?;
        let observational_evidence_digest: [u8; 32] = proto
            .observational_evidence_digest
            .try_into()
            .map_err(|_| {
                AatReceiptError::InvalidData(
                    "observational_evidence_digest must be 32 bytes".into(),
                )
            })?;
        let terminal_verifier_outputs_digest: [u8; 32] = proto
            .terminal_verifier_outputs_digest
            .try_into()
            .map_err(|_| {
                AatReceiptError::InvalidData(
                    "terminal_verifier_outputs_digest must be 32 bytes".into(),
                )
            })?;
        let stability_digest: [u8; 32] = proto.stability_digest.try_into().map_err(|_| {
            AatReceiptError::InvalidData("stability_digest must be 32 bytes".into())
        })?;
        let transcript_chain_root_hash: [u8; 32] =
            proto.transcript_chain_root_hash.try_into().map_err(|_| {
                AatReceiptError::InvalidData("transcript_chain_root_hash must be 32 bytes".into())
            })?;
        let transcript_bundle_hash: [u8; 32] =
            proto.transcript_bundle_hash.try_into().map_err(|_| {
                AatReceiptError::InvalidData("transcript_bundle_hash must be 32 bytes".into())
            })?;
        let artifact_manifest_hash: [u8; 32] =
            proto.artifact_manifest_hash.try_into().map_err(|_| {
                AatReceiptError::InvalidData("artifact_manifest_hash must be 32 bytes".into())
            })?;
        let verifier_policy_hash: [u8; 32] =
            proto.verifier_policy_hash.try_into().map_err(|_| {
                AatReceiptError::InvalidData("verifier_policy_hash must be 32 bytes".into())
            })?;

        // Convert run_receipt_hashes
        let run_receipt_hashes: Vec<[u8; 32]> = proto
            .run_receipt_hashes
            .into_iter()
            .map(|h| {
                h.try_into().map_err(|_| {
                    AatReceiptError::InvalidData("run_receipt_hash must be 32 bytes".into())
                })
            })
            .collect::<Result<_, _>>()?;

        // Convert terminal_verifier_outputs
        let terminal_verifier_outputs: Vec<TerminalVerifierOutput> = proto
            .terminal_verifier_outputs
            .into_iter()
            .map(|o| {
                let output_digest: [u8; 32] = o.output_digest.try_into().map_err(|_| {
                    AatReceiptError::InvalidData("output_digest must be 32 bytes".into())
                })?;
                Ok(TerminalVerifierOutput {
                    verifier_kind: o.verifier_kind,
                    output_digest,
                    predicate_satisfied: o.predicate_satisfied,
                })
            })
            .collect::<Result<_, AatReceiptError>>()?;

        // Convert enums
        let determinism_class_u8: u8 =
            proto
                .determinism_class
                .try_into()
                .map_err(|_| AatReceiptError::InvalidEnumValue {
                    field: "determinism_class",
                    value: i32::try_from(proto.determinism_class).unwrap_or(i32::MAX),
                })?;
        let determinism_class = DeterminismClass::try_from(determinism_class_u8).map_err(|_| {
            AatReceiptError::InvalidEnumValue {
                field: "determinism_class",
                value: i32::from(determinism_class_u8),
            }
        })?;
        let determinism_status = DeterminismStatus::try_from(proto.determinism_status)?;
        let flake_class = FlakeClass::try_from(proto.flake_class)?;
        let verdict = AatVerdict::try_from(proto.verdict)?;
        // risk_tier is stored as uint32 (0-4) for fidelity preservation
        let risk_tier_u8: u8 =
            proto
                .risk_tier
                .try_into()
                .map_err(|_| AatReceiptError::InvalidEnumValue {
                    field: "risk_tier",
                    value: i32::try_from(proto.risk_tier).unwrap_or(i32::MAX),
                })?;
        let risk_tier =
            RiskTier::try_from(risk_tier_u8).map_err(|_| AatReceiptError::InvalidEnumValue {
                field: "risk_tier",
                value: i32::from(risk_tier_u8),
            })?;

        // Convert attestation
        let attestation_proto = proto
            .attestation
            .ok_or(AatReceiptError::MissingField("attestation"))?;

        if attestation_proto.toolchain_digests.len() > MAX_TOOLCHAIN_DIGESTS {
            return Err(AatReceiptError::CollectionTooLarge {
                field: "attestation.toolchain_digests",
                actual: attestation_proto.toolchain_digests.len(),
                max: MAX_TOOLCHAIN_DIGESTS,
            });
        }
        if attestation_proto.runner_identity_key_id.len() > MAX_STRING_LENGTH {
            return Err(AatReceiptError::StringTooLong {
                field: "attestation.runner_identity_key_id",
                actual: attestation_proto.runner_identity_key_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }

        let container_image_digest: [u8; 32] = attestation_proto
            .container_image_digest
            .try_into()
            .map_err(|_| {
                AatReceiptError::InvalidData("container_image_digest must be 32 bytes".into())
            })?;
        let network_policy_profile_hash: [u8; 32] = attestation_proto
            .network_policy_profile_hash
            .try_into()
            .map_err(|_| {
                AatReceiptError::InvalidData("network_policy_profile_hash must be 32 bytes".into())
            })?;
        let toolchain_digests: Vec<[u8; 32]> = attestation_proto
            .toolchain_digests
            .into_iter()
            .map(|h| {
                h.try_into().map_err(|_| {
                    AatReceiptError::InvalidData("toolchain_digest must be 32 bytes".into())
                })
            })
            .collect::<Result<_, _>>()?;

        let attestation = AatAttestation {
            container_image_digest,
            toolchain_digests,
            runner_identity_key_id: attestation_proto.runner_identity_key_id,
            network_policy_profile_hash,
        };

        let receipt = Self {
            view_commitment_hash,
            rcp_manifest_hash,
            rcp_profile_id: proto.rcp_profile_id,
            policy_hash,
            determinism_class,
            determinism_status,
            flake_class,
            run_count: proto.run_count,
            run_receipt_hashes,
            terminal_evidence_digest,
            observational_evidence_digest,
            terminal_verifier_outputs_digest,
            stability_digest,
            verdict,
            transcript_chain_root_hash,
            transcript_bundle_hash,
            artifact_manifest_hash,
            terminal_verifier_outputs,
            verifier_policy_hash,
            selection_policy_id: proto.selection_policy_id,
            risk_tier,
            attestation,
        };

        // Validate all invariants
        receipt.validate_required_fields()?;

        Ok(receipt)
    }
}

impl From<AatGateReceipt> for AatGateReceiptProto {
    fn from(receipt: AatGateReceipt) -> Self {
        Self {
            view_commitment_hash: receipt.view_commitment_hash.to_vec(),
            rcp_manifest_hash: receipt.rcp_manifest_hash.to_vec(),
            rcp_profile_id: receipt.rcp_profile_id,
            policy_hash: receipt.policy_hash.to_vec(),
            determinism_class: u32::from(u8::from(receipt.determinism_class)),
            determinism_status: i32::from(receipt.determinism_status.as_u8()),
            flake_class: i32::from(receipt.flake_class.as_u8()),
            run_count: receipt.run_count,
            run_receipt_hashes: receipt
                .run_receipt_hashes
                .into_iter()
                .map(|h| h.to_vec())
                .collect(),
            terminal_evidence_digest: receipt.terminal_evidence_digest.to_vec(),
            observational_evidence_digest: receipt.observational_evidence_digest.to_vec(),
            terminal_verifier_outputs_digest: receipt.terminal_verifier_outputs_digest.to_vec(),
            stability_digest: receipt.stability_digest.to_vec(),
            verdict: i32::from(receipt.verdict.as_u8()),
            transcript_chain_root_hash: receipt.transcript_chain_root_hash.to_vec(),
            transcript_bundle_hash: receipt.transcript_bundle_hash.to_vec(),
            artifact_manifest_hash: receipt.artifact_manifest_hash.to_vec(),
            terminal_verifier_outputs: receipt
                .terminal_verifier_outputs
                .into_iter()
                .map(|o| TerminalVerifierOutputProto {
                    verifier_kind: o.verifier_kind,
                    output_digest: o.output_digest.to_vec(),
                    predicate_satisfied: o.predicate_satisfied,
                })
                .collect(),
            verifier_policy_hash: receipt.verifier_policy_hash.to_vec(),
            selection_policy_id: receipt.selection_policy_id,
            // risk_tier stored as uint32 (0-4) for fidelity preservation
            risk_tier: u32::from(u8::from(receipt.risk_tier)),
            attestation: Some(AatAttestationProto {
                container_image_digest: receipt.attestation.container_image_digest.to_vec(),
                toolchain_digests: receipt
                    .attestation
                    .toolchain_digests
                    .into_iter()
                    .map(|h| h.to_vec())
                    .collect(),
                runner_identity_key_id: receipt.attestation.runner_identity_key_id,
                network_policy_profile_hash: receipt
                    .attestation
                    .network_policy_profile_hash
                    .to_vec(),
            }),
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
pub mod tests {
    use super::*;

    /// Helper to compute `stability_digest` for test fixtures.
    fn test_stability_digest(
        verdict: AatVerdict,
        terminal_evidence_digest: &[u8; 32],
        terminal_verifier_outputs_digest: &[u8; 32],
    ) -> [u8; 32] {
        AatGateReceipt::compute_stability_digest(
            verdict,
            terminal_evidence_digest,
            terminal_verifier_outputs_digest,
        )
    }

    fn create_test_attestation() -> AatAttestation {
        AatAttestation {
            container_image_digest: [0x01; 32],
            toolchain_digests: vec![[0x02; 32]],
            runner_identity_key_id: "runner-001".to_string(),
            network_policy_profile_hash: [0x03; 32],
        }
    }

    fn create_test_verifier_output(satisfied: bool) -> TerminalVerifierOutput {
        TerminalVerifierOutput {
            verifier_kind: "exit_code".to_string(),
            output_digest: [0xEE; 32],
            predicate_satisfied: satisfied,
        }
    }

    fn create_valid_receipt() -> AatGateReceipt {
        // Compute the correct stability_digest for the test data
        let terminal_evidence_digest = [0x77; 32];
        let terminal_verifier_outputs_digest = [0x99; 32];
        let verdict = AatVerdict::Pass;
        let stability_digest = AatGateReceipt::compute_stability_digest(
            verdict,
            &terminal_evidence_digest,
            &terminal_verifier_outputs_digest,
        );

        AatGateReceiptBuilder::new()
            .view_commitment_hash([0x11; 32])
            .rcp_manifest_hash([0x22; 32])
            .rcp_profile_id("profile-001")
            .policy_hash([0x33; 32])
            .determinism_class(DeterminismClass::FullyDeterministic)
            .determinism_status(DeterminismStatus::Stable)
            .flake_class(FlakeClass::DeterministicFail)
            .run_count(3)
            .run_receipt_hashes(vec![[0x44; 32], [0x55; 32], [0x66; 32]])
            .terminal_evidence_digest(terminal_evidence_digest)
            .observational_evidence_digest([0x88; 32])
            .terminal_verifier_outputs_digest(terminal_verifier_outputs_digest)
            .stability_digest(stability_digest)
            .verdict(verdict)
            .transcript_chain_root_hash([0xBB; 32])
            .transcript_bundle_hash([0xCC; 32])
            .artifact_manifest_hash([0xDD; 32])
            .terminal_verifier_outputs(vec![create_test_verifier_output(true)])
            .verifier_policy_hash([0xFF; 32])
            .selection_policy_id("policy-001")
            .risk_tier(RiskTier::Tier1)
            .attestation(create_test_attestation())
            .build()
            .expect("valid receipt")
    }

    // =========================================================================
    // Builder Tests
    // =========================================================================

    #[test]
    fn test_builder_creates_valid_receipt() {
        let receipt = create_valid_receipt();
        assert_eq!(receipt.view_commitment_hash, [0x11; 32]);
        assert_eq!(receipt.rcp_profile_id, "profile-001");
        assert_eq!(receipt.run_count, 3);
        assert_eq!(receipt.run_receipt_hashes.len(), 3);
        assert_eq!(receipt.verdict, AatVerdict::Pass);
    }

    #[test]
    fn test_builder_missing_field() {
        let result = AatGateReceiptBuilder::new()
            .view_commitment_hash([0x11; 32])
            // Missing other fields
            .build();

        assert!(matches!(result, Err(AatReceiptError::MissingField(_))));
    }

    #[test]
    fn test_all_22_fields_present() {
        let receipt = create_valid_receipt();

        // Verify all 22 fields are present
        assert_ne!(receipt.view_commitment_hash, [0u8; 32]); // 1
        assert_ne!(receipt.rcp_manifest_hash, [0u8; 32]); // 2
        assert!(!receipt.rcp_profile_id.is_empty()); // 3
        assert_ne!(receipt.policy_hash, [0u8; 32]); // 4
        assert_eq!(
            receipt.determinism_class,
            DeterminismClass::FullyDeterministic
        ); // 5
        assert_eq!(receipt.determinism_status, DeterminismStatus::Stable); // 6
        assert_eq!(receipt.flake_class, FlakeClass::DeterministicFail); // 7
        assert_eq!(receipt.run_count, 3); // 8
        assert_eq!(receipt.run_receipt_hashes.len(), 3); // 9
        assert_ne!(receipt.terminal_evidence_digest, [0u8; 32]); // 10
        assert_ne!(receipt.observational_evidence_digest, [0u8; 32]); // 11
        assert_ne!(receipt.terminal_verifier_outputs_digest, [0u8; 32]); // 12
        assert_ne!(receipt.stability_digest, [0u8; 32]); // 13
        assert_eq!(receipt.verdict, AatVerdict::Pass); // 14
        assert_ne!(receipt.transcript_chain_root_hash, [0u8; 32]); // 15
        assert_ne!(receipt.transcript_bundle_hash, [0u8; 32]); // 16
        assert_ne!(receipt.artifact_manifest_hash, [0u8; 32]); // 17
        assert!(!receipt.terminal_verifier_outputs.is_empty()); // 18
        assert_ne!(receipt.verifier_policy_hash, [0u8; 32]); // 19
        assert!(!receipt.selection_policy_id.is_empty()); // 20
        assert_eq!(receipt.risk_tier, RiskTier::Tier1); // 21
        assert_ne!(receipt.attestation.container_image_digest, [0u8; 32]); // 22
    }

    // =========================================================================
    // Validation Tests
    // =========================================================================

    #[test]
    fn test_validate_required_fields_success() {
        let receipt = create_valid_receipt();
        assert!(receipt.validate_required_fields().is_ok());
    }

    #[test]
    fn test_run_count_mismatch_rejected() {
        let terminal_evidence_digest = [0x77; 32];
        let terminal_verifier_outputs_digest = [0x99; 32];
        let verdict = AatVerdict::Fail;
        let stability_digest = test_stability_digest(
            verdict,
            &terminal_evidence_digest,
            &terminal_verifier_outputs_digest,
        );

        let result = AatGateReceiptBuilder::new()
            .view_commitment_hash([0x11; 32])
            .rcp_manifest_hash([0x22; 32])
            .rcp_profile_id("profile-001")
            .policy_hash([0x33; 32])
            .determinism_class(DeterminismClass::FullyDeterministic)
            .determinism_status(DeterminismStatus::Stable)
            .flake_class(FlakeClass::DeterministicFail)
            .run_count(5) // Mismatch: says 5 runs
            .run_receipt_hashes(vec![[0x44; 32], [0x55; 32], [0x66; 32]]) // But only 3 hashes
            .terminal_evidence_digest(terminal_evidence_digest)
            .observational_evidence_digest([0x88; 32])
            .terminal_verifier_outputs_digest(terminal_verifier_outputs_digest)
            .stability_digest(stability_digest)
            .verdict(verdict) // FAIL doesn't require verifier outputs
            .transcript_chain_root_hash([0xBB; 32])
            .transcript_bundle_hash([0xCC; 32])
            .artifact_manifest_hash([0xDD; 32])
            .terminal_verifier_outputs(vec![])
            .verifier_policy_hash([0xFF; 32])
            .selection_policy_id("policy-001")
            .risk_tier(RiskTier::Tier1)
            .attestation(create_test_attestation())
            .build();

        assert!(matches!(
            result,
            Err(AatReceiptError::RunCountMismatch {
                run_count: 5,
                hash_count: 3
            })
        ));
    }

    #[test]
    fn test_pass_verdict_requires_verifier_outputs() {
        let terminal_evidence_digest = [0x77; 32];
        let terminal_verifier_outputs_digest = [0x99; 32];
        let verdict = AatVerdict::Pass;
        let stability_digest = test_stability_digest(
            verdict,
            &terminal_evidence_digest,
            &terminal_verifier_outputs_digest,
        );

        let result = AatGateReceiptBuilder::new()
            .view_commitment_hash([0x11; 32])
            .rcp_manifest_hash([0x22; 32])
            .rcp_profile_id("profile-001")
            .policy_hash([0x33; 32])
            .determinism_class(DeterminismClass::FullyDeterministic)
            .determinism_status(DeterminismStatus::Stable)
            .flake_class(FlakeClass::DeterministicFail)
            .run_count(1)
            .run_receipt_hashes(vec![[0x44; 32]])
            .terminal_evidence_digest(terminal_evidence_digest)
            .observational_evidence_digest([0x88; 32])
            .terminal_verifier_outputs_digest(terminal_verifier_outputs_digest)
            .stability_digest(stability_digest)
            .verdict(verdict) // PASS requires verifiers
            .transcript_chain_root_hash([0xBB; 32])
            .transcript_bundle_hash([0xCC; 32])
            .artifact_manifest_hash([0xDD; 32])
            .terminal_verifier_outputs(vec![]) // Empty!
            .verifier_policy_hash([0xFF; 32])
            .selection_policy_id("policy-001")
            .risk_tier(RiskTier::Tier1)
            .attestation(create_test_attestation())
            .build();

        assert!(matches!(
            result,
            Err(AatReceiptError::PassVerdictWithoutVerifiers)
        ));
    }

    #[test]
    fn test_pass_verdict_requires_satisfied_predicates() {
        let terminal_evidence_digest = [0x77; 32];
        let terminal_verifier_outputs_digest = [0x99; 32];
        let verdict = AatVerdict::Pass;
        let stability_digest = test_stability_digest(
            verdict,
            &terminal_evidence_digest,
            &terminal_verifier_outputs_digest,
        );

        let result = AatGateReceiptBuilder::new()
            .view_commitment_hash([0x11; 32])
            .rcp_manifest_hash([0x22; 32])
            .rcp_profile_id("profile-001")
            .policy_hash([0x33; 32])
            .determinism_class(DeterminismClass::FullyDeterministic)
            .determinism_status(DeterminismStatus::Stable)
            .flake_class(FlakeClass::DeterministicFail)
            .run_count(1)
            .run_receipt_hashes(vec![[0x44; 32]])
            .terminal_evidence_digest(terminal_evidence_digest)
            .observational_evidence_digest([0x88; 32])
            .terminal_verifier_outputs_digest(terminal_verifier_outputs_digest)
            .stability_digest(stability_digest)
            .verdict(verdict)
            .transcript_chain_root_hash([0xBB; 32])
            .transcript_bundle_hash([0xCC; 32])
            .artifact_manifest_hash([0xDD; 32])
            .terminal_verifier_outputs(vec![create_test_verifier_output(false)]) // Not satisfied!
            .verifier_policy_hash([0xFF; 32])
            .selection_policy_id("policy-001")
            .risk_tier(RiskTier::Tier1)
            .attestation(create_test_attestation())
            .build();

        assert!(matches!(
            result,
            Err(AatReceiptError::PassVerdictUnsatisfiedPredicate)
        ));
    }

    #[test]
    fn test_fail_verdict_without_verifiers_ok() {
        let terminal_evidence_digest = [0x77; 32];
        let terminal_verifier_outputs_digest = [0x99; 32];
        let verdict = AatVerdict::Fail;
        let stability_digest = test_stability_digest(
            verdict,
            &terminal_evidence_digest,
            &terminal_verifier_outputs_digest,
        );

        let result = AatGateReceiptBuilder::new()
            .view_commitment_hash([0x11; 32])
            .rcp_manifest_hash([0x22; 32])
            .rcp_profile_id("profile-001")
            .policy_hash([0x33; 32])
            .determinism_class(DeterminismClass::FullyDeterministic)
            .determinism_status(DeterminismStatus::Stable)
            .flake_class(FlakeClass::DeterministicFail)
            .run_count(1)
            .run_receipt_hashes(vec![[0x44; 32]])
            .terminal_evidence_digest(terminal_evidence_digest)
            .observational_evidence_digest([0x88; 32])
            .terminal_verifier_outputs_digest(terminal_verifier_outputs_digest)
            .stability_digest(stability_digest)
            .verdict(AatVerdict::Fail) // FAIL doesn't require verifiers
            .transcript_chain_root_hash([0xBB; 32])
            .transcript_bundle_hash([0xCC; 32])
            .artifact_manifest_hash([0xDD; 32])
            .terminal_verifier_outputs(vec![])
            .verifier_policy_hash([0xFF; 32])
            .selection_policy_id("policy-001")
            .risk_tier(RiskTier::Tier1)
            .attestation(create_test_attestation())
            .build();

        assert!(result.is_ok());
    }

    #[test]
    fn test_string_too_long_rejected() {
        let long_string = "x".repeat(MAX_STRING_LENGTH + 1);
        let terminal_evidence_digest = [0x77; 32];
        let terminal_verifier_outputs_digest = [0x99; 32];
        let verdict = AatVerdict::Fail;
        let stability_digest = test_stability_digest(
            verdict,
            &terminal_evidence_digest,
            &terminal_verifier_outputs_digest,
        );

        let result = AatGateReceiptBuilder::new()
            .view_commitment_hash([0x11; 32])
            .rcp_manifest_hash([0x22; 32])
            .rcp_profile_id(long_string) // Too long
            .policy_hash([0x33; 32])
            .determinism_class(DeterminismClass::FullyDeterministic)
            .determinism_status(DeterminismStatus::Stable)
            .flake_class(FlakeClass::DeterministicFail)
            .run_count(1)
            .run_receipt_hashes(vec![[0x44; 32]])
            .terminal_evidence_digest(terminal_evidence_digest)
            .observational_evidence_digest([0x88; 32])
            .terminal_verifier_outputs_digest(terminal_verifier_outputs_digest)
            .stability_digest(stability_digest)
            .verdict(verdict)
            .transcript_chain_root_hash([0xBB; 32])
            .transcript_bundle_hash([0xCC; 32])
            .artifact_manifest_hash([0xDD; 32])
            .terminal_verifier_outputs(vec![])
            .verifier_policy_hash([0xFF; 32])
            .selection_policy_id("policy-001")
            .risk_tier(RiskTier::Tier1)
            .attestation(create_test_attestation())
            .build();

        assert!(matches!(
            result,
            Err(AatReceiptError::StringTooLong {
                field: "rcp_profile_id",
                ..
            })
        ));
    }

    #[test]
    fn test_collection_too_large_rejected() {
        let too_many_hashes: Vec<[u8; 32]> =
            (0..=MAX_RUN_RECEIPT_HASHES).map(|_| [0x44; 32]).collect();
        let terminal_evidence_digest = [0x77; 32];
        let terminal_verifier_outputs_digest = [0x99; 32];
        let verdict = AatVerdict::Fail;
        let stability_digest = test_stability_digest(
            verdict,
            &terminal_evidence_digest,
            &terminal_verifier_outputs_digest,
        );

        let result = AatGateReceiptBuilder::new()
            .view_commitment_hash([0x11; 32])
            .rcp_manifest_hash([0x22; 32])
            .rcp_profile_id("profile-001")
            .policy_hash([0x33; 32])
            .determinism_class(DeterminismClass::FullyDeterministic)
            .determinism_status(DeterminismStatus::Stable)
            .flake_class(FlakeClass::DeterministicFail)
            .run_count(u32::try_from(MAX_RUN_RECEIPT_HASHES + 1).unwrap())
            .run_receipt_hashes(too_many_hashes)
            .terminal_evidence_digest(terminal_evidence_digest)
            .observational_evidence_digest([0x88; 32])
            .terminal_verifier_outputs_digest(terminal_verifier_outputs_digest)
            .stability_digest(stability_digest)
            .verdict(verdict)
            .transcript_chain_root_hash([0xBB; 32])
            .transcript_bundle_hash([0xCC; 32])
            .artifact_manifest_hash([0xDD; 32])
            .terminal_verifier_outputs(vec![])
            .verifier_policy_hash([0xFF; 32])
            .selection_policy_id("policy-001")
            .risk_tier(RiskTier::Tier1)
            .attestation(create_test_attestation())
            .build();

        assert!(matches!(
            result,
            Err(AatReceiptError::CollectionTooLarge {
                field: "run_receipt_hashes",
                ..
            })
        ));
    }

    // =========================================================================
    // Enum Tests
    // =========================================================================

    #[test]
    fn test_determinism_status_try_from() {
        assert_eq!(
            DeterminismStatus::try_from(1u8).unwrap(),
            DeterminismStatus::Stable
        );
        assert_eq!(
            DeterminismStatus::try_from(2u8).unwrap(),
            DeterminismStatus::Mismatch
        );
        assert!(DeterminismStatus::try_from(0u8).is_err());
        assert!(DeterminismStatus::try_from(3u8).is_err());
    }

    #[test]
    fn test_flake_class_try_from() {
        assert_eq!(
            FlakeClass::try_from(1u8).unwrap(),
            FlakeClass::DeterministicFail
        );
        assert_eq!(FlakeClass::try_from(2u8).unwrap(), FlakeClass::HarnessFlake);
        assert_eq!(
            FlakeClass::try_from(3u8).unwrap(),
            FlakeClass::EnvironmentDrift
        );
        assert_eq!(
            FlakeClass::try_from(4u8).unwrap(),
            FlakeClass::TestNonsemantic
        );
        assert_eq!(
            FlakeClass::try_from(5u8).unwrap(),
            FlakeClass::CodeNonsemantic
        );
        assert_eq!(FlakeClass::try_from(6u8).unwrap(), FlakeClass::Unknown);
        assert!(FlakeClass::try_from(0u8).is_err());
        assert!(FlakeClass::try_from(7u8).is_err());
    }

    #[test]
    fn test_aat_verdict_try_from() {
        assert_eq!(AatVerdict::try_from(1u8).unwrap(), AatVerdict::Pass);
        assert_eq!(AatVerdict::try_from(2u8).unwrap(), AatVerdict::Fail);
        assert_eq!(AatVerdict::try_from(3u8).unwrap(), AatVerdict::NeedsInput);
        assert!(AatVerdict::try_from(0u8).is_err());
        assert!(AatVerdict::try_from(4u8).is_err());
    }

    #[test]
    fn test_enum_display() {
        assert_eq!(DeterminismStatus::Stable.to_string(), "STABLE");
        assert_eq!(DeterminismStatus::Mismatch.to_string(), "MISMATCH");
        assert_eq!(
            FlakeClass::DeterministicFail.to_string(),
            "DETERMINISTIC_FAIL"
        );
        assert_eq!(FlakeClass::HarnessFlake.to_string(), "HARNESS_FLAKE");
        assert_eq!(AatVerdict::Pass.to_string(), "PASS");
        assert_eq!(AatVerdict::Fail.to_string(), "FAIL");
        assert_eq!(AatVerdict::NeedsInput.to_string(), "NEEDS_INPUT");
    }

    // =========================================================================
    // Serde Tests
    // =========================================================================

    #[test]
    fn test_serde_roundtrip() {
        let receipt = create_valid_receipt();

        let json = serde_json::to_string(&receipt).unwrap();
        let deserialized: AatGateReceipt = serde_json::from_str(&json).unwrap();

        assert_eq!(receipt, deserialized);
    }

    #[test]
    fn test_serde_deny_unknown_fields() {
        let json = r#"{
            "view_commitment_hash": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "unknown_field": "should_fail"
        }"#;

        let result: Result<AatGateReceipt, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    // =========================================================================
    // Proto Conversion Tests
    // =========================================================================

    #[test]
    fn test_proto_roundtrip() {
        let original = create_valid_receipt();

        // Convert to proto
        let proto: AatGateReceiptProto = original.clone().into();

        // Convert back to domain type
        let recovered = AatGateReceipt::try_from(proto).unwrap();

        // Key fields should match
        assert_eq!(
            original.view_commitment_hash,
            recovered.view_commitment_hash
        );
        assert_eq!(original.rcp_manifest_hash, recovered.rcp_manifest_hash);
        assert_eq!(original.rcp_profile_id, recovered.rcp_profile_id);
        assert_eq!(original.policy_hash, recovered.policy_hash);
        assert_eq!(original.run_count, recovered.run_count);
        assert_eq!(original.run_receipt_hashes, recovered.run_receipt_hashes);
        assert_eq!(original.verdict, recovered.verdict);
        assert_eq!(original.selection_policy_id, recovered.selection_policy_id);
    }

    #[test]
    fn test_proto_missing_attestation_rejected() {
        let proto = AatGateReceiptProto {
            view_commitment_hash: vec![0u8; 32],
            rcp_manifest_hash: vec![0u8; 32],
            rcp_profile_id: "profile".to_string(),
            policy_hash: vec![0u8; 32],
            determinism_class: 2,
            determinism_status: 1,
            flake_class: 1,
            run_count: 1,
            run_receipt_hashes: vec![vec![0u8; 32]],
            terminal_evidence_digest: vec![0u8; 32],
            observational_evidence_digest: vec![0u8; 32],
            terminal_verifier_outputs_digest: vec![0u8; 32],
            stability_digest: vec![0u8; 32],
            verdict: 2, // FAIL
            transcript_chain_root_hash: vec![0u8; 32],
            transcript_bundle_hash: vec![0u8; 32],
            artifact_manifest_hash: vec![0u8; 32],
            terminal_verifier_outputs: vec![],
            verifier_policy_hash: vec![0u8; 32],
            selection_policy_id: "policy".to_string(),
            risk_tier: 3,
            attestation: None, // Missing!
        };

        let result = AatGateReceipt::try_from(proto);
        assert!(matches!(
            result,
            Err(AatReceiptError::MissingField("attestation"))
        ));
    }

    #[test]
    fn test_proto_invalid_hash_length_rejected() {
        let proto = AatGateReceiptProto {
            view_commitment_hash: vec![0u8; 16], // Wrong length!
            rcp_manifest_hash: vec![0u8; 32],
            rcp_profile_id: "profile".to_string(),
            policy_hash: vec![0u8; 32],
            determinism_class: 2,
            determinism_status: 1,
            flake_class: 1,
            run_count: 1,
            run_receipt_hashes: vec![vec![0u8; 32]],
            terminal_evidence_digest: vec![0u8; 32],
            observational_evidence_digest: vec![0u8; 32],
            terminal_verifier_outputs_digest: vec![0u8; 32],
            stability_digest: vec![0u8; 32],
            verdict: 2,
            transcript_chain_root_hash: vec![0u8; 32],
            transcript_bundle_hash: vec![0u8; 32],
            artifact_manifest_hash: vec![0u8; 32],
            terminal_verifier_outputs: vec![],
            verifier_policy_hash: vec![0u8; 32],
            selection_policy_id: "policy".to_string(),
            risk_tier: 3,
            attestation: Some(AatAttestationProto {
                container_image_digest: vec![0u8; 32],
                toolchain_digests: vec![],
                runner_identity_key_id: "runner".to_string(),
                network_policy_profile_hash: vec![0u8; 32],
            }),
        };

        let result = AatGateReceipt::try_from(proto);
        assert!(matches!(result, Err(AatReceiptError::InvalidData(_))));
    }

    // =========================================================================
    // Edge Cases
    // =========================================================================

    #[test]
    fn test_zero_run_count() {
        let terminal_evidence_digest = [0x77; 32];
        let terminal_verifier_outputs_digest = [0x99; 32];
        let verdict = AatVerdict::Fail;
        let stability_digest = test_stability_digest(
            verdict,
            &terminal_evidence_digest,
            &terminal_verifier_outputs_digest,
        );

        let result = AatGateReceiptBuilder::new()
            .view_commitment_hash([0x11; 32])
            .rcp_manifest_hash([0x22; 32])
            .rcp_profile_id("profile-001")
            .policy_hash([0x33; 32])
            .determinism_class(DeterminismClass::FullyDeterministic)
            .determinism_status(DeterminismStatus::Stable)
            .flake_class(FlakeClass::DeterministicFail)
            .run_count(0) // Zero runs
            .run_receipt_hashes(vec![]) // Empty
            .terminal_evidence_digest(terminal_evidence_digest)
            .observational_evidence_digest([0x88; 32])
            .terminal_verifier_outputs_digest(terminal_verifier_outputs_digest)
            .stability_digest(stability_digest)
            .verdict(verdict)
            .transcript_chain_root_hash([0xBB; 32])
            .transcript_bundle_hash([0xCC; 32])
            .artifact_manifest_hash([0xDD; 32])
            .terminal_verifier_outputs(vec![])
            .verifier_policy_hash([0xFF; 32])
            .selection_policy_id("policy-001")
            .risk_tier(RiskTier::Tier1)
            .attestation(create_test_attestation())
            .build();

        // Zero runs with empty hashes is valid (matches)
        assert!(result.is_ok());
    }

    #[test]
    fn test_needs_input_verdict() {
        let terminal_evidence_digest = [0x77; 32];
        let terminal_verifier_outputs_digest = [0x99; 32];
        let verdict = AatVerdict::NeedsInput;
        let stability_digest = test_stability_digest(
            verdict,
            &terminal_evidence_digest,
            &terminal_verifier_outputs_digest,
        );

        let result = AatGateReceiptBuilder::new()
            .view_commitment_hash([0x11; 32])
            .rcp_manifest_hash([0x22; 32])
            .rcp_profile_id("profile-001")
            .policy_hash([0x33; 32])
            .determinism_class(DeterminismClass::FullyDeterministic)
            .determinism_status(DeterminismStatus::Stable)
            .flake_class(FlakeClass::Unknown)
            .run_count(1)
            .run_receipt_hashes(vec![[0x44; 32]])
            .terminal_evidence_digest(terminal_evidence_digest)
            .observational_evidence_digest([0x88; 32])
            .terminal_verifier_outputs_digest(terminal_verifier_outputs_digest)
            .stability_digest(stability_digest)
            .verdict(verdict) // NEEDS_INPUT doesn't require verifiers
            .transcript_chain_root_hash([0xBB; 32])
            .transcript_bundle_hash([0xCC; 32])
            .artifact_manifest_hash([0xDD; 32])
            .terminal_verifier_outputs(vec![])
            .verifier_policy_hash([0xFF; 32])
            .selection_policy_id("policy-001")
            .risk_tier(RiskTier::Tier1)
            .attestation(create_test_attestation())
            .build();

        assert!(result.is_ok());
    }

    // =========================================================================
    // Stability Digest Tests
    // =========================================================================

    #[test]
    fn test_stability_digest_validation() {
        // Test that a receipt with incorrect stability_digest is rejected
        let terminal_evidence_digest = [0x77; 32];
        let terminal_verifier_outputs_digest = [0x99; 32];
        let verdict = AatVerdict::Fail;
        // Use wrong stability_digest
        let wrong_stability_digest = [0xAA; 32];

        let result = AatGateReceiptBuilder::new()
            .view_commitment_hash([0x11; 32])
            .rcp_manifest_hash([0x22; 32])
            .rcp_profile_id("profile-001")
            .policy_hash([0x33; 32])
            .determinism_class(DeterminismClass::FullyDeterministic)
            .determinism_status(DeterminismStatus::Stable)
            .flake_class(FlakeClass::DeterministicFail)
            .run_count(1)
            .run_receipt_hashes(vec![[0x44; 32]])
            .terminal_evidence_digest(terminal_evidence_digest)
            .observational_evidence_digest([0x88; 32])
            .terminal_verifier_outputs_digest(terminal_verifier_outputs_digest)
            .stability_digest(wrong_stability_digest)
            .verdict(verdict)
            .transcript_chain_root_hash([0xBB; 32])
            .transcript_bundle_hash([0xCC; 32])
            .artifact_manifest_hash([0xDD; 32])
            .terminal_verifier_outputs(vec![])
            .verifier_policy_hash([0xFF; 32])
            .selection_policy_id("policy-001")
            .risk_tier(RiskTier::Tier1)
            .attestation(create_test_attestation())
            .build();

        assert!(matches!(
            result,
            Err(AatReceiptError::StabilityDigestMismatch)
        ));
    }

    #[test]
    fn test_stability_digest_computation() {
        // Test that compute_stability_digest produces deterministic results
        let terminal_evidence_digest = [0x77; 32];
        let terminal_verifier_outputs_digest = [0x99; 32];

        let digest1 = AatGateReceipt::compute_stability_digest(
            AatVerdict::Pass,
            &terminal_evidence_digest,
            &terminal_verifier_outputs_digest,
        );
        let digest2 = AatGateReceipt::compute_stability_digest(
            AatVerdict::Pass,
            &terminal_evidence_digest,
            &terminal_verifier_outputs_digest,
        );
        assert_eq!(digest1, digest2);

        // Different verdict should produce different digest
        let digest3 = AatGateReceipt::compute_stability_digest(
            AatVerdict::Fail,
            &terminal_evidence_digest,
            &terminal_verifier_outputs_digest,
        );
        assert_ne!(digest1, digest3);
    }

    // =========================================================================
    // RiskTier Fidelity Tests
    // =========================================================================

    #[test]
    fn test_risk_tier_proto_roundtrip_preserves_all_tiers() {
        // Test that all 5 RiskTier values survive proto roundtrip
        for tier in [
            RiskTier::Tier0,
            RiskTier::Tier1,
            RiskTier::Tier2,
            RiskTier::Tier3,
            RiskTier::Tier4,
        ] {
            let terminal_evidence_digest = [0x77; 32];
            let terminal_verifier_outputs_digest = [0x99; 32];
            let verdict = AatVerdict::Fail;
            let stability_digest = test_stability_digest(
                verdict,
                &terminal_evidence_digest,
                &terminal_verifier_outputs_digest,
            );

            let receipt = AatGateReceiptBuilder::new()
                .view_commitment_hash([0x11; 32])
                .rcp_manifest_hash([0x22; 32])
                .rcp_profile_id("profile-001")
                .policy_hash([0x33; 32])
                .determinism_class(DeterminismClass::FullyDeterministic)
                .determinism_status(DeterminismStatus::Stable)
                .flake_class(FlakeClass::DeterministicFail)
                .run_count(1)
                .run_receipt_hashes(vec![[0x44; 32]])
                .terminal_evidence_digest(terminal_evidence_digest)
                .observational_evidence_digest([0x88; 32])
                .terminal_verifier_outputs_digest(terminal_verifier_outputs_digest)
                .stability_digest(stability_digest)
                .verdict(verdict)
                .transcript_chain_root_hash([0xBB; 32])
                .transcript_bundle_hash([0xCC; 32])
                .artifact_manifest_hash([0xDD; 32])
                .terminal_verifier_outputs(vec![])
                .verifier_policy_hash([0xFF; 32])
                .selection_policy_id("policy-001")
                .risk_tier(tier)
                .attestation(create_test_attestation())
                .build()
                .expect("valid receipt");

            // Convert to proto and back
            let proto: AatGateReceiptProto = receipt.into();
            let recovered = AatGateReceipt::try_from(proto).expect("valid proto");

            // Verify the tier is preserved exactly
            assert_eq!(
                recovered.risk_tier, tier,
                "RiskTier {tier:?} not preserved through proto roundtrip"
            );
        }
    }
}
