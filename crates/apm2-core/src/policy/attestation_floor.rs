// AGENT-AUTHORED
//! Attestation floor tightening by risk tier (TCK-00379).
//!
//! This module enforces RFC-0020 Section 6.5 attestation tightening:
//!
//! - **Tier0-Tier1**: `Soft` attestation allowed.
//! - **Tier2**: `Soft` attestation required; `Strong` recommended for external
//!   integration.
//! - **Tier3+**: `Strong` attestation required; Tier4 may additionally require
//!   human/operator co-sign.
//!
//! Cross-cell imported facts that fail the attestation floor are quarantined
//! rather than silently accepted. All floor evaluations produce auditable
//! [`FloorEvaluation`] records.
//!
//! # Security Model
//!
//! - **Fail-closed**: Missing or unrecognized attestation levels are treated as
//!   `None`, which fails any floor requirement above `None`.
//! - **Monotonic tightening**: The delegation meet operator takes the *maximum*
//!   (strictest) floor from parent and child, preventing attestation
//!   laundering.
//! - **Receipt-visible**: Every floor evaluation emits a [`FloorEvaluation`]
//!   record, whether it passes or fails.
//! - **Strict deserialization**: All boundary structs use
//!   `#[serde(deny_unknown_fields)]` to reject non-canonical payloads.
//! - **Fail-closed identifiers**: Oversized actor/cell IDs are rejected (not
//!   truncated) in authoritative evaluation records to prevent audit-trail
//!   collision.
//!
//! # Runtime Integration
//!
//! The [`AttestationFloorGuard`] is the single admission gate for floor
//! checks. It is designed to be composed with the
//! [`TaintEnforcementGuard`](super::taint::TaintEnforcementGuard) in the
//! daemon's tool broker admission path:
//!
//! 1. The broker calls `TaintEnforcementGuard::admit()` for dual-lattice
//!    taint/classification checks.
//! 2. The broker calls `AttestationFloorGuard::admit_tier()` for attestation
//!    floor checks.
//! 3. Both checks must pass for the request to proceed (fail-closed).
//!
//! For cross-cell imports, the import admission path calls
//! `AttestationFloorGuard::admit_cross_cell_import()` and quarantines facts
//! that fail the floor.
//!
//! # Contract References
//!
//! - `REQ-0033`: Attestation floor tightening by risk tier
//! - `EVID-0033`: Attestation floor enforcement evidence
//! - `EVID-0308`: Declassification receipt security and correctness evidence

use serde::{Deserialize, Serialize};
use thiserror::Error;

// =============================================================================
// Constants
// =============================================================================

/// Maximum length of an actor ID string in attestation metadata.
const MAX_ACTOR_ID_LEN: usize = 256;

/// Maximum length of an environment fingerprint string.
const MAX_ENV_FINGERPRINT_LEN: usize = 512;

/// Maximum length of a policy root key ID string.
const MAX_POLICY_ROOT_KEY_ID_LEN: usize = 256;

/// Maximum length of a quarantine reason string.
const MAX_QUARANTINE_REASON_LEN: usize = 1024;

/// Maximum length of a detail/rationale string in floor evaluations.
const MAX_DETAIL_LEN: usize = 2048;

/// Maximum number of evaluation records in a batch evaluation.
const MAX_BATCH_EVALUATIONS: usize = 10_000;

/// Maximum length of a source cell ID string for cross-cell imports.
const MAX_CELL_ID_LEN: usize = 256;

/// Maximum length of a fact hash in bytes (BLAKE3 = 32).
const FACT_HASH_LEN: usize = 32;

// =============================================================================
// AttestationLevel
// =============================================================================

/// Attestation level for authoritative receipts and facts.
///
/// Levels are ordered by strength: `None < Soft < Strong < HumanCosign`.
///
/// RFC-0020 Section 6.5 defines the minimum attestation mapping per risk
/// tier. Higher-risk operations require stronger attestation to ensure
/// provenance integrity.
///
/// # Lattice Properties
///
/// - `join(a, b)` returns the *maximum* (strictest) level, used by the
///   delegation meet operator to prevent weakening.
/// - `meet(a, b)` returns the *minimum* (weakest) level.
/// - The ordering is total: `None < Soft < Strong < HumanCosign`.
#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[repr(u8)]
pub enum AttestationLevel {
    /// No attestation present. Fails any floor requirement.
    #[default]
    None        = 0,
    /// Soft attestation: signed adapter attestation with CAS artifact
    /// digests. Minimum for Tier2 operations.
    Soft        = 1,
    /// Strong attestation: replayable verifier proof or TEE-backed
    /// attestation. Required for Tier3+ operations.
    Strong      = 2,
    /// Human/operator co-sign attestation. May be required for Tier4
    /// operations in high-assurance deployments.
    HumanCosign = 3,
}

impl AttestationLevel {
    /// Returns the numeric ordinal for this level.
    #[must_use]
    pub const fn ordinal(self) -> u8 {
        self as u8
    }

    /// Construct from ordinal, returning `None` for out-of-range values
    /// (fail-closed).
    #[must_use]
    pub const fn from_ordinal(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::None),
            1 => Some(Self::Soft),
            2 => Some(Self::Strong),
            3 => Some(Self::HumanCosign),
            _ => Option::None,
        }
    }

    /// Returns `true` if this level meets or exceeds the given floor.
    #[must_use]
    pub const fn meets_floor(self, floor: Self) -> bool {
        (self as u8) >= (floor as u8)
    }

    /// Lattice join (least upper bound): returns the stricter level.
    ///
    /// Used by the delegation meet operator to prevent attestation
    /// weakening: `floor(D) = join(floor(A), floor(O))`.
    #[must_use]
    pub const fn join(self, other: Self) -> Self {
        if (self as u8) >= (other as u8) {
            self
        } else {
            other
        }
    }

    /// Lattice meet (greatest lower bound): returns the weaker level.
    #[must_use]
    pub const fn meet(self, other: Self) -> Self {
        if (self as u8) <= (other as u8) {
            self
        } else {
            other
        }
    }

    /// Returns the display name for this level.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "NONE",
            Self::Soft => "SOFT",
            Self::Strong => "STRONG",
            Self::HumanCosign => "HUMAN_COSIGN",
        }
    }
}

impl std::fmt::Display for AttestationLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// =============================================================================
// AttestationFloorPolicy
// =============================================================================

/// Policy mapping risk tiers to minimum attestation levels.
///
/// Encodes RFC-0020 Section 6.5 normative requirements:
/// - Tier0-Tier1: `Soft` allowed (floor = `None`)
/// - Tier2: `Soft` required (floor = `Soft`)
/// - Tier3: `Strong` required (floor = `Strong`)
/// - Tier4: `Strong` required; `HumanCosign` if configured
///
/// The policy also governs cross-cell import floor requirements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationFloorPolicy {
    /// Floor for Tier0 operations.
    #[serde(rename = "tier0_floor")]
    tier0: AttestationLevel,
    /// Floor for Tier1 operations.
    #[serde(rename = "tier1_floor")]
    tier1: AttestationLevel,
    /// Floor for Tier2 operations.
    #[serde(rename = "tier2_floor")]
    tier2: AttestationLevel,
    /// Floor for Tier3 operations.
    #[serde(rename = "tier3_floor")]
    tier3: AttestationLevel,
    /// Floor for Tier4 operations.
    #[serde(rename = "tier4_floor")]
    tier4: AttestationLevel,
    /// Floor for cross-cell imported facts. If not set, defaults to the
    /// tier3 floor (strictest common case for authoritative imports).
    #[serde(rename = "cross_cell_import_floor")]
    cross_cell_import: AttestationLevel,
}

impl Default for AttestationFloorPolicy {
    /// Returns the RFC-0020 Section 6.5 normative defaults.
    fn default() -> Self {
        Self {
            tier0: AttestationLevel::None,
            tier1: AttestationLevel::None,
            tier2: AttestationLevel::Soft,
            tier3: AttestationLevel::Strong,
            tier4: AttestationLevel::Strong,
            cross_cell_import: AttestationLevel::Strong,
        }
    }
}

impl AttestationFloorPolicy {
    /// Create a new policy with explicit per-tier floors.
    ///
    /// # Errors
    ///
    /// Returns [`AttestationFloorError::NonMonotonicFloors`] if a lower tier
    /// has a stricter floor than a higher tier (monotonicity violation).
    pub fn new(
        tier0: AttestationLevel,
        tier1: AttestationLevel,
        tier2: AttestationLevel,
        tier3: AttestationLevel,
        tier4: AttestationLevel,
        cross_cell_import: AttestationLevel,
    ) -> Result<Self, AttestationFloorError> {
        // Enforce monotonicity: higher tiers must not be weaker.
        if (tier1 as u8) < (tier0 as u8)
            || (tier2 as u8) < (tier1 as u8)
            || (tier3 as u8) < (tier2 as u8)
            || (tier4 as u8) < (tier3 as u8)
        {
            return Err(AttestationFloorError::NonMonotonicFloors {
                detail: format!(
                    "tier floors must be non-decreasing: tier0={tier0}, tier1={tier1}, \
                     tier2={tier2}, tier3={tier3}, tier4={tier4}"
                ),
            });
        }
        Ok(Self {
            tier0,
            tier1,
            tier2,
            tier3,
            tier4,
            cross_cell_import,
        })
    }

    /// Returns the attestation floor for the given risk tier.
    ///
    /// Tier values 0-4 map to the configured floors. Tiers above 4 are
    /// mapped to Tier4 (fail-closed: unknown high tiers get the strictest
    /// floor).
    #[must_use]
    pub const fn floor_for_tier(&self, tier: u8) -> AttestationLevel {
        match tier {
            0 => self.tier0,
            1 => self.tier1,
            2 => self.tier2,
            3 => self.tier3,
            // 4 and above get tier4 floor (fail-closed for unknown high tiers)
            _ => self.tier4,
        }
    }

    /// Returns the attestation floor for cross-cell imported facts.
    #[must_use]
    pub const fn cross_cell_import_floor(&self) -> AttestationLevel {
        self.cross_cell_import
    }

    /// Evaluates whether the given attestation level meets the floor for
    /// the specified risk tier.
    ///
    /// Returns a [`FloorEvaluation`] regardless of pass/fail for audit
    /// visibility. Rejects oversized actor IDs fail-closed to prevent
    /// audit-trail collision.
    ///
    /// # Errors
    ///
    /// Returns [`AttestationFloorError::FieldTooLong`] if `actor_id`
    /// exceeds the maximum length.
    pub fn evaluate_tier(
        &self,
        tier: u8,
        actual: AttestationLevel,
        actor_id: &str,
    ) -> Result<FloorEvaluation, AttestationFloorError> {
        validate_bounded(actor_id, "actor_id", MAX_ACTOR_ID_LEN)?;

        let required = self.floor_for_tier(tier);
        let passed = actual.meets_floor(required);

        Ok(FloorEvaluation {
            kind: EvaluationKind::TierRequest,
            tier,
            required_level: required,
            actual_level: actual,
            passed,
            actor_id: actor_id.to_string(),
            source_cell_id: String::new(),
            fact_hash: [0u8; FACT_HASH_LEN],
            detail: truncate_string(
                &if passed {
                    format!("attestation {actual} meets tier-{tier} floor {required}")
                } else {
                    format!("attestation {actual} below tier-{tier} floor {required}: DENIED")
                },
                MAX_DETAIL_LEN,
            ),
        })
    }

    /// Evaluates whether a cross-cell imported fact meets the import floor.
    ///
    /// Returns a [`FloorEvaluation`] with quarantine recommendation on
    /// failure. Rejects oversized identifiers fail-closed.
    ///
    /// # Errors
    ///
    /// Returns [`AttestationFloorError::FieldTooLong`] if `actor_id` or
    /// `source_cell_id` exceeds the maximum length.
    pub fn evaluate_cross_cell_import(
        &self,
        actual: AttestationLevel,
        source_cell_id: &str,
        fact_hash: [u8; FACT_HASH_LEN],
        actor_id: &str,
    ) -> Result<FloorEvaluation, AttestationFloorError> {
        validate_bounded(actor_id, "actor_id", MAX_ACTOR_ID_LEN)?;
        validate_bounded(source_cell_id, "source_cell_id", MAX_CELL_ID_LEN)?;

        let required = self.cross_cell_import;
        let passed = actual.meets_floor(required);

        Ok(FloorEvaluation {
            kind: EvaluationKind::CrossCellImport,
            tier: 0, // not tier-specific
            required_level: required,
            actual_level: actual,
            passed,
            actor_id: actor_id.to_string(),
            source_cell_id: source_cell_id.to_string(),
            fact_hash,
            detail: truncate_string(
                &if passed {
                    format!(
                        "cross-cell import attestation {actual} meets floor {required} \
                         from cell {source_cell_id}"
                    )
                } else {
                    format!(
                        "cross-cell import attestation {actual} below floor {required} \
                         from cell {source_cell_id}: QUARANTINED"
                    )
                },
                MAX_DETAIL_LEN,
            ),
        })
    }
}

// =============================================================================
// AttestationMetadata
// =============================================================================

/// Attestation metadata attached to authoritative receipts.
///
/// RFC-0020 Section 6.5 requires all authoritative receipts to include:
/// - actor identity
/// - environment fingerprint
/// - policy root key id
/// - optional TEE / runner attestations
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationMetadata {
    /// The attestation level achieved.
    pub level: AttestationLevel,
    /// Actor identity (`holon_id`/`actor_id`).
    pub actor_id: String,
    /// Environment fingerprint (capsule profile hash, toolchain hash).
    pub env_fingerprint: String,
    /// Policy root key ID.
    pub policy_root_key_id: String,
    /// Optional TEE attestation evidence hash (32 bytes, zeroed if absent).
    #[serde(with = "serde_bytes")]
    pub tee_evidence_hash: [u8; 32],
}

impl AttestationMetadata {
    /// Creates new attestation metadata.
    ///
    /// # Errors
    ///
    /// Returns [`AttestationFloorError::FieldTooLong`] if any string field
    /// exceeds its bound.
    pub fn new(
        level: AttestationLevel,
        actor_id: &str,
        env_fingerprint: &str,
        policy_root_key_id: &str,
        tee_evidence_hash: [u8; 32],
    ) -> Result<Self, AttestationFloorError> {
        validate_bounded(actor_id, "actor_id", MAX_ACTOR_ID_LEN)?;
        validate_bounded(env_fingerprint, "env_fingerprint", MAX_ENV_FINGERPRINT_LEN)?;
        validate_bounded(
            policy_root_key_id,
            "policy_root_key_id",
            MAX_POLICY_ROOT_KEY_ID_LEN,
        )?;
        Ok(Self {
            level,
            actor_id: actor_id.to_string(),
            env_fingerprint: env_fingerprint.to_string(),
            policy_root_key_id: policy_root_key_id.to_string(),
            tee_evidence_hash,
        })
    }

    /// Returns whether this metadata meets the given attestation floor.
    #[must_use]
    pub const fn meets_floor(&self, floor: AttestationLevel) -> bool {
        self.level.meets_floor(floor)
    }
}

// =============================================================================
// FloorEvaluation
// =============================================================================

/// The kind of attestation floor evaluation that was performed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvaluationKind {
    /// Evaluation of a tier-based request (local actuation).
    TierRequest,
    /// Evaluation of a cross-cell imported fact.
    CrossCellImport,
}

impl std::fmt::Display for EvaluationKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TierRequest => write!(f, "TIER_REQUEST"),
            Self::CrossCellImport => write!(f, "CROSS_CELL_IMPORT"),
        }
    }
}

/// Record of an attestation floor evaluation.
///
/// Every floor check produces one of these records for audit/receipt
/// visibility, regardless of whether it passes or fails. This satisfies
/// the REQ-0033 acceptance criterion that floor evaluations are
/// receipt/audit-event visible.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FloorEvaluation {
    /// The kind of evaluation.
    pub kind: EvaluationKind,
    /// The risk tier being evaluated (0 for cross-cell imports).
    pub tier: u8,
    /// The required attestation level (floor).
    pub required_level: AttestationLevel,
    /// The actual attestation level presented.
    pub actual_level: AttestationLevel,
    /// Whether the evaluation passed.
    pub passed: bool,
    /// Actor ID associated with the request.
    pub actor_id: String,
    /// Source cell ID (non-empty for cross-cell imports).
    pub source_cell_id: String,
    /// Fact hash for cross-cell imports (zeroed for tier requests).
    #[serde(with = "serde_bytes")]
    pub fact_hash: [u8; FACT_HASH_LEN],
    /// Human-readable evaluation detail.
    pub detail: String,
}

impl FloorEvaluation {
    /// Returns `true` if this evaluation represents a denial.
    #[must_use]
    pub const fn is_denied(&self) -> bool {
        !self.passed
    }

    /// Returns `true` if this evaluation requires quarantine
    /// (cross-cell import that failed the floor).
    #[must_use]
    pub const fn requires_quarantine(&self) -> bool {
        matches!(self.kind, EvaluationKind::CrossCellImport) && !self.passed
    }

    /// Returns a summary string suitable for audit events.
    #[must_use]
    pub fn summary(&self) -> String {
        if self.passed {
            format!(
                "floor_eval:PASS kind={} tier={} actual={} required={}",
                self.kind, self.tier, self.actual_level, self.required_level,
            )
        } else {
            format!(
                "floor_eval:FAIL kind={} tier={} actual={} required={} action={}",
                self.kind,
                self.tier,
                self.actual_level,
                self.required_level,
                if self.requires_quarantine() {
                    "QUARANTINE"
                } else {
                    "DENY"
                },
            )
        }
    }
}

// =============================================================================
// QuarantineRecord
// =============================================================================

/// Record of a fact quarantined due to attestation floor violation.
///
/// Cross-cell imported facts that fail the attestation floor are placed in
/// quarantine rather than accepted or silently dropped. This allows
/// operators to inspect and potentially re-admit facts once proper
/// attestation is obtained.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuarantineRecord {
    /// Hash of the quarantined fact.
    #[serde(with = "serde_bytes")]
    pub fact_hash: [u8; FACT_HASH_LEN],
    /// Source cell that produced the fact.
    pub source_cell_id: String,
    /// The attestation level the fact presented.
    pub actual_level: AttestationLevel,
    /// The floor it failed to meet.
    pub required_level: AttestationLevel,
    /// Human-readable quarantine reason.
    pub reason: String,
}

impl QuarantineRecord {
    /// Creates a quarantine record from a failed floor evaluation.
    ///
    /// # Errors
    ///
    /// Returns [`AttestationFloorError::NotQuarantinable`] if the
    /// evaluation passed or is not a cross-cell import.
    pub fn from_evaluation(eval: &FloorEvaluation) -> Result<Self, AttestationFloorError> {
        if !eval.requires_quarantine() {
            return Err(AttestationFloorError::NotQuarantinable {
                detail: format!(
                    "evaluation kind={} passed={} does not require quarantine",
                    eval.kind, eval.passed,
                ),
            });
        }
        Ok(Self {
            fact_hash: eval.fact_hash,
            source_cell_id: eval.source_cell_id.clone(),
            actual_level: eval.actual_level,
            required_level: eval.required_level,
            reason: truncate_string(&eval.detail, MAX_QUARANTINE_REASON_LEN),
        })
    }
}

// =============================================================================
// AttestationFloorGuard
// =============================================================================

/// Runtime guard that enforces attestation floor policy.
///
/// This guard is the single entry-point for attestation floor checks. It
/// wraps an [`AttestationFloorPolicy`] and provides `admit_tier` and
/// `admit_cross_cell_import` methods that return structured evaluation
/// records.
///
/// # Runtime Wiring
///
/// This guard is composed with the taint enforcement guard in the daemon's
/// tool broker admission path. Both guards must pass for a request to
/// proceed:
///
/// ```rust
/// use apm2_core::policy::attestation_floor::{
///     AttestationFloorGuard, AttestationFloorPolicy, AttestationLevel,
/// };
///
/// let policy = AttestationFloorPolicy::default();
/// let guard = AttestationFloorGuard::new(policy);
///
/// // Tier3 request with Strong attestation passes.
/// let eval = guard
///     .admit_tier(3, AttestationLevel::Strong, "actor-1")
///     .unwrap();
/// assert!(eval.passed);
///
/// // Tier3 request with Soft attestation is denied.
/// let eval = guard
///     .admit_tier(3, AttestationLevel::Soft, "actor-2")
///     .unwrap();
/// assert!(!eval.passed);
/// ```
#[derive(Debug, Clone)]
pub struct AttestationFloorGuard {
    policy: AttestationFloorPolicy,
}

impl AttestationFloorGuard {
    /// Create a new guard wrapping the given policy.
    #[must_use]
    pub const fn new(policy: AttestationFloorPolicy) -> Self {
        Self { policy }
    }

    /// Admit a tier-based request.
    ///
    /// Returns a [`FloorEvaluation`] recording the outcome. If the
    /// evaluation fails (i.e., `eval.passed == false`), the caller MUST
    /// deny the request.
    ///
    /// # Errors
    ///
    /// Returns [`AttestationFloorError::FieldTooLong`] if `actor_id`
    /// exceeds the maximum length (fail-closed).
    pub fn admit_tier(
        &self,
        tier: u8,
        actual: AttestationLevel,
        actor_id: &str,
    ) -> Result<FloorEvaluation, AttestationFloorError> {
        self.policy.evaluate_tier(tier, actual, actor_id)
    }

    /// Admit a cross-cell imported fact.
    ///
    /// Returns a [`FloorEvaluation`] recording the outcome. If the
    /// evaluation fails, the caller MUST quarantine the fact.
    ///
    /// # Errors
    ///
    /// Returns [`AttestationFloorError::FieldTooLong`] if `actor_id` or
    /// `source_cell_id` exceeds the maximum length (fail-closed).
    pub fn admit_cross_cell_import(
        &self,
        actual: AttestationLevel,
        source_cell_id: &str,
        fact_hash: [u8; FACT_HASH_LEN],
        actor_id: &str,
    ) -> Result<FloorEvaluation, AttestationFloorError> {
        self.policy
            .evaluate_cross_cell_import(actual, source_cell_id, fact_hash, actor_id)
    }

    /// Returns a reference to the underlying policy.
    #[must_use]
    pub const fn policy(&self) -> &AttestationFloorPolicy {
        &self.policy
    }

    /// Batch-evaluate a set of cross-cell imports and return all evaluations.
    ///
    /// This is a convenience method for bulk import admission. Each fact is
    /// independently evaluated.
    ///
    /// # Errors
    ///
    /// Returns [`AttestationFloorError::BatchTooLarge`] if the input exceeds
    /// the maximum batch evaluation count (10,000), or
    /// [`AttestationFloorError::FieldTooLong`] if any import request
    /// contains an oversized identifier.
    pub fn batch_admit_cross_cell(
        &self,
        imports: &[CrossCellImportRequest],
    ) -> Result<Vec<FloorEvaluation>, AttestationFloorError> {
        if imports.len() > MAX_BATCH_EVALUATIONS {
            return Err(AttestationFloorError::BatchTooLarge {
                count: imports.len(),
                max: MAX_BATCH_EVALUATIONS,
            });
        }
        imports
            .iter()
            .map(|req| {
                self.admit_cross_cell_import(
                    req.actual_level,
                    &req.source_cell_id,
                    req.fact_hash,
                    &req.actor_id,
                )
            })
            .collect()
    }
}

// =============================================================================
// CrossCellImportRequest
// =============================================================================

/// A request to import a fact from another cell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossCellImportRequest {
    /// The attestation level of the imported fact.
    pub actual_level: AttestationLevel,
    /// The source cell ID.
    pub source_cell_id: String,
    /// Hash of the fact being imported.
    pub fact_hash: [u8; FACT_HASH_LEN],
    /// Actor ID performing the import.
    pub actor_id: String,
}

// =============================================================================
// Error Types
// =============================================================================

/// Errors from attestation floor operations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum AttestationFloorError {
    /// A string field exceeds its maximum length.
    #[error("field '{field}' length {len} exceeds maximum {max}")]
    FieldTooLong {
        /// The field name.
        field: String,
        /// Actual length.
        len: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// Tier floors are not monotonically non-decreasing.
    #[error("non-monotonic attestation floors: {detail}")]
    NonMonotonicFloors {
        /// Detail about which tiers violate monotonicity.
        detail: String,
    },

    /// Attempted to create a quarantine record from a non-quarantinable
    /// evaluation.
    #[error("evaluation does not require quarantine: {detail}")]
    NotQuarantinable {
        /// Detail about why quarantine is not applicable.
        detail: String,
    },

    /// Batch import request exceeds the maximum allowed count.
    #[error("batch import count {count} exceeds maximum {max}")]
    BatchTooLarge {
        /// Number of imports requested.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Validates that a string field does not exceed a maximum length.
fn validate_bounded(value: &str, field: &str, max_len: usize) -> Result<(), AttestationFloorError> {
    if value.len() > max_len {
        return Err(AttestationFloorError::FieldTooLong {
            field: field.to_string(),
            len: value.len(),
            max: max_len,
        });
    }
    Ok(())
}

/// Truncates a string to the maximum length, preserving valid UTF-8.
fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        return s.to_string();
    }
    let mut end = max_len;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // AttestationLevel Tests
    // =========================================================================

    #[test]
    fn attestation_level_ordering() {
        assert!(AttestationLevel::None < AttestationLevel::Soft);
        assert!(AttestationLevel::Soft < AttestationLevel::Strong);
        assert!(AttestationLevel::Strong < AttestationLevel::HumanCosign);
    }

    #[test]
    fn attestation_level_ordinal_roundtrip() {
        for ordinal in 0..=3u8 {
            let level = AttestationLevel::from_ordinal(ordinal).unwrap();
            assert_eq!(level.ordinal(), ordinal);
        }
        assert!(AttestationLevel::from_ordinal(4).is_none());
        assert!(AttestationLevel::from_ordinal(255).is_none());
    }

    #[test]
    fn attestation_level_meets_floor() {
        assert!(AttestationLevel::Strong.meets_floor(AttestationLevel::None));
        assert!(AttestationLevel::Strong.meets_floor(AttestationLevel::Soft));
        assert!(AttestationLevel::Strong.meets_floor(AttestationLevel::Strong));
        assert!(!AttestationLevel::Strong.meets_floor(AttestationLevel::HumanCosign));
        assert!(!AttestationLevel::None.meets_floor(AttestationLevel::Soft));
        assert!(AttestationLevel::None.meets_floor(AttestationLevel::None));
    }

    #[test]
    fn attestation_level_join() {
        assert_eq!(
            AttestationLevel::Soft.join(AttestationLevel::Strong),
            AttestationLevel::Strong
        );
        assert_eq!(
            AttestationLevel::Strong.join(AttestationLevel::Soft),
            AttestationLevel::Strong
        );
        assert_eq!(
            AttestationLevel::None.join(AttestationLevel::None),
            AttestationLevel::None
        );
        assert_eq!(
            AttestationLevel::HumanCosign.join(AttestationLevel::None),
            AttestationLevel::HumanCosign
        );
    }

    #[test]
    fn attestation_level_meet() {
        assert_eq!(
            AttestationLevel::Soft.meet(AttestationLevel::Strong),
            AttestationLevel::Soft
        );
        assert_eq!(
            AttestationLevel::Strong.meet(AttestationLevel::Soft),
            AttestationLevel::Soft
        );
        assert_eq!(
            AttestationLevel::None.meet(AttestationLevel::None),
            AttestationLevel::None
        );
    }

    #[test]
    fn attestation_level_display() {
        assert_eq!(AttestationLevel::None.to_string(), "NONE");
        assert_eq!(AttestationLevel::Soft.to_string(), "SOFT");
        assert_eq!(AttestationLevel::Strong.to_string(), "STRONG");
        assert_eq!(AttestationLevel::HumanCosign.to_string(), "HUMAN_COSIGN");
    }

    #[test]
    fn attestation_level_default() {
        assert_eq!(AttestationLevel::default(), AttestationLevel::None);
    }

    #[test]
    fn attestation_level_serde_roundtrip() {
        for ordinal in 0..=3u8 {
            let level = AttestationLevel::from_ordinal(ordinal).unwrap();
            let json = serde_json::to_string(&level).unwrap();
            let deserialized: AttestationLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(level, deserialized);
        }
    }

    // =========================================================================
    // AttestationFloorPolicy Tests
    // =========================================================================

    #[test]
    fn default_policy_matches_rfc_0020() {
        let policy = AttestationFloorPolicy::default();

        // Tier0-1: None floor (Soft allowed)
        assert_eq!(policy.floor_for_tier(0), AttestationLevel::None);
        assert_eq!(policy.floor_for_tier(1), AttestationLevel::None);

        // Tier2: Soft required
        assert_eq!(policy.floor_for_tier(2), AttestationLevel::Soft);

        // Tier3: Strong required
        assert_eq!(policy.floor_for_tier(3), AttestationLevel::Strong);

        // Tier4: Strong required
        assert_eq!(policy.floor_for_tier(4), AttestationLevel::Strong);

        // Cross-cell: Strong required
        assert_eq!(policy.cross_cell_import_floor(), AttestationLevel::Strong);
    }

    #[test]
    fn policy_tier_above_4_maps_to_tier4() {
        let policy = AttestationFloorPolicy::default();
        assert_eq!(policy.floor_for_tier(5), AttestationLevel::Strong);
        assert_eq!(policy.floor_for_tier(255), AttestationLevel::Strong);
    }

    #[test]
    fn policy_rejects_non_monotonic_floors() {
        let result = AttestationFloorPolicy::new(
            AttestationLevel::Strong, // tier0 stricter than tier1
            AttestationLevel::Soft,
            AttestationLevel::Soft,
            AttestationLevel::Strong,
            AttestationLevel::Strong,
            AttestationLevel::Strong,
        );
        assert!(matches!(
            result,
            Err(AttestationFloorError::NonMonotonicFloors { .. })
        ));
    }

    #[test]
    fn policy_accepts_monotonic_floors() {
        let result = AttestationFloorPolicy::new(
            AttestationLevel::None,
            AttestationLevel::Soft,
            AttestationLevel::Soft,
            AttestationLevel::Strong,
            AttestationLevel::HumanCosign,
            AttestationLevel::Strong,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn policy_accepts_equal_floors() {
        let result = AttestationFloorPolicy::new(
            AttestationLevel::Soft,
            AttestationLevel::Soft,
            AttestationLevel::Soft,
            AttestationLevel::Soft,
            AttestationLevel::Soft,
            AttestationLevel::Soft,
        );
        assert!(result.is_ok());
    }

    // =========================================================================
    // FloorEvaluation Tests: Tier Requests
    // =========================================================================

    #[test]
    fn tier3_strong_attestation_passes() {
        let policy = AttestationFloorPolicy::default();
        let eval = policy
            .evaluate_tier(3, AttestationLevel::Strong, "actor-1")
            .unwrap();
        assert!(eval.passed);
        assert!(!eval.is_denied());
        assert_eq!(eval.kind, EvaluationKind::TierRequest);
        assert_eq!(eval.tier, 3);
        assert_eq!(eval.required_level, AttestationLevel::Strong);
        assert_eq!(eval.actual_level, AttestationLevel::Strong);
    }

    #[test]
    fn tier3_soft_attestation_denied() {
        let policy = AttestationFloorPolicy::default();
        let eval = policy
            .evaluate_tier(3, AttestationLevel::Soft, "actor-1")
            .unwrap();
        assert!(!eval.passed);
        assert!(eval.is_denied());
        assert!(eval.detail.contains("DENIED"));
    }

    #[test]
    fn tier3_none_attestation_denied() {
        let policy = AttestationFloorPolicy::default();
        let eval = policy
            .evaluate_tier(3, AttestationLevel::None, "actor-1")
            .unwrap();
        assert!(!eval.passed);
    }

    #[test]
    fn tier3_human_cosign_passes() {
        let policy = AttestationFloorPolicy::default();
        let eval = policy
            .evaluate_tier(3, AttestationLevel::HumanCosign, "actor-1")
            .unwrap();
        assert!(eval.passed);
    }

    #[test]
    fn tier0_none_attestation_passes() {
        let policy = AttestationFloorPolicy::default();
        let eval = policy
            .evaluate_tier(0, AttestationLevel::None, "actor-1")
            .unwrap();
        assert!(eval.passed);
    }

    #[test]
    fn tier2_soft_attestation_passes() {
        let policy = AttestationFloorPolicy::default();
        let eval = policy
            .evaluate_tier(2, AttestationLevel::Soft, "actor-1")
            .unwrap();
        assert!(eval.passed);
    }

    #[test]
    fn tier2_none_attestation_denied() {
        let policy = AttestationFloorPolicy::default();
        let eval = policy
            .evaluate_tier(2, AttestationLevel::None, "actor-1")
            .unwrap();
        assert!(!eval.passed);
    }

    #[test]
    fn tier4_strong_attestation_passes() {
        let policy = AttestationFloorPolicy::default();
        let eval = policy
            .evaluate_tier(4, AttestationLevel::Strong, "actor-1")
            .unwrap();
        assert!(eval.passed);
    }

    #[test]
    fn unknown_high_tier_uses_tier4_floor() {
        let policy = AttestationFloorPolicy::default();
        let eval = policy
            .evaluate_tier(99, AttestationLevel::Soft, "actor-1")
            .unwrap();
        assert!(!eval.passed);
        assert_eq!(eval.required_level, AttestationLevel::Strong);
    }

    // =========================================================================
    // FloorEvaluation Tests: Cross-Cell Import
    // =========================================================================

    #[test]
    fn cross_cell_strong_passes() {
        let policy = AttestationFloorPolicy::default();
        let eval = policy
            .evaluate_cross_cell_import(
                AttestationLevel::Strong,
                "cell-remote-01",
                [0xAA; 32],
                "importer-1",
            )
            .unwrap();
        assert!(eval.passed);
        assert!(!eval.requires_quarantine());
        assert_eq!(eval.kind, EvaluationKind::CrossCellImport);
    }

    #[test]
    fn cross_cell_soft_quarantined() {
        let policy = AttestationFloorPolicy::default();
        let eval = policy
            .evaluate_cross_cell_import(
                AttestationLevel::Soft,
                "cell-remote-01",
                [0xBB; 32],
                "importer-1",
            )
            .unwrap();
        assert!(!eval.passed);
        assert!(eval.requires_quarantine());
        assert!(eval.detail.contains("QUARANTINED"));
    }

    #[test]
    fn cross_cell_none_quarantined() {
        let policy = AttestationFloorPolicy::default();
        let eval = policy
            .evaluate_cross_cell_import(
                AttestationLevel::None,
                "cell-remote-01",
                [0xCC; 32],
                "importer-1",
            )
            .unwrap();
        assert!(!eval.passed);
        assert!(eval.requires_quarantine());
    }

    #[test]
    fn cross_cell_human_cosign_passes() {
        let policy = AttestationFloorPolicy::default();
        let eval = policy
            .evaluate_cross_cell_import(
                AttestationLevel::HumanCosign,
                "cell-remote-01",
                [0xDD; 32],
                "importer-1",
            )
            .unwrap();
        assert!(eval.passed);
    }

    // =========================================================================
    // Oversized Identifier Rejection Tests (MAJOR fix #1)
    // =========================================================================

    #[test]
    fn oversized_actor_id_rejected_in_tier_eval() {
        let policy = AttestationFloorPolicy::default();
        let long_actor = "a".repeat(MAX_ACTOR_ID_LEN + 1);
        let result = policy.evaluate_tier(3, AttestationLevel::Strong, &long_actor);
        assert!(matches!(
            result,
            Err(AttestationFloorError::FieldTooLong { .. })
        ));
    }

    #[test]
    fn oversized_actor_id_rejected_in_cross_cell_eval() {
        let policy = AttestationFloorPolicy::default();
        let long_actor = "a".repeat(MAX_ACTOR_ID_LEN + 1);
        let result = policy.evaluate_cross_cell_import(
            AttestationLevel::Strong,
            "cell-01",
            [0; 32],
            &long_actor,
        );
        assert!(matches!(
            result,
            Err(AttestationFloorError::FieldTooLong { .. })
        ));
    }

    #[test]
    fn oversized_cell_id_rejected_in_cross_cell_eval() {
        let policy = AttestationFloorPolicy::default();
        let long_cell = "c".repeat(MAX_CELL_ID_LEN + 1);
        let result = policy.evaluate_cross_cell_import(
            AttestationLevel::Strong,
            &long_cell,
            [0; 32],
            "actor-1",
        );
        assert!(matches!(
            result,
            Err(AttestationFloorError::FieldTooLong { .. })
        ));
    }

    #[test]
    fn max_length_actor_id_accepted() {
        let policy = AttestationFloorPolicy::default();
        let exact_actor = "a".repeat(MAX_ACTOR_ID_LEN);
        let eval = policy
            .evaluate_tier(3, AttestationLevel::Strong, &exact_actor)
            .unwrap();
        assert!(eval.passed);
        assert_eq!(eval.actor_id.len(), MAX_ACTOR_ID_LEN);
    }

    #[test]
    fn max_length_cell_id_accepted() {
        let policy = AttestationFloorPolicy::default();
        let exact_cell = "c".repeat(MAX_CELL_ID_LEN);
        let eval = policy
            .evaluate_cross_cell_import(AttestationLevel::Strong, &exact_cell, [0; 32], "actor-1")
            .unwrap();
        assert!(eval.passed);
        assert_eq!(eval.source_cell_id.len(), MAX_CELL_ID_LEN);
    }

    // =========================================================================
    // Deny Unknown Fields Tests (MAJOR fix #2)
    // =========================================================================

    #[test]
    fn policy_rejects_unknown_fields() {
        let json = r#"{
            "tier0_floor": "NONE",
            "tier1_floor": "NONE",
            "tier2_floor": "SOFT",
            "tier3_floor": "STRONG",
            "tier4_floor": "STRONG",
            "cross_cell_import_floor": "STRONG",
            "smuggled_field": "evil"
        }"#;
        let result: Result<AttestationFloorPolicy, _> = serde_json::from_str(json);
        assert!(result.is_err(), "unknown fields must be rejected");
    }

    #[test]
    fn metadata_rejects_unknown_fields() {
        let json = r#"{
            "level": "STRONG",
            "actor_id": "actor",
            "env_fingerprint": "env",
            "policy_root_key_id": "key",
            "tee_evidence_hash": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "smuggled": true
        }"#;
        let result: Result<AttestationMetadata, _> = serde_json::from_str(json);
        assert!(result.is_err(), "unknown fields must be rejected");
    }

    #[test]
    fn floor_evaluation_rejects_unknown_fields() {
        let json = r#"{
            "kind": "TIER_REQUEST",
            "tier": 3,
            "required_level": "STRONG",
            "actual_level": "STRONG",
            "passed": true,
            "actor_id": "a",
            "source_cell_id": "",
            "fact_hash": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "detail": "ok",
            "extra": "bad"
        }"#;
        let result: Result<FloorEvaluation, _> = serde_json::from_str(json);
        assert!(result.is_err(), "unknown fields must be rejected");
    }

    #[test]
    fn quarantine_record_rejects_unknown_fields() {
        let json = r#"{
            "fact_hash": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "source_cell_id": "cell",
            "actual_level": "SOFT",
            "required_level": "STRONG",
            "reason": "below floor",
            "injected": 42
        }"#;
        let result: Result<QuarantineRecord, _> = serde_json::from_str(json);
        assert!(result.is_err(), "unknown fields must be rejected");
    }

    // =========================================================================
    // QuarantineRecord Tests
    // =========================================================================

    #[test]
    fn quarantine_record_from_failed_cross_cell() {
        let policy = AttestationFloorPolicy::default();
        let eval = policy
            .evaluate_cross_cell_import(
                AttestationLevel::Soft,
                "cell-remote-01",
                [0xBB; 32],
                "importer-1",
            )
            .unwrap();
        let record = QuarantineRecord::from_evaluation(&eval).unwrap();
        assert_eq!(record.fact_hash, [0xBB; 32]);
        assert_eq!(record.source_cell_id, "cell-remote-01");
        assert_eq!(record.actual_level, AttestationLevel::Soft);
        assert_eq!(record.required_level, AttestationLevel::Strong);
    }

    #[test]
    fn quarantine_record_from_passing_eval_fails() {
        let policy = AttestationFloorPolicy::default();
        let eval = policy
            .evaluate_cross_cell_import(
                AttestationLevel::Strong,
                "cell-remote-01",
                [0xAA; 32],
                "importer-1",
            )
            .unwrap();
        assert!(matches!(
            QuarantineRecord::from_evaluation(&eval),
            Err(AttestationFloorError::NotQuarantinable { .. })
        ));
    }

    #[test]
    fn quarantine_record_from_tier_eval_fails() {
        let policy = AttestationFloorPolicy::default();
        let eval = policy
            .evaluate_tier(3, AttestationLevel::Soft, "actor-1")
            .unwrap();
        assert!(matches!(
            QuarantineRecord::from_evaluation(&eval),
            Err(AttestationFloorError::NotQuarantinable { .. })
        ));
    }

    // =========================================================================
    // AttestationFloorGuard Tests
    // =========================================================================

    #[test]
    fn guard_admit_tier_passes() {
        let guard = AttestationFloorGuard::new(AttestationFloorPolicy::default());
        let eval = guard
            .admit_tier(3, AttestationLevel::Strong, "actor-1")
            .unwrap();
        assert!(eval.passed);
    }

    #[test]
    fn guard_admit_tier_denied() {
        let guard = AttestationFloorGuard::new(AttestationFloorPolicy::default());
        let eval = guard
            .admit_tier(3, AttestationLevel::Soft, "actor-1")
            .unwrap();
        assert!(!eval.passed);
    }

    #[test]
    fn guard_admit_cross_cell_passes() {
        let guard = AttestationFloorGuard::new(AttestationFloorPolicy::default());
        let eval = guard
            .admit_cross_cell_import(AttestationLevel::Strong, "cell-01", [0xFF; 32], "actor-1")
            .unwrap();
        assert!(eval.passed);
    }

    #[test]
    fn guard_admit_cross_cell_quarantined() {
        let guard = AttestationFloorGuard::new(AttestationFloorPolicy::default());
        let eval = guard
            .admit_cross_cell_import(AttestationLevel::None, "cell-01", [0xFF; 32], "actor-1")
            .unwrap();
        assert!(!eval.passed);
        assert!(eval.requires_quarantine());
    }

    #[test]
    fn guard_rejects_oversized_actor() {
        let guard = AttestationFloorGuard::new(AttestationFloorPolicy::default());
        let long_actor = "x".repeat(MAX_ACTOR_ID_LEN + 1);
        assert!(matches!(
            guard.admit_tier(3, AttestationLevel::Strong, &long_actor),
            Err(AttestationFloorError::FieldTooLong { .. })
        ));
    }

    // =========================================================================
    // Batch Evaluation Tests
    // =========================================================================

    #[test]
    fn batch_admit_cross_cell_evaluates_all() {
        let guard = AttestationFloorGuard::new(AttestationFloorPolicy::default());
        let imports = vec![
            CrossCellImportRequest {
                actual_level: AttestationLevel::Strong,
                source_cell_id: "cell-01".to_string(),
                fact_hash: [0x01; 32],
                actor_id: "actor-1".to_string(),
            },
            CrossCellImportRequest {
                actual_level: AttestationLevel::Soft,
                source_cell_id: "cell-02".to_string(),
                fact_hash: [0x02; 32],
                actor_id: "actor-1".to_string(),
            },
            CrossCellImportRequest {
                actual_level: AttestationLevel::HumanCosign,
                source_cell_id: "cell-03".to_string(),
                fact_hash: [0x03; 32],
                actor_id: "actor-1".to_string(),
            },
        ];

        let evals = guard.batch_admit_cross_cell(&imports).unwrap();
        assert_eq!(evals.len(), 3);
        assert!(evals[0].passed);
        assert!(!evals[1].passed); // Soft below Strong floor
        assert!(evals[2].passed);
    }

    #[test]
    fn batch_admit_rejects_oversized_batch() {
        let guard = AttestationFloorGuard::new(AttestationFloorPolicy::default());
        let imports: Vec<CrossCellImportRequest> = (0..=MAX_BATCH_EVALUATIONS)
            .map(|i| CrossCellImportRequest {
                actual_level: AttestationLevel::Strong,
                source_cell_id: format!("cell-{i}"),
                fact_hash: [0x00; 32],
                actor_id: "actor-1".to_string(),
            })
            .collect();
        assert!(matches!(
            guard.batch_admit_cross_cell(&imports),
            Err(AttestationFloorError::BatchTooLarge { .. })
        ));
    }

    #[test]
    fn batch_admit_fails_on_oversized_id_in_import() {
        let guard = AttestationFloorGuard::new(AttestationFloorPolicy::default());
        let imports = vec![CrossCellImportRequest {
            actual_level: AttestationLevel::Strong,
            source_cell_id: "c".repeat(MAX_CELL_ID_LEN + 1),
            fact_hash: [0x00; 32],
            actor_id: "actor-1".to_string(),
        }];
        assert!(matches!(
            guard.batch_admit_cross_cell(&imports),
            Err(AttestationFloorError::FieldTooLong { .. })
        ));
    }

    // =========================================================================
    // AttestationMetadata Tests
    // =========================================================================

    #[test]
    fn metadata_creation_valid() {
        let meta = AttestationMetadata::new(
            AttestationLevel::Strong,
            "holon-001",
            "env-fp-abc123",
            "key-root-001",
            [0x42; 32],
        )
        .unwrap();
        assert_eq!(meta.level, AttestationLevel::Strong);
        assert_eq!(meta.actor_id, "holon-001");
    }

    #[test]
    fn metadata_rejects_oversized_actor_id() {
        let long_id = "a".repeat(MAX_ACTOR_ID_LEN + 1);
        let result = AttestationMetadata::new(
            AttestationLevel::Strong,
            &long_id,
            "env-fp",
            "key-root",
            [0; 32],
        );
        assert!(matches!(
            result,
            Err(AttestationFloorError::FieldTooLong { .. })
        ));
    }

    #[test]
    fn metadata_rejects_oversized_env_fingerprint() {
        let long_fp = "x".repeat(MAX_ENV_FINGERPRINT_LEN + 1);
        let result = AttestationMetadata::new(
            AttestationLevel::Strong,
            "actor",
            &long_fp,
            "key-root",
            [0; 32],
        );
        assert!(matches!(
            result,
            Err(AttestationFloorError::FieldTooLong { .. })
        ));
    }

    #[test]
    fn metadata_rejects_oversized_policy_root_key_id() {
        let long_key = "k".repeat(MAX_POLICY_ROOT_KEY_ID_LEN + 1);
        let result =
            AttestationMetadata::new(AttestationLevel::Strong, "actor", "env", &long_key, [0; 32]);
        assert!(matches!(
            result,
            Err(AttestationFloorError::FieldTooLong { .. })
        ));
    }

    #[test]
    fn metadata_meets_floor() {
        let meta =
            AttestationMetadata::new(AttestationLevel::Strong, "actor", "env", "key", [0; 32])
                .unwrap();
        assert!(meta.meets_floor(AttestationLevel::None));
        assert!(meta.meets_floor(AttestationLevel::Soft));
        assert!(meta.meets_floor(AttestationLevel::Strong));
        assert!(!meta.meets_floor(AttestationLevel::HumanCosign));
    }

    // =========================================================================
    // FloorEvaluation Summary Tests
    // =========================================================================

    #[test]
    fn floor_evaluation_summary_pass() {
        let policy = AttestationFloorPolicy::default();
        let eval = policy
            .evaluate_tier(3, AttestationLevel::Strong, "actor-1")
            .unwrap();
        let summary = eval.summary();
        assert!(summary.contains("PASS"));
        assert!(summary.contains("tier=3"));
        assert!(summary.contains("STRONG"));
    }

    #[test]
    fn floor_evaluation_summary_fail_deny() {
        let policy = AttestationFloorPolicy::default();
        let eval = policy
            .evaluate_tier(3, AttestationLevel::Soft, "actor-1")
            .unwrap();
        let summary = eval.summary();
        assert!(summary.contains("FAIL"));
        assert!(summary.contains("DENY"));
    }

    #[test]
    fn floor_evaluation_summary_fail_quarantine() {
        let policy = AttestationFloorPolicy::default();
        let eval = policy
            .evaluate_cross_cell_import(AttestationLevel::Soft, "cell-01", [0; 32], "actor-1")
            .unwrap();
        let summary = eval.summary();
        assert!(summary.contains("FAIL"));
        assert!(summary.contains("QUARANTINE"));
    }

    // =========================================================================
    // Delegation Meet Operator Tests
    // =========================================================================

    #[test]
    fn delegation_meet_takes_strictest_floor() {
        let parent = AttestationLevel::Soft;
        let child = AttestationLevel::Strong;
        assert_eq!(parent.join(child), AttestationLevel::Strong);

        let parent = AttestationLevel::Strong;
        let child = AttestationLevel::Soft;
        assert_eq!(parent.join(child), AttestationLevel::Strong);

        let parent = AttestationLevel::None;
        let child = AttestationLevel::HumanCosign;
        assert_eq!(parent.join(child), AttestationLevel::HumanCosign);
    }

    #[test]
    fn delegation_cannot_weaken_attestation_floor() {
        let parent_floor = AttestationLevel::Strong;
        let proposed_child = AttestationLevel::Soft;
        let effective = parent_floor.join(proposed_child);
        assert_eq!(effective, AttestationLevel::Strong);
        assert!(effective.meets_floor(parent_floor));
    }

    // =========================================================================
    // Fail-Closed Semantics Tests
    // =========================================================================

    #[test]
    fn fail_closed_unknown_ordinal() {
        assert!(AttestationLevel::from_ordinal(4).is_none());
        assert!(AttestationLevel::from_ordinal(255).is_none());
    }

    #[test]
    fn fail_closed_tier3_no_attestation() {
        let policy = AttestationFloorPolicy::default();
        let eval = policy
            .evaluate_tier(3, AttestationLevel::None, "actor-1")
            .unwrap();
        assert!(!eval.passed);
    }

    #[test]
    fn fail_closed_cross_cell_no_attestation() {
        let policy = AttestationFloorPolicy::default();
        let eval = policy
            .evaluate_cross_cell_import(
                AttestationLevel::None,
                "cell-untrusted",
                [0; 32],
                "importer-1",
            )
            .unwrap();
        assert!(!eval.passed);
        assert!(eval.requires_quarantine());
    }

    // =========================================================================
    // EvaluationKind Display Tests
    // =========================================================================

    #[test]
    fn evaluation_kind_display() {
        assert_eq!(EvaluationKind::TierRequest.to_string(), "TIER_REQUEST");
        assert_eq!(
            EvaluationKind::CrossCellImport.to_string(),
            "CROSS_CELL_IMPORT"
        );
    }

    // =========================================================================
    // Serialization Roundtrip Tests
    // =========================================================================

    #[test]
    fn floor_evaluation_serde_roundtrip() {
        let policy = AttestationFloorPolicy::default();
        let eval = policy
            .evaluate_tier(3, AttestationLevel::Strong, "actor-1")
            .unwrap();
        let json = serde_json::to_string(&eval).unwrap();
        let deserialized: FloorEvaluation = serde_json::from_str(&json).unwrap();
        assert_eq!(eval, deserialized);
    }

    #[test]
    fn quarantine_record_serde_roundtrip() {
        let policy = AttestationFloorPolicy::default();
        let eval = policy
            .evaluate_cross_cell_import(AttestationLevel::Soft, "cell-01", [0xBB; 32], "actor-1")
            .unwrap();
        let record = QuarantineRecord::from_evaluation(&eval).unwrap();
        let json = serde_json::to_string(&record).unwrap();
        let deserialized: QuarantineRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, deserialized);
    }

    #[test]
    fn attestation_metadata_serde_roundtrip() {
        let meta = AttestationMetadata::new(
            AttestationLevel::Strong,
            "holon-001",
            "env-fp-abc123",
            "key-root-001",
            [0x42; 32],
        )
        .unwrap();
        let json = serde_json::to_string(&meta).unwrap();
        let deserialized: AttestationMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(meta, deserialized);
    }

    #[test]
    fn policy_serde_roundtrip() {
        let policy = AttestationFloorPolicy::default();
        let json = serde_json::to_string(&policy).unwrap();
        let deserialized: AttestationFloorPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, deserialized);
    }

    // =========================================================================
    // Edge Case: All Tiers With All Levels
    // =========================================================================

    #[test]
    fn exhaustive_tier_level_matrix() {
        let policy = AttestationFloorPolicy::default();
        let tiers = [0u8, 1, 2, 3, 4, 5, 255];
        let levels = [
            AttestationLevel::None,
            AttestationLevel::Soft,
            AttestationLevel::Strong,
            AttestationLevel::HumanCosign,
        ];

        for &tier in &tiers {
            let floor = policy.floor_for_tier(tier);
            for &level in &levels {
                let eval = policy.evaluate_tier(tier, level, "test-actor").unwrap();
                let expected = level.meets_floor(floor);
                assert_eq!(
                    eval.passed, expected,
                    "tier={tier} level={level} floor={floor}: expected passed={expected}"
                );
            }
        }
    }
}
