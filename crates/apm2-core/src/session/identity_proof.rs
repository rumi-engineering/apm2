// AGENT-AUTHORED
//! Session-open identity proof and freshness enforcement (TCK-00361).
//!
//! This module implements proof-carrying session-open semantics that bind
//! identity freshness to risk-tier authority decisions. Every session-open
//! request MUST carry the holon identity and an identity proof hash; the
//! daemon response MUST include the cell certificate hash and directory
//! head hash.
//!
//! # Freshness Policy
//!
//! [`FreshnessPolicy`] specifies per-risk-tier staleness thresholds in
//! ticks. When a proof's age (current tick minus proof generation tick)
//! exceeds the configured threshold for the session's risk tier, the
//! session-open is denied for Tier2+ authority surfaces. Discovery-only
//! surfaces (Tier0/Tier1) may proceed under a configurable degraded
//! policy.
//!
//! # Defect Emission
//!
//! Stale or missing identity proofs emit [`SessionIdentityDefect`] for
//! auditable tracing. All defects include the risk tier, proof age,
//! and configured threshold.
//!
//! # Receipt Instrumentation
//!
//! Every session-open decision emits a [`SessionOpenReceipt`] that
//! records the request hash, response hash, freshness decision, and
//! risk tier for deterministic replay and audit.
//!
//! # Security Model
//!
//! - Fail-closed: missing proofs always deny Tier2+ authority.
//! - No wall-clock: freshness uses tick-based age only.
//! - Bounded: all collections are bounded by compile-time constants.

use crate::crypto::{HASH_SIZE, Hash};
use crate::fac::RiskTier;

// =============================================================================
// Constants
// =============================================================================

/// Maximum staleness in ticks for Tier0 (discovery-only). 0 means no limit.
pub const DEFAULT_TIER0_MAX_STALENESS_TICKS: u64 = 0;

/// Maximum staleness in ticks for Tier1 (local development).
pub const DEFAULT_TIER1_MAX_STALENESS_TICKS: u64 = 1_000_000;

/// Maximum staleness in ticks for Tier2 (production-adjacent).
pub const DEFAULT_TIER2_MAX_STALENESS_TICKS: u64 = 100_000;

/// Maximum staleness in ticks for Tier3 (production with external effects).
pub const DEFAULT_TIER3_MAX_STALENESS_TICKS: u64 = 10_000;

/// Maximum staleness in ticks for Tier4 (critical operations).
pub const DEFAULT_TIER4_MAX_STALENESS_TICKS: u64 = 1_000;

/// Domain separator for session-open receipt hashing.
const SESSION_OPEN_RECEIPT_DOMAIN: &[u8] = b"apm2:session_open_receipt:v1\0";

/// Domain separator for session-open request hashing.
const SESSION_OPEN_REQUEST_DOMAIN: &[u8] = b"apm2:session_open_request:v1\0";

/// Domain separator for session-open response hashing.
const SESSION_OPEN_RESPONSE_DOMAIN: &[u8] = b"apm2:session_open_response:v1\0";

// =============================================================================
// Error Types
// =============================================================================

/// Errors during session-open identity proof validation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SessionIdentityError {
    /// Holon ID hash is missing (all zeros).
    #[error("holon ID hash is missing")]
    MissingHolonId,

    /// Identity proof is stale for the requested risk tier.
    #[error(
        "identity proof stale: age_ticks {age_ticks} exceeds max_staleness_ticks {max_staleness_ticks} for {risk_tier:?}"
    )]
    ProofStale {
        /// Computed age in ticks.
        age_ticks: u64,
        /// Maximum allowed staleness in ticks.
        max_staleness_ticks: u64,
        /// Risk tier that triggered the denial.
        risk_tier: RiskTier,
    },

    /// Identity proof is missing and the risk tier requires one.
    #[error("identity proof required for {risk_tier:?} authority but not provided")]
    ProofRequired {
        /// Risk tier that requires proof.
        risk_tier: RiskTier,
    },

    /// Cell certificate hash is missing in the daemon response.
    #[error("cell certificate hash is missing in daemon response")]
    MissingCellCertificateHash,

    /// Directory head hash is missing in the daemon response.
    #[error("directory head hash is missing in daemon response")]
    MissingDirectoryHeadHash,

    /// Current tick is before proof generation tick (time reversal).
    #[error("current tick {current_tick} predates proof generation tick {proof_generated_at_tick}")]
    TickReversal {
        /// Current tick.
        current_tick: u64,
        /// Proof generation tick.
        proof_generated_at_tick: u64,
    },

    /// Freshness threshold is zero for an authoritative tier (Tier2+).
    ///
    /// A zero threshold means "no freshness check" which violates
    /// fail-closed semantics for authoritative tiers.
    #[error("freshness threshold must be > 0 for authoritative tier {risk_tier:?}")]
    ZeroThresholdForAuthoritativeTier {
        /// The risk tier with the invalid threshold.
        risk_tier: RiskTier,
    },

    /// Freshness witness is missing for an authoritative (Tier2+)
    /// non-denied response.
    #[error("freshness witness is required for non-denied {risk_tier:?} response")]
    MissingFreshnessWitness {
        /// The risk tier that required a freshness witness.
        risk_tier: RiskTier,
    },

    /// Freshness witness is the zero hash for an authoritative (Tier2+)
    /// non-denied response.
    #[error("freshness witness must be non-zero for non-denied {risk_tier:?} response")]
    ZeroFreshnessWitness {
        /// The risk tier that required a non-zero freshness witness.
        risk_tier: RiskTier,
    },

    /// Policy pointer is missing for an authoritative (Tier2+)
    /// non-denied response.
    #[error("policy pointer is required for non-denied {risk_tier:?} response")]
    MissingPolicyPointer {
        /// The risk tier that required a policy pointer.
        risk_tier: RiskTier,
    },

    /// Policy pointer is the zero hash for an authoritative (Tier2+)
    /// non-denied response.
    #[error("policy pointer must be non-zero for non-denied {risk_tier:?} response")]
    ZeroPolicyPointer {
        /// The risk tier that required a non-zero policy pointer.
        risk_tier: RiskTier,
    },

    /// Response construction failed; receipt forced to denied.
    #[error("response construction failed: {reason}")]
    ResponseConstructionFailed {
        /// Human-readable reason for the failure.
        reason: String,
    },
}

// =============================================================================
// Freshness Policy
// =============================================================================

/// Risk-tier-specific staleness thresholds for identity proof freshness.
///
/// A threshold of `0` means "no freshness enforcement" for that tier (the
/// proof is always accepted regardless of age). This is only appropriate
/// for discovery-only surfaces (Tier0).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FreshnessPolicy {
    /// Maximum staleness in ticks per risk tier, indexed by tier ordinal.
    /// Index 0 = Tier0, ..., index 4 = Tier4.
    thresholds: [u64; 5],

    /// Whether to allow degraded (proof-absent) operation for Tier0/Tier1.
    /// When true, Tier0 and Tier1 sessions may proceed without a proof.
    /// Tier2+ always requires a valid, fresh proof.
    allow_degraded_discovery: bool,
}

impl Default for FreshnessPolicy {
    fn default() -> Self {
        Self {
            thresholds: [
                DEFAULT_TIER0_MAX_STALENESS_TICKS,
                DEFAULT_TIER1_MAX_STALENESS_TICKS,
                DEFAULT_TIER2_MAX_STALENESS_TICKS,
                DEFAULT_TIER3_MAX_STALENESS_TICKS,
                DEFAULT_TIER4_MAX_STALENESS_TICKS,
            ],
            allow_degraded_discovery: true,
        }
    }
}

impl FreshnessPolicy {
    /// Creates a new freshness policy with explicit thresholds.
    ///
    /// # Errors
    ///
    /// Returns [`SessionIdentityError::ZeroThresholdForAuthoritativeTier`]
    /// if any Tier2+ threshold is zero. A zero threshold would disable
    /// freshness enforcement, violating fail-closed semantics.
    pub fn new(
        thresholds: [u64; 5],
        allow_degraded_discovery: bool,
    ) -> Result<Self, SessionIdentityError> {
        // Tier2 = index 2, Tier3 = index 3, Tier4 = index 4.
        let authoritative_tiers = [
            (2, RiskTier::Tier2),
            (3, RiskTier::Tier3),
            (4, RiskTier::Tier4),
        ];
        for (idx, tier) in authoritative_tiers {
            if thresholds[idx] == 0 {
                return Err(SessionIdentityError::ZeroThresholdForAuthoritativeTier {
                    risk_tier: tier,
                });
            }
        }
        Ok(Self {
            thresholds,
            allow_degraded_discovery,
        })
    }

    /// Returns the maximum staleness in ticks for the given risk tier.
    ///
    /// A return value of `0` means no staleness enforcement.
    #[must_use]
    pub const fn max_staleness_ticks(&self, tier: RiskTier) -> u64 {
        self.thresholds[tier as usize]
    }

    /// Returns whether degraded (proof-absent) discovery is allowed.
    #[must_use]
    pub const fn allow_degraded_discovery(&self) -> bool {
        self.allow_degraded_discovery
    }

    /// Returns true if the given risk tier is considered "authoritative"
    /// (Tier2+) and therefore requires strict freshness enforcement.
    #[must_use]
    pub const fn is_authoritative_tier(tier: RiskTier) -> bool {
        (tier as u8) >= 2
    }
}

// =============================================================================
// Session Open Request
// =============================================================================

/// Client-to-daemon session-open request carrying identity proof bindings.
///
/// The request MUST include a non-zero `holon_id` and `identity_proof_hash`.
/// For discovery-only sessions under degraded policy, the
/// `identity_proof_hash` MAY be zero (all bytes 0x00).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionOpenRequest {
    /// Hash of the holon identity (derived from `HolonIdV1`).
    holon_id: Hash,

    /// Hash of the identity proof artifact (`IdentityProofV1`).
    /// All-zeros indicates "no proof provided" (degraded mode).
    identity_proof_hash: Hash,

    /// Tick at which the identity proof was generated.
    /// Zero when no proof is provided.
    proof_generated_at_tick: u64,

    /// Requested risk tier for the session.
    risk_tier: RiskTier,
}

impl SessionOpenRequest {
    /// Creates a new session-open request.
    ///
    /// # Errors
    ///
    /// Returns [`SessionIdentityError::MissingHolonId`] if `holon_id` is
    /// all zeros.
    pub fn new(
        holon_id: Hash,
        identity_proof_hash: Hash,
        proof_generated_at_tick: u64,
        risk_tier: RiskTier,
    ) -> Result<Self, SessionIdentityError> {
        if holon_id == [0u8; HASH_SIZE] {
            return Err(SessionIdentityError::MissingHolonId);
        }
        Ok(Self {
            holon_id,
            identity_proof_hash,
            proof_generated_at_tick,
            risk_tier,
        })
    }

    /// Returns the holon ID hash.
    #[must_use]
    pub const fn holon_id(&self) -> &Hash {
        &self.holon_id
    }

    /// Returns the identity proof hash.
    #[must_use]
    pub const fn identity_proof_hash(&self) -> &Hash {
        &self.identity_proof_hash
    }

    /// Returns the proof generation tick.
    #[must_use]
    pub const fn proof_generated_at_tick(&self) -> u64 {
        self.proof_generated_at_tick
    }

    /// Returns the requested risk tier.
    #[must_use]
    pub const fn risk_tier(&self) -> RiskTier {
        self.risk_tier
    }

    /// Returns true if an identity proof is present (non-zero hash).
    #[must_use]
    pub fn has_proof(&self) -> bool {
        self.identity_proof_hash != [0u8; HASH_SIZE]
    }

    /// Computes the canonical hash of this request for receipt binding.
    #[must_use]
    pub fn canonical_hash(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(SESSION_OPEN_REQUEST_DOMAIN);
        hasher.update(&self.holon_id);
        hasher.update(&self.identity_proof_hash);
        hasher.update(&self.proof_generated_at_tick.to_le_bytes());
        hasher.update(&[self.risk_tier as u8]);
        *hasher.finalize().as_bytes()
    }
}

// =============================================================================
// Session Open Response
// =============================================================================

/// Daemon-to-client session-open response carrying authority bindings.
///
/// The response MUST include non-zero `cell_certificate_hash` and
/// `directory_head_hash` for the session authority to be valid.
///
/// For Tier2+ (authoritative) sessions, `freshness_witness` and
/// `policy_pointer` MUST be populated to satisfy bound requirements.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionOpenResponse {
    /// Hash of the cell certificate binding the session authority.
    cell_certificate_hash: Hash,

    /// Hash of the directory head at the time of session open.
    directory_head_hash: Hash,

    /// The freshness decision made by the daemon.
    decision: FreshnessDecision,

    /// Risk tier acknowledged by the daemon.
    risk_tier: RiskTier,

    /// Verifier-side freshness witness hash binding the proof evaluation
    /// to the verifier's observed state. Required for Tier2+ responses.
    freshness_witness: Option<Hash>,

    /// Hash of the freshness policy that was applied. Required for Tier2+
    /// responses so clients can verify which policy governed admission.
    policy_pointer: Option<Hash>,
}

impl SessionOpenResponse {
    /// Creates a new session-open response.
    ///
    /// # Errors
    ///
    /// Returns an error if required hashes are missing for the given
    /// decision. For non-denied responses:
    /// - `cell_certificate_hash` and `directory_head_hash` must be non-zero.
    /// - For Tier2+ (authoritative) tiers, `freshness_witness` and
    ///   `policy_pointer` must be `Some(non-zero-hash)`.
    pub fn new(
        cell_certificate_hash: Hash,
        directory_head_hash: Hash,
        decision: FreshnessDecision,
        risk_tier: RiskTier,
        freshness_witness: Option<Hash>,
        policy_pointer: Option<Hash>,
    ) -> Result<Self, SessionIdentityError> {
        // For non-denied sessions, both certificate hashes must be present.
        if decision != FreshnessDecision::Denied {
            if cell_certificate_hash == [0u8; HASH_SIZE] {
                return Err(SessionIdentityError::MissingCellCertificateHash);
            }
            if directory_head_hash == [0u8; HASH_SIZE] {
                return Err(SessionIdentityError::MissingDirectoryHeadHash);
            }

            // Tier2+ (authoritative) non-denied responses require both
            // freshness_witness and policy_pointer with non-zero hashes.
            if FreshnessPolicy::is_authoritative_tier(risk_tier) {
                match freshness_witness {
                    None => {
                        return Err(SessionIdentityError::MissingFreshnessWitness { risk_tier });
                    },
                    Some(h) if h == [0u8; HASH_SIZE] => {
                        return Err(SessionIdentityError::ZeroFreshnessWitness { risk_tier });
                    },
                    _ => {},
                }
                match policy_pointer {
                    None => {
                        return Err(SessionIdentityError::MissingPolicyPointer { risk_tier });
                    },
                    Some(h) if h == [0u8; HASH_SIZE] => {
                        return Err(SessionIdentityError::ZeroPolicyPointer { risk_tier });
                    },
                    _ => {},
                }
            }
        }
        Ok(Self {
            cell_certificate_hash,
            directory_head_hash,
            decision,
            risk_tier,
            freshness_witness,
            policy_pointer,
        })
    }

    /// Returns the cell certificate hash.
    #[must_use]
    pub const fn cell_certificate_hash(&self) -> &Hash {
        &self.cell_certificate_hash
    }

    /// Returns the directory head hash.
    #[must_use]
    pub const fn directory_head_hash(&self) -> &Hash {
        &self.directory_head_hash
    }

    /// Returns the freshness decision.
    #[must_use]
    pub const fn decision(&self) -> FreshnessDecision {
        self.decision
    }

    /// Returns the risk tier.
    #[must_use]
    pub const fn risk_tier(&self) -> RiskTier {
        self.risk_tier
    }

    /// Returns the freshness witness hash, if present.
    #[must_use]
    pub const fn freshness_witness(&self) -> Option<&Hash> {
        self.freshness_witness.as_ref()
    }

    /// Returns the policy pointer hash, if present.
    #[must_use]
    pub const fn policy_pointer(&self) -> Option<&Hash> {
        self.policy_pointer.as_ref()
    }

    /// Computes the canonical hash of this response for receipt binding.
    #[must_use]
    pub fn canonical_hash(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(SESSION_OPEN_RESPONSE_DOMAIN);
        hasher.update(&self.cell_certificate_hash);
        hasher.update(&self.directory_head_hash);
        hasher.update(&[self.decision as u8]);
        hasher.update(&[self.risk_tier as u8]);
        match &self.freshness_witness {
            Some(h) => {
                hasher.update(&[0x01]);
                hasher.update(h);
            },
            None => {
                hasher.update(&[0x00]);
            },
        }
        match &self.policy_pointer {
            Some(h) => {
                hasher.update(&[0x01]);
                hasher.update(h);
            },
            None => {
                hasher.update(&[0x00]);
            },
        }
        *hasher.finalize().as_bytes()
    }
}

// =============================================================================
// Freshness Decision
// =============================================================================

/// Outcome of freshness evaluation for a session-open request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FreshnessDecision {
    /// Proof is fresh; full authority granted.
    Admitted = 0,
    /// Proof is absent or stale but discovery-only access is allowed
    /// under degraded policy (Tier0/Tier1 only).
    Degraded = 1,
    /// Proof is stale or missing; session denied.
    Denied   = 2,
}

// =============================================================================
// Freshness Evaluator
// =============================================================================

/// Evaluates identity proof freshness against a configured policy.
///
/// This is the core enforcement logic for TCK-00361. It is deterministic
/// and side-effect-free; defect/receipt emission is handled by the caller
/// using the returned [`FreshnessOutcome`].
#[derive(Debug, Clone)]
pub struct FreshnessEvaluator {
    policy: FreshnessPolicy,
}

/// Result of freshness evaluation with all data needed for
/// defect emission and receipt instrumentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FreshnessOutcome {
    /// The freshness decision.
    pub decision: FreshnessDecision,
    /// Risk tier evaluated.
    pub risk_tier: RiskTier,
    /// Proof age in ticks (None if no proof or tick reversal).
    pub age_ticks: Option<u64>,
    /// Configured threshold for the risk tier.
    pub max_staleness_ticks: u64,
    /// Whether a defect should be emitted.
    pub defect: Option<SessionIdentityDefect>,
}

impl FreshnessEvaluator {
    /// Creates a new evaluator with the given policy.
    #[must_use]
    pub const fn new(policy: FreshnessPolicy) -> Self {
        Self { policy }
    }

    /// Returns a reference to the policy.
    #[must_use]
    pub const fn policy(&self) -> &FreshnessPolicy {
        &self.policy
    }

    /// Evaluates freshness for a session-open request.
    ///
    /// # Arguments
    ///
    /// * `request` - The session-open request to evaluate.
    /// * `current_tick` - The current authoritative tick from the verifier.
    /// * `verifier_observed_tick` - Verifier-side tick at which the proof was
    ///   first observed or validated. This MUST come from verifier-bound data,
    ///   NOT from the request. Freshness age is computed as `current_tick -
    ///   verifier_observed_tick` to prevent clients from claiming an
    ///   artificially recent generation time.
    ///
    /// # Returns
    ///
    /// A [`FreshnessOutcome`] describing the decision and any defect to emit.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn evaluate(
        &self,
        request: &SessionOpenRequest,
        current_tick: u64,
        verifier_observed_tick: u64,
    ) -> FreshnessOutcome {
        let risk_tier = request.risk_tier();
        let max_staleness = self.policy.max_staleness_ticks(risk_tier);
        let is_authoritative = FreshnessPolicy::is_authoritative_tier(risk_tier);

        // Case 1: No proof provided.
        if !request.has_proof() {
            return if is_authoritative {
                // Tier2+: always deny missing proof.
                FreshnessOutcome {
                    decision: FreshnessDecision::Denied,
                    risk_tier,
                    age_ticks: None,
                    max_staleness_ticks: max_staleness,
                    defect: Some(SessionIdentityDefect::MissingProof { risk_tier }),
                }
            } else if self.policy.allow_degraded_discovery() {
                // Tier0/Tier1: allow degraded if configured.
                FreshnessOutcome {
                    decision: FreshnessDecision::Degraded,
                    risk_tier,
                    age_ticks: None,
                    max_staleness_ticks: max_staleness,
                    defect: Some(SessionIdentityDefect::MissingProofDegraded { risk_tier }),
                }
            } else {
                // Even Tier0/Tier1 denied when degraded not allowed.
                FreshnessOutcome {
                    decision: FreshnessDecision::Denied,
                    risk_tier,
                    age_ticks: None,
                    max_staleness_ticks: max_staleness,
                    defect: Some(SessionIdentityDefect::MissingProof { risk_tier }),
                }
            };
        }

        // Case 2: Tick reversal (current < verifier observed).
        if current_tick < verifier_observed_tick {
            return FreshnessOutcome {
                decision: FreshnessDecision::Denied,
                risk_tier,
                age_ticks: None,
                max_staleness_ticks: max_staleness,
                defect: Some(SessionIdentityDefect::TickReversal {
                    risk_tier,
                    current_tick,
                    proof_generated_at_tick: verifier_observed_tick,
                }),
            };
        }

        // Use verifier-side timestamp for age computation, not the
        // client-provided proof_generated_at_tick. This prevents a
        // client from claiming an artificially recent generation time.
        let age_ticks = current_tick - verifier_observed_tick;

        // Case 3: No staleness enforcement for this tier (threshold == 0).
        // This is only reachable for Tier0/Tier1; FreshnessPolicy::new rejects
        // threshold=0 for Tier2+ to enforce fail-closed semantics.
        if max_staleness == 0 {
            debug_assert!(
                !is_authoritative,
                "threshold=0 should be rejected at construction for Tier2+"
            );
            return FreshnessOutcome {
                decision: FreshnessDecision::Admitted,
                risk_tier,
                age_ticks: Some(age_ticks),
                max_staleness_ticks: 0,
                defect: None,
            };
        }

        // Case 4: Proof is fresh enough.
        if age_ticks <= max_staleness {
            return FreshnessOutcome {
                decision: FreshnessDecision::Admitted,
                risk_tier,
                age_ticks: Some(age_ticks),
                max_staleness_ticks: max_staleness,
                defect: None,
            };
        }

        // Case 5: Proof is stale.
        if is_authoritative {
            // Tier2+: deny stale proof.
            FreshnessOutcome {
                decision: FreshnessDecision::Denied,
                risk_tier,
                age_ticks: Some(age_ticks),
                max_staleness_ticks: max_staleness,
                defect: Some(SessionIdentityDefect::StaleProof {
                    risk_tier,
                    age_ticks,
                    max_staleness_ticks: max_staleness,
                }),
            }
        } else if self.policy.allow_degraded_discovery() {
            // Tier0/Tier1: allow degraded.
            FreshnessOutcome {
                decision: FreshnessDecision::Degraded,
                risk_tier,
                age_ticks: Some(age_ticks),
                max_staleness_ticks: max_staleness,
                defect: Some(SessionIdentityDefect::StaleProofDegraded {
                    risk_tier,
                    age_ticks,
                    max_staleness_ticks: max_staleness,
                }),
            }
        } else {
            FreshnessOutcome {
                decision: FreshnessDecision::Denied,
                risk_tier,
                age_ticks: Some(age_ticks),
                max_staleness_ticks: max_staleness,
                defect: Some(SessionIdentityDefect::StaleProof {
                    risk_tier,
                    age_ticks,
                    max_staleness_ticks: max_staleness,
                }),
            }
        }
    }
}

// =============================================================================
// Defect Types
// =============================================================================

/// Defect events emitted during session-open identity proof validation.
///
/// These are structured for deterministic audit trail emission.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SessionIdentityDefect {
    /// Identity proof is missing for an authoritative (Tier2+) session.
    MissingProof {
        /// Risk tier that required the proof.
        risk_tier: RiskTier,
    },

    /// Identity proof is missing for a discovery-only session under
    /// degraded policy.
    MissingProofDegraded {
        /// Risk tier of the session.
        risk_tier: RiskTier,
    },

    /// Identity proof is stale for an authoritative (Tier2+) session.
    StaleProof {
        /// Risk tier that triggered the denial.
        risk_tier: RiskTier,
        /// Computed proof age in ticks.
        age_ticks: u64,
        /// Configured maximum staleness threshold.
        max_staleness_ticks: u64,
    },

    /// Identity proof is stale for a discovery-only session under
    /// degraded policy.
    StaleProofDegraded {
        /// Risk tier of the session.
        risk_tier: RiskTier,
        /// Computed proof age in ticks.
        age_ticks: u64,
        /// Configured maximum staleness threshold.
        max_staleness_ticks: u64,
    },

    /// Tick reversal detected: current tick predates proof generation.
    TickReversal {
        /// Risk tier of the session.
        risk_tier: RiskTier,
        /// Current tick.
        current_tick: u64,
        /// Proof generation tick.
        proof_generated_at_tick: u64,
    },
}

impl SessionIdentityDefect {
    /// Returns a static defect kind label for structured logging.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::MissingProof { .. } => "session_identity.missing_proof",
            Self::MissingProofDegraded { .. } => "session_identity.missing_proof_degraded",
            Self::StaleProof { .. } => "session_identity.stale_proof",
            Self::StaleProofDegraded { .. } => "session_identity.stale_proof_degraded",
            Self::TickReversal { .. } => "session_identity.tick_reversal",
        }
    }

    /// Returns the risk tier associated with this defect.
    #[must_use]
    pub const fn risk_tier(&self) -> RiskTier {
        match self {
            Self::MissingProof { risk_tier }
            | Self::MissingProofDegraded { risk_tier }
            | Self::StaleProof { risk_tier, .. }
            | Self::StaleProofDegraded { risk_tier, .. }
            | Self::TickReversal { risk_tier, .. } => *risk_tier,
        }
    }
}

// =============================================================================
// Session Open Receipt
// =============================================================================

/// Receipt emitted for every session-open decision (admit/degrade/deny).
///
/// The receipt provides a deterministic, CAS-addressable audit record
/// binding the request, response, and freshness evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionOpenReceipt {
    /// Canonical hash of the session-open request.
    request_hash: Hash,

    /// Canonical hash of the session-open response (zeros if denied
    /// before response construction).
    response_hash: Hash,

    /// The freshness decision.
    decision: FreshnessDecision,

    /// Risk tier of the session.
    risk_tier: RiskTier,

    /// Proof age in ticks (None if no proof provided).
    age_ticks: Option<u64>,

    /// Configured staleness threshold for this tier.
    max_staleness_ticks: u64,

    /// Current tick at evaluation time.
    evaluated_at_tick: u64,
}

impl SessionOpenReceipt {
    /// Creates a receipt from a request, an optional response, and
    /// a freshness outcome.
    #[must_use]
    pub fn from_outcome(
        request: &SessionOpenRequest,
        response: Option<&SessionOpenResponse>,
        outcome: &FreshnessOutcome,
        evaluated_at_tick: u64,
    ) -> Self {
        Self {
            request_hash: request.canonical_hash(),
            response_hash: response.map_or([0u8; HASH_SIZE], SessionOpenResponse::canonical_hash),
            decision: outcome.decision,
            risk_tier: outcome.risk_tier,
            age_ticks: outcome.age_ticks,
            max_staleness_ticks: outcome.max_staleness_ticks,
            evaluated_at_tick,
        }
    }

    /// Returns the request hash.
    #[must_use]
    pub const fn request_hash(&self) -> &Hash {
        &self.request_hash
    }

    /// Returns the response hash.
    #[must_use]
    pub const fn response_hash(&self) -> &Hash {
        &self.response_hash
    }

    /// Returns the freshness decision.
    #[must_use]
    pub const fn decision(&self) -> FreshnessDecision {
        self.decision
    }

    /// Returns the risk tier.
    #[must_use]
    pub const fn risk_tier(&self) -> RiskTier {
        self.risk_tier
    }

    /// Returns the proof age in ticks.
    #[must_use]
    pub const fn age_ticks(&self) -> Option<u64> {
        self.age_ticks
    }

    /// Returns the configured staleness threshold.
    #[must_use]
    pub const fn max_staleness_ticks(&self) -> u64 {
        self.max_staleness_ticks
    }

    /// Returns the evaluation tick.
    #[must_use]
    pub const fn evaluated_at_tick(&self) -> u64 {
        self.evaluated_at_tick
    }

    /// Computes the canonical hash of this receipt for CAS storage.
    #[must_use]
    pub fn canonical_hash(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(SESSION_OPEN_RECEIPT_DOMAIN);
        hasher.update(&self.request_hash);
        hasher.update(&self.response_hash);
        hasher.update(&[self.decision as u8]);
        hasher.update(&[self.risk_tier as u8]);
        match self.age_ticks {
            Some(age) => {
                hasher.update(&[0x01]);
                hasher.update(&age.to_le_bytes());
            },
            None => {
                hasher.update(&[0x00]);
            },
        }
        hasher.update(&self.max_staleness_ticks.to_le_bytes());
        hasher.update(&self.evaluated_at_tick.to_le_bytes());
        *hasher.finalize().as_bytes()
    }
}

// =============================================================================
// Top-Level Session Open Handler
// =============================================================================

/// Result of [`process_session_open`] including the response, receipt,
/// and any defects emitted during evaluation.
#[derive(Debug, Clone)]
pub struct SessionOpenResult {
    /// The response outcome: `Ok` on admit/degrade, `Err` on deny.
    pub response: Result<SessionOpenResponse, SessionIdentityError>,
    /// Audit receipt binding the request, response, and freshness decision.
    pub receipt: SessionOpenReceipt,
    /// Defects emitted during freshness evaluation (stale/missing proofs,
    /// tick reversals, etc.). Empty when the proof is valid and fresh.
    pub defects: Vec<SessionIdentityDefect>,
}

/// Processes a session-open request against a freshness policy.
///
/// This is the primary entry point for session-open identity enforcement.
/// It evaluates the request, constructs the response (or denial), emits
/// a receipt, and returns the outcome including any defects.
///
/// # Arguments
///
/// * `evaluator` - The freshness evaluator with configured policy.
/// * `request` - The session-open request.
/// * `current_tick` - Authoritative current tick from the verifier.
/// * `verifier_observed_tick` - Verifier-side tick at which the proof was first
///   observed. MUST NOT come from the request.
/// * `cell_certificate_hash` - Cell certificate hash from the daemon.
/// * `directory_head_hash` - Directory head hash from the daemon.
/// * `freshness_witness` - Verifier freshness witness hash (required for
///   Tier2+).
/// * `policy_pointer` - Hash of the applied freshness policy (required for
///   Tier2+).
///
/// # Returns
///
/// A [`SessionOpenResult`] containing the response, receipt, and defects.
///
/// # Integration
///
/// TODO: Daemon wiring is a separate integration task. The daemon's
/// session-open flow must call this function with verifier-local tick
/// and proof-observation data. See RFC-0020 for the integration path.
#[must_use]
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub fn process_session_open(
    evaluator: &FreshnessEvaluator,
    request: &SessionOpenRequest,
    current_tick: u64,
    verifier_observed_tick: u64,
    cell_certificate_hash: Hash,
    directory_head_hash: Hash,
    freshness_witness: Option<Hash>,
    policy_pointer: Option<Hash>,
) -> SessionOpenResult {
    let outcome = evaluator.evaluate(request, current_tick, verifier_observed_tick);
    let defects: Vec<SessionIdentityDefect> = outcome.defect.clone().into_iter().collect();

    match outcome.decision {
        FreshnessDecision::Admitted | FreshnessDecision::Degraded => {
            match SessionOpenResponse::new(
                cell_certificate_hash,
                directory_head_hash,
                outcome.decision,
                request.risk_tier(),
                freshness_witness,
                policy_pointer,
            ) {
                Ok(response) => {
                    let receipt = SessionOpenReceipt::from_outcome(
                        request,
                        Some(&response),
                        &outcome,
                        current_tick,
                    );
                    SessionOpenResult {
                        response: Ok(response),
                        receipt,
                        defects,
                    }
                },
                Err(e) => {
                    // Response construction failed — force receipt to Denied.
                    // Fail-closed: never emit a success-class receipt when
                    // the response could not be constructed.
                    let denied_outcome = FreshnessOutcome {
                        decision: FreshnessDecision::Denied,
                        risk_tier: outcome.risk_tier,
                        age_ticks: outcome.age_ticks,
                        max_staleness_ticks: outcome.max_staleness_ticks,
                        defect: outcome.defect,
                    };
                    let receipt = SessionOpenReceipt::from_outcome(
                        request,
                        None,
                        &denied_outcome,
                        current_tick,
                    );
                    SessionOpenResult {
                        response: Err(e),
                        receipt,
                        defects,
                    }
                },
            }
        },
        FreshnessDecision::Denied => {
            let receipt = SessionOpenReceipt::from_outcome(request, None, &outcome, current_tick);
            let error = if !request.has_proof() {
                SessionIdentityError::ProofRequired {
                    risk_tier: request.risk_tier(),
                }
            } else if current_tick < verifier_observed_tick {
                SessionIdentityError::TickReversal {
                    current_tick,
                    proof_generated_at_tick: verifier_observed_tick,
                }
            } else {
                let age_ticks = current_tick - verifier_observed_tick;
                SessionIdentityError::ProofStale {
                    age_ticks,
                    max_staleness_ticks: evaluator
                        .policy()
                        .max_staleness_ticks(request.risk_tier()),
                    risk_tier: request.risk_tier(),
                }
            };
            SessionOpenResult {
                response: Err(error),
                receipt,
                defects,
            }
        },
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn zero_hash() -> Hash {
        [0u8; HASH_SIZE]
    }

    fn test_hash(seed: u8) -> Hash {
        [seed; HASH_SIZE]
    }

    fn default_evaluator() -> FreshnessEvaluator {
        FreshnessEvaluator::new(FreshnessPolicy::default())
    }

    fn strict_evaluator() -> FreshnessEvaluator {
        FreshnessEvaluator::new(
            FreshnessPolicy::new([0, 1_000_000, 100_000, 10_000, 1_000], false).unwrap(),
        )
    }

    // =========================================================================
    // SessionOpenRequest Tests
    // =========================================================================

    #[test]
    fn request_rejects_zero_holon_id() {
        let result = SessionOpenRequest::new(zero_hash(), test_hash(0xAA), 100, RiskTier::Tier0);
        assert_eq!(result.unwrap_err(), SessionIdentityError::MissingHolonId);
    }

    #[test]
    fn request_accepts_valid_holon_id() {
        let req = SessionOpenRequest::new(test_hash(0x01), test_hash(0x02), 100, RiskTier::Tier2)
            .unwrap();
        assert_eq!(req.holon_id(), &test_hash(0x01));
        assert_eq!(req.identity_proof_hash(), &test_hash(0x02));
        assert_eq!(req.proof_generated_at_tick(), 100);
        assert_eq!(req.risk_tier(), RiskTier::Tier2);
        assert!(req.has_proof());
    }

    #[test]
    fn request_allows_zero_proof_hash() {
        let req =
            SessionOpenRequest::new(test_hash(0x01), zero_hash(), 0, RiskTier::Tier0).unwrap();
        assert!(!req.has_proof());
    }

    #[test]
    fn request_canonical_hash_is_deterministic() {
        let req1 = SessionOpenRequest::new(test_hash(0x01), test_hash(0x02), 100, RiskTier::Tier2)
            .unwrap();
        let req2 = SessionOpenRequest::new(test_hash(0x01), test_hash(0x02), 100, RiskTier::Tier2)
            .unwrap();
        assert_eq!(req1.canonical_hash(), req2.canonical_hash());
    }

    #[test]
    fn request_canonical_hash_differs_on_tier() {
        let req1 = SessionOpenRequest::new(test_hash(0x01), test_hash(0x02), 100, RiskTier::Tier0)
            .unwrap();
        let req2 = SessionOpenRequest::new(test_hash(0x01), test_hash(0x02), 100, RiskTier::Tier3)
            .unwrap();
        assert_ne!(req1.canonical_hash(), req2.canonical_hash());
    }

    // =========================================================================
    // SessionOpenResponse Tests
    // =========================================================================

    #[test]
    fn response_rejects_zero_cell_cert_when_admitted() {
        // Use Tier0 to isolate the cell-cert check from Tier2+ witness/policy checks.
        let result = SessionOpenResponse::new(
            zero_hash(),
            test_hash(0x02),
            FreshnessDecision::Admitted,
            RiskTier::Tier0,
            None,
            None,
        );
        assert_eq!(
            result.unwrap_err(),
            SessionIdentityError::MissingCellCertificateHash
        );
    }

    #[test]
    fn response_rejects_zero_cell_cert_when_admitted_tier2() {
        // Tier2 with valid witness/policy still rejects zero cell cert.
        let result = SessionOpenResponse::new(
            zero_hash(),
            test_hash(0x02),
            FreshnessDecision::Admitted,
            RiskTier::Tier2,
            Some(test_hash(0xCC)),
            Some(test_hash(0xDD)),
        );
        assert_eq!(
            result.unwrap_err(),
            SessionIdentityError::MissingCellCertificateHash
        );
    }

    #[test]
    fn response_rejects_zero_dir_head_when_admitted() {
        // Use Tier0 to isolate the dir-head check from Tier2+ witness/policy checks.
        let result = SessionOpenResponse::new(
            test_hash(0x01),
            zero_hash(),
            FreshnessDecision::Admitted,
            RiskTier::Tier0,
            None,
            None,
        );
        assert_eq!(
            result.unwrap_err(),
            SessionIdentityError::MissingDirectoryHeadHash
        );
    }

    #[test]
    fn response_rejects_zero_dir_head_when_admitted_tier2() {
        // Tier2 with valid witness/policy still rejects zero dir head.
        let result = SessionOpenResponse::new(
            test_hash(0x01),
            zero_hash(),
            FreshnessDecision::Admitted,
            RiskTier::Tier2,
            Some(test_hash(0xCC)),
            Some(test_hash(0xDD)),
        );
        assert_eq!(
            result.unwrap_err(),
            SessionIdentityError::MissingDirectoryHeadHash
        );
    }

    #[test]
    fn response_allows_zero_hashes_when_denied() {
        let resp = SessionOpenResponse::new(
            zero_hash(),
            zero_hash(),
            FreshnessDecision::Denied,
            RiskTier::Tier3,
            None,
            None,
        )
        .unwrap();
        assert_eq!(resp.decision(), FreshnessDecision::Denied);
    }

    #[test]
    fn response_canonical_hash_is_deterministic() {
        let r1 = SessionOpenResponse::new(
            test_hash(0x01),
            test_hash(0x02),
            FreshnessDecision::Admitted,
            RiskTier::Tier2,
            Some(test_hash(0xCC)),
            Some(test_hash(0xDD)),
        )
        .unwrap();
        let r2 = SessionOpenResponse::new(
            test_hash(0x01),
            test_hash(0x02),
            FreshnessDecision::Admitted,
            RiskTier::Tier2,
            Some(test_hash(0xCC)),
            Some(test_hash(0xDD)),
        )
        .unwrap();
        assert_eq!(r1.canonical_hash(), r2.canonical_hash());
    }

    #[test]
    fn response_freshness_witness_and_policy_pointer_accessors() {
        let resp = SessionOpenResponse::new(
            test_hash(0x01),
            test_hash(0x02),
            FreshnessDecision::Admitted,
            RiskTier::Tier2,
            Some(test_hash(0xCC)),
            Some(test_hash(0xDD)),
        )
        .unwrap();
        assert_eq!(resp.freshness_witness(), Some(&test_hash(0xCC)));
        assert_eq!(resp.policy_pointer(), Some(&test_hash(0xDD)));
    }

    #[test]
    fn response_canonical_hash_differs_with_witness() {
        // Use Tier0 (non-authoritative) to compare responses with/without witness
        // since Tier2+ now requires witness + policy for non-denied.
        let r1 = SessionOpenResponse::new(
            test_hash(0x01),
            test_hash(0x02),
            FreshnessDecision::Admitted,
            RiskTier::Tier0,
            None,
            None,
        )
        .unwrap();
        let r2 = SessionOpenResponse::new(
            test_hash(0x01),
            test_hash(0x02),
            FreshnessDecision::Admitted,
            RiskTier::Tier0,
            Some(test_hash(0xCC)),
            None,
        )
        .unwrap();
        assert_ne!(r1.canonical_hash(), r2.canonical_hash());
    }

    // =========================================================================
    // FreshnessPolicy Tests
    // =========================================================================

    #[test]
    fn default_policy_thresholds() {
        let policy = FreshnessPolicy::default();
        assert_eq!(
            policy.max_staleness_ticks(RiskTier::Tier0),
            DEFAULT_TIER0_MAX_STALENESS_TICKS
        );
        assert_eq!(
            policy.max_staleness_ticks(RiskTier::Tier1),
            DEFAULT_TIER1_MAX_STALENESS_TICKS
        );
        assert_eq!(
            policy.max_staleness_ticks(RiskTier::Tier2),
            DEFAULT_TIER2_MAX_STALENESS_TICKS
        );
        assert_eq!(
            policy.max_staleness_ticks(RiskTier::Tier3),
            DEFAULT_TIER3_MAX_STALENESS_TICKS
        );
        assert_eq!(
            policy.max_staleness_ticks(RiskTier::Tier4),
            DEFAULT_TIER4_MAX_STALENESS_TICKS
        );
        assert!(policy.allow_degraded_discovery());
    }

    #[test]
    fn is_authoritative_tier() {
        assert!(!FreshnessPolicy::is_authoritative_tier(RiskTier::Tier0));
        assert!(!FreshnessPolicy::is_authoritative_tier(RiskTier::Tier1));
        assert!(FreshnessPolicy::is_authoritative_tier(RiskTier::Tier2));
        assert!(FreshnessPolicy::is_authoritative_tier(RiskTier::Tier3));
        assert!(FreshnessPolicy::is_authoritative_tier(RiskTier::Tier4));
    }

    #[test]
    fn policy_rejects_zero_threshold_for_tier2() {
        let result = FreshnessPolicy::new([0, 1_000, 0, 10_000, 1_000], true);
        assert_eq!(
            result.unwrap_err(),
            SessionIdentityError::ZeroThresholdForAuthoritativeTier {
                risk_tier: RiskTier::Tier2,
            }
        );
    }

    #[test]
    fn policy_rejects_zero_threshold_for_tier3() {
        let result = FreshnessPolicy::new([0, 1_000, 100_000, 0, 1_000], true);
        assert_eq!(
            result.unwrap_err(),
            SessionIdentityError::ZeroThresholdForAuthoritativeTier {
                risk_tier: RiskTier::Tier3,
            }
        );
    }

    #[test]
    fn policy_rejects_zero_threshold_for_tier4() {
        let result = FreshnessPolicy::new([0, 1_000, 100_000, 10_000, 0], true);
        assert_eq!(
            result.unwrap_err(),
            SessionIdentityError::ZeroThresholdForAuthoritativeTier {
                risk_tier: RiskTier::Tier4,
            }
        );
    }

    #[test]
    fn policy_allows_zero_threshold_for_tier0_tier1() {
        let policy = FreshnessPolicy::new([0, 0, 100_000, 10_000, 1_000], true).unwrap();
        assert_eq!(policy.max_staleness_ticks(RiskTier::Tier0), 0);
        assert_eq!(policy.max_staleness_ticks(RiskTier::Tier1), 0);
    }

    // =========================================================================
    // FreshnessEvaluator: Tier0 Tests
    // =========================================================================

    #[test]
    fn tier0_fresh_proof_admitted() {
        let eval = default_evaluator();
        let req = SessionOpenRequest::new(test_hash(0x01), test_hash(0x02), 100, RiskTier::Tier0)
            .unwrap();
        // verifier_observed_tick = 100 (same as client claim), current = 200
        let outcome = eval.evaluate(&req, 200, 100);
        assert_eq!(outcome.decision, FreshnessDecision::Admitted);
        assert!(outcome.defect.is_none());
    }

    #[test]
    fn tier0_no_proof_degraded_default_policy() {
        let eval = default_evaluator();
        let req =
            SessionOpenRequest::new(test_hash(0x01), zero_hash(), 0, RiskTier::Tier0).unwrap();
        let outcome = eval.evaluate(&req, 200, 0);
        assert_eq!(outcome.decision, FreshnessDecision::Degraded);
        assert!(matches!(
            outcome.defect,
            Some(SessionIdentityDefect::MissingProofDegraded { .. })
        ));
    }

    #[test]
    fn tier0_no_proof_denied_strict_policy() {
        let eval = strict_evaluator();
        let req =
            SessionOpenRequest::new(test_hash(0x01), zero_hash(), 0, RiskTier::Tier0).unwrap();
        let outcome = eval.evaluate(&req, 200, 0);
        assert_eq!(outcome.decision, FreshnessDecision::Denied);
        assert!(matches!(
            outcome.defect,
            Some(SessionIdentityDefect::MissingProof { .. })
        ));
    }

    // =========================================================================
    // FreshnessEvaluator: Tier1 Tests
    // =========================================================================

    #[test]
    fn tier1_fresh_proof_admitted() {
        let eval = default_evaluator();
        let req = SessionOpenRequest::new(test_hash(0x01), test_hash(0x02), 100, RiskTier::Tier1)
            .unwrap();
        let outcome = eval.evaluate(&req, 200, 100);
        assert_eq!(outcome.decision, FreshnessDecision::Admitted);
        assert!(outcome.defect.is_none());
    }

    #[test]
    fn tier1_stale_proof_degraded() {
        let eval = default_evaluator();
        // Verifier observed at tick 0, current at 2_000_000 => age exceeds 1M.
        let req =
            SessionOpenRequest::new(test_hash(0x01), test_hash(0x02), 0, RiskTier::Tier1).unwrap();
        let outcome = eval.evaluate(&req, 2_000_000, 0);
        assert_eq!(outcome.decision, FreshnessDecision::Degraded);
        assert!(matches!(
            outcome.defect,
            Some(SessionIdentityDefect::StaleProofDegraded { .. })
        ));
    }

    #[test]
    fn tier1_no_proof_degraded_default() {
        let eval = default_evaluator();
        let req =
            SessionOpenRequest::new(test_hash(0x01), zero_hash(), 0, RiskTier::Tier1).unwrap();
        let outcome = eval.evaluate(&req, 200, 0);
        assert_eq!(outcome.decision, FreshnessDecision::Degraded);
    }

    // =========================================================================
    // FreshnessEvaluator: Tier2 Tests
    // =========================================================================

    #[test]
    fn tier2_fresh_proof_admitted() {
        let eval = default_evaluator();
        let req = SessionOpenRequest::new(test_hash(0x01), test_hash(0x02), 100, RiskTier::Tier2)
            .unwrap();
        let outcome = eval.evaluate(&req, 200, 100);
        assert_eq!(outcome.decision, FreshnessDecision::Admitted);
        assert_eq!(outcome.age_ticks, Some(100));
        assert!(outcome.defect.is_none());
    }

    #[test]
    fn tier2_stale_proof_denied() {
        let eval = default_evaluator();
        // Verifier observed at 0, current at 200_000 => age 200k > threshold 100k.
        let req =
            SessionOpenRequest::new(test_hash(0x01), test_hash(0x02), 0, RiskTier::Tier2).unwrap();
        let outcome = eval.evaluate(&req, 200_000, 0);
        assert_eq!(outcome.decision, FreshnessDecision::Denied);
        assert!(matches!(
            outcome.defect,
            Some(SessionIdentityDefect::StaleProof {
                risk_tier: RiskTier::Tier2,
                ..
            })
        ));
    }

    #[test]
    fn tier2_no_proof_denied() {
        let eval = default_evaluator();
        let req =
            SessionOpenRequest::new(test_hash(0x01), zero_hash(), 0, RiskTier::Tier2).unwrap();
        let outcome = eval.evaluate(&req, 200, 0);
        assert_eq!(outcome.decision, FreshnessDecision::Denied);
        assert!(matches!(
            outcome.defect,
            Some(SessionIdentityDefect::MissingProof {
                risk_tier: RiskTier::Tier2,
            })
        ));
    }

    #[test]
    fn tier2_boundary_exactly_at_threshold_admitted() {
        let eval = default_evaluator();
        // Verifier observed at 0, current at exactly 100_000 => age == threshold.
        let req =
            SessionOpenRequest::new(test_hash(0x01), test_hash(0x02), 0, RiskTier::Tier2).unwrap();
        let outcome = eval.evaluate(&req, DEFAULT_TIER2_MAX_STALENESS_TICKS, 0);
        assert_eq!(outcome.decision, FreshnessDecision::Admitted);
    }

    #[test]
    fn tier2_boundary_one_past_threshold_denied() {
        let eval = default_evaluator();
        let req =
            SessionOpenRequest::new(test_hash(0x01), test_hash(0x02), 0, RiskTier::Tier2).unwrap();
        let outcome = eval.evaluate(&req, DEFAULT_TIER2_MAX_STALENESS_TICKS + 1, 0);
        assert_eq!(outcome.decision, FreshnessDecision::Denied);
    }

    #[test]
    fn tier2_verifier_tick_prevents_client_freshness_lie() {
        // Client claims proof was generated at tick 900 (recent),
        // but verifier observed it at tick 100 (old). Current = 200_000.
        // Age should be 200_000 - 100 = 199_900, NOT 200_000 - 900.
        let eval = default_evaluator();
        let req = SessionOpenRequest::new(test_hash(0x01), test_hash(0x02), 900, RiskTier::Tier2)
            .unwrap();
        // With verifier_observed_tick=100, age = 200_000 - 100 = 199_900 > 100k
        // threshold
        let outcome = eval.evaluate(&req, 200_000, 100);
        assert_eq!(outcome.decision, FreshnessDecision::Denied);
        assert_eq!(outcome.age_ticks, Some(199_900));
    }

    // =========================================================================
    // FreshnessEvaluator: Tier3 Tests
    // =========================================================================

    #[test]
    fn tier3_fresh_proof_admitted() {
        let eval = default_evaluator();
        let req = SessionOpenRequest::new(test_hash(0x01), test_hash(0x02), 100, RiskTier::Tier3)
            .unwrap();
        let outcome = eval.evaluate(&req, 200, 100);
        assert_eq!(outcome.decision, FreshnessDecision::Admitted);
    }

    #[test]
    fn tier3_stale_proof_denied() {
        let eval = default_evaluator();
        let req =
            SessionOpenRequest::new(test_hash(0x01), test_hash(0x02), 0, RiskTier::Tier3).unwrap();
        let outcome = eval.evaluate(&req, 20_000, 0);
        assert_eq!(outcome.decision, FreshnessDecision::Denied);
        assert!(matches!(
            outcome.defect,
            Some(SessionIdentityDefect::StaleProof {
                risk_tier: RiskTier::Tier3,
                ..
            })
        ));
    }

    #[test]
    fn tier3_no_proof_denied() {
        let eval = default_evaluator();
        let req =
            SessionOpenRequest::new(test_hash(0x01), zero_hash(), 0, RiskTier::Tier3).unwrap();
        let outcome = eval.evaluate(&req, 200, 0);
        assert_eq!(outcome.decision, FreshnessDecision::Denied);
    }

    // =========================================================================
    // FreshnessEvaluator: Tier4 Tests
    // =========================================================================

    #[test]
    fn tier4_fresh_proof_admitted() {
        let eval = default_evaluator();
        let req = SessionOpenRequest::new(test_hash(0x01), test_hash(0x02), 100, RiskTier::Tier4)
            .unwrap();
        let outcome = eval.evaluate(&req, 200, 100);
        assert_eq!(outcome.decision, FreshnessDecision::Admitted);
    }

    #[test]
    fn tier4_stale_proof_denied() {
        let eval = default_evaluator();
        let req =
            SessionOpenRequest::new(test_hash(0x01), test_hash(0x02), 0, RiskTier::Tier4).unwrap();
        let outcome = eval.evaluate(&req, 2_000, 0);
        assert_eq!(outcome.decision, FreshnessDecision::Denied);
    }

    #[test]
    fn tier4_no_proof_denied() {
        let eval = default_evaluator();
        let req =
            SessionOpenRequest::new(test_hash(0x01), zero_hash(), 0, RiskTier::Tier4).unwrap();
        let outcome = eval.evaluate(&req, 200, 0);
        assert_eq!(outcome.decision, FreshnessDecision::Denied);
    }

    // =========================================================================
    // Tick Reversal Tests
    // =========================================================================

    #[test]
    fn tick_reversal_denied_all_tiers() {
        let eval = default_evaluator();
        for tier in [
            RiskTier::Tier0,
            RiskTier::Tier1,
            RiskTier::Tier2,
            RiskTier::Tier3,
            RiskTier::Tier4,
        ] {
            let req = SessionOpenRequest::new(test_hash(0x01), test_hash(0x02), 500, tier).unwrap();
            // verifier_observed_tick=500 > current_tick=100 => reversal
            let outcome = eval.evaluate(&req, 100, 500);
            assert_eq!(
                outcome.decision,
                FreshnessDecision::Denied,
                "tick reversal should deny for {tier:?}"
            );
            assert!(
                matches!(
                    outcome.defect,
                    Some(SessionIdentityDefect::TickReversal { .. })
                ),
                "should emit tick reversal defect for {tier:?}"
            );
        }
    }

    // =========================================================================
    // Defect Kind Labels
    // =========================================================================

    #[test]
    fn defect_kind_labels() {
        assert_eq!(
            SessionIdentityDefect::MissingProof {
                risk_tier: RiskTier::Tier2
            }
            .kind(),
            "session_identity.missing_proof"
        );
        assert_eq!(
            SessionIdentityDefect::MissingProofDegraded {
                risk_tier: RiskTier::Tier0
            }
            .kind(),
            "session_identity.missing_proof_degraded"
        );
        assert_eq!(
            SessionIdentityDefect::StaleProof {
                risk_tier: RiskTier::Tier3,
                age_ticks: 100,
                max_staleness_ticks: 50,
            }
            .kind(),
            "session_identity.stale_proof"
        );
        assert_eq!(
            SessionIdentityDefect::StaleProofDegraded {
                risk_tier: RiskTier::Tier1,
                age_ticks: 100,
                max_staleness_ticks: 50,
            }
            .kind(),
            "session_identity.stale_proof_degraded"
        );
        assert_eq!(
            SessionIdentityDefect::TickReversal {
                risk_tier: RiskTier::Tier0,
                current_tick: 10,
                proof_generated_at_tick: 20,
            }
            .kind(),
            "session_identity.tick_reversal"
        );
    }

    // =========================================================================
    // Receipt Tests
    // =========================================================================

    #[test]
    fn receipt_hash_is_deterministic() {
        let eval = default_evaluator();
        let req = SessionOpenRequest::new(test_hash(0x01), test_hash(0x02), 100, RiskTier::Tier2)
            .unwrap();
        let outcome = eval.evaluate(&req, 200, 100);
        let resp = SessionOpenResponse::new(
            test_hash(0x0A),
            test_hash(0x0B),
            outcome.decision,
            RiskTier::Tier2,
            Some(test_hash(0xCC)),
            Some(test_hash(0xDD)),
        )
        .unwrap();
        let r1 = SessionOpenReceipt::from_outcome(&req, Some(&resp), &outcome, 200);
        let r2 = SessionOpenReceipt::from_outcome(&req, Some(&resp), &outcome, 200);
        assert_eq!(r1.canonical_hash(), r2.canonical_hash());
    }

    #[test]
    fn receipt_differs_on_decision() {
        let req = SessionOpenRequest::new(test_hash(0x01), test_hash(0x02), 100, RiskTier::Tier2)
            .unwrap();
        let outcome_admitted = FreshnessOutcome {
            decision: FreshnessDecision::Admitted,
            risk_tier: RiskTier::Tier2,
            age_ticks: Some(100),
            max_staleness_ticks: 100_000,
            defect: None,
        };
        let outcome_denied = FreshnessOutcome {
            decision: FreshnessDecision::Denied,
            risk_tier: RiskTier::Tier2,
            age_ticks: Some(100),
            max_staleness_ticks: 100_000,
            defect: None,
        };
        let r1 = SessionOpenReceipt::from_outcome(&req, None, &outcome_admitted, 200);
        let r2 = SessionOpenReceipt::from_outcome(&req, None, &outcome_denied, 200);
        assert_ne!(r1.canonical_hash(), r2.canonical_hash());
    }

    #[test]
    fn receipt_accessors() {
        let req = SessionOpenRequest::new(test_hash(0x01), test_hash(0x02), 100, RiskTier::Tier3)
            .unwrap();
        let outcome = FreshnessOutcome {
            decision: FreshnessDecision::Denied,
            risk_tier: RiskTier::Tier3,
            age_ticks: Some(50_000),
            max_staleness_ticks: 10_000,
            defect: None,
        };
        let receipt = SessionOpenReceipt::from_outcome(&req, None, &outcome, 50_100);
        assert_eq!(receipt.decision(), FreshnessDecision::Denied);
        assert_eq!(receipt.risk_tier(), RiskTier::Tier3);
        assert_eq!(receipt.age_ticks(), Some(50_000));
        assert_eq!(receipt.max_staleness_ticks(), 10_000);
        assert_eq!(receipt.evaluated_at_tick(), 50_100);
        assert_eq!(receipt.response_hash(), &zero_hash());
    }

    // =========================================================================
    // process_session_open Integration Tests
    // =========================================================================

    #[test]
    fn process_tier2_fresh_proof_succeeds() {
        let eval = default_evaluator();
        let req = SessionOpenRequest::new(test_hash(0x01), test_hash(0x02), 100, RiskTier::Tier2)
            .unwrap();
        let result = process_session_open(
            &eval,
            &req,
            200,
            100,
            test_hash(0xAA),
            test_hash(0xBB),
            Some(test_hash(0xCC)),
            Some(test_hash(0xDD)),
        );
        let resp = result.response.unwrap();
        assert_eq!(resp.decision(), FreshnessDecision::Admitted);
        assert_eq!(resp.cell_certificate_hash(), &test_hash(0xAA));
        assert_eq!(resp.directory_head_hash(), &test_hash(0xBB));
        assert_eq!(resp.freshness_witness(), Some(&test_hash(0xCC)));
        assert_eq!(resp.policy_pointer(), Some(&test_hash(0xDD)));
        assert_eq!(result.receipt.decision(), FreshnessDecision::Admitted);
        assert!(result.defects.is_empty());
    }

    #[test]
    fn process_tier2_stale_proof_denied() {
        let eval = default_evaluator();
        let req =
            SessionOpenRequest::new(test_hash(0x01), test_hash(0x02), 0, RiskTier::Tier2).unwrap();
        let result = process_session_open(
            &eval,
            &req,
            200_000,
            0,
            test_hash(0xAA),
            test_hash(0xBB),
            Some(test_hash(0xCC)),
            Some(test_hash(0xDD)),
        );
        assert!(result.response.is_err());
        assert_eq!(result.receipt.decision(), FreshnessDecision::Denied);
        assert!(!result.defects.is_empty());
    }

    #[test]
    fn process_tier0_no_proof_degraded() {
        let eval = default_evaluator();
        let req =
            SessionOpenRequest::new(test_hash(0x01), zero_hash(), 0, RiskTier::Tier0).unwrap();
        let result = process_session_open(
            &eval,
            &req,
            200,
            0,
            test_hash(0xAA),
            test_hash(0xBB),
            None,
            None,
        );
        let resp = result.response.unwrap();
        assert_eq!(resp.decision(), FreshnessDecision::Degraded);
        assert_eq!(result.receipt.decision(), FreshnessDecision::Degraded);
        assert!(!result.defects.is_empty());
    }

    #[test]
    fn process_tier3_missing_proof_denied() {
        let eval = default_evaluator();
        let req =
            SessionOpenRequest::new(test_hash(0x01), zero_hash(), 0, RiskTier::Tier3).unwrap();
        let result = process_session_open(
            &eval,
            &req,
            200,
            0,
            test_hash(0xAA),
            test_hash(0xBB),
            Some(test_hash(0xCC)),
            Some(test_hash(0xDD)),
        );
        assert!(matches!(
            result.response.unwrap_err(),
            SessionIdentityError::ProofRequired {
                risk_tier: RiskTier::Tier3,
            }
        ));
        assert_eq!(result.receipt.decision(), FreshnessDecision::Denied);
    }

    #[test]
    fn process_tier4_tick_reversal_denied() {
        let eval = default_evaluator();
        let req = SessionOpenRequest::new(test_hash(0x01), test_hash(0x02), 500, RiskTier::Tier4)
            .unwrap();
        // verifier_observed_tick=500 > current_tick=100 => reversal
        let result = process_session_open(
            &eval,
            &req,
            100,
            500,
            test_hash(0xAA),
            test_hash(0xBB),
            Some(test_hash(0xCC)),
            Some(test_hash(0xDD)),
        );
        assert!(matches!(
            result.response.unwrap_err(),
            SessionIdentityError::TickReversal { .. }
        ));
        assert_eq!(result.receipt.decision(), FreshnessDecision::Denied);
    }

    #[test]
    fn process_admitted_with_zero_cell_cert_fails_receipt_denied() {
        // When the evaluator admits but response construction fails,
        // the receipt MUST be forced to Denied (fail-closed).
        let eval = default_evaluator();
        let req = SessionOpenRequest::new(test_hash(0x01), test_hash(0x02), 100, RiskTier::Tier2)
            .unwrap();
        let result = process_session_open(
            &eval,
            &req,
            200,
            100,
            zero_hash(),
            test_hash(0xBB),
            Some(test_hash(0xCC)),
            Some(test_hash(0xDD)),
        );
        assert!(matches!(
            result.response.unwrap_err(),
            SessionIdentityError::MissingCellCertificateHash
        ));
        // Receipt forced to Denied on response construction failure (BLOCKER 2).
        assert_eq!(result.receipt.decision(), FreshnessDecision::Denied);
    }

    #[test]
    fn process_defects_surfaced_in_result() {
        let eval = default_evaluator();
        let req =
            SessionOpenRequest::new(test_hash(0x01), zero_hash(), 0, RiskTier::Tier2).unwrap();
        let result = process_session_open(
            &eval,
            &req,
            200,
            0,
            test_hash(0xAA),
            test_hash(0xBB),
            Some(test_hash(0xCC)),
            Some(test_hash(0xDD)),
        );
        assert!(result.response.is_err());
        assert_eq!(result.defects.len(), 1);
        assert!(matches!(
            result.defects[0],
            SessionIdentityDefect::MissingProof {
                risk_tier: RiskTier::Tier2
            }
        ));
    }

    // =========================================================================
    // Defect risk_tier accessor
    // =========================================================================

    #[test]
    fn defect_risk_tier_accessor() {
        let d = SessionIdentityDefect::StaleProof {
            risk_tier: RiskTier::Tier4,
            age_ticks: 5000,
            max_staleness_ticks: 1000,
        };
        assert_eq!(d.risk_tier(), RiskTier::Tier4);
    }

    // =========================================================================
    // BLOCKER 1: Tier2+ freshness_witness / policy_pointer enforcement
    // =========================================================================

    #[test]
    fn tier2_admitted_rejects_missing_freshness_witness() {
        let result = SessionOpenResponse::new(
            test_hash(0x01),
            test_hash(0x02),
            FreshnessDecision::Admitted,
            RiskTier::Tier2,
            None,
            Some(test_hash(0xDD)),
        );
        assert_eq!(
            result.unwrap_err(),
            SessionIdentityError::MissingFreshnessWitness {
                risk_tier: RiskTier::Tier2
            }
        );
    }

    #[test]
    fn tier2_admitted_rejects_zero_freshness_witness() {
        let result = SessionOpenResponse::new(
            test_hash(0x01),
            test_hash(0x02),
            FreshnessDecision::Admitted,
            RiskTier::Tier2,
            Some(zero_hash()),
            Some(test_hash(0xDD)),
        );
        assert_eq!(
            result.unwrap_err(),
            SessionIdentityError::ZeroFreshnessWitness {
                risk_tier: RiskTier::Tier2
            }
        );
    }

    #[test]
    fn tier2_admitted_rejects_missing_policy_pointer() {
        let result = SessionOpenResponse::new(
            test_hash(0x01),
            test_hash(0x02),
            FreshnessDecision::Admitted,
            RiskTier::Tier2,
            Some(test_hash(0xCC)),
            None,
        );
        assert_eq!(
            result.unwrap_err(),
            SessionIdentityError::MissingPolicyPointer {
                risk_tier: RiskTier::Tier2
            }
        );
    }

    #[test]
    fn tier2_admitted_rejects_zero_policy_pointer() {
        let result = SessionOpenResponse::new(
            test_hash(0x01),
            test_hash(0x02),
            FreshnessDecision::Admitted,
            RiskTier::Tier2,
            Some(test_hash(0xCC)),
            Some(zero_hash()),
        );
        assert_eq!(
            result.unwrap_err(),
            SessionIdentityError::ZeroPolicyPointer {
                risk_tier: RiskTier::Tier2
            }
        );
    }

    #[test]
    fn tier3_degraded_rejects_missing_witness_and_policy() {
        // Tier3 is authoritative, even degraded decisions need bindings.
        // Note: Tier3 degraded is unusual but possible via direct response
        // construction; the evaluator itself would deny Tier3 missing proofs.
        let result = SessionOpenResponse::new(
            test_hash(0x01),
            test_hash(0x02),
            FreshnessDecision::Degraded,
            RiskTier::Tier3,
            None,
            None,
        );
        assert_eq!(
            result.unwrap_err(),
            SessionIdentityError::MissingFreshnessWitness {
                risk_tier: RiskTier::Tier3
            }
        );
    }

    #[test]
    fn tier4_admitted_rejects_zero_witness() {
        let result = SessionOpenResponse::new(
            test_hash(0x01),
            test_hash(0x02),
            FreshnessDecision::Admitted,
            RiskTier::Tier4,
            Some(zero_hash()),
            Some(test_hash(0xDD)),
        );
        assert_eq!(
            result.unwrap_err(),
            SessionIdentityError::ZeroFreshnessWitness {
                risk_tier: RiskTier::Tier4
            }
        );
    }

    #[test]
    fn tier0_admitted_allows_missing_witness_and_policy() {
        // Tier0 is non-authoritative; witness/policy not required.
        let resp = SessionOpenResponse::new(
            test_hash(0x01),
            test_hash(0x02),
            FreshnessDecision::Admitted,
            RiskTier::Tier0,
            None,
            None,
        )
        .unwrap();
        assert_eq!(resp.decision(), FreshnessDecision::Admitted);
        assert!(resp.freshness_witness().is_none());
        assert!(resp.policy_pointer().is_none());
    }

    #[test]
    fn tier1_degraded_allows_missing_witness_and_policy() {
        // Tier1 is non-authoritative; witness/policy not required.
        let resp = SessionOpenResponse::new(
            test_hash(0x01),
            test_hash(0x02),
            FreshnessDecision::Degraded,
            RiskTier::Tier1,
            None,
            None,
        )
        .unwrap();
        assert_eq!(resp.decision(), FreshnessDecision::Degraded);
    }

    #[test]
    fn tier2_denied_allows_missing_witness_and_policy() {
        // Denied responses skip all binding checks regardless of tier.
        let resp = SessionOpenResponse::new(
            zero_hash(),
            zero_hash(),
            FreshnessDecision::Denied,
            RiskTier::Tier2,
            None,
            None,
        )
        .unwrap();
        assert_eq!(resp.decision(), FreshnessDecision::Denied);
    }

    #[test]
    fn tier2_admitted_accepts_valid_bindings() {
        // Happy path: Tier2 admitted with non-zero witness and policy.
        let resp = SessionOpenResponse::new(
            test_hash(0x01),
            test_hash(0x02),
            FreshnessDecision::Admitted,
            RiskTier::Tier2,
            Some(test_hash(0xCC)),
            Some(test_hash(0xDD)),
        )
        .unwrap();
        assert_eq!(resp.freshness_witness(), Some(&test_hash(0xCC)));
        assert_eq!(resp.policy_pointer(), Some(&test_hash(0xDD)));
    }

    // =========================================================================
    // BLOCKER 2: Receipt consistency on response construction failure
    // =========================================================================

    #[test]
    fn process_response_construction_failure_forces_denied_receipt_tier2() {
        // Evaluator admits (fresh Tier2 proof), but we supply zero cell cert
        // to force response construction failure. Receipt MUST be Denied.
        let eval = default_evaluator();
        let req = SessionOpenRequest::new(test_hash(0x01), test_hash(0x02), 100, RiskTier::Tier2)
            .unwrap();
        let result = process_session_open(
            &eval,
            &req,
            200,
            100,
            zero_hash(), // <-- forces response construction failure
            test_hash(0xBB),
            Some(test_hash(0xCC)),
            Some(test_hash(0xDD)),
        );
        // Response is an error.
        assert!(result.response.is_err());
        // Receipt MUST be Denied even though evaluator would have admitted.
        assert_eq!(
            result.receipt.decision(),
            FreshnessDecision::Denied,
            "receipt must be denied when response construction fails"
        );
        // Response hash must be zero (no response constructed).
        assert_eq!(result.receipt.response_hash(), &zero_hash());
    }

    #[test]
    fn process_response_construction_failure_forces_denied_receipt_degraded() {
        // Evaluator degrades (Tier0, missing proof), but we supply zero
        // directory head to force response construction failure.
        let eval = default_evaluator();
        let req =
            SessionOpenRequest::new(test_hash(0x01), zero_hash(), 0, RiskTier::Tier0).unwrap();
        let result = process_session_open(
            &eval,
            &req,
            200,
            0,
            test_hash(0xAA),
            zero_hash(), // <-- forces response construction failure
            None,
            None,
        );
        // Response is an error.
        assert!(result.response.is_err());
        // Receipt MUST be Denied even though evaluator would have degraded.
        assert_eq!(
            result.receipt.decision(),
            FreshnessDecision::Denied,
            "receipt must be denied when response construction fails (degraded path)"
        );
    }

    #[test]
    fn process_response_construction_failure_missing_witness_forces_denied() {
        // Evaluator admits Tier2, but no freshness witness provided.
        // Response construction fails; receipt forced to Denied.
        let eval = default_evaluator();
        let req = SessionOpenRequest::new(test_hash(0x01), test_hash(0x02), 100, RiskTier::Tier2)
            .unwrap();
        let result = process_session_open(
            &eval,
            &req,
            200,
            100,
            test_hash(0xAA),
            test_hash(0xBB),
            None, // <-- missing freshness witness for Tier2
            Some(test_hash(0xDD)),
        );
        assert!(matches!(
            result.response.unwrap_err(),
            SessionIdentityError::MissingFreshnessWitness {
                risk_tier: RiskTier::Tier2
            }
        ));
        assert_eq!(
            result.receipt.decision(),
            FreshnessDecision::Denied,
            "receipt forced to denied on missing Tier2 freshness witness"
        );
    }

    #[test]
    fn process_successful_response_receipt_matches_decision() {
        // Verify that a successful admit produces a matching receipt decision.
        let eval = default_evaluator();
        let req = SessionOpenRequest::new(test_hash(0x01), test_hash(0x02), 100, RiskTier::Tier2)
            .unwrap();
        let result = process_session_open(
            &eval,
            &req,
            200,
            100,
            test_hash(0xAA),
            test_hash(0xBB),
            Some(test_hash(0xCC)),
            Some(test_hash(0xDD)),
        );
        let resp = result.response.unwrap();
        assert_eq!(resp.decision(), FreshnessDecision::Admitted);
        assert_eq!(result.receipt.decision(), FreshnessDecision::Admitted);
        // Response hash must be non-zero (response was constructed).
        assert_ne!(result.receipt.response_hash(), &zero_hash());
    }
}
