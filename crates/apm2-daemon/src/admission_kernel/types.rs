// AGENT-AUTHORED
//! `AdmissionKernel` types: request, plan, result, spine join extension,
//! witness seeds, and boundary mediation (RFC-0019 §§3–8, Appendix A).
//!
//! All types enforce bounded fields, `deny_unknown_fields` where
//! digest-stable, and versioned naming per §1.3.
//!
//! # Security Model
//!
//! - [`AdmissionPlanV1`] is single-use, non-cloneable, non-serializable across
//!   trust boundaries (RFC-0019 §3.3).
//! - [`AdmissionSpineJoinExtV1`] commits to all spine-required bindings so the
//!   join hash is collision-free (RFC-0019 §4.1.1).
//! - [`WitnessSeedV1`] is daemon-created with provider provenance binding
//!   (RFC-0019 §4.2.1).

use apm2_core::crypto::Hash;
use apm2_core::pcac::{
    AuthorityConsumeRecordV1, AuthorityConsumedV1, AuthorityJoinCertificateV1,
    IdentityEvidenceLevel, PcacPolicyKnobs, RiskTier,
};
use serde::{Deserialize, Serialize};

use super::capabilities::{EffectCapability, LedgerWriteCapability, QuarantineCapability};
use super::prerequisites::LedgerAnchorV1;

// =============================================================================
// Bounded deserialization helpers (SECURITY BLOCKER 2, TCK-00492)
// =============================================================================

/// Bounded string deserialization module.
///
/// Prevents denial-of-service via unbounded allocation when deserializing
/// string fields from untrusted input. Each string is rejected if it exceeds
/// the corresponding `MAX_*` limit.
mod bounded_deser {
    use serde::{self, Deserialize, Deserializer};

    /// Macro to generate bounded deserializer functions with compile-time
    /// maximum length constants.
    macro_rules! bounded_string_deser {
        ($fn_name:ident, $max:expr) => {
            pub fn $fn_name<'de, D>(deserializer: D) -> Result<String, D::Error>
            where
                D: Deserializer<'de>,
            {
                let s = String::deserialize(deserializer)?;
                if s.len() > $max {
                    return Err(serde::de::Error::custom(concat!(
                        "string exceeds maximum length of ",
                        stringify!($max),
                        " bytes"
                    )));
                }
                Ok(s)
            }
        };
    }

    // Bounded deserializers for each field type.
    // These enforce MAX_* limits at deserialization time, preventing
    // attackers from forcing large allocations via malicious payloads.
    bounded_string_deser!(deser_kernel_string, super::MAX_KERNEL_STRING_LENGTH);
    bounded_string_deser!(deser_tool_class, super::MAX_TOOL_CLASS_LENGTH);
    bounded_string_deser!(deser_boundary_profile, super::MAX_BOUNDARY_PROFILE_LENGTH);
    bounded_string_deser!(
        deser_witness_provider_id,
        super::MAX_WITNESS_PROVIDER_ID_LENGTH
    );
    bounded_string_deser!(deser_witness_class, super::MAX_KERNEL_STRING_LENGTH);
}

// =============================================================================
// Resource limits
// =============================================================================

/// Maximum length for string fields in kernel request types.
pub const MAX_KERNEL_STRING_LENGTH: usize = 256;

/// Maximum length for the tool class identifier.
pub const MAX_TOOL_CLASS_LENGTH: usize = 128;

/// Maximum length for the boundary profile identifier.
pub const MAX_BOUNDARY_PROFILE_LENGTH: usize = 128;

/// Maximum length for the mechanism identifier in external anchors.
pub const MAX_MECHANISM_ID_LENGTH: usize = 128;

/// Maximum length for the algorithm identifier in governance provenance.
pub const MAX_ALGORITHM_ID_LENGTH: usize = 64;

/// Maximum length for the witness provider identifier.
pub const MAX_WITNESS_PROVIDER_ID_LENGTH: usize = 256;

// =============================================================================
// Enforcement tier
// =============================================================================

/// Policy-derived enforcement tier for admission decisions.
///
/// Tiers are NOT compile-time constants; they MUST be derived from
/// policy root and `tool_class`/`boundary_profile` per RFC-0019 §1.1.
///
/// # Fail-Closed Semantics
///
/// `FailClosed` tiers deny on missing authoritative prerequisites.
/// `Monitor` tiers may proceed with warnings but MUST NOT execute
/// effects that require authoritative enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementTier {
    /// Fail-closed: deny on missing prerequisites.
    FailClosed,
    /// Monitor-only: log violations but allow (non-authoritative).
    Monitor,
}

impl std::fmt::Display for EnforcementTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FailClosed => write!(f, "fail_closed"),
            Self::Monitor => write!(f, "monitor"),
        }
    }
}

// =============================================================================
// KernelRequestV1
// =============================================================================

/// Versioned kernel request input (RFC-0019 §5.3 phase A).
///
/// Captures all bindings needed by `AdmissionKernel` to plan and execute
/// an admission decision. Constructed by handlers from transport/protocol
/// structs.
///
/// # Bounded Fields
///
/// All string and collection fields enforce explicit size limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelRequestV1 {
    /// Stable request identifier (daemon-generated or HSI-derived).
    pub request_id: Hash,
    /// Session identifier for the requesting session.
    pub session_id: String,
    /// Tool class identifier (determines enforcement tier).
    pub tool_class: String,
    /// Boundary profile identifier.
    pub boundary_profile_id: String,
    /// PCAC risk tier for this request.
    pub risk_tier: RiskTier,
    /// Effect descriptor digest (tool identity + arguments hash).
    pub effect_descriptor_digest: Hash,
    /// Intent digest for PCAC binding.
    pub intent_digest: Hash,
    /// HSI contract manifest digest.
    pub hsi_contract_manifest_digest: Hash,
    /// HSI envelope binding digest.
    pub hsi_envelope_binding_digest: Hash,
    /// Stop/budget profile digest.
    pub stop_budget_digest: Hash,
    /// PCAC policy knobs for this request.
    pub pcac_policy: PcacPolicyKnobs,
    /// Whether declared idempotent by the tool descriptor.
    pub declared_idempotent: bool,
    /// Lease ID for the requesting session.
    pub lease_id: String,
    /// Identity proof hash.
    pub identity_proof_hash: Hash,
    /// Capability manifest hash at request time.
    pub capability_manifest_hash: Hash,
    /// Current time envelope reference (HTF).
    pub time_envelope_ref: Hash,
    /// Current freshness witness tick.
    pub freshness_witness_tick: u64,
    /// Directory head hash.
    pub directory_head_hash: Hash,
    /// Freshness policy hash.
    pub freshness_policy_hash: Hash,
    /// Current revocation head hash.
    pub revocation_head_hash: Hash,
    /// Identity evidence level for this request (`Verified` or `PointerOnly`).
    ///
    /// For Tier2+ (fail-closed) paths, this is expected to be `Verified`.
    /// `PointerOnly` at Tier2+ requires a non-`None`
    /// `pointer_only_waiver_hash`.
    pub identity_evidence_level: IdentityEvidenceLevel,
    /// Optional pointer-only waiver hash.
    ///
    /// Required when `identity_evidence_level` is `PointerOnly` at Tier2+.
    /// The waiver hash references a governance policy waiver allowing
    /// pointer-only identity evidence for the given request context.
    pub pointer_only_waiver_hash: Option<Hash>,
}

impl KernelRequestV1 {
    /// Validate all boundary constraints on this kernel request.
    ///
    /// # Errors
    ///
    /// Returns a description of the first violation found (fail-closed).
    pub fn validate(&self) -> Result<(), AdmitError> {
        const ZERO: Hash = [0u8; 32];

        // String length bounds
        if self.session_id.is_empty() || self.session_id.len() > MAX_KERNEL_STRING_LENGTH {
            return Err(AdmitError::InvalidRequest {
                reason: "session_id empty or exceeds maximum length".into(),
            });
        }
        if self.tool_class.is_empty() || self.tool_class.len() > MAX_TOOL_CLASS_LENGTH {
            return Err(AdmitError::InvalidRequest {
                reason: "tool_class empty or exceeds maximum length".into(),
            });
        }
        if self.boundary_profile_id.is_empty()
            || self.boundary_profile_id.len() > MAX_BOUNDARY_PROFILE_LENGTH
        {
            return Err(AdmitError::InvalidRequest {
                reason: "boundary_profile_id empty or exceeds maximum length".into(),
            });
        }
        if self.lease_id.is_empty() || self.lease_id.len() > MAX_KERNEL_STRING_LENGTH {
            return Err(AdmitError::InvalidRequest {
                reason: "lease_id empty or exceeds maximum length".into(),
            });
        }

        // Required hash fields must be non-zero
        if self.request_id == ZERO {
            return Err(AdmitError::InvalidRequest {
                reason: "request_id is zero".into(),
            });
        }
        if self.intent_digest == ZERO {
            return Err(AdmitError::InvalidRequest {
                reason: "intent_digest is zero".into(),
            });
        }
        if self.effect_descriptor_digest == ZERO {
            return Err(AdmitError::InvalidRequest {
                reason: "effect_descriptor_digest is zero".into(),
            });
        }
        if self.identity_proof_hash == ZERO {
            return Err(AdmitError::InvalidRequest {
                reason: "identity_proof_hash is zero".into(),
            });
        }
        if self.capability_manifest_hash == ZERO {
            return Err(AdmitError::InvalidRequest {
                reason: "capability_manifest_hash is zero".into(),
            });
        }
        if self.time_envelope_ref == ZERO {
            return Err(AdmitError::InvalidRequest {
                reason: "time_envelope_ref is zero".into(),
            });
        }
        if self.freshness_witness_tick == 0 {
            return Err(AdmitError::InvalidRequest {
                reason: "freshness_witness_tick is zero".into(),
            });
        }
        if self.directory_head_hash == ZERO {
            return Err(AdmitError::InvalidRequest {
                reason: "directory_head_hash is zero".into(),
            });
        }
        if self.freshness_policy_hash == ZERO {
            return Err(AdmitError::InvalidRequest {
                reason: "freshness_policy_hash is zero".into(),
            });
        }
        // QUALITY MAJOR 1 (TCK-00492): Non-zero checks for ALL mandatory
        // digest fields. These were previously missing, allowing requests
        // with unbound digests to pass validation.
        if self.hsi_contract_manifest_digest == ZERO {
            return Err(AdmitError::InvalidRequest {
                reason: "hsi_contract_manifest_digest is zero".into(),
            });
        }
        if self.hsi_envelope_binding_digest == ZERO {
            return Err(AdmitError::InvalidRequest {
                reason: "hsi_envelope_binding_digest is zero".into(),
            });
        }
        if self.stop_budget_digest == ZERO {
            return Err(AdmitError::InvalidRequest {
                reason: "stop_budget_digest is zero".into(),
            });
        }
        if self.revocation_head_hash == ZERO {
            return Err(AdmitError::InvalidRequest {
                reason: "revocation_head_hash is zero".into(),
            });
        }

        Ok(())
    }
}

// =============================================================================
// AdmissionSpineJoinExtV1
// =============================================================================

/// Spine join extension object (RFC-0019 §4.1.1).
///
/// Committed into the PCAC join input to ensure the join hash covers
/// all spine-required bindings without mutating `AuthorityJoinInputV1`.
///
/// # Digest Stability
///
/// The content hash uses domain-separated canonical bytes with
/// deterministic field ordering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionSpineJoinExtV1 {
    /// Stable request identifier.
    pub request_id: Hash,
    /// Session identifier.
    #[serde(deserialize_with = "bounded_deser::deser_kernel_string")]
    pub session_id: String,
    /// Tool class identifier.
    #[serde(deserialize_with = "bounded_deser::deser_tool_class")]
    pub tool_class: String,
    /// Boundary profile identifier.
    #[serde(deserialize_with = "bounded_deser::deser_boundary_profile")]
    pub boundary_profile_id: String,
    /// Policy-derived enforcement tier.
    pub enforcement_tier: EnforcementTier,
    /// HSI contract manifest digest.
    pub hsi_contract_manifest_digest: Hash,
    /// HSI envelope binding digest.
    pub hsi_envelope_binding_digest: Hash,
    /// Canonical request digest.
    pub canonical_request_digest: Hash,
    /// Effect descriptor digest.
    pub effect_descriptor_digest: Hash,
    /// Whether the effect is declared idempotent.
    pub declared_idempotent: bool,
    /// Stop/budget digest for boundary arbitration.
    pub stop_budget_digest: Hash,
    /// Selected ledger anchor (including `ledger_id`).
    pub ledger_anchor: LedgerAnchorV1,
    /// Policy root digest.
    pub policy_root_digest: Hash,
    /// Policy root epoch (monotonic generation).
    pub policy_root_epoch: u64,
    /// Leakage witness seed hash.
    pub leakage_witness_seed_hash: Hash,
    /// Timing witness seed hash.
    pub timing_witness_seed_hash: Hash,
}

impl AdmissionSpineJoinExtV1 {
    /// Compute a deterministic content hash for this extension.
    ///
    /// Uses domain-separated BLAKE3 hashing over all fields in
    /// canonical order.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // String fields are bounded by MAX_* constants (<=256), safe for u32.
    pub fn content_hash(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"apm2-admission-spine-join-ext-v1");
        hasher.update(&self.request_id);
        hasher.update(self.session_id.as_bytes());
        hasher.update(&(self.session_id.len() as u32).to_le_bytes());
        hasher.update(self.tool_class.as_bytes());
        hasher.update(&(self.tool_class.len() as u32).to_le_bytes());
        hasher.update(self.boundary_profile_id.as_bytes());
        hasher.update(&(self.boundary_profile_id.len() as u32).to_le_bytes());
        hasher.update(match self.enforcement_tier {
            EnforcementTier::FailClosed => &[0x01],
            EnforcementTier::Monitor => &[0x02],
        });
        hasher.update(&self.hsi_contract_manifest_digest);
        hasher.update(&self.hsi_envelope_binding_digest);
        hasher.update(&self.canonical_request_digest);
        hasher.update(&self.effect_descriptor_digest);
        hasher.update(&[u8::from(self.declared_idempotent)]);
        hasher.update(&self.stop_budget_digest);
        // Inline ledger anchor fields for deterministic digest
        hasher.update(&self.ledger_anchor.ledger_id);
        hasher.update(&self.ledger_anchor.event_hash);
        hasher.update(&self.ledger_anchor.height.to_le_bytes());
        hasher.update(&self.ledger_anchor.he_time.to_le_bytes());
        hasher.update(&self.policy_root_digest);
        hasher.update(&self.policy_root_epoch.to_le_bytes());
        hasher.update(&self.leakage_witness_seed_hash);
        hasher.update(&self.timing_witness_seed_hash);
        *hasher.finalize().as_bytes()
    }
}

// =============================================================================
// WitnessSeedV1
// =============================================================================

/// Witness seed object created at join time (RFC-0019 §4.2.1).
///
/// Binds the request to a future witness object. Created by the daemon
/// (not the client) with provider provenance binding.
///
/// # Digest Domain Separation
///
/// Content hash: `b"apm2-witness-seed-v1" || witness_class || request_id ||
/// session_id_len || session_id || tool_class_len || tool_class ||
/// boundary_profile_id_len || boundary_profile_id || ledger_anchor_hash ||
/// ht_start_le || nonce || provider_id_len || provider_id ||
/// provider_build_digest`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessSeedV1 {
    /// Witness class (e.g., "leakage", "timing").
    #[serde(deserialize_with = "bounded_deser::deser_witness_class")]
    pub witness_class: String,
    /// Stable request identifier.
    pub request_id: Hash,
    /// Session identifier.
    #[serde(deserialize_with = "bounded_deser::deser_kernel_string")]
    pub session_id: String,
    /// Tool class identifier.
    #[serde(deserialize_with = "bounded_deser::deser_tool_class")]
    pub tool_class: String,
    /// Boundary profile identifier.
    #[serde(deserialize_with = "bounded_deser::deser_boundary_profile")]
    pub boundary_profile_id: String,
    /// Ledger anchor hash at seed creation time.
    pub ledger_anchor_hash: Hash,
    /// Holonic time at seed creation (start of request).
    pub ht_start: u64,
    /// Cryptographic nonce for uniqueness.
    pub nonce: Hash,
    /// Witness provider identifier (module id / build digest).
    #[serde(deserialize_with = "bounded_deser::deser_witness_provider_id")]
    pub provider_id: String,
    /// Witness provider build digest for measurement binding.
    pub provider_build_digest: Hash,
}

impl WitnessSeedV1 {
    /// Compute a deterministic content hash for this witness seed.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // String fields are bounded by MAX_* constants (<=256), safe for u32.
    pub fn content_hash(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"apm2-witness-seed-v1");
        hasher.update(self.witness_class.as_bytes());
        hasher.update(&(self.witness_class.len() as u32).to_le_bytes());
        hasher.update(&self.request_id);
        hasher.update(self.session_id.as_bytes());
        hasher.update(&(self.session_id.len() as u32).to_le_bytes());
        hasher.update(self.tool_class.as_bytes());
        hasher.update(&(self.tool_class.len() as u32).to_le_bytes());
        hasher.update(self.boundary_profile_id.as_bytes());
        hasher.update(&(self.boundary_profile_id.len() as u32).to_le_bytes());
        hasher.update(&self.ledger_anchor_hash);
        hasher.update(&self.ht_start.to_le_bytes());
        hasher.update(&self.nonce);
        hasher.update(self.provider_id.as_bytes());
        hasher.update(&(self.provider_id.len() as u32).to_le_bytes());
        hasher.update(&self.provider_build_digest);
        *hasher.finalize().as_bytes()
    }
}

// =============================================================================
// PlanState — internal state machine for single-use enforcement
// =============================================================================

/// Internal state for plan lifecycle enforcement.
///
/// Tracks whether a plan has been executed to enforce single-use
/// semantics per RFC-0019 §3.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PlanState {
    /// Plan is ready to execute.
    Ready,
    /// Plan has been consumed (execute was called).
    Consumed,
}

// =============================================================================
// AdmissionPlanV1
// =============================================================================

/// Single-use admission plan (RFC-0019 §3.3, Appendix A).
///
/// Contains all join-time bindings and is consumed exactly once by
/// `execute()`. Re-execution is structurally denied.
///
/// # Single-Use Semantics
///
/// - Non-cloneable, non-copyable.
/// - Non-serializable across trust boundaries (no Serialize/Deserialize).
/// - `execute()` transitions `state` from `Ready` to `Consumed`; second call
///   returns `AdmitError::PlanAlreadyConsumed`.
///
/// # Durability
///
/// Join-time bindings (`as_of` anchor, policy root, seeds) are captured
/// in the plan for restart-safe retry behavior.
pub struct AdmissionPlanV1 {
    /// Internal state for single-use enforcement.
    pub(super) state: PlanState,
    /// The AJC produced by the join phase.
    pub(super) certificate: AuthorityJoinCertificateV1,
    /// Spine join extension committed into the join.
    pub(super) spine_ext: AdmissionSpineJoinExtV1,
    /// Leakage witness seed.
    pub(super) leakage_witness_seed: WitnessSeedV1,
    /// Timing witness seed.
    pub(super) timing_witness_seed: WitnessSeedV1,
    /// The original kernel request (for execute-phase revalidation).
    pub(super) request: KernelRequestV1,
    /// Policy-derived enforcement tier.
    pub(super) enforcement_tier: EnforcementTier,
    /// Selected ledger anchor at plan time.
    pub(super) as_of_ledger_anchor: LedgerAnchorV1,
    /// Policy root state at plan time.
    pub(super) policy_root_digest: Hash,
    /// Policy root epoch at plan time.
    pub(super) policy_root_epoch: u64,
}

// Intentionally no Clone, Copy, Serialize, or Deserialize implementations.

impl std::fmt::Debug for AdmissionPlanV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdmissionPlanV1")
            .field("state", &self.state)
            .field("ajc_id", &hex::encode(self.certificate.ajc_id))
            .field(
                "spine_ext_hash",
                &hex::encode(self.spine_ext.content_hash()),
            )
            .field(
                "leakage_seed_hash",
                &hex::encode(self.leakage_witness_seed.content_hash()),
            )
            .field(
                "timing_seed_hash",
                &hex::encode(self.timing_witness_seed.content_hash()),
            )
            .field("request_id", &hex::encode(self.request.request_id))
            .field("enforcement_tier", &self.enforcement_tier)
            .field(
                "as_of_ledger_anchor_hash",
                &hex::encode(self.as_of_ledger_anchor.content_hash()),
            )
            .field("policy_root_digest", &hex::encode(self.policy_root_digest))
            .field("policy_root_epoch", &self.policy_root_epoch)
            .finish()
    }
}

// =============================================================================
// BoundarySpanV1
// =============================================================================

/// In-kernel boundary mediation span (RFC-0019 §1.1, §5.3 phase M-N).
///
/// Buffers/governs outputs until post-effect checks complete for
/// fail-closed tiers. Output is released only after witness finalization
/// and boundary admissibility checks pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundarySpanV1 {
    /// Request ID this span mediates.
    pub request_id: Hash,
    /// Whether output is currently held (not yet released).
    pub output_held: bool,
    /// Enforcement tier for this boundary span.
    pub enforcement_tier: EnforcementTier,
}

// =============================================================================
// AdmissionResultV1
// =============================================================================

/// Result of successful admission plan execution (RFC-0019 Appendix A).
///
/// Contains the admission bundle digest, capability tokens for effect
/// execution, and lifecycle receipts.
pub struct AdmissionResultV1 {
    /// Digest of the sealed `AdmissionBundleV1` CAS object.
    pub bundle_digest: Hash,
    /// Capability token for effect execution.
    pub effect_capability: EffectCapability,
    /// Capability token for authoritative ledger writes.
    ///
    /// `Some` only for fail-closed tiers that have passed all prerequisite
    /// checks. `None` for monitor tiers — monitor-tier requests MUST NOT
    /// perform authoritative ledger writes (CTR-2617: fail-closed
    /// capabilities).
    pub ledger_write_capability: Option<LedgerWriteCapability>,
    /// Capability token for quarantine insertion (if applicable).
    pub quarantine_capability: Option<QuarantineCapability>,
    /// The consumed authority witness.
    pub consumed_witness: AuthorityConsumedV1,
    /// The durable consume record.
    pub consume_record: AuthorityConsumeRecordV1,
    /// Boundary span for output mediation.
    pub boundary_span: BoundarySpanV1,
}

// Intentionally no Clone or Serialize — capability tokens are non-cloneable.

impl std::fmt::Debug for AdmissionResultV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdmissionResultV1")
            .field("bundle_digest", &hex::encode(self.bundle_digest))
            .field("effect_capability", &self.effect_capability)
            .field("ledger_write_capability", &self.ledger_write_capability)
            .field("quarantine_capability", &self.quarantine_capability)
            .field("consumed_witness", &self.consumed_witness)
            .field("consume_record", &self.consume_record)
            .field("boundary_span", &self.boundary_span)
            .finish()
    }
}

// =============================================================================
// AdmitError
// =============================================================================

/// Error type for admission kernel operations.
///
/// All variants represent deterministic denials (fail-closed). There is
/// no "unknown -> allow" path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmitError {
    /// Request validation failed.
    InvalidRequest {
        /// Bounded reason string.
        reason: String,
    },
    /// Ledger trust verification failed.
    LedgerTrustFailure {
        /// Bounded reason string.
        reason: String,
    },
    /// Policy root resolution failed.
    PolicyRootFailure {
        /// Bounded reason string.
        reason: String,
    },
    /// Anti-rollback anchor verification failed.
    AntiRollbackFailure {
        /// Bounded reason string.
        reason: String,
    },
    /// PCAC join was denied.
    JoinDenied {
        /// Bounded reason string.
        reason: String,
    },
    /// PCAC revalidation was denied.
    RevalidationDenied {
        /// Bounded reason string.
        reason: String,
    },
    /// PCAC consume was denied (includes intent mismatch, already consumed).
    ConsumeDenied {
        /// Bounded reason string.
        reason: String,
    },
    /// Witness seed creation failed.
    WitnessSeedFailure {
        /// Bounded reason string.
        reason: String,
    },
    /// Plan has already been consumed (single-use enforcement).
    PlanAlreadyConsumed,
    /// Quarantine capacity could not be reserved for fail-closed tier.
    QuarantineReservationFailure {
        /// Bounded reason string.
        reason: String,
    },
    /// Boundary mediation failed (output cannot be held/released).
    BoundaryMediationFailure {
        /// Bounded reason string.
        reason: String,
    },
    /// Missing prerequisite for fail-closed tier.
    MissingPrerequisite {
        /// Name of the missing prerequisite.
        prerequisite: String,
    },
    /// A prerequisite drifted between plan and execute (TOCTOU protection).
    ///
    /// This error is raised when a fail-closed tier detects that a
    /// prerequisite (ledger anchor, policy root, anti-rollback) changed
    /// between `plan()` and `execute()`.
    ExecutePrerequisiteDrift {
        /// Which prerequisite drifted.
        prerequisite: String,
        /// Bounded reason string.
        reason: String,
    },
}

impl std::fmt::Display for AdmitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRequest { reason } => write!(f, "invalid request: {reason}"),
            Self::LedgerTrustFailure { reason } => {
                write!(f, "ledger trust failure: {reason}")
            },
            Self::PolicyRootFailure { reason } => {
                write!(f, "policy root failure: {reason}")
            },
            Self::AntiRollbackFailure { reason } => {
                write!(f, "anti-rollback failure: {reason}")
            },
            Self::JoinDenied { reason } => write!(f, "join denied: {reason}"),
            Self::RevalidationDenied { reason } => {
                write!(f, "revalidation denied: {reason}")
            },
            Self::ConsumeDenied { reason } => write!(f, "consume denied: {reason}"),
            Self::WitnessSeedFailure { reason } => {
                write!(f, "witness seed failure: {reason}")
            },
            Self::PlanAlreadyConsumed => write!(f, "plan already consumed (single-use)"),
            Self::QuarantineReservationFailure { reason } => {
                write!(f, "quarantine reservation failure: {reason}")
            },
            Self::BoundaryMediationFailure { reason } => {
                write!(f, "boundary mediation failure: {reason}")
            },
            Self::MissingPrerequisite { prerequisite } => {
                write!(f, "missing prerequisite: {prerequisite}")
            },
            Self::ExecutePrerequisiteDrift {
                prerequisite,
                reason,
            } => {
                write!(f, "execute prerequisite drift: {prerequisite}: {reason}")
            },
        }
    }
}

impl std::error::Error for AdmitError {}
