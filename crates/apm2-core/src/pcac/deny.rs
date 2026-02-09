// AGENT-AUTHORED
//! PCAC deny taxonomy — machine-checkable denial classes (RFC-0027 §15.5).
//!
//! Every authority denial produces an [`AuthorityDenyV1`] with a specific
//! [`AuthorityDenyClass`] that enables deterministic classification,
//! replay verification, and automated incident response.
//!
//! # Fail-Closed Semantics
//!
//! Unknown or missing authority state always maps to a denial class.
//! There is no "unknown -> allow" path in the deny taxonomy.

use serde::{Deserialize, Serialize};

use super::types::{
    MAX_DESCRIPTION_LENGTH, MAX_FIELD_NAME_LENGTH, MAX_OPERATION_LENGTH, MAX_REASON_LENGTH,
    PcacValidationError, RiskTier,
};
use crate::crypto::Hash;

// =============================================================================
// AuthorityDenyClass
// =============================================================================

/// Machine-checkable deny taxonomy for PCAC lifecycle failures.
///
/// Each variant represents a specific, deterministic reason for authority
/// denial. This taxonomy is stable across versions — new classes are added
/// as new variants, never by redefining existing ones.
///
/// # Categories
///
/// - **Join failures**: Missing or invalid inputs at join time.
/// - **Revalidation failures**: Authority state drift between join and consume.
/// - **Consume failures**: Final checks before side effect execution.
/// - **Policy failures**: Administrative policy denials.
/// - **Unknown state**: Fail-closed on unrecognized inputs.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum AuthorityDenyClass {
    // ---- Join failures ----
    /// Required field is missing from the join input.
    MissingRequiredField {
        /// Name of the missing field.
        field_name: String,
    },

    /// A hash field contains all zeros (uninitialized).
    ZeroHash {
        /// Name of the zero-hash field.
        field_name: String,
    },

    /// Session ID is empty or exceeds bounds.
    InvalidSessionId,

    /// Lease ID is empty or exceeds bounds.
    InvalidLeaseId,

    /// Intent digest validation failed.
    InvalidIntentDigest,

    /// Capability manifest is unknown or invalid.
    InvalidCapabilityManifest,

    /// Identity proof hash is invalid or missing.
    InvalidIdentityProof,

    /// Freshness witness is missing or stale at join time.
    StaleFreshnessAtJoin,

    /// Time envelope reference is invalid or missing.
    InvalidTimeEnvelope,

    /// Ledger anchor is invalid or missing.
    InvalidLedgerAnchor,

    // ---- Revalidation failures ----
    /// Revocation frontier has advanced beyond the AJC's admissibility.
    ///
    /// Per RFC-0027 §4 Law 4 (Revocation Dominance).
    RevocationFrontierAdvanced,

    /// Freshness authority is stale at revalidation time.
    ///
    /// Per RFC-0027 §4 Law 3 (Freshness Dominance).
    StaleFreshnessAtRevalidate,

    /// The AJC has expired (tick > `expires_at_tick`).
    CertificateExpired {
        /// The tick at which the AJC expired.
        expired_at: u64,
        /// The current tick.
        current_tick: u64,
    },

    /// Ledger anchor has advanced beyond the AJC's `as_of_ledger_anchor`.
    LedgerAnchorDrift,

    // ---- Consume failures ----
    /// Intent digest mismatch between join and consume.
    ///
    /// Per RFC-0027 §4 Law 2 (Intent Equality).
    IntentDigestMismatch {
        /// Expected intent digest (from the AJC).
        expected: Hash,
        /// Actual intent digest provided at consume time.
        actual: Hash,
    },

    /// This AJC has already been consumed (duplicate consume attempt).
    ///
    /// Per RFC-0027 §4 Law 1 (Linear Consumption).
    AlreadyConsumed {
        /// The AJC ID that was already consumed.
        ajc_id: Hash,
    },

    /// Pre-actuation receipt selectors are missing when required by policy.
    MissingPreActuationReceipt,

    /// Boundary monotonicity violation.
    ///
    /// Per RFC-0027 §4 Law 6: `join < revalidate <= consume <= effect`.
    BoundaryMonotonicityViolation {
        /// Description of the violation.
        description: String,
    },

    // ---- Tier2+ sovereignty failures (RFC-0027 §6.6) ----
    /// Sovereignty epoch evidence is stale for Tier2+ operations.
    StaleSovereigntyEpoch,

    /// Principal revocation head state is unknown or ambiguous.
    UnknownRevocationHead,

    /// Autonomy ceiling is incompatible with requested risk tier.
    IncompatibleAutonomyCeiling,

    /// Active sovereign freeze state for the target scope.
    ActiveSovereignFreeze,

    // ---- Policy failures ----
    /// Tier2+ denies `PointerOnly` identity evidence without waiver.
    PointerOnlyDeniedAtTier2Plus,

    /// Waiver has expired or is invalid.
    WaiverExpiredOrInvalid,

    /// Policy explicitly denies this authority request.
    PolicyDeny {
        /// Machine-readable reason code.
        reason: String,
    },

    // ---- Delegation failures ----
    /// Delegated authority is wider than parent authority.
    ///
    /// Per RFC-0027 §4 Law 5 (Delegation Narrowing).
    DelegationWidening,

    /// Delegation chain is missing or invalid.
    InvalidDelegationChain,

    // ---- Verifier economics failures ----
    /// Verifier economics bounds exceeded for the risk tier.
    VerifierEconomicsBoundsExceeded {
        /// The operation that exceeded bounds.
        operation: String,
        /// The risk tier that was exceeded.
        risk_tier: RiskTier,
    },

    // ---- Unknown / fail-closed ----
    /// Unknown authority state — fail closed.
    ///
    /// Per RFC-0027 §12 invariant 8: "Unknown/missing required authority
    /// state is fail-closed."
    UnknownState {
        /// Description of the unknown state.
        description: String,
    },
}

impl std::fmt::Display for AuthorityDenyClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingRequiredField { field_name } => {
                write!(f, "missing required field: {field_name}")
            },
            Self::ZeroHash { field_name } => write!(f, "zero hash for field: {field_name}"),
            Self::InvalidSessionId => write!(f, "invalid session ID"),
            Self::InvalidLeaseId => write!(f, "invalid lease ID"),
            Self::InvalidIntentDigest => write!(f, "invalid intent digest"),
            Self::InvalidCapabilityManifest => write!(f, "invalid capability manifest"),
            Self::InvalidIdentityProof => write!(f, "invalid identity proof"),
            Self::StaleFreshnessAtJoin => write!(f, "stale freshness at join"),
            Self::InvalidTimeEnvelope => write!(f, "invalid time envelope"),
            Self::InvalidLedgerAnchor => write!(f, "invalid ledger anchor"),
            Self::RevocationFrontierAdvanced => write!(f, "revocation frontier advanced"),
            Self::StaleFreshnessAtRevalidate => write!(f, "stale freshness at revalidate"),
            Self::CertificateExpired {
                expired_at,
                current_tick,
            } => write!(
                f,
                "certificate expired at tick {expired_at} (current: {current_tick})"
            ),
            Self::LedgerAnchorDrift => write!(f, "ledger anchor drift"),
            Self::IntentDigestMismatch { .. } => write!(f, "intent digest mismatch"),
            Self::AlreadyConsumed { .. } => write!(f, "authority already consumed"),
            Self::MissingPreActuationReceipt => write!(f, "missing pre-actuation receipt"),
            Self::BoundaryMonotonicityViolation { description } => {
                write!(f, "boundary monotonicity violation: {description}")
            },
            Self::StaleSovereigntyEpoch => write!(f, "stale sovereignty epoch"),
            Self::UnknownRevocationHead => write!(f, "unknown revocation head"),
            Self::IncompatibleAutonomyCeiling => write!(f, "incompatible autonomy ceiling"),
            Self::ActiveSovereignFreeze => write!(f, "active sovereign freeze"),
            Self::PointerOnlyDeniedAtTier2Plus => {
                write!(f, "pointer-only identity denied at Tier2+")
            },
            Self::WaiverExpiredOrInvalid => write!(f, "waiver expired or invalid"),
            Self::PolicyDeny { reason } => write!(f, "policy deny: {reason}"),
            Self::DelegationWidening => write!(f, "delegation widening"),
            Self::InvalidDelegationChain => write!(f, "invalid delegation chain"),
            Self::VerifierEconomicsBoundsExceeded {
                operation,
                risk_tier,
            } => write!(
                f,
                "verifier economics bounds exceeded for {operation} at {risk_tier}"
            ),
            Self::UnknownState { description } => {
                write!(f, "unknown authority state: {description}")
            },
        }
    }
}

// =============================================================================
// AuthorityDenyV1
// =============================================================================

/// Complete authority denial with all context needed for replay and audit.
///
/// This is the error type returned by all `AuthorityJoinKernel` operations.
/// It carries enough information for:
///
/// - Machine-checkable classification (via `deny_class`).
/// - Replay verification (via `time_envelope_ref` and `ledger_anchor`).
/// - Audit trail (via `ajc_id` when available).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityDenyV1 {
    /// The specific denial class.
    pub deny_class: AuthorityDenyClass,

    /// The AJC ID, if the denial occurred after join (during
    /// revalidate/consume).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ajc_id: Option<Hash>,

    /// Time envelope reference at denial time.
    pub time_envelope_ref: Hash,

    /// Ledger anchor at denial time.
    pub ledger_anchor: Hash,

    /// Tick at denial time.
    pub denied_at_tick: u64,
}

impl std::fmt::Display for AuthorityDenyV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "authority denied: {}", self.deny_class)?;
        if let Some(ref ajc_id) = self.ajc_id {
            write!(f, " (ajc_id: {})", hex::encode(ajc_id))?;
        }
        Ok(())
    }
}

impl std::error::Error for AuthorityDenyV1 {}

impl AuthorityDenyClass {
    /// Validate that all embedded string fields are within size bounds.
    ///
    /// # Errors
    ///
    /// Returns `PcacValidationError::StringTooLong` if any string field
    /// exceeds its maximum length.
    pub fn validate(&self) -> Result<(), PcacValidationError> {
        match self {
            Self::MissingRequiredField { field_name } | Self::ZeroHash { field_name } => {
                if field_name.len() > MAX_FIELD_NAME_LENGTH {
                    return Err(PcacValidationError::StringTooLong {
                        field: "field_name",
                        len: field_name.len(),
                        max: MAX_FIELD_NAME_LENGTH,
                    });
                }
            },
            Self::BoundaryMonotonicityViolation { description }
            | Self::UnknownState { description } => {
                if description.len() > MAX_DESCRIPTION_LENGTH {
                    return Err(PcacValidationError::StringTooLong {
                        field: "description",
                        len: description.len(),
                        max: MAX_DESCRIPTION_LENGTH,
                    });
                }
            },
            Self::PolicyDeny { reason } => {
                if reason.len() > MAX_REASON_LENGTH {
                    return Err(PcacValidationError::StringTooLong {
                        field: "reason",
                        len: reason.len(),
                        max: MAX_REASON_LENGTH,
                    });
                }
            },
            Self::VerifierEconomicsBoundsExceeded { operation, .. } => {
                if operation.len() > MAX_OPERATION_LENGTH {
                    return Err(PcacValidationError::StringTooLong {
                        field: "operation",
                        len: operation.len(),
                        max: MAX_OPERATION_LENGTH,
                    });
                }
            },
            // All other variants have no unbounded string fields.
            _ => {},
        }
        Ok(())
    }
}

impl AuthorityDenyV1 {
    /// Validate all boundary constraints on this deny record.
    ///
    /// Delegates to [`AuthorityDenyClass::validate`] for embedded string
    /// field bounds.
    ///
    /// # Errors
    ///
    /// Returns `PcacValidationError` on the first violation found.
    pub fn validate(&self) -> Result<(), PcacValidationError> {
        self.deny_class.validate()
    }
}
