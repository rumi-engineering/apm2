// AGENT-AUTHORED
//! Core PCAC types: authority join inputs, certificates, and consume records.
//!
//! These types implement RFC-0027 §3 — the canonical authority lifecycle
//! primitives.

use serde::{Deserialize, Serialize};

use crate::crypto::Hash;

// =============================================================================
// Identity Evidence Level
// =============================================================================

/// Evidence level for identity proofs in the PCAC lifecycle.
///
/// Per RFC-0027 §5, transitional evidence levels allow managed migration
/// from pointer-only to fully verified identity proofs.
///
/// # Policy Requirements
///
/// - Tier0/1 MAY admit `PointerOnly` under explicit waiver binding.
/// - Tier2+ MUST default deny on `PointerOnly` unless explicitly waived.
/// - Every `PointerOnly` admission MUST emit a waiver-binding receipt.
/// - Waiver expiry immediately reverts to fail-closed behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum IdentityEvidenceLevel {
    /// Proof dereference + cryptographic verification completed under policy.
    Verified,
    /// Hash-shape commitment only; allowed only under explicit waiver policy.
    PointerOnly,
}

impl std::fmt::Display for IdentityEvidenceLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Verified => write!(f, "verified"),
            Self::PointerOnly => write!(f, "pointer_only"),
        }
    }
}

// =============================================================================
// AuthorityJoinInputV1
// =============================================================================

/// Canonical input set used to compute admissible authority (RFC-0027 §3.1).
///
/// This structure captures all bindings required to produce an
/// [`AuthorityJoinCertificateV1`]. The authority join hash is computed over
/// the canonical encoding of these fields.
///
/// # Required Fields
///
/// All hash fields are 32-byte BLAKE3 digests. Missing or zero-valued
/// required fields MUST cause join denial (fail-closed).
///
/// # Security Invariants
///
/// - `intent_digest` binds the specific effect being authorized.
/// - `capability_manifest_hash` pins the capability set at join time.
/// - `freshness_witness_hash` ensures authority is current.
/// - `stop_budget_profile_digest` captures stop/budget constraints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityJoinInputV1 {
    // -- Subject bindings --
    /// Session identifier for the requesting session.
    pub session_id: String,

    /// Optional holon identifier when operating within a holon context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holon_id: Option<String>,

    // -- Intent binding --
    /// Canonicalized digest of the request/effect intent.
    pub intent_digest: Hash,

    // -- Capability bindings --
    /// Hash of the capability manifest at join time.
    pub capability_manifest_hash: Hash,

    /// Hash(es) of scope witness(es).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scope_witness_hashes: Vec<Hash>,

    // -- Delegation bindings --
    /// Lease identifier for the requesting session.
    pub lease_id: String,

    /// Optional permeability receipt hash for delegated authority paths.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permeability_receipt_hash: Option<Hash>,

    // -- Identity bindings --
    /// Hash of the identity proof.
    pub identity_proof_hash: Hash,

    /// Evidence level of the identity proof.
    pub identity_evidence_level: IdentityEvidenceLevel,

    // -- Freshness bindings --
    /// Hash of the directory head at join time.
    pub directory_head_hash: Hash,

    /// Hash of the freshness policy.
    pub freshness_policy_hash: Hash,

    /// Witness tick/boundary for freshness.
    pub freshness_witness_tick: u64,

    // -- Stop/budget policy bindings --
    /// Digest of the stop/budget profile at join time.
    pub stop_budget_profile_digest: Hash,

    /// Pre-actuation receipt hash(es) required before revalidate/consume.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pre_actuation_receipt_hashes: Vec<Hash>,

    // -- Risk classification --
    /// Risk tier for this authority request.
    pub risk_tier: RiskTier,

    /// Determinism class for the effect.
    pub determinism_class: DeterminismClass,

    // -- HTF time witness bindings --
    /// Content hash reference to the time envelope.
    pub time_envelope_ref: Hash,

    /// Ledger anchor hash at join time.
    pub as_of_ledger_anchor: Hash,
}

/// Risk tier for authority classification.
///
/// Maps to the broader `RiskTierClass` but scoped to the PCAC context
/// with fail-closed semantics on unknown variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RiskTier {
    /// Tier 0: Lowest risk, most permissive.
    Tier0,
    /// Tier 1: Standard risk.
    Tier1,
    /// Tier 2+: Elevated risk, strictest controls.
    Tier2Plus,
}

impl std::fmt::Display for RiskTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tier0 => write!(f, "tier0"),
            Self::Tier1 => write!(f, "tier1"),
            Self::Tier2Plus => write!(f, "tier2+"),
        }
    }
}

/// Determinism class for effect classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DeterminismClass {
    /// Effect is deterministic (same inputs always produce same outputs).
    Deterministic,
    /// Effect is non-deterministic but bounded.
    BoundedNondeterministic,
}

// =============================================================================
// AuthorityJoinCertificateV1 (AJC)
// =============================================================================

/// Single-use authority witness (RFC-0027 §3.2).
///
/// Copy-tolerant semantics: certificate bytes MAY be copied, but only one
/// authoritative consume is admissible per `ajc_id`.
///
/// # Fields
///
/// - `ajc_id`: Content hash of canonical certificate bytes.
/// - `authority_join_hash`: Digest over normalized join inputs.
/// - `intent_digest`: The intent this certificate authorizes.
/// - `risk_tier`: Risk classification at join time.
/// - `issued_time_envelope_ref`: HTF authoritative issue witness.
/// - `as_of_ledger_anchor`: Ledger anchor used at join time.
/// - `expires_at_tick`: Policy/freshness cutoff in authoritative tick space.
/// - `revocation_head_hash`: Revocation frontier commitment.
/// - `identity_evidence_level`: Evidence level at join time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityJoinCertificateV1 {
    /// Content hash of the canonical certificate bytes (32 bytes).
    pub ajc_id: Hash,

    /// Digest over normalized join inputs (32 bytes).
    pub authority_join_hash: Hash,

    /// The intent this certificate authorizes (32 bytes).
    pub intent_digest: Hash,

    /// Risk classification at join time.
    pub risk_tier: RiskTier,

    /// HTF authoritative issue witness (content hash of time envelope).
    pub issued_time_envelope_ref: Hash,

    /// Ledger anchor used at join time.
    pub as_of_ledger_anchor: Hash,

    /// Policy/freshness cutoff in authoritative tick space.
    pub expires_at_tick: u64,

    /// Revocation frontier commitment at join time.
    pub revocation_head_hash: Hash,

    /// Evidence level of the identity proof at join time.
    pub identity_evidence_level: IdentityEvidenceLevel,

    /// Optional admission-capacity token binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admission_capacity_token: Option<Hash>,
}

// =============================================================================
// AuthorityConsumedV1
// =============================================================================

/// Result of a successful authority consumption (RFC-0027 §3.3).
///
/// Returned by `AuthorityJoinKernel::consume()` alongside the durable
/// consume record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityConsumedV1 {
    /// The consumed certificate's ID.
    pub ajc_id: Hash,

    /// The intent that was consumed.
    pub intent_digest: Hash,

    /// Time envelope reference at consume time.
    pub consumed_time_envelope_ref: Hash,

    /// Tick at which consumption occurred.
    pub consumed_at_tick: u64,
}

// =============================================================================
// AuthorityConsumeRecordV1
// =============================================================================

/// Durable consume record for single-use enforcement (RFC-0027 §3.4).
///
/// This record MUST be durably persisted before any side effect is accepted.
/// It serves as the authoritative proof that a given AJC has been consumed,
/// preventing duplicate consumption across restarts and replays.
///
/// # Durability Invariant
///
/// Per RFC-0027 §12 invariant 2: "AJC single-use enforcement is durable
/// for authoritative mode." This means:
///
/// - The consume record MUST be written to durable storage.
/// - The write MUST complete before the side effect is accepted.
/// - Crash-replay MUST find the record if consumption was committed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityConsumeRecordV1 {
    /// The consumed certificate's ID (primary key for uniqueness).
    pub ajc_id: Hash,

    /// Time envelope reference at consume time.
    pub consumed_time_envelope_ref: Hash,

    /// Tick at which consumption occurred.
    pub consumed_at_tick: u64,

    /// Digest of the effect selector that was authorized.
    pub effect_selector_digest: Hash,
}
