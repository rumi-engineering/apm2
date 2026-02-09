// AGENT-AUTHORED
//! Lifecycle receipts for PCAC authority operations (RFC-0027 §3.4).
//!
//! All receipts MUST include:
//! - Canonicalizer and digest metadata.
//! - Time authority bindings (`time_envelope_ref`).
//! - Signer/seal bindings required by policy tier.
//!
//! For authoritative acceptance, lifecycle receipts additionally bind:
//! - `episode_envelope_hash` (capability/budget/stop/freshness pinset).
//! - `view_commitment_hash` (ledger/context observation commitment).
//! - One admissible receipt authentication shape (direct or pointer/batched).

use serde::{Deserialize, Serialize};

use super::deny::AuthorityDenyClass;
use super::types::RiskTier;
use crate::crypto::Hash;

// =============================================================================
// MerkleProofEntry — direction-aware inclusion proof step
// =============================================================================

/// A single step in a Merkle inclusion proof carrying direction information.
///
/// Each entry records a sibling hash and whether that sibling is on the left
/// side of the pair (`sibling_is_left`). This enables the verifier to
/// reconstruct the root for both left-branch and right-branch positions
/// without ambiguity.
///
/// Aligns with the canonical `consensus::merkle::MerkleProof` direction
/// semantics where `is_left` on the sibling indicates the sibling's position.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MerkleProofEntry {
    /// The sibling hash at this level.
    pub sibling_hash: Hash,
    /// If `true`, the sibling is on the left (i.e., the current node is on
    /// the right). If `false`, the sibling is on the right (current on left).
    pub sibling_is_left: bool,
}

// =============================================================================
// Common receipt metadata
// =============================================================================

/// Canonicalizer and digest metadata for receipt verification.
///
/// Per RFC-0027 §3.4: all receipts include canonicalizer identification
/// and content digest for deterministic verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptDigestMeta {
    /// Canonicalizer identifier (e.g., `"apm2.canonicalizer.jcs"`).
    pub canonicalizer_id: String,

    /// Content digest of the receipt body (32 bytes).
    pub content_digest: Hash,
}

/// Receipt authentication shape — direct or pointer/batched.
///
/// Per RFC-0027 §6.5, authoritative acceptance requires one of these
/// authentication shapes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "auth_type", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum ReceiptAuthentication {
    /// Direct receipt authentication via `authority_seal_hash`.
    Direct {
        /// Hash of the authority seal.
        authority_seal_hash: Hash,
    },

    /// Pointer/batched receipt authentication.
    Pointer {
        /// Hash of the individual receipt.
        receipt_hash: Hash,
        /// Hash of the authority seal.
        authority_seal_hash: Hash,
        /// Direction-aware Merkle inclusion proof (required when batched).
        ///
        /// Each entry carries the sibling hash and its position (left or
        /// right), enabling correct root recomputation for both
        /// left-branch and right-branch leaves in the batch tree.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        merkle_inclusion_proof: Option<Vec<MerkleProofEntry>>,
        /// Batch root hash (when using batch descriptor path).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        receipt_batch_root_hash: Option<Hash>,
    },
}

/// Authoritative binding fields required for lifecycle receipts.
///
/// Per RFC-0027 §3.4: missing any required authoritative binding
/// MUST fail closed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativeBindings {
    /// Capability/budget/stop/freshness pinset commitment surface.
    pub episode_envelope_hash: Hash,

    /// Ledger/context observation commitment.
    pub view_commitment_hash: Hash,

    /// HTF authority witness for receipt time semantics.
    pub time_envelope_ref: Hash,

    /// Receipt authentication shape.
    pub authentication: ReceiptAuthentication,

    /// Delegated-path binding: permeability receipt hash.
    /// Required when delegated authority is consumed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permeability_receipt_hash: Option<Hash>,

    /// Delegated-path binding: delegation chain hash.
    /// Required when delegated authority is consumed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_chain_hash: Option<Hash>,
}

// =============================================================================
// AuthorityJoinReceiptV1
// =============================================================================

/// Receipt emitted upon successful authority join.
///
/// Records the creation of an AJC with all binding context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityJoinReceiptV1 {
    /// Digest metadata for verification.
    pub digest_meta: ReceiptDigestMeta,

    /// The AJC ID that was created.
    pub ajc_id: Hash,

    /// The authority join hash (digest over inputs).
    pub authority_join_hash: Hash,

    /// Risk tier at join time.
    pub risk_tier: RiskTier,

    /// Time envelope reference at join time.
    pub time_envelope_ref: Hash,

    /// Ledger anchor at join time.
    pub ledger_anchor: Hash,

    /// Tick at join time.
    pub joined_at_tick: u64,

    /// Authoritative bindings (for authoritative mode).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authoritative_bindings: Option<AuthoritativeBindings>,
}

// =============================================================================
// AuthorityRevalidateReceiptV1
// =============================================================================

/// Receipt emitted upon successful authority revalidation.
///
/// Records that the AJC was checked against current authority state
/// and remains valid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityRevalidateReceiptV1 {
    /// Digest metadata for verification.
    pub digest_meta: ReceiptDigestMeta,

    /// The AJC ID that was revalidated.
    pub ajc_id: Hash,

    /// Time envelope reference at revalidation time.
    pub time_envelope_ref: Hash,

    /// Ledger anchor at revalidation time.
    pub ledger_anchor: Hash,

    /// Revocation head hash at revalidation time.
    pub revocation_head_hash: Hash,

    /// Tick at revalidation time.
    pub revalidated_at_tick: u64,

    /// Revalidation checkpoint identifier (e.g., `before_broker`,
    /// `before_execute`).
    pub checkpoint: String,

    /// Authoritative bindings (for authoritative mode).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authoritative_bindings: Option<AuthoritativeBindings>,
}

// =============================================================================
// AuthorityConsumeReceiptV1
// =============================================================================

/// Receipt emitted upon successful authority consumption.
///
/// Records that the AJC was consumed for a specific effect. This receipt
/// is the definitive proof that authority was exercised.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityConsumeReceiptV1 {
    /// Digest metadata for verification.
    pub digest_meta: ReceiptDigestMeta,

    /// The AJC ID that was consumed.
    pub ajc_id: Hash,

    /// The intent digest that was consumed.
    pub intent_digest: Hash,

    /// Time envelope reference at consume time.
    pub time_envelope_ref: Hash,

    /// Ledger anchor at consume time.
    pub ledger_anchor: Hash,

    /// Tick at consume time.
    pub consumed_at_tick: u64,

    /// Digest of the effect selector that was authorized.
    pub effect_selector_digest: Hash,

    /// Hash of the pre-actuation receipt (when required by policy).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_actuation_receipt_hash: Option<Hash>,

    /// Authoritative bindings (for authoritative mode).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authoritative_bindings: Option<AuthoritativeBindings>,
}

// =============================================================================
// AuthorityDenyReceiptV1
// =============================================================================

/// Receipt emitted when authority is denied at any lifecycle stage.
///
/// Records the denial with enough context for replay verification
/// and audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityDenyReceiptV1 {
    /// Digest metadata for verification.
    pub digest_meta: ReceiptDigestMeta,

    /// The specific denial class.
    pub deny_class: AuthorityDenyClass,

    /// The AJC ID (if denial occurred after join).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ajc_id: Option<Hash>,

    /// Time envelope reference at denial time.
    pub time_envelope_ref: Hash,

    /// Ledger anchor at denial time.
    pub ledger_anchor: Hash,

    /// Tick at denial time.
    pub denied_at_tick: u64,

    /// The lifecycle stage at which denial occurred.
    pub denied_at_stage: LifecycleStage,
}

/// Lifecycle stage at which a denial occurred.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleStage {
    /// Denial occurred during `join`.
    Join,
    /// Denial occurred during `revalidate`.
    Revalidate,
    /// Denial occurred during `consume`.
    Consume,
}

impl std::fmt::Display for LifecycleStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Join => write!(f, "join"),
            Self::Revalidate => write!(f, "revalidate"),
            Self::Consume => write!(f, "consume"),
        }
    }
}
