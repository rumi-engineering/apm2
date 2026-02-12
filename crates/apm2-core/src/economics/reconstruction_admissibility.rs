// AGENT-AUTHORED
//! Tiered erasure+BFT reconstruction admissibility for RFC-0029 REQ-0010.
//!
//! Implements:
//! - Erasure decode validity checking with profile-bound reconstruction.
//! - BFT quorum certification over recovered digests.
//! - [`SourceTrustSnapshot`] digest-match verification (CAS root, ledger head,
//!   policy signatures).
//! - [`ReconstructionAdmissibilityReceiptV1`] binding to TP-EIO29-001 and
//!   TP-EIO29-004 temporal authority references, carrying `time_authority_ref`,
//!   `window_ref`, `digest_proof_ref`, and `quorum_cert_ref`.
//! - Deterministic deny diagnostics for reconstruction failure modes.
//!
//! # Security Domain
//!
//! `DOMAIN_SECURITY` and `DOMAIN_RELIABILITY` are in scope. All unknown,
//! missing, stale, or unverifiable reconstruction states fail closed.
//!
//! # Temporal Model
//!
//! Receipts carry `time_authority_ref` and `window_ref` hashes binding them
//! to HTF evaluation windows. Receipts are Ed25519-signed with domain
//! separation to prevent cross-protocol replay. The canonical temporal
//! predicates for this requirement are `TP-EIO29-001` and `TP-EIO29-004`.
//!
//! # Fail-Closed Semantics
//!
//! Missing recovery proof components (erasure profile, quorum certificate,
//! source trust snapshot, temporal references) all result in deterministic
//! deny outcomes with structured diagnostics.

use std::collections::HashSet;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use subtle::ConstantTimeEq;
use thiserror::Error;

use crate::crypto::{Hash, Signer, SignerError, parse_signature, parse_verifying_key};
use crate::fac::{sign_with_domain, verify_with_domain};
use crate::pcac::MAX_REASON_LENGTH;
use crate::pcac::temporal_arbitration::TemporalPredicateId;

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of erasure shards per reconstruction profile.
pub const MAX_ERASURE_SHARDS: usize = 256;

/// Maximum number of quorum signers per BFT certificate.
pub const MAX_QUORUM_SIGNERS: usize = 128;

/// Maximum number of reconstruction receipts per evaluation.
pub const MAX_RECONSTRUCTION_RECEIPTS: usize = 256;

/// Maximum number of policy signature entries in a source trust snapshot.
pub const MAX_POLICY_SIGNATURES: usize = 64;

/// Maximum string length for receipt identifiers.
pub const MAX_RECEIPT_ID_LENGTH: usize = 256;

/// Maximum string length for boundary identifiers.
pub const MAX_BOUNDARY_ID_LENGTH: usize = 256;

/// Maximum string length for actor identifiers.
pub const MAX_ACTOR_ID_LENGTH: usize = 256;

/// Maximum string length for tier identifiers.
pub const MAX_TIER_ID_LENGTH: usize = 128;

/// Maximum string length for profile identifiers.
pub const MAX_PROFILE_ID_LENGTH: usize = 256;

/// Maximum string length for deny reason codes.
///
/// Re-uses the canonical [`MAX_REASON_LENGTH`] from PCAC types to ensure
/// consistent bounds across the codebase.
pub const MAX_DENY_REASON_LENGTH: usize = MAX_REASON_LENGTH;

/// Minimum quorum fraction numerator (2/3 BFT threshold).
/// The quorum threshold is `MIN_QUORUM_NUMERATOR / MIN_QUORUM_DENOMINATOR`.
pub const MIN_QUORUM_NUMERATOR: usize = 2;

/// Minimum quorum fraction denominator.
pub const MIN_QUORUM_DENOMINATOR: usize = 3;

/// Domain prefix for reconstruction admissibility receipt signing.
///
/// Domain separation ensures that a signature for a reconstruction
/// admissibility receipt cannot be replayed as another receipt type.
pub const RECONSTRUCTION_ADMISSIBILITY_RECEIPT_PREFIX: &[u8] =
    b"RECONSTRUCTION_ADMISSIBILITY_RECEIPT:";

const ZERO_HASH: Hash = [0u8; 32];

// ============================================================================
// Deny reason constants (stable strings for replay verification)
// ============================================================================

/// Deny: erasure profile is missing.
pub const DENY_ERASURE_PROFILE_MISSING: &str = "reconstruction_erasure_profile_missing";
/// Deny: erasure profile has zero digest.
pub const DENY_ERASURE_PROFILE_DIGEST_ZERO: &str = "reconstruction_erasure_profile_digest_zero";
/// Deny: erasure profile tier ID is empty or oversized.
pub const DENY_ERASURE_TIER_ID_INVALID: &str = "reconstruction_erasure_tier_id_invalid";
/// Deny: erasure profile ID is empty or oversized.
pub const DENY_ERASURE_PROFILE_ID_INVALID: &str = "reconstruction_erasure_profile_id_invalid";
/// Deny: erasure shard count exceeds maximum.
pub const DENY_ERASURE_SHARDS_EXCEEDED: &str = "reconstruction_erasure_shards_exceeded";
/// Deny: erasure total shards is zero.
pub const DENY_ERASURE_TOTAL_SHARDS_ZERO: &str = "reconstruction_erasure_total_shards_zero";
/// Deny: erasure required shards is zero.
pub const DENY_ERASURE_REQUIRED_SHARDS_ZERO: &str = "reconstruction_erasure_required_shards_zero";
/// Deny: erasure required shards exceeds total.
pub const DENY_ERASURE_REQUIRED_EXCEEDS_TOTAL: &str =
    "reconstruction_erasure_required_exceeds_total";
/// Deny: erasure available shards below required threshold.
pub const DENY_ERASURE_INSUFFICIENT_SHARDS: &str = "reconstruction_erasure_insufficient_shards";
/// Deny: erasure shard digest is zero.
pub const DENY_ERASURE_SHARD_DIGEST_ZERO: &str = "reconstruction_erasure_shard_digest_zero";
/// Deny: erasure recovered digest does not match expected.
pub const DENY_ERASURE_RECOVERED_DIGEST_MISMATCH: &str =
    "reconstruction_erasure_recovered_digest_mismatch";
/// Deny: BFT quorum certificate is missing.
pub const DENY_QUORUM_CERT_MISSING: &str = "reconstruction_quorum_cert_missing";
/// Deny: BFT quorum certificate digest is zero.
pub const DENY_QUORUM_CERT_DIGEST_ZERO: &str = "reconstruction_quorum_cert_digest_zero";
/// Deny: BFT quorum total nodes is zero.
pub const DENY_QUORUM_TOTAL_NODES_ZERO: &str = "reconstruction_quorum_total_nodes_zero";
/// Deny: BFT quorum has insufficient signers (below 2f+1 threshold).
pub const DENY_QUORUM_INSUFFICIENT: &str = "reconstruction_quorum_insufficient";
/// Deny: BFT quorum signer count exceeds maximum.
pub const DENY_QUORUM_SIGNERS_EXCEEDED: &str = "reconstruction_quorum_signers_exceeded";
/// Deny: BFT quorum signer key is zero.
pub const DENY_QUORUM_SIGNER_KEY_ZERO: &str = "reconstruction_quorum_signer_key_zero";
/// Deny: BFT quorum signer is not in the trusted set.
pub const DENY_QUORUM_SIGNER_UNTRUSTED: &str = "reconstruction_quorum_signer_untrusted";
/// Deny: BFT quorum signer signature is invalid.
pub const DENY_QUORUM_SIGNATURE_INVALID: &str = "reconstruction_quorum_signature_invalid";
/// Deny: BFT quorum certified digest does not match recovered digest.
pub const DENY_QUORUM_DIGEST_MISMATCH: &str = "reconstruction_quorum_digest_mismatch";
/// Deny: BFT quorum has duplicate signer keys.
pub const DENY_QUORUM_DUPLICATE_SIGNER: &str = "reconstruction_quorum_duplicate_signer";
/// Deny: source trust snapshot is missing.
pub const DENY_TRUST_SNAPSHOT_MISSING: &str = "reconstruction_trust_snapshot_missing";
/// Deny: source trust snapshot CAS root is zero.
pub const DENY_TRUST_SNAPSHOT_CAS_ROOT_ZERO: &str = "reconstruction_trust_snapshot_cas_root_zero";
/// Deny: source trust snapshot ledger head is zero.
pub const DENY_TRUST_SNAPSHOT_LEDGER_HEAD_ZERO: &str =
    "reconstruction_trust_snapshot_ledger_head_zero";
/// Deny: source trust snapshot policy digest is zero.
pub const DENY_TRUST_SNAPSHOT_POLICY_DIGEST_ZERO: &str =
    "reconstruction_trust_snapshot_policy_digest_zero";
/// Deny: source trust snapshot has too many policy signatures.
pub const DENY_TRUST_SNAPSHOT_POLICY_SIGS_EXCEEDED: &str =
    "reconstruction_trust_snapshot_policy_signatures_exceeded";
/// Deny: source trust snapshot policy signature count is zero.
pub const DENY_TRUST_SNAPSHOT_NO_POLICY_SIGS: &str =
    "reconstruction_trust_snapshot_no_policy_signatures";
/// Deny: source trust snapshot digest does not match recovered digest.
pub const DENY_TRUST_SNAPSHOT_DIGEST_MISMATCH: &str =
    "reconstruction_trust_snapshot_digest_mismatch";
/// Deny: source trust snapshot content hash is zero.
pub const DENY_TRUST_SNAPSHOT_CONTENT_HASH_ZERO: &str =
    "reconstruction_trust_snapshot_content_hash_zero";
/// Deny: reconstruction receipt is missing.
pub const DENY_RECONSTRUCTION_RECEIPT_MISSING: &str = "reconstruction_receipt_missing";
/// Deny: reconstruction receipt count exceeds maximum.
pub const DENY_RECONSTRUCTION_RECEIPTS_EXCEEDED: &str = "reconstruction_receipts_exceeded";
/// Deny: reconstruction receipt ID is empty or oversized.
pub const DENY_RECONSTRUCTION_RECEIPT_ID_INVALID: &str = "reconstruction_receipt_id_invalid";
/// Deny: reconstruction receipt boundary ID is empty or oversized.
pub const DENY_RECONSTRUCTION_RECEIPT_BOUNDARY_ID_INVALID: &str =
    "reconstruction_receipt_boundary_id_invalid";
/// Deny: reconstruction receipt time authority reference is zero.
pub const DENY_RECONSTRUCTION_RECEIPT_TIME_AUTH_ZERO: &str =
    "reconstruction_receipt_time_authority_ref_zero";
/// Deny: reconstruction receipt window reference is zero.
pub const DENY_RECONSTRUCTION_RECEIPT_WINDOW_ZERO: &str = "reconstruction_receipt_window_ref_zero";
/// Deny: reconstruction receipt digest proof reference is zero.
pub const DENY_RECONSTRUCTION_RECEIPT_DIGEST_PROOF_ZERO: &str =
    "reconstruction_receipt_digest_proof_ref_zero";
/// Deny: reconstruction receipt quorum cert reference is zero.
pub const DENY_RECONSTRUCTION_RECEIPT_QUORUM_CERT_ZERO: &str =
    "reconstruction_receipt_quorum_cert_ref_zero";
/// Deny: reconstruction receipt content hash is zero.
pub const DENY_RECONSTRUCTION_RECEIPT_CONTENT_HASH_ZERO: &str =
    "reconstruction_receipt_content_hash_zero";
/// Deny: reconstruction receipt signer key is zero.
pub const DENY_RECONSTRUCTION_RECEIPT_SIGNER_ZERO: &str = "reconstruction_receipt_signer_key_zero";
/// Deny: reconstruction receipt signature is invalid.
pub const DENY_RECONSTRUCTION_RECEIPT_SIGNATURE_INVALID: &str =
    "reconstruction_receipt_signature_invalid";
/// Deny: reconstruction receipt signer is not in the trusted set.
pub const DENY_RECONSTRUCTION_RECEIPT_SIGNER_UNTRUSTED: &str =
    "reconstruction_receipt_signer_untrusted";
/// Deny: reconstruction receipt boundary mismatch.
pub const DENY_RECONSTRUCTION_RECEIPT_BOUNDARY_MISMATCH: &str =
    "reconstruction_receipt_boundary_mismatch";
/// Deny: reconstruction receipt time authority reference mismatch.
pub const DENY_RECONSTRUCTION_RECEIPT_TIME_AUTH_MISMATCH: &str =
    "reconstruction_receipt_time_authority_ref_mismatch";
/// Deny: reconstruction receipt window reference mismatch.
pub const DENY_RECONSTRUCTION_RECEIPT_WINDOW_MISMATCH: &str =
    "reconstruction_receipt_window_ref_mismatch";
/// Deny: reconstruction receipt not admitted.
pub const DENY_RECONSTRUCTION_RECEIPT_NOT_ADMITTED: &str = "reconstruction_receipt_not_admitted";
/// Deny: reconstruction receipt duplicate ID detected.
pub const DENY_RECONSTRUCTION_RECEIPT_DUPLICATE_ID: &str = "reconstruction_receipt_duplicate_id";
/// Deny: unknown reconstruction state.
pub const DENY_UNKNOWN_RECONSTRUCTION_STATE: &str = "reconstruction_unknown_state";

// ============================================================================
// Bounded serde helpers (OOM-safe deserialization)
// ============================================================================

/// Deserializes a `String` with a hard length bound to prevent OOM during
/// deserialization from untrusted input.
///
/// Uses a Visitor-based implementation so that `visit_str` checks the length
/// BEFORE allocating (calling `to_owned()`), closing the Check-After-Allocate
/// OOM-DoS vector present in naive `String::deserialize` + post-check patterns.
fn deserialize_bounded_string<'de, D>(
    deserializer: D,
    max_len: usize,
    field_name: &'static str,
) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    struct BoundedStringVisitor {
        max_len: usize,
        field_name: &'static str,
    }

    impl Visitor<'_> for BoundedStringVisitor {
        type Value = String;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(
                formatter,
                "a string of at most {} bytes for field '{}'",
                self.max_len, self.field_name
            )
        }

        fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
            if value.len() > self.max_len {
                Err(E::custom(format!(
                    "string field '{}' exceeds maximum length ({} > {})",
                    self.field_name,
                    value.len(),
                    self.max_len
                )))
            } else {
                // Length validated BEFORE allocation.
                Ok(value.to_owned())
            }
        }

        fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
            if value.len() > self.max_len {
                Err(E::custom(format!(
                    "string field '{}' exceeds maximum length ({} > {})",
                    self.field_name,
                    value.len(),
                    self.max_len
                )))
            } else {
                // Already owned -- no additional allocation needed.
                Ok(value)
            }
        }
    }

    deserializer.deserialize_string(BoundedStringVisitor {
        max_len,
        field_name,
    })
}

// Field-specific deserializers for `#[serde(deserialize_with = "...")]`.

fn deser_receipt_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_string(deserializer, MAX_RECEIPT_ID_LENGTH, "receipt_id")
}

fn deser_boundary_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_string(deserializer, MAX_BOUNDARY_ID_LENGTH, "boundary_id")
}

fn deser_signer_actor_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_string(deserializer, MAX_ACTOR_ID_LENGTH, "signer_actor_id")
}

fn deser_deny_reason<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_string(deserializer, MAX_DENY_REASON_LENGTH, "reason")
}

fn deser_defect_boundary_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_string(deserializer, MAX_BOUNDARY_ID_LENGTH, "boundary_id")
}

fn deser_tier_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_string(deserializer, MAX_TIER_ID_LENGTH, "tier_id")
}

fn deser_profile_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_string(deserializer, MAX_PROFILE_ID_LENGTH, "profile_id")
}

// ============================================================================
// Error types
// ============================================================================

/// Errors from reconstruction admissibility operations.
#[derive(Debug, Error)]
pub enum ReconstructionAdmissibilityError {
    /// Receipt field validation failed.
    #[error("receipt validation: {reason}")]
    ValidationFailed {
        /// Human-readable description.
        reason: String,
    },
    /// Signature creation or verification failed.
    #[error("signature error: {detail}")]
    SignatureError {
        /// Details of the signature failure.
        detail: String,
    },
    /// A required field is missing or empty.
    #[error("required field missing: {field}")]
    RequiredFieldMissing {
        /// Name of the missing field.
        field: String,
    },
    /// A field value exceeds its maximum allowed length.
    #[error("field '{field}' exceeds maximum length ({actual} > {max})")]
    FieldTooLong {
        /// Name of the violating field.
        field: String,
        /// Actual length observed.
        actual: usize,
        /// Maximum allowed length.
        max: usize,
    },
    /// A hash field is zero.
    #[error("field '{field}' must not be zero")]
    ZeroHash {
        /// Name of the violating field.
        field: String,
    },
    /// Collection exceeds capacity.
    #[error("collection '{collection}' exceeds capacity ({count} > {max})")]
    CollectionExceeded {
        /// Collection name.
        collection: String,
        /// Current count.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },
}

// ============================================================================
// ErasureProfile
// ============================================================================

/// Erasure coding profile declaring shard requirements for tier reconstruction.
///
/// Represents the declared erasure profile for a mandatory artifact tier.
/// Reconstruction requires at least `required_shards` of `total_shards`
/// available shards to decode.
///
/// # Invariants
///
/// - `total_shards > 0`
/// - `required_shards > 0`
/// - `required_shards <= total_shards`
/// - `total_shards <= MAX_ERASURE_SHARDS`
/// - All shard digests are non-zero
/// - `profile_digest` is non-zero (content-addressed profile binding)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErasureProfile {
    /// Identifier for the artifact tier (e.g., `"source_snapshots"`,
    /// `"policy_roots"`).
    #[serde(deserialize_with = "deser_tier_id")]
    pub tier_id: String,
    /// Identifier for this erasure profile.
    #[serde(deserialize_with = "deser_profile_id")]
    pub profile_id: String,
    /// Total number of shards in the erasure coding scheme.
    pub total_shards: u32,
    /// Minimum number of shards required for reconstruction.
    pub required_shards: u32,
    /// Digests of available (recovered) shards.
    pub available_shard_digests: Vec<Hash>,
    /// Content-addressed digest of the erasure profile declaration.
    pub profile_digest: Hash,
    /// Expected digest of the fully reconstructed artifact.
    pub expected_artifact_digest: Hash,
}

/// Result of erasure decode validity checking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErasureDecodeResult {
    /// Whether the erasure decode produced a valid artifact.
    pub decode_valid: bool,
    /// Digest of the recovered artifact (if decode was successful).
    pub recovered_digest: Hash,
    /// Number of available shards used.
    pub shards_used: u32,
}

// ============================================================================
// BftQuorumCertificate
// ============================================================================

/// BFT quorum certificate over a recovered digest.
///
/// Represents a BFT quorum certification where at least 2f+1 nodes
/// have signed attestations over the same recovered digest.
///
/// # Invariants
///
/// - `total_nodes > 0`
/// - `signers` has at least `ceil(2 * total_nodes / 3)` entries
/// - `signers.len() <= MAX_QUORUM_SIGNERS`
/// - All signer keys are non-zero
/// - All signer keys are unique (no duplicate signers)
/// - All signatures are valid Ed25519 signatures over the certified digest
/// - `certified_digest` is non-zero
/// - `cert_digest` is non-zero (content hash of the certificate)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BftQuorumCertificate {
    /// Total number of nodes in the BFT quorum.
    pub total_nodes: u32,
    /// Signers who have certified the recovered digest.
    pub signers: Vec<QuorumSigner>,
    /// The digest that has been quorum-certified.
    pub certified_digest: Hash,
    /// Content-addressed hash of the certificate.
    pub cert_digest: Hash,
}

/// Individual signer entry in a BFT quorum certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuorumSigner {
    /// Ed25519 public key of the signer (32 bytes).
    #[serde(with = "serde_bytes")]
    pub signer_key: [u8; 32],
    /// Ed25519 signature over the certified digest (64 bytes).
    #[serde(with = "serde_bytes")]
    pub signature: [u8; 64],
}

// ============================================================================
// SourceTrustSnapshot
// ============================================================================

/// Source trust snapshot binding for reconstruction admission.
///
/// Represents the authoritative trust bindings (CAS root, ledger head,
/// policy signatures) that the recovered state must match.
///
/// # Invariants
///
/// - `cas_root` is non-zero
/// - `ledger_head` is non-zero
/// - `policy_digest` is non-zero
/// - `policy_signatures` has at least one entry
/// - `policy_signatures.len() <= MAX_POLICY_SIGNATURES`
/// - `content_hash` is non-zero
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceTrustSnapshot {
    /// CAS root hash of the trusted source state.
    pub cas_root: Hash,
    /// Ledger head hash of the trusted source state.
    pub ledger_head: Hash,
    /// Combined digest of policy signatures.
    pub policy_digest: Hash,
    /// Individual policy signature entries (each a hash binding).
    pub policy_signatures: Vec<Hash>,
    /// Content-addressed hash of the snapshot.
    pub content_hash: Hash,
}

// ============================================================================
// ReconstructionAdmissibilityReceiptV1
// ============================================================================

/// Durable, signed receipt proving reconstruction admissibility with full
/// erasure+BFT+digest closure within an HTF window.
///
/// Implements `ReconstructionAdmissibilityReceiptV1` from RFC-0029 REQ-0010.
/// Each receipt is domain-separated and Ed25519-signed, binding a
/// reconstruction admissibility decision to specific temporal authority,
/// evaluation window, digest proof, and quorum certificate references.
///
/// # Fields
///
/// - `receipt_id`: unique identifier for this receipt instance.
/// - `boundary_id`: boundary context (must match evaluation window).
/// - `tier_id`: artifact tier identifier.
/// - `admitted`: whether reconstruction is admissible.
/// - `time_authority_ref`: hash of the time authority envelope (TP-EIO29-001).
/// - `window_ref`: hash of the HTF evaluation window.
/// - `digest_proof_ref`: hash of the digest proof binding.
/// - `quorum_cert_ref`: hash of the BFT quorum certificate.
/// - `content_hash`: content-addressed hash of the receipt payload.
/// - `signer_actor_id`: identity of the signing actor.
/// - `signer_key`: Ed25519 public key bytes.
/// - `signature`: Ed25519 signature over domain-separated canonical bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconstructionAdmissibilityReceiptV1 {
    /// Unique receipt identifier.
    #[serde(deserialize_with = "deser_receipt_id")]
    pub receipt_id: String,
    /// Boundary identifier (must match evaluation context).
    #[serde(deserialize_with = "deser_boundary_id")]
    pub boundary_id: String,
    /// Artifact tier identifier.
    #[serde(deserialize_with = "deser_tier_id")]
    pub tier_id: String,
    /// Whether reconstruction is admissible.
    pub admitted: bool,
    /// Time authority reference hash (HTF binding, TP-EIO29-001).
    pub time_authority_ref: Hash,
    /// HTF evaluation window reference hash.
    pub window_ref: Hash,
    /// Digest proof reference hash.
    pub digest_proof_ref: Hash,
    /// BFT quorum certificate reference hash.
    pub quorum_cert_ref: Hash,
    /// Caller-provided digest of external content (not self-referential).
    ///
    /// This hash covers the external payload that this receipt attests to.
    /// It is NOT a hash of the receipt itself. Integrity is protected by the
    /// Ed25519 signature over canonical bytes, which includes `content_hash`.
    /// The non-zero check in `validate()` prevents accidental omission.
    pub content_hash: Hash,
    /// Identity of the signing actor.
    #[serde(deserialize_with = "deser_signer_actor_id")]
    pub signer_actor_id: String,
    /// Ed25519 public key of the signer (32 bytes).
    #[serde(with = "serde_bytes")]
    pub signer_key: [u8; 32],
    /// Ed25519 signature over domain-separated canonical bytes (64 bytes).
    #[serde(with = "serde_bytes")]
    pub signature: [u8; 64],
}

impl ReconstructionAdmissibilityReceiptV1 {
    /// Creates and signs a reconstruction admissibility receipt.
    ///
    /// String fields are validated for length BEFORE allocation to prevent
    /// unbounded memory allocation from oversized inputs.
    ///
    /// # Errors
    ///
    /// Returns an error if any field fails validation or signing fails.
    #[allow(clippy::too_many_arguments)]
    pub fn create_signed(
        receipt_id: &str,
        boundary_id: &str,
        tier_id: &str,
        admitted: bool,
        time_authority_ref: Hash,
        window_ref: Hash,
        digest_proof_ref: Hash,
        quorum_cert_ref: Hash,
        content_hash: Hash,
        signer_actor_id: &str,
        signer: &Signer,
    ) -> Result<Self, ReconstructionAdmissibilityError> {
        // Validate length BEFORE allocating to prevent DoS via oversized input.
        validate_required_string("receipt_id", receipt_id, MAX_RECEIPT_ID_LENGTH)?;
        validate_required_string("boundary_id", boundary_id, MAX_BOUNDARY_ID_LENGTH)?;
        validate_required_string("tier_id", tier_id, MAX_TIER_ID_LENGTH)?;
        validate_required_string("signer_actor_id", signer_actor_id, MAX_ACTOR_ID_LENGTH)?;
        validate_non_zero_hash("time_authority_ref", &time_authority_ref)?;
        validate_non_zero_hash("window_ref", &window_ref)?;
        validate_non_zero_hash("digest_proof_ref", &digest_proof_ref)?;
        validate_non_zero_hash("quorum_cert_ref", &quorum_cert_ref)?;
        validate_non_zero_hash("content_hash", &content_hash)?;

        let mut receipt = Self {
            receipt_id: receipt_id.to_string(),
            boundary_id: boundary_id.to_string(),
            tier_id: tier_id.to_string(),
            admitted,
            time_authority_ref,
            window_ref,
            digest_proof_ref,
            quorum_cert_ref,
            content_hash,
            signer_actor_id: signer_actor_id.to_string(),
            signer_key: signer.public_key_bytes(),
            signature: [0u8; 64],
        };

        let sig = sign_with_domain(
            signer,
            RECONSTRUCTION_ADMISSIBILITY_RECEIPT_PREFIX,
            &receipt.canonical_bytes(),
        );
        receipt.signature = sig.to_bytes();
        Ok(receipt)
    }

    /// Returns canonical bytes for signing/verification.
    ///
    /// Format: length-prefixed strings + fixed-size fields, all big-endian.
    /// Includes all normative fields for complete preimage framing.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        // Fixed-size fields: admitted(1) + time_authority_ref(32) +
        // window_ref(32) + digest_proof_ref(32) + quorum_cert_ref(32) +
        // content_hash(32) = 161
        // Four length-prefixed strings: 4 * 4 = 16 bytes of length headers
        let estimated_size = 161
            + 16
            + self.receipt_id.len()
            + self.boundary_id.len()
            + self.tier_id.len()
            + self.signer_actor_id.len();
        let mut bytes = Vec::with_capacity(estimated_size);

        bytes.extend_from_slice(&(self.receipt_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.receipt_id.as_bytes());

        bytes.extend_from_slice(&(self.boundary_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.boundary_id.as_bytes());

        bytes.extend_from_slice(&(self.tier_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.tier_id.as_bytes());

        bytes.push(u8::from(self.admitted));
        bytes.extend_from_slice(&self.time_authority_ref);
        bytes.extend_from_slice(&self.window_ref);
        bytes.extend_from_slice(&self.digest_proof_ref);
        bytes.extend_from_slice(&self.quorum_cert_ref);
        bytes.extend_from_slice(&self.content_hash);

        bytes.extend_from_slice(&(self.signer_actor_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.signer_actor_id.as_bytes());

        bytes
    }

    /// Verifies the receipt's Ed25519 signature.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature is invalid.
    pub fn verify_signature(&self) -> Result<(), ReconstructionAdmissibilityError> {
        if self.signer_key == [0u8; 32] {
            return Err(ReconstructionAdmissibilityError::SignatureError {
                detail: DENY_RECONSTRUCTION_RECEIPT_SIGNER_ZERO.to_string(),
            });
        }

        let key = parse_verifying_key(&self.signer_key).map_err(|e: SignerError| {
            ReconstructionAdmissibilityError::SignatureError {
                detail: e.to_string(),
            }
        })?;

        let sig = parse_signature(&self.signature).map_err(|e: SignerError| {
            ReconstructionAdmissibilityError::SignatureError {
                detail: e.to_string(),
            }
        })?;

        verify_with_domain(
            &key,
            RECONSTRUCTION_ADMISSIBILITY_RECEIPT_PREFIX,
            &self.canonical_bytes(),
            &sig,
        )
        .map_err(
            |e: SignerError| ReconstructionAdmissibilityError::SignatureError {
                detail: e.to_string(),
            },
        )
    }

    /// Validates structural invariants without verifying the signature.
    ///
    /// # Errors
    ///
    /// Returns a stable deny reason for any structural violation.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.receipt_id.is_empty() || self.receipt_id.len() > MAX_RECEIPT_ID_LENGTH {
            return Err(DENY_RECONSTRUCTION_RECEIPT_ID_INVALID);
        }
        if self.boundary_id.is_empty() || self.boundary_id.len() > MAX_BOUNDARY_ID_LENGTH {
            return Err(DENY_RECONSTRUCTION_RECEIPT_BOUNDARY_ID_INVALID);
        }
        if is_zero_hash(&self.time_authority_ref) {
            return Err(DENY_RECONSTRUCTION_RECEIPT_TIME_AUTH_ZERO);
        }
        if is_zero_hash(&self.window_ref) {
            return Err(DENY_RECONSTRUCTION_RECEIPT_WINDOW_ZERO);
        }
        if is_zero_hash(&self.digest_proof_ref) {
            return Err(DENY_RECONSTRUCTION_RECEIPT_DIGEST_PROOF_ZERO);
        }
        if is_zero_hash(&self.quorum_cert_ref) {
            return Err(DENY_RECONSTRUCTION_RECEIPT_QUORUM_CERT_ZERO);
        }
        if is_zero_hash(&self.content_hash) {
            return Err(DENY_RECONSTRUCTION_RECEIPT_CONTENT_HASH_ZERO);
        }
        if self.signer_key == [0u8; 32] {
            return Err(DENY_RECONSTRUCTION_RECEIPT_SIGNER_ZERO);
        }
        if self.signature.ct_eq(&[0u8; 64]).unwrap_u8() == 1 {
            return Err(DENY_RECONSTRUCTION_RECEIPT_SIGNATURE_INVALID);
        }
        Ok(())
    }
}

// ============================================================================
// Deny defect
// ============================================================================

/// Deny defect emitted when a reconstruction admissibility check fails.
///
/// Provides auditable structured evidence for why an admission was denied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconstructionDenyDefect {
    /// Stable deny reason code.
    #[serde(deserialize_with = "deser_deny_reason")]
    pub reason: String,
    /// The temporal predicate that was violated.
    pub predicate_id: TemporalPredicateId,
    /// Boundary context of the denial.
    #[serde(deserialize_with = "deser_defect_boundary_id")]
    pub boundary_id: String,
    /// Tick at which the denial occurred.
    pub denied_at_tick: u64,
    /// Hash of the time authority envelope (if available).
    pub envelope_hash: Hash,
    /// Window reference hash (if available).
    pub window_ref: Hash,
    /// Failure mode classification for deterministic diagnostics.
    pub failure_mode: ReconstructionFailureMode,
}

/// Classification of reconstruction failure modes for deterministic
/// diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconstructionFailureMode {
    /// Erasure decode failed (insufficient shards, shard corruption).
    ErasureDecodeFailed,
    /// BFT quorum certification failed (insufficient signers, invalid sigs).
    QuorumCertificationFailed,
    /// Digest mismatch between recovered state and trust snapshot.
    DigestMismatch,
    /// Missing recovery proof component.
    MissingProofComponent,
    /// Temporal authority reference invalid or unresolved.
    TemporalAuthorityInvalid,
    /// Receipt structural or signature validation failed.
    ReceiptValidationFailed,
}

// ============================================================================
// Erasure decode validation
// ============================================================================

/// Validates erasure decode validity for a reconstruction profile.
///
/// Checks:
/// 1. Erasure profile is present (fail-closed).
/// 2. Profile has valid `tier_id` and `profile_id`.
/// 3. Total and required shard counts are valid.
/// 4. Available shards meet the required threshold.
/// 5. All shard digests are non-zero.
/// 6. Profile digest is non-zero.
/// 7. Recovered digest matches expected artifact digest.
///
/// # Errors
///
/// Returns a stable deny reason string for any violation.
pub fn validate_erasure_decode(
    profile: Option<&ErasureProfile>,
    decode_result: Option<&ErasureDecodeResult>,
) -> Result<(), &'static str> {
    // Fail-closed: missing erasure profile.
    let profile = profile.ok_or(DENY_ERASURE_PROFILE_MISSING)?;

    // Structural validation.
    if profile.tier_id.is_empty() || profile.tier_id.len() > MAX_TIER_ID_LENGTH {
        return Err(DENY_ERASURE_TIER_ID_INVALID);
    }
    if profile.profile_id.is_empty() || profile.profile_id.len() > MAX_PROFILE_ID_LENGTH {
        return Err(DENY_ERASURE_PROFILE_ID_INVALID);
    }
    if is_zero_hash(&profile.profile_digest) {
        return Err(DENY_ERASURE_PROFILE_DIGEST_ZERO);
    }
    if profile.total_shards == 0 {
        return Err(DENY_ERASURE_TOTAL_SHARDS_ZERO);
    }
    if profile.required_shards == 0 {
        return Err(DENY_ERASURE_REQUIRED_SHARDS_ZERO);
    }
    if profile.required_shards > profile.total_shards {
        return Err(DENY_ERASURE_REQUIRED_EXCEEDS_TOTAL);
    }
    if profile.total_shards as usize > MAX_ERASURE_SHARDS {
        return Err(DENY_ERASURE_SHARDS_EXCEEDED);
    }
    if profile.available_shard_digests.len() > MAX_ERASURE_SHARDS {
        return Err(DENY_ERASURE_SHARDS_EXCEEDED);
    }

    // All shard digests must be non-zero.
    for shard_digest in &profile.available_shard_digests {
        if is_zero_hash(shard_digest) {
            return Err(DENY_ERASURE_SHARD_DIGEST_ZERO);
        }
    }

    // Check available shards meet the required threshold.
    // Safe: available_shard_digests.len() <= MAX_ERASURE_SHARDS(256) which fits
    // u32.
    #[allow(clippy::cast_possible_truncation)]
    let available_count = profile.available_shard_digests.len() as u32;
    if available_count < profile.required_shards {
        return Err(DENY_ERASURE_INSUFFICIENT_SHARDS);
    }

    // Validate decode result if present.
    let decode = decode_result.ok_or(DENY_ERASURE_PROFILE_MISSING)?;

    if !decode.decode_valid {
        return Err(DENY_ERASURE_INSUFFICIENT_SHARDS);
    }

    if is_zero_hash(&decode.recovered_digest) {
        return Err(DENY_ERASURE_RECOVERED_DIGEST_MISMATCH);
    }

    // Recovered digest must match expected artifact digest (constant-time).
    if decode
        .recovered_digest
        .ct_eq(&profile.expected_artifact_digest)
        .unwrap_u8()
        == 0
    {
        return Err(DENY_ERASURE_RECOVERED_DIGEST_MISMATCH);
    }

    Ok(())
}

// ============================================================================
// BFT quorum certification validation
// ============================================================================

/// Validates BFT quorum certification over a recovered digest.
///
/// Checks:
/// 1. Quorum certificate is present (fail-closed).
/// 2. Total nodes count is non-zero.
/// 3. Signer count is within bounds.
/// 4. Signer count meets the 2f+1 BFT threshold (ceil(2n/3)).
/// 5. All signer keys are non-zero.
/// 6. All signer keys are unique (no duplicate signers).
/// 7. All signers are in the trusted signer set (constant-time).
/// 8. All signatures are valid Ed25519 signatures over the certified digest.
/// 9. Certified digest is non-zero.
/// 10. Certificate content hash is non-zero.
/// 11. Certified digest matches the recovered digest (constant-time).
///
/// # Errors
///
/// Returns a stable deny reason string for any violation.
pub fn validate_bft_quorum_certification(
    cert: Option<&BftQuorumCertificate>,
    recovered_digest: &Hash,
    trusted_quorum_keys: &[[u8; 32]],
) -> Result<(), &'static str> {
    // Fail-closed: missing quorum certificate.
    let cert = cert.ok_or(DENY_QUORUM_CERT_MISSING)?;

    if is_zero_hash(&cert.certified_digest) {
        return Err(DENY_QUORUM_CERT_DIGEST_ZERO);
    }
    if is_zero_hash(&cert.cert_digest) {
        return Err(DENY_QUORUM_CERT_DIGEST_ZERO);
    }
    if cert.total_nodes == 0 {
        return Err(DENY_QUORUM_TOTAL_NODES_ZERO);
    }
    if cert.signers.len() > MAX_QUORUM_SIGNERS {
        return Err(DENY_QUORUM_SIGNERS_EXCEEDED);
    }

    // BFT quorum threshold: ceil(2n/3).
    let total = cert.total_nodes as usize;
    let required = (MIN_QUORUM_NUMERATOR * total).div_ceil(MIN_QUORUM_DENOMINATOR);
    if cert.signers.len() < required {
        return Err(DENY_QUORUM_INSUFFICIENT);
    }

    // Validate individual signers.
    let mut seen_keys: HashSet<[u8; 32]> = HashSet::new();

    for signer_entry in &cert.signers {
        // Signer key must be non-zero.
        if signer_entry.signer_key == [0u8; 32] {
            return Err(DENY_QUORUM_SIGNER_KEY_ZERO);
        }

        // No duplicate signer keys.
        if !seen_keys.insert(signer_entry.signer_key) {
            return Err(DENY_QUORUM_DUPLICATE_SIGNER);
        }

        // Verify signer is in trusted set (non-short-circuiting constant-time
        // fold to prevent timing side-channel leaking signer position).
        let signer_trusted = trusted_quorum_keys.iter().fold(0u8, |acc, ts| {
            acc | ts.ct_eq(&signer_entry.signer_key).unwrap_u8()
        });
        if signer_trusted == 0 {
            return Err(DENY_QUORUM_SIGNER_UNTRUSTED);
        }

        // Verify Ed25519 signature over the certified digest.
        let key = parse_verifying_key(&signer_entry.signer_key)
            .map_err(|_| DENY_QUORUM_SIGNATURE_INVALID)?;
        let sig =
            parse_signature(&signer_entry.signature).map_err(|_| DENY_QUORUM_SIGNATURE_INVALID)?;
        // Quorum signatures are over the raw certified_digest bytes.
        verify_with_domain(
            &key,
            RECONSTRUCTION_ADMISSIBILITY_RECEIPT_PREFIX,
            &cert.certified_digest,
            &sig,
        )
        .map_err(|_| DENY_QUORUM_SIGNATURE_INVALID)?;
    }

    // Certified digest must match recovered digest (constant-time).
    if cert.certified_digest.ct_eq(recovered_digest).unwrap_u8() == 0 {
        return Err(DENY_QUORUM_DIGEST_MISMATCH);
    }

    Ok(())
}

// ============================================================================
// Source trust snapshot validation
// ============================================================================

/// Validates source trust snapshot digest match for reconstruction.
///
/// Checks:
/// 1. Snapshot is present (fail-closed).
/// 2. CAS root, ledger head, and policy digest are non-zero.
/// 3. Policy signatures are present and within bounds.
/// 4. Content hash is non-zero.
/// 5. Recovered digest matches the snapshot's expected binding (CAS root,
///    constant-time comparison).
///
/// # Errors
///
/// Returns a stable deny reason string for any violation.
pub fn validate_source_trust_snapshot(
    snapshot: Option<&SourceTrustSnapshot>,
    recovered_digest: &Hash,
) -> Result<(), &'static str> {
    // Fail-closed: missing snapshot.
    let snapshot = snapshot.ok_or(DENY_TRUST_SNAPSHOT_MISSING)?;

    if is_zero_hash(&snapshot.cas_root) {
        return Err(DENY_TRUST_SNAPSHOT_CAS_ROOT_ZERO);
    }
    if is_zero_hash(&snapshot.ledger_head) {
        return Err(DENY_TRUST_SNAPSHOT_LEDGER_HEAD_ZERO);
    }
    if is_zero_hash(&snapshot.policy_digest) {
        return Err(DENY_TRUST_SNAPSHOT_POLICY_DIGEST_ZERO);
    }
    if is_zero_hash(&snapshot.content_hash) {
        return Err(DENY_TRUST_SNAPSHOT_CONTENT_HASH_ZERO);
    }
    if snapshot.policy_signatures.is_empty() {
        return Err(DENY_TRUST_SNAPSHOT_NO_POLICY_SIGS);
    }
    if snapshot.policy_signatures.len() > MAX_POLICY_SIGNATURES {
        return Err(DENY_TRUST_SNAPSHOT_POLICY_SIGS_EXCEEDED);
    }

    // Recovered digest must match CAS root (constant-time).
    if recovered_digest.ct_eq(&snapshot.cas_root).unwrap_u8() == 0 {
        return Err(DENY_TRUST_SNAPSHOT_DIGEST_MISMATCH);
    }

    Ok(())
}

// ============================================================================
// Combined reconstruction admissibility evaluation
// ============================================================================

/// Verdict for a reconstruction admissibility evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconstructionVerdict {
    /// Reconstruction admitted.
    Allow,
    /// Reconstruction denied with structured defect.
    Deny,
}

/// Decision from a reconstruction admissibility evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconstructionDecision {
    /// Verdict of the admission evaluation.
    pub verdict: ReconstructionVerdict,
    /// Deny defect (present when verdict is `Deny`).
    pub defect: Option<ReconstructionDenyDefect>,
    /// Temporal predicate results: (`predicate_id`, passed).
    pub predicate_results: Vec<(TemporalPredicateId, bool)>,
}

impl ReconstructionDecision {
    /// Creates an allow decision with predicate results.
    #[must_use]
    const fn allow(predicate_results: Vec<(TemporalPredicateId, bool)>) -> Self {
        Self {
            verdict: ReconstructionVerdict::Allow,
            defect: None,
            predicate_results,
        }
    }

    /// Creates a deny decision with a structured defect.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    fn deny(
        reason: &str,
        predicate_id: TemporalPredicateId,
        boundary_id: &str,
        denied_at_tick: u64,
        envelope_hash: Hash,
        window_ref: Hash,
        failure_mode: ReconstructionFailureMode,
        predicate_results: Vec<(TemporalPredicateId, bool)>,
    ) -> Self {
        Self {
            verdict: ReconstructionVerdict::Deny,
            defect: Some(ReconstructionDenyDefect {
                reason: reason.to_string(),
                predicate_id,
                boundary_id: boundary_id.to_string(),
                denied_at_tick,
                envelope_hash,
                window_ref,
                failure_mode,
            }),
            predicate_results,
        }
    }
}

/// Input data for reconstruction admissibility evaluation.
#[derive(Debug, Clone)]
pub struct ReconstructionCheckInput {
    /// Erasure profile for the artifact tier.
    pub erasure_profile: Option<ErasureProfile>,
    /// Erasure decode result (if decoding was attempted).
    pub decode_result: Option<ErasureDecodeResult>,
    /// BFT quorum certificate over the recovered digest.
    pub quorum_cert: Option<BftQuorumCertificate>,
    /// Source trust snapshot for digest match verification.
    pub trust_snapshot: Option<SourceTrustSnapshot>,
    /// Reconstruction admissibility receipts.
    pub receipts: Vec<ReconstructionAdmissibilityReceiptV1>,
    /// Trusted signer public keys for receipt verification.
    pub trusted_receipt_signers: Vec<[u8; 32]>,
    /// Trusted quorum node public keys for quorum certification.
    pub trusted_quorum_keys: Vec<[u8; 32]>,
    /// Expected time authority reference hash.
    pub expected_time_authority_ref: Hash,
    /// Expected window reference hash.
    pub expected_window_ref: Hash,
}

/// Typed mode for reconstruction admissibility evaluation.
///
/// Callers must explicitly declare whether reconstruction is active. When
/// active, the full admissibility gate is enforced (fail-closed). When not
/// reconstructing, the check is skipped.
///
/// This prevents fail-open bypass via `Option<&ReconstructionCheckInput>`.
#[derive(Debug, Clone)]
pub enum ReconstructionMode {
    /// System is in active reconstruction; admissibility check is required.
    Active(Box<ReconstructionCheckInput>),
    /// System is not reconstructing; reconstruction check does not apply.
    NotReconstructing,
}

/// Evaluates tiered erasure+BFT reconstruction admissibility.
///
/// This is the top-level evaluator for RFC-0029 REQ-0010 that checks:
/// 1. Erasure decode validity (artifact tier reconstructable from declared
///    erasure profile).
/// 2. BFT quorum certification over recovered digests.
/// 3. Source trust snapshot digest match (recovered digest matches CAS root).
/// 4. Reconstruction admissibility receipt validation (signature, trusted
///    signer, context binding, admitted status).
///
/// All checks are bound to TP-EIO29-001 and TP-EIO29-004 temporal authority
/// references.
///
/// # Arguments
///
/// - `input`: Complete reconstruction check input.
/// - `eval_boundary_id`: boundary identifier for this evaluation.
/// - `eval_tick`: current tick for deny defect reporting.
/// - `envelope_hash`: time authority envelope hash for defect reporting.
/// - `window_ref_hash`: window reference hash for defect reporting.
///
/// # Returns
///
/// A [`ReconstructionDecision`] with verdict and structured defect.
#[must_use]
pub fn evaluate_reconstruction_admissibility(
    input: &ReconstructionCheckInput,
    eval_boundary_id: &str,
    eval_tick: u64,
    envelope_hash: Hash,
    window_ref_hash: Hash,
) -> ReconstructionDecision {
    let mut predicate_results = Vec::new();

    // Gate 1: Erasure decode validity (bound to TP-EIO29-004).
    let erasure_result =
        validate_erasure_decode(input.erasure_profile.as_ref(), input.decode_result.as_ref());
    let erasure_passed = erasure_result.is_ok();
    predicate_results.push((TemporalPredicateId::TpEio29004, erasure_passed));

    if let Err(reason) = erasure_result {
        return ReconstructionDecision::deny(
            reason,
            TemporalPredicateId::TpEio29004,
            eval_boundary_id,
            eval_tick,
            envelope_hash,
            window_ref_hash,
            ReconstructionFailureMode::ErasureDecodeFailed,
            predicate_results,
        );
    }

    // Extract the recovered digest from the decode result.
    // Gate 1 validated both erasure_profile and decode_result are present,
    // so this branch is unreachable. Fail-closed on the impossible case.
    let recovered_digest = match input.decode_result.as_ref() {
        Some(result) => &result.recovered_digest,
        None => {
            return ReconstructionDecision::deny(
                DENY_ERASURE_PROFILE_MISSING,
                TemporalPredicateId::TpEio29004,
                eval_boundary_id,
                eval_tick,
                envelope_hash,
                window_ref_hash,
                ReconstructionFailureMode::MissingProofComponent,
                predicate_results,
            );
        },
    };

    // Gate 2: BFT quorum certification (bound to TP-EIO29-004).
    let quorum_result = validate_bft_quorum_certification(
        input.quorum_cert.as_ref(),
        recovered_digest,
        &input.trusted_quorum_keys,
    );
    // Record quorum result as part of TP-EIO29-004 (same predicate, sub-gate).
    if let Err(reason) = quorum_result {
        // Update the last predicate result to false since this is sub-gate.
        if let Some(last) = predicate_results.last_mut() {
            last.1 = false;
        }
        return ReconstructionDecision::deny(
            reason,
            TemporalPredicateId::TpEio29004,
            eval_boundary_id,
            eval_tick,
            envelope_hash,
            window_ref_hash,
            ReconstructionFailureMode::QuorumCertificationFailed,
            predicate_results,
        );
    }

    // Gate 3: Source trust snapshot digest match (bound to TP-EIO29-004).
    let snapshot_result =
        validate_source_trust_snapshot(input.trust_snapshot.as_ref(), recovered_digest);
    if let Err(reason) = snapshot_result {
        if let Some(last) = predicate_results.last_mut() {
            last.1 = false;
        }
        return ReconstructionDecision::deny(
            reason,
            TemporalPredicateId::TpEio29004,
            eval_boundary_id,
            eval_tick,
            envelope_hash,
            window_ref_hash,
            ReconstructionFailureMode::DigestMismatch,
            predicate_results,
        );
    }

    // Gate 4: Reconstruction receipt validation (bound to TP-EIO29-001).
    let receipt_result = validate_reconstruction_receipts(
        &input.receipts,
        eval_boundary_id,
        &input.trusted_receipt_signers,
        &input.expected_time_authority_ref,
        &input.expected_window_ref,
    );
    let tp001_passed = receipt_result.is_ok();
    predicate_results.push((TemporalPredicateId::TpEio29001, tp001_passed));

    if let Err(reason) = receipt_result {
        return ReconstructionDecision::deny(
            reason,
            TemporalPredicateId::TpEio29001,
            eval_boundary_id,
            eval_tick,
            envelope_hash,
            window_ref_hash,
            ReconstructionFailureMode::ReceiptValidationFailed,
            predicate_results,
        );
    }

    ReconstructionDecision::allow(predicate_results)
}

/// Validates reconstruction admissibility receipts.
///
/// Checks:
/// 1. At least one receipt is present (fail-closed).
/// 2. Receipt count is within bounds.
/// 3. No duplicate receipt IDs.
/// 4. Each receipt passes structural validation.
/// 5. Each receipt passes Ed25519 signature verification.
/// 6. Each receipt signer is in the trusted set (constant-time).
/// 7. Receipt context binds to expected time authority and window refs.
/// 8. Receipt boundary matches the evaluation boundary.
/// 9. At least one receipt has `admitted == true`.
///
/// # Errors
///
/// Returns a stable deny reason string for any violation.
pub fn validate_reconstruction_receipts(
    receipts: &[ReconstructionAdmissibilityReceiptV1],
    eval_boundary_id: &str,
    trusted_signers: &[[u8; 32]],
    expected_time_authority_ref: &Hash,
    expected_window_ref: &Hash,
) -> Result<(), &'static str> {
    if receipts.is_empty() {
        return Err(DENY_RECONSTRUCTION_RECEIPT_MISSING);
    }

    if receipts.len() > MAX_RECONSTRUCTION_RECEIPTS {
        return Err(DENY_RECONSTRUCTION_RECEIPTS_EXCEEDED);
    }

    let mut any_admitted = false;
    let mut seen_receipt_ids: HashSet<&str> = HashSet::new();

    for receipt in receipts {
        // Reject duplicate receipt IDs (prevent signature amplification).
        if !seen_receipt_ids.insert(&receipt.receipt_id) {
            return Err(DENY_RECONSTRUCTION_RECEIPT_DUPLICATE_ID);
        }

        receipt.validate()?;

        // Verify Ed25519 signature (not just structural form).
        receipt
            .verify_signature()
            .map_err(|_| DENY_RECONSTRUCTION_RECEIPT_SIGNATURE_INVALID)?;

        // Verify signer is in trusted set (non-short-circuiting constant-time
        // fold to prevent timing side-channel leaking signer position).
        let signer_trusted = trusted_signers.iter().fold(0u8, |acc, ts| {
            acc | ts.ct_eq(&receipt.signer_key).unwrap_u8()
        });
        if signer_trusted == 0 {
            return Err(DENY_RECONSTRUCTION_RECEIPT_SIGNER_UNTRUSTED);
        }

        // Context binding: boundary must match evaluation.
        if receipt.boundary_id != eval_boundary_id {
            return Err(DENY_RECONSTRUCTION_RECEIPT_BOUNDARY_MISMATCH);
        }

        // Context binding: time authority reference must match (constant-time).
        if receipt
            .time_authority_ref
            .ct_eq(expected_time_authority_ref)
            .unwrap_u8()
            == 0
        {
            return Err(DENY_RECONSTRUCTION_RECEIPT_TIME_AUTH_MISMATCH);
        }

        // Context binding: window reference must match (constant-time).
        if receipt.window_ref.ct_eq(expected_window_ref).unwrap_u8() == 0 {
            return Err(DENY_RECONSTRUCTION_RECEIPT_WINDOW_MISMATCH);
        }

        if receipt.admitted {
            any_admitted = true;
        }
    }

    // Fail-closed: at least one receipt must have admitted == true.
    if !any_admitted {
        return Err(DENY_RECONSTRUCTION_RECEIPT_NOT_ADMITTED);
    }

    Ok(())
}

// ============================================================================
// Validation helpers
// ============================================================================

fn is_zero_hash(hash: &[u8; 32]) -> bool {
    hash.ct_eq(&ZERO_HASH).unwrap_u8() == 1
}

fn validate_required_string(
    field: &str,
    value: &str,
    max_len: usize,
) -> Result<(), ReconstructionAdmissibilityError> {
    if value.is_empty() {
        return Err(ReconstructionAdmissibilityError::RequiredFieldMissing {
            field: field.to_string(),
        });
    }
    if value.len() > max_len {
        return Err(ReconstructionAdmissibilityError::FieldTooLong {
            field: field.to_string(),
            actual: value.len(),
            max: max_len,
        });
    }
    Ok(())
}

fn validate_non_zero_hash(
    field: &str,
    hash: &Hash,
) -> Result<(), ReconstructionAdmissibilityError> {
    if is_zero_hash(hash) {
        return Err(ReconstructionAdmissibilityError::ZeroHash {
            field: field.to_string(),
        });
    }
    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Signer;

    fn test_hash(val: u8) -> Hash {
        let mut h = [0u8; 32];
        h[0] = val;
        h[31] = val;
        h
    }

    fn valid_signer() -> Signer {
        Signer::generate()
    }

    fn trusted_signers_for(signer: &Signer) -> Vec<[u8; 32]> {
        vec![signer.public_key_bytes()]
    }

    fn expected_time_authority_ref() -> Hash {
        test_hash(0xBB)
    }

    fn expected_window_ref() -> Hash {
        test_hash(0xCC)
    }

    fn valid_erasure_profile() -> ErasureProfile {
        ErasureProfile {
            tier_id: "source_snapshots".to_string(),
            profile_id: "erasure-prof-001".to_string(),
            total_shards: 6,
            required_shards: 4,
            available_shard_digests: vec![
                test_hash(0x10),
                test_hash(0x11),
                test_hash(0x12),
                test_hash(0x13),
            ],
            profile_digest: test_hash(0xAA),
            expected_artifact_digest: test_hash(0xFF),
        }
    }

    fn valid_decode_result() -> ErasureDecodeResult {
        ErasureDecodeResult {
            decode_valid: true,
            recovered_digest: test_hash(0xFF),
            shards_used: 4,
        }
    }

    fn sign_quorum_digest(signer: &Signer, digest: &Hash) -> [u8; 64] {
        let sig = sign_with_domain(signer, RECONSTRUCTION_ADMISSIBILITY_RECEIPT_PREFIX, digest);
        sig.to_bytes()
    }

    fn valid_quorum_cert(signers: &[&Signer]) -> BftQuorumCertificate {
        let certified_digest = test_hash(0xFF);
        let quorum_signers: Vec<QuorumSigner> = signers
            .iter()
            .map(|s| QuorumSigner {
                signer_key: s.public_key_bytes(),
                signature: sign_quorum_digest(s, &certified_digest),
            })
            .collect();

        BftQuorumCertificate {
            total_nodes: 3,
            signers: quorum_signers,
            certified_digest,
            cert_digest: test_hash(0xEE),
        }
    }

    fn valid_trust_snapshot() -> SourceTrustSnapshot {
        SourceTrustSnapshot {
            cas_root: test_hash(0xFF), // Must match recovered_digest.
            ledger_head: test_hash(0xDD),
            policy_digest: test_hash(0xCC),
            policy_signatures: vec![test_hash(0x01), test_hash(0x02)],
            content_hash: test_hash(0xBB),
        }
    }

    fn valid_reconstruction_receipt(signer: &Signer) -> ReconstructionAdmissibilityReceiptV1 {
        ReconstructionAdmissibilityReceiptV1::create_signed(
            "recon-rcpt-001",
            "boundary-1",
            "source_snapshots",
            true,
            test_hash(0xBB),
            test_hash(0xCC),
            test_hash(0xAA),
            test_hash(0xEE),
            test_hash(0xDD),
            "actor-1",
            signer,
        )
        .expect("valid receipt")
    }

    fn valid_reconstruction_input(
        receipt_signer: &Signer,
        quorum_signers: &[&Signer],
    ) -> ReconstructionCheckInput {
        let trusted_quorum_keys: Vec<[u8; 32]> = quorum_signers
            .iter()
            .map(|s| s.public_key_bytes())
            .collect();

        ReconstructionCheckInput {
            erasure_profile: Some(valid_erasure_profile()),
            decode_result: Some(valid_decode_result()),
            quorum_cert: Some(valid_quorum_cert(quorum_signers)),
            trust_snapshot: Some(valid_trust_snapshot()),
            receipts: vec![valid_reconstruction_receipt(receipt_signer)],
            trusted_receipt_signers: trusted_signers_for(receipt_signer),
            trusted_quorum_keys,
            expected_time_authority_ref: expected_time_authority_ref(),
            expected_window_ref: expected_window_ref(),
        }
    }

    // ========================================================================
    // ReconstructionAdmissibilityReceiptV1 -- creation and signing
    // ========================================================================

    #[test]
    fn reconstruction_receipt_create_and_sign_roundtrip() {
        let signer = valid_signer();
        let receipt = valid_reconstruction_receipt(&signer);
        assert!(receipt.verify_signature().is_ok());
        assert!(receipt.validate().is_ok());
        assert_eq!(receipt.receipt_id, "recon-rcpt-001");
        assert_eq!(receipt.boundary_id, "boundary-1");
        assert_eq!(receipt.tier_id, "source_snapshots");
        assert!(receipt.admitted);
    }

    #[test]
    fn reconstruction_receipt_deterministic_signature() {
        let signer = valid_signer();
        let r1 = valid_reconstruction_receipt(&signer);
        let r2 = valid_reconstruction_receipt(&signer);
        assert_eq!(r1.signature, r2.signature);
    }

    #[test]
    fn reconstruction_receipt_wrong_key_fails_verification() {
        let signer1 = valid_signer();
        let signer2 = valid_signer();
        let receipt = valid_reconstruction_receipt(&signer1);
        let mut tampered = receipt;
        tampered.signer_key = signer2.public_key_bytes();
        assert!(tampered.verify_signature().is_err());
    }

    #[test]
    fn reconstruction_receipt_tampered_data_fails_verification() {
        let signer = valid_signer();
        let mut receipt = valid_reconstruction_receipt(&signer);
        receipt.boundary_id = "tampered".to_string();
        assert!(receipt.verify_signature().is_err());
    }

    #[test]
    fn reconstruction_receipt_zero_signer_key_denied() {
        let signer = valid_signer();
        let mut receipt = valid_reconstruction_receipt(&signer);
        receipt.signer_key = [0u8; 32];
        assert!(receipt.verify_signature().is_err());
        assert_eq!(
            receipt.validate().unwrap_err(),
            DENY_RECONSTRUCTION_RECEIPT_SIGNER_ZERO
        );
    }

    #[test]
    fn reconstruction_receipt_zero_signature_denied() {
        let signer = valid_signer();
        let mut receipt = valid_reconstruction_receipt(&signer);
        receipt.signature = [0u8; 64];
        assert_eq!(
            receipt.validate().unwrap_err(),
            DENY_RECONSTRUCTION_RECEIPT_SIGNATURE_INVALID
        );
    }

    #[test]
    fn reconstruction_receipt_empty_receipt_id_denied() {
        let signer = valid_signer();
        let result = ReconstructionAdmissibilityReceiptV1::create_signed(
            "",
            "boundary-1",
            "tier-1",
            true,
            test_hash(0xBB),
            test_hash(0xCC),
            test_hash(0xAA),
            test_hash(0xEE),
            test_hash(0xDD),
            "actor-1",
            &signer,
        );
        assert!(result.is_err());
    }

    #[test]
    fn reconstruction_receipt_oversized_receipt_id_denied() {
        let signer = valid_signer();
        let big_id = "x".repeat(MAX_RECEIPT_ID_LENGTH + 1);
        let result = ReconstructionAdmissibilityReceiptV1::create_signed(
            &big_id,
            "boundary-1",
            "tier-1",
            true,
            test_hash(0xBB),
            test_hash(0xCC),
            test_hash(0xAA),
            test_hash(0xEE),
            test_hash(0xDD),
            "actor-1",
            &signer,
        );
        assert!(result.is_err());
    }

    #[test]
    fn reconstruction_receipt_zero_time_authority_ref_denied() {
        let signer = valid_signer();
        let result = ReconstructionAdmissibilityReceiptV1::create_signed(
            "rcpt-001",
            "boundary-1",
            "tier-1",
            true,
            [0u8; 32],
            test_hash(0xCC),
            test_hash(0xAA),
            test_hash(0xEE),
            test_hash(0xDD),
            "actor-1",
            &signer,
        );
        assert!(result.is_err());
    }

    #[test]
    fn reconstruction_receipt_zero_window_ref_denied() {
        let signer = valid_signer();
        let result = ReconstructionAdmissibilityReceiptV1::create_signed(
            "rcpt-001",
            "boundary-1",
            "tier-1",
            true,
            test_hash(0xBB),
            [0u8; 32],
            test_hash(0xAA),
            test_hash(0xEE),
            test_hash(0xDD),
            "actor-1",
            &signer,
        );
        assert!(result.is_err());
    }

    #[test]
    fn reconstruction_receipt_zero_digest_proof_ref_denied() {
        let signer = valid_signer();
        let result = ReconstructionAdmissibilityReceiptV1::create_signed(
            "rcpt-001",
            "boundary-1",
            "tier-1",
            true,
            test_hash(0xBB),
            test_hash(0xCC),
            [0u8; 32],
            test_hash(0xEE),
            test_hash(0xDD),
            "actor-1",
            &signer,
        );
        assert!(result.is_err());
    }

    #[test]
    fn reconstruction_receipt_zero_quorum_cert_ref_denied() {
        let signer = valid_signer();
        let result = ReconstructionAdmissibilityReceiptV1::create_signed(
            "rcpt-001",
            "boundary-1",
            "tier-1",
            true,
            test_hash(0xBB),
            test_hash(0xCC),
            test_hash(0xAA),
            [0u8; 32],
            test_hash(0xDD),
            "actor-1",
            &signer,
        );
        assert!(result.is_err());
    }

    #[test]
    fn reconstruction_receipt_zero_content_hash_denied() {
        let signer = valid_signer();
        let result = ReconstructionAdmissibilityReceiptV1::create_signed(
            "rcpt-001",
            "boundary-1",
            "tier-1",
            true,
            test_hash(0xBB),
            test_hash(0xCC),
            test_hash(0xAA),
            test_hash(0xEE),
            [0u8; 32],
            "actor-1",
            &signer,
        );
        assert!(result.is_err());
    }

    #[test]
    fn reconstruction_receipt_serde_roundtrip() {
        let signer = valid_signer();
        let receipt = valid_reconstruction_receipt(&signer);
        let json = serde_json::to_string(&receipt).unwrap();
        let decoded: ReconstructionAdmissibilityReceiptV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, decoded);
        assert!(decoded.verify_signature().is_ok());
    }

    #[test]
    fn reconstruction_receipt_domain_separation_prevents_cross_type_replay() {
        let signer = valid_signer();
        let receipt = valid_reconstruction_receipt(&signer);

        // Try to verify with a different domain prefix -- should fail.
        let key = parse_verifying_key(&receipt.signer_key).unwrap();
        let sig = parse_signature(&receipt.signature).unwrap();
        let result = verify_with_domain(
            &key,
            b"RECOVERY_ADMISSIBILITY_RECEIPT:", // wrong domain
            &receipt.canonical_bytes(),
            &sig,
        );
        assert!(result.is_err());
    }

    #[test]
    fn reconstruction_receipt_validate_zero_digest_proof_ref() {
        let signer = valid_signer();
        let mut receipt = valid_reconstruction_receipt(&signer);
        receipt.digest_proof_ref = [0u8; 32];
        assert_eq!(
            receipt.validate().unwrap_err(),
            DENY_RECONSTRUCTION_RECEIPT_DIGEST_PROOF_ZERO
        );
    }

    #[test]
    fn reconstruction_receipt_validate_zero_quorum_cert_ref() {
        let signer = valid_signer();
        let mut receipt = valid_reconstruction_receipt(&signer);
        receipt.quorum_cert_ref = [0u8; 32];
        assert_eq!(
            receipt.validate().unwrap_err(),
            DENY_RECONSTRUCTION_RECEIPT_QUORUM_CERT_ZERO
        );
    }

    // ========================================================================
    // Erasure decode validation
    // ========================================================================

    #[test]
    fn erasure_valid_profile_passes() {
        let result =
            validate_erasure_decode(Some(&valid_erasure_profile()), Some(&valid_decode_result()));
        assert!(result.is_ok());
    }

    #[test]
    fn erasure_missing_profile_denies() {
        let result = validate_erasure_decode(None, Some(&valid_decode_result()));
        assert_eq!(result.unwrap_err(), DENY_ERASURE_PROFILE_MISSING);
    }

    #[test]
    fn erasure_missing_decode_result_denies() {
        let result = validate_erasure_decode(Some(&valid_erasure_profile()), None);
        assert_eq!(result.unwrap_err(), DENY_ERASURE_PROFILE_MISSING);
    }

    #[test]
    fn erasure_zero_total_shards_denies() {
        let mut profile = valid_erasure_profile();
        profile.total_shards = 0;
        let result = validate_erasure_decode(Some(&profile), Some(&valid_decode_result()));
        assert_eq!(result.unwrap_err(), DENY_ERASURE_TOTAL_SHARDS_ZERO);
    }

    #[test]
    fn erasure_zero_required_shards_denies() {
        let mut profile = valid_erasure_profile();
        profile.required_shards = 0;
        let result = validate_erasure_decode(Some(&profile), Some(&valid_decode_result()));
        assert_eq!(result.unwrap_err(), DENY_ERASURE_REQUIRED_SHARDS_ZERO);
    }

    #[test]
    fn erasure_required_exceeds_total_denies() {
        let mut profile = valid_erasure_profile();
        profile.required_shards = 7; // > total_shards(6)
        let result = validate_erasure_decode(Some(&profile), Some(&valid_decode_result()));
        assert_eq!(result.unwrap_err(), DENY_ERASURE_REQUIRED_EXCEEDS_TOTAL);
    }

    #[test]
    fn erasure_insufficient_shards_denies() {
        let mut profile = valid_erasure_profile();
        // Only 2 available shards, need 4.
        profile.available_shard_digests = vec![test_hash(0x10), test_hash(0x11)];
        let result = validate_erasure_decode(Some(&profile), Some(&valid_decode_result()));
        assert_eq!(result.unwrap_err(), DENY_ERASURE_INSUFFICIENT_SHARDS);
    }

    #[test]
    fn erasure_zero_shard_digest_denies() {
        let mut profile = valid_erasure_profile();
        profile.available_shard_digests[2] = [0u8; 32];
        let result = validate_erasure_decode(Some(&profile), Some(&valid_decode_result()));
        assert_eq!(result.unwrap_err(), DENY_ERASURE_SHARD_DIGEST_ZERO);
    }

    #[test]
    fn erasure_zero_profile_digest_denies() {
        let mut profile = valid_erasure_profile();
        profile.profile_digest = [0u8; 32];
        let result = validate_erasure_decode(Some(&profile), Some(&valid_decode_result()));
        assert_eq!(result.unwrap_err(), DENY_ERASURE_PROFILE_DIGEST_ZERO);
    }

    #[test]
    fn erasure_decode_not_valid_denies() {
        let mut decode = valid_decode_result();
        decode.decode_valid = false;
        let result = validate_erasure_decode(Some(&valid_erasure_profile()), Some(&decode));
        assert_eq!(result.unwrap_err(), DENY_ERASURE_INSUFFICIENT_SHARDS);
    }

    #[test]
    fn erasure_recovered_digest_mismatch_denies() {
        let mut decode = valid_decode_result();
        decode.recovered_digest = test_hash(0x01); // Mismatch with expected 0xFF.
        let result = validate_erasure_decode(Some(&valid_erasure_profile()), Some(&decode));
        assert_eq!(result.unwrap_err(), DENY_ERASURE_RECOVERED_DIGEST_MISMATCH);
    }

    #[test]
    fn erasure_empty_tier_id_denies() {
        let mut profile = valid_erasure_profile();
        profile.tier_id = String::new();
        let result = validate_erasure_decode(Some(&profile), Some(&valid_decode_result()));
        assert_eq!(result.unwrap_err(), DENY_ERASURE_TIER_ID_INVALID);
    }

    #[test]
    fn erasure_oversized_tier_id_denies() {
        let mut profile = valid_erasure_profile();
        profile.tier_id = "x".repeat(MAX_TIER_ID_LENGTH + 1);
        let result = validate_erasure_decode(Some(&profile), Some(&valid_decode_result()));
        assert_eq!(result.unwrap_err(), DENY_ERASURE_TIER_ID_INVALID);
    }

    #[test]
    fn erasure_exceeds_max_shards_denies() {
        let mut profile = valid_erasure_profile();
        #[allow(clippy::cast_possible_truncation)]
        {
            profile.total_shards = (MAX_ERASURE_SHARDS + 1) as u32;
        }
        profile.required_shards = 4;
        let result = validate_erasure_decode(Some(&profile), Some(&valid_decode_result()));
        assert_eq!(result.unwrap_err(), DENY_ERASURE_SHARDS_EXCEEDED);
    }

    // ========================================================================
    // BFT quorum certification validation
    // ========================================================================

    #[test]
    fn quorum_valid_cert_passes() {
        let s1 = valid_signer();
        let s2 = valid_signer();
        let s3 = valid_signer();
        let signers = vec![&s1, &s2, &s3];
        let cert = valid_quorum_cert(&signers);
        let trusted: Vec<[u8; 32]> = signers.iter().map(|s| s.public_key_bytes()).collect();
        let recovered = test_hash(0xFF);
        let result = validate_bft_quorum_certification(Some(&cert), &recovered, &trusted);
        assert!(result.is_ok());
    }

    #[test]
    fn quorum_missing_cert_denies() {
        let recovered = test_hash(0xFF);
        let result = validate_bft_quorum_certification(None, &recovered, &[]);
        assert_eq!(result.unwrap_err(), DENY_QUORUM_CERT_MISSING);
    }

    #[test]
    fn quorum_zero_total_nodes_denies() {
        let s1 = valid_signer();
        let mut cert = valid_quorum_cert(&[&s1]);
        cert.total_nodes = 0;
        let trusted = vec![s1.public_key_bytes()];
        let recovered = test_hash(0xFF);
        let result = validate_bft_quorum_certification(Some(&cert), &recovered, &trusted);
        assert_eq!(result.unwrap_err(), DENY_QUORUM_TOTAL_NODES_ZERO);
    }

    #[test]
    fn quorum_insufficient_signers_denies() {
        let s1 = valid_signer();
        let s2 = valid_signer();
        // total_nodes=3, only 1 signer (need 2).
        let cert = BftQuorumCertificate {
            total_nodes: 3,
            signers: vec![QuorumSigner {
                signer_key: s1.public_key_bytes(),
                signature: sign_quorum_digest(&s1, &test_hash(0xFF)),
            }],
            certified_digest: test_hash(0xFF),
            cert_digest: test_hash(0xEE),
        };
        let trusted = vec![s1.public_key_bytes(), s2.public_key_bytes()];
        let recovered = test_hash(0xFF);
        let result = validate_bft_quorum_certification(Some(&cert), &recovered, &trusted);
        assert_eq!(result.unwrap_err(), DENY_QUORUM_INSUFFICIENT);
    }

    #[test]
    fn quorum_zero_signer_key_denies() {
        let s1 = valid_signer();
        let s2 = valid_signer();
        let s3 = valid_signer();
        let mut cert = valid_quorum_cert(&[&s1, &s2, &s3]);
        cert.signers[1].signer_key = [0u8; 32];
        let trusted = vec![
            s1.public_key_bytes(),
            s2.public_key_bytes(),
            s3.public_key_bytes(),
        ];
        let recovered = test_hash(0xFF);
        let result = validate_bft_quorum_certification(Some(&cert), &recovered, &trusted);
        assert_eq!(result.unwrap_err(), DENY_QUORUM_SIGNER_KEY_ZERO);
    }

    #[test]
    fn quorum_duplicate_signer_denies() {
        let s1 = valid_signer();
        let cert = BftQuorumCertificate {
            total_nodes: 3,
            signers: vec![
                QuorumSigner {
                    signer_key: s1.public_key_bytes(),
                    signature: sign_quorum_digest(&s1, &test_hash(0xFF)),
                },
                QuorumSigner {
                    signer_key: s1.public_key_bytes(),
                    signature: sign_quorum_digest(&s1, &test_hash(0xFF)),
                },
            ],
            certified_digest: test_hash(0xFF),
            cert_digest: test_hash(0xEE),
        };
        let trusted = vec![s1.public_key_bytes()];
        let recovered = test_hash(0xFF);
        let result = validate_bft_quorum_certification(Some(&cert), &recovered, &trusted);
        assert_eq!(result.unwrap_err(), DENY_QUORUM_DUPLICATE_SIGNER);
    }

    #[test]
    fn quorum_untrusted_signer_denies() {
        let s1 = valid_signer();
        let s2 = valid_signer();
        let s_untrusted = valid_signer();
        let cert = valid_quorum_cert(&[&s1, &s2, &s_untrusted]);
        // Only trust s1 and s2, not s_untrusted.
        let trusted = vec![s1.public_key_bytes(), s2.public_key_bytes()];
        let recovered = test_hash(0xFF);
        let result = validate_bft_quorum_certification(Some(&cert), &recovered, &trusted);
        assert_eq!(result.unwrap_err(), DENY_QUORUM_SIGNER_UNTRUSTED);
    }

    #[test]
    fn quorum_invalid_signature_denies() {
        let s1 = valid_signer();
        let s2 = valid_signer();
        let s3 = valid_signer();
        let mut cert = valid_quorum_cert(&[&s1, &s2, &s3]);
        // Tamper with a signature.
        cert.signers[1].signature[0] ^= 0xFF;
        let trusted = vec![
            s1.public_key_bytes(),
            s2.public_key_bytes(),
            s3.public_key_bytes(),
        ];
        let recovered = test_hash(0xFF);
        let result = validate_bft_quorum_certification(Some(&cert), &recovered, &trusted);
        assert_eq!(result.unwrap_err(), DENY_QUORUM_SIGNATURE_INVALID);
    }

    #[test]
    fn quorum_digest_mismatch_denies() {
        let s1 = valid_signer();
        let s2 = valid_signer();
        let s3 = valid_signer();
        let cert = valid_quorum_cert(&[&s1, &s2, &s3]);
        let trusted = vec![
            s1.public_key_bytes(),
            s2.public_key_bytes(),
            s3.public_key_bytes(),
        ];
        // Recovered digest does not match certified digest.
        let recovered = test_hash(0x01);
        let result = validate_bft_quorum_certification(Some(&cert), &recovered, &trusted);
        assert_eq!(result.unwrap_err(), DENY_QUORUM_DIGEST_MISMATCH);
    }

    #[test]
    fn quorum_zero_certified_digest_denies() {
        let s1 = valid_signer();
        let mut cert = valid_quorum_cert(&[&s1]);
        cert.total_nodes = 1;
        cert.certified_digest = [0u8; 32];
        let trusted = vec![s1.public_key_bytes()];
        let recovered = test_hash(0xFF);
        let result = validate_bft_quorum_certification(Some(&cert), &recovered, &trusted);
        assert_eq!(result.unwrap_err(), DENY_QUORUM_CERT_DIGEST_ZERO);
    }

    #[test]
    fn quorum_zero_cert_digest_denies() {
        let s1 = valid_signer();
        let mut cert = valid_quorum_cert(&[&s1]);
        cert.total_nodes = 1;
        cert.cert_digest = [0u8; 32];
        let trusted = vec![s1.public_key_bytes()];
        let recovered = test_hash(0xFF);
        let result = validate_bft_quorum_certification(Some(&cert), &recovered, &trusted);
        assert_eq!(result.unwrap_err(), DENY_QUORUM_CERT_DIGEST_ZERO);
    }

    #[test]
    fn quorum_exceeds_max_signers_denies() {
        let signers: Vec<Signer> = (0..=MAX_QUORUM_SIGNERS).map(|_| valid_signer()).collect();
        let signer_refs: Vec<&Signer> = signers.iter().collect();
        #[allow(clippy::cast_possible_truncation)]
        let cert = BftQuorumCertificate {
            total_nodes: signer_refs.len() as u32,
            signers: signer_refs
                .iter()
                .map(|s| QuorumSigner {
                    signer_key: s.public_key_bytes(),
                    signature: sign_quorum_digest(s, &test_hash(0xFF)),
                })
                .collect(),
            certified_digest: test_hash(0xFF),
            cert_digest: test_hash(0xEE),
        };
        let trusted: Vec<[u8; 32]> = signer_refs.iter().map(|s| s.public_key_bytes()).collect();
        let recovered = test_hash(0xFF);
        let result = validate_bft_quorum_certification(Some(&cert), &recovered, &trusted);
        assert_eq!(result.unwrap_err(), DENY_QUORUM_SIGNERS_EXCEEDED);
    }

    // ========================================================================
    // Source trust snapshot validation
    // ========================================================================

    #[test]
    fn trust_snapshot_valid_passes() {
        let recovered = test_hash(0xFF);
        let result = validate_source_trust_snapshot(Some(&valid_trust_snapshot()), &recovered);
        assert!(result.is_ok());
    }

    #[test]
    fn trust_snapshot_missing_denies() {
        let recovered = test_hash(0xFF);
        let result = validate_source_trust_snapshot(None, &recovered);
        assert_eq!(result.unwrap_err(), DENY_TRUST_SNAPSHOT_MISSING);
    }

    #[test]
    fn trust_snapshot_zero_cas_root_denies() {
        let mut snapshot = valid_trust_snapshot();
        snapshot.cas_root = [0u8; 32];
        let recovered = test_hash(0xFF);
        let result = validate_source_trust_snapshot(Some(&snapshot), &recovered);
        assert_eq!(result.unwrap_err(), DENY_TRUST_SNAPSHOT_CAS_ROOT_ZERO);
    }

    #[test]
    fn trust_snapshot_zero_ledger_head_denies() {
        let mut snapshot = valid_trust_snapshot();
        snapshot.ledger_head = [0u8; 32];
        let recovered = test_hash(0xFF);
        let result = validate_source_trust_snapshot(Some(&snapshot), &recovered);
        assert_eq!(result.unwrap_err(), DENY_TRUST_SNAPSHOT_LEDGER_HEAD_ZERO);
    }

    #[test]
    fn trust_snapshot_zero_policy_digest_denies() {
        let mut snapshot = valid_trust_snapshot();
        snapshot.policy_digest = [0u8; 32];
        let recovered = test_hash(0xFF);
        let result = validate_source_trust_snapshot(Some(&snapshot), &recovered);
        assert_eq!(result.unwrap_err(), DENY_TRUST_SNAPSHOT_POLICY_DIGEST_ZERO);
    }

    #[test]
    fn trust_snapshot_zero_content_hash_denies() {
        let mut snapshot = valid_trust_snapshot();
        snapshot.content_hash = [0u8; 32];
        let recovered = test_hash(0xFF);
        let result = validate_source_trust_snapshot(Some(&snapshot), &recovered);
        assert_eq!(result.unwrap_err(), DENY_TRUST_SNAPSHOT_CONTENT_HASH_ZERO);
    }

    #[test]
    fn trust_snapshot_no_policy_signatures_denies() {
        let mut snapshot = valid_trust_snapshot();
        snapshot.policy_signatures = vec![];
        let recovered = test_hash(0xFF);
        let result = validate_source_trust_snapshot(Some(&snapshot), &recovered);
        assert_eq!(result.unwrap_err(), DENY_TRUST_SNAPSHOT_NO_POLICY_SIGS);
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn trust_snapshot_exceeds_max_policy_signatures_denies() {
        let mut snapshot = valid_trust_snapshot();
        snapshot.policy_signatures = (0..=MAX_POLICY_SIGNATURES)
            .map(|i| {
                let mut h = [0u8; 32];
                h[0] = (i & 0xFF) as u8;
                h[31] = 0xFF;
                h
            })
            .collect();
        let recovered = test_hash(0xFF);
        let result = validate_source_trust_snapshot(Some(&snapshot), &recovered);
        assert_eq!(
            result.unwrap_err(),
            DENY_TRUST_SNAPSHOT_POLICY_SIGS_EXCEEDED
        );
    }

    #[test]
    fn trust_snapshot_digest_mismatch_denies() {
        let recovered = test_hash(0x01); // Does not match cas_root(0xFF).
        let result = validate_source_trust_snapshot(Some(&valid_trust_snapshot()), &recovered);
        assert_eq!(result.unwrap_err(), DENY_TRUST_SNAPSHOT_DIGEST_MISMATCH);
    }

    // ========================================================================
    // Reconstruction receipt validation
    // ========================================================================

    #[test]
    fn reconstruction_receipts_valid_passes() {
        let signer = valid_signer();
        let receipt = valid_reconstruction_receipt(&signer);
        let trusted = trusted_signers_for(&signer);
        let result = validate_reconstruction_receipts(
            &[receipt],
            "boundary-1",
            &trusted,
            &expected_time_authority_ref(),
            &expected_window_ref(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn reconstruction_receipts_empty_denies() {
        let result = validate_reconstruction_receipts(
            &[],
            "boundary-1",
            &[],
            &expected_time_authority_ref(),
            &expected_window_ref(),
        );
        assert_eq!(result.unwrap_err(), DENY_RECONSTRUCTION_RECEIPT_MISSING);
    }

    #[test]
    fn reconstruction_receipts_duplicate_id_denies() {
        let signer = valid_signer();
        let r1 = valid_reconstruction_receipt(&signer);
        let r2 = valid_reconstruction_receipt(&signer); // Same ID.
        let trusted = trusted_signers_for(&signer);
        let result = validate_reconstruction_receipts(
            &[r1, r2],
            "boundary-1",
            &trusted,
            &expected_time_authority_ref(),
            &expected_window_ref(),
        );
        assert_eq!(
            result.unwrap_err(),
            DENY_RECONSTRUCTION_RECEIPT_DUPLICATE_ID
        );
    }

    #[test]
    fn reconstruction_receipts_untrusted_signer_denies() {
        let signer_a = valid_signer();
        let signer_b = valid_signer();
        let receipt = valid_reconstruction_receipt(&signer_a);
        let trusted = trusted_signers_for(&signer_b); // Does not trust signer_a.
        let result = validate_reconstruction_receipts(
            &[receipt],
            "boundary-1",
            &trusted,
            &expected_time_authority_ref(),
            &expected_window_ref(),
        );
        assert_eq!(
            result.unwrap_err(),
            DENY_RECONSTRUCTION_RECEIPT_SIGNER_UNTRUSTED
        );
    }

    #[test]
    fn reconstruction_receipts_boundary_mismatch_denies() {
        let signer = valid_signer();
        let receipt = valid_reconstruction_receipt(&signer);
        let trusted = trusted_signers_for(&signer);
        let result = validate_reconstruction_receipts(
            &[receipt],
            "wrong-boundary",
            &trusted,
            &expected_time_authority_ref(),
            &expected_window_ref(),
        );
        assert_eq!(
            result.unwrap_err(),
            DENY_RECONSTRUCTION_RECEIPT_BOUNDARY_MISMATCH
        );
    }

    #[test]
    fn reconstruction_receipts_time_auth_mismatch_denies() {
        let signer = valid_signer();
        let receipt = valid_reconstruction_receipt(&signer);
        let trusted = trusted_signers_for(&signer);
        let result = validate_reconstruction_receipts(
            &[receipt],
            "boundary-1",
            &trusted,
            &test_hash(0x11), // Wrong time auth.
            &expected_window_ref(),
        );
        assert_eq!(
            result.unwrap_err(),
            DENY_RECONSTRUCTION_RECEIPT_TIME_AUTH_MISMATCH
        );
    }

    #[test]
    fn reconstruction_receipts_window_mismatch_denies() {
        let signer = valid_signer();
        let receipt = valid_reconstruction_receipt(&signer);
        let trusted = trusted_signers_for(&signer);
        let result = validate_reconstruction_receipts(
            &[receipt],
            "boundary-1",
            &trusted,
            &expected_time_authority_ref(),
            &test_hash(0x22), // Wrong window ref.
        );
        assert_eq!(
            result.unwrap_err(),
            DENY_RECONSTRUCTION_RECEIPT_WINDOW_MISMATCH
        );
    }

    #[test]
    fn reconstruction_receipts_not_admitted_denies() {
        let signer = valid_signer();
        let receipt = ReconstructionAdmissibilityReceiptV1::create_signed(
            "rcpt-notadmitted",
            "boundary-1",
            "source_snapshots",
            false, // Not admitted.
            test_hash(0xBB),
            test_hash(0xCC),
            test_hash(0xAA),
            test_hash(0xEE),
            test_hash(0xDD),
            "actor-1",
            &signer,
        )
        .unwrap();
        let trusted = trusted_signers_for(&signer);
        let result = validate_reconstruction_receipts(
            &[receipt],
            "boundary-1",
            &trusted,
            &expected_time_authority_ref(),
            &expected_window_ref(),
        );
        assert_eq!(
            result.unwrap_err(),
            DENY_RECONSTRUCTION_RECEIPT_NOT_ADMITTED
        );
    }

    #[test]
    fn reconstruction_receipts_forged_signature_denies() {
        let signer = valid_signer();
        let mut receipt = valid_reconstruction_receipt(&signer);
        // Tamper with data to invalidate signature.
        receipt.tier_id = "tampered-tier".to_string();
        let trusted = trusted_signers_for(&signer);
        let result = validate_reconstruction_receipts(
            &[receipt],
            "boundary-1",
            &trusted,
            &expected_time_authority_ref(),
            &expected_window_ref(),
        );
        assert_eq!(
            result.unwrap_err(),
            DENY_RECONSTRUCTION_RECEIPT_SIGNATURE_INVALID
        );
    }

    #[test]
    fn reconstruction_receipts_exceeded_denies() {
        let signer = valid_signer();
        let trusted = trusted_signers_for(&signer);
        let receipts: Vec<_> = (0..=MAX_RECONSTRUCTION_RECEIPTS)
            .map(|i| {
                ReconstructionAdmissibilityReceiptV1::create_signed(
                    &format!("rcpt-{i}"),
                    "boundary-1",
                    "source_snapshots",
                    true,
                    test_hash(0xBB),
                    test_hash(0xCC),
                    test_hash(0xAA),
                    test_hash(0xEE),
                    test_hash(0xDD),
                    "actor-1",
                    &signer,
                )
                .unwrap()
            })
            .collect();
        let result = validate_reconstruction_receipts(
            &receipts,
            "boundary-1",
            &trusted,
            &expected_time_authority_ref(),
            &expected_window_ref(),
        );
        assert_eq!(result.unwrap_err(), DENY_RECONSTRUCTION_RECEIPTS_EXCEEDED);
    }

    // ========================================================================
    // Combined evaluation
    // ========================================================================

    #[test]
    fn evaluate_full_valid_input_passes() {
        let receipt_signer = valid_signer();
        let s1 = valid_signer();
        let s2 = valid_signer();
        let s3 = valid_signer();
        let input = valid_reconstruction_input(&receipt_signer, &[&s1, &s2, &s3]);
        let decision = evaluate_reconstruction_admissibility(
            &input,
            "boundary-1",
            500,
            test_hash(0xBB),
            test_hash(0xCC),
        );
        assert_eq!(decision.verdict, ReconstructionVerdict::Allow);
        assert!(decision.defect.is_none());
        assert!(!decision.predicate_results.is_empty());
        // Should have at least TP-EIO29-004 and TP-EIO29-001.
        assert!(decision.predicate_results.len() >= 2);
    }

    #[test]
    fn evaluate_missing_erasure_denies() {
        let receipt_signer = valid_signer();
        let s1 = valid_signer();
        let s2 = valid_signer();
        let s3 = valid_signer();
        let mut input = valid_reconstruction_input(&receipt_signer, &[&s1, &s2, &s3]);
        input.erasure_profile = None;
        let decision = evaluate_reconstruction_admissibility(
            &input,
            "boundary-1",
            500,
            test_hash(0xBB),
            test_hash(0xCC),
        );
        assert_eq!(decision.verdict, ReconstructionVerdict::Deny);
        let defect = decision.defect.as_ref().unwrap();
        assert_eq!(defect.reason, DENY_ERASURE_PROFILE_MISSING);
        assert_eq!(
            defect.failure_mode,
            ReconstructionFailureMode::ErasureDecodeFailed
        );
    }

    #[test]
    fn evaluate_missing_quorum_cert_denies() {
        let receipt_signer = valid_signer();
        let s1 = valid_signer();
        let s2 = valid_signer();
        let s3 = valid_signer();
        let mut input = valid_reconstruction_input(&receipt_signer, &[&s1, &s2, &s3]);
        input.quorum_cert = None;
        let decision = evaluate_reconstruction_admissibility(
            &input,
            "boundary-1",
            500,
            test_hash(0xBB),
            test_hash(0xCC),
        );
        assert_eq!(decision.verdict, ReconstructionVerdict::Deny);
        let defect = decision.defect.as_ref().unwrap();
        assert_eq!(defect.reason, DENY_QUORUM_CERT_MISSING);
        assert_eq!(
            defect.failure_mode,
            ReconstructionFailureMode::QuorumCertificationFailed
        );
    }

    #[test]
    fn evaluate_missing_trust_snapshot_denies() {
        let receipt_signer = valid_signer();
        let s1 = valid_signer();
        let s2 = valid_signer();
        let s3 = valid_signer();
        let mut input = valid_reconstruction_input(&receipt_signer, &[&s1, &s2, &s3]);
        input.trust_snapshot = None;
        let decision = evaluate_reconstruction_admissibility(
            &input,
            "boundary-1",
            500,
            test_hash(0xBB),
            test_hash(0xCC),
        );
        assert_eq!(decision.verdict, ReconstructionVerdict::Deny);
        let defect = decision.defect.as_ref().unwrap();
        assert_eq!(defect.reason, DENY_TRUST_SNAPSHOT_MISSING);
        assert_eq!(
            defect.failure_mode,
            ReconstructionFailureMode::DigestMismatch
        );
    }

    #[test]
    fn evaluate_missing_receipts_denies() {
        let receipt_signer = valid_signer();
        let s1 = valid_signer();
        let s2 = valid_signer();
        let s3 = valid_signer();
        let mut input = valid_reconstruction_input(&receipt_signer, &[&s1, &s2, &s3]);
        input.receipts = vec![];
        let decision = evaluate_reconstruction_admissibility(
            &input,
            "boundary-1",
            500,
            test_hash(0xBB),
            test_hash(0xCC),
        );
        assert_eq!(decision.verdict, ReconstructionVerdict::Deny);
        let defect = decision.defect.as_ref().unwrap();
        assert_eq!(defect.reason, DENY_RECONSTRUCTION_RECEIPT_MISSING);
        assert_eq!(
            defect.failure_mode,
            ReconstructionFailureMode::ReceiptValidationFailed
        );
    }

    #[test]
    fn evaluate_digest_mismatch_between_quorum_and_erasure_denies() {
        let receipt_signer = valid_signer();
        let s1 = valid_signer();
        let s2 = valid_signer();
        let s3 = valid_signer();
        let mut input = valid_reconstruction_input(&receipt_signer, &[&s1, &s2, &s3]);
        // Quorum certifies a different digest than erasure recovered.
        if let Some(ref mut cert) = input.quorum_cert {
            // Re-sign the quorum over a different digest.
            let wrong_digest = test_hash(0x01);
            cert.certified_digest = wrong_digest;
            cert.signers = [&s1, &s2, &s3]
                .iter()
                .map(|s| QuorumSigner {
                    signer_key: s.public_key_bytes(),
                    signature: sign_quorum_digest(s, &wrong_digest),
                })
                .collect();
        }
        let decision = evaluate_reconstruction_admissibility(
            &input,
            "boundary-1",
            500,
            test_hash(0xBB),
            test_hash(0xCC),
        );
        assert_eq!(decision.verdict, ReconstructionVerdict::Deny);
        let defect = decision.defect.as_ref().unwrap();
        assert_eq!(defect.reason, DENY_QUORUM_DIGEST_MISMATCH);
    }

    #[test]
    fn evaluate_trust_snapshot_digest_mismatch_denies() {
        let receipt_signer = valid_signer();
        let s1 = valid_signer();
        let s2 = valid_signer();
        let s3 = valid_signer();
        let mut input = valid_reconstruction_input(&receipt_signer, &[&s1, &s2, &s3]);
        // CAS root in snapshot does not match the recovered digest.
        if let Some(ref mut snapshot) = input.trust_snapshot {
            snapshot.cas_root = test_hash(0x01);
        }
        let decision = evaluate_reconstruction_admissibility(
            &input,
            "boundary-1",
            500,
            test_hash(0xBB),
            test_hash(0xCC),
        );
        assert_eq!(decision.verdict, ReconstructionVerdict::Deny);
        let defect = decision.defect.as_ref().unwrap();
        assert_eq!(defect.reason, DENY_TRUST_SNAPSHOT_DIGEST_MISMATCH);
    }

    #[test]
    fn evaluate_defect_includes_failure_mode() {
        let receipt_signer = valid_signer();
        let s1 = valid_signer();
        let s2 = valid_signer();
        let s3 = valid_signer();
        let mut input = valid_reconstruction_input(&receipt_signer, &[&s1, &s2, &s3]);
        input.erasure_profile = None;
        let decision = evaluate_reconstruction_admissibility(
            &input,
            "boundary-1",
            500,
            test_hash(0xBB),
            test_hash(0xCC),
        );
        let defect = decision.defect.as_ref().unwrap();
        assert_eq!(defect.denied_at_tick, 500);
        assert_eq!(defect.boundary_id, "boundary-1");
        assert_eq!(defect.envelope_hash, test_hash(0xBB));
        assert_eq!(defect.window_ref, test_hash(0xCC));
    }

    #[test]
    fn evaluate_insufficient_quorum_fail_closed() {
        let receipt_signer = valid_signer();
        let s1 = valid_signer();
        // Only 1 quorum signer when total_nodes=3 requires 2.
        let mut input = valid_reconstruction_input(&receipt_signer, &[&s1]);
        if let Some(ref mut cert) = input.quorum_cert {
            cert.total_nodes = 3;
        }
        let decision = evaluate_reconstruction_admissibility(
            &input,
            "boundary-1",
            500,
            test_hash(0xBB),
            test_hash(0xCC),
        );
        assert_eq!(decision.verdict, ReconstructionVerdict::Deny);
        let defect = decision.defect.as_ref().unwrap();
        assert_eq!(defect.reason, DENY_QUORUM_INSUFFICIENT);
        assert_eq!(
            defect.failure_mode,
            ReconstructionFailureMode::QuorumCertificationFailed
        );
    }

    // ========================================================================
    // ReconstructionMode
    // ========================================================================

    #[test]
    fn reconstruction_mode_not_reconstructing_skips() {
        // No reconstruction to evaluate -- just prove the mode works.
        let mode = ReconstructionMode::NotReconstructing;
        match mode {
            ReconstructionMode::NotReconstructing => {},
            ReconstructionMode::Active(_) => panic!("expected NotReconstructing"),
        }
    }

    #[test]
    fn reconstruction_mode_active_requires_full_check() {
        let receipt_signer = valid_signer();
        let s1 = valid_signer();
        let s2 = valid_signer();
        let s3 = valid_signer();
        let input = valid_reconstruction_input(&receipt_signer, &[&s1, &s2, &s3]);
        let mode = ReconstructionMode::Active(Box::new(input));
        match mode {
            ReconstructionMode::Active(ref inner) => {
                let decision = evaluate_reconstruction_admissibility(
                    inner,
                    "boundary-1",
                    500,
                    test_hash(0xBB),
                    test_hash(0xCC),
                );
                assert_eq!(decision.verdict, ReconstructionVerdict::Allow);
            },
            ReconstructionMode::NotReconstructing => panic!("expected Active"),
        }
    }

    // ========================================================================
    // BFT quorum threshold edge cases
    // ========================================================================

    #[test]
    fn quorum_threshold_exact_2_of_3_passes() {
        let s1 = valid_signer();
        let s2 = valid_signer();
        // total_nodes=3, need ceil(6/3)=2 signers.
        let cert = BftQuorumCertificate {
            total_nodes: 3,
            signers: vec![
                QuorumSigner {
                    signer_key: s1.public_key_bytes(),
                    signature: sign_quorum_digest(&s1, &test_hash(0xFF)),
                },
                QuorumSigner {
                    signer_key: s2.public_key_bytes(),
                    signature: sign_quorum_digest(&s2, &test_hash(0xFF)),
                },
            ],
            certified_digest: test_hash(0xFF),
            cert_digest: test_hash(0xEE),
        };
        let trusted = vec![s1.public_key_bytes(), s2.public_key_bytes()];
        let recovered = test_hash(0xFF);
        let result = validate_bft_quorum_certification(Some(&cert), &recovered, &trusted);
        assert!(result.is_ok());
    }

    #[test]
    fn quorum_threshold_4_nodes_needs_3() {
        let s1 = valid_signer();
        let s2 = valid_signer();
        // total_nodes=4, need ceil(8/3)=3 signers.
        let cert = BftQuorumCertificate {
            total_nodes: 4,
            signers: vec![
                QuorumSigner {
                    signer_key: s1.public_key_bytes(),
                    signature: sign_quorum_digest(&s1, &test_hash(0xFF)),
                },
                QuorumSigner {
                    signer_key: s2.public_key_bytes(),
                    signature: sign_quorum_digest(&s2, &test_hash(0xFF)),
                },
            ],
            certified_digest: test_hash(0xFF),
            cert_digest: test_hash(0xEE),
        };
        let trusted = vec![s1.public_key_bytes(), s2.public_key_bytes()];
        let recovered = test_hash(0xFF);
        // Should deny: 2 < 3 required.
        let result = validate_bft_quorum_certification(Some(&cert), &recovered, &trusted);
        assert_eq!(result.unwrap_err(), DENY_QUORUM_INSUFFICIENT);
    }

    #[test]
    fn quorum_threshold_1_node_needs_1() {
        let s1 = valid_signer();
        // total_nodes=1, need ceil(2/3)=1 signer.
        let cert = BftQuorumCertificate {
            total_nodes: 1,
            signers: vec![QuorumSigner {
                signer_key: s1.public_key_bytes(),
                signature: sign_quorum_digest(&s1, &test_hash(0xFF)),
            }],
            certified_digest: test_hash(0xFF),
            cert_digest: test_hash(0xEE),
        };
        let trusted = vec![s1.public_key_bytes()];
        let recovered = test_hash(0xFF);
        let result = validate_bft_quorum_certification(Some(&cert), &recovered, &trusted);
        assert!(result.is_ok());
    }
}
