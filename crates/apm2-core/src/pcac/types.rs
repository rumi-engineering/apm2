// AGENT-AUTHORED
//! Core PCAC types: authority join inputs, certificates, and consume records.
//!
//! These types implement RFC-0027 §3 — the canonical authority lifecycle
//! primitives.
//!
//! # Boundary Validation
//!
//! All untrusted string and collection fields enforce explicit size and
//! cardinality limits via [`AuthorityJoinInputV1::validate`]. Violations
//! produce deterministic denials (fail-closed).

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use super::intent_class::BoundaryIntentClass;
use crate::crypto::Hash;

mod signature_bytes_serde {
    use serde::de::{self, SeqAccess, Visitor};
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(value)
    }

    /// Bounded deserializer for 64-byte Ed25519 signatures.
    ///
    /// Rejects oversized payloads during deserialization, avoiding
    /// unbounded allocation through intermediary `Vec<u8>`.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SignatureBytesVisitor;

        impl<'de> Visitor<'de> for SignatureBytesVisitor {
            type Value = [u8; 64];

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a byte sequence of exactly 64 bytes")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                if let Some(size) = seq.size_hint() {
                    if size > 64 {
                        return Err(de::Error::custom(format!(
                            "signature too long: more than 64 bytes ({size})"
                        )));
                    }
                }

                let mut arr = [0u8; 64];
                for (i, slot) in arr.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(i, &self))?;
                }

                if seq.next_element::<u8>()?.is_some() {
                    return Err(de::Error::custom("signature too long: more than 64 bytes"));
                }

                Ok(arr)
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if v.len() != 64 {
                    return Err(E::custom(format!(
                        "expected 64 bytes for signature, got {}",
                        v.len()
                    )));
                }

                let mut arr = [0u8; 64];
                arr.copy_from_slice(v);
                Ok(arr)
            }

            fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                self.visit_bytes(&v)
            }
        }

        deserializer.deserialize_seq(SignatureBytesVisitor)
    }
}

// =============================================================================
// Resource Limits
// =============================================================================

/// Maximum length for string identifier fields (`session_id`, `lease_id`,
/// `holon_id`).
pub const MAX_STRING_LENGTH: usize = 256;

/// Maximum number of scope witness hashes in a join input.
pub const MAX_SCOPE_WITNESS_HASHES: usize = 64;

/// Maximum number of pre-actuation receipt hashes in a join input.
pub const MAX_PRE_ACTUATION_RECEIPT_HASHES: usize = 64;

/// Maximum length for the `canonicalizer_id` string in receipt digest metadata.
pub const MAX_CANONICALIZER_ID_LENGTH: usize = 256;

/// Maximum length for the checkpoint string in revalidation receipts.
pub const MAX_CHECKPOINT_LENGTH: usize = 256;

/// Maximum number of Merkle proof steps in a batched pointer auth.
pub const MAX_MERKLE_PROOF_STEPS: usize = 64;

/// Maximum length for description strings in deny classes.
pub const MAX_DESCRIPTION_LENGTH: usize = 1024;

/// Maximum length for machine-readable reason codes in deny classes.
pub const MAX_REASON_LENGTH: usize = 256;

/// Maximum length for `field_name` strings in deny classes.
pub const MAX_FIELD_NAME_LENGTH: usize = 128;

/// Maximum length for operation strings in deny classes.
pub const MAX_OPERATION_LENGTH: usize = 256;

// =============================================================================
// Deserialization helpers
// =============================================================================

/// Serde deserializer that enforces [`MAX_STRING_LENGTH`] during
/// deserialization.
///
/// This rejects oversized strings at the protocol boundary so large payloads
/// cannot bypass size constraints until `validate()` time.
pub fn deserialize_bounded_string<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    struct BoundedStringVisitor;

    impl Visitor<'_> for BoundedStringVisitor {
        type Value = String;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(formatter, "a string with at most {MAX_STRING_LENGTH} bytes")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            if v.len() > MAX_STRING_LENGTH {
                return Err(E::custom(format!(
                    "string field length {} exceeds maximum {}",
                    v.len(),
                    MAX_STRING_LENGTH,
                )));
            }
            Ok(v.to_owned())
        }

        fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
            if v.len() > MAX_STRING_LENGTH {
                return Err(E::custom(format!(
                    "string field length {} exceeds maximum {}",
                    v.len(),
                    MAX_STRING_LENGTH,
                )));
            }
            Ok(v)
        }
    }

    deserializer.deserialize_string(BoundedStringVisitor)
}

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
/// - `freshness_witness_tick` ensures authority is current.
/// - `stop_budget_profile_digest` captures stop/budget constraints.
/// - `leakage_witness_hash` and `timing_witness_hash` bind authoritative
///   boundary-flow measurements into join-time admission.
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

    /// Boundary intent class for lifecycle admission.
    ///
    /// Missing values deserialize to `observe` for backward compatibility and
    /// fail-closed authorization behavior.
    #[serde(default = "default_boundary_intent_class")]
    pub boundary_intent_class: BoundaryIntentClass,

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

    /// Optional waiver hash for `PointerOnly` identity at Tier2+.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pointer_only_waiver_hash: Option<Hash>,

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

    /// Hash commitment to authoritative leakage witness evidence.
    #[serde(default)]
    pub leakage_witness_hash: Hash,

    /// Hash commitment to authoritative timing-variance witness evidence.
    #[serde(default)]
    pub timing_witness_hash: Hash,

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

// =============================================================================
// Boundary validation error
// =============================================================================

/// Error returned by boundary validation of PCAC types.
///
/// All variants represent deterministic denials — there is no "unknown ->
/// allow" path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PcacValidationError {
    /// A required string field is empty.
    EmptyRequiredField {
        /// Name of the empty field.
        field: &'static str,
    },
    /// A required hash field contains all zeros (uninitialized).
    ZeroHash {
        /// Name of the zero-hash field.
        field: &'static str,
    },
    /// A string field exceeds the maximum allowed length.
    StringTooLong {
        /// Name of the oversized field.
        field: &'static str,
        /// Actual length.
        len: usize,
        /// Maximum allowed length.
        max: usize,
    },
    /// A collection exceeds the maximum allowed cardinality.
    CollectionTooLarge {
        /// Name of the oversized collection.
        field: &'static str,
        /// Actual count.
        count: usize,
        /// Maximum allowed count.
        max: usize,
    },
    /// Merkle proof is empty in a batched pointer auth (must have >= 1 step).
    EmptyMerkleProof,
    /// Delegated-path bindings are incoherent: both `permeability_receipt_hash`
    /// and `delegation_chain_hash` must be present or both absent.
    IncoherentDelegatedBindings,
    /// Two semantically duplicated fields diverge and violate binding
    /// coherence.
    FieldCoherenceMismatch {
        /// Name of the outer (top-level) field.
        outer_field: &'static str,
        /// Name of the nested/coherent field that must match.
        inner_field: &'static str,
    },
    /// Authoritative bindings are required for trust-admission validation.
    MissingAuthoritativeBindings {
        /// Receipt type that is missing required authoritative bindings.
        receipt_type: &'static str,
    },
    /// Receipt digest does not match canonical bytes.
    DigestMismatch,
    /// Canonicalizer identifier is not in the allowlist.
    UnknownCanonicalizer {
        /// Unrecognized canonicalizer identifier.
        id: String,
    },
    /// Tick field must be strictly positive.
    NonPositiveTick {
        /// Name of the invalid tick field.
        field: &'static str,
    },
}

impl std::fmt::Display for PcacValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyRequiredField { field } => {
                write!(f, "required field is empty: {field}")
            },
            Self::ZeroHash { field } => {
                write!(f, "zero hash for required field: {field}")
            },
            Self::StringTooLong { field, len, max } => {
                write!(
                    f,
                    "string field '{field}' exceeds maximum length ({len} > {max})"
                )
            },
            Self::CollectionTooLarge { field, count, max } => {
                write!(
                    f,
                    "collection '{field}' exceeds maximum cardinality ({count} > {max})"
                )
            },
            Self::EmptyMerkleProof => {
                write!(f, "batched pointer auth has empty merkle inclusion proof")
            },
            Self::IncoherentDelegatedBindings => {
                write!(
                    f,
                    "delegated-path bindings incoherent: permeability_receipt_hash and delegation_chain_hash must co-occur"
                )
            },
            Self::FieldCoherenceMismatch {
                outer_field,
                inner_field,
            } => {
                write!(
                    f,
                    "field coherence mismatch: '{outer_field}' must equal '{inner_field}'"
                )
            },
            Self::MissingAuthoritativeBindings { receipt_type } => {
                write!(
                    f,
                    "missing authoritative bindings for receipt type: {receipt_type}"
                )
            },
            Self::DigestMismatch => write!(f, "receipt digest mismatch"),
            Self::UnknownCanonicalizer { id } => {
                write!(f, "unknown canonicalizer identifier: {id}")
            },
            Self::NonPositiveTick { field } => {
                write!(f, "tick field '{field}' must be > 0")
            },
        }
    }
}

impl std::error::Error for PcacValidationError {}

// =============================================================================
// AuthorityJoinInputV1 validation
// =============================================================================

/// Zero hash constant for comparison.
const ZERO_HASH: Hash = [0u8; 32];

const fn default_boundary_intent_class() -> BoundaryIntentClass {
    BoundaryIntentClass::Observe
}

impl AuthorityJoinInputV1 {
    /// Validate string field constraints (non-empty, within length bounds).
    fn validate_strings(&self) -> Result<(), PcacValidationError> {
        // String field: session_id
        if self.session_id.is_empty() {
            return Err(PcacValidationError::EmptyRequiredField {
                field: "session_id",
            });
        }
        if self.session_id.len() > MAX_STRING_LENGTH {
            return Err(PcacValidationError::StringTooLong {
                field: "session_id",
                len: self.session_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }

        // String field: holon_id (optional but bounded)
        if let Some(ref holon_id) = self.holon_id {
            if holon_id.is_empty() {
                return Err(PcacValidationError::EmptyRequiredField { field: "holon_id" });
            }
            if holon_id.len() > MAX_STRING_LENGTH {
                return Err(PcacValidationError::StringTooLong {
                    field: "holon_id",
                    len: holon_id.len(),
                    max: MAX_STRING_LENGTH,
                });
            }
        }

        // String field: lease_id
        if self.lease_id.is_empty() {
            return Err(PcacValidationError::EmptyRequiredField { field: "lease_id" });
        }
        if self.lease_id.len() > MAX_STRING_LENGTH {
            return Err(PcacValidationError::StringTooLong {
                field: "lease_id",
                len: self.lease_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        Ok(())
    }

    /// Validate all boundary constraints on this join input.
    ///
    /// Checks that:
    /// - Required string fields are non-empty and within length bounds.
    /// - Required hash fields are non-zero.
    /// - Collection fields are within cardinality bounds.
    /// - Per-element hash vectors contain no zero-hash entries.
    /// - Optional hash fields, when present, are non-zero.
    ///
    /// # Errors
    ///
    /// Returns `PcacValidationError` on the first violation found
    /// (fail-closed).
    pub fn validate(&self) -> Result<(), PcacValidationError> {
        self.validate_strings()?;

        // Required hash fields — must not be zero
        if self.intent_digest == ZERO_HASH {
            return Err(PcacValidationError::ZeroHash {
                field: "intent_digest",
            });
        }
        if self.capability_manifest_hash == ZERO_HASH {
            return Err(PcacValidationError::ZeroHash {
                field: "capability_manifest_hash",
            });
        }
        if self.identity_proof_hash == ZERO_HASH {
            return Err(PcacValidationError::ZeroHash {
                field: "identity_proof_hash",
            });
        }
        if self.directory_head_hash == ZERO_HASH {
            return Err(PcacValidationError::ZeroHash {
                field: "directory_head_hash",
            });
        }
        if self.freshness_policy_hash == ZERO_HASH {
            return Err(PcacValidationError::ZeroHash {
                field: "freshness_policy_hash",
            });
        }
        if self.freshness_witness_tick == 0 {
            return Err(PcacValidationError::NonPositiveTick {
                field: "freshness_witness_tick",
            });
        }
        if self.stop_budget_profile_digest == ZERO_HASH {
            return Err(PcacValidationError::ZeroHash {
                field: "stop_budget_profile_digest",
            });
        }
        if self.leakage_witness_hash == ZERO_HASH {
            return Err(PcacValidationError::ZeroHash {
                field: "leakage_witness_hash",
            });
        }
        if self.timing_witness_hash == ZERO_HASH {
            return Err(PcacValidationError::ZeroHash {
                field: "timing_witness_hash",
            });
        }
        if self.time_envelope_ref == ZERO_HASH {
            return Err(PcacValidationError::ZeroHash {
                field: "time_envelope_ref",
            });
        }
        if self.as_of_ledger_anchor == ZERO_HASH {
            return Err(PcacValidationError::ZeroHash {
                field: "as_of_ledger_anchor",
            });
        }

        // Collection bounds
        if self.scope_witness_hashes.len() > MAX_SCOPE_WITNESS_HASHES {
            return Err(PcacValidationError::CollectionTooLarge {
                field: "scope_witness_hashes",
                count: self.scope_witness_hashes.len(),
                max: MAX_SCOPE_WITNESS_HASHES,
            });
        }
        if self.pre_actuation_receipt_hashes.len() > MAX_PRE_ACTUATION_RECEIPT_HASHES {
            return Err(PcacValidationError::CollectionTooLarge {
                field: "pre_actuation_receipt_hashes",
                count: self.pre_actuation_receipt_hashes.len(),
                max: MAX_PRE_ACTUATION_RECEIPT_HASHES,
            });
        }

        // Per-element zero-hash checks for hash vectors (fail-closed).
        for h in &self.scope_witness_hashes {
            if *h == ZERO_HASH {
                return Err(PcacValidationError::ZeroHash {
                    field: "scope_witness_hashes[element]",
                });
            }
        }
        for h in &self.pre_actuation_receipt_hashes {
            if *h == ZERO_HASH {
                return Err(PcacValidationError::ZeroHash {
                    field: "pre_actuation_receipt_hashes[element]",
                });
            }
        }

        // Optional hash field: permeability_receipt_hash must be non-zero when present.
        if let Some(ref prh) = self.permeability_receipt_hash {
            if *prh == ZERO_HASH {
                return Err(PcacValidationError::ZeroHash {
                    field: "permeability_receipt_hash",
                });
            }
        }

        // Optional hash field: pointer_only_waiver_hash must be non-zero when present.
        if let Some(ref pwh) = self.pointer_only_waiver_hash {
            if *pwh == ZERO_HASH {
                return Err(PcacValidationError::ZeroHash {
                    field: "pointer_only_waiver_hash",
                });
            }
        }

        Ok(())
    }
}

/// Risk tier for authority classification.
///
/// Maps to the broader `RiskTierClass` but scoped to the PCAC context
/// with fail-closed semantics on unknown variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
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
/// - `issued_at_tick`: Authoritative issue tick.
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

    /// Boundary intent class admitted at join time.
    ///
    /// Missing values deserialize to `observe` for backward compatibility and
    /// fail-closed authorization behavior.
    #[serde(default = "default_boundary_intent_class")]
    pub boundary_intent_class: BoundaryIntentClass,

    /// Risk classification at join time.
    pub risk_tier: RiskTier,

    /// HTF authoritative issue witness (content hash of time envelope).
    pub issued_time_envelope_ref: Hash,

    /// Authoritative issue tick.
    pub issued_at_tick: u64,

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
// Sovereignty types (RFC-0027 §6.6, TCK-00427)
// =============================================================================

/// Sovereignty epoch evidence for Tier2+ authority paths.
///
/// Captures the epoch identifier, last known freshness tick, a signer public
/// key, and a cryptographic signature binding the epoch to the authority scope.
/// Tier2+ consume and revalidate check that the epoch is current (not stale)
/// and that the signature cryptographically verifies against the signer key.
///
/// # Signature Verification
///
/// Signatures are Ed25519 signatures over a domain-separated message:
/// `b"apm2-sovereignty-epoch-v1" || principal_scope_hash || epoch_id ||
/// freshness_tick`. The `principal_scope_hash` is a BLAKE3 digest of the
/// principal ID, cryptographically binding the epoch to a specific principal
/// scope and preventing cross-principal replay attacks.
/// The signature field stores raw 64-byte signature bytes.
///
/// Runtime validators MUST also bind `signer_public_key` to a trusted
/// authority key source. A signer/key mismatch is fail-closed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SovereigntyEpoch {
    /// Unique epoch identifier.
    #[serde(deserialize_with = "deserialize_bounded_string")]
    pub epoch_id: String,

    /// The freshness tick at which this epoch was last observed.
    pub freshness_tick: u64,

    /// BLAKE3 digest of the principal ID this epoch is bound to.
    ///
    /// Signatures commit to this hash, preventing cross-principal replay.
    /// Validators MUST verify that this matches the runtime principal scope.
    pub principal_scope_hash: Hash,

    /// Public key of the signer that produced this epoch's signature.
    pub signer_public_key: Hash,

    /// Cryptographic signature binding the epoch to the authority scope.
    /// Must verify against `signer_public_key` via Ed25519 verification.
    #[serde(with = "signature_bytes_serde")]
    pub signature: [u8; 64],
}

impl SovereigntyEpoch {
    /// Validate boundary constraints on sovereignty epoch fields.
    ///
    /// Checks that:
    /// - `epoch_id` is non-empty and within [`MAX_STRING_LENGTH`].
    /// - `principal_scope_hash` is non-zero.
    /// - `signer_public_key` is non-zero.
    /// - `freshness_tick` is strictly positive.
    /// - `signature` is non-zero (unsigned epochs are invalid).
    ///
    /// # Errors
    ///
    /// Returns `PcacValidationError` on the first violation found
    /// (fail-closed).
    pub fn validate(&self) -> Result<(), PcacValidationError> {
        if self.epoch_id.is_empty() {
            return Err(PcacValidationError::EmptyRequiredField { field: "epoch_id" });
        }
        if self.epoch_id.len() > MAX_STRING_LENGTH {
            return Err(PcacValidationError::StringTooLong {
                field: "epoch_id",
                len: self.epoch_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }

        if self.principal_scope_hash == ZERO_HASH {
            return Err(PcacValidationError::ZeroHash {
                field: "principal_scope_hash",
            });
        }
        if self.signer_public_key == ZERO_HASH {
            return Err(PcacValidationError::ZeroHash {
                field: "signer_public_key",
            });
        }
        if self.freshness_tick == 0 {
            return Err(PcacValidationError::NonPositiveTick {
                field: "freshness_tick",
            });
        }
        if self.signature == [0u8; 64] {
            return Err(PcacValidationError::ZeroHash { field: "signature" });
        }
        Ok(())
    }
}

/// Freeze action emitted on sovereignty uncertainty conditions.
///
/// When sovereignty state is uncertain, policy may require a freeze to
/// prevent authority consumption until the uncertainty is resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum FreezeAction {
    /// No freeze action required.
    NoAction,
    /// Soft freeze: deny new authority joins but allow in-flight consumes.
    SoftFreeze,
    /// Hard freeze: deny all authority operations immediately.
    HardFreeze,
}

impl std::fmt::Display for FreezeAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoAction => write!(f, "no_action"),
            Self::SoftFreeze => write!(f, "soft_freeze"),
            Self::HardFreeze => write!(f, "hard_freeze"),
        }
    }
}

/// Autonomy ceiling representing the maximum authority level for a scope.
///
/// Consume checks verify that the requested risk tier does not exceed the
/// autonomy ceiling for the principal's scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutonomyCeiling {
    /// Maximum risk tier allowed under this ceiling.
    pub max_risk_tier: RiskTier,

    /// Hash binding the ceiling to the policy that established it.
    pub policy_binding_hash: Hash,
}

// =============================================================================
// Policy Types (RFC-0027 §5, TCK-00428)
// =============================================================================

/// Enforcement mode for sovereignty checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SovereigntyEnforcementMode {
    /// Enforce all checks (epoch, revocation, ceiling, freeze).
    #[default]
    Strict,
    /// Monitor only (log violations but allow).
    Monitor,
    /// Disabled (bypass checks).
    Disabled,
}

impl std::fmt::Display for SovereigntyEnforcementMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Strict => write!(f, "strict"),
            Self::Monitor => write!(f, "monitor"),
            Self::Disabled => write!(f, "disabled"),
        }
    }
}

/// Waiver for `PointerOnly` identity evidence at Tier2+.
///
/// Per RFC-0027 §5: Tier2+ defaults to `Verified` identity. `PointerOnly`
/// is allowed only with an explicit, unexpired waiver bound to the session
/// or scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PointerOnlyWaiver {
    /// Unique waiver identifier (WVR-XXXX).
    #[serde(deserialize_with = "deserialize_bounded_string")]
    pub waiver_id: String,

    /// Expiry tick for the waiver.
    pub expires_at_tick: u64,

    /// Hash of the scope (e.g., `work_id` or `principal_id`) this waiver binds
    /// to.
    pub scope_binding_hash: Hash,
}

/// Waiver binding metadata persisted on lifecycle receipts for audit and
/// replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WaiverBindingMeta {
    /// Canonical hash of the waiver used at join time.
    pub waiver_hash: Hash,
    /// Human-readable scope identifier for audit surfaces.
    #[serde(deserialize_with = "deserialize_bounded_string")]
    pub waiver_scope: String,
    /// Tick at which the waiver expires.
    pub waiver_expires_at_tick: u64,
    /// Risk tier captured when the waiver was consumed.
    pub risk_tier_at_issuance: RiskTier,
}

/// Policy configuration for PCAC enforcement.
///
/// Defines the minimum policy knobs required by RFC-0027 for authority
/// lifecycle, identity evidence, and sovereignty checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcacPolicyKnobs {
    /// Whether to enforce the full join-revalidate-consume lifecycle.
    ///
    /// If `true`, `RequestTool` must pass the PCAC gate. If `false`, the
    /// gate is bypassed (Phase 1 opt-out).
    pub lifecycle_enforcement: bool,

    /// Minimum identity evidence level required for Tier2+ operations.
    pub min_tier2_identity_evidence: IdentityEvidenceLevel,

    /// Maximum age (in ticks) for freshness witnesses.
    pub freshness_max_age_ticks: u64,

    /// Sovereignty enforcement mode for Tier2+ operations.
    pub tier2_sovereignty_mode: SovereigntyEnforcementMode,

    /// Optional waiver permitting `PointerOnly` evidence in constrained paths.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pointer_only_waiver: Option<PointerOnlyWaiver>,
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

impl PointerOnlyWaiver {
    /// Returns a deterministic content hash used for join-time binding.
    #[must_use]
    pub fn content_hash(&self) -> Hash {
        use blake3::Hasher;

        let mut hasher = Hasher::new();
        hasher.update(b"pcac-pointer-only-waiver-v1");
        hasher.update(self.waiver_id.as_bytes());
        hasher.update(&self.expires_at_tick.to_le_bytes());
        hasher.update(&self.scope_binding_hash);
        *hasher.finalize().as_bytes()
    }

    /// Validates boundary constraints on waiver fields.
    ///
    /// # Errors
    ///
    /// Returns [`PcacValidationError`] when any field is empty, zero-valued,
    /// or exceeds bounded size constraints.
    pub fn validate(&self) -> Result<(), PcacValidationError> {
        if self.waiver_id.is_empty() {
            return Err(PcacValidationError::EmptyRequiredField { field: "waiver_id" });
        }
        if self.waiver_id.len() > MAX_STRING_LENGTH {
            return Err(PcacValidationError::StringTooLong {
                field: "waiver_id",
                len: self.waiver_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if self.expires_at_tick == 0 {
            return Err(PcacValidationError::NonPositiveTick {
                field: "expires_at_tick",
            });
        }
        if self.scope_binding_hash == ZERO_HASH {
            return Err(PcacValidationError::ZeroHash {
                field: "scope_binding_hash",
            });
        }
        Ok(())
    }
}

impl WaiverBindingMeta {
    /// Validates boundary constraints on waiver binding metadata.
    ///
    /// # Errors
    ///
    /// Returns [`PcacValidationError`] when any field is empty, zero-valued,
    /// or exceeds bounded size constraints.
    pub fn validate(&self) -> Result<(), PcacValidationError> {
        if self.waiver_hash == ZERO_HASH {
            return Err(PcacValidationError::ZeroHash {
                field: "waiver_hash",
            });
        }
        if self.waiver_scope.is_empty() {
            return Err(PcacValidationError::EmptyRequiredField {
                field: "waiver_scope",
            });
        }
        if self.waiver_scope.len() > MAX_STRING_LENGTH {
            return Err(PcacValidationError::StringTooLong {
                field: "waiver_scope",
                len: self.waiver_scope.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if self.waiver_expires_at_tick == 0 {
            return Err(PcacValidationError::NonPositiveTick {
                field: "waiver_expires_at_tick",
            });
        }
        Ok(())
    }
}

impl Default for PcacPolicyKnobs {
    fn default() -> Self {
        Self {
            lifecycle_enforcement: true,
            min_tier2_identity_evidence: IdentityEvidenceLevel::Verified,
            freshness_max_age_ticks: 100,
            tier2_sovereignty_mode: SovereigntyEnforcementMode::Strict,
            pointer_only_waiver: None,
        }
    }
}

impl AuthorityJoinCertificateV1 {
    /// Validate boundary constraints for authority join certificates.
    ///
    /// # Errors
    ///
    /// Returns `PcacValidationError` on the first violation found
    /// (fail-closed).
    pub fn validate(&self) -> Result<(), PcacValidationError> {
        if self.ajc_id == ZERO_HASH {
            return Err(PcacValidationError::ZeroHash { field: "ajc_id" });
        }
        if self.authority_join_hash == ZERO_HASH {
            return Err(PcacValidationError::ZeroHash {
                field: "authority_join_hash",
            });
        }
        if self.intent_digest == ZERO_HASH {
            return Err(PcacValidationError::ZeroHash {
                field: "intent_digest",
            });
        }
        if self.issued_time_envelope_ref == ZERO_HASH {
            return Err(PcacValidationError::ZeroHash {
                field: "issued_time_envelope_ref",
            });
        }
        if self.issued_at_tick == 0 {
            return Err(PcacValidationError::NonPositiveTick {
                field: "issued_at_tick",
            });
        }
        if self.as_of_ledger_anchor == ZERO_HASH {
            return Err(PcacValidationError::ZeroHash {
                field: "as_of_ledger_anchor",
            });
        }
        if self.revocation_head_hash == ZERO_HASH {
            return Err(PcacValidationError::ZeroHash {
                field: "revocation_head_hash",
            });
        }
        if let Some(token) = self.admission_capacity_token {
            if token == ZERO_HASH {
                return Err(PcacValidationError::ZeroHash {
                    field: "admission_capacity_token",
                });
            }
        }
        if self.expires_at_tick == 0 {
            return Err(PcacValidationError::NonPositiveTick {
                field: "expires_at_tick",
            });
        }
        Ok(())
    }
}

impl AuthorityConsumedV1 {
    /// Validate boundary constraints for consumed-authority witnesses.
    ///
    /// # Errors
    ///
    /// Returns `PcacValidationError` on the first violation found
    /// (fail-closed).
    pub fn validate(&self) -> Result<(), PcacValidationError> {
        if self.ajc_id == ZERO_HASH {
            return Err(PcacValidationError::ZeroHash { field: "ajc_id" });
        }
        if self.intent_digest == ZERO_HASH {
            return Err(PcacValidationError::ZeroHash {
                field: "intent_digest",
            });
        }
        if self.consumed_time_envelope_ref == ZERO_HASH {
            return Err(PcacValidationError::ZeroHash {
                field: "consumed_time_envelope_ref",
            });
        }
        if self.consumed_at_tick == 0 {
            return Err(PcacValidationError::NonPositiveTick {
                field: "consumed_at_tick",
            });
        }
        Ok(())
    }
}

impl AuthorityConsumeRecordV1 {
    /// Validate boundary constraints for durable consume records.
    ///
    /// # Errors
    ///
    /// Returns `PcacValidationError` on the first violation found
    /// (fail-closed).
    pub fn validate(&self) -> Result<(), PcacValidationError> {
        if self.ajc_id == ZERO_HASH {
            return Err(PcacValidationError::ZeroHash { field: "ajc_id" });
        }
        if self.consumed_time_envelope_ref == ZERO_HASH {
            return Err(PcacValidationError::ZeroHash {
                field: "consumed_time_envelope_ref",
            });
        }
        if self.consumed_at_tick == 0 {
            return Err(PcacValidationError::NonPositiveTick {
                field: "consumed_at_tick",
            });
        }
        if self.effect_selector_digest == ZERO_HASH {
            return Err(PcacValidationError::ZeroHash {
                field: "effect_selector_digest",
            });
        }
        Ok(())
    }
}
