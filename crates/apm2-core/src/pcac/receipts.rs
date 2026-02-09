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
use subtle::ConstantTimeEq;

use super::deny::AuthorityDenyClass;
use super::types::{
    MAX_CANONICALIZER_ID_LENGTH, MAX_CHECKPOINT_LENGTH, MAX_MERKLE_PROOF_STEPS,
    PcacValidationError, RiskTier,
};
use crate::crypto::Hash;

/// Zero hash constant for comparison.
const ZERO_HASH: Hash = [0u8; 32];
/// Canonicalizer IDs that are currently admissible for digest verification.
const ALLOWED_CANONICALIZER_IDS: &[&str] = &["blake3-canonical-v1", "apm2.canonicalizer.jcs"];

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

/// Receipt authentication shape — direct, pointer-unbatched, or
/// pointer-batched.
///
/// Per RFC-0027 §6.5, authoritative acceptance requires one of these
/// authentication shapes. Pointer authentication is split into two strict
/// variants to prevent omission of mandatory batched-path fields:
///
/// - `PointerUnbatched`: individual receipt auth without batch proof.
/// - `PointerBatched`: batch receipt auth with mandatory Merkle proof and batch
///   root hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "auth_type", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum ReceiptAuthentication {
    /// Direct receipt authentication via `authority_seal_hash`.
    Direct {
        /// Hash of the authority seal.
        authority_seal_hash: Hash,
    },

    /// Pointer authentication for an unbatched individual receipt.
    PointerUnbatched {
        /// Hash of the individual receipt.
        receipt_hash: Hash,
        /// Hash of the authority seal.
        authority_seal_hash: Hash,
    },

    /// Pointer authentication for a batched receipt — Merkle inclusion proof
    /// and batch root hash are mandatory.
    PointerBatched {
        /// Hash of the individual receipt.
        receipt_hash: Hash,
        /// Hash of the authority seal.
        authority_seal_hash: Hash,
        /// Merkle inclusion proof binding the receipt to the batch root.
        merkle_inclusion_proof: Vec<Hash>,
        /// Batch root hash for the receipt batch descriptor.
        receipt_batch_root_hash: Hash,
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

    /// Authoritative bindings (for authoritative mode).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authoritative_bindings: Option<AuthoritativeBindings>,
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

// =============================================================================
// Boundary validation for receipt types
// =============================================================================

impl ReceiptDigestMeta {
    /// Validate `canonicalizer_id` and `content_digest`.
    ///
    /// Checks:
    /// - `canonicalizer_id` is non-empty and within length bounds.
    /// - `content_digest` is non-zero.
    ///
    /// # Errors
    ///
    /// Returns `PcacValidationError` on the first violation found
    /// (fail-closed).
    pub fn validate(&self) -> Result<(), PcacValidationError> {
        if self.canonicalizer_id.is_empty() {
            return Err(PcacValidationError::EmptyRequiredField {
                field: "canonicalizer_id",
            });
        }
        if self.canonicalizer_id.len() > MAX_CANONICALIZER_ID_LENGTH {
            return Err(PcacValidationError::StringTooLong {
                field: "canonicalizer_id",
                len: self.canonicalizer_id.len(),
                max: MAX_CANONICALIZER_ID_LENGTH,
            });
        }
        if self.content_digest == ZERO_HASH {
            return Err(PcacValidationError::ZeroHash {
                field: "content_digest",
            });
        }
        Ok(())
    }

    /// Validate digest metadata under authoritative acceptance requirements.
    ///
    /// This enforces canonicalizer allowlisting in addition to
    /// [`Self::validate`].
    fn validate_authoritative(&self) -> Result<(), PcacValidationError> {
        self.validate()?;
        if !ALLOWED_CANONICALIZER_IDS
            .iter()
            .any(|id| self.canonicalizer_id == *id)
        {
            return Err(PcacValidationError::UnknownCanonicalizer {
                id: self.canonicalizer_id.clone(),
            });
        }
        Ok(())
    }

    /// Verify receipt digest against canonical bytes under an allowed
    /// canonicalization regime.
    ///
    /// # Errors
    ///
    /// Returns `PcacValidationError` if the canonicalizer is not allowlisted
    /// or if the digest does not match the BLAKE3 hash of `canonical_bytes`.
    pub fn verify_digest(&self, canonical_bytes: &[u8]) -> Result<(), PcacValidationError> {
        self.validate_authoritative()?;

        let computed = blake3::hash(canonical_bytes);
        if self.content_digest.ct_eq(computed.as_bytes()).unwrap_u8() != 1 {
            return Err(PcacValidationError::DigestMismatch);
        }
        Ok(())
    }
}

/// Enforce coherence between duplicated top-level and authoritative HTF witness
/// fields.
fn validate_time_envelope_ref_coherence(
    outer_time_envelope_ref: &Hash,
    bindings: &AuthoritativeBindings,
) -> Result<(), PcacValidationError> {
    if outer_time_envelope_ref != &bindings.time_envelope_ref {
        return Err(PcacValidationError::FieldCoherenceMismatch {
            outer_field: "time_envelope_ref",
            inner_field: "authoritative_bindings.time_envelope_ref",
        });
    }
    Ok(())
}

impl ReceiptAuthentication {
    /// Validate receipt authentication shape constraints.
    ///
    /// All variants enforce non-zero hash checks for mandatory cryptographic
    /// bindings. For `PointerBatched`, additionally:
    /// - Merkle inclusion proof must contain at least one step (non-empty).
    /// - Merkle inclusion proof must not exceed [`MAX_MERKLE_PROOF_STEPS`].
    ///
    /// # Errors
    ///
    /// Returns `PcacValidationError` on violation (fail-closed).
    pub fn validate(&self) -> Result<(), PcacValidationError> {
        match self {
            Self::Direct {
                authority_seal_hash,
            } => {
                if *authority_seal_hash == ZERO_HASH {
                    return Err(PcacValidationError::ZeroHash {
                        field: "authority_seal_hash",
                    });
                }
            },
            Self::PointerUnbatched {
                receipt_hash,
                authority_seal_hash,
            } => {
                if *receipt_hash == ZERO_HASH {
                    return Err(PcacValidationError::ZeroHash {
                        field: "receipt_hash",
                    });
                }
                if *authority_seal_hash == ZERO_HASH {
                    return Err(PcacValidationError::ZeroHash {
                        field: "authority_seal_hash",
                    });
                }
            },
            Self::PointerBatched {
                receipt_hash,
                authority_seal_hash,
                merkle_inclusion_proof,
                receipt_batch_root_hash,
            } => {
                if *receipt_hash == ZERO_HASH {
                    return Err(PcacValidationError::ZeroHash {
                        field: "receipt_hash",
                    });
                }
                if *authority_seal_hash == ZERO_HASH {
                    return Err(PcacValidationError::ZeroHash {
                        field: "authority_seal_hash",
                    });
                }
                if *receipt_batch_root_hash == ZERO_HASH {
                    return Err(PcacValidationError::ZeroHash {
                        field: "receipt_batch_root_hash",
                    });
                }
                if merkle_inclusion_proof.is_empty() {
                    return Err(PcacValidationError::EmptyMerkleProof);
                }
                if merkle_inclusion_proof.len() > MAX_MERKLE_PROOF_STEPS {
                    return Err(PcacValidationError::CollectionTooLarge {
                        field: "merkle_inclusion_proof",
                        count: merkle_inclusion_proof.len(),
                        max: MAX_MERKLE_PROOF_STEPS,
                    });
                }
                // Per-element zero-hash check for proof steps (fail-closed).
                for step in merkle_inclusion_proof {
                    if *step == ZERO_HASH {
                        return Err(PcacValidationError::ZeroHash {
                            field: "merkle_inclusion_proof[step]",
                        });
                    }
                }
            },
        }
        Ok(())
    }
}

impl AuthoritativeBindings {
    /// Validate all authoritative binding constraints.
    ///
    /// Checks:
    /// - `episode_envelope_hash` is non-zero.
    /// - `view_commitment_hash` is non-zero.
    /// - `time_envelope_ref` is non-zero.
    /// - Delegated-path binding coherence: `permeability_receipt_hash` and
    ///   `delegation_chain_hash` must both be present or both absent.
    /// - Delegated-path hashes, when present, must be non-zero.
    /// - Embedded receipt authentication shape is valid.
    ///
    /// # Errors
    ///
    /// Returns `PcacValidationError` on the first violation found
    /// (fail-closed).
    pub fn validate(&self) -> Result<(), PcacValidationError> {
        if self.episode_envelope_hash == ZERO_HASH {
            return Err(PcacValidationError::ZeroHash {
                field: "episode_envelope_hash",
            });
        }
        if self.view_commitment_hash == ZERO_HASH {
            return Err(PcacValidationError::ZeroHash {
                field: "view_commitment_hash",
            });
        }
        if self.time_envelope_ref == ZERO_HASH {
            return Err(PcacValidationError::ZeroHash {
                field: "time_envelope_ref",
            });
        }
        // Delegated-path binding coherence: both must co-occur or both be absent.
        match (&self.permeability_receipt_hash, &self.delegation_chain_hash) {
            (Some(prh), Some(dch)) => {
                if *prh == ZERO_HASH {
                    return Err(PcacValidationError::ZeroHash {
                        field: "permeability_receipt_hash",
                    });
                }
                if *dch == ZERO_HASH {
                    return Err(PcacValidationError::ZeroHash {
                        field: "delegation_chain_hash",
                    });
                }
            },
            (None, None) => { /* valid: no delegated path */ },
            _ => return Err(PcacValidationError::IncoherentDelegatedBindings),
        }
        self.authentication.validate()
    }
}

impl AuthorityRevalidateReceiptV1 {
    /// Validate all boundary constraints on this revalidation receipt.
    ///
    /// Checks:
    /// - Digest metadata is valid (non-empty canonicalizer, non-zero digest).
    /// - `ajc_id` is non-zero.
    /// - `time_envelope_ref` is non-zero.
    /// - `ledger_anchor` is non-zero.
    /// - `revocation_head_hash` is non-zero.
    /// - `revalidated_at_tick` is strictly positive.
    /// - `checkpoint` is non-empty and within length bounds.
    /// - Authoritative bindings, when present, are valid.
    ///
    /// # Errors
    ///
    /// Returns `PcacValidationError` on the first violation found
    /// (fail-closed).
    pub fn validate(&self) -> Result<(), PcacValidationError> {
        self.digest_meta.validate()?;
        if self.ajc_id == ZERO_HASH {
            return Err(PcacValidationError::ZeroHash { field: "ajc_id" });
        }
        if self.time_envelope_ref == ZERO_HASH {
            return Err(PcacValidationError::ZeroHash {
                field: "time_envelope_ref",
            });
        }
        if self.ledger_anchor == ZERO_HASH {
            return Err(PcacValidationError::ZeroHash {
                field: "ledger_anchor",
            });
        }
        if self.revocation_head_hash == ZERO_HASH {
            return Err(PcacValidationError::ZeroHash {
                field: "revocation_head_hash",
            });
        }
        if self.revalidated_at_tick == 0 {
            return Err(PcacValidationError::NonPositiveTick {
                field: "revalidated_at_tick",
            });
        }
        if self.checkpoint.is_empty() {
            return Err(PcacValidationError::EmptyRequiredField {
                field: "checkpoint",
            });
        }
        if self.checkpoint.len() > MAX_CHECKPOINT_LENGTH {
            return Err(PcacValidationError::StringTooLong {
                field: "checkpoint",
                len: self.checkpoint.len(),
                max: MAX_CHECKPOINT_LENGTH,
            });
        }
        if let Some(ref bindings) = self.authoritative_bindings {
            bindings.validate()?;
            validate_time_envelope_ref_coherence(&self.time_envelope_ref, bindings)?;
        }
        Ok(())
    }

    /// Validate this receipt as an authoritative trust-admission artifact.
    ///
    /// This is stricter than [`Self::validate`] and requires authoritative
    /// bindings to be present.
    ///
    /// # Errors
    ///
    /// Returns `PcacValidationError::MissingAuthoritativeBindings` when
    /// authoritative bindings are absent, or propagates any structural/binding
    /// validation error.
    pub fn validate_authoritative(&self) -> Result<(), PcacValidationError> {
        self.validate()?;
        self.digest_meta.validate_authoritative()?;
        let bindings = self.authoritative_bindings.as_ref().ok_or(
            PcacValidationError::MissingAuthoritativeBindings {
                receipt_type: "authority_revalidate_receipt_v1",
            },
        )?;
        bindings.validate()?;
        validate_time_envelope_ref_coherence(&self.time_envelope_ref, bindings)?;
        Ok(())
    }

    /// Validate this receipt as authoritative and verify digest against
    /// canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns any structural authoritative validation error from
    /// [`Self::validate_authoritative`] or digest verification error from
    /// [`ReceiptDigestMeta::verify_digest`].
    pub fn validate_authoritative_with_digest(
        &self,
        canonical_bytes: &[u8],
    ) -> Result<(), PcacValidationError> {
        self.validate_authoritative()?;
        self.digest_meta.verify_digest(canonical_bytes)?;
        Ok(())
    }
}

impl AuthorityJoinReceiptV1 {
    /// Validate all boundary constraints on this join receipt.
    ///
    /// Checks:
    /// - Digest metadata is valid (non-empty canonicalizer, non-zero digest).
    /// - `ajc_id` is non-zero.
    /// - `authority_join_hash` is non-zero.
    /// - `time_envelope_ref` is non-zero.
    /// - `ledger_anchor` is non-zero.
    /// - `joined_at_tick` is strictly positive.
    /// - Authoritative bindings, when present, are valid.
    ///
    /// # Errors
    ///
    /// Returns `PcacValidationError` on the first violation found
    /// (fail-closed).
    pub fn validate(&self) -> Result<(), PcacValidationError> {
        self.digest_meta.validate()?;
        if self.ajc_id == ZERO_HASH {
            return Err(PcacValidationError::ZeroHash { field: "ajc_id" });
        }
        if self.authority_join_hash == ZERO_HASH {
            return Err(PcacValidationError::ZeroHash {
                field: "authority_join_hash",
            });
        }
        if self.time_envelope_ref == ZERO_HASH {
            return Err(PcacValidationError::ZeroHash {
                field: "time_envelope_ref",
            });
        }
        if self.ledger_anchor == ZERO_HASH {
            return Err(PcacValidationError::ZeroHash {
                field: "ledger_anchor",
            });
        }
        if self.joined_at_tick == 0 {
            return Err(PcacValidationError::NonPositiveTick {
                field: "joined_at_tick",
            });
        }
        if let Some(ref bindings) = self.authoritative_bindings {
            bindings.validate()?;
            validate_time_envelope_ref_coherence(&self.time_envelope_ref, bindings)?;
        }
        Ok(())
    }

    /// Validate this receipt as an authoritative trust-admission artifact.
    ///
    /// This is stricter than [`Self::validate`] and requires authoritative
    /// bindings to be present.
    ///
    /// # Errors
    ///
    /// Returns `PcacValidationError::MissingAuthoritativeBindings` when
    /// authoritative bindings are absent, or propagates any structural/binding
    /// validation error.
    pub fn validate_authoritative(&self) -> Result<(), PcacValidationError> {
        self.validate()?;
        self.digest_meta.validate_authoritative()?;
        let bindings = self.authoritative_bindings.as_ref().ok_or(
            PcacValidationError::MissingAuthoritativeBindings {
                receipt_type: "authority_join_receipt_v1",
            },
        )?;
        bindings.validate()?;
        validate_time_envelope_ref_coherence(&self.time_envelope_ref, bindings)?;
        Ok(())
    }

    /// Validate this receipt as authoritative and verify digest against
    /// canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns any structural authoritative validation error from
    /// [`Self::validate_authoritative`] or digest verification error from
    /// [`ReceiptDigestMeta::verify_digest`].
    pub fn validate_authoritative_with_digest(
        &self,
        canonical_bytes: &[u8],
    ) -> Result<(), PcacValidationError> {
        self.validate_authoritative()?;
        self.digest_meta.verify_digest(canonical_bytes)?;
        Ok(())
    }
}

impl AuthorityConsumeReceiptV1 {
    /// Validate all boundary constraints on this consume receipt.
    ///
    /// Checks:
    /// - Digest metadata is valid (non-empty canonicalizer, non-zero digest).
    /// - `ajc_id` is non-zero.
    /// - `intent_digest` is non-zero.
    /// - `time_envelope_ref` is non-zero.
    /// - `ledger_anchor` is non-zero.
    /// - `consumed_at_tick` is strictly positive.
    /// - `effect_selector_digest` is non-zero.
    /// - Authoritative bindings, when present, are valid.
    ///
    /// # Errors
    ///
    /// Returns `PcacValidationError` on the first violation found
    /// (fail-closed).
    pub fn validate(&self) -> Result<(), PcacValidationError> {
        self.digest_meta.validate()?;
        if self.ajc_id == ZERO_HASH {
            return Err(PcacValidationError::ZeroHash { field: "ajc_id" });
        }
        if self.intent_digest == ZERO_HASH {
            return Err(PcacValidationError::ZeroHash {
                field: "intent_digest",
            });
        }
        if self.time_envelope_ref == ZERO_HASH {
            return Err(PcacValidationError::ZeroHash {
                field: "time_envelope_ref",
            });
        }
        if self.ledger_anchor == ZERO_HASH {
            return Err(PcacValidationError::ZeroHash {
                field: "ledger_anchor",
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
        // Optional hash field: pre_actuation_receipt_hash must be non-zero
        // when present (authority-critical binding).
        if let Some(ref parh) = self.pre_actuation_receipt_hash {
            if *parh == ZERO_HASH {
                return Err(PcacValidationError::ZeroHash {
                    field: "pre_actuation_receipt_hash",
                });
            }
        }
        if let Some(ref bindings) = self.authoritative_bindings {
            bindings.validate()?;
            validate_time_envelope_ref_coherence(&self.time_envelope_ref, bindings)?;
        }
        Ok(())
    }

    /// Validate this receipt as an authoritative trust-admission artifact.
    ///
    /// This is stricter than [`Self::validate`] and requires authoritative
    /// bindings to be present.
    ///
    /// # Errors
    ///
    /// Returns `PcacValidationError::MissingAuthoritativeBindings` when
    /// authoritative bindings are absent, or propagates any structural/binding
    /// validation error.
    pub fn validate_authoritative(&self) -> Result<(), PcacValidationError> {
        self.validate()?;
        self.digest_meta.validate_authoritative()?;
        let bindings = self.authoritative_bindings.as_ref().ok_or(
            PcacValidationError::MissingAuthoritativeBindings {
                receipt_type: "authority_consume_receipt_v1",
            },
        )?;
        bindings.validate()?;
        validate_time_envelope_ref_coherence(&self.time_envelope_ref, bindings)?;
        Ok(())
    }

    /// Validate this receipt as authoritative and verify digest against
    /// canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns any structural authoritative validation error from
    /// [`Self::validate_authoritative`] or digest verification error from
    /// [`ReceiptDigestMeta::verify_digest`].
    pub fn validate_authoritative_with_digest(
        &self,
        canonical_bytes: &[u8],
    ) -> Result<(), PcacValidationError> {
        self.validate_authoritative()?;
        self.digest_meta.verify_digest(canonical_bytes)?;
        Ok(())
    }
}

impl AuthorityDenyReceiptV1 {
    /// Validate all boundary constraints on this deny receipt.
    ///
    /// Checks:
    /// - Digest metadata is valid (non-empty canonicalizer, non-zero digest).
    /// - `deny_class` embedded string fields are within bounds.
    /// - `time_envelope_ref` is non-zero.
    /// - `ledger_anchor` is non-zero.
    /// - `denied_at_tick` is strictly positive.
    /// - `ajc_id`, when present, is non-zero.
    ///
    /// # Errors
    ///
    /// Returns `PcacValidationError` on the first violation found
    /// (fail-closed).
    pub fn validate(&self) -> Result<(), PcacValidationError> {
        self.digest_meta.validate()?;
        self.deny_class.validate()?;
        if self.time_envelope_ref == ZERO_HASH {
            return Err(PcacValidationError::ZeroHash {
                field: "time_envelope_ref",
            });
        }
        if self.ledger_anchor == ZERO_HASH {
            return Err(PcacValidationError::ZeroHash {
                field: "ledger_anchor",
            });
        }
        if self.denied_at_tick == 0 {
            return Err(PcacValidationError::NonPositiveTick {
                field: "denied_at_tick",
            });
        }
        if let Some(ref ajc) = self.ajc_id {
            if *ajc == ZERO_HASH {
                return Err(PcacValidationError::ZeroHash { field: "ajc_id" });
            }
        }
        if let Some(ref bindings) = self.authoritative_bindings {
            bindings.validate()?;
            validate_time_envelope_ref_coherence(&self.time_envelope_ref, bindings)?;
        }
        Ok(())
    }

    /// Validate this receipt as an authoritative trust-admission artifact.
    ///
    /// This is stricter than [`Self::validate`] and requires authoritative
    /// bindings to be present.
    ///
    /// # Errors
    ///
    /// Returns `PcacValidationError::MissingAuthoritativeBindings` when
    /// authoritative bindings are absent, or propagates any structural/binding
    /// validation error.
    pub fn validate_authoritative(&self) -> Result<(), PcacValidationError> {
        self.validate()?;
        self.digest_meta.validate_authoritative()?;
        let bindings = self.authoritative_bindings.as_ref().ok_or(
            PcacValidationError::MissingAuthoritativeBindings {
                receipt_type: "authority_deny_receipt_v1",
            },
        )?;
        bindings.validate()?;
        validate_time_envelope_ref_coherence(&self.time_envelope_ref, bindings)?;
        Ok(())
    }

    /// Validate this receipt as authoritative and verify digest against
    /// canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns any structural authoritative validation error from
    /// [`Self::validate_authoritative`] or digest verification error from
    /// [`ReceiptDigestMeta::verify_digest`].
    pub fn validate_authoritative_with_digest(
        &self,
        canonical_bytes: &[u8],
    ) -> Result<(), PcacValidationError> {
        self.validate_authoritative()?;
        self.digest_meta.verify_digest(canonical_bytes)?;
        Ok(())
    }
}
