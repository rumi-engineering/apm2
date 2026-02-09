// AGENT-AUTHORED
//! Receipt authentication verifier for PCAC acceptance-fact composition
//! (RFC-0027 §6.5, TCK-00425).
//!
//! This module implements the verification logic that distinguishes
//! authoritative acceptance facts from non-authoritative routing facts:
//!
//! - [`verify_receipt_authentication`]: validates direct or pointer/batched
//!   receipt authentication shapes.
//! - [`validate_authoritative_bindings`]: ensures all mandatory fields in
//!   [`AuthoritativeBindings`] are non-zero and structurally valid.
//! - [`classify_fact`]: classifies a lifecycle outcome as an acceptance fact or
//!   routing fact based on the presence and validity of authoritative bindings.
//!
//! # Fail-Closed Semantics
//!
//! Every function in this module fails closed: unknown authentication
//! shapes, missing fields, zero hashes, and malformed inclusion proofs
//! all produce deterministic [`AuthorityDenyV1`] denials.

use serde::{Deserialize, Serialize};

use super::deny::{AuthorityDenyClass, AuthorityDenyV1};
use super::receipts::{
    AuthoritativeBindings, LifecycleStage, MerkleProofEntry, ReceiptAuthentication,
};
use crate::consensus::merkle;
use crate::crypto::Hash;

/// Zero hash constant for fail-closed comparisons.
const ZERO_HASH: Hash = [0u8; 32];

/// Maximum number of sibling hashes in a merkle inclusion proof.
///
/// Bounded to the consensus merkle module's `MAX_PROOF_NODES` (21) to prevent
/// unbounded memory consumption on decode. Any proof deeper than this is
/// structurally invalid (a tree with >2^20 leaves).
pub(crate) const MAX_MERKLE_INCLUSION_PROOF_DEPTH: usize = merkle::MAX_PROOF_NODES;

// =============================================================================
// FactClass
// =============================================================================

/// Classification of a lifecycle outcome as acceptance fact or routing fact.
///
/// Per RFC-0027 §6.5:
/// - **Acceptance facts** have complete authoritative bindings with valid
///   receipt authentication. They are authority-bearing and suitable for
///   replay/adjudication.
/// - **Routing facts** lack authoritative bindings or have incomplete
///   authentication. They are forwarded raw bytes without admissible authority
///   proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactClass {
    /// Authoritative acceptance fact with valid receipt authentication.
    AcceptanceFact,
    /// Non-authoritative routing fact (missing or invalid bindings).
    RoutingFact,
}

impl std::fmt::Display for FactClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AcceptanceFact => write!(f, "acceptance_fact"),
            Self::RoutingFact => write!(f, "routing_fact"),
        }
    }
}

// =============================================================================
// Receipt authentication verification
// =============================================================================

/// Verify a receipt authentication shape is admissible.
///
/// # Direct Path
///
/// Verifies that `authority_seal_hash` is non-zero and matches the
/// `expected_seal_hash`.
///
/// # Pointer Path
///
/// Verifies:
/// 1. `receipt_hash` is non-zero.
/// 2. `authority_seal_hash` is non-zero and matches `expected_seal_hash`.
/// 3. If `merkle_inclusion_proof` is present, it is non-empty and all proof
///    hashes are non-zero. Each proof entry carries direction information for
///    correct left/right branch reconstruction.
/// 4. If `receipt_batch_root_hash` is present, it is non-zero.
/// 5. When `merkle_inclusion_proof` is present, `receipt_batch_root_hash` must
///    also be present (and vice versa).
/// 6. When `receipt_batch_root_hash` is present and `seal_subject_hash` is
///    provided, the batch root must equal the seal subject hash to anchor the
///    batch to the authority seal.
///
/// # Arguments
///
/// * `seal_subject_hash` - The subject hash authenticated by the authority
///   seal. When present, pointer-path batch roots MUST equal this hash to bind
///   the Merkle proof to the seal. Pass `None` when seal subject binding is
///   enforced elsewhere.
///
/// # Errors
///
/// Returns [`AuthorityDenyV1`] on any invalid or missing state.
pub fn verify_receipt_authentication(
    auth: &ReceiptAuthentication,
    expected_seal_hash: &Hash,
    seal_subject_hash: Option<&Hash>,
    time_envelope_ref: Hash,
    ledger_anchor: Hash,
    denied_at_tick: u64,
) -> Result<(), Box<AuthorityDenyV1>> {
    let ctx = DenyContext {
        time_envelope_ref,
        ledger_anchor,
        denied_at_tick,
    };
    match auth {
        ReceiptAuthentication::Direct {
            authority_seal_hash,
        } => verify_direct_auth(authority_seal_hash, expected_seal_hash, &ctx),
        ReceiptAuthentication::Pointer {
            receipt_hash,
            authority_seal_hash,
            merkle_inclusion_proof,
            receipt_batch_root_hash,
        } => verify_pointer_auth(
            receipt_hash,
            authority_seal_hash,
            expected_seal_hash,
            seal_subject_hash,
            merkle_inclusion_proof.as_deref(),
            receipt_batch_root_hash.as_ref(),
            &ctx,
        ),
    }
}

// =============================================================================
// Authoritative bindings validation
// =============================================================================

/// Validate that all mandatory authoritative binding fields are present,
/// non-zero, and contextually bound to the caller-provided witnesses.
///
/// Checks:
/// 1. `episode_envelope_hash` is non-zero.
/// 2. `view_commitment_hash` is non-zero and, when `expected_view_commitment`
///    is provided, equals the expected value.
/// 3. `time_envelope_ref` is non-zero and equals the contextual
///    `time_envelope_ref` argument (temporal binding).
/// 4. `authentication` shape is structurally valid (delegated to
///    [`verify_receipt_authentication`] by the caller).
/// 5. When `permeability_receipt_hash` is present, it must be non-zero.
/// 6. When `delegation_chain_hash` is present, it must be non-zero.
///
/// # Arguments
///
/// * `expected_view_commitment` - When provided, the `view_commitment_hash` in
///   the bindings must equal this value. Pass `None` when view commitment
///   binding is enforced elsewhere.
///
/// # Errors
///
/// Returns [`AuthorityDenyV1`] for any missing or zero-hash mandatory field,
/// or for contextual binding mismatch.
pub fn validate_authoritative_bindings(
    bindings: &AuthoritativeBindings,
    time_envelope_ref: Hash,
    ledger_anchor: Hash,
    denied_at_tick: u64,
    expected_view_commitment: Option<&Hash>,
) -> Result<(), Box<AuthorityDenyV1>> {
    let ctx = DenyContext {
        time_envelope_ref,
        ledger_anchor,
        denied_at_tick,
    };

    require_nonzero(
        &bindings.episode_envelope_hash,
        "episode_envelope_hash",
        &ctx,
    )?;
    require_nonzero(&bindings.view_commitment_hash, "view_commitment_hash", &ctx)?;
    require_nonzero(&bindings.time_envelope_ref, "time_envelope_ref", &ctx)?;

    // Contextual binding: time_envelope_ref in bindings MUST match the
    // caller-provided contextual witness. A mismatch indicates the receipt
    // was issued in a different temporal context.
    if bindings.time_envelope_ref != time_envelope_ref {
        return Err(make_deny(
            AuthorityDenyClass::UnknownState {
                description:
                    "bindings.time_envelope_ref does not match contextual time_envelope_ref"
                        .to_string(),
            },
            &ctx,
        ));
    }

    // Contextual binding: view_commitment_hash in bindings MUST match the
    // caller-provided expected view commitment when present.
    if let Some(expected_vc) = expected_view_commitment {
        if bindings.view_commitment_hash != *expected_vc {
            return Err(make_deny(
                AuthorityDenyClass::UnknownState {
                    description:
                        "bindings.view_commitment_hash does not match expected view commitment"
                            .to_string(),
                },
                &ctx,
            ));
        }
    }

    if let Some(ref h) = bindings.permeability_receipt_hash {
        require_nonzero(h, "permeability_receipt_hash", &ctx)?;
    }
    if let Some(ref h) = bindings.delegation_chain_hash {
        require_nonzero(h, "delegation_chain_hash", &ctx)?;
    }

    Ok(())
}

// =============================================================================
// Fact classification
// =============================================================================

/// Classify a lifecycle outcome as an acceptance fact or routing fact.
///
/// - If `bindings` is `None`, the outcome is a routing fact.
/// - If `bindings` is `Some`, validation is performed on all mandatory fields
///   and the authentication shape. If validation succeeds, the outcome is an
///   acceptance fact. If validation fails, the outcome is a routing fact
///   (fail-closed: invalid bindings do not produce acceptance facts).
///
/// # Arguments
///
/// * `seal_subject_hash` - The subject hash authenticated by the authority
///   seal. Passed through to pointer-path batch root verification. Pass `None`
///   when seal subject binding is enforced elsewhere.
/// * `expected_view_commitment` - The expected view commitment hash. Passed
///   through to contextual binding verification. Pass `None` when view
///   commitment binding is enforced elsewhere.
#[must_use]
pub fn classify_fact(
    bindings: Option<&AuthoritativeBindings>,
    expected_seal_hash: &Hash,
    seal_subject_hash: Option<&Hash>,
    time_envelope_ref: Hash,
    ledger_anchor: Hash,
    current_tick: u64,
    expected_view_commitment: Option<&Hash>,
) -> FactClass {
    let Some(bindings) = bindings else {
        return FactClass::RoutingFact;
    };

    if validate_authoritative_bindings(
        bindings,
        time_envelope_ref,
        ledger_anchor,
        current_tick,
        expected_view_commitment,
    )
    .is_err()
    {
        return FactClass::RoutingFact;
    }

    if verify_receipt_authentication(
        &bindings.authentication,
        expected_seal_hash,
        seal_subject_hash,
        time_envelope_ref,
        ledger_anchor,
        current_tick,
    )
    .is_err()
    {
        return FactClass::RoutingFact;
    }

    FactClass::AcceptanceFact
}

// =============================================================================
// Internal helpers
// =============================================================================

/// Context for building deny values.
struct DenyContext {
    time_envelope_ref: Hash,
    ledger_anchor: Hash,
    denied_at_tick: u64,
}

fn make_deny(deny_class: AuthorityDenyClass, ctx: &DenyContext) -> Box<AuthorityDenyV1> {
    Box::new(AuthorityDenyV1 {
        deny_class,
        ajc_id: None,
        time_envelope_ref: ctx.time_envelope_ref,
        ledger_anchor: ctx.ledger_anchor,
        denied_at_tick: ctx.denied_at_tick,
    })
}

fn require_nonzero(
    hash: &Hash,
    field_name: &str,
    ctx: &DenyContext,
) -> Result<(), Box<AuthorityDenyV1>> {
    if *hash == ZERO_HASH {
        return Err(make_deny(
            AuthorityDenyClass::ZeroHash {
                field_name: field_name.to_string(),
            },
            ctx,
        ));
    }
    Ok(())
}

fn verify_seal(
    authority_seal_hash: &Hash,
    expected_seal_hash: &Hash,
    ctx: &DenyContext,
) -> Result<(), Box<AuthorityDenyV1>> {
    require_nonzero(authority_seal_hash, "authority_seal_hash", ctx)?;
    if authority_seal_hash != expected_seal_hash {
        return Err(make_deny(
            AuthorityDenyClass::UnknownState {
                description: "authority_seal_hash does not match expected seal".to_string(),
            },
            ctx,
        ));
    }
    Ok(())
}

fn verify_direct_auth(
    authority_seal_hash: &Hash,
    expected_seal_hash: &Hash,
    ctx: &DenyContext,
) -> Result<(), Box<AuthorityDenyV1>> {
    verify_seal(authority_seal_hash, expected_seal_hash, ctx)
}

fn verify_pointer_auth(
    receipt_hash: &Hash,
    authority_seal_hash: &Hash,
    expected_seal_hash: &Hash,
    seal_subject_hash: Option<&Hash>,
    merkle_inclusion_proof: Option<&[MerkleProofEntry]>,
    receipt_batch_root_hash: Option<&Hash>,
    ctx: &DenyContext,
) -> Result<(), Box<AuthorityDenyV1>> {
    require_nonzero(receipt_hash, "receipt_hash", ctx)?;
    verify_seal(authority_seal_hash, expected_seal_hash, ctx)?;

    match (merkle_inclusion_proof, receipt_batch_root_hash) {
        (Some(proof), Some(batch_root)) => {
            if proof.is_empty() {
                return Err(make_deny(
                    AuthorityDenyClass::UnknownState {
                        description: "merkle_inclusion_proof is empty".to_string(),
                    },
                    ctx,
                ));
            }
            if proof.len() > MAX_MERKLE_INCLUSION_PROOF_DEPTH {
                return Err(make_deny(
                    AuthorityDenyClass::UnknownState {
                        description: format!(
                            "merkle_inclusion_proof length {} exceeds maximum {}",
                            proof.len(),
                            MAX_MERKLE_INCLUSION_PROOF_DEPTH,
                        ),
                    },
                    ctx,
                ));
            }
            for (i, entry) in proof.iter().enumerate() {
                if entry.sibling_hash == ZERO_HASH {
                    return Err(make_deny(
                        AuthorityDenyClass::ZeroHash {
                            field_name: format!("merkle_inclusion_proof[{i}]"),
                        },
                        ctx,
                    ));
                }
            }
            require_nonzero(batch_root, "receipt_batch_root_hash", ctx)?;

            // BLOCKER 2 fix: Verify batch root is authenticated by the
            // authority seal. The seal's subject hash must equal the batch
            // root to anchor the Merkle proof to the seal authority.
            if let Some(subject_hash) = seal_subject_hash {
                if batch_root != subject_hash {
                    return Err(make_deny(
                        AuthorityDenyClass::UnknownState {
                            description:
                                "receipt_batch_root_hash does not match seal subject hash: batch root not anchored to authority seal"
                                    .to_string(),
                        },
                        ctx,
                    ));
                }
            }

            // Deterministic inclusion verification: recompute the merkle root
            // from receipt_hash + direction-aware proof entries. Each entry
            // carries the sibling hash and a `sibling_is_left` flag that
            // determines hash ordering at each tree level.
            //
            // This matches the canonical `consensus::merkle` module's
            // direction-aware proof semantics. The leaf is hashed with the
            // `merkle:leaf:` prefix and internal nodes with
            // `merkle:internal:` prefix.
            let computed_root = recompute_merkle_root(receipt_hash, proof);
            if computed_root != *batch_root {
                return Err(make_deny(
                    AuthorityDenyClass::UnknownState {
                        description:
                            "merkle inclusion proof does not verify: recomputed root does not match receipt_batch_root_hash"
                                .to_string(),
                    },
                    ctx,
                ));
            }
        },
        (Some(_), None) => {
            return Err(make_deny(
                AuthorityDenyClass::UnknownState {
                    description: "merkle_inclusion_proof present without receipt_batch_root_hash"
                        .to_string(),
                },
                ctx,
            ));
        },
        (None, Some(_)) => {
            return Err(make_deny(
                AuthorityDenyClass::UnknownState {
                    description: "receipt_batch_root_hash present without merkle_inclusion_proof"
                        .to_string(),
                },
                ctx,
            ));
        },
        (None, None) => {},
    }
    Ok(())
}

/// Recompute the merkle root from a leaf hash and a direction-aware inclusion
/// proof.
///
/// The proof entries are `MerkleProofEntry` values ordered from leaf level to
/// root level. Each entry carries the sibling hash and a `sibling_is_left`
/// flag indicating the sibling's position at that tree level.
///
/// This function domain-separates the `leaf_data` hash as a leaf, then walks
/// up the proof using the consensus merkle `hash_internal` function, placing
/// sibling and current hashes in the correct left/right positions based on
/// the direction flag.
///
/// The caller is responsible for checking the result against the expected root.
fn recompute_merkle_root(leaf_data: &Hash, proof_entries: &[MerkleProofEntry]) -> Hash {
    let mut current = merkle::hash_leaf(leaf_data);
    for entry in proof_entries {
        if entry.sibling_is_left {
            // Sibling is on the left, current is on the right.
            current = merkle::hash_internal(&entry.sibling_hash, &current);
        } else {
            // Sibling is on the right, current is on the left.
            current = merkle::hash_internal(&current, &entry.sibling_hash);
        }
    }
    current
}

// =============================================================================
// Replay lifecycle ordering validation (REQ-0006)
// =============================================================================

/// Maximum number of lifecycle entries in a single replay sequence.
///
/// Bounded to prevent unbounded memory consumption on decode.
pub const MAX_REPLAY_LIFECYCLE_ENTRIES: usize = 256;

/// A lifecycle stage entry for replay ordering validation.
///
/// Per RFC-0027 §6.4 / REQ-0006, the authoritative replay lifecycle must
/// follow this strict ordering:
///
/// ```text
/// AuthorityJoin < AuthorityRevalidate < AuthorityConsume <= EffectReceipt
/// ```
///
/// When pre-actuation applies, `AuthorityConsume` MUST reference the prior
/// pre-actuation selector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayLifecycleEntry {
    /// The lifecycle stage of this entry.
    pub stage: LifecycleStage,
    /// Tick at which this entry occurred.
    pub tick: u64,
    /// Whether this entry requires pre-actuation (only relevant for Consume).
    pub requires_pre_actuation: bool,
    /// Pre-actuation selector hash (must be non-zero when
    /// `requires_pre_actuation` is true and stage is Consume).
    pub pre_actuation_selector_hash: Option<Hash>,
}

/// Validate replay lifecycle ordering per REQ-0006.
///
/// Checks:
/// 1. The sequence contains at least Join, Revalidate, Consume (and optionally
///    `EffectReceipt`, represented by `effect_receipt_tick`).
/// 2. All Join entries come before all Revalidate entries (strict `<`).
/// 3. All Revalidate entries come before all Consume entries (strict `<`).
/// 4. If `effect_receipt_tick` is present, all Consume ticks are `<=` it.
/// 5. When a Consume entry has `requires_pre_actuation`, the
///    `pre_actuation_selector_hash` MUST be present and non-zero.
/// 6. Entries do not exceed `MAX_REPLAY_LIFECYCLE_ENTRIES`.
///
/// # Errors
///
/// Returns [`AuthorityDenyV1`] with `BoundaryMonotonicityViolation` or
/// `MissingPreActuationReceipt` on invalid ordering.
pub fn validate_replay_lifecycle_order(
    entries: &[ReplayLifecycleEntry],
    effect_receipt_tick: Option<u64>,
    time_envelope_ref: Hash,
    ledger_anchor: Hash,
    denied_at_tick: u64,
) -> Result<(), Box<AuthorityDenyV1>> {
    let ctx = DenyContext {
        time_envelope_ref,
        ledger_anchor,
        denied_at_tick,
    };

    if entries.len() > MAX_REPLAY_LIFECYCLE_ENTRIES {
        return Err(make_deny(
            AuthorityDenyClass::UnknownState {
                description: format!(
                    "replay lifecycle entry count {} exceeds maximum {}",
                    entries.len(),
                    MAX_REPLAY_LIFECYCLE_ENTRIES,
                ),
            },
            &ctx,
        ));
    }

    let classified = classify_lifecycle_entries(entries, &ctx)?;
    require_all_stages_present(&classified, &ctx)?;
    check_stage_ordering(&classified, effect_receipt_tick, &ctx)
}

/// Ticks collected per lifecycle stage.
struct ClassifiedTicks {
    join: Vec<u64>,
    revalidate: Vec<u64>,
    consume: Vec<u64>,
}

/// Classify entries into per-stage tick vectors, validating pre-actuation along
/// the way.
fn classify_lifecycle_entries(
    entries: &[ReplayLifecycleEntry],
    ctx: &DenyContext,
) -> Result<ClassifiedTicks, Box<AuthorityDenyV1>> {
    let mut result = ClassifiedTicks {
        join: Vec::new(),
        revalidate: Vec::new(),
        consume: Vec::new(),
    };
    for entry in entries {
        match entry.stage {
            LifecycleStage::Join => result.join.push(entry.tick),
            LifecycleStage::Revalidate => result.revalidate.push(entry.tick),
            LifecycleStage::Consume => {
                result.consume.push(entry.tick);
                check_pre_actuation(entry, ctx)?;
            },
        }
    }
    Ok(result)
}

/// Validate pre-actuation selector completeness for a consume entry.
fn check_pre_actuation(
    entry: &ReplayLifecycleEntry,
    ctx: &DenyContext,
) -> Result<(), Box<AuthorityDenyV1>> {
    if !entry.requires_pre_actuation {
        return Ok(());
    }
    match entry.pre_actuation_selector_hash {
        None | Some(ZERO_HASH) => Err(make_deny(
            AuthorityDenyClass::MissingPreActuationReceipt,
            ctx,
        )),
        Some(_) => Ok(()),
    }
}

/// Require that all three lifecycle stages are present.
fn require_all_stages_present(
    ct: &ClassifiedTicks,
    ctx: &DenyContext,
) -> Result<(), Box<AuthorityDenyV1>> {
    for (ticks, name) in [
        (&ct.join, "AuthorityJoin"),
        (&ct.revalidate, "AuthorityRevalidate"),
        (&ct.consume, "AuthorityConsume"),
    ] {
        if ticks.is_empty() {
            return Err(make_deny(
                AuthorityDenyClass::BoundaryMonotonicityViolation {
                    description: format!("replay sequence missing {name} stage"),
                },
                ctx,
            ));
        }
    }
    Ok(())
}

/// Check strict ordering: Join < Revalidate < Consume <= `EffectReceipt`.
fn check_stage_ordering(
    ct: &ClassifiedTicks,
    effect_receipt_tick: Option<u64>,
    ctx: &DenyContext,
) -> Result<(), Box<AuthorityDenyV1>> {
    let max_join = ct.join.iter().copied().max().unwrap_or(0);
    let min_revalidate = ct.revalidate.iter().copied().min().unwrap_or(0);
    if max_join >= min_revalidate {
        return Err(make_deny(
            AuthorityDenyClass::BoundaryMonotonicityViolation {
                description: format!(
                    "AuthorityJoin tick ({max_join}) must be strictly less than \
                     AuthorityRevalidate tick ({min_revalidate})"
                ),
            },
            ctx,
        ));
    }

    let max_revalidate = ct.revalidate.iter().copied().max().unwrap_or(0);
    let min_consume = ct.consume.iter().copied().min().unwrap_or(0);
    if max_revalidate >= min_consume {
        return Err(make_deny(
            AuthorityDenyClass::BoundaryMonotonicityViolation {
                description: format!(
                    "AuthorityRevalidate tick ({max_revalidate}) must be strictly less than \
                     AuthorityConsume tick ({min_consume})"
                ),
            },
            ctx,
        ));
    }

    if let Some(effect_tick) = effect_receipt_tick {
        let max_consume = ct.consume.iter().copied().max().unwrap_or(0);
        if max_consume > effect_tick {
            return Err(make_deny(
                AuthorityDenyClass::BoundaryMonotonicityViolation {
                    description: format!(
                        "AuthorityConsume tick ({max_consume}) must be <= \
                         EffectReceipt tick ({effect_tick})"
                    ),
                },
                ctx,
            ));
        }
    }

    Ok(())
}
