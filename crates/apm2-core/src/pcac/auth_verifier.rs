// AGENT-AUTHORED
//! Receipt authentication verifier for PCAC acceptance-fact composition
//! (RFC-0027 §6.5, TCK-00425).
//!
//! This module implements verification logic for authoritative acceptance
//! facts:
//!
//! - [`verify_receipt_authentication`]: validates direct and pointer receipt
//!   authentication shapes.
//! - [`validate_authoritative_bindings`]: validates mandatory binding
//!   completeness and contextual witness coherence.
//! - [`classify_fact`]: classifies outcomes as authoritative acceptance facts
//!   vs non-authoritative routing facts.
//! - [`validate_replay_lifecycle_order`]: validates replay/adjudication
//!   lifecycle ordering and pre-actuation selector referential integrity.
//!
//! All checks fail closed: unknown, incomplete, or mismatched proof state is
//! denied.

use std::time::Instant;

use serde::{Deserialize, Serialize};
use subtle::{Choice, ConstantTimeEq};

use super::deny::{AuthorityDenyClass, AuthorityDenyV1};
use super::receipts::{AuthoritativeBindings, LifecycleStage, ReceiptAuthentication};
use crate::consensus::{anti_entropy, merkle};
use crate::crypto::Hash;

/// Zero hash constant for fail-closed comparisons.
const ZERO_HASH: Hash = [0u8; 32];

/// Maximum number of sibling hashes in a merkle inclusion proof.
///
/// Bound to consensus merkle constraints (`MAX_PROOF_NODES`) to prevent
/// unbounded decode/verification work.
pub const MAX_MERKLE_INCLUSION_PROOF_DEPTH: usize = merkle::MAX_PROOF_NODES;

/// Maximum number of lifecycle entries in a replay sequence.
pub const MAX_REPLAY_LIFECYCLE_ENTRIES: usize = 256;

/// Classification of lifecycle outcomes for replay/adjudication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactClass {
    /// Authoritative acceptance fact with admissible bindings + authentication.
    AcceptanceFact,
    /// Routing-only fact; non-authoritative for acceptance adjudication.
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

/// Optional contextual expectations for authoritative binding validation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BindingExpectations<'a> {
    /// Expected view commitment hash, if caller contract binds view commitment.
    pub expected_view_commitment: Option<&'a Hash>,
    /// Expected ledger anchor hash, if caller contract binds ledger anchor.
    pub expected_ledger_anchor: Option<&'a Hash>,
}

/// Replay lifecycle stage entry used by [`validate_replay_lifecycle_order`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayLifecycleEntry {
    /// Lifecycle stage.
    pub stage: LifecycleStage,
    /// Tick at which this stage occurred.
    pub tick: u64,
    /// Whether this consume stage requires a pre-actuation selector.
    pub requires_pre_actuation: bool,
    /// Pre-actuation selector hash, required when
    /// `requires_pre_actuation == true`.
    pub pre_actuation_selector_hash: Option<Hash>,
}

/// Result of a timed verification operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimedVerificationResult<T> {
    /// Original result returned by the verification operation.
    pub result: T,
    /// Elapsed wall-clock time in microseconds.
    pub elapsed_us: u64,
    /// Count of cryptographic proof checks performed by the operation.
    ///
    /// This count is reserved for cryptographic verification work
    /// (for example, digest comparisons or Merkle-proof verification calls).
    /// It intentionally excludes generic payload volume.
    pub proof_check_count: u64,
    /// Count of non-crypto items processed by the operation.
    ///
    /// For anti-entropy verification this is the number of events processed.
    /// Other verifier operations set this to `0`.
    pub event_count: u64,
}

/// Verify an authentication shape is admissible for authoritative acceptance.
///
/// `expected_seal_subject_hash` is required for all pointer paths:
///
/// - unbatched pointer: must equal `receipt_hash`
/// - batched pointer: must equal `receipt_batch_root_hash`
///
/// # Errors
///
/// Returns an [`AuthorityDenyV1`] on any missing, zero, malformed, or mismatch
/// state.
pub fn verify_receipt_authentication(
    auth: &ReceiptAuthentication,
    expected_seal_hash: &Hash,
    expected_seal_subject_hash: Option<&Hash>,
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
        ReceiptAuthentication::PointerUnbatched {
            receipt_hash,
            authority_seal_hash,
        } => verify_pointer_unbatched_auth(
            receipt_hash,
            authority_seal_hash,
            expected_seal_hash,
            expected_seal_subject_hash,
            &ctx,
        ),
        ReceiptAuthentication::PointerBatched {
            receipt_hash,
            authority_seal_hash,
            merkle_inclusion_proof,
            receipt_batch_root_hash,
        } => verify_pointer_batched_auth(
            receipt_hash,
            authority_seal_hash,
            merkle_inclusion_proof,
            receipt_batch_root_hash,
            expected_seal_hash,
            expected_seal_subject_hash,
            &ctx,
        ),
    }
}

/// Validate mandatory authoritative bindings for replay/adjudication.
///
/// This validates structural completeness, zero-hash rejection, contextual
/// time witness coherence, optional contextual view/ledger binding checks, and
/// delegated-path completeness.
///
/// # Errors
///
/// Returns an [`AuthorityDenyV1`] when required fields are zero/missing,
/// contextual bindings mismatch, or delegated-path bindings are incomplete.
pub fn validate_authoritative_bindings(
    bindings: &AuthoritativeBindings,
    time_envelope_ref: Hash,
    ledger_anchor: Hash,
    denied_at_tick: u64,
    expected_view_commitment: Option<&Hash>,
    expected_ledger_anchor: Option<&Hash>,
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
    require_nonzero(&ledger_anchor, "ledger_anchor", &ctx)?;

    if !hashes_equal(&bindings.time_envelope_ref, &time_envelope_ref) {
        return Err(make_deny(
            AuthorityDenyClass::UnknownState {
                description:
                    "bindings.time_envelope_ref does not match contextual time_envelope_ref"
                        .to_string(),
            },
            &ctx,
        ));
    }

    if let Some(expected_view_commitment) = expected_view_commitment {
        if !hashes_equal(&bindings.view_commitment_hash, expected_view_commitment) {
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

    if let Some(expected_ledger_anchor) = expected_ledger_anchor {
        if !hashes_equal(&ledger_anchor, expected_ledger_anchor) {
            return Err(make_deny(
                AuthorityDenyClass::UnknownState {
                    description: "contextual ledger_anchor does not match expected ledger anchor"
                        .to_string(),
                },
                &ctx,
            ));
        }
    }

    match (
        bindings.permeability_receipt_hash.as_ref(),
        bindings.delegation_chain_hash.as_ref(),
    ) {
        (Some(permeability_receipt_hash), Some(delegation_chain_hash)) => {
            require_nonzero(permeability_receipt_hash, "permeability_receipt_hash", &ctx)?;
            require_nonzero(delegation_chain_hash, "delegation_chain_hash", &ctx)?;
        },
        (None, None) => {},
        (Some(_), None) | (None, Some(_)) => {
            return Err(make_deny(
                AuthorityDenyClass::UnknownState {
                    description:
                        "delegated-path bindings are incomplete: permeability_receipt_hash and delegation_chain_hash must be present together"
                            .to_string(),
                },
                &ctx,
            ));
        },
    }

    Ok(())
}

/// Classify lifecycle outcome as authoritative acceptance vs routing fact.
///
/// Any missing/invalid authoritative bindings or invalid receipt auth shape is
/// routed as [`FactClass::RoutingFact`] (fail closed).
#[must_use]
pub fn classify_fact(
    bindings: Option<&AuthoritativeBindings>,
    expected_seal_hash: &Hash,
    expected_seal_subject_hash: Option<&Hash>,
    time_envelope_ref: Hash,
    ledger_anchor: Hash,
    current_tick: u64,
    expectations: BindingExpectations<'_>,
) -> FactClass {
    let Some(bindings) = bindings else {
        return FactClass::RoutingFact;
    };

    if validate_authoritative_bindings(
        bindings,
        time_envelope_ref,
        ledger_anchor,
        current_tick,
        expectations.expected_view_commitment,
        expectations.expected_ledger_anchor,
    )
    .is_err()
    {
        return FactClass::RoutingFact;
    }

    if verify_receipt_authentication(
        &bindings.authentication,
        expected_seal_hash,
        expected_seal_subject_hash,
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

/// Validate replay lifecycle order and pre-actuation selector completeness
/// (`REQ-0006`).
///
/// Enforces:
///
/// `AuthorityJoin < AuthorityRevalidate < AuthorityConsume <= EffectReceipt`
///
/// and pre-actuation selector referential integrity where required.
///
/// # Errors
///
/// Returns an [`AuthorityDenyV1`] with
/// [`AuthorityDenyClass::BoundaryMonotonicityViolation`] or
/// [`AuthorityDenyClass::MissingPreActuationReceipt`] when replay ordering or
/// selector integrity constraints fail.
pub fn validate_replay_lifecycle_order(
    entries: &[ReplayLifecycleEntry],
    effect_receipt_tick: Option<u64>,
    known_pre_actuation_hashes: &[Hash],
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

    let classified = classify_lifecycle_entries(entries, known_pre_actuation_hashes, &ctx)?;
    require_all_stages_present(&classified, &ctx)?;
    check_stage_ordering(&classified, effect_receipt_tick, &ctx)
}

/// Times [`verify_receipt_authentication`] and returns elapsed microseconds.
#[must_use]
pub fn timed_verify_receipt_authentication(
    auth: &ReceiptAuthentication,
    expected_seal_hash: &Hash,
    expected_seal_subject_hash: Option<&Hash>,
    time_envelope_ref: Hash,
    ledger_anchor: Hash,
    denied_at_tick: u64,
) -> TimedVerificationResult<Result<(), Box<AuthorityDenyV1>>> {
    let start = Instant::now();
    let result = verify_receipt_authentication(
        auth,
        expected_seal_hash,
        expected_seal_subject_hash,
        time_envelope_ref,
        ledger_anchor,
        denied_at_tick,
    );
    TimedVerificationResult {
        result,
        elapsed_us: elapsed_us_since(start),
        proof_check_count: proof_checks_for_receipt_auth(auth),
        event_count: 0,
    }
}

/// Times [`validate_authoritative_bindings`] and returns elapsed microseconds.
#[must_use]
pub fn timed_validate_authoritative_bindings(
    bindings: &AuthoritativeBindings,
    time_envelope_ref: Hash,
    ledger_anchor: Hash,
    denied_at_tick: u64,
    expected_view_commitment: Option<&Hash>,
    expected_ledger_anchor: Option<&Hash>,
) -> TimedVerificationResult<Result<(), Box<AuthorityDenyV1>>> {
    let start = Instant::now();
    let result = validate_authoritative_bindings(
        bindings,
        time_envelope_ref,
        ledger_anchor,
        denied_at_tick,
        expected_view_commitment,
        expected_ledger_anchor,
    );
    TimedVerificationResult {
        result,
        elapsed_us: elapsed_us_since(start),
        proof_check_count: proof_checks_for_validate_bindings(
            expected_view_commitment.is_some(),
            expected_ledger_anchor.is_some(),
        ),
        event_count: 0,
    }
}

/// Times [`classify_fact`] and returns elapsed microseconds.
#[must_use]
pub fn timed_classify_fact(
    bindings: Option<&AuthoritativeBindings>,
    expected_seal_hash: &Hash,
    expected_seal_subject_hash: Option<&Hash>,
    time_envelope_ref: Hash,
    ledger_anchor: Hash,
    current_tick: u64,
    expectations: BindingExpectations<'_>,
) -> TimedVerificationResult<FactClass> {
    let start = Instant::now();
    let binding_checks = bindings.map_or(0, |_| {
        proof_checks_for_validate_bindings(
            expectations.expected_view_commitment.is_some(),
            expectations.expected_ledger_anchor.is_some(),
        )
    });
    let receipt_checks = bindings.map_or(0, |binding| {
        proof_checks_for_receipt_auth(&binding.authentication)
    });
    let result = classify_fact(
        bindings,
        expected_seal_hash,
        expected_seal_subject_hash,
        time_envelope_ref,
        ledger_anchor,
        current_tick,
        expectations,
    );
    TimedVerificationResult {
        result,
        elapsed_us: elapsed_us_since(start),
        proof_check_count: binding_checks.saturating_add(receipt_checks),
        event_count: 0,
    }
}

/// Times [`validate_replay_lifecycle_order`] and returns elapsed microseconds.
#[must_use]
pub fn timed_validate_replay_lifecycle_order(
    entries: &[ReplayLifecycleEntry],
    effect_receipt_tick: Option<u64>,
    known_pre_actuation_hashes: &[Hash],
    time_envelope_ref: Hash,
    ledger_anchor: Hash,
    denied_at_tick: u64,
) -> TimedVerificationResult<Result<(), Box<AuthorityDenyV1>>> {
    let start = Instant::now();
    let result = validate_replay_lifecycle_order(
        entries,
        effect_receipt_tick,
        known_pre_actuation_hashes,
        time_envelope_ref,
        ledger_anchor,
        denied_at_tick,
    );
    TimedVerificationResult {
        result,
        elapsed_us: elapsed_us_since(start),
        proof_check_count: u64::try_from(entries.len()).unwrap_or(u64::MAX),
        event_count: 0,
    }
}

/// Times anti-entropy digest + transfer verification and returns elapsed
/// microseconds.
#[must_use]
pub fn timed_anti_entropy_verification(
    local_digest: Option<&Hash>,
    remote_digest: Option<&Hash>,
    events: &[anti_entropy::SyncEvent],
    expected_prev_hash: &Hash,
    expected_start_seq_id: Option<u64>,
    proof: Option<&merkle::MerkleProof>,
    proof_root: Option<&Hash>,
) -> TimedVerificationResult<Result<(), anti_entropy::AntiEntropyError>> {
    let start = Instant::now();
    let result = anti_entropy::verify_sync_catchup(
        local_digest,
        remote_digest,
        events,
        expected_prev_hash,
        expected_start_seq_id,
        proof,
        proof_root,
    );
    let digest_comparison_checks = u64::from(local_digest.is_some() && remote_digest.is_some());
    let merkle_proof_checks = u64::from(proof.is_some());
    TimedVerificationResult {
        result,
        elapsed_us: elapsed_us_since(start),
        proof_check_count: digest_comparison_checks.saturating_add(merkle_proof_checks),
        event_count: u64::try_from(events.len()).unwrap_or(u64::MAX),
    }
}

#[inline]
fn elapsed_us_since(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX)
}

/// Counts the constant-time hash comparisons performed by
/// [`validate_authoritative_bindings`].
///
/// 1 mandatory (`time_envelope_ref`) + conditionals for view commitment
/// and ledger anchor.
#[inline]
const fn proof_checks_for_validate_bindings(
    expected_view_commitment: bool,
    expected_ledger_anchor: bool,
) -> u64 {
    1 + expected_view_commitment as u64 + expected_ledger_anchor as u64
}

#[inline]
fn proof_checks_for_receipt_auth(auth: &ReceiptAuthentication) -> u64 {
    match auth {
        ReceiptAuthentication::PointerBatched {
            merkle_inclusion_proof,
            ..
        } => {
            let proof_depth = u64::try_from(merkle_inclusion_proof.len()).unwrap_or(u64::MAX);
            2_u64.saturating_add(proof_depth)
        },
        ReceiptAuthentication::Direct { .. } | ReceiptAuthentication::PointerUnbatched { .. } => 1,
    }
}

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
        containment_action: None,
    })
}

fn require_nonzero(
    hash: &Hash,
    field_name: &str,
    ctx: &DenyContext,
) -> Result<(), Box<AuthorityDenyV1>> {
    if bool::from(hash.ct_eq(&ZERO_HASH)) {
        return Err(make_deny(
            AuthorityDenyClass::ZeroHash {
                field_name: field_name.to_string(),
            },
            ctx,
        ));
    }
    Ok(())
}

#[inline]
fn hashes_equal(lhs: &Hash, rhs: &Hash) -> bool {
    bool::from(lhs.ct_eq(rhs))
}

fn verify_seal(
    authority_seal_hash: &Hash,
    expected_seal_hash: &Hash,
    ctx: &DenyContext,
) -> Result<(), Box<AuthorityDenyV1>> {
    require_nonzero(authority_seal_hash, "authority_seal_hash", ctx)?;
    if !hashes_equal(authority_seal_hash, expected_seal_hash) {
        return Err(make_deny(
            AuthorityDenyClass::UnknownState {
                description: "authority_seal_hash does not match expected seal".to_string(),
            },
            ctx,
        ));
    }
    Ok(())
}

fn require_expected_subject(
    expected_seal_subject_hash: Option<&Hash>,
    path_name: &str,
    ctx: &DenyContext,
) -> Result<Hash, Box<AuthorityDenyV1>> {
    let subject_hash = expected_seal_subject_hash.ok_or_else(|| {
        make_deny(
            AuthorityDenyClass::UnknownState {
                description: format!(
                    "missing expected_seal_subject_hash for {path_name} pointer verification"
                ),
            },
            ctx,
        )
    })?;
    require_nonzero(subject_hash, "expected_seal_subject_hash", ctx)?;
    Ok(*subject_hash)
}

fn verify_direct_auth(
    authority_seal_hash: &Hash,
    expected_seal_hash: &Hash,
    ctx: &DenyContext,
) -> Result<(), Box<AuthorityDenyV1>> {
    verify_seal(authority_seal_hash, expected_seal_hash, ctx)
}

fn verify_pointer_unbatched_auth(
    receipt_hash: &Hash,
    authority_seal_hash: &Hash,
    expected_seal_hash: &Hash,
    expected_seal_subject_hash: Option<&Hash>,
    ctx: &DenyContext,
) -> Result<(), Box<AuthorityDenyV1>> {
    require_nonzero(receipt_hash, "receipt_hash", ctx)?;
    verify_seal(authority_seal_hash, expected_seal_hash, ctx)?;

    let subject_hash = require_expected_subject(expected_seal_subject_hash, "unbatched", ctx)?;
    if !hashes_equal(receipt_hash, &subject_hash) {
        return Err(make_deny(
            AuthorityDenyClass::UnknownState {
                description:
                    "UnbatchedReceiptNotSealSubject: receipt_hash does not match expected_seal_subject_hash"
                        .to_string(),
            },
            ctx,
        ));
    }
    Ok(())
}

fn verify_pointer_batched_auth(
    receipt_hash: &Hash,
    authority_seal_hash: &Hash,
    merkle_inclusion_proof: &[Hash],
    receipt_batch_root_hash: &Hash,
    expected_seal_hash: &Hash,
    expected_seal_subject_hash: Option<&Hash>,
    ctx: &DenyContext,
) -> Result<(), Box<AuthorityDenyV1>> {
    require_nonzero(receipt_hash, "receipt_hash", ctx)?;
    verify_seal(authority_seal_hash, expected_seal_hash, ctx)?;

    if merkle_inclusion_proof.is_empty() {
        return Err(make_deny(
            AuthorityDenyClass::UnknownState {
                description: "merkle_inclusion_proof is empty".to_string(),
            },
            ctx,
        ));
    }
    if merkle_inclusion_proof.len() > MAX_MERKLE_INCLUSION_PROOF_DEPTH {
        return Err(make_deny(
            AuthorityDenyClass::UnknownState {
                description: format!(
                    "merkle_inclusion_proof length {} exceeds maximum {}",
                    merkle_inclusion_proof.len(),
                    MAX_MERKLE_INCLUSION_PROOF_DEPTH,
                ),
            },
            ctx,
        ));
    }
    for step in merkle_inclusion_proof {
        require_nonzero(step, "merkle_inclusion_proof[step]", ctx)?;
    }
    require_nonzero(receipt_batch_root_hash, "receipt_batch_root_hash", ctx)?;

    let subject_hash = require_expected_subject(expected_seal_subject_hash, "batched", ctx)?;
    if !hashes_equal(receipt_batch_root_hash, &subject_hash) {
        return Err(make_deny(
            AuthorityDenyClass::UnknownState {
                description:
                    "receipt_batch_root_hash does not match expected_seal_subject_hash: batch root not anchored to authority seal"
                        .to_string(),
            },
            ctx,
        ));
    }

    if !verify_merkle_proof_unordered(
        receipt_hash,
        merkle_inclusion_proof,
        receipt_batch_root_hash,
    ) {
        return Err(make_deny(
            AuthorityDenyClass::UnknownState {
                description:
                    "merkle inclusion proof does not verify: recomputed root does not match receipt_batch_root_hash"
                        .to_string(),
            },
            ctx,
        ));
    }

    Ok(())
}

/// Verifies inclusion without explicit branch-direction bits.
///
/// Current receipt schema encodes sibling hashes only; branch orientation is
/// not present. Verification therefore succeeds when any admissible
/// left/right ordering across the bounded proof depth recomputes the expected
/// root.
#[must_use]
fn verify_merkle_proof_unordered(
    receipt_hash: &Hash,
    merkle_inclusion_proof: &[Hash],
    expected_root: &Hash,
) -> bool {
    let leaf_hash = merkle::hash_leaf(receipt_hash);
    verify_merkle_path_dfs(&leaf_hash, merkle_inclusion_proof, expected_root)
}

#[must_use]
fn verify_merkle_path_dfs(current: &Hash, remaining: &[Hash], expected_root: &Hash) -> bool {
    if remaining.is_empty() {
        return hashes_equal(current, expected_root);
    }

    let sibling = remaining[0];
    let tail = &remaining[1..];

    let left = merkle::hash_internal(current, &sibling);
    if verify_merkle_path_dfs(&left, tail, expected_root) {
        return true;
    }

    let right = merkle::hash_internal(&sibling, current);
    verify_merkle_path_dfs(&right, tail, expected_root)
}

struct ClassifiedTicks {
    join: Vec<u64>,
    revalidate: Vec<u64>,
    consume: Vec<u64>,
}

fn classify_lifecycle_entries(
    entries: &[ReplayLifecycleEntry],
    known_pre_actuation_hashes: &[Hash],
    ctx: &DenyContext,
) -> Result<ClassifiedTicks, Box<AuthorityDenyV1>> {
    let mut classified = ClassifiedTicks {
        join: Vec::new(),
        revalidate: Vec::new(),
        consume: Vec::new(),
    };

    for entry in entries {
        match entry.stage {
            LifecycleStage::Join => classified.join.push(entry.tick),
            LifecycleStage::Revalidate => classified.revalidate.push(entry.tick),
            LifecycleStage::Consume => {
                classified.consume.push(entry.tick);
                check_pre_actuation(entry, known_pre_actuation_hashes, ctx)?;
            },
        }
    }

    Ok(classified)
}

fn check_pre_actuation(
    entry: &ReplayLifecycleEntry,
    known_pre_actuation_hashes: &[Hash],
    ctx: &DenyContext,
) -> Result<(), Box<AuthorityDenyV1>> {
    if !entry.requires_pre_actuation {
        return Ok(());
    }

    let selector = match entry.pre_actuation_selector_hash {
        Some(selector) if !hashes_equal(&selector, &ZERO_HASH) => selector,
        _ => {
            return Err(make_deny(
                AuthorityDenyClass::MissingPreActuationReceipt,
                ctx,
            ));
        },
    };

    let mut found = Choice::from(0u8);
    for known in known_pre_actuation_hashes {
        found |= known.ct_eq(&selector);
    }
    if found.unwrap_u8() != 1 {
        return Err(make_deny(
            AuthorityDenyClass::MissingPreActuationReceipt,
            ctx,
        ));
    }

    Ok(())
}

fn require_all_stages_present(
    classified: &ClassifiedTicks,
    ctx: &DenyContext,
) -> Result<(), Box<AuthorityDenyV1>> {
    for (ticks, stage_name) in [
        (&classified.join, "AuthorityJoin"),
        (&classified.revalidate, "AuthorityRevalidate"),
        (&classified.consume, "AuthorityConsume"),
    ] {
        if ticks.is_empty() {
            return Err(make_deny(
                AuthorityDenyClass::BoundaryMonotonicityViolation {
                    description: format!("replay sequence missing {stage_name} stage"),
                },
                ctx,
            ));
        }
    }
    Ok(())
}

fn check_stage_ordering(
    classified: &ClassifiedTicks,
    effect_receipt_tick: Option<u64>,
    ctx: &DenyContext,
) -> Result<(), Box<AuthorityDenyV1>> {
    let max_join = classified.join.iter().copied().max().unwrap_or(0);
    let min_revalidate = classified.revalidate.iter().copied().min().unwrap_or(0);
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

    let max_revalidate = classified.revalidate.iter().copied().max().unwrap_or(0);
    let min_consume = classified.consume.iter().copied().min().unwrap_or(0);
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
        let max_consume = classified.consume.iter().copied().max().unwrap_or(0);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::merkle;

    const fn test_hash(byte: u8) -> Hash {
        [byte; 32]
    }

    #[test]
    fn proof_checks_for_receipt_auth_direct_counts_one() {
        let auth = ReceiptAuthentication::Direct {
            authority_seal_hash: test_hash(0x11),
        };

        let timed = timed_verify_receipt_authentication(
            &auth,
            &test_hash(0x11),
            None,
            test_hash(0x12),
            test_hash(0x13),
            100,
        );
        assert!(timed.result.is_ok(), "direct auth should verify");
        assert_eq!(timed.proof_check_count, 1);
    }

    #[test]
    fn proof_checks_for_receipt_auth_pointer_unbatched_counts_one() {
        let receipt_hash = test_hash(0x21);
        let auth = ReceiptAuthentication::PointerUnbatched {
            receipt_hash,
            authority_seal_hash: test_hash(0x22),
        };

        let timed = timed_verify_receipt_authentication(
            &auth,
            &test_hash(0x22),
            Some(&receipt_hash),
            test_hash(0x23),
            test_hash(0x24),
            200,
        );
        assert!(timed.result.is_ok(), "pointer-unbatched auth should verify");
        assert_eq!(timed.proof_check_count, 1);
    }

    #[test]
    fn proof_checks_for_receipt_auth_pointer_batched_counts_depth_plus_two() {
        let receipt_hash = test_hash(0x31);
        let authority_seal_hash = test_hash(0x32);
        let merkle_inclusion_proof = vec![test_hash(0x33), test_hash(0x34), test_hash(0x35)];
        let expected_proof_checks =
            2_u64.saturating_add(u64::try_from(merkle_inclusion_proof.len()).unwrap_or(u64::MAX));

        let mut receipt_batch_root_hash = merkle::hash_leaf(&receipt_hash);
        for sibling in &merkle_inclusion_proof {
            receipt_batch_root_hash = merkle::hash_internal(&receipt_batch_root_hash, sibling);
        }

        let auth = ReceiptAuthentication::PointerBatched {
            receipt_hash,
            authority_seal_hash,
            merkle_inclusion_proof,
            receipt_batch_root_hash,
        };

        let timed = timed_verify_receipt_authentication(
            &auth,
            &authority_seal_hash,
            Some(&receipt_batch_root_hash),
            test_hash(0x36),
            test_hash(0x37),
            300,
        );
        assert!(timed.result.is_ok(), "pointer-batched auth should verify");
        assert_eq!(timed.proof_check_count, expected_proof_checks);
    }
}
