// AGENT-AUTHORED
//! Proof-Carrying Authority Continuity (PCAC) — RFC-0027.
//!
//! This module implements the core PCAC primitives: the authority lifecycle
//! contract (`join -> revalidate -> consume -> effect`) that gates all
//! authority-bearing side effects with a single, canonical, one-time-consumable
//! authority witness.
//!
//! # Core Abstractions
//!
//! - [`AuthorityJoinInputV1`]: Canonical input set for computing admissible
//!   authority.
//! - [`AuthorityJoinCertificateV1`] (AJC): Single-use authority witness with
//!   copy-tolerant semantics.
//! - [`AuthorityJoinKernel`]: Minimal kernel API (`join`, `revalidate`,
//!   `consume`).
//! - Lifecycle receipts: [`AuthorityJoinReceiptV1`],
//!   [`AuthorityRevalidateReceiptV1`], [`AuthorityConsumeReceiptV1`],
//!   [`AuthorityDenyReceiptV1`].
//! - [`AuthorityDenyV1`]: Machine-checkable deny taxonomy.
//!
//! # Semantic Laws (RFC-0027 §4)
//!
//! 1. **Linear Consumption**: each AJC authorizes at most one side effect.
//! 2. **Intent Equality**: consume requires exact intent digest equality.
//! 3. **Freshness Dominance**: Tier2+ consume denies on stale/missing/ambiguous
//!    freshness.
//! 4. **Revocation Dominance**: revocation frontier advancement denies consume.
//! 5. **Delegation Narrowing**: delegated joins must be strict-subset of
//!    parent.
//! 6. **Boundary Monotonicity**: `join < revalidate <= consume <= effect`.
//! 7. **Evidence Sufficiency**: authoritative outcomes require
//!    replay-resolvable receipts.
//!
//! # Security Model
//!
//! All types enforce fail-closed semantics: missing required fields, unknown
//! enum variants, and ambiguous authority states produce deterministic denials.

mod auth_verifier;
mod deny;
mod evidence_export;
pub mod intent_class;
mod kernel;
mod receipts;
pub mod temporal_arbitration;
mod types;
pub mod verifier_economics;
pub mod verifier_metrics;

#[cfg(test)]
mod serialization_compat;
#[cfg(test)]
mod tests;

pub use auth_verifier::{
    BindingExpectations, FactClass, MAX_MERKLE_INCLUSION_PROOF_DEPTH, MAX_REPLAY_LIFECYCLE_ENTRIES,
    ReplayLifecycleEntry, TimedVerificationResult, classify_fact, timed_anti_entropy_verification,
    timed_classify_fact, timed_validate_authoritative_bindings,
    timed_validate_replay_lifecycle_order, timed_verify_receipt_authentication,
    validate_authoritative_bindings, validate_replay_lifecycle_order,
    verify_receipt_authentication,
};
pub use deny::{AuthorityDenyClass, AuthorityDenyV1};
pub use evidence_export::{
    PCAC_EVIDENCE_EXPORT_ROOT_ENV, PcacEvidenceBundle, PcacEvidenceExportError, PcacGateId,
    PcacLifecycleEvidenceState, PcacObjectiveId, PcacPredicateEvaluationReport,
    PcacPredicateSummary, PcacRuntimeExportOutcome, PredicateEvaluation, SummarySource,
    assert_exported_predicates, evaluate_exported_predicates, evaluate_gate_predicate_value,
    evaluate_objective_predicate_value, export_pcac_evidence_bundle, export_runtime_bundle_to_root,
    maybe_export_runtime_bundle, maybe_export_runtime_pass_bundle,
};
pub use intent_class::{AcceptanceFactClass, BoundaryIntentClass};
pub use kernel::AuthorityJoinKernel;
pub use receipts::{
    AuthoritativeBindings, AuthorityConsumeReceiptV1, AuthorityDenyReceiptV1,
    AuthorityJoinReceiptV1, AuthorityRevalidateReceiptV1, LifecycleStage, ReceiptAuthentication,
    ReceiptDigestMeta,
};
pub use temporal_arbitration::{
    ArbitrationAction, ArbitrationOutcome, EvaluatorTuple, FreshnessViolation,
    MAX_DENY_REASON_LENGTH, MAX_EVALUATOR_ID_LENGTH, MAX_EVALUATORS, MAX_PREDICATE_ID_LENGTH,
    RevocationViolation, TemporalArbitrationReceiptV1, TemporalPredicateId,
    check_freshness_dominance, check_revocation_dominance, map_arbitration_outcome,
};
pub use types::{
    AuthorityConsumeRecordV1, AuthorityConsumedV1, AuthorityJoinCertificateV1,
    AuthorityJoinInputV1, AutonomyCeiling, DeterminismClass, FreezeAction, IdentityEvidenceLevel,
    MAX_CANONICALIZER_ID_LENGTH, MAX_CHECKPOINT_LENGTH, MAX_DESCRIPTION_LENGTH,
    MAX_FIELD_NAME_LENGTH, MAX_MERKLE_PROOF_STEPS, MAX_OPERATION_LENGTH,
    MAX_PRE_ACTUATION_RECEIPT_HASHES, MAX_REASON_LENGTH, MAX_SCOPE_WITNESS_HASHES,
    MAX_STRING_LENGTH, PcacPolicyKnobs, PcacValidationError, PointerOnlyWaiver, RiskTier,
    SovereigntyEnforcementMode, SovereigntyEpoch, WaiverBindingMeta,
};
pub use verifier_economics::{
    VerifierEconomicsChecker, VerifierEconomicsProfile, VerifierOperation,
};
pub use verifier_metrics::{record_anti_entropy_event_metrics, record_verifier_metrics};
