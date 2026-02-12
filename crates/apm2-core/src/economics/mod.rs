//! Canonical economics profiles, deterministic budget admission, and
//! HTF-bound queue admission.
//!
//! This module implements RFC-0029 baseline primitives:
//! - REQ-0001: canonical, content-addressed economics profiles keyed by
//!   `(RiskTier, BoundaryIntentClass)`
//! - REQ-0001: deterministic admission decisions with fail-closed deny behavior
//! - REQ-0001: replay-verifiable admission traces with stable deny reasons
//! - REQ-0004: HTF-bound queue admission with lane reservations, tick-floor
//!   invariants, and anti-entropy anti-starvation enforcement

pub mod admission;
pub mod profile;
pub mod queue_admission;

pub use admission::{
    BudgetAdmissionDecision, BudgetAdmissionEvaluator, BudgetAdmissionTrace,
    BudgetAdmissionVerdict, ObservedUsage,
};
pub use profile::{
    BudgetEntry, ECONOMICS_PROFILE_HASH_DOMAIN, EconomicsProfile, EconomicsProfileError,
    EconomicsProfileInputState, LifecycleCostVector,
};
pub use queue_admission::{
    AntiEntropyAdmissionRequest, AntiEntropyBudget, AntiEntropyDirection, ConvergenceHorizonRef,
    ConvergenceReceipt, EnvelopeSignature, FreshnessHorizonRef, HtfEvaluationWindow, NoOpVerifier,
    QueueAdmissionDecision, QueueAdmissionRequest, QueueAdmissionTrace, QueueAdmissionVerdict,
    QueueDenyDefect, QueueLane, QueueSchedulerState, RevocationFrontierSnapshot, SignatureVerifier,
    TimeAuthorityEnvelopeV1, evaluate_anti_entropy_admission, evaluate_queue_admission,
    validate_convergence_horizon_tp003, validate_envelope_tp001, validate_freshness_horizon_tp002,
};
