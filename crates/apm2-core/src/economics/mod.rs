//! Canonical economics profiles, deterministic budget admission,
//! HTF-bound queue admission, replay-recovery bounds, and
//! security-interlocked optimization gates.
//!
//! This module implements RFC-0029 baseline primitives:
//! - REQ-0001: canonical, content-addressed economics profiles keyed by
//!   `(RiskTier, BoundaryIntentClass)`
//! - REQ-0001: deterministic admission decisions with fail-closed deny behavior
//! - REQ-0001: replay-verifiable admission traces with stable deny reasons
//! - REQ-0004: HTF-bound queue admission with lane reservations, tick-floor
//!   invariants, and anti-entropy anti-starvation enforcement
//! - REQ-0005: replay-recovery bounds and idempotency closure with TP-EIO29-004
//!   and TP-EIO29-007 enforcement
//! - REQ-0006: security-interlocked optimization gates and quantitative
//!   evidence quality enforcement

pub mod admission;
pub mod optimization_gate;
pub mod profile;
pub mod queue_admission;
pub mod replay_recovery;

pub use admission::{
    BudgetAdmissionDecision, BudgetAdmissionEvaluator, BudgetAdmissionTrace,
    BudgetAdmissionVerdict, ObservedUsage,
};
pub use optimization_gate::{
    CANONICAL_EVALUATOR_ID, CountermetricProfile, DENY_ALPHA_ABOVE_THRESHOLD, DENY_ALPHA_NAN,
    DENY_ARBITRATION_NOT_AGREED_ALLOW, DENY_COUNTERMETRIC_ENTRIES_OVERFLOW,
    DENY_COUNTERMETRIC_PROFILE_MISSING, DENY_EVALUATOR_ID_EMPTY, DENY_EVIDENCE_FUTURE_TICK,
    DENY_EVIDENCE_QUALITY_MISSING, DENY_EVIDENCE_SAMPLES_OVERFLOW, DENY_EVIDENCE_STALE,
    DENY_KPI_ENTRIES_OVERFLOW, DENY_KPI_MISSING_COUNTERMETRIC, DENY_NON_CANONICAL_EVALUATOR,
    DENY_POWER_BELOW_THRESHOLD, DENY_POWER_NAN, DENY_REPRODUCIBILITY_INSUFFICIENT,
    DENY_RUNTIME_CLASSES_OVERFLOW, DENY_SAMPLE_SIZE_ZERO, DENY_THROUGHPUT_DOMINANCE_VIOLATION,
    DENY_THROUGHPUT_RATIO_NAN, EvidenceQualityReport, MAX_COUNTERMETRIC_ENTRIES,
    MAX_COUNTERMETRIC_ID_LENGTH, MAX_EVIDENCE_FRESHNESS_TICKS, MAX_EVIDENCE_SAMPLES,
    MAX_KPI_ENTRIES, MAX_KPI_ID_LENGTH, MAX_RUNTIME_CLASS_ID_LENGTH, MAX_RUNTIME_CLASSES,
    MAX_SIGNIFICANCE_ALPHA, MIN_REPRODUCIBILITY_RUNTIME_CLASSES, MIN_STATISTICAL_POWER,
    OptimizationGateDecision, OptimizationGateTrace, OptimizationGateVerdict, OptimizationProposal,
    THROUGHPUT_DOMINANCE_MIN_RATIO, TemporalSloProfileV1, evaluate_optimization_gate,
    validate_arbitration_outcome, validate_canonical_evaluator_binding,
    validate_evidence_freshness, validate_evidence_quality,
    validate_kpi_countermetric_completeness, validate_throughput_dominance,
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
pub use replay_recovery::{
    AdjacentWindowPair, BacklogState, IdempotencyCheckInput, IdempotencyMode,
    RecoveryAdmissibilityReceiptV1, RecoveryCheckInput, RecoveryMode, ReplayConvergenceHorizonRef,
    ReplayConvergenceReceiptV1, ReplayRecoveryDecision, ReplayRecoveryDenyDefect,
    ReplayRecoveryError, ReplayRecoveryVerdict, evaluate_replay_recovery,
    validate_recovery_admissibility, validate_replay_convergence_tp004,
    validate_replay_idempotency_tp007,
};
