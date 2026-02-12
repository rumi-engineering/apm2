//! Economics profiles, budget admission, and optimization gates.
//!
//! Canonical economics profiles, deterministic budget admission,
//! HTF-bound queue admission, replay-recovery bounds,
//! security-interlocked optimization gates, authority-surface
//! monotonicity enforcement, and tiered erasure+BFT reconstruction
//! admissibility.
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
//! - REQ-0008: authority-surface monotonicity and direct-GitHub non-regression
//!   enforcement for optimization candidates
//! - REQ-0009: projection multi-sink outage continuity and deferred replay
//!   boundedness with TP-EIO29-005 enforcement
//! - REQ-0010: tiered erasure+BFT reconstruction admissibility closure with
//!   TP-EIO29-001 and TP-EIO29-004 enforcement

pub mod admission;
pub mod optimization_gate;
pub mod profile;
pub mod projection_continuity;
pub mod queue_admission;
pub mod reconstruction_admissibility;
pub mod replay_recovery;

pub use admission::{
    BudgetAdmissionDecision, BudgetAdmissionEvaluator, BudgetAdmissionTrace,
    BudgetAdmissionVerdict, ObservedUsage,
};
pub use optimization_gate::{
    AuthoritySurfaceDiff, AuthoritySurfaceEvidence, AuthoritySurfaceEvidenceState,
    CANONICAL_EVALUATOR_ID, CountermetricProfile, DENY_ALPHA_ABOVE_THRESHOLD, DENY_ALPHA_NAN,
    DENY_ARBITRATION_NOT_AGREED_ALLOW, DENY_AUTHORITY_SURFACE_DIGEST_ZERO,
    DENY_AUTHORITY_SURFACE_EVIDENCE_AMBIGUOUS, DENY_AUTHORITY_SURFACE_EVIDENCE_FUTURE_TICK,
    DENY_AUTHORITY_SURFACE_EVIDENCE_MISSING, DENY_AUTHORITY_SURFACE_EVIDENCE_STALE,
    DENY_AUTHORITY_SURFACE_EVIDENCE_UNKNOWN, DENY_AUTHORITY_SURFACE_INCREASE,
    DENY_AUTHORITY_SURFACE_ROLE_ID_EMPTY, DENY_CAPABILITY_SURFACE_ENTRIES_OVERFLOW,
    DENY_COUNTERMETRIC_ENTRIES_OVERFLOW, DENY_COUNTERMETRIC_PROFILE_MISSING,
    DENY_DIRECT_GITHUB_CAPABILITY_REINTRODUCED, DENY_DISCLOSURE_CHANNELS_OVERFLOW,
    DENY_DISCLOSURE_MODE_MISMATCH, DENY_DISCLOSURE_POLICY_AMBIGUOUS,
    DENY_DISCLOSURE_POLICY_DIGEST_MISMATCH, DENY_DISCLOSURE_POLICY_DIGEST_ZERO,
    DENY_DISCLOSURE_POLICY_FUTURE_TICK, DENY_DISCLOSURE_POLICY_KEY_INVALID,
    DENY_DISCLOSURE_POLICY_MISSING, DENY_DISCLOSURE_POLICY_PHASE_ID_EMPTY,
    DENY_DISCLOSURE_POLICY_PHASE_MISMATCH, DENY_DISCLOSURE_POLICY_SIGNATURE_INVALID,
    DENY_DISCLOSURE_POLICY_SIGNATURE_ZERO, DENY_DISCLOSURE_POLICY_STALE,
    DENY_DISCLOSURE_POLICY_UNKNOWN, DENY_DISCLOSURE_POLICY_UNSIGNED, DENY_EVALUATOR_ID_EMPTY,
    DENY_EVIDENCE_FUTURE_TICK, DENY_EVIDENCE_QUALITY_MISSING, DENY_EVIDENCE_SAMPLES_OVERFLOW,
    DENY_EVIDENCE_STALE, DENY_KPI_ENTRIES_OVERFLOW, DENY_KPI_MISSING_COUNTERMETRIC,
    DENY_NON_CANONICAL_EVALUATOR, DENY_POWER_BELOW_THRESHOLD, DENY_POWER_NAN,
    DENY_PROPOSAL_DISCLOSURE_CHANNELS_OVERFLOW, DENY_REPRODUCIBILITY_INSUFFICIENT,
    DENY_RUNTIME_CLASSES_OVERFLOW, DENY_SAMPLE_SIZE_ZERO, DENY_THROUGHPUT_DOMINANCE_VIOLATION,
    DENY_THROUGHPUT_RATIO_NAN, DENY_TRADE_SECRET_PATENT_CHANNEL,
    DENY_UNAPPROVED_DISCLOSURE_CHANNEL, DisclosurePolicyMode, DisclosurePolicySnapshot,
    DisclosurePolicyState, EvidenceQualityReport, FORBIDDEN_TRADE_SECRET_CHANNEL_CLASSES,
    MAX_APPROVED_DISCLOSURE_CHANNELS, MAX_AUTHORITY_SURFACE_EVIDENCE_AGE_TICKS,
    MAX_CAPABILITY_SURFACE_ENTRIES, MAX_COUNTERMETRIC_ENTRIES, MAX_COUNTERMETRIC_ID_LENGTH,
    MAX_DISCLOSURE_CHANNEL_CLASS_LENGTH, MAX_DISCLOSURE_POLICY_AGE_TICKS,
    MAX_EVIDENCE_FRESHNESS_TICKS, MAX_EVIDENCE_SAMPLES, MAX_KPI_ENTRIES, MAX_KPI_ID_LENGTH,
    MAX_PHASE_ID_LENGTH, MAX_RUNTIME_CLASS_ID_LENGTH, MAX_RUNTIME_CLASSES, MAX_SIGNIFICANCE_ALPHA,
    MAX_SURFACE_CAPABILITY_ID_LENGTH, MAX_SURFACE_ROLE_ID_LENGTH,
    MIN_REPRODUCIBILITY_RUNTIME_CLASSES, MIN_STATISTICAL_POWER, OptimizationGateDecision,
    OptimizationGateTrace, OptimizationGateVerdict, OptimizationProposal,
    THROUGHPUT_DOMINANCE_MIN_RATIO, TemporalSloProfileV1, compute_disclosure_policy_digest,
    evaluate_optimization_gate, validate_arbitration_outcome, validate_authority_surface_evidence,
    validate_authority_surface_monotonicity, validate_canonical_evaluator_binding,
    validate_disclosure_channels, validate_disclosure_mode_match, validate_disclosure_policy,
    validate_evidence_freshness, validate_evidence_quality,
    validate_kpi_countermetric_completeness, validate_no_direct_github_capabilities,
    validate_throughput_dominance,
};
pub use profile::{
    BudgetEntry, ECONOMICS_PROFILE_HASH_DOMAIN, EconomicsProfile, EconomicsProfileError,
    EconomicsProfileInputState, LifecycleCostVector,
};
pub use projection_continuity::{
    ContinuityDecision, ContinuityDenyDefect, ContinuityScenarioVerdict, ContinuityVerdict,
    DeferredReplayInput, DeferredReplayMode, DeferredReplayReceiptV1, ProjectionContinuityError,
    ProjectionContinuityWindowV1, ProjectionSinkContinuityProfileV1, SinkIdentityEntry,
    SinkIdentitySnapshotV1, evaluate_projection_continuity, validate_deferred_replay_boundedness,
    validate_projection_continuity_tp005,
};
pub use queue_admission::{
    AntiEntropyAdmissionRequest, AntiEntropyBudget, AntiEntropyDirection, ConvergenceHorizonRef,
    ConvergenceReceipt, EnvelopeSignature, FreshnessHorizonRef, HtfEvaluationWindow, NoOpVerifier,
    QueueAdmissionDecision, QueueAdmissionRequest, QueueAdmissionTrace, QueueAdmissionVerdict,
    QueueDenyDefect, QueueLane, QueueSchedulerState, RevocationFrontierSnapshot, SignatureVerifier,
    TimeAuthorityEnvelopeV1, evaluate_anti_entropy_admission, evaluate_queue_admission,
    validate_convergence_horizon_tp003, validate_envelope_tp001, validate_freshness_horizon_tp002,
};
pub use reconstruction_admissibility::{
    BftQuorumCertificate, ErasureDecodeResult, ErasureProfile, QuorumSigner,
    ReconstructionAdmissibilityError, ReconstructionAdmissibilityReceiptV1,
    ReconstructionCheckInput, ReconstructionDecision, ReconstructionDenyDefect,
    ReconstructionFailureMode, ReconstructionMode, ReconstructionVerdict, SourceTrustSnapshot,
    evaluate_reconstruction_admissibility, validate_bft_quorum_certification,
    validate_erasure_decode, validate_reconstruction_receipts, validate_source_trust_snapshot,
};
pub use replay_recovery::{
    AdjacentWindowPair, BacklogState, IdempotencyCheckInput, IdempotencyMode,
    RecoveryAdmissibilityReceiptV1, RecoveryCheckInput, RecoveryMode, ReplayConvergenceHorizonRef,
    ReplayConvergenceReceiptV1, ReplayRecoveryDecision, ReplayRecoveryDenyDefect,
    ReplayRecoveryError, ReplayRecoveryVerdict, evaluate_replay_recovery,
    validate_recovery_admissibility, validate_replay_convergence_tp004,
    validate_replay_idempotency_tp007,
};
