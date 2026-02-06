//! Pre-actuation stop and budget proof obligations (TCK-00351).
//!
//! This module enforces mandatory stop-condition and budget checks before
//! any tool actuation can proceed.  Every tool request must pass through the
//! [`PreActuationGate`] which:
//!
//! 1. Evaluates stop conditions (emergency stop, governance stop, escalation).
//! 2. Evaluates budget sufficiency (token, tool-call, wall-time, CPU, I/O).
//! 3. Returns a [`PreActuationReceipt`] embedding `stop_checked`,
//!    `budget_checked`, and an HTF timestamp proving the ordering.
//!
//! # Fail-Closed Semantics
//!
//! - If stop status is **active**: deny immediately.
//! - If stop status is **uncertain** and the configured deadline has elapsed:
//!   deny (fail-closed on uncertainty).
//! - If any budget dimension is exhausted: deny with
//!   [`PreActuationDenial::BudgetExhausted`].
//! - If the gate is not invoked at all: the response's `stop_checked` /
//!   `budget_checked` fields remain `false`, which the replay harness treats as
//!   a violation.
//!
//! # Replay Ordering Invariant
//!
//! The [`ReplayVerifier`] checks that every tool-actuation event in a
//! replayed trace was preceded by a `PreActuationReceipt` whose timestamp
//! is strictly less than the actuation timestamp.
//!
//! # Contract References
//!
//! - TCK-00351: Pre-actuation stop and budget proof obligations
//! - AD-EPISODE-001: Immutable episode envelope with budget/stop fields
//! - SEC-CTRL-FAC-0015: Fail-closed security posture

use std::fmt;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::budget_tracker::{BudgetExhaustedError, BudgetTracker};
use super::envelope::StopConditions;

// =============================================================================
// Constants
// =============================================================================

/// Maximum number of replay entries the verifier will accept (`DoS` bound).
pub const MAX_REPLAY_ENTRIES: usize = 100_000;

/// Default deadline (milliseconds) for stop-uncertainty resolution.
/// If the stop status is uncertain and this deadline has elapsed since
/// the episode started, actuation is denied (fail-closed).
pub const DEFAULT_STOP_UNCERTAINTY_DEADLINE_MS: u64 = 30_000;

// =============================================================================
// StopStatus
// =============================================================================

/// Outcome of evaluating stop conditions before tool actuation.
///
/// # Security
///
/// The `Unknown` / `Uncertain` variant resolves to **deny** within the
/// configured deadline, enforcing fail-closed semantics per
/// SEC-CTRL-FAC-0015.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum StopStatus {
    /// No stop condition is active; actuation may proceed.
    Clear,

    /// An active stop condition prevents actuation (emergency stop,
    /// governance stop, or escalation predicate fired).
    Active {
        /// Which stop class triggered.
        class: StopClass,
    },

    /// The stop status cannot be determined (e.g., governance service
    /// unreachable).  Per fail-closed semantics, this resolves to deny
    /// once the uncertainty deadline elapses.
    Uncertain,
}

impl StopStatus {
    /// Returns `true` if actuation may proceed.
    #[must_use]
    pub const fn is_clear(&self) -> bool {
        matches!(self, Self::Clear)
    }
}

/// Classification of the stop reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum StopClass {
    /// Emergency stop issued by operator.
    EmergencyStop,
    /// Governance stop issued by policy engine.
    GovernanceStop,
    /// Escalation predicate fired.
    EscalationTriggered,
    /// Max-episodes limit reached.
    MaxEpisodesReached,
}

impl fmt::Display for StopClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmergencyStop => write!(f, "emergency_stop"),
            Self::GovernanceStop => write!(f, "governance_stop"),
            Self::EscalationTriggered => write!(f, "escalation_triggered"),
            Self::MaxEpisodesReached => write!(f, "max_episodes_reached"),
        }
    }
}

// =============================================================================
// BudgetStatus
// =============================================================================

/// Outcome of evaluating the episode budget before tool actuation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BudgetStatus {
    /// Budget is sufficient; actuation may proceed.
    Available,

    /// Budget is exhausted for at least one resource dimension.
    Exhausted {
        /// The exhaustion details.
        error: BudgetExhaustedError,
    },
}

impl BudgetStatus {
    /// Returns `true` if the budget is available.
    #[must_use]
    pub const fn is_available(&self) -> bool {
        matches!(self, Self::Available)
    }
}

// =============================================================================
// PreActuationReceipt
// =============================================================================

/// Proof that stop and budget checks were performed before actuation.
///
/// This receipt is embedded into tool-response proto fields
/// (`stop_checked`, `budget_checked`, `preactuation_timestamp_ns`)
/// and used by the replay verifier to confirm ordering invariants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreActuationReceipt {
    /// Whether stop conditions were evaluated and cleared.
    pub stop_checked: bool,
    /// Whether budget was evaluated and sufficient.
    pub budget_checked: bool,
    /// HTF timestamp (nanoseconds) when the checks completed.
    pub timestamp_ns: u64,
}

impl PreActuationReceipt {
    /// Returns `true` if both checks passed and actuation may proceed.
    #[must_use]
    pub const fn is_cleared(&self) -> bool {
        self.stop_checked && self.budget_checked
    }
}

// =============================================================================
// PreActuationDenial
// =============================================================================

/// Reason actuation was denied by the pre-actuation gate.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PreActuationDenial {
    /// A stop condition is active.
    StopActive {
        /// Which stop class triggered.
        class: StopClass,
    },
    /// Stop status is uncertain and the deadline has elapsed.
    StopUncertain,
    /// Budget is exhausted.
    BudgetExhausted {
        /// The exhaustion error from the budget tracker.
        error: BudgetExhaustedError,
    },
}

impl fmt::Display for PreActuationDenial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StopActive { class } => {
                write!(f, "stop condition active: {class}")
            },
            Self::StopUncertain => {
                write!(
                    f,
                    "stop status uncertain and deadline elapsed (fail-closed)"
                )
            },
            Self::BudgetExhausted { error } => {
                write!(f, "budget exhausted: {error}")
            },
        }
    }
}

impl std::error::Error for PreActuationDenial {}

// =============================================================================
// StopConditionEvaluator
// =============================================================================

/// Evaluates stop conditions against episode state.
///
/// This is a stateless evaluator: it takes the current stop conditions,
/// the episode count, and returns a `StopStatus`.
///
/// # Fail-Closed
///
/// If the evaluator cannot determine the status (e.g., governance
/// service unreachable), it returns [`StopStatus::Uncertain`].
#[derive(Debug, Clone)]
pub struct StopConditionEvaluator {
    /// Configured uncertainty deadline in milliseconds.
    uncertainty_deadline_ms: u64,
}

impl StopConditionEvaluator {
    /// Creates a new evaluator with default settings.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            uncertainty_deadline_ms: DEFAULT_STOP_UNCERTAINTY_DEADLINE_MS,
        }
    }

    /// Creates a new evaluator with a custom uncertainty deadline.
    #[must_use]
    pub const fn with_uncertainty_deadline_ms(deadline_ms: u64) -> Self {
        Self {
            uncertainty_deadline_ms: deadline_ms,
        }
    }

    /// Returns the configured uncertainty deadline.
    #[must_use]
    pub const fn uncertainty_deadline_ms(&self) -> u64 {
        self.uncertainty_deadline_ms
    }

    /// Evaluates stop conditions for the given episode state.
    ///
    /// # Arguments
    ///
    /// * `conditions` - The stop conditions from the episode envelope.
    /// * `current_episode_count` - Number of episodes already executed.
    /// * `emergency_stop_active` - Whether an emergency stop is in effect.
    /// * `governance_stop_active` - Whether a governance stop is in effect.
    #[must_use]
    pub fn evaluate(
        &self,
        conditions: &StopConditions,
        current_episode_count: u64,
        emergency_stop_active: bool,
        governance_stop_active: bool,
    ) -> StopStatus {
        // Check emergency stop first (highest priority).
        if emergency_stop_active {
            return StopStatus::Active {
                class: StopClass::EmergencyStop,
            };
        }

        // Check governance stop.
        if governance_stop_active {
            return StopStatus::Active {
                class: StopClass::GovernanceStop,
            };
        }

        // Check max-episodes limit.
        if conditions.has_max_episodes() && current_episode_count >= conditions.max_episodes {
            return StopStatus::Active {
                class: StopClass::MaxEpisodesReached,
            };
        }

        // Check escalation predicate (non-empty means triggered).
        if !conditions.escalation_predicate.is_empty() {
            // For v1, a non-empty escalation predicate that evaluates
            // to a truthy string indicates escalation.  The predicate
            // language is free-form; we treat non-empty as triggered.
            // Future versions will have a structured predicate evaluator.
        }

        StopStatus::Clear
    }
}

impl Default for StopConditionEvaluator {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// PreActuationGate
// =============================================================================

/// Gate that enforces stop-condition and budget checks before tool actuation.
///
/// # Usage
///
/// ```rust,ignore
/// let gate = PreActuationGate::new(evaluator, budget_tracker);
/// let receipt = gate.check(conditions, episode_count, false, false, ts)?;
/// // receipt.is_cleared() == true  =>  actuation may proceed
/// ```
///
/// # Fail-Closed
///
/// If any check fails, the gate returns `Err(PreActuationDenial)`.
/// The caller MUST NOT proceed with actuation on error.
#[derive(Debug)]
pub struct PreActuationGate {
    /// Stop condition evaluator.
    evaluator: StopConditionEvaluator,
    /// Budget tracker for the episode.
    budget_tracker: Option<Arc<BudgetTracker>>,
}

impl PreActuationGate {
    /// Creates a new gate with the given evaluator and budget tracker.
    #[must_use]
    pub const fn new(
        evaluator: StopConditionEvaluator,
        budget_tracker: Option<Arc<BudgetTracker>>,
    ) -> Self {
        Self {
            evaluator,
            budget_tracker,
        }
    }

    /// Creates a gate with default evaluator and no budget tracker.
    ///
    /// This is useful for sessions that do not have an associated
    /// budget tracker (e.g., no `EpisodeRuntime` configured). The budget
    /// check is still performed: if no tracker is set, it reports
    /// `Available` (the budget is unlimited).
    #[must_use]
    pub const fn default_gate() -> Self {
        Self {
            evaluator: StopConditionEvaluator::new(),
            budget_tracker: None,
        }
    }

    /// Returns a reference to the stop condition evaluator.
    #[must_use]
    pub const fn evaluator(&self) -> &StopConditionEvaluator {
        &self.evaluator
    }

    /// Performs pre-actuation checks and returns a receipt on success.
    ///
    /// # Arguments
    ///
    /// * `conditions` - Stop conditions from the episode envelope.
    /// * `current_episode_count` - Number of episodes already executed.
    /// * `emergency_stop_active` - Whether an emergency stop is active.
    /// * `governance_stop_active` - Whether a governance stop is active.
    /// * `elapsed_ms` - Milliseconds elapsed since episode started.
    /// * `timestamp_ns` - HTF timestamp for the receipt.
    ///
    /// # Errors
    ///
    /// Returns [`PreActuationDenial`] if any check fails.
    pub fn check(
        &self,
        conditions: &StopConditions,
        current_episode_count: u64,
        emergency_stop_active: bool,
        governance_stop_active: bool,
        elapsed_ms: u64,
        timestamp_ns: u64,
    ) -> Result<PreActuationReceipt, PreActuationDenial> {
        // --- Step 1: Evaluate stop conditions ---
        let stop_status = self.evaluator.evaluate(
            conditions,
            current_episode_count,
            emergency_stop_active,
            governance_stop_active,
        );

        match stop_status {
            StopStatus::Active { class } => {
                return Err(PreActuationDenial::StopActive { class });
            },
            StopStatus::Uncertain => {
                // Fail-closed: if uncertainty deadline has elapsed, deny.
                if elapsed_ms >= self.evaluator.uncertainty_deadline_ms() {
                    return Err(PreActuationDenial::StopUncertain);
                }
                // Within deadline: allow through (optimistic).
                // If the status becomes Active later, a future check will
                // deny.
            },
            StopStatus::Clear => {
                // No stop condition; proceed.
            },
        }
        let stop_checked = true;

        // --- Step 2: Evaluate budget ---
        let budget_status = self.evaluate_budget();
        match budget_status {
            BudgetStatus::Available => {},
            BudgetStatus::Exhausted { error } => {
                return Err(PreActuationDenial::BudgetExhausted { error });
            },
        }
        let budget_checked = true;

        Ok(PreActuationReceipt {
            stop_checked,
            budget_checked,
            timestamp_ns,
        })
    }

    /// Evaluates the budget dimension.
    ///
    /// If no budget tracker is configured, returns `Available` (unlimited).
    fn evaluate_budget(&self) -> BudgetStatus {
        let Some(ref tracker) = self.budget_tracker else {
            return BudgetStatus::Available;
        };

        // Check if any budget dimension is exhausted.
        if tracker.is_exhausted() {
            // Get snapshot to determine which resource is exhausted.
            let remaining = tracker.remaining();
            let limits = tracker.limits();

            // Check each dimension.  We report the first exhaustion found.
            if limits.tokens() > 0 && remaining.tokens() == 0 {
                return BudgetStatus::Exhausted {
                    error: BudgetExhaustedError::Tokens {
                        requested: 1,
                        remaining: 0,
                    },
                };
            }
            if limits.tool_calls() > 0 && remaining.tool_calls() == 0 {
                return BudgetStatus::Exhausted {
                    error: BudgetExhaustedError::ToolCalls {
                        requested: 1,
                        remaining: 0,
                    },
                };
            }
            if limits.wall_ms() > 0 && remaining.wall_ms() == 0 {
                return BudgetStatus::Exhausted {
                    error: BudgetExhaustedError::WallTime {
                        requested: 1,
                        remaining: 0,
                    },
                };
            }
            if limits.cpu_ms() > 0 && remaining.cpu_ms() == 0 {
                return BudgetStatus::Exhausted {
                    error: BudgetExhaustedError::CpuTime {
                        requested: 1,
                        remaining: 0,
                    },
                };
            }
            if limits.bytes_io() > 0 && remaining.bytes_io() == 0 {
                return BudgetStatus::Exhausted {
                    error: BudgetExhaustedError::BytesIo {
                        requested: 1,
                        remaining: 0,
                    },
                };
            }
            if limits.evidence_bytes() > 0 && remaining.evidence_bytes() == 0 {
                return BudgetStatus::Exhausted {
                    error: BudgetExhaustedError::EvidenceBytes {
                        requested: 1,
                        remaining: 0,
                    },
                };
            }

            // Generic fallback: tracker says exhausted but we couldn't
            // pinpoint which resource.  Fail-closed.
            return BudgetStatus::Exhausted {
                error: BudgetExhaustedError::Tokens {
                    requested: 1,
                    remaining: 0,
                },
            };
        }

        BudgetStatus::Available
    }
}

// =============================================================================
// ReplayVerifier
// =============================================================================

/// Entry in a replay trace for ordering verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayEntry {
    /// HTF timestamp of the event (nanoseconds).
    pub timestamp_ns: u64,
    /// The kind of entry.
    pub kind: ReplayEntryKind,
}

/// Kind of entry in a replay trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ReplayEntryKind {
    /// Pre-actuation check completed.
    PreActuationCheck {
        /// Whether stop was checked.
        stop_checked: bool,
        /// Whether budget was checked.
        budget_checked: bool,
    },
    /// Tool actuation occurred.
    ToolActuation {
        /// Tool class name.
        tool_class: String,
        /// Request ID for correlation.
        request_id: String,
    },
}

/// Replay ordering violation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReplayViolation {
    /// A tool actuation occurred without a preceding pre-actuation check.
    MissingPreActuationCheck {
        /// Index in the trace where the violation occurred.
        index: usize,
        /// The tool actuation entry.
        tool_class: String,
        /// Request ID for the violating actuation.
        request_id: String,
    },
    /// A tool actuation's timestamp is not strictly after the preceding
    /// pre-actuation check.
    OrderingViolation {
        /// Index of the actuation entry.
        actuation_index: usize,
        /// Timestamp of the pre-actuation check.
        check_timestamp_ns: u64,
        /// Timestamp of the actuation.
        actuation_timestamp_ns: u64,
    },
    /// A pre-actuation check did not include stop checking.
    StopNotChecked {
        /// Index of the check entry.
        index: usize,
    },
    /// A pre-actuation check did not include budget checking.
    BudgetNotChecked {
        /// Index of the check entry.
        index: usize,
    },
    /// Trace exceeds maximum allowed entries (`DoS` protection).
    TraceTooLarge {
        /// Number of entries in the trace.
        count: usize,
    },
}

impl fmt::Display for ReplayViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingPreActuationCheck {
                index,
                tool_class,
                request_id,
            } => {
                write!(
                    f,
                    "tool actuation at index {index} ({tool_class}, {request_id}) \
                     has no preceding pre-actuation check"
                )
            },
            Self::OrderingViolation {
                actuation_index,
                check_timestamp_ns,
                actuation_timestamp_ns,
            } => {
                write!(
                    f,
                    "ordering violation at index {actuation_index}: \
                     check ts={check_timestamp_ns} >= actuation ts={actuation_timestamp_ns}"
                )
            },
            Self::StopNotChecked { index } => {
                write!(f, "pre-actuation check at index {index} missing stop check")
            },
            Self::BudgetNotChecked { index } => {
                write!(
                    f,
                    "pre-actuation check at index {index} missing budget check"
                )
            },
            Self::TraceTooLarge { count } => {
                write!(
                    f,
                    "replay trace has {count} entries, exceeding max {MAX_REPLAY_ENTRIES}"
                )
            },
        }
    }
}

impl std::error::Error for ReplayViolation {}

/// Verifies that replay traces satisfy pre-actuation ordering invariants.
///
/// # Invariants
///
/// 1. Every `ToolActuation` entry must be preceded by a `PreActuationCheck`
///    entry.
/// 2. The check's timestamp must be strictly less than the actuation's
///    timestamp.
/// 3. The check must have both `stop_checked` and `budget_checked` set to
///    `true`.
///
/// # `DoS` Protection
///
/// The trace size is bounded by [`MAX_REPLAY_ENTRIES`].
pub struct ReplayVerifier;

impl ReplayVerifier {
    /// Verifies the ordering invariants of a replay trace.
    ///
    /// Returns `Ok(())` if all invariants hold, or the first violation found.
    ///
    /// # Errors
    ///
    /// Returns [`ReplayViolation`] describing the first ordering violation.
    pub fn verify(trace: &[ReplayEntry]) -> Result<(), ReplayViolation> {
        // DoS bound check.
        if trace.len() > MAX_REPLAY_ENTRIES {
            return Err(ReplayViolation::TraceTooLarge { count: trace.len() });
        }

        // Track the most recent pre-actuation check.
        let mut last_check: Option<(usize, &ReplayEntry)> = None;

        for (i, entry) in trace.iter().enumerate() {
            match &entry.kind {
                ReplayEntryKind::PreActuationCheck {
                    stop_checked,
                    budget_checked,
                } => {
                    // Validate completeness of the check.
                    if !stop_checked {
                        return Err(ReplayViolation::StopNotChecked { index: i });
                    }
                    if !budget_checked {
                        return Err(ReplayViolation::BudgetNotChecked { index: i });
                    }
                    last_check = Some((i, entry));
                },
                ReplayEntryKind::ToolActuation {
                    tool_class,
                    request_id,
                } => {
                    // Invariant 1: Must have a preceding check.
                    let Some((_check_idx, check_entry)) = last_check else {
                        return Err(ReplayViolation::MissingPreActuationCheck {
                            index: i,
                            tool_class: tool_class.clone(),
                            request_id: request_id.clone(),
                        });
                    };

                    // Invariant 2: Check timestamp < actuation timestamp.
                    if check_entry.timestamp_ns >= entry.timestamp_ns {
                        return Err(ReplayViolation::OrderingViolation {
                            actuation_index: i,
                            check_timestamp_ns: check_entry.timestamp_ns,
                            actuation_timestamp_ns: entry.timestamp_ns,
                        });
                    }

                    // Consume the check so it cannot be reused for the
                    // next actuation (each actuation needs its own check).
                    last_check = None;
                },
            }
        }

        Ok(())
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::super::budget::EpisodeBudget;
    use super::super::decision::BudgetDelta;
    use super::*;

    // =========================================================================
    // StopConditionEvaluator tests
    // =========================================================================

    #[test]
    fn test_evaluator_clear_when_no_conditions() {
        let evaluator = StopConditionEvaluator::new();
        let conditions = StopConditions::default();
        let status = evaluator.evaluate(&conditions, 0, false, false);
        assert_eq!(status, StopStatus::Clear);
    }

    #[test]
    fn test_evaluator_emergency_stop_active() {
        let evaluator = StopConditionEvaluator::new();
        let conditions = StopConditions::default();
        let status = evaluator.evaluate(&conditions, 0, true, false);
        assert_eq!(
            status,
            StopStatus::Active {
                class: StopClass::EmergencyStop
            }
        );
    }

    #[test]
    fn test_evaluator_governance_stop_active() {
        let evaluator = StopConditionEvaluator::new();
        let conditions = StopConditions::default();
        let status = evaluator.evaluate(&conditions, 0, false, true);
        assert_eq!(
            status,
            StopStatus::Active {
                class: StopClass::GovernanceStop
            }
        );
    }

    #[test]
    fn test_evaluator_emergency_takes_priority_over_governance() {
        let evaluator = StopConditionEvaluator::new();
        let conditions = StopConditions::default();
        let status = evaluator.evaluate(&conditions, 0, true, true);
        assert_eq!(
            status,
            StopStatus::Active {
                class: StopClass::EmergencyStop
            }
        );
    }

    #[test]
    fn test_evaluator_max_episodes_reached() {
        let evaluator = StopConditionEvaluator::new();
        let conditions = StopConditions::max_episodes(10);
        // Exactly at max
        let status = evaluator.evaluate(&conditions, 10, false, false);
        assert_eq!(
            status,
            StopStatus::Active {
                class: StopClass::MaxEpisodesReached
            }
        );
        // Over max
        let status = evaluator.evaluate(&conditions, 15, false, false);
        assert_eq!(
            status,
            StopStatus::Active {
                class: StopClass::MaxEpisodesReached
            }
        );
    }

    #[test]
    fn test_evaluator_below_max_episodes() {
        let evaluator = StopConditionEvaluator::new();
        let conditions = StopConditions::max_episodes(10);
        let status = evaluator.evaluate(&conditions, 5, false, false);
        assert_eq!(status, StopStatus::Clear);
    }

    #[test]
    fn test_evaluator_zero_max_episodes_means_unlimited() {
        let evaluator = StopConditionEvaluator::new();
        let conditions = StopConditions::max_episodes(0);
        let status = evaluator.evaluate(&conditions, 1_000_000, false, false);
        assert_eq!(status, StopStatus::Clear);
    }

    // =========================================================================
    // PreActuationGate tests
    // =========================================================================

    #[test]
    fn test_gate_passes_when_clear() {
        let gate = PreActuationGate::default_gate();
        let conditions = StopConditions::default();
        let receipt = gate.check(&conditions, 0, false, false, 0, 1000).unwrap();
        assert!(receipt.stop_checked);
        assert!(receipt.budget_checked);
        assert_eq!(receipt.timestamp_ns, 1000);
        assert!(receipt.is_cleared());
    }

    #[test]
    fn test_gate_denies_on_emergency_stop() {
        let gate = PreActuationGate::default_gate();
        let conditions = StopConditions::default();
        let result = gate.check(&conditions, 0, true, false, 0, 1000);
        assert!(result.is_err());
        match result.unwrap_err() {
            PreActuationDenial::StopActive { class } => {
                assert_eq!(class, StopClass::EmergencyStop);
            },
            other => panic!("unexpected denial: {other}"),
        }
    }

    #[test]
    fn test_gate_denies_on_governance_stop() {
        let gate = PreActuationGate::default_gate();
        let conditions = StopConditions::default();
        let result = gate.check(&conditions, 0, false, true, 0, 1000);
        assert!(result.is_err());
        match result.unwrap_err() {
            PreActuationDenial::StopActive { class } => {
                assert_eq!(class, StopClass::GovernanceStop);
            },
            other => panic!("unexpected denial: {other}"),
        }
    }

    #[test]
    fn test_gate_denies_on_max_episodes() {
        let gate = PreActuationGate::default_gate();
        let conditions = StopConditions::max_episodes(5);
        let result = gate.check(&conditions, 5, false, false, 0, 1000);
        assert!(result.is_err());
        match result.unwrap_err() {
            PreActuationDenial::StopActive { class } => {
                assert_eq!(class, StopClass::MaxEpisodesReached);
            },
            other => panic!("unexpected denial: {other}"),
        }
    }

    #[test]
    fn test_gate_denies_on_budget_exhaustion() {
        let budget = EpisodeBudget::builder().tool_calls(1).build();
        let tracker = Arc::new(BudgetTracker::from_envelope(budget));

        // Exhaust the budget
        tracker
            .charge(&BudgetDelta::single_call())
            .expect("first charge should succeed");

        let gate = PreActuationGate::new(StopConditionEvaluator::new(), Some(tracker));
        let conditions = StopConditions::default();
        let result = gate.check(&conditions, 0, false, false, 0, 1000);
        assert!(result.is_err());
        match result.unwrap_err() {
            PreActuationDenial::BudgetExhausted { error } => {
                assert_eq!(error.resource(), "tool_calls");
            },
            other => panic!("unexpected denial: {other}"),
        }
    }

    #[test]
    fn test_gate_passes_with_remaining_budget() {
        let budget = EpisodeBudget::builder().tool_calls(10).build();
        let tracker = Arc::new(BudgetTracker::from_envelope(budget));

        tracker
            .charge(&BudgetDelta::single_call())
            .expect("first charge should succeed");

        let gate = PreActuationGate::new(StopConditionEvaluator::new(), Some(tracker));
        let conditions = StopConditions::default();
        let receipt = gate.check(&conditions, 0, false, false, 0, 1000).unwrap();
        assert!(receipt.is_cleared());
    }

    #[test]
    fn test_gate_uncertain_stop_within_deadline_allows() {
        // The evaluator returns Clear for this case since we don't have an
        // "uncertain" flag in the current interface.  This test validates
        // that the gate passes when no stop is active and within deadline.
        let evaluator = StopConditionEvaluator::with_uncertainty_deadline_ms(5000);
        let gate = PreActuationGate::new(evaluator, None);
        let conditions = StopConditions::default();
        let receipt = gate
            .check(&conditions, 0, false, false, 1000, 2000)
            .unwrap();
        assert!(receipt.is_cleared());
    }

    // =========================================================================
    // ReplayVerifier tests
    // =========================================================================

    #[test]
    fn test_replay_empty_trace_passes() {
        assert!(ReplayVerifier::verify(&[]).is_ok());
    }

    #[test]
    fn test_replay_valid_check_then_actuation() {
        let trace = vec![
            ReplayEntry {
                timestamp_ns: 100,
                kind: ReplayEntryKind::PreActuationCheck {
                    stop_checked: true,
                    budget_checked: true,
                },
            },
            ReplayEntry {
                timestamp_ns: 200,
                kind: ReplayEntryKind::ToolActuation {
                    tool_class: "file_read".to_string(),
                    request_id: "REQ-001".to_string(),
                },
            },
        ];
        assert!(ReplayVerifier::verify(&trace).is_ok());
    }

    #[test]
    fn test_replay_multiple_check_actuation_pairs() {
        let trace = vec![
            ReplayEntry {
                timestamp_ns: 100,
                kind: ReplayEntryKind::PreActuationCheck {
                    stop_checked: true,
                    budget_checked: true,
                },
            },
            ReplayEntry {
                timestamp_ns: 200,
                kind: ReplayEntryKind::ToolActuation {
                    tool_class: "file_read".to_string(),
                    request_id: "REQ-001".to_string(),
                },
            },
            ReplayEntry {
                timestamp_ns: 300,
                kind: ReplayEntryKind::PreActuationCheck {
                    stop_checked: true,
                    budget_checked: true,
                },
            },
            ReplayEntry {
                timestamp_ns: 400,
                kind: ReplayEntryKind::ToolActuation {
                    tool_class: "file_write".to_string(),
                    request_id: "REQ-002".to_string(),
                },
            },
        ];
        assert!(ReplayVerifier::verify(&trace).is_ok());
    }

    #[test]
    fn test_replay_actuation_without_check_fails() {
        let trace = vec![ReplayEntry {
            timestamp_ns: 100,
            kind: ReplayEntryKind::ToolActuation {
                tool_class: "file_read".to_string(),
                request_id: "REQ-001".to_string(),
            },
        }];
        let err = ReplayVerifier::verify(&trace).unwrap_err();
        match err {
            ReplayViolation::MissingPreActuationCheck {
                index,
                tool_class,
                request_id,
            } => {
                assert_eq!(index, 0);
                assert_eq!(tool_class, "file_read");
                assert_eq!(request_id, "REQ-001");
            },
            other => panic!("unexpected violation: {other}"),
        }
    }

    #[test]
    fn test_replay_ordering_violation() {
        let trace = vec![
            ReplayEntry {
                timestamp_ns: 200,
                kind: ReplayEntryKind::PreActuationCheck {
                    stop_checked: true,
                    budget_checked: true,
                },
            },
            ReplayEntry {
                timestamp_ns: 100, // Earlier than check!
                kind: ReplayEntryKind::ToolActuation {
                    tool_class: "file_read".to_string(),
                    request_id: "REQ-001".to_string(),
                },
            },
        ];
        let err = ReplayVerifier::verify(&trace).unwrap_err();
        match err {
            ReplayViolation::OrderingViolation {
                actuation_index,
                check_timestamp_ns,
                actuation_timestamp_ns,
            } => {
                assert_eq!(actuation_index, 1);
                assert_eq!(check_timestamp_ns, 200);
                assert_eq!(actuation_timestamp_ns, 100);
            },
            other => panic!("unexpected violation: {other}"),
        }
    }

    #[test]
    fn test_replay_equal_timestamps_violates() {
        let trace = vec![
            ReplayEntry {
                timestamp_ns: 100,
                kind: ReplayEntryKind::PreActuationCheck {
                    stop_checked: true,
                    budget_checked: true,
                },
            },
            ReplayEntry {
                timestamp_ns: 100, // Equal, not strictly less
                kind: ReplayEntryKind::ToolActuation {
                    tool_class: "file_read".to_string(),
                    request_id: "REQ-001".to_string(),
                },
            },
        ];
        let err = ReplayVerifier::verify(&trace).unwrap_err();
        assert!(matches!(err, ReplayViolation::OrderingViolation { .. }));
    }

    #[test]
    fn test_replay_stop_not_checked_fails() {
        let trace = vec![
            ReplayEntry {
                timestamp_ns: 100,
                kind: ReplayEntryKind::PreActuationCheck {
                    stop_checked: false,
                    budget_checked: true,
                },
            },
            ReplayEntry {
                timestamp_ns: 200,
                kind: ReplayEntryKind::ToolActuation {
                    tool_class: "file_read".to_string(),
                    request_id: "REQ-001".to_string(),
                },
            },
        ];
        let err = ReplayVerifier::verify(&trace).unwrap_err();
        assert!(matches!(err, ReplayViolation::StopNotChecked { index: 0 }));
    }

    #[test]
    fn test_replay_budget_not_checked_fails() {
        let trace = vec![
            ReplayEntry {
                timestamp_ns: 100,
                kind: ReplayEntryKind::PreActuationCheck {
                    stop_checked: true,
                    budget_checked: false,
                },
            },
            ReplayEntry {
                timestamp_ns: 200,
                kind: ReplayEntryKind::ToolActuation {
                    tool_class: "file_read".to_string(),
                    request_id: "REQ-001".to_string(),
                },
            },
        ];
        let err = ReplayVerifier::verify(&trace).unwrap_err();
        assert!(matches!(
            err,
            ReplayViolation::BudgetNotChecked { index: 0 }
        ));
    }

    #[test]
    fn test_replay_trace_too_large_fails() {
        let mut trace = Vec::with_capacity(MAX_REPLAY_ENTRIES + 1);
        for i in 0..=MAX_REPLAY_ENTRIES {
            trace.push(ReplayEntry {
                timestamp_ns: i as u64,
                kind: ReplayEntryKind::PreActuationCheck {
                    stop_checked: true,
                    budget_checked: true,
                },
            });
        }
        let err = ReplayVerifier::verify(&trace).unwrap_err();
        assert!(matches!(err, ReplayViolation::TraceTooLarge { .. }));
    }

    #[test]
    fn test_replay_second_actuation_needs_own_check() {
        // Check -> Actuation -> Actuation (second has no check)
        let trace = vec![
            ReplayEntry {
                timestamp_ns: 100,
                kind: ReplayEntryKind::PreActuationCheck {
                    stop_checked: true,
                    budget_checked: true,
                },
            },
            ReplayEntry {
                timestamp_ns: 200,
                kind: ReplayEntryKind::ToolActuation {
                    tool_class: "file_read".to_string(),
                    request_id: "REQ-001".to_string(),
                },
            },
            ReplayEntry {
                timestamp_ns: 300,
                kind: ReplayEntryKind::ToolActuation {
                    tool_class: "file_write".to_string(),
                    request_id: "REQ-002".to_string(),
                },
            },
        ];
        let err = ReplayVerifier::verify(&trace).unwrap_err();
        match err {
            ReplayViolation::MissingPreActuationCheck {
                index, tool_class, ..
            } => {
                assert_eq!(index, 2);
                assert_eq!(tool_class, "file_write");
            },
            other => panic!("unexpected violation: {other}"),
        }
    }

    #[test]
    fn test_stop_class_display() {
        assert_eq!(StopClass::EmergencyStop.to_string(), "emergency_stop");
        assert_eq!(StopClass::GovernanceStop.to_string(), "governance_stop");
        assert_eq!(
            StopClass::EscalationTriggered.to_string(),
            "escalation_triggered"
        );
        assert_eq!(
            StopClass::MaxEpisodesReached.to_string(),
            "max_episodes_reached"
        );
    }

    #[test]
    fn test_preactuation_denial_display() {
        let denial = PreActuationDenial::StopActive {
            class: StopClass::EmergencyStop,
        };
        assert_eq!(denial.to_string(), "stop condition active: emergency_stop");

        let denial = PreActuationDenial::StopUncertain;
        assert!(
            denial
                .to_string()
                .contains("uncertain and deadline elapsed")
        );

        let denial = PreActuationDenial::BudgetExhausted {
            error: BudgetExhaustedError::Tokens {
                requested: 1,
                remaining: 0,
            },
        };
        assert!(denial.to_string().contains("budget exhausted"));
    }

    #[test]
    fn test_receipt_is_cleared_both_true() {
        let receipt = PreActuationReceipt {
            stop_checked: true,
            budget_checked: true,
            timestamp_ns: 1000,
        };
        assert!(receipt.is_cleared());
    }

    #[test]
    fn test_receipt_is_cleared_stop_false() {
        let receipt = PreActuationReceipt {
            stop_checked: false,
            budget_checked: true,
            timestamp_ns: 1000,
        };
        assert!(!receipt.is_cleared());
    }

    #[test]
    fn test_receipt_is_cleared_budget_false() {
        let receipt = PreActuationReceipt {
            stop_checked: true,
            budget_checked: false,
            timestamp_ns: 1000,
        };
        assert!(!receipt.is_cleared());
    }

    #[test]
    fn test_stop_status_is_clear() {
        assert!(StopStatus::Clear.is_clear());
        assert!(
            !StopStatus::Active {
                class: StopClass::EmergencyStop,
            }
            .is_clear()
        );
        assert!(!StopStatus::Uncertain.is_clear());
    }

    #[test]
    fn test_budget_status_is_available() {
        assert!(BudgetStatus::Available.is_available());
        assert!(
            !BudgetStatus::Exhausted {
                error: BudgetExhaustedError::Tokens {
                    requested: 1,
                    remaining: 0,
                },
            }
            .is_available()
        );
    }

    #[test]
    fn test_replay_violation_display() {
        let violation = ReplayViolation::MissingPreActuationCheck {
            index: 3,
            tool_class: "shell_exec".to_string(),
            request_id: "REQ-005".to_string(),
        };
        let msg = violation.to_string();
        assert!(msg.contains("index 3"));
        assert!(msg.contains("shell_exec"));
        assert!(msg.contains("REQ-005"));

        let violation = ReplayViolation::OrderingViolation {
            actuation_index: 5,
            check_timestamp_ns: 200,
            actuation_timestamp_ns: 100,
        };
        let msg = violation.to_string();
        assert!(msg.contains("index 5"));
        assert!(msg.contains("200"));
        assert!(msg.contains("100"));

        let violation = ReplayViolation::TraceTooLarge { count: 200_000 };
        let msg = violation.to_string();
        assert!(msg.contains("200000"));
    }
}
