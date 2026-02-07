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
//! - If the gate is not invoked at all: `stop_checked` remains `false`, which
//!   the replay harness treats as a violation.
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
use std::sync::atomic::{AtomicBool, Ordering};

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
// StopAuthority
// =============================================================================

/// Thread-safe authoritative stop state for the daemon runtime.
///
/// This struct holds the runtime stop flags that are set by the operator
/// (emergency stop) or policy engine (governance stop).  The
/// [`PreActuationGate`] reads these flags on every tool request to determine
/// whether actuation should be blocked.
///
/// # TCK-00351 BLOCKER 1 FIX
///
/// Prior to this fix, the session dispatcher passed hardcoded `false` for
/// both `emergency_stop_active` and `governance_stop_active`, meaning real
/// stop conditions from operators/governance could never block tool requests
/// at the gate level.  `StopAuthority` provides the authoritative source of
/// truth for these flags.
///
/// # Thread Safety
///
/// All flags use `AtomicBool` for lock-free reads from the dispatch hot path.
/// Writes are expected to be rare (operator action or policy engine trigger).
#[derive(Debug)]
pub struct StopAuthority {
    /// Whether an emergency stop has been issued by an operator.
    emergency_stop: AtomicBool,
    /// Whether a governance stop has been issued by the policy engine.
    governance_stop: AtomicBool,
    /// Whether the governance stop state is uncertain (service unreachable
    /// or response stale beyond freshness threshold).
    ///
    /// TCK-00351 MAJOR 1 v2 FIX: When this flag is set, the
    /// [`StopConditionEvaluator::evaluate_with_uncertainty`] returns
    /// [`StopStatus::Uncertain`], which triggers deadline-based fail-closed
    /// denial.
    ///
    /// # Production Wiring (TCK-00364)
    ///
    /// Currently this flag is only set in tests.  The production call path
    /// will be wired in TCK-00364 (`FreshnessPolicyV1`), where the
    /// governance freshness monitor periodically checks the governance
    /// service health and calls [`StopAuthority::set_governance_uncertain`]
    /// when the response is stale beyond the configured threshold.  The
    /// control surface exists and is fully testable; only the monitoring
    /// integration remains.
    governance_uncertain: AtomicBool,
}

impl StopAuthority {
    /// Creates a new stop authority with no active stops.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            emergency_stop: AtomicBool::new(false),
            governance_stop: AtomicBool::new(false),
            governance_uncertain: AtomicBool::new(false),
        }
    }

    /// Returns whether an emergency stop is active.
    #[must_use]
    pub fn emergency_stop_active(&self) -> bool {
        self.emergency_stop.load(Ordering::Acquire)
    }

    /// Returns whether a governance stop is active.
    #[must_use]
    pub fn governance_stop_active(&self) -> bool {
        self.governance_stop.load(Ordering::Acquire)
    }

    /// Returns whether the governance stop state is uncertain.
    #[must_use]
    pub fn governance_uncertain(&self) -> bool {
        self.governance_uncertain.load(Ordering::Acquire)
    }

    /// Sets the emergency stop flag.
    pub fn set_emergency_stop(&self, active: bool) {
        self.emergency_stop.store(active, Ordering::Release);
    }

    /// Sets the governance stop flag.
    pub fn set_governance_stop(&self, active: bool) {
        self.governance_stop.store(active, Ordering::Release);
    }

    /// Sets the governance-uncertain flag.
    ///
    /// When `true`, the evaluator treats governance stop state as uncertain
    /// and the gate applies deadline-based fail-closed logic.
    pub fn set_governance_uncertain(&self, uncertain: bool) {
        self.governance_uncertain
            .store(uncertain, Ordering::Release);
    }
}

impl Default for StopAuthority {
    fn default() -> Self {
        Self::new()
    }
}

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
    /// Whether budget was enforced at pre-actuation.
    ///
    /// When budget enforcement is deferred to `EpisodeRuntime`, this is `false`
    /// even when the request is allowed.
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
        // TCK-00351 BLOCKER 1 FIX: Actually trigger EscalationTriggered
        // deny when the predicate is non-empty.  The previous implementation
        // checked the predicate but fell through to Clear, allowing actuation
        // to proceed even when escalation was triggered.
        if !conditions.escalation_predicate.is_empty() {
            return StopStatus::Active {
                class: StopClass::EscalationTriggered,
            };
        }

        StopStatus::Clear
    }

    /// Evaluates stop conditions with governance-uncertainty awareness.
    ///
    /// This is the extended variant of [`evaluate`](Self::evaluate) that
    /// accepts a `governance_uncertain` flag.  When the governance service
    /// is unreachable or its response is stale beyond the freshness
    /// threshold, the caller sets `governance_uncertain = true` and the
    /// evaluator returns [`StopStatus::Uncertain`], which the gate
    /// resolves via the deadline logic (deny if elapsed > deadline).
    ///
    /// # Arguments
    ///
    /// * `conditions`            - Stop conditions from the episode envelope.
    /// * `current_episode_count` - Number of episodes already executed.
    /// * `emergency_stop_active` - Whether an emergency stop is in effect.
    /// * `governance_stop_active`- Whether a governance stop is in effect.
    /// * `governance_uncertain`  - Whether the governance stop state is
    ///   uncertain (service unreachable / stale).
    #[must_use]
    pub fn evaluate_with_uncertainty(
        &self,
        conditions: &StopConditions,
        current_episode_count: u64,
        emergency_stop_active: bool,
        governance_stop_active: bool,
        governance_uncertain: bool,
    ) -> StopStatus {
        // Delegate to the base evaluator first -- it handles the
        // deterministic conditions (emergency, governance-active, max
        // episodes, escalation).
        let base = self.evaluate(
            conditions,
            current_episode_count,
            emergency_stop_active,
            governance_stop_active,
        );

        // If the base evaluation already returned a definitive status
        // (Active or Clear-but-governance-is-uncertain), handle accordingly.
        if !base.is_clear() {
            return base;
        }

        // If governance status is uncertain, return Uncertain so the gate
        // can apply the deadline-based fail-closed logic.
        if governance_uncertain {
            return StopStatus::Uncertain;
        }

        base
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
/// let authority = Arc::new(StopAuthority::new());
/// let gate = PreActuationGate::new(evaluator, Some(budget_tracker))
///     .with_stop_authority(authority);
/// let receipt = gate.check(conditions, episode_count, 0, ts)?;
/// // receipt.is_cleared() == true  =>  actuation may proceed
/// ```
///
/// # Fail-Closed
///
/// If any check fails, the gate returns `Err(PreActuationDenial)`.
/// The caller MUST NOT proceed with actuation on error.
///
/// # TCK-00351 BLOCKER 1 & 2 FIX
///
/// The gate now holds:
/// - [`StopAuthority`] for authoritative emergency/governance stop state
///   (BLOCKER 1: stop-state enforcement connected to runtime state).
/// - `require_budget`: when `true`, a missing budget tracker causes fail-closed
///   denial instead of pass-through (BLOCKER 2: budget validation no longer
///   defaults to available when tracker is absent).
#[derive(Debug)]
pub struct PreActuationGate {
    /// Stop condition evaluator.
    evaluator: StopConditionEvaluator,
    /// Budget tracker for the episode.
    budget_tracker: Option<Arc<BudgetTracker>>,
    /// Authoritative stop state from the daemon runtime.
    ///
    /// TCK-00351 BLOCKER 1: When set, the gate reads emergency and
    /// governance stop flags from this authority instead of accepting
    /// hardcoded `false` from the caller.
    stop_authority: Option<Arc<StopAuthority>>,
    /// Whether to require a budget tracker for authority-bearing actuation.
    ///
    /// TCK-00351 BLOCKER 2: When `true` and no budget tracker is
    /// configured, the gate denies with `BudgetExhausted` (fail-closed).
    /// When `false`, a missing tracker is treated as unlimited budget
    /// (useful for tests or non-budget-constrained sessions).
    require_budget: bool,
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
            stop_authority: None,
            require_budget: false,
        }
    }

    /// Creates a gate with default evaluator and no budget tracker.
    ///
    /// **WARNING**: This gate does NOT enforce budget checks (budget
    /// defaults to `Available`).  For production use, prefer
    /// [`production_gate`](Self::production_gate) which fails closed
    /// when the budget tracker is absent.
    #[must_use]
    pub const fn default_gate() -> Self {
        Self {
            evaluator: StopConditionEvaluator::new(),
            budget_tracker: None,
            stop_authority: None,
            require_budget: false,
        }
    }

    /// Creates a production gate with stop-authority wired and optional budget.
    ///
    /// # Budget Enforcement
    ///
    /// When `budget_tracker` is `Some`, the gate enforces budget limits and
    /// denies if exhausted (fail-closed).  When `budget_tracker` is `None`,
    /// the gate does NOT deny on missing budget -- session-level budget
    /// enforcement is deferred to `EpisodeRuntime` which tracks per-episode
    /// budgets.  This avoids a self-DoS where ALL tool requests are denied
    /// because the session-level gate has no tracker.
    ///
    /// To require a budget tracker at this level (e.g., when per-session
    /// budgets are implemented), call `.with_require_budget(true)` after
    /// construction.
    ///
    /// # Arguments
    ///
    /// * `stop_authority` - Authoritative runtime stop state.
    /// * `budget_tracker` - Budget tracker; `None` defers budget checks to
    ///   `EpisodeRuntime`.
    #[must_use]
    pub const fn production_gate(
        stop_authority: Arc<StopAuthority>,
        budget_tracker: Option<Arc<BudgetTracker>>,
    ) -> Self {
        // require_budget is false when no tracker is provided so the gate
        // does not self-DoS.  When a real tracker IS provided, we still
        // enforce it via the evaluate_budget path (tracker.is_exhausted()).
        Self {
            evaluator: StopConditionEvaluator::new(),
            budget_tracker,
            stop_authority: Some(stop_authority),
            require_budget: false,
        }
    }

    /// Sets the stop authority for authoritative stop state reads.
    ///
    /// TCK-00351 BLOCKER 1 FIX: Connects the gate to the runtime's
    /// stop state so emergency/governance stops actually block actuation.
    #[must_use]
    pub fn with_stop_authority(mut self, authority: Arc<StopAuthority>) -> Self {
        self.stop_authority = Some(authority);
        self
    }

    /// Sets the budget tracker for budget enforcement.
    #[must_use]
    pub fn with_budget_tracker(mut self, tracker: Arc<BudgetTracker>) -> Self {
        self.budget_tracker = Some(tracker);
        self
    }

    /// Enables fail-closed budget enforcement.
    ///
    /// When enabled, a missing budget tracker causes denial instead of
    /// pass-through.
    #[must_use]
    pub const fn with_require_budget(mut self, require: bool) -> Self {
        self.require_budget = require;
        self
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
    ///   **Ignored** when a [`StopAuthority`] is configured; the authority's
    ///   value takes precedence.
    /// * `governance_stop_active` - Whether a governance stop is active.
    ///   **Ignored** when a [`StopAuthority`] is configured; the authority's
    ///   value takes precedence.
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
        // TCK-00351 BLOCKER 1 FIX: Read from authoritative stop state
        // when available, instead of trusting caller-supplied values.
        let (emer_stop, gov_stop, gov_uncertain) = self.stop_authority.as_ref().map_or(
            (emergency_stop_active, governance_stop_active, false),
            |authority| {
                (
                    authority.emergency_stop_active(),
                    authority.governance_stop_active(),
                    authority.governance_uncertain(),
                )
            },
        );

        // --- Step 1: Evaluate stop conditions ---
        // TCK-00351 MAJOR 1 v2 FIX: Use evaluate_with_uncertainty so
        // the Uncertain path is reachable when governance is uncertain.
        let stop_status = self.evaluator.evaluate_with_uncertainty(
            conditions,
            current_episode_count,
            emer_stop,
            gov_stop,
            gov_uncertain,
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
        // Track whether budget was actually enforced at pre-actuation.
        // A deferred tracker performs availability plumbing but defers
        // enforcement to EpisodeRuntime, so receipts must report
        // budget_checked=false to avoid proof-semantics drift.
        let has_real_tracker = self
            .budget_tracker
            .as_ref()
            .is_some_and(|tracker| !tracker.is_deferred());
        let budget_status = self.evaluate_budget();
        match budget_status {
            BudgetStatus::Available => {},
            BudgetStatus::Exhausted { error } => {
                return Err(PreActuationDenial::BudgetExhausted { error });
            },
        }
        let budget_checked = has_real_tracker;

        Ok(PreActuationReceipt {
            stop_checked,
            budget_checked,
            timestamp_ns,
        })
    }

    /// Evaluates the budget dimension.
    ///
    /// TCK-00351 BLOCKER 2 FIX: When `require_budget` is `true` and no
    /// budget tracker is configured, returns `Exhausted` (fail-closed).
    /// When `require_budget` is `false` (legacy/test mode), returns
    /// `Available` for missing trackers (unlimited budget).
    fn evaluate_budget(&self) -> BudgetStatus {
        let Some(ref tracker) = self.budget_tracker else {
            // TCK-00351 BLOCKER 2: Fail-closed when budget is required
            // but no tracker is available.
            if self.require_budget {
                return BudgetStatus::Exhausted {
                    error: BudgetExhaustedError::Tokens {
                        requested: 1,
                        remaining: 0,
                    },
                };
            }
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
/// # Evidence Binding
///
/// This verifier is bound to **EVID-0305**: Pre-actuation ordering proof.
/// It is invoked during evidence validation to confirm that every tool
/// actuation in a replayed trace was preceded by a valid pre-actuation
/// receipt.
///
/// # Invariants
///
/// 1. Every `ToolActuation` entry must be preceded by a `PreActuationCheck`
///    entry.
/// 2. The check's timestamp must be strictly less than the actuation's
///    timestamp.
/// 3. The check must have `stop_checked=true`. `budget_checked` may be `false`
///    when budget enforcement is deferred to `EpisodeRuntime`.
///
/// # `DoS` Protection
///
/// The trace size is bounded by [`MAX_REPLAY_ENTRIES`].
///
/// # Production Integration Status
///
/// TODO(TCK-00356): Integrate `ReplayVerifier::verify` into the production
/// replay/evidence validation pipeline.  Currently the verifier is only
/// exercised in unit and integration tests (this module's `tests` section).
/// The production replay pipeline does not exist yet -- when it is
/// implemented (TCK-00356: Replay Evidence Pipeline), this verifier MUST
/// be invoked on every replayed episode trace before the trace is accepted
/// as valid evidence.  The verifier logic is complete and fully tested;
/// only the production call site is missing.
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
                    budget_checked: _,
                } => {
                    // Validate completeness of the check.
                    if !stop_checked {
                        return Err(ReplayViolation::StopNotChecked { index: i });
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
        // TCK-00351 v3: budget_checked is false when no tracker is wired
        // (honest receipt -- no tracker means no real budget check occurred).
        assert!(!receipt.budget_checked);
        assert_eq!(receipt.timestamp_ns, 1000);
        // is_cleared() requires both stop_checked AND budget_checked, so
        // without a tracker the receipt is not fully cleared.
        assert!(!receipt.is_cleared());
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
        // TCK-00351 v3: stop_checked is true, budget_checked is false
        // (no tracker wired).
        assert!(receipt.stop_checked);
        assert!(!receipt.budget_checked);
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
    fn test_replay_budget_not_checked_allowed_when_deferred() {
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
        assert!(
            ReplayVerifier::verify(&trace).is_ok(),
            "budget_checked=false is valid when enforcement is deferred"
        );
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

    // =========================================================================
    // StopAuthority tests (TCK-00351 BLOCKER 1 FIX)
    // =========================================================================

    #[test]
    fn test_stop_authority_default_no_stops() {
        let authority = StopAuthority::new();
        assert!(!authority.emergency_stop_active());
        assert!(!authority.governance_stop_active());
    }

    #[test]
    fn test_stop_authority_emergency_stop() {
        let authority = StopAuthority::new();
        authority.set_emergency_stop(true);
        assert!(authority.emergency_stop_active());
        assert!(!authority.governance_stop_active());
    }

    #[test]
    fn test_stop_authority_governance_stop() {
        let authority = StopAuthority::new();
        authority.set_governance_stop(true);
        assert!(!authority.emergency_stop_active());
        assert!(authority.governance_stop_active());
    }

    #[test]
    fn test_stop_authority_both_stops() {
        let authority = StopAuthority::new();
        authority.set_emergency_stop(true);
        authority.set_governance_stop(true);
        assert!(authority.emergency_stop_active());
        assert!(authority.governance_stop_active());
    }

    #[test]
    fn test_stop_authority_clear_after_set() {
        let authority = StopAuthority::new();
        authority.set_emergency_stop(true);
        assert!(authority.emergency_stop_active());
        authority.set_emergency_stop(false);
        assert!(!authority.emergency_stop_active());
    }

    // =========================================================================
    // Gate with StopAuthority tests (TCK-00351 BLOCKER 1 FIX)
    // =========================================================================

    #[test]
    fn test_gate_with_stop_authority_emergency_stop_denies() {
        let authority = Arc::new(StopAuthority::new());
        authority.set_emergency_stop(true);

        let gate = PreActuationGate::new(StopConditionEvaluator::new(), None)
            .with_stop_authority(Arc::clone(&authority));

        let conditions = StopConditions::default();
        // Even though caller passes false for emergency_stop, the authority
        // overrides it to true.
        let result = gate.check(&conditions, 0, false, false, 0, 1000);
        assert!(result.is_err());
        match result.unwrap_err() {
            PreActuationDenial::StopActive { class } => {
                assert_eq!(class, StopClass::EmergencyStop);
            },
            other => panic!("unexpected denial: {other}"),
        }
    }

    #[test]
    fn test_gate_with_stop_authority_governance_stop_denies() {
        let authority = Arc::new(StopAuthority::new());
        authority.set_governance_stop(true);

        let gate = PreActuationGate::new(StopConditionEvaluator::new(), None)
            .with_stop_authority(Arc::clone(&authority));

        let conditions = StopConditions::default();
        let result = gate.check(&conditions, 0, false, false, 0, 1000);
        assert!(result.is_err());
        match result.unwrap_err() {
            PreActuationDenial::StopActive { class } => {
                assert_eq!(class, StopClass::GovernanceStop);
            },
            other => panic!("unexpected denial: {other}"),
        }
    }

    #[test]
    fn test_gate_with_stop_authority_overrides_caller_false() {
        // StopAuthority says emergency stop is active, but caller passes false.
        // The authority MUST take precedence.
        let authority = Arc::new(StopAuthority::new());
        authority.set_emergency_stop(true);

        let gate = PreActuationGate::new(StopConditionEvaluator::new(), None)
            .with_stop_authority(authority);

        let conditions = StopConditions::default();
        let result = gate.check(&conditions, 0, false, false, 0, 1000);
        assert!(result.is_err());
    }

    #[test]
    fn test_gate_without_stop_authority_uses_caller_flags() {
        // No StopAuthority; gate should use the caller-supplied false values.
        let gate = PreActuationGate::new(StopConditionEvaluator::new(), None);

        let conditions = StopConditions::default();
        let result = gate.check(&conditions, 0, false, false, 0, 1000);
        assert!(result.is_ok());
    }

    // =========================================================================
    // Production gate / require_budget tests (TCK-00351 BLOCKER 2 FIX)
    // =========================================================================

    #[test]
    fn test_production_gate_no_tracker_allows() {
        // TCK-00351 BLOCKER 1 v2 FIX: Production gate with no budget
        // tracker should ALLOW (budget deferred to EpisodeRuntime) to
        // avoid self-DoS where ALL tool requests are denied.
        let authority = Arc::new(StopAuthority::new());
        let gate = PreActuationGate::production_gate(authority, None);

        let conditions = StopConditions::default();
        let result = gate.check(&conditions, 0, false, false, 0, 1000);
        assert!(
            result.is_ok(),
            "production gate without tracker should allow"
        );
        let receipt = result.unwrap();
        // TCK-00351 v3: stop_checked is true, budget_checked is false
        // (no tracker wired -- honest receipt).
        assert!(receipt.stop_checked);
        assert!(!receipt.budget_checked);
    }

    #[test]
    fn test_production_gate_with_require_budget_and_no_tracker_denies() {
        // Explicit require_budget=true on production gate should deny
        // when no tracker is configured (opt-in per-session budget).
        let authority = Arc::new(StopAuthority::new());
        let gate = PreActuationGate::production_gate(authority, None).with_require_budget(true);

        let conditions = StopConditions::default();
        let result = gate.check(&conditions, 0, false, false, 0, 1000);
        assert!(result.is_err());
        match result.unwrap_err() {
            PreActuationDenial::BudgetExhausted { .. } => {},
            other => panic!("expected BudgetExhausted, got: {other}"),
        }
    }

    #[test]
    fn test_production_gate_with_tracker_allows() {
        // Production gate with a real tracker that has budget remaining.
        let authority = Arc::new(StopAuthority::new());
        let budget = EpisodeBudget::builder().tool_calls(10).build();
        let tracker = Arc::new(BudgetTracker::from_envelope(budget));

        let gate = PreActuationGate::production_gate(authority, Some(tracker));
        let conditions = StopConditions::default();
        let result = gate.check(&conditions, 0, false, false, 0, 1000);
        assert!(result.is_ok());
        let receipt = result.unwrap();
        assert!(receipt.is_cleared());
    }

    #[test]
    fn test_default_gate_no_tracker_allows() {
        // Default gate (test mode) with no tracker should allow (backwards compat).
        let gate = PreActuationGate::default_gate();
        let conditions = StopConditions::default();
        let result = gate.check(&conditions, 0, false, false, 0, 1000);
        assert!(result.is_ok());
    }

    #[test]
    fn test_with_require_budget_flag() {
        // Test explicit require_budget flag via builder.
        let gate =
            PreActuationGate::new(StopConditionEvaluator::new(), None).with_require_budget(true);

        let conditions = StopConditions::default();
        let result = gate.check(&conditions, 0, false, false, 0, 1000);
        assert!(result.is_err());
        match result.unwrap_err() {
            PreActuationDenial::BudgetExhausted { .. } => {},
            other => panic!("expected BudgetExhausted, got: {other}"),
        }
    }

    // =========================================================================
    // Receipt field provenance tests (TCK-00351 MAJOR 1 FIX)
    // =========================================================================

    #[test]
    fn test_receipt_fields_from_gate_check() {
        // Verify that the receipt fields come from the gate check, not
        // from hardcoded values.
        let gate = PreActuationGate::default_gate();
        let conditions = StopConditions::default();
        let receipt = gate.check(&conditions, 0, false, false, 0, 42_000).unwrap();

        // stop_checked is true (checks passed), budget_checked is false
        // (no tracker wired), timestamp must be 42_000 (the value we passed
        // in, not a later clock sample).
        assert!(receipt.stop_checked);
        // TCK-00351 v3: budget_checked is false without a real tracker.
        assert!(!receipt.budget_checked);
        assert_eq!(receipt.timestamp_ns, 42_000);
    }

    // =========================================================================
    // Escalation predicate denial tests (TCK-00351 BLOCKER 1 FIX)
    // =========================================================================

    #[test]
    fn test_evaluator_escalation_predicate_triggers_deny() {
        let evaluator = StopConditionEvaluator::new();
        let conditions = StopConditions {
            max_episodes: 0,
            goal_predicate: String::new(),
            failure_predicate: String::new(),
            escalation_predicate: "model_uncertainty_high".to_string(),
        };
        let status = evaluator.evaluate(&conditions, 0, false, false);
        assert_eq!(
            status,
            StopStatus::Active {
                class: StopClass::EscalationTriggered,
            }
        );
    }

    #[test]
    fn test_gate_denies_on_escalation_predicate() {
        let gate = PreActuationGate::default_gate();
        let conditions = StopConditions {
            max_episodes: 0,
            goal_predicate: String::new(),
            failure_predicate: String::new(),
            escalation_predicate: "uncertainty_threshold_exceeded".to_string(),
        };
        let result = gate.check(&conditions, 0, false, false, 0, 1000);
        assert!(result.is_err());
        match result.unwrap_err() {
            PreActuationDenial::StopActive { class } => {
                assert_eq!(class, StopClass::EscalationTriggered);
            },
            other => panic!("unexpected denial: {other}"),
        }
    }

    // =========================================================================
    // TCK-00351 MAJOR 1 v2 FIX: Governance-uncertainty & deadline tests
    // =========================================================================

    #[test]
    fn test_evaluator_returns_uncertain_when_governance_uncertain() {
        let evaluator = StopConditionEvaluator::new();
        let conditions = StopConditions::default();
        let status = evaluator.evaluate_with_uncertainty(&conditions, 0, false, false, true);
        assert_eq!(status, StopStatus::Uncertain);
    }

    #[test]
    fn test_evaluator_active_takes_priority_over_uncertain() {
        let evaluator = StopConditionEvaluator::new();
        let conditions = StopConditions::default();
        // Emergency stop is active AND governance uncertain -- Active wins.
        let status = evaluator.evaluate_with_uncertainty(&conditions, 0, true, false, true);
        assert_eq!(
            status,
            StopStatus::Active {
                class: StopClass::EmergencyStop,
            }
        );
    }

    #[test]
    fn test_gate_uncertain_deadline_crossing_denies() {
        // TCK-00351 MAJOR 1 v2 FIX: When governance is uncertain and
        // elapsed_ms exceeds the deadline, the gate MUST deny with
        // StopUncertain.
        let authority = Arc::new(StopAuthority::new());
        authority.set_governance_uncertain(true);

        let deadline_ms = 5_000;
        let evaluator = StopConditionEvaluator::with_uncertainty_deadline_ms(deadline_ms);
        let gate =
            PreActuationGate::new(evaluator, None).with_stop_authority(Arc::clone(&authority));

        let conditions = StopConditions::default();
        // elapsed_ms == deadline => deny
        let result = gate.check(&conditions, 0, false, false, deadline_ms, 1000);
        assert!(result.is_err());
        match result.unwrap_err() {
            PreActuationDenial::StopUncertain => {},
            other => panic!("expected StopUncertain, got: {other}"),
        }
    }

    #[test]
    fn test_gate_uncertain_within_deadline_allows() {
        // Within deadline, uncertain status is optimistic (allow).
        let authority = Arc::new(StopAuthority::new());
        authority.set_governance_uncertain(true);

        let deadline_ms = 30_000;
        let evaluator = StopConditionEvaluator::with_uncertainty_deadline_ms(deadline_ms);
        let gate =
            PreActuationGate::new(evaluator, None).with_stop_authority(Arc::clone(&authority));

        let conditions = StopConditions::default();
        // elapsed_ms < deadline => allow
        let result = gate.check(&conditions, 0, false, false, 1_000, 2000);
        assert!(result.is_ok());
    }

    // =========================================================================
    // TCK-00351 MAJOR 2 v2 FIX: StopAuthority runtime mutation test
    // =========================================================================

    #[test]
    fn test_stop_authority_flip_immediately_denies() {
        // Verify that flipping stop flags on a shared StopAuthority is
        // immediately visible to the gate (no stale cache).
        let authority = Arc::new(StopAuthority::new());
        let gate = PreActuationGate::production_gate(Arc::clone(&authority), None);

        let conditions = StopConditions::default();

        // Initially clear
        let result = gate.check(&conditions, 0, false, false, 0, 1000);
        assert!(result.is_ok(), "should allow before stop");

        // Operator flips emergency stop
        authority.set_emergency_stop(true);

        let result = gate.check(&conditions, 0, false, false, 0, 2000);
        assert!(result.is_err(), "should deny after emergency stop");
        match result.unwrap_err() {
            PreActuationDenial::StopActive { class } => {
                assert_eq!(class, StopClass::EmergencyStop);
            },
            other => panic!("expected EmergencyStop, got: {other}"),
        }

        // Operator clears emergency stop
        authority.set_emergency_stop(false);

        let result = gate.check(&conditions, 0, false, false, 0, 3000);
        assert!(result.is_ok(), "should allow after stop cleared");
    }

    #[test]
    fn test_stop_authority_governance_uncertain_flag() {
        let authority = StopAuthority::new();
        assert!(!authority.governance_uncertain());
        authority.set_governance_uncertain(true);
        assert!(authority.governance_uncertain());
        authority.set_governance_uncertain(false);
        assert!(!authority.governance_uncertain());
    }

    // =========================================================================
    // TCK-00351 MAJOR 3 v2 FIX: ReplayVerifier integration test (EVID-0305)
    // =========================================================================

    /// Integration-style test exercising `ReplayVerifier::verify` on a
    /// production-like trace: gate check => actuation for two tool calls.
    ///
    /// # Evidence Binding
    ///
    /// This test is bound to **EVID-0305**: Pre-actuation ordering proof
    /// verifier evidence.
    #[test]
    fn test_replay_verifier_production_flow_evid_0305() {
        use crate::episode::budget_tracker::BudgetTracker;

        // Simulate a production flow: gate check -> tool actuation.
        // TCK-00351 v3: Use a real budget tracker so budget_checked=true
        // in the receipt, matching production deployment where a tracker
        // is always wired.
        let authority = Arc::new(StopAuthority::new());
        let budget = EpisodeBudget::builder()
            .tokens(10_000)
            .tool_calls(1000)
            .build();
        let tracker = Arc::new(BudgetTracker::from_envelope(budget));
        let gate =
            PreActuationGate::production_gate(Arc::clone(&authority), Some(Arc::clone(&tracker)));
        let conditions = StopConditions::default();

        // First tool request: gate check at ts=100
        let receipt1 = gate
            .check(&conditions, 0, false, false, 0, 100)
            .expect("gate should clear");
        assert!(receipt1.stop_checked);
        assert!(receipt1.budget_checked);

        // Second tool request: gate check at ts=300
        let receipt2 = gate
            .check(&conditions, 0, false, false, 0, 300)
            .expect("gate should clear");

        // Build trace as the runtime would
        let trace = vec![
            ReplayEntry {
                timestamp_ns: receipt1.timestamp_ns,
                kind: ReplayEntryKind::PreActuationCheck {
                    stop_checked: receipt1.stop_checked,
                    budget_checked: receipt1.budget_checked,
                },
            },
            ReplayEntry {
                timestamp_ns: 200, // actuation at ts=200
                kind: ReplayEntryKind::ToolActuation {
                    tool_class: "file_read".to_string(),
                    request_id: "REQ-001".to_string(),
                },
            },
            ReplayEntry {
                timestamp_ns: receipt2.timestamp_ns,
                kind: ReplayEntryKind::PreActuationCheck {
                    stop_checked: receipt2.stop_checked,
                    budget_checked: receipt2.budget_checked,
                },
            },
            ReplayEntry {
                timestamp_ns: 400, // actuation at ts=400
                kind: ReplayEntryKind::ToolActuation {
                    tool_class: "shell_exec".to_string(),
                    request_id: "REQ-002".to_string(),
                },
            },
        ];

        // Verify passes
        ReplayVerifier::verify(&trace).expect("production flow trace should verify (EVID-0305)");
    }

    /// Negative integration test: actuation without gate check must fail
    /// replay verification (EVID-0305).
    #[test]
    fn test_replay_verifier_rejects_ungated_actuation_evid_0305() {
        // Trace with actuation but no preceding check
        let trace = vec![ReplayEntry {
            timestamp_ns: 100,
            kind: ReplayEntryKind::ToolActuation {
                tool_class: "file_write".to_string(),
                request_id: "REQ-UNGATED".to_string(),
            },
        }];

        let err = ReplayVerifier::verify(&trace).unwrap_err();
        assert!(
            matches!(err, ReplayViolation::MissingPreActuationCheck { .. }),
            "ungated actuation must be caught by verifier (EVID-0305)"
        );
    }

    // =========================================================================
    // TCK-00351 v3: Integration tests for real stop conditions enforcement
    // =========================================================================

    /// TCK-00351 BLOCKER 1 v3: When `max_episodes=2` and
    /// `current_episode_count=2`, the gate MUST deny with
    /// `StopActive { class: MaxEpisodesReached }`.
    ///
    /// This proves that the gate actually enforces `max_episodes` when real
    /// conditions are passed (as opposed to `StopConditions::default()`
    /// which has `max_episodes=0` and is never checked).
    #[test]
    fn test_gate_denies_when_max_episodes_reached() {
        let authority = Arc::new(StopAuthority::new());
        let gate = PreActuationGate::production_gate(Arc::clone(&authority), None);

        // max_episodes=2, so episode_count >= 2 must deny
        let conditions = StopConditions::max_episodes(2);

        // episode_count=1: should still pass
        let receipt = gate
            .check(&conditions, 1, false, false, 0, 100)
            .expect("gate should clear when episode_count < max_episodes");
        assert!(receipt.stop_checked);

        // episode_count=2: should deny (2 >= 2)
        let err = gate
            .check(&conditions, 2, false, false, 0, 200)
            .expect_err("gate should deny when episode_count >= max_episodes");
        assert!(
            matches!(
                err,
                PreActuationDenial::StopActive {
                    class: StopClass::MaxEpisodesReached
                }
            ),
            "expected MaxEpisodesReached denial, got: {err:?}"
        );

        // episode_count=10: should also deny (10 >= 2)
        let err = gate
            .check(&conditions, 10, false, false, 0, 300)
            .expect_err("gate should deny when episode_count >> max_episodes");
        assert!(
            matches!(
                err,
                PreActuationDenial::StopActive {
                    class: StopClass::MaxEpisodesReached
                }
            ),
            "expected MaxEpisodesReached denial at count=10, got: {err:?}"
        );
    }

    /// TCK-00351 BLOCKER 1 v3: When the escalation predicate is non-empty,
    /// the gate MUST deny with `StopActive { class: EscalationTriggered }`.
    #[test]
    fn test_gate_denies_when_escalation_predicate_set() {
        let authority = Arc::new(StopAuthority::new());
        let gate = PreActuationGate::production_gate(Arc::clone(&authority), None);

        let conditions = StopConditions {
            max_episodes: 0,
            goal_predicate: String::new(),
            failure_predicate: String::new(),
            escalation_predicate: "cost > $100".to_string(),
        };

        let err = gate
            .check(&conditions, 0, false, false, 0, 100)
            .expect_err("gate should deny when escalation predicate is set");
        assert!(
            matches!(
                err,
                PreActuationDenial::StopActive {
                    class: StopClass::EscalationTriggered
                }
            ),
            "expected EscalationTriggered denial, got: {err:?}"
        );
    }

    /// TCK-00351 BLOCKER 2 v3: When no budget tracker is wired and
    /// `require_budget=false`, the receipt MUST set `budget_checked=false`
    /// (honest receipt claim).
    ///
    /// Previously the receipt claimed `budget_checked=true` even when no
    /// tracker performed the check.
    #[test]
    fn test_budget_checked_false_without_tracker() {
        let authority = Arc::new(StopAuthority::new());
        // production_gate with no budget tracker
        let gate = PreActuationGate::production_gate(Arc::clone(&authority), None);

        let conditions = StopConditions::default();
        let receipt = gate
            .check(&conditions, 0, false, false, 0, 100)
            .expect("gate should clear (no budget enforcement)");

        assert!(receipt.stop_checked, "stop should always be checked");
        assert!(
            !receipt.budget_checked,
            "budget_checked must be false when no tracker is wired"
        );
    }

    /// Deferred trackers must not claim pre-actuation budget enforcement.
    #[test]
    fn test_budget_checked_false_with_deferred_tracker() {
        use crate::episode::budget_tracker::BudgetTracker;

        let authority = Arc::new(StopAuthority::new());
        let tracker = Arc::new(BudgetTracker::deferred());
        let gate = PreActuationGate::production_gate(Arc::clone(&authority), Some(tracker));

        let conditions = StopConditions::default();
        let receipt = gate
            .check(&conditions, 0, false, false, 0, 100)
            .expect("gate should clear with deferred tracker");

        assert!(receipt.stop_checked, "stop should always be checked");
        assert!(
            !receipt.budget_checked,
            "budget_checked must be false when tracker enforcement is deferred"
        );
    }

    /// TCK-00351 BLOCKER 2 v3: When a real budget tracker IS wired and
    /// has sufficient budget, the receipt MUST set `budget_checked=true`.
    #[test]
    fn test_budget_checked_true_with_real_tracker() {
        use crate::episode::budget_tracker::BudgetTracker;

        let authority = Arc::new(StopAuthority::new());
        let budget = EpisodeBudget::builder()
            .tokens(1000)
            .tool_calls(100)
            .build();
        let tracker = Arc::new(BudgetTracker::from_envelope(budget));
        let gate = PreActuationGate::production_gate(Arc::clone(&authority), Some(tracker));

        let conditions = StopConditions::default();
        let receipt = gate
            .check(&conditions, 0, false, false, 0, 100)
            .expect("gate should clear with sufficient budget");

        assert!(receipt.stop_checked, "stop should be checked");
        assert!(
            receipt.budget_checked,
            "budget_checked must be true when a real tracker verified the budget"
        );
    }
}
