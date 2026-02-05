//! Orchestration state and driver implementation.
//!
//! This module defines the core state machine for FAC orchestration,
//! including the state struct, termination reasons, and the driver
//! that manages the revision loop.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::HolonError;
use crate::ledger::validate_id;
use crate::resource::Budget;

/// Maximum number of iterations allowed for safety (1-100 per ticket spec).
pub const MAX_ITERATIONS_LIMIT: u64 = 100;

/// Minimum number of iterations (must be at least 1).
pub const MIN_ITERATIONS: u64 = 1;

/// Maximum length for reason/error/description strings.
pub const MAX_REASON_LENGTH: usize = 1024;

/// Maximum length for role strings.
pub const MAX_ROLE_LENGTH: usize = 256;

/// Reason code for blocked termination.
///
/// These codes provide structured information about why work was blocked,
/// enabling automated triage and metrics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub enum BlockedReasonCode {
    /// A reviewer found blocking issues that cannot be automatically resolved.
    ReviewerBlocked {
        /// The reviewer role that blocked (e.g., "security", "quality").
        reviewer_role: String,
        /// Optional finding summary.
        finding_summary: Option<String>,
    },
    /// The changeset cannot be applied to the workspace.
    ChangeSetApplyFailed {
        /// Error message from the apply operation.
        error: String,
    },
    /// Required context or dependencies are missing.
    MissingDependency {
        /// What is missing.
        dependency: String,
    },
    /// Policy prevents the work from proceeding.
    PolicyViolation {
        /// The policy that was violated.
        policy: String,
    },
    /// The implementer cannot make progress.
    ImplementerStalled {
        /// Reason for the stall.
        reason: String,
    },
    /// Unclassified blocking reason.
    Other {
        /// Description of the reason.
        description: String,
    },
}

impl BlockedReasonCode {
    /// Validates bounds on all string fields.
    ///
    /// # Errors
    ///
    /// Returns `HolonError::InvalidInput` if any field exceeds limits.
    pub fn validate(&self) -> Result<(), HolonError> {
        match self {
            Self::ReviewerBlocked {
                reviewer_role,
                finding_summary,
            } => {
                if reviewer_role.len() > MAX_ROLE_LENGTH {
                    return Err(HolonError::invalid_input(format!(
                        "reviewer_role exceeds max length: {} > {MAX_ROLE_LENGTH}",
                        reviewer_role.len()
                    )));
                }
                if let Some(summary) = finding_summary {
                    if summary.len() > MAX_REASON_LENGTH {
                        return Err(HolonError::invalid_input(format!(
                            "finding_summary exceeds max length: {} > {MAX_REASON_LENGTH}",
                            summary.len()
                        )));
                    }
                }
            },
            Self::ChangeSetApplyFailed { error } => {
                if error.len() > MAX_REASON_LENGTH {
                    return Err(HolonError::invalid_input(format!(
                        "error exceeds max length: {} > {MAX_REASON_LENGTH}",
                        error.len()
                    )));
                }
            },
            Self::MissingDependency { dependency } => {
                if dependency.len() > MAX_REASON_LENGTH {
                    return Err(HolonError::invalid_input(format!(
                        "dependency exceeds max length: {} > {MAX_REASON_LENGTH}",
                        dependency.len()
                    )));
                }
            },
            Self::PolicyViolation { policy } => {
                if policy.len() > MAX_REASON_LENGTH {
                    return Err(HolonError::invalid_input(format!(
                        "policy exceeds max length: {} > {MAX_REASON_LENGTH}",
                        policy.len()
                    )));
                }
            },
            Self::ImplementerStalled { reason } => {
                if reason.len() > MAX_REASON_LENGTH {
                    return Err(HolonError::invalid_input(format!(
                        "reason exceeds max length: {} > {MAX_REASON_LENGTH}",
                        reason.len()
                    )));
                }
            },
            Self::Other { description } => {
                if description.len() > MAX_REASON_LENGTH {
                    return Err(HolonError::invalid_input(format!(
                        "description exceeds max length: {} > {MAX_REASON_LENGTH}",
                        description.len()
                    )));
                }
            },
        }
        Ok(())
    }
}

impl fmt::Display for BlockedReasonCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReviewerBlocked {
                reviewer_role,
                finding_summary,
            } => {
                write!(f, "reviewer '{reviewer_role}' blocked")?;
                if let Some(summary) = finding_summary {
                    write!(f, ": {summary}")?;
                }
                Ok(())
            },
            Self::ChangeSetApplyFailed { error } => {
                write!(f, "changeset apply failed: {error}")
            },
            Self::MissingDependency { dependency } => {
                write!(f, "missing dependency: {dependency}")
            },
            Self::PolicyViolation { policy } => {
                write!(f, "policy violation: {policy}")
            },
            Self::ImplementerStalled { reason } => {
                write!(f, "implementer stalled: {reason}")
            },
            Self::Other { description } => write!(f, "{description}"),
        }
    }
}

/// Reason why orchestration terminated.
///
/// This enum captures the authoritative termination reason for the
/// orchestration loop. It is recorded in the ledger and used for
/// metrics, debugging, and deciding next actions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub enum TerminationReason {
    /// All reviews passed; work is complete.
    Pass,

    /// Work is blocked and cannot proceed automatically.
    Blocked(BlockedReasonCode),

    /// Budget was exhausted before completion.
    BudgetExhausted {
        /// Which resource was exhausted.
        resource: String,
        /// How much was consumed.
        consumed: u64,
        /// What the limit was.
        limit: u64,
    },

    /// An external operator requested termination.
    OperatorStop {
        /// Reason provided by the operator.
        reason: String,
        /// Operator identity (if available).
        operator_id: Option<String>,
    },

    /// Maximum iterations reached without resolution.
    MaxIterationsReached {
        /// Number of iterations executed.
        iterations: u64,
    },

    /// An unrecoverable error occurred.
    Error {
        /// Error description.
        error: String,
    },
}

impl TerminationReason {
    /// Creates a Pass termination.
    #[must_use]
    pub const fn pass() -> Self {
        Self::Pass
    }

    /// Creates a Blocked termination with a reason code.
    #[must_use]
    pub const fn blocked(reason_code: BlockedReasonCode) -> Self {
        Self::Blocked(reason_code)
    }

    /// Creates a `BudgetExhausted` termination.
    #[must_use]
    pub fn budget_exhausted(resource: impl Into<String>, consumed: u64, limit: u64) -> Self {
        Self::BudgetExhausted {
            resource: resource.into(),
            consumed,
            limit,
        }
    }

    /// Creates an `OperatorStop` termination.
    #[must_use]
    pub fn operator_stop(reason: impl Into<String>) -> Self {
        Self::OperatorStop {
            reason: reason.into(),
            operator_id: None,
        }
    }

    /// Creates an `OperatorStop` termination with operator ID.
    #[must_use]
    pub fn operator_stop_with_id(
        reason: impl Into<String>,
        operator_id: impl Into<String>,
    ) -> Self {
        Self::OperatorStop {
            reason: reason.into(),
            operator_id: Some(operator_id.into()),
        }
    }

    /// Creates a `MaxIterationsReached` termination.
    #[must_use]
    pub const fn max_iterations_reached(iterations: u64) -> Self {
        Self::MaxIterationsReached { iterations }
    }

    /// Creates an Error termination.
    #[must_use]
    pub fn error(error: impl Into<String>) -> Self {
        Self::Error {
            error: error.into(),
        }
    }

    /// Returns `true` if this is a successful termination (Pass).
    #[must_use]
    pub const fn is_success(&self) -> bool {
        matches!(self, Self::Pass)
    }

    /// Returns `true` if this is a blocked termination.
    #[must_use]
    pub const fn is_blocked(&self) -> bool {
        matches!(self, Self::Blocked(_))
    }

    /// Returns `true` if this is a resource-related termination.
    #[must_use]
    pub const fn is_resource_limit(&self) -> bool {
        matches!(
            self,
            Self::BudgetExhausted { .. } | Self::MaxIterationsReached { .. }
        )
    }

    /// Returns `true` if this is an error termination.
    #[must_use]
    pub const fn is_error(&self) -> bool {
        matches!(self, Self::Error { .. })
    }

    /// Returns the termination reason as a string identifier.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Blocked(_) => "blocked",
            Self::BudgetExhausted { .. } => "budget_exhausted",
            Self::OperatorStop { .. } => "operator_stop",
            Self::MaxIterationsReached { .. } => "max_iterations_reached",
            Self::Error { .. } => "error",
        }
    }

    /// Validates bounds on all string fields.
    ///
    /// # Errors
    ///
    /// Returns `HolonError::InvalidInput` if any field exceeds limits.
    pub fn validate(&self) -> Result<(), HolonError> {
        match self {
            Self::Pass | Self::MaxIterationsReached { .. } => Ok(()),
            Self::Blocked(code) => code.validate(),
            Self::BudgetExhausted { resource, .. } => {
                if resource.len() > MAX_ROLE_LENGTH {
                    return Err(HolonError::invalid_input(format!(
                        "resource exceeds max length: {} > {MAX_ROLE_LENGTH}",
                        resource.len()
                    )));
                }
                Ok(())
            },
            Self::OperatorStop {
                reason,
                operator_id,
            } => {
                if reason.len() > MAX_REASON_LENGTH {
                    return Err(HolonError::invalid_input(format!(
                        "reason exceeds max length: {} > {MAX_REASON_LENGTH}",
                        reason.len()
                    )));
                }
                if let Some(id) = operator_id {
                    if id.len() > MAX_ROLE_LENGTH {
                        return Err(HolonError::invalid_input(format!(
                            "operator_id exceeds max length: {} > {MAX_ROLE_LENGTH}",
                            id.len()
                        )));
                    }
                }
                Ok(())
            },
            Self::Error { error } => {
                if error.len() > MAX_REASON_LENGTH {
                    return Err(HolonError::invalid_input(format!(
                        "error exceeds max length: {} > {MAX_REASON_LENGTH}",
                        error.len()
                    )));
                }
                Ok(())
            },
        }
    }
}

impl fmt::Display for TerminationReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass => write!(f, "pass"),
            Self::Blocked(code) => write!(f, "blocked: {code}"),
            Self::BudgetExhausted {
                resource,
                consumed,
                limit,
            } => {
                write!(f, "budget exhausted: {resource} ({consumed}/{limit})")
            },
            Self::OperatorStop {
                reason,
                operator_id,
            } => {
                write!(f, "operator stop: {reason}")?;
                if let Some(id) = operator_id {
                    write!(f, " (by {id})")?;
                }
                Ok(())
            },
            Self::MaxIterationsReached { iterations } => {
                write!(f, "max iterations reached: {iterations}")
            },
            Self::Error { error } => write!(f, "error: {error}"),
        }
    }
}

/// Configuration for the orchestration driver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrchestrationConfig {
    /// Maximum number of revision iterations (1-100).
    pub max_iterations: u64,

    /// Token budget for the entire orchestration.
    pub token_budget: u64,

    /// Time budget in milliseconds.
    pub time_budget_ms: u64,

    /// Whether to emit ledger events.
    pub emit_events: bool,

    /// Whether to fail fast on errors.
    pub fail_fast: bool,
}

impl Default for OrchestrationConfig {
    fn default() -> Self {
        Self {
            max_iterations: MAX_ITERATIONS_LIMIT,
            token_budget: 10_000_000,  // 10M tokens
            time_budget_ms: 3_600_000, // 1 hour
            emit_events: true,
            fail_fast: true,
        }
    }
}

impl OrchestrationConfig {
    /// Creates a new configuration with the specified max iterations.
    ///
    /// # Panics
    ///
    /// Panics if `max_iterations` is 0 or exceeds `MAX_ITERATIONS_LIMIT`.
    #[must_use]
    pub fn with_max_iterations(mut self, max: u64) -> Self {
        assert!(
            (MIN_ITERATIONS..=MAX_ITERATIONS_LIMIT).contains(&max),
            "max_iterations must be between {MIN_ITERATIONS} and {MAX_ITERATIONS_LIMIT}"
        );
        self.max_iterations = max;
        self
    }

    /// Creates a new configuration with the specified token budget.
    #[must_use]
    pub const fn with_token_budget(mut self, budget: u64) -> Self {
        self.token_budget = budget;
        self
    }

    /// Creates a new configuration with the specified time budget.
    #[must_use]
    pub const fn with_time_budget_ms(mut self, budget_ms: u64) -> Self {
        self.time_budget_ms = budget_ms;
        self
    }

    /// Creates a new configuration with event emission enabled/disabled.
    #[must_use]
    pub const fn with_emit_events(mut self, emit: bool) -> Self {
        self.emit_events = emit;
        self
    }

    /// Creates a new configuration with fail-fast behavior.
    #[must_use]
    pub const fn with_fail_fast(mut self, fail_fast: bool) -> Self {
        self.fail_fast = fail_fast;
        self
    }

    /// Validates the configuration.
    ///
    /// # Errors
    ///
    /// Returns `HolonError::InvalidInput` if configuration is invalid.
    pub fn validate(&self) -> Result<(), HolonError> {
        if self.max_iterations < MIN_ITERATIONS {
            return Err(HolonError::invalid_input(format!(
                "max_iterations must be at least {MIN_ITERATIONS}"
            )));
        }
        if self.max_iterations > MAX_ITERATIONS_LIMIT {
            return Err(HolonError::invalid_input(format!(
                "max_iterations cannot exceed {MAX_ITERATIONS_LIMIT}"
            )));
        }
        if self.token_budget == 0 {
            return Err(HolonError::invalid_input(
                "token_budget must be positive".to_string(),
            ));
        }
        if self.time_budget_ms == 0 {
            return Err(HolonError::invalid_input(
                "time_budget_ms must be positive".to_string(),
            ));
        }
        Ok(())
    }
}

/// Orchestration state for FAC revision loops (version 1).
///
/// This struct represents the current state of an orchestration session,
/// including iteration count, budgets, and termination status. The state
/// is designed to be reconstructed from ledger events for crash-only
/// recovery.
///
/// # Invariants
///
/// - `iteration_count` is monotonically increasing
/// - `tokens_consumed` and `time_consumed_ms` are monotonically increasing
/// - Once `termination_reason` is `Some`, the state is terminal
/// - `iteration_count` never exceeds `max_iterations`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrchestrationStateV1 {
    /// Work ID being orchestrated.
    work_id: String,

    /// Unique orchestration session ID.
    orchestration_id: String,

    /// Current iteration count (0-indexed, incremented after each cycle).
    iteration_count: u64,

    /// Maximum number of iterations allowed.
    max_iterations: u64,

    /// Initial token budget.
    initial_token_budget: u64,

    /// Tokens consumed so far.
    tokens_consumed: u64,

    /// Initial time budget in milliseconds.
    initial_time_budget_ms: u64,

    /// Time consumed so far in milliseconds.
    time_consumed_ms: u64,

    /// Timestamp when orchestration started (nanoseconds since epoch).
    started_at_ns: u64,

    /// Timestamp of last iteration completion (nanoseconds since epoch).
    last_iteration_at_ns: Option<u64>,

    /// Termination reason (None if still running).
    termination_reason: Option<TerminationReason>,

    /// BLAKE3 hash of the last changeset bundle processed.
    #[serde(skip_serializing_if = "Option::is_none")]
    last_changeset_hash: Option<[u8; 32]>,

    /// BLAKE3 hash of the last reviewer receipt.
    #[serde(skip_serializing_if = "Option::is_none")]
    last_receipt_hash: Option<[u8; 32]>,
}

impl OrchestrationStateV1 {
    /// Creates a new orchestration state.
    ///
    /// # Arguments
    ///
    /// * `work_id` - The work ID being orchestrated
    /// * `orchestration_id` - Unique ID for this orchestration session
    /// * `max_iterations` - Maximum number of iterations (1-100)
    /// * `token_budget` - Total token budget
    /// * `time_budget_ms` - Total time budget in milliseconds
    ///
    /// # Errors
    ///
    /// Returns `HolonError::InvalidInput` if:
    /// - `work_id` fails ID validation
    /// - `orchestration_id` fails ID validation
    /// - `max_iterations` is outside 1-100 range
    /// - Budgets are zero
    pub fn try_new(
        work_id: impl Into<String>,
        orchestration_id: impl Into<String>,
        max_iterations: u64,
        token_budget: u64,
        time_budget_ms: u64,
    ) -> Result<Self, HolonError> {
        let work_id = work_id.into();
        let orchestration_id = orchestration_id.into();

        validate_id(&work_id, "work_id")?;
        validate_id(&orchestration_id, "orchestration_id")?;

        if max_iterations < MIN_ITERATIONS {
            return Err(HolonError::invalid_input(format!(
                "max_iterations must be at least {MIN_ITERATIONS}"
            )));
        }
        if max_iterations > MAX_ITERATIONS_LIMIT {
            return Err(HolonError::invalid_input(format!(
                "max_iterations cannot exceed {MAX_ITERATIONS_LIMIT}"
            )));
        }
        if token_budget == 0 {
            return Err(HolonError::invalid_input(
                "token_budget must be positive".to_string(),
            ));
        }
        if time_budget_ms == 0 {
            return Err(HolonError::invalid_input(
                "time_budget_ms must be positive".to_string(),
            ));
        }

        Ok(Self {
            work_id,
            orchestration_id,
            iteration_count: 0,
            max_iterations,
            initial_token_budget: token_budget,
            tokens_consumed: 0,
            initial_time_budget_ms: time_budget_ms,
            time_consumed_ms: 0,
            started_at_ns: 0,
            last_iteration_at_ns: None,
            termination_reason: None,
            last_changeset_hash: None,
            last_receipt_hash: None,
        })
    }

    /// Creates a new orchestration state without validation.
    ///
    /// # Warning
    ///
    /// This constructor skips validation. Use [`try_new`](Self::try_new) for
    /// external input.
    #[must_use]
    pub fn new(
        work_id: impl Into<String>,
        orchestration_id: impl Into<String>,
        max_iterations: u64,
        token_budget: u64,
        time_budget_ms: u64,
    ) -> Self {
        Self {
            work_id: work_id.into(),
            orchestration_id: orchestration_id.into(),
            iteration_count: 0,
            max_iterations: max_iterations.clamp(MIN_ITERATIONS, MAX_ITERATIONS_LIMIT),
            initial_token_budget: token_budget.max(1),
            tokens_consumed: 0,
            initial_time_budget_ms: time_budget_ms.max(1),
            time_consumed_ms: 0,
            started_at_ns: 0,
            last_iteration_at_ns: None,
            termination_reason: None,
            last_changeset_hash: None,
            last_receipt_hash: None,
        }
    }

    /// Returns the work ID.
    #[must_use]
    pub fn work_id(&self) -> &str {
        &self.work_id
    }

    /// Returns the orchestration session ID.
    #[must_use]
    pub fn orchestration_id(&self) -> &str {
        &self.orchestration_id
    }

    /// Returns the current iteration count.
    #[must_use]
    pub const fn iteration_count(&self) -> u64 {
        self.iteration_count
    }

    /// Returns the maximum iterations allowed.
    #[must_use]
    pub const fn max_iterations(&self) -> u64 {
        self.max_iterations
    }

    /// Returns the remaining iterations.
    #[must_use]
    pub const fn remaining_iterations(&self) -> u64 {
        self.max_iterations.saturating_sub(self.iteration_count)
    }

    /// Returns the initial token budget.
    #[must_use]
    pub const fn initial_token_budget(&self) -> u64 {
        self.initial_token_budget
    }

    /// Returns tokens consumed so far.
    #[must_use]
    pub const fn tokens_consumed(&self) -> u64 {
        self.tokens_consumed
    }

    /// Returns remaining token budget.
    #[must_use]
    pub const fn remaining_tokens(&self) -> u64 {
        self.initial_token_budget
            .saturating_sub(self.tokens_consumed)
    }

    /// Returns the initial time budget in milliseconds.
    #[must_use]
    pub const fn initial_time_budget_ms(&self) -> u64 {
        self.initial_time_budget_ms
    }

    /// Returns time consumed in milliseconds.
    #[must_use]
    pub const fn time_consumed_ms(&self) -> u64 {
        self.time_consumed_ms
    }

    /// Returns remaining time budget in milliseconds.
    #[must_use]
    pub const fn remaining_time_ms(&self) -> u64 {
        self.initial_time_budget_ms
            .saturating_sub(self.time_consumed_ms)
    }

    /// Returns the start timestamp.
    #[must_use]
    pub const fn started_at_ns(&self) -> u64 {
        self.started_at_ns
    }

    /// Returns the timestamp of the last iteration.
    #[must_use]
    pub const fn last_iteration_at_ns(&self) -> Option<u64> {
        self.last_iteration_at_ns
    }

    /// Returns the termination reason if terminated.
    #[must_use]
    pub const fn termination_reason(&self) -> Option<&TerminationReason> {
        self.termination_reason.as_ref()
    }

    /// Returns `true` if the orchestration is terminated.
    #[must_use]
    pub const fn is_terminated(&self) -> bool {
        self.termination_reason.is_some()
    }

    /// Returns `true` if the orchestration succeeded (Pass).
    #[must_use]
    pub const fn is_success(&self) -> bool {
        matches!(&self.termination_reason, Some(TerminationReason::Pass))
    }

    /// Returns `true` if budget is exhausted.
    #[must_use]
    pub const fn budget_exhausted(&self) -> bool {
        self.tokens_consumed >= self.initial_token_budget
            || self.time_consumed_ms >= self.initial_time_budget_ms
            || self.iteration_count >= self.max_iterations
    }

    /// Returns the last changeset hash.
    #[must_use]
    pub const fn last_changeset_hash(&self) -> Option<&[u8; 32]> {
        self.last_changeset_hash.as_ref()
    }

    /// Returns the last receipt hash.
    #[must_use]
    pub const fn last_receipt_hash(&self) -> Option<&[u8; 32]> {
        self.last_receipt_hash.as_ref()
    }

    /// Sets the start timestamp.
    pub const fn set_started_at_ns(&mut self, timestamp_ns: u64) {
        self.started_at_ns = timestamp_ns;
    }

    /// Increments the iteration count and records consumption.
    ///
    /// # Arguments
    ///
    /// * `tokens_used` - Tokens consumed in this iteration
    /// * `time_used_ms` - Time consumed in this iteration
    /// * `timestamp_ns` - Completion timestamp
    /// * `changeset_hash` - Hash of the changeset processed
    /// * `receipt_hash` - Hash of the reviewer receipt
    ///
    /// # Returns
    ///
    /// Returns `Some(TerminationReason)` if the iteration should cause
    /// termination, `None` otherwise.
    pub fn record_iteration(
        &mut self,
        tokens_used: u64,
        time_used_ms: u64,
        timestamp_ns: u64,
        changeset_hash: Option<[u8; 32]>,
        receipt_hash: Option<[u8; 32]>,
    ) -> Option<TerminationReason> {
        // Record consumption (saturating to prevent overflow)
        self.tokens_consumed = self.tokens_consumed.saturating_add(tokens_used);
        self.time_consumed_ms = self.time_consumed_ms.saturating_add(time_used_ms);
        self.last_iteration_at_ns = Some(timestamp_ns);
        self.last_changeset_hash = changeset_hash;
        self.last_receipt_hash = receipt_hash;

        // Increment iteration
        self.iteration_count = self.iteration_count.saturating_add(1);

        // Check for budget exhaustion
        if self.tokens_consumed >= self.initial_token_budget {
            return Some(TerminationReason::budget_exhausted(
                "tokens",
                self.tokens_consumed,
                self.initial_token_budget,
            ));
        }

        if self.time_consumed_ms >= self.initial_time_budget_ms {
            return Some(TerminationReason::budget_exhausted(
                "time",
                self.time_consumed_ms,
                self.initial_time_budget_ms,
            ));
        }

        if self.iteration_count >= self.max_iterations {
            return Some(TerminationReason::max_iterations_reached(
                self.iteration_count,
            ));
        }

        None
    }

    /// Terminates the orchestration with the given reason.
    ///
    /// # Returns
    ///
    /// Returns `true` if termination was set, `false` if already terminated.
    pub fn terminate(&mut self, reason: TerminationReason) -> bool {
        if self.termination_reason.is_some() {
            return false;
        }
        self.termination_reason = Some(reason);
        true
    }

    /// Creates a Budget struct from current remaining resources.
    ///
    /// This is useful for passing to episode execution.
    #[must_use]
    pub const fn as_budget(&self) -> Budget {
        Budget::new(
            self.remaining_iterations(),
            u64::MAX, // tool calls not tracked at orchestration level
            self.remaining_tokens(),
            self.remaining_time_ms(),
        )
    }
}

/// Driver for running orchestration loops.
///
/// The driver manages the high-level orchestration flow, including:
/// - Starting orchestration
/// - Running iterations
/// - Handling termination
/// - Emitting events
///
/// # Crash Recovery
///
/// The driver supports crash-only recovery by reconstructing state from
/// ledger events. Use [`OrchestrationDriver::resume_from_events`] to
/// resume from a checkpoint.
#[derive(Debug, Clone)]
pub struct OrchestrationDriver {
    /// Configuration for the driver.
    config: OrchestrationConfig,
}

impl OrchestrationDriver {
    /// Creates a new orchestration driver.
    #[must_use]
    pub const fn new(config: OrchestrationConfig) -> Self {
        Self { config }
    }

    /// Creates a driver with default configuration.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(OrchestrationConfig::default())
    }

    /// Returns the driver configuration.
    #[must_use]
    pub const fn config(&self) -> &OrchestrationConfig {
        &self.config
    }

    /// Creates initial orchestration state for a work ID.
    ///
    /// # Errors
    ///
    /// Returns `HolonError::InvalidInput` if `work_id` validation fails.
    pub fn create_state(
        &self,
        work_id: &str,
        orchestration_id: &str,
    ) -> Result<OrchestrationStateV1, HolonError> {
        self.config.validate()?;
        OrchestrationStateV1::try_new(
            work_id,
            orchestration_id,
            self.config.max_iterations,
            self.config.token_budget,
            self.config.time_budget_ms,
        )
    }

    /// Resumes orchestration state from a sequence of events.
    ///
    /// This method reconstructs the orchestration state by replaying events
    /// in order. It expects events to be:
    /// 1. An `OrchestrationStarted` event
    /// 2. Zero or more `IterationCompleted` events
    /// 3. Optionally an `OrchestrationTerminated` event
    ///
    /// # Arguments
    ///
    /// * `events` - Iterator of orchestration events in chronological order
    ///
    /// # Returns
    ///
    /// Returns the reconstructed state, or `None` if no start event was found.
    ///
    /// # Errors
    ///
    /// Returns `HolonError::InvalidState` if events are inconsistent,
    /// including:
    /// - Events out of order (missing start, wrong iteration numbers)
    /// - Non-monotonic timestamps
    /// - Termination summary mismatches
    /// - Invalid field values (exceeding limits)
    pub fn resume_from_events<'a, I>(
        &self,
        events: I,
    ) -> Result<Option<OrchestrationStateV1>, HolonError>
    where
        I: IntoIterator<Item = &'a super::OrchestrationEvent>,
    {
        let mut state: Option<OrchestrationStateV1> = None;
        let mut last_timestamp_ns: u64 = 0;

        for event in events {
            match event {
                super::OrchestrationEvent::Started(started) => {
                    // Use validating constructor to fail hard on invalid data
                    let mut new_state = OrchestrationStateV1::try_new(
                        started.work_id(),
                        started.orchestration_id(),
                        started.max_iterations(),
                        started.token_budget(),
                        started.time_budget_ms(),
                    )?;
                    new_state.set_started_at_ns(started.started_at_ns());
                    last_timestamp_ns = started.started_at_ns();
                    state = Some(new_state);
                },
                super::OrchestrationEvent::IterationCompleted(completed) => {
                    let s = state.as_mut().ok_or_else(|| {
                        HolonError::invalid_state(
                            "OrchestrationStarted event",
                            "IterationCompleted event without start",
                        )
                    })?;

                    // Validate event fields
                    completed.validate()?;

                    // Verify iteration number matches
                    let expected_iteration = s.iteration_count + 1;
                    if completed.iteration_number() != expected_iteration {
                        return Err(HolonError::invalid_state(
                            format!("iteration {expected_iteration}"),
                            format!("iteration {}", completed.iteration_number()),
                        ));
                    }

                    // Verify timestamp monotonicity
                    if completed.completed_at_ns() < last_timestamp_ns {
                        return Err(HolonError::invalid_state(
                            format!("timestamp >= {last_timestamp_ns}"),
                            format!("timestamp {}", completed.completed_at_ns()),
                        ));
                    }
                    last_timestamp_ns = completed.completed_at_ns();

                    // Record the iteration
                    s.record_iteration(
                        completed.tokens_consumed(),
                        completed.time_consumed_ms(),
                        completed.completed_at_ns(),
                        completed.changeset_hash().copied(),
                        completed.receipt_hash().copied(),
                    );
                },
                super::OrchestrationEvent::Terminated(terminated) => {
                    let s = state.as_mut().ok_or_else(|| {
                        HolonError::invalid_state(
                            "OrchestrationStarted event",
                            "OrchestrationTerminated event without start",
                        )
                    })?;

                    // Validate termination reason
                    terminated.reason().validate()?;

                    // Verify timestamp monotonicity
                    if terminated.terminated_at_ns() < last_timestamp_ns {
                        return Err(HolonError::invalid_state(
                            format!("timestamp >= {last_timestamp_ns}"),
                            format!("timestamp {}", terminated.terminated_at_ns()),
                        ));
                    }

                    // Verify summary totals match reconstructed state (LAW-07)
                    if terminated.total_iterations() != s.iteration_count {
                        return Err(HolonError::invalid_state(
                            format!("total_iterations = {}", s.iteration_count),
                            format!("total_iterations = {}", terminated.total_iterations()),
                        ));
                    }
                    if terminated.total_tokens_consumed() != s.tokens_consumed {
                        return Err(HolonError::invalid_state(
                            format!("total_tokens_consumed = {}", s.tokens_consumed),
                            format!(
                                "total_tokens_consumed = {}",
                                terminated.total_tokens_consumed()
                            ),
                        ));
                    }
                    if terminated.total_time_consumed_ms() != s.time_consumed_ms {
                        return Err(HolonError::invalid_state(
                            format!("total_time_consumed_ms = {}", s.time_consumed_ms),
                            format!(
                                "total_time_consumed_ms = {}",
                                terminated.total_time_consumed_ms()
                            ),
                        ));
                    }

                    s.terminate(terminated.reason().clone());
                },
            }
        }

        Ok(state)
    }

    /// Checks if the given state should terminate based on current conditions.
    ///
    /// This method evaluates stop conditions in priority order:
    /// 1. Already terminated
    /// 2. Budget exhausted
    /// 3. Max iterations reached
    ///
    /// # Returns
    ///
    /// Returns `Some(TerminationReason)` if should terminate, `None` otherwise.
    #[must_use]
    pub fn check_termination(&self, state: &OrchestrationStateV1) -> Option<TerminationReason> {
        // Already terminated
        if let Some(reason) = state.termination_reason() {
            return Some(reason.clone());
        }

        // Budget exhaustion
        if state.remaining_tokens() == 0 {
            return Some(TerminationReason::budget_exhausted(
                "tokens",
                state.tokens_consumed(),
                state.initial_token_budget(),
            ));
        }

        if state.remaining_time_ms() == 0 {
            return Some(TerminationReason::budget_exhausted(
                "time",
                state.time_consumed_ms(),
                state.initial_time_budget_ms(),
            ));
        }

        // Max iterations
        if state.remaining_iterations() == 0 {
            return Some(TerminationReason::max_iterations_reached(
                state.iteration_count(),
            ));
        }

        None
    }
}

impl Default for OrchestrationDriver {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_termination_reason_pass() {
        let reason = TerminationReason::pass();
        assert!(reason.is_success());
        assert!(!reason.is_blocked());
        assert!(!reason.is_resource_limit());
        assert_eq!(reason.as_str(), "pass");
        assert_eq!(reason.to_string(), "pass");
    }

    #[test]
    fn test_termination_reason_blocked() {
        let reason = TerminationReason::blocked(BlockedReasonCode::ReviewerBlocked {
            reviewer_role: "security".to_string(),
            finding_summary: Some("unsafe code detected".to_string()),
        });
        assert!(!reason.is_success());
        assert!(reason.is_blocked());
        assert!(reason.to_string().contains("security"));
    }

    #[test]
    fn test_termination_reason_budget_exhausted() {
        let reason = TerminationReason::budget_exhausted("tokens", 10000, 10000);
        assert!(reason.is_resource_limit());
        assert!(reason.to_string().contains("10000"));
    }

    #[test]
    fn test_termination_reason_operator_stop() {
        let reason = TerminationReason::operator_stop("manual intervention");
        assert!(!reason.is_success());
        assert!(reason.to_string().contains("manual intervention"));

        let reason_with_id =
            TerminationReason::operator_stop_with_id("cancel", "admin@example.com");
        assert!(reason_with_id.to_string().contains("admin@example.com"));
    }

    #[test]
    fn test_termination_reason_max_iterations() {
        let reason = TerminationReason::max_iterations_reached(100);
        assert!(reason.is_resource_limit());
        assert!(reason.to_string().contains("100"));
    }

    #[test]
    fn test_termination_reason_error() {
        let reason = TerminationReason::error("fatal crash");
        assert!(reason.is_error());
        assert!(reason.to_string().contains("fatal crash"));
    }

    #[test]
    fn test_blocked_reason_code_display() {
        let code = BlockedReasonCode::ReviewerBlocked {
            reviewer_role: "quality".to_string(),
            finding_summary: None,
        };
        assert!(code.to_string().contains("quality"));

        let code = BlockedReasonCode::ChangeSetApplyFailed {
            error: "patch conflict".to_string(),
        };
        assert!(code.to_string().contains("patch conflict"));

        let code = BlockedReasonCode::MissingDependency {
            dependency: "libfoo".to_string(),
        };
        assert!(code.to_string().contains("libfoo"));
    }

    #[test]
    fn test_orchestration_config_default() {
        let config = OrchestrationConfig::default();
        assert_eq!(config.max_iterations, MAX_ITERATIONS_LIMIT);
        assert!(config.token_budget > 0);
        assert!(config.time_budget_ms > 0);
        assert!(config.emit_events);
        assert!(config.fail_fast);
    }

    #[test]
    fn test_orchestration_config_builder() {
        let config = OrchestrationConfig::default()
            .with_max_iterations(50)
            .with_token_budget(1_000_000)
            .with_time_budget_ms(60_000)
            .with_emit_events(false)
            .with_fail_fast(false);

        assert_eq!(config.max_iterations, 50);
        assert_eq!(config.token_budget, 1_000_000);
        assert_eq!(config.time_budget_ms, 60_000);
        assert!(!config.emit_events);
        assert!(!config.fail_fast);
    }

    #[test]
    fn test_orchestration_config_validation() {
        // Valid config
        let config = OrchestrationConfig::default();
        assert!(config.validate().is_ok());

        // Invalid: zero iterations (handled by with_max_iterations panic)
        // Invalid: zero budget
        let config = OrchestrationConfig {
            token_budget: 0,
            ..OrchestrationConfig::default()
        };
        assert!(config.validate().is_err());

        let config = OrchestrationConfig {
            time_budget_ms: 0,
            ..OrchestrationConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_orchestration_state_creation() {
        let state =
            OrchestrationStateV1::try_new("work-123", "orch-001", 100, 1_000_000, 3_600_000)
                .unwrap();

        assert_eq!(state.work_id(), "work-123");
        assert_eq!(state.orchestration_id(), "orch-001");
        assert_eq!(state.iteration_count(), 0);
        assert_eq!(state.max_iterations(), 100);
        assert_eq!(state.remaining_iterations(), 100);
        assert_eq!(state.initial_token_budget(), 1_000_000);
        assert_eq!(state.remaining_tokens(), 1_000_000);
        assert!(!state.is_terminated());
    }

    #[test]
    fn test_orchestration_state_validation() {
        // Invalid work_id
        let result = OrchestrationStateV1::try_new("", "orch-001", 100, 1000, 1000);
        assert!(result.is_err());

        // Invalid orchestration_id
        let result = OrchestrationStateV1::try_new("work-123", "", 100, 1000, 1000);
        assert!(result.is_err());

        // Invalid max_iterations (0)
        let result = OrchestrationStateV1::try_new("work-123", "orch-001", 0, 1000, 1000);
        assert!(result.is_err());

        // Invalid max_iterations (> 100)
        let result = OrchestrationStateV1::try_new("work-123", "orch-001", 101, 1000, 1000);
        assert!(result.is_err());

        // Invalid budget (0)
        let result = OrchestrationStateV1::try_new("work-123", "orch-001", 100, 0, 1000);
        assert!(result.is_err());
    }

    #[test]
    fn test_orchestration_state_record_iteration() {
        let mut state = OrchestrationStateV1::new("work-123", "orch-001", 10, 10_000, 100_000);

        let changeset_hash = [1u8; 32];
        let receipt_hash = [2u8; 32];

        // First iteration
        let result = state.record_iteration(
            100,
            1000,
            1_000_000_000,
            Some(changeset_hash),
            Some(receipt_hash),
        );

        assert!(result.is_none()); // Should not terminate
        assert_eq!(state.iteration_count(), 1);
        assert_eq!(state.tokens_consumed(), 100);
        assert_eq!(state.time_consumed_ms(), 1000);
        assert_eq!(state.last_changeset_hash(), Some(&changeset_hash));
        assert_eq!(state.last_receipt_hash(), Some(&receipt_hash));
    }

    #[test]
    fn test_orchestration_state_budget_exhaustion() {
        let mut state = OrchestrationStateV1::new("work-123", "orch-001", 100, 1000, 100_000);

        // Exhaust token budget
        let result = state.record_iteration(1000, 100, 1_000_000_000, None, None);

        assert!(result.is_some());
        match result.unwrap() {
            TerminationReason::BudgetExhausted { resource, .. } => {
                assert_eq!(resource, "tokens");
            },
            _ => panic!("Expected BudgetExhausted"),
        }
    }

    #[test]
    fn test_orchestration_state_max_iterations() {
        let mut state = OrchestrationStateV1::new("work-123", "orch-001", 3, 1_000_000, 1_000_000);

        // Run 3 iterations
        for i in 1..=3 {
            let result = state.record_iteration(100, 100, i * 1_000_000_000, None, None);
            if i < 3 {
                assert!(result.is_none());
            } else {
                assert!(matches!(
                    result,
                    Some(TerminationReason::MaxIterationsReached { .. })
                ));
            }
        }

        assert_eq!(state.iteration_count(), 3);
        assert_eq!(state.remaining_iterations(), 0);
    }

    #[test]
    fn test_orchestration_state_terminate() {
        let mut state =
            OrchestrationStateV1::new("work-123", "orch-001", 100, 1_000_000, 1_000_000);

        // First termination succeeds
        assert!(state.terminate(TerminationReason::pass()));
        assert!(state.is_terminated());
        assert!(state.is_success());

        // Second termination fails
        assert!(!state.terminate(TerminationReason::error("late error")));
        // Original reason preserved
        assert!(state.is_success());
    }

    #[test]
    fn test_orchestration_state_as_budget() {
        let state = OrchestrationStateV1::new("work-123", "orch-001", 50, 1_000_000, 3_600_000);

        let budget = state.as_budget();
        assert_eq!(budget.remaining_episodes(), 50);
        assert_eq!(budget.remaining_tokens(), 1_000_000);
        assert_eq!(budget.remaining_duration_ms(), 3_600_000);
    }

    #[test]
    fn test_orchestration_driver_create_state() {
        let driver = OrchestrationDriver::with_defaults();
        let state = driver.create_state("work-123", "orch-001").unwrap();

        assert_eq!(state.work_id(), "work-123");
        assert_eq!(state.max_iterations(), MAX_ITERATIONS_LIMIT);
    }

    #[test]
    fn test_orchestration_driver_check_termination() {
        let driver = OrchestrationDriver::with_defaults();
        let mut state = OrchestrationStateV1::new("work-123", "orch-001", 2, 1000, 1000);

        // Not terminated initially
        assert!(driver.check_termination(&state).is_none());

        // After reaching max iterations
        state.record_iteration(100, 100, 1_000_000_000, None, None);
        assert!(driver.check_termination(&state).is_none());

        state.record_iteration(100, 100, 2_000_000_000, None, None);
        let reason = driver.check_termination(&state);
        assert!(matches!(
            reason,
            Some(TerminationReason::MaxIterationsReached { .. })
        ));
    }

    #[test]
    fn test_termination_reason_serialization() {
        let reason = TerminationReason::blocked(BlockedReasonCode::ReviewerBlocked {
            reviewer_role: "security".to_string(),
            finding_summary: Some("issue found".to_string()),
        });

        let json = serde_json::to_string(&reason).unwrap();
        let deserialized: TerminationReason = serde_json::from_str(&json).unwrap();

        assert_eq!(reason, deserialized);
    }

    #[test]
    fn test_orchestration_state_serialization() {
        let state = OrchestrationStateV1::new("work-123", "orch-001", 50, 1_000_000, 3_600_000);

        let json = serde_json::to_string(&state).unwrap();
        let deserialized: OrchestrationStateV1 = serde_json::from_str(&json).unwrap();

        assert_eq!(state, deserialized);
    }

    /// Test that state can run >= 20 iterations without human interaction.
    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn test_twenty_plus_iterations() {
        let mut state =
            OrchestrationStateV1::new("work-123", "orch-001", 100, 10_000_000, 100_000_000);

        // Run 25 iterations
        for i in 1..=25_u64 {
            let result =
                state.record_iteration(1000, 1000, i * 1_000_000_000, Some([i as u8; 32]), None);
            assert!(result.is_none(), "Should not terminate at iteration {i}");
        }

        assert_eq!(state.iteration_count(), 25);
        assert!(!state.is_terminated());
    }

    /// SECURITY TEST: Verify state rejects unknown fields.
    #[test]
    fn test_orchestration_state_rejects_unknown_fields() {
        let json = r#"{
            "work_id": "work-123",
            "orchestration_id": "orch-001",
            "iteration_count": 0,
            "max_iterations": 100,
            "initial_token_budget": 1000000,
            "tokens_consumed": 0,
            "initial_time_budget_ms": 3600000,
            "time_consumed_ms": 0,
            "started_at_ns": 0,
            "last_iteration_at_ns": null,
            "termination_reason": null,
            "malicious_field": "should_be_rejected"
        }"#;

        let result: Result<OrchestrationStateV1, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    /// SECURITY TEST: Verify config rejects unknown fields.
    #[test]
    fn test_orchestration_config_rejects_unknown_fields() {
        let json = r#"{
            "max_iterations": 100,
            "token_budget": 1000000,
            "time_budget_ms": 3600000,
            "emit_events": true,
            "fail_fast": true,
            "malicious_field": "should_be_rejected"
        }"#;

        let result: Result<OrchestrationConfig, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }
}
