//! Coordination controller for autonomous work loop execution.
//!
//! This module implements [`CoordinationController`] which provides the state
//! machine and event generation logic for serial execution of work items with
//! budget enforcement and circuit breaker protection.
//!
//! # Architecture
//!
//! The controller provides building blocks for an execution loop. The caller is
//! responsible for integrating with the ledger, session spawning, and async
//! orchestration. A typical execution loop follows this pattern:
//!
//! ```text
//! Caller's run_loop:
//!     |
//!     +-- controller.start() --> emit coordination.started
//!     |
//!     +-- loop:
//!     |       |
//!     |       +-- check controller.check_stop_condition()
//!     |       |       --> if Some(stop), break
//!     |       |
//!     |       +-- controller.check_work_freshness(work_id, seq_id, is_claimable)
//!     |       |       --> if not eligible, controller.skip_work_item()
//!     |       |
//!     |       +-- controller.prepare_session_spawn(work_id, ...) --> session_id, binding_event
//!     |       |       --> caller writes binding_event to ledger
//!     |       |       --> caller spawns holon session with session_id
//!     |       |
//!     |       +-- caller observes session termination
//!     |       |       --> poll SessionReducer until terminal
//!     |       |
//!     |       +-- controller.record_session_termination(...) --> unbound_event
//!     |               --> caller writes unbound_event to ledger
//!     |
//!     +-- controller.complete(stop_condition) or controller.abort(reason)
//!             --> caller writes completed/aborted event to ledger
//! ```
//!
//! # Key Design Decisions
//!
//! - **Serial execution (AD-COORD-002)**: One session at a time. The controller
//!   tracks state to ensure sessions are processed sequentially.
//!
//! - **Session ID generation (AD-COORD-007)**: Session ID is generated BEFORE
//!   the binding event via `prepare_session_spawn()`, ensuring the UUID in the
//!   binding matches the session the caller will spawn.
//!
//! - **Binding bracket (AD-COORD-003)**: `prepare_session_spawn()` generates
//!   `session_bound` BEFORE the caller spawns the session.
//!   `record_session_termination()` generates `session_unbound` AFTER the
//!   session terminates.
//!
//! - **Work freshness (AD-COORD-006)**: `check_work_freshness()` validates work
//!   state at a known ledger sequence. The caller should call this before
//!   spawn.
//!
//! # Example
//!
//! ```rust,ignore
//! use apm2_core::coordination::{
//!     CoordinationConfig, CoordinationController, CoordinationBudget,
//! };
//!
//! // Create configuration
//! let config = CoordinationConfig::new(
//!     vec!["work-1".to_string(), "work-2".to_string()],
//!     CoordinationBudget::new(10, 300_000, Some(100_000)).unwrap(),
//!     3, // max attempts per work
//! ).unwrap();
//!
//! // Create controller
//! let mut controller = CoordinationController::new(config);
//!
//! // Start coordination
//! let coordination_id = controller.start(timestamp_ns)?;
//!
//! // Execution loop (caller implements async orchestration)
//! loop {
//!     if let Some(stop) = controller.check_stop_condition() {
//!         controller.complete(stop, timestamp_ns)?;
//!         break;
//!     }
//!
//!     let work_id = controller.current_work_id().unwrap();
//!     let freshness = controller.check_work_freshness(work_id, seq_id, is_claimable);
//!
//!     if !freshness.is_eligible {
//!         controller.skip_work_item(work_id);
//!         continue;
//!     }
//!
//!     let spawn_result = controller.prepare_session_spawn(work_id, seq_id, timestamp_ns)?;
//!     // ... write binding_event to ledger ...
//!     // ... spawn session with spawn_result.session_id ...
//!     // ... observe session termination ...
//!
//!     controller.record_session_termination(&spawn_result.session_id, work_id, outcome, tokens, timestamp_ns)?;
//!     // ... write unbound_event to ledger ...
//! }
//! ```
//!
//! # References
//!
//! - TCK-00150: Implement `CoordinationController` serial execution loop
//! - RFC-0012: Agent Coordination Layer for Autonomous Work Loop Execution
//! - AD-COORD-002: Serial execution, one session at a time
//! - AD-COORD-003: Binding events bracket session lifecycle
//! - AD-COORD-006: Work freshness validation
//! - AD-COORD-007: Session ID generation before binding event

use std::time::Instant;

use super::error::{ControllerError, ControllerResult};
use super::events::{
    BLAKE3_HASH_SIZE, CoordinationAborted, CoordinationCompleted, CoordinationEvent,
    CoordinationSessionBound, CoordinationSessionUnbound, CoordinationStarted,
};
use super::state::{
    AbortReason, BudgetUsage, CoordinationBudget, CoordinationStatus, MAX_WORK_QUEUE_SIZE,
    SessionOutcome, StopCondition, WorkItemOutcome,
};

/// Maximum number of attempts per work item (default).
pub const DEFAULT_MAX_ATTEMPTS_PER_WORK: u32 = 3;

/// Circuit breaker threshold: abort after this many consecutive failures.
///
/// Per AD-COORD-005: Abort after 3 consecutive session failures.
pub const CIRCUIT_BREAKER_THRESHOLD: u32 = 3;

/// Configuration for a coordination run.
///
/// Specifies the work queue, budget constraints, and retry settings.
#[derive(Debug, Clone)]
pub struct CoordinationConfig {
    /// Work item IDs to process in order.
    ///
    /// Limited to [`MAX_WORK_QUEUE_SIZE`] items.
    pub work_ids: Vec<String>,

    /// Budget constraints (episodes, duration, tokens).
    pub budget: CoordinationBudget,

    /// Maximum attempts per work item before marking as failed.
    pub max_attempts_per_work: u32,

    /// Maximum work queue size validation.
    ///
    /// Per AD-COORD-008: Reject if `work_ids.len() > max_work_queue_size`.
    pub max_work_queue_size: usize,
}

impl CoordinationConfig {
    /// Creates a new coordination configuration.
    ///
    /// # Arguments
    ///
    /// * `work_ids` - Work item IDs to process
    /// * `budget` - Budget constraints
    /// * `max_attempts_per_work` - Maximum retry attempts per work item
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::EmptyWorkQueue`] if `work_ids` is empty.
    /// Returns [`ControllerError::WorkQueueSizeExceeded`] if queue exceeds
    /// limit.
    pub fn new(
        work_ids: Vec<String>,
        budget: CoordinationBudget,
        max_attempts_per_work: u32,
    ) -> ControllerResult<Self> {
        Self::with_max_queue_size(work_ids, budget, max_attempts_per_work, MAX_WORK_QUEUE_SIZE)
    }

    /// Creates a new coordination configuration with custom queue size limit.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::EmptyWorkQueue`] if `work_ids` is empty.
    /// Returns [`ControllerError::WorkQueueSizeExceeded`] if queue exceeds
    /// limit.
    pub fn with_max_queue_size(
        work_ids: Vec<String>,
        budget: CoordinationBudget,
        max_attempts_per_work: u32,
        max_work_queue_size: usize,
    ) -> ControllerResult<Self> {
        if work_ids.is_empty() {
            return Err(ControllerError::EmptyWorkQueue);
        }

        if work_ids.len() > max_work_queue_size {
            return Err(ControllerError::WorkQueueSizeExceeded {
                actual: work_ids.len(),
                max: max_work_queue_size,
            });
        }

        Ok(Self {
            work_ids,
            budget,
            max_attempts_per_work,
            max_work_queue_size,
        })
    }
}

/// Tracking state for an individual work item during coordination.
#[derive(Debug, Clone)]
pub struct WorkItemState {
    /// Work item ID.
    pub work_id: String,

    /// Number of attempts made.
    pub attempt_count: u32,

    /// Session IDs used for this work.
    pub session_ids: Vec<String>,

    /// Final outcome (if processing is complete).
    pub final_outcome: Option<WorkItemOutcome>,
}

impl WorkItemState {
    /// Creates a new work item tracking state.
    #[must_use]
    pub const fn new(work_id: String) -> Self {
        Self {
            work_id,
            attempt_count: 0,
            session_ids: Vec::new(),
            final_outcome: None,
        }
    }
}

/// Result of a freshness check for a work item.
#[derive(Debug, Clone)]
pub struct FreshnessCheck {
    /// The work ID that was checked.
    pub work_id: String,

    /// The ledger sequence ID at which freshness was verified.
    pub seq_id: u64,

    /// Whether the work item is eligible for processing.
    pub is_eligible: bool,

    /// Reason if not eligible.
    pub skip_reason: Option<String>,
}

/// Result of spawning a session for a work item.
#[derive(Debug, Clone)]
pub struct SpawnResult {
    /// The session ID that was generated.
    pub session_id: String,

    /// The work ID being processed.
    pub work_id: String,

    /// The attempt number (1-indexed).
    pub attempt_number: u32,

    /// The coordination event that was emitted.
    pub binding_event: CoordinationSessionBound,
}

/// Result of observing a session termination.
#[derive(Debug, Clone)]
pub struct TerminationResult {
    /// The session ID that terminated.
    pub session_id: String,

    /// The work ID that was processed.
    pub work_id: String,

    /// The outcome of the session.
    pub outcome: SessionOutcome,

    /// Tokens consumed by the session.
    pub tokens_consumed: u64,
}

/// Coordination controller for autonomous work loop execution.
///
/// The controller manages the serial execution of work items:
/// 1. Validates work freshness before spawning sessions
/// 2. Generates session IDs and emits binding events
/// 3. Observes session termination and handles outcomes
/// 4. Enforces budget constraints and circuit breaker
///
/// # Thread Safety
///
/// The controller is designed to be used from a single async task.
/// State is protected internally and event emission is serialized.
#[derive(Debug)]
pub struct CoordinationController {
    /// Coordination ID (generated on start).
    coordination_id: Option<String>,

    /// Configuration for this coordination.
    config: CoordinationConfig,

    /// Current work index (0-indexed).
    work_index: usize,

    /// Per-work tracking state.
    work_tracking: Vec<WorkItemState>,

    /// Active session ID (enforces serial execution).
    ///
    /// Set in `prepare_session_spawn`, cleared in `record_session_termination`.
    /// Having a value here means a session is currently active and no new
    /// session can be spawned (serial execution invariant).
    active_session_id: Option<String>,

    /// Budget usage tracking.
    budget_usage: BudgetUsage,

    /// Consecutive session failures (for circuit breaker).
    consecutive_failures: u32,

    /// Total sessions spawned.
    total_sessions: u32,

    /// Successful sessions count.
    successful_sessions: u32,

    /// Failed sessions count.
    failed_sessions: u32,

    /// Start time for duration tracking.
    started_at: Option<Instant>,

    /// Current status.
    status: CoordinationStatus,

    /// Emitted events (for testing and verification).
    emitted_events: Vec<CoordinationEvent>,
}

impl CoordinationController {
    /// Creates a new coordination controller.
    ///
    /// # Arguments
    ///
    /// * `config` - Coordination configuration
    #[must_use]
    pub fn new(config: CoordinationConfig) -> Self {
        let work_tracking = config
            .work_ids
            .iter()
            .map(|id| WorkItemState::new(id.clone()))
            .collect();

        Self {
            coordination_id: None,
            config,
            work_index: 0,
            work_tracking,
            active_session_id: None,
            budget_usage: BudgetUsage::new(),
            consecutive_failures: 0,
            total_sessions: 0,
            successful_sessions: 0,
            failed_sessions: 0,
            started_at: None,
            status: CoordinationStatus::Initializing,
            emitted_events: Vec::new(),
        }
    }

    /// Returns the coordination ID, if started.
    #[must_use]
    pub fn coordination_id(&self) -> Option<&str> {
        self.coordination_id.as_deref()
    }

    /// Returns the current status.
    #[must_use]
    pub const fn status(&self) -> &CoordinationStatus {
        &self.status
    }

    /// Returns `true` if the coordination is in a terminal state.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        self.status.is_terminal()
    }

    /// Returns the current work index.
    #[must_use]
    pub const fn work_index(&self) -> usize {
        self.work_index
    }

    /// Returns the budget usage.
    #[must_use]
    pub const fn budget_usage(&self) -> &BudgetUsage {
        &self.budget_usage
    }

    /// Returns the consecutive failure count.
    #[must_use]
    pub const fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }

    /// Returns the emitted events (for testing).
    #[must_use]
    pub fn emitted_events(&self) -> &[CoordinationEvent] {
        &self.emitted_events
    }

    /// Returns the configuration.
    #[must_use]
    pub const fn config(&self) -> &CoordinationConfig {
        &self.config
    }

    /// Returns the current work ID being processed, if any.
    #[must_use]
    pub fn current_work_id(&self) -> Option<&str> {
        self.config
            .work_ids
            .get(self.work_index)
            .map(String::as_str)
    }

    /// Returns `true` if all work items have been processed.
    #[must_use]
    pub fn is_work_queue_exhausted(&self) -> bool {
        self.work_index >= self.config.work_ids.len()
    }

    // =========================================================================
    // Lifecycle Methods
    // =========================================================================

    /// Starts the coordination and emits the started event.
    ///
    /// Generates a coordination ID (UUID v4) and emits `coordination.started`.
    ///
    /// # Returns
    ///
    /// The generated coordination ID.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::CoordinationAlreadyExists`] if already
    /// started.
    pub fn start(&mut self, timestamp_ns: u64) -> ControllerResult<String> {
        if self.coordination_id.is_some() {
            return Err(ControllerError::CoordinationAlreadyExists {
                coordination_id: self.coordination_id.clone().unwrap_or_default(),
            });
        }

        // Generate coordination ID (UUID v4 format)
        let coordination_id = generate_uuid();

        // Record start time
        self.started_at = Some(Instant::now());
        self.coordination_id = Some(coordination_id.clone());
        self.status = CoordinationStatus::Running;

        // Build and emit the started event
        let started_event = CoordinationStarted::new(
            coordination_id.clone(),
            self.config.work_ids.clone(),
            self.config.budget.clone(),
            self.config.max_attempts_per_work,
            timestamp_ns,
        )
        .map_err(|e| ControllerError::Internal {
            message: format!("failed to create started event: {e}"),
        })?;

        self.emitted_events
            .push(CoordinationEvent::Started(started_event));

        Ok(coordination_id)
    }

    /// Checks the work freshness for the current work item.
    ///
    /// Per AD-COORD-006: Work state is checked at a known ledger sequence.
    /// If the work is not eligible, it should be skipped.
    ///
    /// # Arguments
    ///
    /// * `seq_id` - Current ledger sequence ID
    /// * `is_claimable` - Whether the work item is claimable
    ///
    /// # Returns
    ///
    /// A [`FreshnessCheck`] result indicating eligibility.
    #[must_use]
    pub fn check_work_freshness(
        &self,
        work_id: &str,
        seq_id: u64,
        is_claimable: bool,
    ) -> FreshnessCheck {
        if is_claimable {
            FreshnessCheck {
                work_id: work_id.to_string(),
                seq_id,
                is_eligible: true,
                skip_reason: None,
            }
        } else {
            FreshnessCheck {
                work_id: work_id.to_string(),
                seq_id,
                is_eligible: false,
                skip_reason: Some("work is not claimable".to_string()),
            }
        }
    }

    /// Prepares to spawn a session for the current work item.
    ///
    /// Per AD-COORD-007: Session ID is generated BEFORE the binding event.
    /// Per AD-COORD-003: `session_bound` is emitted BEFORE `session.started`.
    ///
    /// This method:
    /// 1. Checks that no session is currently active (serial execution)
    /// 2. Checks that no stop condition is met
    /// 3. Validates the `work_id` matches the current work index
    /// 4. Generates a new session ID (UUID v4)
    /// 5. Creates and stores the binding event
    /// 6. Updates attempt tracking
    ///
    /// The caller is responsible for actually spawning the session after
    /// calling this method, ensuring the bracket ordering is correct.
    ///
    /// # Arguments
    ///
    /// * `work_id` - The work item ID (must match current work index)
    /// * `freshness_seq_id` - The sequence ID at which freshness was verified
    /// * `timestamp_ns` - Current timestamp in nanoseconds
    ///
    /// # Returns
    ///
    /// A [`SpawnResult`] containing the session ID and binding event.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Coordination is not running
    /// - A session is already active (serial execution violation)
    /// - A stop condition is met
    /// - The `work_id` doesn't match the current work index
    pub fn prepare_session_spawn(
        &mut self,
        work_id: &str,
        freshness_seq_id: u64,
        timestamp_ns: u64,
    ) -> ControllerResult<SpawnResult> {
        // Verify coordination is running
        if !matches!(self.status, CoordinationStatus::Running) {
            return Err(ControllerError::CoordinationTerminal {
                coordination_id: self.coordination_id.clone().unwrap_or_default(),
            });
        }

        // Enforce serial execution: fail if a session is already active
        if let Some(ref active_id) = self.active_session_id {
            return Err(ControllerError::SessionAlreadyBound {
                session_id: active_id.clone(),
            });
        }

        // Check stop conditions before spawning (fail-closed)
        if let Some(stop_condition) = self.check_stop_condition() {
            return Err(ControllerError::Internal {
                message: format!("stop condition met before spawn: {stop_condition:?}"),
            });
        }

        let coordination_id =
            self.coordination_id
                .clone()
                .ok_or_else(|| ControllerError::Internal {
                    message: "coordination not started".to_string(),
                })?;

        // Verify work_id matches current work index (prevents duplicate ID bugs)
        let expected_work_id =
            self.config
                .work_ids
                .get(self.work_index)
                .ok_or_else(|| ControllerError::Internal {
                    message: "work index out of bounds".to_string(),
                })?;
        if work_id != expected_work_id {
            return Err(ControllerError::WorkNotFound {
                work_id: work_id.to_string(),
            });
        }

        // Access tracking by index (handles duplicate work IDs correctly)
        let tracking = &mut self.work_tracking[self.work_index];

        // Generate session ID BEFORE binding event (AD-COORD-007)
        let session_id = generate_uuid();
        let attempt_number = tracking.attempt_count + 1;

        // Update tracking
        tracking.attempt_count = attempt_number;
        tracking.session_ids.push(session_id.clone());

        // Create binding event (AD-COORD-003: emitted BEFORE session.started)
        let binding_event = CoordinationSessionBound::new(
            coordination_id,
            session_id.clone(),
            work_id.to_string(),
            attempt_number,
            freshness_seq_id,
            timestamp_ns,
        );

        // Store the event
        self.emitted_events
            .push(CoordinationEvent::SessionBound(binding_event.clone()));

        // Increment total sessions
        self.total_sessions += 1;

        // Set active session (serial execution enforcement)
        self.active_session_id = Some(session_id.clone());

        Ok(SpawnResult {
            session_id,
            work_id: work_id.to_string(),
            attempt_number,
            binding_event,
        })
    }

    /// Records the termination of a session and emits the unbound event.
    ///
    /// Per AD-COORD-003: `session_unbound` is emitted AFTER
    /// `session.terminated`.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The terminated session ID
    /// * `work_id` - The work item that was processed
    /// * `outcome` - The session outcome (Success or Failure)
    /// * `tokens_consumed` - Tokens consumed by the session
    /// * `timestamp_ns` - Current timestamp in nanoseconds
    ///
    /// # Returns
    ///
    /// A [`TerminationResult`] with the outcome details.
    ///
    /// # Errors
    ///
    /// Returns an error if the coordination is not running or `session_id`
    /// doesn't match the active session.
    pub fn record_session_termination(
        &mut self,
        session_id: &str,
        work_id: &str,
        outcome: SessionOutcome,
        tokens_consumed: u64,
        timestamp_ns: u64,
    ) -> ControllerResult<TerminationResult> {
        let coordination_id =
            self.coordination_id
                .clone()
                .ok_or_else(|| ControllerError::Internal {
                    message: "coordination not started".to_string(),
                })?;

        // Verify session_id matches active session (serial execution enforcement)
        match &self.active_session_id {
            Some(active_id) if active_id != session_id => {
                return Err(ControllerError::Internal {
                    message: format!("session_id mismatch: expected {active_id}, got {session_id}"),
                });
            },
            None => {
                return Err(ControllerError::Internal {
                    message: "no active session to terminate".to_string(),
                });
            },
            _ => {},
        }

        // Clear active session (serial execution: allow next spawn)
        self.active_session_id = None;

        // Update budget usage
        self.budget_usage.consumed_episodes = self.budget_usage.consumed_episodes.saturating_add(1);
        self.budget_usage.consumed_tokens = self
            .budget_usage
            .consumed_tokens
            .saturating_add(tokens_consumed);

        // Update elapsed time
        // Note: truncation is safe - u64 can hold ~584 million years in milliseconds
        if let Some(started_at) = self.started_at {
            #[allow(clippy::cast_possible_truncation)]
            {
                self.budget_usage.elapsed_ms = started_at.elapsed().as_millis() as u64;
            }
        }

        // Access tracking by index (handles duplicate work IDs correctly)
        // Note: work_index hasn't been incremented yet, so it points to current work
        let tracking = &mut self.work_tracking[self.work_index];

        // Handle outcome
        match outcome {
            SessionOutcome::Success => {
                self.consecutive_failures = 0;
                self.successful_sessions += 1;

                // Mark work item as succeeded
                tracking.final_outcome = Some(WorkItemOutcome::Succeeded);

                // Advance to next work item
                self.work_index += 1;
            },
            SessionOutcome::Failure => {
                self.consecutive_failures += 1;
                self.failed_sessions += 1;

                // Check if retries are exhausted
                if tracking.attempt_count >= self.config.max_attempts_per_work {
                    // Mark as failed and advance
                    tracking.final_outcome = Some(WorkItemOutcome::Failed);
                    self.work_index += 1;
                }
                // Otherwise, stay on same work item for retry
            },
        }

        // Create unbound event (AD-COORD-003: emitted AFTER session.terminated)
        let unbound_event = CoordinationSessionUnbound::new(
            coordination_id,
            session_id.to_string(),
            work_id.to_string(),
            outcome,
            tokens_consumed,
            timestamp_ns,
        );

        self.emitted_events
            .push(CoordinationEvent::SessionUnbound(unbound_event));

        Ok(TerminationResult {
            session_id: session_id.to_string(),
            work_id: work_id.to_string(),
            outcome,
            tokens_consumed,
        })
    }

    /// Marks a work item as skipped (e.g., due to freshness violation).
    ///
    /// # Arguments
    ///
    /// * `work_id` - The work item to skip
    pub fn skip_work_item(&mut self, work_id: &str) {
        if let Some(tracking) = self.work_tracking.iter_mut().find(|t| t.work_id == work_id) {
            tracking.final_outcome = Some(WorkItemOutcome::Skipped);
        }
        self.work_index += 1;
    }

    /// Checks if a stop condition is met.
    ///
    /// Per AD-COORD-013 priority ordering:
    /// 1. `CircuitBreakerTriggered` (highest)
    /// 2. `BudgetExhausted(Duration)`
    /// 3. `BudgetExhausted(Tokens)`
    /// 4. `BudgetExhausted(Episodes)`
    /// 5. `MaxAttemptsExceeded`
    /// 6. `WorkCompleted` (lowest)
    ///
    /// # Returns
    ///
    /// `Some(StopCondition)` if a stop condition is met, `None` otherwise.
    #[must_use]
    pub fn check_stop_condition(&self) -> Option<StopCondition> {
        // Check circuit breaker (highest priority)
        if self.consecutive_failures >= CIRCUIT_BREAKER_THRESHOLD {
            return Some(StopCondition::CircuitBreakerTriggered {
                consecutive_failures: self.consecutive_failures,
            });
        }

        // Check duration budget
        if self.budget_usage.elapsed_ms >= self.config.budget.max_duration_ms {
            return Some(StopCondition::BudgetExhausted(
                super::state::BudgetType::Duration,
            ));
        }

        // Check token budget (if set)
        if let Some(max_tokens) = self.config.budget.max_tokens {
            if self.budget_usage.consumed_tokens >= max_tokens {
                return Some(StopCondition::BudgetExhausted(
                    super::state::BudgetType::Tokens,
                ));
            }
        }

        // Check episode budget
        if self.budget_usage.consumed_episodes >= self.config.budget.max_episodes {
            return Some(StopCondition::BudgetExhausted(
                super::state::BudgetType::Episodes,
            ));
        }

        // Check work completion
        if self.is_work_queue_exhausted() {
            return Some(StopCondition::WorkCompleted);
        }

        None
    }

    /// Completes the coordination with the given stop condition.
    ///
    /// Emits `coordination.completed` and transitions to terminal state.
    ///
    /// # Arguments
    ///
    /// * `stop_condition` - The stop condition that caused completion
    /// * `timestamp_ns` - Current timestamp in nanoseconds
    ///
    /// # Returns
    ///
    /// The completed event that was emitted.
    ///
    /// # Errors
    ///
    /// Returns an error if already in terminal state.
    pub fn complete(
        &mut self,
        stop_condition: StopCondition,
        timestamp_ns: u64,
    ) -> ControllerResult<CoordinationCompleted> {
        if self.status.is_terminal() {
            return Err(ControllerError::CoordinationTerminal {
                coordination_id: self.coordination_id.clone().unwrap_or_default(),
            });
        }

        let coordination_id =
            self.coordination_id
                .clone()
                .ok_or_else(|| ControllerError::Internal {
                    message: "coordination not started".to_string(),
                })?;

        // Update elapsed time
        // Note: truncation is safe - u64 can hold ~584 million years in milliseconds
        if let Some(started_at) = self.started_at {
            #[allow(clippy::cast_possible_truncation)]
            {
                self.budget_usage.elapsed_ms = started_at.elapsed().as_millis() as u64;
            }
        }

        // Compute receipt hash (placeholder - actual hash computation is in TCK-00154)
        let receipt_hash = [0u8; BLAKE3_HASH_SIZE];

        let completed_event = CoordinationCompleted::new(
            coordination_id,
            stop_condition.clone(),
            self.budget_usage.clone(),
            self.total_sessions,
            self.successful_sessions,
            self.failed_sessions,
            receipt_hash,
            timestamp_ns,
        );

        self.status = CoordinationStatus::Completed(stop_condition);
        self.emitted_events
            .push(CoordinationEvent::Completed(completed_event.clone()));

        Ok(completed_event)
    }

    /// Aborts the coordination with the given reason.
    ///
    /// Emits `coordination.aborted` and transitions to terminal state.
    ///
    /// # Arguments
    ///
    /// * `reason` - The reason for abortion
    /// * `timestamp_ns` - Current timestamp in nanoseconds
    ///
    /// # Returns
    ///
    /// The aborted event that was emitted.
    ///
    /// # Errors
    ///
    /// Returns an error if already in terminal state.
    pub fn abort(
        &mut self,
        reason: AbortReason,
        timestamp_ns: u64,
    ) -> ControllerResult<CoordinationAborted> {
        if self.status.is_terminal() {
            return Err(ControllerError::CoordinationTerminal {
                coordination_id: self.coordination_id.clone().unwrap_or_default(),
            });
        }

        let coordination_id =
            self.coordination_id
                .clone()
                .ok_or_else(|| ControllerError::Internal {
                    message: "coordination not started".to_string(),
                })?;

        // Update elapsed time
        // Note: truncation is safe - u64 can hold ~584 million years in milliseconds
        if let Some(started_at) = self.started_at {
            #[allow(clippy::cast_possible_truncation)]
            {
                self.budget_usage.elapsed_ms = started_at.elapsed().as_millis() as u64;
            }
        }

        let aborted_event = CoordinationAborted::new(
            coordination_id,
            reason.clone(),
            self.budget_usage.clone(),
            timestamp_ns,
        );

        self.status = CoordinationStatus::Aborted(reason);
        self.emitted_events
            .push(CoordinationEvent::Aborted(aborted_event.clone()));

        Ok(aborted_event)
    }
}

/// Generates a cryptographically secure UUID v4 string.
///
/// Uses the `uuid` crate with random number generation for secure session IDs.
/// Format: `xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx`
fn generate_uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_budget() -> CoordinationBudget {
        CoordinationBudget::new(10, 60_000, Some(100_000)).unwrap()
    }

    fn test_config(work_ids: Vec<String>) -> CoordinationConfig {
        CoordinationConfig::new(work_ids, test_budget(), 3).unwrap()
    }

    // =========================================================================
    // Configuration Tests
    // =========================================================================

    #[test]
    fn tck_00150_config_valid() {
        let config = test_config(vec!["work-1".to_string(), "work-2".to_string()]);
        assert_eq!(config.work_ids.len(), 2);
        assert_eq!(config.max_attempts_per_work, 3);
    }

    #[test]
    fn tck_00150_config_empty_work_queue() {
        let result = CoordinationConfig::new(vec![], test_budget(), 3);
        assert!(matches!(result, Err(ControllerError::EmptyWorkQueue)));
    }

    #[test]
    fn tck_00150_config_queue_size_exceeded() {
        let work_ids: Vec<String> = (0..=MAX_WORK_QUEUE_SIZE)
            .map(|i| format!("work-{i}"))
            .collect();
        let result = CoordinationConfig::new(work_ids, test_budget(), 3);
        assert!(matches!(
            result,
            Err(ControllerError::WorkQueueSizeExceeded { .. })
        ));
    }

    // =========================================================================
    // Controller Lifecycle Tests
    // =========================================================================

    #[test]
    fn tck_00150_controller_start() {
        let config = test_config(vec!["work-1".to_string()]);
        let mut controller = CoordinationController::new(config);

        let coord_id = controller.start(1_000_000_000).unwrap();

        assert!(controller.coordination_id().is_some());
        assert_eq!(controller.coordination_id().unwrap(), coord_id);
        assert!(matches!(controller.status(), CoordinationStatus::Running));
        assert_eq!(controller.emitted_events().len(), 1);

        // Verify started event
        let event = &controller.emitted_events()[0];
        assert!(matches!(event, CoordinationEvent::Started(_)));
    }

    #[test]
    fn tck_00150_controller_double_start() {
        let config = test_config(vec!["work-1".to_string()]);
        let mut controller = CoordinationController::new(config);

        controller.start(1_000_000_000).unwrap();
        let result = controller.start(2_000_000_000);

        assert!(matches!(
            result,
            Err(ControllerError::CoordinationAlreadyExists { .. })
        ));
    }

    // =========================================================================
    // Session Spawn Tests (AD-COORD-007: Session ID before binding)
    // =========================================================================

    #[test]
    fn tck_00150_session_id_generated_before_binding() {
        let config = test_config(vec!["work-1".to_string()]);
        let mut controller = CoordinationController::new(config);
        controller.start(1_000_000_000).unwrap();

        let result = controller
            .prepare_session_spawn("work-1", 100, 2_000_000_000)
            .unwrap();

        // Verify session ID is generated
        assert!(!result.session_id.is_empty());

        // Verify binding event contains the same session ID
        assert_eq!(result.binding_event.session_id, result.session_id);

        // Verify event was emitted
        assert_eq!(controller.emitted_events().len(), 2); // started + bound
        let bound_event = &controller.emitted_events()[1];
        if let CoordinationEvent::SessionBound(bound) = bound_event {
            assert_eq!(bound.session_id, result.session_id);
        } else {
            panic!("Expected SessionBound event");
        }
    }

    // =========================================================================
    // Binding Bracket Tests (AD-COORD-003)
    // =========================================================================

    #[test]
    fn tck_00150_binding_bracket_ordering() {
        let config = test_config(vec!["work-1".to_string()]);
        let mut controller = CoordinationController::new(config);
        controller.start(1_000_000_000).unwrap();

        // Prepare spawn (emits session_bound)
        let spawn_result = controller
            .prepare_session_spawn("work-1", 100, 2_000_000_000)
            .unwrap();

        // At this point, session_bound has been emitted but session.started has NOT
        // The caller would spawn the session here

        // Record termination (emits session_unbound AFTER session.terminated)
        controller
            .record_session_termination(
                &spawn_result.session_id,
                "work-1",
                SessionOutcome::Success,
                1000,
                3_000_000_000,
            )
            .unwrap();

        // Verify event order: started, session_bound, session_unbound
        let events = controller.emitted_events();
        assert_eq!(events.len(), 3);
        assert!(matches!(events[0], CoordinationEvent::Started(_)));
        assert!(matches!(events[1], CoordinationEvent::SessionBound(_)));
        assert!(matches!(events[2], CoordinationEvent::SessionUnbound(_)));
    }

    // =========================================================================
    // Work Freshness Tests (AD-COORD-006)
    // =========================================================================

    #[test]
    fn tck_00150_work_freshness_eligible() {
        let config = test_config(vec!["work-1".to_string()]);
        let controller = CoordinationController::new(config);

        let check = controller.check_work_freshness("work-1", 100, true);

        assert!(check.is_eligible);
        assert_eq!(check.seq_id, 100);
        assert!(check.skip_reason.is_none());
    }

    #[test]
    fn tck_00150_work_freshness_not_claimable() {
        let config = test_config(vec!["work-1".to_string()]);
        let controller = CoordinationController::new(config);

        let check = controller.check_work_freshness("work-1", 100, false);

        assert!(!check.is_eligible);
        assert!(check.skip_reason.is_some());
    }

    #[test]
    fn tck_00150_skip_stale_work() {
        let config = test_config(vec!["work-1".to_string(), "work-2".to_string()]);
        let mut controller = CoordinationController::new(config);
        controller.start(1_000_000_000).unwrap();

        // Skip work-1 due to freshness violation
        controller.skip_work_item("work-1");

        // Verify work index advanced
        assert_eq!(controller.work_index(), 1);
        assert_eq!(controller.current_work_id(), Some("work-2"));

        // Verify work-1 marked as skipped
        let tracking = &controller.work_tracking[0];
        assert_eq!(tracking.final_outcome, Some(WorkItemOutcome::Skipped));
    }

    // =========================================================================
    // Serial Execution Tests (AD-COORD-002)
    // =========================================================================

    #[test]
    fn tck_00150_serial_execution_consecutive_spawn_fails() {
        let config = test_config(vec!["work-1".to_string()]);
        let mut controller = CoordinationController::new(config);
        controller.start(1_000_000_000).unwrap();

        // First spawn succeeds
        let spawn1 = controller
            .prepare_session_spawn("work-1", 100, 2_000_000_000)
            .unwrap();

        // Second spawn before termination should fail
        let result = controller.prepare_session_spawn("work-1", 101, 3_000_000_000);
        assert!(matches!(
            result,
            Err(ControllerError::SessionAlreadyBound { .. })
        ));

        // Terminate first session
        controller
            .record_session_termination(
                &spawn1.session_id,
                "work-1",
                SessionOutcome::Failure,
                100,
                4_000_000_000,
            )
            .unwrap();

        // Now retry should succeed (max_attempts allows 3)
        let spawn2 = controller
            .prepare_session_spawn("work-1", 102, 5_000_000_000)
            .unwrap();

        // Different session ID
        assert_ne!(spawn1.session_id, spawn2.session_id);
    }

    #[test]
    fn tck_00150_serial_execution_duplicate_work_ids() {
        // Test with duplicate work IDs in queue
        let config = CoordinationConfig::new(
            vec!["A".to_string(), "B".to_string(), "A".to_string()],
            test_budget(),
            3,
        )
        .unwrap();
        let mut controller = CoordinationController::new(config);
        controller.start(1_000_000_000).unwrap();

        // Process first "A" (index 0)
        let spawn_a1 = controller
            .prepare_session_spawn("A", 100, 2_000_000_000)
            .unwrap();
        controller
            .record_session_termination(
                &spawn_a1.session_id,
                "A",
                SessionOutcome::Success,
                100,
                3_000_000_000,
            )
            .unwrap();

        // First "A" should be marked as Succeeded
        assert_eq!(
            controller.work_tracking[0].final_outcome,
            Some(WorkItemOutcome::Succeeded)
        );
        assert_eq!(controller.work_tracking[0].attempt_count, 1);

        // Process "B" (index 1)
        let spawn_b = controller
            .prepare_session_spawn("B", 200, 4_000_000_000)
            .unwrap();
        controller
            .record_session_termination(
                &spawn_b.session_id,
                "B",
                SessionOutcome::Success,
                200,
                5_000_000_000,
            )
            .unwrap();

        // Process second "A" (index 2)
        let spawn_a2 = controller
            .prepare_session_spawn("A", 300, 6_000_000_000)
            .unwrap();
        controller
            .record_session_termination(
                &spawn_a2.session_id,
                "A",
                SessionOutcome::Success,
                300,
                7_000_000_000,
            )
            .unwrap();

        // Second "A" should be tracked independently
        assert_eq!(
            controller.work_tracking[2].final_outcome,
            Some(WorkItemOutcome::Succeeded)
        );
        assert_eq!(controller.work_tracking[2].attempt_count, 1);

        // First "A" unchanged
        assert_eq!(controller.work_tracking[0].attempt_count, 1);
    }

    #[test]
    fn tck_00150_serial_execution_one_session_at_time() {
        let config = test_config(vec!["work-1".to_string(), "work-2".to_string()]);
        let mut controller = CoordinationController::new(config);
        controller.start(1_000_000_000).unwrap();

        // Process work-1
        let spawn1 = controller
            .prepare_session_spawn("work-1", 100, 2_000_000_000)
            .unwrap();

        // Before terminating, work_index should still be 0
        assert_eq!(controller.work_index(), 0);

        // Terminate work-1 session
        controller
            .record_session_termination(
                &spawn1.session_id,
                "work-1",
                SessionOutcome::Success,
                1000,
                3_000_000_000,
            )
            .unwrap();

        // Now work_index should advance to 1
        assert_eq!(controller.work_index(), 1);
        assert_eq!(controller.current_work_id(), Some("work-2"));

        // Process work-2
        let spawn2 = controller
            .prepare_session_spawn("work-2", 200, 4_000_000_000)
            .unwrap();

        // Different session ID
        assert_ne!(spawn1.session_id, spawn2.session_id);

        controller
            .record_session_termination(
                &spawn2.session_id,
                "work-2",
                SessionOutcome::Success,
                2000,
                5_000_000_000,
            )
            .unwrap();

        // Work queue exhausted
        assert!(controller.is_work_queue_exhausted());
        assert_eq!(controller.total_sessions, 2);
        assert_eq!(controller.successful_sessions, 2);
    }

    // =========================================================================
    // Stop Condition Tests
    // =========================================================================

    #[test]
    fn tck_00150_stop_condition_work_completed() {
        let config = test_config(vec!["work-1".to_string()]);
        let mut controller = CoordinationController::new(config);
        controller.start(1_000_000_000).unwrap();

        // Process work-1
        let spawn = controller
            .prepare_session_spawn("work-1", 100, 2_000_000_000)
            .unwrap();
        controller
            .record_session_termination(
                &spawn.session_id,
                "work-1",
                SessionOutcome::Success,
                1000,
                3_000_000_000,
            )
            .unwrap();

        let stop = controller.check_stop_condition();
        assert_eq!(stop, Some(StopCondition::WorkCompleted));
    }

    #[test]
    fn tck_00150_stop_condition_circuit_breaker() {
        let config = test_config(vec!["work-1".to_string()]);
        let mut controller = CoordinationController::new(config);
        controller.start(1_000_000_000).unwrap();

        // Simulate 3 consecutive failures
        for i in 0u64..3 {
            let spawn = controller
                .prepare_session_spawn("work-1", 100 + i, 2_000_000_000 + i * 1_000_000_000)
                .unwrap();
            controller
                .record_session_termination(
                    &spawn.session_id,
                    "work-1",
                    SessionOutcome::Failure,
                    100,
                    3_000_000_000 + i * 1_000_000_000,
                )
                .unwrap();
        }

        let stop = controller.check_stop_condition();
        assert!(matches!(
            stop,
            Some(StopCondition::CircuitBreakerTriggered {
                consecutive_failures: 3
            })
        ));
    }

    #[test]
    fn tck_00150_stop_condition_episode_budget() {
        // Create config with max 2 episodes
        let budget = CoordinationBudget::new(2, 60_000, None).unwrap();
        let config = CoordinationConfig::new(vec!["work-1".to_string()], budget, 5).unwrap();
        let mut controller = CoordinationController::new(config);
        controller.start(1_000_000_000).unwrap();

        // Use up 2 episodes
        for i in 0u64..2 {
            let spawn = controller
                .prepare_session_spawn("work-1", 100 + i, 2_000_000_000 + i * 1_000_000_000)
                .unwrap();
            controller
                .record_session_termination(
                    &spawn.session_id,
                    "work-1",
                    SessionOutcome::Failure,
                    100,
                    3_000_000_000 + i * 1_000_000_000,
                )
                .unwrap();
        }

        let stop = controller.check_stop_condition();
        assert!(matches!(
            stop,
            Some(StopCondition::BudgetExhausted(
                super::super::state::BudgetType::Episodes
            ))
        ));
    }

    // =========================================================================
    // Completion Tests
    // =========================================================================

    #[test]
    fn tck_00150_complete_coordination() {
        let config = test_config(vec!["work-1".to_string()]);
        let mut controller = CoordinationController::new(config);
        controller.start(1_000_000_000).unwrap();

        let spawn = controller
            .prepare_session_spawn("work-1", 100, 2_000_000_000)
            .unwrap();
        controller
            .record_session_termination(
                &spawn.session_id,
                "work-1",
                SessionOutcome::Success,
                1000,
                3_000_000_000,
            )
            .unwrap();

        let completed = controller
            .complete(StopCondition::WorkCompleted, 4_000_000_000)
            .unwrap();

        assert!(controller.is_terminal());
        assert_eq!(completed.stop_condition, StopCondition::WorkCompleted);
        assert_eq!(completed.total_sessions, 1);
        assert_eq!(completed.successful_sessions, 1);
    }

    #[test]
    fn tck_00150_abort_coordination() {
        let config = test_config(vec!["work-1".to_string()]);
        let mut controller = CoordinationController::new(config);
        controller.start(1_000_000_000).unwrap();

        let aborted = controller
            .abort(AbortReason::NoEligibleWork, 2_000_000_000)
            .unwrap();

        assert!(controller.is_terminal());
        assert_eq!(aborted.reason, AbortReason::NoEligibleWork);
    }

    // =========================================================================
    // Retry Logic Tests
    // =========================================================================

    #[test]
    fn tck_00150_retry_on_failure() {
        let config = test_config(vec!["work-1".to_string()]);
        let mut controller = CoordinationController::new(config);
        controller.start(1_000_000_000).unwrap();

        // First attempt - failure
        let spawn1 = controller
            .prepare_session_spawn("work-1", 100, 2_000_000_000)
            .unwrap();
        controller
            .record_session_termination(
                &spawn1.session_id,
                "work-1",
                SessionOutcome::Failure,
                100,
                3_000_000_000,
            )
            .unwrap();

        // Should stay on work-1 for retry
        assert_eq!(controller.work_index(), 0);
        assert_eq!(controller.consecutive_failures, 1);

        // Second attempt - success
        let spawn2 = controller
            .prepare_session_spawn("work-1", 101, 4_000_000_000)
            .unwrap();
        controller
            .record_session_termination(
                &spawn2.session_id,
                "work-1",
                SessionOutcome::Success,
                200,
                5_000_000_000,
            )
            .unwrap();

        // Should advance and reset failures
        assert_eq!(controller.work_index(), 1);
        assert_eq!(controller.consecutive_failures, 0);
    }

    #[test]
    fn tck_00150_max_attempts_exhausted() {
        let config = test_config(vec!["work-1".to_string(), "work-2".to_string()]);
        let mut controller = CoordinationController::new(config);
        controller.start(1_000_000_000).unwrap();

        // Exhaust 3 attempts for work-1
        for i in 0u64..3 {
            let spawn = controller
                .prepare_session_spawn("work-1", 100 + i, 2_000_000_000 + i * 1_000_000_000)
                .unwrap();
            controller
                .record_session_termination(
                    &spawn.session_id,
                    "work-1",
                    SessionOutcome::Failure,
                    100,
                    3_000_000_000 + i * 1_000_000_000,
                )
                .unwrap();
        }

        // Should advance to work-2 after exhausting attempts
        assert_eq!(controller.work_index(), 1);
        assert_eq!(controller.current_work_id(), Some("work-2"));

        // Verify work-1 marked as failed
        let tracking = &controller.work_tracking[0];
        assert_eq!(tracking.final_outcome, Some(WorkItemOutcome::Failed));
    }

    // =========================================================================
    // UUID Generation Tests
    // =========================================================================

    #[test]
    fn tck_00150_uuid_format() {
        let uuid = generate_uuid();

        // Check format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
        assert_eq!(uuid.len(), 36);
        assert_eq!(&uuid[8..9], "-");
        assert_eq!(&uuid[13..14], "-");
        assert_eq!(&uuid[14..15], "4"); // Version 4
        assert_eq!(&uuid[18..19], "-");
        assert_eq!(&uuid[23..24], "-");

        // Check variant bits (y should be 8, 9, a, or b)
        let variant_char = uuid.chars().nth(19).unwrap();
        assert!(
            variant_char == '8'
                || variant_char == '9'
                || variant_char == 'a'
                || variant_char == 'b'
        );
    }

    #[test]
    fn tck_00150_uuid_uniqueness() {
        let mut uuids = Vec::new();
        for _ in 0..100 {
            uuids.push(generate_uuid());
        }

        // Check uniqueness
        uuids.sort();
        uuids.dedup();
        assert_eq!(uuids.len(), 100, "UUIDs should be unique");
    }

    // =========================================================================
    // Integration Test: Full Coordination Run
    // =========================================================================

    #[test]
    fn tck_00150_integration_full_coordination_run() {
        let config = test_config(vec![
            "work-1".to_string(),
            "work-2".to_string(),
            "work-3".to_string(),
        ]);
        let mut controller = CoordinationController::new(config);

        // Start coordination
        let coord_id = controller.start(1_000_000_000).unwrap();
        assert!(!coord_id.is_empty());

        // Process work-1 (success)
        let spawn1 = controller
            .prepare_session_spawn("work-1", 100, 2_000_000_000)
            .unwrap();
        controller
            .record_session_termination(
                &spawn1.session_id,
                "work-1",
                SessionOutcome::Success,
                1000,
                3_000_000_000,
            )
            .unwrap();

        // Process work-2 (fail, retry, success)
        let spawn_work2_attempt1 = controller
            .prepare_session_spawn("work-2", 200, 4_000_000_000)
            .unwrap();
        controller
            .record_session_termination(
                &spawn_work2_attempt1.session_id,
                "work-2",
                SessionOutcome::Failure,
                500,
                5_000_000_000,
            )
            .unwrap();

        let spawn_work2_attempt2 = controller
            .prepare_session_spawn("work-2", 201, 6_000_000_000)
            .unwrap();
        controller
            .record_session_termination(
                &spawn_work2_attempt2.session_id,
                "work-2",
                SessionOutcome::Success,
                800,
                7_000_000_000,
            )
            .unwrap();

        // Process work-3 (success)
        let spawn3 = controller
            .prepare_session_spawn("work-3", 300, 8_000_000_000)
            .unwrap();
        controller
            .record_session_termination(
                &spawn3.session_id,
                "work-3",
                SessionOutcome::Success,
                1200,
                9_000_000_000,
            )
            .unwrap();

        // Check stop condition
        let stop = controller.check_stop_condition();
        assert_eq!(stop, Some(StopCondition::WorkCompleted));

        // Complete coordination
        let completed = controller
            .complete(StopCondition::WorkCompleted, 10_000_000_000)
            .unwrap();

        assert!(controller.is_terminal());
        assert_eq!(completed.total_sessions, 4);
        assert_eq!(completed.successful_sessions, 3);
        assert_eq!(completed.failed_sessions, 1);
        assert_eq!(
            controller.budget_usage.consumed_tokens,
            1000 + 500 + 800 + 1200
        );

        // Verify event sequence
        let events = controller.emitted_events();
        assert_eq!(events.len(), 10); // started + 4*(bound+unbound) + completed
    }
}
