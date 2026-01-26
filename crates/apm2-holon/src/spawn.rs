//! Holon spawning and orchestration.
//!
//! This module provides the [`spawn_holon`] function that orchestrates the
//! complete lifecycle of a holon execution:
//!
//! 1. Creates a [`WorkObject`] for tracking the work
//! 2. Issues a [`Lease`] authorizing execution
//! 3. Runs the episode loop via [`EpisodeController`]
//! 4. Emits artifacts to the ledger
//! 5. Handles escalation and forwards to caller
//!
//! # Example
//!
//! ```rust,ignore
//! use apm2_holon::{
//!     spawn::{spawn_holon, SpawnConfig, SpawnResult},
//!     resource::{Budget, LeaseScope},
//!     traits::MockHolon,
//! };
//!
//! // Create a mock holon for testing
//! let mut holon = MockHolon::new("test-holon").with_episodes_until_complete(3);
//!
//! // Configure the spawn
//! let config = SpawnConfig::builder()
//!     .work_id("work-001")
//!     .work_title("Test work")
//!     .issuer_id("registrar-001")
//!     .holder_id("agent-001")
//!     .scope(LeaseScope::unlimited())
//!     .budget(Budget::new(10, 100, 10_000, 60_000))
//!     .build()?;
//!
//! // Spawn and run the holon
//! let result = spawn_holon(
//!     &mut holon,
//!     "input".to_string(),
//!     config,
//!     || current_time_ns(),
//! )?;
//!
//! assert!(result.is_successful());
//! ```

use serde::{Deserialize, Serialize};

use crate::episode::{EpisodeController, EpisodeControllerConfig, EpisodeLoopOutcome};
use crate::error::HolonError;
use crate::ledger::{EpisodeEvent, EventHash, EventType, LedgerEvent};
use crate::resource::{Budget, Lease, LeaseScope};
use crate::traits::Holon;
use crate::work::WorkObject;

/// Configuration for spawning a holon.
///
/// This struct contains all the parameters needed to create a work object
/// and lease for holon execution.
#[derive(Debug, Clone)]
pub struct SpawnConfig {
    /// Unique identifier for the work.
    pub work_id: String,

    /// Human-readable title for the work.
    pub work_title: String,

    /// The entity issuing the lease (typically a registrar).
    pub issuer_id: String,

    /// The holon that will hold the lease.
    pub holder_id: String,

    /// The scope of authority granted by the lease.
    pub scope: LeaseScope,

    /// The resource budget for execution.
    pub budget: Budget,

    /// Lease expiration time in nanoseconds since epoch.
    /// Defaults to 1 hour from now if not specified.
    pub expires_at_ns: Option<u64>,

    /// Optional goal specification.
    pub goal_spec: Option<String>,

    /// Episode controller configuration.
    pub episode_config: EpisodeControllerConfig,
}

impl SpawnConfig {
    /// Returns a builder for constructing a `SpawnConfig`.
    #[must_use]
    pub fn builder() -> SpawnConfigBuilder {
        SpawnConfigBuilder::default()
    }
}

/// Builder for [`SpawnConfig`].
#[derive(Debug, Default)]
pub struct SpawnConfigBuilder {
    work_id: Option<String>,
    work_title: Option<String>,
    issuer_id: Option<String>,
    holder_id: Option<String>,
    scope: Option<LeaseScope>,
    budget: Option<Budget>,
    expires_at_ns: Option<u64>,
    goal_spec: Option<String>,
    episode_config: Option<EpisodeControllerConfig>,
}

impl SpawnConfigBuilder {
    /// Sets the work ID.
    #[must_use]
    pub fn work_id(mut self, id: impl Into<String>) -> Self {
        self.work_id = Some(id.into());
        self
    }

    /// Sets the work title.
    #[must_use]
    pub fn work_title(mut self, title: impl Into<String>) -> Self {
        self.work_title = Some(title.into());
        self
    }

    /// Sets the issuer ID.
    #[must_use]
    pub fn issuer_id(mut self, id: impl Into<String>) -> Self {
        self.issuer_id = Some(id.into());
        self
    }

    /// Sets the holder ID.
    #[must_use]
    pub fn holder_id(mut self, id: impl Into<String>) -> Self {
        self.holder_id = Some(id.into());
        self
    }

    /// Sets the lease scope.
    #[must_use]
    pub fn scope(mut self, scope: LeaseScope) -> Self {
        self.scope = Some(scope);
        self
    }

    /// Sets the budget.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // destructors cannot be const
    pub fn budget(mut self, budget: Budget) -> Self {
        self.budget = Some(budget);
        self
    }

    /// Sets the lease expiration time.
    #[must_use]
    pub const fn expires_at_ns(mut self, ts: u64) -> Self {
        self.expires_at_ns = Some(ts);
        self
    }

    /// Sets the goal specification.
    #[must_use]
    pub fn goal_spec(mut self, spec: impl Into<String>) -> Self {
        self.goal_spec = Some(spec.into());
        self
    }

    /// Sets the episode controller configuration.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // destructors cannot be const
    pub fn episode_config(mut self, config: EpisodeControllerConfig) -> Self {
        self.episode_config = Some(config);
        self
    }

    /// Builds the `SpawnConfig`.
    ///
    /// # Errors
    ///
    /// Returns `HolonError::MissingContext` if any required field is not set.
    pub fn build(self) -> Result<SpawnConfig, HolonError> {
        let work_id = self
            .work_id
            .ok_or_else(|| HolonError::missing_context("work_id"))?;
        let work_title = self
            .work_title
            .ok_or_else(|| HolonError::missing_context("work_title"))?;
        let issuer_id = self
            .issuer_id
            .ok_or_else(|| HolonError::missing_context("issuer_id"))?;
        let holder_id = self
            .holder_id
            .ok_or_else(|| HolonError::missing_context("holder_id"))?;
        let scope = self
            .scope
            .ok_or_else(|| HolonError::missing_context("scope"))?;
        let budget = self
            .budget
            .ok_or_else(|| HolonError::missing_context("budget"))?;

        Ok(SpawnConfig {
            work_id,
            work_title,
            issuer_id,
            holder_id,
            scope,
            budget,
            expires_at_ns: self.expires_at_ns,
            goal_spec: self.goal_spec,
            episode_config: self.episode_config.unwrap_or_default(),
        })
    }
}

/// The result of spawning and executing a holon.
///
/// Contains the final work object state, outcome, emitted events, and
/// any output produced.
#[derive(Debug, Clone)]
pub struct SpawnResult<T> {
    /// The final work object state.
    pub work: WorkObject,

    /// The outcome of the episode loop.
    pub outcome: SpawnOutcome,

    /// Ledger events emitted during execution.
    pub events: Vec<LedgerEvent>,

    /// Episode events emitted during execution.
    pub episode_events: Vec<EpisodeEvent>,

    /// The final output, if the goal was satisfied.
    pub output: Option<T>,

    /// Number of episodes executed.
    pub episodes_executed: u64,

    /// Total tokens consumed.
    pub tokens_consumed: u64,
}

impl<T> SpawnResult<T> {
    /// Returns `true` if this is a successful completion.
    #[must_use]
    pub const fn is_successful(&self) -> bool {
        matches!(self.outcome, SpawnOutcome::Completed)
    }

    /// Returns `true` if the work was escalated.
    #[must_use]
    pub const fn is_escalated(&self) -> bool {
        matches!(self.outcome, SpawnOutcome::Escalated { .. })
    }

    /// Returns `true` if an error occurred.
    #[must_use]
    pub const fn is_error(&self) -> bool {
        matches!(self.outcome, SpawnOutcome::Error { .. })
    }

    /// Returns the escalation reason, if escalated.
    #[must_use]
    pub fn escalation_reason(&self) -> Option<&str> {
        match &self.outcome {
            SpawnOutcome::Escalated { reason } => Some(reason),
            _ => None,
        }
    }
}

/// The outcome of a holon spawn operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SpawnOutcome {
    /// The goal was satisfied; work is complete.
    Completed,

    /// The budget was exhausted before completion.
    BudgetExhausted {
        /// The resource that was exhausted.
        resource: String,
    },

    /// The maximum episode limit was reached.
    MaxEpisodesReached,

    /// The holon signaled it is blocked.
    Blocked {
        /// Reason for the block.
        reason: String,
    },

    /// The holon escalated the work.
    Escalated {
        /// Reason for escalation.
        reason: String,
    },

    /// An error occurred during execution.
    Error {
        /// Error description.
        error: String,
        /// Whether this error is recoverable.
        recoverable: bool,
    },
}

impl SpawnOutcome {
    /// Returns the outcome as a string identifier.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::BudgetExhausted { .. } => "budget_exhausted",
            Self::MaxEpisodesReached => "max_episodes_reached",
            Self::Blocked { .. } => "blocked",
            Self::Escalated { .. } => "escalated",
            Self::Error { .. } => "error",
        }
    }
}

impl From<&EpisodeLoopOutcome> for SpawnOutcome {
    fn from(outcome: &EpisodeLoopOutcome) -> Self {
        match outcome {
            EpisodeLoopOutcome::Completed { .. } => Self::Completed,
            EpisodeLoopOutcome::BudgetExhausted { resource, .. } => Self::BudgetExhausted {
                resource: resource.clone(),
            },
            EpisodeLoopOutcome::MaxEpisodesReached { .. } => Self::MaxEpisodesReached,
            EpisodeLoopOutcome::Blocked { reason, .. } => Self::Blocked {
                reason: reason.clone(),
            },
            EpisodeLoopOutcome::Escalated { reason, .. } => Self::Escalated {
                reason: reason.clone(),
            },
            EpisodeLoopOutcome::Error {
                error, recoverable, ..
            } => Self::Error {
                error: error.clone(),
                recoverable: *recoverable,
            },
        }
    }
}

/// Default lease expiration: 1 hour in nanoseconds.
const DEFAULT_LEASE_DURATION_NS: u64 = 3_600_000_000_000;

/// Spawns a holon and executes it until completion or a stop condition.
///
/// This function orchestrates the complete holon lifecycle:
///
/// 1. **Work Creation**: Creates a [`WorkObject`] to track the work
/// 2. **Lease Issuance**: Issues a [`Lease`] authorizing the holon to execute
/// 3. **Intake**: Calls [`Holon::intake`] with the input and lease ID
/// 4. **Episode Loop**: Runs episodes via [`EpisodeController`] until stop
/// 5. **Artifact Emission**: Collects ledger events from execution
/// 6. **Escalation Handling**: Forwards escalation reasons to the caller
///
/// # Arguments
///
/// * `holon` - The holon to spawn and execute
/// * `input` - The input to provide to the holon's intake method
/// * `config` - Configuration for the spawn operation
/// * `clock` - Function to get current timestamp in nanoseconds
///
/// # Returns
///
/// Returns a [`SpawnResult`] containing the final work state, outcome,
/// events, and optional output.
///
/// # Errors
///
/// Returns `HolonError` if:
/// - Lease creation fails
/// - The holon's intake method fails
/// - A fatal error occurs during episode execution
///
/// # Example
///
/// ```rust,ignore
/// use apm2_holon::{
///     spawn::{spawn_holon, SpawnConfig},
///     resource::{Budget, LeaseScope},
///     traits::MockHolon,
/// };
///
/// let mut holon = MockHolon::new("test").with_episodes_until_complete(2);
///
/// let config = SpawnConfig::builder()
///     .work_id("work-001")
///     .work_title("Test work")
///     .issuer_id("registrar")
///     .holder_id("agent")
///     .scope(LeaseScope::unlimited())
///     .budget(Budget::new(10, 100, 10_000, 60_000))
///     .build()?;
///
/// let result = spawn_holon(&mut holon, "input".to_string(), config, || 1_000_000_000)?;
///
/// assert!(result.is_successful());
/// assert_eq!(result.episodes_executed, 2);
/// ```
// Note: This function manages the complete holon lifecycle including work creation,
// lease issuance, episode execution, and state transitions. The logic is intentionally
// kept together to maintain clear control flow despite the length.
#[allow(clippy::too_many_lines)]
pub fn spawn_holon<H, F>(
    holon: &mut H,
    input: H::Input,
    config: SpawnConfig,
    mut clock: F,
) -> Result<SpawnResult<H::Output>, HolonError>
where
    H: Holon,
    F: FnMut() -> u64,
{
    let start_ns = clock();

    // Step 1: Create the work object
    let mut work = WorkObject::new_with_timestamp(&config.work_id, &config.work_title, start_ns);

    // Step 2: Create the lease
    let lease_id = format!("{}-lease", config.work_id);
    let expires_at_ns = config
        .expires_at_ns
        .unwrap_or_else(|| start_ns.saturating_add(DEFAULT_LEASE_DURATION_NS));

    let mut lease = Lease::builder()
        .lease_id(&lease_id)
        .issuer_id(&config.issuer_id)
        .holder_id(&config.holder_id)
        .scope(config.scope)
        .budget(config.budget)
        .issued_at_ns(start_ns)
        .expires_at_ns(expires_at_ns)
        .build()
        .map_err(|e| HolonError::invalid_input(format!("failed to create lease: {e}")))?;

    // Step 3: Transition work to Leased state
    work.transition_to_leased_at(&lease_id, start_ns)?;

    // Collect ledger events
    let mut events = Vec::new();

    // Generate unique event IDs
    let work_created_event_id = format!("{}-work-created", config.work_id);
    let lease_issued_event_id = format!("{}-lease-issued", config.work_id);

    // Emit work created event
    let work_created_event = LedgerEvent::builder()
        .event_id(&work_created_event_id)
        .work_id(&config.work_id)
        .holon_id(&config.holder_id)
        .timestamp_ns(start_ns)
        .event_type(EventType::WorkCreated {
            title: config.work_title.clone(),
        })
        .previous_hash(EventHash::ZERO)
        .build();
    let work_created_hash = work_created_event.compute_hash();
    events.push(work_created_event);

    // Emit lease issued event
    let lease_issued_event = LedgerEvent::builder()
        .event_id(&lease_issued_event_id)
        .work_id(&config.work_id)
        .holon_id(&config.issuer_id)
        .timestamp_ns(start_ns)
        .event_type(EventType::LeaseIssued {
            lease_id: lease_id.clone(),
            holder_id: config.holder_id.clone(),
            expires_at_ns,
        })
        .previous_hash(work_created_hash)
        .build();
    let last_hash = lease_issued_event.compute_hash();
    events.push(lease_issued_event);

    // Step 4: Call holon intake
    holon.intake(input, &lease_id)?;

    // Step 5: Transition work to InProgress
    let transition_ns = clock();
    work.transition_to_in_progress_at(transition_ns)?;

    // Step 6: Run the episode loop
    let controller = EpisodeController::new(config.episode_config);
    let loop_result = controller.run_episode_loop(
        holon,
        &config.work_id,
        &mut lease,
        config.goal_spec.as_deref(),
        1, // Start at episode 1
        &mut clock,
    )?;

    // Keep episode events separate for detailed tracking
    let episode_events = loop_result.events.clone();

    // Step 7: Transition work to final state based on outcome
    let end_ns = clock();
    let outcome = SpawnOutcome::from(&loop_result.outcome);

    match &loop_result.outcome {
        EpisodeLoopOutcome::Completed { .. } => {
            work.transition_to_completed_at(end_ns)?;

            // Emit work completed event
            let completed_event_id = format!("{}-completed", config.work_id);
            let completed_event = LedgerEvent::builder()
                .event_id(&completed_event_id)
                .work_id(&config.work_id)
                .holon_id(&config.holder_id)
                .timestamp_ns(end_ns)
                .event_type(EventType::WorkCompleted {
                    evidence_ids: Vec::new(),
                })
                .previous_hash(last_hash)
                .build();
            // Update hash for chain integrity (even if not used after this)
            let _ = completed_event.compute_hash();
            events.push(completed_event);
        },
        EpisodeLoopOutcome::Escalated { reason, .. } => {
            work.transition_to_escalated_at(reason, end_ns)?;

            // Emit work escalated event
            let escalated_event_id = format!("{}-escalated", config.work_id);
            let escalated_event = LedgerEvent::builder()
                .event_id(&escalated_event_id)
                .work_id(&config.work_id)
                .holon_id(&config.holder_id)
                .timestamp_ns(end_ns)
                .event_type(EventType::WorkEscalated {
                    to_holon_id: String::new(), // No specific target yet
                    reason: reason.clone(),
                })
                .previous_hash(last_hash)
                .build();
            let _ = escalated_event.compute_hash();
            events.push(escalated_event);
        },
        EpisodeLoopOutcome::Error {
            error, recoverable, ..
        } => {
            if *recoverable {
                // Recoverable errors go to blocked state
                work.transition_to_blocked_at(error, end_ns)?;
            } else {
                // Non-recoverable errors go to failed state
                work.transition_to_failed_at(error, end_ns)?;

                // Emit work failed event
                let failed_event_id = format!("{}-failed", config.work_id);
                let failed_event = LedgerEvent::builder()
                    .event_id(&failed_event_id)
                    .work_id(&config.work_id)
                    .holon_id(&config.holder_id)
                    .timestamp_ns(end_ns)
                    .event_type(EventType::WorkFailed {
                        reason: error.clone(),
                        recoverable: *recoverable,
                    })
                    .previous_hash(last_hash)
                    .build();
                let _ = failed_event.compute_hash();
                events.push(failed_event);
            }
        },
        EpisodeLoopOutcome::Blocked { reason, .. } => {
            work.transition_to_blocked_at(reason, end_ns)?;
        },
        EpisodeLoopOutcome::BudgetExhausted { .. }
        | EpisodeLoopOutcome::MaxEpisodesReached { .. } => {
            // Budget exhaustion keeps work in progress for potential continuation
            // with a new lease. Record the reason in metadata.
            let reason = match &loop_result.outcome {
                EpisodeLoopOutcome::BudgetExhausted { resource, .. } => {
                    format!("budget exhausted: {resource}")
                },
                EpisodeLoopOutcome::MaxEpisodesReached { .. } => "max episodes reached".to_string(),
                _ => unreachable!(),
            };
            // Work stays in InProgress state but we record the pause reason
            // This allows resumption with a new lease
            let _ = work.set_metadata("pause_reason", reason);
        },
    }

    Ok(SpawnResult {
        work,
        outcome,
        events,
        episode_events,
        output: loop_result.output,
        episodes_executed: loop_result.outcome.episodes_executed(),
        tokens_consumed: match &loop_result.outcome {
            EpisodeLoopOutcome::Completed { tokens_consumed, .. }
            | EpisodeLoopOutcome::BudgetExhausted { tokens_consumed, .. }
            | EpisodeLoopOutcome::MaxEpisodesReached { tokens_consumed, .. } => *tokens_consumed,
            _ => 0,
        },
    })
}

#[cfg(test)]
mod unit_tests {
    use super::*;
    use crate::traits::MockHolon;
    use crate::work::WorkLifecycle;

    fn test_config() -> SpawnConfig {
        SpawnConfig::builder()
            .work_id("work-001")
            .work_title("Test work")
            .issuer_id("registrar-001")
            .holder_id("agent-001")
            .scope(LeaseScope::unlimited())
            .budget(Budget::new(10, 100, 10_000, 60_000))
            .expires_at_ns(2_000_000_000)
            .build()
            .unwrap()
    }

    #[test]
    fn test_spawn_config_builder() {
        let config = test_config();
        assert_eq!(config.work_id, "work-001");
        assert_eq!(config.work_title, "Test work");
        assert_eq!(config.issuer_id, "registrar-001");
        assert_eq!(config.holder_id, "agent-001");
        assert_eq!(config.expires_at_ns, Some(2_000_000_000));
    }

    #[test]
    fn test_spawn_config_builder_missing_work_id() {
        let result = SpawnConfig::builder()
            .work_title("Test")
            .issuer_id("issuer")
            .holder_id("holder")
            .scope(LeaseScope::unlimited())
            .budget(Budget::new(1, 1, 1, 1))
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_spawn_holon_success() {
        let mut holon = MockHolon::new("test-holon").with_episodes_until_complete(2);
        let config = test_config();

        let mut time = 1_000_000_000u64;
        let result = spawn_holon(&mut holon, "input".to_string(), config, || {
            let t = time;
            time += 1_000_000;
            t
        })
        .unwrap();

        assert!(result.is_successful());
        assert_eq!(result.episodes_executed, 2);
        assert!(result.work.lifecycle() == WorkLifecycle::Completed);
        assert!(result.output.is_some());
    }

    #[test]
    fn test_spawn_holon_escalation() {
        let mut holon = MockHolon::new("test-holon").with_episodes_until_complete(10);
        holon.escalate_next_episode = true;

        let config = test_config();

        let mut time = 1_000_000_000u64;
        let result = spawn_holon(&mut holon, "input".to_string(), config, || {
            let t = time;
            time += 1_000_000;
            t
        })
        .unwrap();

        assert!(result.is_escalated());
        assert!(result.work.lifecycle() == WorkLifecycle::Escalated);
        assert!(result.escalation_reason().is_some());
    }

    #[test]
    fn test_spawn_holon_max_episodes_reached() {
        // Test that we hit max_episodes when budget episodes < config max_episodes
        let mut holon = MockHolon::new("test-holon").with_episodes_until_complete(100);

        let config = SpawnConfig::builder()
            .work_id("work-001")
            .work_title("Test work")
            .issuer_id("registrar-001")
            .holder_id("agent-001")
            .scope(LeaseScope::unlimited())
            .budget(Budget::new(2, 100, 10_000, 60_000)) // Only 2 episodes in budget
            .expires_at_ns(2_000_000_000)
            .episode_config(
                crate::episode::EpisodeControllerConfig::default()
                    .with_max_episodes(2), // Match budget episodes
            )
            .build()
            .unwrap();

        let mut time = 1_000_000_000u64;
        let result = spawn_holon(&mut holon, "input".to_string(), config, || {
            let t = time;
            time += 1_000_000;
            t
        })
        .unwrap();

        // When max_episodes == budget.episodes, we hit max_episodes_reached
        assert_eq!(result.outcome.as_str(), "max_episodes_reached");
        // Work stays in progress for potential continuation
        assert!(result.work.lifecycle() == WorkLifecycle::InProgress);
    }

    #[test]
    fn test_spawn_holon_emits_events() {
        let mut holon = MockHolon::new("test-holon").with_episodes_until_complete(1);
        let config = test_config();

        let mut time = 1_000_000_000u64;
        let result = spawn_holon(&mut holon, "input".to_string(), config, || {
            let t = time;
            time += 1_000_000;
            t
        })
        .unwrap();

        // Should have: WorkCreated, LeaseIssued, WorkCompleted
        assert!(!result.events.is_empty());

        // Verify WorkCreated event
        let work_created = result
            .events
            .iter()
            .find(|e| matches!(e.event_type(), EventType::WorkCreated { .. }));
        assert!(work_created.is_some());

        // Verify LeaseIssued event
        let lease_issued = result
            .events
            .iter()
            .find(|e| matches!(e.event_type(), EventType::LeaseIssued { .. }));
        assert!(lease_issued.is_some());

        // Verify WorkCompleted event
        let work_completed = result
            .events
            .iter()
            .find(|e| matches!(e.event_type(), EventType::WorkCompleted { .. }));
        assert!(work_completed.is_some());
    }

    #[test]
    fn test_spawn_outcome_conversion() {
        let completed = EpisodeLoopOutcome::Completed {
            episodes_executed: 5,
            tokens_consumed: 1000,
        };
        assert_eq!(SpawnOutcome::from(&completed), SpawnOutcome::Completed);

        let escalated = EpisodeLoopOutcome::Escalated {
            reason: "test".to_string(),
            episodes_executed: 3,
        };
        assert_eq!(
            SpawnOutcome::from(&escalated),
            SpawnOutcome::Escalated {
                reason: "test".to_string()
            }
        );
    }

    #[test]
    fn test_spawn_result_methods() {
        let work = WorkObject::new("work-1", "Test");
        let result: SpawnResult<String> = SpawnResult {
            work,
            outcome: SpawnOutcome::Completed,
            events: Vec::new(),
            episode_events: Vec::new(),
            output: Some("done".to_string()),
            episodes_executed: 1,
            tokens_consumed: 100,
        };

        assert!(result.is_successful());
        assert!(!result.is_escalated());
        assert!(!result.is_error());
        assert!(result.escalation_reason().is_none());

        let work2 = WorkObject::new("work-2", "Test");
        let escalated_result: SpawnResult<String> = SpawnResult {
            work: work2,
            outcome: SpawnOutcome::Escalated {
                reason: "beyond scope".to_string(),
            },
            events: Vec::new(),
            episode_events: Vec::new(),
            output: None,
            episodes_executed: 2,
            tokens_consumed: 200,
        };

        assert!(!escalated_result.is_successful());
        assert!(escalated_result.is_escalated());
        assert_eq!(escalated_result.escalation_reason(), Some("beyond scope"));
    }
}

#[cfg(test)]
mod integration_tests {
    //! Integration tests for spawn_holon with MockHolon.
    //!
    //! These tests verify the complete orchestration flow as specified
    //! in TCK-00045 definition of done.

    use super::*;
    use crate::episode::EpisodeControllerConfig;
    use crate::traits::MockHolon;
    use crate::work::WorkLifecycle;

    /// Integration test: spawn_holon creates work and issues lease.
    #[test]
    fn test_integration_spawn_creates_work_and_lease() {
        let mut holon = MockHolon::new("integration-holon").with_episodes_until_complete(1);

        let config = SpawnConfig::builder()
            .work_id("integration-work-001")
            .work_title("Integration test work")
            .issuer_id("integration-registrar")
            .holder_id("integration-agent")
            .scope(LeaseScope::unlimited())
            .budget(Budget::new(10, 100, 10_000, 60_000))
            .expires_at_ns(10_000_000_000)
            .build()
            .unwrap();

        let mut time = 1_000_000_000u64;
        let result = spawn_holon(&mut holon, "test input".to_string(), config, || {
            let t = time;
            time += 1_000_000;
            t
        })
        .unwrap();

        // Verify work was created
        assert_eq!(result.work.id(), "integration-work-001");
        assert_eq!(result.work.title(), "Integration test work");

        // Verify lease was issued (check events)
        let lease_event = result.events.iter().find(|e| {
            matches!(
                e.event_type(),
                EventType::LeaseIssued { lease_id, .. } if lease_id == "integration-work-001-lease"
            )
        });
        assert!(lease_event.is_some(), "Lease issued event not found");

        // Verify intake was called
        assert!(holon.intake_called);
    }

    /// Integration test: Episode loop executes until stop condition.
    #[test]
    fn test_integration_episode_loop_until_stop() {
        let mut holon = MockHolon::new("loop-holon").with_episodes_until_complete(5);

        let config = SpawnConfig::builder()
            .work_id("loop-work")
            .work_title("Loop test")
            .issuer_id("registrar")
            .holder_id("agent")
            .scope(LeaseScope::unlimited())
            .budget(Budget::new(10, 100, 10_000, 60_000))
            .expires_at_ns(10_000_000_000)
            .build()
            .unwrap();

        let mut time = 1_000_000_000u64;
        let result = spawn_holon(&mut holon, "input".to_string(), config, || {
            let t = time;
            time += 1_000_000;
            t
        })
        .unwrap();

        // Verify episodes executed
        assert_eq!(result.episodes_executed, 5);
        assert!(result.is_successful());

        // Verify holon executed the expected number of episodes
        assert_eq!(holon.episodes_executed, 5);
    }

    /// Integration test: Artifacts emitted to ledger.
    #[test]
    fn test_integration_artifacts_emitted() {
        let mut holon = MockHolon::new("artifact-holon").with_episodes_until_complete(2);

        let config = SpawnConfig::builder()
            .work_id("artifact-work")
            .work_title("Artifact test")
            .issuer_id("registrar")
            .holder_id("agent")
            .scope(LeaseScope::unlimited())
            .budget(Budget::new(10, 100, 10_000, 60_000))
            .expires_at_ns(10_000_000_000)
            .episode_config(EpisodeControllerConfig::default().with_emit_events(true))
            .build()
            .unwrap();

        let mut time = 1_000_000_000u64;
        let result = spawn_holon(&mut holon, "input".to_string(), config, || {
            let t = time;
            time += 1_000_000;
            t
        })
        .unwrap();

        // Verify events were emitted
        assert!(
            !result.events.is_empty(),
            "Expected ledger events to be emitted"
        );

        // Verify we have episode events
        assert!(
            !result.episode_events.is_empty(),
            "Expected episode events to be emitted"
        );
    }

    /// Integration test: Escalation propagates to caller.
    #[test]
    fn test_integration_escalation_propagates() {
        let mut holon = MockHolon::new("escalate-holon").with_episodes_until_complete(10);
        holon.escalate_next_episode = true;

        let config = SpawnConfig::builder()
            .work_id("escalate-work")
            .work_title("Escalation test")
            .issuer_id("registrar")
            .holder_id("agent")
            .scope(LeaseScope::unlimited())
            .budget(Budget::new(10, 100, 10_000, 60_000))
            .expires_at_ns(10_000_000_000)
            .build()
            .unwrap();

        let mut time = 1_000_000_000u64;
        let result = spawn_holon(&mut holon, "input".to_string(), config, || {
            let t = time;
            time += 1_000_000;
            t
        })
        .unwrap();

        // Verify escalation was propagated
        assert!(result.is_escalated(), "Expected escalation outcome");
        assert!(
            result.escalation_reason().is_some(),
            "Expected escalation reason"
        );

        // Verify work state reflects escalation
        assert_eq!(
            result.work.lifecycle(),
            WorkLifecycle::Escalated,
            "Work should be in Escalated state"
        );

        // Verify escalation event was emitted
        let escalation_event = result
            .events
            .iter()
            .find(|e| matches!(e.event_type(), EventType::WorkEscalated { .. }));
        assert!(
            escalation_event.is_some(),
            "Expected WorkEscalated event to be emitted"
        );
    }

    /// Integration test: Complete orchestration with mock holon.
    #[test]
    fn test_integration_full_orchestration() {
        // This test exercises the full spawn_holon flow as a comprehensive
        // integration test covering all TCK-00045 acceptance criteria.

        let mut holon = MockHolon::new("full-test-holon").with_episodes_until_complete(3);

        let config = SpawnConfig::builder()
            .work_id("full-test-work")
            .work_title("Full orchestration test")
            .issuer_id("test-registrar")
            .holder_id("test-agent")
            .scope(LeaseScope::builder().work_ids(["full-test-work"]).build())
            .budget(Budget::new(10, 100, 10_000, 60_000))
            .expires_at_ns(5_000_000_000)
            .goal_spec("Complete the test task")
            .episode_config(EpisodeControllerConfig::default().with_emit_events(true))
            .build()
            .unwrap();

        let mut time = 1_000_000_000u64;
        let result = spawn_holon(&mut holon, "full test input".to_string(), config, || {
            let t = time;
            time += 100_000_000; // 100ms per call
            t
        })
        .unwrap();

        // Criterion 1: spawn_holon creates work and issues lease
        assert_eq!(result.work.id(), "full-test-work");
        let has_lease_event = result
            .events
            .iter()
            .any(|e| matches!(e.event_type(), EventType::LeaseIssued { .. }));
        assert!(has_lease_event, "Lease should be issued");

        // Criterion 2: Episode loop executes until stop condition
        assert_eq!(result.episodes_executed, 3);
        assert!(result.is_successful());

        // Criterion 3: Artifacts emitted to ledger
        let has_work_events = result
            .events
            .iter()
            .any(|e| matches!(e.event_type(), EventType::WorkCreated { .. }));
        assert!(has_work_events, "Work events should be emitted");

        // Criterion 4: (Escalation tested separately above)

        // Criterion 5: Integration test with mock holon (this is it!)
        assert!(holon.intake_called);
        assert_eq!(holon.episodes_executed, 3);
        assert!(result.output.is_some());
    }
}
