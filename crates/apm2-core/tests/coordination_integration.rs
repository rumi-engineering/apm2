//! End-to-end integration tests for the coordination system (TCK-00155).
//!
//! This module provides integration tests that verify:
//!
//! 1. Happy path produces valid receipt with deterministic hash
//! 2. Atomic binding via CAS-at-commit (`SessionBound` committed BEFORE spawn)
//! 3. Proper event ordering throughout the coordination lifecycle
//! 4. `SessionSpawner` trait decouples session execution from coordination
//!
//! # Test Architecture
//!
//! ```text
//! CoordinationController
//!     |
//!     v
//! MockSessionSpawner (records spawn calls)
//!     |
//!     v
//! Verification of event ordering and receipt contents
//! ```
//!
//! # Key Invariants Verified
//!
//! - `[INV-COORD-001]` Binding committed before spawn (CAS-at-commit)
//! - `[INV-COORD-002]` Every bound session is eventually unbound
//! - `[INV-COORD-003]` Receipt hash matches content
//!
//! # References
//!
//! - TCK-00155: Implement coordination end-to-end integration tests
//! - RFC-0012: Agent Coordination Layer for Autonomous Work Loop Execution
//! - AD-COORD-006: Normative atomic work binding (CAS-at-commit)
//! - AD-COORD-014: `SessionSpawner` trait for execution decoupling

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use apm2_core::coordination::{
    CoordinationBudget, CoordinationConfig, CoordinationController, CoordinationEvent,
    CoordinationReceipt, ReceiptBuilder, SessionOutcome, SessionSpawner, SessionTerminationInfo,
    SpawnError, StopCondition, WorkOutcome,
};
use apm2_core::evidence::MemoryCas;

// ============================================================================
// MockSessionSpawner Implementation
// ============================================================================

/// Record of a spawn call made by the coordination controller.
///
/// Used for verifying CAS-at-commit ordering: the spawn call should occur
/// AFTER the `session_bound` event is committed to the ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpawnRecord {
    /// Session ID passed to spawn.
    pub session_id: String,
    /// Work ID passed to spawn.
    pub work_id: String,
    /// Monotonic sequence number (order in which spawns occurred).
    pub sequence: u64,
}

/// Configured outcome for a session spawn.
///
/// Allows tests to pre-configure how the mock spawner should behave for
/// specific sessions.
#[derive(Debug, Clone)]
pub struct ConfiguredOutcome {
    /// The outcome to return.
    pub outcome: SessionOutcome,
    /// Tokens to report as consumed.
    pub tokens_consumed: u64,
}

impl ConfiguredOutcome {
    /// Creates a successful outcome.
    #[must_use]
    pub const fn success(tokens_consumed: u64) -> Self {
        Self {
            outcome: SessionOutcome::Success,
            tokens_consumed,
        }
    }

    /// Creates a failed outcome.
    #[must_use]
    pub const fn failure(tokens_consumed: u64) -> Self {
        Self {
            outcome: SessionOutcome::Failure,
            tokens_consumed,
        }
    }
}

/// Mock implementation of [`SessionSpawner`] for integration testing.
///
/// This mock:
/// - Records all spawn calls with timestamps
/// - Returns pre-configured outcomes
/// - Allows verification of CAS-at-commit ordering
///
/// # Usage
///
/// ```rust,ignore
/// let spawner = MockSessionSpawner::new();
///
/// // Pre-configure outcomes
/// spawner.configure_outcome("work-1", ConfiguredOutcome::success(1000));
/// spawner.configure_outcome("work-2", ConfiguredOutcome::failure(500));
///
/// // Use with controller...
///
/// // Verify spawn ordering
/// let records = spawner.spawn_records();
/// assert_eq!(records[0].work_id, "work-1");
/// ```
#[derive(Debug)]
pub struct MockSessionSpawner {
    /// Recorded spawn calls.
    spawn_records: Arc<Mutex<Vec<SpawnRecord>>>,
    /// Pre-configured outcomes by `work_id`.
    configured_outcomes: Arc<Mutex<std::collections::HashMap<String, VecDeque<ConfiguredOutcome>>>>,
    /// Default outcome when no specific configuration exists.
    default_outcome: Arc<Mutex<ConfiguredOutcome>>,
    /// Sequence counter for ordering verification.
    sequence: Arc<Mutex<u64>>,
    /// Whether to fail spawn (for testing spawn failure handling).
    fail_spawn: Arc<Mutex<bool>>,
}

impl Default for MockSessionSpawner {
    fn default() -> Self {
        Self::new()
    }
}

impl MockSessionSpawner {
    /// Creates a new mock spawner with default success outcome.
    #[must_use]
    pub fn new() -> Self {
        Self {
            spawn_records: Arc::new(Mutex::new(Vec::new())),
            configured_outcomes: Arc::new(Mutex::new(std::collections::HashMap::new())),
            default_outcome: Arc::new(Mutex::new(ConfiguredOutcome::success(1000))),
            sequence: Arc::new(Mutex::new(0)),
            fail_spawn: Arc::new(Mutex::new(false)),
        }
    }

    /// Configures the outcome for spawns with the given `work_id`.
    ///
    /// Multiple calls with the same `work_id` will queue outcomes (FIFO).
    pub fn configure_outcome(&self, work_id: &str, outcome: ConfiguredOutcome) {
        let mut outcomes = self.configured_outcomes.lock().unwrap();
        outcomes
            .entry(work_id.to_string())
            .or_default()
            .push_back(outcome);
    }

    /// Sets the default outcome for unconfigured work items.
    pub fn set_default_outcome(&self, outcome: ConfiguredOutcome) {
        *self.default_outcome.lock().unwrap() = outcome;
    }

    /// Configures the spawner to fail all spawn calls.
    pub fn set_fail_spawn(&self, fail: bool) {
        *self.fail_spawn.lock().unwrap() = fail;
    }

    /// Returns all recorded spawn calls.
    #[must_use]
    pub fn spawn_records(&self) -> Vec<SpawnRecord> {
        self.spawn_records.lock().unwrap().clone()
    }

    /// Returns the number of spawn calls made.
    #[must_use]
    pub fn spawn_count(&self) -> usize {
        self.spawn_records.lock().unwrap().len()
    }

    /// Clears all recorded spawn calls.
    pub fn clear_records(&self) {
        self.spawn_records.lock().unwrap().clear();
    }

    /// Gets the next outcome for a `work_id`.
    fn get_outcome(&self, work_id: &str) -> ConfiguredOutcome {
        let mut outcomes = self.configured_outcomes.lock().unwrap();
        if let Some(queue) = outcomes.get_mut(work_id) {
            if let Some(outcome) = queue.pop_front() {
                return outcome;
            }
        }
        self.default_outcome.lock().unwrap().clone()
    }
}

impl SessionSpawner for MockSessionSpawner {
    fn spawn(&self, session_id: &str, work_id: &str) -> Result<(), SpawnError> {
        // Check if we should fail
        if *self.fail_spawn.lock().unwrap() {
            return Err(SpawnError::SpawnFailed {
                reason: "Mock configured to fail".to_string(),
            });
        }

        // Record the spawn call
        let sequence = {
            let mut seq = self.sequence.lock().unwrap();
            let current = *seq;
            *seq += 1;
            current
        };

        self.spawn_records.lock().unwrap().push(SpawnRecord {
            session_id: session_id.to_string(),
            work_id: work_id.to_string(),
            sequence,
        });

        Ok(())
    }

    fn observe_termination(&self, session_id: &str) -> Result<SessionTerminationInfo, SpawnError> {
        // Find the spawn record to get the work_id
        let records = self.spawn_records.lock().unwrap();
        let record = records
            .iter()
            .find(|r| r.session_id == session_id)
            .ok_or_else(|| SpawnError::SessionNotFound {
                session_id: session_id.to_string(),
            })?;

        let outcome = self.get_outcome(&record.work_id);

        Ok(SessionTerminationInfo::new(
            session_id.to_string(),
            outcome.outcome,
            outcome.tokens_consumed,
        ))
    }
}

// ============================================================================
// Test Helpers
// ============================================================================

/// Creates a standard test budget.
fn create_test_budget() -> CoordinationBudget {
    CoordinationBudget::new(10, 60_000, Some(100_000)).unwrap()
}

/// Creates a test configuration with the given work IDs.
fn create_test_config(work_ids: Vec<&str>) -> CoordinationConfig {
    let work_ids: Vec<String> = work_ids.into_iter().map(String::from).collect();
    CoordinationConfig::new(work_ids, create_test_budget(), 3).unwrap()
}

/// Simulates a complete coordination run using the controller and spawner.
///
/// This helper:
/// 1. Starts coordination
/// 2. Processes work items with the mock spawner
/// 3. Returns all emitted events for verification
///
/// Note: We build the receipt separately since `complete()` doesn't return
/// the receipt directly (it returns `CoordinationCompleted` event).
fn run_coordination(
    controller: &mut CoordinationController,
    spawner: &MockSessionSpawner,
) -> Vec<CoordinationEvent> {
    let timestamp_ns = 1_000_000_000u64;

    // Start coordination
    let _coord_id = controller
        .start(timestamp_ns)
        .expect("start should succeed");

    // Process work items
    while !controller.is_work_queue_exhausted() {
        if let Some(stop) = controller.check_stop_condition() {
            // Complete with stop condition
            let _completed_event = controller
                .complete(stop, timestamp_ns + 1_000_000)
                .expect("complete should succeed");
            return controller.emitted_events().to_vec();
        }

        let work_id = controller.current_work_id().unwrap().to_string();

        // Check freshness (simplified - always fresh in this test)
        let freshness = controller.check_work_freshness(&work_id, 1, true);

        if !freshness.is_eligible {
            controller
                .skip_work_item(&work_id)
                .expect("skip should succeed");
            continue;
        }

        // Prepare spawn - this generates the session_bound event
        let spawn_result = controller
            .prepare_session_spawn(&work_id, 1, timestamp_ns)
            .expect("prepare_session_spawn should succeed");

        // CRITICAL: At this point, session_bound event should be emitted
        // BEFORE we call spawner.spawn()

        // Spawn the session
        let spawn_outcome = spawner.spawn(&spawn_result.session_id, &work_id);

        if spawn_outcome.is_err() {
            // Record spawn failure
            controller
                .record_session_termination(
                    &spawn_result.session_id,
                    &work_id,
                    SessionOutcome::Failure,
                    0,
                    timestamp_ns,
                )
                .expect("record_session_termination should succeed");
            continue;
        }

        // Observe termination
        let termination = spawner
            .observe_termination(&spawn_result.session_id)
            .expect("observe_termination should succeed");

        // Record termination
        controller
            .record_session_termination(
                &spawn_result.session_id,
                &work_id,
                termination.outcome,
                termination.tokens_consumed,
                timestamp_ns,
            )
            .expect("record_session_termination should succeed");
    }

    // All work completed
    let _completed_event = controller
        .complete(StopCondition::WorkCompleted, timestamp_ns + 1_000_000)
        .expect("complete should succeed");

    controller.emitted_events().to_vec()
}

// ============================================================================
// Integration Tests
// ============================================================================

/// TCK-00155: Happy path produces valid completion event.
///
/// This test verifies that a complete coordination run:
/// 1. Processes all work items successfully
/// 2. Produces correct event sequence
/// 3. Completion event contains correct stop condition
#[test]
fn tck_00155_happy_path_produces_valid_completion() {
    let config = create_test_config(vec!["work-1", "work-2", "work-3"]);
    let mut controller = CoordinationController::new(config);
    let spawner = MockSessionSpawner::new();

    // Configure all work items to succeed
    spawner.configure_outcome("work-1", ConfiguredOutcome::success(1000));
    spawner.configure_outcome("work-2", ConfiguredOutcome::success(1500));
    spawner.configure_outcome("work-3", ConfiguredOutcome::success(2000));

    let events = run_coordination(&mut controller, &spawner);

    // Verify the controller state
    assert!(controller.is_terminal(), "Controller should be terminal");

    // Verify budget usage reflects 3 successful sessions
    let budget_usage = controller.budget_usage();
    assert_eq!(budget_usage.consumed_episodes, 3);
    assert_eq!(budget_usage.consumed_tokens, 1000 + 1500 + 2000);

    // Verify spawner was called 3 times
    assert_eq!(spawner.spawn_count(), 3);

    // Verify event sequence ends with Completed
    assert!(
        matches!(events.last().unwrap(), CoordinationEvent::Completed(c) if matches!(c.stop_condition, StopCondition::WorkCompleted)),
        "Last event should be Completed with WorkCompleted"
    );
}

/// TCK-00155: Verify CAS-at-commit ordering (`SessionBound` BEFORE spawn).
///
/// This test verifies the NORMATIVE ordering per AD-COORD-006:
/// 1. Controller emits `session_bound` event
/// 2. Event is committed to ledger (simulated by checking `emitted_events`)
/// 3. THEN spawn is called on `SessionSpawner`
///
/// This ordering prevents TOCTOU races and ensures atomic binding.
#[test]
fn tck_00155_cas_at_commit_ordering_session_bound_before_spawn() {
    let config = create_test_config(vec!["work-1"]);
    let mut controller = CoordinationController::new(config);
    let spawner = MockSessionSpawner::new();

    let timestamp_ns = 1_000_000_000u64;

    // Start coordination
    let _coord_id = controller
        .start(timestamp_ns)
        .expect("start should succeed");

    // Get current event count BEFORE prepare_session_spawn
    let events_before = controller.emitted_events().len();

    let work_id = controller.current_work_id().unwrap().to_string();

    // Prepare spawn - this should emit session_bound event
    let spawn_result = controller
        .prepare_session_spawn(&work_id, 1, timestamp_ns)
        .expect("prepare_session_spawn should succeed");

    // CRITICAL CHECK: session_bound event should be emitted BEFORE we call spawn
    let events_after_prepare = controller.emitted_events().len();
    assert!(
        events_after_prepare > events_before,
        "session_bound event should be emitted by prepare_session_spawn"
    );

    // Verify the emitted event is session_bound
    let bound_event = controller
        .emitted_events()
        .last()
        .expect("should have emitted event");
    assert!(
        matches!(bound_event, CoordinationEvent::SessionBound(_)),
        "Last event should be SessionBound, got {bound_event:?}"
    );

    // Verify spawner has NOT been called yet
    assert_eq!(
        spawner.spawn_count(),
        0,
        "Spawner should not be called before event is committed"
    );

    // NOW we call spawn (after binding is committed)
    spawner
        .spawn(&spawn_result.session_id, &work_id)
        .expect("spawn should succeed");

    // Verify spawner was called
    assert_eq!(spawner.spawn_count(), 1, "Spawner should be called once");

    // Verify the session_id matches
    let records = spawner.spawn_records();
    assert_eq!(records[0].session_id, spawn_result.session_id);
    assert_eq!(records[0].work_id, work_id);
}

/// TCK-00155: Proper event ordering throughout coordination lifecycle.
///
/// Verifies the event sequence:
/// 1. `coordination.started`
/// 2. For each work item: `session_bound` -> (spawn) -> `session_unbound`
/// 3. `coordination.completed` (or aborted)
#[test]
fn tck_00155_proper_event_ordering() {
    let config = create_test_config(vec!["work-1", "work-2"]);
    let mut controller = CoordinationController::new(config);
    let spawner = MockSessionSpawner::new();

    let events = run_coordination(&mut controller, &spawner);

    // Verify event sequence
    assert!(events.len() >= 6, "Should have at least 6 events");

    // First event should be Started
    assert!(
        matches!(events[0], CoordinationEvent::Started(_)),
        "First event should be Started"
    );

    // Last event should be Completed
    assert!(
        matches!(events.last().unwrap(), CoordinationEvent::Completed(_)),
        "Last event should be Completed"
    );

    // Verify bound/unbound pairs for each work item
    let mut bound_count = 0;
    let mut unbound_count = 0;

    for event in &events {
        match event {
            CoordinationEvent::SessionBound(_) => bound_count += 1,
            CoordinationEvent::SessionUnbound(_) => unbound_count += 1,
            _ => {},
        }
    }

    assert_eq!(
        bound_count, 2,
        "Should have 2 session_bound events (one per work item)"
    );
    assert_eq!(
        unbound_count, 2,
        "Should have 2 session_unbound events (one per work item)"
    );

    // Verify every bound is followed by its unbound (before next bound)
    let mut current_session: Option<String> = None;
    for event in &events {
        match event {
            CoordinationEvent::SessionBound(bound) => {
                assert!(current_session.is_none(), "Should not have nested bindings");
                current_session = Some(bound.session_id.clone());
            },
            CoordinationEvent::SessionUnbound(unbound) => {
                assert!(current_session.is_some(), "Unbound should follow bound");
                assert_eq!(
                    current_session.as_ref().unwrap(),
                    &unbound.session_id,
                    "Unbound session_id should match bound"
                );
                current_session = None;
            },
            _ => {},
        }
    }
}

/// TCK-00155: `MockSessionSpawner` correctly records spawns.
#[test]
fn tck_00155_mock_spawner_records_spawns() {
    let spawner = MockSessionSpawner::new();

    // Spawn multiple sessions
    spawner.spawn("sess-1", "work-1").unwrap();
    spawner.spawn("sess-2", "work-2").unwrap();
    spawner.spawn("sess-3", "work-1").unwrap();

    let records = spawner.spawn_records();

    assert_eq!(records.len(), 3);
    assert_eq!(records[0].session_id, "sess-1");
    assert_eq!(records[0].work_id, "work-1");
    assert_eq!(records[0].sequence, 0);

    assert_eq!(records[1].session_id, "sess-2");
    assert_eq!(records[1].work_id, "work-2");
    assert_eq!(records[1].sequence, 1);

    assert_eq!(records[2].session_id, "sess-3");
    assert_eq!(records[2].work_id, "work-1");
    assert_eq!(records[2].sequence, 2);
}

/// TCK-00155: `MockSessionSpawner` returns configured outcomes.
#[test]
fn tck_00155_mock_spawner_configured_outcomes() {
    let spawner = MockSessionSpawner::new();

    // Configure specific outcomes
    spawner.configure_outcome("work-1", ConfiguredOutcome::success(1000));
    spawner.configure_outcome("work-2", ConfiguredOutcome::failure(500));

    // Spawn sessions
    spawner.spawn("sess-1", "work-1").unwrap();
    spawner.spawn("sess-2", "work-2").unwrap();
    spawner.spawn("sess-3", "work-3").unwrap(); // Uses default

    // Observe terminations
    let term1 = spawner.observe_termination("sess-1").unwrap();
    let term2 = spawner.observe_termination("sess-2").unwrap();
    let term3 = spawner.observe_termination("sess-3").unwrap();

    assert!(matches!(term1.outcome, SessionOutcome::Success));
    assert_eq!(term1.tokens_consumed, 1000);

    assert!(matches!(term2.outcome, SessionOutcome::Failure));
    assert_eq!(term2.tokens_consumed, 500);

    // Default outcome is success with 1000 tokens
    assert!(matches!(term3.outcome, SessionOutcome::Success));
    assert_eq!(term3.tokens_consumed, 1000);
}

/// TCK-00155: `MockSessionSpawner` can be configured to fail spawns.
#[test]
fn tck_00155_mock_spawner_fail_spawn() {
    let spawner = MockSessionSpawner::new();

    // Configure to fail
    spawner.set_fail_spawn(true);

    let result = spawner.spawn("sess-1", "work-1");
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        SpawnError::SpawnFailed { .. }
    ));

    // Re-enable
    spawner.set_fail_spawn(false);

    let result = spawner.spawn("sess-2", "work-1");
    assert!(result.is_ok());
}

/// TCK-00155: Receipt can be stored in CAS and retrieved.
#[test]
fn tck_00155_receipt_cas_storage() {
    let cas = MemoryCas::new();
    let budget = create_test_budget();

    let mut builder = ReceiptBuilder::new("coord-test".to_string(), budget, 1_000_000_000);

    builder
        .record_work_outcome(
            WorkOutcome::new(
                "work-1".to_string(),
                1,
                SessionOutcome::Success,
                vec!["sess-1".to_string()],
            )
            .unwrap(),
        )
        .unwrap();

    builder.record_session(SessionOutcome::Success);

    let usage = apm2_core::coordination::BudgetUsage {
        consumed_episodes: 1,
        elapsed_ms: 1000,
        consumed_tokens: 1000,
    };

    let (receipt, canonical_hash, cas_hash) = builder
        .build_and_store(&cas, StopCondition::WorkCompleted, usage, 1_001_000_000)
        .unwrap();

    // Load from CAS
    let loaded = CoordinationReceipt::load(&cas, &cas_hash).unwrap();
    assert_eq!(receipt, loaded);

    // Verify canonical hash
    assert!(receipt.verify(&canonical_hash).is_ok());
}

/// TCK-00155: Coordination with failed work items.
#[test]
fn tck_00155_coordination_with_failures() {
    let config = create_test_config(vec!["work-1", "work-2"]);
    let mut controller = CoordinationController::new(config);
    let spawner = MockSessionSpawner::new();

    // Configure work-1 to fail (will exhaust retries)
    spawner.configure_outcome("work-1", ConfiguredOutcome::failure(100));
    spawner.configure_outcome("work-1", ConfiguredOutcome::failure(100));
    spawner.configure_outcome("work-1", ConfiguredOutcome::failure(100));
    // work-2 succeeds
    spawner.configure_outcome("work-2", ConfiguredOutcome::success(1000));

    let events = run_coordination(&mut controller, &spawner);

    // Count bound/unbound events
    let mut bound_count = 0;
    let mut unbound_count = 0;
    for event in &events {
        match event {
            CoordinationEvent::SessionBound(_) => bound_count += 1,
            CoordinationEvent::SessionUnbound(_) => unbound_count += 1,
            _ => {},
        }
    }

    // work-1 should have 3 attempts, work-2 should have 1
    assert_eq!(
        bound_count, 4,
        "Should have 4 session_bound events (3 for work-1, 1 for work-2)"
    );
    assert_eq!(unbound_count, 4, "Should have 4 session_unbound events");

    // Verify spawner was called 4 times
    assert_eq!(spawner.spawn_count(), 4);
}

/// TCK-00155: `SessionSpawner` trait is Send + Sync.
#[test]
fn tck_00155_session_spawner_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    fn assert_trait_object_send_sync<T: SessionSpawner + ?Sized>() {}

    assert_send_sync::<MockSessionSpawner>();

    // Also verify the trait object is Send + Sync
    assert_trait_object_send_sync::<dyn SessionSpawner>();
}

/// TCK-00155: `SpawnError` is properly formatted.
#[test]
fn tck_00155_spawn_error_display() {
    let errors = vec![
        (
            SpawnError::SpawnFailed {
                reason: "test reason".to_string(),
            },
            "session spawn failed: test reason",
        ),
        (
            SpawnError::ObservationTimeout {
                session_id: "sess-123".to_string(),
            },
            "session observation timed out for session sess-123",
        ),
        (
            SpawnError::SessionNotFound {
                session_id: "sess-456".to_string(),
            },
            "session not found: sess-456",
        ),
        (
            SpawnError::Internal {
                message: "something went wrong".to_string(),
            },
            "internal error: something went wrong",
        ),
    ];

    for (error, expected) in errors {
        assert_eq!(error.to_string(), expected);
    }
}

/// TCK-00155: `SessionTerminationInfo` helpers work correctly.
#[test]
fn tck_00155_session_termination_info_helpers() {
    let success = SessionTerminationInfo::success("sess-1", 1000);
    assert!(matches!(success.outcome, SessionOutcome::Success));
    assert_eq!(success.session_id, "sess-1");
    assert_eq!(success.tokens_consumed, 1000);

    let failure = SessionTerminationInfo::failure("sess-2", 500);
    assert!(matches!(failure.outcome, SessionOutcome::Failure));
    assert_eq!(failure.session_id, "sess-2");
    assert_eq!(failure.tokens_consumed, 500);
}

/// TCK-00155: Receipt hash changes with content changes.
#[test]
fn tck_00155_receipt_hash_changes_with_content() {
    let budget = create_test_budget();

    let builder1 = ReceiptBuilder::new("coord-1".to_string(), budget.clone(), 1_000_000_000);
    let receipt1 = builder1.build(
        StopCondition::WorkCompleted,
        apm2_core::coordination::BudgetUsage::new(),
        1_001_000_000,
    );

    let builder2 = ReceiptBuilder::new("coord-2".to_string(), budget, 1_000_000_000);
    let receipt2 = builder2.build(
        StopCondition::WorkCompleted,
        apm2_core::coordination::BudgetUsage::new(),
        1_001_000_000,
    );

    // Different coordination IDs should produce different hashes
    assert_ne!(
        receipt1.compute_hash(),
        receipt2.compute_hash(),
        "Different receipts should have different hashes"
    );
}
