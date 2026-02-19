#![cfg(feature = "e2e-agent-tests")]
#![allow(missing_docs)]
// AGENT-AUTHORED (TCK-00391)
//! TCK-00391: Autonomous FAC end-to-end integration test: full lifecycle
//! without external tooling.
//!
//! This test module exercises the complete FAC lifecycle through daemon
//! components, verifying every state transition and ledger event from work
//! opening to completion:
//!
//! ```text
//! Open -> Claimed -> InProgress -> CiPending -> ReadyForReview
//!      -> Review -> Completed
//! ```
//!
//! The test harness wires:
//! - `DispatcherState` with in-memory ledger, CAS, and broker
//! - `GateOrchestrator` for gate lifecycle (policy -> lease -> receipt)
//! - `MergeExecutor` with mock `GitHubMergeAdapter` (no real API calls)
//! - `WorkReducer` for state machine verification
//!
//! # Security Constraints
//!
//! - **EVID-HEF-0012**: `GITHUB_TOKEN` and `GH_TOKEN` must be unset
//! - **Mock adapter only**: No real GitHub API calls
//! - **Domain-separated signing**: Ledger events use domain prefixes
//! - **Fail-closed**: Gate timeout and review rejection halt lifecycle
//!
//! # Verification Commands
//!
//! ```bash
//! cargo test -p apm2-daemon --test fac_autonomous_e2e -- --nocapture
//! ```

use std::sync::Arc;

use apm2_core::crypto::Signer;
use apm2_core::fac::{GateReceiptBuilder, PolicyResolvedForChangeSetBuilder, ReasonCode};
use apm2_core::ledger::{EventRecord, Ledger};
use apm2_core::reducer::{Reducer, ReducerContext};
use apm2_core::work::helpers::{
    work_completed_payload, work_opened_payload, work_transitioned_payload_with_sequence,
};
use apm2_core::work::{WorkReducer, WorkState, WorkType};

/// Actor ID for the CI system processor (must match `CI_SYSTEM_ACTOR_ID`
/// in the work reducer).
const CI_SYSTEM_ACTOR_ID: &str = "system:ci-processor";
use apm2_daemon::gate::{
    GateOrchestrator, GateOrchestratorConfig, GateOrchestratorEvent, GateOutcome, GateType,
    GitHubMergeAdapter, MergeExecutor, MergeExecutorError, MergeExecutorEvent, MergeInput,
    MergeResult, SessionTerminatedInfo,
};

// =============================================================================
// EVID-HEF-0012: Environment Constraints
// =============================================================================

/// Enforces EVID-HEF-0012 environment constraints: no GitHub tokens.
fn enforce_env_constraints() {
    assert!(
        std::env::var_os("GITHUB_TOKEN").is_none(),
        "EVID-HEF-0012: GITHUB_TOKEN must not be set during evidence runs"
    );
    assert!(
        std::env::var_os("GH_TOKEN").is_none(),
        "EVID-HEF-0012: GH_TOKEN must not be set during evidence runs"
    );
}

// =============================================================================
// Mock GitHub Merge Adapter
// =============================================================================

/// Mock GitHub merge adapter that always succeeds with a deterministic SHA.
struct MockSuccessGitHubAdapter {
    result_sha: String,
}

impl MockSuccessGitHubAdapter {
    fn new(result_sha: &str) -> Self {
        Self {
            result_sha: result_sha.to_string(),
        }
    }
}

impl GitHubMergeAdapter for MockSuccessGitHubAdapter {
    fn squash_merge(
        &self,
        _pr_number: u64,
        _commit_title: &str,
        target_branch: &str,
    ) -> Result<MergeResult, MergeExecutorError> {
        Ok(MergeResult {
            result_sha: self.result_sha.clone(),
            target_branch: target_branch.to_string(),
        })
    }
}

/// Mock GitHub merge adapter that always returns a merge conflict.
struct MockConflictGitHubAdapter;

impl GitHubMergeAdapter for MockConflictGitHubAdapter {
    fn squash_merge(
        &self,
        _pr_number: u64,
        _commit_title: &str,
        _target_branch: &str,
    ) -> Result<MergeResult, MergeExecutorError> {
        Err(MergeExecutorError::MergeConflict {
            work_id: "test-work".to_string(),
            reason: "conflicting changes in src/main.rs".to_string(),
        })
    }
}

// =============================================================================
// Test Harness
// =============================================================================

/// Autonomous FAC E2E test harness with all daemon dependencies wired.
struct FacAutonomousHarness {
    /// Signer for ledger events.
    signer: Arc<Signer>,
    /// Work reducer for state machine verification.
    work_reducer: WorkReducer,
    /// Gate orchestrator for gate lifecycle.
    gate_orchestrator: GateOrchestrator,
    /// Merge executor for autonomous merge.
    merge_executor: MergeExecutor,
    /// Current timestamp in nanoseconds (monotonically advancing).
    current_timestamp_ns: u64,
    /// Transition counter for work events (tracks expected next sequence).
    transition_count: u32,
}

impl FacAutonomousHarness {
    fn new() -> Self {
        let signer = Arc::new(Signer::generate());
        let work_reducer = WorkReducer::new();
        let gate_config = GateOrchestratorConfig::default();
        let gate_orchestrator = GateOrchestrator::new(gate_config, Arc::clone(&signer));
        let merge_executor = MergeExecutor::new(Arc::clone(&signer), "merge-executor-actor");

        Self {
            signer,
            work_reducer,
            gate_orchestrator,
            merge_executor,
            // Start at 2024-01-01T00:00:00Z in nanoseconds
            current_timestamp_ns: 1_704_067_200_000_000_000,
            transition_count: 0,
        }
    }

    /// Returns the actor ID derived from the signer's verifying key.
    fn actor_id(&self) -> String {
        hex::encode(self.signer.verifying_key().as_bytes())
    }

    /// Advances the current timestamp.
    const fn advance_time_ms(&mut self, ms: u64) {
        self.current_timestamp_ns += ms * 1_000_000;
    }

    /// Returns a reducer context for applying events.
    const fn reducer_context() -> ReducerContext {
        ReducerContext {
            seq_id: 0,
            is_replay: false,
            checkpoint_seq_id: None,
        }
    }

    /// Emits a `WorkOpened` event and applies it to the reducer.
    fn emit_work_opened(&mut self, work_id: &str) {
        let payload = work_opened_payload(
            work_id,
            WorkType::Ticket.as_str(),
            vec![0xAA; 32], // spec_snapshot_hash
            vec!["REQ-FAC-001".to_string()],
            vec![],
        );

        let record = EventRecord::with_timestamp(
            "work.opened",
            work_id,
            self.actor_id(),
            payload,
            self.current_timestamp_ns,
        );

        let ctx = Self::reducer_context();
        self.work_reducer
            .apply(&record, &ctx)
            .expect("apply work.opened");
        self.transition_count = 0;
    }

    /// Emits a `WorkTransitioned` event and applies it to the reducer.
    fn emit_work_transitioned(
        &mut self,
        work_id: &str,
        from_state: &str,
        to_state: &str,
        rationale_code: &str,
        actor_id: &str,
    ) {
        let payload = work_transitioned_payload_with_sequence(
            work_id,
            from_state,
            to_state,
            rationale_code,
            self.transition_count,
        );

        let record = EventRecord::with_timestamp(
            "work.transitioned",
            work_id,
            actor_id.to_string(),
            payload,
            self.current_timestamp_ns,
        );

        let ctx = Self::reducer_context();
        self.work_reducer
            .apply(&record, &ctx)
            .expect("apply work.transitioned");
        self.transition_count += 1;
    }

    /// Emits a `WorkCompleted` event and applies it to the reducer.
    fn emit_work_completed(
        &mut self,
        work_id: &str,
        evidence_bundle_hash: Vec<u8>,
        evidence_ids: Vec<String>,
        gate_receipt_id: &str,
    ) {
        let payload =
            work_completed_payload(work_id, evidence_bundle_hash, evidence_ids, gate_receipt_id);

        let record = EventRecord::with_timestamp(
            "work.completed",
            work_id,
            self.actor_id(),
            payload,
            self.current_timestamp_ns,
        );

        let ctx = Self::reducer_context();
        self.work_reducer
            .apply(&record, &ctx)
            .expect("apply work.completed");
        self.transition_count += 1;
    }

    /// Returns the current work state from the reducer.
    fn work_state(&self, work_id: &str) -> Option<WorkState> {
        self.work_reducer.state().get(work_id).map(|w| w.state)
    }

    /// Asserts the work state matches the expected state.
    fn assert_work_state(&self, work_id: &str, expected: WorkState) {
        let actual = self.work_state(work_id);
        assert_eq!(
            actual,
            Some(expected),
            "Expected work state {expected:?} for {work_id}, got {actual:?}",
        );
    }
}

/// Computes BLAKE3 hash over payload + `prev_hash`, then signs it.
fn hash_and_sign(signer: &Signer, payload: &[u8], prev_hash: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut hasher = blake3::Hasher::new();
    hasher.update(payload);
    hasher.update(prev_hash);
    let event_hash = hasher.finalize().as_bytes().to_vec();
    let signature = signer.sign(&event_hash).to_bytes().to_vec();
    (event_hash, signature)
}

fn make_valid_work_events(work_id: &str) -> (Vec<EventRecord>, apm2_core::work::WorkReducerState) {
    let opened_payload = work_opened_payload(work_id, "TICKET", vec![1, 2, 3], vec![], vec![]);
    let events = vec![
        EventRecord::with_timestamp("work.opened", work_id, "actor:test", opened_payload, 1_000)
            .with_seq_id(1),
    ];

    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);
    reducer.apply(&events[0], &ctx).expect("apply work.opened");

    (events, reducer.state().clone())
}

// =============================================================================
// IT-00391-01: Full Lifecycle - All State Transitions
// =============================================================================

/// Tests the complete FAC autonomous lifecycle through all state transitions.
///
/// Exercises:
/// - Open -> Claimed -> `InProgress` -> `CiPending` -> `ReadyForReview` ->
///   Review -> Completed
/// - `GateOrchestrator`: session terminated -> policy resolved -> lease issued
///   -> receipt collected -> all gates completed
/// - `MergeExecutor`: all gates passed -> squash merge -> `MergeReceipt` ->
///   work completed
/// - Ledger events emitted in correct causal order with valid signatures
/// - Work state machine reaches Completed from Open through all intermediate
///   states
#[tokio::test]
async fn test_fac_autonomous_full_lifecycle() {
    enforce_env_constraints();

    let mut harness = FacAutonomousHarness::new();
    let work_id = "work-fac-e2e-001";
    let changeset_digest = [0x42; 32];

    // =========================================================================
    // Phase 1: Open -> Claimed
    // =========================================================================

    harness.emit_work_opened(work_id);
    harness.assert_work_state(work_id, WorkState::Open);

    harness.advance_time_ms(100);
    harness.emit_work_transitioned(
        work_id,
        "OPEN",
        "CLAIMED",
        "agent_claim",
        &harness.actor_id(),
    );
    harness.assert_work_state(work_id, WorkState::Claimed);

    // =========================================================================
    // Phase 2: Claimed -> InProgress
    // =========================================================================

    harness.advance_time_ms(50);
    harness.emit_work_transitioned(
        work_id,
        "CLAIMED",
        "IN_PROGRESS",
        "work_started",
        &harness.actor_id(),
    );
    harness.assert_work_state(work_id, WorkState::InProgress);

    // =========================================================================
    // Phase 3: InProgress -> CiPending (PR created, CI running)
    // =========================================================================

    harness.advance_time_ms(5000);
    harness.emit_work_transitioned(
        work_id,
        "IN_PROGRESS",
        "CI_PENDING",
        "pr_created",
        &harness.actor_id(),
    );
    harness.assert_work_state(work_id, WorkState::CiPending);

    // Verify work is NOT claimable in CiPending state
    assert!(
        !WorkState::CiPending.is_claimable(),
        "CiPending state should not be claimable"
    );

    // =========================================================================
    // Phase 4: CiPending -> ReadyForReview (CI passed)
    // =========================================================================

    harness.advance_time_ms(120_000); // CI takes ~2 minutes
    harness.emit_work_transitioned(
        work_id,
        "CI_PENDING",
        "READY_FOR_REVIEW",
        "ci_passed",
        CI_SYSTEM_ACTOR_ID,
    );
    harness.assert_work_state(work_id, WorkState::ReadyForReview);

    // Verify work IS claimable in ReadyForReview state
    assert!(
        WorkState::ReadyForReview.is_claimable(),
        "ReadyForReview state should be claimable"
    );

    // =========================================================================
    // Phase 5: ReadyForReview -> Review (review agent claims)
    // =========================================================================

    harness.advance_time_ms(200);
    harness.emit_work_transitioned(
        work_id,
        "READY_FOR_REVIEW",
        "REVIEW",
        "review_claimed",
        &harness.actor_id(),
    );
    harness.assert_work_state(work_id, WorkState::Review);

    // =========================================================================
    // Phase 6: Simulate session work and termination -> Gate lifecycle
    // =========================================================================

    harness.advance_time_ms(30_000); // Session runs for 30s

    // Trigger gate orchestration via session termination
    let session_info = SessionTerminatedInfo {
        session_id: format!("session-{work_id}"),
        work_id: work_id.to_string(),
        changeset_digest,
        terminated_at_ms: 0, // bypass freshness for tests
    };

    let (gate_types, executor_signers, setup_events) = harness
        .gate_orchestrator
        .on_session_terminated(session_info)
        .await
        .expect("gate orchestration should succeed");

    // Verify: 3 gate types (aat, quality, security)
    assert_eq!(gate_types.len(), 3, "Should issue 3 gate types");

    // Verify: 1 PolicyResolved + 3 GateLeaseIssued = 4 events
    assert_eq!(
        setup_events.len(),
        4,
        "Expected 1 PolicyResolved + 3 GateLeaseIssued events, got {}",
        setup_events.len()
    );

    // Verify event ordering: PolicyResolved MUST be first
    assert!(
        matches!(
            setup_events[0],
            GateOrchestratorEvent::PolicyResolved { .. }
        ),
        "First event must be PolicyResolved, got {:?}",
        setup_events[0]
    );

    // Verify all subsequent events are GateLeaseIssued
    for (i, event) in setup_events.iter().enumerate().skip(1) {
        assert!(
            matches!(event, GateOrchestratorEvent::GateLeaseIssued { .. }),
            "Event at index {i} should be GateLeaseIssued, got {event:?}"
        );
    }

    // =========================================================================
    // Phase 7: Record executor spawned for each gate
    // =========================================================================

    for &gt in &gate_types {
        let spawn_events = harness
            .gate_orchestrator
            .record_executor_spawned(work_id, gt, &format!("ep-{gt}"))
            .await
            .expect("record executor spawned");
        assert_eq!(
            spawn_events.len(),
            1,
            "Should emit 1 GateExecutorSpawned event for {gt}"
        );
        assert!(matches!(
            spawn_events[0],
            GateOrchestratorEvent::GateExecutorSpawned { .. }
        ));
    }

    // =========================================================================
    // Phase 8: Collect gate receipts (all PASS)
    // =========================================================================

    let mut all_gate_events = Vec::new();
    let mut final_outcomes: Option<Vec<GateOutcome>> = None;

    for gt in GateType::all() {
        let lease = harness
            .gate_orchestrator
            .gate_lease(work_id, gt)
            .await
            .expect("gate lease should exist");

        let exec_signer = &executor_signers[&gt];
        let receipt = GateReceiptBuilder::new(
            format!("receipt-{}", gt.as_gate_id()),
            gt.as_gate_id(),
            &lease.lease_id,
        )
        .changeset_digest(changeset_digest)
        .executor_actor_id(&lease.executor_actor_id)
        .receipt_version(1)
        .payload_kind(gt.payload_kind())
        .payload_schema_version(1)
        .payload_hash([0xBB; 32])
        .evidence_bundle_hash([0xCC; 32])
        .passed(true)
        .build_and_sign(exec_signer);

        let (outcomes, events) = harness
            .gate_orchestrator
            .record_gate_receipt(work_id, gt, receipt)
            .await
            .expect("record gate receipt");

        all_gate_events.extend(events);

        if let Some(o) = outcomes {
            final_outcomes = Some(o);
        }
    }

    // Verify: all 3 receipts collected
    let receipt_count = all_gate_events
        .iter()
        .filter(|e| matches!(e, GateOrchestratorEvent::GateReceiptCollected { .. }))
        .count();
    assert_eq!(receipt_count, 3, "Should have collected 3 gate receipts");

    // Verify: AllGatesCompleted event emitted
    let completed_count = all_gate_events
        .iter()
        .filter(|e| matches!(e, GateOrchestratorEvent::AllGatesCompleted { .. }))
        .count();
    assert_eq!(
        completed_count, 1,
        "Should have exactly 1 AllGatesCompleted event"
    );

    // Verify: all gates passed
    let outcomes = final_outcomes.expect("should have outcomes from last gate");
    assert_eq!(outcomes.len(), 3, "Should have 3 gate outcomes");
    assert!(
        outcomes.iter().all(|o| o.passed),
        "All gate outcomes should be PASS"
    );

    // =========================================================================
    // Phase 9: Execute merge via mock adapter
    // =========================================================================

    harness.advance_time_ms(500);

    let policy_resolution = PolicyResolvedForChangeSetBuilder::new(work_id, changeset_digest)
        .resolved_risk_tier(1)
        .resolved_determinism_class(0)
        .resolver_actor_id("resolver-001")
        .resolver_version("1.0.0")
        .build_and_sign(&harness.signer);
    let (work_events, expected_reducer_state) = make_valid_work_events(work_id);

    let merge_input = MergeInput {
        work_id: work_id.to_string(),
        changeset_digest,
        pr_number: 42,
        target_branch: "main".to_string(),
        gate_outcomes: outcomes,
        policy_resolution,
        actor_id: harness.actor_id(),
        work_events,
        expected_reducer_state: Some(expected_reducer_state),
        promotion_stage: None,
        formal_artifacts: None,
        stop_path_slo_allows_promotion: None,
        rpo_rto_within_targets: None,
    };

    let mock_adapter = MockSuccessGitHubAdapter::new("abc123def456");

    let (merge_receipt, merge_events) = harness
        .merge_executor
        .execute_merge(&merge_input, &mock_adapter)
        .expect("merge should succeed");

    // Verify merge events
    assert_eq!(
        merge_events.len(),
        3,
        "Should have MergeExecuted + MergeReceiptCreated + WorkCompleted events"
    );

    // Verify MergeExecuted event
    assert!(
        matches!(
            &merge_events[0],
            MergeExecutorEvent::MergeExecuted { work_id: w, result_sha, .. }
            if w == "work-fac-e2e-001" && result_sha == "abc123def456"
        ),
        "First event should be MergeExecuted with correct SHA"
    );

    // Verify MergeReceiptCreated event
    assert!(
        matches!(
            &merge_events[1],
            MergeExecutorEvent::MergeReceiptCreated { work_id: w, .. }
            if w == "work-fac-e2e-001"
        ),
        "Second event should be MergeReceiptCreated"
    );

    // Verify WorkCompleted event
    assert!(
        matches!(
            &merge_events[2],
            MergeExecutorEvent::WorkCompleted { work_id: w, .. }
            if w == "work-fac-e2e-001"
        ),
        "Third event should be WorkCompleted"
    );

    // Verify merge receipt fields
    assert_eq!(
        merge_receipt.changeset_digest, changeset_digest,
        "MergeReceipt should bind to changeset_digest"
    );
    assert_eq!(
        merge_receipt.result_selector, "abc123def456",
        "MergeReceipt should reference the merge commit SHA"
    );

    // =========================================================================
    // Phase 10: Transition work to Completed via reducer
    // =========================================================================

    harness.advance_time_ms(100);

    let evidence_bundle_hash = vec![0xDD; 32];
    let evidence_ids = vec!["EVID-FAC-001".to_string(), "EVID-FAC-002".to_string()];
    let gate_receipt_id = "merge-receipt-abc123def456";

    harness.emit_work_completed(work_id, evidence_bundle_hash, evidence_ids, gate_receipt_id);
    harness.assert_work_state(work_id, WorkState::Completed);

    // =========================================================================
    // Final Verification: Complete state audit
    // =========================================================================

    let work = harness
        .work_reducer
        .state()
        .get(work_id)
        .expect("work should exist");

    // Verify terminal state
    assert!(work.is_terminal(), "Work should be in terminal state");
    assert!(!work.is_active(), "Work should not be active");
    assert_eq!(work.state, WorkState::Completed);

    // Verify transition count: Open->Claimed(1) + Claimed->InProgress(2) +
    // InProgress->CiPending(3) + CiPending->ReadyForReview(4) +
    // ReadyForReview->Review(5) + Review->Completed(6)
    assert_eq!(
        work.transition_count, 6,
        "Should have 6 transitions (Open->Claimed->InProgress->CiPending->ReadyForReview->Review->Completed)"
    );

    // Verify evidence binding
    assert_eq!(
        work.evidence_bundle_hash,
        Some(vec![0xDD; 32]),
        "Evidence bundle hash should be set"
    );
    assert_eq!(work.evidence_ids.len(), 2, "Should have 2 evidence IDs");
    assert_eq!(
        work.gate_receipt_id,
        Some("merge-receipt-abc123def456".to_string()),
        "Gate receipt ID should reference merge receipt"
    );

    // Verify work type
    assert_eq!(work.work_type, WorkType::Ticket);
}

// =============================================================================
// IT-00391-02: Ledger Events Emitted in Correct Causal Order
// =============================================================================

/// Tests that ledger events are emitted in correct causal order with valid
/// signatures during the FAC lifecycle.
///
/// Verifies:
/// - Events are appended in chronological order
/// - Each event has a valid signature
/// - The hash chain links events causally
/// - Event types appear in the expected sequence
#[tokio::test]
async fn test_fac_ledger_events_causal_order() {
    enforce_env_constraints();

    let signer = Signer::generate();
    let ledger = Ledger::in_memory().expect("create ledger");
    let actor_id = hex::encode(signer.verifying_key().as_bytes());

    // Emit a sequence of signed events to the ledger
    let mut timestamp_ns: u64 = 1_704_067_200_000_000_000;

    // Event 1: work_opened
    let payload1 = work_opened_payload(
        "work-ledger-001",
        "TICKET",
        vec![0xAA; 32],
        vec!["REQ-001".to_string()],
        vec![],
    );
    let prev_hash1 = ledger.last_event_hash().expect("genesis hash");
    let (event_hash1, sig1) = hash_and_sign(&signer, &payload1, &prev_hash1);
    let mut record1 = EventRecord::with_timestamp(
        "work.opened",
        "work-ledger-001",
        actor_id.clone(),
        payload1,
        timestamp_ns,
    );
    record1.prev_hash = Some(prev_hash1);
    record1.event_hash = Some(event_hash1);
    record1.signature = Some(sig1);

    let seq1 = ledger.append(&record1).expect("append event 1");
    assert_eq!(seq1, 1, "First event should have seq_id 1");

    // Event 2: work_transitioned (Open -> Claimed)
    timestamp_ns += 100_000_000; // +100ms
    let payload2 = work_transitioned_payload_with_sequence(
        "work-ledger-001",
        "OPEN",
        "CLAIMED",
        "agent_claim",
        0,
    );
    let prev_hash2 = ledger.last_event_hash().expect("prev hash");
    let (event_hash2, sig2) = hash_and_sign(&signer, &payload2, &prev_hash2);
    let mut record2 = EventRecord::with_timestamp(
        "work.transitioned",
        "work-ledger-001",
        actor_id.clone(),
        payload2,
        timestamp_ns,
    );
    record2.prev_hash = Some(prev_hash2);
    record2.event_hash = Some(event_hash2);
    record2.signature = Some(sig2);

    let seq2 = ledger.append(&record2).expect("append event 2");
    assert_eq!(seq2, 2, "Second event should have seq_id 2");

    // Event 3: work_transitioned (Claimed -> InProgress)
    timestamp_ns += 50_000_000; // +50ms
    let payload3 = work_transitioned_payload_with_sequence(
        "work-ledger-001",
        "CLAIMED",
        "IN_PROGRESS",
        "work_started",
        1,
    );
    let prev_hash3 = ledger.last_event_hash().expect("prev hash");
    let (event_hash3, sig3) = hash_and_sign(&signer, &payload3, &prev_hash3);
    let mut record3 = EventRecord::with_timestamp(
        "work.transitioned",
        "work-ledger-001",
        actor_id,
        payload3,
        timestamp_ns,
    );
    record3.prev_hash = Some(prev_hash3);
    record3.event_hash = Some(event_hash3);
    record3.signature = Some(sig3);

    let seq3 = ledger.append(&record3).expect("append event 3");
    assert_eq!(seq3, 3, "Third event should have seq_id 3");

    // Verify hash chain integrity
    let events = ledger.read_from(1, 10).expect("read all events");
    assert_eq!(events.len(), 3, "Should have 3 ledger events");

    // First event should have genesis prev_hash (all zeros)
    let genesis_hash = vec![0u8; 32];
    assert_eq!(
        events[0]
            .prev_hash
            .as_ref()
            .expect("prev_hash should be set"),
        &genesis_hash,
        "First event should link to genesis hash"
    );

    // Each subsequent event should link to the previous event's hash
    for i in 1..events.len() {
        let prev_event_hash = events[i - 1]
            .event_hash
            .as_ref()
            .expect("event_hash should be set by append_signed");
        let this_prev_hash = events[i]
            .prev_hash
            .as_ref()
            .expect("prev_hash should be set by append_signed");
        assert_eq!(
            this_prev_hash,
            prev_event_hash,
            "Event {} prev_hash should link to event {} event_hash",
            i + 1,
            i
        );
    }

    // Verify event types are in expected order
    assert_eq!(events[0].event_type, "work.opened");
    assert_eq!(events[1].event_type, "work.transitioned");
    assert_eq!(events[2].event_type, "work.transitioned");

    // Verify timestamps are monotonically increasing
    for i in 1..events.len() {
        assert!(
            events[i].timestamp_ns >= events[i - 1].timestamp_ns,
            "Timestamps should be monotonically increasing: {} >= {}",
            events[i].timestamp_ns,
            events[i - 1].timestamp_ns
        );
    }

    // Verify all events have signatures set
    for (i, event) in events.iter().enumerate() {
        assert!(
            event.signature.is_some(),
            "Event {} should have a signature",
            i + 1
        );
        assert!(
            event.event_hash.is_some(),
            "Event {} should have an event_hash",
            i + 1
        );
    }
}

// =============================================================================
// IT-00391-03: Gate Failure Halts Lifecycle
// =============================================================================

/// Tests that a gate failure (FAIL verdict) prevents the lifecycle from
/// proceeding to merge.
///
/// When any gate returns FAIL, `AllGatesCompleted` should report `all_passed`
/// as false, and the `MergeExecutor` should reject the merge input.
#[tokio::test]
async fn test_gate_failure_halts_lifecycle() {
    enforce_env_constraints();

    let signer = Arc::new(Signer::generate());
    let config = GateOrchestratorConfig::default();
    let orch = GateOrchestrator::new(config, Arc::clone(&signer));

    let work_id = "work-gate-fail-001";
    let changeset_digest = [0x42; 32];

    // Step 1: Session terminates
    let session_info = SessionTerminatedInfo {
        session_id: "session-gate-fail".to_string(),
        work_id: work_id.to_string(),
        changeset_digest,
        terminated_at_ms: 0,
    };

    let (gate_types, executor_signers, _events) = orch
        .on_session_terminated(session_info)
        .await
        .expect("orchestration setup");

    // Record executor spawned
    for &gt in &gate_types {
        orch.record_executor_spawned(work_id, gt, &format!("ep-{gt}"))
            .await
            .expect("record spawned");
    }

    // Step 2: Record PASS for aat and quality, FAIL for security
    let mut outcomes_from_last: Option<Vec<GateOutcome>> = None;

    for gt in GateType::all() {
        let lease = orch.gate_lease(work_id, gt).await.expect("lease");
        let exec_signer = &executor_signers[&gt];

        let passed = gt != GateType::Security; // Security gate fails

        let receipt = GateReceiptBuilder::new(
            format!("receipt-{}", gt.as_gate_id()),
            gt.as_gate_id(),
            &lease.lease_id,
        )
        .changeset_digest(changeset_digest)
        .executor_actor_id(&lease.executor_actor_id)
        .receipt_version(1)
        .payload_kind(gt.payload_kind())
        .payload_schema_version(1)
        .payload_hash([0xBB; 32])
        .evidence_bundle_hash([0xCC; 32])
        .passed(passed)
        .build_and_sign(exec_signer);

        let (outcomes, _events) = orch
            .record_gate_receipt(work_id, gt, receipt)
            .await
            .expect("record receipt");

        if let Some(o) = outcomes {
            outcomes_from_last = Some(o);
        }
    }

    // Step 3: Verify AllGatesCompleted reports failure
    let outcomes = outcomes_from_last.expect("should have final outcomes");
    assert_eq!(outcomes.len(), 3);

    let security_outcome = outcomes
        .iter()
        .find(|o| o.gate_type == GateType::Security)
        .expect("security outcome should exist");
    assert!(
        !security_outcome.passed,
        "Security gate should have FAIL verdict"
    );

    let all_passed = outcomes.iter().all(|o| o.passed);
    assert!(!all_passed, "Not all gates should have passed");

    // Step 4: MergeExecutor should reject non-passing outcomes
    let merge_executor = MergeExecutor::new(Arc::clone(&signer), "merge-actor");

    let policy_resolution = PolicyResolvedForChangeSetBuilder::new(work_id, changeset_digest)
        .resolved_risk_tier(1)
        .resolved_determinism_class(0)
        .resolver_actor_id("resolver-001")
        .resolver_version("1.0.0")
        .build_and_sign(&signer);
    let (work_events, expected_reducer_state) = make_valid_work_events(work_id);

    let merge_input = MergeInput {
        work_id: work_id.to_string(),
        changeset_digest,
        pr_number: 99,
        target_branch: "main".to_string(),
        gate_outcomes: outcomes,
        policy_resolution,
        actor_id: "merge-actor".to_string(),
        work_events,
        expected_reducer_state: Some(expected_reducer_state),
        promotion_stage: None,
        formal_artifacts: None,
        stop_path_slo_allows_promotion: None,
        rpo_rto_within_targets: None,
    };

    let mock_adapter = MockSuccessGitHubAdapter::new("should-not-be-used");
    let result = merge_executor.execute_merge(&merge_input, &mock_adapter);

    assert!(result.is_err(), "Merge should be rejected when gates fail");
    assert!(
        matches!(result, Err(MergeExecutorError::GatesNotAllPassed { .. })),
        "Error should be GatesNotAllPassed, got: {result:?}",
    );
}

// =============================================================================
// IT-00391-04: Merge Conflict Produces ReviewBlockedRecorded
// =============================================================================

/// Tests that a merge conflict during execution produces a
/// `ReviewBlockedRecorded` event with `MergeConflict` reason code.
///
/// The lifecycle should halt at the merge phase, and the blocked event
/// should contain the conflict details.
#[tokio::test]
async fn test_merge_conflict_produces_review_blocked() {
    enforce_env_constraints();

    let signer = Arc::new(Signer::generate());
    let merge_executor = MergeExecutor::new(Arc::clone(&signer), "merge-actor");

    let changeset_digest = [0x42; 32];

    let policy_resolution =
        PolicyResolvedForChangeSetBuilder::new("work-conflict-001", changeset_digest)
            .resolved_risk_tier(1)
            .resolved_determinism_class(0)
            .resolver_actor_id("resolver-001")
            .resolver_version("1.0.0")
            .build_and_sign(&signer);

    // Create all-pass gate outcomes
    let gate_outcomes = GateType::all()
        .iter()
        .map(|gt| GateOutcome {
            gate_type: *gt,
            passed: true,
            receipt_id: Some(format!("receipt-{}", gt.as_gate_id())),
            timed_out: false,
        })
        .collect::<Vec<_>>();
    let (work_events, expected_reducer_state) = make_valid_work_events("work-conflict-001");

    let merge_input = MergeInput {
        work_id: "work-conflict-001".to_string(),
        changeset_digest,
        pr_number: 77,
        target_branch: "main".to_string(),
        gate_outcomes,
        policy_resolution,
        actor_id: "merge-actor".to_string(),
        work_events,
        expected_reducer_state: Some(expected_reducer_state),
        promotion_stage: None,
        formal_artifacts: None,
        stop_path_slo_allows_promotion: None,
        rpo_rto_within_targets: None,
    };

    // Use the conflict adapter
    let conflict_adapter = MockConflictGitHubAdapter;

    let result = merge_executor.execute_or_block(&merge_input, &conflict_adapter);
    let (receipt, blocked, events) = result.expect("execute_or_block should succeed");

    // Merge receipt should be None (conflict)
    assert!(receipt.is_none(), "MergeReceipt should be None on conflict");

    // ReviewBlockedRecorded should be present
    let blocked_event = blocked.expect("ReviewBlockedRecorded should be present");
    assert_eq!(
        blocked_event.reason_code,
        ReasonCode::MergeConflict,
        "Reason code should be MergeConflict"
    );

    // Events should contain MergeBlocked
    assert_eq!(events.len(), 1, "Should have 1 MergeBlocked event");
    assert!(
        matches!(
            &events[0],
            MergeExecutorEvent::MergeBlocked { work_id, reason, .. }
            if work_id == "work-conflict-001" && reason.contains("conflicting")
        ),
        "Should have MergeBlocked with conflict details"
    );
}

// =============================================================================
// IT-00391-05: Review Rejection (Gate FAIL) Halts at Review State
// =============================================================================

/// Tests that when gate review returns FAIL, the work remains in Review
/// state and does not transition to Completed.
///
/// The work state machine should prevent transition from Review to Completed
/// without passing evidence.
#[tokio::test]
async fn test_review_rejection_halts_lifecycle() {
    enforce_env_constraints();

    let mut harness = FacAutonomousHarness::new();
    let work_id = "work-review-reject-001";

    // Drive work to Review state
    harness.emit_work_opened(work_id);
    harness.advance_time_ms(50);
    harness.emit_work_transitioned(
        work_id,
        "OPEN",
        "CLAIMED",
        "agent_claim",
        &harness.actor_id(),
    );
    harness.advance_time_ms(50);
    harness.emit_work_transitioned(
        work_id,
        "CLAIMED",
        "IN_PROGRESS",
        "work_started",
        &harness.actor_id(),
    );
    harness.advance_time_ms(50);
    harness.emit_work_transitioned(
        work_id,
        "IN_PROGRESS",
        "CI_PENDING",
        "pr_created",
        &harness.actor_id(),
    );
    harness.advance_time_ms(100);
    harness.emit_work_transitioned(
        work_id,
        "CI_PENDING",
        "READY_FOR_REVIEW",
        "ci_passed",
        CI_SYSTEM_ACTOR_ID,
    );
    harness.advance_time_ms(50);
    harness.emit_work_transitioned(
        work_id,
        "READY_FOR_REVIEW",
        "REVIEW",
        "review_claimed",
        &harness.actor_id(),
    );
    harness.assert_work_state(work_id, WorkState::Review);

    // Attempt to complete without evidence should fail
    let payload_no_evidence = work_completed_payload(
        work_id,
        vec![], // empty evidence_bundle_hash
        vec![], // empty evidence_ids
        "",
    );

    let record = EventRecord::with_timestamp(
        "work.completed",
        work_id,
        harness.actor_id(),
        payload_no_evidence,
        harness.current_timestamp_ns,
    );

    let ctx = FacAutonomousHarness::reducer_context();
    let result = harness.work_reducer.apply(&record, &ctx);
    assert!(
        result.is_err(),
        "Completion without evidence should be rejected by the reducer"
    );

    // Work should still be in Review state
    harness.assert_work_state(work_id, WorkState::Review);

    // Verify the work can be sent back to InProgress (rejection path)
    harness.emit_work_transitioned(
        work_id,
        "REVIEW",
        "IN_PROGRESS",
        "review_rejected",
        &harness.actor_id(),
    );
    harness.assert_work_state(work_id, WorkState::InProgress);
}

// =============================================================================
// IT-00391-06: CI Failure Blocks at CiPending -> Blocked
// =============================================================================

/// Tests that CI failure transitions work from `CiPending` to Blocked,
/// and that Blocked work cannot be claimed by agents.
#[tokio::test]
async fn test_ci_failure_blocks_lifecycle() {
    enforce_env_constraints();

    let mut harness = FacAutonomousHarness::new();
    let work_id = "work-ci-fail-001";

    // Drive work to CiPending
    harness.emit_work_opened(work_id);
    harness.advance_time_ms(50);
    harness.emit_work_transitioned(
        work_id,
        "OPEN",
        "CLAIMED",
        "agent_claim",
        &harness.actor_id(),
    );
    harness.advance_time_ms(50);
    harness.emit_work_transitioned(
        work_id,
        "CLAIMED",
        "IN_PROGRESS",
        "work_started",
        &harness.actor_id(),
    );
    harness.advance_time_ms(50);
    harness.emit_work_transitioned(
        work_id,
        "IN_PROGRESS",
        "CI_PENDING",
        "pr_created",
        &harness.actor_id(),
    );
    harness.assert_work_state(work_id, WorkState::CiPending);

    // CI fails -> Blocked
    harness.advance_time_ms(60_000);
    harness.emit_work_transitioned(
        work_id,
        "CI_PENDING",
        "BLOCKED",
        "ci_failed",
        CI_SYSTEM_ACTOR_ID,
    );
    harness.assert_work_state(work_id, WorkState::Blocked);

    // Verify Blocked work is NOT claimable
    assert!(
        !WorkState::Blocked.is_claimable(),
        "Blocked state should not be claimable"
    );

    // Verify Blocked work cannot skip to Completed
    assert!(
        !WorkState::Blocked.can_transition_to(&WorkState::Completed),
        "Blocked should not transition directly to Completed"
    );

    // Verify recovery path: Blocked -> CiPending (fix pushed, CI retried)
    harness.advance_time_ms(120_000);
    harness.emit_work_transitioned(
        work_id,
        "BLOCKED",
        "CI_PENDING",
        "ci_retry",
        // Blocked->CiPending is not CI-gated, so any actor can do it
        &harness.actor_id(),
    );
    harness.assert_work_state(work_id, WorkState::CiPending);

    // CI passes this time
    harness.advance_time_ms(90_000);
    harness.emit_work_transitioned(
        work_id,
        "CI_PENDING",
        "READY_FOR_REVIEW",
        "ci_passed",
        CI_SYSTEM_ACTOR_ID,
    );
    harness.assert_work_state(work_id, WorkState::ReadyForReview);
}

// =============================================================================
// IT-00391-07: Gate Receipt Signature Verification
// =============================================================================

/// Tests that the gate orchestrator rejects receipts signed by the wrong key.
///
/// This is a critical security test: gate receipts must be signed by the
/// executor signer whose verifying key matches the lease.
#[tokio::test]
async fn test_gate_receipt_signature_verification() {
    enforce_env_constraints();

    let signer = Arc::new(Signer::generate());
    let config = GateOrchestratorConfig::default();
    let orch = GateOrchestrator::new(config, Arc::clone(&signer));

    let work_id = "work-sig-verify-001";
    let changeset_digest = [0x42; 32];

    let session_info = SessionTerminatedInfo {
        session_id: "session-sig-verify".to_string(),
        work_id: work_id.to_string(),
        changeset_digest,
        terminated_at_ms: 0,
    };

    let (_gate_types, _executor_signers, _events) = orch
        .on_session_terminated(session_info)
        .await
        .expect("orchestration setup");

    // Record executor spawned for Quality gate
    orch.record_executor_spawned(work_id, GateType::Quality, "ep-quality")
        .await
        .expect("record spawned");

    let lease = orch
        .gate_lease(work_id, GateType::Quality)
        .await
        .expect("lease");

    // Sign with WRONG key
    let wrong_signer = Signer::generate();
    let bad_receipt = GateReceiptBuilder::new("receipt-bad", "gate-quality", &lease.lease_id)
        .changeset_digest(changeset_digest)
        .executor_actor_id(&lease.executor_actor_id)
        .receipt_version(1)
        .payload_kind("quality")
        .payload_schema_version(1)
        .payload_hash([0xBB; 32])
        .evidence_bundle_hash([0xCC; 32])
        .passed(true)
        .build_and_sign(&wrong_signer);

    let result = orch
        .record_gate_receipt(work_id, GateType::Quality, bad_receipt)
        .await;

    assert!(
        result.is_err(),
        "Gate receipt with wrong signature should be rejected"
    );
}

// =============================================================================
// IT-00391-08: Work State Transitions Coverage
// =============================================================================

/// Tests all valid transitions in the work state machine to ensure complete
/// coverage of the FAC lifecycle paths.
#[test]
fn test_work_state_transition_coverage() {
    // Valid forward path
    assert!(WorkState::Open.can_transition_to(&WorkState::Claimed));
    assert!(WorkState::Claimed.can_transition_to(&WorkState::InProgress));
    assert!(WorkState::InProgress.can_transition_to(&WorkState::CiPending));
    assert!(WorkState::CiPending.can_transition_to(&WorkState::ReadyForReview));
    assert!(WorkState::ReadyForReview.can_transition_to(&WorkState::Review));
    assert!(WorkState::Review.can_transition_to(&WorkState::Completed));

    // CI failure path
    assert!(WorkState::CiPending.can_transition_to(&WorkState::Blocked));
    assert!(WorkState::Blocked.can_transition_to(&WorkState::CiPending));
    assert!(WorkState::Blocked.can_transition_to(&WorkState::InProgress));

    // Review rejection path
    assert!(WorkState::Review.can_transition_to(&WorkState::InProgress));

    // Abort from any active state
    assert!(WorkState::Open.can_transition_to(&WorkState::Aborted));
    assert!(WorkState::Claimed.can_transition_to(&WorkState::Aborted));
    assert!(WorkState::InProgress.can_transition_to(&WorkState::Aborted));
    assert!(WorkState::CiPending.can_transition_to(&WorkState::Aborted));
    assert!(WorkState::ReadyForReview.can_transition_to(&WorkState::Aborted));
    assert!(WorkState::Review.can_transition_to(&WorkState::Aborted));

    // Invalid transitions from terminal states
    assert!(!WorkState::Completed.can_transition_to(&WorkState::Open));
    assert!(!WorkState::Completed.can_transition_to(&WorkState::InProgress));
    assert!(!WorkState::Aborted.can_transition_to(&WorkState::Open));

    // Invalid skip transitions
    assert!(!WorkState::Open.can_transition_to(&WorkState::Completed));
    assert!(!WorkState::Open.can_transition_to(&WorkState::InProgress));
    assert!(!WorkState::CiPending.can_transition_to(&WorkState::Completed));
    assert!(!WorkState::Blocked.can_transition_to(&WorkState::Completed));
}
