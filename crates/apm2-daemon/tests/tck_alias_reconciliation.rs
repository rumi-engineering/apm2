//! TCK-00420: Alias reconciliation and snapshot-emitter sunset integration
//! tests.
//!
//! Validates that:
//! - Alias/`work_id` projection mismatch count is zero at promotion gate when
//!   projections are consistent.
//! - Mismatched aliases produce defects that block promotion (fail-closed).
//! - Ambiguous aliases (multiple `work_id` values for one alias) always block
//!   promotion.
//! - Temporal inversions (tick regression) are treated as stale (fail-closed).
//! - Runtime authority decisions remain `work_id`-centric throughout the
//!   observation window.
//! - Snapshot-emitter sunset evaluation integrates with reconciliation state.
//!
//! Evidence command: `cargo test -p apm2-daemon --tests
//! tck_alias_reconciliation -- --nocapture`

use std::collections::HashMap;
use std::sync::Arc;

use apm2_core::events::alias_reconcile::{
    DefectClass, Hash, ObservationWindow, SnapshotEmitterStatus, SnapshotSunsetCriteria,
    TicketAliasBinding, promotion_gate, reconcile_aliases,
};
use apm2_daemon::protocol::dispatch::WorkTransition;
use apm2_daemon::protocol::{LedgerEventEmitter, PrivilegedDispatcher};
use apm2_daemon::work::authority::{
    AliasReconciliationGate, ProjectionAliasReconciliationGate, ProjectionWorkAuthority,
    WorkAuthority, work_id_to_hash,
};

const fn make_hash(byte: u8) -> Hash {
    [byte; 32]
}

fn make_binding(alias: &str, work_id_byte: u8) -> TicketAliasBinding {
    TicketAliasBinding {
        ticket_alias: alias.to_string(),
        canonical_work_id: make_hash(work_id_byte),
        observed_at_tick: 100,
        observation_window_start: 90,
        observation_window_end: 110,
    }
}

#[allow(clippy::too_many_arguments)]
fn emit_transition(
    emitter: &dyn LedgerEventEmitter,
    work_id: &str,
    from_state: &str,
    to_state: &str,
    rationale_code: &str,
    previous_transition_count: u32,
    actor_id: &str,
    timestamp_ns: u64,
) {
    emitter
        .emit_work_transitioned(&WorkTransition {
            work_id,
            from_state,
            to_state,
            rationale_code,
            previous_transition_count,
            actor_id,
            timestamp_ns,
        })
        .expect("work transition should persist");
}

// ============================================================================
// Reconciliation gate integration tests
// ============================================================================

#[test]
fn tck_alias_reconciliation_mismatch_blocks_promotion() {
    // Verify that mismatched aliases produce defects that block promotion
    // via the production reconciliation path.
    let bindings = vec![make_binding("TCK-001", 0x01), make_binding("TCK-002", 0x02)];

    let mut projections: HashMap<String, Vec<Hash>> = HashMap::new();
    projections.insert("TCK-001".to_string(), vec![make_hash(0x01)]); // match
    projections.insert("TCK-002".to_string(), vec![make_hash(0xFF)]); // mismatch

    let result = reconcile_aliases(&bindings, &projections, 100);

    assert_eq!(result.resolved_count, 1);
    assert_eq!(result.unresolved_defects.len(), 1);
    assert_eq!(
        result.unresolved_defects[0].defect_class,
        DefectClass::Mismatch
    );
    assert!(
        !promotion_gate(&result),
        "promotion gate must block on mismatch (fail-closed)"
    );
}

#[test]
fn tck_alias_reconciliation_clean_projection_permits_promotion() {
    // When all aliases match, the promotion gate must pass.
    let bindings = vec![
        make_binding("TCK-001", 0x01),
        make_binding("TCK-002", 0x02),
        make_binding("TCK-003", 0x03),
    ];

    let mut projections: HashMap<String, Vec<Hash>> = HashMap::new();
    projections.insert("TCK-001".to_string(), vec![make_hash(0x01)]);
    projections.insert("TCK-002".to_string(), vec![make_hash(0x02)]);
    projections.insert("TCK-003".to_string(), vec![make_hash(0x03)]);

    let result = reconcile_aliases(&bindings, &projections, 100);

    assert_eq!(result.resolved_count, 3);
    assert!(result.unresolved_defects.is_empty());
    assert!(
        promotion_gate(&result),
        "promotion gate must pass on zero defects"
    );
}

#[test]
fn tck_alias_reconciliation_ambiguity_always_blocks_promotion() {
    // An alias that maps to multiple distinct work_ids must produce an
    // Ambiguous defect and block promotion (fail-closed).
    let bindings = vec![make_binding("TCK-AMBIG", 0x01)];

    let mut projections: HashMap<String, Vec<Hash>> = HashMap::new();
    projections.insert(
        "TCK-AMBIG".to_string(),
        vec![make_hash(0x01), make_hash(0x02)],
    );

    let result = reconcile_aliases(&bindings, &projections, 100);

    assert_eq!(result.resolved_count, 0);
    assert_eq!(result.unresolved_defects.len(), 1);
    assert_eq!(
        result.unresolved_defects[0].defect_class,
        DefectClass::Ambiguous,
        "ambiguous alias must produce Ambiguous defect"
    );
    assert!(
        !promotion_gate(&result),
        "ambiguity must always block promotion"
    );
}

#[test]
fn tck_alias_reconciliation_tick_regression_is_stale() {
    // Temporal inversion (current_tick < last_seen_tick) must be treated as
    // stale (fail-closed), not silently passed.
    let window = ObservationWindow {
        start_tick: 0,
        end_tick: 1000,
        max_staleness_ticks: 10,
    };

    // Tick regression scenarios
    assert!(
        window.is_stale(100, 50),
        "tick regression (100 -> 50) must be stale"
    );
    assert!(
        window.is_stale(200, 100),
        "tick regression (200 -> 100) must be stale"
    );
    assert!(
        window.is_stale(1, 0),
        "tick regression (1 -> 0) must be stale"
    );

    // Normal staleness still works
    assert!(
        window.is_stale(0, 100),
        "gap 100 > threshold 10 must be stale"
    );
    assert!(
        !window.is_stale(95, 100),
        "gap 5 <= threshold 10 must not be stale"
    );
}

// ============================================================================
// Work-ID-centric authority integration tests
// ============================================================================

#[test]
fn tck_alias_reconciliation_authority_remains_work_id_centric() {
    // Verify that work authority decisions are based on work_id, not on
    // ticket aliases. The alias reconciliation layer is advisory only.
    let dispatcher = PrivilegedDispatcher::new();
    let emitter = dispatcher.event_emitter();

    // Create work items via ledger events
    emit_transition(
        emitter.as_ref(),
        "W-AUTH-001",
        "Open",
        "Claimed",
        "claim",
        0,
        "actor:authority-test",
        1_000_000_000,
    );

    // Work authority must resolve by work_id, not alias
    let authority = ProjectionWorkAuthority::new(Arc::clone(emitter));
    let status = authority
        .get_work_status("W-AUTH-001")
        .expect("work status lookup by work_id must succeed");
    assert_eq!(status.work_id, "W-AUTH-001");
    assert_eq!(status.transition_count, 1);

    // Non-existent work_id must fail (authority is work_id-centric)
    let err = authority.get_work_status("TCK-00420-alias");
    assert!(
        err.is_err(),
        "ticket alias must not resolve in work authority"
    );
}

#[test]
fn tck_alias_reconciliation_gate_wired_to_projection() {
    // Verify the ProjectionAliasReconciliationGate wires correctly to the
    // daemon projection and produces real reconciliation results.
    let dispatcher = PrivilegedDispatcher::new();
    let emitter = dispatcher.event_emitter();

    // Emit work events to populate the projection
    emit_transition(
        emitter.as_ref(),
        "W-GATE-001",
        "Open",
        "Claimed",
        "claim",
        0,
        "actor:gate-test",
        1_000_000_000,
    );

    let gate = ProjectionAliasReconciliationGate::new(Arc::clone(emitter));

    // Create a binding that matches the projection's work_id hash
    let work_hash = work_id_to_hash("W-GATE-001");
    let binding = TicketAliasBinding {
        ticket_alias: "W-GATE-001".to_string(),
        canonical_work_id: work_hash,
        observed_at_tick: 100,
        observation_window_start: 90,
        observation_window_end: 110,
    };

    let result = gate
        .check_promotion(&[binding], 100)
        .expect("promotion check must not fail on infrastructure");
    assert_eq!(result.resolved_count, 1);
    assert!(result.unresolved_defects.is_empty());
    assert!(
        promotion_gate(&result),
        "consistent binding must pass promotion gate"
    );
}

#[test]
fn tck_alias_reconciliation_gate_blocks_on_mismatch() {
    // Verify the gate blocks promotion when a binding has a mismatched hash.
    let dispatcher = PrivilegedDispatcher::new();
    let emitter = dispatcher.event_emitter();

    emit_transition(
        emitter.as_ref(),
        "W-MISMATCH-001",
        "Open",
        "Claimed",
        "claim",
        0,
        "actor:mismatch-test",
        1_000_000_000,
    );

    let gate = ProjectionAliasReconciliationGate::new(Arc::clone(emitter));

    // Use an intentionally wrong hash to force mismatch
    let binding = TicketAliasBinding {
        ticket_alias: "W-MISMATCH-001".to_string(),
        canonical_work_id: [0xFF; 32], // wrong hash
        observed_at_tick: 100,
        observation_window_start: 90,
        observation_window_end: 110,
    };

    let result = gate
        .check_promotion(&[binding], 100)
        .expect("promotion check must not fail on infrastructure");
    assert!(
        !result.unresolved_defects.is_empty(),
        "mismatched binding must produce defects"
    );
    assert!(
        !promotion_gate(&result),
        "gate must block on mismatched binding"
    );
}

// ============================================================================
// Snapshot-emitter sunset integration tests
// ============================================================================

#[test]
fn tck_alias_reconciliation_sunset_evaluation_via_gate() {
    let dispatcher = PrivilegedDispatcher::new();
    let emitter = dispatcher.event_emitter();

    let gate = ProjectionAliasReconciliationGate::new(Arc::clone(emitter));

    // Clean ticks insufficient, has defects => Active
    assert_eq!(
        gate.evaluate_emitter_sunset(10, true),
        SnapshotEmitterStatus::Active,
    );

    // Clean ticks sufficient, has defects => SunsetPending
    assert_eq!(
        gate.evaluate_emitter_sunset(50, true),
        SnapshotEmitterStatus::SunsetPending,
    );

    // Clean ticks sufficient, no defects => Sunset
    assert_eq!(
        gate.evaluate_emitter_sunset(50, false),
        SnapshotEmitterStatus::Sunset,
    );
}

#[test]
fn tck_alias_reconciliation_sunset_with_custom_criteria() {
    let dispatcher = PrivilegedDispatcher::new();
    let emitter = dispatcher.event_emitter();

    let gate = ProjectionAliasReconciliationGate::with_config(
        Arc::clone(emitter),
        ObservationWindow {
            start_tick: 0,
            end_tick: 10_000,
            max_staleness_ticks: 50,
        },
        SnapshotSunsetCriteria {
            min_reconciled_ticks: 100,
            zero_defects_required: true,
        },
    );

    // Insufficient ticks
    assert_eq!(
        gate.evaluate_emitter_sunset(99, false),
        SnapshotEmitterStatus::SunsetPending,
    );

    // Sufficient ticks, no defects
    assert_eq!(
        gate.evaluate_emitter_sunset(100, false),
        SnapshotEmitterStatus::Sunset,
    );
}

// ============================================================================
// Multiple work items test (verifies projection-level reconciliation)
// ============================================================================

#[test]
fn tck_alias_reconciliation_multiple_work_items_projection() {
    let dispatcher = PrivilegedDispatcher::new();
    let emitter = dispatcher.event_emitter();

    // Populate three work items
    for (work_id, ts) in &[
        ("W-MULTI-001", 1_000_000_000u64),
        ("W-MULTI-002", 1_000_000_100),
        ("W-MULTI-003", 1_000_000_200),
    ] {
        emit_transition(
            emitter.as_ref(),
            work_id,
            "Open",
            "Claimed",
            "claim",
            0,
            "actor:multi-test",
            *ts,
        );
    }

    let gate = ProjectionAliasReconciliationGate::new(Arc::clone(emitter));

    // All three bindings match their projection hashes
    let bindings: Vec<TicketAliasBinding> = ["W-MULTI-001", "W-MULTI-002", "W-MULTI-003"]
        .iter()
        .map(|wid| TicketAliasBinding {
            ticket_alias: wid.to_string(),
            canonical_work_id: work_id_to_hash(wid),
            observed_at_tick: 200,
            observation_window_start: 100,
            observation_window_end: 300,
        })
        .collect();

    let result = gate
        .check_promotion(&bindings, 200)
        .expect("multi-item promotion check must succeed");
    assert_eq!(result.resolved_count, 3);
    assert!(result.unresolved_defects.is_empty());
    assert!(promotion_gate(&result));
}

#[test]
fn tck_alias_reconciliation_not_found_alias_blocks_promotion() {
    let dispatcher = PrivilegedDispatcher::new();
    let emitter = dispatcher.event_emitter();

    // Emit only one work item
    emit_transition(
        emitter.as_ref(),
        "W-EXIST-001",
        "Open",
        "Claimed",
        "claim",
        0,
        "actor:not-found-test",
        1_000_000_000,
    );

    let gate = ProjectionAliasReconciliationGate::new(Arc::clone(emitter));

    // Binding references a work_id that does NOT exist in the projection
    let binding = TicketAliasBinding {
        ticket_alias: "W-NONEXIST-999".to_string(),
        canonical_work_id: work_id_to_hash("W-NONEXIST-999"),
        observed_at_tick: 100,
        observation_window_start: 90,
        observation_window_end: 110,
    };

    let result = gate
        .check_promotion(&[binding], 100)
        .expect("promotion check must succeed");
    assert_eq!(result.unresolved_defects.len(), 1);
    assert_eq!(
        result.unresolved_defects[0].defect_class,
        DefectClass::NotFound,
    );
    assert!(!promotion_gate(&result));
}

// ============================================================================
// Staleness enforcement in check_promotion (BLOCKER 2 fix)
// ============================================================================

#[test]
fn tck_alias_reconciliation_staleness_blocks_promotion() {
    // Verify that check_promotion enforces staleness detection fail-closed.
    // A binding with observed_at_tick far in the past (relative to
    // current_tick) must produce a Stale defect even if hash matches.
    let dispatcher = PrivilegedDispatcher::new();
    let emitter = dispatcher.event_emitter();

    emit_transition(
        emitter.as_ref(),
        "W-STALE-001",
        "Open",
        "Claimed",
        "claim",
        0,
        "actor:stale-test",
        1_000_000_000,
    );

    // Use a gate with tight staleness threshold (10 ticks).
    let gate = ProjectionAliasReconciliationGate::with_config(
        Arc::clone(emitter),
        ObservationWindow {
            start_tick: 0,
            end_tick: 100_000,
            max_staleness_ticks: 10,
        },
        SnapshotSunsetCriteria {
            min_reconciled_ticks: 50,
            zero_defects_required: true,
        },
    );

    // Binding observed at tick 50, but current tick is 200.
    // Gap = 200 - 50 = 150 > max_staleness_ticks (10) => stale.
    let binding = TicketAliasBinding {
        ticket_alias: "W-STALE-001".to_string(),
        canonical_work_id: work_id_to_hash("W-STALE-001"),
        observed_at_tick: 50,
        observation_window_start: 40,
        observation_window_end: 60,
    };

    let result = gate
        .check_promotion(&[binding], 200)
        .expect("promotion check must succeed on infrastructure");

    // Must produce a Stale defect
    let has_stale = result
        .unresolved_defects
        .iter()
        .any(|d| d.defect_class == DefectClass::Stale);
    assert!(
        has_stale,
        "stale binding must produce Stale defect (fail-closed)"
    );
    assert!(
        !promotion_gate(&result),
        "stale binding must block promotion"
    );
}

#[test]
fn tck_alias_reconciliation_fresh_binding_passes_staleness_check() {
    // Verify that a fresh binding does NOT produce a Stale defect.
    let dispatcher = PrivilegedDispatcher::new();
    let emitter = dispatcher.event_emitter();

    emit_transition(
        emitter.as_ref(),
        "W-FRESH-001",
        "Open",
        "Claimed",
        "claim",
        0,
        "actor:fresh-test",
        1_000_000_000,
    );

    let gate = ProjectionAliasReconciliationGate::with_config(
        Arc::clone(emitter),
        ObservationWindow {
            start_tick: 0,
            end_tick: 100_000,
            max_staleness_ticks: 10,
        },
        SnapshotSunsetCriteria {
            min_reconciled_ticks: 50,
            zero_defects_required: true,
        },
    );

    // Binding observed at tick 195, current tick is 200.
    // Gap = 200 - 195 = 5 <= max_staleness_ticks (10) => NOT stale.
    let binding = TicketAliasBinding {
        ticket_alias: "W-FRESH-001".to_string(),
        canonical_work_id: work_id_to_hash("W-FRESH-001"),
        observed_at_tick: 195,
        observation_window_start: 190,
        observation_window_end: 210,
    };

    let result = gate
        .check_promotion(&[binding], 200)
        .expect("promotion check must succeed");

    assert!(result.unresolved_defects.is_empty());
    assert_eq!(result.resolved_count, 1);
    assert!(
        promotion_gate(&result),
        "fresh binding with matching hash must pass"
    );
}

#[test]
fn tck_alias_reconciliation_tick_regression_blocks_via_check_promotion() {
    // Verify that temporal inversion (current_tick < observed_at_tick)
    // produces a Stale defect through the production check_promotion path.
    let dispatcher = PrivilegedDispatcher::new();
    let emitter = dispatcher.event_emitter();

    emit_transition(
        emitter.as_ref(),
        "W-REGRESS-001",
        "Open",
        "Claimed",
        "claim",
        0,
        "actor:regress-test",
        1_000_000_000,
    );

    let gate = ProjectionAliasReconciliationGate::with_config(
        Arc::clone(emitter),
        ObservationWindow {
            start_tick: 0,
            end_tick: 100_000,
            max_staleness_ticks: 10,
        },
        SnapshotSunsetCriteria {
            min_reconciled_ticks: 50,
            zero_defects_required: true,
        },
    );

    // Temporal inversion: binding observed at tick 200, but current is 100.
    let binding = TicketAliasBinding {
        ticket_alias: "W-REGRESS-001".to_string(),
        canonical_work_id: work_id_to_hash("W-REGRESS-001"),
        observed_at_tick: 200,
        observation_window_start: 190,
        observation_window_end: 210,
    };

    let result = gate
        .check_promotion(&[binding], 100)
        .expect("promotion check must succeed on infrastructure");

    let has_stale = result
        .unresolved_defects
        .iter()
        .any(|d| d.defect_class == DefectClass::Stale);
    assert!(
        has_stale,
        "tick regression must produce Stale defect (fail-closed)"
    );
    assert!(
        !promotion_gate(&result),
        "tick regression must block promotion"
    );
}

// ============================================================================
// Dispatcher gate wiring tests (BLOCKER 3 fix)
// ============================================================================

#[test]
fn tck_alias_reconciliation_dispatcher_gate_accessible() {
    // Verify the PrivilegedDispatcher exposes the alias reconciliation gate
    // and that it produces valid results when invoked directly.
    let dispatcher = PrivilegedDispatcher::new();
    let emitter = dispatcher.event_emitter();

    emit_transition(
        emitter.as_ref(),
        "W-DISPATCH-001",
        "Open",
        "Claimed",
        "claim",
        0,
        "actor:dispatch-gate-test",
        1_000_000_000,
    );

    let gate = dispatcher.alias_reconciliation_gate();
    let binding = TicketAliasBinding {
        ticket_alias: "W-DISPATCH-001".to_string(),
        canonical_work_id: work_id_to_hash("W-DISPATCH-001"),
        observed_at_tick: 100,
        observation_window_start: 90,
        observation_window_end: 110,
    };

    let result = gate
        .check_promotion(&[binding], 100)
        .expect("dispatcher gate must produce valid results");
    assert_eq!(result.resolved_count, 1);
    assert!(result.unresolved_defects.is_empty());
    assert!(promotion_gate(&result));
}

#[test]
fn tck_alias_reconciliation_dispatcher_gate_blocks_mismatch() {
    // Verify the dispatcher's gate blocks on mismatched hashes.
    let dispatcher = PrivilegedDispatcher::new();
    let emitter = dispatcher.event_emitter();

    emit_transition(
        emitter.as_ref(),
        "W-DISPATCH-MISMATCH",
        "Open",
        "Claimed",
        "claim",
        0,
        "actor:dispatch-mismatch",
        1_000_000_000,
    );

    let gate = dispatcher.alias_reconciliation_gate();
    let binding = TicketAliasBinding {
        ticket_alias: "W-DISPATCH-MISMATCH".to_string(),
        canonical_work_id: [0xFF; 32], // wrong hash
        observed_at_tick: 100,
        observation_window_start: 90,
        observation_window_end: 110,
    };

    let result = gate
        .check_promotion(&[binding], 100)
        .expect("gate must not fail on infrastructure");
    assert!(
        !result.unresolved_defects.is_empty(),
        "mismatched binding must produce defects via dispatcher gate"
    );
    assert!(!promotion_gate(&result));
}
