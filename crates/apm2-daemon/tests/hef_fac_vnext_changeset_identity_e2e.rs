#![allow(missing_docs)]

use std::sync::{Arc, Mutex};

use apm2_core::crypto::Signer;
use apm2_core::ledger::EventRecord;
use apm2_core::reducer::{Reducer, ReducerContext};
use apm2_core::work::{WorkReducer, WorkState, helpers as work_helpers};
use apm2_daemon::gate::{
    GateOrchestrator, GateOrchestratorConfig, GateStartKernel, GateStartKernelConfig, GateType,
};
use apm2_daemon::ledger::SqliteLedgerEventEmitter;
use apm2_daemon::protocol::dispatch::LedgerEventEmitter;
use rusqlite::Connection;
use tempfile::TempDir;

const CI_SYSTEM_ACTOR_ID: &str = "system:ci-processor";

fn make_emitter(conn: Arc<Mutex<Connection>>, key_seed: u8) -> SqliteLedgerEventEmitter {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[key_seed; 32]);
    SqliteLedgerEventEmitter::new(conn, signing_key)
}

/// Emits a digest-bound event through the ledger emitter (canonical persistence
/// path), then reads the persisted row back and applies it to the reducer.
///
/// This replaces the previous `apply_digest_event` helper that bypassed
/// canonical ledger storage by constructing synthetic `EventRecord` inputs
/// and calling `reducer.apply(...)` directly. The new implementation
/// exercises the full daemon event path:
///   emit -> ledger persist -> read -> reduce
///
/// This is required by CSID-005 (end-to-end integration coverage).
#[allow(clippy::too_many_arguments)]
fn emit_and_apply_digest_event(
    emitter: &SqliteLedgerEventEmitter,
    conn: &Arc<Mutex<Connection>>,
    reducer: &mut WorkReducer,
    ctx: &ReducerContext,
    event_type: &str,
    work_id: &str,
    digest: [u8; 32],
    timestamp_ns: u64,
) {
    let payload = serde_json::to_vec(&serde_json::json!({
        "event_type": event_type,
        "work_id": work_id,
        "changeset_digest": hex::encode(digest),
    }))
    .expect("serialize digest event payload");
    // Emit through canonical ledger path (persist to SQLite).
    emitter
        .emit_session_event(
            work_id,
            event_type,
            &payload,
            "actor:fac-kernel",
            timestamp_ns,
        )
        .expect("emit digest-bound event through ledger");

    // Read the persisted event back from the ledger and apply to reducer.
    // This proves the full persistence -> replay path.
    let guard = conn.lock().expect("lock sqlite for read-back");
    let (read_payload, read_ts, read_actor): (Vec<u8>, i64, String) = guard
        .query_row(
            "SELECT payload, timestamp_ns, actor_id FROM ledger_events
             WHERE event_type = ?1
             ORDER BY rowid DESC LIMIT 1",
            rusqlite::params![event_type],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("read persisted event from ledger");
    drop(guard);
    let record = EventRecord::with_timestamp(
        event_type,
        work_id,
        &read_actor,
        read_payload,
        u64::try_from(read_ts).expect("timestamp positive"),
    );
    reducer
        .apply(&record, ctx)
        .expect("apply ledger-persisted digest-bound event");
}

struct TransitionSpec<'a> {
    from_state: &'a str,
    to_state: &'a str,
    rationale_code: &'a str,
    previous_transition_count: u32,
    actor_id: &'a str,
}

/// Emits a work.transitioned event through the ledger, then reads back and
/// applies to the reducer (CSID-005 canonical path).
fn emit_and_apply_work_transition(
    emitter: &SqliteLedgerEventEmitter,
    conn: &Arc<Mutex<Connection>>,
    reducer: &mut WorkReducer,
    ctx: &ReducerContext,
    work_id: &str,
    spec: &TransitionSpec<'_>,
    timestamp_ns: u64,
) {
    let payload = work_helpers::work_transitioned_payload_with_sequence(
        work_id,
        spec.from_state,
        spec.to_state,
        spec.rationale_code,
        spec.previous_transition_count,
    );
    // Persist through canonical ledger path.
    emitter
        .emit_session_event(
            work_id,
            "work.transitioned",
            &payload,
            spec.actor_id,
            timestamp_ns,
        )
        .expect("emit work.transitioned through ledger");

    // Read back and apply.
    let guard = conn.lock().expect("lock sqlite for transition read-back");
    let (read_payload, read_ts, read_actor): (Vec<u8>, i64, String) = guard
        .query_row(
            "SELECT payload, timestamp_ns, actor_id FROM ledger_events
             WHERE event_type = 'work.transitioned'
             ORDER BY rowid DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("read persisted work.transitioned from ledger");
    drop(guard);
    let record = EventRecord::with_timestamp(
        "work.transitioned",
        work_id,
        &read_actor,
        read_payload,
        u64::try_from(read_ts).expect("timestamp positive"),
    );
    reducer
        .apply(&record, ctx)
        .expect("apply ledger-persisted work.transitioned");
}

fn setup_ci_pending(
    emitter: &SqliteLedgerEventEmitter,
    conn: &Arc<Mutex<Connection>>,
    reducer: &mut WorkReducer,
    ctx: &ReducerContext,
    work_id: &str,
    base_ts: u64,
) {
    let opened = work_helpers::work_opened_payload(work_id, "TICKET", vec![1], vec![], vec![]);
    // Emit work.opened through the canonical ledger path.
    emitter
        .emit_session_event(
            work_id,
            "work.opened",
            &opened,
            "actor:implementer",
            base_ts,
        )
        .expect("emit work.opened through ledger");
    {
        let guard = conn.lock().expect("lock sqlite for work.opened read-back");
        let (read_payload, read_ts, read_actor): (Vec<u8>, i64, String) = guard
            .query_row(
                "SELECT payload, timestamp_ns, actor_id FROM ledger_events
                 WHERE event_type = 'work.opened'
                 ORDER BY rowid DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("read persisted work.opened from ledger");
        drop(guard);
        let record = EventRecord::with_timestamp(
            "work.opened",
            work_id,
            &read_actor,
            read_payload,
            u64::try_from(read_ts).expect("timestamp positive"),
        );
        reducer
            .apply(&record, ctx)
            .expect("apply ledger-persisted work.opened");
    }

    emit_and_apply_work_transition(
        emitter,
        conn,
        reducer,
        ctx,
        work_id,
        &TransitionSpec {
            from_state: "OPEN",
            to_state: "CLAIMED",
            rationale_code: "agent_claimed",
            previous_transition_count: 0,
            actor_id: "actor:implementer",
        },
        base_ts + 1,
    );
    emit_and_apply_work_transition(
        emitter,
        conn,
        reducer,
        ctx,
        work_id,
        &TransitionSpec {
            from_state: "CLAIMED",
            to_state: "IN_PROGRESS",
            rationale_code: "episode_spawned",
            previous_transition_count: 1,
            actor_id: "actor:implementer",
        },
        base_ts + 2,
    );
    emit_and_apply_work_transition(
        emitter,
        conn,
        reducer,
        ctx,
        work_id,
        &TransitionSpec {
            from_state: "IN_PROGRESS",
            to_state: "CI_PENDING",
            rationale_code: "pr_created",
            previous_transition_count: 2,
            actor_id: "actor:implementer",
        },
        base_ts + 3,
    );
}

#[tokio::test]
async fn hef_fac_vnext_changeset_identity_e2e() {
    let sqlite = Arc::new(Mutex::new(
        Connection::open_in_memory().expect("open in-memory sqlite"),
    ));
    {
        let guard = sqlite.lock().expect("lock sqlite for schema init");
        SqliteLedgerEventEmitter::init_schema_for_test(&guard).expect("initialize ledger schema");
    }
    let publish_emitter = make_emitter(Arc::clone(&sqlite), 0x11);
    let kernel_emitter = make_emitter(Arc::clone(&sqlite), 0x12);

    let gate_orchestrator = Arc::new(GateOrchestrator::new(
        GateOrchestratorConfig::default(),
        Arc::new(Signer::generate()),
    ));
    let fac_root = TempDir::new().expect("create temp fac root");
    let mut gate_start_kernel = GateStartKernel::new(
        Arc::clone(&gate_orchestrator),
        Some(&sqlite),
        Some(kernel_emitter),
        fac_root.path(),
        GateStartKernelConfig::default(),
    )
    .expect("create gate start kernel");

    let work_id = "W-hef-fac-vnext-csid-e2e";
    let published_digest = [0x44; 32];
    let bundle_cas_hash = [0x55; 32];
    // STEP_06 assertion 1: ChangeSetPublished event exists for (W, D) with cas_hash
    // == H
    let published_event = publish_emitter
        .emit_changeset_published(
            work_id,
            &published_digest,
            &bundle_cas_hash,
            "actor:publish",
            1_706_000_000_123_000_000,
        )
        .expect("emit changeset_published");
    assert_eq!(
        published_event.event_type, "changeset_published",
        "STEP_06 assertion 1: ChangeSetPublished event must exist for (W, D)"
    );

    let report = gate_start_kernel
        .tick()
        .await
        .expect("gate start kernel tick succeeds");
    assert_eq!(
        report.completed_intents, 1,
        "one changeset publication should complete"
    );

    // STEP_06 assertion 3: all GateLeaseIssued have changeset_digest == D
    for gate_type in GateType::all() {
        let lease = gate_orchestrator
            .gate_lease(work_id, gate_type)
            .await
            .expect("gate lease should exist after gate start");
        assert_eq!(
            lease.changeset_digest, published_digest,
            "STEP_06 assertion 3: gate lease for {gate_type:?} must have changeset_digest == D",
        );
    }

    // =========================================================================
    // STEP_06 assertions 2-7: drive full identity chain through the work
    // reducer, asserting each stage uses the SAME published digest D.
    // =========================================================================

    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);
    setup_ci_pending(
        &publish_emitter,
        &sqlite,
        &mut reducer,
        &ctx,
        work_id,
        2_000_000_000,
    );

    // STEP_06 assertion 2: work_latest_changeset(W) == D
    emit_and_apply_digest_event(
        &publish_emitter,
        &sqlite,
        &mut reducer,
        &ctx,
        "changeset_published",
        work_id,
        published_digest,
        2_000_000_100,
    );
    assert_eq!(
        reducer
            .state()
            .latest_changeset_by_work
            .get(work_id)
            .copied(),
        Some(published_digest),
        "STEP_06 assertion 2: work_latest_changeset(W) must equal published digest D"
    );

    // STEP_06 assertion 4: gate receipts have changeset_digest == D
    emit_and_apply_digest_event(
        &publish_emitter,
        &sqlite,
        &mut reducer,
        &ctx,
        "gate.receipt_collected",
        work_id,
        published_digest,
        2_000_000_200,
    );
    assert_eq!(
        reducer
            .state()
            .ci_receipt_digest_by_work
            .get(work_id)
            .copied(),
        Some(published_digest),
        "STEP_06 assertion 4: gate receipt digest must equal published digest D"
    );

    // STEP_06 assertion 5: work transitions to ReadyForReview only from
    // receipts bound to D
    emit_and_apply_work_transition(
        &publish_emitter,
        &sqlite,
        &mut reducer,
        &ctx,
        work_id,
        &TransitionSpec {
            from_state: "CI_PENDING",
            to_state: "READY_FOR_REVIEW",
            rationale_code: "ci_passed",
            previous_transition_count: 3,
            actor_id: CI_SYSTEM_ACTOR_ID,
        },
        2_000_000_300,
    );
    assert_eq!(
        reducer
            .state()
            .get(work_id)
            .expect("work should exist")
            .state,
        WorkState::ReadyForReview,
        "STEP_06 assertion 5: CI transition admitted only for receipts bound to digest D"
    );

    // Review start transition (ReadyForReview -> Review)
    emit_and_apply_work_transition(
        &publish_emitter,
        &sqlite,
        &mut reducer,
        &ctx,
        work_id,
        &TransitionSpec {
            from_state: "READY_FOR_REVIEW",
            to_state: "REVIEW",
            rationale_code: "review_claimed",
            previous_transition_count: 4,
            actor_id: "actor:reviewer",
        },
        2_000_000_400,
    );
    assert_eq!(
        reducer
            .state()
            .get(work_id)
            .expect("work should exist")
            .state,
        WorkState::Review,
        "review start must be admitted when latest changeset is known"
    );

    // STEP_06 assertion 6: review receipt has changeset_digest == D
    emit_and_apply_digest_event(
        &publish_emitter,
        &sqlite,
        &mut reducer,
        &ctx,
        "review_receipt_recorded",
        work_id,
        published_digest,
        2_000_000_500,
    );
    assert_eq!(
        reducer
            .state()
            .review_receipt_digest_by_work
            .get(work_id)
            .copied(),
        Some(published_digest),
        "STEP_06 assertion 6: review receipt digest must equal published digest D"
    );

    // STEP_06 assertion 7: merge receipt has changeset_digest == D
    emit_and_apply_digest_event(
        &publish_emitter,
        &sqlite,
        &mut reducer,
        &ctx,
        "merge_receipt_recorded",
        work_id,
        published_digest,
        2_000_000_600,
    );
    assert_eq!(
        reducer
            .state()
            .merge_receipt_digest_by_work
            .get(work_id)
            .copied(),
        Some(published_digest),
        "STEP_06 assertion 7: merge receipt digest must equal published digest D"
    );

    // Work completion with latest-digest merge admission
    {
        let completed = work_helpers::work_completed_payload(
            work_id,
            vec![1],
            vec!["evidence-1".to_string()],
            "gate-receipt-quality-1",
            "merge-receipt-sha111",
        );
        publish_emitter
            .emit_session_event(
                work_id,
                "work.completed",
                &completed,
                "actor:merge",
                2_000_000_700,
            )
            .expect("emit work.completed through ledger");
        let guard = sqlite
            .lock()
            .expect("lock sqlite for work.completed read-back");
        let (read_payload, read_ts, read_actor): (Vec<u8>, i64, String) = guard
            .query_row(
                "SELECT payload, timestamp_ns, actor_id FROM ledger_events
                 WHERE event_type = 'work.completed'
                 ORDER BY rowid DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("read persisted work.completed from ledger");
        drop(guard);
        let record = EventRecord::with_timestamp(
            "work.completed",
            work_id,
            &read_actor,
            read_payload,
            u64::try_from(read_ts).expect("timestamp positive"),
        );
        reducer
            .apply(&record, &ctx)
            .expect("apply ledger-persisted work.completed");
    }
    assert_eq!(
        reducer
            .state()
            .get(work_id)
            .expect("work should exist")
            .state,
        WorkState::Completed,
        "work must complete only after review/merge receipts are bound to digest D"
    );

    // =========================================================================
    // STEP_06 assertion 9: staleness sub-test.
    // After publishing second changeset D2, receipts for D cannot advance
    // work state at ANY stage boundary (gate, CI, review, merge).
    // =========================================================================

    let stale_work_id = "W-hef-fac-vnext-csid-e2e-stale";
    let newer_digest = [0x66; 32];
    setup_ci_pending(
        &publish_emitter,
        &sqlite,
        &mut reducer,
        &ctx,
        stale_work_id,
        3_000_000_000,
    );

    // Publish D for stale_work_id, then supersede with D2
    emit_and_apply_digest_event(
        &publish_emitter,
        &sqlite,
        &mut reducer,
        &ctx,
        "changeset_published",
        stale_work_id,
        published_digest,
        3_000_000_100,
    );
    emit_and_apply_digest_event(
        &publish_emitter,
        &sqlite,
        &mut reducer,
        &ctx,
        "changeset_published",
        stale_work_id,
        newer_digest,
        3_000_000_200,
    );
    assert_eq!(
        reducer
            .state()
            .latest_changeset_by_work
            .get(stale_work_id)
            .copied(),
        Some(newer_digest),
        "staleness: latest changeset must be D2 after second publication"
    );

    // Stale gate receipt for D must NOT be admitted
    emit_and_apply_digest_event(
        &publish_emitter,
        &sqlite,
        &mut reducer,
        &ctx,
        "gate.receipt_collected",
        stale_work_id,
        published_digest,
        3_000_000_300,
    );
    assert_eq!(
        reducer.state().ci_receipt_digest_by_work.get(stale_work_id),
        None,
        "staleness: gate receipt for stale D must be rejected (not stored)"
    );

    // Stale CI transition from D must NOT advance state
    emit_and_apply_work_transition(
        &publish_emitter,
        &sqlite,
        &mut reducer,
        &ctx,
        stale_work_id,
        &TransitionSpec {
            from_state: "CI_PENDING",
            to_state: "READY_FOR_REVIEW",
            rationale_code: "ci_passed",
            previous_transition_count: 3,
            actor_id: CI_SYSTEM_ACTOR_ID,
        },
        3_000_000_400,
    );
    assert_eq!(
        reducer
            .state()
            .get(stale_work_id)
            .expect("stale work should exist")
            .state,
        WorkState::CiPending,
        "staleness: stale D gate receipts must not drive CI transition after D2 publication"
    );

    // D2 gate receipt SHOULD be admitted
    emit_and_apply_digest_event(
        &publish_emitter,
        &sqlite,
        &mut reducer,
        &ctx,
        "gate.receipt_collected",
        stale_work_id,
        newer_digest,
        3_000_000_500,
    );
    assert_eq!(
        reducer
            .state()
            .ci_receipt_digest_by_work
            .get(stale_work_id)
            .copied(),
        Some(newer_digest),
        "staleness: D2 gate receipt must be admitted"
    );

    // D2 CI transition succeeds
    emit_and_apply_work_transition(
        &publish_emitter,
        &sqlite,
        &mut reducer,
        &ctx,
        stale_work_id,
        &TransitionSpec {
            from_state: "CI_PENDING",
            to_state: "READY_FOR_REVIEW",
            rationale_code: "ci_passed",
            previous_transition_count: 3,
            actor_id: CI_SYSTEM_ACTOR_ID,
        },
        3_000_000_600,
    );
    assert_eq!(
        reducer
            .state()
            .get(stale_work_id)
            .expect("stale work should exist")
            .state,
        WorkState::ReadyForReview,
        "staleness: only D2-bound receipts may drive forward progress"
    );

    // Stale review receipt for D must NOT be admitted
    emit_and_apply_digest_event(
        &publish_emitter,
        &sqlite,
        &mut reducer,
        &ctx,
        "review_receipt_recorded",
        stale_work_id,
        published_digest,
        3_000_000_700,
    );
    assert_eq!(
        reducer
            .state()
            .review_receipt_digest_by_work
            .get(stale_work_id),
        None,
        "staleness: review receipt for stale D must be rejected"
    );

    // D2 review receipt must be admitted
    emit_and_apply_digest_event(
        &publish_emitter,
        &sqlite,
        &mut reducer,
        &ctx,
        "review_receipt_recorded",
        stale_work_id,
        newer_digest,
        3_000_000_800,
    );
    assert_eq!(
        reducer
            .state()
            .review_receipt_digest_by_work
            .get(stale_work_id)
            .copied(),
        Some(newer_digest),
        "staleness: D2 review receipt must be admitted"
    );

    // Stale merge receipt for D must NOT be admitted
    emit_and_apply_digest_event(
        &publish_emitter,
        &sqlite,
        &mut reducer,
        &ctx,
        "merge_receipt_recorded",
        stale_work_id,
        published_digest,
        3_000_000_900,
    );
    assert_eq!(
        reducer
            .state()
            .merge_receipt_digest_by_work
            .get(stale_work_id),
        None,
        "staleness: merge receipt for stale D must be rejected"
    );

    // D2 merge receipt must be admitted
    emit_and_apply_digest_event(
        &publish_emitter,
        &sqlite,
        &mut reducer,
        &ctx,
        "merge_receipt_recorded",
        stale_work_id,
        newer_digest,
        3_000_001_000,
    );
    assert_eq!(
        reducer
            .state()
            .merge_receipt_digest_by_work
            .get(stale_work_id)
            .copied(),
        Some(newer_digest),
        "staleness: D2 merge receipt must be admitted"
    );

    let guard = sqlite.lock().expect("lock sqlite for assertions");
    let changeset_count: i64 = guard
        .query_row(
            "SELECT COUNT(*) FROM ledger_events WHERE event_type = 'changeset_published'",
            [],
            |row| row.get(0),
        )
        .expect("count changeset_published events");
    assert_eq!(changeset_count, 1, "expected one changeset_published event");

    let lease_count: i64 = guard
        .query_row(
            "SELECT COUNT(*) FROM ledger_events WHERE event_type = 'gate_lease_issued'",
            [],
            |row| row.get(0),
        )
        .expect("count gate_lease_issued events");
    assert_eq!(
        lease_count,
        i64::try_from(GateType::all().len()).expect("gate type length fits i64"),
        "expected one gate_lease_issued per gate type"
    );

    // STEP_06 assertion 8: no digest in event stream equals
    // BLAKE3(session_id || work_id)
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"S-regression-sentinel");
    hasher.update(work_id.as_bytes());
    let synthetic_digest: [u8; 32] = *hasher.finalize().as_bytes();

    let mut stmt = guard
        .prepare("SELECT payload FROM ledger_events ORDER BY timestamp_ns ASC, event_id ASC")
        .expect("prepare payload query");
    let rows = stmt
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .expect("query payload rows");

    let mut observed_digests = Vec::new();
    for row in rows {
        let payload = row.expect("decode payload row");
        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&payload) {
            collect_changeset_digests(&json, &mut observed_digests);
        }
    }

    assert!(
        !observed_digests.is_empty(),
        "expected to observe changeset digests in persisted event stream"
    );
    for digest in observed_digests {
        assert_ne!(
            digest, synthetic_digest,
            "STEP_06 assertion 8: event stream must not contain synthetic BLAKE3(session_id || work_id) digest"
        );
    }
}

fn collect_changeset_digests(value: &serde_json::Value, out: &mut Vec<[u8; 32]>) {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(candidate) = map.get("changeset_digest") {
                if let Some(digest) = decode_digest_value(candidate) {
                    out.push(digest);
                }
            }
            for nested in map.values() {
                collect_changeset_digests(nested, out);
            }
        },
        serde_json::Value::Array(items) => {
            for nested in items {
                collect_changeset_digests(nested, out);
            }
        },
        _ => {},
    }
}

fn decode_digest_value(value: &serde_json::Value) -> Option<[u8; 32]> {
    match value {
        serde_json::Value::String(hex_value) => {
            let raw = hex::decode(hex_value).ok()?;
            if raw.len() != 32 {
                return None;
            }
            let mut digest = [0u8; 32];
            digest.copy_from_slice(&raw);
            Some(digest)
        },
        serde_json::Value::Array(values) => {
            if values.len() != 32 {
                return None;
            }
            let mut digest = [0u8; 32];
            for (idx, item) in values.iter().enumerate() {
                let n = item.as_u64()?;
                digest[idx] = u8::try_from(n).ok()?;
            }
            Some(digest)
        },
        _ => None,
    }
}
