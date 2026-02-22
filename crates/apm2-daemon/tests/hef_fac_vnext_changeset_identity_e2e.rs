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

fn create_event(
    event_type: &str,
    actor_id: &str,
    payload: Vec<u8>,
    timestamp_ns: u64,
) -> EventRecord {
    EventRecord::with_timestamp(
        event_type,
        "session-hef-fac-vnext",
        actor_id,
        payload,
        timestamp_ns,
    )
}

fn apply_digest_event(
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
    reducer
        .apply(
            &create_event(event_type, "actor:fac-kernel", payload, timestamp_ns),
            ctx,
        )
        .expect("apply digest-bound event");
}

struct TransitionSpec<'a> {
    from_state: &'a str,
    to_state: &'a str,
    rationale_code: &'a str,
    previous_transition_count: u32,
    actor_id: &'a str,
}

fn apply_work_transition(
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
    reducer
        .apply(
            &create_event("work.transitioned", spec.actor_id, payload, timestamp_ns),
            ctx,
        )
        .expect("apply work.transitioned");
}

fn setup_ci_pending(reducer: &mut WorkReducer, ctx: &ReducerContext, work_id: &str, base_ts: u64) {
    let opened = work_helpers::work_opened_payload(work_id, "TICKET", vec![1], vec![], vec![]);
    reducer
        .apply(
            &create_event("work.opened", "actor:implementer", opened, base_ts),
            ctx,
        )
        .expect("apply work.opened");

    apply_work_transition(
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
    apply_work_transition(
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
    apply_work_transition(
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
    let published_event = publish_emitter
        .emit_changeset_published(
            work_id,
            &published_digest,
            &bundle_cas_hash,
            "actor:publish",
            1_706_000_000_123_000_000,
        )
        .expect("emit changeset_published");
    assert_eq!(published_event.event_type, "changeset_published");

    let report = gate_start_kernel
        .tick()
        .await
        .expect("gate start kernel tick succeeds");
    assert_eq!(
        report.completed_intents, 1,
        "one changeset publication should complete"
    );

    for gate_type in GateType::all() {
        let lease = gate_orchestrator
            .gate_lease(work_id, gate_type)
            .await
            .expect("gate lease should exist after gate start");
        assert_eq!(
            lease.changeset_digest, published_digest,
            "gate lease digest must match ChangeSetPublished digest"
        );
    }

    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);
    setup_ci_pending(&mut reducer, &ctx, work_id, 2_000_000_000);

    apply_digest_event(
        &mut reducer,
        &ctx,
        "changeset_published",
        work_id,
        published_digest,
        2_000_000_100,
    );
    apply_digest_event(
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
        "gate receipt stage must preserve published digest"
    );

    // TODO(TCK-00641): Replace manual CI transition injection with the CI
    // processor's authoritative transition emission once wired in this harness.
    apply_work_transition(
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
        "CI transition must be admitted only for digest D"
    );

    apply_work_transition(
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
    apply_digest_event(
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
        "review receipt stage must preserve published digest"
    );

    // TODO(TCK-00647): Replace manual merge receipt injection with daemon-owned
    // merge admission wiring when reviewer/merge orchestrators are end-to-end.
    apply_digest_event(
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
        "merge receipt stage must preserve published digest"
    );

    let completed = work_helpers::work_completed_payload(
        work_id,
        vec![1],
        vec!["evidence-1".to_string()],
        "gate-receipt-quality-1",
        "merge-receipt-sha111",
    );
    reducer
        .apply(
            &create_event("work.completed", "actor:merge", completed, 2_000_000_700),
            &ctx,
        )
        .expect("apply work.completed");
    assert_eq!(
        reducer
            .state()
            .get(work_id)
            .expect("work should exist")
            .state,
        WorkState::Completed,
        "work must complete only after review/merge receipts are bound to digest D"
    );

    // Staleness sub-test: publish D2 then provide stale D receipts.
    let stale_work_id = "W-hef-fac-vnext-csid-e2e-stale";
    let newer_digest = [0x66; 32];
    setup_ci_pending(&mut reducer, &ctx, stale_work_id, 3_000_000_000);
    apply_digest_event(
        &mut reducer,
        &ctx,
        "changeset_published",
        stale_work_id,
        published_digest,
        3_000_000_100,
    );
    apply_digest_event(
        &mut reducer,
        &ctx,
        "changeset_published",
        stale_work_id,
        newer_digest,
        3_000_000_200,
    );
    apply_digest_event(
        &mut reducer,
        &ctx,
        "gate.receipt_collected",
        stale_work_id,
        published_digest,
        3_000_000_300,
    );
    apply_work_transition(
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
        "stale D receipts must not transition work after D2 publication"
    );

    apply_digest_event(
        &mut reducer,
        &ctx,
        "gate.receipt_collected",
        stale_work_id,
        newer_digest,
        3_000_000_500,
    );
    apply_work_transition(
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
        "only D2-bound receipts may drive forward progress"
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
            "event stream must not contain synthetic BLAKE3(session_id || work_id) digest"
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
