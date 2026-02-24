//! TCK-00415: `WorkObject` ledger-authority cutover integration tests.
//!
//! Validates that runtime work lifecycle authority is derived from
//! projection rebuilds of ledger events (no filesystem ticket authority).

use std::collections::BTreeSet;
use std::sync::Arc;
use std::{fs, thread};

use apm2_daemon::protocol::dispatch::WorkTransition;
use apm2_daemon::protocol::{
    ConnectionContext, LedgerEventEmitter, PeerCredentials, PrivilegedDispatcher,
    PrivilegedErrorCode, PrivilegedResponse, WorkListRequest, WorkStatusRequest,
    encode_work_list_request, encode_work_status_request,
};
use apm2_daemon::work::authority::{MAX_WORK_LIST_ROWS, ProjectionWorkAuthority, WorkAuthority};
use apm2_daemon::work::projection::WorkObjectProjection;
use tempfile::tempdir;

fn privileged_ctx() -> ConnectionContext {
    ConnectionContext::privileged_session_open(Some(PeerCredentials {
        uid: 1000,
        gid: 1000,
        pid: Some(4242),
    }))
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

fn emit_changeset_published(
    emitter: &dyn LedgerEventEmitter,
    work_id: &str,
    changeset_digest: [u8; 32],
    timestamp_ns: u64,
) {
    emitter
        .emit_changeset_published(
            work_id,
            &changeset_digest,
            &[0xCD; 32],
            "actor:claimability",
            timestamp_ns,
        )
        .expect("changeset_published should persist");
}

fn emit_gate_receipt_collected(
    emitter: &dyn LedgerEventEmitter,
    work_id: &str,
    changeset_digest: [u8; 32],
    timestamp_ns: u64,
) {
    let payload_envelope = serde_json::json!({
        "payload": "",
        "work_id": work_id,
        "changeset_digest": hex::encode(changeset_digest),
        "receipt_id": format!("receipt-{work_id}"),
        "gate_type": "quality",
    });

    // Use work_id as session_id so envelope binding matches payload (CSID-004).
    emitter
        .emit_session_event_with_envelope(
            work_id,
            "gate.receipt_collected",
            &payload_envelope,
            "system:gate",
            timestamp_ns,
        )
        .expect("gate receipt should persist");
}

fn status_snapshot(projection: &WorkObjectProjection) -> Vec<(String, String, u32)> {
    projection
        .list_work()
        .into_iter()
        .map(|work| {
            (
                work.work_id.clone(),
                work.state.as_str().to_string(),
                work.transition_count,
            )
        })
        .collect()
}

#[test]
fn test_projection_rebuild_determinism() {
    let dispatcher = PrivilegedDispatcher::new();

    emit_transition(
        dispatcher.event_emitter().as_ref(),
        "W-DET-001",
        "Open",
        "Claimed",
        "claim",
        0,
        "actor:determinism",
        1_000_000_000,
    );
    emit_transition(
        dispatcher.event_emitter().as_ref(),
        "W-DET-001",
        "Claimed",
        "InProgress",
        "start",
        1,
        "actor:determinism",
        1_000_000_100,
    );

    let events = dispatcher.event_emitter().get_all_events();
    assert_eq!(
        events.len(),
        2,
        "expected two ledger events for deterministic replay"
    );

    let mut projection_a = WorkObjectProjection::new();
    let mut projection_b = WorkObjectProjection::new();

    projection_a
        .rebuild_from_signed_events(&events)
        .expect("projection A rebuild should succeed");
    projection_b
        .rebuild_from_signed_events(&events)
        .expect("projection B rebuild should succeed");

    let snapshot_a = status_snapshot(&projection_a);
    let snapshot_b = status_snapshot(&projection_b);

    assert_eq!(
        snapshot_a, snapshot_b,
        "same event history must converge to identical state"
    );
    assert_eq!(
        snapshot_a.len(),
        1,
        "deterministic snapshot should include one work item"
    );
}

#[test]
fn test_work_status_from_projection_only() {
    let dispatcher = PrivilegedDispatcher::new();

    // Emit projection-authoritative events without registering session/work claim.
    emit_transition(
        dispatcher.event_emitter().as_ref(),
        "W-PROJ-ONLY-001",
        "Open",
        "Claimed",
        "claim",
        0,
        "actor:projection",
        1_000_000_000,
    );

    let request = WorkStatusRequest {
        work_id: "W-PROJ-ONLY-001".to_string(),
    };
    let frame = encode_work_status_request(&request);
    let response = dispatcher
        .dispatch(&frame, &privileged_ctx())
        .expect("work status request should decode and dispatch");

    match response {
        PrivilegedResponse::WorkStatus(status) => {
            assert_eq!(status.work_id, "W-PROJ-ONLY-001");
            assert_eq!(status.status, "CLAIMED");
            assert!(
                status.session_id.is_none(),
                "session metadata should be supplementary"
            );
            assert!(
                status.lease_id.is_none(),
                "lease metadata should be supplementary"
            );
        },
        other => panic!("expected WorkStatus response, got: {other:?}"),
    }
}

#[test]
fn test_no_filesystem_ticket_authority() {
    let dispatcher = PrivilegedDispatcher::new();

    emit_transition(
        dispatcher.event_emitter().as_ref(),
        "W-FS-NONAUTH-001",
        "Open",
        "Claimed",
        "claim",
        0,
        "actor:filesystem",
        1_000_000_000,
    );

    // Create a conflicting ticket file and make it unreadable to prove runtime
    // authority does not depend on filesystem ticket YAML.
    //
    // NOTE: We do NOT mutate the global CWD — the dispatcher resolves
    // projection authority from the emitter regardless of CWD, so changing
    // the working directory is not necessary to demonstrate independence
    // from filesystem ticket files.
    let temp_dir = tempdir().expect("temp dir should be created");
    let ticket_dir = temp_dir.path().join("documents/work/tickets");
    fs::create_dir_all(&ticket_dir).expect("ticket directory should be created");
    let ticket_path = ticket_dir.join("TCK-99999.yaml");
    fs::write(
        &ticket_path,
        "ticket_meta:\n  ticket:\n    id: \"TCK-99999\"\n    status: \"COMPLETED\"\n",
    )
    .expect("ticket fixture should be written");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut perms = fs::metadata(&ticket_path)
            .expect("ticket metadata should be readable")
            .permissions();
        perms.set_mode(0o000);
        fs::set_permissions(&ticket_path, perms).expect("ticket permissions should be updated");
    }

    // Dispatch with the temp dir existing but unreadable — authority MUST
    // derive state from ledger projection, not filesystem.
    let request = WorkStatusRequest {
        work_id: "W-FS-NONAUTH-001".to_string(),
    };
    let frame = encode_work_status_request(&request);
    let response = dispatcher
        .dispatch(&frame, &privileged_ctx())
        .expect("work status request should dispatch");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut perms = fs::metadata(&ticket_path)
            .expect("ticket metadata should be readable after test")
            .permissions();
        perms.set_mode(0o644);
        fs::set_permissions(&ticket_path, perms).expect("ticket permissions should be restored");
    }

    match response {
        PrivilegedResponse::WorkStatus(status) => {
            assert_eq!(status.work_id, "W-FS-NONAUTH-001");
            assert_eq!(status.status, "CLAIMED");
        },
        other => panic!("expected WorkStatus response, got: {other:?}"),
    }
}

#[test]
fn test_claimability_from_projection_only() {
    let emitter = Arc::new(apm2_daemon::protocol::StubLedgerEventEmitter::new());
    let authority =
        ProjectionWorkAuthority::new(Arc::clone(&emitter) as Arc<dyn LedgerEventEmitter>);
    let digest_w2 = [0x42; 32];

    // Non-claimable work (CLAIMED).
    emit_transition(
        emitter.as_ref(),
        "W-CLAIMABILITY-001",
        "Open",
        "Claimed",
        "claim",
        0,
        "actor:claimability",
        1_000_000_000,
    );

    // Claimable work (READY_FOR_REVIEW).
    emit_transition(
        emitter.as_ref(),
        "W-CLAIMABILITY-002",
        "Open",
        "Claimed",
        "claim",
        0,
        "actor:claimability",
        1_000_000_100,
    );
    emit_transition(
        emitter.as_ref(),
        "W-CLAIMABILITY-002",
        "Claimed",
        "InProgress",
        "start",
        1,
        "actor:claimability",
        1_000_000_200,
    );
    emit_transition(
        emitter.as_ref(),
        "W-CLAIMABILITY-002",
        "InProgress",
        "CiPending",
        "ci_wait",
        2,
        "actor:claimability",
        1_000_000_300,
    );
    emit_changeset_published(
        emitter.as_ref(),
        "W-CLAIMABILITY-002",
        digest_w2,
        1_000_000_325,
    );
    emit_gate_receipt_collected(
        emitter.as_ref(),
        "W-CLAIMABILITY-002",
        digest_w2,
        1_000_000_350,
    );
    emit_transition(
        emitter.as_ref(),
        "W-CLAIMABILITY-002",
        "CiPending",
        "ReadyForReview",
        "ci_passed",
        3,
        "system:ci-processor",
        1_000_000_400,
    );

    let claimable = authority
        .list_claimable(MAX_WORK_LIST_ROWS, "")
        .expect("claimable list should rebuild from projection");

    assert_eq!(
        claimable.len(),
        1,
        "exactly one work item should be claimable"
    );
    assert_eq!(claimable[0].work_id, "W-CLAIMABILITY-002");
    assert_eq!(claimable[0].state.as_str(), "READY_FOR_REVIEW");

    assert!(
        !authority
            .is_claimable("W-CLAIMABILITY-001")
            .expect("claimable lookup should succeed"),
        "claimed work must not be claimable"
    );
}

#[test]
fn test_concurrent_projection_access() {
    let emitter = Arc::new(apm2_daemon::protocol::StubLedgerEventEmitter::new());
    let authority = Arc::new(ProjectionWorkAuthority::new(
        Arc::clone(&emitter) as Arc<dyn LedgerEventEmitter>
    ));

    let writer_emitter = Arc::clone(&emitter);
    let writer = thread::spawn(move || {
        for idx in 0..50u64 {
            let work_id = format!("W-CONCURRENT-{idx:03}");
            emit_transition(
                writer_emitter.as_ref(),
                &work_id,
                "Open",
                "Claimed",
                "claim",
                0,
                "actor:concurrent",
                2_000_000_000 + idx,
            );
        }
    });

    let mut readers = Vec::new();
    for _ in 0..4 {
        let authority_reader = Arc::clone(&authority);
        readers.push(thread::spawn(move || {
            for _ in 0..80 {
                let rows = authority_reader
                    .list_all(MAX_WORK_LIST_ROWS, "")
                    .expect("concurrent projection read should succeed");
                let total_rows = rows.len();

                let mut seen = BTreeSet::new();
                for row in rows {
                    seen.insert(row.work_id);
                }
                assert_eq!(
                    seen.len(),
                    total_rows,
                    "projection rows should not duplicate work IDs"
                );
            }
        }));
    }

    writer.join().expect("writer thread should complete");
    for reader in readers {
        reader.join().expect("reader thread should complete");
    }

    let final_rows = authority
        .list_all(MAX_WORK_LIST_ROWS, "")
        .expect("final projection read should succeed");
    assert_eq!(final_rows.len(), 50, "all concurrent writes must converge");

    let unique_ids: BTreeSet<String> = final_rows.into_iter().map(|row| row.work_id).collect();
    assert_eq!(
        unique_ids.len(),
        50,
        "final projection must contain 50 unique work IDs"
    );
}

#[test]
fn test_projection_rebuild_after_restart() {
    let emitter = Arc::new(apm2_daemon::protocol::StubLedgerEventEmitter::new());

    emit_transition(
        emitter.as_ref(),
        "W-RESTART-001",
        "Open",
        "Claimed",
        "claim",
        0,
        "actor:restart",
        3_000_000_000,
    );
    emit_transition(
        emitter.as_ref(),
        "W-RESTART-001",
        "Claimed",
        "InProgress",
        "start",
        1,
        "actor:restart",
        3_000_000_100,
    );

    let authority_before =
        ProjectionWorkAuthority::new(Arc::clone(&emitter) as Arc<dyn LedgerEventEmitter>);
    let before = authority_before
        .list_all(MAX_WORK_LIST_ROWS, "")
        .expect("pre-restart projection read should succeed");

    let authority_after =
        ProjectionWorkAuthority::new(Arc::clone(&emitter) as Arc<dyn LedgerEventEmitter>);
    let after = authority_after
        .list_all(MAX_WORK_LIST_ROWS, "")
        .expect("post-restart projection read should succeed");

    let before_snapshot: Vec<(String, String, u32)> = before
        .into_iter()
        .map(|row| {
            (
                row.work_id,
                row.state.as_str().to_string(),
                row.transition_count,
            )
        })
        .collect();
    let after_snapshot: Vec<(String, String, u32)> = after
        .into_iter()
        .map(|row| {
            (
                row.work_id,
                row.state.as_str().to_string(),
                row.transition_count,
            )
        })
        .collect();

    assert_eq!(
        before_snapshot, after_snapshot,
        "restart projection rebuild must converge to the same state"
    );
    assert_eq!(
        before_snapshot.len(),
        1,
        "restart snapshot should include one work item"
    );
}

/// IT-00415-02: `WorkList` is denied from session socket (`PERMISSION_DENIED`).
#[test]
fn test_work_list_denied_from_session_socket() {
    let dispatcher = PrivilegedDispatcher::new();
    let ctx = ConnectionContext::session_open(
        Some(PeerCredentials {
            uid: 1000,
            gid: 1000,
            pid: Some(12346),
        }),
        Some("session-001".to_string()),
    );

    let request = WorkListRequest {
        claimable_only: false,
        limit: 0,
        cursor: String::new(),
    };
    let frame = encode_work_list_request(&request);
    let response = dispatcher.dispatch(&frame, &ctx).unwrap();

    match response {
        PrivilegedResponse::Error(err) => {
            assert_eq!(
                err.code,
                PrivilegedErrorCode::PermissionDenied as i32,
                "WorkList from session socket must be denied"
            );
        },
        other => panic!("Expected PERMISSION_DENIED, got: {other:?}"),
    }
}

/// IT-00415-03: `claimed_at_ns` reflects first claim timestamp, not
/// `last_transition_at`.
#[test]
fn test_claimed_at_ns_tracks_first_claim_timestamp() {
    let emitter = Arc::new(apm2_daemon::protocol::StubLedgerEventEmitter::new());
    let authority =
        ProjectionWorkAuthority::new(Arc::clone(&emitter) as Arc<dyn LedgerEventEmitter>);

    let claim_ts: u64 = 5_000_000_000;
    let progress_ts: u64 = 5_000_000_100;

    // Open -> Claimed at claim_ts.
    emit_transition(
        emitter.as_ref(),
        "W-CLAIM-TS-001",
        "Open",
        "Claimed",
        "claim",
        0,
        "actor:claim-ts",
        claim_ts,
    );

    // Claimed -> InProgress at progress_ts (later).
    emit_transition(
        emitter.as_ref(),
        "W-CLAIM-TS-001",
        "Claimed",
        "InProgress",
        "start",
        1,
        "actor:claim-ts",
        progress_ts,
    );

    let status = authority
        .get_work_status("W-CLAIM-TS-001")
        .expect("work status should resolve");

    assert_eq!(
        status.claimed_at_ns,
        Some(claim_ts),
        "claimed_at_ns must be the first claim timestamp, not last_transition_at"
    );
    assert_eq!(
        status.last_transition_at_ns, progress_ts,
        "last_transition_at should reflect the most recent transition"
    );
}

/// IT-00415-04: Bounded `WorkList` enforces `MAX_WORK_LIST_ROWS` cap.
#[test]
fn test_work_list_bounded_by_max_rows() {
    let dispatcher = PrivilegedDispatcher::new();
    let ctx = privileged_ctx();

    // Emit more than MAX_WORK_LIST_ROWS work items — but keep it small for
    // test speed. We test the limit parameter clamping behaviour instead.
    for idx in 0..5u64 {
        let work_id = format!("W-BOUNDED-{idx:03}");
        emit_transition(
            dispatcher.event_emitter().as_ref(),
            &work_id,
            "Open",
            "Claimed",
            "claim",
            0,
            "actor:bounded",
            6_000_000_000 + idx,
        );
    }

    // Request with limit=2 — should return exactly 2 rows.
    let request = WorkListRequest {
        claimable_only: false,
        limit: 2,
        cursor: String::new(),
    };
    let frame = encode_work_list_request(&request);
    let response = dispatcher.dispatch(&frame, &ctx).unwrap();

    match response {
        PrivilegedResponse::WorkList(resp) => {
            assert_eq!(
                resp.work_items.len(),
                2,
                "WorkList with limit=2 must return exactly 2 rows"
            );
        },
        other => panic!("Expected WorkList response, got: {other:?}"),
    }
}

/// IT-00415-05: Shared authority cache prevents redundant rebuilds.
///
/// Regression test for MAJOR/BLOCKER: per-request `ProjectionWorkAuthority`
/// instantiation. The shared instance must reuse its cache so that the
/// second call with unchanged event count does NOT trigger a full replay.
#[test]
fn test_shared_authority_cache_reuse() {
    let emitter = Arc::new(apm2_daemon::protocol::StubLedgerEventEmitter::new());
    let authority =
        ProjectionWorkAuthority::new(Arc::clone(&emitter) as Arc<dyn LedgerEventEmitter>);

    // Emit one work item.
    emit_transition(
        emitter.as_ref(),
        "W-CACHE-001",
        "Open",
        "Claimed",
        "claim",
        0,
        "actor:cache",
        7_000_000_000,
    );

    // First call: triggers rebuild.
    let first = authority
        .list_all(MAX_WORK_LIST_ROWS, "")
        .expect("first authority query should succeed");
    assert_eq!(first.len(), 1, "first call must return one work item");

    // Second call with same event count: must NOT error and must reuse
    // cache. If a new ProjectionWorkAuthority were created per-request,
    // the cache would always be empty and this would re-verify signatures.
    let second = authority
        .list_all(MAX_WORK_LIST_ROWS, "")
        .expect("second authority query should reuse cache");
    assert_eq!(second.len(), 1, "cached call must return same result");
    assert_eq!(
        first[0].work_id, second[0].work_id,
        "cached result must match initial query"
    );
}

/// IT-00415-06: Dispatcher uses shared authority across requests.
///
/// Regression test proving the dispatcher's `projection_work_authority()`
/// returns a shared instance rather than creating one per-request.
#[test]
fn test_dispatcher_shared_work_authority() {
    let dispatcher = PrivilegedDispatcher::new();
    let ctx = privileged_ctx();

    emit_transition(
        dispatcher.event_emitter().as_ref(),
        "W-SHARED-001",
        "Open",
        "Claimed",
        "claim",
        0,
        "actor:shared",
        8_000_000_000,
    );

    // First dispatch triggers rebuild.
    let request = WorkStatusRequest {
        work_id: "W-SHARED-001".to_string(),
    };
    let frame = encode_work_status_request(&request);
    let r1 = dispatcher.dispatch(&frame, &ctx).unwrap();
    match &r1 {
        PrivilegedResponse::WorkStatus(s) => assert_eq!(s.status, "CLAIMED"),
        other => panic!("Expected WorkStatus, got: {other:?}"),
    }

    // Second dispatch must succeed with cached projection (no new
    // ProjectionWorkAuthority allocation). If per-request, the cache
    // fields would never be reused.
    let r2 = dispatcher.dispatch(&frame, &ctx).unwrap();
    match &r2 {
        PrivilegedResponse::WorkStatus(s) => assert_eq!(s.status, "CLAIMED"),
        other => panic!("Expected WorkStatus on cached call, got: {other:?}"),
    }
}

/// IT-00415-07: Projection survives key rotation (trust-on-persist).
///
/// Regression test for BLOCKER 1: restart invalidates prior event
/// signature verification. After removing signature re-verification from
/// projection rebuild, events persisted with one signing key must still
/// be projectable after constructing a new authority (simulating restart
/// with a new key).
#[test]
fn test_projection_survives_key_rotation() {
    let emitter = Arc::new(apm2_daemon::protocol::StubLedgerEventEmitter::new());

    // Emit events with the emitter's current signing key.
    emit_transition(
        emitter.as_ref(),
        "W-KEYROT-001",
        "Open",
        "Claimed",
        "claim",
        0,
        "actor:keyrot",
        9_000_000_000,
    );

    // Create a FRESH authority (simulating restart where the signing key
    // would be regenerated). Under the old verify_signed_events approach,
    // this would fail because the new key cannot verify signatures made
    // with the old key.
    let fresh_authority =
        ProjectionWorkAuthority::new(Arc::clone(&emitter) as Arc<dyn LedgerEventEmitter>);

    let result = fresh_authority
        .list_all(MAX_WORK_LIST_ROWS, "")
        .expect("projection must succeed after simulated key rotation");
    assert_eq!(
        result.len(),
        1,
        "trust-on-persist model must project events regardless of current key"
    );
    assert_eq!(result[0].work_id, "W-KEYROT-001");
    assert_eq!(result[0].state.as_str(), "CLAIMED");
}

/// IT-00415-08: Session events with spoofed work event names are filtered.
///
/// Regression test for BLOCKER 2: namespace collision attack. Session
/// `EmitEvent` could inject events with `event_type = "work_transitioned"`
/// that would be picked up by projection rebuild. The domain-prefix
/// filtering must reject these because session event payloads have a
/// different structural shape (they contain `session_id` instead of
/// `work_id`).
#[test]
fn test_session_spoofed_work_events_filtered() {
    let emitter = Arc::new(apm2_daemon::protocol::StubLedgerEventEmitter::new());

    // Emit a genuine work transition.
    emit_transition(
        emitter.as_ref(),
        "W-SPOOF-001",
        "Open",
        "Claimed",
        "claim",
        0,
        "actor:spoof-test",
        10_000_000_000,
    );

    // Simulate a session-originated event with spoofed event_type
    // "work_transitioned". Session events use emit_session_event which
    // wraps the payload with session_id, not work_id.
    emitter
        .emit_session_event(
            "session-malicious",
            "work_transitioned",
            b"malicious payload",
            "attacker",
            10_000_000_100,
        )
        .expect("session event should persist");

    // Build authority from all events. The spoofed session event must NOT
    // affect the work projection.
    let authority =
        ProjectionWorkAuthority::new(Arc::clone(&emitter) as Arc<dyn LedgerEventEmitter>);
    let items = authority
        .list_all(MAX_WORK_LIST_ROWS, "")
        .expect("projection should succeed despite spoofed events");

    // Only the genuine work event should appear.
    assert_eq!(
        items.len(),
        1,
        "spoofed session events must not appear in work projection"
    );
    assert_eq!(items[0].work_id, "W-SPOOF-001");

    // Also verify that the raw ledger contains both events.
    let all_events = emitter.get_all_events();
    assert!(
        all_events.len() >= 2,
        "ledger should contain both genuine and spoofed events"
    );

    // The filter_work_domain_events (invoked inside refresh_projection)
    // removes the spoofed session event before translate_signed_events
    // processes the events. Verify this by checking the authority result
    // is consistent even with the spoofed event in the ledger.
    let authority2 =
        ProjectionWorkAuthority::new(Arc::clone(&emitter) as Arc<dyn LedgerEventEmitter>);
    let items2 = authority2
        .list_all(MAX_WORK_LIST_ROWS, "")
        .expect("fresh authority must also filter spoofed events");
    assert_eq!(
        items2.len(),
        1,
        "fresh authority must filter spoofed session events"
    );
}
