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
    PrivilegedResponse, WorkStatusRequest, encode_work_status_request,
};
use apm2_daemon::work::authority::{ProjectionWorkAuthority, WorkAuthority};
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

    let previous_cwd = std::env::current_dir().expect("cwd should resolve");
    std::env::set_current_dir(temp_dir.path()).expect("cwd should switch to isolated temp dir");

    let request = WorkStatusRequest {
        work_id: "W-FS-NONAUTH-001".to_string(),
    };
    let frame = encode_work_status_request(&request);
    let response = dispatcher
        .dispatch(&frame, &privileged_ctx())
        .expect("work status request should dispatch");

    std::env::set_current_dir(previous_cwd).expect("cwd should be restored");

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
        .list_claimable()
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
                    .list_all()
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
        .list_all()
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
        .list_all()
        .expect("pre-restart projection read should succeed");

    let authority_after =
        ProjectionWorkAuthority::new(Arc::clone(&emitter) as Arc<dyn LedgerEventEmitter>);
    let after = authority_after
        .list_all()
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
