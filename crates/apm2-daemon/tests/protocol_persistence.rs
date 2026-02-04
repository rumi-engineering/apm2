//! Integration tests for persistent protocol state (TCK-00289).
//!
//! Verifies that:
//! - `ClaimWork` persists work claims to `SQLite`
//! - `ClaimWork` emits signed `WorkClaimed` events to `SQLite` ledger
//! - `IssueCapability` validates leases against `SQLite` ledger

use std::sync::{Arc, Mutex};

use apm2_daemon::episode::InMemorySessionRegistry;
use apm2_daemon::ledger::{SqliteLedgerEventEmitter, SqliteWorkRegistry};
use apm2_daemon::protocol::credentials::PeerCredentials;
use apm2_daemon::protocol::dispatch::{
    ConnectionContext, PrivilegedResponse, encode_claim_work_request,
    encode_issue_capability_request, encode_spawn_episode_request,
};
use apm2_daemon::protocol::messages::{
    CapabilityRequest, ClaimWorkRequest, IssueCapabilityRequest, SpawnEpisodeRequest, WorkRole,
};
use apm2_daemon::state::DispatcherState;
use rusqlite::Connection;
use tempfile::NamedTempFile;

fn make_privileged_ctx() -> ConnectionContext {
    ConnectionContext::privileged(Some(PeerCredentials {
        uid: 1000,
        gid: 1000,
        pid: Some(12345),
    }))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_persistence_end_to_end() {
    // 1. Setup SQLite
    let db_file = NamedTempFile::new().unwrap();
    let conn = Connection::open(db_file.path()).unwrap();

    // Init schemas
    SqliteLedgerEventEmitter::init_schema(&conn).unwrap();
    SqliteWorkRegistry::init_schema(&conn).unwrap();

    let conn_arc = Arc::new(Mutex::new(conn));

    // 2. Setup DispatcherState with persistence
    let session_registry = Arc::new(InMemorySessionRegistry::new());
    let state = DispatcherState::with_persistence(session_registry, None, Some(conn_arc.clone()));
    let dispatcher = state.privileged_dispatcher();

    // 3. ClaimWork
    let ctx = make_privileged_ctx();
    let claim_req = ClaimWorkRequest {
        actor_id: "test-actor".to_string(),
        role: WorkRole::GateExecutor.into(),
        credential_signature: vec![],
        nonce: vec![1, 2, 3, 4],
    };
    let claim_frame = encode_claim_work_request(&claim_req);
    let claim_resp = dispatcher.dispatch(&claim_frame, &ctx).unwrap();

    let (work_id, lease_id) = match claim_resp {
        PrivilegedResponse::ClaimWork(resp) => (resp.work_id, resp.lease_id),
        _ => panic!("Expected ClaimWork response"),
    };

    // 4. Verify Persistence
    {
        let conn = conn_arc.lock().unwrap();

        // Verify WorkClaim
        let claim_count: i64 = conn
            .query_row(
                "SELECT count(*) FROM work_claims WHERE work_id = ?1",
                rusqlite::params![work_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(claim_count, 1, "Work claim should be persisted");

        // Verify WorkClaimed Event
        let event_count: i64 = conn.query_row(
            "SELECT count(*) FROM ledger_events WHERE event_type = 'work_claimed' AND work_id = ?1",
            rusqlite::params![work_id],
            |row| row.get(0)
        ).unwrap();
        assert_eq!(event_count, 1, "WorkClaimed event should be persisted");
    }

    // 5. SpawnEpisode (to get session_id)
    // TCK-00289: Now that we have persistence, SpawnEpisode should validate the
    // lease. For GateExecutor, it checks ledger events.
    // Our SqliteLeaseValidator queries ledger_events.
    // However, currently SqliteLeaseValidator checks for 'gate_lease_issued' event
    // type. ClaimWork emits 'work_claimed'.
    // If SpawnEpisode checks for 'gate_lease_issued', it will fail unless we also
    // emit that. But 'gate_lease_issued' is usually emitted by the Gate Holon.
    // In this test, we might need to manually insert a gate lease event or use a
    // different role.

    // Let's use IMPLEMENTER role for Spawn first, as it doesn't require gate lease
    // validation. But wait, the test above used GateExecutor for ClaimWork.
    // Let's assume for this test we want to verify the Claim persistence mainly.
    // But let's try to Spawn as GateExecutor and see if it fails (as expected
    // without gate lease event).

    let spawn_req = SpawnEpisodeRequest {
        work_id,
        role: WorkRole::GateExecutor.into(),
        lease_id: Some(lease_id),
        workspace_root: "/tmp".to_string(),
    };
    let spawn_frame = encode_spawn_episode_request(&spawn_req);
    let spawn_resp = dispatcher.dispatch(&spawn_frame, &ctx).unwrap();

    match spawn_resp {
        PrivilegedResponse::Error(err) => {
            // Expected failure: GateLeaseMissing (because we didn't emit gate_lease_issued,
            // only work_claimed) This proves LeaseValidator is active and
            // querying the DB.
            assert_eq!(
                err.code,
                apm2_daemon::protocol::messages::PrivilegedErrorCode::GateLeaseMissing as i32
            );
        },
        _ => panic!("Expected GateLeaseMissing error"),
    }

    // Now let's try IssueCapability (TCK-00289).
    // We need a valid session first. Let's spawn as Implementer (doesn't check gate
    // lease). But we claimed as GateExecutor. Role mismatch will occur.

    // Let's do a fresh flow for Implementer.
    let claim_req_impl = ClaimWorkRequest {
        actor_id: "impl-actor".to_string(),
        role: WorkRole::Implementer.into(),
        credential_signature: vec![],
        nonce: vec![5, 6, 7, 8],
    };
    let claim_frame_impl = encode_claim_work_request(&claim_req_impl);
    let claim_resp_impl = dispatcher.dispatch(&claim_frame_impl, &ctx).unwrap();
    let (work_id_impl, lease_id_impl) = match claim_resp_impl {
        PrivilegedResponse::ClaimWork(resp) => (resp.work_id, resp.lease_id),
        _ => panic!("Expected ClaimWork response"),
    };

    let spawn_req_impl = SpawnEpisodeRequest {
        work_id: work_id_impl,
        role: WorkRole::Implementer.into(),
        lease_id: Some(lease_id_impl),
        workspace_root: "/tmp".to_string(),
    };
    let spawn_frame_impl = encode_spawn_episode_request(&spawn_req_impl);
    let spawn_resp_impl = dispatcher.dispatch(&spawn_frame_impl, &ctx).unwrap();

    let session_id = match spawn_resp_impl {
        PrivilegedResponse::SpawnEpisode(resp) => resp.session_id,
        _ => panic!("Expected SpawnEpisode response"),
    };

    // 6. IssueCapability
    // TCK-00289: Verify that IssueCapability succeeds with persistent registry
    // validation. The previous steps established a valid Implementer session
    // (session_id) backed by a persistent work claim.
    let issue_req = IssueCapabilityRequest {
        session_id,
        capability_request: Some(CapabilityRequest {
            tool_class: "file_read".to_string(),
            read_patterns: vec!["/tmp/**".to_string()],
            write_patterns: vec![],
            duration_secs: 60,
        }),
    };

    let issue_frame = encode_issue_capability_request(&issue_req);
    let issue_resp = dispatcher.dispatch(&issue_frame, &ctx).unwrap();

    match issue_resp {
        PrivilegedResponse::IssueCapability(resp) => {
            assert!(resp.capability_id.starts_with("C-"));
            assert!(resp.granted_at > 0);
            assert!(resp.expires_at > resp.granted_at);
        },
        PrivilegedResponse::Error(e) => panic!("IssueCapability failed: {e:?}"),
        _ => panic!("Expected IssueCapability response"),
    }
}
