//! TCK-00412: `PublishChangeSet` fail-closed closure integration tests.
//!
//! Exercises production dispatcher wiring via `DispatcherState` constructors:
//! - CAS configured: publish succeeds and semantic idempotency replays
//!   persisted bindings.
//! - CAS missing: publish fails closed.
//! - Ownership, validation, and digest integrity checks reject before mutation.

use std::sync::{Arc, Mutex};

use apm2_core::fac::{ChangeKind, ChangeSetBundleV1, FileChange, GitObjectRef, HashAlgo};
use apm2_daemon::cas::{DurableCas, DurableCasConfig};
use apm2_daemon::episode::InMemorySessionRegistry;
use apm2_daemon::ledger::{SqliteLedgerEventEmitter, SqliteWorkRegistry};
use apm2_daemon::protocol::credentials::PeerCredentials;
use apm2_daemon::protocol::dispatch::{
    ConnectionContext, PrivilegedResponse, encode_claim_work_request,
    encode_publish_changeset_request,
};
use apm2_daemon::protocol::messages::{
    ClaimWorkRequest, PrivilegedErrorCode, PublishChangeSetRequest, WorkRole,
};
use apm2_daemon::session::SessionRegistry;
use apm2_daemon::state::DispatcherState;
use rusqlite::Connection;
use tempfile::TempDir;

fn make_sqlite_conn() -> Arc<Mutex<Connection>> {
    let conn = Connection::open_in_memory().expect("sqlite in-memory should open");
    SqliteLedgerEventEmitter::init_schema(&conn).expect("ledger schema init should succeed");
    SqliteWorkRegistry::init_schema(&conn).expect("work schema init should succeed");
    Arc::new(Mutex::new(conn))
}

fn make_privileged_ctx(uid: u32, gid: u32) -> ConnectionContext {
    ConnectionContext::privileged_session_open(Some(PeerCredentials {
        uid,
        gid,
        pid: Some(12345),
    }))
}

/// Creates a temporary CAS directory with secure 0700 permissions.
///
/// Returns `(root_tempdir, cas_path)` -- the `root_tempdir` must be kept alive
/// for the duration of the test to prevent early cleanup.
fn make_secure_cas_dir() -> (TempDir, std::path::PathBuf) {
    let root = tempfile::tempdir().expect("temp CAS root");
    let cas_dir = root.path().join("cas");
    std::fs::create_dir(&cas_dir).expect("create CAS dir");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut perms = std::fs::metadata(&cas_dir)
            .expect("CAS dir metadata should exist")
            .permissions();
        perms.set_mode(0o700);
        std::fs::set_permissions(&cas_dir, perms).expect("set CAS dir permissions");
    }

    (root, cas_dir)
}

fn claim_work(
    dispatcher: &apm2_daemon::protocol::dispatch::PrivilegedDispatcher,
    ctx: &ConnectionContext,
) -> String {
    let claim_request = ClaimWorkRequest {
        actor_id: "tck-00412-test-actor".to_string(),
        role: WorkRole::Implementer.into(),
        credential_signature: vec![1, 2, 3],
        nonce: vec![4, 5, 6],
    };
    let claim_response = dispatcher
        .dispatch(&encode_claim_work_request(&claim_request), ctx)
        .expect("ClaimWork should dispatch");
    match claim_response {
        PrivilegedResponse::ClaimWork(resp) => resp.work_id,
        other => panic!("Expected ClaimWork response, got {other:?}"),
    }
}

fn make_valid_bundle(changeset_id: &str) -> ChangeSetBundleV1 {
    ChangeSetBundleV1::builder()
        .changeset_id(changeset_id)
        .base(GitObjectRef {
            algo: HashAlgo::Sha1,
            object_kind: "commit".to_string(),
            object_id: "a".repeat(40),
        })
        .diff_hash([0x42; 32])
        .file_manifest(vec![FileChange {
            path: "src/main.rs".to_string(),
            change_kind: ChangeKind::Modify,
            old_path: None,
        }])
        .binary_detected(false)
        .build()
        .expect("bundle should build")
}

fn make_noncanonical_bundle_json(changeset_id: &str) -> Vec<u8> {
    let bundle = make_valid_bundle(changeset_id);
    let value = serde_json::json!({
        "binary_detected": bundle.binary_detected,
        "file_manifest": [{
            "change_kind": "MODIFY",
            "path": "src/main.rs"
        }],
        "diff_hash": hex::encode(bundle.diff_hash),
        "diff_format": bundle.diff_format,
        "changeset_digest": hex::encode(bundle.changeset_digest),
        "base": {
            "object_id": bundle.base.object_id,
            "object_kind": bundle.base.object_kind,
            "algo": "sha1"
        },
        "changeset_id": bundle.changeset_id,
        "schema_version": bundle.schema_version,
        "schema": bundle.schema
    });
    serde_json::to_vec_pretty(&value).expect("non-canonical JSON should serialize")
}

fn count_changeset_events(
    dispatcher: &apm2_daemon::protocol::dispatch::PrivilegedDispatcher,
    work_id: &str,
) -> usize {
    dispatcher
        .event_emitter()
        .get_events_by_work_id(work_id)
        .into_iter()
        .filter(|event| event.event_type == "changeset_published")
        .count()
}

#[test]
fn tck_00412_publish_changeset_production_with_cas_semantic_idempotency() {
    let conn = make_sqlite_conn();
    let (_cas_root, cas_path) = make_secure_cas_dir();
    let session_registry: Arc<dyn SessionRegistry> = Arc::new(InMemorySessionRegistry::new());

    let state = DispatcherState::with_persistence_and_cas(
        session_registry,
        None,
        Arc::clone(&conn),
        &cas_path,
    )
    .expect("production state with CAS should initialize");

    let dispatcher = state.privileged_dispatcher();
    let ctx = make_privileged_ctx(1000, 1000);
    let work_id = claim_work(dispatcher, &ctx);

    let canonical_bundle = serde_json::to_vec(&make_valid_bundle("cs-prod-semantic")).unwrap();
    let noncanonical_bundle = make_noncanonical_bundle_json("cs-prod-semantic");

    let response1 = dispatcher
        .dispatch(
            &encode_publish_changeset_request(&PublishChangeSetRequest {
                work_id: work_id.clone(),
                bundle_bytes: canonical_bundle,
            }),
            &ctx,
        )
        .expect("first publish should dispatch");
    let (digest1, cas_hash1, event_id1) = match response1 {
        PrivilegedResponse::PublishChangeSet(resp) => {
            (resp.changeset_digest, resp.cas_hash, resp.event_id)
        },
        other => panic!("Expected PublishChangeSet, got {other:?}"),
    };

    let response2 = dispatcher
        .dispatch(
            &encode_publish_changeset_request(&PublishChangeSetRequest {
                work_id: work_id.clone(),
                bundle_bytes: noncanonical_bundle,
            }),
            &ctx,
        )
        .expect("second publish should dispatch");
    let (digest2, cas_hash2, event_id2) = match response2 {
        PrivilegedResponse::PublishChangeSet(resp) => {
            (resp.changeset_digest, resp.cas_hash, resp.event_id)
        },
        other => panic!("Expected PublishChangeSet replay, got {other:?}"),
    };

    assert_eq!(digest1, digest2, "semantic replay must preserve digest");
    assert_eq!(
        event_id1, event_id2,
        "semantic replay must preserve event_id"
    );
    assert_eq!(
        cas_hash1, cas_hash2,
        "semantic replay must preserve persisted CAS binding"
    );
    assert_eq!(
        count_changeset_events(dispatcher, &work_id),
        1,
        "semantic replay must not emit duplicate changeset_published events"
    );

    let cas = DurableCas::new(DurableCasConfig::new(cas_path)).expect("durable CAS should open");
    let cas_hash: [u8; 32] = hex::decode(&cas_hash1)
        .expect("cas hash should decode")
        .try_into()
        .expect("cas hash should be 32 bytes");
    assert!(
        cas.exists(&cas_hash),
        "published CAS hash should exist in durable CAS"
    );
}

#[test]
fn tck_00412_publish_changeset_fails_closed_without_cas() {
    let conn = make_sqlite_conn();
    let session_registry: Arc<dyn SessionRegistry> = Arc::new(InMemorySessionRegistry::new());

    let state =
        DispatcherState::with_persistence(session_registry, None, Some(Arc::clone(&conn)), None);

    let dispatcher = state.privileged_dispatcher();
    let ctx = make_privileged_ctx(1000, 1000);
    let work_id = claim_work(dispatcher, &ctx);

    let response = dispatcher
        .dispatch(
            &encode_publish_changeset_request(&PublishChangeSetRequest {
                work_id,
                bundle_bytes: serde_json::to_vec(&make_valid_bundle("cs-no-cas")).unwrap(),
            }),
            &ctx,
        )
        .expect("publish request should dispatch");

    match response {
        PrivilegedResponse::Error(err) => {
            assert_eq!(
                err.code,
                PrivilegedErrorCode::CapabilityRequestRejected as i32,
                "missing CAS must fail closed"
            );
            assert!(
                err.message
                    .contains("content-addressed store not configured"),
                "expected CAS wiring error, got: {}",
                err.message
            );
        },
        other => panic!("Expected fail-closed CAS rejection, got {other:?}"),
    }
}

#[test]
fn tck_00412_publish_changeset_rejects_ownership_mismatch_before_mutation() {
    let conn = make_sqlite_conn();
    let (_cas_root, cas_path) = make_secure_cas_dir();
    let session_registry: Arc<dyn SessionRegistry> = Arc::new(InMemorySessionRegistry::new());

    let state = DispatcherState::with_persistence_and_cas(
        session_registry,
        None,
        Arc::clone(&conn),
        &cas_path,
    )
    .expect("production state with CAS should initialize");

    let dispatcher = state.privileged_dispatcher();
    let owner_ctx = make_privileged_ctx(1000, 1000);
    let non_owner_ctx = make_privileged_ctx(2000, 2000);
    let work_id = claim_work(dispatcher, &owner_ctx);

    let bundle_bytes = serde_json::to_vec(&make_valid_bundle("cs-owner-mismatch")).unwrap();
    let expected_hash = *blake3::hash(&bundle_bytes).as_bytes();

    let response = dispatcher
        .dispatch(
            &encode_publish_changeset_request(&PublishChangeSetRequest {
                work_id: work_id.clone(),
                bundle_bytes,
            }),
            &non_owner_ctx,
        )
        .expect("publish request should dispatch");

    match response {
        PrivilegedResponse::Error(err) => {
            assert_eq!(
                err.code,
                PrivilegedErrorCode::PermissionDenied as i32,
                "non-owner publish must be denied"
            );
            assert!(
                err.message.contains("does not own work claim"),
                "expected ownership rejection, got: {}",
                err.message
            );
        },
        other => panic!("Expected ownership rejection, got {other:?}"),
    }

    let cas = DurableCas::new(DurableCasConfig::new(cas_path)).expect("durable CAS should open");
    assert!(
        !cas.exists(&expected_hash),
        "ownership rejection must happen before CAS write"
    );
    assert_eq!(
        count_changeset_events(dispatcher, &work_id),
        0,
        "ownership rejection must happen before ledger emission"
    );
}

#[test]
fn tck_00412_publish_changeset_rejects_invalid_bundle() {
    let conn = make_sqlite_conn();
    let (_cas_root, cas_path) = make_secure_cas_dir();
    let session_registry: Arc<dyn SessionRegistry> = Arc::new(InMemorySessionRegistry::new());

    let state = DispatcherState::with_persistence_and_cas(
        session_registry,
        None,
        Arc::clone(&conn),
        &cas_path,
    )
    .expect("production state with CAS should initialize");

    let dispatcher = state.privileged_dispatcher();
    let ctx = make_privileged_ctx(1000, 1000);
    let work_id = claim_work(dispatcher, &ctx);

    let mut bundle = make_valid_bundle("cs-invalid-bundle");
    bundle.diff_format = "custom_diff".to_string();
    bundle.changeset_digest = bundle.compute_digest();
    let bundle_bytes = serde_json::to_vec(&bundle).unwrap();
    let expected_hash = *blake3::hash(&bundle_bytes).as_bytes();

    let response = dispatcher
        .dispatch(
            &encode_publish_changeset_request(&PublishChangeSetRequest {
                work_id: work_id.clone(),
                bundle_bytes,
            }),
            &ctx,
        )
        .expect("publish request should dispatch");

    match response {
        PrivilegedResponse::Error(err) => {
            assert_eq!(
                err.code,
                PrivilegedErrorCode::CapabilityRequestRejected as i32,
                "invalid bundle must be rejected"
            );
            assert!(
                err.message.contains("invalid ChangeSetBundleV1")
                    && err.message.contains("diff_format"),
                "expected full bundle validation rejection, got: {}",
                err.message
            );
        },
        other => panic!("Expected invalid bundle rejection, got {other:?}"),
    }

    let cas = DurableCas::new(DurableCasConfig::new(cas_path)).expect("durable CAS should open");
    assert!(
        !cas.exists(&expected_hash),
        "invalid bundle rejection must happen before CAS write"
    );
    assert_eq!(
        count_changeset_events(dispatcher, &work_id),
        0,
        "invalid bundle rejection must happen before ledger emission"
    );
}

#[test]
fn tck_00412_publish_changeset_rejects_digest_mismatch() {
    let conn = make_sqlite_conn();
    let (_cas_root, cas_path) = make_secure_cas_dir();
    let session_registry: Arc<dyn SessionRegistry> = Arc::new(InMemorySessionRegistry::new());

    let state = DispatcherState::with_persistence_and_cas(
        session_registry,
        None,
        Arc::clone(&conn),
        &cas_path,
    )
    .expect("production state with CAS should initialize");

    let dispatcher = state.privileged_dispatcher();
    let ctx = make_privileged_ctx(1000, 1000);
    let work_id = claim_work(dispatcher, &ctx);

    let mut bundle = make_valid_bundle("cs-digest-mismatch");
    bundle.changeset_digest = [0xAA; 32];
    let bundle_bytes = serde_json::to_vec(&bundle).unwrap();
    let expected_hash = *blake3::hash(&bundle_bytes).as_bytes();

    let response = dispatcher
        .dispatch(
            &encode_publish_changeset_request(&PublishChangeSetRequest {
                work_id: work_id.clone(),
                bundle_bytes,
            }),
            &ctx,
        )
        .expect("publish request should dispatch");

    match response {
        PrivilegedResponse::Error(err) => {
            assert_eq!(
                err.code,
                PrivilegedErrorCode::CapabilityRequestRejected as i32,
                "digest mismatch must be rejected"
            );
            assert!(
                err.message.contains("changeset_digest mismatch"),
                "expected digest mismatch rejection, got: {}",
                err.message
            );
        },
        other => panic!("Expected digest mismatch rejection, got {other:?}"),
    }

    let cas = DurableCas::new(DurableCasConfig::new(cas_path)).expect("durable CAS should open");
    assert!(
        !cas.exists(&expected_hash),
        "digest mismatch rejection must happen before CAS write"
    );
    assert_eq!(
        count_changeset_events(dispatcher, &work_id),
        0,
        "digest mismatch rejection must happen before ledger emission"
    );
}
