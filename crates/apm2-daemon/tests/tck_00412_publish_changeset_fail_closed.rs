//! TCK-00412: `PublishChangeSet` fail-closed closure integration tests.
//!
//! Exercises production dispatcher wiring via `DispatcherState` constructors:
//! - CAS configured: publish succeeds and semantic idempotency replays
//!   persisted bindings.
//! - CAS missing: publish fails closed.
//! - Ownership, validation, and digest integrity checks reject before mutation.

use std::sync::{Arc, Barrier, Mutex};

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

/// Verifies that concurrent publish requests for the same `(work_id,
/// changeset_digest)` produce exactly one ledger entry and all threads observe
/// identical bindings.
///
/// This exercises the defense-in-depth between the application-level semantic
/// idempotency check (`find_changeset_published_replay`) and the database-level
/// `idx_unique_changeset_published` partial unique index. Under concurrent
/// dispatch, at most one thread wins the INSERT race; all others hit either the
/// application-level fast-path or the database UNIQUE constraint followed by
/// the race-safe replay fallback.
#[test]
fn tck_00412_publish_changeset_concurrent_publish_exactly_once() {
    const NUM_THREADS: usize = 8;

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

    let bundle_bytes = serde_json::to_vec(&make_valid_bundle("cs-concurrent")).unwrap();
    let barrier = Barrier::new(NUM_THREADS);

    let results: Vec<_> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..NUM_THREADS)
            .map(|_| {
                s.spawn(|| {
                    let thread_ctx = make_privileged_ctx(1000, 1000);
                    let request = PublishChangeSetRequest {
                        work_id: work_id.clone(),
                        bundle_bytes: bundle_bytes.clone(),
                    };
                    let encoded = encode_publish_changeset_request(&request);

                    // Synchronize all threads to maximize contention.
                    barrier.wait();

                    let response = dispatcher
                        .dispatch(&encoded, &thread_ctx)
                        .expect("concurrent publish should dispatch");

                    match response {
                        PrivilegedResponse::PublishChangeSet(resp) => {
                            (resp.changeset_digest, resp.cas_hash, resp.event_id)
                        },
                        other => {
                            panic!("Expected PublishChangeSet (success or replay), got {other:?}")
                        },
                    }
                })
            })
            .collect();

        handles
            .into_iter()
            .map(|h| h.join().expect("thread should not panic"))
            .collect()
    });

    // Every thread must succeed — no CAS failures are acceptable now that
    // the CAS store handles concurrent same-hash writes idempotently.
    assert_eq!(
        results.len(),
        NUM_THREADS,
        "all threads must return PublishChangeSet (success or replay)"
    );

    // All threads must observe the same canonical bindings.
    let (ref expected_digest, ref expected_cas_hash, ref expected_event_id) = results[0];
    for (i, (digest, cas_hash, event_id)) in results.iter().enumerate() {
        assert_eq!(
            digest, expected_digest,
            "thread {i} returned different changeset_digest"
        );
        assert_eq!(
            cas_hash, expected_cas_hash,
            "thread {i} returned different cas_hash"
        );
        assert_eq!(
            event_id, expected_event_id,
            "thread {i} returned different event_id"
        );
    }

    // Exactly one ledger entry must exist.
    assert_eq!(
        count_changeset_events(dispatcher, &work_id),
        1,
        "concurrent publish must produce exactly one changeset_published event"
    );
}

/// Regression: `init_schema` quarantine migration moves duplicate
/// `changeset_published` rows (same `(work_id, changeset_digest)`) into
/// `ledger_events_quarantine` with reason `changeset_digest_dedupe_migration`,
/// creates the `idx_unique_changeset_published` unique index, and is idempotent
/// across repeated invocations.
#[test]
fn tck_00412_quarantine_migration_deduplicates_changeset_published() {
    use rusqlite::params;

    let conn = Connection::open_in_memory().expect("sqlite in-memory should open");

    // Step 1: Create the ledger_events table WITHOUT unique indexes or
    // quarantine infrastructure -- simulating a database that predates the
    // quarantine migration.
    conn.execute(
        "CREATE TABLE ledger_events (
            event_id TEXT PRIMARY KEY,
            event_type TEXT NOT NULL,
            work_id TEXT NOT NULL,
            actor_id TEXT NOT NULL,
            payload BLOB NOT NULL,
            signature BLOB NOT NULL,
            timestamp_ns INTEGER NOT NULL
        )",
        [],
    )
    .expect("bare ledger_events table creation should succeed");

    // Step 2: Insert two changeset_published rows with the SAME
    // (work_id, changeset_digest) pair.  The first-inserted row (lowest
    // rowid) should be kept; the second should be quarantined.
    let shared_work_id = "work-quarantine-test";
    let shared_digest = "abcd1234deadbeef";
    let canonical_payload = format!(r#"{{"changeset_digest":"{shared_digest}","cas_hash":"aaa"}}"#);
    let duplicate_payload = format!(r#"{{"changeset_digest":"{shared_digest}","cas_hash":"bbb"}}"#);

    conn.execute(
        "INSERT INTO ledger_events
            (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            "cs-event-keep",
            "changeset_published",
            shared_work_id,
            "actor-1",
            canonical_payload.as_bytes(),
            b"sig-keep".as_slice(),
            100_i64,
        ],
    )
    .expect("insert canonical changeset_published row");

    conn.execute(
        "INSERT INTO ledger_events
            (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            "cs-event-duplicate",
            "changeset_published",
            shared_work_id,
            "actor-1",
            duplicate_payload.as_bytes(),
            b"sig-dup".as_slice(),
            101_i64,
        ],
    )
    .expect("insert duplicate changeset_published row");

    // Also insert an unrelated event to ensure it is not affected.
    conn.execute(
        "INSERT INTO ledger_events
            (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            "unrelated-event",
            "work_claimed",
            shared_work_id,
            "actor-1",
            br#"{"ok":true}"#.as_slice(),
            b"sig-unrelated".as_slice(),
            99_i64,
        ],
    )
    .expect("insert unrelated event");

    // Step 3: Run init_schema -- this triggers the quarantine migration.
    SqliteLedgerEventEmitter::init_schema(&conn)
        .expect("init_schema should succeed with pre-existing duplicates");

    // Verification (a): Only one canonical row with that (work_id,
    // changeset_digest) remains in ledger_events.
    let canonical_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM ledger_events
             WHERE event_type = 'changeset_published'
             AND work_id = ?1
             AND json_extract(CAST(payload AS TEXT), '$.changeset_digest') = ?2",
            params![shared_work_id, shared_digest],
            |row| row.get(0),
        )
        .expect("count canonical rows");
    assert_eq!(
        canonical_count, 1,
        "exactly one canonical changeset_published row must remain"
    );

    let kept_event_exists: bool = conn
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM ledger_events WHERE event_id = 'cs-event-keep'
            )",
            [],
            |row| row.get(0),
        )
        .expect("check kept event");
    assert!(
        kept_event_exists,
        "the earliest-inserted (canonical) event must be preserved"
    );

    let duplicate_removed: bool = conn
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM ledger_events WHERE event_id = 'cs-event-duplicate'
            )",
            [],
            |row| row.get(0),
        )
        .expect("check duplicate event");
    assert!(
        !duplicate_removed,
        "the duplicate event must be removed from ledger_events"
    );

    // Verification (b): The quarantine table exists and contains the
    // duplicate with the correct reason.
    let quarantine_table_exists: bool = conn
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM sqlite_master
                WHERE type = 'table' AND name = 'ledger_events_quarantine'
            )",
            [],
            |row| row.get(0),
        )
        .expect("check quarantine table exists");
    assert!(
        quarantine_table_exists,
        "ledger_events_quarantine table must exist after migration"
    );

    let quarantine_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM ledger_events_quarantine
             WHERE event_id = 'cs-event-duplicate'
             AND quarantine_reason = 'changeset_digest_dedupe_migration'",
            [],
            |row| row.get(0),
        )
        .expect("count quarantined duplicates");
    assert_eq!(
        quarantine_count, 1,
        "duplicate changeset_published event must be quarantined exactly once \
         with reason 'changeset_digest_dedupe_migration'"
    );

    // The canonical event must NOT appear in quarantine.
    let canonical_not_quarantined: bool = conn
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM ledger_events_quarantine
                WHERE event_id = 'cs-event-keep'
            )",
            [],
            |row| row.get(0),
        )
        .expect("check canonical not quarantined");
    assert!(
        !canonical_not_quarantined,
        "the canonical event must not be quarantined"
    );

    // The unrelated event must be untouched.
    let unrelated_still_exists: bool = conn
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM ledger_events WHERE event_id = 'unrelated-event'
            )",
            [],
            |row| row.get(0),
        )
        .expect("check unrelated event");
    assert!(
        unrelated_still_exists,
        "unrelated events must not be affected by changeset quarantine migration"
    );

    // Verification (c): The unique index exists.
    let index_exists: bool = conn
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM sqlite_master
                WHERE type = 'index'
                AND name = 'idx_unique_changeset_published'
            )",
            [],
            |row| row.get(0),
        )
        .expect("check unique index exists");
    assert!(
        index_exists,
        "idx_unique_changeset_published unique index must exist after migration"
    );

    // Verification (d): Running init_schema a second time is idempotent.
    SqliteLedgerEventEmitter::init_schema(&conn)
        .expect("second init_schema invocation must be idempotent");

    let canonical_count_after: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM ledger_events
             WHERE event_type = 'changeset_published'
             AND work_id = ?1
             AND json_extract(CAST(payload AS TEXT), '$.changeset_digest') = ?2",
            params![shared_work_id, shared_digest],
            |row| row.get(0),
        )
        .expect("count canonical rows after rerun");
    assert_eq!(
        canonical_count_after, 1,
        "idempotent rerun must not change canonical row count"
    );

    let quarantine_count_after: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM ledger_events_quarantine
             WHERE event_id = 'cs-event-duplicate'
             AND quarantine_reason = 'changeset_digest_dedupe_migration'",
            [],
            |row| row.get(0),
        )
        .expect("count quarantined duplicates after rerun");
    assert_eq!(
        quarantine_count_after, 1,
        "idempotent rerun must not duplicate quarantine entries"
    );
}
