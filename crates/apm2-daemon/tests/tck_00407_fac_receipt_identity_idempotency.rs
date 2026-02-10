//! TCK-00407: FAC receipt identity normalization and semantic idempotency.
//!
//! Verifies that duplicate `IngestReviewReceipt` requests replay the same
//! authoritative event identity and preserve canonical ledger bindings.

use std::sync::{Arc, Mutex};

use apm2_core::crypto::Signer;
use apm2_core::evidence::ContentAddressedStore;
use apm2_core::fac::GateLeaseBuilder;
use apm2_core::htf::{
    BoundedWallInterval, Canonicalizable, ClockProfile, Hlc, LedgerTime, MonotonicReading,
    MonotonicSource, TimeEnvelope, WallTimeSource,
};
use apm2_daemon::cas::{DurableCas, DurableCasConfig};
use apm2_daemon::episode::InMemorySessionRegistry;
use apm2_daemon::ledger::{SqliteLedgerEventEmitter, SqliteWorkRegistry};
use apm2_daemon::protocol::ReviewReceiptVerdict;
use apm2_daemon::protocol::credentials::PeerCredentials;
use apm2_daemon::protocol::dispatch::{
    ConnectionContext, PrivilegedResponse, derive_actor_id, encode_claim_work_request,
    encode_ingest_review_receipt_request,
};
use apm2_daemon::protocol::messages::{ClaimWorkRequest, IngestReviewReceiptRequest, WorkRole};
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

const fn make_peer_credentials() -> PeerCredentials {
    PeerCredentials {
        uid: 1000,
        gid: 1000,
        pid: Some(12345),
    }
}

fn make_privileged_ctx(peer: &PeerCredentials) -> ConnectionContext {
    ConnectionContext::privileged_session_open(Some(peer.clone()))
}

fn claim_work(
    dispatcher: &apm2_daemon::protocol::dispatch::PrivilegedDispatcher,
    ctx: &ConnectionContext,
    actor_id: &str,
) -> String {
    let claim_request = ClaimWorkRequest {
        actor_id: actor_id.to_string(),
        role: WorkRole::Implementer.into(),
        credential_signature: vec![1, 2, 3],
        nonce: vec![4, 5, 6],
    };

    let response = dispatcher
        .dispatch(&encode_claim_work_request(&claim_request), ctx)
        .expect("ClaimWork should dispatch");
    match response {
        PrivilegedResponse::ClaimWork(resp) => resp.work_id,
        other => panic!("Expected ClaimWork response, got {other:?}"),
    }
}

fn store_time_authority_artifacts(cas: &dyn ContentAddressedStore) -> String {
    let clock_profile = ClockProfile {
        attestation: Some(serde_json::json!({"kind": "integration-test"})),
        build_fingerprint: "apm2-daemon/tck-00407".to_string(),
        hlc_enabled: true,
        max_wall_uncertainty_ns: 1_000_000,
        monotonic_source: MonotonicSource::ClockMonotonic,
        profile_policy_id: "tck-00407-profile-policy".to_string(),
        tick_rate_hz: 1_000_000_000,
        wall_time_source: WallTimeSource::AuthenticatedNts,
    };

    let profile_bytes = clock_profile
        .canonical_bytes()
        .expect("clock profile canonicalization should succeed");
    let profile_hash = clock_profile
        .canonical_hash()
        .expect("clock profile hash should succeed");
    let stored_profile = cas
        .store(&profile_bytes)
        .expect("clock profile should store");
    assert_eq!(
        stored_profile.hash, profile_hash,
        "stored profile hash must match canonical hash"
    );

    let envelope = TimeEnvelope {
        clock_profile_hash: hex::encode(profile_hash),
        hlc: Hlc {
            logical: 0,
            wall_ns: 1_800_000_000_000_000_000,
        },
        ledger_anchor: LedgerTime::new("tck-00407-ledger", 0, 1),
        mono: MonotonicReading {
            start_tick: 0,
            end_tick: Some(5_000_000_000),
            tick_rate_hz: 1_000_000_000,
            source: MonotonicSource::ClockMonotonic,
        },
        wall: BoundedWallInterval::new(
            1_800_000_000_000_000_000,
            1_800_000_000_100_000_000,
            WallTimeSource::AuthenticatedNts,
            "95%",
        )
        .expect("bounded wall interval should be valid"),
        notes: Some("tck-00407-receipt-authority".to_string()),
    };

    let envelope_bytes = envelope
        .canonical_bytes()
        .expect("time envelope canonicalization should succeed");
    let envelope_hash = envelope
        .canonical_hash()
        .expect("time envelope hash should succeed");
    let stored_envelope = cas
        .store(&envelope_bytes)
        .expect("time envelope should store");
    assert_eq!(
        stored_envelope.hash, envelope_hash,
        "stored envelope hash must match canonical hash"
    );

    hex::encode(envelope_hash)
}

fn register_authoritative_lease(
    dispatcher: &apm2_daemon::protocol::dispatch::PrivilegedDispatcher,
    cas: &dyn ContentAddressedStore,
    lease_id: &str,
    work_id: &str,
    gate_id: &str,
    executor_actor_id: &str,
) {
    let time_envelope_ref = store_time_authority_artifacts(cas);
    let signer = Signer::generate();
    let full_lease = GateLeaseBuilder::new(lease_id, work_id, gate_id)
        .changeset_digest([0x42; 32])
        .executor_actor_id(executor_actor_id)
        .issued_at(1_000_000)
        .expires_at(2_000_000)
        .policy_hash([0; 32])
        .issuer_actor_id("issuer-tck-00407")
        .time_envelope_ref(&time_envelope_ref)
        .build_and_sign(&signer);

    dispatcher
        .lease_validator()
        .register_full_lease(&full_lease)
        .expect("full lease registration should succeed");
}

fn count_review_receipt_events(
    dispatcher: &apm2_daemon::protocol::dispatch::PrivilegedDispatcher,
    work_id: &str,
) -> usize {
    dispatcher
        .event_emitter()
        .get_events_by_work_id(work_id)
        .into_iter()
        .filter(|event| event.event_type == "review_receipt_recorded")
        .count()
}

#[test]
fn tck_00407_ingest_review_receipt_semantic_replay_returns_stable_authoritative_identity() {
    let conn = make_sqlite_conn();
    let (_cas_root, cas_path) = make_secure_cas_dir();
    let cas = DurableCas::new(DurableCasConfig::new(cas_path.clone()))
        .expect("durable CAS should initialize");

    let session_registry: Arc<dyn SessionRegistry> = Arc::new(InMemorySessionRegistry::new());
    let state = DispatcherState::with_persistence_and_cas(
        session_registry,
        None,
        Arc::clone(&conn),
        &cas_path,
    )
    .expect("production dispatcher state should initialize");
    let dispatcher = state.privileged_dispatcher();

    let peer = make_peer_credentials();
    let ctx = make_privileged_ctx(&peer);
    let actor_id = derive_actor_id(&peer);
    let work_id = claim_work(dispatcher, &ctx, &actor_id);

    let lease_id = "lease-tck-00407-001";
    register_authoritative_lease(
        dispatcher,
        &cas,
        lease_id,
        &work_id,
        "gate-tck-00407",
        &actor_id,
    );

    let artifact_store = cas
        .store(b"tck-00407-artifact-bundle")
        .expect("artifact bundle should store in CAS");
    let changeset_digest = vec![0x42; 32];

    let request = IngestReviewReceiptRequest {
        lease_id: lease_id.to_string(),
        receipt_id: "RR-TCK-00407-001".to_string(),
        reviewer_actor_id: actor_id,
        changeset_digest,
        artifact_bundle_hash: artifact_store.hash.to_vec(),
        verdict: ReviewReceiptVerdict::Approve.into(),
        blocked_reason_code: 0,
        blocked_log_hash: Vec::new(),
        identity_proof_hash: vec![0x99; 32],
    };

    let response_1 = dispatcher
        .dispatch(&encode_ingest_review_receipt_request(&request), &ctx)
        .expect("first IngestReviewReceipt should dispatch");
    let response_2 = dispatcher
        .dispatch(&encode_ingest_review_receipt_request(&request), &ctx)
        .expect("duplicate IngestReviewReceipt should dispatch");

    let (event_id_1, event_type_1) = match response_1 {
        PrivilegedResponse::IngestReviewReceipt(resp) => (resp.event_id, resp.event_type),
        other => panic!("Expected IngestReviewReceipt response, got {other:?}"),
    };
    let (event_id_2, event_type_2) = match response_2 {
        PrivilegedResponse::IngestReviewReceipt(resp) => (resp.event_id, resp.event_type),
        other => panic!("Expected replayed IngestReviewReceipt response, got {other:?}"),
    };

    assert_eq!(
        event_id_1, event_id_2,
        "duplicate semantic receipt request must return the canonical original event_id"
    );
    assert_eq!(
        event_type_1, event_type_2,
        "duplicate semantic receipt request must return stable event_type"
    );
    assert_eq!(
        count_review_receipt_events(dispatcher, &work_id),
        1,
        "duplicate semantic receipt request must not create a second review_receipt_recorded row"
    );
    assert_eq!(
        count_review_receipt_events(dispatcher, lease_id),
        0,
        "canonical work_id binding must prevent lease_id aliasing in work_id index"
    );

    let semantic_event = dispatcher
        .event_emitter()
        .get_event_by_receipt_identity(
            "RR-TCK-00407-001",
            lease_id,
            &work_id,
            &hex::encode([0x42u8; 32]),
        )
        .expect("semantic receipt identity tuple should resolve");
    assert_eq!(
        semantic_event.event_id, event_id_1,
        "semantic lookup must resolve to the authoritative persisted event"
    );
    assert_eq!(
        semantic_event.work_id, work_id,
        "event work_id column must bind to authoritative work_id"
    );

    let payload: serde_json::Value =
        serde_json::from_slice(&semantic_event.payload).expect("payload must be JSON");
    assert_eq!(
        payload.get("lease_id").and_then(serde_json::Value::as_str),
        Some(lease_id),
        "receipt payload must preserve lease_id binding"
    );
    assert_eq!(
        payload.get("work_id").and_then(serde_json::Value::as_str),
        Some(work_id.as_str()),
        "receipt payload must include canonical work_id binding"
    );
}
