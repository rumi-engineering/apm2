//! TCK-00438: Umbrella rollout validation for FAC launch over subagents.
//!
//! Cross-slice integration coverage:
//! - Launch admission lineage (role/context hash binding)
//! - Markov-blanket boundary enforcement (channel token + fail-closed defects)
//! - Liveness heartbeat + bounded restart policy
//! - Auditor/orchestrator projection determinism and fail-closed uncertainty

#![allow(clippy::doc_markdown)]

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use apm2_core::channel::{
    ChannelBoundaryCheck, ChannelSource, ChannelViolationClass, decode_channel_context_token,
    derive_channel_source_witness, issue_channel_context_token, validate_channel_boundary,
};
use apm2_core::crypto::Signer;
use apm2_core::fac::{
    AuditorLaunchProjectionV1, OrchestratorLaunchProjectionV1,
    fac_workobject_implementor_v2_role_contract,
};
use apm2_core::liveness::{
    HealthVerdict, LivenessDenialReason, RestartController, RestartDecision, RestartPolicyConfig,
    TerminalReason, check_liveness_for_progression,
};
use apm2_daemon::cas::{DurableCas, DurableCasConfig};
use apm2_daemon::episode::InMemorySessionRegistry;
use apm2_daemon::ledger::{SqliteLedgerEventEmitter, SqliteWorkRegistry};
use apm2_daemon::protocol::dispatch::{
    ConnectionContext, PrivilegedPcacLifecycleArtifacts, SignedLedgerEvent, WorkClaim,
    build_liveness_heartbeat, encode_auditor_launch_projection_request, encode_claim_work_request,
    encode_end_session_request, encode_orchestrator_launch_projection_request,
    encode_spawn_episode_request, policy_context_pack_hash,
};
use apm2_daemon::protocol::messages::{
    AuditorLaunchProjectionRequest, ClaimWorkRequest, ClaimWorkResponse, EndSessionRequest,
    OrchestratorLaunchProjectionRequest, PrivilegedErrorCode, SpawnEpisodeRequest,
    TerminationOutcome, WorkRole,
};
use apm2_daemon::protocol::{
    PeerCredentials, PrivilegedResponse, ProjectionUncertaintyFlag, derive_actor_id,
};
use apm2_daemon::session::SessionRegistry;
use apm2_daemon::state::DispatcherState;
use rusqlite::{Connection, params};
use tempfile::TempDir;

const TEST_WORKSPACE: &str = "/tmp";

const fn test_peer_credentials() -> PeerCredentials {
    PeerCredentials {
        uid: 1000,
        gid: 1000,
        pid: Some(4380),
    }
}

fn make_privileged_ctx(peer: &PeerCredentials) -> ConnectionContext {
    ConnectionContext::privileged_session_open(Some(peer.clone()))
}

fn make_sqlite_conn() -> Arc<Mutex<Connection>> {
    let conn = Connection::open_in_memory().expect("sqlite in-memory should open");
    SqliteLedgerEventEmitter::init_schema(&conn).expect("ledger schema init should succeed");
    SqliteWorkRegistry::init_schema(&conn).expect("work schema init should succeed");
    Arc::new(Mutex::new(conn))
}

fn make_dispatcher_state(
    sqlite_conn: Arc<Mutex<Connection>>,
    cas_path: &Path,
) -> Arc<DispatcherState> {
    let session_registry: Arc<dyn SessionRegistry> = Arc::new(InMemorySessionRegistry::new());
    Arc::new(
        DispatcherState::with_persistence_and_cas(session_registry, None, sqlite_conn, cas_path)
            .expect("dispatcher state with persistence and CAS should initialize"),
    )
}

fn claim_work(
    dispatcher: &apm2_daemon::protocol::dispatch::PrivilegedDispatcher,
    ctx: &ConnectionContext,
    actor_hint: &str,
) -> ClaimWorkResponse {
    let frame = encode_claim_work_request(&ClaimWorkRequest {
        actor_id: actor_hint.to_string(),
        role: WorkRole::Implementer.into(),
        credential_signature: vec![1, 2, 3],
        nonce: vec![4, 5, 6],
    });

    match dispatcher
        .dispatch(&frame, ctx)
        .expect("claim request should dispatch")
    {
        PrivilegedResponse::ClaimWork(resp) => resp,
        other => panic!("expected ClaimWork response, got: {other:?}"),
    }
}

fn spawn_request(
    work_id: &str,
    lease_id: &str,
    adapter_profile_hash: Option<Vec<u8>>,
) -> SpawnEpisodeRequest {
    SpawnEpisodeRequest {
        work_id: work_id.to_string(),
        role: WorkRole::Implementer.into(),
        lease_id: Some(lease_id.to_string()),
        workspace_root: TEST_WORKSPACE.to_string(),
        max_episodes: None,
        escalation_predicate: None,
        adapter_profile_hash,
        permeability_receipt_hash: None,
    }
}

fn to_hash32(bytes: &[u8], field: &str) -> [u8; 32] {
    <[u8; 32]>::try_from(bytes)
        .unwrap_or_else(|_| panic!("{field} must be 32 bytes, got {}", bytes.len()))
}

fn parse_payload(event: &SignedLedgerEvent) -> serde_json::Value {
    serde_json::from_slice(&event.payload).expect("ledger payload must be valid JSON")
}

fn find_event<'a>(events: &'a [SignedLedgerEvent], event_type: &str) -> &'a SignedLedgerEvent {
    events
        .iter()
        .find(|event| event.event_type == event_type)
        .unwrap_or_else(|| panic!("missing {event_type} event in ledger stream"))
}

fn decode_hash32(payload: &serde_json::Value, field: &str) -> [u8; 32] {
    let Some(value) = payload.get(field).and_then(serde_json::Value::as_str) else {
        panic!("{field} must exist as hex string");
    };

    let bytes = hex::decode(value).unwrap_or_else(|error| {
        panic!("{field} must be valid hex: {error}");
    });

    to_hash32(&bytes, field)
}

fn assert_projection_digest_matches(digest: &[u8], canonical_projection_json: &[u8]) {
    assert_eq!(
        digest.len(),
        32,
        "projection_digest must be exactly 32 bytes"
    );
    assert_eq!(
        digest,
        blake3::hash(canonical_projection_json).as_bytes(),
        "projection_digest must match canonical_projection_json hash"
    );
}

fn decode_uncertainty_flags(raw_flags: &[i32]) -> BTreeSet<ProjectionUncertaintyFlag> {
    raw_flags
        .iter()
        .map(|raw| {
            ProjectionUncertaintyFlag::try_from(*raw)
                .expect("projection uncertainty flag should decode")
        })
        .collect()
}

fn store_test_adapter_profile(cas_path: &Path) -> [u8; 32] {
    let mut profile = apm2_core::fac::builtin_profiles::claude_code_profile();
    profile.profile_id = "tck-00438-raw-sleep".to_string();
    profile.command = "/bin/sh".to_string();
    profile.args_template = vec!["-lc".to_string(), "sleep 30".to_string()];

    let cas =
        DurableCas::new(DurableCasConfig::new(cas_path.to_path_buf())).expect("CAS should open");
    profile
        .store_in_cas(&cas)
        .expect("test adapter profile should store in CAS")
}

fn load_claim(sqlite_conn: &Arc<Mutex<Connection>>, work_id: &str) -> WorkClaim {
    let conn = sqlite_conn
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let claim_json: Vec<u8> = conn
        .query_row(
            "SELECT claim_json FROM work_claims WHERE work_id = ?1",
            params![work_id],
            |row| row.get(0),
        )
        .expect("claim_json should exist for claimed work");

    serde_json::from_slice(&claim_json).expect("claim_json should deserialize")
}

fn persist_claim(sqlite_conn: &Arc<Mutex<Connection>>, claim: &WorkClaim) {
    let claim_json = serde_json::to_vec(claim).expect("claim should serialize");
    let conn = sqlite_conn
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    conn.execute(
        "UPDATE work_claims SET claim_json = ?2 WHERE work_id = ?1",
        params![claim.work_id, claim_json],
    )
    .expect("claim update should succeed");
}

fn seed_malformed_receipt(conn: &Arc<Mutex<Connection>>, lease_id: &str) {
    let payload = serde_json::json!({
        "receipt_id": "RCP-TCK-00438-MALFORMED",
        "changeset_digest": "11".repeat(32),
        "lease_id": lease_id,
        // Deliberately omit role_spec_hash/context_pack_hash/identity_proof_hash/time_envelope_ref
        // so projections fail closed on lineage + boundary checks.
    });
    let payload_bytes = serde_json::to_vec(&payload).expect("payload should serialize");

    let conn_guard = conn
        .lock()
        .expect("sqlite lock should be available for malformed receipt seed");
    conn_guard
        .execute(
            "INSERT INTO ledger_events
                 (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                "EVT-TCK-00438-MALFORMED",
                "review_receipt_recorded",
                "W-TCK-00438-MALFORMED",
                "actor:reviewer",
                payload_bytes,
                vec![0u8; 64],
                4_380_000_001i64,
            ],
        )
        .expect("malformed receipt insert should succeed");
}

#[test]
fn tck_00438_launch_rollout_e2e_lineage_liveness_and_projection() {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime should initialize");
    let _guard = rt.enter();

    let temp_dir = TempDir::new().expect("temp dir should be created");
    let cas_path = temp_dir.path().join("cas");
    let sqlite_conn = make_sqlite_conn();
    let state = make_dispatcher_state(Arc::clone(&sqlite_conn), &cas_path);
    let dispatcher = state.privileged_dispatcher();

    let custom_adapter_profile_hash = store_test_adapter_profile(&cas_path);

    let peer = test_peer_credentials();
    let ctx = make_privileged_ctx(&peer);
    let actor_id = derive_actor_id(&peer);

    let claim = claim_work(dispatcher, &ctx, "tck-00438-e2e");
    let expected_context_hash = policy_context_pack_hash(&claim.work_id, &actor_id);
    assert_eq!(
        to_hash32(&claim.context_pack_hash, "context_pack_hash"),
        expected_context_hash,
        "claim context hash must match deterministic policy context hash"
    );

    let spawn = spawn_request(
        &claim.work_id,
        &claim.lease_id,
        Some(custom_adapter_profile_hash.to_vec()),
    );
    let spawn_frame = encode_spawn_episode_request(&spawn);
    let spawn_response = match dispatcher
        .dispatch(&spawn_frame, &ctx)
        .expect("spawn request should dispatch")
    {
        PrivilegedResponse::SpawnEpisode(resp) => resp,
        other => panic!("expected SpawnEpisode success, got: {other:?}"),
    };

    assert!(
        !spawn_response.session_id.is_empty(),
        "spawn must return non-empty session_id"
    );
    assert_eq!(
        spawn_response.capability_manifest_hash, claim.capability_manifest_hash,
        "spawn capability hash must preserve claim-time admission binding"
    );

    let events = dispatcher
        .event_emitter()
        .get_events_by_work_id(&claim.work_id);
    let work_claimed = parse_payload(find_event(&events, "work_claimed"));
    let session_started = parse_payload(find_event(&events, "session_started"));

    let expected_role_hash = fac_workobject_implementor_v2_role_contract()
        .compute_cas_hash()
        .expect("builtin role hash should compute");
    let role_hash = decode_hash32(&work_claimed, "role_spec_hash");
    let context_hash = decode_hash32(&work_claimed, "context_pack_hash");
    let recipe_hash = decode_hash32(&work_claimed, "context_pack_recipe_hash");

    assert_eq!(
        role_hash, expected_role_hash,
        "work_claimed role hash must bind to authoritative implementer role"
    );
    assert_eq!(
        context_hash, expected_context_hash,
        "work_claimed context hash must bind deterministic policy context"
    );
    assert_ne!(
        recipe_hash, [0u8; 32],
        "context recipe hash must be populated for launch lineage"
    );
    assert_eq!(
        decode_hash32(&session_started, "role_spec_hash"),
        role_hash,
        "session_started role hash must preserve launch role lineage"
    );

    let boundary_check = ChannelBoundaryCheck {
        source: ChannelSource::TypedToolIntent,
        channel_source_witness: Some(derive_channel_source_witness(
            ChannelSource::TypedToolIntent,
        )),
        broker_verified: true,
        capability_verified: true,
        context_firewall_verified: true,
        policy_ledger_verified: true,
    };
    assert!(
        validate_channel_boundary(&boundary_check).is_empty(),
        "typed + fully verified channel boundary must admit authoritative actuation"
    );

    let signer = Signer::generate();
    let request_id = "REQ-TCK-00438-E2E";
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_secs();

    let token = issue_channel_context_token(
        &boundary_check,
        &claim.lease_id,
        request_id,
        now_secs,
        &signer,
    )
    .expect("channel context token should encode");
    let decoded = decode_channel_context_token(
        &token,
        &signer.verifying_key(),
        &claim.lease_id,
        now_secs,
        request_id,
    )
    .expect("channel context token should decode");
    assert_eq!(decoded, boundary_check);

    let capability_manifest_hash = to_hash32(
        &spawn_response.capability_manifest_hash,
        "capability_manifest_hash",
    );
    let changeset_digest = *blake3::hash(b"tck-00438-changeset").as_bytes();
    let artifact_bundle_hash = *blake3::hash(b"tck-00438-artifact-bundle").as_bytes();
    let identity_proof_hash = *blake3::hash(b"tck-00438-identity-proof").as_bytes();
    let lifecycle = PrivilegedPcacLifecycleArtifacts {
        ajc_id: [0x81; 32],
        intent_digest: [0x82; 32],
        consume_tick: 77,
        time_envelope_ref: [0x83; 32],
        consume_selector_digest: [0x84; 32],
    };

    let receipt_event = dispatcher
        .event_emitter()
        .emit_review_receipt(
            &claim.lease_id,
            &claim.work_id,
            "RCP-TCK-00438-001",
            &changeset_digest,
            &artifact_bundle_hash,
            &capability_manifest_hash,
            &context_hash,
            &role_hash,
            "actor:reviewer",
            4_380_000_100,
            &identity_proof_hash,
            "cas://time-envelope/tck-00438/001",
            Some(&lifecycle),
        )
        .expect("receipt event should persist");

    let receipt_payload = parse_payload(&receipt_event);
    assert_eq!(
        decode_hash32(&receipt_payload, "role_spec_hash"),
        role_hash,
        "receipt must preserve role hash lineage from launch"
    );
    assert_eq!(
        decode_hash32(&receipt_payload, "context_pack_hash"),
        context_hash,
        "receipt must preserve context hash lineage from launch"
    );
    assert_eq!(
        decode_hash32(&receipt_payload, "capability_manifest_hash"),
        capability_manifest_hash,
        "receipt must preserve capability hash lineage from launch"
    );
    assert_eq!(
        receipt_payload["consume_tick"].as_u64(),
        Some(lifecycle.consume_tick),
        "receipt must carry consume_tick for orchestrator projection"
    );

    let heartbeat = build_liveness_heartbeat(
        &[0xAB; 32],
        "run-tck-00438-e2e",
        100,
        HealthVerdict::Healthy,
    );
    check_liveness_for_progression(&heartbeat, 101, 5)
        .expect("fresh healthy heartbeat should allow progression");

    let restart_config = RestartPolicyConfig {
        max_restarts: 1,
        window_ticks: 20,
        circuit_breaker_threshold_ticks: 10,
        circuit_breaker_max_failures: 10,
        stall_timeout_ticks: 8,
    };
    let mut restart_controller =
        RestartController::new(restart_config).expect("restart policy config should be valid");
    assert_eq!(
        restart_controller.record_restart(200),
        RestartDecision::Allow { attempt: 1 },
        "first restart inside bound should be allowed"
    );
    assert_eq!(
        restart_controller.record_restart(201),
        RestartDecision::Deny {
            reason: TerminalReason::RestartLimitExceeded,
        },
        "restart beyond bound must deny"
    );

    let auditor_frame =
        encode_auditor_launch_projection_request(&AuditorLaunchProjectionRequest {});
    let first_auditor = match dispatcher
        .dispatch(&auditor_frame, &ctx)
        .expect("auditor projection should dispatch")
    {
        PrivilegedResponse::AuditorLaunchProjection(resp) => resp,
        other => panic!("expected AuditorLaunchProjection response, got: {other:?}"),
    };
    let second_auditor = match dispatcher
        .dispatch(&auditor_frame, &ctx)
        .expect("auditor projection should dispatch")
    {
        PrivilegedResponse::AuditorLaunchProjection(resp) => resp,
        other => panic!("expected AuditorLaunchProjection response, got: {other:?}"),
    };

    assert_eq!(
        first_auditor, second_auditor,
        "auditor projection must be replay-deterministic"
    );
    assert_projection_digest_matches(
        &first_auditor.projection_digest,
        &first_auditor.canonical_projection_json,
    );
    assert_eq!(first_auditor.authoritative_receipt_count, 1);
    assert_eq!(first_auditor.complete_lineage_receipt_count, 1);
    assert_eq!(first_auditor.boundary_conformant_receipt_count, 1);
    assert!(first_auditor.lineage_complete);
    assert!(first_auditor.boundary_conformant);
    assert!(first_auditor.uncertainty_flags.is_empty());
    assert!(first_auditor.admissible);

    let canonical_auditor: AuditorLaunchProjectionV1 =
        serde_json::from_slice(&first_auditor.canonical_projection_json)
            .expect("canonical auditor projection must decode");
    assert_eq!(
        canonical_auditor.authoritative_receipt_count,
        first_auditor.authoritative_receipt_count
    );
    assert_eq!(canonical_auditor.admissible, first_auditor.admissible);

    let orchestrator_frame =
        encode_orchestrator_launch_projection_request(&OrchestratorLaunchProjectionRequest {});
    let first_orchestrator = match dispatcher
        .dispatch(&orchestrator_frame, &ctx)
        .expect("orchestrator projection should dispatch")
    {
        PrivilegedResponse::OrchestratorLaunchProjection(resp) => resp,
        other => panic!("expected OrchestratorLaunchProjection response, got: {other:?}"),
    };
    let second_orchestrator = match dispatcher
        .dispatch(&orchestrator_frame, &ctx)
        .expect("orchestrator projection should dispatch")
    {
        PrivilegedResponse::OrchestratorLaunchProjection(resp) => resp,
        other => panic!("expected OrchestratorLaunchProjection response, got: {other:?}"),
    };

    assert_eq!(
        first_orchestrator, second_orchestrator,
        "orchestrator projection must be replay-deterministic"
    );
    assert_projection_digest_matches(
        &first_orchestrator.projection_digest,
        &first_orchestrator.canonical_projection_json,
    );
    assert_eq!(
        first_orchestrator.active_runs, 1,
        "active run count must reflect spawned (non-terminated) session"
    );
    assert_eq!(
        first_orchestrator.last_authoritative_receipt_tick,
        Some(lifecycle.consume_tick),
        "orchestrator projection must surface latest authoritative consume tick"
    );
    assert_eq!(
        first_orchestrator.restart_count, 0,
        "no non-zero session termination means no restart count increment"
    );
    assert!(first_orchestrator.uncertainty_flags.is_empty());
    assert!(first_orchestrator.admissible);

    let canonical_orchestrator: OrchestratorLaunchProjectionV1 =
        serde_json::from_slice(&first_orchestrator.canonical_projection_json)
            .expect("canonical orchestrator projection must decode");
    assert_eq!(
        canonical_orchestrator.active_runs,
        first_orchestrator.active_runs
    );
    assert_eq!(
        canonical_orchestrator.last_authoritative_receipt_tick,
        first_orchestrator.last_authoritative_receipt_tick
    );

    let end_frame = encode_end_session_request(&EndSessionRequest {
        session_id: spawn_response.session_id,
        reason: "tck-00438 cleanup".to_string(),
        outcome: TerminationOutcome::Success.into(),
    });
    match dispatcher
        .dispatch(&end_frame, &ctx)
        .expect("end session request should dispatch")
    {
        PrivilegedResponse::EndSession(resp) => assert!(
            !resp.session_id.is_empty(),
            "end session response must echo session"
        ),
        other => panic!("expected EndSession response, got: {other:?}"),
    }
}

#[test]
fn tck_00438_launch_rollout_fails_closed_on_missing_or_inconsistent_slices() {
    let temp_dir = TempDir::new().expect("temp dir should be created");
    let cas_path = temp_dir.path().join("cas");
    let sqlite_conn = make_sqlite_conn();
    let state = make_dispatcher_state(Arc::clone(&sqlite_conn), &cas_path);
    let dispatcher = state.privileged_dispatcher();

    let peer = test_peer_credentials();
    let ctx = make_privileged_ctx(&peer);

    // Launch admission fail-closed: tamper stored role hash lineage.
    let claim = claim_work(dispatcher, &ctx, "tck-00438-fail-closed");
    let mut tampered_claim = load_claim(&sqlite_conn, &claim.work_id);
    tampered_claim.policy_resolution.role_spec_hash =
        *blake3::hash(b"tck-00438-role-hash-tamper").as_bytes();
    persist_claim(&sqlite_conn, &tampered_claim);

    let response = dispatcher
        .dispatch(
            &encode_spawn_episode_request(&spawn_request(&claim.work_id, &claim.lease_id, None)),
            &ctx,
        )
        .expect("spawn request should dispatch");

    match response {
        PrivilegedResponse::Error(err) => {
            assert_eq!(
                err.code,
                PrivilegedErrorCode::CapabilityRequestRejected as i32,
                "tampered launch lineage must deny with capability rejection"
            );
            assert!(
                err.message.contains("role_spec_hash mismatch"),
                "tampered launch lineage denial must mention role hash mismatch: {}",
                err.message
            );
        },
        other => panic!("expected fail-closed SpawnEpisode error, got: {other:?}"),
    }

    assert!(
        dispatcher
            .session_registry()
            .get_session_by_work_id(&claim.work_id)
            .is_none(),
        "fail-closed launch denial must not register a session"
    );

    // Boundary fail-closed: missing typed source witness is denied.
    let boundary_defects = validate_channel_boundary(&ChannelBoundaryCheck {
        source: ChannelSource::TypedToolIntent,
        channel_source_witness: None,
        broker_verified: true,
        capability_verified: true,
        context_firewall_verified: true,
        policy_ledger_verified: true,
    });
    let boundary_classes: Vec<ChannelViolationClass> = boundary_defects
        .iter()
        .map(|defect| defect.violation_class)
        .collect();
    assert!(
        boundary_classes.contains(&ChannelViolationClass::MissingChannelMetadata),
        "missing witness must emit MissingChannelMetadata defect"
    );
    assert!(
        boundary_classes.contains(&ChannelViolationClass::UnknownChannelSource),
        "missing witness must force unknown source fail-closed"
    );

    // Liveness fail-closed: stale heartbeat + bounded restart denial.
    let heartbeat = build_liveness_heartbeat(
        &[0xDD; 32],
        "run-tck-00438-stale",
        10,
        HealthVerdict::Healthy,
    );
    let stale_denial = check_liveness_for_progression(&heartbeat, 30, 5)
        .expect_err("stale heartbeat must deny progression");
    assert_eq!(stale_denial.reason, LivenessDenialReason::StaleHeartbeat);

    let mut restart_controller = RestartController::new(RestartPolicyConfig {
        max_restarts: 1,
        window_ticks: 20,
        circuit_breaker_threshold_ticks: 10,
        circuit_breaker_max_failures: 10,
        stall_timeout_ticks: 8,
    })
    .expect("restart policy config should be valid");

    assert_eq!(
        restart_controller.record_restart(100),
        RestartDecision::Allow { attempt: 1 }
    );
    assert_eq!(
        restart_controller.record_restart(101),
        RestartDecision::Deny {
            reason: TerminalReason::RestartLimitExceeded,
        },
        "restart controller must fail closed at the configured bound"
    );

    // Projection fail-closed: malformed receipt lacks lineage + boundary fields.
    seed_malformed_receipt(&sqlite_conn, &claim.lease_id);

    let auditor = match dispatcher
        .dispatch(
            &encode_auditor_launch_projection_request(&AuditorLaunchProjectionRequest {}),
            &ctx,
        )
        .expect("auditor projection should dispatch")
    {
        PrivilegedResponse::AuditorLaunchProjection(resp) => resp,
        other => panic!("expected AuditorLaunchProjection response, got: {other:?}"),
    };

    assert_projection_digest_matches(
        &auditor.projection_digest,
        &auditor.canonical_projection_json,
    );
    assert_eq!(auditor.authoritative_receipt_count, 1);
    assert_eq!(auditor.complete_lineage_receipt_count, 0);
    assert_eq!(auditor.boundary_conformant_receipt_count, 0);
    assert!(!auditor.lineage_complete);
    assert!(!auditor.boundary_conformant);
    assert!(!auditor.admissible);

    let mut expected_auditor_flags = BTreeSet::new();
    expected_auditor_flags.insert(ProjectionUncertaintyFlag::MissingLineageEvidence);
    expected_auditor_flags.insert(ProjectionUncertaintyFlag::BoundaryConformanceUnverifiable);
    assert_eq!(
        decode_uncertainty_flags(&auditor.uncertainty_flags),
        expected_auditor_flags,
        "malformed receipt lineage must fail closed in auditor projection"
    );

    let orchestrator = match dispatcher
        .dispatch(
            &encode_orchestrator_launch_projection_request(&OrchestratorLaunchProjectionRequest {}),
            &ctx,
        )
        .expect("orchestrator projection should dispatch")
    {
        PrivilegedResponse::OrchestratorLaunchProjection(resp) => resp,
        other => panic!("expected OrchestratorLaunchProjection response, got: {other:?}"),
    };

    assert_projection_digest_matches(
        &orchestrator.projection_digest,
        &orchestrator.canonical_projection_json,
    );
    assert_eq!(orchestrator.active_runs, 0);
    assert_eq!(orchestrator.last_authoritative_receipt_tick, None);
    assert!(!orchestrator.admissible);

    let mut expected_orchestrator_flags = BTreeSet::new();
    expected_orchestrator_flags.insert(ProjectionUncertaintyFlag::MissingLivenessEvidence);
    expected_orchestrator_flags.insert(ProjectionUncertaintyFlag::MissingAuthoritativeReceiptTick);
    assert_eq!(
        decode_uncertainty_flags(&orchestrator.uncertainty_flags),
        expected_orchestrator_flags,
        "missing liveness/receipt tick must fail closed in orchestrator projection"
    );
}
