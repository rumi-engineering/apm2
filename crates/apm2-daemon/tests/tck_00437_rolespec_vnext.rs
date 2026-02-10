//! TCK-00437: FAC RoleSpec vNext rollout validation for WorkObject execution.
//!
//! Cross-slice integration coverage:
//! - RoleSpec vNext selected by authoritative hash.
//! - Deterministic context recipe reconstruction from receipt-bound hashes.
//! - Production spawn-path lineage binding (role/context hash chain).
//! - Fail-closed denials for role/context ambiguity and lineage breaks.
#![allow(clippy::doc_markdown)]

use std::path::Path;
use std::sync::{Arc, Mutex};

use apm2_core::context::reconstruct_from_receipts;
use apm2_core::evidence::ContentAddressedStore;
use apm2_core::fac::{builtin_profiles, fac_workobject_implementor_v2_role_contract};
use apm2_daemon::cas::{DurableCas, DurableCasConfig};
use apm2_daemon::episode::InMemorySessionRegistry;
use apm2_daemon::ledger::{SqliteLedgerEventEmitter, SqliteWorkRegistry};
use apm2_daemon::protocol::credentials::PeerCredentials;
use apm2_daemon::protocol::dispatch::{
    ConnectionContext, PolicyResolution, PrivilegedResponse, SignedLedgerEvent, WorkClaim,
    build_policy_context_pack_recipe, encode_claim_work_request, encode_end_session_request,
    encode_spawn_episode_request, policy_context_pack_hash, policy_context_pack_recipe_hash,
    resolve_workobject_role_spec_hash, seed_policy_artifacts_in_cas,
};
use apm2_daemon::protocol::messages::{
    ClaimWorkRequest, ClaimWorkResponse, EndSessionRequest, PrivilegedErrorCode,
    SpawnEpisodeRequest, TerminationOutcome, WorkRole,
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
        pid: Some(4242),
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
) -> ClaimWorkResponse {
    let frame = encode_claim_work_request(&ClaimWorkRequest {
        actor_id: "tck-00437-actor-hint".to_string(),
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

fn to_hash32(bytes: Vec<u8>, field: &str) -> [u8; 32] {
    bytes
        .try_into()
        .unwrap_or_else(|b: Vec<u8>| panic!("{field} must be 32 bytes, got {}", b.len()))
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

fn store_required_read_digest_preimage(
    cas: &dyn ContentAddressedStore,
    recipe: &apm2_core::context::ContextPackRecipe,
) {
    let mut payload = Vec::new();
    for (path, digest) in &recipe.required_read_digests {
        let path_len =
            u32::try_from(path.len()).expect("required read path length must fit in u32");
        payload.extend_from_slice(&path_len.to_be_bytes());
        payload.extend_from_slice(path.as_bytes());
        payload.extend_from_slice(digest);
    }

    let stored_hash = cas
        .store(&payload)
        .expect("required-read digest preimage should store")
        .hash;
    assert_eq!(
        stored_hash, recipe.required_read_digest_set_hash,
        "required read digest preimage hash must match recipe binding"
    );
}

fn store_budget_profile_preimage(cas: &dyn ContentAddressedStore, work_id: &str, actor_id: &str) {
    let payload = format!("budget:{work_id}:{actor_id}");
    let stored_hash = cas
        .store(payload.as_bytes())
        .expect("budget profile preimage should store")
        .hash;
    let expected = *blake3::hash(payload.as_bytes()).as_bytes();
    assert_eq!(
        stored_hash, expected,
        "budget profile preimage hash must match deterministic binding"
    );
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

fn assert_spawn_denied(
    dispatcher: &apm2_daemon::protocol::dispatch::PrivilegedDispatcher,
    ctx: &ConnectionContext,
    request: &SpawnEpisodeRequest,
    expected_code: PrivilegedErrorCode,
    expected_message_substrings: &[&str],
) {
    let baseline_events = dispatcher
        .event_emitter()
        .get_events_by_work_id(&request.work_id);

    let frame = encode_spawn_episode_request(request);
    let response = dispatcher
        .dispatch(&frame, ctx)
        .expect("spawn request should dispatch");

    match response {
        PrivilegedResponse::Error(err) => {
            assert_eq!(
                err.code, expected_code as i32,
                "unexpected fail-closed error code"
            );
            for expected in expected_message_substrings {
                assert!(
                    err.message.contains(expected),
                    "error must contain '{expected}', got: {}",
                    err.message
                );
            }
        },
        other => panic!("expected fail-closed SpawnEpisode error, got: {other:?}"),
    }

    let after_events = dispatcher
        .event_emitter()
        .get_events_by_work_id(&request.work_id);
    assert_eq!(
        after_events.len(),
        baseline_events.len(),
        "fail-closed spawn denial must not append ledger side effects"
    );
    assert!(
        dispatcher
            .session_registry()
            .get_session_by_work_id(&request.work_id)
            .is_none(),
        "fail-closed spawn denial must not register a session"
    );
}

fn store_test_adapter_profile(cas_path: &Path) -> [u8; 32] {
    let mut profile = builtin_profiles::claude_code_profile();
    profile.profile_id = "tck-00437-raw-sleep".to_string();
    profile.command = "/bin/sh".to_string();
    profile.args_template = vec!["-lc".to_string(), "sleep 30".to_string()];

    let cas = DurableCas::new(DurableCasConfig::new(cas_path.to_path_buf()))
        .expect("durable CAS should open for adapter profile storage");
    profile
        .store_in_cas(&cas)
        .expect("test adapter profile should store in CAS")
}

#[test]
fn tck_00437_rolespec_vnext_hash_lineage_and_spawn_binding() {
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
    let actor_id = apm2_daemon::protocol::derive_actor_id(&peer);

    let claim = claim_work(dispatcher, &ctx);
    let work_id = claim.work_id.clone();
    let lease_id = claim.lease_id.clone();

    let cas = DurableCas::new(DurableCasConfig::new(cas_path))
        .expect("durable CAS should open for lineage verification");

    let contract_hash = fac_workobject_implementor_v2_role_contract()
        .compute_cas_hash()
        .expect("RoleSpec vNext contract hash should compute");
    let resolved_role_hash = resolve_workobject_role_spec_hash(&cas)
        .expect("authoritative RoleSpec vNext hash should resolve from CAS");

    assert_eq!(
        resolved_role_hash, contract_hash,
        "production RoleSpec vNext selection must match built-in contract hash"
    );

    let claim_context_hash = to_hash32(claim.context_pack_hash, "context_pack_hash");
    let deterministic_context_hash = policy_context_pack_hash(&work_id, &actor_id);
    assert_eq!(
        claim_context_hash, deterministic_context_hash,
        "ClaimWork context hash must match deterministic reconstruction"
    );

    let compiled_a = build_policy_context_pack_recipe(
        &work_id,
        &actor_id,
        resolved_role_hash,
        claim_context_hash,
    )
    .expect("context recipe compilation should succeed");
    let compiled_b = build_policy_context_pack_recipe(
        &work_id,
        &actor_id,
        resolved_role_hash,
        claim_context_hash,
    )
    .expect("deterministic context recipe recompilation should succeed");

    assert_eq!(
        compiled_a.recipe, compiled_b.recipe,
        "same lineage inputs must produce identical ContextPackRecipe"
    );
    assert_eq!(
        compiled_a.fingerprint, compiled_b.fingerprint,
        "same lineage inputs must produce identical drift fingerprint"
    );

    let recipe_hash = policy_context_pack_recipe_hash(
        &work_id,
        &actor_id,
        resolved_role_hash,
        claim_context_hash,
    )
    .expect("context recipe hash should derive");
    assert_eq!(
        recipe_hash, compiled_a.fingerprint.recipe_hash,
        "compiled recipe hash must match deterministic helper hash"
    );

    seed_policy_artifacts_in_cas(
        &work_id,
        &actor_id,
        WorkRole::Implementer,
        resolved_role_hash,
        recipe_hash,
        &cas,
    )
    .expect("policy lineage artifacts should seed in CAS");

    store_required_read_digest_preimage(&cas, &compiled_a.recipe);
    store_budget_profile_preimage(&cas, &work_id, &actor_id);

    let reconstructed = reconstruct_from_receipts(&cas, &compiled_a.fingerprint)
        .expect("context recipe should reconstruct from receipt-bound hashes");
    assert_eq!(
        reconstructed, compiled_a.recipe,
        "reconstruction from receipt hashes must be deterministic"
    );

    let spawn = spawn_request(
        &work_id,
        &lease_id,
        Some(custom_adapter_profile_hash.to_vec()),
    );
    let spawn_frame = encode_spawn_episode_request(&spawn);
    let spawn_response = dispatcher
        .dispatch(&spawn_frame, &ctx)
        .expect("spawn request should dispatch");

    let session_id = match spawn_response {
        PrivilegedResponse::SpawnEpisode(resp) => {
            assert!(
                !resp.session_id.is_empty(),
                "successful spawn must return a non-empty session_id"
            );
            resp.session_id
        },
        other => panic!("expected SpawnEpisode success, got: {other:?}"),
    };

    let events = dispatcher.event_emitter().get_events_by_work_id(&work_id);
    assert!(
        events.len() >= 3,
        "claim + spawn lifecycle must emit multiple ledger events"
    );

    let work_claimed = parse_payload(find_event(&events, "work_claimed"));
    let session_started = parse_payload(find_event(&events, "session_started"));

    let role_hash_hex = hex::encode(resolved_role_hash);
    let context_hash_hex = hex::encode(claim_context_hash);
    let recipe_hash_hex = hex::encode(recipe_hash);

    assert_eq!(
        work_claimed["role_spec_hash"].as_str(),
        Some(role_hash_hex.as_str()),
        "work_claimed event must bind authoritative role hash"
    );
    assert_eq!(
        work_claimed["context_pack_hash"].as_str(),
        Some(context_hash_hex.as_str()),
        "work_claimed event must bind deterministic context hash"
    );
    assert_eq!(
        work_claimed["context_pack_recipe_hash"].as_str(),
        Some(recipe_hash_hex.as_str()),
        "work_claimed event must bind deterministic context recipe hash"
    );
    assert_eq!(
        session_started["role_spec_hash"].as_str(),
        Some(role_hash_hex.as_str()),
        "session_started event must carry spawn-time role hash binding"
    );

    let end_frame = encode_end_session_request(&EndSessionRequest {
        session_id: session_id.clone(),
        reason: "tck-00437 cleanup".to_string(),
        outcome: TerminationOutcome::Success.into(),
    });
    match dispatcher
        .dispatch(&end_frame, &ctx)
        .expect("end session request should dispatch")
    {
        PrivilegedResponse::EndSession(resp) => {
            assert_eq!(
                resp.session_id, session_id,
                "end session response must reference the spawned session"
            );
        },
        other => panic!("expected EndSession response, got: {other:?}"),
    }
}

#[test]
fn tck_00437_rolespec_vnext_spawn_fails_closed_on_role_context_ambiguity() {
    let temp_dir = TempDir::new().expect("temp dir should be created");
    let cas_path = temp_dir.path().join("cas");
    let sqlite_conn = make_sqlite_conn();
    let state = make_dispatcher_state(Arc::clone(&sqlite_conn), &cas_path);
    let dispatcher = state.privileged_dispatcher();

    let peer = test_peer_credentials();
    let ctx = make_privileged_ctx(&peer);

    // Scenario A: ambiguous role profile selection (hash mismatch)
    let claim_a = claim_work(dispatcher, &ctx);
    let mut stored_claim_a = load_claim(&sqlite_conn, &claim_a.work_id);
    stored_claim_a.policy_resolution.role_spec_hash =
        *blake3::hash(b"tck-00437-ambiguous-role").as_bytes();
    persist_claim(&sqlite_conn, &stored_claim_a);

    assert_spawn_denied(
        dispatcher,
        &ctx,
        &spawn_request(&claim_a.work_id, &claim_a.lease_id, None),
        PrivilegedErrorCode::CapabilityRequestRejected,
        &[
            "policy CAS artifact seeding failed",
            "role_spec_hash mismatch",
        ],
    );

    // Scenario B: stale/mismatched context recipe lineage
    let claim_b = claim_work(dispatcher, &ctx);
    let mut stored_claim_b = load_claim(&sqlite_conn, &claim_b.work_id);

    let durable_cas = DurableCas::new(DurableCasConfig::new(cas_path))
        .expect("durable CAS should open for stale recipe injection");
    let stale_recipe = build_policy_context_pack_recipe(
        "W-TCK-00437-LEGACY",
        "actor:legacy",
        stored_claim_b.policy_resolution.role_spec_hash,
        stored_claim_b.policy_resolution.context_pack_hash,
    )
    .expect("stale recipe should compile");
    let stale_bytes = stale_recipe
        .recipe
        .canonical_bytes()
        .expect("stale recipe canonicalization should succeed");
    let stale_hash = *blake3::hash(&stale_bytes).as_bytes();
    durable_cas
        .store(&stale_bytes)
        .expect("stale recipe bytes should store in CAS");

    assert_ne!(
        stale_hash, stored_claim_b.policy_resolution.context_pack_recipe_hash,
        "stale recipe hash must differ from authoritative recipe hash"
    );
    stored_claim_b.policy_resolution.context_pack_recipe_hash = stale_hash;
    persist_claim(&sqlite_conn, &stored_claim_b);

    assert_spawn_denied(
        dispatcher,
        &ctx,
        &spawn_request(&claim_b.work_id, &claim_b.lease_id, None),
        PrivilegedErrorCode::CapabilityRequestRejected,
        &[
            "policy CAS artifact seeding failed",
            "context_pack_recipe_hash mismatch",
        ],
    );

    // Scenario C: hash-chain break (missing authority context hash)
    let claim_c = claim_work(dispatcher, &ctx);
    let mut stored_claim_c = load_claim(&sqlite_conn, &claim_c.work_id);
    stored_claim_c.policy_resolution.context_pack_recipe_hash = [0u8; 32];
    persist_claim(&sqlite_conn, &stored_claim_c);

    assert_spawn_denied(
        dispatcher,
        &ctx,
        &spawn_request(&claim_c.work_id, &claim_c.lease_id, None),
        PrivilegedErrorCode::CapabilityRequestRejected,
        &[
            "policy CAS artifact seeding failed",
            "context_pack_recipe_hash is zero (missing authority context)",
        ],
    );
}

#[test]
fn tck_00437_rolespec_vnext_claim_work_lineage_fields_are_populated() {
    let temp_dir = TempDir::new().expect("temp dir should be created");
    let cas_path = temp_dir.path().join("cas");
    let sqlite_conn = make_sqlite_conn();
    let state = make_dispatcher_state(Arc::clone(&sqlite_conn), &cas_path);
    let dispatcher = state.privileged_dispatcher();

    let peer = test_peer_credentials();
    let ctx = make_privileged_ctx(&peer);
    let actor_id = apm2_daemon::protocol::derive_actor_id(&peer);

    let claim = claim_work(dispatcher, &ctx);
    let context_pack_hash = to_hash32(claim.context_pack_hash.clone(), "context_pack_hash");

    let claim_row = load_claim(&sqlite_conn, &claim.work_id);
    let policy: &PolicyResolution = &claim_row.policy_resolution;

    assert_ne!(
        policy.role_spec_hash, [0u8; 32],
        "claim policy resolution must include non-zero role_spec_hash"
    );
    assert_ne!(
        policy.context_pack_recipe_hash, [0u8; 32],
        "claim policy resolution must include non-zero context_pack_recipe_hash"
    );
    assert_eq!(
        policy.context_pack_hash, context_pack_hash,
        "stored policy resolution must preserve response context hash"
    );

    let expected_recipe_hash = policy_context_pack_recipe_hash(
        &claim.work_id,
        &actor_id,
        policy.role_spec_hash,
        policy.context_pack_hash,
    )
    .expect("authoritative recipe hash should derive from claim lineage");

    assert_eq!(
        policy.context_pack_recipe_hash, expected_recipe_hash,
        "claim policy recipe hash must match authoritative deterministic derivation"
    );
}
