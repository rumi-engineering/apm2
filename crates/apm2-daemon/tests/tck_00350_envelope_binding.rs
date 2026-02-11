//! Integration tests for `EpisodeEnvelopeV1` and receipt binding enforcement
//! (TCK-00350).
//!
//! Verifies:
//! - Tool receipts always carry envelope/capability/view bindings
//! - Episode envelopes bind a deterministic freshness pinset commitment hash
//! - Spawn/resume denied when envelope absent or malformed
//! - Replay harness can resolve and verify bindings from CAS + ledger
//!
//! These tests exercise production wiring paths (`DispatcherState`) where
//! applicable, per the common review findings.

use std::sync::{Arc, Mutex};

use apm2_daemon::episode::{
    EnvelopeBindings, EnvelopeV1Error, EpisodeBudget, EpisodeEnvelopeV1, PinnedSnapshot,
    StopConditions, validate_spawn_gate,
};
use apm2_daemon::ledger::SqliteLedgerEventEmitter;
use apm2_daemon::protocol::dispatch::{LedgerEventEmitter, StubLedgerEventEmitter};
use rand::rngs::OsRng;
use rusqlite::Connection;

/// Creates a minimal valid V1 envelope for testing.
fn test_v1_envelope() -> EpisodeEnvelopeV1 {
    EpisodeEnvelopeV1::builder()
        .episode_id("ep-test-001")
        .actor_id("agent-test")
        .work_id("work-test")
        .lease_id("lease-test")
        .capability_manifest_hash([0xab; 32])
        .budget(EpisodeBudget::default())
        .stop_conditions(StopConditions::max_episodes(100))
        .pinned_snapshot(PinnedSnapshot::empty())
        .view_commitment_hash([0xcc; 32])
        .freshness_pinset_hash([0xdd; 32])
        .build()
        .expect("valid V1 envelope")
}

/// Creates a delegated V1 envelope for testing.
fn test_delegated_v1_envelope() -> EpisodeEnvelopeV1 {
    EpisodeEnvelopeV1::builder()
        .episode_id("ep-delegated-001")
        .actor_id("agent-delegated")
        .work_id("work-delegated")
        .lease_id("lease-delegated")
        .capability_manifest_hash([0xab; 32])
        .budget(EpisodeBudget::default())
        .stop_conditions(StopConditions::max_episodes(50))
        .pinned_snapshot(PinnedSnapshot::empty())
        .view_commitment_hash([0xcc; 32])
        .freshness_pinset_hash([0xdd; 32])
        .permeability_receipt_hash([0xee; 32])
        .build()
        .expect("valid delegated V1 envelope")
}

// =========================================================================
// Spawn gate tests
// =========================================================================

/// Spawn denied when envelope is absent (None).
#[test]
fn spawn_denied_without_envelope() {
    let result = validate_spawn_gate(None, false);
    assert!(result.is_err(), "spawn must be denied without envelope");
}

/// Spawn denied with malformed envelope (zero view commitment hash).
#[test]
fn spawn_denied_with_zero_view_commitment() {
    let result = EpisodeEnvelopeV1::builder()
        .episode_id("ep")
        .actor_id("agent")
        .lease_id("lease")
        .capability_manifest_hash([0xab; 32])
        .budget(EpisodeBudget::default())
        .stop_conditions(StopConditions::max_episodes(10))
        .pinned_snapshot(PinnedSnapshot::empty())
        .view_commitment_hash([0u8; 32])
        .freshness_pinset_hash([0xdd; 32])
        .build();

    assert!(
        matches!(result, Err(EnvelopeV1Error::ZeroViewCommitmentHash)),
        "build must reject zero view_commitment_hash, got: {result:?}"
    );
}

/// Spawn denied with malformed envelope (zero freshness pinset hash).
#[test]
fn spawn_denied_with_zero_freshness_pinset() {
    let result = EpisodeEnvelopeV1::builder()
        .episode_id("ep")
        .actor_id("agent")
        .lease_id("lease")
        .capability_manifest_hash([0xab; 32])
        .budget(EpisodeBudget::default())
        .stop_conditions(StopConditions::max_episodes(10))
        .pinned_snapshot(PinnedSnapshot::empty())
        .view_commitment_hash([0xcc; 32])
        .freshness_pinset_hash([0u8; 32])
        .build();

    assert!(
        matches!(result, Err(EnvelopeV1Error::ZeroFreshnessPinsetHash)),
        "build must reject zero freshness_pinset_hash, got: {result:?}"
    );
}

/// Spawn accepted with valid envelope.
#[test]
fn spawn_accepted_with_valid_envelope() {
    let env = test_v1_envelope();
    let result = validate_spawn_gate(Some(&env), false);
    assert!(result.is_ok(), "spawn must succeed with valid envelope");
}

/// Legacy spawn gate rejects delegated mode outright (must use
/// `validate_delegated_spawn_gate` for consumption binding enforcement).
#[test]
fn delegated_spawn_denied_via_legacy_gate_without_receipt() {
    let env = test_v1_envelope(); // No permeability_receipt_hash
    let result = validate_spawn_gate(Some(&env), true);
    assert!(
        matches!(
            result,
            Err(EnvelopeV1Error::DelegatedRequiresConsumptionBinding)
        ),
        "legacy gate must reject delegated mode, got: {result:?}"
    );
}

/// Legacy spawn gate rejects delegated mode even when
/// `permeability_receipt_hash` is present — full consumption binding is
/// required.
#[test]
fn delegated_spawn_denied_via_legacy_gate_with_receipt() {
    let env = test_delegated_v1_envelope();
    let result = validate_spawn_gate(Some(&env), true);
    assert!(
        matches!(
            result,
            Err(EnvelopeV1Error::DelegatedRequiresConsumptionBinding)
        ),
        "legacy gate must reject delegated mode even with receipt hash, got: {result:?}"
    );
}

// =========================================================================
// Receipt binding tests
// =========================================================================

/// Receipt always carries bindings after valid spawn.
#[test]
fn receipt_carries_bindings_after_valid_spawn() {
    let env = test_v1_envelope();
    let bindings = env.bindings();

    // All bindings must be non-zero
    assert_ne!(bindings.envelope_hash, [0u8; 32]);
    assert_ne!(bindings.capability_manifest_hash, [0u8; 32]);
    assert_ne!(bindings.view_commitment_hash, [0u8; 32]);

    // Bindings must validate
    assert!(bindings.validate().is_ok());
}

/// Receipt with zero bindings is rejected (fail-closed).
#[test]
fn receipt_rejected_with_zero_bindings() {
    let zero_bindings = EnvelopeBindings {
        envelope_hash: [0u8; 32],
        capability_manifest_hash: [0xab; 32],
        view_commitment_hash: [0xcc; 32],
    };

    assert!(
        zero_bindings.validate().is_err(),
        "zero envelope_hash must be rejected"
    );
}

/// `emit_receipt_with_bindings` rejects zero bindings (fail-closed).
#[test]
fn emit_receipt_rejects_zero_bindings() {
    let emitter = StubLedgerEventEmitter::new();
    let zero_bindings = EnvelopeBindings {
        envelope_hash: [0u8; 32],
        capability_manifest_hash: [0xab; 32],
        view_commitment_hash: [0xcc; 32],
    };

    let result = emitter.emit_receipt_with_bindings(
        "ep-001",
        "receipt-001",
        &[0x11; 32],
        &[0x22; 32],
        "reviewer-001",
        1_000_000,
        &zero_bindings,
        &[0x99; 32],
    );

    assert!(result.is_err(), "emit must reject zero bindings");
    if let Err(e) = result {
        let msg = format!("{e}");
        assert!(
            msg.contains("validation failed"),
            "error must mention validation: {msg}"
        );
    }
}

/// `emit_receipt_with_bindings` succeeds with valid bindings (stub).
#[test]
fn emit_receipt_succeeds_with_valid_bindings_stub() {
    let emitter = StubLedgerEventEmitter::new();
    let env = test_v1_envelope();
    let bindings = env.bindings();

    let result = emitter.emit_receipt_with_bindings(
        "ep-001",
        "receipt-001",
        &[0x11; 32],
        &[0x22; 32],
        "reviewer-001",
        1_000_000,
        &bindings,
        &[0x99; 32],
    );

    assert!(result.is_ok(), "emit must succeed with valid bindings");

    // Verify the event was persisted
    let event = result.unwrap();
    assert_eq!(event.event_type, "review_receipt_recorded");
    assert_eq!(event.work_id, "ep-001");

    // Verify bindings are in the payload
    let payload_str = std::str::from_utf8(&event.payload).expect("valid utf8");
    let payload_json: serde_json::Value = serde_json::from_str(payload_str).expect("valid json");

    assert!(
        payload_json.get("envelope_hash").is_some(),
        "payload must contain envelope_hash"
    );
    assert!(
        payload_json.get("capability_manifest_hash").is_some(),
        "payload must contain capability_manifest_hash"
    );
    assert!(
        payload_json.get("view_commitment_hash").is_some(),
        "payload must contain view_commitment_hash"
    );

    // Verify the hex values match
    let (env_hex, cap_hex, view_hex) = bindings.to_hex_map();
    assert_eq!(payload_json["envelope_hash"].as_str().unwrap(), &env_hex);
    assert_eq!(
        payload_json["capability_manifest_hash"].as_str().unwrap(),
        &cap_hex
    );
    assert_eq!(
        payload_json["view_commitment_hash"].as_str().unwrap(),
        &view_hex
    );
}

/// `emit_receipt_with_bindings` succeeds with valid bindings (sqlite).
#[test]
fn emit_receipt_succeeds_with_valid_bindings_sqlite() {
    let conn = Connection::open_in_memory().expect("sqlite open");
    SqliteLedgerEventEmitter::init_schema_for_test(&conn).expect("init schema");
    let conn = Arc::new(Mutex::new(conn));

    let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
    let emitter = SqliteLedgerEventEmitter::new(conn.clone(), signing_key);

    let env = test_v1_envelope();
    let bindings = env.bindings();

    let result = emitter.emit_receipt_with_bindings(
        "ep-sqlite-001",
        "receipt-sqlite-001",
        &[0x11; 32],
        &[0x22; 32],
        "reviewer-sqlite",
        2_000_000,
        &bindings,
        &[0x99; 32],
    );

    assert!(
        result.is_ok(),
        "sqlite emit must succeed with valid bindings"
    );

    let event = result.unwrap();
    assert_eq!(event.event_type, "review_receipt_recorded");

    // Verify bindings are in the payload
    let payload_str = std::str::from_utf8(&event.payload).expect("valid utf8");
    let payload_json: serde_json::Value = serde_json::from_str(payload_str).expect("valid json");

    let (env_hex, cap_hex, view_hex) = bindings.to_hex_map();
    assert_eq!(
        payload_json["envelope_hash"].as_str().unwrap(),
        &env_hex,
        "sqlite payload must contain matching envelope_hash"
    );
    assert_eq!(
        payload_json["capability_manifest_hash"].as_str().unwrap(),
        &cap_hex,
        "sqlite payload must contain matching capability_manifest_hash"
    );
    assert_eq!(
        payload_json["view_commitment_hash"].as_str().unwrap(),
        &view_hex,
        "sqlite payload must contain matching view_commitment_hash"
    );

    // Verify event was persisted to SQLite
    let guard = conn.lock().unwrap();
    let count: i64 = guard
        .query_row(
            "SELECT COUNT(*) FROM ledger_events WHERE event_type = 'review_receipt_recorded'",
            [],
            |row| row.get(0),
        )
        .expect("query");
    assert_eq!(count, 1, "exactly 1 receipt event in SQLite");
}

/// `emit_receipt_with_bindings` rejects zero bindings (sqlite, fail-closed).
#[test]
fn emit_receipt_rejects_zero_bindings_sqlite() {
    let conn = Connection::open_in_memory().expect("sqlite open");
    SqliteLedgerEventEmitter::init_schema_for_test(&conn).expect("init schema");
    let conn = Arc::new(Mutex::new(conn));

    let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
    let emitter = SqliteLedgerEventEmitter::new(conn, signing_key);

    let zero_bindings = EnvelopeBindings {
        envelope_hash: [0u8; 32],
        capability_manifest_hash: [0xab; 32],
        view_commitment_hash: [0xcc; 32],
    };

    let result = emitter.emit_receipt_with_bindings(
        "ep-fail",
        "receipt-fail",
        &[0x11; 32],
        &[0x22; 32],
        "reviewer-fail",
        3_000_000,
        &zero_bindings,
        &[0x99; 32],
    );

    assert!(
        result.is_err(),
        "sqlite emit must reject zero bindings (fail-closed)"
    );
}

// =========================================================================
// Replay verification tests
// =========================================================================

/// Replay harness can resolve and verify bindings from CAS + ledger.
#[test]
fn replay_verification_roundtrip() {
    // Step 1: Build envelope (simulates CAS-stored envelope)
    let env = test_v1_envelope();

    // Step 2: Extract bindings (simulates receipt in ledger)
    let receipt_bindings = env.bindings();

    // Step 3: Validate bindings are well-formed
    assert!(
        receipt_bindings.validate().is_ok(),
        "bindings must be valid"
    );

    // Step 4: Verify bindings against the CAS-stored envelope
    assert!(
        receipt_bindings.verify_against(&env).is_ok(),
        "bindings must verify against original envelope"
    );
}

/// Replay verification detects tampered `envelope_hash`.
#[test]
fn replay_verification_detects_tampered_envelope_hash() {
    let env = test_v1_envelope();
    let mut tampered_bindings = env.bindings();
    tampered_bindings.envelope_hash = [0xff; 32]; // Tamper

    let result = tampered_bindings.verify_against(&env);
    assert!(
        matches!(
            result,
            Err(EnvelopeV1Error::BindingMismatch {
                field: "envelope_hash"
            })
        ),
        "tampered envelope_hash must be detected, got: {result:?}"
    );
}

/// Replay verification detects tampered `capability_manifest_hash`.
#[test]
fn replay_verification_detects_tampered_capability_hash() {
    let env = test_v1_envelope();
    let mut tampered_bindings = env.bindings();
    tampered_bindings.capability_manifest_hash = [0xff; 32]; // Tamper

    let result = tampered_bindings.verify_against(&env);
    assert!(
        matches!(
            result,
            Err(EnvelopeV1Error::BindingMismatch {
                field: "capability_manifest_hash"
            })
        ),
        "tampered capability_manifest_hash must be detected, got: {result:?}"
    );
}

/// Replay verification detects tampered `view_commitment_hash`.
#[test]
fn replay_verification_detects_tampered_view_hash() {
    let env = test_v1_envelope();
    let mut tampered_bindings = env.bindings();
    tampered_bindings.view_commitment_hash = [0xff; 32]; // Tamper

    let result = tampered_bindings.verify_against(&env);
    assert!(
        matches!(
            result,
            Err(EnvelopeV1Error::BindingMismatch {
                field: "view_commitment_hash"
            })
        ),
        "tampered view_commitment_hash must be detected, got: {result:?}"
    );
}

/// `freshness_pinset_hash` is bound in the envelope (acceptance criterion).
#[test]
fn envelope_binds_freshness_pinset_hash() {
    let env = test_v1_envelope();

    // The freshness_pinset_hash must be non-zero and exactly what was set
    assert_eq!(env.freshness_pinset_hash(), &[0xdd; 32]);
    assert_ne!(
        env.freshness_pinset_hash(),
        &[0u8; 32],
        "freshness_pinset_hash must be non-zero"
    );
}

/// Delegated episode binds `permeability_receipt_hash`.
#[test]
fn delegated_episode_binds_permeability_receipt_hash() {
    let env = test_delegated_v1_envelope();

    assert!(env.is_delegated());
    assert_eq!(env.permeability_receipt_hash(), Some(&[0xee; 32]));
}

/// End-to-end: envelope -> bindings -> receipt -> verify
#[test]
fn e2e_envelope_bindings_receipt_verify() {
    // 1. Create envelope (spawn-time)
    let env = EpisodeEnvelopeV1::builder()
        .episode_id("ep-e2e")
        .actor_id("agent-e2e")
        .work_id("work-e2e")
        .lease_id("lease-e2e")
        .capability_manifest_hash([0x11; 32])
        .budget(EpisodeBudget::default())
        .stop_conditions(StopConditions::max_episodes(50))
        .pinned_snapshot(PinnedSnapshot::empty())
        .view_commitment_hash([0x22; 32])
        .freshness_pinset_hash([0x33; 32])
        .build()
        .expect("valid envelope");

    // 2. Validate spawn gate
    let gate_result = validate_spawn_gate(Some(&env), false);
    assert!(gate_result.is_ok(), "spawn gate must pass");

    // 3. Extract bindings for receipt
    let bindings = env.bindings();
    assert!(bindings.validate().is_ok(), "bindings must validate");

    // 4. Emit receipt with bindings via stub emitter
    let emitter = StubLedgerEventEmitter::new();
    let receipt = emitter
        .emit_receipt_with_bindings(
            "ep-e2e",
            "receipt-e2e",
            &[0x44; 32],
            &[0x55; 32],
            "reviewer-e2e",
            5_000_000,
            &bindings,
            &[0x99; 32],
        )
        .expect("receipt emission must succeed");

    // 5. Parse receipt payload and reconstruct bindings
    let payload_str = std::str::from_utf8(&receipt.payload).expect("utf8");
    let payload_json: serde_json::Value = serde_json::from_str(payload_str).expect("json");

    let stored_env_hash = hex::decode(payload_json["envelope_hash"].as_str().unwrap()).unwrap();
    let stored_cap_hash =
        hex::decode(payload_json["capability_manifest_hash"].as_str().unwrap()).unwrap();
    let stored_view_hash =
        hex::decode(payload_json["view_commitment_hash"].as_str().unwrap()).unwrap();

    let reconstructed = EnvelopeBindings {
        envelope_hash: stored_env_hash.try_into().unwrap(),
        capability_manifest_hash: stored_cap_hash.try_into().unwrap(),
        view_commitment_hash: stored_view_hash.try_into().unwrap(),
    };

    // 6. Verify reconstructed bindings against original envelope
    assert!(
        reconstructed.verify_against(&env).is_ok(),
        "reconstructed bindings must verify against original envelope"
    );
}
