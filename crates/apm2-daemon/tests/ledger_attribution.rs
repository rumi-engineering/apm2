// AGENT-AUTHORED
//! RFC-0032::REQ-0123: Ledger attribution integration tests.
//!
//! This module tests:
//! 1. `emit_episode_run_attributed` emits events with `adapter_profile_hash`
//! 2. Ledger events can be queried by `work_id`
//! 3. Non-interactive receipt production works across all builtin profiles

use apm2_core::evidence::MemoryCas;
use apm2_core::fac::{
    AgentAdapterProfileV1, all_builtin_profiles, claude_code_profile, codex_cli_profile,
    gemini_cli_profile, local_inference_profile,
};
use apm2_daemon::protocol::dispatch::{LedgerEventEmitter, StubLedgerEventEmitter};
use ed25519_dalek::{Signature, Verifier};

// ============================================================================
// Ledger Attribution Tests
// ============================================================================

/// Tests that `emit_episode_run_attributed` correctly emits ledger events
/// with `adapter_profile_hash` attribution.
#[test]
fn test_emit_episode_run_attributed() {
    let emitter = StubLedgerEventEmitter::new();

    let work_id = "work-001";
    let episode_id = "episode-001";
    let session_id = "session-001";
    let adapter_profile_hash = [0x42u8; 32];
    let timestamp_ns = 1_704_067_200_000_000_000u64;

    let event = emitter
        .emit_episode_run_attributed(
            work_id,
            episode_id,
            session_id,
            &adapter_profile_hash,
            timestamp_ns,
        )
        .expect("emit should succeed");

    // Verify event metadata
    assert_eq!(event.event_type, "episode_run_attributed");
    assert_eq!(event.work_id, work_id);
    assert_eq!(event.actor_id, session_id); // Session is the actor
    assert_eq!(event.timestamp_ns, timestamp_ns);

    // Verify payload contains adapter_profile_hash
    let payload: serde_json::Value =
        serde_json::from_slice(&event.payload).expect("payload should be valid JSON");

    assert_eq!(
        payload["adapter_profile_hash"].as_str().unwrap(),
        hex::encode(adapter_profile_hash)
    );
    assert_eq!(payload["work_id"].as_str().unwrap(), work_id);
    assert_eq!(payload["episode_id"].as_str().unwrap(), episode_id);
    assert_eq!(payload["session_id"].as_str().unwrap(), session_id);
}

/// Tests that ledger events can be queried by `work_id`.
#[test]
fn test_query_events_by_work_id() {
    let emitter = StubLedgerEventEmitter::new();

    let work_id = "work-001";

    // Emit multiple events for the same work_id
    for i in 0u8..3 {
        let episode_id = format!("episode-00{i}");
        let session_id = format!("session-00{i}");
        let adapter_profile_hash = [i + 1; 32];
        let timestamp_ns = 1_704_067_200_000_000_000u64 + (u64::from(i) * 1_000_000);

        emitter
            .emit_episode_run_attributed(
                work_id,
                &episode_id,
                &session_id,
                &adapter_profile_hash,
                timestamp_ns,
            )
            .expect("emit should succeed");
    }

    // Query by work_id
    let events = emitter.get_events_by_work_id(work_id);
    assert_eq!(events.len(), 3);

    // Verify all events are for the same work_id
    for event in &events {
        assert_eq!(event.work_id, work_id);
        assert_eq!(event.event_type, "episode_run_attributed");
    }
}

/// Tests that events for different `work_ids` are properly separated.
#[test]
fn test_events_separated_by_work_id() {
    let emitter = StubLedgerEventEmitter::new();

    // Emit events for two different work_ids
    let profile_hash = [0x42u8; 32];

    emitter
        .emit_episode_run_attributed(
            "work-001",
            "episode-001",
            "session-001",
            &profile_hash,
            1000,
        )
        .expect("emit should succeed");

    emitter
        .emit_episode_run_attributed(
            "work-002",
            "episode-002",
            "session-002",
            &profile_hash,
            2000,
        )
        .expect("emit should succeed");

    // Query each work_id separately
    let events_1 = emitter.get_events_by_work_id("work-001");
    let events_2 = emitter.get_events_by_work_id("work-002");

    assert_eq!(events_1.len(), 1);
    assert_eq!(events_2.len(), 1);
    assert_eq!(events_1[0].work_id, "work-001");
    assert_eq!(events_2[0].work_id, "work-002");
}

// ============================================================================
// Non-Interactive Receipt Production Tests
// ============================================================================

/// Tests non-interactive receipt production with Claude Code profile.
#[test]
fn test_non_interactive_receipt_claude_code() {
    let cas = MemoryCas::new();
    let emitter = StubLedgerEventEmitter::new();
    let profile = claude_code_profile();

    verify_non_interactive_receipt_production(&cas, &emitter, &profile);
}

/// Tests non-interactive receipt production with Gemini CLI profile.
#[test]
fn test_non_interactive_receipt_gemini_cli() {
    let cas = MemoryCas::new();
    let emitter = StubLedgerEventEmitter::new();
    let profile = gemini_cli_profile();

    verify_non_interactive_receipt_production(&cas, &emitter, &profile);
}

/// Tests non-interactive receipt production with Codex CLI profile.
#[test]
fn test_non_interactive_receipt_codex_cli() {
    let cas = MemoryCas::new();
    let emitter = StubLedgerEventEmitter::new();
    let profile = codex_cli_profile();

    verify_non_interactive_receipt_production(&cas, &emitter, &profile);
}

/// Tests non-interactive receipt production with local inference profile.
#[test]
fn test_non_interactive_receipt_local_inference() {
    let cas = MemoryCas::new();
    let emitter = StubLedgerEventEmitter::new();
    let profile = local_inference_profile();

    verify_non_interactive_receipt_production(&cas, &emitter, &profile);
}

/// Tests non-interactive receipt production across all builtin profiles.
#[test]
fn test_non_interactive_receipt_all_profiles() {
    let cas = MemoryCas::new();
    let emitter = StubLedgerEventEmitter::new();

    for profile in all_builtin_profiles() {
        verify_non_interactive_receipt_production(&cas, &emitter, &profile);
    }
}

/// Helper function to verify non-interactive receipt production for a profile.
fn verify_non_interactive_receipt_production(
    cas: &MemoryCas,
    emitter: &StubLedgerEventEmitter,
    profile: &AgentAdapterProfileV1,
) {
    // Step 1: Store profile in CAS
    let profile_hash = profile
        .store_in_cas(cas)
        .expect("store in CAS should succeed");

    // Step 2: Emit episode run attributed event with profile hash
    let work_id = format!("work-{}", uuid::Uuid::new_v4());
    let episode_id = format!("episode-{}", uuid::Uuid::new_v4());
    let session_id = format!("session-{}", uuid::Uuid::new_v4());
    let timestamp_ns = 1_704_067_200_000_000_000u64;

    let event = emitter
        .emit_episode_run_attributed(
            &work_id,
            &episode_id,
            &session_id,
            &profile_hash,
            timestamp_ns,
        )
        .expect("emit should succeed");

    // Step 3: Verify event contains correct attribution
    assert_eq!(event.event_type, "episode_run_attributed");
    assert_eq!(event.work_id, work_id);

    // Step 4: Extract profile hash from event payload
    let payload: serde_json::Value =
        serde_json::from_slice(&event.payload).expect("payload should be valid JSON");
    let event_profile_hash_hex = payload["adapter_profile_hash"]
        .as_str()
        .expect("adapter_profile_hash should be present");

    // Step 5: Verify profile can be recovered from the hash
    let recovered_hash: [u8; 32] = hex::decode(event_profile_hash_hex)
        .expect("hex decode should succeed")
        .try_into()
        .expect("should be 32 bytes");

    let recovered_profile = AgentAdapterProfileV1::load_from_cas(cas, &recovered_hash)
        .expect("load from CAS should succeed");

    // Step 6: Verify recovered profile matches original
    assert_eq!(profile.profile_id, recovered_profile.profile_id);
    assert_eq!(profile.adapter_mode, recovered_profile.adapter_mode);
    assert_eq!(profile.command, recovered_profile.command);

    // Step 7: Verify event can be queried back
    let event_opt = emitter.get_event(&event.event_id);
    assert!(event_opt.is_some(), "event should be retrievable");
    let retrieved = event_opt.unwrap();
    assert_eq!(retrieved.event_id, event.event_id);
}

// ============================================================================
// Signature Verification Tests
// ============================================================================

/// Tests that emitted events have valid signatures.
#[test]
fn test_event_signature_verification() {
    let emitter = StubLedgerEventEmitter::new();
    let verifying_key = emitter.verifying_key();

    let profile_hash = [0x42u8; 32];
    let event = emitter
        .emit_episode_run_attributed(
            "work-001",
            "episode-001",
            "session-001",
            &profile_hash,
            1000,
        )
        .expect("emit should succeed");

    // Verify signature length (Ed25519 = 64 bytes)
    assert_eq!(event.signature.len(), 64);

    // Reconstruct and verify the signature
    // Build canonical bytes (domain prefix + payload)
    let domain_prefix = b"apm2.event.episode_run_attributed:";
    let mut canonical_bytes = Vec::new();
    canonical_bytes.extend_from_slice(domain_prefix);
    canonical_bytes.extend_from_slice(&event.payload);

    let signature = Signature::from_bytes(
        &event.signature[..]
            .try_into()
            .expect("signature should be 64 bytes"),
    );

    assert!(
        verifying_key.verify(&canonical_bytes, &signature).is_ok(),
        "signature verification should succeed"
    );
}

/// Tests that tampered payloads fail signature verification.
#[test]
fn test_tampered_payload_fails_verification() {
    let emitter = StubLedgerEventEmitter::new();
    let verifying_key = emitter.verifying_key();

    let profile_hash = [0x42u8; 32];
    let event = emitter
        .emit_episode_run_attributed(
            "work-001",
            "episode-001",
            "session-001",
            &profile_hash,
            1000,
        )
        .expect("emit should succeed");

    // Tamper with payload
    let mut tampered_payload = event.payload.clone();
    if !tampered_payload.is_empty() {
        tampered_payload[0] ^= 0xFF;
    }

    // Verify signature fails with tampered payload
    let domain_prefix = b"apm2.event.episode_run_attributed:";
    let mut canonical_bytes = Vec::new();
    canonical_bytes.extend_from_slice(domain_prefix);
    canonical_bytes.extend_from_slice(&tampered_payload);

    let signature = Signature::from_bytes(
        &event.signature[..]
            .try_into()
            .expect("signature should be 64 bytes"),
    );

    assert!(
        verifying_key.verify(&canonical_bytes, &signature).is_err(),
        "signature verification should fail for tampered payload"
    );
}

// ============================================================================
// Profile Hash Uniqueness Tests
// ============================================================================

/// Tests that different profiles produce different ledger events.
#[test]
fn test_different_profiles_different_events() {
    let cas = MemoryCas::new();
    let emitter = StubLedgerEventEmitter::new();

    let profiles = all_builtin_profiles();
    let mut event_hashes: Vec<String> = Vec::new();

    for profile in &profiles {
        let profile_hash = profile.store_in_cas(&cas).expect("store should succeed");

        let event = emitter
            .emit_episode_run_attributed(
                "work-001",
                "episode-001",
                "session-001",
                &profile_hash,
                1000,
            )
            .expect("emit should succeed");

        let payload: serde_json::Value =
            serde_json::from_slice(&event.payload).expect("parse should succeed");
        let hash_str = payload["adapter_profile_hash"]
            .as_str()
            .expect("hash should exist")
            .to_string();

        // Verify this hash is unique
        assert!(
            !event_hashes.contains(&hash_str),
            "Profile '{}' should have unique hash",
            profile.profile_id
        );
        event_hashes.push(hash_str);
    }

    assert_eq!(event_hashes.len(), profiles.len());
}
