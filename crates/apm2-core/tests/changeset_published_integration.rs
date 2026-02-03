//! Integration tests for `ChangeSetPublished` event emission.
//!
//! These tests verify that `ChangeSetPublished` events can be:
//! 1. Successfully signed with proper domain separation
//! 2. Appended to the ledger with signature verification
//! 3. Retrieved from the ledger with all fields intact
//!
//! # Security Properties Verified
//!
//! - Domain-separated signature coverage (`CHANGESET_PUBLISHED:` prefix)
//! - Signature verification on ledger append
//! - `time_envelope_ref` field preservation through proto roundtrip
//! - Hash chain integrity when appending events

#![allow(clippy::items_after_statements)]

use apm2_core::crypto::Signer;
use apm2_core::fac::{
    ChangeKind, ChangeSetBundleV1, ChangeSetPublished, FileChange, GitObjectRef, HashAlgo,
};
use apm2_core::htf::TimeEnvelopeRef;
use apm2_core::ledger::{EventRecord, Ledger};
use prost::Message;

// ============================================================================
// Test Helpers
// ============================================================================

/// Creates a test `ChangeSetBundleV1` for use in tests.
fn create_test_bundle() -> ChangeSetBundleV1 {
    ChangeSetBundleV1::builder()
        .changeset_id("cs-test-001")
        .base(GitObjectRef {
            algo: HashAlgo::Sha1,
            object_kind: "commit".to_string(),
            object_id: "a".repeat(40),
        })
        .diff_hash([0x42; 32])
        .file_manifest(vec![FileChange {
            path: "src/lib.rs".to_string(),
            change_kind: ChangeKind::Modify,
            old_path: None,
        }])
        .build()
        .expect("valid bundle")
}

// ============================================================================
// Integration Tests: ChangeSetPublished Event Emission
// ============================================================================

/// Test: `ChangeSetPublished` event can be created, signed, and verified.
///
/// This test verifies the basic workflow:
/// 1. Create a `ChangeSetBundleV1` and compute its digest
/// 2. Create a `ChangeSetPublished` event with signing
/// 3. Verify the signature is valid
#[test]
fn test_changeset_published_create_sign_verify() {
    let signer = Signer::generate();
    let bundle = create_test_bundle();
    let cas_hash = [0x33; 32]; // Simulated CAS hash

    // Create the event
    let event = ChangeSetPublished::create(
        "work-001".to_string(),
        bundle.changeset_digest(),
        cas_hash,
        1_704_067_200_000,
        "publisher-001".to_string(),
        &signer,
    )
    .expect("should create event");

    // Verify signature
    assert!(
        event.verify_signature(&signer.verifying_key()).is_ok(),
        "Signature should verify with correct key"
    );

    // Verify field values
    assert_eq!(event.work_id, "work-001");
    assert_eq!(event.changeset_digest, bundle.changeset_digest());
    assert_eq!(event.cas_hash, cas_hash);
    assert_eq!(event.published_at, 1_704_067_200_000);
    assert_eq!(event.publisher_actor_id, "publisher-001");
}

/// Test: `ChangeSetPublished` event with `time_envelope_ref` can be created
/// and verified.
///
/// This test verifies that the `time_envelope_ref` field:
/// 1. Is included in the canonical bytes for signing
/// 2. Affects the signature (tampering with it invalidates the signature)
#[test]
fn test_changeset_published_with_time_envelope_ref() {
    let signer = Signer::generate();
    let bundle = create_test_bundle();
    let cas_hash = [0x33; 32];
    let time_envelope_ref = TimeEnvelopeRef::new([0xAB; 32]);

    // Create the event with time_envelope_ref
    let event = ChangeSetPublished::create_with_time_envelope(
        "work-002".to_string(),
        bundle.changeset_digest(),
        cas_hash,
        1_704_067_200_000,
        "publisher-002".to_string(),
        Some(time_envelope_ref),
        &signer,
    )
    .expect("should create event");

    // Verify signature
    assert!(
        event.verify_signature(&signer.verifying_key()).is_ok(),
        "Signature should verify with time_envelope_ref"
    );

    // Verify time_envelope_ref is set
    assert!(event.time_envelope_ref.is_some());
    assert_eq!(
        event.time_envelope_ref.as_ref().unwrap().as_bytes(),
        &[0xAB; 32]
    );

    // Verify tampering with time_envelope_ref invalidates signature
    let mut tampered = event;
    tampered.time_envelope_ref = Some(TimeEnvelopeRef::new([0xCD; 32]));
    assert!(
        tampered.verify_signature(&signer.verifying_key()).is_err(),
        "Signature should fail after tampering with time_envelope_ref"
    );
}

/// Test: `ChangeSetPublished` event can be converted to/from proto format.
///
/// This test verifies the proto roundtrip preserves all fields, including
/// the `time_envelope_ref` field (HTF compliance).
#[test]
fn test_changeset_published_proto_roundtrip_with_time_envelope_ref() {
    use apm2_core::fac::ChangeSetPublishedProto;

    let signer = Signer::generate();
    let bundle = create_test_bundle();
    let time_envelope_ref = TimeEnvelopeRef::new([0xEF; 32]);

    // Create event with time_envelope_ref
    let original = ChangeSetPublished::create_with_time_envelope(
        "work-003".to_string(),
        bundle.changeset_digest(),
        [0x44; 32],
        1_704_067_200_000,
        "publisher-003".to_string(),
        Some(time_envelope_ref),
        &signer,
    )
    .expect("should create event");

    // Convert to proto
    let proto: ChangeSetPublishedProto = original.clone().into();

    // Verify proto has time_envelope_ref
    assert!(proto.time_envelope_ref.is_some());
    assert_eq!(
        proto.time_envelope_ref.as_ref().unwrap().hash,
        vec![0xEF; 32]
    );

    // Convert back to domain type
    let recovered: ChangeSetPublished = proto.try_into().expect("should convert back");

    // Verify all fields match
    assert_eq!(original.work_id, recovered.work_id);
    assert_eq!(original.changeset_digest, recovered.changeset_digest);
    assert_eq!(original.cas_hash, recovered.cas_hash);
    assert_eq!(original.published_at, recovered.published_at);
    assert_eq!(original.publisher_actor_id, recovered.publisher_actor_id);
    assert_eq!(original.publisher_signature, recovered.publisher_signature);

    // Critical: time_envelope_ref must be preserved
    assert!(recovered.time_envelope_ref.is_some());
    assert_eq!(
        recovered.time_envelope_ref.as_ref().unwrap().as_bytes(),
        &[0xEF; 32]
    );

    // Verify signature still validates after roundtrip
    assert!(
        recovered.verify_signature(&signer.verifying_key()).is_ok(),
        "Signature should verify after proto roundtrip"
    );
}

/// Test: `ChangeSetPublished` event can be appended to ledger and retrieved.
///
/// This test verifies the full ledger integration:
/// 1. Create an in-memory ledger
/// 2. Create and sign a `ChangeSetPublished` event
/// 3. Encode event to protobuf payload
/// 4. Sign the payload for ledger ingestion (separate from event signature)
/// 5. Append to ledger using `append_verified`
/// 6. Retrieve event from ledger
/// 7. Decode and verify all fields
///
/// Note: There are TWO signatures in this flow:
/// 1. `publisher_signature` in `ChangeSetPublished`: Signs the event's
///    canonical bytes using the `CHANGESET_PUBLISHED:` prefix from the fac
///    module
/// 2. Ledger event signature: Signs the protobuf payload using the
///    `apm2.event.changeset_published:` prefix for ledger ingestion
#[test]
fn test_changeset_published_ledger_append_and_retrieve() {
    use apm2_core::events::CHANGESET_PUBLISHED_DOMAIN_PREFIX;
    use apm2_core::fac::ChangeSetPublishedProto;

    // Set up ledger and signer
    let ledger = Ledger::in_memory().expect("should create ledger");
    let signer = Signer::generate();
    let actor_id = hex::encode(signer.verifying_key().as_bytes());

    // Create changeset bundle and event
    let bundle = create_test_bundle();
    let time_envelope_ref = TimeEnvelopeRef::new([0x99; 32]);

    let event = ChangeSetPublished::create_with_time_envelope(
        "work-ledger-001".to_string(),
        bundle.changeset_digest(),
        [0x55; 32],
        1_704_067_200_000,
        actor_id.clone(),
        Some(time_envelope_ref),
        &signer,
    )
    .expect("should create event");

    // Verify event's publisher_signature before ledger append
    assert!(event.verify_signature(&signer.verifying_key()).is_ok());

    // Convert to proto and encode
    let proto: ChangeSetPublishedProto = event.clone().into();
    let payload = proto.encode_to_vec();

    // Get the genesis hash (ledger is empty)
    let prev_hash = ledger.last_event_hash().expect("should get hash");

    // Sign the payload for ledger ingestion using the ledger's domain prefix
    // This is a SEPARATE signature from the event's publisher_signature.
    // The ledger uses `apm2.event.changeset_published:` prefix (from events module)
    // while the event uses `CHANGESET_PUBLISHED:` prefix (from fac module).
    use apm2_core::fac::sign_with_domain;

    let ledger_signature = sign_with_domain(&signer, CHANGESET_PUBLISHED_DOMAIN_PREFIX, &payload);

    let mut record = EventRecord::new("changeset_published", "session-test", &actor_id, payload);
    record.prev_hash = Some(prev_hash);
    record.signature = Some(ledger_signature.to_bytes().to_vec());

    // Append to ledger with signature verification
    let seq_id = ledger
        .append_verified(&record, &signer.verifying_key())
        .expect("should append to ledger");

    assert_eq!(seq_id, 1, "First event should have seq_id 1");

    // Retrieve from ledger
    let retrieved = ledger.read_one(seq_id).expect("should read event");

    // Verify event type and payload
    assert_eq!(retrieved.event_type, "changeset_published");
    assert_eq!(retrieved.actor_id, actor_id);

    // Decode payload and verify fields
    let decoded_proto =
        ChangeSetPublishedProto::decode(retrieved.payload.as_slice()).expect("should decode");
    let decoded: ChangeSetPublished = decoded_proto.try_into().expect("should convert");

    // Verify all fields match original
    assert_eq!(decoded.work_id, event.work_id);
    assert_eq!(decoded.changeset_digest, event.changeset_digest);
    assert_eq!(decoded.cas_hash, event.cas_hash);
    assert_eq!(decoded.published_at, event.published_at);
    assert_eq!(decoded.publisher_actor_id, event.publisher_actor_id);
    assert_eq!(decoded.publisher_signature, event.publisher_signature);

    // Critical: time_envelope_ref must be preserved through ledger roundtrip
    assert!(decoded.time_envelope_ref.is_some());
    assert_eq!(
        decoded.time_envelope_ref.as_ref().unwrap().as_bytes(),
        &[0x99; 32]
    );

    // Verify the event's publisher_signature still validates after retrieval
    assert!(
        decoded.verify_signature(&signer.verifying_key()).is_ok(),
        "Publisher signature should verify after ledger roundtrip"
    );
}

/// Test: Signature verification fails with wrong key.
#[test]
fn test_changeset_published_signature_fails_wrong_key() {
    let signer1 = Signer::generate();
    let signer2 = Signer::generate();
    let bundle = create_test_bundle();

    let event = ChangeSetPublished::create(
        "work-004".to_string(),
        bundle.changeset_digest(),
        [0x66; 32],
        1_704_067_200_000,
        "publisher-004".to_string(),
        &signer1,
    )
    .expect("should create event");

    // Verify with wrong key should fail
    assert!(
        event.verify_signature(&signer2.verifying_key()).is_err(),
        "Signature should fail with wrong key"
    );
}

/// Test: Signature verification fails after tampering with any field.
#[test]
fn test_changeset_published_signature_fails_on_tamper() {
    let signer = Signer::generate();
    let bundle = create_test_bundle();

    let original = ChangeSetPublished::create(
        "work-005".to_string(),
        bundle.changeset_digest(),
        [0x77; 32],
        1_704_067_200_000,
        "publisher-005".to_string(),
        &signer,
    )
    .expect("should create event");

    // Tamper with work_id
    let mut tampered = original.clone();
    tampered.work_id = "work-tampered".to_string();
    assert!(
        tampered.verify_signature(&signer.verifying_key()).is_err(),
        "Signature should fail after tampering with work_id"
    );

    // Tamper with changeset_digest
    let mut tampered = original.clone();
    tampered.changeset_digest = [0xFF; 32];
    assert!(
        tampered.verify_signature(&signer.verifying_key()).is_err(),
        "Signature should fail after tampering with changeset_digest"
    );

    // Tamper with cas_hash
    let mut tampered = original.clone();
    tampered.cas_hash = [0xEE; 32];
    assert!(
        tampered.verify_signature(&signer.verifying_key()).is_err(),
        "Signature should fail after tampering with cas_hash"
    );

    // Tamper with published_at
    let mut tampered = original.clone();
    tampered.published_at = 9_999_999_999;
    assert!(
        tampered.verify_signature(&signer.verifying_key()).is_err(),
        "Signature should fail after tampering with published_at"
    );

    // Tamper with publisher_actor_id
    let mut tampered = original;
    tampered.publisher_actor_id = "tampered-actor".to_string();
    assert!(
        tampered.verify_signature(&signer.verifying_key()).is_err(),
        "Signature should fail after tampering with publisher_actor_id"
    );
}

/// Test: Canonical bytes are deterministic.
#[test]
fn test_changeset_published_canonical_bytes_deterministic() {
    let signer = Signer::generate();
    let bundle = create_test_bundle();
    let time_envelope_ref = TimeEnvelopeRef::new([0xDD; 32]);

    // Create two identical events
    let event1 = ChangeSetPublished::create_with_time_envelope(
        "work-det-001".to_string(),
        bundle.changeset_digest(),
        [0x88; 32],
        1_704_067_200_000,
        "publisher-det".to_string(),
        Some(time_envelope_ref),
        &signer,
    )
    .expect("should create event");

    let event2 = ChangeSetPublished::create_with_time_envelope(
        "work-det-001".to_string(),
        bundle.changeset_digest(),
        [0x88; 32],
        1_704_067_200_000,
        "publisher-det".to_string(),
        Some(TimeEnvelopeRef::new([0xDD; 32])),
        &signer,
    )
    .expect("should create event");

    // Canonical bytes should be identical
    assert_eq!(
        event1.canonical_bytes(),
        event2.canonical_bytes(),
        "Canonical bytes must be deterministic"
    );

    // Signatures should be identical (Ed25519 is deterministic)
    assert_eq!(
        event1.publisher_signature, event2.publisher_signature,
        "Signatures must be deterministic"
    );
}
