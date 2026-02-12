// AGENT-AUTHORED
//! Tests for the ledger trust stack (TCK-00500).
//!
//! Coverage:
//! - (a) `RootTrustBundle` validation: empty, oversized, duplicate keys
//! - (b) `TrustBundleKeyEntry`: active/revoked at epoch semantics
//! - (c) `TrustedSealV1` validation and signing payload
//! - (d) `ConcreteLedgerTrustVerifier` startup verification:
//!   - Seal found and verified -- validated state available
//!   - Missing seal -- `IntegrityFailure`
//!   - Seal signature mismatch -- `IntegrityFailure`
//!   - Seal distance exceeded -- `SealDistanceExceeded`
//!   - Hash chain break -- `IntegrityFailure`
//!   - HT monotonicity violation -- `IntegrityFailure`
//!   - Fork/divergence detection -- `IntegrityFailure`
//!   - Not ready before startup -- `NotReady`
//! - (e) `GovernancePolicyRootResolver`:
//!   - Deterministic derivation from governance events
//!   - No governance events -- `NoGovernanceEvents`
//!   - Unsigned governance event -- `SignatureVerificationFailed`
//!   - Cache hit on repeated resolution
//!   - Cache eviction at capacity
//! - (f) Key rotation/revocation semantics:
//!   - Key active at epoch -- verification passes
//!   - Key revoked at epoch -- verification fails
//!   - Key not yet active -- verification fails
//! - (g) `Ed25519SignatureVerifier`: unknown algorithm -- fail-closed
//! - (h) Tamper detection: modified `event_hash` detected
//! - (i) Keyset digest changes with rotation
//! - (j) Seal anchor binding:
//!   - Forked chain (different `event_hash` at seal height) --
//!     `IntegrityFailure`
//!   - Correct chain with matching anchor -- success
//! - (k) Incomplete chain reads fail-closed:
//!   - Chain ends before `end_height` -- `IntegrityFailure`
//! - (l) Per-event key epoch resolution:
//!   - Post-seal key rotation accepted with per-event epoch
//!   - Revoked key rejected at event epoch

use std::sync::Arc;

use apm2_core::crypto::Hash;

use super::*;

// =============================================================================
// Test helpers
// =============================================================================

/// Non-zero hash for testing.
fn test_hash(byte: u8) -> Hash {
    let mut h = [0u8; 32];
    h[0] = byte;
    h[31] = byte;
    h
}

/// Create a minimal valid trust bundle with one ed25519 key.
fn test_trust_bundle(public_key: &[u8; 32], key_id: &str) -> RootTrustBundle {
    RootTrustBundle {
        schema_version: ROOT_TRUST_BUNDLE_SCHEMA_VERSION.to_string(),
        bundle_id: test_hash(0xBB),
        keys: vec![TrustBundleKeyEntry {
            algorithm_id: "ed25519".to_string(),
            key_id: key_id.to_string(),
            public_key_bytes: public_key.to_vec(),
            active_from_epoch: 0,
            revoked_at_epoch: None,
        }],
    }
}

/// Generate an ed25519 signing key and return (`signing_key`,
/// `public_key_bytes`).
fn generate_test_keypair() -> (ed25519_dalek::SigningKey, [u8; 32]) {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let public_key = signing_key.verifying_key().to_bytes();
    (signing_key, public_key)
}

/// Create a signed seal for testing.
fn create_test_seal(
    signing_key: &ed25519_dalek::SigningKey,
    anchor: &LedgerAnchorV1,
    key_id: &str,
    epoch: u64,
) -> TrustedSealV1 {
    use ed25519_dalek::Signer;

    let mut seal = TrustedSealV1 {
        anchor: anchor.clone(),
        signer_key_id: key_id.to_string(),
        algorithm_id: "ed25519".to_string(),
        signature: Vec::new(),
        seal_epoch: epoch,
    };
    let payload = seal.signing_payload();
    seal.signature = signing_key.sign(&payload).to_bytes().to_vec();
    seal
}

/// A mock ledger event source for testing.
struct MockEventSource {
    events: Vec<LedgerEventView>,
    ledger_id: Hash,
    seal: Option<TrustedSealV1>,
    governance_events: Vec<LedgerEventView>,
}

impl MockEventSource {
    fn new(ledger_id: Hash) -> Self {
        Self {
            events: Vec::new(),
            ledger_id,
            seal: None,
            governance_events: Vec::new(),
        }
    }

    fn with_events(mut self, events: Vec<LedgerEventView>) -> Self {
        self.events = events;
        self
    }

    fn with_seal(mut self, seal: TrustedSealV1) -> Self {
        self.seal = Some(seal);
        self
    }

    fn with_governance_events(mut self, events: Vec<LedgerEventView>) -> Self {
        self.governance_events = events;
        self
    }
}

impl LedgerEventSource for MockEventSource {
    fn read_events(&self, start_height: u64, limit: usize) -> Result<Vec<LedgerEventView>, String> {
        let events: Vec<_> = self
            .events
            .iter()
            .filter(|e| e.height >= start_height)
            .take(limit)
            .cloned()
            .collect();
        Ok(events)
    }

    fn tip_height(&self) -> Result<u64, String> {
        self.events
            .last()
            .map(|e| e.height)
            .ok_or_else(|| "no events".to_string())
    }

    fn ledger_id(&self) -> Hash {
        self.ledger_id
    }

    fn find_latest_seal(&self, _max_height: u64) -> Result<Option<TrustedSealV1>, String> {
        Ok(self.seal.clone())
    }

    fn read_governance_events(
        &self,
        start_height: u64,
        end_height: u64,
        limit: usize,
    ) -> Result<Vec<LedgerEventView>, String> {
        let events: Vec<_> = self
            .governance_events
            .iter()
            .filter(|e| e.height >= start_height && e.height <= end_height)
            .take(limit)
            .cloned()
            .collect();
        Ok(events)
    }
}

/// Build a valid chain of events for testing.
fn build_test_chain(
    ledger_id: Hash,
    start_height: u64,
    count: u64,
    signing_key: &ed25519_dalek::SigningKey,
    key_id: &str,
) -> Vec<LedgerEventView> {
    use ed25519_dalek::Signer;

    let mut events = Vec::new();
    let mut prev_hash = [0u8; 32]; // genesis prev_hash

    for i in 0..count {
        let height = start_height + i;
        let he_time = 1000 + i * 10;

        // Compute event hash deterministically.
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"test-event");
        hasher.update(&prev_hash);
        hasher.update(&height.to_le_bytes());
        hasher.update(&ledger_id);
        let event_hash = *hasher.finalize().as_bytes();

        // Sign the event hash.
        let signature = signing_key.sign(&event_hash).to_bytes().to_vec();

        events.push(LedgerEventView {
            height,
            event_hash,
            prev_hash,
            he_time,
            event_type: "test.event".to_string(),
            payload: Vec::new(),
            signature,
            signer_key_id: Some(key_id.to_string()),
        });

        prev_hash = event_hash;
    }

    events
}

// =============================================================================
// RootTrustBundle tests
// =============================================================================

#[test]
fn root_trust_bundle_empty_keys_rejected() {
    let bundle = RootTrustBundle {
        schema_version: ROOT_TRUST_BUNDLE_SCHEMA_VERSION.to_string(),
        bundle_id: test_hash(1),
        keys: vec![],
    };
    assert!(bundle.validate().is_err());
}

#[test]
fn root_trust_bundle_oversized_rejected() {
    let keys: Vec<TrustBundleKeyEntry> = (0..=MAX_TRUST_BUNDLE_KEYS)
        .map(|i| TrustBundleKeyEntry {
            algorithm_id: "ed25519".to_string(),
            key_id: format!("key-{i}"),
            public_key_bytes: vec![0x42; 32],
            active_from_epoch: 0,
            revoked_at_epoch: None,
        })
        .collect();
    let bundle = RootTrustBundle {
        schema_version: ROOT_TRUST_BUNDLE_SCHEMA_VERSION.to_string(),
        bundle_id: test_hash(1),
        keys,
    };
    assert!(bundle.validate().is_err());
}

#[test]
fn root_trust_bundle_duplicate_key_ids_rejected() {
    let bundle = RootTrustBundle {
        schema_version: ROOT_TRUST_BUNDLE_SCHEMA_VERSION.to_string(),
        bundle_id: test_hash(1),
        keys: vec![
            TrustBundleKeyEntry {
                algorithm_id: "ed25519".to_string(),
                key_id: "same-key".to_string(),
                public_key_bytes: vec![0x42; 32],
                active_from_epoch: 0,
                revoked_at_epoch: None,
            },
            TrustBundleKeyEntry {
                algorithm_id: "ed25519".to_string(),
                key_id: "same-key".to_string(),
                public_key_bytes: vec![0x43; 32],
                active_from_epoch: 0,
                revoked_at_epoch: None,
            },
        ],
    };
    assert!(bundle.validate().is_err());
}

#[test]
fn root_trust_bundle_valid_passes() {
    let (_, pk) = generate_test_keypair();
    let bundle = test_trust_bundle(&pk, "test-key-1");
    assert!(bundle.validate().is_ok());
}

#[test]
fn root_trust_bundle_content_hash_deterministic() {
    let (_, pk) = generate_test_keypair();
    let bundle = test_trust_bundle(&pk, "test-key-1");
    let hash1 = bundle.content_hash();
    let hash2 = bundle.content_hash();
    assert_eq!(hash1, hash2, "content hash must be deterministic");
}

// =============================================================================
// Key rotation/revocation semantics tests
// =============================================================================

#[test]
fn key_entry_active_at_epoch() {
    let entry = TrustBundleKeyEntry {
        algorithm_id: "ed25519".to_string(),
        key_id: "key-1".to_string(),
        public_key_bytes: vec![0x42; 32],
        active_from_epoch: 10,
        revoked_at_epoch: Some(20),
    };

    // Before active
    assert!(!entry.is_active_at(9));

    // At active_from (inclusive)
    assert!(entry.is_active_at(10));

    // In active range
    assert!(entry.is_active_at(15));

    // At revoked_at (exclusive — NOT active at revocation epoch)
    assert!(!entry.is_active_at(20));

    // After revoked
    assert!(!entry.is_active_at(25));
}

#[test]
fn key_entry_active_no_revocation() {
    let entry = TrustBundleKeyEntry {
        algorithm_id: "ed25519".to_string(),
        key_id: "key-1".to_string(),
        public_key_bytes: vec![0x42; 32],
        active_from_epoch: 5,
        revoked_at_epoch: None,
    };

    assert!(!entry.is_active_at(4));
    assert!(entry.is_active_at(5));
    assert!(entry.is_active_at(u64::MAX));
}

#[test]
fn key_entry_invalid_revocation_before_active() {
    let entry = TrustBundleKeyEntry {
        algorithm_id: "ed25519".to_string(),
        key_id: "key-1".to_string(),
        public_key_bytes: vec![0x42; 32],
        active_from_epoch: 20,
        revoked_at_epoch: Some(10), // Invalid: revoked before active
    };
    assert!(entry.validate().is_err());
}

#[test]
fn keyset_digest_changes_with_rotation() {
    let (_, pk1) = generate_test_keypair();
    let (_, pk2) = generate_test_keypair();

    let bundle = RootTrustBundle {
        schema_version: ROOT_TRUST_BUNDLE_SCHEMA_VERSION.to_string(),
        bundle_id: test_hash(0xBB),
        keys: vec![
            TrustBundleKeyEntry {
                algorithm_id: "ed25519".to_string(),
                key_id: "key-1".to_string(),
                public_key_bytes: pk1.to_vec(),
                active_from_epoch: 0,
                revoked_at_epoch: Some(100),
            },
            TrustBundleKeyEntry {
                algorithm_id: "ed25519".to_string(),
                key_id: "key-2".to_string(),
                public_key_bytes: pk2.to_vec(),
                active_from_epoch: 100,
                revoked_at_epoch: None,
            },
        ],
    };

    // Before rotation: only key-1 active
    let digest_before = bundle.active_keyset_digest(50);
    // After rotation: only key-2 active
    let digest_after = bundle.active_keyset_digest(150);

    assert_ne!(
        digest_before, digest_after,
        "keyset digest must change when active keyset changes due to rotation"
    );
}

// =============================================================================
// TrustedSealV1 tests
// =============================================================================

#[test]
fn trusted_seal_validation_empty_signature() {
    let seal = TrustedSealV1 {
        anchor: LedgerAnchorV1 {
            ledger_id: test_hash(1),
            event_hash: test_hash(2),
            height: 10,
            he_time: 100,
        },
        signer_key_id: "key-1".to_string(),
        algorithm_id: "ed25519".to_string(),
        signature: vec![], // Empty!
        seal_epoch: 5,
    };
    assert!(seal.validate().is_err());
}

#[test]
fn trusted_seal_signing_payload_deterministic() {
    let seal = TrustedSealV1 {
        anchor: LedgerAnchorV1 {
            ledger_id: test_hash(1),
            event_hash: test_hash(2),
            height: 10,
            he_time: 100,
        },
        signer_key_id: "key-1".to_string(),
        algorithm_id: "ed25519".to_string(),
        signature: vec![0x42; 64],
        seal_epoch: 5,
    };
    let payload1 = seal.signing_payload();
    let payload2 = seal.signing_payload();
    assert_eq!(payload1, payload2, "signing payload must be deterministic");
}

// =============================================================================
// Ed25519SignatureVerifier tests
// =============================================================================

#[test]
fn ed25519_verifier_unknown_algorithm_fails() {
    let verifier = Ed25519SignatureVerifier;
    let result = verifier.verify("dilithium3", &[0; 32], &[0; 32], &[0; 64]);
    assert!(result.is_err());
    assert!(
        result.unwrap_err().contains("unsupported algorithm"),
        "must fail closed on unknown algorithm"
    );
}

#[test]
fn ed25519_verifier_valid_signature_passes() {
    use ed25519_dalek::Signer;

    let (signing_key, public_key) = generate_test_keypair();
    let message = b"test message";
    let signature = signing_key.sign(message);

    let verifier = Ed25519SignatureVerifier;
    let result = verifier.verify("ed25519", &public_key, message, &signature.to_bytes());
    assert!(result.is_ok());
}

#[test]
fn ed25519_verifier_tampered_signature_fails() {
    use ed25519_dalek::Signer;

    let (signing_key, public_key) = generate_test_keypair();
    let message = b"test message";
    let signature = signing_key.sign(message);
    let mut bad_sig = signature.to_bytes();
    bad_sig[0] ^= 0xFF; // Tamper

    let verifier = Ed25519SignatureVerifier;
    let result = verifier.verify("ed25519", &public_key, message, &bad_sig);
    assert!(result.is_err());
}

// =============================================================================
// ConcreteLedgerTrustVerifier tests
// =============================================================================

#[test]
fn verifier_not_ready_before_startup() {
    let (_, pk) = generate_test_keypair();
    let bundle = test_trust_bundle(&pk, "test-key");
    let event_source = Arc::new(MockEventSource::new(test_hash(0xAA)));

    let verifier = ConcreteLedgerTrustVerifier::new(
        bundle,
        event_source,
        Arc::new(Ed25519SignatureVerifier),
        TrustVerifierConfig::default(),
    )
    .unwrap();

    let result = verifier.validated_state();
    assert!(matches!(result, Err(TrustError::NotReady)));
}

#[test]
fn verifier_missing_seal_fails() {
    let (signing_key, pk) = generate_test_keypair();
    let ledger_id = test_hash(0xAA);
    let events = build_test_chain(ledger_id, 1, 5, &signing_key, "test-key");

    let event_source = Arc::new(
        MockEventSource::new(ledger_id).with_events(events),
        // No seal!
    );

    let verifier = ConcreteLedgerTrustVerifier::new(
        test_trust_bundle(&pk, "test-key"),
        event_source,
        Arc::new(Ed25519SignatureVerifier),
        TrustVerifierConfig::default(),
    )
    .unwrap();

    let result = verifier.verify_startup();
    assert!(matches!(result, Err(TrustError::IntegrityFailure { .. })));
}

#[test]
fn verifier_startup_success() {
    let (signing_key, pk) = generate_test_keypair();
    let ledger_id = test_hash(0xAA);
    let events = build_test_chain(ledger_id, 1, 10, &signing_key, "test-key");

    // Create a seal at the first event.
    let seal_anchor = LedgerAnchorV1 {
        ledger_id,
        event_hash: events[0].event_hash,
        height: 1,
        he_time: events[0].he_time,
    };
    let seal = create_test_seal(&signing_key, &seal_anchor, "test-key", 0);

    let event_source = Arc::new(
        MockEventSource::new(ledger_id)
            .with_events(events)
            .with_seal(seal),
    );

    let verifier = ConcreteLedgerTrustVerifier::new(
        test_trust_bundle(&pk, "test-key"),
        event_source,
        Arc::new(Ed25519SignatureVerifier),
        TrustVerifierConfig::default(),
    )
    .unwrap();

    let result = verifier.verify_startup();
    assert!(result.is_ok(), "startup should succeed: {result:?}");

    // Validated state should now be available.
    let state = verifier.validated_state();
    assert!(state.is_ok());
    let state = state.unwrap();
    assert_eq!(state.validated_anchor.height, 1);
    assert_eq!(state.tip_anchor.height, 10);
    assert_eq!(
        state.root_trust_bundle_digest,
        test_trust_bundle(&pk, "test-key").content_hash()
    );
}

#[test]
fn verifier_seal_distance_exceeded() {
    let (signing_key, pk) = generate_test_keypair();
    let ledger_id = test_hash(0xAA);
    let events = build_test_chain(ledger_id, 1, 20, &signing_key, "test-key");

    let seal_anchor = LedgerAnchorV1 {
        ledger_id,
        event_hash: events[0].event_hash,
        height: 1,
        he_time: events[0].he_time,
    };
    let seal = create_test_seal(&signing_key, &seal_anchor, "test-key", 0);

    let event_source = Arc::new(
        MockEventSource::new(ledger_id)
            .with_events(events)
            .with_seal(seal),
    );

    let config = TrustVerifierConfig {
        max_seal_to_tip_distance: 5, // Very small limit
        allow_full_chain_fallback: false,
    };

    let verifier = ConcreteLedgerTrustVerifier::new(
        test_trust_bundle(&pk, "test-key"),
        event_source,
        Arc::new(Ed25519SignatureVerifier),
        config,
    )
    .unwrap();

    let result = verifier.verify_startup();
    assert!(
        matches!(
            result,
            Err(TrustError::SealDistanceExceeded {
                distance: 19,
                max_distance: 5
            })
        ),
        "should fail with SealDistanceExceeded, got: {result:?}"
    );
}

#[test]
fn verifier_seal_distance_exceeded_with_fallback() {
    let (signing_key, pk) = generate_test_keypair();
    let ledger_id = test_hash(0xAA);
    let events = build_test_chain(ledger_id, 1, 20, &signing_key, "test-key");

    let seal_anchor = LedgerAnchorV1 {
        ledger_id,
        event_hash: events[0].event_hash,
        height: 1,
        he_time: events[0].he_time,
    };
    let seal = create_test_seal(&signing_key, &seal_anchor, "test-key", 0);

    let event_source = Arc::new(
        MockEventSource::new(ledger_id)
            .with_events(events)
            .with_seal(seal),
    );

    let config = TrustVerifierConfig {
        max_seal_to_tip_distance: 5,
        allow_full_chain_fallback: true, // Allow fallback
    };

    let verifier = ConcreteLedgerTrustVerifier::new(
        test_trust_bundle(&pk, "test-key"),
        event_source,
        Arc::new(Ed25519SignatureVerifier),
        config,
    )
    .unwrap();

    // With full chain fallback enabled, startup should succeed even with
    // the seal being too far from tip.
    let result = verifier.verify_startup();
    assert!(
        result.is_ok(),
        "startup with full-chain fallback should succeed: {result:?}"
    );
}

#[test]
fn verifier_hash_chain_break_detected() {
    let (signing_key, pk) = generate_test_keypair();
    let ledger_id = test_hash(0xAA);
    let mut events = build_test_chain(ledger_id, 1, 10, &signing_key, "test-key");

    // Tamper with an event in the middle (break hash chain).
    events[5].prev_hash = test_hash(0xFF); // Wrong prev_hash

    let seal_anchor = LedgerAnchorV1 {
        ledger_id,
        event_hash: events[0].event_hash,
        height: 1,
        he_time: events[0].he_time,
    };
    let seal = create_test_seal(&signing_key, &seal_anchor, "test-key", 0);

    let event_source = Arc::new(
        MockEventSource::new(ledger_id)
            .with_events(events)
            .with_seal(seal),
    );

    let verifier = ConcreteLedgerTrustVerifier::new(
        test_trust_bundle(&pk, "test-key"),
        event_source,
        Arc::new(Ed25519SignatureVerifier),
        TrustVerifierConfig::default(),
    )
    .unwrap();

    let result = verifier.verify_startup();
    assert!(matches!(result, Err(TrustError::IntegrityFailure { .. })));
    if let Err(TrustError::IntegrityFailure { reason }) = &result {
        assert!(reason.contains("hash chain break"), "reason: {reason}");
    }
}

#[test]
fn verifier_ht_monotonicity_violation_detected() {
    let (signing_key, pk) = generate_test_keypair();
    let ledger_id = test_hash(0xAA);
    let mut events = build_test_chain(ledger_id, 1, 10, &signing_key, "test-key");

    // Make HT go backwards in the middle.
    events[5].he_time = 0; // Less than previous

    let seal_anchor = LedgerAnchorV1 {
        ledger_id,
        event_hash: events[0].event_hash,
        height: 1,
        he_time: events[0].he_time,
    };
    let seal = create_test_seal(&signing_key, &seal_anchor, "test-key", 0);

    let event_source = Arc::new(
        MockEventSource::new(ledger_id)
            .with_events(events)
            .with_seal(seal),
    );

    let verifier = ConcreteLedgerTrustVerifier::new(
        test_trust_bundle(&pk, "test-key"),
        event_source,
        Arc::new(Ed25519SignatureVerifier),
        TrustVerifierConfig::default(),
    )
    .unwrap();

    let result = verifier.verify_startup();
    assert!(matches!(result, Err(TrustError::IntegrityFailure { .. })));
    if let Err(TrustError::IntegrityFailure { reason }) = &result {
        assert!(reason.contains("HT monotonicity"), "reason: {reason}");
    }
}

#[test]
fn verifier_seal_signature_mismatch_detected() {
    let (signing_key, pk) = generate_test_keypair();
    let (other_key, _) = generate_test_keypair(); // Different key!
    let ledger_id = test_hash(0xAA);
    let events = build_test_chain(ledger_id, 1, 10, &signing_key, "test-key");

    let seal_anchor = LedgerAnchorV1 {
        ledger_id,
        event_hash: events[0].event_hash,
        height: 1,
        he_time: events[0].he_time,
    };
    // Sign seal with a DIFFERENT key than what's in the trust bundle.
    let seal = create_test_seal(&other_key, &seal_anchor, "test-key", 0);

    let event_source = Arc::new(
        MockEventSource::new(ledger_id)
            .with_events(events)
            .with_seal(seal),
    );

    let verifier = ConcreteLedgerTrustVerifier::new(
        test_trust_bundle(&pk, "test-key"),
        event_source,
        Arc::new(Ed25519SignatureVerifier),
        TrustVerifierConfig::default(),
    )
    .unwrap();

    let result = verifier.verify_startup();
    assert!(matches!(result, Err(TrustError::IntegrityFailure { .. })));
    if let Err(TrustError::IntegrityFailure { reason }) = &result {
        assert!(
            reason.contains("seal signature verification failed"),
            "reason: {reason}"
        );
    }
}

#[test]
fn verifier_seal_ledger_id_mismatch_detected() {
    let (signing_key, pk) = generate_test_keypair();
    let ledger_id = test_hash(0xAA);
    let events = build_test_chain(ledger_id, 1, 10, &signing_key, "test-key");

    // Create seal with a different ledger_id.
    let seal_anchor = LedgerAnchorV1 {
        ledger_id: test_hash(0xBB), // Different!
        event_hash: events[0].event_hash,
        height: 1,
        he_time: events[0].he_time,
    };
    let seal = create_test_seal(&signing_key, &seal_anchor, "test-key", 0);

    let event_source = Arc::new(
        MockEventSource::new(ledger_id)
            .with_events(events)
            .with_seal(seal),
    );

    let verifier = ConcreteLedgerTrustVerifier::new(
        test_trust_bundle(&pk, "test-key"),
        event_source,
        Arc::new(Ed25519SignatureVerifier),
        TrustVerifierConfig::default(),
    )
    .unwrap();

    let result = verifier.verify_startup();
    assert!(matches!(result, Err(TrustError::IntegrityFailure { .. })));
}

#[test]
fn verifier_key_revoked_at_seal_epoch_fails() {
    let (signing_key, pk) = generate_test_keypair();
    let ledger_id = test_hash(0xAA);
    let events = build_test_chain(ledger_id, 1, 10, &signing_key, "test-key");

    let seal_anchor = LedgerAnchorV1 {
        ledger_id,
        event_hash: events[0].event_hash,
        height: 1,
        he_time: events[0].he_time,
    };
    // Seal at epoch 50, but key is revoked at epoch 50 (exclusive).
    let seal = create_test_seal(&signing_key, &seal_anchor, "test-key", 50);

    // Key active from 0, revoked at 50 — NOT active at epoch 50.
    let bundle = RootTrustBundle {
        schema_version: ROOT_TRUST_BUNDLE_SCHEMA_VERSION.to_string(),
        bundle_id: test_hash(0xBB),
        keys: vec![TrustBundleKeyEntry {
            algorithm_id: "ed25519".to_string(),
            key_id: "test-key".to_string(),
            public_key_bytes: pk.to_vec(),
            active_from_epoch: 0,
            revoked_at_epoch: Some(50), // Revoked at seal epoch!
        }],
    };

    let event_source = Arc::new(
        MockEventSource::new(ledger_id)
            .with_events(events)
            .with_seal(seal),
    );

    let verifier = ConcreteLedgerTrustVerifier::new(
        bundle,
        event_source,
        Arc::new(Ed25519SignatureVerifier),
        TrustVerifierConfig::default(),
    )
    .unwrap();

    let result = verifier.verify_startup();
    assert!(
        matches!(result, Err(TrustError::IntegrityFailure { .. })),
        "verification should fail when key is revoked at seal epoch: {result:?}"
    );
}

// =============================================================================
// GovernancePolicyRootResolver tests
// =============================================================================

#[test]
fn policy_resolver_no_governance_events() {
    let (_, pk) = generate_test_keypair();
    let ledger_id = test_hash(0xAA);
    let event_source = Arc::new(MockEventSource::new(ledger_id));

    let resolver = GovernancePolicyRootResolver::new(
        test_trust_bundle(&pk, "test-key"),
        event_source,
        Arc::new(Ed25519SignatureVerifier),
    )
    .unwrap();

    let anchor = LedgerAnchorV1 {
        ledger_id,
        event_hash: test_hash(1),
        height: 10,
        he_time: 100,
    };
    let result = resolver.resolve(&anchor);
    assert!(matches!(result, Err(PolicyError::NoGovernanceEvents)));
}

#[test]
fn policy_resolver_unsigned_governance_event_fails() {
    let (_, pk) = generate_test_keypair();
    let ledger_id = test_hash(0xAA);

    let gov_events = vec![LedgerEventView {
        height: 1,
        event_hash: test_hash(0x10),
        prev_hash: [0u8; 32],
        he_time: 50,
        event_type: "governance.policy_update".to_string(),
        payload: Vec::new(),
        signature: Vec::new(), // Unsigned!
        signer_key_id: None,
    }];

    let event_source = Arc::new(MockEventSource::new(ledger_id).with_governance_events(gov_events));

    let resolver = GovernancePolicyRootResolver::new(
        test_trust_bundle(&pk, "test-key"),
        event_source,
        Arc::new(Ed25519SignatureVerifier),
    )
    .unwrap();

    let anchor = LedgerAnchorV1 {
        ledger_id,
        event_hash: test_hash(1),
        height: 10,
        he_time: 100,
    };
    let result = resolver.resolve(&anchor);
    assert!(matches!(
        result,
        Err(PolicyError::SignatureVerificationFailed { .. })
    ));
}

#[test]
fn policy_resolver_deterministic_derivation() {
    use ed25519_dalek::Signer;

    let (signing_key, pk) = generate_test_keypair();
    let ledger_id = test_hash(0xAA);

    // Build signed governance events.
    let mut gov_events = Vec::new();
    for i in 1..=3u64 {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"gov-event");
        hasher.update(&i.to_le_bytes());
        let event_hash = *hasher.finalize().as_bytes();
        let signature = signing_key.sign(&event_hash).to_bytes().to_vec();

        gov_events.push(LedgerEventView {
            height: i,
            event_hash,
            prev_hash: [0u8; 32],
            he_time: i * 10,
            event_type: "governance.policy_update".to_string(),
            payload: Vec::new(),
            signature,
            signer_key_id: Some("test-key".to_string()),
        });
    }

    let event_source = Arc::new(MockEventSource::new(ledger_id).with_governance_events(gov_events));

    let resolver = GovernancePolicyRootResolver::new(
        test_trust_bundle(&pk, "test-key"),
        event_source,
        Arc::new(Ed25519SignatureVerifier),
    )
    .unwrap();

    let anchor = LedgerAnchorV1 {
        ledger_id,
        event_hash: test_hash(1),
        height: 10,
        he_time: 100,
    };

    let result1 = resolver.resolve(&anchor).unwrap();
    let result2 = resolver.resolve(&anchor).unwrap();

    assert_eq!(
        result1.policy_root_digest, result2.policy_root_digest,
        "policy root derivation must be deterministic"
    );
    assert_eq!(result1.policy_root_epoch, result2.policy_root_epoch);
}

#[test]
fn policy_resolver_cache_hit() {
    use ed25519_dalek::Signer;

    let (signing_key, pk) = generate_test_keypair();
    let ledger_id = test_hash(0xAA);

    let mut hasher = blake3::Hasher::new();
    hasher.update(b"gov-event-1");
    let event_hash = *hasher.finalize().as_bytes();
    let signature = signing_key.sign(&event_hash).to_bytes().to_vec();

    let gov_events = vec![LedgerEventView {
        height: 1,
        event_hash,
        prev_hash: [0u8; 32],
        he_time: 10,
        event_type: "governance.policy_update".to_string(),
        payload: Vec::new(),
        signature,
        signer_key_id: Some("test-key".to_string()),
    }];

    let event_source = Arc::new(MockEventSource::new(ledger_id).with_governance_events(gov_events));

    let resolver = GovernancePolicyRootResolver::new(
        test_trust_bundle(&pk, "test-key"),
        event_source,
        Arc::new(Ed25519SignatureVerifier),
    )
    .unwrap();

    let anchor = LedgerAnchorV1 {
        ledger_id,
        event_hash: test_hash(1),
        height: 10,
        he_time: 100,
    };

    // First call: cache miss, derives
    let _ = resolver.resolve(&anchor).unwrap();

    // Second call: cache hit (same result)
    let result = resolver.resolve(&anchor).unwrap();
    assert_ne!(result.policy_root_digest, [0u8; 32]);

    // Verify cache has an entry.
    let cache = resolver.cache.read().unwrap();
    assert_eq!(cache.len(), 1);
}

#[test]
fn policy_resolver_cache_eviction_at_capacity() {
    use ed25519_dalek::Signer;

    let (signing_key, pk) = generate_test_keypair();
    let ledger_id = test_hash(0xAA);

    // Create a single governance event.
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"gov-event-1");
    let event_hash = *hasher.finalize().as_bytes();
    let signature = signing_key.sign(&event_hash).to_bytes().to_vec();

    let gov_events = vec![LedgerEventView {
        height: 1,
        event_hash,
        prev_hash: [0u8; 32],
        he_time: 10,
        event_type: "governance.policy_update".to_string(),
        payload: Vec::new(),
        signature,
        signer_key_id: Some("test-key".to_string()),
    }];

    let event_source = Arc::new(MockEventSource::new(ledger_id).with_governance_events(gov_events));

    let resolver = GovernancePolicyRootResolver::new(
        test_trust_bundle(&pk, "test-key"),
        event_source,
        Arc::new(Ed25519SignatureVerifier),
    )
    .unwrap();

    // Fill the cache to capacity with different anchors.
    #[allow(clippy::cast_possible_truncation)]
    // test values bounded by MAX_POLICY_ROOT_CACHE_ENTRIES (64)
    for i in 0..MAX_POLICY_ROOT_CACHE_ENTRIES {
        let byte = (i + 1) as u8;
        let anchor = LedgerAnchorV1 {
            ledger_id,
            event_hash: test_hash(byte),
            height: 10,
            he_time: (i + 1) as u64, // Different he_time = different cache key
        };
        let _ = resolver.resolve(&anchor).unwrap();
    }

    {
        let cache = resolver.cache.read().unwrap();
        assert_eq!(cache.len(), MAX_POLICY_ROOT_CACHE_ENTRIES);
    }

    // One more should evict oldest.
    let anchor = LedgerAnchorV1 {
        ledger_id,
        event_hash: test_hash(0xFF),
        height: 10,
        he_time: (MAX_POLICY_ROOT_CACHE_ENTRIES + 1) as u64,
    };
    let _ = resolver.resolve(&anchor).unwrap();

    let cache = resolver.cache.read().unwrap();
    assert_eq!(
        cache.len(),
        MAX_POLICY_ROOT_CACHE_ENTRIES,
        "cache should not grow beyond capacity"
    );
}

#[test]
fn policy_resolver_different_anchors_produce_different_roots() {
    use ed25519_dalek::Signer;

    let (signing_key, pk) = generate_test_keypair();
    let ledger_id = test_hash(0xAA);

    // Create multiple governance events at different heights.
    let mut gov_events = Vec::new();
    for i in 1..=5u64 {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"gov-event");
        hasher.update(&i.to_le_bytes());
        let event_hash = *hasher.finalize().as_bytes();
        let signature = signing_key.sign(&event_hash).to_bytes().to_vec();

        gov_events.push(LedgerEventView {
            height: i,
            event_hash,
            prev_hash: [0u8; 32],
            he_time: i * 10,
            event_type: "governance.policy_update".to_string(),
            payload: Vec::new(),
            signature,
            signer_key_id: Some("test-key".to_string()),
        });
    }

    let event_source = Arc::new(MockEventSource::new(ledger_id).with_governance_events(gov_events));

    let resolver = GovernancePolicyRootResolver::new(
        test_trust_bundle(&pk, "test-key"),
        event_source,
        Arc::new(Ed25519SignatureVerifier),
    )
    .unwrap();

    // Anchor at height 3 (includes events 1-3)
    let anchor_3 = LedgerAnchorV1 {
        ledger_id,
        event_hash: test_hash(1),
        height: 3,
        he_time: 100,
    };

    // Anchor at height 5 (includes events 1-5)
    let anchor_5 = LedgerAnchorV1 {
        ledger_id,
        event_hash: test_hash(2),
        height: 5,
        he_time: 200,
    };

    let result_3 = resolver.resolve(&anchor_3).unwrap();
    let result_5 = resolver.resolve(&anchor_5).unwrap();

    assert_ne!(
        result_3.policy_root_digest, result_5.policy_root_digest,
        "different anchor heights with different governance events should produce different roots"
    );
}

// =============================================================================
// Finding 1: Seal anchor binding tests
// =============================================================================

/// Build a valid chain with a different starting `event_hash` than
/// `forked_hash`, but internally consistent (valid hash chain, valid
/// signatures, monotonic HT).
fn build_forked_chain(
    ledger_id: Hash,
    start_height: u64,
    count: u64,
    signing_key: &ed25519_dalek::SigningKey,
    key_id: &str,
    fork_seed: u8,
) -> Vec<LedgerEventView> {
    use ed25519_dalek::Signer;

    let mut events = Vec::new();
    let mut prev_hash = [0u8; 32];

    for i in 0..count {
        let height = start_height + i;
        let he_time = 1000 + i * 10;

        // Compute event hash with a fork seed to produce a different chain.
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"forked-event");
        hasher.update(&[fork_seed]);
        hasher.update(&prev_hash);
        hasher.update(&height.to_le_bytes());
        hasher.update(&ledger_id);
        let event_hash = *hasher.finalize().as_bytes();

        let signature = signing_key.sign(&event_hash).to_bytes().to_vec();

        events.push(LedgerEventView {
            height,
            event_hash,
            prev_hash,
            he_time,
            event_type: "test.event".to_string(),
            payload: Vec::new(),
            signature,
            signer_key_id: Some(key_id.to_string()),
        });

        prev_hash = event_hash;
    }

    events
}

#[test]
fn verifier_anchor_binding_rejects_forked_chain() {
    let (signing_key, pk) = generate_test_keypair();
    let ledger_id = test_hash(0xAA);

    // Build a "canonical" chain to establish the seal anchor.
    let canonical_events = build_test_chain(ledger_id, 1, 10, &signing_key, "test-key");
    let seal_anchor = LedgerAnchorV1 {
        ledger_id,
        event_hash: canonical_events[0].event_hash,
        height: 1,
        he_time: canonical_events[0].he_time,
    };
    let seal = create_test_seal(&signing_key, &seal_anchor, "test-key", 0);

    // Build a FORKED chain that is internally consistent but starts with a
    // different event_hash at height 1 than the seal commits to.
    let forked_events = build_forked_chain(ledger_id, 1, 10, &signing_key, "test-key", 0xFF);

    // Verify the forked chain's first event hash differs from the seal anchor.
    assert_ne!(
        forked_events[0].event_hash, canonical_events[0].event_hash,
        "forked chain must have a different event_hash at height 1"
    );

    let event_source = Arc::new(
        MockEventSource::new(ledger_id)
            .with_events(forked_events)
            .with_seal(seal),
    );

    let verifier = ConcreteLedgerTrustVerifier::new(
        test_trust_bundle(&pk, "test-key"),
        event_source,
        Arc::new(Ed25519SignatureVerifier),
        TrustVerifierConfig::default(),
    )
    .unwrap();

    let result = verifier.verify_startup();
    assert!(
        matches!(result, Err(TrustError::IntegrityFailure { .. })),
        "forked chain should be rejected: {result:?}"
    );
    if let Err(TrustError::IntegrityFailure { reason }) = &result {
        assert!(
            reason.contains("does not match sealed anchor event_hash"),
            "reason should mention anchor mismatch: {reason}"
        );
    }
}

#[test]
fn verifier_anchor_binding_accepts_correct_chain() {
    // This is essentially the same as verifier_startup_success but
    // explicitly validates that anchor binding works on the happy path.
    let (signing_key, pk) = generate_test_keypair();
    let ledger_id = test_hash(0xAA);
    let events = build_test_chain(ledger_id, 1, 10, &signing_key, "test-key");

    let seal_anchor = LedgerAnchorV1 {
        ledger_id,
        event_hash: events[0].event_hash,
        height: 1,
        he_time: events[0].he_time,
    };
    let seal = create_test_seal(&signing_key, &seal_anchor, "test-key", 0);

    let event_source = Arc::new(
        MockEventSource::new(ledger_id)
            .with_events(events)
            .with_seal(seal),
    );

    let verifier = ConcreteLedgerTrustVerifier::new(
        test_trust_bundle(&pk, "test-key"),
        event_source,
        Arc::new(Ed25519SignatureVerifier),
        TrustVerifierConfig::default(),
    )
    .unwrap();

    let result = verifier.verify_startup();
    assert!(
        result.is_ok(),
        "correct chain with matching anchor should succeed: {result:?}"
    );
}

// =============================================================================
// Finding 2: Incomplete chain reads fail-closed
// =============================================================================

/// Mock event source that delegates to an inner [`MockEventSource`] but
/// overrides `tip_height()` to return a caller-specified value, simulating
/// a ledger that claims a tip higher than the events it can actually produce.
struct TruncatedEventSource {
    inner: MockEventSource,
    fake_tip: u64,
}

impl LedgerEventSource for TruncatedEventSource {
    fn read_events(&self, start_height: u64, limit: usize) -> Result<Vec<LedgerEventView>, String> {
        self.inner.read_events(start_height, limit)
    }

    fn tip_height(&self) -> Result<u64, String> {
        Ok(self.fake_tip)
    }

    fn ledger_id(&self) -> Hash {
        self.inner.ledger_id()
    }

    fn find_latest_seal(&self, max_height: u64) -> Result<Option<TrustedSealV1>, String> {
        self.inner.find_latest_seal(max_height)
    }

    fn read_governance_events(
        &self,
        start_height: u64,
        end_height: u64,
        limit: usize,
    ) -> Result<Vec<LedgerEventView>, String> {
        self.inner
            .read_governance_events(start_height, end_height, limit)
    }
}

#[test]
fn verifier_incomplete_chain_fails_closed() {
    let (signing_key, pk) = generate_test_keypair();
    let ledger_id = test_hash(0xAA);

    // Build a chain of 10 events, but only include events for heights 1-5.
    // The mock event source will claim tip_height = 10 but return empty
    // for heights 6+.
    let full_events = build_test_chain(ledger_id, 1, 10, &signing_key, "test-key");
    let partial_events: Vec<_> = full_events.into_iter().take(5).collect();

    let seal_anchor = LedgerAnchorV1 {
        ledger_id,
        event_hash: partial_events[0].event_hash,
        height: 1,
        he_time: partial_events[0].he_time,
    };
    let seal = create_test_seal(&signing_key, &seal_anchor, "test-key", 0);

    let inner_source = MockEventSource::new(ledger_id)
        .with_events(partial_events)
        .with_seal(seal);

    let event_source = Arc::new(TruncatedEventSource {
        inner: inner_source,
        fake_tip: 10,
    });

    let verifier = ConcreteLedgerTrustVerifier::new(
        test_trust_bundle(&pk, "test-key"),
        event_source,
        Arc::new(Ed25519SignatureVerifier),
        TrustVerifierConfig::default(),
    )
    .unwrap();

    let result = verifier.verify_startup();
    assert!(
        matches!(result, Err(TrustError::IntegrityFailure { .. })),
        "incomplete chain should fail closed: {result:?}"
    );
    if let Err(TrustError::IntegrityFailure { reason }) = &result {
        assert!(
            reason.contains("chain verification gap"),
            "reason should mention chain gap: {reason}"
        );
    }
}

// =============================================================================
// Finding 3: Per-event key epoch resolution tests
// =============================================================================

/// Build a chain where events have specific `he_time` values and are signed
/// with a specific key.
fn build_chain_with_key_rotation(
    ledger_id: Hash,
    start_height: u64,
    entries: &[(u64, &ed25519_dalek::SigningKey, &str)], // (he_time, key, key_id)
) -> Vec<LedgerEventView> {
    use ed25519_dalek::Signer;

    let mut events = Vec::new();
    let mut prev_hash = [0u8; 32];

    for (i, &(he_time, signing_key, key_id)) in entries.iter().enumerate() {
        #[allow(clippy::cast_possible_truncation)]
        let height = start_height + i as u64;

        let mut hasher = blake3::Hasher::new();
        hasher.update(b"test-event");
        hasher.update(&prev_hash);
        hasher.update(&height.to_le_bytes());
        hasher.update(&ledger_id);
        let event_hash = *hasher.finalize().as_bytes();

        let signature = signing_key.sign(&event_hash).to_bytes().to_vec();

        events.push(LedgerEventView {
            height,
            event_hash,
            prev_hash,
            he_time,
            event_type: "test.event".to_string(),
            payload: Vec::new(),
            signature,
            signer_key_id: Some(key_id.to_string()),
        });

        prev_hash = event_hash;
    }

    events
}

#[test]
fn verifier_post_seal_key_rotation_accepted() {
    let (key1, pk1) = generate_test_keypair();
    let (key2, pk2) = generate_test_keypair();
    let ledger_id = test_hash(0xAA);

    // Trust bundle with two keys:
    //   key-1: active [0, 100)
    //   key-2: active [100, inf)
    let bundle = RootTrustBundle {
        schema_version: ROOT_TRUST_BUNDLE_SCHEMA_VERSION.to_string(),
        bundle_id: test_hash(0xBB),
        keys: vec![
            TrustBundleKeyEntry {
                algorithm_id: "ed25519".to_string(),
                key_id: "key-1".to_string(),
                public_key_bytes: pk1.to_vec(),
                active_from_epoch: 0,
                revoked_at_epoch: Some(100),
            },
            TrustBundleKeyEntry {
                algorithm_id: "ed25519".to_string(),
                key_id: "key-2".to_string(),
                public_key_bytes: pk2.to_vec(),
                active_from_epoch: 100,
                revoked_at_epoch: None,
            },
        ],
    };

    // Build a chain where:
    //   Events at he_time < 100 are signed with key-1
    //   Events at he_time >= 100 are signed with key-2
    let entries: Vec<(u64, &ed25519_dalek::SigningKey, &str)> = vec![
        (10, &key1, "key-1"),
        (30, &key1, "key-1"),
        (50, &key1, "key-1"),
        (80, &key1, "key-1"),
        (100, &key2, "key-2"), // Post-rotation
        (120, &key2, "key-2"),
        (150, &key2, "key-2"),
    ];
    let events = build_chain_with_key_rotation(ledger_id, 1, &entries);

    // Seal at epoch 50 using key-1 (anchored at first event).
    let seal_anchor = LedgerAnchorV1 {
        ledger_id,
        event_hash: events[0].event_hash,
        height: 1,
        he_time: events[0].he_time,
    };
    let seal = create_test_seal(&key1, &seal_anchor, "key-1", 50);

    let event_source = Arc::new(
        MockEventSource::new(ledger_id)
            .with_events(events)
            .with_seal(seal),
    );

    let verifier = ConcreteLedgerTrustVerifier::new(
        bundle,
        event_source,
        Arc::new(Ed25519SignatureVerifier),
        TrustVerifierConfig::default(),
    )
    .unwrap();

    let result = verifier.verify_startup();
    assert!(
        result.is_ok(),
        "post-seal key rotation should be accepted with per-event epoch resolution: {result:?}"
    );
}

#[test]
fn verifier_revoked_key_rejected_at_event_epoch() {
    let (key1, pk1) = generate_test_keypair();
    let ledger_id = test_hash(0xAA);

    // Trust bundle with one key that is revoked at epoch 50.
    let bundle = RootTrustBundle {
        schema_version: ROOT_TRUST_BUNDLE_SCHEMA_VERSION.to_string(),
        bundle_id: test_hash(0xBB),
        keys: vec![TrustBundleKeyEntry {
            algorithm_id: "ed25519".to_string(),
            key_id: "key-1".to_string(),
            public_key_bytes: pk1.to_vec(),
            active_from_epoch: 0,
            revoked_at_epoch: Some(50),
        }],
    };

    // Build a chain where an event at he_time=60 is signed with key-1.
    // key-1 is NOT active at epoch 60 (revoked at 50), so this should fail.
    let entries: Vec<(u64, &ed25519_dalek::SigningKey, &str)> = vec![
        (10, &key1, "key-1"),
        (20, &key1, "key-1"),
        (30, &key1, "key-1"),
        (60, &key1, "key-1"), // key-1 is revoked at epoch 50 -- should fail
    ];
    let events = build_chain_with_key_rotation(ledger_id, 1, &entries);

    // Seal at epoch 10 using key-1 (valid at epoch 10).
    let seal_anchor = LedgerAnchorV1 {
        ledger_id,
        event_hash: events[0].event_hash,
        height: 1,
        he_time: events[0].he_time,
    };
    let seal = create_test_seal(&key1, &seal_anchor, "key-1", 10);

    let event_source = Arc::new(
        MockEventSource::new(ledger_id)
            .with_events(events)
            .with_seal(seal),
    );

    let verifier = ConcreteLedgerTrustVerifier::new(
        bundle,
        event_source,
        Arc::new(Ed25519SignatureVerifier),
        TrustVerifierConfig::default(),
    )
    .unwrap();

    let result = verifier.verify_startup();
    assert!(
        matches!(result, Err(TrustError::IntegrityFailure { .. })),
        "revoked key at event epoch should be rejected: {result:?}"
    );
    if let Err(TrustError::IntegrityFailure { reason }) = &result {
        assert!(
            reason.contains("not found or not active at epoch"),
            "reason should mention key not active: {reason}"
        );
    }
}
