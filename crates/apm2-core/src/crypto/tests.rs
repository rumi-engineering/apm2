//! Integration tests for crypto primitives.

use super::hash::Hash;
use super::*;

/// Test end-to-end event signing and verification.
#[test]
fn test_event_sign_verify_workflow() {
    let key_manager = KeyManager::in_memory();

    // Generate a keypair for the actor
    let signing_key = key_manager.generate_keypair("actor-1").unwrap();
    let signer = Signer::new(signing_key);

    // Simulate creating and signing events
    let prev_hash = EventHasher::GENESIS_PREV_HASH;
    let event_content = b"session.start: session-123";

    // Hash the event content with chain linking
    let event_hash = EventHasher::hash_event(event_content, &prev_hash);

    // Sign the event hash
    let signature = signer.sign(&event_hash);

    // Verify the signature
    assert!(signer.verify(&event_hash, &signature));

    // Verify using standalone function with public key
    let verifying_key = signer.verifying_key();
    verify_signature(&verifying_key, &event_hash, &signature).unwrap();
}

/// Test hash chain with multiple events.
#[test]
fn test_hash_chain_integrity() {
    let events = [
        (b"event-1".as_slice(), "First event"),
        (b"event-2".as_slice(), "Second event"),
        (b"event-3".as_slice(), "Third event"),
    ];

    let mut chain_events: Vec<(Vec<u8>, Hash, Hash)> = Vec::new();
    let mut prev_hash = EventHasher::GENESIS_PREV_HASH;

    for (content, _description) in &events {
        let event_hash = EventHasher::hash_event(content, &prev_hash);
        chain_events.push((content.to_vec(), prev_hash, event_hash));
        prev_hash = event_hash;
    }

    // Verify the entire chain
    let chain_refs: Vec<_> = chain_events
        .iter()
        .map(|(content, prev, hash)| (content.as_slice(), prev, hash))
        .collect();

    EventHasher::verify_chain(chain_refs).unwrap();
}

/// Test that tampering with event content breaks verification.
#[test]
fn test_tampering_detection() {
    let key_manager = KeyManager::in_memory();
    let signing_key = key_manager.generate_keypair("actor-1").unwrap();
    let signer = Signer::new(signing_key);

    let original_content = b"original event content";
    let prev_hash = EventHasher::GENESIS_PREV_HASH;

    let event_hash = EventHasher::hash_event(original_content, &prev_hash);
    let signature = signer.sign(&event_hash);

    // Tamper with the content
    let tampered_content = b"tampered event content";
    let tampered_hash = EventHasher::hash_event(tampered_content, &prev_hash);

    // Signature should not verify with tampered hash
    assert!(!signer.verify(&tampered_hash, &signature));
}

/// Test that tampering with hash chain breaks verification.
#[test]
fn test_chain_tampering_detection() {
    // Create a chain of events
    let content1 = b"event-1";
    let content2 = b"event-2";
    let content3 = b"event-3";

    let hash1 = EventHasher::hash_event(content1, &EventHasher::GENESIS_PREV_HASH);
    let hash2 = EventHasher::hash_event(content2, &hash1);
    let hash3 = EventHasher::hash_event(content3, &hash2);

    // Valid chain
    let valid_chain = [
        (content1.as_slice(), &EventHasher::GENESIS_PREV_HASH, &hash1),
        (content2.as_slice(), &hash1, &hash2),
        (content3.as_slice(), &hash2, &hash3),
    ];

    EventHasher::verify_chain(valid_chain).unwrap();

    // Tampered chain (wrong prev_hash in event 2)
    let wrong_prev = [0xffu8; HASH_SIZE];
    let tampered_chain = [
        (content1.as_slice(), &EventHasher::GENESIS_PREV_HASH, &hash1),
        (content2.as_slice(), &wrong_prev, &hash2), // Wrong prev_hash
        (content3.as_slice(), &hash2, &hash3),
    ];

    let result = EventHasher::verify_chain(tampered_chain);
    assert!(matches!(result, Err(HashChainError::ChainBroken { .. })));
}

/// Test key persistence and retrieval.
#[test]
fn test_key_persistence() {
    let key_manager = KeyManager::in_memory();

    // Generate and store a key
    let original_key = key_manager.generate_keypair("persistent-actor").unwrap();
    let original_public = original_key.verifying_key().to_bytes();

    // Retrieve the key
    let stored = key_manager.get_keypair("persistent-actor").unwrap();

    // Public keys should match
    assert_eq!(stored.public_key, original_public);

    // Signatures should match
    let message = b"test message";
    let sig1 = Signer::new(original_key).sign(message);
    let sig2 = Signer::new(stored.signing_key().clone()).sign(message);
    assert_eq!(sig1, sig2);
}

/// Test multiple actors with separate keys.
#[test]
fn test_multiple_actors() {
    let key_manager = KeyManager::in_memory();

    // Generate keys for multiple actors
    let key1 = key_manager.generate_keypair("actor-1").unwrap();
    let key2 = key_manager.generate_keypair("actor-2").unwrap();
    let key3 = key_manager.generate_keypair("actor-3").unwrap();

    // Keys should be different
    assert_ne!(
        key1.verifying_key().to_bytes(),
        key2.verifying_key().to_bytes()
    );
    assert_ne!(
        key2.verifying_key().to_bytes(),
        key3.verifying_key().to_bytes()
    );

    // Each actor can sign and verify their own messages
    let message = b"shared message";

    let sig1 = Signer::new(key1.clone()).sign(message);
    let sig2 = Signer::new(key2.clone()).sign(message);

    // Actor 1's signature verifies with actor 1's key
    assert!(Signer::new(key1).verify(message, &sig1));

    // Actor 1's signature doesn't verify with actor 2's key
    assert!(!Signer::new(key2).verify(message, &sig1));

    // Actor 2's signature verifies with actor 2's key
    let signer2 = Signer::new(
        key_manager
            .get_keypair("actor-2")
            .unwrap()
            .signing_key()
            .clone(),
    );
    assert!(signer2.verify(message, &sig2));
}

/// Test signature serialization and deserialization.
#[test]
fn test_signature_serialization() {
    let signer = Signer::generate();
    let message = b"message to sign";

    let signature = signer.sign(message);
    let signature_bytes = signature.to_bytes();

    // Parse signature from bytes
    let parsed = parse_signature(&signature_bytes).unwrap();
    assert_eq!(signature, parsed);

    // Parsed signature should verify
    assert!(signer.verify(message, &parsed));
}

/// Test verifying key serialization and deserialization.
#[test]
fn test_verifying_key_serialization() {
    let signer = Signer::generate();
    let message = b"message to sign";
    let signature = signer.sign(message);

    let key_bytes = signer.public_key_bytes();

    // Parse verifying key from bytes
    let parsed_key = parse_verifying_key(&key_bytes).unwrap();
    assert_eq!(signer.verifying_key(), parsed_key);

    // Verify signature with parsed key
    verify_signature(&parsed_key, message, &signature).unwrap();
}

/// Test that hash output is 32 bytes.
#[test]
fn test_hash_size() {
    let hash = EventHasher::hash_content(b"any content");
    assert_eq!(hash.len(), HASH_SIZE);
    assert_eq!(hash.len(), 32);
}

/// Test that signature output is 64 bytes.
#[test]
fn test_signature_size() {
    let signer = Signer::generate();
    let signature = signer.sign(b"any message");
    assert_eq!(signature.to_bytes().len(), SIGNATURE_SIZE);
    assert_eq!(signature.to_bytes().len(), 64);
}

/// Test empty content hashing.
#[test]
fn test_empty_content() {
    let empty = b"";
    let hash = EventHasher::hash_content(empty);
    assert_eq!(hash.len(), HASH_SIZE);

    // Empty content with genesis prev_hash
    let event_hash = EventHasher::hash_event(empty, &EventHasher::GENESIS_PREV_HASH);
    assert_eq!(event_hash.len(), HASH_SIZE);
    assert_ne!(hash, event_hash); // Chain linking changes the hash
}

/// Test large content hashing.
#[test]
fn test_large_content() {
    let large_content = vec![0xab_u8; 1_000_000]; // 1MB
    let hash = EventHasher::hash_content(&large_content);
    assert_eq!(hash.len(), HASH_SIZE);

    // Large event with chain linking
    let event_hash = EventHasher::hash_event(&large_content, &EventHasher::GENESIS_PREV_HASH);
    assert_eq!(event_hash.len(), HASH_SIZE);
}
