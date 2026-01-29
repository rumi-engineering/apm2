//! E2E receipt verification tests for TCK-00177.
//!
//! This module tests the full receipt signing and verification flow including:
//! - Ed25519 signature generation
//! - Signature verification against public key
//! - Tampered receipt detection
//! - Signer identity verification
//!
//! # Test Approach
//!
//! These tests use the signer and verifier modules to ensure:
//! 1. Signed receipts verify correctly with the signer's public key
//! 2. Tampered receipts fail verification
//! 3. Wrong public key causes verification failure
//!
//! # Contract References
//!
//! - TCK-00177: E2E evidence and receipt verification tests
//! - AD-RECEIPT-001: Tool receipt generation
//! - AD-KEY-001: Key lifecycle management
//! - AD-VERIFY-001: Receipt verification
//!
//! # Test Coverage
//!
//! | Test ID        | Description                          |
//! |----------------|--------------------------------------|
//! | E2E-00177-02   | Receipt verification E2E             |
//! | UT-RC-001      | Signature verifies with correct key  |
//! | UT-RC-002      | Tampered receipt fails verification  |
//! | UT-RC-003      | Wrong key fails verification         |
//! | UT-RC-004      | Signer identity matches              |
//! | UT-RC-005      | Deterministic signatures             |

mod common;

use apm2_daemon::episode::EpisodeId;
use apm2_daemon::evidence::{
    KeyId, ReceiptBuilder, ReceiptSigner, SignerError, SignerIdentity, ToolExecutionDetails,
    ToolReceipt, VerificationError, verify_receipt, verify_receipt_self_signed,
    verify_receipt_with_bytes,
};

// =============================================================================
// Test Helpers
// =============================================================================

/// Creates a test episode ID.
fn test_episode_id(suffix: &str) -> EpisodeId {
    EpisodeId::new(format!("e2e-receipt-{suffix}")).expect("valid episode ID")
}

/// Creates a test key ID.
fn test_key_id(suffix: &str) -> KeyId {
    KeyId::new(format!("test-key-{suffix}")).expect("valid key ID")
}

/// Test timestamp base: 2024-01-01 00:00:00 UTC in nanoseconds.
const TEST_TIMESTAMP_NS: u64 = 1_704_067_200_000_000_000;

/// Creates a test unsigned receipt.
fn make_test_receipt(suffix: &str) -> ToolReceipt {
    ReceiptBuilder::for_tool_execution(test_episode_id(suffix))
        .with_envelope([0xaa; 32])
        .with_policy([0xbb; 32])
        .with_evidence(vec![[0xcc; 32]])
        .with_timestamp(TEST_TIMESTAMP_NS)
        .with_details(ToolExecutionDetails {
            request_id: format!("req-{suffix}"),
            capability_id: "cap-read".to_string(),
            args_hash: [0x11; 32],
            result_hash: [0x22; 32],
            success: true,
            result_message: Some("completed".to_string()),
            duration_ns: 100_000_000,
        })
        .build()
        .expect("receipt build should succeed")
}

// =============================================================================
// UT-RC-001: Signature Verifies with Correct Key
// =============================================================================

/// Tests that a signed receipt verifies correctly with the signer's public key.
#[test]
fn test_signature_verifies_with_correct_key() {
    let signer = ReceiptSigner::generate(test_key_id("001"), 1).expect("signer generation");

    let receipt = make_test_receipt("verify-001");
    let signed_receipt = signer.sign(receipt).expect("signing should succeed");

    // Verify the receipt is signed
    assert!(signed_receipt.is_signed(), "receipt should be signed");

    // Verify with the correct public key
    let result = verify_receipt(&signed_receipt, signer.verifying_key());
    assert!(
        result.is_ok(),
        "verification should succeed with correct key"
    );
}

/// Tests that multiple receipts from the same signer all verify.
#[test]
fn test_multiple_receipts_same_signer() {
    let signer = ReceiptSigner::generate(test_key_id("002"), 1).expect("signer generation");

    // Sign multiple receipts
    for i in 0..5 {
        let receipt = make_test_receipt(&format!("multi-{i:03}"));
        let signed_receipt = signer.sign(receipt).expect("signing should succeed");

        let result = verify_receipt(&signed_receipt, signer.verifying_key());
        assert!(
            result.is_ok(),
            "all receipts from same signer should verify"
        );
    }
}

/// Tests verification with different receipt kinds.
#[test]
fn test_verify_different_receipt_kinds() {
    let signer = ReceiptSigner::generate(test_key_id("003"), 1).expect("signer generation");

    // EpisodeStart
    let start_receipt = ReceiptBuilder::for_episode_start(test_episode_id("kind-start"))
        .with_envelope([0xaa; 32])
        .with_policy([0xbb; 32])
        .with_timestamp(TEST_TIMESTAMP_NS)
        .build()
        .unwrap();
    let signed_start = signer.sign(start_receipt).unwrap();
    assert!(verify_receipt(&signed_start, signer.verifying_key()).is_ok());

    // EpisodeStop
    let stop_receipt = ReceiptBuilder::for_episode_stop(test_episode_id("kind-stop"))
        .with_envelope([0xaa; 32])
        .with_policy([0xbb; 32])
        .with_timestamp(TEST_TIMESTAMP_NS)
        .build()
        .unwrap();
    let signed_stop = signer.sign(stop_receipt).unwrap();
    assert!(verify_receipt(&signed_stop, signer.verifying_key()).is_ok());

    // BudgetCheckpoint
    let budget_receipt = ReceiptBuilder::for_budget_checkpoint(test_episode_id("kind-budget"))
        .with_envelope([0xaa; 32])
        .with_policy([0xbb; 32])
        .with_timestamp(TEST_TIMESTAMP_NS)
        .build()
        .unwrap();
    let signed_budget = signer.sign(budget_receipt).unwrap();
    assert!(verify_receipt(&signed_budget, signer.verifying_key()).is_ok());
}

// =============================================================================
// UT-RC-002: Tampered Receipt Fails Verification
// =============================================================================

/// Tests that modifying the envelope hash after signing fails verification.
#[test]
fn test_tampered_envelope_hash_fails() {
    let signer = ReceiptSigner::generate(test_key_id("004"), 1).expect("signer generation");

    let receipt = make_test_receipt("tamper-env-001");
    let mut signed_receipt = signer.sign(receipt).expect("signing should succeed");

    // Tamper with the envelope hash
    signed_receipt.envelope_hash = [0xff; 32];

    // Verification should fail
    let result = verify_receipt(&signed_receipt, signer.verifying_key());
    assert!(
        matches!(result, Err(VerificationError::InvalidSignature)),
        "tampered envelope hash should fail verification"
    );
}

/// Tests that modifying the policy hash after signing fails verification.
#[test]
fn test_tampered_policy_hash_fails() {
    let signer = ReceiptSigner::generate(test_key_id("005"), 1).expect("signer generation");

    let receipt = make_test_receipt("tamper-pol-001");
    let mut signed_receipt = signer.sign(receipt).expect("signing should succeed");

    // Tamper with the policy hash
    signed_receipt.policy_hash = [0xff; 32];

    // Verification should fail
    let result = verify_receipt(&signed_receipt, signer.verifying_key());
    assert!(
        matches!(result, Err(VerificationError::InvalidSignature)),
        "tampered policy hash should fail verification"
    );
}

/// Tests that modifying evidence refs after signing fails verification.
#[test]
fn test_tampered_evidence_refs_fails() {
    let signer = ReceiptSigner::generate(test_key_id("006"), 1).expect("signer generation");

    let receipt = make_test_receipt("tamper-evid-001");
    let mut signed_receipt = signer.sign(receipt).expect("signing should succeed");

    // Tamper with evidence refs
    signed_receipt.evidence_refs.push([0xdd; 32]);

    // Verification should fail
    let result = verify_receipt(&signed_receipt, signer.verifying_key());
    assert!(
        matches!(result, Err(VerificationError::InvalidSignature)),
        "tampered evidence refs should fail verification"
    );
}

/// Tests that modifying the timestamp after signing fails verification.
#[test]
fn test_tampered_timestamp_fails() {
    let signer = ReceiptSigner::generate(test_key_id("007"), 1).expect("signer generation");

    let receipt = make_test_receipt("tamper-ts-001");
    let mut signed_receipt = signer.sign(receipt).expect("signing should succeed");

    // Tamper with timestamp
    signed_receipt.timestamp_ns += 1000;

    // Verification should fail
    let result = verify_receipt(&signed_receipt, signer.verifying_key());
    assert!(
        matches!(result, Err(VerificationError::InvalidSignature)),
        "tampered timestamp should fail verification"
    );
}

/// Tests that corrupting the signature itself fails verification.
#[test]
fn test_corrupted_signature_fails() {
    let signer = ReceiptSigner::generate(test_key_id("008"), 1).expect("signer generation");

    let receipt = make_test_receipt("corrupt-sig-001");
    let mut signed_receipt = signer.sign(receipt).expect("signing should succeed");

    // Corrupt the signature
    if let Some(ref mut sig) = signed_receipt.signature {
        sig[0] ^= 0xff;
    }

    // Verification should fail
    let result = verify_receipt(&signed_receipt, signer.verifying_key());
    assert!(
        matches!(result, Err(VerificationError::InvalidSignature)),
        "corrupted signature should fail verification"
    );
}

// =============================================================================
// UT-RC-003: Wrong Key Fails Verification
// =============================================================================

/// Tests that verification fails with a different signer's public key.
#[test]
fn test_wrong_public_key_fails() {
    let signer_a = ReceiptSigner::generate(test_key_id("009a"), 1).expect("signer A generation");
    let signer_b = ReceiptSigner::generate(test_key_id("009b"), 1).expect("signer B generation");

    // Sign with signer A
    let receipt = make_test_receipt("wrong-key-001");
    let signed_receipt = signer_a.sign(receipt).expect("signing should succeed");

    // Try to verify with signer B's public key
    let result = verify_receipt(&signed_receipt, signer_b.verifying_key());

    assert!(
        matches!(result, Err(VerificationError::PublicKeyMismatch)),
        "wrong public key should fail verification"
    );
}

/// Tests that the embedded public key in `signer_identity` must match verifier.
#[test]
fn test_embedded_key_matches_verifier() {
    let signer = ReceiptSigner::generate(test_key_id("010"), 1).expect("signer generation");

    let receipt = make_test_receipt("embed-key-001");
    let signed_receipt = signer.sign(receipt).expect("signing should succeed");

    // Get the embedded public key from signer_identity
    let embedded_key = signed_receipt
        .signer_identity
        .as_ref()
        .expect("signer_identity should be present")
        .public_key;

    // Should match the signer's public key
    assert_eq!(
        embedded_key,
        signer.public_key_bytes(),
        "embedded key should match signer's public key"
    );

    // Verification with embedded key should succeed
    let result = verify_receipt_with_bytes(&signed_receipt, &embedded_key);
    assert!(result.is_ok());
}

// =============================================================================
// UT-RC-004: Signer Identity Matches
// =============================================================================

/// Tests that signer identity contains correct key ID and version.
#[test]
fn test_signer_identity_contains_key_info() {
    let key_id = test_key_id("011");
    let key_version = 42;
    let signer = ReceiptSigner::generate(key_id.clone(), key_version).expect("signer generation");

    let receipt = make_test_receipt("identity-001");
    let signed_receipt = signer.sign(receipt).expect("signing should succeed");

    let identity = signed_receipt
        .signer_identity
        .as_ref()
        .expect("signer_identity should be present");

    // Identity should contain key ID and version
    assert!(
        identity.identity.contains(key_id.as_str()),
        "identity should contain key ID"
    );
    assert!(
        identity.identity.contains(&format!("v{key_version}")),
        "identity should contain key version"
    );
}

/// Tests that signer identity is cryptographically bound to receipt.
#[test]
fn test_signer_identity_cryptographically_bound() {
    let signer = ReceiptSigner::generate(test_key_id("012"), 1).expect("signer generation");

    let receipt = make_test_receipt("bound-001");
    let mut signed_receipt = signer.sign(receipt).expect("signing should succeed");

    // Tamper with the signer identity
    signed_receipt.signer_identity =
        Some(SignerIdentity::new([0x00; 32], "fake-identity").expect("fake identity creation"));

    // Verification should fail because signer_identity is part of signed data
    let result = verify_receipt(&signed_receipt, signer.verifying_key());
    assert!(
        matches!(result, Err(VerificationError::PublicKeyMismatch)),
        "tampered signer identity should fail verification"
    );
}

/// Tests that unsigned receipt has no signer identity.
#[test]
fn test_unsigned_receipt_no_identity() {
    let receipt = make_test_receipt("unsigned-001");

    assert!(
        !receipt.is_signed(),
        "receipt should not be signed initially"
    );
    assert!(
        receipt.signature.is_none(),
        "unsigned receipt should have no signature"
    );
    assert!(
        receipt.signer_identity.is_none(),
        "unsigned receipt should have no signer identity"
    );
}

// =============================================================================
// UT-RC-005: Deterministic Signatures
// =============================================================================

/// Tests that Ed25519 signatures are deterministic.
#[test]
fn test_deterministic_signatures() {
    // Use fixed key bytes for determinism
    let key_bytes = [0x42u8; 32];
    let signer =
        ReceiptSigner::from_bytes(&key_bytes, test_key_id("013"), 1).expect("signer from bytes");

    // Sign the same receipt twice
    let receipt1 = make_test_receipt("determ-001");
    let receipt2 = make_test_receipt("determ-001");

    let signed1 = signer.sign(receipt1).expect("signing should succeed");
    let signed2 = signer.sign(receipt2).expect("signing should succeed");

    // Signatures should be identical for identical receipts
    assert_eq!(
        signed1.signature, signed2.signature,
        "Ed25519 signatures should be deterministic"
    );
}

/// Tests that different receipts produce different signatures.
#[test]
fn test_different_receipts_different_signatures() {
    let signer = ReceiptSigner::generate(test_key_id("014"), 1).expect("signer generation");

    let receipt1 = make_test_receipt("diff-001");
    let receipt2 = make_test_receipt("diff-002");

    let signed1 = signer.sign(receipt1).expect("signing should succeed");
    let signed2 = signer.sign(receipt2).expect("signing should succeed");

    // Different receipts should produce different signatures
    assert_ne!(
        signed1.signature, signed2.signature,
        "different receipts should produce different signatures"
    );
}

// =============================================================================
// UT-RC-006: Signing Already Signed Receipt Fails
// =============================================================================

/// Tests that attempting to sign an already signed receipt fails.
#[test]
fn test_sign_already_signed_fails() {
    let signer = ReceiptSigner::generate(test_key_id("015"), 1).expect("signer generation");

    let receipt = make_test_receipt("double-sign-001");
    let signed_receipt = signer.sign(receipt).expect("first signing should succeed");

    // Attempt to sign again
    let result = signer.sign(signed_receipt);
    assert!(
        matches!(result, Err(SignerError::Receipt(_))),
        "signing already signed receipt should fail"
    );
}

// =============================================================================
// UT-RC-007: Key Rotation Support
// =============================================================================

/// Tests that receipts signed with different key versions are distinguishable.
#[test]
fn test_key_version_distinguishable() {
    // Same key bytes, different versions
    let key_bytes = [0x42u8; 32];
    let signer_v1 =
        ReceiptSigner::from_bytes(&key_bytes, test_key_id("016"), 1).expect("signer v1");
    let signer_v2 =
        ReceiptSigner::from_bytes(&key_bytes, test_key_id("016"), 2).expect("signer v2");

    let receipt1 = make_test_receipt("version-001");
    let receipt2 = make_test_receipt("version-002");

    let signed1 = signer_v1.sign(receipt1).expect("signing should succeed");
    let signed2 = signer_v2.sign(receipt2).expect("signing should succeed");

    // Versions should be distinguishable in signer_identity
    let id1 = signed1.signer_identity.as_ref().unwrap();
    let id2 = signed2.signer_identity.as_ref().unwrap();

    assert!(id1.identity.contains("v1"));
    assert!(id2.identity.contains("v2"));
    assert_ne!(id1.identity, id2.identity);
}

/// Tests that old key can still verify old receipts.
#[test]
fn test_old_key_still_verifies() {
    // Simulate key rotation scenario
    let old_key_bytes = [0x42u8; 32];
    let new_key_bytes = [0x43u8; 32];

    let old_signer =
        ReceiptSigner::from_bytes(&old_key_bytes, test_key_id("017"), 1).expect("old signer");
    let new_signer =
        ReceiptSigner::from_bytes(&new_key_bytes, test_key_id("017"), 2).expect("new signer");

    // Sign receipt with old key
    let receipt = make_test_receipt("rotation-001");
    let signed_receipt = old_signer.sign(receipt).expect("signing should succeed");

    // Old key should still verify
    assert!(verify_receipt(&signed_receipt, old_signer.verifying_key()).is_ok());

    // New key should NOT verify old receipt (public key mismatch)
    let result = verify_receipt(&signed_receipt, new_signer.verifying_key());
    assert!(result.is_err());
}

// =============================================================================
// UT-RC-008: Verifier Public Key Extraction
// =============================================================================

/// Tests that verifier can work with public key bytes.
#[test]
fn test_verify_with_public_key_bytes() {
    let signer = ReceiptSigner::generate(test_key_id("018"), 1).expect("signer generation");

    // Get public key bytes
    let public_key_bytes = signer.public_key_bytes();

    // Sign and verify
    let receipt = make_test_receipt("pk-bytes-001");
    let signed_receipt = signer.sign(receipt).expect("signing should succeed");

    let result = verify_receipt_with_bytes(&signed_receipt, &public_key_bytes);
    assert!(result.is_ok());
}

/// Tests that self-signed verification works.
#[test]
fn test_verify_self_signed() {
    let signer = ReceiptSigner::generate(test_key_id("019"), 1).expect("signer generation");

    let receipt = make_test_receipt("self-signed-001");
    let signed_receipt = signer.sign(receipt).expect("signing should succeed");

    // Verify using embedded public key
    let result = verify_receipt_self_signed(&signed_receipt);
    assert!(result.is_ok());
}

// =============================================================================
// UT-RC-009: Unsigned Receipt Verification Fails
// =============================================================================

/// Tests that attempting to verify an unsigned receipt fails.
#[test]
fn test_verify_unsigned_receipt_fails() {
    let signer = ReceiptSigner::generate(test_key_id("020"), 1).expect("signer generation");

    // Create unsigned receipt
    let unsigned_receipt = make_test_receipt("unsigned-verify-001");

    // Verification should fail
    let result = verify_receipt(&unsigned_receipt, signer.verifying_key());
    assert!(
        matches!(result, Err(VerificationError::NotSigned)),
        "unsigned receipt verification should fail"
    );
}

/// Tests that `verify_receipt_self_signed` fails on unsigned receipt.
#[test]
fn test_verify_self_signed_unsigned_fails() {
    let unsigned_receipt = make_test_receipt("unsigned-self-001");

    let result = verify_receipt_self_signed(&unsigned_receipt);
    assert!(
        matches!(result, Err(VerificationError::NotSigned)),
        "unsigned receipt self-signed verification should fail"
    );
}
