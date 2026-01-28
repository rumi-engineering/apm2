//! Receipt verification implementation using Ed25519.
//!
//! This module implements the verification predicate for tool receipts
//! per AD-RECEIPT-001 and AD-VERIFY-001.
//!
//! # Architecture
//!
//! ```text
//! verify_receipt(receipt, public_key)
//!     |-- Check receipt has signature and signer_identity
//!     |-- Recompute canonical_bytes (includes signer_identity)
//!     |-- Verify signature against canonical_bytes using public_key
//!     `-- Return Ok(()) or VerificationError
//! ```
//!
//! # Security Model
//!
//! Per AD-RECEIPT-001 and AD-VERIFY-001:
//! - Signature verification uses Ed25519 (ed25519-dalek)
//! - `canonical_bytes()` INCLUDES `signer_identity` for cryptographic binding
//! - Verification is constant-time via ed25519-dalek
//! - Tampered receipts fail verification
//!
//! # Contract References
//!
//! - AD-RECEIPT-001: Tool receipt generation
//! - AD-VERIFY-001: Deterministic serialization
//! - CTR-1909: Constant-time operations for sensitive comparisons

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use thiserror::Error;

use super::receipt::{ReceiptError, ToolReceipt};

// =============================================================================
// VerificationError
// =============================================================================

/// Errors that can occur during receipt verification.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerificationError {
    /// Receipt is not signed.
    #[error("receipt is not signed")]
    NotSigned,

    /// Receipt signature is invalid.
    #[error("signature verification failed")]
    InvalidSignature,

    /// Public key does not match signer identity.
    #[error("public key mismatch: provided key does not match signer identity")]
    PublicKeyMismatch,

    /// Invalid signature bytes (wrong length).
    #[error("invalid signature bytes: expected 64 bytes, got {len}")]
    InvalidSignatureBytes {
        /// Actual length.
        len: usize,
    },

    /// Invalid public key bytes.
    #[error("invalid public key bytes: {0}")]
    InvalidPublicKey(String),

    /// Receipt validation failed.
    #[error("receipt validation failed: {0}")]
    ReceiptValidation(#[from] ReceiptError),

    /// Hash mismatch between stored and computed digest.
    #[error("unsigned_bytes_hash mismatch: receipt may have been tampered")]
    DigestMismatch,
}

// =============================================================================
// Verification Functions
// =============================================================================

/// Verifies a signed receipt using the provided public key.
///
/// This function performs the following checks:
/// 1. Receipt has a signature and signer identity
/// 2. Provided public key matches the signer identity's public key
/// 3. Ed25519 signature is valid over the canonical bytes
///
/// # Arguments
///
/// * `receipt` - The signed receipt to verify
/// * `public_key` - The Ed25519 public key to verify against
///
/// # Errors
///
/// Returns an error if:
/// - Receipt is not signed
/// - Public key doesn't match signer identity
/// - Signature is invalid
///
/// # Example
///
/// ```rust,ignore
/// use apm2_daemon::evidence::{verify_receipt, ReceiptSigner, KeyId};
///
/// let signer = ReceiptSigner::generate(KeyId::new("test-key")?, 1)?;
/// let receipt = /* ... build receipt ... */;
/// let signed = signer.sign(receipt)?;
///
/// // Verify with the signer's public key
/// verify_receipt(&signed, signer.verifying_key())?;
/// ```
pub fn verify_receipt(
    receipt: &ToolReceipt,
    public_key: &VerifyingKey,
) -> Result<(), VerificationError> {
    // Check that receipt is signed
    let signature_bytes = receipt.signature.ok_or(VerificationError::NotSigned)?;
    let signer_identity = receipt
        .signer_identity
        .as_ref()
        .ok_or(VerificationError::NotSigned)?;

    // Verify public key matches signer identity
    if public_key.as_bytes() != &signer_identity.public_key {
        return Err(VerificationError::PublicKeyMismatch);
    }

    // Convert signature bytes to Signature type
    let signature = Signature::from_bytes(&signature_bytes);

    // Get the bytes that were signed (canonical_bytes includes signer_identity)
    let signed_bytes = receipt.unsigned_bytes();

    // Verify signature using ed25519-dalek (constant-time)
    public_key
        .verify(&signed_bytes, &signature)
        .map_err(|_| VerificationError::InvalidSignature)
}

/// Verifies a signed receipt using public key bytes.
///
/// This is a convenience wrapper around `verify_receipt` that accepts
/// raw public key bytes instead of a `VerifyingKey`.
///
/// # Arguments
///
/// * `receipt` - The signed receipt to verify
/// * `public_key_bytes` - The 32-byte Ed25519 public key
///
/// # Errors
///
/// Returns an error if verification fails.
pub fn verify_receipt_with_bytes(
    receipt: &ToolReceipt,
    public_key_bytes: &[u8; 32],
) -> Result<(), VerificationError> {
    let public_key = VerifyingKey::from_bytes(public_key_bytes)
        .map_err(|e| VerificationError::InvalidPublicKey(e.to_string()))?;
    verify_receipt(receipt, &public_key)
}

/// Verifies a receipt's integrity without checking the signature.
///
/// This performs a lightweight check that:
/// 1. The `unsigned_bytes_hash` matches the computed digest
/// 2. The receipt validates structurally
///
/// This is useful for checking receipt integrity before signature
/// verification, or when signature verification is deferred.
///
/// # Arguments
///
/// * `receipt` - The receipt to verify
///
/// # Errors
///
/// Returns an error if the digest doesn't match or validation fails.
pub fn verify_receipt_integrity(receipt: &ToolReceipt) -> Result<(), VerificationError> {
    // Compute the digest and compare
    let computed_digest = receipt.digest();
    if computed_digest != receipt.unsigned_bytes_hash {
        return Err(VerificationError::DigestMismatch);
    }

    // Run structural validation (this also checks the hash)
    receipt
        .validate()
        .map_err(VerificationError::ReceiptValidation)
}

/// Verification result for batch verification.
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// Index of the receipt in the batch.
    pub index: usize,
    /// Result of verification.
    pub result: Result<(), VerificationError>,
}

/// Verifies multiple receipts in a batch.
///
/// This verifies each receipt against its embedded public key
/// (from `signer_identity`). This is useful for verifying a set
/// of receipts from potentially different signers.
///
/// # Arguments
///
/// * `receipts` - The receipts to verify
///
/// # Returns
///
/// A vector of verification results, one per receipt.
pub fn verify_receipts_batch(receipts: &[ToolReceipt]) -> Vec<VerificationResult> {
    receipts
        .iter()
        .enumerate()
        .map(|(index, receipt)| {
            let result = verify_receipt_self_signed(receipt);
            VerificationResult { index, result }
        })
        .collect()
}

/// Verifies a receipt using its embedded public key.
///
/// This extracts the public key from the receipt's `signer_identity`
/// and verifies the signature against it. This is useful when you
/// trust the public key registry lookup separately.
///
/// # Arguments
///
/// * `receipt` - The signed receipt to verify
///
/// # Errors
///
/// Returns an error if verification fails.
pub fn verify_receipt_self_signed(receipt: &ToolReceipt) -> Result<(), VerificationError> {
    // Get signer identity
    let signer_identity = receipt
        .signer_identity
        .as_ref()
        .ok_or(VerificationError::NotSigned)?;

    // Construct public key from embedded bytes
    let public_key = VerifyingKey::from_bytes(&signer_identity.public_key)
        .map_err(|e| VerificationError::InvalidPublicKey(e.to_string()))?;

    verify_receipt(receipt, &public_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::episode::EpisodeId;
    use crate::evidence::receipt::{SignerIdentity, ToolExecutionDetails};
    use crate::evidence::receipt_builder::ReceiptBuilder;
    use crate::evidence::signer::{KeyId, ReceiptSigner};

    fn make_test_receipt() -> ToolReceipt {
        ReceiptBuilder::for_tool_execution(EpisodeId::new("ep-test-001").unwrap())
            .with_envelope([0xaa; 32])
            .with_policy([0xbb; 32])
            .with_evidence(vec![[0xcc; 32]])
            .with_timestamp(1_704_067_200_000_000_000)
            .with_details(ToolExecutionDetails {
                request_id: "req-001".to_string(),
                capability_id: "cap-read".to_string(),
                args_hash: [0x11; 32],
                result_hash: [0x22; 32],
                success: true,
                result_message: Some("completed".to_string()),
                duration_ns: 100_000_000,
            })
            .build()
            .unwrap()
    }

    #[test]
    fn test_verify_valid_receipt() {
        let receipt_signer = ReceiptSigner::generate(KeyId::new("test-key").unwrap(), 1).unwrap();
        let receipt = make_test_receipt();
        let signed_receipt = receipt_signer.sign(receipt).unwrap();

        // Verify with the correct public key
        let result = verify_receipt(&signed_receipt, receipt_signer.verifying_key());
        assert!(result.is_ok(), "Valid receipt should verify: {result:?}");
    }

    #[test]
    fn test_verify_unsigned_receipt_fails() {
        let receipt = make_test_receipt();
        let receipt_signer = ReceiptSigner::generate(KeyId::new("test-key").unwrap(), 1).unwrap();

        let result = verify_receipt(&receipt, receipt_signer.verifying_key());
        assert!(matches!(result, Err(VerificationError::NotSigned)));
    }

    #[test]
    fn test_verify_wrong_key_fails() {
        let receipt_signer_a = ReceiptSigner::generate(KeyId::new("key-1").unwrap(), 1).unwrap();
        let receipt_signer_b = ReceiptSigner::generate(KeyId::new("key-2").unwrap(), 1).unwrap();

        let receipt = make_test_receipt();
        let signed_receipt = receipt_signer_a.sign(receipt).unwrap();

        // Verify with the WRONG public key
        let result = verify_receipt(&signed_receipt, receipt_signer_b.verifying_key());
        assert!(
            matches!(result, Err(VerificationError::PublicKeyMismatch)),
            "Wrong key should fail with PublicKeyMismatch: {result:?}"
        );
    }

    #[test]
    fn test_verify_tampered_signature_fails() {
        let receipt_signer = ReceiptSigner::generate(KeyId::new("test-key").unwrap(), 1).unwrap();
        let receipt = make_test_receipt();
        let mut signed_receipt = receipt_signer.sign(receipt).unwrap();

        // Tamper with the signature
        if let Some(ref mut sig) = signed_receipt.signature {
            sig[0] ^= 0xff; // Flip some bits
        }

        let result = verify_receipt(&signed_receipt, receipt_signer.verifying_key());
        assert!(
            matches!(result, Err(VerificationError::InvalidSignature)),
            "Tampered signature should fail: {result:?}"
        );
    }

    #[test]
    fn test_verify_tampered_envelope_hash_fails() {
        let receipt_signer = ReceiptSigner::generate(KeyId::new("test-key").unwrap(), 1).unwrap();
        let receipt = make_test_receipt();
        let mut signed_receipt = receipt_signer.sign(receipt).unwrap();

        // Tamper with the envelope hash
        signed_receipt.envelope_hash[0] ^= 0xff;

        let result = verify_receipt(&signed_receipt, receipt_signer.verifying_key());
        assert!(
            matches!(result, Err(VerificationError::InvalidSignature)),
            "Tampered envelope should fail: {result:?}"
        );
    }

    #[test]
    fn test_verify_tampered_timestamp_fails() {
        let receipt_signer = ReceiptSigner::generate(KeyId::new("test-key").unwrap(), 1).unwrap();
        let receipt = make_test_receipt();
        let mut signed_receipt = receipt_signer.sign(receipt).unwrap();

        // Tamper with the timestamp
        signed_receipt.timestamp_ns = 999_999_999;

        let result = verify_receipt(&signed_receipt, receipt_signer.verifying_key());
        assert!(
            matches!(result, Err(VerificationError::InvalidSignature)),
            "Tampered timestamp should fail: {result:?}"
        );
    }

    #[test]
    fn test_verify_tampered_signer_identity_fails() {
        let receipt_signer = ReceiptSigner::generate(KeyId::new("test-key").unwrap(), 1).unwrap();
        let receipt = make_test_receipt();
        let mut signed_receipt = receipt_signer.sign(receipt).unwrap();

        // Tamper with the signer identity string
        if let Some(ref mut identity) = signed_receipt.signer_identity {
            identity.identity = "tampered-signer".to_string();
        }

        let result = verify_receipt(&signed_receipt, receipt_signer.verifying_key());
        assert!(
            matches!(result, Err(VerificationError::InvalidSignature)),
            "Tampered signer identity should fail: {result:?}"
        );
    }

    #[test]
    fn test_verify_receipt_with_bytes() {
        let receipt_signer = ReceiptSigner::generate(KeyId::new("test-key").unwrap(), 1).unwrap();
        let receipt = make_test_receipt();
        let signed_receipt = receipt_signer.sign(receipt).unwrap();

        // Verify using raw public key bytes
        let public_key_bytes = receipt_signer.public_key_bytes();
        let result = verify_receipt_with_bytes(&signed_receipt, &public_key_bytes);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_receipt_self_signed() {
        let receipt_signer = ReceiptSigner::generate(KeyId::new("test-key").unwrap(), 1).unwrap();
        let receipt = make_test_receipt();
        let signed_receipt = receipt_signer.sign(receipt).unwrap();

        // Verify using embedded public key
        let result = verify_receipt_self_signed(&signed_receipt);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_receipt_integrity() {
        let receipt = make_test_receipt();

        // Valid receipt should pass integrity check
        assert!(verify_receipt_integrity(&receipt).is_ok());

        // Tampered receipt should fail
        let mut tampered = receipt;
        tampered.envelope_hash[0] ^= 0xff;
        assert!(matches!(
            verify_receipt_integrity(&tampered),
            Err(VerificationError::DigestMismatch)
        ));
    }

    #[test]
    fn test_verify_receipts_batch() {
        let receipt_signer = ReceiptSigner::generate(KeyId::new("test-key").unwrap(), 1).unwrap();

        let receipt_a = make_test_receipt();
        let receipt_b = make_test_receipt();
        let receipt_c = make_test_receipt();

        let signed_a = receipt_signer.sign(receipt_a).unwrap();
        let signed_b = receipt_signer.sign(receipt_b).unwrap();
        let mut signed_c_tampered = receipt_signer.sign(receipt_c).unwrap();
        signed_c_tampered.envelope_hash[0] ^= 0xff; // Tamper

        let results = verify_receipts_batch(&[signed_a, signed_b, signed_c_tampered]);

        assert_eq!(results.len(), 3);
        assert!(results[0].result.is_ok());
        assert!(results[1].result.is_ok());
        assert!(matches!(
            results[2].result,
            Err(VerificationError::InvalidSignature)
        ));
    }

    #[test]
    fn test_public_key_replacement_attack_fails() {
        // This tests that an attacker cannot replace the public key
        // in signer_identity to make a forgery verify

        let victim = ReceiptSigner::generate(KeyId::new("victim").unwrap(), 1).unwrap();
        let attacker = ReceiptSigner::generate(KeyId::new("attacker").unwrap(), 1).unwrap();

        // Victim signs a receipt
        let receipt = make_test_receipt();
        let signed_by_victim = victim.sign(receipt).unwrap();

        // Attacker tries to replace the public key with their own
        let mut forged = signed_by_victim;
        forged.signer_identity = Some(SignerIdentity {
            public_key: attacker.public_key_bytes(),
            identity: "attacker:v1".to_string(),
        });

        // Verification with attacker's key should fail because
        // the signature was computed over the ORIGINAL signer_identity
        let result = verify_receipt(&forged, attacker.verifying_key());
        assert!(
            matches!(result, Err(VerificationError::InvalidSignature)),
            "Public key replacement attack should fail: {result:?}"
        );

        // Verification with victim's key should fail because
        // the public key in signer_identity doesn't match
        let result = verify_receipt(&forged, victim.verifying_key());
        assert!(
            matches!(result, Err(VerificationError::PublicKeyMismatch)),
            "Public key mismatch should be detected: {result:?}"
        );
    }
}
