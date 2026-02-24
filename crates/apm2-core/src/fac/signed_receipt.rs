// AGENT-AUTHORED (RFC-0032::REQ-0226)
//! Signed receipt envelope: Ed25519 signature over receipt payload digest.
//!
//! This module implements [`SignedReceiptEnvelopeV1`], a signed container
//! that wraps any content-addressed receipt (identified by its BLAKE3
//! digest) with an Ed25519 signature and signer identity. This is the A3
//! mitigation that makes "receipts are ground truth" true under realistic
//! local threat models.
//!
//! # Design
//!
//! Rather than modifying existing receipt types (which would break
//! content-addressed storage and ledger references), this envelope wraps
//! receipts externally. The envelope signs over the `payload_digest` (the
//! receipt's content hash) using domain-separated Ed25519, binding the
//! receipt content to a specific signer.
//!
//! # Storage
//!
//! Signed envelopes are stored alongside receipts in the receipt store:
//! `$APM2_HOME/private/fac/receipts/<payload_digest>.sig.json`
//!
//! # Verification
//!
//! Verification requires:
//! 1. The signed envelope file exists for the receipt
//! 2. The `payload_digest` in the envelope matches the receipt's content hash
//! 3. The Ed25519 signature verifies against the broker's verifying key
//!
//! # Security Invariants
//!
//! - [INV-SR-001] Missing or unverifiable signatures cause fail-closed denial
//!   for gate-cache reuse decisions.
//! - [INV-SR-002] Signature verification uses constant-time comparison via
//!   domain-separated Ed25519 (no timing side channels).
//! - [INV-SR-003] Envelope reads are bounded by `MAX_SIGNED_ENVELOPE_SIZE`
//!   before deserialization.
//! - [INV-SR-004] All string fields are bounded during validation.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::domain_separator::{
    SIGNED_RECEIPT_ENVELOPE_PREFIX, sign_with_domain, verify_with_domain,
};
use crate::crypto::{Signature, Signer, VerifyingKey};

// =============================================================================
// Constants
// =============================================================================

/// Schema identifier for signed receipt envelopes.
pub const SIGNED_RECEIPT_ENVELOPE_SCHEMA: &str = "apm2.fac.signed_receipt_envelope.v1";

/// Domain prefix for signed receipt envelope signatures.
///
/// Re-exported from `domain_separator` for convenience. This is distinct
/// from `GATE_RECEIPT_PREFIX` to prevent cross-type signature confusion.
pub const SIGNED_RECEIPT_PREFIX: &[u8] = SIGNED_RECEIPT_ENVELOPE_PREFIX;

/// Maximum serialized size of a signed receipt envelope (bytes).
/// Protects against memory-exhaustion attacks during bounded deserialization.
pub const MAX_SIGNED_ENVELOPE_SIZE: usize = 8_192;

/// Maximum length for `signer_id` field.
const MAX_SIGNER_ID_LENGTH: usize = 256;

/// Maximum length for `payload_digest` field.
const MAX_PAYLOAD_DIGEST_LENGTH: usize = 256;

/// File extension for signed receipt envelope files.
const SIGNED_ENVELOPE_EXTENSION: &str = ".sig.json";

// =============================================================================
// Error Types
// =============================================================================

/// Errors from signed receipt envelope operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignedReceiptError {
    /// Signature verification failed.
    #[error("signature verification failed: {0}")]
    InvalidSignature(String),

    /// Missing signed envelope for a receipt.
    #[error("no signed envelope found for receipt: {0}")]
    MissingEnvelope(String),

    /// Payload digest mismatch between envelope and receipt.
    #[error("payload digest mismatch: envelope has {envelope}, receipt has {receipt}")]
    PayloadDigestMismatch {
        /// Digest in the envelope.
        envelope: String,
        /// Digest from the actual receipt.
        receipt: String,
    },

    /// Schema mismatch.
    #[error("schema mismatch: expected {expected}, found {actual}")]
    SchemaMismatch {
        /// Expected schema.
        expected: String,
        /// Actual schema.
        actual: String,
    },

    /// String field exceeds maximum length.
    #[error("field {field} exceeds max length: {actual} > {max}")]
    StringTooLong {
        /// Field name.
        field: &'static str,
        /// Actual length.
        actual: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// Envelope data too large.
    #[error("envelope too large: {size} > {max}")]
    EnvelopeTooLarge {
        /// Actual size.
        size: usize,
        /// Maximum allowed size.
        max: usize,
    },

    /// Deserialization failure.
    #[error("envelope deserialization failed: {0}")]
    Deserialization(String),

    /// I/O error.
    #[error("i/o error: {0}")]
    Io(String),
}

// =============================================================================
// Signed Receipt Envelope
// =============================================================================

/// Signed container for a content-addressed receipt.
///
/// The envelope cryptographically binds a receipt (identified by its
/// BLAKE3 content hash) to a specific signer using domain-separated
/// Ed25519 signatures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedReceiptEnvelopeV1 {
    /// Schema identifier.
    pub schema: String,

    /// BLAKE3 content hash of the receipt payload (e.g., `b3-256:<64hex>`).
    pub payload_digest: String,

    /// Hex-encoded Ed25519 signature over canonical bytes.
    pub signature_hex: String,

    /// Human-readable signer identity (e.g., `fac-broker`).
    pub signer_id: String,

    /// Hex-encoded Ed25519 verifying key bytes (32 bytes = 64 hex chars).
    pub signer_public_key_hex: String,
}

impl SignedReceiptEnvelopeV1 {
    /// Returns the canonical bytes for signing/verification.
    ///
    /// The canonical representation includes `schema`, `payload_digest`,
    /// and `signer_id` in deterministic order with length-prefixed encoding.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let capacity = 4
            + self.schema.len()
            + 4
            + self.payload_digest.len()
            + 4
            + self.signer_id.len()
            + 4
            + self.signer_public_key_hex.len();

        let mut bytes = Vec::with_capacity(capacity);

        // 1. schema (length-prefixed)
        bytes.extend_from_slice(&(self.schema.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.schema.as_bytes());

        // 2. payload_digest (length-prefixed)
        bytes.extend_from_slice(&(self.payload_digest.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.payload_digest.as_bytes());

        // 3. signer_id (length-prefixed)
        bytes.extend_from_slice(&(self.signer_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.signer_id.as_bytes());

        // 4. signer_public_key_hex (length-prefixed)
        bytes.extend_from_slice(&(self.signer_public_key_hex.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.signer_public_key_hex.as_bytes());

        bytes
    }

    /// Verify the envelope signature against the provided verifying key.
    ///
    /// # Errors
    ///
    /// Returns [`SignedReceiptError::InvalidSignature`] if:
    /// - The signature hex cannot be decoded
    /// - The signature does not verify against the key
    pub fn verify_signature(&self, verifying_key: &VerifyingKey) -> Result<(), SignedReceiptError> {
        let sig_bytes = hex::decode(&self.signature_hex).map_err(|e| {
            SignedReceiptError::InvalidSignature(format!("invalid signature hex: {e}"))
        })?;

        if sig_bytes.len() != 64 {
            return Err(SignedReceiptError::InvalidSignature(format!(
                "signature length {} != 64",
                sig_bytes.len()
            )));
        }

        let mut sig_array = [0u8; 64];
        sig_array.copy_from_slice(&sig_bytes);
        let signature = Signature::from_bytes(&sig_array);
        let canonical = self.canonical_bytes();

        verify_with_domain(verifying_key, SIGNED_RECEIPT_PREFIX, &canonical, &signature)
            .map_err(|e| SignedReceiptError::InvalidSignature(e.to_string()))
    }

    /// Validate structural constraints on the envelope.
    ///
    /// # Errors
    ///
    /// Returns [`SignedReceiptError`] if schema, field lengths, or format
    /// constraints are violated.
    pub fn validate(&self) -> Result<(), SignedReceiptError> {
        if self.schema != SIGNED_RECEIPT_ENVELOPE_SCHEMA {
            return Err(SignedReceiptError::SchemaMismatch {
                expected: SIGNED_RECEIPT_ENVELOPE_SCHEMA.to_string(),
                actual: self.schema.clone(),
            });
        }

        if self.payload_digest.len() > MAX_PAYLOAD_DIGEST_LENGTH {
            return Err(SignedReceiptError::StringTooLong {
                field: "payload_digest",
                actual: self.payload_digest.len(),
                max: MAX_PAYLOAD_DIGEST_LENGTH,
            });
        }

        if self.payload_digest.is_empty() {
            return Err(SignedReceiptError::Deserialization(
                "payload_digest is empty".to_string(),
            ));
        }

        if self.signer_id.len() > MAX_SIGNER_ID_LENGTH {
            return Err(SignedReceiptError::StringTooLong {
                field: "signer_id",
                actual: self.signer_id.len(),
                max: MAX_SIGNER_ID_LENGTH,
            });
        }

        if self.signer_id.is_empty() {
            return Err(SignedReceiptError::Deserialization(
                "signer_id is empty".to_string(),
            ));
        }

        if self.signature_hex.is_empty() {
            return Err(SignedReceiptError::Deserialization(
                "signature_hex is empty".to_string(),
            ));
        }

        // Ed25519 signature is 64 bytes = 128 hex chars
        if self.signature_hex.len() != 128 {
            return Err(SignedReceiptError::InvalidSignature(format!(
                "signature_hex length {} != 128",
                self.signature_hex.len()
            )));
        }

        // Verifying key is 32 bytes = 64 hex chars
        if self.signer_public_key_hex.len() != 64 {
            return Err(SignedReceiptError::InvalidSignature(format!(
                "signer_public_key_hex length {} != 64",
                self.signer_public_key_hex.len()
            )));
        }

        Ok(())
    }
}

// =============================================================================
// Signing
// =============================================================================

/// Sign a receipt payload digest, producing a `SignedReceiptEnvelopeV1`.
///
/// # Arguments
///
/// * `payload_digest` - The receipt's content hash (e.g., `b3-256:<64hex>`)
/// * `signer` - The Ed25519 signer (broker key)
/// * `signer_id` - Human-readable signer identity
#[must_use]
pub fn sign_receipt(
    payload_digest: &str,
    signer: &Signer,
    signer_id: &str,
) -> SignedReceiptEnvelopeV1 {
    let vk = signer.verifying_key();
    let vk_hex = hex::encode(vk.as_bytes());

    let envelope = SignedReceiptEnvelopeV1 {
        schema: SIGNED_RECEIPT_ENVELOPE_SCHEMA.to_string(),
        payload_digest: payload_digest.to_string(),
        // Placeholder -- will be overwritten after computing canonical bytes
        signature_hex: String::new(),
        signer_id: signer_id.to_string(),
        signer_public_key_hex: vk_hex,
    };

    // Compute canonical bytes and sign
    let canonical = envelope.canonical_bytes();
    let signature = sign_with_domain(signer, SIGNED_RECEIPT_PREFIX, &canonical);
    let signature_hex = hex::encode(signature.to_bytes());

    SignedReceiptEnvelopeV1 {
        signature_hex,
        ..envelope
    }
}

// =============================================================================
// Persistence
// =============================================================================

/// Compute the signed envelope file path for a given receipt content hash.
///
/// Returns `<receipts_dir>/<content_hash>.sig.json`.
#[must_use]
pub fn signed_envelope_path(receipts_dir: &Path, content_hash: &str) -> PathBuf {
    receipts_dir.join(format!("{content_hash}{SIGNED_ENVELOPE_EXTENSION}"))
}

/// Persist a signed receipt envelope alongside its receipt.
///
/// Uses atomic temp + rename for crash safety.
///
/// # Errors
///
/// Returns [`SignedReceiptError::Io`] on filesystem errors.
/// Returns [`SignedReceiptError::Deserialization`] on serialization errors.
pub fn persist_signed_envelope(
    receipts_dir: &Path,
    envelope: &SignedReceiptEnvelopeV1,
) -> Result<PathBuf, SignedReceiptError> {
    let final_path = signed_envelope_path(receipts_dir, &envelope.payload_digest);
    let temp_path = receipts_dir.join(format!(
        "{}{SIGNED_ENVELOPE_EXTENSION}.tmp",
        &envelope.payload_digest
    ));

    let body = serde_json::to_vec_pretty(envelope).map_err(|e| {
        SignedReceiptError::Deserialization(format!("cannot serialize signed envelope: {e}"))
    })?;

    let mut file = fs::File::create(&temp_path)
        .map_err(|e| SignedReceiptError::Io(format!("cannot create temp file: {e}")))?;
    file.write_all(&body)
        .map_err(|e| SignedReceiptError::Io(format!("cannot write temp file: {e}")))?;
    file.sync_all()
        .map_err(|e| SignedReceiptError::Io(format!("cannot fsync temp file: {e}")))?;
    drop(file);

    fs::rename(&temp_path, &final_path).map_err(|e| {
        SignedReceiptError::Io(format!(
            "cannot rename {} to {}: {e}",
            temp_path.display(),
            final_path.display()
        ))
    })?;

    Ok(final_path)
}

/// Load and validate a signed receipt envelope from disk.
///
/// # Errors
///
/// Returns [`SignedReceiptError`] if the file is missing, too large,
/// malformed, or fails structural validation.
pub fn load_signed_envelope(
    receipts_dir: &Path,
    content_hash: &str,
) -> Result<SignedReceiptEnvelopeV1, SignedReceiptError> {
    let path = signed_envelope_path(receipts_dir, content_hash);

    if !path.exists() {
        return Err(SignedReceiptError::MissingEnvelope(
            content_hash.to_string(),
        ));
    }

    // INV-SR-003: Bounded read before deserialization.
    let metadata = fs::metadata(&path)
        .map_err(|e| SignedReceiptError::Io(format!("cannot stat {}: {e}", path.display())))?;
    // Compare as u64 to avoid truncation warnings; the error struct
    // wants usize but the file_len is guaranteed to exceed the max at
    // this point, so the (saturating) truncation is harmless in the
    // error branch.
    let file_len = metadata.len();
    #[allow(clippy::cast_possible_truncation)]
    if file_len > MAX_SIGNED_ENVELOPE_SIZE as u64 {
        return Err(SignedReceiptError::EnvelopeTooLarge {
            size: file_len as usize,
            max: MAX_SIGNED_ENVELOPE_SIZE,
        });
    }

    let data = fs::read(&path)
        .map_err(|e| SignedReceiptError::Io(format!("cannot read {}: {e}", path.display())))?;

    deserialize_signed_envelope(&data)
}

/// Deserialize and validate a signed receipt envelope from bytes.
///
/// # Errors
///
/// Returns [`SignedReceiptError`] if the data exceeds size limits,
/// fails JSON parsing, or fails structural validation.
pub fn deserialize_signed_envelope(
    data: &[u8],
) -> Result<SignedReceiptEnvelopeV1, SignedReceiptError> {
    if data.len() > MAX_SIGNED_ENVELOPE_SIZE {
        return Err(SignedReceiptError::EnvelopeTooLarge {
            size: data.len(),
            max: MAX_SIGNED_ENVELOPE_SIZE,
        });
    }

    let envelope: SignedReceiptEnvelopeV1 = serde_json::from_slice(data)
        .map_err(|e| SignedReceiptError::Deserialization(e.to_string()))?;

    envelope.validate()?;
    Ok(envelope)
}

// =============================================================================
// Verification helpers
// =============================================================================

/// Verify a signed receipt envelope against a verifying key and expected
/// content hash.
///
/// Performs full validation:
/// 1. Structural validation (schema, field bounds)
/// 2. Payload digest match against expected content hash
/// 3. Ed25519 signature verification
///
/// # Errors
///
/// Returns [`SignedReceiptError`] if any validation step fails.
pub fn verify_receipt_signature(
    envelope: &SignedReceiptEnvelopeV1,
    expected_content_hash: &str,
    verifying_key: &VerifyingKey,
) -> Result<(), SignedReceiptError> {
    // 1. Structural validation
    envelope.validate()?;

    // 2. Payload digest binding
    if envelope.payload_digest != expected_content_hash {
        return Err(SignedReceiptError::PayloadDigestMismatch {
            envelope: envelope.payload_digest.clone(),
            receipt: expected_content_hash.to_string(),
        });
    }

    // 3. Signature verification
    envelope.verify_signature(verifying_key)
}

/// Load a signed envelope from disk and verify it against a verifying key
/// and expected content hash.
///
/// Convenience function that combines `load_signed_envelope` and
/// `verify_receipt_signature`.
///
/// # Errors
///
/// Returns [`SignedReceiptError`] if loading or verification fails.
pub fn load_and_verify_receipt_signature(
    receipts_dir: &Path,
    content_hash: &str,
    verifying_key: &VerifyingKey,
) -> Result<SignedReceiptEnvelopeV1, SignedReceiptError> {
    let envelope = load_signed_envelope(receipts_dir, content_hash)?;
    verify_receipt_signature(&envelope, content_hash, verifying_key)?;
    Ok(envelope)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_signer() -> Signer {
        Signer::generate()
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let signer = make_test_signer();
        let digest = "b3-256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

        let envelope = sign_receipt(digest, &signer, "test-broker");

        assert_eq!(envelope.schema, SIGNED_RECEIPT_ENVELOPE_SCHEMA);
        assert_eq!(envelope.payload_digest, digest);
        assert_eq!(envelope.signer_id, "test-broker");
        assert_eq!(envelope.signature_hex.len(), 128);
        assert_eq!(envelope.signer_public_key_hex.len(), 64);

        // Verification succeeds
        assert!(verify_receipt_signature(&envelope, digest, &signer.verifying_key()).is_ok());
    }

    #[test]
    fn wrong_key_fails_verification() {
        let signer1 = make_test_signer();
        let signer2 = make_test_signer();
        let digest = "b3-256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

        let envelope = sign_receipt(digest, &signer1, "broker-1");

        let result = verify_receipt_signature(&envelope, digest, &signer2.verifying_key());
        assert!(matches!(
            result,
            Err(SignedReceiptError::InvalidSignature(_))
        ));
    }

    #[test]
    fn wrong_digest_fails_verification() {
        let signer = make_test_signer();
        let digest = "b3-256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let wrong = "b3-256:0000000000000000000000000000000000000000000000000000000000000000";

        let envelope = sign_receipt(digest, &signer, "broker");

        let result = verify_receipt_signature(&envelope, wrong, &signer.verifying_key());
        assert!(matches!(
            result,
            Err(SignedReceiptError::PayloadDigestMismatch { .. })
        ));
    }

    #[test]
    fn tampered_signature_fails() {
        let signer = make_test_signer();
        let digest = "b3-256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

        let mut envelope = sign_receipt(digest, &signer, "broker");
        // Tamper with signature
        let mut chars: Vec<char> = envelope.signature_hex.chars().collect();
        chars[0] = if chars[0] == 'a' { 'b' } else { 'a' };
        envelope.signature_hex = chars.into_iter().collect();

        let result = verify_receipt_signature(&envelope, digest, &signer.verifying_key());
        assert!(matches!(
            result,
            Err(SignedReceiptError::InvalidSignature(_))
        ));
    }

    #[test]
    fn unsigned_receipt_detected() {
        let dir = tempfile::tempdir().unwrap();
        let digest = "b3-256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

        let result = load_signed_envelope(dir.path(), digest);
        assert!(matches!(
            result,
            Err(SignedReceiptError::MissingEnvelope(_))
        ));
    }

    #[test]
    fn persist_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let signer = make_test_signer();
        let digest = "b3-256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

        let envelope = sign_receipt(digest, &signer, "test-broker");
        persist_signed_envelope(dir.path(), &envelope).unwrap();

        let loaded = load_signed_envelope(dir.path(), digest).unwrap();
        assert_eq!(loaded.payload_digest, digest);
        assert_eq!(loaded.signer_id, "test-broker");

        // Verify loaded envelope
        assert!(verify_receipt_signature(&loaded, digest, &signer.verifying_key()).is_ok());
    }

    #[test]
    fn oversized_envelope_rejected() {
        let data = vec![b' '; MAX_SIGNED_ENVELOPE_SIZE + 1];
        let result = deserialize_signed_envelope(&data);
        assert!(matches!(
            result,
            Err(SignedReceiptError::EnvelopeTooLarge { .. })
        ));
    }

    #[test]
    fn empty_signer_id_rejected() {
        let envelope = SignedReceiptEnvelopeV1 {
            schema: SIGNED_RECEIPT_ENVELOPE_SCHEMA.to_string(),
            payload_digest:
                "b3-256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
                    .to_string(),
            signature_hex: "a".repeat(128),
            signer_id: String::new(),
            signer_public_key_hex: "b".repeat(64),
        };
        let result = envelope.validate();
        assert!(matches!(
            result,
            Err(SignedReceiptError::Deserialization(_))
        ));
    }

    #[test]
    fn schema_mismatch_rejected() {
        let envelope = SignedReceiptEnvelopeV1 {
            schema: "wrong.schema".to_string(),
            payload_digest:
                "b3-256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
                    .to_string(),
            signature_hex: "a".repeat(128),
            signer_id: "broker".to_string(),
            signer_public_key_hex: "b".repeat(64),
        };
        let result = envelope.validate();
        assert!(matches!(
            result,
            Err(SignedReceiptError::SchemaMismatch { .. })
        ));
    }

    #[test]
    fn deterministic_signatures() {
        let signer = make_test_signer();
        let digest = "b3-256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

        let env1 = sign_receipt(digest, &signer, "broker");
        let env2 = sign_receipt(digest, &signer, "broker");

        // Ed25519 is deterministic
        assert_eq!(env1.signature_hex, env2.signature_hex);
    }

    #[test]
    fn different_digests_produce_different_signatures() {
        let signer = make_test_signer();
        let d1 = "b3-256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let d2 = "b3-256:0000000000000000000000000000000000000000000000000000000000000000";

        let env1 = sign_receipt(d1, &signer, "broker");
        let env2 = sign_receipt(d2, &signer, "broker");

        assert_ne!(env1.signature_hex, env2.signature_hex);
    }
}
