//! Receipt signing implementation using Ed25519.
//!
//! This module implements the `ReceiptSigner` for signing tool receipts
//! with Ed25519 keys per AD-RECEIPT-001 and AD-KEY-001.
//!
//! # Architecture
//!
//! ```text
//! ReceiptSigner
//!     |-- signing_key: SigningKey (Ed25519 private key)
//!     |-- verifying_key: VerifyingKey (Ed25519 public key, derived)
//!     |-- key_id: KeyId (unique identifier)
//!     `-- key_version: u32 (rotation tracking)
//! ```
//!
//! # Security Model
//!
//! Per AD-RECEIPT-001 and AD-KEY-001:
//! - Signing keys are stored in OS keychain (via keychain module)
//! - Key versioning enables rotation without breaking verification
//! - Signature is computed over `canonical_bytes()` which includes
//!   `signer_identity`
//!
//! # Contract References
//!
//! - AD-RECEIPT-001: Tool receipt generation
//! - AD-KEY-001: Key lifecycle management
//! - CTR-1909: Constant-time operations for sensitive comparisons

use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

use super::receipt::{ReceiptError, SignerIdentity, ToolReceipt};
use super::receipt_builder::ReceiptSigning;

// =============================================================================
// Constants
// =============================================================================

/// Maximum length for key ID.
pub const MAX_KEY_ID_LEN: usize = 128;

/// Key version for initial key generation.
pub const INITIAL_KEY_VERSION: u32 = 1;

// =============================================================================
// KeyId
// =============================================================================

/// Unique identifier for a signing key.
///
/// # Security
///
/// Key IDs are used to look up keys in the keychain and must be
/// validated to prevent injection attacks.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct KeyId(String);

impl KeyId {
    /// Creates a new key ID with validation.
    ///
    /// # Errors
    ///
    /// Returns an error if the ID is empty or exceeds `MAX_KEY_ID_LEN`.
    pub fn new(id: impl Into<String>) -> Result<Self, SignerError> {
        let id = id.into();
        if id.is_empty() {
            return Err(SignerError::EmptyKeyId);
        }
        if id.len() > MAX_KEY_ID_LEN {
            return Err(SignerError::KeyIdTooLong {
                len: id.len(),
                max: MAX_KEY_ID_LEN,
            });
        }
        // Validate that key ID contains only safe characters
        if !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(SignerError::InvalidKeyIdCharacter);
        }
        Ok(Self(id))
    }

    /// Returns the key ID as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl TryFrom<String> for KeyId {
    type Error = SignerError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl From<KeyId> for String {
    fn from(key_id: KeyId) -> Self {
        key_id.0
    }
}

// =============================================================================
// SignerError
// =============================================================================

/// Errors that can occur during signing operations.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignerError {
    /// Key ID is empty.
    #[error("key ID is empty")]
    EmptyKeyId,

    /// Key ID exceeds maximum length.
    #[error("key ID too long: {len} bytes (max {max})")]
    KeyIdTooLong {
        /// Actual length.
        len: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Key ID contains invalid characters.
    #[error("key ID contains invalid characters (only alphanumeric, '-', '_' allowed)")]
    InvalidKeyIdCharacter,

    /// Receipt signing failed.
    #[error("receipt error: {0}")]
    Receipt(#[from] ReceiptError),

    /// Key generation failed.
    #[error("key generation failed: {0}")]
    KeyGeneration(String),

    /// Invalid key bytes.
    #[error("invalid key bytes: expected 32 bytes, got {len}")]
    InvalidKeyBytes {
        /// Actual length.
        len: usize,
    },
}

// =============================================================================
// ReceiptSigner
// =============================================================================

/// Signs tool receipts using Ed25519.
///
/// # Example
///
/// ```rust,ignore
/// use apm2_daemon::evidence::{ReceiptBuilder, ReceiptSigner, KeyId};
/// use apm2_daemon::episode::EpisodeId;
///
/// let signer = ReceiptSigner::generate(KeyId::new("daemon-key-001")?, 1)?;
///
/// let receipt = ReceiptBuilder::for_episode_start(EpisodeId::new("ep-001")?)
///     .with_envelope([0xaa; 32])
///     .with_policy([0xbb; 32])
///     .with_timestamp(1_704_067_200_000_000_000)
///     .build()?;
///
/// let signed_receipt = signer.sign(receipt)?;
/// assert!(signed_receipt.is_signed());
/// ```
pub struct ReceiptSigner {
    /// Ed25519 signing key (private).
    signing_key: SigningKey,
    /// Ed25519 verifying key (public, derived from signing key).
    verifying_key: VerifyingKey,
    /// Unique identifier for this key.
    key_id: KeyId,
    /// Version number for key rotation tracking.
    key_version: u32,
}

impl ReceiptSigner {
    /// Creates a new signer from an existing signing key.
    ///
    /// # Arguments
    ///
    /// * `signing_key` - The Ed25519 signing key
    /// * `key_id` - Unique identifier for this key
    /// * `key_version` - Version number for rotation tracking
    #[must_use]
    pub fn new(signing_key: SigningKey, key_id: KeyId, key_version: u32) -> Self {
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
            key_id,
            key_version,
        }
    }

    /// Generates a new signer with a random signing key.
    ///
    /// # Arguments
    ///
    /// * `key_id` - Unique identifier for this key
    /// * `key_version` - Version number for rotation tracking
    ///
    /// # Errors
    ///
    /// Returns an error if key generation fails.
    pub fn generate(key_id: KeyId, key_version: u32) -> Result<Self, SignerError> {
        let mut rng = rand::rngs::OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        Ok(Self::new(signing_key, key_id, key_version))
    }

    /// Creates a signer from raw key bytes.
    ///
    /// # Arguments
    ///
    /// * `key_bytes` - 32-byte Ed25519 signing key seed
    /// * `key_id` - Unique identifier for this key
    /// * `key_version` - Version number for rotation tracking
    ///
    /// # Errors
    ///
    /// Returns an error if the key bytes are invalid.
    pub fn from_bytes(
        key_bytes: &[u8],
        key_id: KeyId,
        key_version: u32,
    ) -> Result<Self, SignerError> {
        if key_bytes.len() != 32 {
            return Err(SignerError::InvalidKeyBytes {
                len: key_bytes.len(),
            });
        }
        // SAFETY: The length check above guarantees key_bytes.len() == 32,
        // so try_into() for [u8; 32] will always succeed. The expect is
        // unreachable but provides defense-in-depth documentation.
        let bytes: [u8; 32] = key_bytes
            .try_into()
            .expect("unreachable: length validated as 32 above");
        let signing_key = SigningKey::from_bytes(&bytes);
        Ok(Self::new(signing_key, key_id, key_version))
    }

    /// Returns the key ID.
    #[must_use]
    pub const fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    /// Returns the key version.
    #[must_use]
    pub const fn key_version(&self) -> u32 {
        self.key_version
    }

    /// Returns the public verifying key.
    #[must_use]
    pub const fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Returns the public key bytes (32 bytes).
    #[must_use]
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    /// Returns the signing key bytes (32 bytes) wrapped in Zeroizing for
    /// secure handling.
    ///
    /// # Security
    ///
    /// The returned bytes are wrapped in `Zeroizing` to ensure they are
    /// zeroed from memory when dropped.
    #[must_use]
    pub fn signing_key_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.signing_key.to_bytes())
    }

    /// Signs a tool receipt.
    ///
    /// This computes the Ed25519 signature over the receipt's canonical bytes
    /// and attaches both the signature and signer identity to the receipt.
    ///
    /// # Arguments
    ///
    /// * `receipt` - The unsigned receipt to sign
    ///
    /// # Errors
    ///
    /// Returns an error if the receipt is already signed.
    pub fn sign(&self, mut receipt: ToolReceipt) -> Result<ToolReceipt, SignerError> {
        // Create signer identity (includes public key for verification)
        let signer_identity = SignerIdentity::new(
            self.public_key_bytes(),
            format!("{}:v{}", self.key_id, self.key_version),
        )
        .map_err(SignerError::Receipt)?;

        // Set signer identity BEFORE computing canonical bytes
        // This ensures the signer is cryptographically bound to the receipt
        receipt.signer_identity = Some(signer_identity.clone());

        // Get the bytes to sign (canonical_bytes includes signer_identity)
        let bytes_to_sign = receipt.unsigned_bytes();

        // Compute Ed25519 signature
        let signature: Signature = self.signing_key.sign(&bytes_to_sign);

        // Attach signature using the ReceiptSigning trait
        // Note: We need to clear signer_identity first since attach_signature
        // expects it to be None (it sets it)
        receipt.signer_identity = None;
        receipt
            .attach_signature(signature.to_bytes(), signer_identity)
            .map_err(SignerError::Receipt)
    }
}

impl fmt::Debug for ReceiptSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReceiptSigner")
            .field("key_id", &self.key_id)
            .field("key_version", &self.key_version)
            .field("verifying_key", &hex::encode(self.verifying_key.as_bytes()))
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::episode::EpisodeId;
    use crate::evidence::receipt::ToolExecutionDetails;
    use crate::evidence::receipt_builder::ReceiptBuilder;

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
    fn test_key_id_validation() {
        // Valid key IDs
        assert!(KeyId::new("my-key-001").is_ok());
        assert!(KeyId::new("KEY_V1").is_ok());
        assert!(KeyId::new("abc123").is_ok());

        // Empty
        assert!(matches!(KeyId::new(""), Err(SignerError::EmptyKeyId)));

        // Too long
        let long_id = "x".repeat(MAX_KEY_ID_LEN + 1);
        assert!(matches!(
            KeyId::new(long_id),
            Err(SignerError::KeyIdTooLong { .. })
        ));

        // Invalid characters
        assert!(matches!(
            KeyId::new("key:001"),
            Err(SignerError::InvalidKeyIdCharacter)
        ));
        assert!(matches!(
            KeyId::new("key/001"),
            Err(SignerError::InvalidKeyIdCharacter)
        ));
        assert!(matches!(
            KeyId::new("key 001"),
            Err(SignerError::InvalidKeyIdCharacter)
        ));
    }

    #[test]
    fn test_signer_generation() {
        let key_id = KeyId::new("test-key").unwrap();
        let receipt_signer = ReceiptSigner::generate(key_id, 1).unwrap();

        assert_eq!(receipt_signer.key_id().as_str(), "test-key");
        assert_eq!(receipt_signer.key_version(), 1);
        assert_eq!(receipt_signer.public_key_bytes().len(), 32);
    }

    #[test]
    fn test_signer_from_bytes() {
        let key_bytes = [0x42u8; 32];
        let key_id = KeyId::new("test-key").unwrap();
        let signer = ReceiptSigner::from_bytes(&key_bytes, key_id, 1).unwrap();

        // Same bytes should produce same public key
        let signer2 =
            ReceiptSigner::from_bytes(&key_bytes, KeyId::new("test-key-2").unwrap(), 1).unwrap();
        assert_eq!(signer.public_key_bytes(), signer2.public_key_bytes());
    }

    #[test]
    fn test_signer_from_bytes_invalid_length() {
        let key_id = KeyId::new("test-key").unwrap();

        // Too short
        assert!(matches!(
            ReceiptSigner::from_bytes(&[0u8; 16], key_id.clone(), 1),
            Err(SignerError::InvalidKeyBytes { len: 16 })
        ));

        // Too long
        assert!(matches!(
            ReceiptSigner::from_bytes(&[0u8; 64], key_id, 1),
            Err(SignerError::InvalidKeyBytes { len: 64 })
        ));
    }

    #[test]
    fn test_sign_receipt() {
        let key_id = KeyId::new("test-key").unwrap();
        let receipt_signer = ReceiptSigner::generate(key_id, 1).unwrap();

        let receipt = make_test_receipt();
        assert!(!receipt.is_signed());

        let signed_receipt = receipt_signer.sign(receipt).unwrap();
        assert!(signed_receipt.is_signed());
        assert!(signed_receipt.signature.is_some());
        assert!(signed_receipt.signer_identity.is_some());

        let identity = signed_receipt.signer_identity.as_ref().unwrap();
        assert_eq!(identity.public_key, receipt_signer.public_key_bytes());
        assert!(identity.identity.contains("test-key"));
        assert!(identity.identity.contains("v1"));
    }

    #[test]
    fn test_sign_already_signed_receipt_fails() {
        let key_id = KeyId::new("test-key").unwrap();
        let receipt_signer = ReceiptSigner::generate(key_id, 1).unwrap();

        let receipt = make_test_receipt();
        let signed_receipt = receipt_signer.sign(receipt).unwrap();

        // Attempting to sign again should fail
        let result = receipt_signer.sign(signed_receipt);
        assert!(matches!(
            result,
            Err(SignerError::Receipt(ReceiptError::AlreadySigned))
        ));
    }

    #[test]
    fn test_different_keys_produce_different_signatures() {
        let receipt_signer_a = ReceiptSigner::generate(KeyId::new("key-1").unwrap(), 1).unwrap();
        let receipt_signer_b = ReceiptSigner::generate(KeyId::new("key-2").unwrap(), 1).unwrap();

        let receipt_a = make_test_receipt();
        let receipt_b = make_test_receipt();

        let signed_a = receipt_signer_a.sign(receipt_a).unwrap();
        let signed_b = receipt_signer_b.sign(receipt_b).unwrap();

        // Different keys should produce different signatures
        assert_ne!(signed_a.signature, signed_b.signature);
    }

    #[test]
    fn test_signing_key_bytes_zeroized() {
        let key_id = KeyId::new("test-key").unwrap();
        let signer = ReceiptSigner::generate(key_id, 1).unwrap();

        // Get the key bytes - they should be wrapped in Zeroizing
        let key_bytes = signer.signing_key_bytes();
        assert_eq!(key_bytes.len(), 32);

        // The Zeroizing wrapper will automatically zero the memory when dropped
        // We can't easily test this, but the type guarantees it
    }

    #[test]
    fn test_signer_debug_does_not_expose_private_key() {
        let key_id = KeyId::new("test-key").unwrap();
        let signer = ReceiptSigner::generate(key_id, 1).unwrap();

        let debug_output = format!("{signer:?}");

        // Debug output should include key_id and verifying_key (public)
        assert!(debug_output.contains("test-key"));
        assert!(debug_output.contains("verifying_key"));

        // Debug output should NOT include the signing key bytes
        // (The struct uses finish_non_exhaustive)
        assert!(!debug_output.contains("signing_key"));
    }

    #[test]
    fn test_deterministic_signature_for_same_receipt() {
        // Ed25519 signatures are deterministic (no random nonce)
        // so the same key + message should always produce the same signature
        let key_bytes = [0x42u8; 32];
        let signer =
            ReceiptSigner::from_bytes(&key_bytes, KeyId::new("test-key").unwrap(), 1).unwrap();

        let receipt1 = make_test_receipt();
        let receipt2 = make_test_receipt();

        let signed1 = signer.sign(receipt1).unwrap();
        let signed2 = signer.sign(receipt2).unwrap();

        // Same key + same message = same signature (Ed25519 is deterministic)
        assert_eq!(signed1.signature, signed2.signature);
    }
}
