//! Ed25519 signing and verification.

use ed25519_dalek::{SecretKey, SigningKey};
pub use ed25519_dalek::{Signature, VerifyingKey};
use thiserror::Error;
use zeroize::Zeroizing;

/// Size of an Ed25519 signature in bytes.
pub const SIGNATURE_SIZE: usize = 64;

/// Size of an Ed25519 secret key in bytes.
pub const SECRET_KEY_SIZE: usize = 32;

/// Size of an Ed25519 public key in bytes.
pub const PUBLIC_KEY_SIZE: usize = 32;

/// Errors that can occur during signing operations.
#[derive(Debug, Error)]
pub enum SignerError {
    /// Invalid key format or length.
    #[error("invalid key: {0}")]
    InvalidKey(String),

    /// Signature verification failed.
    #[error("signature verification failed")]
    VerificationFailed,

    /// The signature is malformed.
    #[error("malformed signature: {0}")]
    MalformedSignature(String),
}

/// A signer that holds an Ed25519 keypair for signing events.
///
/// The secret key is zeroized when the signer is dropped.
pub struct Signer {
    signing_key: SigningKey,
}

impl Signer {
    /// Creates a new signer from a signing key.
    #[must_use]
    pub const fn new(signing_key: SigningKey) -> Self {
        Self { signing_key }
    }

    /// Creates a new signer from secret key bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the key bytes are invalid.
    pub fn from_bytes(secret_key_bytes: &[u8]) -> Result<Self, SignerError> {
        if secret_key_bytes.len() != SECRET_KEY_SIZE {
            return Err(SignerError::InvalidKey(format!(
                "expected {} bytes, got {}",
                SECRET_KEY_SIZE,
                secret_key_bytes.len()
            )));
        }

        let secret_key: SecretKey = secret_key_bytes
            .try_into()
            .map_err(|_| SignerError::InvalidKey("invalid secret key bytes".to_string()))?;

        Ok(Self {
            signing_key: SigningKey::from_bytes(&secret_key),
        })
    }

    /// Generates a new random signer.
    #[must_use]
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        Self {
            signing_key: SigningKey::generate(&mut rng),
        }
    }

    /// Signs a message and returns the signature.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Signature {
        use ed25519_dalek::Signer as _;
        self.signing_key.sign(message)
    }

    /// Verifies a signature against a message using this signer's public key.
    #[must_use]
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        use ed25519_dalek::Verifier as _;
        self.signing_key
            .verifying_key()
            .verify(message, signature)
            .is_ok()
    }

    /// Returns the verifying (public) key for this signer.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Returns the secret key bytes (zeroized container).
    ///
    /// Use this for secure storage of the key.
    #[must_use]
    pub fn secret_key_bytes(&self) -> Zeroizing<[u8; SECRET_KEY_SIZE]> {
        Zeroizing::new(self.signing_key.to_bytes())
    }

    /// Returns the public key bytes.
    #[must_use]
    pub fn public_key_bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
        self.signing_key.verifying_key().to_bytes()
    }
}

/// Verifies a signature using only the public key.
///
/// This function is useful when you only have the verifying key
/// and don't need signing capability.
///
/// # Errors
///
/// Returns an error if the signature is invalid.
pub fn verify_signature(
    verifying_key: &VerifyingKey,
    message: &[u8],
    signature: &Signature,
) -> Result<(), SignerError> {
    use ed25519_dalek::Verifier as _;
    verifying_key
        .verify(message, signature)
        .map_err(|_| SignerError::VerificationFailed)
}

/// Parses a signature from bytes.
///
/// # Errors
///
/// Returns an error if the bytes are not a valid signature.
pub fn parse_signature(bytes: &[u8]) -> Result<Signature, SignerError> {
    if bytes.len() != SIGNATURE_SIZE {
        return Err(SignerError::MalformedSignature(format!(
            "expected {} bytes, got {}",
            SIGNATURE_SIZE,
            bytes.len()
        )));
    }

    let sig_bytes: [u8; SIGNATURE_SIZE] = bytes
        .try_into()
        .map_err(|_| SignerError::MalformedSignature("invalid signature bytes".to_string()))?;

    Ok(Signature::from_bytes(&sig_bytes))
}

/// Parses a verifying key from bytes.
///
/// # Errors
///
/// Returns an error if the bytes are not a valid public key.
pub fn parse_verifying_key(bytes: &[u8]) -> Result<VerifyingKey, SignerError> {
    if bytes.len() != PUBLIC_KEY_SIZE {
        return Err(SignerError::InvalidKey(format!(
            "expected {} bytes, got {}",
            PUBLIC_KEY_SIZE,
            bytes.len()
        )));
    }

    let key_bytes: [u8; PUBLIC_KEY_SIZE] = bytes
        .try_into()
        .map_err(|_| SignerError::InvalidKey("invalid public key bytes".to_string()))?;

    VerifyingKey::from_bytes(&key_bytes).map_err(|e| SignerError::InvalidKey(e.to_string()))
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_generate_signer() {
        let signer = Signer::generate();

        // Should have valid key bytes
        assert_eq!(signer.secret_key_bytes().len(), SECRET_KEY_SIZE);
        assert_eq!(signer.public_key_bytes().len(), PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_sign_and_verify() {
        let signer = Signer::generate();
        let message = b"test message to sign";

        let signature = signer.sign(message);

        // Signature should be valid
        assert!(signer.verify(message, &signature));

        // Modified message should fail verification
        let modified_message = b"modified message";
        assert!(!signer.verify(modified_message, &signature));
    }

    #[test]
    fn test_from_bytes() {
        let original = Signer::generate();
        let secret_bytes = original.secret_key_bytes();

        let restored = Signer::from_bytes(&*secret_bytes).unwrap();

        // Should have the same public key
        assert_eq!(original.public_key_bytes(), restored.public_key_bytes());

        // Signatures should match
        let message = b"test";
        let sig1 = original.sign(message);
        let sig2 = restored.sign(message);
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_from_bytes_invalid_length() {
        let result = Signer::from_bytes(&[0u8; 16]); // Too short
        assert!(matches!(result, Err(SignerError::InvalidKey(_))));
    }

    #[test]
    fn test_verify_signature() {
        let signer = Signer::generate();
        let message = b"test message";
        let signature = signer.sign(message);

        // Verify using the standalone function
        let result = verify_signature(&signer.verifying_key(), message, &signature);
        assert!(result.is_ok());

        // Wrong message should fail
        let result = verify_signature(&signer.verifying_key(), b"wrong", &signature);
        assert!(matches!(result, Err(SignerError::VerificationFailed)));
    }

    #[test]
    fn test_parse_signature() {
        let signer = Signer::generate();
        let signature = signer.sign(b"test");

        // Parse from bytes
        let parsed = parse_signature(&signature.to_bytes()).unwrap();
        assert_eq!(signature, parsed);

        // Invalid length should fail
        let result = parse_signature(&[0u8; 32]);
        assert!(matches!(result, Err(SignerError::MalformedSignature(_))));
    }

    #[test]
    fn test_parse_verifying_key() {
        let signer = Signer::generate();
        let key_bytes = signer.public_key_bytes();

        let parsed = parse_verifying_key(&key_bytes).unwrap();
        assert_eq!(signer.verifying_key(), parsed);

        // Invalid length should fail
        let result = parse_verifying_key(&[0u8; 16]);
        assert!(matches!(result, Err(SignerError::InvalidKey(_))));
    }

    #[test]
    fn test_deterministic_signatures() {
        // Ed25519 signatures are deterministic (no randomness in signing)
        let signer = Signer::generate();
        let message = b"deterministic test";

        let sig1 = signer.sign(message);
        let sig2 = signer.sign(message);

        assert_eq!(sig1, sig2);
    }
}
