//! Ed25519 signing and verification for run manifests.
//!
//! This module provides cryptographic signing of manifests using Ed25519,
//! reusing the signing infrastructure from [`crate::crypto`].

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::manifest::RunManifest;
use crate::crypto::{Signer, SignerError, VerifyingKey, parse_signature, verify_signature};

/// Errors that can occur during manifest signing operations.
#[derive(Debug, Error)]
pub enum ManifestSignerError {
    /// The signature is invalid or verification failed.
    #[error("signature verification failed: {0}")]
    VerificationFailed(String),

    /// The manifest could not be deserialized.
    #[error("manifest deserialization failed: {0}")]
    DeserializationFailed(String),

    /// An underlying signer error occurred.
    #[error("signer error: {0}")]
    SignerError(#[from] SignerError),
}

/// A signed run manifest containing the serialized manifest and its signature.
///
/// The signature is computed over the canonical JSON representation of the
/// manifest. This struct is suitable for storage and transmission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedManifest {
    /// The canonical JSON bytes of the manifest.
    #[serde(with = "base64_bytes")]
    pub manifest_bytes: Vec<u8>,

    /// The Ed25519 signature over the manifest bytes.
    #[serde(with = "base64_bytes")]
    pub signature: Vec<u8>,

    /// The public key that can verify this signature (hex-encoded).
    pub public_key: String,
}

/// Serde helper module for base64 encoding/decoding of byte vectors.
mod base64_bytes {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    const ENGINE: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use base64::Engine;
        let encoded = ENGINE.encode(bytes);
        encoded.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        use base64::Engine;
        let s = String::deserialize(deserializer)?;
        ENGINE.decode(&s).map_err(serde::de::Error::custom)
    }
}

impl SignedManifest {
    /// Returns the manifest ID extracted from the manifest bytes.
    ///
    /// This is a convenience method that deserializes just enough to get
    /// the ID without full validation.
    ///
    /// # Errors
    ///
    /// Returns an error if the manifest bytes cannot be deserialized.
    pub fn manifest_id(&self) -> Result<String, ManifestSignerError> {
        let manifest: RunManifest = serde_json::from_slice(&self.manifest_bytes)
            .map_err(|e| ManifestSignerError::DeserializationFailed(e.to_string()))?;
        Ok(manifest.manifest_id)
    }
}

/// Signs a run manifest using the provided signer.
///
/// The manifest is first serialized to its canonical JSON representation,
/// then signed using Ed25519. The resulting [`SignedManifest`] contains
/// the serialized bytes, signature, and public key for verification.
///
/// # Arguments
///
/// * `manifest` - The manifest to sign
/// * `signer` - The Ed25519 signer (contains the signing key)
///
/// # Example
///
/// ```rust,no_run
/// use apm2_core::crypto::Signer;
/// use apm2_core::run_manifest::{ManifestBuilder, sign_manifest};
///
/// let signer = Signer::generate();
/// let manifest = ManifestBuilder::new()
///     .with_lease_id("lease-123")
///     .with_routing_profile_id("production")
///     .with_ccp_index_hash("abc123")
///     .build()
///     .unwrap();
///
/// let signed = sign_manifest(&manifest, &signer);
/// ```
#[must_use]
pub fn sign_manifest(manifest: &RunManifest, signer: &Signer) -> SignedManifest {
    let manifest_bytes = manifest.canonical_bytes();
    let signature = signer.sign(&manifest_bytes);

    SignedManifest {
        manifest_bytes,
        signature: signature.to_bytes().to_vec(),
        public_key: hex::encode(signer.public_key_bytes()),
    }
}

/// Verifies a signed manifest and returns the contained manifest if valid.
///
/// This function:
/// 1. Parses the public key from the signed manifest
/// 2. Verifies the signature over the manifest bytes
/// 3. Deserializes and returns the manifest if valid
///
/// # Arguments
///
/// * `signed` - The signed manifest to verify
///
/// # Errors
///
/// Returns an error if:
/// - The public key cannot be parsed
/// - The signature is invalid
/// - The manifest cannot be deserialized
///
/// # Example
///
/// ```rust,no_run
/// use apm2_core::run_manifest::verify_manifest;
///
/// # fn example(signed: apm2_core::run_manifest::SignedManifest) {
/// match verify_manifest(&signed) {
///     Ok(manifest) => println!("Valid manifest: {}", manifest.manifest_id),
///     Err(e) => println!("Verification failed: {}", e),
/// }
/// # }
/// ```
pub fn verify_manifest(signed: &SignedManifest) -> Result<RunManifest, ManifestSignerError> {
    // Parse the public key
    let public_key_bytes = hex::decode(&signed.public_key)
        .map_err(|e| ManifestSignerError::VerificationFailed(format!("invalid public key: {e}")))?;

    let verifying_key = crate::crypto::parse_verifying_key(&public_key_bytes)?;

    // Parse the signature
    let signature = parse_signature(&signed.signature)?;

    // Verify the signature
    verify_signature(&verifying_key, &signed.manifest_bytes, &signature)?;

    // Deserialize the manifest
    let manifest: RunManifest = serde_json::from_slice(&signed.manifest_bytes)
        .map_err(|e| ManifestSignerError::DeserializationFailed(e.to_string()))?;

    Ok(manifest)
}

/// Verifies a signed manifest using a specific public key.
///
/// Unlike [`verify_manifest`], this function allows specifying an expected
/// public key, which is useful when you want to verify that a manifest was
/// signed by a specific actor.
///
/// # Arguments
///
/// * `signed` - The signed manifest to verify
/// * `expected_key` - The expected public key
///
/// # Errors
///
/// Returns an error if:
/// - The public key in the signed manifest doesn't match the expected key
/// - The signature is invalid
/// - The manifest cannot be deserialized
pub fn verify_manifest_with_key(
    signed: &SignedManifest,
    expected_key: &VerifyingKey,
) -> Result<RunManifest, ManifestSignerError> {
    // Check that the public key matches
    let expected_hex = hex::encode(expected_key.to_bytes());
    if signed.public_key != expected_hex {
        return Err(ManifestSignerError::VerificationFailed(format!(
            "public key mismatch: expected {}, got {}",
            expected_hex, signed.public_key
        )));
    }

    // Parse the signature
    let signature = parse_signature(&signed.signature)?;

    // Verify the signature
    verify_signature(expected_key, &signed.manifest_bytes, &signature)?;

    // Deserialize the manifest
    let manifest: RunManifest = serde_json::from_slice(&signed.manifest_bytes)
        .map_err(|e| ManifestSignerError::DeserializationFailed(e.to_string()))?;

    Ok(manifest)
}

#[cfg(test)]
#[allow(clippy::similar_names)]
mod unit_tests {
    use chrono::{TimeZone, Utc};

    use super::*;
    use crate::run_manifest::ManifestBuilder;

    fn create_test_manifest() -> RunManifest {
        let created_at = Utc.with_ymd_and_hms(2024, 1, 15, 12, 0, 0).unwrap();

        ManifestBuilder::new()
            .with_lease_id("lease-abc123")
            .with_routing_profile_id("production")
            .with_ccp_index_hash("deadbeef")
            .add_input("requirements.yaml", b"requirement content")
            .add_output("impact_map.yaml", b"impact map content")
            .record_routing_decision("impact_map", "claude-opus-4")
            .record_stage_timing("impact_map", 1500)
            .build_with_id("manifest-001", created_at)
            .unwrap()
    }

    #[test]
    fn test_sign_and_verify_roundtrip() {
        let signer = Signer::generate();
        let manifest = create_test_manifest();

        let signed = sign_manifest(&manifest, &signer);
        let verified = verify_manifest(&signed).unwrap();

        assert_eq!(manifest, verified);
    }

    #[test]
    fn test_verify_detects_tampered_manifest() {
        let signer = Signer::generate();
        let manifest = create_test_manifest();

        let mut signed = sign_manifest(&manifest, &signer);

        // Tamper with the manifest bytes
        if !signed.manifest_bytes.is_empty() {
            signed.manifest_bytes[0] ^= 0xff;
        }

        let result = verify_manifest(&signed);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_detects_tampered_signature() {
        let signer = Signer::generate();
        let manifest = create_test_manifest();

        let mut signed = sign_manifest(&manifest, &signer);

        // Tamper with the signature
        if !signed.signature.is_empty() {
            signed.signature[0] ^= 0xff;
        }

        let result = verify_manifest(&signed);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_with_wrong_public_key() {
        let signer1 = Signer::generate();
        let signer2 = Signer::generate();
        let manifest = create_test_manifest();

        let signed = sign_manifest(&manifest, &signer1);

        // Try to verify with a different key
        let result = verify_manifest_with_key(&signed, &signer2.verifying_key());
        assert!(matches!(
            result,
            Err(ManifestSignerError::VerificationFailed(_))
        ));
    }

    #[test]
    fn test_verify_with_correct_public_key() {
        let signer = Signer::generate();
        let manifest = create_test_manifest();

        let signed = sign_manifest(&manifest, &signer);
        let verified = verify_manifest_with_key(&signed, &signer.verifying_key()).unwrap();

        assert_eq!(manifest, verified);
    }

    #[test]
    fn test_signed_manifest_serialization_roundtrip() {
        let signer = Signer::generate();
        let manifest = create_test_manifest();

        let signed = sign_manifest(&manifest, &signer);
        let json = serde_json::to_string(&signed).unwrap();
        let deserialized: SignedManifest = serde_json::from_str(&json).unwrap();

        assert_eq!(signed, deserialized);

        // Verify the deserialized signed manifest is still valid
        let verified = verify_manifest(&deserialized).unwrap();
        assert_eq!(manifest, verified);
    }

    #[test]
    fn test_signed_manifest_id_extraction() {
        let signer = Signer::generate();
        let manifest = create_test_manifest();

        let signed = sign_manifest(&manifest, &signer);
        let id = signed.manifest_id().unwrap();

        assert_eq!(id, "manifest-001");
    }

    #[test]
    fn test_deterministic_signing() {
        // Ed25519 signatures are deterministic
        let signer = Signer::generate();
        let manifest = create_test_manifest();

        let signed1 = sign_manifest(&manifest, &signer);
        let signed2 = sign_manifest(&manifest, &signer);

        assert_eq!(signed1.signature, signed2.signature);
    }

    #[test]
    fn test_different_signers_produce_different_signatures() {
        let signer1 = Signer::generate();
        let signer2 = Signer::generate();
        let manifest = create_test_manifest();

        let signed1 = sign_manifest(&manifest, &signer1);
        let signed2 = sign_manifest(&manifest, &signer2);

        // Signatures should differ (different keys)
        assert_ne!(signed1.signature, signed2.signature);
        assert_ne!(signed1.public_key, signed2.public_key);

        // Both should still verify
        assert!(verify_manifest(&signed1).is_ok());
        assert!(verify_manifest(&signed2).is_ok());
    }

    #[test]
    fn test_public_key_in_signed_manifest() {
        let signer = Signer::generate();
        let manifest = create_test_manifest();

        let signed = sign_manifest(&manifest, &signer);

        // Public key should be hex-encoded
        assert_eq!(signed.public_key.len(), 64); // 32 bytes = 64 hex chars
        assert!(signed.public_key.chars().all(|c| c.is_ascii_hexdigit()));

        // Should match the signer's public key
        assert_eq!(signed.public_key, hex::encode(signer.public_key_bytes()));
    }
}
