//! Cryptographic primitives for the APM2 kernel.
//!
//! This module provides hash-chain and signature primitives for the event
//! ledger:
//!
//! - **Blake3 hashing**: Fast, secure hashing for event content
//! - **Ed25519 signatures**: Digital signatures for event authentication
//! - **Hash-chain linking**: Cryptographic linking between sequential events
//! - **Key management**: Secure storage and retrieval of signing keys
//! - **HSM integration**: Hardware Security Module support for T1 validator
//!   keys
//!
//! # Hash Chain
//!
//! Each event in the ledger contains a hash of its content and a reference to
//! the previous event's hash, forming an immutable chain. Any tampering with
//! historical events will break the chain.
//!
//! # Signatures
//!
//! Events are signed using Ed25519 keys. The signature covers the canonical
//! encoding of the event (excluding the signature field itself), ensuring
//! authenticity and non-repudiation.
//!
//! # HSM Integration
//!
//! For T1 validator keys in the trust hierarchy, the [`hsm`] module provides
//! hardware security module integration. Keys managed by an HSM never leave
//! the secure hardware boundary; all signing operations are performed via
//! the HSM API.
//!
//! Available HSM providers:
//! - [`hsm::SoftwareHsmProvider`]: In-memory fallback for development
//! - [`yubihsm::YubiHsmProvider`]: Reference implementation for `YubiHSM`
//!
//! # Example
//!
//! ```rust,no_run
//! use apm2_core::crypto::{EventHasher, KeyManager, Signer};
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create a key manager and generate a keypair
//! let key_manager = KeyManager::in_memory();
//! let keypair = key_manager.generate_keypair("actor-1")?;
//!
//! // Hash event content
//! let content = b"event payload";
//! let prev_hash = [0u8; 32]; // Genesis event has zero hash
//! let event_hash = EventHasher::hash_event(content, &prev_hash);
//!
//! // Sign the hash
//! let signer = Signer::new(keypair);
//! let signature = signer.sign(&event_hash);
//!
//! // Verify the signature
//! assert!(signer.verify(&event_hash, &signature));
//! # Ok(())
//! # }
//! ```

mod hash;
pub mod hsm;
mod keys;
mod rotation;
mod sign;
pub mod yubihsm;

#[cfg(test)]
mod tests;

pub use hash::{
    EventHasher, HASH_SIZE, Hash, HashChainError, is_genesis_prev_hash, normalize_prev_hash,
};
pub use hsm::{
    HsmConfig, HsmError, HsmKeyInfo, HsmProvider, HsmProviderType, HsmResult, SoftwareHsmProvider,
    create_hsm_provider,
};
pub use keys::{KeyManager, KeyManagerError, StoredKeypair};
pub use rotation::{
    KEY_ROTATION_RECEIPT_V1_SCHEMA, KeyRotationReceiptError, KeyRotationReceiptV1,
    MAX_ROTATION_KEY_ID_LEN, rotate_key_with_overlap_duration,
    rotate_key_with_overlapping_validity,
};
pub use sign::{
    PUBLIC_KEY_SIZE, SIGNATURE_SIZE, Signature, Signer, SignerError, VerifyingKey, parse_signature,
    parse_verifying_key, verify_signature,
};
pub use yubihsm::YubiHsmProvider;
