//! Domain separator module for cryptographic signature isolation.
//!
//! This module implements domain separation for Ed25519 signatures to prevent
//! cross-protocol signature replay attacks. Each critical event type has a
//! unique domain prefix that is prepended to the canonical message bytes
//! before signing/verification.
//!
//! # Security Rationale
//!
//! Domain separation ensures that a signature valid for one message type cannot
//! be reused for another type. For example, a signature for a `GateLeaseIssued`
//! event cannot be replayed as a `LeaseRevoked` signature.
//!
//! # Format
//!
//! The domain-separated message format is:
//! ```text
//! <PREFIX>: || canonical_bytes(message)
//! ```
//!
//! Where `||` denotes concatenation and the prefix is a UTF-8 string terminated
//! with a colon.
//!
//! # Example
//!
//! ```rust
//! use apm2_core::crypto::Signer;
//! use apm2_core::fac::{
//!     GATE_LEASE_ISSUED_PREFIX, sign_with_domain, verify_with_domain,
//! };
//!
//! let signer = Signer::generate();
//! let canonical_bytes = b"lease data";
//!
//! // Sign with domain separation
//! let signature =
//!     sign_with_domain(&signer, GATE_LEASE_ISSUED_PREFIX, canonical_bytes);
//!
//! // Verify with the same domain prefix
//! assert!(
//!     verify_with_domain(
//!         &signer.verifying_key(),
//!         GATE_LEASE_ISSUED_PREFIX,
//!         canonical_bytes,
//!         &signature
//!     )
//!     .is_ok()
//! );
//! ```

use crate::crypto::{Signature, SignerError, VerifyingKey, verify_signature};

// =============================================================================
// Domain Separator Constants
// =============================================================================

/// Domain prefix for `GateLeaseIssued` events.
///
/// Used when signing/verifying gate lease issuance.
pub const GATE_LEASE_ISSUED_PREFIX: &[u8] = b"GATE_LEASE_ISSUED:";

/// Domain prefix for `LeaseRevoked` events.
///
/// Used when signing/verifying lease revocations.
pub const LEASE_REVOKED_PREFIX: &[u8] = b"LEASE_REVOKED:";

/// Domain prefix for `GateRunCompleted` events.
///
/// Used when signing/verifying gate run completions.
pub const GATE_RUN_COMPLETED_PREFIX: &[u8] = b"GATE_RUN_COMPLETED:";

/// Domain prefix for `MergeReceipt` events.
///
/// Used when signing/verifying merge receipts.
pub const MERGE_RECEIPT_PREFIX: &[u8] = b"MERGE_RECEIPT:";

/// Domain prefix for CI import attestation events.
///
/// Used when signing/verifying CI import attestations.
pub const CI_IMPORT_ATTESTATION_PREFIX: &[u8] = b"CI_IMPORT_ATTESTATION:";

/// Domain prefix for projection receipt events.
///
/// Used when signing/verifying projection receipts.
pub const PROJECTION_RECEIPT_PREFIX: &[u8] = b"PROJECTION_RECEIPT:";

/// Domain prefix for AAT result reused events.
///
/// Used when signing/verifying AAT result reuse attestations.
pub const AAT_RESULT_REUSED_PREFIX: &[u8] = b"AAT_RESULT_REUSED:";

/// Domain prefix for policy resolved events.
///
/// Used when signing/verifying policy resolution for changesets.
pub const POLICY_RESOLVED_PREFIX: &[u8] = b"POLICY_RESOLVED_FOR_CHANGESET:";

/// Domain prefix for gate receipt events.
///
/// Used when signing/verifying gate receipt envelopes.
pub const GATE_RECEIPT_PREFIX: &[u8] = b"GATE_RECEIPT:";

/// Domain prefix for quarantine events.
///
/// Used when signing/verifying quarantine-related events.
pub const QUARANTINE_EVENT_PREFIX: &[u8] = b"QUARANTINE_EVENT:";

// =============================================================================
// Domain-Separated Signing/Verification
// =============================================================================

/// Signs a message with domain separation.
///
/// The signature is computed over `domain_prefix || canonical_bytes`, ensuring
/// that the signature cannot be reused for messages with different domain
/// prefixes.
///
/// # Arguments
///
/// * `signer` - The signer holding the Ed25519 signing key
/// * `domain_prefix` - The domain separator prefix (use the `*_PREFIX`
///   constants)
/// * `canonical_bytes` - The canonicalized message bytes to sign
///
/// # Returns
///
/// The Ed25519 signature over the domain-separated message.
#[must_use]
pub fn sign_with_domain(
    signer: &crate::crypto::Signer,
    domain_prefix: &[u8],
    canonical_bytes: &[u8],
) -> Signature {
    let mut message = Vec::with_capacity(domain_prefix.len() + canonical_bytes.len());
    message.extend_from_slice(domain_prefix);
    message.extend_from_slice(canonical_bytes);
    signer.sign(&message)
}

/// Verifies a domain-separated signature.
///
/// The verification is performed over `domain_prefix || canonical_bytes`. If
/// the signature was created with a different domain prefix, verification will
/// fail.
///
/// # Arguments
///
/// * `verifying_key` - The public key to verify against
/// * `domain_prefix` - The expected domain separator prefix
/// * `canonical_bytes` - The canonicalized message bytes
/// * `signature` - The signature to verify
///
/// # Returns
///
/// `Ok(())` if the signature is valid, `Err(SignerError::VerificationFailed)`
/// otherwise.
///
/// # Errors
///
/// Returns [`SignerError::VerificationFailed`] if the signature is invalid or
/// was created with a different domain prefix.
pub fn verify_with_domain(
    verifying_key: &VerifyingKey,
    domain_prefix: &[u8],
    canonical_bytes: &[u8],
    signature: &Signature,
) -> Result<(), SignerError> {
    let mut message = Vec::with_capacity(domain_prefix.len() + canonical_bytes.len());
    message.extend_from_slice(domain_prefix);
    message.extend_from_slice(canonical_bytes);
    verify_signature(verifying_key, &message, signature)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::crypto::Signer;

    #[test]
    fn test_sign_verify_roundtrip() {
        let signer = Signer::generate();
        let canonical_bytes = b"test message for signing";

        let signature = sign_with_domain(&signer, GATE_LEASE_ISSUED_PREFIX, canonical_bytes);

        let result = verify_with_domain(
            &signer.verifying_key(),
            GATE_LEASE_ISSUED_PREFIX,
            canonical_bytes,
            &signature,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_cross_domain_rejection() {
        // Sign with GATE_LEASE_ISSUED, try to verify with LEASE_REVOKED
        let signer = Signer::generate();
        let canonical_bytes = b"test message";

        let signature = sign_with_domain(&signer, GATE_LEASE_ISSUED_PREFIX, canonical_bytes);

        // Verification with wrong domain should fail
        let result = verify_with_domain(
            &signer.verifying_key(),
            LEASE_REVOKED_PREFIX,
            canonical_bytes,
            &signature,
        );
        assert!(matches!(result, Err(SignerError::VerificationFailed)));
    }

    #[test]
    fn test_all_domain_prefixes_unique() {
        let prefixes = [
            GATE_LEASE_ISSUED_PREFIX,
            LEASE_REVOKED_PREFIX,
            GATE_RUN_COMPLETED_PREFIX,
            MERGE_RECEIPT_PREFIX,
            CI_IMPORT_ATTESTATION_PREFIX,
            PROJECTION_RECEIPT_PREFIX,
            AAT_RESULT_REUSED_PREFIX,
            POLICY_RESOLVED_PREFIX,
            GATE_RECEIPT_PREFIX,
            QUARANTINE_EVENT_PREFIX,
        ];

        // Verify all prefixes end with colon
        for prefix in &prefixes {
            assert!(
                prefix.ends_with(b":"),
                "All domain prefixes must end with colon"
            );
        }

        // Verify all prefixes are unique
        for (i, p1) in prefixes.iter().enumerate() {
            for (j, p2) in prefixes.iter().enumerate() {
                if i != j {
                    assert_ne!(p1, p2, "Domain prefixes must be unique");
                }
            }
        }
    }

    #[test]
    fn test_signature_binds_to_content() {
        let signer = Signer::generate();
        let canonical_bytes = b"original message";
        let modified_bytes = b"modified message";

        let signature = sign_with_domain(&signer, GATE_LEASE_ISSUED_PREFIX, canonical_bytes);

        // Verification with different content should fail
        let result = verify_with_domain(
            &signer.verifying_key(),
            GATE_LEASE_ISSUED_PREFIX,
            modified_bytes,
            &signature,
        );
        assert!(matches!(result, Err(SignerError::VerificationFailed)));
    }

    #[test]
    fn test_different_signers_produce_different_signatures() {
        let signer1 = Signer::generate();
        let signer2 = Signer::generate();
        let canonical_bytes = b"test message";

        let sig1 = sign_with_domain(&signer1, GATE_LEASE_ISSUED_PREFIX, canonical_bytes);
        let sig2 = sign_with_domain(&signer2, GATE_LEASE_ISSUED_PREFIX, canonical_bytes);

        // Signatures should be different (different keys)
        assert_ne!(sig1.to_bytes(), sig2.to_bytes());

        // Each should verify only with its own key
        assert!(
            verify_with_domain(
                &signer1.verifying_key(),
                GATE_LEASE_ISSUED_PREFIX,
                canonical_bytes,
                &sig1,
            )
            .is_ok()
        );
        assert!(
            verify_with_domain(
                &signer2.verifying_key(),
                GATE_LEASE_ISSUED_PREFIX,
                canonical_bytes,
                &sig1,
            )
            .is_err()
        );
    }

    #[test]
    fn test_empty_canonical_bytes() {
        let signer = Signer::generate();
        let canonical_bytes: &[u8] = b"";

        let signature = sign_with_domain(&signer, GATE_LEASE_ISSUED_PREFIX, canonical_bytes);

        let result = verify_with_domain(
            &signer.verifying_key(),
            GATE_LEASE_ISSUED_PREFIX,
            canonical_bytes,
            &signature,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_all_prefixes_sign_verify() {
        let signer = Signer::generate();
        let canonical_bytes = b"test data";

        let prefixes = [
            GATE_LEASE_ISSUED_PREFIX,
            LEASE_REVOKED_PREFIX,
            GATE_RUN_COMPLETED_PREFIX,
            MERGE_RECEIPT_PREFIX,
            CI_IMPORT_ATTESTATION_PREFIX,
            PROJECTION_RECEIPT_PREFIX,
            AAT_RESULT_REUSED_PREFIX,
            POLICY_RESOLVED_PREFIX,
            GATE_RECEIPT_PREFIX,
            QUARANTINE_EVENT_PREFIX,
        ];

        for prefix in &prefixes {
            let signature = sign_with_domain(&signer, prefix, canonical_bytes);
            let result =
                verify_with_domain(&signer.verifying_key(), prefix, canonical_bytes, &signature);
            assert!(
                result.is_ok(),
                "Sign/verify should succeed for prefix: {:?}",
                std::str::from_utf8(prefix)
            );
        }
    }
}
