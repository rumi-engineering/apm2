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
//! <PREFIX> || canonical_bytes(message)
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
/// Used when signing/verifying session quarantine events.
pub const QUARANTINE_EVENT_PREFIX: &[u8] = b"QUARANTINE_EVENT:";

/// Domain prefix for intervention freeze events.
///
/// Used when signing/verifying divergence-triggered freeze events.
pub const INTERVENTION_FREEZE_PREFIX: &[u8] = b"INTERVENTION_FREEZE:";

/// Domain prefix for intervention unfreeze events.
///
/// Used when signing/verifying adjudication-resolved unfreeze events.
pub const INTERVENTION_UNFREEZE_PREFIX: &[u8] = b"INTERVENTION_UNFREEZE:";

/// Domain prefix for ledger event records.
///
/// Used when signing/verifying events on ledger ingestion.
/// This ensures event signatures are bound to the ledger context
/// and cannot be replayed in other contexts.
pub const LEDGER_EVENT_PREFIX: &[u8] = b"LEDGER_EVENT:";

/// Domain prefix for `ChangeSetPublished` events.
///
/// Used when signing/verifying changeset publication events.
/// This anchors the changeset digest and CAS hash before any review begins.
pub const CHANGESET_PUBLISHED_PREFIX: &[u8] = b"CHANGESET_PUBLISHED:";

/// Domain prefix for `ReviewBlockedRecorded` events.
///
/// Used when signing/verifying review blocked events.
/// This records blocked outcomes when workspace apply or tool execution fails.
pub const REVIEW_BLOCKED_RECORDED_PREFIX: &[u8] = b"REVIEW_BLOCKED_RECORDED:";

/// Domain prefix for `ReviewReceiptRecorded` events.
///
/// Used when signing/verifying review receipt events.
/// This records successful review outcomes with artifact bundle bindings.
pub const REVIEW_RECEIPT_RECORDED_PREFIX: &[u8] = b"REVIEW_RECEIPT_RECORDED:";

/// Domain prefix for `ProjectionReceiptRecorded` events.
///
/// Used when signing/verifying projection receipt events.
/// This records successful projection outcomes with artifact bundle bindings.
pub const PROJECTION_RECEIPT_RECORDED_PREFIX: &[u8] = b"PROJECTION_RECEIPT_RECORDED:";

// =============================================================================
// Domain-Separated Signing
// =============================================================================

/// Signs a message with domain separation.
///
/// The signature is computed over `domain_prefix || canonical_bytes`, ensuring
/// that signatures are bound to a specific message type and cannot be replayed
/// in other contexts.
///
/// # Arguments
///
/// * `signer` - The signer holding the Ed25519 keypair
/// * `domain_prefix` - The domain separator prefix (e.g.,
///   `GATE_LEASE_ISSUED_PREFIX`)
/// * `canonical_bytes` - The canonical encoding of the message to sign
///
/// # Returns
///
/// An Ed25519 signature over the domain-separated message.
///
/// # Example
///
/// ```rust
/// use apm2_core::crypto::Signer;
/// use apm2_core::fac::{GATE_LEASE_ISSUED_PREFIX, sign_with_domain};
///
/// let signer = Signer::generate();
/// let data = b"lease canonical bytes";
/// let signature = sign_with_domain(&signer, GATE_LEASE_ISSUED_PREFIX, data);
/// ```
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

/// Verifies a signature with domain separation.
///
/// The verification is performed over `domain_prefix || canonical_bytes`,
/// ensuring that only signatures created with the same domain prefix will
/// verify successfully.
///
/// # Arguments
///
/// * `verifying_key` - The public key to verify against
/// * `domain_prefix` - The domain separator prefix (must match signing prefix)
/// * `canonical_bytes` - The canonical encoding of the original message
/// * `signature` - The signature to verify
///
/// # Returns
///
/// `Ok(())` if the signature is valid, `Err(SignerError::VerificationFailed)`
/// otherwise.
///
/// # Errors
///
/// Returns [`SignerError::VerificationFailed`] if the signature is invalid.
///
/// # Example
///
/// ```rust
/// use apm2_core::crypto::Signer;
/// use apm2_core::fac::{
///     GATE_LEASE_ISSUED_PREFIX, sign_with_domain, verify_with_domain,
/// };
///
/// let signer = Signer::generate();
/// let data = b"lease canonical bytes";
/// let signature = sign_with_domain(&signer, GATE_LEASE_ISSUED_PREFIX, data);
///
/// // Verification succeeds with matching prefix
/// assert!(
///     verify_with_domain(
///         &signer.verifying_key(),
///         GATE_LEASE_ISSUED_PREFIX,
///         data,
///         &signature
///     )
///     .is_ok()
/// );
/// ```
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

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::crypto::Signer;

    #[test]
    fn test_sign_and_verify_roundtrip() {
        let signer = Signer::generate();
        let canonical_bytes = b"test canonical data for signing";

        let signature = sign_with_domain(&signer, GATE_LEASE_ISSUED_PREFIX, canonical_bytes);

        // Verification should succeed with matching prefix
        assert!(
            verify_with_domain(
                &signer.verifying_key(),
                GATE_LEASE_ISSUED_PREFIX,
                canonical_bytes,
                &signature
            )
            .is_ok()
        );
    }

    #[test]
    fn test_wrong_domain_prefix_fails() {
        let signer = Signer::generate();
        let canonical_bytes = b"test data";

        // Sign with GATE_LEASE_ISSUED_PREFIX
        let signature = sign_with_domain(&signer, GATE_LEASE_ISSUED_PREFIX, canonical_bytes);

        // Verification with different prefix should fail
        assert!(
            verify_with_domain(
                &signer.verifying_key(),
                LEASE_REVOKED_PREFIX, // Wrong prefix!
                canonical_bytes,
                &signature
            )
            .is_err()
        );
    }

    #[test]
    fn test_modified_data_fails() {
        let signer = Signer::generate();
        let original = b"original data";
        let modified = b"modified data";

        let signature = sign_with_domain(&signer, GATE_LEASE_ISSUED_PREFIX, original);

        // Verification with modified data should fail
        assert!(
            verify_with_domain(
                &signer.verifying_key(),
                GATE_LEASE_ISSUED_PREFIX,
                modified,
                &signature
            )
            .is_err()
        );
    }

    #[test]
    fn test_wrong_key_fails() {
        let signer1 = Signer::generate();
        let signer2 = Signer::generate();
        let canonical_bytes = b"test data";

        let signature = sign_with_domain(&signer1, GATE_LEASE_ISSUED_PREFIX, canonical_bytes);

        // Verification with different key should fail
        assert!(
            verify_with_domain(
                &signer2.verifying_key(),
                GATE_LEASE_ISSUED_PREFIX,
                canonical_bytes,
                &signature
            )
            .is_err()
        );
    }

    #[test]
    fn test_deterministic_signatures() {
        let signer = Signer::generate();
        let canonical_bytes = b"deterministic test";

        let sig1 = sign_with_domain(&signer, GATE_LEASE_ISSUED_PREFIX, canonical_bytes);
        let sig2 = sign_with_domain(&signer, GATE_LEASE_ISSUED_PREFIX, canonical_bytes);

        // Ed25519 is deterministic, so signatures should match
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_different_prefixes_produce_different_messages() {
        let signer = Signer::generate();
        let canonical_bytes = b"test data";

        let sig1 = sign_with_domain(&signer, GATE_LEASE_ISSUED_PREFIX, canonical_bytes);
        let sig2 = sign_with_domain(&signer, LEASE_REVOKED_PREFIX, canonical_bytes);

        // Different domain prefixes should produce different signatures
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_all_domain_prefixes_defined() {
        // Verify all 16 required domain prefixes are defined
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
            INTERVENTION_FREEZE_PREFIX,
            INTERVENTION_UNFREEZE_PREFIX,
            CHANGESET_PUBLISHED_PREFIX,
            REVIEW_BLOCKED_RECORDED_PREFIX,
            REVIEW_RECEIPT_RECORDED_PREFIX,
            PROJECTION_RECEIPT_RECORDED_PREFIX,
        ];

        // All prefixes should be non-empty and end with ':'
        for prefix in &prefixes {
            assert!(!prefix.is_empty());
            assert!(prefix.ends_with(b":"), "Prefix should end with ':'");
        }

        // All prefixes should be unique
        let mut unique: std::collections::HashSet<&[u8]> = std::collections::HashSet::new();
        for prefix in &prefixes {
            assert!(unique.insert(prefix), "Prefix should be unique");
        }
    }

    #[test]
    fn test_ledger_event_prefix() {
        // Verify the LEDGER_EVENT_PREFIX matches the expected value
        assert_eq!(LEDGER_EVENT_PREFIX, b"LEDGER_EVENT:" as &[u8]);
    }

    #[test]
    fn test_policy_resolved_prefix() {
        // Verify the POLICY_RESOLVED_PREFIX matches the expected value
        assert_eq!(
            POLICY_RESOLVED_PREFIX,
            b"POLICY_RESOLVED_FOR_CHANGESET:" as &[u8]
        );
    }

    #[test]
    fn test_empty_canonical_bytes() {
        let signer = Signer::generate();
        let empty: &[u8] = b"";

        let signature = sign_with_domain(&signer, GATE_LEASE_ISSUED_PREFIX, empty);

        // Should still work with empty canonical bytes
        assert!(
            verify_with_domain(
                &signer.verifying_key(),
                GATE_LEASE_ISSUED_PREFIX,
                empty,
                &signature
            )
            .is_ok()
        );
    }
}
