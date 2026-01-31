// AGENT-AUTHORED
//! Merge receipt with atomic binding.
//!
//! This module implements the `MergeReceipt` which serves as a cryptographic
//! proof that a merge was executed with specific inputs and resulted in a
//! specific outcome.
//!
//! # Atomic Binding (FAC-REQ-0020)
//!
//! The `MergeReceipt` is created *after* the merge operation has been observed.
//! It atomically binds:
//!
//! - **Inputs**: `base_selector`, `changeset_digest`, `policy_hash`,
//!   `gate_receipt_ids`
//! - **Outcome**: `result_selector` (the actual commit hash produced)
//!
//! This prevents "equivocation" where a merge is claimed to have happened
//! but the result points to a different commit.
//!
//! # Security
//!
//! - Signed with `MERGE_RECEIPT:` domain separator
//! - Canonical encoding enforces deterministic serialization
//! - Resource limits prevent DoS attacks

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::domain_separator::{MERGE_RECEIPT_PREFIX, sign_with_domain, verify_with_domain};
use super::policy_resolution::MAX_STRING_LENGTH;
use crate::crypto::{Signature, Signer, VerifyingKey};
// Re-export proto type
pub use crate::events::MergeReceipt as MergeReceiptProto;

// =============================================================================
// Resource Limits
// =============================================================================

/// Maximum number of gate receipt IDs allowed.
pub const MAX_GATE_RECEIPTS: usize = 64;

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during MergeReceipt operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MergeReceiptError {
    /// Missing required field.
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// String field exceeds maximum length.
    #[error("string field '{field}' exceeds maximum length ({len} > {max})")]
    StringTooLong {
        /// The field name.
        field: &'static str,
        /// Actual length.
        len: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// Collection size exceeds limit.
    #[error("collection size exceeds limit: {field} has {actual} items, max is {max}")]
    CollectionTooLarge {
        /// The field name.
        field: &'static str,
        /// Actual size.
        actual: usize,
        /// Maximum allowed size.
        max: usize,
    },

    /// Invalid data in conversion.
    #[error("invalid data: {0}")]
    InvalidData(String),

    /// Signature verification failed.
    #[error("signature verification failed: {0}")]
    SignatureVerificationFailed(String),
}

// =============================================================================
// MergeReceipt
// =============================================================================

/// A receipt proving that a merge was executed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergeReceipt {
    /// Base selector (e.g., branch name "main").
    pub base_selector: String,

    /// Hash of the changeset being merged.
    #[serde(with = "serde_bytes")]
    pub changeset_digest: [u8; 32],

    /// List of gate receipt IDs that authorized this merge.
    pub gate_receipt_ids: Vec<String>,

    /// Policy hash that governed this merge decision.
    #[serde(with = "serde_bytes")]
    pub policy_hash: [u8; 32],

    /// Observed result selector (e.g., new commit SHA).
    pub result_selector: String,

    /// Timestamp when the merge occurred (Unix nanos).
    pub merged_at: u64,

    /// Actor who performed the merge.
    pub gate_actor_id: String,

    /// Ed25519 signature over canonical bytes with MERGE_RECEIPT: domain.
    #[serde(with = "serde_bytes")]
    pub gate_signature: [u8; 64],
}

impl MergeReceipt {
    /// Creates a new `MergeReceipt` after observing the merge result.
    ///
    /// This method enforces the atomic binding between inputs and the observed
    /// result. It canonicalizes the data, signs it with the provided signer
    /// using the `MERGE_RECEIPT:` domain separator, and returns the signed
    /// receipt.
    ///
    /// # Arguments
    ///
    /// * `base_selector` - The branch/ref merged into
    /// * `changeset_digest` - The changeset merged
    /// * `gate_receipt_ids` - IDs of receipts authorizing the merge
    /// * `policy_hash` - The policy hash active during merge
    /// * `result_selector` - The OBSERVED result (e.g., new HEAD SHA)
    /// * `merged_at` - Timestamp of merge
    /// * `gate_actor_id` - ID of the actor performing the merge
    /// * `signer` - Signer to authorize the receipt
    ///
    /// # Returns
    ///
    /// A signed `MergeReceipt` or error if validation fails.
    #[allow(clippy::too_many_arguments)]
    pub fn create_after_observation(
        base_selector: String,
        changeset_digest: [u8; 32],
        gate_receipt_ids: Vec<String>,
        policy_hash: [u8; 32],
        result_selector: String,
        merged_at: u64,
        gate_actor_id: String,
        signer: &Signer,
    ) -> Result<Self, MergeReceiptError> {
        // Validate inputs
        if base_selector.len() > MAX_STRING_LENGTH {
            return Err(MergeReceiptError::StringTooLong {
                field: "base_selector",
                len: base_selector.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if result_selector.len() > MAX_STRING_LENGTH {
            return Err(MergeReceiptError::StringTooLong {
                field: "result_selector",
                len: result_selector.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if gate_actor_id.len() > MAX_STRING_LENGTH {
            return Err(MergeReceiptError::StringTooLong {
                field: "gate_actor_id",
                len: gate_actor_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if gate_receipt_ids.len() > MAX_GATE_RECEIPTS {
            return Err(MergeReceiptError::CollectionTooLarge {
                field: "gate_receipt_ids",
                actual: gate_receipt_ids.len(),
                max: MAX_GATE_RECEIPTS,
            });
        }
        for id in &gate_receipt_ids {
            if id.len() > MAX_STRING_LENGTH {
                return Err(MergeReceiptError::StringTooLong {
                    field: "gate_receipt_ids",
                    len: id.len(),
                    max: MAX_STRING_LENGTH,
                });
            }
        }

        // Construct receipt with placeholder signature
        let mut receipt = Self {
            base_selector,
            changeset_digest,
            gate_receipt_ids,
            policy_hash,
            result_selector,
            merged_at,
            gate_actor_id,
            gate_signature: [0u8; 64],
        };

        // Sign
        let canonical = receipt.canonical_bytes();
        let signature = sign_with_domain(signer, MERGE_RECEIPT_PREFIX, &canonical);
        receipt.gate_signature = signature.to_bytes();

        Ok(receipt)
    }

    /// Computes the canonical bytes for signing/verification.
    ///
    /// Encoding:
    /// - base_selector (len + bytes)
    /// - changeset_digest (32 bytes)
    /// - gate_receipt_ids (count + (len + bytes)...) - sorted!
    /// - policy_hash (32 bytes)
    /// - result_selector (len + bytes)
    /// - merged_at (8 bytes BE)
    /// - gate_actor_id (len + bytes)
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // 1. base_selector
        bytes.extend_from_slice(&(self.base_selector.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.base_selector.as_bytes());

        // 2. changeset_digest
        bytes.extend_from_slice(&self.changeset_digest);

        // 3. gate_receipt_ids (sorted)
        let mut sorted_ids = self.gate_receipt_ids.clone();
        sorted_ids.sort();
        bytes.extend_from_slice(&(sorted_ids.len() as u32).to_be_bytes());
        for id in sorted_ids {
            bytes.extend_from_slice(&(id.len() as u32).to_be_bytes());
            bytes.extend_from_slice(id.as_bytes());
        }

        // 4. policy_hash
        bytes.extend_from_slice(&self.policy_hash);

        // 5. result_selector
        bytes.extend_from_slice(&(self.result_selector.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.result_selector.as_bytes());

        // 6. merged_at
        bytes.extend_from_slice(&self.merged_at.to_be_bytes());

        // 7. gate_actor_id
        bytes.extend_from_slice(&(self.gate_actor_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.gate_actor_id.as_bytes());

        bytes
    }

    /// Verifies the receipt signature.
    pub fn verify_signature(&self, key: &VerifyingKey) -> Result<(), MergeReceiptError> {
        let canonical = self.canonical_bytes();
        let signature = Signature::from_bytes(&self.gate_signature);

        verify_with_domain(key, MERGE_RECEIPT_PREFIX, &canonical, &signature)
            .map_err(|e| MergeReceiptError::SignatureVerificationFailed(e.to_string()))
    }
}

// =============================================================================
// Proto Conversions
// =============================================================================

impl TryFrom<MergeReceiptProto> for MergeReceipt {
    type Error = MergeReceiptError;

    fn try_from(proto: MergeReceiptProto) -> Result<Self, Self::Error> {
        // Validate resource limits
        if proto.base_selector.len() > MAX_STRING_LENGTH {
            return Err(MergeReceiptError::StringTooLong {
                field: "base_selector",
                len: proto.base_selector.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if proto.result_selector.len() > MAX_STRING_LENGTH {
            return Err(MergeReceiptError::StringTooLong {
                field: "result_selector",
                len: proto.result_selector.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if proto.gate_actor_id.len() > MAX_STRING_LENGTH {
            return Err(MergeReceiptError::StringTooLong {
                field: "gate_actor_id",
                len: proto.gate_actor_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if proto.gate_receipt_ids.len() > MAX_GATE_RECEIPTS {
            return Err(MergeReceiptError::CollectionTooLarge {
                field: "gate_receipt_ids",
                actual: proto.gate_receipt_ids.len(),
                max: MAX_GATE_RECEIPTS,
            });
        }
        for id in &proto.gate_receipt_ids {
            if id.len() > MAX_STRING_LENGTH {
                return Err(MergeReceiptError::StringTooLong {
                    field: "gate_receipt_ids",
                    len: id.len(),
                    max: MAX_STRING_LENGTH,
                });
            }
        }

        let changeset_digest = proto.changeset_digest.try_into().map_err(|_| {
            MergeReceiptError::InvalidData("changeset_digest must be 32 bytes".into())
        })?;

        let policy_hash = proto
            .policy_hash
            .try_into()
            .map_err(|_| MergeReceiptError::InvalidData("policy_hash must be 32 bytes".into()))?;

        let gate_signature = proto.gate_signature.try_into().map_err(|_| {
            MergeReceiptError::InvalidData("gate_signature must be 64 bytes".into())
        })?;

        Ok(Self {
            base_selector: proto.base_selector,
            changeset_digest,
            gate_receipt_ids: proto.gate_receipt_ids,
            policy_hash,
            result_selector: proto.result_selector,
            merged_at: proto.merged_at,
            gate_actor_id: proto.gate_actor_id,
            gate_signature,
        })
    }
}

impl From<MergeReceipt> for MergeReceiptProto {
    fn from(receipt: MergeReceipt) -> Self {
        Self {
            base_selector: receipt.base_selector,
            changeset_digest: receipt.changeset_digest.to_vec(),
            gate_receipt_ids: receipt.gate_receipt_ids,
            policy_hash: receipt.policy_hash.to_vec(),
            result_selector: receipt.result_selector,
            merged_at: receipt.merged_at,
            gate_actor_id: receipt.gate_actor_id,
            gate_signature: receipt.gate_signature.to_vec(),
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_atomic_binding() {
        let signer = Signer::generate();
        let receipt = MergeReceipt::create_after_observation(
            "main".to_string(),
            [0x11; 32],
            vec!["receipt-1".to_string()],
            [0x22; 32],
            "sha-123".to_string(),
            1000,
            "gate-1".to_string(),
            &signer,
        )
        .expect("should create receipt");

        // Verify signature binds to all fields
        assert!(receipt.verify_signature(&signer.verifying_key()).is_ok());
    }

    #[test]
    fn test_signature_fails_on_tamper() {
        let signer = Signer::generate();
        let mut receipt = MergeReceipt::create_after_observation(
            "main".to_string(),
            [0x11; 32],
            vec!["receipt-1".to_string()],
            [0x22; 32],
            "sha-123".to_string(),
            1000,
            "gate-1".to_string(),
            &signer,
        )
        .expect("should create receipt");

        // Tamper with result_selector
        receipt.result_selector = "sha-999".to_string();

        assert!(receipt.verify_signature(&signer.verifying_key()).is_err());
    }

    #[test]
    fn test_limit_gate_receipts() {
        let signer = Signer::generate();
        let ids = vec!["id".to_string(); MAX_GATE_RECEIPTS + 1];

        let result = MergeReceipt::create_after_observation(
            "main".to_string(),
            [0x11; 32],
            ids,
            [0x22; 32],
            "sha-123".to_string(),
            1000,
            "gate-1".to_string(),
            &signer,
        );

        assert!(matches!(
            result,
            Err(MergeReceiptError::CollectionTooLarge { .. })
        ));
    }

    #[test]
    fn test_proto_roundtrip() {
        let signer = Signer::generate();
        let original = MergeReceipt::create_after_observation(
            "main".to_string(),
            [0x11; 32],
            vec!["receipt-1".to_string()],
            [0x22; 32],
            "sha-123".to_string(),
            1000,
            "gate-1".to_string(),
            &signer,
        )
        .expect("should create receipt");

        let proto: MergeReceiptProto = original.clone().into();
        let recovered: MergeReceipt = proto.try_into().expect("should convert");

        assert_eq!(original, recovered);
    }
}
