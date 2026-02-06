// AGENT-AUTHORED
//! Gate receipt types for the Forge Admission Cycle.
//!
//! This module defines [`GateReceipt`] which is a versioned envelope for gate
//! execution results. The receipt cryptographically binds a gate's output to a
//! specific lease and changeset.
//!
//! # Versioning Model
//!
//! `GateReceipt` implements a two-level versioning scheme:
//!
//! - **Envelope version** (`receipt_version`): Schema of the receipt envelope
//!   itself. Changes here affect all gate types.
//! - **Payload version** (`payload_schema_version`): Schema of the payload
//!   content. Each payload kind can evolve independently.
//!
//! # Supported Versions
//!
//! - Receipt versions: `[1]` (see [`SUPPORTED_RECEIPT_VERSIONS`])
//! - Payload kinds: `["aat", "quality", "security"]` (see
//!   [`SUPPORTED_PAYLOAD_KINDS`])
//! - Payload schema versions: `[1]` (see [`SUPPORTED_PAYLOAD_SCHEMA_VERSIONS`])
//!
//! # Validation Modes
//!
//! The [`GateReceipt::validate_version`] method supports two modes:
//!
//! - **Enforce mode** (`enforce: true`): Unknown versions are rejected with an
//!   error. Use this for processing receipts that must be fully validated.
//! - **Permissive mode** (`enforce: false`): Unknown versions return `Ok(())`
//!   silently. Use this for logging or archival.
//!
//! # Security Model
//!
//! - Signatures use the `GATE_RECEIPT:` domain prefix
//! - All fields except the signature are included in canonical bytes
//! - Length-prefixed encoding prevents canonicalization collision attacks
//!
//! # Example
//!
//! ```rust
//! use apm2_core::crypto::Signer;
//! use apm2_core::fac::{GateReceipt, GateReceiptBuilder};
//!
//! // Create a gate receipt
//! let signer = Signer::generate();
//! let receipt =
//!     GateReceiptBuilder::new("receipt-001", "gate-aat", "lease-001")
//!         .changeset_digest([0x42; 32])
//!         .executor_actor_id("executor-001")
//!         .receipt_version(1)
//!         .payload_kind("aat")
//!         .payload_schema_version(1)
//!         .payload_hash([0xAB; 32])
//!         .evidence_bundle_hash([0xCD; 32])
//!         .passed(true)
//!         .build_and_sign(&signer);
//!
//! // Validate version in enforce mode
//! assert!(receipt.validate_version(true).is_ok());
//!
//! // Verify signature
//! assert!(receipt.validate_signature(&signer.verifying_key()).is_ok());
//! ```

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::domain_separator::{GATE_RECEIPT_PREFIX, sign_with_domain, verify_with_domain};
use super::policy_resolution::MAX_STRING_LENGTH;
use crate::crypto::{Signature, VerifyingKey};
// Re-export the generated proto type for wire format serialization.
pub use crate::events::GateReceipt as GateReceiptProto;

// =============================================================================
// Version Constants
// =============================================================================

/// Supported receipt envelope versions.
///
/// Currently only version 1 is supported. New versions may be added as the
/// envelope schema evolves.
pub const SUPPORTED_RECEIPT_VERSIONS: &[u32] = &[1];

/// Supported payload kinds.
///
/// - `"aat"`: Agent Acceptance Testing payload
/// - `"quality"`: Quality gate payload (linting, tests, etc.)
/// - `"security"`: Security gate payload (vulnerability scans, etc.)
pub const SUPPORTED_PAYLOAD_KINDS: &[&str] = &["aat", "quality", "security"];

/// Supported payload schema versions.
///
/// Currently only version 1 is supported for all payload kinds. New versions
/// may be added as payload schemas evolve.
pub const SUPPORTED_PAYLOAD_SCHEMA_VERSIONS: &[u32] = &[1];

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during gate receipt operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReceiptError {
    /// The receipt signature is invalid.
    #[error("invalid receipt signature: {0}")]
    InvalidSignature(String),

    /// Missing required field.
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// Invalid receipt data.
    #[error("invalid receipt data: {0}")]
    InvalidData(String),

    /// String field exceeds maximum length.
    #[error("string field {field} exceeds max length: {actual} > {max}")]
    StringTooLong {
        /// Name of the field that exceeded the limit.
        field: &'static str,
        /// Actual length of the string.
        actual: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// Unsupported receipt version.
    #[error("unsupported receipt version: {version}, supported: {supported:?}")]
    UnsupportedVersion {
        /// The unsupported version.
        version: u32,
        /// List of supported versions.
        supported: Vec<u32>,
    },

    /// Unsupported payload kind.
    #[error("unsupported payload kind: {kind}, supported: {supported:?}")]
    UnsupportedPayloadKind {
        /// The unsupported payload kind.
        kind: String,
        /// List of supported payload kinds.
        supported: Vec<String>,
    },

    /// Unsupported payload schema version.
    #[error("unsupported payload schema version: {version}, supported: {supported:?}")]
    UnsupportedPayloadSchemaVersion {
        /// The unsupported payload schema version.
        version: u32,
        /// List of supported payload schema versions.
        supported: Vec<u32>,
    },
}

// =============================================================================
// GateReceipt
// =============================================================================

/// A cryptographically signed gate receipt with versioning support.
///
/// The gate receipt is the canonical envelope for gate execution results. It
/// binds a gate's output to a specific lease and changeset, enabling audit
/// and verification of the gate execution.
///
/// # Fields (11 total)
///
/// - `receipt_id`: Unique identifier for this receipt
/// - `gate_id`: Gate that generated this receipt
/// - `lease_id`: Lease that authorized this gate execution
/// - `changeset_digest`: Hash binding to specific changeset
/// - `executor_actor_id`: Actor who executed the gate
/// - `receipt_version`: Envelope schema version (currently: 1)
/// - `payload_kind`: Type of payload ("aat", "quality", "security")
/// - `payload_schema_version`: Version of the payload schema
/// - `payload_hash`: Hash of the payload content
/// - `evidence_bundle_hash`: Hash of the evidence bundle
/// - `passed`: Explicit pass/fail verdict declared by the executor
/// - `receipt_signature`: Ed25519 signature with domain separation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GateReceipt {
    /// Unique identifier for this receipt.
    pub receipt_id: String,

    /// Gate that generated this receipt.
    pub gate_id: String,

    /// Lease that authorized this gate execution.
    pub lease_id: String,

    /// Hash binding to specific changeset.
    #[serde(with = "serde_bytes")]
    pub changeset_digest: [u8; 32],

    /// Actor who executed the gate.
    pub executor_actor_id: String,

    /// Envelope schema version.
    ///
    /// Current supported versions: `[1]`
    pub receipt_version: u32,

    /// Type of payload.
    ///
    /// Supported kinds: `["aat", "quality", "security"]`
    pub payload_kind: String,

    /// Version of the payload schema.
    pub payload_schema_version: u32,

    /// Hash of the payload content.
    #[serde(with = "serde_bytes")]
    pub payload_hash: [u8; 32],

    /// Hash of the evidence bundle.
    #[serde(with = "serde_bytes")]
    pub evidence_bundle_hash: [u8; 32],

    /// Explicit pass/fail verdict declared by the gate executor.
    ///
    /// This is the authoritative verdict field. The orchestrator uses this
    /// field directly rather than deriving the verdict from hash inspection.
    /// Receipts without an explicit verdict are rejected at the admission
    /// boundary (TCK-00388 Quality BLOCKER 2).
    pub passed: bool,

    /// Ed25519 signature over canonical bytes with domain separation.
    #[serde(with = "serde_bytes")]
    pub receipt_signature: [u8; 64],
}

impl GateReceipt {
    /// Returns the canonical bytes for signing/verification.
    ///
    /// The canonical representation includes all fields except the signature,
    /// encoded in a deterministic order.
    ///
    /// # Encoding
    ///
    /// Uses length-prefixed encoding (4-byte big-endian u32) for
    /// variable-length strings to prevent canonicalization collision
    /// attacks.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // String lengths are validated elsewhere
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let capacity = 4 + self.receipt_id.len()
            + 4 + self.gate_id.len()
            + 4 + self.lease_id.len()
            + 32  // changeset_digest
            + 4 + self.executor_actor_id.len()
            + 4   // receipt_version
            + 4 + self.payload_kind.len()
            + 4   // payload_schema_version
            + 32  // payload_hash
            + 32  // evidence_bundle_hash
            + 1; // passed (bool)

        let mut bytes = Vec::with_capacity(capacity);

        // 1. receipt_id (length-prefixed)
        bytes.extend_from_slice(&(self.receipt_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.receipt_id.as_bytes());

        // 2. gate_id (length-prefixed)
        bytes.extend_from_slice(&(self.gate_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.gate_id.as_bytes());

        // 3. lease_id (length-prefixed)
        bytes.extend_from_slice(&(self.lease_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.lease_id.as_bytes());

        // 4. changeset_digest
        bytes.extend_from_slice(&self.changeset_digest);

        // 5. executor_actor_id (length-prefixed)
        bytes.extend_from_slice(&(self.executor_actor_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.executor_actor_id.as_bytes());

        // 6. receipt_version (big-endian)
        bytes.extend_from_slice(&self.receipt_version.to_be_bytes());

        // 7. payload_kind (length-prefixed)
        bytes.extend_from_slice(&(self.payload_kind.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.payload_kind.as_bytes());

        // 8. payload_schema_version (big-endian)
        bytes.extend_from_slice(&self.payload_schema_version.to_be_bytes());

        // 9. payload_hash
        bytes.extend_from_slice(&self.payload_hash);

        // 10. evidence_bundle_hash
        bytes.extend_from_slice(&self.evidence_bundle_hash);

        // 11. passed (1 byte: 0 = false, 1 = true)
        bytes.push(u8::from(self.passed));

        bytes
    }

    /// Validates the receipt signature using domain separation.
    ///
    /// # Arguments
    ///
    /// * `verifying_key` - The public key of the expected executor
    ///
    /// # Returns
    ///
    /// `Ok(())` if the signature is valid,
    /// `Err(ReceiptError::InvalidSignature)` otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`ReceiptError::InvalidSignature`] if signature verification
    /// fails.
    pub fn validate_signature(&self, verifying_key: &VerifyingKey) -> Result<(), ReceiptError> {
        let signature = Signature::from_bytes(&self.receipt_signature);
        let canonical = self.canonical_bytes();

        verify_with_domain(verifying_key, GATE_RECEIPT_PREFIX, &canonical, &signature)
            .map_err(|e| ReceiptError::InvalidSignature(e.to_string()))
    }

    /// Validates the receipt version, payload kind, and payload schema version.
    ///
    /// # Arguments
    ///
    /// * `enforce` - If `true`, unknown versions/kinds return an error. If
    ///   `false`, unknown versions/kinds are silently accepted (permissive
    ///   mode).
    ///
    /// # Returns
    ///
    /// - `Ok(())` if validation passes (or permissive mode is enabled)
    /// - `Err(ReceiptError::UnsupportedVersion)` if `enforce` is `true` and
    ///   receipt version is unsupported
    /// - `Err(ReceiptError::UnsupportedPayloadKind)` if `enforce` is `true` and
    ///   payload kind is unsupported
    /// - `Err(ReceiptError::UnsupportedPayloadSchemaVersion)` if `enforce` is
    ///   `true` and payload schema version is unsupported
    ///
    /// # Errors
    ///
    /// Returns [`ReceiptError::UnsupportedVersion`] if `enforce` is `true` and
    /// the receipt version is not in [`SUPPORTED_RECEIPT_VERSIONS`].
    ///
    /// Returns [`ReceiptError::UnsupportedPayloadKind`] if `enforce` is `true`
    /// and the payload kind is not in [`SUPPORTED_PAYLOAD_KINDS`].
    ///
    /// Returns [`ReceiptError::UnsupportedPayloadSchemaVersion`] if `enforce`
    /// is `true` and the payload schema version is not in
    /// [`SUPPORTED_PAYLOAD_SCHEMA_VERSIONS`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use apm2_core::crypto::Signer;
    /// use apm2_core::fac::GateReceiptBuilder;
    ///
    /// let signer = Signer::generate();
    /// let receipt =
    ///     GateReceiptBuilder::new("receipt-001", "gate-aat", "lease-001")
    ///         .changeset_digest([0x42; 32])
    ///         .executor_actor_id("executor-001")
    ///         .receipt_version(1)
    ///         .payload_kind("aat")
    ///         .payload_schema_version(1)
    ///         .payload_hash([0xAB; 32])
    ///         .evidence_bundle_hash([0xCD; 32])
    ///         .passed(true)
    ///         .build_and_sign(&signer);
    ///
    /// // Enforce mode: errors on unknown versions
    /// assert!(receipt.validate_version(true).is_ok());
    ///
    /// // Permissive mode: silently accepts unknown versions
    /// assert!(receipt.validate_version(false).is_ok());
    /// ```
    pub fn validate_version(&self, enforce: bool) -> Result<(), ReceiptError> {
        // Check receipt version
        if !SUPPORTED_RECEIPT_VERSIONS.contains(&self.receipt_version) {
            if enforce {
                return Err(ReceiptError::UnsupportedVersion {
                    version: self.receipt_version,
                    supported: SUPPORTED_RECEIPT_VERSIONS.to_vec(),
                });
            }
            return Ok(());
        }

        // Check payload kind
        if !SUPPORTED_PAYLOAD_KINDS.contains(&self.payload_kind.as_str()) {
            if enforce {
                return Err(ReceiptError::UnsupportedPayloadKind {
                    kind: self.payload_kind.clone(),
                    supported: SUPPORTED_PAYLOAD_KINDS
                        .iter()
                        .map(|s| (*s).to_string())
                        .collect(),
                });
            }
            return Ok(());
        }

        // Check payload schema version
        if !SUPPORTED_PAYLOAD_SCHEMA_VERSIONS.contains(&self.payload_schema_version) {
            if enforce {
                return Err(ReceiptError::UnsupportedPayloadSchemaVersion {
                    version: self.payload_schema_version,
                    supported: SUPPORTED_PAYLOAD_SCHEMA_VERSIONS.to_vec(),
                });
            }
            return Ok(());
        }

        Ok(())
    }
}

// =============================================================================
// Builder
// =============================================================================

/// Builder for constructing [`GateReceipt`] instances.
#[derive(Debug, Default)]
pub struct GateReceiptBuilder {
    receipt_id: String,
    gate_id: String,
    lease_id: String,
    changeset_digest: Option<[u8; 32]>,
    executor_actor_id: Option<String>,
    receipt_version: Option<u32>,
    payload_kind: Option<String>,
    payload_schema_version: Option<u32>,
    payload_hash: Option<[u8; 32]>,
    evidence_bundle_hash: Option<[u8; 32]>,
    passed: Option<bool>,
}

impl GateReceiptBuilder {
    /// Creates a new builder with required IDs.
    #[must_use]
    pub fn new(
        receipt_id: impl Into<String>,
        gate_id: impl Into<String>,
        lease_id: impl Into<String>,
    ) -> Self {
        Self {
            receipt_id: receipt_id.into(),
            gate_id: gate_id.into(),
            lease_id: lease_id.into(),
            ..Default::default()
        }
    }

    /// Sets the changeset digest.
    #[must_use]
    pub const fn changeset_digest(mut self, digest: [u8; 32]) -> Self {
        self.changeset_digest = Some(digest);
        self
    }

    /// Sets the executor actor ID.
    #[must_use]
    pub fn executor_actor_id(mut self, actor_id: impl Into<String>) -> Self {
        self.executor_actor_id = Some(actor_id.into());
        self
    }

    /// Sets the receipt envelope version.
    #[must_use]
    pub const fn receipt_version(mut self, version: u32) -> Self {
        self.receipt_version = Some(version);
        self
    }

    /// Sets the payload kind.
    #[must_use]
    pub fn payload_kind(mut self, kind: impl Into<String>) -> Self {
        self.payload_kind = Some(kind.into());
        self
    }

    /// Sets the payload schema version.
    #[must_use]
    pub const fn payload_schema_version(mut self, version: u32) -> Self {
        self.payload_schema_version = Some(version);
        self
    }

    /// Sets the payload hash.
    #[must_use]
    pub const fn payload_hash(mut self, hash: [u8; 32]) -> Self {
        self.payload_hash = Some(hash);
        self
    }

    /// Sets the evidence bundle hash.
    #[must_use]
    pub const fn evidence_bundle_hash(mut self, hash: [u8; 32]) -> Self {
        self.evidence_bundle_hash = Some(hash);
        self
    }

    /// Sets the explicit pass/fail verdict.
    ///
    /// This is the authoritative verdict field that the orchestrator reads
    /// directly. Receipts MUST declare their verdict explicitly rather than
    /// relying on hash-based inference (TCK-00388 Quality BLOCKER 2).
    #[must_use]
    pub const fn passed(mut self, passed: bool) -> Self {
        self.passed = Some(passed);
        self
    }

    /// Builds the receipt and signs it with the provided signer.
    ///
    /// # Panics
    ///
    /// Panics if required fields are missing.
    #[must_use]
    pub fn build_and_sign(self, signer: &crate::crypto::Signer) -> GateReceipt {
        self.try_build_and_sign(signer)
            .expect("missing required field")
    }

    /// Attempts to build and sign the receipt.
    ///
    /// # Errors
    ///
    /// Returns [`ReceiptError::MissingField`] if any required field is not set.
    /// Returns [`ReceiptError::StringTooLong`] if any string field exceeds the
    /// maximum length.
    #[allow(clippy::too_many_lines)]
    pub fn try_build_and_sign(
        self,
        signer: &crate::crypto::Signer,
    ) -> Result<GateReceipt, ReceiptError> {
        let changeset_digest = self
            .changeset_digest
            .ok_or(ReceiptError::MissingField("changeset_digest"))?;
        let executor_actor_id = self
            .executor_actor_id
            .ok_or(ReceiptError::MissingField("executor_actor_id"))?;
        let receipt_version = self
            .receipt_version
            .ok_or(ReceiptError::MissingField("receipt_version"))?;
        let payload_kind = self
            .payload_kind
            .ok_or(ReceiptError::MissingField("payload_kind"))?;
        let payload_schema_version = self
            .payload_schema_version
            .ok_or(ReceiptError::MissingField("payload_schema_version"))?;
        let payload_hash = self
            .payload_hash
            .ok_or(ReceiptError::MissingField("payload_hash"))?;
        let evidence_bundle_hash = self
            .evidence_bundle_hash
            .ok_or(ReceiptError::MissingField("evidence_bundle_hash"))?;
        let passed = self.passed.ok_or(ReceiptError::MissingField("passed"))?;

        // Validate string lengths to prevent DoS
        if self.receipt_id.len() > MAX_STRING_LENGTH {
            return Err(ReceiptError::StringTooLong {
                field: "receipt_id",
                actual: self.receipt_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if self.gate_id.len() > MAX_STRING_LENGTH {
            return Err(ReceiptError::StringTooLong {
                field: "gate_id",
                actual: self.gate_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if self.lease_id.len() > MAX_STRING_LENGTH {
            return Err(ReceiptError::StringTooLong {
                field: "lease_id",
                actual: self.lease_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if executor_actor_id.len() > MAX_STRING_LENGTH {
            return Err(ReceiptError::StringTooLong {
                field: "executor_actor_id",
                actual: executor_actor_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if payload_kind.len() > MAX_STRING_LENGTH {
            return Err(ReceiptError::StringTooLong {
                field: "payload_kind",
                actual: payload_kind.len(),
                max: MAX_STRING_LENGTH,
            });
        }

        // Create receipt with placeholder signature
        let mut receipt = GateReceipt {
            receipt_id: self.receipt_id,
            gate_id: self.gate_id,
            lease_id: self.lease_id,
            changeset_digest,
            executor_actor_id,
            receipt_version,
            payload_kind,
            payload_schema_version,
            payload_hash,
            evidence_bundle_hash,
            passed,
            receipt_signature: [0u8; 64],
        };

        // Sign the canonical bytes
        let canonical = receipt.canonical_bytes();
        let signature = sign_with_domain(signer, GATE_RECEIPT_PREFIX, &canonical);
        receipt.receipt_signature = signature.to_bytes();

        Ok(receipt)
    }
}

// =============================================================================
// Proto Message Conversion
// =============================================================================

impl TryFrom<GateReceiptProto> for GateReceipt {
    type Error = ReceiptError;

    fn try_from(proto: GateReceiptProto) -> Result<Self, Self::Error> {
        // Validate string lengths to prevent DoS
        if proto.receipt_id.len() > MAX_STRING_LENGTH {
            return Err(ReceiptError::StringTooLong {
                field: "receipt_id",
                actual: proto.receipt_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if proto.gate_id.len() > MAX_STRING_LENGTH {
            return Err(ReceiptError::StringTooLong {
                field: "gate_id",
                actual: proto.gate_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if proto.lease_id.len() > MAX_STRING_LENGTH {
            return Err(ReceiptError::StringTooLong {
                field: "lease_id",
                actual: proto.lease_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if proto.executor_actor_id.len() > MAX_STRING_LENGTH {
            return Err(ReceiptError::StringTooLong {
                field: "executor_actor_id",
                actual: proto.executor_actor_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if proto.payload_kind.len() > MAX_STRING_LENGTH {
            return Err(ReceiptError::StringTooLong {
                field: "payload_kind",
                actual: proto.payload_kind.len(),
                max: MAX_STRING_LENGTH,
            });
        }

        let changeset_digest: [u8; 32] = proto.changeset_digest.try_into().map_err(|_| {
            ReceiptError::InvalidData("changeset_digest must be 32 bytes".to_string())
        })?;

        let payload_hash: [u8; 32] = proto
            .payload_hash
            .try_into()
            .map_err(|_| ReceiptError::InvalidData("payload_hash must be 32 bytes".to_string()))?;

        let evidence_bundle_hash: [u8; 32] =
            proto.evidence_bundle_hash.try_into().map_err(|_| {
                ReceiptError::InvalidData("evidence_bundle_hash must be 32 bytes".to_string())
            })?;

        let receipt_signature: [u8; 64] = proto.receipt_signature.try_into().map_err(|_| {
            ReceiptError::InvalidData("receipt_signature must be 64 bytes".to_string())
        })?;

        Ok(Self {
            receipt_id: proto.receipt_id,
            gate_id: proto.gate_id,
            lease_id: proto.lease_id,
            changeset_digest,
            executor_actor_id: proto.executor_actor_id,
            receipt_version: proto.receipt_version,
            payload_kind: proto.payload_kind,
            payload_schema_version: proto.payload_schema_version,
            payload_hash,
            evidence_bundle_hash,
            passed: proto.passed,
            receipt_signature,
        })
    }
}

impl From<GateReceipt> for GateReceiptProto {
    fn from(receipt: GateReceipt) -> Self {
        Self {
            receipt_id: receipt.receipt_id,
            gate_id: receipt.gate_id,
            lease_id: receipt.lease_id,
            changeset_digest: receipt.changeset_digest.to_vec(),
            executor_actor_id: receipt.executor_actor_id,
            receipt_version: receipt.receipt_version,
            payload_kind: receipt.payload_kind,
            payload_schema_version: receipt.payload_schema_version,
            payload_hash: receipt.payload_hash.to_vec(),
            evidence_bundle_hash: receipt.evidence_bundle_hash.to_vec(),
            receipt_signature: receipt.receipt_signature.to_vec(),
            // HTF time envelope reference (RFC-0016): not yet populated by this conversion.
            // The daemon clock service (TCK-00240) will stamp envelopes at runtime boundaries.
            time_envelope_ref: None,
            passed: receipt.passed,
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
pub mod tests {
    use prost::Message;

    use super::*;
    use crate::crypto::Signer;

    fn create_test_receipt(signer: &Signer) -> GateReceipt {
        GateReceiptBuilder::new("receipt-001", "gate-aat", "lease-001")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .receipt_version(1)
            .payload_kind("aat")
            .payload_schema_version(1)
            .payload_hash([0xAB; 32])
            .evidence_bundle_hash([0xCD; 32])
            .passed(true)
            .build_and_sign(signer)
    }

    #[test]
    fn test_build_and_sign() {
        let signer = Signer::generate();
        let receipt = create_test_receipt(&signer);

        assert_eq!(receipt.receipt_id, "receipt-001");
        assert_eq!(receipt.gate_id, "gate-aat");
        assert_eq!(receipt.lease_id, "lease-001");
        assert_eq!(receipt.changeset_digest, [0x42; 32]);
        assert_eq!(receipt.executor_actor_id, "executor-001");
        assert_eq!(receipt.receipt_version, 1);
        assert_eq!(receipt.payload_kind, "aat");
        assert_eq!(receipt.payload_schema_version, 1);
        assert_eq!(receipt.payload_hash, [0xAB; 32]);
        assert_eq!(receipt.evidence_bundle_hash, [0xCD; 32]);
    }

    #[test]
    fn test_signature_validation() {
        let signer = Signer::generate();
        let receipt = create_test_receipt(&signer);

        // Valid signature
        assert!(receipt.validate_signature(&signer.verifying_key()).is_ok());

        // Wrong key should fail
        let other_signer = Signer::generate();
        assert!(
            receipt
                .validate_signature(&other_signer.verifying_key())
                .is_err()
        );
    }

    #[test]
    fn test_signature_binds_to_content() {
        let signer = Signer::generate();
        let mut receipt = create_test_receipt(&signer);

        // Modify content after signing
        receipt.gate_id = "gate-other".to_string();

        // Signature should now be invalid
        assert!(receipt.validate_signature(&signer.verifying_key()).is_err());
    }

    #[test]
    fn test_canonical_bytes_deterministic() {
        let signer = Signer::generate();
        let receipt1 = create_test_receipt(&signer);
        let receipt2 = create_test_receipt(&signer);

        // Same content should produce same canonical bytes
        assert_eq!(receipt1.canonical_bytes(), receipt2.canonical_bytes());
    }

    #[test]
    fn test_missing_field_error() {
        let signer = Signer::generate();

        // Missing changeset_digest
        let result = GateReceiptBuilder::new("receipt-001", "gate-aat", "lease-001")
            .executor_actor_id("executor-001")
            .receipt_version(1)
            .payload_kind("aat")
            .payload_schema_version(1)
            .payload_hash([0xAB; 32])
            .evidence_bundle_hash([0xCD; 32])
            .passed(true)
            .try_build_and_sign(&signer);

        assert!(matches!(
            result,
            Err(ReceiptError::MissingField("changeset_digest"))
        ));
    }

    #[test]
    fn test_domain_separator_prevents_replay() {
        // Verify that receipt uses GATE_RECEIPT: domain separator
        // by ensuring a signature created without the prefix fails
        let signer = Signer::generate();
        let receipt = create_test_receipt(&signer);

        // Create a signature without domain prefix
        let canonical = receipt.canonical_bytes();
        let wrong_signature = signer.sign(&canonical); // No domain prefix!

        // Manually create a receipt with the wrong signature
        let mut bad_receipt = receipt;
        bad_receipt.receipt_signature = wrong_signature.to_bytes();

        // Verification should fail
        assert!(
            bad_receipt
                .validate_signature(&signer.verifying_key())
                .is_err()
        );
    }

    #[test]
    fn test_length_prefixed_canonicalization_prevents_collision() {
        let signer = Signer::generate();

        // Create two receipts with different field values that could collide
        // with null-termination but not with length-prefixing
        let receipt1 = GateReceiptBuilder::new("ab", "cd", "ef")
            .changeset_digest([0x42; 32])
            .executor_actor_id("gh")
            .receipt_version(1)
            .payload_kind("aat")
            .payload_schema_version(1)
            .payload_hash([0xAB; 32])
            .evidence_bundle_hash([0xCD; 32])
            .passed(true)
            .build_and_sign(&signer);

        // "ab" + "cd" should NOT equal "a" + "bcd" with length-prefixing
        let receipt2 = GateReceiptBuilder::new("a", "bcd", "ef")
            .changeset_digest([0x42; 32])
            .executor_actor_id("gh")
            .receipt_version(1)
            .payload_kind("aat")
            .payload_schema_version(1)
            .payload_hash([0xAB; 32])
            .evidence_bundle_hash([0xCD; 32])
            .passed(true)
            .build_and_sign(&signer);

        // Canonical bytes should be different
        assert_ne!(receipt1.canonical_bytes(), receipt2.canonical_bytes());
    }

    // =========================================================================
    // Version Validation Tests
    // =========================================================================

    #[test]
    fn test_validate_version_supported_version() {
        let signer = Signer::generate();
        let receipt = create_test_receipt(&signer);

        // Enforce mode - valid receipt should return Ok(())
        assert!(receipt.validate_version(true).is_ok());

        // Permissive mode - valid receipt should return Ok(())
        assert!(receipt.validate_version(false).is_ok());
    }

    #[test]
    fn test_validate_version_unsupported_version_enforce() {
        let signer = Signer::generate();
        let mut receipt = create_test_receipt(&signer);
        receipt.receipt_version = 999; // Unsupported version

        let result = receipt.validate_version(true);
        assert!(matches!(
            result,
            Err(ReceiptError::UnsupportedVersion { version: 999, .. })
        ));
    }

    #[test]
    fn test_validate_version_unsupported_version_permissive() {
        let signer = Signer::generate();
        let mut receipt = create_test_receipt(&signer);
        receipt.receipt_version = 999; // Unsupported version

        // Permissive mode: returns Ok(()) even for unsupported versions
        assert!(receipt.validate_version(false).is_ok());
    }

    #[test]
    fn test_validate_version_unsupported_payload_kind_enforce() {
        let signer = Signer::generate();
        let mut receipt = create_test_receipt(&signer);
        receipt.payload_kind = "unknown".to_string(); // Unsupported kind

        let result = receipt.validate_version(true);
        assert!(matches!(
            result,
            Err(ReceiptError::UnsupportedPayloadKind { kind, .. }) if kind == "unknown"
        ));
    }

    #[test]
    fn test_validate_version_unsupported_payload_kind_permissive() {
        let signer = Signer::generate();
        let mut receipt = create_test_receipt(&signer);
        receipt.payload_kind = "unknown".to_string(); // Unsupported kind

        // Permissive mode: returns Ok(()) even for unsupported payload kinds
        assert!(receipt.validate_version(false).is_ok());
    }

    #[test]
    fn test_validate_version_unsupported_payload_schema_version_enforce() {
        let signer = Signer::generate();
        let mut receipt = create_test_receipt(&signer);
        receipt.payload_schema_version = 999; // Unsupported payload schema version

        let result = receipt.validate_version(true);
        assert!(matches!(
            result,
            Err(ReceiptError::UnsupportedPayloadSchemaVersion { version: 999, .. })
        ));
    }

    #[test]
    fn test_validate_version_unsupported_payload_schema_version_permissive() {
        let signer = Signer::generate();
        let mut receipt = create_test_receipt(&signer);
        receipt.payload_schema_version = 999; // Unsupported payload schema version

        // Permissive mode: returns Ok(()) even for unsupported payload schema versions
        assert!(receipt.validate_version(false).is_ok());
    }

    #[test]
    fn test_all_supported_payload_kinds() {
        let signer = Signer::generate();

        for kind in SUPPORTED_PAYLOAD_KINDS {
            let receipt = GateReceiptBuilder::new("receipt-001", "gate-test", "lease-001")
                .changeset_digest([0x42; 32])
                .executor_actor_id("executor-001")
                .receipt_version(1)
                .payload_kind(*kind)
                .payload_schema_version(1)
                .payload_hash([0xAB; 32])
                .evidence_bundle_hash([0xCD; 32])
                .passed(true)
                .build_and_sign(&signer);

            assert!(
                receipt.validate_version(true).is_ok(),
                "payload_kind '{kind}' should be supported"
            );
        }
    }

    #[test]
    fn test_supported_receipt_versions_constant() {
        // Verify version 1 is supported
        assert!(SUPPORTED_RECEIPT_VERSIONS.contains(&1));
    }

    #[test]
    fn test_supported_payload_kinds_constant() {
        // Verify expected payload kinds
        assert!(SUPPORTED_PAYLOAD_KINDS.contains(&"aat"));
        assert!(SUPPORTED_PAYLOAD_KINDS.contains(&"quality"));
        assert!(SUPPORTED_PAYLOAD_KINDS.contains(&"security"));
    }

    #[test]
    fn test_supported_payload_schema_versions_constant() {
        // Verify version 1 is supported
        assert!(SUPPORTED_PAYLOAD_SCHEMA_VERSIONS.contains(&1));
    }

    // =========================================================================
    // Proto Roundtrip Tests
    // =========================================================================

    #[test]
    fn test_proto_roundtrip() {
        let signer = Signer::generate();
        let original = create_test_receipt(&signer);

        // Convert to proto
        let proto: GateReceiptProto = original.clone().into();

        // Encode and decode
        let encoded = proto.encode_to_vec();
        let decoded_proto = GateReceiptProto::decode(encoded.as_slice()).unwrap();

        // Convert back to domain type
        let recovered = GateReceipt::try_from(decoded_proto).unwrap();

        // Fields should match
        assert_eq!(original.receipt_id, recovered.receipt_id);
        assert_eq!(original.gate_id, recovered.gate_id);
        assert_eq!(original.lease_id, recovered.lease_id);
        assert_eq!(original.changeset_digest, recovered.changeset_digest);
        assert_eq!(original.executor_actor_id, recovered.executor_actor_id);
        assert_eq!(original.receipt_version, recovered.receipt_version);
        assert_eq!(original.payload_kind, recovered.payload_kind);
        assert_eq!(
            original.payload_schema_version,
            recovered.payload_schema_version
        );
        assert_eq!(original.payload_hash, recovered.payload_hash);
        assert_eq!(
            original.evidence_bundle_hash,
            recovered.evidence_bundle_hash
        );
        assert_eq!(original.receipt_signature, recovered.receipt_signature);

        // Signature should still be valid
        assert!(
            recovered
                .validate_signature(&signer.verifying_key())
                .is_ok()
        );
    }

    #[test]
    fn test_invalid_proto_changeset_digest_length() {
        let proto = GateReceiptProto {
            receipt_id: "receipt-001".to_string(),
            gate_id: "gate-aat".to_string(),
            lease_id: "lease-001".to_string(),
            changeset_digest: vec![0x42; 16], // Wrong length - should be 32
            executor_actor_id: "executor-001".to_string(),
            receipt_version: 1,
            payload_kind: "aat".to_string(),
            payload_schema_version: 1,
            payload_hash: vec![0xAB; 32],
            evidence_bundle_hash: vec![0xCD; 32],
            receipt_signature: vec![0u8; 64],
            // HTF time envelope reference (RFC-0016): not yet populated.
            time_envelope_ref: None,
            passed: false,
        };

        let result = GateReceipt::try_from(proto);
        assert!(matches!(result, Err(ReceiptError::InvalidData(_))));
    }

    #[test]
    fn test_invalid_proto_signature_length() {
        let proto = GateReceiptProto {
            receipt_id: "receipt-001".to_string(),
            gate_id: "gate-aat".to_string(),
            lease_id: "lease-001".to_string(),
            changeset_digest: vec![0x42; 32],
            executor_actor_id: "executor-001".to_string(),
            receipt_version: 1,
            payload_kind: "aat".to_string(),
            payload_schema_version: 1,
            payload_hash: vec![0xAB; 32],
            evidence_bundle_hash: vec![0xCD; 32],
            receipt_signature: vec![0u8; 32], // Wrong length - should be 64
            // HTF time envelope reference (RFC-0016): not yet populated.
            time_envelope_ref: None,
            passed: false,
        };

        let result = GateReceipt::try_from(proto);
        assert!(matches!(result, Err(ReceiptError::InvalidData(_))));
    }

    #[test]
    fn test_string_too_long_rejected() {
        let signer = Signer::generate();
        let long_string = "x".repeat(MAX_STRING_LENGTH + 1);

        let result = GateReceiptBuilder::new(long_string, "gate-aat", "lease-001")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .receipt_version(1)
            .payload_kind("aat")
            .payload_schema_version(1)
            .payload_hash([0xAB; 32])
            .evidence_bundle_hash([0xCD; 32])
            .passed(true)
            .try_build_and_sign(&signer);

        assert!(matches!(
            result,
            Err(ReceiptError::StringTooLong {
                field: "receipt_id",
                ..
            })
        ));
    }

    #[test]
    fn test_proto_string_too_long_rejected() {
        let long_string = "x".repeat(MAX_STRING_LENGTH + 1);
        let proto = GateReceiptProto {
            receipt_id: long_string,
            gate_id: "gate-aat".to_string(),
            lease_id: "lease-001".to_string(),
            changeset_digest: vec![0x42; 32],
            executor_actor_id: "executor-001".to_string(),
            receipt_version: 1,
            payload_kind: "aat".to_string(),
            payload_schema_version: 1,
            payload_hash: vec![0xAB; 32],
            evidence_bundle_hash: vec![0xCD; 32],
            receipt_signature: vec![0u8; 64],
            // HTF time envelope reference (RFC-0016): not yet populated.
            time_envelope_ref: None,
            passed: false,
        };

        let result = GateReceipt::try_from(proto);
        assert!(matches!(
            result,
            Err(ReceiptError::StringTooLong {
                field: "receipt_id",
                ..
            })
        ));
    }
}
