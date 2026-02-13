// AGENT-AUTHORED
//! Tool execution receipt types for proof-carrying tool actuation.
//!
//! This module implements [`ToolExecutionReceipt`] per TCK-00327 and RFC-0019.
//! Each tool actuation produces a signed receipt that binds:
//! - Episode/policy/request/capability context
//! - Arguments hash and result hash
//! - Time envelope and duration
//!
//! # Security Model
//!
//! - **Domain Separation**: Signatures use `TOOL_EXECUTION_RECEIPT:` prefix
//! - **Hash Binding**: Args and results are bound by BLAKE3 hashes to CAS
//! - **Temporal Authority**: Time envelope provides HTF ordering
//! - **Capability Binding**: Receipt binds to the capability that authorized it
//!
//! # Example
//!
//! ```rust
//! use apm2_core::crypto::Signer;
//! use apm2_core::fac::ToolExecutionReceiptBuilder;
//!
//! let signer = Signer::generate();
//! let receipt = ToolExecutionReceiptBuilder::new()
//!     .episode_id("ep-001")
//!     .policy_hash([0x11; 32])
//!     .request_id("req-001")
//!     .capability_id("cap-001")
//!     .tool_class("Read")
//!     .args_hash([0x22; 32])
//!     .result_hash([0x33; 32])
//!     .time_envelope_ref([0x44; 32])
//!     .started_at_ns(1000000000)
//!     .duration_ns(5000000)
//!     .build_and_sign(&signer)
//!     .expect("valid receipt");
//!
//! assert!(receipt.verify_signature(&signer.verifying_key()).is_ok());
//! ```

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::domain_separator::{sign_with_domain, verify_with_domain};
use crate::crypto::{Signature, Signer, VerifyingKey};

// =============================================================================
// Domain Separator
// =============================================================================

/// Domain prefix for `ToolExecutionReceipt` signatures.
pub const TOOL_EXECUTION_RECEIPT_PREFIX: &[u8] = b"TOOL_EXECUTION_RECEIPT:";

// =============================================================================
// Resource Limits
// =============================================================================

/// Maximum length for episode ID.
pub const MAX_EPISODE_ID_LENGTH: usize = 128;

/// Maximum length for request ID.
pub const MAX_REQUEST_ID_LENGTH: usize = 256;

/// Maximum length for capability ID.
pub const MAX_CAPABILITY_ID_LENGTH: usize = 128;

/// Maximum length for tool class string.
pub const MAX_TOOL_CLASS_LENGTH: usize = 64;

/// Schema identifier for `ToolExecutionReceipt`.
pub const TOOL_EXECUTION_RECEIPT_SCHEMA: &str = "apm2.tool_execution_receipt.v1";

/// Current schema version.
pub const TOOL_EXECUTION_RECEIPT_VERSION: &str = "1.0.0";

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during tool execution receipt operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ToolExecutionReceiptError {
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

    /// Signature verification failed.
    #[error("signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    /// Invalid data in conversion.
    #[error("invalid data: {0}")]
    InvalidData(String),
}

// =============================================================================
// ToolExecutionReceipt
// =============================================================================

/// A signed receipt proving a tool call occurred.
///
/// This receipt binds the tool execution to its context (episode, policy,
/// capability) and evidence (`args_hash`, `result_hash`, time envelope).
///
/// # Fields
///
/// - `episode_id`: Episode this tool execution belongs to
/// - `policy_hash`: Hash of the policy that authorized the execution
/// - `request_id`: Unique request ID for this tool call
/// - `capability_id`: Capability that authorized this tool call
/// - `tool_class`: Classification of the tool (Read, Write, Execute, etc.)
/// - `args_hash`: BLAKE3 hash of tool arguments in CAS
/// - `result_hash`: BLAKE3 hash of tool result in CAS
/// - `time_envelope_ref`: HTF time envelope reference (32 bytes)
/// - `started_at_ns`: Timestamp when execution started (nanoseconds)
/// - `duration_ns`: Duration of execution (nanoseconds)
/// - `signer_identity`: Hex-encoded public key of signer
/// - `signature`: Ed25519 signature with domain separation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolExecutionReceipt {
    /// Schema identifier.
    pub schema: String,
    /// Schema version.
    pub schema_version: String,
    /// Episode this tool execution belongs to.
    pub episode_id: String,
    /// Hash of the policy that authorized the execution (32 bytes).
    #[serde(with = "serde_bytes")]
    pub policy_hash: [u8; 32],
    /// Unique request ID for this tool call.
    pub request_id: String,
    /// Capability that authorized this tool call.
    pub capability_id: String,
    /// Classification of the tool (e.g., "Read", "Write", "Execute").
    pub tool_class: String,
    /// BLAKE3 hash of tool arguments stored in CAS (32 bytes).
    #[serde(with = "serde_bytes")]
    pub args_hash: [u8; 32],
    /// BLAKE3 hash of tool result stored in CAS (32 bytes).
    #[serde(with = "serde_bytes")]
    pub result_hash: [u8; 32],
    /// HTF time envelope reference hash (32 bytes).
    #[serde(with = "serde_bytes")]
    pub time_envelope_ref: [u8; 32],
    /// Timestamp when execution started (nanoseconds since epoch).
    pub started_at_ns: u64,
    /// Duration of execution (nanoseconds).
    pub duration_ns: u64,
    /// Hex-encoded public key of signer.
    pub signer_identity: String,
    /// Ed25519 signature over canonical bytes with domain separation.
    #[serde(with = "serde_bytes")]
    pub signature: [u8; 64],
}

impl ToolExecutionReceipt {
    /// Computes the canonical bytes for signing/verification.
    ///
    /// Encoding order (length-prefixed for variable-length fields):
    /// 1. `schema` (len + bytes)
    /// 2. `schema_version` (len + bytes)
    /// 3. `episode_id` (len + bytes)
    /// 4. `policy_hash` (32 bytes)
    /// 5. `request_id` (len + bytes)
    /// 6. `capability_id` (len + bytes)
    /// 7. `tool_class` (len + bytes)
    /// 8. `args_hash` (32 bytes)
    /// 9. `result_hash` (32 bytes)
    /// 10. `time_envelope_ref` (32 bytes)
    /// 11. `started_at_ns` (8 bytes, big-endian)
    /// 12. `duration_ns` (8 bytes, big-endian)
    /// 13. `signer_identity` (len + bytes)
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // 1. schema
        bytes.extend_from_slice(&(self.schema.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.schema.as_bytes());

        // 2. schema_version
        bytes.extend_from_slice(&(self.schema_version.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.schema_version.as_bytes());

        // 3. episode_id
        bytes.extend_from_slice(&(self.episode_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.episode_id.as_bytes());

        // 4. policy_hash
        bytes.extend_from_slice(&self.policy_hash);

        // 5. request_id
        bytes.extend_from_slice(&(self.request_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.request_id.as_bytes());

        // 6. capability_id
        bytes.extend_from_slice(&(self.capability_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.capability_id.as_bytes());

        // 7. tool_class
        bytes.extend_from_slice(&(self.tool_class.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.tool_class.as_bytes());

        // 8. args_hash
        bytes.extend_from_slice(&self.args_hash);

        // 9. result_hash
        bytes.extend_from_slice(&self.result_hash);

        // 10. time_envelope_ref
        bytes.extend_from_slice(&self.time_envelope_ref);

        // 11. started_at_ns
        bytes.extend_from_slice(&self.started_at_ns.to_be_bytes());

        // 12. duration_ns
        bytes.extend_from_slice(&self.duration_ns.to_be_bytes());

        // 13. signer_identity
        bytes.extend_from_slice(&(self.signer_identity.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.signer_identity.as_bytes());

        bytes
    }

    /// Verifies the receipt signature.
    ///
    /// # Errors
    ///
    /// Returns error if the signature doesn't match the canonical bytes.
    pub fn verify_signature(&self, key: &VerifyingKey) -> Result<(), ToolExecutionReceiptError> {
        let canonical = self.canonical_bytes();
        let signature = Signature::from_bytes(&self.signature);

        verify_with_domain(key, TOOL_EXECUTION_RECEIPT_PREFIX, &canonical, &signature)
            .map_err(|e| ToolExecutionReceiptError::SignatureVerificationFailed(e.to_string()))
    }

    /// Computes the CAS hash of this receipt.
    ///
    /// # Panics
    ///
    /// Panics if JSON serialization fails, which should not happen for valid
    /// receipts.
    #[must_use]
    pub fn compute_cas_hash(&self) -> [u8; 32] {
        let json = serde_json::to_vec(self).expect("ToolExecutionReceipt is always serializable");
        *blake3::hash(&json).as_bytes()
    }

    /// Validates the receipt structure.
    ///
    /// # Errors
    ///
    /// Returns error if validation fails.
    pub fn validate(&self) -> Result<(), ToolExecutionReceiptError> {
        // Validate schema
        if self.schema != TOOL_EXECUTION_RECEIPT_SCHEMA {
            return Err(ToolExecutionReceiptError::InvalidData(format!(
                "invalid schema: expected {TOOL_EXECUTION_RECEIPT_SCHEMA}, got {}",
                self.schema
            )));
        }

        // Validate episode_id
        if self.episode_id.is_empty() {
            return Err(ToolExecutionReceiptError::MissingField("episode_id"));
        }
        if self.episode_id.len() > MAX_EPISODE_ID_LENGTH {
            return Err(ToolExecutionReceiptError::StringTooLong {
                field: "episode_id",
                len: self.episode_id.len(),
                max: MAX_EPISODE_ID_LENGTH,
            });
        }

        // Validate request_id
        if self.request_id.is_empty() {
            return Err(ToolExecutionReceiptError::MissingField("request_id"));
        }
        if self.request_id.len() > MAX_REQUEST_ID_LENGTH {
            return Err(ToolExecutionReceiptError::StringTooLong {
                field: "request_id",
                len: self.request_id.len(),
                max: MAX_REQUEST_ID_LENGTH,
            });
        }

        // Validate capability_id
        if self.capability_id.is_empty() {
            return Err(ToolExecutionReceiptError::MissingField("capability_id"));
        }
        if self.capability_id.len() > MAX_CAPABILITY_ID_LENGTH {
            return Err(ToolExecutionReceiptError::StringTooLong {
                field: "capability_id",
                len: self.capability_id.len(),
                max: MAX_CAPABILITY_ID_LENGTH,
            });
        }

        // Validate tool_class
        if self.tool_class.is_empty() {
            return Err(ToolExecutionReceiptError::MissingField("tool_class"));
        }
        if self.tool_class.len() > MAX_TOOL_CLASS_LENGTH {
            return Err(ToolExecutionReceiptError::StringTooLong {
                field: "tool_class",
                len: self.tool_class.len(),
                max: MAX_TOOL_CLASS_LENGTH,
            });
        }

        Ok(())
    }
}

// =============================================================================
// ToolExecutionReceiptBuilder
// =============================================================================

/// Builder for constructing a `ToolExecutionReceipt`.
#[derive(Debug, Default)]
pub struct ToolExecutionReceiptBuilder {
    episode_id: Option<String>,
    policy_hash: Option<[u8; 32]>,
    request_id: Option<String>,
    capability_id: Option<String>,
    tool_class: Option<String>,
    args_hash: Option<[u8; 32]>,
    result_hash: Option<[u8; 32]>,
    time_envelope_ref: Option<[u8; 32]>,
    started_at_ns: Option<u64>,
    duration_ns: Option<u64>,
}

#[allow(clippy::missing_const_for_fn)]
impl ToolExecutionReceiptBuilder {
    /// Creates a new builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the episode ID.
    #[must_use]
    pub fn episode_id(mut self, id: impl Into<String>) -> Self {
        self.episode_id = Some(id.into());
        self
    }

    /// Sets the policy hash.
    #[must_use]
    pub fn policy_hash(mut self, hash: [u8; 32]) -> Self {
        self.policy_hash = Some(hash);
        self
    }

    /// Sets the request ID.
    #[must_use]
    pub fn request_id(mut self, id: impl Into<String>) -> Self {
        self.request_id = Some(id.into());
        self
    }

    /// Sets the capability ID.
    #[must_use]
    pub fn capability_id(mut self, id: impl Into<String>) -> Self {
        self.capability_id = Some(id.into());
        self
    }

    /// Sets the tool class.
    #[must_use]
    pub fn tool_class(mut self, class: impl Into<String>) -> Self {
        self.tool_class = Some(class.into());
        self
    }

    /// Sets the args hash.
    #[must_use]
    pub fn args_hash(mut self, hash: [u8; 32]) -> Self {
        self.args_hash = Some(hash);
        self
    }

    /// Sets the result hash.
    #[must_use]
    pub fn result_hash(mut self, hash: [u8; 32]) -> Self {
        self.result_hash = Some(hash);
        self
    }

    /// Sets the time envelope reference.
    #[must_use]
    pub fn time_envelope_ref(mut self, hash: [u8; 32]) -> Self {
        self.time_envelope_ref = Some(hash);
        self
    }

    /// Sets the start timestamp.
    #[must_use]
    pub fn started_at_ns(mut self, ns: u64) -> Self {
        self.started_at_ns = Some(ns);
        self
    }

    /// Sets the duration.
    #[must_use]
    pub fn duration_ns(mut self, ns: u64) -> Self {
        self.duration_ns = Some(ns);
        self
    }

    /// Builds and signs the receipt.
    ///
    /// # Errors
    ///
    /// Returns error if required fields are missing or validation fails.
    pub fn build_and_sign(
        self,
        signer: &Signer,
    ) -> Result<ToolExecutionReceipt, ToolExecutionReceiptError> {
        let episode_id = self
            .episode_id
            .ok_or(ToolExecutionReceiptError::MissingField("episode_id"))?;
        let policy_hash = self
            .policy_hash
            .ok_or(ToolExecutionReceiptError::MissingField("policy_hash"))?;
        let request_id = self
            .request_id
            .ok_or(ToolExecutionReceiptError::MissingField("request_id"))?;
        let capability_id = self
            .capability_id
            .ok_or(ToolExecutionReceiptError::MissingField("capability_id"))?;
        let tool_class = self
            .tool_class
            .ok_or(ToolExecutionReceiptError::MissingField("tool_class"))?;
        let args_hash = self
            .args_hash
            .ok_or(ToolExecutionReceiptError::MissingField("args_hash"))?;
        let result_hash = self
            .result_hash
            .ok_or(ToolExecutionReceiptError::MissingField("result_hash"))?;
        let time_envelope_ref = self
            .time_envelope_ref
            .ok_or(ToolExecutionReceiptError::MissingField("time_envelope_ref"))?;
        let started_at_ns = self
            .started_at_ns
            .ok_or(ToolExecutionReceiptError::MissingField("started_at_ns"))?;
        let duration_ns = self
            .duration_ns
            .ok_or(ToolExecutionReceiptError::MissingField("duration_ns"))?;

        // Validate lengths
        if episode_id.len() > MAX_EPISODE_ID_LENGTH {
            return Err(ToolExecutionReceiptError::StringTooLong {
                field: "episode_id",
                len: episode_id.len(),
                max: MAX_EPISODE_ID_LENGTH,
            });
        }
        if request_id.len() > MAX_REQUEST_ID_LENGTH {
            return Err(ToolExecutionReceiptError::StringTooLong {
                field: "request_id",
                len: request_id.len(),
                max: MAX_REQUEST_ID_LENGTH,
            });
        }
        if capability_id.len() > MAX_CAPABILITY_ID_LENGTH {
            return Err(ToolExecutionReceiptError::StringTooLong {
                field: "capability_id",
                len: capability_id.len(),
                max: MAX_CAPABILITY_ID_LENGTH,
            });
        }
        if tool_class.len() > MAX_TOOL_CLASS_LENGTH {
            return Err(ToolExecutionReceiptError::StringTooLong {
                field: "tool_class",
                len: tool_class.len(),
                max: MAX_TOOL_CLASS_LENGTH,
            });
        }

        // Get signer identity
        let signer_identity = hex::encode(signer.verifying_key().as_bytes());

        // Build receipt with placeholder signature
        let mut receipt = ToolExecutionReceipt {
            schema: TOOL_EXECUTION_RECEIPT_SCHEMA.to_string(),
            schema_version: TOOL_EXECUTION_RECEIPT_VERSION.to_string(),
            episode_id,
            policy_hash,
            request_id,
            capability_id,
            tool_class,
            args_hash,
            result_hash,
            time_envelope_ref,
            started_at_ns,
            duration_ns,
            signer_identity,
            signature: [0u8; 64],
        };

        // Sign
        let canonical = receipt.canonical_bytes();
        let signature = sign_with_domain(signer, TOOL_EXECUTION_RECEIPT_PREFIX, &canonical);
        receipt.signature = signature.to_bytes();

        Ok(receipt)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_receipt(signer: &Signer) -> ToolExecutionReceipt {
        ToolExecutionReceiptBuilder::new()
            .episode_id("ep-001")
            .policy_hash([0x11; 32])
            .request_id("req-001")
            .capability_id("cap-001")
            .tool_class("Read")
            .args_hash([0x22; 32])
            .result_hash([0x33; 32])
            .time_envelope_ref([0x44; 32])
            .started_at_ns(1_000_000_000)
            .duration_ns(5_000_000)
            .build_and_sign(signer)
            .expect("valid receipt")
    }

    #[test]
    fn test_build_and_sign() {
        let signer = Signer::generate();
        let receipt = create_test_receipt(&signer);

        assert_eq!(receipt.schema, TOOL_EXECUTION_RECEIPT_SCHEMA);
        assert_eq!(receipt.episode_id, "ep-001");
        assert_eq!(receipt.request_id, "req-001");
        assert_eq!(receipt.capability_id, "cap-001");
        assert_eq!(receipt.tool_class, "Read");
        assert_eq!(receipt.started_at_ns, 1_000_000_000);
        assert_eq!(receipt.duration_ns, 5_000_000);
    }

    #[test]
    fn test_signature_verification() {
        let signer = Signer::generate();
        let receipt = create_test_receipt(&signer);

        // Valid signature
        assert!(receipt.verify_signature(&signer.verifying_key()).is_ok());

        // Wrong key should fail
        let other_signer = Signer::generate();
        assert!(
            receipt
                .verify_signature(&other_signer.verifying_key())
                .is_err()
        );
    }

    #[test]
    fn test_signature_binds_to_content() {
        let signer = Signer::generate();
        let mut receipt = create_test_receipt(&signer);

        // Tamper with content
        receipt.episode_id = "ep-tampered".to_string();

        // Signature should now be invalid
        assert!(receipt.verify_signature(&signer.verifying_key()).is_err());
    }

    #[test]
    fn test_canonical_bytes_deterministic() {
        let signer = Signer::generate();
        let receipt1 = create_test_receipt(&signer);
        let receipt2 = create_test_receipt(&signer);

        // Same inputs produce same canonical bytes
        assert_eq!(receipt1.canonical_bytes(), receipt2.canonical_bytes());
        // Ed25519 is deterministic
        assert_eq!(receipt1.signature, receipt2.signature);
    }

    #[test]
    fn test_cas_hash_deterministic() {
        let signer = Signer::generate();
        let receipt1 = create_test_receipt(&signer);
        let receipt2 = create_test_receipt(&signer);

        assert_eq!(receipt1.compute_cas_hash(), receipt2.compute_cas_hash());
    }

    #[test]
    fn test_missing_field_error() {
        let signer = Signer::generate();

        let result = ToolExecutionReceiptBuilder::new()
            // Missing episode_id
            .policy_hash([0x11; 32])
            .request_id("req-001")
            .capability_id("cap-001")
            .tool_class("Read")
            .args_hash([0x22; 32])
            .result_hash([0x33; 32])
            .time_envelope_ref([0x44; 32])
            .started_at_ns(1_000_000_000)
            .duration_ns(5_000_000)
            .build_and_sign(&signer);

        assert!(matches!(
            result,
            Err(ToolExecutionReceiptError::MissingField("episode_id"))
        ));
    }

    #[test]
    fn test_string_too_long() {
        let signer = Signer::generate();
        let long_string = "x".repeat(MAX_EPISODE_ID_LENGTH + 1);

        let result = ToolExecutionReceiptBuilder::new()
            .episode_id(long_string)
            .policy_hash([0x11; 32])
            .request_id("req-001")
            .capability_id("cap-001")
            .tool_class("Read")
            .args_hash([0x22; 32])
            .result_hash([0x33; 32])
            .time_envelope_ref([0x44; 32])
            .started_at_ns(1_000_000_000)
            .duration_ns(5_000_000)
            .build_and_sign(&signer);

        assert!(matches!(
            result,
            Err(ToolExecutionReceiptError::StringTooLong {
                field: "episode_id",
                ..
            })
        ));
    }

    #[test]
    fn test_validate() {
        let signer = Signer::generate();
        let receipt = create_test_receipt(&signer);

        assert!(receipt.validate().is_ok());
    }

    #[test]
    fn test_validate_invalid_schema() {
        let signer = Signer::generate();
        let mut receipt = create_test_receipt(&signer);
        receipt.schema = "invalid.schema".to_string();

        assert!(receipt.validate().is_err());
    }

    #[test]
    fn test_domain_separator_prevents_replay() {
        let signer = Signer::generate();
        let receipt = create_test_receipt(&signer);

        // Sign without domain prefix
        let canonical = receipt.canonical_bytes();
        let wrong_signature = signer.sign(&canonical);

        let mut bad_receipt = receipt;
        bad_receipt.signature = wrong_signature.to_bytes();

        // Verification should fail
        assert!(
            bad_receipt
                .verify_signature(&signer.verifying_key())
                .is_err()
        );
    }
}
