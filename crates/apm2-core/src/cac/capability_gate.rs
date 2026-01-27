//! Capability gating for AAT receipt verification.
//!
//! This module provides the [`CapabilityGate`] struct for verifying
//! capabilities against AAT (Agent Acceptance Test) receipts and enforcing
//! cutover gating.
//!
//! # Design Principles
//!
//! - **`AATReceipt` Binding**: Per DD-0006, capability gating requires a valid
//!   `AATReceipt` that proves selftests have passed for the current binary
//! - **Binary Hash Verification**: Receipts are bound to the binary version via
//!   `binary_hash` to prevent replay across versions
//! - **Graceful Degradation**: Optional capabilities can be marked as Degraded
//!   when unavailable, allowing operation with reduced functionality
//! - **`DefectRecord` Emission**: Missing required capabilities emit structured
//!   defect records for feedback loops
//!
//! # Security Properties
//!
//! - `AATReceipt` signature verification prevents capability spoofing
//! - Binary hash binding ensures receipts match the current binary
//! - Cutover gating prevents untested capabilities from reaching production
//!
//! # Example
//!
//! ```rust
//! use apm2_core::cac::capability_gate::{
//!     CapabilityGate, CapabilityRequirement, CapabilityStatus,
//! };
//! use apm2_core::crypto::Signer;
//! use apm2_core::evidence::{AATReceipt, AATReceiptGenerator, TestSummary};
//!
//! // Create a signer and generator
//! let signer = Signer::generate();
//! let binary_hash = "a".repeat(64);
//! let generator = AATReceiptGenerator::new(signer, binary_hash.clone());
//!
//! // Generate a receipt with tested capabilities
//! let summary = TestSummary::new(10, 0, 0);
//! let caps = vec![
//!     "cac:patch:apply".to_string(),
//!     "cac:admission:validate".to_string(),
//! ];
//! let receipt = generator
//!     .generate_with_budget(
//!         "rcpt-001",
//!         summary,
//!         Default::default(),
//!         caps,
//!         1_000_000_000,
//!     )
//!     .unwrap();
//!
//! // Create the gate with the generator's public key
//! let gate = CapabilityGate::new(binary_hash, generator.public_key_bytes());
//!
//! // Verify the receipt
//! assert!(gate.verify_receipt(&receipt).is_ok());
//!
//! // Check capabilities
//! let requirements = vec![
//!     CapabilityRequirement::required("cac:patch:apply"),
//!     CapabilityRequirement::optional("cac:export:render"),
//! ];
//! let statuses = gate.check_capabilities(&requirements, &receipt);
//!
//! // First capability is available, second is degraded (optional but missing)
//! assert!(matches!(statuses[0], CapabilityStatus::Available { .. }));
//! assert!(matches!(statuses[1], CapabilityStatus::Degraded { .. }));
//! ```

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::crypto::{PUBLIC_KEY_SIZE, parse_signature, parse_verifying_key, verify_signature};
use crate::evidence::{AATReceipt, AATReceiptError};

// ============================================================================
// Constants
// ============================================================================

/// Maximum length for capability IDs in gate operations.
pub const MAX_CAPABILITY_ID_LENGTH: usize = 256;

/// Maximum number of requirements that can be checked in a single call.
pub const MAX_REQUIREMENTS_PER_CHECK: usize = 1000;

// ============================================================================
// Errors
// ============================================================================

/// Errors that can occur during capability gate operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CapabilityError {
    /// The `AATReceipt` signature verification failed.
    #[error("receipt signature verification failed")]
    SignatureVerificationFailed,

    /// The `AATReceipt` binary hash does not match the current binary.
    #[error("binary hash mismatch: expected {expected}, got {actual}")]
    BinaryHashMismatch {
        /// Expected binary hash (current binary).
        expected: String,
        /// Actual binary hash in the receipt.
        actual: String,
    },

    /// The `AATReceipt` has invalid format.
    #[error("invalid receipt format: {reason}")]
    InvalidReceiptFormat {
        /// The reason the receipt format is invalid.
        reason: String,
    },

    /// A required capability is not available.
    #[error("required capability unavailable: {capability_id}")]
    RequiredCapabilityUnavailable {
        /// The capability ID that is required but unavailable.
        capability_id: String,
    },

    /// The public key for verification is invalid.
    #[error("invalid public key: {reason}")]
    InvalidPublicKey {
        /// The reason the public key is invalid.
        reason: String,
    },

    /// A capability ID is invalid.
    #[error("invalid capability ID '{capability_id}': {reason}")]
    InvalidCapabilityId {
        /// The invalid capability ID.
        capability_id: String,
        /// The reason it's invalid.
        reason: String,
    },

    /// Too many requirements in a single check.
    #[error("too many requirements: {count} exceeds maximum of {max}")]
    TooManyRequirements {
        /// The number of requirements provided.
        count: usize,
        /// The maximum allowed.
        max: usize,
    },

    /// Too many capabilities in a receipt.
    #[error("too many capabilities in receipt: {count} exceeds maximum of {max}")]
    TooManyCapabilities {
        /// The number of capabilities in the receipt.
        count: usize,
        /// The maximum allowed.
        max: usize,
    },
}

impl From<AATReceiptError> for CapabilityError {
    fn from(err: AATReceiptError) -> Self {
        match err {
            AATReceiptError::BinaryHashMismatch { expected, actual } => {
                Self::BinaryHashMismatch { expected, actual }
            },
            AATReceiptError::SignatureVerificationFailed => Self::SignatureVerificationFailed,
            AATReceiptError::MalformedSignature { reason } => Self::InvalidReceiptFormat { reason },
            other => Self::InvalidReceiptFormat {
                reason: other.to_string(),
            },
        }
    }
}

// ============================================================================
// CapabilityStatus
// ============================================================================

/// Status of a capability after gate check.
///
/// Per DD-0006, capabilities can be in one of three states:
/// - **Available**: The capability is verified by an `AATReceipt`
/// - **Unavailable**: The capability is required but not in the receipt
/// - **Degraded**: The capability is optional but not in the receipt
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "status", rename_all = "snake_case")]
#[non_exhaustive]
pub enum CapabilityStatus {
    /// The capability is available and verified.
    Available {
        /// The capability ID that is available.
        capability_id: String,
    },

    /// The capability is required but not available.
    Unavailable {
        /// The capability ID that is unavailable.
        capability_id: String,
        /// Human-readable reason for unavailability.
        reason: String,
    },

    /// The capability is optional but not available (graceful degradation).
    Degraded {
        /// The capability ID that is degraded.
        capability_id: String,
        /// Human-readable reason for degradation.
        reason: String,
    },
}

impl CapabilityStatus {
    /// Returns `true` if the capability is available.
    #[must_use]
    pub const fn is_available(&self) -> bool {
        matches!(self, Self::Available { .. })
    }

    /// Returns `true` if the capability is unavailable (required but missing).
    #[must_use]
    pub const fn is_unavailable(&self) -> bool {
        matches!(self, Self::Unavailable { .. })
    }

    /// Returns `true` if the capability is degraded (optional but missing).
    #[must_use]
    pub const fn is_degraded(&self) -> bool {
        matches!(self, Self::Degraded { .. })
    }

    /// Returns the capability ID.
    #[must_use]
    pub fn capability_id(&self) -> &str {
        match self {
            Self::Available { capability_id }
            | Self::Unavailable { capability_id, .. }
            | Self::Degraded { capability_id, .. } => capability_id,
        }
    }

    /// Returns the status as a string identifier.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Available { .. } => "available",
            Self::Unavailable { .. } => "unavailable",
            Self::Degraded { .. } => "degraded",
        }
    }
}

// ============================================================================
// CapabilityRequirement
// ============================================================================

/// A capability requirement for gate checking.
///
/// Requirements can be marked as required (must be present) or optional
/// (graceful degradation allowed).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityRequirement {
    /// The capability ID being required.
    pub capability_id: String,

    /// Whether this capability is required (true) or optional (false).
    ///
    /// Required capabilities result in [`CapabilityStatus::Unavailable`] when
    /// missing. Optional capabilities result in [`CapabilityStatus::Degraded`].
    pub required: bool,
}

impl CapabilityRequirement {
    /// Creates a new required capability requirement.
    #[must_use]
    pub fn required(capability_id: impl Into<String>) -> Self {
        Self {
            capability_id: capability_id.into(),
            required: true,
        }
    }

    /// Creates a new optional capability requirement.
    #[must_use]
    pub fn optional(capability_id: impl Into<String>) -> Self {
        Self {
            capability_id: capability_id.into(),
            required: false,
        }
    }

    /// Validates the requirement.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityError::InvalidCapabilityId`] if the ID is empty,
    /// too long, or contains invalid characters.
    pub fn validate(&self) -> Result<(), CapabilityError> {
        if self.capability_id.is_empty() {
            return Err(CapabilityError::InvalidCapabilityId {
                capability_id: String::new(),
                reason: "capability ID cannot be empty".to_string(),
            });
        }

        if self.capability_id.len() > MAX_CAPABILITY_ID_LENGTH {
            return Err(CapabilityError::InvalidCapabilityId {
                capability_id: self.capability_id.chars().take(50).collect(),
                reason: format!("exceeds maximum length of {MAX_CAPABILITY_ID_LENGTH} characters"),
            });
        }

        // Validate characters (alphanumeric, hyphens, underscores, colons)
        if !self
            .capability_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == ':')
        {
            return Err(CapabilityError::InvalidCapabilityId {
                capability_id: self.capability_id.chars().take(50).collect(),
                reason: "must contain only alphanumeric characters, hyphens, underscores, and \
                         colons"
                    .to_string(),
            });
        }

        Ok(())
    }
}

// ============================================================================
// CapabilityGate
// ============================================================================

/// Gate for verifying capabilities against AAT receipts.
///
/// The `CapabilityGate` holds the current binary hash and public key for
/// receipt verification. It provides methods to:
/// 1. Verify an [`AATReceipt`]'s signature and binary hash
/// 2. Check a list of capability requirements against a receipt
/// 3. Filter plan steps by available capabilities
///
/// # Security
///
/// Per DD-0006:
/// - Receipts are bound to binary version via `binary_hash`
/// - Signature verification prevents capability spoofing
/// - Cutover gating prevents untested code paths
#[derive(Debug, Clone)]
pub struct CapabilityGate {
    /// BLAKE3 hash of the current binary (hex-encoded, 64 characters).
    binary_hash: String,

    /// Ed25519 public key for receipt signature verification.
    public_key_bytes: [u8; PUBLIC_KEY_SIZE],
}

impl CapabilityGate {
    /// Creates a new capability gate.
    ///
    /// # Arguments
    ///
    /// * `binary_hash` - BLAKE3 hash of the current binary (64 hex characters)
    /// * `public_key_bytes` - Ed25519 public key for signature verification
    #[must_use]
    pub const fn new(binary_hash: String, public_key_bytes: [u8; PUBLIC_KEY_SIZE]) -> Self {
        Self {
            binary_hash,
            public_key_bytes,
        }
    }

    /// Returns the binary hash this gate is bound to.
    #[must_use]
    pub fn binary_hash(&self) -> &str {
        &self.binary_hash
    }

    /// Returns the public key bytes for verification.
    #[must_use]
    pub const fn public_key_bytes(&self) -> &[u8; PUBLIC_KEY_SIZE] {
        &self.public_key_bytes
    }

    /// Verifies an AAT receipt's signature and binary hash.
    ///
    /// This method performs two checks:
    /// 1. Binary hash matches the current binary (fast check first)
    /// 2. Ed25519 signature is valid for the receipt content
    ///
    /// # Returns
    ///
    /// `Ok(())` if verification succeeds.
    ///
    /// # Errors
    ///
    /// - [`CapabilityError::BinaryHashMismatch`] if the receipt's binary hash
    ///   doesn't match the current binary
    /// - [`CapabilityError::SignatureVerificationFailed`] if the signature is
    ///   invalid
    /// - [`CapabilityError::InvalidPublicKey`] if the public key is malformed
    /// - [`CapabilityError::InvalidReceiptFormat`] if the receipt signature is
    ///   malformed
    #[must_use = "verification result must be checked"]
    pub fn verify_receipt(&self, receipt: &AATReceipt) -> Result<(), CapabilityError> {
        // SECURITY: Limit capabilities count to prevent DoS via unbounded allocation
        // during canonicalization (which clones, sorts, and joins the vector).
        if receipt.capabilities_tested.len() > crate::cac::manifest::MAX_CAPABILITIES {
            return Err(CapabilityError::TooManyCapabilities {
                count: receipt.capabilities_tested.len(),
                max: crate::cac::manifest::MAX_CAPABILITIES,
            });
        }

        // Fast check: binary hash match
        if !receipt.verify_binary_hash(&self.binary_hash) {
            return Err(CapabilityError::BinaryHashMismatch {
                expected: self.binary_hash.clone(),
                actual: receipt.binary_hash.clone(),
            });
        }

        // Verify signature
        let verifying_key = parse_verifying_key(&self.public_key_bytes).map_err(|e| {
            CapabilityError::InvalidPublicKey {
                reason: e.to_string(),
            }
        })?;

        // Use AATReceipt::canonical_bytes to ensure consistency between signer and
        // verifier
        let canonical = receipt.canonical_bytes();
        let signature = parse_signature(receipt.signature()).map_err(|e| {
            CapabilityError::InvalidReceiptFormat {
                reason: e.to_string(),
            }
        })?;

        verify_signature(&verifying_key, &canonical, &signature)
            .map_err(|_| CapabilityError::SignatureVerificationFailed)?;

        Ok(())
    }

    /// Checks a list of capability requirements against a receipt.
    ///
    /// For each requirement, this method checks if the capability is present
    /// in the receipt's `capabilities_tested` list.
    ///
    /// # Arguments
    ///
    /// * `requirements` - List of capability requirements to check
    /// * `receipt` - The verified AAT receipt to check against
    ///
    /// # Returns
    ///
    /// A vector of [`CapabilityStatus`] in the same order as the requirements.
    ///
    /// # Panics
    ///
    /// This method does not panic. Invalid requirements are returned as
    /// [`CapabilityStatus::Unavailable`] with an appropriate error message.
    #[must_use]
    pub fn check_capabilities(
        &self,
        requirements: &[CapabilityRequirement],
        receipt: &AATReceipt,
    ) -> Vec<CapabilityStatus> {
        requirements
            .iter()
            .map(|req| self.check_single_capability(req, receipt))
            .collect()
    }

    /// Checks a list of capability requirements and returns an error if any
    /// required capability is unavailable.
    ///
    /// This is a convenience method that combines [`Self::check_capabilities`]
    /// with validation that all required capabilities are present.
    ///
    /// # Arguments
    ///
    /// * `requirements` - List of capability requirements to check
    /// * `receipt` - The verified AAT receipt to check against
    ///
    /// # Returns
    ///
    /// - `Ok(statuses)` if all required capabilities are available (optional
    ///   caps may be degraded)
    /// - `Err(CapabilityError::RequiredCapabilityUnavailable)` if any required
    ///   capability is missing
    /// - `Err(CapabilityError::TooManyRequirements)` if the requirements list
    ///   exceeds the maximum
    ///
    /// # Errors
    ///
    /// Returns an error if any required capability is unavailable or if there
    /// are too many requirements.
    #[must_use = "gate result must be checked"]
    pub fn check_capabilities_strict(
        &self,
        requirements: &[CapabilityRequirement],
        receipt: &AATReceipt,
    ) -> Result<Vec<CapabilityStatus>, CapabilityError> {
        // Validate requirements count
        if requirements.len() > MAX_REQUIREMENTS_PER_CHECK {
            return Err(CapabilityError::TooManyRequirements {
                count: requirements.len(),
                max: MAX_REQUIREMENTS_PER_CHECK,
            });
        }

        let statuses = self.check_capabilities(requirements, receipt);

        // Check for any unavailable (required but missing) capabilities
        for status in &statuses {
            if let CapabilityStatus::Unavailable { capability_id, .. } = status {
                return Err(CapabilityError::RequiredCapabilityUnavailable {
                    capability_id: capability_id.clone(),
                });
            }
        }

        Ok(statuses)
    }

    /// Checks a single capability requirement against a receipt.
    #[allow(clippy::unused_self)] // Method signature for future extensibility
    fn check_single_capability(
        &self,
        requirement: &CapabilityRequirement,
        receipt: &AATReceipt,
    ) -> CapabilityStatus {
        // Validate the requirement first
        if let Err(e) = requirement.validate() {
            return CapabilityStatus::Unavailable {
                capability_id: requirement.capability_id.clone(),
                reason: format!("invalid requirement: {e}"),
            };
        }

        // Check if capability is in the receipt
        let is_available = receipt
            .capabilities_tested
            .iter()
            .any(|cap| cap == &requirement.capability_id);

        if is_available {
            CapabilityStatus::Available {
                capability_id: requirement.capability_id.clone(),
            }
        } else if requirement.required {
            CapabilityStatus::Unavailable {
                capability_id: requirement.capability_id.clone(),
                reason: "capability not in AAT receipt".to_string(),
            }
        } else {
            CapabilityStatus::Degraded {
                capability_id: requirement.capability_id.clone(),
                reason: "optional capability not in AAT receipt".to_string(),
            }
        }
    }

    /// Filters a list of capability IDs to only those available in the receipt.
    ///
    /// This is useful for planning phase integration where available
    /// capabilities determine which plan steps can execute.
    ///
    /// # Arguments
    ///
    /// * `capability_ids` - List of capability IDs to filter
    /// * `receipt` - The verified AAT receipt
    ///
    /// # Returns
    ///
    /// A vector of capability IDs that are present in the receipt.
    #[must_use]
    pub fn filter_available_capabilities(
        &self,
        capability_ids: &[String],
        receipt: &AATReceipt,
    ) -> Vec<String> {
        capability_ids
            .iter()
            .filter(|id| receipt.capabilities_tested.contains(id))
            .cloned()
            .collect()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Signer;
    use crate::evidence::{AATBudgetConsumed, AATReceiptGenerator, TestSummary};

    /// Creates a valid 64-character hex hash for testing.
    fn make_test_binary_hash() -> String {
        "a".repeat(64)
    }

    fn make_gate_and_generator() -> (CapabilityGate, AATReceiptGenerator) {
        let signer = Signer::generate();
        let binary_hash = make_test_binary_hash();
        let public_key_bytes = signer.public_key_bytes();
        let generator = AATReceiptGenerator::new(signer, binary_hash.clone());
        let gate = CapabilityGate::new(binary_hash, public_key_bytes);
        (gate, generator)
    }

    // =========================================================================
    // CapabilityStatus Tests
    // =========================================================================

    #[test]
    fn test_capability_status_available() {
        let status = CapabilityStatus::Available {
            capability_id: "cac:test".to_string(),
        };
        assert!(status.is_available());
        assert!(!status.is_unavailable());
        assert!(!status.is_degraded());
        assert_eq!(status.capability_id(), "cac:test");
        assert_eq!(status.as_str(), "available");
    }

    #[test]
    fn test_capability_status_unavailable() {
        let status = CapabilityStatus::Unavailable {
            capability_id: "cac:test".to_string(),
            reason: "not in receipt".to_string(),
        };
        assert!(!status.is_available());
        assert!(status.is_unavailable());
        assert!(!status.is_degraded());
        assert_eq!(status.as_str(), "unavailable");
    }

    #[test]
    fn test_capability_status_degraded() {
        let status = CapabilityStatus::Degraded {
            capability_id: "cac:test".to_string(),
            reason: "optional".to_string(),
        };
        assert!(!status.is_available());
        assert!(!status.is_unavailable());
        assert!(status.is_degraded());
        assert_eq!(status.as_str(), "degraded");
    }

    #[test]
    fn test_capability_status_serialization() {
        let status = CapabilityStatus::Available {
            capability_id: "cac:test".to_string(),
        };
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("\"status\":\"available\""));

        let parsed: CapabilityStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, parsed);
    }

    #[test]
    fn test_capability_status_rejects_unknown_fields() {
        let json = r#"{"status":"available","capability_id":"test","unknown":"field"}"#;
        let result: Result<CapabilityStatus, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    // =========================================================================
    // CapabilityRequirement Tests
    // =========================================================================

    #[test]
    fn test_capability_requirement_required() {
        let req = CapabilityRequirement::required("cac:test");
        assert_eq!(req.capability_id, "cac:test");
        assert!(req.required);
        assert!(req.validate().is_ok());
    }

    #[test]
    fn test_capability_requirement_optional() {
        let req = CapabilityRequirement::optional("cac:test");
        assert_eq!(req.capability_id, "cac:test");
        assert!(!req.required);
        assert!(req.validate().is_ok());
    }

    #[test]
    fn test_capability_requirement_empty_id_rejected() {
        let req = CapabilityRequirement::required("");
        let result = req.validate();
        assert!(matches!(
            result,
            Err(CapabilityError::InvalidCapabilityId { .. })
        ));
    }

    #[test]
    fn test_capability_requirement_long_id_rejected() {
        let long_id = "x".repeat(MAX_CAPABILITY_ID_LENGTH + 1);
        let req = CapabilityRequirement::required(long_id);
        let result = req.validate();
        assert!(matches!(
            result,
            Err(CapabilityError::InvalidCapabilityId { .. })
        ));
    }

    #[test]
    fn test_capability_requirement_invalid_chars_rejected() {
        let req = CapabilityRequirement::required("cac:test|invalid");
        let result = req.validate();
        assert!(matches!(
            result,
            Err(CapabilityError::InvalidCapabilityId { .. })
        ));
    }

    #[test]
    fn test_capability_requirement_serialization() {
        let req = CapabilityRequirement::required("cac:test");
        let json = serde_json::to_string(&req).unwrap();
        let parsed: CapabilityRequirement = serde_json::from_str(&json).unwrap();
        assert_eq!(req, parsed);
    }

    // =========================================================================
    // CapabilityGate Verification Tests
    // =========================================================================

    #[test]
    fn test_verify_receipt_success() {
        let (gate, generator) = make_gate_and_generator();

        let summary = TestSummary::new(10, 0, 0);
        let receipt = generator
            .generate("rcpt-001", summary, 1_000_000_000)
            .unwrap();

        assert!(gate.verify_receipt(&receipt).is_ok());
    }

    #[test]
    fn test_verify_receipt_binary_hash_mismatch() {
        let signer = Signer::generate();
        let binary_hash = make_test_binary_hash();
        let different_binary_hash = "b".repeat(64);

        // Generator with different hash
        let generator = AATReceiptGenerator::new(signer, different_binary_hash);

        // Gate expects the original hash
        let gate = CapabilityGate::new(binary_hash, generator.public_key_bytes());

        let summary = TestSummary::new(10, 0, 0);
        let receipt = generator
            .generate("rcpt-001", summary, 1_000_000_000)
            .unwrap();

        let result = gate.verify_receipt(&receipt);
        assert!(matches!(
            result,
            Err(CapabilityError::BinaryHashMismatch { .. })
        ));
    }

    #[test]
    fn test_verify_receipt_signature_verification_failed() {
        let signer1 = Signer::generate();
        let signer2 = Signer::generate();
        let binary_hash = make_test_binary_hash();

        // Generator uses signer1
        let generator = AATReceiptGenerator::new(signer1, binary_hash.clone());

        // Gate uses signer2's public key
        let gate = CapabilityGate::new(binary_hash, signer2.public_key_bytes());

        let summary = TestSummary::new(10, 0, 0);
        let receipt = generator
            .generate("rcpt-001", summary, 1_000_000_000)
            .unwrap();

        let result = gate.verify_receipt(&receipt);
        assert!(matches!(
            result,
            Err(CapabilityError::SignatureVerificationFailed)
        ));
    }

    // =========================================================================
    // CapabilityGate Check Tests
    // =========================================================================

    #[test]
    fn test_check_capabilities_all_available() {
        let (gate, generator) = make_gate_and_generator();

        let summary = TestSummary::new(10, 0, 0);
        let caps = vec![
            "cac:patch:apply".to_string(),
            "cac:admission:validate".to_string(),
        ];
        let receipt = generator
            .generate_with_budget(
                "rcpt-001",
                summary,
                AATBudgetConsumed::default(),
                caps,
                1_000_000_000,
            )
            .unwrap();

        let requirements = vec![
            CapabilityRequirement::required("cac:patch:apply"),
            CapabilityRequirement::required("cac:admission:validate"),
        ];

        let statuses = gate.check_capabilities(&requirements, &receipt);

        assert_eq!(statuses.len(), 2);
        assert!(statuses[0].is_available());
        assert!(statuses[1].is_available());
    }

    #[test]
    fn test_check_capabilities_required_missing() {
        let (gate, generator) = make_gate_and_generator();

        let summary = TestSummary::new(10, 0, 0);
        let caps = vec!["cac:patch:apply".to_string()];
        let receipt = generator
            .generate_with_budget(
                "rcpt-001",
                summary,
                AATBudgetConsumed::default(),
                caps,
                1_000_000_000,
            )
            .unwrap();

        let requirements = vec![
            CapabilityRequirement::required("cac:patch:apply"),
            CapabilityRequirement::required("cac:admission:validate"), // Not in receipt
        ];

        let statuses = gate.check_capabilities(&requirements, &receipt);

        assert_eq!(statuses.len(), 2);
        assert!(statuses[0].is_available());
        assert!(statuses[1].is_unavailable());
    }

    #[test]
    fn test_check_capabilities_optional_missing() {
        let (gate, generator) = make_gate_and_generator();

        let summary = TestSummary::new(10, 0, 0);
        let caps = vec!["cac:patch:apply".to_string()];
        let receipt = generator
            .generate_with_budget(
                "rcpt-001",
                summary,
                AATBudgetConsumed::default(),
                caps,
                1_000_000_000,
            )
            .unwrap();

        let requirements = vec![
            CapabilityRequirement::required("cac:patch:apply"),
            CapabilityRequirement::optional("cac:export:render"), // Optional, not in receipt
        ];

        let statuses = gate.check_capabilities(&requirements, &receipt);

        assert_eq!(statuses.len(), 2);
        assert!(statuses[0].is_available());
        assert!(statuses[1].is_degraded());
    }

    #[test]
    fn test_check_capabilities_strict_success() {
        let (gate, generator) = make_gate_and_generator();

        let summary = TestSummary::new(10, 0, 0);
        let caps = vec![
            "cac:patch:apply".to_string(),
            "cac:admission:validate".to_string(),
        ];
        let receipt = generator
            .generate_with_budget(
                "rcpt-001",
                summary,
                AATBudgetConsumed::default(),
                caps,
                1_000_000_000,
            )
            .unwrap();

        let requirements = vec![
            CapabilityRequirement::required("cac:patch:apply"),
            CapabilityRequirement::optional("cac:export:render"), // Optional
        ];

        let result = gate.check_capabilities_strict(&requirements, &receipt);
        assert!(result.is_ok());
        let statuses = result.unwrap();
        assert!(statuses[0].is_available());
        assert!(statuses[1].is_degraded()); // Optional missing is OK
    }

    #[test]
    fn test_check_capabilities_strict_required_missing() {
        let (gate, generator) = make_gate_and_generator();

        let summary = TestSummary::new(10, 0, 0);
        let caps = vec!["cac:patch:apply".to_string()];
        let receipt = generator
            .generate_with_budget(
                "rcpt-001",
                summary,
                AATBudgetConsumed::default(),
                caps,
                1_000_000_000,
            )
            .unwrap();

        let requirements = vec![
            CapabilityRequirement::required("cac:patch:apply"),
            CapabilityRequirement::required("cac:admission:validate"), // Required but missing
        ];

        let result = gate.check_capabilities_strict(&requirements, &receipt);
        assert!(matches!(
            result,
            Err(CapabilityError::RequiredCapabilityUnavailable { capability_id })
            if capability_id == "cac:admission:validate"
        ));
    }

    #[test]
    fn test_check_capabilities_strict_too_many() {
        let (gate, generator) = make_gate_and_generator();

        let summary = TestSummary::new(10, 0, 0);
        let receipt = generator
            .generate("rcpt-001", summary, 1_000_000_000)
            .unwrap();

        // Create more requirements than allowed
        let requirements: Vec<_> = (0..=MAX_REQUIREMENTS_PER_CHECK)
            .map(|i| CapabilityRequirement::required(format!("cap:{i}")))
            .collect();

        let result = gate.check_capabilities_strict(&requirements, &receipt);
        assert!(matches!(
            result,
            Err(CapabilityError::TooManyRequirements { .. })
        ));
    }

    // =========================================================================
    // Filter Capabilities Tests
    // =========================================================================

    #[test]
    fn test_filter_available_capabilities() {
        let (gate, generator) = make_gate_and_generator();

        let summary = TestSummary::new(10, 0, 0);
        let caps = vec![
            "cac:patch:apply".to_string(),
            "cac:admission:validate".to_string(),
        ];
        let receipt = generator
            .generate_with_budget(
                "rcpt-001",
                summary,
                AATBudgetConsumed::default(),
                caps,
                1_000_000_000,
            )
            .unwrap();

        let requested = vec![
            "cac:patch:apply".to_string(),
            "cac:export:render".to_string(), // Not in receipt
            "cac:admission:validate".to_string(),
        ];

        let available = gate.filter_available_capabilities(&requested, &receipt);

        assert_eq!(available.len(), 2);
        assert!(available.contains(&"cac:patch:apply".to_string()));
        assert!(available.contains(&"cac:admission:validate".to_string()));
        assert!(!available.contains(&"cac:export:render".to_string()));
    }

    // =========================================================================
    // Error Display Tests
    // =========================================================================

    #[test]
    fn test_capability_error_display() {
        let err = CapabilityError::SignatureVerificationFailed;
        assert!(err.to_string().contains("signature verification failed"));

        let err = CapabilityError::BinaryHashMismatch {
            expected: "aaa".to_string(),
            actual: "bbb".to_string(),
        };
        assert!(err.to_string().contains("aaa"));
        assert!(err.to_string().contains("bbb"));

        let err = CapabilityError::RequiredCapabilityUnavailable {
            capability_id: "cac:test".to_string(),
        };
        assert!(err.to_string().contains("cac:test"));
    }

    // =========================================================================
    // Integration Tests
    // =========================================================================

    #[test]
    fn test_full_gating_workflow() {
        // Simulate a full capability gating workflow

        // 1. Create gate and generator with matching keys
        let (gate, generator) = make_gate_and_generator();

        // 2. Generate a receipt from selftest execution
        let summary = TestSummary::new(15, 0, 2); // 15 passed, 2 skipped
        let budget = AATBudgetConsumed::new(5000, 20, 1000);
        let caps = vec![
            "cac:patch:apply".to_string(),
            "cac:admission:validate".to_string(),
            "cac:schema:validate".to_string(),
        ];
        let receipt = generator
            .generate_with_budget("rcpt-selftest-001", summary, budget, caps, 1_000_000_000)
            .unwrap();

        // 3. Verify the receipt
        gate.verify_receipt(&receipt)
            .expect("receipt should verify");

        // 4. Check planning phase requirements
        let plan_requirements = vec![
            CapabilityRequirement::required("cac:patch:apply"),
            CapabilityRequirement::required("cac:admission:validate"),
            CapabilityRequirement::optional("cac:export:render"), // Optional advanced feature
        ];

        let statuses = gate
            .check_capabilities_strict(&plan_requirements, &receipt)
            .expect("should pass strict check");

        // 5. Verify results
        assert!(statuses[0].is_available()); // patch:apply
        assert!(statuses[1].is_available()); // admission:validate
        assert!(statuses[2].is_degraded()); // export:render (optional, missing)

        // 6. Filter for plan step execution
        let plan_step_caps = vec![
            "cac:patch:apply".to_string(),
            "cac:export:render".to_string(),
        ];
        let executable_steps = gate.filter_available_capabilities(&plan_step_caps, &receipt);
        assert_eq!(executable_steps.len(), 1);
        assert_eq!(executable_steps[0], "cac:patch:apply");
    }

    /// SECURITY TEST: Verify binary hash binding prevents replay.
    #[test]
    fn test_security_binary_hash_binding_prevents_replay() {
        let signer = Signer::generate();
        let old_binary_hash = "a".repeat(64);
        let new_binary_hash = "b".repeat(64);

        // Old receipt from old binary version
        let old_generator = AATReceiptGenerator::new(Signer::generate(), old_binary_hash);
        let old_receipt = old_generator
            .generate("rcpt-old", TestSummary::new(10, 0, 0), 1_000_000_000)
            .unwrap();

        // New gate for new binary version
        let new_gate = CapabilityGate::new(new_binary_hash, signer.public_key_bytes());

        // Old receipt should be rejected by new gate
        let result = new_gate.verify_receipt(&old_receipt);
        assert!(
            matches!(result, Err(CapabilityError::BinaryHashMismatch { .. })),
            "Old receipt should be rejected by new binary version"
        );
    }

    /// SECURITY TEST: Verify receipt with too many capabilities is rejected.
    ///
    /// This test proves that receipts with unbounded `capabilities_tested`
    /// vectors are rejected before canonicalization to prevent
    /// denial-of-service attacks via OOM or CPU exhaustion.
    #[test]
    fn test_verify_receipt_too_many_capabilities() {
        let (gate, generator) = make_gate_and_generator();

        // Create a valid receipt first, then modify capabilities_tested
        // (the signature will be invalid, but the capabilities check happens first)
        let summary = TestSummary::new(10, 0, 0);
        let mut receipt = generator
            .generate("rcpt-dos", summary, 1_000_000_000)
            .unwrap();

        // Replace capabilities_tested with too many items
        receipt.capabilities_tested = (0..=crate::cac::manifest::MAX_CAPABILITIES)
            .map(|i| format!("cap:{i}"))
            .collect();

        // The receipt has MAX_CAPABILITIES + 1 items
        assert_eq!(
            receipt.capabilities_tested.len(),
            crate::cac::manifest::MAX_CAPABILITIES + 1
        );

        // Verification should fail with TooManyCapabilities error
        let result = gate.verify_receipt(&receipt);
        assert!(
            matches!(
                result,
                Err(CapabilityError::TooManyCapabilities { count, max })
                if count == crate::cac::manifest::MAX_CAPABILITIES + 1
                    && max == crate::cac::manifest::MAX_CAPABILITIES
            ),
            "Receipt with too many capabilities should be rejected: {result:?}"
        );

        // Also test that exactly MAX_CAPABILITIES is allowed
        receipt.capabilities_tested.pop();
        assert_eq!(
            receipt.capabilities_tested.len(),
            crate::cac::manifest::MAX_CAPABILITIES
        );

        // This should pass the capabilities count check (but may fail signature
        // because we modified the receipt after signing)
        let result = gate.verify_receipt(&receipt);
        assert!(
            !matches!(result, Err(CapabilityError::TooManyCapabilities { .. })),
            "Receipt with exactly MAX_CAPABILITIES should not be rejected for count"
        );
    }

    /// SECURITY TEST: Verify signature prevents capability spoofing.
    #[test]
    fn test_security_signature_prevents_spoofing() {
        let (gate, generator) = make_gate_and_generator();

        // Create a legitimate receipt
        let summary = TestSummary::new(10, 0, 0);
        let caps = vec!["cac:limited".to_string()];
        let receipt = generator
            .generate_with_budget(
                "rcpt-001",
                summary,
                AATBudgetConsumed::default(),
                caps,
                1_000_000_000,
            )
            .unwrap();

        // Verify the legitimate receipt works
        assert!(gate.verify_receipt(&receipt).is_ok());

        // An attacker cannot add capabilities because:
        // 1. They can't modify the receipt (signature would fail)
        // 2. They can't create new receipts (no private key)

        // Different signer trying to create spoofed receipt
        let attacker_signer = Signer::generate();
        let attacker_generator = AATReceiptGenerator::new(attacker_signer, make_test_binary_hash());
        let spoofed_caps = vec!["cac:admin:all".to_string()]; // Attacker claims admin caps
        let spoofed_receipt = attacker_generator
            .generate_with_budget(
                "rcpt-spoofed",
                TestSummary::new(10, 0, 0),
                AATBudgetConsumed::default(),
                spoofed_caps,
                1_000_000_000,
            )
            .unwrap();

        // Spoofed receipt rejected - signature from wrong key
        let result = gate.verify_receipt(&spoofed_receipt);
        assert!(
            matches!(result, Err(CapabilityError::SignatureVerificationFailed)),
            "Spoofed receipt should be rejected"
        );
    }
}
