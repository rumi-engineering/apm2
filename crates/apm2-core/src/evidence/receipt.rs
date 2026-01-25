//! Gate receipt generator for evidence bundles.
//!
//! This module provides the [`GateReceiptGenerator`] for creating signed gate
//! receipts from evidence bundles. Gate receipts serve as cryptographic proof
//! that a work item has passed (or failed) its quality gate.
//!
//! # Architecture
//!
//! ```text
//! EvidenceBundle (from reducer)
//!        |
//!        v
//! GateReceiptGenerator.generate()
//!        |
//!        ├──> Validate evidence completeness
//!        ├──> Compute PASS/FAIL result
//!        ├──> Auto-populate receipt fields
//!        └──> Sign receipt
//!        |
//!        v
//! GateReceipt (signed, ready for event)
//!        |
//!        v
//! GateReceiptGenerated (kernel event payload)
//! ```
//!
//! # Security Properties
//!
//! - **Signed receipts**: Receipts are signed with the generator's private key
//! - **Fail-closed validation**: Missing required evidence causes FAIL
//! - **Deterministic**: Same input produces same receipt (except timestamp)
//!
//! # Example
//!
//! ```rust
//! use apm2_core::crypto::Signer;
//! use apm2_core::evidence::{
//!     EvidenceBundle, EvidenceCategory, GateReceiptGenerator,
//!     GateRequirements,
//! };
//!
//! // Create a generator with a signing key
//! let signer = Signer::generate();
//! let requirements = GateRequirements::default();
//! let generator = GateReceiptGenerator::new(signer, requirements);
//!
//! // Generate a receipt from a bundle
//! let bundle = EvidenceBundle::new(
//!     "work-123".to_string(),
//!     [0u8; 32],
//!     vec!["evid-001".to_string()],
//!     vec![EvidenceCategory::TestResults],
//!     1024,
//!     1_000_000_000,
//! );
//!
//! let receipt = generator
//!     .generate("gate-001", &bundle, 2_000_000_000)
//!     .unwrap();
//! assert!(receipt.is_signed());
//! ```

use std::fmt::Write;

use prost::Message;
use serde::{Deserialize, Serialize};

use super::category::EvidenceCategory;
use super::error::EvidenceError;
use super::state::EvidenceBundle;
use crate::crypto::{Hash, SIGNATURE_SIZE, Signature, Signer};
use crate::events::{EvidenceEvent, GateReceiptGenerated, evidence_event};

/// Maximum length for gate IDs and receipt IDs.
const MAX_ID_LEN: usize = 256;

/// Characters that are forbidden in IDs because they break canonical
/// serialization or could be used for injection attacks.
///
/// - `|` is the field separator in canonical format
/// - `,` is the evidence ID separator in canonical format
/// - `/` and `\` could enable path traversal
/// - `..` sequences could enable directory traversal (handled separately)
/// - Control characters (< 0x20) could be used for log injection
/// - Newlines and carriage returns break log formatting
const FORBIDDEN_ID_CHARS: &[char] = &['|', ',', '/', '\\', '\n', '\r', '\0'];

/// Validates an identifier string for use in gate receipts.
///
/// # Validation Rules
///
/// - Must not be empty
/// - Must not exceed `MAX_ID_LEN` bytes
/// - Must not contain forbidden characters (see `FORBIDDEN_ID_CHARS`)
/// - Must not contain `..` sequences (path traversal)
/// - Must only contain ASCII printable characters (0x20-0x7E)
///
/// # Arguments
///
/// * `id` - The identifier to validate
/// * `id_type` - Human-readable type name for error messages (e.g., "gate ID")
///
/// # Returns
///
/// `Ok(())` if valid, or an appropriate `EvidenceError` if invalid.
fn validate_id(id: &str, id_type: &str) -> Result<(), String> {
    // Check for empty ID
    if id.is_empty() {
        return Err(format!("{id_type} cannot be empty"));
    }

    // Check length limit
    if id.len() > MAX_ID_LEN {
        return Err(format!(
            "{id_type} exceeds maximum length of {MAX_ID_LEN} bytes: {} bytes",
            id.len()
        ));
    }

    // Check for forbidden characters
    for forbidden in FORBIDDEN_ID_CHARS {
        if id.contains(*forbidden) {
            return Err(format!(
                "{id_type} contains forbidden character: {forbidden:?}"
            ));
        }
    }

    // Check for path traversal sequences
    if id.contains("..") {
        return Err(format!("{id_type} contains path traversal sequence: .."));
    }

    // Check for non-ASCII printable characters
    for (i, c) in id.chars().enumerate() {
        if !c.is_ascii() || c.is_ascii_control() {
            return Err(format!(
                "{id_type} contains invalid character at position {i}: {c:?}"
            ));
        }
    }

    Ok(())
}

/// Validates a gate ID.
fn validate_gate_id(gate_id: &str) -> Result<(), EvidenceError> {
    validate_id(gate_id, "gate ID").map_err(|reason| EvidenceError::InvalidGateId { value: reason })
}

/// Validates a receipt ID.
fn validate_receipt_id(receipt_id: &str) -> Result<(), EvidenceError> {
    validate_id(receipt_id, "receipt ID")
        .map_err(|reason| EvidenceError::InvalidReceiptId { value: reason })
}

/// Validates a work ID from an evidence bundle.
///
/// This is a defense-in-depth check - the reducer should already validate
/// work IDs, but we re-validate here since they're included in the
/// cryptographic canonical format.
fn validate_work_id(work_id: &str) -> Result<(), EvidenceError> {
    validate_id(work_id, "work ID").map_err(|reason| EvidenceError::InvalidWorkId { value: reason })
}

/// Validates all evidence IDs from a bundle.
///
/// This is a defense-in-depth check - the reducer should already validate
/// evidence IDs, but we re-validate here since they're included in the
/// cryptographic canonical format.
fn validate_evidence_ids(evidence_ids: &[String]) -> Result<(), EvidenceError> {
    for (i, evidence_id) in evidence_ids.iter().enumerate() {
        validate_id(evidence_id, &format!("evidence ID at index {i}"))
            .map_err(|reason| EvidenceError::InvalidEvidenceId { value: reason })?;
    }
    Ok(())
}

/// Encodes bytes as a hex string.
fn hex_encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut acc, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        })
}

/// Result of a gate review.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum GateResult {
    /// All required evidence is present and valid.
    Pass,
    /// Required evidence is missing or invalid.
    Fail,
}

impl GateResult {
    /// Returns the string representation for the protobuf event.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
        }
    }

    /// Parses a gate result from a string.
    ///
    /// Returns `None` if the string is not a valid gate result.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "PASS" => Some(Self::Pass),
            "FAIL" => Some(Self::Fail),
            _ => None,
        }
    }
}

/// Reason codes explaining why a gate passed or failed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum GateReasonCode {
    /// All required categories present and evidence valid.
    AllRequirementsMet,
    /// One or more required evidence categories are missing.
    MissingRequiredCategory {
        /// The missing categories.
        missing: Vec<EvidenceCategory>,
    },
    /// Evidence bundle is empty (no evidence at all).
    EmptyBundle,
    /// Work ID does not match expected.
    WorkIdMismatch,
}

impl GateReasonCode {
    /// Returns a human-readable description of the reason.
    #[must_use]
    pub fn description(&self) -> String {
        match self {
            Self::AllRequirementsMet => "All required evidence categories are present".to_string(),
            Self::MissingRequiredCategory { missing } => {
                let names: Vec<&str> = missing.iter().map(EvidenceCategory::as_str).collect();
                format!("Missing required categories: {}", names.join(", "))
            },
            Self::EmptyBundle => "Evidence bundle is empty".to_string(),
            Self::WorkIdMismatch => "Work ID does not match gate context".to_string(),
        }
    }

    /// Returns a short code for serialization.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::AllRequirementsMet => "ALL_REQUIREMENTS_MET",
            Self::MissingRequiredCategory { .. } => "MISSING_REQUIRED_CATEGORY",
            Self::EmptyBundle => "EMPTY_BUNDLE",
            Self::WorkIdMismatch => "WORK_ID_MISMATCH",
        }
    }
}

/// Requirements for a gate to pass.
///
/// Defines which evidence categories must be present for a work item
/// to pass the gate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateRequirements {
    /// Categories that must be present for the gate to pass.
    pub required_categories: Vec<EvidenceCategory>,

    /// Minimum number of evidence items required.
    pub min_evidence_count: usize,

    /// Whether an empty bundle automatically fails.
    pub fail_on_empty: bool,
}

impl Default for GateRequirements {
    fn default() -> Self {
        Self {
            required_categories: vec![EvidenceCategory::TestResults],
            min_evidence_count: 1,
            fail_on_empty: true,
        }
    }
}

impl GateRequirements {
    /// Creates new gate requirements with the specified required categories.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Vec doesn't work in const context
    pub fn new(required_categories: Vec<EvidenceCategory>) -> Self {
        Self {
            required_categories,
            min_evidence_count: 1,
            fail_on_empty: true,
        }
    }

    /// Creates permissive requirements that accept any non-empty bundle.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // vec![] macro doesn't work in const context
    pub fn permissive() -> Self {
        Self {
            required_categories: vec![],
            min_evidence_count: 1,
            fail_on_empty: true,
        }
    }

    /// Creates strict requirements for high-assurance gates.
    #[must_use]
    pub fn high_assurance() -> Self {
        Self {
            required_categories: vec![
                EvidenceCategory::TestResults,
                EvidenceCategory::LintReports,
                EvidenceCategory::SecurityScans,
            ],
            min_evidence_count: 3,
            fail_on_empty: true,
        }
    }

    /// Sets the minimum evidence count.
    #[must_use]
    pub const fn with_min_count(mut self, count: usize) -> Self {
        self.min_evidence_count = count;
        self
    }

    /// Sets whether empty bundles automatically fail.
    #[must_use]
    pub const fn with_fail_on_empty(mut self, fail: bool) -> Self {
        self.fail_on_empty = fail;
        self
    }
}

/// A signed gate receipt proving gate passage or failure.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct GateReceipt {
    /// Unique identifier for this receipt.
    pub receipt_id: String,

    /// The gate this receipt is for.
    pub gate_id: String,

    /// The work item this receipt covers.
    pub work_id: String,

    /// The result of the gate review.
    pub result: GateResult,

    /// Reason code explaining the result.
    pub reason_code: GateReasonCode,

    /// Evidence IDs included in this receipt.
    pub evidence_ids: Vec<String>,

    /// Hash of the evidence bundle.
    pub bundle_hash: Hash,

    /// Categories found in the bundle.
    pub categories_present: Vec<EvidenceCategory>,

    /// Total size of evidence artifacts in bytes.
    pub total_evidence_size: usize,

    /// Timestamp when the receipt was generated (Unix nanos).
    pub generated_at: u64,

    /// Ed25519 signature over the receipt content.
    #[serde(with = "signature_serde")]
    signature: [u8; SIGNATURE_SIZE],
}

/// Custom serde for [u8; 64] signature (serde doesn't support arrays > 32).
mod signature_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use crate::crypto::SIGNATURE_SIZE;

    pub fn serialize<S>(bytes: &[u8; SIGNATURE_SIZE], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Serialize as a Vec<u8> which serde supports
        bytes.as_slice().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; SIGNATURE_SIZE], D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec = Vec::<u8>::deserialize(deserializer)?;
        if vec.len() != SIGNATURE_SIZE {
            return Err(serde::de::Error::custom(format!(
                "expected {} bytes, got {}",
                SIGNATURE_SIZE,
                vec.len()
            )));
        }
        let mut arr = [0u8; SIGNATURE_SIZE];
        arr.copy_from_slice(&vec);
        Ok(arr)
    }
}

impl GateReceipt {
    /// Returns whether this receipt has a valid signature.
    ///
    /// Note: This only checks that the signature field is non-zero.
    /// Use [`GateReceiptGenerator::verify`] for cryptographic verification.
    #[must_use]
    pub fn is_signed(&self) -> bool {
        self.signature.iter().any(|&b| b != 0)
    }

    /// Returns the signature bytes.
    #[must_use]
    pub const fn signature(&self) -> &[u8; SIGNATURE_SIZE] {
        &self.signature
    }

    /// Returns true if the gate passed.
    #[must_use]
    pub const fn passed(&self) -> bool {
        matches!(self.result, GateResult::Pass)
    }

    /// Returns true if the gate failed.
    #[must_use]
    pub const fn failed(&self) -> bool {
        matches!(self.result, GateResult::Fail)
    }

    /// Computes the canonical bytes to sign/verify.
    ///
    /// The canonical format is:
    /// `receipt_id|gate_id|work_id|result|bundle_hash_hex|evidence_ids_sorted`
    #[must_use]
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut sorted_ids = self.evidence_ids.clone();
        sorted_ids.sort();

        let bundle_hash_hex = hex_encode(&self.bundle_hash);
        let evidence_ids_str = sorted_ids.join(",");

        format!(
            "{}|{}|{}|{}|{}|{}",
            self.receipt_id,
            self.gate_id,
            self.work_id,
            self.result.as_str(),
            bundle_hash_hex,
            evidence_ids_str
        )
        .into_bytes()
    }

    /// Creates a `GateReceiptGenerated` event payload.
    #[must_use]
    pub fn to_event_payload(&self) -> Vec<u8> {
        let mut sorted_ids = self.evidence_ids.clone();
        sorted_ids.sort();

        let receipt = GateReceiptGenerated {
            receipt_id: self.receipt_id.clone(),
            gate_id: self.gate_id.clone(),
            work_id: self.work_id.clone(),
            result: self.result.as_str().to_string(),
            evidence_ids: sorted_ids,
            receipt_signature: self.signature.to_vec(),
        };

        let event = EvidenceEvent {
            event: Some(evidence_event::Event::GateReceipt(receipt)),
        };

        event.encode_to_vec()
    }
}

/// Generator for gate receipts.
///
/// The generator holds a signing key and requirements definition,
/// and produces signed gate receipts from evidence bundles.
pub struct GateReceiptGenerator {
    signer: Signer,
    requirements: GateRequirements,
}

impl GateReceiptGenerator {
    /// Creates a new gate receipt generator.
    #[must_use]
    pub const fn new(signer: Signer, requirements: GateRequirements) -> Self {
        Self {
            signer,
            requirements,
        }
    }

    /// Returns a reference to the requirements.
    #[must_use]
    pub const fn requirements(&self) -> &GateRequirements {
        &self.requirements
    }

    /// Returns the public key bytes for verification.
    #[must_use]
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signer.public_key_bytes()
    }

    /// Generates a gate receipt from an evidence bundle.
    ///
    /// This method:
    /// 1. Validates the gate ID
    /// 2. Validates evidence completeness against requirements
    /// 3. Computes the PASS/FAIL result
    /// 4. Auto-populates receipt fields from bundle data
    /// 5. Signs the receipt
    ///
    /// # Arguments
    ///
    /// * `gate_id` - Identifier for the gate being reviewed. Must be non-empty,
    ///   at most 256 bytes, and contain only ASCII printable characters without
    ///   path separators or the canonical format delimiter (`|`).
    /// * `bundle` - The evidence bundle to review
    /// * `timestamp` - Timestamp for the receipt (Unix nanos)
    ///
    /// # Returns
    ///
    /// A signed gate receipt ready for event emission, or an error if
    /// validation fails.
    ///
    /// # Errors
    ///
    /// Returns [`EvidenceError::InvalidGateId`] if the gate ID is invalid.
    /// Returns [`EvidenceError::InvalidWorkId`] if the bundle's work ID is
    /// invalid. Returns [`EvidenceError::InvalidEvidenceId`] if any evidence
    /// ID in the bundle is invalid.
    pub fn generate(
        &self,
        gate_id: &str,
        bundle: &EvidenceBundle,
        timestamp: u64,
    ) -> Result<GateReceipt, EvidenceError> {
        // Validate all IDs first (fail-closed, defense-in-depth)
        // These should already be validated by the reducer, but we re-check
        // since they're used in the cryptographic canonical format.
        validate_gate_id(gate_id)?;
        validate_work_id(&bundle.work_id)?;
        validate_evidence_ids(&bundle.evidence_ids)?;

        // Generate receipt ID deterministically from bundle hash and gate
        let receipt_id = self.generate_receipt_id(gate_id, &bundle.bundle_hash);

        // Validate and compute result
        let (result, reason_code) = self.evaluate_bundle(bundle);

        // Create the receipt (unsigned)
        let mut receipt = GateReceipt {
            receipt_id,
            gate_id: gate_id.to_string(),
            work_id: bundle.work_id.clone(),
            result,
            reason_code,
            evidence_ids: bundle.evidence_ids.clone(),
            bundle_hash: bundle.bundle_hash,
            categories_present: bundle.categories.clone(),
            total_evidence_size: bundle.total_size,
            generated_at: timestamp,
            signature: [0u8; SIGNATURE_SIZE],
        };

        // Sign the receipt
        let canonical = receipt.canonical_bytes();
        let signature = self.signer.sign(&canonical);
        receipt.signature = signature.to_bytes();

        Ok(receipt)
    }

    /// Generates a gate receipt with a specific receipt ID.
    ///
    /// Use this when you need deterministic receipt IDs for testing.
    ///
    /// # Arguments
    ///
    /// * `receipt_id` - Custom receipt identifier. Must be non-empty, at most
    ///   256 bytes, and contain only ASCII printable characters without path
    ///   separators or the canonical format delimiter (`|`).
    /// * `gate_id` - Identifier for the gate being reviewed
    /// * `bundle` - The evidence bundle to review
    /// * `timestamp` - Timestamp for the receipt (Unix nanos)
    ///
    /// # Errors
    ///
    /// Returns [`EvidenceError::InvalidReceiptId`] if the receipt ID is
    /// invalid. Returns [`EvidenceError::InvalidGateId`] if the gate ID is
    /// invalid. Returns [`EvidenceError::InvalidWorkId`] if the bundle's
    /// work ID is invalid. Returns [`EvidenceError::InvalidEvidenceId`] if
    /// any evidence ID in the bundle is invalid.
    pub fn generate_with_id(
        &self,
        receipt_id: &str,
        gate_id: &str,
        bundle: &EvidenceBundle,
        timestamp: u64,
    ) -> Result<GateReceipt, EvidenceError> {
        // Validate all IDs first (fail-closed, defense-in-depth)
        validate_receipt_id(receipt_id)?;
        validate_gate_id(gate_id)?;
        validate_work_id(&bundle.work_id)?;
        validate_evidence_ids(&bundle.evidence_ids)?;

        let (result, reason_code) = self.evaluate_bundle(bundle);

        let mut receipt = GateReceipt {
            receipt_id: receipt_id.to_string(),
            gate_id: gate_id.to_string(),
            work_id: bundle.work_id.clone(),
            result,
            reason_code,
            evidence_ids: bundle.evidence_ids.clone(),
            bundle_hash: bundle.bundle_hash,
            categories_present: bundle.categories.clone(),
            total_evidence_size: bundle.total_size,
            generated_at: timestamp,
            signature: [0u8; SIGNATURE_SIZE],
        };

        let canonical = receipt.canonical_bytes();
        let signature = self.signer.sign(&canonical);
        receipt.signature = signature.to_bytes();

        Ok(receipt)
    }

    /// Verifies a gate receipt's signature.
    ///
    /// # Returns
    ///
    /// `true` if the signature is valid for this generator's public key.
    #[must_use]
    pub fn verify(&self, receipt: &GateReceipt) -> bool {
        let canonical = receipt.canonical_bytes();
        let signature = Signature::from_bytes(&receipt.signature);
        self.signer.verify(&canonical, &signature)
    }

    /// Evaluates an evidence bundle against requirements.
    ///
    /// Returns the result and reason code.
    fn evaluate_bundle(&self, bundle: &EvidenceBundle) -> (GateResult, GateReasonCode) {
        // Check for empty bundle
        if bundle.is_empty() && self.requirements.fail_on_empty {
            return (GateResult::Fail, GateReasonCode::EmptyBundle);
        }

        // Check minimum evidence count
        if bundle.evidence_count() < self.requirements.min_evidence_count {
            return (
                GateResult::Fail,
                GateReasonCode::MissingRequiredCategory {
                    missing: vec![], // Count failure, not category
                },
            );
        }

        // Check required categories
        let missing: Vec<EvidenceCategory> = self
            .requirements
            .required_categories
            .iter()
            .filter(|cat| !bundle.has_category(**cat))
            .copied()
            .collect();

        if !missing.is_empty() {
            return (
                GateResult::Fail,
                GateReasonCode::MissingRequiredCategory { missing },
            );
        }

        // All requirements met
        (GateResult::Pass, GateReasonCode::AllRequirementsMet)
    }

    /// Generates a deterministic receipt ID from gate and bundle hash.
    #[allow(clippy::unused_self)] // self reserved for future use (e.g., signer key in ID)
    fn generate_receipt_id(&self, gate_id: &str, bundle_hash: &Hash) -> String {
        // Use first 8 bytes of bundle hash as suffix
        let hash_suffix = hex_encode(&bundle_hash[..8]);
        format!("rcpt-{gate_id}-{hash_suffix}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_bundle(
        work_id: &str,
        evidence_ids: Vec<&str>,
        categories: Vec<EvidenceCategory>,
    ) -> EvidenceBundle {
        EvidenceBundle::new(
            work_id.to_string(),
            [1u8; 32],
            evidence_ids.into_iter().map(String::from).collect(),
            categories,
            1024,
            1_000_000_000,
        )
    }

    #[test]
    fn test_gate_result_as_str() {
        assert_eq!(GateResult::Pass.as_str(), "PASS");
        assert_eq!(GateResult::Fail.as_str(), "FAIL");
    }

    #[test]
    fn test_gate_result_parse() {
        assert_eq!(GateResult::parse("PASS"), Some(GateResult::Pass));
        assert_eq!(GateResult::parse("pass"), Some(GateResult::Pass));
        assert_eq!(GateResult::parse("FAIL"), Some(GateResult::Fail));
        assert_eq!(GateResult::parse("fail"), Some(GateResult::Fail));
        assert_eq!(GateResult::parse("UNKNOWN"), None);
    }

    #[test]
    fn test_gate_requirements_default() {
        let req = GateRequirements::default();
        assert_eq!(req.required_categories, vec![EvidenceCategory::TestResults]);
        assert_eq!(req.min_evidence_count, 1);
        assert!(req.fail_on_empty);
    }

    #[test]
    fn test_gate_requirements_permissive() {
        let req = GateRequirements::permissive();
        assert!(req.required_categories.is_empty());
        assert_eq!(req.min_evidence_count, 1);
    }

    #[test]
    fn test_gate_requirements_high_assurance() {
        let req = GateRequirements::high_assurance();
        assert_eq!(req.required_categories.len(), 3);
        assert!(
            req.required_categories
                .contains(&EvidenceCategory::TestResults)
        );
        assert!(
            req.required_categories
                .contains(&EvidenceCategory::LintReports)
        );
        assert!(
            req.required_categories
                .contains(&EvidenceCategory::SecurityScans)
        );
        assert_eq!(req.min_evidence_count, 3);
    }

    #[test]
    fn test_generate_receipt_pass() {
        let signer = Signer::generate();
        let requirements = GateRequirements::default();
        let generator = GateReceiptGenerator::new(signer, requirements);

        let bundle = make_test_bundle(
            "work-123",
            vec!["evid-001"],
            vec![EvidenceCategory::TestResults],
        );

        let receipt = generator
            .generate("gate-001", &bundle, 2_000_000_000)
            .unwrap();

        assert!(receipt.passed());
        assert!(!receipt.failed());
        assert_eq!(receipt.result, GateResult::Pass);
        assert_eq!(receipt.gate_id, "gate-001");
        assert_eq!(receipt.work_id, "work-123");
        assert!(receipt.is_signed());
        assert!(matches!(
            receipt.reason_code,
            GateReasonCode::AllRequirementsMet
        ));
    }

    #[test]
    fn test_generate_receipt_fail_missing_category() {
        let signer = Signer::generate();
        let requirements = GateRequirements::default(); // Requires TestResults
        let generator = GateReceiptGenerator::new(signer, requirements);

        // Bundle with wrong category
        let bundle = make_test_bundle(
            "work-123",
            vec!["evid-001"],
            vec![EvidenceCategory::LintReports],
        );

        let receipt = generator
            .generate("gate-001", &bundle, 2_000_000_000)
            .unwrap();

        assert!(receipt.failed());
        assert_eq!(receipt.result, GateResult::Fail);
        if let GateReasonCode::MissingRequiredCategory { missing } = &receipt.reason_code {
            assert!(missing.contains(&EvidenceCategory::TestResults));
        } else {
            panic!("Expected MissingRequiredCategory");
        }
    }

    #[test]
    fn test_generate_receipt_fail_empty_bundle() {
        let signer = Signer::generate();
        let requirements = GateRequirements::default();
        let generator = GateReceiptGenerator::new(signer, requirements);

        let bundle = make_test_bundle("work-123", vec![], vec![]);

        let receipt = generator
            .generate("gate-001", &bundle, 2_000_000_000)
            .unwrap();

        assert!(receipt.failed());
        assert!(matches!(receipt.reason_code, GateReasonCode::EmptyBundle));
    }

    #[test]
    fn test_generate_receipt_fail_min_count() {
        let signer = Signer::generate();
        let requirements = GateRequirements::permissive().with_min_count(3);
        let generator = GateReceiptGenerator::new(signer, requirements);

        // Only 2 evidence items
        let bundle = make_test_bundle(
            "work-123",
            vec!["evid-001", "evid-002"],
            vec![EvidenceCategory::TestResults],
        );

        let receipt = generator
            .generate("gate-001", &bundle, 2_000_000_000)
            .unwrap();

        assert!(receipt.failed());
    }

    #[test]
    fn test_generate_receipt_high_assurance_pass() {
        let signer = Signer::generate();
        let requirements = GateRequirements::high_assurance();
        let generator = GateReceiptGenerator::new(signer, requirements);

        let bundle = make_test_bundle(
            "work-123",
            vec!["evid-001", "evid-002", "evid-003"],
            vec![
                EvidenceCategory::TestResults,
                EvidenceCategory::LintReports,
                EvidenceCategory::SecurityScans,
            ],
        );

        let receipt = generator
            .generate("gate-001", &bundle, 2_000_000_000)
            .unwrap();

        assert!(receipt.passed());
    }

    #[test]
    fn test_generate_receipt_high_assurance_fail() {
        let signer = Signer::generate();
        let requirements = GateRequirements::high_assurance();
        let generator = GateReceiptGenerator::new(signer, requirements);

        // Missing SecurityScans
        let bundle = make_test_bundle(
            "work-123",
            vec!["evid-001", "evid-002", "evid-003"],
            vec![EvidenceCategory::TestResults, EvidenceCategory::LintReports],
        );

        let receipt = generator
            .generate("gate-001", &bundle, 2_000_000_000)
            .unwrap();

        assert!(receipt.failed());
        if let GateReasonCode::MissingRequiredCategory { missing } = &receipt.reason_code {
            assert!(missing.contains(&EvidenceCategory::SecurityScans));
        } else {
            panic!("Expected MissingRequiredCategory");
        }
    }

    #[test]
    fn test_verify_signature() {
        let signer = Signer::generate();
        let requirements = GateRequirements::default();
        let generator = GateReceiptGenerator::new(signer, requirements);

        let bundle = make_test_bundle(
            "work-123",
            vec!["evid-001"],
            vec![EvidenceCategory::TestResults],
        );

        let receipt = generator
            .generate("gate-001", &bundle, 2_000_000_000)
            .unwrap();

        // Generator can verify its own receipts
        assert!(generator.verify(&receipt));
    }

    #[test]
    fn test_verify_fails_for_wrong_key() {
        let signer1 = Signer::generate();
        let signer2 = Signer::generate();
        let requirements = GateRequirements::default();

        let generator1 = GateReceiptGenerator::new(signer1, requirements.clone());
        let generator2 = GateReceiptGenerator::new(signer2, requirements);

        let bundle = make_test_bundle(
            "work-123",
            vec!["evid-001"],
            vec![EvidenceCategory::TestResults],
        );

        let receipt = generator1
            .generate("gate-001", &bundle, 2_000_000_000)
            .unwrap();

        // generator2 should NOT verify generator1's receipt
        assert!(!generator2.verify(&receipt));
    }

    #[test]
    fn test_generate_with_id() {
        let signer = Signer::generate();
        let requirements = GateRequirements::default();
        let generator = GateReceiptGenerator::new(signer, requirements);

        let bundle = make_test_bundle(
            "work-123",
            vec!["evid-001"],
            vec![EvidenceCategory::TestResults],
        );

        let receipt = generator
            .generate_with_id("custom-id-001", "gate-001", &bundle, 2_000_000_000)
            .unwrap();

        assert_eq!(receipt.receipt_id, "custom-id-001");
        assert!(receipt.is_signed());
        assert!(generator.verify(&receipt));
    }

    #[test]
    fn test_to_event_payload() {
        let signer = Signer::generate();
        let requirements = GateRequirements::default();
        let generator = GateReceiptGenerator::new(signer, requirements);

        let bundle = make_test_bundle(
            "work-123",
            vec!["evid-002", "evid-001"], // Unsorted
            vec![EvidenceCategory::TestResults],
        );

        let receipt = generator
            .generate("gate-001", &bundle, 2_000_000_000)
            .unwrap();
        let payload = receipt.to_event_payload();

        // Decode and verify
        let event = EvidenceEvent::decode(&payload[..]).unwrap();
        if let Some(evidence_event::Event::GateReceipt(gr)) = event.event {
            assert_eq!(gr.work_id, "work-123");
            assert_eq!(gr.result, "PASS");
            // Evidence IDs should be sorted
            assert_eq!(gr.evidence_ids, vec!["evid-001", "evid-002"]);
            assert_eq!(gr.receipt_signature.len(), SIGNATURE_SIZE);
        } else {
            panic!("Expected GateReceipt event");
        }
    }

    #[test]
    fn test_receipt_id_deterministic() {
        let signer = Signer::generate();
        let requirements = GateRequirements::default();
        let generator = GateReceiptGenerator::new(signer, requirements);

        let bundle = make_test_bundle(
            "work-123",
            vec!["evid-001"],
            vec![EvidenceCategory::TestResults],
        );

        let receipt1 = generator
            .generate("gate-001", &bundle, 1_000_000_000)
            .unwrap();
        let receipt2 = generator
            .generate("gate-001", &bundle, 2_000_000_000)
            .unwrap();

        // Same gate + bundle should produce same receipt ID (timestamp differs)
        assert_eq!(receipt1.receipt_id, receipt2.receipt_id);
    }

    #[test]
    fn test_reason_code_description() {
        let desc = GateReasonCode::AllRequirementsMet.description();
        assert!(desc.contains("present"));

        let desc = GateReasonCode::MissingRequiredCategory {
            missing: vec![EvidenceCategory::TestResults],
        }
        .description();
        assert!(desc.contains("TEST_RESULTS"));

        let desc = GateReasonCode::EmptyBundle.description();
        assert!(desc.contains("empty"));
    }

    #[test]
    fn test_auto_population_coverage() {
        // Verify that 80-95% of receipt fields are auto-populated from bundle
        let signer = Signer::generate();
        let requirements = GateRequirements::default();
        let generator = GateReceiptGenerator::new(signer, requirements);

        let bundle = make_test_bundle(
            "work-123",
            vec!["evid-001", "evid-002"],
            vec![EvidenceCategory::TestResults, EvidenceCategory::LintReports],
        );

        let receipt = generator
            .generate("gate-001", &bundle, 2_000_000_000)
            .unwrap();

        // Auto-populated from bundle:
        // - work_id (from bundle)
        // - evidence_ids (from bundle)
        // - bundle_hash (from bundle)
        // - categories_present (from bundle)
        // - total_evidence_size (from bundle)
        // Auto-computed:
        // - result (computed from requirements)
        // - reason_code (computed from requirements)
        // - receipt_id (computed from gate_id + bundle_hash)
        // - signature (computed)
        // From input:
        // - gate_id (input)
        // - generated_at (input timestamp)

        // Total fields: 11
        // Auto-populated/computed: 9 (receipt_id, work_id, result, reason_code,
        //                             evidence_ids, bundle_hash, categories_present,
        //                             total_evidence_size, signature)
        // From input: 2 (gate_id, generated_at)
        // Auto-population rate: 9/11 = 81.8% (within 80-95% target)

        assert_eq!(receipt.work_id, bundle.work_id);
        assert_eq!(receipt.evidence_ids, bundle.evidence_ids);
        assert_eq!(receipt.bundle_hash, bundle.bundle_hash);
        assert_eq!(receipt.categories_present, bundle.categories);
        assert_eq!(receipt.total_evidence_size, bundle.total_size);
    }

    #[test]
    fn test_canonical_bytes_deterministic() {
        let signer = Signer::generate();
        let requirements = GateRequirements::default();
        let generator = GateReceiptGenerator::new(signer, requirements);

        let bundle = make_test_bundle(
            "work-123",
            vec!["evid-002", "evid-001"], // Unsorted order
            vec![EvidenceCategory::TestResults],
        );

        let receipt = generator
            .generate("gate-001", &bundle, 2_000_000_000)
            .unwrap();

        // Canonical bytes should always have sorted evidence IDs
        let canonical1 = receipt.canonical_bytes();
        let canonical2 = receipt.canonical_bytes();
        assert_eq!(canonical1, canonical2);

        // Should contain sorted evidence IDs
        let canonical_str = String::from_utf8(canonical1).unwrap();
        assert!(canonical_str.contains("evid-001,evid-002"));
    }

    // =========================================================================
    // Security tests for input validation (CRITICAL: Canonicalization Injection)
    // =========================================================================

    #[test]
    fn test_generate_rejects_empty_gate_id() {
        let signer = Signer::generate();
        let requirements = GateRequirements::default();
        let generator = GateReceiptGenerator::new(signer, requirements);

        let bundle = make_test_bundle(
            "work-123",
            vec!["evid-001"],
            vec![EvidenceCategory::TestResults],
        );

        let result = generator.generate("", &bundle, 2_000_000_000);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            EvidenceError::InvalidGateId { .. }
        ));
    }

    #[test]
    fn test_generate_rejects_gate_id_with_pipe_separator() {
        // Pipe is used as field separator in canonical format - injection attack vector
        let signer = Signer::generate();
        let requirements = GateRequirements::default();
        let generator = GateReceiptGenerator::new(signer, requirements);

        let bundle = make_test_bundle(
            "work-123",
            vec!["evid-001"],
            vec![EvidenceCategory::TestResults],
        );

        let result = generator.generate("gate|injection", &bundle, 2_000_000_000);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            EvidenceError::InvalidGateId { .. }
        ));
    }

    #[test]
    fn test_generate_rejects_gate_id_with_path_traversal() {
        let signer = Signer::generate();
        let requirements = GateRequirements::default();
        let generator = GateReceiptGenerator::new(signer, requirements);

        let bundle = make_test_bundle(
            "work-123",
            vec!["evid-001"],
            vec![EvidenceCategory::TestResults],
        );

        // Test forward slash
        let result = generator.generate("gate/traversal", &bundle, 2_000_000_000);
        assert!(result.is_err());

        // Test backslash
        let result = generator.generate("gate\\traversal", &bundle, 2_000_000_000);
        assert!(result.is_err());

        // Test parent directory traversal
        let result = generator.generate("gate..traversal", &bundle, 2_000_000_000);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_rejects_gate_id_with_control_characters() {
        let signer = Signer::generate();
        let requirements = GateRequirements::default();
        let generator = GateReceiptGenerator::new(signer, requirements);

        let bundle = make_test_bundle(
            "work-123",
            vec!["evid-001"],
            vec![EvidenceCategory::TestResults],
        );

        // Test newline (log injection)
        let result = generator.generate("gate\ninjection", &bundle, 2_000_000_000);
        assert!(result.is_err());

        // Test carriage return
        let result = generator.generate("gate\rinjection", &bundle, 2_000_000_000);
        assert!(result.is_err());

        // Test null byte
        let result = generator.generate("gate\0injection", &bundle, 2_000_000_000);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_rejects_gate_id_too_long() {
        let signer = Signer::generate();
        let requirements = GateRequirements::default();
        let generator = GateReceiptGenerator::new(signer, requirements);

        let bundle = make_test_bundle(
            "work-123",
            vec!["evid-001"],
            vec![EvidenceCategory::TestResults],
        );

        // Create a gate ID that exceeds the maximum length
        let long_gate_id = "g".repeat(257);
        let result = generator.generate(&long_gate_id, &bundle, 2_000_000_000);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            EvidenceError::InvalidGateId { .. }
        ));
    }

    #[test]
    fn test_generate_with_id_rejects_invalid_receipt_id() {
        let signer = Signer::generate();
        let requirements = GateRequirements::default();
        let generator = GateReceiptGenerator::new(signer, requirements);

        let bundle = make_test_bundle(
            "work-123",
            vec!["evid-001"],
            vec![EvidenceCategory::TestResults],
        );

        // Empty receipt ID
        let result = generator.generate_with_id("", "gate-001", &bundle, 2_000_000_000);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            EvidenceError::InvalidReceiptId { .. }
        ));

        // Receipt ID with pipe separator
        let result =
            generator.generate_with_id("rcpt|injection", "gate-001", &bundle, 2_000_000_000);
        assert!(result.is_err());

        // Receipt ID with path traversal
        let result =
            generator.generate_with_id("rcpt/../attack", "gate-001", &bundle, 2_000_000_000);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_with_id_rejects_invalid_gate_id() {
        let signer = Signer::generate();
        let requirements = GateRequirements::default();
        let generator = GateReceiptGenerator::new(signer, requirements);

        let bundle = make_test_bundle(
            "work-123",
            vec!["evid-001"],
            vec![EvidenceCategory::TestResults],
        );

        // Valid receipt ID but invalid gate ID
        let result =
            generator.generate_with_id("rcpt-001", "gate|injection", &bundle, 2_000_000_000);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            EvidenceError::InvalidGateId { .. }
        ));
    }

    #[test]
    fn test_generate_accepts_valid_gate_id_with_hyphens_and_dots() {
        // Valid gate IDs should work: alphanumeric, hyphens, underscores, dots
        let signer = Signer::generate();
        let requirements = GateRequirements::default();
        let generator = GateReceiptGenerator::new(signer, requirements);

        let bundle = make_test_bundle(
            "work-123",
            vec!["evid-001"],
            vec![EvidenceCategory::TestResults],
        );

        // These should all succeed
        let result = generator.generate("gate-001", &bundle, 2_000_000_000);
        assert!(result.is_ok());

        let result = generator.generate("gate_001", &bundle, 2_000_000_000);
        assert!(result.is_ok());

        let result = generator.generate("gate.v1.0", &bundle, 2_000_000_000);
        assert!(result.is_ok());

        let result = generator.generate("GATE-001-PROD", &bundle, 2_000_000_000);
        assert!(result.is_ok());
    }

    #[test]
    fn test_generate_rejects_non_ascii_characters() {
        let signer = Signer::generate();
        let requirements = GateRequirements::default();
        let generator = GateReceiptGenerator::new(signer, requirements);

        let bundle = make_test_bundle(
            "work-123",
            vec!["evid-001"],
            vec![EvidenceCategory::TestResults],
        );

        // Unicode characters are not allowed
        let result = generator.generate("gate-\u{0080}", &bundle, 2_000_000_000);
        assert!(result.is_err());

        // Emoji is not allowed
        let result = generator.generate("gate-\u{1F600}", &bundle, 2_000_000_000);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_id_boundary_length() {
        let signer = Signer::generate();
        let requirements = GateRequirements::default();
        let generator = GateReceiptGenerator::new(signer, requirements);

        let bundle = make_test_bundle(
            "work-123",
            vec!["evid-001"],
            vec![EvidenceCategory::TestResults],
        );

        // Exactly 256 bytes should succeed
        let max_gate_id = "g".repeat(256);
        let result = generator.generate(&max_gate_id, &bundle, 2_000_000_000);
        assert!(result.is_ok());

        // 257 bytes should fail
        let over_max_gate_id = "g".repeat(257);
        let result = generator.generate(&over_max_gate_id, &bundle, 2_000_000_000);
        assert!(result.is_err());
    }

    // =========================================================================
    // Security tests for bundle data validation (defense-in-depth)
    // =========================================================================

    #[test]
    fn test_generate_rejects_work_id_with_pipe() {
        let signer = Signer::generate();
        let requirements = GateRequirements::default();
        let generator = GateReceiptGenerator::new(signer, requirements);

        // Create bundle with malicious work_id containing pipe
        let bundle = EvidenceBundle::new(
            "work|injection".to_string(),
            [1u8; 32],
            vec!["evid-001".to_string()],
            vec![EvidenceCategory::TestResults],
            1024,
            1_000_000_000,
        );

        let result = generator.generate("gate-001", &bundle, 2_000_000_000);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            EvidenceError::InvalidWorkId { .. }
        ));
    }

    #[test]
    fn test_generate_rejects_evidence_id_with_comma() {
        let signer = Signer::generate();
        let requirements = GateRequirements::default();
        let generator = GateReceiptGenerator::new(signer, requirements);

        // Create bundle with malicious evidence_id containing comma
        let bundle = EvidenceBundle::new(
            "work-123".to_string(),
            [1u8; 32],
            vec!["evid,injection".to_string()],
            vec![EvidenceCategory::TestResults],
            1024,
            1_000_000_000,
        );

        let result = generator.generate("gate-001", &bundle, 2_000_000_000);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            EvidenceError::InvalidEvidenceId { .. }
        ));
    }

    #[test]
    fn test_generate_rejects_work_id_with_path_traversal() {
        let signer = Signer::generate();
        let requirements = GateRequirements::default();
        let generator = GateReceiptGenerator::new(signer, requirements);

        // Create bundle with malicious work_id containing path traversal
        let bundle = EvidenceBundle::new(
            "work/../attack".to_string(),
            [1u8; 32],
            vec!["evid-001".to_string()],
            vec![EvidenceCategory::TestResults],
            1024,
            1_000_000_000,
        );

        let result = generator.generate("gate-001", &bundle, 2_000_000_000);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            EvidenceError::InvalidWorkId { .. }
        ));
    }

    #[test]
    fn test_generate_rejects_evidence_id_with_path_traversal() {
        let signer = Signer::generate();
        let requirements = GateRequirements::default();
        let generator = GateReceiptGenerator::new(signer, requirements);

        // Create bundle with malicious evidence_id containing path traversal
        let bundle = EvidenceBundle::new(
            "work-123".to_string(),
            [1u8; 32],
            vec!["evid-001".to_string(), "evid/../attack".to_string()],
            vec![EvidenceCategory::TestResults],
            1024,
            1_000_000_000,
        );

        let result = generator.generate("gate-001", &bundle, 2_000_000_000);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            EvidenceError::InvalidEvidenceId { .. }
        ));
    }

    #[test]
    fn test_generate_with_id_rejects_invalid_bundle_data() {
        let signer = Signer::generate();
        let requirements = GateRequirements::default();
        let generator = GateReceiptGenerator::new(signer, requirements);

        // Test with invalid work_id
        let bundle = EvidenceBundle::new(
            "work|attack".to_string(),
            [1u8; 32],
            vec!["evid-001".to_string()],
            vec![EvidenceCategory::TestResults],
            1024,
            1_000_000_000,
        );

        let result = generator.generate_with_id("rcpt-001", "gate-001", &bundle, 2_000_000_000);
        assert!(result.is_err());

        // Test with invalid evidence_id
        let bundle = EvidenceBundle::new(
            "work-123".to_string(),
            [1u8; 32],
            vec!["evid,attack".to_string()],
            vec![EvidenceCategory::TestResults],
            1024,
            1_000_000_000,
        );

        let result = generator.generate_with_id("rcpt-001", "gate-001", &bundle, 2_000_000_000);
        assert!(result.is_err());
    }
}
