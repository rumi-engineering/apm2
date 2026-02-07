//! AAT Receipt for selftest verification.
//!
//! This module provides the [`AATReceipt`] type for cryptographically signing
//! selftest results and binding them to a specific binary version.
//!
//! # Binary Hash Binding
//!
//! Per DD-0006, AAT receipts are bound to the binary version via `binary_hash`.
//! This prevents receipt replay across different binary versions - a receipt
//! generated for version 0.3.0 cannot be used to attest capabilities of
//! version 0.4.0.
//!
//! # Signing Pattern
//!
//! The signing pattern follows [`GateReceipt`](super::GateReceipt) for
//! consistency:
//! 1. Construct canonical bytes from receipt fields
//! 2. Sign canonical bytes with Ed25519
//! 3. Store signature in receipt
//!
//! # Example
//!
//! ```rust
//! use apm2_core::crypto::Signer;
//! use apm2_core::evidence::aat_receipt::{AATReceipt, AATReceiptGenerator, TestSummary};
//!
//! // Create a generator with a signing key
//! let signer = Signer::generate();
//! let binary_hash = "abc123def456".repeat(5); // 60 chars for demo
//! let binary_hash = format!("{:0<64}", binary_hash); // Pad to 64 chars
//! let generator = AATReceiptGenerator::new(signer, binary_hash);
//!
//! // Generate a receipt
//! let summary = TestSummary {
//!     tests_passed: 10,
//!     tests_failed: 0,
//!     tests_skipped: 0,
//! };
//! let receipt = generator
//!     .generate("rcpt-001", summary, 1_000_000_000)
//!     .unwrap();
//!
//! // Verify the receipt
//! assert!(generator.verify(&receipt));
//! assert!(receipt.verify_binary_hash(&generator.binary_hash()));
//! ```
//!
//! # Security Properties
//!
//! - **Binary hash binding**: Receipts cannot be replayed across versions
//! - **Ed25519 signature**: Receipts cannot be forged
//! - **Canonical format**: Deterministic signing input

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::crypto::{SIGNATURE_SIZE, Signature, Signer, parse_signature, verify_signature};

// ============================================================================
// Constants
// ============================================================================

/// Maximum length for receipt IDs.
pub const MAX_RECEIPT_ID_LENGTH: usize = 256;

/// Maximum length for binary hash strings.
/// BLAKE3 produces 64 hex characters.
pub const MAX_BINARY_HASH_LENGTH: usize = 64;

/// Characters that are forbidden in receipt IDs because they break canonical
/// serialization.
const FORBIDDEN_ID_CHARS: &[char] = &['|', ',', '/', '\\', '\n', '\r', '\0'];

// ============================================================================
// Errors
// ============================================================================

/// Errors that can occur during AAT receipt operations.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AATReceiptError {
    /// The receipt ID is invalid.
    InvalidReceiptId {
        /// The reason the ID is invalid.
        reason: String,
    },
    /// The binary hash is invalid.
    InvalidBinaryHash {
        /// The reason the hash is invalid.
        reason: String,
    },
    /// Binary hash mismatch (stale receipt).
    BinaryHashMismatch {
        /// Expected binary hash.
        expected: String,
        /// Actual binary hash in receipt.
        actual: String,
    },
    /// Signature verification failed.
    SignatureVerificationFailed,
    /// Signature is malformed.
    MalformedSignature {
        /// The reason the signature is malformed.
        reason: String,
    },
    /// A capability ID is invalid.
    InvalidCapabilityId {
        /// The invalid capability ID.
        id: String,
        /// The reason it's invalid.
        reason: String,
    },
}

impl std::fmt::Display for AATReceiptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidReceiptId { reason } => {
                write!(f, "invalid receipt ID: {reason}")
            },
            Self::InvalidBinaryHash { reason } => {
                write!(f, "invalid binary hash: {reason}")
            },
            Self::BinaryHashMismatch { expected, actual } => {
                write!(f, "binary hash mismatch: expected {expected}, got {actual}")
            },
            Self::SignatureVerificationFailed => {
                write!(f, "signature verification failed")
            },
            Self::MalformedSignature { reason } => {
                write!(f, "malformed signature: {reason}")
            },
            Self::InvalidCapabilityId { id, reason } => {
                write!(f, "invalid capability ID '{id}': {reason}")
            },
        }
    }
}

impl std::error::Error for AATReceiptError {}

// ============================================================================
// Validation Helpers
// ============================================================================

/// Validates a "safe ID" that can be used in canonical serialization.
///
/// Safe IDs must:
/// - Be non-empty
/// - Not exceed the maximum length
/// - Not contain forbidden characters (`|`, `,`, `/`, `\`, `\n`, `\r`, `\0`)
/// - Not contain path traversal sequences (`..`)
/// - Contain only ASCII printable characters
///
/// This function is shared between receipt IDs and capability IDs to ensure
/// consistent canonicalization safety.
///
/// # Arguments
///
/// * `id` - The ID to validate
/// * `max_length` - Maximum allowed length
///
/// # Returns
///
/// `Ok(())` if valid, or a reason string describing the validation failure.
///
/// # Errors
///
/// Returns `Err(String)` with a description of why the ID is invalid if:
/// - The ID is empty
/// - The ID exceeds the maximum length
/// - The ID contains forbidden characters
/// - The ID contains path traversal sequences
/// - The ID contains non-ASCII or control characters
pub fn validate_safe_id(id: &str, max_length: usize) -> Result<(), String> {
    if id.is_empty() {
        return Err("cannot be empty".to_string());
    }

    if id.len() > max_length {
        return Err(format!("exceeds maximum length of {max_length}"));
    }

    for forbidden in FORBIDDEN_ID_CHARS {
        if id.contains(*forbidden) {
            return Err(format!("contains forbidden character: {forbidden:?}"));
        }
    }

    // Check for path traversal
    if id.contains("..") {
        return Err("contains path traversal sequence: ..".to_string());
    }

    // Check for non-ASCII printable characters
    for (i, c) in id.chars().enumerate() {
        if !c.is_ascii() || c.is_ascii_control() {
            return Err(format!("contains invalid character at position {i}: {c:?}"));
        }
    }

    Ok(())
}

/// Validates a receipt ID.
fn validate_receipt_id(id: &str) -> Result<(), AATReceiptError> {
    validate_safe_id(id, MAX_RECEIPT_ID_LENGTH).map_err(|reason| {
        AATReceiptError::InvalidReceiptId {
            reason: format!("receipt ID {reason}"),
        }
    })
}

/// Validates a capability ID for use in AAT receipts.
fn validate_capability_id(id: &str) -> Result<(), AATReceiptError> {
    validate_safe_id(id, MAX_RECEIPT_ID_LENGTH).map_err(|reason| {
        AATReceiptError::InvalidCapabilityId {
            id: id.chars().take(50).collect(),
            reason,
        }
    })
}

/// Validates a binary hash.
fn validate_binary_hash(hash: &str) -> Result<(), AATReceiptError> {
    if hash.is_empty() {
        return Err(AATReceiptError::InvalidBinaryHash {
            reason: "binary hash cannot be empty".to_string(),
        });
    }

    if hash.len() != MAX_BINARY_HASH_LENGTH {
        return Err(AATReceiptError::InvalidBinaryHash {
            reason: format!(
                "binary hash must be exactly {MAX_BINARY_HASH_LENGTH} characters, got {}",
                hash.len()
            ),
        });
    }

    // Verify it's valid hexadecimal
    if !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AATReceiptError::InvalidBinaryHash {
            reason: "binary hash must contain only hexadecimal characters".to_string(),
        });
    }

    Ok(())
}

// ============================================================================
// TestSummary
// ============================================================================

/// Summary of test execution results.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestSummary {
    /// Number of tests that passed.
    pub tests_passed: u32,

    /// Number of tests that failed.
    pub tests_failed: u32,

    /// Number of tests that were skipped.
    pub tests_skipped: u32,
}

impl TestSummary {
    /// Creates a new test summary.
    #[must_use]
    pub const fn new(tests_passed: u32, tests_failed: u32, tests_skipped: u32) -> Self {
        Self {
            tests_passed,
            tests_failed,
            tests_skipped,
        }
    }

    /// Returns the total number of tests.
    #[must_use]
    pub const fn total(&self) -> u32 {
        self.tests_passed + self.tests_failed + self.tests_skipped
    }

    /// Returns true if all tests passed (none failed).
    #[must_use]
    pub const fn all_passed(&self) -> bool {
        self.tests_failed == 0 && self.tests_passed > 0
    }

    /// Returns the pass rate as a percentage.
    #[must_use]
    pub fn pass_rate(&self) -> f64 {
        let total = self.total();
        if total == 0 {
            0.0
        } else {
            f64::from(self.tests_passed) / f64::from(total) * 100.0
        }
    }
}

// ============================================================================
// BudgetConsumed
// ============================================================================

/// Record of resources consumed during test execution.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetConsumed {
    /// Total duration in milliseconds.
    pub duration_ms: u64,

    /// Number of tool calls made.
    pub tool_calls: u32,

    /// Number of tokens consumed.
    pub tokens: u64,
}

impl BudgetConsumed {
    /// Creates a new budget consumed record.
    #[must_use]
    pub const fn new(duration_ms: u64, tool_calls: u32, tokens: u64) -> Self {
        Self {
            duration_ms,
            tool_calls,
            tokens,
        }
    }

    /// Creates from a Duration.
    ///
    /// # Note
    ///
    /// Duration values exceeding `u64::MAX` milliseconds will be saturated.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // Saturating at u64::MAX is acceptable
    pub fn from_duration(duration: Duration, tool_calls: u32, tokens: u64) -> Self {
        // Saturate at u64::MAX for durations that would overflow (unlikely in practice)
        let millis = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
        Self {
            duration_ms: millis,
            tool_calls,
            tokens,
        }
    }

    /// Returns the duration as a `Duration`.
    #[must_use]
    pub const fn duration(&self) -> Duration {
        Duration::from_millis(self.duration_ms)
    }
}

// ============================================================================
// AATReceipt
// ============================================================================

/// A signed AAT receipt proving selftest execution.
///
/// The receipt includes:
/// - Test results (passed/failed counts)
/// - Binary hash binding (prevents replay across versions)
/// - Ed25519 signature (ensures integrity and origin)
/// - Budget consumption (resource tracking)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct AATReceipt {
    /// Unique identifier for this receipt.
    pub receipt_id: String,

    /// BLAKE3 hash of the binary that ran the tests.
    /// This binds the receipt to a specific binary version.
    pub binary_hash: String,

    /// Summary of test results.
    pub test_summary: TestSummary,

    /// Budget consumed during execution.
    pub budget_consumed: BudgetConsumed,

    /// Capabilities that were tested.
    pub capabilities_tested: Vec<String>,

    /// Timestamp when the receipt was generated (Unix nanos).
    pub generated_at: u64,

    /// Ed25519 signature over the receipt content.
    #[serde(with = "signature_serde")]
    signature: [u8; SIGNATURE_SIZE],
}

/// Custom serde for [u8; 64] signature.
mod signature_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use crate::crypto::SIGNATURE_SIZE;

    pub fn serialize<S>(bytes: &[u8; SIGNATURE_SIZE], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
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

impl AATReceipt {
    /// Returns whether this receipt has a valid signature.
    ///
    /// Note: This only checks that the signature field is non-zero.
    /// Use [`AATReceiptGenerator::verify`] for cryptographic verification.
    #[must_use]
    pub fn is_signed(&self) -> bool {
        self.signature.iter().any(|&b| b != 0)
    }

    /// Returns the signature bytes.
    #[must_use]
    pub const fn signature(&self) -> &[u8; SIGNATURE_SIZE] {
        &self.signature
    }

    /// Returns true if all tests passed.
    #[must_use]
    pub const fn all_passed(&self) -> bool {
        self.test_summary.all_passed()
    }

    /// Verifies that the receipt's binary hash matches the expected hash.
    ///
    /// This is used to reject stale receipts from different binary versions.
    ///
    /// # Arguments
    ///
    /// * `expected_hash` - The binary hash of the current binary
    ///
    /// # Returns
    ///
    /// `true` if the hashes match, `false` if they differ.
    #[must_use]
    pub fn verify_binary_hash(&self, expected_hash: &str) -> bool {
        self.binary_hash == expected_hash
    }

    /// Computes the canonical bytes to sign/verify.
    ///
    /// The canonical format is:
    /// `receipt_id|binary_hash|passed|failed|skipped|capabilities_sorted|timestamp`
    #[must_use]
    pub(crate) fn canonical_bytes(&self) -> Vec<u8> {
        let mut sorted_caps = self.capabilities_tested.clone();
        sorted_caps.sort();

        format!(
            "{}|{}|{}|{}|{}|{}|{}",
            self.receipt_id,
            self.binary_hash,
            self.test_summary.tests_passed,
            self.test_summary.tests_failed,
            self.test_summary.tests_skipped,
            sorted_caps.join(","),
            self.generated_at
        )
        .into_bytes()
    }
}

// ============================================================================
// AATReceiptGenerator
// ============================================================================

/// Generator for AAT receipts.
///
/// The generator holds a signing key and the current binary hash,
/// and produces signed receipts from test results.
pub struct AATReceiptGenerator {
    signer: Signer,
    binary_hash: String,
}

impl AATReceiptGenerator {
    /// Creates a new AAT receipt generator.
    ///
    /// # Arguments
    ///
    /// * `signer` - The Ed25519 signer for signing receipts
    /// * `binary_hash` - The BLAKE3 hash of the current binary
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // String is not Copy, cannot be const
    pub fn new(signer: Signer, binary_hash: String) -> Self {
        Self {
            signer,
            binary_hash,
        }
    }

    /// Returns the binary hash this generator is bound to.
    #[must_use]
    pub fn binary_hash(&self) -> &str {
        &self.binary_hash
    }

    /// Returns the public key bytes for verification.
    #[must_use]
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signer.public_key_bytes()
    }

    /// Generates an AAT receipt from test results.
    ///
    /// # Arguments
    ///
    /// * `receipt_id` - Unique identifier for the receipt
    /// * `test_summary` - Summary of test results
    /// * `timestamp` - Timestamp for the receipt (Unix nanos)
    ///
    /// # Errors
    ///
    /// Returns an error if the receipt ID or binary hash is invalid.
    pub fn generate(
        &self,
        receipt_id: &str,
        test_summary: TestSummary,
        timestamp: u64,
    ) -> Result<AATReceipt, AATReceiptError> {
        self.generate_with_budget(
            receipt_id,
            test_summary,
            BudgetConsumed::default(),
            vec![],
            timestamp,
        )
    }

    /// Generates an AAT receipt with full details.
    ///
    /// # Arguments
    ///
    /// * `receipt_id` - Unique identifier for the receipt
    /// * `test_summary` - Summary of test results
    /// * `budget_consumed` - Resources consumed during execution
    /// * `capabilities_tested` - List of capability IDs that were tested
    /// * `timestamp` - Timestamp for the receipt (Unix nanos)
    ///
    /// # Errors
    ///
    /// Returns an error if the receipt ID, binary hash, or any capability ID is
    /// invalid. Capability IDs must not contain forbidden characters (`|`, `,`)
    /// that would break the canonical serialization format.
    pub fn generate_with_budget(
        &self,
        receipt_id: &str,
        test_summary: TestSummary,
        budget_consumed: BudgetConsumed,
        capabilities_tested: Vec<String>,
        timestamp: u64,
    ) -> Result<AATReceipt, AATReceiptError> {
        // Validate inputs
        validate_receipt_id(receipt_id)?;
        validate_binary_hash(&self.binary_hash)?;

        // Validate all capability IDs to prevent canonicalization ambiguity
        // (capability IDs containing `|` or `,` could spoof the list or break
        // out of the canonical field structure)
        for cap_id in &capabilities_tested {
            validate_capability_id(cap_id)?;
        }

        // Create the receipt (unsigned)
        let mut receipt = AATReceipt {
            receipt_id: receipt_id.to_string(),
            binary_hash: self.binary_hash.clone(),
            test_summary,
            budget_consumed,
            capabilities_tested,
            generated_at: timestamp,
            signature: [0u8; SIGNATURE_SIZE],
        };

        // Sign the receipt
        let canonical = receipt.canonical_bytes();
        let signature = self.signer.sign(&canonical);
        receipt.signature = signature.to_bytes();

        Ok(receipt)
    }

    /// Verifies an AAT receipt's signature.
    ///
    /// # Returns
    ///
    /// `true` if the signature is valid for this generator's public key.
    #[must_use]
    pub fn verify(&self, receipt: &AATReceipt) -> bool {
        let canonical = receipt.canonical_bytes();
        let signature = Signature::from_bytes(&receipt.signature);
        self.signer.verify(&canonical, &signature)
    }

    /// Verifies an AAT receipt's signature and binary hash.
    ///
    /// This is the recommended verification method as it checks both
    /// the cryptographic signature and the binary hash binding.
    ///
    /// # Returns
    ///
    /// `Ok(())` if both checks pass, or an error describing what failed.
    ///
    /// # Errors
    ///
    /// Returns [`AATReceiptError::BinaryHashMismatch`] if the receipt's binary
    /// hash doesn't match this generator's binary hash.
    /// Returns [`AATReceiptError::SignatureVerificationFailed`] if the
    /// signature is invalid.
    pub fn verify_full(&self, receipt: &AATReceipt) -> Result<(), AATReceiptError> {
        // Verify binary hash first (fast check)
        if !receipt.verify_binary_hash(&self.binary_hash) {
            return Err(AATReceiptError::BinaryHashMismatch {
                expected: self.binary_hash.clone(),
                actual: receipt.binary_hash.clone(),
            });
        }

        // Verify signature
        if !self.verify(receipt) {
            return Err(AATReceiptError::SignatureVerificationFailed);
        }

        Ok(())
    }
}

// ============================================================================
// Standalone Verification
// ============================================================================

/// Verifies an AAT receipt using only the public key.
///
/// This function is useful when you only have the verifying key
/// and don't need signing capability.
///
/// # Arguments
///
/// * `receipt` - The receipt to verify
/// * `public_key_bytes` - The public key bytes (32 bytes)
///
/// # Returns
///
/// `Ok(())` if the signature is valid, or an error.
///
/// # Errors
///
/// Returns an error if the signature is invalid or malformed.
pub fn verify_aat_receipt(
    receipt: &AATReceipt,
    public_key_bytes: &[u8],
) -> Result<(), AATReceiptError> {
    let verifying_key = crate::crypto::parse_verifying_key(public_key_bytes).map_err(|e| {
        AATReceiptError::MalformedSignature {
            reason: e.to_string(),
        }
    })?;

    let canonical = receipt.canonical_bytes();
    let signature =
        parse_signature(&receipt.signature).map_err(|e| AATReceiptError::MalformedSignature {
            reason: e.to_string(),
        })?;

    verify_signature(&verifying_key, &canonical, &signature)
        .map_err(|_| AATReceiptError::SignatureVerificationFailed)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Creates a valid 64-character hex hash for testing.
    fn make_test_binary_hash() -> String {
        "a".repeat(64)
    }

    // =========================================================================
    // TestSummary Tests
    // =========================================================================

    #[test]
    fn test_test_summary_new() {
        let summary = TestSummary::new(10, 2, 1);
        assert_eq!(summary.tests_passed, 10);
        assert_eq!(summary.tests_failed, 2);
        assert_eq!(summary.tests_skipped, 1);
    }

    #[test]
    fn test_test_summary_total() {
        let summary = TestSummary::new(10, 2, 1);
        assert_eq!(summary.total(), 13);
    }

    #[test]
    fn test_test_summary_all_passed() {
        let passed = TestSummary::new(10, 0, 0);
        assert!(passed.all_passed());

        let failed = TestSummary::new(10, 1, 0);
        assert!(!failed.all_passed());

        let empty = TestSummary::new(0, 0, 0);
        assert!(!empty.all_passed());
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_test_summary_pass_rate() {
        let summary = TestSummary::new(8, 2, 0);
        assert_eq!(summary.pass_rate(), 80.0);

        let all_passed = TestSummary::new(10, 0, 0);
        assert_eq!(all_passed.pass_rate(), 100.0);

        let empty = TestSummary::new(0, 0, 0);
        assert_eq!(empty.pass_rate(), 0.0);
    }

    // =========================================================================
    // BudgetConsumed Tests
    // =========================================================================

    #[test]
    fn test_budget_consumed_new() {
        let budget = BudgetConsumed::new(1000, 5, 500);
        assert_eq!(budget.duration_ms, 1000);
        assert_eq!(budget.tool_calls, 5);
        assert_eq!(budget.tokens, 500);
    }

    #[test]
    fn test_budget_consumed_from_duration() {
        let duration = Duration::from_millis(1500);
        let budget = BudgetConsumed::from_duration(duration, 3, 100);
        assert_eq!(budget.duration_ms, 1500);
        assert_eq!(budget.duration(), Duration::from_millis(1500));
    }

    // =========================================================================
    // AATReceipt Generation Tests
    // =========================================================================

    #[test]
    fn test_generate_receipt() {
        let signer = Signer::generate();
        let binary_hash = make_test_binary_hash();
        let generator = AATReceiptGenerator::new(signer, binary_hash.clone());

        let summary = TestSummary::new(10, 0, 0);
        let receipt = generator
            .generate("rcpt-001", summary, 1_000_000_000)
            .unwrap();

        assert_eq!(receipt.receipt_id, "rcpt-001");
        assert_eq!(receipt.binary_hash, binary_hash);
        assert!(receipt.is_signed());
        assert!(receipt.all_passed());
    }

    #[test]
    fn test_generate_receipt_with_budget() {
        let signer = Signer::generate();
        let binary_hash = make_test_binary_hash();
        let generator = AATReceiptGenerator::new(signer, binary_hash);

        let summary = TestSummary::new(5, 2, 1);
        let budget = BudgetConsumed::new(5000, 10, 1000);
        let caps = vec!["cap:a".to_string(), "cap:b".to_string()];

        let receipt = generator
            .generate_with_budget("rcpt-002", summary, budget, caps, 2_000_000_000)
            .unwrap();

        assert_eq!(receipt.test_summary.tests_passed, 5);
        assert_eq!(receipt.test_summary.tests_failed, 2);
        assert_eq!(receipt.budget_consumed.duration_ms, 5000);
        assert_eq!(receipt.capabilities_tested.len(), 2);
    }

    // =========================================================================
    // Signature Verification Tests
    // =========================================================================

    #[test]
    fn test_verify_receipt() {
        let signer = Signer::generate();
        let binary_hash = make_test_binary_hash();
        let generator = AATReceiptGenerator::new(signer, binary_hash);

        let summary = TestSummary::new(10, 0, 0);
        let receipt = generator
            .generate("rcpt-001", summary, 1_000_000_000)
            .unwrap();

        assert!(generator.verify(&receipt));
    }

    #[test]
    fn test_verify_fails_for_wrong_key() {
        let signer1 = Signer::generate();
        let signer2 = Signer::generate();
        let binary_hash = make_test_binary_hash();

        let generator1 = AATReceiptGenerator::new(signer1, binary_hash.clone());
        let generator2 = AATReceiptGenerator::new(signer2, binary_hash);

        let summary = TestSummary::new(10, 0, 0);
        let receipt = generator1
            .generate("rcpt-001", summary, 1_000_000_000)
            .unwrap();

        // generator2 should NOT verify generator1's receipt
        assert!(!generator2.verify(&receipt));
    }

    #[test]
    fn test_verify_full_success() {
        let signer = Signer::generate();
        let binary_hash = make_test_binary_hash();
        let generator = AATReceiptGenerator::new(signer, binary_hash);

        let summary = TestSummary::new(10, 0, 0);
        let receipt = generator
            .generate("rcpt-001", summary, 1_000_000_000)
            .unwrap();

        assert!(generator.verify_full(&receipt).is_ok());
    }

    #[test]
    fn test_verify_full_binary_hash_mismatch() {
        let binary_hash1 = make_test_binary_hash();
        let binary_hash2 = "b".repeat(64);

        let generator1 = AATReceiptGenerator::new(Signer::generate(), binary_hash1);
        let generator2 = AATReceiptGenerator::new(Signer::generate(), binary_hash2);

        let summary = TestSummary::new(10, 0, 0);
        let receipt = generator1
            .generate("rcpt-001", summary, 1_000_000_000)
            .unwrap();

        let result = generator2.verify_full(&receipt);
        assert!(matches!(
            result,
            Err(AATReceiptError::BinaryHashMismatch { .. })
        ));
    }

    // =========================================================================
    // Binary Hash Verification Tests
    // =========================================================================

    #[test]
    fn test_verify_binary_hash_success() {
        let signer = Signer::generate();
        let binary_hash = make_test_binary_hash();
        let generator = AATReceiptGenerator::new(signer, binary_hash.clone());

        let summary = TestSummary::new(10, 0, 0);
        let receipt = generator
            .generate("rcpt-001", summary, 1_000_000_000)
            .unwrap();

        assert!(receipt.verify_binary_hash(&binary_hash));
    }

    #[test]
    fn test_verify_binary_hash_mismatch() {
        let signer = Signer::generate();
        let binary_hash = make_test_binary_hash();
        let generator = AATReceiptGenerator::new(signer, binary_hash);

        let summary = TestSummary::new(10, 0, 0);
        let receipt = generator
            .generate("rcpt-001", summary, 1_000_000_000)
            .unwrap();

        // Different binary hash should fail
        let different_hash = "b".repeat(64);
        assert!(!receipt.verify_binary_hash(&different_hash));
    }

    // =========================================================================
    // Standalone Verification Tests
    // =========================================================================

    #[test]
    fn test_verify_aat_receipt_standalone() {
        let signer = Signer::generate();
        let public_key_bytes = signer.public_key_bytes();
        let binary_hash = make_test_binary_hash();
        let generator = AATReceiptGenerator::new(signer, binary_hash);

        let summary = TestSummary::new(10, 0, 0);
        let receipt = generator
            .generate("rcpt-001", summary, 1_000_000_000)
            .unwrap();

        let result = verify_aat_receipt(&receipt, &public_key_bytes);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_aat_receipt_wrong_key() {
        let signer = Signer::generate();
        let wrong_signer = Signer::generate();
        let binary_hash = make_test_binary_hash();
        let generator = AATReceiptGenerator::new(signer, binary_hash);

        let summary = TestSummary::new(10, 0, 0);
        let receipt = generator
            .generate("rcpt-001", summary, 1_000_000_000)
            .unwrap();

        let result = verify_aat_receipt(&receipt, &wrong_signer.public_key_bytes());
        assert!(matches!(
            result,
            Err(AATReceiptError::SignatureVerificationFailed)
        ));
    }

    // =========================================================================
    // Validation Tests
    // =========================================================================

    #[test]
    fn test_empty_receipt_id_rejected() {
        let signer = Signer::generate();
        let binary_hash = make_test_binary_hash();
        let generator = AATReceiptGenerator::new(signer, binary_hash);

        let summary = TestSummary::new(10, 0, 0);
        let result = generator.generate("", summary, 1_000_000_000);

        assert!(matches!(
            result,
            Err(AATReceiptError::InvalidReceiptId { .. })
        ));
    }

    #[test]
    fn test_receipt_id_with_forbidden_chars_rejected() {
        let signer = Signer::generate();
        let binary_hash = make_test_binary_hash();
        let generator = AATReceiptGenerator::new(signer, binary_hash);

        let summary = TestSummary::new(10, 0, 0);

        // Pipe separator
        let result = generator.generate("rcpt|001", summary.clone(), 1_000_000_000);
        assert!(matches!(
            result,
            Err(AATReceiptError::InvalidReceiptId { .. })
        ));

        // Newline
        let result = generator.generate("rcpt\n001", summary.clone(), 1_000_000_000);
        assert!(matches!(
            result,
            Err(AATReceiptError::InvalidReceiptId { .. })
        ));

        // Path traversal
        let result = generator.generate("rcpt/../001", summary, 1_000_000_000);
        assert!(matches!(
            result,
            Err(AATReceiptError::InvalidReceiptId { .. })
        ));
    }

    #[test]
    fn test_invalid_binary_hash_length_rejected() {
        let signer = Signer::generate();
        let invalid_hash = "abc123"; // Too short

        let generator = AATReceiptGenerator::new(signer, invalid_hash.to_string());

        let summary = TestSummary::new(10, 0, 0);
        let result = generator.generate("rcpt-001", summary, 1_000_000_000);

        assert!(matches!(
            result,
            Err(AATReceiptError::InvalidBinaryHash { .. })
        ));
    }

    #[test]
    fn test_invalid_binary_hash_chars_rejected() {
        let signer = Signer::generate();
        let invalid_hash = "g".repeat(64); // 'g' is not a hex digit

        let generator = AATReceiptGenerator::new(signer, invalid_hash);

        let summary = TestSummary::new(10, 0, 0);
        let result = generator.generate("rcpt-001", summary, 1_000_000_000);

        assert!(matches!(
            result,
            Err(AATReceiptError::InvalidBinaryHash { .. })
        ));
    }

    // =========================================================================
    // Capability ID Validation Tests (Security: Canonicalization Ambiguity)
    // =========================================================================

    /// SECURITY PROOF TEST: Capability IDs containing pipe character are
    /// rejected.
    ///
    /// This test proves that an attacker cannot craft a capability ID
    /// containing `|` to break out of the canonical field structure. The
    /// `|` character is the field separator in `canonical_bytes()`, so
    /// allowing it in capability IDs would enable field injection attacks.
    #[test]
    fn test_capability_id_with_pipe_rejected() {
        let signer = Signer::generate();
        let binary_hash = make_test_binary_hash();
        let generator = AATReceiptGenerator::new(signer, binary_hash);

        let summary = TestSummary::new(10, 0, 0);
        let caps = vec!["cap:valid".to_string(), "cap|injected".to_string()];

        let result = generator.generate_with_budget(
            "rcpt-001",
            summary,
            BudgetConsumed::default(),
            caps,
            1_000_000_000,
        );

        assert!(
            matches!(result, Err(AATReceiptError::InvalidCapabilityId { .. })),
            "Capability ID with pipe character should be rejected"
        );
    }

    /// SECURITY PROOF TEST: Capability IDs containing comma are rejected.
    ///
    /// This test proves that an attacker cannot craft a capability ID
    /// containing `,` to spoof the list of tested capabilities. The `,`
    /// character is the list separator in `canonical_bytes()` for
    /// `capabilities_tested`, so allowing it in capability IDs would enable
    /// list spoofing attacks.
    #[test]
    fn test_capability_id_with_comma_rejected() {
        let signer = Signer::generate();
        let binary_hash = make_test_binary_hash();
        let generator = AATReceiptGenerator::new(signer, binary_hash);

        let summary = TestSummary::new(10, 0, 0);
        let caps = vec!["cap:a,cap:b".to_string()]; // Single cap pretending to be two

        let result = generator.generate_with_budget(
            "rcpt-001",
            summary,
            BudgetConsumed::default(),
            caps,
            1_000_000_000,
        );

        assert!(
            matches!(result, Err(AATReceiptError::InvalidCapabilityId { .. })),
            "Capability ID with comma should be rejected"
        );
    }

    /// SECURITY PROOF TEST: Valid capability IDs are accepted.
    ///
    /// This test verifies that normal capability IDs without forbidden
    /// characters are still accepted after adding the validation.
    #[test]
    fn test_valid_capability_ids_accepted() {
        let signer = Signer::generate();
        let binary_hash = make_test_binary_hash();
        let generator = AATReceiptGenerator::new(signer, binary_hash);

        let summary = TestSummary::new(10, 0, 0);
        let caps = vec![
            "cac:patch:apply".to_string(),
            "cac:admission:validate".to_string(),
            "test-capability_v2.3".to_string(),
        ];

        let result = generator.generate_with_budget(
            "rcpt-001",
            summary,
            BudgetConsumed::default(),
            caps.clone(),
            1_000_000_000,
        );

        assert!(result.is_ok(), "Valid capability IDs should be accepted");
        let receipt = result.unwrap();
        assert_eq!(receipt.capabilities_tested, caps);
    }

    // =========================================================================
    // Serialization Tests
    // =========================================================================

    #[test]
    fn test_test_summary_serialization() {
        let summary = TestSummary::new(10, 2, 1);
        let json = serde_json::to_string(&summary).unwrap();
        let parsed: TestSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary, parsed);
    }

    #[test]
    fn test_budget_consumed_serialization() {
        let budget = BudgetConsumed::new(1000, 5, 500);
        let json = serde_json::to_string(&budget).unwrap();
        let parsed: BudgetConsumed = serde_json::from_str(&json).unwrap();
        assert_eq!(budget, parsed);
    }

    #[test]
    fn test_aat_receipt_serialization() {
        let signer = Signer::generate();
        let binary_hash = make_test_binary_hash();
        let generator = AATReceiptGenerator::new(signer, binary_hash);

        let summary = TestSummary::new(10, 0, 0);
        let receipt = generator
            .generate("rcpt-001", summary, 1_000_000_000)
            .unwrap();

        let json = serde_json::to_string(&receipt).unwrap();
        let parsed: AATReceipt = serde_json::from_str(&json).unwrap();

        assert_eq!(receipt.receipt_id, parsed.receipt_id);
        assert_eq!(receipt.binary_hash, parsed.binary_hash);
        assert_eq!(receipt.signature, parsed.signature);
    }

    // =========================================================================
    // Canonical Bytes Tests
    // =========================================================================

    #[test]
    fn test_canonical_bytes_deterministic() {
        let signer = Signer::generate();
        let binary_hash = make_test_binary_hash();
        let generator = AATReceiptGenerator::new(signer, binary_hash);

        let summary = TestSummary::new(10, 0, 0);
        let caps = vec!["cap:b".to_string(), "cap:a".to_string()]; // Unsorted

        let receipt = generator
            .generate_with_budget(
                "rcpt-001",
                summary,
                BudgetConsumed::default(),
                caps,
                1_000_000_000,
            )
            .unwrap();

        // Canonical bytes should be deterministic
        let canonical1 = receipt.canonical_bytes();
        let canonical2 = receipt.canonical_bytes();
        assert_eq!(canonical1, canonical2);

        // Should contain sorted capabilities
        let canonical_str = String::from_utf8(canonical1).unwrap();
        assert!(canonical_str.contains("cap:a,cap:b"));
    }

    // =========================================================================
    // Error Display Tests
    // =========================================================================

    #[test]
    fn test_error_display() {
        let err = AATReceiptError::InvalidReceiptId {
            reason: "empty".to_string(),
        };
        assert!(err.to_string().contains("empty"));

        let err = AATReceiptError::BinaryHashMismatch {
            expected: "aaa".to_string(),
            actual: "bbb".to_string(),
        };
        assert!(err.to_string().contains("aaa"));
        assert!(err.to_string().contains("bbb"));

        let err = AATReceiptError::SignatureVerificationFailed;
        assert!(err.to_string().contains("verification failed"));
    }
}
