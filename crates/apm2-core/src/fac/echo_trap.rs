#![allow(clippy::disallowed_methods)] // Metadata/observability usage or adapter.
// AGENT-AUTHORED
//! Echo-trap detection and escalation for the Forge Admission Cycle.
//!
//! This module implements echo-trap detection to prevent reasoning degeneration
//! where an agent keeps producing the same findings without progress. When the
//! same finding signature is recorded multiple times (threshold = 3), an
//! `EchoTrapEvent` is triggered, leading to session termination with
//! `REASONING_DEGENERATION` rationale and escalation to oracle.
//!
//! # Security Model
//!
//! Echo-trap detection is a detective control (SEC-CTRL-FAC-0007) that:
//! - Monitors `FindingSignature` repetition within a gate run window
//! - Triggers `SessionTerminated` with escalation when threshold is reached
//! - Prevents infinite loops in agent reasoning
//! - Emits `DefectRecord(ECHO_TRAP)` for audit trail
//!
//! # Design
//!
//! The `EchoTrapDetector` maintains a list of finding signatures recorded
//! during a gate run. When `record_finding()` is called:
//! 1. The signature is added to the internal list
//! 2. Occurrences of that signature are counted
//! 3. If count >= `ECHO_TRAP_THRESHOLD`, an `EchoTrapEvent` is returned
//!
//! The `on_echo_trap()` method handles escalation by returning a
//! `SessionTermination` with `REASONING_DEGENERATION` rationale.
//!
//! # Denial-of-Service Protection
//!
//! Resource limits prevent denial-of-service attacks:
//! - `MAX_SIGNATURES`: Maximum signatures tracked per detector (256)
//! - `MAX_SIGNATURE_LENGTH`: Maximum length of a single signature (4096 bytes)
//!
//! # Example
//!
//! ```rust
//! use apm2_core::fac::echo_trap::{EchoTrapDetector, FindingSignature};
//!
//! let mut detector = EchoTrapDetector::new();
//!
//! // Record the same finding multiple times
//! let signature = FindingSignature::new("test-123".to_string());
//! assert!(
//!     detector
//!         .record_finding(signature.clone())
//!         .unwrap()
//!         .is_none()
//! );
//! assert!(
//!     detector
//!         .record_finding(signature.clone())
//!         .unwrap()
//!         .is_none()
//! );
//!
//! // Third occurrence triggers echo trap
//! let event = detector.record_finding(signature).unwrap();
//! assert!(event.is_some());
//!
//! // Handle the echo trap
//! let termination = EchoTrapDetector::on_echo_trap(&event.unwrap());
//! assert!(termination.escalate_to_oracle);
//! ```

use serde::{Deserialize, Serialize};
use thiserror::Error;

// =============================================================================
// Constants
// =============================================================================

/// Threshold for echo-trap detection.
///
/// When a finding signature is recorded this many times, an echo trap is
/// triggered. Per RFC-0015 SEC-CTRL-FAC-0007, the threshold is 3.
pub const ECHO_TRAP_THRESHOLD: usize = 3;

/// Maximum number of signatures that can be tracked by a single detector.
///
/// This prevents denial-of-service attacks via unbounded memory growth.
pub const MAX_SIGNATURES: usize = 256;

/// Maximum length of a finding signature in bytes.
///
/// This prevents denial-of-service attacks via oversized signatures.
pub const MAX_SIGNATURE_LENGTH: usize = 4096;

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during echo-trap operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EchoTrapError {
    /// Signature exceeds maximum length.
    #[error("signature exceeds maximum length ({actual} > {max})")]
    SignatureTooLong {
        /// Actual length of the signature.
        actual: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// Too many signatures recorded (denial-of-service protection).
    #[error("too many signatures recorded ({actual} > {max})")]
    TooManySignatures {
        /// Actual number of signatures.
        actual: usize,
        /// Maximum allowed signatures.
        max: usize,
    },

    /// Empty signature is not allowed.
    #[error("signature cannot be empty")]
    EmptySignature,
}

// =============================================================================
// FindingSignature
// =============================================================================

/// A signature identifying a unique finding.
///
/// Finding signatures are used to detect when an agent produces the same
/// finding repeatedly, indicating potential reasoning degeneration.
///
/// The signature should be a stable identifier for the finding, such as:
/// - A hash of the finding content
/// - A structured identifier (e.g., "lint:E0001:file.rs:42")
/// - A canonicalized representation of the finding
///
/// # Validation
///
/// - Must be non-empty
/// - Must not exceed `MAX_SIGNATURE_LENGTH` bytes
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindingSignature {
    /// The signature value.
    value: String,
}

impl FindingSignature {
    /// Creates a new finding signature.
    ///
    /// # Arguments
    ///
    /// * `value` - The signature value
    ///
    /// # Note
    ///
    /// This constructor does not validate. Use `validate()` or
    /// `try_new()` for validated construction.
    #[must_use]
    pub const fn new(value: String) -> Self {
        Self { value }
    }

    /// Creates a new finding signature with validation.
    ///
    /// # Arguments
    ///
    /// * `value` - The signature value
    ///
    /// # Errors
    ///
    /// Returns `EchoTrapError::EmptySignature` if the value is empty.
    /// Returns `EchoTrapError::SignatureTooLong` if the value exceeds
    /// `MAX_SIGNATURE_LENGTH`.
    pub fn try_new(value: String) -> Result<Self, EchoTrapError> {
        let signature = Self::new(value);
        signature.validate()?;
        Ok(signature)
    }

    /// Returns the signature value.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Validates the signature.
    ///
    /// # Errors
    ///
    /// Returns `EchoTrapError::EmptySignature` if the value is empty.
    /// Returns `EchoTrapError::SignatureTooLong` if the value exceeds
    /// `MAX_SIGNATURE_LENGTH`.
    pub fn validate(&self) -> Result<(), EchoTrapError> {
        if self.value.is_empty() {
            return Err(EchoTrapError::EmptySignature);
        }
        if self.value.len() > MAX_SIGNATURE_LENGTH {
            return Err(EchoTrapError::SignatureTooLong {
                actual: self.value.len(),
                max: MAX_SIGNATURE_LENGTH,
            });
        }
        Ok(())
    }
}

impl std::fmt::Display for FindingSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value)
    }
}

// =============================================================================
// EchoTrapEvent
// =============================================================================

/// An event indicating that an echo trap was triggered.
///
/// This event is returned by `EchoTrapDetector::record_finding()` when the
/// same signature has been recorded `ECHO_TRAP_THRESHOLD` times.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EchoTrapEvent {
    /// The signature that triggered the echo trap.
    pub signature: FindingSignature,

    /// The number of times this signature was recorded.
    pub occurrence_count: usize,

    /// Timestamp when the echo trap was detected (Unix nanoseconds).
    pub detected_at: u64,
}

impl EchoTrapEvent {
    /// Creates a new echo trap event.
    #[must_use]
    pub const fn new(
        signature: FindingSignature,
        occurrence_count: usize,
        detected_at: u64,
    ) -> Self {
        Self {
            signature,
            occurrence_count,
            detected_at,
        }
    }
}

// =============================================================================
// SessionTermination
// =============================================================================

/// Session termination result from echo-trap escalation.
///
/// When an echo trap is triggered, the session should be terminated with
/// the `REASONING_DEGENERATION` rationale, and escalation to oracle should
/// be requested.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionTermination {
    /// The termination rationale.
    pub rationale: TerminationRationale,

    /// Whether to escalate to oracle for review.
    pub escalate_to_oracle: bool,

    /// The echo trap event that triggered the termination.
    pub trigger_event: EchoTrapEvent,
}

/// Rationale for session termination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TerminationRationale {
    /// Agent is producing repeated findings without progress.
    ReasoningDegeneration,
}

impl TerminationRationale {
    /// Returns the rationale as a string identifier.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ReasoningDegeneration => "REASONING_DEGENERATION",
        }
    }
}

impl std::fmt::Display for TerminationRationale {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// =============================================================================
// EchoTrapDetector
// =============================================================================

/// Detector for echo-trap patterns in agent findings.
///
/// The detector maintains a list of finding signatures and detects when
/// the same signature is recorded multiple times, indicating potential
/// reasoning degeneration.
///
/// # Usage
///
/// 1. Create a new detector for each gate run
/// 2. Call `record_finding()` for each finding produced by the agent
/// 3. If `record_finding()` returns `Some(EchoTrapEvent)`, call
///    `on_echo_trap()`
///
/// # Thread Safety
///
/// This type is not thread-safe. Each gate run should have its own detector.
#[derive(Debug, Clone, Default)]
pub struct EchoTrapDetector {
    /// List of recorded finding signatures.
    finding_signatures: Vec<FindingSignature>,
}

impl EchoTrapDetector {
    /// Creates a new echo-trap detector.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            finding_signatures: Vec::new(),
        }
    }

    /// Creates a new detector with pre-allocated capacity.
    ///
    /// # Arguments
    ///
    /// * `capacity` - Initial capacity for the signature list
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            finding_signatures: Vec::with_capacity(capacity.min(MAX_SIGNATURES)),
        }
    }

    /// Records a finding signature and checks for echo trap.
    ///
    /// # Arguments
    ///
    /// * `signature` - The finding signature to record
    ///
    /// # Returns
    ///
    /// - `Ok(None)` if the signature was recorded but threshold not reached
    /// - `Ok(Some(EchoTrapEvent))` if threshold was reached (echo trap
    ///   detected)
    ///
    /// # Errors
    ///
    /// Returns `EchoTrapError::SignatureTooLong` if the signature exceeds
    /// `MAX_SIGNATURE_LENGTH`. Returns `EchoTrapError::TooManySignatures` if
    /// recording this signature would exceed `MAX_SIGNATURES`.
    pub fn record_finding(
        &mut self,
        signature: FindingSignature,
    ) -> Result<Option<EchoTrapEvent>, EchoTrapError> {
        // Validate signature
        signature.validate()?;

        // Check DoS limit
        if self.finding_signatures.len() >= MAX_SIGNATURES {
            return Err(EchoTrapError::TooManySignatures {
                actual: self.finding_signatures.len() + 1,
                max: MAX_SIGNATURES,
            });
        }

        // Add signature to list
        self.finding_signatures.push(signature.clone());

        // Count occurrences
        let count = self
            .finding_signatures
            .iter()
            .filter(|s| **s == signature)
            .count();

        // Check threshold
        if count >= ECHO_TRAP_THRESHOLD {
            let event = EchoTrapEvent::new(signature, count, current_timestamp_ns());
            Ok(Some(event))
        } else {
            Ok(None)
        }
    }

    /// Handles an echo trap event by producing a session termination.
    ///
    /// This method should be called when `record_finding()` returns
    /// `Some(EchoTrapEvent)`. It returns a `SessionTermination` with:
    /// - Rationale: `REASONING_DEGENERATION`
    /// - `escalate_to_oracle`: `true`
    ///
    /// # Arguments
    ///
    /// * `event` - The echo trap event to handle
    ///
    /// # Returns
    ///
    /// A `SessionTermination` indicating the session should be terminated
    /// and escalated to oracle.
    #[must_use]
    pub fn on_echo_trap(event: &EchoTrapEvent) -> SessionTermination {
        SessionTermination {
            rationale: TerminationRationale::ReasoningDegeneration,
            escalate_to_oracle: true,
            trigger_event: event.clone(),
        }
    }

    /// Returns the number of signatures currently recorded.
    #[must_use]
    pub fn signature_count(&self) -> usize {
        self.finding_signatures.len()
    }

    /// Returns the occurrence count for a given signature.
    #[must_use]
    pub fn occurrence_count(&self, signature: &FindingSignature) -> usize {
        self.finding_signatures
            .iter()
            .filter(|s| *s == signature)
            .count()
    }

    /// Clears all recorded signatures.
    ///
    /// This can be used to reset the detector for a new gate run.
    pub fn clear(&mut self) {
        self.finding_signatures.clear();
    }

    /// Returns true if an echo trap has been detected for any signature.
    #[must_use]
    pub fn has_echo_trap(&self) -> bool {
        // Count occurrences of each unique signature
        let mut seen = std::collections::HashSet::new();
        for sig in &self.finding_signatures {
            if !seen.insert(sig) {
                // Already seen, count total occurrences
                let count = self.occurrence_count(sig);
                if count >= ECHO_TRAP_THRESHOLD {
                    return true;
                }
            }
        }
        false
    }
}

/// Returns the current timestamp in nanoseconds since epoch.
fn current_timestamp_ns() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    #[allow(clippy::cast_possible_truncation)]
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // FindingSignature Tests
    // =========================================================================

    #[test]
    fn test_finding_signature_new() {
        let sig = FindingSignature::new("test-123".to_string());
        assert_eq!(sig.value(), "test-123");
    }

    #[test]
    fn test_finding_signature_try_new_valid() {
        let sig = FindingSignature::try_new("test-123".to_string()).unwrap();
        assert_eq!(sig.value(), "test-123");
    }

    #[test]
    fn test_finding_signature_try_new_empty() {
        let result = FindingSignature::try_new(String::new());
        assert!(matches!(result, Err(EchoTrapError::EmptySignature)));
    }

    #[test]
    fn test_finding_signature_try_new_too_long() {
        let long_value = "x".repeat(MAX_SIGNATURE_LENGTH + 1);
        let result = FindingSignature::try_new(long_value);
        assert!(matches!(
            result,
            Err(EchoTrapError::SignatureTooLong { .. })
        ));
    }

    #[test]
    fn test_finding_signature_max_length_accepted() {
        let max_value = "x".repeat(MAX_SIGNATURE_LENGTH);
        let result = FindingSignature::try_new(max_value);
        assert!(result.is_ok());
    }

    #[test]
    fn test_finding_signature_display() {
        let sig = FindingSignature::new("test-123".to_string());
        assert_eq!(sig.to_string(), "test-123");
    }

    #[test]
    fn test_finding_signature_serde_roundtrip() {
        let sig = FindingSignature::new("test-123".to_string());
        let json = serde_json::to_string(&sig).unwrap();
        let deserialized: FindingSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(sig, deserialized);
    }

    #[test]
    fn test_finding_signature_equality() {
        let sig1 = FindingSignature::new("test".to_string());
        let sig2 = FindingSignature::new("test".to_string());
        let sig3 = FindingSignature::new("other".to_string());

        assert_eq!(sig1, sig2);
        assert_ne!(sig1, sig3);
    }

    #[test]
    fn test_finding_signature_hash() {
        use std::collections::HashSet;

        let sig1 = FindingSignature::new("test".to_string());
        let sig2 = FindingSignature::new("test".to_string());

        let mut set = HashSet::new();
        set.insert(sig1);
        assert!(set.contains(&sig2));
    }

    // =========================================================================
    // EchoTrapDetector Tests
    // =========================================================================

    #[test]
    fn test_detector_new() {
        let detector = EchoTrapDetector::new();
        assert_eq!(detector.signature_count(), 0);
    }

    #[test]
    fn test_detector_with_capacity() {
        let detector = EchoTrapDetector::with_capacity(10);
        assert_eq!(detector.signature_count(), 0);
    }

    #[test]
    fn test_detector_record_finding_below_threshold() {
        let mut detector = EchoTrapDetector::new();
        let sig = FindingSignature::new("test".to_string());

        // First occurrence - no echo trap
        let result = detector.record_finding(sig.clone()).unwrap();
        assert!(result.is_none());
        assert_eq!(detector.signature_count(), 1);

        // Second occurrence - no echo trap
        let result = detector.record_finding(sig).unwrap();
        assert!(result.is_none());
        assert_eq!(detector.signature_count(), 2);
    }

    #[test]
    fn test_detector_record_finding_at_threshold() {
        let mut detector = EchoTrapDetector::new();
        let sig = FindingSignature::new("test".to_string());

        // Record up to threshold
        for _ in 0..(ECHO_TRAP_THRESHOLD - 1) {
            let result = detector.record_finding(sig.clone()).unwrap();
            assert!(result.is_none());
        }

        // Threshold reached - echo trap triggered
        let result = detector.record_finding(sig.clone()).unwrap();
        assert!(result.is_some());

        let event = result.unwrap();
        assert_eq!(event.signature, sig);
        assert_eq!(event.occurrence_count, ECHO_TRAP_THRESHOLD);
    }

    #[test]
    fn test_detector_echo_trap_threshold_is_3() {
        // Per RFC-0015, threshold should be exactly 3
        assert_eq!(ECHO_TRAP_THRESHOLD, 3);
    }

    #[test]
    fn test_detector_different_signatures_no_echo_trap() {
        let mut detector = EchoTrapDetector::new();

        // Record different signatures - no echo trap
        for i in 0..10 {
            let sig = FindingSignature::new(format!("test-{i}"));
            let result = detector.record_finding(sig).unwrap();
            assert!(result.is_none());
        }
    }

    #[test]
    fn test_detector_occurrence_count() {
        let mut detector = EchoTrapDetector::new();
        let sig1 = FindingSignature::new("test-1".to_string());
        let sig2 = FindingSignature::new("test-2".to_string());

        detector.record_finding(sig1.clone()).unwrap();
        detector.record_finding(sig1.clone()).unwrap();
        detector.record_finding(sig2.clone()).unwrap();

        assert_eq!(detector.occurrence_count(&sig1), 2);
        assert_eq!(detector.occurrence_count(&sig2), 1);
    }

    #[test]
    fn test_detector_clear() {
        let mut detector = EchoTrapDetector::new();
        let sig = FindingSignature::new("test".to_string());

        detector.record_finding(sig.clone()).unwrap();
        detector.record_finding(sig).unwrap();
        assert_eq!(detector.signature_count(), 2);

        detector.clear();
        assert_eq!(detector.signature_count(), 0);
    }

    #[test]
    fn test_detector_has_echo_trap() {
        let mut detector = EchoTrapDetector::new();
        let sig = FindingSignature::new("test".to_string());

        assert!(!detector.has_echo_trap());

        for _ in 0..ECHO_TRAP_THRESHOLD {
            detector.record_finding(sig.clone()).unwrap();
        }

        assert!(detector.has_echo_trap());
    }

    #[test]
    fn test_detector_dos_protection_max_signatures() {
        let mut detector = EchoTrapDetector::new();

        // Fill up to max
        for i in 0..MAX_SIGNATURES {
            let sig = FindingSignature::new(format!("sig-{i}"));
            detector.record_finding(sig).unwrap();
        }

        // Next one should fail
        let sig = FindingSignature::new("overflow".to_string());
        let result = detector.record_finding(sig);
        assert!(matches!(
            result,
            Err(EchoTrapError::TooManySignatures { .. })
        ));
    }

    #[test]
    fn test_detector_rejects_empty_signature() {
        let mut detector = EchoTrapDetector::new();
        let sig = FindingSignature::new(String::new());

        let result = detector.record_finding(sig);
        assert!(matches!(result, Err(EchoTrapError::EmptySignature)));
    }

    #[test]
    fn test_detector_rejects_oversized_signature() {
        let mut detector = EchoTrapDetector::new();
        let sig = FindingSignature::new("x".repeat(MAX_SIGNATURE_LENGTH + 1));

        let result = detector.record_finding(sig);
        assert!(matches!(
            result,
            Err(EchoTrapError::SignatureTooLong { .. })
        ));
    }

    // =========================================================================
    // EchoTrapEvent Tests
    // =========================================================================

    #[test]
    fn test_echo_trap_event_new() {
        let sig = FindingSignature::new("test".to_string());
        let event = EchoTrapEvent::new(sig.clone(), 3, 1_000_000);

        assert_eq!(event.signature, sig);
        assert_eq!(event.occurrence_count, 3);
        assert_eq!(event.detected_at, 1_000_000);
    }

    #[test]
    fn test_echo_trap_event_serde_roundtrip() {
        let sig = FindingSignature::new("test".to_string());
        let event = EchoTrapEvent::new(sig, 3, 1_000_000);

        let json = serde_json::to_string(&event).unwrap();
        let deserialized: EchoTrapEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, deserialized);
    }

    // =========================================================================
    // SessionTermination Tests
    // =========================================================================

    #[test]
    fn test_on_echo_trap() {
        let sig = FindingSignature::new("test".to_string());
        let event = EchoTrapEvent::new(sig, 3, 1_000_000);

        let termination = EchoTrapDetector::on_echo_trap(&event);

        assert_eq!(
            termination.rationale,
            TerminationRationale::ReasoningDegeneration
        );
        assert!(termination.escalate_to_oracle);
        assert_eq!(termination.trigger_event, event);
    }

    #[test]
    fn test_termination_rationale_as_str() {
        assert_eq!(
            TerminationRationale::ReasoningDegeneration.as_str(),
            "REASONING_DEGENERATION"
        );
    }

    #[test]
    fn test_termination_rationale_display() {
        assert_eq!(
            TerminationRationale::ReasoningDegeneration.to_string(),
            "REASONING_DEGENERATION"
        );
    }

    #[test]
    fn test_termination_rationale_serde() {
        let json = serde_json::to_string(&TerminationRationale::ReasoningDegeneration).unwrap();
        assert_eq!(json, "\"REASONING_DEGENERATION\"");

        let deserialized: TerminationRationale = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, TerminationRationale::ReasoningDegeneration);
    }

    #[test]
    fn test_session_termination_serde_roundtrip() {
        let sig = FindingSignature::new("test".to_string());
        let event = EchoTrapEvent::new(sig, 3, 1_000_000);
        let termination = EchoTrapDetector::on_echo_trap(&event);

        let json = serde_json::to_string(&termination).unwrap();
        let deserialized: SessionTermination = serde_json::from_str(&json).unwrap();
        assert_eq!(termination, deserialized);
    }

    // =========================================================================
    // Integration Tests
    // =========================================================================

    #[test]
    fn test_full_echo_trap_flow() {
        let mut detector = EchoTrapDetector::new();
        let sig = FindingSignature::try_new("lint:E0001:main.rs:42".to_string()).unwrap();

        // Agent produces the same finding repeatedly
        let result1 = detector.record_finding(sig.clone()).unwrap();
        assert!(result1.is_none());

        let result2 = detector.record_finding(sig.clone()).unwrap();
        assert!(result2.is_none());

        let result3 = detector.record_finding(sig).unwrap();
        assert!(result3.is_some());

        // Handle the echo trap
        let event = result3.unwrap();
        let termination = EchoTrapDetector::on_echo_trap(&event);

        // Verify termination properties
        assert_eq!(
            termination.rationale,
            TerminationRationale::ReasoningDegeneration
        );
        assert!(termination.escalate_to_oracle);
        assert_eq!(termination.trigger_event.occurrence_count, 3);
    }

    #[test]
    fn test_mixed_signatures_partial_echo_trap() {
        let mut detector = EchoTrapDetector::new();
        let sig_a = FindingSignature::new("a".to_string());
        let sig_b = FindingSignature::new("b".to_string());

        // Interleave different signatures
        assert!(detector.record_finding(sig_a.clone()).unwrap().is_none());
        assert!(detector.record_finding(sig_b.clone()).unwrap().is_none());
        assert!(detector.record_finding(sig_a.clone()).unwrap().is_none());
        assert!(detector.record_finding(sig_b.clone()).unwrap().is_none());

        // sig_a reaches threshold
        let result = detector.record_finding(sig_a.clone()).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().signature, sig_a);

        // sig_b still below threshold
        assert_eq!(detector.occurrence_count(&sig_b), 2);
    }

    // =========================================================================
    // Error Display Tests
    // =========================================================================

    #[test]
    fn test_error_display() {
        let err = EchoTrapError::EmptySignature;
        assert!(err.to_string().contains("empty"));

        let err = EchoTrapError::SignatureTooLong {
            actual: 5000,
            max: 4096,
        };
        assert!(err.to_string().contains("5000"));
        assert!(err.to_string().contains("4096"));

        let err = EchoTrapError::TooManySignatures {
            actual: 300,
            max: 256,
        };
        assert!(err.to_string().contains("300"));
        assert!(err.to_string().contains("256"));
    }
}
