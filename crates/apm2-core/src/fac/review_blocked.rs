// AGENT-AUTHORED
//! Review blocked event types for FAC v0 workspace apply failures.
//!
//! This module implements the `ReviewBlockedRecorded` event which is emitted
//! when workspace apply fails or tool execution fails during review. The
//! blocked outcome is made durable in the ledger to ensure liveness tracking.
//!
//! # Design Overview
//!
//! The [`ReviewBlockedRecorded`] event captures:
//! - The specific reason code for the failure (apply, tool, binary, etc.)
//! - CAS reference to blocked logs for debugging
//! - HTF time envelope for temporal authority
//! - Domain-separated signature for integrity
//!
//! # Security Properties
//!
//! - **Domain Separation**: The signature uses the `REVIEW_BLOCKED_RECORDED:`
//!   domain prefix to prevent replay attacks.
//! - **CAS Binding**: Blocked logs are stored in CAS with hash reference for
//!   integrity verification.
//! - **HTF Time Binding**: Time envelope reference provides temporal authority
//!   for retry window enforcement.
//!
//! # Example
//!
//! ```rust
//! use apm2_core::crypto::Signer;
//! use apm2_core::fac::{ReasonCode, ReviewBlockedRecorded};
//!
//! let signer = Signer::generate();
//! let event = ReviewBlockedRecorded::create(
//!     "blocked-001".to_string(),
//!     [0x42; 32], // changeset_digest
//!     ReasonCode::ApplyFailed,
//!     [0x33; 32], // blocked_log_hash
//!     [0x44; 32], // time_envelope_ref hash
//!     "recorder-001".to_string(),
//!     &signer,
//! )
//! .expect("valid event");
//!
//! // Verify signature
//! assert!(event.verify_signature(&signer.verifying_key()).is_ok());
//! ```

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::domain_separator::{
    REVIEW_BLOCKED_RECORDED_PREFIX, sign_with_domain, verify_with_domain,
};
use crate::crypto::{Signature, Signer, VerifyingKey};
use crate::htf::TimeEnvelopeRef;

// =============================================================================
// Resource Limits
// =============================================================================

/// Maximum length for string fields.
pub const MAX_STRING_LENGTH: usize = 256;

/// Maximum length for blocked ID.
pub const MAX_BLOCKED_ID_LENGTH: usize = 128;

/// Schema identifier for `ReviewBlockedV1`.
pub const SCHEMA_IDENTIFIER: &str = "apm2.review_blocked.v1";

/// Current schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during review blocked operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ReviewBlockedError {
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

    /// Invalid reason code.
    #[error("invalid reason code: {0}")]
    InvalidReasonCode(String),

    /// Signature verification failed.
    #[error("signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    /// Invalid data in conversion.
    #[error("invalid data: {0}")]
    InvalidData(String),
}

// =============================================================================
// ReasonCode
// =============================================================================

/// Reason codes for review blocked events.
///
/// These codes classify why a review was blocked, enabling appropriate
/// routing for retry or escalation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReasonCode {
    /// Workspace apply operation failed.
    ApplyFailed,
    /// Tool execution failed during review.
    ToolFailed,
    /// Binary file detected (unsupported in v0).
    BinaryUnsupported,
    /// Required artifact missing from CAS.
    MissingArtifact,
    /// Invalid changeset bundle format.
    InvalidBundle,
    /// Operation timed out.
    Timeout,
    /// Policy denied the operation.
    PolicyDenied,
    /// Context miss detected.
    ContextMiss,
    /// View commitment missing or invalid (TCK-00325).
    ///
    /// This code is emitted when the view commitment hash is missing from the
    /// review artifacts. Per SEC-CTRL-FAC-0015, review outcomes MUST bind to
    /// a verifiable view commitment. Missing this binding is a hard failure.
    MissingViewCommitment,
}

impl std::fmt::Display for ReasonCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApplyFailed => write!(f, "APPLY_FAILED"),
            Self::ToolFailed => write!(f, "TOOL_FAILED"),
            Self::BinaryUnsupported => write!(f, "BINARY_UNSUPPORTED"),
            Self::MissingArtifact => write!(f, "MISSING_ARTIFACT"),
            Self::InvalidBundle => write!(f, "INVALID_BUNDLE"),
            Self::Timeout => write!(f, "TIMEOUT"),
            Self::PolicyDenied => write!(f, "POLICY_DENIED"),
            Self::ContextMiss => write!(f, "CONTEXT_MISS"),
            Self::MissingViewCommitment => write!(f, "MISSING_VIEW_COMMITMENT"),
        }
    }
}

impl std::str::FromStr for ReasonCode {
    type Err = ReviewBlockedError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "APPLY_FAILED" => Ok(Self::ApplyFailed),
            "TOOL_FAILED" => Ok(Self::ToolFailed),
            "BINARY_UNSUPPORTED" => Ok(Self::BinaryUnsupported),
            "MISSING_ARTIFACT" => Ok(Self::MissingArtifact),
            "INVALID_BUNDLE" => Ok(Self::InvalidBundle),
            "TIMEOUT" => Ok(Self::Timeout),
            "POLICY_DENIED" => Ok(Self::PolicyDenied),
            "CONTEXT_MISS" => Ok(Self::ContextMiss),
            "MISSING_VIEW_COMMITMENT" => Ok(Self::MissingViewCommitment),
            _ => Err(ReviewBlockedError::InvalidReasonCode(s.to_string())),
        }
    }
}

impl ReasonCode {
    /// Returns the numeric code for this reason.
    ///
    /// Used for canonical encoding and wire format serialization.
    /// Values match the protobuf `ReviewBlockedReasonCode` enum:
    /// - 0 = UNSPECIFIED (not used in Rust)
    /// - 1 = `APPLY_FAILED`
    /// - 2 = `TOOL_FAILED`
    /// - etc.
    /// - 9 = `MISSING_VIEW_COMMITMENT` (TCK-00325)
    #[must_use]
    pub const fn to_code(self) -> u8 {
        match self {
            Self::ApplyFailed => 1,
            Self::ToolFailed => 2,
            Self::BinaryUnsupported => 3,
            Self::MissingArtifact => 4,
            Self::InvalidBundle => 5,
            Self::Timeout => 6,
            Self::PolicyDenied => 7,
            Self::ContextMiss => 8,
            Self::MissingViewCommitment => 9,
        }
    }

    /// Creates a reason code from its numeric code.
    ///
    /// # Errors
    ///
    /// Returns error if the code is invalid or 0 (UNSPECIFIED).
    pub fn from_code(code: u8) -> Result<Self, ReviewBlockedError> {
        match code {
            1 => Ok(Self::ApplyFailed),
            2 => Ok(Self::ToolFailed),
            3 => Ok(Self::BinaryUnsupported),
            4 => Ok(Self::MissingArtifact),
            5 => Ok(Self::InvalidBundle),
            6 => Ok(Self::Timeout),
            7 => Ok(Self::PolicyDenied),
            8 => Ok(Self::ContextMiss),
            9 => Ok(Self::MissingViewCommitment),
            0 => Err(ReviewBlockedError::InvalidReasonCode(
                "UNSPECIFIED (0) is not a valid reason code".to_string(),
            )),
            _ => Err(ReviewBlockedError::InvalidReasonCode(format!(
                "invalid code: {code}"
            ))),
        }
    }

    /// Returns true if this reason code is retryable.
    ///
    /// Some failures (like `Timeout`) may be retried, while others
    /// (like `BinaryUnsupported`) require intervention.
    #[must_use]
    pub const fn is_retryable(self) -> bool {
        matches!(
            self,
            Self::ApplyFailed | Self::ToolFailed | Self::Timeout | Self::MissingArtifact
        )
    }
}

// =============================================================================
// ReviewBlockedRecorded
// =============================================================================

/// Event emitted when a review is blocked due to workspace apply or tool
/// failure.
///
/// This event captures the blocked outcome and stores it durably in the ledger.
/// It binds the failure to the changeset and provides CAS references for logs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewBlockedRecorded {
    /// Unique identifier for this blocked event.
    pub blocked_id: String,
    /// BLAKE3 digest of the changeset that was being reviewed (32 bytes).
    #[serde(with = "serde_bytes")]
    pub changeset_digest: [u8; 32],
    /// Reason code classifying the failure.
    pub reason_code: ReasonCode,
    /// BLAKE3 hash of the blocked logs stored in CAS (32 bytes).
    #[serde(with = "serde_bytes")]
    pub blocked_log_hash: [u8; 32],
    /// HTF time envelope reference hash for temporal authority (32 bytes).
    #[serde(with = "serde_bytes")]
    pub time_envelope_ref: [u8; 32],
    /// Actor who recorded the blocked event.
    pub recorder_actor_id: String,
    /// Ed25519 signature over canonical bytes with `REVIEW_BLOCKED_RECORDED:`
    /// domain.
    #[serde(with = "serde_bytes")]
    pub recorder_signature: [u8; 64],
}

impl ReviewBlockedRecorded {
    /// Creates a new `ReviewBlockedRecorded` event.
    ///
    /// # Arguments
    ///
    /// * `blocked_id` - Unique identifier for this blocked event
    /// * `changeset_digest` - BLAKE3 digest of the changeset
    /// * `reason_code` - Reason code classifying the failure
    /// * `blocked_log_hash` - CAS hash of blocked logs
    /// * `time_envelope_ref` - HTF time envelope reference hash
    /// * `recorder_actor_id` - ID of the recording actor
    /// * `signer` - Signer to authorize the event
    ///
    /// # Errors
    ///
    /// Returns error if any string field exceeds `MAX_STRING_LENGTH`.
    pub fn create(
        blocked_id: String,
        changeset_digest: [u8; 32],
        reason_code: ReasonCode,
        blocked_log_hash: [u8; 32],
        time_envelope_ref: [u8; 32],
        recorder_actor_id: String,
        signer: &Signer,
    ) -> Result<Self, ReviewBlockedError> {
        // Validate inputs
        if blocked_id.is_empty() {
            return Err(ReviewBlockedError::MissingField("blocked_id"));
        }
        if blocked_id.len() > MAX_BLOCKED_ID_LENGTH {
            return Err(ReviewBlockedError::StringTooLong {
                field: "blocked_id",
                len: blocked_id.len(),
                max: MAX_BLOCKED_ID_LENGTH,
            });
        }
        if recorder_actor_id.is_empty() {
            return Err(ReviewBlockedError::MissingField("recorder_actor_id"));
        }
        if recorder_actor_id.len() > MAX_STRING_LENGTH {
            return Err(ReviewBlockedError::StringTooLong {
                field: "recorder_actor_id",
                len: recorder_actor_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }

        // Construct event with placeholder signature
        let mut event = Self {
            blocked_id,
            changeset_digest,
            reason_code,
            blocked_log_hash,
            time_envelope_ref,
            recorder_actor_id,
            recorder_signature: [0u8; 64],
        };

        // Sign
        let canonical = event.canonical_bytes();
        let signature = sign_with_domain(signer, REVIEW_BLOCKED_RECORDED_PREFIX, &canonical);
        event.recorder_signature = signature.to_bytes();

        Ok(event)
    }

    /// Creates a `ReviewBlockedRecorded` event with a `TimeEnvelopeRef`.
    ///
    /// This is a convenience constructor that extracts the hash from a
    /// `TimeEnvelopeRef`.
    ///
    /// # Errors
    ///
    /// Returns error if any string field exceeds maximum length.
    pub fn create_with_envelope(
        blocked_id: String,
        changeset_digest: [u8; 32],
        reason_code: ReasonCode,
        blocked_log_hash: [u8; 32],
        envelope_ref: &TimeEnvelopeRef,
        recorder_actor_id: String,
        signer: &Signer,
    ) -> Result<Self, ReviewBlockedError> {
        let time_envelope_ref: [u8; 32] = *envelope_ref.as_bytes();
        Self::create(
            blocked_id,
            changeset_digest,
            reason_code,
            blocked_log_hash,
            time_envelope_ref,
            recorder_actor_id,
            signer,
        )
    }

    /// Computes the canonical bytes for signing/verification.
    ///
    /// Encoding:
    /// - `blocked_id` (len + bytes)
    /// - `changeset_digest` (32 bytes)
    /// - `reason_code` (1 byte)
    /// - `blocked_log_hash` (32 bytes)
    /// - `time_envelope_ref` (32 bytes)
    /// - `recorder_actor_id` (len + bytes)
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // All strings are bounded by MAX_STRING_LENGTH
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // 1. blocked_id
        bytes.extend_from_slice(&(self.blocked_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.blocked_id.as_bytes());

        // 2. changeset_digest
        bytes.extend_from_slice(&self.changeset_digest);

        // 3. reason_code
        bytes.push(self.reason_code.to_code());

        // 4. blocked_log_hash
        bytes.extend_from_slice(&self.blocked_log_hash);

        // 5. time_envelope_ref
        bytes.extend_from_slice(&self.time_envelope_ref);

        // 6. recorder_actor_id
        bytes.extend_from_slice(&(self.recorder_actor_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.recorder_actor_id.as_bytes());

        bytes
    }

    /// Verifies the event signature.
    ///
    /// # Errors
    ///
    /// Returns error if the signature doesn't match the canonical bytes.
    pub fn verify_signature(&self, key: &VerifyingKey) -> Result<(), ReviewBlockedError> {
        let canonical = self.canonical_bytes();
        let signature = Signature::from_bytes(&self.recorder_signature);

        verify_with_domain(key, REVIEW_BLOCKED_RECORDED_PREFIX, &canonical, &signature)
            .map_err(|e| ReviewBlockedError::SignatureVerificationFailed(e.to_string()))
    }

    /// Returns the time envelope reference as a `TimeEnvelopeRef`.
    #[must_use]
    pub fn time_envelope(&self) -> Option<TimeEnvelopeRef> {
        TimeEnvelopeRef::from_slice(&self.time_envelope_ref)
    }
}

// =============================================================================
// ReviewBlockedRecordedBuilder
// =============================================================================

/// Builder for constructing a `ReviewBlockedRecorded` event.
#[derive(Debug, Default)]
pub struct ReviewBlockedRecordedBuilder {
    blocked_id: Option<String>,
    changeset_digest: Option<[u8; 32]>,
    reason_code: Option<ReasonCode>,
    blocked_log_hash: Option<[u8; 32]>,
    time_envelope_ref: Option<[u8; 32]>,
    recorder_actor_id: Option<String>,
}

#[allow(clippy::missing_const_for_fn)] // Builder methods take `mut self` and can't be const
impl ReviewBlockedRecordedBuilder {
    /// Creates a new builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the blocked ID.
    #[must_use]
    pub fn blocked_id(mut self, id: impl Into<String>) -> Self {
        self.blocked_id = Some(id.into());
        self
    }

    /// Sets the changeset digest.
    #[must_use]
    pub fn changeset_digest(mut self, digest: [u8; 32]) -> Self {
        self.changeset_digest = Some(digest);
        self
    }

    /// Sets the reason code.
    #[must_use]
    pub fn reason_code(mut self, code: ReasonCode) -> Self {
        self.reason_code = Some(code);
        self
    }

    /// Sets the blocked log hash.
    #[must_use]
    pub fn blocked_log_hash(mut self, hash: [u8; 32]) -> Self {
        self.blocked_log_hash = Some(hash);
        self
    }

    /// Sets the time envelope reference.
    #[must_use]
    pub fn time_envelope_ref(mut self, hash: [u8; 32]) -> Self {
        self.time_envelope_ref = Some(hash);
        self
    }

    /// Sets the time envelope reference from a `TimeEnvelopeRef`.
    #[must_use]
    pub fn time_envelope(mut self, envelope_ref: &TimeEnvelopeRef) -> Self {
        self.time_envelope_ref = Some(*envelope_ref.as_bytes());
        self
    }

    /// Sets the recorder actor ID.
    #[must_use]
    pub fn recorder_actor_id(mut self, id: impl Into<String>) -> Self {
        self.recorder_actor_id = Some(id.into());
        self
    }

    /// Builds the event and signs it.
    ///
    /// # Errors
    ///
    /// Returns error if required fields are missing or validation fails.
    pub fn build_and_sign(
        self,
        signer: &Signer,
    ) -> Result<ReviewBlockedRecorded, ReviewBlockedError> {
        let blocked_id = self
            .blocked_id
            .ok_or(ReviewBlockedError::MissingField("blocked_id"))?;
        let changeset_digest = self
            .changeset_digest
            .ok_or(ReviewBlockedError::MissingField("changeset_digest"))?;
        let reason_code = self
            .reason_code
            .ok_or(ReviewBlockedError::MissingField("reason_code"))?;
        let blocked_log_hash = self
            .blocked_log_hash
            .ok_or(ReviewBlockedError::MissingField("blocked_log_hash"))?;
        let time_envelope_ref = self
            .time_envelope_ref
            .ok_or(ReviewBlockedError::MissingField("time_envelope_ref"))?;
        let recorder_actor_id = self
            .recorder_actor_id
            .ok_or(ReviewBlockedError::MissingField("recorder_actor_id"))?;

        ReviewBlockedRecorded::create(
            blocked_id,
            changeset_digest,
            reason_code,
            blocked_log_hash,
            time_envelope_ref,
            recorder_actor_id,
            signer,
        )
    }
}

// =============================================================================
// Proto Conversions
// =============================================================================

// Re-export proto type for wire format serialization
pub use crate::events::ReviewBlockedRecorded as ReviewBlockedRecordedProto;

impl TryFrom<ReviewBlockedRecordedProto> for ReviewBlockedRecorded {
    type Error = ReviewBlockedError;

    fn try_from(proto: ReviewBlockedRecordedProto) -> Result<Self, Self::Error> {
        // Validate resource limits
        if proto.blocked_id.is_empty() {
            return Err(ReviewBlockedError::MissingField("blocked_id"));
        }
        if proto.blocked_id.len() > MAX_BLOCKED_ID_LENGTH {
            return Err(ReviewBlockedError::StringTooLong {
                field: "blocked_id",
                len: proto.blocked_id.len(),
                max: MAX_BLOCKED_ID_LENGTH,
            });
        }
        if proto.recorder_actor_id.len() > MAX_STRING_LENGTH {
            return Err(ReviewBlockedError::StringTooLong {
                field: "recorder_actor_id",
                len: proto.recorder_actor_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }

        let changeset_digest = proto.changeset_digest.try_into().map_err(|_| {
            ReviewBlockedError::InvalidData("changeset_digest must be 32 bytes".into())
        })?;

        let blocked_log_hash = proto.blocked_log_hash.try_into().map_err(|_| {
            ReviewBlockedError::InvalidData("blocked_log_hash must be 32 bytes".into())
        })?;

        let time_envelope_ref = proto
            .time_envelope_ref
            .as_ref()
            .map(|ter| {
                ter.hash.as_slice().try_into().map_err(|_| {
                    ReviewBlockedError::InvalidData("time_envelope_ref must be 32 bytes".into())
                })
            })
            .transpose()?
            .unwrap_or([0u8; 32]);

        let recorder_signature = proto.recorder_signature.try_into().map_err(|_| {
            ReviewBlockedError::InvalidData("recorder_signature must be 64 bytes".into())
        })?;

        // Parse reason code from proto enum value
        let reason_code =
            ReasonCode::from_code(u8::try_from(proto.reason_code).map_err(|_| {
                ReviewBlockedError::InvalidData("reason_code must fit in u8".into())
            })?)?;

        Ok(Self {
            blocked_id: proto.blocked_id,
            changeset_digest,
            reason_code,
            blocked_log_hash,
            time_envelope_ref,
            recorder_actor_id: proto.recorder_actor_id,
            recorder_signature,
        })
    }
}

impl From<ReviewBlockedRecorded> for ReviewBlockedRecordedProto {
    fn from(event: ReviewBlockedRecorded) -> Self {
        // Import the proto TimeEnvelopeRef type
        use crate::events::TimeEnvelopeRef as TimeEnvelopeRefProto;

        Self {
            blocked_id: event.blocked_id,
            changeset_digest: event.changeset_digest.to_vec(),
            reason_code: i32::from(event.reason_code.to_code()),
            blocked_log_hash: event.blocked_log_hash.to_vec(),
            time_envelope_ref: Some(TimeEnvelopeRefProto {
                hash: event.time_envelope_ref.to_vec(),
            }),
            recorder_actor_id: event.recorder_actor_id,
            recorder_signature: event.recorder_signature.to_vec(),
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
    fn test_reason_code_from_str() {
        assert_eq!(
            "APPLY_FAILED".parse::<ReasonCode>().unwrap(),
            ReasonCode::ApplyFailed
        );
        assert_eq!(
            "TOOL_FAILED".parse::<ReasonCode>().unwrap(),
            ReasonCode::ToolFailed
        );
        assert_eq!(
            "BINARY_UNSUPPORTED".parse::<ReasonCode>().unwrap(),
            ReasonCode::BinaryUnsupported
        );
        assert_eq!(
            "MISSING_ARTIFACT".parse::<ReasonCode>().unwrap(),
            ReasonCode::MissingArtifact
        );
        assert_eq!(
            "INVALID_BUNDLE".parse::<ReasonCode>().unwrap(),
            ReasonCode::InvalidBundle
        );
        assert_eq!(
            "TIMEOUT".parse::<ReasonCode>().unwrap(),
            ReasonCode::Timeout
        );
        assert_eq!(
            "POLICY_DENIED".parse::<ReasonCode>().unwrap(),
            ReasonCode::PolicyDenied
        );
        assert_eq!(
            "CONTEXT_MISS".parse::<ReasonCode>().unwrap(),
            ReasonCode::ContextMiss
        );
        assert_eq!(
            "MISSING_VIEW_COMMITMENT".parse::<ReasonCode>().unwrap(),
            ReasonCode::MissingViewCommitment
        );
        assert!("UNKNOWN".parse::<ReasonCode>().is_err());
    }

    #[test]
    fn test_reason_code_to_code_roundtrip() {
        // Values 1-9 are valid (0 is UNSPECIFIED per protobuf)
        for code in 1..=9u8 {
            let reason = ReasonCode::from_code(code).unwrap();
            assert_eq!(reason.to_code(), code);
        }
        // 0 (UNSPECIFIED) and 10+ are invalid
        assert!(ReasonCode::from_code(0).is_err());
        assert!(ReasonCode::from_code(10).is_err());
    }

    #[test]
    fn test_reason_code_display() {
        assert_eq!(ReasonCode::ApplyFailed.to_string(), "APPLY_FAILED");
        assert_eq!(ReasonCode::ToolFailed.to_string(), "TOOL_FAILED");
        assert_eq!(
            ReasonCode::BinaryUnsupported.to_string(),
            "BINARY_UNSUPPORTED"
        );
        assert_eq!(ReasonCode::MissingArtifact.to_string(), "MISSING_ARTIFACT");
        assert_eq!(ReasonCode::InvalidBundle.to_string(), "INVALID_BUNDLE");
        assert_eq!(ReasonCode::Timeout.to_string(), "TIMEOUT");
        assert_eq!(ReasonCode::PolicyDenied.to_string(), "POLICY_DENIED");
        assert_eq!(ReasonCode::ContextMiss.to_string(), "CONTEXT_MISS");
        assert_eq!(
            ReasonCode::MissingViewCommitment.to_string(),
            "MISSING_VIEW_COMMITMENT"
        );
    }

    #[test]
    fn test_reason_code_retryable() {
        assert!(ReasonCode::ApplyFailed.is_retryable());
        assert!(ReasonCode::ToolFailed.is_retryable());
        assert!(ReasonCode::Timeout.is_retryable());
        assert!(ReasonCode::MissingArtifact.is_retryable());
        assert!(!ReasonCode::BinaryUnsupported.is_retryable());
        assert!(!ReasonCode::InvalidBundle.is_retryable());
        assert!(!ReasonCode::PolicyDenied.is_retryable());
        assert!(!ReasonCode::ContextMiss.is_retryable());
        // MissingViewCommitment is NOT retryable - it indicates a structural issue
        assert!(!ReasonCode::MissingViewCommitment.is_retryable());
    }

    #[test]
    fn test_review_blocked_create_and_verify() {
        let signer = Signer::generate();
        let event = ReviewBlockedRecorded::create(
            "blocked-001".to_string(),
            [0x42; 32],
            ReasonCode::ApplyFailed,
            [0x33; 32],
            [0x44; 32],
            "recorder-001".to_string(),
            &signer,
        )
        .expect("valid event");

        // Verify signature
        assert!(event.verify_signature(&signer.verifying_key()).is_ok());
    }

    #[test]
    fn test_review_blocked_signature_fails_on_tamper() {
        let signer = Signer::generate();
        let mut event = ReviewBlockedRecorded::create(
            "blocked-001".to_string(),
            [0x42; 32],
            ReasonCode::ApplyFailed,
            [0x33; 32],
            [0x44; 32],
            "recorder-001".to_string(),
            &signer,
        )
        .expect("valid event");

        // Tamper with changeset_digest
        event.changeset_digest = [0xFF; 32];

        // Verification should fail
        assert!(event.verify_signature(&signer.verifying_key()).is_err());
    }

    #[test]
    fn test_review_blocked_builder() {
        let signer = Signer::generate();
        let event = ReviewBlockedRecordedBuilder::new()
            .blocked_id("blocked-002")
            .changeset_digest([0x11; 32])
            .reason_code(ReasonCode::ToolFailed)
            .blocked_log_hash([0x22; 32])
            .time_envelope_ref([0x33; 32])
            .recorder_actor_id("recorder-002")
            .build_and_sign(&signer)
            .expect("valid event");

        assert_eq!(event.blocked_id, "blocked-002");
        assert_eq!(event.reason_code, ReasonCode::ToolFailed);
        assert!(event.verify_signature(&signer.verifying_key()).is_ok());
    }

    #[test]
    fn test_review_blocked_builder_missing_fields() {
        let signer = Signer::generate();

        // Missing blocked_id
        let result = ReviewBlockedRecordedBuilder::new()
            .changeset_digest([0x11; 32])
            .reason_code(ReasonCode::ToolFailed)
            .blocked_log_hash([0x22; 32])
            .time_envelope_ref([0x33; 32])
            .recorder_actor_id("recorder-002")
            .build_and_sign(&signer);
        assert!(matches!(
            result,
            Err(ReviewBlockedError::MissingField("blocked_id"))
        ));

        // Missing reason_code
        let result = ReviewBlockedRecordedBuilder::new()
            .blocked_id("blocked-002")
            .changeset_digest([0x11; 32])
            .blocked_log_hash([0x22; 32])
            .time_envelope_ref([0x33; 32])
            .recorder_actor_id("recorder-002")
            .build_and_sign(&signer);
        assert!(matches!(
            result,
            Err(ReviewBlockedError::MissingField("reason_code"))
        ));
    }

    #[test]
    fn test_review_blocked_string_too_long() {
        let signer = Signer::generate();
        let long_id = "x".repeat(MAX_BLOCKED_ID_LENGTH + 1);

        let result = ReviewBlockedRecorded::create(
            long_id,
            [0x42; 32],
            ReasonCode::ApplyFailed,
            [0x33; 32],
            [0x44; 32],
            "recorder-001".to_string(),
            &signer,
        );

        assert!(matches!(
            result,
            Err(ReviewBlockedError::StringTooLong {
                field: "blocked_id",
                ..
            })
        ));
    }

    #[test]
    fn test_review_blocked_canonical_bytes_deterministic() {
        let signer = Signer::generate();
        let event1 = ReviewBlockedRecorded::create(
            "blocked-001".to_string(),
            [0x42; 32],
            ReasonCode::ApplyFailed,
            [0x33; 32],
            [0x44; 32],
            "recorder-001".to_string(),
            &signer,
        )
        .expect("valid event");

        let event2 = ReviewBlockedRecorded::create(
            "blocked-001".to_string(),
            [0x42; 32],
            ReasonCode::ApplyFailed,
            [0x33; 32],
            [0x44; 32],
            "recorder-001".to_string(),
            &signer,
        )
        .expect("valid event");

        // Same inputs produce same canonical bytes
        assert_eq!(event1.canonical_bytes(), event2.canonical_bytes());
        // Ed25519 is deterministic, so signatures should match
        assert_eq!(event1.recorder_signature, event2.recorder_signature);
    }

    #[test]
    fn test_different_reason_codes_different_canonical_bytes() {
        let signer = Signer::generate();
        let event1 = ReviewBlockedRecorded::create(
            "blocked-001".to_string(),
            [0x42; 32],
            ReasonCode::ApplyFailed,
            [0x33; 32],
            [0x44; 32],
            "recorder-001".to_string(),
            &signer,
        )
        .expect("valid event");

        let event2 = ReviewBlockedRecorded::create(
            "blocked-001".to_string(),
            [0x42; 32],
            ReasonCode::ToolFailed, // Different reason
            [0x33; 32],
            [0x44; 32],
            "recorder-001".to_string(),
            &signer,
        )
        .expect("valid event");

        // Different reason codes produce different canonical bytes
        assert_ne!(event1.canonical_bytes(), event2.canonical_bytes());
    }
}
