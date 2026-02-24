//! Builder pattern for constructing tool receipts.
//!
//! This module implements the `ReceiptBuilder` for constructing unsigned
//! tool receipts per AD-RECEIPT-001. The builder validates all inputs
//! and computes the `unsigned_bytes_hash` before building.
//!
//! # Architecture
//!
//! ```text
//! ReceiptBuilder
//!     |-- for_tool_execution() or for_episode_start() or ...
//!     |-- with_envelope(envelope_hash)
//!     |-- with_policy(policy_hash)
//!     |-- with_evidence(evidence_refs)
//!     |-- with_timestamp(timestamp_ns)
//!     |-- with_details(tool_execution_details)
//!     `-- build() -> Result<ToolReceipt, ReceiptError>
//! ```
//!
//! # Security Model
//!
//! Per CTR-1205 and CTR-2603:
//! - Builder validates ALL inputs, not just IDs
//! - Required fields must be set before `build()`
//! - `unsigned_bytes_hash` is computed during `build()`
//!
//! # Contract References
//!
//! - AD-RECEIPT-001: Tool receipt generation
//! - CTR-1205: Builder validates ALL inputs
//! - CTR-2603: Builder completeness

use apm2_core::htf::TimeEnvelopeRef;

use super::receipt::{
    CanonicalizerId, Hash, MAX_EVIDENCE_REFS, ReceiptError, ReceiptKind, Signature, SignerIdentity,
    ToolExecutionDetails, ToolReceipt,
};
use crate::episode::EpisodeId;

/// Builder for constructing unsigned tool receipts.
///
/// The builder enforces required fields and validates all inputs per
/// CTR-1205 and CTR-2603.
///
/// # Example
///
/// ```rust,ignore
/// use apm2_daemon::evidence::{ReceiptBuilder, ToolExecutionDetails};
/// use apm2_daemon::episode::EpisodeId;
///
/// let receipt = ReceiptBuilder::for_tool_execution(EpisodeId::new("ep-001")?)
///     .with_envelope([0xaa; 32])
///     .with_policy([0xbb; 32])
///     .with_evidence(vec![[0xcc; 32]])
///     .with_timestamp(1_704_067_200_000_000_000)
///     .with_details(ToolExecutionDetails {
///         request_id: "req-001".to_string(),
///         capability_id: "cap-read".to_string(),
///         args_hash: [0x11; 32],
///         result_hash: [0x22; 32],
///         success: true,
///         result_message: None,
///         duration_ns: 100_000_000,
///     })
///     .build()?;
/// ```
#[derive(Debug, Clone)]
pub struct ReceiptBuilder {
    kind: ReceiptKind,
    episode_id: EpisodeId,
    envelope_hash: Option<Hash>,
    policy_hash: Option<Hash>,
    canonicalizer_id: CanonicalizerId,
    canonicalizer_version: u32,
    evidence_refs: Vec<Hash>,
    timestamp_ns: Option<u64>,
    tool_execution_details: Option<ToolExecutionDetails>,
    time_envelope_ref: Option<TimeEnvelopeRef>,
}

impl ReceiptBuilder {
    /// Creates a new builder with the specified kind and episode ID.
    fn new(kind: ReceiptKind, episode_id: EpisodeId) -> Self {
        Self {
            kind,
            episode_id,
            envelope_hash: None,
            policy_hash: None,
            canonicalizer_id: CanonicalizerId::apm2_proto_v1(),
            canonicalizer_version: 1,
            evidence_refs: Vec::new(),
            timestamp_ns: None,
            tool_execution_details: None,
            time_envelope_ref: None,
        }
    }

    /// Creates a builder for a tool execution receipt.
    ///
    /// # Arguments
    ///
    /// * `episode_id` - Episode this receipt belongs to (validated `EpisodeId`)
    #[must_use]
    pub fn for_tool_execution(episode_id: EpisodeId) -> Self {
        Self::new(ReceiptKind::ToolExecution, episode_id)
    }

    /// Creates a builder for an episode start receipt.
    ///
    /// # Arguments
    ///
    /// * `episode_id` - Episode this receipt belongs to (validated `EpisodeId`)
    #[must_use]
    pub fn for_episode_start(episode_id: EpisodeId) -> Self {
        Self::new(ReceiptKind::EpisodeStart, episode_id)
    }

    /// Creates a builder for an episode stop receipt.
    ///
    /// # Arguments
    ///
    /// * `episode_id` - Episode this receipt belongs to (validated `EpisodeId`)
    #[must_use]
    pub fn for_episode_stop(episode_id: EpisodeId) -> Self {
        Self::new(ReceiptKind::EpisodeStop, episode_id)
    }

    /// Creates a builder for an episode quarantine receipt.
    ///
    /// # Arguments
    ///
    /// * `episode_id` - Episode this receipt belongs to (validated `EpisodeId`)
    #[must_use]
    pub fn for_episode_quarantine(episode_id: EpisodeId) -> Self {
        Self::new(ReceiptKind::EpisodeQuarantine, episode_id)
    }

    /// Creates a builder for a budget checkpoint receipt.
    ///
    /// # Arguments
    ///
    /// * `episode_id` - Episode this receipt belongs to (validated `EpisodeId`)
    #[must_use]
    pub fn for_budget_checkpoint(episode_id: EpisodeId) -> Self {
        Self::new(ReceiptKind::BudgetCheckpoint, episode_id)
    }

    /// Creates a builder for a policy evaluation receipt.
    ///
    /// # Arguments
    ///
    /// * `episode_id` - Episode this receipt belongs to (validated `EpisodeId`)
    #[must_use]
    pub fn for_policy_evaluation(episode_id: EpisodeId) -> Self {
        Self::new(ReceiptKind::PolicyEvaluation, episode_id)
    }

    /// Sets the envelope hash.
    ///
    /// # Arguments
    ///
    /// * `hash` - BLAKE3 hash of the episode envelope
    #[must_use]
    pub const fn with_envelope(mut self, hash: Hash) -> Self {
        self.envelope_hash = Some(hash);
        self
    }

    /// Sets the policy hash.
    ///
    /// # Arguments
    ///
    /// * `hash` - BLAKE3 hash of the policy version used for evaluation
    #[must_use]
    pub const fn with_policy(mut self, hash: Hash) -> Self {
        self.policy_hash = Some(hash);
        self
    }

    /// Sets the canonicalizer ID and version.
    ///
    /// # Arguments
    ///
    /// * `id` - Canonicalizer identifier
    /// * `version` - Canonicalizer version
    #[must_use]
    pub fn with_canonicalizer(mut self, id: CanonicalizerId, version: u32) -> Self {
        self.canonicalizer_id = id;
        self.canonicalizer_version = version;
        self
    }

    /// Sets the evidence references.
    ///
    /// # Arguments
    ///
    /// * `refs` - CAS hashes for evidence artifacts
    #[must_use]
    pub fn with_evidence(mut self, refs: Vec<Hash>) -> Self {
        self.evidence_refs = refs;
        self
    }

    /// Adds a single evidence reference.
    ///
    /// # Arguments
    ///
    /// * `hash` - CAS hash for an evidence artifact
    #[must_use]
    pub fn add_evidence(mut self, hash: Hash) -> Self {
        self.evidence_refs.push(hash);
        self
    }

    /// Sets the timestamp.
    ///
    /// # Arguments
    ///
    /// * `timestamp_ns` - Timestamp in nanoseconds since epoch
    #[must_use]
    pub const fn with_timestamp(mut self, timestamp_ns: u64) -> Self {
        self.timestamp_ns = Some(timestamp_ns);
        self
    }

    /// Sets the tool execution details.
    ///
    /// # Arguments
    ///
    /// * `details` - Tool execution details (required for `ToolExecution` kind)
    #[must_use]
    pub fn with_details(mut self, details: ToolExecutionDetails) -> Self {
        self.tool_execution_details = Some(details);
        self
    }

    /// Sets the time envelope reference (RFC-0016 HTF).
    ///
    /// # Arguments
    ///
    /// * `envelope_ref` - Reference to the `TimeEnvelope` for temporal ordering
    ///
    /// Per RFC-0016::REQ-0002, tool receipts should include a time envelope reference
    /// for temporal ordering and causality tracking.
    #[must_use]
    pub const fn with_time_envelope_ref(mut self, envelope_ref: TimeEnvelopeRef) -> Self {
        self.time_envelope_ref = Some(envelope_ref);
        self
    }

    /// Builds the unsigned receipt.
    ///
    /// This validates all inputs and computes the `unsigned_bytes_hash`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Required fields are missing (`envelope_hash`, `policy_hash`,
    ///   `timestamp`)
    /// - Any field exceeds its maximum length
    /// - `ToolExecution` kind is missing `tool_execution_details`
    pub fn build(self) -> Result<ToolReceipt, ReceiptError> {
        // Note: episode_id is already validated by the EpisodeId type

        // Validate required fields
        let envelope_hash = self.envelope_hash.ok_or(ReceiptError::EmptyField {
            field: "envelope_hash",
        })?;

        let policy_hash = self.policy_hash.ok_or(ReceiptError::EmptyField {
            field: "policy_hash",
        })?;

        let timestamp_ns = self.timestamp_ns.ok_or(ReceiptError::EmptyField {
            field: "timestamp_ns",
        })?;

        // Validate evidence refs count (CTR-1303)
        if self.evidence_refs.len() > MAX_EVIDENCE_REFS {
            return Err(ReceiptError::TooManyEvidenceRefs {
                count: self.evidence_refs.len(),
                max: MAX_EVIDENCE_REFS,
            });
        }

        // Validate tool_execution_details if ToolExecution kind
        if self.kind == ReceiptKind::ToolExecution && self.tool_execution_details.is_none() {
            return Err(ReceiptError::MissingDetails {
                kind: ReceiptKind::ToolExecution,
            });
        }

        // Validate details if present
        if let Some(ref details) = self.tool_execution_details {
            details.validate()?;
        }

        // Create receipt with placeholder hash
        let mut receipt = ToolReceipt {
            kind: self.kind,
            episode_id: self.episode_id,
            envelope_hash,
            policy_hash,
            canonicalizer_id: self.canonicalizer_id,
            canonicalizer_version: self.canonicalizer_version,
            evidence_refs: self.evidence_refs,
            timestamp_ns,
            unsigned_bytes_hash: [0; 32], // Will be computed below
            tool_execution_details: self.tool_execution_details,
            time_envelope_ref: self.time_envelope_ref,
            signature: None,
            signer_identity: None,
        };

        // Compute unsigned_bytes_hash
        receipt.unsigned_bytes_hash = receipt.digest();

        Ok(receipt)
    }
}

/// Extension trait for adding signature to a receipt.
///
/// This is separate from the builder to enforce the unsigned->signed flow.
pub trait ReceiptSigning {
    /// Attaches a signature to the receipt.
    ///
    /// # Arguments
    ///
    /// * `signature` - Ed25519 signature over the canonical bytes
    /// * `signer_identity` - Identity of the signer
    ///
    /// # Errors
    ///
    /// Returns an error if the receipt is already signed.
    fn attach_signature(
        self,
        signature: Signature,
        signer_identity: SignerIdentity,
    ) -> Result<ToolReceipt, ReceiptError>;
}

impl ReceiptSigning for ToolReceipt {
    fn attach_signature(
        mut self,
        signature: Signature,
        signer_identity: SignerIdentity,
    ) -> Result<ToolReceipt, ReceiptError> {
        if self.is_signed() {
            return Err(ReceiptError::AlreadySigned);
        }
        self.signature = Some(signature);
        self.signer_identity = Some(signer_identity);
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::episode::EpisodeError;

    fn test_episode_id(id: &str) -> EpisodeId {
        EpisodeId::new(id).unwrap()
    }

    fn test_details() -> ToolExecutionDetails {
        ToolExecutionDetails {
            request_id: "req-001".to_string(),
            capability_id: "cap-read".to_string(),
            args_hash: [0x11; 32],
            result_hash: [0x22; 32],
            success: true,
            result_message: Some("completed".to_string()),
            duration_ns: 100_000_000,
        }
    }

    #[test]
    fn test_builder_for_tool_execution() {
        let receipt = ReceiptBuilder::for_tool_execution(test_episode_id("ep-001"))
            .with_envelope([0xaa; 32])
            .with_policy([0xbb; 32])
            .with_evidence(vec![[0xcc; 32]])
            .with_timestamp(1_704_067_200_000_000_000)
            .with_details(test_details())
            .build()
            .unwrap();

        assert_eq!(receipt.kind, ReceiptKind::ToolExecution);
        assert_eq!(receipt.episode_id.as_str(), "ep-001");
        assert_eq!(receipt.envelope_hash, [0xaa; 32]);
        assert_eq!(receipt.policy_hash, [0xbb; 32]);
        assert_eq!(receipt.evidence_refs.len(), 1);
        assert!(!receipt.is_signed());
        assert!(receipt.tool_execution_details.is_some());
    }

    #[test]
    fn test_builder_for_episode_start() {
        let receipt = ReceiptBuilder::for_episode_start(test_episode_id("ep-002"))
            .with_envelope([0xaa; 32])
            .with_policy([0xbb; 32])
            .with_timestamp(1_000_000)
            .build()
            .unwrap();

        assert_eq!(receipt.kind, ReceiptKind::EpisodeStart);
        assert_eq!(receipt.episode_id.as_str(), "ep-002");
    }

    #[test]
    fn test_builder_for_episode_stop() {
        let receipt = ReceiptBuilder::for_episode_stop(test_episode_id("ep-003"))
            .with_envelope([0xaa; 32])
            .with_policy([0xbb; 32])
            .with_timestamp(2_000_000)
            .build()
            .unwrap();

        assert_eq!(receipt.kind, ReceiptKind::EpisodeStop);
    }

    #[test]
    fn test_builder_for_episode_quarantine() {
        let receipt = ReceiptBuilder::for_episode_quarantine(test_episode_id("ep-004"))
            .with_envelope([0xaa; 32])
            .with_policy([0xbb; 32])
            .with_timestamp(3_000_000)
            .build()
            .unwrap();

        assert_eq!(receipt.kind, ReceiptKind::EpisodeQuarantine);
    }

    #[test]
    fn test_builder_for_budget_checkpoint() {
        let receipt = ReceiptBuilder::for_budget_checkpoint(test_episode_id("ep-005"))
            .with_envelope([0xaa; 32])
            .with_policy([0xbb; 32])
            .with_timestamp(4_000_000)
            .build()
            .unwrap();

        assert_eq!(receipt.kind, ReceiptKind::BudgetCheckpoint);
    }

    #[test]
    fn test_builder_for_policy_evaluation() {
        let receipt = ReceiptBuilder::for_policy_evaluation(test_episode_id("ep-006"))
            .with_envelope([0xaa; 32])
            .with_policy([0xbb; 32])
            .with_timestamp(5_000_000)
            .build()
            .unwrap();

        assert_eq!(receipt.kind, ReceiptKind::PolicyEvaluation);
    }

    #[test]
    fn test_builder_missing_envelope() {
        let result = ReceiptBuilder::for_episode_start(test_episode_id("ep-001"))
            .with_policy([0xbb; 32])
            .with_timestamp(1_000_000)
            .build();

        assert!(matches!(
            result,
            Err(ReceiptError::EmptyField {
                field: "envelope_hash"
            })
        ));
    }

    #[test]
    fn test_builder_missing_policy() {
        let result = ReceiptBuilder::for_episode_start(test_episode_id("ep-001"))
            .with_envelope([0xaa; 32])
            .with_timestamp(1_000_000)
            .build();

        assert!(matches!(
            result,
            Err(ReceiptError::EmptyField {
                field: "policy_hash"
            })
        ));
    }

    #[test]
    fn test_builder_missing_timestamp() {
        let result = ReceiptBuilder::for_episode_start(test_episode_id("ep-001"))
            .with_envelope([0xaa; 32])
            .with_policy([0xbb; 32])
            .build();

        assert!(matches!(
            result,
            Err(ReceiptError::EmptyField {
                field: "timestamp_ns"
            })
        ));
    }

    #[test]
    fn test_builder_tool_execution_missing_details() {
        let result = ReceiptBuilder::for_tool_execution(test_episode_id("ep-001"))
            .with_envelope([0xaa; 32])
            .with_policy([0xbb; 32])
            .with_timestamp(1_000_000)
            .build();

        assert!(matches!(
            result,
            Err(ReceiptError::MissingDetails {
                kind: ReceiptKind::ToolExecution
            })
        ));
    }

    // Note: Episode ID validation (empty, too long) is now handled by
    // EpisodeId::new() and will panic or return Err(EpisodeError) at
    // construction time.

    #[test]
    fn test_episode_id_empty_rejected() {
        // EpisodeId validation happens at construction time, not at build time
        let result = EpisodeId::new("");
        assert!(matches!(result, Err(EpisodeError::InvalidId { .. })));
    }

    #[test]
    fn test_builder_too_many_evidence_refs() {
        let refs = vec![[0; 32]; MAX_EVIDENCE_REFS + 1];
        let result = ReceiptBuilder::for_episode_start(test_episode_id("ep-001"))
            .with_envelope([0xaa; 32])
            .with_policy([0xbb; 32])
            .with_evidence(refs)
            .with_timestamp(1_000_000)
            .build();

        assert!(matches!(
            result,
            Err(ReceiptError::TooManyEvidenceRefs { .. })
        ));
    }

    #[test]
    fn test_builder_add_evidence() {
        let receipt = ReceiptBuilder::for_episode_start(test_episode_id("ep-001"))
            .with_envelope([0xaa; 32])
            .with_policy([0xbb; 32])
            .add_evidence([0x11; 32])
            .add_evidence([0x22; 32])
            .add_evidence([0x33; 32])
            .with_timestamp(1_000_000)
            .build()
            .unwrap();

        assert_eq!(receipt.evidence_refs.len(), 3);
    }

    #[test]
    fn test_builder_with_canonicalizer() {
        let custom_id = CanonicalizerId::new("custom-v2").unwrap();
        let receipt = ReceiptBuilder::for_episode_start(test_episode_id("ep-001"))
            .with_envelope([0xaa; 32])
            .with_policy([0xbb; 32])
            .with_canonicalizer(custom_id, 2)
            .with_timestamp(1_000_000)
            .build()
            .unwrap();

        assert_eq!(receipt.canonicalizer_id.as_str(), "custom-v2");
        assert_eq!(receipt.canonicalizer_version, 2);
    }

    #[test]
    fn test_builder_computes_unsigned_bytes_hash() {
        let receipt = ReceiptBuilder::for_episode_start(test_episode_id("ep-001"))
            .with_envelope([0xaa; 32])
            .with_policy([0xbb; 32])
            .with_timestamp(1_000_000)
            .build()
            .unwrap();

        // unsigned_bytes_hash should be computed from the digest
        assert_ne!(receipt.unsigned_bytes_hash, [0; 32]);
        assert_eq!(receipt.unsigned_bytes_hash, receipt.digest());
    }

    #[test]
    fn test_receipt_signing() {
        let receipt = ReceiptBuilder::for_episode_start(test_episode_id("ep-001"))
            .with_envelope([0xaa; 32])
            .with_policy([0xbb; 32])
            .with_timestamp(1_000_000)
            .build()
            .unwrap();

        assert!(!receipt.is_signed());

        let signer_identity = SignerIdentity::new([0x12; 32], "test-signer").unwrap();
        let signed_receipt = receipt
            .attach_signature([0xab; 64], signer_identity)
            .unwrap();

        assert!(signed_receipt.is_signed());
        assert!(signed_receipt.signature.is_some());
        assert!(signed_receipt.signer_identity.is_some());
    }

    #[test]
    fn test_receipt_signing_already_signed() {
        let receipt = ReceiptBuilder::for_episode_start(test_episode_id("ep-001"))
            .with_envelope([0xaa; 32])
            .with_policy([0xbb; 32])
            .with_timestamp(1_000_000)
            .build()
            .unwrap();

        let signer_identity = SignerIdentity::new([0x12; 32], "test-signer").unwrap();
        let signed_receipt = receipt
            .attach_signature([0xab; 64], signer_identity.clone())
            .unwrap();

        let result = signed_receipt.attach_signature([0xcd; 64], signer_identity);
        assert!(matches!(result, Err(ReceiptError::AlreadySigned)));
    }

    #[test]
    fn test_builder_validates_details() {
        let invalid_details = ToolExecutionDetails {
            request_id: String::new(), // Empty - should fail
            capability_id: "cap-001".to_string(),
            args_hash: [0; 32],
            result_hash: [0; 32],
            success: true,
            result_message: None,
            duration_ns: 100,
        };

        let result = ReceiptBuilder::for_tool_execution(test_episode_id("ep-001"))
            .with_envelope([0xaa; 32])
            .with_policy([0xbb; 32])
            .with_timestamp(1_000_000)
            .with_details(invalid_details)
            .build();

        assert!(matches!(
            result,
            Err(ReceiptError::EmptyField {
                field: "request_id"
            })
        ));
    }
}
