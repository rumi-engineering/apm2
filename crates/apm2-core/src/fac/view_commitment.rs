use serde::{Deserialize, Serialize};

/// View Commitment V1 schema identifier.
pub const VIEW_COMMITMENT_V1_SCHEMA: &str = "apm2.view_commitment.v1";

/// View Commitment V1.
///
/// Represents the state of the workspace view after materialization and
/// execution. This commitment binds the policy resolution to the resulting
/// file state.
///
/// # Security Properties
///
/// - **Policy Binding**: Binds the view to a specific policy resolution (`policy_resolved_ref`).
/// - **State Integrity**: Binds the view to a specific filesystem state (`result_digest`).
/// - **Temporal Authority**: Binds the view to a specific time (`committed_at_ns`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewCommitmentV1 {
    /// Schema identifier (always `apm2.view_commitment.v1`).
    pub schema: String,

    /// The unique work identifier for this commitment.
    pub work_id: String,

    /// The digest of the workspace state (e.g., git tree hash or file hash).
    /// Typically a BLAKE3 hash of the directory content or git tree.
    pub result_digest: String,

    /// Reference to the policy resolution used for this view.
    pub policy_resolved_ref: String,

    /// Timestamp when this view was committed (nanoseconds since epoch).
    pub committed_at_ns: u64,
}

impl ViewCommitmentV1 {
    /// Creates a new view commitment.
    #[must_use]
    pub fn new(
        work_id: impl Into<String>,
        result_digest: impl Into<String>,
        policy_resolved_ref: impl Into<String>,
        committed_at_ns: u64,
    ) -> Self {
        Self {
            schema: VIEW_COMMITMENT_V1_SCHEMA.to_string(),
            work_id: work_id.into(),
            result_digest: result_digest.into(),
            policy_resolved_ref: policy_resolved_ref.into(),
            committed_at_ns,
        }
    }

    /// Computes the CAS hash of this commitment.
    #[must_use]
    pub fn compute_cas_hash(&self) -> [u8; 32] {
        let json = serde_json::to_vec(self).expect("ViewCommitmentV1 is always serializable");
        *blake3::hash(&json).as_bytes()
    }
}

// Note: DomainSeparator is typically implemented for events that are SIGNED.
// ViewCommitment is currently just a data structure stored in CAS and referenced
// by signed events (like ReviewReceiptRecorded). It acts as the "Body" of the view.
//
// If we need to sign the ViewCommitment directly, we would implement DomainSeparator.
// For now, it is bound via the ReviewArtifactBundle -> ReviewReceiptRecorded chain.
