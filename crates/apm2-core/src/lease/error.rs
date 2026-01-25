//! Lease-specific error types.

use thiserror::Error;

/// Errors that can occur during lease operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum LeaseError {
    /// A lease already exists for this work item.
    #[error("work item {work_id} already has an active lease: {existing_lease_id}")]
    WorkAlreadyLeased {
        /// The work ID that already has a lease.
        work_id: String,
        /// The ID of the existing lease.
        existing_lease_id: String,
    },

    /// The lease was not found.
    #[error("lease not found: {lease_id}")]
    LeaseNotFound {
        /// The lease ID that was not found.
        lease_id: String,
    },

    /// Attempted to operate on a lease in a terminal state.
    #[error("lease {lease_id} is already in terminal state: {current_state}")]
    LeaseAlreadyTerminal {
        /// The lease ID.
        lease_id: String,
        /// The current terminal state.
        current_state: String,
    },

    /// The lease has expired.
    #[error("lease {lease_id} has expired at {expired_at}")]
    LeaseExpired {
        /// The lease ID.
        lease_id: String,
        /// When the lease expired (Unix nanos).
        expired_at: u64,
    },

    /// Invalid release reason.
    #[error("invalid release reason: {value}")]
    InvalidReleaseReason {
        /// The invalid value provided.
        value: String,
    },

    /// Invalid lease state.
    #[error("invalid lease state: {value}")]
    InvalidLeaseState {
        /// The invalid value provided.
        value: String,
    },

    /// Signature verification failed.
    #[error("registrar signature verification failed for lease {lease_id}")]
    InvalidSignature {
        /// The lease ID with the invalid signature.
        lease_id: String,
    },

    /// Missing required signature.
    #[error("registrar signature is required for lease operation on {lease_id}")]
    MissingSignature {
        /// The lease ID missing a signature.
        lease_id: String,
    },

    /// Renewal would not extend the lease.
    #[error(
        "renewal for lease {lease_id} must extend expiration: current={current_expires_at}, new={new_expires_at}"
    )]
    RenewalDoesNotExtend {
        /// The lease ID.
        lease_id: String,
        /// Current expiration time.
        current_expires_at: u64,
        /// Attempted new expiration time.
        new_expires_at: u64,
    },

    /// Failed to decode the event payload.
    #[error("failed to decode lease event: {0}")]
    DecodeError(#[from] prost::DecodeError),

    /// A lease with this ID already exists.
    #[error("lease already exists: {lease_id}")]
    LeaseAlreadyExists {
        /// The duplicate lease ID.
        lease_id: String,
    },

    /// Unauthorized operation.
    #[error("unauthorized operation on lease {lease_id}: actor {actor_id} is not the lease holder")]
    Unauthorized {
        /// The lease ID.
        lease_id: String,
        /// The unauthorized actor.
        actor_id: String,
    },

    /// Invalid expiration time.
    #[error(
        "invalid expiration time for lease {lease_id}: provided={provided}, lease_expires_at={lease_expires_at}"
    )]
    InvalidExpiration {
        /// The lease ID.
        lease_id: String,
        /// The provided expiration time.
        provided: u64,
        /// The lease's expiration time.
        lease_expires_at: u64,
    },

    /// Invalid input.
    #[error("invalid input for field {field}: {reason}")]
    InvalidInput {
        /// The field name.
        field: String,
        /// The reason it is invalid.
        reason: String,
    },
}
