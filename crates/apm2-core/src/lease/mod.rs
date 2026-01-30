//! Lease registrar and capability proof model for work item ownership.
//!
//! This module provides the lease management infrastructure for the APM2
//! kernel. Leases ensure at-most-one agent can claim a work item at any time.
//!
//! # Architecture
//!
//! ```text
//! LeaseIssued --> Lease (ACTIVE)
//!                |
//!                v
//! LeaseRenewed --> Lease (ACTIVE, new expires_at)
//!                |
//!                v
//! LeaseReleased/LeaseExpired --> Lease (RELEASED/EXPIRED)
//! ```
//!
//! # Key Concepts
//!
//! - **Lease**: A time-bounded exclusive claim on a work item
//! - **Registrar**: The authority that issues and signs leases
//! - **At-most-one**: Only one active lease per `work_id` at any time
//! - **Signature**: Registrar signs all lease operations for authenticity
//! - **Capability**: An unforgeable token granting specific permissions
//! - **Capability Proof**: Cryptographic proof of authority with delegation
//!   chain
//!
//! # Capability Model (RFC-0014)
//!
//! The [`capability`] submodule implements the OCAP (Object Capability) model
//! for cross-node authority verification. Key features:
//!
//! - **Namespace binding**: Capabilities are bound to namespaces to prevent
//!   cross-namespace replay attacks
//! - **Delegation chains**: Capabilities can be delegated hierarchically
//! - **Lease linkage**: `capability_id == lease_id` for lease-backed
//!   capabilities
//! - **Ledger verifiable**: Proofs can be verified against the ledger
//!
//! # Security Properties
//!
//! - **Registrar signing**: All lease events carry a registrar signature
//! - **Duplicate rejection**: Attempting to issue a lease for already-leased
//!   work fails
//! - **Expiration enforcement**: Expired leases are auto-detected and released
//! - **Cross-node verification**: Capability proofs work across nodes
//!
//! # Example
//!
//! ```rust
//! use apm2_core::lease::{LeaseReducer, LeaseState};
//! use apm2_core::reducer::{Reducer, ReducerContext};
//!
//! let mut reducer = LeaseReducer::new();
//! // Apply lease events from the ledger...
//! ```

pub mod capability;
mod error;
mod reducer;
mod state;

#[cfg(test)]
mod security_repro;
#[cfg(test)]
mod tests;

pub use capability::{
    Capability, CapabilityProof, CapabilityRegistryState, CapabilityState, DelegationChainEntry,
    MAX_CAPABILITIES_PER_NAMESPACE, MAX_DELEGATION_CHAIN_ENTRIES, MAX_DELEGATION_DEPTH,
    MAX_HASH_LEN, MAX_ID_LEN, MAX_SIGNATURE_LEN, RevocationReason,
};
pub use error::LeaseError;
pub use reducer::{LeaseReducer, LeaseReducerState, helpers};
pub use state::{Lease, LeaseState, ReleaseReason};
