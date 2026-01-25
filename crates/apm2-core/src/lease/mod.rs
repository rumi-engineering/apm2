//! Lease registrar for work item ownership tracking.
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
//!
//! # Security Properties
//!
//! - **Registrar signing**: All lease events carry a registrar signature
//! - **Duplicate rejection**: Attempting to issue a lease for already-leased
//!   work fails
//! - **Expiration enforcement**: Expired leases are auto-detected and released
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

mod error;
mod reducer;
mod state;

#[cfg(test)]
mod security_repro;
#[cfg(test)]
mod tests;

pub use error::LeaseError;
pub use reducer::{LeaseReducer, LeaseReducerState, helpers};
pub use state::{Lease, LeaseState, ReleaseReason};
