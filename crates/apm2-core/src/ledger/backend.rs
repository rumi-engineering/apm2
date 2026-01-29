//! Ledger backend trait abstraction.
//!
//! This module defines the `LedgerBackend` trait that abstracts the core
//! operations of an append-only event ledger. The trait enables different
//! storage implementations while maintaining consistent semantics.
//!
//! # Async Pattern
//!
//! All trait methods return `BoxFuture` to support async execution while
//! maintaining object safety. This follows the pattern established in
//! `crates/apm2-core/src/adapter/traits.rs` per RFC-0014 DD-0002.

use std::future::Future;
use std::pin::Pin;

use super::storage::{EventRecord, LedgerError};

/// A boxed future for async trait methods.
///
/// This type alias follows the pattern from `adapter::traits::BoxFuture`.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Function type for computing event hash given payload and previous hash.
///
/// This is object-safe (uses trait object) to allow `LedgerBackend` to be
/// used with `Box<dyn LedgerBackend>`.
pub type HashFn<'a> = &'a (dyn Fn(&[u8], &[u8]) -> Vec<u8> + Send + Sync);

/// Function type for verifying event signatures.
///
/// Returns `true` if the signature is valid.
pub type VerifyFn<'a> = &'a (dyn Fn(&[u8], &[u8]) -> bool + Send + Sync);

/// Trait defining the core operations of an append-only event ledger.
///
/// Implementations of this trait provide the fundamental storage operations
/// for the APM2 event-sourcing architecture: append, read, head, and chain
/// verification.
///
/// # Object Safety
///
/// This trait is object-safe and can be used with `Box<dyn LedgerBackend>`.
/// All methods return `BoxFuture` and use trait objects for callbacks.
///
/// # Invariants
///
/// - [INV-BKD-001] Events are immutable once appended; the ledger is
///   append-only.
/// - [INV-BKD-002] Sequence IDs are monotonically increasing.
/// - [INV-BKD-003] Hash chain integrity must be maintainable across appends.
///
/// # Contracts
///
/// - [CTR-BKD-001] `append` must return a unique, monotonically increasing
///   sequence ID.
/// - [CTR-BKD-002] `read_from` must return events in sequence order.
/// - [CTR-BKD-003] `head` must return the current maximum sequence ID (0 if
///   empty).
/// - [CTR-BKD-004] `verify_chain` must validate all events from genesis.
pub trait LedgerBackend: Send + Sync {
    /// Appends an event to the ledger within a namespace.
    ///
    /// Returns the assigned sequence ID for the event.
    ///
    /// # Arguments
    ///
    /// * `namespace` - The namespace for this event (e.g., "kernel",
    ///   "holon-A").
    /// * `event` - The event record to append.
    ///
    /// # Errors
    ///
    /// Returns an error if the event cannot be inserted.
    fn append<'a>(
        &'a self,
        namespace: &'a str,
        event: &'a EventRecord,
    ) -> BoxFuture<'a, Result<u64, LedgerError>>;

    /// Reads events starting from a cursor position within a namespace.
    ///
    /// Returns up to `limit` events with sequence IDs >= `cursor`.
    /// Events are returned in sequence order (ascending by `seq_id`).
    ///
    /// # Arguments
    ///
    /// * `namespace` - The namespace to read from.
    /// * `cursor` - The starting sequence ID.
    /// * `limit` - Maximum number of events to return.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    fn read_from<'a>(
        &'a self,
        namespace: &'a str,
        cursor: u64,
        limit: u64,
    ) -> BoxFuture<'a, Result<Vec<EventRecord>, LedgerError>>;

    /// Gets the current maximum sequence ID (head of the ledger) for a
    /// namespace.
    ///
    /// Returns 0 if the ledger is empty for this namespace.
    ///
    /// # Arguments
    ///
    /// * `namespace` - The namespace to query.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    fn head<'a>(&'a self, namespace: &'a str) -> BoxFuture<'a, Result<u64, LedgerError>>;

    /// Verifies the entire hash chain from a starting sequence ID within a
    /// namespace.
    ///
    /// # Arguments
    ///
    /// * `namespace` - The namespace to verify.
    /// * `from_seq_id` - The sequence ID to start verification from (use 1 for
    ///   genesis).
    /// * `verify_hash_fn` - Function to compute event hash given payload and
    ///   `prev_hash`.
    /// * `verify_sig_fn` - Function to verify signature (returns true if
    ///   valid).
    ///
    /// # Errors
    ///
    /// Returns an error if any event fails verification:
    /// - `HashChainBroken` if hash chain integrity is violated.
    /// - `SignatureInvalid` if a signature fails verification.
    fn verify_chain<'a>(
        &'a self,
        namespace: &'a str,
        from_seq_id: u64,
        verify_hash_fn: HashFn<'a>,
        verify_sig_fn: VerifyFn<'a>,
    ) -> BoxFuture<'a, Result<(), LedgerError>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test that the trait is object-safe
    fn _assert_object_safety(_: &dyn LedgerBackend) {}

    // Test that BoxFuture works correctly
    #[tokio::test]
    async fn test_box_future() {
        let future: BoxFuture<'_, i32> = Box::pin(async { 42 });
        assert_eq!(future.await, 42);
    }
}
