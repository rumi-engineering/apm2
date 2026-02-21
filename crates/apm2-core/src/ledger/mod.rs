//! Ledger storage layer for the APM2 kernel.
//!
//! This module provides an append-only event ledger backed by `SQLite` with WAL
//! mode for efficient concurrent reads. The ledger stores all kernel events in
//! sequence and maintains references to artifacts stored in the
//! content-addressable storage.
//!
//! # Features
//!
//! - **Append-only semantics**: Events can only be added, never modified or
//!   deleted
//! - **Cursor-based reads**: Efficient iteration through events by sequence
//!   number
//! - **WAL mode**: Concurrent read access while writes are in progress
//! - **Artifact references**: Links to content-addressable storage for large
//!   payloads
//! - **Backend trait**: Abstraction for different storage implementations
//! - **BFT integration**: Support for distributed consensus finalization
//!
//! # Backend Architecture
//!
//! The [`LedgerBackend`] trait defines the core operations for an append-only
//! event ledger. The [`SqliteLedgerBackend`] provides the default SQLite-backed
//! implementation. The [`BftLedgerBackend`] wraps a storage backend to provide
//! BFT consensus integration. The [`Ledger`] type alias preserves backward
//! compatibility.
//!
//! # BFT Integration (RFC-0014)
//!
//! The [`BftLedgerBackend`] provides distributed consensus integration:
//!
//! - **`TotalOrder` events**: Submitted to BFT consensus, stored with quorum
//!   certificate
//! - **`Eventual` events**: Written directly to storage
//! - **Crash recovery**: Consensus metadata persisted for replay
//!
//! # Example
//!
//! ```rust,no_run
//! use apm2_core::ledger::{EventRecord, Ledger};
//!
//! # fn example() -> Result<(), apm2_core::ledger::LedgerError> {
//! let ledger = Ledger::open("/path/to/ledger.db")?;
//!
//! // Append an event
//! let event = EventRecord::new(
//!     "session.start",
//!     "session-123",
//!     "actor-456",
//!     b"{\"user\": \"alice\"}".to_vec(),
//! );
//! let seq_id = ledger.append(&event)?;
//!
//! // Read events from a cursor
//! let events = ledger.read_from(0, 100)?;
//! # Ok(())
//! # }
//! ```

mod backend;
mod bft_backend;
mod storage;

#[cfg(test)]
mod tests;

pub use backend::{BoxFuture, HashFn, LedgerBackend, VerifyFn};
pub use bft_backend::{
    AppendResult, BftLedgerBackend, BftLedgerError, ConsensusIndex, ConsensusMetadata,
    DEFAULT_FINALIZATION_TIMEOUT_MS, EventMetadata, HlcTimestamp, MAX_PENDING_EVENTS,
    MergeOperator, NoOpSchemaRegistry, OrderingGuarantee,
};
pub use storage::{
    ArtifactRef, CURRENT_RECORD_VERSION, EventRecord, Ledger, LedgerError, LedgerStats,
    MigrationStats, SqliteLedgerBackend, init_canonical_schema, migrate_legacy_ledger_events,
};

// ============================================================================
// Post-Commit Notification (TCK-00304: HEF Outbox)
// ============================================================================

/// Channel capacity for commit notifications.
///
/// Per TCK-00304: Channel type is
/// `tokio::sync::mpsc::Sender<CommitNotification>` with capacity 1024. This
/// bounds memory usage while providing sufficient buffering for burst
/// scenarios.
pub const COMMIT_NOTIFICATION_CHANNEL_CAPACITY: usize = 1024;

/// Maximum length for event type strings in commit notifications.
///
/// Per TCK-00304 security review: Unbounded string fields enable memory denial
/// of service. This bound matches segment bounds in HEF topic grammar (64
/// chars).
pub const MAX_EVENT_TYPE_LEN: usize = 64;

/// Maximum length for namespace strings in commit notifications.
///
/// Per TCK-00304 security review: Unbounded string fields enable memory denial
/// of service. This bound matches segment bounds in HEF topic grammar (64
/// chars).
pub const MAX_NAMESPACE_LEN: usize = 64;

/// Notification sent after a successful ledger commit.
///
/// Per DD-HEF-0007, pulse emission order is: CAS persist -> ledger commit ->
/// outbox enqueue -> pulse publish. This struct carries the minimal information
/// needed for the daemon's pulse publisher to emit `PulseEvent` messages.
///
/// # Design Constraints (TCK-00304)
///
/// - Defined in apm2-core with NO daemon type dependencies
/// - Contains only primitive types and stdlib types
/// - Used with `tokio::sync::mpsc::Sender<CommitNotification>` (capacity 1024)
/// - Sent via `try_send()` for non-blocking notification
/// - Notification drops are acceptable (fire-and-forget, never fails commit)
///
/// # Security Invariants
///
/// - [INV-HEF-OUTBOX-001] Notification MUST only be sent AFTER `tx.commit()`
///   succeeds
/// - [INV-HEF-OUTBOX-002] Notification failure MUST NOT fail the ledger commit
/// - [INV-HEF-OUTBOX-003] Notification is best-effort; drops are logged but
///   acceptable
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitNotification {
    /// Ledger sequence ID of the committed event.
    ///
    /// Authoritative for ordering and catch-up per DD-HEF-0001.
    pub seq_id: u64,

    /// Blake3 hash of the committed event (32 bytes).
    ///
    /// Used for content verification and deduplication.
    pub event_hash: [u8; 32],

    /// Event type discriminant (e.g., `WorkEvent`, `GateReceipt`).
    ///
    /// Used by the pulse publisher to determine the topic and envelope fields.
    pub event_type: String,

    /// Namespace of the committed event.
    ///
    /// Used for topic routing (e.g., "kernel", "holon-1").
    pub namespace: String,

    /// Optional consensus index for BFT-committed events.
    ///
    /// Present only for `TotalOrder` events that went through BFT consensus.
    pub consensus_index: Option<ConsensusIndex>,
}

impl CommitNotification {
    /// Creates a new commit notification.
    ///
    /// # String Bounds (TCK-00304 Security Review)
    ///
    /// The `event_type` and `namespace` fields are truncated to their maximum
    /// lengths (`MAX_EVENT_TYPE_LEN` and `MAX_NAMESPACE_LEN`) to prevent
    /// memory `DoS` via unbounded string deserialization.
    #[must_use]
    pub fn new(
        seq_id: u64,
        event_hash: [u8; 32],
        event_type: impl Into<String>,
        namespace: impl Into<String>,
    ) -> Self {
        let event_type = Self::truncate_string(event_type.into(), MAX_EVENT_TYPE_LEN);
        let namespace = Self::truncate_string(namespace.into(), MAX_NAMESPACE_LEN);

        Self {
            seq_id,
            event_hash,
            event_type,
            namespace,
            consensus_index: None,
        }
    }

    /// Creates a commit notification with consensus index.
    ///
    /// # String Bounds (TCK-00304 Security Review)
    ///
    /// The `event_type` and `namespace` fields are truncated to their maximum
    /// lengths (`MAX_EVENT_TYPE_LEN` and `MAX_NAMESPACE_LEN`) to prevent
    /// memory `DoS` via unbounded string deserialization.
    #[must_use]
    pub fn with_consensus(
        seq_id: u64,
        event_hash: [u8; 32],
        event_type: impl Into<String>,
        namespace: impl Into<String>,
        consensus_index: ConsensusIndex,
    ) -> Self {
        let event_type = Self::truncate_string(event_type.into(), MAX_EVENT_TYPE_LEN);
        let namespace = Self::truncate_string(namespace.into(), MAX_NAMESPACE_LEN);

        Self {
            seq_id,
            event_hash,
            event_type,
            namespace,
            consensus_index: Some(consensus_index),
        }
    }

    /// Truncates a string to the specified maximum length at a valid UTF-8
    /// boundary.
    ///
    /// This ensures the string is bounded without panicking on multi-byte
    /// characters.
    fn truncate_string(s: String, max_len: usize) -> String {
        if s.len() <= max_len {
            s
        } else {
            // Find the largest valid UTF-8 boundary <= max_len
            let mut truncate_at = max_len;
            while truncate_at > 0 && !s.is_char_boundary(truncate_at) {
                truncate_at -= 1;
            }
            s[..truncate_at].to_string()
        }
    }
}

/// Type alias for the commit notification sender.
///
/// Per TCK-00304: Uses `tokio::sync::mpsc::Sender` with capacity 1024.
/// The sender is stored optionally in `BftLedgerBackend` and used via
/// `try_send()` for non-blocking notification.
pub type CommitNotificationSender = tokio::sync::mpsc::Sender<CommitNotification>;

/// Type alias for the commit notification receiver.
///
/// Used by the daemon's pulse publisher to drain notifications and emit
/// `PulseEvent` messages.
pub type CommitNotificationReceiver = tokio::sync::mpsc::Receiver<CommitNotification>;
