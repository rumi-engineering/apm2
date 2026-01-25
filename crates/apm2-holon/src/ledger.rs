//! Ledger event types for holonic operations.
//!
//! This module defines the [`LedgerEvent`] struct and [`EventType`] enum for
//! recording holonic operations to an append-only ledger. Events are linked
//! using hash chains to enable tamper detection.
//!
//! # Design
//!
//! The ledger provides:
//! - **Immutable audit trail**: All holonic operations are recorded
//! - **Deterministic serialization**: Events serialize consistently for hashing
//! - **Hash chain linking**: Each event references the hash of the previous
//!   event
//! - **Tamper detection**: Chain verification detects modifications
//!
//! # Event Types
//!
//! Events cover the full lifecycle of holonic work:
//! - Work lifecycle: Created, Claimed, Progressed, Completed, Failed, Escalated
//! - Episode events: Started, Completed
//! - Artifact events: Emitted, Evidence published
//! - Lease events: Issued, Renewed, Released, Expired
//! - Resource events: Budget consumed, Budget exhausted
//!
//! # Example
//!
//! ```rust
//! use apm2_holon::ledger::{EventHash, EventType, LedgerEvent};
//!
//! // Create a genesis event (first event in chain)
//! let genesis = LedgerEvent::builder()
//!     .event_id("evt-001")
//!     .work_id("work-001")
//!     .holon_id("holon-001")
//!     .event_type(EventType::WorkCreated {
//!         title: "Implement feature X".to_string(),
//!     })
//!     .build();
//!
//! assert!(genesis.is_genesis());
//!
//! // Create a subsequent event linked to the genesis
//! let second = LedgerEvent::builder()
//!     .event_id("evt-002")
//!     .work_id("work-001")
//!     .holon_id("holon-001")
//!     .event_type(EventType::WorkClaimed {
//!         lease_id: "lease-001".to_string(),
//!     })
//!     .previous_hash(genesis.compute_hash())
//!     .build();
//!
//! // Verify the chain
//! assert!(second.verify_previous(&genesis));
//! ```

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::work::WorkLifecycle;

/// SHA-256 hash of an event, represented as a 32-byte array.
///
/// The hash is computed over the canonical (deterministic) serialization
/// of the event, excluding the signature field.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EventHash([u8; 32]);

impl EventHash {
    /// The zero hash, used for the genesis event's `previous_hash`.
    pub const ZERO: Self = Self([0u8; 32]);

    /// Creates a new `EventHash` from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the hash bytes as a slice.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns `true` if this is the zero hash (genesis marker).
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }

    /// Returns the hash as a hexadecimal string.
    #[must_use]
    pub fn to_hex(&self) -> String {
        use std::fmt::Write;
        self.0.iter().fold(String::with_capacity(64), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
    }

    /// Parses a hash from a hexadecimal string.
    ///
    /// # Errors
    ///
    /// Returns an error if the string is not exactly 64 hex characters
    /// or contains invalid hex digits.
    pub fn from_hex(s: &str) -> Result<Self, EventHashError> {
        if s.len() != 64 {
            return Err(EventHashError::InvalidLength {
                expected: 64,
                actual: s.len(),
            });
        }

        let mut bytes = [0u8; 32];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let hex_str = std::str::from_utf8(chunk).map_err(|_| EventHashError::InvalidHex)?;
            bytes[i] = u8::from_str_radix(hex_str, 16).map_err(|_| EventHashError::InvalidHex)?;
        }

        Ok(Self(bytes))
    }
}

impl fmt::Debug for EventHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EventHash({})", self.to_hex())
    }
}

impl fmt::Display for EventHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Display first 8 and last 8 hex chars for readability
        let hex = self.to_hex();
        write!(f, "{}...{}", &hex[..8], &hex[56..])
    }
}

impl Default for EventHash {
    fn default() -> Self {
        Self::ZERO
    }
}

/// Errors that can occur when parsing an `EventHash`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventHashError {
    /// The hex string has an invalid length.
    InvalidLength {
        /// Expected length in characters.
        expected: usize,
        /// Actual length in characters.
        actual: usize,
    },
    /// The string contains invalid hex characters.
    InvalidHex,
}

impl fmt::Display for EventHashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { expected, actual } => {
                write!(f, "invalid hash length: expected {expected}, got {actual}")
            },
            Self::InvalidHex => write!(f, "invalid hex character"),
        }
    }
}

impl std::error::Error for EventHashError {}

/// Event type discriminant with associated data.
///
/// This enum represents all types of events that can occur in holonic
/// coordination. Each variant carries the data specific to that event type.
///
/// # Stability
///
/// Event type discriminants are stable across versions. New event types
/// may be added in minor versions, but existing types will not change
/// their serialized representation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum EventType {
    // =========================================================================
    // Work lifecycle events
    // =========================================================================
    /// Work was created.
    WorkCreated {
        /// Human-readable title of the work.
        title: String,
    },

    /// Work was claimed by a holon via a lease.
    WorkClaimed {
        /// The lease ID authorizing the claim.
        lease_id: String,
    },

    /// Work made progress (intermediate state update).
    WorkProgressed {
        /// Description of the progress made.
        description: String,
        /// New lifecycle state.
        new_state: WorkLifecycle,
    },

    /// Work was completed successfully.
    WorkCompleted {
        /// Evidence IDs supporting completion.
        evidence_ids: Vec<String>,
    },

    /// Work failed and cannot be retried.
    WorkFailed {
        /// Reason for the failure.
        reason: String,
        /// Whether the failure is recoverable.
        recoverable: bool,
    },

    /// Work was escalated to a supervisor.
    WorkEscalated {
        /// ID of the supervisor holon.
        to_holon_id: String,
        /// Reason for escalation.
        reason: String,
    },

    /// Work was cancelled.
    WorkCancelled {
        /// Reason for cancellation.
        reason: String,
    },

    // =========================================================================
    // Episode events
    // =========================================================================
    /// An episode started.
    EpisodeStarted {
        /// Unique episode ID.
        episode_id: String,
        /// Attempt number for this episode.
        attempt_number: u32,
    },

    /// An episode completed.
    EpisodeCompleted {
        /// Unique episode ID.
        episode_id: String,
        /// Outcome of the episode.
        outcome: EpisodeOutcome,
        /// Tokens consumed during the episode.
        tokens_consumed: u64,
    },

    // =========================================================================
    // Artifact events
    // =========================================================================
    /// An artifact was emitted.
    ArtifactEmitted {
        /// Unique artifact ID.
        artifact_id: String,
        /// Type of artifact.
        artifact_kind: String,
        /// Content hash for integrity verification.
        content_hash: Option<String>,
    },

    /// Evidence was published (special artifact for verification).
    EvidencePublished {
        /// Evidence ID.
        evidence_id: String,
        /// Requirement ID this evidence supports.
        requirement_id: String,
        /// Hash of the evidence content.
        content_hash: String,
    },

    // =========================================================================
    // Lease events
    // =========================================================================
    /// A lease was issued.
    LeaseIssued {
        /// Unique lease ID.
        lease_id: String,
        /// Holon receiving the lease.
        holder_id: String,
        /// Expiration timestamp (nanoseconds since epoch).
        expires_at_ns: u64,
    },

    /// A lease was renewed (expiration extended).
    LeaseRenewed {
        /// Unique lease ID.
        lease_id: String,
        /// New expiration timestamp.
        new_expires_at_ns: u64,
    },

    /// A lease was released (voluntarily relinquished).
    LeaseReleased {
        /// Unique lease ID.
        lease_id: String,
        /// Reason for release.
        reason: String,
    },

    /// A lease expired (time-based termination).
    LeaseExpired {
        /// Unique lease ID.
        lease_id: String,
    },

    // =========================================================================
    // Resource events
    // =========================================================================
    /// Budget was consumed.
    BudgetConsumed {
        /// Type of resource consumed.
        resource_type: String,
        /// Amount consumed.
        amount: u64,
        /// Remaining budget.
        remaining: u64,
    },

    /// Budget was exhausted (resource limit reached).
    BudgetExhausted {
        /// Type of resource exhausted.
        resource_type: String,
        /// Total amount used.
        total_used: u64,
        /// Limit that was exceeded.
        limit: u64,
    },
}

impl EventType {
    /// Returns the event type name as a string.
    #[must_use]
    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::WorkCreated { .. } => "work_created",
            Self::WorkClaimed { .. } => "work_claimed",
            Self::WorkProgressed { .. } => "work_progressed",
            Self::WorkCompleted { .. } => "work_completed",
            Self::WorkFailed { .. } => "work_failed",
            Self::WorkEscalated { .. } => "work_escalated",
            Self::WorkCancelled { .. } => "work_cancelled",
            Self::EpisodeStarted { .. } => "episode_started",
            Self::EpisodeCompleted { .. } => "episode_completed",
            Self::ArtifactEmitted { .. } => "artifact_emitted",
            Self::EvidencePublished { .. } => "evidence_published",
            Self::LeaseIssued { .. } => "lease_issued",
            Self::LeaseRenewed { .. } => "lease_renewed",
            Self::LeaseReleased { .. } => "lease_released",
            Self::LeaseExpired { .. } => "lease_expired",
            Self::BudgetConsumed { .. } => "budget_consumed",
            Self::BudgetExhausted { .. } => "budget_exhausted",
        }
    }

    /// Returns `true` if this is a work lifecycle event.
    #[must_use]
    pub const fn is_work_event(&self) -> bool {
        matches!(
            self,
            Self::WorkCreated { .. }
                | Self::WorkClaimed { .. }
                | Self::WorkProgressed { .. }
                | Self::WorkCompleted { .. }
                | Self::WorkFailed { .. }
                | Self::WorkEscalated { .. }
                | Self::WorkCancelled { .. }
        )
    }

    /// Returns `true` if this is an episode event.
    #[must_use]
    pub const fn is_episode_event(&self) -> bool {
        matches!(
            self,
            Self::EpisodeStarted { .. } | Self::EpisodeCompleted { .. }
        )
    }

    /// Returns `true` if this is an artifact event.
    #[must_use]
    pub const fn is_artifact_event(&self) -> bool {
        matches!(
            self,
            Self::ArtifactEmitted { .. } | Self::EvidencePublished { .. }
        )
    }

    /// Returns `true` if this is a lease event.
    #[must_use]
    pub const fn is_lease_event(&self) -> bool {
        matches!(
            self,
            Self::LeaseIssued { .. }
                | Self::LeaseRenewed { .. }
                | Self::LeaseReleased { .. }
                | Self::LeaseExpired { .. }
        )
    }

    /// Returns `true` if this is a resource event.
    #[must_use]
    pub const fn is_resource_event(&self) -> bool {
        matches!(
            self,
            Self::BudgetConsumed { .. } | Self::BudgetExhausted { .. }
        )
    }

    /// Returns `true` if this event represents a terminal state for work.
    #[must_use]
    pub const fn is_terminal_work_event(&self) -> bool {
        matches!(
            self,
            Self::WorkCompleted { .. } | Self::WorkFailed { .. } | Self::WorkCancelled { .. }
        )
    }
}

impl fmt::Display for EventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.type_name())
    }
}

/// Outcome of an episode execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EpisodeOutcome {
    /// Episode completed with goal satisfied.
    Completed,
    /// Episode needs continuation.
    Continuation,
    /// Episode failed with error.
    Failed,
    /// Episode was interrupted (e.g., budget exhausted).
    Interrupted,
    /// Episode resulted in escalation.
    Escalated,
}

impl EpisodeOutcome {
    /// Returns the outcome as a string identifier.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Continuation => "continuation",
            Self::Failed => "failed",
            Self::Interrupted => "interrupted",
            Self::Escalated => "escalated",
        }
    }
}

impl fmt::Display for EpisodeOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// An event recorded in the holonic ledger.
///
/// Each event captures a discrete operation in the holonic system. Events
/// are linked via hash chains to form an immutable, tamper-evident log.
///
/// # Hash Chain
///
/// Events are linked using SHA-256 hashes:
/// - The genesis event has `previous_hash = EventHash::ZERO`
/// - Each subsequent event's `previous_hash` is the hash of the prior event
/// - This creates a chain that detects any modifications
///
/// # Deterministic Serialization
///
/// Events use deterministic JSON serialization for hashing:
/// - Fields are ordered consistently
/// - No optional whitespace variations
/// - All fields (except signature) are included in the hash
///
/// # Signature
///
/// Events can carry a signature from the producing holon. This enables:
/// - Non-repudiation (holon cannot deny producing the event)
/// - Integrity verification independent of chain position
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerEvent {
    /// Unique identifier for this event.
    id: String,

    /// Timestamp when the event occurred (nanoseconds since epoch).
    timestamp_ns: u64,

    /// Associated work identifier.
    work_id: String,

    /// Holon that produced this event.
    holon_id: String,

    /// Event type and payload.
    event_type: EventType,

    /// Hash of the previous event in the chain.
    previous_hash: EventHash,

    /// Holon signature over the canonical event bytes.
    /// Empty for unsigned events.
    #[serde(with = "serde_bytes")]
    signature: Vec<u8>,
}

impl LedgerEvent {
    /// Returns a builder for constructing a `LedgerEvent`.
    #[must_use]
    pub fn builder() -> LedgerEventBuilder {
        LedgerEventBuilder::default()
    }

    /// Returns the event ID.
    #[must_use]
    pub fn event_id(&self) -> &str {
        &self.id
    }

    /// Returns the timestamp in nanoseconds since epoch.
    #[must_use]
    pub const fn timestamp_ns(&self) -> u64 {
        self.timestamp_ns
    }

    /// Returns the associated work ID.
    #[must_use]
    pub fn work_id(&self) -> &str {
        &self.work_id
    }

    /// Returns the holon ID that produced this event.
    #[must_use]
    pub fn holon_id(&self) -> &str {
        &self.holon_id
    }

    /// Returns the event type.
    #[must_use]
    pub const fn event_type(&self) -> &EventType {
        &self.event_type
    }

    /// Returns the hash of the previous event.
    #[must_use]
    pub const fn previous_hash(&self) -> &EventHash {
        &self.previous_hash
    }

    /// Returns the signature bytes.
    #[must_use]
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Returns `true` if this event has a signature.
    #[must_use]
    pub fn is_signed(&self) -> bool {
        !self.signature.is_empty()
    }

    /// Returns `true` if this is a genesis event (first in chain).
    ///
    /// Genesis events have a zero `previous_hash`.
    #[must_use]
    pub fn is_genesis(&self) -> bool {
        self.previous_hash.is_zero()
    }

    /// Returns the canonical byte representation for hashing/signing.
    ///
    /// This produces a deterministic JSON serialization that:
    /// - Has consistent field ordering (via RFC 8785 / JCS)
    /// - Excludes the signature field
    /// - Is suitable for hash computation and signature verification
    ///
    /// # Canonicalization Rules
    ///
    /// The canonical form is JSON with fields in this order:
    /// 1. `id`
    /// 2. `timestamp_ns`
    /// 3. `work_id`
    /// 4. `holon_id`
    /// 5. `event_type` (with its own deterministic serialization)
    /// 6. `previous_hash` (as hex string)
    ///
    /// # Panics
    ///
    /// This method will not panic under normal circumstances. The internal
    /// JSON serialization uses only types that are guaranteed to serialize
    /// successfully.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        // Use serde_json::Value to ensure deterministic field ordering
        let canonical = serde_json::json!({
            "id": self.id,
            "timestamp_ns": self.timestamp_ns,
            "work_id": self.work_id,
            "holon_id": self.holon_id,
            "event_type": self.event_type,
            "previous_hash": self.previous_hash.to_hex(),
        });

        // Use serde_jcs to ensure RFC 8785 canonicalization (sorted keys, no
        // whitespace)
        serde_jcs::to_vec(&canonical).expect("serialization cannot fail")
    }

    /// Computes the hash of this event.
    ///
    /// The hash is computed over the canonical byte representation,
    /// which excludes the signature field.
    #[must_use]
    #[allow(clippy::collection_is_never_read)] // bytes is read via Hash trait
    pub fn compute_hash(&self) -> EventHash {
        let bytes = self.canonical_bytes();
        let hash = blake3::hash(&bytes);
        EventHash(*hash.as_bytes())
    }

    /// Verifies that this event correctly links to the given previous event.
    ///
    /// Returns `true` if `self.previous_hash` matches the computed hash
    /// of `previous_event`.
    #[must_use]
    pub fn verify_previous(&self, previous_event: &Self) -> bool {
        self.previous_hash == previous_event.compute_hash()
    }
}

/// Builder for constructing [`LedgerEvent`] instances.
#[derive(Debug, Default)]
pub struct LedgerEventBuilder {
    event_id: Option<String>,
    timestamp_ns: Option<u64>,
    work_id: Option<String>,
    holon_id: Option<String>,
    event_type: Option<EventType>,
    previous_hash: Option<EventHash>,
    signature: Vec<u8>,
}

impl LedgerEventBuilder {
    /// Sets the event ID.
    #[must_use]
    pub fn event_id(mut self, id: impl Into<String>) -> Self {
        self.event_id = Some(id.into());
        self
    }

    /// Sets the timestamp in nanoseconds since epoch.
    #[must_use]
    pub const fn timestamp_ns(mut self, ts: u64) -> Self {
        self.timestamp_ns = Some(ts);
        self
    }

    /// Sets the work ID.
    #[must_use]
    pub fn work_id(mut self, id: impl Into<String>) -> Self {
        self.work_id = Some(id.into());
        self
    }

    /// Sets the holon ID.
    #[must_use]
    pub fn holon_id(mut self, id: impl Into<String>) -> Self {
        self.holon_id = Some(id.into());
        self
    }

    /// Sets the event type.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // destructors cannot be const
    pub fn event_type(mut self, event_type: EventType) -> Self {
        self.event_type = Some(event_type);
        self
    }

    /// Sets the previous hash (for non-genesis events).
    #[must_use]
    pub const fn previous_hash(mut self, hash: EventHash) -> Self {
        self.previous_hash = Some(hash);
        self
    }

    /// Sets the signature.
    #[must_use]
    pub fn signature(mut self, sig: Vec<u8>) -> Self {
        self.signature = sig;
        self
    }

    /// Builds the `LedgerEvent`.
    ///
    /// # Panics
    ///
    /// Panics if required fields (`event_id`, `work_id`, `holon_id`,
    /// `event_type`) are not set.
    #[must_use]
    pub fn build(self) -> LedgerEvent {
        LedgerEvent {
            id: self.event_id.expect("event_id is required"),
            timestamp_ns: self.timestamp_ns.unwrap_or_else(current_timestamp_ns),
            work_id: self.work_id.expect("work_id is required"),
            holon_id: self.holon_id.expect("holon_id is required"),
            event_type: self.event_type.expect("event_type is required"),
            previous_hash: self.previous_hash.unwrap_or(EventHash::ZERO),
            signature: self.signature,
        }
    }
}

/// Errors that can occur during chain verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainError {
    /// The chain is empty (no events).
    EmptyChain,

    /// The first event is not a genesis event.
    MissingGenesis {
        /// The event ID that should have been genesis.
        event_id: String,
    },

    /// A link in the chain is broken (hash mismatch).
    BrokenLink {
        /// Index of the event with the broken link.
        event_index: usize,
        /// The event ID with the broken link.
        event_id: String,
        /// Expected hash (from previous event).
        expected_hash: EventHash,
        /// Actual hash stored in the event.
        actual_hash: EventHash,
    },

    /// Events are not ordered by timestamp.
    OutOfOrder {
        /// Index of the out-of-order event.
        event_index: usize,
        /// The event ID that is out of order.
        event_id: String,
    },
}

impl fmt::Display for ChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyChain => write!(f, "chain is empty"),
            Self::MissingGenesis { event_id } => {
                write!(f, "first event '{event_id}' is not a genesis event")
            },
            Self::BrokenLink {
                event_index,
                event_id,
                expected_hash,
                actual_hash,
            } => {
                write!(
                    f,
                    "broken link at index {event_index} (event '{event_id}'): \
                     expected hash {expected_hash}, got {actual_hash}"
                )
            },
            Self::OutOfOrder {
                event_index,
                event_id,
            } => {
                write!(
                    f,
                    "event at index {event_index} ('{event_id}') is out of timestamp order"
                )
            },
        }
    }
}

impl std::error::Error for ChainError {}

/// Verifies the integrity of an event chain.
///
/// This function checks that:
/// 1. The chain is not empty
/// 2. The first event is a genesis event (`previous_hash` is zero)
/// 3. Each subsequent event's `previous_hash` matches the hash of the prior
///    event
/// 4. Events are ordered by timestamp (non-decreasing)
///
/// # Arguments
///
/// * `events` - The events to verify, in chain order (oldest first)
///
/// # Returns
///
/// Returns `Ok(())` if the chain is valid, or `Err(ChainError)` describing
/// the first problem found.
///
/// # Errors
///
/// Returns `ChainError::EmptyChain` if the events slice is empty.
/// Returns `ChainError::MissingGenesis` if the first event has a non-zero
/// previous hash. Returns `ChainError::BrokenLink` if any event's
/// `previous_hash` doesn't match. Returns `ChainError::OutOfOrder` if events
/// have decreasing timestamps.
///
/// # Example
///
/// ```rust
/// use apm2_holon::ledger::{EventType, LedgerEvent, verify_chain};
///
/// let genesis = LedgerEvent::builder()
///     .event_id("evt-001")
///     .work_id("work-001")
///     .holon_id("holon-001")
///     .timestamp_ns(1000)
///     .event_type(EventType::WorkCreated {
///         title: "Test".to_string(),
///     })
///     .build();
///
/// let second = LedgerEvent::builder()
///     .event_id("evt-002")
///     .work_id("work-001")
///     .holon_id("holon-001")
///     .timestamp_ns(2000)
///     .event_type(EventType::WorkClaimed {
///         lease_id: "lease-001".to_string(),
///     })
///     .previous_hash(genesis.compute_hash())
///     .build();
///
/// assert!(verify_chain(&[genesis, second]).is_ok());
/// ```
pub fn verify_chain(events: &[LedgerEvent]) -> Result<(), ChainError> {
    if events.is_empty() {
        return Err(ChainError::EmptyChain);
    }

    // Check genesis event
    let genesis = &events[0];
    if !genesis.is_genesis() {
        return Err(ChainError::MissingGenesis {
            event_id: genesis.event_id().to_string(),
        });
    }

    // Verify chain links and ordering
    let mut prev_hash = genesis.compute_hash();
    let mut prev_timestamp = genesis.timestamp_ns();

    for (i, event) in events.iter().enumerate().skip(1) {
        // Check hash chain
        if event.previous_hash != prev_hash {
            return Err(ChainError::BrokenLink {
                event_index: i,
                event_id: event.event_id().to_string(),
                expected_hash: prev_hash,
                actual_hash: event.previous_hash,
            });
        }

        // Check timestamp ordering (allow equal timestamps for concurrent events)
        if event.timestamp_ns() < prev_timestamp {
            return Err(ChainError::OutOfOrder {
                event_index: i,
                event_id: event.event_id().to_string(),
            });
        }

        prev_hash = event.compute_hash();
        prev_timestamp = event.timestamp_ns();
    }

    Ok(())
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

#[cfg(test)]
mod unit_tests {
    use super::*;

    // =========================================================================
    // EventHash Tests
    // =========================================================================

    #[test]
    fn test_event_hash_zero() {
        let zero = EventHash::ZERO;
        assert!(zero.is_zero());
        assert_eq!(zero.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn test_event_hash_from_bytes() {
        let bytes = [1u8; 32];
        let hash = EventHash::from_bytes(bytes);
        assert_eq!(hash.as_bytes(), &bytes);
        assert!(!hash.is_zero());
    }

    #[test]
    fn test_event_hash_to_hex() {
        let bytes = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef,
        ];
        let hash = EventHash::from_bytes(bytes);
        let hex = hash.to_hex();
        assert_eq!(hex.len(), 64);
        assert_eq!(&hex[..16], "0123456789abcdef");
    }

    #[test]
    fn test_event_hash_from_hex() {
        let hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let hash = EventHash::from_hex(hex).unwrap();
        assert_eq!(hash.to_hex(), hex);
    }

    #[test]
    fn test_event_hash_from_hex_invalid_length() {
        let result = EventHash::from_hex("0123");
        assert!(matches!(result, Err(EventHashError::InvalidLength { .. })));
    }

    #[test]
    fn test_event_hash_from_hex_invalid_chars() {
        // 64 characters, but 'g' is not a valid hex digit
        let hex = "0123456789abcdefg123456789abcdef0123456789abcdef0123456789abcdef";
        let result = EventHash::from_hex(hex);
        assert!(matches!(result, Err(EventHashError::InvalidHex)));
    }

    #[test]
    fn test_event_hash_display() {
        let hash = EventHash::from_bytes([0xab; 32]);
        let display = hash.to_string();
        // Should show first 8 and last 8 chars
        assert!(display.contains("..."));
    }

    #[test]
    fn test_event_hash_default() {
        let hash = EventHash::default();
        assert!(hash.is_zero());
    }

    // =========================================================================
    // EventType Tests
    // =========================================================================

    #[test]
    fn test_event_type_names() {
        assert_eq!(
            EventType::WorkCreated {
                title: String::new()
            }
            .type_name(),
            "work_created"
        );
        assert_eq!(
            EventType::WorkClaimed {
                lease_id: String::new()
            }
            .type_name(),
            "work_claimed"
        );
        assert_eq!(
            EventType::EpisodeStarted {
                episode_id: String::new(),
                attempt_number: 0
            }
            .type_name(),
            "episode_started"
        );
        assert_eq!(
            EventType::ArtifactEmitted {
                artifact_id: String::new(),
                artifact_kind: String::new(),
                content_hash: None
            }
            .type_name(),
            "artifact_emitted"
        );
        assert_eq!(
            EventType::LeaseIssued {
                lease_id: String::new(),
                holder_id: String::new(),
                expires_at_ns: 0
            }
            .type_name(),
            "lease_issued"
        );
        assert_eq!(
            EventType::BudgetConsumed {
                resource_type: String::new(),
                amount: 0,
                remaining: 0
            }
            .type_name(),
            "budget_consumed"
        );
    }

    #[test]
    fn test_event_type_categories() {
        let work_event = EventType::WorkCreated {
            title: "Test".into(),
        };
        assert!(work_event.is_work_event());
        assert!(!work_event.is_episode_event());
        assert!(!work_event.is_artifact_event());
        assert!(!work_event.is_lease_event());
        assert!(!work_event.is_resource_event());

        let episode_event = EventType::EpisodeStarted {
            episode_id: "ep-1".into(),
            attempt_number: 1,
        };
        assert!(!episode_event.is_work_event());
        assert!(episode_event.is_episode_event());

        let artifact_event = EventType::ArtifactEmitted {
            artifact_id: "art-1".into(),
            artifact_kind: "code".into(),
            content_hash: None,
        };
        assert!(artifact_event.is_artifact_event());

        let lease_event = EventType::LeaseIssued {
            lease_id: "lease-1".into(),
            holder_id: "holon-1".into(),
            expires_at_ns: 1000,
        };
        assert!(lease_event.is_lease_event());

        let resource_event = EventType::BudgetConsumed {
            resource_type: "tokens".into(),
            amount: 100,
            remaining: 900,
        };
        assert!(resource_event.is_resource_event());
    }

    #[test]
    fn test_event_type_terminal() {
        assert!(
            EventType::WorkCompleted {
                evidence_ids: vec![]
            }
            .is_terminal_work_event()
        );
        assert!(
            EventType::WorkFailed {
                reason: "test".into(),
                recoverable: false
            }
            .is_terminal_work_event()
        );
        assert!(
            EventType::WorkCancelled {
                reason: "test".into()
            }
            .is_terminal_work_event()
        );

        assert!(
            !EventType::WorkCreated {
                title: "test".into()
            }
            .is_terminal_work_event()
        );
        assert!(
            !EventType::WorkProgressed {
                description: "test".into(),
                new_state: WorkLifecycle::InProgress
            }
            .is_terminal_work_event()
        );
    }

    #[test]
    fn test_event_type_serialization() {
        let event = EventType::WorkCreated {
            title: "Test work".into(),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("work_created"));
        assert!(json.contains("Test work"));

        let deserialized: EventType = serde_json::from_str(&json).unwrap();
        assert_eq!(event, deserialized);
    }

    // =========================================================================
    // EpisodeOutcome Tests
    // =========================================================================

    #[test]
    fn test_episode_outcome_as_str() {
        assert_eq!(EpisodeOutcome::Completed.as_str(), "completed");
        assert_eq!(EpisodeOutcome::Continuation.as_str(), "continuation");
        assert_eq!(EpisodeOutcome::Failed.as_str(), "failed");
        assert_eq!(EpisodeOutcome::Interrupted.as_str(), "interrupted");
        assert_eq!(EpisodeOutcome::Escalated.as_str(), "escalated");
    }

    // =========================================================================
    // LedgerEvent Tests
    // =========================================================================

    #[test]
    fn test_ledger_event_builder() {
        let event = LedgerEvent::builder()
            .event_id("evt-001")
            .timestamp_ns(1_000_000_000)
            .work_id("work-001")
            .holon_id("holon-001")
            .event_type(EventType::WorkCreated {
                title: "Test".into(),
            })
            .build();

        assert_eq!(event.event_id(), "evt-001");
        assert_eq!(event.timestamp_ns(), 1_000_000_000);
        assert_eq!(event.work_id(), "work-001");
        assert_eq!(event.holon_id(), "holon-001");
        assert!(event.is_genesis());
        assert!(!event.is_signed());
    }

    #[test]
    fn test_ledger_event_with_previous_hash() {
        let prev_hash = EventHash::from_bytes([1u8; 32]);
        let event = LedgerEvent::builder()
            .event_id("evt-002")
            .work_id("work-001")
            .holon_id("holon-001")
            .event_type(EventType::WorkClaimed {
                lease_id: "lease-1".into(),
            })
            .previous_hash(prev_hash)
            .build();

        assert!(!event.is_genesis());
        assert_eq!(event.previous_hash(), &prev_hash);
    }

    #[test]
    fn test_ledger_event_with_signature() {
        let event = LedgerEvent::builder()
            .event_id("evt-001")
            .work_id("work-001")
            .holon_id("holon-001")
            .event_type(EventType::WorkCreated {
                title: "Test".into(),
            })
            .signature(vec![1, 2, 3, 4])
            .build();

        assert!(event.is_signed());
        assert_eq!(event.signature(), &[1, 2, 3, 4]);
    }

    #[test]
    fn test_ledger_event_canonical_bytes_deterministic() {
        let event1 = LedgerEvent::builder()
            .event_id("evt-001")
            .timestamp_ns(1000)
            .work_id("work-001")
            .holon_id("holon-001")
            .event_type(EventType::WorkCreated {
                title: "Test".into(),
            })
            .build();

        let event2 = LedgerEvent::builder()
            .event_id("evt-001")
            .timestamp_ns(1000)
            .work_id("work-001")
            .holon_id("holon-001")
            .event_type(EventType::WorkCreated {
                title: "Test".into(),
            })
            .build();

        assert_eq!(event1.canonical_bytes(), event2.canonical_bytes());
    }

    #[test]
    fn test_ledger_event_canonical_bytes_excludes_signature() {
        let unsigned = LedgerEvent::builder()
            .event_id("evt-001")
            .timestamp_ns(1000)
            .work_id("work-001")
            .holon_id("holon-001")
            .event_type(EventType::WorkCreated {
                title: "Test".into(),
            })
            .build();

        let signed = LedgerEvent::builder()
            .event_id("evt-001")
            .timestamp_ns(1000)
            .work_id("work-001")
            .holon_id("holon-001")
            .event_type(EventType::WorkCreated {
                title: "Test".into(),
            })
            .signature(vec![1, 2, 3, 4, 5])
            .build();

        // Canonical bytes should be the same regardless of signature
        assert_eq!(unsigned.canonical_bytes(), signed.canonical_bytes());
    }

    #[test]
    fn test_ledger_event_compute_hash_deterministic() {
        let event1 = LedgerEvent::builder()
            .event_id("evt-001")
            .timestamp_ns(1000)
            .work_id("work-001")
            .holon_id("holon-001")
            .event_type(EventType::WorkCreated {
                title: "Test".into(),
            })
            .build();

        let event2 = LedgerEvent::builder()
            .event_id("evt-001")
            .timestamp_ns(1000)
            .work_id("work-001")
            .holon_id("holon-001")
            .event_type(EventType::WorkCreated {
                title: "Test".into(),
            })
            .build();

        assert_eq!(event1.compute_hash(), event2.compute_hash());
    }

    #[test]
    fn test_ledger_event_hash_differs_with_content() {
        let event1 = LedgerEvent::builder()
            .event_id("evt-001")
            .timestamp_ns(1000)
            .work_id("work-001")
            .holon_id("holon-001")
            .event_type(EventType::WorkCreated {
                title: "Test 1".into(),
            })
            .build();

        let event2 = LedgerEvent::builder()
            .event_id("evt-001")
            .timestamp_ns(1000)
            .work_id("work-001")
            .holon_id("holon-001")
            .event_type(EventType::WorkCreated {
                title: "Test 2".into(),
            })
            .build();

        assert_ne!(event1.compute_hash(), event2.compute_hash());
    }

    #[test]
    fn test_ledger_event_verify_previous() {
        let genesis = LedgerEvent::builder()
            .event_id("evt-001")
            .timestamp_ns(1000)
            .work_id("work-001")
            .holon_id("holon-001")
            .event_type(EventType::WorkCreated {
                title: "Test".into(),
            })
            .build();

        let second = LedgerEvent::builder()
            .event_id("evt-002")
            .timestamp_ns(2000)
            .work_id("work-001")
            .holon_id("holon-001")
            .event_type(EventType::WorkClaimed {
                lease_id: "lease-1".into(),
            })
            .previous_hash(genesis.compute_hash())
            .build();

        assert!(second.verify_previous(&genesis));
    }

    #[test]
    fn test_ledger_event_verify_previous_fails_on_mismatch() {
        let genesis = LedgerEvent::builder()
            .event_id("evt-001")
            .timestamp_ns(1000)
            .work_id("work-001")
            .holon_id("holon-001")
            .event_type(EventType::WorkCreated {
                title: "Test".into(),
            })
            .build();

        let wrong_hash = EventHash::from_bytes([99u8; 32]);
        let second = LedgerEvent::builder()
            .event_id("evt-002")
            .timestamp_ns(2000)
            .work_id("work-001")
            .holon_id("holon-001")
            .event_type(EventType::WorkClaimed {
                lease_id: "lease-1".into(),
            })
            .previous_hash(wrong_hash)
            .build();

        assert!(!second.verify_previous(&genesis));
    }

    #[test]
    fn test_ledger_event_serialization() {
        let event = LedgerEvent::builder()
            .event_id("evt-001")
            .timestamp_ns(1000)
            .work_id("work-001")
            .holon_id("holon-001")
            .event_type(EventType::WorkCreated {
                title: "Test".into(),
            })
            .build();

        let json = serde_json::to_string(&event).unwrap();
        let deserialized: LedgerEvent = serde_json::from_str(&json).unwrap();

        assert_eq!(event, deserialized);
    }

    // =========================================================================
    // Chain Verification Tests
    // =========================================================================

    #[test]
    fn test_verify_chain_empty() {
        let result = verify_chain(&[]);
        assert!(matches!(result, Err(ChainError::EmptyChain)));
    }

    #[test]
    fn test_verify_chain_single_genesis() {
        let genesis = LedgerEvent::builder()
            .event_id("evt-001")
            .timestamp_ns(1000)
            .work_id("work-001")
            .holon_id("holon-001")
            .event_type(EventType::WorkCreated {
                title: "Test".into(),
            })
            .build();

        assert!(verify_chain(&[genesis]).is_ok());
    }

    #[test]
    fn test_verify_chain_missing_genesis() {
        let non_genesis = LedgerEvent::builder()
            .event_id("evt-001")
            .timestamp_ns(1000)
            .work_id("work-001")
            .holon_id("holon-001")
            .event_type(EventType::WorkCreated {
                title: "Test".into(),
            })
            .previous_hash(EventHash::from_bytes([1u8; 32]))
            .build();

        let result = verify_chain(&[non_genesis]);
        assert!(matches!(result, Err(ChainError::MissingGenesis { .. })));
    }

    #[test]
    fn test_verify_chain_valid_chain() {
        let genesis = LedgerEvent::builder()
            .event_id("evt-001")
            .timestamp_ns(1000)
            .work_id("work-001")
            .holon_id("holon-001")
            .event_type(EventType::WorkCreated {
                title: "Test".into(),
            })
            .build();

        let second = LedgerEvent::builder()
            .event_id("evt-002")
            .timestamp_ns(2000)
            .work_id("work-001")
            .holon_id("holon-001")
            .event_type(EventType::WorkClaimed {
                lease_id: "lease-1".into(),
            })
            .previous_hash(genesis.compute_hash())
            .build();

        let third = LedgerEvent::builder()
            .event_id("evt-003")
            .timestamp_ns(3000)
            .work_id("work-001")
            .holon_id("holon-001")
            .event_type(EventType::WorkCompleted {
                evidence_ids: vec!["evid-1".into()],
            })
            .previous_hash(second.compute_hash())
            .build();

        assert!(verify_chain(&[genesis, second, third]).is_ok());
    }

    #[test]
    fn test_verify_chain_broken_link() {
        let genesis = LedgerEvent::builder()
            .event_id("evt-001")
            .timestamp_ns(1000)
            .work_id("work-001")
            .holon_id("holon-001")
            .event_type(EventType::WorkCreated {
                title: "Test".into(),
            })
            .build();

        // Wrong previous hash
        let second = LedgerEvent::builder()
            .event_id("evt-002")
            .timestamp_ns(2000)
            .work_id("work-001")
            .holon_id("holon-001")
            .event_type(EventType::WorkClaimed {
                lease_id: "lease-1".into(),
            })
            .previous_hash(EventHash::from_bytes([99u8; 32]))
            .build();

        let result = verify_chain(&[genesis, second]);
        assert!(matches!(
            result,
            Err(ChainError::BrokenLink { event_index: 1, .. })
        ));
    }

    #[test]
    fn test_verify_chain_out_of_order() {
        let genesis = LedgerEvent::builder()
            .event_id("evt-001")
            .timestamp_ns(2000) // Later timestamp
            .work_id("work-001")
            .holon_id("holon-001")
            .event_type(EventType::WorkCreated { title: "Test".into() })
            .build();

        let second = LedgerEvent::builder()
            .event_id("evt-002")
            .timestamp_ns(1000) // Earlier timestamp - out of order!
            .work_id("work-001")
            .holon_id("holon-001")
            .event_type(EventType::WorkClaimed { lease_id: "lease-1".into() })
            .previous_hash(genesis.compute_hash())
            .build();

        let result = verify_chain(&[genesis, second]);
        assert!(matches!(
            result,
            Err(ChainError::OutOfOrder { event_index: 1, .. })
        ));
    }

    #[test]
    fn test_verify_chain_same_timestamp_allowed() {
        // Concurrent events may have the same timestamp
        let genesis = LedgerEvent::builder()
            .event_id("evt-001")
            .timestamp_ns(1000)
            .work_id("work-001")
            .holon_id("holon-001")
            .event_type(EventType::WorkCreated {
                title: "Test".into(),
            })
            .build();

        let second = LedgerEvent::builder()
            .event_id("evt-002")
            .timestamp_ns(1000) // Same timestamp - should be allowed
            .work_id("work-001")
            .holon_id("holon-001")
            .event_type(EventType::WorkClaimed { lease_id: "lease-1".into() })
            .previous_hash(genesis.compute_hash())
            .build();

        assert!(verify_chain(&[genesis, second]).is_ok());
    }

    // =========================================================================
    // Tamper Detection Tests
    // =========================================================================

    #[test]
    fn test_tamper_detection_modified_event() {
        // Build a valid chain
        let genesis = LedgerEvent::builder()
            .event_id("evt-001")
            .timestamp_ns(1000)
            .work_id("work-001")
            .holon_id("holon-001")
            .event_type(EventType::WorkCreated {
                title: "Original".into(),
            })
            .build();

        let second = LedgerEvent::builder()
            .event_id("evt-002")
            .timestamp_ns(2000)
            .work_id("work-001")
            .holon_id("holon-001")
            .event_type(EventType::WorkCompleted {
                evidence_ids: vec![],
            })
            .previous_hash(genesis.compute_hash())
            .build();

        // "Tamper" with the genesis event by creating a modified version
        let tampered_genesis = LedgerEvent::builder()
            .event_id("evt-001")
            .timestamp_ns(1000)
            .work_id("work-001")
            .holon_id("holon-001")
            .event_type(EventType::WorkCreated {
                title: "TAMPERED".into(),
            })
            .build();

        // Chain should fail verification because second.previous_hash
        // doesn't match tampered_genesis.compute_hash()
        let result = verify_chain(&[tampered_genesis, second]);
        assert!(matches!(result, Err(ChainError::BrokenLink { .. })));
    }

    #[test]
    fn test_hash_chain_integrity_long_chain() {
        // Build a longer chain
        let mut events = Vec::new();

        // Genesis
        let genesis = LedgerEvent::builder()
            .event_id("evt-001")
            .timestamp_ns(1000)
            .work_id("work-001")
            .holon_id("holon-001")
            .event_type(EventType::WorkCreated {
                title: "Test".into(),
            })
            .build();
        events.push(genesis);

        // Add 10 more events
        for i in 2_u64..=11 {
            let prev_hash = events.last().unwrap().compute_hash();
            let event = LedgerEvent::builder()
                .event_id(format!("evt-{i:03}"))
                .timestamp_ns(1000 * i)
                .work_id("work-001")
                .holon_id("holon-001")
                .event_type(EventType::WorkProgressed {
                    description: format!("Progress {i}"),
                    new_state: WorkLifecycle::InProgress,
                })
                .previous_hash(prev_hash)
                .build();
            events.push(event);
        }

        // Verify the entire chain
        assert!(verify_chain(&events).is_ok());

        // Verify that modifying any event breaks the chain
        // (We can't easily test this without mutation, but the principle is
        // demonstrated)
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;

    /// Test that hash computation is pure (deterministic).
    #[test]
    fn test_hash_computation_is_pure() {
        let event = LedgerEvent::builder()
            .event_id("evt-001")
            .timestamp_ns(1000)
            .work_id("work-001")
            .holon_id("holon-001")
            .event_type(EventType::WorkCreated {
                title: "Test".into(),
            })
            .build();

        // Compute hash multiple times
        let hash1 = event.compute_hash();
        let hash2 = event.compute_hash();
        let hash3 = event.compute_hash();

        assert_eq!(hash1, hash2);
        assert_eq!(hash2, hash3);
    }

    /// Test that different events produce different hashes.
    #[test]
    fn test_hash_collision_resistance() {
        let events: Vec<LedgerEvent> = (0_u64..100)
            .map(|i| {
                LedgerEvent::builder()
                    .event_id(format!("evt-{i:03}"))
                    .timestamp_ns(1000 + i)
                    .work_id("work-001")
                    .holon_id("holon-001")
                    .event_type(EventType::WorkProgressed {
                        description: format!("Event {i}"),
                        new_state: WorkLifecycle::InProgress,
                    })
                    .build()
            })
            .collect();

        // All hashes should be unique
        let hashes: std::collections::HashSet<_> =
            events.iter().map(LedgerEvent::compute_hash).collect();
        assert_eq!(hashes.len(), events.len());
    }

    /// Test that canonical bytes are valid JSON.
    #[test]
    fn test_canonical_bytes_is_valid_json() {
        let event = LedgerEvent::builder()
            .event_id("evt-001")
            .timestamp_ns(1000)
            .work_id("work-001")
            .holon_id("holon-001")
            .event_type(EventType::WorkCreated {
                title: "Test".into(),
            })
            .build();

        let bytes = event.canonical_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        // Should contain expected fields
        assert!(json.get("id").is_some());
        assert!(json.get("timestamp_ns").is_some());
        assert!(json.get("work_id").is_some());
        assert!(json.get("holon_id").is_some());
        assert!(json.get("event_type").is_some());
        assert!(json.get("previous_hash").is_some());

        // Should NOT contain signature field
        assert!(json.get("signature").is_none());
    }

    /// Test chain verification invariant: valid chain remains valid.
    #[test]
    fn test_valid_chain_stays_valid() {
        let genesis = LedgerEvent::builder()
            .event_id("evt-001")
            .timestamp_ns(1000)
            .work_id("work-001")
            .holon_id("holon-001")
            .event_type(EventType::WorkCreated {
                title: "Test".into(),
            })
            .build();

        let second = LedgerEvent::builder()
            .event_id("evt-002")
            .timestamp_ns(2000)
            .work_id("work-001")
            .holon_id("holon-001")
            .event_type(EventType::WorkClaimed {
                lease_id: "lease-1".into(),
            })
            .previous_hash(genesis.compute_hash())
            .build();

        let chain = vec![genesis, second];

        // Verify multiple times
        for _ in 0..10 {
            assert!(verify_chain(&chain).is_ok());
        }
    }
}
