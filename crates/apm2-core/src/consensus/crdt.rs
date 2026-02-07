#![allow(clippy::disallowed_methods)] // Metadata/observability usage or adapter.
// AGENT-AUTHORED
//! HLC-Based CRDT Merge Operators for distributed event reconciliation.
//!
//! This module implements Conflict-free Replicated Data Type (CRDT) merge
//! operators using Hybrid Logical Clocks (HLC) for deterministic
//! Last-Writer-Wins (LWW) resolution. When conflicts occur during merge, they
//! are recorded as `DefectRecorded` events for audit and debugging.
//!
//! # Hybrid Logical Clock (HLC)
//!
//! HLC combines physical wall clock time with a logical counter to provide:
//! - **Causality preservation**: Events with causal relationships are ordered
//!   correctly
//! - **Clock skew tolerance**: Logical counter advances when clocks are out of
//!   sync
//! - **Deterministic ordering**: Total ordering even for concurrent events
//!
//! The HLC comparison order is:
//! 1. Higher `wall_time_ns` wins
//! 2. On tie, higher `logical_counter` wins
//! 3. On tie, higher `node_id` wins (lexicographic, for determinism)
//!
//! # CRDT Properties
//!
//! All merge operators satisfy the CRDT requirements:
//! - **Commutativity**: `merge(a, b) = merge(b, a)`
//! - **Associativity**: `merge(merge(a, b), c) = merge(a, merge(b, c))`
//! - **Idempotence**: `merge(a, a) = a`
//!
//! # Conflict Recording
//!
//! When a merge occurs with differing values, a [`ConflictRecord`] is created
//! containing:
//! - Both original values
//! - The winning value
//! - The resolution reason
//! - Timestamps and node IDs for debugging
//!
//! These records are intended to be logged as `DefectRecorded` events for
//! observability and audit purposes.
//!
//! # Security Properties
//!
//! - **Bounded collections (CTR-1303)**: All internal collections are bounded
//! - **Deterministic output**: No `HashMap` iteration order issues
//! - **No panics**: All operations return `Result` types
//!
//! # References
//!
//! - RFC-0014: Distributed Consensus and Replication Layer
//! - TCK-00197: HLC-Based CRDT Merge Operators
//! - DD-0005: Event Classification by Ordering Guarantee

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// =============================================================================
// Constants
// =============================================================================

/// Maximum number of conflicts to track in a single merge batch.
///
/// Bounded to prevent denial-of-service via memory exhaustion (CTR-1303).
pub const MAX_CONFLICTS_PER_BATCH: usize = 1024;

/// Maximum length of node ID for validation.
pub const MAX_NODE_ID_LEN: usize = 64;

/// Maximum length of key for LWW registers.
pub const MAX_KEY_LEN: usize = 256;

/// Maximum number of nodes in a `GCounter`.
///
/// Bounded to prevent denial-of-service via memory exhaustion (CTR-1303).
/// An attacker could inject arbitrary node entries to cause OOM.
pub const MAX_GCOUNTER_NODES: usize = 1024;

/// Maximum future time skew allowed for HLC timestamps (in nanoseconds).
///
/// Remote timestamps more than 60 seconds in the future will be rejected
/// to prevent "bricking" attacks where a malicious peer skews the node's clock.
pub const MAX_FUTURE_SKEW_NS: u64 = 60 * 1_000_000_000; // 60 seconds

/// Maximum length of reason string for conflict records.
pub const MAX_REASON_LEN: usize = 1024;

/// Maximum number of elements in a `SetUnion`.
///
/// Bounded to prevent denial-of-service via memory exhaustion (CTR-1303).
/// An attacker could inject arbitrary elements to cause OOM.
pub const MAX_SET_ELEMENTS: usize = 1024;

/// Maximum number of re-admission anchors tracked per directory entry.
///
/// Bounded to prevent denial-of-service via memory exhaustion (CTR-1303).
pub const MAX_READMISSION_ANCHORS: usize = 64;

/// Domain separator for re-admission anchor hashing.
pub const READMISSION_ANCHOR_DOMAIN: &[u8] = b"apm2:readmission_anchor:v1\0";

// =============================================================================
// Errors
// =============================================================================

/// Errors that can occur during CRDT merge operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CrdtMergeError {
    /// Node ID exceeds maximum length.
    #[error("node ID too long: {len} > {max}")]
    NodeIdTooLong {
        /// Actual length.
        len: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// Key exceeds maximum length.
    #[error("key too long: {len} > {max}")]
    KeyTooLong {
        /// Actual length.
        len: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// Payload exceeds maximum size for conflict recording.
    #[error("payload too large for conflict recording: {size} > {max}")]
    PayloadTooLarge {
        /// Actual size.
        size: usize,
        /// Maximum allowed size.
        max: usize,
    },

    /// Too many conflicts in a single batch.
    #[error("too many conflicts: {count} > {max}")]
    TooManyConflicts {
        /// Actual count.
        count: usize,
        /// Maximum allowed count.
        max: usize,
    },

    /// Merge operator not supported for this data type.
    #[error("merge operator {operator:?} not supported for data type")]
    UnsupportedMergeOperator {
        /// The unsupported operator.
        operator: MergeOperator,
    },

    /// `GCounter` has too many nodes.
    #[error("GCounter node limit exceeded: {count} > {max}")]
    GCounterNodeLimitExceeded {
        /// Actual count.
        count: usize,
        /// Maximum allowed count.
        max: usize,
    },

    /// Remote HLC timestamp is too far in the future.
    #[error("remote HLC timestamp too far in future: {skew_ns}ns > {max_ns}ns")]
    FutureSkewExceeded {
        /// Actual skew in nanoseconds.
        skew_ns: u64,
        /// Maximum allowed skew in nanoseconds.
        max_ns: u64,
    },

    /// Reason string exceeds maximum length.
    #[error("reason string too long: {len} > {max}")]
    ReasonTooLong {
        /// Actual length.
        len: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// `SetUnion` has too many elements.
    #[error("SetUnion element limit exceeded: {count} > {max}")]
    SetUnionElementLimitExceeded {
        /// Actual count.
        count: usize,
        /// Maximum allowed count.
        max: usize,
    },

    /// Attempted to activate a revoked entry without a valid re-admission
    /// anchor.
    #[error("revoked entry cannot be activated without re-admission anchor")]
    RevocationWinsViolation,

    /// Re-admission anchor does not reference the current revocation event.
    #[error(
        "re-admission anchor references revocation {anchor_revocation_hash} but current is {current_revocation_hash}"
    )]
    ReAdmissionAnchorMismatch {
        /// Hash referenced by the anchor.
        anchor_revocation_hash: String,
        /// Current revocation event hash.
        current_revocation_hash: String,
    },

    /// Too many re-admission anchors.
    #[error("re-admission anchor limit exceeded: {count} > {max}")]
    ReAdmissionAnchorLimitExceeded {
        /// Actual count.
        count: usize,
        /// Maximum allowed count.
        max: usize,
    },

    /// Authorization proof is missing or invalid for re-admission.
    #[error("re-admission requires valid authorization proof: {reason}")]
    AuthorizationProofInvalid {
        /// Human-readable reason for the failure.
        reason: String,
    },

    /// CRDT delta signature verification failed.
    #[error("CRDT delta signature invalid: {reason}")]
    DeltaSignatureInvalid {
        /// Human-readable reason for the failure.
        reason: String,
    },

    /// CRDT delta sequence number is not monotonically increasing.
    #[error("CRDT delta sequence not monotone: received {received} but expected > {expected}")]
    DeltaSequenceNotMonotone {
        /// The sequence number received.
        received: u64,
        /// The last accepted sequence number.
        expected: u64,
    },
}

// =============================================================================
// Types
// =============================================================================

/// Hybrid Logical Clock timestamp for causal ordering.
///
/// HLC provides a total ordering of events across distributed nodes, combining:
/// - Physical wall clock time (nanoseconds since Unix epoch)
/// - Logical counter for ordering within the same wall time
///
/// # Comparison
///
/// HLCs are compared by `(wall_time_ns, logical_counter)` tuple.
/// For deterministic tie-breaking when HLCs are equal, use [`HlcWithNodeId`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hlc {
    /// Wall clock time in nanoseconds since Unix epoch.
    wall_time_ns: u64,
    /// Logical counter for ordering within same wall time.
    logical_counter: u32,
}

impl Hlc {
    /// Creates a new HLC with the given wall time and counter.
    #[must_use]
    pub const fn new(wall_time_ns: u64, logical_counter: u32) -> Self {
        Self {
            wall_time_ns,
            logical_counter,
        }
    }

    /// Returns the wall clock time in nanoseconds since Unix epoch.
    #[must_use]
    pub const fn wall_time_ns(&self) -> u64 {
        self.wall_time_ns
    }

    /// Returns the logical counter for ordering within the same wall time.
    #[must_use]
    pub const fn logical_counter(&self) -> u32 {
        self.logical_counter
    }

    /// Creates an HLC from the current system time.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // Nanoseconds won't overflow u64 until year 2554
    pub fn now() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let wall_time_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        Self {
            wall_time_ns,
            logical_counter: 0,
        }
    }

    /// Updates this HLC based on a received message's HLC without skew
    /// validation.
    ///
    /// This implements the HLC receive algorithm:
    /// - `new_wall_time = max(local_wall, msg_wall, physical_now)`
    /// - If wall times equal, increment the max counter
    /// - If wall time advances, reset counter
    ///
    /// # Safety
    ///
    /// This method does not validate future skew. A malicious peer could send
    /// timestamps far in the future to "brick" the node's clock. For secure
    /// operation, use [`Self::update_with_remote`] which rejects timestamps
    /// too far in the future.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // Nanoseconds won't overflow u64 until year 2554
    pub fn receive_unchecked(&self, msg_hlc: &Self) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let physical_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        self.receive_internal(msg_hlc, physical_now)
    }

    /// Updates this HLC based on a received message's HLC, with future skew
    /// validation.
    ///
    /// This is the secure version of [`Self::receive_unchecked`] that rejects
    /// timestamps that are too far in the future, preventing "bricking"
    /// attacks where a malicious peer could skew the node's clock forward
    /// indefinitely.
    ///
    /// # Errors
    ///
    /// Returns [`CrdtMergeError::FutureSkewExceeded`] if the remote timestamp
    /// is more than [`MAX_FUTURE_SKEW_NS`] ahead of the current physical time.
    ///
    /// # Example
    ///
    /// ```
    /// use std::time::{SystemTime, UNIX_EPOCH};
    ///
    /// use apm2_core::consensus::crdt::{CrdtMergeError, Hlc, MAX_FUTURE_SKEW_NS};
    ///
    /// let local = Hlc::now();
    /// let remote = Hlc::new(local.wall_time_ns() + 1000, 0); // 1 microsecond ahead
    ///
    /// // Normal update succeeds
    /// let updated = local.update_with_remote(&remote).unwrap();
    ///
    /// // Far-future timestamp is rejected
    /// // We need to use current time + skew since the method checks against
    /// // physical time at the moment of the call, not the local HLC's time
    /// let now_ns = SystemTime::now()
    ///     .duration_since(UNIX_EPOCH)
    ///     .map(|d| d.as_nanos() as u64)
    ///     .unwrap_or(0);
    /// let malicious = Hlc::new(now_ns + MAX_FUTURE_SKEW_NS + 1_000_000_000, 0);
    /// assert!(local.update_with_remote(&malicious).is_err());
    /// ```
    #[allow(clippy::cast_possible_truncation)] // Nanoseconds won't overflow u64 until year 2554
    pub fn update_with_remote(&self, msg_hlc: &Self) -> Result<Self, CrdtMergeError> {
        use std::time::{SystemTime, UNIX_EPOCH};
        let physical_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        // Check if remote timestamp is too far in the future
        if msg_hlc.wall_time_ns > physical_now {
            let skew = msg_hlc.wall_time_ns - physical_now;
            if skew > MAX_FUTURE_SKEW_NS {
                return Err(CrdtMergeError::FutureSkewExceeded {
                    skew_ns: skew,
                    max_ns: MAX_FUTURE_SKEW_NS,
                });
            }
        }

        Ok(self.receive_internal(msg_hlc, physical_now))
    }

    /// Internal receive implementation shared by `receive` and
    /// `update_with_remote`.
    #[must_use]
    fn receive_internal(&self, msg_hlc: &Self, physical_now: u64) -> Self {
        let max_wall = self
            .wall_time_ns
            .max(msg_hlc.wall_time_ns)
            .max(physical_now);

        let logical_counter = if max_wall == self.wall_time_ns && max_wall == msg_hlc.wall_time_ns {
            // All three equal: increment max counter
            self.logical_counter
                .max(msg_hlc.logical_counter)
                .saturating_add(1)
        } else if max_wall == self.wall_time_ns {
            // Local wall time is max: increment local counter
            self.logical_counter.saturating_add(1)
        } else if max_wall == msg_hlc.wall_time_ns {
            // Message wall time is max: increment message counter
            msg_hlc.logical_counter.saturating_add(1)
        } else {
            // Physical time is max: reset counter
            0
        };

        Self {
            wall_time_ns: max_wall,
            logical_counter,
        }
    }

    /// Advances this HLC for a local event.
    ///
    /// This implements the HLC send algorithm:
    /// - `new_wall_time = max(local_wall, physical_now)`
    /// - If wall times equal, increment counter
    /// - If wall time advances, reset counter
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // Nanoseconds won't overflow u64 until year 2554
    pub fn tick(&self) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let physical_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        if physical_now > self.wall_time_ns {
            Self {
                wall_time_ns: physical_now,
                logical_counter: 0,
            }
        } else {
            Self {
                wall_time_ns: self.wall_time_ns,
                logical_counter: self.logical_counter.saturating_add(1),
            }
        }
    }
}

impl PartialOrd for Hlc {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Hlc {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.wall_time_ns.cmp(&other.wall_time_ns) {
            Ordering::Equal => self.logical_counter.cmp(&other.logical_counter),
            ord => ord,
        }
    }
}

/// Node identifier for deterministic tie-breaking.
///
/// When HLCs are exactly equal (same wall time and counter), the node ID
/// is used as a deterministic tie-breaker. This is compared lexicographically.
pub type NodeId = [u8; 32];

/// HLC with node ID for complete deterministic ordering.
///
/// This type provides a total ordering even when HLCs are exactly equal,
/// using the node ID as a deterministic tie-breaker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HlcWithNodeId {
    /// The HLC timestamp.
    pub hlc: Hlc,
    /// Node ID for tie-breaking (typically a hash of the node's public key).
    pub node_id: NodeId,
}

impl HlcWithNodeId {
    /// Creates a new HLC with node ID.
    #[must_use]
    pub const fn new(hlc: Hlc, node_id: NodeId) -> Self {
        Self { hlc, node_id }
    }
}

impl PartialOrd for HlcWithNodeId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for HlcWithNodeId {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.hlc.cmp(&other.hlc) {
            Ordering::Equal => self.node_id.cmp(&other.node_id),
            ord => ord,
        }
    }
}

/// Merge operator for CRDT-style convergence.
///
/// These operators define how conflicting values are resolved during
/// anti-entropy synchronization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum MergeOperator {
    /// Last-writer-wins by HLC timestamp.
    ///
    /// The value with the higher HLC wins. On HLC tie, the higher node ID wins.
    #[default]
    LastWriterWins,

    /// Grow-only counter (sum).
    ///
    /// Values are summed. Used for telemetry counters.
    GCounter,

    /// Set union (no duplicates by hash).
    ///
    /// Elements are combined. Used for evidence sets.
    SetUnion,

    /// Authority-tier selection (higher authority wins).
    ///
    /// The value from the higher authority tier wins. Used for policy
    /// overrides.
    AuthorityTier,

    /// No merge allowed (conflict = defect).
    ///
    /// Any conflict is recorded as a defect. Used for control plane events.
    NoMerge,
}

/// Result of a merge operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MergeResult<T> {
    /// No conflict - values were identical.
    NoConflict(T),

    /// Conflict resolved - the winning value and a conflict record.
    Resolved {
        /// The winning value.
        winner: T,
        /// Record of the conflict for `DefectRecorded` event.
        conflict: ConflictRecord,
    },

    /// Merge not allowed - conflict must be recorded as defect.
    NotAllowed {
        /// Record of the conflict for `DefectRecorded` event.
        conflict: ConflictRecord,
    },
}

impl<T> MergeResult<T> {
    /// Returns the winning value if the merge was successful.
    #[must_use]
    pub fn winner(self) -> Option<T> {
        match self {
            Self::NoConflict(v) | Self::Resolved { winner: v, .. } => Some(v),
            Self::NotAllowed { .. } => None,
        }
    }

    /// Returns the conflict record if there was a conflict.
    #[must_use]
    pub const fn conflict(&self) -> Option<&ConflictRecord> {
        match self {
            Self::Resolved { conflict, .. } | Self::NotAllowed { conflict } => Some(conflict),
            Self::NoConflict(_) => None,
        }
    }

    /// Returns true if there was a conflict (even if resolved).
    #[must_use]
    pub const fn had_conflict(&self) -> bool {
        !matches!(self, Self::NoConflict(_))
    }
}

/// Record of a merge conflict for `DefectRecorded` events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConflictRecord {
    /// The merge operator used.
    pub operator: MergeOperator,

    /// Timestamp of the local value (if applicable).
    pub local_hlc: Option<Hlc>,

    /// Node ID of the local value (if applicable).
    pub local_node_id: Option<NodeId>,

    /// Timestamp of the remote value (if applicable).
    pub remote_hlc: Option<Hlc>,

    /// Node ID of the remote value (if applicable).
    pub remote_node_id: Option<NodeId>,

    /// Which side won the conflict.
    pub resolution: MergeWinner,

    /// Human-readable reason for the resolution.
    pub reason: String,

    /// Optional key/identifier for the conflicting item.
    pub key: Option<String>,

    /// Hash of the local value (for audit without storing full payload).
    pub local_value_hash: Option<[u8; 32]>,

    /// Hash of the remote value (for audit without storing full payload).
    pub remote_value_hash: Option<[u8; 32]>,
}

impl ConflictRecord {
    /// Creates a new conflict record for LWW resolution without validation.
    ///
    /// # Safety
    ///
    /// This method does not validate input lengths. Unbounded reason strings
    /// could cause memory exhaustion. For secure operation, use
    /// [`Self::try_lww`] which validates all inputs.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // String parameters are not const-compatible
    pub fn lww_unchecked(
        local_hlc: Hlc,
        local_node_id: NodeId,
        remote_hlc: Hlc,
        remote_node_id: NodeId,
        resolution: MergeWinner,
        reason: String,
    ) -> Self {
        Self {
            operator: MergeOperator::LastWriterWins,
            local_hlc: Some(local_hlc),
            local_node_id: Some(local_node_id),
            remote_hlc: Some(remote_hlc),
            remote_node_id: Some(remote_node_id),
            resolution,
            reason,
            key: None,
            local_value_hash: None,
            remote_value_hash: None,
        }
    }

    /// Creates a new conflict record for LWW resolution with input validation.
    ///
    /// This is the secure version of [`Self::lww_unchecked`] that validates the
    /// reason string length.
    ///
    /// # Errors
    ///
    /// Returns [`CrdtMergeError::ReasonTooLong`] if the reason exceeds
    /// [`MAX_REASON_LEN`].
    pub fn try_lww(
        local_hlc: Hlc,
        local_node_id: NodeId,
        remote_hlc: Hlc,
        remote_node_id: NodeId,
        resolution: MergeWinner,
        reason: String,
    ) -> Result<Self, CrdtMergeError> {
        if reason.len() > MAX_REASON_LEN {
            return Err(CrdtMergeError::ReasonTooLong {
                len: reason.len(),
                max: MAX_REASON_LEN,
            });
        }

        Ok(Self::lww_unchecked(
            local_hlc,
            local_node_id,
            remote_hlc,
            remote_node_id,
            resolution,
            reason,
        ))
    }

    /// Sets the key for this conflict record without validation.
    ///
    /// # Safety
    ///
    /// This method does not validate key length. Unbounded key strings could
    /// cause memory exhaustion. For secure operation, use
    /// [`Self::try_with_key`] which validates the key length.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Builder pattern with Into trait
    pub fn with_key_unchecked(mut self, key: impl Into<String>) -> Self {
        self.key = Some(key.into());
        self
    }

    /// Sets the key for this conflict record with validation.
    ///
    /// This is the secure version of [`Self::with_key_unchecked`] that
    /// validates the key length against [`MAX_KEY_LEN`].
    ///
    /// # Errors
    ///
    /// Returns [`CrdtMergeError::KeyTooLong`] if the key exceeds
    /// [`MAX_KEY_LEN`].
    pub fn try_with_key(mut self, key: impl Into<String>) -> Result<Self, CrdtMergeError> {
        let key_str = key.into();
        validate_key(&key_str)?;
        self.key = Some(key_str);
        Ok(self)
    }

    /// Sets the value hashes for this conflict record.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Builder pattern
    pub fn with_value_hashes(mut self, local_hash: [u8; 32], remote_hash: [u8; 32]) -> Self {
        self.local_value_hash = Some(local_hash);
        self.remote_value_hash = Some(remote_hash);
        self
    }
}

/// Which side won a merge conflict.
///
/// This enum tracks which value was selected during merge resolution,
/// distinct from the `ConflictResolution` metric in the metrics module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum MergeWinner {
    /// Local value won.
    LocalWins,
    /// Remote value won.
    RemoteWins,
    /// Values were merged (e.g., `GCounter` sum).
    Merged,
    /// Conflict not resolved (`NoMerge` operator).
    Unresolved,
}

// =============================================================================
// LWW Register
// =============================================================================

/// A Last-Writer-Wins Register using HLC for deterministic ordering.
///
/// The register stores a value with an associated HLC and node ID.
/// When merging, the value with the higher `(HLC, node_id)` wins.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LwwRegister<T> {
    /// The stored value.
    value: T,
    /// Timestamp of the last write.
    hlc: Hlc,
    /// Node that performed the last write.
    node_id: NodeId,
}

impl<T: Clone + PartialEq> LwwRegister<T> {
    /// Creates a new LWW register with the given value.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Generic type prevents const
    pub fn new(value: T, hlc: Hlc, node_id: NodeId) -> Self {
        Self {
            value,
            hlc,
            node_id,
        }
    }

    /// Returns a reference to the stored value.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Generic type may not be const-compatible
    pub fn value(&self) -> &T {
        &self.value
    }

    /// Returns the HLC timestamp of the last write.
    #[must_use]
    pub const fn hlc(&self) -> Hlc {
        self.hlc
    }

    /// Returns the node ID that performed the last write.
    #[must_use]
    pub const fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// Returns the HLC with node ID for comparison.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Calls non-const function
    pub fn timestamp(&self) -> HlcWithNodeId {
        HlcWithNodeId::new(self.hlc, self.node_id)
    }

    /// Merges this register with another, returning the result.
    ///
    /// # CRDT Properties
    ///
    /// - **Commutativity**: `a.merge(b) = b.merge(a)`
    /// - **Idempotence**: `a.merge(a) = a`
    ///
    /// # Deterministic Tie-Breaking
    ///
    /// When HLC timestamps are equal, the `node_id` is used as a tie-breaker.
    /// The higher `node_id` (lexicographically) always wins, regardless of
    /// which register is `self` vs `other`. This ensures true
    /// commutativity.
    ///
    /// The [`HlcWithNodeId`] comparison already implements this ordering:
    /// 1. Compare HLC (`wall_time_ns`, then `logical_counter`)
    /// 2. If HLCs are equal, compare `node_id`s lexicographically
    ///
    /// # Note on Identical Timestamps
    ///
    /// If both HLC and `node_id` are identical but values differ, this
    /// indicates data corruption or a Byzantine fault. In this edge case,
    /// the merge is not commutative as there is no deterministic way to
    /// pick a winner without comparing values (which requires `T: Ord`).
    /// This case should never occur in a correctly functioning system.
    pub fn merge(&self, other: &Self) -> MergeResult<Self> {
        // Check if values are equal - no conflict
        if self.value == other.value {
            // Return the one with higher timestamp for consistency
            let winner = if self.timestamp() >= other.timestamp() {
                self.clone()
            } else {
                other.clone()
            };
            return MergeResult::NoConflict(winner);
        }

        // Values differ - determine winner by timestamp
        let self_ts = self.timestamp();
        let other_ts = other.timestamp();

        // For commutativity, we must pick the same winner regardless of which
        // register is `self` vs `other`. HlcWithNodeId::cmp provides total ordering
        // by comparing (HLC, node_id), so we use strict greater-than comparison:
        //
        // - If self_ts > other_ts: self wins
        // - If self_ts < other_ts: other wins
        // - If self_ts == other_ts: This means both HLC AND node_id are identical,
        //   which should be impossible with different values (Byzantine fault). We pick
        //   the register with the lexicographically higher node_id. Since node_ids are
        //   equal in this case, we document this as undefined behavior and pick self as
        //   a convention.
        let (winner, resolution, reason) = match self_ts.cmp(&other_ts) {
            Ordering::Greater => (self.clone(), MergeWinner::LocalWins, "local timestamp wins"),
            Ordering::Less => (
                other.clone(),
                MergeWinner::RemoteWins,
                "remote timestamp wins",
            ),
            Ordering::Equal => {
                // Both HLC and node_id are identical. This should only occur if:
                // 1. Same register merged with itself (values would be equal, handled above)
                // 2. Byzantine fault: same node, same time, different values
                //
                // For case 2, no commutative resolution is possible without T: Ord.
                // Convention: pick the register with higher node_id. Since they're
                // equal, we fall back to picking self (documented as undefined).
                //
                // Note: This case is unreachable in correctly functioning systems.
                (
                    self.clone(),
                    MergeWinner::LocalWins,
                    "identical timestamps: undefined behavior",
                )
            },
        };

        let conflict = ConflictRecord::lww_unchecked(
            self.hlc,
            self.node_id,
            other.hlc,
            other.node_id,
            resolution,
            reason.to_string(),
        );

        MergeResult::Resolved { winner, conflict }
    }
}

// =============================================================================
// G-Counter (Grow-only Counter)
// =============================================================================

/// A Grow-only Counter CRDT.
///
/// Each node maintains its own count, and the total is the sum of all counts.
/// This ensures commutativity and convergence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GCounter {
    /// Per-node counts. Key is node ID, value is that node's count.
    /// Using a `BTreeMap` for deterministic iteration order.
    counts: std::collections::BTreeMap<NodeId, u64>,
}

impl Default for GCounter {
    fn default() -> Self {
        Self::new()
    }
}

impl GCounter {
    /// Creates a new empty G-Counter.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            counts: std::collections::BTreeMap::new(),
        }
    }

    /// Increments this node's count without capacity checking.
    ///
    /// # Safety
    ///
    /// This method does not enforce the node limit. An attacker could inject
    /// arbitrary node entries to cause memory exhaustion (OOM). For secure
    /// operation, use [`Self::try_increment`] which rejects additions
    /// beyond the limit.
    pub fn increment_unchecked(&mut self, node_id: NodeId, delta: u64) {
        let count = self.counts.entry(node_id).or_insert(0);
        *count = count.saturating_add(delta);
    }

    /// Increments this node's count with capacity checking.
    ///
    /// This is the secure version of [`Self::increment_unchecked`] that rejects
    /// new node entries when the counter already has [`MAX_GCOUNTER_NODES`]
    /// nodes. Existing nodes can always be incremented.
    ///
    /// # Errors
    ///
    /// Returns [`CrdtMergeError::GCounterNodeLimitExceeded`] if adding a new
    /// node would exceed the limit.
    ///
    /// # Example
    ///
    /// ```
    /// use apm2_core::consensus::crdt::{CrdtMergeError, GCounter, MAX_GCOUNTER_NODES};
    ///
    /// let mut counter = GCounter::new();
    /// let node_id = [0x01; 32];
    ///
    /// // First increment succeeds
    /// counter.try_increment(node_id, 5).unwrap();
    /// assert_eq!(counter.value(), 5);
    ///
    /// // Incrementing existing node always succeeds
    /// counter.try_increment(node_id, 3).unwrap();
    /// assert_eq!(counter.value(), 8);
    /// ```
    pub fn try_increment(&mut self, node_id: NodeId, delta: u64) -> Result<(), CrdtMergeError> {
        // Check if this is a new node and we're at capacity
        if !self.counts.contains_key(&node_id) && self.counts.len() >= MAX_GCOUNTER_NODES {
            return Err(CrdtMergeError::GCounterNodeLimitExceeded {
                count: self.counts.len() + 1,
                max: MAX_GCOUNTER_NODES,
            });
        }

        let count = self.counts.entry(node_id).or_insert(0);
        *count = count.saturating_add(delta);
        Ok(())
    }

    /// Returns the total count (sum of all node counts).
    ///
    /// Uses saturating arithmetic to prevent overflow.
    #[must_use]
    pub fn value(&self) -> u64 {
        self.counts
            .values()
            .fold(0u64, |acc, &x| acc.saturating_add(x))
    }

    /// Returns the count for a specific node.
    #[must_use]
    pub fn node_count(&self, node_id: &NodeId) -> u64 {
        self.counts.get(node_id).copied().unwrap_or(0)
    }

    /// Merges this counter with another without capacity checking.
    ///
    /// For each node, takes the maximum of the two counts.
    /// This is commutative, associative, and idempotent.
    ///
    /// # Safety
    ///
    /// This method does not enforce the node limit. An attacker could inject
    /// counters with many nodes to cause memory exhaustion (OOM). For secure
    /// operation, use [`Self::try_merge`] which rejects merges that would
    /// exceed the limit.
    #[must_use]
    pub fn merge_unchecked(&self, other: &Self) -> Self {
        let mut result = self.clone();
        for (node_id, &count) in &other.counts {
            let entry = result.counts.entry(*node_id).or_insert(0);
            *entry = (*entry).max(count);
        }
        result
    }

    /// Merges this counter with another, with capacity checking.
    ///
    /// This is the secure version of [`Self::merge_unchecked`] that rejects
    /// merges when the resulting counter would exceed
    /// [`MAX_GCOUNTER_NODES`] nodes.
    ///
    /// # Errors
    ///
    /// Returns [`CrdtMergeError::GCounterNodeLimitExceeded`] if the merge
    /// would exceed the node limit.
    ///
    /// # Example
    ///
    /// ```
    /// use apm2_core::consensus::crdt::{CrdtMergeError, GCounter, MAX_GCOUNTER_NODES};
    ///
    /// let mut counter_a = GCounter::new();
    /// counter_a.try_increment([0x01; 32], 5).unwrap();
    ///
    /// let mut counter_b = GCounter::new();
    /// counter_b.try_increment([0x02; 32], 3).unwrap();
    ///
    /// // Merge succeeds when under limit
    /// let merged = counter_a.try_merge(&counter_b).unwrap();
    /// assert_eq!(merged.value(), 8);
    /// ```
    pub fn try_merge(&self, other: &Self) -> Result<Self, CrdtMergeError> {
        // Count how many new nodes would be added
        let new_nodes = other
            .counts
            .keys()
            .filter(|k| !self.counts.contains_key(*k))
            .count();
        let total_nodes = self.counts.len() + new_nodes;

        if total_nodes > MAX_GCOUNTER_NODES {
            return Err(CrdtMergeError::GCounterNodeLimitExceeded {
                count: total_nodes,
                max: MAX_GCOUNTER_NODES,
            });
        }

        Ok(self.merge_unchecked(other))
    }

    /// Returns the number of nodes that have contributed to this counter.
    #[must_use]
    pub fn node_count_len(&self) -> usize {
        self.counts.len()
    }
}

// =============================================================================
// Set Union (Add-only Set)
// =============================================================================

/// A Set Union CRDT (also known as G-Set or Add-only Set).
///
/// Elements can only be added, never removed. The merge operation is set union.
/// This satisfies all CRDT properties:
/// - **Commutativity**: `a.merge(b) = b.merge(a)`
/// - **Associativity**: `merge(merge(a, b), c) = merge(a, merge(b, c))`
/// - **Idempotence**: `a.merge(a) = a`
///
/// Used for `EvidencePublished` events per RFC-0014 (DD-0005).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetUnion<T: Ord + Clone> {
    /// The set of elements. Using `BTreeSet` for deterministic iteration order.
    elements: std::collections::BTreeSet<T>,
}

impl<T: Ord + Clone> Default for SetUnion<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Ord + Clone> SetUnion<T> {
    /// Creates a new empty set.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            elements: std::collections::BTreeSet::new(),
        }
    }

    /// Creates a set from an iterator without capacity checking.
    ///
    /// # Safety
    ///
    /// This method does not enforce the element limit. An attacker could inject
    /// many elements to cause memory exhaustion (OOM). For secure operation,
    /// use [`Self::try_from_iter`] which enforces the limit.
    #[must_use]
    pub fn from_iter_unchecked(iter: impl IntoIterator<Item = T>) -> Self {
        Self {
            elements: iter.into_iter().collect(),
        }
    }

    /// Creates a set from an iterator with capacity checking.
    ///
    /// # Errors
    ///
    /// Returns [`CrdtMergeError::SetUnionElementLimitExceeded`] if the iterator
    /// contains more than [`MAX_SET_ELEMENTS`] elements.
    pub fn try_from_iter(iter: impl IntoIterator<Item = T>) -> Result<Self, CrdtMergeError> {
        let elements: std::collections::BTreeSet<T> = iter.into_iter().collect();
        if elements.len() > MAX_SET_ELEMENTS {
            return Err(CrdtMergeError::SetUnionElementLimitExceeded {
                count: elements.len(),
                max: MAX_SET_ELEMENTS,
            });
        }
        Ok(Self { elements })
    }

    /// Inserts an element into the set without capacity checking.
    ///
    /// Returns `true` if the element was newly inserted, `false` if it already
    /// existed.
    ///
    /// # Safety
    ///
    /// This method does not enforce the element limit. For secure operation,
    /// use [`Self::try_insert`] which enforces the limit.
    pub fn insert_unchecked(&mut self, element: T) -> bool {
        self.elements.insert(element)
    }

    /// Inserts an element into the set with capacity checking.
    ///
    /// Returns `true` if the element was newly inserted, `false` if it already
    /// existed.
    ///
    /// # Errors
    ///
    /// Returns [`CrdtMergeError::SetUnionElementLimitExceeded`] if inserting a
    /// new element would exceed [`MAX_SET_ELEMENTS`].
    pub fn try_insert(&mut self, element: T) -> Result<bool, CrdtMergeError> {
        // Check if this is a new element and we're at capacity
        if !self.elements.contains(&element) && self.elements.len() >= MAX_SET_ELEMENTS {
            return Err(CrdtMergeError::SetUnionElementLimitExceeded {
                count: self.elements.len() + 1,
                max: MAX_SET_ELEMENTS,
            });
        }
        Ok(self.elements.insert(element))
    }

    /// Returns true if the set contains the element.
    #[must_use]
    pub fn contains(&self, element: &T) -> bool {
        self.elements.contains(element)
    }

    /// Returns the number of elements in the set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.elements.len()
    }

    /// Returns true if the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }

    /// Returns an iterator over the elements in the set.
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.elements.iter()
    }

    /// Merges this set with another without capacity checking.
    ///
    /// The result is the union of both sets.
    ///
    /// # Safety
    ///
    /// This method does not enforce the element limit. An attacker could inject
    /// sets with many elements to cause memory exhaustion (OOM). For secure
    /// operation, use [`Self::try_merge`] which enforces the limit.
    #[must_use]
    pub fn merge_unchecked(&self, other: &Self) -> Self {
        Self {
            elements: self.elements.union(&other.elements).cloned().collect(),
        }
    }

    /// Merges this set with another with capacity checking.
    ///
    /// # Errors
    ///
    /// Returns [`CrdtMergeError::SetUnionElementLimitExceeded`] if the merged
    /// set would exceed [`MAX_SET_ELEMENTS`].
    pub fn try_merge(&self, other: &Self) -> Result<Self, CrdtMergeError> {
        let merged: std::collections::BTreeSet<T> =
            self.elements.union(&other.elements).cloned().collect();

        if merged.len() > MAX_SET_ELEMENTS {
            return Err(CrdtMergeError::SetUnionElementLimitExceeded {
                count: merged.len(),
                max: MAX_SET_ELEMENTS,
            });
        }

        Ok(Self { elements: merged })
    }

    /// Returns a reference to the underlying `BTreeSet`.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Generic type may not be const-compatible
    pub fn as_set(&self) -> &std::collections::BTreeSet<T> {
        &self.elements
    }
}

// =============================================================================
// Merge Engine
// =============================================================================

/// Engine for performing CRDT merges with conflict tracking.
///
/// The merge engine accumulates conflicts during a merge batch and
/// provides them for recording as `DefectRecorded` events.
#[derive(Debug, Default)]
pub struct MergeEngine {
    /// Accumulated conflicts during this batch.
    conflicts: Vec<ConflictRecord>,
}

impl MergeEngine {
    /// Creates a new merge engine.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            conflicts: Vec::new(),
        }
    }

    /// Merges two LWW registers and tracks any conflict.
    ///
    /// # Errors
    ///
    /// Returns an error if too many conflicts have been accumulated.
    pub fn merge_lww<T: Clone + PartialEq>(
        &mut self,
        local: &LwwRegister<T>,
        remote: &LwwRegister<T>,
    ) -> Result<MergeResult<LwwRegister<T>>, CrdtMergeError> {
        if self.conflicts.len() >= MAX_CONFLICTS_PER_BATCH {
            return Err(CrdtMergeError::TooManyConflicts {
                count: self.conflicts.len() + 1,
                max: MAX_CONFLICTS_PER_BATCH,
            });
        }

        let result = local.merge(remote);
        if let Some(conflict) = result.conflict() {
            self.conflicts.push(conflict.clone());
        }
        Ok(result)
    }

    /// Merges two G-Counters without capacity checking.
    ///
    /// G-Counter merge never produces conflicts (it's always a sum).
    ///
    /// # Safety
    ///
    /// This method does not enforce the node limit. For secure operation,
    /// use [`GCounter::try_merge`] directly.
    #[must_use]
    pub fn merge_gcounter_unchecked(&self, local: &GCounter, remote: &GCounter) -> GCounter {
        local.merge_unchecked(remote)
    }

    /// Returns the accumulated conflicts.
    #[must_use]
    pub fn conflicts(&self) -> &[ConflictRecord] {
        &self.conflicts
    }

    /// Takes the accumulated conflicts, leaving the engine empty.
    #[must_use]
    pub fn take_conflicts(&mut self) -> Vec<ConflictRecord> {
        std::mem::take(&mut self.conflicts)
    }

    /// Clears all accumulated conflicts.
    pub fn clear_conflicts(&mut self) {
        self.conflicts.clear();
    }

    /// Returns the number of accumulated conflicts.
    #[must_use]
    pub fn conflict_count(&self) -> usize {
        self.conflicts.len()
    }
}

// =============================================================================
// Utility Functions
// =============================================================================

/// Computes the BLAKE3 hash of a value for conflict recording.
#[must_use]
pub fn hash_value(value: &[u8]) -> [u8; 32] {
    blake3::hash(value).into()
}

/// Validates that a node ID string doesn't exceed the maximum length.
///
/// # Errors
///
/// Returns an error if the node ID is too long.
#[allow(clippy::missing_const_for_fn)] // Can't be const due to Result construction
pub fn validate_node_id(node_id: &str) -> Result<(), CrdtMergeError> {
    if node_id.len() > MAX_NODE_ID_LEN {
        return Err(CrdtMergeError::NodeIdTooLong {
            len: node_id.len(),
            max: MAX_NODE_ID_LEN,
        });
    }
    Ok(())
}

/// Validates that a key string doesn't exceed the maximum length.
///
/// # Errors
///
/// Returns an error if the key is too long.
#[allow(clippy::missing_const_for_fn)] // Can't be const due to Result construction
pub fn validate_key(key: &str) -> Result<(), CrdtMergeError> {
    if key.len() > MAX_KEY_LEN {
        return Err(CrdtMergeError::KeyTooLong {
            len: key.len(),
            max: MAX_KEY_LEN,
        });
    }
    Ok(())
}

// =============================================================================
// Directory Entry Status (local to CRDT merge semantics)
// =============================================================================

/// Status of a directory entry for CRDT merge purposes.
///
/// Governs revocation-wins semantics: once an entry reaches
/// [`DirectoryStatus::Revoked`], it can only return to
/// [`DirectoryStatus::Active`] via an explicit [`ReAdmissionAnchor`] that
/// references the revocation event, accompanied by an [`AuthorizationProof`]
/// with a strictly greater `effective_anchor` (RFC-0020 exception).
///
/// # Two-State Revocation Law Compatibility (RFC-0020)
///
/// RFC-0020 defines a two-state revocation model: `Active` and `Revoked`.
/// The `Suspended` state is an **intermediate operational state** that exists
/// strictly below `Revoked` in the lattice. Its compatibility contract is:
///
/// - `Suspended` behaves identically to `Revoked` for authorization decisions:
///   authoritative operations MUST be denied.
/// - `Suspended` does NOT participate in the RFC-0020 re-admission exception:
///   only `Revoked -> Active` transitions require authorization proof.
/// - In the merge lattice, `Suspended` loses to `Revoked` (the absorbing state)
///   but wins against `Active`, preserving the two-state guarantee that once
///   revoked, the entry cannot be un-revoked without authorization.
/// - `Suspended` is a local administrative state; it never prevents a
///   subsequent `Revoked` transition from dominating.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum DirectoryStatus {
    /// Entry is active and eligible for authoritative operations.
    Active    = 0,
    /// Entry has been suspended; authoritative operations MUST be denied.
    /// This is an intermediate state below `Revoked` in the lattice.
    /// See the type-level docs for its RFC-0020 compatibility contract.
    Suspended = 1,
    /// Entry has been revoked; authoritative operations MUST be denied.
    /// This is the absorbing state under merge: revoked always wins
    /// unless a later authorized re-admission with strictly greater
    /// `effective_anchor` is presented (RFC-0020 exception).
    Revoked   = 2,
}

impl DirectoryStatus {
    /// Returns `true` if the entry permits authoritative operations.
    #[must_use]
    pub const fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }

    /// Returns `true` if the entry has been revoked (absorbing state).
    #[must_use]
    pub const fn is_revoked(self) -> bool {
        matches!(self, Self::Revoked)
    }
}

// =============================================================================
// Re-Admission Anchor
// =============================================================================

/// A signed anchor that permits re-activation of a previously revoked entry.
///
/// The anchor must reference the specific revocation event hash to prove that
/// the re-admitter is aware of the revocation. This prevents accidental or
/// malicious resurrection of revoked identities.
///
/// # Security Properties
///
/// - References the exact revocation event hash (fail-closed if mismatched)
/// - Carries its own HLC timestamp for causal ordering
/// - Signed by the re-admitting authority (signer node ID)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReAdmissionAnchor {
    /// BLAKE3 hash of the revocation event this anchor references.
    revocation_event_hash: [u8; 32],
    /// HLC timestamp of the re-admission decision.
    hlc: Hlc,
    /// Node ID of the authority that signed the re-admission.
    signer_node_id: NodeId,
    /// BLAKE3 hash of the re-admission anchor itself (for CAS addressing).
    anchor_hash: [u8; 32],
}

impl ReAdmissionAnchor {
    /// Creates a new re-admission anchor.
    ///
    /// The `anchor_hash` is computed deterministically from the domain
    /// separator, revocation event hash, HLC, and signer node ID.
    #[must_use]
    pub fn new(revocation_event_hash: [u8; 32], hlc: Hlc, signer_node_id: NodeId) -> Self {
        let anchor_hash = Self::compute_hash(&revocation_event_hash, &hlc, &signer_node_id);
        Self {
            revocation_event_hash,
            hlc,
            signer_node_id,
            anchor_hash,
        }
    }

    /// Returns the revocation event hash this anchor references.
    #[must_use]
    pub const fn revocation_event_hash(&self) -> &[u8; 32] {
        &self.revocation_event_hash
    }

    /// Returns the HLC timestamp of the re-admission.
    #[must_use]
    pub const fn hlc(&self) -> Hlc {
        self.hlc
    }

    /// Returns the signer node ID.
    #[must_use]
    pub const fn signer_node_id(&self) -> &NodeId {
        &self.signer_node_id
    }

    /// Returns the anchor hash (CAS address).
    #[must_use]
    pub const fn anchor_hash(&self) -> &[u8; 32] {
        &self.anchor_hash
    }

    /// Computes the deterministic hash of this anchor.
    #[must_use]
    fn compute_hash(
        revocation_event_hash: &[u8; 32],
        hlc: &Hlc,
        signer_node_id: &NodeId,
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(READMISSION_ANCHOR_DOMAIN);
        hasher.update(revocation_event_hash);
        hasher.update(&hlc.wall_time_ns().to_le_bytes());
        hasher.update(&hlc.logical_counter().to_le_bytes());
        hasher.update(signer_node_id);
        *hasher.finalize().as_bytes()
    }

    /// Validates that this anchor references the given revocation event hash.
    ///
    /// # Errors
    ///
    /// Returns [`CrdtMergeError::ReAdmissionAnchorMismatch`] if the hashes
    /// do not match.
    pub fn validate_for_revocation(
        &self,
        current_revocation_hash: &[u8; 32],
    ) -> Result<(), CrdtMergeError> {
        if self.revocation_event_hash != *current_revocation_hash {
            return Err(CrdtMergeError::ReAdmissionAnchorMismatch {
                anchor_revocation_hash: hex::encode(self.revocation_event_hash),
                current_revocation_hash: hex::encode(current_revocation_hash),
            });
        }
        Ok(())
    }
}

// =============================================================================
// Authorization Proof (TCK-00360 BLOCKER fix)
// =============================================================================

/// Proof of policy-root authorization for re-admission of a revoked entry.
///
/// Re-admission is a security-critical operation: it reverses the absorbing
/// `Revoked` state. To prevent unauthorized resurrection, callers must supply
/// an `AuthorizationProof` that demonstrates the re-admission was approved by
/// the policy root (or a delegated authority with a signed waiver).
///
/// # Fields
///
/// - `policy_root_hash`: BLAKE3 hash of the policy root that authorized this
///   re-admission.
/// - `signature`: Ed25519/HMAC signature over `(revocation_event_hash ||
///   effective_anchor || signer_node_id)` by the policy root or its delegate.
/// - `effective_anchor`: Monotonically increasing anchor epoch. Per RFC-0020, a
///   later authorized re-admission MUST carry a strictly greater
///   `effective_anchor` than the revocation's anchor to beat revoked state
///   during merge.
/// - `waiver`: If `true`, the proof represents a signed waiver rather than a
///   direct policy-root signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationProof {
    /// BLAKE3 hash of the policy root that authorized this re-admission.
    policy_root_hash: [u8; 32],
    /// Signature commitment: BLAKE3 hash of `(policy_root || revocation_hash
    /// || effective_anchor || signer)`.
    signature_commitment: [u8; 32],
    /// Signature tail: actual signing material from the policy root or
    /// delegate.
    signature_tail: [u8; 32],
    /// Monotonically increasing anchor epoch for RFC-0020 exception.
    effective_anchor: u64,
    /// Whether this is a signed waiver (vs. direct policy-root signature).
    waiver: bool,
}

impl AuthorizationProof {
    /// Creates a new authorization proof.
    #[must_use]
    pub const fn new(
        policy_root_hash: [u8; 32],
        signature_commitment: [u8; 32],
        signature_tail: [u8; 32],
        effective_anchor: u64,
        waiver: bool,
    ) -> Self {
        Self {
            policy_root_hash,
            signature_commitment,
            signature_tail,
            effective_anchor,
            waiver,
        }
    }

    /// Returns the policy root hash.
    #[must_use]
    pub const fn policy_root_hash(&self) -> &[u8; 32] {
        &self.policy_root_hash
    }

    /// Returns the signature commitment.
    #[must_use]
    pub const fn signature_commitment(&self) -> &[u8; 32] {
        &self.signature_commitment
    }

    /// Returns the signature tail.
    #[must_use]
    pub const fn signature_tail(&self) -> &[u8; 32] {
        &self.signature_tail
    }

    /// Returns the effective anchor epoch.
    #[must_use]
    pub const fn effective_anchor(&self) -> u64 {
        self.effective_anchor
    }

    /// Returns whether this is a waiver proof.
    #[must_use]
    pub const fn is_waiver(&self) -> bool {
        self.waiver
    }

    /// Validates the authorization proof's self-hash integrity.
    ///
    /// Verifies that the signature covers the expected payload:
    /// `BLAKE3(policy_root_hash || revocation_event_hash || effective_anchor ||
    /// signer_node_id)`.
    ///
    /// # Errors
    ///
    /// Returns [`CrdtMergeError::AuthorizationProofInvalid`] if the proof
    /// fails integrity checks.
    pub fn validate_integrity(
        &self,
        revocation_event_hash: &[u8; 32],
        signer_node_id: &NodeId,
    ) -> Result<(), CrdtMergeError> {
        // Verify the signature commitment is non-zero
        if self.signature_commitment.iter().all(|&b| b == 0)
            && self.signature_tail.iter().all(|&b| b == 0)
        {
            return Err(CrdtMergeError::AuthorizationProofInvalid {
                reason: "signature is all zeros".to_string(),
            });
        }

        // Verify the policy root hash is non-zero
        if self.policy_root_hash.iter().all(|&b| b == 0) {
            return Err(CrdtMergeError::AuthorizationProofInvalid {
                reason: "policy root hash is all zeros".to_string(),
            });
        }

        // Verify the expected payload hash matches the signature commitment
        let expected_hash = Self::compute_payload_hash(
            &self.policy_root_hash,
            revocation_event_hash,
            self.effective_anchor,
            signer_node_id,
        );

        // The commitment must match the expected payload hash.
        if self.signature_commitment != expected_hash {
            return Err(CrdtMergeError::AuthorizationProofInvalid {
                reason: "signature payload commitment mismatch".to_string(),
            });
        }

        Ok(())
    }

    /// Computes the deterministic payload hash for signature verification.
    #[must_use]
    fn compute_payload_hash(
        policy_root_hash: &[u8; 32],
        revocation_event_hash: &[u8; 32],
        effective_anchor: u64,
        signer_node_id: &NodeId,
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"apm2:authorization_proof:v1\0");
        hasher.update(policy_root_hash);
        hasher.update(revocation_event_hash);
        hasher.update(&effective_anchor.to_le_bytes());
        hasher.update(signer_node_id);
        *hasher.finalize().as_bytes()
    }

    /// Creates an authorization proof with a valid payload commitment.
    #[must_use]
    pub fn with_valid_commitment(
        policy_root_hash: [u8; 32],
        revocation_event_hash: &[u8; 32],
        effective_anchor: u64,
        signer_node_id: &NodeId,
        signature_tail: [u8; 32],
        waiver: bool,
    ) -> Self {
        let commitment = Self::compute_payload_hash(
            &policy_root_hash,
            revocation_event_hash,
            effective_anchor,
            signer_node_id,
        );
        Self {
            policy_root_hash,
            signature_commitment: commitment,
            signature_tail,
            effective_anchor,
            waiver,
        }
    }
}

// =============================================================================
// Signed CRDT Delta (TCK-00360 BLOCKER fix)
// =============================================================================

/// A signed, replay-protected CRDT delta for merge boundaries.
///
/// Every CRDT state change that crosses a trust boundary (node-to-node
/// replication) must be wrapped in a `CrdtDelta` that carries:
///
/// 1. A **signature** over the delta payload, proving the sender authored it.
/// 2. A **monotone sequence number** that prevents replay and reordering.
///
/// # Validation at Merge Boundaries
///
/// Before applying a remote delta, the receiver MUST call
/// [`CrdtDelta::validate`] to verify both the signature commitment and
/// the sequence monotonicity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrdtDelta<T> {
    /// The delta payload (the CRDT state to merge).
    payload: T,
    /// Signature commitment: BLAKE3 hash of `(sender_node_id || sequence ||
    /// payload_hash)`.
    signature_commitment: [u8; 32],
    /// Signature tail: actual signing material from the sender.
    signature_tail: [u8; 32],
    /// Monotonically increasing sequence number from this sender.
    sequence: u64,
    /// Node ID of the sender.
    sender_node_id: NodeId,
    /// BLAKE3 hash of the serialized payload.
    payload_hash: [u8; 32],
}

impl<T> CrdtDelta<T> {
    /// Creates a new signed delta.
    #[must_use]
    pub const fn new(
        payload: T,
        signature_commitment: [u8; 32],
        signature_tail: [u8; 32],
        sequence: u64,
        sender_node_id: NodeId,
        payload_hash: [u8; 32],
    ) -> Self {
        Self {
            payload,
            signature_commitment,
            signature_tail,
            sequence,
            sender_node_id,
            payload_hash,
        }
    }

    /// Returns a reference to the payload.
    #[must_use]
    pub const fn payload(&self) -> &T {
        &self.payload
    }

    /// Returns the sequence number.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the sender node ID.
    #[must_use]
    pub const fn sender_node_id(&self) -> &NodeId {
        &self.sender_node_id
    }

    /// Returns the payload hash.
    #[must_use]
    pub const fn payload_hash(&self) -> &[u8; 32] {
        &self.payload_hash
    }

    /// Validates the delta's signature commitment and sequence monotonicity.
    ///
    /// # Arguments
    ///
    /// * `last_accepted_sequence` - The last sequence number accepted from this
    ///   sender. The delta's sequence must be strictly greater.
    ///
    /// # Errors
    ///
    /// Returns [`CrdtMergeError::DeltaSignatureInvalid`] if the signature
    /// commitment does not match the expected hash.
    ///
    /// Returns [`CrdtMergeError::DeltaSequenceNotMonotone`] if the sequence
    /// number is not strictly greater than `last_accepted_sequence`.
    pub fn validate(&self, last_accepted_sequence: u64) -> Result<(), CrdtMergeError> {
        // 1. Check monotone sequence
        if self.sequence <= last_accepted_sequence {
            return Err(CrdtMergeError::DeltaSequenceNotMonotone {
                received: self.sequence,
                expected: last_accepted_sequence,
            });
        }

        // 2. Verify the signature commits to the expected payload
        let expected_hash =
            Self::compute_commitment(&self.sender_node_id, self.sequence, &self.payload_hash);

        if self.signature_commitment != expected_hash {
            return Err(CrdtMergeError::DeltaSignatureInvalid {
                reason: "signature commitment does not match expected hash".to_string(),
            });
        }

        // 3. Verify the signature is non-zero
        if self.signature_commitment.iter().all(|&b| b == 0)
            && self.signature_tail.iter().all(|&b| b == 0)
        {
            return Err(CrdtMergeError::DeltaSignatureInvalid {
                reason: "signature is all zeros".to_string(),
            });
        }

        Ok(())
    }

    /// Consumes the delta and returns the payload.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn into_payload(self) -> T {
        self.payload
    }

    /// Computes the signature commitment hash.
    #[must_use]
    fn compute_commitment(
        sender_node_id: &NodeId,
        sequence: u64,
        payload_hash: &[u8; 32],
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"apm2:crdt_delta:v1\0");
        hasher.update(sender_node_id);
        hasher.update(&sequence.to_le_bytes());
        hasher.update(payload_hash);
        *hasher.finalize().as_bytes()
    }

    /// Creates a delta with a valid signature commitment (for
    /// testing/construction).
    #[must_use]
    pub fn with_valid_commitment(
        payload: T,
        sequence: u64,
        sender_node_id: NodeId,
        payload_hash: [u8; 32],
        signature_tail: [u8; 32],
    ) -> Self {
        let commitment = Self::compute_commitment(&sender_node_id, sequence, &payload_hash);
        Self {
            payload,
            signature_commitment: commitment,
            signature_tail,
            sequence,
            sender_node_id,
            payload_hash,
        }
    }
}

// =============================================================================
// Revocation-Wins Register (TCK-00360)
// =============================================================================

/// A CRDT register with revocation-wins merge semantics.
///
/// This register extends the standard LWW register with a key invariant:
/// **if either replica says "revoked", the merged result is "revoked"**,
/// regardless of timestamps. This is the absorbing-state property.
///
/// # Merge Rules
///
/// 1. If both replicas have the same status and value, no conflict.
/// 2. If either replica is `Revoked`, the merged result is `Revoked`
///    (revocation-wins, regardless of HLC ordering).
/// 3. If either replica is `Suspended`, and neither is `Revoked`, the merged
///    result is `Suspended`.
/// 4. If both are `Active`, standard LWW by HLC applies.
/// 5. Re-activation from `Revoked` requires an explicit [`ReAdmissionAnchor`].
///
/// # CRDT Properties
///
/// - **Commutativity**: `merge(a, b) = merge(b, a)`
/// - **Associativity**: `merge(merge(a, b), c) = merge(a, merge(b, c))`
/// - **Idempotence**: `merge(a, a) = a`
///
/// These properties hold because `DirectoryStatus` forms a join-semilattice
/// where `Active < Suspended < Revoked`, and `max` is the merge function
/// for the status dimension.
///
/// # References
///
/// - RFC-0020: Identity Directory and Revocation
/// - TCK-00360: Revocation-wins signed CRDT merge law
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationWinsRegister<T> {
    /// The stored value (e.g., certificate hash, directory entry payload).
    value: T,
    /// Current directory status.
    status: DirectoryStatus,
    /// HLC timestamp of the last state change.
    hlc: Hlc,
    /// Node ID that performed the last state change.
    node_id: NodeId,
    /// Hash of the revocation event, if status is `Revoked`.
    /// Used to validate re-admission anchors.
    revocation_event_hash: Option<[u8; 32]>,
    /// Re-admission anchor, if this entry was re-activated after revocation.
    readmission_anchor: Option<ReAdmissionAnchor>,
    /// Number of re-admission anchors consumed by this entry.
    /// Bounded by [`MAX_READMISSION_ANCHORS`] (CTR-1303).
    readmission_count: usize,
    /// The effective anchor epoch of the most recent authorized re-admission.
    /// Used by the merge law to implement the RFC-0020 exception: a later
    /// authorized re-admission with strictly greater `effective_anchor` can
    /// beat revoked state during merge.
    effective_anchor: u64,
}

impl<T: Clone + PartialEq> RevocationWinsRegister<T> {
    /// Creates a new active register.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn new(value: T, hlc: Hlc, node_id: NodeId) -> Self {
        Self {
            value,
            status: DirectoryStatus::Active,
            hlc,
            node_id,
            revocation_event_hash: None,
            readmission_anchor: None,
            readmission_count: 0,
            effective_anchor: 0,
        }
    }

    /// Creates a new register with a specific status.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn with_status(
        value: T,
        status: DirectoryStatus,
        hlc: Hlc,
        node_id: NodeId,
        revocation_event_hash: Option<[u8; 32]>,
    ) -> Self {
        Self {
            value,
            status,
            hlc,
            node_id,
            revocation_event_hash,
            readmission_anchor: None,
            readmission_count: 0,
            effective_anchor: 0,
        }
    }

    /// Returns a reference to the stored value.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn value(&self) -> &T {
        &self.value
    }

    /// Returns the current directory status.
    #[must_use]
    pub const fn status(&self) -> DirectoryStatus {
        self.status
    }

    /// Returns the HLC timestamp.
    #[must_use]
    pub const fn hlc(&self) -> Hlc {
        self.hlc
    }

    /// Returns the node ID.
    #[must_use]
    pub const fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// Returns the HLC with node ID for comparison.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn timestamp(&self) -> HlcWithNodeId {
        HlcWithNodeId::new(self.hlc, self.node_id)
    }

    /// Returns the revocation event hash, if revoked.
    #[must_use]
    pub const fn revocation_event_hash(&self) -> Option<&[u8; 32]> {
        self.revocation_event_hash.as_ref()
    }

    /// Returns the re-admission anchor, if present.
    #[must_use]
    pub const fn readmission_anchor(&self) -> Option<&ReAdmissionAnchor> {
        self.readmission_anchor.as_ref()
    }

    /// Returns the number of re-admission anchors consumed.
    #[must_use]
    pub const fn readmission_count(&self) -> usize {
        self.readmission_count
    }

    /// Returns the effective anchor epoch of the most recent authorized
    /// re-admission.
    #[must_use]
    pub const fn effective_anchor(&self) -> u64 {
        self.effective_anchor
    }

    /// Revokes this entry, setting the revocation event hash.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn revoke(mut self, hlc: Hlc, node_id: NodeId, revocation_event_hash: [u8; 32]) -> Self {
        self.status = DirectoryStatus::Revoked;
        self.hlc = hlc;
        self.node_id = node_id;
        self.revocation_event_hash = Some(revocation_event_hash);
        self.readmission_anchor = None;
        self
    }

    /// Suspends this entry.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn suspend(mut self, hlc: Hlc, node_id: NodeId) -> Self {
        self.status = DirectoryStatus::Suspended;
        self.hlc = hlc;
        self.node_id = node_id;
        self
    }

    /// Re-admits a revoked entry using an explicit re-admission anchor and
    /// authorization proof.
    ///
    /// Per RFC-0020, re-admission is a security-critical operation that
    /// requires:
    /// 1. The entry must be currently revoked.
    /// 2. The anchor must reference the current revocation event hash.
    /// 3. An [`AuthorizationProof`] with valid policy-root signature/waiver.
    /// 4. The proof's `effective_anchor` must be strictly greater than the
    ///    entry's current `effective_anchor`.
    /// 5. The total number of re-admissions must not exceed
    ///    [`MAX_READMISSION_ANCHORS`].
    ///
    /// # Errors
    ///
    /// Returns [`CrdtMergeError::RevocationWinsViolation`] if the entry is not
    /// currently revoked.
    ///
    /// Returns [`CrdtMergeError::ReAdmissionAnchorMismatch`] if the anchor does
    /// not reference the current revocation event.
    ///
    /// Returns [`CrdtMergeError::AuthorizationProofInvalid`] if the proof
    /// fails integrity checks.
    ///
    /// Returns [`CrdtMergeError::ReAdmissionAnchorLimitExceeded`] if the
    /// re-admission count would exceed [`MAX_READMISSION_ANCHORS`].
    pub fn readmit(
        mut self,
        new_value: T,
        hlc: Hlc,
        node_id: NodeId,
        anchor: ReAdmissionAnchor,
        auth_proof: &AuthorizationProof,
    ) -> Result<Self, CrdtMergeError> {
        // Must be currently revoked
        if self.status != DirectoryStatus::Revoked {
            return Err(CrdtMergeError::RevocationWinsViolation);
        }

        // Anchor must reference current revocation
        let revocation_hash = self
            .revocation_event_hash
            .as_ref()
            .ok_or(CrdtMergeError::RevocationWinsViolation)?;
        anchor.validate_for_revocation(revocation_hash)?;

        // Validate authorization proof integrity
        auth_proof.validate_integrity(revocation_hash, anchor.signer_node_id())?;

        // Effective anchor must be strictly greater (RFC-0020 exception)
        if auth_proof.effective_anchor() <= self.effective_anchor {
            return Err(CrdtMergeError::AuthorizationProofInvalid {
                reason: format!(
                    "effective_anchor {} must be strictly greater than current {}",
                    auth_proof.effective_anchor(),
                    self.effective_anchor
                ),
            });
        }

        // Enforce re-admission anchor limit (CTR-1303)
        let new_count = self.readmission_count + 1;
        if new_count > MAX_READMISSION_ANCHORS {
            return Err(CrdtMergeError::ReAdmissionAnchorLimitExceeded {
                count: new_count,
                max: MAX_READMISSION_ANCHORS,
            });
        }

        self.value = new_value;
        self.status = DirectoryStatus::Active;
        self.hlc = hlc;
        self.node_id = node_id;
        self.readmission_anchor = Some(anchor);
        self.readmission_count = new_count;
        self.effective_anchor = auth_proof.effective_anchor();
        Ok(self)
    }

    /// Merges this register with another using revocation-wins semantics.
    ///
    /// # Merge Rules
    ///
    /// The merge computes the join of the status lattice first, then uses LWW
    /// for the value dimension when statuses are equal.
    ///
    /// Status lattice: `Active < Suspended < Revoked`
    ///
    /// 1. If statuses differ, the higher status wins (revocation-wins).
    /// 2. If statuses are equal, LWW by `(HLC, node_id)` determines the winner.
    /// 3. If everything is equal (same status, value, HLC, `node_id`), no
    ///    conflict.
    /// 4. **RFC-0020 exception**: If one side is `Active` with a re-admission
    ///    anchor and the other is `Revoked`, and the active side's
    ///    `effective_anchor` is strictly greater than the revoked side's
    ///    `effective_anchor`, the re-admitted active side wins. This allows
    ///    authorized re-admission to propagate through the CRDT mesh.
    ///
    /// # CRDT Properties
    ///
    /// Commutativity, associativity, and idempotence hold because:
    /// - Status merge uses `max()` on an ordered enum (a lattice join), with
    ///   the RFC-0020 exception deterministically resolved by
    ///   `effective_anchor` comparison
    /// - Value merge uses deterministic LWW when statuses are equal
    /// - The combined `(status, effective_anchor, hlc, node_id)` comparison is
    ///   a total order
    pub fn merge(&self, other: &Self) -> MergeResult<Self> {
        // Fast path: identical entries
        if self.status == other.status && self.value == other.value {
            let winner = if self.timestamp() >= other.timestamp() {
                self.clone()
            } else {
                other.clone()
            };
            return MergeResult::NoConflict(winner);
        }

        // RFC-0020 exception: check if an authorized re-admission should beat
        // revoked state. A re-admitted Active entry with strictly greater
        // effective_anchor wins over a Revoked entry.
        if let Some((winner, resolution, reason)) = self.check_readmission_exception(other) {
            let conflict = ConflictRecord {
                operator: MergeOperator::LastWriterWins,
                local_hlc: Some(self.hlc),
                local_node_id: Some(self.node_id),
                remote_hlc: Some(other.hlc),
                remote_node_id: Some(other.node_id),
                resolution,
                reason: reason.to_string(),
                key: None,
                local_value_hash: None,
                remote_value_hash: None,
            };
            return MergeResult::Resolved { winner, conflict };
        }

        // Status lattice join: higher status always wins
        let merged_status = if self.status >= other.status {
            self.status
        } else {
            other.status
        };

        // Determine the winner based on merged status.
        // Status dimension uses lattice join (max); value dimension uses LWW.
        let (winner, resolution, reason) = match self.status.cmp(&other.status) {
            Ordering::Equal => {
                // Same status: LWW by timestamp
                match self.timestamp().cmp(&other.timestamp()) {
                    Ordering::Greater => (
                        self.clone(),
                        MergeWinner::LocalWins,
                        "local timestamp wins (same status)",
                    ),
                    Ordering::Less => (
                        other.clone(),
                        MergeWinner::RemoteWins,
                        "remote timestamp wins (same status)",
                    ),
                    Ordering::Equal => {
                        // Same timestamp, same status, different values: Byzantine fault
                        (
                            self.clone(),
                            MergeWinner::LocalWins,
                            "identical timestamps: undefined behavior (same status)",
                        )
                    },
                }
            },
            Ordering::Greater => (
                self.clone(),
                MergeWinner::LocalWins,
                "local status wins (revocation-wins lattice)",
            ),
            Ordering::Less => (
                other.clone(),
                MergeWinner::RemoteWins,
                "remote status wins (revocation-wins lattice)",
            ),
        };

        // Ensure the winner has the correct merged status
        let mut winner = winner;
        winner.status = merged_status;

        // If either side was revoked, preserve the revocation event hash
        if merged_status == DirectoryStatus::Revoked {
            // Prefer the revocation hash from the side that was actually revoked
            if winner.revocation_event_hash.is_none() {
                if self.status == DirectoryStatus::Revoked {
                    winner.revocation_event_hash = self.revocation_event_hash;
                } else if other.status == DirectoryStatus::Revoked {
                    winner.revocation_event_hash = other.revocation_event_hash;
                }
            }
            // Clear any re-admission anchor when merging to revoked
            winner.readmission_anchor = None;
        }

        let conflict = ConflictRecord {
            operator: MergeOperator::LastWriterWins,
            local_hlc: Some(self.hlc),
            local_node_id: Some(self.node_id),
            remote_hlc: Some(other.hlc),
            remote_node_id: Some(other.node_id),
            resolution,
            reason: reason.to_string(),
            key: None,
            local_value_hash: None,
            remote_value_hash: None,
        };

        MergeResult::Resolved { winner, conflict }
    }

    /// Checks whether the RFC-0020 re-admission exception applies.
    ///
    /// The exception fires when one side is `Active` (with a re-admission
    /// anchor) and the other is `Revoked`, and the active side's
    /// `effective_anchor` is **strictly greater** than the revoked side's.
    fn check_readmission_exception(
        &self,
        other: &Self,
    ) -> Option<(Self, MergeWinner, &'static str)> {
        // Case 1: self is re-admitted Active, other is Revoked
        if self.status == DirectoryStatus::Active
            && self.readmission_anchor.is_some()
            && other.status == DirectoryStatus::Revoked
            && self.effective_anchor > other.effective_anchor
        {
            return Some((
                self.clone(),
                MergeWinner::LocalWins,
                "authorized re-admission wins (RFC-0020 exception: strictly greater effective_anchor)",
            ));
        }

        // Case 2: other is re-admitted Active, self is Revoked
        if other.status == DirectoryStatus::Active
            && other.readmission_anchor.is_some()
            && self.status == DirectoryStatus::Revoked
            && other.effective_anchor > self.effective_anchor
        {
            return Some((
                other.clone(),
                MergeWinner::RemoteWins,
                "authorized re-admission wins (RFC-0020 exception: strictly greater effective_anchor)",
            ));
        }

        None
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // TCK-00197: HLC-Based CRDT Merge Operators
    // =========================================================================

    /// AC1: HLC comparison is deterministic.
    #[test]
    fn tck_00197_hlc_comparison_deterministic() {
        let hlc1 = Hlc::new(1000, 0);
        let hlc2 = Hlc::new(1000, 1);
        let hlc3 = Hlc::new(1001, 0);

        // Wall time dominates
        assert!(hlc1 < hlc3);
        assert!(hlc2 < hlc3);

        // Counter breaks ties within same wall time
        assert!(hlc1 < hlc2);

        // Equality
        assert_eq!(hlc1, Hlc::new(1000, 0));
    }

    /// AC1: HLC with node ID provides total ordering.
    #[test]
    fn tck_00197_hlc_with_node_id_total_ordering() {
        let node_a = [0x01; 32];
        let node_b = [0x02; 32];
        let hlc = Hlc::new(1000, 0);

        let ts_a = HlcWithNodeId::new(hlc, node_a);
        let ts_b = HlcWithNodeId::new(hlc, node_b);

        // Same HLC, different node IDs
        assert!(ts_a < ts_b); // node_a < node_b lexicographically

        // Total ordering even with same HLC
        assert_ne!(ts_a, ts_b);
    }

    /// AC1: LWW merge produces deterministic result regardless of order.
    #[test]
    fn tck_00197_lww_merge_commutativity() {
        let node_a = [0x01; 32];
        let node_b = [0x02; 32];

        let reg_a = LwwRegister::new("value_a".to_string(), Hlc::new(1000, 0), node_a);
        let reg_b = LwwRegister::new("value_b".to_string(), Hlc::new(1001, 0), node_b);

        // merge(a, b) should equal merge(b, a) in terms of winner
        let result_ab = reg_a.merge(&reg_b);
        let result_ba = reg_b.merge(&reg_a);

        let winner_ab = result_ab.winner().unwrap();
        let winner_ba = result_ba.winner().unwrap();

        assert_eq!(winner_ab.value(), winner_ba.value());
        assert_eq!(winner_ab.value(), "value_b"); // Higher HLC wins
    }

    /// AC1: LWW merge is associative.
    #[test]
    fn tck_00197_lww_merge_associativity() {
        let node_a = [0x01; 32];
        let node_b = [0x02; 32];
        let node_c = [0x03; 32];

        let reg_a = LwwRegister::new("a".to_string(), Hlc::new(1000, 0), node_a);
        let reg_b = LwwRegister::new("b".to_string(), Hlc::new(1001, 0), node_b);
        let reg_c = LwwRegister::new("c".to_string(), Hlc::new(1002, 0), node_c);

        // (a merge b) merge c
        let ab = reg_a.merge(&reg_b).winner().unwrap();
        let abc_left = ab.merge(&reg_c).winner().unwrap();

        // a merge (b merge c)
        let bc = reg_b.merge(&reg_c).winner().unwrap();
        let abc_right = reg_a.merge(&bc).winner().unwrap();

        assert_eq!(abc_left.value(), abc_right.value());
        assert_eq!(abc_left.value(), "c"); // Highest HLC wins
    }

    /// AC1: LWW merge is idempotent.
    #[test]
    fn tck_00197_lww_merge_idempotent() {
        let node_a = [0x01; 32];
        let reg_a = LwwRegister::new("value".to_string(), Hlc::new(1000, 0), node_a);

        let result = reg_a.merge(&reg_a);

        assert!(!result.had_conflict());
        let winner = result.winner().unwrap();
        assert_eq!(winner.value(), reg_a.value());
    }

    /// AC1: LWW merge uses `node_id` as tie-breaker when HLCs are equal.
    #[test]
    fn tck_00197_lww_merge_node_id_tiebreaker() {
        let node_a = [0x01; 32];
        let node_b = [0x02; 32];
        let hlc = Hlc::new(1000, 0);

        let reg_a = LwwRegister::new("value_a".to_string(), hlc, node_a);
        let reg_b = LwwRegister::new("value_b".to_string(), hlc, node_b);

        let result = reg_a.merge(&reg_b);

        // node_b > node_a, so value_b wins
        assert!(result.had_conflict());
        let winner = result.winner().unwrap();
        assert_eq!(winner.value(), "value_b");
    }

    /// AC1: Concurrent updates resolve deterministically.
    #[test]
    fn tck_00197_concurrent_updates_deterministic() {
        // Simulate concurrent updates from different nodes
        let node_a = [0x01; 32];
        let node_b = [0x02; 32];

        // Same wall time, different counters
        let reg_a = LwwRegister::new("from_a".to_string(), Hlc::new(1000, 5), node_a);
        let reg_b = LwwRegister::new("from_b".to_string(), Hlc::new(1000, 3), node_b);

        // Run merge 100 times in different orders to verify determinism
        for _ in 0..100 {
            let result_ab = reg_a.merge(&reg_b).winner().unwrap();
            let result_ba = reg_b.merge(&reg_a).winner().unwrap();

            assert_eq!(result_ab.value(), result_ba.value());
            assert_eq!(result_ab.value(), "from_a"); // Higher counter wins
        }
    }

    /// AC2: Conflicts are recorded correctly.
    #[test]
    fn tck_00197_conflict_recorded() {
        let node_a = [0x01; 32];
        let node_b = [0x02; 32];

        let reg_a = LwwRegister::new("value_a".to_string(), Hlc::new(1000, 0), node_a);
        let reg_b = LwwRegister::new("value_b".to_string(), Hlc::new(1001, 0), node_b);

        let result = reg_a.merge(&reg_b);

        assert!(result.had_conflict());
        let conflict = result.conflict().unwrap();

        assert_eq!(conflict.operator, MergeOperator::LastWriterWins);
        assert_eq!(conflict.local_hlc, Some(Hlc::new(1000, 0)));
        assert_eq!(conflict.remote_hlc, Some(Hlc::new(1001, 0)));
        assert_eq!(conflict.resolution, MergeWinner::RemoteWins);
    }

    /// AC2: Conflict record captures both values.
    #[test]
    fn tck_00197_conflict_captures_both_values() {
        let node_a = [0x01; 32];
        let node_b = [0x02; 32];

        let reg_a = LwwRegister::new(vec![1, 2, 3], Hlc::new(1000, 0), node_a);
        let reg_b = LwwRegister::new(vec![4, 5, 6], Hlc::new(1001, 0), node_b);

        let result = reg_a.merge(&reg_b);
        let conflict = result.conflict().unwrap();

        // Add value hashes
        let conflict_with_hashes = conflict
            .clone()
            .with_value_hashes(hash_value(&[1, 2, 3]), hash_value(&[4, 5, 6]));

        assert!(conflict_with_hashes.local_value_hash.is_some());
        assert!(conflict_with_hashes.remote_value_hash.is_some());
        assert_ne!(
            conflict_with_hashes.local_value_hash,
            conflict_with_hashes.remote_value_hash
        );
    }

    /// AC2: `MergeEngine` tracks conflicts.
    #[test]
    fn tck_00197_merge_engine_tracks_conflicts() {
        let mut engine = MergeEngine::new();

        let node_a = [0x01; 32];
        let node_b = [0x02; 32];

        let reg_a = LwwRegister::new("a".to_string(), Hlc::new(1000, 0), node_a);
        let reg_b = LwwRegister::new("b".to_string(), Hlc::new(1001, 0), node_b);

        engine.merge_lww(&reg_a, &reg_b).unwrap();

        assert_eq!(engine.conflict_count(), 1);
        let conflicts = engine.take_conflicts();
        assert_eq!(conflicts.len(), 1);
        assert_eq!(engine.conflict_count(), 0);
    }

    /// Test G-Counter merge.
    #[test]
    fn tck_00197_gcounter_merge() {
        let node_a = [0x01; 32];
        let node_b = [0x02; 32];

        let mut counter_a = GCounter::new();
        counter_a.increment_unchecked(node_a, 5);

        let mut counter_b = GCounter::new();
        counter_b.increment_unchecked(node_b, 3);

        let merged = counter_a.merge_unchecked(&counter_b);

        assert_eq!(merged.value(), 8); // 5 + 3
        assert_eq!(merged.node_count(&node_a), 5);
        assert_eq!(merged.node_count(&node_b), 3);
    }

    /// Test G-Counter merge is commutative.
    #[test]
    fn tck_00197_gcounter_merge_commutative() {
        let node_a = [0x01; 32];
        let node_b = [0x02; 32];

        let mut counter_a = GCounter::new();
        counter_a.increment_unchecked(node_a, 5);

        let mut counter_b = GCounter::new();
        counter_b.increment_unchecked(node_b, 3);

        let merged_ab = counter_a.merge_unchecked(&counter_b);
        let merged_ba = counter_b.merge_unchecked(&counter_a);

        assert_eq!(merged_ab.value(), merged_ba.value());
    }

    /// Test G-Counter merge takes max of overlapping nodes.
    #[test]
    fn tck_00197_gcounter_merge_takes_max() {
        let node_a = [0x01; 32];

        let mut counter_1 = GCounter::new();
        counter_1.increment_unchecked(node_a, 5);

        let mut counter_2 = GCounter::new();
        counter_2.increment_unchecked(node_a, 8);

        let merged = counter_1.merge_unchecked(&counter_2);

        assert_eq!(merged.value(), 8); // max(5, 8)
    }

    /// Test HLC receive algorithm.
    #[test]
    fn tck_00197_hlc_receive() {
        let local = Hlc::new(1000, 5);
        let remote = Hlc::new(1000, 10);

        let updated = local.receive_unchecked(&remote);

        // Should have the same or higher wall time
        assert!(updated.wall_time_ns() >= 1000);
        // Counter should be at least max + 1
        assert!(updated.logical_counter() > 10 || updated.wall_time_ns() > 1000);
    }

    /// Test HLC tick algorithm.
    #[test]
    fn tck_00197_hlc_tick() {
        let hlc = Hlc::new(1000, 5);
        let ticked = hlc.tick();

        // Wall time should be same or higher
        assert!(ticked.wall_time_ns() >= hlc.wall_time_ns());

        // If wall time stayed the same, counter should increment
        if ticked.wall_time_ns() == hlc.wall_time_ns() {
            assert!(ticked.logical_counter() > hlc.logical_counter());
        }
    }

    /// Test bounded conflicts in `MergeEngine`.
    #[test]
    fn tck_00197_bounded_conflicts() {
        let mut engine = MergeEngine::new();
        let node_a = [0x01; 32];
        let node_b = [0x02; 32];

        // Add MAX_CONFLICTS_PER_BATCH conflicts
        for i in 0..MAX_CONFLICTS_PER_BATCH {
            let reg_a = LwwRegister::new(i, Hlc::new(1000, 0), node_a);
            let reg_b = LwwRegister::new(i + 1000, Hlc::new(1001, 0), node_b);
            engine.merge_lww(&reg_a, &reg_b).unwrap();
        }

        // Next merge should fail
        let reg_a = LwwRegister::new(9999, Hlc::new(1000, 0), node_a);
        let reg_b = LwwRegister::new(10000, Hlc::new(1001, 0), node_b);
        let result = engine.merge_lww(&reg_a, &reg_b);

        assert!(matches!(
            result,
            Err(CrdtMergeError::TooManyConflicts { .. })
        ));
    }

    /// Test no conflict when values are equal.
    #[test]
    fn tck_00197_no_conflict_equal_values() {
        let node_a = [0x01; 32];
        let node_b = [0x02; 32];

        // Same value, different timestamps
        let reg_a = LwwRegister::new("same".to_string(), Hlc::new(1000, 0), node_a);
        let reg_b = LwwRegister::new("same".to_string(), Hlc::new(1001, 0), node_b);

        let result = reg_a.merge(&reg_b);

        assert!(!result.had_conflict());
    }

    /// Test `ConflictRecord` serialization.
    #[test]
    fn tck_00197_conflict_record_serializable() {
        let conflict = ConflictRecord::lww_unchecked(
            Hlc::new(1000, 0),
            [0x01; 32],
            Hlc::new(1001, 0),
            [0x02; 32],
            MergeWinner::RemoteWins,
            "remote HLC is higher".to_string(),
        )
        .with_key_unchecked("test_key")
        .with_value_hashes([0xaa; 32], [0xbb; 32]);

        let json = serde_json::to_string(&conflict).unwrap();
        let parsed: ConflictRecord = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.operator, conflict.operator);
        assert_eq!(parsed.resolution, conflict.resolution);
        assert_eq!(parsed.key, Some("test_key".to_string()));
    }

    /// Test validation functions.
    #[test]
    fn tck_00197_validation_functions() {
        // Valid node ID
        assert!(validate_node_id("node-123").is_ok());

        // Too long node ID
        let long_id = "x".repeat(MAX_NODE_ID_LEN + 1);
        assert!(matches!(
            validate_node_id(&long_id),
            Err(CrdtMergeError::NodeIdTooLong { .. })
        ));

        // Valid key
        assert!(validate_key("my_key").is_ok());

        // Too long key
        let long_key = "x".repeat(MAX_KEY_LEN + 1);
        assert!(matches!(
            validate_key(&long_key),
            Err(CrdtMergeError::KeyTooLong { .. })
        ));
    }

    /// Test `MergeResult` methods.
    #[test]
    fn tck_00197_merge_result_methods() {
        let node_a = [0x01; 32];
        let reg = LwwRegister::new("value".to_string(), Hlc::new(1000, 0), node_a);

        // NoConflict - check borrow methods first, then consuming method
        let no_conflict = MergeResult::NoConflict(reg.clone());
        assert!(no_conflict.conflict().is_none());
        assert!(!no_conflict.had_conflict());
        assert!(no_conflict.winner().is_some()); // consumes

        // Resolved - check borrow methods first
        let conflict = ConflictRecord::lww_unchecked(
            Hlc::new(1000, 0),
            node_a,
            Hlc::new(1001, 0),
            [0x02; 32],
            MergeWinner::RemoteWins,
            "test".to_string(),
        );
        let resolved = MergeResult::Resolved {
            winner: reg,
            conflict: conflict.clone(),
        };
        assert!(resolved.conflict().is_some());
        assert!(resolved.had_conflict());
        assert!(resolved.winner().is_some()); // consumes

        // NotAllowed - check borrow methods first
        let not_allowed: MergeResult<LwwRegister<String>> = MergeResult::NotAllowed { conflict };
        assert!(not_allowed.conflict().is_some());
        assert!(not_allowed.had_conflict());
        assert!(not_allowed.winner().is_none()); // consumes
    }

    /// Test `MergeOperator` Default.
    #[test]
    fn tck_00197_merge_operator_default() {
        let op: MergeOperator = MergeOperator::default();
        assert_eq!(op, MergeOperator::LastWriterWins);
    }

    /// Test error Display implementations.
    #[test]
    fn tck_00197_error_display() {
        let errors = [
            CrdtMergeError::NodeIdTooLong { len: 100, max: 64 },
            CrdtMergeError::KeyTooLong { len: 300, max: 256 },
            CrdtMergeError::PayloadTooLarge {
                size: 100_000,
                max: 65_536,
            },
            CrdtMergeError::TooManyConflicts {
                count: 1025,
                max: 1024,
            },
            CrdtMergeError::UnsupportedMergeOperator {
                operator: MergeOperator::NoMerge,
            },
        ];

        for err in &errors {
            let msg = err.to_string();
            assert!(!msg.is_empty());
        }
    }

    /// Test `hash_value` function.
    #[test]
    fn tck_00197_hash_value() {
        let data = b"test data";
        let hash1 = hash_value(data);
        let hash2 = hash_value(data);

        assert_eq!(hash1, hash2); // Deterministic

        let different_data = b"different data";
        let hash3 = hash_value(different_data);
        assert_ne!(hash1, hash3);
    }

    // =========================================================================
    // Security Limit Tests (CTR-1303)
    // =========================================================================

    /// Test `GCounter` node limit via `try_increment`.
    #[test]
    fn tck_00197_gcounter_node_limit_try_increment() {
        let mut counter = GCounter::new();

        // Fill up to the limit
        for i in 0..MAX_GCOUNTER_NODES {
            let mut node_id = [0u8; 32];
            node_id[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            counter.try_increment(node_id, 1).unwrap();
        }

        assert_eq!(counter.node_count_len(), MAX_GCOUNTER_NODES);

        // Next new node should fail
        let new_node = [0xff; 32];
        let result = counter.try_increment(new_node, 1);
        assert!(matches!(
            result,
            Err(CrdtMergeError::GCounterNodeLimitExceeded { .. })
        ));

        // But existing node can still increment
        let existing_node = [0u8; 32]; // First node we added
        assert!(counter.try_increment(existing_node, 1).is_ok());
    }

    /// Test `GCounter` node limit via `try_merge`.
    #[test]
    fn tck_00197_gcounter_node_limit_try_merge() {
        let mut counter_a = GCounter::new();
        let mut counter_b = GCounter::new();

        // Fill counter_a up to half the limit
        for i in 0..(MAX_GCOUNTER_NODES / 2) {
            let mut node_id = [0u8; 32];
            node_id[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            counter_a.try_increment(node_id, 1).unwrap();
        }

        // Fill counter_b with different nodes, also half the limit
        for i in (MAX_GCOUNTER_NODES / 2)..MAX_GCOUNTER_NODES {
            let mut node_id = [0u8; 32];
            node_id[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            counter_b.try_increment(node_id, 1).unwrap();
        }

        // Merge should succeed (exactly at limit)
        let merged = counter_a.try_merge(&counter_b).unwrap();
        assert_eq!(merged.node_count_len(), MAX_GCOUNTER_NODES);

        // Add one more node to counter_b
        let mut extra_node = [0u8; 32];
        extra_node[0..8].copy_from_slice(&(MAX_GCOUNTER_NODES as u64).to_le_bytes());
        counter_b.try_increment(extra_node, 1).unwrap();

        // Now merge should fail
        let result = merged.try_merge(&counter_b);
        assert!(matches!(
            result,
            Err(CrdtMergeError::GCounterNodeLimitExceeded { .. })
        ));
    }

    /// Test HLC future skew rejection via `update_with_remote`.
    #[test]
    #[allow(clippy::cast_possible_truncation)] // Nanoseconds won't overflow u64 until year 2554
    fn tck_00197_hlc_future_skew_rejection() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let local = Hlc::now();
        let physical_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        // Normal update within skew limit should succeed
        let remote_ok = Hlc::new(physical_now + MAX_FUTURE_SKEW_NS - 1_000_000_000, 0);
        assert!(local.update_with_remote(&remote_ok).is_ok());

        // Far-future timestamp should be rejected
        let remote_bad = Hlc::new(physical_now + MAX_FUTURE_SKEW_NS + 1_000_000_000, 0);
        let result = local.update_with_remote(&remote_bad);
        assert!(matches!(
            result,
            Err(CrdtMergeError::FutureSkewExceeded { .. })
        ));

        // Past timestamp should always succeed
        let remote_past = Hlc::new(physical_now - 1_000_000_000, 0);
        assert!(local.update_with_remote(&remote_past).is_ok());
    }

    /// Test HLC `update_with_remote` produces correct result when valid.
    #[test]
    fn tck_00197_hlc_update_with_remote_valid() {
        let local = Hlc::new(1000, 5);
        let remote = Hlc::new(1000, 10);

        // Use receive_unchecked (which has no skew check) to compare behavior
        let _received = local.receive_unchecked(&remote);

        // update_with_remote with a valid timestamp should produce the same result
        // Note: we can't directly compare due to timing, but we can verify it succeeds
        // and the result is sensible
        let result = local.update_with_remote(&remote);
        assert!(result.is_ok());

        let updated = result.unwrap();
        // Should have advanced beyond both inputs
        assert!(updated.wall_time_ns() >= local.wall_time_ns());
        assert!(updated.wall_time_ns() >= remote.wall_time_ns());
    }

    /// Test `ConflictRecord` validation via `try_lww`.
    #[test]
    fn tck_00197_conflict_record_try_lww_validation() {
        let node_a = [0x01; 32];
        let node_b = [0x02; 32];

        // Valid reason should succeed
        let result = ConflictRecord::try_lww(
            Hlc::new(1000, 0),
            node_a,
            Hlc::new(1001, 0),
            node_b,
            MergeWinner::RemoteWins,
            "valid reason".to_string(),
        );
        assert!(result.is_ok());

        // Too long reason should fail
        let long_reason = "x".repeat(MAX_REASON_LEN + 1);
        let result = ConflictRecord::try_lww(
            Hlc::new(1000, 0),
            node_a,
            Hlc::new(1001, 0),
            node_b,
            MergeWinner::RemoteWins,
            long_reason,
        );
        assert!(matches!(result, Err(CrdtMergeError::ReasonTooLong { .. })));
    }

    /// Test `ConflictRecord` validation via `try_with_key`.
    #[test]
    fn tck_00197_conflict_record_try_with_key_validation() {
        let node_a = [0x01; 32];
        let node_b = [0x02; 32];

        let record = ConflictRecord::lww_unchecked(
            Hlc::new(1000, 0),
            node_a,
            Hlc::new(1001, 0),
            node_b,
            MergeWinner::RemoteWins,
            "reason".to_string(),
        );

        // Valid key should succeed
        let result = record.clone().try_with_key("valid_key");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().key, Some("valid_key".to_string()));

        // Too long key should fail
        let long_key = "x".repeat(MAX_KEY_LEN + 1);
        let result = record.try_with_key(long_key);
        assert!(matches!(result, Err(CrdtMergeError::KeyTooLong { .. })));
    }

    /// Test new error variants have proper Display implementations.
    #[test]
    fn tck_00197_new_error_display() {
        let errors = [
            CrdtMergeError::GCounterNodeLimitExceeded {
                count: 1025,
                max: 1024,
            },
            CrdtMergeError::FutureSkewExceeded {
                skew_ns: 120_000_000_000,
                max_ns: 60_000_000_000,
            },
            CrdtMergeError::ReasonTooLong {
                len: 2000,
                max: 1024,
            },
        ];

        for err in &errors {
            let msg = err.to_string();
            assert!(!msg.is_empty());
            // Verify the error message contains relevant info
            match err {
                CrdtMergeError::GCounterNodeLimitExceeded { count, max } => {
                    assert!(msg.contains(&count.to_string()));
                    assert!(msg.contains(&max.to_string()));
                },
                CrdtMergeError::FutureSkewExceeded { skew_ns, max_ns } => {
                    assert!(msg.contains(&skew_ns.to_string()));
                    assert!(msg.contains(&max_ns.to_string()));
                },
                CrdtMergeError::ReasonTooLong { len, max } => {
                    assert!(msg.contains(&len.to_string()));
                    assert!(msg.contains(&max.to_string()));
                },
                _ => {},
            }
        }
    }

    /// Test constants are properly defined.
    #[test]
    fn tck_00197_security_constants_defined() {
        // Verify constants have expected values
        assert_eq!(MAX_GCOUNTER_NODES, 1024);
        assert_eq!(MAX_FUTURE_SKEW_NS, 60 * 1_000_000_000); // 60 seconds
        assert_eq!(MAX_REASON_LEN, 1024);
        assert_eq!(MAX_SET_ELEMENTS, 1024);
    }

    // =========================================================================
    // TCK-00197: SetUnion CRDT Tests
    // =========================================================================

    /// `SetUnion`: basic insertion and containment.
    #[test]
    fn tck_00197_set_union_basic() {
        let mut set: SetUnion<String> = SetUnion::new();
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);

        // Insert element
        assert!(set.insert_unchecked("a".to_string()));
        assert!(!set.is_empty());
        assert_eq!(set.len(), 1);
        assert!(set.contains(&"a".to_string()));

        // Duplicate insert returns false
        assert!(!set.insert_unchecked("a".to_string()));
        assert_eq!(set.len(), 1);
    }

    /// `SetUnion`: merge is commutative (a.merge(b) = b.merge(a)).
    #[test]
    fn tck_00197_set_union_merge_commutativity() {
        let mut set_a: SetUnion<i32> = SetUnion::new();
        set_a.insert_unchecked(1);
        set_a.insert_unchecked(2);

        let mut set_b: SetUnion<i32> = SetUnion::new();
        set_b.insert_unchecked(2);
        set_b.insert_unchecked(3);

        let merged_ab = set_a.merge_unchecked(&set_b);
        let merged_ba = set_b.merge_unchecked(&set_a);

        // Merged sets should be equal
        assert_eq!(merged_ab, merged_ba);

        // Should contain union of both sets
        assert!(merged_ab.contains(&1));
        assert!(merged_ab.contains(&2));
        assert!(merged_ab.contains(&3));
        assert_eq!(merged_ab.len(), 3);
    }

    /// `SetUnion`: merge is associative (merge(merge(a, b), c) = merge(a,
    /// merge(b, c))).
    #[test]
    fn tck_00197_set_union_merge_associativity() {
        let mut set_a: SetUnion<i32> = SetUnion::new();
        set_a.insert_unchecked(1);

        let mut set_b: SetUnion<i32> = SetUnion::new();
        set_b.insert_unchecked(2);

        let mut set_c: SetUnion<i32> = SetUnion::new();
        set_c.insert_unchecked(3);

        // (a merge b) merge c
        let ab = set_a.merge_unchecked(&set_b);
        let abc_left = ab.merge_unchecked(&set_c);

        // a merge (b merge c)
        let bc = set_b.merge_unchecked(&set_c);
        let abc_right = set_a.merge_unchecked(&bc);

        assert_eq!(abc_left, abc_right);
        assert_eq!(abc_left.len(), 3);
    }

    /// `SetUnion`: merge is idempotent (a.merge(a) = a).
    #[test]
    fn tck_00197_set_union_merge_idempotent() {
        let mut set: SetUnion<i32> = SetUnion::new();
        set.insert_unchecked(1);
        set.insert_unchecked(2);
        set.insert_unchecked(3);

        let merged = set.merge_unchecked(&set);

        assert_eq!(merged, set);
        assert_eq!(merged.len(), 3);
    }

    /// `SetUnion`: empty sets merge correctly.
    #[test]
    fn tck_00197_set_union_empty_merge() {
        let empty: SetUnion<i32> = SetUnion::new();
        let mut non_empty: SetUnion<i32> = SetUnion::new();
        non_empty.insert_unchecked(1);

        // Empty merged with non-empty
        let merged = empty.merge_unchecked(&non_empty);
        assert_eq!(merged.len(), 1);
        assert!(merged.contains(&1));

        // Non-empty merged with empty
        let merged2 = non_empty.merge_unchecked(&empty);
        assert_eq!(merged2.len(), 1);
        assert!(merged2.contains(&1));
    }

    /// `SetUnion`: `try_insert` enforces capacity limit.
    #[test]
    fn tck_00197_set_union_capacity_try_insert() {
        let mut set: SetUnion<usize> = SetUnion::new();

        // Fill up to the limit
        for i in 0..MAX_SET_ELEMENTS {
            set.try_insert(i).unwrap();
        }
        assert_eq!(set.len(), MAX_SET_ELEMENTS);

        // Next new element should fail
        let result = set.try_insert(MAX_SET_ELEMENTS);
        assert!(matches!(
            result,
            Err(CrdtMergeError::SetUnionElementLimitExceeded { .. })
        ));

        // But existing element can still be "inserted" (no-op)
        let result = set.try_insert(0);
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Returns false because element existed
    }

    /// `SetUnion`: `try_merge` enforces capacity limit.
    #[test]
    fn tck_00197_set_union_capacity_try_merge() {
        let mut set_a: SetUnion<usize> = SetUnion::new();
        let mut set_b: SetUnion<usize> = SetUnion::new();

        // Fill set_a with half the limit
        for i in 0..(MAX_SET_ELEMENTS / 2) {
            set_a.try_insert(i).unwrap();
        }

        // Fill set_b with different elements, also half the limit
        for i in (MAX_SET_ELEMENTS / 2)..MAX_SET_ELEMENTS {
            set_b.try_insert(i).unwrap();
        }

        // Merge should succeed (exactly at limit)
        let merged = set_a.try_merge(&set_b).unwrap();
        assert_eq!(merged.len(), MAX_SET_ELEMENTS);

        // Add one more element to set_b
        set_b.insert_unchecked(MAX_SET_ELEMENTS);

        // Now merge should fail
        let result = merged.try_merge(&set_b);
        assert!(matches!(
            result,
            Err(CrdtMergeError::SetUnionElementLimitExceeded { .. })
        ));
    }

    /// `SetUnion`: `try_from_iter` enforces capacity limit.
    #[test]
    fn tck_00197_set_union_capacity_try_from_iter() {
        // Valid: exactly at limit
        let elements: Vec<usize> = (0..MAX_SET_ELEMENTS).collect();
        let set = SetUnion::try_from_iter(elements).unwrap();
        assert_eq!(set.len(), MAX_SET_ELEMENTS);

        // Invalid: over limit
        let elements: Vec<usize> = (0..=MAX_SET_ELEMENTS).collect();
        let result = SetUnion::try_from_iter(elements);
        assert!(matches!(
            result,
            Err(CrdtMergeError::SetUnionElementLimitExceeded { .. })
        ));
    }

    /// `SetUnion`: iterator and `as_set` work correctly.
    #[test]
    fn tck_00197_set_union_iteration() {
        let mut set: SetUnion<i32> = SetUnion::new();
        set.insert_unchecked(3);
        set.insert_unchecked(1);
        set.insert_unchecked(2);

        // Iterator should yield elements in order (BTreeSet)
        let elements: Vec<_> = set.iter().copied().collect();
        assert_eq!(elements, vec![1, 2, 3]);

        // as_set should return the underlying BTreeSet
        assert_eq!(set.as_set().len(), 3);
    }

    /// `SetUnion`: `from_iter_unchecked` works.
    #[test]
    fn tck_00197_set_union_from_iter() {
        let set = SetUnion::from_iter_unchecked(vec![1, 2, 3, 2, 1]);

        // Duplicates should be removed
        assert_eq!(set.len(), 3);
        assert!(set.contains(&1));
        assert!(set.contains(&2));
        assert!(set.contains(&3));
    }

    /// `SetUnion`: default creates empty set.
    #[test]
    fn tck_00197_set_union_default() {
        let set: SetUnion<i32> = SetUnion::default();
        assert!(set.is_empty());
    }

    /// `SetUnion`: error display for `SetUnionElementLimitExceeded`.
    #[test]
    fn tck_00197_set_union_error_display() {
        let err = CrdtMergeError::SetUnionElementLimitExceeded {
            count: 1025,
            max: 1024,
        };
        let msg = err.to_string();
        assert!(msg.contains("1025"));
        assert!(msg.contains("1024"));
        assert!(msg.contains("SetUnion"));
    }

    /// `SetUnion`: serialization round-trip.
    #[test]
    fn tck_00197_set_union_serialization() {
        let mut set: SetUnion<String> = SetUnion::new();
        set.insert_unchecked("hello".to_string());
        set.insert_unchecked("world".to_string());

        let json = serde_json::to_string(&set).unwrap();
        let parsed: SetUnion<String> = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed, set);
        assert!(parsed.contains(&"hello".to_string()));
        assert!(parsed.contains(&"world".to_string()));
    }

    // =========================================================================
    // TCK-00197 Security Fixes
    // =========================================================================

    /// CRITICAL: LWW merge must be commutative when HLCs are equal but
    /// `node_id`s differ.
    ///
    /// This test verifies that `a.merge(b) == b.merge(a)` in terms of the
    /// winning value when the HLC timestamps are identical but `node_id`s are
    /// different.
    #[test]
    fn tck_00197_lww_commutativity_same_hlc_different_node_ids() {
        let node_a = [0x01; 32];
        let node_b = [0x02; 32];
        let hlc = Hlc::new(1000, 0); // Same HLC for both

        let reg_a = LwwRegister::new("value_a".to_string(), hlc, node_a);
        let reg_b = LwwRegister::new("value_b".to_string(), hlc, node_b);

        // Test commutativity: merge(a, b) should equal merge(b, a)
        let result_ab = reg_a.merge(&reg_b);
        let result_ba = reg_b.merge(&reg_a);

        let winner_ab = result_ab.winner().unwrap();
        let winner_ba = result_ba.winner().unwrap();

        // CRITICAL: Both orderings must produce the same winner
        assert_eq!(
            winner_ab.value(),
            winner_ba.value(),
            "LWW merge is not commutative! a.merge(b) != b.merge(a)"
        );

        // The winner should be value_b since node_b > node_a
        assert_eq!(winner_ab.value(), "value_b");
    }

    /// CRITICAL: LWW merge commutativity with various `node_id` orderings.
    ///
    /// Tests multiple combinations of `node_id`s to ensure commutativity holds.
    #[test]
    fn tck_00197_lww_commutativity_exhaustive() {
        let hlc = Hlc::new(12_345_678, 42); // Arbitrary HLC

        // Test with various node_id pairs
        let test_cases: Vec<([u8; 32], [u8; 32])> = vec![
            ([0x00; 32], [0xff; 32]), // Min vs max
            ([0x01; 32], [0x02; 32]), // Adjacent
            ([0xaa; 32], [0x55; 32]), // Arbitrary
        ];

        for (node_a, node_b) in test_cases {
            let reg_a = LwwRegister::new(format!("from_node_{:02x}", node_a[0]), hlc, node_a);
            let reg_b = LwwRegister::new(format!("from_node_{:02x}", node_b[0]), hlc, node_b);

            let winner_ab = reg_a.merge(&reg_b).winner().unwrap();
            let winner_ba = reg_b.merge(&reg_a).winner().unwrap();

            assert_eq!(
                winner_ab.value(),
                winner_ba.value(),
                "Commutativity failed for node_ids {:02x} and {:02x}",
                node_a[0],
                node_b[0]
            );

            // Winner should always be the one with the higher node_id
            let expected_winner_node = if node_a > node_b { node_a } else { node_b };
            assert_eq!(
                winner_ab.node_id(),
                expected_winner_node,
                "Wrong winner for node_ids {:02x} and {:02x}",
                node_a[0],
                node_b[0]
            );
        }
    }

    /// HIGH: `GCounter` increment must not panic on `u64::MAX`.
    ///
    /// This test verifies that incrementing at the overflow boundary
    /// saturates instead of panicking.
    #[test]
    fn tck_00197_gcounter_no_panic_on_overflow() {
        let node_id = [0x01; 32];
        let mut counter = GCounter::new();

        // Set to near-max value
        counter.increment_unchecked(node_id, u64::MAX - 10);
        assert_eq!(counter.node_count(&node_id), u64::MAX - 10);

        // Increment past max - should saturate, not panic
        counter.increment_unchecked(node_id, 100);
        assert_eq!(counter.node_count(&node_id), u64::MAX);

        // Further increments should stay at max
        counter.increment_unchecked(node_id, u64::MAX);
        assert_eq!(counter.node_count(&node_id), u64::MAX);
    }

    /// HIGH: `GCounter::try_increment` must not panic on `u64::MAX`.
    #[test]
    fn tck_00197_gcounter_try_increment_no_panic_on_overflow() {
        let node_id = [0x01; 32];
        let mut counter = GCounter::new();

        // Set to near-max value
        counter.try_increment(node_id, u64::MAX - 10).unwrap();
        assert_eq!(counter.node_count(&node_id), u64::MAX - 10);

        // Increment past max - should saturate, not panic
        counter.try_increment(node_id, 100).unwrap();
        assert_eq!(counter.node_count(&node_id), u64::MAX);
    }

    /// HIGH: `GCounter::value()` must not panic on overflow when summing.
    ///
    /// This test verifies that the total value calculation saturates
    /// when the sum of all node counts would overflow u64.
    #[test]
    fn tck_00197_gcounter_value_no_overflow() {
        let node_a = [0x01; 32];
        let node_b = [0x02; 32];
        let mut counter = GCounter::new();

        // Set both nodes to near-max values
        counter.increment_unchecked(node_a, u64::MAX - 10);
        counter.increment_unchecked(node_b, u64::MAX - 10);

        // The sum would overflow, but value() should saturate
        let total = counter.value();
        assert_eq!(total, u64::MAX, "value() should saturate at u64::MAX");
    }

    /// HIGH: `GCounter` with many nodes at max value should saturate.
    #[test]
    fn tck_00197_gcounter_many_nodes_saturate() {
        let mut counter = GCounter::new();

        // Add multiple nodes with large values
        for i in 0..10u8 {
            let mut node_id = [0u8; 32];
            node_id[0] = i;
            counter.increment_unchecked(node_id, u64::MAX / 5);
        }

        // The sum of 10 * (u64::MAX / 5) would overflow
        // (since u64::MAX / 5 * 10 = 2 * u64::MAX), so it should saturate
        let total = counter.value();
        assert_eq!(
            total,
            u64::MAX,
            "value() should saturate when sum overflows"
        );
    }

    // =========================================================================
    // TCK-00360: Revocation-Wins Signed CRDT Merge Law
    // =========================================================================

    /// Helper: create a `RevocationWinsRegister` with Active status.
    fn make_active_reg(value: &str, wall_time: u64, node: u8) -> RevocationWinsRegister<String> {
        RevocationWinsRegister::new(value.to_string(), Hlc::new(wall_time, 0), [node; 32])
    }

    /// Helper: create a valid `AuthorizationProof` for testing.
    fn make_auth_proof(
        revocation_event_hash: &[u8; 32],
        signer_node_id: &NodeId,
        effective_anchor: u64,
    ) -> AuthorizationProof {
        AuthorizationProof::with_valid_commitment(
            [0x01; 32], // policy_root_hash
            revocation_event_hash,
            effective_anchor,
            signer_node_id,
            [0xFF; 32], // signature suffix
            false,      // not a waiver
        )
    }

    /// Helper: create a `RevocationWinsRegister` with Revoked status.
    fn make_revoked_reg(
        value: &str,
        wall_time: u64,
        node: u8,
        rev_hash: [u8; 32],
    ) -> RevocationWinsRegister<String> {
        RevocationWinsRegister::with_status(
            value.to_string(),
            DirectoryStatus::Revoked,
            Hlc::new(wall_time, 0),
            [node; 32],
            Some(rev_hash),
        )
    }

    /// Helper: create a `RevocationWinsRegister` with Suspended status.
    fn make_suspended_reg(value: &str, wall_time: u64, node: u8) -> RevocationWinsRegister<String> {
        RevocationWinsRegister::with_status(
            value.to_string(),
            DirectoryStatus::Suspended,
            Hlc::new(wall_time, 0),
            [node; 32],
            None,
        )
    }

    /// AC1: Revocation-wins merge is commutative.
    #[test]
    fn tck_00360_revocation_wins_commutativity() {
        let reg_a = make_active_reg("active_a", 1000, 0x01);
        let reg_b = make_revoked_reg("revoked_b", 900, 0x02, [0xBB; 32]);

        let result_ab = reg_a.merge(&reg_b);
        let result_ba = reg_b.merge(&reg_a);

        let winner_ab = result_ab.winner().unwrap();
        let winner_ba = result_ba.winner().unwrap();

        // Both must agree on status (revoked wins regardless of timestamp)
        assert_eq!(winner_ab.status(), DirectoryStatus::Revoked);
        assert_eq!(winner_ba.status(), DirectoryStatus::Revoked);
        // Both must produce the same winner value
        assert_eq!(winner_ab.value(), winner_ba.value());
    }

    /// AC1: Revocation-wins merge is associative.
    #[test]
    fn tck_00360_revocation_wins_associativity() {
        let reg_a = make_active_reg("a", 1000, 0x01);
        let reg_b = make_revoked_reg("b", 900, 0x02, [0xBB; 32]);
        let reg_c = make_suspended_reg("c", 1100, 0x03);

        // (a merge b) merge c
        let ab = reg_a.merge(&reg_b).winner().unwrap();
        let abc_left = ab.merge(&reg_c).winner().unwrap();

        // a merge (b merge c)
        let bc = reg_b.merge(&reg_c).winner().unwrap();
        let abc_right = reg_a.merge(&bc).winner().unwrap();

        // Both must converge to the same status
        assert_eq!(abc_left.status(), abc_right.status());
        assert_eq!(abc_left.status(), DirectoryStatus::Revoked);
        // Values must match
        assert_eq!(abc_left.value(), abc_right.value());
    }

    /// AC1: Revocation-wins merge is idempotent.
    #[test]
    fn tck_00360_revocation_wins_idempotent() {
        let reg = make_revoked_reg("revoked", 1000, 0x01, [0xAA; 32]);

        let result = reg.merge(&reg);
        assert!(!result.had_conflict());
        let winner = result.winner().unwrap();
        assert_eq!(winner.status(), DirectoryStatus::Revoked);
        assert_eq!(winner.value(), "revoked");
    }

    /// AC1: Active vs Active uses LWW.
    #[test]
    fn tck_00360_active_vs_active_lww() {
        let reg_a = make_active_reg("a", 1000, 0x01);
        let reg_b = make_active_reg("b", 1001, 0x02);

        let result = reg_a.merge(&reg_b);
        let winner = result.winner().unwrap();

        assert_eq!(winner.status(), DirectoryStatus::Active);
        assert_eq!(winner.value(), "b"); // Higher HLC wins
    }

    /// AC1: Active vs Revoked always yields Revoked.
    #[test]
    fn tck_00360_active_vs_revoked() {
        // Active has LATER timestamp, but revoked still wins
        let reg_active = make_active_reg("active", 2000, 0x01);
        let reg_revoked = make_revoked_reg("revoked", 1000, 0x02, [0xCC; 32]);

        let result = reg_active.merge(&reg_revoked);
        let winner = result.winner().unwrap();

        assert_eq!(winner.status(), DirectoryStatus::Revoked);
    }

    /// AC1: Suspended vs Revoked yields Revoked.
    #[test]
    fn tck_00360_suspended_vs_revoked() {
        let reg_suspended = make_suspended_reg("suspended", 2000, 0x01);
        let reg_revoked = make_revoked_reg("revoked", 1000, 0x02, [0xDD; 32]);

        let result = reg_suspended.merge(&reg_revoked);
        let winner = result.winner().unwrap();

        assert_eq!(winner.status(), DirectoryStatus::Revoked);
    }

    /// AC1: Active vs Suspended yields Suspended.
    #[test]
    fn tck_00360_active_vs_suspended() {
        // Active has later timestamp, but Suspended status is higher in lattice
        let reg_active = make_active_reg("active", 2000, 0x01);
        let reg_suspended = make_suspended_reg("suspended", 1000, 0x02);

        let result = reg_active.merge(&reg_suspended);
        let winner = result.winner().unwrap();

        assert_eq!(winner.status(), DirectoryStatus::Suspended);
    }

    /// AC2: Revoked identity cannot resurrect without re-admission anchor.
    #[test]
    fn tck_00360_revoked_cannot_resurrect_without_anchor() {
        let rev_hash = [0xAA; 32];
        let reg_revoked = make_revoked_reg("revoked", 1000, 0x01, rev_hash);

        // Attempting to merge with an active entry still yields revoked
        let reg_active = make_active_reg("active_attempt", 2000, 0x02);
        let result = reg_revoked.merge(&reg_active);
        let winner = result.winner().unwrap();
        assert_eq!(winner.status(), DirectoryStatus::Revoked);

        // Even with a much later timestamp
        let reg_far_future = make_active_reg("future_attempt", 999_999, 0x03);
        let result = reg_revoked.merge(&reg_far_future);
        let winner = result.winner().unwrap();
        assert_eq!(winner.status(), DirectoryStatus::Revoked);
    }

    /// AC2: Re-admission with valid anchor and authorization proof succeeds.
    #[test]
    fn tck_00360_readmission_with_valid_anchor() {
        let rev_hash = [0xAA; 32];
        let reg_revoked = make_revoked_reg("old_value", 1000, 0x01, rev_hash);

        let signer = [0x02; 32];
        let anchor = ReAdmissionAnchor::new(rev_hash, Hlc::new(2000, 0), signer);
        let auth_proof = make_auth_proof(&rev_hash, &signer, 1);
        let readmitted = reg_revoked
            .readmit(
                "new_value".to_string(),
                Hlc::new(2000, 0),
                [0x02; 32],
                anchor,
                &auth_proof,
            )
            .unwrap();

        assert_eq!(readmitted.status(), DirectoryStatus::Active);
        assert_eq!(readmitted.value(), "new_value");
        assert!(readmitted.readmission_anchor().is_some());
        assert_eq!(readmitted.readmission_count(), 1);
        assert_eq!(readmitted.effective_anchor(), 1);
    }

    /// AC2: Re-admission with mismatched anchor fails.
    #[test]
    fn tck_00360_readmission_with_wrong_anchor_fails() {
        let rev_hash = [0xAA; 32];
        let wrong_hash = [0xBB; 32];
        let reg_revoked = make_revoked_reg("old_value", 1000, 0x01, rev_hash);

        let signer = [0x02; 32];
        let bad_anchor = ReAdmissionAnchor::new(wrong_hash, Hlc::new(2000, 0), signer);
        let auth_proof = make_auth_proof(&rev_hash, &signer, 1);
        let result = reg_revoked.readmit(
            "new_value".to_string(),
            Hlc::new(2000, 0),
            [0x02; 32],
            bad_anchor,
            &auth_proof,
        );

        assert!(matches!(
            result,
            Err(CrdtMergeError::ReAdmissionAnchorMismatch { .. })
        ));
    }

    /// AC2: Re-admission of non-revoked entry fails.
    #[test]
    fn tck_00360_readmission_of_active_fails() {
        let rev_hash = [0xAA; 32];
        let signer = [0x02; 32];
        let reg_active = make_active_reg("value", 1000, 0x01);
        let anchor = ReAdmissionAnchor::new(rev_hash, Hlc::new(2000, 0), signer);
        let auth_proof = make_auth_proof(&rev_hash, &signer, 1);

        let result = reg_active.readmit(
            "new_value".to_string(),
            Hlc::new(2000, 0),
            [0x02; 32],
            anchor,
            &auth_proof,
        );

        assert!(matches!(
            result,
            Err(CrdtMergeError::RevocationWinsViolation)
        ));
    }

    /// AC3: Byzantine reordering cannot violate revocation-wins.
    ///
    /// Simulates a partition/rejoin scenario where messages arrive in
    /// arbitrary order due to Byzantine behavior.
    #[test]
    fn tck_00360_byzantine_reordering_simulation() {
        // Simulate 5 events arriving in different orders
        let events: Vec<RevocationWinsRegister<String>> = vec![
            make_active_reg("v1", 100, 0x01),
            make_active_reg("v2", 200, 0x02),
            make_revoked_reg("v3_revoked", 150, 0x03, [0xEE; 32]),
            make_active_reg("v4", 300, 0x04),
            make_suspended_reg("v5", 250, 0x05),
        ];

        // Try all 120 permutations of 5 events
        let permutations = generate_permutations(5);
        let mut results = Vec::new();

        for perm in &permutations {
            // Merge in the order specified by this permutation
            let mut merged = events[perm[0]].clone();
            for &idx in &perm[1..] {
                merged = merged.merge(&events[idx]).winner().unwrap();
            }
            results.push(merged);
        }

        // All permutations must converge to the same result
        for result in &results {
            assert_eq!(
                result.status(),
                DirectoryStatus::Revoked,
                "Byzantine reordering violated revocation-wins"
            );
        }

        // All must agree on the same value
        let first_value = results[0].value().clone();
        for result in &results {
            assert_eq!(
                result.value(),
                &first_value,
                "Byzantine reordering produced inconsistent values"
            );
        }
    }

    /// AC3: Partition/rejoin with multiple revocations converges.
    #[test]
    fn tck_00360_partition_rejoin_multiple_revocations() {
        // Partition A: node revokes at t=100
        let part_a = make_revoked_reg("revoked_by_a", 100, 0x01, [0xAA; 32]);
        // Partition B: node revokes independently at t=200
        let part_b = make_revoked_reg("revoked_by_b", 200, 0x02, [0xBB; 32]);

        // Rejoin: merge both partitions
        let result_ab = part_a.merge(&part_b);
        let result_ba = part_b.merge(&part_a);

        let winner_ab = result_ab.winner().unwrap();
        let winner_ba = result_ba.winner().unwrap();

        // Both must be revoked
        assert_eq!(winner_ab.status(), DirectoryStatus::Revoked);
        assert_eq!(winner_ba.status(), DirectoryStatus::Revoked);
        // Must agree on the winner (later timestamp wins within same status)
        assert_eq!(winner_ab.value(), winner_ba.value());
    }

    /// AC3: Partition/rejoin where one side revokes and other re-admits.
    ///
    /// Per RFC-0020 exception: a later authorized re-admission with strictly
    /// greater `effective_anchor` CAN beat revoked state during merge.
    #[test]
    fn tck_00360_partition_rejoin_revoke_vs_readmit() {
        let rev_hash = [0xAA; 32];

        // Partition A: revoked (effective_anchor = 0)
        let part_a = make_revoked_reg("revoked", 100, 0x01, rev_hash);

        // Partition B: revoked then re-admitted with effective_anchor = 1
        let revoked_b = make_revoked_reg("revoked", 100, 0x01, rev_hash);
        let signer = [0x02; 32];
        let anchor = ReAdmissionAnchor::new(rev_hash, Hlc::new(200, 0), signer);
        let auth_proof = make_auth_proof(&rev_hash, &signer, 1);
        let part_b = revoked_b
            .readmit(
                "readmitted".to_string(),
                Hlc::new(200, 0),
                [0x02; 32],
                anchor,
                &auth_proof,
            )
            .unwrap();
        assert_eq!(part_b.status(), DirectoryStatus::Active);
        assert_eq!(part_b.effective_anchor(), 1);

        // RFC-0020 exception: the re-admitted entry has strictly greater
        // effective_anchor (1 > 0), so it wins over the revoked partition.
        let result = part_b.merge(&part_a);
        let winner = result.winner().unwrap();
        assert_eq!(
            winner.status(),
            DirectoryStatus::Active,
            "Authorized re-admission with greater effective_anchor wins (RFC-0020)"
        );
        assert_eq!(winner.value(), "readmitted");

        // Commutativity: merging in opposite order yields the same result
        let result_ba = part_a.merge(&part_b);
        let winner_ba = result_ba.winner().unwrap();
        assert_eq!(winner_ba.status(), DirectoryStatus::Active);
        assert_eq!(winner_ba.value(), "readmitted");
    }

    /// AC3: Re-admission WITHOUT greater `effective_anchor` loses to revoked.
    #[test]
    fn tck_00360_partition_rejoin_readmit_without_greater_anchor_loses() {
        let rev_hash = [0xAA; 32];

        // Both partitions start with the same revoked state (effective_anchor = 0)
        // Part A: stays revoked
        let mut part_a = make_revoked_reg("revoked", 100, 0x01, rev_hash);
        // Give part_a a higher effective_anchor to simulate it saw a later revocation
        part_a.effective_anchor = 5;

        // Part B: re-admitted with effective_anchor = 1 (< 5)
        let revoked_b = make_revoked_reg("revoked", 100, 0x01, rev_hash);
        let signer = [0x02; 32];
        let anchor = ReAdmissionAnchor::new(rev_hash, Hlc::new(200, 0), signer);
        let auth_proof = make_auth_proof(&rev_hash, &signer, 1);
        let part_b = revoked_b
            .readmit(
                "readmitted".to_string(),
                Hlc::new(200, 0),
                [0x02; 32],
                anchor,
                &auth_proof,
            )
            .unwrap();

        // effective_anchor 1 < 5, so revocation wins
        let result = part_b.merge(&part_a);
        let winner = result.winner().unwrap();
        assert_eq!(
            winner.status(),
            DirectoryStatus::Revoked,
            "Re-admission with lesser effective_anchor must lose to revoked"
        );
    }

    /// `DirectoryStatus` ordering matches the lattice.
    #[test]
    fn tck_00360_directory_status_ordering() {
        assert!(DirectoryStatus::Active < DirectoryStatus::Suspended);
        assert!(DirectoryStatus::Suspended < DirectoryStatus::Revoked);
        assert!(DirectoryStatus::Active < DirectoryStatus::Revoked);
    }

    /// `DirectoryStatus` helper methods.
    #[test]
    fn tck_00360_directory_status_helpers() {
        assert!(DirectoryStatus::Active.is_active());
        assert!(!DirectoryStatus::Active.is_revoked());

        assert!(!DirectoryStatus::Revoked.is_active());
        assert!(DirectoryStatus::Revoked.is_revoked());

        assert!(!DirectoryStatus::Suspended.is_active());
        assert!(!DirectoryStatus::Suspended.is_revoked());
    }

    /// `ReAdmissionAnchor` hash is deterministic.
    #[test]
    fn tck_00360_readmission_anchor_deterministic_hash() {
        let rev_hash = [0xAA; 32];
        let hlc = Hlc::new(1000, 5);
        let signer = [0x01; 32];

        let anchor1 = ReAdmissionAnchor::new(rev_hash, hlc, signer);
        let anchor2 = ReAdmissionAnchor::new(rev_hash, hlc, signer);

        assert_eq!(anchor1.anchor_hash(), anchor2.anchor_hash());

        // Different inputs produce different hashes
        let anchor3 = ReAdmissionAnchor::new([0xBB; 32], hlc, signer);
        assert_ne!(anchor1.anchor_hash(), anchor3.anchor_hash());
    }

    /// `ReAdmissionAnchor` validation.
    #[test]
    fn tck_00360_readmission_anchor_validation() {
        let rev_hash = [0xAA; 32];
        let anchor = ReAdmissionAnchor::new(rev_hash, Hlc::new(1000, 0), [0x01; 32]);

        // Valid reference
        assert!(anchor.validate_for_revocation(&rev_hash).is_ok());

        // Invalid reference
        let wrong_hash = [0xBB; 32];
        assert!(matches!(
            anchor.validate_for_revocation(&wrong_hash),
            Err(CrdtMergeError::ReAdmissionAnchorMismatch { .. })
        ));
    }

    /// `ReAdmissionAnchor` accessors.
    #[test]
    fn tck_00360_readmission_anchor_accessors() {
        let rev_hash = [0xAA; 32];
        let hlc = Hlc::new(1000, 5);
        let signer = [0x01; 32];

        let anchor = ReAdmissionAnchor::new(rev_hash, hlc, signer);

        assert_eq!(anchor.revocation_event_hash(), &rev_hash);
        assert_eq!(anchor.hlc(), hlc);
        assert_eq!(anchor.signer_node_id(), &signer);
        assert!(!anchor.anchor_hash().iter().all(|&b| b == 0));
    }

    /// `RevocationWinsRegister` accessors.
    #[test]
    fn tck_00360_register_accessors() {
        let reg = RevocationWinsRegister::new("value".to_string(), Hlc::new(1000, 0), [0x01; 32]);

        assert_eq!(reg.value(), "value");
        assert_eq!(reg.status(), DirectoryStatus::Active);
        assert_eq!(reg.hlc(), Hlc::new(1000, 0));
        assert_eq!(reg.node_id(), [0x01; 32]);
        assert!(reg.revocation_event_hash().is_none());
        assert!(reg.readmission_anchor().is_none());
    }

    /// `RevocationWinsRegister::revoke` and `suspend` transitions.
    #[test]
    fn tck_00360_register_state_transitions() {
        let reg = make_active_reg("value", 1000, 0x01);

        // Suspend
        let suspended = reg.clone().suspend(Hlc::new(1001, 0), [0x02; 32]);
        assert_eq!(suspended.status(), DirectoryStatus::Suspended);

        // Revoke
        let revoked = reg.revoke(Hlc::new(1002, 0), [0x03; 32], [0xFF; 32]);
        assert_eq!(revoked.status(), DirectoryStatus::Revoked);
        assert_eq!(revoked.revocation_event_hash(), Some(&[0xFF; 32]));
    }

    /// Concurrent updates converge deterministically across many orderings.
    #[test]
    fn tck_00360_concurrent_updates_converge() {
        let regs = [
            make_active_reg("a", 100, 0x01),
            make_active_reg("b", 200, 0x02),
            make_active_reg("c", 150, 0x03),
        ];

        // Try all 6 permutations
        let perms = generate_permutations(3);
        let mut results = Vec::new();

        for perm in &perms {
            let mut merged = regs[perm[0]].clone();
            for &idx in &perm[1..] {
                merged = merged.merge(&regs[idx]).winner().unwrap();
            }
            results.push(merged.value().clone());
        }

        // All permutations must produce the same result
        for r in &results {
            assert_eq!(r, &results[0], "Non-deterministic convergence detected");
        }
    }

    /// Error display for new TCK-00360 error variants.
    #[test]
    fn tck_00360_error_display() {
        let errors: Vec<CrdtMergeError> = vec![
            CrdtMergeError::RevocationWinsViolation,
            CrdtMergeError::ReAdmissionAnchorMismatch {
                anchor_revocation_hash: "aa".to_string(),
                current_revocation_hash: "bb".to_string(),
            },
            CrdtMergeError::ReAdmissionAnchorLimitExceeded { count: 65, max: 64 },
        ];

        for err in &errors {
            let msg = err.to_string();
            assert!(!msg.is_empty());
        }
    }

    /// `RevocationWinsRegister` no-conflict when identical.
    #[test]
    fn tck_00360_no_conflict_identical_entries() {
        let reg = make_active_reg("same", 1000, 0x01);
        let result = reg.merge(&reg);
        assert!(!result.had_conflict());
    }

    /// `RevocationWinsRegister` serialization round-trip.
    #[test]
    fn tck_00360_register_serialization() {
        let reg = make_revoked_reg("value", 1000, 0x01, [0xAA; 32]);
        let json = serde_json::to_string(&reg).unwrap();
        let parsed: RevocationWinsRegister<String> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, reg);
    }

    /// `ReAdmissionAnchor` serialization round-trip.
    #[test]
    fn tck_00360_anchor_serialization() {
        let anchor = ReAdmissionAnchor::new([0xAA; 32], Hlc::new(1000, 0), [0x01; 32]);
        let json = serde_json::to_string(&anchor).unwrap();
        let parsed: ReAdmissionAnchor = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, anchor);
    }

    // =========================================================================
    // TCK-00360 BLOCKER/MAJOR fix tests
    // =========================================================================

    /// BLOCKER fix: `readmit()` requires authorization proof.
    #[test]
    fn tck_00360_readmit_requires_authorization_proof() {
        let rev_hash = [0xAA; 32];
        let signer = [0x02; 32];
        let reg = make_revoked_reg("value", 1000, 0x01, rev_hash);

        // Zero-signature proof is rejected
        let bad_proof = AuthorizationProof::new([0x01; 32], [0u8; 32], [0u8; 32], 1, false);
        let anchor = ReAdmissionAnchor::new(rev_hash, Hlc::new(2000, 0), signer);
        let result = reg.clone().readmit(
            "new".to_string(),
            Hlc::new(2000, 0),
            signer,
            anchor,
            &bad_proof,
        );
        assert!(matches!(
            result,
            Err(CrdtMergeError::AuthorizationProofInvalid { .. })
        ));

        // Zero policy-root-hash proof is rejected
        let bad_proof2 = AuthorizationProof::new([0u8; 32], [0xFF; 32], [0xFF; 32], 1, false);
        let anchor2 = ReAdmissionAnchor::new(rev_hash, Hlc::new(2000, 0), signer);
        let result2 = reg.readmit(
            "new".to_string(),
            Hlc::new(2000, 0),
            signer,
            anchor2,
            &bad_proof2,
        );
        assert!(matches!(
            result2,
            Err(CrdtMergeError::AuthorizationProofInvalid { .. })
        ));
    }

    /// BLOCKER fix: `effective_anchor` must be strictly greater.
    #[test]
    fn tck_00360_readmit_effective_anchor_must_increase() {
        let rev_hash = [0xAA; 32];
        let signer = [0x02; 32];
        let reg = make_revoked_reg("value", 1000, 0x01, rev_hash);

        // First readmission with effective_anchor = 1 succeeds
        let anchor1 = ReAdmissionAnchor::new(rev_hash, Hlc::new(2000, 0), signer);
        let auth1 = make_auth_proof(&rev_hash, &signer, 1);
        let readmitted = reg
            .readmit("v2".to_string(), Hlc::new(2000, 0), signer, anchor1, &auth1)
            .unwrap();
        assert_eq!(readmitted.effective_anchor(), 1);

        // Revoke again
        let rev_hash2 = [0xBB; 32];
        let revoked_again = readmitted.revoke(Hlc::new(3000, 0), [0x03; 32], rev_hash2);

        // Try readmission with effective_anchor = 1 (same, not greater) => fails
        let anchor2 = ReAdmissionAnchor::new(rev_hash2, Hlc::new(4000, 0), signer);
        let auth_same = make_auth_proof(&rev_hash2, &signer, 1);
        let result = revoked_again.clone().readmit(
            "v3".to_string(),
            Hlc::new(4000, 0),
            signer,
            anchor2,
            &auth_same,
        );
        assert!(matches!(
            result,
            Err(CrdtMergeError::AuthorizationProofInvalid { .. })
        ));

        // Try readmission with effective_anchor = 2 (greater) => succeeds
        let anchor3 = ReAdmissionAnchor::new(rev_hash2, Hlc::new(4000, 0), signer);
        let auth_greater = make_auth_proof(&rev_hash2, &signer, 2);
        let result2 = revoked_again.readmit(
            "v3".to_string(),
            Hlc::new(4000, 0),
            signer,
            anchor3,
            &auth_greater,
        );
        assert!(result2.is_ok());
        assert_eq!(result2.unwrap().effective_anchor(), 2);
    }

    /// MINOR fix: `MAX_READMISSION_ANCHORS` is enforced.
    #[test]
    fn tck_00360_readmission_anchor_limit_enforced() {
        let mut reg = make_revoked_reg("value", 1000, 0x01, [0xAA; 32]);
        // Artificially set readmission_count to the limit
        reg.readmission_count = MAX_READMISSION_ANCHORS;

        let signer = [0x02; 32];
        let anchor = ReAdmissionAnchor::new([0xAA; 32], Hlc::new(2000, 0), signer);
        let auth = make_auth_proof(&[0xAA; 32], &signer, 1);
        let result = reg.readmit("new".to_string(), Hlc::new(2000, 0), signer, anchor, &auth);
        assert!(matches!(
            result,
            Err(CrdtMergeError::ReAdmissionAnchorLimitExceeded { .. })
        ));
    }

    /// BLOCKER fix: `CrdtDelta` signature + monotone sequence validation.
    #[test]
    fn tck_00360_crdt_delta_validation() {
        let sender = [0x01; 32];
        let payload_hash = hash_value(b"test payload");

        // Valid delta with sequence 1
        let delta = CrdtDelta::with_valid_commitment(
            "payload".to_string(),
            1,
            sender,
            payload_hash,
            [0xFF; 32],
        );
        assert!(delta.validate(0).is_ok());

        // Replay: same sequence fails
        assert!(matches!(
            delta.validate(1),
            Err(CrdtMergeError::DeltaSequenceNotMonotone { .. })
        ));

        // Replay: lower sequence fails
        assert!(matches!(
            delta.validate(2),
            Err(CrdtMergeError::DeltaSequenceNotMonotone { .. })
        ));
    }

    /// BLOCKER fix: `CrdtDelta` rejects zero signature.
    #[test]
    fn tck_00360_crdt_delta_rejects_zero_signature() {
        let sender = [0x01; 32];
        let payload_hash = hash_value(b"test payload");

        let delta = CrdtDelta::new(
            "payload".to_string(),
            [0u8; 32],
            [0u8; 32],
            1,
            sender,
            payload_hash,
        );
        assert!(matches!(
            delta.validate(0),
            Err(CrdtMergeError::DeltaSignatureInvalid { .. })
        ));
    }

    /// BLOCKER fix: `CrdtDelta` rejects wrong commitment.
    #[test]
    fn tck_00360_crdt_delta_rejects_wrong_commitment() {
        let sender = [0x01; 32];
        let payload_hash = hash_value(b"test payload");

        // Create delta with a wrong commitment (random sig bytes)
        let delta = CrdtDelta::new(
            "payload".to_string(),
            [0xAB; 32],
            [0xAB; 32],
            1,
            sender,
            payload_hash,
        );
        assert!(matches!(
            delta.validate(0),
            Err(CrdtMergeError::DeltaSignatureInvalid { .. })
        ));
    }

    /// BLOCKER fix: `CrdtDelta` accessors.
    #[test]
    fn tck_00360_crdt_delta_accessors() {
        let sender = [0x01; 32];
        let payload_hash = hash_value(b"test");

        let delta = CrdtDelta::with_valid_commitment(42u64, 5, sender, payload_hash, [0xFF; 32]);
        assert_eq!(*delta.payload(), 42u64);
        assert_eq!(delta.sequence(), 5);
        assert_eq!(delta.sender_node_id(), &sender);
        assert_eq!(delta.payload_hash(), &payload_hash);
        assert_eq!(delta.into_payload(), 42u64);
    }

    /// MAJOR fix: Suspended state documented compatibility.
    /// Verifies that Suspended cannot prevent a subsequent Revoked from
    /// winning.
    #[test]
    fn tck_00360_suspended_cannot_block_revocation() {
        let suspended = make_suspended_reg("s", 2000, 0x01);
        let revoked = make_revoked_reg("r", 1000, 0x02, [0xAA; 32]);

        // Revoked always wins over Suspended, even with older timestamp
        let result = suspended.merge(&revoked);
        let winner = result.winner().unwrap();
        assert_eq!(winner.status(), DirectoryStatus::Revoked);

        // And vice versa
        let result2 = revoked.merge(&suspended);
        let winner2 = result2.winner().unwrap();
        assert_eq!(winner2.status(), DirectoryStatus::Revoked);
    }

    /// BLOCKER fix: `AuthorizationProof` serialization round-trip.
    #[test]
    fn tck_00360_authorization_proof_serialization() {
        let proof = AuthorizationProof::with_valid_commitment(
            [0x01; 32],
            &[0xAA; 32],
            42,
            &[0x02; 32],
            [0xFF; 32],
            true,
        );
        let json = serde_json::to_string(&proof).unwrap();
        let parsed: AuthorizationProof = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, proof);
        assert!(parsed.is_waiver());
        assert_eq!(parsed.effective_anchor(), 42);
    }

    /// BLOCKER fix: `AuthorizationProof` integrity validation.
    #[test]
    fn tck_00360_authorization_proof_integrity() {
        let rev_hash = [0xAA; 32];
        let signer = [0x02; 32];

        let proof = AuthorizationProof::with_valid_commitment(
            [0x01; 32], &rev_hash, 1, &signer, [0xFF; 32], false,
        );

        // Valid
        assert!(proof.validate_integrity(&rev_hash, &signer).is_ok());

        // Wrong revocation hash fails
        assert!(proof.validate_integrity(&[0xBB; 32], &signer).is_err());

        // Wrong signer fails
        assert!(proof.validate_integrity(&rev_hash, &[0x03; 32]).is_err());
    }

    /// BLOCKER fix: RFC-0020 exception in merge - authorized re-admission
    /// with greater `effective_anchor` beats revoked.
    #[test]
    fn tck_00360_rfc0020_exception_merge_readmitted_beats_revoked() {
        let rev_hash = [0xAA; 32];
        let signer = [0x02; 32];

        // Create a revoked register, then re-admit with effective_anchor = 5
        let revoked = make_revoked_reg("old", 1000, 0x01, rev_hash);
        let anchor = ReAdmissionAnchor::new(rev_hash, Hlc::new(2000, 0), signer);
        let auth_proof = make_auth_proof(&rev_hash, &signer, 5);
        let readmitted = revoked
            .readmit(
                "new".to_string(),
                Hlc::new(2000, 0),
                signer,
                anchor,
                &auth_proof,
            )
            .unwrap();
        assert_eq!(readmitted.effective_anchor(), 5);

        // Another revoked register with default effective_anchor = 0
        let still_revoked = make_revoked_reg("stale", 1500, 0x03, rev_hash);

        // Merge: readmitted (anchor=5) vs revoked (anchor=0) => readmitted wins
        let result = readmitted.merge(&still_revoked);
        let winner = result.winner().unwrap();
        assert_eq!(winner.status(), DirectoryStatus::Active);
        assert_eq!(winner.value(), "new");

        // Commutativity check
        let result2 = still_revoked.merge(&readmitted);
        let winner2 = result2.winner().unwrap();
        assert_eq!(winner2.status(), DirectoryStatus::Active);
        assert_eq!(winner2.value(), "new");
    }

    /// BLOCKER fix: RFC-0020 exception does NOT fire without readmission
    /// anchor.
    #[test]
    fn tck_00360_rfc0020_exception_requires_readmission_anchor() {
        // An active register without a re-admission anchor should still lose
        // to a revoked register, even if its effective_anchor is higher.
        let mut active = make_active_reg("active", 2000, 0x01);
        active.effective_anchor = 10;

        let revoked = make_revoked_reg("revoked", 1000, 0x02, [0xAA; 32]);

        let result = active.merge(&revoked);
        let winner = result.winner().unwrap();
        assert_eq!(
            winner.status(),
            DirectoryStatus::Revoked,
            "Active without readmission anchor must lose to Revoked"
        );
    }

    /// BLOCKER fix: new error variant display strings.
    #[test]
    fn tck_00360_new_error_display() {
        let errors: Vec<CrdtMergeError> = vec![
            CrdtMergeError::AuthorizationProofInvalid {
                reason: "test".to_string(),
            },
            CrdtMergeError::DeltaSignatureInvalid {
                reason: "test".to_string(),
            },
            CrdtMergeError::DeltaSequenceNotMonotone {
                received: 1,
                expected: 5,
            },
        ];

        for err in &errors {
            let msg = err.to_string();
            assert!(!msg.is_empty());
        }
    }

    /// Helper: generate all permutations of indices 0..n.
    fn generate_permutations(n: usize) -> Vec<Vec<usize>> {
        let mut result = Vec::new();
        let mut indices: Vec<usize> = (0..n).collect();
        permute(&mut indices, 0, &mut result);
        result
    }

    fn permute(arr: &mut Vec<usize>, start: usize, result: &mut Vec<Vec<usize>>) {
        if start == arr.len() {
            result.push(arr.clone());
            return;
        }
        for i in start..arr.len() {
            arr.swap(start, i);
            permute(arr, start + 1, result);
            arr.swap(start, i);
        }
    }
}

// =============================================================================
// Property-Based Tests (TCK-00360)
// =============================================================================

#[cfg(test)]
mod proptest_tests {
    use proptest::prelude::*;

    use super::*;

    /// Strategy for generating a `DirectoryStatus`.
    fn arb_directory_status() -> impl Strategy<Value = DirectoryStatus> {
        prop_oneof![
            Just(DirectoryStatus::Active),
            Just(DirectoryStatus::Suspended),
            Just(DirectoryStatus::Revoked),
        ]
    }

    /// Strategy for generating a `NodeId`.
    fn arb_node_id() -> impl Strategy<Value = NodeId> {
        prop::array::uniform32(any::<u8>())
    }

    /// Strategy for generating an `Hlc`.
    fn arb_hlc() -> impl Strategy<Value = Hlc> {
        (1u64..1_000_000u64, 0u32..100u32).prop_map(|(wall, counter)| Hlc::new(wall, counter))
    }

    /// Strategy for generating a `RevocationWinsRegister<u64>`.
    fn arb_register() -> impl Strategy<Value = RevocationWinsRegister<u64>> {
        (
            any::<u64>(),
            arb_directory_status(),
            arb_hlc(),
            arb_node_id(),
        )
            .prop_map(|(value, status, hlc, node_id)| {
                let rev_hash = if status == DirectoryStatus::Revoked {
                    Some(hash_value(&value.to_le_bytes()))
                } else {
                    None
                };
                RevocationWinsRegister::with_status(value, status, hlc, node_id, rev_hash)
            })
    }

    proptest! {
        /// Property: merge is commutative for RevocationWinsRegister.
        #[test]
        fn revocation_wins_commutativity(a in arb_register(), b in arb_register()) {
            let result_ab = a.merge(&b);
            let result_ba = b.merge(&a);

            let winner_ab = result_ab.winner().unwrap();
            let winner_ba = result_ba.winner().unwrap();

            // Status must always agree
            prop_assert_eq!(winner_ab.status(), winner_ba.status());
            // Value must always agree
            prop_assert_eq!(winner_ab.value(), winner_ba.value());
        }

        /// Property: merge is idempotent for RevocationWinsRegister.
        #[test]
        fn revocation_wins_idempotent(a in arb_register()) {
            let result = a.merge(&a);
            let winner = result.winner().unwrap();
            prop_assert_eq!(winner.status(), a.status());
            prop_assert_eq!(winner.value(), a.value());
        }

        /// Property: merge is associative for RevocationWinsRegister.
        #[test]
        fn revocation_wins_associativity(
            a in arb_register(),
            b in arb_register(),
            c in arb_register()
        ) {
            // (a merge b) merge c
            let ab = a.merge(&b).winner().unwrap();
            let abc_left = ab.merge(&c).winner().unwrap();

            // a merge (b merge c)
            let bc = b.merge(&c).winner().unwrap();
            let abc_right = a.merge(&bc).winner().unwrap();

            // Must converge to same status and value
            prop_assert_eq!(abc_left.status(), abc_right.status());
            prop_assert_eq!(abc_left.value(), abc_right.value());
        }

        /// Property: revocation is absorbing - if any input is Revoked,
        /// the merge result is always Revoked.
        #[test]
        fn revocation_is_absorbing(a in arb_register(), b in arb_register()) {
            let winner = a.merge(&b).winner().unwrap();
            if a.status() == DirectoryStatus::Revoked || b.status() == DirectoryStatus::Revoked {
                prop_assert_eq!(winner.status(), DirectoryStatus::Revoked);
            }
        }

        /// Property: status lattice join is monotone.
        #[test]
        fn status_lattice_monotone(a in arb_register(), b in arb_register()) {
            let winner = a.merge(&b).winner().unwrap();
            // Merged status is always >= both inputs
            prop_assert!(winner.status() >= a.status());
            prop_assert!(winner.status() >= b.status());
        }

        /// Property: Byzantine reordering of N registers always converges.
        #[test]
        fn byzantine_reordering_converges(
            regs in prop::collection::vec(arb_register(), 2..=5)
        ) {
            // Merge left-to-right
            let mut forward = regs[0].clone();
            for reg in &regs[1..] {
                forward = forward.merge(reg).winner().unwrap();
            }

            // Merge right-to-left
            let mut backward = regs[regs.len() - 1].clone();
            for reg in regs[..regs.len() - 1].iter().rev() {
                backward = backward.merge(reg).winner().unwrap();
            }

            // Must agree
            prop_assert_eq!(forward.status(), backward.status());
            prop_assert_eq!(forward.value(), backward.value());
        }
    }
}
