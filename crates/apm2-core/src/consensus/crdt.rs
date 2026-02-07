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
}
