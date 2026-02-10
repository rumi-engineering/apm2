// AGENT-AUTHORED
//! Anti-entropy gossip protocol for event log synchronization.
//!
//! This module implements a pull-based anti-entropy protocol using Merkle tree
//! digests to efficiently identify and transfer missing events between peers.
//!
//! # Protocol Overview
//!
//! 1. **Digest Exchange**: Peers exchange Merkle tree root digests
//! 2. **Range Comparison**: On mismatch, recursively compare subtree digests to
//!    find divergent ranges
//! 3. **Event Transfer**: Pull missing events for divergent ranges
//! 4. **Verification**: Verify received events before integrating
//!
//! # Security Properties
//!
//! - **Pull-Based**: Prevents byzantine event spread (INV-0024)
//! - **Rate Limiting**: Bounded requests per peer per interval (INV-0025)
//! - **Verification**: All received events verified before integration
//! - **Bounded Sync**: Maximum events per sync batch prevents memory exhaustion
//!
//! # References
//!
//! - RFC-0014: Distributed Consensus and Replication Layer (DD-0006)
//! - Demers et al. "Epidemic Algorithms for Replicated Database Maintenance."
//!   PODC 1987.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use thiserror::Error;

use super::merkle::{DivergentRange, MerkleError, MerkleProof, MerkleTree};
use crate::crypto::{EventHasher, HASH_SIZE, Hash};
use crate::ledger::EventRecord;

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of events to request in a single sync batch.
///
/// Bounded to prevent memory exhaustion from large sync requests.
///
/// # Data Plane vs Control Plane
///
/// Note that `MAX_SYNC_BATCH_SIZE` (1000 events) exceeds `CONTROL_FRAME_SIZE`
/// (1024 bytes). This is intentional: anti-entropy event transfer uses the
/// **data plane** with larger frame sizes, not the control plane. The control
/// plane is used only for protocol negotiation and small metadata exchanges.
///
/// Event batches are serialized and transmitted over the data plane, which
/// supports frames sized to accommodate the serialized batch (typically using
/// length-prefixed framing or chunked transfer).
pub const MAX_SYNC_BATCH_SIZE: usize = 1000;

/// Maximum number of divergent ranges to process per sync round.
///
/// Limits work per round to prevent CPU exhaustion.
pub const MAX_DIVERGENT_RANGES: usize = 100;

/// Maximum number of pending sync requests per peer.
///
/// Prevents a single peer from overwhelming with requests.
pub const MAX_PENDING_REQUESTS_PER_PEER: usize = 10;

/// Rate limit: maximum sync requests per peer per interval.
pub const MAX_REQUESTS_PER_INTERVAL: u32 = 100;

/// Rate limit interval duration.
pub const RATE_LIMIT_INTERVAL: Duration = Duration::from_secs(60);

/// Maximum age of a cached tree digest (for `DoS` prevention).
///
/// This constant defines the maximum time a cached Merkle tree digest should
/// be considered valid. Implementations using digest caching should expire
/// entries older than this duration to prevent serving stale data and to
/// bound memory usage.
///
/// Note: This constant is provided for future caching implementations and
/// external consumers. The current in-memory sync protocol does not cache
/// digests between sync sessions.
pub const MAX_DIGEST_CACHE_AGE: Duration = Duration::from_secs(300);

/// Maximum number of peers to track in rate limiter.
///
/// Bounded to prevent memory exhaustion from tracking many peers.
pub const MAX_RATE_LIMIT_PEERS: usize = 1000;

/// Maximum tree depth for comparison (`DoS` prevention).
///
/// This constant bounds the maximum depth of tree comparison operations
/// to prevent resource exhaustion attacks. The Merkle tree implementation
/// uses iterative BFS traversal (not recursion), so stack exhaustion is
/// not a concern. However, this constant is enforced during remote sync
/// operations to prevent malicious peers from requesting comparisons at
/// excessive depths.
///
/// The value of 32 supports trees with up to 2^32 leaves, which is well
/// above `MAX_TREE_LEAVES` (2^20). This provides headroom for future
/// expansion while maintaining safety bounds.
///
/// See also: `merkle::MAX_TREE_DEPTH` for the actual tree depth limit.
pub const MAX_COMPARISON_DEPTH: usize = 32;

/// Default sync interval for periodic anti-entropy.
pub const DEFAULT_SYNC_INTERVAL: Duration = Duration::from_secs(30);

/// Session timeout duration for stale session cleanup.
///
/// Sessions that have not had activity within this duration will be
/// automatically cleaned up to prevent session slot exhaustion attacks.
/// This bounds the time an attacker can hold session slots without
/// performing legitimate sync operations.
pub const SESSION_TIMEOUT: Duration = Duration::from_secs(60);

// ============================================================================
// Errors
// ============================================================================

/// Errors that can occur during anti-entropy operations.
#[derive(Debug, Error)]
pub enum AntiEntropyError {
    /// Merkle tree operation failed.
    #[error("merkle tree error: {0}")]
    MerkleError(#[from] MerkleError),

    /// Rate limit exceeded for peer.
    #[error("rate limit exceeded for peer {peer_id}")]
    RateLimitExceeded {
        /// The peer that exceeded the rate limit.
        peer_id: String,
    },

    /// Too many pending requests for peer.
    #[error("too many pending requests for peer {peer_id}")]
    TooManyPendingRequests {
        /// The peer with too many pending requests.
        peer_id: String,
    },

    /// Too many tracked peers in rate limiter.
    ///
    /// This error is returned when the rate limiter has reached its maximum
    /// capacity for tracked peers (`MAX_RATE_LIMIT_PEERS`) and cannot accept
    /// new peer requests. This prevents memory exhaustion from Sybil attacks.
    #[error(
        "rate limiter at capacity ({} peers), cannot track new peer {peer_id}",
        MAX_RATE_LIMIT_PEERS
    )]
    RateLimiterAtCapacity {
        /// The peer that was rejected.
        peer_id: String,
    },

    /// Invalid sync request.
    #[error("invalid sync request: {0}")]
    InvalidRequest(String),

    /// Invalid sync response.
    #[error("invalid sync response: {0}")]
    InvalidResponse(String),

    /// Event verification failed.
    #[error("event verification failed at seq_id {seq_id}: {reason}")]
    EventVerificationFailed {
        /// The sequence ID of the event.
        seq_id: u64,
        /// The reason for failure.
        reason: String,
    },

    /// Hash chain verification failed.
    #[error("hash chain broken at seq_id {seq_id}")]
    HashChainBroken {
        /// The sequence ID where the chain broke.
        seq_id: u64,
    },

    /// Sequence ID monotonicity violation.
    ///
    /// Sequence IDs must be strictly increasing. This error is returned
    /// when a non-increasing `seq_id` is detected, which could indicate
    /// a replay attack or data corruption.
    #[error("seq_id not strictly increasing: {current} <= {previous}")]
    SeqIdNotIncreasing {
        /// The current `seq_id` that violated monotonicity.
        current: u64,
        /// The previous `seq_id`.
        previous: u64,
    },

    /// Sequence ID continuity violation.
    ///
    /// The first event's `seq_id` does not match the expected starting
    /// `seq_id`. This indicates a gap in the event sequence which could
    /// indicate missing events or a sync protocol error.
    #[error("seq_id continuity broken: expected {expected}, got {actual}")]
    SeqIdContinuityBroken {
        /// The expected starting `seq_id`.
        expected: u64,
        /// The actual `seq_id` of the first event.
        actual: u64,
    },

    /// Sync batch too large.
    #[error("sync batch size {size} exceeds limit {}", MAX_SYNC_BATCH_SIZE)]
    BatchTooLarge {
        /// The requested batch size.
        size: usize,
    },

    /// Too many divergent ranges.
    #[error(
        "too many divergent ranges: {count} exceeds limit {}",
        MAX_DIVERGENT_RANGES
    )]
    TooManyDivergentRanges {
        /// The number of divergent ranges found.
        count: usize,
    },

    /// Comparison depth exceeds limit.
    ///
    /// This error is returned when a compare request specifies a range
    /// that would require traversing deeper than `MAX_COMPARISON_DEPTH`.
    /// This prevents `DoS` attacks via deeply nested comparison requests.
    #[error("comparison depth {depth} exceeds limit {}", MAX_COMPARISON_DEPTH)]
    ComparisonDepthExceeded {
        /// The requested comparison depth.
        depth: usize,
    },

    /// Index overflow during u64 to usize conversion.
    ///
    /// On 32-bit platforms, `u64` indices may exceed `usize::MAX`. This error
    /// is returned when a range index cannot be safely converted to `usize`,
    /// preventing truncation and potential security issues.
    #[error("index {index} overflows usize (max: {})", usize::MAX)]
    IndexOverflow {
        /// The u64 index that could not be converted.
        index: u64,
    },
}

// ============================================================================
// Protocol Messages
// ============================================================================

/// A request to exchange Merkle tree digests.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DigestRequest {
    /// The namespace being synchronized.
    pub namespace: String,
    /// Sequence range [start, end) to build tree for.
    pub range: (u64, u64),
    /// Requesting peer's ID.
    pub peer_id: String,
    /// Request timestamp for freshness validation.
    pub timestamp_ns: u64,
}

/// A response containing the Merkle tree root digest.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DigestResponse {
    /// The namespace being synchronized.
    pub namespace: String,
    /// Sequence range [start, end) the tree covers.
    pub range: (u64, u64),
    /// Root hash of the Merkle tree.
    pub root_hash: Hash,
    /// Number of events in the tree.
    pub event_count: u64,
    /// Responding peer's ID.
    pub peer_id: String,
}

/// A request to compare subtrees at specific ranges.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompareRequest {
    /// The namespace being synchronized.
    pub namespace: String,
    /// Ranges to compare, with expected local hashes.
    pub ranges: Vec<RangeQuery>,
    /// Requesting peer's ID.
    pub peer_id: String,
}

/// A single range query with expected hash.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RangeQuery {
    /// Sequence range [start, end).
    pub range: (u64, u64),
    /// Expected hash for this range (from local tree).
    pub expected_hash: Hash,
}

/// A response with subtree digests for comparison.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompareResponse {
    /// The namespace being synchronized.
    pub namespace: String,
    /// Digests for each queried range.
    pub digests: Vec<RangeDigestResult>,
    /// Responding peer's ID.
    pub peer_id: String,
}

/// Result of comparing a single range.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RangeDigestResult {
    /// Sequence range [start, end).
    pub range: (u64, u64),
    /// Hash for this range.
    pub hash: Hash,
    /// Whether this range matches the queried expected hash.
    pub matches: bool,
    /// Child hashes if range doesn't match (for recursive comparison).
    pub children: Option<(Hash, Hash)>,
}

/// A request to transfer events for a range.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventRequest {
    /// The namespace being synchronized.
    pub namespace: String,
    /// Sequence range [start, end) to fetch.
    pub range: (u64, u64),
    /// Maximum number of events to return.
    pub limit: usize,
    /// Requesting peer's ID.
    pub peer_id: String,
}

/// A response containing events for a range.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventResponse {
    /// The namespace being synchronized.
    pub namespace: String,
    /// Sequence range [start, end) included.
    pub range: (u64, u64),
    /// Events in the range (serialized).
    pub events: Vec<SyncEvent>,
    /// Whether there are more events in this range.
    pub has_more: bool,
    /// Responding peer's ID.
    pub peer_id: String,
}

/// A compact event representation for sync.
///
/// # Security Note
///
/// `SyncEvent` does not include `signature` or `actor_id` fields. This is
/// intentional: sync events are verified by their hash chain linkage
/// (`prev_hash` -> `event_hash`) and Merkle proof membership. The hash chain
/// provides integrity, while the Merkle proof provides authenticity relative to
/// a trusted root.
///
/// If actor-level provenance is needed, the full event record should be
/// retrieved from the ledger after sync verification completes.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncEvent {
    /// Sequence ID.
    pub seq_id: u64,
    /// Event type.
    pub event_type: String,
    /// Event payload.
    #[serde(with = "serde_bytes")]
    pub payload: Vec<u8>,
    /// Previous event hash.
    pub prev_hash: Hash,
    /// This event's hash.
    pub event_hash: Hash,
    /// Event timestamp.
    pub timestamp_ns: u64,
}

// ============================================================================
// Rate Limiter
// ============================================================================

/// Rate limiter for sync requests per peer.
#[derive(Debug)]
pub struct SyncRateLimiter {
    /// Request counts per peer.
    requests: HashMap<String, (u32, Instant)>,
    /// Maximum requests per interval.
    max_requests: u32,
    /// Rate limit interval.
    interval: Duration,
}

impl SyncRateLimiter {
    /// Creates a new rate limiter with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            requests: HashMap::new(),
            max_requests: MAX_REQUESTS_PER_INTERVAL,
            interval: RATE_LIMIT_INTERVAL,
        }
    }

    /// Creates a rate limiter with custom settings.
    #[must_use]
    pub fn with_config(max_requests: u32, interval: Duration) -> Self {
        Self {
            requests: HashMap::new(),
            max_requests,
            interval,
        }
    }

    /// Checks if a request from a peer is allowed.
    ///
    /// Returns `Ok(())` if allowed, `Err` if rate limited or at capacity.
    ///
    /// # Errors
    ///
    /// Returns `AntiEntropyError::RateLimitExceeded` if the peer has exceeded
    /// the rate limit for this interval.
    ///
    /// Returns `AntiEntropyError::RateLimiterAtCapacity` if the rate limiter
    /// is tracking the maximum number of peers and cannot accept new peers.
    /// This prevents memory exhaustion from Sybil attacks where an attacker
    /// floods the node with requests from unique peer IDs.
    pub fn check(&mut self, peer_id: &str) -> Result<(), AntiEntropyError> {
        let now = Instant::now();

        // Check if peer is already tracked (existing peers always allowed through)
        if let Some((count, last_reset)) = self.requests.get_mut(peer_id) {
            if now.duration_since(*last_reset) >= self.interval {
                // Reset for new interval
                *count = 1;
                *last_reset = now;
                Ok(())
            } else if *count >= self.max_requests {
                Err(AntiEntropyError::RateLimitExceeded {
                    peer_id: peer_id.to_string(),
                })
            } else {
                *count += 1;
                Ok(())
            }
        } else {
            // New peer - check capacity before adding
            // First, try to clean up expired entries if at capacity
            if self.requests.len() >= MAX_RATE_LIMIT_PEERS {
                self.requests
                    .retain(|_, (_, last)| now.duration_since(*last) < self.interval);
            }

            // SECURITY: Explicit capacity check after cleanup (fail-closed).
            // We use strict less-than to ensure we're actually under capacity,
            // not just at the boundary. This prevents any edge case where
            // cleanup + immediate insert could exceed capacity.
            if self.requests.len() >= MAX_RATE_LIMIT_PEERS {
                return Err(AntiEntropyError::RateLimiterAtCapacity {
                    peer_id: peer_id.to_string(),
                });
            }

            // Final capacity check before insert to prevent TOCTOU issues.
            // This is defensive - the check above should have caught it,
            // but we verify again immediately before mutation.
            debug_assert!(
                self.requests.len() < MAX_RATE_LIMIT_PEERS,
                "capacity check should have rejected at-capacity state"
            );

            self.requests.insert(peer_id.to_string(), (1, now));
            Ok(())
        }
    }

    /// Returns the current request count for a peer.
    #[must_use]
    pub fn get_count(&self, peer_id: &str) -> u32 {
        self.requests.get(peer_id).map_or(0, |(count, _)| *count)
    }

    /// Resets rate limit for a peer.
    pub fn reset(&mut self, peer_id: &str) {
        self.requests.remove(peer_id);
    }

    /// Clears all rate limit entries.
    pub fn clear(&mut self) {
        self.requests.clear();
    }
}

impl Default for SyncRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Sync State
// ============================================================================

/// State for an ongoing sync session with a peer.
#[derive(Debug)]
pub struct SyncSession {
    /// The peer we're syncing with.
    pub peer_id: String,
    /// The namespace being synchronized.
    pub namespace: String,
    /// Local Merkle tree for the namespace.
    pub local_tree: MerkleTree,
    /// Divergent ranges identified so far.
    pub divergent_ranges: Vec<DivergentRange>,
    /// Ranges already processed.
    pub processed_ranges: Vec<(u64, u64)>,
    /// Session start time.
    pub started_at: Instant,
    /// Last activity time for session timeout tracking.
    ///
    /// Updated whenever meaningful sync activity occurs (digest exchange,
    /// range comparison, event transfer). Used by `cleanup_stale_sessions()`
    /// to evict abandoned sessions.
    pub last_activity: Instant,
    /// Number of events synced.
    pub events_synced: u64,
}

impl SyncSession {
    /// Creates a new sync session.
    #[must_use]
    pub fn new(peer_id: String, namespace: String, local_tree: MerkleTree) -> Self {
        let now = Instant::now();
        Self {
            peer_id,
            namespace,
            local_tree,
            divergent_ranges: Vec::new(),
            processed_ranges: Vec::new(),
            started_at: now,
            last_activity: now,
            events_synced: 0,
        }
    }

    /// Updates the last activity timestamp to the current time.
    ///
    /// Call this method whenever meaningful sync activity occurs to
    /// prevent the session from being cleaned up as stale.
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Checks if this session is stale (no activity within timeout).
    #[must_use]
    pub fn is_stale(&self, timeout: Duration) -> bool {
        self.last_activity.elapsed() >= timeout
    }

    /// Returns the session duration.
    #[must_use]
    pub fn duration(&self) -> Duration {
        self.started_at.elapsed()
    }

    /// Checks if all divergent ranges have been processed.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.divergent_ranges.is_empty()
            || self
                .divergent_ranges
                .iter()
                .all(|r| self.is_range_processed(r.start, r.end))
    }

    /// Checks if a range has been processed.
    #[must_use]
    pub fn is_range_processed(&self, start: usize, end: usize) -> bool {
        self.processed_ranges
            .iter()
            .any(|(s, e)| *s <= start as u64 && *e >= end as u64)
    }

    /// Marks a range as processed.
    pub fn mark_processed(&mut self, start: u64, end: u64) {
        self.processed_ranges.push((start, end));
    }
}

// ============================================================================
// Anti-Entropy Engine
// ============================================================================

/// The anti-entropy engine coordinates synchronization with peers.
#[derive(Debug)]
pub struct AntiEntropyEngine {
    /// Rate limiter for incoming requests.
    rate_limiter: SyncRateLimiter,
    /// Active sync sessions by peer ID.
    sessions: HashMap<String, SyncSession>,
    /// Maximum concurrent sessions.
    max_sessions: usize,
}

impl AntiEntropyEngine {
    /// Creates a new anti-entropy engine with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            rate_limiter: SyncRateLimiter::new(),
            sessions: HashMap::new(),
            max_sessions: 10,
        }
    }

    /// Creates an engine with custom settings.
    #[must_use]
    pub fn with_config(rate_limiter: SyncRateLimiter, max_sessions: usize) -> Self {
        Self {
            rate_limiter,
            sessions: HashMap::new(),
            max_sessions,
        }
    }

    /// Builds a Merkle tree from event hashes.
    ///
    /// # Errors
    ///
    /// Returns an error if the tree cannot be constructed.
    pub fn build_tree(&self, event_hashes: &[Hash]) -> Result<MerkleTree, AntiEntropyError> {
        Ok(MerkleTree::new(event_hashes.iter().copied())?)
    }

    /// Cleans up stale sessions that have exceeded the timeout duration.
    ///
    /// This method removes sessions that have not had any activity within
    /// `SESSION_TIMEOUT`. Call this before checking session limits to prevent
    /// session slot exhaustion attacks where an attacker occupies all slots
    /// indefinitely.
    ///
    /// Returns the number of sessions cleaned up.
    pub fn cleanup_stale_sessions(&mut self) -> usize {
        let before = self.sessions.len();
        self.sessions
            .retain(|_, session| !session.is_stale(SESSION_TIMEOUT));
        before - self.sessions.len()
    }

    /// Cleans up stale sessions using a custom timeout duration.
    ///
    /// This is useful for testing or for use cases that need different
    /// timeout values.
    ///
    /// Returns the number of sessions cleaned up.
    pub fn cleanup_stale_sessions_with_timeout(&mut self, timeout: Duration) -> usize {
        let before = self.sessions.len();
        self.sessions
            .retain(|_, session| !session.is_stale(timeout));
        before - self.sessions.len()
    }

    /// Starts a new sync session with a peer.
    ///
    /// # Errors
    ///
    /// Returns an error if rate limited or too many sessions.
    ///
    /// # Errors
    ///
    /// Returns an error if rate limited or too many pending sessions.
    pub fn start_session(
        &mut self,
        peer_id: &str,
        namespace: &str,
        local_tree: MerkleTree,
    ) -> Result<&mut SyncSession, AntiEntropyError> {
        use std::collections::hash_map::Entry;

        self.rate_limiter.check(peer_id)?;

        // Clean up stale sessions before checking the limit to prevent
        // session slot exhaustion attacks (INV-0024 related).
        self.cleanup_stale_sessions();

        if self.sessions.len() >= self.max_sessions && !self.sessions.contains_key(peer_id) {
            return Err(AntiEntropyError::TooManyPendingRequests {
                peer_id: peer_id.to_string(),
            });
        }

        let session = match self.sessions.entry(peer_id.to_string()) {
            Entry::Occupied(entry) => {
                let session = entry.into_mut();
                // Refresh activity timestamp for existing session
                session.touch();
                session
            },
            Entry::Vacant(entry) => entry.insert(SyncSession::new(
                peer_id.to_string(),
                namespace.to_string(),
                local_tree,
            )),
        };

        Ok(session)
    }

    /// Gets an active session for a peer.
    #[must_use]
    pub fn get_session(&self, peer_id: &str) -> Option<&SyncSession> {
        self.sessions.get(peer_id)
    }

    /// Gets a mutable reference to an active session.
    #[must_use]
    pub fn get_session_mut(&mut self, peer_id: &str) -> Option<&mut SyncSession> {
        self.sessions.get_mut(peer_id)
    }

    /// Ends a sync session.
    pub fn end_session(&mut self, peer_id: &str) -> Option<SyncSession> {
        self.sessions.remove(peer_id)
    }

    /// Handles a digest request from a peer.
    ///
    /// # Errors
    ///
    /// Returns an error if rate limited.
    pub fn handle_digest_request(
        &mut self,
        request: &DigestRequest,
        local_tree: &MerkleTree,
    ) -> Result<DigestResponse, AntiEntropyError> {
        self.rate_limiter.check(&request.peer_id)?;

        Ok(DigestResponse {
            namespace: request.namespace.clone(),
            range: request.range,
            root_hash: local_tree.root(),
            event_count: local_tree.leaf_count() as u64,
            peer_id: request.peer_id.clone(),
        })
    }

    /// Handles a compare request from a peer.
    ///
    /// # Errors
    ///
    /// Returns an error if rate limited, invalid request, or comparison
    /// depth exceeds `MAX_COMPARISON_DEPTH`.
    pub fn handle_compare_request(
        &mut self,
        request: &CompareRequest,
        local_tree: &MerkleTree,
    ) -> Result<CompareResponse, AntiEntropyError> {
        self.rate_limiter.check(&request.peer_id)?;

        if request.ranges.len() > MAX_DIVERGENT_RANGES {
            return Err(AntiEntropyError::TooManyDivergentRanges {
                count: request.ranges.len(),
            });
        }

        let mut digests = Vec::with_capacity(request.ranges.len());

        for query in &request.ranges {
            // SECURITY: Use try_from to safely convert u64 to usize.
            // On 32-bit platforms, u64 values may exceed usize::MAX, causing
            // truncation with `as usize`. This would be a security issue as it
            // could allow accessing unintended tree indices.
            let start =
                usize::try_from(query.range.0).map_err(|_| AntiEntropyError::IndexOverflow {
                    index: query.range.0,
                })?;
            let end =
                usize::try_from(query.range.1).map_err(|_| AntiEntropyError::IndexOverflow {
                    index: query.range.1,
                })?;

            // Validate comparison depth to prevent DoS via deeply nested requests.
            // Depth is computed as log2(range_size), bounded by MAX_COMPARISON_DEPTH.
            let range_size = end.saturating_sub(start);
            if range_size > 0 {
                // Calculate the depth required to represent this range
                // depth = ceil(log2(range_size)) when range_size > 1
                let depth = if range_size <= 1 {
                    0
                } else {
                    usize::BITS as usize - range_size.leading_zeros() as usize
                };
                if depth > MAX_COMPARISON_DEPTH {
                    return Err(AntiEntropyError::ComparisonDepthExceeded { depth });
                }
            }

            // Get local digest for this range
            let local_digest = local_tree
                .range_digest(start, end)
                .map_err(|e| AntiEntropyError::InvalidRequest(e.to_string()))?;

            let matches = local_digest.hash == query.expected_hash;

            // If mismatch and not at leaf level, provide child hashes
            let children = if !matches && end - start > 1 {
                let mid = usize::midpoint(start, end);
                let left = local_tree.range_digest(start, mid).ok();
                let right = local_tree.range_digest(mid, end).ok();
                match (left, right) {
                    (Some(l), Some(r)) => Some((l.hash, r.hash)),
                    _ => None,
                }
            } else {
                None
            };

            digests.push(RangeDigestResult {
                range: query.range,
                hash: local_digest.hash,
                matches,
                children,
            });
        }

        Ok(CompareResponse {
            namespace: request.namespace.clone(),
            digests,
            peer_id: request.peer_id.clone(),
        })
    }

    /// Handles an event request from a peer.
    ///
    /// # Arguments
    ///
    /// * `request` - The event request.
    /// * `fetch_events` - Closure to fetch events from storage.
    ///
    /// # Errors
    ///
    /// Returns an error if rate limited or batch too large.
    pub fn handle_event_request<F>(
        &mut self,
        request: &EventRequest,
        fetch_events: F,
    ) -> Result<EventResponse, AntiEntropyError>
    where
        F: FnOnce(u64, u64, usize) -> Vec<SyncEvent>,
    {
        self.rate_limiter.check(&request.peer_id)?;

        if request.limit > MAX_SYNC_BATCH_SIZE {
            return Err(AntiEntropyError::BatchTooLarge {
                size: request.limit,
            });
        }

        let events = fetch_events(request.range.0, request.range.1, request.limit);
        let actual_end = events.last().map_or(request.range.0, |e| e.seq_id + 1);
        let has_more = actual_end < request.range.1 && events.len() >= request.limit;

        Ok(EventResponse {
            namespace: request.namespace.clone(),
            range: (request.range.0, actual_end),
            events,
            has_more,
            peer_id: request.peer_id.clone(),
        })
    }

    /// Compares local and remote trees to find divergent ranges.
    ///
    /// # Errors
    ///
    /// Returns an error if too many divergent ranges are found.
    pub fn find_divergences(
        &self,
        local_tree: &MerkleTree,
        remote_tree: &MerkleTree,
    ) -> Result<Vec<DivergentRange>, AntiEntropyError> {
        let divergent = local_tree.find_divergent_ranges(remote_tree);

        if divergent.len() > MAX_DIVERGENT_RANGES {
            return Err(AntiEntropyError::TooManyDivergentRanges {
                count: divergent.len(),
            });
        }

        Ok(divergent)
    }

    /// Returns the number of active sessions.
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Returns a reference to the rate limiter.
    #[must_use]
    pub const fn rate_limiter(&self) -> &SyncRateLimiter {
        &self.rate_limiter
    }

    /// Returns a mutable reference to the rate limiter.
    #[must_use]
    pub const fn rate_limiter_mut(&mut self) -> &mut SyncRateLimiter {
        &mut self.rate_limiter
    }
}

impl Default for AntiEntropyEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Event Verification
// ============================================================================

/// Verifies a batch of sync events for integrity.
///
/// Checks that:
/// 1. Sequence IDs are strictly increasing (monotonicity)
/// 2. Event hashes are correct
/// 3. Hash chain is valid (each event links to previous)
///
/// # Arguments
///
/// * `events` - Events to verify.
/// * `expected_prev_hash` - Expected previous hash for the first event.
///
/// # Errors
///
/// Returns an error if any event fails verification.
///
/// # Security Note
///
/// Since `EventHasher` does not include `seq_id` in the hash computation,
/// this function explicitly verifies `seq_id` monotonicity to prevent attacks
/// where a malicious peer provides events with spoofed `seq_ids`.
pub fn verify_sync_events(
    events: &[SyncEvent],
    expected_prev_hash: &Hash,
) -> Result<(), AntiEntropyError> {
    verify_sync_events_with_start_seq(events, expected_prev_hash, None)
}

/// Verifies a batch of sync events with optional starting `seq_id` check.
///
/// This is the full verification function that checks:
/// 1. Optional: First event's `seq_id` matches `expected_start_seq_id`
/// 2. Sequence IDs are strictly increasing (monotonicity)
/// 3. Event hashes are correct
/// 4. Hash chain is valid (each event links to previous)
///
/// # Arguments
///
/// * `events` - Events to verify.
/// * `expected_prev_hash` - Expected previous hash for the first event.
/// * `expected_start_seq_id` - If `Some(id)`, verify the first event has this
///   `seq_id`. Use this to verify continuity with the local ledger.
///
/// # Errors
///
/// Returns an error if any event fails verification:
/// - `SeqIdContinuityBroken` if first event's `seq_id` doesn't match expected
/// - `SeqIdNotIncreasing` if `seq_ids` are not strictly increasing
/// - `HashChainBroken` if `prev_hash` linkage is broken
/// - `EventVerificationFailed` if computed hash doesn't match `event_hash`
///
/// # Security Note
///
/// Since `EventHasher` does not include `seq_id` in the hash computation,
/// this function explicitly verifies `seq_id` monotonicity to prevent attacks
/// where a malicious peer provides events with spoofed `seq_ids`.
pub fn verify_sync_events_with_start_seq(
    events: &[SyncEvent],
    expected_prev_hash: &Hash,
    expected_start_seq_id: Option<u64>,
) -> Result<(), AntiEntropyError> {
    if events.is_empty() {
        return Ok(());
    }

    // Verify starting seq_id if specified
    if let Some(expected_start) = expected_start_seq_id {
        let actual_start = events[0].seq_id;
        if actual_start != expected_start {
            return Err(AntiEntropyError::SeqIdContinuityBroken {
                expected: expected_start,
                actual: actual_start,
            });
        }
    }

    let mut prev_hash = *expected_prev_hash;
    let mut prev_seq_id: Option<u64> = None;

    for event in events {
        // Verify seq_id monotonicity (strictly increasing)
        if let Some(prev) = prev_seq_id {
            if event.seq_id <= prev {
                return Err(AntiEntropyError::SeqIdNotIncreasing {
                    current: event.seq_id,
                    previous: prev,
                });
            }
        }
        prev_seq_id = Some(event.seq_id);

        // Verify previous hash linkage
        if event.prev_hash != prev_hash {
            return Err(AntiEntropyError::HashChainBroken {
                seq_id: event.seq_id,
            });
        }

        // Verify event hash
        let computed_hash = EventHasher::hash_event(&event.payload, &event.prev_hash);
        if computed_hash != event.event_hash {
            return Err(AntiEntropyError::EventVerificationFailed {
                seq_id: event.seq_id,
                reason: "event hash mismatch".to_string(),
            });
        }

        prev_hash = event.event_hash;
    }

    Ok(())
}

/// Verifies that sync events match their claimed Merkle proof.
///
/// # Arguments
///
/// * `events` - Events to verify.
/// * `proof` - Merkle proof for the first event.
/// * `root` - Expected Merkle root.
///
/// # Errors
///
/// Returns an error if the proof doesn't verify.
pub fn verify_events_with_proof(
    events: &[SyncEvent],
    proof: &MerkleProof,
    root: &Hash,
) -> Result<(), AntiEntropyError> {
    if events.is_empty() {
        return Ok(());
    }

    // Verify the proof's leaf hash matches the first event
    let first_event_leaf_hash = super::merkle::hash_leaf(&events[0].event_hash);
    if first_event_leaf_hash != proof.leaf_hash {
        return Err(AntiEntropyError::EventVerificationFailed {
            seq_id: events[0].seq_id,
            reason: "leaf hash mismatch with proof".to_string(),
        });
    }

    // Verify the proof itself
    proof.verify(root)?;

    Ok(())
}

/// Verifies anti-entropy catch-up inputs using digest comparison and event
/// transfer verification.
///
/// This is a thin composition wrapper that checks:
/// 1. Optional local/remote digest equality.
/// 2. Event transfer integrity (`verify_sync_events_with_start_seq`).
/// 3. Optional Merkle proof verification for transferred events.
///
/// # Errors
///
/// Returns [`AntiEntropyError::InvalidResponse`] when digest/proof context is
/// ambiguous and propagates verifier errors from the underlying checks.
pub fn verify_sync_catchup(
    local_digest: Option<&Hash>,
    remote_digest: Option<&Hash>,
    events: &[SyncEvent],
    expected_prev_hash: &Hash,
    expected_start_seq_id: Option<u64>,
    proof: Option<&MerkleProof>,
    proof_root: Option<&Hash>,
) -> Result<(), AntiEntropyError> {
    if let (Some(local), Some(remote)) = (local_digest, remote_digest) {
        if local != remote {
            return Err(AntiEntropyError::InvalidResponse(
                "anti-entropy digest mismatch between local and remote roots".to_string(),
            ));
        }
    }

    verify_sync_events_with_start_seq(events, expected_prev_hash, expected_start_seq_id)?;

    if let Some(proof) = proof {
        let root = proof_root.ok_or_else(|| {
            AntiEntropyError::InvalidResponse(
                "missing proof root for anti-entropy transfer verification".to_string(),
            )
        })?;
        verify_events_with_proof(events, proof, root)?;
    }

    Ok(())
}

/// Converts an `EventRecord` to a `SyncEvent`.
#[must_use]
pub fn event_record_to_sync_event(record: &EventRecord) -> Option<SyncEvent> {
    let seq_id = record.seq_id?;
    let prev_hash_vec = record.prev_hash.as_ref()?;
    let event_hash_vec = record.event_hash.as_ref()?;

    if prev_hash_vec.len() != HASH_SIZE || event_hash_vec.len() != HASH_SIZE {
        return None;
    }

    let mut prev_hash = [0u8; HASH_SIZE];
    prev_hash.copy_from_slice(prev_hash_vec);

    let mut event_hash = [0u8; HASH_SIZE];
    event_hash.copy_from_slice(event_hash_vec);

    Some(SyncEvent {
        seq_id,
        event_type: record.event_type.clone(),
        payload: record.payload.clone(),
        prev_hash,
        event_hash,
        timestamp_ns: record.timestamp_ns,
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tck_00191_unit_tests {
    use super::*;

    fn make_test_events(count: usize) -> Vec<SyncEvent> {
        let mut events = Vec::with_capacity(count);
        let mut prev_hash = [0u8; HASH_SIZE];

        for i in 0..count {
            let payload = format!("event-{i}").into_bytes();
            let event_hash = EventHasher::hash_event(&payload, &prev_hash);

            events.push(SyncEvent {
                seq_id: i as u64 + 1,
                event_type: "test.event".to_string(),
                payload,
                prev_hash,
                event_hash,
                timestamp_ns: 1_000_000 * (i as u64),
            });

            prev_hash = event_hash;
        }

        events
    }

    fn make_test_tree(count: usize) -> MerkleTree {
        let events = make_test_events(count);
        let hashes: Vec<Hash> = events.iter().map(|e| e.event_hash).collect();
        MerkleTree::new(hashes.iter().copied()).unwrap()
    }

    // ==================== Rate Limiter Tests ====================

    #[test]
    fn test_rate_limiter_allows_initial_requests() {
        let mut limiter = SyncRateLimiter::new();

        for _ in 0..10 {
            assert!(limiter.check("peer-1").is_ok());
        }
    }

    #[test]
    fn test_rate_limiter_blocks_excessive_requests() {
        let mut limiter = SyncRateLimiter::with_config(5, Duration::from_secs(60));

        for _ in 0..5 {
            assert!(limiter.check("peer-1").is_ok());
        }

        // 6th request should be blocked
        assert!(matches!(
            limiter.check("peer-1"),
            Err(AntiEntropyError::RateLimitExceeded { .. })
        ));
    }

    #[test]
    fn test_rate_limiter_separate_peers() {
        let mut limiter = SyncRateLimiter::with_config(2, Duration::from_secs(60));

        assert!(limiter.check("peer-1").is_ok());
        assert!(limiter.check("peer-1").is_ok());
        assert!(limiter.check("peer-1").is_err());

        // Different peer should have own limit
        assert!(limiter.check("peer-2").is_ok());
        assert!(limiter.check("peer-2").is_ok());
        assert!(limiter.check("peer-2").is_err());
    }

    #[test]
    fn test_rate_limiter_reset() {
        let mut limiter = SyncRateLimiter::with_config(2, Duration::from_secs(60));

        assert!(limiter.check("peer-1").is_ok());
        assert!(limiter.check("peer-1").is_ok());
        assert!(limiter.check("peer-1").is_err());

        limiter.reset("peer-1");

        assert!(limiter.check("peer-1").is_ok());
    }

    #[test]
    fn test_rate_limiter_peer_cap_rejects_new_peers_at_capacity() {
        // Use a small cap for testing (override MAX_RATE_LIMIT_PEERS behavior)
        // We test with the default limiter but fill it up to MAX_RATE_LIMIT_PEERS
        let mut limiter = SyncRateLimiter::with_config(100, Duration::from_secs(60));

        // Fill up to MAX_RATE_LIMIT_PEERS
        for i in 0..MAX_RATE_LIMIT_PEERS {
            let peer_id = format!("peer-{i}");
            assert!(
                limiter.check(&peer_id).is_ok(),
                "peer {i} should be allowed"
            );
        }

        // Next new peer should be rejected (at capacity)
        let result = limiter.check("new-peer-overflow");
        assert!(
            matches!(result, Err(AntiEntropyError::RateLimiterAtCapacity { .. })),
            "new peer should be rejected when at capacity, got: {result:?}"
        );
    }

    #[test]
    fn test_rate_limiter_existing_peer_allowed_at_capacity() {
        let mut limiter = SyncRateLimiter::with_config(100, Duration::from_secs(60));

        // Fill up to MAX_RATE_LIMIT_PEERS
        for i in 0..MAX_RATE_LIMIT_PEERS {
            let peer_id = format!("peer-{i}");
            assert!(limiter.check(&peer_id).is_ok());
        }

        // Existing peer should still be allowed (already tracked)
        let result = limiter.check("peer-0");
        assert!(
            result.is_ok(),
            "existing peer should be allowed even at capacity, got: {result:?}"
        );

        // New peer should still be rejected
        let result = limiter.check("totally-new-peer");
        assert!(matches!(
            result,
            Err(AntiEntropyError::RateLimiterAtCapacity { .. })
        ));
    }

    #[test]
    fn test_rate_limiter_peer_cap_error_message() {
        let mut limiter = SyncRateLimiter::with_config(100, Duration::from_secs(60));

        // Fill to capacity
        for i in 0..MAX_RATE_LIMIT_PEERS {
            limiter.check(&format!("peer-{i}")).unwrap();
        }

        // Check error message format
        let result = limiter.check("rejected-peer");
        match result {
            Err(AntiEntropyError::RateLimiterAtCapacity { peer_id }) => {
                assert_eq!(peer_id, "rejected-peer");
            },
            other => panic!("expected RateLimiterAtCapacity, got: {other:?}"),
        }
    }

    #[test]
    fn test_rate_limiter_capacity_check_after_cleanup() {
        // SECURITY TEST: Verify that after cleanup, capacity is still enforced.
        // Use a very short interval so entries expire quickly.
        let mut limiter = SyncRateLimiter::with_config(100, Duration::from_millis(1));

        // Fill to capacity
        for i in 0..MAX_RATE_LIMIT_PEERS {
            limiter.check(&format!("peer-{i}")).unwrap();
        }

        // Wait for entries to expire
        std::thread::sleep(Duration::from_millis(5));

        // After sleep, cleanup should have freed space.
        // A new peer should now be allowed (cleanup makes room).
        let result = limiter.check("new-peer-after-cleanup");
        assert!(
            result.is_ok(),
            "new peer should be allowed after expired entries cleanup, got: {result:?}"
        );

        // Phase 2: Create a fresh limiter with a long interval to verify capacity
        // is enforced even when entries don't expire. We use a separate limiter
        // to avoid timing sensitivity (the short 1ms interval could cause entries
        // to expire during the fill loop on slow CI machines).
        let mut limiter = SyncRateLimiter::with_config(100, Duration::from_secs(60));

        // Fill exactly to capacity
        for i in 0..MAX_RATE_LIMIT_PEERS {
            limiter.check(&format!("fresh-peer-{i}")).unwrap();
        }

        // Now we should be at capacity - new peer should be rejected
        let result = limiter.check("overflow-peer");
        assert!(
            matches!(result, Err(AntiEntropyError::RateLimiterAtCapacity { .. })),
            "should reject at capacity after refill, got: {result:?}"
        );
    }

    #[test]
    fn test_rate_limiter_strict_capacity_enforcement() {
        // SECURITY TEST: Verify that capacity is strictly enforced.
        // We should never exceed MAX_RATE_LIMIT_PEERS entries.
        let mut limiter = SyncRateLimiter::with_config(100, Duration::from_secs(60));

        // Fill exactly to capacity
        for i in 0..MAX_RATE_LIMIT_PEERS {
            limiter.check(&format!("peer-{i}")).unwrap();
        }

        // Verify we have exactly MAX_RATE_LIMIT_PEERS entries
        assert_eq!(
            limiter.requests.len(),
            MAX_RATE_LIMIT_PEERS,
            "should have exactly MAX_RATE_LIMIT_PEERS entries"
        );

        // Try to add one more - should fail
        let result = limiter.check("overflow-peer");
        assert!(matches!(
            result,
            Err(AntiEntropyError::RateLimiterAtCapacity { .. })
        ));

        // Verify we still have exactly MAX_RATE_LIMIT_PEERS entries (no overflow)
        assert_eq!(
            limiter.requests.len(),
            MAX_RATE_LIMIT_PEERS,
            "should still have exactly MAX_RATE_LIMIT_PEERS entries after rejection"
        );
    }

    // ==================== Sync Session Tests ====================

    #[test]
    fn test_sync_session_creation() {
        let tree = make_test_tree(10);
        let session = SyncSession::new("peer-1".to_string(), "kernel".to_string(), tree);

        assert_eq!(session.peer_id, "peer-1");
        assert_eq!(session.namespace, "kernel");
        assert_eq!(session.events_synced, 0);
        assert!(session.divergent_ranges.is_empty());
        // Verify last_activity is initialized
        assert!(session.last_activity.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn test_sync_session_is_complete() {
        let tree = make_test_tree(10);
        let mut session = SyncSession::new("peer-1".to_string(), "kernel".to_string(), tree);

        // No divergent ranges = complete
        assert!(session.is_complete());

        // Add divergent range
        session
            .divergent_ranges
            .push(DivergentRange { start: 2, end: 5 });
        assert!(!session.is_complete());

        // Mark as processed
        session.mark_processed(2, 5);
        assert!(session.is_complete());
    }

    #[test]
    fn test_sync_session_touch_updates_activity() {
        let tree = make_test_tree(10);
        let mut session = SyncSession::new("peer-1".to_string(), "kernel".to_string(), tree);

        let initial_activity = session.last_activity;

        // Small sleep to ensure time passes
        std::thread::sleep(Duration::from_millis(10));

        session.touch();

        // last_activity should have been updated
        assert!(session.last_activity > initial_activity);
    }

    #[test]
    fn test_sync_session_is_stale() {
        let tree = make_test_tree(10);
        let session = SyncSession::new("peer-1".to_string(), "kernel".to_string(), tree);

        // Session should not be stale immediately with a reasonable timeout
        assert!(!session.is_stale(Duration::from_secs(60)));

        // Session should be stale with zero timeout
        assert!(session.is_stale(Duration::ZERO));
    }

    #[test]
    fn test_session_timeout_constant() {
        // Verify SESSION_TIMEOUT is set to expected value
        assert_eq!(SESSION_TIMEOUT, Duration::from_secs(60));
    }

    // ==================== Anti-Entropy Engine Tests ====================

    #[test]
    fn test_engine_start_session() {
        let mut engine = AntiEntropyEngine::new();
        let tree = make_test_tree(10);

        let session = engine.start_session("peer-1", "kernel", tree).unwrap();
        assert_eq!(session.peer_id, "peer-1");
        assert_eq!(engine.session_count(), 1);
    }

    #[test]
    fn test_engine_max_sessions() {
        let mut engine = AntiEntropyEngine::with_config(SyncRateLimiter::new(), 2);

        let tree1 = make_test_tree(10);
        let tree2 = make_test_tree(10);
        let tree3 = make_test_tree(10);

        assert!(engine.start_session("peer-1", "kernel", tree1).is_ok());
        assert!(engine.start_session("peer-2", "kernel", tree2).is_ok());
        assert!(engine.start_session("peer-3", "kernel", tree3).is_err());
    }

    #[test]
    fn test_engine_end_session() {
        let mut engine = AntiEntropyEngine::new();
        let tree = make_test_tree(10);

        engine.start_session("peer-1", "kernel", tree).unwrap();
        assert_eq!(engine.session_count(), 1);

        let session = engine.end_session("peer-1");
        assert!(session.is_some());
        assert_eq!(engine.session_count(), 0);
    }

    #[test]
    fn test_engine_cleanup_stale_sessions() {
        let mut engine = AntiEntropyEngine::with_config(SyncRateLimiter::new(), 10);

        let tree1 = make_test_tree(10);
        let tree2 = make_test_tree(10);

        engine.start_session("peer-1", "kernel", tree1).unwrap();
        engine.start_session("peer-2", "kernel", tree2).unwrap();

        assert_eq!(engine.session_count(), 2);

        // With zero timeout, all sessions should be stale
        let cleaned = engine.cleanup_stale_sessions_with_timeout(Duration::ZERO);
        assert_eq!(cleaned, 2);
        assert_eq!(engine.session_count(), 0);
    }

    #[test]
    fn test_engine_cleanup_preserves_active_sessions() {
        let mut engine = AntiEntropyEngine::with_config(SyncRateLimiter::new(), 10);

        let tree1 = make_test_tree(10);
        let tree2 = make_test_tree(10);

        engine.start_session("peer-1", "kernel", tree1).unwrap();
        engine.start_session("peer-2", "kernel", tree2).unwrap();

        assert_eq!(engine.session_count(), 2);

        // With a long timeout, no sessions should be cleaned
        let cleaned = engine.cleanup_stale_sessions_with_timeout(Duration::from_secs(3600));
        assert_eq!(cleaned, 0);
        assert_eq!(engine.session_count(), 2);
    }

    #[test]
    fn test_engine_start_session_cleans_stale_on_full() {
        // Create engine with max 2 sessions
        let mut engine = AntiEntropyEngine::with_config(SyncRateLimiter::new(), 2);

        let tree1 = make_test_tree(10);
        let tree2 = make_test_tree(10);
        let tree3 = make_test_tree(10);

        // Fill up to max sessions
        engine.start_session("peer-1", "kernel", tree1).unwrap();
        engine.start_session("peer-2", "kernel", tree2).unwrap();

        // Normally peer-3 would be rejected, but sessions are fresh
        // so they won't be cleaned and peer-3 will still be rejected
        // (This tests that cleanup runs but doesn't help when sessions are active)
        let result = engine.start_session("peer-3", "kernel", tree3);
        assert!(
            matches!(result, Err(AntiEntropyError::TooManyPendingRequests { .. })),
            "peer-3 should be rejected when sessions are at max and active"
        );
    }

    #[test]
    fn test_engine_start_session_touches_existing() {
        let mut engine = AntiEntropyEngine::new();
        let tree = make_test_tree(10);

        engine.start_session("peer-1", "kernel", tree).unwrap();

        // Get the session and record its last_activity
        let initial_activity = engine.get_session("peer-1").unwrap().last_activity;

        // Small sleep to ensure time passes
        std::thread::sleep(Duration::from_millis(10));

        // Start session again (reuses existing)
        let tree2 = make_test_tree(10);
        engine.start_session("peer-1", "kernel", tree2).unwrap();

        // last_activity should have been updated
        let new_activity = engine.get_session("peer-1").unwrap().last_activity;
        assert!(new_activity > initial_activity);
    }

    #[test]
    fn test_engine_handle_digest_request() {
        let mut engine = AntiEntropyEngine::new();
        let tree = make_test_tree(16);

        let request = DigestRequest {
            namespace: "kernel".to_string(),
            range: (1, 17),
            peer_id: "peer-1".to_string(),
            timestamp_ns: 1_000_000,
        };

        let response = engine.handle_digest_request(&request, &tree).unwrap();

        assert_eq!(response.namespace, "kernel");
        assert_eq!(response.root_hash, tree.root());
        assert_eq!(response.event_count, 16);
    }

    #[test]
    fn test_engine_handle_compare_request() {
        let mut engine = AntiEntropyEngine::new();
        let tree = make_test_tree(8);

        let request = CompareRequest {
            namespace: "kernel".to_string(),
            ranges: vec![RangeQuery {
                range: (0, 8),
                expected_hash: tree.root(),
            }],
            peer_id: "peer-1".to_string(),
        };

        let response = engine.handle_compare_request(&request, &tree).unwrap();

        assert_eq!(response.digests.len(), 1);
        assert!(response.digests[0].matches);
    }

    #[test]
    fn test_engine_handle_compare_request_mismatch() {
        let mut engine = AntiEntropyEngine::new();
        let tree = make_test_tree(8);

        let wrong_hash = [0xFFu8; 32];
        let request = CompareRequest {
            namespace: "kernel".to_string(),
            ranges: vec![RangeQuery {
                range: (0, 8),
                expected_hash: wrong_hash,
            }],
            peer_id: "peer-1".to_string(),
        };

        let response = engine.handle_compare_request(&request, &tree).unwrap();

        assert_eq!(response.digests.len(), 1);
        assert!(!response.digests[0].matches);
        assert!(response.digests[0].children.is_some());
    }

    #[test]
    fn test_engine_handle_event_request() {
        let mut engine = AntiEntropyEngine::new();
        let test_events = make_test_events(20);

        let request = EventRequest {
            namespace: "kernel".to_string(),
            range: (5, 15),
            limit: 5,
            peer_id: "peer-1".to_string(),
        };

        let response = engine
            .handle_event_request(&request, |start, end, limit| {
                test_events
                    .iter()
                    .filter(|e| e.seq_id >= start && e.seq_id < end)
                    .take(limit)
                    .cloned()
                    .collect()
            })
            .unwrap();

        assert_eq!(response.events.len(), 5);
        assert!(response.has_more);
    }

    #[test]
    fn test_engine_handle_event_request_batch_limit() {
        let mut engine = AntiEntropyEngine::new();

        let request = EventRequest {
            namespace: "kernel".to_string(),
            range: (1, 10000),
            limit: MAX_SYNC_BATCH_SIZE + 1,
            peer_id: "peer-1".to_string(),
        };

        let result = engine.handle_event_request(&request, |_, _, _| vec![]);
        assert!(matches!(
            result,
            Err(AntiEntropyError::BatchTooLarge { .. })
        ));
    }

    #[test]
    fn test_engine_handle_compare_request_depth_limit() {
        let mut engine = AntiEntropyEngine::new();
        let tree = make_test_tree(8);

        // Create a range that would exceed MAX_COMPARISON_DEPTH
        // A range of 2^33 would require depth 33 which exceeds MAX_COMPARISON_DEPTH
        // (32)
        let huge_range: u64 = 1u64 << 33; // 8 billion
        let request = CompareRequest {
            namespace: "kernel".to_string(),
            ranges: vec![RangeQuery {
                range: (0, huge_range),
                expected_hash: tree.root(),
            }],
            peer_id: "peer-1".to_string(),
        };

        let result = engine.handle_compare_request(&request, &tree);
        assert!(
            matches!(
                result,
                Err(AntiEntropyError::ComparisonDepthExceeded { .. })
            ),
            "expected ComparisonDepthExceeded, got: {result:?}"
        );
    }

    #[test]
    fn test_engine_handle_compare_request_depth_at_limit_allowed() {
        let mut engine = AntiEntropyEngine::new();
        let tree = make_test_tree(8);

        // A range of 2^31 would require depth 32 (since depth = bit_length)
        // which equals MAX_COMPARISON_DEPTH (32). This should be allowed.
        // Note: depth is computed as usize::BITS - leading_zeros for range_size > 1
        let max_allowed_range: u64 = 1u64 << 31; // 2 billion - requires depth 32
        let request = CompareRequest {
            namespace: "kernel".to_string(),
            ranges: vec![RangeQuery {
                range: (0, max_allowed_range),
                expected_hash: tree.root(),
            }],
            peer_id: "peer-1".to_string(),
        };

        // This will fail due to InvalidRange (out of bounds for our small tree)
        // but NOT due to depth exceeded - that's what we're testing
        let result = engine.handle_compare_request(&request, &tree);
        assert!(
            !matches!(
                result,
                Err(AntiEntropyError::ComparisonDepthExceeded { .. })
            ),
            "depth at limit should be allowed, got: {result:?}"
        );
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn test_engine_handle_compare_request_index_overflow_simulation() {
        // SECURITY TEST: On 64-bit platforms, we can't actually overflow usize
        // with u64 values (they're the same size). This test verifies the
        // error handling code compiles and the error type exists.
        // On 32-bit platforms, this would actually trigger IndexOverflow.

        // Verify the error type exists and formats correctly
        let err = AntiEntropyError::IndexOverflow { index: u64::MAX };
        let msg = format!("{err}");
        assert!(msg.contains("overflows usize"));
        assert!(msg.contains(&u64::MAX.to_string()));
    }

    #[test]
    #[cfg(target_pointer_width = "32")]
    fn test_engine_handle_compare_request_index_overflow_32bit() {
        // SECURITY TEST: On 32-bit platforms, verify that u64 values > u32::MAX
        // are properly rejected with IndexOverflow error.
        let mut engine = AntiEntropyEngine::new();
        let tree = make_test_tree(8);

        // This value exceeds u32::MAX and would truncate on 32-bit
        let overflow_index: u64 = (u32::MAX as u64) + 1000;
        let request = CompareRequest {
            namespace: "kernel".to_string(),
            ranges: vec![RangeQuery {
                range: (0, overflow_index),
                expected_hash: tree.root(),
            }],
            peer_id: "peer-1".to_string(),
        };

        let result = engine.handle_compare_request(&request, &tree);
        assert!(
            matches!(result, Err(AntiEntropyError::IndexOverflow { .. })),
            "should reject index overflow on 32-bit, got: {result:?}"
        );
    }

    // ==================== Event Verification Tests ====================

    #[test]
    fn test_verify_sync_events_valid() {
        let events = make_test_events(10);
        let genesis_hash = [0u8; HASH_SIZE];

        let result = verify_sync_events(&events, &genesis_hash);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_sync_events_broken_chain() {
        let mut events = make_test_events(10);
        // Break the chain by modifying prev_hash
        events[5].prev_hash = [0xFFu8; HASH_SIZE];

        let genesis_hash = [0u8; HASH_SIZE];
        let result = verify_sync_events(&events, &genesis_hash);

        assert!(matches!(
            result,
            Err(AntiEntropyError::HashChainBroken { seq_id: 6 })
        ));
    }

    #[test]
    fn test_verify_sync_events_hash_mismatch() {
        let mut events = make_test_events(10);
        // Corrupt an event hash
        events[3].event_hash = [0xFFu8; HASH_SIZE];

        let genesis_hash = [0u8; HASH_SIZE];
        let result = verify_sync_events(&events, &genesis_hash);

        assert!(matches!(
            result,
            Err(AntiEntropyError::EventVerificationFailed { seq_id: 4, .. })
        ));
    }

    #[test]
    fn test_verify_sync_events_empty() {
        let result = verify_sync_events(&[], &[0u8; HASH_SIZE]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_sync_events_seq_id_not_increasing() {
        let mut events = make_test_events(10);
        // Make seq_ids not strictly increasing by setting event 5's seq_id = event 4's
        // seq_id
        events[5].seq_id = events[4].seq_id;

        let genesis_hash = [0u8; HASH_SIZE];
        let result = verify_sync_events(&events, &genesis_hash);

        assert!(
            matches!(
                result,
                Err(AntiEntropyError::SeqIdNotIncreasing {
                    current: 5,
                    previous: 5
                })
            ),
            "expected SeqIdNotIncreasing, got: {result:?}"
        );
    }

    #[test]
    fn test_verify_sync_events_seq_id_decreasing() {
        let mut events = make_test_events(10);
        // Make seq_ids decrease by setting event 5's seq_id to less than event 4's
        // seq_id
        events[5].seq_id = 1; // Way less than event 4's seq_id (5)

        let genesis_hash = [0u8; HASH_SIZE];
        let result = verify_sync_events(&events, &genesis_hash);

        assert!(
            matches!(
                result,
                Err(AntiEntropyError::SeqIdNotIncreasing {
                    current: 1,
                    previous: 5
                })
            ),
            "expected SeqIdNotIncreasing, got: {result:?}"
        );
    }

    #[test]
    fn test_verify_sync_events_with_start_seq_correct() {
        let events = make_test_events(10);
        let genesis_hash = [0u8; HASH_SIZE];

        // First event has seq_id 1
        let result = verify_sync_events_with_start_seq(&events, &genesis_hash, Some(1));
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_sync_events_with_start_seq_mismatch() {
        let events = make_test_events(10);
        let genesis_hash = [0u8; HASH_SIZE];

        // First event has seq_id 1, but we expect 100
        let result = verify_sync_events_with_start_seq(&events, &genesis_hash, Some(100));

        assert!(
            matches!(
                result,
                Err(AntiEntropyError::SeqIdContinuityBroken {
                    expected: 100,
                    actual: 1
                })
            ),
            "expected SeqIdContinuityBroken, got: {result:?}"
        );
    }

    #[test]
    fn test_verify_sync_events_with_start_seq_none() {
        let events = make_test_events(10);
        let genesis_hash = [0u8; HASH_SIZE];

        // When expected_start_seq_id is None, no continuity check
        let result = verify_sync_events_with_start_seq(&events, &genesis_hash, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_sync_events_with_start_seq_empty_events() {
        // Empty events should succeed regardless of expected_start_seq_id
        let result = verify_sync_events_with_start_seq(&[], &[0u8; HASH_SIZE], Some(100));
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_sync_events_spoofed_seq_id_detected() {
        // This test verifies that a malicious peer cannot provide spoofed seq_ids.
        // Since EventHasher doesn't include seq_id in the hash, an attacker could
        // potentially send valid events with fake seq_ids. Our monotonicity check
        // prevents this.
        let mut spoofed_events = make_test_events(5);
        let genesis_hash = [0u8; HASH_SIZE];

        // Create events with spoofed (duplicated) seq_ids but valid hashes
        spoofed_events[2].seq_id = 1; // Spoof: claim this is seq_id 1 (already seen)

        let result = verify_sync_events(&spoofed_events, &genesis_hash);
        assert!(
            matches!(result, Err(AntiEntropyError::SeqIdNotIncreasing { .. })),
            "spoofed seq_id should be detected"
        );
    }

    // ==================== Find Divergences Tests ====================

    #[test]
    fn test_find_divergences_identical() {
        let engine = AntiEntropyEngine::new();
        let tree1 = make_test_tree(16);
        let tree2 = make_test_tree(16);

        let divergent = engine.find_divergences(&tree1, &tree2).unwrap();
        assert!(divergent.is_empty());
    }

    #[test]
    fn test_find_divergences_different() {
        let engine = AntiEntropyEngine::new();
        let events1 = make_test_events(16);
        let mut events2 = make_test_events(16);

        // Modify one event
        events2[7].payload = b"modified".to_vec();
        events2[7].event_hash = EventHasher::hash_event(&events2[7].payload, &events2[7].prev_hash);

        let hashes1: Vec<Hash> = events1.iter().map(|e| e.event_hash).collect();
        let hashes2: Vec<Hash> = events2.iter().map(|e| e.event_hash).collect();

        let tree1 = MerkleTree::new(hashes1.iter().copied()).unwrap();
        let tree2 = MerkleTree::new(hashes2.iter().copied()).unwrap();

        let divergent = engine.find_divergences(&tree1, &tree2).unwrap();
        assert!(!divergent.is_empty());
    }

    // ==================== Event Record Conversion Tests ====================

    #[test]
    fn test_event_record_to_sync_event() {
        let mut record =
            EventRecord::new("test.event", "session-1", "actor-1", b"payload".to_vec());

        record.seq_id = Some(42);
        record.prev_hash = Some(vec![0u8; HASH_SIZE]);
        record.event_hash = Some(vec![1u8; HASH_SIZE]);

        let sync_event = event_record_to_sync_event(&record).unwrap();

        assert_eq!(sync_event.seq_id, 42);
        assert_eq!(sync_event.event_type, "test.event");
        assert_eq!(sync_event.prev_hash, [0u8; HASH_SIZE]);
        assert_eq!(sync_event.event_hash, [1u8; HASH_SIZE]);
    }

    #[test]
    fn test_event_record_to_sync_event_missing_fields() {
        let record = EventRecord::new("test.event", "session-1", "actor-1", b"payload".to_vec());

        // Missing seq_id should return None
        let result = event_record_to_sync_event(&record);
        assert!(result.is_none());
    }
}
