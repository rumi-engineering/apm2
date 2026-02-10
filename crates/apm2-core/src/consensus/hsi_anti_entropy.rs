// AGENT-AUTHORED
//! RFC-0020 HSI anti-entropy protocol primitives.
//!
//! This module implements the wire-level offer/compare/request/deliver
//! negotiation shape with strict pull-only semantics, bounded relay budgets,
//! replay protection, and Byzantine relay defect detection.
//!
//! Security and safety goals:
//! - Pull-only delivery: unsolicited `DELIVER_EVENTS` are rejected.
//! - Budget-bound operation: per-session event/byte/fanout/session caps.
//! - Replay resistance: issuer `(hlc, sequence)` monotonic checks and replay
//!   window tracking.
//! - Byzantine resilience: tampered delivery, fanout amplification, and budget
//!   abuse produce structured defects.
//! - Deterministic behavior: bounded stores and ordered maps/sets.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::anti_entropy::{SyncEvent, verify_sync_events_with_start_seq};
use super::crdt::Hlc;
use super::merkle::{MAX_TREE_DEPTH, MAX_TREE_LEAVES, MerkleTree};
use crate::crypto::{EventHasher, HASH_SIZE, Hash};
use crate::htf::{Canonicalizable, CanonicalizationError};

// ============================================================================
// Constants
// ============================================================================

/// Maximum anti-entropy leaves permitted by wire offers (`2^20`).
pub const MAX_ANTI_ENTROPY_LEAVES: u32 = 1 << 20;

/// Maximum length for cell identifiers on the anti-entropy boundary.
pub const MAX_CELL_ID_LEN: usize = 128;

/// Maximum length for issuer identifiers on the anti-entropy boundary.
pub const MAX_ISSUER_ID_LEN: usize = 128;

/// Maximum length for relay identifiers on the anti-entropy boundary.
pub const MAX_RELAY_ID_LEN: usize = 128;

/// Maximum length for session identifiers on the anti-entropy boundary.
pub const MAX_SESSION_ID_LEN: usize = 128;

/// Maximum length for request identifiers on the anti-entropy boundary.
pub const MAX_REQUEST_ID_LEN: usize = 128;

/// Maximum length for offer identifiers on the anti-entropy boundary.
pub const MAX_OFFER_ID_LEN: usize = 128;

/// Maximum length for compare identifiers on the anti-entropy boundary.
pub const MAX_COMPARE_ID_LEN: usize = 128;

/// Maximum length for event type strings in delivered events.
pub const MAX_EVENT_TYPE_LEN: usize = 128;

/// Maximum length for actor identifiers in delivered events.
pub const MAX_ACTOR_ID_LEN: usize = 128;

/// Maximum signature size accepted on delivered events.
pub const MAX_SIGNATURE_LEN: usize = 512;

/// Maximum attestation hashes carried by each delivered event.
pub const MAX_ATTESTATION_HASHES_PER_EVENT: usize = 64;

/// Maximum number of events in a single `DELIVER_EVENTS` frame.
pub const MAX_EVENTS_PER_DELIVER: usize = 4096;

/// Maximum proof hashes included in a single `DELIVER_EVENTS` frame.
pub const MAX_DELIVER_PROOF_HASHES: usize = MAX_TREE_DEPTH;

/// Maximum outstanding event requests tracked by the pull-only enforcer.
pub const MAX_OUTSTANDING_REQUESTS: usize = 1024;

/// Maximum replay entries retained in bounded replay windows.
pub const MAX_REPLAY_LOG_ENTRIES: usize = 8192;

/// Maximum relays tracked by Byzantine relay fanout detector.
pub const MAX_TRACKED_RELAYS: usize = 1024;

/// Maximum detail string length on structured anti-entropy defects.
pub const MAX_DEFECT_DETAIL_LEN: usize = 512;

/// Maximum tracked issuer identities in the replay high-water map.
///
/// When this limit is reached, the oldest issuer entry (by sequence) is
/// evicted. This prevents unbounded memory growth under adversarial or
/// high-churn issuer sets.
pub const MAX_REPLAY_ISSUERS: usize = 4096;

/// Maximum configurable events-per-session budget.
pub const MAX_EVENTS_PER_SESSION_BUDGET: usize = 1 << 20;

/// Maximum configurable bytes-per-session budget.
pub const MAX_BYTES_PER_SESSION_BUDGET: usize = 128 * 1024 * 1024;

/// Maximum configurable fanout budget (`relay_count` per cell).
pub const MAX_FANOUT_BUDGET: usize = 1024;

/// Maximum configurable concurrent session budget.
pub const MAX_CONCURRENT_SESSION_BUDGET: usize = 4096;

// ============================================================================
// Errors
// ============================================================================

/// Errors produced by HSI anti-entropy validation and enforcement.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum HsiAntiEntropyError {
    /// A string field exceeds configured bounds.
    #[error("{field} exceeds max length: {len} > {max}")]
    StringTooLong {
        /// Field name.
        field: String,
        /// Actual length.
        len: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// A string field contains ASCII control characters.
    #[error("{field} contains control characters")]
    ControlCharactersNotAllowed {
        /// Field name.
        field: String,
    },

    /// A numeric range is invalid.
    #[error("invalid range: start {start} > end {end}")]
    InvalidRange {
        /// Inclusive start.
        start: u64,
        /// Inclusive end.
        end: u64,
    },

    /// A value exceeds the wire leaf cap.
    #[error("max_leaves {actual} exceeds cap {cap}")]
    MaxLeavesExceeded {
        /// Actual value.
        actual: u32,
        /// Maximum supported value.
        cap: u32,
    },

    /// `max_leaves` was zero.
    #[error("max_leaves must be non-zero")]
    ZeroMaxLeaves,

    /// A compare depth exceeds the configured depth limit.
    #[error("compare depth {actual} exceeds max {max}")]
    CompareDepthExceeded {
        /// Actual depth.
        actual: usize,
        /// Maximum supported depth.
        max: usize,
    },

    /// A deliver payload contained too many events.
    #[error("deliver event count {actual} exceeds max {max}")]
    DeliverEventCountExceeded {
        /// Actual count.
        actual: usize,
        /// Maximum supported count.
        max: usize,
    },

    /// A deliver payload contained too many proof hashes.
    #[error("deliver proof count {actual} exceeds max {max}")]
    DeliverProofCountExceeded {
        /// Actual count.
        actual: usize,
        /// Maximum supported count.
        max: usize,
    },

    /// Event span and payload cardinality do not match.
    #[error("deliver span mismatch: expected {expected} events, got {actual}")]
    DeliverSpanMismatch {
        /// Expected event count from `[seq_start, seq_end]`.
        expected: usize,
        /// Actual event count.
        actual: usize,
    },

    /// Event hash verification failed for a delivered event.
    #[error("delivered event hash verification failed at seq {seq_id}")]
    DeliveredEventHashInvalid {
        /// Sequence identifier.
        seq_id: u64,
    },

    /// Canonicalization failed.
    #[error("canonicalization failed: {reason}")]
    CanonicalizationFailed {
        /// Error description.
        reason: String,
    },

    /// A budget value is invalid.
    #[error("invalid budget: {reason}")]
    InvalidBudget {
        /// Validation failure reason.
        reason: String,
    },

    /// A request was not found in outstanding pull state.
    #[error("unknown request_id: {request_id}")]
    UnknownRequest {
        /// Missing request identifier.
        request_id: String,
    },

    /// Requests exceeded local tracking cap.
    #[error("outstanding request limit exceeded: {count} > {max}")]
    OutstandingRequestLimitExceeded {
        /// Current outstanding count.
        count: usize,
        /// Maximum allowed count.
        max: usize,
    },

    /// Structured protocol defect emitted by anti-entropy defenses.
    #[error("{defect}")]
    Defect {
        /// Structured defect payload.
        defect: Box<AntiEntropyDefect>,
    },
}

impl From<CanonicalizationError> for HsiAntiEntropyError {
    fn from(value: CanonicalizationError) -> Self {
        Self::CanonicalizationFailed {
            reason: value.to_string(),
        }
    }
}

impl HsiAntiEntropyError {
    /// Returns defect payload when this error represents a structured defect.
    #[must_use]
    pub fn defect(&self) -> Option<&AntiEntropyDefect> {
        match self {
            Self::Defect { defect } => Some(defect.as_ref()),
            _ => None,
        }
    }
}

// ============================================================================
// Structured defects
// ============================================================================

/// Byzantine/abuse defect kinds emitted by anti-entropy guards.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AntiEntropyDefectKind {
    /// A peer attempted unsolicited push delivery.
    UnsolicitedDelivery,
    /// Delivered payload integrity did not match requested facts.
    TamperedDelivery,
    /// Relay attempted fanout amplification or alias abuse.
    FanoutAmplification,
    /// Budget cap was exceeded and actuation was denied.
    BudgetExceeded,
    /// Replay was detected via monotone sequence or replay window.
    ReplayDetected,
    /// Delivery carried invalid signature or attestation.
    InvalidAttestation,
}

/// Structured defect emitted when anti-entropy guards deny actuation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AntiEntropyDefect {
    /// Defect category.
    pub kind: AntiEntropyDefectKind,
    /// Issuer identifier associated with this defect.
    pub issuer_id: String,
    /// Relay identifier (if applicable).
    pub relay_id: Option<String>,
    /// Cell identifier (if applicable).
    pub cell_id: Option<String>,
    /// Session identifier (if applicable).
    pub session_id: Option<String>,
    /// Correlation identifier (`request_id`, `offer_id`, etc.) if known.
    pub correlation_id: Option<String>,
    /// Human-readable defect detail.
    pub detail: String,
}

impl fmt::Display for AntiEntropyDefect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} issuer={} relay={:?} cell={:?} session={:?} correlation={:?}: {}",
            self.kind,
            self.issuer_id,
            self.relay_id,
            self.cell_id,
            self.session_id,
            self.correlation_id,
            self.detail
        )
    }
}

// ============================================================================
// Wire shapes (RFC-0020 §2.4.6)
// ============================================================================

/// `OFFER` message advertising anti-entropy checkpoint state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AntiEntropyOffer {
    /// Offer identifier for correlation.
    pub offer_id: String,
    /// Advertised cell identifier.
    pub cell_id: String,
    /// Issuer identity for replay protection.
    pub issuer_id: String,
    /// Issuer HLC timestamp for replay protection.
    pub issuer_hlc: Hlc,
    /// Issuer monotone sequence for replay protection.
    pub issuer_sequence: u64,
    /// Advertised ledger head sequence.
    pub ledger_head_seq: u64,
    /// Advertised ledger head hash.
    pub ledger_head_hash: Hash,
    /// Advertised Merkle root hash.
    pub merkle_root_hash: Hash,
    /// Advertised inclusive sequence range `(start, end)`.
    pub range_bounds: (u64, u64),
    /// Merkle leaf cap used to construct proofs.
    pub max_leaves: u32,
}

impl AntiEntropyOffer {
    /// Validates structural and bounds constraints.
    ///
    /// # Errors
    ///
    /// Returns [`HsiAntiEntropyError`] when any field violates ingress
    /// constraints.
    pub fn validate(&self) -> Result<(), HsiAntiEntropyError> {
        validate_bounded_string("offer_id", &self.offer_id, MAX_OFFER_ID_LEN)?;
        validate_bounded_string("cell_id", &self.cell_id, MAX_CELL_ID_LEN)?;
        validate_bounded_string("issuer_id", &self.issuer_id, MAX_ISSUER_ID_LEN)?;
        validate_inclusive_range(self.range_bounds.0, self.range_bounds.1)?;

        if self.max_leaves == 0 {
            return Err(HsiAntiEntropyError::ZeroMaxLeaves);
        }
        if self.max_leaves > MAX_ANTI_ENTROPY_LEAVES {
            return Err(HsiAntiEntropyError::MaxLeavesExceeded {
                actual: self.max_leaves,
                cap: MAX_ANTI_ENTROPY_LEAVES,
            });
        }
        Ok(())
    }

    /// Computes the canonical JCS hash of this offer.
    ///
    /// # Errors
    ///
    /// Returns [`HsiAntiEntropyError::CanonicalizationFailed`] when
    /// canonicalization fails.
    pub fn canonical_message_hash(&self) -> Result<Hash, HsiAntiEntropyError> {
        <Self as Canonicalizable>::canonical_hash(self).map_err(Into::into)
    }
}

/// `COMPARE` message requesting subtree/range digests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AntiEntropyCompare {
    /// Compare identifier for correlation.
    pub compare_id: String,
    /// Parent offer identifier.
    pub offer_id: String,
    /// Cell identifier.
    pub cell_id: String,
    /// Issuer identity for replay protection.
    pub issuer_id: String,
    /// Issuer HLC timestamp.
    pub issuer_hlc: Hlc,
    /// Issuer monotone sequence.
    pub issuer_sequence: u64,
    /// Inclusive range start.
    pub range_start: u64,
    /// Inclusive range end.
    pub range_end: u64,
    /// Requested Merkle depth for range decomposition.
    pub depth: u8,
}

impl AntiEntropyCompare {
    /// Validates structural and bounds constraints.
    ///
    /// # Errors
    ///
    /// Returns [`HsiAntiEntropyError`] when any field violates ingress
    /// constraints.
    pub fn validate(&self) -> Result<(), HsiAntiEntropyError> {
        validate_bounded_string("compare_id", &self.compare_id, MAX_COMPARE_ID_LEN)?;
        validate_bounded_string("offer_id", &self.offer_id, MAX_OFFER_ID_LEN)?;
        validate_bounded_string("cell_id", &self.cell_id, MAX_CELL_ID_LEN)?;
        validate_bounded_string("issuer_id", &self.issuer_id, MAX_ISSUER_ID_LEN)?;
        validate_inclusive_range(self.range_start, self.range_end)?;

        if usize::from(self.depth) > MAX_TREE_DEPTH {
            return Err(HsiAntiEntropyError::CompareDepthExceeded {
                actual: usize::from(self.depth),
                max: MAX_TREE_DEPTH,
            });
        }
        Ok(())
    }

    /// Computes the canonical JCS hash of this compare message.
    ///
    /// # Errors
    ///
    /// Returns [`HsiAntiEntropyError::CanonicalizationFailed`] when
    /// canonicalization fails.
    pub fn canonical_message_hash(&self) -> Result<Hash, HsiAntiEntropyError> {
        <Self as Canonicalizable>::canonical_hash(self).map_err(Into::into)
    }
}

/// `REQUEST_EVENTS` message requesting a bounded event range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AntiEntropyRequestEvents {
    /// Request identifier for correlation.
    pub request_id: String,
    /// Parent offer identifier.
    pub offer_id: String,
    /// Parent compare identifier.
    pub compare_id: String,
    /// Session identifier used for relay budget accounting.
    pub session_id: String,
    /// Cell identifier.
    pub cell_id: String,
    /// Issuer identity for replay protection.
    pub issuer_id: String,
    /// Issuer HLC timestamp.
    pub issuer_hlc: Hlc,
    /// Issuer monotone sequence.
    pub issuer_sequence: u64,
    /// Request nonce to bind request/deliver exchange.
    pub nonce: u64,
    /// Inclusive sequence start.
    pub seq_start: u64,
    /// Inclusive sequence end.
    pub seq_end: u64,
    /// Expected digest for requested range.
    pub expected_range_digest: Hash,
}

impl AntiEntropyRequestEvents {
    /// Validates structural and bounds constraints.
    ///
    /// # Errors
    ///
    /// Returns [`HsiAntiEntropyError`] when any field violates ingress
    /// constraints.
    pub fn validate(&self) -> Result<(), HsiAntiEntropyError> {
        validate_bounded_string("request_id", &self.request_id, MAX_REQUEST_ID_LEN)?;
        validate_bounded_string("offer_id", &self.offer_id, MAX_OFFER_ID_LEN)?;
        validate_bounded_string("compare_id", &self.compare_id, MAX_COMPARE_ID_LEN)?;
        validate_bounded_string("session_id", &self.session_id, MAX_SESSION_ID_LEN)?;
        validate_bounded_string("cell_id", &self.cell_id, MAX_CELL_ID_LEN)?;
        validate_bounded_string("issuer_id", &self.issuer_id, MAX_ISSUER_ID_LEN)?;
        validate_inclusive_range(self.seq_start, self.seq_end)
    }

    /// Returns the requested event count for the inclusive sequence range.
    ///
    /// # Errors
    ///
    /// Returns [`HsiAntiEntropyError::InvalidRange`] if arithmetic overflows.
    pub fn requested_event_count(&self) -> Result<usize, HsiAntiEntropyError> {
        inclusive_span_len(self.seq_start, self.seq_end)
    }

    /// Computes the canonical JCS hash of this request.
    ///
    /// # Errors
    ///
    /// Returns [`HsiAntiEntropyError::CanonicalizationFailed`] when
    /// canonicalization fails.
    pub fn canonical_message_hash(&self) -> Result<Hash, HsiAntiEntropyError> {
        <Self as Canonicalizable>::canonical_hash(self).map_err(Into::into)
    }
}

/// Delivered event entry included in `DELIVER_EVENTS`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveredEvent {
    /// Sequence identifier.
    pub seq_id: u64,
    /// Event type.
    pub event_type: String,
    /// Serialized event payload.
    #[serde(with = "serde_bytes")]
    pub payload: Vec<u8>,
    /// Previous hash in hash chain.
    pub prev_hash: Hash,
    /// Event hash (must equal `hash(payload, prev_hash)`).
    pub event_hash: Hash,
    /// Event timestamp (HTF-derived at producer).
    pub timestamp_ns: u64,
    /// Event signer identity.
    pub actor_id: String,
    /// Event signature bytes.
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
    /// Quorum/attestation hashes carried with this event.
    pub attestation_hashes: Vec<Hash>,
}

impl DeliveredEvent {
    /// Validates event field bounds and hash integrity.
    ///
    /// # Errors
    ///
    /// Returns [`HsiAntiEntropyError`] when any bound or hash check fails.
    pub fn validate(&self) -> Result<(), HsiAntiEntropyError> {
        validate_bounded_string("event_type", &self.event_type, MAX_EVENT_TYPE_LEN)?;
        validate_bounded_string("actor_id", &self.actor_id, MAX_ACTOR_ID_LEN)?;

        if self.signature.is_empty() || self.signature.len() > MAX_SIGNATURE_LEN {
            return Err(HsiAntiEntropyError::StringTooLong {
                field: "signature".to_string(),
                len: self.signature.len(),
                max: MAX_SIGNATURE_LEN,
            });
        }

        if self.attestation_hashes.is_empty()
            || self.attestation_hashes.len() > MAX_ATTESTATION_HASHES_PER_EVENT
        {
            return Err(HsiAntiEntropyError::DeliverProofCountExceeded {
                actual: self.attestation_hashes.len(),
                max: MAX_ATTESTATION_HASHES_PER_EVENT,
            });
        }

        let computed = EventHasher::hash_event(&self.payload, &self.prev_hash);
        if computed != self.event_hash {
            return Err(HsiAntiEntropyError::DeliveredEventHashInvalid {
                seq_id: self.seq_id,
            });
        }
        Ok(())
    }

    /// Returns a conservative wire-size estimate for budget accounting.
    #[must_use]
    pub fn estimated_wire_bytes(&self) -> usize {
        let attestation_bytes = self.attestation_hashes.len().saturating_mul(HASH_SIZE);
        self.event_type
            .len()
            .saturating_add(self.payload.len())
            .saturating_add(HASH_SIZE)
            .saturating_add(HASH_SIZE)
            .saturating_add(std::mem::size_of::<u64>())
            .saturating_add(self.actor_id.len())
            .saturating_add(self.signature.len())
            .saturating_add(attestation_bytes)
    }
}

/// `DELIVER_EVENTS` message carrying bounded requested events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AntiEntropyDeliver {
    /// Request identifier being satisfied.
    pub request_id: String,
    /// Session identifier for budget accounting.
    pub session_id: String,
    /// Cell identifier.
    pub cell_id: String,
    /// Issuer identity for replay protection.
    pub issuer_id: String,
    /// Issuer HLC timestamp.
    pub issuer_hlc: Hlc,
    /// Issuer monotone sequence.
    pub issuer_sequence: u64,
    /// Nonce copied from request.
    pub nonce: u64,
    /// Inclusive delivered sequence start.
    pub seq_start: u64,
    /// Inclusive delivered sequence end.
    pub seq_end: u64,
    /// Digest for delivered range.
    pub range_digest: Hash,
    /// Merkle proof hashes (bounded by `O(log max_leaves)`).
    pub proof_hashes: Vec<Hash>,
    /// Delivered events for requested range.
    pub events: Vec<DeliveredEvent>,
}

impl AntiEntropyDeliver {
    /// Validates structural and integrity constraints.
    ///
    /// # Errors
    ///
    /// Returns [`HsiAntiEntropyError`] when any ingress or integrity invariant
    /// is violated.
    pub fn validate(&self) -> Result<(), HsiAntiEntropyError> {
        validate_bounded_string("request_id", &self.request_id, MAX_REQUEST_ID_LEN)?;
        validate_bounded_string("session_id", &self.session_id, MAX_SESSION_ID_LEN)?;
        validate_bounded_string("cell_id", &self.cell_id, MAX_CELL_ID_LEN)?;
        validate_bounded_string("issuer_id", &self.issuer_id, MAX_ISSUER_ID_LEN)?;
        validate_inclusive_range(self.seq_start, self.seq_end)?;

        if self.events.len() > MAX_EVENTS_PER_DELIVER {
            return Err(HsiAntiEntropyError::DeliverEventCountExceeded {
                actual: self.events.len(),
                max: MAX_EVENTS_PER_DELIVER,
            });
        }
        if self.proof_hashes.len() > MAX_DELIVER_PROOF_HASHES {
            return Err(HsiAntiEntropyError::DeliverProofCountExceeded {
                actual: self.proof_hashes.len(),
                max: MAX_DELIVER_PROOF_HASHES,
            });
        }

        let expected_count = inclusive_span_len(self.seq_start, self.seq_end)?;
        if expected_count != self.events.len() {
            return Err(HsiAntiEntropyError::DeliverSpanMismatch {
                expected: expected_count,
                actual: self.events.len(),
            });
        }

        for event in &self.events {
            event.validate()?;
        }

        let sync_events = self.to_sync_events();
        let Some(first) = self.events.first() else {
            return Err(HsiAntiEntropyError::DeliverSpanMismatch {
                expected: expected_count,
                actual: 0,
            });
        };
        verify_sync_events_with_start_seq(&sync_events, &first.prev_hash, Some(self.seq_start))
            .map_err(|_| HsiAntiEntropyError::DeliveredEventHashInvalid {
                seq_id: self.seq_start,
            })?;

        let computed_digest = self.computed_range_digest()?;
        if computed_digest != self.range_digest {
            return Err(HsiAntiEntropyError::Defect {
                defect: Box::new(AntiEntropyDefect {
                    kind: AntiEntropyDefectKind::TamperedDelivery,
                    issuer_id: self.issuer_id.clone(),
                    relay_id: None,
                    cell_id: Some(self.cell_id.clone()),
                    session_id: Some(self.session_id.clone()),
                    correlation_id: Some(self.request_id.clone()),
                    detail: "range digest mismatch against delivered events".to_string(),
                }),
            });
        }

        Ok(())
    }

    /// Computes canonical JCS hash of the full deliver message.
    ///
    /// # Errors
    ///
    /// Returns [`HsiAntiEntropyError::CanonicalizationFailed`] when
    /// canonicalization fails.
    pub fn canonical_message_hash(&self) -> Result<Hash, HsiAntiEntropyError> {
        <Self as Canonicalizable>::canonical_hash(self).map_err(Into::into)
    }

    /// Computes the Merkle root digest of delivered event hashes.
    ///
    /// # Errors
    ///
    /// Returns [`HsiAntiEntropyError`] when tree construction fails.
    pub fn computed_range_digest(&self) -> Result<Hash, HsiAntiEntropyError> {
        let leaf_count = self.events.len();
        if leaf_count == 0 || leaf_count > MAX_TREE_LEAVES {
            return Err(HsiAntiEntropyError::DeliverEventCountExceeded {
                actual: leaf_count,
                max: MAX_TREE_LEAVES,
            });
        }

        let tree =
            MerkleTree::new(self.events.iter().map(|event| event.event_hash)).map_err(|_| {
                HsiAntiEntropyError::DeliverEventCountExceeded {
                    actual: self.events.len(),
                    max: MAX_TREE_LEAVES,
                }
            })?;
        Ok(tree.root())
    }

    /// Returns a conservative wire-size estimate for budget accounting.
    #[must_use]
    pub fn estimated_wire_bytes(&self) -> usize {
        let base = self
            .request_id
            .len()
            .saturating_add(self.session_id.len())
            .saturating_add(self.cell_id.len())
            .saturating_add(self.issuer_id.len())
            .saturating_add(self.proof_hashes.len().saturating_mul(HASH_SIZE))
            .saturating_add(std::mem::size_of::<u64>() * 4);
        self.events.iter().fold(base, |acc, event| {
            acc.saturating_add(event.estimated_wire_bytes())
        })
    }

    #[must_use]
    fn to_sync_events(&self) -> Vec<SyncEvent> {
        self.events
            .iter()
            .map(|event| SyncEvent {
                seq_id: event.seq_id,
                event_type: event.event_type.clone(),
                payload: event.payload.clone(),
                prev_hash: event.prev_hash,
                event_hash: event.event_hash,
                timestamp_ns: event.timestamp_ns,
            })
            .collect()
    }
}

/// Marker trait for replay-protected anti-entropy wire messages.
pub trait ReplayStamped: Canonicalizable {
    /// Returns issuer identifier.
    fn issuer_id(&self) -> &str;
    /// Returns issuer HLC timestamp.
    fn issuer_hlc(&self) -> Hlc;
    /// Returns issuer monotone sequence.
    fn issuer_sequence(&self) -> u64;
}

impl ReplayStamped for AntiEntropyOffer {
    fn issuer_id(&self) -> &str {
        &self.issuer_id
    }
    fn issuer_hlc(&self) -> Hlc {
        self.issuer_hlc
    }
    fn issuer_sequence(&self) -> u64 {
        self.issuer_sequence
    }
}

impl ReplayStamped for AntiEntropyCompare {
    fn issuer_id(&self) -> &str {
        &self.issuer_id
    }
    fn issuer_hlc(&self) -> Hlc {
        self.issuer_hlc
    }
    fn issuer_sequence(&self) -> u64 {
        self.issuer_sequence
    }
}

impl ReplayStamped for AntiEntropyRequestEvents {
    fn issuer_id(&self) -> &str {
        &self.issuer_id
    }
    fn issuer_hlc(&self) -> Hlc {
        self.issuer_hlc
    }
    fn issuer_sequence(&self) -> u64 {
        self.issuer_sequence
    }
}

impl ReplayStamped for AntiEntropyDeliver {
    fn issuer_id(&self) -> &str {
        &self.issuer_id
    }
    fn issuer_hlc(&self) -> Hlc {
        self.issuer_hlc
    }
    fn issuer_sequence(&self) -> u64 {
        self.issuer_sequence
    }
}

// ============================================================================
// Relay budget enforcement
// ============================================================================

/// Relay budget envelope for anti-entropy sessions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayBudget {
    /// Maximum events accepted per session.
    pub max_events_per_session: usize,
    /// Maximum bytes accepted per session.
    pub max_bytes_per_session: usize,
    /// Maximum relays allowed per cell fanout set.
    pub max_fanout: usize,
    /// Maximum concurrent anti-entropy sessions.
    pub max_concurrent_sessions: usize,
}

impl RelayBudget {
    /// Validates budget bounds.
    ///
    /// # Errors
    ///
    /// Returns [`HsiAntiEntropyError::InvalidBudget`] when any bound is zero
    /// or exceeds safe limits.
    pub fn validate(&self) -> Result<(), HsiAntiEntropyError> {
        if self.max_events_per_session == 0
            || self.max_events_per_session > MAX_EVENTS_PER_SESSION_BUDGET
        {
            return Err(HsiAntiEntropyError::InvalidBudget {
                reason: format!(
                    "max_events_per_session must be 1..={MAX_EVENTS_PER_SESSION_BUDGET}"
                ),
            });
        }
        if self.max_bytes_per_session == 0
            || self.max_bytes_per_session > MAX_BYTES_PER_SESSION_BUDGET
        {
            return Err(HsiAntiEntropyError::InvalidBudget {
                reason: format!("max_bytes_per_session must be 1..={MAX_BYTES_PER_SESSION_BUDGET}"),
            });
        }
        if self.max_fanout == 0 || self.max_fanout > MAX_FANOUT_BUDGET {
            return Err(HsiAntiEntropyError::InvalidBudget {
                reason: format!("max_fanout must be 1..={MAX_FANOUT_BUDGET}"),
            });
        }
        if self.max_concurrent_sessions == 0
            || self.max_concurrent_sessions > MAX_CONCURRENT_SESSION_BUDGET
        {
            return Err(HsiAntiEntropyError::InvalidBudget {
                reason: format!(
                    "max_concurrent_sessions must be 1..={MAX_CONCURRENT_SESSION_BUDGET}"
                ),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SessionUsage {
    cell_id: String,
    relay_id: Option<String>,
    events_used: usize,
    bytes_used: usize,
}

/// Read-only session budget snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionUsageSnapshot {
    /// Cell ID tied to the budget session.
    pub cell_id: String,
    /// Relay ID tied to the budget session.
    pub relay_id: Option<String>,
    /// Events already consumed.
    pub events_used: usize,
    /// Bytes already consumed.
    pub bytes_used: usize,
}

/// Budget enforcer for relay-bounded anti-entropy sessions.
#[derive(Debug, Clone)]
pub struct RelayBudgetEnforcer {
    budget: RelayBudget,
    sessions: BTreeMap<String, SessionUsage>,
    relay_fanout: BTreeMap<String, BTreeSet<String>>,
}

impl RelayBudgetEnforcer {
    /// Constructs a budget enforcer from validated budget configuration.
    ///
    /// # Errors
    ///
    /// Returns [`HsiAntiEntropyError::InvalidBudget`] for invalid bounds.
    pub fn new(budget: RelayBudget) -> Result<Self, HsiAntiEntropyError> {
        budget.validate()?;
        Ok(Self {
            budget,
            sessions: BTreeMap::new(),
            relay_fanout: BTreeMap::new(),
        })
    }

    /// Ensures a session exists and satisfies fanout/session budget bounds.
    ///
    /// # Errors
    ///
    /// Returns a structured budget/fanout defect on denial.
    pub fn ensure_session(
        &mut self,
        session_id: &str,
        cell_id: &str,
        issuer_id: &str,
        relay_id: Option<&str>,
    ) -> Result<(), HsiAntiEntropyError> {
        validate_bounded_string("session_id", session_id, MAX_SESSION_ID_LEN)?;
        validate_bounded_string("cell_id", cell_id, MAX_CELL_ID_LEN)?;
        validate_bounded_string("issuer_id", issuer_id, MAX_ISSUER_ID_LEN)?;
        if let Some(relay) = relay_id {
            validate_bounded_string("relay_id", relay, MAX_RELAY_ID_LEN)?;
        }

        if let Some(existing) = self.sessions.get(session_id) {
            if existing.cell_id != cell_id || existing.relay_id.as_deref() != relay_id {
                return Err(defect_error(
                    AntiEntropyDefectKind::BudgetExceeded,
                    issuer_id,
                    relay_id,
                    Some(cell_id),
                    Some(session_id),
                    None,
                    "session reused with conflicting cell/relay binding",
                ));
            }
            return Ok(());
        }

        if self.sessions.len() >= self.budget.max_concurrent_sessions {
            return Err(defect_error(
                AntiEntropyDefectKind::BudgetExceeded,
                issuer_id,
                relay_id,
                Some(cell_id),
                Some(session_id),
                None,
                "max_concurrent_sessions exceeded",
            ));
        }

        if let Some(relay) = relay_id {
            let current = self.relay_fanout.get(cell_id).map_or(0, BTreeSet::len);
            let already_present = self
                .relay_fanout
                .get(cell_id)
                .is_some_and(|set| set.contains(relay));
            if !already_present && current >= self.budget.max_fanout {
                return Err(defect_error(
                    AntiEntropyDefectKind::FanoutAmplification,
                    issuer_id,
                    Some(relay),
                    Some(cell_id),
                    Some(session_id),
                    None,
                    "max_fanout exceeded for cell",
                ));
            }
        }

        let usage = SessionUsage {
            cell_id: cell_id.to_string(),
            relay_id: relay_id.map(ToString::to_string),
            events_used: 0,
            bytes_used: 0,
        };
        self.sessions.insert(session_id.to_string(), usage);
        if let Some(relay) = relay_id {
            self.relay_fanout
                .entry(cell_id.to_string())
                .or_default()
                .insert(relay.to_string());
        }
        Ok(())
    }

    /// Records accepted delivery usage for an open session.
    ///
    /// # Errors
    ///
    /// Returns a structured budget defect if applying usage would exceed event
    /// or byte caps.
    pub fn record_delivery(
        &mut self,
        session_id: &str,
        issuer_id: &str,
        event_count: usize,
        byte_count: usize,
    ) -> Result<(), HsiAntiEntropyError> {
        let Some(existing) = self.sessions.get(session_id) else {
            return Err(HsiAntiEntropyError::InvalidBudget {
                reason: format!("unknown session_id {session_id}"),
            });
        };

        let next_events = existing
            .events_used
            .checked_add(event_count)
            .ok_or_else(|| HsiAntiEntropyError::InvalidBudget {
                reason: "event budget arithmetic overflow".to_string(),
            })?;
        let next_bytes = existing.bytes_used.checked_add(byte_count).ok_or_else(|| {
            HsiAntiEntropyError::InvalidBudget {
                reason: "byte budget arithmetic overflow".to_string(),
            }
        })?;

        if next_events > self.budget.max_events_per_session {
            return Err(defect_error(
                AntiEntropyDefectKind::BudgetExceeded,
                issuer_id,
                existing.relay_id.as_deref(),
                Some(&existing.cell_id),
                Some(session_id),
                None,
                "max_events_per_session exceeded",
            ));
        }
        if next_bytes > self.budget.max_bytes_per_session {
            return Err(defect_error(
                AntiEntropyDefectKind::BudgetExceeded,
                issuer_id,
                existing.relay_id.as_deref(),
                Some(&existing.cell_id),
                Some(session_id),
                None,
                "max_bytes_per_session exceeded",
            ));
        }

        let Some(usage) = self.sessions.get_mut(session_id) else {
            return Err(HsiAntiEntropyError::InvalidBudget {
                reason: format!("unknown session_id {session_id}"),
            });
        };
        usage.events_used = next_events;
        usage.bytes_used = next_bytes;
        Ok(())
    }

    /// Returns usage snapshot for the given session.
    #[must_use]
    pub fn session_usage(&self, session_id: &str) -> Option<SessionUsageSnapshot> {
        self.sessions
            .get(session_id)
            .map(|usage| SessionUsageSnapshot {
                cell_id: usage.cell_id.clone(),
                relay_id: usage.relay_id.clone(),
                events_used: usage.events_used,
                bytes_used: usage.bytes_used,
            })
    }

    /// Returns number of tracked sessions.
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Returns number of relays currently fanned out for the given cell.
    #[must_use]
    pub fn fanout_count(&self, cell_id: &str) -> usize {
        self.relay_fanout.get(cell_id).map_or(0, BTreeSet::len)
    }
}

// ============================================================================
// Replay protection
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReplayEntry {
    issuer_id: String,
    sequence: u64,
    message_hash: Hash,
}

/// Replay guard using per-issuer monotone sequences and HLC checks.
#[derive(Debug, Clone)]
pub struct ReplayProtector {
    max_entries: usize,
    window: VecDeque<ReplayEntry>,
    seen_sequences: BTreeSet<(String, u64)>,
    seen_hashes: BTreeSet<(String, Hash)>,
    high_water: BTreeMap<String, (Hlc, u64)>,
}

impl ReplayProtector {
    /// Constructs a replay protector with bounded log capacity.
    ///
    /// # Errors
    ///
    /// Returns [`HsiAntiEntropyError::InvalidBudget`] if `max_entries` is zero
    /// or exceeds [`MAX_REPLAY_LOG_ENTRIES`].
    pub fn new(max_entries: usize) -> Result<Self, HsiAntiEntropyError> {
        if max_entries == 0 || max_entries > MAX_REPLAY_LOG_ENTRIES {
            return Err(HsiAntiEntropyError::InvalidBudget {
                reason: format!("replay window must be 1..={MAX_REPLAY_LOG_ENTRIES}"),
            });
        }
        Ok(Self {
            max_entries,
            window: VecDeque::new(),
            seen_sequences: BTreeSet::new(),
            seen_hashes: BTreeSet::new(),
            high_water: BTreeMap::new(),
        })
    }

    /// Verifies replay monotonicity and records a message on success.
    ///
    /// # Errors
    ///
    /// Returns structured replay defects on duplicate or non-monotone issuer
    /// metadata.
    pub fn check_and_record<M>(&mut self, message: &M) -> Result<(), HsiAntiEntropyError>
    where
        M: ReplayStamped,
    {
        self.check(message)?;
        self.record(message)
    }

    /// Read-only monotonicity and duplicate check. Does NOT mutate state.
    ///
    /// Use this when you need to verify replay constraints before other
    /// authorization gates and only commit replay state after all checks
    /// pass.
    ///
    /// # Errors
    ///
    /// Returns structured replay defects on duplicate or non-monotone issuer
    /// metadata.
    pub fn check<M>(&self, message: &M) -> Result<(), HsiAntiEntropyError>
    where
        M: ReplayStamped,
    {
        let issuer_id = message.issuer_id();
        validate_bounded_string("issuer_id", issuer_id, MAX_ISSUER_ID_LEN)?;

        let sequence = message.issuer_sequence();
        let hlc = message.issuer_hlc();
        let message_hash =
            <M as Canonicalizable>::canonical_hash(message).map_err(HsiAntiEntropyError::from)?;

        if let Some((high_hlc, high_seq)) = self.high_water.get(issuer_id) {
            if sequence <= *high_seq || hlc < *high_hlc {
                return Err(defect_error(
                    AntiEntropyDefectKind::ReplayDetected,
                    issuer_id,
                    None,
                    None,
                    None,
                    None,
                    "issuer sequence/HLC is non-monotone",
                ));
            }
        }

        let seq_key = (issuer_id.to_string(), sequence);
        if self.seen_sequences.contains(&seq_key) {
            return Err(defect_error(
                AntiEntropyDefectKind::ReplayDetected,
                issuer_id,
                None,
                None,
                None,
                None,
                "issuer sequence was replayed",
            ));
        }

        let hash_key = (issuer_id.to_string(), message_hash);
        if self.seen_hashes.contains(&hash_key) {
            return Err(defect_error(
                AntiEntropyDefectKind::ReplayDetected,
                issuer_id,
                None,
                None,
                None,
                None,
                "issuer message hash was replayed",
            ));
        }

        Ok(())
    }

    /// Records a message into replay state. Must only be called after all
    /// authorization gates have passed.
    ///
    /// # Errors
    ///
    /// Returns [`HsiAntiEntropyError::CanonicalizationFailed`] if the
    /// message cannot be hashed.
    pub fn record<M>(&mut self, message: &M) -> Result<(), HsiAntiEntropyError>
    where
        M: ReplayStamped,
    {
        let issuer_id = message.issuer_id();
        let sequence = message.issuer_sequence();
        let hlc = message.issuer_hlc();
        let message_hash =
            <M as Canonicalizable>::canonical_hash(message).map_err(HsiAntiEntropyError::from)?;

        self.window.push_back(ReplayEntry {
            issuer_id: issuer_id.to_string(),
            sequence,
            message_hash,
        });
        self.seen_sequences
            .insert((issuer_id.to_string(), sequence));
        self.seen_hashes
            .insert((issuer_id.to_string(), message_hash));
        self.high_water
            .insert(issuer_id.to_string(), (hlc, sequence));

        // Evict oldest window entries when exceeding capacity.
        while self.window.len() > self.max_entries {
            if let Some(oldest) = self.window.pop_front() {
                self.seen_sequences
                    .remove(&(oldest.issuer_id.clone(), oldest.sequence));
                self.seen_hashes
                    .remove(&(oldest.issuer_id, oldest.message_hash));
            }
        }

        // Evict oldest high-water issuer entries when exceeding
        // MAX_REPLAY_ISSUERS to prevent unbounded memory growth under
        // adversarial or high-churn issuer sets.
        while self.high_water.len() > MAX_REPLAY_ISSUERS {
            // Evict the issuer with the lowest sequence number.
            let evict_key = self
                .high_water
                .iter()
                .min_by_key(|(_, (_, seq))| *seq)
                .map(|(k, _)| k.clone());
            if let Some(key) = evict_key {
                self.high_water.remove(&key);
            } else {
                break;
            }
        }

        Ok(())
    }

    /// Returns replay window length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.window.len()
    }

    /// Returns true when the replay window is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.window.is_empty()
    }

    /// Returns the number of tracked issuers in the high-water map.
    #[must_use]
    pub fn high_water_len(&self) -> usize {
        self.high_water.len()
    }
}

// ============================================================================
// Byzantine relay detection
// ============================================================================

/// Stateful detector for relay amplification and delivery abuse patterns.
#[derive(Debug, Clone)]
pub struct ByzantineRelayDetector {
    max_cells_per_relay: usize,
    relay_claims: BTreeMap<String, BTreeSet<String>>,
}

impl ByzantineRelayDetector {
    /// Creates a relay detector.
    ///
    /// # Errors
    ///
    /// Returns [`HsiAntiEntropyError::InvalidBudget`] if cap is invalid.
    pub fn new(max_cells_per_relay: usize) -> Result<Self, HsiAntiEntropyError> {
        if max_cells_per_relay == 0 || max_cells_per_relay > MAX_FANOUT_BUDGET {
            return Err(HsiAntiEntropyError::InvalidBudget {
                reason: format!("max_cells_per_relay must be 1..={MAX_FANOUT_BUDGET}"),
            });
        }
        Ok(Self {
            max_cells_per_relay,
            relay_claims: BTreeMap::new(),
        })
    }

    /// Records a relay claim that it can represent a given cell.
    ///
    /// # Errors
    ///
    /// Returns a structured fanout amplification defect on cap exceedance.
    pub fn observe_relay_claim(
        &mut self,
        relay_id: &str,
        cell_id: &str,
        issuer_id: &str,
    ) -> Result<(), HsiAntiEntropyError> {
        validate_bounded_string("relay_id", relay_id, MAX_RELAY_ID_LEN)?;
        validate_bounded_string("cell_id", cell_id, MAX_CELL_ID_LEN)?;
        validate_bounded_string("issuer_id", issuer_id, MAX_ISSUER_ID_LEN)?;

        if !self.relay_claims.contains_key(relay_id)
            && self.relay_claims.len() >= MAX_TRACKED_RELAYS
        {
            return Err(defect_error(
                AntiEntropyDefectKind::FanoutAmplification,
                issuer_id,
                Some(relay_id),
                Some(cell_id),
                None,
                None,
                "relay claim tracker is at capacity",
            ));
        }

        let claim_count = self.relay_claims.get(relay_id).map_or(0, BTreeSet::len);
        let known = self
            .relay_claims
            .get(relay_id)
            .is_some_and(|set| set.contains(cell_id));
        if !known && claim_count >= self.max_cells_per_relay {
            return Err(defect_error(
                AntiEntropyDefectKind::FanoutAmplification,
                issuer_id,
                Some(relay_id),
                Some(cell_id),
                None,
                None,
                "relay claimed more cells than configured cap",
            ));
        }

        self.relay_claims
            .entry(relay_id.to_string())
            .or_default()
            .insert(cell_id.to_string());
        Ok(())
    }

    /// Returns `true` when relay amplification is currently tracked.
    #[must_use]
    pub fn has_claim(&self, relay_id: &str, cell_id: &str) -> bool {
        self.relay_claims
            .get(relay_id)
            .is_some_and(|set| set.contains(cell_id))
    }
}

// ============================================================================
// Pull-only protocol enforcement
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)] // Fields read via clone in accept_deliver binding checks.
struct OutstandingRequest {
    request_id: String,
    session_id: String,
    cell_id: String,
    issuer_id: String,
    nonce: u64,
    seq_start: u64,
    seq_end: u64,
    expected_range_digest: Hash,
}

/// Verifier abstraction for event signature/quorum attestation checks.
pub trait EventAttestationVerifier: fmt::Debug + Send + Sync {
    /// Returns `true` when event signature/attestation is valid.
    fn verify_event(&self, event: &DeliveredEvent) -> bool;
}

/// Pull-only enforcer for offer/compare/request/deliver protocol sessions.
#[derive(Debug)]
pub struct PullOnlyEnforcer {
    local_is_initiator: bool,
    outstanding_requests: BTreeMap<String, OutstandingRequest>,
    budget_enforcer: RelayBudgetEnforcer,
    replay_protector: ReplayProtector,
    relay_detector: ByzantineRelayDetector,
}

impl PullOnlyEnforcer {
    /// Creates a pull-only enforcer with default replay window sizing.
    ///
    /// # Errors
    ///
    /// Returns configuration errors for invalid budgets.
    pub fn new(
        local_is_initiator: bool,
        relay_budget: RelayBudget,
    ) -> Result<Self, HsiAntiEntropyError> {
        let budget_enforcer = RelayBudgetEnforcer::new(relay_budget)?;
        let replay_protector = ReplayProtector::new(MAX_OUTSTANDING_REQUESTS)?;
        let relay_detector = ByzantineRelayDetector::new(relay_budget.max_fanout)?;
        Ok(Self {
            local_is_initiator,
            outstanding_requests: BTreeMap::new(),
            budget_enforcer,
            replay_protector,
            relay_detector,
        })
    }

    /// Registers a pull request that authorizes a future `DELIVER_EVENTS`.
    ///
    /// # Errors
    ///
    /// Returns structured defects for budget, replay, fanout, or role
    /// violations.
    pub fn register_request(
        &mut self,
        request: &AntiEntropyRequestEvents,
        relay_id: Option<&str>,
    ) -> Result<(), HsiAntiEntropyError> {
        if !self.local_is_initiator {
            return Err(defect_error(
                AntiEntropyDefectKind::UnsolicitedDelivery,
                &request.issuer_id,
                relay_id,
                Some(&request.cell_id),
                Some(&request.session_id),
                Some(&request.request_id),
                "local node is not configured as pull initiator",
            ));
        }

        request.validate()?;
        self.replay_protector.check_and_record(request)?;

        if self.outstanding_requests.len() >= MAX_OUTSTANDING_REQUESTS {
            return Err(HsiAntiEntropyError::OutstandingRequestLimitExceeded {
                count: self.outstanding_requests.len(),
                max: MAX_OUTSTANDING_REQUESTS,
            });
        }

        if let Some(relay) = relay_id {
            self.relay_detector
                .observe_relay_claim(relay, &request.cell_id, &request.issuer_id)?;
        }

        self.budget_enforcer.ensure_session(
            &request.session_id,
            &request.cell_id,
            &request.issuer_id,
            relay_id,
        )?;

        if self.outstanding_requests.contains_key(&request.request_id) {
            return Err(defect_error(
                AntiEntropyDefectKind::ReplayDetected,
                &request.issuer_id,
                relay_id,
                Some(&request.cell_id),
                Some(&request.session_id),
                Some(&request.request_id),
                "duplicate request_id in outstanding set",
            ));
        }

        let entry = OutstandingRequest {
            request_id: request.request_id.clone(),
            session_id: request.session_id.clone(),
            cell_id: request.cell_id.clone(),
            issuer_id: request.issuer_id.clone(),
            nonce: request.nonce,
            seq_start: request.seq_start,
            seq_end: request.seq_end,
            expected_range_digest: request.expected_range_digest,
        };
        self.outstanding_requests
            .insert(request.request_id.clone(), entry);
        Ok(())
    }

    /// Validates and admits a `DELIVER_EVENTS` message against outstanding pull
    /// state.
    ///
    /// # Errors
    ///
    /// Returns structured defects for unsolicited push, tampering, replay,
    /// invalid attestation, and budget exceedance.
    pub fn accept_deliver(
        &mut self,
        deliver: &AntiEntropyDeliver,
        verifier: &dyn EventAttestationVerifier,
    ) -> Result<(), HsiAntiEntropyError> {
        self.validate_deliver_preconditions(deliver)?;

        // SECURITY: Read-only replay check BEFORE request correlation.
        // State mutation (record) is deferred until after all authorization
        // gates pass. This prevents unsolicited deliveries from poisoning
        // replay high-water marks for legitimate future deliveries.
        self.replay_protector.check(deliver)?;

        let request = match self.outstanding_requests.get(&deliver.request_id) {
            Some(req) => req.clone(),
            None => {
                return Err(defect_error(
                    AntiEntropyDefectKind::UnsolicitedDelivery,
                    &deliver.issuer_id,
                    None,
                    Some(&deliver.cell_id),
                    Some(&deliver.session_id),
                    Some(&deliver.request_id),
                    "deliver without matching prior request",
                ));
            },
        };

        // Verify request/deliver binding (identity, nonce, range, digest).
        self.verify_request_binding(&request, deliver)?;

        // SECURITY: Check budget availability BEFORE expensive per-event
        // cryptographic verification. This prevents CPU amplification where
        // an attacker sends deliveries that trigger verification loops but
        // would exceed budget anyway. The request is consumed on budget
        // failure to prevent infinite retry.
        let bytes = deliver.estimated_wire_bytes();
        if let Err(budget_err) = self.budget_enforcer.record_delivery(
            &deliver.session_id,
            &request.issuer_id,
            deliver.events.len(),
            bytes,
        ) {
            self.outstanding_requests.remove(&deliver.request_id);
            return Err(budget_err);
        }

        for event in &deliver.events {
            if !verifier.verify_event(event) {
                // Consume the request to prevent retry abuse with invalid
                // attestations that would repeatedly trigger verification.
                self.outstanding_requests.remove(&deliver.request_id);
                return Err(defect_error(
                    AntiEntropyDefectKind::InvalidAttestation,
                    &deliver.issuer_id,
                    None,
                    Some(&deliver.cell_id),
                    Some(&deliver.session_id),
                    Some(&deliver.request_id),
                    &format!("event attestation rejected at seq {}", event.seq_id),
                ));
            }
        }

        // SECURITY: Only record replay state AFTER all authorization gates
        // have passed. This ensures unsolicited or tampered deliveries
        // cannot poison replay high-water marks.
        self.replay_protector.record(deliver)?;

        self.outstanding_requests.remove(&deliver.request_id);
        Ok(())
    }

    /// Validates deliver preconditions: initiator role and structural
    /// integrity.
    fn validate_deliver_preconditions(
        &self,
        deliver: &AntiEntropyDeliver,
    ) -> Result<(), HsiAntiEntropyError> {
        if !self.local_is_initiator {
            return Err(defect_error(
                AntiEntropyDefectKind::UnsolicitedDelivery,
                &deliver.issuer_id,
                None,
                Some(&deliver.cell_id),
                Some(&deliver.session_id),
                Some(&deliver.request_id),
                "local node is not configured as pull initiator",
            ));
        }

        if let Err(error) = deliver.validate() {
            return Err(defect_error(
                AntiEntropyDefectKind::TamperedDelivery,
                &deliver.issuer_id,
                None,
                Some(&deliver.cell_id),
                Some(&deliver.session_id),
                Some(&deliver.request_id),
                &format!("delivery validation failed: {error}"),
            ));
        }

        Ok(())
    }

    /// Verifies request/deliver binding: identity, nonce, ranges, and digest.
    /// Consumes (one-shot) the outstanding request on any mismatch to prevent
    /// retry abuse.
    fn verify_request_binding(
        &mut self,
        request: &OutstandingRequest,
        deliver: &AntiEntropyDeliver,
    ) -> Result<(), HsiAntiEntropyError> {
        // SECURITY: Verify issuer identity binding. The deliver issuer_id
        // MUST match the request issuer_id. Without this check, an attacker
        // could spoof a different issuer_id, causing budget to be charged to
        // the original requester while replay state is applied to the spoofed
        // identity.
        if request.issuer_id != deliver.issuer_id {
            self.outstanding_requests.remove(&deliver.request_id);
            return Err(defect_error(
                AntiEntropyDefectKind::TamperedDelivery,
                &deliver.issuer_id,
                None,
                Some(&deliver.cell_id),
                Some(&deliver.session_id),
                Some(&deliver.request_id),
                "deliver issuer_id does not match request issuer_id",
            ));
        }

        if request.nonce != deliver.nonce
            || request.seq_start != deliver.seq_start
            || request.seq_end != deliver.seq_end
            || request.session_id != deliver.session_id
            || request.cell_id != deliver.cell_id
        {
            self.outstanding_requests.remove(&deliver.request_id);
            return Err(defect_error(
                AntiEntropyDefectKind::TamperedDelivery,
                &deliver.issuer_id,
                None,
                Some(&deliver.cell_id),
                Some(&deliver.session_id),
                Some(&deliver.request_id),
                "deliver metadata does not match authorized request",
            ));
        }

        if request.expected_range_digest != deliver.range_digest {
            self.outstanding_requests.remove(&deliver.request_id);
            return Err(defect_error(
                AntiEntropyDefectKind::TamperedDelivery,
                &deliver.issuer_id,
                None,
                Some(&deliver.cell_id),
                Some(&deliver.session_id),
                Some(&deliver.request_id),
                "deliver digest does not match requested digest",
            ));
        }

        Ok(())
    }

    /// Returns number of outstanding pull requests.
    #[must_use]
    pub fn outstanding_request_count(&self) -> usize {
        self.outstanding_requests.len()
    }

    /// Returns budget usage for a session, if present.
    #[must_use]
    pub fn session_usage(&self, session_id: &str) -> Option<SessionUsageSnapshot> {
        self.budget_enforcer.session_usage(session_id)
    }
}

// ============================================================================
// Helpers
// ============================================================================

#[must_use]
fn contains_control_characters(value: &str) -> bool {
    value.bytes().any(|byte| byte < 32 || byte == 127)
}

fn validate_bounded_string(
    field: &str,
    value: &str,
    max_len: usize,
) -> Result<(), HsiAntiEntropyError> {
    if value.len() > max_len {
        return Err(HsiAntiEntropyError::StringTooLong {
            field: field.to_string(),
            len: value.len(),
            max: max_len,
        });
    }
    if contains_control_characters(value) {
        return Err(HsiAntiEntropyError::ControlCharactersNotAllowed {
            field: field.to_string(),
        });
    }
    Ok(())
}

const fn validate_inclusive_range(start: u64, end: u64) -> Result<(), HsiAntiEntropyError> {
    if start > end {
        return Err(HsiAntiEntropyError::InvalidRange { start, end });
    }
    Ok(())
}

fn inclusive_span_len(start: u64, end: u64) -> Result<usize, HsiAntiEntropyError> {
    let span = end
        .checked_sub(start)
        .and_then(|value| value.checked_add(1))
        .ok_or(HsiAntiEntropyError::InvalidRange { start, end })?;
    usize::try_from(span).map_err(|_| HsiAntiEntropyError::InvalidRange { start, end })
}

fn defect_error(
    kind: AntiEntropyDefectKind,
    issuer_id: &str,
    relay_id: Option<&str>,
    cell_id: Option<&str>,
    session_id: Option<&str>,
    correlation_id: Option<&str>,
    detail: &str,
) -> HsiAntiEntropyError {
    let detail_bounded = if detail.len() > MAX_DEFECT_DETAIL_LEN {
        detail[..MAX_DEFECT_DETAIL_LEN].to_string()
    } else {
        detail.to_string()
    };

    HsiAntiEntropyError::Defect {
        defect: Box::new(AntiEntropyDefect {
            kind,
            issuer_id: issuer_id.to_string(),
            relay_id: relay_id.map(ToString::to_string),
            cell_id: cell_id.map(ToString::to_string),
            session_id: session_id.map(ToString::to_string),
            correlation_id: correlation_id.map(ToString::to_string),
            detail: detail_bounded,
        }),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct AcceptAllVerifier;
    impl EventAttestationVerifier for AcceptAllVerifier {
        fn verify_event(&self, event: &DeliveredEvent) -> bool {
            !event.signature.is_empty() && !event.attestation_hashes.is_empty()
        }
    }

    #[derive(Debug)]
    struct RejectAllVerifier;
    impl EventAttestationVerifier for RejectAllVerifier {
        fn verify_event(&self, _event: &DeliveredEvent) -> bool {
            false
        }
    }

    fn default_budget() -> RelayBudget {
        RelayBudget {
            max_events_per_session: 128,
            max_bytes_per_session: 1024 * 1024,
            max_fanout: 4,
            max_concurrent_sessions: 16,
        }
    }

    fn mk_offer(issuer_sequence: u64) -> AntiEntropyOffer {
        AntiEntropyOffer {
            offer_id: "offer-1".to_string(),
            cell_id: "cell-a".to_string(),
            issuer_id: "issuer-a".to_string(),
            issuer_hlc: Hlc::new(10_000 + issuer_sequence, 0),
            issuer_sequence,
            ledger_head_seq: 10,
            ledger_head_hash: [1u8; HASH_SIZE],
            merkle_root_hash: [2u8; HASH_SIZE],
            range_bounds: (1, 10),
            max_leaves: 1024,
        }
    }

    fn mk_compare(issuer_sequence: u64) -> AntiEntropyCompare {
        AntiEntropyCompare {
            compare_id: "cmp-1".to_string(),
            offer_id: "offer-1".to_string(),
            cell_id: "cell-a".to_string(),
            issuer_id: "issuer-a".to_string(),
            issuer_hlc: Hlc::new(10_000 + issuer_sequence, 0),
            issuer_sequence,
            range_start: 1,
            range_end: 3,
            depth: 2,
        }
    }

    fn build_events(seq_start: u64, count: usize, prev_hash: Hash) -> Vec<DeliveredEvent> {
        let mut current_prev = prev_hash;
        let mut events = Vec::with_capacity(count);
        for index in 0..count {
            let seq_id = seq_start + u64::try_from(index).unwrap_or(0);
            let payload = format!("payload-{seq_id}").into_bytes();
            let event_hash = EventHasher::hash_event(&payload, &current_prev);
            let event = DeliveredEvent {
                seq_id,
                event_type: "unit.test".to_string(),
                payload,
                prev_hash: current_prev,
                event_hash,
                timestamp_ns: 1_000_000 + seq_id,
                actor_id: "actor-1".to_string(),
                signature: vec![0xAB; 64],
                attestation_hashes: vec![[0xCD; HASH_SIZE]],
            };
            current_prev = event_hash;
            events.push(event);
        }
        events
    }

    fn range_digest_for(events: &[DeliveredEvent]) -> Hash {
        let tree = MerkleTree::new(events.iter().map(|event| event.event_hash)).unwrap();
        tree.root()
    }

    fn mk_request(
        request_id: &str,
        session_id: &str,
        seq_start: u64,
        seq_end: u64,
        nonce: u64,
        digest: Hash,
        issuer_sequence: u64,
    ) -> AntiEntropyRequestEvents {
        AntiEntropyRequestEvents {
            request_id: request_id.to_string(),
            offer_id: "offer-1".to_string(),
            compare_id: "cmp-1".to_string(),
            session_id: session_id.to_string(),
            cell_id: "cell-a".to_string(),
            issuer_id: "issuer-a".to_string(),
            issuer_hlc: Hlc::new(10_000 + issuer_sequence, 0),
            issuer_sequence,
            nonce,
            seq_start,
            seq_end,
            expected_range_digest: digest,
        }
    }

    fn mk_deliver(
        request_id: &str,
        session_id: &str,
        seq_start: u64,
        seq_end: u64,
        nonce: u64,
        events: Vec<DeliveredEvent>,
        issuer_sequence: u64,
    ) -> AntiEntropyDeliver {
        mk_deliver_with_issuer(
            request_id,
            session_id,
            "issuer-a",
            seq_start,
            seq_end,
            nonce,
            events,
            issuer_sequence,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn mk_deliver_with_issuer(
        request_id: &str,
        session_id: &str,
        issuer_id: &str,
        seq_start: u64,
        seq_end: u64,
        nonce: u64,
        events: Vec<DeliveredEvent>,
        issuer_sequence: u64,
    ) -> AntiEntropyDeliver {
        // Use the same HLC base (10_000) as other wire messages so that
        // replay monotonicity is satisfied when issuer_id matches across
        // request and deliver messages.
        AntiEntropyDeliver {
            request_id: request_id.to_string(),
            session_id: session_id.to_string(),
            cell_id: "cell-a".to_string(),
            issuer_id: issuer_id.to_string(),
            issuer_hlc: Hlc::new(10_000 + issuer_sequence, 0),
            issuer_sequence,
            nonce,
            seq_start,
            seq_end,
            range_digest: range_digest_for(&events),
            proof_hashes: vec![[0x11; HASH_SIZE]],
            events,
        }
    }

    #[test]
    fn tck_00381_offer_compare_request_deliver_happy_path() {
        let offer = mk_offer(1);
        let compare = mk_compare(2);
        assert!(offer.validate().is_ok());
        assert!(compare.validate().is_ok());

        let mut enforcer = PullOnlyEnforcer::new(true, default_budget()).unwrap();

        let events = build_events(1, 3, [0u8; HASH_SIZE]);
        let digest = range_digest_for(&events);
        let request = mk_request("req-1", "sess-1", 1, 3, 7, digest, 3);
        enforcer
            .register_request(&request, Some("relay-1"))
            .unwrap();

        let deliver = mk_deliver("req-1", "sess-1", 1, 3, 7, events, 4);
        enforcer
            .accept_deliver(&deliver, &AcceptAllVerifier)
            .unwrap();

        assert_eq!(enforcer.outstanding_request_count(), 0);
        let usage = enforcer.session_usage("sess-1").unwrap();
        assert!(usage.events_used > 0);
        assert!(usage.bytes_used > 0);
    }

    #[test]
    fn tck_00381_pull_only_unsolicited_deliver_rejected() {
        let mut enforcer = PullOnlyEnforcer::new(true, default_budget()).unwrap();
        let events = build_events(10, 1, [0u8; HASH_SIZE]);
        let deliver = mk_deliver("req-missing", "sess-x", 10, 10, 99, events, 9);

        let err = enforcer
            .accept_deliver(&deliver, &AcceptAllVerifier)
            .unwrap_err();
        let defect = err.defect().unwrap();
        assert_eq!(defect.kind, AntiEntropyDefectKind::UnsolicitedDelivery);
    }

    #[test]
    fn tck_00381_budget_enforcement_denies_after_exhaustion() {
        let mut budget = default_budget();
        budget.max_events_per_session = 2;
        let mut enforcer = PullOnlyEnforcer::new(true, budget).unwrap();

        let events_a = build_events(1, 2, [0u8; HASH_SIZE]);
        let request_a = mk_request("req-a", "sess-1", 1, 2, 42, range_digest_for(&events_a), 10);
        enforcer
            .register_request(&request_a, Some("relay-1"))
            .unwrap();
        let deliver_a = mk_deliver("req-a", "sess-1", 1, 2, 42, events_a, 11);
        enforcer
            .accept_deliver(&deliver_a, &AcceptAllVerifier)
            .unwrap();

        let events_b = build_events(3, 1, deliver_a.events[1].event_hash);
        let request_b = mk_request("req-b", "sess-1", 3, 3, 43, range_digest_for(&events_b), 12);
        enforcer
            .register_request(&request_b, Some("relay-1"))
            .unwrap();
        let deliver_b = mk_deliver("req-b", "sess-1", 3, 3, 43, events_b, 13);

        let err = enforcer
            .accept_deliver(&deliver_b, &AcceptAllVerifier)
            .unwrap_err();
        let defect = err.defect().unwrap();
        assert_eq!(defect.kind, AntiEntropyDefectKind::BudgetExceeded);
    }

    #[test]
    fn tck_00381_replay_protector_rejects_duplicate_offers_and_delivers() {
        let mut replay = ReplayProtector::new(32).unwrap();
        let offer = mk_offer(100);
        replay.check_and_record(&offer).unwrap();
        let duplicate_offer = replay.check_and_record(&offer).unwrap_err();
        assert_eq!(
            duplicate_offer.defect().unwrap().kind,
            AntiEntropyDefectKind::ReplayDetected
        );

        let events = build_events(20, 1, [0u8; HASH_SIZE]);
        let deliver = mk_deliver("req-dup", "sess-dup", 20, 20, 5, events, 101);
        replay.check_and_record(&deliver).unwrap();
        let duplicate_deliver = replay.check_and_record(&deliver).unwrap_err();
        assert_eq!(
            duplicate_deliver.defect().unwrap().kind,
            AntiEntropyDefectKind::ReplayDetected
        );
    }

    #[test]
    fn tck_00381_byzantine_detector_tampered_and_fanout_caught() {
        let mut detector = ByzantineRelayDetector::new(1).unwrap();
        detector
            .observe_relay_claim("relay-1", "cell-a", "issuer-a")
            .unwrap();

        let fanout_err = detector
            .observe_relay_claim("relay-1", "cell-b", "issuer-a")
            .unwrap_err();
        assert_eq!(
            fanout_err.defect().unwrap().kind,
            AntiEntropyDefectKind::FanoutAmplification
        );

        let mut enforcer = PullOnlyEnforcer::new(true, default_budget()).unwrap();
        let events = build_events(1, 1, [0u8; HASH_SIZE]);
        let request = mk_request("req-1", "sess-1", 1, 1, 1, range_digest_for(&events), 4);
        enforcer
            .register_request(&request, Some("relay-1"))
            .unwrap();

        let mut tampered = mk_deliver("req-1", "sess-1", 1, 1, 1, events, 5);
        tampered.events[0].event_hash = [0xFF; HASH_SIZE];

        let err = enforcer
            .accept_deliver(&tampered, &AcceptAllVerifier)
            .unwrap_err();
        assert_eq!(
            err.defect().unwrap().kind,
            AntiEntropyDefectKind::TamperedDelivery
        );
    }

    #[test]
    fn tck_00381_byzantine_relay_simulation_drop_duplicate_reorder_lie() {
        let mut enforcer = PullOnlyEnforcer::new(true, default_budget()).unwrap();
        let events = build_events(1, 3, [0u8; HASH_SIZE]);
        let digest = range_digest_for(&events);
        let request = mk_request("req-sim", "sess-sim", 1, 3, 70, digest, 1);
        enforcer
            .register_request(&request, Some("relay-sim"))
            .unwrap();

        // Duplicate attempt: first delivery accepted.
        let deliver_ok = mk_deliver("req-sim", "sess-sim", 1, 3, 70, events.clone(), 2);
        enforcer
            .accept_deliver(&deliver_ok, &AcceptAllVerifier)
            .unwrap();

        // Duplicate replay of same frame.
        let replay_err = enforcer
            .accept_deliver(&deliver_ok, &AcceptAllVerifier)
            .unwrap_err();
        assert_eq!(
            replay_err.defect().unwrap().kind,
            AntiEntropyDefectKind::ReplayDetected
        );

        // Reordered frame for a fresh request.
        let reordered_request = mk_request("req-reorder", "sess-sim", 4, 6, 71, digest, 3);
        enforcer
            .register_request(&reordered_request, Some("relay-sim"))
            .unwrap();
        let mut reordered_events = build_events(4, 3, events[2].event_hash);
        reordered_events.swap(0, 2);
        let reordered_deliver =
            mk_deliver("req-reorder", "sess-sim", 4, 6, 71, reordered_events, 4);
        let reorder_err = enforcer
            .accept_deliver(&reordered_deliver, &AcceptAllVerifier)
            .unwrap_err();
        assert_eq!(
            reorder_err.defect().unwrap().kind,
            AntiEntropyDefectKind::TamperedDelivery
        );

        // Lie: wrong digest.
        let lie_events = build_events(7, 1, [0u8; HASH_SIZE]);
        let lie_request = mk_request(
            "req-lie",
            "sess-sim",
            7,
            7,
            72,
            range_digest_for(&lie_events),
            5,
        );
        enforcer
            .register_request(&lie_request, Some("relay-sim"))
            .unwrap();
        let mut lie_deliver = mk_deliver("req-lie", "sess-sim", 7, 7, 72, lie_events, 6);
        lie_deliver.range_digest = [0xEE; HASH_SIZE];
        let lie_err = enforcer
            .accept_deliver(&lie_deliver, &AcceptAllVerifier)
            .unwrap_err();
        assert_eq!(
            lie_err.defect().unwrap().kind,
            AntiEntropyDefectKind::TamperedDelivery
        );
    }

    #[test]
    fn tck_00381_budget_exhaustion_under_adversarial_load() {
        let mut budget = default_budget();
        budget.max_bytes_per_session = 350;
        let mut enforcer = PullOnlyEnforcer::new(true, budget).unwrap();

        let mut denied = 0usize;
        let mut prev = [0u8; HASH_SIZE];
        // Use strictly monotone issuer sequences: request at 2*index+1,
        // deliver at 2*index+2, so the interleaved sequence is always
        // increasing for the same issuer.
        for index in 0..8usize {
            let seq = u64::try_from(index + 1).unwrap();
            let events = build_events(seq, 1, prev);
            prev = events[0].event_hash;
            let req_issuer_seq = u64::try_from(2 * index + 1).unwrap();
            let del_issuer_seq = u64::try_from(2 * index + 2).unwrap();
            let request = mk_request(
                &format!("req-{index}"),
                "sess-ddos",
                seq,
                seq,
                seq,
                range_digest_for(&events),
                req_issuer_seq,
            );
            enforcer
                .register_request(&request, Some("relay-ddos"))
                .unwrap();
            let deliver = mk_deliver(
                &format!("req-{index}"),
                "sess-ddos",
                seq,
                seq,
                seq,
                events,
                del_issuer_seq,
            );
            if enforcer
                .accept_deliver(&deliver, &AcceptAllVerifier)
                .is_err()
            {
                denied = denied.saturating_add(1);
            }
        }

        assert!(denied > 0);
    }

    #[test]
    fn tck_00381_invalid_attestation_denied() {
        let mut enforcer = PullOnlyEnforcer::new(true, default_budget()).unwrap();
        let events = build_events(1, 1, [0u8; HASH_SIZE]);
        let request = mk_request(
            "req-verify",
            "sess-verify",
            1,
            1,
            1,
            range_digest_for(&events),
            1,
        );
        enforcer
            .register_request(&request, Some("relay-1"))
            .unwrap();
        let deliver = mk_deliver("req-verify", "sess-verify", 1, 1, 1, events, 2);

        let err = enforcer
            .accept_deliver(&deliver, &RejectAllVerifier)
            .unwrap_err();
        assert_eq!(
            err.defect().unwrap().kind,
            AntiEntropyDefectKind::InvalidAttestation
        );
    }

    // ─── Regression: unsolicited deliver must NOT poison replay state ─────
    #[test]
    fn tck_00381_unsolicited_deliver_does_not_poison_replay_for_valid_deliver() {
        // SECURITY REGRESSION: Verifies the blocker fix — an unsolicited
        // delivery (no matching request) must NOT advance the replay
        // high-water mark so that a subsequent legitimate delivery with
        // the same issuer sequence still succeeds.
        let events = build_events(1, 1, [0u8; HASH_SIZE]);
        let mut enforcer = PullOnlyEnforcer::new(true, default_budget()).unwrap();

        // Register a legitimate request.
        let digest = range_digest_for(&events);
        let request = mk_request("req-legit", "sess-1", 1, 1, 42, digest, 1);
        enforcer
            .register_request(&request, Some("relay-1"))
            .unwrap();

        // Attempt an unsolicited delivery (request_id does not match).
        let unsolicited = mk_deliver("req-bogus", "sess-1", 1, 1, 42, events.clone(), 10);
        let err = enforcer
            .accept_deliver(&unsolicited, &AcceptAllVerifier)
            .unwrap_err();
        assert_eq!(
            err.defect().unwrap().kind,
            AntiEntropyDefectKind::UnsolicitedDelivery,
            "unsolicited deliver must be rejected"
        );

        // Now deliver the SAME events with the legitimate request_id.
        // The replay protector must NOT reject this because the unsolicited
        // delivery above should not have mutated replay state.
        let legit = mk_deliver("req-legit", "sess-1", 1, 1, 42, events, 10);
        enforcer
            .accept_deliver(&legit, &AcceptAllVerifier)
            .expect("legitimate deliver must succeed after unsolicited rejection");
    }

    // ─── Regression: replay high-water eviction bounded ──────────────────
    #[test]
    fn tck_00381_replay_high_water_eviction_bounded() {
        // SECURITY REGRESSION: Verifies the major fix — the high-water
        // map must not grow unbounded. After inserting MAX_REPLAY_ISSUERS + N
        // distinct issuers, the map must not exceed MAX_REPLAY_ISSUERS.
        let mut rp = ReplayProtector::new(MAX_REPLAY_LOG_ENTRIES).unwrap();
        let extra = 100;
        for i in 0..(MAX_REPLAY_ISSUERS + extra) {
            let offer = AntiEntropyOffer {
                offer_id: format!("offer-{i}"),
                cell_id: "cell-hw".to_string(),
                issuer_id: format!("issuer-{i}"),
                issuer_hlc: Hlc::new(1000 + u64::try_from(i).unwrap_or(0), 0),
                issuer_sequence: 1,
                ledger_head_seq: 10,
                ledger_head_hash: [1u8; HASH_SIZE],
                merkle_root_hash: [2u8; HASH_SIZE],
                range_bounds: (1, 10),
                max_leaves: 1024,
            };
            rp.check_and_record(&offer).unwrap();
        }
        assert!(
            rp.high_water_len() <= MAX_REPLAY_ISSUERS,
            "high_water must be bounded: {} > {}",
            rp.high_water_len(),
            MAX_REPLAY_ISSUERS,
        );
    }

    // ─── Regression: issuer identity binding in accept_deliver ────────────
    #[test]
    fn tck_00381_deliver_issuer_mismatch_rejected_and_request_consumed() {
        // SECURITY REGRESSION: Verifies the blocker fix — a DELIVER whose
        // issuer_id differs from the original REQUEST issuer_id must be
        // rejected with TamperedDelivery. The mismatched request must be
        // consumed (one-shot) to prevent retry abuse.
        let mut enforcer = PullOnlyEnforcer::new(true, default_budget()).unwrap();
        let events = build_events(1, 1, [0u8; HASH_SIZE]);
        let digest = range_digest_for(&events);

        // Register request as "issuer-a".
        let request = mk_request("req-id-bind", "sess-id", 1, 1, 50, digest, 1);
        enforcer
            .register_request(&request, Some("relay-1"))
            .unwrap();

        // Deliver claims to be "issuer-evil" (different from "issuer-a").
        let spoofed = mk_deliver_with_issuer(
            "req-id-bind",
            "sess-id",
            "issuer-evil",
            1,
            1,
            50,
            events.clone(),
            2,
        );
        let err = enforcer
            .accept_deliver(&spoofed, &AcceptAllVerifier)
            .unwrap_err();
        assert_eq!(
            err.defect().unwrap().kind,
            AntiEntropyDefectKind::TamperedDelivery,
            "issuer_id mismatch must produce TamperedDelivery"
        );
        assert!(
            err.defect()
                .unwrap()
                .detail
                .contains("issuer_id does not match"),
            "detail must mention issuer_id mismatch"
        );

        // The outstanding request must have been consumed (one-shot).
        assert_eq!(
            enforcer.outstanding_request_count(),
            0,
            "mismatched issuer must consume the request"
        );

        // A subsequent legitimate deliver for the same request_id must
        // fail with UnsolicitedDelivery (request already consumed).
        let legit = mk_deliver("req-id-bind", "sess-id", 1, 1, 50, events, 3);
        let err2 = enforcer
            .accept_deliver(&legit, &AcceptAllVerifier)
            .unwrap_err();
        assert_eq!(
            err2.defect().unwrap().kind,
            AntiEntropyDefectKind::UnsolicitedDelivery,
            "consumed request must reject subsequent deliver"
        );
    }

    // ─── Regression: one-shot request prevents CPU amplification ──────────
    #[test]
    fn tck_00381_failed_verification_consumes_request_one_shot() {
        // SECURITY REGRESSION: Verifies the major fix — when event
        // attestation verification fails, the outstanding request is
        // consumed (one-shot policy). This prevents an attacker from
        // repeatedly sending deliveries with invalid signatures to
        // trigger expensive verification loops against the same request.
        let mut enforcer = PullOnlyEnforcer::new(true, default_budget()).unwrap();
        let events = build_events(1, 1, [0u8; HASH_SIZE]);
        let digest = range_digest_for(&events);

        let request = mk_request("req-oneshot", "sess-os", 1, 1, 77, digest, 1);
        enforcer
            .register_request(&request, Some("relay-1"))
            .unwrap();
        assert_eq!(enforcer.outstanding_request_count(), 1);

        // First deliver with invalid attestation — must fail and consume.
        let deliver = mk_deliver("req-oneshot", "sess-os", 1, 1, 77, events.clone(), 2);
        let err = enforcer
            .accept_deliver(&deliver, &RejectAllVerifier)
            .unwrap_err();
        assert_eq!(
            err.defect().unwrap().kind,
            AntiEntropyDefectKind::InvalidAttestation,
        );
        assert_eq!(
            enforcer.outstanding_request_count(),
            0,
            "failed verification must consume the request (one-shot)"
        );

        // Second attempt on the same request_id must fail as unsolicited.
        let retry = mk_deliver("req-oneshot", "sess-os", 1, 1, 77, events, 3);
        let err2 = enforcer
            .accept_deliver(&retry, &AcceptAllVerifier)
            .unwrap_err();
        assert_eq!(
            err2.defect().unwrap().kind,
            AntiEntropyDefectKind::UnsolicitedDelivery,
            "retry after one-shot consumption must be unsolicited"
        );
    }
}
