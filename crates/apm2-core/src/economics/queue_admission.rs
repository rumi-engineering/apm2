// AGENT-AUTHORED
//! HTF-bound queue admission and anti-entropy anti-starvation enforcement.
//!
//! Implements RFC-0029 REQ-0004:
//! - Lane reservations and tick-floor invariants for stop/revoke and control
//!   lanes
//! - TP-EIO29-001/002/003 enforcement in queue and anti-entropy admission paths
//! - Structured deny defects for stale, unsigned, missing, or invalid temporal
//!   authority
//! - Pull-only, budget-bound anti-entropy admission
//!
//! # Queue Lane Model
//!
//! Queue lanes are ordered by priority: `StopRevoke > Control > Consume >
//! Replay > ProjectionReplay > Bulk`. Stop/revoke has strict priority with a
//! guaranteed reservation. Control has a guaranteed minimum reservation. All
//! other lanes use weighted deficit round-robin.
//!
//! # Temporal Authority Model
//!
//! All admission decisions require a valid `TimeAuthorityEnvelopeV1`. The
//! envelope must be signed, fresh (within TTL), and bound to the correct
//! `(boundary_id, authority_clock)` context. Missing, stale, unsigned, or
//! invalid envelopes produce fail-closed denials with structured defects.
//!
//! # Anti-Entropy Model
//!
//! Anti-entropy is pull-only and budget-bound. No unsolicited authority
//! acceptance from pushed data-plane payloads is admissible. Oversized proof
//! ranges or proof bytes are denied. TP-EIO29-003 convergence horizon checks
//! gate anti-entropy admission.
//!
//! # Security Domain
//!
//! `DOMAIN_SECURITY` is in scope. All unknown or ambiguous states fail closed.

use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use subtle::ConstantTimeEq;
use thiserror::Error;

use crate::crypto::Hash;
use crate::determinism::canonicalize_json;
use crate::fac::scheduler_state::{
    LaneSnapshot, SCHEDULER_STATE_SCHEMA, SchedulerStateV1, lane_from_str,
};
use crate::pcac::temporal_arbitration::TemporalPredicateId;

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of pending items across all lanes.
///
/// Hard cap to prevent unbounded memory growth under adversarial load.
pub const MAX_TOTAL_QUEUE_ITEMS: usize = 16_384;

/// Maximum backlog per individual lane.
///
/// Per-lane cap prevents a single lane from consuming the entire queue budget.
pub const MAX_LANE_BACKLOG: usize = 4_096;

/// Maximum anti-entropy budget per evaluation window (in abstract cost units).
pub const MAX_ANTI_ENTROPY_BUDGET: u64 = 1_000;

/// Maximum number of convergence receipts per anti-entropy admission check.
pub const MAX_CONVERGENCE_RECEIPTS: usize = 256;

/// Maximum number of required authority sets for anti-entropy convergence.
pub const MAX_REQUIRED_AUTHORITY_SETS: usize = 64;

/// Maximum string length for boundary and clock identifiers.
pub const MAX_BOUNDARY_ID_LENGTH: usize = 256;

/// Maximum number of signatures in a time authority envelope.
pub const MAX_ENVELOPE_SIGNATURES: usize = 16;

/// Maximum TTL value in ticks (approximately 1 day at 1MHz).
pub const MAX_TTL_TICKS: u64 = 86_400_000_000;

/// Minimum reservation fraction for stop/revoke lane (parts per 1000).
///
/// Stop/revoke lane is guaranteed at least this fraction of total queue
/// capacity.
pub const STOP_REVOKE_RESERVATION_PERMILLE: u32 = 200;

/// Minimum reservation fraction for control lane (parts per 1000).
///
/// Control lane is guaranteed at least this fraction of total queue capacity.
pub const CONTROL_RESERVATION_PERMILLE: u32 = 150;

/// Maximum wait ticks for stop/revoke lane items.
///
/// Items waiting longer than this are considered a tick-floor violation.
pub const MAX_STOP_REVOKE_WAIT_TICKS: u64 = 100;

/// Maximum wait ticks for control lane items.
pub const MAX_CONTROL_WAIT_TICKS: u64 = 500;

/// Maximum string length for deny defect reason codes.
pub const MAX_DENY_REASON_LENGTH: usize = 256;

const ZERO_HASH: Hash = [0u8; 32];

// ============================================================================
// Bounded serde helpers (OOM-safe deserialization)
// ============================================================================

/// Deserializes a `String` with a hard length bound to prevent OOM during
/// deserialization from untrusted input.
///
/// Uses a Visitor-based implementation so that `visit_str` checks the length
/// BEFORE allocating (calling `to_owned()`), closing the Check-After-Allocate
/// OOM-DoS vector present in naive `String::deserialize` + post-check patterns.
fn deserialize_bounded_string<'de, D>(
    deserializer: D,
    max_len: usize,
    field_name: &'static str,
) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    struct BoundedStringVisitor {
        max_len: usize,
        field_name: &'static str,
    }

    impl Visitor<'_> for BoundedStringVisitor {
        type Value = String;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(
                formatter,
                "a string of at most {} bytes for field '{}'",
                self.max_len, self.field_name
            )
        }

        fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
            if value.len() > self.max_len {
                Err(E::custom(format!(
                    "string field '{}' exceeds maximum length ({} > {})",
                    self.field_name,
                    value.len(),
                    self.max_len
                )))
            } else {
                // Length validated BEFORE allocation.
                Ok(value.to_owned())
            }
        }

        fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
            if value.len() > self.max_len {
                Err(E::custom(format!(
                    "string field '{}' exceeds maximum length ({} > {})",
                    self.field_name,
                    value.len(),
                    self.max_len
                )))
            } else {
                // Already owned — no additional allocation needed.
                Ok(value)
            }
        }
    }

    deserializer.deserialize_string(BoundedStringVisitor {
        max_len,
        field_name,
    })
}

/// Deserializes a `Vec<T>` with a hard item-count bound to prevent OOM during
/// deserialization from untrusted input.
fn deserialize_bounded_vec<'de, D, T>(
    deserializer: D,
    max_items: usize,
    field_name: &'static str,
) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct BoundedVecVisitor<T> {
        max_items: usize,
        field_name: &'static str,
        _marker: std::marker::PhantomData<T>,
    }

    impl<'de, T> Visitor<'de> for BoundedVecVisitor<T>
    where
        T: Deserialize<'de>,
    {
        type Value = Vec<T>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(
                formatter,
                "a sequence with at most {} items",
                self.max_items
            )
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut vec = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(self.max_items));

            while let Some(item) = seq.next_element()? {
                if vec.len() >= self.max_items {
                    return Err(de::Error::custom(format!(
                        "collection '{}' exceeds maximum size of {}",
                        self.field_name, self.max_items
                    )));
                }
                vec.push(item);
            }

            Ok(vec)
        }
    }

    deserializer.deserialize_seq(BoundedVecVisitor {
        max_items,
        field_name,
        _marker: std::marker::PhantomData,
    })
}

// Field-specific deserializers for `#[serde(deserialize_with = "...")]`.

fn deser_boundary_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_string(deserializer, MAX_BOUNDARY_ID_LENGTH, "boundary_id")
}

fn deser_authority_clock<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_string(deserializer, MAX_BOUNDARY_ID_LENGTH, "authority_clock")
}

fn deser_signature_set<'de, D>(deserializer: D) -> Result<Vec<EnvelopeSignature>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec(deserializer, MAX_ENVELOPE_SIGNATURES, "signature_set")
}

fn deser_convergence_receipts<'de, D>(deserializer: D) -> Result<Vec<ConvergenceReceipt>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec(
        deserializer,
        MAX_CONVERGENCE_RECEIPTS,
        "convergence_receipts",
    )
}

fn deser_required_authority_sets<'de, D>(deserializer: D) -> Result<Vec<Hash>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec(
        deserializer,
        MAX_REQUIRED_AUTHORITY_SETS,
        "required_authority_sets",
    )
}

fn deser_deny_reason<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_string(deserializer, MAX_DENY_REASON_LENGTH, "reason")
}

fn deser_defect_boundary_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_string(deserializer, MAX_BOUNDARY_ID_LENGTH, "boundary_id")
}

// ============================================================================
// Deny reasons (stable strings for replay verification)
// ============================================================================

/// Deny: time authority envelope is missing.
pub const DENY_ENVELOPE_MISSING: &str = "time_authority_envelope_missing";
/// Deny: time authority envelope has zero/null hash.
pub const DENY_ENVELOPE_HASH_ZERO: &str = "time_authority_envelope_hash_zero";
/// Deny: envelope signature set is empty.
pub const DENY_ENVELOPE_UNSIGNED: &str = "time_authority_envelope_unsigned";
/// Deny: envelope signature verification failed.
pub const DENY_ENVELOPE_SIGNATURE_INVALID: &str = "time_authority_envelope_signature_invalid";
/// Deny: envelope `boundary_id` mismatch.
pub const DENY_ENVELOPE_BOUNDARY_MISMATCH: &str = "time_authority_envelope_boundary_mismatch";
/// Deny: envelope `authority_clock` mismatch.
pub const DENY_ENVELOPE_CLOCK_MISMATCH: &str = "time_authority_envelope_clock_mismatch";
/// Deny: envelope does not cover the evaluation window.
pub const DENY_ENVELOPE_WINDOW_UNCOVERED: &str = "time_authority_envelope_window_uncovered";
/// Deny: envelope TTL is stale.
pub const DENY_ENVELOPE_STALE: &str = "time_authority_envelope_stale";
/// Deny: envelope `deny_on_unknown` is false (must be true).
pub const DENY_ENVELOPE_DENY_ON_UNKNOWN_FALSE: &str =
    "time_authority_envelope_deny_on_unknown_false";
/// Deny: freshness horizon reference is unresolved.
pub const DENY_FRESHNESS_HORIZON_UNRESOLVED: &str = "freshness_horizon_unresolved";
/// Deny: current window exceeds freshness horizon.
pub const DENY_FRESHNESS_HORIZON_EXCEEDED: &str = "freshness_horizon_exceeded";
/// Deny: revocation frontier is stale or missing.
pub const DENY_REVOCATION_FRONTIER_STALE: &str = "revocation_frontier_stale";
/// Deny: anti-entropy convergence horizon unresolved.
pub const DENY_CONVERGENCE_HORIZON_UNRESOLVED: &str = "anti_entropy_convergence_horizon_unresolved";
/// Deny: required authority set not converged.
pub const DENY_AUTHORITY_SET_NOT_CONVERGED: &str = "required_authority_set_not_converged";
/// Deny: convergence receipt missing for required set.
pub const DENY_CONVERGENCE_RECEIPT_MISSING: &str = "convergence_receipt_missing";
/// Deny: lane backlog exceeded.
pub const DENY_LANE_BACKLOG_EXCEEDED: &str = "queue_lane_backlog_exceeded";
/// Deny: total queue capacity exceeded.
pub const DENY_TOTAL_QUEUE_EXCEEDED: &str = "queue_total_capacity_exceeded";
/// Deny: anti-entropy budget exhausted.
pub const DENY_ANTI_ENTROPY_BUDGET_EXHAUSTED: &str = "anti_entropy_budget_exhausted";
/// Deny: anti-entropy request is push (not pull).
pub const DENY_ANTI_ENTROPY_PUSH_REJECTED: &str = "anti_entropy_push_not_pull_rejected";
/// Deny: anti-entropy proof range oversized.
pub const DENY_ANTI_ENTROPY_OVERSIZED: &str = "anti_entropy_proof_range_oversized";
/// Deny: tick-floor invariant violated for stop/revoke lane.
pub const DENY_TICK_FLOOR_STOP_REVOKE: &str = "tick_floor_violated_stop_revoke";
/// Deny: tick-floor invariant violated for control lane.
pub const DENY_TICK_FLOOR_CONTROL: &str = "tick_floor_violated_control";
/// Deny: unknown temporal authority state.
pub const DENY_UNKNOWN_TEMPORAL_STATE: &str = "unknown_temporal_authority_state";
/// Deny: envelope `boundary_id` is empty or oversized.
pub const DENY_ENVELOPE_BOUNDARY_ID_INVALID: &str = "time_authority_envelope_boundary_id_invalid";
/// Deny: envelope `authority_clock` is empty or oversized.
pub const DENY_ENVELOPE_CLOCK_INVALID: &str = "time_authority_envelope_clock_invalid";
/// Deny: envelope tick range is invalid (start > end).
pub const DENY_ENVELOPE_TICK_RANGE_INVALID: &str = "time_authority_envelope_tick_range_invalid";
/// Deny: envelope TTL is zero.
pub const DENY_ENVELOPE_TTL_ZERO: &str = "time_authority_envelope_ttl_zero";
/// Deny: envelope TTL exceeds maximum.
pub const DENY_ENVELOPE_TTL_EXCESSIVE: &str = "time_authority_envelope_ttl_excessive";
/// Deny: envelope signatures exceed maximum count.
pub const DENY_ENVELOPE_TOO_MANY_SIGNATURES: &str = "time_authority_envelope_too_many_signatures";

// ============================================================================
// Queue lane types
// ============================================================================

/// Queue lanes ordered by priority (highest first).
///
/// Mapping from RFC-0029 formal model: `L = {stop_revoke, control, consume,
/// replay, projection_replay, bulk}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueLane {
    /// Stop and revocation orders. Strict priority, guaranteed reservation.
    StopRevoke       = 0,
    /// Control traffic. Guaranteed minimum reservation.
    Control          = 1,
    /// Consume/effect execution traffic.
    Consume          = 2,
    /// Replay traffic for convergence.
    Replay           = 3,
    /// Projection replay traffic.
    ProjectionReplay = 4,
    /// Bulk/low-priority traffic.
    Bulk             = 5,
}

impl QueueLane {
    /// Returns `true` if this lane has a guaranteed tick-floor reservation.
    #[must_use]
    pub const fn has_tick_floor_guarantee(self) -> bool {
        matches!(self, Self::StopRevoke | Self::Control)
    }

    /// Returns the maximum wait ticks for this lane, if it has a tick-floor
    /// guarantee.
    #[must_use]
    pub const fn max_wait_ticks(self) -> Option<u64> {
        match self {
            Self::StopRevoke => Some(MAX_STOP_REVOKE_WAIT_TICKS),
            Self::Control => Some(MAX_CONTROL_WAIT_TICKS),
            _ => None,
        }
    }

    /// Returns the reservation permille for this lane (parts per 1000), or 0.
    #[must_use]
    pub const fn reservation_permille(self) -> u32 {
        match self {
            Self::StopRevoke => STOP_REVOKE_RESERVATION_PERMILLE,
            Self::Control => CONTROL_RESERVATION_PERMILLE,
            _ => 0,
        }
    }

    /// Returns all lane variants in priority order.
    #[must_use]
    pub const fn all() -> [Self; 6] {
        [
            Self::StopRevoke,
            Self::Control,
            Self::Consume,
            Self::Replay,
            Self::ProjectionReplay,
            Self::Bulk,
        ]
    }
}

impl std::fmt::Display for QueueLane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StopRevoke => write!(f, "stop_revoke"),
            Self::Control => write!(f, "control"),
            Self::Consume => write!(f, "consume"),
            Self::Replay => write!(f, "replay"),
            Self::ProjectionReplay => write!(f, "projection_replay"),
            Self::Bulk => write!(f, "bulk"),
        }
    }
}

// ============================================================================
// Time authority envelope
// ============================================================================

/// Signed time authority envelope for temporal admission gates.
///
/// Implements `TimeAuthorityEnvelopeV1` from RFC-0029 TP-EIO29-001.
/// All queue admission paths require a valid envelope or deny fail-closed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimeAuthorityEnvelopeV1 {
    /// Boundary identifier (must match evaluation context).
    /// Bounded at deserialization time to `MAX_BOUNDARY_ID_LENGTH` bytes.
    #[serde(deserialize_with = "deser_boundary_id")]
    pub boundary_id: String,
    /// Authority clock identifier (must match evaluation context).
    /// Bounded at deserialization time to `MAX_BOUNDARY_ID_LENGTH` bytes.
    #[serde(deserialize_with = "deser_authority_clock")]
    pub authority_clock: String,
    /// Start tick of the envelope's validity window.
    pub tick_start: u64,
    /// End tick of the envelope's validity window (inclusive).
    pub tick_end: u64,
    /// Time-to-live in ticks from `tick_start`.
    pub ttl_ticks: u64,
    /// When true, unknown state denies admission (must be true for admission).
    pub deny_on_unknown: bool,
    /// Signature set proving envelope authenticity.
    /// Each entry is a 32-byte signer public key concatenated with a 64-byte
    /// signature. Bounded at deserialization time to `MAX_ENVELOPE_SIGNATURES`.
    #[serde(deserialize_with = "deser_signature_set")]
    pub signature_set: Vec<EnvelopeSignature>,
    /// Content hash of the envelope payload (for CAS binding).
    pub content_hash: Hash,
}

/// A single signature in the envelope's signature set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvelopeSignature {
    /// 32-byte Ed25519 public key of the signer.
    pub signer_id: [u8; 32],
    /// 64-byte Ed25519 signature over the canonical envelope payload.
    #[serde(with = "envelope_signature_serde")]
    pub signature: [u8; 64],
}

mod envelope_signature_serde {
    use serde::de::{self, SeqAccess, Visitor};
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(value)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Sig64Visitor;

        impl<'de> Visitor<'de> for Sig64Visitor {
            type Value = [u8; 64];

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a byte sequence of exactly 64 bytes")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut arr = [0u8; 64];
                for (index, slot) in arr.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(index, &self))?;
                }
                if seq.next_element::<u8>()?.is_some() {
                    return Err(de::Error::custom("signature too long: more than 64 bytes"));
                }
                Ok(arr)
            }

            fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if bytes.len() != 64 {
                    return Err(E::custom(format!(
                        "expected 64 bytes for signature, got {}",
                        bytes.len()
                    )));
                }
                let mut arr = [0u8; 64];
                arr.copy_from_slice(bytes);
                Ok(arr)
            }

            fn visit_byte_buf<E>(self, bytes: Vec<u8>) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                self.visit_bytes(&bytes)
            }
        }

        deserializer.deserialize_any(Sig64Visitor)
    }
}

impl TimeAuthorityEnvelopeV1 {
    /// Validates envelope shape and fail-closed invariants.
    ///
    /// This performs structural validation only. Cryptographic signature
    /// verification is performed separately via [`validate_envelope_tp001`].
    ///
    /// # Errors
    ///
    /// Returns a stable deny reason string for any structural violation.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.boundary_id.is_empty() || self.boundary_id.len() > MAX_BOUNDARY_ID_LENGTH {
            return Err(DENY_ENVELOPE_BOUNDARY_ID_INVALID);
        }
        if self.authority_clock.is_empty() || self.authority_clock.len() > MAX_BOUNDARY_ID_LENGTH {
            return Err(DENY_ENVELOPE_CLOCK_INVALID);
        }
        if self.tick_start > self.tick_end {
            return Err(DENY_ENVELOPE_TICK_RANGE_INVALID);
        }
        if self.ttl_ticks == 0 {
            return Err(DENY_ENVELOPE_TTL_ZERO);
        }
        if self.ttl_ticks > MAX_TTL_TICKS {
            return Err(DENY_ENVELOPE_TTL_EXCESSIVE);
        }
        if !self.deny_on_unknown {
            return Err(DENY_ENVELOPE_DENY_ON_UNKNOWN_FALSE);
        }
        if self.signature_set.is_empty() {
            return Err(DENY_ENVELOPE_UNSIGNED);
        }
        if self.signature_set.len() > MAX_ENVELOPE_SIGNATURES {
            return Err(DENY_ENVELOPE_TOO_MANY_SIGNATURES);
        }
        if is_zero_hash(&self.content_hash) {
            return Err(DENY_ENVELOPE_HASH_ZERO);
        }
        // Verify no zero signer IDs or zero signatures
        for sig in &self.signature_set {
            if is_zero_hash(&sig.signer_id) {
                return Err(DENY_ENVELOPE_UNSIGNED);
            }
            if sig.signature.ct_eq(&[0u8; 64]).unwrap_u8() == 1 {
                return Err(DENY_ENVELOPE_UNSIGNED);
            }
        }
        Ok(())
    }
}

// ============================================================================
// Evaluation window
// ============================================================================

/// HTF evaluation window for temporal predicate checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HtfEvaluationWindow {
    /// Boundary identifier for this window.
    /// Bounded at deserialization time to `MAX_BOUNDARY_ID_LENGTH` bytes.
    #[serde(deserialize_with = "deser_boundary_id")]
    pub boundary_id: String,
    /// Authority clock for this window.
    /// Bounded at deserialization time to `MAX_BOUNDARY_ID_LENGTH` bytes.
    #[serde(deserialize_with = "deser_authority_clock")]
    pub authority_clock: String,
    /// Start tick of the evaluation window.
    pub tick_start: u64,
    /// End tick of the evaluation window (inclusive).
    pub tick_end: u64,
}

// ============================================================================
// Freshness horizon (TP-EIO29-002)
// ============================================================================

/// Freshness horizon reference for TP-EIO29-002 evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FreshnessHorizonRef {
    /// Content-addressed hash of the freshness horizon definition.
    pub horizon_hash: Hash,
    /// End tick of the freshness horizon window.
    pub tick_end: u64,
    /// Whether this reference has been resolved against CAS.
    pub resolved: bool,
}

/// Revocation frontier snapshot for TP-EIO29-002.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationFrontierSnapshot {
    /// Content-addressed hash of the frontier state.
    pub frontier_hash: Hash,
    /// Whether the frontier is current (not stale).
    pub current: bool,
}

// ============================================================================
// Anti-entropy convergence (TP-EIO29-003)
// ============================================================================

/// Convergence horizon reference for TP-EIO29-003 evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConvergenceHorizonRef {
    /// Content-addressed hash of the convergence horizon definition.
    pub horizon_hash: Hash,
    /// Whether this reference has been resolved against CAS.
    pub resolved: bool,
}

/// Convergence receipt proving a required authority set has converged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConvergenceReceipt {
    /// Identity of the authority set that converged.
    pub authority_set_hash: Hash,
    /// Content hash of the convergence proof.
    pub proof_hash: Hash,
    /// Whether convergence was achieved within the horizon.
    pub converged: bool,
}

// ============================================================================
// Queue admission request
// ============================================================================

/// A queue admission request binding a lane to temporal authority evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueueAdmissionRequest {
    /// Target lane for this request.
    pub lane: QueueLane,
    /// Time authority envelope (None = missing = deny).
    pub envelope: Option<TimeAuthorityEnvelopeV1>,
    /// Evaluation window for temporal predicate checks.
    pub eval_window: HtfEvaluationWindow,
    /// Freshness horizon reference for TP-EIO29-002.
    pub freshness_horizon: Option<FreshnessHorizonRef>,
    /// Revocation frontier snapshot for TP-EIO29-002.
    pub revocation_frontier: Option<RevocationFrontierSnapshot>,
    /// Anti-entropy convergence horizon for TP-EIO29-003.
    pub convergence_horizon: Option<ConvergenceHorizonRef>,
    /// Convergence receipts for required authority sets.
    /// Bounded at deserialization time to `MAX_CONVERGENCE_RECEIPTS`.
    #[serde(deserialize_with = "deser_convergence_receipts")]
    pub convergence_receipts: Vec<ConvergenceReceipt>,
    /// Required authority set hashes for convergence checks.
    /// Bounded at deserialization time to `MAX_REQUIRED_AUTHORITY_SETS`.
    #[serde(deserialize_with = "deser_required_authority_sets")]
    pub required_authority_sets: Vec<Hash>,
    /// Cost of this request in abstract queue-budget units.
    pub cost: u64,
    /// Current HTF tick at admission time.
    pub current_tick: u64,
}

// ============================================================================
// Anti-entropy admission request
// ============================================================================

/// Direction of an anti-entropy request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AntiEntropyDirection {
    /// Pull-based: requesting data from a peer. Admissible.
    Pull,
    /// Push-based: unsolicited data from a peer. Denied.
    Push,
}

/// Anti-entropy admission request with budget and convergence evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AntiEntropyAdmissionRequest {
    /// Direction of the anti-entropy request.
    pub direction: AntiEntropyDirection,
    /// Time authority envelope (None = missing = deny).
    pub envelope: Option<TimeAuthorityEnvelopeV1>,
    /// Evaluation window for temporal predicate checks.
    pub eval_window: HtfEvaluationWindow,
    /// Budget cost of this anti-entropy request.
    pub cost: u64,
    /// Anti-entropy convergence horizon for TP-EIO29-003.
    pub convergence_horizon: Option<ConvergenceHorizonRef>,
    /// Convergence receipts for required authority sets.
    /// Bounded at deserialization time to `MAX_CONVERGENCE_RECEIPTS`.
    #[serde(deserialize_with = "deser_convergence_receipts")]
    pub convergence_receipts: Vec<ConvergenceReceipt>,
    /// Required authority set hashes for convergence.
    /// Bounded at deserialization time to `MAX_REQUIRED_AUTHORITY_SETS`.
    #[serde(deserialize_with = "deser_required_authority_sets")]
    pub required_authority_sets: Vec<Hash>,
    /// Proof byte count for oversized check.
    pub proof_bytes: u64,
    /// Maximum allowed proof bytes.
    pub max_proof_bytes: u64,
    /// Current HTF tick at admission time.
    pub current_tick: u64,
}

// ============================================================================
// Queue admission verdict and trace
// ============================================================================

/// Admission verdict for queue and anti-entropy requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum QueueAdmissionVerdict {
    /// Request is admissible.
    Allow,
    /// Request is denied fail-closed.
    Deny,
    /// Request triggers freeze (transient disagreement).
    Freeze,
}

/// Structured deny defect for queue admission failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueueDenyDefect {
    /// Stable deny reason code.
    /// Bounded at deserialization time to `MAX_DENY_REASON_LENGTH` bytes.
    #[serde(deserialize_with = "deser_deny_reason")]
    pub reason: String,
    /// The lane that was targeted (or None for anti-entropy).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lane: Option<QueueLane>,
    /// Predicate that failed (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub predicate_id: Option<TemporalPredicateId>,
    /// Current tick at denial time.
    pub denied_at_tick: u64,
    /// Time authority envelope hash (zero if missing).
    pub envelope_hash: Hash,
    /// Evaluation window `boundary_id`.
    /// Bounded at deserialization time to `MAX_BOUNDARY_ID_LENGTH` bytes.
    #[serde(deserialize_with = "deser_defect_boundary_id")]
    pub boundary_id: String,
}

/// Deterministic admission trace for queue decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueueAdmissionTrace {
    /// Lane targeted by the request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lane: Option<QueueLane>,
    /// Verdict.
    pub verdict: QueueAdmissionVerdict,
    /// Deny defect (present when verdict is not Allow).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub defect: Option<QueueDenyDefect>,
    /// TP-EIO29-001 evaluation result.
    pub tp001_passed: bool,
    /// TP-EIO29-002 evaluation result.
    pub tp002_passed: bool,
    /// TP-EIO29-003 evaluation result.
    pub tp003_passed: bool,
    /// Current tick at evaluation time.
    pub evaluated_at_tick: u64,
    /// TCK-00532: Cost estimate (in ticks) used for this admission decision.
    /// Present when the cost model provided the estimate; absent for legacy
    /// admission traces created before cost model integration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_estimate_ticks: Option<u64>,
}

impl QueueAdmissionTrace {
    /// Returns deterministic canonical JSON bytes for replay verification.
    ///
    /// # Errors
    ///
    /// Returns an error when serialization or canonicalization fails.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, QueueAdmissionError> {
        let json = serde_json::to_string(self).map_err(|e| QueueAdmissionError::Serialization {
            message: e.to_string(),
        })?;
        let canonical =
            canonicalize_json(&json).map_err(|e| QueueAdmissionError::Serialization {
                message: e.to_string(),
            })?;
        Ok(canonical.into_bytes())
    }
}

/// Queue admission decision with trace.
///
/// The deny defect (if any) is available via
/// [`QueueAdmissionDecision::defect()`] which delegates to `trace.defect`.
/// There is no separate top-level defect field — the trace is the single source
/// of truth for defect data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueueAdmissionDecision {
    /// Verdict.
    pub verdict: QueueAdmissionVerdict,
    /// Deterministic trace (contains defect when verdict is Deny).
    pub trace: QueueAdmissionTrace,
}

impl QueueAdmissionDecision {
    /// Returns the deny defect, if present.
    ///
    /// This is a convenience accessor that delegates to `self.trace.defect`.
    #[must_use]
    pub const fn defect(&self) -> Option<&QueueDenyDefect> {
        self.trace.defect.as_ref()
    }
}

/// Queue admission errors.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum QueueAdmissionError {
    /// Serialization or canonicalization failed.
    #[error("queue admission serialization failed: {message}")]
    Serialization {
        /// Error message.
        message: String,
    },
}

// ============================================================================
// Queue scheduler state
// ============================================================================

/// Per-lane state for the queue scheduler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaneState {
    /// Current backlog count.
    pub backlog: usize,
    /// Maximum recorded wait in ticks for the oldest item.
    pub max_wait_ticks: u64,
}

/// Queue scheduler state tracking per-lane backlogs and total capacity.
///
/// This is a snapshot of the scheduler state at admission time. It does not
/// contain the actual queue items (which are managed externally).
///
/// # Synchronization Protocol
///
/// This struct is not internally synchronized. Callers must ensure exclusive
/// access during admission evaluation (typically by holding a lock on the
/// queue scheduler).
#[derive(Debug, Clone)]
pub struct QueueSchedulerState {
    /// Per-lane state indexed by lane ordinal.
    lanes: [LaneState; 6],
    /// Total items across all lanes.
    total_items: usize,
}

impl QueueSchedulerState {
    /// Creates a new empty scheduler state.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            lanes: [
                LaneState {
                    backlog: 0,
                    max_wait_ticks: 0,
                },
                LaneState {
                    backlog: 0,
                    max_wait_ticks: 0,
                },
                LaneState {
                    backlog: 0,
                    max_wait_ticks: 0,
                },
                LaneState {
                    backlog: 0,
                    max_wait_ticks: 0,
                },
                LaneState {
                    backlog: 0,
                    max_wait_ticks: 0,
                },
                LaneState {
                    backlog: 0,
                    max_wait_ticks: 0,
                },
            ],
            total_items: 0,
        }
    }

    /// Returns the lane state for the given lane.
    #[must_use]
    pub const fn lane(&self, lane: QueueLane) -> &LaneState {
        &self.lanes[lane as usize]
    }

    /// Returns the total items across all lanes.
    #[must_use]
    pub const fn total_items(&self) -> usize {
        self.total_items
    }

    /// Records admission of an item to a lane.
    ///
    /// High-priority lanes (`StopRevoke`, `Control`) may admit items even
    /// when the total queue is at capacity, as long as the lane's backlog
    /// is below its reserved capacity. This prevents low-priority traffic
    /// floods from starving critical lanes (INV-QA02).
    ///
    /// # Errors
    ///
    /// Returns a deny reason if lane or total capacity would be exceeded.
    pub const fn record_admission(&mut self, lane: QueueLane) -> Result<(), &'static str> {
        let lane_state = &self.lanes[lane as usize];
        if lane_state.backlog >= MAX_LANE_BACKLOG {
            return Err(DENY_LANE_BACKLOG_EXCEEDED);
        }
        if self.total_items >= MAX_TOTAL_QUEUE_ITEMS {
            let reserved = Self::reserved_capacity(lane);
            let lane_backlog = self.lanes[lane as usize].backlog;
            if reserved == 0 || lane_backlog >= reserved {
                return Err(DENY_TOTAL_QUEUE_EXCEEDED);
            }
            // High-priority lane uses reservation — admitted.
        }
        self.lanes[lane as usize].backlog = self.lanes[lane as usize].backlog.saturating_add(1);
        self.total_items = self.total_items.saturating_add(1);
        Ok(())
    }

    /// Records completion/removal of an item from a lane.
    pub const fn record_completion(&mut self, lane: QueueLane) {
        let lane_state = &mut self.lanes[lane as usize];
        lane_state.backlog = lane_state.backlog.saturating_sub(1);
        self.total_items = self.total_items.saturating_sub(1);
    }

    /// Converts the in-memory state to a persistable scheduler snapshot.
    #[must_use]
    pub fn to_scheduler_state_v1(&self, current_tick: u64) -> SchedulerStateV1 {
        let mut lane_snapshots = Vec::with_capacity(QueueLane::all().len());
        for lane in QueueLane::all() {
            let lane_state = self.lane(lane);
            lane_snapshots.push(LaneSnapshot {
                lane: lane.to_string(),
                backlog: lane_state.backlog,
                max_wait_ticks: lane_state.max_wait_ticks,
            });
        }

        SchedulerStateV1 {
            schema: SCHEDULER_STATE_SCHEMA.to_string(),
            lane_snapshots,
            last_evaluation_tick: current_tick,
            persisted_at_secs: 0,
            cost_model: None,
            content_hash: String::new(),
        }
    }

    /// Restores scheduler state from persisted snapshots, conservatively.
    #[must_use]
    pub fn from_persisted(saved: &SchedulerStateV1) -> Self {
        let mut scheduler = Self::new();
        let mut seen = [false; 6];

        for snapshot in &saved.lane_snapshots {
            let Some(lane) = lane_from_str(&snapshot.lane) else {
                continue;
            };

            let idx = lane as usize;
            if seen[idx] {
                continue;
            }
            seen[idx] = true;

            if snapshot.backlog > MAX_LANE_BACKLOG {
                continue;
            }

            scheduler.lanes[idx].backlog = snapshot.backlog;
            scheduler.lanes[idx].max_wait_ticks = snapshot.max_wait_ticks;
            scheduler.total_items = scheduler.total_items.saturating_add(snapshot.backlog);
        }

        scheduler
    }

    /// Updates the maximum wait ticks for a lane.
    pub const fn update_max_wait(&mut self, lane: QueueLane, wait_ticks: u64) {
        let lane_state = &mut self.lanes[lane as usize];
        if wait_ticks > lane_state.max_wait_ticks {
            lane_state.max_wait_ticks = wait_ticks;
        }
    }

    /// Checks tick-floor invariants for stop/revoke and control lanes.
    ///
    /// # Errors
    ///
    /// Returns a deny reason if any guaranteed lane exceeds its maximum wait.
    pub const fn check_tick_floor_invariants(&self) -> Result<(), &'static str> {
        let stop_state = &self.lanes[QueueLane::StopRevoke as usize];
        if stop_state.max_wait_ticks > MAX_STOP_REVOKE_WAIT_TICKS && stop_state.backlog > 0 {
            return Err(DENY_TICK_FLOOR_STOP_REVOKE);
        }
        let control_state = &self.lanes[QueueLane::Control as usize];
        if control_state.max_wait_ticks > MAX_CONTROL_WAIT_TICKS && control_state.backlog > 0 {
            return Err(DENY_TICK_FLOOR_CONTROL);
        }
        Ok(())
    }

    /// Returns the reserved capacity for a lane based on total capacity.
    #[must_use]
    pub const fn reserved_capacity(lane: QueueLane) -> usize {
        let permille = lane.reservation_permille() as usize;
        (MAX_TOTAL_QUEUE_ITEMS * permille) / 1000
    }
}

impl Default for QueueSchedulerState {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Anti-entropy budget tracker
// ============================================================================

/// Budget tracker for anti-entropy admission within an HTF evaluation window.
///
/// # Synchronization Protocol
///
/// This struct is not internally synchronized. Callers must ensure exclusive
/// access during budget evaluation (typically by holding a lock on the
/// anti-entropy scheduler).
#[derive(Debug, Clone)]
pub struct AntiEntropyBudget {
    /// Total budget consumed in the current window.
    consumed: u64,
    /// Maximum budget for the current window.
    max_budget: u64,
}

impl AntiEntropyBudget {
    /// Creates a new budget tracker with the given maximum.
    #[must_use]
    pub const fn new(max_budget: u64) -> Self {
        Self {
            consumed: 0,
            max_budget,
        }
    }

    /// Creates a new budget tracker with the default maximum.
    #[must_use]
    pub const fn default_budget() -> Self {
        Self::new(MAX_ANTI_ENTROPY_BUDGET)
    }

    /// Returns the remaining budget.
    #[must_use]
    pub const fn remaining(&self) -> u64 {
        self.max_budget.saturating_sub(self.consumed)
    }

    /// Attempts to consume budget for a request.
    ///
    /// # Errors
    ///
    /// Returns a deny reason if the budget would be exceeded.
    pub const fn try_consume(&mut self, cost: u64) -> Result<(), &'static str> {
        if cost > self.remaining() {
            return Err(DENY_ANTI_ENTROPY_BUDGET_EXHAUSTED);
        }
        self.consumed = self.consumed.saturating_add(cost);
        Ok(())
    }

    /// Resets budget for a new window.
    pub const fn reset(&mut self) {
        self.consumed = 0;
    }
}

// ============================================================================
// Signature verifier trait
// ============================================================================

/// Deny: signature verification not configured (fail-closed).
pub const DENY_SIGNATURE_VERIFICATION_NOT_CONFIGURED: &str =
    "signature_verification_not_configured";

/// Trait for cryptographic signature verification against envelope signatures.
///
/// Callers must inject a concrete implementation. The default
/// [`NoOpVerifier`] always returns `Err` (fail-closed) so that
/// `tp001_passed` is never `true` without real cryptographic verification.
pub trait SignatureVerifier: Send + Sync {
    /// Verifies that `signature` over `message` was produced by
    /// `signer_id`.
    ///
    /// # Errors
    ///
    /// Returns a static reason string on verification failure.
    fn verify(
        &self,
        signer_id: &Hash,
        message: &[u8],
        signature: &[u8; 64],
    ) -> Result<(), &'static str>;
}

/// Default fail-closed verifier. Always returns
/// `Err("signature_verification_not_configured")`.
///
/// This ensures `tp001_passed` is never `true` without a real verifier.
pub struct NoOpVerifier;

impl SignatureVerifier for NoOpVerifier {
    fn verify(
        &self,
        _signer_id: &Hash,
        _message: &[u8],
        _signature: &[u8; 64],
    ) -> Result<(), &'static str> {
        Err(DENY_SIGNATURE_VERIFICATION_NOT_CONFIGURED)
    }
}

// ============================================================================
// TP-EIO29-001 evaluation
// ============================================================================

/// Validates a time authority envelope against TP-EIO29-001.
///
/// Checks:
/// 1. Envelope is present and structurally valid
/// 2. Boundary ID and authority clock match the evaluation window
/// 3. Envelope tick range covers the evaluation window
/// 4. TTL is fresh relative to the evaluation window
/// 5. `deny_on_unknown` is true
/// 6. All signatures verify cryptographically via `verifier`
///
/// If `verifier` is `None`, signature verification is skipped and the
/// function denies fail-closed (returns
/// `DENY_SIGNATURE_VERIFICATION_NOT_CONFIGURED`). This ensures
/// `tp001_passed` is never `true` without real crypto verification.
///
/// # Errors
///
/// Returns a stable deny reason for any violation.
pub fn validate_envelope_tp001(
    envelope: Option<&TimeAuthorityEnvelopeV1>,
    eval_window: &HtfEvaluationWindow,
    verifier: Option<&dyn SignatureVerifier>,
) -> Result<(), &'static str> {
    let envelope = envelope.ok_or(DENY_ENVELOPE_MISSING)?;

    // Structural validation
    envelope.validate()?;

    // Boundary and clock context match
    if envelope.boundary_id != eval_window.boundary_id {
        return Err(DENY_ENVELOPE_BOUNDARY_MISMATCH);
    }
    if envelope.authority_clock != eval_window.authority_clock {
        return Err(DENY_ENVELOPE_CLOCK_MISMATCH);
    }

    // Window coverage: envelope must cover the evaluation window
    if envelope.tick_start > eval_window.tick_start || envelope.tick_end < eval_window.tick_end {
        return Err(DENY_ENVELOPE_WINDOW_UNCOVERED);
    }

    // TTL freshness: tick_start + ttl_ticks must reach at least
    // eval_window.tick_end
    let ttl_end = envelope.tick_start.saturating_add(envelope.ttl_ticks);
    if ttl_end < eval_window.tick_end {
        return Err(DENY_ENVELOPE_STALE);
    }

    // Cryptographic signature verification (fail-closed when no verifier).
    let sig_verifier = verifier.unwrap_or(&NoOpVerifier);
    let canonical = envelope_signature_canonical_bytes(envelope);
    for sig in &envelope.signature_set {
        sig_verifier.verify(&sig.signer_id, &canonical, &sig.signature)?;
    }

    Ok(())
}

/// Returns deterministic canonical bytes for envelope signature verification.
///
/// Variable-length fields (`boundary_id`, `authority_clock`) are
/// length-prefixed with a 4-byte LE u32 to ensure injectivity — otherwise
/// concatenation of different pairs can produce identical byte sequences (e.g.,
/// `("ab","cd")` vs `("abc","d")`).
pub(crate) fn envelope_signature_canonical_bytes(envelope: &TimeAuthorityEnvelopeV1) -> Vec<u8> {
    // Build a deterministic, injective byte representation:
    // len(boundary_id) || boundary_id || len(authority_clock) || authority_clock
    // || tick_start || tick_end || ttl_ticks || deny_on_unknown || content_hash
    let mut buf = Vec::with_capacity(256);

    // boundary_id (length-prefixed)
    #[allow(clippy::cast_possible_truncation)]
    let bid_len = envelope.boundary_id.len().min(u32::MAX as usize) as u32;
    buf.extend_from_slice(&bid_len.to_le_bytes());
    buf.extend_from_slice(envelope.boundary_id.as_bytes());

    // authority_clock (length-prefixed)
    #[allow(clippy::cast_possible_truncation)]
    let clk_len = envelope.authority_clock.len().min(u32::MAX as usize) as u32;
    buf.extend_from_slice(&clk_len.to_le_bytes());
    buf.extend_from_slice(envelope.authority_clock.as_bytes());

    buf.extend_from_slice(&envelope.tick_start.to_le_bytes());
    buf.extend_from_slice(&envelope.tick_end.to_le_bytes());
    buf.extend_from_slice(&envelope.ttl_ticks.to_le_bytes());
    buf.push(u8::from(envelope.deny_on_unknown));
    buf.extend_from_slice(&envelope.content_hash);
    buf
}

// ============================================================================
// TP-EIO29-002 evaluation
// ============================================================================

/// Validates freshness horizon against TP-EIO29-002.
///
/// Checks:
/// 1. Freshness horizon reference resolves
/// 2. Current window `tick_end` does not exceed freshness horizon `tick_end`
/// 3. Revocation frontier is current
///
/// # Errors
///
/// Returns a stable deny reason for any violation.
pub fn validate_freshness_horizon_tp002(
    freshness_horizon: Option<&FreshnessHorizonRef>,
    revocation_frontier: Option<&RevocationFrontierSnapshot>,
    eval_window: &HtfEvaluationWindow,
) -> Result<(), &'static str> {
    let horizon = freshness_horizon.ok_or(DENY_FRESHNESS_HORIZON_UNRESOLVED)?;

    if !horizon.resolved {
        return Err(DENY_FRESHNESS_HORIZON_UNRESOLVED);
    }
    if is_zero_hash(&horizon.horizon_hash) {
        return Err(DENY_FRESHNESS_HORIZON_UNRESOLVED);
    }

    // Current window must not exceed freshness horizon
    if eval_window.tick_end > horizon.tick_end {
        return Err(DENY_FRESHNESS_HORIZON_EXCEEDED);
    }

    // Revocation frontier must be current
    let frontier = revocation_frontier.ok_or(DENY_REVOCATION_FRONTIER_STALE)?;
    if !frontier.current {
        return Err(DENY_REVOCATION_FRONTIER_STALE);
    }
    if is_zero_hash(&frontier.frontier_hash) {
        return Err(DENY_REVOCATION_FRONTIER_STALE);
    }

    Ok(())
}

// ============================================================================
// TP-EIO29-003 evaluation
// ============================================================================

/// Validates anti-entropy convergence horizon against TP-EIO29-003.
///
/// Checks:
/// 1. Convergence horizon reference resolves
/// 2. All required authority sets have matching convergence receipts
/// 3. All receipts indicate convergence within the horizon
///
/// # Errors
///
/// Returns a stable deny reason for any violation.
pub fn validate_convergence_horizon_tp003(
    convergence_horizon: Option<&ConvergenceHorizonRef>,
    convergence_receipts: &[ConvergenceReceipt],
    required_authority_sets: &[Hash],
) -> Result<(), &'static str> {
    let horizon = convergence_horizon.ok_or(DENY_CONVERGENCE_HORIZON_UNRESOLVED)?;

    if !horizon.resolved {
        return Err(DENY_CONVERGENCE_HORIZON_UNRESOLVED);
    }
    if is_zero_hash(&horizon.horizon_hash) {
        return Err(DENY_CONVERGENCE_HORIZON_UNRESOLVED);
    }

    // Bound checks to prevent DoS
    if required_authority_sets.len() > MAX_REQUIRED_AUTHORITY_SETS {
        return Err(DENY_AUTHORITY_SET_NOT_CONVERGED);
    }
    if convergence_receipts.len() > MAX_CONVERGENCE_RECEIPTS {
        return Err(DENY_CONVERGENCE_RECEIPT_MISSING);
    }

    // O(N*M) where N=required_authority_sets (max 64) and M=convergence_receipts
    // (max 256). Upper bound: 16,384 constant-time comparisons — negligible at
    // these cardinalities.
    for required_set in required_authority_sets {
        if is_zero_hash(required_set) {
            return Err(DENY_AUTHORITY_SET_NOT_CONVERGED);
        }

        let receipt = convergence_receipts
            .iter()
            .find(|r| hashes_equal(&r.authority_set_hash, required_set));

        match receipt {
            None => return Err(DENY_CONVERGENCE_RECEIPT_MISSING),
            Some(r) if !r.converged => return Err(DENY_AUTHORITY_SET_NOT_CONVERGED),
            Some(r) if is_zero_hash(&r.proof_hash) => {
                return Err(DENY_CONVERGENCE_RECEIPT_MISSING);
            },
            Some(_) => {}, // converged with valid proof
        }
    }

    Ok(())
}

// ============================================================================
// Queue admission evaluator
// ============================================================================

/// Evaluates queue admission for a request against temporal authority
/// predicates and scheduler state.
///
/// All unknown, missing, stale, or invalid temporal authority states
/// deny fail-closed.
///
/// `verifier` is used for cryptographic signature verification in
/// TP-EIO29-001. Pass `None` to use the fail-closed [`NoOpVerifier`].
#[must_use]
pub fn evaluate_queue_admission(
    request: &QueueAdmissionRequest,
    scheduler: &QueueSchedulerState,
    verifier: Option<&dyn SignatureVerifier>,
) -> QueueAdmissionDecision {
    let current_tick = request.current_tick;
    let lane = request.lane;
    let envelope_hash = request
        .envelope
        .as_ref()
        .map_or(ZERO_HASH, |e| e.content_hash);
    let boundary_id = &request.eval_window.boundary_id;

    // Evaluate all three temporal predicates
    let (tp001_passed, tp002_passed, tp003_passed) = match evaluate_temporal_predicates(
        request,
        lane,
        current_tick,
        envelope_hash,
        boundary_id,
        verifier,
    ) {
        Ok(tp) => tp,
        Err(decision) => return decision,
    };

    // Check structural constraints (tick-floors, capacity)
    if let Err(decision) = check_structural_constraints(
        scheduler,
        lane,
        current_tick,
        envelope_hash,
        boundary_id,
        tp001_passed,
        tp002_passed,
        tp003_passed,
        Some(request.cost),
    ) {
        return decision;
    }

    // All checks passed
    let trace = QueueAdmissionTrace {
        lane: Some(lane),
        verdict: QueueAdmissionVerdict::Allow,
        defect: None,
        tp001_passed,
        tp002_passed,
        tp003_passed,
        evaluated_at_tick: current_tick,
        cost_estimate_ticks: Some(request.cost),
    };

    QueueAdmissionDecision {
        verdict: QueueAdmissionVerdict::Allow,
        trace,
    }
}

/// Evaluates TP-EIO29-001/002/003 for queue admission. Returns
/// `(tp001, tp002, tp003)` on success or a deny decision on failure.
// JUSTIFICATION: `QueueAdmissionDecision` in the `Err` variant is returned by value
// (not boxed) to avoid heap allocation on the deny hot-path.
#[allow(clippy::result_large_err)]
fn evaluate_temporal_predicates(
    request: &QueueAdmissionRequest,
    lane: QueueLane,
    current_tick: u64,
    envelope_hash: Hash,
    boundary_id: &str,
    verifier: Option<&dyn SignatureVerifier>,
) -> Result<(bool, bool, bool), QueueAdmissionDecision> {
    // TP-EIO29-001: Time authority envelope validity
    let tp001_result =
        validate_envelope_tp001(request.envelope.as_ref(), &request.eval_window, verifier);
    let tp001_passed = tp001_result.is_ok();
    // For stop_revoke lane, allow local monotonic emergency time if full
    // envelope fails (fail-open to authority reduction only).
    let tp001_stop_revoke_emergency = !tp001_passed && lane == QueueLane::StopRevoke;

    let cost_estimate = Some(request.cost);

    if !tp001_passed && !tp001_stop_revoke_emergency {
        let reason = tp001_result.unwrap_err();
        return Err(deny_queue(&DenyContext {
            lane: Some(lane),
            reason,
            predicate_id: Some(TemporalPredicateId::TpEio29001),
            current_tick,
            envelope_hash,
            boundary_id,
            tp001_passed,
            tp002_passed: false,
            tp003_passed: false,
            cost_estimate_ticks: cost_estimate,
        }));
    }

    // TP-EIO29-002: Freshness horizon
    let tp002_result = validate_freshness_horizon_tp002(
        request.freshness_horizon.as_ref(),
        request.revocation_frontier.as_ref(),
        &request.eval_window,
    );
    let tp002_passed = tp002_result.is_ok();
    if !tp002_passed {
        let reason = tp002_result.unwrap_err();
        return Err(deny_queue(&DenyContext {
            lane: Some(lane),
            reason,
            predicate_id: Some(TemporalPredicateId::TpEio29002),
            current_tick,
            envelope_hash,
            boundary_id,
            tp001_passed,
            tp002_passed,
            tp003_passed: false,
            cost_estimate_ticks: cost_estimate,
        }));
    }

    // TP-EIO29-003: Anti-entropy convergence horizon
    let tp003_result = validate_convergence_horizon_tp003(
        request.convergence_horizon.as_ref(),
        &request.convergence_receipts,
        &request.required_authority_sets,
    );
    let tp003_passed = tp003_result.is_ok();
    if !tp003_passed {
        let reason = tp003_result.unwrap_err();
        return Err(deny_queue(&DenyContext {
            lane: Some(lane),
            reason,
            predicate_id: Some(TemporalPredicateId::TpEio29003),
            current_tick,
            envelope_hash,
            boundary_id,
            tp001_passed,
            tp002_passed,
            tp003_passed,
            cost_estimate_ticks: cost_estimate,
        }));
    }

    Ok((tp001_passed, tp002_passed, tp003_passed))
}

/// Checks tick-floor invariants and capacity constraints. Returns `Ok(())`
/// on success or a deny decision on failure.
// JUSTIFICATION: 8 parameters are individually meaningful context for deny-path
// construction; a wrapper struct would add ceremony for a single internal call site.
// `result_large_err`: returned by value to avoid heap allocation on deny hot-path.
#[allow(clippy::too_many_arguments, clippy::result_large_err)]
fn check_structural_constraints(
    scheduler: &QueueSchedulerState,
    lane: QueueLane,
    current_tick: u64,
    envelope_hash: Hash,
    boundary_id: &str,
    tp001_passed: bool,
    tp002_passed: bool,
    tp003_passed: bool,
    cost_estimate_ticks: Option<u64>,
) -> Result<(), QueueAdmissionDecision> {
    let mk_ctx = |reason: &'static str| DenyContext {
        lane: Some(lane),
        reason,
        predicate_id: None,
        current_tick,
        envelope_hash,
        boundary_id,
        tp001_passed,
        tp002_passed,
        tp003_passed,
        cost_estimate_ticks,
    };

    // Tick-floor invariants for guaranteed lanes
    if let Err(reason) = scheduler.check_tick_floor_invariants() {
        return Err(deny_queue(&mk_ctx(reason)));
    }

    // Lane backlog
    let lane_state = scheduler.lane(lane);
    if lane_state.backlog >= MAX_LANE_BACKLOG {
        return Err(deny_queue(&mk_ctx(DENY_LANE_BACKLOG_EXCEEDED)));
    }

    // Total queue capacity with lane-reservation bypass.
    //
    // High-priority lanes (StopRevoke, Control) have reserved capacity that
    // allows them to admit items even when the common pool is full. This
    // prevents low-priority traffic from starving critical lanes (INV-QA02).
    if scheduler.total_items() >= MAX_TOTAL_QUEUE_ITEMS {
        let reserved = QueueSchedulerState::reserved_capacity(lane);
        let lane_backlog = scheduler.lane(lane).backlog;
        // Only allow if lane has a reservation AND is below its reserved
        // capacity.
        if reserved == 0 || lane_backlog >= reserved {
            return Err(deny_queue(&mk_ctx(DENY_TOTAL_QUEUE_EXCEEDED)));
        }
        // High-priority lane uses reservation — admitted.
    }

    Ok(())
}

/// Evaluates anti-entropy admission against temporal authority predicates
/// and budget constraints.
///
/// Anti-entropy is pull-only and budget-bound. Push requests are denied.
/// Oversized proof ranges are denied. TP-EIO29-001 and TP-EIO29-003 are
/// enforced.
///
/// `verifier` is used for cryptographic signature verification in
/// TP-EIO29-001. Pass `None` to use the fail-closed [`NoOpVerifier`].
#[must_use]
pub fn evaluate_anti_entropy_admission(
    request: &AntiEntropyAdmissionRequest,
    budget: &AntiEntropyBudget,
    verifier: Option<&dyn SignatureVerifier>,
) -> QueueAdmissionDecision {
    let current_tick = request.current_tick;
    let envelope_hash = request
        .envelope
        .as_ref()
        .map_or(ZERO_HASH, |e| e.content_hash);
    let boundary_id = &request.eval_window.boundary_id;

    let cost_estimate = Some(request.cost);
    let mk_deny = |reason: &str, pred: Option<TemporalPredicateId>, tp001: bool, tp003: bool| {
        deny_queue(&DenyContext {
            lane: None,
            reason,
            predicate_id: pred,
            current_tick,
            envelope_hash,
            boundary_id,
            tp001_passed: tp001,
            tp002_passed: false,
            tp003_passed: tp003,
            cost_estimate_ticks: cost_estimate,
        })
    };

    // Pull-only enforcement
    if request.direction == AntiEntropyDirection::Push {
        return mk_deny(DENY_ANTI_ENTROPY_PUSH_REJECTED, None, false, false);
    }

    // Oversized proof check
    if request.proof_bytes > request.max_proof_bytes {
        return mk_deny(DENY_ANTI_ENTROPY_OVERSIZED, None, false, false);
    }

    // TP-EIO29-001
    let tp001_result =
        validate_envelope_tp001(request.envelope.as_ref(), &request.eval_window, verifier);
    let tp001_passed = tp001_result.is_ok();
    if !tp001_passed {
        let reason = tp001_result.unwrap_err();
        return mk_deny(reason, Some(TemporalPredicateId::TpEio29001), false, false);
    }

    // TP-EIO29-003
    let tp003_result = validate_convergence_horizon_tp003(
        request.convergence_horizon.as_ref(),
        &request.convergence_receipts,
        &request.required_authority_sets,
    );
    let tp003_passed = tp003_result.is_ok();
    if !tp003_passed {
        let reason = tp003_result.unwrap_err();
        return mk_deny(
            reason,
            Some(TemporalPredicateId::TpEio29003),
            tp001_passed,
            false,
        );
    }

    // Budget check
    if request.cost > budget.remaining() {
        return mk_deny(
            DENY_ANTI_ENTROPY_BUDGET_EXHAUSTED,
            None,
            tp001_passed,
            tp003_passed,
        );
    }

    // All checks passed
    let trace = QueueAdmissionTrace {
        lane: None,
        verdict: QueueAdmissionVerdict::Allow,
        defect: None,
        tp001_passed,
        tp002_passed: false, // TP-002 not evaluated for anti-entropy
        tp003_passed,
        evaluated_at_tick: current_tick,
        cost_estimate_ticks: Some(request.cost),
    };

    QueueAdmissionDecision {
        verdict: QueueAdmissionVerdict::Allow,
        trace,
    }
}

// ============================================================================
// Internal helpers
// ============================================================================

/// Internal context for constructing deny decisions, avoiding excessive
/// argument lists.
struct DenyContext<'a> {
    lane: Option<QueueLane>,
    reason: &'a str,
    predicate_id: Option<TemporalPredicateId>,
    current_tick: u64,
    envelope_hash: Hash,
    boundary_id: &'a str,
    tp001_passed: bool,
    tp002_passed: bool,
    tp003_passed: bool,
    /// Cost estimate (in ticks) from the admission request for audit trail.
    cost_estimate_ticks: Option<u64>,
}

fn deny_queue(ctx: &DenyContext<'_>) -> QueueAdmissionDecision {
    let defect = QueueDenyDefect {
        reason: ctx.reason.to_string(),
        lane: ctx.lane,
        predicate_id: ctx.predicate_id,
        denied_at_tick: ctx.current_tick,
        envelope_hash: ctx.envelope_hash,
        boundary_id: ctx.boundary_id.to_string(),
    };

    let trace = QueueAdmissionTrace {
        lane: ctx.lane,
        verdict: QueueAdmissionVerdict::Deny,
        defect: Some(defect),
        tp001_passed: ctx.tp001_passed,
        tp002_passed: ctx.tp002_passed,
        tp003_passed: ctx.tp003_passed,
        evaluated_at_tick: ctx.current_tick,
        cost_estimate_ticks: ctx.cost_estimate_ticks,
    };

    QueueAdmissionDecision {
        verdict: QueueAdmissionVerdict::Deny,
        trace,
    }
}

fn is_zero_hash(hash: &[u8; 32]) -> bool {
    hash.ct_eq(&ZERO_HASH).unwrap_u8() == 1
}

fn hashes_equal(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.ct_eq(right).unwrap_u8() == 1
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Test helpers
    // ========================================================================

    fn test_hash(byte: u8) -> Hash {
        [byte; 32]
    }

    /// Verifier that accepts all signatures (for tests that do not exercise
    /// cryptographic verification).
    struct AcceptAllVerifier;

    impl SignatureVerifier for AcceptAllVerifier {
        fn verify(
            &self,
            _signer_id: &Hash,
            _message: &[u8],
            _signature: &[u8; 64],
        ) -> Result<(), &'static str> {
            Ok(())
        }
    }

    /// Convenience: all evaluator tests use this verifier to keep existing
    /// semantics (structural checks pass without real crypto).
    #[allow(clippy::unnecessary_wraps)]
    fn test_verifier() -> Option<&'static dyn SignatureVerifier> {
        Some(&AcceptAllVerifier as &dyn SignatureVerifier)
    }

    fn valid_envelope() -> TimeAuthorityEnvelopeV1 {
        TimeAuthorityEnvelopeV1 {
            boundary_id: "boundary-main".to_string(),
            authority_clock: "clock-main".to_string(),
            tick_start: 1000,
            tick_end: 2000,
            ttl_ticks: 1500,
            deny_on_unknown: true,
            signature_set: vec![EnvelopeSignature {
                signer_id: test_hash(0xA1),
                signature: [0xBB; 64],
            }],
            content_hash: test_hash(0xCC),
        }
    }

    fn valid_eval_window() -> HtfEvaluationWindow {
        HtfEvaluationWindow {
            boundary_id: "boundary-main".to_string(),
            authority_clock: "clock-main".to_string(),
            tick_start: 1000,
            tick_end: 1500,
        }
    }

    fn valid_freshness_horizon() -> FreshnessHorizonRef {
        FreshnessHorizonRef {
            horizon_hash: test_hash(0xDD),
            tick_end: 2000,
            resolved: true,
        }
    }

    fn valid_revocation_frontier() -> RevocationFrontierSnapshot {
        RevocationFrontierSnapshot {
            frontier_hash: test_hash(0xEE),
            current: true,
        }
    }

    fn valid_convergence_horizon() -> ConvergenceHorizonRef {
        ConvergenceHorizonRef {
            horizon_hash: test_hash(0xFF),
            resolved: true,
        }
    }

    fn valid_convergence_receipt(authority_set: Hash) -> ConvergenceReceipt {
        ConvergenceReceipt {
            authority_set_hash: authority_set,
            proof_hash: test_hash(0xAB),
            converged: true,
        }
    }

    fn valid_queue_request(lane: QueueLane) -> QueueAdmissionRequest {
        let required_set = test_hash(0x01);
        QueueAdmissionRequest {
            lane,
            envelope: Some(valid_envelope()),
            eval_window: valid_eval_window(),
            freshness_horizon: Some(valid_freshness_horizon()),
            revocation_frontier: Some(valid_revocation_frontier()),
            convergence_horizon: Some(valid_convergence_horizon()),
            convergence_receipts: vec![valid_convergence_receipt(required_set)],
            required_authority_sets: vec![required_set],
            cost: 1,
            current_tick: 1200,
        }
    }

    fn valid_anti_entropy_request() -> AntiEntropyAdmissionRequest {
        let required_set = test_hash(0x01);
        AntiEntropyAdmissionRequest {
            direction: AntiEntropyDirection::Pull,
            envelope: Some(valid_envelope()),
            eval_window: valid_eval_window(),
            cost: 10,
            convergence_horizon: Some(valid_convergence_horizon()),
            convergence_receipts: vec![valid_convergence_receipt(required_set)],
            required_authority_sets: vec![required_set],
            proof_bytes: 100,
            max_proof_bytes: 1000,
            current_tick: 1200,
        }
    }

    // ========================================================================
    // Envelope validation (TP-EIO29-001)
    // ========================================================================

    #[test]
    fn tp001_valid_envelope_passes_with_verifier() {
        let result = validate_envelope_tp001(
            Some(&valid_envelope()),
            &valid_eval_window(),
            test_verifier(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn tp001_missing_envelope_denies() {
        let result = validate_envelope_tp001(None, &valid_eval_window(), test_verifier());
        assert_eq!(result.unwrap_err(), DENY_ENVELOPE_MISSING);
    }

    #[test]
    fn tp001_unsigned_envelope_denies() {
        let mut envelope = valid_envelope();
        envelope.signature_set.clear();
        let result =
            validate_envelope_tp001(Some(&envelope), &valid_eval_window(), test_verifier());
        assert_eq!(result.unwrap_err(), DENY_ENVELOPE_UNSIGNED);
    }

    #[test]
    fn tp001_zero_signer_denies() {
        let mut envelope = valid_envelope();
        envelope.signature_set[0].signer_id = [0u8; 32];
        let result =
            validate_envelope_tp001(Some(&envelope), &valid_eval_window(), test_verifier());
        assert_eq!(result.unwrap_err(), DENY_ENVELOPE_UNSIGNED);
    }

    #[test]
    fn tp001_zero_signature_denies() {
        let mut envelope = valid_envelope();
        envelope.signature_set[0].signature = [0u8; 64];
        let result =
            validate_envelope_tp001(Some(&envelope), &valid_eval_window(), test_verifier());
        assert_eq!(result.unwrap_err(), DENY_ENVELOPE_UNSIGNED);
    }

    #[test]
    fn tp001_boundary_mismatch_denies() {
        let envelope = valid_envelope();
        let mut window = valid_eval_window();
        window.boundary_id = "other-boundary".to_string();
        let result = validate_envelope_tp001(Some(&envelope), &window, test_verifier());
        assert_eq!(result.unwrap_err(), DENY_ENVELOPE_BOUNDARY_MISMATCH);
    }

    #[test]
    fn tp001_clock_mismatch_denies() {
        let envelope = valid_envelope();
        let mut window = valid_eval_window();
        window.authority_clock = "other-clock".to_string();
        let result = validate_envelope_tp001(Some(&envelope), &window, test_verifier());
        assert_eq!(result.unwrap_err(), DENY_ENVELOPE_CLOCK_MISMATCH);
    }

    #[test]
    fn tp001_window_not_covered_denies() {
        let mut envelope = valid_envelope();
        envelope.tick_end = 1499; // Does not cover eval_window.tick_end=1500
        let result =
            validate_envelope_tp001(Some(&envelope), &valid_eval_window(), test_verifier());
        assert_eq!(result.unwrap_err(), DENY_ENVELOPE_WINDOW_UNCOVERED);
    }

    #[test]
    fn tp001_stale_envelope_denies() {
        let mut envelope = valid_envelope();
        envelope.ttl_ticks = 400; // tick_start(1000) + 400 = 1400 < eval_window.tick_end(1500)
        let result =
            validate_envelope_tp001(Some(&envelope), &valid_eval_window(), test_verifier());
        assert_eq!(result.unwrap_err(), DENY_ENVELOPE_STALE);
    }

    #[test]
    fn tp001_deny_on_unknown_false_denies() {
        let mut envelope = valid_envelope();
        envelope.deny_on_unknown = false;
        let result =
            validate_envelope_tp001(Some(&envelope), &valid_eval_window(), test_verifier());
        assert_eq!(result.unwrap_err(), DENY_ENVELOPE_DENY_ON_UNKNOWN_FALSE);
    }

    #[test]
    fn tp001_zero_content_hash_denies() {
        let mut envelope = valid_envelope();
        envelope.content_hash = [0u8; 32];
        let result =
            validate_envelope_tp001(Some(&envelope), &valid_eval_window(), test_verifier());
        assert_eq!(result.unwrap_err(), DENY_ENVELOPE_HASH_ZERO);
    }

    #[test]
    fn tp001_empty_boundary_id_denies() {
        let mut envelope = valid_envelope();
        envelope.boundary_id = String::new();
        let result =
            validate_envelope_tp001(Some(&envelope), &valid_eval_window(), test_verifier());
        assert_eq!(result.unwrap_err(), DENY_ENVELOPE_BOUNDARY_ID_INVALID);
    }

    #[test]
    fn tp001_oversized_boundary_id_denies() {
        let mut envelope = valid_envelope();
        envelope.boundary_id = "x".repeat(MAX_BOUNDARY_ID_LENGTH + 1);
        let result =
            validate_envelope_tp001(Some(&envelope), &valid_eval_window(), test_verifier());
        assert_eq!(result.unwrap_err(), DENY_ENVELOPE_BOUNDARY_ID_INVALID);
    }

    #[test]
    fn tp001_zero_ttl_denies() {
        let mut envelope = valid_envelope();
        envelope.ttl_ticks = 0;
        let result =
            validate_envelope_tp001(Some(&envelope), &valid_eval_window(), test_verifier());
        assert_eq!(result.unwrap_err(), DENY_ENVELOPE_TTL_ZERO);
    }

    #[test]
    fn tp001_excessive_ttl_denies() {
        let mut envelope = valid_envelope();
        envelope.ttl_ticks = MAX_TTL_TICKS + 1;
        let result =
            validate_envelope_tp001(Some(&envelope), &valid_eval_window(), test_verifier());
        assert_eq!(result.unwrap_err(), DENY_ENVELOPE_TTL_EXCESSIVE);
    }

    #[test]
    fn tp001_tick_range_inverted_denies() {
        let mut envelope = valid_envelope();
        envelope.tick_start = 2001;
        envelope.tick_end = 2000;
        let result =
            validate_envelope_tp001(Some(&envelope), &valid_eval_window(), test_verifier());
        assert_eq!(result.unwrap_err(), DENY_ENVELOPE_TICK_RANGE_INVALID);
    }

    #[test]
    fn tp001_too_many_signatures_denies() {
        let mut envelope = valid_envelope();
        envelope.signature_set = (0..=MAX_ENVELOPE_SIGNATURES)
            .map(|i| EnvelopeSignature {
                #[allow(clippy::cast_possible_truncation)]
                signer_id: test_hash(i as u8),
                signature: [0xBB; 64],
            })
            .collect();
        let result =
            validate_envelope_tp001(Some(&envelope), &valid_eval_window(), test_verifier());
        assert_eq!(result.unwrap_err(), DENY_ENVELOPE_TOO_MANY_SIGNATURES);
    }

    // ========================================================================
    // Signature verifier trait
    // ========================================================================

    #[test]
    fn tp001_no_verifier_denies_fail_closed() {
        // When no verifier is provided, the NoOpVerifier denies.
        let result = validate_envelope_tp001(Some(&valid_envelope()), &valid_eval_window(), None);
        assert_eq!(
            result.unwrap_err(),
            DENY_SIGNATURE_VERIFICATION_NOT_CONFIGURED
        );
    }

    #[test]
    fn tp001_noop_verifier_denies_fail_closed() {
        let noop = NoOpVerifier;
        let result =
            validate_envelope_tp001(Some(&valid_envelope()), &valid_eval_window(), Some(&noop));
        assert_eq!(
            result.unwrap_err(),
            DENY_SIGNATURE_VERIFICATION_NOT_CONFIGURED
        );
    }

    #[test]
    fn tp001_accept_all_verifier_passes() {
        let result = validate_envelope_tp001(
            Some(&valid_envelope()),
            &valid_eval_window(),
            test_verifier(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn tp001_random_signature_bytes_denied_without_real_verifier() {
        // Random non-zero signature bytes pass structural checks but fail
        // without a real verifier (NoOpVerifier denies).
        let result = validate_envelope_tp001(Some(&valid_envelope()), &valid_eval_window(), None);
        assert!(result.is_err());
    }

    // ========================================================================
    // Freshness horizon (TP-EIO29-002)
    // ========================================================================

    #[test]
    fn tp002_valid_inputs_pass() {
        let result = validate_freshness_horizon_tp002(
            Some(&valid_freshness_horizon()),
            Some(&valid_revocation_frontier()),
            &valid_eval_window(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn tp002_missing_horizon_denies() {
        let result = validate_freshness_horizon_tp002(
            None,
            Some(&valid_revocation_frontier()),
            &valid_eval_window(),
        );
        assert_eq!(result.unwrap_err(), DENY_FRESHNESS_HORIZON_UNRESOLVED);
    }

    #[test]
    fn tp002_unresolved_horizon_denies() {
        let mut horizon = valid_freshness_horizon();
        horizon.resolved = false;
        let result = validate_freshness_horizon_tp002(
            Some(&horizon),
            Some(&valid_revocation_frontier()),
            &valid_eval_window(),
        );
        assert_eq!(result.unwrap_err(), DENY_FRESHNESS_HORIZON_UNRESOLVED);
    }

    #[test]
    fn tp002_zero_horizon_hash_denies() {
        let mut horizon = valid_freshness_horizon();
        horizon.horizon_hash = [0u8; 32];
        let result = validate_freshness_horizon_tp002(
            Some(&horizon),
            Some(&valid_revocation_frontier()),
            &valid_eval_window(),
        );
        assert_eq!(result.unwrap_err(), DENY_FRESHNESS_HORIZON_UNRESOLVED);
    }

    #[test]
    fn tp002_window_exceeds_horizon_denies() {
        let mut horizon = valid_freshness_horizon();
        horizon.tick_end = 1400; // < eval_window.tick_end(1500)
        let result = validate_freshness_horizon_tp002(
            Some(&horizon),
            Some(&valid_revocation_frontier()),
            &valid_eval_window(),
        );
        assert_eq!(result.unwrap_err(), DENY_FRESHNESS_HORIZON_EXCEEDED);
    }

    #[test]
    fn tp002_missing_frontier_denies() {
        let result = validate_freshness_horizon_tp002(
            Some(&valid_freshness_horizon()),
            None,
            &valid_eval_window(),
        );
        assert_eq!(result.unwrap_err(), DENY_REVOCATION_FRONTIER_STALE);
    }

    #[test]
    fn tp002_stale_frontier_denies() {
        let mut frontier = valid_revocation_frontier();
        frontier.current = false;
        let result = validate_freshness_horizon_tp002(
            Some(&valid_freshness_horizon()),
            Some(&frontier),
            &valid_eval_window(),
        );
        assert_eq!(result.unwrap_err(), DENY_REVOCATION_FRONTIER_STALE);
    }

    #[test]
    fn tp002_zero_frontier_hash_denies() {
        let mut frontier = valid_revocation_frontier();
        frontier.frontier_hash = [0u8; 32];
        let result = validate_freshness_horizon_tp002(
            Some(&valid_freshness_horizon()),
            Some(&frontier),
            &valid_eval_window(),
        );
        assert_eq!(result.unwrap_err(), DENY_REVOCATION_FRONTIER_STALE);
    }

    // ========================================================================
    // Convergence horizon (TP-EIO29-003)
    // ========================================================================

    #[test]
    fn tp003_valid_inputs_pass() {
        let required = test_hash(0x01);
        let result = validate_convergence_horizon_tp003(
            Some(&valid_convergence_horizon()),
            &[valid_convergence_receipt(required)],
            &[required],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn tp003_missing_horizon_denies() {
        let result = validate_convergence_horizon_tp003(None, &[], &[]);
        assert_eq!(result.unwrap_err(), DENY_CONVERGENCE_HORIZON_UNRESOLVED);
    }

    #[test]
    fn tp003_unresolved_horizon_denies() {
        let mut horizon = valid_convergence_horizon();
        horizon.resolved = false;
        let result = validate_convergence_horizon_tp003(Some(&horizon), &[], &[]);
        assert_eq!(result.unwrap_err(), DENY_CONVERGENCE_HORIZON_UNRESOLVED);
    }

    #[test]
    fn tp003_zero_horizon_hash_denies() {
        let mut horizon = valid_convergence_horizon();
        horizon.horizon_hash = [0u8; 32];
        let result = validate_convergence_horizon_tp003(Some(&horizon), &[], &[]);
        assert_eq!(result.unwrap_err(), DENY_CONVERGENCE_HORIZON_UNRESOLVED);
    }

    #[test]
    fn tp003_missing_receipt_denies() {
        let required = test_hash(0x01);
        let result = validate_convergence_horizon_tp003(
            Some(&valid_convergence_horizon()),
            &[], // no receipts
            &[required],
        );
        assert_eq!(result.unwrap_err(), DENY_CONVERGENCE_RECEIPT_MISSING);
    }

    #[test]
    fn tp003_not_converged_denies() {
        let required = test_hash(0x01);
        let mut receipt = valid_convergence_receipt(required);
        receipt.converged = false;
        let result = validate_convergence_horizon_tp003(
            Some(&valid_convergence_horizon()),
            &[receipt],
            &[required],
        );
        assert_eq!(result.unwrap_err(), DENY_AUTHORITY_SET_NOT_CONVERGED);
    }

    #[test]
    fn tp003_zero_proof_hash_denies() {
        let required = test_hash(0x01);
        let mut receipt = valid_convergence_receipt(required);
        receipt.proof_hash = [0u8; 32];
        let result = validate_convergence_horizon_tp003(
            Some(&valid_convergence_horizon()),
            &[receipt],
            &[required],
        );
        assert_eq!(result.unwrap_err(), DENY_CONVERGENCE_RECEIPT_MISSING);
    }

    #[test]
    fn tp003_zero_required_set_denies() {
        let result = validate_convergence_horizon_tp003(
            Some(&valid_convergence_horizon()),
            &[],
            &[[0u8; 32]],
        );
        assert_eq!(result.unwrap_err(), DENY_AUTHORITY_SET_NOT_CONVERGED);
    }

    #[test]
    fn tp003_multiple_required_sets_all_must_converge() {
        let set_a = test_hash(0x01);
        let set_b = test_hash(0x02);
        let result = validate_convergence_horizon_tp003(
            Some(&valid_convergence_horizon()),
            &[valid_convergence_receipt(set_a)], // missing receipt for set_b
            &[set_a, set_b],
        );
        assert_eq!(result.unwrap_err(), DENY_CONVERGENCE_RECEIPT_MISSING);
    }

    #[test]
    fn tp003_empty_required_sets_passes() {
        let result = validate_convergence_horizon_tp003(
            Some(&valid_convergence_horizon()),
            &[],
            &[], // no required sets
        );
        assert!(result.is_ok());
    }

    // ========================================================================
    // Queue admission evaluator
    // ========================================================================

    #[test]
    fn queue_admit_valid_request_allows() {
        let request = valid_queue_request(QueueLane::Consume);
        let scheduler = QueueSchedulerState::new();
        let decision = evaluate_queue_admission(&request, &scheduler, test_verifier());
        assert_eq!(decision.verdict, QueueAdmissionVerdict::Allow);
        assert!(decision.defect().is_none());
        assert!(decision.trace.tp001_passed);
        assert!(decision.trace.tp002_passed);
        assert!(decision.trace.tp003_passed);
    }

    #[test]
    fn queue_admit_missing_envelope_denies_non_stop_revoke() {
        let mut request = valid_queue_request(QueueLane::Consume);
        request.envelope = None;
        let scheduler = QueueSchedulerState::new();
        let decision = evaluate_queue_admission(&request, &scheduler, test_verifier());
        assert_eq!(decision.verdict, QueueAdmissionVerdict::Deny);
        assert_eq!(
            decision.defect().map(|d| d.reason.as_str()),
            Some(DENY_ENVELOPE_MISSING)
        );
    }

    #[test]
    fn queue_admit_stop_revoke_allows_without_full_envelope() {
        // Stop/revoke lane has emergency carve-out for authority-reducing ops.
        // With valid tp002/tp003 state, the request is admitted despite tp001
        // failure because the stop_revoke lane permits local monotonic
        // emergency time for authority-reducing operations.
        let mut request = valid_queue_request(QueueLane::StopRevoke);
        request.envelope = None;
        let scheduler = QueueSchedulerState::new();
        let decision = evaluate_queue_admission(&request, &scheduler, test_verifier());
        assert_eq!(decision.verdict, QueueAdmissionVerdict::Allow);
        // tp001 should be flagged as failed
        assert!(!decision.trace.tp001_passed);
        assert!(decision.trace.tp002_passed);
        assert!(decision.trace.tp003_passed);
    }

    #[test]
    fn queue_admit_stop_revoke_denies_when_tp002_also_fails() {
        let mut request = valid_queue_request(QueueLane::StopRevoke);
        request.envelope = None;
        request.freshness_horizon = None;
        let scheduler = QueueSchedulerState::new();
        let decision = evaluate_queue_admission(&request, &scheduler, test_verifier());
        assert_eq!(decision.verdict, QueueAdmissionVerdict::Deny);
        let defect = decision.defect().expect("should have defect");
        assert_eq!(defect.predicate_id, Some(TemporalPredicateId::TpEio29002));
    }

    #[test]
    fn queue_admit_all_lanes_with_valid_request() {
        let scheduler = QueueSchedulerState::new();
        for lane in QueueLane::all() {
            let request = valid_queue_request(lane);
            let decision = evaluate_queue_admission(&request, &scheduler, test_verifier());
            assert_eq!(
                decision.verdict,
                QueueAdmissionVerdict::Allow,
                "lane {lane} should be allowed with valid request"
            );
        }
    }

    #[test]
    fn queue_lane_backlog_exceeded_denies() {
        let request = valid_queue_request(QueueLane::Bulk);
        let mut scheduler = QueueSchedulerState::new();
        scheduler.lanes[QueueLane::Bulk as usize].backlog = MAX_LANE_BACKLOG;
        let decision = evaluate_queue_admission(&request, &scheduler, test_verifier());
        assert_eq!(decision.verdict, QueueAdmissionVerdict::Deny);
        assert_eq!(
            decision.defect().map(|d| d.reason.as_str()),
            Some(DENY_LANE_BACKLOG_EXCEEDED)
        );
    }

    #[test]
    fn queue_total_capacity_exceeded_denies() {
        // Non-reserved lane (Consume) must be denied when total is full.
        let request = valid_queue_request(QueueLane::Consume);
        let mut scheduler = QueueSchedulerState::new();
        scheduler.total_items = MAX_TOTAL_QUEUE_ITEMS;
        let decision = evaluate_queue_admission(&request, &scheduler, test_verifier());
        assert_eq!(decision.verdict, QueueAdmissionVerdict::Deny);
        assert_eq!(
            decision.defect().map(|d| d.reason.as_str()),
            Some(DENY_TOTAL_QUEUE_EXCEEDED)
        );
    }

    #[test]
    fn queue_tick_floor_violation_stop_revoke_denies() {
        let request = valid_queue_request(QueueLane::Consume);
        let mut scheduler = QueueSchedulerState::new();
        scheduler.lanes[QueueLane::StopRevoke as usize].backlog = 1;
        scheduler.lanes[QueueLane::StopRevoke as usize].max_wait_ticks =
            MAX_STOP_REVOKE_WAIT_TICKS + 1;
        let decision = evaluate_queue_admission(&request, &scheduler, test_verifier());
        assert_eq!(decision.verdict, QueueAdmissionVerdict::Deny);
        assert_eq!(
            decision.defect().map(|d| d.reason.as_str()),
            Some(DENY_TICK_FLOOR_STOP_REVOKE)
        );
    }

    #[test]
    fn queue_tick_floor_violation_control_denies() {
        let request = valid_queue_request(QueueLane::Bulk);
        let mut scheduler = QueueSchedulerState::new();
        scheduler.lanes[QueueLane::Control as usize].backlog = 1;
        scheduler.lanes[QueueLane::Control as usize].max_wait_ticks = MAX_CONTROL_WAIT_TICKS + 1;
        let decision = evaluate_queue_admission(&request, &scheduler, test_verifier());
        assert_eq!(decision.verdict, QueueAdmissionVerdict::Deny);
        assert_eq!(
            decision.defect().map(|d| d.reason.as_str()),
            Some(DENY_TICK_FLOOR_CONTROL)
        );
    }

    // ========================================================================
    // Lane reservation bypass (FINDING 2 — anti-starvation)
    // ========================================================================

    #[test]
    fn test_stop_revoke_admitted_when_total_full_but_reservation_available() {
        let request = valid_queue_request(QueueLane::StopRevoke);
        let mut scheduler = QueueSchedulerState::new();
        scheduler.total_items = MAX_TOTAL_QUEUE_ITEMS;
        // StopRevoke backlog is below its reserved capacity.
        scheduler.lanes[QueueLane::StopRevoke as usize].backlog = 0;
        let decision = evaluate_queue_admission(&request, &scheduler, test_verifier());
        assert_eq!(
            decision.verdict,
            QueueAdmissionVerdict::Allow,
            "StopRevoke must admit when total full but reservation available"
        );
    }

    #[test]
    fn test_control_admitted_when_total_full_but_reservation_available() {
        let request = valid_queue_request(QueueLane::Control);
        let mut scheduler = QueueSchedulerState::new();
        scheduler.total_items = MAX_TOTAL_QUEUE_ITEMS;
        scheduler.lanes[QueueLane::Control as usize].backlog = 0;
        let decision = evaluate_queue_admission(&request, &scheduler, test_verifier());
        assert_eq!(
            decision.verdict,
            QueueAdmissionVerdict::Allow,
            "Control must admit when total full but reservation available"
        );
    }

    #[test]
    fn test_stop_revoke_denied_when_reservation_exhausted() {
        let request = valid_queue_request(QueueLane::StopRevoke);
        let mut scheduler = QueueSchedulerState::new();
        scheduler.total_items = MAX_TOTAL_QUEUE_ITEMS;
        let reserved = QueueSchedulerState::reserved_capacity(QueueLane::StopRevoke);
        scheduler.lanes[QueueLane::StopRevoke as usize].backlog = reserved;
        let decision = evaluate_queue_admission(&request, &scheduler, test_verifier());
        assert_eq!(
            decision.verdict,
            QueueAdmissionVerdict::Deny,
            "StopRevoke must deny when reservation exhausted"
        );
        assert_eq!(
            decision.defect().map(|d| d.reason.as_str()),
            Some(DENY_TOTAL_QUEUE_EXCEEDED)
        );
    }

    #[test]
    fn test_bulk_denied_when_total_full() {
        let request = valid_queue_request(QueueLane::Bulk);
        let mut scheduler = QueueSchedulerState::new();
        scheduler.total_items = MAX_TOTAL_QUEUE_ITEMS;
        let decision = evaluate_queue_admission(&request, &scheduler, test_verifier());
        assert_eq!(
            decision.verdict,
            QueueAdmissionVerdict::Deny,
            "Bulk must deny when total full (no reservation)"
        );
    }

    #[test]
    fn test_adversarial_low_priority_flood_cannot_block_stop_revoke() {
        // Fill the queue entirely with Bulk traffic.
        let mut scheduler = QueueSchedulerState::new();
        scheduler.total_items = MAX_TOTAL_QUEUE_ITEMS;
        scheduler.lanes[QueueLane::Bulk as usize].backlog = MAX_LANE_BACKLOG;
        // StopRevoke has zero backlog — reservation should allow admission.
        scheduler.lanes[QueueLane::StopRevoke as usize].backlog = 0;

        let request = valid_queue_request(QueueLane::StopRevoke);
        let decision = evaluate_queue_admission(&request, &scheduler, test_verifier());
        assert_eq!(
            decision.verdict,
            QueueAdmissionVerdict::Allow,
            "adversarial low-priority flood must not block stop_revoke"
        );
    }

    #[test]
    fn scheduler_record_admission_reservation_aware() {
        let mut scheduler = QueueSchedulerState::new();
        scheduler.total_items = MAX_TOTAL_QUEUE_ITEMS;
        // StopRevoke should admit via reservation.
        assert!(scheduler.record_admission(QueueLane::StopRevoke).is_ok());
        // Non-reserved lane must fail.
        let mut sched2 = QueueSchedulerState::new();
        sched2.total_items = MAX_TOTAL_QUEUE_ITEMS;
        assert_eq!(
            sched2.record_admission(QueueLane::Bulk).unwrap_err(),
            DENY_TOTAL_QUEUE_EXCEEDED
        );
    }

    // ========================================================================
    // Anti-entropy admission
    // ========================================================================

    #[test]
    fn anti_entropy_valid_pull_allows() {
        let request = valid_anti_entropy_request();
        let budget = AntiEntropyBudget::default_budget();
        let decision = evaluate_anti_entropy_admission(&request, &budget, test_verifier());
        assert_eq!(decision.verdict, QueueAdmissionVerdict::Allow);
    }

    #[test]
    fn anti_entropy_push_denies() {
        let mut request = valid_anti_entropy_request();
        request.direction = AntiEntropyDirection::Push;
        let budget = AntiEntropyBudget::default_budget();
        let decision = evaluate_anti_entropy_admission(&request, &budget, test_verifier());
        assert_eq!(decision.verdict, QueueAdmissionVerdict::Deny);
        assert_eq!(
            decision.defect().map(|d| d.reason.as_str()),
            Some(DENY_ANTI_ENTROPY_PUSH_REJECTED)
        );
    }

    #[test]
    fn anti_entropy_oversized_proof_denies() {
        let mut request = valid_anti_entropy_request();
        request.proof_bytes = 1001;
        request.max_proof_bytes = 1000;
        let budget = AntiEntropyBudget::default_budget();
        let decision = evaluate_anti_entropy_admission(&request, &budget, test_verifier());
        assert_eq!(decision.verdict, QueueAdmissionVerdict::Deny);
        assert_eq!(
            decision.defect().map(|d| d.reason.as_str()),
            Some(DENY_ANTI_ENTROPY_OVERSIZED)
        );
    }

    #[test]
    fn anti_entropy_budget_exhausted_denies() {
        let request = valid_anti_entropy_request();
        let budget = AntiEntropyBudget::new(5); // cost is 10, budget is 5
        let decision = evaluate_anti_entropy_admission(&request, &budget, test_verifier());
        assert_eq!(decision.verdict, QueueAdmissionVerdict::Deny);
        assert_eq!(
            decision.defect().map(|d| d.reason.as_str()),
            Some(DENY_ANTI_ENTROPY_BUDGET_EXHAUSTED)
        );
    }

    #[test]
    fn anti_entropy_missing_envelope_denies() {
        let mut request = valid_anti_entropy_request();
        request.envelope = None;
        let budget = AntiEntropyBudget::default_budget();
        let decision = evaluate_anti_entropy_admission(&request, &budget, test_verifier());
        assert_eq!(decision.verdict, QueueAdmissionVerdict::Deny);
        assert_eq!(
            decision.defect().map(|d| d.reason.as_str()),
            Some(DENY_ENVELOPE_MISSING)
        );
    }

    #[test]
    fn anti_entropy_missing_convergence_denies() {
        let mut request = valid_anti_entropy_request();
        request.convergence_horizon = None;
        let budget = AntiEntropyBudget::default_budget();
        let decision = evaluate_anti_entropy_admission(&request, &budget, test_verifier());
        assert_eq!(decision.verdict, QueueAdmissionVerdict::Deny);
        assert_eq!(
            decision.defect().map(|d| d.reason.as_str()),
            Some(DENY_CONVERGENCE_HORIZON_UNRESOLVED)
        );
    }

    // ========================================================================
    // Scheduler state
    // ========================================================================

    #[test]
    fn scheduler_record_admission_and_completion() {
        let mut scheduler = QueueSchedulerState::new();
        assert_eq!(scheduler.total_items(), 0);

        scheduler
            .record_admission(QueueLane::Consume)
            .expect("should admit");
        assert_eq!(scheduler.total_items(), 1);
        assert_eq!(scheduler.lane(QueueLane::Consume).backlog, 1);

        scheduler.record_completion(QueueLane::Consume);
        assert_eq!(scheduler.total_items(), 0);
        assert_eq!(scheduler.lane(QueueLane::Consume).backlog, 0);
    }

    #[test]
    fn scheduler_lane_backlog_cap_enforced() {
        let mut scheduler = QueueSchedulerState::new();
        scheduler.lanes[QueueLane::Bulk as usize].backlog = MAX_LANE_BACKLOG;
        let result = scheduler.record_admission(QueueLane::Bulk);
        assert_eq!(result.unwrap_err(), DENY_LANE_BACKLOG_EXCEEDED);
    }

    #[test]
    fn scheduler_total_items_cap_enforced() {
        let mut scheduler = QueueSchedulerState::new();
        scheduler.total_items = MAX_TOTAL_QUEUE_ITEMS;
        let result = scheduler.record_admission(QueueLane::Consume);
        assert_eq!(result.unwrap_err(), DENY_TOTAL_QUEUE_EXCEEDED);
    }

    #[test]
    fn scheduler_reserved_capacity_correct() {
        let stop_reserved = QueueSchedulerState::reserved_capacity(QueueLane::StopRevoke);
        assert_eq!(
            stop_reserved,
            (MAX_TOTAL_QUEUE_ITEMS * STOP_REVOKE_RESERVATION_PERMILLE as usize) / 1000
        );

        let control_reserved = QueueSchedulerState::reserved_capacity(QueueLane::Control);
        assert_eq!(
            control_reserved,
            (MAX_TOTAL_QUEUE_ITEMS * CONTROL_RESERVATION_PERMILLE as usize) / 1000
        );

        let bulk_reserved = QueueSchedulerState::reserved_capacity(QueueLane::Bulk);
        assert_eq!(bulk_reserved, 0);
    }

    #[test]
    fn scheduler_tick_floor_ok_when_empty() {
        let scheduler = QueueSchedulerState::new();
        assert!(scheduler.check_tick_floor_invariants().is_ok());
    }

    #[test]
    fn scheduler_tick_floor_ok_when_within_limits() {
        let mut scheduler = QueueSchedulerState::new();
        scheduler.lanes[QueueLane::StopRevoke as usize].backlog = 1;
        scheduler.lanes[QueueLane::StopRevoke as usize].max_wait_ticks = MAX_STOP_REVOKE_WAIT_TICKS;
        assert!(scheduler.check_tick_floor_invariants().is_ok());
    }

    // ========================================================================
    // Budget tracker
    // ========================================================================

    #[test]
    fn budget_consume_and_remaining() {
        let mut budget = AntiEntropyBudget::new(100);
        assert_eq!(budget.remaining(), 100);

        budget.try_consume(30).expect("should consume");
        assert_eq!(budget.remaining(), 70);

        budget.try_consume(70).expect("should consume");
        assert_eq!(budget.remaining(), 0);

        let err = budget.try_consume(1).unwrap_err();
        assert_eq!(err, DENY_ANTI_ENTROPY_BUDGET_EXHAUSTED);
    }

    #[test]
    fn budget_reset_restores_full_budget() {
        let mut budget = AntiEntropyBudget::new(100);
        budget.try_consume(100).expect("should consume");
        assert_eq!(budget.remaining(), 0);

        budget.reset();
        assert_eq!(budget.remaining(), 100);
    }

    // ========================================================================
    // Lane properties
    // ========================================================================

    #[test]
    fn lane_priority_ordering() {
        assert!(QueueLane::StopRevoke < QueueLane::Control);
        assert!(QueueLane::Control < QueueLane::Consume);
        assert!(QueueLane::Consume < QueueLane::Replay);
        assert!(QueueLane::Replay < QueueLane::ProjectionReplay);
        assert!(QueueLane::ProjectionReplay < QueueLane::Bulk);
    }

    #[test]
    fn lane_tick_floor_guarantees() {
        assert!(QueueLane::StopRevoke.has_tick_floor_guarantee());
        assert!(QueueLane::Control.has_tick_floor_guarantee());
        assert!(!QueueLane::Consume.has_tick_floor_guarantee());
        assert!(!QueueLane::Replay.has_tick_floor_guarantee());
        assert!(!QueueLane::ProjectionReplay.has_tick_floor_guarantee());
        assert!(!QueueLane::Bulk.has_tick_floor_guarantee());
    }

    #[test]
    fn lane_max_wait_ticks_correct() {
        assert_eq!(
            QueueLane::StopRevoke.max_wait_ticks(),
            Some(MAX_STOP_REVOKE_WAIT_TICKS)
        );
        assert_eq!(
            QueueLane::Control.max_wait_ticks(),
            Some(MAX_CONTROL_WAIT_TICKS)
        );
        assert_eq!(QueueLane::Consume.max_wait_ticks(), None);
    }

    // ========================================================================
    // Trace canonical bytes
    // ========================================================================

    #[test]
    fn trace_canonical_bytes_deterministic() {
        let request = valid_queue_request(QueueLane::Consume);
        let scheduler = QueueSchedulerState::new();
        let d1 = evaluate_queue_admission(&request, &scheduler, test_verifier());
        let d2 = evaluate_queue_admission(&request, &scheduler, test_verifier());

        let bytes1 = d1.trace.canonical_bytes().expect("should serialize");
        let bytes2 = d2.trace.canonical_bytes().expect("should serialize");
        assert_eq!(bytes1, bytes2);
        assert!(!bytes1.is_empty());
    }

    // ========================================================================
    // Adversarial drill: replay flood
    // ========================================================================

    #[test]
    fn adversarial_replay_flood_bounded_by_lane_backlog() {
        let scheduler = QueueSchedulerState::new();
        let mut admitted = 0usize;
        let mut denied = 0usize;

        for i in 0..MAX_LANE_BACKLOG + 100 {
            let mut request = valid_queue_request(QueueLane::Replay);
            request.current_tick = 1200 + i as u64;
            let mut sched = scheduler.clone();
            sched.lanes[QueueLane::Replay as usize].backlog = i.min(MAX_LANE_BACKLOG);
            sched.total_items = i.min(MAX_TOTAL_QUEUE_ITEMS);
            let decision = evaluate_queue_admission(&request, &sched, test_verifier());
            match decision.verdict {
                QueueAdmissionVerdict::Allow => admitted += 1,
                QueueAdmissionVerdict::Deny => denied += 1,
                QueueAdmissionVerdict::Freeze => {},
            }
        }

        assert!(admitted > 0, "some replay requests should be admitted");
        assert!(denied > 0, "overflow replay requests must be denied");
        assert!(
            admitted <= MAX_LANE_BACKLOG,
            "admitted replay count must not exceed lane backlog cap"
        );
    }

    // ========================================================================
    // Adversarial drill: mixed control/replay bursts
    // ========================================================================

    #[test]
    fn adversarial_mixed_bursts_control_lane_preserved() {
        let mut scheduler = QueueSchedulerState::new();

        // Fill replay lane to capacity
        for _ in 0..MAX_LANE_BACKLOG {
            let _ = scheduler.record_admission(QueueLane::Replay);
        }

        // Control lane should still admit
        let request = valid_queue_request(QueueLane::Control);
        let decision = evaluate_queue_admission(&request, &scheduler, test_verifier());
        assert_eq!(
            decision.verdict,
            QueueAdmissionVerdict::Allow,
            "control lane must be preserved even when replay is saturated"
        );

        // Stop/revoke should still admit
        let request = valid_queue_request(QueueLane::StopRevoke);
        let decision = evaluate_queue_admission(&request, &scheduler, test_verifier());
        assert_eq!(
            decision.verdict,
            QueueAdmissionVerdict::Allow,
            "stop_revoke lane must be preserved even when replay is saturated"
        );
    }

    // ========================================================================
    // Adversarial drill: low-rate exhaustion
    // ========================================================================

    #[test]
    fn adversarial_low_rate_anti_entropy_exhaustion() {
        let mut budget = AntiEntropyBudget::default_budget();
        let mut admitted = 0u64;
        let mut denied = 0u64;

        // Send many small requests to exhaust budget
        for _ in 0..MAX_ANTI_ENTROPY_BUDGET + 100 {
            let mut request = valid_anti_entropy_request();
            request.cost = 1;
            let decision = evaluate_anti_entropy_admission(&request, &budget, test_verifier());
            match decision.verdict {
                QueueAdmissionVerdict::Allow => {
                    let _ = budget.try_consume(request.cost);
                    admitted += 1;
                },
                QueueAdmissionVerdict::Deny => denied += 1,
                QueueAdmissionVerdict::Freeze => {},
            }
        }

        assert_eq!(admitted, MAX_ANTI_ENTROPY_BUDGET);
        assert!(denied > 0, "budget exhaustion must cause denials");
    }

    // ========================================================================
    // Adversarial drill: unknown/invalid temporal state
    // ========================================================================

    #[test]
    fn unknown_temporal_state_denies_all_lanes() {
        let scheduler = QueueSchedulerState::new();

        for lane in QueueLane::all() {
            let mut request = valid_queue_request(lane);
            request.envelope = None;
            request.freshness_horizon = None;
            request.revocation_frontier = None;
            request.convergence_horizon = None;
            let decision = evaluate_queue_admission(&request, &scheduler, test_verifier());

            if lane == QueueLane::StopRevoke {
                // Stop/revoke has emergency carve-out but still fails on tp002
                assert_eq!(decision.verdict, QueueAdmissionVerdict::Deny);
            } else {
                assert_eq!(
                    decision.verdict,
                    QueueAdmissionVerdict::Deny,
                    "lane {lane} must deny with unknown temporal state"
                );
            }
        }
    }

    // ========================================================================
    // Envelope structural tests
    // ========================================================================

    #[test]
    fn envelope_validate_valid() {
        let envelope = valid_envelope();
        assert!(envelope.validate().is_ok());
    }

    #[test]
    fn envelope_serde_roundtrip() {
        let envelope = valid_envelope();
        let json = serde_json::to_string(&envelope).expect("should serialize");
        let parsed: TimeAuthorityEnvelopeV1 =
            serde_json::from_str(&json).expect("should deserialize");
        assert_eq!(envelope, parsed);
    }

    // ========================================================================
    // Bounded deserialization tests (FINDING 1 — DoS prevention)
    // ========================================================================

    #[test]
    fn test_deserialize_oversized_boundary_id_rejected() {
        let oversized_id = "x".repeat(MAX_BOUNDARY_ID_LENGTH + 1);
        let json = format!(
            r#"{{
                "boundary_id": "{oversized_id}",
                "authority_clock": "clock-main",
                "tick_start": 1000,
                "tick_end": 2000,
                "ttl_ticks": 1500,
                "deny_on_unknown": true,
                "signature_set": [],
                "content_hash": [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]
            }}"#
        );
        let result = serde_json::from_str::<TimeAuthorityEnvelopeV1>(&json);
        assert!(
            result.is_err(),
            "oversized boundary_id must be rejected during deserialization"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("exceeds maximum length"),
            "error should mention length: {err}"
        );
    }

    #[test]
    fn test_deserialize_oversized_signature_set_rejected() {
        // Build JSON with 17 signatures (MAX_ENVELOPE_SIGNATURES=16).
        let sig_json = r#"{"signer_id": [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1], "signature": [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]}"#;
        let sigs: Vec<&str> = (0..=MAX_ENVELOPE_SIGNATURES).map(|_| sig_json).collect();
        let json = format!(
            r#"{{
                "boundary_id": "b",
                "authority_clock": "c",
                "tick_start": 1000,
                "tick_end": 2000,
                "ttl_ticks": 1500,
                "deny_on_unknown": true,
                "signature_set": [{}],
                "content_hash": [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]
            }}"#,
            sigs.join(",")
        );
        let result = serde_json::from_str::<TimeAuthorityEnvelopeV1>(&json);
        assert!(
            result.is_err(),
            "oversized signature_set must be rejected during deserialization"
        );
    }

    #[test]
    fn test_deserialize_oversized_convergence_receipts_rejected() {
        let receipt_json = r#"{"authority_set_hash": [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1], "proof_hash": [2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2], "converged": true}"#;
        let receipts: Vec<&str> = (0..=MAX_CONVERGENCE_RECEIPTS)
            .map(|_| receipt_json)
            .collect();
        let json = format!(
            r#"{{
                "lane": "bulk",
                "envelope": null,
                "eval_window": {{ "boundary_id": "b", "authority_clock": "c", "tick_start": 0, "tick_end": 0 }},
                "freshness_horizon": null,
                "revocation_frontier": null,
                "convergence_horizon": null,
                "convergence_receipts": [{}],
                "required_authority_sets": [],
                "cost": 0,
                "current_tick": 0
            }}"#,
            receipts.join(",")
        );
        let result = serde_json::from_str::<QueueAdmissionRequest>(&json);
        assert!(
            result.is_err(),
            "oversized convergence_receipts must be rejected during deserialization"
        );
    }

    #[test]
    fn test_deserialize_oversized_required_authority_sets_rejected() {
        let hash_json = "[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]";
        let sets: Vec<&str> = (0..=MAX_REQUIRED_AUTHORITY_SETS)
            .map(|_| hash_json)
            .collect();
        let json = format!(
            r#"{{
                "lane": "bulk",
                "envelope": null,
                "eval_window": {{ "boundary_id": "b", "authority_clock": "c", "tick_start": 0, "tick_end": 0 }},
                "freshness_horizon": null,
                "revocation_frontier": null,
                "convergence_horizon": null,
                "convergence_receipts": [],
                "required_authority_sets": [{}],
                "cost": 0,
                "current_tick": 0
            }}"#,
            sets.join(",")
        );
        let result = serde_json::from_str::<QueueAdmissionRequest>(&json);
        assert!(
            result.is_err(),
            "oversized required_authority_sets must be rejected during deserialization"
        );
    }

    #[test]
    fn test_deserialize_valid_payloads_still_work() {
        // Confirm that valid payloads still round-trip correctly after adding bounds.
        let envelope = valid_envelope();
        let json = serde_json::to_string(&envelope).expect("serialize");
        let parsed: TimeAuthorityEnvelopeV1 =
            serde_json::from_str(&json).expect("should deserialize");
        assert_eq!(envelope, parsed);

        let window = valid_eval_window();
        let json = serde_json::to_string(&window).expect("serialize");
        let parsed: HtfEvaluationWindow = serde_json::from_str(&json).expect("should deserialize");
        assert_eq!(window, parsed);

        let request = valid_queue_request(QueueLane::Consume);
        let json = serde_json::to_string(&request).expect("serialize");
        let parsed: QueueAdmissionRequest =
            serde_json::from_str(&json).expect("should deserialize");
        assert_eq!(request, parsed);

        let ae_request = valid_anti_entropy_request();
        let json = serde_json::to_string(&ae_request).expect("serialize");
        let parsed: AntiEntropyAdmissionRequest =
            serde_json::from_str(&json).expect("should deserialize");
        assert_eq!(ae_request, parsed);
    }

    #[test]
    fn test_deserialize_oversized_deny_reason_rejected() {
        let oversized_reason = "x".repeat(MAX_DENY_REASON_LENGTH + 1);
        let json = format!(
            r#"{{
                "reason": "{oversized_reason}",
                "denied_at_tick": 0,
                "envelope_hash": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
                "boundary_id": "b"
            }}"#
        );
        let result = serde_json::from_str::<QueueDenyDefect>(&json);
        assert!(
            result.is_err(),
            "oversized deny reason must be rejected during deserialization"
        );
    }

    // ========================================================================
    // QueueLane Display
    // ========================================================================

    #[test]
    fn queue_lane_display() {
        assert_eq!(QueueLane::StopRevoke.to_string(), "stop_revoke");
        assert_eq!(QueueLane::Control.to_string(), "control");
        assert_eq!(QueueLane::Consume.to_string(), "consume");
        assert_eq!(QueueLane::Replay.to_string(), "replay");
        assert_eq!(QueueLane::ProjectionReplay.to_string(), "projection_replay");
        assert_eq!(QueueLane::Bulk.to_string(), "bulk");
    }

    // ========================================================================
    // Defect accessor
    // ========================================================================

    #[test]
    fn decision_defect_accessor_matches_trace() {
        let mut request = valid_queue_request(QueueLane::Consume);
        request.envelope = None;
        let scheduler = QueueSchedulerState::new();
        let decision = evaluate_queue_admission(&request, &scheduler, test_verifier());
        assert_eq!(decision.verdict, QueueAdmissionVerdict::Deny);
        // The defect() accessor must delegate to trace.defect.
        assert_eq!(decision.defect(), decision.trace.defect.as_ref());
    }

    // ========================================================================
    // BLOCKER 1 — Visitor-based bounded string deserialization
    // ========================================================================

    #[test]
    fn test_bounded_string_visitor_rejects_oversized_boundary_id_at_deser() {
        // A boundary_id exceeding MAX_BOUNDARY_ID_LENGTH (256) must fail at
        // deserialization time — not at post-validation — proving the Visitor
        // checks length before allocation on the `visit_str` path.
        let oversized = "A".repeat(MAX_BOUNDARY_ID_LENGTH + 1);
        let json = format!(
            r#"{{
                "boundary_id": "{oversized}",
                "authority_clock": "c",
                "tick_start": 0,
                "tick_end": 0
            }}"#
        );
        let result = serde_json::from_str::<HtfEvaluationWindow>(&json);
        assert!(
            result.is_err(),
            "boundary_id exceeding MAX_BOUNDARY_ID_LENGTH must fail at deserialization"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("exceeds maximum length"),
            "error must mention exceeds maximum length, got: {err_msg}"
        );
    }

    // ========================================================================
    // BLOCKER 2 — Injective (length-prefixed) canonical bytes
    // ========================================================================

    #[test]
    fn test_envelope_canonical_bytes_injective() {
        // Three envelopes whose (boundary_id, authority_clock) pairs would
        // collide under naive concatenation must produce DISTINCT canonical
        // bytes with the length-prefix framing.
        let make = |bid: &str, clk: &str| {
            let mut env = valid_envelope();
            env.boundary_id = bid.to_string();
            env.authority_clock = clk.to_string();
            env
        };

        let e1 = make("ab", "cd");
        let e2 = make("abc", "d");
        let e3 = make("a", "bcd");

        let b1 = envelope_signature_canonical_bytes(&e1);
        let b2 = envelope_signature_canonical_bytes(&e2);
        let b3 = envelope_signature_canonical_bytes(&e3);

        assert_ne!(
            b1, b2,
            "('ab','cd') and ('abc','d') must produce different canonical bytes"
        );
        assert_ne!(
            b1, b3,
            "('ab','cd') and ('a','bcd') must produce different canonical bytes"
        );
        assert_ne!(
            b2, b3,
            "('abc','d') and ('a','bcd') must produce different canonical bytes"
        );
    }
}
