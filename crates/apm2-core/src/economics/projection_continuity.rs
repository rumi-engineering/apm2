// AGENT-AUTHORED
//! Projection multi-sink outage continuity and deferred replay boundedness
//! for RFC-0029 REQ-0009.
//!
//! Implements:
//! - [`ProjectionContinuityWindowV1`] outage/replay horizon enforcement.
//! - [`ProjectionSinkContinuityProfileV1`] per-sink-set scenario evaluation.
//! - [`SinkIdentitySnapshotV1`] sink identity binding.
//! - TP-EIO29-005 (`projection_multi_sink_continuity_valid`) enforcement.
//! - TP-EIO29-001/003/004 continuity predicates for sink outage/churn/partition
//!   scenarios.
//! - Authoritative progression independence from projection sink state.
//! - Fail closed on missing/stale/invalid temporal authority in continuity
//!   decisions.
//!
//! # Security Domain
//!
//! `DOMAIN_SECURITY` is in scope. All unknown, missing, stale, or
//! unverifiable continuity states fail closed.
//!
//! # Temporal Model
//!
//! All continuity window declarations carry `time_authority_ref` and
//! `window_ref` hashes binding them to HTF evaluation windows. Continuity
//! profiles are Ed25519-signed with domain separation to prevent
//! cross-protocol replay.
//!
//! # Projection Independence Invariant
//!
//! FAC authoritative progression MUST remain admissible during outage
//! scenarios bounded by `ProjectionContinuityWindowV1.outage_window_ref`.
//! Projection intents MUST be durably buffered and replayed idempotently
//! after sink recovery within `replay_window_ref`.

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use subtle::ConstantTimeEq;
use thiserror::Error;

use crate::crypto::{Hash, Signer, SignerError, parse_signature, parse_verifying_key};
use crate::fac::{sign_with_domain, verify_with_domain};
use crate::pcac::MAX_REASON_LENGTH;
use crate::pcac::temporal_arbitration::TemporalPredicateId;

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of sink identities in a snapshot.
pub const MAX_SINK_IDENTITIES: usize = 64;

/// Maximum number of scenario verdicts per continuity profile.
pub const MAX_SCENARIO_VERDICTS: usize = 256;

/// Maximum number of deferred replay receipts per evaluation.
pub const MAX_DEFERRED_REPLAY_RECEIPTS: usize = 256;

/// Maximum string length for sink identifiers.
pub const MAX_SINK_ID_LENGTH: usize = 256;

/// Maximum string length for scenario identifiers.
pub const MAX_SCENARIO_ID_LENGTH: usize = 256;

/// Maximum string length for receipt identifiers.
pub const MAX_RECEIPT_ID_LENGTH: usize = 256;

/// Maximum string length for boundary identifiers.
pub const MAX_BOUNDARY_ID_LENGTH: usize = 256;

/// Maximum string length for actor identifiers.
pub const MAX_ACTOR_ID_LENGTH: usize = 256;

/// Maximum string length for deny reason codes.
pub const MAX_DENY_REASON_LENGTH: usize = MAX_REASON_LENGTH;

/// Maximum backlog item count (deferred projection intent buffer bound).
pub const MAX_BACKLOG_ITEMS: usize = 65_536;

/// Maximum replay window ticks (approximately 1 day at 1MHz).
pub const MAX_REPLAY_WINDOW_TICKS: u64 = 86_400_000_000;

/// Maximum outage window ticks.
pub const MAX_OUTAGE_WINDOW_TICKS: u64 = 86_400_000_000;

/// Domain prefix for projection continuity window signing.
pub const CONTINUITY_WINDOW_SIGN_PREFIX: &[u8] = b"PROJECTION_CONTINUITY_WINDOW:";

/// Domain prefix for sink continuity profile signing.
pub const CONTINUITY_PROFILE_SIGN_PREFIX: &[u8] = b"PROJECTION_SINK_CONTINUITY_PROFILE:";

/// Domain prefix for deferred replay receipt signing.
pub const DEFERRED_REPLAY_RECEIPT_PREFIX: &[u8] = b"DEFERRED_REPLAY_RECEIPT:";

const ZERO_HASH: Hash = [0u8; 32];

// ============================================================================
// Deny reason constants (stable strings for replay verification)
// ============================================================================

/// Deny: continuity window is missing.
pub const DENY_CONTINUITY_WINDOW_MISSING: &str = "projection_continuity_window_missing";
/// Deny: continuity window outage window reference is zero.
pub const DENY_CONTINUITY_WINDOW_OUTAGE_REF_ZERO: &str =
    "projection_continuity_window_outage_ref_zero";
/// Deny: continuity window replay window reference is zero.
pub const DENY_CONTINUITY_WINDOW_REPLAY_REF_ZERO: &str =
    "projection_continuity_window_replay_ref_zero";
/// Deny: continuity window time authority reference is zero.
pub const DENY_CONTINUITY_WINDOW_TIME_AUTH_ZERO: &str =
    "projection_continuity_window_time_authority_ref_zero";
/// Deny: continuity window HTF window reference is zero.
pub const DENY_CONTINUITY_WINDOW_REF_ZERO: &str = "projection_continuity_window_ref_zero";
/// Deny: continuity window signature is invalid.
pub const DENY_CONTINUITY_WINDOW_SIGNATURE_INVALID: &str =
    "projection_continuity_window_signature_invalid";
/// Deny: continuity window signer key is zero.
pub const DENY_CONTINUITY_WINDOW_SIGNER_ZERO: &str = "projection_continuity_window_signer_key_zero";
/// Deny: continuity window signer is not in the trusted set.
pub const DENY_CONTINUITY_WINDOW_SIGNER_UNTRUSTED: &str =
    "projection_continuity_window_signer_untrusted";
/// Deny: continuity window ID is empty or oversized.
pub const DENY_CONTINUITY_WINDOW_ID_INVALID: &str = "projection_continuity_window_id_invalid";
/// Deny: continuity window boundary mismatch.
pub const DENY_CONTINUITY_WINDOW_BOUNDARY_MISMATCH: &str =
    "projection_continuity_window_boundary_mismatch";
/// Deny: continuity window time authority reference mismatch.
pub const DENY_CONTINUITY_WINDOW_TIME_AUTH_MISMATCH: &str =
    "projection_continuity_window_time_authority_ref_mismatch";
/// Deny: continuity window HTF window reference mismatch.
pub const DENY_CONTINUITY_WINDOW_REF_MISMATCH: &str = "projection_continuity_window_ref_mismatch";
/// Deny: outage window ticks exceed maximum.
pub const DENY_OUTAGE_WINDOW_TICKS_EXCEEDED: &str =
    "projection_continuity_outage_window_ticks_exceeded";
/// Deny: replay window ticks exceed maximum.
pub const DENY_REPLAY_WINDOW_TICKS_EXCEEDED: &str =
    "projection_continuity_replay_window_ticks_exceeded";
/// Deny: outage window tick range is invalid (start > end).
pub const DENY_OUTAGE_WINDOW_TICK_RANGE_INVALID: &str =
    "projection_continuity_outage_window_tick_range_invalid";
/// Deny: replay window tick range is invalid (start > end).
pub const DENY_REPLAY_WINDOW_TICK_RANGE_INVALID: &str =
    "projection_continuity_replay_window_tick_range_invalid";

/// Deny: sink continuity profile is missing.
pub const DENY_CONTINUITY_PROFILE_MISSING: &str = "projection_sink_continuity_profile_missing";
/// Deny: sink continuity profile signature is invalid.
pub const DENY_CONTINUITY_PROFILE_SIGNATURE_INVALID: &str =
    "projection_sink_continuity_profile_signature_invalid";
/// Deny: sink continuity profile signer key is zero.
pub const DENY_CONTINUITY_PROFILE_SIGNER_ZERO: &str =
    "projection_sink_continuity_profile_signer_key_zero";
/// Deny: sink continuity profile signer untrusted.
pub const DENY_CONTINUITY_PROFILE_SIGNER_UNTRUSTED: &str =
    "projection_sink_continuity_profile_signer_untrusted";
/// Deny: sink continuity profile ID is invalid.
pub const DENY_CONTINUITY_PROFILE_ID_INVALID: &str =
    "projection_sink_continuity_profile_id_invalid";
/// Deny: sink continuity profile has zero content hash.
pub const DENY_CONTINUITY_PROFILE_HASH_ZERO: &str = "projection_sink_continuity_profile_hash_zero";
/// Deny: sink continuity profile has no scenario verdicts.
pub const DENY_CONTINUITY_PROFILE_NO_SCENARIOS: &str =
    "projection_sink_continuity_profile_no_scenarios";
/// Deny: scenario verdict count exceeded.
pub const DENY_SCENARIO_VERDICTS_EXCEEDED: &str =
    "projection_continuity_scenario_verdicts_exceeded";
/// Deny: scenario failed truth-plane progression.
pub const DENY_SCENARIO_TRUTH_PLANE_HALT: &str = "projection_continuity_scenario_truth_plane_halt";
/// Deny: scenario backlog unbounded.
pub const DENY_SCENARIO_BACKLOG_UNBOUNDED: &str =
    "projection_continuity_scenario_backlog_unbounded";
/// Deny: scenario verdict is unknown/unresolved.
pub const DENY_SCENARIO_VERDICT_UNKNOWN: &str = "projection_continuity_scenario_verdict_unknown";
/// Deny: scenario ID is empty or oversized.
pub const DENY_SCENARIO_ID_INVALID: &str = "projection_continuity_scenario_id_invalid";
/// Deny: scenario digest is zero.
pub const DENY_SCENARIO_DIGEST_ZERO: &str = "projection_continuity_scenario_digest_zero";

/// Deny: sink identity snapshot is missing.
pub const DENY_SINK_SNAPSHOT_MISSING: &str = "projection_sink_identity_snapshot_missing";
/// Deny: sink identity count exceeded.
pub const DENY_SINK_IDENTITIES_EXCEEDED: &str = "projection_sink_identities_exceeded";
/// Deny: sink snapshot has no sinks.
pub const DENY_SINK_SNAPSHOT_EMPTY: &str = "projection_sink_identity_snapshot_empty";
/// Deny: sink identity digest is zero.
pub const DENY_SINK_IDENTITY_DIGEST_ZERO: &str = "projection_sink_identity_digest_zero";
/// Deny: sink ID is empty or oversized.
pub const DENY_SINK_ID_INVALID: &str = "projection_sink_id_invalid";
/// Deny: sink snapshot digest is zero.
pub const DENY_SINK_SNAPSHOT_DIGEST_ZERO: &str = "projection_sink_identity_snapshot_digest_zero";

/// Deny: deferred replay receipt is missing.
pub const DENY_DEFERRED_REPLAY_RECEIPT_MISSING: &str = "projection_deferred_replay_receipt_missing";
/// Deny: deferred replay receipt has zero content hash.
pub const DENY_DEFERRED_REPLAY_RECEIPT_HASH_ZERO: &str =
    "projection_deferred_replay_receipt_hash_zero";
/// Deny: deferred replay receipt signature is invalid.
pub const DENY_DEFERRED_REPLAY_RECEIPT_SIGNATURE_INVALID: &str =
    "projection_deferred_replay_receipt_signature_invalid";
/// Deny: deferred replay receipt signer key is zero.
pub const DENY_DEFERRED_REPLAY_RECEIPT_SIGNER_ZERO: &str =
    "projection_deferred_replay_receipt_signer_key_zero";
/// Deny: deferred replay receipt signer untrusted.
pub const DENY_DEFERRED_REPLAY_RECEIPT_SIGNER_UNTRUSTED: &str =
    "projection_deferred_replay_receipt_signer_untrusted";
/// Deny: deferred replay receipt ID is invalid.
pub const DENY_DEFERRED_REPLAY_RECEIPT_ID_INVALID: &str =
    "projection_deferred_replay_receipt_id_invalid";
/// Deny: deferred replay receipt boundary mismatch.
pub const DENY_DEFERRED_REPLAY_RECEIPT_BOUNDARY_MISMATCH: &str =
    "projection_deferred_replay_receipt_boundary_mismatch";
/// Deny: deferred replay receipt time authority mismatch.
pub const DENY_DEFERRED_REPLAY_RECEIPT_TIME_AUTH_MISMATCH: &str =
    "projection_deferred_replay_receipt_time_authority_ref_mismatch";
/// Deny: deferred replay receipt window reference mismatch.
pub const DENY_DEFERRED_REPLAY_RECEIPT_WINDOW_MISMATCH: &str =
    "projection_deferred_replay_receipt_window_ref_mismatch";
/// Deny: deferred replay did not converge.
pub const DENY_DEFERRED_REPLAY_NOT_CONVERGED: &str = "projection_deferred_replay_not_converged";
/// Deny: backlog exceeds retention envelope.
pub const DENY_BACKLOG_EXCEEDS_RETENTION: &str = "projection_continuity_backlog_exceeds_retention";
/// Deny: backlog item count exceeds hard cap.
pub const DENY_BACKLOG_ITEMS_EXCEEDED: &str = "projection_continuity_backlog_items_exceeded";
/// Deny: deferred replay receipts exceeded maximum count.
pub const DENY_DEFERRED_REPLAY_RECEIPTS_EXCEEDED: &str =
    "projection_deferred_replay_receipts_exceeded";
/// Deny: duplicate deferred replay receipt ID.
pub const DENY_DEFERRED_REPLAY_RECEIPT_DUPLICATE_ID: &str =
    "projection_deferred_replay_receipt_duplicate_id";
/// Deny: unknown temporal state in continuity evaluation.
pub const DENY_UNKNOWN_TEMPORAL_STATE: &str = "projection_continuity_unknown_temporal_state";
/// Deny: continuity profile boundary mismatch.
pub const DENY_CONTINUITY_PROFILE_BOUNDARY_MISMATCH: &str =
    "projection_sink_continuity_profile_boundary_mismatch";
/// Deny: continuity profile time authority reference mismatch.
pub const DENY_CONTINUITY_PROFILE_TIME_AUTH_MISMATCH: &str =
    "projection_sink_continuity_profile_time_authority_ref_mismatch";
/// Deny: continuity profile window reference mismatch.
pub const DENY_CONTINUITY_PROFILE_WINDOW_MISMATCH: &str =
    "projection_sink_continuity_profile_window_ref_mismatch";
/// Deny: deferred replay receipt backlog digest mismatch.
pub const DENY_DEFERRED_REPLAY_RECEIPT_BACKLOG_MISMATCH: &str =
    "projection_deferred_replay_receipt_backlog_digest_mismatch";
/// Deny: continuity window content hash is zero.
pub const DENY_CONTINUITY_WINDOW_HASH_ZERO: &str = "projection_continuity_window_content_hash_zero";

// ============================================================================
// Bounded serde helpers (OOM-safe deserialization)
// ============================================================================

/// Deserializes a `String` with a hard length bound to prevent OOM during
/// deserialization from untrusted input.
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
                Ok(value)
            }
        }
    }

    deserializer.deserialize_string(BoundedStringVisitor {
        max_len,
        field_name,
    })
}

/// Deserializes a `Vec<T>` with a hard item-count bound.
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
            A: de::SeqAccess<'de>,
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

fn deser_window_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_string(deserializer, MAX_RECEIPT_ID_LENGTH, "window_id")
}

fn deser_profile_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_string(deserializer, MAX_RECEIPT_ID_LENGTH, "profile_id")
}

fn deser_receipt_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_string(deserializer, MAX_RECEIPT_ID_LENGTH, "receipt_id")
}

fn deser_boundary_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_string(deserializer, MAX_BOUNDARY_ID_LENGTH, "boundary_id")
}

fn deser_signer_actor_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_string(deserializer, MAX_ACTOR_ID_LENGTH, "signer_actor_id")
}

fn deser_scenario_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_string(deserializer, MAX_SCENARIO_ID_LENGTH, "scenario_id")
}

fn deser_sink_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_string(deserializer, MAX_SINK_ID_LENGTH, "sink_id")
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

fn deser_scenario_verdicts<'de, D>(
    deserializer: D,
) -> Result<Vec<ContinuityScenarioVerdict>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec(deserializer, MAX_SCENARIO_VERDICTS, "scenario_verdicts")
}

fn deser_sink_identities<'de, D>(deserializer: D) -> Result<Vec<SinkIdentityEntry>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec(deserializer, MAX_SINK_IDENTITIES, "sink_identities")
}

// ============================================================================
// Error types
// ============================================================================

/// Errors from projection continuity operations.
#[derive(Debug, Error)]
pub enum ProjectionContinuityError {
    /// Field validation failed.
    #[error("continuity validation: {reason}")]
    ValidationFailed {
        /// Human-readable description.
        reason: String,
    },
    /// Signature creation or verification failed.
    #[error("signature error: {detail}")]
    SignatureError {
        /// Details of the signature failure.
        detail: String,
    },
    /// A required field is missing or empty.
    #[error("required field missing: {field}")]
    RequiredFieldMissing {
        /// Name of the missing field.
        field: String,
    },
    /// A field value exceeds its maximum allowed length.
    #[error("field '{field}' exceeds maximum length ({actual} > {max})")]
    FieldTooLong {
        /// Name of the violating field.
        field: String,
        /// Actual length observed.
        actual: usize,
        /// Maximum allowed length.
        max: usize,
    },
    /// A hash field is zero.
    #[error("field '{field}' must not be zero")]
    ZeroHash {
        /// Name of the violating field.
        field: String,
    },
    /// Collection exceeds capacity.
    #[error("collection '{collection}' exceeds capacity ({count} > {max})")]
    CollectionExceeded {
        /// Collection name.
        collection: String,
        /// Current count.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },
}

// ============================================================================
// ProjectionContinuityWindowV1
// ============================================================================

/// Signed declaration of outage and replay windows for projection continuity.
///
/// Implements `ProjectionContinuityWindowV1` from RFC-0029 REQ-0009.
/// Binds outage and replay window tick ranges to a specific time authority
/// and HTF evaluation window via Ed25519 domain-separated signature.
///
/// # Fields
///
/// - `window_id`: unique identifier for this window declaration.
/// - `boundary_id`: boundary context (must match evaluation window).
/// - `outage_window_start`: start tick of the declared outage window.
/// - `outage_window_end`: end tick of the declared outage window.
/// - `replay_window_start`: start tick of the declared replay window.
/// - `replay_window_end`: end tick of the declared replay window.
/// - `outage_window_ref`: hash binding of the outage window declaration.
/// - `replay_window_ref`: hash binding of the replay window declaration.
/// - `time_authority_ref`: hash of the time authority envelope.
/// - `window_ref`: hash of the HTF evaluation window.
/// - `content_hash`: content-addressed hash of the window payload.
/// - `signer_actor_id`: identity of the signing actor.
/// - `signer_key`: Ed25519 public key bytes.
/// - `signature`: Ed25519 signature over domain-separated canonical bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionContinuityWindowV1 {
    /// Unique window declaration identifier.
    #[serde(deserialize_with = "deser_window_id")]
    pub window_id: String,
    /// Boundary identifier (must match evaluation context).
    #[serde(deserialize_with = "deser_boundary_id")]
    pub boundary_id: String,
    /// Start tick of the declared outage window.
    pub outage_window_start: u64,
    /// End tick of the declared outage window (inclusive).
    pub outage_window_end: u64,
    /// Start tick of the declared replay window.
    pub replay_window_start: u64,
    /// End tick of the declared replay window (inclusive).
    pub replay_window_end: u64,
    /// Hash binding of the outage window declaration.
    pub outage_window_ref: Hash,
    /// Hash binding of the replay window declaration.
    pub replay_window_ref: Hash,
    /// Time authority reference hash (HTF binding).
    pub time_authority_ref: Hash,
    /// HTF evaluation window reference hash.
    pub window_ref: Hash,
    /// Content-addressed hash of the window payload.
    pub content_hash: Hash,
    /// Identity of the signing actor.
    #[serde(deserialize_with = "deser_signer_actor_id")]
    pub signer_actor_id: String,
    /// Ed25519 public key of the signer (32 bytes).
    #[serde(with = "serde_bytes")]
    pub signer_key: [u8; 32],
    /// Ed25519 signature over domain-separated canonical bytes (64 bytes).
    #[serde(with = "serde_bytes")]
    pub signature: [u8; 64],
}

impl ProjectionContinuityWindowV1 {
    /// Creates and signs a projection continuity window declaration.
    ///
    /// # Errors
    ///
    /// Returns an error if any field fails validation or signing fails.
    #[allow(clippy::too_many_arguments)]
    pub fn create_signed(
        window_id: &str,
        boundary_id: &str,
        outage_window_start: u64,
        outage_window_end: u64,
        replay_window_start: u64,
        replay_window_end: u64,
        outage_window_ref: Hash,
        replay_window_ref: Hash,
        time_authority_ref: Hash,
        window_ref: Hash,
        content_hash: Hash,
        signer_actor_id: &str,
        signer: &Signer,
    ) -> Result<Self, ProjectionContinuityError> {
        validate_required_string("window_id", window_id, MAX_RECEIPT_ID_LENGTH)?;
        validate_required_string("boundary_id", boundary_id, MAX_BOUNDARY_ID_LENGTH)?;
        validate_required_string("signer_actor_id", signer_actor_id, MAX_ACTOR_ID_LENGTH)?;
        validate_non_zero_hash("outage_window_ref", &outage_window_ref)?;
        validate_non_zero_hash("replay_window_ref", &replay_window_ref)?;
        validate_non_zero_hash("time_authority_ref", &time_authority_ref)?;
        validate_non_zero_hash("window_ref", &window_ref)?;
        validate_non_zero_hash("content_hash", &content_hash)?;

        if outage_window_start > outage_window_end {
            return Err(ProjectionContinuityError::ValidationFailed {
                reason: DENY_OUTAGE_WINDOW_TICK_RANGE_INVALID.to_string(),
            });
        }
        if replay_window_start > replay_window_end {
            return Err(ProjectionContinuityError::ValidationFailed {
                reason: DENY_REPLAY_WINDOW_TICK_RANGE_INVALID.to_string(),
            });
        }

        let outage_span = outage_window_end.saturating_sub(outage_window_start);
        if outage_span > MAX_OUTAGE_WINDOW_TICKS {
            return Err(ProjectionContinuityError::ValidationFailed {
                reason: DENY_OUTAGE_WINDOW_TICKS_EXCEEDED.to_string(),
            });
        }

        let replay_span = replay_window_end.saturating_sub(replay_window_start);
        if replay_span > MAX_REPLAY_WINDOW_TICKS {
            return Err(ProjectionContinuityError::ValidationFailed {
                reason: DENY_REPLAY_WINDOW_TICKS_EXCEEDED.to_string(),
            });
        }

        let mut window = Self {
            window_id: window_id.to_string(),
            boundary_id: boundary_id.to_string(),
            outage_window_start,
            outage_window_end,
            replay_window_start,
            replay_window_end,
            outage_window_ref,
            replay_window_ref,
            time_authority_ref,
            window_ref,
            content_hash,
            signer_actor_id: signer_actor_id.to_string(),
            signer_key: signer.public_key_bytes(),
            signature: [0u8; 64],
        };

        let sig = sign_with_domain(
            signer,
            CONTINUITY_WINDOW_SIGN_PREFIX,
            &window.canonical_bytes(),
        );
        window.signature = sig.to_bytes();
        Ok(window)
    }

    /// Returns canonical bytes for signing/verification.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        // Fixed-size fields: 6 * 8 (ticks) + 5 * 32 (hashes) = 48 + 160 = 208
        // Three length-prefixed strings: 3 * 4 = 12 bytes of length headers
        let estimated_size =
            208 + 12 + self.window_id.len() + self.boundary_id.len() + self.signer_actor_id.len();
        let mut bytes = Vec::with_capacity(estimated_size);

        bytes.extend_from_slice(&(self.window_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.window_id.as_bytes());

        bytes.extend_from_slice(&(self.boundary_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.boundary_id.as_bytes());

        bytes.extend_from_slice(&self.outage_window_start.to_be_bytes());
        bytes.extend_from_slice(&self.outage_window_end.to_be_bytes());
        bytes.extend_from_slice(&self.replay_window_start.to_be_bytes());
        bytes.extend_from_slice(&self.replay_window_end.to_be_bytes());

        bytes.extend_from_slice(&self.outage_window_ref);
        bytes.extend_from_slice(&self.replay_window_ref);
        bytes.extend_from_slice(&self.time_authority_ref);
        bytes.extend_from_slice(&self.window_ref);
        bytes.extend_from_slice(&self.content_hash);

        bytes.extend_from_slice(&(self.signer_actor_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.signer_actor_id.as_bytes());

        bytes
    }

    /// Verifies the window's Ed25519 signature.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature is invalid.
    pub fn verify_signature(&self) -> Result<(), ProjectionContinuityError> {
        if self.signer_key == [0u8; 32] {
            return Err(ProjectionContinuityError::SignatureError {
                detail: DENY_CONTINUITY_WINDOW_SIGNER_ZERO.to_string(),
            });
        }

        let key = parse_verifying_key(&self.signer_key).map_err(|e: SignerError| {
            ProjectionContinuityError::SignatureError {
                detail: e.to_string(),
            }
        })?;

        let sig = parse_signature(&self.signature).map_err(|e: SignerError| {
            ProjectionContinuityError::SignatureError {
                detail: e.to_string(),
            }
        })?;

        verify_with_domain(
            &key,
            CONTINUITY_WINDOW_SIGN_PREFIX,
            &self.canonical_bytes(),
            &sig,
        )
        .map_err(|e: SignerError| ProjectionContinuityError::SignatureError {
            detail: e.to_string(),
        })
    }

    /// Validates structural invariants without verifying the signature.
    ///
    /// # Errors
    ///
    /// Returns a stable deny reason for any structural violation.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.window_id.is_empty() || self.window_id.len() > MAX_RECEIPT_ID_LENGTH {
            return Err(DENY_CONTINUITY_WINDOW_ID_INVALID);
        }
        if self.boundary_id.is_empty() || self.boundary_id.len() > MAX_BOUNDARY_ID_LENGTH {
            return Err(DENY_CONTINUITY_WINDOW_BOUNDARY_MISMATCH);
        }
        if is_zero_hash(&self.outage_window_ref) {
            return Err(DENY_CONTINUITY_WINDOW_OUTAGE_REF_ZERO);
        }
        if is_zero_hash(&self.replay_window_ref) {
            return Err(DENY_CONTINUITY_WINDOW_REPLAY_REF_ZERO);
        }
        if is_zero_hash(&self.time_authority_ref) {
            return Err(DENY_CONTINUITY_WINDOW_TIME_AUTH_ZERO);
        }
        if is_zero_hash(&self.window_ref) {
            return Err(DENY_CONTINUITY_WINDOW_REF_ZERO);
        }
        if is_zero_hash(&self.content_hash) {
            return Err(DENY_CONTINUITY_WINDOW_HASH_ZERO);
        }
        if self.signer_key == [0u8; 32] {
            return Err(DENY_CONTINUITY_WINDOW_SIGNER_ZERO);
        }
        if self.signature.ct_eq(&[0u8; 64]).unwrap_u8() == 1 {
            return Err(DENY_CONTINUITY_WINDOW_SIGNATURE_INVALID);
        }
        if self.outage_window_start > self.outage_window_end {
            return Err(DENY_OUTAGE_WINDOW_TICK_RANGE_INVALID);
        }
        if self.replay_window_start > self.replay_window_end {
            return Err(DENY_REPLAY_WINDOW_TICK_RANGE_INVALID);
        }
        Ok(())
    }
}

// ============================================================================
// ContinuityScenarioVerdict
// ============================================================================

/// Per-scenario verdict from a multi-sink outage/churn/partition drill.
///
/// Each verdict attests whether authoritative truth-plane progression
/// continued and whether projection backlog remained bounded during the
/// scenario.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuityScenarioVerdict {
    /// Unique scenario identifier.
    #[serde(deserialize_with = "deser_scenario_id")]
    pub scenario_id: String,
    /// Digest of the scenario parameters.
    pub scenario_digest: Hash,
    /// Whether authoritative truth-plane progression continued.
    pub truth_plane_continued: bool,
    /// Whether projection backlog remained bounded.
    pub backlog_bounded: bool,
    /// Maximum backlog items observed during the scenario.
    pub max_backlog_items: u64,
}

impl ContinuityScenarioVerdict {
    /// Validates structural invariants of this verdict.
    ///
    /// # Errors
    ///
    /// Returns a stable deny reason for any structural violation.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.scenario_id.is_empty() || self.scenario_id.len() > MAX_SCENARIO_ID_LENGTH {
            return Err(DENY_SCENARIO_ID_INVALID);
        }
        if is_zero_hash(&self.scenario_digest) {
            return Err(DENY_SCENARIO_DIGEST_ZERO);
        }
        Ok(())
    }
}

// ============================================================================
// ProjectionSinkContinuityProfileV1
// ============================================================================

/// Signed profile declaring scenario verdicts for projection sink continuity.
///
/// Implements `ProjectionSinkContinuityProfileV1` from RFC-0029 REQ-0009.
/// Each profile is domain-separated and Ed25519-signed, binding scenario
/// verdicts to a specific time authority and evaluation window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionSinkContinuityProfileV1 {
    /// Unique profile identifier.
    #[serde(deserialize_with = "deser_profile_id")]
    pub profile_id: String,
    /// Boundary identifier (must match evaluation context).
    #[serde(deserialize_with = "deser_boundary_id")]
    pub boundary_id: String,
    /// Scenario verdicts from outage/churn/partition drills.
    #[serde(deserialize_with = "deser_scenario_verdicts")]
    pub scenario_verdicts: Vec<ContinuityScenarioVerdict>,
    /// Digest of the sink identity snapshot used for scenario generation.
    pub sink_snapshot_digest: Hash,
    /// Time authority reference hash (HTF binding).
    pub time_authority_ref: Hash,
    /// HTF evaluation window reference hash.
    pub window_ref: Hash,
    /// Content-addressed hash of the profile payload.
    pub content_hash: Hash,
    /// Identity of the signing actor.
    #[serde(deserialize_with = "deser_signer_actor_id")]
    pub signer_actor_id: String,
    /// Ed25519 public key of the signer (32 bytes).
    #[serde(with = "serde_bytes")]
    pub signer_key: [u8; 32],
    /// Ed25519 signature over domain-separated canonical bytes (64 bytes).
    #[serde(with = "serde_bytes")]
    pub signature: [u8; 64],
}

impl ProjectionSinkContinuityProfileV1 {
    /// Creates and signs a sink continuity profile.
    ///
    /// # Errors
    ///
    /// Returns an error if any field fails validation or signing fails.
    #[allow(clippy::too_many_arguments)]
    pub fn create_signed(
        profile_id: &str,
        boundary_id: &str,
        scenario_verdicts: Vec<ContinuityScenarioVerdict>,
        sink_snapshot_digest: Hash,
        time_authority_ref: Hash,
        window_ref: Hash,
        content_hash: Hash,
        signer_actor_id: &str,
        signer: &Signer,
    ) -> Result<Self, ProjectionContinuityError> {
        validate_required_string("profile_id", profile_id, MAX_RECEIPT_ID_LENGTH)?;
        validate_required_string("boundary_id", boundary_id, MAX_BOUNDARY_ID_LENGTH)?;
        validate_required_string("signer_actor_id", signer_actor_id, MAX_ACTOR_ID_LENGTH)?;
        validate_non_zero_hash("sink_snapshot_digest", &sink_snapshot_digest)?;
        validate_non_zero_hash("time_authority_ref", &time_authority_ref)?;
        validate_non_zero_hash("window_ref", &window_ref)?;
        validate_non_zero_hash("content_hash", &content_hash)?;

        if scenario_verdicts.is_empty() {
            return Err(ProjectionContinuityError::ValidationFailed {
                reason: DENY_CONTINUITY_PROFILE_NO_SCENARIOS.to_string(),
            });
        }

        if scenario_verdicts.len() > MAX_SCENARIO_VERDICTS {
            return Err(ProjectionContinuityError::CollectionExceeded {
                collection: "scenario_verdicts".to_string(),
                count: scenario_verdicts.len(),
                max: MAX_SCENARIO_VERDICTS,
            });
        }

        // Validate each scenario verdict.
        for v in &scenario_verdicts {
            v.validate()
                .map_err(|reason| ProjectionContinuityError::ValidationFailed {
                    reason: reason.to_string(),
                })?;
        }

        let mut profile = Self {
            profile_id: profile_id.to_string(),
            boundary_id: boundary_id.to_string(),
            scenario_verdicts,
            sink_snapshot_digest,
            time_authority_ref,
            window_ref,
            content_hash,
            signer_actor_id: signer_actor_id.to_string(),
            signer_key: signer.public_key_bytes(),
            signature: [0u8; 64],
        };

        let sig = sign_with_domain(
            signer,
            CONTINUITY_PROFILE_SIGN_PREFIX,
            &profile.canonical_bytes(),
        );
        profile.signature = sig.to_bytes();
        Ok(profile)
    }

    /// Returns canonical bytes for signing/verification.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        // Fixed-size: sink_snapshot_digest(32) + time_authority_ref(32) +
        // window_ref(32) + content_hash(32) = 128
        // 3 length-prefixed strings + scenario count (4 bytes)
        let scenario_size: usize = self
            .scenario_verdicts
            .iter()
            .map(|v| 4 + v.scenario_id.len() + 32 + 1 + 1 + 8)
            .sum();
        let estimated_size = 128
            + 16
            + self.profile_id.len()
            + self.boundary_id.len()
            + self.signer_actor_id.len()
            + scenario_size;
        let mut bytes = Vec::with_capacity(estimated_size);

        bytes.extend_from_slice(&(self.profile_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.profile_id.as_bytes());

        bytes.extend_from_slice(&(self.boundary_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.boundary_id.as_bytes());

        // Scenario count + verdicts.
        bytes.extend_from_slice(&(self.scenario_verdicts.len() as u32).to_be_bytes());
        for v in &self.scenario_verdicts {
            bytes.extend_from_slice(&(v.scenario_id.len() as u32).to_be_bytes());
            bytes.extend_from_slice(v.scenario_id.as_bytes());
            bytes.extend_from_slice(&v.scenario_digest);
            bytes.push(u8::from(v.truth_plane_continued));
            bytes.push(u8::from(v.backlog_bounded));
            bytes.extend_from_slice(&v.max_backlog_items.to_be_bytes());
        }

        bytes.extend_from_slice(&self.sink_snapshot_digest);
        bytes.extend_from_slice(&self.time_authority_ref);
        bytes.extend_from_slice(&self.window_ref);
        bytes.extend_from_slice(&self.content_hash);

        bytes.extend_from_slice(&(self.signer_actor_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.signer_actor_id.as_bytes());

        bytes
    }

    /// Verifies the profile's Ed25519 signature.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature is invalid.
    pub fn verify_signature(&self) -> Result<(), ProjectionContinuityError> {
        if self.signer_key == [0u8; 32] {
            return Err(ProjectionContinuityError::SignatureError {
                detail: DENY_CONTINUITY_PROFILE_SIGNER_ZERO.to_string(),
            });
        }

        let key = parse_verifying_key(&self.signer_key).map_err(|e: SignerError| {
            ProjectionContinuityError::SignatureError {
                detail: e.to_string(),
            }
        })?;

        let sig = parse_signature(&self.signature).map_err(|e: SignerError| {
            ProjectionContinuityError::SignatureError {
                detail: e.to_string(),
            }
        })?;

        verify_with_domain(
            &key,
            CONTINUITY_PROFILE_SIGN_PREFIX,
            &self.canonical_bytes(),
            &sig,
        )
        .map_err(|e: SignerError| ProjectionContinuityError::SignatureError {
            detail: e.to_string(),
        })
    }

    /// Validates structural invariants without verifying the signature.
    ///
    /// # Errors
    ///
    /// Returns a stable deny reason for any structural violation.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.profile_id.is_empty() || self.profile_id.len() > MAX_RECEIPT_ID_LENGTH {
            return Err(DENY_CONTINUITY_PROFILE_ID_INVALID);
        }
        if self.boundary_id.is_empty() || self.boundary_id.len() > MAX_BOUNDARY_ID_LENGTH {
            return Err(DENY_CONTINUITY_PROFILE_BOUNDARY_MISMATCH);
        }
        if is_zero_hash(&self.content_hash) {
            return Err(DENY_CONTINUITY_PROFILE_HASH_ZERO);
        }
        if is_zero_hash(&self.time_authority_ref) {
            return Err(DENY_CONTINUITY_WINDOW_TIME_AUTH_ZERO);
        }
        if is_zero_hash(&self.window_ref) {
            return Err(DENY_CONTINUITY_WINDOW_REF_ZERO);
        }
        if is_zero_hash(&self.sink_snapshot_digest) {
            return Err(DENY_SINK_SNAPSHOT_DIGEST_ZERO);
        }
        if self.signer_key == [0u8; 32] {
            return Err(DENY_CONTINUITY_PROFILE_SIGNER_ZERO);
        }
        if self.signature.ct_eq(&[0u8; 64]).unwrap_u8() == 1 {
            return Err(DENY_CONTINUITY_PROFILE_SIGNATURE_INVALID);
        }
        if self.scenario_verdicts.is_empty() {
            return Err(DENY_CONTINUITY_PROFILE_NO_SCENARIOS);
        }
        if self.scenario_verdicts.len() > MAX_SCENARIO_VERDICTS {
            return Err(DENY_SCENARIO_VERDICTS_EXCEEDED);
        }
        for v in &self.scenario_verdicts {
            v.validate()?;
        }
        Ok(())
    }
}

// ============================================================================
// SinkIdentitySnapshotV1
// ============================================================================

/// A single sink identity entry in the snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SinkIdentityEntry {
    /// Unique sink identifier.
    #[serde(deserialize_with = "deser_sink_id")]
    pub sink_id: String,
    /// Digest of the sink's identity material.
    pub identity_digest: Hash,
}

/// Snapshot of projection sink identities used for scenario generation.
///
/// Implements `SinkIdentitySnapshotV1` from RFC-0029 REQ-0009.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SinkIdentitySnapshotV1 {
    /// Sink identities.
    #[serde(deserialize_with = "deser_sink_identities")]
    pub sink_identities: Vec<SinkIdentityEntry>,
    /// Content-addressed digest of the snapshot.
    pub snapshot_digest: Hash,
}

impl SinkIdentitySnapshotV1 {
    /// Validates structural invariants.
    ///
    /// # Errors
    ///
    /// Returns a stable deny reason for any structural violation.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.sink_identities.is_empty() {
            return Err(DENY_SINK_SNAPSHOT_EMPTY);
        }
        if self.sink_identities.len() > MAX_SINK_IDENTITIES {
            return Err(DENY_SINK_IDENTITIES_EXCEEDED);
        }
        if is_zero_hash(&self.snapshot_digest) {
            return Err(DENY_SINK_SNAPSHOT_DIGEST_ZERO);
        }
        for entry in &self.sink_identities {
            if entry.sink_id.is_empty() || entry.sink_id.len() > MAX_SINK_ID_LENGTH {
                return Err(DENY_SINK_ID_INVALID);
            }
            if is_zero_hash(&entry.identity_digest) {
                return Err(DENY_SINK_IDENTITY_DIGEST_ZERO);
            }
        }
        Ok(())
    }
}

// ============================================================================
// DeferredReplayReceiptV1
// ============================================================================

/// Signed receipt proving deferred replay convergence after sink recovery.
///
/// Proves that projection intents were durably buffered and replayed
/// idempotently after sink recovery within the declared replay window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeferredReplayReceiptV1 {
    /// Unique receipt identifier.
    #[serde(deserialize_with = "deser_receipt_id")]
    pub receipt_id: String,
    /// Boundary identifier (must match evaluation context).
    #[serde(deserialize_with = "deser_boundary_id")]
    pub boundary_id: String,
    /// Digest of the backlog state at convergence evaluation.
    pub backlog_digest: Hash,
    /// Number of deferred items replayed.
    pub replayed_item_count: u64,
    /// Tick marking the end of the replay convergence horizon.
    pub replay_horizon_tick: u64,
    /// Whether replay converged idempotently within the replay window.
    pub converged: bool,
    /// Time authority reference hash (HTF binding).
    pub time_authority_ref: Hash,
    /// HTF evaluation window reference hash.
    pub window_ref: Hash,
    /// Content-addressed hash of the receipt payload.
    pub content_hash: Hash,
    /// Identity of the signing actor.
    #[serde(deserialize_with = "deser_signer_actor_id")]
    pub signer_actor_id: String,
    /// Ed25519 public key of the signer (32 bytes).
    #[serde(with = "serde_bytes")]
    pub signer_key: [u8; 32],
    /// Ed25519 signature over domain-separated canonical bytes (64 bytes).
    #[serde(with = "serde_bytes")]
    pub signature: [u8; 64],
}

impl DeferredReplayReceiptV1 {
    /// Creates and signs a deferred replay receipt.
    ///
    /// # Errors
    ///
    /// Returns an error if any field fails validation or signing fails.
    #[allow(clippy::too_many_arguments)]
    pub fn create_signed(
        receipt_id: &str,
        boundary_id: &str,
        backlog_digest: Hash,
        replayed_item_count: u64,
        replay_horizon_tick: u64,
        converged: bool,
        time_authority_ref: Hash,
        window_ref: Hash,
        content_hash: Hash,
        signer_actor_id: &str,
        signer: &Signer,
    ) -> Result<Self, ProjectionContinuityError> {
        validate_required_string("receipt_id", receipt_id, MAX_RECEIPT_ID_LENGTH)?;
        validate_required_string("boundary_id", boundary_id, MAX_BOUNDARY_ID_LENGTH)?;
        validate_required_string("signer_actor_id", signer_actor_id, MAX_ACTOR_ID_LENGTH)?;
        validate_non_zero_hash("backlog_digest", &backlog_digest)?;
        validate_non_zero_hash("time_authority_ref", &time_authority_ref)?;
        validate_non_zero_hash("window_ref", &window_ref)?;
        validate_non_zero_hash("content_hash", &content_hash)?;

        let mut receipt = Self {
            receipt_id: receipt_id.to_string(),
            boundary_id: boundary_id.to_string(),
            backlog_digest,
            replayed_item_count,
            replay_horizon_tick,
            converged,
            time_authority_ref,
            window_ref,
            content_hash,
            signer_actor_id: signer_actor_id.to_string(),
            signer_key: signer.public_key_bytes(),
            signature: [0u8; 64],
        };

        let sig = sign_with_domain(
            signer,
            DEFERRED_REPLAY_RECEIPT_PREFIX,
            &receipt.canonical_bytes(),
        );
        receipt.signature = sig.to_bytes();
        Ok(receipt)
    }

    /// Returns canonical bytes for signing/verification.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        // Fixed-size: backlog_digest(32) + replayed_item_count(8) +
        // replay_horizon_tick(8) + converged(1) + time_authority_ref(32) +
        // window_ref(32) + content_hash(32) = 145
        // 3 length-prefixed strings: 3 * 4 = 12
        let estimated_size =
            145 + 12 + self.receipt_id.len() + self.boundary_id.len() + self.signer_actor_id.len();
        let mut bytes = Vec::with_capacity(estimated_size);

        bytes.extend_from_slice(&(self.receipt_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.receipt_id.as_bytes());

        bytes.extend_from_slice(&(self.boundary_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.boundary_id.as_bytes());

        bytes.extend_from_slice(&self.backlog_digest);
        bytes.extend_from_slice(&self.replayed_item_count.to_be_bytes());
        bytes.extend_from_slice(&self.replay_horizon_tick.to_be_bytes());
        bytes.push(u8::from(self.converged));
        bytes.extend_from_slice(&self.time_authority_ref);
        bytes.extend_from_slice(&self.window_ref);
        bytes.extend_from_slice(&self.content_hash);

        bytes.extend_from_slice(&(self.signer_actor_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.signer_actor_id.as_bytes());

        bytes
    }

    /// Verifies the receipt's Ed25519 signature.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature is invalid.
    pub fn verify_signature(&self) -> Result<(), ProjectionContinuityError> {
        if self.signer_key == [0u8; 32] {
            return Err(ProjectionContinuityError::SignatureError {
                detail: DENY_DEFERRED_REPLAY_RECEIPT_SIGNER_ZERO.to_string(),
            });
        }

        let key = parse_verifying_key(&self.signer_key).map_err(|e: SignerError| {
            ProjectionContinuityError::SignatureError {
                detail: e.to_string(),
            }
        })?;

        let sig = parse_signature(&self.signature).map_err(|e: SignerError| {
            ProjectionContinuityError::SignatureError {
                detail: e.to_string(),
            }
        })?;

        verify_with_domain(
            &key,
            DEFERRED_REPLAY_RECEIPT_PREFIX,
            &self.canonical_bytes(),
            &sig,
        )
        .map_err(|e: SignerError| ProjectionContinuityError::SignatureError {
            detail: e.to_string(),
        })
    }

    /// Validates structural invariants without verifying the signature.
    ///
    /// # Errors
    ///
    /// Returns a stable deny reason for any structural violation.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.receipt_id.is_empty() || self.receipt_id.len() > MAX_RECEIPT_ID_LENGTH {
            return Err(DENY_DEFERRED_REPLAY_RECEIPT_ID_INVALID);
        }
        if self.boundary_id.is_empty() || self.boundary_id.len() > MAX_BOUNDARY_ID_LENGTH {
            return Err(DENY_DEFERRED_REPLAY_RECEIPT_BOUNDARY_MISMATCH);
        }
        if is_zero_hash(&self.time_authority_ref) {
            return Err(DENY_CONTINUITY_WINDOW_TIME_AUTH_ZERO);
        }
        if is_zero_hash(&self.window_ref) {
            return Err(DENY_CONTINUITY_WINDOW_REF_ZERO);
        }
        if is_zero_hash(&self.content_hash) {
            return Err(DENY_DEFERRED_REPLAY_RECEIPT_HASH_ZERO);
        }
        if is_zero_hash(&self.backlog_digest) {
            return Err(DENY_DEFERRED_REPLAY_RECEIPT_HASH_ZERO);
        }
        if self.signer_key == [0u8; 32] {
            return Err(DENY_DEFERRED_REPLAY_RECEIPT_SIGNER_ZERO);
        }
        if self.signature.ct_eq(&[0u8; 64]).unwrap_u8() == 1 {
            return Err(DENY_DEFERRED_REPLAY_RECEIPT_SIGNATURE_INVALID);
        }
        Ok(())
    }
}

// ============================================================================
// Deny defect
// ============================================================================

/// Deny defect emitted when a projection continuity admission check fails.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuityDenyDefect {
    /// Stable deny reason code.
    #[serde(deserialize_with = "deser_deny_reason")]
    pub reason: String,
    /// The temporal predicate that was violated.
    pub predicate_id: TemporalPredicateId,
    /// Boundary context of the denial.
    #[serde(deserialize_with = "deser_defect_boundary_id")]
    pub boundary_id: String,
    /// Tick at which the denial occurred.
    pub denied_at_tick: u64,
    /// Hash of the time authority envelope (if available).
    pub envelope_hash: Hash,
    /// Window reference hash (if available).
    pub window_ref: Hash,
}

// ============================================================================
// TP-EIO29-005: projection_multi_sink_continuity_valid
// ============================================================================

/// Validates TP-EIO29-005: projection multi-sink continuity valid.
///
/// Checks that:
/// 1. Continuity window is present and structurally valid.
/// 2. Continuity window signature is verified with trusted signers.
/// 3. Continuity window boundary and context bindings match evaluation.
/// 4. Sink continuity profile is present, signed, and trusted.
/// 5. Profile boundary and context bindings match evaluation.
/// 6. Sink identity snapshot is present and valid.
/// 7. Profile's `sink_snapshot_digest` matches the snapshot's digest.
/// 8. All scenario verdicts passed: `truth_plane_continued` AND
///    `backlog_bounded`.
/// 9. Unknown/missing scenario verdicts fail closed.
///
/// # Errors
///
/// Returns a stable deny reason string for any violation.
#[allow(clippy::too_many_arguments)]
pub fn validate_projection_continuity_tp005(
    continuity_window: Option<&ProjectionContinuityWindowV1>,
    continuity_profile: Option<&ProjectionSinkContinuityProfileV1>,
    sink_snapshot: Option<&SinkIdentitySnapshotV1>,
    eval_boundary_id: &str,
    trusted_signers: &[[u8; 32]],
    expected_time_authority_ref: &Hash,
    expected_window_ref: &Hash,
) -> Result<(), &'static str> {
    // ---- Continuity window validation ----
    let window = continuity_window.ok_or(DENY_CONTINUITY_WINDOW_MISSING)?;
    window.validate()?;

    window
        .verify_signature()
        .map_err(|_| DENY_CONTINUITY_WINDOW_SIGNATURE_INVALID)?;

    // Trusted signer check (constant-time fold).
    let window_signer_trusted = trusted_signers.iter().fold(0u8, |acc, ts| {
        acc | ts.ct_eq(&window.signer_key).unwrap_u8()
    });
    if window_signer_trusted == 0 {
        return Err(DENY_CONTINUITY_WINDOW_SIGNER_UNTRUSTED);
    }

    // Context binding.
    if window.boundary_id != eval_boundary_id {
        return Err(DENY_CONTINUITY_WINDOW_BOUNDARY_MISMATCH);
    }
    if window
        .time_authority_ref
        .ct_eq(expected_time_authority_ref)
        .unwrap_u8()
        == 0
    {
        return Err(DENY_CONTINUITY_WINDOW_TIME_AUTH_MISMATCH);
    }
    if window.window_ref.ct_eq(expected_window_ref).unwrap_u8() == 0 {
        return Err(DENY_CONTINUITY_WINDOW_REF_MISMATCH);
    }

    // ---- Sink continuity profile validation ----
    let profile = continuity_profile.ok_or(DENY_CONTINUITY_PROFILE_MISSING)?;
    profile.validate()?;

    profile
        .verify_signature()
        .map_err(|_| DENY_CONTINUITY_PROFILE_SIGNATURE_INVALID)?;

    // Trusted signer check (constant-time fold).
    let profile_signer_trusted = trusted_signers.iter().fold(0u8, |acc, ts| {
        acc | ts.ct_eq(&profile.signer_key).unwrap_u8()
    });
    if profile_signer_trusted == 0 {
        return Err(DENY_CONTINUITY_PROFILE_SIGNER_UNTRUSTED);
    }

    // Context binding: profile must match evaluation boundary.
    if profile.boundary_id != eval_boundary_id {
        return Err(DENY_CONTINUITY_PROFILE_BOUNDARY_MISMATCH);
    }
    if profile
        .time_authority_ref
        .ct_eq(expected_time_authority_ref)
        .unwrap_u8()
        == 0
    {
        return Err(DENY_CONTINUITY_PROFILE_TIME_AUTH_MISMATCH);
    }
    if profile.window_ref.ct_eq(expected_window_ref).unwrap_u8() == 0 {
        return Err(DENY_CONTINUITY_PROFILE_WINDOW_MISMATCH);
    }

    // ---- Sink identity snapshot validation ----
    let snapshot = sink_snapshot.ok_or(DENY_SINK_SNAPSHOT_MISSING)?;
    snapshot.validate()?;

    // Profile's sink_snapshot_digest must match the snapshot's digest.
    if profile
        .sink_snapshot_digest
        .ct_eq(&snapshot.snapshot_digest)
        .unwrap_u8()
        == 0
    {
        return Err(DENY_SINK_SNAPSHOT_DIGEST_ZERO);
    }

    // ---- Scenario verdict evaluation ----
    // TP-EIO29-005: forall scenario in sink_failure_set(S),
    // authoritative_truth_plane_progress(scenario) AND
    // bounded_projection_backlog(scenario)
    for v in &profile.scenario_verdicts {
        if !v.truth_plane_continued {
            return Err(DENY_SCENARIO_TRUTH_PLANE_HALT);
        }
        if !v.backlog_bounded {
            return Err(DENY_SCENARIO_BACKLOG_UNBOUNDED);
        }
    }

    Ok(())
}

// ============================================================================
// Deferred replay boundedness validation
// ============================================================================

/// Input for deferred replay boundedness evaluation.
#[derive(Debug, Clone)]
pub struct DeferredReplayInput {
    /// Deferred replay receipts.
    pub receipts: Vec<DeferredReplayReceiptV1>,
    /// Trusted signer public keys.
    pub trusted_signers: Vec<[u8; 32]>,
    /// Expected time authority reference hash.
    pub expected_time_authority_ref: Hash,
    /// Expected window reference hash.
    pub expected_window_ref: Hash,
    /// Expected backlog digest for context binding.
    pub expected_backlog_digest: Hash,
    /// Maximum allowed backlog items (retention envelope).
    pub max_backlog_items: u64,
}

/// Typed mode for deferred replay evaluation.
///
/// Callers must explicitly declare whether deferred replay is active.
/// This prevents fail-open bypass via `Option`.
#[derive(Debug, Clone)]
pub enum DeferredReplayMode {
    /// Deferred replay is active; boundedness check is required.
    Active(DeferredReplayInput),
    /// No deferred replay; check does not apply.
    Inactive,
}

/// Validates deferred replay boundedness.
///
/// Checks that:
/// 1. At least one receipt is present.
/// 2. Each receipt passes structural validation.
/// 3. Each receipt passes Ed25519 signature verification.
/// 4. Each receipt signer is in the trusted set.
/// 5. Receipt context binds to expected boundary, time authority, window.
/// 6. Receipt backlog digest matches expected context.
/// 7. Receipt replay converged idempotently.
/// 8. Replayed item count does not exceed retention envelope.
///
/// # Errors
///
/// Returns a stable deny reason string for any violation.
pub fn validate_deferred_replay_boundedness(
    input: &DeferredReplayInput,
    eval_boundary_id: &str,
) -> Result<(), &'static str> {
    if input.receipts.is_empty() {
        return Err(DENY_DEFERRED_REPLAY_RECEIPT_MISSING);
    }

    if input.receipts.len() > MAX_DEFERRED_REPLAY_RECEIPTS {
        return Err(DENY_DEFERRED_REPLAY_RECEIPTS_EXCEEDED);
    }

    let mut seen_ids = std::collections::HashSet::new();

    for receipt in &input.receipts {
        // Dedup by receipt_id.
        if !seen_ids.insert(&receipt.receipt_id) {
            return Err(DENY_DEFERRED_REPLAY_RECEIPT_DUPLICATE_ID);
        }

        receipt.validate()?;

        // Ed25519 signature verification.
        receipt
            .verify_signature()
            .map_err(|_| DENY_DEFERRED_REPLAY_RECEIPT_SIGNATURE_INVALID)?;

        // Trusted signer check (constant-time fold).
        let signer_trusted = input.trusted_signers.iter().fold(0u8, |acc, ts| {
            acc | ts.ct_eq(&receipt.signer_key).unwrap_u8()
        });
        if signer_trusted == 0 {
            return Err(DENY_DEFERRED_REPLAY_RECEIPT_SIGNER_UNTRUSTED);
        }

        // Context binding.
        if receipt.boundary_id != eval_boundary_id {
            return Err(DENY_DEFERRED_REPLAY_RECEIPT_BOUNDARY_MISMATCH);
        }
        if receipt
            .time_authority_ref
            .ct_eq(&input.expected_time_authority_ref)
            .unwrap_u8()
            == 0
        {
            return Err(DENY_DEFERRED_REPLAY_RECEIPT_TIME_AUTH_MISMATCH);
        }
        if receipt
            .window_ref
            .ct_eq(&input.expected_window_ref)
            .unwrap_u8()
            == 0
        {
            return Err(DENY_DEFERRED_REPLAY_RECEIPT_WINDOW_MISMATCH);
        }
        if receipt
            .backlog_digest
            .ct_eq(&input.expected_backlog_digest)
            .unwrap_u8()
            == 0
        {
            return Err(DENY_DEFERRED_REPLAY_RECEIPT_BACKLOG_MISMATCH);
        }

        // Convergence check.
        if !receipt.converged {
            return Err(DENY_DEFERRED_REPLAY_NOT_CONVERGED);
        }

        // Retention envelope check.
        if receipt.replayed_item_count > input.max_backlog_items {
            return Err(DENY_BACKLOG_EXCEEDS_RETENTION);
        }
    }

    Ok(())
}

// ============================================================================
// Combined evaluation
// ============================================================================

/// Verdict for a projection continuity evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContinuityVerdict {
    /// Admission allowed.
    Allow,
    /// Admission denied with structured defect.
    Deny,
}

/// Decision from a projection continuity evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuityDecision {
    /// Verdict of the continuity evaluation.
    pub verdict: ContinuityVerdict,
    /// Deny defect (present when verdict is `Deny`).
    pub defect: Option<ContinuityDenyDefect>,
    /// Temporal predicate results: (`predicate_id`, passed).
    pub predicate_results: Vec<(TemporalPredicateId, bool)>,
}

impl ContinuityDecision {
    /// Creates an allow decision with predicate results.
    #[must_use]
    const fn allow(predicate_results: Vec<(TemporalPredicateId, bool)>) -> Self {
        Self {
            verdict: ContinuityVerdict::Allow,
            defect: None,
            predicate_results,
        }
    }

    /// Creates a deny decision with a structured defect.
    #[must_use]
    fn deny(
        reason: &str,
        predicate_id: TemporalPredicateId,
        boundary_id: &str,
        denied_at_tick: u64,
        envelope_hash: Hash,
        window_ref: Hash,
        predicate_results: Vec<(TemporalPredicateId, bool)>,
    ) -> Self {
        Self {
            verdict: ContinuityVerdict::Deny,
            defect: Some(ContinuityDenyDefect {
                reason: reason.to_string(),
                predicate_id,
                boundary_id: boundary_id.to_string(),
                denied_at_tick,
                envelope_hash,
                window_ref,
            }),
            predicate_results,
        }
    }
}

/// Evaluates projection continuity admission.
///
/// Combines TP-EIO29-005 (multi-sink continuity) with deferred replay
/// boundedness checks via [`DeferredReplayMode`].
///
/// # Arguments
///
/// - `continuity_window`: continuity window declaration.
/// - `continuity_profile`: sink continuity profile with scenario verdicts.
/// - `sink_snapshot`: sink identity snapshot.
/// - `eval_boundary_id`: boundary identifier for this evaluation.
/// - `eval_tick`: current tick for deny defect reporting.
/// - `envelope_hash`: time authority envelope hash for defect reporting.
/// - `window_ref_hash`: window reference hash for defect reporting.
/// - `trusted_signers`: trusted signer public keys.
/// - `deferred_replay`: typed mode for deferred replay evaluation.
///
/// # Returns
///
/// A [`ContinuityDecision`] with verdict and structured defect.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn evaluate_projection_continuity(
    continuity_window: Option<&ProjectionContinuityWindowV1>,
    continuity_profile: Option<&ProjectionSinkContinuityProfileV1>,
    sink_snapshot: Option<&SinkIdentitySnapshotV1>,
    eval_boundary_id: &str,
    eval_tick: u64,
    envelope_hash: Hash,
    window_ref_hash: Hash,
    trusted_signers: &[[u8; 32]],
    deferred_replay: &DeferredReplayMode,
) -> ContinuityDecision {
    let mut predicate_results = Vec::new();

    // TP-EIO29-005: projection multi-sink continuity valid.
    let tp005_result = validate_projection_continuity_tp005(
        continuity_window,
        continuity_profile,
        sink_snapshot,
        eval_boundary_id,
        trusted_signers,
        &envelope_hash,
        &window_ref_hash,
    );
    let tp005_passed = tp005_result.is_ok();
    predicate_results.push((TemporalPredicateId::TpEio29005, tp005_passed));

    if let Err(reason) = tp005_result {
        return ContinuityDecision::deny(
            reason,
            TemporalPredicateId::TpEio29005,
            eval_boundary_id,
            eval_tick,
            envelope_hash,
            window_ref_hash,
            predicate_results,
        );
    }

    // Deferred replay boundedness (if active).
    match deferred_replay {
        DeferredReplayMode::Inactive => {
            // No deferred replay; check does not apply.
        },
        DeferredReplayMode::Active(input) => {
            let replay_result = validate_deferred_replay_boundedness(input, eval_boundary_id);
            let replay_passed = replay_result.is_ok();
            predicate_results.push((TemporalPredicateId::TpEio29004, replay_passed));

            if let Err(reason) = replay_result {
                return ContinuityDecision::deny(
                    reason,
                    TemporalPredicateId::TpEio29004,
                    eval_boundary_id,
                    eval_tick,
                    envelope_hash,
                    window_ref_hash,
                    predicate_results,
                );
            }
        },
    }

    ContinuityDecision::allow(predicate_results)
}

// ============================================================================
// Validation helpers
// ============================================================================

fn is_zero_hash(hash: &[u8; 32]) -> bool {
    hash.ct_eq(&ZERO_HASH).unwrap_u8() == 1
}

fn validate_required_string(
    field: &str,
    value: &str,
    max_len: usize,
) -> Result<(), ProjectionContinuityError> {
    if value.is_empty() {
        return Err(ProjectionContinuityError::RequiredFieldMissing {
            field: field.to_string(),
        });
    }
    if value.len() > max_len {
        return Err(ProjectionContinuityError::FieldTooLong {
            field: field.to_string(),
            actual: value.len(),
            max: max_len,
        });
    }
    Ok(())
}

fn validate_non_zero_hash(field: &str, hash: &Hash) -> Result<(), ProjectionContinuityError> {
    if is_zero_hash(hash) {
        return Err(ProjectionContinuityError::ZeroHash {
            field: field.to_string(),
        });
    }
    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Signer;

    fn test_hash(val: u8) -> Hash {
        let mut h = [0u8; 32];
        h[0] = val;
        h[31] = val;
        h
    }

    fn valid_signer() -> Signer {
        Signer::generate()
    }

    fn trusted_signers_for(signer: &Signer) -> [[u8; 32]; 1] {
        [signer.public_key_bytes()]
    }

    fn expected_time_authority_ref() -> Hash {
        test_hash(0xBB)
    }

    fn expected_window_ref() -> Hash {
        test_hash(0xCC)
    }

    fn valid_continuity_window(signer: &Signer) -> ProjectionContinuityWindowV1 {
        ProjectionContinuityWindowV1::create_signed(
            "cw-001",
            "boundary-1",
            100,  // outage_window_start
            2000, // outage_window_end
            2001, // replay_window_start
            5000, // replay_window_end
            test_hash(0xA1),
            test_hash(0xA2),
            test_hash(0xBB),
            test_hash(0xCC),
            test_hash(0xDD),
            "actor-1",
            signer,
        )
        .expect("valid continuity window")
    }

    fn valid_scenario_verdict(id: &str) -> ContinuityScenarioVerdict {
        ContinuityScenarioVerdict {
            scenario_id: id.to_string(),
            scenario_digest: test_hash(0xF0),
            truth_plane_continued: true,
            backlog_bounded: true,
            max_backlog_items: 100,
        }
    }

    fn valid_continuity_profile(signer: &Signer) -> ProjectionSinkContinuityProfileV1 {
        ProjectionSinkContinuityProfileV1::create_signed(
            "cp-001",
            "boundary-1",
            vec![
                valid_scenario_verdict("outage-1"),
                valid_scenario_verdict("churn-1"),
                valid_scenario_verdict("partition-1"),
            ],
            test_hash(0xEE), // sink_snapshot_digest matching snapshot
            test_hash(0xBB),
            test_hash(0xCC),
            test_hash(0xDD),
            "actor-1",
            signer,
        )
        .expect("valid continuity profile")
    }

    fn valid_sink_snapshot() -> SinkIdentitySnapshotV1 {
        SinkIdentitySnapshotV1 {
            sink_identities: vec![
                SinkIdentityEntry {
                    sink_id: "github-main".to_string(),
                    identity_digest: test_hash(0x01),
                },
                SinkIdentityEntry {
                    sink_id: "github-mirror".to_string(),
                    identity_digest: test_hash(0x02),
                },
            ],
            snapshot_digest: test_hash(0xEE), // matches profile sink_snapshot_digest
        }
    }

    fn valid_deferred_replay_receipt(signer: &Signer) -> DeferredReplayReceiptV1 {
        DeferredReplayReceiptV1::create_signed(
            "dr-001",
            "boundary-1",
            test_hash(0xFF), // backlog_digest
            42,              // replayed_item_count
            5000,            // replay_horizon_tick
            true,            // converged
            test_hash(0xBB),
            test_hash(0xCC),
            test_hash(0xDD),
            "actor-1",
            signer,
        )
        .expect("valid deferred replay receipt")
    }

    // ========================================================================
    // ProjectionContinuityWindowV1 -- creation and signing
    // ========================================================================

    #[test]
    fn continuity_window_create_and_sign_roundtrip() {
        let signer = valid_signer();
        let window = valid_continuity_window(&signer);
        assert!(window.verify_signature().is_ok());
        assert!(window.validate().is_ok());
        assert_eq!(window.window_id, "cw-001");
        assert_eq!(window.boundary_id, "boundary-1");
        assert_eq!(window.outage_window_start, 100);
        assert_eq!(window.outage_window_end, 2000);
    }

    #[test]
    fn continuity_window_deterministic_signature() {
        let signer = valid_signer();
        let w1 = valid_continuity_window(&signer);
        let w2 = valid_continuity_window(&signer);
        assert_eq!(w1.signature, w2.signature);
    }

    #[test]
    fn continuity_window_tampered_data_fails_verification() {
        let signer = valid_signer();
        let mut window = valid_continuity_window(&signer);
        window.boundary_id = "tampered".to_string();
        assert!(window.verify_signature().is_err());
    }

    #[test]
    fn continuity_window_zero_signer_key_denied() {
        let signer = valid_signer();
        let mut window = valid_continuity_window(&signer);
        window.signer_key = [0u8; 32];
        assert!(window.verify_signature().is_err());
        assert_eq!(
            window.validate().unwrap_err(),
            DENY_CONTINUITY_WINDOW_SIGNER_ZERO
        );
    }

    #[test]
    fn continuity_window_empty_id_denied() {
        let signer = valid_signer();
        let result = ProjectionContinuityWindowV1::create_signed(
            "",
            "boundary-1",
            100,
            2000,
            2001,
            5000,
            test_hash(0xA1),
            test_hash(0xA2),
            test_hash(0xBB),
            test_hash(0xCC),
            test_hash(0xDD),
            "actor-1",
            &signer,
        );
        assert!(result.is_err());
    }

    #[test]
    fn continuity_window_inverted_outage_range_denied() {
        let signer = valid_signer();
        let result = ProjectionContinuityWindowV1::create_signed(
            "cw-002",
            "boundary-1",
            2000,
            100, // inverted
            2001,
            5000,
            test_hash(0xA1),
            test_hash(0xA2),
            test_hash(0xBB),
            test_hash(0xCC),
            test_hash(0xDD),
            "actor-1",
            &signer,
        );
        assert!(result.is_err());
    }

    #[test]
    fn continuity_window_inverted_replay_range_denied() {
        let signer = valid_signer();
        let result = ProjectionContinuityWindowV1::create_signed(
            "cw-003",
            "boundary-1",
            100,
            2000,
            5000,
            2001, // inverted
            test_hash(0xA1),
            test_hash(0xA2),
            test_hash(0xBB),
            test_hash(0xCC),
            test_hash(0xDD),
            "actor-1",
            &signer,
        );
        assert!(result.is_err());
    }

    // ========================================================================
    // ProjectionSinkContinuityProfileV1
    // ========================================================================

    #[test]
    fn continuity_profile_create_and_sign_roundtrip() {
        let signer = valid_signer();
        let profile = valid_continuity_profile(&signer);
        assert!(profile.verify_signature().is_ok());
        assert!(profile.validate().is_ok());
        assert_eq!(profile.profile_id, "cp-001");
        assert_eq!(profile.scenario_verdicts.len(), 3);
    }

    #[test]
    fn continuity_profile_no_scenarios_denied() {
        let signer = valid_signer();
        let result = ProjectionSinkContinuityProfileV1::create_signed(
            "cp-002",
            "boundary-1",
            vec![], // empty scenarios
            test_hash(0xEE),
            test_hash(0xBB),
            test_hash(0xCC),
            test_hash(0xDD),
            "actor-1",
            &signer,
        );
        assert!(result.is_err());
    }

    #[test]
    fn continuity_profile_tampered_data_fails() {
        let signer = valid_signer();
        let mut profile = valid_continuity_profile(&signer);
        profile.boundary_id = "tampered".to_string();
        assert!(profile.verify_signature().is_err());
    }

    // ========================================================================
    // SinkIdentitySnapshotV1
    // ========================================================================

    #[test]
    fn sink_snapshot_valid() {
        let snapshot = valid_sink_snapshot();
        assert!(snapshot.validate().is_ok());
    }

    #[test]
    fn sink_snapshot_empty_denied() {
        let snapshot = SinkIdentitySnapshotV1 {
            sink_identities: vec![],
            snapshot_digest: test_hash(0xEE),
        };
        assert_eq!(snapshot.validate().unwrap_err(), DENY_SINK_SNAPSHOT_EMPTY);
    }

    #[test]
    fn sink_snapshot_zero_digest_denied() {
        let snapshot = SinkIdentitySnapshotV1 {
            sink_identities: vec![SinkIdentityEntry {
                sink_id: "sink-1".to_string(),
                identity_digest: test_hash(0x01),
            }],
            snapshot_digest: [0u8; 32],
        };
        assert_eq!(
            snapshot.validate().unwrap_err(),
            DENY_SINK_SNAPSHOT_DIGEST_ZERO
        );
    }

    #[test]
    fn sink_snapshot_zero_identity_digest_denied() {
        let snapshot = SinkIdentitySnapshotV1 {
            sink_identities: vec![SinkIdentityEntry {
                sink_id: "sink-1".to_string(),
                identity_digest: [0u8; 32],
            }],
            snapshot_digest: test_hash(0xEE),
        };
        assert_eq!(
            snapshot.validate().unwrap_err(),
            DENY_SINK_IDENTITY_DIGEST_ZERO
        );
    }

    // ========================================================================
    // DeferredReplayReceiptV1
    // ========================================================================

    #[test]
    fn deferred_replay_receipt_create_and_sign_roundtrip() {
        let signer = valid_signer();
        let receipt = valid_deferred_replay_receipt(&signer);
        assert!(receipt.verify_signature().is_ok());
        assert!(receipt.validate().is_ok());
        assert_eq!(receipt.receipt_id, "dr-001");
        assert!(receipt.converged);
        assert_eq!(receipt.replayed_item_count, 42);
    }

    #[test]
    fn deferred_replay_receipt_tampered_fails() {
        let signer = valid_signer();
        let mut receipt = valid_deferred_replay_receipt(&signer);
        receipt.boundary_id = "tampered".to_string();
        assert!(receipt.verify_signature().is_err());
    }

    #[test]
    fn deferred_replay_receipt_zero_signer_denied() {
        let signer = valid_signer();
        let mut receipt = valid_deferred_replay_receipt(&signer);
        receipt.signer_key = [0u8; 32];
        assert!(receipt.verify_signature().is_err());
        assert_eq!(
            receipt.validate().unwrap_err(),
            DENY_DEFERRED_REPLAY_RECEIPT_SIGNER_ZERO
        );
    }

    // ========================================================================
    // TP-EIO29-005: validate_projection_continuity_tp005
    // ========================================================================

    #[test]
    fn tp005_valid_full_evaluation() {
        let signer = valid_signer();
        let trusted = trusted_signers_for(&signer);
        let window = valid_continuity_window(&signer);
        let profile = valid_continuity_profile(&signer);
        let snapshot = valid_sink_snapshot();

        let result = validate_projection_continuity_tp005(
            Some(&window),
            Some(&profile),
            Some(&snapshot),
            "boundary-1",
            &trusted,
            &expected_time_authority_ref(),
            &expected_window_ref(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn tp005_missing_window_denied() {
        let signer = valid_signer();
        let trusted = trusted_signers_for(&signer);
        let profile = valid_continuity_profile(&signer);
        let snapshot = valid_sink_snapshot();

        let result = validate_projection_continuity_tp005(
            None,
            Some(&profile),
            Some(&snapshot),
            "boundary-1",
            &trusted,
            &expected_time_authority_ref(),
            &expected_window_ref(),
        );
        assert_eq!(result.unwrap_err(), DENY_CONTINUITY_WINDOW_MISSING);
    }

    #[test]
    fn tp005_missing_profile_denied() {
        let signer = valid_signer();
        let trusted = trusted_signers_for(&signer);
        let window = valid_continuity_window(&signer);
        let snapshot = valid_sink_snapshot();

        let result = validate_projection_continuity_tp005(
            Some(&window),
            None,
            Some(&snapshot),
            "boundary-1",
            &trusted,
            &expected_time_authority_ref(),
            &expected_window_ref(),
        );
        assert_eq!(result.unwrap_err(), DENY_CONTINUITY_PROFILE_MISSING);
    }

    #[test]
    fn tp005_missing_snapshot_denied() {
        let signer = valid_signer();
        let trusted = trusted_signers_for(&signer);
        let window = valid_continuity_window(&signer);
        let profile = valid_continuity_profile(&signer);

        let result = validate_projection_continuity_tp005(
            Some(&window),
            Some(&profile),
            None,
            "boundary-1",
            &trusted,
            &expected_time_authority_ref(),
            &expected_window_ref(),
        );
        assert_eq!(result.unwrap_err(), DENY_SINK_SNAPSHOT_MISSING);
    }

    #[test]
    fn tp005_untrusted_window_signer_denied() {
        let signer = valid_signer();
        let other_signer = valid_signer();
        let trusted = trusted_signers_for(&other_signer);
        let window = valid_continuity_window(&signer);
        let profile = valid_continuity_profile(&signer);
        let snapshot = valid_sink_snapshot();

        let result = validate_projection_continuity_tp005(
            Some(&window),
            Some(&profile),
            Some(&snapshot),
            "boundary-1",
            &trusted,
            &expected_time_authority_ref(),
            &expected_window_ref(),
        );
        assert_eq!(result.unwrap_err(), DENY_CONTINUITY_WINDOW_SIGNER_UNTRUSTED);
    }

    #[test]
    fn tp005_boundary_mismatch_denied() {
        let signer = valid_signer();
        let trusted = trusted_signers_for(&signer);
        let window = valid_continuity_window(&signer);
        let profile = valid_continuity_profile(&signer);
        let snapshot = valid_sink_snapshot();

        let result = validate_projection_continuity_tp005(
            Some(&window),
            Some(&profile),
            Some(&snapshot),
            "wrong-boundary", // mismatch
            &trusted,
            &expected_time_authority_ref(),
            &expected_window_ref(),
        );
        assert_eq!(
            result.unwrap_err(),
            DENY_CONTINUITY_WINDOW_BOUNDARY_MISMATCH
        );
    }

    #[test]
    fn tp005_time_authority_mismatch_denied() {
        let signer = valid_signer();
        let trusted = trusted_signers_for(&signer);
        let window = valid_continuity_window(&signer);
        let profile = valid_continuity_profile(&signer);
        let snapshot = valid_sink_snapshot();
        let wrong_ta = test_hash(0x99);

        let result = validate_projection_continuity_tp005(
            Some(&window),
            Some(&profile),
            Some(&snapshot),
            "boundary-1",
            &trusted,
            &wrong_ta, // mismatch
            &expected_window_ref(),
        );
        assert_eq!(
            result.unwrap_err(),
            DENY_CONTINUITY_WINDOW_TIME_AUTH_MISMATCH
        );
    }

    #[test]
    fn tp005_window_ref_mismatch_denied() {
        let signer = valid_signer();
        let trusted = trusted_signers_for(&signer);
        let window = valid_continuity_window(&signer);
        let profile = valid_continuity_profile(&signer);
        let snapshot = valid_sink_snapshot();
        let wrong_wr = test_hash(0x99);

        let result = validate_projection_continuity_tp005(
            Some(&window),
            Some(&profile),
            Some(&snapshot),
            "boundary-1",
            &trusted,
            &expected_time_authority_ref(),
            &wrong_wr, // mismatch
        );
        assert_eq!(result.unwrap_err(), DENY_CONTINUITY_WINDOW_REF_MISMATCH);
    }

    #[test]
    fn tp005_scenario_truth_plane_halt_denied() {
        let signer = valid_signer();
        let trusted = trusted_signers_for(&signer);
        let window = valid_continuity_window(&signer);
        let snapshot = valid_sink_snapshot();

        let mut bad_verdict = valid_scenario_verdict("outage-bad");
        bad_verdict.truth_plane_continued = false;

        let profile = ProjectionSinkContinuityProfileV1::create_signed(
            "cp-bad",
            "boundary-1",
            vec![bad_verdict],
            test_hash(0xEE),
            test_hash(0xBB),
            test_hash(0xCC),
            test_hash(0xDD),
            "actor-1",
            &signer,
        )
        .expect("profile created");

        let result = validate_projection_continuity_tp005(
            Some(&window),
            Some(&profile),
            Some(&snapshot),
            "boundary-1",
            &trusted,
            &expected_time_authority_ref(),
            &expected_window_ref(),
        );
        assert_eq!(result.unwrap_err(), DENY_SCENARIO_TRUTH_PLANE_HALT);
    }

    #[test]
    fn tp005_scenario_backlog_unbounded_denied() {
        let signer = valid_signer();
        let trusted = trusted_signers_for(&signer);
        let window = valid_continuity_window(&signer);
        let snapshot = valid_sink_snapshot();

        let mut bad_verdict = valid_scenario_verdict("churn-bad");
        bad_verdict.backlog_bounded = false;

        let profile = ProjectionSinkContinuityProfileV1::create_signed(
            "cp-bad2",
            "boundary-1",
            vec![bad_verdict],
            test_hash(0xEE),
            test_hash(0xBB),
            test_hash(0xCC),
            test_hash(0xDD),
            "actor-1",
            &signer,
        )
        .expect("profile created");

        let result = validate_projection_continuity_tp005(
            Some(&window),
            Some(&profile),
            Some(&snapshot),
            "boundary-1",
            &trusted,
            &expected_time_authority_ref(),
            &expected_window_ref(),
        );
        assert_eq!(result.unwrap_err(), DENY_SCENARIO_BACKLOG_UNBOUNDED);
    }

    // ========================================================================
    // Deferred replay boundedness
    // ========================================================================

    #[test]
    fn deferred_replay_valid() {
        let signer = valid_signer();
        let trusted = trusted_signers_for(&signer);
        let receipt = valid_deferred_replay_receipt(&signer);

        let input = DeferredReplayInput {
            receipts: vec![receipt],
            trusted_signers: trusted.to_vec(),
            expected_time_authority_ref: expected_time_authority_ref(),
            expected_window_ref: expected_window_ref(),
            expected_backlog_digest: test_hash(0xFF),
            max_backlog_items: 1000,
        };

        let result = validate_deferred_replay_boundedness(&input, "boundary-1");
        assert!(result.is_ok());
    }

    #[test]
    fn deferred_replay_missing_receipt_denied() {
        let input = DeferredReplayInput {
            receipts: vec![],
            trusted_signers: vec![],
            expected_time_authority_ref: expected_time_authority_ref(),
            expected_window_ref: expected_window_ref(),
            expected_backlog_digest: test_hash(0xFF),
            max_backlog_items: 1000,
        };

        let result = validate_deferred_replay_boundedness(&input, "boundary-1");
        assert_eq!(result.unwrap_err(), DENY_DEFERRED_REPLAY_RECEIPT_MISSING);
    }

    #[test]
    fn deferred_replay_untrusted_signer_denied() {
        let signer = valid_signer();
        let other_signer = valid_signer();
        let trusted = trusted_signers_for(&other_signer);
        let receipt = valid_deferred_replay_receipt(&signer);

        let input = DeferredReplayInput {
            receipts: vec![receipt],
            trusted_signers: trusted.to_vec(),
            expected_time_authority_ref: expected_time_authority_ref(),
            expected_window_ref: expected_window_ref(),
            expected_backlog_digest: test_hash(0xFF),
            max_backlog_items: 1000,
        };

        let result = validate_deferred_replay_boundedness(&input, "boundary-1");
        assert_eq!(
            result.unwrap_err(),
            DENY_DEFERRED_REPLAY_RECEIPT_SIGNER_UNTRUSTED
        );
    }

    #[test]
    fn deferred_replay_boundary_mismatch_denied() {
        let signer = valid_signer();
        let trusted = trusted_signers_for(&signer);
        let receipt = valid_deferred_replay_receipt(&signer);

        let input = DeferredReplayInput {
            receipts: vec![receipt],
            trusted_signers: trusted.to_vec(),
            expected_time_authority_ref: expected_time_authority_ref(),
            expected_window_ref: expected_window_ref(),
            expected_backlog_digest: test_hash(0xFF),
            max_backlog_items: 1000,
        };

        let result = validate_deferred_replay_boundedness(&input, "wrong-boundary");
        assert_eq!(
            result.unwrap_err(),
            DENY_DEFERRED_REPLAY_RECEIPT_BOUNDARY_MISMATCH
        );
    }

    #[test]
    fn deferred_replay_not_converged_denied() {
        let signer = valid_signer();
        let trusted = trusted_signers_for(&signer);
        let mut receipt = valid_deferred_replay_receipt(&signer);
        // Corrupt the converged field AFTER signing to test structural check.
        // We need to create a non-converged receipt properly.
        // For the test, create an unsigned receipt with converged=false.
        receipt.converged = false;
        // Re-sign with the correct converged field.
        let re_signed = DeferredReplayReceiptV1::create_signed(
            "dr-002",
            "boundary-1",
            test_hash(0xFF),
            42,
            5000,
            false, // not converged
            test_hash(0xBB),
            test_hash(0xCC),
            test_hash(0xDD),
            "actor-1",
            &signer,
        )
        .expect("receipt created");

        let input = DeferredReplayInput {
            receipts: vec![re_signed],
            trusted_signers: trusted.to_vec(),
            expected_time_authority_ref: expected_time_authority_ref(),
            expected_window_ref: expected_window_ref(),
            expected_backlog_digest: test_hash(0xFF),
            max_backlog_items: 1000,
        };

        let result = validate_deferred_replay_boundedness(&input, "boundary-1");
        assert_eq!(result.unwrap_err(), DENY_DEFERRED_REPLAY_NOT_CONVERGED);
    }

    #[test]
    fn deferred_replay_exceeds_retention_denied() {
        let signer = valid_signer();
        let trusted = trusted_signers_for(&signer);
        let receipt = DeferredReplayReceiptV1::create_signed(
            "dr-003",
            "boundary-1",
            test_hash(0xFF),
            10_000, // replayed_item_count exceeds max_backlog_items
            5000,
            true,
            test_hash(0xBB),
            test_hash(0xCC),
            test_hash(0xDD),
            "actor-1",
            &signer,
        )
        .expect("receipt created");

        let input = DeferredReplayInput {
            receipts: vec![receipt],
            trusted_signers: trusted.to_vec(),
            expected_time_authority_ref: expected_time_authority_ref(),
            expected_window_ref: expected_window_ref(),
            expected_backlog_digest: test_hash(0xFF),
            max_backlog_items: 100, // below replayed count
        };

        let result = validate_deferred_replay_boundedness(&input, "boundary-1");
        assert_eq!(result.unwrap_err(), DENY_BACKLOG_EXCEEDS_RETENTION);
    }

    #[test]
    fn deferred_replay_duplicate_id_denied() {
        let signer = valid_signer();
        let trusted = trusted_signers_for(&signer);
        let receipt = valid_deferred_replay_receipt(&signer);
        let receipt2 = receipt.clone();

        let input = DeferredReplayInput {
            receipts: vec![receipt, receipt2],
            trusted_signers: trusted.to_vec(),
            expected_time_authority_ref: expected_time_authority_ref(),
            expected_window_ref: expected_window_ref(),
            expected_backlog_digest: test_hash(0xFF),
            max_backlog_items: 1000,
        };

        let result = validate_deferred_replay_boundedness(&input, "boundary-1");
        assert_eq!(
            result.unwrap_err(),
            DENY_DEFERRED_REPLAY_RECEIPT_DUPLICATE_ID
        );
    }

    #[test]
    fn deferred_replay_time_auth_mismatch_denied() {
        let signer = valid_signer();
        let trusted = trusted_signers_for(&signer);
        let receipt = valid_deferred_replay_receipt(&signer);

        let input = DeferredReplayInput {
            receipts: vec![receipt],
            trusted_signers: trusted.to_vec(),
            expected_time_authority_ref: test_hash(0x99), // mismatch
            expected_window_ref: expected_window_ref(),
            expected_backlog_digest: test_hash(0xFF),
            max_backlog_items: 1000,
        };

        let result = validate_deferred_replay_boundedness(&input, "boundary-1");
        assert_eq!(
            result.unwrap_err(),
            DENY_DEFERRED_REPLAY_RECEIPT_TIME_AUTH_MISMATCH
        );
    }

    #[test]
    fn deferred_replay_window_ref_mismatch_denied() {
        let signer = valid_signer();
        let trusted = trusted_signers_for(&signer);
        let receipt = valid_deferred_replay_receipt(&signer);

        let input = DeferredReplayInput {
            receipts: vec![receipt],
            trusted_signers: trusted.to_vec(),
            expected_time_authority_ref: expected_time_authority_ref(),
            expected_window_ref: test_hash(0x99), // mismatch
            expected_backlog_digest: test_hash(0xFF),
            max_backlog_items: 1000,
        };

        let result = validate_deferred_replay_boundedness(&input, "boundary-1");
        assert_eq!(
            result.unwrap_err(),
            DENY_DEFERRED_REPLAY_RECEIPT_WINDOW_MISMATCH
        );
    }

    #[test]
    fn deferred_replay_backlog_digest_mismatch_denied() {
        let signer = valid_signer();
        let trusted = trusted_signers_for(&signer);
        let receipt = valid_deferred_replay_receipt(&signer);

        let input = DeferredReplayInput {
            receipts: vec![receipt],
            trusted_signers: trusted.to_vec(),
            expected_time_authority_ref: expected_time_authority_ref(),
            expected_window_ref: expected_window_ref(),
            expected_backlog_digest: test_hash(0x99), // mismatch
            max_backlog_items: 1000,
        };

        let result = validate_deferred_replay_boundedness(&input, "boundary-1");
        assert_eq!(
            result.unwrap_err(),
            DENY_DEFERRED_REPLAY_RECEIPT_BACKLOG_MISMATCH
        );
    }

    // ========================================================================
    // Combined evaluation
    // ========================================================================

    #[test]
    fn evaluate_projection_continuity_allow_no_deferred_replay() {
        let signer = valid_signer();
        let trusted = trusted_signers_for(&signer);
        let window = valid_continuity_window(&signer);
        let profile = valid_continuity_profile(&signer);
        let snapshot = valid_sink_snapshot();

        let decision = evaluate_projection_continuity(
            Some(&window),
            Some(&profile),
            Some(&snapshot),
            "boundary-1",
            500,
            expected_time_authority_ref(),
            expected_window_ref(),
            &trusted,
            &DeferredReplayMode::Inactive,
        );

        assert_eq!(decision.verdict, ContinuityVerdict::Allow);
        assert!(decision.defect.is_none());
        assert_eq!(decision.predicate_results.len(), 1);
        assert_eq!(
            decision.predicate_results[0],
            (TemporalPredicateId::TpEio29005, true)
        );
    }

    #[test]
    fn evaluate_projection_continuity_allow_with_deferred_replay() {
        let signer = valid_signer();
        let trusted = trusted_signers_for(&signer);
        let window = valid_continuity_window(&signer);
        let profile = valid_continuity_profile(&signer);
        let snapshot = valid_sink_snapshot();
        let receipt = valid_deferred_replay_receipt(&signer);

        let deferred = DeferredReplayMode::Active(DeferredReplayInput {
            receipts: vec![receipt],
            trusted_signers: trusted.to_vec(),
            expected_time_authority_ref: expected_time_authority_ref(),
            expected_window_ref: expected_window_ref(),
            expected_backlog_digest: test_hash(0xFF),
            max_backlog_items: 1000,
        });

        let decision = evaluate_projection_continuity(
            Some(&window),
            Some(&profile),
            Some(&snapshot),
            "boundary-1",
            500,
            expected_time_authority_ref(),
            expected_window_ref(),
            &trusted,
            &deferred,
        );

        assert_eq!(decision.verdict, ContinuityVerdict::Allow);
        assert!(decision.defect.is_none());
        assert_eq!(decision.predicate_results.len(), 2);
        assert_eq!(
            decision.predicate_results[0],
            (TemporalPredicateId::TpEio29005, true)
        );
        assert_eq!(
            decision.predicate_results[1],
            (TemporalPredicateId::TpEio29004, true)
        );
    }

    #[test]
    fn evaluate_projection_continuity_deny_missing_window() {
        let signer = valid_signer();
        let trusted = trusted_signers_for(&signer);
        let profile = valid_continuity_profile(&signer);
        let snapshot = valid_sink_snapshot();

        let decision = evaluate_projection_continuity(
            None,
            Some(&profile),
            Some(&snapshot),
            "boundary-1",
            500,
            expected_time_authority_ref(),
            expected_window_ref(),
            &trusted,
            &DeferredReplayMode::Inactive,
        );

        assert_eq!(decision.verdict, ContinuityVerdict::Deny);
        assert!(decision.defect.is_some());
        let defect = decision.defect.unwrap();
        assert_eq!(defect.reason, DENY_CONTINUITY_WINDOW_MISSING);
        assert_eq!(defect.predicate_id, TemporalPredicateId::TpEio29005);
    }

    #[test]
    fn evaluate_projection_continuity_deny_deferred_replay_failure() {
        let signer = valid_signer();
        let trusted = trusted_signers_for(&signer);
        let window = valid_continuity_window(&signer);
        let profile = valid_continuity_profile(&signer);
        let snapshot = valid_sink_snapshot();

        let deferred = DeferredReplayMode::Active(DeferredReplayInput {
            receipts: vec![], // empty = denied
            trusted_signers: trusted.to_vec(),
            expected_time_authority_ref: expected_time_authority_ref(),
            expected_window_ref: expected_window_ref(),
            expected_backlog_digest: test_hash(0xFF),
            max_backlog_items: 1000,
        });

        let decision = evaluate_projection_continuity(
            Some(&window),
            Some(&profile),
            Some(&snapshot),
            "boundary-1",
            500,
            expected_time_authority_ref(),
            expected_window_ref(),
            &trusted,
            &deferred,
        );

        assert_eq!(decision.verdict, ContinuityVerdict::Deny);
        assert!(decision.defect.is_some());
        let defect = decision.defect.unwrap();
        assert_eq!(defect.reason, DENY_DEFERRED_REPLAY_RECEIPT_MISSING);
        assert_eq!(defect.predicate_id, TemporalPredicateId::TpEio29004);
    }

    // ========================================================================
    // Time-authority denial tests
    // ========================================================================

    #[test]
    fn tp005_stale_time_authority_denied() {
        // Tests that a mismatched time_authority_ref is caught.
        let signer = valid_signer();
        let trusted = trusted_signers_for(&signer);
        let window = valid_continuity_window(&signer);
        let profile = valid_continuity_profile(&signer);
        let snapshot = valid_sink_snapshot();

        let stale_ta = test_hash(0x01); // wrong time authority

        let result = validate_projection_continuity_tp005(
            Some(&window),
            Some(&profile),
            Some(&snapshot),
            "boundary-1",
            &trusted,
            &stale_ta,
            &expected_window_ref(),
        );
        assert_eq!(
            result.unwrap_err(),
            DENY_CONTINUITY_WINDOW_TIME_AUTH_MISMATCH
        );
    }

    #[test]
    fn tp005_invalid_signature_envelope_denied() {
        let signer = valid_signer();
        let trusted = trusted_signers_for(&signer);
        let mut window = valid_continuity_window(&signer);
        // Corrupt the signature to simulate invalid time authority envelope.
        window.signature[0] ^= 0xFF;
        let profile = valid_continuity_profile(&signer);
        let snapshot = valid_sink_snapshot();

        let result = validate_projection_continuity_tp005(
            Some(&window),
            Some(&profile),
            Some(&snapshot),
            "boundary-1",
            &trusted,
            &expected_time_authority_ref(),
            &expected_window_ref(),
        );
        assert_eq!(
            result.unwrap_err(),
            DENY_CONTINUITY_WINDOW_SIGNATURE_INVALID
        );
    }
}
