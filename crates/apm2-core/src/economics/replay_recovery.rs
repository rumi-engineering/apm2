// AGENT-AUTHORED
//! Replay-recovery bounds and idempotency closure for RFC-0029 REQ-0005.
//!
//! Implements:
//! - [`ReplayConvergenceReceiptV1`] and [`RecoveryAdmissibilityReceiptV1`] with
//!   signed temporal bindings (`time_authority_ref`, `window_ref`).
//! - TP-EIO29-004 (`replay_convergence_horizon_satisfied`) enforcement.
//! - TP-EIO29-007 (`replay_idempotency_monotone`) enforcement.
//! - Dedup closure for authoritative effects under retry/restart and
//!   partition/rejoin.
//! - Structured deny defects for unresolved effect identity and stale replay
//!   receipts.
//!
//! # Security Domain
//!
//! `DOMAIN_SECURITY` is in scope. All unknown, missing, stale, or unverifiable
//! replay/recovery states fail closed.
//!
//! # Temporal Model
//!
//! All receipts carry `time_authority_ref` and `window_ref` hashes binding them
//! to HTF evaluation windows. Receipts are Ed25519-signed with domain
//! separation to prevent cross-protocol replay.
//!
//! # Idempotency Closure
//!
//! TP-EIO29-007 enforces that authoritative effects admitted in adjacent
//! windows do not duplicate: revoked effects must be absent from the later
//! window, and no effect identity may appear in both windows unless explicitly
//! re-admitted. Unknown or unresolved effect identity always denies.

use std::collections::HashSet;

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

/// Maximum number of replay convergence receipts per evaluation.
pub const MAX_REPLAY_RECEIPTS: usize = 256;

/// Maximum number of effect identity digests per idempotency check.
pub const MAX_EFFECT_IDENTITIES: usize = 4_096;

/// Maximum number of revoked effect digests per window.
pub const MAX_REVOKED_EFFECTS: usize = 4_096;

/// Maximum string length for receipt identifiers.
pub const MAX_RECEIPT_ID_LENGTH: usize = 256;

/// Maximum string length for boundary identifiers.
pub const MAX_BOUNDARY_ID_LENGTH: usize = 256;

/// Maximum string length for actor identifiers.
pub const MAX_ACTOR_ID_LENGTH: usize = 256;

/// Maximum string length for deny reason codes.
///
/// Re-uses the canonical [`MAX_REASON_LENGTH`] from PCAC types to ensure
/// consistent bounds across the codebase.
pub const MAX_DENY_REASON_LENGTH: usize = MAX_REASON_LENGTH;

/// Domain prefix for replay convergence receipt signing.
///
/// Domain separation ensures that a signature for a replay convergence
/// receipt cannot be replayed as another receipt type.
pub const REPLAY_CONVERGENCE_RECEIPT_PREFIX: &[u8] = b"REPLAY_CONVERGENCE_RECEIPT:";

/// Domain prefix for recovery admissibility receipt signing.
pub const RECOVERY_ADMISSIBILITY_RECEIPT_PREFIX: &[u8] = b"RECOVERY_ADMISSIBILITY_RECEIPT:";

const ZERO_HASH: Hash = [0u8; 32];

// ============================================================================
// Deny reason constants (stable strings for replay verification)
// ============================================================================

/// Deny: replay convergence receipt is missing.
pub const DENY_REPLAY_RECEIPT_MISSING: &str = "replay_convergence_receipt_missing";
/// Deny: replay convergence receipt has zero content hash.
pub const DENY_REPLAY_RECEIPT_HASH_ZERO: &str = "replay_convergence_receipt_hash_zero";
/// Deny: replay convergence horizon reference is unresolved.
pub const DENY_REPLAY_HORIZON_UNRESOLVED: &str = "replay_convergence_horizon_unresolved";
/// Deny: backlog remains unresolved after replay horizon end.
pub const DENY_BACKLOG_UNRESOLVED: &str = "replay_backlog_unresolved_after_horizon";
/// Deny: replay receipt signature is invalid.
pub const DENY_REPLAY_RECEIPT_SIGNATURE_INVALID: &str =
    "replay_convergence_receipt_signature_invalid";
/// Deny: replay receipt window reference is zero/missing.
pub const DENY_REPLAY_RECEIPT_WINDOW_ZERO: &str = "replay_convergence_receipt_window_ref_zero";
/// Deny: replay receipt time authority reference is zero/missing.
pub const DENY_REPLAY_RECEIPT_TIME_AUTH_ZERO: &str =
    "replay_convergence_receipt_time_authority_ref_zero";
/// Deny: replay receipt signer key is zero.
pub const DENY_REPLAY_RECEIPT_SIGNER_ZERO: &str = "replay_convergence_receipt_signer_key_zero";
/// Deny: replay receipt signer is not in the trusted set.
pub const DENY_REPLAY_RECEIPT_SIGNER_UNTRUSTED: &str =
    "replay_convergence_receipt_signer_untrusted";
/// Deny: replay receipt ID is empty or oversized.
pub const DENY_REPLAY_RECEIPT_ID_INVALID: &str = "replay_convergence_receipt_id_invalid";
/// Deny: replay receipt boundary mismatch.
pub const DENY_REPLAY_RECEIPT_BOUNDARY_MISMATCH: &str =
    "replay_convergence_receipt_boundary_mismatch";
/// Deny: replay receipt time authority reference does not match evaluation
/// context.
pub const DENY_REPLAY_RECEIPT_TIME_AUTH_MISMATCH: &str =
    "replay_convergence_receipt_time_authority_ref_mismatch";
/// Deny: replay receipt window reference does not match evaluation context.
pub const DENY_REPLAY_RECEIPT_WINDOW_MISMATCH: &str =
    "replay_convergence_receipt_window_ref_mismatch";
/// Deny: replay receipt backlog digest does not match evaluation context.
pub const DENY_REPLAY_RECEIPT_BACKLOG_MISMATCH: &str =
    "replay_convergence_receipt_backlog_digest_mismatch";
/// Deny: recovery admissibility receipt is missing.
pub const DENY_RECOVERY_RECEIPT_MISSING: &str = "recovery_admissibility_receipt_missing";
/// Deny: recovery admissibility receipt hash is zero.
pub const DENY_RECOVERY_RECEIPT_HASH_ZERO: &str = "recovery_admissibility_receipt_hash_zero";
/// Deny: recovery admissibility receipt signature is invalid.
pub const DENY_RECOVERY_RECEIPT_SIGNATURE_INVALID: &str =
    "recovery_admissibility_receipt_signature_invalid";
/// Deny: recovery admissibility receipt window reference is zero.
pub const DENY_RECOVERY_RECEIPT_WINDOW_ZERO: &str =
    "recovery_admissibility_receipt_window_ref_zero";
/// Deny: recovery admissibility receipt time authority reference is zero.
pub const DENY_RECOVERY_RECEIPT_TIME_AUTH_ZERO: &str =
    "recovery_admissibility_receipt_time_authority_ref_zero";
/// Deny: recovery admissibility receipt signer key is zero.
pub const DENY_RECOVERY_RECEIPT_SIGNER_ZERO: &str =
    "recovery_admissibility_receipt_signer_key_zero";
/// Deny: recovery admissibility receipt ID is invalid.
pub const DENY_RECOVERY_RECEIPT_ID_INVALID: &str = "recovery_admissibility_receipt_id_invalid";
/// Deny: adjacent windows are not actually adjacent.
pub const DENY_WINDOWS_NOT_ADJACENT: &str = "idempotency_windows_not_adjacent";
/// Deny: revoked effect found in later window.
pub const DENY_REVOKED_EFFECT_IN_LATER_WINDOW: &str = "idempotency_revoked_effect_in_later_window";
/// Deny: duplicate authoritative effect across windows.
pub const DENY_DUPLICATE_AUTHORITATIVE_EFFECT: &str = "idempotency_duplicate_authoritative_effect";
/// Deny: unresolved effect identity.
pub const DENY_UNRESOLVED_EFFECT_IDENTITY: &str = "idempotency_unresolved_effect_identity";
/// Deny: effect identity digest is zero.
pub const DENY_EFFECT_IDENTITY_ZERO: &str = "idempotency_effect_identity_zero";
/// Deny: replay receipt exceeds maximum count.
pub const DENY_REPLAY_RECEIPTS_EXCEEDED: &str = "replay_convergence_receipts_exceeded";
/// Deny: effect set exceeds maximum count.
pub const DENY_EFFECT_SET_EXCEEDED: &str = "idempotency_effect_set_exceeded";
/// Deny: revoked set exceeds maximum count.
pub const DENY_REVOKED_SET_EXCEEDED: &str = "idempotency_revoked_set_exceeded";
/// Deny: stale replay receipt (window does not match evaluation context).
pub const DENY_STALE_REPLAY_RECEIPT: &str = "replay_convergence_receipt_stale";
/// Deny: unknown temporal state.
pub const DENY_UNKNOWN_TEMPORAL_STATE: &str = "replay_recovery_unknown_temporal_state";
/// Deny: replay receipt `boundary_id` is empty or oversized (distinct from
/// `receipt_id`).
pub const DENY_REPLAY_RECEIPT_BOUNDARY_ID_EMPTY: &str =
    "replay_convergence_receipt_boundary_id_invalid";
/// Deny: recovery receipt `boundary_id` is empty or oversized (distinct from
/// `receipt_id`).
pub const DENY_RECOVERY_RECEIPT_BOUNDARY_ID_EMPTY: &str =
    "recovery_admissibility_receipt_boundary_id_invalid";
/// Deny: duplicate replay receipt ID detected.
pub const DENY_REPLAY_RECEIPT_DUPLICATE_ID: &str = "replay_convergence_receipt_duplicate_id";
/// Deny: recovery admissibility receipt signer is not in the trusted set.
pub const DENY_RECOVERY_RECEIPT_SIGNER_UNTRUSTED: &str =
    "recovery_admissibility_receipt_signer_untrusted";
/// Deny: recovery receipt boundary mismatch.
pub const DENY_RECOVERY_RECEIPT_BOUNDARY_MISMATCH: &str =
    "recovery_admissibility_receipt_boundary_mismatch";
/// Deny: recovery receipt time authority mismatch.
pub const DENY_RECOVERY_RECEIPT_TIME_AUTH_MISMATCH: &str =
    "recovery_admissibility_receipt_time_authority_ref_mismatch";
/// Deny: recovery receipt window reference mismatch.
pub const DENY_RECOVERY_RECEIPT_WINDOW_MISMATCH: &str =
    "recovery_admissibility_receipt_window_ref_mismatch";
/// Deny: recovery admissibility receipt not admitted.
pub const DENY_RECOVERY_RECEIPT_NOT_ADMITTED: &str = "recovery_admissibility_receipt_not_admitted";

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

// Field-specific deserializers for `#[serde(deserialize_with = "...")]`.

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
// Error types
// ============================================================================

/// Errors from replay-recovery receipt operations.
#[derive(Debug, Error)]
pub enum ReplayRecoveryError {
    /// Receipt field validation failed.
    #[error("receipt validation: {reason}")]
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
// ReplayConvergenceReceiptV1
// ============================================================================

/// Durable, signed receipt proving bounded idempotent convergence of a replay
/// within an HTF window.
///
/// Implements `ReplayConvergenceReceiptV1` from RFC-0029 REQ-0005.
/// Each receipt is domain-separated and Ed25519-signed, binding a replay
/// convergence outcome to a specific time authority and evaluation window.
///
/// # Fields
///
/// - `receipt_id`: unique identifier for this receipt instance.
/// - `boundary_id`: boundary context (must match evaluation window).
/// - `backlog_digest`: digest of the backlog state at convergence.
/// - `replay_horizon_tick`: tick marking the replay convergence horizon.
/// - `converged`: whether replay converged within the horizon.
/// - `time_authority_ref`: hash of the time authority envelope.
/// - `window_ref`: hash of the HTF evaluation window.
/// - `content_hash`: content-addressed hash of the receipt payload.
/// - `signer_actor_id`: identity of the signing actor.
/// - `signer_key`: Ed25519 public key bytes.
/// - `signature`: Ed25519 signature over domain-separated canonical bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayConvergenceReceiptV1 {
    /// Unique receipt identifier.
    #[serde(deserialize_with = "deser_receipt_id")]
    pub receipt_id: String,
    /// Boundary identifier (must match evaluation context).
    #[serde(deserialize_with = "deser_boundary_id")]
    pub boundary_id: String,
    /// Digest of the backlog state at convergence evaluation.
    pub backlog_digest: Hash,
    /// Tick marking the end of the replay convergence horizon.
    pub replay_horizon_tick: u64,
    /// Whether replay converged idempotently within the horizon.
    pub converged: bool,
    /// Time authority reference hash (HTF binding).
    pub time_authority_ref: Hash,
    /// HTF evaluation window reference hash.
    pub window_ref: Hash,
    /// Caller-provided digest of external content (not self-referential).
    ///
    /// This hash covers the external payload that this receipt attests to.
    /// It is NOT a hash of the receipt itself. Integrity is protected by the
    /// Ed25519 signature over canonical bytes, which includes `content_hash`.
    /// The non-zero check in `validate()` prevents accidental omission.
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

impl ReplayConvergenceReceiptV1 {
    /// Creates and signs a replay convergence receipt.
    ///
    /// String fields are validated for length BEFORE allocation to prevent
    /// unbounded memory allocation from oversized inputs.
    ///
    /// # Errors
    ///
    /// Returns an error if any field fails validation or signing fails.
    #[allow(clippy::too_many_arguments)]
    pub fn create_signed(
        receipt_id: &str,
        boundary_id: &str,
        backlog_digest: Hash,
        replay_horizon_tick: u64,
        converged: bool,
        time_authority_ref: Hash,
        window_ref: Hash,
        content_hash: Hash,
        signer_actor_id: &str,
        signer: &Signer,
    ) -> Result<Self, ReplayRecoveryError> {
        // Validate length BEFORE allocating to prevent DoS via oversized input.
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
            REPLAY_CONVERGENCE_RECEIPT_PREFIX,
            &receipt.canonical_bytes(),
        );
        receipt.signature = sig.to_bytes();
        Ok(receipt)
    }

    /// Returns canonical bytes for signing/verification.
    ///
    /// Format: length-prefixed strings + fixed-size fields, all big-endian.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        // Fixed-size fields: backlog_digest(32) + tick(8) + converged(1) +
        // time_authority_ref(32) + window_ref(32) + content_hash(32) = 137
        // Three length-prefixed strings: 3 * 4 = 12 bytes of length headers
        let estimated_size =
            137 + 12 + self.receipt_id.len() + self.boundary_id.len() + self.signer_actor_id.len();
        let mut bytes = Vec::with_capacity(estimated_size);

        bytes.extend_from_slice(&(self.receipt_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.receipt_id.as_bytes());

        bytes.extend_from_slice(&(self.boundary_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.boundary_id.as_bytes());

        bytes.extend_from_slice(&self.backlog_digest);
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
    pub fn verify_signature(&self) -> Result<(), ReplayRecoveryError> {
        if self.signer_key == [0u8; 32] {
            return Err(ReplayRecoveryError::SignatureError {
                detail: DENY_REPLAY_RECEIPT_SIGNER_ZERO.to_string(),
            });
        }

        let key = parse_verifying_key(&self.signer_key).map_err(|e: SignerError| {
            ReplayRecoveryError::SignatureError {
                detail: e.to_string(),
            }
        })?;

        let sig = parse_signature(&self.signature).map_err(|e: SignerError| {
            ReplayRecoveryError::SignatureError {
                detail: e.to_string(),
            }
        })?;

        verify_with_domain(
            &key,
            REPLAY_CONVERGENCE_RECEIPT_PREFIX,
            &self.canonical_bytes(),
            &sig,
        )
        .map_err(|e: SignerError| ReplayRecoveryError::SignatureError {
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
            return Err(DENY_REPLAY_RECEIPT_ID_INVALID);
        }
        if self.boundary_id.is_empty() || self.boundary_id.len() > MAX_BOUNDARY_ID_LENGTH {
            return Err(DENY_REPLAY_RECEIPT_BOUNDARY_ID_EMPTY);
        }
        if is_zero_hash(&self.time_authority_ref) {
            return Err(DENY_REPLAY_RECEIPT_TIME_AUTH_ZERO);
        }
        if is_zero_hash(&self.window_ref) {
            return Err(DENY_REPLAY_RECEIPT_WINDOW_ZERO);
        }
        if is_zero_hash(&self.content_hash) {
            return Err(DENY_REPLAY_RECEIPT_HASH_ZERO);
        }
        if self.signer_key == [0u8; 32] {
            return Err(DENY_REPLAY_RECEIPT_SIGNER_ZERO);
        }
        if self.signature.ct_eq(&[0u8; 64]).unwrap_u8() == 1 {
            return Err(DENY_REPLAY_RECEIPT_SIGNATURE_INVALID);
        }
        Ok(())
    }
}

// ============================================================================
// RecoveryAdmissibilityReceiptV1
// ============================================================================

/// Durable, signed receipt proving recovery admissibility for a partial-loss
/// rebuild within an HTF window.
///
/// Implements `RecoveryAdmissibilityReceiptV1` from RFC-0029 REQ-0005.
/// Each receipt is domain-separated and Ed25519-signed, binding a recovery
/// admissibility decision to specific time authority and evaluation window.
///
/// # Fields
///
/// - `receipt_id`: unique identifier for this receipt instance.
/// - `boundary_id`: boundary context.
/// - `recovery_scope_digest`: digest of the recovery scope (partial-loss
///   rebuild boundary).
/// - `admitted`: whether recovery is admissible within the window.
/// - `time_authority_ref`: hash of the time authority envelope.
/// - `window_ref`: hash of the HTF evaluation window.
/// - `content_hash`: content-addressed hash of the receipt payload.
/// - `signer_actor_id`: identity of the signing actor.
/// - `signer_key`: Ed25519 public key bytes.
/// - `signature`: Ed25519 signature over domain-separated canonical bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryAdmissibilityReceiptV1 {
    /// Unique receipt identifier.
    #[serde(deserialize_with = "deser_receipt_id")]
    pub receipt_id: String,
    /// Boundary identifier.
    #[serde(deserialize_with = "deser_boundary_id")]
    pub boundary_id: String,
    /// Digest of the recovery scope.
    pub recovery_scope_digest: Hash,
    /// Whether recovery is admissible within the window.
    pub admitted: bool,
    /// Time authority reference hash (HTF binding).
    pub time_authority_ref: Hash,
    /// HTF evaluation window reference hash.
    pub window_ref: Hash,
    /// Caller-provided digest of external content (not self-referential).
    ///
    /// This hash covers the external payload that this receipt attests to.
    /// It is NOT a hash of the receipt itself. Integrity is protected by the
    /// Ed25519 signature over canonical bytes, which includes `content_hash`.
    /// The non-zero check in `validate()` prevents accidental omission.
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

impl RecoveryAdmissibilityReceiptV1 {
    /// Creates and signs a recovery admissibility receipt.
    ///
    /// String fields are validated for length BEFORE allocation to prevent
    /// unbounded memory allocation from oversized inputs.
    ///
    /// # Errors
    ///
    /// Returns an error if any field fails validation or signing fails.
    #[allow(clippy::too_many_arguments)]
    pub fn create_signed(
        receipt_id: &str,
        boundary_id: &str,
        recovery_scope_digest: Hash,
        admitted: bool,
        time_authority_ref: Hash,
        window_ref: Hash,
        content_hash: Hash,
        signer_actor_id: &str,
        signer: &Signer,
    ) -> Result<Self, ReplayRecoveryError> {
        // Validate length BEFORE allocating to prevent DoS via oversized input.
        validate_required_string("receipt_id", receipt_id, MAX_RECEIPT_ID_LENGTH)?;
        validate_required_string("boundary_id", boundary_id, MAX_BOUNDARY_ID_LENGTH)?;
        validate_required_string("signer_actor_id", signer_actor_id, MAX_ACTOR_ID_LENGTH)?;
        validate_non_zero_hash("recovery_scope_digest", &recovery_scope_digest)?;
        validate_non_zero_hash("time_authority_ref", &time_authority_ref)?;
        validate_non_zero_hash("window_ref", &window_ref)?;
        validate_non_zero_hash("content_hash", &content_hash)?;

        let mut receipt = Self {
            receipt_id: receipt_id.to_string(),
            boundary_id: boundary_id.to_string(),
            recovery_scope_digest,
            admitted,
            time_authority_ref,
            window_ref,
            content_hash,
            signer_actor_id: signer_actor_id.to_string(),
            signer_key: signer.public_key_bytes(),
            signature: [0u8; 64],
        };

        let sig = sign_with_domain(
            signer,
            RECOVERY_ADMISSIBILITY_RECEIPT_PREFIX,
            &receipt.canonical_bytes(),
        );
        receipt.signature = sig.to_bytes();
        Ok(receipt)
    }

    /// Returns canonical bytes for signing/verification.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        // Fixed-size fields: recovery_scope_digest(32) + admitted(1) +
        // time_authority_ref(32) + window_ref(32) + content_hash(32) = 129
        // Three length-prefixed strings: 3 * 4 = 12 bytes of length headers
        let estimated_size =
            129 + 12 + self.receipt_id.len() + self.boundary_id.len() + self.signer_actor_id.len();
        let mut bytes = Vec::with_capacity(estimated_size);

        bytes.extend_from_slice(&(self.receipt_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.receipt_id.as_bytes());

        bytes.extend_from_slice(&(self.boundary_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.boundary_id.as_bytes());

        bytes.extend_from_slice(&self.recovery_scope_digest);
        bytes.push(u8::from(self.admitted));
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
    pub fn verify_signature(&self) -> Result<(), ReplayRecoveryError> {
        if self.signer_key == [0u8; 32] {
            return Err(ReplayRecoveryError::SignatureError {
                detail: DENY_RECOVERY_RECEIPT_SIGNER_ZERO.to_string(),
            });
        }

        let key = parse_verifying_key(&self.signer_key).map_err(|e: SignerError| {
            ReplayRecoveryError::SignatureError {
                detail: e.to_string(),
            }
        })?;

        let sig = parse_signature(&self.signature).map_err(|e: SignerError| {
            ReplayRecoveryError::SignatureError {
                detail: e.to_string(),
            }
        })?;

        verify_with_domain(
            &key,
            RECOVERY_ADMISSIBILITY_RECEIPT_PREFIX,
            &self.canonical_bytes(),
            &sig,
        )
        .map_err(|e: SignerError| ReplayRecoveryError::SignatureError {
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
            return Err(DENY_RECOVERY_RECEIPT_ID_INVALID);
        }
        if self.boundary_id.is_empty() || self.boundary_id.len() > MAX_BOUNDARY_ID_LENGTH {
            return Err(DENY_RECOVERY_RECEIPT_BOUNDARY_ID_EMPTY);
        }
        if is_zero_hash(&self.time_authority_ref) {
            return Err(DENY_RECOVERY_RECEIPT_TIME_AUTH_ZERO);
        }
        if is_zero_hash(&self.window_ref) {
            return Err(DENY_RECOVERY_RECEIPT_WINDOW_ZERO);
        }
        if is_zero_hash(&self.content_hash) {
            return Err(DENY_RECOVERY_RECEIPT_HASH_ZERO);
        }
        if self.signer_key == [0u8; 32] {
            return Err(DENY_RECOVERY_RECEIPT_SIGNER_ZERO);
        }
        if self.signature.ct_eq(&[0u8; 64]).unwrap_u8() == 1 {
            return Err(DENY_RECOVERY_RECEIPT_SIGNATURE_INVALID);
        }
        Ok(())
    }
}

// ============================================================================
// TP-EIO29-004: replay_convergence_horizon_satisfied
// ============================================================================

/// Replay convergence horizon reference for TP-EIO29-004 evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayConvergenceHorizonRef {
    /// Whether the horizon reference is resolved.
    pub resolved: bool,
    /// End tick of the replay convergence horizon.
    pub horizon_end_tick: u64,
    /// Hash binding of the horizon reference.
    pub horizon_digest: Hash,
}

/// Backlog state snapshot for TP-EIO29-004 evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BacklogState {
    /// Whether the backlog is fully resolved.
    pub resolved: bool,
    /// Digest of the backlog state.
    pub backlog_digest: Hash,
    /// Current tick of the backlog evaluation.
    pub current_tick: u64,
}

/// Deny defect emitted when a replay-recovery admission check fails.
///
/// Provides auditable structured evidence for why an admission was denied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayRecoveryDenyDefect {
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

/// Validates TP-EIO29-004: replay convergence horizon satisfied.
///
/// Checks that:
/// 1. The replay convergence horizon reference is present and resolved.
/// 2. Replay receipts are present and within bounds.
/// 3. The backlog state is resolved.
/// 4. All receipts have valid structural form.
/// 5. All receipts pass Ed25519 signature verification.
/// 6. All receipt signers are in the trusted signer set (constant-time).
/// 7. All receipts match the evaluation boundary.
/// 8. All receipts bind to the expected time authority, window, and backlog
///    context (constant-time comparison to prevent cross-context replay).
/// 9. The backlog converged idempotently within the horizon.
///
/// # Errors
///
/// Returns a stable deny reason string for any violation. All unknown
/// or missing states fail closed.
#[allow(clippy::too_many_arguments)]
pub fn validate_replay_convergence_tp004(
    horizon: Option<&ReplayConvergenceHorizonRef>,
    backlog: Option<&BacklogState>,
    receipts: &[ReplayConvergenceReceiptV1],
    eval_boundary_id: &str,
    trusted_signers: &[[u8; 32]],
    expected_time_authority_ref: &Hash,
    expected_window_ref: &Hash,
) -> Result<(), &'static str> {
    // Fail-closed: missing horizon reference.
    let horizon = horizon.ok_or(DENY_REPLAY_HORIZON_UNRESOLVED)?;

    if !horizon.resolved {
        return Err(DENY_REPLAY_HORIZON_UNRESOLVED);
    }

    if is_zero_hash(&horizon.horizon_digest) {
        return Err(DENY_REPLAY_HORIZON_UNRESOLVED);
    }

    // Fail-closed: missing backlog state.
    let backlog = backlog.ok_or(DENY_BACKLOG_UNRESOLVED)?;

    if !backlog.resolved {
        return Err(DENY_BACKLOG_UNRESOLVED);
    }

    if is_zero_hash(&backlog.backlog_digest) {
        return Err(DENY_BACKLOG_UNRESOLVED);
    }

    // Bounded receipt count.
    if receipts.len() > MAX_REPLAY_RECEIPTS {
        return Err(DENY_REPLAY_RECEIPTS_EXCEEDED);
    }

    // Fail-closed: at least one receipt must be present.
    if receipts.is_empty() {
        return Err(DENY_REPLAY_RECEIPT_MISSING);
    }

    // Validate each receipt structurally, verify signature, check trusted
    // signer, and bind to evaluation context.
    // Deduplicate by receipt_id to prevent signature amplification attacks
    // (Finding 5: an attacker submitting 256 copies of the same valid receipt).
    let mut seen_receipt_ids = HashSet::new();
    for receipt in receipts {
        if !seen_receipt_ids.insert(&receipt.receipt_id) {
            return Err(DENY_REPLAY_RECEIPT_DUPLICATE_ID);
        }

        receipt.validate()?;

        // Verify Ed25519 signature (not just structural form).
        receipt
            .verify_signature()
            .map_err(|_| DENY_REPLAY_RECEIPT_SIGNATURE_INVALID)?;

        // Verify signer is in trusted set (non-short-circuiting constant-time
        // fold to prevent timing side-channel leaking signer position).
        let signer_trusted = trusted_signers.iter().fold(0u8, |acc, ts| {
            acc | ts.ct_eq(&receipt.signer_key).unwrap_u8()
        });
        if signer_trusted == 0 {
            return Err(DENY_REPLAY_RECEIPT_SIGNER_UNTRUSTED);
        }

        if receipt.boundary_id != eval_boundary_id {
            return Err(DENY_REPLAY_RECEIPT_BOUNDARY_MISMATCH);
        }

        // Context binding: receipt time_authority_ref must match expected
        // (constant-time to prevent cross-context replay).
        if receipt
            .time_authority_ref
            .ct_eq(expected_time_authority_ref)
            .unwrap_u8()
            == 0
        {
            return Err(DENY_REPLAY_RECEIPT_TIME_AUTH_MISMATCH);
        }

        // Context binding: receipt window_ref must match expected.
        if receipt.window_ref.ct_eq(expected_window_ref).unwrap_u8() == 0 {
            return Err(DENY_REPLAY_RECEIPT_WINDOW_MISMATCH);
        }

        // Context binding: receipt backlog_digest must match backlog state.
        if receipt
            .backlog_digest
            .ct_eq(&backlog.backlog_digest)
            .unwrap_u8()
            == 0
        {
            return Err(DENY_REPLAY_RECEIPT_BACKLOG_MISMATCH);
        }

        // Receipt must be within the replay horizon.
        if receipt.replay_horizon_tick > horizon.horizon_end_tick {
            return Err(DENY_STALE_REPLAY_RECEIPT);
        }

        // Receipt must have converged.
        if !receipt.converged {
            return Err(DENY_BACKLOG_UNRESOLVED);
        }
    }

    Ok(())
}

// ============================================================================
// TP-EIO29-007: replay_idempotency_monotone
// ============================================================================

/// Adjacent-window pair for TP-EIO29-007 evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdjacentWindowPair {
    /// Earlier window tick range.
    pub w_t_start: u64,
    /// Earlier window tick end.
    pub w_t_end: u64,
    /// Later window tick range.
    pub w_t1_start: u64,
    /// Later window tick end.
    pub w_t1_end: u64,
}

impl AdjacentWindowPair {
    /// Checks whether the two windows are adjacent.
    ///
    /// Windows are adjacent if the later window starts exactly one tick after
    /// the earlier window ends (no gap, no overlap).
    #[must_use]
    pub const fn is_adjacent(&self) -> bool {
        // Guard: earlier window must end before later window starts.
        if self.w_t_end >= self.w_t1_start {
            return false;
        }
        // Adjacent: gap of exactly 1 tick.
        self.w_t1_start == self.w_t_end.saturating_add(1)
    }
}

/// Validates TP-EIO29-007: replay idempotency monotone.
///
/// Checks that:
/// 1. Windows are adjacent.
/// 2. No revoked effect is present in the later window.
/// 3. No authoritative effect in the earlier window appears in the later window
///    (dedup closure).
/// 4. All effect identity digests are non-zero.
///
/// # Errors
///
/// Returns a stable deny reason string for any violation. Unresolved
/// effect identities and unknown state fail closed.
pub fn validate_replay_idempotency_tp007(
    windows: &AdjacentWindowPair,
    effects_t: &[Hash],
    effects_t1: &[Hash],
    revoked_t1: &[Hash],
) -> Result<(), &'static str> {
    // Bounded input validation.
    if effects_t.len() > MAX_EFFECT_IDENTITIES {
        return Err(DENY_EFFECT_SET_EXCEEDED);
    }
    if effects_t1.len() > MAX_EFFECT_IDENTITIES {
        return Err(DENY_EFFECT_SET_EXCEEDED);
    }
    if revoked_t1.len() > MAX_REVOKED_EFFECTS {
        return Err(DENY_REVOKED_SET_EXCEEDED);
    }

    // Adjacency check.
    if !windows.is_adjacent() {
        return Err(DENY_WINDOWS_NOT_ADJACENT);
    }

    // Validate all effect identity digests are non-zero.
    for effect in effects_t {
        if is_zero_hash(effect) {
            return Err(DENY_EFFECT_IDENTITY_ZERO);
        }
    }
    for effect in effects_t1 {
        if is_zero_hash(effect) {
            return Err(DENY_EFFECT_IDENTITY_ZERO);
        }
    }
    for effect in revoked_t1 {
        if is_zero_hash(effect) {
            return Err(DENY_EFFECT_IDENTITY_ZERO);
        }
    }

    // Build HashSet of later-window effects for O(N) lookups instead of O(N^2).
    // Effect identity digests are public evidence hashes, not secrets, so
    // constant-time comparison is not required (no timing side-channel threat).
    let effects_t1_set: HashSet<[u8; 32]> = effects_t1.iter().copied().collect();

    // TP-EIO29-007 clause: forall e in Rev_t1, e notin E_t1
    // Revoked effects must not appear in the later window.
    for revoked in revoked_t1 {
        if effects_t1_set.contains(revoked) {
            return Err(DENY_REVOKED_EFFECT_IN_LATER_WINDOW);
        }
    }

    // TP-EIO29-007 clause: no duplicate authoritative effects across windows.
    // effects_in_later_window_do_not_duplicate_authoritative_outcome(E_t, E_t1)
    for e_earlier in effects_t {
        if effects_t1_set.contains(e_earlier) {
            return Err(DENY_DUPLICATE_AUTHORITATIVE_EFFECT);
        }
    }

    Ok(())
}

// ============================================================================
// Combined evaluation
// ============================================================================

/// Verdict for a replay-recovery admission evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayRecoveryVerdict {
    /// Admission allowed.
    Allow,
    /// Admission denied with structured defect.
    Deny,
}

/// Decision from a replay-recovery admission evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayRecoveryDecision {
    /// Verdict of the admission evaluation.
    pub verdict: ReplayRecoveryVerdict,
    /// Deny defect (present when verdict is `Deny`).
    pub defect: Option<ReplayRecoveryDenyDefect>,
    /// Temporal predicate results: (`predicate_id`, passed).
    pub predicate_results: Vec<(TemporalPredicateId, bool)>,
}

impl ReplayRecoveryDecision {
    /// Creates an allow decision with predicate results.
    #[must_use]
    const fn allow(predicate_results: Vec<(TemporalPredicateId, bool)>) -> Self {
        Self {
            verdict: ReplayRecoveryVerdict::Allow,
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
            verdict: ReplayRecoveryVerdict::Deny,
            defect: Some(ReplayRecoveryDenyDefect {
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

/// Evaluates replay-recovery admission for a given evaluation context.
///
/// This is the top-level evaluator that checks TP-EIO29-004 (replay
/// convergence), TP-EIO29-007 (idempotency monotone) when the caller
/// declares adjacent windows via [`IdempotencyMode::Adjacent`], and
/// TP-EIO29-009 (recovery admissibility) when the caller declares active
/// recovery via [`RecoveryMode::Active`].
///
/// # Arguments
///
/// - `horizon`: replay convergence horizon reference.
/// - `backlog`: current backlog state.
/// - `receipts`: replay convergence receipts.
/// - `eval_boundary_id`: boundary identifier for this evaluation.
/// - `eval_tick`: current tick for deny defect reporting.
/// - `envelope_hash`: time authority envelope hash for defect reporting.
/// - `window_ref_hash`: window reference hash for defect reporting.
/// - `trusted_signers`: trusted signer public keys for receipt verification.
/// - `idempotency`: typed mode indicating whether TP-EIO29-007 applies.
/// - `recovery`: typed mode indicating whether TP-EIO29-009 applies.
///
/// # Returns
///
/// A [`ReplayRecoveryDecision`] with verdict and structured defect.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn evaluate_replay_recovery(
    horizon: Option<&ReplayConvergenceHorizonRef>,
    backlog: Option<&BacklogState>,
    receipts: &[ReplayConvergenceReceiptV1],
    eval_boundary_id: &str,
    eval_tick: u64,
    envelope_hash: Hash,
    window_ref_hash: Hash,
    trusted_signers: &[[u8; 32]],
    idempotency: IdempotencyMode<'_>,
    recovery: &RecoveryMode,
) -> ReplayRecoveryDecision {
    let mut predicate_results = Vec::new();

    // TP-EIO29-004: replay convergence horizon satisfied.
    let tp004_result = validate_replay_convergence_tp004(
        horizon,
        backlog,
        receipts,
        eval_boundary_id,
        trusted_signers,
        &envelope_hash,
        &window_ref_hash,
    );
    let tp004_passed = tp004_result.is_ok();
    predicate_results.push((TemporalPredicateId::TpEio29004, tp004_passed));

    if let Err(reason) = tp004_result {
        return ReplayRecoveryDecision::deny(
            reason,
            TemporalPredicateId::TpEio29004,
            eval_boundary_id,
            eval_tick,
            envelope_hash,
            window_ref_hash,
            predicate_results,
        );
    }

    // TP-EIO29-007: replay idempotency monotone.
    // Only checked when the caller explicitly declares adjacent windows.
    // `IdempotencyMode::NotAdjacent` means the caller attests non-adjacency;
    // `IdempotencyMode::Adjacent(input)` requires the full check.
    match idempotency {
        IdempotencyMode::NotAdjacent => {
            // Caller explicitly declared non-adjacency; TP007 does not apply.
        },
        IdempotencyMode::Adjacent(idem) => {
            let tp007_result = validate_replay_idempotency_tp007(
                &idem.windows,
                &idem.effects_t,
                &idem.effects_t1,
                &idem.revoked_t1,
            );
            let tp007_passed = tp007_result.is_ok();
            predicate_results.push((TemporalPredicateId::TpEio29007, tp007_passed));

            if let Err(reason) = tp007_result {
                return ReplayRecoveryDecision::deny(
                    reason,
                    TemporalPredicateId::TpEio29007,
                    eval_boundary_id,
                    eval_tick,
                    envelope_hash,
                    window_ref_hash,
                    predicate_results,
                );
            }
        },
    }

    // TP-EIO29-009: recovery admissibility gate.
    // Only checked when the caller declares active recovery.
    // `RecoveryMode::NotRecovering` means TP-EIO29-009 does not apply.
    // `RecoveryMode::Active(input)` requires a valid, admitted receipt.
    match recovery {
        RecoveryMode::NotRecovering => {
            // System is not recovering; TP-EIO29-009 does not apply.
        },
        RecoveryMode::Active(input) => {
            let tp009_result = validate_recovery_admissibility(input, eval_boundary_id);
            let tp009_passed = tp009_result.is_ok();
            predicate_results.push((TemporalPredicateId::TpEio29009, tp009_passed));

            if let Err(reason) = tp009_result {
                return ReplayRecoveryDecision::deny(
                    reason,
                    TemporalPredicateId::TpEio29009,
                    eval_boundary_id,
                    eval_tick,
                    envelope_hash,
                    window_ref_hash,
                    predicate_results,
                );
            }
        },
    }

    ReplayRecoveryDecision::allow(predicate_results)
}

/// Input data for the TP-EIO29-007 idempotency check.
#[derive(Debug, Clone)]
pub struct IdempotencyCheckInput {
    /// Adjacent window pair.
    pub windows: AdjacentWindowPair,
    /// Admitted effect digests from the earlier window.
    pub effects_t: Vec<Hash>,
    /// Admitted effect digests from the later window.
    pub effects_t1: Vec<Hash>,
    /// Revoked effect digests in the later window.
    pub revoked_t1: Vec<Hash>,
}

/// Typed mode for TP-EIO29-007 idempotency evaluation.
///
/// Replaces `Option<&IdempotencyCheckInput>` to prevent fail-open bypass.
/// Callers must explicitly declare whether windows are adjacent (requiring
/// the full idempotency check) or not adjacent (TP-EIO29-007 does not apply).
///
/// This design follows CTR-2623 (no boolean blindness) and CTR-2617
/// (fail-closed distributed capabilities): ambiguous optional parameters on
/// security paths must resolve to deny, not allow.
#[derive(Debug, Clone, Copy)]
pub enum IdempotencyMode<'a> {
    /// Windows are not adjacent; TP-EIO29-007 does not apply.
    NotAdjacent,
    /// Windows are adjacent; idempotency check is required.
    Adjacent(&'a IdempotencyCheckInput),
}

// ============================================================================
// Recovery admissibility (TP-EIO29-009)
// ============================================================================

/// Input data for the recovery admissibility check.
#[derive(Debug, Clone)]
pub struct RecoveryCheckInput {
    /// Recovery admissibility receipts.
    pub receipts: Vec<RecoveryAdmissibilityReceiptV1>,
    /// Trusted signer public keys for receipt verification.
    pub trusted_signers: Vec<[u8; 32]>,
    /// Expected time authority reference hash.
    pub expected_time_authority_ref: Hash,
    /// Expected window reference hash.
    pub expected_window_ref: Hash,
}

/// Typed mode for recovery admissibility evaluation.
///
/// Callers must explicitly declare whether recovery is active. When active,
/// the full admissibility gate is enforced (fail-closed). When not recovering,
/// the check is skipped.
///
/// This prevents fail-open bypass via `Option<&RecoveryCheckInput>`.
#[derive(Debug, Clone)]
pub enum RecoveryMode {
    /// System is in active recovery; admissibility check is required.
    Active(RecoveryCheckInput),
    /// System is not recovering; TP-EIO29-009 does not apply.
    NotRecovering,
}

/// Validates recovery admissibility: at least one valid, admitted
/// `RecoveryAdmissibilityReceiptV1` must be present when recovery is active.
///
/// Checks:
/// 1. At least one receipt is present (fail-closed).
/// 2. Each receipt passes structural validation.
/// 3. Each receipt passes Ed25519 signature verification.
/// 4. Each receipt signer is in the trusted set.
/// 5. Receipt context binds to expected time authority and window refs.
/// 6. Receipt boundary matches the evaluation boundary.
/// 7. At least one receipt has `admitted == true`.
///
/// # Errors
///
/// Returns a stable deny reason string for any violation.
pub fn validate_recovery_admissibility(
    input: &RecoveryCheckInput,
    eval_boundary_id: &str,
) -> Result<(), &'static str> {
    if input.receipts.is_empty() {
        return Err(DENY_RECOVERY_RECEIPT_MISSING);
    }

    if input.receipts.len() > MAX_REPLAY_RECEIPTS {
        return Err(DENY_REPLAY_RECEIPTS_EXCEEDED);
    }

    let mut any_admitted = false;

    for receipt in &input.receipts {
        receipt.validate()?;

        // Verify Ed25519 signature.
        receipt
            .verify_signature()
            .map_err(|_| DENY_RECOVERY_RECEIPT_SIGNATURE_INVALID)?;

        // Verify signer is in trusted set (non-short-circuiting constant-time
        // fold to prevent timing side-channel leaking signer position).
        let signer_trusted = input.trusted_signers.iter().fold(0u8, |acc, ts| {
            acc | ts.ct_eq(&receipt.signer_key).unwrap_u8()
        });
        if signer_trusted == 0 {
            return Err(DENY_RECOVERY_RECEIPT_SIGNER_UNTRUSTED);
        }

        // Context binding: boundary must match evaluation.
        if receipt.boundary_id != eval_boundary_id {
            return Err(DENY_RECOVERY_RECEIPT_BOUNDARY_MISMATCH);
        }

        // Context binding: time authority reference must match.
        if receipt
            .time_authority_ref
            .ct_eq(&input.expected_time_authority_ref)
            .unwrap_u8()
            == 0
        {
            return Err(DENY_RECOVERY_RECEIPT_TIME_AUTH_MISMATCH);
        }

        // Context binding: window reference must match.
        if receipt
            .window_ref
            .ct_eq(&input.expected_window_ref)
            .unwrap_u8()
            == 0
        {
            return Err(DENY_RECOVERY_RECEIPT_WINDOW_MISMATCH);
        }

        if receipt.admitted {
            any_admitted = true;
        }
    }

    // Fail-closed: at least one receipt must have admitted == true.
    if !any_admitted {
        return Err(DENY_RECOVERY_RECEIPT_NOT_ADMITTED);
    }

    Ok(())
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
) -> Result<(), ReplayRecoveryError> {
    if value.is_empty() {
        return Err(ReplayRecoveryError::RequiredFieldMissing {
            field: field.to_string(),
        });
    }
    if value.len() > max_len {
        return Err(ReplayRecoveryError::FieldTooLong {
            field: field.to_string(),
            actual: value.len(),
            max: max_len,
        });
    }
    Ok(())
}

fn validate_non_zero_hash(field: &str, hash: &Hash) -> Result<(), ReplayRecoveryError> {
    if is_zero_hash(hash) {
        return Err(ReplayRecoveryError::ZeroHash {
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

    /// Standard trusted signer set containing the given signer's public key.
    fn trusted_signers_for(signer: &Signer) -> [[u8; 32]; 1] {
        [signer.public_key_bytes()]
    }

    /// Expected time authority ref used in valid receipts.
    fn expected_time_authority_ref() -> Hash {
        test_hash(0xBB)
    }

    /// Expected window ref used in valid receipts.
    fn expected_window_ref() -> Hash {
        test_hash(0xCC)
    }

    fn valid_replay_receipt(signer: &Signer) -> ReplayConvergenceReceiptV1 {
        ReplayConvergenceReceiptV1::create_signed(
            "rcpt-001",
            "boundary-1",
            // backlog_digest must match valid_backlog().backlog_digest for
            // context binding checks.
            test_hash(0xFF),
            1000,
            true,
            test_hash(0xBB),
            test_hash(0xCC),
            test_hash(0xDD),
            "actor-1",
            signer,
        )
        .expect("valid receipt")
    }

    fn valid_recovery_receipt(signer: &Signer) -> RecoveryAdmissibilityReceiptV1 {
        RecoveryAdmissibilityReceiptV1::create_signed(
            "rcpt-002",
            "boundary-1",
            test_hash(0xAA),
            true,
            test_hash(0xBB),
            test_hash(0xCC),
            test_hash(0xDD),
            "actor-1",
            signer,
        )
        .expect("valid receipt")
    }

    fn valid_horizon() -> ReplayConvergenceHorizonRef {
        ReplayConvergenceHorizonRef {
            resolved: true,
            horizon_end_tick: 2000,
            horizon_digest: test_hash(0xEE),
        }
    }

    fn valid_backlog() -> BacklogState {
        BacklogState {
            resolved: true,
            backlog_digest: test_hash(0xFF),
            current_tick: 500,
        }
    }

    // ========================================================================
    // ReplayConvergenceReceiptV1 -- creation and signing
    // ========================================================================

    #[test]
    fn replay_receipt_create_and_sign_roundtrip() {
        let signer = valid_signer();
        let receipt = valid_replay_receipt(&signer);
        assert!(receipt.verify_signature().is_ok());
        assert!(receipt.validate().is_ok());
        assert_eq!(receipt.receipt_id, "rcpt-001");
        assert_eq!(receipt.boundary_id, "boundary-1");
        assert!(receipt.converged);
    }

    #[test]
    fn replay_receipt_deterministic_signature() {
        let signer = valid_signer();
        let r1 = valid_replay_receipt(&signer);
        let r2 = valid_replay_receipt(&signer);
        assert_eq!(r1.signature, r2.signature);
    }

    #[test]
    fn replay_receipt_wrong_key_fails_verification() {
        let signer1 = valid_signer();
        let signer2 = valid_signer();
        let receipt = valid_replay_receipt(&signer1);

        let mut tampered = receipt;
        tampered.signer_key = signer2.public_key_bytes();
        assert!(tampered.verify_signature().is_err());
    }

    #[test]
    fn replay_receipt_tampered_data_fails_verification() {
        let signer = valid_signer();
        let mut receipt = valid_replay_receipt(&signer);
        receipt.boundary_id = "tampered".to_string();
        assert!(receipt.verify_signature().is_err());
    }

    #[test]
    fn replay_receipt_zero_signer_key_denied() {
        let signer = valid_signer();
        let mut receipt = valid_replay_receipt(&signer);
        receipt.signer_key = [0u8; 32];
        assert!(receipt.verify_signature().is_err());
        assert_eq!(
            receipt.validate().unwrap_err(),
            DENY_REPLAY_RECEIPT_SIGNER_ZERO
        );
    }

    #[test]
    fn replay_receipt_zero_signature_denied() {
        let signer = valid_signer();
        let mut receipt = valid_replay_receipt(&signer);
        receipt.signature = [0u8; 64];
        assert_eq!(
            receipt.validate().unwrap_err(),
            DENY_REPLAY_RECEIPT_SIGNATURE_INVALID
        );
    }

    #[test]
    fn replay_receipt_empty_receipt_id_denied() {
        let signer = valid_signer();
        let result = ReplayConvergenceReceiptV1::create_signed(
            "",
            "boundary-1",
            test_hash(0xFF),
            1000,
            true,
            test_hash(0xBB),
            test_hash(0xCC),
            test_hash(0xDD),
            "actor-1",
            &signer,
        );
        assert!(result.is_err());
    }

    #[test]
    fn replay_receipt_oversized_receipt_id_denied() {
        let signer = valid_signer();
        let big_id = "x".repeat(MAX_RECEIPT_ID_LENGTH + 1);
        let result = ReplayConvergenceReceiptV1::create_signed(
            &big_id,
            "boundary-1",
            test_hash(0xFF),
            1000,
            true,
            test_hash(0xBB),
            test_hash(0xCC),
            test_hash(0xDD),
            "actor-1",
            &signer,
        );
        assert!(result.is_err());
    }

    #[test]
    fn replay_receipt_zero_time_authority_ref_denied() {
        let signer = valid_signer();
        let result = ReplayConvergenceReceiptV1::create_signed(
            "rcpt-001",
            "boundary-1",
            test_hash(0xFF),
            1000,
            true,
            [0u8; 32], // zero time_authority_ref
            test_hash(0xCC),
            test_hash(0xDD),
            "actor-1",
            &signer,
        );
        assert!(result.is_err());
    }

    #[test]
    fn replay_receipt_zero_window_ref_denied() {
        let signer = valid_signer();
        let result = ReplayConvergenceReceiptV1::create_signed(
            "rcpt-001",
            "boundary-1",
            test_hash(0xFF),
            1000,
            true,
            test_hash(0xBB),
            [0u8; 32], // zero window_ref
            test_hash(0xDD),
            "actor-1",
            &signer,
        );
        assert!(result.is_err());
    }

    #[test]
    fn replay_receipt_zero_content_hash_denied() {
        let signer = valid_signer();
        let result = ReplayConvergenceReceiptV1::create_signed(
            "rcpt-001",
            "boundary-1",
            test_hash(0xFF),
            1000,
            true,
            test_hash(0xBB),
            test_hash(0xCC),
            [0u8; 32], // zero content_hash
            "actor-1",
            &signer,
        );
        assert!(result.is_err());
    }

    #[test]
    fn replay_receipt_zero_backlog_digest_denied() {
        let signer = valid_signer();
        let result = ReplayConvergenceReceiptV1::create_signed(
            "rcpt-001",
            "boundary-1",
            [0u8; 32], // zero backlog_digest
            1000,
            true,
            test_hash(0xBB),
            test_hash(0xCC),
            test_hash(0xDD),
            "actor-1",
            &signer,
        );
        assert!(result.is_err());
    }

    #[test]
    fn replay_receipt_serde_roundtrip() {
        let signer = valid_signer();
        let receipt = valid_replay_receipt(&signer);
        let json = serde_json::to_string(&receipt).unwrap();
        let decoded: ReplayConvergenceReceiptV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, decoded);
        assert!(decoded.verify_signature().is_ok());
    }

    #[test]
    fn replay_receipt_domain_separation_prevents_cross_type_replay() {
        let signer = valid_signer();
        let replay_receipt = valid_replay_receipt(&signer);

        // Try to verify with recovery receipt domain -- should fail.
        let key = parse_verifying_key(&replay_receipt.signer_key).unwrap();
        let sig = parse_signature(&replay_receipt.signature).unwrap();
        let result = verify_with_domain(
            &key,
            RECOVERY_ADMISSIBILITY_RECEIPT_PREFIX,
            &replay_receipt.canonical_bytes(),
            &sig,
        );
        assert!(result.is_err());
    }

    // ========================================================================
    // RecoveryAdmissibilityReceiptV1 -- creation and signing
    // ========================================================================

    #[test]
    fn recovery_receipt_create_and_sign_roundtrip() {
        let signer = valid_signer();
        let receipt = valid_recovery_receipt(&signer);
        assert!(receipt.verify_signature().is_ok());
        assert!(receipt.validate().is_ok());
        assert_eq!(receipt.receipt_id, "rcpt-002");
        assert!(receipt.admitted);
    }

    #[test]
    fn recovery_receipt_deterministic_signature() {
        let signer = valid_signer();
        let r1 = valid_recovery_receipt(&signer);
        let r2 = valid_recovery_receipt(&signer);
        assert_eq!(r1.signature, r2.signature);
    }

    #[test]
    fn recovery_receipt_wrong_key_fails_verification() {
        let signer1 = valid_signer();
        let signer2 = valid_signer();
        let receipt = valid_recovery_receipt(&signer1);
        let mut tampered = receipt;
        tampered.signer_key = signer2.public_key_bytes();
        assert!(tampered.verify_signature().is_err());
    }

    #[test]
    fn recovery_receipt_tampered_data_fails_verification() {
        let signer = valid_signer();
        let mut receipt = valid_recovery_receipt(&signer);
        receipt.boundary_id = "tampered".to_string();
        assert!(receipt.verify_signature().is_err());
    }

    #[test]
    fn recovery_receipt_zero_signer_key_denied() {
        let signer = valid_signer();
        let mut receipt = valid_recovery_receipt(&signer);
        receipt.signer_key = [0u8; 32];
        assert!(receipt.verify_signature().is_err());
        assert_eq!(
            receipt.validate().unwrap_err(),
            DENY_RECOVERY_RECEIPT_SIGNER_ZERO
        );
    }

    #[test]
    fn recovery_receipt_zero_signature_denied() {
        let signer = valid_signer();
        let mut receipt = valid_recovery_receipt(&signer);
        receipt.signature = [0u8; 64];
        assert_eq!(
            receipt.validate().unwrap_err(),
            DENY_RECOVERY_RECEIPT_SIGNATURE_INVALID
        );
    }

    #[test]
    fn recovery_receipt_serde_roundtrip() {
        let signer = valid_signer();
        let receipt = valid_recovery_receipt(&signer);
        let json = serde_json::to_string(&receipt).unwrap();
        let decoded: RecoveryAdmissibilityReceiptV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, decoded);
        assert!(decoded.verify_signature().is_ok());
    }

    #[test]
    fn recovery_receipt_domain_separation_prevents_cross_type_replay() {
        let signer = valid_signer();
        let recovery_receipt = valid_recovery_receipt(&signer);

        // Try to verify with replay receipt domain -- should fail.
        let key = parse_verifying_key(&recovery_receipt.signer_key).unwrap();
        let sig = parse_signature(&recovery_receipt.signature).unwrap();
        let result = verify_with_domain(
            &key,
            REPLAY_CONVERGENCE_RECEIPT_PREFIX,
            &recovery_receipt.canonical_bytes(),
            &sig,
        );
        assert!(result.is_err());
    }

    #[test]
    fn recovery_receipt_empty_receipt_id_denied() {
        let signer = valid_signer();
        let result = RecoveryAdmissibilityReceiptV1::create_signed(
            "",
            "boundary-1",
            test_hash(0xAA),
            true,
            test_hash(0xBB),
            test_hash(0xCC),
            test_hash(0xDD),
            "actor-1",
            &signer,
        );
        assert!(result.is_err());
    }

    #[test]
    fn recovery_receipt_zero_time_authority_ref_denied() {
        let signer = valid_signer();
        let result = RecoveryAdmissibilityReceiptV1::create_signed(
            "rcpt-002",
            "boundary-1",
            test_hash(0xAA),
            true,
            [0u8; 32],
            test_hash(0xCC),
            test_hash(0xDD),
            "actor-1",
            &signer,
        );
        assert!(result.is_err());
    }

    // ========================================================================
    // TP-EIO29-004: replay convergence horizon satisfied
    // ========================================================================

    #[test]
    fn tp004_valid_inputs_pass() {
        let signer = valid_signer();
        let receipt = valid_replay_receipt(&signer);
        let ts = trusted_signers_for(&signer);
        let result = validate_replay_convergence_tp004(
            Some(&valid_horizon()),
            Some(&valid_backlog()),
            &[receipt],
            "boundary-1",
            &ts,
            &expected_time_authority_ref(),
            &expected_window_ref(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn tp004_missing_horizon_denies() {
        let signer = valid_signer();
        let receipt = valid_replay_receipt(&signer);
        let ts = trusted_signers_for(&signer);
        let result = validate_replay_convergence_tp004(
            None,
            Some(&valid_backlog()),
            &[receipt],
            "boundary-1",
            &ts,
            &expected_time_authority_ref(),
            &expected_window_ref(),
        );
        assert_eq!(result.unwrap_err(), DENY_REPLAY_HORIZON_UNRESOLVED);
    }

    #[test]
    fn tp004_unresolved_horizon_denies() {
        let signer = valid_signer();
        let receipt = valid_replay_receipt(&signer);
        let ts = trusted_signers_for(&signer);
        let mut horizon = valid_horizon();
        horizon.resolved = false;
        let result = validate_replay_convergence_tp004(
            Some(&horizon),
            Some(&valid_backlog()),
            &[receipt],
            "boundary-1",
            &ts,
            &expected_time_authority_ref(),
            &expected_window_ref(),
        );
        assert_eq!(result.unwrap_err(), DENY_REPLAY_HORIZON_UNRESOLVED);
    }

    #[test]
    fn tp004_zero_horizon_digest_denies() {
        let signer = valid_signer();
        let receipt = valid_replay_receipt(&signer);
        let ts = trusted_signers_for(&signer);
        let mut horizon = valid_horizon();
        horizon.horizon_digest = [0u8; 32];
        let result = validate_replay_convergence_tp004(
            Some(&horizon),
            Some(&valid_backlog()),
            &[receipt],
            "boundary-1",
            &ts,
            &expected_time_authority_ref(),
            &expected_window_ref(),
        );
        assert_eq!(result.unwrap_err(), DENY_REPLAY_HORIZON_UNRESOLVED);
    }

    #[test]
    fn tp004_missing_backlog_denies() {
        let signer = valid_signer();
        let receipt = valid_replay_receipt(&signer);
        let ts = trusted_signers_for(&signer);
        let result = validate_replay_convergence_tp004(
            Some(&valid_horizon()),
            None,
            &[receipt],
            "boundary-1",
            &ts,
            &expected_time_authority_ref(),
            &expected_window_ref(),
        );
        assert_eq!(result.unwrap_err(), DENY_BACKLOG_UNRESOLVED);
    }

    #[test]
    fn tp004_unresolved_backlog_denies() {
        let signer = valid_signer();
        let receipt = valid_replay_receipt(&signer);
        let ts = trusted_signers_for(&signer);
        let mut backlog = valid_backlog();
        backlog.resolved = false;
        let result = validate_replay_convergence_tp004(
            Some(&valid_horizon()),
            Some(&backlog),
            &[receipt],
            "boundary-1",
            &ts,
            &expected_time_authority_ref(),
            &expected_window_ref(),
        );
        assert_eq!(result.unwrap_err(), DENY_BACKLOG_UNRESOLVED);
    }

    #[test]
    fn tp004_zero_backlog_digest_denies() {
        let signer = valid_signer();
        let receipt = valid_replay_receipt(&signer);
        let ts = trusted_signers_for(&signer);
        let mut backlog = valid_backlog();
        backlog.backlog_digest = [0u8; 32];
        let result = validate_replay_convergence_tp004(
            Some(&valid_horizon()),
            Some(&backlog),
            &[receipt],
            "boundary-1",
            &ts,
            &expected_time_authority_ref(),
            &expected_window_ref(),
        );
        assert_eq!(result.unwrap_err(), DENY_BACKLOG_UNRESOLVED);
    }

    #[test]
    fn tp004_empty_receipts_denies() {
        let signer = valid_signer();
        let ts = trusted_signers_for(&signer);
        let result = validate_replay_convergence_tp004(
            Some(&valid_horizon()),
            Some(&valid_backlog()),
            &[],
            "boundary-1",
            &ts,
            &expected_time_authority_ref(),
            &expected_window_ref(),
        );
        assert_eq!(result.unwrap_err(), DENY_REPLAY_RECEIPT_MISSING);
    }

    #[test]
    fn tp004_receipt_boundary_mismatch_denies() {
        let signer = valid_signer();
        let receipt = valid_replay_receipt(&signer);
        let ts = trusted_signers_for(&signer);
        let result = validate_replay_convergence_tp004(
            Some(&valid_horizon()),
            Some(&valid_backlog()),
            &[receipt],
            "wrong-boundary",
            &ts,
            &expected_time_authority_ref(),
            &expected_window_ref(),
        );
        assert_eq!(result.unwrap_err(), DENY_REPLAY_RECEIPT_BOUNDARY_MISMATCH);
    }

    #[test]
    fn tp004_receipt_beyond_horizon_denies() {
        let signer = valid_signer();
        let ts = trusted_signers_for(&signer);
        let receipt = ReplayConvergenceReceiptV1::create_signed(
            "rcpt-stale",
            "boundary-1",
            test_hash(0xFF),
            3000, // beyond horizon_end_tick=2000
            true,
            test_hash(0xBB),
            test_hash(0xCC),
            test_hash(0xDD),
            "actor-1",
            &signer,
        )
        .unwrap();
        let result = validate_replay_convergence_tp004(
            Some(&valid_horizon()),
            Some(&valid_backlog()),
            &[receipt],
            "boundary-1",
            &ts,
            &expected_time_authority_ref(),
            &expected_window_ref(),
        );
        assert_eq!(result.unwrap_err(), DENY_STALE_REPLAY_RECEIPT);
    }

    #[test]
    fn tp004_non_converged_receipt_denies() {
        let signer = valid_signer();
        let ts = trusted_signers_for(&signer);
        let receipt = ReplayConvergenceReceiptV1::create_signed(
            "rcpt-nc",
            "boundary-1",
            test_hash(0xFF),
            1000,
            false, // not converged
            test_hash(0xBB),
            test_hash(0xCC),
            test_hash(0xDD),
            "actor-1",
            &signer,
        )
        .unwrap();
        let result = validate_replay_convergence_tp004(
            Some(&valid_horizon()),
            Some(&valid_backlog()),
            &[receipt],
            "boundary-1",
            &ts,
            &expected_time_authority_ref(),
            &expected_window_ref(),
        );
        assert_eq!(result.unwrap_err(), DENY_BACKLOG_UNRESOLVED);
    }

    #[test]
    fn tp004_exceeds_max_receipts_denies() {
        let signer = valid_signer();
        let ts = trusted_signers_for(&signer);
        let receipts: Vec<_> = (0..=MAX_REPLAY_RECEIPTS)
            .map(|i| {
                ReplayConvergenceReceiptV1::create_signed(
                    &format!("rcpt-{i}"),
                    "boundary-1",
                    test_hash(0xFF),
                    1000,
                    true,
                    test_hash(0xBB),
                    test_hash(0xCC),
                    test_hash(0xDD),
                    "actor-1",
                    &signer,
                )
                .unwrap()
            })
            .collect();
        let result = validate_replay_convergence_tp004(
            Some(&valid_horizon()),
            Some(&valid_backlog()),
            &receipts,
            "boundary-1",
            &ts,
            &expected_time_authority_ref(),
            &expected_window_ref(),
        );
        assert_eq!(result.unwrap_err(), DENY_REPLAY_RECEIPTS_EXCEEDED);
    }

    // ========================================================================
    // TP004 BLOCKER fix: signature verification and trusted signer enforcement
    // ========================================================================

    #[test]
    fn tp004_forged_signature_denies() {
        let signer = valid_signer();
        let ts = trusted_signers_for(&signer);
        let mut receipt = valid_replay_receipt(&signer);
        // Tamper with a field to invalidate the signature.
        receipt.boundary_id = "tampered-boundary".to_string();
        let result = validate_replay_convergence_tp004(
            Some(&valid_horizon()),
            Some(&valid_backlog()),
            &[receipt],
            "tampered-boundary",
            &ts,
            &expected_time_authority_ref(),
            &expected_window_ref(),
        );
        assert_eq!(result.unwrap_err(), DENY_REPLAY_RECEIPT_SIGNATURE_INVALID);
    }

    #[test]
    fn tp004_untrusted_signer_denies() {
        let signer_a = valid_signer();
        let signer_b = valid_signer();
        let receipt = valid_replay_receipt(&signer_a);
        // Trust only signer_b, not signer_a.
        let ts = trusted_signers_for(&signer_b);
        let result = validate_replay_convergence_tp004(
            Some(&valid_horizon()),
            Some(&valid_backlog()),
            &[receipt],
            "boundary-1",
            &ts,
            &expected_time_authority_ref(),
            &expected_window_ref(),
        );
        assert_eq!(result.unwrap_err(), DENY_REPLAY_RECEIPT_SIGNER_UNTRUSTED);
    }

    #[test]
    fn tp004_trusted_signer_passes() {
        let signer = valid_signer();
        let receipt = valid_replay_receipt(&signer);
        let ts = trusted_signers_for(&signer);
        let result = validate_replay_convergence_tp004(
            Some(&valid_horizon()),
            Some(&valid_backlog()),
            &[receipt],
            "boundary-1",
            &ts,
            &expected_time_authority_ref(),
            &expected_window_ref(),
        );
        assert!(result.is_ok());
    }

    // ========================================================================
    // TP004 MAJOR-1 fix: context binding (cross-context replay prevention)
    // ========================================================================

    #[test]
    fn tp004_receipt_time_authority_mismatch_denies() {
        let signer = valid_signer();
        let receipt = valid_replay_receipt(&signer);
        let ts = trusted_signers_for(&signer);
        // Expected time authority does not match receipt's.
        let wrong_time_auth = test_hash(0x11);
        let result = validate_replay_convergence_tp004(
            Some(&valid_horizon()),
            Some(&valid_backlog()),
            &[receipt],
            "boundary-1",
            &ts,
            &wrong_time_auth,
            &expected_window_ref(),
        );
        assert_eq!(result.unwrap_err(), DENY_REPLAY_RECEIPT_TIME_AUTH_MISMATCH);
    }

    #[test]
    fn tp004_receipt_window_ref_mismatch_denies() {
        let signer = valid_signer();
        let receipt = valid_replay_receipt(&signer);
        let ts = trusted_signers_for(&signer);
        // Expected window ref does not match receipt's.
        let wrong_window_ref = test_hash(0x22);
        let result = validate_replay_convergence_tp004(
            Some(&valid_horizon()),
            Some(&valid_backlog()),
            &[receipt],
            "boundary-1",
            &ts,
            &expected_time_authority_ref(),
            &wrong_window_ref,
        );
        assert_eq!(result.unwrap_err(), DENY_REPLAY_RECEIPT_WINDOW_MISMATCH);
    }

    #[test]
    fn tp004_receipt_backlog_digest_mismatch_denies() {
        let signer = valid_signer();
        let ts = trusted_signers_for(&signer);
        // Create receipt with a backlog_digest that does NOT match
        // valid_backlog().backlog_digest.
        let receipt = ReplayConvergenceReceiptV1::create_signed(
            "rcpt-mismatch",
            "boundary-1",
            test_hash(0xAA), // != valid_backlog().backlog_digest (0xFF)
            1000,
            true,
            test_hash(0xBB),
            test_hash(0xCC),
            test_hash(0xDD),
            "actor-1",
            &signer,
        )
        .unwrap();
        let result = validate_replay_convergence_tp004(
            Some(&valid_horizon()),
            Some(&valid_backlog()),
            &[receipt],
            "boundary-1",
            &ts,
            &expected_time_authority_ref(),
            &expected_window_ref(),
        );
        assert_eq!(result.unwrap_err(), DENY_REPLAY_RECEIPT_BACKLOG_MISMATCH);
    }

    #[test]
    fn tp004_receipt_context_binding_all_match_passes() {
        let signer = valid_signer();
        let receipt = valid_replay_receipt(&signer);
        let ts = trusted_signers_for(&signer);
        // All context fields match: time_authority_ref, window_ref, backlog_digest.
        let result = validate_replay_convergence_tp004(
            Some(&valid_horizon()),
            Some(&valid_backlog()),
            &[receipt],
            "boundary-1",
            &ts,
            &expected_time_authority_ref(),
            &expected_window_ref(),
        );
        assert!(result.is_ok());
    }

    // ========================================================================
    // TP-EIO29-007: replay idempotency monotone
    // ========================================================================

    fn adjacent_windows() -> AdjacentWindowPair {
        AdjacentWindowPair {
            w_t_start: 0,
            w_t_end: 999,
            w_t1_start: 1000,
            w_t1_end: 1999,
        }
    }

    #[test]
    fn tp007_valid_disjoint_effects_pass() {
        let result = validate_replay_idempotency_tp007(
            &adjacent_windows(),
            &[test_hash(0x01), test_hash(0x02)],
            &[test_hash(0x03), test_hash(0x04)],
            &[], // no revoked effects
        );
        assert!(result.is_ok());
    }

    #[test]
    fn tp007_non_adjacent_windows_denies() {
        let windows = AdjacentWindowPair {
            w_t_start: 0,
            w_t_end: 999,
            w_t1_start: 1001, // gap of 2 ticks
            w_t1_end: 1999,
        };
        let result = validate_replay_idempotency_tp007(
            &windows,
            &[test_hash(0x01)],
            &[test_hash(0x03)],
            &[],
        );
        assert_eq!(result.unwrap_err(), DENY_WINDOWS_NOT_ADJACENT);
    }

    #[test]
    fn tp007_overlapping_windows_denies() {
        let windows = AdjacentWindowPair {
            w_t_start: 0,
            w_t_end: 1000,
            w_t1_start: 1000, // overlap
            w_t1_end: 1999,
        };
        let result = validate_replay_idempotency_tp007(
            &windows,
            &[test_hash(0x01)],
            &[test_hash(0x03)],
            &[],
        );
        assert_eq!(result.unwrap_err(), DENY_WINDOWS_NOT_ADJACENT);
    }

    #[test]
    fn tp007_revoked_effect_in_later_window_denies() {
        let revoked = test_hash(0x05);
        let result = validate_replay_idempotency_tp007(
            &adjacent_windows(),
            &[test_hash(0x01)],
            &[test_hash(0x03), revoked], // revoked effect appears in later window
            &[revoked],
        );
        assert_eq!(result.unwrap_err(), DENY_REVOKED_EFFECT_IN_LATER_WINDOW);
    }

    #[test]
    fn tp007_duplicate_authoritative_effect_denies() {
        let shared = test_hash(0x01);
        let result = validate_replay_idempotency_tp007(
            &adjacent_windows(),
            &[shared],
            &[shared], // same effect in both windows
            &[],
        );
        assert_eq!(result.unwrap_err(), DENY_DUPLICATE_AUTHORITATIVE_EFFECT);
    }

    #[test]
    fn tp007_zero_effect_identity_denies() {
        let result = validate_replay_idempotency_tp007(
            &adjacent_windows(),
            &[[0u8; 32]], // zero effect identity
            &[test_hash(0x03)],
            &[],
        );
        assert_eq!(result.unwrap_err(), DENY_EFFECT_IDENTITY_ZERO);
    }

    #[test]
    fn tp007_zero_effect_identity_in_later_window_denies() {
        let result = validate_replay_idempotency_tp007(
            &adjacent_windows(),
            &[test_hash(0x01)],
            &[[0u8; 32]], // zero effect identity
            &[],
        );
        assert_eq!(result.unwrap_err(), DENY_EFFECT_IDENTITY_ZERO);
    }

    #[test]
    fn tp007_zero_revoked_effect_denies() {
        let result = validate_replay_idempotency_tp007(
            &adjacent_windows(),
            &[test_hash(0x01)],
            &[test_hash(0x03)],
            &[[0u8; 32]], // zero revoked effect
        );
        assert_eq!(result.unwrap_err(), DENY_EFFECT_IDENTITY_ZERO);
    }

    #[test]
    fn tp007_exceeds_max_effects_denies() {
        #[allow(clippy::cast_possible_truncation)]
        let effects: Vec<Hash> = (0..=MAX_EFFECT_IDENTITIES)
            .map(|i| {
                let mut h = [0u8; 32];
                h[0..4].copy_from_slice(&(i as u32).to_be_bytes());
                h[31] = 0xFF;
                h
            })
            .collect();
        let result = validate_replay_idempotency_tp007(
            &adjacent_windows(),
            &effects,
            &[test_hash(0x99)],
            &[],
        );
        assert_eq!(result.unwrap_err(), DENY_EFFECT_SET_EXCEEDED);
    }

    #[test]
    fn tp007_exceeds_max_revoked_denies() {
        #[allow(clippy::cast_possible_truncation)]
        let revoked: Vec<Hash> = (0..=MAX_REVOKED_EFFECTS)
            .map(|i| {
                let mut h = [0u8; 32];
                h[0..4].copy_from_slice(&(i as u32).to_be_bytes());
                h[31] = 0xFF;
                h
            })
            .collect();
        let result = validate_replay_idempotency_tp007(
            &adjacent_windows(),
            &[test_hash(0x01)],
            &[test_hash(0x99)],
            &revoked,
        );
        assert_eq!(result.unwrap_err(), DENY_REVOKED_SET_EXCEEDED);
    }

    #[test]
    fn tp007_empty_effects_passes() {
        let result = validate_replay_idempotency_tp007(&adjacent_windows(), &[], &[], &[]);
        assert!(result.is_ok());
    }

    #[test]
    fn tp007_revoked_not_in_later_window_passes() {
        let result = validate_replay_idempotency_tp007(
            &adjacent_windows(),
            &[test_hash(0x01)],
            &[test_hash(0x03)],
            &[test_hash(0x05)], // revoked but not in effects_t1
        );
        assert!(result.is_ok());
    }

    // ========================================================================
    // AdjacentWindowPair
    // ========================================================================

    #[test]
    fn adjacent_pair_exact_gap_of_one() {
        let pair = AdjacentWindowPair {
            w_t_start: 0,
            w_t_end: 99,
            w_t1_start: 100,
            w_t1_end: 199,
        };
        assert!(pair.is_adjacent());
    }

    #[test]
    fn adjacent_pair_gap_of_two_not_adjacent() {
        let pair = AdjacentWindowPair {
            w_t_start: 0,
            w_t_end: 99,
            w_t1_start: 101,
            w_t1_end: 199,
        };
        assert!(!pair.is_adjacent());
    }

    #[test]
    fn adjacent_pair_overlap_not_adjacent() {
        let pair = AdjacentWindowPair {
            w_t_start: 0,
            w_t_end: 100,
            w_t1_start: 100,
            w_t1_end: 199,
        };
        assert!(!pair.is_adjacent());
    }

    #[test]
    fn adjacent_pair_saturating_add_at_max() {
        let pair = AdjacentWindowPair {
            w_t_start: 0,
            w_t_end: u64::MAX,
            w_t1_start: u64::MAX, // saturating_add(1) wraps to MAX
            w_t1_end: u64::MAX,
        };
        // Not adjacent: w_t_end == w_t1_start so fails first guard.
        assert!(!pair.is_adjacent());
    }

    // ========================================================================
    // Combined evaluation (with IdempotencyMode)
    // ========================================================================

    #[test]
    fn evaluate_replay_recovery_not_adjacent_skips_tp007() {
        let signer = valid_signer();
        let receipt = valid_replay_receipt(&signer);
        let ts = trusted_signers_for(&signer);
        let decision = evaluate_replay_recovery(
            Some(&valid_horizon()),
            Some(&valid_backlog()),
            &[receipt],
            "boundary-1",
            500,
            test_hash(0xBB),
            test_hash(0xCC),
            &ts,
            IdempotencyMode::NotAdjacent,
            &RecoveryMode::NotRecovering,
        );
        assert_eq!(decision.verdict, ReplayRecoveryVerdict::Allow);
        assert!(decision.defect.is_none());
        assert_eq!(decision.predicate_results.len(), 1);
        assert_eq!(
            decision.predicate_results[0],
            (TemporalPredicateId::TpEio29004, true)
        );
    }

    #[test]
    fn evaluate_replay_recovery_tp004_denies_produces_defect() {
        let signer = valid_signer();
        let ts = trusted_signers_for(&signer);
        let decision = evaluate_replay_recovery(
            None, // missing horizon -> deny
            Some(&valid_backlog()),
            &[],
            "boundary-1",
            500,
            test_hash(0xBB),
            test_hash(0xCC),
            &ts,
            IdempotencyMode::NotAdjacent,
            &RecoveryMode::NotRecovering,
        );
        assert_eq!(decision.verdict, ReplayRecoveryVerdict::Deny);
        let defect = decision.defect.as_ref().unwrap();
        assert_eq!(defect.reason, DENY_REPLAY_HORIZON_UNRESOLVED);
        assert_eq!(defect.predicate_id, TemporalPredicateId::TpEio29004);
        assert_eq!(defect.boundary_id, "boundary-1");
        assert_eq!(defect.denied_at_tick, 500);
    }

    #[test]
    fn evaluate_replay_recovery_tp007_denies_duplicate_effect() {
        let signer = valid_signer();
        let receipt = valid_replay_receipt(&signer);
        let ts = trusted_signers_for(&signer);
        let shared = test_hash(0x01);
        let idem = IdempotencyCheckInput {
            windows: adjacent_windows(),
            effects_t: vec![shared],
            effects_t1: vec![shared],
            revoked_t1: vec![],
        };
        let decision = evaluate_replay_recovery(
            Some(&valid_horizon()),
            Some(&valid_backlog()),
            &[receipt],
            "boundary-1",
            500,
            test_hash(0xBB),
            test_hash(0xCC),
            &ts,
            IdempotencyMode::Adjacent(&idem),
            &RecoveryMode::NotRecovering,
        );
        assert_eq!(decision.verdict, ReplayRecoveryVerdict::Deny);
        let defect = decision.defect.as_ref().unwrap();
        assert_eq!(defect.reason, DENY_DUPLICATE_AUTHORITATIVE_EFFECT);
        assert_eq!(defect.predicate_id, TemporalPredicateId::TpEio29007);
    }

    #[test]
    fn evaluate_replay_recovery_tp004_and_tp007_both_pass() {
        let signer = valid_signer();
        let receipt = valid_replay_receipt(&signer);
        let ts = trusted_signers_for(&signer);
        let idem = IdempotencyCheckInput {
            windows: adjacent_windows(),
            effects_t: vec![test_hash(0x01)],
            effects_t1: vec![test_hash(0x02)],
            revoked_t1: vec![],
        };
        let decision = evaluate_replay_recovery(
            Some(&valid_horizon()),
            Some(&valid_backlog()),
            &[receipt],
            "boundary-1",
            500,
            test_hash(0xBB),
            test_hash(0xCC),
            &ts,
            IdempotencyMode::Adjacent(&idem),
            &RecoveryMode::NotRecovering,
        );
        assert_eq!(decision.verdict, ReplayRecoveryVerdict::Allow);
        assert_eq!(decision.predicate_results.len(), 2);
        assert_eq!(
            decision.predicate_results[0],
            (TemporalPredicateId::TpEio29004, true)
        );
        assert_eq!(
            decision.predicate_results[1],
            (TemporalPredicateId::TpEio29007, true)
        );
    }

    #[test]
    fn evaluate_replay_recovery_tp007_revoked_effect_denies() {
        let signer = valid_signer();
        let receipt = valid_replay_receipt(&signer);
        let ts = trusted_signers_for(&signer);
        let revoked = test_hash(0x05);
        let idem = IdempotencyCheckInput {
            windows: adjacent_windows(),
            effects_t: vec![test_hash(0x01)],
            effects_t1: vec![test_hash(0x02), revoked],
            revoked_t1: vec![revoked],
        };
        let decision = evaluate_replay_recovery(
            Some(&valid_horizon()),
            Some(&valid_backlog()),
            &[receipt],
            "boundary-1",
            500,
            test_hash(0xBB),
            test_hash(0xCC),
            &ts,
            IdempotencyMode::Adjacent(&idem),
            &RecoveryMode::NotRecovering,
        );
        assert_eq!(decision.verdict, ReplayRecoveryVerdict::Deny);
        let defect = decision.defect.as_ref().unwrap();
        assert_eq!(defect.reason, DENY_REVOKED_EFFECT_IN_LATER_WINDOW);
        assert_eq!(defect.predicate_id, TemporalPredicateId::TpEio29007);
    }

    #[test]
    fn evaluate_replay_recovery_adjacent_runs_tp007() {
        let signer = valid_signer();
        let receipt = valid_replay_receipt(&signer);
        let ts = trusted_signers_for(&signer);
        let idem = IdempotencyCheckInput {
            windows: adjacent_windows(),
            effects_t: vec![test_hash(0x01)],
            effects_t1: vec![test_hash(0x02)],
            revoked_t1: vec![],
        };
        let decision = evaluate_replay_recovery(
            Some(&valid_horizon()),
            Some(&valid_backlog()),
            &[receipt],
            "boundary-1",
            500,
            test_hash(0xBB),
            test_hash(0xCC),
            &ts,
            IdempotencyMode::Adjacent(&idem),
            &RecoveryMode::NotRecovering,
        );
        assert_eq!(decision.verdict, ReplayRecoveryVerdict::Allow);
        // Both predicates must appear in results.
        assert_eq!(decision.predicate_results.len(), 2);
        assert_eq!(
            decision.predicate_results[1],
            (TemporalPredicateId::TpEio29007, true)
        );
    }

    // ========================================================================
    // Partition/rejoin negative tests
    // ========================================================================

    #[test]
    fn partition_rejoin_duplicate_effect_denied() {
        // Simulate: partition isolates effect 0x01. On rejoin, both
        // partitions try to admit the same effect. TP-EIO29-007 denies.
        let earlier_partition_effects = vec![test_hash(0x01)];
        let later_partition_effects = vec![test_hash(0x01)]; // duplicate

        let result = validate_replay_idempotency_tp007(
            &adjacent_windows(),
            &earlier_partition_effects,
            &later_partition_effects,
            &[],
        );
        assert_eq!(result.unwrap_err(), DENY_DUPLICATE_AUTHORITATIVE_EFFECT);
    }

    #[test]
    fn retry_restart_revoked_effect_denied_on_replay() {
        // Simulate: effect 0x05 is revoked during a retry/restart cycle.
        // On replay, the same effect must not be re-admitted.
        let revoked = test_hash(0x05);
        let result = validate_replay_idempotency_tp007(
            &adjacent_windows(),
            &[test_hash(0x01), test_hash(0x02)],
            &[test_hash(0x03), revoked], // re-admitted revoked effect
            &[revoked],
        );
        assert_eq!(result.unwrap_err(), DENY_REVOKED_EFFECT_IN_LATER_WINDOW);
    }

    #[test]
    fn retry_restart_fresh_effects_after_revocation_pass() {
        // After revocation, completely new effects in later window pass.
        let revoked = test_hash(0x05);
        let result = validate_replay_idempotency_tp007(
            &adjacent_windows(),
            &[test_hash(0x01), test_hash(0x02)],
            &[test_hash(0x03), test_hash(0x04)], // all fresh
            &[revoked],                          // revoked but not in effects_t1
        );
        assert!(result.is_ok());
    }

    // ========================================================================
    // Fail-closed unknown state tests
    // ========================================================================

    #[test]
    fn unknown_temporal_state_fails_closed_missing_horizon() {
        let signer = valid_signer();
        let ts = trusted_signers_for(&signer);
        let result = validate_replay_convergence_tp004(
            None,
            None,
            &[],
            "boundary-1",
            &ts,
            &expected_time_authority_ref(),
            &expected_window_ref(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn unknown_temporal_state_fails_closed_missing_everything() {
        let signer = valid_signer();
        let ts = trusted_signers_for(&signer);
        let decision = evaluate_replay_recovery(
            None,
            None,
            &[],
            "boundary-1",
            0,
            [0u8; 32],
            [0u8; 32],
            &ts,
            IdempotencyMode::NotAdjacent,
            &RecoveryMode::NotRecovering,
        );
        assert_eq!(decision.verdict, ReplayRecoveryVerdict::Deny);
    }

    // ========================================================================
    // Finding 1: Bounded serde deserialization OOM prevention tests
    // ========================================================================

    #[test]
    fn replay_receipt_serde_rejects_oversized_receipt_id() {
        let signer = valid_signer();
        let mut receipt = valid_replay_receipt(&signer);
        // Inject oversized string AFTER construction (bypass create_signed checks).
        receipt.receipt_id = "x".repeat(10_000);
        let json = serde_json::to_string(&receipt).unwrap();
        let result: Result<ReplayConvergenceReceiptV1, _> = serde_json::from_str(&json);
        assert!(
            result.is_err(),
            "deserialization must reject oversized receipt_id"
        );
    }

    #[test]
    fn replay_receipt_serde_rejects_oversized_boundary_id() {
        let signer = valid_signer();
        let mut receipt = valid_replay_receipt(&signer);
        receipt.boundary_id = "x".repeat(10_000);
        let json = serde_json::to_string(&receipt).unwrap();
        let result: Result<ReplayConvergenceReceiptV1, _> = serde_json::from_str(&json);
        assert!(
            result.is_err(),
            "deserialization must reject oversized boundary_id"
        );
    }

    #[test]
    fn replay_receipt_serde_rejects_oversized_signer_actor_id() {
        let signer = valid_signer();
        let mut receipt = valid_replay_receipt(&signer);
        receipt.signer_actor_id = "x".repeat(10_000);
        let json = serde_json::to_string(&receipt).unwrap();
        let result: Result<ReplayConvergenceReceiptV1, _> = serde_json::from_str(&json);
        assert!(
            result.is_err(),
            "deserialization must reject oversized signer_actor_id"
        );
    }

    #[test]
    fn recovery_receipt_serde_rejects_oversized_receipt_id() {
        let signer = valid_signer();
        let mut receipt = valid_recovery_receipt(&signer);
        receipt.receipt_id = "x".repeat(10_000);
        let json = serde_json::to_string(&receipt).unwrap();
        let result: Result<RecoveryAdmissibilityReceiptV1, _> = serde_json::from_str(&json);
        assert!(
            result.is_err(),
            "deserialization must reject oversized receipt_id"
        );
    }

    #[test]
    fn recovery_receipt_serde_rejects_oversized_boundary_id() {
        let signer = valid_signer();
        let mut receipt = valid_recovery_receipt(&signer);
        receipt.boundary_id = "x".repeat(10_000);
        let json = serde_json::to_string(&receipt).unwrap();
        let result: Result<RecoveryAdmissibilityReceiptV1, _> = serde_json::from_str(&json);
        assert!(
            result.is_err(),
            "deserialization must reject oversized boundary_id"
        );
    }

    #[test]
    fn deny_defect_serde_rejects_oversized_reason() {
        let defect = ReplayRecoveryDenyDefect {
            reason: "x".repeat(10_000),
            predicate_id: TemporalPredicateId::TpEio29004,
            boundary_id: "boundary-1".to_string(),
            denied_at_tick: 100,
            envelope_hash: test_hash(0xBB),
            window_ref: test_hash(0xCC),
        };
        let json = serde_json::to_string(&defect).unwrap();
        let result: Result<ReplayRecoveryDenyDefect, _> = serde_json::from_str(&json);
        assert!(
            result.is_err(),
            "deserialization must reject oversized reason"
        );
    }

    #[test]
    fn deny_defect_serde_rejects_oversized_boundary_id() {
        let defect = ReplayRecoveryDenyDefect {
            reason: "test_reason".to_string(),
            predicate_id: TemporalPredicateId::TpEio29004,
            boundary_id: "x".repeat(10_000),
            denied_at_tick: 100,
            envelope_hash: test_hash(0xBB),
            window_ref: test_hash(0xCC),
        };
        let json = serde_json::to_string(&defect).unwrap();
        let result: Result<ReplayRecoveryDenyDefect, _> = serde_json::from_str(&json);
        assert!(
            result.is_err(),
            "deserialization must reject oversized boundary_id"
        );
    }

    // ========================================================================
    // Finding 5: Duplicate receipt ID amplification prevention
    // ========================================================================

    #[test]
    fn tp004_duplicate_receipt_id_denied() {
        let signer = valid_signer();
        let ts = trusted_signers_for(&signer);
        let receipt = valid_replay_receipt(&signer);
        let receipt2 = receipt.clone();
        let result = validate_replay_convergence_tp004(
            Some(&valid_horizon()),
            Some(&valid_backlog()),
            &[receipt, receipt2],
            "boundary-1",
            &ts,
            &expected_time_authority_ref(),
            &expected_window_ref(),
        );
        assert_eq!(result.unwrap_err(), DENY_REPLAY_RECEIPT_DUPLICATE_ID);
    }

    // ========================================================================
    // Finding 9: Distinct boundary_id error codes
    // ========================================================================

    #[test]
    fn replay_receipt_empty_boundary_id_returns_distinct_error() {
        let signer = valid_signer();
        let mut receipt = valid_replay_receipt(&signer);
        receipt.boundary_id = String::new();
        assert_eq!(
            receipt.validate().unwrap_err(),
            DENY_REPLAY_RECEIPT_BOUNDARY_ID_EMPTY
        );
    }

    #[test]
    fn recovery_receipt_empty_boundary_id_returns_distinct_error() {
        let signer = valid_signer();
        let mut receipt = valid_recovery_receipt(&signer);
        receipt.boundary_id = String::new();
        assert_eq!(
            receipt.validate().unwrap_err(),
            DENY_RECOVERY_RECEIPT_BOUNDARY_ID_EMPTY
        );
    }

    // ========================================================================
    // Finding 3: Recovery admissibility tests (TP-EIO29-009)
    // ========================================================================

    fn valid_recovery_check_input(signer: &Signer) -> RecoveryCheckInput {
        RecoveryCheckInput {
            receipts: vec![valid_recovery_receipt(signer)],
            trusted_signers: vec![signer.public_key_bytes()],
            expected_time_authority_ref: expected_time_authority_ref(),
            expected_window_ref: expected_window_ref(),
        }
    }

    #[test]
    fn recovery_admissibility_valid_receipt_passes() {
        let signer = valid_signer();
        let input = valid_recovery_check_input(&signer);
        let result = validate_recovery_admissibility(&input, "boundary-1");
        assert!(result.is_ok());
    }

    #[test]
    fn recovery_admissibility_no_receipt_denies() {
        let signer = valid_signer();
        let input = RecoveryCheckInput {
            receipts: vec![],
            trusted_signers: vec![signer.public_key_bytes()],
            expected_time_authority_ref: expected_time_authority_ref(),
            expected_window_ref: expected_window_ref(),
        };
        let result = validate_recovery_admissibility(&input, "boundary-1");
        assert_eq!(result.unwrap_err(), DENY_RECOVERY_RECEIPT_MISSING);
    }

    #[test]
    fn recovery_admissibility_invalid_signature_denies() {
        let signer = valid_signer();
        let mut input = valid_recovery_check_input(&signer);
        // Tamper with the receipt data to invalidate the signature.
        input.receipts[0].boundary_id = "tampered".to_string();
        let result = validate_recovery_admissibility(&input, "tampered");
        assert_eq!(result.unwrap_err(), DENY_RECOVERY_RECEIPT_SIGNATURE_INVALID);
    }

    #[test]
    fn recovery_admissibility_untrusted_signer_denies() {
        let signer_a = valid_signer();
        let signer_b = valid_signer();
        let input = RecoveryCheckInput {
            receipts: vec![valid_recovery_receipt(&signer_a)],
            trusted_signers: vec![signer_b.public_key_bytes()], // wrong signer
            expected_time_authority_ref: expected_time_authority_ref(),
            expected_window_ref: expected_window_ref(),
        };
        let result = validate_recovery_admissibility(&input, "boundary-1");
        assert_eq!(result.unwrap_err(), DENY_RECOVERY_RECEIPT_SIGNER_UNTRUSTED);
    }

    #[test]
    fn recovery_admissibility_boundary_mismatch_denies() {
        let signer = valid_signer();
        let input = valid_recovery_check_input(&signer);
        let result = validate_recovery_admissibility(&input, "wrong-boundary");
        assert_eq!(result.unwrap_err(), DENY_RECOVERY_RECEIPT_BOUNDARY_MISMATCH);
    }

    #[test]
    fn recovery_admissibility_time_authority_mismatch_denies() {
        let signer = valid_signer();
        let mut input = valid_recovery_check_input(&signer);
        input.expected_time_authority_ref = test_hash(0x11); // does not match receipt
        let result = validate_recovery_admissibility(&input, "boundary-1");
        assert_eq!(
            result.unwrap_err(),
            DENY_RECOVERY_RECEIPT_TIME_AUTH_MISMATCH
        );
    }

    #[test]
    fn recovery_admissibility_window_mismatch_denies() {
        let signer = valid_signer();
        let mut input = valid_recovery_check_input(&signer);
        input.expected_window_ref = test_hash(0x22); // does not match receipt
        let result = validate_recovery_admissibility(&input, "boundary-1");
        assert_eq!(result.unwrap_err(), DENY_RECOVERY_RECEIPT_WINDOW_MISMATCH);
    }

    #[test]
    fn recovery_admissibility_not_admitted_denies() {
        let signer = valid_signer();
        let receipt = RecoveryAdmissibilityReceiptV1::create_signed(
            "rcpt-not-admitted",
            "boundary-1",
            test_hash(0xAA),
            false, // not admitted
            test_hash(0xBB),
            test_hash(0xCC),
            test_hash(0xDD),
            "actor-1",
            &signer,
        )
        .unwrap();
        let input = RecoveryCheckInput {
            receipts: vec![receipt],
            trusted_signers: vec![signer.public_key_bytes()],
            expected_time_authority_ref: expected_time_authority_ref(),
            expected_window_ref: expected_window_ref(),
        };
        let result = validate_recovery_admissibility(&input, "boundary-1");
        assert_eq!(result.unwrap_err(), DENY_RECOVERY_RECEIPT_NOT_ADMITTED);
    }

    #[test]
    fn recovery_not_recovering_skips_check() {
        let signer = valid_signer();
        let receipt = valid_replay_receipt(&signer);
        let ts = trusted_signers_for(&signer);
        let decision = evaluate_replay_recovery(
            Some(&valid_horizon()),
            Some(&valid_backlog()),
            &[receipt],
            "boundary-1",
            500,
            test_hash(0xBB),
            test_hash(0xCC),
            &ts,
            IdempotencyMode::NotAdjacent,
            &RecoveryMode::NotRecovering,
        );
        assert_eq!(decision.verdict, ReplayRecoveryVerdict::Allow);
        // No TP-EIO29-009 result should be present.
        assert!(
            !decision
                .predicate_results
                .iter()
                .any(|(id, _)| *id == TemporalPredicateId::TpEio29009)
        );
    }

    #[test]
    fn recovery_active_valid_receipt_passes() {
        let signer = valid_signer();
        let replay_receipt = valid_replay_receipt(&signer);
        let ts = trusted_signers_for(&signer);
        let recovery_input = valid_recovery_check_input(&signer);
        let decision = evaluate_replay_recovery(
            Some(&valid_horizon()),
            Some(&valid_backlog()),
            &[replay_receipt],
            "boundary-1",
            500,
            test_hash(0xBB),
            test_hash(0xCC),
            &ts,
            IdempotencyMode::NotAdjacent,
            &RecoveryMode::Active(recovery_input),
        );
        assert_eq!(decision.verdict, ReplayRecoveryVerdict::Allow);
        assert!(
            decision
                .predicate_results
                .iter()
                .any(|(id, passed)| *id == TemporalPredicateId::TpEio29009 && *passed)
        );
    }

    #[test]
    fn recovery_active_missing_receipt_denies() {
        let signer = valid_signer();
        let replay_receipt = valid_replay_receipt(&signer);
        let ts = trusted_signers_for(&signer);
        let recovery_input = RecoveryCheckInput {
            receipts: vec![],
            trusted_signers: vec![signer.public_key_bytes()],
            expected_time_authority_ref: expected_time_authority_ref(),
            expected_window_ref: expected_window_ref(),
        };
        let decision = evaluate_replay_recovery(
            Some(&valid_horizon()),
            Some(&valid_backlog()),
            &[replay_receipt],
            "boundary-1",
            500,
            test_hash(0xBB),
            test_hash(0xCC),
            &ts,
            IdempotencyMode::NotAdjacent,
            &RecoveryMode::Active(recovery_input),
        );
        assert_eq!(decision.verdict, ReplayRecoveryVerdict::Deny);
        let defect = decision.defect.as_ref().unwrap();
        assert_eq!(defect.reason, DENY_RECOVERY_RECEIPT_MISSING);
        assert_eq!(defect.predicate_id, TemporalPredicateId::TpEio29009);
    }

    #[test]
    fn recovery_active_invalid_sig_denies() {
        let signer = valid_signer();
        let replay_receipt = valid_replay_receipt(&signer);
        let ts = trusted_signers_for(&signer);
        let mut recovery_input = valid_recovery_check_input(&signer);
        // Tamper the recovery_scope_digest to invalidate the signature while
        // keeping boundary_id = "boundary-1" so TP-EIO29-004 still passes.
        recovery_input.receipts[0].recovery_scope_digest = test_hash(0x99);
        let decision = evaluate_replay_recovery(
            Some(&valid_horizon()),
            Some(&valid_backlog()),
            &[replay_receipt],
            "boundary-1",
            500,
            test_hash(0xBB),
            test_hash(0xCC),
            &ts,
            IdempotencyMode::NotAdjacent,
            &RecoveryMode::Active(recovery_input),
        );
        assert_eq!(decision.verdict, ReplayRecoveryVerdict::Deny);
        let defect = decision.defect.as_ref().unwrap();
        assert_eq!(defect.predicate_id, TemporalPredicateId::TpEio29009);
    }

    // ========================================================================
    // deny_unknown_fields tests
    // ========================================================================

    #[test]
    fn deny_defect_rejects_unknown_field() {
        let json = r#"{
            "reason": "test_deny_reason",
            "predicate_id": "TP-EIO29-004",
            "boundary_id": "boundary-1",
            "denied_at_tick": 100,
            "envelope_hash": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "window_ref": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "injected_field": "malicious"
        }"#;
        let result = serde_json::from_str::<ReplayRecoveryDenyDefect>(json);
        assert!(result.is_err(), "must reject unknown field in deny defect");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown field"),
            "error should mention unknown field: {err}",
        );
    }

    #[test]
    fn deny_defect_accepts_known_fields() {
        let json = r#"{
            "reason": "test_deny_reason",
            "predicate_id": "TP-EIO29-004",
            "boundary_id": "boundary-1",
            "denied_at_tick": 100,
            "envelope_hash": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "window_ref": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
        }"#;
        let result = serde_json::from_str::<ReplayRecoveryDenyDefect>(json);
        assert!(result.is_ok(), "must accept valid deny defect: {result:?}");
    }

    #[test]
    fn decision_rejects_unknown_field() {
        let json = r#"{
            "verdict": "allow",
            "defect": null,
            "predicate_results": [],
            "injected_field": "malicious"
        }"#;
        let result = serde_json::from_str::<ReplayRecoveryDecision>(json);
        assert!(result.is_err(), "must reject unknown field in decision");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown field"),
            "error should mention unknown field: {err}",
        );
    }

    #[test]
    fn decision_accepts_known_fields() {
        let json = r#"{
            "verdict": "allow",
            "defect": null,
            "predicate_results": []
        }"#;
        let result = serde_json::from_str::<ReplayRecoveryDecision>(json);
        assert!(result.is_ok(), "must accept valid decision: {result:?}");
    }
}
