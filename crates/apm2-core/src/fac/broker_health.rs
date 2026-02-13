// AGENT-AUTHORED
//! Broker health monitoring: validates RFC-0029 TP001/TP002/TP003 invariants
//! and emits health receipts.
//!
//! Implements TCK-00585: the broker periodically self-checks its horizon and
//! envelope invariants and produces a [`HealthReceiptV1`] that workers can
//! inspect before admitting work.
//!
//! # Security Invariants
//!
//! - [INV-BRK-HEALTH-001] Health status defaults to `Failed` (fail-closed).
//!   Only explicit successful validation of all 3 invariants yields `Healthy`.
//! - [INV-BRK-HEALTH-002] Workers MUST refuse to admit jobs when health is
//!   `Degraded` or `Failed` (policy-driven fail-closed gate).
//! - [INV-BRK-HEALTH-003] Health receipts are signed by the broker key for
//!   authenticity.
//! - [INV-BRK-HEALTH-004] All in-memory collections are bounded by `MAX_*`
//!   caps. The check result history is capped at [`MAX_HEALTH_HISTORY`].
//! - [INV-BRK-HEALTH-005] Health receipt verification recomputes the canonical
//!   content hash from payload fields and constant-time compares it against
//!   `content_hash` before signature verification. This binds the signature to
//!   all receipt payload fields, preventing post-signing field tampering.
//! - [INV-BRK-HEALTH-006] All string fields and Vec collections enforce bounded
//!   deserialization to prevent memory exhaustion (RSK-1601).
//! - [INV-BRK-HEALTH-007] Hash computation uses `u64::to_le_bytes()` length
//!   prefixes for injective framing of variable-length fields.
//! - [INV-BRK-HEALTH-010] Worker health gate requires
//!   `expected_eval_window_hash` and rejects receipts generated for a different
//!   evaluation window (context binding, anti-replay).
//! - [INV-BRK-HEALTH-011] Worker health gate requires `min_broker_tick` and
//!   rejects receipts with stale broker ticks (recency enforcement,
//!   anti-replay).
//! - [INV-BRK-HEALTH-012] On health check input validation errors, a synthetic
//!   `FAILED` receipt is persisted so downstream gates cannot continue on a
//!   stale `HEALTHY` receipt.
//! - [INV-BRK-HEALTH-013] A monotonically increasing `health_seq` counter
//!   advances on every health check invocation (including error-path synthetic
//!   receipts). It is included in the receipt and content hash, providing
//!   per-invocation freshness independent of broker tick advancement. The
//!   worker gate enforces `receipt.health_seq >= min_health_seq` to prevent
//!   same-tick replay attacks.
//! - [INV-BRK-HEALTH-014] The `health_seq` counter uses `checked_add` (not
//!   `wrapping_add`) to detect overflow at `u64::MAX`. On overflow, a synthetic
//!   FAILED receipt is persisted and `HealthSeqOverflow` is returned. This is a
//!   terminal condition requiring broker key/epoch rotation (fail-closed).

use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use subtle::ConstantTimeEq;

use super::BrokerSignatureVerifier;
use super::broker::Hash;
use crate::crypto::Signer;
use crate::economics::queue_admission::{
    ConvergenceHorizonRef, ConvergenceReceipt, FreshnessHorizonRef, HtfEvaluationWindow,
    RevocationFrontierSnapshot, SignatureVerifier, TimeAuthorityEnvelopeV1,
    validate_convergence_horizon_tp003, validate_envelope_tp001, validate_freshness_horizon_tp002,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of health check results retained in the history ring.
///
/// Prevents unbounded growth under repeated health checks (CTR-1303).
pub const MAX_HEALTH_HISTORY: usize = 64;

/// Maximum number of required authority sets that a health check accepts.
///
/// Matches the economics module cap for convergence validation.
pub const MAX_HEALTH_REQUIRED_AUTHORITY_SETS: usize = 64;

/// Maximum number of findings in a single health receipt.
pub const MAX_HEALTH_FINDINGS: usize = 16;

/// Maximum string length for `predicate_id` fields (SEC-CTRL-FAC-0016).
pub const MAX_PREDICATE_ID_LENGTH: usize = 64;

/// Maximum string length for `deny_reason` fields (SEC-CTRL-FAC-0016).
pub const MAX_DENY_REASON_LENGTH: usize = 1024;

/// Maximum string length for `schema_id` fields (SEC-CTRL-FAC-0016).
/// Actual schema IDs are ~40 bytes; 128 provides headroom.
pub const MAX_SCHEMA_ID_LENGTH: usize = 128;

/// Maximum string length for `schema_version` fields (SEC-CTRL-FAC-0016).
pub const MAX_SCHEMA_VERSION_LENGTH: usize = 64;

/// Domain separator for health receipt content hashing.
const HEALTH_RECEIPT_HASH_DOMAIN: &[u8] = b"apm2.fac_broker.health_receipt.v1";

/// Schema identifier for health receipts.
pub const HEALTH_RECEIPT_SCHEMA_ID: &str = "apm2.fac_broker_health_receipt.v1";

/// Schema version for health receipts.
pub const HEALTH_RECEIPT_SCHEMA_VERSION: &str = "1.0.0";

// ---------------------------------------------------------------------------
// Bounded deserialization helpers (SEC-CTRL-FAC-0016)
// ---------------------------------------------------------------------------

/// Deserialize a `Vec` with a maximum size bound to prevent OOM attacks.
///
/// Per SEC-CTRL-FAC-0016, all collections deserialized from untrusted input
/// must enforce size limits during parsing to prevent denial-of-service via
/// memory exhaustion.
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

/// Deserialize a string with a maximum length bound to prevent OOM attacks.
///
/// Per SEC-CTRL-FAC-0016 / RSK-1601, all string fields deserialized from
/// untrusted input must enforce length limits during parsing to prevent
/// denial-of-service via memory exhaustion.
///
/// Uses a Visitor-based implementation so that `visit_str` checks the length
/// BEFORE allocating (calling `to_owned()`), closing the Check-After-Allocate
/// OOM-DoS vector present in naive `String::deserialize` + post-check patterns.
/// Same pattern as `crates/apm2-core/src/economics/queue_admission.rs`.
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

/// Deserialize an optional string with a maximum length bound.
///
/// Uses a Visitor-based implementation so that `visit_str` / `visit_string`
/// check the length BEFORE allocating, and `visit_none` / `visit_unit` handle
/// the `None` / `null` case without any allocation. This closes the
/// Check-After-Allocate OOM-DoS vector present in naive
/// `Option::<String>::deserialize` + post-check patterns.
fn deserialize_bounded_option_string<'de, D>(
    deserializer: D,
    max_len: usize,
    field_name: &'static str,
) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct BoundedOptionStringVisitor<'de> {
        max_len: usize,
        field_name: &'static str,
        _lifetime: std::marker::PhantomData<&'de ()>,
    }

    impl<'de> Visitor<'de> for BoundedOptionStringVisitor<'de> {
        type Value = Option<String>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(
                formatter,
                "null or a string of at most {} bytes for field '{}'",
                self.max_len, self.field_name
            )
        }

        fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_some<D2>(self, deserializer: D2) -> Result<Self::Value, D2::Error>
        where
            D2: Deserializer<'de>,
        {
            // Delegate to the non-optional bounded string visitor and wrap in Some.
            deserialize_bounded_string(deserializer, self.max_len, self.field_name).map(Some)
        }
    }

    deserializer.deserialize_option(BoundedOptionStringVisitor {
        max_len,
        field_name,
        _lifetime: std::marker::PhantomData,
    })
}

// Field-specific deserializers

fn deserialize_schema_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_string(deserializer, MAX_SCHEMA_ID_LENGTH, "schema_id")
}

fn deserialize_schema_version<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_string(deserializer, MAX_SCHEMA_VERSION_LENGTH, "schema_version")
}

fn deserialize_predicate_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_string(deserializer, MAX_PREDICATE_ID_LENGTH, "predicate_id")
}

fn deserialize_deny_reason<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_option_string(deserializer, MAX_DENY_REASON_LENGTH, "deny_reason")
}

fn deserialize_checks<'de, D>(deserializer: D) -> Result<Vec<InvariantCheckResult>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec(deserializer, MAX_HEALTH_FINDINGS, "checks")
}

// ---------------------------------------------------------------------------
// Health status (fail-closed default)
// ---------------------------------------------------------------------------

/// Broker health status derived from TP001/TP002/TP003 invariant checks.
///
/// The default is [`BrokerHealthStatus::Failed`] (fail-closed:
/// INV-BRK-HEALTH-001).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BrokerHealthStatus {
    /// All invariants passed.
    Healthy,
    /// Reserved for future use. This variant exists to support future
    /// degraded-mode policies where some invariants produce non-blocking
    /// warnings while all critical checks pass. It is not currently emitted
    /// by `BrokerHealthChecker::check_health` but is recognized by the
    /// worker health gate under [`WorkerHealthPolicy::AllowDegraded`].
    Degraded,
    /// At least one critical invariant failed. Workers MUST NOT admit jobs
    /// (fail-closed).
    Failed,
}

impl Default for BrokerHealthStatus {
    /// Fail-closed default: unknown health is treated as failure.
    fn default() -> Self {
        Self::Failed
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from health check operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BrokerHealthError {
    /// Input `required_authority_sets` exceeds
    /// `MAX_HEALTH_REQUIRED_AUTHORITY_SETS`.
    #[error("required_authority_sets exceeds maximum ({actual} > {max})")]
    TooManyRequiredAuthoritySets {
        /// Actual count.
        actual: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Input `checks` exceeds `MAX_HEALTH_FINDINGS`.
    #[error("checks exceeds maximum ({actual} > {max})")]
    TooManyChecks {
        /// Actual count.
        actual: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// A string field exceeds its maximum length.
    #[error("string field '{field}' exceeds maximum length ({len} > {max})")]
    StringTooLong {
        /// Field name.
        field: &'static str,
        /// Actual length.
        len: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Schema ID does not match expected value.
    #[error("schema_id mismatch: expected '{expected}', got '{actual}'")]
    SchemaMismatch {
        /// Expected schema ID.
        expected: String,
        /// Actual schema ID.
        actual: String,
    },

    /// Content hash does not match recomputed value (payload tampering).
    #[error("content_hash does not match recomputed hash (payload tampered)")]
    ContentHashMismatch,

    /// Signature verification failed.
    #[error("signature verification failed")]
    InvalidSignature,

    /// Health sequence counter overflow (`u64::MAX` reached).
    ///
    /// The monotonic health sequence has exhausted its u64 range. This is a
    /// terminal condition requiring broker key/epoch rotation. Fail-closed:
    /// no further health receipts can be issued until the broker is
    /// re-initialized with a fresh sequence epoch.
    #[error(
        "health sequence counter overflow: u64::MAX reached, broker requires key/epoch rotation"
    )]
    HealthSeqOverflow,
}

// ---------------------------------------------------------------------------
// Individual invariant check result
// ---------------------------------------------------------------------------

/// Result of a single TP invariant check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvariantCheckResult {
    /// Predicate identifier (e.g., "TP001", "TP002", "TP003").
    ///
    /// Bounded at deserialization time to `MAX_PREDICATE_ID_LENGTH`
    /// (SEC-CTRL-FAC-0016).
    #[serde(deserialize_with = "deserialize_predicate_id")]
    pub predicate_id: String,
    /// Whether the check passed.
    pub passed: bool,
    /// Human-readable reason code when the check fails.
    ///
    /// Bounded at deserialization time to `MAX_DENY_REASON_LENGTH`
    /// (SEC-CTRL-FAC-0016).
    #[serde(deserialize_with = "deserialize_deny_reason")]
    pub deny_reason: Option<String>,
}

// ---------------------------------------------------------------------------
// Health receipt
// ---------------------------------------------------------------------------

/// A signed health receipt capturing the outcome of a broker self-check.
///
/// Workers inspect this receipt to decide whether to admit jobs. The receipt
/// is signed by the broker's Ed25519 key so recipients can verify authenticity
/// (INV-BRK-HEALTH-003).
///
/// # Verification
///
/// [`HealthReceiptV1::verify`] performs full payload-binding verification:
/// 1. Validates `schema_id` and `schema_version` match expected constants.
/// 2. Recomputes the canonical content hash from `(schema_id, schema_version,
///    broker_tick, health_seq, eval_window_hash, status, checks)`.
/// 3. Constant-time compares the recomputed hash with the stored
///    `content_hash`.
/// 4. Verifies the Ed25519 signature over `content_hash`.
///
/// This ensures an attacker cannot tamper with payload fields (e.g., changing
/// `status` from `FAILED` to `HEALTHY`) while keeping the original signature.
///
/// # Replay Protection (INV-BH-013)
///
/// The `health_seq` field is a monotonically increasing sequence number
/// assigned by [`BrokerHealthChecker`]. It advances on every health check,
/// even when the broker tick does not change. This prevents same-tick replay
/// attacks where an old `HEALTHY` receipt is presented after health has
/// degraded but the broker tick has not advanced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthReceiptV1 {
    /// Schema identifier for version checking.
    ///
    /// Bounded at deserialization time to `MAX_SCHEMA_ID_LENGTH`
    /// (SEC-CTRL-FAC-0016).
    #[serde(deserialize_with = "deserialize_schema_id")]
    pub schema_id: String,
    /// Schema version.
    ///
    /// Bounded at deserialization time to `MAX_SCHEMA_VERSION_LENGTH`
    /// (SEC-CTRL-FAC-0016).
    #[serde(deserialize_with = "deserialize_schema_version")]
    pub schema_version: String,
    /// Overall health status (fail-closed aggregate).
    pub status: BrokerHealthStatus,
    /// Broker tick at the time of the health check.
    pub broker_tick: u64,
    /// Monotonic health check sequence number (INV-BH-013).
    ///
    /// Assigned by [`BrokerHealthChecker`] and incremented on every health
    /// check invocation. Provides per-invocation freshness independent of
    /// broker tick advancement, preventing same-tick replay attacks.
    pub health_seq: u64,
    /// BLAKE3 hash of the evaluation window used for this health check,
    /// binding the receipt to a specific boundary context.
    pub eval_window_hash: Hash,
    /// Individual invariant check results.
    ///
    /// Bounded at deserialization time to `MAX_HEALTH_FINDINGS`
    /// (SEC-CTRL-FAC-0016).
    #[serde(deserialize_with = "deserialize_checks")]
    pub checks: Vec<InvariantCheckResult>,
    /// Content hash of the receipt (domain-separated).
    pub content_hash: Hash,
    /// Ed25519 signature over the content hash.
    #[serde(with = "serde_bytes")]
    pub signature: [u8; 64],
    /// Signer public key bytes (broker verifying key).
    pub signer_id: Hash,
}

impl HealthReceiptV1 {
    /// Verifies the receipt signature using the provided verifier.
    ///
    /// Performs full payload-binding verification (INV-BRK-HEALTH-005):
    /// 1. Validates `schema_id` and `schema_version`.
    /// 2. Recomputes canonical hash from payload fields.
    /// 3. Constant-time compares recomputed hash with stored `content_hash`.
    /// 4. Verifies Ed25519 signature over `content_hash`.
    ///
    /// # Errors
    ///
    /// Returns a [`BrokerHealthError`] describing the verification failure.
    pub fn verify(&self, verifier: &BrokerSignatureVerifier) -> Result<(), BrokerHealthError> {
        // Step 1: Validate schema identity
        if self.schema_id != HEALTH_RECEIPT_SCHEMA_ID {
            return Err(BrokerHealthError::SchemaMismatch {
                expected: HEALTH_RECEIPT_SCHEMA_ID.to_string(),
                actual: self.schema_id.clone(),
            });
        }
        if self.schema_version != HEALTH_RECEIPT_SCHEMA_VERSION {
            return Err(BrokerHealthError::SchemaMismatch {
                expected: HEALTH_RECEIPT_SCHEMA_VERSION.to_string(),
                actual: self.schema_version.clone(),
            });
        }

        // Step 2: Recompute canonical hash from payload fields
        let recomputed = compute_health_receipt_hash(
            self.broker_tick,
            self.health_seq,
            self.eval_window_hash,
            self.status,
            &self.checks,
        );

        // Step 3: Constant-time compare recomputed hash with stored content_hash
        if !bool::from(recomputed.ct_eq(&self.content_hash)) {
            return Err(BrokerHealthError::ContentHashMismatch);
        }

        // Step 4: Verify Ed25519 signature
        if !verifier.verify_broker_signature(&self.content_hash, &self.signer_id, &self.signature) {
            return Err(BrokerHealthError::InvalidSignature);
        }

        Ok(())
    }

    /// Validates the receipt's structural integrity without signature
    /// verification.
    ///
    /// Enforces:
    /// - `schema_id` matches [`HEALTH_RECEIPT_SCHEMA_ID`]
    /// - `schema_version` matches [`HEALTH_RECEIPT_SCHEMA_VERSION`]
    /// - `checks.len() <= MAX_HEALTH_FINDINGS`
    /// - All string fields within length bounds
    ///
    /// # Errors
    ///
    /// Returns a [`BrokerHealthError`] describing the validation failure.
    pub fn validate(&self) -> Result<(), BrokerHealthError> {
        // Schema identity
        if self.schema_id != HEALTH_RECEIPT_SCHEMA_ID {
            return Err(BrokerHealthError::SchemaMismatch {
                expected: HEALTH_RECEIPT_SCHEMA_ID.to_string(),
                actual: self.schema_id.clone(),
            });
        }
        if self.schema_version != HEALTH_RECEIPT_SCHEMA_VERSION {
            return Err(BrokerHealthError::SchemaMismatch {
                expected: HEALTH_RECEIPT_SCHEMA_VERSION.to_string(),
                actual: self.schema_version.clone(),
            });
        }

        // Checks vector bound
        if self.checks.len() > MAX_HEALTH_FINDINGS {
            return Err(BrokerHealthError::TooManyChecks {
                actual: self.checks.len(),
                max: MAX_HEALTH_FINDINGS,
            });
        }

        // String field bounds within checks
        for check in &self.checks {
            if check.predicate_id.len() > MAX_PREDICATE_ID_LENGTH {
                return Err(BrokerHealthError::StringTooLong {
                    field: "predicate_id",
                    len: check.predicate_id.len(),
                    max: MAX_PREDICATE_ID_LENGTH,
                });
            }
            if let Some(ref reason) = check.deny_reason {
                if reason.len() > MAX_DENY_REASON_LENGTH {
                    return Err(BrokerHealthError::StringTooLong {
                        field: "deny_reason",
                        len: reason.len(),
                        max: MAX_DENY_REASON_LENGTH,
                    });
                }
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Health check input
// ---------------------------------------------------------------------------

/// Input bundle for a broker health check.
///
/// Aggregates all the state needed to validate TP001/TP002/TP003 in one
/// struct so callers do not need to pass many individual parameters.
pub struct HealthCheckInput<'a> {
    /// Time authority envelope for TP001 validation.
    pub envelope: Option<&'a TimeAuthorityEnvelopeV1>,
    /// Evaluation window for TP001 validation.
    pub eval_window: &'a HtfEvaluationWindow,
    /// Signature verifier for TP001 validation.
    pub verifier: Option<&'a dyn SignatureVerifier>,
    /// Freshness horizon for TP002 validation.
    pub freshness_horizon: Option<&'a FreshnessHorizonRef>,
    /// Revocation frontier for TP002 validation.
    pub revocation_frontier: Option<&'a RevocationFrontierSnapshot>,
    /// Convergence horizon for TP003 validation.
    pub convergence_horizon: Option<&'a ConvergenceHorizonRef>,
    /// Convergence receipts for TP003 validation.
    pub convergence_receipts: &'a [ConvergenceReceipt],
    /// Required authority sets for TP003 validation.
    pub required_authority_sets: &'a [Hash],
}

// ---------------------------------------------------------------------------
// Health checker
// ---------------------------------------------------------------------------

/// Validates broker TP001/TP002/TP003 invariants and produces signed health
/// receipts.
///
/// # Thread Safety
///
/// `BrokerHealthChecker` is not internally synchronized. Callers must hold
/// appropriate locks when accessing from multiple threads (same pattern as
/// `FacBroker`).
///
/// # Monotonic Health Sequence (INV-BH-013)
///
/// The checker maintains a monotonically increasing `health_seq` counter that
/// advances on every `check_health` call (including error-path synthetic
/// receipts). This counter is included in each [`HealthReceiptV1`] and bound
/// into the content hash, providing strict per-invocation freshness that is
/// independent of the broker tick. Callers enforce replay protection via
/// `min_health_seq` in [`evaluate_worker_health_gate`].
pub struct BrokerHealthChecker {
    /// Recent health check history (bounded ring buffer).
    history: Vec<HealthReceiptV1>,
    /// Monotonically increasing health check sequence number.
    ///
    /// Incremented on every `check_health` invocation (including error-path
    /// synthetic receipts). Provides per-invocation freshness independent of
    /// broker tick advancement.
    ///
    /// Synchronization: protected by the same external lock that guards
    /// `&mut self` access. No interior mutability.
    health_seq: u64,
}

impl Default for BrokerHealthChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl BrokerHealthChecker {
    /// Creates a new health checker with empty history and sequence 0.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            history: Vec::new(),
            health_seq: 0,
        }
    }

    /// Creates a health checker restored from persisted state.
    ///
    /// The `health_seq` is loaded from `BrokerState::health_seq` so that
    /// the counter resumes from the last known value after a daemon restart.
    /// This prevents replay of old health receipts from a previous daemon
    /// lifetime (INV-BH-013).
    ///
    /// History is not persisted and starts empty; the first health check
    /// after restart will populate it.
    #[must_use]
    pub const fn from_persisted_seq(health_seq: u64) -> Self {
        Self {
            history: Vec::new(),
            health_seq,
        }
    }

    /// Returns the current health sequence number.
    ///
    /// This is the sequence number that will be assigned to the *next* health
    /// receipt. After each `check_health` call, the returned receipt's
    /// `health_seq` equals this value, and the internal counter advances to
    /// `health_seq + 1`.
    #[must_use]
    pub const fn current_health_seq(&self) -> u64 {
        self.health_seq
    }

    /// Runs a full health check against broker state and produces a signed
    /// receipt.
    ///
    /// Validates all three RFC-0029 temporal predicates:
    /// - **TP001**: envelope signature validity
    /// - **TP002**: freshness horizon resolved/current with non-zero
    ///   commitments
    /// - **TP003**: convergence horizon resolved/converged with non-zero
    ///   commitments
    ///
    /// The result is signed by the broker's Ed25519 key and appended to the
    /// bounded history ring.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerHealthError::TooManyRequiredAuthoritySets`] if
    /// `input.required_authority_sets` exceeds
    /// [`MAX_HEALTH_REQUIRED_AUTHORITY_SETS`] (INV-BH-005).
    pub fn check_health(
        &mut self,
        input: &HealthCheckInput<'_>,
        broker_tick: u64,
        signer: &Signer,
    ) -> Result<HealthReceiptV1, BrokerHealthError> {
        // INV-BH-005: Enforce input bounds before evaluation (fail-closed).
        // INV-BH-012: On input validation failure, persist a synthetic FAILED
        // receipt so downstream gates cannot continue on a stale HEALTHY receipt.
        if input.required_authority_sets.len() > MAX_HEALTH_REQUIRED_AUTHORITY_SETS {
            let reason = format!(
                "required_authority_sets exceeds maximum ({} > {})",
                input.required_authority_sets.len(),
                MAX_HEALTH_REQUIRED_AUTHORITY_SETS
            );
            self.persist_synthetic_failed_receipt(broker_tick, input.eval_window, &reason, signer);
            return Err(BrokerHealthError::TooManyRequiredAuthoritySets {
                actual: input.required_authority_sets.len(),
                max: MAX_HEALTH_REQUIRED_AUTHORITY_SETS,
            });
        }

        let mut checks = Vec::with_capacity(3);

        // TP001: envelope signature validity
        let tp001_result =
            validate_envelope_tp001(input.envelope, input.eval_window, input.verifier);
        checks.push(InvariantCheckResult {
            predicate_id: "TP001".to_string(),
            passed: tp001_result.is_ok(),
            deny_reason: tp001_result.err().map(ToString::to_string),
        });

        // TP002: freshness horizon resolved/current
        let tp002_result = validate_freshness_horizon_tp002(
            input.freshness_horizon,
            input.revocation_frontier,
            input.eval_window,
        );
        checks.push(InvariantCheckResult {
            predicate_id: "TP002".to_string(),
            passed: tp002_result.is_ok(),
            deny_reason: tp002_result.err().map(ToString::to_string),
        });

        // TP003: convergence horizon resolved/converged
        let tp003_result = validate_convergence_horizon_tp003(
            input.convergence_horizon,
            input.convergence_receipts,
            input.required_authority_sets,
        );
        checks.push(InvariantCheckResult {
            predicate_id: "TP003".to_string(),
            passed: tp003_result.is_ok(),
            deny_reason: tp003_result.err().map(ToString::to_string),
        });

        // Derive aggregate status (fail-closed: any failure = Failed)
        let all_passed = checks.iter().all(|c| c.passed);
        let status = if all_passed {
            BrokerHealthStatus::Healthy
        } else {
            BrokerHealthStatus::Failed
        };

        // Compute eval_window hash for boundary context binding (SEC-MINOR-2)
        let eval_window_hash = compute_eval_window_hash(input.eval_window);

        // INV-BH-013: Capture and advance the monotonic health sequence.
        // This happens AFTER input validation but BEFORE receipt construction,
        // ensuring each receipt gets a unique, strictly increasing sequence.
        // Fail-closed on overflow: if the u64 sequence space is exhausted,
        // persist a synthetic FAILED receipt and return an error.
        let seq = self.health_seq;
        if let Some(next) = self.health_seq.checked_add(1) {
            self.health_seq = next;
        } else {
            // Sequence exhausted — persist synthetic FAILED at current
            // (saturated) seq so downstream gates see a FAILED receipt,
            // then return the overflow error.
            let reason =
                "health_seq overflow: u64::MAX reached, broker requires key/epoch rotation";
            self.persist_overflow_failed_receipt(broker_tick, input.eval_window, reason, signer);
            return Err(BrokerHealthError::HealthSeqOverflow);
        }

        // Compute content hash (domain-separated, includes schema + eval_window +
        // health_seq)
        let content_hash =
            compute_health_receipt_hash(broker_tick, seq, eval_window_hash, status, &checks);

        // Sign the content hash
        let signature_bytes = signer.sign(&content_hash);
        let signer_id = signer.verifying_key().to_bytes();

        let receipt = HealthReceiptV1 {
            schema_id: HEALTH_RECEIPT_SCHEMA_ID.to_string(),
            schema_version: HEALTH_RECEIPT_SCHEMA_VERSION.to_string(),
            status,
            broker_tick,
            health_seq: seq,
            eval_window_hash,
            checks,
            content_hash,
            signature: signature_bytes.to_bytes(),
            signer_id,
        };

        // Append to bounded history (evict oldest when at cap)
        if self.history.len() >= MAX_HEALTH_HISTORY {
            self.history.remove(0);
        }
        self.history.push(receipt.clone());

        Ok(receipt)
    }

    /// Persists a synthetic `FAILED` receipt when a health check encounters
    /// an error before evaluation completes.
    ///
    /// This ensures downstream gates cannot rely on a stale `HEALTHY` receipt
    /// after a failed re-check attempt (INV-BH-012). The synthetic receipt
    /// carries a machine-readable reason in a single `EVAL_ERROR` check result.
    ///
    /// INV-BH-013: The monotonic `health_seq` is advanced even for synthetic
    /// receipts, so sequence-based replay protection remains consistent.
    fn persist_synthetic_failed_receipt(
        &mut self,
        broker_tick: u64,
        eval_window: &HtfEvaluationWindow,
        reason: &str,
        signer: &Signer,
    ) {
        let checks = vec![InvariantCheckResult {
            predicate_id: "EVAL_ERROR".to_string(),
            passed: false,
            deny_reason: Some(reason.to_string()),
        }];

        // INV-BH-013: Capture and advance sequence for synthetic receipt.
        // Fail-closed on overflow: saturate at u64::MAX. The next
        // `check_health` call will detect the overflow and return
        // `HealthSeqOverflow`. We do NOT skip the synthetic receipt here
        // because the primary invariant (INV-BH-012: downstream gates must
        // not see a stale HEALTHY receipt) takes precedence.
        let seq = self.health_seq;
        self.health_seq = self.health_seq.saturating_add(1);

        let eval_window_hash = compute_eval_window_hash(eval_window);
        let content_hash = compute_health_receipt_hash(
            broker_tick,
            seq,
            eval_window_hash,
            BrokerHealthStatus::Failed,
            &checks,
        );
        let signature_bytes = signer.sign(&content_hash);

        let receipt = HealthReceiptV1 {
            schema_id: HEALTH_RECEIPT_SCHEMA_ID.to_string(),
            schema_version: HEALTH_RECEIPT_SCHEMA_VERSION.to_string(),
            status: BrokerHealthStatus::Failed,
            broker_tick,
            health_seq: seq,
            eval_window_hash,
            checks,
            content_hash,
            signature: signature_bytes.to_bytes(),
            signer_id: signer.verifying_key().to_bytes(),
        };

        // Append to bounded history (evict oldest when at cap)
        if self.history.len() >= MAX_HEALTH_HISTORY {
            self.history.remove(0);
        }
        self.history.push(receipt);
    }

    /// Persists a synthetic `FAILED` receipt when the health sequence counter
    /// overflows (`u64::MAX` reached).
    ///
    /// Unlike [`Self::persist_synthetic_failed_receipt`], this method does NOT
    /// advance the sequence counter (it is already at `u64::MAX`). The receipt
    /// is stamped with the current (saturated) sequence value so downstream
    /// gates see a `FAILED` status.
    fn persist_overflow_failed_receipt(
        &mut self,
        broker_tick: u64,
        eval_window: &HtfEvaluationWindow,
        reason: &str,
        signer: &Signer,
    ) {
        let checks = vec![InvariantCheckResult {
            predicate_id: "SEQ_OVERFLOW".to_string(),
            passed: false,
            deny_reason: Some(reason.to_string()),
        }];

        // Use the current (saturated) sequence — do NOT advance further.
        let seq = self.health_seq;

        let eval_window_hash = compute_eval_window_hash(eval_window);
        let content_hash = compute_health_receipt_hash(
            broker_tick,
            seq,
            eval_window_hash,
            BrokerHealthStatus::Failed,
            &checks,
        );
        let signature_bytes = signer.sign(&content_hash);

        let receipt = HealthReceiptV1 {
            schema_id: HEALTH_RECEIPT_SCHEMA_ID.to_string(),
            schema_version: HEALTH_RECEIPT_SCHEMA_VERSION.to_string(),
            status: BrokerHealthStatus::Failed,
            broker_tick,
            health_seq: seq,
            eval_window_hash,
            checks,
            content_hash,
            signature: signature_bytes.to_bytes(),
            signer_id: signer.verifying_key().to_bytes(),
        };

        // Append to bounded history (evict oldest when at cap)
        if self.history.len() >= MAX_HEALTH_HISTORY {
            self.history.remove(0);
        }
        self.history.push(receipt);
    }

    /// Returns the most recent health receipt, if any.
    #[must_use]
    pub fn latest(&self) -> Option<&HealthReceiptV1> {
        self.history.last()
    }

    /// Returns the most recent health status, defaulting to `Failed` if no
    /// check has been performed (fail-closed).
    #[must_use]
    pub fn latest_status(&self) -> BrokerHealthStatus {
        self.history
            .last()
            .map_or(BrokerHealthStatus::Failed, |r| r.status)
    }

    /// Returns the full health check history (bounded by
    /// [`MAX_HEALTH_HISTORY`]).
    #[must_use]
    pub fn history(&self) -> &[HealthReceiptV1] {
        &self.history
    }

    /// Returns the number of health checks in the history.
    #[must_use]
    pub fn history_len(&self) -> usize {
        self.history.len()
    }
}

// ---------------------------------------------------------------------------
// Worker admission gate
// ---------------------------------------------------------------------------

/// Error returned when the worker admission health gate rejects a job.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WorkerHealthGateError {
    /// No health receipt is available (broker has never been checked).
    #[error("no health receipt available: broker health unknown (fail-closed)")]
    NoHealthReceipt,

    /// Broker health is degraded.
    #[error("broker health degraded: {reason}")]
    HealthDegraded {
        /// Reason detail from the health receipt.
        reason: String,
    },

    /// Broker health has failed.
    #[error("broker health failed: {reason}")]
    HealthFailed {
        /// Reason detail from the health receipt.
        reason: String,
    },

    /// Health receipt verification failed (signature, content hash, or schema).
    #[error("health receipt verification failed: {0}")]
    VerificationFailed(#[from] BrokerHealthError),

    /// Receipt `eval_window_hash` does not match the expected evaluation
    /// window.
    ///
    /// This prevents replay of receipts generated for a different evaluation
    /// context (INV-BH-010).
    #[error(
        "receipt eval_window_hash mismatch: receipt was generated for a different evaluation window"
    )]
    EvalWindowMismatch,

    /// Receipt `broker_tick` is below the required minimum (stale receipt).
    ///
    /// This prevents replay of old receipts from earlier broker ticks
    /// (INV-BH-011).
    #[error(
        "receipt broker_tick {receipt_tick} is below minimum required tick {min_tick} (stale receipt)"
    )]
    StaleReceipt {
        /// The broker tick on the receipt.
        receipt_tick: u64,
        /// The minimum required broker tick.
        min_tick: u64,
    },

    /// Receipt `health_seq` is below the required minimum (stale sequence).
    ///
    /// This prevents same-tick replay attacks where an old `HEALTHY` receipt is
    /// presented after health has degraded but the broker tick has not advanced
    /// (INV-BH-013).
    #[error(
        "receipt health_seq {receipt_seq} is below minimum required seq {min_seq} (stale health sequence)"
    )]
    StaleHealthSeq {
        /// The health sequence on the receipt.
        receipt_seq: u64,
        /// The minimum required health sequence.
        min_seq: u64,
    },
}

/// Policy for the worker health admission gate.
///
/// Determines whether the worker admits jobs under degraded health.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WorkerHealthPolicy {
    /// Only admit when health is `Healthy`. This is the default (fail-closed).
    #[default]
    StrictHealthy,
    /// Admit when health is `Healthy` or `Degraded`.
    AllowDegraded,
}

/// Evaluates the worker admission health gate with replay protection.
///
/// The gate checks (in order, fail-closed):
/// 1. A health receipt exists (fail-closed if missing).
/// 2. The receipt payload integrity (content hash recomputed and compared).
/// 3. The receipt signature is valid.
/// 4. **Freshness**: The receipt's `eval_window_hash` matches
///    `expected_eval_window_hash` (context binding, INV-BH-010).
/// 5. **Recency**: The receipt's `broker_tick` is at or above `min_broker_tick`
///    (anti-replay staleness check, INV-BH-011).
/// 6. **Sequence freshness**: The receipt's `health_seq` is at or above
///    `min_health_seq` (per-invocation anti-replay, INV-BH-013).
/// 7. The health status meets the configured policy.
///
/// Steps 4, 5, and 6 prevent replay of previously healthy receipts after
/// broker state has degraded. Step 6 specifically closes the same-tick replay
/// vector where an old `HEALTHY` receipt at tick T is presented after a newer
/// `FAILED` receipt was issued at the same tick T.
///
/// # Errors
///
/// Returns a [`WorkerHealthGateError`] if the gate rejects the job.
pub fn evaluate_worker_health_gate(
    receipt: Option<&HealthReceiptV1>,
    verifier: &BrokerSignatureVerifier,
    policy: WorkerHealthPolicy,
    expected_eval_window_hash: Hash,
    min_broker_tick: u64,
    min_health_seq: u64,
) -> Result<(), WorkerHealthGateError> {
    let receipt = receipt.ok_or(WorkerHealthGateError::NoHealthReceipt)?;

    // Verify receipt: schema + content hash recompute + signature
    // (INV-BRK-HEALTH-005)
    receipt.verify(verifier)?;

    // INV-BH-010: Verify evaluation window context binding.
    // Reject receipts generated for a different evaluation window to prevent
    // cross-context replay attacks.
    if !bool::from(receipt.eval_window_hash.ct_eq(&expected_eval_window_hash)) {
        return Err(WorkerHealthGateError::EvalWindowMismatch);
    }

    // INV-BH-011: Verify receipt recency via broker tick floor.
    // Reject stale receipts from earlier broker ticks to prevent temporal
    // replay attacks where an attacker presents an old HEALTHY receipt after
    // the broker's health has degraded.
    if receipt.broker_tick < min_broker_tick {
        return Err(WorkerHealthGateError::StaleReceipt {
            receipt_tick: receipt.broker_tick,
            min_tick: min_broker_tick,
        });
    }

    // INV-BH-013: Verify receipt freshness via monotonic health sequence.
    // Reject stale receipts from earlier health check invocations. This
    // closes the same-tick replay vector: even when broker tick does not
    // advance between health checks, the health_seq always advances,
    // so an old HEALTHY receipt cannot bypass a newer FAILED assessment.
    if receipt.health_seq < min_health_seq {
        return Err(WorkerHealthGateError::StaleHealthSeq {
            receipt_seq: receipt.health_seq,
            min_seq: min_health_seq,
        });
    }

    match receipt.status {
        BrokerHealthStatus::Healthy => Ok(()),
        BrokerHealthStatus::Degraded => match policy {
            WorkerHealthPolicy::AllowDegraded => Ok(()),
            WorkerHealthPolicy::StrictHealthy => {
                let reason = format_deny_reasons(&receipt.checks);
                Err(WorkerHealthGateError::HealthDegraded { reason })
            },
        },
        BrokerHealthStatus::Failed => {
            let reason = format_deny_reasons(&receipt.checks);
            Err(WorkerHealthGateError::HealthFailed { reason })
        },
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Computes the canonical content hash for a health receipt.
///
/// The hash covers all semantically relevant fields using injective framing
/// (u64 length prefixes) to prevent ambiguity between different payloads:
/// - Domain separator
/// - Schema ID and version (bound to interpretation)
/// - Broker tick
/// - Health sequence number (INV-BH-013: monotonic per-invocation freshness)
/// - Evaluation window hash (boundary context binding)
/// - Status byte
/// - All check results (`predicate_id`, `passed`, `deny_reason`)
///
/// # INV-BRK-HEALTH-007
///
/// Length prefixes use `u64::to_le_bytes()` for injective framing.
fn compute_health_receipt_hash(
    broker_tick: u64,
    health_seq: u64,
    eval_window_hash: Hash,
    status: BrokerHealthStatus,
    checks: &[InvariantCheckResult],
) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(HEALTH_RECEIPT_HASH_DOMAIN);

    // Schema identity binding (CQ-BLOCKER-1)
    let schema_id_bytes = HEALTH_RECEIPT_SCHEMA_ID.as_bytes();
    hasher.update(&(schema_id_bytes.len() as u64).to_le_bytes());
    hasher.update(schema_id_bytes);
    let schema_version_bytes = HEALTH_RECEIPT_SCHEMA_VERSION.as_bytes();
    hasher.update(&(schema_version_bytes.len() as u64).to_le_bytes());
    hasher.update(schema_version_bytes);

    // Broker tick
    hasher.update(&broker_tick.to_le_bytes());

    // INV-BH-013: Health sequence number (monotonic replay protection)
    hasher.update(&health_seq.to_le_bytes());

    // Evaluation window hash (SEC-MINOR-2: boundary context binding)
    hasher.update(&eval_window_hash);

    // Encode status as a single byte
    let status_byte = match status {
        BrokerHealthStatus::Healthy => 0u8,
        BrokerHealthStatus::Degraded => 1u8,
        BrokerHealthStatus::Failed => 2u8,
    };
    hasher.update(&[status_byte]);

    // Encode ALL check results with u64 length prefixes (SEC-MINOR-1)
    // No truncation: callers must enforce MAX_HEALTH_FINDINGS before hashing.
    let check_count = checks.len() as u64;
    hasher.update(&check_count.to_le_bytes());
    for check in checks {
        // Length-prefix the predicate_id with u64 for injective framing
        let pid_bytes = check.predicate_id.as_bytes();
        hasher.update(&(pid_bytes.len() as u64).to_le_bytes());
        hasher.update(pid_bytes);
        hasher.update(&[u8::from(check.passed)]);
        if let Some(ref reason) = check.deny_reason {
            hasher.update(&[1u8]); // present marker
            let reason_bytes = reason.as_bytes();
            hasher.update(&(reason_bytes.len() as u64).to_le_bytes());
            hasher.update(reason_bytes);
        } else {
            hasher.update(&[0u8]); // absent marker
        }
    }

    *hasher.finalize().as_bytes()
}

/// Computes a BLAKE3 hash of the evaluation window fields for boundary
/// context binding.
///
/// This is the canonical hash used for `expected_eval_window_hash` in
/// [`evaluate_worker_health_gate`]. Production callers must use this
/// function to compute the expected hash from the current evaluation
/// window before calling the gate.
#[must_use]
pub fn compute_eval_window_hash(eval_window: &HtfEvaluationWindow) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"apm2.eval_window.v1");
    let bid = eval_window.boundary_id.as_bytes();
    hasher.update(&(bid.len() as u64).to_le_bytes());
    hasher.update(bid);
    let ac = eval_window.authority_clock.as_bytes();
    hasher.update(&(ac.len() as u64).to_le_bytes());
    hasher.update(ac);
    hasher.update(&eval_window.tick_start.to_le_bytes());
    hasher.update(&eval_window.tick_end.to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn format_deny_reasons(checks: &[InvariantCheckResult]) -> String {
    let failed: Vec<String> = checks
        .iter()
        .filter(|c| !c.passed)
        .map(|c| {
            format!(
                "{}: {}",
                c.predicate_id,
                c.deny_reason.as_deref().unwrap_or("unknown")
            )
        })
        .collect();

    if failed.is_empty() {
        "unknown".to_string()
    } else {
        failed.join("; ")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Signer;
    use crate::economics::queue_admission::{
        ConvergenceHorizonRef, ConvergenceReceipt, EnvelopeSignature, FreshnessHorizonRef,
        HtfEvaluationWindow, RevocationFrontierSnapshot, TimeAuthorityEnvelopeV1,
        envelope_signature_canonical_bytes,
    };
    use crate::fac::BrokerSignatureVerifier;

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    fn test_signer() -> Signer {
        Signer::generate()
    }

    fn valid_eval_window() -> HtfEvaluationWindow {
        HtfEvaluationWindow {
            boundary_id: "test-boundary".to_string(),
            authority_clock: "test-clock".to_string(),
            tick_start: 100,
            tick_end: 200,
        }
    }

    fn valid_envelope(signer: &Signer) -> TimeAuthorityEnvelopeV1 {
        let mut envelope = TimeAuthorityEnvelopeV1 {
            boundary_id: "test-boundary".to_string(),
            authority_clock: "test-clock".to_string(),
            tick_start: 100,
            tick_end: 200,
            ttl_ticks: 500,
            deny_on_unknown: true,
            signature_set: Vec::new(),
            content_hash: [0x42; 32],
        };
        let canonical = envelope_signature_canonical_bytes(&envelope);
        let sig = signer.sign(&canonical);
        envelope.signature_set.push(EnvelopeSignature {
            signer_id: signer.verifying_key().to_bytes(),
            signature: sig.to_bytes(),
        });
        envelope
    }

    fn valid_freshness_horizon() -> FreshnessHorizonRef {
        FreshnessHorizonRef {
            horizon_hash: [0x11; 32],
            tick_end: 300, // Must be >= eval_window.tick_end (200)
            resolved: true,
        }
    }

    fn valid_revocation_frontier() -> RevocationFrontierSnapshot {
        RevocationFrontierSnapshot {
            frontier_hash: [0x22; 32],
            current: true,
        }
    }

    fn valid_convergence_horizon() -> ConvergenceHorizonRef {
        ConvergenceHorizonRef {
            horizon_hash: [0x33; 32],
            resolved: true,
        }
    }

    fn valid_convergence_receipt(authority_set_hash: Hash) -> ConvergenceReceipt {
        ConvergenceReceipt {
            authority_set_hash,
            proof_hash: [0x44; 32],
            converged: true,
        }
    }

    fn make_verifier(signer: &Signer) -> BrokerSignatureVerifier {
        BrokerSignatureVerifier::new(signer.verifying_key())
    }

    // -----------------------------------------------------------------------
    // BrokerHealthStatus defaults
    // -----------------------------------------------------------------------

    #[test]
    fn health_status_default_is_failed() {
        assert_eq!(BrokerHealthStatus::default(), BrokerHealthStatus::Failed);
    }

    // -----------------------------------------------------------------------
    // BrokerHealthChecker: all invariants pass
    // -----------------------------------------------------------------------

    #[test]
    fn check_health_all_pass_returns_healthy() {
        let signer = test_signer();
        let verifier = make_verifier(&signer);
        let mut checker = BrokerHealthChecker::new();

        let envelope = valid_envelope(&signer);
        let eval_window = valid_eval_window();
        let freshness = valid_freshness_horizon();
        let frontier = valid_revocation_frontier();
        let convergence = valid_convergence_horizon();
        let authority_set = [0x55; 32];
        let receipts = vec![valid_convergence_receipt(authority_set)];

        let input = HealthCheckInput {
            envelope: Some(&envelope),
            eval_window: &eval_window,
            verifier: Some(&verifier),
            freshness_horizon: Some(&freshness),
            revocation_frontier: Some(&frontier),
            convergence_horizon: Some(&convergence),
            convergence_receipts: &receipts,
            required_authority_sets: &[authority_set],
        };

        let receipt = checker.check_health(&input, 42, &signer).unwrap();

        assert_eq!(receipt.status, BrokerHealthStatus::Healthy);
        assert_eq!(receipt.broker_tick, 42);
        assert_eq!(receipt.checks.len(), 3);
        assert!(receipt.checks.iter().all(|c| c.passed));
        assert_ne!(receipt.content_hash, [0u8; 32]);
        assert_ne!(receipt.signature, [0u8; 64]);
        assert!(receipt.verify(&verifier).is_ok());
    }

    // -----------------------------------------------------------------------
    // BrokerHealthChecker: TP001 failure
    // -----------------------------------------------------------------------

    #[test]
    fn check_health_tp001_fails_returns_failed() {
        let signer = test_signer();
        let mut checker = BrokerHealthChecker::new();

        let eval_window = valid_eval_window();
        let freshness = valid_freshness_horizon();
        let frontier = valid_revocation_frontier();
        let convergence = valid_convergence_horizon();

        // No envelope => TP001 fails
        let input = HealthCheckInput {
            envelope: None,
            eval_window: &eval_window,
            verifier: None,
            freshness_horizon: Some(&freshness),
            revocation_frontier: Some(&frontier),
            convergence_horizon: Some(&convergence),
            convergence_receipts: &[],
            required_authority_sets: &[],
        };

        let receipt = checker.check_health(&input, 10, &signer).unwrap();

        assert_eq!(receipt.status, BrokerHealthStatus::Failed);
        assert!(!receipt.checks[0].passed); // TP001
        assert!(receipt.checks[0].deny_reason.is_some());
        assert!(receipt.checks[1].passed); // TP002
        assert!(receipt.checks[2].passed); // TP003 (no required sets)
    }

    // -----------------------------------------------------------------------
    // BrokerHealthChecker: TP002 failure
    // -----------------------------------------------------------------------

    #[test]
    fn check_health_tp002_fails_returns_failed() {
        let signer = test_signer();
        let verifier = make_verifier(&signer);
        let mut checker = BrokerHealthChecker::new();

        let envelope = valid_envelope(&signer);
        let eval_window = valid_eval_window();
        let convergence = valid_convergence_horizon();

        // Missing freshness horizon => TP002 fails
        let input = HealthCheckInput {
            envelope: Some(&envelope),
            eval_window: &eval_window,
            verifier: Some(&verifier),
            freshness_horizon: None,
            revocation_frontier: None,
            convergence_horizon: Some(&convergence),
            convergence_receipts: &[],
            required_authority_sets: &[],
        };

        let receipt = checker.check_health(&input, 10, &signer).unwrap();

        assert_eq!(receipt.status, BrokerHealthStatus::Failed);
        assert!(receipt.checks[0].passed); // TP001
        assert!(!receipt.checks[1].passed); // TP002
        assert!(receipt.checks[1].deny_reason.is_some());
    }

    // -----------------------------------------------------------------------
    // BrokerHealthChecker: TP003 failure
    // -----------------------------------------------------------------------

    #[test]
    fn check_health_tp003_fails_returns_failed() {
        let signer = test_signer();
        let verifier = make_verifier(&signer);
        let mut checker = BrokerHealthChecker::new();

        let envelope = valid_envelope(&signer);
        let eval_window = valid_eval_window();
        let freshness = valid_freshness_horizon();
        let frontier = valid_revocation_frontier();
        let convergence = valid_convergence_horizon();

        // Required authority set with no matching receipt => TP003 fails
        let required = [0x99; 32];
        let input = HealthCheckInput {
            envelope: Some(&envelope),
            eval_window: &eval_window,
            verifier: Some(&verifier),
            freshness_horizon: Some(&freshness),
            revocation_frontier: Some(&frontier),
            convergence_horizon: Some(&convergence),
            convergence_receipts: &[],
            required_authority_sets: &[required],
        };

        let receipt = checker.check_health(&input, 10, &signer).unwrap();

        assert_eq!(receipt.status, BrokerHealthStatus::Failed);
        assert!(receipt.checks[0].passed); // TP001
        assert!(receipt.checks[1].passed); // TP002
        assert!(!receipt.checks[2].passed); // TP003
        assert!(receipt.checks[2].deny_reason.is_some());
    }

    // -----------------------------------------------------------------------
    // BrokerHealthChecker: all invariants fail
    // -----------------------------------------------------------------------

    #[test]
    fn check_health_all_fail_returns_failed() {
        let signer = test_signer();
        let mut checker = BrokerHealthChecker::new();

        let eval_window = valid_eval_window();
        let required = [0x99; 32];

        let input = HealthCheckInput {
            envelope: None,
            eval_window: &eval_window,
            verifier: None,
            freshness_horizon: None,
            revocation_frontier: None,
            convergence_horizon: None,
            convergence_receipts: &[],
            required_authority_sets: &[required],
        };

        let receipt = checker.check_health(&input, 10, &signer).unwrap();

        assert_eq!(receipt.status, BrokerHealthStatus::Failed);
        assert!(!receipt.checks[0].passed);
        assert!(!receipt.checks[1].passed);
        assert!(!receipt.checks[2].passed);
    }

    // -----------------------------------------------------------------------
    // Health receipt signature verification
    // -----------------------------------------------------------------------

    #[test]
    fn health_receipt_signature_verified_by_correct_key() {
        let signer = test_signer();
        let verifier = make_verifier(&signer);
        let mut checker = BrokerHealthChecker::new();

        let eval_window = valid_eval_window();
        let input = HealthCheckInput {
            envelope: None,
            eval_window: &eval_window,
            verifier: None,
            freshness_horizon: None,
            revocation_frontier: None,
            convergence_horizon: None,
            convergence_receipts: &[],
            required_authority_sets: &[],
        };

        let receipt = checker.check_health(&input, 1, &signer).unwrap();
        assert!(receipt.verify(&verifier).is_ok());
    }

    #[test]
    fn health_receipt_signature_rejected_by_wrong_key() {
        let signer = test_signer();
        let other_signer = test_signer();
        let other_verifier = make_verifier(&other_signer);
        let mut checker = BrokerHealthChecker::new();

        let eval_window = valid_eval_window();
        let input = HealthCheckInput {
            envelope: None,
            eval_window: &eval_window,
            verifier: None,
            freshness_horizon: None,
            revocation_frontier: None,
            convergence_horizon: None,
            convergence_receipts: &[],
            required_authority_sets: &[],
        };

        let receipt = checker.check_health(&input, 1, &signer).unwrap();
        assert!(receipt.verify(&other_verifier).is_err());
    }

    // -----------------------------------------------------------------------
    // History ring buffer cap
    // -----------------------------------------------------------------------

    #[test]
    fn health_history_bounded_at_max() {
        let signer = test_signer();
        let mut checker = BrokerHealthChecker::new();

        let eval_window = valid_eval_window();
        let input = HealthCheckInput {
            envelope: None,
            eval_window: &eval_window,
            verifier: None,
            freshness_horizon: None,
            revocation_frontier: None,
            convergence_horizon: None,
            convergence_receipts: &[],
            required_authority_sets: &[],
        };

        for tick in 0..(MAX_HEALTH_HISTORY + 10) {
            let _ = checker.check_health(&input, tick as u64, &signer);
        }

        assert_eq!(checker.history_len(), MAX_HEALTH_HISTORY);
        // Latest should be the last tick
        let latest = checker.latest().expect("history should not be empty");
        assert_eq!(latest.broker_tick, (MAX_HEALTH_HISTORY + 9) as u64);
    }

    // -----------------------------------------------------------------------
    // Latest status defaults to Failed
    // -----------------------------------------------------------------------

    #[test]
    fn latest_status_defaults_to_failed_when_empty() {
        let checker = BrokerHealthChecker::new();
        assert_eq!(checker.latest_status(), BrokerHealthStatus::Failed);
    }

    // -----------------------------------------------------------------------
    // Worker health gate: pass
    // -----------------------------------------------------------------------

    #[test]
    fn worker_gate_passes_on_healthy_receipt() {
        let signer = test_signer();
        let verifier = make_verifier(&signer);
        let mut checker = BrokerHealthChecker::new();

        let envelope = valid_envelope(&signer);
        let eval_window = valid_eval_window();
        let freshness = valid_freshness_horizon();
        let frontier = valid_revocation_frontier();
        let convergence = valid_convergence_horizon();

        let input = HealthCheckInput {
            envelope: Some(&envelope),
            eval_window: &eval_window,
            verifier: Some(&verifier),
            freshness_horizon: Some(&freshness),
            revocation_frontier: Some(&frontier),
            convergence_horizon: Some(&convergence),
            convergence_receipts: &[],
            required_authority_sets: &[],
        };

        let receipt = checker.check_health(&input, 42, &signer).unwrap();
        assert_eq!(receipt.status, BrokerHealthStatus::Healthy);

        let expected_hash = compute_eval_window_hash(&eval_window);
        let result = evaluate_worker_health_gate(
            Some(&receipt),
            &verifier,
            WorkerHealthPolicy::default(),
            expected_hash,
            42, // min_broker_tick matches receipt tick
            0,  // min_health_seq: permissive for this test
        );
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // Worker health gate: no receipt (fail-closed)
    // -----------------------------------------------------------------------

    #[test]
    fn worker_gate_rejects_when_no_receipt() {
        let signer = test_signer();
        let verifier = make_verifier(&signer);

        let result = evaluate_worker_health_gate(
            None,
            &verifier,
            WorkerHealthPolicy::StrictHealthy,
            [0u8; 32], // dummy hash, not reached
            0,         // dummy tick, not reached
            0,         // dummy seq, not reached
        );
        assert!(matches!(
            result,
            Err(WorkerHealthGateError::NoHealthReceipt)
        ));
    }

    // -----------------------------------------------------------------------
    // Worker health gate: failed receipt
    // -----------------------------------------------------------------------

    #[test]
    fn worker_gate_rejects_failed_receipt() {
        let signer = test_signer();
        let verifier = make_verifier(&signer);
        let mut checker = BrokerHealthChecker::new();

        let eval_window = valid_eval_window();
        let input = HealthCheckInput {
            envelope: None,
            eval_window: &eval_window,
            verifier: None,
            freshness_horizon: None,
            revocation_frontier: None,
            convergence_horizon: None,
            convergence_receipts: &[],
            required_authority_sets: &[],
        };

        let receipt = checker.check_health(&input, 1, &signer).unwrap();
        assert_eq!(receipt.status, BrokerHealthStatus::Failed);

        let expected_hash = compute_eval_window_hash(&eval_window);
        let result = evaluate_worker_health_gate(
            Some(&receipt),
            &verifier,
            WorkerHealthPolicy::StrictHealthy,
            expected_hash,
            1, // min_broker_tick matches receipt tick
            0, // min_health_seq: permissive for this test
        );
        assert!(matches!(
            result,
            Err(WorkerHealthGateError::HealthFailed { .. })
        ));
    }

    // -----------------------------------------------------------------------
    // Worker health gate: invalid signature
    // -----------------------------------------------------------------------

    #[test]
    fn worker_gate_rejects_invalid_signature() {
        let signer = test_signer();
        let other_signer = test_signer();
        let other_verifier = make_verifier(&other_signer);
        let mut checker = BrokerHealthChecker::new();

        let envelope = valid_envelope(&signer);
        let eval_window = valid_eval_window();
        let freshness = valid_freshness_horizon();
        let frontier = valid_revocation_frontier();
        let convergence = valid_convergence_horizon();

        let input = HealthCheckInput {
            envelope: Some(&envelope),
            eval_window: &eval_window,
            verifier: Some(&make_verifier(&signer)),
            freshness_horizon: Some(&freshness),
            revocation_frontier: Some(&frontier),
            convergence_horizon: Some(&convergence),
            convergence_receipts: &[],
            required_authority_sets: &[],
        };

        let receipt = checker.check_health(&input, 42, &signer).unwrap();

        let expected_hash = compute_eval_window_hash(&eval_window);
        // Verify with a different key => must reject
        let result = evaluate_worker_health_gate(
            Some(&receipt),
            &other_verifier,
            WorkerHealthPolicy::StrictHealthy,
            expected_hash,
            42,
            0, // min_health_seq: permissive for this test
        );
        assert!(matches!(
            result,
            Err(WorkerHealthGateError::VerificationFailed(_))
        ));
    }

    // -----------------------------------------------------------------------
    // Worker health gate: AllowDegraded policy
    // -----------------------------------------------------------------------

    #[test]
    fn worker_gate_allow_degraded_policy_admits_degraded() {
        // Since our current checker only emits Healthy or Failed, we manually
        // construct a degraded receipt to test the policy path.
        let signer = test_signer();
        let verifier = make_verifier(&signer);
        let eval_window = valid_eval_window();

        let checks = vec![
            InvariantCheckResult {
                predicate_id: "TP001".to_string(),
                passed: true,
                deny_reason: None,
            },
            InvariantCheckResult {
                predicate_id: "TP002".to_string(),
                passed: true,
                deny_reason: None,
            },
            InvariantCheckResult {
                predicate_id: "TP003".to_string(),
                passed: true,
                deny_reason: None,
            },
        ];

        let eval_window_hash = compute_eval_window_hash(&eval_window);
        let content_hash = compute_health_receipt_hash(
            42,
            0, // health_seq for manually constructed receipt
            eval_window_hash,
            BrokerHealthStatus::Degraded,
            &checks,
        );
        let signature_bytes = signer.sign(&content_hash);

        let receipt = HealthReceiptV1 {
            schema_id: HEALTH_RECEIPT_SCHEMA_ID.to_string(),
            schema_version: HEALTH_RECEIPT_SCHEMA_VERSION.to_string(),
            status: BrokerHealthStatus::Degraded,
            broker_tick: 42,
            health_seq: 0,
            eval_window_hash,
            checks,
            content_hash,
            signature: signature_bytes.to_bytes(),
            signer_id: signer.verifying_key().to_bytes(),
        };

        // AllowDegraded should pass
        let result = evaluate_worker_health_gate(
            Some(&receipt),
            &verifier,
            WorkerHealthPolicy::AllowDegraded,
            eval_window_hash,
            42,
            0, // min_health_seq: permissive for this test
        );
        assert!(result.is_ok());

        // StrictHealthy should reject
        let result = evaluate_worker_health_gate(
            Some(&receipt),
            &verifier,
            WorkerHealthPolicy::StrictHealthy,
            eval_window_hash,
            42,
            0, // min_health_seq: permissive for this test
        );
        assert!(matches!(
            result,
            Err(WorkerHealthGateError::HealthDegraded { .. })
        ));
    }

    // -----------------------------------------------------------------------
    // Content hash determinism
    // -----------------------------------------------------------------------

    #[test]
    fn content_hash_is_deterministic() {
        let signer = test_signer();
        let mut checker1 = BrokerHealthChecker::new();
        let mut checker2 = BrokerHealthChecker::new();

        let eval_window = valid_eval_window();
        let input = HealthCheckInput {
            envelope: None,
            eval_window: &eval_window,
            verifier: None,
            freshness_horizon: None,
            revocation_frontier: None,
            convergence_horizon: None,
            convergence_receipts: &[],
            required_authority_sets: &[],
        };

        let r1 = checker1.check_health(&input, 42, &signer).unwrap();
        let r2 = checker2.check_health(&input, 42, &signer).unwrap();

        // Same inputs => same content hash
        assert_eq!(r1.content_hash, r2.content_hash);
        // Signatures are deterministic for Ed25519 with same key + same message
        assert_eq!(r1.signature, r2.signature);
    }

    // -----------------------------------------------------------------------
    // Content hash changes with different inputs
    // -----------------------------------------------------------------------

    #[test]
    fn content_hash_changes_with_different_tick() {
        let signer = test_signer();
        let mut checker = BrokerHealthChecker::new();

        let eval_window = valid_eval_window();
        let input = HealthCheckInput {
            envelope: None,
            eval_window: &eval_window,
            verifier: None,
            freshness_horizon: None,
            revocation_frontier: None,
            convergence_horizon: None,
            convergence_receipts: &[],
            required_authority_sets: &[],
        };

        let r1 = checker.check_health(&input, 1, &signer).unwrap();
        let r2 = checker.check_health(&input, 2, &signer).unwrap();

        assert_ne!(r1.content_hash, r2.content_hash);
    }

    // -----------------------------------------------------------------------
    // Content hash changes with different eval windows
    // -----------------------------------------------------------------------

    #[test]
    fn content_hash_changes_with_different_eval_window() {
        let signer = test_signer();
        let mut checker = BrokerHealthChecker::new();

        let eval_window1 = HtfEvaluationWindow {
            boundary_id: "boundary-A".to_string(),
            authority_clock: "clock-1".to_string(),
            tick_start: 100,
            tick_end: 200,
        };
        let eval_window2 = HtfEvaluationWindow {
            boundary_id: "boundary-B".to_string(),
            authority_clock: "clock-1".to_string(),
            tick_start: 100,
            tick_end: 200,
        };

        let input1 = HealthCheckInput {
            envelope: None,
            eval_window: &eval_window1,
            verifier: None,
            freshness_horizon: None,
            revocation_frontier: None,
            convergence_horizon: None,
            convergence_receipts: &[],
            required_authority_sets: &[],
        };
        let input2 = HealthCheckInput {
            envelope: None,
            eval_window: &eval_window2,
            verifier: None,
            freshness_horizon: None,
            revocation_frontier: None,
            convergence_horizon: None,
            convergence_receipts: &[],
            required_authority_sets: &[],
        };

        let r1 = checker.check_health(&input1, 1, &signer).unwrap();
        let r2 = checker.check_health(&input2, 1, &signer).unwrap();

        assert_ne!(r1.eval_window_hash, r2.eval_window_hash);
        assert_ne!(r1.content_hash, r2.content_hash);
    }

    // -----------------------------------------------------------------------
    // Format deny reasons
    // -----------------------------------------------------------------------

    #[test]
    fn format_deny_reasons_produces_readable_output() {
        let checks = vec![
            InvariantCheckResult {
                predicate_id: "TP001".to_string(),
                passed: false,
                deny_reason: Some("envelope_missing".to_string()),
            },
            InvariantCheckResult {
                predicate_id: "TP002".to_string(),
                passed: true,
                deny_reason: None,
            },
            InvariantCheckResult {
                predicate_id: "TP003".to_string(),
                passed: false,
                deny_reason: Some("convergence_receipt_missing".to_string()),
            },
        ];

        let reasons = format_deny_reasons(&checks);
        assert!(reasons.contains("TP001: envelope_missing"));
        assert!(reasons.contains("TP003: convergence_receipt_missing"));
        assert!(!reasons.contains("TP002"));
    }

    #[test]
    fn format_deny_reasons_returns_unknown_when_all_pass() {
        let checks = vec![InvariantCheckResult {
            predicate_id: "TP001".to_string(),
            passed: true,
            deny_reason: None,
        }];

        assert_eq!(format_deny_reasons(&checks), "unknown");
    }

    // -----------------------------------------------------------------------
    // CQ-BLOCKER-1: Payload tampering detection
    // -----------------------------------------------------------------------

    #[test]
    fn verify_rejects_tampered_status() {
        let signer = test_signer();
        let verifier = make_verifier(&signer);
        let mut checker = BrokerHealthChecker::new();

        let eval_window = valid_eval_window();
        let input = HealthCheckInput {
            envelope: None,
            eval_window: &eval_window,
            verifier: None,
            freshness_horizon: None,
            revocation_frontier: None,
            convergence_horizon: None,
            convergence_receipts: &[],
            required_authority_sets: &[],
        };

        let mut receipt = checker.check_health(&input, 1, &signer).unwrap();
        assert_eq!(receipt.status, BrokerHealthStatus::Failed);

        // Tamper: change Failed -> Healthy without re-signing
        receipt.status = BrokerHealthStatus::Healthy;

        // Verification must detect the tampering via content hash mismatch
        let result = receipt.verify(&verifier);
        assert!(
            matches!(result, Err(BrokerHealthError::ContentHashMismatch)),
            "expected ContentHashMismatch, got {result:?}"
        );
    }

    #[test]
    fn verify_rejects_tampered_broker_tick() {
        let signer = test_signer();
        let verifier = make_verifier(&signer);
        let mut checker = BrokerHealthChecker::new();

        let eval_window = valid_eval_window();
        let input = HealthCheckInput {
            envelope: None,
            eval_window: &eval_window,
            verifier: None,
            freshness_horizon: None,
            revocation_frontier: None,
            convergence_horizon: None,
            convergence_receipts: &[],
            required_authority_sets: &[],
        };

        let mut receipt = checker.check_health(&input, 1, &signer).unwrap();

        // Tamper: change broker_tick without re-signing
        receipt.broker_tick = 9999;

        let result = receipt.verify(&verifier);
        assert!(matches!(
            result,
            Err(BrokerHealthError::ContentHashMismatch)
        ));
    }

    #[test]
    fn verify_rejects_tampered_checks() {
        let signer = test_signer();
        let verifier = make_verifier(&signer);
        let mut checker = BrokerHealthChecker::new();

        let eval_window = valid_eval_window();
        let input = HealthCheckInput {
            envelope: None,
            eval_window: &eval_window,
            verifier: None,
            freshness_horizon: None,
            revocation_frontier: None,
            convergence_horizon: None,
            convergence_receipts: &[],
            required_authority_sets: &[],
        };

        let mut receipt = checker.check_health(&input, 1, &signer).unwrap();

        // Tamper: mark TP001 as passed without re-signing
        receipt.checks[0].passed = true;
        receipt.checks[0].deny_reason = None;

        let result = receipt.verify(&verifier);
        assert!(matches!(
            result,
            Err(BrokerHealthError::ContentHashMismatch)
        ));
    }

    #[test]
    fn verify_rejects_wrong_schema_id() {
        let signer = test_signer();
        let verifier = make_verifier(&signer);
        let mut checker = BrokerHealthChecker::new();

        let eval_window = valid_eval_window();
        let input = HealthCheckInput {
            envelope: None,
            eval_window: &eval_window,
            verifier: None,
            freshness_horizon: None,
            revocation_frontier: None,
            convergence_horizon: None,
            convergence_receipts: &[],
            required_authority_sets: &[],
        };

        let mut receipt = checker.check_health(&input, 1, &signer).unwrap();

        // Tamper: change schema_id
        receipt.schema_id = "evil.schema.v1".to_string();

        let result = receipt.verify(&verifier);
        assert!(matches!(
            result,
            Err(BrokerHealthError::SchemaMismatch { .. })
        ));
    }

    // -----------------------------------------------------------------------
    // SEC-MAJOR-2: required_authority_sets bound enforcement
    // -----------------------------------------------------------------------

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn check_health_rejects_too_many_required_authority_sets() {
        let signer = test_signer();
        let mut checker = BrokerHealthChecker::new();

        let eval_window = valid_eval_window();
        let oversized: Vec<Hash> = (0..=MAX_HEALTH_REQUIRED_AUTHORITY_SETS)
            .map(|i| {
                let mut h = [0u8; 32];
                h[0] = (i & 0xFF) as u8;
                h[1] = ((i >> 8) & 0xFF) as u8;
                h
            })
            .collect();

        let input = HealthCheckInput {
            envelope: None,
            eval_window: &eval_window,
            verifier: None,
            freshness_horizon: None,
            revocation_frontier: None,
            convergence_horizon: None,
            convergence_receipts: &[],
            required_authority_sets: &oversized,
        };

        let result = checker.check_health(&input, 1, &signer);
        assert!(matches!(
            result,
            Err(BrokerHealthError::TooManyRequiredAuthoritySets { .. })
        ));
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn check_health_accepts_max_required_authority_sets() {
        let signer = test_signer();
        let mut checker = BrokerHealthChecker::new();

        let eval_window = valid_eval_window();
        let at_limit: Vec<Hash> = (0..MAX_HEALTH_REQUIRED_AUTHORITY_SETS)
            .map(|i| {
                let mut h = [0u8; 32];
                h[0] = (i & 0xFF) as u8;
                h[1] = ((i >> 8) & 0xFF) as u8;
                h
            })
            .collect();

        let input = HealthCheckInput {
            envelope: None,
            eval_window: &eval_window,
            verifier: None,
            freshness_horizon: None,
            revocation_frontier: None,
            convergence_horizon: None,
            convergence_receipts: &[],
            required_authority_sets: &at_limit,
        };

        // Should succeed (at limit, not over)
        let result = checker.check_health(&input, 1, &signer);
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // SEC-BLOCKER-1: Bounded deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn deserialize_rejects_oversized_predicate_id() {
        let long_id = "x".repeat(MAX_PREDICATE_ID_LENGTH + 1);
        let json =
            format!(r#"{{"predicate_id": "{long_id}", "passed": true, "deny_reason": null}}"#);
        let result: Result<InvariantCheckResult, _> = serde_json::from_str(&json);
        assert!(result.is_err(), "should reject oversized predicate_id");
    }

    #[test]
    fn deserialize_rejects_oversized_deny_reason() {
        let long_reason = "x".repeat(MAX_DENY_REASON_LENGTH + 1);
        let json = format!(
            r#"{{"predicate_id": "TP001", "passed": false, "deny_reason": "{long_reason}"}}"#
        );
        let result: Result<InvariantCheckResult, _> = serde_json::from_str(&json);
        assert!(result.is_err(), "should reject oversized deny_reason");
    }

    #[test]
    fn deserialize_rejects_oversized_checks_vec() {
        // Build a JSON with MAX_HEALTH_FINDINGS + 1 checks
        let check_json = r#"{"predicate_id": "TP", "passed": true, "deny_reason": null}"#;
        let checks_array = format!(
            "[{}]",
            std::iter::repeat_n(check_json, MAX_HEALTH_FINDINGS + 1)
                .collect::<Vec<_>>()
                .join(",")
        );
        let receipt_json = format!(
            r#"{{
                "schema_id": "apm2.fac_broker_health_receipt.v1",
                "schema_version": "1.0.0",
                "status": "HEALTHY",
                "broker_tick": 1,
                "health_seq": 0,
                "eval_window_hash": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
                "checks": {checks_array},
                "content_hash": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
                "signature": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
                "signer_id": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
            }}"#
        );
        let result: Result<HealthReceiptV1, _> = serde_json::from_str(&receipt_json);
        assert!(result.is_err(), "should reject oversized checks vec");
    }

    #[test]
    fn deserialize_rejects_oversized_schema_id() {
        let long_schema = "x".repeat(MAX_SCHEMA_ID_LENGTH + 1);
        let receipt_json = format!(
            r#"{{
                "schema_id": "{long_schema}",
                "schema_version": "1.0.0",
                "status": "HEALTHY",
                "broker_tick": 1,
                "health_seq": 0,
                "eval_window_hash": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
                "checks": [],
                "content_hash": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
                "signature": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
                "signer_id": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
            }}"#
        );
        let result: Result<HealthReceiptV1, _> = serde_json::from_str(&receipt_json);
        assert!(result.is_err(), "should reject oversized schema_id");
    }

    // -----------------------------------------------------------------------
    // HealthReceiptV1::validate
    // -----------------------------------------------------------------------

    #[test]
    fn validate_accepts_valid_receipt() {
        let signer = test_signer();
        let mut checker = BrokerHealthChecker::new();

        let eval_window = valid_eval_window();
        let input = HealthCheckInput {
            envelope: None,
            eval_window: &eval_window,
            verifier: None,
            freshness_horizon: None,
            revocation_frontier: None,
            convergence_horizon: None,
            convergence_receipts: &[],
            required_authority_sets: &[],
        };

        let receipt = checker.check_health(&input, 1, &signer).unwrap();
        assert!(receipt.validate().is_ok());
    }

    #[test]
    fn validate_rejects_wrong_schema() {
        let signer = test_signer();
        let mut checker = BrokerHealthChecker::new();

        let eval_window = valid_eval_window();
        let input = HealthCheckInput {
            envelope: None,
            eval_window: &eval_window,
            verifier: None,
            freshness_horizon: None,
            revocation_frontier: None,
            convergence_horizon: None,
            convergence_receipts: &[],
            required_authority_sets: &[],
        };

        let mut receipt = checker.check_health(&input, 1, &signer).unwrap();
        receipt.schema_id = "wrong.schema".to_string();
        assert!(matches!(
            receipt.validate(),
            Err(BrokerHealthError::SchemaMismatch { .. })
        ));
    }

    // -----------------------------------------------------------------------
    // SEC-MINOR-2: eval_window_hash binding
    // -----------------------------------------------------------------------

    #[test]
    fn eval_window_hash_is_deterministic() {
        let w1 = valid_eval_window();
        let w2 = valid_eval_window();
        assert_eq!(compute_eval_window_hash(&w1), compute_eval_window_hash(&w2));
    }

    #[test]
    fn eval_window_hash_differs_for_different_windows() {
        let w1 = valid_eval_window();
        let mut w2 = valid_eval_window();
        w2.tick_end = 999;
        assert_ne!(compute_eval_window_hash(&w1), compute_eval_window_hash(&w2));
    }

    // -----------------------------------------------------------------------
    // Visitor-based bounded string deserialization (RSK-1601 OOM hardening)
    // -----------------------------------------------------------------------

    #[test]
    fn visitor_bounded_string_accepts_at_limit() {
        // predicate_id at exactly MAX_PREDICATE_ID_LENGTH should succeed
        let exact_id = "x".repeat(MAX_PREDICATE_ID_LENGTH);
        let json =
            format!(r#"{{"predicate_id": "{exact_id}", "passed": true, "deny_reason": null}}"#);
        let result: Result<InvariantCheckResult, _> = serde_json::from_str(&json);
        assert!(
            result.is_ok(),
            "should accept predicate_id at exactly MAX length"
        );
        assert_eq!(result.unwrap().predicate_id.len(), MAX_PREDICATE_ID_LENGTH);
    }

    #[test]
    fn visitor_bounded_string_rejects_one_over_limit() {
        // predicate_id at MAX_PREDICATE_ID_LENGTH + 1 must be rejected
        let over_id = "x".repeat(MAX_PREDICATE_ID_LENGTH + 1);
        let json =
            format!(r#"{{"predicate_id": "{over_id}", "passed": true, "deny_reason": null}}"#);
        let result: Result<InvariantCheckResult, _> = serde_json::from_str(&json);
        assert!(result.is_err(), "should reject predicate_id one over MAX");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("exceeds maximum length"),
            "error should mention length violation: {err}"
        );
    }

    #[test]
    fn visitor_bounded_option_string_accepts_null() {
        // deny_reason = null should deserialize to None
        let json = r#"{"predicate_id": "TP001", "passed": true, "deny_reason": null}"#;
        let result: Result<InvariantCheckResult, _> = serde_json::from_str(json);
        assert!(result.is_ok(), "should accept null deny_reason");
        assert_eq!(result.unwrap().deny_reason, None);
    }

    #[test]
    fn visitor_bounded_option_string_accepts_at_limit() {
        // deny_reason at exactly MAX_DENY_REASON_LENGTH should succeed
        let exact_reason = "r".repeat(MAX_DENY_REASON_LENGTH);
        let json = format!(
            r#"{{"predicate_id": "TP001", "passed": false, "deny_reason": "{exact_reason}"}}"#
        );
        let result: Result<InvariantCheckResult, _> = serde_json::from_str(&json);
        assert!(
            result.is_ok(),
            "should accept deny_reason at exactly MAX length"
        );
        assert_eq!(
            result.unwrap().deny_reason.unwrap().len(),
            MAX_DENY_REASON_LENGTH
        );
    }

    #[test]
    fn visitor_bounded_option_string_rejects_one_over_limit() {
        // deny_reason at MAX_DENY_REASON_LENGTH + 1 must be rejected
        let over_reason = "r".repeat(MAX_DENY_REASON_LENGTH + 1);
        let json = format!(
            r#"{{"predicate_id": "TP001", "passed": false, "deny_reason": "{over_reason}"}}"#
        );
        let result: Result<InvariantCheckResult, _> = serde_json::from_str(&json);
        assert!(result.is_err(), "should reject deny_reason one over MAX");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("exceeds maximum length"),
            "error should mention length violation: {err}"
        );
    }

    #[test]
    fn visitor_bounded_schema_id_rejects_oversized() {
        // Schema ID oversized by a large margin to verify visitor path
        let huge_schema = "s".repeat(MAX_SCHEMA_ID_LENGTH + 100);
        let receipt_json = format!(
            r#"{{
                "schema_id": "{huge_schema}",
                "schema_version": "1.0.0",
                "status": "HEALTHY",
                "broker_tick": 1,
                "health_seq": 0,
                "eval_window_hash": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
                "checks": [],
                "content_hash": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
                "signature": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
                "signer_id": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
            }}"#
        );
        let result: Result<HealthReceiptV1, _> = serde_json::from_str(&receipt_json);
        assert!(
            result.is_err(),
            "should reject oversized schema_id via visitor"
        );
    }

    #[test]
    fn visitor_bounded_schema_version_rejects_oversized() {
        let huge_version = "v".repeat(MAX_SCHEMA_VERSION_LENGTH + 1);
        let receipt_json = format!(
            r#"{{
                "schema_id": "apm2.fac_broker_health_receipt.v1",
                "schema_version": "{huge_version}",
                "status": "HEALTHY",
                "broker_tick": 1,
                "health_seq": 0,
                "eval_window_hash": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
                "checks": [],
                "content_hash": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
                "signature": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
                "signer_id": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
            }}"#
        );
        let result: Result<HealthReceiptV1, _> = serde_json::from_str(&receipt_json);
        assert!(
            result.is_err(),
            "should reject oversized schema_version via visitor"
        );
    }

    // -----------------------------------------------------------------------
    // MAJOR-1: Replay protection — eval_window_hash binding (INV-BH-010)
    // -----------------------------------------------------------------------

    #[test]
    fn worker_gate_rejects_receipt_with_wrong_eval_window_hash() {
        let signer = test_signer();
        let verifier = make_verifier(&signer);
        let mut checker = BrokerHealthChecker::new();

        let envelope = valid_envelope(&signer);
        let eval_window = valid_eval_window();
        let freshness = valid_freshness_horizon();
        let frontier = valid_revocation_frontier();
        let convergence = valid_convergence_horizon();

        let input = HealthCheckInput {
            envelope: Some(&envelope),
            eval_window: &eval_window,
            verifier: Some(&verifier),
            freshness_horizon: Some(&freshness),
            revocation_frontier: Some(&frontier),
            convergence_horizon: Some(&convergence),
            convergence_receipts: &[],
            required_authority_sets: &[],
        };

        let receipt = checker.check_health(&input, 42, &signer).unwrap();
        assert_eq!(receipt.status, BrokerHealthStatus::Healthy);

        // Replay attack: present this healthy receipt with a DIFFERENT
        // expected eval_window_hash (simulating context change)
        let different_window = HtfEvaluationWindow {
            boundary_id: "different-boundary".to_string(),
            authority_clock: "different-clock".to_string(),
            tick_start: 500,
            tick_end: 600,
        };
        let wrong_hash = compute_eval_window_hash(&different_window);

        let result = evaluate_worker_health_gate(
            Some(&receipt),
            &verifier,
            WorkerHealthPolicy::StrictHealthy,
            wrong_hash,
            42,
            0, // min_health_seq: permissive for this test
        );
        assert!(
            matches!(result, Err(WorkerHealthGateError::EvalWindowMismatch)),
            "expected EvalWindowMismatch, got {result:?}"
        );
    }

    #[test]
    fn worker_gate_accepts_receipt_with_matching_eval_window_hash() {
        let signer = test_signer();
        let verifier = make_verifier(&signer);
        let mut checker = BrokerHealthChecker::new();

        let envelope = valid_envelope(&signer);
        let eval_window = valid_eval_window();
        let freshness = valid_freshness_horizon();
        let frontier = valid_revocation_frontier();
        let convergence = valid_convergence_horizon();

        let input = HealthCheckInput {
            envelope: Some(&envelope),
            eval_window: &eval_window,
            verifier: Some(&verifier),
            freshness_horizon: Some(&freshness),
            revocation_frontier: Some(&frontier),
            convergence_horizon: Some(&convergence),
            convergence_receipts: &[],
            required_authority_sets: &[],
        };

        let receipt = checker.check_health(&input, 42, &signer).unwrap();
        assert_eq!(receipt.status, BrokerHealthStatus::Healthy);

        let correct_hash = compute_eval_window_hash(&eval_window);
        let result = evaluate_worker_health_gate(
            Some(&receipt),
            &verifier,
            WorkerHealthPolicy::StrictHealthy,
            correct_hash,
            1, // min_broker_tick well below receipt tick 42
            0, // min_health_seq: permissive for this test
        );
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    // -----------------------------------------------------------------------
    // MAJOR-1: Replay protection — stale broker tick (INV-BH-011)
    // -----------------------------------------------------------------------

    #[test]
    fn worker_gate_rejects_stale_receipt_below_min_broker_tick() {
        let signer = test_signer();
        let verifier = make_verifier(&signer);
        let mut checker = BrokerHealthChecker::new();

        let envelope = valid_envelope(&signer);
        let eval_window = valid_eval_window();
        let freshness = valid_freshness_horizon();
        let frontier = valid_revocation_frontier();
        let convergence = valid_convergence_horizon();

        let input = HealthCheckInput {
            envelope: Some(&envelope),
            eval_window: &eval_window,
            verifier: Some(&verifier),
            freshness_horizon: Some(&freshness),
            revocation_frontier: Some(&frontier),
            convergence_horizon: Some(&convergence),
            convergence_receipts: &[],
            required_authority_sets: &[],
        };

        // Generate receipt at tick 42
        let receipt = checker.check_health(&input, 42, &signer).unwrap();
        assert_eq!(receipt.status, BrokerHealthStatus::Healthy);

        let correct_hash = compute_eval_window_hash(&eval_window);

        // Replay attack: present old tick-42 receipt when system requires
        // at least tick 100
        let result = evaluate_worker_health_gate(
            Some(&receipt),
            &verifier,
            WorkerHealthPolicy::StrictHealthy,
            correct_hash,
            100, // min_broker_tick above receipt's 42
            0,   // min_health_seq: permissive for this test
        );
        assert!(
            matches!(
                result,
                Err(WorkerHealthGateError::StaleReceipt {
                    receipt_tick: 42,
                    min_tick: 100,
                })
            ),
            "expected StaleReceipt, got {result:?}"
        );
    }

    #[test]
    fn worker_gate_accepts_receipt_at_exact_min_broker_tick() {
        let signer = test_signer();
        let verifier = make_verifier(&signer);
        let mut checker = BrokerHealthChecker::new();

        let envelope = valid_envelope(&signer);
        let eval_window = valid_eval_window();
        let freshness = valid_freshness_horizon();
        let frontier = valid_revocation_frontier();
        let convergence = valid_convergence_horizon();

        let input = HealthCheckInput {
            envelope: Some(&envelope),
            eval_window: &eval_window,
            verifier: Some(&verifier),
            freshness_horizon: Some(&freshness),
            revocation_frontier: Some(&frontier),
            convergence_horizon: Some(&convergence),
            convergence_receipts: &[],
            required_authority_sets: &[],
        };

        let receipt = checker.check_health(&input, 42, &signer).unwrap();
        assert_eq!(receipt.status, BrokerHealthStatus::Healthy);

        let correct_hash = compute_eval_window_hash(&eval_window);

        // Exact match: broker_tick == min_broker_tick should pass
        let result = evaluate_worker_health_gate(
            Some(&receipt),
            &verifier,
            WorkerHealthPolicy::StrictHealthy,
            correct_hash,
            42, // exactly matches receipt tick
            0,  // min_health_seq: permissive for this test
        );
        assert!(
            result.is_ok(),
            "expected Ok at exact min_broker_tick, got {result:?}"
        );
    }

    #[test]
    fn worker_gate_rejects_stale_receipt_one_below_min() {
        let signer = test_signer();
        let verifier = make_verifier(&signer);
        let mut checker = BrokerHealthChecker::new();

        let envelope = valid_envelope(&signer);
        let eval_window = valid_eval_window();
        let freshness = valid_freshness_horizon();
        let frontier = valid_revocation_frontier();
        let convergence = valid_convergence_horizon();

        let input = HealthCheckInput {
            envelope: Some(&envelope),
            eval_window: &eval_window,
            verifier: Some(&verifier),
            freshness_horizon: Some(&freshness),
            revocation_frontier: Some(&frontier),
            convergence_horizon: Some(&convergence),
            convergence_receipts: &[],
            required_authority_sets: &[],
        };

        let receipt = checker.check_health(&input, 42, &signer).unwrap();
        let correct_hash = compute_eval_window_hash(&eval_window);

        // min_broker_tick = 43 (one above receipt's 42) => reject
        let result = evaluate_worker_health_gate(
            Some(&receipt),
            &verifier,
            WorkerHealthPolicy::StrictHealthy,
            correct_hash,
            43,
            0, // min_health_seq: permissive for this test
        );
        assert!(
            matches!(
                result,
                Err(WorkerHealthGateError::StaleReceipt {
                    receipt_tick: 42,
                    min_tick: 43,
                })
            ),
            "expected StaleReceipt, got {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // MAJOR-1: Full replay scenario — healthy receipt replayed after failure
    // -----------------------------------------------------------------------

    #[test]
    fn replay_of_old_healthy_receipt_rejected_after_broker_degradation() {
        let signer = test_signer();
        let verifier = make_verifier(&signer);
        let mut checker = BrokerHealthChecker::new();

        let envelope = valid_envelope(&signer);
        let eval_window = valid_eval_window();
        let freshness = valid_freshness_horizon();
        let frontier = valid_revocation_frontier();
        let convergence = valid_convergence_horizon();

        // Step 1: Broker is healthy at tick 10
        let healthy_input = HealthCheckInput {
            envelope: Some(&envelope),
            eval_window: &eval_window,
            verifier: Some(&verifier),
            freshness_horizon: Some(&freshness),
            revocation_frontier: Some(&frontier),
            convergence_horizon: Some(&convergence),
            convergence_receipts: &[],
            required_authority_sets: &[],
        };
        let healthy_receipt = checker.check_health(&healthy_input, 10, &signer).unwrap();
        assert_eq!(healthy_receipt.status, BrokerHealthStatus::Healthy);

        // Step 2: Broker degrades at tick 20 (TP001 fails — no envelope)
        let failed_input = HealthCheckInput {
            envelope: None,
            eval_window: &eval_window,
            verifier: None,
            freshness_horizon: Some(&freshness),
            revocation_frontier: Some(&frontier),
            convergence_horizon: Some(&convergence),
            convergence_receipts: &[],
            required_authority_sets: &[],
        };
        let failed_receipt = checker.check_health(&failed_input, 20, &signer).unwrap();
        assert_eq!(failed_receipt.status, BrokerHealthStatus::Failed);

        let correct_hash = compute_eval_window_hash(&eval_window);

        // Step 3: Attacker replays the old healthy receipt (tick 10)
        // Worker should require min_broker_tick >= 20 (current tick)
        let result = evaluate_worker_health_gate(
            Some(&healthy_receipt),
            &verifier,
            WorkerHealthPolicy::StrictHealthy,
            correct_hash,
            20, // min_broker_tick = current tick
            0,  // min_health_seq: permissive (tick check catches this)
        );
        assert!(
            matches!(
                result,
                Err(WorkerHealthGateError::StaleReceipt {
                    receipt_tick: 10,
                    min_tick: 20,
                })
            ),
            "replay of old healthy receipt must be rejected, got {result:?}"
        );

        // Step 4: Current failed receipt passes freshness but is rejected
        // on status
        let result = evaluate_worker_health_gate(
            Some(&failed_receipt),
            &verifier,
            WorkerHealthPolicy::StrictHealthy,
            correct_hash,
            20,
            0, // min_health_seq: permissive for this test
        );
        assert!(
            matches!(result, Err(WorkerHealthGateError::HealthFailed { .. })),
            "current failed receipt must be rejected on status, got {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // MINOR-1: Error path persists synthetic FAILED receipt (INV-BH-012)
    // -----------------------------------------------------------------------

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn check_health_error_persists_synthetic_failed_receipt() {
        let signer = test_signer();
        let verifier = make_verifier(&signer);
        let mut checker = BrokerHealthChecker::new();

        let envelope = valid_envelope(&signer);
        let eval_window = valid_eval_window();
        let freshness = valid_freshness_horizon();
        let frontier = valid_revocation_frontier();
        let convergence = valid_convergence_horizon();

        // Step 1: Establish healthy state at tick 5
        let healthy_input = HealthCheckInput {
            envelope: Some(&envelope),
            eval_window: &eval_window,
            verifier: Some(&verifier),
            freshness_horizon: Some(&freshness),
            revocation_frontier: Some(&frontier),
            convergence_horizon: Some(&convergence),
            convergence_receipts: &[],
            required_authority_sets: &[],
        };
        let healthy_receipt = checker.check_health(&healthy_input, 5, &signer).unwrap();
        assert_eq!(healthy_receipt.status, BrokerHealthStatus::Healthy);
        assert_eq!(checker.latest_status(), BrokerHealthStatus::Healthy);

        // Step 2: Trigger input overflow error at tick 10
        let oversized: Vec<Hash> = (0..=MAX_HEALTH_REQUIRED_AUTHORITY_SETS)
            .map(|i| {
                let mut h = [0u8; 32];
                h[0] = (i & 0xFF) as u8;
                h[1] = ((i >> 8) & 0xFF) as u8;
                h
            })
            .collect();

        let error_input = HealthCheckInput {
            envelope: Some(&envelope),
            eval_window: &eval_window,
            verifier: Some(&verifier),
            freshness_horizon: Some(&freshness),
            revocation_frontier: Some(&frontier),
            convergence_horizon: Some(&convergence),
            convergence_receipts: &[],
            required_authority_sets: &oversized,
        };

        let result = checker.check_health(&error_input, 10, &signer);
        assert!(result.is_err(), "should return Err for oversized input");

        // Step 3: Verify synthetic FAILED receipt was persisted
        assert_eq!(
            checker.latest_status(),
            BrokerHealthStatus::Failed,
            "latest status must be Failed after error, not stale Healthy"
        );

        let latest = checker.latest().expect("history should not be empty");
        assert_eq!(latest.status, BrokerHealthStatus::Failed);
        assert_eq!(latest.broker_tick, 10);
        assert_eq!(latest.checks.len(), 1);
        assert_eq!(latest.checks[0].predicate_id, "EVAL_ERROR");
        assert!(!latest.checks[0].passed);
        assert!(latest.checks[0].deny_reason.is_some());
        assert!(
            latest.checks[0]
                .deny_reason
                .as_ref()
                .unwrap()
                .contains("exceeds maximum"),
            "deny_reason should contain machine-readable error"
        );

        // Step 4: Verify the synthetic receipt is properly signed
        assert!(
            latest.verify(&verifier).is_ok(),
            "synthetic FAILED receipt must be verifiable"
        );
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn synthetic_failed_receipt_prevents_stale_healthy_gate_pass() {
        let signer = test_signer();
        let verifier = make_verifier(&signer);
        let mut checker = BrokerHealthChecker::new();

        let envelope = valid_envelope(&signer);
        let eval_window = valid_eval_window();
        let freshness = valid_freshness_horizon();
        let frontier = valid_revocation_frontier();
        let convergence = valid_convergence_horizon();

        // Step 1: Establish healthy state at tick 5
        let healthy_input = HealthCheckInput {
            envelope: Some(&envelope),
            eval_window: &eval_window,
            verifier: Some(&verifier),
            freshness_horizon: Some(&freshness),
            revocation_frontier: Some(&frontier),
            convergence_horizon: Some(&convergence),
            convergence_receipts: &[],
            required_authority_sets: &[],
        };
        let _healthy = checker.check_health(&healthy_input, 5, &signer).unwrap();

        // Step 2: Error path at tick 10 — synthetic FAILED persisted
        let oversized: Vec<Hash> = (0..=MAX_HEALTH_REQUIRED_AUTHORITY_SETS)
            .map(|i| {
                let mut h = [0u8; 32];
                h[0] = (i & 0xFF) as u8;
                h[1] = ((i >> 8) & 0xFF) as u8;
                h
            })
            .collect();

        let error_input = HealthCheckInput {
            envelope: Some(&envelope),
            eval_window: &eval_window,
            verifier: Some(&verifier),
            freshness_horizon: Some(&freshness),
            revocation_frontier: Some(&frontier),
            convergence_horizon: Some(&convergence),
            convergence_receipts: &[],
            required_authority_sets: &oversized,
        };
        let _ = checker.check_health(&error_input, 10, &signer);

        // Step 3: Gate evaluation with latest receipt must fail
        let latest = checker.latest().unwrap();
        let correct_hash = compute_eval_window_hash(&eval_window);
        let result = evaluate_worker_health_gate(
            Some(latest),
            &verifier,
            WorkerHealthPolicy::StrictHealthy,
            correct_hash,
            10,
            0, // min_health_seq: permissive for this test
        );
        assert!(
            matches!(result, Err(WorkerHealthGateError::HealthFailed { .. })),
            "gate must reject after error-path receipt invalidation, got {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // MINOR-1: Synthetic FAILED receipt history count
    // -----------------------------------------------------------------------

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn synthetic_failed_receipt_increments_history() {
        let signer = test_signer();
        let mut checker = BrokerHealthChecker::new();

        let eval_window = valid_eval_window();
        let oversized: Vec<Hash> = (0..=MAX_HEALTH_REQUIRED_AUTHORITY_SETS)
            .map(|i| {
                let mut h = [0u8; 32];
                h[0] = (i & 0xFF) as u8;
                h[1] = ((i >> 8) & 0xFF) as u8;
                h
            })
            .collect();

        let error_input = HealthCheckInput {
            envelope: None,
            eval_window: &eval_window,
            verifier: None,
            freshness_horizon: None,
            revocation_frontier: None,
            convergence_horizon: None,
            convergence_receipts: &[],
            required_authority_sets: &oversized,
        };

        // Before: empty history
        assert_eq!(checker.history_len(), 0);

        // Error triggers synthetic receipt
        let _ = checker.check_health(&error_input, 1, &signer);
        assert_eq!(
            checker.history_len(),
            1,
            "synthetic receipt must be in history"
        );

        // Verify it's a FAILED receipt with EVAL_ERROR
        let latest = checker.latest().unwrap();
        assert_eq!(latest.status, BrokerHealthStatus::Failed);
        assert_eq!(latest.checks[0].predicate_id, "EVAL_ERROR");
    }

    // -----------------------------------------------------------------------
    // INV-BH-013: health_seq monotonicity
    // -----------------------------------------------------------------------

    #[test]
    fn consecutive_health_checks_produce_incrementing_health_seq() {
        let signer = test_signer();
        let mut checker = BrokerHealthChecker::new();

        assert_eq!(
            checker.current_health_seq(),
            0,
            "initial health_seq must be 0"
        );

        let eval_window = valid_eval_window();
        let input = HealthCheckInput {
            envelope: None,
            eval_window: &eval_window,
            verifier: None,
            freshness_horizon: None,
            revocation_frontier: None,
            convergence_horizon: None,
            convergence_receipts: &[],
            required_authority_sets: &[],
        };

        let r1 = checker.check_health(&input, 42, &signer).unwrap();
        assert_eq!(r1.health_seq, 0, "first receipt health_seq must be 0");
        assert_eq!(
            checker.current_health_seq(),
            1,
            "after first check, next seq must be 1"
        );

        let r2 = checker.check_health(&input, 42, &signer).unwrap();
        assert_eq!(r2.health_seq, 1, "second receipt health_seq must be 1");
        assert_eq!(
            checker.current_health_seq(),
            2,
            "after second check, next seq must be 2"
        );

        // health_seq is strictly increasing even with same broker_tick
        assert!(r2.health_seq > r1.health_seq);

        // Content hashes differ due to health_seq difference
        assert_ne!(
            r1.content_hash, r2.content_hash,
            "same tick but different health_seq must produce different hashes"
        );
    }

    #[test]
    fn health_seq_included_in_content_hash() {
        // Verify that health_seq is bound into the content hash by
        // computing two hashes that differ only in health_seq.
        let eval_window = valid_eval_window();
        let eval_window_hash = compute_eval_window_hash(&eval_window);
        let checks: Vec<InvariantCheckResult> = vec![];

        let hash_seq_0 = compute_health_receipt_hash(
            42,
            0, // health_seq = 0
            eval_window_hash,
            BrokerHealthStatus::Healthy,
            &checks,
        );
        let hash_seq_1 = compute_health_receipt_hash(
            42,
            1, // health_seq = 1
            eval_window_hash,
            BrokerHealthStatus::Healthy,
            &checks,
        );

        assert_ne!(
            hash_seq_0, hash_seq_1,
            "different health_seq must produce different content hashes"
        );
    }

    // -----------------------------------------------------------------------
    // INV-BH-013: Same-tick replay attack prevention
    // -----------------------------------------------------------------------

    #[test]
    fn same_tick_replay_rejected_via_health_seq() {
        // Scenario: Broker is HEALTHY at tick T with health_seq=N, then
        // health degrades and a FAILED receipt is issued at the same tick T
        // with health_seq=N+1. A replay of the old HEALTHY receipt with
        // min_health_seq=N+1 MUST be denied.
        let signer = test_signer();
        let verifier = make_verifier(&signer);
        let mut checker = BrokerHealthChecker::new();

        let envelope = valid_envelope(&signer);
        let eval_window = valid_eval_window();
        let freshness = valid_freshness_horizon();
        let frontier = valid_revocation_frontier();
        let convergence = valid_convergence_horizon();

        // Step 1: Broker is HEALTHY at tick 100, health_seq=0
        let healthy_input = HealthCheckInput {
            envelope: Some(&envelope),
            eval_window: &eval_window,
            verifier: Some(&verifier),
            freshness_horizon: Some(&freshness),
            revocation_frontier: Some(&frontier),
            convergence_horizon: Some(&convergence),
            convergence_receipts: &[],
            required_authority_sets: &[],
        };
        let healthy_receipt = checker.check_health(&healthy_input, 100, &signer).unwrap();
        assert_eq!(healthy_receipt.status, BrokerHealthStatus::Healthy);
        assert_eq!(healthy_receipt.health_seq, 0);
        assert_eq!(healthy_receipt.broker_tick, 100);

        // Step 2: Broker degrades at SAME tick 100, health_seq=1
        let failed_input = HealthCheckInput {
            envelope: None,
            eval_window: &eval_window,
            verifier: None,
            freshness_horizon: Some(&freshness),
            revocation_frontier: Some(&frontier),
            convergence_horizon: Some(&convergence),
            convergence_receipts: &[],
            required_authority_sets: &[],
        };
        let failed_receipt = checker.check_health(&failed_input, 100, &signer).unwrap();
        assert_eq!(failed_receipt.status, BrokerHealthStatus::Failed);
        assert_eq!(failed_receipt.health_seq, 1);
        assert_eq!(failed_receipt.broker_tick, 100);

        let correct_hash = compute_eval_window_hash(&eval_window);

        // Step 3: Replay attack — present old HEALTHY receipt (health_seq=0)
        // with min_health_seq=1 (requiring the latest check)
        let result = evaluate_worker_health_gate(
            Some(&healthy_receipt),
            &verifier,
            WorkerHealthPolicy::StrictHealthy,
            correct_hash,
            100, // min_broker_tick: same tick, would pass tick check
            1,   // min_health_seq: requires seq >= 1, old receipt has 0
        );
        assert!(
            matches!(
                result,
                Err(WorkerHealthGateError::StaleHealthSeq {
                    receipt_seq: 0,
                    min_seq: 1,
                })
            ),
            "same-tick replay of old HEALTHY receipt must be rejected via health_seq, got {result:?}"
        );

        // Step 4: Current FAILED receipt passes health_seq check but is
        // rejected on status
        let result = evaluate_worker_health_gate(
            Some(&failed_receipt),
            &verifier,
            WorkerHealthPolicy::StrictHealthy,
            correct_hash,
            100,
            1, // min_health_seq: failed receipt has seq=1, passes
        );
        assert!(
            matches!(result, Err(WorkerHealthGateError::HealthFailed { .. })),
            "current FAILED receipt should pass seq check but fail on status, got {result:?}"
        );
    }

    #[test]
    fn min_health_seq_enforcement_rejects_stale_seq() {
        // Verify that min_health_seq enforcement works at exact boundaries.
        let signer = test_signer();
        let verifier = make_verifier(&signer);
        let mut checker = BrokerHealthChecker::new();

        let envelope = valid_envelope(&signer);
        let eval_window = valid_eval_window();
        let freshness = valid_freshness_horizon();
        let frontier = valid_revocation_frontier();
        let convergence = valid_convergence_horizon();

        let input = HealthCheckInput {
            envelope: Some(&envelope),
            eval_window: &eval_window,
            verifier: Some(&verifier),
            freshness_horizon: Some(&freshness),
            revocation_frontier: Some(&frontier),
            convergence_horizon: Some(&convergence),
            convergence_receipts: &[],
            required_authority_sets: &[],
        };

        // Generate 6 receipts (health_seq 0..5)
        let mut receipts = Vec::new();
        for _ in 0..6 {
            receipts.push(checker.check_health(&input, 50, &signer).unwrap());
        }
        assert_eq!(receipts[5].health_seq, 5);

        let correct_hash = compute_eval_window_hash(&eval_window);

        // health_seq=5 with min_health_seq=6 => denied
        let result = evaluate_worker_health_gate(
            Some(&receipts[5]),
            &verifier,
            WorkerHealthPolicy::StrictHealthy,
            correct_hash,
            50,
            6, // min_health_seq > receipt.health_seq
        );
        assert!(
            matches!(
                result,
                Err(WorkerHealthGateError::StaleHealthSeq {
                    receipt_seq: 5,
                    min_seq: 6,
                })
            ),
            "receipt with health_seq=5 must be rejected when min_health_seq=6, got {result:?}"
        );

        // health_seq=5 with min_health_seq=5 => accepted (>= semantics)
        let result = evaluate_worker_health_gate(
            Some(&receipts[5]),
            &verifier,
            WorkerHealthPolicy::StrictHealthy,
            correct_hash,
            50,
            5, // min_health_seq == receipt.health_seq
        );
        assert!(
            result.is_ok(),
            "receipt with health_seq=5 must pass when min_health_seq=5, got {result:?}"
        );

        // health_seq=5 with min_health_seq=4 => accepted
        let result = evaluate_worker_health_gate(
            Some(&receipts[5]),
            &verifier,
            WorkerHealthPolicy::StrictHealthy,
            correct_hash,
            50,
            4, // min_health_seq < receipt.health_seq
        );
        assert!(
            result.is_ok(),
            "receipt with health_seq=5 must pass when min_health_seq=4, got {result:?}"
        );
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn synthetic_failed_receipt_advances_health_seq() {
        // Verify that error-path synthetic receipts also advance health_seq.
        let signer = test_signer();
        let mut checker = BrokerHealthChecker::new();

        let eval_window = valid_eval_window();

        // First: normal check (health_seq=0)
        let input = HealthCheckInput {
            envelope: None,
            eval_window: &eval_window,
            verifier: None,
            freshness_horizon: None,
            revocation_frontier: None,
            convergence_horizon: None,
            convergence_receipts: &[],
            required_authority_sets: &[],
        };
        let r1 = checker.check_health(&input, 1, &signer).unwrap();
        assert_eq!(r1.health_seq, 0);

        // Second: error path (oversized input) — health_seq should be 1
        let oversized: Vec<Hash> = (0..=MAX_HEALTH_REQUIRED_AUTHORITY_SETS)
            .map(|i| {
                let mut h = [0u8; 32];
                h[0] = (i & 0xFF) as u8;
                h[1] = ((i >> 8) & 0xFF) as u8;
                h
            })
            .collect();

        let error_input = HealthCheckInput {
            envelope: None,
            eval_window: &eval_window,
            verifier: None,
            freshness_horizon: None,
            revocation_frontier: None,
            convergence_horizon: None,
            convergence_receipts: &[],
            required_authority_sets: &oversized,
        };
        let _ = checker.check_health(&error_input, 2, &signer);

        let synthetic = checker.latest().unwrap();
        assert_eq!(
            synthetic.health_seq, 1,
            "synthetic receipt must advance health_seq"
        );

        // Third: normal check after error — health_seq should be 2
        let r3 = checker.check_health(&input, 3, &signer).unwrap();
        assert_eq!(
            r3.health_seq, 2,
            "health_seq must continue advancing after synthetic receipt"
        );
    }

    #[test]
    fn health_receipt_verify_detects_tampered_health_seq() {
        let signer = test_signer();
        let verifier = make_verifier(&signer);
        let mut checker = BrokerHealthChecker::new();

        let eval_window = valid_eval_window();
        let input = HealthCheckInput {
            envelope: None,
            eval_window: &eval_window,
            verifier: None,
            freshness_horizon: None,
            revocation_frontier: None,
            convergence_horizon: None,
            convergence_receipts: &[],
            required_authority_sets: &[],
        };

        let mut receipt = checker.check_health(&input, 1, &signer).unwrap();

        // Tamper: change health_seq without re-signing
        receipt.health_seq = 9999;

        let result = receipt.verify(&verifier);
        assert!(
            matches!(result, Err(BrokerHealthError::ContentHashMismatch)),
            "expected ContentHashMismatch for tampered health_seq, got {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // MINOR-1 regression: health_seq overflow (checked_add fail-closed)
    // -----------------------------------------------------------------------

    #[test]
    fn health_seq_overflow_returns_error_and_persists_failed_receipt() {
        let signer = test_signer();
        let mut checker = BrokerHealthChecker::new();

        // Artificially set the sequence to u64::MAX - 1 so the next
        // successful check uses u64::MAX - 1 and advances to u64::MAX.
        // The check after that should overflow and fail.
        checker.health_seq = u64::MAX - 1;

        let eval_window = valid_eval_window();
        let input = HealthCheckInput {
            envelope: None,
            eval_window: &eval_window,
            verifier: None,
            freshness_horizon: None,
            revocation_frontier: None,
            convergence_horizon: None,
            convergence_receipts: &[],
            required_authority_sets: &[],
        };

        // First check at u64::MAX - 1 should succeed and advance to
        // u64::MAX.
        let r1 = checker.check_health(&input, 1, &signer).unwrap();
        assert_eq!(r1.health_seq, u64::MAX - 1);
        assert_eq!(checker.current_health_seq(), u64::MAX);

        // Second check at u64::MAX should succeed (uses u64::MAX) and try
        // to advance to u64::MAX + 1 — but checked_add(1) wraps, so it
        // should detect overflow and fail.
        // Wait — actually the seq u64::MAX is valid. checked_add(1) on
        // u64::MAX returns None. So this call should fail.
        let r2 = checker.check_health(&input, 2, &signer);
        assert!(
            matches!(r2, Err(BrokerHealthError::HealthSeqOverflow)),
            "expected HealthSeqOverflow, got {r2:?}"
        );

        // A synthetic FAILED receipt should have been persisted at
        // health_seq = u64::MAX (the saturated value).
        let latest = checker.latest().unwrap();
        assert_eq!(latest.status, BrokerHealthStatus::Failed);
        assert_eq!(latest.health_seq, u64::MAX);
        assert!(
            latest
                .checks
                .iter()
                .any(|c| c.predicate_id == "SEQ_OVERFLOW"),
            "expected SEQ_OVERFLOW check in synthetic receipt"
        );

        // Subsequent calls should also fail with overflow.
        let r3 = checker.check_health(&input, 3, &signer);
        assert!(
            matches!(r3, Err(BrokerHealthError::HealthSeqOverflow)),
            "expected repeated HealthSeqOverflow, got {r3:?}"
        );
    }

    #[test]
    fn health_seq_overflow_synthetic_receipt_also_saturates() {
        let signer = test_signer();
        let mut checker = BrokerHealthChecker::new();

        // Set sequence to u64::MAX - 1 so that the next
        // persist_synthetic_failed_receipt uses u64::MAX - 1 and saturates
        // to u64::MAX.
        checker.health_seq = u64::MAX - 1;

        let eval_window = valid_eval_window();

        // Trigger an error path that calls persist_synthetic_failed_receipt.
        #[allow(clippy::cast_possible_truncation)]
        let oversized: Vec<Hash> = (0..=MAX_HEALTH_REQUIRED_AUTHORITY_SETS)
            .map(|i| {
                let mut h = [0u8; 32];
                h[0] = (i & 0xFF) as u8;
                h[1] = ((i >> 8) & 0xFF) as u8;
                h
            })
            .collect();

        let error_input = HealthCheckInput {
            envelope: None,
            eval_window: &eval_window,
            verifier: None,
            freshness_horizon: None,
            revocation_frontier: None,
            convergence_horizon: None,
            convergence_receipts: &[],
            required_authority_sets: &oversized,
        };

        // This should persist a synthetic FAILED receipt at
        // health_seq = u64::MAX - 1 and saturate to u64::MAX.
        let _ = checker.check_health(&error_input, 1, &signer);

        let synthetic = checker.latest().unwrap();
        assert_eq!(synthetic.health_seq, u64::MAX - 1);
        assert_eq!(
            checker.current_health_seq(),
            u64::MAX,
            "saturating_add should cap at u64::MAX, not wrap to 0"
        );

        // One more synthetic receipt at u64::MAX — saturating_add(1)
        // should still be u64::MAX (no wrap).
        let _ = checker.check_health(&error_input, 2, &signer);
        let synthetic2 = checker.latest().unwrap();
        assert_eq!(synthetic2.health_seq, u64::MAX);
        assert_eq!(
            checker.current_health_seq(),
            u64::MAX,
            "must stay saturated at u64::MAX, not wrap"
        );
    }

    // -----------------------------------------------------------------------
    // MAJOR-1: Production admission gate integration test
    // -----------------------------------------------------------------------

    #[test]
    fn broker_admission_gate_denies_when_health_failed() {
        use crate::fac::FacBroker;

        let mut broker = FacBroker::new();
        let mut checker = BrokerHealthChecker::new();

        // Build an evaluation window from the broker.
        let eval_window = broker
            .build_evaluation_window("test-boundary", "test-clock", 0, 100)
            .unwrap();

        // Run a health check — with no envelope and no freshness/convergence
        // data, TP001/TP002/TP003 will fail, resulting in FAILED status.
        let receipt = broker
            .check_health(None, &eval_window, &[], &mut checker)
            .unwrap();
        assert_eq!(receipt.status, BrokerHealthStatus::Failed);

        // INV-BRK-HEALTH-GATE-001: After a FAILED check_health, the
        // admission_health_gate_passed flag must be false.
        assert!(
            !broker.is_admission_health_gate_passed(),
            "health gate must be closed after FAILED check"
        );

        // Now use the production admission gate — it should DENY.
        // MINOR-4: The broker now uses its own current_tick() and
        // state.health_seq as floors, so no caller-supplied values.
        let result = broker.evaluate_admission_health_gate(
            &checker,
            &eval_window,
            WorkerHealthPolicy::StrictHealthy,
        );
        assert!(
            result.is_err(),
            "admission gate must deny when broker health is FAILED"
        );
        assert!(
            matches!(result, Err(WorkerHealthGateError::HealthFailed { .. })),
            "expected HealthFailed error, got {result:?}"
        );
    }

    #[test]
    fn broker_admission_gate_denies_when_no_receipt() {
        use crate::fac::FacBroker;

        let mut broker = FacBroker::new();
        let checker = BrokerHealthChecker::new();
        let eval_window = broker
            .build_evaluation_window("test-boundary", "test-clock", 0, 100)
            .unwrap();

        // No health check has been run — gate should deny (fail-closed).
        let result = broker.evaluate_admission_health_gate(
            &checker,
            &eval_window,
            WorkerHealthPolicy::StrictHealthy,
        );
        assert!(
            result.is_err(),
            "admission gate must deny when no health receipt exists"
        );
        assert!(
            matches!(result, Err(WorkerHealthGateError::NoHealthReceipt)),
            "expected NoHealthReceipt error, got {result:?}"
        );
    }

    #[test]
    fn broker_admission_gate_denies_stale_receipt() {
        use crate::fac::FacBroker;

        let mut broker = FacBroker::new();
        let mut checker = BrokerHealthChecker::new();

        let eval_window = broker
            .build_evaluation_window("test-boundary", "test-clock", 0, 100)
            .unwrap();

        // Run health check at current broker tick (1).
        let _ = broker
            .check_health(None, &eval_window, &[], &mut checker)
            .unwrap();

        // Advance the broker tick well past the receipt's tick so that
        // the broker's current_tick() floor rejects the old receipt.
        // MINOR-4: The broker now uses self.current_tick() as the
        // min_broker_tick floor internally, so advancing the tick
        // makes the old receipt stale.
        for _ in 0..99 {
            let _ = broker.advance_tick();
        }

        let result = broker.evaluate_admission_health_gate(
            &checker,
            &eval_window,
            WorkerHealthPolicy::StrictHealthy,
        );
        assert!(
            matches!(result, Err(WorkerHealthGateError::StaleReceipt { .. })),
            "expected StaleReceipt error, got {result:?}"
        );
    }
}
