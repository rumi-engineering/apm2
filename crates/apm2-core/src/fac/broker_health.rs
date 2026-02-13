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
pub const MAX_SCHEMA_ID_LENGTH: usize = 256;

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
/// Per SEC-CTRL-FAC-0016, all string fields deserialized from untrusted input
/// must enforce length limits during parsing to prevent denial-of-service via
/// memory exhaustion.
fn deserialize_bounded_string<'de, D>(
    deserializer: D,
    max_len: usize,
    field_name: &'static str,
) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    if s.len() > max_len {
        return Err(de::Error::custom(format!(
            "string field '{}' exceeds maximum length ({} > {})",
            field_name,
            s.len(),
            max_len
        )));
    }
    Ok(s)
}

/// Deserialize an optional string with a maximum length bound.
fn deserialize_bounded_option_string<'de, D>(
    deserializer: D,
    max_len: usize,
    field_name: &'static str,
) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt: Option<String> = Option::deserialize(deserializer)?;
    if let Some(ref s) = opt {
        if s.len() > max_len {
            return Err(de::Error::custom(format!(
                "string field '{}' exceeds maximum length ({} > {})",
                field_name,
                s.len(),
                max_len
            )));
        }
    }
    Ok(opt)
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
///    broker_tick, eval_window_hash, status, checks)`.
/// 3. Constant-time compares the recomputed hash with the stored
///    `content_hash`.
/// 4. Verifies the Ed25519 signature over `content_hash`.
///
/// This ensures an attacker cannot tamper with payload fields (e.g., changing
/// `status` from `FAILED` to `HEALTHY`) while keeping the original signature.
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
pub struct BrokerHealthChecker {
    /// Recent health check history (bounded ring buffer).
    history: Vec<HealthReceiptV1>,
}

impl Default for BrokerHealthChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl BrokerHealthChecker {
    /// Creates a new health checker with empty history.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            history: Vec::new(),
        }
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
        if input.required_authority_sets.len() > MAX_HEALTH_REQUIRED_AUTHORITY_SETS {
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

        // Compute content hash (domain-separated, includes schema + eval_window)
        let content_hash =
            compute_health_receipt_hash(broker_tick, eval_window_hash, status, &checks);

        // Sign the content hash
        let signature_bytes = signer.sign(&content_hash);
        let signer_id = signer.verifying_key().to_bytes();

        let receipt = HealthReceiptV1 {
            schema_id: HEALTH_RECEIPT_SCHEMA_ID.to_string(),
            schema_version: HEALTH_RECEIPT_SCHEMA_VERSION.to_string(),
            status,
            broker_tick,
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

/// Evaluates the worker admission health gate.
///
/// The gate checks:
/// 1. A health receipt exists (fail-closed if missing).
/// 2. The receipt payload integrity (content hash recomputed and compared).
/// 3. The receipt signature is valid.
/// 4. The health status meets the configured policy.
///
/// # Errors
///
/// Returns a [`WorkerHealthGateError`] if the gate rejects the job.
pub fn evaluate_worker_health_gate(
    receipt: Option<&HealthReceiptV1>,
    verifier: &BrokerSignatureVerifier,
    policy: WorkerHealthPolicy,
) -> Result<(), WorkerHealthGateError> {
    let receipt = receipt.ok_or(WorkerHealthGateError::NoHealthReceipt)?;

    // Verify receipt: schema + content hash recompute + signature
    // (INV-BRK-HEALTH-005)
    receipt.verify(verifier)?;

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
/// - Evaluation window hash (boundary context binding)
/// - Status byte
/// - All check results (`predicate_id`, `passed`, `deny_reason`)
///
/// # INV-BRK-HEALTH-007
///
/// Length prefixes use `u64::to_le_bytes()` for injective framing.
fn compute_health_receipt_hash(
    broker_tick: u64,
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
fn compute_eval_window_hash(eval_window: &HtfEvaluationWindow) -> Hash {
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

        let result =
            evaluate_worker_health_gate(Some(&receipt), &verifier, WorkerHealthPolicy::default());
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // Worker health gate: no receipt (fail-closed)
    // -----------------------------------------------------------------------

    #[test]
    fn worker_gate_rejects_when_no_receipt() {
        let signer = test_signer();
        let verifier = make_verifier(&signer);

        let result =
            evaluate_worker_health_gate(None, &verifier, WorkerHealthPolicy::StrictHealthy);
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

        let result = evaluate_worker_health_gate(
            Some(&receipt),
            &verifier,
            WorkerHealthPolicy::StrictHealthy,
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

        // Verify with a different key => must reject
        let result = evaluate_worker_health_gate(
            Some(&receipt),
            &other_verifier,
            WorkerHealthPolicy::StrictHealthy,
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
        );
        assert!(result.is_ok());

        // StrictHealthy should reject
        let result = evaluate_worker_health_gate(
            Some(&receipt),
            &verifier,
            WorkerHealthPolicy::StrictHealthy,
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
}
