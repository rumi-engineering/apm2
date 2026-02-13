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

use serde::{Deserialize, Serialize};

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

/// Domain separator for health receipt content hashing.
const HEALTH_RECEIPT_HASH_DOMAIN: &[u8] = b"apm2.fac_broker.health_receipt.v1";

/// Schema identifier for health receipts.
pub const HEALTH_RECEIPT_SCHEMA_ID: &str = "apm2.fac_broker_health_receipt.v1";

/// Schema version for health receipts.
pub const HEALTH_RECEIPT_SCHEMA_VERSION: &str = "1.0.0";

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
    /// At least one invariant has a non-blocking warning but all critical
    /// checks passed. Workers MAY admit jobs under policy-configured
    /// degraded-mode tolerance.
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
// Individual invariant check result
// ---------------------------------------------------------------------------

/// Result of a single TP invariant check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvariantCheckResult {
    /// Predicate identifier (e.g., "TP001", "TP002", "TP003").
    pub predicate_id: String,
    /// Whether the check passed.
    pub passed: bool,
    /// Human-readable reason code when the check fails.
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthReceiptV1 {
    /// Schema identifier for version checking.
    pub schema_id: String,
    /// Schema version.
    pub schema_version: String,
    /// Overall health status (fail-closed aggregate).
    pub status: BrokerHealthStatus,
    /// Broker tick at the time of the health check.
    pub broker_tick: u64,
    /// Individual invariant check results.
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
    /// Returns `true` if the signature is valid, `false` otherwise.
    #[must_use]
    pub fn verify(&self, verifier: &BrokerSignatureVerifier) -> bool {
        verifier.verify_broker_signature(&self.content_hash, &self.signer_id, &self.signature)
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
    pub fn check_health(
        &mut self,
        input: &HealthCheckInput<'_>,
        broker_tick: u64,
        signer: &Signer,
    ) -> HealthReceiptV1 {
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

        // Compute content hash (domain-separated)
        let content_hash = compute_health_receipt_hash(broker_tick, status, &checks);

        // Sign the content hash
        let signature_bytes = signer.sign(&content_hash);
        let signer_id = signer.verifying_key().to_bytes();

        let receipt = HealthReceiptV1 {
            schema_id: HEALTH_RECEIPT_SCHEMA_ID.to_string(),
            schema_version: HEALTH_RECEIPT_SCHEMA_VERSION.to_string(),
            status,
            broker_tick,
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

        receipt
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

    /// Health receipt signature verification failed.
    #[error("health receipt signature invalid")]
    InvalidSignature,
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
/// 2. The receipt signature is valid.
/// 3. The health status meets the configured policy.
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

    // Verify receipt signature (authenticity gate)
    if !receipt.verify(verifier) {
        return Err(WorkerHealthGateError::InvalidSignature);
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

fn compute_health_receipt_hash(
    broker_tick: u64,
    status: BrokerHealthStatus,
    checks: &[InvariantCheckResult],
) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(HEALTH_RECEIPT_HASH_DOMAIN);
    hasher.update(&broker_tick.to_le_bytes());

    // Encode status as a single byte
    let status_byte = match status {
        BrokerHealthStatus::Healthy => 0u8,
        BrokerHealthStatus::Degraded => 1u8,
        BrokerHealthStatus::Failed => 2u8,
    };
    hasher.update(&[status_byte]);

    // Encode check results (bounded by MAX_HEALTH_FINDINGS)
    let check_count = checks.len().min(MAX_HEALTH_FINDINGS);
    #[allow(clippy::cast_possible_truncation)]
    let count_u8 = check_count as u8;
    hasher.update(&[count_u8]);
    for check in checks.iter().take(MAX_HEALTH_FINDINGS) {
        // Length-prefix the predicate_id for framing
        #[allow(clippy::cast_possible_truncation)]
        let pid_len = check.predicate_id.len().min(255) as u8;
        hasher.update(&[pid_len]);
        hasher.update(check.predicate_id.as_bytes());
        hasher.update(&[u8::from(check.passed)]);
        if let Some(ref reason) = check.deny_reason {
            hasher.update(&[1u8]); // present marker
            #[allow(clippy::cast_possible_truncation)]
            let reason_len = reason.len().min(u16::MAX as usize) as u16;
            hasher.update(&reason_len.to_le_bytes());
            hasher.update(reason.as_bytes());
        } else {
            hasher.update(&[0u8]); // absent marker
        }
    }

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

        let receipt = checker.check_health(&input, 42, &signer);

        assert_eq!(receipt.status, BrokerHealthStatus::Healthy);
        assert_eq!(receipt.broker_tick, 42);
        assert_eq!(receipt.checks.len(), 3);
        assert!(receipt.checks.iter().all(|c| c.passed));
        assert_ne!(receipt.content_hash, [0u8; 32]);
        assert_ne!(receipt.signature, [0u8; 64]);
        assert!(receipt.verify(&verifier));
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

        let receipt = checker.check_health(&input, 10, &signer);

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

        let receipt = checker.check_health(&input, 10, &signer);

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

        let receipt = checker.check_health(&input, 10, &signer);

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

        let receipt = checker.check_health(&input, 10, &signer);

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

        let receipt = checker.check_health(&input, 1, &signer);
        assert!(receipt.verify(&verifier));
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

        let receipt = checker.check_health(&input, 1, &signer);
        assert!(!receipt.verify(&other_verifier));
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

        let receipt = checker.check_health(&input, 42, &signer);
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

        let receipt = checker.check_health(&input, 1, &signer);
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

        let receipt = checker.check_health(&input, 42, &signer);

        // Verify with a different key => must reject
        let result = evaluate_worker_health_gate(
            Some(&receipt),
            &other_verifier,
            WorkerHealthPolicy::StrictHealthy,
        );
        assert!(matches!(
            result,
            Err(WorkerHealthGateError::InvalidSignature)
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

        let content_hash = compute_health_receipt_hash(42, BrokerHealthStatus::Degraded, &checks);
        let signature_bytes = signer.sign(&content_hash);

        let receipt = HealthReceiptV1 {
            schema_id: HEALTH_RECEIPT_SCHEMA_ID.to_string(),
            schema_version: HEALTH_RECEIPT_SCHEMA_VERSION.to_string(),
            status: BrokerHealthStatus::Degraded,
            broker_tick: 42,
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

        let r1 = checker1.check_health(&input, 42, &signer);
        let r2 = checker2.check_health(&input, 42, &signer);

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

        let r1 = checker.check_health(&input, 1, &signer);
        let r2 = checker.check_health(&input, 2, &signer);

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
}
