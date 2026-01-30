//! Gate run completion types for the Forge Admission Cycle.
//!
//! This module defines [`GateRunCompleted`] which represents a
//! cryptographically signed attestation that a gate run has completed under a
//! valid [`GateLease`].
//!
//! # Security Model
//!
//! `GateRunCompleted` is the critical event for FAC admission decisions. All
//! validation steps in [`GateRunCompleted::verify_for_admission`] must pass
//! for admission to proceed:
//!
//! 1. **Signature verification**: The executor's signature over the canonical
//!    bytes with `GATE_RUN_COMPLETED:` domain prefix
//! 2. **Lease ID binding**: The run must reference the correct lease
//! 3. **Changeset binding**: The changeset digest must match the lease
//! 4. **Executor binding**: The executor must match the lease
//! 5. **Revocation check**: The lease must not be revoked
//! 6. **Expiry check**: The completion must be within the lease's time window
//!
//! # Example
//!
//! ```rust
//! use apm2_core::crypto::Signer;
//! use apm2_core::fac::{
//!     GateLease, GateLeaseBuilder, GateRunCompleted, GateRunCompletedBuilder,
//! };
//!
//! // Create an issuer and executor
//! let issuer = Signer::generate();
//! let executor = Signer::generate();
//!
//! // Issue a gate lease
//! let lease = GateLeaseBuilder::new("lease-001", "work-001", "gate-build")
//!     .changeset_digest([0x42; 32])
//!     .executor_actor_id("executor-001")
//!     .issued_at(1704067200000)
//!     .expires_at(1704070800000)
//!     .policy_hash([0xab; 32])
//!     .issuer_actor_id("issuer-001")
//!     .time_envelope_ref("htf:tick:12345")
//!     .build_and_sign(&issuer);
//!
//! // Complete a gate run
//! let run = GateRunCompletedBuilder::new("run-001", "gate-build", "work-001")
//!     .lease_id("lease-001")
//!     .changeset_digest([0x42; 32])
//!     .executor_actor_id("executor-001")
//!     .result("PASS")
//!     .completed_at(1704068000000)
//!     .build_and_sign(&executor);
//!
//! // Verify for admission (no revocation check function for this example)
//! let result = run.verify_for_admission(
//!     &lease,
//!     &executor.verifying_key(),
//!     |_| false, // is_revoked
//! );
//! assert!(result.is_ok());
//! ```

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::domain_separator::{GATE_RUN_COMPLETED_PREFIX, sign_with_domain, verify_with_domain};
use super::lease::GateLease;
use crate::crypto::{Signature, VerifyingKey};
use crate::events::Canonicalize;

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during gate run validation.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum GateRunError {
    /// The executor signature is invalid.
    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    /// The lease ID does not match.
    #[error("lease ID mismatch: expected {expected}, got {actual}")]
    LeaseIdMismatch {
        /// Expected lease ID from the run.
        expected: String,
        /// Actual lease ID from the lease.
        actual: String,
    },

    /// The changeset digest does not match.
    #[error("changeset digest mismatch")]
    ChangesetMismatch,

    /// The executor does not match the lease.
    #[error("executor mismatch: expected {expected}, got {actual}")]
    ExecutorMismatch {
        /// Expected executor from the lease.
        expected: String,
        /// Actual executor from the run.
        actual: String,
    },

    /// The lease has been revoked.
    #[error("lease {lease_id} has been revoked")]
    LeaseRevoked {
        /// The revoked lease ID.
        lease_id: String,
    },

    /// The completion time is outside the lease validity window.
    #[error("lease expired: completion at {completed_at} is after lease expiry at {expires_at}")]
    LeaseExpired {
        /// When the run completed.
        completed_at: u64,
        /// When the lease expired.
        expires_at: u64,
    },

    /// The completion time is before the lease was issued.
    #[error("completion time {completed_at} is before lease was issued at {issued_at}")]
    CompletionBeforeIssued {
        /// When the run completed.
        completed_at: u64,
        /// When the lease was issued.
        issued_at: u64,
    },

    /// Missing required field.
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// Invalid run data.
    #[error("invalid run data: {0}")]
    InvalidData(String),
}

// =============================================================================
// Gate Run Result
// =============================================================================

/// The result of a gate run execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GateRunResult {
    /// The gate run passed all checks.
    Pass,
    /// The gate run failed one or more checks.
    Fail,
}

impl GateRunResult {
    /// Returns the string representation of the result.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
        }
    }

    /// Parses a result from a string.
    ///
    /// # Errors
    ///
    /// Returns an error if the string is not a valid result.
    pub fn parse(s: &str) -> Result<Self, GateRunError> {
        match s {
            "PASS" => Ok(Self::Pass),
            "FAIL" => Ok(Self::Fail),
            other => Err(GateRunError::InvalidData(format!(
                "invalid result: {other}, expected PASS or FAIL"
            ))),
        }
    }
}

impl std::fmt::Display for GateRunResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// =============================================================================
// Gate Run Completed
// =============================================================================

/// A signed attestation that a gate run has completed.
///
/// This is the critical event for FAC admission decisions. The executor signs
/// this event with their Ed25519 key using the `GATE_RUN_COMPLETED:` domain
/// prefix.
///
/// # Fields
///
/// All 10 required fields as specified in the ticket:
/// - `run_id`: Unique identifier for this completion event
/// - `gate_id`: Gate this run completed for
/// - `work_id`: Work item this run is associated with
/// - `lease_id`: Lease ID authorizing this run
/// - `changeset_digest`: Hash of the changeset executed
/// - `executor_actor_id`: Actor who executed the run
/// - `result`: Outcome of the run (PASS or FAIL)
/// - `evidence_ids`: Evidence IDs produced by this run
/// - `completed_at`: HTF timestamp when the run completed
/// - `executor_signature`: Ed25519 signature with domain separation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateRunCompleted {
    /// Unique identifier for this completion event.
    pub run_id: String,

    /// Gate this run completed for.
    pub gate_id: String,

    /// Work item this run is associated with.
    pub work_id: String,

    /// Lease ID authorizing this run.
    pub lease_id: String,

    /// Hash of the changeset executed.
    #[serde(with = "serde_bytes")]
    pub changeset_digest: [u8; 32],

    /// Actor who executed the run.
    pub executor_actor_id: String,

    /// Outcome of the run.
    pub result: GateRunResult,

    /// Evidence IDs produced by this run.
    pub evidence_ids: Vec<String>,

    /// HTF timestamp when the run completed (Unix millis).
    pub completed_at: u64,

    /// Ed25519 signature over canonical bytes with domain separation.
    #[serde(with = "serde_bytes")]
    pub executor_signature: [u8; 64],
}

impl GateRunCompleted {
    /// Returns the canonical bytes for signing/verification.
    ///
    /// The canonical representation includes all fields except the signature,
    /// encoded in a deterministic order.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let capacity = 32 // run_id estimate
            + 32 // gate_id estimate
            + 32 // work_id estimate
            + 32 // lease_id estimate
            + 32 // changeset_digest
            + 32 // executor_actor_id estimate
            + 8  // result
            + 64 // evidence_ids estimate
            + 8; // completed_at

        let mut bytes = Vec::with_capacity(capacity);

        // Field order is deterministic and matches proto field order
        // 1. run_id
        bytes.extend_from_slice(self.run_id.as_bytes());
        bytes.push(0); // null separator

        // 2. gate_id
        bytes.extend_from_slice(self.gate_id.as_bytes());
        bytes.push(0);

        // 3. work_id
        bytes.extend_from_slice(self.work_id.as_bytes());
        bytes.push(0);

        // 4. lease_id
        bytes.extend_from_slice(self.lease_id.as_bytes());
        bytes.push(0);

        // 5. changeset_digest
        bytes.extend_from_slice(&self.changeset_digest);

        // 6. executor_actor_id
        bytes.extend_from_slice(self.executor_actor_id.as_bytes());
        bytes.push(0);

        // 7. result
        bytes.extend_from_slice(self.result.as_str().as_bytes());
        bytes.push(0);

        // 8. evidence_ids (sorted for determinism)
        let mut sorted_ids = self.evidence_ids.clone();
        sorted_ids.sort();
        for id in &sorted_ids {
            bytes.extend_from_slice(id.as_bytes());
            bytes.push(0);
        }
        bytes.push(0xFF); // section separator

        // 9. completed_at (big-endian for consistent ordering)
        bytes.extend_from_slice(&self.completed_at.to_be_bytes());

        bytes
    }

    /// Validates the executor signature using domain separation.
    ///
    /// # Arguments
    ///
    /// * `verifying_key` - The public key of the expected executor
    ///
    /// # Returns
    ///
    /// `Ok(())` if the signature is valid,
    /// `Err(GateRunError::InvalidSignature)` otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`GateRunError::InvalidSignature`] if the signature verification
    /// fails.
    pub fn validate_signature(&self, verifying_key: &VerifyingKey) -> Result<(), GateRunError> {
        let signature = Signature::from_bytes(&self.executor_signature);
        let canonical = self.canonical_bytes();

        verify_with_domain(
            verifying_key,
            GATE_RUN_COMPLETED_PREFIX,
            &canonical,
            &signature,
        )
        .map_err(|e| GateRunError::InvalidSignature(e.to_string()))
    }

    /// Verifies this gate run completion for admission.
    ///
    /// This is the critical validation function for FAC admission. All 6
    /// validation steps must pass:
    ///
    /// 1. Verify signature with domain separator
    /// 2. Check `lease_id` matches
    /// 3. Check `changeset_digest` matches lease
    /// 4. Check executor matches lease
    /// 5. Check lease not revoked
    /// 6. Check completion within lease expiry (HTF-based)
    ///
    /// # Arguments
    ///
    /// * `lease` - The gate lease that authorized this run
    /// * `executor_key` - The public key of the executor
    /// * `is_revoked` - A function that checks if a lease ID is revoked
    ///
    /// # Returns
    ///
    /// `Ok(())` if all validation steps pass.
    ///
    /// # Errors
    ///
    /// Returns the appropriate [`GateRunError`] if any validation step fails:
    /// - [`GateRunError::InvalidSignature`] if signature verification fails
    /// - [`GateRunError::LeaseIdMismatch`] if lease IDs don't match
    /// - [`GateRunError::ChangesetMismatch`] if changeset digests don't match
    /// - [`GateRunError::ExecutorMismatch`] if executors don't match
    /// - [`GateRunError::LeaseRevoked`] if the lease is revoked
    /// - [`GateRunError::LeaseExpired`] if completion is after lease expiry
    /// - [`GateRunError::CompletionBeforeIssued`] if completion is before lease
    ///   was issued
    pub fn verify_for_admission<F>(
        &self,
        lease: &GateLease,
        executor_key: &VerifyingKey,
        is_revoked: F,
    ) -> Result<(), GateRunError>
    where
        F: FnOnce(&str) -> bool,
    {
        // Step 1: Verify signature with domain separator
        self.validate_signature(executor_key)?;

        // Step 2: Check lease_id matches
        if self.lease_id != lease.lease_id {
            return Err(GateRunError::LeaseIdMismatch {
                expected: self.lease_id.clone(),
                actual: lease.lease_id.clone(),
            });
        }

        // Step 3: Check changeset_digest matches lease
        if self.changeset_digest != lease.changeset_digest {
            return Err(GateRunError::ChangesetMismatch);
        }

        // Step 4: Check executor matches lease
        if self.executor_actor_id != lease.executor_actor_id {
            return Err(GateRunError::ExecutorMismatch {
                expected: lease.executor_actor_id.clone(),
                actual: self.executor_actor_id.clone(),
            });
        }

        // Step 5: Check lease not revoked
        if is_revoked(&self.lease_id) {
            return Err(GateRunError::LeaseRevoked {
                lease_id: self.lease_id.clone(),
            });
        }

        // Step 6: Check completion within lease expiry (HTF-based)
        // The completion must be after the lease was issued
        if self.completed_at < lease.issued_at {
            return Err(GateRunError::CompletionBeforeIssued {
                completed_at: self.completed_at,
                issued_at: lease.issued_at,
            });
        }

        // The completion must be before or at the lease expiry
        if self.completed_at > lease.expires_at {
            return Err(GateRunError::LeaseExpired {
                completed_at: self.completed_at,
                expires_at: lease.expires_at,
            });
        }

        Ok(())
    }
}

impl Canonicalize for GateRunCompleted {
    fn canonicalize(&mut self) {
        self.evidence_ids.sort();
    }
}

// =============================================================================
// Gate Run Completed Builder
// =============================================================================

/// Builder for constructing [`GateRunCompleted`] instances.
#[derive(Debug, Default)]
pub struct GateRunCompletedBuilder {
    run_id: String,
    gate_id: String,
    work_id: String,
    lease_id: Option<String>,
    changeset_digest: Option<[u8; 32]>,
    executor_actor_id: Option<String>,
    result: Option<GateRunResult>,
    evidence_ids: Vec<String>,
    completed_at: Option<u64>,
}

impl GateRunCompletedBuilder {
    /// Creates a new builder with required identifiers.
    #[must_use]
    pub fn new(
        run_id: impl Into<String>,
        gate_id: impl Into<String>,
        work_id: impl Into<String>,
    ) -> Self {
        Self {
            run_id: run_id.into(),
            gate_id: gate_id.into(),
            work_id: work_id.into(),
            ..Default::default()
        }
    }

    /// Sets the lease ID.
    #[must_use]
    pub fn lease_id(mut self, lease_id: impl Into<String>) -> Self {
        self.lease_id = Some(lease_id.into());
        self
    }

    /// Sets the changeset digest.
    #[must_use]
    pub const fn changeset_digest(mut self, digest: [u8; 32]) -> Self {
        self.changeset_digest = Some(digest);
        self
    }

    /// Sets the executor actor ID.
    #[must_use]
    pub fn executor_actor_id(mut self, actor_id: impl Into<String>) -> Self {
        self.executor_actor_id = Some(actor_id.into());
        self
    }

    /// Sets the result.
    #[must_use]
    pub const fn result_enum(mut self, result: GateRunResult) -> Self {
        self.result = Some(result);
        self
    }

    /// Sets the result from a string.
    ///
    /// # Panics
    ///
    /// Panics if the string is not "PASS" or "FAIL".
    #[must_use]
    pub fn result(mut self, result: &str) -> Self {
        self.result = Some(GateRunResult::parse(result).expect("invalid result"));
        self
    }

    /// Adds evidence IDs.
    #[must_use]
    pub fn evidence_ids(mut self, ids: Vec<String>) -> Self {
        self.evidence_ids = ids;
        self
    }

    /// Adds a single evidence ID.
    #[must_use]
    pub fn add_evidence_id(mut self, id: impl Into<String>) -> Self {
        self.evidence_ids.push(id.into());
        self
    }

    /// Sets the completion timestamp.
    #[must_use]
    pub const fn completed_at(mut self, timestamp_ms: u64) -> Self {
        self.completed_at = Some(timestamp_ms);
        self
    }

    /// Builds the run completion and signs it with the provided signer.
    ///
    /// # Panics
    ///
    /// Panics if required fields are missing. Use `try_build_and_sign` for
    /// fallible construction.
    #[must_use]
    pub fn build_and_sign(self, signer: &crate::crypto::Signer) -> GateRunCompleted {
        self.try_build_and_sign(signer)
            .expect("missing required field")
    }

    /// Attempts to build and sign the run completion.
    ///
    /// # Errors
    ///
    /// Returns [`GateRunError::MissingField`] if any required field is not set.
    pub fn try_build_and_sign(
        self,
        signer: &crate::crypto::Signer,
    ) -> Result<GateRunCompleted, GateRunError> {
        let lease_id = self
            .lease_id
            .ok_or(GateRunError::MissingField("lease_id"))?;
        let changeset_digest = self
            .changeset_digest
            .ok_or(GateRunError::MissingField("changeset_digest"))?;
        let executor_actor_id = self
            .executor_actor_id
            .ok_or(GateRunError::MissingField("executor_actor_id"))?;
        let result = self.result.ok_or(GateRunError::MissingField("result"))?;
        let completed_at = self
            .completed_at
            .ok_or(GateRunError::MissingField("completed_at"))?;

        // Create run with placeholder signature
        let mut run = GateRunCompleted {
            run_id: self.run_id,
            gate_id: self.gate_id,
            work_id: self.work_id,
            lease_id,
            changeset_digest,
            executor_actor_id,
            result,
            evidence_ids: self.evidence_ids,
            completed_at,
            executor_signature: [0u8; 64],
        };

        // Canonicalize before signing
        run.canonicalize();

        // Sign the canonical bytes
        let canonical = run.canonical_bytes();
        let signature = sign_with_domain(signer, GATE_RUN_COMPLETED_PREFIX, &canonical);
        run.executor_signature = signature.to_bytes();

        Ok(run)
    }
}

// =============================================================================
// Proto Message Conversion
// =============================================================================

/// Type alias for the proto-generated `GateRunCompleted` message.
pub type GateRunCompletedProto = crate::events::GateRunCompleted;

impl TryFrom<GateRunCompletedProto> for GateRunCompleted {
    type Error = GateRunError;

    fn try_from(proto: GateRunCompletedProto) -> Result<Self, Self::Error> {
        let changeset_digest: [u8; 32] = proto.changeset_digest.try_into().map_err(|_| {
            GateRunError::InvalidData("changeset_digest must be 32 bytes".to_string())
        })?;

        let executor_signature: [u8; 64] = proto.executor_signature.try_into().map_err(|_| {
            GateRunError::InvalidData("executor_signature must be 64 bytes".to_string())
        })?;

        let result = GateRunResult::parse(&proto.result)?;

        Ok(Self {
            run_id: proto.run_id,
            gate_id: proto.gate_id,
            work_id: proto.work_id,
            lease_id: proto.lease_id,
            changeset_digest,
            executor_actor_id: proto.executor_actor_id,
            result,
            evidence_ids: proto.evidence_ids,
            completed_at: proto.completed_at,
            executor_signature,
        })
    }
}

impl From<GateRunCompleted> for GateRunCompletedProto {
    fn from(run: GateRunCompleted) -> Self {
        Self {
            run_id: run.run_id,
            gate_id: run.gate_id,
            work_id: run.work_id,
            lease_id: run.lease_id,
            changeset_digest: run.changeset_digest.to_vec(),
            executor_actor_id: run.executor_actor_id,
            result: run.result.as_str().to_string(),
            evidence_ids: run.evidence_ids,
            completed_at: run.completed_at,
            executor_signature: run.executor_signature.to_vec(),
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::crypto::Signer;
    use crate::fac::GateLeaseBuilder;

    fn create_test_lease(issuer: &Signer, executor_id: &str) -> GateLease {
        GateLeaseBuilder::new("lease-001", "work-001", "gate-build")
            .changeset_digest([0x42; 32])
            .executor_actor_id(executor_id)
            .issued_at(1_704_067_200_000)
            .expires_at(1_704_070_800_000)
            .policy_hash([0xab; 32])
            .issuer_actor_id("issuer-001")
            .time_envelope_ref("htf:tick:12345")
            .build_and_sign(issuer)
    }

    fn create_test_run(executor: &Signer, executor_id: &str) -> GateRunCompleted {
        GateRunCompletedBuilder::new("run-001", "gate-build", "work-001")
            .lease_id("lease-001")
            .changeset_digest([0x42; 32])
            .executor_actor_id(executor_id)
            .result("PASS")
            .completed_at(1_704_068_000_000)
            .add_evidence_id("evid-001")
            .add_evidence_id("evid-002")
            .build_and_sign(executor)
    }

    #[test]
    fn test_build_and_sign() {
        let executor = Signer::generate();
        let run = create_test_run(&executor, "executor-001");

        assert_eq!(run.run_id, "run-001");
        assert_eq!(run.gate_id, "gate-build");
        assert_eq!(run.work_id, "work-001");
        assert_eq!(run.lease_id, "lease-001");
        assert_eq!(run.changeset_digest, [0x42; 32]);
        assert_eq!(run.executor_actor_id, "executor-001");
        assert_eq!(run.result, GateRunResult::Pass);
        assert_eq!(run.completed_at, 1_704_068_000_000);
        // Evidence IDs should be sorted
        assert_eq!(run.evidence_ids, vec!["evid-001", "evid-002"]);
    }

    #[test]
    fn test_signature_validation() {
        let executor = Signer::generate();
        let run = create_test_run(&executor, "executor-001");

        // Valid signature
        assert!(run.validate_signature(&executor.verifying_key()).is_ok());

        // Wrong key should fail
        let other_signer = Signer::generate();
        assert!(
            run.validate_signature(&other_signer.verifying_key())
                .is_err()
        );
    }

    #[test]
    fn test_signature_binds_to_content() {
        let executor = Signer::generate();
        let mut run = create_test_run(&executor, "executor-001");

        // Modify content after signing
        run.work_id = "work-002".to_string();

        // Signature should now be invalid
        assert!(run.validate_signature(&executor.verifying_key()).is_err());
    }

    #[test]
    fn test_verify_for_admission_happy_path() {
        let issuer = Signer::generate();
        let executor = Signer::generate();

        let lease = create_test_lease(&issuer, "executor-001");
        let run = create_test_run(&executor, "executor-001");

        let result = run.verify_for_admission(&lease, &executor.verifying_key(), |_| false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_for_admission_invalid_signature() {
        let issuer = Signer::generate();
        let executor = Signer::generate();
        let wrong_key = Signer::generate();

        let lease = create_test_lease(&issuer, "executor-001");
        let run = create_test_run(&executor, "executor-001");

        // Use wrong verifying key
        let result = run.verify_for_admission(&lease, &wrong_key.verifying_key(), |_| false);
        assert!(matches!(result, Err(GateRunError::InvalidSignature(_))));
    }

    #[test]
    fn test_verify_for_admission_lease_id_mismatch() {
        let issuer = Signer::generate();
        let executor = Signer::generate();

        // Create lease with different ID
        let lease = GateLeaseBuilder::new("lease-002", "work-001", "gate-build")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .issued_at(1_704_067_200_000)
            .expires_at(1_704_070_800_000)
            .policy_hash([0xab; 32])
            .issuer_actor_id("issuer-001")
            .time_envelope_ref("htf:tick:12345")
            .build_and_sign(&issuer);

        let run = create_test_run(&executor, "executor-001");

        let result = run.verify_for_admission(&lease, &executor.verifying_key(), |_| false);
        assert!(matches!(result, Err(GateRunError::LeaseIdMismatch { .. })));
    }

    #[test]
    fn test_verify_for_admission_changeset_mismatch() {
        let issuer = Signer::generate();
        let executor = Signer::generate();

        // Create lease with different changeset
        let lease = GateLeaseBuilder::new("lease-001", "work-001", "gate-build")
            .changeset_digest([0x99; 32]) // Different!
            .executor_actor_id("executor-001")
            .issued_at(1_704_067_200_000)
            .expires_at(1_704_070_800_000)
            .policy_hash([0xab; 32])
            .issuer_actor_id("issuer-001")
            .time_envelope_ref("htf:tick:12345")
            .build_and_sign(&issuer);

        let run = create_test_run(&executor, "executor-001");

        let result = run.verify_for_admission(&lease, &executor.verifying_key(), |_| false);
        assert!(matches!(result, Err(GateRunError::ChangesetMismatch)));
    }

    #[test]
    fn test_verify_for_admission_executor_mismatch() {
        let issuer = Signer::generate();
        let executor = Signer::generate();

        // Create lease with different executor
        let lease = GateLeaseBuilder::new("lease-001", "work-001", "gate-build")
            .changeset_digest([0x42; 32])
            .executor_actor_id("other-executor") // Different!
            .issued_at(1_704_067_200_000)
            .expires_at(1_704_070_800_000)
            .policy_hash([0xab; 32])
            .issuer_actor_id("issuer-001")
            .time_envelope_ref("htf:tick:12345")
            .build_and_sign(&issuer);

        let run = create_test_run(&executor, "executor-001");

        let result = run.verify_for_admission(&lease, &executor.verifying_key(), |_| false);
        assert!(matches!(result, Err(GateRunError::ExecutorMismatch { .. })));
    }

    #[test]
    fn test_verify_for_admission_lease_revoked() {
        let issuer = Signer::generate();
        let executor = Signer::generate();

        let lease = create_test_lease(&issuer, "executor-001");
        let run = create_test_run(&executor, "executor-001");

        // Mark lease as revoked
        let result =
            run.verify_for_admission(&lease, &executor.verifying_key(), |id| id == "lease-001");
        assert!(matches!(result, Err(GateRunError::LeaseRevoked { .. })));
    }

    #[test]
    fn test_verify_for_admission_lease_expired() {
        let issuer = Signer::generate();
        let executor = Signer::generate();

        let lease = create_test_lease(&issuer, "executor-001");

        // Create run that completed after lease expiry
        let run = GateRunCompletedBuilder::new("run-001", "gate-build", "work-001")
            .lease_id("lease-001")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .result("PASS")
            .completed_at(1_704_080_000_000) // After expiry!
            .build_and_sign(&executor);

        let result = run.verify_for_admission(&lease, &executor.verifying_key(), |_| false);
        assert!(matches!(result, Err(GateRunError::LeaseExpired { .. })));
    }

    #[test]
    fn test_verify_for_admission_completion_before_issued() {
        let issuer = Signer::generate();
        let executor = Signer::generate();

        let lease = create_test_lease(&issuer, "executor-001");

        // Create run that completed before lease was issued
        let run = GateRunCompletedBuilder::new("run-001", "gate-build", "work-001")
            .lease_id("lease-001")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .result("PASS")
            .completed_at(1_704_060_000_000) // Before issued!
            .build_and_sign(&executor);

        let result = run.verify_for_admission(&lease, &executor.verifying_key(), |_| false);
        assert!(matches!(
            result,
            Err(GateRunError::CompletionBeforeIssued { .. })
        ));
    }

    #[test]
    fn test_canonical_bytes_deterministic() {
        let executor = Signer::generate();
        let run1 = create_test_run(&executor, "executor-001");
        let run2 = create_test_run(&executor, "executor-001");

        // Same content should produce same canonical bytes
        assert_eq!(run1.canonical_bytes(), run2.canonical_bytes());
    }

    #[test]
    fn test_evidence_ids_sorted_in_canonical() {
        let executor = Signer::generate();

        // Create with unsorted evidence IDs
        let run1 = GateRunCompletedBuilder::new("run-001", "gate-build", "work-001")
            .lease_id("lease-001")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .result("PASS")
            .completed_at(1_704_068_000_000)
            .evidence_ids(vec!["evid-z".into(), "evid-a".into(), "evid-m".into()])
            .build_and_sign(&executor);

        // Create with sorted evidence IDs
        let run2 = GateRunCompletedBuilder::new("run-001", "gate-build", "work-001")
            .lease_id("lease-001")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .result("PASS")
            .completed_at(1_704_068_000_000)
            .evidence_ids(vec!["evid-a".into(), "evid-m".into(), "evid-z".into()])
            .build_and_sign(&executor);

        // Canonical bytes should be the same
        assert_eq!(run1.canonical_bytes(), run2.canonical_bytes());

        // Signatures should be the same
        assert_eq!(run1.executor_signature, run2.executor_signature);
    }

    #[test]
    fn test_gate_run_result_parse() {
        assert_eq!(GateRunResult::parse("PASS").unwrap(), GateRunResult::Pass);
        assert_eq!(GateRunResult::parse("FAIL").unwrap(), GateRunResult::Fail);
        assert!(GateRunResult::parse("INVALID").is_err());
    }

    #[test]
    fn test_gate_run_result_display() {
        assert_eq!(GateRunResult::Pass.to_string(), "PASS");
        assert_eq!(GateRunResult::Fail.to_string(), "FAIL");
    }

    #[test]
    fn test_proto_roundtrip() {
        use prost::Message;

        let executor = Signer::generate();
        let original = create_test_run(&executor, "executor-001");

        // Convert to proto
        let proto: GateRunCompletedProto = original.clone().into();

        // Encode and decode
        let encoded = proto.encode_to_vec();
        let decoded_proto = GateRunCompletedProto::decode(encoded.as_slice()).unwrap();

        // Convert back to domain type
        let recovered = GateRunCompleted::try_from(decoded_proto).unwrap();

        // Core fields should match
        assert_eq!(original.run_id, recovered.run_id);
        assert_eq!(original.gate_id, recovered.gate_id);
        assert_eq!(original.work_id, recovered.work_id);
        assert_eq!(original.lease_id, recovered.lease_id);
        assert_eq!(original.changeset_digest, recovered.changeset_digest);
        assert_eq!(original.executor_actor_id, recovered.executor_actor_id);
        assert_eq!(original.result, recovered.result);
        assert_eq!(original.evidence_ids, recovered.evidence_ids);
        assert_eq!(original.completed_at, recovered.completed_at);
        assert_eq!(original.executor_signature, recovered.executor_signature);

        // Signature should still be valid
        assert!(
            recovered
                .validate_signature(&executor.verifying_key())
                .is_ok()
        );
    }

    #[test]
    fn test_missing_field_error() {
        let executor = Signer::generate();

        let result = GateRunCompletedBuilder::new("run-001", "gate-build", "work-001")
            .changeset_digest([0x42; 32])
            // Missing lease_id
            .executor_actor_id("executor-001")
            .result("PASS")
            .completed_at(1_704_068_000_000)
            .try_build_and_sign(&executor);

        assert!(matches!(
            result,
            Err(GateRunError::MissingField("lease_id"))
        ));
    }

    #[test]
    fn test_fail_result() {
        let executor = Signer::generate();

        let run = GateRunCompletedBuilder::new("run-001", "gate-build", "work-001")
            .lease_id("lease-001")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .result("FAIL")
            .completed_at(1_704_068_000_000)
            .build_and_sign(&executor);

        assert_eq!(run.result, GateRunResult::Fail);

        // Signature should still be valid
        assert!(run.validate_signature(&executor.verifying_key()).is_ok());
    }

    #[test]
    fn test_boundary_time_validity() {
        let issuer = Signer::generate();
        let executor = Signer::generate();

        let lease = create_test_lease(&issuer, "executor-001");

        // Completion exactly at issued_at should pass
        let run_at_issued = GateRunCompletedBuilder::new("run-001", "gate-build", "work-001")
            .lease_id("lease-001")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .result("PASS")
            .completed_at(1_704_067_200_000) // Exactly at issued_at
            .build_and_sign(&executor);

        assert!(
            run_at_issued
                .verify_for_admission(&lease, &executor.verifying_key(), |_| false)
                .is_ok()
        );

        // Completion exactly at expires_at should pass
        let run_at_expiry = GateRunCompletedBuilder::new("run-002", "gate-build", "work-001")
            .lease_id("lease-001")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .result("PASS")
            .completed_at(1_704_070_800_000) // Exactly at expires_at
            .build_and_sign(&executor);

        assert!(
            run_at_expiry
                .verify_for_admission(&lease, &executor.verifying_key(), |_| false)
                .is_ok()
        );
    }
}
