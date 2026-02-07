// AGENT-AUTHORED
//! Gate lease types for the Forge Admission Cycle.
//!
//! This module defines [`GateLease`] which represents a cryptographically
//! signed authorization binding an executor to a specific changeset and time
//! window.
//!
//! # Security Model
//!
//! Gate leases implement the authority model for the Forge Admission Cycle:
//!
//! - **Executor Binding**: The lease binds a specific executor actor to the
//!   work
//! - **Changeset Binding**: The changeset digest prevents substitution attacks
//! - **Time Binding**: The time envelope reference enforces temporal bounds
//! - **Policy Binding**: The `policy_hash` links to the resolved policy
//!
//! # Signature Verification
//!
//! All gate leases are signed using domain-separated Ed25519 signatures.
//! The signature covers the canonical encoding of the lease (excluding the
//! signature field itself) with the `GATE_LEASE_ISSUED:` domain prefix.
//!
//! # AAT Extension
//!
//! For AAT gates, the lease includes an optional `aat_extension` field that
//! binds the lease to specific RCP manifest and view commitment. This is
//! required by RFC-0015 and TCK-00203.
//!
//! # Example
//!
//! ```rust
//! use apm2_core::crypto::Signer;
//! use apm2_core::fac::{GateLease, GateLeaseBuilder};
//!
//! // Create a gate lease
//! let signer = Signer::generate();
//! let lease = GateLeaseBuilder::new("lease-001", "work-001", "gate-build")
//!     .changeset_digest([0x42; 32])
//!     .executor_actor_id("executor-001")
//!     .issued_at(1704067200000)
//!     .expires_at(1704070800000)
//!     .policy_hash([0xab; 32])
//!     .issuer_actor_id("issuer-001")
//!     .time_envelope_ref("htf:tick:12345")
//!     .build_and_sign(&signer);
//!
//! // Verify the signature
//! assert!(lease.validate_signature(&signer.verifying_key()).is_ok());
//! ```

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use thiserror::Error;

use super::aat_receipt::AatGateReceipt;
use super::domain_separator::{GATE_LEASE_ISSUED_PREFIX, sign_with_domain, verify_with_domain};
use super::key_policy::{KeyPolicy, KeyPolicyError};
use super::policy_resolution::MAX_STRING_LENGTH;
use crate::crypto::{Signature, VerifyingKey};

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during gate lease operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LeaseError {
    /// The lease signature is invalid.
    #[error("invalid lease signature: {0}")]
    InvalidSignature(String),

    /// Missing required field.
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// Invalid lease data.
    #[error("invalid lease data: {0}")]
    InvalidData(String),

    /// String field exceeds maximum length.
    #[error("string field {field} exceeds max length: {actual} > {max}")]
    StringTooLong {
        /// Name of the field that exceeded the limit.
        field: &'static str,
        /// Actual length of the string.
        actual: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// AAT extension invariant violation.
    #[error("AAT extension invariant violation: {0}")]
    AatExtensionInvariant(String),

    /// AAT binding validation failure.
    #[error("AAT binding mismatch: {field}")]
    AatBindingMismatch {
        /// Name of the mismatched field.
        field: &'static str,
    },

    /// Lease is missing required AAT extension.
    #[error("lease is missing required AAT extension for binding validation")]
    MissingAatExtension,

    /// Custody domain validation failure (self-review attack prevention).
    #[error("custody domain violation: executor in same domain as author (domain: {domain_id})")]
    CustodyDomainViolation {
        /// The custody domain where the violation occurred.
        domain_id: String,
    },

    /// Key policy error during custody validation.
    #[error("key policy error: {0}")]
    KeyPolicyError(#[from] KeyPolicyError),
}

// =============================================================================
// AatLeaseExtension
// =============================================================================

/// AAT-specific extension fields for gate leases.
///
/// When a lease is issued for an AAT gate, this extension binds the lease
/// to specific RCP manifest, view commitment, and selection policy.
///
/// # Fields
///
/// - `view_commitment_hash`: Hash of the view commitment for this AAT run
/// - `rcp_manifest_hash`: Hash of the RCP manifest for this profile
/// - `rcp_profile_id`: Identifier of the RCP profile being used
/// - `selection_policy_id`: Identifier of the selection policy
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AatLeaseExtension {
    /// Hash of the view commitment for this AAT run.
    #[serde(with = "serde_bytes")]
    pub view_commitment_hash: [u8; 32],

    /// Hash of the RCP manifest for this profile.
    #[serde(with = "serde_bytes")]
    pub rcp_manifest_hash: [u8; 32],

    /// Identifier of the RCP profile being used.
    pub rcp_profile_id: String,

    /// Identifier of the selection policy.
    pub selection_policy_id: String,
}

// =============================================================================
// GateLease
// =============================================================================

/// A cryptographically signed gate lease binding an executor to a changeset.
///
/// The gate lease authorizes a specific executor to run a gate on a specific
/// changeset within a time window. The lease includes a `policy_hash` that
/// must match the resolved policy for the changeset.
///
/// # Fields
///
/// - `lease_id`: Unique identifier for this lease
/// - `work_id`: Work item this lease applies to
/// - `gate_id`: Gate this lease authorizes
/// - `changeset_digest`: Hash binding to specific changeset
/// - `executor_actor_id`: Actor authorized to execute
/// - `issued_at`: Timestamp when lease was issued (millis)
/// - `expires_at`: Timestamp when lease expires (millis)
/// - `policy_hash`: Hash of the resolved policy tuple
/// - `issuer_actor_id`: Actor who issued the lease
/// - `time_envelope_ref`: Reference to time envelope for temporal bounds
/// - `aat_extension`: Optional AAT-specific extension (required for AAT gates)
/// - `issuer_signature`: Ed25519 signature with domain separation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GateLease {
    /// Unique identifier for this lease.
    pub lease_id: String,

    /// Work item this lease applies to.
    pub work_id: String,

    /// Gate this lease authorizes execution on.
    pub gate_id: String,

    /// Hash binding to specific changeset.
    #[serde(with = "serde_bytes")]
    pub changeset_digest: [u8; 32],

    /// Actor authorized to execute the gate.
    pub executor_actor_id: String,

    /// Timestamp when the lease was issued (milliseconds since epoch).
    pub issued_at: u64,

    /// Timestamp when the lease expires (milliseconds since epoch).
    pub expires_at: u64,

    /// Hash of the resolved policy tuple.
    ///
    /// This must match the `resolved_policy_hash` from the corresponding
    /// `PolicyResolvedForChangeSet` event.
    #[serde(with = "serde_bytes")]
    pub policy_hash: [u8; 32],

    /// Actor who issued this lease.
    pub issuer_actor_id: String,

    /// Reference to the time envelope for temporal bounds.
    pub time_envelope_ref: String,

    /// Optional AAT-specific extension (required for AAT gates).
    ///
    /// When `gate_id` is "aat", this field must be present and binds the
    /// lease to specific RCP manifest and view commitment.
    pub aat_extension: Option<AatLeaseExtension>,

    /// Ed25519 signature over canonical bytes with domain separation.
    #[serde(with = "serde_bytes")]
    pub issuer_signature: [u8; 64],
}

impl GateLease {
    /// Returns the canonical bytes for signing/verification.
    ///
    /// The canonical representation includes all fields except the signature,
    /// encoded in a deterministic order.
    ///
    /// # Encoding
    ///
    /// Uses length-prefixed encoding (4-byte big-endian u32) for
    /// variable-length strings to prevent canonicalization collision
    /// attacks.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // String lengths are validated elsewhere
    pub fn canonical_bytes(&self) -> Vec<u8> {
        // Calculate AAT extension size if present
        let aat_ext_size = self.aat_extension.as_ref().map_or(0, |ext| {
            1 + 32 + 32 + 4 + ext.rcp_profile_id.len() + 4 + ext.selection_policy_id.len()
        });

        let capacity = 4 + self.lease_id.len()
            + 4 + self.work_id.len()
            + 4 + self.gate_id.len()
            + 32  // changeset_digest
            + 4 + self.executor_actor_id.len()
            + 8   // issued_at
            + 8   // expires_at
            + 32  // policy_hash
            + 4 + self.issuer_actor_id.len()
            + 4 + self.time_envelope_ref.len()
            + aat_ext_size;

        let mut bytes = Vec::with_capacity(capacity);

        // 1. lease_id (length-prefixed)
        bytes.extend_from_slice(&(self.lease_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.lease_id.as_bytes());

        // 2. work_id (length-prefixed)
        bytes.extend_from_slice(&(self.work_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.work_id.as_bytes());

        // 3. gate_id (length-prefixed)
        bytes.extend_from_slice(&(self.gate_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.gate_id.as_bytes());

        // 4. changeset_digest
        bytes.extend_from_slice(&self.changeset_digest);

        // 5. executor_actor_id (length-prefixed)
        bytes.extend_from_slice(&(self.executor_actor_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.executor_actor_id.as_bytes());

        // 6. issued_at (big-endian)
        bytes.extend_from_slice(&self.issued_at.to_be_bytes());

        // 7. expires_at (big-endian)
        bytes.extend_from_slice(&self.expires_at.to_be_bytes());

        // 8. policy_hash
        bytes.extend_from_slice(&self.policy_hash);

        // 9. issuer_actor_id (length-prefixed)
        bytes.extend_from_slice(&(self.issuer_actor_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.issuer_actor_id.as_bytes());

        // 10. time_envelope_ref (length-prefixed)
        bytes.extend_from_slice(&(self.time_envelope_ref.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.time_envelope_ref.as_bytes());

        // 11. aat_extension (optional)
        if let Some(ref ext) = self.aat_extension {
            bytes.push(1); // presence flag
            bytes.extend_from_slice(&ext.view_commitment_hash);
            bytes.extend_from_slice(&ext.rcp_manifest_hash);
            bytes.extend_from_slice(&(ext.rcp_profile_id.len() as u32).to_be_bytes());
            bytes.extend_from_slice(ext.rcp_profile_id.as_bytes());
            bytes.extend_from_slice(&(ext.selection_policy_id.len() as u32).to_be_bytes());
            bytes.extend_from_slice(ext.selection_policy_id.as_bytes());
        } else {
            bytes.push(0); // absence flag
        }

        bytes
    }

    /// Validates that the given timestamp falls within the lease's temporal
    /// bounds.
    ///
    /// Returns `true` if `issued_at <= now_ms < expires_at`, `false` otherwise.
    ///
    /// # Arguments
    ///
    /// * `now_ms` - The current timestamp in milliseconds since epoch
    ///
    /// # Returns
    ///
    /// `true` if the lease is valid at the given time, `false` otherwise.
    ///
    /// # Example
    ///
    /// ```rust
    /// use apm2_core::crypto::Signer;
    /// use apm2_core::fac::GateLeaseBuilder;
    ///
    /// let signer = Signer::generate();
    /// let lease = GateLeaseBuilder::new("lease-001", "work-001", "gate-build")
    ///     .changeset_digest([0x42; 32])
    ///     .executor_actor_id("executor-001")
    ///     .issued_at(1000)
    ///     .expires_at(2000)
    ///     .policy_hash([0xab; 32])
    ///     .issuer_actor_id("issuer-001")
    ///     .time_envelope_ref("htf:tick:12345")
    ///     .build_and_sign(&signer);
    ///
    /// assert!(!lease.validate_temporal_bounds(999)); // Before issued_at
    /// assert!(lease.validate_temporal_bounds(1000)); // At issued_at
    /// assert!(lease.validate_temporal_bounds(1500)); // Between
    /// assert!(!lease.validate_temporal_bounds(2000)); // At expires_at (exclusive)
    /// assert!(!lease.validate_temporal_bounds(2001)); // After expires_at
    /// ```
    #[must_use]
    pub const fn validate_temporal_bounds(&self, now_ms: u64) -> bool {
        now_ms >= self.issued_at && now_ms < self.expires_at
    }

    /// Alias for `validate_temporal_bounds` - checks if the lease is valid at
    /// the given time.
    ///
    /// Returns `true` if `issued_at <= now_ms < expires_at`, `false` otherwise.
    #[must_use]
    pub const fn is_valid_at(&self, now_ms: u64) -> bool {
        self.validate_temporal_bounds(now_ms)
    }

    /// Validates the lease signature using domain separation.
    ///
    /// # Arguments
    ///
    /// * `verifying_key` - The public key of the expected issuer
    ///
    /// # Returns
    ///
    /// `Ok(())` if the signature is valid,
    /// `Err(LeaseError::InvalidSignature)` otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`LeaseError::InvalidSignature`] if signature verification
    /// fails.
    pub fn validate_signature(&self, verifying_key: &VerifyingKey) -> Result<(), LeaseError> {
        let signature = Signature::from_bytes(&self.issuer_signature);
        let canonical = self.canonical_bytes();

        verify_with_domain(
            verifying_key,
            GATE_LEASE_ISSUED_PREFIX,
            &canonical,
            &signature,
        )
        .map_err(|e| LeaseError::InvalidSignature(e.to_string()))
    }

    /// Validates that an AAT gate receipt matches the lease's AAT extension.
    ///
    /// This method verifies that the receipt was produced for the same view
    /// commitment and RCP manifest that the lease was issued for, preventing
    /// substitution attacks where an attacker could swap receipt data.
    ///
    /// # Security Notes
    ///
    /// - Uses constant-time comparison for hash values to prevent timing
    ///   attacks
    /// - FAIL-CLOSED: if lease lacks AAT extension, validation fails
    /// - Both `view_commitment_hash` and `rcp_manifest_hash` must match
    ///
    /// # Arguments
    ///
    /// * `receipt` - The AAT gate receipt to validate against this lease
    ///
    /// # Returns
    ///
    /// `Ok(())` if the receipt matches the lease binding, error otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`LeaseError::MissingAatExtension`] if the lease has no AAT
    /// extension.
    ///
    /// Returns [`LeaseError::AatBindingMismatch`] if either hash does not
    /// match.
    ///
    /// # Example
    ///
    /// ```rust
    /// use apm2_core::crypto::Signer;
    /// use apm2_core::fac::{
    ///     AatAttestation, AatGateReceipt, AatGateReceiptBuilder, AatLeaseExtension, AatVerdict,
    ///     DeterminismClass, DeterminismStatus, FlakeClass, GateLeaseBuilder, RiskTier,
    ///     TerminalVerifierOutput,
    /// };
    ///
    /// let signer = Signer::generate();
    /// let view_hash = [0x11; 32];
    /// let manifest_hash = [0x22; 32];
    ///
    /// let lease = GateLeaseBuilder::new("lease-001", "work-001", "aat")
    ///     .changeset_digest([0x42; 32])
    ///     .executor_actor_id("executor-001")
    ///     .issued_at(1704067200000)
    ///     .expires_at(1704070800000)
    ///     .policy_hash([0xab; 32])
    ///     .issuer_actor_id("issuer-001")
    ///     .time_envelope_ref("htf:tick:12345")
    ///     .aat_extension(AatLeaseExtension {
    ///         view_commitment_hash: view_hash,
    ///         rcp_manifest_hash: manifest_hash,
    ///         rcp_profile_id: "profile-001".to_string(),
    ///         selection_policy_id: "policy-001".to_string(),
    ///     })
    ///     .build_and_sign(&signer);
    ///
    /// // Create matching receipt
    /// let terminal_evidence_digest = [0x77; 32];
    /// let terminal_verifier_outputs_digest = [0x99; 32];
    /// let verdict = AatVerdict::Pass;
    /// let stability_digest = AatGateReceipt::compute_stability_digest(
    ///     verdict,
    ///     &terminal_evidence_digest,
    ///     &terminal_verifier_outputs_digest,
    /// );
    ///
    /// let receipt = AatGateReceiptBuilder::new()
    ///     .view_commitment_hash(view_hash)  // Must match lease
    ///     .rcp_manifest_hash(manifest_hash)  // Must match lease
    ///     .rcp_profile_id("profile-001")
    ///     .policy_hash([0x33; 32])
    ///     .determinism_class(DeterminismClass::FullyDeterministic)
    ///     .determinism_status(DeterminismStatus::Stable)
    ///     .flake_class(FlakeClass::DeterministicFail)
    ///     .run_count(1)
    ///     .run_receipt_hashes(vec![[0x44; 32]])
    ///     .terminal_evidence_digest(terminal_evidence_digest)
    ///     .observational_evidence_digest([0x88; 32])
    ///     .terminal_verifier_outputs_digest(terminal_verifier_outputs_digest)
    ///     .stability_digest(stability_digest)
    ///     .verdict(verdict)
    ///     .transcript_chain_root_hash([0xBB; 32])
    ///     .transcript_bundle_hash([0xCC; 32])
    ///     .artifact_manifest_hash([0xDD; 32])
    ///     .terminal_verifier_outputs(vec![TerminalVerifierOutput {
    ///         verifier_kind: "exit_code".to_string(),
    ///         output_digest: [0xEE; 32],
    ///         predicate_satisfied: true,
    ///     }])
    ///     .verifier_policy_hash([0xFF; 32])
    ///     .selection_policy_id("policy-001")
    ///     .risk_tier(RiskTier::Tier1)
    ///     .attestation(AatAttestation {
    ///         container_image_digest: [0x01; 32],
    ///         toolchain_digests: vec![[0x02; 32]],
    ///         runner_identity_key_id: "runner-001".to_string(),
    ///         network_policy_profile_hash: [0x03; 32],
    ///     })
    ///     .build()
    ///     .expect("valid receipt");
    ///
    /// // Validation should pass
    /// assert!(lease.validate_aat_binding(&receipt).is_ok());
    /// ```
    pub fn validate_aat_binding(&self, receipt: &AatGateReceipt) -> Result<(), LeaseError> {
        // FAIL-CLOSED: If lease has no AAT extension, reject
        let ext = self
            .aat_extension
            .as_ref()
            .ok_or(LeaseError::MissingAatExtension)?;

        // Use constant-time comparison for view_commitment_hash (RSK-1909)
        if !bool::from(
            ext.view_commitment_hash
                .ct_eq(&receipt.view_commitment_hash),
        ) {
            return Err(LeaseError::AatBindingMismatch {
                field: "view_commitment_hash",
            });
        }

        // Use constant-time comparison for rcp_manifest_hash (RSK-1909)
        if !bool::from(ext.rcp_manifest_hash.ct_eq(&receipt.rcp_manifest_hash)) {
            return Err(LeaseError::AatBindingMismatch {
                field: "rcp_manifest_hash",
            });
        }

        // Validate rcp_profile_id matches (TCK-00225)
        if ext.rcp_profile_id != receipt.rcp_profile_id {
            return Err(LeaseError::AatBindingMismatch {
                field: "rcp_profile_id",
            });
        }

        // Validate selection_policy_id matches (TCK-00225)
        if ext.selection_policy_id != receipt.selection_policy_id {
            return Err(LeaseError::AatBindingMismatch {
                field: "selection_policy_id",
            });
        }

        Ok(())
    }
}

// =============================================================================
// Custody Domain Validation
// =============================================================================

/// Validates that an AAT lease executor is in a different custody domain than
/// the changeset author using key-based validation.
///
/// **NOTE**: This function uses `executor_key_id` for validation. For
/// issuance-time validation where you have an `executor_actor_id` from the
/// lease, use [`validate_custody_for_aat_lease_by_actor`] instead.
///
/// This function is a defense against self-review attacks, where an
/// author could attempt to review their own code changes. By ensuring the
/// executor (reviewer) is in a different custody domain than the author, we
/// enforce separation of concerns.
///
/// # Security Notes
///
/// - FAIL-CLOSED: If executor or author cannot be found in the policy, the
///   function returns an error
/// - Uses the `KeyPolicy::validate_coi()` method which performs constant-time
///   comparison internally
/// - The function checks COI (Conflict of Interest) groups, which map to
///   custody domains
///
/// # Arguments
///
/// * `key_policy` - The key policy defining custody domains and COI rules
/// * `executor_key_id` - The key ID of the executor (the reviewer)
/// * `author_actor_id` - The actor ID of the changeset author
///
/// # Returns
///
/// `Ok(())` if the executor is in a different custody domain than the author.
///
/// # Errors
///
/// Returns [`LeaseError::KeyPolicyError`] wrapping the underlying error if:
/// - The executor key is not found in any custody domain
/// - The author actor is not found in any custody domain
/// - A COI violation is detected (same custody domain)
///
/// # Example
///
/// ```rust
/// use apm2_core::fac::{
///     CustodyDomain, KeyBinding, KeyPolicy, KeyPolicyBuilder, validate_custody_for_aat_lease,
/// };
///
/// let policy = KeyPolicyBuilder::new("policy-001")
///     .schema_version(1)
///     .add_custody_domain(CustodyDomain {
///         domain_id: "dev-team-a".to_string(),
///         coi_group_id: "coi-group-alpha".to_string(),
///         key_bindings: vec![KeyBinding {
///             key_id: "key-alice".to_string(),
///             actor_id: "alice".to_string(),
///         }],
///     })
///     .add_custody_domain(CustodyDomain {
///         domain_id: "dev-team-b".to_string(),
///         coi_group_id: "coi-group-beta".to_string(),
///         key_bindings: vec![KeyBinding {
///             key_id: "key-bob".to_string(),
///             actor_id: "bob".to_string(),
///         }],
///     })
///     .build();
///
/// // Bob can review Alice's code (different custody domains)
/// assert!(validate_custody_for_aat_lease(&policy, "key-bob", "alice").is_ok());
///
/// // Alice cannot review her own code (same custody domain)
/// assert!(validate_custody_for_aat_lease(&policy, "key-alice", "alice").is_err());
/// ```
pub fn validate_custody_for_aat_lease(
    key_policy: &KeyPolicy,
    executor_key_id: &str,
    author_actor_id: &str,
) -> Result<(), LeaseError> {
    // Delegate to KeyPolicy::validate_coi which:
    // - Finds executor's COI group from their key
    // - Finds ALL of author's COI groups (prevents multi-binding bypass)
    // - Uses constant-time comparison
    // - Returns CoiViolation if groups overlap
    key_policy
        .validate_coi(executor_key_id, author_actor_id)
        .map_err(LeaseError::from)
}

/// Validates that an AAT lease executor is in a different custody domain than
/// the changeset author using actor-based validation.
///
/// This function is designed for **issuance-time validation** where the lease
/// binds `executor_actor_id` rather than a key ID. It validates COI based on
/// comparing the COI groups of both actors.
///
/// # Security Notes
///
/// - FAIL-CLOSED: If executor or author cannot be found in the policy, the
///   function returns an error
/// - Uses constant-time comparison for COI group comparison
/// - Checks ALL COI groups the author belongs to (prevents multi-binding
///   bypass)
/// - Returns error if ANY of the executor's COI groups overlap with ANY of the
///   author's COI groups
///
/// # Arguments
///
/// * `key_policy` - The key policy defining custody domains and COI rules
/// * `executor_actor_id` - The actor ID of the executor (from
///   `GateLease.executor_actor_id`)
/// * `author_actor_id` - The actor ID of the changeset author
///
/// # Returns
///
/// `Ok(())` if the executor is in a different custody domain than the author.
///
/// # Errors
///
/// Returns [`LeaseError::KeyPolicyError`] wrapping the underlying error if:
/// - The executor actor is not found in any custody domain
/// - The author actor is not found in any custody domain
/// - A COI violation is detected (same or overlapping custody domains)
///
/// # Example
///
/// ```rust
/// use apm2_core::fac::{
///     CustodyDomain, KeyBinding, KeyPolicy, KeyPolicyBuilder,
///     validate_custody_for_aat_lease_by_actor,
/// };
///
/// let policy = KeyPolicyBuilder::new("policy-001")
///     .schema_version(1)
///     .add_custody_domain(CustodyDomain {
///         domain_id: "dev-team-a".to_string(),
///         coi_group_id: "coi-group-alpha".to_string(),
///         key_bindings: vec![KeyBinding {
///             key_id: "key-alice".to_string(),
///             actor_id: "alice".to_string(),
///         }],
///     })
///     .add_custody_domain(CustodyDomain {
///         domain_id: "dev-team-b".to_string(),
///         coi_group_id: "coi-group-beta".to_string(),
///         key_bindings: vec![KeyBinding {
///             key_id: "key-bob".to_string(),
///             actor_id: "bob".to_string(),
///         }],
///     })
///     .build();
///
/// // Bob can review Alice's code (different custody domains)
/// assert!(validate_custody_for_aat_lease_by_actor(&policy, "bob", "alice").is_ok());
///
/// // Alice cannot review her own code (same person)
/// assert!(validate_custody_for_aat_lease_by_actor(&policy, "alice", "alice").is_err());
/// ```
pub fn validate_custody_for_aat_lease_by_actor(
    key_policy: &KeyPolicy,
    executor_actor_id: &str,
    author_actor_id: &str,
) -> Result<(), LeaseError> {
    // Find ALL COI groups for the executor actor
    let executor_coi_groups = key_policy.get_coi_groups_for_actor(executor_actor_id);

    if executor_coi_groups.is_empty() {
        return Err(LeaseError::KeyPolicyError(KeyPolicyError::ActorNotFound {
            actor_id: executor_actor_id.to_string(),
        }));
    }

    // Find ALL COI groups for the author actor
    let author_coi_groups = key_policy.get_coi_groups_for_actor(author_actor_id);

    if author_coi_groups.is_empty() {
        return Err(LeaseError::KeyPolicyError(KeyPolicyError::ActorNotFound {
            actor_id: author_actor_id.to_string(),
        }));
    }

    // Check for COI violation: executor's groups must not overlap with author's
    // groups Use constant-time comparison for each group comparison (RSK-1909)
    for executor_group in &executor_coi_groups {
        for author_group in &author_coi_groups {
            let executor_bytes = executor_group.as_bytes();
            let author_bytes = author_group.as_bytes();

            // Constant-time comparison requires equal-length inputs
            let is_equal = if executor_bytes.len() == author_bytes.len() {
                bool::from(executor_bytes.ct_eq(author_bytes))
            } else {
                false
            };

            if is_equal {
                return Err(LeaseError::CustodyDomainViolation {
                    domain_id: executor_group.clone(),
                });
            }
        }
    }

    Ok(())
}

// =============================================================================
// Builder
// =============================================================================

/// Builder for constructing [`GateLease`] instances.
#[derive(Debug, Default)]
pub struct GateLeaseBuilder {
    lease_id: String,
    work_id: String,
    gate_id: String,
    changeset_digest: Option<[u8; 32]>,
    executor_actor_id: Option<String>,
    issued_at: Option<u64>,
    expires_at: Option<u64>,
    policy_hash: Option<[u8; 32]>,
    issuer_actor_id: Option<String>,
    time_envelope_ref: Option<String>,
    aat_extension: Option<AatLeaseExtension>,
}

impl GateLeaseBuilder {
    /// Creates a new builder with required IDs.
    #[must_use]
    pub fn new(
        lease_id: impl Into<String>,
        work_id: impl Into<String>,
        gate_id: impl Into<String>,
    ) -> Self {
        Self {
            lease_id: lease_id.into(),
            work_id: work_id.into(),
            gate_id: gate_id.into(),
            ..Default::default()
        }
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

    /// Sets the issuance timestamp (milliseconds since epoch).
    #[must_use]
    pub const fn issued_at(mut self, timestamp: u64) -> Self {
        self.issued_at = Some(timestamp);
        self
    }

    /// Sets the expiration timestamp (milliseconds since epoch).
    #[must_use]
    pub const fn expires_at(mut self, timestamp: u64) -> Self {
        self.expires_at = Some(timestamp);
        self
    }

    /// Sets the policy hash.
    #[must_use]
    pub const fn policy_hash(mut self, hash: [u8; 32]) -> Self {
        self.policy_hash = Some(hash);
        self
    }

    /// Sets the issuer actor ID.
    #[must_use]
    pub fn issuer_actor_id(mut self, actor_id: impl Into<String>) -> Self {
        self.issuer_actor_id = Some(actor_id.into());
        self
    }

    /// Sets the time envelope reference.
    #[must_use]
    pub fn time_envelope_ref(mut self, ref_id: impl Into<String>) -> Self {
        self.time_envelope_ref = Some(ref_id.into());
        self
    }

    /// Sets the AAT extension.
    #[must_use]
    pub fn aat_extension(mut self, extension: AatLeaseExtension) -> Self {
        self.aat_extension = Some(extension);
        self
    }

    /// Builds the lease and signs it with the provided signer.
    ///
    /// # Panics
    ///
    /// Panics if required fields are missing.
    #[must_use]
    pub fn build_and_sign(self, signer: &crate::crypto::Signer) -> GateLease {
        self.try_build_and_sign(signer)
            .expect("missing required field")
    }

    /// Attempts to build and sign the lease.
    ///
    /// # Errors
    ///
    /// Returns [`LeaseError::MissingField`] if any required field is not set.
    /// Returns [`LeaseError::StringTooLong`] if any string field exceeds the
    /// maximum length.
    /// Returns [`LeaseError::AatExtensionInvariant`] if the AAT extension
    /// invariant is violated.
    #[allow(clippy::too_many_lines)]
    pub fn try_build_and_sign(
        self,
        signer: &crate::crypto::Signer,
    ) -> Result<GateLease, LeaseError> {
        let changeset_digest = self
            .changeset_digest
            .ok_or(LeaseError::MissingField("changeset_digest"))?;
        let executor_actor_id = self
            .executor_actor_id
            .ok_or(LeaseError::MissingField("executor_actor_id"))?;
        let issued_at = self
            .issued_at
            .ok_or(LeaseError::MissingField("issued_at"))?;
        let expires_at = self
            .expires_at
            .ok_or(LeaseError::MissingField("expires_at"))?;
        let policy_hash = self
            .policy_hash
            .ok_or(LeaseError::MissingField("policy_hash"))?;
        let issuer_actor_id = self
            .issuer_actor_id
            .ok_or(LeaseError::MissingField("issuer_actor_id"))?;
        let time_envelope_ref = self
            .time_envelope_ref
            .ok_or(LeaseError::MissingField("time_envelope_ref"))?;

        // Validate string lengths to prevent DoS
        if self.lease_id.len() > MAX_STRING_LENGTH {
            return Err(LeaseError::StringTooLong {
                field: "lease_id",
                actual: self.lease_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if self.work_id.len() > MAX_STRING_LENGTH {
            return Err(LeaseError::StringTooLong {
                field: "work_id",
                actual: self.work_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if self.gate_id.len() > MAX_STRING_LENGTH {
            return Err(LeaseError::StringTooLong {
                field: "gate_id",
                actual: self.gate_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if executor_actor_id.len() > MAX_STRING_LENGTH {
            return Err(LeaseError::StringTooLong {
                field: "executor_actor_id",
                actual: executor_actor_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if issuer_actor_id.len() > MAX_STRING_LENGTH {
            return Err(LeaseError::StringTooLong {
                field: "issuer_actor_id",
                actual: issuer_actor_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if time_envelope_ref.len() > MAX_STRING_LENGTH {
            return Err(LeaseError::StringTooLong {
                field: "time_envelope_ref",
                actual: time_envelope_ref.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if let Some(ref ext) = self.aat_extension {
            if ext.rcp_profile_id.len() > MAX_STRING_LENGTH {
                return Err(LeaseError::StringTooLong {
                    field: "aat_extension.rcp_profile_id",
                    actual: ext.rcp_profile_id.len(),
                    max: MAX_STRING_LENGTH,
                });
            }
            if ext.selection_policy_id.len() > MAX_STRING_LENGTH {
                return Err(LeaseError::StringTooLong {
                    field: "aat_extension.selection_policy_id",
                    actual: ext.selection_policy_id.len(),
                    max: MAX_STRING_LENGTH,
                });
            }
        }

        // Validate AAT extension invariant:
        // - If gate_id contains "aat" (case-insensitive), aat_extension MUST be Some
        // - If gate_id does NOT contain "aat", aat_extension SHOULD be None
        let is_aat_gate = self.gate_id.to_lowercase().contains("aat");
        if is_aat_gate && self.aat_extension.is_none() {
            return Err(LeaseError::AatExtensionInvariant(
                "AAT gate requires aat_extension to be set".to_string(),
            ));
        }
        if !is_aat_gate && self.aat_extension.is_some() {
            return Err(LeaseError::AatExtensionInvariant(
                "non-AAT gate should not have aat_extension set".to_string(),
            ));
        }

        // Create lease with placeholder signature
        let mut lease = GateLease {
            lease_id: self.lease_id,
            work_id: self.work_id,
            gate_id: self.gate_id,
            changeset_digest,
            executor_actor_id,
            issued_at,
            expires_at,
            policy_hash,
            issuer_actor_id,
            time_envelope_ref,
            aat_extension: self.aat_extension,
            issuer_signature: [0u8; 64],
        };

        // Sign the canonical bytes
        let canonical = lease.canonical_bytes();
        let signature = sign_with_domain(signer, GATE_LEASE_ISSUED_PREFIX, &canonical);
        lease.issuer_signature = signature.to_bytes();

        Ok(lease)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::crypto::Signer;

    fn create_test_lease(signer: &Signer) -> GateLease {
        GateLeaseBuilder::new("lease-001", "work-001", "gate-build")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .issued_at(1_704_067_200_000)
            .expires_at(1_704_070_800_000)
            .policy_hash([0xab; 32])
            .issuer_actor_id("issuer-001")
            .time_envelope_ref("htf:tick:12345")
            .build_and_sign(signer)
    }

    #[test]
    fn test_build_and_sign() {
        let signer = Signer::generate();
        let lease = create_test_lease(&signer);

        assert_eq!(lease.lease_id, "lease-001");
        assert_eq!(lease.work_id, "work-001");
        assert_eq!(lease.gate_id, "gate-build");
        assert_eq!(lease.changeset_digest, [0x42; 32]);
        assert_eq!(lease.executor_actor_id, "executor-001");
        assert_eq!(lease.issued_at, 1_704_067_200_000);
        assert_eq!(lease.expires_at, 1_704_070_800_000);
        assert_eq!(lease.policy_hash, [0xab; 32]);
        assert_eq!(lease.issuer_actor_id, "issuer-001");
        assert_eq!(lease.time_envelope_ref, "htf:tick:12345");
    }

    #[test]
    fn test_signature_validation() {
        let signer = Signer::generate();
        let lease = create_test_lease(&signer);

        // Valid signature
        assert!(lease.validate_signature(&signer.verifying_key()).is_ok());

        // Wrong key should fail
        let other_signer = Signer::generate();
        assert!(
            lease
                .validate_signature(&other_signer.verifying_key())
                .is_err()
        );
    }

    #[test]
    fn test_signature_binds_to_content() {
        let signer = Signer::generate();
        let mut lease = create_test_lease(&signer);

        // Modify content after signing
        lease.work_id = "work-002".to_string();

        // Signature should now be invalid
        assert!(lease.validate_signature(&signer.verifying_key()).is_err());
    }

    #[test]
    fn test_canonical_bytes_deterministic() {
        let signer = Signer::generate();
        let lease1 = create_test_lease(&signer);
        let lease2 = create_test_lease(&signer);

        // Same content should produce same canonical bytes
        assert_eq!(lease1.canonical_bytes(), lease2.canonical_bytes());
    }

    #[test]
    fn test_missing_field_error() {
        let signer = Signer::generate();

        // Missing changeset_digest
        let result = GateLeaseBuilder::new("lease-001", "work-001", "gate-build")
            .executor_actor_id("executor-001")
            .issued_at(1_704_067_200_000)
            .expires_at(1_704_070_800_000)
            .policy_hash([0xab; 32])
            .issuer_actor_id("issuer-001")
            .time_envelope_ref("htf:tick:12345")
            .try_build_and_sign(&signer);

        assert!(matches!(
            result,
            Err(LeaseError::MissingField("changeset_digest"))
        ));
    }

    #[test]
    fn test_domain_separator_prevents_replay() {
        // Verify that lease uses GATE_LEASE_ISSUED: domain separator
        // by ensuring a signature created without the prefix fails
        let signer = Signer::generate();
        let lease = create_test_lease(&signer);

        // Create a signature without domain prefix
        let canonical = lease.canonical_bytes();
        let wrong_signature = signer.sign(&canonical); // No domain prefix!

        // Manually create a lease with the wrong signature
        let mut bad_lease = lease;
        bad_lease.issuer_signature = wrong_signature.to_bytes();

        // Verification should fail
        assert!(
            bad_lease
                .validate_signature(&signer.verifying_key())
                .is_err()
        );
    }

    #[test]
    fn test_build_with_aat_extension() {
        let signer = Signer::generate();
        let lease = GateLeaseBuilder::new("lease-001", "work-001", "aat")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .issued_at(1_704_067_200_000)
            .expires_at(1_704_070_800_000)
            .policy_hash([0xab; 32])
            .issuer_actor_id("issuer-001")
            .time_envelope_ref("htf:tick:12345")
            .aat_extension(AatLeaseExtension {
                view_commitment_hash: [0x11; 32],
                rcp_manifest_hash: [0x22; 32],
                rcp_profile_id: "aat-profile-001".to_string(),
                selection_policy_id: "policy-001".to_string(),
            })
            .build_and_sign(&signer);

        assert_eq!(lease.gate_id, "aat");
        assert!(lease.aat_extension.is_some());
        let ext = lease.aat_extension.as_ref().unwrap();
        assert_eq!(ext.view_commitment_hash, [0x11; 32]);
        assert_eq!(ext.rcp_manifest_hash, [0x22; 32]);
        assert_eq!(ext.rcp_profile_id, "aat-profile-001");
        assert_eq!(ext.selection_policy_id, "policy-001");

        // Signature should be valid
        assert!(lease.validate_signature(&signer.verifying_key()).is_ok());
    }

    #[test]
    fn test_aat_extension_in_canonical_bytes() {
        let signer = Signer::generate();

        // Create non-AAT lease without extension
        let lease_without_ext = GateLeaseBuilder::new("lease-001", "work-001", "gate-build")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .issued_at(1_704_067_200_000)
            .expires_at(1_704_070_800_000)
            .policy_hash([0xab; 32])
            .issuer_actor_id("issuer-001")
            .time_envelope_ref("htf:tick:12345")
            .build_and_sign(&signer);

        // Create AAT lease with extension (use same IDs to isolate extension
        // difference)
        let lease_with_ext = GateLeaseBuilder::new("lease-001", "work-001", "aat")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .issued_at(1_704_067_200_000)
            .expires_at(1_704_070_800_000)
            .policy_hash([0xab; 32])
            .issuer_actor_id("issuer-001")
            .time_envelope_ref("htf:tick:12345")
            .aat_extension(AatLeaseExtension {
                view_commitment_hash: [0x11; 32],
                rcp_manifest_hash: [0x22; 32],
                rcp_profile_id: "aat-profile-001".to_string(),
                selection_policy_id: "policy-001".to_string(),
            })
            .build_and_sign(&signer);

        // Canonical bytes should be different (different gate_id AND extension
        // presence)
        assert_ne!(
            lease_without_ext.canonical_bytes(),
            lease_with_ext.canonical_bytes()
        );

        // Also verify two AAT leases with different extensions have different canonical
        // bytes
        let lease_with_ext_2 = GateLeaseBuilder::new("lease-001", "work-001", "aat")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .issued_at(1_704_067_200_000)
            .expires_at(1_704_070_800_000)
            .policy_hash([0xab; 32])
            .issuer_actor_id("issuer-001")
            .time_envelope_ref("htf:tick:12345")
            .aat_extension(AatLeaseExtension {
                view_commitment_hash: [0x33; 32], // Different hash
                rcp_manifest_hash: [0x22; 32],
                rcp_profile_id: "aat-profile-001".to_string(),
                selection_policy_id: "policy-001".to_string(),
            })
            .build_and_sign(&signer);

        assert_ne!(
            lease_with_ext.canonical_bytes(),
            lease_with_ext_2.canonical_bytes()
        );
    }

    #[test]
    fn test_aat_extension_binds_to_signature() {
        let signer = Signer::generate();
        let mut lease = GateLeaseBuilder::new("lease-001", "work-001", "aat")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .issued_at(1_704_067_200_000)
            .expires_at(1_704_070_800_000)
            .policy_hash([0xab; 32])
            .issuer_actor_id("issuer-001")
            .time_envelope_ref("htf:tick:12345")
            .aat_extension(AatLeaseExtension {
                view_commitment_hash: [0x11; 32],
                rcp_manifest_hash: [0x22; 32],
                rcp_profile_id: "aat-profile-001".to_string(),
                selection_policy_id: "policy-001".to_string(),
            })
            .build_and_sign(&signer);

        // Modify AAT extension after signing
        if let Some(ref mut ext) = lease.aat_extension {
            ext.rcp_manifest_hash = [0xFF; 32];
        }

        // Signature should now be invalid
        assert!(lease.validate_signature(&signer.verifying_key()).is_err());
    }

    #[test]
    fn test_length_prefixed_canonicalization_prevents_collision() {
        let signer = Signer::generate();

        // Create two leases with different field values that could collide
        // with null-termination but not with length-prefixing
        let lease1 = GateLeaseBuilder::new("ab", "cd", "gate")
            .changeset_digest([0x42; 32])
            .executor_actor_id("ef")
            .issued_at(1_704_067_200_000)
            .expires_at(1_704_070_800_000)
            .policy_hash([0xab; 32])
            .issuer_actor_id("issuer")
            .time_envelope_ref("ref")
            .build_and_sign(&signer);

        // "ab" + "cd" + "ef" should NOT equal "a" + "bcd" + "ef" with length-prefixing
        let lease2 = GateLeaseBuilder::new("a", "bcd", "gate")
            .changeset_digest([0x42; 32])
            .executor_actor_id("ef")
            .issued_at(1_704_067_200_000)
            .expires_at(1_704_070_800_000)
            .policy_hash([0xab; 32])
            .issuer_actor_id("issuer")
            .time_envelope_ref("ref")
            .build_and_sign(&signer);

        // Canonical bytes should be different
        assert_ne!(lease1.canonical_bytes(), lease2.canonical_bytes());
    }

    #[test]
    fn test_validate_temporal_bounds() {
        let signer = Signer::generate();
        let lease = GateLeaseBuilder::new("lease-001", "work-001", "gate-build")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .issued_at(1000)
            .expires_at(2000)
            .policy_hash([0xab; 32])
            .issuer_actor_id("issuer-001")
            .time_envelope_ref("htf:tick:12345")
            .build_and_sign(&signer);

        // Before issued_at
        assert!(!lease.validate_temporal_bounds(999));

        // At issued_at (inclusive)
        assert!(lease.validate_temporal_bounds(1000));

        // Between issued_at and expires_at
        assert!(lease.validate_temporal_bounds(1500));

        // At expires_at (exclusive)
        assert!(!lease.validate_temporal_bounds(2000));

        // After expires_at
        assert!(!lease.validate_temporal_bounds(2001));
    }

    #[test]
    fn test_is_valid_at_alias() {
        let signer = Signer::generate();
        let lease = GateLeaseBuilder::new("lease-001", "work-001", "gate-build")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .issued_at(1000)
            .expires_at(2000)
            .policy_hash([0xab; 32])
            .issuer_actor_id("issuer-001")
            .time_envelope_ref("htf:tick:12345")
            .build_and_sign(&signer);

        // is_valid_at should behave identically to validate_temporal_bounds
        assert_eq!(lease.is_valid_at(999), lease.validate_temporal_bounds(999));
        assert_eq!(
            lease.is_valid_at(1000),
            lease.validate_temporal_bounds(1000)
        );
        assert_eq!(
            lease.is_valid_at(1500),
            lease.validate_temporal_bounds(1500)
        );
        assert_eq!(
            lease.is_valid_at(2000),
            lease.validate_temporal_bounds(2000)
        );
    }

    #[test]
    fn test_aat_gate_requires_extension() {
        let signer = Signer::generate();

        // AAT gate without extension should fail
        let result = GateLeaseBuilder::new("lease-001", "work-001", "aat")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .issued_at(1_704_067_200_000)
            .expires_at(1_704_070_800_000)
            .policy_hash([0xab; 32])
            .issuer_actor_id("issuer-001")
            .time_envelope_ref("htf:tick:12345")
            .try_build_and_sign(&signer);

        assert!(matches!(
            result,
            Err(LeaseError::AatExtensionInvariant(msg)) if msg.contains("requires aat_extension")
        ));
    }

    #[test]
    fn test_aat_gate_case_insensitive() {
        let signer = Signer::generate();

        // Uppercase AAT without extension should fail
        let result = GateLeaseBuilder::new("lease-001", "work-001", "AAT")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .issued_at(1_704_067_200_000)
            .expires_at(1_704_070_800_000)
            .policy_hash([0xab; 32])
            .issuer_actor_id("issuer-001")
            .time_envelope_ref("htf:tick:12345")
            .try_build_and_sign(&signer);

        assert!(matches!(
            result,
            Err(LeaseError::AatExtensionInvariant(msg)) if msg.contains("requires aat_extension")
        ));

        // Mixed case AAT without extension should fail
        let result = GateLeaseBuilder::new("lease-001", "work-001", "Aat")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .issued_at(1_704_067_200_000)
            .expires_at(1_704_070_800_000)
            .policy_hash([0xab; 32])
            .issuer_actor_id("issuer-001")
            .time_envelope_ref("htf:tick:12345")
            .try_build_and_sign(&signer);

        assert!(matches!(
            result,
            Err(LeaseError::AatExtensionInvariant(msg)) if msg.contains("requires aat_extension")
        ));
    }

    #[test]
    fn test_aat_gate_with_prefix_suffix() {
        let signer = Signer::generate();

        // Gate containing "aat" as substring should require extension
        let result = GateLeaseBuilder::new("lease-001", "work-001", "pre-aat-post")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .issued_at(1_704_067_200_000)
            .expires_at(1_704_070_800_000)
            .policy_hash([0xab; 32])
            .issuer_actor_id("issuer-001")
            .time_envelope_ref("htf:tick:12345")
            .try_build_and_sign(&signer);

        assert!(matches!(
            result,
            Err(LeaseError::AatExtensionInvariant(msg)) if msg.contains("requires aat_extension")
        ));
    }

    #[test]
    fn test_non_aat_gate_rejects_extension() {
        let signer = Signer::generate();

        // Non-AAT gate with extension should fail
        let result = GateLeaseBuilder::new("lease-001", "work-001", "gate-build")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .issued_at(1_704_067_200_000)
            .expires_at(1_704_070_800_000)
            .policy_hash([0xab; 32])
            .issuer_actor_id("issuer-001")
            .time_envelope_ref("htf:tick:12345")
            .aat_extension(AatLeaseExtension {
                view_commitment_hash: [0x11; 32],
                rcp_manifest_hash: [0x22; 32],
                rcp_profile_id: "aat-profile-001".to_string(),
                selection_policy_id: "policy-001".to_string(),
            })
            .try_build_and_sign(&signer);

        assert!(matches!(
            result,
            Err(LeaseError::AatExtensionInvariant(msg)) if msg.contains("should not have aat_extension")
        ));
    }

    #[test]
    fn test_aat_gate_with_extension_succeeds() {
        let signer = Signer::generate();

        // AAT gate with extension should succeed
        let result = GateLeaseBuilder::new("lease-001", "work-001", "aat")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .issued_at(1_704_067_200_000)
            .expires_at(1_704_070_800_000)
            .policy_hash([0xab; 32])
            .issuer_actor_id("issuer-001")
            .time_envelope_ref("htf:tick:12345")
            .aat_extension(AatLeaseExtension {
                view_commitment_hash: [0x11; 32],
                rcp_manifest_hash: [0x22; 32],
                rcp_profile_id: "aat-profile-001".to_string(),
                selection_policy_id: "policy-001".to_string(),
            })
            .try_build_and_sign(&signer);

        assert!(result.is_ok());
        let lease = result.unwrap();
        assert!(lease.aat_extension.is_some());
    }

    #[test]
    fn test_non_aat_gate_without_extension_succeeds() {
        let signer = Signer::generate();

        // Non-AAT gate without extension should succeed
        let result = GateLeaseBuilder::new("lease-001", "work-001", "gate-build")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .issued_at(1_704_067_200_000)
            .expires_at(1_704_070_800_000)
            .policy_hash([0xab; 32])
            .issuer_actor_id("issuer-001")
            .time_envelope_ref("htf:tick:12345")
            .try_build_and_sign(&signer);

        assert!(result.is_ok());
        let lease = result.unwrap();
        assert!(lease.aat_extension.is_none());
    }

    // =========================================================================
    // AAT Binding Validation Tests (TCK-00225)
    // =========================================================================

    mod aat {
        use super::*;
        use crate::fac::aat_receipt::{
            AatAttestation, AatGateReceipt, AatGateReceiptBuilder, AatVerdict, DeterminismStatus,
            FlakeClass, TerminalVerifierOutput,
        };
        use crate::fac::key_policy::{
            CoiEnforcementLevel, CoiRule, CustodyDomain, KeyBinding, KeyPolicyBuilder,
        };
        use crate::fac::policy_resolution::{DeterminismClass, RiskTier};

        /// Helper to create a valid AAT gate receipt with the given hashes and
        /// IDs.
        fn create_test_receipt_with_ids(
            view_commitment_hash: [u8; 32],
            rcp_manifest_hash: [u8; 32],
            rcp_profile_id: &str,
            selection_policy_id: &str,
        ) -> AatGateReceipt {
            let terminal_evidence_digest = [0x77; 32];
            let terminal_verifier_outputs_digest = [0x99; 32];
            let verdict = AatVerdict::Pass;
            let stability_digest = AatGateReceipt::compute_stability_digest(
                verdict,
                &terminal_evidence_digest,
                &terminal_verifier_outputs_digest,
            );

            AatGateReceiptBuilder::new()
                .view_commitment_hash(view_commitment_hash)
                .rcp_manifest_hash(rcp_manifest_hash)
                .rcp_profile_id(rcp_profile_id)
                .policy_hash([0x33; 32])
                .determinism_class(DeterminismClass::FullyDeterministic)
                .determinism_status(DeterminismStatus::Stable)
                .flake_class(FlakeClass::DeterministicFail)
                .run_count(1)
                .run_receipt_hashes(vec![[0x44; 32]])
                .terminal_evidence_digest(terminal_evidence_digest)
                .observational_evidence_digest([0x88; 32])
                .terminal_verifier_outputs_digest(terminal_verifier_outputs_digest)
                .stability_digest(stability_digest)
                .verdict(verdict)
                .transcript_chain_root_hash([0xBB; 32])
                .transcript_bundle_hash([0xCC; 32])
                .artifact_manifest_hash([0xDD; 32])
                .terminal_verifier_outputs(vec![TerminalVerifierOutput {
                    verifier_kind: "exit_code".to_string(),
                    output_digest: [0xEE; 32],
                    predicate_satisfied: true,
                }])
                .verifier_policy_hash([0xFF; 32])
                .selection_policy_id(selection_policy_id)
                .risk_tier(RiskTier::Tier1)
                .attestation(AatAttestation {
                    container_image_digest: [0x01; 32],
                    toolchain_digests: vec![[0x02; 32]],
                    runner_identity_key_id: "runner-001".to_string(),
                    network_policy_profile_hash: [0x03; 32],
                })
                .build()
                .expect("valid receipt")
        }

        /// Helper to create a valid AAT gate receipt with the given hashes.
        fn create_test_receipt(
            view_commitment_hash: [u8; 32],
            rcp_manifest_hash: [u8; 32],
        ) -> AatGateReceipt {
            // Use default IDs that match the lease helper
            create_test_receipt_with_ids(
                view_commitment_hash,
                rcp_manifest_hash,
                "aat-profile-001",
                "policy-001",
            )
        }

        /// Helper to create a test AAT lease with the given hashes and IDs.
        fn create_test_aat_lease_with_ids(
            signer: &Signer,
            view_commitment_hash: [u8; 32],
            rcp_manifest_hash: [u8; 32],
            rcp_profile_id: &str,
            selection_policy_id: &str,
        ) -> GateLease {
            GateLeaseBuilder::new("lease-001", "work-001", "aat")
                .changeset_digest([0x42; 32])
                .executor_actor_id("executor-001")
                .issued_at(1_704_067_200_000)
                .expires_at(1_704_070_800_000)
                .policy_hash([0xab; 32])
                .issuer_actor_id("issuer-001")
                .time_envelope_ref("htf:tick:12345")
                .aat_extension(AatLeaseExtension {
                    view_commitment_hash,
                    rcp_manifest_hash,
                    rcp_profile_id: rcp_profile_id.to_string(),
                    selection_policy_id: selection_policy_id.to_string(),
                })
                .build_and_sign(signer)
        }

        /// Helper to create a test AAT lease with the given hashes.
        fn create_test_aat_lease(
            signer: &Signer,
            view_commitment_hash: [u8; 32],
            rcp_manifest_hash: [u8; 32],
        ) -> GateLease {
            create_test_aat_lease_with_ids(
                signer,
                view_commitment_hash,
                rcp_manifest_hash,
                "aat-profile-001",
                "policy-001",
            )
        }

        #[test]
        fn test_validate_aat_binding_matching_hashes() {
            let signer = Signer::generate();
            let view_hash = [0x11; 32];
            let manifest_hash = [0x22; 32];

            let lease = create_test_aat_lease(&signer, view_hash, manifest_hash);
            let receipt = create_test_receipt(view_hash, manifest_hash);

            // Matching hashes and IDs should pass validation
            assert!(lease.validate_aat_binding(&receipt).is_ok());
        }

        // =====================================================================
        // Profile and Policy ID Binding Validation Tests (TCK-00225 BLOCKER)
        // =====================================================================

        #[test]
        fn test_validate_aat_binding_rcp_profile_id_mismatch() {
            let signer = Signer::generate();
            let view_hash = [0x11; 32];
            let manifest_hash = [0x22; 32];

            // Lease has profile "aat-profile-001"
            let lease = create_test_aat_lease(&signer, view_hash, manifest_hash);

            // Receipt has different profile "different-profile"
            let receipt = create_test_receipt_with_ids(
                view_hash,
                manifest_hash,
                "different-profile",
                "policy-001",
            );

            let result = lease.validate_aat_binding(&receipt);
            assert!(matches!(
                result,
                Err(LeaseError::AatBindingMismatch {
                    field: "rcp_profile_id"
                })
            ));
        }

        #[test]
        fn test_validate_aat_binding_selection_policy_id_mismatch() {
            let signer = Signer::generate();
            let view_hash = [0x11; 32];
            let manifest_hash = [0x22; 32];

            // Lease has selection_policy_id "policy-001"
            let lease = create_test_aat_lease(&signer, view_hash, manifest_hash);

            // Receipt has different selection_policy_id "different-policy"
            let receipt = create_test_receipt_with_ids(
                view_hash,
                manifest_hash,
                "aat-profile-001",
                "different-policy",
            );

            let result = lease.validate_aat_binding(&receipt);
            assert!(matches!(
                result,
                Err(LeaseError::AatBindingMismatch {
                    field: "selection_policy_id"
                })
            ));
        }

        #[test]
        fn test_validate_aat_binding_both_ids_mismatch() {
            let signer = Signer::generate();
            let view_hash = [0x11; 32];
            let manifest_hash = [0x22; 32];

            let lease = create_test_aat_lease(&signer, view_hash, manifest_hash);

            // Both IDs different
            let receipt = create_test_receipt_with_ids(
                view_hash,
                manifest_hash,
                "different-profile",
                "different-policy",
            );

            // Should fail on rcp_profile_id first (checked after hashes)
            let result = lease.validate_aat_binding(&receipt);
            assert!(matches!(
                result,
                Err(LeaseError::AatBindingMismatch {
                    field: "rcp_profile_id"
                })
            ));
        }

        #[test]
        fn test_validate_aat_binding_all_fields_match() {
            let signer = Signer::generate();
            let view_hash = [0x11; 32];
            let manifest_hash = [0x22; 32];
            let profile_id = "custom-profile";
            let policy_id = "custom-policy";

            let lease = create_test_aat_lease_with_ids(
                &signer,
                view_hash,
                manifest_hash,
                profile_id,
                policy_id,
            );
            let receipt =
                create_test_receipt_with_ids(view_hash, manifest_hash, profile_id, policy_id);

            // All fields match
            assert!(lease.validate_aat_binding(&receipt).is_ok());
        }

        #[test]
        fn test_validate_aat_binding_view_commitment_mismatch() {
            let signer = Signer::generate();
            let view_hash = [0x11; 32];
            let manifest_hash = [0x22; 32];

            let lease = create_test_aat_lease(&signer, view_hash, manifest_hash);
            // Create receipt with different view_commitment_hash
            let receipt = create_test_receipt([0xFF; 32], manifest_hash);

            let result = lease.validate_aat_binding(&receipt);
            assert!(matches!(
                result,
                Err(LeaseError::AatBindingMismatch {
                    field: "view_commitment_hash"
                })
            ));
        }

        #[test]
        fn test_validate_aat_binding_rcp_manifest_mismatch() {
            let signer = Signer::generate();
            let view_hash = [0x11; 32];
            let manifest_hash = [0x22; 32];

            let lease = create_test_aat_lease(&signer, view_hash, manifest_hash);
            // Create receipt with different rcp_manifest_hash
            let receipt = create_test_receipt(view_hash, [0xFF; 32]);

            let result = lease.validate_aat_binding(&receipt);
            assert!(matches!(
                result,
                Err(LeaseError::AatBindingMismatch {
                    field: "rcp_manifest_hash"
                })
            ));
        }

        #[test]
        fn test_validate_aat_binding_both_mismatch() {
            let signer = Signer::generate();
            let view_hash = [0x11; 32];
            let manifest_hash = [0x22; 32];

            let lease = create_test_aat_lease(&signer, view_hash, manifest_hash);
            // Create receipt with both hashes different
            let receipt = create_test_receipt([0xAA; 32], [0xBB; 32]);

            // Should fail on view_commitment_hash first (checked first)
            let result = lease.validate_aat_binding(&receipt);
            assert!(matches!(
                result,
                Err(LeaseError::AatBindingMismatch {
                    field: "view_commitment_hash"
                })
            ));
        }

        #[test]
        fn test_validate_aat_binding_missing_extension() {
            let signer = Signer::generate();
            let view_hash = [0x11; 32];
            let manifest_hash = [0x22; 32];

            // Create non-AAT lease without extension
            let lease = GateLeaseBuilder::new("lease-001", "work-001", "gate-build")
                .changeset_digest([0x42; 32])
                .executor_actor_id("executor-001")
                .issued_at(1_704_067_200_000)
                .expires_at(1_704_070_800_000)
                .policy_hash([0xab; 32])
                .issuer_actor_id("issuer-001")
                .time_envelope_ref("htf:tick:12345")
                .build_and_sign(&signer);

            let receipt = create_test_receipt(view_hash, manifest_hash);

            // FAIL-CLOSED: Should reject if lease has no AAT extension
            let result = lease.validate_aat_binding(&receipt);
            assert!(matches!(result, Err(LeaseError::MissingAatExtension)));
        }

        #[test]
        fn test_validate_aat_binding_single_bit_difference() {
            let signer = Signer::generate();
            let view_hash = [0x11; 32];
            let manifest_hash = [0x22; 32];

            let lease = create_test_aat_lease(&signer, view_hash, manifest_hash);

            // Create receipt with only the first bit different in view_commitment_hash
            let mut tampered_view_hash = view_hash;
            tampered_view_hash[0] ^= 0x01; // Flip one bit

            let receipt = create_test_receipt(tampered_view_hash, manifest_hash);

            // Even a single bit difference should be detected
            let result = lease.validate_aat_binding(&receipt);
            assert!(matches!(
                result,
                Err(LeaseError::AatBindingMismatch {
                    field: "view_commitment_hash"
                })
            ));
        }

        #[test]
        fn test_validate_aat_binding_zero_hashes() {
            let signer = Signer::generate();
            let zero_hash = [0x00; 32];

            let lease = create_test_aat_lease(&signer, zero_hash, zero_hash);
            let receipt = create_test_receipt(zero_hash, zero_hash);

            // Zero hashes should still work if they match
            assert!(lease.validate_aat_binding(&receipt).is_ok());
        }

        #[test]
        fn test_validate_aat_binding_max_hashes() {
            let signer = Signer::generate();
            let max_hash = [0xFF; 32];

            let lease = create_test_aat_lease(&signer, max_hash, max_hash);
            let receipt = create_test_receipt(max_hash, max_hash);

            // Max value hashes should still work if they match
            assert!(lease.validate_aat_binding(&receipt).is_ok());
        }

        // =====================================================================
        // Custody Domain Validation Tests (TCK-00225)
        // =====================================================================

        #[test]
        fn test_validate_custody_different_domains_ok() {
            let policy = KeyPolicyBuilder::new("policy-001")
                .schema_version(1)
                .add_custody_domain(CustodyDomain {
                    domain_id: "dev-team-a".to_string(),
                    coi_group_id: "coi-group-alpha".to_string(),
                    key_bindings: vec![KeyBinding {
                        key_id: "key-alice".to_string(),
                        actor_id: "alice".to_string(),
                    }],
                })
                .add_custody_domain(CustodyDomain {
                    domain_id: "dev-team-b".to_string(),
                    coi_group_id: "coi-group-beta".to_string(),
                    key_bindings: vec![KeyBinding {
                        key_id: "key-bob".to_string(),
                        actor_id: "bob".to_string(),
                    }],
                })
                .add_coi_rule(CoiRule {
                    rule_id: "no-self-review".to_string(),
                    description: "Prevent self-review attacks".to_string(),
                    enforcement_level: CoiEnforcementLevel::Reject,
                })
                .build();

            // Bob (group-beta) can review Alice's (group-alpha) code
            assert!(
                super::super::validate_custody_for_aat_lease(&policy, "key-bob", "alice").is_ok()
            );
        }

        #[test]
        fn test_validate_custody_same_domain_rejected() {
            let policy = KeyPolicyBuilder::new("policy-001")
                .schema_version(1)
                .add_custody_domain(CustodyDomain {
                    domain_id: "dev-team-a".to_string(),
                    coi_group_id: "coi-group-alpha".to_string(),
                    key_bindings: vec![
                        KeyBinding {
                            key_id: "key-alice".to_string(),
                            actor_id: "alice".to_string(),
                        },
                        KeyBinding {
                            key_id: "key-charlie".to_string(),
                            actor_id: "charlie".to_string(),
                        },
                    ],
                })
                .build();

            // Alice cannot review her own code (self-review attack)
            let result =
                super::super::validate_custody_for_aat_lease(&policy, "key-alice", "alice");
            assert!(result.is_err());

            // Charlie cannot review Alice's code (same COI group)
            let result =
                super::super::validate_custody_for_aat_lease(&policy, "key-charlie", "alice");
            assert!(result.is_err());
        }

        #[test]
        fn test_validate_custody_executor_key_not_found() {
            let policy = KeyPolicyBuilder::new("policy-001")
                .schema_version(1)
                .add_custody_domain(CustodyDomain {
                    domain_id: "dev-team-a".to_string(),
                    coi_group_id: "coi-group-alpha".to_string(),
                    key_bindings: vec![KeyBinding {
                        key_id: "key-alice".to_string(),
                        actor_id: "alice".to_string(),
                    }],
                })
                .build();

            // Unknown executor key should be rejected (FAIL-CLOSED)
            let result =
                super::super::validate_custody_for_aat_lease(&policy, "unknown-key", "alice");
            assert!(result.is_err());
        }

        #[test]
        fn test_validate_custody_author_not_found() {
            let policy = KeyPolicyBuilder::new("policy-001")
                .schema_version(1)
                .add_custody_domain(CustodyDomain {
                    domain_id: "dev-team-a".to_string(),
                    coi_group_id: "coi-group-alpha".to_string(),
                    key_bindings: vec![KeyBinding {
                        key_id: "key-alice".to_string(),
                        actor_id: "alice".to_string(),
                    }],
                })
                .build();

            // Unknown author should be rejected (FAIL-CLOSED)
            let result = super::super::validate_custody_for_aat_lease(
                &policy,
                "key-alice",
                "unknown-author",
            );
            assert!(result.is_err());
        }

        #[test]
        fn test_validate_custody_multi_domain_author_rejected() {
            // CRITICAL: Test for COI bypass via multiple group bindings
            // Author belongs to groups {A, B}, executor is in group B
            // The check MUST detect overlap and reject
            let policy = KeyPolicyBuilder::new("policy-001")
                .schema_version(1)
                .add_custody_domain(CustodyDomain {
                    domain_id: "dev-team-a".to_string(),
                    coi_group_id: "coi-group-alpha".to_string(),
                    key_bindings: vec![KeyBinding {
                        key_id: "key-alice-alpha".to_string(),
                        actor_id: "alice".to_string(), // Alice in group alpha
                    }],
                })
                .add_custody_domain(CustodyDomain {
                    domain_id: "dev-team-b".to_string(),
                    coi_group_id: "coi-group-beta".to_string(),
                    key_bindings: vec![
                        KeyBinding {
                            key_id: "key-alice-beta".to_string(),
                            actor_id: "alice".to_string(), // Alice ALSO in group beta
                        },
                        KeyBinding {
                            key_id: "key-bob".to_string(),
                            actor_id: "bob".to_string(),
                        },
                    ],
                })
                .build();

            // Bob (group-beta) reviewing Alice's changeset: MUST be REJECTED
            // because Alice is ALSO in group-beta
            let result = super::super::validate_custody_for_aat_lease(&policy, "key-bob", "alice");
            assert!(
                result.is_err(),
                "COI bypass via multiple group bindings should be rejected"
            );
        }

        #[test]
        fn test_validate_custody_multi_domain_no_overlap_ok() {
            // Author in groups {A, B}, executor in group C - no overlap
            let policy = KeyPolicyBuilder::new("policy-001")
                .schema_version(1)
                .add_custody_domain(CustodyDomain {
                    domain_id: "dev-team-a".to_string(),
                    coi_group_id: "coi-group-alpha".to_string(),
                    key_bindings: vec![KeyBinding {
                        key_id: "key-alice-alpha".to_string(),
                        actor_id: "alice".to_string(),
                    }],
                })
                .add_custody_domain(CustodyDomain {
                    domain_id: "dev-team-b".to_string(),
                    coi_group_id: "coi-group-beta".to_string(),
                    key_bindings: vec![KeyBinding {
                        key_id: "key-alice-beta".to_string(),
                        actor_id: "alice".to_string(),
                    }],
                })
                .add_custody_domain(CustodyDomain {
                    domain_id: "dev-team-c".to_string(),
                    coi_group_id: "coi-group-gamma".to_string(),
                    key_bindings: vec![KeyBinding {
                        key_id: "key-carol".to_string(),
                        actor_id: "carol".to_string(),
                    }],
                })
                .build();

            // Carol (group-gamma) can review Alice's (groups alpha, beta) code
            let result =
                super::super::validate_custody_for_aat_lease(&policy, "key-carol", "alice");
            assert!(result.is_ok());
        }

        #[test]
        fn test_validate_custody_empty_policy_fails() {
            let policy = KeyPolicyBuilder::new("policy-001")
                .schema_version(1)
                .build();

            // Empty policy should fail for any executor/author (FAIL-CLOSED)
            let result =
                super::super::validate_custody_for_aat_lease(&policy, "any-key", "any-actor");
            assert!(result.is_err());
        }

        // =====================================================================
        // Actor-Based Custody Validation Tests (TCK-00225 MAJOR)
        // =====================================================================

        #[test]
        fn test_validate_custody_by_actor_different_domains_ok() {
            let policy = KeyPolicyBuilder::new("policy-001")
                .schema_version(1)
                .add_custody_domain(CustodyDomain {
                    domain_id: "dev-team-a".to_string(),
                    coi_group_id: "coi-group-alpha".to_string(),
                    key_bindings: vec![KeyBinding {
                        key_id: "key-alice".to_string(),
                        actor_id: "alice".to_string(),
                    }],
                })
                .add_custody_domain(CustodyDomain {
                    domain_id: "dev-team-b".to_string(),
                    coi_group_id: "coi-group-beta".to_string(),
                    key_bindings: vec![KeyBinding {
                        key_id: "key-bob".to_string(),
                        actor_id: "bob".to_string(),
                    }],
                })
                .build();

            // Bob can review Alice's code (different custody domains)
            let result =
                super::super::validate_custody_for_aat_lease_by_actor(&policy, "bob", "alice");
            assert!(result.is_ok());
        }

        #[test]
        fn test_validate_custody_by_actor_same_domain_rejected() {
            let policy = KeyPolicyBuilder::new("policy-001")
                .schema_version(1)
                .add_custody_domain(CustodyDomain {
                    domain_id: "dev-team-a".to_string(),
                    coi_group_id: "coi-group-alpha".to_string(),
                    key_bindings: vec![
                        KeyBinding {
                            key_id: "key-alice".to_string(),
                            actor_id: "alice".to_string(),
                        },
                        KeyBinding {
                            key_id: "key-charlie".to_string(),
                            actor_id: "charlie".to_string(),
                        },
                    ],
                })
                .build();

            // Alice cannot review her own code (self-review)
            let result =
                super::super::validate_custody_for_aat_lease_by_actor(&policy, "alice", "alice");
            assert!(result.is_err());

            // Charlie cannot review Alice's code (same COI group)
            let result =
                super::super::validate_custody_for_aat_lease_by_actor(&policy, "charlie", "alice");
            assert!(result.is_err());
        }

        #[test]
        fn test_validate_custody_by_actor_executor_not_found() {
            let policy = KeyPolicyBuilder::new("policy-001")
                .schema_version(1)
                .add_custody_domain(CustodyDomain {
                    domain_id: "dev-team-a".to_string(),
                    coi_group_id: "coi-group-alpha".to_string(),
                    key_bindings: vec![KeyBinding {
                        key_id: "key-alice".to_string(),
                        actor_id: "alice".to_string(),
                    }],
                })
                .build();

            // Unknown executor actor should be rejected (FAIL-CLOSED)
            let result = super::super::validate_custody_for_aat_lease_by_actor(
                &policy,
                "unknown-executor",
                "alice",
            );
            assert!(result.is_err());
        }

        #[test]
        fn test_validate_custody_by_actor_author_not_found() {
            let policy = KeyPolicyBuilder::new("policy-001")
                .schema_version(1)
                .add_custody_domain(CustodyDomain {
                    domain_id: "dev-team-a".to_string(),
                    coi_group_id: "coi-group-alpha".to_string(),
                    key_bindings: vec![KeyBinding {
                        key_id: "key-alice".to_string(),
                        actor_id: "alice".to_string(),
                    }],
                })
                .build();

            // Unknown author actor should be rejected (FAIL-CLOSED)
            let result = super::super::validate_custody_for_aat_lease_by_actor(
                &policy,
                "alice",
                "unknown-author",
            );
            assert!(result.is_err());
        }

        #[test]
        fn test_validate_custody_by_actor_multi_group_author_overlap_rejected() {
            // CRITICAL: Author belongs to groups {A, B}, executor also in group B
            let policy = KeyPolicyBuilder::new("policy-001")
                .schema_version(1)
                .add_custody_domain(CustodyDomain {
                    domain_id: "dev-team-a".to_string(),
                    coi_group_id: "coi-group-alpha".to_string(),
                    key_bindings: vec![KeyBinding {
                        key_id: "key-alice-alpha".to_string(),
                        actor_id: "alice".to_string(), // Alice in group alpha
                    }],
                })
                .add_custody_domain(CustodyDomain {
                    domain_id: "dev-team-b".to_string(),
                    coi_group_id: "coi-group-beta".to_string(),
                    key_bindings: vec![
                        KeyBinding {
                            key_id: "key-alice-beta".to_string(),
                            actor_id: "alice".to_string(), // Alice ALSO in group beta
                        },
                        KeyBinding {
                            key_id: "key-bob".to_string(),
                            actor_id: "bob".to_string(), // Bob in group beta
                        },
                    ],
                })
                .build();

            // Bob (group-beta) reviewing Alice (groups alpha, beta): REJECTED
            // because Alice is also in group-beta
            let result =
                super::super::validate_custody_for_aat_lease_by_actor(&policy, "bob", "alice");
            assert!(
                result.is_err(),
                "COI bypass via actor in multiple groups should be rejected"
            );
        }

        #[test]
        fn test_validate_custody_by_actor_multi_group_no_overlap_ok() {
            // Author in groups {A, B}, executor in group C - no overlap
            let policy = KeyPolicyBuilder::new("policy-001")
                .schema_version(1)
                .add_custody_domain(CustodyDomain {
                    domain_id: "dev-team-a".to_string(),
                    coi_group_id: "coi-group-alpha".to_string(),
                    key_bindings: vec![KeyBinding {
                        key_id: "key-alice-alpha".to_string(),
                        actor_id: "alice".to_string(),
                    }],
                })
                .add_custody_domain(CustodyDomain {
                    domain_id: "dev-team-b".to_string(),
                    coi_group_id: "coi-group-beta".to_string(),
                    key_bindings: vec![KeyBinding {
                        key_id: "key-alice-beta".to_string(),
                        actor_id: "alice".to_string(),
                    }],
                })
                .add_custody_domain(CustodyDomain {
                    domain_id: "dev-team-c".to_string(),
                    coi_group_id: "coi-group-gamma".to_string(),
                    key_bindings: vec![KeyBinding {
                        key_id: "key-carol".to_string(),
                        actor_id: "carol".to_string(),
                    }],
                })
                .build();

            // Carol (group-gamma) can review Alice's (groups alpha, beta) code
            let result =
                super::super::validate_custody_for_aat_lease_by_actor(&policy, "carol", "alice");
            assert!(result.is_ok());
        }

        #[test]
        fn test_validate_custody_by_actor_empty_policy_fails() {
            let policy = KeyPolicyBuilder::new("policy-001")
                .schema_version(1)
                .build();

            // Empty policy should fail for any executor/author (FAIL-CLOSED)
            let result = super::super::validate_custody_for_aat_lease_by_actor(
                &policy,
                "any-actor",
                "other-actor",
            );
            assert!(result.is_err());
        }

        #[test]
        fn test_validate_custody_by_actor_executor_multi_group_overlap_rejected() {
            // CRITICAL: Executor belongs to groups {A, B}, author in group A
            let policy = KeyPolicyBuilder::new("policy-001")
                .schema_version(1)
                .add_custody_domain(CustodyDomain {
                    domain_id: "dev-team-a".to_string(),
                    coi_group_id: "coi-group-alpha".to_string(),
                    key_bindings: vec![
                        KeyBinding {
                            key_id: "key-bob-alpha".to_string(),
                            actor_id: "bob".to_string(), // Bob in group alpha
                        },
                        KeyBinding {
                            key_id: "key-alice".to_string(),
                            actor_id: "alice".to_string(), // Alice in group alpha
                        },
                    ],
                })
                .add_custody_domain(CustodyDomain {
                    domain_id: "dev-team-b".to_string(),
                    coi_group_id: "coi-group-beta".to_string(),
                    key_bindings: vec![KeyBinding {
                        key_id: "key-bob-beta".to_string(),
                        actor_id: "bob".to_string(), // Bob ALSO in group beta
                    }],
                })
                .build();

            // Bob (groups alpha, beta) reviewing Alice (group alpha): REJECTED
            // because Bob is also in group alpha
            let result =
                super::super::validate_custody_for_aat_lease_by_actor(&policy, "bob", "alice");
            assert!(
                result.is_err(),
                "COI bypass via executor in multiple groups should be rejected"
            );
        }
    }
}
