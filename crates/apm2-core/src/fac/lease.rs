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
use thiserror::Error;

use super::domain_separator::{GATE_LEASE_ISSUED_PREFIX, sign_with_domain, verify_with_domain};
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
}
