// AGENT-AUTHORED
//! Policy resolution types for the Forge Admission Cycle.
//!
//! This module defines [`PolicyResolvedForChangeSet`] which is the anchor event
//! that locks policy decisions for a changeset. All subsequent lease issuance
//! and receipt validation must reference this anchor.
//!
//! # Security Model
//!
//! `PolicyResolvedForChangeSet` serves as the cryptographic anchor for policy
//! binding:
//!
//! - **Policy Binding**: The `resolved_policy_hash` binds all policy decisions
//!   for a changeset
//! - **Lease Verification**: `verify_lease_match()` ensures lease `policy_hash`
//!   matches resolution
//! - **Anti-Downgrade**: `verify_receipt_match()` detects policy downgrades
//! - **Domain Separation**: Signature uses `POLICY_RESOLVED_FOR_CHANGESET:`
//!   prefix
//!
//! # Ordering Invariant
//!
//! **CRITICAL**: A `PolicyResolvedForChangeSet` event MUST exist before any
//! `GateLeaseIssued` event for the same `work_id`/changeset. This ensures all
//! leases operate under a locked policy configuration.
//!
//! # Example
//!
//! ```rust
//! use apm2_core::crypto::Signer;
//! use apm2_core::fac::{
//!     GateLease, GateLeaseBuilder, PolicyResolvedForChangeSet,
//!     PolicyResolvedForChangeSetBuilder,
//! };
//!
//! // Create a policy resolution
//! let resolver_signer = Signer::generate();
//! let resolution =
//!     PolicyResolvedForChangeSetBuilder::new("work-001", [0x42; 32])
//!         .resolved_risk_tier(1)
//!         .resolved_determinism_class(0)
//!         .resolver_actor_id("resolver-001")
//!         .resolver_version("1.0.0")
//!         .build_and_sign(&resolver_signer);
//!
//! // Create a lease that references the resolution's policy hash
//! let issuer_signer = Signer::generate();
//! let lease = GateLeaseBuilder::new("lease-001", "work-001", "gate-build")
//!     .changeset_digest([0x42; 32])
//!     .executor_actor_id("executor-001")
//!     .issued_at(1704067200000)
//!     .expires_at(1704070800000)
//!     .policy_hash(resolution.resolved_policy_hash())
//!     .issuer_actor_id("issuer-001")
//!     .time_envelope_ref("htf:tick:12345")
//!     .build_and_sign(&issuer_signer);
//!
//! // Verify the lease matches the policy resolution
//! assert!(resolution.verify_lease_match(&lease).is_ok());
//! ```

use subtle::ConstantTimeEq;

// Re-export the generated proto type for wire format serialization.
// This replaces the previously manual struct definition.
pub use crate::events::PolicyResolvedForChangeSet as PolicyResolvedForChangeSetProto;

// =============================================================================
// Resource Limits
// =============================================================================

/// Maximum number of RCP profiles allowed in a policy resolution.
/// This prevents denial-of-service attacks via oversized repeated fields.
pub const MAX_RCP_PROFILES: usize = 256;

/// Maximum number of verifier policy hashes allowed in a policy resolution.
pub const MAX_VERIFIER_POLICIES: usize = 256;

/// Maximum length of any string field in a policy resolution.
/// This prevents denial-of-service attacks via oversized strings.
pub const MAX_STRING_LENGTH: usize = 4096;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// =============================================================================
// Typed Enums for Risk Tier and Determinism Class
// =============================================================================

/// Risk tier levels (0-4) for policy resolution.
///
/// The risk tier indicates the security classification of the changeset:
/// - `Tier0`: Lowest risk, minimal review required
/// - `Tier1`: Low risk
/// - `Tier2`: Medium risk
/// - `Tier3`: High risk
/// - `Tier4`: Highest risk, maximum review required
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum RiskTier {
    /// Tier 0: Lowest risk level.
    Tier0 = 0,
    /// Tier 1: Low risk level.
    Tier1 = 1,
    /// Tier 2: Medium risk level.
    Tier2 = 2,
    /// Tier 3: High risk level.
    Tier3 = 3,
    /// Tier 4: Highest risk level.
    Tier4 = 4,
}

impl TryFrom<u8> for RiskTier {
    type Error = PolicyResolutionError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Tier0),
            1 => Ok(Self::Tier1),
            2 => Ok(Self::Tier2),
            3 => Ok(Self::Tier3),
            4 => Ok(Self::Tier4),
            _ => Err(PolicyResolutionError::InvalidData(format!(
                "invalid risk tier {value}, must be 0-4"
            ))),
        }
    }
}

impl From<RiskTier> for u8 {
    fn from(tier: RiskTier) -> Self {
        tier as Self
    }
}

/// Determinism class for policy resolution.
///
/// The determinism class indicates the reproducibility requirements:
/// - `NonDeterministic`: No reproducibility guarantees
/// - `SoftDeterministic`: Best-effort reproducibility
/// - `FullyDeterministic`: Strict reproducibility required
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum DeterminismClass {
    /// Non-deterministic: No reproducibility guarantees.
    NonDeterministic   = 0,
    /// Soft-deterministic: Best-effort reproducibility.
    SoftDeterministic  = 1,
    /// Fully deterministic: Strict reproducibility required.
    FullyDeterministic = 2,
}

impl TryFrom<u8> for DeterminismClass {
    type Error = PolicyResolutionError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::NonDeterministic),
            1 => Ok(Self::SoftDeterministic),
            2 => Ok(Self::FullyDeterministic),
            _ => Err(PolicyResolutionError::InvalidData(format!(
                "invalid determinism class {value}, must be 0-2"
            ))),
        }
    }
}

impl From<DeterminismClass> for u8 {
    fn from(class: DeterminismClass) -> Self {
        class as Self
    }
}

use super::domain_separator::{POLICY_RESOLVED_PREFIX, sign_with_domain, verify_with_domain};
use super::lease::GateLease;
use crate::crypto::{Signature, VerifyingKey};

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during policy resolution operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PolicyResolutionError {
    /// The resolution signature is invalid.
    #[error("invalid resolution signature: {0}")]
    InvalidSignature(String),

    /// Missing required field.
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// Invalid resolution data.
    #[error("invalid resolution data: {0}")]
    InvalidData(String),

    /// Policy hash mismatch between resolution and lease.
    #[error("policy hash mismatch: resolution={resolution_hash}, lease={lease_hash}")]
    PolicyHashMismatch {
        /// Hash from the policy resolution.
        resolution_hash: String,
        /// Hash from the lease.
        lease_hash: String,
    },

    /// Work ID mismatch between resolution and lease.
    #[error("work ID mismatch: resolution={resolution_work_id}, lease={lease_work_id}")]
    WorkIdMismatch {
        /// Work ID from the policy resolution.
        resolution_work_id: String,
        /// Work ID from the lease.
        lease_work_id: String,
    },

    /// Changeset digest mismatch between resolution and lease.
    #[error("changeset digest mismatch")]
    ChangesetDigestMismatch,

    /// Receipt policy hash does not match resolution.
    #[error("receipt policy hash mismatch: expected={expected}, actual={actual}")]
    ReceiptPolicyMismatch {
        /// Expected hash from policy resolution.
        expected: String,
        /// Actual hash from receipt.
        actual: String,
    },

    /// Collection size exceeds resource limit.
    #[error("collection size exceeds limit: {field} has {actual} items, max is {max}")]
    CollectionTooLarge {
        /// Name of the field that exceeded the limit.
        field: &'static str,
        /// Actual size of the collection.
        actual: usize,
        /// Maximum allowed size.
        max: usize,
    },

    /// RCP profile ID and manifest hash arrays have mismatched lengths.
    #[error(
        "rcp_profile_ids length ({profile_count}) != rcp_manifest_hashes length ({hash_count})"
    )]
    ProfileHashLengthMismatch {
        /// Number of profile IDs.
        profile_count: usize,
        /// Number of manifest hashes.
        hash_count: usize,
    },

    /// RCP manifest hash mismatch in lease AAT extension.
    #[error("lease rcp_manifest_hash does not match resolved hash for profile {profile_id}")]
    RcpManifestHashMismatch {
        /// The profile ID that was checked.
        profile_id: String,
    },

    /// AAT extension missing for AAT gate.
    #[error("aat_extension is required when gate_id contains 'aat'")]
    MissingAatExtension,

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

    /// Duplicate RCP profile ID found.
    #[error("duplicate rcp_profile_id: {profile_id}")]
    DuplicateProfileId {
        /// The duplicate profile ID.
        profile_id: String,
    },

    /// Array lengths do not match (safety check for zip truncation).
    #[error("internal error: array lengths do not match for zip operation")]
    ArrayLengthMismatch,
}

// =============================================================================
// PolicyResolvedForChangeSet
// =============================================================================

/// The anchor event that locks policy decisions for a changeset.
///
/// This event cryptographically binds the resolved policy tuple to a specific
/// changeset. All subsequent lease issuance and receipt validation must
/// reference this anchor.
///
/// # Fields (11 total)
///
/// - `work_id`: Work item this policy resolution applies to
/// - `changeset_digest`: Hash binding to specific changeset
/// - `resolved_policy_hash`: Hash of the resolved policy tuple
/// - `resolved_risk_tier`: Resolved risk tier (0-4)
/// - `resolved_determinism_class`: Resolved determinism class (0=non, 1=soft,
///   2=fully)
/// - `resolved_rcp_profile_ids`: Resolved RCP profile IDs
/// - `resolved_rcp_manifest_hashes`: Hashes of resolved RCP manifests
/// - `resolved_verifier_policy_hashes`: Hashes of resolved verifier policies
/// - `resolver_actor_id`: Actor who performed the policy resolution
/// - `resolver_version`: Version of the resolver component
/// - `resolver_signature`: Ed25519 signature with domain separation
///
/// # Security
///
/// The signature uses the `POLICY_RESOLVED_FOR_CHANGESET:` domain prefix to
/// prevent cross-protocol signature replay attacks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyResolvedForChangeSet {
    /// Work item this policy resolution applies to.
    pub work_id: String,

    /// Hash binding to specific changeset.
    #[serde(with = "serde_bytes")]
    pub changeset_digest: [u8; 32],

    /// Hash of the resolved policy tuple.
    ///
    /// Computed from: `risk_tier || determinism_class ||
    /// sorted(rcp_profile_ids) || sorted(rcp_manifest_hashes) ||
    /// sorted(verifier_policy_hashes)`
    #[serde(with = "serde_bytes")]
    resolved_policy_hash: [u8; 32],

    /// Resolved risk tier (0-4).
    pub resolved_risk_tier: u8,

    /// Resolved determinism class (0=non, 1=soft, 2=fully).
    pub resolved_determinism_class: u8,

    /// Resolved RCP profile IDs (sorted for canonical encoding).
    pub resolved_rcp_profile_ids: Vec<String>,

    /// Hashes of resolved RCP manifests (sorted for canonical encoding).
    #[serde(with = "vec_hash_serde")]
    pub resolved_rcp_manifest_hashes: Vec<[u8; 32]>,

    /// Hashes of resolved verifier policies (sorted for canonical encoding).
    #[serde(with = "vec_hash_serde")]
    pub resolved_verifier_policy_hashes: Vec<[u8; 32]>,

    /// Actor who performed the policy resolution.
    pub resolver_actor_id: String,

    /// Version of the resolver component.
    pub resolver_version: String,

    /// Ed25519 signature over canonical bytes with domain separation.
    #[serde(with = "serde_bytes")]
    pub resolver_signature: [u8; 64],
}

/// Custom serde for Vec<[u8; 32]> (serde doesn't support arrays > 32 in Vec).
mod vec_hash_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(hashes: &[[u8; 32]], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let vec_of_vecs: Vec<&[u8]> = hashes.iter().map(<[u8; 32]>::as_slice).collect();
        vec_of_vecs.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec_of_vecs = Vec::<Vec<u8>>::deserialize(deserializer)?;
        vec_of_vecs
            .into_iter()
            .map(|v| {
                if v.len() != 32 {
                    return Err(serde::de::Error::custom(format!(
                        "expected 32 bytes, got {}",
                        v.len()
                    )));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&v);
                Ok(arr)
            })
            .collect()
    }
}

impl PolicyResolvedForChangeSet {
    /// Returns the resolved policy hash.
    #[must_use]
    pub const fn resolved_policy_hash(&self) -> [u8; 32] {
        self.resolved_policy_hash
    }

    /// Computes the policy hash from the resolved fields.
    ///
    /// The hash is computed over:
    /// `risk_tier || determinism_class || sorted_pairs(rcp_profile_ids,
    /// rcp_manifest_hashes) ||  sorted(verifier_policy_hashes)`
    ///
    /// # Encoding
    ///
    /// Uses length-prefixed encoding (4-byte big-endian u32) for
    /// variable-length strings to prevent canonicalization collision
    /// attacks.
    ///
    /// # Panics
    ///
    /// Panics if `rcp_profile_ids.len() != rcp_manifest_hashes.len()`.
    /// Callers must ensure this invariant is upheld.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // Collection sizes are validated by MAX_RCP_PROFILES
    fn compute_policy_hash(
        risk_tier: u8,
        determinism_class: u8,
        rcp_profile_ids: &[String],
        rcp_manifest_hashes: &[[u8; 32]],
        verifier_policy_hashes: &[[u8; 32]],
    ) -> [u8; 32] {
        // Safety: panic if lengths don't match to prevent zip truncation
        assert_eq!(
            rcp_profile_ids.len(),
            rcp_manifest_hashes.len(),
            "BUG: rcp_profile_ids and rcp_manifest_hashes must have equal lengths"
        );

        let mut hasher = blake3::Hasher::new();

        // Risk tier and determinism class
        hasher.update(&[risk_tier, determinism_class]);

        // Zip, sort by profile ID, then encode pairs together to maintain alignment
        let mut pairs: Vec<(&String, &[u8; 32])> = rcp_profile_ids
            .iter()
            .zip(rcp_manifest_hashes.iter())
            .collect();
        pairs.sort_by(|a, b| a.0.cmp(b.0));

        // Write number of pairs as u32
        hasher.update(&(pairs.len() as u32).to_be_bytes());
        for (id, hash) in &pairs {
            // Length-prefixed encoding for profile ID
            hasher.update(&(id.len() as u32).to_be_bytes());
            hasher.update(id.as_bytes());
            // Fixed-length hash (no length prefix needed)
            hasher.update(*hash);
        }
        hasher.update(&[0xFF]); // section separator

        // Sorted verifier policy hashes
        let mut sorted_verifiers = verifier_policy_hashes.to_vec();
        sorted_verifiers.sort_unstable();
        // Write number of verifier hashes
        hasher.update(&(sorted_verifiers.len() as u32).to_be_bytes());
        for hash in &sorted_verifiers {
            hasher.update(hash);
        }

        *hasher.finalize().as_bytes()
    }

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
    ///
    /// # Panics
    ///
    /// Panics if `resolved_rcp_profile_ids.len() !=
    /// resolved_rcp_manifest_hashes.len()`. This invariant is enforced
    /// during construction via builder and proto conversion.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // Collection sizes are validated by MAX_RCP_PROFILES
    pub fn canonical_bytes(&self) -> Vec<u8> {
        // Capacity includes:
        // - 4 bytes for work_id length + work_id content
        // - 32 bytes for changeset_digest
        // - 32 bytes for resolved_policy_hash
        // - 2 bytes for risk_tier + determinism_class
        // - 4 bytes for pairs count
        // - For each profile: 4 bytes length + content + 32 bytes hash
        // - 1 byte section separator
        // - 4 bytes for verifier count + 32 bytes per verifier hash
        // - 1 byte section separator
        // - 4 bytes for resolver_actor_id length + content
        // - 4 bytes for resolver_version length + content
        let capacity = 4
            + self.work_id.len()
            + 32 // changeset_digest
            + 32 // resolved_policy_hash
            + 2  // risk_tier + determinism_class
            + 4  // pairs count
            + self.resolved_rcp_profile_ids.iter().map(|s| 4 + s.len() + 32).sum::<usize>()
            + 1  // section separator
            + 4  // verifier count
            + self.resolved_verifier_policy_hashes.len() * 32
            + 1  // section separator
            + 4 + self.resolver_actor_id.len()
            + 4 + self.resolver_version.len();

        let mut bytes = Vec::with_capacity(capacity);

        // Safety: assert lengths match to prevent zip truncation
        assert_eq!(
            self.resolved_rcp_profile_ids.len(),
            self.resolved_rcp_manifest_hashes.len(),
            "BUG: rcp_profile_ids and rcp_manifest_hashes must have equal lengths"
        );

        // 1. work_id (length-prefixed)
        bytes.extend_from_slice(&(self.work_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.work_id.as_bytes());

        // 2. changeset_digest
        bytes.extend_from_slice(&self.changeset_digest);

        // 3. resolved_policy_hash
        bytes.extend_from_slice(&self.resolved_policy_hash);

        // 4. resolved_risk_tier
        bytes.push(self.resolved_risk_tier);

        // 5. resolved_determinism_class
        bytes.push(self.resolved_determinism_class);

        // 6+7. resolved_rcp_profile_ids and resolved_rcp_manifest_hashes
        // Zip, sort by profile ID, maintain alignment
        let mut pairs: Vec<(&String, &[u8; 32])> = self
            .resolved_rcp_profile_ids
            .iter()
            .zip(self.resolved_rcp_manifest_hashes.iter())
            .collect();
        pairs.sort_by(|a, b| a.0.cmp(b.0));

        // Write count of pairs
        bytes.extend_from_slice(&(pairs.len() as u32).to_be_bytes());
        for (id, hash) in &pairs {
            // Length-prefixed profile ID
            bytes.extend_from_slice(&(id.len() as u32).to_be_bytes());
            bytes.extend_from_slice(id.as_bytes());
            // Fixed-length hash
            bytes.extend_from_slice(*hash);
        }
        bytes.push(0xFF); // section separator

        // 8. resolved_verifier_policy_hashes (sorted)
        let mut sorted_verifiers = self.resolved_verifier_policy_hashes.clone();
        sorted_verifiers.sort_unstable();

        // Write count of verifier hashes
        bytes.extend_from_slice(&(sorted_verifiers.len() as u32).to_be_bytes());
        for hash in &sorted_verifiers {
            bytes.extend_from_slice(hash);
        }
        bytes.push(0xFF); // section separator

        // 9. resolver_actor_id (length-prefixed)
        bytes.extend_from_slice(&(self.resolver_actor_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.resolver_actor_id.as_bytes());

        // 10. resolver_version (length-prefixed)
        bytes.extend_from_slice(&(self.resolver_version.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.resolver_version.as_bytes());

        bytes
    }

    /// Validates the resolution signature using domain separation.
    ///
    /// # Arguments
    ///
    /// * `verifying_key` - The public key of the expected resolver
    ///
    /// # Returns
    ///
    /// `Ok(())` if the signature is valid,
    /// `Err(PolicyResolutionError::InvalidSignature)` otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyResolutionError::InvalidSignature`] if signature
    /// verification fails.
    pub fn validate_signature(
        &self,
        verifying_key: &VerifyingKey,
    ) -> Result<(), PolicyResolutionError> {
        let signature = Signature::from_bytes(&self.resolver_signature);
        let canonical = self.canonical_bytes();

        verify_with_domain(
            verifying_key,
            POLICY_RESOLVED_PREFIX,
            &canonical,
            &signature,
        )
        .map_err(|e| PolicyResolutionError::InvalidSignature(e.to_string()))
    }

    /// Looks up the manifest hash for a given RCP profile ID.
    ///
    /// # Arguments
    ///
    /// * `profile_id` - The RCP profile ID to look up
    ///
    /// # Returns
    ///
    /// `Some(&[u8; 32])` if the profile ID is found, `None` otherwise.
    #[must_use]
    pub fn get_manifest_hash_for_profile(&self, profile_id: &str) -> Option<&[u8; 32]> {
        self.resolved_rcp_profile_ids
            .iter()
            .position(|id| id == profile_id)
            .map(|idx| &self.resolved_rcp_manifest_hashes[idx])
    }

    /// Verifies that a lease's `policy_hash` matches this resolution.
    ///
    /// This is the primary mechanism for ensuring that leases operate under
    /// the locked policy configuration established by this resolution.
    ///
    /// # Arguments
    ///
    /// * `lease` - The gate lease to verify
    ///
    /// # Returns
    ///
    /// `Ok(())` if the lease matches this resolution, error otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyResolutionError::WorkIdMismatch`] if work IDs don't
    /// match. Returns [`PolicyResolutionError::ChangesetDigestMismatch`] if
    /// changeset digests don't match.
    /// Returns [`PolicyResolutionError::PolicyHashMismatch`] if policy hashes
    /// don't match.
    /// Returns [`PolicyResolutionError::MissingAatExtension`] if the `gate_id`
    /// contains "aat" (case-insensitive) but no AAT extension is provided.
    /// Returns [`PolicyResolutionError::RcpManifestHashMismatch`] if the lease
    /// has an AAT extension and its `rcp_manifest_hash` doesn't match the
    /// resolved hash for the corresponding `rcp_profile_id`.
    pub fn verify_lease_match(&self, lease: &GateLease) -> Result<(), PolicyResolutionError> {
        // Check work_id matches
        if self.work_id != lease.work_id {
            return Err(PolicyResolutionError::WorkIdMismatch {
                resolution_work_id: self.work_id.clone(),
                lease_work_id: lease.work_id.clone(),
            });
        }

        // Check changeset_digest matches using constant-time comparison (RSK-1909)
        if !bool::from(self.changeset_digest.ct_eq(&lease.changeset_digest)) {
            return Err(PolicyResolutionError::ChangesetDigestMismatch);
        }

        // Check policy_hash matches using constant-time comparison (RSK-1909)
        if !bool::from(self.resolved_policy_hash.ct_eq(&lease.policy_hash)) {
            return Err(PolicyResolutionError::PolicyHashMismatch {
                resolution_hash: hex_encode(&self.resolved_policy_hash),
                lease_hash: hex_encode(&lease.policy_hash),
            });
        }

        // Check if gate_id contains "aat" (case-insensitive) - require AAT extension
        let is_aat_gate = lease.gate_id.to_ascii_lowercase().contains("aat");
        if is_aat_gate && lease.aat_extension.is_none() {
            return Err(PolicyResolutionError::MissingAatExtension);
        }

        // If lease has an AAT extension, verify rcp_manifest_hash matches
        if let Some(ref aat_ext) = lease.aat_extension {
            if let Some(resolved_hash) = self.get_manifest_hash_for_profile(&aat_ext.rcp_profile_id)
            {
                // Use constant-time comparison for hash (RSK-1909)
                if !bool::from(aat_ext.rcp_manifest_hash.ct_eq(resolved_hash)) {
                    return Err(PolicyResolutionError::RcpManifestHashMismatch {
                        profile_id: aat_ext.rcp_profile_id.clone(),
                    });
                }
            } else {
                // Profile ID not found in resolution - this is a mismatch
                return Err(PolicyResolutionError::RcpManifestHashMismatch {
                    profile_id: aat_ext.rcp_profile_id.clone(),
                });
            }
        }

        Ok(())
    }

    /// Verifies that a receipt's policy hash matches this resolution.
    ///
    /// This provides basic anti-downgrade protection by ensuring receipts
    /// reference the locked policy configuration.
    ///
    /// # Arguments
    ///
    /// * `receipt_policy_hash` - The policy hash from a gate receipt
    ///
    /// # Returns
    ///
    /// `Ok(())` if the receipt policy hash matches, error otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyResolutionError::ReceiptPolicyMismatch`] if hashes don't
    /// match.
    pub fn verify_receipt_match(
        &self,
        receipt_policy_hash: &[u8; 32],
    ) -> Result<(), PolicyResolutionError> {
        // Use constant-time comparison for security-sensitive hash comparison
        // (RSK-1909)
        if !bool::from(self.resolved_policy_hash.ct_eq(receipt_policy_hash)) {
            return Err(PolicyResolutionError::ReceiptPolicyMismatch {
                expected: hex_encode(&self.resolved_policy_hash),
                actual: hex_encode(receipt_policy_hash),
            });
        }
        Ok(())
    }
}

/// Encodes bytes as a hex string.
fn hex_encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut acc, b| {
            use std::fmt::Write;
            let _ = write!(acc, "{b:02x}");
            acc
        })
}

// =============================================================================
// Builder
// =============================================================================

/// Builder for constructing [`PolicyResolvedForChangeSet`] instances.
#[derive(Debug, Default)]
pub struct PolicyResolvedForChangeSetBuilder {
    work_id: String,
    changeset_digest: [u8; 32],
    resolved_risk_tier: Option<u8>,
    resolved_determinism_class: Option<u8>,
    resolved_rcp_profile_ids: Vec<String>,
    resolved_rcp_manifest_hashes: Vec<[u8; 32]>,
    resolved_verifier_policy_hashes: Vec<[u8; 32]>,
    resolver_actor_id: Option<String>,
    resolver_version: Option<String>,
}

impl PolicyResolvedForChangeSetBuilder {
    /// Creates a new builder with required `work_id` and `changeset_digest`.
    #[must_use]
    pub fn new(work_id: impl Into<String>, changeset_digest: [u8; 32]) -> Self {
        Self {
            work_id: work_id.into(),
            changeset_digest,
            ..Default::default()
        }
    }

    /// Sets the resolved risk tier (0-4).
    #[must_use]
    pub const fn resolved_risk_tier(mut self, tier: u8) -> Self {
        self.resolved_risk_tier = Some(tier);
        self
    }

    /// Sets the resolved determinism class (0=non, 1=soft, 2=fully).
    #[must_use]
    pub const fn resolved_determinism_class(mut self, class: u8) -> Self {
        self.resolved_determinism_class = Some(class);
        self
    }

    /// Sets the resolved RCP profile IDs.
    #[must_use]
    pub fn resolved_rcp_profile_ids(mut self, ids: Vec<String>) -> Self {
        self.resolved_rcp_profile_ids = ids;
        self
    }

    /// Adds a single RCP profile ID.
    #[must_use]
    pub fn add_rcp_profile_id(mut self, id: impl Into<String>) -> Self {
        self.resolved_rcp_profile_ids.push(id.into());
        self
    }

    /// Sets the resolved RCP manifest hashes.
    #[must_use]
    pub fn resolved_rcp_manifest_hashes(mut self, hashes: Vec<[u8; 32]>) -> Self {
        self.resolved_rcp_manifest_hashes = hashes;
        self
    }

    /// Adds a single RCP manifest hash.
    #[must_use]
    pub fn add_rcp_manifest_hash(mut self, hash: [u8; 32]) -> Self {
        self.resolved_rcp_manifest_hashes.push(hash);
        self
    }

    /// Sets the resolved verifier policy hashes.
    #[must_use]
    pub fn resolved_verifier_policy_hashes(mut self, hashes: Vec<[u8; 32]>) -> Self {
        self.resolved_verifier_policy_hashes = hashes;
        self
    }

    /// Adds a single verifier policy hash.
    #[must_use]
    pub fn add_verifier_policy_hash(mut self, hash: [u8; 32]) -> Self {
        self.resolved_verifier_policy_hashes.push(hash);
        self
    }

    /// Sets the resolver actor ID.
    #[must_use]
    pub fn resolver_actor_id(mut self, actor_id: impl Into<String>) -> Self {
        self.resolver_actor_id = Some(actor_id.into());
        self
    }

    /// Sets the resolver version.
    #[must_use]
    pub fn resolver_version(mut self, version: impl Into<String>) -> Self {
        self.resolver_version = Some(version.into());
        self
    }

    /// Builds the resolution and signs it with the provided signer.
    ///
    /// # Panics
    ///
    /// Panics if required fields are missing.
    #[must_use]
    pub fn build_and_sign(self, signer: &crate::crypto::Signer) -> PolicyResolvedForChangeSet {
        self.try_build_and_sign(signer)
            .expect("missing required field")
    }

    /// Attempts to build and sign the resolution.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyResolutionError::MissingField`] if any required field is
    /// not set.
    /// Returns [`PolicyResolutionError::ProfileHashLengthMismatch`] if
    /// `resolved_rcp_profile_ids` and `resolved_rcp_manifest_hashes` have
    /// different lengths.
    /// Returns [`PolicyResolutionError::CollectionTooLarge`] if any collection
    /// exceeds resource limits.
    /// Returns [`PolicyResolutionError::StringTooLong`] if any string field
    /// exceeds the maximum length.
    /// Returns [`PolicyResolutionError::DuplicateProfileId`] if there are
    /// duplicate profile IDs.
    #[allow(clippy::too_many_lines)]
    pub fn try_build_and_sign(
        self,
        signer: &crate::crypto::Signer,
    ) -> Result<PolicyResolvedForChangeSet, PolicyResolutionError> {
        let resolved_risk_tier = self
            .resolved_risk_tier
            .ok_or(PolicyResolutionError::MissingField("resolved_risk_tier"))?;
        let resolved_determinism_class =
            self.resolved_determinism_class
                .ok_or(PolicyResolutionError::MissingField(
                    "resolved_determinism_class",
                ))?;
        let resolver_actor_id = self
            .resolver_actor_id
            .ok_or(PolicyResolutionError::MissingField("resolver_actor_id"))?;
        let resolver_version = self
            .resolver_version
            .ok_or(PolicyResolutionError::MissingField("resolver_version"))?;

        // Validate length alignment between profile IDs and manifest hashes
        if self.resolved_rcp_profile_ids.len() != self.resolved_rcp_manifest_hashes.len() {
            return Err(PolicyResolutionError::ProfileHashLengthMismatch {
                profile_count: self.resolved_rcp_profile_ids.len(),
                hash_count: self.resolved_rcp_manifest_hashes.len(),
            });
        }

        // Validate resource limits
        if self.resolved_rcp_profile_ids.len() > MAX_RCP_PROFILES {
            return Err(PolicyResolutionError::CollectionTooLarge {
                field: "resolved_rcp_profile_ids",
                actual: self.resolved_rcp_profile_ids.len(),
                max: MAX_RCP_PROFILES,
            });
        }
        if self.resolved_verifier_policy_hashes.len() > MAX_VERIFIER_POLICIES {
            return Err(PolicyResolutionError::CollectionTooLarge {
                field: "resolved_verifier_policy_hashes",
                actual: self.resolved_verifier_policy_hashes.len(),
                max: MAX_VERIFIER_POLICIES,
            });
        }

        // Validate string lengths
        if self.work_id.len() > MAX_STRING_LENGTH {
            return Err(PolicyResolutionError::StringTooLong {
                field: "work_id",
                actual: self.work_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if resolver_actor_id.len() > MAX_STRING_LENGTH {
            return Err(PolicyResolutionError::StringTooLong {
                field: "resolver_actor_id",
                actual: resolver_actor_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if resolver_version.len() > MAX_STRING_LENGTH {
            return Err(PolicyResolutionError::StringTooLong {
                field: "resolver_version",
                actual: resolver_version.len(),
                max: MAX_STRING_LENGTH,
            });
        }

        // Check for duplicate profile IDs
        for (i, id) in self.resolved_rcp_profile_ids.iter().enumerate() {
            if id.len() > MAX_STRING_LENGTH {
                return Err(PolicyResolutionError::StringTooLong {
                    field: "resolved_rcp_profile_ids",
                    actual: id.len(),
                    max: MAX_STRING_LENGTH,
                });
            }
            for (j, other_id) in self.resolved_rcp_profile_ids.iter().enumerate() {
                if i != j && id == other_id {
                    return Err(PolicyResolutionError::DuplicateProfileId {
                        profile_id: id.clone(),
                    });
                }
            }
        }

        // Zip profile IDs with manifest hashes, sort by ID, then unzip
        // This maintains alignment between IDs and their corresponding hashes
        let mut pairs: Vec<(String, [u8; 32])> = self
            .resolved_rcp_profile_ids
            .into_iter()
            .zip(self.resolved_rcp_manifest_hashes)
            .collect();
        pairs.sort_by(|a, b| a.0.cmp(&b.0));
        let (resolved_rcp_profile_ids, resolved_rcp_manifest_hashes): (Vec<_>, Vec<_>) =
            pairs.into_iter().unzip();

        // Sort verifier policy hashes independently (they're not paired)
        let mut resolved_verifier_policy_hashes = self.resolved_verifier_policy_hashes;
        resolved_verifier_policy_hashes.sort_unstable();

        // Compute the policy hash
        let resolved_policy_hash = PolicyResolvedForChangeSet::compute_policy_hash(
            resolved_risk_tier,
            resolved_determinism_class,
            &resolved_rcp_profile_ids,
            &resolved_rcp_manifest_hashes,
            &resolved_verifier_policy_hashes,
        );

        // Create resolution with placeholder signature
        let mut resolution = PolicyResolvedForChangeSet {
            work_id: self.work_id,
            changeset_digest: self.changeset_digest,
            resolved_policy_hash,
            resolved_risk_tier,
            resolved_determinism_class,
            resolved_rcp_profile_ids,
            resolved_rcp_manifest_hashes,
            resolved_verifier_policy_hashes,
            resolver_actor_id,
            resolver_version,
            resolver_signature: [0u8; 64],
        };

        // Sign the canonical bytes
        let canonical = resolution.canonical_bytes();
        let signature = sign_with_domain(signer, POLICY_RESOLVED_PREFIX, &canonical);
        resolution.resolver_signature = signature.to_bytes();

        Ok(resolution)
    }
}

// =============================================================================
// Proto Message Conversion
// =============================================================================

impl TryFrom<PolicyResolvedForChangeSetProto> for PolicyResolvedForChangeSet {
    type Error = PolicyResolutionError;

    #[allow(clippy::too_many_lines)]
    fn try_from(proto: PolicyResolvedForChangeSetProto) -> Result<Self, Self::Error> {
        // Validate resource limits on repeated fields FIRST to prevent DoS
        if proto.resolved_rcp_profile_ids.len() > MAX_RCP_PROFILES {
            return Err(PolicyResolutionError::CollectionTooLarge {
                field: "resolved_rcp_profile_ids",
                actual: proto.resolved_rcp_profile_ids.len(),
                max: MAX_RCP_PROFILES,
            });
        }
        if proto.resolved_rcp_manifest_hashes.len() > MAX_RCP_PROFILES {
            return Err(PolicyResolutionError::CollectionTooLarge {
                field: "resolved_rcp_manifest_hashes",
                actual: proto.resolved_rcp_manifest_hashes.len(),
                max: MAX_RCP_PROFILES,
            });
        }
        if proto.resolved_verifier_policy_hashes.len() > MAX_VERIFIER_POLICIES {
            return Err(PolicyResolutionError::CollectionTooLarge {
                field: "resolved_verifier_policy_hashes",
                actual: proto.resolved_verifier_policy_hashes.len(),
                max: MAX_VERIFIER_POLICIES,
            });
        }

        // Validate length alignment between profile IDs and manifest hashes
        if proto.resolved_rcp_profile_ids.len() != proto.resolved_rcp_manifest_hashes.len() {
            return Err(PolicyResolutionError::ProfileHashLengthMismatch {
                profile_count: proto.resolved_rcp_profile_ids.len(),
                hash_count: proto.resolved_rcp_manifest_hashes.len(),
            });
        }

        // Validate string lengths to prevent DoS
        if proto.work_id.len() > MAX_STRING_LENGTH {
            return Err(PolicyResolutionError::StringTooLong {
                field: "work_id",
                actual: proto.work_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if proto.resolver_actor_id.len() > MAX_STRING_LENGTH {
            return Err(PolicyResolutionError::StringTooLong {
                field: "resolver_actor_id",
                actual: proto.resolver_actor_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if proto.resolver_version.len() > MAX_STRING_LENGTH {
            return Err(PolicyResolutionError::StringTooLong {
                field: "resolver_version",
                actual: proto.resolver_version.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        for (i, id) in proto.resolved_rcp_profile_ids.iter().enumerate() {
            if id.len() > MAX_STRING_LENGTH {
                return Err(PolicyResolutionError::StringTooLong {
                    field: "resolved_rcp_profile_ids",
                    actual: id.len(),
                    max: MAX_STRING_LENGTH,
                });
            }
            // Check for duplicates (O(n^2) but n is bounded by MAX_RCP_PROFILES=256)
            for (j, other_id) in proto.resolved_rcp_profile_ids.iter().enumerate() {
                if i != j && id == other_id {
                    return Err(PolicyResolutionError::DuplicateProfileId {
                        profile_id: id.clone(),
                    });
                }
            }
        }

        let changeset_digest: [u8; 32] = proto.changeset_digest.try_into().map_err(|_| {
            PolicyResolutionError::InvalidData("changeset_digest must be 32 bytes".to_string())
        })?;

        let resolved_policy_hash: [u8; 32] =
            proto.resolved_policy_hash.try_into().map_err(|_| {
                PolicyResolutionError::InvalidData(
                    "resolved_policy_hash must be 32 bytes".to_string(),
                )
            })?;

        let resolver_signature: [u8; 64] = proto.resolver_signature.try_into().map_err(|_| {
            PolicyResolutionError::InvalidData("resolver_signature must be 64 bytes".to_string())
        })?;

        // Validate risk tier (0-4)
        let resolved_risk_tier = u8::try_from(proto.resolved_risk_tier).map_err(|_| {
            PolicyResolutionError::InvalidData("resolved_risk_tier must fit in u8".to_string())
        })?;
        if resolved_risk_tier > 4 {
            return Err(PolicyResolutionError::InvalidData(
                "resolved_risk_tier must be 0-4".to_string(),
            ));
        }

        // Validate determinism class (0-2)
        let resolved_determinism_class =
            u8::try_from(proto.resolved_determinism_class).map_err(|_| {
                PolicyResolutionError::InvalidData(
                    "resolved_determinism_class must fit in u8".to_string(),
                )
            })?;
        if resolved_determinism_class > 2 {
            return Err(PolicyResolutionError::InvalidData(
                "resolved_determinism_class must be 0-2".to_string(),
            ));
        }

        // Convert manifest hashes
        let resolved_rcp_manifest_hashes: Vec<[u8; 32]> = proto
            .resolved_rcp_manifest_hashes
            .into_iter()
            .map(|h| {
                h.try_into().map_err(|_| {
                    PolicyResolutionError::InvalidData(
                        "rcp_manifest_hash must be 32 bytes".to_string(),
                    )
                })
            })
            .collect::<Result<_, _>>()?;

        // Convert verifier hashes
        let resolved_verifier_policy_hashes: Vec<[u8; 32]> = proto
            .resolved_verifier_policy_hashes
            .into_iter()
            .map(|h| {
                h.try_into().map_err(|_| {
                    PolicyResolutionError::InvalidData(
                        "verifier_policy_hash must be 32 bytes".to_string(),
                    )
                })
            })
            .collect::<Result<_, _>>()?;

        // Sort arrays for canonical representation
        // Zip profile IDs with manifest hashes, sort by ID, then unzip
        let mut pairs: Vec<(String, [u8; 32])> = proto
            .resolved_rcp_profile_ids
            .into_iter()
            .zip(resolved_rcp_manifest_hashes)
            .collect();
        pairs.sort_by(|a, b| a.0.cmp(&b.0));
        let (resolved_rcp_profile_ids, resolved_rcp_manifest_hashes): (Vec<_>, Vec<_>) =
            pairs.into_iter().unzip();

        // Sort verifier policy hashes
        let mut resolved_verifier_policy_hashes = resolved_verifier_policy_hashes;
        resolved_verifier_policy_hashes.sort_unstable();

        // CRITICAL: Verify resolved_policy_hash matches computed hash
        // This prevents a compromised resolver from binding leases to a different
        // policy than what the audit fields indicate
        let computed_hash = Self::compute_policy_hash(
            resolved_risk_tier,
            resolved_determinism_class,
            &resolved_rcp_profile_ids,
            &resolved_rcp_manifest_hashes,
            &resolved_verifier_policy_hashes,
        );
        if computed_hash != resolved_policy_hash {
            return Err(PolicyResolutionError::InvalidData(
                "resolved_policy_hash does not match computed hash from fields".to_string(),
            ));
        }

        Ok(Self {
            work_id: proto.work_id,
            changeset_digest,
            resolved_policy_hash,
            resolved_risk_tier,
            resolved_determinism_class,
            resolved_rcp_profile_ids,
            resolved_rcp_manifest_hashes,
            resolved_verifier_policy_hashes,
            resolver_actor_id: proto.resolver_actor_id,
            resolver_version: proto.resolver_version,
            resolver_signature,
        })
    }
}

impl From<PolicyResolvedForChangeSet> for PolicyResolvedForChangeSetProto {
    fn from(resolution: PolicyResolvedForChangeSet) -> Self {
        Self {
            work_id: resolution.work_id,
            changeset_digest: resolution.changeset_digest.to_vec(),
            resolved_policy_hash: resolution.resolved_policy_hash.to_vec(),
            resolved_risk_tier: u32::from(resolution.resolved_risk_tier),
            resolved_determinism_class: u32::from(resolution.resolved_determinism_class),
            resolved_rcp_profile_ids: resolution.resolved_rcp_profile_ids,
            resolved_rcp_manifest_hashes: resolution
                .resolved_rcp_manifest_hashes
                .into_iter()
                .map(|h| h.to_vec())
                .collect(),
            resolved_verifier_policy_hashes: resolution
                .resolved_verifier_policy_hashes
                .into_iter()
                .map(|h| h.to_vec())
                .collect(),
            resolver_actor_id: resolution.resolver_actor_id,
            resolver_version: resolution.resolver_version,
            resolver_signature: resolution.resolver_signature.to_vec(),
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
pub mod tests {
    use prost::Message;

    use super::*;
    use crate::crypto::Signer;
    use crate::fac::{GateLeaseBuilder, LeaseError};

    fn create_test_resolution(signer: &Signer) -> PolicyResolvedForChangeSet {
        PolicyResolvedForChangeSetBuilder::new("work-001", [0x42; 32])
            .resolved_risk_tier(1)
            .resolved_determinism_class(0)
            .add_rcp_profile_id("rcp-profile-001")
            .add_rcp_manifest_hash([0x11; 32])
            .add_verifier_policy_hash([0x22; 32])
            .resolver_actor_id("resolver-001")
            .resolver_version("1.0.0")
            .build_and_sign(signer)
    }

    #[test]
    fn test_build_and_sign() {
        let signer = Signer::generate();
        let resolution = create_test_resolution(&signer);

        assert_eq!(resolution.work_id, "work-001");
        assert_eq!(resolution.changeset_digest, [0x42; 32]);
        assert_eq!(resolution.resolved_risk_tier, 1);
        assert_eq!(resolution.resolved_determinism_class, 0);
        assert_eq!(
            resolution.resolved_rcp_profile_ids,
            vec!["rcp-profile-001".to_string()]
        );
        assert_eq!(resolution.resolved_rcp_manifest_hashes, vec![[0x11; 32]]);
        assert_eq!(resolution.resolved_verifier_policy_hashes, vec![[0x22; 32]]);
        assert_eq!(resolution.resolver_actor_id, "resolver-001");
        assert_eq!(resolution.resolver_version, "1.0.0");
    }

    #[test]
    fn test_signature_validation() {
        let signer = Signer::generate();
        let resolution = create_test_resolution(&signer);

        // Valid signature
        assert!(
            resolution
                .validate_signature(&signer.verifying_key())
                .is_ok()
        );

        // Wrong key should fail
        let other_signer = Signer::generate();
        assert!(
            resolution
                .validate_signature(&other_signer.verifying_key())
                .is_err()
        );
    }

    #[test]
    fn test_signature_binds_to_content() {
        let signer = Signer::generate();
        let mut resolution = create_test_resolution(&signer);

        // Modify content after signing
        resolution.work_id = "work-002".to_string();

        // Signature should now be invalid
        assert!(
            resolution
                .validate_signature(&signer.verifying_key())
                .is_err()
        );
    }

    #[test]
    fn test_canonical_bytes_deterministic() {
        let signer = Signer::generate();
        let resolution1 = create_test_resolution(&signer);
        let resolution2 = create_test_resolution(&signer);

        // Same content should produce same canonical bytes
        assert_eq!(resolution1.canonical_bytes(), resolution2.canonical_bytes());
    }

    #[test]
    fn test_policy_hash_deterministic() {
        let signer = Signer::generate();
        let resolution1 = create_test_resolution(&signer);
        let resolution2 = create_test_resolution(&signer);

        // Same inputs should produce same policy hash
        assert_eq!(
            resolution1.resolved_policy_hash(),
            resolution2.resolved_policy_hash()
        );
    }

    #[test]
    fn test_policy_hash_differs_with_different_inputs() {
        let signer = Signer::generate();

        let resolution1 = PolicyResolvedForChangeSetBuilder::new("work-001", [0x42; 32])
            .resolved_risk_tier(1)
            .resolved_determinism_class(0)
            .resolver_actor_id("resolver-001")
            .resolver_version("1.0.0")
            .build_and_sign(&signer);

        let resolution2 = PolicyResolvedForChangeSetBuilder::new("work-001", [0x42; 32])
            .resolved_risk_tier(2) // Different risk tier
            .resolved_determinism_class(0)
            .resolver_actor_id("resolver-001")
            .resolver_version("1.0.0")
            .build_and_sign(&signer);

        // Different risk tier should produce different policy hash
        assert_ne!(
            resolution1.resolved_policy_hash(),
            resolution2.resolved_policy_hash()
        );
    }

    #[test]
    fn test_verify_lease_match_success() {
        let resolver_signer = Signer::generate();
        let resolution = create_test_resolution(&resolver_signer);

        // Create a matching lease
        let issuer_signer = Signer::generate();
        let lease = GateLeaseBuilder::new("lease-001", "work-001", "gate-build")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .issued_at(1_704_067_200_000)
            .expires_at(1_704_070_800_000)
            .policy_hash(resolution.resolved_policy_hash())
            .issuer_actor_id("issuer-001")
            .time_envelope_ref("htf:tick:12345")
            .build_and_sign(&issuer_signer);

        // Should match
        assert!(resolution.verify_lease_match(&lease).is_ok());
    }

    #[test]
    fn test_verify_lease_match_work_id_mismatch() {
        let resolver_signer = Signer::generate();
        let resolution = create_test_resolution(&resolver_signer);

        let issuer_signer = Signer::generate();
        let lease = GateLeaseBuilder::new("lease-001", "work-002", "gate-build") // Different work_id
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .issued_at(1_704_067_200_000)
            .expires_at(1_704_070_800_000)
            .policy_hash(resolution.resolved_policy_hash())
            .issuer_actor_id("issuer-001")
            .time_envelope_ref("htf:tick:12345")
            .build_and_sign(&issuer_signer);

        let result = resolution.verify_lease_match(&lease);
        assert!(matches!(
            result,
            Err(PolicyResolutionError::WorkIdMismatch { .. })
        ));
    }

    #[test]
    fn test_verify_lease_match_changeset_mismatch() {
        let resolver_signer = Signer::generate();
        let resolution = create_test_resolution(&resolver_signer);

        let issuer_signer = Signer::generate();
        let lease = GateLeaseBuilder::new("lease-001", "work-001", "gate-build")
            .changeset_digest([0x99; 32]) // Different changeset
            .executor_actor_id("executor-001")
            .issued_at(1_704_067_200_000)
            .expires_at(1_704_070_800_000)
            .policy_hash(resolution.resolved_policy_hash())
            .issuer_actor_id("issuer-001")
            .time_envelope_ref("htf:tick:12345")
            .build_and_sign(&issuer_signer);

        let result = resolution.verify_lease_match(&lease);
        assert!(matches!(
            result,
            Err(PolicyResolutionError::ChangesetDigestMismatch)
        ));
    }

    #[test]
    fn test_verify_lease_match_policy_hash_mismatch() {
        let resolver_signer = Signer::generate();
        let resolution = create_test_resolution(&resolver_signer);

        let issuer_signer = Signer::generate();
        let lease = GateLeaseBuilder::new("lease-001", "work-001", "gate-build")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .issued_at(1_704_067_200_000)
            .expires_at(1_704_070_800_000)
            .policy_hash([0xAB; 32]) // Different policy hash
            .issuer_actor_id("issuer-001")
            .time_envelope_ref("htf:tick:12345")
            .build_and_sign(&issuer_signer);

        let result = resolution.verify_lease_match(&lease);
        assert!(matches!(
            result,
            Err(PolicyResolutionError::PolicyHashMismatch { .. })
        ));
    }

    #[test]
    fn test_verify_receipt_match_success() {
        let signer = Signer::generate();
        let resolution = create_test_resolution(&signer);

        // Matching receipt policy hash
        assert!(
            resolution
                .verify_receipt_match(&resolution.resolved_policy_hash())
                .is_ok()
        );
    }

    #[test]
    fn test_verify_receipt_match_failure() {
        let signer = Signer::generate();
        let resolution = create_test_resolution(&signer);

        // Non-matching receipt policy hash
        let wrong_hash = [0xAB; 32];
        let result = resolution.verify_receipt_match(&wrong_hash);
        assert!(matches!(
            result,
            Err(PolicyResolutionError::ReceiptPolicyMismatch { .. })
        ));
    }

    #[test]
    fn test_proto_roundtrip() {
        let signer = Signer::generate();
        let original = create_test_resolution(&signer);

        // Convert to proto
        let proto: PolicyResolvedForChangeSetProto = original.clone().into();

        // Encode and decode
        let encoded = proto.encode_to_vec();
        let decoded_proto = PolicyResolvedForChangeSetProto::decode(encoded.as_slice()).unwrap();

        // Convert back to domain type
        let recovered = PolicyResolvedForChangeSet::try_from(decoded_proto).unwrap();

        // Fields should match
        assert_eq!(original.work_id, recovered.work_id);
        assert_eq!(original.changeset_digest, recovered.changeset_digest);
        assert_eq!(
            original.resolved_policy_hash,
            recovered.resolved_policy_hash
        );
        assert_eq!(original.resolved_risk_tier, recovered.resolved_risk_tier);
        assert_eq!(
            original.resolved_determinism_class,
            recovered.resolved_determinism_class
        );
        assert_eq!(
            original.resolved_rcp_profile_ids,
            recovered.resolved_rcp_profile_ids
        );
        assert_eq!(
            original.resolved_rcp_manifest_hashes,
            recovered.resolved_rcp_manifest_hashes
        );
        assert_eq!(
            original.resolved_verifier_policy_hashes,
            recovered.resolved_verifier_policy_hashes
        );
        assert_eq!(original.resolver_actor_id, recovered.resolver_actor_id);
        assert_eq!(original.resolver_version, recovered.resolver_version);
        assert_eq!(original.resolver_signature, recovered.resolver_signature);

        // Signature should still be valid
        assert!(
            recovered
                .validate_signature(&signer.verifying_key())
                .is_ok()
        );
    }

    #[test]
    fn test_invalid_proto_risk_tier() {
        let proto = PolicyResolvedForChangeSetProto {
            work_id: "work-001".to_string(),
            changeset_digest: vec![0x42; 32],
            resolved_policy_hash: vec![0x00; 32],
            resolved_risk_tier: 5, // Invalid: must be 0-4
            resolved_determinism_class: 0,
            resolved_rcp_profile_ids: vec![],
            resolved_rcp_manifest_hashes: vec![],
            resolved_verifier_policy_hashes: vec![],
            resolver_actor_id: "resolver-001".to_string(),
            resolver_version: "1.0.0".to_string(),
            resolver_signature: vec![0u8; 64],
        };

        let result = PolicyResolvedForChangeSet::try_from(proto);
        assert!(matches!(result, Err(PolicyResolutionError::InvalidData(_))));
    }

    #[test]
    fn test_invalid_proto_determinism_class() {
        let proto = PolicyResolvedForChangeSetProto {
            work_id: "work-001".to_string(),
            changeset_digest: vec![0x42; 32],
            resolved_policy_hash: vec![0x00; 32],
            resolved_risk_tier: 0,
            resolved_determinism_class: 3, // Invalid: must be 0-2
            resolved_rcp_profile_ids: vec![],
            resolved_rcp_manifest_hashes: vec![],
            resolved_verifier_policy_hashes: vec![],
            resolver_actor_id: "resolver-001".to_string(),
            resolver_version: "1.0.0".to_string(),
            resolver_signature: vec![0u8; 64],
        };

        let result = PolicyResolvedForChangeSet::try_from(proto);
        assert!(matches!(result, Err(PolicyResolutionError::InvalidData(_))));
    }

    #[test]
    fn test_invalid_proto_signature_length() {
        let proto = PolicyResolvedForChangeSetProto {
            work_id: "work-001".to_string(),
            changeset_digest: vec![0x42; 32],
            resolved_policy_hash: vec![0x00; 32],
            resolved_risk_tier: 0,
            resolved_determinism_class: 0,
            resolved_rcp_profile_ids: vec![],
            resolved_rcp_manifest_hashes: vec![],
            resolved_verifier_policy_hashes: vec![],
            resolver_actor_id: "resolver-001".to_string(),
            resolver_version: "1.0.0".to_string(),
            resolver_signature: vec![0u8; 32], // Wrong length - should be 64
        };

        let result = PolicyResolvedForChangeSet::try_from(proto);
        assert!(matches!(result, Err(PolicyResolutionError::InvalidData(_))));
    }

    #[test]
    fn test_missing_field_error() {
        let signer = Signer::generate();

        // Missing resolved_risk_tier
        let result = PolicyResolvedForChangeSetBuilder::new("work-001", [0x42; 32])
            .resolved_determinism_class(0)
            .resolver_actor_id("resolver-001")
            .resolver_version("1.0.0")
            .try_build_and_sign(&signer);

        assert!(matches!(
            result,
            Err(PolicyResolutionError::MissingField("resolved_risk_tier"))
        ));
    }

    #[test]
    fn test_domain_separator_prevents_replay() {
        // Verify that resolution uses POLICY_RESOLVED_FOR_CHANGESET: domain separator
        // by ensuring a signature created with a different prefix fails
        let signer = Signer::generate();
        let resolution = create_test_resolution(&signer);

        // Create a signature with the wrong domain prefix
        let canonical = resolution.canonical_bytes();
        let wrong_signature = super::super::domain_separator::sign_with_domain(
            &signer,
            super::super::domain_separator::GATE_LEASE_ISSUED_PREFIX,
            &canonical,
        );

        // Verification should fail because domains don't match
        let result = super::super::domain_separator::verify_with_domain(
            &signer.verifying_key(),
            super::super::domain_separator::POLICY_RESOLVED_PREFIX,
            &canonical,
            &wrong_signature,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_sorted_arrays_for_canonical_encoding() {
        let signer = Signer::generate();

        // Create with unsorted arrays
        // Profile IDs and manifest hashes are sorted together as pairs (by profile ID)
        // Input:  z-profile -> 0x99, a-profile -> 0x11, m-profile -> 0x55
        // Output: a-profile -> 0x11, m-profile -> 0x55, z-profile -> 0x99
        let resolution = PolicyResolvedForChangeSetBuilder::new("work-001", [0x42; 32])
            .resolved_risk_tier(1)
            .resolved_determinism_class(0)
            .resolved_rcp_profile_ids(vec![
                "z-profile".to_string(),
                "a-profile".to_string(),
                "m-profile".to_string(),
            ])
            .resolved_rcp_manifest_hashes(vec![[0x99; 32], [0x11; 32], [0x55; 32]])
            .resolved_verifier_policy_hashes(vec![[0xCC; 32], [0xAA; 32], [0xBB; 32]])
            .resolver_actor_id("resolver-001")
            .resolver_version("1.0.0")
            .build_and_sign(&signer);

        // Profile IDs should be sorted alphabetically
        assert_eq!(
            resolution.resolved_rcp_profile_ids,
            vec![
                "a-profile".to_string(),
                "m-profile".to_string(),
                "z-profile".to_string()
            ]
        );
        // Manifest hashes should follow the same order as their corresponding profile
        // IDs (pairs sorted by profile ID, maintaining alignment)
        assert_eq!(
            resolution.resolved_rcp_manifest_hashes,
            vec![[0x11; 32], [0x55; 32], [0x99; 32]]
        );
        // Verifier policy hashes are sorted independently (not paired with anything)
        assert_eq!(
            resolution.resolved_verifier_policy_hashes,
            vec![[0xAA; 32], [0xBB; 32], [0xCC; 32]]
        );
    }

    #[test]
    fn test_empty_arrays() {
        let signer = Signer::generate();

        // Create with empty arrays
        let resolution = PolicyResolvedForChangeSetBuilder::new("work-001", [0x42; 32])
            .resolved_risk_tier(0)
            .resolved_determinism_class(0)
            .resolver_actor_id("resolver-001")
            .resolver_version("1.0.0")
            .build_and_sign(&signer);

        assert!(resolution.resolved_rcp_profile_ids.is_empty());
        assert!(resolution.resolved_rcp_manifest_hashes.is_empty());
        assert!(resolution.resolved_verifier_policy_hashes.is_empty());

        // Signature should still be valid
        assert!(
            resolution
                .validate_signature(&signer.verifying_key())
                .is_ok()
        );
    }

    #[test]
    fn test_profile_hash_length_mismatch_error() {
        let signer = Signer::generate();

        // Mismatched lengths: 2 profile IDs but 3 manifest hashes
        let result = PolicyResolvedForChangeSetBuilder::new("work-001", [0x42; 32])
            .resolved_risk_tier(1)
            .resolved_determinism_class(0)
            .resolved_rcp_profile_ids(vec!["profile-1".to_string(), "profile-2".to_string()])
            .resolved_rcp_manifest_hashes(vec![[0x11; 32], [0x22; 32], [0x33; 32]])
            .resolver_actor_id("resolver-001")
            .resolver_version("1.0.0")
            .try_build_and_sign(&signer);

        assert!(matches!(
            result,
            Err(PolicyResolutionError::ProfileHashLengthMismatch {
                profile_count: 2,
                hash_count: 3
            })
        ));
    }

    #[test]
    fn test_collection_too_large_error() {
        let signer = Signer::generate();

        // Create 257 profile IDs and manifest hashes (exceeds MAX_RCP_PROFILES = 256)
        let profile_ids: Vec<String> = (0..257).map(|i| format!("profile-{i}")).collect();
        let manifest_hashes: Vec<[u8; 32]> = (0..257).map(|_| [0x00; 32]).collect();

        let result = PolicyResolvedForChangeSetBuilder::new("work-001", [0x42; 32])
            .resolved_risk_tier(1)
            .resolved_determinism_class(0)
            .resolved_rcp_profile_ids(profile_ids)
            .resolved_rcp_manifest_hashes(manifest_hashes)
            .resolver_actor_id("resolver-001")
            .resolver_version("1.0.0")
            .try_build_and_sign(&signer);

        assert!(matches!(
            result,
            Err(PolicyResolutionError::CollectionTooLarge {
                field: "resolved_rcp_profile_ids",
                actual: 257,
                max: 256
            })
        ));
    }

    #[test]
    fn test_proto_collection_too_large_error() {
        // Create proto with too many verifier hashes
        let mut proto = PolicyResolvedForChangeSetProto {
            work_id: "work-001".to_string(),
            changeset_digest: vec![0x42; 32],
            resolved_policy_hash: vec![0x00; 32],
            resolved_risk_tier: 0,
            resolved_determinism_class: 0,
            resolved_rcp_profile_ids: vec![],
            resolved_rcp_manifest_hashes: vec![],
            resolved_verifier_policy_hashes: vec![],
            resolver_actor_id: "resolver-001".to_string(),
            resolver_version: "1.0.0".to_string(),
            resolver_signature: vec![0u8; 64],
        };

        // Add 257 verifier hashes (exceeds MAX_VERIFIER_POLICIES = 256)
        for _ in 0..257 {
            proto.resolved_verifier_policy_hashes.push(vec![0x00; 32]);
        }

        let result = PolicyResolvedForChangeSet::try_from(proto);
        assert!(matches!(
            result,
            Err(PolicyResolutionError::CollectionTooLarge {
                field: "resolved_verifier_policy_hashes",
                actual: 257,
                max: 256
            })
        ));
    }

    #[test]
    fn test_proto_profile_hash_length_mismatch() {
        let proto = PolicyResolvedForChangeSetProto {
            work_id: "work-001".to_string(),
            changeset_digest: vec![0x42; 32],
            resolved_policy_hash: vec![0x00; 32],
            resolved_risk_tier: 0,
            resolved_determinism_class: 0,
            resolved_rcp_profile_ids: vec!["profile-1".to_string()],
            resolved_rcp_manifest_hashes: vec![vec![0x00; 32], vec![0x11; 32]], // Mismatch: 1 vs 2
            resolved_verifier_policy_hashes: vec![],
            resolver_actor_id: "resolver-001".to_string(),
            resolver_version: "1.0.0".to_string(),
            resolver_signature: vec![0u8; 64],
        };

        let result = PolicyResolvedForChangeSet::try_from(proto);
        assert!(matches!(
            result,
            Err(PolicyResolutionError::ProfileHashLengthMismatch {
                profile_count: 1,
                hash_count: 2
            })
        ));
    }

    #[test]
    fn test_get_manifest_hash_for_profile() {
        let signer = Signer::generate();
        let resolution = PolicyResolvedForChangeSetBuilder::new("work-001", [0x42; 32])
            .resolved_risk_tier(1)
            .resolved_determinism_class(0)
            .resolved_rcp_profile_ids(vec![
                "profile-a".to_string(),
                "profile-b".to_string(),
                "profile-c".to_string(),
            ])
            .resolved_rcp_manifest_hashes(vec![[0xAA; 32], [0xBB; 32], [0xCC; 32]])
            .resolver_actor_id("resolver-001")
            .resolver_version("1.0.0")
            .build_and_sign(&signer);

        // Look up existing profiles
        assert_eq!(
            resolution.get_manifest_hash_for_profile("profile-a"),
            Some(&[0xAA; 32])
        );
        assert_eq!(
            resolution.get_manifest_hash_for_profile("profile-b"),
            Some(&[0xBB; 32])
        );
        assert_eq!(
            resolution.get_manifest_hash_for_profile("profile-c"),
            Some(&[0xCC; 32])
        );

        // Non-existent profile
        assert_eq!(resolution.get_manifest_hash_for_profile("profile-d"), None);
    }

    #[test]
    fn test_verify_lease_match_with_aat_extension() {
        use crate::fac::AatLeaseExtension;

        let resolver_signer = Signer::generate();
        let resolution = PolicyResolvedForChangeSetBuilder::new("work-001", [0x42; 32])
            .resolved_risk_tier(1)
            .resolved_determinism_class(0)
            .add_rcp_profile_id("aat-profile-001")
            .add_rcp_manifest_hash([0x11; 32])
            .add_verifier_policy_hash([0x22; 32])
            .resolver_actor_id("resolver-001")
            .resolver_version("1.0.0")
            .build_and_sign(&resolver_signer);

        // Create a matching lease with AAT extension
        let issuer_signer = Signer::generate();
        let lease = GateLeaseBuilder::new("lease-001", "work-001", "aat")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .issued_at(1_704_067_200_000)
            .expires_at(1_704_070_800_000)
            .policy_hash(resolution.resolved_policy_hash())
            .issuer_actor_id("issuer-001")
            .time_envelope_ref("htf:tick:12345")
            .aat_extension(AatLeaseExtension {
                view_commitment_hash: [0x33; 32],
                rcp_manifest_hash: [0x11; 32], // Matches resolution
                rcp_profile_id: "aat-profile-001".to_string(),
                selection_policy_id: "policy-001".to_string(),
            })
            .build_and_sign(&issuer_signer);

        // Should match
        assert!(resolution.verify_lease_match(&lease).is_ok());
    }

    #[test]
    fn test_verify_lease_match_aat_extension_hash_mismatch() {
        use crate::fac::AatLeaseExtension;

        let resolver_signer = Signer::generate();
        let resolution = PolicyResolvedForChangeSetBuilder::new("work-001", [0x42; 32])
            .resolved_risk_tier(1)
            .resolved_determinism_class(0)
            .add_rcp_profile_id("aat-profile-001")
            .add_rcp_manifest_hash([0x11; 32])
            .resolver_actor_id("resolver-001")
            .resolver_version("1.0.0")
            .build_and_sign(&resolver_signer);

        // Create a lease with mismatched manifest hash
        let issuer_signer = Signer::generate();
        let lease = GateLeaseBuilder::new("lease-001", "work-001", "aat")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .issued_at(1_704_067_200_000)
            .expires_at(1_704_070_800_000)
            .policy_hash(resolution.resolved_policy_hash())
            .issuer_actor_id("issuer-001")
            .time_envelope_ref("htf:tick:12345")
            .aat_extension(AatLeaseExtension {
                view_commitment_hash: [0x33; 32],
                rcp_manifest_hash: [0xFF; 32], // Does NOT match resolution
                rcp_profile_id: "aat-profile-001".to_string(),
                selection_policy_id: "policy-001".to_string(),
            })
            .build_and_sign(&issuer_signer);

        let result = resolution.verify_lease_match(&lease);
        assert!(matches!(
            result,
            Err(PolicyResolutionError::RcpManifestHashMismatch { .. })
        ));
    }

    #[test]
    fn test_verify_lease_match_aat_extension_unknown_profile() {
        use crate::fac::AatLeaseExtension;

        let resolver_signer = Signer::generate();
        let resolution = PolicyResolvedForChangeSetBuilder::new("work-001", [0x42; 32])
            .resolved_risk_tier(1)
            .resolved_determinism_class(0)
            .add_rcp_profile_id("aat-profile-001")
            .add_rcp_manifest_hash([0x11; 32])
            .resolver_actor_id("resolver-001")
            .resolver_version("1.0.0")
            .build_and_sign(&resolver_signer);

        // Create a lease with unknown profile ID
        let issuer_signer = Signer::generate();
        let lease = GateLeaseBuilder::new("lease-001", "work-001", "aat")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .issued_at(1_704_067_200_000)
            .expires_at(1_704_070_800_000)
            .policy_hash(resolution.resolved_policy_hash())
            .issuer_actor_id("issuer-001")
            .time_envelope_ref("htf:tick:12345")
            .aat_extension(AatLeaseExtension {
                view_commitment_hash: [0x33; 32],
                rcp_manifest_hash: [0x11; 32],
                rcp_profile_id: "unknown-profile".to_string(), // Not in resolution
                selection_policy_id: "policy-001".to_string(),
            })
            .build_and_sign(&issuer_signer);

        let result = resolution.verify_lease_match(&lease);
        assert!(matches!(
            result,
            Err(PolicyResolutionError::RcpManifestHashMismatch { .. })
        ));
    }

    #[test]
    fn test_length_prefixed_canonicalization_prevents_collision() {
        let signer = Signer::generate();

        // Create two resolutions with different field values that could collide
        // with null-termination but not with length-prefixing
        let resolution1 = PolicyResolvedForChangeSetBuilder::new("ab", [0x42; 32])
            .resolved_risk_tier(1)
            .resolved_determinism_class(0)
            .resolver_actor_id("cd")
            .resolver_version("1.0")
            .build_and_sign(&signer);

        // "ab" + "cd" should NOT equal "a" + "bcd" with length-prefixing
        let resolution2 = PolicyResolvedForChangeSetBuilder::new("a", [0x42; 32])
            .resolved_risk_tier(1)
            .resolved_determinism_class(0)
            .resolver_actor_id("bcd")
            .resolver_version("1.0")
            .build_and_sign(&signer);

        // Canonical bytes should be different
        assert_ne!(resolution1.canonical_bytes(), resolution2.canonical_bytes());
    }

    #[test]
    fn test_duplicate_profile_id_rejected() {
        let signer = Signer::generate();

        let result = PolicyResolvedForChangeSetBuilder::new("work-001", [0x42; 32])
            .resolved_risk_tier(1)
            .resolved_determinism_class(0)
            .resolved_rcp_profile_ids(vec![
                "profile-a".to_string(),
                "profile-a".to_string(), // Duplicate
            ])
            .resolved_rcp_manifest_hashes(vec![[0xAA; 32], [0xBB; 32]])
            .resolver_actor_id("resolver-001")
            .resolver_version("1.0.0")
            .try_build_and_sign(&signer);

        assert!(matches!(
            result,
            Err(PolicyResolutionError::DuplicateProfileId { .. })
        ));
    }

    #[test]
    fn test_string_too_long_rejected() {
        let signer = Signer::generate();
        let long_string = "x".repeat(MAX_STRING_LENGTH + 1);

        let result = PolicyResolvedForChangeSetBuilder::new(long_string, [0x42; 32])
            .resolved_risk_tier(1)
            .resolved_determinism_class(0)
            .resolver_actor_id("resolver-001")
            .resolver_version("1.0.0")
            .try_build_and_sign(&signer);

        assert!(matches!(
            result,
            Err(PolicyResolutionError::StringTooLong {
                field: "work_id",
                ..
            })
        ));
    }

    #[test]
    fn test_proto_duplicate_profile_id_rejected() {
        let proto = PolicyResolvedForChangeSetProto {
            work_id: "work-001".to_string(),
            changeset_digest: vec![0x42; 32],
            resolved_policy_hash: vec![0x00; 32],
            resolved_risk_tier: 0,
            resolved_determinism_class: 0,
            resolved_rcp_profile_ids: vec![
                "profile-a".to_string(),
                "profile-a".to_string(), // Duplicate
            ],
            resolved_rcp_manifest_hashes: vec![vec![0x00; 32], vec![0x11; 32]],
            resolved_verifier_policy_hashes: vec![],
            resolver_actor_id: "resolver-001".to_string(),
            resolver_version: "1.0.0".to_string(),
            resolver_signature: vec![0u8; 64],
        };

        let result = PolicyResolvedForChangeSet::try_from(proto);
        assert!(matches!(
            result,
            Err(PolicyResolutionError::DuplicateProfileId { .. })
        ));
    }

    #[test]
    fn test_proto_string_too_long_rejected() {
        let long_string = "x".repeat(MAX_STRING_LENGTH + 1);
        let proto = PolicyResolvedForChangeSetProto {
            work_id: long_string,
            changeset_digest: vec![0x42; 32],
            resolved_policy_hash: vec![0x00; 32],
            resolved_risk_tier: 0,
            resolved_determinism_class: 0,
            resolved_rcp_profile_ids: vec![],
            resolved_rcp_manifest_hashes: vec![],
            resolved_verifier_policy_hashes: vec![],
            resolver_actor_id: "resolver-001".to_string(),
            resolver_version: "1.0.0".to_string(),
            resolver_signature: vec![0u8; 64],
        };

        let result = PolicyResolvedForChangeSet::try_from(proto);
        assert!(matches!(
            result,
            Err(PolicyResolutionError::StringTooLong {
                field: "work_id",
                ..
            })
        ));
    }

    // =========================================================================
    // Tests for AAT extension enforcement
    // =========================================================================

    #[test]
    fn test_verify_lease_match_aat_gate_without_extension_rejected() {
        // Attempt to create a lease with gate_id "aat" but NO AAT extension
        // This should fail at build time with AatExtensionInvariant error
        let issuer_signer = Signer::generate();
        let result = GateLeaseBuilder::new("lease-001", "work-001", "aat")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .issued_at(1_704_067_200_000)
            .expires_at(1_704_070_800_000)
            .policy_hash([0xab; 32])
            .issuer_actor_id("issuer-001")
            .time_envelope_ref("htf:tick:12345")
            // .aat_extension(...) is NOT called
            .try_build_and_sign(&issuer_signer);

        // MUST fail because gate_id is "aat" but extension is missing
        assert!(
            matches!(result, Err(LeaseError::AatExtensionInvariant(ref msg)) if msg.contains("requires aat_extension")),
            "try_build_and_sign should fail with AatExtensionInvariant when aat_extension is missing for gate_id='aat'"
        );
    }

    #[test]
    fn test_verify_lease_match_aat_case_insensitive() {
        // Test various case variations of "aat" in gate_id
        // The builder should reject all of these without an aat_extension
        let test_cases = ["AAT", "Aat", "aAt", "aat-security", "pre-AAT-check"];

        for gate_id in test_cases {
            let issuer_signer = Signer::generate();
            let result = GateLeaseBuilder::new("lease-001", "work-001", gate_id)
                .changeset_digest([0x42; 32])
                .executor_actor_id("executor-001")
                .issued_at(1_704_067_200_000)
                .expires_at(1_704_070_800_000)
                .policy_hash([0xab; 32])
                .issuer_actor_id("issuer-001")
                .time_envelope_ref("htf:tick:12345")
                // Missing AAT extension
                .try_build_and_sign(&issuer_signer);

            assert!(
                matches!(result, Err(LeaseError::AatExtensionInvariant(ref msg)) if msg.contains("requires aat_extension")),
                "gate_id '{gate_id}' should require aat_extension"
            );
        }
    }

    #[test]
    fn test_verify_lease_match_non_aat_gate_without_extension_ok() {
        let resolver_signer = Signer::generate();
        let resolution = PolicyResolvedForChangeSetBuilder::new("work-001", [0x42; 32])
            .resolved_risk_tier(1)
            .resolved_determinism_class(0)
            .resolver_actor_id("resolver-001")
            .resolver_version("1.0.0")
            .build_and_sign(&resolver_signer);

        // Create a lease with gate_id "build" (not AAT) and no extension
        let issuer_signer = Signer::generate();
        let lease = GateLeaseBuilder::new("lease-001", "work-001", "build")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .issued_at(1_704_067_200_000)
            .expires_at(1_704_070_800_000)
            .policy_hash(resolution.resolved_policy_hash())
            .issuer_actor_id("issuer-001")
            .time_envelope_ref("htf:tick:12345")
            .build_and_sign(&issuer_signer);

        // Should succeed - non-AAT gates don't require AAT extension
        assert!(resolution.verify_lease_match(&lease).is_ok());
    }

    // =========================================================================
    // Tests for RiskTier and DeterminismClass enums
    // =========================================================================

    #[test]
    fn test_risk_tier_try_from_valid() {
        assert_eq!(RiskTier::try_from(0).unwrap(), RiskTier::Tier0);
        assert_eq!(RiskTier::try_from(1).unwrap(), RiskTier::Tier1);
        assert_eq!(RiskTier::try_from(2).unwrap(), RiskTier::Tier2);
        assert_eq!(RiskTier::try_from(3).unwrap(), RiskTier::Tier3);
        assert_eq!(RiskTier::try_from(4).unwrap(), RiskTier::Tier4);
    }

    #[test]
    fn test_risk_tier_try_from_invalid() {
        assert!(RiskTier::try_from(5).is_err());
        assert!(RiskTier::try_from(255).is_err());
    }

    #[test]
    fn test_risk_tier_to_u8() {
        assert_eq!(u8::from(RiskTier::Tier0), 0);
        assert_eq!(u8::from(RiskTier::Tier1), 1);
        assert_eq!(u8::from(RiskTier::Tier2), 2);
        assert_eq!(u8::from(RiskTier::Tier3), 3);
        assert_eq!(u8::from(RiskTier::Tier4), 4);
    }

    #[test]
    fn test_determinism_class_try_from_valid() {
        assert_eq!(
            DeterminismClass::try_from(0).unwrap(),
            DeterminismClass::NonDeterministic
        );
        assert_eq!(
            DeterminismClass::try_from(1).unwrap(),
            DeterminismClass::SoftDeterministic
        );
        assert_eq!(
            DeterminismClass::try_from(2).unwrap(),
            DeterminismClass::FullyDeterministic
        );
    }

    #[test]
    fn test_determinism_class_try_from_invalid() {
        assert!(DeterminismClass::try_from(3).is_err());
        assert!(DeterminismClass::try_from(255).is_err());
    }

    #[test]
    fn test_determinism_class_to_u8() {
        assert_eq!(u8::from(DeterminismClass::NonDeterministic), 0);
        assert_eq!(u8::from(DeterminismClass::SoftDeterministic), 1);
        assert_eq!(u8::from(DeterminismClass::FullyDeterministic), 2);
    }

    #[test]
    fn test_risk_tier_serde_roundtrip() {
        let tier = RiskTier::Tier3;
        let serialized = serde_json::to_string(&tier).unwrap();
        let deserialized: RiskTier = serde_json::from_str(&serialized).unwrap();
        assert_eq!(tier, deserialized);
    }

    #[test]
    fn test_determinism_class_serde_roundtrip() {
        let class = DeterminismClass::FullyDeterministic;
        let serialized = serde_json::to_string(&class).unwrap();
        let deserialized: DeterminismClass = serde_json::from_str(&serialized).unwrap();
        assert_eq!(class, deserialized);
    }
}
