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
//! - **Scope Subset Rule**: Child leases cannot broaden permissions
//!
//! # Signature Verification
//!
//! All gate leases are signed using domain-separated Ed25519 signatures.
//! The signature covers the canonical encoding of the lease (excluding the
//! signature field itself) with the `GATE_LEASE_ISSUED:` domain prefix.
//!
//! # Example
//!
//! ```rust
//! use apm2_core::crypto::Signer;
//! use apm2_core::fac::{AatLeaseExtension, GateLease, GateLeaseBuilder};
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

use prost::Message;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::domain_separator::{GATE_LEASE_ISSUED_PREFIX, sign_with_domain, verify_with_domain};
use crate::crypto::{Signature, VerifyingKey};
use crate::events::Canonicalize;

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

    /// The scope validation failed.
    #[error("scope validation failed: {0}")]
    ScopeViolation(String),

    /// The lease is expired.
    #[error("lease expired at {0}")]
    Expired(u64),

    /// The lease is not yet valid.
    #[error("lease not valid until {0}")]
    NotYetValid(u64),

    /// Missing required field.
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// Invalid lease data.
    #[error("invalid lease data: {0}")]
    InvalidData(String),
}

// =============================================================================
// AAT Lease Extension
// =============================================================================

/// Extension fields for AAT (Autonomous Agent Team) leases.
///
/// This extension contains additional fields required when a gate lease
/// is issued for AAT execution contexts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AatLeaseExtension {
    /// Hash of the view commitment for the AAT context.
    #[serde(with = "serde_bytes")]
    pub view_commitment_hash: [u8; 32],

    /// Hash of the RCP (Runnable Capability Profile) manifest.
    #[serde(with = "serde_bytes")]
    pub rcp_manifest_hash: [u8; 32],

    /// Identifier for the RCP profile being used.
    pub rcp_profile_id: String,

    /// Identifier for the selection policy used.
    pub selection_policy_id: String,
}

impl AatLeaseExtension {
    /// Creates a new AAT lease extension.
    #[must_use]
    pub fn new(
        view_commitment_hash: [u8; 32],
        rcp_manifest_hash: [u8; 32],
        rcp_profile_id: impl Into<String>,
        selection_policy_id: impl Into<String>,
    ) -> Self {
        Self {
            view_commitment_hash,
            rcp_manifest_hash,
            rcp_profile_id: rcp_profile_id.into(),
            selection_policy_id: selection_policy_id.into(),
        }
    }

    /// Returns the canonical bytes for this extension.
    ///
    /// Used when computing the overall lease canonical representation.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes =
            Vec::with_capacity(64 + self.rcp_profile_id.len() + self.selection_policy_id.len());
        bytes.extend_from_slice(&self.view_commitment_hash);
        bytes.extend_from_slice(&self.rcp_manifest_hash);
        bytes.extend_from_slice(self.rcp_profile_id.as_bytes());
        bytes.push(0); // null separator
        bytes.extend_from_slice(self.selection_policy_id.as_bytes());
        bytes
    }
}

// =============================================================================
// Gate Lease Scope
// =============================================================================

/// Scope constraints for a gate lease.
///
/// Defines the boundaries of what the lease authorizes.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct GateLeaseScope {
    /// Gate IDs this lease authorizes execution on.
    pub gate_ids: Vec<String>,

    /// Tool names this lease authorizes.
    pub tools: Vec<String>,

    /// Namespace prefixes this lease authorizes access to.
    pub namespaces: Vec<String>,

    /// Whether this is an unlimited scope.
    pub unlimited: bool,
}

impl GateLeaseScope {
    /// Creates an empty scope with no permissions.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Creates an unlimited scope.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Vec::new() is not stable const
    pub fn unlimited() -> Self {
        Self {
            gate_ids: Vec::new(),
            tools: Vec::new(),
            namespaces: Vec::new(),
            unlimited: true,
        }
    }

    /// Returns `true` if this scope is a subset of the parent scope.
    ///
    /// The subset rule ensures that child leases cannot broaden permissions:
    /// - If parent is unlimited, any child scope is valid
    /// - If child is unlimited, it's only valid if parent is also unlimited
    /// - Otherwise, all child permissions must be present in parent
    #[must_use]
    pub fn is_subset_of(&self, parent: &Self) -> bool {
        // Unlimited parent allows any child scope
        if parent.unlimited {
            return true;
        }

        // If child is unlimited but parent is not, that's a scope expansion
        if self.unlimited {
            return false;
        }

        // Check gate_ids: all child gates must be in parent
        for gate in &self.gate_ids {
            if !parent.gate_ids.contains(gate) {
                return false;
            }
        }

        // Check tools: all child tools must be in parent
        for tool in &self.tools {
            if !parent.tools.contains(tool) {
                return false;
            }
        }

        // Check namespaces: all child namespaces must be covered by parent
        for ns in &self.namespaces {
            if !parent
                .namespaces
                .iter()
                .any(|p| Self::is_namespace_covered(p, ns))
            {
                return false;
            }
        }

        true
    }

    /// Checks if a parent namespace covers a child namespace.
    ///
    /// A parent covers a child if:
    /// - They are equal, OR
    /// - The child starts with parent followed by "/"
    fn is_namespace_covered(parent: &str, child: &str) -> bool {
        if parent == child {
            return true;
        }
        child.starts_with(parent) && child.as_bytes().get(parent.len()) == Some(&b'/')
    }

    /// Returns the canonical bytes for scope comparison.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Encode unlimited flag
        bytes.push(u8::from(self.unlimited));

        // Encode sorted gate_ids
        let mut sorted_gates = self.gate_ids.clone();
        sorted_gates.sort();
        for gate in &sorted_gates {
            bytes.extend_from_slice(gate.as_bytes());
            bytes.push(0);
        }
        bytes.push(0xFF); // section separator

        // Encode sorted tools
        let mut sorted_tools = self.tools.clone();
        sorted_tools.sort();
        for tool in &sorted_tools {
            bytes.extend_from_slice(tool.as_bytes());
            bytes.push(0);
        }
        bytes.push(0xFF); // section separator

        // Encode sorted namespaces
        let mut sorted_ns = self.namespaces.clone();
        sorted_ns.sort();
        for ns in &sorted_ns {
            bytes.extend_from_slice(ns.as_bytes());
            bytes.push(0);
        }

        bytes
    }
}

// =============================================================================
// Gate Lease
// =============================================================================

/// A gate lease authorizing execution within the Forge Admission Cycle.
///
/// The gate lease is a cryptographically signed authorization that binds:
/// - An executor actor to a specific work item
/// - A specific changeset (via digest)
/// - A time window (via HTF time envelope reference)
/// - A policy configuration
///
/// # Fields
///
/// All 12 required fields as specified in the ticket:
/// - `lease_id`: Unique identifier for this lease
/// - `work_id`: Work item this lease authorizes
/// - `gate_id`: Gate this lease applies to
/// - `changeset_digest`: Hash binding the lease to specific changes
/// - `executor_actor_id`: Actor authorized to execute
/// - `issued_at`: Timestamp when lease was issued (observational)
/// - `expires_at`: Timestamp when lease expires (observational)
/// - `policy_hash`: Hash of the policy configuration
/// - `issuer_actor_id`: Actor who issued the lease
/// - `issuer_signature`: Ed25519 signature with domain separation
/// - `time_envelope_ref`: HTF time envelope reference
/// - `aat_extension`: Optional AAT-specific fields
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateLease {
    /// Unique identifier for this lease.
    pub lease_id: String,

    /// Work item this lease authorizes.
    pub work_id: String,

    /// Gate this lease applies to.
    pub gate_id: String,

    /// Hash binding the lease to specific changeset.
    #[serde(with = "serde_bytes")]
    pub changeset_digest: [u8; 32],

    /// Actor authorized to execute under this lease.
    pub executor_actor_id: String,

    /// Timestamp when lease was issued (Unix millis, observational).
    pub issued_at: u64,

    /// Timestamp when lease expires (Unix millis, observational).
    pub expires_at: u64,

    /// Hash of the policy configuration.
    #[serde(with = "serde_bytes")]
    pub policy_hash: [u8; 32],

    /// Actor who issued this lease.
    pub issuer_actor_id: String,

    /// Ed25519 signature over canonical bytes with domain separation.
    #[serde(with = "serde_bytes")]
    pub issuer_signature: [u8; 64],

    /// HTF time envelope reference for temporal authority.
    pub time_envelope_ref: String,

    /// Optional AAT-specific extension fields.
    pub aat_extension: Option<AatLeaseExtension>,

    /// Scope constraints for this lease.
    #[serde(default)]
    pub scope: GateLeaseScope,
}

impl GateLease {
    /// Returns the canonical bytes for signing/verification.
    ///
    /// The canonical representation includes all fields except the signature,
    /// encoded in a deterministic order. This ensures that the same logical
    /// lease always produces the same canonical bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        // Pre-calculate capacity for efficiency
        let capacity = 32 // lease_id estimate
            + 32 // work_id estimate
            + 32 // gate_id estimate
            + 32 // changeset_digest
            + 32 // executor_actor_id estimate
            + 16 // issued_at + expires_at
            + 32 // policy_hash
            + 32 // issuer_actor_id estimate
            + 64 // time_envelope_ref estimate
            + 128; // aat_extension estimate

        let mut bytes = Vec::with_capacity(capacity);

        // Field order is deterministic and matches proto field order
        // 1. lease_id
        bytes.extend_from_slice(self.lease_id.as_bytes());
        bytes.push(0); // null separator

        // 2. work_id
        bytes.extend_from_slice(self.work_id.as_bytes());
        bytes.push(0);

        // 3. gate_id
        bytes.extend_from_slice(self.gate_id.as_bytes());
        bytes.push(0);

        // 4. changeset_digest
        bytes.extend_from_slice(&self.changeset_digest);

        // 5. executor_actor_id
        bytes.extend_from_slice(self.executor_actor_id.as_bytes());
        bytes.push(0);

        // 6. issued_at (big-endian for consistent ordering)
        bytes.extend_from_slice(&self.issued_at.to_be_bytes());

        // 7. expires_at
        bytes.extend_from_slice(&self.expires_at.to_be_bytes());

        // 8. policy_hash
        bytes.extend_from_slice(&self.policy_hash);

        // 9. issuer_actor_id
        bytes.extend_from_slice(self.issuer_actor_id.as_bytes());
        bytes.push(0);

        // 10. time_envelope_ref
        bytes.extend_from_slice(self.time_envelope_ref.as_bytes());
        bytes.push(0);

        // 11. scope
        bytes.extend_from_slice(&self.scope.canonical_bytes());
        bytes.push(0xFF); // section separator

        // 12. aat_extension (optional)
        if let Some(ext) = &self.aat_extension {
            bytes.push(1); // present marker
            bytes.extend_from_slice(&ext.canonical_bytes());
        } else {
            bytes.push(0); // absent marker
        }

        bytes
    }

    /// Validates the lease signature using domain separation.
    ///
    /// # Arguments
    ///
    /// * `verifying_key` - The public key of the expected issuer
    ///
    /// # Returns
    ///
    /// `Ok(())` if the signature is valid, `Err(LeaseError::InvalidSignature)`
    /// otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`LeaseError::InvalidSignature`] if the signature verification
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

    /// Validates that this lease's scope is a subset of the parent lease's
    /// scope.
    ///
    /// This enforces the subset rule: child leases cannot broaden permissions.
    ///
    /// # Arguments
    ///
    /// * `parent` - The parent lease to validate against
    ///
    /// # Returns
    ///
    /// `Ok(())` if this lease's scope is a valid subset,
    /// `Err(LeaseError::ScopeViolation)` otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`LeaseError::ScopeViolation`] if this lease's scope exceeds
    /// the parent's scope.
    pub fn validate_scope(&self, parent: &Self) -> Result<(), LeaseError> {
        if !self.scope.is_subset_of(&parent.scope) {
            return Err(LeaseError::ScopeViolation(
                "child lease scope exceeds parent scope".to_string(),
            ));
        }

        // Also validate that expires_at is not later than parent
        if self.expires_at > parent.expires_at {
            return Err(LeaseError::ScopeViolation(
                "child lease expiration exceeds parent expiration".to_string(),
            ));
        }

        Ok(())
    }

    /// Checks if the lease is currently valid based on timestamps.
    ///
    /// Note: This only checks observational timestamps. The authoritative
    /// time reference is the HTF time envelope.
    ///
    /// # Arguments
    ///
    /// * `current_time_ms` - Current Unix timestamp in milliseconds
    ///
    /// # Returns
    ///
    /// `Ok(())` if the lease is valid, error otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`LeaseError::NotYetValid`] if current time is before
    /// `issued_at`. Returns [`LeaseError::Expired`] if current time is
    /// after `expires_at`.
    #[allow(clippy::missing_const_for_fn)] // const Result::Err is not stable
    pub fn check_time_validity(&self, current_time_ms: u64) -> Result<(), LeaseError> {
        if current_time_ms < self.issued_at {
            return Err(LeaseError::NotYetValid(self.issued_at));
        }
        if current_time_ms > self.expires_at {
            return Err(LeaseError::Expired(self.expires_at));
        }
        Ok(())
    }
}

impl Canonicalize for GateLease {
    fn canonicalize(&mut self) {
        // Sort scope fields for deterministic encoding
        self.scope.gate_ids.sort();
        self.scope.tools.sort();
        self.scope.namespaces.sort();
    }
}

// =============================================================================
// Gate Lease Builder
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
    scope: GateLeaseScope,
}

impl GateLeaseBuilder {
    /// Creates a new builder with required identifiers.
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

    /// Sets the issued timestamp.
    #[must_use]
    pub const fn issued_at(mut self, timestamp_ms: u64) -> Self {
        self.issued_at = Some(timestamp_ms);
        self
    }

    /// Sets the expiration timestamp.
    #[must_use]
    pub const fn expires_at(mut self, timestamp_ms: u64) -> Self {
        self.expires_at = Some(timestamp_ms);
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
    pub fn time_envelope_ref(mut self, envelope_ref: impl Into<String>) -> Self {
        self.time_envelope_ref = Some(envelope_ref.into());
        self
    }

    /// Sets the AAT extension.
    #[must_use]
    pub fn aat_extension(mut self, extension: AatLeaseExtension) -> Self {
        self.aat_extension = Some(extension);
        self
    }

    /// Sets the scope.
    #[must_use]
    pub fn scope(mut self, scope: GateLeaseScope) -> Self {
        self.scope = scope;
        self
    }

    /// Builds the lease and signs it with the provided signer.
    ///
    /// # Panics
    ///
    /// Panics if required fields are missing. Use `try_build_and_sign` for
    /// fallible construction.
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
            issuer_signature: [0u8; 64],
            time_envelope_ref,
            aat_extension: self.aat_extension,
            scope: self.scope,
        };

        // Canonicalize before signing
        lease.canonicalize();

        // Sign the canonical bytes
        let canonical = lease.canonical_bytes();
        let signature = sign_with_domain(signer, GATE_LEASE_ISSUED_PREFIX, &canonical);
        lease.issuer_signature = signature.to_bytes();

        Ok(lease)
    }
}

// =============================================================================
// Proto Message Conversion
// =============================================================================

/// Proto-generated `GateLease` message for wire format.
///
/// This mirrors the structure in `kernel_events.proto`.
#[derive(Clone, PartialEq, Eq, Message)]
#[allow(missing_docs)]
pub struct GateLeaseProto {
    #[prost(string, tag = "1")]
    pub lease_id: String,

    #[prost(string, tag = "2")]
    pub work_id: String,

    #[prost(string, tag = "3")]
    pub gate_id: String,

    #[prost(bytes = "vec", tag = "4")]
    pub changeset_digest: Vec<u8>,

    #[prost(string, tag = "5")]
    pub executor_actor_id: String,

    #[prost(uint64, tag = "6")]
    pub issued_at: u64,

    #[prost(uint64, tag = "7")]
    pub expires_at: u64,

    #[prost(bytes = "vec", tag = "8")]
    pub policy_hash: Vec<u8>,

    #[prost(string, tag = "9")]
    pub issuer_actor_id: String,

    #[prost(bytes = "vec", tag = "10")]
    pub issuer_signature: Vec<u8>,

    #[prost(string, tag = "11")]
    pub time_envelope_ref: String,

    #[prost(message, optional, tag = "12")]
    pub aat_extension: Option<AatLeaseExtensionProto>,
}

/// Proto-generated AAT lease extension message.
#[derive(Clone, PartialEq, Eq, Message)]
#[allow(missing_docs)]
pub struct AatLeaseExtensionProto {
    #[prost(bytes = "vec", tag = "1")]
    pub view_commitment_hash: Vec<u8>,

    #[prost(bytes = "vec", tag = "2")]
    pub rcp_manifest_hash: Vec<u8>,

    #[prost(string, tag = "3")]
    pub rcp_profile_id: String,

    #[prost(string, tag = "4")]
    pub selection_policy_id: String,
}

impl TryFrom<GateLeaseProto> for GateLease {
    type Error = LeaseError;

    fn try_from(proto: GateLeaseProto) -> Result<Self, Self::Error> {
        let changeset_digest: [u8; 32] = proto.changeset_digest.try_into().map_err(|_| {
            LeaseError::InvalidData("changeset_digest must be 32 bytes".to_string())
        })?;

        let policy_hash: [u8; 32] = proto
            .policy_hash
            .try_into()
            .map_err(|_| LeaseError::InvalidData("policy_hash must be 32 bytes".to_string()))?;

        let issuer_signature: [u8; 64] = proto.issuer_signature.try_into().map_err(|_| {
            LeaseError::InvalidData("issuer_signature must be 64 bytes".to_string())
        })?;

        let aat_extension = proto
            .aat_extension
            .map(AatLeaseExtension::try_from)
            .transpose()?;

        Ok(Self {
            lease_id: proto.lease_id,
            work_id: proto.work_id,
            gate_id: proto.gate_id,
            changeset_digest,
            executor_actor_id: proto.executor_actor_id,
            issued_at: proto.issued_at,
            expires_at: proto.expires_at,
            policy_hash,
            issuer_actor_id: proto.issuer_actor_id,
            issuer_signature,
            time_envelope_ref: proto.time_envelope_ref,
            aat_extension,
            scope: GateLeaseScope::default(),
        })
    }
}

impl From<GateLease> for GateLeaseProto {
    fn from(lease: GateLease) -> Self {
        Self {
            lease_id: lease.lease_id,
            work_id: lease.work_id,
            gate_id: lease.gate_id,
            changeset_digest: lease.changeset_digest.to_vec(),
            executor_actor_id: lease.executor_actor_id,
            issued_at: lease.issued_at,
            expires_at: lease.expires_at,
            policy_hash: lease.policy_hash.to_vec(),
            issuer_actor_id: lease.issuer_actor_id,
            issuer_signature: lease.issuer_signature.to_vec(),
            time_envelope_ref: lease.time_envelope_ref,
            aat_extension: lease.aat_extension.map(Into::into),
        }
    }
}

impl TryFrom<AatLeaseExtensionProto> for AatLeaseExtension {
    type Error = LeaseError;

    fn try_from(proto: AatLeaseExtensionProto) -> Result<Self, Self::Error> {
        let view_commitment_hash: [u8; 32] =
            proto.view_commitment_hash.try_into().map_err(|_| {
                LeaseError::InvalidData("view_commitment_hash must be 32 bytes".to_string())
            })?;

        let rcp_manifest_hash: [u8; 32] = proto.rcp_manifest_hash.try_into().map_err(|_| {
            LeaseError::InvalidData("rcp_manifest_hash must be 32 bytes".to_string())
        })?;

        Ok(Self {
            view_commitment_hash,
            rcp_manifest_hash,
            rcp_profile_id: proto.rcp_profile_id,
            selection_policy_id: proto.selection_policy_id,
        })
    }
}

impl From<AatLeaseExtension> for AatLeaseExtensionProto {
    fn from(ext: AatLeaseExtension) -> Self {
        Self {
            view_commitment_hash: ext.view_commitment_hash.to_vec(),
            rcp_manifest_hash: ext.rcp_manifest_hash.to_vec(),
            rcp_profile_id: ext.rcp_profile_id,
            selection_policy_id: ext.selection_policy_id,
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
        assert!(lease.aat_extension.is_none());
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
    fn test_scope_subset_rule_basic() {
        let signer = Signer::generate();

        // Parent with broader scope
        let parent = GateLeaseBuilder::new("parent-lease", "work-001", "gate-build")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .issued_at(1_704_067_200_000)
            .expires_at(1_704_070_800_000)
            .policy_hash([0xab; 32])
            .issuer_actor_id("issuer-001")
            .time_envelope_ref("htf:tick:12345")
            .scope(GateLeaseScope {
                gate_ids: vec!["gate-1".into(), "gate-2".into()],
                tools: vec!["read".into(), "write".into()],
                namespaces: vec!["project/src".into()],
                unlimited: false,
            })
            .build_and_sign(&signer);

        // Child with narrower scope (subset) - should pass
        let valid_child = GateLeaseBuilder::new("child-lease", "work-001", "gate-build")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .issued_at(1_704_067_200_000)
            .expires_at(1_704_070_000_000) // Earlier expiration
            .policy_hash([0xab; 32])
            .issuer_actor_id("issuer-001")
            .time_envelope_ref("htf:tick:12345")
            .scope(GateLeaseScope {
                gate_ids: vec!["gate-1".into()],
                tools: vec!["read".into()],
                namespaces: vec!["project/src/main".into()],
                unlimited: false,
            })
            .build_and_sign(&signer);

        assert!(valid_child.validate_scope(&parent).is_ok());
    }

    #[test]
    fn test_scope_subset_rule_violation() {
        let signer = Signer::generate();

        let parent = GateLeaseBuilder::new("parent-lease", "work-001", "gate-build")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .issued_at(1_704_067_200_000)
            .expires_at(1_704_070_800_000)
            .policy_hash([0xab; 32])
            .issuer_actor_id("issuer-001")
            .time_envelope_ref("htf:tick:12345")
            .scope(GateLeaseScope {
                gate_ids: vec!["gate-1".into()],
                tools: vec!["read".into()],
                namespaces: vec!["project/src".into()],
                unlimited: false,
            })
            .build_and_sign(&signer);

        // Child with broader scope (not a subset) - should fail
        let invalid_child = GateLeaseBuilder::new("child-lease", "work-001", "gate-build")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .issued_at(1_704_067_200_000)
            .expires_at(1_704_070_000_000)
            .policy_hash([0xab; 32])
            .issuer_actor_id("issuer-001")
            .time_envelope_ref("htf:tick:12345")
            .scope(GateLeaseScope {
                gate_ids: vec!["gate-1".into(), "gate-2".into()], // Broader!
                tools: vec!["read".into()],
                namespaces: vec!["project/src".into()],
                unlimited: false,
            })
            .build_and_sign(&signer);

        let result = invalid_child.validate_scope(&parent);
        assert!(result.is_err());
        assert!(matches!(result, Err(LeaseError::ScopeViolation(_))));
    }

    #[test]
    fn test_scope_expiration_rule() {
        let signer = Signer::generate();

        let parent = GateLeaseBuilder::new("parent-lease", "work-001", "gate-build")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .issued_at(1_704_067_200_000)
            .expires_at(1_704_070_800_000)
            .policy_hash([0xab; 32])
            .issuer_actor_id("issuer-001")
            .time_envelope_ref("htf:tick:12345")
            .build_and_sign(&signer);

        // Child with later expiration - should fail
        let invalid_child = GateLeaseBuilder::new("child-lease", "work-001", "gate-build")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .issued_at(1_704_067_200_000)
            .expires_at(1_704_080_000_000) // Later than parent!
            .policy_hash([0xab; 32])
            .issuer_actor_id("issuer-001")
            .time_envelope_ref("htf:tick:12345")
            .build_and_sign(&signer);

        let result = invalid_child.validate_scope(&parent);
        assert!(result.is_err());
        assert!(matches!(result, Err(LeaseError::ScopeViolation(_))));
    }

    #[test]
    fn test_unlimited_scope() {
        let signer = Signer::generate();

        let unlimited_parent = GateLeaseBuilder::new("parent-lease", "work-001", "gate-build")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .issued_at(1_704_067_200_000)
            .expires_at(1_704_070_800_000)
            .policy_hash([0xab; 32])
            .issuer_actor_id("issuer-001")
            .time_envelope_ref("htf:tick:12345")
            .scope(GateLeaseScope::unlimited())
            .build_and_sign(&signer);

        // Any limited scope is subset of unlimited
        let limited_child = GateLeaseBuilder::new("child-lease", "work-001", "gate-build")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .issued_at(1_704_067_200_000)
            .expires_at(1_704_070_000_000)
            .policy_hash([0xab; 32])
            .issuer_actor_id("issuer-001")
            .time_envelope_ref("htf:tick:12345")
            .scope(GateLeaseScope {
                gate_ids: vec!["anything".into()],
                tools: vec!["everything".into()],
                namespaces: vec!["anywhere".into()],
                unlimited: false,
            })
            .build_and_sign(&signer);

        assert!(limited_child.validate_scope(&unlimited_parent).is_ok());
    }

    #[test]
    fn test_aat_extension() {
        let signer = Signer::generate();

        let lease = GateLeaseBuilder::new("lease-001", "work-001", "gate-build")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .issued_at(1_704_067_200_000)
            .expires_at(1_704_070_800_000)
            .policy_hash([0xab; 32])
            .issuer_actor_id("issuer-001")
            .time_envelope_ref("htf:tick:12345")
            .aat_extension(AatLeaseExtension::new(
                [0x11; 32],
                [0x22; 32],
                "rcp-profile-001",
                "selection-policy-001",
            ))
            .build_and_sign(&signer);

        assert!(lease.aat_extension.is_some());
        let ext = lease.aat_extension.as_ref().unwrap();
        assert_eq!(ext.view_commitment_hash, [0x11; 32]);
        assert_eq!(ext.rcp_manifest_hash, [0x22; 32]);
        assert_eq!(ext.rcp_profile_id, "rcp-profile-001");
        assert_eq!(ext.selection_policy_id, "selection-policy-001");

        // Signature should still be valid
        assert!(lease.validate_signature(&signer.verifying_key()).is_ok());
    }

    #[test]
    fn test_time_validity() {
        let signer = Signer::generate();
        let lease = create_test_lease(&signer);

        // Within valid window
        assert!(lease.check_time_validity(1_704_068_000_000).is_ok());

        // Before issued_at
        let result = lease.check_time_validity(1_704_067_000_000);
        assert!(matches!(result, Err(LeaseError::NotYetValid(_))));

        // After expires_at
        let result = lease.check_time_validity(1_704_071_000_000);
        assert!(matches!(result, Err(LeaseError::Expired(_))));
    }

    #[test]
    fn test_proto_roundtrip() {
        let signer = Signer::generate();
        let original = create_test_lease(&signer);

        // Convert to proto
        let proto: GateLeaseProto = original.clone().into();

        // Encode and decode
        let encoded = proto.encode_to_vec();
        let decoded_proto = GateLeaseProto::decode(encoded.as_slice()).unwrap();

        // Convert back to domain type
        let recovered = GateLease::try_from(decoded_proto).unwrap();

        // Core fields should match
        assert_eq!(original.lease_id, recovered.lease_id);
        assert_eq!(original.work_id, recovered.work_id);
        assert_eq!(original.gate_id, recovered.gate_id);
        assert_eq!(original.changeset_digest, recovered.changeset_digest);
        assert_eq!(original.executor_actor_id, recovered.executor_actor_id);
        assert_eq!(original.issued_at, recovered.issued_at);
        assert_eq!(original.expires_at, recovered.expires_at);
        assert_eq!(original.policy_hash, recovered.policy_hash);
        assert_eq!(original.issuer_actor_id, recovered.issuer_actor_id);
        assert_eq!(original.issuer_signature, recovered.issuer_signature);
        assert_eq!(original.time_envelope_ref, recovered.time_envelope_ref);

        // Signature should still be valid
        assert!(
            recovered
                .validate_signature(&signer.verifying_key())
                .is_ok()
        );
    }

    #[test]
    fn test_proto_roundtrip_with_aat() {
        let signer = Signer::generate();

        let original = GateLeaseBuilder::new("lease-001", "work-001", "gate-build")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .issued_at(1_704_067_200_000)
            .expires_at(1_704_070_800_000)
            .policy_hash([0xab; 32])
            .issuer_actor_id("issuer-001")
            .time_envelope_ref("htf:tick:12345")
            .aat_extension(AatLeaseExtension::new(
                [0x11; 32],
                [0x22; 32],
                "rcp-profile-001",
                "selection-policy-001",
            ))
            .build_and_sign(&signer);

        let proto: GateLeaseProto = original.into();
        let encoded = proto.encode_to_vec();
        let decoded_proto = GateLeaseProto::decode(encoded.as_slice()).unwrap();
        let recovered = GateLease::try_from(decoded_proto).unwrap();

        assert!(recovered.aat_extension.is_some());
        let ext = recovered.aat_extension.as_ref().unwrap();
        assert_eq!(ext.view_commitment_hash, [0x11; 32]);
        assert_eq!(ext.rcp_manifest_hash, [0x22; 32]);
        assert_eq!(ext.rcp_profile_id, "rcp-profile-001");
        assert_eq!(ext.selection_policy_id, "selection-policy-001");
    }

    #[test]
    fn test_missing_field_error() {
        let signer = Signer::generate();

        let result = GateLeaseBuilder::new("lease-001", "work-001", "gate-build")
            .changeset_digest([0x42; 32])
            // Missing executor_actor_id
            .issued_at(1_704_067_200_000)
            .expires_at(1_704_070_800_000)
            .policy_hash([0xab; 32])
            .issuer_actor_id("issuer-001")
            .time_envelope_ref("htf:tick:12345")
            .try_build_and_sign(&signer);

        assert!(matches!(
            result,
            Err(LeaseError::MissingField("executor_actor_id"))
        ));
    }

    #[test]
    fn test_canonicalize_trait() {
        let signer = Signer::generate();
        let mut lease = GateLeaseBuilder::new("lease-001", "work-001", "gate-build")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .issued_at(1_704_067_200_000)
            .expires_at(1_704_070_800_000)
            .policy_hash([0xab; 32])
            .issuer_actor_id("issuer-001")
            .time_envelope_ref("htf:tick:12345")
            .scope(GateLeaseScope {
                gate_ids: vec!["z-gate".into(), "a-gate".into(), "m-gate".into()],
                tools: vec!["write".into(), "read".into()],
                namespaces: vec!["beta".into(), "alpha".into()],
                unlimited: false,
            })
            .build_and_sign(&signer);

        // Before canonicalize, scope fields may be unsorted
        // (actually they're sorted during build, but let's verify canonicalize works)
        lease.scope.gate_ids = vec!["z-gate".into(), "a-gate".into(), "m-gate".into()];
        lease.scope.tools = vec!["write".into(), "read".into()];
        lease.scope.namespaces = vec!["beta".into(), "alpha".into()];

        lease.canonicalize();

        assert_eq!(lease.scope.gate_ids, vec!["a-gate", "m-gate", "z-gate"]);
        assert_eq!(lease.scope.tools, vec!["read", "write"]);
        assert_eq!(lease.scope.namespaces, vec!["alpha", "beta"]);
    }

    #[test]
    fn test_namespace_coverage() {
        // Test path-aware prefix matching
        assert!(GateLeaseScope::is_namespace_covered("project", "project"));
        assert!(GateLeaseScope::is_namespace_covered(
            "project",
            "project/src"
        ));
        assert!(GateLeaseScope::is_namespace_covered(
            "project",
            "project/src/main.rs"
        ));
        assert!(!GateLeaseScope::is_namespace_covered(
            "project",
            "project_backup"
        ));
        assert!(!GateLeaseScope::is_namespace_covered("project", "other"));
    }
}
