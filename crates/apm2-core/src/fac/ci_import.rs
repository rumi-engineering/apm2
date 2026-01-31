// AGENT-AUTHORED
//! CI evidence import with CAS integration for the Forge Admission Cycle.
//!
//! This module defines [`CiEvidenceImport`] and [`CiImportAttestation`] which
//! represent imported CI evidence and its attestation. CI evidence must be
//! validated before it can influence admission decisions.
//!
//! # Security Model
//!
//! CI evidence import requires:
//!
//! 1. **Webhook signature verification**: The webhook must be cryptographically
//!    verified before processing.
//! 2. **CAS verification**: All artifact digests must exist in the
//!    Content-Addressed Store (CAS).
//! 3. **Attestation level check**: The attestation level must meet the minimum
//!    policy requirement. L0 (status-only) is rejected when CI gating is
//!    enabled, enforcing fail-closed semantics (SEC-CTRL-FAC-0015).
//!
//! # Validation Flow
//!
//! ```text
//! CI Webhook Event
//!       |
//!       v
//! Verify webhook signature
//!       |
//!       v
//! CiEvidenceImport created
//!       |
//!       v
//! validate_ci_import(import, policy, cas)
//!       |
//!       +--> Check webhook_signature_verified
//!       +--> Check artifact_digests exist in CAS
//!       +--> Check attestation.meets_minimum(policy.minimum_level)
//!       |
//!       v
//! CiImportAttestation emitted
//! ```
//!
//! # Example
//!
//! ```rust
//! use apm2_core::evidence::{ContentAddressedStore, MemoryCas};
//! use apm2_core::fac::{
//!     CiAttestation, CiAttestationLevel, CiEvidenceImport, CiImportPolicy,
//!     validate_ci_import,
//! };
//!
//! // Create an import with verified webhook
//! let import = CiEvidenceImport::builder()
//!     .workflow_run_id("run-12345")
//!     .webhook_signature_verified(true)
//!     .attestation(
//!         CiAttestation::builder()
//!             .level(CiAttestationLevel::L1)
//!             .workflow_run_id("run-12345")
//!             .build()
//!             .unwrap(),
//!     )
//!     .build()
//!     .unwrap();
//!
//! // Create a policy requiring L1 minimum
//! let policy = CiImportPolicy::new(CiAttestationLevel::L1, true);
//!
//! // Create a CAS (in production, use a real implementation)
//! let cas = MemoryCas::new();
//!
//! // Validate the import
//! let result = validate_ci_import(&import, &policy, &cas);
//! assert!(result.is_ok());
//! ```

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::ci_attestation::{CiAttestation, CiAttestationLevel};
use super::domain_separator::{CI_IMPORT_ATTESTATION_PREFIX, sign_with_domain};
use crate::crypto::{Hash, Signature, Signer};
use crate::evidence::{CasError, ContentAddressedStore};

// =============================================================================
// Resource Limits
// =============================================================================

/// Maximum number of artifact digests allowed in a CI evidence import.
/// This prevents denial-of-service attacks via oversized repeated fields.
pub const MAX_ARTIFACT_DIGESTS: usize = 1024;

/// Maximum length of the workflow run ID string.
pub const MAX_WORKFLOW_RUN_ID_LENGTH: usize = 4096;

/// Maximum length of the import ID string.
pub const MAX_IMPORT_ID_LENGTH: usize = 256;

// =============================================================================
// CiEvidenceImport
// =============================================================================

/// CI evidence import representing a webhook-triggered CI result.
///
/// This struct captures the evidence from a CI workflow run that has been
/// received via webhook. The import must be validated before it can influence
/// admission decisions.
///
/// # Required Fields
///
/// - `workflow_run_id`: Unique identifier for the CI workflow run
/// - `webhook_signature_verified`: Whether the webhook signature was verified
/// - `attestation`: The CI attestation for this import
///
/// # Optional Fields
///
/// - `artifact_digests`: Hashes of artifacts stored in CAS
///
/// # Builder Pattern
///
/// Use [`CiEvidenceImport::builder()`] to construct instances with validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CiEvidenceImport {
    /// The CI workflow run identifier.
    workflow_run_id: String,

    /// Whether the webhook signature was cryptographically verified.
    ///
    /// This MUST be `true` for the import to be valid. Set to `false` only
    /// when the webhook signature could not be verified.
    webhook_signature_verified: bool,

    /// Hashes of downloaded artifacts stored in CAS.
    ///
    /// These are content hashes (e.g., SHA-256 or BLAKE3) of the artifact
    /// contents. Each digest must exist in the CAS for validation to pass.
    artifact_digests: Vec<Hash>,

    /// The CI attestation for this import.
    ///
    /// Contains the attestation level and evidence metadata.
    attestation: CiAttestation,
}

impl CiEvidenceImport {
    /// Creates a new builder for constructing a `CiEvidenceImport`.
    #[must_use]
    pub fn builder() -> CiEvidenceImportBuilder {
        CiEvidenceImportBuilder::new()
    }

    /// Returns the workflow run identifier.
    #[must_use]
    pub fn workflow_run_id(&self) -> &str {
        &self.workflow_run_id
    }

    /// Returns whether the webhook signature was verified.
    #[must_use]
    pub const fn webhook_signature_verified(&self) -> bool {
        self.webhook_signature_verified
    }

    /// Returns the artifact digests.
    #[must_use]
    pub fn artifact_digests(&self) -> &[Hash] {
        &self.artifact_digests
    }

    /// Returns the CI attestation.
    #[must_use]
    pub const fn attestation(&self) -> &CiAttestation {
        &self.attestation
    }
}

// =============================================================================
// CiEvidenceImport Builder
// =============================================================================

/// Builder for constructing [`CiEvidenceImport`] instances with validation.
#[derive(Debug, Default)]
pub struct CiEvidenceImportBuilder {
    workflow_run_id: Option<String>,
    webhook_signature_verified: Option<bool>,
    artifact_digests: Vec<Hash>,
    attestation: Option<CiAttestation>,
}

impl CiEvidenceImportBuilder {
    /// Creates a new builder with default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the workflow run identifier.
    #[must_use]
    pub fn workflow_run_id(mut self, id: impl Into<String>) -> Self {
        self.workflow_run_id = Some(id.into());
        self
    }

    /// Sets whether the webhook signature was verified.
    #[must_use]
    pub const fn webhook_signature_verified(mut self, verified: bool) -> Self {
        self.webhook_signature_verified = Some(verified);
        self
    }

    /// Adds an artifact digest.
    #[must_use]
    pub fn artifact_digest(mut self, digest: Hash) -> Self {
        self.artifact_digests.push(digest);
        self
    }

    /// Sets multiple artifact digests, replacing any previously added.
    #[must_use]
    pub fn artifact_digests(mut self, digests: impl IntoIterator<Item = Hash>) -> Self {
        self.artifact_digests = digests.into_iter().collect();
        self
    }

    /// Sets the CI attestation.
    #[must_use]
    pub fn attestation(mut self, attestation: CiAttestation) -> Self {
        self.attestation = Some(attestation);
        self
    }

    /// Builds the [`CiEvidenceImport`], validating all fields.
    ///
    /// # Errors
    ///
    /// Returns [`CiImportError`] if:
    /// - Required fields are missing
    /// - `workflow_run_id` exceeds [`MAX_WORKFLOW_RUN_ID_LENGTH`]
    /// - `artifact_digests` exceeds [`MAX_ARTIFACT_DIGESTS`]
    pub fn build(self) -> Result<CiEvidenceImport, CiImportError> {
        let workflow_run_id = self
            .workflow_run_id
            .ok_or(CiImportError::MissingField("workflow_run_id"))?;

        if workflow_run_id.len() > MAX_WORKFLOW_RUN_ID_LENGTH {
            return Err(CiImportError::StringTooLong {
                field: "workflow_run_id",
                length: workflow_run_id.len(),
                max: MAX_WORKFLOW_RUN_ID_LENGTH,
            });
        }

        let webhook_signature_verified = self
            .webhook_signature_verified
            .ok_or(CiImportError::MissingField("webhook_signature_verified"))?;

        if self.artifact_digests.len() > MAX_ARTIFACT_DIGESTS {
            return Err(CiImportError::TooManyArtifactDigests {
                count: self.artifact_digests.len(),
                max: MAX_ARTIFACT_DIGESTS,
            });
        }

        let attestation = self
            .attestation
            .ok_or(CiImportError::MissingField("attestation"))?;

        Ok(CiEvidenceImport {
            workflow_run_id,
            webhook_signature_verified,
            artifact_digests: self.artifact_digests,
            attestation,
        })
    }
}

// =============================================================================
// CiImportAttestation
// =============================================================================

/// CI import attestation event representing a validated CI evidence import.
///
/// This struct is emitted after [`validate_ci_import`] succeeds. It
/// cryptographically binds the import to the adapter that validated it.
///
/// # Fields
///
/// - `import_id`: Unique identifier for this import attestation
/// - `workflow_run_id`: The CI workflow run identifier
/// - `artifact_digests`: Hashes of artifacts stored in CAS
/// - `imported_at`: Timestamp (millis since epoch) when the import was created
/// - `adapter_signature`: Signature by the adapter over the attestation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CiImportAttestation {
    /// Unique identifier for this import attestation.
    import_id: String,

    /// The CI workflow run identifier.
    workflow_run_id: String,

    /// Hashes of artifacts stored in CAS.
    artifact_digests: Vec<Hash>,

    /// Timestamp (milliseconds since Unix epoch) when the import was created.
    imported_at: u64,

    /// Adapter signature over the attestation content.
    ///
    /// Uses the `CI_IMPORT_ATTESTATION:` domain prefix.
    #[serde(with = "signature_bytes")]
    adapter_signature: Signature,
}

/// Serde helper for signature bytes.
mod signature_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    use crate::crypto::Signature;

    pub fn serialize<S>(value: &Signature, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&value.to_bytes())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Signature, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        let arr: [u8; 64] = bytes
            .try_into()
            .map_err(|_| D::Error::custom("signature must be exactly 64 bytes"))?;
        Ok(Signature::from_bytes(&arr))
    }
}

impl CiImportAttestation {
    /// Creates a new builder for constructing a `CiImportAttestation`.
    #[must_use]
    pub fn builder() -> CiImportAttestationBuilder {
        CiImportAttestationBuilder::new()
    }

    /// Returns the import identifier.
    #[must_use]
    pub fn import_id(&self) -> &str {
        &self.import_id
    }

    /// Returns the workflow run identifier.
    #[must_use]
    pub fn workflow_run_id(&self) -> &str {
        &self.workflow_run_id
    }

    /// Returns the artifact digests.
    #[must_use]
    pub fn artifact_digests(&self) -> &[Hash] {
        &self.artifact_digests
    }

    /// Returns the import timestamp (millis since epoch).
    #[must_use]
    pub const fn imported_at(&self) -> u64 {
        self.imported_at
    }

    /// Returns the adapter signature.
    #[must_use]
    pub const fn adapter_signature(&self) -> &Signature {
        &self.adapter_signature
    }

    /// Computes the canonical bytes for signing/verification.
    ///
    /// The canonical format is:
    /// - `import_id` (length-prefixed)
    /// - `workflow_run_id` (length-prefixed)
    /// - `artifact_digests` count (4 bytes, big-endian)
    /// - Each digest (32 bytes each)
    /// - `imported_at` (8 bytes, big-endian)
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // import_id (length-prefixed)
        // Safety: import_id is limited to MAX_IMPORT_ID_LENGTH (256) by builder
        let id_bytes = self.import_id.as_bytes();
        bytes.extend_from_slice(&(id_bytes.len() as u32).to_be_bytes());
        bytes.extend_from_slice(id_bytes);

        // workflow_run_id (length-prefixed)
        // Safety: workflow_run_id is limited to MAX_WORKFLOW_RUN_ID_LENGTH (4096) by
        // builder
        let wf_bytes = self.workflow_run_id.as_bytes();
        bytes.extend_from_slice(&(wf_bytes.len() as u32).to_be_bytes());
        bytes.extend_from_slice(wf_bytes);

        // artifact_digests count + each digest
        // Safety: artifact_digests is limited to MAX_ARTIFACT_DIGESTS (1024) by builder
        bytes.extend_from_slice(&(self.artifact_digests.len() as u32).to_be_bytes());
        for digest in &self.artifact_digests {
            bytes.extend_from_slice(digest);
        }

        // imported_at
        bytes.extend_from_slice(&self.imported_at.to_be_bytes());

        bytes
    }

    /// Verifies the adapter signature.
    ///
    /// # Errors
    ///
    /// Returns [`CiImportError::SignatureVerificationFailed`] if the signature
    /// is invalid.
    pub fn verify_signature(
        &self,
        verifying_key: &crate::crypto::VerifyingKey,
    ) -> Result<(), CiImportError> {
        use super::domain_separator::verify_with_domain;

        let canonical = self.canonical_bytes();
        verify_with_domain(
            verifying_key,
            CI_IMPORT_ATTESTATION_PREFIX,
            &canonical,
            &self.adapter_signature,
        )
        .map_err(|_| CiImportError::SignatureVerificationFailed)
    }
}

// =============================================================================
// CiImportAttestation Builder
// =============================================================================

/// Builder for constructing [`CiImportAttestation`] instances.
#[derive(Debug, Default)]
pub struct CiImportAttestationBuilder {
    import_id: Option<String>,
    workflow_run_id: Option<String>,
    artifact_digests: Vec<Hash>,
    imported_at: Option<u64>,
}

impl CiImportAttestationBuilder {
    /// Creates a new builder with default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the import identifier.
    #[must_use]
    pub fn import_id(mut self, id: impl Into<String>) -> Self {
        self.import_id = Some(id.into());
        self
    }

    /// Sets the workflow run identifier.
    #[must_use]
    pub fn workflow_run_id(mut self, id: impl Into<String>) -> Self {
        self.workflow_run_id = Some(id.into());
        self
    }

    /// Adds an artifact digest.
    #[must_use]
    pub fn artifact_digest(mut self, digest: Hash) -> Self {
        self.artifact_digests.push(digest);
        self
    }

    /// Sets multiple artifact digests, replacing any previously added.
    #[must_use]
    pub fn artifact_digests(mut self, digests: impl IntoIterator<Item = Hash>) -> Self {
        self.artifact_digests = digests.into_iter().collect();
        self
    }

    /// Sets the import timestamp (millis since epoch).
    #[must_use]
    pub const fn imported_at(mut self, timestamp: u64) -> Self {
        self.imported_at = Some(timestamp);
        self
    }

    /// Builds and signs the [`CiImportAttestation`].
    ///
    /// # Errors
    ///
    /// Returns [`CiImportError`] if:
    /// - Required fields are missing
    /// - `import_id` exceeds [`MAX_IMPORT_ID_LENGTH`]
    /// - `workflow_run_id` exceeds [`MAX_WORKFLOW_RUN_ID_LENGTH`]
    /// - `artifact_digests` exceeds [`MAX_ARTIFACT_DIGESTS`]
    #[allow(clippy::cast_possible_truncation)]
    pub fn build_and_sign(self, signer: &Signer) -> Result<CiImportAttestation, CiImportError> {
        let import_id = self
            .import_id
            .ok_or(CiImportError::MissingField("import_id"))?;

        if import_id.len() > MAX_IMPORT_ID_LENGTH {
            return Err(CiImportError::StringTooLong {
                field: "import_id",
                length: import_id.len(),
                max: MAX_IMPORT_ID_LENGTH,
            });
        }

        let workflow_run_id = self
            .workflow_run_id
            .ok_or(CiImportError::MissingField("workflow_run_id"))?;

        if workflow_run_id.len() > MAX_WORKFLOW_RUN_ID_LENGTH {
            return Err(CiImportError::StringTooLong {
                field: "workflow_run_id",
                length: workflow_run_id.len(),
                max: MAX_WORKFLOW_RUN_ID_LENGTH,
            });
        }

        if self.artifact_digests.len() > MAX_ARTIFACT_DIGESTS {
            return Err(CiImportError::TooManyArtifactDigests {
                count: self.artifact_digests.len(),
                max: MAX_ARTIFACT_DIGESTS,
            });
        }

        let imported_at = self
            .imported_at
            .ok_or(CiImportError::MissingField("imported_at"))?;

        // Build a temporary struct to compute canonical bytes
        // We need to create the signature, but the struct requires it.
        // So we compute canonical bytes manually here.
        let mut canonical = Vec::new();

        // import_id (length-prefixed)
        let id_bytes = import_id.as_bytes();
        canonical.extend_from_slice(&(id_bytes.len() as u32).to_be_bytes());
        canonical.extend_from_slice(id_bytes);

        // workflow_run_id (length-prefixed)
        let wf_bytes = workflow_run_id.as_bytes();
        canonical.extend_from_slice(&(wf_bytes.len() as u32).to_be_bytes());
        canonical.extend_from_slice(wf_bytes);

        // artifact_digests count + each digest
        canonical.extend_from_slice(&(self.artifact_digests.len() as u32).to_be_bytes());
        for digest in &self.artifact_digests {
            canonical.extend_from_slice(digest);
        }

        // imported_at
        canonical.extend_from_slice(&imported_at.to_be_bytes());

        let adapter_signature = sign_with_domain(signer, CI_IMPORT_ATTESTATION_PREFIX, &canonical);

        Ok(CiImportAttestation {
            import_id,
            workflow_run_id,
            artifact_digests: self.artifact_digests,
            imported_at,
            adapter_signature,
        })
    }
}

// =============================================================================
// CiImportPolicy
// =============================================================================

/// Policy configuration for CI evidence import validation.
///
/// The policy specifies the minimum attestation level required and whether
/// CI gating is enabled. When CI gating is enabled, L0 (status-only)
/// attestations are rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CiImportPolicy {
    /// Minimum attestation level required for import to be valid.
    minimum_level: CiAttestationLevel,

    /// Whether CI gating is enabled.
    ///
    /// When enabled, L0 attestations are rejected regardless of
    /// `minimum_level`.
    ci_gating_enabled: bool,
}

impl CiImportPolicy {
    /// Creates a new CI import policy.
    ///
    /// # Arguments
    ///
    /// * `minimum_level` - The minimum attestation level required
    /// * `ci_gating_enabled` - Whether CI gating is enabled
    #[must_use]
    pub const fn new(minimum_level: CiAttestationLevel, ci_gating_enabled: bool) -> Self {
        Self {
            minimum_level,
            ci_gating_enabled,
        }
    }

    /// Returns the minimum attestation level.
    #[must_use]
    pub const fn minimum_level(&self) -> CiAttestationLevel {
        self.minimum_level
    }

    /// Returns whether CI gating is enabled.
    #[must_use]
    pub const fn ci_gating_enabled(&self) -> bool {
        self.ci_gating_enabled
    }

    /// Creates a permissive policy that accepts any attestation level.
    ///
    /// This policy:
    /// - Sets minimum level to L0
    /// - Disables CI gating
    ///
    /// Use only for testing or non-production environments.
    #[must_use]
    pub const fn permissive() -> Self {
        Self {
            minimum_level: CiAttestationLevel::L0,
            ci_gating_enabled: false,
        }
    }

    /// Creates a strict policy requiring L1 attestation with CI gating.
    ///
    /// This policy:
    /// - Sets minimum level to L1
    /// - Enables CI gating (rejects L0)
    #[must_use]
    pub const fn strict() -> Self {
        Self {
            minimum_level: CiAttestationLevel::L1,
            ci_gating_enabled: true,
        }
    }
}

impl Default for CiImportPolicy {
    /// Default policy is strict: requires L1 with CI gating enabled.
    fn default() -> Self {
        Self::strict()
    }
}

// =============================================================================
// Validation
// =============================================================================

/// Validates a CI evidence import against a policy with CAS verification.
///
/// This function performs three checks:
///
/// 1. **Webhook signature verification**: `webhook_signature_verified` must be
///    `true`
/// 2. **CAS verification**: All artifact digests must exist in the CAS
/// 3. **Attestation level check**: The attestation must meet the policy's
///    minimum level
///
/// When CI gating is enabled, L0 attestations are always rejected regardless
/// of the minimum level setting.
///
/// # Arguments
///
/// * `import` - The CI evidence import to validate
/// * `policy` - The policy to validate against
/// * `cas` - The content-addressed store to verify artifact digests
///
/// # Errors
///
/// Returns [`CiImportError`] if:
/// - Webhook signature was not verified
/// - Any artifact digest is not found in CAS
/// - Attestation level is below the minimum required
/// - L0 attestation is rejected when CI gating is enabled
///
/// # Example
///
/// ```rust
/// use apm2_core::evidence::{ContentAddressedStore, MemoryCas};
/// use apm2_core::fac::{
///     CiAttestation, CiAttestationLevel, CiEvidenceImport, CiImportPolicy,
///     validate_ci_import,
/// };
///
/// let import = CiEvidenceImport::builder()
///     .workflow_run_id("run-001")
///     .webhook_signature_verified(true)
///     .attestation(
///         CiAttestation::builder()
///             .level(CiAttestationLevel::L1)
///             .workflow_run_id("run-001")
///             .build()
///             .unwrap(),
///     )
///     .build()
///     .unwrap();
///
/// let policy = CiImportPolicy::strict();
/// let cas = MemoryCas::new();
///
/// // No artifact digests, so CAS check passes
/// let result = validate_ci_import(&import, &policy, &cas);
/// assert!(result.is_ok());
/// ```
pub fn validate_ci_import<C: ContentAddressedStore>(
    import: &CiEvidenceImport,
    policy: &CiImportPolicy,
    cas: &C,
) -> Result<(), CiImportError> {
    // Check 1: Webhook signature must be verified
    if !import.webhook_signature_verified {
        return Err(CiImportError::WebhookSignatureNotVerified);
    }

    // Check 2: All artifact digests must exist in CAS
    for digest in &import.artifact_digests {
        let exists = cas.exists(digest).map_err(CiImportError::CasError)?;
        if !exists {
            return Err(CiImportError::ArtifactNotInCas {
                digest: hex_encode(digest),
            });
        }
    }

    // Check 3: Attestation level must meet policy requirements
    let level = import.attestation.level();

    // If CI gating is enabled, L0 is always rejected
    if policy.ci_gating_enabled && !level.is_sufficient_for_gating() {
        return Err(CiImportError::L0RejectedWithGatingEnabled);
    }

    // Check minimum level
    if !import.attestation.meets_minimum(policy.minimum_level) {
        return Err(CiImportError::InsufficientAttestationLevel {
            actual: level,
            required: policy.minimum_level,
        });
    }

    Ok(())
}

/// Converts a hash to hex string for error messages.
fn hex_encode(hash: &Hash) -> String {
    use std::fmt::Write;
    hash.iter().fold(String::with_capacity(64), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

// =============================================================================
// Errors
// =============================================================================

/// Errors that can occur during CI import operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CiImportError {
    /// Missing required field.
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// String field exceeds maximum length.
    #[error("string field '{field}' too long: {length} > {max}")]
    StringTooLong {
        /// The field name.
        field: &'static str,
        /// The actual length.
        length: usize,
        /// The maximum allowed length.
        max: usize,
    },

    /// Too many artifact digests.
    #[error("too many artifact digests: {count} > {max}")]
    TooManyArtifactDigests {
        /// The actual count.
        count: usize,
        /// The maximum allowed count.
        max: usize,
    },

    /// Webhook signature was not verified.
    #[error("webhook signature was not verified")]
    WebhookSignatureNotVerified,

    /// Artifact digest not found in CAS.
    #[error("artifact digest not found in CAS: {digest}")]
    ArtifactNotInCas {
        /// The digest that was not found (hex-encoded).
        digest: String,
    },

    /// CAS operation error.
    #[error("CAS error: {0}")]
    CasError(#[from] CasError),

    /// Attestation level is insufficient.
    #[error("attestation level {actual} is insufficient, minimum required is {required}")]
    InsufficientAttestationLevel {
        /// The actual level.
        actual: CiAttestationLevel,
        /// The required level.
        required: CiAttestationLevel,
    },

    /// L0 attestation rejected when CI gating is enabled.
    #[error("L0 (status-only) attestation rejected: CI gating is enabled")]
    L0RejectedWithGatingEnabled,

    /// Signature verification failed.
    #[error("signature verification failed")]
    SignatureVerificationFailed,
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::crypto::Signer;
    use crate::evidence::MemoryCas;

    // =========================================================================
    // CiEvidenceImport Builder Tests
    // =========================================================================

    #[test]
    fn test_import_builder_minimal() {
        let attestation = CiAttestation::builder()
            .level(CiAttestationLevel::L1)
            .workflow_run_id("run-001")
            .build()
            .unwrap();

        let import = CiEvidenceImport::builder()
            .workflow_run_id("run-001")
            .webhook_signature_verified(true)
            .attestation(attestation)
            .build()
            .unwrap();

        assert_eq!(import.workflow_run_id(), "run-001");
        assert!(import.webhook_signature_verified());
        assert!(import.artifact_digests().is_empty());
    }

    #[test]
    fn test_import_builder_with_digests() {
        let attestation = CiAttestation::builder()
            .level(CiAttestationLevel::L1)
            .workflow_run_id("run-002")
            .build()
            .unwrap();

        let import = CiEvidenceImport::builder()
            .workflow_run_id("run-002")
            .webhook_signature_verified(true)
            .artifact_digest([0x11; 32])
            .artifact_digest([0x22; 32])
            .attestation(attestation)
            .build()
            .unwrap();

        assert_eq!(import.artifact_digests().len(), 2);
    }

    #[test]
    fn test_import_builder_missing_workflow_run_id() {
        let attestation = CiAttestation::builder()
            .level(CiAttestationLevel::L0)
            .build()
            .unwrap();

        let result = CiEvidenceImport::builder()
            .webhook_signature_verified(true)
            .attestation(attestation)
            .build();

        assert!(matches!(
            result,
            Err(CiImportError::MissingField("workflow_run_id"))
        ));
    }

    #[test]
    fn test_import_builder_missing_attestation() {
        let result = CiEvidenceImport::builder()
            .workflow_run_id("run-001")
            .webhook_signature_verified(true)
            .build();

        assert!(matches!(
            result,
            Err(CiImportError::MissingField("attestation"))
        ));
    }

    #[test]
    fn test_import_builder_too_many_digests() {
        let attestation = CiAttestation::builder()
            .level(CiAttestationLevel::L0)
            .build()
            .unwrap();

        let digests: Vec<Hash> = (0..=MAX_ARTIFACT_DIGESTS).map(|_| [0x00; 32]).collect();

        let result = CiEvidenceImport::builder()
            .workflow_run_id("run-001")
            .webhook_signature_verified(true)
            .artifact_digests(digests)
            .attestation(attestation)
            .build();

        assert!(matches!(
            result,
            Err(CiImportError::TooManyArtifactDigests { .. })
        ));
    }

    // =========================================================================
    // Webhook Signature Verification Tests
    // =========================================================================

    #[test]
    fn test_webhook_signature_not_verified_rejected() {
        let attestation = CiAttestation::builder()
            .level(CiAttestationLevel::L1)
            .workflow_run_id("run-001")
            .build()
            .unwrap();

        let import = CiEvidenceImport::builder()
            .workflow_run_id("run-001")
            .webhook_signature_verified(false) // Not verified!
            .attestation(attestation)
            .build()
            .unwrap();

        let policy = CiImportPolicy::permissive();
        let cas = MemoryCas::new();

        let result = validate_ci_import(&import, &policy, &cas);
        assert!(matches!(
            result,
            Err(CiImportError::WebhookSignatureNotVerified)
        ));
    }

    #[test]
    fn test_webhook_signature_verified_accepted() {
        let attestation = CiAttestation::builder()
            .level(CiAttestationLevel::L1)
            .workflow_run_id("run-001")
            .build()
            .unwrap();

        let import = CiEvidenceImport::builder()
            .workflow_run_id("run-001")
            .webhook_signature_verified(true)
            .attestation(attestation)
            .build()
            .unwrap();

        let policy = CiImportPolicy::permissive();
        let cas = MemoryCas::new();

        let result = validate_ci_import(&import, &policy, &cas);
        assert!(result.is_ok());
    }

    // =========================================================================
    // CAS Verification Tests
    // =========================================================================

    #[test]
    fn test_artifact_not_in_cas_rejected() {
        let attestation = CiAttestation::builder()
            .level(CiAttestationLevel::L1)
            .workflow_run_id("run-001")
            .build()
            .unwrap();

        let import = CiEvidenceImport::builder()
            .workflow_run_id("run-001")
            .webhook_signature_verified(true)
            .artifact_digest([0xAB; 32]) // This digest is not in CAS
            .attestation(attestation)
            .build()
            .unwrap();

        let policy = CiImportPolicy::permissive();
        let cas = MemoryCas::new();

        let result = validate_ci_import(&import, &policy, &cas);
        assert!(matches!(
            result,
            Err(CiImportError::ArtifactNotInCas { .. })
        ));
    }

    #[test]
    fn test_artifact_in_cas_accepted() {
        let attestation = CiAttestation::builder()
            .level(CiAttestationLevel::L1)
            .workflow_run_id("run-001")
            .build()
            .unwrap();

        let cas = MemoryCas::new();
        // Store content in CAS and get its hash
        let content = b"test artifact content";
        let store_result = cas.store(content).unwrap();

        let import = CiEvidenceImport::builder()
            .workflow_run_id("run-001")
            .webhook_signature_verified(true)
            .artifact_digest(store_result.hash) // This digest IS in CAS
            .attestation(attestation)
            .build()
            .unwrap();

        let policy = CiImportPolicy::permissive();

        let result = validate_ci_import(&import, &policy, &cas);
        assert!(result.is_ok());
    }

    #[test]
    fn test_multiple_artifacts_all_in_cas() {
        let attestation = CiAttestation::builder()
            .level(CiAttestationLevel::L1)
            .workflow_run_id("run-002")
            .build()
            .unwrap();

        let cas = MemoryCas::new();
        let hash1 = cas.store(b"artifact 1").unwrap().hash;
        let hash2 = cas.store(b"artifact 2").unwrap().hash;

        let import = CiEvidenceImport::builder()
            .workflow_run_id("run-002")
            .webhook_signature_verified(true)
            .artifact_digest(hash1)
            .artifact_digest(hash2)
            .attestation(attestation)
            .build()
            .unwrap();

        let policy = CiImportPolicy::permissive();

        let result = validate_ci_import(&import, &policy, &cas);
        assert!(result.is_ok());
    }

    #[test]
    fn test_one_missing_artifact_rejects_all() {
        let attestation = CiAttestation::builder()
            .level(CiAttestationLevel::L1)
            .workflow_run_id("run-003")
            .build()
            .unwrap();

        let cas = MemoryCas::new();
        let hash1 = cas.store(b"artifact 1").unwrap().hash;
        let missing_hash = [0xFF; 32]; // Not in CAS

        let import = CiEvidenceImport::builder()
            .workflow_run_id("run-003")
            .webhook_signature_verified(true)
            .artifact_digest(hash1)
            .artifact_digest(missing_hash)
            .attestation(attestation)
            .build()
            .unwrap();

        let policy = CiImportPolicy::permissive();

        let result = validate_ci_import(&import, &policy, &cas);
        assert!(matches!(
            result,
            Err(CiImportError::ArtifactNotInCas { .. })
        ));
    }

    // =========================================================================
    // Attestation Level Check Tests
    // =========================================================================

    #[test]
    fn test_l0_rejected_with_gating_enabled() {
        let attestation = CiAttestation::builder()
            .level(CiAttestationLevel::L0)
            .build()
            .unwrap();

        let import = CiEvidenceImport::builder()
            .workflow_run_id("run-001")
            .webhook_signature_verified(true)
            .attestation(attestation)
            .build()
            .unwrap();

        // CI gating enabled - L0 should be rejected
        let policy = CiImportPolicy::new(CiAttestationLevel::L0, true);
        let cas = MemoryCas::new();

        let result = validate_ci_import(&import, &policy, &cas);
        assert!(matches!(
            result,
            Err(CiImportError::L0RejectedWithGatingEnabled)
        ));
    }

    #[test]
    fn test_l0_accepted_with_gating_disabled() {
        let attestation = CiAttestation::builder()
            .level(CiAttestationLevel::L0)
            .build()
            .unwrap();

        let import = CiEvidenceImport::builder()
            .workflow_run_id("run-001")
            .webhook_signature_verified(true)
            .attestation(attestation)
            .build()
            .unwrap();

        // CI gating disabled - L0 should be accepted
        let policy = CiImportPolicy::new(CiAttestationLevel::L0, false);
        let cas = MemoryCas::new();

        let result = validate_ci_import(&import, &policy, &cas);
        assert!(result.is_ok());
    }

    #[test]
    fn test_l1_meets_l1_requirement() {
        let attestation = CiAttestation::builder()
            .level(CiAttestationLevel::L1)
            .workflow_run_id("run-001")
            .build()
            .unwrap();

        let import = CiEvidenceImport::builder()
            .workflow_run_id("run-001")
            .webhook_signature_verified(true)
            .attestation(attestation)
            .build()
            .unwrap();

        let policy = CiImportPolicy::strict(); // Requires L1
        let cas = MemoryCas::new();

        let result = validate_ci_import(&import, &policy, &cas);
        assert!(result.is_ok());
    }

    #[test]
    fn test_l0_does_not_meet_l1_requirement() {
        let attestation = CiAttestation::builder()
            .level(CiAttestationLevel::L0)
            .build()
            .unwrap();

        let import = CiEvidenceImport::builder()
            .workflow_run_id("run-001")
            .webhook_signature_verified(true)
            .attestation(attestation)
            .build()
            .unwrap();

        // Even with gating disabled, L0 doesn't meet L1 minimum
        let policy = CiImportPolicy::new(CiAttestationLevel::L1, false);
        let cas = MemoryCas::new();

        let result = validate_ci_import(&import, &policy, &cas);
        assert!(matches!(
            result,
            Err(CiImportError::InsufficientAttestationLevel { .. })
        ));
    }

    #[test]
    fn test_l2_exceeds_l1_requirement() {
        let attestation = CiAttestation::builder()
            .level(CiAttestationLevel::L2)
            .workflow_run_id("run-001")
            .build()
            .unwrap();

        let import = CiEvidenceImport::builder()
            .workflow_run_id("run-001")
            .webhook_signature_verified(true)
            .attestation(attestation)
            .build()
            .unwrap();

        let policy = CiImportPolicy::strict(); // Requires L1
        let cas = MemoryCas::new();

        let result = validate_ci_import(&import, &policy, &cas);
        assert!(result.is_ok()); // L2 > L1, so it passes
    }

    // =========================================================================
    // CiImportPolicy Tests
    // =========================================================================

    #[test]
    fn test_policy_permissive() {
        let policy = CiImportPolicy::permissive();
        assert_eq!(policy.minimum_level(), CiAttestationLevel::L0);
        assert!(!policy.ci_gating_enabled());
    }

    #[test]
    fn test_policy_strict() {
        let policy = CiImportPolicy::strict();
        assert_eq!(policy.minimum_level(), CiAttestationLevel::L1);
        assert!(policy.ci_gating_enabled());
    }

    #[test]
    fn test_policy_default_is_strict() {
        let policy = CiImportPolicy::default();
        assert_eq!(policy.minimum_level(), CiAttestationLevel::L1);
        assert!(policy.ci_gating_enabled());
    }

    // =========================================================================
    // CiImportAttestation Tests
    // =========================================================================

    #[test]
    fn test_import_attestation_builder() {
        let signer = Signer::generate();

        let attestation = CiImportAttestation::builder()
            .import_id("import-001")
            .workflow_run_id("run-001")
            .artifact_digest([0x11; 32])
            .imported_at(1_704_067_200_000)
            .build_and_sign(&signer)
            .unwrap();

        assert_eq!(attestation.import_id(), "import-001");
        assert_eq!(attestation.workflow_run_id(), "run-001");
        assert_eq!(attestation.artifact_digests().len(), 1);
        assert_eq!(attestation.imported_at(), 1_704_067_200_000);
    }

    #[test]
    fn test_import_attestation_signature_verification() {
        let signer = Signer::generate();

        let attestation = CiImportAttestation::builder()
            .import_id("import-002")
            .workflow_run_id("run-002")
            .imported_at(1_704_067_200_000)
            .build_and_sign(&signer)
            .unwrap();

        // Verification should succeed with correct key
        assert!(
            attestation
                .verify_signature(&signer.verifying_key())
                .is_ok()
        );

        // Verification should fail with wrong key
        let wrong_signer = Signer::generate();
        assert!(
            attestation
                .verify_signature(&wrong_signer.verifying_key())
                .is_err()
        );
    }

    #[test]
    fn test_import_attestation_canonical_bytes_deterministic() {
        let signer = Signer::generate();

        let att1 = CiImportAttestation::builder()
            .import_id("import-003")
            .workflow_run_id("run-003")
            .artifact_digest([0xAA; 32])
            .imported_at(1_704_067_200_000)
            .build_and_sign(&signer)
            .unwrap();

        let att2 = CiImportAttestation::builder()
            .import_id("import-003")
            .workflow_run_id("run-003")
            .artifact_digest([0xAA; 32])
            .imported_at(1_704_067_200_000)
            .build_and_sign(&signer)
            .unwrap();

        // Canonical bytes should be identical
        assert_eq!(att1.canonical_bytes(), att2.canonical_bytes());

        // Signatures should also be identical (Ed25519 is deterministic)
        assert_eq!(
            att1.adapter_signature().to_bytes(),
            att2.adapter_signature().to_bytes()
        );
    }

    #[test]
    fn test_import_attestation_missing_fields() {
        let signer = Signer::generate();

        // Missing import_id
        let result = CiImportAttestation::builder()
            .workflow_run_id("run-001")
            .imported_at(1_704_067_200_000)
            .build_and_sign(&signer);
        assert!(matches!(
            result,
            Err(CiImportError::MissingField("import_id"))
        ));

        // Missing workflow_run_id
        let result = CiImportAttestation::builder()
            .import_id("import-001")
            .imported_at(1_704_067_200_000)
            .build_and_sign(&signer);
        assert!(matches!(
            result,
            Err(CiImportError::MissingField("workflow_run_id"))
        ));

        // Missing imported_at
        let result = CiImportAttestation::builder()
            .import_id("import-001")
            .workflow_run_id("run-001")
            .build_and_sign(&signer);
        assert!(matches!(
            result,
            Err(CiImportError::MissingField("imported_at"))
        ));
    }

    // =========================================================================
    // Integration Tests
    // =========================================================================

    #[test]
    fn test_full_import_validation_flow() {
        // 1. Set up CAS with some artifacts
        let cas = MemoryCas::new();
        let artifact1 = cas.store(b"build artifact").unwrap();
        let artifact2 = cas.store(b"test results").unwrap();

        // 2. Create a valid L1 attestation
        let attestation = CiAttestation::builder()
            .level(CiAttestationLevel::L1)
            .workflow_run_id("github-actions-run-12345")
            .downloaded_artifact_hash([0x11; 32])
            .build()
            .unwrap();

        // 3. Create the import
        let import = CiEvidenceImport::builder()
            .workflow_run_id("github-actions-run-12345")
            .webhook_signature_verified(true)
            .artifact_digest(artifact1.hash)
            .artifact_digest(artifact2.hash)
            .attestation(attestation)
            .build()
            .unwrap();

        // 4. Validate with strict policy
        let policy = CiImportPolicy::strict();
        let result = validate_ci_import(&import, &policy, &cas);
        assert!(result.is_ok());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let attestation = CiAttestation::builder()
            .level(CiAttestationLevel::L1)
            .workflow_run_id("run-serde")
            .build()
            .unwrap();

        let import = CiEvidenceImport::builder()
            .workflow_run_id("run-serde")
            .webhook_signature_verified(true)
            .artifact_digest([0xAA; 32])
            .attestation(attestation)
            .build()
            .unwrap();

        let json = serde_json::to_string(&import).unwrap();
        let deserialized: CiEvidenceImport = serde_json::from_str(&json).unwrap();
        assert_eq!(import, deserialized);
    }
}
