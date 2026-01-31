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
///
/// # Security
///
/// Deserialization enforces the same resource limits as the builder:
/// - `workflow_run_id` is limited to [`MAX_WORKFLOW_RUN_ID_LENGTH`] bytes
/// - `artifact_digests` is limited to [`MAX_ARTIFACT_DIGESTS`] entries
/// - `webhook_signature_verified` is **always** set to `false` during
///   deserialization to prevent security invariant bypass via crafted JSON
///   payloads
///
/// This prevents denial-of-service attacks via oversized payloads and ensures
/// webhook signature verification cannot be bypassed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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

/// Custom deserialization that enforces resource limits and security
/// invariants.
///
/// This implementation:
/// 1. **Always** sets `webhook_signature_verified` to `false` - this field is
///    ignored during deserialization to prevent security bypass attacks
///    (SEC-CTRL-FAC-0016)
/// 2. Validates `workflow_run_id.len() <= MAX_WORKFLOW_RUN_ID_LENGTH`
/// 3. Validates `artifact_digests.len() <= MAX_ARTIFACT_DIGESTS`
///
/// This prevents:
/// - Security invariant bypass via crafted JSON with
///   `"webhook_signature_verified": true`
/// - Denial-of-service attacks via oversized payloads
impl<'de> Deserialize<'de> for CiEvidenceImport {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        // Helper struct for deserialization.
        // webhook_signature_verified is captured but ignored - it MUST always
        // be false after deserialization to prevent security invariant bypass.
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct CiEvidenceImportHelper {
            workflow_run_id: String,
            // This field is present to allow deserialization of serialized data,
            // but its value is IGNORED - we always set it to false.
            #[serde(default)]
            #[allow(dead_code)]
            webhook_signature_verified: bool,
            artifact_digests: Vec<Hash>,
            attestation: CiAttestation,
        }

        let helper = CiEvidenceImportHelper::deserialize(deserializer)?;

        // Validate workflow_run_id length
        if helper.workflow_run_id.len() > MAX_WORKFLOW_RUN_ID_LENGTH {
            return Err(D::Error::custom(format!(
                "workflow_run_id exceeds maximum length: {} > {MAX_WORKFLOW_RUN_ID_LENGTH}",
                helper.workflow_run_id.len(),
            )));
        }

        // Validate artifact_digests count
        if helper.artifact_digests.len() > MAX_ARTIFACT_DIGESTS {
            return Err(D::Error::custom(format!(
                "too many artifact digests: {} > {MAX_ARTIFACT_DIGESTS}",
                helper.artifact_digests.len(),
            )));
        }

        Ok(Self {
            workflow_run_id: helper.workflow_run_id,
            // SECURITY: Always false after deserialization.
            // The webhook signature must be verified by the receiving code,
            // not trusted from wire data. The helper.webhook_signature_verified
            // value is intentionally ignored.
            webhook_signature_verified: false,
            artifact_digests: helper.artifact_digests,
            attestation: helper.attestation,
        })
    }
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
///
/// # Security
///
/// Deserialization enforces the same resource limits as the builder:
/// - `import_id` is limited to [`MAX_IMPORT_ID_LENGTH`] bytes
/// - `workflow_run_id` is limited to [`MAX_WORKFLOW_RUN_ID_LENGTH`] bytes
/// - `artifact_digests` is limited to [`MAX_ARTIFACT_DIGESTS`] entries
/// - `adapter_signature` is validated to be exactly 64 bytes
///
/// This prevents denial-of-service attacks via oversized payloads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
///
/// # Security
///
/// The deserializer uses a custom visitor that deserializes directly into
/// a `[u8; 64]` array without allocating an unbounded `Vec<u8>` first.
/// This prevents denial-of-service attacks via oversized signature payloads.
mod signature_bytes {
    use serde::de::{Error, SeqAccess, Visitor};
    use serde::{Deserializer, Serializer};

    use crate::crypto::Signature;

    /// Expected signature length in bytes.
    const SIGNATURE_LENGTH: usize = 64;

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
        deserializer.deserialize_seq(SignatureBytesVisitor)
    }

    /// Visitor that deserializes signature bytes directly into a fixed-size
    /// array.
    ///
    /// This avoids allocating an unbounded `Vec<u8>` before checking length,
    /// preventing denial-of-service via oversized payloads.
    struct SignatureBytesVisitor;

    impl<'de> Visitor<'de> for SignatureBytesVisitor {
        type Value = Signature;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(formatter, "a sequence of exactly {SIGNATURE_LENGTH} bytes")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut arr = [0u8; SIGNATURE_LENGTH];

            for (i, byte) in arr.iter_mut().enumerate() {
                *byte = seq
                    .next_element()?
                    .ok_or_else(|| A::Error::invalid_length(i, &self))?;
            }

            // Verify no extra elements (reject oversized input)
            if seq.next_element::<u8>()?.is_some() {
                return Err(A::Error::invalid_length(SIGNATURE_LENGTH + 1, &self));
            }

            Ok(Signature::from_bytes(&arr))
        }

        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
        where
            E: Error,
        {
            let arr: [u8; SIGNATURE_LENGTH] = v
                .try_into()
                .map_err(|_| E::invalid_length(v.len(), &self))?;
            Ok(Signature::from_bytes(&arr))
        }
    }
}

/// Custom deserialization that enforces resource limits.
///
/// This implementation:
/// 1. Validates `import_id.len() <= MAX_IMPORT_ID_LENGTH`
/// 2. Validates `workflow_run_id.len() <= MAX_WORKFLOW_RUN_ID_LENGTH`
/// 3. Validates `artifact_digests.len() <= MAX_ARTIFACT_DIGESTS`
///
/// This prevents denial-of-service attacks via oversized payloads.
impl<'de> Deserialize<'de> for CiImportAttestation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        // Helper struct for deserialization with bounded signature handling.
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct CiImportAttestationHelper {
            import_id: String,
            workflow_run_id: String,
            artifact_digests: Vec<Hash>,
            imported_at: u64,
            #[serde(with = "signature_bytes")]
            adapter_signature: Signature,
        }

        let helper = CiImportAttestationHelper::deserialize(deserializer)?;

        // Validate import_id length
        if helper.import_id.len() > MAX_IMPORT_ID_LENGTH {
            return Err(D::Error::custom(format!(
                "import_id exceeds maximum length: {} > {MAX_IMPORT_ID_LENGTH}",
                helper.import_id.len(),
            )));
        }

        // Validate workflow_run_id length
        if helper.workflow_run_id.len() > MAX_WORKFLOW_RUN_ID_LENGTH {
            return Err(D::Error::custom(format!(
                "workflow_run_id exceeds maximum length: {} > {MAX_WORKFLOW_RUN_ID_LENGTH}",
                helper.workflow_run_id.len(),
            )));
        }

        // Validate artifact_digests count
        if helper.artifact_digests.len() > MAX_ARTIFACT_DIGESTS {
            return Err(D::Error::custom(format!(
                "too many artifact digests: {} > {MAX_ARTIFACT_DIGESTS}",
                helper.artifact_digests.len(),
            )));
        }

        Ok(Self {
            import_id: helper.import_id,
            workflow_run_id: helper.workflow_run_id,
            artifact_digests: helper.artifact_digests,
            imported_at: helper.imported_at,
            adapter_signature: helper.adapter_signature,
        })
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
// Transition Gate
// =============================================================================

/// Checks whether a `READY_FOR_REVIEW` transition is allowed based on CI
/// evidence.
///
/// This function implements the transition gate for moving to
/// `READY_FOR_REVIEW` state. When CI gating is enabled, valid CI evidence with
/// attestation level L1 or higher is required. This enforces fail-closed
/// semantics (SEC-CTRL-FAC-0015).
///
/// # Arguments
///
/// * `ci_enabled` - Whether CI gating is enabled for this workflow
/// * `import` - Optional CI evidence import to validate
///
/// # Errors
///
/// Returns [`CiImportError`] if:
/// - [`CiImportError::CiEvidenceMissing`]: CI gating is enabled but no import
///   was provided
/// - [`CiImportError::WebhookSignatureNotVerified`]: The webhook signature was
///   not verified (SEC-CTRL-FAC-0017)
/// - [`CiImportError::InsufficientAttestationLevel`]: The attestation level
///   does not meet the policy minimum
///
/// # Security
///
/// When CI gating is enabled:
/// - Plain "success" status without evidence is rejected (`CiEvidenceMissing`)
/// - Unverified webhook signatures are rejected (`WebhookSignatureNotVerified`)
/// - Attestation below the policy minimum is rejected
///   (`InsufficientAttestationLevel`)
/// - Attestation meeting or exceeding the policy minimum with verified webhook
///   signature is required for transition approval
///
/// # Example
///
/// ```rust
/// use apm2_core::fac::{
///     CiAttestation, CiAttestationLevel, CiEvidenceImport, CiImportError,
///     can_transition_to_ready_for_review,
/// };
///
/// // CI gating disabled - always allowed (minimum_level ignored)
/// assert!(
///     can_transition_to_ready_for_review(false, None, CiAttestationLevel::L1)
///         .is_ok()
/// );
///
/// // CI gating enabled with no evidence - rejected
/// let result =
///     can_transition_to_ready_for_review(true, None, CiAttestationLevel::L1);
/// assert!(matches!(result, Err(CiImportError::CiEvidenceMissing)));
///
/// // CI gating enabled with unverified signature - rejected
/// let unverified_attestation = CiAttestation::builder()
///     .level(CiAttestationLevel::L1)
///     .workflow_run_id("run-001")
///     .build()
///     .unwrap();
/// let unverified_import = CiEvidenceImport::builder()
///     .workflow_run_id("run-001")
///     .webhook_signature_verified(false)
///     .attestation(unverified_attestation)
///     .build()
///     .unwrap();
/// let result = can_transition_to_ready_for_review(
///     true,
///     Some(&unverified_import),
///     CiAttestationLevel::L1,
/// );
/// assert!(matches!(
///     result,
///     Err(CiImportError::WebhookSignatureNotVerified)
/// ));
///
/// // CI gating enabled with L0 when L1 required - rejected
/// let l0_attestation = CiAttestation::builder()
///     .level(CiAttestationLevel::L0)
///     .build()
///     .unwrap();
/// let l0_import = CiEvidenceImport::builder()
///     .workflow_run_id("run-001")
///     .webhook_signature_verified(true)
///     .attestation(l0_attestation)
///     .build()
///     .unwrap();
/// let result = can_transition_to_ready_for_review(
///     true,
///     Some(&l0_import),
///     CiAttestationLevel::L1,
/// );
/// assert!(matches!(
///     result,
///     Err(CiImportError::InsufficientAttestationLevel { .. })
/// ));
///
/// // CI gating enabled with L1 meeting L1 requirement - allowed
/// let l1_attestation = CiAttestation::builder()
///     .level(CiAttestationLevel::L1)
///     .workflow_run_id("run-001")
///     .build()
///     .unwrap();
/// let l1_import = CiEvidenceImport::builder()
///     .workflow_run_id("run-001")
///     .webhook_signature_verified(true)
///     .attestation(l1_attestation)
///     .build()
///     .unwrap();
/// assert!(
///     can_transition_to_ready_for_review(
///         true,
///         Some(&l1_import),
///         CiAttestationLevel::L1
///     )
///     .is_ok()
/// );
///
/// // Policy requiring L2 for high-risk scenarios
/// let l1_for_l2 = CiEvidenceImport::builder()
///     .workflow_run_id("run-002")
///     .webhook_signature_verified(true)
///     .attestation(
///         CiAttestation::builder()
///             .level(CiAttestationLevel::L1)
///             .workflow_run_id("run-002")
///             .build()
///             .unwrap(),
///     )
///     .build()
///     .unwrap();
/// // L1 does not meet L2 requirement
/// let result = can_transition_to_ready_for_review(
///     true,
///     Some(&l1_for_l2),
///     CiAttestationLevel::L2,
/// );
/// assert!(matches!(
///     result,
///     Err(CiImportError::InsufficientAttestationLevel {
///         actual: CiAttestationLevel::L1,
///         required: CiAttestationLevel::L2,
///     })
/// ));
/// ```
pub fn can_transition_to_ready_for_review(
    ci_enabled: bool,
    import: Option<&CiEvidenceImport>,
    minimum_level: CiAttestationLevel,
) -> Result<(), CiImportError> {
    // If CI gating is disabled, transition is always allowed
    if !ci_enabled {
        return Ok(());
    }

    // CI gating is enabled - evidence is required
    let import = import.ok_or(CiImportError::CiEvidenceMissing)?;

    // SEC-CTRL-FAC-0017: Webhook signature must be verified
    // This prevents spoofed/unverified CI evidence from authorizing transitions
    if !import.webhook_signature_verified() {
        return Err(CiImportError::WebhookSignatureNotVerified);
    }

    // Check attestation level against policy minimum
    let actual_level = import.attestation.level();
    if !import.attestation.meets_minimum(minimum_level) {
        return Err(CiImportError::InsufficientAttestationLevel {
            actual: actual_level,
            required: minimum_level,
        });
    }

    Ok(())
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

    /// CI evidence is missing when required for transition.
    ///
    /// Returned by [`can_transition_to_ready_for_review`] when CI gating is
    /// enabled but no CI evidence import was provided. This enforces
    /// fail-closed semantics (SEC-CTRL-FAC-0015).
    #[error("CI evidence is required for READY_FOR_REVIEW transition")]
    CiEvidenceMissing,
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

        // Create with webhook_signature_verified = false to match post-deserialization
        // state
        let import = CiEvidenceImport::builder()
            .workflow_run_id("run-serde")
            .webhook_signature_verified(false)
            .artifact_digest([0xAA; 32])
            .attestation(attestation)
            .build()
            .unwrap();

        let json = serde_json::to_string(&import).unwrap();
        let deserialized: CiEvidenceImport = serde_json::from_str(&json).unwrap();

        // After roundtrip, webhook_signature_verified is always false (security
        // invariant)
        assert_eq!(import, deserialized);
        assert!(!deserialized.webhook_signature_verified());
    }

    // =========================================================================
    // Deserialization Security Tests (Negative Tests)
    // =========================================================================

    /// SEC-CTRL-FAC-0016: Tests that `webhook_signature_verified` is ALWAYS
    /// false after deserialization, regardless of what the JSON payload
    /// contains. This prevents attackers from bypassing signature verification
    /// by crafting malicious JSON with `webhook_signature_verified: true`.
    #[test]
    fn test_deser_webhook_signature_verified_bypass_prevented() {
        // Craft malicious JSON with webhook_signature_verified = true
        let malicious_json = r#"{
            "workflow_run_id": "attacker-run",
            "webhook_signature_verified": true,
            "artifact_digests": [],
            "attestation": {
                "level": "L1",
                "workflow_run_id": "attacker-run",
                "downloaded_artifact_hashes": []
            }
        }"#;

        let import: CiEvidenceImport = serde_json::from_str(malicious_json).unwrap();

        // SECURITY: webhook_signature_verified MUST be false regardless of JSON input
        assert!(
            !import.webhook_signature_verified(),
            "webhook_signature_verified must ALWAYS be false after deserialization"
        );

        // Validation should fail because webhook signature is not verified
        let policy = CiImportPolicy::permissive();
        let cas = MemoryCas::new();
        let result = validate_ci_import(&import, &policy, &cas);
        assert!(
            matches!(result, Err(CiImportError::WebhookSignatureNotVerified)),
            "import with deserialized webhook_signature_verified=true must fail validation"
        );
    }

    /// Tests that oversized `workflow_run_id` is rejected during
    /// deserialization. This prevents denial-of-service attacks via unbounded
    /// string allocation.
    #[test]
    fn test_deser_rejects_oversized_workflow_run_id() {
        let oversized_id = "x".repeat(MAX_WORKFLOW_RUN_ID_LENGTH + 1);

        let json = format!(
            r#"{{
                "workflow_run_id": "{oversized_id}",
                "webhook_signature_verified": false,
                "artifact_digests": [],
                "attestation": {{
                    "level": "L0",
                    "workflow_run_id": "",
                    "downloaded_artifact_hashes": []
                }}
            }}"#,
        );

        let result: Result<CiEvidenceImport, _> = serde_json::from_str(&json);
        assert!(
            result.is_err(),
            "oversized workflow_run_id must be rejected"
        );

        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("workflow_run_id exceeds maximum length"),
            "error message should mention workflow_run_id limit: {error_msg}"
        );
    }

    /// Tests that too many `artifact_digests` is rejected during
    /// deserialization. This prevents denial-of-service attacks via unbounded
    /// array allocation.
    #[test]
    fn test_deser_rejects_too_many_artifact_digests() {
        // Create JSON with MAX_ARTIFACT_DIGESTS + 1 entries
        // Hash is serialized as an array of 32 bytes
        let hash_array = "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]";
        let digests: Vec<&str> = (0..=MAX_ARTIFACT_DIGESTS).map(|_| hash_array).collect();
        let digests_json = digests.join(",");

        let json = format!(
            r#"{{
                "workflow_run_id": "test-run",
                "webhook_signature_verified": false,
                "artifact_digests": [{digests_json}],
                "attestation": {{
                    "level": "L0",
                    "workflow_run_id": "",
                    "downloaded_artifact_hashes": []
                }}
            }}"#,
        );

        let result: Result<CiEvidenceImport, _> = serde_json::from_str(&json);
        assert!(
            result.is_err(),
            "too many artifact_digests must be rejected"
        );

        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("too many artifact digests"),
            "error message should mention artifact digests limit: {error_msg}"
        );
    }

    /// Tests that maximum allowed sizes are accepted (boundary test).
    #[test]
    fn test_deser_accepts_max_allowed_sizes() {
        let max_id = "x".repeat(MAX_WORKFLOW_RUN_ID_LENGTH);

        let json = format!(
            r#"{{
                "workflow_run_id": "{max_id}",
                "webhook_signature_verified": false,
                "artifact_digests": [],
                "attestation": {{
                    "level": "L0",
                    "workflow_run_id": "",
                    "downloaded_artifact_hashes": []
                }}
            }}"#,
        );

        let result: Result<CiEvidenceImport, _> = serde_json::from_str(&json);
        assert!(
            result.is_ok(),
            "max allowed workflow_run_id length should be accepted"
        );
    }

    /// Tests that a serialized import with `webhook_signature_verified=true`
    /// deserializes with `webhook_signature_verified=false`, ensuring that
    /// persisted data cannot be used to bypass security checks.
    #[test]
    fn test_deser_resets_signature_flag_from_trusted_source() {
        // Simulate a trusted source (e.g., database) that has stored
        // webhook_signature_verified = true
        let attestation = CiAttestation::builder()
            .level(CiAttestationLevel::L1)
            .workflow_run_id("trusted-run")
            .build()
            .unwrap();

        let original = CiEvidenceImport::builder()
            .workflow_run_id("trusted-run")
            .webhook_signature_verified(true)
            .attestation(attestation)
            .build()
            .unwrap();

        // Serialize and deserialize (simulates loading from storage)
        let json = serde_json::to_string(&original).unwrap();
        let loaded: CiEvidenceImport = serde_json::from_str(&json).unwrap();

        // Even though the original had webhook_signature_verified = true,
        // the deserialized version MUST have it as false
        assert!(original.webhook_signature_verified());
        assert!(
            !loaded.webhook_signature_verified(),
            "webhook_signature_verified must be reset to false on deserialization"
        );
    }

    // =========================================================================
    // CiImportAttestation Deserialization Security Tests
    // =========================================================================

    /// Helper to create a valid signature bytes array for test JSON.
    fn test_signature_bytes_json() -> String {
        // 64 zeros serialized as JSON array
        let bytes: Vec<u8> = vec![0u8; 64];
        serde_json::to_string(&bytes).unwrap()
    }

    /// Tests that oversized `import_id` is rejected during deserialization.
    #[test]
    fn test_attestation_deser_rejects_oversized_import_id() {
        let oversized_id = "x".repeat(MAX_IMPORT_ID_LENGTH + 1);
        let sig_bytes = test_signature_bytes_json();

        let json = format!(
            r#"{{
                "import_id": "{oversized_id}",
                "workflow_run_id": "run-001",
                "artifact_digests": [],
                "imported_at": 1704067200000,
                "adapter_signature": {sig_bytes}
            }}"#,
        );

        let result: Result<CiImportAttestation, _> = serde_json::from_str(&json);
        assert!(result.is_err(), "oversized import_id must be rejected");

        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("import_id exceeds maximum length"),
            "error message should mention import_id limit: {error_msg}"
        );
    }

    /// Tests that oversized `workflow_run_id` is rejected during
    /// `CiImportAttestation` deserialization.
    #[test]
    fn test_attestation_deser_rejects_oversized_workflow_run_id() {
        let oversized_id = "x".repeat(MAX_WORKFLOW_RUN_ID_LENGTH + 1);
        let sig_bytes = test_signature_bytes_json();

        let json = format!(
            r#"{{
                "import_id": "import-001",
                "workflow_run_id": "{oversized_id}",
                "artifact_digests": [],
                "imported_at": 1704067200000,
                "adapter_signature": {sig_bytes}
            }}"#,
        );

        let result: Result<CiImportAttestation, _> = serde_json::from_str(&json);
        assert!(
            result.is_err(),
            "oversized workflow_run_id must be rejected"
        );

        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("workflow_run_id exceeds maximum length"),
            "error message should mention workflow_run_id limit: {error_msg}"
        );
    }

    /// Tests that too many `artifact_digests` is rejected during
    /// `CiImportAttestation` deserialization.
    #[test]
    fn test_attestation_deser_rejects_too_many_artifact_digests() {
        let hash_array = "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]";
        let digests: Vec<&str> = (0..=MAX_ARTIFACT_DIGESTS).map(|_| hash_array).collect();
        let digests_json = digests.join(",");
        let sig_bytes = test_signature_bytes_json();

        let json = format!(
            r#"{{
                "import_id": "import-001",
                "workflow_run_id": "run-001",
                "artifact_digests": [{digests_json}],
                "imported_at": 1704067200000,
                "adapter_signature": {sig_bytes}
            }}"#,
        );

        let result: Result<CiImportAttestation, _> = serde_json::from_str(&json);
        assert!(
            result.is_err(),
            "too many artifact_digests must be rejected"
        );

        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("too many artifact digests"),
            "error message should mention artifact digests limit: {error_msg}"
        );
    }

    /// Tests that invalid signature length is rejected (too short).
    #[test]
    fn test_attestation_deser_rejects_short_signature() {
        // Only 32 bytes instead of 64
        let short_sig: Vec<u8> = vec![0u8; 32];
        let sig_bytes = serde_json::to_string(&short_sig).unwrap();

        let json = format!(
            r#"{{
                "import_id": "import-001",
                "workflow_run_id": "run-001",
                "artifact_digests": [],
                "imported_at": 1704067200000,
                "adapter_signature": {sig_bytes}
            }}"#,
        );

        let result: Result<CiImportAttestation, _> = serde_json::from_str(&json);
        assert!(result.is_err(), "short signature must be rejected");
    }

    /// Tests that invalid signature length is rejected (too long).
    #[test]
    fn test_attestation_deser_rejects_long_signature() {
        // 128 bytes instead of 64
        let long_sig: Vec<u8> = vec![0u8; 128];
        let sig_bytes = serde_json::to_string(&long_sig).unwrap();

        let json = format!(
            r#"{{
                "import_id": "import-001",
                "workflow_run_id": "run-001",
                "artifact_digests": [],
                "imported_at": 1704067200000,
                "adapter_signature": {sig_bytes}
            }}"#,
        );

        let result: Result<CiImportAttestation, _> = serde_json::from_str(&json);
        assert!(result.is_err(), "oversized signature must be rejected");
    }

    /// Tests that maximum allowed sizes are accepted for `CiImportAttestation`.
    #[test]
    fn test_attestation_deser_accepts_max_allowed_sizes() {
        let max_import_id = "x".repeat(MAX_IMPORT_ID_LENGTH);
        let max_workflow_id = "x".repeat(MAX_WORKFLOW_RUN_ID_LENGTH);
        let sig_bytes = test_signature_bytes_json();

        let json = format!(
            r#"{{
                "import_id": "{max_import_id}",
                "workflow_run_id": "{max_workflow_id}",
                "artifact_digests": [],
                "imported_at": 1704067200000,
                "adapter_signature": {sig_bytes}
            }}"#,
        );

        let result: Result<CiImportAttestation, _> = serde_json::from_str(&json);
        assert!(
            result.is_ok(),
            "max allowed sizes should be accepted: {:?}",
            result.err()
        );

        let attestation = result.unwrap();
        assert_eq!(attestation.import_id().len(), MAX_IMPORT_ID_LENGTH);
        assert_eq!(
            attestation.workflow_run_id().len(),
            MAX_WORKFLOW_RUN_ID_LENGTH
        );
    }

    /// Tests that `CiImportAttestation` serialization roundtrip works
    /// correctly.
    #[test]
    fn test_attestation_serialization_roundtrip() {
        let signer = Signer::generate();

        let original = CiImportAttestation::builder()
            .import_id("import-roundtrip")
            .workflow_run_id("run-roundtrip")
            .artifact_digest([0xAA; 32])
            .imported_at(1_704_067_200_000)
            .build_and_sign(&signer)
            .unwrap();

        let json = serde_json::to_string(&original).unwrap();
        let deserialized: CiImportAttestation = serde_json::from_str(&json).unwrap();

        assert_eq!(original, deserialized);
        assert_eq!(original.import_id(), deserialized.import_id());
        assert_eq!(original.workflow_run_id(), deserialized.workflow_run_id());
        assert_eq!(original.artifact_digests(), deserialized.artifact_digests());
        assert_eq!(original.imported_at(), deserialized.imported_at());
        assert_eq!(
            original.adapter_signature().to_bytes(),
            deserialized.adapter_signature().to_bytes()
        );
    }

    /// Tests that unknown fields are rejected during `CiImportAttestation`
    /// deserialization (`deny_unknown_fields`).
    #[test]
    fn test_attestation_deser_rejects_unknown_fields() {
        let sig_bytes = test_signature_bytes_json();

        let json = format!(
            r#"{{
                "import_id": "import-001",
                "workflow_run_id": "run-001",
                "artifact_digests": [],
                "imported_at": 1704067200000,
                "adapter_signature": {sig_bytes},
                "malicious_field": "injected"
            }}"#,
        );

        let result: Result<CiImportAttestation, _> = serde_json::from_str(&json);
        assert!(result.is_err(), "unknown fields must be rejected");

        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("unknown field"),
            "error message should mention unknown field: {error_msg}"
        );
    }

    /// Tests that unknown fields are rejected during `CiEvidenceImport`
    /// deserialization (`deny_unknown_fields`).
    #[test]
    fn test_import_deser_rejects_unknown_fields() {
        let json = r#"{
            "workflow_run_id": "run-001",
            "webhook_signature_verified": false,
            "artifact_digests": [],
            "attestation": {
                "level": "L0",
                "workflow_run_id": "",
                "downloaded_artifact_hashes": []
            },
            "malicious_field": "injected"
        }"#;

        let result: Result<CiEvidenceImport, _> = serde_json::from_str(json);
        assert!(result.is_err(), "unknown fields must be rejected");

        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("unknown field"),
            "error message should mention unknown field: {error_msg}"
        );
    }

    // =========================================================================
    // Transition Gate Tests (can_transition_to_ready_for_review)
    // =========================================================================

    /// Test submodule for transition gate tests, matching the ticket's
    /// test path: `fac::ci_import::tests::transition`
    pub mod transition {
        use super::*;

        #[test]
        fn test_ci_disabled_allows_transition_without_evidence() {
            // CI gating disabled - transition always allowed, even with no evidence
            // minimum_level is ignored when CI is disabled
            let result = can_transition_to_ready_for_review(false, None, CiAttestationLevel::L1);
            assert!(result.is_ok());
        }

        #[test]
        fn test_ci_disabled_allows_transition_with_l0() {
            // CI gating disabled - transition allowed even with L0
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

            let result =
                can_transition_to_ready_for_review(false, Some(&import), CiAttestationLevel::L1);
            assert!(result.is_ok());
        }

        #[test]
        fn test_ci_enabled_rejects_missing_evidence() {
            // CI gating enabled with no evidence - plain "success" is rejected
            let result = can_transition_to_ready_for_review(true, None, CiAttestationLevel::L1);
            assert!(matches!(result, Err(CiImportError::CiEvidenceMissing)));
        }

        #[test]
        fn test_ci_enabled_rejects_l0_when_l1_required() {
            // CI gating enabled with L0 attestation when L1 required - rejected
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

            let result =
                can_transition_to_ready_for_review(true, Some(&import), CiAttestationLevel::L1);
            assert!(
                matches!(
                    result,
                    Err(CiImportError::InsufficientAttestationLevel {
                        actual: CiAttestationLevel::L0,
                        required: CiAttestationLevel::L1,
                    })
                ),
                "Expected InsufficientAttestationLevel for L0 when L1 required, got: {result:?}"
            );
        }

        /// SEC-CTRL-FAC-0017: Tests that unverified webhook signatures are
        /// rejected even when attestation level is sufficient. This
        /// prevents spoofed/unverified CI evidence from authorizing
        /// transitions.
        #[test]
        fn test_ci_enabled_rejects_unverified_webhook_signature() {
            // CI gating enabled with L1 attestation but UNVERIFIED signature - rejected
            let attestation = CiAttestation::builder()
                .level(CiAttestationLevel::L1)
                .workflow_run_id("run-unverified")
                .build()
                .unwrap();

            let import = CiEvidenceImport::builder()
                .workflow_run_id("run-unverified")
                .webhook_signature_verified(false) // Unverified!
                .attestation(attestation)
                .build()
                .unwrap();

            let result =
                can_transition_to_ready_for_review(true, Some(&import), CiAttestationLevel::L1);
            assert!(
                matches!(result, Err(CiImportError::WebhookSignatureNotVerified)),
                "Expected WebhookSignatureNotVerified error, got: {result:?}"
            );
        }

        /// Tests the error message for unverified webhook signature rejection.
        #[test]
        fn test_error_message_for_unverified_webhook_signature() {
            let attestation = CiAttestation::builder()
                .level(CiAttestationLevel::L1)
                .workflow_run_id("run-err-msg")
                .build()
                .unwrap();

            let import = CiEvidenceImport::builder()
                .workflow_run_id("run-err-msg")
                .webhook_signature_verified(false)
                .attestation(attestation)
                .build()
                .unwrap();

            let result =
                can_transition_to_ready_for_review(true, Some(&import), CiAttestationLevel::L1);
            let err = result.unwrap_err();
            assert_eq!(
                err.to_string(),
                "webhook signature was not verified",
                "Error message should clearly indicate webhook signature issue"
            );
        }

        /// Tests that L2 attestation with unverified signature is still
        /// rejected. The signature check must happen before the
        /// attestation level check.
        #[test]
        fn test_unverified_signature_rejected_even_with_l2() {
            let attestation = CiAttestation::builder()
                .level(CiAttestationLevel::L2)
                .workflow_run_id("run-l2-unverified")
                .build()
                .unwrap();

            let import = CiEvidenceImport::builder()
                .workflow_run_id("run-l2-unverified")
                .webhook_signature_verified(false)
                .attestation(attestation)
                .build()
                .unwrap();

            let result =
                can_transition_to_ready_for_review(true, Some(&import), CiAttestationLevel::L1);
            assert!(
                matches!(result, Err(CiImportError::WebhookSignatureNotVerified)),
                "Unverified signature must be rejected even with L2 attestation"
            );
        }

        #[test]
        fn test_ci_enabled_accepts_l1_when_l1_required() {
            // CI gating enabled with L1 attestation meeting L1 requirement - allowed
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

            let result =
                can_transition_to_ready_for_review(true, Some(&import), CiAttestationLevel::L1);
            assert!(result.is_ok());
        }

        #[test]
        fn test_ci_enabled_accepts_l2_when_l1_required() {
            // CI gating enabled with L2 attestation exceeding L1 requirement - allowed
            let attestation = CiAttestation::builder()
                .level(CiAttestationLevel::L2)
                .workflow_run_id("run-002")
                .build()
                .unwrap();

            let import = CiEvidenceImport::builder()
                .workflow_run_id("run-002")
                .webhook_signature_verified(true)
                .attestation(attestation)
                .build()
                .unwrap();

            let result =
                can_transition_to_ready_for_review(true, Some(&import), CiAttestationLevel::L1);
            assert!(result.is_ok());
        }

        #[test]
        fn test_ci_enabled_accepts_l3_when_l1_required() {
            // CI gating enabled with L3 attestation exceeding L1 requirement - allowed
            let attestation = CiAttestation::builder()
                .level(CiAttestationLevel::L3)
                .workflow_run_id("run-003")
                .build()
                .unwrap();

            let import = CiEvidenceImport::builder()
                .workflow_run_id("run-003")
                .webhook_signature_verified(true)
                .attestation(attestation)
                .build()
                .unwrap();

            let result =
                can_transition_to_ready_for_review(true, Some(&import), CiAttestationLevel::L1);
            assert!(result.is_ok());
        }

        #[test]
        fn test_error_message_for_ci_evidence_missing() {
            // Verify the error message is descriptive
            let result = can_transition_to_ready_for_review(true, None, CiAttestationLevel::L1);
            let err = result.unwrap_err();
            assert_eq!(
                err.to_string(),
                "CI evidence is required for READY_FOR_REVIEW transition"
            );
        }

        #[test]
        fn test_error_message_for_insufficient_attestation_level() {
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

            let result =
                can_transition_to_ready_for_review(true, Some(&import), CiAttestationLevel::L1);
            let err = result.unwrap_err();
            assert!(
                err.to_string().contains("L0 (status-only) is insufficient"),
                "Expected error about L0 being insufficient, got: {err}"
            );
        }

        // =====================================================================
        // Policy-Based Enforcement Tests
        // =====================================================================

        /// Tests that L2 can be required by policy for high-risk scenarios.
        #[test]
        fn test_policy_requires_l2_rejects_l1() {
            // High-risk policy requiring L2
            let attestation = CiAttestation::builder()
                .level(CiAttestationLevel::L1)
                .workflow_run_id("run-high-risk")
                .build()
                .unwrap();

            let import = CiEvidenceImport::builder()
                .workflow_run_id("run-high-risk")
                .webhook_signature_verified(true)
                .attestation(attestation)
                .build()
                .unwrap();

            let result = can_transition_to_ready_for_review(
                true,
                Some(&import),
                CiAttestationLevel::L2, // High-risk requires L2
            );
            assert!(
                matches!(
                    result,
                    Err(CiImportError::InsufficientAttestationLevel {
                        actual: CiAttestationLevel::L1,
                        required: CiAttestationLevel::L2,
                    })
                ),
                "L1 should not meet L2 requirement for high-risk policy, got: {result:?}"
            );
        }

        /// Tests that L2 meets L2 requirement.
        #[test]
        fn test_policy_requires_l2_accepts_l2() {
            let attestation = CiAttestation::builder()
                .level(CiAttestationLevel::L2)
                .workflow_run_id("run-high-risk-ok")
                .build()
                .unwrap();

            let import = CiEvidenceImport::builder()
                .workflow_run_id("run-high-risk-ok")
                .webhook_signature_verified(true)
                .attestation(attestation)
                .build()
                .unwrap();

            let result =
                can_transition_to_ready_for_review(true, Some(&import), CiAttestationLevel::L2);
            assert!(result.is_ok(), "L2 should meet L2 requirement");
        }

        /// Tests that L3 exceeds L2 requirement.
        #[test]
        fn test_policy_requires_l2_accepts_l3() {
            let attestation = CiAttestation::builder()
                .level(CiAttestationLevel::L3)
                .workflow_run_id("run-high-risk-l3")
                .build()
                .unwrap();

            let import = CiEvidenceImport::builder()
                .workflow_run_id("run-high-risk-l3")
                .webhook_signature_verified(true)
                .attestation(attestation)
                .build()
                .unwrap();

            let result =
                can_transition_to_ready_for_review(true, Some(&import), CiAttestationLevel::L2);
            assert!(result.is_ok(), "L3 should exceed L2 requirement");
        }

        /// Tests error message when L1 doesn't meet L2 requirement.
        #[test]
        fn test_error_message_l1_insufficient_for_l2() {
            let attestation = CiAttestation::builder()
                .level(CiAttestationLevel::L1)
                .workflow_run_id("run-err-l2")
                .build()
                .unwrap();

            let import = CiEvidenceImport::builder()
                .workflow_run_id("run-err-l2")
                .webhook_signature_verified(true)
                .attestation(attestation)
                .build()
                .unwrap();

            let result =
                can_transition_to_ready_for_review(true, Some(&import), CiAttestationLevel::L2);
            let err = result.unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains("L1 (signed attestation) is insufficient"),
                "Error should mention L1 is insufficient, got: {msg}"
            );
            assert!(
                msg.contains("L2 (replayable proof)"),
                "Error should mention L2 is required, got: {msg}"
            );
        }

        /// Tests that L0 can be accepted if policy permits (`minimum_level` =
        /// L0).
        #[test]
        fn test_policy_allows_l0_accepts_l0() {
            let attestation = CiAttestation::builder()
                .level(CiAttestationLevel::L0)
                .build()
                .unwrap();

            let import = CiEvidenceImport::builder()
                .workflow_run_id("run-permissive")
                .webhook_signature_verified(true)
                .attestation(attestation)
                .build()
                .unwrap();

            // Permissive policy allows L0
            let result =
                can_transition_to_ready_for_review(true, Some(&import), CiAttestationLevel::L0);
            assert!(result.is_ok(), "L0 should meet L0 requirement");
        }
    }
}
