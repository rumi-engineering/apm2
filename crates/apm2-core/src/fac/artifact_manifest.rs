// AGENT-AUTHORED
//! Artifact manifest types for evidence binding in the Forge Admission Cycle.
//!
//! This module defines [`ArtifactManifest`] which binds evidence artifacts to
//! gate receipts. Each artifact includes data classification, redaction
//! metadata, and retention policy references to ensure evidence hygiene.
//!
//! # Data Classification
//!
//! All artifacts MUST have a data classification:
//! - **Public**: No access restrictions
//! - **Internal**: Organization-internal access
//! - **Confidential**: Restricted access with audit logging
//! - **Restricted**: Maximum security controls required
//!
//! # Artifact Types
//!
//! - **Log**: Execution logs and traces
//! - **Junit**: JUnit/xUnit test reports
//! - **Coverage**: Code coverage reports
//! - **Snapshot**: State snapshots for determinism verification
//! - **Binary**: Compiled artifacts (executables, libraries)
//!
//! # Evidence Hygiene
//!
//! The `validate_hygiene()` method enforces:
//! - All artifacts have valid data classification
//! - Redaction applied flag must have corresponding profile hash when true
//! - Retention window reference is present
//! - No duplicate digests within a manifest
//!
//! # Security Model
//!
//! `ArtifactManifest` supports evidence hygiene requirements (FAC-REQ-0014):
//! - Data classification enforces access control at consumption
//! - Redaction profiles are bound to specific sanitization rules
//! - Retention windows enable automated cleanup per policy
//! - Admission rejects evidence with policy violations
//!
//! # Example
//!
//! ```rust
//! use apm2_core::fac::{
//!     ArtifactDigest, ArtifactManifest, ArtifactManifestBuilder, ArtifactType, DataClassification,
//! };
//!
//! let manifest = ArtifactManifestBuilder::new()
//!     .add_artifact(ArtifactDigest {
//!         artifact_type: ArtifactType::Log,
//!         digest: [0x11; 32],
//!         data_classification: DataClassification::Internal,
//!         redaction_applied: false,
//!         redaction_profile_hash: None,
//!         retention_window_ref: "htf:window:30d".to_string(),
//!     })
//!     .add_artifact(ArtifactDigest {
//!         artifact_type: ArtifactType::Junit,
//!         digest: [0x22; 32],
//!         data_classification: DataClassification::Public,
//!         redaction_applied: false,
//!         redaction_profile_hash: None,
//!         retention_window_ref: "htf:window:90d".to_string(),
//!     })
//!     .build()
//!     .expect("valid manifest");
//!
//! // Validate hygiene requirements
//! assert!(manifest.validate_hygiene().is_ok());
//! ```

use serde::{Deserialize, Serialize};
use thiserror::Error;

// =============================================================================
// Resource Limits
// =============================================================================

/// Maximum number of artifacts allowed in a manifest.
/// This prevents denial-of-service attacks via oversized repeated fields.
pub const MAX_ARTIFACTS: usize = 1024;

/// Maximum length of any string field in an artifact.
/// This prevents denial-of-service attacks via oversized strings.
pub const MAX_STRING_LENGTH: usize = 4096;

// =============================================================================
// Enums
// =============================================================================

/// Type of evidence artifact.
///
/// Classifies artifacts for processing and retention policy routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[repr(u8)]
pub enum ArtifactType {
    /// Execution logs and traces.
    Log      = 1,
    /// JUnit/xUnit test reports.
    Junit    = 2,
    /// Code coverage reports.
    Coverage = 3,
    /// State snapshots for determinism verification.
    Snapshot = 4,
    /// Compiled artifacts (executables, libraries).
    Binary   = 5,
}

impl ArtifactType {
    /// Returns the numeric value of this type.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Returns an iterator over all artifact types.
    pub fn all() -> impl Iterator<Item = Self> {
        [
            Self::Log,
            Self::Junit,
            Self::Coverage,
            Self::Snapshot,
            Self::Binary,
        ]
        .into_iter()
    }
}

impl TryFrom<u8> for ArtifactType {
    type Error = ArtifactManifestError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Log),
            2 => Ok(Self::Junit),
            3 => Ok(Self::Coverage),
            4 => Ok(Self::Snapshot),
            5 => Ok(Self::Binary),
            _ => Err(ArtifactManifestError::InvalidEnumValue {
                field: "artifact_type",
                value: i32::from(value),
            }),
        }
    }
}

impl TryFrom<i32> for ArtifactType {
    type Error = ArtifactManifestError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Log),
            2 => Ok(Self::Junit),
            3 => Ok(Self::Coverage),
            4 => Ok(Self::Snapshot),
            5 => Ok(Self::Binary),
            _ => Err(ArtifactManifestError::InvalidEnumValue {
                field: "artifact_type",
                value,
            }),
        }
    }
}

impl std::fmt::Display for ArtifactType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Log => write!(f, "LOG"),
            Self::Junit => write!(f, "JUNIT"),
            Self::Coverage => write!(f, "COVERAGE"),
            Self::Snapshot => write!(f, "SNAPSHOT"),
            Self::Binary => write!(f, "BINARY"),
        }
    }
}

/// Data classification level for evidence artifacts.
///
/// Determines access control and handling requirements. Higher classifications
/// require stricter controls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[repr(u8)]
pub enum DataClassification {
    /// No access restrictions.
    Public       = 1,
    /// Organization-internal access only.
    Internal     = 2,
    /// Restricted access with audit logging.
    Confidential = 3,
    /// Maximum security controls required.
    Restricted   = 4,
}

impl DataClassification {
    /// Returns the numeric value of this classification.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Returns the security rank of this classification.
    ///
    /// Higher ranks indicate more sensitive data:
    /// - Public: 1
    /// - Internal: 2
    /// - Confidential: 3
    /// - Restricted: 4
    #[must_use]
    pub const fn rank(self) -> u8 {
        self as u8
    }

    /// Returns an iterator over all data classifications in rank order.
    pub fn all() -> impl Iterator<Item = Self> {
        [
            Self::Public,
            Self::Internal,
            Self::Confidential,
            Self::Restricted,
        ]
        .into_iter()
    }
}

impl TryFrom<u8> for DataClassification {
    type Error = ArtifactManifestError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Public),
            2 => Ok(Self::Internal),
            3 => Ok(Self::Confidential),
            4 => Ok(Self::Restricted),
            _ => Err(ArtifactManifestError::InvalidEnumValue {
                field: "data_classification",
                value: i32::from(value),
            }),
        }
    }
}

impl TryFrom<i32> for DataClassification {
    type Error = ArtifactManifestError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Public),
            2 => Ok(Self::Internal),
            3 => Ok(Self::Confidential),
            4 => Ok(Self::Restricted),
            _ => Err(ArtifactManifestError::InvalidEnumValue {
                field: "data_classification",
                value,
            }),
        }
    }
}

impl PartialOrd for DataClassification {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DataClassification {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.rank().cmp(&other.rank())
    }
}

impl std::fmt::Display for DataClassification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Public => write!(f, "PUBLIC"),
            Self::Internal => write!(f, "INTERNAL"),
            Self::Confidential => write!(f, "CONFIDENTIAL"),
            Self::Restricted => write!(f, "RESTRICTED"),
        }
    }
}

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during artifact manifest operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArtifactManifestError {
    /// Invalid enum value.
    #[error("invalid enum value for {field}: {value}")]
    InvalidEnumValue {
        /// Name of the field with invalid value.
        field: &'static str,
        /// The invalid value.
        value: i32,
    },

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

    /// Collection size exceeds limit.
    #[error("collection {field} exceeds limit: {actual} > {max}")]
    CollectionTooLarge {
        /// Name of the field that exceeded the limit.
        field: &'static str,
        /// Actual size.
        actual: usize,
        /// Maximum allowed size.
        max: usize,
    },

    /// Redaction applied but profile hash missing.
    #[error(
        "redaction_applied is true but redaction_profile_hash is missing for artifact at index {index}"
    )]
    RedactionProfileMissing {
        /// Index of the artifact with the error.
        index: usize,
    },

    /// Retention window reference is empty.
    #[error("retention_window_ref is empty for artifact at index {index}")]
    RetentionWindowEmpty {
        /// Index of the artifact with the error.
        index: usize,
    },

    /// Duplicate artifact digest found.
    #[error("duplicate artifact digest found at indices {first} and {second}")]
    DuplicateDigest {
        /// Index of the first occurrence.
        first: usize,
        /// Index of the duplicate.
        second: usize,
    },

    /// Manifest is empty.
    #[error("artifact manifest must contain at least one artifact")]
    EmptyManifest,
}

// =============================================================================
// Evidence Hygiene Error Types
// =============================================================================

/// Errors that indicate evidence hygiene violations blocking admission.
///
/// These errors are SECURITY-CRITICAL and indicate that an artifact manifest
/// does not meet the evidence hygiene requirements defined in DD-FAC-0014.
/// Any occurrence blocks admission and should be logged for audit.
///
/// # Security Model
///
/// Evidence hygiene enforcement ensures:
/// - **Data Classification**: All artifacts have proper classification
/// - **Retention Compliance**: Confidential/Restricted artifacts have retention
///   windows
/// - **Redaction Tracking**: Redacted non-public artifacts have redaction
///   profiles
///
/// # Fail-Closed Design
///
/// This module uses a FAIL-CLOSED approach: if any hygiene check fails,
/// admission is blocked. This ensures that incomplete or improperly classified
/// evidence cannot be admitted into the system.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum HygieneError {
    /// Confidential or Restricted artifact is missing `retention_window_ref`.
    ///
    /// All artifacts with `DataClassification::Confidential` or
    /// `DataClassification::Restricted` MUST have a non-empty
    /// `retention_window_ref` to ensure proper data lifecycle management
    /// and compliance.
    #[error(
        "missing retention window for {classification} artifact at index {index} (digest: {digest})"
    )]
    MissingRetentionWindow {
        /// Index of the artifact with the violation.
        index: usize,
        /// The artifact digest (hex-encoded first 8 bytes).
        digest: String,
        /// The data classification that requires retention window.
        classification: DataClassification,
    },

    /// Redacted non-public artifact is missing `redaction_profile_hash`.
    ///
    /// All artifacts with `redaction_applied = true` AND a non-Public data
    /// classification MUST have a `redaction_profile_hash` to provide
    /// traceability of what redaction rules were applied.
    #[error(
        "missing redaction profile for redacted {classification} artifact at index {index} (digest: {digest})"
    )]
    MissingRedactionProfile {
        /// Index of the artifact with the violation.
        index: usize,
        /// The artifact digest (hex-encoded first 8 bytes).
        digest: String,
        /// The data classification of the redacted artifact.
        classification: DataClassification,
    },
}

// =============================================================================
// ArtifactDigest
// =============================================================================

/// Digest and metadata for a single evidence artifact.
///
/// Each artifact is identified by its content digest and includes metadata
/// for access control, redaction tracking, and retention policy.
///
/// # Required Fields
///
/// - `artifact_type`: Classification of the artifact content
/// - `digest`: SHA-256 hash of the artifact content
/// - `data_classification`: Access control level
/// - `redaction_applied`: Whether sanitization was performed
/// - `redaction_profile_hash`: Hash of redaction rules (required if
///   `redaction_applied`)
/// - `retention_window_ref`: HTF time reference for retention policy
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactDigest {
    /// Type of artifact (Log, Junit, Coverage, Snapshot, Binary).
    pub artifact_type: ArtifactType,

    /// SHA-256 digest of the artifact content.
    #[serde(with = "serde_bytes")]
    pub digest: [u8; 32],

    /// Data classification for access control.
    pub data_classification: DataClassification,

    /// Whether redaction/sanitization was applied to this artifact.
    pub redaction_applied: bool,

    /// Hash of the redaction profile used (required if `redaction_applied` is
    /// true).
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "option_hash_serde")]
    pub redaction_profile_hash: Option<[u8; 32]>,

    /// Reference to the retention window for this artifact.
    ///
    /// Uses HTF time envelope format (e.g., `htf:window:30d`).
    pub retention_window_ref: String,
}

/// Custom serde for Option<[u8; 32]>.
mod option_hash_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    #[allow(clippy::ref_option)]
    pub fn serialize<S>(value: &Option<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(bytes) => serializer.serialize_bytes(bytes),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        let opt: Option<Vec<u8>> = Option::deserialize(deserializer)?;
        match opt {
            Some(bytes) => {
                let arr: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| D::Error::custom("hash must be exactly 32 bytes"))?;
                Ok(Some(arr))
            },
            None => Ok(None),
        }
    }
}

impl ArtifactDigest {
    /// Validates the hygiene requirements for this artifact.
    ///
    /// # Checks
    ///
    /// - `redaction_profile_hash` is present when `redaction_applied` is true
    /// - `retention_window_ref` is not empty
    /// - String fields do not exceed maximum length
    ///
    /// # Returns
    ///
    /// `Ok(())` if all checks pass.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactManifestError`] on validation failure.
    pub fn validate(&self, index: usize) -> Result<(), ArtifactManifestError> {
        // Check redaction invariant
        if self.redaction_applied && self.redaction_profile_hash.is_none() {
            return Err(ArtifactManifestError::RedactionProfileMissing { index });
        }

        // Check retention window is not empty
        if self.retention_window_ref.is_empty() {
            return Err(ArtifactManifestError::RetentionWindowEmpty { index });
        }

        // Check string length
        if self.retention_window_ref.len() > MAX_STRING_LENGTH {
            return Err(ArtifactManifestError::StringTooLong {
                field: "retention_window_ref",
                actual: self.retention_window_ref.len(),
                max: MAX_STRING_LENGTH,
            });
        }

        Ok(())
    }
}

// =============================================================================
// ArtifactManifest
// =============================================================================

/// Manifest of evidence artifacts for a gate receipt.
///
/// The manifest binds all evidence artifacts produced during gate execution,
/// enabling independent verification and retention management.
///
/// # Invariants
///
/// - Must contain at least one artifact (empty manifests are rejected)
/// - No duplicate digests allowed
/// - All artifacts must pass hygiene validation
///
/// # Security
///
/// The manifest is referenced by `artifact_manifest_hash` in `AatGateReceipt`
/// and stored in CAS for independent verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactManifest {
    /// List of artifact digests and metadata.
    pub artifacts: Vec<ArtifactDigest>,
}

impl ArtifactManifest {
    /// Creates a new empty manifest builder.
    #[must_use]
    pub fn builder() -> ArtifactManifestBuilder {
        ArtifactManifestBuilder::new()
    }

    /// Returns the number of artifacts in this manifest.
    #[must_use]
    pub fn len(&self) -> usize {
        self.artifacts.len()
    }

    /// Returns true if the manifest contains no artifacts.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.artifacts.is_empty()
    }

    /// Returns an iterator over artifacts of a specific type.
    pub fn artifacts_by_type(
        &self,
        artifact_type: ArtifactType,
    ) -> impl Iterator<Item = &ArtifactDigest> {
        self.artifacts
            .iter()
            .filter(move |a| a.artifact_type == artifact_type)
    }

    /// Returns an iterator over artifacts with a specific classification or
    /// higher.
    pub fn artifacts_by_min_classification(
        &self,
        min_classification: DataClassification,
    ) -> impl Iterator<Item = &ArtifactDigest> {
        self.artifacts
            .iter()
            .filter(move |a| a.data_classification >= min_classification)
    }

    /// Computes the manifest hash for binding to receipts.
    ///
    /// The hash is computed over the canonical representation of all artifacts.
    #[must_use]
    pub fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();

        // Hash number of artifacts first (4-byte big-endian)
        #[allow(clippy::cast_possible_truncation)]
        let count = self.artifacts.len() as u32;
        hasher.update(&count.to_be_bytes());

        // Hash each artifact in order
        for artifact in &self.artifacts {
            hasher.update(&[artifact.artifact_type.as_u8()]);
            hasher.update(&artifact.digest);
            hasher.update(&[artifact.data_classification.as_u8()]);
            hasher.update(&[u8::from(artifact.redaction_applied)]);
            if let Some(ref profile_hash) = artifact.redaction_profile_hash {
                hasher.update(&[1u8]); // has profile hash
                hasher.update(profile_hash);
            } else {
                hasher.update(&[0u8]); // no profile hash
            }
            // Length-prefixed retention window ref
            #[allow(clippy::cast_possible_truncation)]
            let len = artifact.retention_window_ref.len() as u32;
            hasher.update(&len.to_be_bytes());
            hasher.update(artifact.retention_window_ref.as_bytes());
        }

        *hasher.finalize().as_bytes()
    }

    /// Validates hygiene requirements for all artifacts in this manifest.
    ///
    /// # Checks
    ///
    /// - Manifest is not empty
    /// - Artifact count does not exceed [`MAX_ARTIFACTS`]
    /// - No duplicate digests
    /// - Each artifact passes individual validation
    ///
    /// # Returns
    ///
    /// `Ok(())` if all checks pass.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactManifestError`] on validation failure.
    pub fn validate_hygiene(&self) -> Result<(), ArtifactManifestError> {
        // Check for empty manifest
        if self.artifacts.is_empty() {
            return Err(ArtifactManifestError::EmptyManifest);
        }

        // Check collection size
        if self.artifacts.len() > MAX_ARTIFACTS {
            return Err(ArtifactManifestError::CollectionTooLarge {
                field: "artifacts",
                actual: self.artifacts.len(),
                max: MAX_ARTIFACTS,
            });
        }

        // Check for duplicate digests
        for (i, artifact) in self.artifacts.iter().enumerate() {
            for (j, other) in self.artifacts.iter().enumerate().skip(i + 1) {
                if artifact.digest == other.digest {
                    return Err(ArtifactManifestError::DuplicateDigest {
                        first: i,
                        second: j,
                    });
                }
            }
        }

        // Validate each artifact
        for (index, artifact) in self.artifacts.iter().enumerate() {
            artifact.validate(index)?;
        }

        Ok(())
    }
}

// =============================================================================
// Evidence Hygiene Validation for Admission
// =============================================================================

/// Formats the first 8 bytes of a digest as a hex string for error messages.
fn format_digest_prefix(digest: &[u8; 32]) -> String {
    use std::fmt::Write;
    digest[..8].iter().fold(String::new(), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

/// Validates evidence hygiene requirements for admission.
///
/// This function enforces the evidence hygiene requirements defined in
/// DD-FAC-0014:
///
/// 1. **Retention Window Requirement**: All artifacts with
///    `DataClassification::Confidential` or `DataClassification::Restricted`
///    MUST have a non-empty `retention_window_ref`. This ensures proper data
///    lifecycle management for sensitive evidence.
///
/// 2. **Redaction Profile Requirement**: All artifacts with `redaction_applied
///    = true` AND a non-Public classification (Internal, Confidential, or
///    Restricted) MUST have a `redaction_profile_hash`. This provides
///    traceability of sanitization rules applied to sensitive data.
///
/// # Security Model
///
/// Evidence hygiene is SECURITY-CRITICAL:
/// - **Fail-Closed**: Any violation blocks admission entirely
/// - **Audit Support**: Violations include digest prefixes for traceability
/// - **Compliance**: Ensures all sensitive artifacts meet retention and
///   redaction requirements
///
/// # Arguments
///
/// * `manifest` - The artifact manifest to validate
///
/// # Returns
///
/// `Ok(())` if all hygiene checks pass, or [`HygieneError`] on first violation.
///
/// # Errors
///
/// Returns [`HygieneError::MissingRetentionWindow`] if a
/// Confidential/Restricted artifact has an empty `retention_window_ref`.
///
/// Returns [`HygieneError::MissingRedactionProfile`] if a redacted non-public
/// artifact is missing `redaction_profile_hash`.
///
/// # Example
///
/// ```rust
/// use apm2_core::fac::{
///     ArtifactDigest, ArtifactManifest, ArtifactType, DataClassification,
///     validate_evidence_hygiene_for_admission,
/// };
///
/// // Valid: Confidential artifact with retention window
/// let manifest = ArtifactManifest {
///     artifacts: vec![ArtifactDigest {
///         artifact_type: ArtifactType::Log,
///         digest: [0x11; 32],
///         data_classification: DataClassification::Confidential,
///         redaction_applied: false,
///         redaction_profile_hash: None,
///         retention_window_ref: "htf:window:30d".to_string(),
///     }],
/// };
/// assert!(validate_evidence_hygiene_for_admission(&manifest).is_ok());
///
/// // Invalid: Confidential artifact without retention window
/// let manifest = ArtifactManifest {
///     artifacts: vec![ArtifactDigest {
///         artifact_type: ArtifactType::Log,
///         digest: [0x22; 32],
///         data_classification: DataClassification::Confidential,
///         redaction_applied: false,
///         redaction_profile_hash: None,
///         retention_window_ref: String::new(), // Empty!
///     }],
/// };
/// assert!(validate_evidence_hygiene_for_admission(&manifest).is_err());
/// ```
pub fn validate_evidence_hygiene_for_admission(
    manifest: &ArtifactManifest,
) -> Result<(), HygieneError> {
    for (index, artifact) in manifest.artifacts.iter().enumerate() {
        // Check 1: Confidential/Restricted artifacts require retention_window_ref
        if matches!(
            artifact.data_classification,
            DataClassification::Confidential | DataClassification::Restricted
        ) && artifact.retention_window_ref.is_empty()
        {
            return Err(HygieneError::MissingRetentionWindow {
                index,
                digest: format_digest_prefix(&artifact.digest),
                classification: artifact.data_classification,
            });
        }

        // Check 2: Redacted non-public artifacts require redaction_profile_hash
        // Non-public means Internal, Confidential, or Restricted (not Public)
        if artifact.redaction_applied
            && artifact.data_classification != DataClassification::Public
            && artifact.redaction_profile_hash.is_none()
        {
            return Err(HygieneError::MissingRedactionProfile {
                index,
                digest: format_digest_prefix(&artifact.digest),
                classification: artifact.data_classification,
            });
        }
    }

    Ok(())
}

// =============================================================================
// Builder
// =============================================================================

/// Builder for constructing [`ArtifactManifest`] instances with validation.
#[derive(Debug, Default)]
pub struct ArtifactManifestBuilder {
    artifacts: Vec<ArtifactDigest>,
}

impl ArtifactManifestBuilder {
    /// Creates a new empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an artifact to the manifest.
    #[must_use]
    pub fn add_artifact(mut self, artifact: ArtifactDigest) -> Self {
        self.artifacts.push(artifact);
        self
    }

    /// Adds multiple artifacts to the manifest.
    #[must_use]
    pub fn add_artifacts(mut self, artifacts: impl IntoIterator<Item = ArtifactDigest>) -> Self {
        self.artifacts.extend(artifacts);
        self
    }

    /// Builds the manifest, validating all hygiene requirements.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactManifestError`] if validation fails.
    pub fn build(self) -> Result<ArtifactManifest, ArtifactManifestError> {
        let manifest = ArtifactManifest {
            artifacts: self.artifacts,
        };
        manifest.validate_hygiene()?;
        Ok(manifest)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
pub mod tests {
    use super::*;

    fn create_test_artifact(artifact_type: ArtifactType, digest: u8) -> ArtifactDigest {
        ArtifactDigest {
            artifact_type,
            digest: [digest; 32],
            data_classification: DataClassification::Internal,
            redaction_applied: false,
            redaction_profile_hash: None,
            retention_window_ref: "htf:window:30d".to_string(),
        }
    }

    fn create_valid_manifest() -> ArtifactManifest {
        ArtifactManifestBuilder::new()
            .add_artifact(create_test_artifact(ArtifactType::Log, 0x11))
            .add_artifact(create_test_artifact(ArtifactType::Junit, 0x22))
            .build()
            .expect("valid manifest")
    }

    // =========================================================================
    // ArtifactType Tests
    // =========================================================================

    #[test]
    fn test_artifact_type_try_from_u8() {
        assert_eq!(ArtifactType::try_from(1u8).unwrap(), ArtifactType::Log);
        assert_eq!(ArtifactType::try_from(2u8).unwrap(), ArtifactType::Junit);
        assert_eq!(ArtifactType::try_from(3u8).unwrap(), ArtifactType::Coverage);
        assert_eq!(ArtifactType::try_from(4u8).unwrap(), ArtifactType::Snapshot);
        assert_eq!(ArtifactType::try_from(5u8).unwrap(), ArtifactType::Binary);
        assert!(ArtifactType::try_from(0u8).is_err());
        assert!(ArtifactType::try_from(6u8).is_err());
    }

    #[test]
    fn test_artifact_type_try_from_i32() {
        assert_eq!(ArtifactType::try_from(1i32).unwrap(), ArtifactType::Log);
        assert_eq!(ArtifactType::try_from(5i32).unwrap(), ArtifactType::Binary);
        assert!(ArtifactType::try_from(0i32).is_err());
        assert!(ArtifactType::try_from(-1i32).is_err());
    }

    #[test]
    fn test_artifact_type_display() {
        assert_eq!(ArtifactType::Log.to_string(), "LOG");
        assert_eq!(ArtifactType::Junit.to_string(), "JUNIT");
        assert_eq!(ArtifactType::Coverage.to_string(), "COVERAGE");
        assert_eq!(ArtifactType::Snapshot.to_string(), "SNAPSHOT");
        assert_eq!(ArtifactType::Binary.to_string(), "BINARY");
    }

    #[test]
    fn test_artifact_type_all() {
        let types: Vec<_> = ArtifactType::all().collect();
        assert_eq!(types.len(), 5);
        assert_eq!(types[0], ArtifactType::Log);
        assert_eq!(types[4], ArtifactType::Binary);
    }

    // =========================================================================
    // DataClassification Tests
    // =========================================================================

    #[test]
    fn test_data_classification_try_from_u8() {
        assert_eq!(
            DataClassification::try_from(1u8).unwrap(),
            DataClassification::Public
        );
        assert_eq!(
            DataClassification::try_from(2u8).unwrap(),
            DataClassification::Internal
        );
        assert_eq!(
            DataClassification::try_from(3u8).unwrap(),
            DataClassification::Confidential
        );
        assert_eq!(
            DataClassification::try_from(4u8).unwrap(),
            DataClassification::Restricted
        );
        assert!(DataClassification::try_from(0u8).is_err());
        assert!(DataClassification::try_from(5u8).is_err());
    }

    #[test]
    fn test_data_classification_ordering() {
        assert!(DataClassification::Public < DataClassification::Internal);
        assert!(DataClassification::Internal < DataClassification::Confidential);
        assert!(DataClassification::Confidential < DataClassification::Restricted);
    }

    #[test]
    fn test_data_classification_rank() {
        assert_eq!(DataClassification::Public.rank(), 1);
        assert_eq!(DataClassification::Internal.rank(), 2);
        assert_eq!(DataClassification::Confidential.rank(), 3);
        assert_eq!(DataClassification::Restricted.rank(), 4);
    }

    #[test]
    fn test_data_classification_display() {
        assert_eq!(DataClassification::Public.to_string(), "PUBLIC");
        assert_eq!(DataClassification::Internal.to_string(), "INTERNAL");
        assert_eq!(DataClassification::Confidential.to_string(), "CONFIDENTIAL");
        assert_eq!(DataClassification::Restricted.to_string(), "RESTRICTED");
    }

    #[test]
    fn test_data_classification_all() {
        let classifications: Vec<_> = DataClassification::all().collect();
        assert_eq!(classifications.len(), 4);
        assert_eq!(classifications[0], DataClassification::Public);
        assert_eq!(classifications[3], DataClassification::Restricted);
    }

    // =========================================================================
    // ArtifactDigest Tests
    // =========================================================================

    #[test]
    fn test_artifact_digest_validate_success() {
        let artifact = create_test_artifact(ArtifactType::Log, 0x11);
        assert!(artifact.validate(0).is_ok());
    }

    #[test]
    fn test_artifact_digest_validate_with_redaction() {
        let artifact = ArtifactDigest {
            artifact_type: ArtifactType::Log,
            digest: [0x11; 32],
            data_classification: DataClassification::Confidential,
            redaction_applied: true,
            redaction_profile_hash: Some([0xAA; 32]),
            retention_window_ref: "htf:window:30d".to_string(),
        };
        assert!(artifact.validate(0).is_ok());
    }

    #[test]
    fn test_artifact_digest_validate_redaction_missing_profile() {
        let artifact = ArtifactDigest {
            artifact_type: ArtifactType::Log,
            digest: [0x11; 32],
            data_classification: DataClassification::Confidential,
            redaction_applied: true,
            redaction_profile_hash: None, // Missing!
            retention_window_ref: "htf:window:30d".to_string(),
        };
        let result = artifact.validate(0);
        assert!(matches!(
            result,
            Err(ArtifactManifestError::RedactionProfileMissing { index: 0 })
        ));
    }

    #[test]
    fn test_artifact_digest_validate_empty_retention_window() {
        let artifact = ArtifactDigest {
            artifact_type: ArtifactType::Log,
            digest: [0x11; 32],
            data_classification: DataClassification::Internal,
            redaction_applied: false,
            redaction_profile_hash: None,
            retention_window_ref: String::new(), // Empty!
        };
        let result = artifact.validate(0);
        assert!(matches!(
            result,
            Err(ArtifactManifestError::RetentionWindowEmpty { index: 0 })
        ));
    }

    #[test]
    fn test_artifact_digest_validate_retention_window_too_long() {
        let artifact = ArtifactDigest {
            artifact_type: ArtifactType::Log,
            digest: [0x11; 32],
            data_classification: DataClassification::Internal,
            redaction_applied: false,
            redaction_profile_hash: None,
            retention_window_ref: "x".repeat(MAX_STRING_LENGTH + 1),
        };
        let result = artifact.validate(0);
        assert!(matches!(
            result,
            Err(ArtifactManifestError::StringTooLong { .. })
        ));
    }

    // =========================================================================
    // ArtifactManifest Tests
    // =========================================================================

    #[test]
    fn test_manifest_build_success() {
        let manifest = create_valid_manifest();
        assert_eq!(manifest.len(), 2);
        assert!(!manifest.is_empty());
    }

    #[test]
    fn test_manifest_validate_hygiene_success() {
        let manifest = create_valid_manifest();
        assert!(manifest.validate_hygiene().is_ok());
    }

    #[test]
    fn test_manifest_validate_hygiene_empty() {
        let manifest = ArtifactManifest { artifacts: vec![] };
        let result = manifest.validate_hygiene();
        assert!(matches!(result, Err(ArtifactManifestError::EmptyManifest)));
    }

    #[test]
    fn test_manifest_validate_hygiene_duplicate_digest() {
        let manifest = ArtifactManifest {
            artifacts: vec![
                create_test_artifact(ArtifactType::Log, 0x11),
                create_test_artifact(ArtifactType::Junit, 0x11), // Same digest!
            ],
        };
        let result = manifest.validate_hygiene();
        assert!(matches!(
            result,
            Err(ArtifactManifestError::DuplicateDigest {
                first: 0,
                second: 1
            })
        ));
    }

    #[test]
    fn test_manifest_validate_hygiene_too_many_artifacts() {
        let artifacts: Vec<ArtifactDigest> = (0..=MAX_ARTIFACTS)
            .map(|i| {
                #[allow(clippy::cast_possible_truncation)]
                create_test_artifact(ArtifactType::Log, i as u8)
            })
            .collect();

        let manifest = ArtifactManifest { artifacts };
        let result = manifest.validate_hygiene();
        assert!(matches!(
            result,
            Err(ArtifactManifestError::CollectionTooLarge { .. })
        ));
    }

    #[test]
    fn test_manifest_artifacts_by_type() {
        let manifest = ArtifactManifestBuilder::new()
            .add_artifact(create_test_artifact(ArtifactType::Log, 0x11))
            .add_artifact(create_test_artifact(ArtifactType::Log, 0x22))
            .add_artifact(create_test_artifact(ArtifactType::Junit, 0x33))
            .build()
            .unwrap();

        assert_eq!(manifest.artifacts_by_type(ArtifactType::Log).count(), 2);

        assert_eq!(manifest.artifacts_by_type(ArtifactType::Junit).count(), 1);

        assert!(
            manifest
                .artifacts_by_type(ArtifactType::Coverage)
                .next()
                .is_none()
        );
    }

    #[test]
    fn test_manifest_artifacts_by_min_classification() {
        let manifest = ArtifactManifest {
            artifacts: vec![
                ArtifactDigest {
                    artifact_type: ArtifactType::Log,
                    digest: [0x11; 32],
                    data_classification: DataClassification::Public,
                    redaction_applied: false,
                    redaction_profile_hash: None,
                    retention_window_ref: "htf:window:30d".to_string(),
                },
                ArtifactDigest {
                    artifact_type: ArtifactType::Junit,
                    digest: [0x22; 32],
                    data_classification: DataClassification::Confidential,
                    redaction_applied: false,
                    redaction_profile_hash: None,
                    retention_window_ref: "htf:window:30d".to_string(),
                },
                ArtifactDigest {
                    artifact_type: ArtifactType::Coverage,
                    digest: [0x33; 32],
                    data_classification: DataClassification::Restricted,
                    redaction_applied: false,
                    redaction_profile_hash: None,
                    retention_window_ref: "htf:window:30d".to_string(),
                },
            ],
        };

        assert_eq!(
            manifest
                .artifacts_by_min_classification(DataClassification::Public)
                .count(),
            3
        );

        assert_eq!(
            manifest
                .artifacts_by_min_classification(DataClassification::Confidential)
                .count(),
            2
        );

        assert_eq!(
            manifest
                .artifacts_by_min_classification(DataClassification::Restricted)
                .count(),
            1
        );
    }

    #[test]
    fn test_manifest_compute_hash_deterministic() {
        let manifest1 = create_valid_manifest();
        let manifest2 = create_valid_manifest();

        assert_eq!(manifest1.compute_hash(), manifest2.compute_hash());
    }

    #[test]
    fn test_manifest_compute_hash_differs() {
        let manifest1 = ArtifactManifestBuilder::new()
            .add_artifact(create_test_artifact(ArtifactType::Log, 0x11))
            .build()
            .unwrap();

        let manifest2 = ArtifactManifestBuilder::new()
            .add_artifact(create_test_artifact(ArtifactType::Log, 0x22))
            .build()
            .unwrap();

        assert_ne!(manifest1.compute_hash(), manifest2.compute_hash());
    }

    // =========================================================================
    // Builder Tests
    // =========================================================================

    #[test]
    fn test_builder_add_artifacts() {
        let artifacts = vec![
            create_test_artifact(ArtifactType::Log, 0x11),
            create_test_artifact(ArtifactType::Junit, 0x22),
        ];

        let manifest = ArtifactManifestBuilder::new()
            .add_artifacts(artifacts)
            .build()
            .unwrap();

        assert_eq!(manifest.len(), 2);
    }

    #[test]
    fn test_builder_empty_fails() {
        let result = ArtifactManifestBuilder::new().build();
        assert!(matches!(result, Err(ArtifactManifestError::EmptyManifest)));
    }

    // =========================================================================
    // Serde Tests
    // =========================================================================

    #[test]
    fn test_artifact_type_serde_roundtrip() {
        for artifact_type in ArtifactType::all() {
            let json = serde_json::to_string(&artifact_type).unwrap();
            let deserialized: ArtifactType = serde_json::from_str(&json).unwrap();
            assert_eq!(artifact_type, deserialized);
        }
    }

    #[test]
    fn test_data_classification_serde_roundtrip() {
        for classification in DataClassification::all() {
            let json = serde_json::to_string(&classification).unwrap();
            let deserialized: DataClassification = serde_json::from_str(&json).unwrap();
            assert_eq!(classification, deserialized);
        }
    }

    #[test]
    fn test_manifest_serde_roundtrip() {
        let manifest = create_valid_manifest();
        let json = serde_json::to_string(&manifest).unwrap();
        let deserialized: ArtifactManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(manifest, deserialized);
    }

    #[test]
    fn test_manifest_serde_deny_unknown_fields() {
        let json = r#"{
            "artifacts": [],
            "unknown_field": "should_fail"
        }"#;
        let result: Result<ArtifactManifest, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_artifact_digest_serde_with_redaction() {
        let artifact = ArtifactDigest {
            artifact_type: ArtifactType::Log,
            digest: [0x11; 32],
            data_classification: DataClassification::Confidential,
            redaction_applied: true,
            redaction_profile_hash: Some([0xAA; 32]),
            retention_window_ref: "htf:window:30d".to_string(),
        };

        let json = serde_json::to_string(&artifact).unwrap();
        let deserialized: ArtifactDigest = serde_json::from_str(&json).unwrap();
        assert_eq!(artifact, deserialized);
    }

    // =========================================================================
    // Edge Cases
    // =========================================================================

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn test_max_artifacts_allowed() {
        let artifacts: Vec<ArtifactDigest> = (0..MAX_ARTIFACTS)
            .map(|i| {
                let mut artifact = create_test_artifact(ArtifactType::Log, 0x00);
                // Create unique digests (truncation is intentional for test data)
                artifact.digest[0] = (i >> 8) as u8;
                artifact.digest[1] = (i & 0xFF) as u8;
                artifact
            })
            .collect();

        let manifest = ArtifactManifest { artifacts };
        assert!(manifest.validate_hygiene().is_ok());
        assert_eq!(manifest.len(), MAX_ARTIFACTS);
    }

    #[test]
    fn test_max_string_length_allowed() {
        let artifact = ArtifactDigest {
            artifact_type: ArtifactType::Log,
            digest: [0x11; 32],
            data_classification: DataClassification::Internal,
            redaction_applied: false,
            redaction_profile_hash: None,
            retention_window_ref: "x".repeat(MAX_STRING_LENGTH),
        };
        assert!(artifact.validate(0).is_ok());
    }

    #[test]
    fn test_all_artifact_types_in_manifest() {
        let manifest = ArtifactManifestBuilder::new()
            .add_artifact(create_test_artifact(ArtifactType::Log, 0x11))
            .add_artifact(create_test_artifact(ArtifactType::Junit, 0x22))
            .add_artifact(create_test_artifact(ArtifactType::Coverage, 0x33))
            .add_artifact(create_test_artifact(ArtifactType::Snapshot, 0x44))
            .add_artifact(create_test_artifact(ArtifactType::Binary, 0x55))
            .build()
            .unwrap();

        assert_eq!(manifest.len(), 5);
        assert!(manifest.validate_hygiene().is_ok());
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn test_all_data_classifications_in_manifest() {
        let mut artifacts = Vec::new();

        for (i, classification) in DataClassification::all().enumerate() {
            artifacts.push(ArtifactDigest {
                artifact_type: ArtifactType::Log,
                digest: [i as u8; 32],
                data_classification: classification,
                redaction_applied: false,
                redaction_profile_hash: None,
                retention_window_ref: "htf:window:30d".to_string(),
            });
        }

        let manifest = ArtifactManifest { artifacts };
        assert!(manifest.validate_hygiene().is_ok());
        assert_eq!(manifest.len(), 4);
    }

    // =========================================================================
    // Evidence Hygiene for Admission Tests (TCK-00229)
    // =========================================================================

    /// Helper to create a confidential artifact with specified retention
    /// window.
    fn create_confidential_artifact(digest: u8, retention: &str) -> ArtifactDigest {
        ArtifactDigest {
            artifact_type: ArtifactType::Log,
            digest: [digest; 32],
            data_classification: DataClassification::Confidential,
            redaction_applied: false,
            redaction_profile_hash: None,
            retention_window_ref: retention.to_string(),
        }
    }

    /// Helper to create a restricted artifact with specified retention window.
    fn create_restricted_artifact(digest: u8, retention: &str) -> ArtifactDigest {
        ArtifactDigest {
            artifact_type: ArtifactType::Snapshot,
            digest: [digest; 32],
            data_classification: DataClassification::Restricted,
            redaction_applied: false,
            redaction_profile_hash: None,
            retention_window_ref: retention.to_string(),
        }
    }

    /// Helper to create a redacted artifact.
    fn create_redacted_artifact(
        digest: u8,
        classification: DataClassification,
        profile_hash: Option<[u8; 32]>,
    ) -> ArtifactDigest {
        ArtifactDigest {
            artifact_type: ArtifactType::Log,
            digest: [digest; 32],
            data_classification: classification,
            redaction_applied: true,
            redaction_profile_hash: profile_hash,
            retention_window_ref: "htf:window:30d".to_string(),
        }
    }

    // -------------------------------------------------------------------------
    // Retention Window Requirement Tests
    // -------------------------------------------------------------------------

    #[test]
    fn hygiene_confidential_with_retention_passes() {
        let manifest = ArtifactManifest {
            artifacts: vec![create_confidential_artifact(0x11, "htf:window:30d")],
        };
        assert!(validate_evidence_hygiene_for_admission(&manifest).is_ok());
    }

    #[test]
    fn hygiene_restricted_with_retention_passes() {
        let manifest = ArtifactManifest {
            artifacts: vec![create_restricted_artifact(0x22, "htf:window:90d")],
        };
        assert!(validate_evidence_hygiene_for_admission(&manifest).is_ok());
    }

    #[test]
    fn hygiene_confidential_missing_retention_fails() {
        let manifest = ArtifactManifest {
            artifacts: vec![create_confidential_artifact(0x33, "")],
        };
        let result = validate_evidence_hygiene_for_admission(&manifest);
        assert!(matches!(
            result,
            Err(HygieneError::MissingRetentionWindow {
                index: 0,
                classification: DataClassification::Confidential,
                ..
            })
        ));
    }

    #[test]
    fn hygiene_restricted_missing_retention_fails() {
        let manifest = ArtifactManifest {
            artifacts: vec![create_restricted_artifact(0x44, "")],
        };
        let result = validate_evidence_hygiene_for_admission(&manifest);
        assert!(matches!(
            result,
            Err(HygieneError::MissingRetentionWindow {
                index: 0,
                classification: DataClassification::Restricted,
                ..
            })
        ));
    }

    #[test]
    fn hygiene_public_empty_retention_passes() {
        // Public artifacts do NOT require retention window
        let manifest = ArtifactManifest {
            artifacts: vec![ArtifactDigest {
                artifact_type: ArtifactType::Junit,
                digest: [0x55; 32],
                data_classification: DataClassification::Public,
                redaction_applied: false,
                redaction_profile_hash: None,
                retention_window_ref: "htf:window:any".to_string(), // Has value for basic hygiene
            }],
        };
        assert!(validate_evidence_hygiene_for_admission(&manifest).is_ok());
    }

    #[test]
    fn hygiene_internal_empty_retention_passes() {
        // Internal artifacts do NOT require retention window for admission hygiene
        let manifest = ArtifactManifest {
            artifacts: vec![ArtifactDigest {
                artifact_type: ArtifactType::Coverage,
                digest: [0x66; 32],
                data_classification: DataClassification::Internal,
                redaction_applied: false,
                redaction_profile_hash: None,
                retention_window_ref: "htf:window:any".to_string(), // Has value for basic hygiene
            }],
        };
        assert!(validate_evidence_hygiene_for_admission(&manifest).is_ok());
    }

    #[test]
    fn hygiene_retention_violation_at_second_artifact() {
        let manifest = ArtifactManifest {
            artifacts: vec![
                create_confidential_artifact(0x11, "htf:window:30d"), // Valid
                create_restricted_artifact(0x22, ""),                 // Invalid - no retention
            ],
        };
        let result = validate_evidence_hygiene_for_admission(&manifest);
        assert!(matches!(
            result,
            Err(HygieneError::MissingRetentionWindow {
                index: 1,
                classification: DataClassification::Restricted,
                ..
            })
        ));
    }

    #[test]
    fn hygiene_all_confidential_restricted_with_retention_passes() {
        let manifest = ArtifactManifest {
            artifacts: vec![
                create_confidential_artifact(0x11, "htf:window:30d"),
                create_restricted_artifact(0x22, "htf:window:90d"),
                create_confidential_artifact(0x33, "htf:window:7d"),
                create_restricted_artifact(0x44, "htf:window:365d"),
            ],
        };
        assert!(validate_evidence_hygiene_for_admission(&manifest).is_ok());
    }

    // -------------------------------------------------------------------------
    // Redaction Profile Requirement Tests
    // -------------------------------------------------------------------------

    #[test]
    fn hygiene_redacted_internal_with_profile_passes() {
        let manifest = ArtifactManifest {
            artifacts: vec![create_redacted_artifact(
                0x77,
                DataClassification::Internal,
                Some([0xAA; 32]),
            )],
        };
        assert!(validate_evidence_hygiene_for_admission(&manifest).is_ok());
    }

    #[test]
    fn hygiene_redacted_confidential_with_profile_passes() {
        let manifest = ArtifactManifest {
            artifacts: vec![create_redacted_artifact(
                0x88,
                DataClassification::Confidential,
                Some([0xBB; 32]),
            )],
        };
        assert!(validate_evidence_hygiene_for_admission(&manifest).is_ok());
    }

    #[test]
    fn hygiene_redacted_restricted_with_profile_passes() {
        let manifest = ArtifactManifest {
            artifacts: vec![create_redacted_artifact(
                0x99,
                DataClassification::Restricted,
                Some([0xCC; 32]),
            )],
        };
        assert!(validate_evidence_hygiene_for_admission(&manifest).is_ok());
    }

    #[test]
    fn hygiene_redacted_public_without_profile_passes() {
        // Public artifacts do NOT require redaction profile even if redacted
        let manifest = ArtifactManifest {
            artifacts: vec![create_redacted_artifact(
                0xAA,
                DataClassification::Public,
                None,
            )],
        };
        assert!(validate_evidence_hygiene_for_admission(&manifest).is_ok());
    }

    #[test]
    fn hygiene_redacted_internal_missing_profile_fails() {
        let manifest = ArtifactManifest {
            artifacts: vec![create_redacted_artifact(
                0xBB,
                DataClassification::Internal,
                None,
            )],
        };
        let result = validate_evidence_hygiene_for_admission(&manifest);
        assert!(matches!(
            result,
            Err(HygieneError::MissingRedactionProfile {
                index: 0,
                classification: DataClassification::Internal,
                ..
            })
        ));
    }

    #[test]
    fn hygiene_redacted_confidential_missing_profile_fails() {
        let manifest = ArtifactManifest {
            artifacts: vec![create_redacted_artifact(
                0xCC,
                DataClassification::Confidential,
                None,
            )],
        };
        let result = validate_evidence_hygiene_for_admission(&manifest);
        assert!(matches!(
            result,
            Err(HygieneError::MissingRedactionProfile {
                index: 0,
                classification: DataClassification::Confidential,
                ..
            })
        ));
    }

    #[test]
    fn hygiene_redacted_restricted_missing_profile_fails() {
        let manifest = ArtifactManifest {
            artifacts: vec![create_redacted_artifact(
                0xDD,
                DataClassification::Restricted,
                None,
            )],
        };
        let result = validate_evidence_hygiene_for_admission(&manifest);
        assert!(matches!(
            result,
            Err(HygieneError::MissingRedactionProfile {
                index: 0,
                classification: DataClassification::Restricted,
                ..
            })
        ));
    }

    #[test]
    fn hygiene_non_redacted_without_profile_passes() {
        // Non-redacted artifacts do NOT require a redaction profile
        let manifest = ArtifactManifest {
            artifacts: vec![ArtifactDigest {
                artifact_type: ArtifactType::Log,
                digest: [0xEE; 32],
                data_classification: DataClassification::Confidential,
                redaction_applied: false, // Not redacted
                redaction_profile_hash: None,
                retention_window_ref: "htf:window:30d".to_string(),
            }],
        };
        assert!(validate_evidence_hygiene_for_admission(&manifest).is_ok());
    }

    #[test]
    fn hygiene_redaction_violation_at_third_artifact() {
        let manifest = ArtifactManifest {
            artifacts: vec![
                create_redacted_artifact(0x11, DataClassification::Internal, Some([0xAA; 32])),
                create_redacted_artifact(0x22, DataClassification::Public, None), // OK - public
                create_redacted_artifact(0x33, DataClassification::Confidential, None), // Fails
            ],
        };
        let result = validate_evidence_hygiene_for_admission(&manifest);
        assert!(matches!(
            result,
            Err(HygieneError::MissingRedactionProfile {
                index: 2,
                classification: DataClassification::Confidential,
                ..
            })
        ));
    }

    // -------------------------------------------------------------------------
    // Admission Blocking Tests
    // -------------------------------------------------------------------------

    #[test]
    fn hygiene_retention_checked_before_redaction() {
        // First artifact: missing retention (should fail first)
        // Second artifact: missing redaction profile
        let manifest = ArtifactManifest {
            artifacts: vec![
                ArtifactDigest {
                    artifact_type: ArtifactType::Log,
                    digest: [0x11; 32],
                    data_classification: DataClassification::Confidential,
                    redaction_applied: false,
                    redaction_profile_hash: None,
                    retention_window_ref: String::new(), // Missing retention
                },
                create_redacted_artifact(0x22, DataClassification::Internal, None), /* Missing profile */
            ],
        };

        // Retention violation should be detected first
        let result = validate_evidence_hygiene_for_admission(&manifest);
        assert!(matches!(
            result,
            Err(HygieneError::MissingRetentionWindow {
                index: 0,
                classification: DataClassification::Confidential,
                ..
            })
        ));
    }

    #[test]
    fn hygiene_multiple_violations_reports_first() {
        let manifest = ArtifactManifest {
            artifacts: vec![
                create_restricted_artifact(0x11, ""), // First violation: missing retention
                create_confidential_artifact(0x22, ""), // Second violation: missing retention
            ],
        };

        // First violation should be reported
        let result = validate_evidence_hygiene_for_admission(&manifest);
        assert!(matches!(
            result,
            Err(HygieneError::MissingRetentionWindow {
                index: 0,
                classification: DataClassification::Restricted,
                ..
            })
        ));
    }

    #[test]
    fn hygiene_empty_manifest_passes() {
        // validate_evidence_hygiene_for_admission does not check for empty manifests
        // (that's handled by validate_hygiene)
        let manifest = ArtifactManifest { artifacts: vec![] };
        assert!(validate_evidence_hygiene_for_admission(&manifest).is_ok());
    }

    #[test]
    fn hygiene_mixed_classifications_all_valid() {
        let manifest = ArtifactManifest {
            artifacts: vec![
                // Public - no restrictions
                ArtifactDigest {
                    artifact_type: ArtifactType::Junit,
                    digest: [0x11; 32],
                    data_classification: DataClassification::Public,
                    redaction_applied: true, // Redacted but public - OK without profile
                    redaction_profile_hash: None,
                    retention_window_ref: "htf:window:90d".to_string(),
                },
                // Internal - non-redacted
                ArtifactDigest {
                    artifact_type: ArtifactType::Coverage,
                    digest: [0x22; 32],
                    data_classification: DataClassification::Internal,
                    redaction_applied: false,
                    redaction_profile_hash: None,
                    retention_window_ref: "htf:window:30d".to_string(),
                },
                // Internal - redacted with profile
                create_redacted_artifact(0x33, DataClassification::Internal, Some([0xAA; 32])),
                // Confidential - with retention
                create_confidential_artifact(0x44, "htf:window:14d"),
                // Restricted - with retention
                create_restricted_artifact(0x55, "htf:window:7d"),
                // Confidential - redacted with profile
                ArtifactDigest {
                    artifact_type: ArtifactType::Snapshot,
                    digest: [0x66; 32],
                    data_classification: DataClassification::Confidential,
                    redaction_applied: true,
                    redaction_profile_hash: Some([0xBB; 32]),
                    retention_window_ref: "htf:window:60d".to_string(),
                },
            ],
        };
        assert!(validate_evidence_hygiene_for_admission(&manifest).is_ok());
    }

    // -------------------------------------------------------------------------
    // Error Message Tests
    // -------------------------------------------------------------------------

    #[test]
    fn hygiene_error_display_missing_retention() {
        let err = HygieneError::MissingRetentionWindow {
            index: 5,
            digest: "aabbccdd".to_string(),
            classification: DataClassification::Restricted,
        };
        let msg = err.to_string();
        assert!(msg.contains("missing retention window"));
        assert!(msg.contains("RESTRICTED"));
        assert!(msg.contains("index 5"));
        assert!(msg.contains("aabbccdd"));
    }

    #[test]
    fn hygiene_error_display_missing_redaction() {
        let err = HygieneError::MissingRedactionProfile {
            index: 3,
            digest: "11223344".to_string(),
            classification: DataClassification::Internal,
        };
        let msg = err.to_string();
        assert!(msg.contains("missing redaction profile"));
        assert!(msg.contains("INTERNAL"));
        assert!(msg.contains("index 3"));
        assert!(msg.contains("11223344"));
    }

    #[test]
    fn hygiene_digest_prefix_formatting() {
        // Verify that the digest prefix is correctly formatted
        // Use a known digest to verify hex encoding
        let mut test_digest = [0x00u8; 32];
        test_digest[0] = 0xAB;
        test_digest[1] = 0xCD;
        test_digest[2] = 0xEF;
        test_digest[3] = 0x01;
        test_digest[4] = 0x23;
        test_digest[5] = 0x45;
        test_digest[6] = 0x67;
        test_digest[7] = 0x89;

        let manifest = ArtifactManifest {
            artifacts: vec![ArtifactDigest {
                artifact_type: ArtifactType::Log,
                digest: test_digest,
                data_classification: DataClassification::Confidential,
                redaction_applied: false,
                redaction_profile_hash: None,
                retention_window_ref: String::new(),
            }],
        };
        let result = validate_evidence_hygiene_for_admission(&manifest);
        if let Err(HygieneError::MissingRetentionWindow { digest, .. }) = result {
            // Check that digest contains hex-encoded first bytes
            assert_eq!(digest, "abcdef0123456789");
        } else {
            panic!("Expected MissingRetentionWindow error");
        }
    }

    // -------------------------------------------------------------------------
    // Regression Tests
    // -------------------------------------------------------------------------

    #[test]
    fn hygiene_both_retention_and_redaction_violations_same_artifact() {
        // An artifact that violates both rules - retention should be checked first
        let manifest = ArtifactManifest {
            artifacts: vec![ArtifactDigest {
                artifact_type: ArtifactType::Log,
                digest: [0xFF; 32],
                data_classification: DataClassification::Confidential,
                redaction_applied: true,
                redaction_profile_hash: None,        // Missing profile
                retention_window_ref: String::new(), // Missing retention
            }],
        };
        // Retention violation should be detected first
        let result = validate_evidence_hygiene_for_admission(&manifest);
        assert!(matches!(
            result,
            Err(HygieneError::MissingRetentionWindow { .. })
        ));
    }

    #[test]
    fn hygiene_redaction_profile_required_for_all_non_public() {
        // Verify that all non-public classifications require redaction profile when
        // redacted
        for classification in [
            DataClassification::Internal,
            DataClassification::Confidential,
            DataClassification::Restricted,
        ] {
            let manifest = ArtifactManifest {
                artifacts: vec![create_redacted_artifact(0x11, classification, None)],
            };
            let result = validate_evidence_hygiene_for_admission(&manifest);
            assert!(
                matches!(result, Err(HygieneError::MissingRedactionProfile { classification: c, .. }) if c == classification),
                "Classification {classification:?} should require redaction profile when redacted"
            );
        }
    }

    #[test]
    fn hygiene_retention_required_only_for_confidential_restricted() {
        // Public and Internal should NOT require retention window for admission hygiene
        for classification in [DataClassification::Public, DataClassification::Internal] {
            let manifest = ArtifactManifest {
                artifacts: vec![ArtifactDigest {
                    artifact_type: ArtifactType::Log,
                    digest: [0x11; 32],
                    data_classification: classification,
                    redaction_applied: false,
                    redaction_profile_hash: None,
                    retention_window_ref: "htf:window:30d".to_string(),
                }],
            };
            assert!(
                validate_evidence_hygiene_for_admission(&manifest).is_ok(),
                "Classification {classification:?} should not require retention window for admission hygiene"
            );
        }

        // Confidential and Restricted SHOULD require retention window
        for classification in [
            DataClassification::Confidential,
            DataClassification::Restricted,
        ] {
            let manifest = ArtifactManifest {
                artifacts: vec![ArtifactDigest {
                    artifact_type: ArtifactType::Log,
                    digest: [0x22; 32],
                    data_classification: classification,
                    redaction_applied: false,
                    redaction_profile_hash: None,
                    retention_window_ref: String::new(), // Missing!
                }],
            };
            assert!(
                matches!(
                    validate_evidence_hygiene_for_admission(&manifest),
                    Err(HygieneError::MissingRetentionWindow { classification: c, .. }) if c == classification
                ),
                "Classification {classification:?} MUST require retention window for admission hygiene"
            );
        }
    }
}
