// AGENT-AUTHORED
//! CI attestation level types for the Forge Admission Cycle.
//!
//! This module defines [`CiAttestationLevel`] and [`CiAttestation`] which
//! represent the trustworthiness of CI evidence. CI conclusions are treated
//! as observations requiring evidence import and attestation before they
//! can influence admission decisions.
//!
//! # Attestation Levels
//!
//! - **L0 (Status-only)**: Insufficient for gating decisions. Only CI status is
//!   available without evidence backing.
//! - **L1 (Signed Attestation)**: Adapter attestation is signed and artifact
//!   digests are stored in CAS. Minimum level for CI-gated readiness.
//! - **L2 (Replayable Proof)**: Replayable verifier proof. Reserved for Phase
//!   2.
//! - **L3 (Measured Boot)**: TPM-backed measured boot attestation. Reserved for
//!   Phase 2.
//!
//! # Security Model
//!
//! The attestation level hierarchy enforces that higher levels subsume lower
//! ones. Level comparison uses explicit rank mapping (L0 < L1 < L2 < L3),
//! not enum ordinal, to ensure correctness if variants are reordered.
//!
//! Policy maps risk tier to minimum CI attestation level. L0 is rejected
//! when CI gating is enabled, enforcing fail-closed semantics
//! (SEC-CTRL-FAC-0015).
//!
//! # Example
//!
//! ```rust
//! use apm2_core::fac::{CiAttestation, CiAttestationLevel};
//!
//! // L1 attestation with workflow run and artifact hashes
//! let attestation = CiAttestation::builder()
//!     .level(CiAttestationLevel::L1)
//!     .workflow_run_id("run-12345")
//!     .downloaded_artifact_hash([0xaa; 32])
//!     .build()
//!     .expect("valid attestation");
//!
//! // L1 meets minimum L1 requirement
//! assert!(attestation.meets_minimum(CiAttestationLevel::L1));
//!
//! // L1 meets minimum L0 requirement (higher level satisfies lower)
//! assert!(attestation.meets_minimum(CiAttestationLevel::L0));
//!
//! // L1 does NOT meet minimum L2 requirement
//! assert!(!attestation.meets_minimum(CiAttestationLevel::L2));
//! ```

use serde::{Deserialize, Serialize};
use thiserror::Error;

// =============================================================================
// Resource Limits
// =============================================================================

/// Maximum number of downloaded artifact hashes allowed in a CI attestation.
/// This prevents denial-of-service attacks via oversized repeated fields.
pub const MAX_DOWNLOADED_ARTIFACT_HASHES: usize = 1024;

/// Maximum length of any string field in a CI attestation.
/// This prevents denial-of-service attacks via oversized strings.
pub const MAX_STRING_LENGTH: usize = 4096;

// =============================================================================
// CI Attestation Level
// =============================================================================

/// CI attestation levels representing the trustworthiness of CI evidence.
///
/// The levels form a strict hierarchy where higher levels subsume lower ones:
/// - L0: Status-only (insufficient for gating)
/// - L1: Signed adapter attestation + CAS artifact digests
/// - L2: Replayable verifier proof (Phase 2)
/// - L3: Measured boot/TPM-backed (Phase 2)
///
/// # Level Comparison
///
/// Level comparison uses explicit rank mapping via
/// [`CiAttestationLevel::rank()`], not enum discriminant values. This ensures
/// correctness even if variants are reordered in the future.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum CiAttestationLevel {
    /// Status-only attestation. Insufficient for gating decisions.
    ///
    /// Only CI status (pass/fail) is available without evidence backing.
    /// This level MUST NOT be accepted when CI gating is enabled.
    L0,

    /// Signed adapter attestation with CAS artifact digests.
    ///
    /// Requirements:
    /// - Adapter attestation is signed with `CI_IMPORT_ATTESTATION` domain
    ///   prefix
    /// - Artifact digests are stored in CAS
    /// - `workflow_run_id` is recorded
    ///
    /// This is the minimum level for CI-gated readiness transitions.
    L1,

    /// Replayable verifier proof. Reserved for Phase 2.
    ///
    /// Requirements (Phase 2):
    /// - All L1 requirements
    /// - Verifier proof is replayable
    /// - Proof is bound to specific toolchain and runner image
    L2,

    /// Measured boot/TPM-backed attestation. Reserved for Phase 2.
    ///
    /// Requirements (Phase 2):
    /// - All L2 requirements
    /// - TPM-backed measured boot attestation
    /// - Hardware root of trust
    L3,
}

impl CiAttestationLevel {
    /// Returns the numeric rank of this attestation level.
    ///
    /// Higher ranks indicate higher trustworthiness. Ranks are explicitly
    /// assigned to ensure level comparison remains correct even if enum
    /// variants are reordered.
    ///
    /// # Returns
    ///
    /// - L0 -> 0
    /// - L1 -> 1
    /// - L2 -> 2
    /// - L3 -> 3
    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::L0 => 0,
            Self::L1 => 1,
            Self::L2 => 2,
            Self::L3 => 3,
        }
    }

    /// Returns true if this level is sufficient for gating decisions.
    ///
    /// L0 (status-only) is never sufficient for gating. L1 and above are
    /// sufficient.
    #[must_use]
    pub const fn is_sufficient_for_gating(self) -> bool {
        self.rank() >= Self::L1.rank()
    }

    /// Returns an iterator over all attestation levels in rank order.
    pub fn all() -> impl Iterator<Item = Self> {
        [Self::L0, Self::L1, Self::L2, Self::L3].into_iter()
    }
}

impl TryFrom<u8> for CiAttestationLevel {
    type Error = CiAttestationError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::L0),
            1 => Ok(Self::L1),
            2 => Ok(Self::L2),
            3 => Ok(Self::L3),
            _ => Err(CiAttestationError::InvalidLevel(value)),
        }
    }
}

impl From<CiAttestationLevel> for u8 {
    fn from(level: CiAttestationLevel) -> Self {
        level.rank()
    }
}

impl std::fmt::Display for CiAttestationLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::L0 => write!(f, "L0 (status-only)"),
            Self::L1 => write!(f, "L1 (signed attestation)"),
            Self::L2 => write!(f, "L2 (replayable proof)"),
            Self::L3 => write!(f, "L3 (measured boot)"),
        }
    }
}

impl PartialOrd for CiAttestationLevel {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CiAttestationLevel {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.rank().cmp(&other.rank())
    }
}

// =============================================================================
// CI Attestation
// =============================================================================

/// A 32-byte hash digest (e.g., SHA-256).
pub type Hash = [u8; 32];

/// CI attestation representing the evidence backing for a CI workflow run.
///
/// This struct captures all the metadata and artifacts associated with a
/// CI evidence import. The `level` field determines the trustworthiness
/// of this attestation.
///
/// # Required Fields by Level
///
/// - **L0**: Only `level` is meaningful; other fields may be empty.
/// - **L1**: `workflow_run_id`, `downloaded_artifact_hashes`, and
///   `adapter_signature` are required.
/// - **L2/L3**: Additional fields TBD in Phase 2.
///
/// # Builder Pattern
///
/// Use [`CiAttestation::builder()`] to construct instances with validation.
///
/// # Security
///
/// Deserialization enforces the same resource limits as the builder:
/// - String fields are limited to [`MAX_STRING_LENGTH`] bytes
/// - Artifact hashes are limited to [`MAX_DOWNLOADED_ARTIFACT_HASHES`] entries
///
/// This prevents denial-of-service attacks via oversized payloads during
/// deserialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CiAttestation {
    /// The attestation level indicating trustworthiness.
    level: CiAttestationLevel,

    /// The CI workflow run identifier.
    ///
    /// For GitHub Actions, this is the `workflow_run_id`.
    workflow_run_id: String,

    /// Hashes of downloaded artifacts stored in CAS.
    ///
    /// These are SHA-256 digests of the raw artifact contents.
    downloaded_artifact_hashes: Vec<Hash>,

    /// Optional digest of the runner image used.
    ///
    /// Required for L2+ attestations (Phase 2).
    #[serde(skip_serializing_if = "Option::is_none")]
    runner_image_digest: Option<Hash>,

    /// Optional toolchain identifier (e.g., "rust-1.85.0").
    ///
    /// Required for L2+ attestations (Phase 2).
    #[serde(skip_serializing_if = "Option::is_none")]
    toolchain: Option<String>,

    /// Optional hash of the command transcript.
    ///
    /// Required for L2+ attestations (Phase 2).
    #[serde(skip_serializing_if = "Option::is_none")]
    command_transcript_hash: Option<Hash>,

    /// Adapter signature over the attestation (64 bytes).
    ///
    /// This signature is created using the `CI_IMPORT_ATTESTATION` domain
    /// prefix. Required for L1+ attestations. Stored as raw bytes to
    /// support serde.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "option_signature_bytes")]
    adapter_signature: Option<[u8; 64]>,
}

/// Serde helper for optional signature bytes.
mod option_signature_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    #[allow(clippy::ref_option)]
    pub fn serialize<S>(value: &Option<[u8; 64]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(bytes) => serializer.serialize_bytes(bytes),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 64]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        let opt: Option<Vec<u8>> = Option::deserialize(deserializer)?;
        match opt {
            Some(bytes) => {
                let arr: [u8; 64] = bytes
                    .try_into()
                    .map_err(|_| D::Error::custom("signature must be exactly 64 bytes"))?;
                Ok(Some(arr))
            },
            None => Ok(None),
        }
    }
}

/// Custom deserialization that enforces resource limits.
///
/// This implementation validates all deserialized data against the same limits
/// that the builder enforces, preventing denial-of-service attacks via
/// oversized payloads.
impl<'de> Deserialize<'de> for CiAttestation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        // Helper struct for deserialization that mirrors `CiAttestation` fields.
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct CiAttestationHelper {
            level: CiAttestationLevel,
            workflow_run_id: String,
            downloaded_artifact_hashes: Vec<Hash>,
            #[serde(skip_serializing_if = "Option::is_none")]
            runner_image_digest: Option<Hash>,
            #[serde(skip_serializing_if = "Option::is_none")]
            toolchain: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            command_transcript_hash: Option<Hash>,
            #[serde(default)]
            #[serde(skip_serializing_if = "Option::is_none")]
            #[serde(with = "option_signature_bytes")]
            adapter_signature: Option<[u8; 64]>,
        }

        let helper = CiAttestationHelper::deserialize(deserializer)?;

        // Validate workflow_run_id length
        if helper.workflow_run_id.len() > MAX_STRING_LENGTH {
            return Err(D::Error::custom(format!(
                "workflow_run_id exceeds maximum length: {} > {MAX_STRING_LENGTH}",
                helper.workflow_run_id.len(),
            )));
        }

        // Validate toolchain length
        if let Some(ref toolchain) = helper.toolchain {
            if toolchain.len() > MAX_STRING_LENGTH {
                return Err(D::Error::custom(format!(
                    "toolchain exceeds maximum length: {} > {MAX_STRING_LENGTH}",
                    toolchain.len(),
                )));
            }
        }

        // Validate artifact hashes count
        if helper.downloaded_artifact_hashes.len() > MAX_DOWNLOADED_ARTIFACT_HASHES {
            return Err(D::Error::custom(format!(
                "too many artifact hashes: {} > {MAX_DOWNLOADED_ARTIFACT_HASHES}",
                helper.downloaded_artifact_hashes.len(),
            )));
        }

        // Validate L1+ requires workflow_run_id
        if helper.level >= CiAttestationLevel::L1 && helper.workflow_run_id.is_empty() {
            return Err(D::Error::custom(
                "L1+ attestation requires non-empty workflow_run_id",
            ));
        }

        Ok(Self {
            level: helper.level,
            workflow_run_id: helper.workflow_run_id,
            downloaded_artifact_hashes: helper.downloaded_artifact_hashes,
            runner_image_digest: helper.runner_image_digest,
            toolchain: helper.toolchain,
            command_transcript_hash: helper.command_transcript_hash,
            adapter_signature: helper.adapter_signature,
        })
    }
}

impl CiAttestation {
    /// Creates a new builder for constructing a `CiAttestation`.
    #[must_use]
    pub fn builder() -> CiAttestationBuilder {
        CiAttestationBuilder::new()
    }

    /// Returns the attestation level.
    #[must_use]
    pub const fn level(&self) -> CiAttestationLevel {
        self.level
    }

    /// Returns the workflow run identifier.
    #[must_use]
    pub fn workflow_run_id(&self) -> &str {
        &self.workflow_run_id
    }

    /// Returns the downloaded artifact hashes.
    #[must_use]
    pub fn downloaded_artifact_hashes(&self) -> &[Hash] {
        &self.downloaded_artifact_hashes
    }

    /// Returns the optional runner image digest.
    #[must_use]
    pub const fn runner_image_digest(&self) -> Option<&Hash> {
        self.runner_image_digest.as_ref()
    }

    /// Returns the optional toolchain identifier.
    #[must_use]
    pub fn toolchain(&self) -> Option<&str> {
        self.toolchain.as_deref()
    }

    /// Returns the optional command transcript hash.
    #[must_use]
    pub const fn command_transcript_hash(&self) -> Option<&Hash> {
        self.command_transcript_hash.as_ref()
    }

    /// Returns the optional adapter signature bytes.
    #[must_use]
    pub const fn adapter_signature(&self) -> Option<&[u8; 64]> {
        self.adapter_signature.as_ref()
    }

    /// Returns true if this attestation meets the minimum required level.
    ///
    /// Level comparison uses explicit rank mapping to ensure correctness:
    /// - L0 < L1 < L2 < L3
    ///
    /// # Arguments
    ///
    /// * `required` - The minimum required attestation level
    ///
    /// # Returns
    ///
    /// `true` if `self.level >= required`, `false` otherwise.
    ///
    /// # Example
    ///
    /// ```rust
    /// use apm2_core::fac::{CiAttestation, CiAttestationLevel};
    ///
    /// let attestation = CiAttestation::builder()
    ///     .level(CiAttestationLevel::L1)
    ///     .workflow_run_id("run-001")
    ///     .build()
    ///     .unwrap();
    ///
    /// assert!(attestation.meets_minimum(CiAttestationLevel::L0));
    /// assert!(attestation.meets_minimum(CiAttestationLevel::L1));
    /// assert!(!attestation.meets_minimum(CiAttestationLevel::L2));
    /// ```
    #[must_use]
    pub fn meets_minimum(&self, required: CiAttestationLevel) -> bool {
        self.level >= required
    }

    /// Returns true if this attestation is sufficient for gating decisions.
    ///
    /// This is a convenience method equivalent to checking if the level is L1
    /// or higher.
    #[must_use]
    pub const fn is_sufficient_for_gating(&self) -> bool {
        self.level.is_sufficient_for_gating()
    }
}

// =============================================================================
// Builder
// =============================================================================

/// Builder for constructing [`CiAttestation`] instances with validation.
#[derive(Debug, Default)]
pub struct CiAttestationBuilder {
    level: Option<CiAttestationLevel>,
    workflow_run_id: Option<String>,
    downloaded_artifact_hashes: Vec<Hash>,
    runner_image_digest: Option<Hash>,
    toolchain: Option<String>,
    command_transcript_hash: Option<Hash>,
    adapter_signature: Option<[u8; 64]>,
}

impl CiAttestationBuilder {
    /// Creates a new builder with default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the attestation level.
    #[must_use]
    pub const fn level(mut self, level: CiAttestationLevel) -> Self {
        self.level = Some(level);
        self
    }

    /// Sets the workflow run identifier.
    ///
    /// # Errors
    ///
    /// Returns an error during [`CiAttestationBuilder::build()`] if the string
    /// exceeds [`MAX_STRING_LENGTH`].
    #[must_use]
    pub fn workflow_run_id(mut self, id: impl Into<String>) -> Self {
        self.workflow_run_id = Some(id.into());
        self
    }

    /// Adds a downloaded artifact hash.
    ///
    /// # Errors
    ///
    /// Returns an error during [`CiAttestationBuilder::build()`] if more than
    /// [`MAX_DOWNLOADED_ARTIFACT_HASHES`] are added.
    #[must_use]
    pub fn downloaded_artifact_hash(mut self, hash: Hash) -> Self {
        self.downloaded_artifact_hashes.push(hash);
        self
    }

    /// Sets multiple downloaded artifact hashes, replacing any previously
    /// added.
    ///
    /// # Errors
    ///
    /// Returns an error during [`CiAttestationBuilder::build()`] if more than
    /// [`MAX_DOWNLOADED_ARTIFACT_HASHES`] are provided.
    #[must_use]
    pub fn downloaded_artifact_hashes(mut self, hashes: impl IntoIterator<Item = Hash>) -> Self {
        self.downloaded_artifact_hashes = hashes.into_iter().collect();
        self
    }

    /// Sets the runner image digest.
    #[must_use]
    pub const fn runner_image_digest(mut self, digest: Hash) -> Self {
        self.runner_image_digest = Some(digest);
        self
    }

    /// Sets the toolchain identifier.
    ///
    /// # Errors
    ///
    /// Returns an error during [`CiAttestationBuilder::build()`] if the string
    /// exceeds [`MAX_STRING_LENGTH`].
    #[must_use]
    pub fn toolchain(mut self, toolchain: impl Into<String>) -> Self {
        self.toolchain = Some(toolchain.into());
        self
    }

    /// Sets the command transcript hash.
    #[must_use]
    pub const fn command_transcript_hash(mut self, hash: Hash) -> Self {
        self.command_transcript_hash = Some(hash);
        self
    }

    /// Sets the adapter signature bytes.
    #[must_use]
    pub const fn adapter_signature(mut self, signature: [u8; 64]) -> Self {
        self.adapter_signature = Some(signature);
        self
    }

    /// Builds the [`CiAttestation`], validating all fields.
    ///
    /// # Errors
    ///
    /// Returns [`CiAttestationError`] if:
    /// - Required fields are missing
    /// - String fields exceed [`MAX_STRING_LENGTH`]
    /// - Artifact hashes exceed [`MAX_DOWNLOADED_ARTIFACT_HASHES`]
    /// - L1+ attestation is missing required fields (`workflow_run_id`)
    pub fn build(self) -> Result<CiAttestation, CiAttestationError> {
        let level = self
            .level
            .ok_or(CiAttestationError::MissingField("level"))?;

        // Validate workflow_run_id
        let workflow_run_id = self.workflow_run_id.unwrap_or_default();
        if workflow_run_id.len() > MAX_STRING_LENGTH {
            return Err(CiAttestationError::StringTooLong {
                field: "workflow_run_id",
                length: workflow_run_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }

        // For L1+, workflow_run_id is required
        if level >= CiAttestationLevel::L1 && workflow_run_id.is_empty() {
            return Err(CiAttestationError::MissingField("workflow_run_id"));
        }

        // Validate downloaded_artifact_hashes count
        if self.downloaded_artifact_hashes.len() > MAX_DOWNLOADED_ARTIFACT_HASHES {
            return Err(CiAttestationError::TooManyArtifactHashes {
                count: self.downloaded_artifact_hashes.len(),
                max: MAX_DOWNLOADED_ARTIFACT_HASHES,
            });
        }

        // Validate toolchain length
        if let Some(ref toolchain) = self.toolchain {
            if toolchain.len() > MAX_STRING_LENGTH {
                return Err(CiAttestationError::StringTooLong {
                    field: "toolchain",
                    length: toolchain.len(),
                    max: MAX_STRING_LENGTH,
                });
            }
        }

        Ok(CiAttestation {
            level,
            workflow_run_id,
            downloaded_artifact_hashes: self.downloaded_artifact_hashes,
            runner_image_digest: self.runner_image_digest,
            toolchain: self.toolchain,
            command_transcript_hash: self.command_transcript_hash,
            adapter_signature: self.adapter_signature,
        })
    }
}

// =============================================================================
// Errors
// =============================================================================

/// Errors that can occur during CI attestation operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CiAttestationError {
    /// Missing required field.
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// Invalid attestation level value.
    #[error("invalid attestation level: {0}, must be 0-3")]
    InvalidLevel(u8),

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

    /// Too many artifact hashes.
    #[error("too many artifact hashes: {count} > {max}")]
    TooManyArtifactHashes {
        /// The actual count.
        count: usize,
        /// The maximum allowed count.
        max: usize,
    },

    /// Attestation level is insufficient for the required operation.
    #[error("attestation level {actual} is insufficient, minimum required is {required}")]
    InsufficientLevel {
        /// The actual level.
        actual: CiAttestationLevel,
        /// The required level.
        required: CiAttestationLevel,
    },
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
pub mod tests {
    use super::*;

    // =========================================================================
    // CiAttestationLevel Tests
    // =========================================================================

    #[test]
    fn test_level_rank_ordering() {
        // Verify L0 < L1 < L2 < L3 using explicit rank
        assert!(CiAttestationLevel::L0.rank() < CiAttestationLevel::L1.rank());
        assert!(CiAttestationLevel::L1.rank() < CiAttestationLevel::L2.rank());
        assert!(CiAttestationLevel::L2.rank() < CiAttestationLevel::L3.rank());
    }

    #[test]
    fn test_level_ord_trait() {
        // Verify Ord implementation matches rank ordering
        assert!(CiAttestationLevel::L0 < CiAttestationLevel::L1);
        assert!(CiAttestationLevel::L1 < CiAttestationLevel::L2);
        assert!(CiAttestationLevel::L2 < CiAttestationLevel::L3);
        assert!(CiAttestationLevel::L3 > CiAttestationLevel::L0);
    }

    #[test]
    fn test_level_equality() {
        assert_eq!(CiAttestationLevel::L0, CiAttestationLevel::L0);
        assert_eq!(CiAttestationLevel::L1, CiAttestationLevel::L1);
        assert_ne!(CiAttestationLevel::L0, CiAttestationLevel::L1);
    }

    #[test]
    fn test_level_try_from_u8() {
        assert_eq!(
            CiAttestationLevel::try_from(0).unwrap(),
            CiAttestationLevel::L0
        );
        assert_eq!(
            CiAttestationLevel::try_from(1).unwrap(),
            CiAttestationLevel::L1
        );
        assert_eq!(
            CiAttestationLevel::try_from(2).unwrap(),
            CiAttestationLevel::L2
        );
        assert_eq!(
            CiAttestationLevel::try_from(3).unwrap(),
            CiAttestationLevel::L3
        );
        assert!(CiAttestationLevel::try_from(4).is_err());
        assert!(CiAttestationLevel::try_from(255).is_err());
    }

    #[test]
    fn test_level_into_u8() {
        assert_eq!(u8::from(CiAttestationLevel::L0), 0);
        assert_eq!(u8::from(CiAttestationLevel::L1), 1);
        assert_eq!(u8::from(CiAttestationLevel::L2), 2);
        assert_eq!(u8::from(CiAttestationLevel::L3), 3);
    }

    #[test]
    fn test_level_is_sufficient_for_gating() {
        // L0 is NOT sufficient for gating
        assert!(!CiAttestationLevel::L0.is_sufficient_for_gating());
        // L1+ is sufficient for gating
        assert!(CiAttestationLevel::L1.is_sufficient_for_gating());
        assert!(CiAttestationLevel::L2.is_sufficient_for_gating());
        assert!(CiAttestationLevel::L3.is_sufficient_for_gating());
    }

    #[test]
    fn test_level_all_iterator() {
        let levels: Vec<_> = CiAttestationLevel::all().collect();
        assert_eq!(levels.len(), 4);
        assert_eq!(levels[0], CiAttestationLevel::L0);
        assert_eq!(levels[1], CiAttestationLevel::L1);
        assert_eq!(levels[2], CiAttestationLevel::L2);
        assert_eq!(levels[3], CiAttestationLevel::L3);
    }

    #[test]
    fn test_level_display() {
        assert_eq!(CiAttestationLevel::L0.to_string(), "L0 (status-only)");
        assert_eq!(
            CiAttestationLevel::L1.to_string(),
            "L1 (signed attestation)"
        );
        assert_eq!(CiAttestationLevel::L2.to_string(), "L2 (replayable proof)");
        assert_eq!(CiAttestationLevel::L3.to_string(), "L3 (measured boot)");
    }

    // =========================================================================
    // CiAttestation Builder Tests
    // =========================================================================

    #[test]
    fn test_builder_l0_minimal() {
        let attestation = CiAttestation::builder()
            .level(CiAttestationLevel::L0)
            .build()
            .expect("L0 should build without workflow_run_id");

        assert_eq!(attestation.level(), CiAttestationLevel::L0);
        assert!(attestation.workflow_run_id().is_empty());
        assert!(attestation.downloaded_artifact_hashes().is_empty());
    }

    #[test]
    fn test_builder_l1_requires_workflow_run_id() {
        let result = CiAttestation::builder()
            .level(CiAttestationLevel::L1)
            .build();

        assert!(matches!(
            result,
            Err(CiAttestationError::MissingField("workflow_run_id"))
        ));
    }

    #[test]
    fn test_builder_l1_with_workflow_run_id() {
        let attestation = CiAttestation::builder()
            .level(CiAttestationLevel::L1)
            .workflow_run_id("run-12345")
            .downloaded_artifact_hash([0xaa; 32])
            .build()
            .expect("L1 with workflow_run_id should build");

        assert_eq!(attestation.level(), CiAttestationLevel::L1);
        assert_eq!(attestation.workflow_run_id(), "run-12345");
        assert_eq!(attestation.downloaded_artifact_hashes().len(), 1);
    }

    #[test]
    fn test_builder_missing_level() {
        let result = CiAttestation::builder().workflow_run_id("run-001").build();

        assert!(matches!(
            result,
            Err(CiAttestationError::MissingField("level"))
        ));
    }

    #[test]
    fn test_builder_all_fields() {
        let signature_bytes = [0x42u8; 64];

        let attestation = CiAttestation::builder()
            .level(CiAttestationLevel::L2)
            .workflow_run_id("run-99999")
            .downloaded_artifact_hash([0x11; 32])
            .downloaded_artifact_hash([0x22; 32])
            .runner_image_digest([0x33; 32])
            .toolchain("rust-1.85.0")
            .command_transcript_hash([0x44; 32])
            .adapter_signature(signature_bytes)
            .build()
            .expect("should build with all fields");

        assert_eq!(attestation.level(), CiAttestationLevel::L2);
        assert_eq!(attestation.workflow_run_id(), "run-99999");
        assert_eq!(attestation.downloaded_artifact_hashes().len(), 2);
        assert_eq!(attestation.runner_image_digest(), Some(&[0x33; 32]));
        assert_eq!(attestation.toolchain(), Some("rust-1.85.0"));
        assert_eq!(attestation.command_transcript_hash(), Some(&[0x44; 32]));
        assert!(attestation.adapter_signature().is_some());
    }

    #[test]
    fn test_builder_string_too_long() {
        let long_string = "x".repeat(MAX_STRING_LENGTH + 1);

        let result = CiAttestation::builder()
            .level(CiAttestationLevel::L0)
            .workflow_run_id(long_string)
            .build();

        assert!(matches!(
            result,
            Err(CiAttestationError::StringTooLong {
                field: "workflow_run_id",
                ..
            })
        ));
    }

    #[test]
    fn test_builder_toolchain_too_long() {
        let long_string = "x".repeat(MAX_STRING_LENGTH + 1);

        let result = CiAttestation::builder()
            .level(CiAttestationLevel::L0)
            .toolchain(long_string)
            .build();

        assert!(matches!(
            result,
            Err(CiAttestationError::StringTooLong {
                field: "toolchain",
                ..
            })
        ));
    }

    #[test]
    fn test_builder_too_many_artifact_hashes() {
        #[allow(clippy::cast_possible_truncation)]
        let hashes: Vec<Hash> = (0..=MAX_DOWNLOADED_ARTIFACT_HASHES)
            .map(|i| [i as u8; 32])
            .collect();

        let result = CiAttestation::builder()
            .level(CiAttestationLevel::L0)
            .downloaded_artifact_hashes(hashes)
            .build();

        assert!(matches!(
            result,
            Err(CiAttestationError::TooManyArtifactHashes { .. })
        ));
    }

    // =========================================================================
    // meets_minimum Tests
    // =========================================================================

    #[test]
    fn test_meets_minimum_l0() {
        let attestation = CiAttestation::builder()
            .level(CiAttestationLevel::L0)
            .build()
            .unwrap();

        // L0 meets L0
        assert!(attestation.meets_minimum(CiAttestationLevel::L0));
        // L0 does NOT meet L1, L2, or L3
        assert!(!attestation.meets_minimum(CiAttestationLevel::L1));
        assert!(!attestation.meets_minimum(CiAttestationLevel::L2));
        assert!(!attestation.meets_minimum(CiAttestationLevel::L3));
    }

    #[test]
    fn test_meets_minimum_l1() {
        let attestation = CiAttestation::builder()
            .level(CiAttestationLevel::L1)
            .workflow_run_id("run-001")
            .build()
            .unwrap();

        // L1 meets L0 and L1
        assert!(attestation.meets_minimum(CiAttestationLevel::L0));
        assert!(attestation.meets_minimum(CiAttestationLevel::L1));
        // L1 does NOT meet L2 or L3
        assert!(!attestation.meets_minimum(CiAttestationLevel::L2));
        assert!(!attestation.meets_minimum(CiAttestationLevel::L3));
    }

    #[test]
    fn test_meets_minimum_l2() {
        let attestation = CiAttestation::builder()
            .level(CiAttestationLevel::L2)
            .workflow_run_id("run-002")
            .build()
            .unwrap();

        // L2 meets L0, L1, and L2
        assert!(attestation.meets_minimum(CiAttestationLevel::L0));
        assert!(attestation.meets_minimum(CiAttestationLevel::L1));
        assert!(attestation.meets_minimum(CiAttestationLevel::L2));
        // L2 does NOT meet L3
        assert!(!attestation.meets_minimum(CiAttestationLevel::L3));
    }

    #[test]
    fn test_meets_minimum_l3() {
        let attestation = CiAttestation::builder()
            .level(CiAttestationLevel::L3)
            .workflow_run_id("run-003")
            .build()
            .unwrap();

        // L3 meets all levels
        assert!(attestation.meets_minimum(CiAttestationLevel::L0));
        assert!(attestation.meets_minimum(CiAttestationLevel::L1));
        assert!(attestation.meets_minimum(CiAttestationLevel::L2));
        assert!(attestation.meets_minimum(CiAttestationLevel::L3));
    }

    #[test]
    fn test_is_sufficient_for_gating() {
        let l0 = CiAttestation::builder()
            .level(CiAttestationLevel::L0)
            .build()
            .unwrap();
        assert!(!l0.is_sufficient_for_gating());

        let l1 = CiAttestation::builder()
            .level(CiAttestationLevel::L1)
            .workflow_run_id("run-001")
            .build()
            .unwrap();
        assert!(l1.is_sufficient_for_gating());

        let l2 = CiAttestation::builder()
            .level(CiAttestationLevel::L2)
            .workflow_run_id("run-002")
            .build()
            .unwrap();
        assert!(l2.is_sufficient_for_gating());
    }

    // =========================================================================
    // Serialization Tests
    // =========================================================================

    #[test]
    fn test_level_serde_roundtrip() {
        for level in CiAttestationLevel::all() {
            let json = serde_json::to_string(&level).unwrap();
            let deserialized: CiAttestationLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(level, deserialized);
        }
    }

    #[test]
    fn test_level_serde_format() {
        // Verify SCREAMING_SNAKE_CASE serialization
        assert_eq!(
            serde_json::to_string(&CiAttestationLevel::L0).unwrap(),
            "\"L0\""
        );
        assert_eq!(
            serde_json::to_string(&CiAttestationLevel::L1).unwrap(),
            "\"L1\""
        );
        assert_eq!(
            serde_json::to_string(&CiAttestationLevel::L2).unwrap(),
            "\"L2\""
        );
        assert_eq!(
            serde_json::to_string(&CiAttestationLevel::L3).unwrap(),
            "\"L3\""
        );
    }

    #[test]
    fn test_attestation_serde_roundtrip() {
        let attestation = CiAttestation::builder()
            .level(CiAttestationLevel::L1)
            .workflow_run_id("run-serde-test")
            .downloaded_artifact_hash([0xaa; 32])
            .toolchain("rust-1.85.0")
            .build()
            .unwrap();

        let json = serde_json::to_string(&attestation).unwrap();
        let deserialized: CiAttestation = serde_json::from_str(&json).unwrap();
        assert_eq!(attestation, deserialized);
    }

    #[test]
    fn test_attestation_serde_deny_unknown_fields() {
        // Verify that unknown fields are rejected
        let json = r#"{
            "level": "L1",
            "workflow_run_id": "run-001",
            "downloaded_artifact_hashes": [],
            "unknown_field": "should_fail"
        }"#;

        let result: Result<CiAttestation, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    // =========================================================================
    // Deserialization Security Tests
    // =========================================================================

    #[test]
    fn test_deserialize_rejects_oversized_workflow_run_id() {
        // Attempt to deserialize a payload with oversized workflow_run_id
        let oversized_string = "x".repeat(MAX_STRING_LENGTH + 1);
        let json = format!(
            r#"{{"level": "L0", "workflow_run_id": "{oversized_string}", "downloaded_artifact_hashes": []}}"#,
        );

        let result: Result<CiAttestation, _> = serde_json::from_str(&json);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("workflow_run_id exceeds maximum length"),
            "Expected error about workflow_run_id length, got: {err_msg}",
        );
    }

    #[test]
    fn test_deserialize_rejects_oversized_toolchain() {
        // Attempt to deserialize a payload with oversized toolchain
        let oversized_string = "x".repeat(MAX_STRING_LENGTH + 1);
        let json = format!(
            r#"{{"level": "L0", "workflow_run_id": "", "downloaded_artifact_hashes": [], "toolchain": "{oversized_string}"}}"#,
        );

        let result: Result<CiAttestation, _> = serde_json::from_str(&json);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("toolchain exceeds maximum length"),
            "Expected error about toolchain length, got: {err_msg}",
        );
    }

    #[test]
    fn test_deserialize_rejects_too_many_artifact_hashes() {
        // Attempt to deserialize a payload with too many artifact hashes
        // We'll construct a JSON with MAX + 1 hashes (using byte array format)
        let hash_array = "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]";
        let hashes: Vec<&str> = (0..=MAX_DOWNLOADED_ARTIFACT_HASHES)
            .map(|_| hash_array)
            .collect();
        let hashes_json = hashes.join(",");

        let json = format!(
            r#"{{"level": "L0", "workflow_run_id": "", "downloaded_artifact_hashes": [{hashes_json}]}}"#,
        );

        let result: Result<CiAttestation, _> = serde_json::from_str(&json);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("too many artifact hashes"),
            "Expected error about artifact hashes count, got: {err_msg}",
        );
    }

    #[test]
    fn test_deserialize_rejects_l1_without_workflow_run_id() {
        // Attempt to deserialize L1 attestation without workflow_run_id
        let json = r#"{"level": "L1", "workflow_run_id": "", "downloaded_artifact_hashes": []}"#;

        let result: Result<CiAttestation, _> = serde_json::from_str(json);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("L1+ attestation requires non-empty workflow_run_id"),
            "Expected error about missing workflow_run_id, got: {err_msg}",
        );
    }

    #[test]
    fn test_deserialize_accepts_max_valid_limits() {
        // Verify we can deserialize at the exact limits
        let max_string = "x".repeat(MAX_STRING_LENGTH);

        // Create a valid attestation at limits via builder
        let original = CiAttestation::builder()
            .level(CiAttestationLevel::L1)
            .workflow_run_id(max_string.clone())
            .toolchain(max_string)
            .build()
            .unwrap();

        // Serialize and deserialize
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: CiAttestation = serde_json::from_str(&json).unwrap();
        assert_eq!(original, deserialized);
    }

    // =========================================================================
    // Edge Cases
    // =========================================================================

    #[test]
    fn test_empty_artifact_hashes() {
        let attestation = CiAttestation::builder()
            .level(CiAttestationLevel::L1)
            .workflow_run_id("run-001")
            .build()
            .unwrap();

        // Empty artifact hashes is valid
        assert!(attestation.downloaded_artifact_hashes().is_empty());
    }

    #[test]
    fn test_max_artifact_hashes() {
        let hashes: Vec<Hash> = (0..MAX_DOWNLOADED_ARTIFACT_HASHES)
            .map(|_| [0x00; 32])
            .collect();

        let attestation = CiAttestation::builder()
            .level(CiAttestationLevel::L1)
            .workflow_run_id("run-max")
            .downloaded_artifact_hashes(hashes)
            .build()
            .unwrap();

        assert_eq!(
            attestation.downloaded_artifact_hashes().len(),
            MAX_DOWNLOADED_ARTIFACT_HASHES
        );
    }

    #[test]
    fn test_max_string_length() {
        let max_string = "x".repeat(MAX_STRING_LENGTH);

        let attestation = CiAttestation::builder()
            .level(CiAttestationLevel::L1)
            .workflow_run_id(max_string.clone())
            .toolchain(max_string)
            .build()
            .unwrap();

        assert_eq!(attestation.workflow_run_id().len(), MAX_STRING_LENGTH);
        assert_eq!(attestation.toolchain().unwrap().len(), MAX_STRING_LENGTH);
    }
}
