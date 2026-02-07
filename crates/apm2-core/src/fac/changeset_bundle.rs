// AGENT-AUTHORED
//! `ChangeSet` bundle canonicalization and `ChangeSetPublished` event.
//!
//! This module implements the FAC v0 changeset anchoring mechanism, which
//! ensures that changeset digests are computed deterministically and anchored
//! in the ledger before any review begins.
//!
//! # Design Overview
//!
//! The [`ChangeSetBundleV1`] struct represents the canonical form of a
//! changeset bundle stored in CAS. The [`ChangeSetPublished`] event anchors the
//! changeset digest and CAS hash in the ledger.
//!
//! # Security Properties
//!
//! - **Deterministic Digest**: The `changeset_digest` is computed over
//!   canonical bundle bytes with the `changeset_digest` field itself excluded
//!   from the hash input. This prevents circular dependency and ensures the
//!   same inputs always produce the same digest.
//!
//! - **Domain Separation**: The `ChangeSetPublished` event signature uses the
//!   canonical `CHANGESET_PUBLISHED_PREFIX` domain separator to prevent replay
//!   attacks.
//!
//! - **Anchor Before Review**: The `ChangeSetPublished` event MUST be emitted
//!   before any review activities begin for a work item.
//!
//! # Example
//!
//! ```rust
//! use apm2_core::crypto::Signer;
//! use apm2_core::fac::{
//!     ChangeKind, ChangeSetBundleV1, ChangeSetPublished, FileChange, GitObjectRef, HashAlgo,
//! };
//!
//! // Create a changeset bundle
//! let bundle = ChangeSetBundleV1::builder()
//!     .changeset_id("cs-001")
//!     .base(GitObjectRef {
//!         algo: HashAlgo::Sha1,
//!         object_kind: "commit".to_string(),
//!         object_id: "a".repeat(40),
//!     })
//!     .diff_hash([0x42; 32])
//!     .file_manifest(vec![FileChange {
//!         path: "src/lib.rs".to_string(),
//!         change_kind: ChangeKind::Modify,
//!         old_path: None,
//!     }])
//!     .build()
//!     .expect("valid bundle");
//!
//! // The changeset_digest is computed deterministically
//! let digest = bundle.changeset_digest();
//!
//! // Create the anchor event
//! let signer = Signer::generate();
//! let cas_hash = [0x33; 32]; // Hash of full bundle in CAS
//! let event = ChangeSetPublished::create(
//!     "work-001".to_string(),
//!     digest,
//!     cas_hash,
//!     1_704_067_200_000,
//!     "publisher-001".to_string(),
//!     &signer,
//! )
//! .expect("valid event");
//!
//! // Verify signature
//! assert!(event.verify_signature(&signer.verifying_key()).is_ok());
//! ```

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::domain_separator::{CHANGESET_PUBLISHED_PREFIX, sign_with_domain, verify_with_domain};
use super::policy_resolution::MAX_STRING_LENGTH;
use crate::crypto::{Signature, Signer, VerifyingKey};
// Re-export proto type for wire format serialization
pub use crate::events::ChangeSetPublished as ChangeSetPublishedProto;
use crate::htf::TimeEnvelopeRef;

// =============================================================================
// Resource Limits
// =============================================================================

/// Maximum number of files in the file manifest.
pub const MAX_FILE_MANIFEST_SIZE: usize = 100_000;

/// Maximum length for file paths.
pub const MAX_PATH_LENGTH: usize = 4096;

/// Maximum length for changeset ID.
pub const MAX_CHANGESET_ID_LENGTH: usize = 128;

/// Schema identifier for `ChangeSetBundleV1`.
pub const SCHEMA_IDENTIFIER: &str = "apm2.changeset_bundle.v1";

/// Current schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during changeset bundle operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ChangeSetBundleError {
    /// Missing required field.
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// String field exceeds maximum length.
    #[error("string field '{field}' exceeds maximum length ({len} > {max})")]
    StringTooLong {
        /// The field name.
        field: &'static str,
        /// Actual length.
        len: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// Collection size exceeds limit.
    #[error("collection size exceeds limit: {field} has {actual} items, max is {max}")]
    CollectionTooLarge {
        /// The field name.
        field: &'static str,
        /// Actual size.
        actual: usize,
        /// Maximum allowed size.
        max: usize,
    },

    /// Invalid data in conversion.
    #[error("invalid data: {0}")]
    InvalidData(String),

    /// Signature verification failed.
    #[error("signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    /// Invalid hash algorithm.
    #[error("invalid hash algorithm: {0}")]
    InvalidHashAlgo(String),

    /// Invalid change kind.
    #[error("invalid change kind: {0}")]
    InvalidChangeKind(String),
}

// =============================================================================
// Supporting Types
// =============================================================================

/// Hash algorithm used by the Git repository.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HashAlgo {
    /// SHA-1 (40 hex chars).
    Sha1,
    /// SHA-256 (64 hex chars).
    Sha256,
}

impl HashAlgo {
    /// Returns the expected hex length for this algorithm.
    #[must_use]
    pub const fn hex_length(self) -> usize {
        match self {
            Self::Sha1 => 40,
            Self::Sha256 => 64,
        }
    }
}

impl std::fmt::Display for HashAlgo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sha1 => write!(f, "sha1"),
            Self::Sha256 => write!(f, "sha256"),
        }
    }
}

impl std::str::FromStr for HashAlgo {
    type Err = ChangeSetBundleError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "sha1" => Ok(Self::Sha1),
            "sha256" => Ok(Self::Sha256),
            _ => Err(ChangeSetBundleError::InvalidHashAlgo(s.to_string())),
        }
    }
}

/// A reference to a Git object.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GitObjectRef {
    /// Hash algorithm used.
    pub algo: HashAlgo,
    /// Kind of object (commit, tree, blob, tag).
    pub object_kind: String,
    /// Hex-encoded object ID (lowercase).
    pub object_id: String,
}

impl GitObjectRef {
    /// Validates the object reference.
    ///
    /// # Errors
    ///
    /// Returns error if `object_id` length doesn't match the algorithm.
    pub fn validate(&self) -> Result<(), ChangeSetBundleError> {
        if self.object_kind.is_empty() {
            return Err(ChangeSetBundleError::MissingField("object_kind"));
        }
        if self.object_kind.len() > MAX_STRING_LENGTH {
            return Err(ChangeSetBundleError::StringTooLong {
                field: "object_kind",
                len: self.object_kind.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if !matches!(
            self.object_kind.as_str(),
            "commit" | "tree" | "blob" | "tag"
        ) {
            return Err(ChangeSetBundleError::InvalidData(format!(
                "object_kind must be one of commit/tree/blob/tag, got '{}'",
                self.object_kind
            )));
        }

        let expected_len = self.algo.hex_length();
        if self.object_id.len() != expected_len {
            return Err(ChangeSetBundleError::InvalidData(format!(
                "object_id length {} doesn't match {} expected length {}",
                self.object_id.len(),
                self.algo,
                expected_len
            )));
        }
        // Validate hex characters
        if !self.object_id.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ChangeSetBundleError::InvalidData(
                "object_id contains non-hex characters".to_string(),
            ));
        }
        // Validate lowercase
        if self.object_id != self.object_id.to_ascii_lowercase() {
            return Err(ChangeSetBundleError::InvalidData(
                "object_id must be lowercase".to_string(),
            ));
        }
        Ok(())
    }
}

/// Kind of file change in the changeset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ChangeKind {
    /// File was added.
    Add,
    /// File was modified.
    Modify,
    /// File was deleted.
    Delete,
    /// File was renamed (requires `old_path`).
    Rename,
}

impl std::fmt::Display for ChangeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Add => write!(f, "ADD"),
            Self::Modify => write!(f, "MODIFY"),
            Self::Delete => write!(f, "DELETE"),
            Self::Rename => write!(f, "RENAME"),
        }
    }
}

impl std::str::FromStr for ChangeKind {
    type Err = ChangeSetBundleError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ADD" => Ok(Self::Add),
            "MODIFY" => Ok(Self::Modify),
            "DELETE" => Ok(Self::Delete),
            "RENAME" => Ok(Self::Rename),
            _ => Err(ChangeSetBundleError::InvalidChangeKind(s.to_string())),
        }
    }
}

/// A single file change in the changeset.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FileChange {
    /// Path of the changed file.
    pub path: String,
    /// Kind of change.
    pub change_kind: ChangeKind,
    /// Original path for renames.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_path: Option<String>,
}

impl FileChange {
    /// Validates the file change.
    ///
    /// # Errors
    ///
    /// Returns error if path is too long or rename is missing `old_path`.
    pub fn validate(&self) -> Result<(), ChangeSetBundleError> {
        if self.path.is_empty() {
            return Err(ChangeSetBundleError::MissingField("path"));
        }
        if self.path.len() > MAX_PATH_LENGTH {
            return Err(ChangeSetBundleError::StringTooLong {
                field: "path",
                len: self.path.len(),
                max: MAX_PATH_LENGTH,
            });
        }
        if let Some(ref old_path) = self.old_path {
            if old_path.len() > MAX_PATH_LENGTH {
                return Err(ChangeSetBundleError::StringTooLong {
                    field: "old_path",
                    len: old_path.len(),
                    max: MAX_PATH_LENGTH,
                });
            }
        }
        if self.change_kind == ChangeKind::Rename && self.old_path.is_none() {
            return Err(ChangeSetBundleError::InvalidData(
                "RENAME change requires old_path".to_string(),
            ));
        }
        Ok(())
    }
}

// =============================================================================
// ChangeSetBundleV1
// =============================================================================

/// A canonical changeset bundle stored in CAS.
///
/// The `changeset_digest` is computed deterministically over the canonical
/// bundle bytes with the `changeset_digest` field itself excluded from the
/// hash input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangeSetBundleV1 {
    /// Schema identifier (always `apm2.changeset_bundle.v1`).
    pub schema: String,
    /// Schema version (semver format).
    pub schema_version: String,
    /// Unique changeset identifier.
    pub changeset_id: String,
    /// Base Git object reference (commit or tree).
    pub base: GitObjectRef,
    /// BLAKE3 digest of canonical bundle bytes (32 bytes).
    /// IMPORTANT: This field is EXCLUDED from the hash input.
    #[serde(with = "hex_serde")]
    pub changeset_digest: [u8; 32],
    /// Diff format (currently only `git_unified_diff`).
    pub diff_format: String,
    /// BLAKE3 hash of the diff bytes stored in CAS.
    #[serde(with = "hex_serde")]
    pub diff_hash: [u8; 32],
    /// Manifest of changed files.
    pub file_manifest: Vec<FileChange>,
    /// True if any binary change was detected.
    pub binary_detected: bool,
}

/// Serde helper for hex-encoded 32-byte arrays.
mod hex_serde {
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(D::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| D::Error::custom("expected 32 bytes"))
    }
}

impl ChangeSetBundleV1 {
    /// Creates a builder for constructing a `ChangeSetBundleV1`.
    #[must_use]
    pub fn builder() -> ChangeSetBundleV1Builder {
        ChangeSetBundleV1Builder::default()
    }

    /// Returns the changeset digest.
    #[must_use]
    pub const fn changeset_digest(&self) -> [u8; 32] {
        self.changeset_digest
    }

    /// Computes the canonical bytes for digest computation.
    ///
    /// IMPORTANT: This excludes the `changeset_digest` field from the hash
    /// input to prevent circular dependency.
    ///
    /// Encoding (deterministic):
    /// - `schema` (len + bytes)
    /// - `schema_version` (len + bytes)
    /// - `changeset_id` (len + bytes)
    /// - `base.algo` (1 byte: 0=sha1, 1=sha256)
    /// - `base.object_kind` (len + bytes)
    /// - `base.object_id` (len + bytes)
    /// - `diff_format` (len + bytes)
    /// - `diff_hash` (32 bytes)
    /// - `file_manifest` (count + sorted entries)
    ///   - each entry: `path` (len + bytes) + `change_kind` (1 byte) +
    ///     `old_path` (1 byte flag + len + bytes if present)
    /// - `binary_detected` (1 byte: 0 or 1)
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // All strings are bounded
    pub fn canonical_bytes_for_digest(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // 1. schema
        bytes.extend_from_slice(&(self.schema.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.schema.as_bytes());

        // 2. schema_version
        bytes.extend_from_slice(&(self.schema_version.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.schema_version.as_bytes());

        // 3. changeset_id
        bytes.extend_from_slice(&(self.changeset_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.changeset_id.as_bytes());

        // 4. base.algo
        bytes.push(match self.base.algo {
            HashAlgo::Sha1 => 0,
            HashAlgo::Sha256 => 1,
        });

        // 5. base.object_kind
        bytes.extend_from_slice(&(self.base.object_kind.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.base.object_kind.as_bytes());

        // 6. base.object_id
        bytes.extend_from_slice(&(self.base.object_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.base.object_id.as_bytes());

        // 7. diff_format
        bytes.extend_from_slice(&(self.diff_format.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.diff_format.as_bytes());

        // 8. diff_hash
        bytes.extend_from_slice(&self.diff_hash);

        // 9. file_manifest (sorted by path for determinism)
        let mut sorted_manifest = self.file_manifest.clone();
        sorted_manifest.sort_by(|a, b| a.path.cmp(&b.path));

        bytes.extend_from_slice(&(sorted_manifest.len() as u32).to_be_bytes());
        for entry in sorted_manifest {
            // path
            bytes.extend_from_slice(&(entry.path.len() as u32).to_be_bytes());
            bytes.extend_from_slice(entry.path.as_bytes());
            // change_kind
            bytes.push(match entry.change_kind {
                ChangeKind::Add => 0,
                ChangeKind::Modify => 1,
                ChangeKind::Delete => 2,
                ChangeKind::Rename => 3,
            });
            // old_path
            if let Some(ref old_path) = entry.old_path {
                bytes.push(1); // present flag
                bytes.extend_from_slice(&(old_path.len() as u32).to_be_bytes());
                bytes.extend_from_slice(old_path.as_bytes());
            } else {
                bytes.push(0); // not present flag
            }
        }

        // 10. binary_detected
        bytes.push(u8::from(self.binary_detected));

        bytes
    }

    /// Computes the BLAKE3 digest over canonical bytes.
    ///
    /// This is the deterministic digest computation used for
    /// `changeset_digest`.
    #[must_use]
    pub fn compute_digest(&self) -> [u8; 32] {
        let canonical = self.canonical_bytes_for_digest();
        *blake3::hash(&canonical).as_bytes()
    }

    /// Validates the bundle and verifies the `changeset_digest` is correct.
    ///
    /// # Errors
    ///
    /// Returns error if validation fails or digest doesn't match.
    pub fn validate(&self) -> Result<(), ChangeSetBundleError> {
        // Validate schema
        if self.schema != SCHEMA_IDENTIFIER {
            return Err(ChangeSetBundleError::InvalidData(format!(
                "invalid schema: expected {SCHEMA_IDENTIFIER}, got {}",
                self.schema
            )));
        }
        if self.schema_version != SCHEMA_VERSION {
            return Err(ChangeSetBundleError::InvalidData(format!(
                "invalid schema_version: expected {SCHEMA_VERSION}, got {}",
                self.schema_version
            )));
        }

        // Validate changeset_id
        if self.changeset_id.is_empty() {
            return Err(ChangeSetBundleError::MissingField("changeset_id"));
        }
        if self.changeset_id.len() > MAX_CHANGESET_ID_LENGTH {
            return Err(ChangeSetBundleError::StringTooLong {
                field: "changeset_id",
                len: self.changeset_id.len(),
                max: MAX_CHANGESET_ID_LENGTH,
            });
        }

        // Validate base
        self.base.validate()?;

        if self.diff_format != "git_unified_diff" {
            return Err(ChangeSetBundleError::InvalidData(format!(
                "invalid diff_format: expected git_unified_diff, got {}",
                self.diff_format
            )));
        }

        // Validate file_manifest size
        if self.file_manifest.is_empty() {
            return Err(ChangeSetBundleError::MissingField("file_manifest"));
        }
        if self.file_manifest.len() > MAX_FILE_MANIFEST_SIZE {
            return Err(ChangeSetBundleError::CollectionTooLarge {
                field: "file_manifest",
                actual: self.file_manifest.len(),
                max: MAX_FILE_MANIFEST_SIZE,
            });
        }

        // Validate each file change
        for entry in &self.file_manifest {
            entry.validate()?;
        }

        // Verify changeset_digest
        let computed = self.compute_digest();
        if computed != self.changeset_digest {
            return Err(ChangeSetBundleError::InvalidData(
                "changeset_digest does not match computed digest".to_string(),
            ));
        }

        Ok(())
    }
}

// =============================================================================
// ChangeSetBundleV1Builder
// =============================================================================

/// Builder for constructing a `ChangeSetBundleV1`.
#[derive(Debug, Default)]
pub struct ChangeSetBundleV1Builder {
    changeset_id: Option<String>,
    base: Option<GitObjectRef>,
    diff_hash: Option<[u8; 32]>,
    file_manifest: Vec<FileChange>,
    binary_detected: bool,
}

#[allow(clippy::missing_const_for_fn)] // Builder methods take `mut self` and can't be const
impl ChangeSetBundleV1Builder {
    /// Sets the changeset ID.
    #[must_use]
    pub fn changeset_id(mut self, id: impl Into<String>) -> Self {
        self.changeset_id = Some(id.into());
        self
    }

    /// Sets the base Git object reference.
    #[must_use]
    pub fn base(mut self, base: GitObjectRef) -> Self {
        self.base = Some(base);
        self
    }

    /// Sets the diff hash.
    #[must_use]
    pub fn diff_hash(mut self, hash: [u8; 32]) -> Self {
        self.diff_hash = Some(hash);
        self
    }

    /// Sets the file manifest.
    #[must_use]
    pub fn file_manifest(mut self, manifest: Vec<FileChange>) -> Self {
        self.file_manifest = manifest;
        self
    }

    /// Adds a file change to the manifest.
    #[must_use]
    pub fn add_file_change(mut self, change: FileChange) -> Self {
        self.file_manifest.push(change);
        self
    }

    /// Sets the `binary_detected` flag.
    #[must_use]
    pub fn binary_detected(mut self, detected: bool) -> Self {
        self.binary_detected = detected;
        self
    }

    /// Builds the `ChangeSetBundleV1`.
    ///
    /// The `changeset_digest` is computed automatically from the canonical
    /// bytes.
    ///
    /// # Errors
    ///
    /// Returns error if required fields are missing or validation fails.
    pub fn build(self) -> Result<ChangeSetBundleV1, ChangeSetBundleError> {
        let changeset_id = self
            .changeset_id
            .ok_or(ChangeSetBundleError::MissingField("changeset_id"))?;
        let base = self
            .base
            .ok_or(ChangeSetBundleError::MissingField("base"))?;
        let diff_hash = self
            .diff_hash
            .ok_or(ChangeSetBundleError::MissingField("diff_hash"))?;

        // Create bundle with placeholder digest
        let mut bundle = ChangeSetBundleV1 {
            schema: SCHEMA_IDENTIFIER.to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
            changeset_id,
            base,
            changeset_digest: [0u8; 32], // Placeholder
            diff_format: "git_unified_diff".to_string(),
            diff_hash,
            file_manifest: self.file_manifest,
            binary_detected: self.binary_detected,
        };

        // Validate base
        bundle.base.validate()?;

        // Validate changeset_id
        if bundle.changeset_id.len() > MAX_CHANGESET_ID_LENGTH {
            return Err(ChangeSetBundleError::StringTooLong {
                field: "changeset_id",
                len: bundle.changeset_id.len(),
                max: MAX_CHANGESET_ID_LENGTH,
            });
        }

        // Validate file_manifest size
        if bundle.file_manifest.len() > MAX_FILE_MANIFEST_SIZE {
            return Err(ChangeSetBundleError::CollectionTooLarge {
                field: "file_manifest",
                actual: bundle.file_manifest.len(),
                max: MAX_FILE_MANIFEST_SIZE,
            });
        }

        // Validate each file change
        for entry in &bundle.file_manifest {
            entry.validate()?;
        }

        // Compute digest
        bundle.changeset_digest = bundle.compute_digest();

        Ok(bundle)
    }
}

// =============================================================================
// ChangeSetPublished
// =============================================================================

/// Event emitted when a changeset is published to CAS and anchored in the
/// ledger.
///
/// This event MUST be emitted before any review activities begin for a work
/// item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangeSetPublished {
    /// Work item ID this changeset belongs to.
    pub work_id: String,
    /// BLAKE3 digest of the canonical bundle (32 bytes).
    #[serde(with = "serde_bytes")]
    pub changeset_digest: [u8; 32],
    /// CAS hash of the full `ChangeSetBundleV1` artifact (32 bytes).
    #[serde(with = "serde_bytes")]
    pub cas_hash: [u8; 32],
    /// Timestamp when published (Unix nanos).
    pub published_at: u64,
    /// Actor who published the changeset.
    pub publisher_actor_id: String,
    /// Ed25519 signature over canonical bytes with
    /// `CHANGESET_PUBLISHED_PREFIX` domain separation.
    #[serde(with = "serde_bytes")]
    pub publisher_signature: [u8; 64],
    /// HTF time envelope reference for temporal authority (RFC-0016).
    /// Binds the changeset publication to verifiable HTF time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_envelope_ref: Option<TimeEnvelopeRef>,
}

impl ChangeSetPublished {
    /// Creates a new `ChangeSetPublished` event.
    ///
    /// # Arguments
    ///
    /// * `work_id` - The work item ID
    /// * `changeset_digest` - BLAKE3 digest of the canonical bundle
    /// * `cas_hash` - CAS hash of the full bundle artifact
    /// * `published_at` - Timestamp when published
    /// * `publisher_actor_id` - ID of the publishing actor
    /// * `signer` - Signer to authorize the event
    ///
    /// # Errors
    ///
    /// Returns error if any string field exceeds `MAX_STRING_LENGTH`.
    pub fn create(
        work_id: String,
        changeset_digest: [u8; 32],
        cas_hash: [u8; 32],
        published_at: u64,
        publisher_actor_id: String,
        signer: &Signer,
    ) -> Result<Self, ChangeSetBundleError> {
        Self::create_with_time_envelope(
            work_id,
            changeset_digest,
            cas_hash,
            published_at,
            publisher_actor_id,
            None,
            signer,
        )
    }

    /// Creates a new `ChangeSetPublished` event with an HTF time envelope
    /// reference.
    ///
    /// # Arguments
    ///
    /// * `work_id` - The work item ID
    /// * `changeset_digest` - BLAKE3 digest of the canonical bundle
    /// * `cas_hash` - CAS hash of the full bundle artifact
    /// * `published_at` - Timestamp when published
    /// * `publisher_actor_id` - ID of the publishing actor
    /// * `time_envelope_ref` - Optional HTF time envelope reference for
    ///   temporal authority
    /// * `signer` - Signer to authorize the event
    ///
    /// # Errors
    ///
    /// Returns error if any string field exceeds `MAX_STRING_LENGTH`.
    pub fn create_with_time_envelope(
        work_id: String,
        changeset_digest: [u8; 32],
        cas_hash: [u8; 32],
        published_at: u64,
        publisher_actor_id: String,
        time_envelope_ref: Option<TimeEnvelopeRef>,
        signer: &Signer,
    ) -> Result<Self, ChangeSetBundleError> {
        // Validate inputs
        if work_id.len() > MAX_STRING_LENGTH {
            return Err(ChangeSetBundleError::StringTooLong {
                field: "work_id",
                len: work_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if publisher_actor_id.len() > MAX_STRING_LENGTH {
            return Err(ChangeSetBundleError::StringTooLong {
                field: "publisher_actor_id",
                len: publisher_actor_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }

        // Construct event with placeholder signature
        let mut event = Self {
            work_id,
            changeset_digest,
            cas_hash,
            published_at,
            publisher_actor_id,
            publisher_signature: [0u8; 64],
            time_envelope_ref,
        };

        // Sign
        let canonical = event.canonical_bytes();
        let signature = sign_with_domain(signer, CHANGESET_PUBLISHED_PREFIX, &canonical);
        event.publisher_signature = signature.to_bytes();

        Ok(event)
    }

    /// Computes the canonical bytes for signing/verification.
    ///
    /// Encoding:
    /// - `work_id` (len + bytes)
    /// - `changeset_digest` (32 bytes)
    /// - `cas_hash` (32 bytes)
    /// - `published_at` (8 bytes BE)
    /// - `publisher_actor_id` (len + bytes)
    /// - `time_envelope_ref` (1 byte flag + 32 bytes hash if present)
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // All strings are bounded by MAX_STRING_LENGTH
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // 1. work_id
        bytes.extend_from_slice(&(self.work_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.work_id.as_bytes());

        // 2. changeset_digest
        bytes.extend_from_slice(&self.changeset_digest);

        // 3. cas_hash
        bytes.extend_from_slice(&self.cas_hash);

        // 4. published_at
        bytes.extend_from_slice(&self.published_at.to_be_bytes());

        // 5. publisher_actor_id
        bytes.extend_from_slice(&(self.publisher_actor_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.publisher_actor_id.as_bytes());

        // 6. time_envelope_ref (optional: 1 byte flag + 32 bytes hash if present)
        // Including this in the signed payload ensures signature coverage per RFC-0016.
        if let Some(ref envelope_ref) = self.time_envelope_ref {
            bytes.push(1); // present flag
            bytes.extend_from_slice(envelope_ref.as_bytes());
        } else {
            bytes.push(0); // not present flag
        }

        bytes
    }

    /// Verifies the event signature.
    ///
    /// # Errors
    ///
    /// Returns error if the signature doesn't match the canonical bytes.
    pub fn verify_signature(&self, key: &VerifyingKey) -> Result<(), ChangeSetBundleError> {
        let canonical = self.canonical_bytes();
        let signature = Signature::from_bytes(&self.publisher_signature);

        verify_with_domain(key, CHANGESET_PUBLISHED_PREFIX, &canonical, &signature)
            .map_err(|e| ChangeSetBundleError::SignatureVerificationFailed(e.to_string()))
    }
}

// =============================================================================
// Proto Conversions
// =============================================================================

impl TryFrom<ChangeSetPublishedProto> for ChangeSetPublished {
    type Error = ChangeSetBundleError;

    fn try_from(proto: ChangeSetPublishedProto) -> Result<Self, Self::Error> {
        // Validate resource limits
        if proto.work_id.len() > MAX_STRING_LENGTH {
            return Err(ChangeSetBundleError::StringTooLong {
                field: "work_id",
                len: proto.work_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if proto.publisher_actor_id.len() > MAX_STRING_LENGTH {
            return Err(ChangeSetBundleError::StringTooLong {
                field: "publisher_actor_id",
                len: proto.publisher_actor_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }

        let changeset_digest = proto.changeset_digest.try_into().map_err(|_| {
            ChangeSetBundleError::InvalidData("changeset_digest must be 32 bytes".into())
        })?;

        let cas_hash = proto
            .cas_hash
            .try_into()
            .map_err(|_| ChangeSetBundleError::InvalidData("cas_hash must be 32 bytes".into()))?;

        let publisher_signature = proto.publisher_signature.try_into().map_err(|_| {
            ChangeSetBundleError::InvalidData("publisher_signature must be 64 bytes".into())
        })?;

        // Convert time_envelope_ref from proto format to domain type
        let time_envelope_ref = proto
            .time_envelope_ref
            .and_then(|ter| TimeEnvelopeRef::from_slice(&ter.hash));

        Ok(Self {
            work_id: proto.work_id,
            changeset_digest,
            cas_hash,
            published_at: proto.published_at,
            publisher_actor_id: proto.publisher_actor_id,
            publisher_signature,
            time_envelope_ref,
        })
    }
}

impl From<ChangeSetPublished> for ChangeSetPublishedProto {
    fn from(event: ChangeSetPublished) -> Self {
        // Import the proto TimeEnvelopeRef type
        use crate::events::TimeEnvelopeRef as TimeEnvelopeRefProto;

        Self {
            work_id: event.work_id,
            changeset_digest: event.changeset_digest.to_vec(),
            cas_hash: event.cas_hash.to_vec(),
            published_at: event.published_at,
            publisher_actor_id: event.publisher_actor_id,
            publisher_signature: event.publisher_signature.to_vec(),
            // Convert HTF time envelope reference to proto format
            time_envelope_ref: event.time_envelope_ref.map(|ter| TimeEnvelopeRefProto {
                hash: ter.as_bytes().to_vec(),
            }),
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_base() -> GitObjectRef {
        GitObjectRef {
            algo: HashAlgo::Sha1,
            object_kind: "commit".to_string(),
            object_id: "a".repeat(40),
        }
    }

    #[test]
    fn test_bundle_deterministic_digest() {
        // Create two identical bundles
        let bundle1 = ChangeSetBundleV1::builder()
            .changeset_id("cs-001")
            .base(test_base())
            .diff_hash([0x42; 32])
            .file_manifest(vec![FileChange {
                path: "src/lib.rs".to_string(),
                change_kind: ChangeKind::Modify,
                old_path: None,
            }])
            .build()
            .expect("valid bundle");

        let bundle2 = ChangeSetBundleV1::builder()
            .changeset_id("cs-001")
            .base(test_base())
            .diff_hash([0x42; 32])
            .file_manifest(vec![FileChange {
                path: "src/lib.rs".to_string(),
                change_kind: ChangeKind::Modify,
                old_path: None,
            }])
            .build()
            .expect("valid bundle");

        // Same inputs produce same digest
        assert_eq!(bundle1.changeset_digest, bundle2.changeset_digest);
    }

    #[test]
    fn test_bundle_digest_excludes_digest_field() {
        // Create a bundle
        let bundle = ChangeSetBundleV1::builder()
            .changeset_id("cs-001")
            .base(test_base())
            .diff_hash([0x42; 32])
            .file_manifest(vec![])
            .build()
            .expect("valid bundle");

        // The canonical bytes for digest should NOT include the changeset_digest field
        let canonical = bundle.canonical_bytes_for_digest();

        // The changeset_digest is 32 bytes. If it were included, the canonical bytes
        // would contain it. We verify by checking that changing the digest doesn't
        // change the canonical bytes.
        let mut modified_bundle = bundle;
        modified_bundle.changeset_digest = [0xFF; 32];

        let modified_canonical = modified_bundle.canonical_bytes_for_digest();

        // Canonical bytes should be identical because digest is excluded
        assert_eq!(canonical, modified_canonical);
    }

    #[test]
    fn test_bundle_different_inputs_different_digest() {
        let bundle1 = ChangeSetBundleV1::builder()
            .changeset_id("cs-001")
            .base(test_base())
            .diff_hash([0x42; 32])
            .file_manifest(vec![])
            .build()
            .expect("valid bundle");

        let bundle2 = ChangeSetBundleV1::builder()
            .changeset_id("cs-002") // Different ID
            .base(test_base())
            .diff_hash([0x42; 32])
            .file_manifest(vec![])
            .build()
            .expect("valid bundle");

        // Different inputs produce different digests
        assert_ne!(bundle1.changeset_digest, bundle2.changeset_digest);
    }

    #[test]
    fn test_bundle_validation() {
        let bundle = ChangeSetBundleV1::builder()
            .changeset_id("cs-001")
            .base(test_base())
            .diff_hash([0x42; 32])
            .file_manifest(vec![FileChange {
                path: "src/lib.rs".to_string(),
                change_kind: ChangeKind::Modify,
                old_path: None,
            }])
            .build()
            .expect("valid bundle");

        // Bundle should validate
        assert!(bundle.validate().is_ok());
    }

    #[test]
    fn test_bundle_validation_fails_wrong_digest() {
        let mut bundle = ChangeSetBundleV1::builder()
            .changeset_id("cs-001")
            .base(test_base())
            .diff_hash([0x42; 32])
            .file_manifest(vec![])
            .build()
            .expect("valid bundle");

        // Tamper with digest
        bundle.changeset_digest = [0xFF; 32];

        // Validation should fail
        assert!(bundle.validate().is_err());
    }

    #[test]
    fn test_bundle_validation_fails_empty_manifest() {
        let bundle = ChangeSetBundleV1::builder()
            .changeset_id("cs-empty")
            .base(test_base())
            .diff_hash([0x42; 32])
            .file_manifest(vec![])
            .build()
            .expect("valid bundle construction");

        let err = bundle.validate().expect_err("validation should fail");
        assert_eq!(err, ChangeSetBundleError::MissingField("file_manifest"));
    }

    #[test]
    fn test_bundle_validation_fails_bad_schema_version() {
        let mut bundle = ChangeSetBundleV1::builder()
            .changeset_id("cs-schema-version")
            .base(test_base())
            .diff_hash([0x42; 32])
            .file_manifest(vec![FileChange {
                path: "src/lib.rs".to_string(),
                change_kind: ChangeKind::Modify,
                old_path: None,
            }])
            .build()
            .expect("valid bundle construction");
        bundle.schema_version = "2.0.0".to_string();

        let err = bundle.validate().expect_err("validation should fail");
        assert!(
            matches!(err, ChangeSetBundleError::InvalidData(message) if message.contains("invalid schema_version"))
        );
    }

    #[test]
    fn test_bundle_validation_fails_bad_diff_format() {
        let mut bundle = ChangeSetBundleV1::builder()
            .changeset_id("cs-diff-format")
            .base(test_base())
            .diff_hash([0x42; 32])
            .file_manifest(vec![FileChange {
                path: "src/lib.rs".to_string(),
                change_kind: ChangeKind::Modify,
                old_path: None,
            }])
            .build()
            .expect("valid bundle construction");
        bundle.diff_format = "custom_diff".to_string();

        let err = bundle.validate().expect_err("validation should fail");
        assert!(
            matches!(err, ChangeSetBundleError::InvalidData(message) if message.contains("invalid diff_format"))
        );
    }

    #[test]
    fn test_file_manifest_sorting() {
        // Create bundle with unsorted manifest
        let bundle = ChangeSetBundleV1::builder()
            .changeset_id("cs-001")
            .base(test_base())
            .diff_hash([0x42; 32])
            .file_manifest(vec![
                FileChange {
                    path: "z.rs".to_string(),
                    change_kind: ChangeKind::Add,
                    old_path: None,
                },
                FileChange {
                    path: "a.rs".to_string(),
                    change_kind: ChangeKind::Add,
                    old_path: None,
                },
            ])
            .build()
            .expect("valid bundle");

        // Create bundle with sorted manifest
        let bundle_sorted = ChangeSetBundleV1::builder()
            .changeset_id("cs-001")
            .base(test_base())
            .diff_hash([0x42; 32])
            .file_manifest(vec![
                FileChange {
                    path: "a.rs".to_string(),
                    change_kind: ChangeKind::Add,
                    old_path: None,
                },
                FileChange {
                    path: "z.rs".to_string(),
                    change_kind: ChangeKind::Add,
                    old_path: None,
                },
            ])
            .build()
            .expect("valid bundle");

        // Same digest regardless of input order (canonical encoding sorts)
        assert_eq!(bundle.changeset_digest, bundle_sorted.changeset_digest);
    }

    #[test]
    fn test_changeset_published_create_and_verify() {
        let signer = Signer::generate();
        let event = ChangeSetPublished::create(
            "work-001".to_string(),
            [0x11; 32],
            [0x22; 32],
            1_704_067_200_000,
            "publisher-001".to_string(),
            &signer,
        )
        .expect("valid event");

        // Verify signature
        assert!(event.verify_signature(&signer.verifying_key()).is_ok());
    }

    #[test]
    fn test_changeset_published_signature_fails_on_tamper() {
        let signer = Signer::generate();
        let mut event = ChangeSetPublished::create(
            "work-001".to_string(),
            [0x11; 32],
            [0x22; 32],
            1_704_067_200_000,
            "publisher-001".to_string(),
            &signer,
        )
        .expect("valid event");

        // Tamper with cas_hash
        event.cas_hash = [0xFF; 32];

        // Verification should fail
        assert!(event.verify_signature(&signer.verifying_key()).is_err());
    }

    #[test]
    fn test_changeset_published_proto_roundtrip() {
        let signer = Signer::generate();
        let original = ChangeSetPublished::create(
            "work-001".to_string(),
            [0x11; 32],
            [0x22; 32],
            1_704_067_200_000,
            "publisher-001".to_string(),
            &signer,
        )
        .expect("valid event");

        let proto: ChangeSetPublishedProto = original.clone().into();
        let recovered: ChangeSetPublished = proto.try_into().expect("should convert");

        assert_eq!(original, recovered);
    }

    #[test]
    fn test_hash_algo_from_str() {
        assert_eq!("sha1".parse::<HashAlgo>().unwrap(), HashAlgo::Sha1);
        assert_eq!("sha256".parse::<HashAlgo>().unwrap(), HashAlgo::Sha256);
        assert!("md5".parse::<HashAlgo>().is_err());
    }

    #[test]
    fn test_change_kind_from_str() {
        assert_eq!("ADD".parse::<ChangeKind>().unwrap(), ChangeKind::Add);
        assert_eq!("MODIFY".parse::<ChangeKind>().unwrap(), ChangeKind::Modify);
        assert_eq!("DELETE".parse::<ChangeKind>().unwrap(), ChangeKind::Delete);
        assert_eq!("RENAME".parse::<ChangeKind>().unwrap(), ChangeKind::Rename);
        assert!("UNKNOWN".parse::<ChangeKind>().is_err());
    }

    #[test]
    fn test_rename_requires_old_path() {
        let change = FileChange {
            path: "new.rs".to_string(),
            change_kind: ChangeKind::Rename,
            old_path: None, // Missing!
        };

        assert!(change.validate().is_err());
    }

    #[test]
    fn test_rename_with_old_path() {
        let change = FileChange {
            path: "new.rs".to_string(),
            change_kind: ChangeKind::Rename,
            old_path: Some("old.rs".to_string()),
        };

        assert!(change.validate().is_ok());
    }

    #[test]
    fn test_git_object_ref_validation() {
        // Valid SHA-1
        let valid_sha1 = GitObjectRef {
            algo: HashAlgo::Sha1,
            object_kind: "commit".to_string(),
            object_id: "a".repeat(40),
        };
        assert!(valid_sha1.validate().is_ok());

        // Valid SHA-256
        let valid_sha256 = GitObjectRef {
            algo: HashAlgo::Sha256,
            object_kind: "commit".to_string(),
            object_id: "a".repeat(64),
        };
        assert!(valid_sha256.validate().is_ok());

        // Wrong length
        let wrong_len = GitObjectRef {
            algo: HashAlgo::Sha1,
            object_kind: "commit".to_string(),
            object_id: "a".repeat(32), // Wrong!
        };
        assert!(wrong_len.validate().is_err());

        // Uppercase (invalid)
        let uppercase = GitObjectRef {
            algo: HashAlgo::Sha1,
            object_kind: "commit".to_string(),
            object_id: "A".repeat(40),
        };
        assert!(uppercase.validate().is_err());

        // Invalid object kind
        let invalid_kind = GitObjectRef {
            algo: HashAlgo::Sha1,
            object_kind: "branch".to_string(),
            object_id: "a".repeat(40),
        };
        assert!(invalid_kind.validate().is_err());
    }
}
