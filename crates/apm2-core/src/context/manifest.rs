// AGENT-AUTHORED
//! Context pack manifest types for file access control.
//!
//! This module defines [`ContextPackManifest`] which represents the OCAP
//! (Object-Capability) allowlist for file reads. The manifest defines which
//! files an agent is permitted to read and at what access level.
//!
//! # Security Model
//!
//! The context firewall uses the manifest as an allowlist:
//!
//! 1. **Path matching**: Only files explicitly listed in the manifest can be
//!    read
//! 2. **Content hash verification**: File content must match the recorded
//!    `content_hash` to prevent TOCTOU (time-of-check-to-time-of-use) attacks
//! 3. **Access levels**: Different access levels (Read, `ReadWithZoom`) control
//!    what operations are permitted
//!
//! # OCAP Model
//!
//! The manifest implements the Object-Capability security model:
//!
//! - **Unforgeable**: Manifests are identified by cryptographic hash
//! - **Transferable**: Manifests can be passed to authorized agents
//! - **Attenuated**: Access levels can only be reduced, never elevated
//!
//! # Example
//!
//! ```rust
//! use apm2_core::context::{
//!     AccessLevel, ContextPackManifest, ContextPackManifestBuilder,
//!     ManifestEntry, ManifestEntryBuilder,
//! };
//!
//! // Create a manifest with file entries
//! let manifest =
//!     ContextPackManifestBuilder::new("manifest-001", "profile-001")
//!         .add_entry(
//!             ManifestEntryBuilder::new("/project/src/main.rs", [0x42; 32])
//!                 .stable_id("src-main")
//!                 .access_level(AccessLevel::Read)
//!                 .build(),
//!         )
//!         .add_entry(
//!             ManifestEntryBuilder::new("/project/README.md", [0xAB; 32])
//!                 .access_level(AccessLevel::ReadWithZoom)
//!                 .build(),
//!         )
//!         .build();
//!
//! // Check if a file is allowed (with hash for ReadWithZoom)
//! assert!(
//!     manifest
//!         .is_allowed("/project/src/main.rs", Some(&[0x42; 32]))
//!         .unwrap()
//! );
//!
//! // For Read access level, hash check can be omitted
//! assert!(manifest.is_allowed("/project/src/main.rs", None).unwrap());
//!
//! // Wrong hash is rejected
//! assert!(
//!     !manifest
//!         .is_allowed("/project/src/main.rs", Some(&[0xFF; 32]))
//!         .unwrap()
//! );
//!
//! // Unknown path is rejected
//! assert!(
//!     !manifest
//!         .is_allowed("/project/secret.txt", Some(&[0x00; 32]))
//!         .unwrap()
//! );
//! ```

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use thiserror::Error;

use crate::fac::MAX_STRING_LENGTH;

// =============================================================================
// Resource Limits (DoS Protection)
// =============================================================================

/// Maximum number of entries allowed in a context pack manifest.
/// This prevents denial-of-service attacks via oversized repeated fields.
pub const MAX_ENTRIES: usize = 10_000;

/// Maximum path length in bytes.
/// Prevents memory exhaustion from extremely long paths.
pub const MAX_PATH_LENGTH: usize = 4096;

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during manifest operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ManifestError {
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

    /// Path exceeds maximum length.
    #[error("path exceeds max length: {actual} > {max}")]
    PathTooLong {
        /// Actual length of the path.
        actual: usize,
        /// Maximum allowed length.
        max: usize,
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

    /// Missing required field.
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// Invalid manifest data.
    #[error("invalid manifest data: {0}")]
    InvalidData(String),

    /// Duplicate path in manifest.
    #[error("duplicate path in manifest: {path}")]
    DuplicatePath {
        /// The duplicate path.
        path: String,
    },

    /// Duplicate `stable_id` in manifest.
    #[error("duplicate stable_id in manifest: {stable_id}")]
    DuplicateStableId {
        /// The duplicate `stable_id`.
        stable_id: String,
    },

    /// Path not found in manifest.
    #[error("path not found in manifest: {path}")]
    PathNotFound {
        /// The path that was not found.
        path: String,
    },

    /// Content hash mismatch.
    #[error("content hash mismatch for path: {path}")]
    ContentHashMismatch {
        /// The path with mismatched hash.
        path: String,
    },

    /// Content hash required but not provided.
    #[error("content hash required for ReadWithZoom access level: {path}")]
    ContentHashRequired {
        /// The path that requires a hash.
        path: String,
    },

    /// Invalid path (contains traversal or null bytes).
    #[error("invalid path: {reason}")]
    InvalidPath {
        /// The reason the path is invalid.
        reason: String,
    },
}

// =============================================================================
// Path Normalization
// =============================================================================

/// Normalizes a path for secure allowlist matching.
///
/// This function ensures paths are in a canonical form to prevent path
/// traversal attacks. It:
///
/// 1. Rejects paths containing embedded null bytes
/// 2. Converts relative paths to absolute (prefixes with `/`)
/// 3. Resolves `.` (current directory) and `..` (parent directory) components
/// 4. Rejects paths where `..` would escape the root
/// 5. Normalizes multiple consecutive slashes to single slash
///
/// # Arguments
///
/// * `path` - The path to normalize
///
/// # Returns
///
/// The normalized absolute path.
///
/// # Errors
///
/// Returns [`ManifestError::InvalidPath`] if:
/// - The path contains embedded null bytes
/// - The path attempts to traverse above the root directory
///
/// # Example
///
/// ```ignore
/// assert_eq!(normalize_path("/foo/bar/../baz")?, "/foo/baz");
/// assert_eq!(normalize_path("/foo/./bar")?, "/foo/bar");
/// assert_eq!(normalize_path("foo/bar")?, "/foo/bar");
/// assert!(normalize_path("/foo/../../bar").is_err()); // escapes root
/// assert!(normalize_path("/foo\0bar").is_err()); // null byte
/// ```
pub fn normalize_path(path: &str) -> Result<String, ManifestError> {
    // Defense in depth: enforce path length limit early
    if path.len() > MAX_PATH_LENGTH {
        return Err(ManifestError::PathTooLong {
            actual: path.len(),
            max: MAX_PATH_LENGTH,
        });
    }

    // Reject embedded null bytes
    if path.contains('\0') {
        return Err(ManifestError::InvalidPath {
            reason: "path contains embedded null byte".to_string(),
        });
    }

    // Handle empty path
    if path.is_empty() {
        return Err(ManifestError::InvalidPath {
            reason: "path is empty".to_string(),
        });
    }

    // Process components
    let mut components: Vec<&str> = Vec::new();

    for component in path.split('/') {
        match component {
            // Skip empty components (from consecutive slashes) and current dir
            "" | "." => {},
            // Handle parent directory
            ".." => {
                if components.is_empty() {
                    // Trying to go above root
                    return Err(ManifestError::InvalidPath {
                        reason: format!("path traversal would escape root: {path}"),
                    });
                }
                components.pop();
            },
            // Normal component
            _ => components.push(component),
        }
    }

    // Build normalized path (always absolute)
    Ok(format!("/{}", components.join("/")))
}

// =============================================================================
// AccessLevel
// =============================================================================

/// Access level for a manifest entry.
///
/// Defines what operations are permitted on the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum AccessLevel {
    /// Read-only access to the file content.
    Read         = 0,
    /// Read access with zoom capability (e.g., semantic navigation).
    ReadWithZoom = 1,
}

impl TryFrom<u8> for AccessLevel {
    type Error = ManifestError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Read),
            1 => Ok(Self::ReadWithZoom),
            _ => Err(ManifestError::InvalidData(format!(
                "invalid access level {value}, must be 0-1"
            ))),
        }
    }
}

impl From<AccessLevel> for u8 {
    fn from(level: AccessLevel) -> Self {
        level as Self
    }
}

// =============================================================================
// ManifestEntry
// =============================================================================

/// An entry in the context pack manifest.
///
/// Each entry defines a single file that is permitted to be read, along with
/// its content hash for integrity verification.
///
/// Use [`ManifestEntryBuilder`] to construct entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestEntry {
    /// Optional stable identifier for the entry.
    ///
    /// Used for semantic referencing across manifest versions. When present,
    /// allows tracking the same logical file across renames or moves.
    #[serde(skip_serializing_if = "Option::is_none")]
    stable_id: Option<String>,

    /// Absolute path to the file.
    path: String,

    /// BLAKE3 hash of the file content.
    ///
    /// Used for integrity verification to prevent TOCTOU attacks.
    #[serde(with = "serde_bytes")]
    content_hash: [u8; 32],

    /// Access level for this file.
    access_level: AccessLevel,
}

impl ManifestEntry {
    /// Returns the stable identifier for this entry, if any.
    #[must_use]
    pub fn stable_id(&self) -> Option<&str> {
        self.stable_id.as_deref()
    }

    /// Returns the absolute path to the file.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the BLAKE3 content hash.
    #[must_use]
    pub const fn content_hash(&self) -> &[u8; 32] {
        &self.content_hash
    }

    /// Returns the access level for this entry.
    #[must_use]
    pub const fn access_level(&self) -> AccessLevel {
        self.access_level
    }
}

// =============================================================================
// ManifestEntryBuilder
// =============================================================================

/// Builder for constructing [`ManifestEntry`] instances.
#[derive(Debug)]
pub struct ManifestEntryBuilder {
    stable_id: Option<String>,
    path: String,
    content_hash: [u8; 32],
    access_level: AccessLevel,
}

impl ManifestEntryBuilder {
    /// Creates a new builder with the required path and content hash.
    #[must_use]
    pub fn new(path: impl Into<String>, content_hash: [u8; 32]) -> Self {
        Self {
            stable_id: None,
            path: path.into(),
            content_hash,
            access_level: AccessLevel::Read,
        }
    }

    /// Sets the stable identifier.
    #[must_use]
    pub fn stable_id(mut self, stable_id: impl Into<String>) -> Self {
        self.stable_id = Some(stable_id.into());
        self
    }

    /// Sets the access level.
    #[must_use]
    pub const fn access_level(mut self, access_level: AccessLevel) -> Self {
        self.access_level = access_level;
        self
    }

    /// Builds the manifest entry.
    #[must_use]
    pub fn build(self) -> ManifestEntry {
        ManifestEntry {
            stable_id: self.stable_id,
            path: self.path,
            content_hash: self.content_hash,
            access_level: self.access_level,
        }
    }
}

// =============================================================================
// ContextPackManifest
// =============================================================================

/// A context pack manifest defining the allowlist for file reads.
///
/// The manifest is the central data structure for the context firewall. It
/// defines which files an agent is permitted to read and provides content
/// hashes for integrity verification.
///
/// # Fields
///
/// - `manifest_id`: Unique identifier for this manifest
/// - `manifest_hash`: BLAKE3 hash of the manifest content (computed at build
///   time)
/// - `profile_id`: Profile that generated this manifest
/// - `entries`: List of allowed file entries
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextPackManifest {
    /// Unique identifier for this manifest.
    pub manifest_id: String,

    /// BLAKE3 hash of the manifest content.
    #[serde(with = "serde_bytes")]
    manifest_hash: [u8; 32],

    /// Profile that generated this manifest.
    pub profile_id: String,

    /// List of allowed file entries.
    entries: Vec<ManifestEntry>,

    /// Index for O(1) path lookups.
    /// Maps normalized path to index in entries vector.
    #[serde(skip)]
    path_index: HashMap<String, usize>,
}

impl PartialEq for ContextPackManifest {
    fn eq(&self, other: &Self) -> bool {
        // path_index is derived from entries, so we don't need to compare it
        self.manifest_id == other.manifest_id
            && self.manifest_hash == other.manifest_hash
            && self.profile_id == other.profile_id
            && self.entries == other.entries
    }
}

impl Eq for ContextPackManifest {}

impl ContextPackManifest {
    /// Returns the manifest hash.
    #[must_use]
    pub const fn manifest_hash(&self) -> [u8; 32] {
        self.manifest_hash
    }

    /// Returns a slice of all entries.
    #[must_use]
    pub fn entries(&self) -> &[ManifestEntry] {
        &self.entries
    }

    /// Computes the manifest hash from the manifest fields.
    ///
    /// The hash is computed over the canonical representation of all fields
    /// except the hash itself.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    fn compute_manifest_hash(
        manifest_id: &str,
        profile_id: &str,
        entries: &[ManifestEntry],
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();

        // Manifest ID (length-prefixed)
        hasher.update(&(manifest_id.len() as u32).to_be_bytes());
        hasher.update(manifest_id.as_bytes());

        // Profile ID (length-prefixed)
        hasher.update(&(profile_id.len() as u32).to_be_bytes());
        hasher.update(profile_id.as_bytes());

        // Entries
        hasher.update(&(entries.len() as u32).to_be_bytes());
        for entry in entries {
            // stable_id (optional, length-prefixed)
            if let Some(ref stable_id) = entry.stable_id {
                hasher.update(&[1u8]); // presence flag
                hasher.update(&(stable_id.len() as u32).to_be_bytes());
                hasher.update(stable_id.as_bytes());
            } else {
                hasher.update(&[0u8]); // absence flag
            }

            // path (length-prefixed)
            hasher.update(&(entry.path.len() as u32).to_be_bytes());
            hasher.update(entry.path.as_bytes());

            // content_hash
            hasher.update(&entry.content_hash);

            // access_level
            hasher.update(&[entry.access_level as u8]);
        }

        *hasher.finalize().as_bytes()
    }

    /// Builds the path index from entries.
    fn build_path_index(entries: &[ManifestEntry]) -> HashMap<String, usize> {
        let mut index = HashMap::with_capacity(entries.len());
        for (i, entry) in entries.iter().enumerate() {
            index.insert(entry.path.clone(), i);
        }
        index
    }

    /// Checks if access to a file is allowed.
    ///
    /// This is the primary security check for the context firewall. A file
    /// access is allowed if and only if:
    ///
    /// 1. The path exists in the manifest (after normalization)
    /// 2. The content hash matches (if provided, or required for
    ///    `ReadWithZoom`)
    ///
    /// # Access Level Rules
    ///
    /// - **Read**: Hash check is optional. If `content_hash` is `None`, access
    ///   is granted. If `Some(hash)`, the hash must match.
    /// - **`ReadWithZoom`**: Hash is required. If `content_hash` is `None`,
    ///   returns an error.
    ///
    /// # Security Notes
    ///
    /// - Paths are normalized before lookup to prevent traversal attacks
    /// - Uses constant-time comparison for hash verification to prevent timing
    ///   attacks
    ///
    /// # Arguments
    ///
    /// * `path` - The absolute path to check
    /// * `content_hash` - The BLAKE3 hash of the file content (optional for
    ///   Read)
    ///
    /// # Returns
    ///
    /// `Ok(true)` if access is allowed, `Ok(false)` if path not found or hash
    /// mismatch.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError::InvalidPath`] if the path is invalid.
    /// Returns [`ManifestError::ContentHashRequired`] if the entry has
    /// `ReadWithZoom` access level but no hash was provided.
    ///
    /// # Example
    ///
    /// ```rust
    /// use apm2_core::context::{
    ///     AccessLevel, ContextPackManifest, ContextPackManifestBuilder,
    ///     ManifestEntryBuilder,
    /// };
    ///
    /// let manifest =
    ///     ContextPackManifestBuilder::new("manifest-001", "profile-001")
    ///         .add_entry(
    ///             ManifestEntryBuilder::new("/project/src/main.rs", [0x42; 32])
    ///                 .access_level(AccessLevel::Read)
    ///                 .build(),
    ///         )
    ///         .build();
    ///
    /// // Matching path and hash: allowed
    /// assert!(
    ///     manifest
    ///         .is_allowed("/project/src/main.rs", Some(&[0x42; 32]))
    ///         .unwrap()
    /// );
    ///
    /// // Read access allows omitting hash
    /// assert!(manifest.is_allowed("/project/src/main.rs", None).unwrap());
    ///
    /// // Wrong hash: denied
    /// assert!(
    ///     !manifest
    ///         .is_allowed("/project/src/main.rs", Some(&[0xFF; 32]))
    ///         .unwrap()
    /// );
    ///
    /// // Unknown path: denied
    /// assert!(
    ///     !manifest
    ///         .is_allowed("/other/file.rs", Some(&[0x42; 32]))
    ///         .unwrap()
    /// );
    /// ```
    pub fn is_allowed(
        &self,
        path: &str,
        content_hash: Option<&[u8; 32]>,
    ) -> Result<bool, ManifestError> {
        let normalized = normalize_path(path)?;

        let Some(&idx) = self.path_index.get(&normalized) else {
            return Ok(false);
        };

        let entry = &self.entries[idx];

        match (entry.access_level, content_hash) {
            // ReadWithZoom requires hash
            (AccessLevel::ReadWithZoom, None) => {
                Err(ManifestError::ContentHashRequired { path: normalized })
            },
            // Hash provided, verify it
            (_, Some(hash)) => Ok(bool::from(entry.content_hash.ct_eq(hash))),
            // Read access without hash - allowed
            (AccessLevel::Read, None) => Ok(true),
        }
    }

    /// Gets a manifest entry by path.
    ///
    /// # Arguments
    ///
    /// * `path` - The absolute path to look up
    ///
    /// # Returns
    ///
    /// `Ok(Some(&ManifestEntry))` if found, `Ok(None)` otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError::InvalidPath`] if the path is invalid.
    ///
    /// # Example
    ///
    /// ```rust
    /// use apm2_core::context::{
    ///     AccessLevel, ContextPackManifest, ContextPackManifestBuilder,
    ///     ManifestEntryBuilder,
    /// };
    ///
    /// let manifest =
    ///     ContextPackManifestBuilder::new("manifest-001", "profile-001")
    ///         .add_entry(
    ///             ManifestEntryBuilder::new("/project/src/main.rs", [0x42; 32])
    ///                 .stable_id("main-file")
    ///                 .access_level(AccessLevel::Read)
    ///                 .build(),
    ///         )
    ///         .build();
    ///
    /// let entry = manifest.get_entry("/project/src/main.rs").unwrap().unwrap();
    /// assert_eq!(entry.stable_id(), Some("main-file"));
    /// assert_eq!(entry.access_level(), AccessLevel::Read);
    /// ```
    pub fn get_entry(&self, path: &str) -> Result<Option<&ManifestEntry>, ManifestError> {
        let normalized = normalize_path(path)?;
        Ok(self
            .path_index
            .get(&normalized)
            .map(|&idx| &self.entries[idx]))
    }

    /// Gets a manifest entry by `stable_id`.
    ///
    /// # Arguments
    ///
    /// * `stable_id` - The stable identifier to look up
    ///
    /// # Returns
    ///
    /// `Some(&ManifestEntry)` if found, `None` otherwise.
    #[must_use]
    pub fn get_entry_by_stable_id(&self, stable_id: &str) -> Option<&ManifestEntry> {
        self.entries
            .iter()
            .find(|e| e.stable_id.as_deref() == Some(stable_id))
    }

    /// Validates access to a file and returns the entry if allowed.
    ///
    /// This is a stricter version of `is_allowed` that returns an error with
    /// details about why access was denied.
    ///
    /// # Access Level Rules
    ///
    /// - **Read**: Hash check is optional. If `content_hash` is `None`, access
    ///   is granted. If `Some(hash)`, the hash must match.
    /// - **`ReadWithZoom`**: Hash is required. If `content_hash` is `None`,
    ///   returns an error.
    ///
    /// # Arguments
    ///
    /// * `path` - The absolute path to check
    /// * `content_hash` - The BLAKE3 hash of the file content (optional for
    ///   Read)
    ///
    /// # Returns
    ///
    /// `Ok(&ManifestEntry)` if access is allowed.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError::InvalidPath`] if the path is invalid.
    /// Returns [`ManifestError::PathNotFound`] if the path is not in the
    /// manifest.
    /// Returns [`ManifestError::ContentHashRequired`] if `ReadWithZoom` but
    /// hash is `None`.
    /// Returns [`ManifestError::ContentHashMismatch`] if the path exists but
    /// the hash doesn't match.
    pub fn validate_access(
        &self,
        path: &str,
        content_hash: Option<&[u8; 32]>,
    ) -> Result<&ManifestEntry, ManifestError> {
        let normalized = normalize_path(path)?;

        let entry = self
            .path_index
            .get(&normalized)
            .map(|&idx| &self.entries[idx])
            .ok_or_else(|| ManifestError::PathNotFound {
                path: normalized.clone(),
            })?;

        match (entry.access_level, content_hash) {
            // ReadWithZoom requires hash
            (AccessLevel::ReadWithZoom, None) => {
                Err(ManifestError::ContentHashRequired { path: normalized })
            },
            // Hash provided, verify it
            (_, Some(hash)) => {
                if !bool::from(entry.content_hash.ct_eq(hash)) {
                    return Err(ManifestError::ContentHashMismatch { path: normalized });
                }
                Ok(entry)
            },
            // Read access without hash - allowed
            (AccessLevel::Read, None) => Ok(entry),
        }
    }

    /// Verifies self-consistency by recomputing the manifest hash and
    /// comparing.
    ///
    /// This method recomputes the manifest hash from the current fields
    /// and verifies it matches the stored `manifest_hash`. This is useful
    /// after deserialization to ensure the manifest has not been tampered
    /// with.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the recomputed hash matches the stored hash.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError::InvalidData`] if the computed hash does not
    /// match the stored hash.
    pub fn verify_self_consistency(&self) -> Result<(), ManifestError> {
        let computed_hash =
            Self::compute_manifest_hash(&self.manifest_id, &self.profile_id, &self.entries);

        // Use constant-time comparison for security
        if !bool::from(computed_hash.ct_eq(&self.manifest_hash)) {
            return Err(ManifestError::InvalidData(format!(
                "manifest hash self-consistency check failed: computed={}, stored={}",
                hex_encode(&computed_hash),
                hex_encode(&self.manifest_hash)
            )));
        }

        Ok(())
    }

    /// Rebuilds the path index after deserialization.
    ///
    /// This is called automatically when needed, but can be called explicitly
    /// after deserializing a manifest.
    pub fn rebuild_index(&mut self) {
        self.path_index = Self::build_path_index(&self.entries);
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

/// Builder for constructing [`ContextPackManifest`] instances.
#[derive(Debug, Default)]
pub struct ContextPackManifestBuilder {
    manifest_id: String,
    profile_id: String,
    entries: Vec<ManifestEntry>,
}

impl ContextPackManifestBuilder {
    /// Creates a new builder with required IDs.
    #[must_use]
    pub fn new(manifest_id: impl Into<String>, profile_id: impl Into<String>) -> Self {
        Self {
            manifest_id: manifest_id.into(),
            profile_id: profile_id.into(),
            entries: Vec::new(),
        }
    }

    /// Adds a manifest entry.
    #[must_use]
    pub fn add_entry(mut self, entry: ManifestEntry) -> Self {
        self.entries.push(entry);
        self
    }

    /// Sets all entries.
    #[must_use]
    pub fn entries(mut self, entries: Vec<ManifestEntry>) -> Self {
        self.entries = entries;
        self
    }

    /// Builds the manifest.
    ///
    /// # Panics
    ///
    /// Panics if validation fails.
    #[must_use]
    pub fn build(self) -> ContextPackManifest {
        self.try_build().expect("manifest build failed")
    }

    /// Attempts to build the manifest.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError::StringTooLong`] if any string field exceeds
    /// the maximum length.
    /// Returns [`ManifestError::PathTooLong`] if any path exceeds the maximum
    /// length.
    /// Returns [`ManifestError::CollectionTooLarge`] if entries exceed the
    /// limit.
    /// Returns [`ManifestError::DuplicatePath`] if duplicate paths are found.
    /// Returns [`ManifestError::DuplicateStableId`] if duplicate `stable_id`s
    /// are found.
    /// Returns [`ManifestError::InvalidPath`] if any path contains traversal
    /// or null bytes.
    pub fn try_build(mut self) -> Result<ContextPackManifest, ManifestError> {
        use std::collections::HashSet;

        // Validate string lengths
        if self.manifest_id.len() > MAX_STRING_LENGTH {
            return Err(ManifestError::StringTooLong {
                field: "manifest_id",
                actual: self.manifest_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if self.profile_id.len() > MAX_STRING_LENGTH {
            return Err(ManifestError::StringTooLong {
                field: "profile_id",
                actual: self.profile_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }

        // Validate collection size
        if self.entries.len() > MAX_ENTRIES {
            return Err(ManifestError::CollectionTooLarge {
                field: "entries",
                actual: self.entries.len(),
                max: MAX_ENTRIES,
            });
        }

        // Track paths and stable_ids for duplicate detection using HashSet for O(N)
        let mut seen_paths: HashSet<String> = HashSet::with_capacity(self.entries.len());
        let mut seen_stable_ids: HashSet<&str> = HashSet::new();

        // Normalize paths and check for duplicates
        for entry in &mut self.entries {
            // Validate path length before normalization
            if entry.path.len() > MAX_PATH_LENGTH {
                return Err(ManifestError::PathTooLong {
                    actual: entry.path.len(),
                    max: MAX_PATH_LENGTH,
                });
            }

            // Normalize the path
            let normalized = normalize_path(&entry.path)?;

            // Check normalized path length
            if normalized.len() > MAX_PATH_LENGTH {
                return Err(ManifestError::PathTooLong {
                    actual: normalized.len(),
                    max: MAX_PATH_LENGTH,
                });
            }

            // Check for duplicate path (using normalized form)
            if !seen_paths.insert(normalized.clone()) {
                return Err(ManifestError::DuplicatePath { path: normalized });
            }

            // Update entry with normalized path
            entry.path = normalized;

            // Validate and check stable_id
            if let Some(ref stable_id) = entry.stable_id {
                if stable_id.len() > MAX_STRING_LENGTH {
                    return Err(ManifestError::StringTooLong {
                        field: "entry.stable_id",
                        actual: stable_id.len(),
                        max: MAX_STRING_LENGTH,
                    });
                }
                if !seen_stable_ids.insert(stable_id.as_str()) {
                    return Err(ManifestError::DuplicateStableId {
                        stable_id: stable_id.clone(),
                    });
                }
            }
        }

        // Build path index for O(1) lookups
        let path_index = ContextPackManifest::build_path_index(&self.entries);

        // Compute manifest hash
        let manifest_hash = ContextPackManifest::compute_manifest_hash(
            &self.manifest_id,
            &self.profile_id,
            &self.entries,
        );

        Ok(ContextPackManifest {
            manifest_id: self.manifest_id,
            manifest_hash,
            profile_id: self.profile_id,
            entries: self.entries,
            path_index,
        })
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(clippy::large_stack_frames)]
pub mod tests {
    use super::*;

    fn create_test_manifest() -> ContextPackManifest {
        ContextPackManifestBuilder::new("manifest-001", "profile-001")
            .add_entry(
                ManifestEntryBuilder::new("/project/src/main.rs", [0x42; 32])
                    .stable_id("src-main")
                    .access_level(AccessLevel::Read)
                    .build(),
            )
            .add_entry(
                ManifestEntryBuilder::new("/project/README.md", [0xAB; 32])
                    .stable_id("readme")
                    .access_level(AccessLevel::ReadWithZoom)
                    .build(),
            )
            .add_entry(
                ManifestEntryBuilder::new("/project/Cargo.toml", [0xCD; 32])
                    .access_level(AccessLevel::Read)
                    .build(),
            )
            .build()
    }

    // =========================================================================
    // Path Normalization Tests
    // =========================================================================

    #[test]
    fn test_normalize_path_basic() {
        assert_eq!(normalize_path("/foo/bar").unwrap(), "/foo/bar");
        assert_eq!(normalize_path("/foo/bar/").unwrap(), "/foo/bar");
        assert_eq!(normalize_path("/").unwrap(), "/");
    }

    #[test]
    fn test_normalize_path_removes_dot() {
        assert_eq!(normalize_path("/foo/./bar").unwrap(), "/foo/bar");
        assert_eq!(normalize_path("/./foo/./bar/.").unwrap(), "/foo/bar");
    }

    #[test]
    fn test_normalize_path_resolves_dotdot() {
        assert_eq!(normalize_path("/foo/bar/../baz").unwrap(), "/foo/baz");
        assert_eq!(
            normalize_path("/foo/bar/baz/../../qux").unwrap(),
            "/foo/qux"
        );
        assert_eq!(normalize_path("/foo/bar/..").unwrap(), "/foo");
    }

    #[test]
    fn test_normalize_path_multiple_slashes() {
        assert_eq!(normalize_path("/foo//bar").unwrap(), "/foo/bar");
        assert_eq!(normalize_path("/foo///bar////baz").unwrap(), "/foo/bar/baz");
    }

    #[test]
    fn test_normalize_path_relative_becomes_absolute() {
        assert_eq!(normalize_path("foo/bar").unwrap(), "/foo/bar");
        assert_eq!(normalize_path("foo").unwrap(), "/foo");
    }

    #[test]
    fn test_normalize_path_rejects_traversal_escape() {
        assert!(matches!(
            normalize_path("/foo/../../bar"),
            Err(ManifestError::InvalidPath { .. })
        ));
        assert!(matches!(
            normalize_path("/../foo"),
            Err(ManifestError::InvalidPath { .. })
        ));
        assert!(matches!(
            normalize_path("/.."),
            Err(ManifestError::InvalidPath { .. })
        ));
    }

    #[test]
    fn test_normalize_path_rejects_null_bytes() {
        assert!(matches!(
            normalize_path("/foo\0bar"),
            Err(ManifestError::InvalidPath { reason }) if reason.contains("null byte")
        ));
        assert!(matches!(
            normalize_path("/foo/bar\0"),
            Err(ManifestError::InvalidPath { .. })
        ));
    }

    #[test]
    fn test_normalize_path_rejects_empty() {
        assert!(matches!(
            normalize_path(""),
            Err(ManifestError::InvalidPath { reason }) if reason.contains("empty")
        ));
    }

    #[test]
    fn test_normalize_path_rejects_too_long() {
        // Path exactly at limit should succeed
        let at_limit = "/".to_string() + &"x".repeat(MAX_PATH_LENGTH - 1);
        assert_eq!(at_limit.len(), MAX_PATH_LENGTH);
        assert!(normalize_path(&at_limit).is_ok());

        // Path one byte over limit should fail
        let over_limit = "/".to_string() + &"x".repeat(MAX_PATH_LENGTH);
        assert_eq!(over_limit.len(), MAX_PATH_LENGTH + 1);
        assert!(matches!(
            normalize_path(&over_limit),
            Err(ManifestError::PathTooLong { actual, max })
                if actual == MAX_PATH_LENGTH + 1 && max == MAX_PATH_LENGTH
        ));
    }

    // =========================================================================
    // Basic Construction Tests
    // =========================================================================

    #[test]
    fn test_build_manifest() {
        let manifest = create_test_manifest();

        assert_eq!(manifest.manifest_id, "manifest-001");
        assert_eq!(manifest.profile_id, "profile-001");
        assert_eq!(manifest.entries().len(), 3);
    }

    #[test]
    fn test_manifest_hash_deterministic() {
        let manifest1 = create_test_manifest();
        let manifest2 = create_test_manifest();

        // Same content should produce same hash
        assert_eq!(manifest1.manifest_hash(), manifest2.manifest_hash());
    }

    #[test]
    fn test_manifest_hash_differs_with_different_content() {
        let manifest1 = create_test_manifest();

        let manifest2 = ContextPackManifestBuilder::new("manifest-002", "profile-001")
            .add_entry(
                ManifestEntryBuilder::new("/project/src/main.rs", [0x42; 32])
                    .access_level(AccessLevel::Read)
                    .build(),
            )
            .build();

        assert_ne!(manifest1.manifest_hash(), manifest2.manifest_hash());
    }

    // =========================================================================
    // is_allowed Tests
    // =========================================================================

    #[test]
    fn test_is_allowed_matching_path_and_hash() {
        let manifest = create_test_manifest();

        // Matching path and hash
        assert!(
            manifest
                .is_allowed("/project/src/main.rs", Some(&[0x42; 32]))
                .unwrap()
        );
        assert!(
            manifest
                .is_allowed("/project/README.md", Some(&[0xAB; 32]))
                .unwrap()
        );
        assert!(
            manifest
                .is_allowed("/project/Cargo.toml", Some(&[0xCD; 32]))
                .unwrap()
        );
    }

    #[test]
    fn test_is_allowed_read_without_hash() {
        let manifest = create_test_manifest();

        // Read access level allows omitting hash
        assert!(manifest.is_allowed("/project/src/main.rs", None).unwrap());
        assert!(manifest.is_allowed("/project/Cargo.toml", None).unwrap());
    }

    #[test]
    fn test_is_allowed_read_with_zoom_requires_hash() {
        let manifest = create_test_manifest();

        // ReadWithZoom requires hash
        let result = manifest.is_allowed("/project/README.md", None);
        assert!(matches!(
            result,
            Err(ManifestError::ContentHashRequired { path }) if path == "/project/README.md"
        ));
    }

    #[test]
    fn test_is_allowed_wrong_hash_rejected() {
        let manifest = create_test_manifest();

        // Correct path but wrong hash
        assert!(
            !manifest
                .is_allowed("/project/src/main.rs", Some(&[0xFF; 32]))
                .unwrap()
        );
        assert!(
            !manifest
                .is_allowed("/project/README.md", Some(&[0x00; 32]))
                .unwrap()
        );
    }

    #[test]
    fn test_is_allowed_unknown_path_rejected() {
        let manifest = create_test_manifest();

        // Path not in manifest (even with a "valid" hash)
        assert!(
            !manifest
                .is_allowed("/project/secret.txt", Some(&[0x42; 32]))
                .unwrap()
        );
        assert!(
            !manifest
                .is_allowed("/other/path.rs", Some(&[0x00; 32]))
                .unwrap()
        );
    }

    #[test]
    fn test_is_allowed_empty_manifest() {
        let manifest = ContextPackManifestBuilder::new("manifest-empty", "profile-001").build();

        // Empty manifest rejects everything
        assert!(
            !manifest
                .is_allowed("/any/path.rs", Some(&[0x42; 32]))
                .unwrap()
        );
    }

    #[test]
    fn test_is_allowed_with_path_normalization() {
        let manifest = create_test_manifest();

        // Path with .. that normalizes to allowed path
        assert!(
            manifest
                .is_allowed("/project/src/../src/main.rs", Some(&[0x42; 32]))
                .unwrap()
        );

        // Path with . that normalizes to allowed path
        assert!(
            manifest
                .is_allowed("/project/./src/main.rs", Some(&[0x42; 32]))
                .unwrap()
        );

        // Path with multiple slashes
        assert!(
            manifest
                .is_allowed("/project//src//main.rs", Some(&[0x42; 32]))
                .unwrap()
        );
    }

    #[test]
    fn test_is_allowed_rejects_traversal_attack() {
        let manifest = create_test_manifest();

        // Path traversal that would escape root
        let result = manifest.is_allowed("/project/../../../etc/passwd", Some(&[0x42; 32]));
        assert!(matches!(result, Err(ManifestError::InvalidPath { .. })));
    }

    #[test]
    fn test_is_allowed_rejects_null_byte() {
        let manifest = create_test_manifest();

        // Null byte injection
        let result = manifest.is_allowed("/project/src/main.rs\0.txt", Some(&[0x42; 32]));
        assert!(matches!(result, Err(ManifestError::InvalidPath { .. })));
    }

    // =========================================================================
    // get_entry Tests
    // =========================================================================

    #[test]
    fn test_get_entry_found() {
        let manifest = create_test_manifest();

        let entry = manifest.get_entry("/project/src/main.rs").unwrap().unwrap();
        assert_eq!(entry.stable_id(), Some("src-main"));
        assert_eq!(entry.content_hash(), &[0x42; 32]);
        assert_eq!(entry.access_level(), AccessLevel::Read);
    }

    #[test]
    fn test_get_entry_not_found() {
        let manifest = create_test_manifest();

        assert!(
            manifest
                .get_entry("/nonexistent/path.rs")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn test_get_entry_with_normalization() {
        let manifest = create_test_manifest();

        // Should find entry with normalized path
        let entry = manifest
            .get_entry("/project/src/../src/main.rs")
            .unwrap()
            .unwrap();
        assert_eq!(entry.path(), "/project/src/main.rs");
    }

    #[test]
    fn test_get_entry_by_stable_id() {
        let manifest = create_test_manifest();

        let entry = manifest.get_entry_by_stable_id("src-main").unwrap();
        assert_eq!(entry.path(), "/project/src/main.rs");

        let entry = manifest.get_entry_by_stable_id("readme").unwrap();
        assert_eq!(entry.path(), "/project/README.md");
    }

    #[test]
    fn test_get_entry_by_stable_id_not_found() {
        let manifest = create_test_manifest();

        assert!(manifest.get_entry_by_stable_id("nonexistent").is_none());
    }

    // =========================================================================
    // validate_access Tests
    // =========================================================================

    #[test]
    fn test_validate_access_success() {
        let manifest = create_test_manifest();

        let entry = manifest
            .validate_access("/project/src/main.rs", Some(&[0x42; 32]))
            .unwrap();
        assert_eq!(entry.stable_id(), Some("src-main"));
    }

    #[test]
    fn test_validate_access_read_without_hash() {
        let manifest = create_test_manifest();

        // Read access allows omitting hash
        let entry = manifest
            .validate_access("/project/src/main.rs", None)
            .unwrap();
        assert_eq!(entry.stable_id(), Some("src-main"));
    }

    #[test]
    fn test_validate_access_read_with_zoom_requires_hash() {
        let manifest = create_test_manifest();

        // ReadWithZoom requires hash
        let result = manifest.validate_access("/project/README.md", None);
        assert!(matches!(
            result,
            Err(ManifestError::ContentHashRequired { path }) if path == "/project/README.md"
        ));
    }

    #[test]
    fn test_validate_access_path_not_found() {
        let manifest = create_test_manifest();

        let result = manifest.validate_access("/nonexistent/path.rs", Some(&[0x42; 32]));
        assert!(matches!(
            result,
            Err(ManifestError::PathNotFound { path }) if path == "/nonexistent/path.rs"
        ));
    }

    #[test]
    fn test_validate_access_hash_mismatch() {
        let manifest = create_test_manifest();

        let result = manifest.validate_access("/project/src/main.rs", Some(&[0xFF; 32]));
        assert!(matches!(
            result,
            Err(ManifestError::ContentHashMismatch { path }) if path == "/project/src/main.rs"
        ));
    }

    // =========================================================================
    // Resource Limit Tests
    // =========================================================================

    #[test]
    fn test_entries_too_large() {
        let entries: Vec<ManifestEntry> = (0..=MAX_ENTRIES)
            .map(|i| {
                ManifestEntryBuilder::new(format!("/path/file-{i}.rs"), [0x42; 32])
                    .access_level(AccessLevel::Read)
                    .build()
            })
            .collect();

        let result = ContextPackManifestBuilder::new("manifest-001", "profile-001")
            .entries(entries)
            .try_build();

        assert!(matches!(
            result,
            Err(ManifestError::CollectionTooLarge {
                field: "entries",
                actual,
                max,
            }) if actual == MAX_ENTRIES + 1 && max == MAX_ENTRIES
        ));
    }

    #[test]
    fn test_manifest_id_too_long() {
        let long_id = "x".repeat(MAX_STRING_LENGTH + 1);

        let result = ContextPackManifestBuilder::new(long_id, "profile-001").try_build();

        assert!(matches!(
            result,
            Err(ManifestError::StringTooLong {
                field: "manifest_id",
                ..
            })
        ));
    }

    #[test]
    fn test_profile_id_too_long() {
        let long_id = "x".repeat(MAX_STRING_LENGTH + 1);

        let result = ContextPackManifestBuilder::new("manifest-001", long_id).try_build();

        assert!(matches!(
            result,
            Err(ManifestError::StringTooLong {
                field: "profile_id",
                ..
            })
        ));
    }

    #[test]
    fn test_path_too_long() {
        let long_path = "/".to_string() + &"x".repeat(MAX_PATH_LENGTH);

        let result = ContextPackManifestBuilder::new("manifest-001", "profile-001")
            .add_entry(
                ManifestEntryBuilder::new(long_path, [0x42; 32])
                    .access_level(AccessLevel::Read)
                    .build(),
            )
            .try_build();

        assert!(matches!(result, Err(ManifestError::PathTooLong { .. })));
    }

    #[test]
    fn test_stable_id_too_long() {
        let long_id = "x".repeat(MAX_STRING_LENGTH + 1);

        let result = ContextPackManifestBuilder::new("manifest-001", "profile-001")
            .add_entry(
                ManifestEntryBuilder::new("/project/file.rs", [0x42; 32])
                    .stable_id(long_id)
                    .access_level(AccessLevel::Read)
                    .build(),
            )
            .try_build();

        assert!(matches!(
            result,
            Err(ManifestError::StringTooLong {
                field: "entry.stable_id",
                ..
            })
        ));
    }

    // =========================================================================
    // Duplicate Detection Tests
    // =========================================================================

    #[test]
    fn test_duplicate_path_rejected() {
        let result = ContextPackManifestBuilder::new("manifest-001", "profile-001")
            .add_entry(
                ManifestEntryBuilder::new("/project/file.rs", [0x42; 32])
                    .access_level(AccessLevel::Read)
                    .build(),
            )
            .add_entry(
                ManifestEntryBuilder::new("/project/file.rs", [0xAB; 32])
                    .access_level(AccessLevel::ReadWithZoom)
                    .build(),
            )
            .try_build();

        assert!(matches!(
            result,
            Err(ManifestError::DuplicatePath { path }) if path == "/project/file.rs"
        ));
    }

    #[test]
    fn test_duplicate_path_after_normalization_rejected() {
        // Paths that normalize to the same value should be detected as duplicates
        let result = ContextPackManifestBuilder::new("manifest-001", "profile-001")
            .add_entry(
                ManifestEntryBuilder::new("/project/src/main.rs", [0x42; 32])
                    .access_level(AccessLevel::Read)
                    .build(),
            )
            .add_entry(
                ManifestEntryBuilder::new("/project/src/../src/main.rs", [0xAB; 32])
                    .access_level(AccessLevel::Read)
                    .build(),
            )
            .try_build();

        assert!(matches!(
            result,
            Err(ManifestError::DuplicatePath { path }) if path == "/project/src/main.rs"
        ));
    }

    #[test]
    fn test_duplicate_stable_id_rejected() {
        let result = ContextPackManifestBuilder::new("manifest-001", "profile-001")
            .add_entry(
                ManifestEntryBuilder::new("/project/file1.rs", [0x42; 32])
                    .stable_id("file-id")
                    .access_level(AccessLevel::Read)
                    .build(),
            )
            .add_entry(
                ManifestEntryBuilder::new("/project/file2.rs", [0xAB; 32])
                    .stable_id("file-id")
                    .access_level(AccessLevel::Read)
                    .build(),
            )
            .try_build();

        assert!(matches!(
            result,
            Err(ManifestError::DuplicateStableId { stable_id }) if stable_id == "file-id"
        ));
    }

    // =========================================================================
    // Self-Consistency Tests
    // =========================================================================

    #[test]
    fn test_verify_self_consistency_passes() {
        let manifest = create_test_manifest();

        assert!(manifest.verify_self_consistency().is_ok());
    }

    #[test]
    fn test_verify_self_consistency_fails_on_tampered_manifest() {
        // Create a manifest with manually corrupted hash via JSON
        let json = r#"{"manifest_id":"manifest-001","manifest_hash":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"profile_id":"profile-001","entries":[]}"#;
        let mut manifest: ContextPackManifest = serde_json::from_str(json).unwrap();
        manifest.rebuild_index();

        let result = manifest.verify_self_consistency();
        assert!(
            matches!(result, Err(ManifestError::InvalidData(_))),
            "Expected InvalidData but got {result:?}"
        );
    }

    #[test]
    fn test_verify_self_consistency_after_deserialization() {
        let original = create_test_manifest();

        // Serialize and deserialize
        let json = serde_json::to_string(&original).unwrap();
        let mut recovered: ContextPackManifest = serde_json::from_str(&json).unwrap();
        recovered.rebuild_index();

        // Self-consistency should still pass
        assert!(recovered.verify_self_consistency().is_ok());
    }

    // =========================================================================
    // AccessLevel Tests
    // =========================================================================

    #[test]
    fn test_access_level_try_from() {
        assert_eq!(AccessLevel::try_from(0).unwrap(), AccessLevel::Read);
        assert_eq!(AccessLevel::try_from(1).unwrap(), AccessLevel::ReadWithZoom);
        assert!(AccessLevel::try_from(2).is_err());
        assert!(AccessLevel::try_from(255).is_err());
    }

    #[test]
    fn test_access_level_to_u8() {
        assert_eq!(u8::from(AccessLevel::Read), 0);
        assert_eq!(u8::from(AccessLevel::ReadWithZoom), 1);
    }

    // =========================================================================
    // Serde Round-Trip Tests
    // =========================================================================

    #[test]
    fn test_serde_roundtrip() {
        let original = create_test_manifest();

        // Serialize to JSON
        let json = serde_json::to_string(&original).unwrap();

        // Deserialize back
        let mut recovered: ContextPackManifest = serde_json::from_str(&json).unwrap();
        recovered.rebuild_index();

        assert_eq!(original.manifest_id, recovered.manifest_id);
        assert_eq!(original.manifest_hash, recovered.manifest_hash);
        assert_eq!(original.profile_id, recovered.profile_id);
        assert_eq!(original.entries, recovered.entries);
    }

    #[test]
    fn test_serde_deny_unknown_fields_manifest() {
        // JSON with unknown field should fail to deserialize
        let json = r#"{"manifest_id":"test","manifest_hash":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"profile_id":"profile","entries":[],"unknown_field":"bad"}"#;

        let result: Result<ContextPackManifest, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_serde_deny_unknown_fields_entry() {
        // Entry JSON with unknown field should fail
        let json = r#"{"path":"/test","content_hash":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"access_level":"Read","unknown":"bad"}"#;

        let result: Result<ManifestEntry, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    // =========================================================================
    // Empty Manifest Tests
    // =========================================================================

    #[test]
    fn test_empty_manifest_valid() {
        let manifest = ContextPackManifestBuilder::new("manifest-empty", "profile-001").build();

        assert!(manifest.entries().is_empty());
        assert!(manifest.verify_self_consistency().is_ok());
    }

    // =========================================================================
    // Edge Cases
    // =========================================================================

    #[test]
    fn test_entry_without_stable_id() {
        let manifest = ContextPackManifestBuilder::new("manifest-001", "profile-001")
            .add_entry(
                ManifestEntryBuilder::new("/project/file.rs", [0x42; 32])
                    .access_level(AccessLevel::Read)
                    .build(),
            )
            .build();

        assert!(
            manifest
                .is_allowed("/project/file.rs", Some(&[0x42; 32]))
                .unwrap()
        );
        assert!(manifest.get_entry_by_stable_id("any").is_none());
    }

    #[test]
    fn test_multiple_entries_same_hash_different_paths() {
        // Same content hash for different files is valid (same content in
        // different locations)
        let manifest = ContextPackManifestBuilder::new("manifest-001", "profile-001")
            .add_entry(
                ManifestEntryBuilder::new("/project/file1.rs", [0x42; 32])
                    .access_level(AccessLevel::Read)
                    .build(),
            )
            .add_entry(
                ManifestEntryBuilder::new("/project/file2.rs", [0x42; 32])
                    .access_level(AccessLevel::Read)
                    .build(),
            )
            .build();

        assert!(
            manifest
                .is_allowed("/project/file1.rs", Some(&[0x42; 32]))
                .unwrap()
        );
        assert!(
            manifest
                .is_allowed("/project/file2.rs", Some(&[0x42; 32]))
                .unwrap()
        );
    }

    #[test]
    fn test_constant_time_hash_comparison() {
        // This test verifies that hash comparison is done in constant time
        // by ensuring the same result regardless of where bytes differ
        let manifest = ContextPackManifestBuilder::new("manifest-001", "profile-001")
            .add_entry(
                ManifestEntryBuilder::new("/project/file.rs", [0xFF; 32])
                    .access_level(AccessLevel::Read)
                    .build(),
            )
            .build();

        // Different in first byte
        let mut hash1 = [0xFF; 32];
        hash1[0] = 0x00;
        assert!(
            !manifest
                .is_allowed("/project/file.rs", Some(&hash1))
                .unwrap()
        );

        // Different in last byte
        let mut hash2 = [0xFF; 32];
        hash2[31] = 0x00;
        assert!(
            !manifest
                .is_allowed("/project/file.rs", Some(&hash2))
                .unwrap()
        );

        // All different
        assert!(
            !manifest
                .is_allowed("/project/file.rs", Some(&[0x00; 32]))
                .unwrap()
        );
    }

    // =========================================================================
    // ManifestEntry Getter Tests
    // =========================================================================

    #[test]
    fn test_manifest_entry_getters() {
        let entry = ManifestEntryBuilder::new("/project/file.rs", [0x42; 32])
            .stable_id("test-id")
            .access_level(AccessLevel::ReadWithZoom)
            .build();

        assert_eq!(entry.path(), "/project/file.rs");
        assert_eq!(entry.content_hash(), &[0x42; 32]);
        assert_eq!(entry.stable_id(), Some("test-id"));
        assert_eq!(entry.access_level(), AccessLevel::ReadWithZoom);
    }

    #[test]
    fn test_manifest_entry_no_stable_id() {
        let entry = ManifestEntryBuilder::new("/project/file.rs", [0x42; 32])
            .access_level(AccessLevel::Read)
            .build();

        assert_eq!(entry.stable_id(), None);
    }

    // =========================================================================
    // Path Index Tests
    // =========================================================================

    #[test]
    fn test_path_index_built_on_construction() {
        let manifest = create_test_manifest();

        // Verify O(1) lookup works
        assert!(
            manifest
                .get_entry("/project/src/main.rs")
                .unwrap()
                .is_some()
        );
        assert!(manifest.get_entry("/project/README.md").unwrap().is_some());
        assert!(manifest.get_entry("/project/Cargo.toml").unwrap().is_some());
    }

    #[test]
    fn test_rebuild_index_after_deserialization() {
        let original = create_test_manifest();
        let json = serde_json::to_string(&original).unwrap();
        let mut recovered: ContextPackManifest = serde_json::from_str(&json).unwrap();

        // Before rebuild, path_index is empty (serde skip)
        assert!(recovered.path_index.is_empty());

        // Rebuild index
        recovered.rebuild_index();

        // Now lookups work
        assert!(
            recovered
                .get_entry("/project/src/main.rs")
                .unwrap()
                .is_some()
        );
    }

    // =========================================================================
    // Path Traversal Attack Tests
    // =========================================================================

    #[test]
    fn test_path_traversal_attack_patterns() {
        let manifest = create_test_manifest();

        // Various traversal patterns that should be handled
        let attack_patterns = [
            "/project/../../../etc/passwd",
            "/../etc/passwd",
            "/project/src/../../..",
        ];

        for pattern in attack_patterns {
            let result = manifest.is_allowed(pattern, Some(&[0x42; 32]));
            assert!(
                matches!(result, Err(ManifestError::InvalidPath { .. })),
                "Pattern '{pattern}' should be rejected as invalid path"
            );
        }
    }

    #[test]
    fn test_null_byte_injection_patterns() {
        let manifest = create_test_manifest();

        let attack_patterns = [
            "/project/src/main.rs\0.txt",
            "/project/\0/file.rs",
            "\0/etc/passwd",
        ];

        for pattern in attack_patterns {
            let result = manifest.is_allowed(pattern, Some(&[0x42; 32]));
            assert!(
                matches!(result, Err(ManifestError::InvalidPath { .. })),
                "Pattern with null byte should be rejected"
            );
        }
    }

    #[test]
    fn test_build_rejects_traversal_in_entry_path() {
        // Paths that would escape root should be rejected at build time
        let result = ContextPackManifestBuilder::new("manifest-001", "profile-001")
            .add_entry(
                ManifestEntryBuilder::new("/project/../../etc/passwd", [0x42; 32])
                    .access_level(AccessLevel::Read)
                    .build(),
            )
            .try_build();

        assert!(matches!(result, Err(ManifestError::InvalidPath { .. })));
    }

    #[test]
    fn test_build_rejects_null_byte_in_entry_path() {
        let result = ContextPackManifestBuilder::new("manifest-001", "profile-001")
            .add_entry(
                ManifestEntryBuilder::new("/project/file\0.rs", [0x42; 32])
                    .access_level(AccessLevel::Read)
                    .build(),
            )
            .try_build();

        assert!(matches!(result, Err(ManifestError::InvalidPath { .. })));
    }
}
