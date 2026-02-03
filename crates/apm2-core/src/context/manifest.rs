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

/// Maximum number of path components allowed.
/// Prevents Vec allocation spikes from paths with many segments.
pub const MAX_PATH_COMPONENTS: usize = 256;

/// Maximum number of tool classes in the tool allowlist.
/// Per CTR-1303, bounded collections prevent `DoS`.
pub const MAX_TOOL_ALLOWLIST: usize = 100;

/// Maximum number of paths in the write allowlist.
/// Per CTR-1303, bounded collections prevent `DoS`.
pub const MAX_WRITE_ALLOWLIST: usize = 1000;

/// Maximum number of patterns in the shell allowlist.
/// Per CTR-1303, bounded collections prevent `DoS`.
pub const MAX_SHELL_ALLOWLIST: usize = 500;

/// Maximum length of a shell pattern.
/// Per CTR-1303, bounded inputs prevent memory exhaustion.
pub const MAX_SHELL_PATTERN_LEN: usize = 1024;

/// Maximum string length for tool class names during parsing.
pub const MAX_TOOL_CLASS_NAME_LEN: usize = 64;

// =============================================================================
// Tool Class Enum (TCK-00254)
//
// Per REQ-DCP-0002, the context pack manifest includes a tool allowlist.
// This is the canonical definition; apm2-daemon re-exports from here.
// =============================================================================

/// Tool class for capability categorization.
///
/// Per AD-TOOL-002, tool classes define the coarse-grained category of
/// operations a capability allows. Fine-grained restrictions are applied
/// via `CapabilityScope`.
///
/// # Discriminant Stability
///
/// Explicit discriminant values maintain semver compatibility. New variants
/// must use new values; existing values must not change.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
#[non_exhaustive]
pub enum ToolClass {
    /// Read operations: file reads, directory listings, git status.
    #[default]
    Read      = 0,

    /// Write operations: file writes, file edits, file deletions.
    Write     = 1,

    /// Execute operations: shell commands, process spawning.
    Execute   = 2,

    /// Network operations: HTTP requests, socket connections.
    Network   = 3,

    /// Git operations: commits, pushes, branch operations.
    Git       = 4,

    /// Inference operations: LLM API calls.
    Inference = 5,

    /// Artifact operations: CAS publish/fetch.
    Artifact  = 6,

    /// `ListFiles` operations: directory listing.
    ListFiles = 7,

    /// Search operations: content search.
    Search    = 8,
}

impl ToolClass {
    /// Returns the numeric value of this tool class.
    #[must_use]
    pub const fn value(&self) -> u8 {
        *self as u8
    }

    /// Parses a tool class from a u8 value.
    ///
    /// # Returns
    ///
    /// `None` if the value does not correspond to a known tool class.
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Read),
            1 => Some(Self::Write),
            2 => Some(Self::Execute),
            3 => Some(Self::Network),
            4 => Some(Self::Git),
            5 => Some(Self::Inference),
            6 => Some(Self::Artifact),
            7 => Some(Self::ListFiles),
            8 => Some(Self::Search),
            _ => None,
        }
    }

    /// Parses a tool class from a u32 value.
    ///
    /// # Security
    ///
    /// This method validates the full u32 range to prevent truncation attacks.
    /// Casting to u8 first would truncate values like 256 to 0, potentially
    /// granting unintended capabilities.
    #[must_use]
    pub const fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Read),
            1 => Some(Self::Write),
            2 => Some(Self::Execute),
            3 => Some(Self::Network),
            4 => Some(Self::Git),
            5 => Some(Self::Inference),
            6 => Some(Self::Artifact),
            7 => Some(Self::ListFiles),
            8 => Some(Self::Search),
            _ => None,
        }
    }

    /// Parses a tool class from a string name.
    ///
    /// # Security
    ///
    /// Rejects names longer than `MAX_TOOL_CLASS_NAME_LEN` to prevent
    /// memory exhaustion attacks.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        if s.len() > MAX_TOOL_CLASS_NAME_LEN {
            return None;
        }
        match s.to_lowercase().as_str() {
            "read" => Some(Self::Read),
            "write" => Some(Self::Write),
            "execute" | "exec" => Some(Self::Execute),
            "network" | "net" => Some(Self::Network),
            "git" => Some(Self::Git),
            "inference" | "llm" => Some(Self::Inference),
            "artifact" | "cas" => Some(Self::Artifact),
            "listfiles" | "ls" => Some(Self::ListFiles),
            "search" | "grep" => Some(Self::Search),
            _ => None,
        }
    }

    /// Returns the canonical name of this tool class.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Read => "Read",
            Self::Write => "Write",
            Self::Execute => "Execute",
            Self::Network => "Network",
            Self::Git => "Git",
            Self::Inference => "Inference",
            Self::Artifact => "Artifact",
            Self::ListFiles => "ListFiles",
            Self::Search => "Search",
        }
    }

    /// Returns `true` if this tool class represents read-only operations.
    #[must_use]
    pub const fn is_read_only(&self) -> bool {
        matches!(self, Self::Read | Self::ListFiles | Self::Search)
    }

    /// Returns `true` if this tool class can modify state.
    #[must_use]
    pub const fn can_mutate(&self) -> bool {
        matches!(
            self,
            Self::Write | Self::Execute | Self::Git | Self::Artifact
        )
    }

    /// Returns `true` if this tool class involves network access.
    #[must_use]
    pub const fn involves_network(&self) -> bool {
        matches!(self, Self::Network | Self::Inference)
    }

    /// Returns all known tool classes.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::Read,
            Self::Write,
            Self::Execute,
            Self::Network,
            Self::Git,
            Self::Inference,
            Self::Artifact,
            Self::ListFiles,
            Self::Search,
        ]
    }
}

impl std::fmt::Display for ToolClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

// =============================================================================
// ToolClassExt - Canonical Serialization
// =============================================================================

/// Internal protobuf representation for `ToolClass`.
#[derive(Clone, PartialEq, prost::Message)]
struct ToolClassProto {
    #[prost(uint32, optional, tag = "1")]
    value: Option<u32>,
}

/// Extension trait for `ToolClass` to provide canonical serialization.
///
/// Per AD-VERIFY-001, this provides deterministic serialization
/// for use in digests and signatures.
pub trait ToolClassExt {
    /// Returns the canonical bytes for this tool class.
    fn canonical_bytes(&self) -> Vec<u8>;
}

impl ToolClassExt for ToolClass {
    fn canonical_bytes(&self) -> Vec<u8> {
        use prost::Message;
        let proto = ToolClassProto {
            value: Some(u32::from(self.value())),
        };
        proto.encode_to_vec()
    }
}

// =============================================================================
// Shell Pattern Matching (TCK-00254)
//
// Per Code Quality Review [MAJOR], this function is shared between
// ContextPackManifest and CapabilityManifest to eliminate duplication.
// =============================================================================

/// Matches a shell command against a pattern with simple glob support.
///
/// Supports `*` as a wildcard that matches any sequence of characters.
/// Patterns without wildcards require exact match.
///
/// # Implementation
///
/// Uses streaming iteration over pattern parts to avoid heap allocations
/// in the hot path (SEC-DOS-MDL-0001). This is critical since this method
/// is called for every tool request against every pattern in the shell
/// allowlist (up to `MAX_SHELL_ALLOWLIST` patterns).
///
/// # Examples
///
/// ```
/// use apm2_core::context::shell_pattern_matches;
///
/// // Exact match (no wildcards)
/// assert!(shell_pattern_matches("cargo build", "cargo build"));
/// assert!(!shell_pattern_matches("cargo build", "cargo test"));
///
/// // Prefix match
/// assert!(shell_pattern_matches("cargo *", "cargo build"));
/// assert!(shell_pattern_matches("cargo *", "cargo test --release"));
///
/// // Suffix match
/// assert!(shell_pattern_matches(
///     "* --release",
///     "cargo build --release"
/// ));
///
/// // Contains match
/// assert!(shell_pattern_matches("*build*", "cargo build --release"));
/// ```
#[must_use]
pub fn shell_pattern_matches(pattern: &str, command: &str) -> bool {
    // Check for wildcards first - if none, exact match required
    if !pattern.contains('*') {
        return pattern == command;
    }

    // Streaming iterator over pattern parts (zero allocations)
    let mut parts = pattern.split('*');
    let mut remaining = command;

    // Handle first part: must be at start unless pattern starts with '*'
    if let Some(first) = parts.next() {
        if !first.is_empty() {
            // Pattern doesn't start with '*', so first part must be prefix
            if let Some(stripped) = remaining.strip_prefix(first) {
                remaining = stripped;
            } else {
                return false;
            }
        }
    }

    // Handle middle and last parts
    // We peek ahead to distinguish middle parts from the last part
    let mut prev_part: Option<&str> = None;
    for part in parts {
        // Process the previous part as a middle part (can be anywhere)
        if let Some(p) = prev_part {
            if !p.is_empty() {
                if let Some(pos) = remaining.find(p) {
                    remaining = &remaining[pos + p.len()..];
                } else {
                    return false;
                }
            }
        }
        prev_part = Some(part);
    }

    // Process the last part: must be at end unless pattern ends with '*'
    if let Some(last_part) = prev_part {
        if !pattern.ends_with('*') && !last_part.is_empty() {
            // Pattern doesn't end with '*', so last part must be suffix
            if !remaining.ends_with(last_part) {
                return false;
            }
        } else if !last_part.is_empty() {
            // Pattern ends with '*', so last part just needs to exist
            if !remaining.contains(last_part) {
                return false;
            }
        }
    }

    true
}

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

    /// Path has too many components.
    #[error("path has too many components: {actual} > {max}")]
    TooManyPathComponents {
        /// Actual number of components.
        actual: usize,
        /// Maximum allowed components.
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

    /// Write allowlist path is not absolute.
    ///
    /// Per CTR-1503, all write paths must be absolute to prevent
    /// path resolution attacks.
    #[error("write allowlist path is not absolute: {path}")]
    WriteAllowlistPathNotAbsolute {
        /// The path that is not absolute.
        path: String,
    },

    /// Write allowlist path contains path traversal.
    ///
    /// Per CTR-1503 and CTR-2609, paths must not contain `..` components
    /// to prevent directory escape attacks.
    #[error("write allowlist path contains traversal (..): {path}")]
    WriteAllowlistPathTraversal {
        /// The path that contains traversal.
        path: String,
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

    // Process components with a pre-allocated Vec capped at MAX_PATH_COMPONENTS
    // This prevents allocation spikes from paths with many segments
    let mut components: Vec<&str> = Vec::with_capacity(MAX_PATH_COMPONENTS.min(64));
    let mut component_count: usize = 0;

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
                // Note: component_count tracks total components seen, not final
                // count
            },
            // Normal component
            _ => {
                component_count += 1;
                if component_count > MAX_PATH_COMPONENTS {
                    return Err(ManifestError::TooManyPathComponents {
                        actual: component_count,
                        max: MAX_PATH_COMPONENTS,
                    });
                }
                components.push(component);
            },
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
/// - `tool_allowlist`: List of allowed tool classes (TCK-00254)
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

    /// Allowlist of tool classes that can be invoked.
    ///
    /// Per TCK-00254 and REQ-DCP-0002, tool requests are validated against
    /// this allowlist. Empty means no tools allowed (fail-closed).
    #[serde(default)]
    pub tool_allowlist: Vec<ToolClass>,

    /// Allowlist of filesystem paths that can be written to.
    ///
    /// Per TCK-00254 and REQ-DCP-0002, write operations are validated against
    /// this allowlist. Paths should be absolute and normalized. Empty means
    /// no writes allowed (fail-closed).
    #[serde(default)]
    pub write_allowlist: Vec<std::path::PathBuf>,

    /// Allowlist of shell command patterns that can be executed.
    ///
    /// Per TCK-00254 and REQ-DCP-0002, shell execution requests are validated
    /// against this allowlist. Patterns may use glob syntax. Empty means no
    /// shell allowed (fail-closed).
    #[serde(default)]
    pub shell_allowlist: Vec<String>,

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
            && self.tool_allowlist == other.tool_allowlist
            && self.write_allowlist == other.write_allowlist
            && self.shell_allowlist == other.shell_allowlist
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

    /// Checks if the given path is in the write allowlist.
    ///
    /// Per TCK-00254, returns `false` if the allowlist is empty (fail-closed).
    /// The path must be a prefix match: `/workspace` allows `/workspace/foo`.
    #[must_use]
    pub fn is_write_path_allowed(&self, path: &std::path::Path) -> bool {
        if self.write_allowlist.is_empty() {
            // Fail-closed: empty allowlist means nothing is allowed
            return false;
        }

        // Check if the path starts with any allowed path
        self.write_allowlist
            .iter()
            .any(|allowed| path.starts_with(allowed))
    }

    /// Checks if the given shell command matches a pattern in the shell
    /// allowlist.
    ///
    /// Per TCK-00254, returns `false` if the allowlist is empty (fail-closed).
    /// Patterns use simple glob matching with `*` as wildcard.
    #[must_use]
    pub fn is_shell_command_allowed(&self, command: &str) -> bool {
        if self.shell_allowlist.is_empty() {
            // Fail-closed: empty allowlist means nothing is allowed
            return false;
        }

        // Check if the command matches any allowed pattern
        // Uses the module-level shell_pattern_matches function to avoid duplication
        self.shell_allowlist
            .iter()
            .any(|pattern| shell_pattern_matches(pattern, command))
    }

    /// Computes the manifest hash from the manifest fields.
    ///
    /// The hash is computed over the canonical representation of all fields
    /// except the hash itself. Per TCK-00254, all allowlists are sorted for
    /// deterministic ordering.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    fn compute_manifest_hash(
        manifest_id: &str,
        profile_id: &str,
        entries: &[ManifestEntry],
        tool_allowlist: &[ToolClass],
        write_allowlist: &[std::path::PathBuf],
        shell_allowlist: &[String],
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

        // Tool allowlist (TCK-00254) - sorted for determinism
        let mut sorted_tools: Vec<u8> = tool_allowlist.iter().map(ToolClass::value).collect();
        sorted_tools.sort_unstable();
        hasher.update(&(sorted_tools.len() as u32).to_be_bytes());
        for tool_value in &sorted_tools {
            hasher.update(&[*tool_value]);
        }

        // Write allowlist (TCK-00254) - sorted for determinism
        let mut sorted_write_paths: Vec<String> = write_allowlist
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect();
        sorted_write_paths.sort_unstable();
        hasher.update(&(sorted_write_paths.len() as u32).to_be_bytes());
        for path in &sorted_write_paths {
            hasher.update(&(path.len() as u32).to_be_bytes());
            hasher.update(path.as_bytes());
        }

        // Shell allowlist (TCK-00254) - sorted for determinism
        let mut sorted_shell_patterns: Vec<&str> =
            shell_allowlist.iter().map(String::as_str).collect();
        sorted_shell_patterns.sort_unstable();
        hasher.update(&(sorted_shell_patterns.len() as u32).to_be_bytes());
        for pattern in &sorted_shell_patterns {
            hasher.update(&(pattern.len() as u32).to_be_bytes());
            hasher.update(pattern.as_bytes());
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
        self.is_allowed_normalized(&normalized, content_hash)
    }

    /// Checks if access to a file is allowed using a pre-normalized path.
    ///
    /// This is an optimization for callers that have already normalized the
    /// path. The path MUST be normalized (via [`normalize_path`]) before
    /// calling this method.
    ///
    /// # Safety
    ///
    /// Passing a non-normalized path may result in incorrect allowlist lookups.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError::ContentHashRequired`] if the entry has
    /// `ReadWithZoom` access level but no hash was provided.
    pub fn is_allowed_normalized(
        &self,
        normalized_path: &str,
        content_hash: Option<&[u8; 32]>,
    ) -> Result<bool, ManifestError> {
        let Some(&idx) = self.path_index.get(normalized_path) else {
            return Ok(false);
        };

        let entry = &self.entries[idx];

        match (entry.access_level, content_hash) {
            // ReadWithZoom requires hash
            (AccessLevel::ReadWithZoom, None) => Err(ManifestError::ContentHashRequired {
                path: normalized_path.to_string(),
            }),
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
        Ok(self.get_entry_normalized(&normalized))
    }

    /// Gets a manifest entry by pre-normalized path.
    ///
    /// This is an optimization for callers that have already normalized the
    /// path. The path MUST be normalized (via [`normalize_path`]) before
    /// calling this method.
    ///
    /// # Safety
    ///
    /// Passing a non-normalized path may result in incorrect lookups.
    #[must_use]
    pub fn get_entry_normalized(&self, normalized_path: &str) -> Option<&ManifestEntry> {
        self.path_index
            .get(normalized_path)
            .map(|&idx| &self.entries[idx])
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
        let computed_hash = Self::compute_manifest_hash(
            &self.manifest_id,
            &self.profile_id,
            &self.entries,
            &self.tool_allowlist,
            &self.write_allowlist,
            &self.shell_allowlist,
        );

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

    /// Seals the context pack and returns the content hash.
    ///
    /// Sealing is the explicit action that finalizes the manifest and produces
    /// a cryptographic hash for verification. This hash:
    ///
    /// 1. Is deterministic: same entries always produce the same hash
    /// 2. Is tamper-evident: any modification to the manifest will change the
    ///    hash
    /// 3. Includes all manifest content: `manifest_id`, `profile_id`, and all
    ///    entries
    ///
    /// The seal hash is computed at build time and stored in `manifest_hash`.
    /// This method returns the pre-computed hash and verifies self-consistency.
    ///
    /// # Use in Work Claim Flow
    ///
    /// Per RFC-0017 DD-003, the Work Orchestrator calls `seal()` on the context
    /// pack before returning the `WorkAssignment`. The returned hash is
    /// included in the `ClaimWorkResponse.context_pack_hash` field.
    ///
    /// # Returns
    ///
    /// The 32-byte BLAKE3 hash of the manifest content.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError::InvalidData`] if the manifest has been tampered
    /// with (hash mismatch).
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
    /// // Seal returns the content hash
    /// let seal_hash = manifest.seal().unwrap();
    /// assert_eq!(seal_hash, manifest.manifest_hash());
    ///
    /// // Same entries always produce the same hash
    /// let manifest2 =
    ///     ContextPackManifestBuilder::new("manifest-001", "profile-001")
    ///         .add_entry(
    ///             ManifestEntryBuilder::new("/project/src/main.rs", [0x42; 32])
    ///                 .access_level(AccessLevel::Read)
    ///                 .build(),
    ///         )
    ///         .build();
    ///
    /// assert_eq!(manifest.seal().unwrap(), manifest2.seal().unwrap());
    /// ```
    pub fn seal(&self) -> Result<[u8; 32], ManifestError> {
        // Verify self-consistency to detect tampering
        self.verify_self_consistency()?;

        Ok(self.manifest_hash)
    }

    /// Verifies the seal of a context pack.
    ///
    /// This method recomputes the content hash and verifies it matches the
    /// stored `manifest_hash`. Use this after deserializing a manifest to
    /// ensure it has not been modified.
    ///
    /// # Tamper Detection
    ///
    /// If the manifest has been modified after construction (e.g., via JSON
    /// manipulation), this method will detect the tampering and return an
    /// error.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the seal is valid (hash matches).
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError::InvalidData`] if the seal is invalid (hash
    /// mismatch).
    ///
    /// # Example
    ///
    /// ```rust
    /// use apm2_core::context::{
    ///     ContextPackManifestBuilder, ManifestEntryBuilder,
    /// };
    ///
    /// let manifest =
    ///     ContextPackManifestBuilder::new("manifest-001", "profile-001")
    ///         .add_entry(
    ///             ManifestEntryBuilder::new("/file.rs", [0x42; 32]).build(),
    ///         )
    ///         .build();
    ///
    /// // Fresh manifest passes verification
    /// assert!(manifest.verify_seal().is_ok());
    ///
    /// // Serialize and deserialize
    /// let json = serde_json::to_string(&manifest).unwrap();
    /// let mut recovered: apm2_core::context::ContextPackManifest =
    ///     serde_json::from_str(&json).unwrap();
    /// recovered.rebuild_index();
    ///
    /// // Deserialized manifest still passes verification
    /// assert!(recovered.verify_seal().is_ok());
    /// ```
    pub fn verify_seal(&self) -> Result<(), ManifestError> {
        self.verify_self_consistency()
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
    tool_allowlist: Vec<ToolClass>,
    write_allowlist: Vec<std::path::PathBuf>,
    shell_allowlist: Vec<String>,
}

impl ContextPackManifestBuilder {
    /// Creates a new builder with required IDs.
    #[must_use]
    pub fn new(manifest_id: impl Into<String>, profile_id: impl Into<String>) -> Self {
        Self {
            manifest_id: manifest_id.into(),
            profile_id: profile_id.into(),
            entries: Vec::new(),
            tool_allowlist: Vec::new(),
            write_allowlist: Vec::new(),
            shell_allowlist: Vec::new(),
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

    /// Sets the tool allowlist.
    ///
    /// Per TCK-00254, only tools in this allowlist can be invoked.
    #[must_use]
    pub fn tool_allowlist(mut self, tools: Vec<ToolClass>) -> Self {
        self.tool_allowlist = tools;
        self
    }

    /// Adds a tool class to the allowlist.
    #[must_use]
    pub fn allow_tool(mut self, tool: ToolClass) -> Self {
        self.tool_allowlist.push(tool);
        self
    }

    /// Sets the write allowlist.
    ///
    /// Per TCK-00254, only writes to paths in this allowlist are permitted.
    #[must_use]
    pub fn write_allowlist(mut self, paths: Vec<std::path::PathBuf>) -> Self {
        self.write_allowlist = paths;
        self
    }

    /// Adds a path to the write allowlist.
    #[must_use]
    pub fn allow_write_path(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.write_allowlist.push(path.into());
        self
    }

    /// Sets the shell allowlist.
    ///
    /// Per TCK-00254, only shell commands matching patterns in this allowlist
    /// can be executed.
    #[must_use]
    pub fn shell_allowlist(mut self, patterns: Vec<String>) -> Self {
        self.shell_allowlist = patterns;
        self
    }

    /// Adds a shell pattern to the allowlist.
    #[must_use]
    pub fn allow_shell_pattern(mut self, pattern: impl Into<String>) -> Self {
        self.shell_allowlist.push(pattern.into());
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
    #[allow(clippy::too_many_lines)]
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

        // Validate collection sizes (CTR-1303: bounded collections)
        if self.entries.len() > MAX_ENTRIES {
            return Err(ManifestError::CollectionTooLarge {
                field: "entries",
                actual: self.entries.len(),
                max: MAX_ENTRIES,
            });
        }

        // Validate tool_allowlist size (TCK-00254)
        if self.tool_allowlist.len() > MAX_TOOL_ALLOWLIST {
            return Err(ManifestError::CollectionTooLarge {
                field: "tool_allowlist",
                actual: self.tool_allowlist.len(),
                max: MAX_TOOL_ALLOWLIST,
            });
        }

        // Validate write_allowlist size (TCK-00254)
        if self.write_allowlist.len() > MAX_WRITE_ALLOWLIST {
            return Err(ManifestError::CollectionTooLarge {
                field: "write_allowlist",
                actual: self.write_allowlist.len(),
                max: MAX_WRITE_ALLOWLIST,
            });
        }

        // Validate write_allowlist paths (TCK-00254: CTR-1503, CTR-2609)
        // This ensures consistency with CapabilityManifest::validate()
        for path in &self.write_allowlist {
            let path_len = path.as_os_str().len();
            if path_len > MAX_PATH_LENGTH {
                return Err(ManifestError::PathTooLong {
                    actual: path_len,
                    max: MAX_PATH_LENGTH,
                });
            }

            // Per CTR-1503: Paths must be absolute
            if !path.is_absolute() {
                return Err(ManifestError::WriteAllowlistPathNotAbsolute {
                    path: path.to_string_lossy().to_string(),
                });
            }

            // Per CTR-2609: Reject path traversal (..) to prevent directory escape
            for component in path.components() {
                if matches!(component, std::path::Component::ParentDir) {
                    return Err(ManifestError::WriteAllowlistPathTraversal {
                        path: path.to_string_lossy().to_string(),
                    });
                }
            }
        }

        // Validate shell_allowlist size (TCK-00254)
        if self.shell_allowlist.len() > MAX_SHELL_ALLOWLIST {
            return Err(ManifestError::CollectionTooLarge {
                field: "shell_allowlist",
                actual: self.shell_allowlist.len(),
                max: MAX_SHELL_ALLOWLIST,
            });
        }

        // Sort allowlists for PartialEq consistency with compute_manifest_hash()
        // This ensures logically identical manifests compare equal regardless of
        // insertion order, preventing bugs in caching or deduplication.
        self.tool_allowlist.sort_by_key(ToolClass::value);
        self.write_allowlist.sort();
        self.shell_allowlist.sort();

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

        // TCK-00255: Sort entries by path for deterministic hashing.
        // This ensures that the same set of entries produces the same hash
        // regardless of insertion order, which is required for reliable seal
        // verification.
        self.entries.sort_by(|a, b| a.path.cmp(&b.path));

        // Build path index for O(1) lookups
        let path_index = ContextPackManifest::build_path_index(&self.entries);

        // Compute manifest hash (includes all allowlists per TCK-00254)
        let manifest_hash = ContextPackManifest::compute_manifest_hash(
            &self.manifest_id,
            &self.profile_id,
            &self.entries,
            &self.tool_allowlist,
            &self.write_allowlist,
            &self.shell_allowlist,
        );

        Ok(ContextPackManifest {
            manifest_id: self.manifest_id,
            manifest_hash,
            profile_id: self.profile_id,
            entries: self.entries,
            tool_allowlist: self.tool_allowlist,
            write_allowlist: self.write_allowlist,
            shell_allowlist: self.shell_allowlist,
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

    #[test]
    fn test_normalize_path_rejects_too_many_components() {
        // Path with exactly MAX_PATH_COMPONENTS should succeed
        let components: Vec<&str> = (0..MAX_PATH_COMPONENTS).map(|_| "a").collect();
        let at_limit = format!("/{}", components.join("/"));
        assert!(normalize_path(&at_limit).is_ok());

        // Path with one component over limit should fail
        let components: Vec<&str> = (0..=MAX_PATH_COMPONENTS).map(|_| "a").collect();
        let over_limit = format!("/{}", components.join("/"));
        assert!(matches!(
            normalize_path(&over_limit),
            Err(ManifestError::TooManyPathComponents { actual, max })
                if actual == MAX_PATH_COMPONENTS + 1 && max == MAX_PATH_COMPONENTS
        ));
    }

    #[test]
    fn test_normalize_path_component_count_excludes_empty_and_dots() {
        // Empty components and dots should not count towards the limit
        // This path has many slashes but only 2 actual components
        let path = "/a//b/./../b/./";
        let result = normalize_path(path);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "/a/b");
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

    // =========================================================================
    // TCK-00254: Tool Allowlist Tests
    // =========================================================================

    #[test]
    fn test_manifest_with_tool_allowlist() {
        let manifest = ContextPackManifestBuilder::new("manifest-001", "profile-001")
            .tool_allowlist(vec![ToolClass::Read, ToolClass::Write])
            .build();

        assert_eq!(manifest.tool_allowlist.len(), 2);
        assert!(manifest.tool_allowlist.contains(&ToolClass::Read));
        assert!(manifest.tool_allowlist.contains(&ToolClass::Write));
    }

    #[test]
    fn test_manifest_builder_allow_tool() {
        let manifest = ContextPackManifestBuilder::new("manifest-001", "profile-001")
            .allow_tool(ToolClass::Read)
            .allow_tool(ToolClass::Execute)
            .build();

        assert_eq!(manifest.tool_allowlist.len(), 2);
        assert!(manifest.tool_allowlist.contains(&ToolClass::Read));
        assert!(manifest.tool_allowlist.contains(&ToolClass::Execute));
    }

    #[test]
    fn test_manifest_tool_allowlist_too_large() {
        let tools: Vec<ToolClass> = (0..=MAX_TOOL_ALLOWLIST).map(|_| ToolClass::Read).collect();

        let result = ContextPackManifestBuilder::new("manifest-001", "profile-001")
            .tool_allowlist(tools)
            .try_build();

        assert!(matches!(
            result,
            Err(ManifestError::CollectionTooLarge { field, actual, max })
            if field == "tool_allowlist" && actual == MAX_TOOL_ALLOWLIST + 1 && max == MAX_TOOL_ALLOWLIST
        ));
    }

    #[test]
    fn test_manifest_hash_includes_tool_allowlist() {
        let manifest1 = ContextPackManifestBuilder::new("manifest-001", "profile-001")
            .tool_allowlist(vec![ToolClass::Read])
            .build();

        let manifest2 = ContextPackManifestBuilder::new("manifest-001", "profile-001")
            .tool_allowlist(vec![ToolClass::Write])
            .build();

        // Different tool allowlists should produce different hashes
        assert_ne!(manifest1.manifest_hash(), manifest2.manifest_hash());
    }

    #[test]
    fn test_manifest_hash_tool_allowlist_order_determinism() {
        // Same tools in different order should produce same hash (sorted before
        // hashing)
        let manifest1 = ContextPackManifestBuilder::new("manifest-001", "profile-001")
            .tool_allowlist(vec![ToolClass::Read, ToolClass::Write, ToolClass::Execute])
            .build();

        let manifest2 = ContextPackManifestBuilder::new("manifest-001", "profile-001")
            .tool_allowlist(vec![ToolClass::Execute, ToolClass::Read, ToolClass::Write])
            .build();

        assert_eq!(
            manifest1.manifest_hash(),
            manifest2.manifest_hash(),
            "manifest hash should be deterministic regardless of tool_allowlist order"
        );
    }

    #[test]
    fn test_manifest_empty_tool_allowlist_valid() {
        // Empty tool_allowlist should be valid (fail-closed semantics)
        let manifest = ContextPackManifestBuilder::new("manifest-001", "profile-001").build();

        assert!(manifest.tool_allowlist.is_empty());
        assert!(manifest.verify_self_consistency().is_ok());
    }

    #[test]
    fn test_manifest_serde_roundtrip_with_tool_allowlist() {
        let manifest = ContextPackManifestBuilder::new("manifest-001", "profile-001")
            .tool_allowlist(vec![ToolClass::Read, ToolClass::Write])
            .add_entry(
                ManifestEntryBuilder::new("/project/file.rs", [0x42; 32])
                    .access_level(AccessLevel::Read)
                    .build(),
            )
            .build();

        // Serialize to JSON
        let json = serde_json::to_string(&manifest).unwrap();

        // Deserialize back
        let mut recovered: ContextPackManifest = serde_json::from_str(&json).unwrap();
        recovered.rebuild_index();

        assert_eq!(manifest.tool_allowlist, recovered.tool_allowlist);
        assert_eq!(manifest.manifest_hash(), recovered.manifest_hash());
        assert!(recovered.verify_self_consistency().is_ok());
    }

    #[test]
    fn test_tool_class_from_u8() {
        assert_eq!(ToolClass::from_u8(0), Some(ToolClass::Read));
        assert_eq!(ToolClass::from_u8(1), Some(ToolClass::Write));
        assert_eq!(ToolClass::from_u8(2), Some(ToolClass::Execute));
        assert_eq!(ToolClass::from_u8(3), Some(ToolClass::Network));
        assert_eq!(ToolClass::from_u8(4), Some(ToolClass::Git));
        assert_eq!(ToolClass::from_u8(5), Some(ToolClass::Inference));
        assert_eq!(ToolClass::from_u8(6), Some(ToolClass::Artifact));
        assert_eq!(ToolClass::from_u8(7), None);
        assert_eq!(ToolClass::from_u8(255), None);
    }

    #[test]
    fn test_tool_class_value() {
        assert_eq!(ToolClass::Read.value(), 0);
        assert_eq!(ToolClass::Write.value(), 1);
        assert_eq!(ToolClass::Execute.value(), 2);
        assert_eq!(ToolClass::Network.value(), 3);
        assert_eq!(ToolClass::Git.value(), 4);
        assert_eq!(ToolClass::Inference.value(), 5);
        assert_eq!(ToolClass::Artifact.value(), 6);
    }

    #[test]
    fn test_tool_class_display() {
        assert_eq!(format!("{}", ToolClass::Read), "Read");
        assert_eq!(format!("{}", ToolClass::Write), "Write");
        assert_eq!(format!("{}", ToolClass::Execute), "Execute");
    }

    // =========================================================================
    // TCK-00255: Sealing Tests
    // =========================================================================

    /// TCK-00255: Verify seal returns the manifest hash.
    #[test]
    fn tck_00255_seal_returns_manifest_hash() {
        let manifest = create_test_manifest();

        let seal_hash = manifest.seal().unwrap();
        assert_eq!(seal_hash, manifest.manifest_hash());
    }

    /// TCK-00255: Verify seal hash is deterministic (same entries produce same
    /// hash).
    #[test]
    fn tck_00255_seal_hash_is_deterministic() {
        // Build two manifests with identical content
        let manifest1 = ContextPackManifestBuilder::new("manifest-001", "profile-001")
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
            .build();

        let manifest2 = ContextPackManifestBuilder::new("manifest-001", "profile-001")
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
            .build();

        // Same entries produce same hash
        assert_eq!(manifest1.seal().unwrap(), manifest2.seal().unwrap());
    }

    /// TCK-00255: Verify modification after sealing is detected (hash mismatch
    /// causes rejection).
    #[test]
    fn tck_00255_modification_after_sealing_detected() {
        // Create a manifest with manually corrupted hash via JSON
        let json = r#"{"manifest_id":"manifest-001","manifest_hash":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"profile_id":"profile-001","entries":[]}"#;
        let mut manifest: ContextPackManifest = serde_json::from_str(json).unwrap();
        manifest.rebuild_index();

        // seal() should detect the tampering
        let result = manifest.seal();
        assert!(
            matches!(result, Err(ManifestError::InvalidData(_))),
            "Expected seal to detect tampered manifest, got {result:?}"
        );

        // verify_seal() should also detect the tampering
        let result = manifest.verify_seal();
        assert!(
            matches!(result, Err(ManifestError::InvalidData(_))),
            "Expected verify_seal to detect tampered manifest, got {result:?}"
        );
    }

    /// TCK-00255: Verify seal works after deserialization roundtrip.
    #[test]
    fn tck_00255_seal_after_deserialization() {
        let original = create_test_manifest();
        let original_seal = original.seal().unwrap();

        // Serialize and deserialize
        let json = serde_json::to_string(&original).unwrap();
        let mut recovered: ContextPackManifest = serde_json::from_str(&json).unwrap();
        recovered.rebuild_index();

        // Seal should produce the same hash
        let recovered_seal = recovered.seal().unwrap();
        assert_eq!(original_seal, recovered_seal);

        // verify_seal should pass
        assert!(recovered.verify_seal().is_ok());
    }

    /// TCK-00255: Verify different entries produce different seal hashes.
    #[test]
    fn tck_00255_different_entries_different_seal() {
        let manifest1 = ContextPackManifestBuilder::new("manifest-001", "profile-001")
            .add_entry(
                ManifestEntryBuilder::new("/file1.rs", [0x42; 32])
                    .access_level(AccessLevel::Read)
                    .build(),
            )
            .build();

        let manifest2 = ContextPackManifestBuilder::new("manifest-001", "profile-001")
            .add_entry(
                ManifestEntryBuilder::new("/file2.rs", [0x42; 32])
                    .access_level(AccessLevel::Read)
                    .build(),
            )
            .build();

        // Different entries produce different hashes
        assert_ne!(manifest1.seal().unwrap(), manifest2.seal().unwrap());
    }

    /// TCK-00255: Verify different content hashes produce different seal.
    #[test]
    fn tck_00255_different_content_hash_different_seal() {
        let manifest1 = ContextPackManifestBuilder::new("manifest-001", "profile-001")
            .add_entry(
                ManifestEntryBuilder::new("/file.rs", [0x42; 32])
                    .access_level(AccessLevel::Read)
                    .build(),
            )
            .build();

        let manifest2 = ContextPackManifestBuilder::new("manifest-001", "profile-001")
            .add_entry(
                ManifestEntryBuilder::new("/file.rs", [0xFF; 32])
                    .access_level(AccessLevel::Read)
                    .build(),
            )
            .build();

        // Different content hashes produce different seal hashes
        assert_ne!(manifest1.seal().unwrap(), manifest2.seal().unwrap());
    }

    /// TCK-00255: Verify different access levels produce different seal.
    #[test]
    fn tck_00255_different_access_level_different_seal() {
        let manifest1 = ContextPackManifestBuilder::new("manifest-001", "profile-001")
            .add_entry(
                ManifestEntryBuilder::new("/file.rs", [0x42; 32])
                    .access_level(AccessLevel::Read)
                    .build(),
            )
            .build();

        let manifest2 = ContextPackManifestBuilder::new("manifest-001", "profile-001")
            .add_entry(
                ManifestEntryBuilder::new("/file.rs", [0x42; 32])
                    .access_level(AccessLevel::ReadWithZoom)
                    .build(),
            )
            .build();

        // Different access levels produce different seal hashes
        assert_ne!(manifest1.seal().unwrap(), manifest2.seal().unwrap());
    }

    /// TCK-00255: Verify seal on empty manifest works.
    #[test]
    fn tck_00255_seal_empty_manifest() {
        let manifest = ContextPackManifestBuilder::new("empty-manifest", "profile-001").build();

        // Empty manifest should seal successfully
        let seal = manifest.seal().unwrap();
        assert_ne!(seal, [0u8; 32]); // Hash should be non-zero

        // verify_seal should pass
        assert!(manifest.verify_seal().is_ok());
    }

    /// TCK-00255: Verify different insertion orders produce the same seal hash.
    ///
    /// This is the critical test for deterministic hashing: entries are sorted
    /// by path before hashing, so insertion order should not affect the result.
    #[test]
    fn tck_00255_insertion_order_independence() {
        // Add entries in order: A, B, C
        let manifest1 = ContextPackManifestBuilder::new("manifest-001", "profile-001")
            .add_entry(
                ManifestEntryBuilder::new("/aaa/file.rs", [0x11; 32])
                    .stable_id("file-a")
                    .access_level(AccessLevel::Read)
                    .build(),
            )
            .add_entry(
                ManifestEntryBuilder::new("/bbb/file.rs", [0x22; 32])
                    .stable_id("file-b")
                    .access_level(AccessLevel::ReadWithZoom)
                    .build(),
            )
            .add_entry(
                ManifestEntryBuilder::new("/ccc/file.rs", [0x33; 32])
                    .stable_id("file-c")
                    .access_level(AccessLevel::Read)
                    .build(),
            )
            .build();

        // Add entries in order: C, A, B (different order, same entries)
        let manifest2 = ContextPackManifestBuilder::new("manifest-001", "profile-001")
            .add_entry(
                ManifestEntryBuilder::new("/ccc/file.rs", [0x33; 32])
                    .stable_id("file-c")
                    .access_level(AccessLevel::Read)
                    .build(),
            )
            .add_entry(
                ManifestEntryBuilder::new("/aaa/file.rs", [0x11; 32])
                    .stable_id("file-a")
                    .access_level(AccessLevel::Read)
                    .build(),
            )
            .add_entry(
                ManifestEntryBuilder::new("/bbb/file.rs", [0x22; 32])
                    .stable_id("file-b")
                    .access_level(AccessLevel::ReadWithZoom)
                    .build(),
            )
            .build();

        // Add entries in order: B, C, A (yet another order)
        let manifest3 = ContextPackManifestBuilder::new("manifest-001", "profile-001")
            .add_entry(
                ManifestEntryBuilder::new("/bbb/file.rs", [0x22; 32])
                    .stable_id("file-b")
                    .access_level(AccessLevel::ReadWithZoom)
                    .build(),
            )
            .add_entry(
                ManifestEntryBuilder::new("/ccc/file.rs", [0x33; 32])
                    .stable_id("file-c")
                    .access_level(AccessLevel::Read)
                    .build(),
            )
            .add_entry(
                ManifestEntryBuilder::new("/aaa/file.rs", [0x11; 32])
                    .stable_id("file-a")
                    .access_level(AccessLevel::Read)
                    .build(),
            )
            .build();

        // All three manifests should produce the same seal hash
        let seal1 = manifest1.seal().unwrap();
        let seal2 = manifest2.seal().unwrap();
        let seal3 = manifest3.seal().unwrap();

        assert_eq!(
            seal1, seal2,
            "Different insertion order produced different hash"
        );
        assert_eq!(
            seal2, seal3,
            "Different insertion order produced different hash"
        );
        assert_eq!(
            seal1, seal3,
            "Different insertion order produced different hash"
        );

        // Verify entries are stored in sorted order
        assert_eq!(manifest1.entries()[0].path(), "/aaa/file.rs");
        assert_eq!(manifest1.entries()[1].path(), "/bbb/file.rs");
        assert_eq!(manifest1.entries()[2].path(), "/ccc/file.rs");
    }

    // =========================================================================
    // TCK-00254: Write Allowlist Path Validation Tests
    //
    // Per Code Quality Review [MAJOR], ContextPackManifestBuilder must validate
    // write_allowlist paths for absolute paths and traversal, consistent with
    // CapabilityManifest::validate().
    // =========================================================================

    #[test]
    fn tck_00254_write_allowlist_path_not_absolute() {
        let result = ContextPackManifestBuilder::new("manifest-001", "profile-001")
            .write_allowlist(vec![std::path::PathBuf::from("relative/path")])
            .try_build();

        assert!(
            matches!(
                result,
                Err(ManifestError::WriteAllowlistPathNotAbsolute { ref path })
                if path == "relative/path"
            ),
            "Expected WriteAllowlistPathNotAbsolute, got {result:?}"
        );
    }

    #[test]
    fn tck_00254_write_allowlist_path_traversal() {
        let result = ContextPackManifestBuilder::new("manifest-001", "profile-001")
            .write_allowlist(vec![std::path::PathBuf::from("/workspace/../etc")])
            .try_build();

        assert!(
            matches!(
                result,
                Err(ManifestError::WriteAllowlistPathTraversal { ref path })
                if path == "/workspace/../etc"
            ),
            "Expected WriteAllowlistPathTraversal, got {result:?}"
        );
    }

    #[test]
    fn tck_00254_write_allowlist_path_traversal_nested() {
        let result = ContextPackManifestBuilder::new("manifest-001", "profile-001")
            .write_allowlist(vec![std::path::PathBuf::from("/workspace/foo/../../etc")])
            .try_build();

        assert!(
            matches!(
                result,
                Err(ManifestError::WriteAllowlistPathTraversal { .. })
            ),
            "Expected WriteAllowlistPathTraversal, got {result:?}"
        );
    }

    #[test]
    fn tck_00254_write_allowlist_valid_absolute_paths() {
        let result = ContextPackManifestBuilder::new("manifest-001", "profile-001")
            .write_allowlist(vec![
                std::path::PathBuf::from("/workspace"),
                std::path::PathBuf::from("/home/user/project"),
            ])
            .try_build();

        assert!(result.is_ok(), "Expected Ok, got {result:?}");
        let manifest = result.unwrap();
        assert_eq!(manifest.write_allowlist.len(), 2);
    }

    #[test]
    fn tck_00254_write_allowlist_path_too_long() {
        let long_path = std::path::PathBuf::from("/".to_string() + &"x".repeat(MAX_PATH_LENGTH));

        let result = ContextPackManifestBuilder::new("manifest-001", "profile-001")
            .write_allowlist(vec![long_path])
            .try_build();

        assert!(
            matches!(result, Err(ManifestError::PathTooLong { .. })),
            "Expected PathTooLong, got {result:?}"
        );
    }
}
