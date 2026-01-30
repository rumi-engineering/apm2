//! Context module for file access control.
//!
//! This module provides types for managing context pack manifests, which define
//! the OCAP (Object-Capability) allowlist for file reads.
//!
//! # Components
//!
//! - [`ContextPackManifest`]: Defines which files are allowed to be read
//! - [`ManifestEntry`]: Individual file entry with path and content hash
//! - [`ManifestEntryBuilder`]: Builder for constructing manifest entries
//! - [`AccessLevel`]: Read or `ReadWithZoom` access levels
//!
//! # Security Model
//!
//! The context firewall uses manifests as allowlists:
//!
//! 1. Only files explicitly listed can be read
//! 2. Content hashes prevent TOCTOU (time-of-check-to-time-of-use) attacks
//! 3. All reads outside the allowlist are denied
//! 4. Path normalization prevents traversal attacks
//!
//! # Example
//!
//! ```rust
//! use apm2_core::context::{
//!     AccessLevel, ContextPackManifest, ContextPackManifestBuilder,
//!     ManifestEntryBuilder,
//! };
//!
//! let manifest =
//!     ContextPackManifestBuilder::new("manifest-001", "profile-001")
//!         .add_entry(
//!             ManifestEntryBuilder::new("/project/src/main.rs", [0x42; 32])
//!                 .stable_id("main")
//!                 .access_level(AccessLevel::Read)
//!                 .build(),
//!         )
//!         .build();
//!
//! // Check if access is allowed (hash optional for Read access level)
//! if manifest.is_allowed("/project/src/main.rs", None).unwrap() {
//!     println!("Access granted");
//! }
//! ```

mod manifest;

pub use manifest::{
    AccessLevel, ContextPackManifest, ContextPackManifestBuilder, MAX_ENTRIES, MAX_PATH_LENGTH,
    ManifestEntry, ManifestEntryBuilder, ManifestError, normalize_path,
};
