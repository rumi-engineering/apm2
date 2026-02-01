//! Context module for file access control.
//!
//! This module provides types for managing context pack manifests, which define
//! the OCAP (Object-Capability) allowlist for file reads, and the context
//! firewall middleware that enforces access control.
//!
//! # Components
//!
//! - [`ContextPackManifest`]: Defines which files are allowed to be read
//! - [`ManifestEntry`]: Individual file entry with path and content hash
//! - [`ManifestEntryBuilder`]: Builder for constructing manifest entries
//! - [`AccessLevel`]: Read or `ReadWithZoom` access levels
//! - [`firewall::ContextAwareValidator`]: Trait for context-aware validation
//! - [`firewall::DefaultContextFirewall`]: Default implementation of the
//!   firewall
//! - [`firewall::FirewallMode`]: Enforcement mode (Warn, `SoftFail`,
//!   `HardFail`)
//!
//! # Sealing (TCK-00255)
//!
//! Context packs are sealed after construction to ensure integrity. The seal
//! is a BLAKE3 hash over all manifest content that:
//!
//! - Is deterministic: same entries always produce the same hash
//! - Is tamper-evident: any modification changes the hash
//! - Is verifiable: [`ContextPackManifest::verify_seal`] detects tampering
//!
//! Use [`ContextPackManifest::seal`] in the Work Claim flow to get the content
//! hash for the `ClaimWorkResponse.context_pack_hash` field.
//!
//! # Security Model
//!
//! The context firewall uses manifests as allowlists:
//!
//! 1. Only files explicitly listed can be read
//! 2. Content hashes prevent TOCTOU (time-of-check-to-time-of-use) attacks
//! 3. All reads outside the allowlist are denied
//! 4. Path normalization prevents traversal attacks
//! 5. [`firewall::FirewallDecision`] events are emitted for audit logging
//!
//! # Firewall Modes
//!
//! - **Warn**: Log warning, allow read (for monitoring/debugging)
//! - **`SoftFail`**: Return error, allow retry (default for graceful handling)
//! - **`HardFail`**: Return error, terminate session (strict enforcement)
//!
//! # Example
//!
//! ```rust
//! use apm2_core::context::firewall::{
//!     ContextAwareValidator, DefaultContextFirewall, FirewallMode,
//! };
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
//! // Create firewall with SoftFail mode
//! let firewall =
//!     DefaultContextFirewall::new(&manifest, FirewallMode::SoftFail);
//!
//! // Validate reads through the firewall
//! let result = firewall.validate_read("/project/src/main.rs", None);
//! assert!(result.is_ok());
//!
//! // Denied reads return errors in SoftFail mode
//! let result = firewall.validate_read("/etc/passwd", None);
//! assert!(result.is_err());
//! ```

pub mod firewall;
mod manifest;

pub use manifest::{
    AccessLevel, ContextPackManifest, ContextPackManifestBuilder, MAX_ENTRIES, MAX_PATH_COMPONENTS,
    MAX_PATH_LENGTH, MAX_TOOL_ALLOWLIST, MAX_TOOL_CLASS_NAME_LEN, ManifestEntry,
    ManifestEntryBuilder, ManifestError, ToolClass, normalize_path,
};
