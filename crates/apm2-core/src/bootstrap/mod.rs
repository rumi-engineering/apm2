//! Bootstrap schema bundle module.
//!
//! This module provides the embedded bootstrap schema bundle and runtime
//! verification functions. Bootstrap schemas form the foundational trust root
//! for the Context-as-Code (CAC) system.
//!
//! # Security Properties
//!
//! - **Embedded at build time**: Schemas are compiled into the binary via
//!   `include!`, preventing filesystem tampering
//! - **Hash verification**: Bundle integrity is verified at startup using
//!   BLAKE3 hashes
//! - **Immutable**: Bootstrap schemas cannot be patched or modified at runtime
//!
//! # Usage
//!
//! ```rust,no_run
//! use apm2_core::bootstrap::{
//!     BootstrapError, is_bootstrap_id, verify_bootstrap_hash,
//! };
//!
//! // Verify bootstrap integrity at startup
//! verify_bootstrap_hash()?;
//!
//! // Check if a stable ID is protected
//! assert!(is_bootstrap_id("bootstrap:common.v1"));
//! assert!(!is_bootstrap_id("dcp://org/my-schema"));
//! # Ok::<(), BootstrapError>(())
//! ```
//!
//! # Architecture
//!
//! The bootstrap bundle contains minimal schemas required for the CAC admission
//! pipeline:
//!
//! - `bootstrap:common.v1` - Common type definitions
//! - `bootstrap:envelope.v1` - Artifact envelope structure
//! - `bootstrap:patch_record.v1` - Patch record format
//! - `bootstrap:admission_receipt.v1` - Admission receipt format
//!
//! These schemas use the reserved `bootstrap:` prefix and cannot be modified
//! through normal CAC operations.

use std::collections::HashMap;
use std::sync::OnceLock;

use thiserror::Error;

use crate::crypto::{EventHasher, Hash};

// Include the generated manifest
include!(concat!(env!("OUT_DIR"), "/bootstrap_manifest.rs"));

/// The reserved prefix for bootstrap stable IDs.
pub const BOOTSTRAP_PREFIX: &str = "bootstrap:";

/// Errors that can occur during bootstrap operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BootstrapError {
    /// Bootstrap bundle hash verification failed.
    ///
    /// This indicates the binary may have been tampered with or there is
    /// a build inconsistency. The application should not proceed.
    #[error("bootstrap verification failed: expected hash {expected}, computed {actual}")]
    VerificationFailed {
        /// The expected bundle hash (from build time).
        expected: String,
        /// The computed bundle hash (at runtime).
        actual: String,
    },

    /// Schema content hash verification failed.
    ///
    /// This indicates the schema content does not match its expected hash,
    /// which could indicate binary tampering. The application should not
    /// proceed.
    #[error("schema content hash mismatch for {stable_id}: expected {expected}, computed {actual}")]
    ContentHashMismatch {
        /// The stable ID of the schema with mismatched content.
        stable_id: String,
        /// The expected content hash (stored in manifest).
        expected: String,
        /// The computed content hash (from actual content).
        actual: String,
    },

    /// Attempted to patch a protected bootstrap schema.
    ///
    /// Bootstrap schemas are immutable and cannot be modified through
    /// the normal patch pipeline.
    #[error("cannot patch bootstrap schema: {stable_id}")]
    BootstrapProtected {
        /// The stable ID that was targeted.
        stable_id: String,
    },

    /// A bootstrap schema was not found.
    #[error("bootstrap schema not found: {stable_id}")]
    SchemaNotFound {
        /// The requested stable ID.
        stable_id: String,
    },

    /// Failed to parse a bootstrap schema as JSON.
    #[error("invalid bootstrap schema JSON: {stable_id}: {message}")]
    InvalidSchemaJson {
        /// The schema's stable ID.
        stable_id: String,
        /// The parse error message.
        message: String,
    },
}

/// A bootstrap schema entry with its content and hash.
#[derive(Debug, Clone)]
pub struct BootstrapSchema {
    /// The stable ID (e.g., `bootstrap:common.v1`).
    pub stable_id: String,
    /// The raw JSON schema content.
    pub content: String,
    /// The BLAKE3 hash of the content.
    pub content_hash: Hash,
}

impl BootstrapSchema {
    /// Returns the content hash as a hex string with the `b3-256:` prefix.
    #[must_use]
    pub fn content_hash_hex(&self) -> String {
        format!("b3-256:{}", hex::encode(self.content_hash))
    }

    /// Parses the schema content as JSON.
    ///
    /// # Errors
    ///
    /// Returns [`BootstrapError::InvalidSchemaJson`] if parsing fails.
    pub fn parse_json(&self) -> Result<serde_json::Value, BootstrapError> {
        serde_json::from_str(&self.content).map_err(|e| BootstrapError::InvalidSchemaJson {
            stable_id: self.stable_id.clone(),
            message: e.to_string(),
        })
    }
}

/// Global cache for bootstrap schemas.
static BOOTSTRAP_CACHE: OnceLock<HashMap<String, BootstrapSchema>> = OnceLock::new();

/// Initializes and returns the bootstrap schema cache.
fn get_bootstrap_cache() -> &'static HashMap<String, BootstrapSchema> {
    BOOTSTRAP_CACHE.get_or_init(|| {
        let mut cache = HashMap::with_capacity(BOOTSTRAP_SCHEMA_COUNT);
        for &(stable_id, content, hash) in BOOTSTRAP_SCHEMAS {
            cache.insert(
                stable_id.to_string(),
                BootstrapSchema {
                    stable_id: stable_id.to_string(),
                    content: content.to_string(),
                    content_hash: hash,
                },
            );
        }
        cache
    })
}

/// Verifies the bootstrap bundle hash at runtime.
///
/// This function recomputes the bundle hash from the embedded schemas and
/// compares it to the expected hash generated at build time.
///
/// # Errors
///
/// Returns [`BootstrapError::VerificationFailed`] if the computed hash
/// does not match the expected hash.
///
/// # Security
///
/// This function should be called early in application startup before
/// processing any CAC artifacts. If verification fails, the application
/// should terminate immediately.
///
/// # Example
///
/// ```rust,no_run
/// use apm2_core::bootstrap::verify_bootstrap_hash;
///
/// fn main() {
///     if let Err(e) = verify_bootstrap_hash() {
///         eprintln!("CRITICAL: Bootstrap verification failed: {}", e);
///         std::process::exit(1);
///     }
///     // Continue with normal startup...
/// }
/// ```
pub fn verify_bootstrap_hash() -> Result<(), BootstrapError> {
    // First, verify each schema's content matches its stored hash.
    // This prevents binary tampering where content is modified in .rodata
    // without updating the hash.
    for &(stable_id, content, hash) in BOOTSTRAP_SCHEMAS {
        let computed_content_hash = EventHasher::hash_content(content.as_bytes());
        if computed_content_hash != hash {
            return Err(BootstrapError::ContentHashMismatch {
                stable_id: stable_id.to_string(),
                expected: hex::encode(hash),
                actual: hex::encode(computed_content_hash),
            });
        }
    }

    // Then verify the bundle hash (hash of all stable_ids and their hashes)
    let mut hasher = blake3::Hasher::new();
    for &(stable_id, _, hash) in BOOTSTRAP_SCHEMAS {
        hasher.update(stable_id.as_bytes());
        hasher.update(&hash);
    }
    let computed: [u8; 32] = *hasher.finalize().as_bytes();

    if computed != BOOTSTRAP_BUNDLE_HASH {
        return Err(BootstrapError::VerificationFailed {
            expected: hex::encode(BOOTSTRAP_BUNDLE_HASH),
            actual: hex::encode(computed),
        });
    }

    Ok(())
}

/// Checks if a stable ID is a protected bootstrap ID.
///
/// Bootstrap IDs use the reserved `bootstrap:` prefix and cannot be
/// modified through normal CAC operations.
///
/// # Examples
///
/// ```rust
/// use apm2_core::bootstrap::is_bootstrap_id;
///
/// assert!(is_bootstrap_id("bootstrap:common.v1"));
/// assert!(is_bootstrap_id("bootstrap:envelope.v1"));
/// assert!(!is_bootstrap_id("dcp://org/my-schema@v1"));
/// assert!(!is_bootstrap_id(""));
/// ```
#[must_use]
pub fn is_bootstrap_id(stable_id: &str) -> bool {
    stable_id.starts_with(BOOTSTRAP_PREFIX)
}

/// Validates that a patch target is not a protected bootstrap ID.
///
/// This function should be called in the admission pipeline before
/// processing any patch record.
///
/// # Errors
///
/// Returns [`BootstrapError::BootstrapProtected`] if the target stable ID
/// starts with the `bootstrap:` prefix.
///
/// # Example
///
/// ```rust
/// use apm2_core::bootstrap::{BootstrapError, reject_bootstrap_patch};
///
/// // Normal IDs are allowed
/// assert!(reject_bootstrap_patch("dcp://org/my-artifact@v1").is_ok());
///
/// // Bootstrap IDs are rejected
/// let result = reject_bootstrap_patch("bootstrap:common.v1");
/// assert!(matches!(
///     result,
///     Err(BootstrapError::BootstrapProtected { .. })
/// ));
/// ```
pub fn reject_bootstrap_patch(target_stable_id: &str) -> Result<(), BootstrapError> {
    if is_bootstrap_id(target_stable_id) {
        return Err(BootstrapError::BootstrapProtected {
            stable_id: target_stable_id.to_string(),
        });
    }
    Ok(())
}

/// Returns a bootstrap schema by its stable ID.
///
/// # Errors
///
/// Returns [`BootstrapError::SchemaNotFound`] if the stable ID is not
/// found in the bootstrap bundle.
///
/// # Example
///
/// ```rust,no_run
/// use apm2_core::bootstrap::get_bootstrap_schema;
///
/// let schema = get_bootstrap_schema("bootstrap:common.v1")?;
/// println!("Schema content: {}", schema.content);
/// # Ok::<(), apm2_core::bootstrap::BootstrapError>(())
/// ```
pub fn get_bootstrap_schema(stable_id: &str) -> Result<&'static BootstrapSchema, BootstrapError> {
    get_bootstrap_cache()
        .get(stable_id)
        .ok_or_else(|| BootstrapError::SchemaNotFound {
            stable_id: stable_id.to_string(),
        })
}

/// Returns all bootstrap schemas.
///
/// # Example
///
/// ```rust,no_run
/// use apm2_core::bootstrap::get_all_bootstrap_schemas;
///
/// for schema in get_all_bootstrap_schemas() {
///     println!("{}: {}", schema.stable_id, schema.content_hash_hex());
/// }
/// ```
pub fn get_all_bootstrap_schemas() -> impl Iterator<Item = &'static BootstrapSchema> {
    get_bootstrap_cache().values()
}

/// Returns the list of all bootstrap stable IDs.
///
/// # Example
///
/// ```rust,no_run
/// use apm2_core::bootstrap::get_bootstrap_stable_ids;
///
/// for id in get_bootstrap_stable_ids() {
///     println!("Bootstrap schema: {}", id);
/// }
/// ```
#[must_use]
pub const fn get_bootstrap_stable_ids() -> &'static [&'static str] {
    BOOTSTRAP_STABLE_IDS
}

/// Returns the expected bundle hash as a hex string.
///
/// This is the hash computed at build time and embedded in the binary.
#[must_use]
pub fn get_expected_bundle_hash() -> String {
    hex::encode(BOOTSTRAP_BUNDLE_HASH)
}

/// Verifies the content hash of a specific bootstrap schema.
///
/// This is useful for additional integrity checks beyond the bundle hash.
///
/// # Errors
///
/// Returns [`BootstrapError::VerificationFailed`] if the hash does not match,
/// or [`BootstrapError::SchemaNotFound`] if the schema is not found.
///
/// # Example
///
/// ```rust,no_run
/// use apm2_core::bootstrap::verify_schema_hash;
///
/// // This should always pass if verify_bootstrap_hash() passed
/// verify_schema_hash("bootstrap:common.v1")?;
/// # Ok::<(), apm2_core::bootstrap::BootstrapError>(())
/// ```
pub fn verify_schema_hash(stable_id: &str) -> Result<(), BootstrapError> {
    let schema = get_bootstrap_schema(stable_id)?;
    let computed = EventHasher::hash_content(schema.content.as_bytes());

    if computed != schema.content_hash {
        return Err(BootstrapError::VerificationFailed {
            expected: hex::encode(schema.content_hash),
            actual: hex::encode(computed),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Bootstrap Hash Verification Tests
    // =========================================================================

    #[test]
    fn test_verify_bootstrap_hash_succeeds() {
        // The hash should match since we're running the same code that generated it
        let result = verify_bootstrap_hash();
        assert!(result.is_ok(), "Bootstrap hash verification should succeed");
    }

    #[test]
    fn test_bootstrap_bundle_has_schemas() {
        // Verify we have the expected schemas
        // Use runtime check to avoid constant assertion warning
        let count = BOOTSTRAP_SCHEMA_COUNT;
        assert!(count > 0, "Bootstrap bundle should contain schemas");
        assert_eq!(
            BOOTSTRAP_SCHEMAS.len(),
            BOOTSTRAP_SCHEMA_COUNT,
            "Schema count should match array length"
        );
    }

    #[test]
    fn test_bootstrap_schemas_have_correct_prefix() {
        for &(stable_id, _, _) in BOOTSTRAP_SCHEMAS {
            assert!(
                stable_id.starts_with(BOOTSTRAP_PREFIX),
                "All bootstrap schemas should have '{BOOTSTRAP_PREFIX}' prefix: {stable_id}"
            );
        }
    }

    // =========================================================================
    // Bootstrap ID Detection Tests
    // =========================================================================

    #[test]
    fn test_is_bootstrap_id_positive() {
        assert!(is_bootstrap_id("bootstrap:common.v1"));
        assert!(is_bootstrap_id("bootstrap:envelope.v1"));
        assert!(is_bootstrap_id("bootstrap:patch_record.v1"));
        assert!(is_bootstrap_id("bootstrap:admission_receipt.v1"));
        assert!(is_bootstrap_id("bootstrap:anything"));
    }

    #[test]
    fn test_is_bootstrap_id_negative() {
        assert!(!is_bootstrap_id("dcp://org/schema@v1"));
        assert!(!is_bootstrap_id("cac.common.v1"));
        assert!(!is_bootstrap_id(""));
        assert!(!is_bootstrap_id("bootstrapfake:schema"));
        assert!(!is_bootstrap_id("BOOTSTRAP:schema"));
    }

    // =========================================================================
    // Patch Rejection Tests
    // =========================================================================

    #[test]
    fn test_reject_bootstrap_patch_allows_normal_ids() {
        let result = reject_bootstrap_patch("dcp://org/my-schema@v1");
        assert!(
            result.is_ok(),
            "Normal stable IDs should not be rejected: {result:?}"
        );

        let result = reject_bootstrap_patch("cac.artifact.envelope.v1");
        assert!(result.is_ok());
    }

    #[test]
    fn test_reject_bootstrap_patch_rejects_bootstrap_ids() {
        let result = reject_bootstrap_patch("bootstrap:common.v1");
        assert!(
            matches!(result, Err(BootstrapError::BootstrapProtected { .. })),
            "Bootstrap IDs should be rejected: {result:?}"
        );

        let result = reject_bootstrap_patch("bootstrap:anything");
        assert!(matches!(
            result,
            Err(BootstrapError::BootstrapProtected { .. })
        ));
    }

    #[test]
    fn test_bootstrap_protected_error_contains_stable_id() {
        let result = reject_bootstrap_patch("bootstrap:test.v1");
        match result {
            Err(BootstrapError::BootstrapProtected { stable_id }) => {
                assert_eq!(stable_id, "bootstrap:test.v1");
            },
            _ => panic!("Expected BootstrapProtected error"),
        }
    }

    // =========================================================================
    // Schema Retrieval Tests
    // =========================================================================

    #[test]
    fn test_get_bootstrap_schema_success() {
        // Get a known schema (using the key format from the generated manifest)
        let ids = get_bootstrap_stable_ids();
        if !ids.is_empty() {
            let result = get_bootstrap_schema(ids[0]);
            assert!(result.is_ok(), "Should find existing schema: {result:?}");

            let schema = result.unwrap();
            assert!(
                !schema.content.is_empty(),
                "Schema content should not be empty"
            );
            assert!(
                !schema.content_hash.iter().all(|&b| b == 0),
                "Hash should not be all zeros"
            );
        }
    }

    #[test]
    fn test_get_bootstrap_schema_not_found() {
        let result = get_bootstrap_schema("bootstrap:nonexistent.v99");
        assert!(
            matches!(result, Err(BootstrapError::SchemaNotFound { .. })),
            "Non-existent schema should return SchemaNotFound: {result:?}"
        );
    }

    #[test]
    fn test_get_all_bootstrap_schemas() {
        assert_eq!(
            get_all_bootstrap_schemas().count(),
            BOOTSTRAP_SCHEMA_COUNT,
            "Should return all schemas"
        );
    }

    #[test]
    fn test_get_bootstrap_stable_ids() {
        let ids = get_bootstrap_stable_ids();
        assert_eq!(ids.len(), BOOTSTRAP_SCHEMA_COUNT, "Should return all IDs");
    }

    // =========================================================================
    // Schema Content Validation Tests
    // =========================================================================

    #[test]
    fn test_bootstrap_schemas_are_valid_json() {
        for schema in get_all_bootstrap_schemas() {
            let result = schema.parse_json();
            assert!(
                result.is_ok(),
                "Schema {} should be valid JSON: {result:?}",
                schema.stable_id
            );
        }
    }

    #[test]
    fn test_verify_individual_schema_hash() {
        for id in get_bootstrap_stable_ids() {
            let result = verify_schema_hash(id);
            assert!(result.is_ok(), "Schema {id} hash should verify: {result:?}");
        }
    }

    #[test]
    fn test_content_hash_hex_format() {
        for schema in get_all_bootstrap_schemas() {
            let hash_hex = schema.content_hash_hex();
            assert!(
                hash_hex.starts_with("b3-256:"),
                "Hash should have b3-256: prefix"
            );
            assert_eq!(
                hash_hex.len(),
                "b3-256:".len() + 64,
                "Hash should be 64 hex chars after prefix"
            );
        }
    }

    // =========================================================================
    // Error Display Tests
    // =========================================================================

    #[test]
    fn test_error_display_verification_failed() {
        let err = BootstrapError::VerificationFailed {
            expected: "abc123".to_string(),
            actual: "def456".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("abc123"));
        assert!(msg.contains("def456"));
        assert!(msg.contains("verification failed"));
    }

    #[test]
    fn test_error_display_bootstrap_protected() {
        let err = BootstrapError::BootstrapProtected {
            stable_id: "bootstrap:test.v1".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("bootstrap:test.v1"));
        assert!(msg.contains("cannot patch"));
    }

    #[test]
    fn test_error_display_schema_not_found() {
        let err = BootstrapError::SchemaNotFound {
            stable_id: "bootstrap:missing.v1".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("bootstrap:missing.v1"));
        assert!(msg.contains("not found"));
    }

    // =========================================================================
    // Integration Tests
    // =========================================================================

    /// Main bootstrap integrity test as specified in Definition of Done.
    /// Tests: `cargo test bootstrap_integrity`
    #[test]
    fn bootstrap_integrity() {
        // 1. Verify bundle hash at startup
        verify_bootstrap_hash().expect("Bundle hash should verify");

        // 2. Verify all schemas are valid JSON
        for schema in get_all_bootstrap_schemas() {
            schema.parse_json().expect("Schema should be valid JSON");
        }

        // 3. Verify individual schema hashes
        for id in get_bootstrap_stable_ids() {
            verify_schema_hash(id).expect("Schema hash should verify");
        }

        // 4. Verify patch rejection for bootstrap IDs
        for id in get_bootstrap_stable_ids() {
            let result = reject_bootstrap_patch(id);
            assert!(
                matches!(result, Err(BootstrapError::BootstrapProtected { .. })),
                "Bootstrap ID should be protected: {id}"
            );
        }

        // 5. Verify normal IDs are not rejected
        reject_bootstrap_patch("dcp://org/my-schema@v1").expect("Normal ID should pass");
    }

    #[test]
    fn test_bootstrap_integrity_full_flow() {
        // 1. Verify bundle hash
        verify_bootstrap_hash().expect("Bundle hash should verify");

        // 2. Get all schemas
        let schemas: Vec<_> = get_all_bootstrap_schemas().collect();
        assert!(!schemas.is_empty(), "Should have schemas");

        // 3. Verify each schema individually
        for schema in &schemas {
            // Parse as JSON
            let json = schema.parse_json().expect("Should parse as JSON");
            assert!(json.is_object(), "Schema should be a JSON object");

            // Verify content hash
            verify_schema_hash(&schema.stable_id).expect("Individual hash should verify");
        }

        // 4. Test patch rejection
        for schema in &schemas {
            let result = reject_bootstrap_patch(&schema.stable_id);
            assert!(
                matches!(result, Err(BootstrapError::BootstrapProtected { .. })),
                "Should reject patch to bootstrap schema"
            );
        }
    }
}
