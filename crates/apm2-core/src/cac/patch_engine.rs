//! CAC Patch Engine with replay protection.
//!
//! This module provides patch application for CAC (Context-as-Code) artifacts
//! with built-in replay protection via expected base hash validation.
//!
//! # Supported Patch Formats
//!
//! - **JSON Patch (RFC 6902)**: Fine-grained operations (add, remove, replace,
//!   move, copy, test)
//! - **Merge Patch (RFC 7396)**: Document-level merge with null handling for
//!   deletions
//!
//! # Replay Protection
//!
//! All patch operations require an `expected_base_hash` parameter. Before
//! applying a patch, the engine computes the hash of the current document
//! (after canonicalization) and compares it to the expected hash. If they
//! don't match, a [`ReplayViolation`] is emitted and the patch is rejected.
//!
//! This prevents stale overwrites where concurrent modifications would be lost.
//!
//! # Pipeline
//!
//! 1. Validate `expected_base_hash` matches current document hash
//! 2. Apply patch (JSON Patch or Merge Patch)
//! 3. Canonicalize output (CAC-JSON format)
//! 4. Compute new content hash
//! 5. Return [`PatchResult`] with hash chain
//!
//! # Example
//!
//! ```
//! use apm2_core::cac::patch_engine::{PatchEngine, PatchEngineError};
//! use serde_json::json;
//!
//! let engine = PatchEngine::new();
//!
//! // Original document
//! let document = json!({"name": "test", "version": 1});
//!
//! // JSON Patch to update version
//! let patch = json!([
//!     {"op": "replace", "path": "/version", "value": 2}
//! ]);
//!
//! // Compute base hash (normally from previous operation)
//! let base_hash = engine.compute_hash(&document).unwrap();
//!
//! // Apply patch with replay protection
//! let result = engine.apply_json_patch(&document, &patch, &base_hash).unwrap();
//!
//! assert_eq!(result.old_hash, base_hash);
//! assert_ne!(result.new_hash, result.old_hash);
//! assert!(result.patched_document["version"] == 2);
//! ```

use blake3::Hasher;
use serde_json::Value;
use thiserror::Error;

use crate::determinism::{CacJsonError, canonicalize_json};

/// Errors that can occur during patch operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PatchEngineError {
    /// The expected base hash does not match the actual document hash.
    ///
    /// This indicates a replay violation - another modification occurred
    /// between reading the document and submitting the patch.
    #[error("replay violation: expected base hash '{expected}' but document has hash '{actual}'")]
    ReplayViolation {
        /// The expected hash provided with the patch request.
        expected: String,
        /// The actual hash of the current document.
        actual: String,
    },

    /// JSON Patch operation failed.
    #[error("json patch failed: {message}")]
    JsonPatchFailed {
        /// Description of the patch failure.
        message: String,
    },

    /// Merge Patch operation failed.
    #[error("merge patch failed: {message}")]
    MergePatchFailed {
        /// Description of the merge failure.
        message: String,
    },

    /// CAC-JSON canonicalization failed.
    #[error("canonicalization failed: {0}")]
    CanonicalizationFailed(#[from] CacJsonError),

    /// JSON serialization failed.
    #[error("serialization failed: {message}")]
    SerializationFailed {
        /// Description of the serialization error.
        message: String,
    },

    /// The patch document is invalid.
    #[error("invalid patch: {message}")]
    InvalidPatch {
        /// Description of the patch validation error.
        message: String,
    },
}

/// Result of a successful patch operation.
///
/// Contains the hash chain linking the old document state to the new state,
/// along with the patched document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchResult {
    /// BLAKE3 hash of the original document (before patching).
    pub old_hash: String,

    /// BLAKE3 hash of the patched document (after canonicalization).
    pub new_hash: String,

    /// BLAKE3 hash of the patch document itself.
    pub patch_hash: String,

    /// The patched document (canonicalized).
    pub patched_document: Value,

    /// Canonical JSON representation of the patched document.
    pub canonical_output: String,
}

/// Replay violation event for audit logging.
///
/// Emitted when a patch is rejected due to hash mismatch, indicating
/// a potential concurrent modification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayViolation {
    /// Hash that was expected by the patch submitter.
    pub expected_hash: String,

    /// Actual hash of the document at patch time.
    pub actual_hash: String,

    /// Type of patch that was attempted.
    pub patch_type: PatchType,

    /// BLAKE3 hash of the rejected patch.
    pub patch_hash: String,
}

/// Type of patch operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchType {
    /// JSON Patch (RFC 6902).
    JsonPatch,

    /// Merge Patch (RFC 7396).
    MergePatch,
}

impl std::fmt::Display for PatchType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::JsonPatch => write!(f, "JSON Patch (RFC 6902)"),
            Self::MergePatch => write!(f, "Merge Patch (RFC 7396)"),
        }
    }
}

/// CAC Patch Engine with replay protection.
///
/// The engine ensures all patch operations maintain the CAC invariants:
/// - Output is always canonicalized CAC-JSON
/// - Replay protection via expected base hash validation
/// - Hash chain linking old state to new state
///
/// # Thread Safety
///
/// `PatchEngine` is stateless and can be safely shared across threads.
#[derive(Debug, Clone, Default)]
pub struct PatchEngine {
    // Stateless - all state is passed as parameters
}

impl PatchEngine {
    /// Creates a new `PatchEngine`.
    #[must_use]
    pub const fn new() -> Self {
        Self {}
    }

    /// Computes the BLAKE3 hash of a JSON document.
    ///
    /// The document is first canonicalized to CAC-JSON format, then hashed.
    /// This ensures deterministic hashing regardless of whitespace or key
    /// order.
    ///
    /// # Arguments
    ///
    /// * `document` - The JSON document to hash
    ///
    /// # Returns
    ///
    /// Hex-encoded BLAKE3 hash of the canonicalized document.
    ///
    /// # Errors
    ///
    /// Returns [`PatchEngineError::CanonicalizationFailed`] if the document
    /// cannot be canonicalized (e.g., contains floats or non-NFC strings).
    pub fn compute_hash(&self, document: &Value) -> Result<String, PatchEngineError> {
        let json_str =
            serde_json::to_string(document).map_err(|e| PatchEngineError::SerializationFailed {
                message: e.to_string(),
            })?;

        let canonical = canonicalize_json(&json_str)?;
        Ok(Self::hash_bytes(canonical.as_bytes()))
    }

    /// Applies a JSON Patch (RFC 6902) to a document with replay protection.
    ///
    /// JSON Patch supports fine-grained operations:
    /// - `add`: Insert a value at a path
    /// - `remove`: Delete a value at a path
    /// - `replace`: Replace a value at a path
    /// - `move`: Move a value from one path to another
    /// - `copy`: Copy a value from one path to another
    /// - `test`: Verify a value equals expected (fails if not)
    ///
    /// # Arguments
    ///
    /// * `document` - The document to patch
    /// * `patch` - JSON Patch array per RFC 6902
    /// * `expected_base_hash` - Expected hash of the current document
    ///
    /// # Returns
    ///
    /// [`PatchResult`] containing the patched document and hash chain.
    ///
    /// # Errors
    ///
    /// - [`PatchEngineError::ReplayViolation`] if hash mismatch
    /// - [`PatchEngineError::InvalidPatch`] if patch is not a valid array
    /// - [`PatchEngineError::JsonPatchFailed`] if patch operation fails
    /// - [`PatchEngineError::CanonicalizationFailed`] if output cannot be
    ///   canonicalized
    ///
    /// # Example
    ///
    /// ```
    /// use apm2_core::cac::patch_engine::PatchEngine;
    /// use serde_json::json;
    ///
    /// let engine = PatchEngine::new();
    /// let doc = json!({"items": [1, 2, 3]});
    /// let patch = json!([
    ///     {"op": "add", "path": "/items/-", "value": 4}
    /// ]);
    ///
    /// let base_hash = engine.compute_hash(&doc).unwrap();
    /// let result = engine.apply_json_patch(&doc, &patch, &base_hash).unwrap();
    ///
    /// assert_eq!(result.patched_document["items"], json!([1, 2, 3, 4]));
    /// ```
    pub fn apply_json_patch(
        &self,
        document: &Value,
        patch: &Value,
        expected_base_hash: &str,
    ) -> Result<PatchResult, PatchEngineError> {
        // Validate replay protection
        let actual_hash = self.compute_hash(document)?;
        if actual_hash != expected_base_hash {
            return Err(PatchEngineError::ReplayViolation {
                expected: expected_base_hash.to_string(),
                actual: actual_hash,
            });
        }

        // Validate patch is an array
        if !patch.is_array() {
            return Err(PatchEngineError::InvalidPatch {
                message: "JSON Patch must be an array of operations".to_string(),
            });
        }

        // Parse patch operations
        let patch_ops: json_patch::Patch =
            serde_json::from_value(patch.clone()).map_err(|e| PatchEngineError::InvalidPatch {
                message: format!("invalid JSON Patch format: {e}"),
            })?;

        // Apply patch to a clone
        let mut patched = document.clone();
        json_patch::patch(&mut patched, &patch_ops).map_err(|e| {
            PatchEngineError::JsonPatchFailed {
                message: e.to_string(),
            }
        })?;

        // Canonicalize and compute hashes
        Self::finalize_patch(&patched, patch, actual_hash)
    }

    /// Applies a Merge Patch (RFC 7396) to a document with replay protection.
    ///
    /// Merge Patch uses a simple merging algorithm:
    /// - Object values are merged recursively
    /// - `null` values remove the corresponding key
    /// - All other values replace the target
    ///
    /// # Arguments
    ///
    /// * `document` - The document to patch
    /// * `patch` - Merge Patch document per RFC 7396
    /// * `expected_base_hash` - Expected hash of the current document
    ///
    /// # Returns
    ///
    /// [`PatchResult`] containing the patched document and hash chain.
    ///
    /// # Errors
    ///
    /// - [`PatchEngineError::ReplayViolation`] if hash mismatch
    /// - [`PatchEngineError::MergePatchFailed`] if merge operation fails
    /// - [`PatchEngineError::CanonicalizationFailed`] if output cannot be
    ///   canonicalized
    ///
    /// # Example
    ///
    /// ```
    /// use apm2_core::cac::patch_engine::PatchEngine;
    /// use serde_json::json;
    ///
    /// let engine = PatchEngine::new();
    /// let doc = json!({"name": "test", "obsolete": true});
    /// let patch = json!({
    ///     "name": "updated",
    ///     "obsolete": null  // Removes the field
    /// });
    ///
    /// let base_hash = engine.compute_hash(&doc).unwrap();
    /// let result = engine.apply_merge_patch(&doc, &patch, &base_hash).unwrap();
    ///
    /// assert_eq!(result.patched_document, json!({"name": "updated"}));
    /// ```
    pub fn apply_merge_patch(
        &self,
        document: &Value,
        patch: &Value,
        expected_base_hash: &str,
    ) -> Result<PatchResult, PatchEngineError> {
        // Validate replay protection
        let actual_hash = self.compute_hash(document)?;
        if actual_hash != expected_base_hash {
            return Err(PatchEngineError::ReplayViolation {
                expected: expected_base_hash.to_string(),
                actual: actual_hash,
            });
        }

        // Apply merge patch to a clone
        let mut patched = document.clone();
        json_patch::merge(&mut patched, patch);

        // Canonicalize and compute hashes
        Self::finalize_patch(&patched, patch, actual_hash)
    }

    /// Creates a [`ReplayViolation`] event for audit logging.
    ///
    /// Call this when a patch is rejected due to hash mismatch.
    ///
    /// # Arguments
    ///
    /// * `expected_hash` - The hash that was expected
    /// * `actual_hash` - The actual document hash
    /// * `patch` - The patch that was rejected
    /// * `patch_type` - Type of patch operation
    ///
    /// # Returns
    ///
    /// A [`ReplayViolation`] event suitable for audit logging.
    #[must_use]
    pub fn create_replay_violation(
        expected_hash: &str,
        actual_hash: &str,
        patch: &Value,
        patch_type: PatchType,
    ) -> ReplayViolation {
        let patch_str = serde_json::to_string(patch).unwrap_or_default();
        let patch_hash = Self::hash_bytes(patch_str.as_bytes());

        ReplayViolation {
            expected_hash: expected_hash.to_string(),
            actual_hash: actual_hash.to_string(),
            patch_type,
            patch_hash,
        }
    }

    /// Finalizes a patch by canonicalizing output and computing hashes.
    fn finalize_patch(
        patched: &Value,
        patch: &Value,
        old_hash: String,
    ) -> Result<PatchResult, PatchEngineError> {
        // Serialize patched document
        let patched_str =
            serde_json::to_string(patched).map_err(|e| PatchEngineError::SerializationFailed {
                message: e.to_string(),
            })?;

        // Canonicalize output
        let canonical_output = canonicalize_json(&patched_str)?;

        // Compute new hash from canonical output
        let new_hash = Self::hash_bytes(canonical_output.as_bytes());

        // Compute patch hash
        let patch_str =
            serde_json::to_string(patch).map_err(|e| PatchEngineError::SerializationFailed {
                message: e.to_string(),
            })?;
        let patch_hash = Self::hash_bytes(patch_str.as_bytes());

        // Parse canonical output back to Value for return
        let canonical_value: Value = serde_json::from_str(&canonical_output).map_err(|e| {
            PatchEngineError::SerializationFailed {
                message: format!("failed to parse canonical output: {e}"),
            }
        })?;

        Ok(PatchResult {
            old_hash,
            new_hash,
            patch_hash,
            patched_document: canonical_value,
            canonical_output,
        })
    }

    /// Computes BLAKE3 hash of bytes, returning hex-encoded string.
    fn hash_bytes(data: &[u8]) -> String {
        let mut hasher = Hasher::new();
        hasher.update(data);
        hasher.finalize().to_hex().to_string()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    // =========================================================================
    // PatchEngine Construction
    // =========================================================================

    #[test]
    fn test_patch_engine_new() {
        let engine = PatchEngine::new();
        // Should be able to use the engine
        let result = engine.compute_hash(&json!({"a": 1}));
        assert!(result.is_ok());
    }

    #[test]
    fn test_patch_engine_default() {
        let engine = PatchEngine::default();
        let result = engine.compute_hash(&json!({"a": 1}));
        assert!(result.is_ok());
    }

    // =========================================================================
    // Hash Computation Tests
    // =========================================================================

    #[test]
    fn test_compute_hash_deterministic() {
        let engine = PatchEngine::new();

        // Different key orders should produce same hash
        let doc1 = json!({"z": 1, "a": 2});
        let doc2 = json!({"a": 2, "z": 1});

        let hash1 = engine.compute_hash(&doc1).unwrap();
        let hash2 = engine.compute_hash(&doc2).unwrap();

        assert_eq!(hash1, hash2, "Equivalent documents should have same hash");
    }

    #[test]
    fn test_compute_hash_different_documents() {
        let engine = PatchEngine::new();

        let doc1 = json!({"value": 1});
        let doc2 = json!({"value": 2});

        let hash1 = engine.compute_hash(&doc1).unwrap();
        let hash2 = engine.compute_hash(&doc2).unwrap();

        assert_ne!(
            hash1, hash2,
            "Different documents should have different hashes"
        );
    }

    #[test]
    fn test_compute_hash_rejects_floats() {
        let engine = PatchEngine::new();

        let doc = json!({"value": 1.5});
        let result = engine.compute_hash(&doc);

        assert!(matches!(
            result,
            Err(PatchEngineError::CanonicalizationFailed(
                CacJsonError::FloatNotAllowed
            ))
        ));
    }

    // =========================================================================
    // JSON Patch (RFC 6902) Tests
    // =========================================================================

    #[test]
    fn test_json_patch_add() {
        let engine = PatchEngine::new();
        let doc = json!({"items": []});
        let patch = json!([{"op": "add", "path": "/items/-", "value": 1}]);

        let base_hash = engine.compute_hash(&doc).unwrap();
        let result = engine.apply_json_patch(&doc, &patch, &base_hash).unwrap();

        assert_eq!(result.patched_document["items"], json!([1]));
        assert_eq!(result.old_hash, base_hash);
        assert_ne!(result.new_hash, result.old_hash);
    }

    #[test]
    fn test_json_patch_remove() {
        let engine = PatchEngine::new();
        let doc = json!({"name": "test", "obsolete": true});
        let patch = json!([{"op": "remove", "path": "/obsolete"}]);

        let base_hash = engine.compute_hash(&doc).unwrap();
        let result = engine.apply_json_patch(&doc, &patch, &base_hash).unwrap();

        assert_eq!(result.patched_document, json!({"name": "test"}));
    }

    #[test]
    fn test_json_patch_replace() {
        let engine = PatchEngine::new();
        let doc = json!({"version": 1});
        let patch = json!([{"op": "replace", "path": "/version", "value": 2}]);

        let base_hash = engine.compute_hash(&doc).unwrap();
        let result = engine.apply_json_patch(&doc, &patch, &base_hash).unwrap();

        assert_eq!(result.patched_document["version"], 2);
    }

    #[test]
    fn test_json_patch_move() {
        let engine = PatchEngine::new();
        let doc = json!({"source": {"value": 42}, "target": {}});
        let patch = json!([{"op": "move", "from": "/source/value", "path": "/target/value"}]);

        let base_hash = engine.compute_hash(&doc).unwrap();
        let result = engine.apply_json_patch(&doc, &patch, &base_hash).unwrap();

        assert_eq!(result.patched_document["target"]["value"], 42);
        assert!(result.patched_document["source"].get("value").is_none());
    }

    #[test]
    fn test_json_patch_copy() {
        let engine = PatchEngine::new();
        let doc = json!({"source": {"value": 42}, "target": {}});
        let patch = json!([{"op": "copy", "from": "/source/value", "path": "/target/value"}]);

        let base_hash = engine.compute_hash(&doc).unwrap();
        let result = engine.apply_json_patch(&doc, &patch, &base_hash).unwrap();

        assert_eq!(result.patched_document["source"]["value"], 42);
        assert_eq!(result.patched_document["target"]["value"], 42);
    }

    #[test]
    fn test_json_patch_test_success() {
        let engine = PatchEngine::new();
        let doc = json!({"version": 1});
        let patch = json!([
            {"op": "test", "path": "/version", "value": 1},
            {"op": "replace", "path": "/version", "value": 2}
        ]);

        let base_hash = engine.compute_hash(&doc).unwrap();
        let result = engine.apply_json_patch(&doc, &patch, &base_hash).unwrap();

        assert_eq!(result.patched_document["version"], 2);
    }

    #[test]
    fn test_json_patch_test_failure() {
        let engine = PatchEngine::new();
        let doc = json!({"version": 1});
        let patch = json!([
            {"op": "test", "path": "/version", "value": 99},
            {"op": "replace", "path": "/version", "value": 2}
        ]);

        let base_hash = engine.compute_hash(&doc).unwrap();
        let result = engine.apply_json_patch(&doc, &patch, &base_hash);

        assert!(matches!(
            result,
            Err(PatchEngineError::JsonPatchFailed { .. })
        ));
    }

    #[test]
    fn test_json_patch_multiple_operations() {
        let engine = PatchEngine::new();
        let doc = json!({"name": "test", "version": 1});
        let patch = json!([
            {"op": "replace", "path": "/name", "value": "updated"},
            {"op": "replace", "path": "/version", "value": 2},
            {"op": "add", "path": "/new_field", "value": true}
        ]);

        let base_hash = engine.compute_hash(&doc).unwrap();
        let result = engine.apply_json_patch(&doc, &patch, &base_hash).unwrap();

        assert_eq!(result.patched_document["name"], "updated");
        assert_eq!(result.patched_document["version"], 2);
        assert_eq!(result.patched_document["new_field"], true);
    }

    #[test]
    fn test_json_patch_invalid_not_array() {
        let engine = PatchEngine::new();
        let doc = json!({"value": 1});
        let patch = json!({"op": "replace", "path": "/value", "value": 2});

        let base_hash = engine.compute_hash(&doc).unwrap();
        let result = engine.apply_json_patch(&doc, &patch, &base_hash);

        assert!(matches!(
            result,
            Err(PatchEngineError::InvalidPatch { message }) if message.contains("must be an array")
        ));
    }

    #[test]
    fn test_json_patch_invalid_operation() {
        let engine = PatchEngine::new();
        let doc = json!({"value": 1});
        let patch = json!([{"op": "invalid_op", "path": "/value"}]);

        let base_hash = engine.compute_hash(&doc).unwrap();
        let result = engine.apply_json_patch(&doc, &patch, &base_hash);

        assert!(matches!(result, Err(PatchEngineError::InvalidPatch { .. })));
    }

    #[test]
    fn test_json_patch_nonexistent_path() {
        let engine = PatchEngine::new();
        let doc = json!({"value": 1});
        let patch = json!([{"op": "remove", "path": "/nonexistent"}]);

        let base_hash = engine.compute_hash(&doc).unwrap();
        let result = engine.apply_json_patch(&doc, &patch, &base_hash);

        assert!(matches!(
            result,
            Err(PatchEngineError::JsonPatchFailed { .. })
        ));
    }

    // =========================================================================
    // Merge Patch (RFC 7396) Tests
    // =========================================================================

    #[test]
    fn test_merge_patch_add_field() {
        let engine = PatchEngine::new();
        let doc = json!({"name": "test"});
        let patch = json!({"version": 1});

        let base_hash = engine.compute_hash(&doc).unwrap();
        let result = engine.apply_merge_patch(&doc, &patch, &base_hash).unwrap();

        assert_eq!(
            result.patched_document,
            json!({"name": "test", "version": 1})
        );
    }

    #[test]
    fn test_merge_patch_replace_field() {
        let engine = PatchEngine::new();
        let doc = json!({"name": "old"});
        let patch = json!({"name": "new"});

        let base_hash = engine.compute_hash(&doc).unwrap();
        let result = engine.apply_merge_patch(&doc, &patch, &base_hash).unwrap();

        assert_eq!(result.patched_document["name"], "new");
    }

    #[test]
    fn test_merge_patch_remove_field_with_null() {
        let engine = PatchEngine::new();
        let doc = json!({"name": "test", "obsolete": true});
        let patch = json!({"obsolete": null});

        let base_hash = engine.compute_hash(&doc).unwrap();
        let result = engine.apply_merge_patch(&doc, &patch, &base_hash).unwrap();

        assert_eq!(result.patched_document, json!({"name": "test"}));
    }

    #[test]
    fn test_merge_patch_nested_merge() {
        let engine = PatchEngine::new();
        let doc = json!({
            "config": {
                "debug": false,
                "timeout": 30
            }
        });
        let patch = json!({
            "config": {
                "debug": true
            }
        });

        let base_hash = engine.compute_hash(&doc).unwrap();
        let result = engine.apply_merge_patch(&doc, &patch, &base_hash).unwrap();

        assert_eq!(result.patched_document["config"]["debug"], true);
        assert_eq!(result.patched_document["config"]["timeout"], 30);
    }

    #[test]
    fn test_merge_patch_replace_array() {
        let engine = PatchEngine::new();
        let doc = json!({"items": [1, 2, 3]});
        let patch = json!({"items": [4, 5]});

        let base_hash = engine.compute_hash(&doc).unwrap();
        let result = engine.apply_merge_patch(&doc, &patch, &base_hash).unwrap();

        // Arrays are replaced, not merged
        assert_eq!(result.patched_document["items"], json!([4, 5]));
    }

    #[test]
    fn test_merge_patch_null_removes_nested() {
        let engine = PatchEngine::new();
        let doc = json!({
            "config": {
                "a": 1,
                "b": 2
            }
        });
        let patch = json!({
            "config": {
                "a": null
            }
        });

        let base_hash = engine.compute_hash(&doc).unwrap();
        let result = engine.apply_merge_patch(&doc, &patch, &base_hash).unwrap();

        assert!(result.patched_document["config"].get("a").is_none());
        assert_eq!(result.patched_document["config"]["b"], 2);
    }

    // =========================================================================
    // Replay Protection Tests
    // =========================================================================

    #[test]
    fn test_replay_violation_json_patch() {
        let engine = PatchEngine::new();
        let doc = json!({"value": 1});
        let patch = json!([{"op": "replace", "path": "/value", "value": 2}]);

        let wrong_hash = "0000000000000000000000000000000000000000000000000000000000000000";
        let result = engine.apply_json_patch(&doc, &patch, wrong_hash);

        match result {
            Err(PatchEngineError::ReplayViolation { expected, actual }) => {
                assert_eq!(expected, wrong_hash);
                assert_ne!(actual, wrong_hash);
            },
            other => panic!("Expected ReplayViolation, got: {other:?}"),
        }
    }

    #[test]
    fn test_replay_violation_merge_patch() {
        let engine = PatchEngine::new();
        let doc = json!({"value": 1});
        let patch = json!({"value": 2});

        let wrong_hash = "0000000000000000000000000000000000000000000000000000000000000000";
        let result = engine.apply_merge_patch(&doc, &patch, wrong_hash);

        match result {
            Err(PatchEngineError::ReplayViolation { expected, actual }) => {
                assert_eq!(expected, wrong_hash);
                assert_ne!(actual, wrong_hash);
            },
            other => panic!("Expected ReplayViolation, got: {other:?}"),
        }
    }

    #[test]
    fn test_create_replay_violation_event() {
        let patch = json!([{"op": "replace", "path": "/value", "value": 2}]);

        let event = PatchEngine::create_replay_violation(
            "expected_hash_abc",
            "actual_hash_xyz",
            &patch,
            PatchType::JsonPatch,
        );

        assert_eq!(event.expected_hash, "expected_hash_abc");
        assert_eq!(event.actual_hash, "actual_hash_xyz");
        assert_eq!(event.patch_type, PatchType::JsonPatch);
        assert!(!event.patch_hash.is_empty());
    }

    // =========================================================================
    // Canonicalization Tests
    // =========================================================================

    #[test]
    fn test_output_is_canonicalized() {
        let engine = PatchEngine::new();
        let doc = json!({"z": 1, "a": 2});
        let patch = json!([{"op": "add", "path": "/m", "value": 3}]);

        let base_hash = engine.compute_hash(&doc).unwrap();
        let result = engine.apply_json_patch(&doc, &patch, &base_hash).unwrap();

        // Output should have sorted keys with no whitespace
        assert_eq!(result.canonical_output, r#"{"a":2,"m":3,"z":1}"#);
    }

    #[test]
    fn test_new_hash_matches_canonical_output() {
        let engine = PatchEngine::new();
        let doc = json!({"value": 1});
        let patch = json!([{"op": "replace", "path": "/value", "value": 2}]);

        let base_hash = engine.compute_hash(&doc).unwrap();
        let result = engine.apply_json_patch(&doc, &patch, &base_hash).unwrap();

        // new_hash should match the hash of the patched document
        let recomputed_hash = engine.compute_hash(&result.patched_document).unwrap();
        assert_eq!(result.new_hash, recomputed_hash);
    }

    #[test]
    fn test_patch_rejects_float_output() {
        let engine = PatchEngine::new();
        let doc = json!({"value": 1});
        // Note: serde_json may represent 1.5 as a float
        let patch = json!([{"op": "replace", "path": "/value", "value": 1.5}]);

        let base_hash = engine.compute_hash(&doc).unwrap();
        let result = engine.apply_json_patch(&doc, &patch, &base_hash);

        assert!(matches!(
            result,
            Err(PatchEngineError::CanonicalizationFailed(
                CacJsonError::FloatNotAllowed
            ))
        ));
    }

    // =========================================================================
    // PatchResult Tests
    // =========================================================================

    #[test]
    fn test_patch_result_contains_patch_hash() {
        let engine = PatchEngine::new();
        let doc = json!({"value": 1});
        let patch = json!([{"op": "replace", "path": "/value", "value": 2}]);

        let base_hash = engine.compute_hash(&doc).unwrap();
        let result = engine.apply_json_patch(&doc, &patch, &base_hash).unwrap();

        // patch_hash should be non-empty
        assert!(!result.patch_hash.is_empty());
        assert_eq!(result.patch_hash.len(), 64); // BLAKE3 hex is 64 chars
    }

    #[test]
    fn test_same_patch_produces_same_patch_hash() {
        let engine = PatchEngine::new();
        let doc = json!({"value": 1});
        let patch = json!([{"op": "replace", "path": "/value", "value": 2}]);

        let base_hash = engine.compute_hash(&doc).unwrap();
        let result1 = engine.apply_json_patch(&doc, &patch, &base_hash).unwrap();

        // Apply same patch again (recompute base from result)
        let doc2 = result1.patched_document.clone();
        let patch2 = json!([{"op": "replace", "path": "/value", "value": 3}]);
        let result2 = engine
            .apply_json_patch(&doc2, &patch2, &result1.new_hash)
            .unwrap();

        // Different patches should have different hashes
        assert_ne!(result1.patch_hash, result2.patch_hash);
    }

    // =========================================================================
    // PatchType Display Tests
    // =========================================================================

    #[test]
    fn test_patch_type_display() {
        assert_eq!(PatchType::JsonPatch.to_string(), "JSON Patch (RFC 6902)");
        assert_eq!(PatchType::MergePatch.to_string(), "Merge Patch (RFC 7396)");
    }

    // =========================================================================
    // Error Display Tests
    // =========================================================================

    #[test]
    fn test_error_display_replay_violation() {
        let err = PatchEngineError::ReplayViolation {
            expected: "abc123".to_string(),
            actual: "xyz789".to_string(),
        };
        assert!(err.to_string().contains("replay violation"));
        assert!(err.to_string().contains("abc123"));
        assert!(err.to_string().contains("xyz789"));
    }

    #[test]
    fn test_error_display_json_patch_failed() {
        let err = PatchEngineError::JsonPatchFailed {
            message: "path not found".to_string(),
        };
        assert!(err.to_string().contains("json patch failed"));
        assert!(err.to_string().contains("path not found"));
    }

    #[test]
    fn test_error_display_merge_patch_failed() {
        let err = PatchEngineError::MergePatchFailed {
            message: "invalid target".to_string(),
        };
        assert!(err.to_string().contains("merge patch failed"));
    }

    #[test]
    fn test_error_display_invalid_patch() {
        let err = PatchEngineError::InvalidPatch {
            message: "not an array".to_string(),
        };
        assert!(err.to_string().contains("invalid patch"));
    }

    // =========================================================================
    // Edge Cases
    // =========================================================================

    #[test]
    fn test_empty_patch_array() {
        let engine = PatchEngine::new();
        let doc = json!({"value": 1});
        let patch = json!([]);

        let base_hash = engine.compute_hash(&doc).unwrap();
        let result = engine.apply_json_patch(&doc, &patch, &base_hash).unwrap();

        // Empty patch should not change document
        assert_eq!(result.patched_document, doc);
        assert_eq!(result.old_hash, result.new_hash);
    }

    #[test]
    fn test_empty_merge_patch() {
        let engine = PatchEngine::new();
        let doc = json!({"value": 1});
        let patch = json!({});

        let base_hash = engine.compute_hash(&doc).unwrap();
        let result = engine.apply_merge_patch(&doc, &patch, &base_hash).unwrap();

        // Empty merge patch should not change document
        assert_eq!(result.patched_document, doc);
        assert_eq!(result.old_hash, result.new_hash);
    }

    #[test]
    fn test_deeply_nested_patch() {
        let engine = PatchEngine::new();
        let doc = json!({
            "level1": {
                "level2": {
                    "level3": {
                        "value": 1
                    }
                }
            }
        });
        let patch = json!([{
            "op": "replace",
            "path": "/level1/level2/level3/value",
            "value": 42
        }]);

        let base_hash = engine.compute_hash(&doc).unwrap();
        let result = engine.apply_json_patch(&doc, &patch, &base_hash).unwrap();

        assert_eq!(
            result.patched_document["level1"]["level2"]["level3"]["value"],
            42
        );
    }

    #[test]
    fn test_unicode_in_patch() {
        let engine = PatchEngine::new();
        let doc = json!({"greeting": "hello"});
        let patch = json!([{"op": "replace", "path": "/greeting", "value": "\u{4e2d}\u{6587}"}]);

        let base_hash = engine.compute_hash(&doc).unwrap();
        let result = engine.apply_json_patch(&doc, &patch, &base_hash).unwrap();

        assert_eq!(result.patched_document["greeting"], "\u{4e2d}\u{6587}");
    }
}
