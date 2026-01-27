//! Context-as-Code (CAC) module.
//!
//! This module provides the CAC v1 implementation including:
//!
//! - **JSON Schema validation**: Strict validation with
//!   `unevaluatedProperties=false`
//! - **Size limit enforcement**: Pre-validation to prevent denial-of-service
//! - **Admission pipeline integration**: Validation after canonicalization
//! - **Patch engine**: JSON Patch (RFC 6902) and Merge Patch (RFC 7396) with
//!   replay protection
//!
//! # Architecture
//!
//! CAC artifacts flow through a validation pipeline:
//! 1. Canonicalization (via `determinism::canonicalize_json`)
//! 2. Schema validation (this module)
//! 3. CAS storage
//!
//! For patch operations:
//! 1. Validate `expected_base_hash` matches current document
//! 2. Apply patch (JSON Patch or Merge Patch)
//! 3. Canonicalize output (CAC-JSON format)
//! 4. Compute new content hash
//! 5. Return `PatchResult` with hash chain
//!
//! # Example
//!
//! ```ignore
//! use apm2_core::cac::{CacValidator, validate_cac_artifact};
//! use serde_json::json;
//!
//! let schema = json!({
//!     "$schema": "https://json-schema.org/draft/2020-12/schema",
//!     "type": "object",
//!     "properties": {
//!         "id": { "type": "string" }
//!     },
//!     "unevaluatedProperties": false
//! });
//!
//! let validator = CacValidator::new(&schema).unwrap();
//! let artifact = json!({"id": "test-001"});
//! validator.validate(&artifact).unwrap();
//! ```
//!
//! # Patch Engine Example
//!
//! ```
//! use apm2_core::cac::patch_engine::{PatchEngine, PatchType};
//! use serde_json::json;
//!
//! let engine = PatchEngine::new();
//! let doc = json!({"version": 1});
//! let patch = json!([{"op": "replace", "path": "/version", "value": 2}]);
//!
//! let base_hash = engine.compute_hash(&doc).unwrap();
//! let result = engine.apply_json_patch(&doc, &patch, &base_hash).unwrap();
//!
//! assert_eq!(result.patched_document["version"], 2);
//! ```

pub mod patch_engine;
mod validator;

pub use patch_engine::{PatchEngine, PatchEngineError, PatchResult, PatchType, ReplayViolation};
pub use validator::{
    CacValidator, MAX_ARRAY_MEMBERS, MAX_DEPTH, MAX_OBJECT_PROPERTIES, ValidationError,
    validate_cac_artifact,
};
