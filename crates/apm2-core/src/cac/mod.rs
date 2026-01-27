//! Context-as-Code (CAC) module.
//!
//! This module provides the CAC v1 implementation including:
//!
//! - **JSON Schema validation**: Strict validation with
//!   `unevaluatedProperties=false`
//! - **Size limit enforcement**: Pre-validation to prevent denial-of-service
//! - **Admission pipeline integration**: Validation after canonicalization
//!
//! # Architecture
//!
//! CAC artifacts flow through a validation pipeline:
//! 1. Canonicalization (via `determinism::canonicalize_json`)
//! 2. Schema validation (this module)
//! 3. CAS storage
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

mod validator;

pub use validator::{
    CacValidator, MAX_ARRAY_MEMBERS, MAX_DEPTH, MAX_OBJECT_PROPERTIES, ValidationError,
    validate_cac_artifact,
};
