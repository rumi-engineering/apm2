//! Context-as-Code (CAC) module.
//!
//! This module provides the CAC v1 implementation including:
//!
//! - **JSON Schema validation**: Strict validation with
//!   `unevaluatedProperties=false`
//! - **Size limit enforcement**: Pre-validation to prevent denial-of-service
//! - **Admission pipeline**: Orchestrates validation, canonicalization, and
//!   storage
//! - **Patch engine**: JSON Patch (RFC 6902) and Merge Patch (RFC 7396) with
//!   replay protection
//! - **Admission receipts**: Cryptographic receipts with hash chains
//!
//! # Architecture
//!
//! CAC artifacts flow through the admission pipeline:
//! 1. Canonicalization (via `determinism::canonicalize_json`)
//! 2. Schema validation
//! 3. CAS storage
//! 4. Receipt generation with hash chain
//! 5. Ledger event emission
//!
//! For patch operations:
//! 1. Validate `expected_base_hash` matches current document
//! 2. Apply patch (JSON Patch or Merge Patch)
//! 3. Canonicalize output (CAC-JSON format)
//! 4. Validate against schema
//! 5. Store in CAS
//! 6. Return `AdmissionReceipt` with hash chain
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
//! # Admission Pipeline Example
//!
//! ```
//! use apm2_core::cac::admission::{AdmissionGate, AdmissionRequest, ArtifactKind};
//! use apm2_core::evidence::MemoryCas;
//! use serde_json::json;
//!
//! let cas = MemoryCas::new();
//! let gate = AdmissionGate::new(cas);
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
//! let artifact = json!({"id": "TCK-00132"});
//! let request = AdmissionRequest::new_artifact(
//!     "dcp://org/project/ticket/TCK-00132",
//!     ArtifactKind::Ticket,
//!     artifact,
//!     &schema,
//! );
//!
//! let result = gate.admit(request).unwrap();
//! assert!(!result.receipt.new_hash.is_empty());
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
//!
//! # DCP Index Example
//!
//! ```
//! use apm2_core::cac::dcp_index::{DcpEntry, DcpIndex};
//!
//! let mut index = DcpIndex::new();
//!
//! // Register an artifact with a valid 64-character hex hash
//! let entry = DcpEntry::new(
//!     "org:ticket:TCK-00134",
//!     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
//!     "cac:schema:ticket-v1",
//! );
//! index.register(entry).unwrap();
//!
//! // Resolve returns the content hash
//! let hash = index.resolve("org:ticket:TCK-00134");
//! assert!(hash.is_some());
//! ```

pub mod admission;
pub mod dcp_index;
pub mod patch_engine;
mod validator;

pub use dcp_index::{
    DcpEntry, DcpIndex, DcpIndexError, DcpIndexReducer, DcpIndexReducerError, DcpIndexState,
    EVENT_TYPE_ARTIFACT_DEPRECATED, EVENT_TYPE_ARTIFACT_REGISTERED, MAX_CONTENT_HASH_LENGTH,
    MAX_STABLE_ID_LENGTH, RESERVED_PREFIXES, parse_stable_id,
};
pub use patch_engine::{PatchEngine, PatchEngineError, PatchResult, PatchType, ReplayViolation};
pub use validator::{
    CacValidator, MAX_ARRAY_MEMBERS, MAX_DEPTH, MAX_OBJECT_PROPERTIES, ValidationError,
    validate_cac_artifact,
};
