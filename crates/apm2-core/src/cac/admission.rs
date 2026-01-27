//! CAC Admission Pipeline and Receipts.
//!
//! This module implements the admission gate that validates, canonicalizes,
//! and stores CAC artifacts. It generates cryptographic receipts and emits
//! ledger events for audit trails.
//!
//! # Admission Pipeline
//!
//! The admission pipeline is the sole entry point for CAC artifacts:
//!
//! 1. **Validate**: Check artifact against JSON Schema with size limits
//! 2. **Canonicalize**: Produce deterministic CAC-JSON output
//! 3. **Store**: Persist to Content-Addressed Store (CAS)
//! 4. **Receipt**: Generate `AdmissionReceipt` with hash chain
//! 5. **Event**: Emit `EvidencePublished` for ledger provenance
//!
//! # Security Properties
//!
//! - **Replay Protection**: Patches require `expected_base_hash` validation
//! - **Hash Chain**: Receipts link base -> patch -> new states
//! - **Immutability**: Stored artifacts cannot be modified
//! - **Audit Trail**: All admissions emit ledger events
//!
//! # Example
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
//! assert!(result.receipt.new_hash.len() == 64); // BLAKE3 hex
//! ```

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;

use super::patch_engine::{PatchEngine, PatchEngineError, PatchType};
use super::validator::{
    CacValidator, MAX_ARRAY_MEMBERS, MAX_DEPTH, MAX_OBJECT_PROPERTIES, ValidationError,
};
use crate::determinism::{CacJsonError, canonicalize_json};
use crate::evidence::{CasError, ContentAddressedStore};

/// Canonicalizer identifier for the CAC-JSON v1 profile.
pub const CANONICALIZER_ID: &str = "cac-json-v1";

/// Canonicalizer version following semver.
pub const CANONICALIZER_VERSION: &str = "1.0.0";

/// Maximum allowed length for DCP IDs.
///
/// This prevents unbounded receipt/ledger bloat from malicious or erroneous
/// artifact IDs. 1024 characters is sufficient for all valid DCP URI formats.
pub const MAX_DCP_ID_LENGTH: usize = 1024;

/// Errors that can occur during admission.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AdmissionError {
    /// Schema validation failed.
    #[error("validation failed: {0}")]
    ValidationFailed(#[from] ValidationError),

    /// CAC-JSON canonicalization failed.
    #[error("canonicalization failed: {0}")]
    CanonicalizationFailed(#[from] CacJsonError),

    /// Patch application failed.
    #[error("patch failed: {0}")]
    PatchFailed(#[from] PatchEngineError),

    /// CAS storage failed.
    #[error("storage failed: {message}")]
    StorageFailed {
        /// Description of the storage error.
        message: String,
    },

    /// The DCP ID is invalid.
    #[error("invalid dcp_id: {reason}")]
    InvalidDcpId {
        /// The reason the DCP ID is invalid.
        reason: String,
    },

    /// Input complexity exceeds allowed limits.
    #[error("input complexity exceeded: {message}")]
    InputComplexityExceeded {
        /// Description of the complexity violation.
        message: String,
    },

    /// The schema hash is missing for patch operations.
    #[error("schema_hash required for patch operations")]
    MissingSchemaHash,

    /// JSON serialization failed.
    #[error("serialization failed: {message}")]
    SerializationFailed {
        /// Description of the serialization error.
        message: String,
    },
}

impl From<CasError> for AdmissionError {
    fn from(err: CasError) -> Self {
        Self::StorageFailed {
            message: err.to_string(),
        }
    }
}

/// The kind of artifact being admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ArtifactKind {
    /// A ticket artifact (work item specification).
    Ticket,

    /// An RFC document.
    Rfc,

    /// A PRD (Product Requirements Document).
    Prd,

    /// A policy artifact.
    Policy,

    /// A context pack specification.
    ContextPack,

    /// A target profile for compilation.
    TargetProfile,

    /// A schema definition.
    Schema,

    /// A bootstrap artifact.
    Bootstrap,

    /// A run manifest.
    RunManifest,

    /// A generic artifact (catch-all).
    Generic,
}

impl std::fmt::Display for ArtifactKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ticket => write!(f, "ticket"),
            Self::Rfc => write!(f, "rfc"),
            Self::Prd => write!(f, "prd"),
            Self::Policy => write!(f, "policy"),
            Self::ContextPack => write!(f, "context_pack"),
            Self::TargetProfile => write!(f, "target_profile"),
            Self::Schema => write!(f, "schema"),
            Self::Bootstrap => write!(f, "bootstrap"),
            Self::RunManifest => write!(f, "run_manifest"),
            Self::Generic => write!(f, "generic"),
        }
    }
}

/// Operation type for admission requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionOperation {
    /// Create a new artifact.
    Create,

    /// Update an existing artifact via JSON Patch (RFC 6902).
    JsonPatch {
        /// The patch operations.
        patch: Value,
        /// Expected hash of the base document.
        expected_base_hash: String,
        /// The base document being patched.
        base_document: Value,
    },

    /// Update an existing artifact via Merge Patch (RFC 7396).
    MergePatch {
        /// The merge patch document.
        patch: Value,
        /// Expected hash of the base document.
        expected_base_hash: String,
        /// The base document being patched.
        base_document: Value,
    },
}

/// Request to admit an artifact through the CAC pipeline.
#[derive(Debug, Clone)]
pub struct AdmissionRequest {
    /// The DCP stable ID for this artifact.
    pub dcp_id: String,

    /// The kind of artifact being admitted.
    pub artifact_kind: ArtifactKind,

    /// The artifact content (for Create) or the result of patching.
    pub content: Value,

    /// The JSON Schema for validation.
    pub schema: Value,

    /// BLAKE3 hash of the schema (hex-encoded).
    pub schema_hash: String,

    /// The admission operation type.
    pub operation: AdmissionOperation,
}

impl AdmissionRequest {
    /// Creates a new artifact admission request (create operation).
    ///
    /// # Arguments
    ///
    /// * `dcp_id` - The DCP stable ID for this artifact
    /// * `artifact_kind` - The kind of artifact
    /// * `content` - The artifact content
    /// * `schema` - The JSON Schema for validation
    ///
    /// # Returns
    ///
    /// An `AdmissionRequest` configured for artifact creation.
    #[must_use]
    pub fn new_artifact(
        dcp_id: impl Into<String>,
        artifact_kind: ArtifactKind,
        content: Value,
        schema: &Value,
    ) -> Self {
        let schema_hash = compute_schema_hash(schema);
        Self {
            dcp_id: dcp_id.into(),
            artifact_kind,
            content,
            schema: schema.clone(),
            schema_hash,
            operation: AdmissionOperation::Create,
        }
    }

    /// Creates a JSON Patch admission request (update operation).
    ///
    /// # Arguments
    ///
    /// * `dcp_id` - The DCP stable ID for the artifact being patched
    /// * `artifact_kind` - The kind of artifact
    /// * `base_document` - The current document state
    /// * `patch` - The JSON Patch operations (RFC 6902)
    /// * `expected_base_hash` - Expected hash of the base document
    /// * `schema` - The JSON Schema for validation
    ///
    /// # Returns
    ///
    /// An `AdmissionRequest` configured for JSON Patch update.
    #[must_use]
    pub fn new_json_patch(
        dcp_id: impl Into<String>,
        artifact_kind: ArtifactKind,
        base_document: Value,
        patch: Value,
        expected_base_hash: impl Into<String>,
        schema: &Value,
    ) -> Self {
        let schema_hash = compute_schema_hash(schema);
        Self {
            dcp_id: dcp_id.into(),
            artifact_kind,
            content: Value::Null, // Will be populated after patching
            schema: schema.clone(),
            schema_hash,
            operation: AdmissionOperation::JsonPatch {
                patch,
                expected_base_hash: expected_base_hash.into(),
                base_document,
            },
        }
    }

    /// Creates a Merge Patch admission request (update operation).
    ///
    /// # Arguments
    ///
    /// * `dcp_id` - The DCP stable ID for the artifact being patched
    /// * `artifact_kind` - The kind of artifact
    /// * `base_document` - The current document state
    /// * `patch` - The merge patch document (RFC 7396)
    /// * `expected_base_hash` - Expected hash of the base document
    /// * `schema` - The JSON Schema for validation
    ///
    /// # Returns
    ///
    /// An `AdmissionRequest` configured for Merge Patch update.
    #[must_use]
    pub fn new_merge_patch(
        dcp_id: impl Into<String>,
        artifact_kind: ArtifactKind,
        base_document: Value,
        patch: Value,
        expected_base_hash: impl Into<String>,
        schema: &Value,
    ) -> Self {
        let schema_hash = compute_schema_hash(schema);
        Self {
            dcp_id: dcp_id.into(),
            artifact_kind,
            content: Value::Null, // Will be populated after patching
            schema: schema.clone(),
            schema_hash,
            operation: AdmissionOperation::MergePatch {
                patch,
                expected_base_hash: expected_base_hash.into(),
                base_document,
            },
        }
    }
}

/// Receipt generated after successful admission.
///
/// The receipt contains all hash fields required for audit and provenance:
/// - `patch_hash`: BLAKE3 hash of the patch (if applicable)
/// - `base_hash`: BLAKE3 hash of the base document (if applicable)
/// - `new_hash`: BLAKE3 hash of the admitted artifact
/// - `schema_hash`: BLAKE3 hash of the validation schema
///
/// The receipt also includes canonicalizer metadata per DD-0002.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionReceipt {
    /// Unique identifier for this receipt.
    pub receipt_id: String,

    /// Timestamp when the admission occurred.
    pub timestamp: DateTime<Utc>,

    /// The DCP stable ID of the admitted artifact.
    pub dcp_id: String,

    /// The kind of artifact that was admitted.
    pub artifact_kind: ArtifactKind,

    /// BLAKE3 hash of the patch (if applicable, hex-encoded).
    /// None for create operations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub patch_hash: Option<String>,

    /// BLAKE3 hash of the base document (if applicable, hex-encoded).
    /// None for create operations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_hash: Option<String>,

    /// BLAKE3 hash of the admitted artifact (hex-encoded).
    pub new_hash: String,

    /// BLAKE3 hash of the validation schema (hex-encoded).
    pub schema_hash: String,

    /// Size of the admitted artifact in bytes.
    pub artifact_size: usize,

    /// The canonicalizer identifier.
    pub canonicalizer_id: String,

    /// The canonicalizer version (semver).
    pub canonicalizer_version: String,

    /// Whether the content was newly stored (true) or deduplicated (false).
    pub is_new_content: bool,

    /// The type of patch operation (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub patch_type: Option<String>,
}

impl AdmissionReceipt {
    /// Creates a new `AdmissionReceipt` from admission results.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    fn new(
        dcp_id: String,
        artifact_kind: ArtifactKind,
        new_hash: String,
        schema_hash: String,
        artifact_size: usize,
        is_new_content: bool,
        patch_hash: Option<String>,
        base_hash: Option<String>,
        patch_type: Option<PatchType>,
    ) -> Self {
        Self {
            receipt_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            dcp_id,
            artifact_kind,
            patch_hash,
            base_hash,
            new_hash,
            schema_hash,
            artifact_size,
            canonicalizer_id: CANONICALIZER_ID.to_string(),
            canonicalizer_version: CANONICALIZER_VERSION.to_string(),
            is_new_content,
            patch_type: patch_type.map(|pt| pt.to_string()),
        }
    }

    /// Returns metadata key-value pairs for event emission.
    ///
    /// Format: `["key=value", ...]` for `EvidencePublished.metadata`.
    #[must_use]
    pub fn to_metadata(&self) -> Vec<String> {
        let mut metadata = vec![
            format!("dcp_id={}", self.dcp_id),
            format!("artifact_kind={}", self.artifact_kind),
            format!("schema_hash={}", self.schema_hash),
            format!("canonicalizer_id={}", self.canonicalizer_id),
            format!("canonicalizer_version={}", self.canonicalizer_version),
        ];

        if let Some(ref patch_hash) = self.patch_hash {
            metadata.push(format!("patch_hash={patch_hash}"));
        }
        if let Some(ref base_hash) = self.base_hash {
            metadata.push(format!("base_hash={base_hash}"));
        }
        if let Some(ref patch_type) = self.patch_type {
            metadata.push(format!("patch_type={patch_type}"));
        }

        metadata
    }
}

/// Summary of semantic changes in a patch operation.
///
/// The `ChangeSetReport` provides a human-readable summary of what changed
/// in a patch operation, supporting audit and review workflows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeSetReport {
    /// The DCP stable ID of the artifact.
    pub dcp_id: String,

    /// The type of patch operation.
    pub patch_type: String,

    /// BLAKE3 hash of the base document.
    pub base_hash: String,

    /// BLAKE3 hash of the new document.
    pub new_hash: String,

    /// BLAKE3 hash of the patch.
    pub patch_hash: String,

    /// Number of add operations (for JSON Patch).
    pub adds: usize,

    /// Number of remove operations (for JSON Patch).
    pub removes: usize,

    /// Number of replace operations (for JSON Patch).
    pub replaces: usize,

    /// Number of move operations (for JSON Patch).
    pub moves: usize,

    /// Number of copy operations (for JSON Patch).
    pub copies: usize,

    /// Number of test operations (for JSON Patch).
    pub tests: usize,

    /// Paths that were modified (for Merge Patch, top-level keys).
    pub modified_paths: Vec<String>,

    /// Timestamp when the report was generated.
    pub timestamp: DateTime<Utc>,
}

impl ChangeSetReport {
    /// Creates a `ChangeSetReport` for a JSON Patch operation.
    ///
    /// # Performance
    ///
    /// Uses `BTreeSet` for O(log N) path deduplication instead of O(N^2)
    /// linear search, ensuring linear time complexity for large patches.
    #[must_use]
    pub fn from_json_patch(
        dcp_id: &str,
        base_hash: &str,
        new_hash: &str,
        patch_hash: &str,
        patch: &Value,
    ) -> Self {
        let mut adds = 0;
        let mut removes = 0;
        let mut replaces = 0;
        let mut moves = 0;
        let mut copies = 0;
        let mut tests = 0;
        // SECURITY: Use BTreeSet for O(log N) deduplication instead of O(N^2)
        // Vec::contains
        let mut paths_set: BTreeSet<String> = BTreeSet::new();

        if let Some(ops) = patch.as_array() {
            for op in ops {
                if let Some(op_name) = op.get("op").and_then(Value::as_str) {
                    match op_name {
                        "add" => adds += 1,
                        "remove" => removes += 1,
                        "replace" => replaces += 1,
                        "move" => moves += 1,
                        "copy" => copies += 1,
                        "test" => tests += 1,
                        _ => {},
                    }
                    if let Some(path) = op.get("path").and_then(Value::as_str) {
                        paths_set.insert(path.to_string());
                    }
                }
            }
        }

        Self {
            dcp_id: dcp_id.to_string(),
            patch_type: PatchType::JsonPatch.to_string(),
            base_hash: base_hash.to_string(),
            new_hash: new_hash.to_string(),
            patch_hash: patch_hash.to_string(),
            adds,
            removes,
            replaces,
            moves,
            copies,
            tests,
            modified_paths: paths_set.into_iter().collect(),
            timestamp: Utc::now(),
        }
    }

    /// Creates a `ChangeSetReport` for a Merge Patch operation.
    #[must_use]
    pub fn from_merge_patch(
        dcp_id: &str,
        base_hash: &str,
        new_hash: &str,
        patch_hash: &str,
        patch: &Value,
    ) -> Self {
        let mut modified_paths = Vec::new();

        // For merge patch, top-level keys indicate modifications
        if let Some(obj) = patch.as_object() {
            for key in obj.keys() {
                modified_paths.push(format!("/{key}"));
            }
        }

        Self {
            dcp_id: dcp_id.to_string(),
            patch_type: PatchType::MergePatch.to_string(),
            base_hash: base_hash.to_string(),
            new_hash: new_hash.to_string(),
            patch_hash: patch_hash.to_string(),
            adds: 0,
            removes: 0,
            replaces: modified_paths.len(), // Approximation for merge patch
            moves: 0,
            copies: 0,
            tests: 0,
            modified_paths,
            timestamp: Utc::now(),
        }
    }
}

/// Result of a successful admission.
#[derive(Debug, Clone)]
pub struct AdmissionResult {
    /// The admission receipt with hash chain.
    pub receipt: AdmissionReceipt,

    /// The canonical JSON output (stored in CAS).
    pub canonical_content: String,

    /// Change set report (for patch operations only).
    pub change_set_report: Option<ChangeSetReport>,
}

/// The admission gate that orchestrates validation, canonicalization, and
/// storage.
///
/// The `AdmissionGate` is the sole entry point for CAC artifacts per TB-0001.
/// It ensures all artifacts are:
/// 1. Validated against their schema
/// 2. Canonicalized to CAC-JSON format
/// 3. Stored in the Content-Addressed Store
/// 4. Accompanied by cryptographic receipts
#[derive(Debug)]
pub struct AdmissionGate<C: ContentAddressedStore> {
    cas: C,
    patch_engine: PatchEngine,
}

impl<C: ContentAddressedStore> AdmissionGate<C> {
    /// Creates a new `AdmissionGate` with the given CAS backend.
    #[must_use]
    pub const fn new(cas: C) -> Self {
        Self {
            cas,
            patch_engine: PatchEngine::new(),
        }
    }

    /// Returns a reference to the underlying CAS.
    #[must_use]
    pub const fn cas(&self) -> &C {
        &self.cas
    }

    /// Admits an artifact through the CAC pipeline.
    ///
    /// The admission process:
    /// 1. For patch operations: apply the patch with replay protection
    /// 2. Canonicalize the artifact to CAC-JSON format
    /// 3. Validate against the provided schema
    /// 4. Store in the Content-Addressed Store
    /// 5. Generate an `AdmissionReceipt` with hash chain
    ///
    /// # Arguments
    ///
    /// * `request` - The admission request containing artifact and metadata
    ///
    /// # Returns
    ///
    /// An `AdmissionResult` containing the receipt and canonical content.
    ///
    /// # Errors
    ///
    /// - [`AdmissionError::ValidationFailed`] if schema validation fails
    /// - [`AdmissionError::CanonicalizationFailed`] if CAC-JSON
    ///   canonicalization fails
    /// - [`AdmissionError::PatchFailed`] if patch application fails
    /// - [`AdmissionError::StorageFailed`] if CAS storage fails
    /// - [`AdmissionError::InvalidDcpId`] if the DCP ID is empty, too long, or
    ///   contains invalid characters
    /// - [`AdmissionError::InputComplexityExceeded`] if input exceeds
    ///   depth/size limits
    pub fn admit(&self, request: AdmissionRequest) -> Result<AdmissionResult, AdmissionError> {
        // SECURITY: Validate DCP ID first (length and character safety)
        validate_dcp_id(&request.dcp_id)?;

        // SECURITY: Validate input complexity BEFORE any serialization/hashing
        // This prevents DoS via unbounded input that would cause expensive
        // operations before being rejected.
        validate_input_complexity(&request.content, "content")?;
        validate_input_complexity(&request.schema, "schema")?;

        // SECURITY: Validate schema complexity before building validator
        // (prevents DoS via maliciously complex schemas)
        // The validator compiles the schema, which can be expensive for complex schemas

        // Build the validator
        let validator = CacValidator::new(&request.schema)?;

        // Process based on operation type
        match request.operation {
            AdmissionOperation::Create => self.admit_create(request, &validator),
            AdmissionOperation::JsonPatch {
                ref patch,
                ref expected_base_hash,
                ref base_document,
            } => {
                // SECURITY: Validate patch and base document complexity
                validate_input_complexity(patch, "patch")?;
                validate_input_complexity(base_document, "base_document")?;

                self.admit_json_patch(
                    request.dcp_id,
                    request.artifact_kind,
                    request.schema_hash,
                    base_document.clone(),
                    patch.clone(),
                    expected_base_hash.clone(),
                    &validator,
                )
            },
            AdmissionOperation::MergePatch {
                ref patch,
                ref expected_base_hash,
                ref base_document,
            } => {
                // SECURITY: Validate patch and base document complexity
                validate_input_complexity(patch, "patch")?;
                validate_input_complexity(base_document, "base_document")?;

                self.admit_merge_patch(
                    request.dcp_id,
                    request.artifact_kind,
                    request.schema_hash,
                    base_document.clone(),
                    patch.clone(),
                    expected_base_hash.clone(),
                    &validator,
                )
            },
        }
    }

    /// Admits a new artifact (create operation).
    fn admit_create(
        &self,
        request: AdmissionRequest,
        validator: &CacValidator,
    ) -> Result<AdmissionResult, AdmissionError> {
        // Serialize to JSON string
        let json_str = serde_json::to_string(&request.content).map_err(|e| {
            AdmissionError::SerializationFailed {
                message: e.to_string(),
            }
        })?;

        // Canonicalize
        let canonical = canonicalize_json(&json_str)?;

        // Parse canonical back to Value for validation
        let canonical_value: Value =
            serde_json::from_str(&canonical).map_err(|e| AdmissionError::SerializationFailed {
                message: format!("failed to parse canonical output: {e}"),
            })?;

        // Validate against schema
        validator.validate(&canonical_value)?;

        // Compute hash and store
        let new_hash = hash_bytes(canonical.as_bytes());
        let store_result = self.cas.store(canonical.as_bytes())?;

        // Generate receipt
        let receipt = AdmissionReceipt::new(
            request.dcp_id,
            request.artifact_kind,
            new_hash,
            request.schema_hash,
            store_result.size,
            store_result.is_new,
            None, // No patch hash for create
            None, // No base hash for create
            None, // No patch type for create
        );

        Ok(AdmissionResult {
            receipt,
            canonical_content: canonical,
            change_set_report: None,
        })
    }

    /// Admits a JSON Patch update.
    #[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
    fn admit_json_patch(
        &self,
        dcp_id: String,
        artifact_kind: ArtifactKind,
        schema_hash: String,
        base_document: Value,
        patch: Value,
        expected_base_hash: String,
        validator: &CacValidator,
    ) -> Result<AdmissionResult, AdmissionError> {
        // Apply patch with replay protection
        let patch_result =
            self.patch_engine
                .apply_json_patch(&base_document, &patch, &expected_base_hash)?;

        // SECURITY: Validate patched document complexity BEFORE expensive validation
        // This prevents DoS via patches that produce oversized/deeply-nested results
        validate_input_complexity(&patch_result.patched_document, "patched_result")?;

        // Validate patched document against schema
        validator.validate(&patch_result.patched_document)?;

        // Store in CAS
        let store_result = self.cas.store(patch_result.canonical_output.as_bytes())?;

        // Generate change set report
        let change_set_report = ChangeSetReport::from_json_patch(
            &dcp_id,
            &patch_result.old_hash,
            &patch_result.new_hash,
            &patch_result.patch_hash,
            &patch,
        );

        // Generate receipt
        let receipt = AdmissionReceipt::new(
            dcp_id,
            artifact_kind,
            patch_result.new_hash,
            schema_hash,
            store_result.size,
            store_result.is_new,
            Some(patch_result.patch_hash),
            Some(patch_result.old_hash),
            Some(PatchType::JsonPatch),
        );

        Ok(AdmissionResult {
            receipt,
            canonical_content: patch_result.canonical_output,
            change_set_report: Some(change_set_report),
        })
    }

    /// Admits a Merge Patch update.
    #[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
    fn admit_merge_patch(
        &self,
        dcp_id: String,
        artifact_kind: ArtifactKind,
        schema_hash: String,
        base_document: Value,
        patch: Value,
        expected_base_hash: String,
        validator: &CacValidator,
    ) -> Result<AdmissionResult, AdmissionError> {
        // Apply merge patch with replay protection
        let patch_result =
            self.patch_engine
                .apply_merge_patch(&base_document, &patch, &expected_base_hash)?;

        // SECURITY: Validate patched document complexity BEFORE expensive validation
        // This prevents DoS via patches that produce oversized/deeply-nested results
        validate_input_complexity(&patch_result.patched_document, "patched_result")?;

        // Validate patched document against schema
        validator.validate(&patch_result.patched_document)?;

        // Store in CAS
        let store_result = self.cas.store(patch_result.canonical_output.as_bytes())?;

        // Generate change set report
        let change_set_report = ChangeSetReport::from_merge_patch(
            &dcp_id,
            &patch_result.old_hash,
            &patch_result.new_hash,
            &patch_result.patch_hash,
            &patch,
        );

        // Generate receipt
        let receipt = AdmissionReceipt::new(
            dcp_id,
            artifact_kind,
            patch_result.new_hash,
            schema_hash,
            store_result.size,
            store_result.is_new,
            Some(patch_result.patch_hash),
            Some(patch_result.old_hash),
            Some(PatchType::MergePatch),
        );

        Ok(AdmissionResult {
            receipt,
            canonical_content: patch_result.canonical_output,
            change_set_report: Some(change_set_report),
        })
    }

    /// Retrieves an artifact by its hash.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError::StorageFailed`] if retrieval fails.
    pub fn retrieve(&self, hash: &[u8; 32]) -> Result<Vec<u8>, AdmissionError> {
        self.cas.retrieve(hash).map_err(AdmissionError::from)
    }

    /// Checks if an artifact exists in the CAS.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError::StorageFailed`] if the check fails.
    pub fn exists(&self, hash: &[u8; 32]) -> Result<bool, AdmissionError> {
        self.cas.exists(hash).map_err(AdmissionError::from)
    }
}

/// Computes BLAKE3 hash of bytes, returning hex-encoded string.
fn hash_bytes(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}

/// Computes the BLAKE3 hash of a JSON Schema.
fn compute_schema_hash(schema: &Value) -> String {
    // Canonicalize the schema for deterministic hashing
    let json_str = serde_json::to_string(schema).unwrap_or_default();
    canonicalize_json(&json_str).map_or_else(
        // Fallback to non-canonical hash if canonicalization fails
        |_| hash_bytes(json_str.as_bytes()),
        |canonical| hash_bytes(canonical.as_bytes()),
    )
}

/// Validates a DCP ID for length and character safety.
///
/// # Security
///
/// - Rejects empty DCP IDs
/// - Enforces maximum length of [`MAX_DCP_ID_LENGTH`] (1024 characters)
/// - Rejects control characters (including newlines) to prevent metadata
///   injection
fn validate_dcp_id(dcp_id: &str) -> Result<(), AdmissionError> {
    // Check empty
    if dcp_id.is_empty() {
        return Err(AdmissionError::InvalidDcpId {
            reason: "dcp_id cannot be empty".to_string(),
        });
    }

    // Check length
    if dcp_id.len() > MAX_DCP_ID_LENGTH {
        return Err(AdmissionError::InvalidDcpId {
            reason: format!(
                "dcp_id exceeds maximum length of {} characters (got {})",
                MAX_DCP_ID_LENGTH,
                dcp_id.len()
            ),
        });
    }

    // SECURITY: Check for control characters (including newlines, tabs, etc.)
    // This prevents metadata injection attacks in to_metadata() output
    if let Some(pos) = dcp_id.chars().position(char::is_control) {
        return Err(AdmissionError::InvalidDcpId {
            reason: format!("dcp_id contains control character at position {pos} (not allowed)"),
        });
    }

    Ok(())
}

/// Validates input complexity (depth and size) to prevent `DoS` attacks.
///
/// # Security
///
/// This function MUST be called on all input `Value`s BEFORE any expensive
/// operations (serialization, hashing, schema compilation, etc.) to prevent
/// denial-of-service attacks via:
/// - Deeply nested structures causing stack overflow or exponential processing
/// - Large shallow objects (e.g., 1M keys) causing memory exhaustion
/// - Large arrays causing memory exhaustion
///
/// Uses the same limits as the validator module for consistency.
fn validate_input_complexity(value: &Value, context: &str) -> Result<(), AdmissionError> {
    validate_complexity_recursive(value, 0, context)
}

/// Recursive helper for complexity validation.
fn validate_complexity_recursive(
    value: &Value,
    depth: usize,
    context: &str,
) -> Result<(), AdmissionError> {
    // Check depth limit
    if depth > MAX_DEPTH {
        return Err(AdmissionError::InputComplexityExceeded {
            message: format!("{context} exceeds maximum depth of {MAX_DEPTH} at level {depth}"),
        });
    }

    match value {
        Value::Array(arr) => {
            // Check array size
            if arr.len() > MAX_ARRAY_MEMBERS {
                return Err(AdmissionError::InputComplexityExceeded {
                    message: format!(
                        "{} array has {} members, exceeds limit of {}",
                        context,
                        arr.len(),
                        MAX_ARRAY_MEMBERS
                    ),
                });
            }
            // Recursively check elements
            for item in arr {
                validate_complexity_recursive(item, depth + 1, context)?;
            }
        },
        Value::Object(obj) => {
            // Check object size
            if obj.len() > MAX_OBJECT_PROPERTIES {
                return Err(AdmissionError::InputComplexityExceeded {
                    message: format!(
                        "{} object has {} properties, exceeds limit of {}",
                        context,
                        obj.len(),
                        MAX_OBJECT_PROPERTIES
                    ),
                });
            }
            // Recursively check values
            for val in obj.values() {
                validate_complexity_recursive(val, depth + 1, context)?;
            }
        },
        // Primitives have no complexity concerns
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {},
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::evidence::MemoryCas;

    fn make_gate() -> AdmissionGate<MemoryCas> {
        AdmissionGate::new(MemoryCas::new())
    }

    fn sample_schema() -> Value {
        json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {
                "id": { "type": "string" },
                "version": { "type": "integer" }
            },
            "required": ["id"],
            "unevaluatedProperties": false
        })
    }

    // =========================================================================
    // Create Operation Tests
    // =========================================================================

    #[test]
    fn test_admit_create_success() {
        let gate = make_gate();
        let schema = sample_schema();
        let artifact = json!({"id": "TCK-00132", "version": 1});

        let request = AdmissionRequest::new_artifact(
            "dcp://org/project/ticket/TCK-00132",
            ArtifactKind::Ticket,
            artifact,
            &schema,
        );

        let result = gate.admit(request).unwrap();

        assert_eq!(result.receipt.dcp_id, "dcp://org/project/ticket/TCK-00132");
        assert_eq!(result.receipt.artifact_kind, ArtifactKind::Ticket);
        assert!(!result.receipt.new_hash.is_empty());
        assert_eq!(result.receipt.new_hash.len(), 64); // BLAKE3 hex
        assert_eq!(result.receipt.canonicalizer_id, CANONICALIZER_ID);
        assert_eq!(result.receipt.canonicalizer_version, CANONICALIZER_VERSION);
        assert!(result.receipt.patch_hash.is_none());
        assert!(result.receipt.base_hash.is_none());
        assert!(result.change_set_report.is_none());
    }

    #[test]
    fn test_admit_create_stored_in_cas() {
        let gate = make_gate();
        let schema = sample_schema();
        let artifact = json!({"id": "TCK-00132"});

        let request =
            AdmissionRequest::new_artifact("dcp://test", ArtifactKind::Ticket, artifact, &schema);

        let result = gate.admit(request).unwrap();

        // Verify artifact is stored in CAS
        let hash_bytes: [u8; 32] = hex::decode(&result.receipt.new_hash)
            .unwrap()
            .try_into()
            .unwrap();
        let stored = gate.retrieve(&hash_bytes).unwrap();
        assert_eq!(stored, result.canonical_content.as_bytes());
    }

    #[test]
    fn test_admit_create_validation_failed() {
        let gate = make_gate();
        let schema = sample_schema();
        // Missing required field "id"
        let artifact = json!({"version": 1});

        let request =
            AdmissionRequest::new_artifact("dcp://test", ArtifactKind::Ticket, artifact, &schema);

        let result = gate.admit(request);
        assert!(matches!(result, Err(AdmissionError::ValidationFailed(_))));
    }

    #[test]
    fn test_admit_create_unknown_field_rejected() {
        let gate = make_gate();
        let schema = sample_schema();
        // Extra field "extra" not allowed
        let artifact = json!({"id": "TCK-00132", "extra": "field"});

        let request =
            AdmissionRequest::new_artifact("dcp://test", ArtifactKind::Ticket, artifact, &schema);

        let result = gate.admit(request);
        assert!(matches!(result, Err(AdmissionError::ValidationFailed(_))));
    }

    #[test]
    fn test_admit_create_empty_dcp_id() {
        let gate = make_gate();
        let schema = sample_schema();
        let artifact = json!({"id": "test"});

        let request = AdmissionRequest::new_artifact("", ArtifactKind::Ticket, artifact, &schema);

        let result = gate.admit(request);
        assert!(matches!(result, Err(AdmissionError::InvalidDcpId { .. })));
    }

    #[test]
    fn test_admit_create_deduplication() {
        let gate = make_gate();
        let schema = sample_schema();
        let artifact = json!({"id": "TCK-00132"});

        let request1 = AdmissionRequest::new_artifact(
            "dcp://test1",
            ArtifactKind::Ticket,
            artifact.clone(),
            &schema,
        );
        let request2 =
            AdmissionRequest::new_artifact("dcp://test2", ArtifactKind::Ticket, artifact, &schema);

        let result1 = gate.admit(request1).unwrap();
        let result2 = gate.admit(request2).unwrap();

        assert!(result1.receipt.is_new_content);
        assert!(!result2.receipt.is_new_content);
        assert_eq!(result1.receipt.new_hash, result2.receipt.new_hash);
    }

    // =========================================================================
    // JSON Patch Tests
    // =========================================================================

    #[test]
    fn test_admit_json_patch_success() {
        let gate = make_gate();
        let schema = sample_schema();
        let base = json!({"id": "TCK-00132", "version": 1});
        let patch = json!([{"op": "replace", "path": "/version", "value": 2}]);

        // Get base hash
        let base_str = serde_json::to_string(&base).unwrap();
        let canonical_base = canonicalize_json(&base_str).unwrap();
        let base_hash = hash_bytes(canonical_base.as_bytes());

        let request = AdmissionRequest::new_json_patch(
            "dcp://test",
            ArtifactKind::Ticket,
            base,
            patch,
            &base_hash,
            &schema,
        );

        let result = gate.admit(request).unwrap();

        assert!(result.receipt.patch_hash.is_some());
        assert!(result.receipt.base_hash.is_some());
        assert_eq!(result.receipt.base_hash.as_ref().unwrap(), &base_hash);
        assert!(result.change_set_report.is_some());

        let report = result.change_set_report.unwrap();
        assert_eq!(report.replaces, 1);
        assert!(report.modified_paths.contains(&"/version".to_string()));
    }

    #[test]
    fn test_admit_json_patch_replay_violation() {
        let gate = make_gate();
        let schema = sample_schema();
        let base = json!({"id": "TCK-00132", "version": 1});
        let patch = json!([{"op": "replace", "path": "/version", "value": 2}]);

        // Wrong base hash
        let wrong_hash = "0000000000000000000000000000000000000000000000000000000000000000";

        let request = AdmissionRequest::new_json_patch(
            "dcp://test",
            ArtifactKind::Ticket,
            base,
            patch,
            wrong_hash,
            &schema,
        );

        let result = gate.admit(request);
        assert!(matches!(result, Err(AdmissionError::PatchFailed(_))));
    }

    #[test]
    fn test_admit_json_patch_validation_after_patch() {
        let gate = make_gate();
        let schema = sample_schema();
        let base = json!({"id": "TCK-00132", "version": 1});
        // Patch adds unknown field
        let patch = json!([{"op": "add", "path": "/extra", "value": "field"}]);

        let base_str = serde_json::to_string(&base).unwrap();
        let canonical_base = canonicalize_json(&base_str).unwrap();
        let base_hash = hash_bytes(canonical_base.as_bytes());

        let request = AdmissionRequest::new_json_patch(
            "dcp://test",
            ArtifactKind::Ticket,
            base,
            patch,
            &base_hash,
            &schema,
        );

        let result = gate.admit(request);
        assert!(matches!(result, Err(AdmissionError::ValidationFailed(_))));
    }

    // =========================================================================
    // Merge Patch Tests
    // =========================================================================

    #[test]
    fn test_admit_merge_patch_success() {
        let gate = make_gate();
        let schema = sample_schema();
        let base = json!({"id": "TCK-00132", "version": 1});
        let patch = json!({"version": 2});

        let base_str = serde_json::to_string(&base).unwrap();
        let canonical_base = canonicalize_json(&base_str).unwrap();
        let base_hash = hash_bytes(canonical_base.as_bytes());

        let request = AdmissionRequest::new_merge_patch(
            "dcp://test",
            ArtifactKind::Ticket,
            base,
            patch,
            &base_hash,
            &schema,
        );

        let result = gate.admit(request).unwrap();

        assert!(result.receipt.patch_hash.is_some());
        assert!(result.receipt.base_hash.is_some());
        assert!(result.change_set_report.is_some());

        let report = result.change_set_report.unwrap();
        assert_eq!(report.patch_type, PatchType::MergePatch.to_string());
        assert!(report.modified_paths.contains(&"/version".to_string()));
    }

    #[test]
    fn test_admit_merge_patch_remove_field() {
        let gate = make_gate();
        // Schema without required version
        let schema = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {
                "id": { "type": "string" },
                "optional": { "type": "string" }
            },
            "required": ["id"],
            "unevaluatedProperties": false
        });
        let base = json!({"id": "TCK-00132", "optional": "value"});
        let patch = json!({"optional": null});

        let base_str = serde_json::to_string(&base).unwrap();
        let canonical_base = canonicalize_json(&base_str).unwrap();
        let base_hash = hash_bytes(canonical_base.as_bytes());

        let request = AdmissionRequest::new_merge_patch(
            "dcp://test",
            ArtifactKind::Ticket,
            base,
            patch,
            &base_hash,
            &schema,
        );

        let result = gate.admit(request).unwrap();

        // Verify the optional field was removed
        let canonical: Value = serde_json::from_str(&result.canonical_content).unwrap();
        assert!(canonical.get("optional").is_none());
    }

    // =========================================================================
    // Receipt Tests
    // =========================================================================

    #[test]
    fn test_receipt_serialization() {
        let gate = make_gate();
        let schema = sample_schema();
        let artifact = json!({"id": "TCK-00132"});

        let request =
            AdmissionRequest::new_artifact("dcp://test", ArtifactKind::Ticket, artifact, &schema);

        let result = gate.admit(request).unwrap();

        // Serialize and deserialize
        let json = serde_json::to_string(&result.receipt).unwrap();
        let deserialized: AdmissionReceipt = serde_json::from_str(&json).unwrap();

        assert_eq!(result.receipt.dcp_id, deserialized.dcp_id);
        assert_eq!(result.receipt.new_hash, deserialized.new_hash);
        assert_eq!(
            result.receipt.canonicalizer_id,
            deserialized.canonicalizer_id
        );
    }

    #[test]
    fn test_receipt_metadata() {
        let gate = make_gate();
        let schema = sample_schema();
        let base = json!({"id": "TCK-00132", "version": 1});
        let patch = json!([{"op": "replace", "path": "/version", "value": 2}]);

        let base_str = serde_json::to_string(&base).unwrap();
        let canonical_base = canonicalize_json(&base_str).unwrap();
        let base_hash = hash_bytes(canonical_base.as_bytes());

        let request = AdmissionRequest::new_json_patch(
            "dcp://test",
            ArtifactKind::Ticket,
            base,
            patch,
            &base_hash,
            &schema,
        );

        let result = gate.admit(request).unwrap();
        let metadata = result.receipt.to_metadata();

        assert!(metadata.iter().any(|m| m.starts_with("dcp_id=")));
        assert!(metadata.iter().any(|m| m.starts_with("artifact_kind=")));
        assert!(metadata.iter().any(|m| m.starts_with("schema_hash=")));
        assert!(metadata.iter().any(|m| m.starts_with("canonicalizer_id=")));
        assert!(metadata.iter().any(|m| m.starts_with("patch_hash=")));
        assert!(metadata.iter().any(|m| m.starts_with("base_hash=")));
    }

    // =========================================================================
    // ChangeSetReport Tests
    // =========================================================================

    #[test]
    fn test_change_set_report_json_patch() {
        let patch = json!([
            {"op": "add", "path": "/new", "value": 1},
            {"op": "remove", "path": "/old"},
            {"op": "replace", "path": "/version", "value": 2}
        ]);

        let report =
            ChangeSetReport::from_json_patch("dcp://test", "base123", "new456", "patch789", &patch);

        assert_eq!(report.adds, 1);
        assert_eq!(report.removes, 1);
        assert_eq!(report.replaces, 1);
        assert_eq!(report.modified_paths.len(), 3);
    }

    #[test]
    fn test_change_set_report_merge_patch() {
        let patch = json!({
            "field1": "value1",
            "field2": null,
            "field3": {"nested": true}
        });

        let report = ChangeSetReport::from_merge_patch(
            "dcp://test",
            "base123",
            "new456",
            "patch789",
            &patch,
        );

        assert_eq!(report.modified_paths.len(), 3);
        assert_eq!(report.replaces, 3);
    }

    // =========================================================================
    // ArtifactKind Tests
    // =========================================================================

    #[test]
    fn test_artifact_kind_display() {
        assert_eq!(ArtifactKind::Ticket.to_string(), "ticket");
        assert_eq!(ArtifactKind::Rfc.to_string(), "rfc");
        assert_eq!(ArtifactKind::Prd.to_string(), "prd");
        assert_eq!(ArtifactKind::Policy.to_string(), "policy");
        assert_eq!(ArtifactKind::ContextPack.to_string(), "context_pack");
        assert_eq!(ArtifactKind::Schema.to_string(), "schema");
        assert_eq!(ArtifactKind::Generic.to_string(), "generic");
    }

    #[test]
    fn test_artifact_kind_serialization() {
        assert_eq!(
            serde_json::to_string(&ArtifactKind::Ticket).unwrap(),
            r#""ticket""#
        );
        assert_eq!(
            serde_json::from_str::<ArtifactKind>(r#""rfc""#).unwrap(),
            ArtifactKind::Rfc
        );
    }

    // =========================================================================
    // Integration Tests
    // =========================================================================

    #[test]
    fn test_admission_pipeline_full_flow() {
        let gate = make_gate();
        let schema = sample_schema();

        // Create initial artifact
        let artifact = json!({"id": "TCK-00132", "version": 1});
        let create_request = AdmissionRequest::new_artifact(
            "dcp://test",
            ArtifactKind::Ticket,
            artifact.clone(),
            &schema,
        );
        let create_result = gate.admit(create_request).unwrap();
        assert!(create_result.receipt.is_new_content);

        // Patch the artifact
        let patch = json!([{"op": "replace", "path": "/version", "value": 2}]);
        let patch_request = AdmissionRequest::new_json_patch(
            "dcp://test",
            ArtifactKind::Ticket,
            artifact,
            patch,
            &create_result.receipt.new_hash,
            &schema,
        );
        let patch_result = gate.admit(patch_request).unwrap();

        // Verify hash chain
        assert_eq!(
            patch_result.receipt.base_hash.as_ref().unwrap(),
            &create_result.receipt.new_hash
        );
        assert_ne!(
            patch_result.receipt.new_hash,
            create_result.receipt.new_hash
        );

        // Verify both artifacts in CAS
        let hash1: [u8; 32] = hex::decode(&create_result.receipt.new_hash)
            .unwrap()
            .try_into()
            .unwrap();
        let hash2: [u8; 32] = hex::decode(&patch_result.receipt.new_hash)
            .unwrap()
            .try_into()
            .unwrap();

        assert!(gate.exists(&hash1).unwrap());
        assert!(gate.exists(&hash2).unwrap());
    }

    // =========================================================================
    // Security Negative Tests (TCK-00132)
    // =========================================================================

    #[test]
    fn test_security_large_patch_linear_time() {
        // SECURITY TEST: Verify O(N) performance with 10k+ operations
        // This test ensures the BTreeSet deduplication fix is working
        let num_ops = 10_000;

        // Build a patch with many distinct paths
        let mut ops = Vec::with_capacity(num_ops);
        for i in 0..num_ops {
            ops.push(json!({
                "op": "add",
                "path": format!("/field_{}", i),
                "value": i
            }));
        }
        let patch = Value::Array(ops);

        // Time the report generation
        let start = std::time::Instant::now();
        let report = ChangeSetReport::from_json_patch(
            "dcp://test",
            "base_hash",
            "new_hash",
            "patch_hash",
            &patch,
        );
        let elapsed = start.elapsed();

        // Verify all paths were collected
        assert_eq!(report.adds, num_ops);
        assert_eq!(report.modified_paths.len(), num_ops);

        // With O(N^2) this would take ~10+ seconds for 10k ops
        // With O(N log N) this should complete in <1 second
        assert!(
            elapsed.as_secs() < 1,
            "ChangeSetReport took {elapsed:?}, expected <1s for {num_ops} ops (O(N^2) detected?)"
        );
    }

    #[test]
    fn test_security_deeply_nested_content_rejected() {
        // SECURITY TEST: Verify deeply nested input is rejected early
        let gate = make_gate();
        let schema = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema"
        });

        // Build deeply nested structure (> MAX_DEPTH levels)
        let mut nested = json!({"value": 1});
        for _ in 0..(MAX_DEPTH + 5) {
            nested = json!({"nested": nested});
        }

        let request =
            AdmissionRequest::new_artifact("dcp://test", ArtifactKind::Generic, nested, &schema);

        let result = gate.admit(request);
        assert!(
            matches!(result, Err(AdmissionError::InputComplexityExceeded { .. })),
            "Expected InputComplexityExceeded for deeply nested content, got: {result:?}"
        );
    }

    #[test]
    fn test_security_large_shallow_object_rejected() {
        // SECURITY TEST: Verify large but shallow object (e.g., 1M keys) is rejected
        let gate = make_gate();
        let schema = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema"
        });

        // Build object with more than MAX_OBJECT_PROPERTIES keys
        let mut large_obj = serde_json::Map::new();
        for i in 0..=MAX_OBJECT_PROPERTIES {
            large_obj.insert(format!("key_{i}"), json!(i));
        }
        let content = Value::Object(large_obj);

        let request =
            AdmissionRequest::new_artifact("dcp://test", ArtifactKind::Generic, content, &schema);

        let result = gate.admit(request);
        assert!(
            matches!(result, Err(AdmissionError::InputComplexityExceeded { .. })),
            "Expected InputComplexityExceeded for oversized object, got: {result:?}"
        );
    }

    #[test]
    fn test_security_malicious_schema_complexity_rejected() {
        // SECURITY TEST: Verify maliciously complex schema is rejected
        let gate = make_gate();

        // Build deeply nested schema structure
        let mut nested_schema = json!({"type": "string"});
        for _ in 0..(MAX_DEPTH + 5) {
            nested_schema = json!({
                "type": "object",
                "properties": {
                    "nested": nested_schema
                }
            });
        }

        let content = json!({"id": "test"});
        let request = AdmissionRequest::new_artifact(
            "dcp://test",
            ArtifactKind::Generic,
            content,
            &nested_schema,
        );

        let result = gate.admit(request);
        assert!(
            matches!(result, Err(AdmissionError::InputComplexityExceeded { .. })),
            "Expected InputComplexityExceeded for complex schema, got: {result:?}"
        );
    }

    #[test]
    fn test_security_dcp_id_with_newlines_rejected() {
        // SECURITY TEST: Verify dcp_id with newlines is rejected (metadata injection)
        let gate = make_gate();
        let schema = sample_schema();
        let artifact = json!({"id": "test"});

        // DCP ID with embedded newline
        let malicious_dcp_id = "dcp://test\nevil_key=evil_value";
        let request = AdmissionRequest::new_artifact(
            malicious_dcp_id,
            ArtifactKind::Ticket,
            artifact,
            &schema,
        );

        let result = gate.admit(request);
        assert!(
            matches!(result, Err(AdmissionError::InvalidDcpId { .. })),
            "Expected InvalidDcpId for newline in dcp_id, got: {result:?}"
        );
    }

    #[test]
    fn test_security_dcp_id_with_control_chars_rejected() {
        // SECURITY TEST: Verify dcp_id with control characters is rejected
        let gate = make_gate();
        let schema = sample_schema();
        let artifact = json!({"id": "test"});

        // DCP ID with tab character
        let malicious_dcp_id = "dcp://test\tinjected";
        let request = AdmissionRequest::new_artifact(
            malicious_dcp_id,
            ArtifactKind::Ticket,
            artifact,
            &schema,
        );

        let result = gate.admit(request);
        assert!(
            matches!(result, Err(AdmissionError::InvalidDcpId { .. })),
            "Expected InvalidDcpId for control char in dcp_id, got: {result:?}"
        );
    }

    #[test]
    fn test_security_multi_megabyte_dcp_id_rejected() {
        // SECURITY TEST: Verify multi-megabyte dcp_id is rejected
        let gate = make_gate();
        let schema = sample_schema();
        let artifact = json!({"id": "test"});

        // Create a DCP ID that exceeds MAX_DCP_ID_LENGTH
        let huge_dcp_id = "x".repeat(MAX_DCP_ID_LENGTH + 1);
        let request =
            AdmissionRequest::new_artifact(&huge_dcp_id, ArtifactKind::Ticket, artifact, &schema);

        let result = gate.admit(request);
        assert!(
            matches!(result, Err(AdmissionError::InvalidDcpId { .. })),
            "Expected InvalidDcpId for oversized dcp_id, got: {result:?}"
        );
    }

    #[test]
    fn test_security_patch_producing_oversized_result_rejected() {
        // SECURITY TEST: Verify patch that produces oversized result is rejected
        let gate = make_gate();
        let schema = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema"
        });
        let base = json!({"id": "test"});

        // Compute base hash
        let base_str = serde_json::to_string(&base).unwrap();
        let canonical_base = canonicalize_json(&base_str).unwrap();
        let base_hash = hash_bytes(canonical_base.as_bytes());

        // Create a patch that adds many properties
        let mut ops = Vec::new();
        for i in 0..=MAX_OBJECT_PROPERTIES {
            ops.push(json!({
                "op": "add",
                "path": format!("/prop_{i}"),
                "value": i
            }));
        }
        let patch = Value::Array(ops);

        let request = AdmissionRequest::new_json_patch(
            "dcp://test",
            ArtifactKind::Generic,
            base,
            patch,
            &base_hash,
            &schema,
        );

        let result = gate.admit(request);
        // The result should fail due to input complexity on patched result
        assert!(
            matches!(result, Err(AdmissionError::InputComplexityExceeded { .. })),
            "Expected InputComplexityExceeded for oversized patch result, got: {result:?}"
        );
    }

    #[test]
    fn test_security_constants_defined() {
        // Verify security constants are properly defined
        assert_eq!(MAX_DCP_ID_LENGTH, 1024);
        // Use const assertions to verify limits are positive
        const { assert!(MAX_DEPTH > 0) };
        const { assert!(MAX_OBJECT_PROPERTIES > 0) };
        const { assert!(MAX_ARRAY_MEMBERS > 0) };
    }

    #[test]
    fn test_security_valid_dcp_id_accepted() {
        // Verify valid DCP IDs are still accepted
        let gate = make_gate();
        let schema = sample_schema();
        let artifact = json!({"id": "test"});

        // Normal DCP ID
        let valid_dcp_id = "dcp://org/project/artifact/id-12345";
        let request =
            AdmissionRequest::new_artifact(valid_dcp_id, ArtifactKind::Ticket, artifact, &schema);

        let result = gate.admit(request);
        assert!(result.is_ok(), "Valid dcp_id should be accepted");
    }

    #[test]
    fn test_security_dcp_id_at_max_length_accepted() {
        // Verify DCP ID at exactly MAX_DCP_ID_LENGTH is accepted
        let gate = make_gate();
        let schema = sample_schema();
        let artifact = json!({"id": "test"});

        let max_length_dcp_id = "x".repeat(MAX_DCP_ID_LENGTH);
        let request = AdmissionRequest::new_artifact(
            &max_length_dcp_id,
            ArtifactKind::Ticket,
            artifact,
            &schema,
        );

        let result = gate.admit(request);
        assert!(
            result.is_ok(),
            "DCP ID at MAX_DCP_ID_LENGTH should be accepted"
        );
    }
}
