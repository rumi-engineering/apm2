//! CAS-backed JSON schemas for work lifecycle artifacts (RFC-0032 Phase 1).
//!
//! This module defines the four CAS JSON schemas introduced by RFC-0032 for
//! kernel-native FAC work lifecycle management:
//!
//! - [`WorkSpecV1`] (`apm2.work_spec.v1`): immutable "what is this work?"
//!   document stored in CAS, referenced by `WorkOpened.spec_snapshot_hash`.
//! - [`WorkContextEntryV1`] (`apm2.work_context_entry.v1`): append-only
//!   context/notes entries anchored in the ledger via `evidence.published`.
//! - [`WorkLoopProfileV1`] (`apm2.work_loop_profile.v1`): operational knobs for
//!   implementer retry/nudge/backoff budgets.
//! - [`WorkAuthorityBindingsV1`] (`apm2.work_authority_bindings.v1`): authority
//!   pins eliminating WorkRegistry as an authority source.
//!
//! # Security Properties
//!
//! - **`deny_unknown_fields`**: All structs reject payloads with unexpected
//!   fields, preventing injection of unvalidated data.
//! - **Bounded decoding**: Per-artifact byte limits are enforced *before* JSON
//!   parsing via [`bounded_decode_work_spec`],
//!   [`bounded_decode_context_entry`], [`bounded_decode_loop_profile`], and
//!   [`bounded_decode_authority_bindings`].
//! - **Fail-closed**: Unknown or mismatched schema IDs cause rejection, never
//!   silent acceptance.
//! - **Canonical JSON**: All artifacts must be canonicalized via
//!   `apm2_core::determinism::canonicalize_json` before CAS storage/hashing.
//!
//! # Drift Barriers (RFC-0032 D1/D2)
//!
//! - **D1**: All four schema IDs are registered in `fac_schemas.rs` and pass
//!   uniqueness + prefix tests.
//! - **D2**: Bounded decoding uses `fac_schemas::bounded_from_slice_with_limit`
//!   with explicit per-artifact byte limits defined in this module.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::schema_registry::fac_schemas::{
    BoundedDeserializeError, bounded_from_slice_with_limit, validate_schema_id,
};

// ---------------------------------------------------------------------------
// Schema ID Constants
// ---------------------------------------------------------------------------

/// Schema identifier for [`WorkSpecV1`].
pub const WORK_SPEC_V1_SCHEMA: &str = "apm2.work_spec.v1";

/// Schema identifier for [`WorkContextEntryV1`].
pub const WORK_CONTEXT_ENTRY_V1_SCHEMA: &str = "apm2.work_context_entry.v1";

/// Schema identifier for [`WorkLoopProfileV1`].
pub const WORK_LOOP_PROFILE_V1_SCHEMA: &str = "apm2.work_loop_profile.v1";

/// Schema identifier for [`WorkAuthorityBindingsV1`].
pub const WORK_AUTHORITY_BINDINGS_V1_SCHEMA: &str = "apm2.work_authority_bindings.v1";

// ---------------------------------------------------------------------------
// Per-Artifact Byte Limits (RFC-0032 hard caps)
// ---------------------------------------------------------------------------

/// Maximum payload size for `WorkSpecV1` bounded decoding (256 KiB).
pub const MAX_WORK_SPEC_SIZE: usize = 262_144;

/// Maximum payload size for `WorkContextEntryV1` bounded decoding (256 KiB).
pub const MAX_CONTEXT_ENTRY_SIZE: usize = 262_144;

/// Maximum payload size for `WorkLoopProfileV1` bounded decoding (64 KiB).
pub const MAX_LOOP_PROFILE_SIZE: usize = 65_536;

/// Maximum payload size for `WorkAuthorityBindingsV1` bounded decoding
/// (256 KiB).
pub const MAX_AUTHORITY_BINDINGS_SIZE: usize = 262_144;

// ---------------------------------------------------------------------------
// Field Length Limits
// ---------------------------------------------------------------------------

/// Maximum length for `work_id` fields across all work CAS schemas.
pub const MAX_WORK_ID_LENGTH: usize = 256;

/// Maximum length for short string fields (IDs, roles, types, etc.).
pub const MAX_SHORT_STRING_LENGTH: usize = 256;

/// Maximum length for medium string fields (titles, summaries, etc.).
pub const MAX_MEDIUM_STRING_LENGTH: usize = 1024;

/// Maximum length for long string fields (descriptions, body text, etc.).
pub const MAX_LONG_STRING_LENGTH: usize = 8192;

/// Maximum number of labels on a [`WorkSpecV1`].
pub const MAX_LABELS: usize = 64;

/// Maximum number of requirement IDs on a [`WorkSpecV1`].
pub const MAX_REQUIREMENT_IDS: usize = 128;

/// Maximum number of tags on a [`WorkContextEntryV1`].
pub const MAX_TAGS: usize = 64;

/// Maximum length for a single label or tag string.
pub const MAX_TAG_LENGTH: usize = 128;

/// Maximum number of backoff intervals in a nudge policy.
pub const MAX_BACKOFF_INTERVALS: usize = 32;

/// Maximum number of capability manifest hashes in authority bindings.
pub const MAX_CAPABILITY_HASHES: usize = 32;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from work CAS schema validation.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum WorkCasSchemaError {
    /// Bounded deserialization failed.
    #[error("bounded deserialization failed: {0}")]
    BoundedDecode(#[from] BoundedDeserializeError),

    /// Schema ID mismatch.
    #[error("schema mismatch: expected {expected}, got {actual}")]
    SchemaMismatch {
        /// Expected schema ID.
        expected: String,
        /// Actual schema ID.
        actual: String,
    },

    /// Missing required field.
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// String field exceeds maximum length.
    #[error("field '{field}' exceeds maximum length ({len} > {max})")]
    FieldTooLong {
        /// Field name.
        field: &'static str,
        /// Actual length.
        len: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// Collection field exceeds maximum count.
    #[error("field '{field}' exceeds maximum count ({count} > {max})")]
    CollectionTooLarge {
        /// Field name.
        field: &'static str,
        /// Actual count.
        count: usize,
        /// Maximum allowed count.
        max: usize,
    },

    /// Field value is not in the allowed set.
    #[error("field '{field}' has invalid value '{value}': not in allowed set")]
    InvalidValue {
        /// Field name.
        field: &'static str,
        /// The invalid value.
        value: String,
    },
}

// ---------------------------------------------------------------------------
// WorkSpecType (closed allowlist for work_type)
// ---------------------------------------------------------------------------

/// Closed allowlist of valid `work_type` values for [`WorkSpecV1`].
///
/// Aligned with `apm2_core::work::WorkType`. Unknown variants are rejected
/// at serde decode time (fail-closed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum WorkSpecType {
    /// Implementation of a specific ticket.
    Ticket,
    /// PRD refinement task.
    PrdRefinement,
    /// RFC refinement task.
    RfcRefinement,
    /// Code or artifact review.
    Review,
}

// ---------------------------------------------------------------------------
// WorkSpecV1
// ---------------------------------------------------------------------------

/// Immutable "what is this work?" document stored in CAS (RFC-0032 §4.1).
///
/// Referenced by `WorkOpened.spec_snapshot_hash`. This is the single source
/// of truth for work identity and requirements. Ticket IDs are aliases, not
/// canonical IDs (per RFC-0032 alignment with `alias_reconcile`).
///
/// # Security Properties
///
/// - **Immutable**: once stored in CAS, the spec cannot be modified.
/// - **`deny_unknown_fields`**: extra JSON fields are rejected.
/// - **Bounded decode**: payloads exceeding [`MAX_WORK_SPEC_SIZE`] are rejected
///   before parsing.
/// - **Closed `work_type` allowlist**: only [`WorkSpecType`] variants are
///   accepted; unknown values are rejected at decode time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkSpecV1 {
    /// Schema identifier (must be `apm2.work_spec.v1`).
    pub schema: String,

    /// Canonical work identifier (e.g., `W-<uuid>`).
    pub work_id: String,

    /// Optional ticket alias (e.g., `TCK-00606`). Not the canonical ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket_alias: Option<String>,

    /// Human-readable title.
    pub title: String,

    /// Extended description of the work.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,

    /// Work type discriminant. Only canonical values from [`WorkSpecType`]
    /// are accepted; unknown variants are rejected at decode time.
    pub work_type: WorkSpecType,

    /// Repository identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo: Option<WorkSpecRepo>,

    /// Requirement binding IDs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requirement_ids: Vec<String>,

    /// Classification labels.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<String>,

    /// RFC identifier this work is scoped to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rfc_id: Option<String>,

    /// Parent work IDs (legacy field; edges are preferred per RFC-0032).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parent_work_ids: Vec<String>,

    /// Creation timestamp (nanoseconds since epoch, as string for JSON
    /// compatibility).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at_ns: Option<u64>,
}

/// Repository identity within a [`WorkSpecV1`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkSpecRepo {
    /// Repository owner (e.g., GitHub org name).
    pub owner: String,

    /// Repository name.
    pub name: String,

    /// Default branch (e.g., `main`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_branch: Option<String>,
}

impl WorkSpecV1 {
    /// Validates the work spec after deserialization.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Schema ID does not match [`WORK_SPEC_V1_SCHEMA`]
    /// - Required fields are empty
    /// - String fields exceed their maximum length
    /// - Collection fields exceed their maximum count
    pub fn validate(&self) -> Result<(), WorkCasSchemaError> {
        if self.schema != WORK_SPEC_V1_SCHEMA {
            return Err(WorkCasSchemaError::SchemaMismatch {
                expected: WORK_SPEC_V1_SCHEMA.to_string(),
                actual: self.schema.clone(),
            });
        }

        if self.work_id.is_empty() {
            return Err(WorkCasSchemaError::MissingField("work_id"));
        }
        // Enforce canonical work_id prefix for consistency with the work
        // lifecycle namespace convention (W-<identifier>).
        if !self.work_id.starts_with("W-") {
            return Err(WorkCasSchemaError::InvalidValue {
                field: "work_id",
                value: self.work_id.clone(),
            });
        }
        validate_field_length("work_id", &self.work_id, MAX_WORK_ID_LENGTH)?;
        validate_field_length("title", &self.title, MAX_MEDIUM_STRING_LENGTH)?;
        // work_type is validated at decode time via WorkSpecType enum — no
        // further string validation needed.

        if let Some(ref alias) = self.ticket_alias {
            validate_field_length("ticket_alias", alias, MAX_SHORT_STRING_LENGTH)?;
        }
        if let Some(ref summary) = self.summary {
            validate_field_length("summary", summary, MAX_LONG_STRING_LENGTH)?;
        }
        if let Some(ref rfc_id) = self.rfc_id {
            validate_field_length("rfc_id", rfc_id, MAX_SHORT_STRING_LENGTH)?;
        }
        if let Some(ref repo) = self.repo {
            validate_field_length("repo.owner", &repo.owner, MAX_SHORT_STRING_LENGTH)?;
            validate_field_length("repo.name", &repo.name, MAX_SHORT_STRING_LENGTH)?;
            if let Some(ref branch) = repo.default_branch {
                validate_field_length("repo.default_branch", branch, MAX_SHORT_STRING_LENGTH)?;
            }
        }

        validate_collection_size("labels", self.labels.len(), MAX_LABELS)?;
        for label in &self.labels {
            validate_field_length("labels[]", label, MAX_TAG_LENGTH)?;
        }

        validate_collection_size(
            "requirement_ids",
            self.requirement_ids.len(),
            MAX_REQUIREMENT_IDS,
        )?;
        for req in &self.requirement_ids {
            validate_field_length("requirement_ids[]", req, MAX_SHORT_STRING_LENGTH)?;
        }

        validate_collection_size(
            "parent_work_ids",
            self.parent_work_ids.len(),
            MAX_REQUIREMENT_IDS,
        )?;
        for parent in &self.parent_work_ids {
            validate_field_length("parent_work_ids[]", parent, MAX_WORK_ID_LENGTH)?;
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// WorkContextKind (closed allowlist for context entry kind)
// ---------------------------------------------------------------------------

/// Closed allowlist of valid `kind` values for [`WorkContextEntryV1`].
///
/// RFC-0032 mandates a closed set of context entry kinds. Unknown variants
/// are rejected at serde decode time (fail-closed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum WorkContextKind {
    /// Handoff notes for implementer transitions.
    HandoffNote,
    /// Implementer terminal output / session summary.
    ImplementerTerminal,
    /// Diagnostic analysis or root-cause notes.
    Diagnosis,
    /// Individual review finding (BLOCKER/MAJOR/MINOR/NIT).
    ReviewFinding,
    /// Aggregate review verdict (APPROVE/DENY).
    ReviewVerdict,
    /// Gate lifecycle note (push/CI/merge-gate).
    GateNote,
    /// External link reference.
    Linkout,
}

// ---------------------------------------------------------------------------
// WorkContextEntryV1
// ---------------------------------------------------------------------------

/// Append-only context/notes entry anchored in the ledger (RFC-0032 §4.3).
///
/// Stored in CAS; anchored by `evidence.published` with category
/// `WORK_CONTEXT_ENTRY`. Supports handoff notes, reviewer findings,
/// diagnostics, and linkouts.
///
/// # Security Properties
///
/// - **Immutable**: once stored in CAS, the entry cannot be modified.
/// - **Deduplication**: entries are deduplicated by `(work_id, kind,
///   dedupe_key)`.
/// - **`deny_unknown_fields`**: extra JSON fields are rejected.
/// - **Closed kind allowlist**: only [`WorkContextKind`] variants are accepted;
///   unknown values are rejected at decode time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkContextEntryV1 {
    /// Schema identifier (must be `apm2.work_context_entry.v1`).
    pub schema: String,

    /// Canonical work identifier.
    pub work_id: String,

    /// Unique entry identifier (e.g., `CTX-<blake3>`).
    pub entry_id: String,

    /// Entry kind discriminant. Only canonical values from
    /// [`WorkContextKind`] are accepted; unknown variants are rejected at
    /// decode time.
    pub kind: WorkContextKind,

    /// Deduplication key for idempotent publishing.
    pub dedupe_key: String,

    /// Session that produced this entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_session_id: Option<String>,

    /// Actor that authored this entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<String>,

    /// Entry body text/content.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,

    /// Structured metadata (key-value pairs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,

    /// Classification tags.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,

    /// Creation timestamp (nanoseconds since epoch).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at_ns: Option<u64>,
}

impl WorkContextEntryV1 {
    /// Validates the context entry after deserialization.
    ///
    /// # Errors
    ///
    /// Returns error if validation constraints are violated.
    pub fn validate(&self) -> Result<(), WorkCasSchemaError> {
        if self.schema != WORK_CONTEXT_ENTRY_V1_SCHEMA {
            return Err(WorkCasSchemaError::SchemaMismatch {
                expected: WORK_CONTEXT_ENTRY_V1_SCHEMA.to_string(),
                actual: self.schema.clone(),
            });
        }

        if self.work_id.is_empty() {
            return Err(WorkCasSchemaError::MissingField("work_id"));
        }
        validate_field_length("work_id", &self.work_id, MAX_WORK_ID_LENGTH)?;

        if self.entry_id.is_empty() {
            return Err(WorkCasSchemaError::MissingField("entry_id"));
        }
        validate_field_length("entry_id", &self.entry_id, MAX_SHORT_STRING_LENGTH)?;

        // kind is validated at decode time via WorkContextKind enum — no
        // further string validation needed.

        if self.dedupe_key.is_empty() {
            return Err(WorkCasSchemaError::MissingField("dedupe_key"));
        }
        validate_field_length("dedupe_key", &self.dedupe_key, MAX_SHORT_STRING_LENGTH)?;

        if let Some(ref session_id) = self.source_session_id {
            validate_field_length("source_session_id", session_id, MAX_SHORT_STRING_LENGTH)?;
        }
        if let Some(ref actor) = self.actor_id {
            validate_field_length("actor_id", actor, MAX_SHORT_STRING_LENGTH)?;
        }
        if let Some(ref body) = self.body {
            validate_field_length("body", body, MAX_LONG_STRING_LENGTH)?;
        }

        validate_collection_size("tags", self.tags.len(), MAX_TAGS)?;
        for tag in &self.tags {
            validate_field_length("tags[]", tag, MAX_TAG_LENGTH)?;
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// WorkLoopProfileV1
// ---------------------------------------------------------------------------

/// Operational knobs for implementer retry/nudge/backoff (RFC-0032 §4.2).
///
/// Stored in CAS; referenced by claim/session dispatch events. This is
/// operational tuning, not privilege escalation. CAS is immutable; "mutable"
/// means a newer profile hash can be published and selected.
///
/// # Security Rule
///
/// `WorkLoopProfileV1` cannot override the role spec / capability manifest /
/// adapter profile constraints resolved by policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkLoopProfileV1 {
    /// Schema identifier (must be `apm2.work_loop_profile.v1`).
    pub schema: String,

    /// Canonical work identifier.
    pub work_id: String,

    /// Workspace configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace: Option<WorkspaceConfig>,

    /// Retry budget configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry: Option<RetryConfig>,

    /// Nudge policy configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nudge_policy: Option<NudgePolicy>,
}

/// Workspace configuration within a [`WorkLoopProfileV1`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceConfig {
    /// Workspace strategy (e.g., `git_worktree`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy: Option<String>,

    /// Root directory for workspaces.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,

    /// Whether to reuse workspace per work item.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reuse_per_work: Option<bool>,
}

/// Retry configuration within a [`WorkLoopProfileV1`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetryConfig {
    /// Maximum number of implementer attempts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_implementer_attempts: Option<u32>,

    /// Maximum number of review rounds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_review_rounds: Option<u32>,

    /// Backoff intervals in seconds.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub backoff_seconds: Vec<u64>,
}

/// Nudge policy within a [`WorkLoopProfileV1`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NudgePolicy {
    /// Maximum number of nudges before escalation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_nudges: Option<u32>,

    /// Backoff intervals for nudges in seconds.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub backoff_seconds: Vec<u64>,
}

impl WorkLoopProfileV1 {
    /// Validates the loop profile after deserialization.
    ///
    /// # Errors
    ///
    /// Returns error if validation constraints are violated.
    pub fn validate(&self) -> Result<(), WorkCasSchemaError> {
        if self.schema != WORK_LOOP_PROFILE_V1_SCHEMA {
            return Err(WorkCasSchemaError::SchemaMismatch {
                expected: WORK_LOOP_PROFILE_V1_SCHEMA.to_string(),
                actual: self.schema.clone(),
            });
        }

        if self.work_id.is_empty() {
            return Err(WorkCasSchemaError::MissingField("work_id"));
        }
        validate_field_length("work_id", &self.work_id, MAX_WORK_ID_LENGTH)?;

        if let Some(ref ws) = self.workspace {
            if let Some(ref strategy) = ws.strategy {
                validate_field_length("workspace.strategy", strategy, MAX_SHORT_STRING_LENGTH)?;
            }
            if let Some(ref root) = ws.root {
                validate_field_length("workspace.root", root, MAX_MEDIUM_STRING_LENGTH)?;
            }
        }

        if let Some(ref retry) = self.retry {
            validate_collection_size(
                "retry.backoff_seconds",
                retry.backoff_seconds.len(),
                MAX_BACKOFF_INTERVALS,
            )?;
        }

        if let Some(ref nudge) = self.nudge_policy {
            validate_collection_size(
                "nudge_policy.backoff_seconds",
                nudge.backoff_seconds.len(),
                MAX_BACKOFF_INTERVALS,
            )?;
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// WorkAuthorityBindingsV1
// ---------------------------------------------------------------------------

/// Authority pins eliminating `WorkRegistry` as authority source (RFC-0032
/// §4.4).
///
/// Stored in CAS; anchored by `evidence.published` with category
/// `WORK_AUTHORITY_BINDINGS`. Contains authority-relevant material for
/// `handle_spawn_episode` to be implementable purely as "read projections +
/// fetch CAS artifacts."
///
/// # Security Properties
///
/// - **Fail-closed**: missing authority pins prevent episode spawning.
/// - **Immutable**: once stored, bindings cannot be modified (new versions are
///   published as separate CAS documents).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkAuthorityBindingsV1 {
    /// Schema identifier (must be `apm2.work_authority_bindings.v1`).
    pub schema: String,

    /// Canonical work identifier.
    pub work_id: String,

    /// Role for which these bindings apply (e.g., `IMPLEMENTER`, `REVIEWER`).
    pub role: String,

    /// Lease identifier binding this authority grant.
    pub lease_id: String,

    /// Actor identifier.
    pub actor_id: String,

    /// Claim timestamp (nanoseconds since epoch).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claimed_at_ns: Option<u64>,

    /// Hash of the adapter profile used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adapter_profile_hash: Option<String>,

    /// Hash of the resolved policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_resolution_hash: Option<String>,

    /// Hash of the capability manifest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_manifest_hash: Option<String>,

    /// Hash of the context pack.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_pack_hash: Option<String>,

    /// Hash of the stop condition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop_condition_hash: Option<String>,

    /// Hash of the typed budget contract.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub typed_budget_contract_hash: Option<String>,

    /// Hash of the permeability receipt (optional per RFC-0018 §6.3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permeability_receipt_hash: Option<String>,

    /// Release timestamp (nanoseconds since epoch, set when authority is
    /// released).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub released_at_ns: Option<u64>,
}

impl WorkAuthorityBindingsV1 {
    /// Validates the authority bindings after deserialization.
    ///
    /// # Errors
    ///
    /// Returns error if validation constraints are violated.
    pub fn validate(&self) -> Result<(), WorkCasSchemaError> {
        if self.schema != WORK_AUTHORITY_BINDINGS_V1_SCHEMA {
            return Err(WorkCasSchemaError::SchemaMismatch {
                expected: WORK_AUTHORITY_BINDINGS_V1_SCHEMA.to_string(),
                actual: self.schema.clone(),
            });
        }

        if self.work_id.is_empty() {
            return Err(WorkCasSchemaError::MissingField("work_id"));
        }
        validate_field_length("work_id", &self.work_id, MAX_WORK_ID_LENGTH)?;

        if self.role.is_empty() {
            return Err(WorkCasSchemaError::MissingField("role"));
        }
        validate_field_length("role", &self.role, MAX_SHORT_STRING_LENGTH)?;

        if self.lease_id.is_empty() {
            return Err(WorkCasSchemaError::MissingField("lease_id"));
        }
        validate_field_length("lease_id", &self.lease_id, MAX_SHORT_STRING_LENGTH)?;

        if self.actor_id.is_empty() {
            return Err(WorkCasSchemaError::MissingField("actor_id"));
        }
        validate_field_length("actor_id", &self.actor_id, MAX_SHORT_STRING_LENGTH)?;

        // RFC-0032 §2.5 / RFC-0018 §6.3 mandatory boundary pins.
        // Fail-closed: every required pin must be present and non-empty.
        for (name, field) in [
            ("permeability_receipt_hash", &self.permeability_receipt_hash),
            ("capability_manifest_hash", &self.capability_manifest_hash),
            ("context_pack_hash", &self.context_pack_hash),
            ("stop_condition_hash", &self.stop_condition_hash),
        ] {
            match field {
                None => return Err(WorkCasSchemaError::MissingField(name)),
                Some(v) if v.is_empty() => {
                    return Err(WorkCasSchemaError::MissingField(name));
                },
                _ => {},
            }
        }

        // Validate all hash fields (mandatory + optional) for length.
        for (name, field) in [
            ("adapter_profile_hash", &self.adapter_profile_hash),
            ("policy_resolution_hash", &self.policy_resolution_hash),
            ("capability_manifest_hash", &self.capability_manifest_hash),
            ("context_pack_hash", &self.context_pack_hash),
            ("stop_condition_hash", &self.stop_condition_hash),
            (
                "typed_budget_contract_hash",
                &self.typed_budget_contract_hash,
            ),
            ("permeability_receipt_hash", &self.permeability_receipt_hash),
        ] {
            if let Some(hash) = field {
                validate_field_length(name, hash, MAX_SHORT_STRING_LENGTH)?;
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Bounded Decode Helpers
// ---------------------------------------------------------------------------

/// Decode and validate a [`WorkSpecV1`] from raw bytes with bounded size
/// enforcement.
///
/// Uses [`MAX_WORK_SPEC_SIZE`] (256 KiB) as the hard cap per RFC-0032.
///
/// # Errors
///
/// - [`WorkCasSchemaError::BoundedDecode`] if payload is empty, oversized, or
///   malformed JSON.
/// - [`WorkCasSchemaError::SchemaMismatch`] if schema ID does not match.
/// - Other validation errors from [`WorkSpecV1::validate`].
pub fn bounded_decode_work_spec(data: &[u8]) -> Result<WorkSpecV1, WorkCasSchemaError> {
    let spec: WorkSpecV1 = bounded_from_slice_with_limit(data, MAX_WORK_SPEC_SIZE)?;
    validate_schema_id(WORK_SPEC_V1_SCHEMA, &spec.schema)?;
    spec.validate()?;
    Ok(spec)
}

/// Decode and validate a [`WorkContextEntryV1`] from raw bytes with bounded
/// size enforcement.
///
/// Uses [`MAX_CONTEXT_ENTRY_SIZE`] (256 KiB) as the hard cap per RFC-0032.
///
/// # Errors
///
/// See [`bounded_decode_work_spec`] for error conditions.
pub fn bounded_decode_context_entry(data: &[u8]) -> Result<WorkContextEntryV1, WorkCasSchemaError> {
    let entry: WorkContextEntryV1 = bounded_from_slice_with_limit(data, MAX_CONTEXT_ENTRY_SIZE)?;
    validate_schema_id(WORK_CONTEXT_ENTRY_V1_SCHEMA, &entry.schema)?;
    entry.validate()?;
    Ok(entry)
}

/// Decode and validate a [`WorkLoopProfileV1`] from raw bytes with bounded
/// size enforcement.
///
/// Uses [`MAX_LOOP_PROFILE_SIZE`] (64 KiB) as the hard cap per RFC-0032.
///
/// # Errors
///
/// See [`bounded_decode_work_spec`] for error conditions.
pub fn bounded_decode_loop_profile(data: &[u8]) -> Result<WorkLoopProfileV1, WorkCasSchemaError> {
    let profile: WorkLoopProfileV1 = bounded_from_slice_with_limit(data, MAX_LOOP_PROFILE_SIZE)?;
    validate_schema_id(WORK_LOOP_PROFILE_V1_SCHEMA, &profile.schema)?;
    profile.validate()?;
    Ok(profile)
}

/// Decode and validate a [`WorkAuthorityBindingsV1`] from raw bytes with
/// bounded size enforcement.
///
/// Uses [`MAX_AUTHORITY_BINDINGS_SIZE`] (256 KiB) as the hard cap per
/// RFC-0032.
///
/// # Errors
///
/// See [`bounded_decode_work_spec`] for error conditions.
pub fn bounded_decode_authority_bindings(
    data: &[u8],
) -> Result<WorkAuthorityBindingsV1, WorkCasSchemaError> {
    let bindings: WorkAuthorityBindingsV1 =
        bounded_from_slice_with_limit(data, MAX_AUTHORITY_BINDINGS_SIZE)?;
    validate_schema_id(WORK_AUTHORITY_BINDINGS_V1_SCHEMA, &bindings.schema)?;
    bindings.validate()?;
    Ok(bindings)
}

// ---------------------------------------------------------------------------
// Canonicalization Helper
// ---------------------------------------------------------------------------

/// Canonicalize a work CAS schema artifact's JSON bytes for hashing/storage.
///
/// Uses `apm2_core::determinism::canonicalize_json` to produce deterministic
/// canonical JSON output (RFC 8785 JCS profile with CAC constraints).
///
/// # Errors
///
/// Returns [`WorkCasSchemaError::BoundedDecode`] wrapping a
/// canonicalization failure if the input is not valid canonical JSON.
pub fn canonicalize_for_cas(json_str: &str) -> Result<String, WorkCasSchemaError> {
    crate::determinism::canonicalize_json(json_str).map_err(|e| {
        WorkCasSchemaError::BoundedDecode(BoundedDeserializeError::CanonicalizationFailed {
            message: e.to_string(),
        })
    })
}

// ---------------------------------------------------------------------------
// Internal Helpers
// ---------------------------------------------------------------------------

const fn validate_field_length(
    field: &'static str,
    value: &str,
    max: usize,
) -> Result<(), WorkCasSchemaError> {
    if value.len() > max {
        return Err(WorkCasSchemaError::FieldTooLong {
            field,
            len: value.len(),
            max,
        });
    }
    Ok(())
}

const fn validate_collection_size(
    field: &'static str,
    count: usize,
    max: usize,
) -> Result<(), WorkCasSchemaError> {
    if count > max {
        return Err(WorkCasSchemaError::CollectionTooLarge { field, count, max });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ===================================================================
    // WorkSpecV1 tests
    // ===================================================================

    fn valid_work_spec_json() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schema": WORK_SPEC_V1_SCHEMA,
            "work_id": "W-550e8400-e29b-41d4-a716-446655440000",
            "ticket_alias": "TCK-00633",
            "title": "RFC-0032 Phase 1: CAS schemas",
            "summary": "Add WorkSpec, ContextEntry, LoopProfile, AuthorityBindings schemas.",
            "work_type": "TICKET",
            "repo": {
                "owner": "guardian-intelligence",
                "name": "apm2"
            },
            "requirement_ids": ["REQ-001"],
            "labels": ["fac", "kernel"]
        }))
        .expect("valid json")
    }

    #[test]
    fn tck_00633_work_spec_bounded_decode_success() {
        let data = valid_work_spec_json();
        let spec = bounded_decode_work_spec(&data).expect("decode should succeed");
        assert_eq!(spec.schema, WORK_SPEC_V1_SCHEMA);
        assert_eq!(spec.work_id, "W-550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(spec.title, "RFC-0032 Phase 1: CAS schemas");
        assert_eq!(spec.work_type, WorkSpecType::Ticket);
        assert_eq!(spec.ticket_alias.as_deref(), Some("TCK-00633"));
        assert_eq!(spec.labels.len(), 2);
    }

    #[test]
    fn tck_00633_work_spec_rejects_oversized_payload() {
        let mut data = vec![b' '; MAX_WORK_SPEC_SIZE + 1];
        let payload = valid_work_spec_json();
        data[..payload.len()].copy_from_slice(&payload);
        let result = bounded_decode_work_spec(&data);
        assert!(
            matches!(
                result,
                Err(WorkCasSchemaError::BoundedDecode(
                    BoundedDeserializeError::PayloadTooLarge { .. }
                ))
            ),
            "oversized work spec should be rejected, got: {result:?}"
        );
    }

    #[test]
    fn tck_00633_work_spec_rejects_empty_payload() {
        let result = bounded_decode_work_spec(b"");
        assert!(
            matches!(
                result,
                Err(WorkCasSchemaError::BoundedDecode(
                    BoundedDeserializeError::EmptyPayload
                ))
            ),
            "empty payload should be rejected"
        );
    }

    #[test]
    fn tck_00633_work_spec_rejects_unknown_fields() {
        let data = serde_json::to_vec(&serde_json::json!({
            "schema": WORK_SPEC_V1_SCHEMA,
            "work_id": "W-001",
            "title": "Test",
            "work_type": "TICKET",
            "unknown_extra_field": "injected"
        }))
        .expect("valid json");
        let result = bounded_decode_work_spec(&data);
        assert!(
            result.is_err(),
            "unknown fields should be rejected by deny_unknown_fields"
        );
    }

    #[test]
    fn tck_00633_work_spec_rejects_wrong_schema() {
        let data = serde_json::to_vec(&serde_json::json!({
            "schema": "apm2.wrong_schema.v1",
            "work_id": "W-001",
            "title": "Test",
            "work_type": "TICKET"
        }))
        .expect("valid json");
        let result = bounded_decode_work_spec(&data);
        assert!(
            matches!(
                result,
                Err(WorkCasSchemaError::BoundedDecode(
                    BoundedDeserializeError::DeserializationFailed { .. }
                ))
            ),
            "wrong schema should be rejected, got: {result:?}"
        );
    }

    #[test]
    fn tck_00633_work_spec_rejects_empty_work_id() {
        let data = serde_json::to_vec(&serde_json::json!({
            "schema": WORK_SPEC_V1_SCHEMA,
            "work_id": "",
            "title": "Test",
            "work_type": "TICKET"
        }))
        .expect("valid json");
        let result = bounded_decode_work_spec(&data);
        assert!(
            matches!(result, Err(WorkCasSchemaError::MissingField("work_id"))),
            "empty work_id should be rejected, got: {result:?}"
        );
    }

    #[test]
    fn tck_00635_work_spec_rejects_work_id_without_w_prefix() {
        let data = serde_json::to_vec(&serde_json::json!({
            "schema": WORK_SPEC_V1_SCHEMA,
            "work_id": "bad-work-id-001",
            "title": "Test",
            "work_type": "TICKET"
        }))
        .expect("valid json");
        let result = bounded_decode_work_spec(&data);
        assert!(
            matches!(
                result,
                Err(WorkCasSchemaError::InvalidValue {
                    field: "work_id",
                    ..
                })
            ),
            "work_id without 'W-' prefix should be rejected, got: {result:?}"
        );
    }

    // ===================================================================
    // WorkContextEntryV1 tests
    // ===================================================================

    fn valid_context_entry_json() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schema": WORK_CONTEXT_ENTRY_V1_SCHEMA,
            "work_id": "W-001",
            "entry_id": "CTX-abc123",
            "kind": "HANDOFF_NOTE",
            "dedupe_key": "session:S-001",
            "source_session_id": "S-001",
            "actor_id": "actor:test",
            "body": "Handoff notes for next implementer.",
            "tags": ["fac", "handoff"]
        }))
        .expect("valid json")
    }

    #[test]
    fn tck_00633_context_entry_bounded_decode_success() {
        let data = valid_context_entry_json();
        let entry = bounded_decode_context_entry(&data).expect("decode should succeed");
        assert_eq!(entry.schema, WORK_CONTEXT_ENTRY_V1_SCHEMA);
        assert_eq!(entry.work_id, "W-001");
        assert_eq!(entry.kind, WorkContextKind::HandoffNote);
        assert_eq!(entry.dedupe_key, "session:S-001");
    }

    #[test]
    fn tck_00633_context_entry_rejects_oversized_payload() {
        let mut data = vec![b' '; MAX_CONTEXT_ENTRY_SIZE + 1];
        let payload = valid_context_entry_json();
        data[..payload.len()].copy_from_slice(&payload);
        let result = bounded_decode_context_entry(&data);
        assert!(
            matches!(
                result,
                Err(WorkCasSchemaError::BoundedDecode(
                    BoundedDeserializeError::PayloadTooLarge { .. }
                ))
            ),
            "oversized context entry should be rejected"
        );
    }

    #[test]
    fn tck_00633_context_entry_rejects_unknown_fields() {
        let data = serde_json::to_vec(&serde_json::json!({
            "schema": WORK_CONTEXT_ENTRY_V1_SCHEMA,
            "work_id": "W-001",
            "entry_id": "CTX-001",
            "kind": "HANDOFF_NOTE",
            "dedupe_key": "session:S-001",
            "injected_field": true
        }))
        .expect("valid json");
        let result = bounded_decode_context_entry(&data);
        assert!(result.is_err(), "unknown fields should be rejected");
    }

    #[test]
    fn tck_00633_context_entry_rejects_empty_dedupe_key() {
        let data = serde_json::to_vec(&serde_json::json!({
            "schema": WORK_CONTEXT_ENTRY_V1_SCHEMA,
            "work_id": "W-001",
            "entry_id": "CTX-001",
            "kind": "HANDOFF_NOTE",
            "dedupe_key": ""
        }))
        .expect("valid json");
        let result = bounded_decode_context_entry(&data);
        assert!(
            matches!(result, Err(WorkCasSchemaError::MissingField("dedupe_key"))),
            "empty dedupe_key should be rejected, got: {result:?}"
        );
    }

    // ===================================================================
    // WorkLoopProfileV1 tests
    // ===================================================================

    fn valid_loop_profile_json() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schema": WORK_LOOP_PROFILE_V1_SCHEMA,
            "work_id": "W-001",
            "workspace": {
                "strategy": "git_worktree",
                "root": "~/.apm2/worktrees",
                "reuse_per_work": true
            },
            "retry": {
                "max_implementer_attempts": 20,
                "max_review_rounds": 10,
                "backoff_seconds": [60, 300, 900]
            },
            "nudge_policy": {
                "max_nudges": 50,
                "backoff_seconds": [60, 300, 900]
            }
        }))
        .expect("valid json")
    }

    #[test]
    fn tck_00633_loop_profile_bounded_decode_success() {
        let data = valid_loop_profile_json();
        let profile = bounded_decode_loop_profile(&data).expect("decode should succeed");
        assert_eq!(profile.schema, WORK_LOOP_PROFILE_V1_SCHEMA);
        assert_eq!(profile.work_id, "W-001");
        let retry = profile.retry.as_ref().expect("retry config present");
        assert_eq!(retry.max_implementer_attempts, Some(20));
        assert_eq!(retry.backoff_seconds.len(), 3);
    }

    #[test]
    fn tck_00633_loop_profile_rejects_oversized_payload() {
        let mut data = vec![b' '; MAX_LOOP_PROFILE_SIZE + 1];
        let payload = valid_loop_profile_json();
        data[..payload.len()].copy_from_slice(&payload);
        let result = bounded_decode_loop_profile(&data);
        assert!(
            matches!(
                result,
                Err(WorkCasSchemaError::BoundedDecode(
                    BoundedDeserializeError::PayloadTooLarge { .. }
                ))
            ),
            "oversized loop profile should be rejected"
        );
    }

    #[test]
    fn tck_00633_loop_profile_rejects_unknown_fields() {
        let data = serde_json::to_vec(&serde_json::json!({
            "schema": WORK_LOOP_PROFILE_V1_SCHEMA,
            "work_id": "W-001",
            "extra_knob": 42
        }))
        .expect("valid json");
        let result = bounded_decode_loop_profile(&data);
        assert!(result.is_err(), "unknown fields should be rejected");
    }

    #[test]
    fn tck_00633_loop_profile_smaller_limit_than_other_schemas() {
        // Verify the 64 KiB limit is enforced (smaller than 256 KiB for others).
        assert_eq!(MAX_LOOP_PROFILE_SIZE, 65_536);
        assert_eq!(MAX_WORK_SPEC_SIZE, 262_144);
        const { assert!(MAX_LOOP_PROFILE_SIZE < MAX_WORK_SPEC_SIZE) };
    }

    // ===================================================================
    // WorkAuthorityBindingsV1 tests
    // ===================================================================

    fn valid_authority_bindings_json() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schema": WORK_AUTHORITY_BINDINGS_V1_SCHEMA,
            "work_id": "W-001",
            "role": "IMPLEMENTER",
            "lease_id": "L-550e8400",
            "actor_id": "actor:uid:1000:gid:1000",
            "claimed_at_ns": 1_704_067_200_000_000_000_u64,
            "adapter_profile_hash": "a".repeat(64),
            "policy_resolution_hash": "b".repeat(64),
            "capability_manifest_hash": "c".repeat(64),
            "context_pack_hash": "d".repeat(64),
            "stop_condition_hash": "e".repeat(64),
            "permeability_receipt_hash": "f".repeat(64)
        }))
        .expect("valid json")
    }

    #[test]
    fn tck_00633_authority_bindings_bounded_decode_success() {
        let data = valid_authority_bindings_json();
        let bindings = bounded_decode_authority_bindings(&data).expect("decode should succeed");
        assert_eq!(bindings.schema, WORK_AUTHORITY_BINDINGS_V1_SCHEMA);
        assert_eq!(bindings.work_id, "W-001");
        assert_eq!(bindings.role, "IMPLEMENTER");
        assert_eq!(bindings.lease_id, "L-550e8400");
        assert_eq!(bindings.actor_id, "actor:uid:1000:gid:1000");
    }

    #[test]
    fn tck_00633_authority_bindings_rejects_oversized_payload() {
        let mut data = vec![b' '; MAX_AUTHORITY_BINDINGS_SIZE + 1];
        let payload = valid_authority_bindings_json();
        data[..payload.len()].copy_from_slice(&payload);
        let result = bounded_decode_authority_bindings(&data);
        assert!(
            matches!(
                result,
                Err(WorkCasSchemaError::BoundedDecode(
                    BoundedDeserializeError::PayloadTooLarge { .. }
                ))
            ),
            "oversized authority bindings should be rejected"
        );
    }

    #[test]
    fn tck_00633_authority_bindings_rejects_unknown_fields() {
        let data = serde_json::to_vec(&serde_json::json!({
            "schema": WORK_AUTHORITY_BINDINGS_V1_SCHEMA,
            "work_id": "W-001",
            "role": "IMPLEMENTER",
            "lease_id": "L-001",
            "actor_id": "actor:test",
            "permeability_receipt_hash": "f".repeat(64),
            "capability_manifest_hash": "c".repeat(64),
            "context_pack_hash": "d".repeat(64),
            "stop_condition_hash": "e".repeat(64),
            "backdoor_field": "should_be_rejected"
        }))
        .expect("valid json");
        let result = bounded_decode_authority_bindings(&data);
        assert!(result.is_err(), "unknown fields should be rejected");
    }

    #[test]
    fn tck_00633_authority_bindings_rejects_missing_role() {
        let data = serde_json::to_vec(&serde_json::json!({
            "schema": WORK_AUTHORITY_BINDINGS_V1_SCHEMA,
            "work_id": "W-001",
            "role": "",
            "lease_id": "L-001",
            "actor_id": "actor:test",
            "permeability_receipt_hash": "f".repeat(64),
            "capability_manifest_hash": "c".repeat(64),
            "context_pack_hash": "d".repeat(64),
            "stop_condition_hash": "e".repeat(64)
        }))
        .expect("valid json");
        let result = bounded_decode_authority_bindings(&data);
        assert!(
            matches!(result, Err(WorkCasSchemaError::MissingField("role"))),
            "empty role should be rejected, got: {result:?}"
        );
    }

    // ===================================================================
    // Boundary / edge-case tests
    // ===================================================================

    #[test]
    fn tck_00633_work_spec_accepts_at_exact_limit() {
        // Create payload that fits exactly in MAX_WORK_SPEC_SIZE.
        let base = valid_work_spec_json();
        assert!(
            base.len() <= MAX_WORK_SPEC_SIZE,
            "base payload should be within limit"
        );
        // Pad to exactly the limit
        let mut padded = vec![b' '; MAX_WORK_SPEC_SIZE];
        padded[..base.len()].copy_from_slice(&base);
        let result = bounded_decode_work_spec(&padded);
        assert!(
            result.is_ok(),
            "payload at exact limit should be accepted, got: {result:?}"
        );
    }

    #[test]
    fn tck_00633_loop_profile_accepts_at_exact_limit() {
        let base = valid_loop_profile_json();
        assert!(
            base.len() <= MAX_LOOP_PROFILE_SIZE,
            "base payload should be within limit"
        );
        let mut padded = vec![b' '; MAX_LOOP_PROFILE_SIZE];
        padded[..base.len()].copy_from_slice(&base);
        let result = bounded_decode_loop_profile(&padded);
        assert!(
            result.is_ok(),
            "payload at exact limit should be accepted, got: {result:?}"
        );
    }

    #[test]
    fn tck_00633_all_byte_limits_are_correct() {
        // Verify hard caps match RFC-0032 normative values.
        assert_eq!(MAX_WORK_SPEC_SIZE, 262_144, "WorkSpec must be 256 KiB");
        assert_eq!(
            MAX_CONTEXT_ENTRY_SIZE, 262_144,
            "ContextEntry must be 256 KiB"
        );
        assert_eq!(MAX_LOOP_PROFILE_SIZE, 65_536, "LoopProfile must be 64 KiB");
        assert_eq!(
            MAX_AUTHORITY_BINDINGS_SIZE, 262_144,
            "AuthorityBindings must be 256 KiB"
        );
    }

    // ===================================================================
    // Field length validation tests
    // ===================================================================

    #[test]
    fn tck_00633_work_spec_rejects_overly_long_title() {
        let data = serde_json::to_vec(&serde_json::json!({
            "schema": WORK_SPEC_V1_SCHEMA,
            "work_id": "W-001",
            "title": "x".repeat(MAX_MEDIUM_STRING_LENGTH + 1),
            "work_type": "TICKET"
        }))
        .expect("valid json");
        let result = bounded_decode_work_spec(&data);
        assert!(
            matches!(
                result,
                Err(WorkCasSchemaError::FieldTooLong { field: "title", .. })
            ),
            "overly long title should be rejected, got: {result:?}"
        );
    }

    #[test]
    fn tck_00633_context_entry_rejects_too_many_tags() {
        let tags: Vec<String> = (0..=MAX_TAGS).map(|i| format!("tag-{i}")).collect();
        let data = serde_json::to_vec(&serde_json::json!({
            "schema": WORK_CONTEXT_ENTRY_V1_SCHEMA,
            "work_id": "W-001",
            "entry_id": "CTX-001",
            "kind": "HANDOFF_NOTE",
            "dedupe_key": "test",
            "tags": tags
        }))
        .expect("valid json");
        let result = bounded_decode_context_entry(&data);
        assert!(
            matches!(
                result,
                Err(WorkCasSchemaError::CollectionTooLarge { field: "tags", .. })
            ),
            "too many tags should be rejected, got: {result:?}"
        );
    }

    #[test]
    fn tck_00633_loop_profile_rejects_too_many_backoff_intervals() {
        let intervals: Vec<u64> = (0..=MAX_BACKOFF_INTERVALS as u64).collect();
        let data = serde_json::to_vec(&serde_json::json!({
            "schema": WORK_LOOP_PROFILE_V1_SCHEMA,
            "work_id": "W-001",
            "retry": {
                "backoff_seconds": intervals
            }
        }))
        .expect("valid json");
        let result = bounded_decode_loop_profile(&data);
        assert!(
            matches!(
                result,
                Err(WorkCasSchemaError::CollectionTooLarge {
                    field: "retry.backoff_seconds",
                    ..
                })
            ),
            "too many backoff intervals should be rejected, got: {result:?}"
        );
    }

    // ===================================================================
    // Canonicalization tests
    // ===================================================================

    #[test]
    fn tck_00633_canonicalize_for_cas_produces_deterministic_output() {
        let input1 = r#"{"z": 1, "a": 2}"#;
        let input2 = r#"{"a": 2,    "z":1}"#;
        let canon1 = canonicalize_for_cas(input1).expect("canonicalize should succeed");
        let canon2 = canonicalize_for_cas(input2).expect("canonicalize should succeed");
        assert_eq!(canon1, canon2, "canonicalization must be deterministic");
        assert_eq!(canon1, r#"{"a":2,"z":1}"#);
    }

    #[test]
    fn tck_00633_canonicalize_for_cas_rejects_duplicate_keys() {
        let input = r#"{"a": 1, "a": 2}"#;
        let result = canonicalize_for_cas(input);
        assert!(result.is_err(), "duplicate keys should be rejected");
    }

    // ===================================================================
    // Schema constant verification tests
    // ===================================================================

    #[test]
    fn tck_00633_schema_id_constants_have_correct_values() {
        assert_eq!(WORK_SPEC_V1_SCHEMA, "apm2.work_spec.v1");
        assert_eq!(WORK_CONTEXT_ENTRY_V1_SCHEMA, "apm2.work_context_entry.v1");
        assert_eq!(WORK_LOOP_PROFILE_V1_SCHEMA, "apm2.work_loop_profile.v1");
        assert_eq!(
            WORK_AUTHORITY_BINDINGS_V1_SCHEMA,
            "apm2.work_authority_bindings.v1"
        );
    }

    #[test]
    fn tck_00633_all_schema_ids_start_with_apm2_prefix() {
        for id in [
            WORK_SPEC_V1_SCHEMA,
            WORK_CONTEXT_ENTRY_V1_SCHEMA,
            WORK_LOOP_PROFILE_V1_SCHEMA,
            WORK_AUTHORITY_BINDINGS_V1_SCHEMA,
        ] {
            assert!(
                id.starts_with("apm2."),
                "schema id {id} must start with 'apm2.'"
            );
        }
    }

    // ===================================================================
    // Roundtrip serialization tests
    // ===================================================================

    #[test]
    fn tck_00633_work_spec_roundtrip() {
        let data = valid_work_spec_json();
        let spec = bounded_decode_work_spec(&data).expect("decode");
        let reserialized = serde_json::to_vec(&spec).expect("serialize");
        let spec2 = bounded_decode_work_spec(&reserialized).expect("re-decode");
        assert_eq!(spec, spec2, "roundtrip must be lossless");
    }

    #[test]
    fn tck_00633_context_entry_roundtrip() {
        let data = valid_context_entry_json();
        let entry = bounded_decode_context_entry(&data).expect("decode");
        let reserialized = serde_json::to_vec(&entry).expect("serialize");
        let entry2 = bounded_decode_context_entry(&reserialized).expect("re-decode");
        assert_eq!(entry, entry2, "roundtrip must be lossless");
    }

    #[test]
    fn tck_00633_loop_profile_roundtrip() {
        let data = valid_loop_profile_json();
        let profile = bounded_decode_loop_profile(&data).expect("decode");
        let reserialized = serde_json::to_vec(&profile).expect("serialize");
        let profile2 = bounded_decode_loop_profile(&reserialized).expect("re-decode");
        assert_eq!(profile, profile2, "roundtrip must be lossless");
    }

    #[test]
    fn tck_00633_authority_bindings_roundtrip() {
        let data = valid_authority_bindings_json();
        let bindings = bounded_decode_authority_bindings(&data).expect("decode");
        let reserialized = serde_json::to_vec(&bindings).expect("serialize");
        let bindings2 = bounded_decode_authority_bindings(&reserialized).expect("re-decode");
        assert_eq!(bindings, bindings2, "roundtrip must be lossless");
    }

    // ===================================================================
    // Minimal valid payloads (optional fields omitted)
    // ===================================================================

    #[test]
    fn tck_00633_work_spec_minimal_valid() {
        let data = serde_json::to_vec(&serde_json::json!({
            "schema": WORK_SPEC_V1_SCHEMA,
            "work_id": "W-001",
            "title": "Minimal",
            "work_type": "TICKET"
        }))
        .expect("valid json");
        let spec = bounded_decode_work_spec(&data).expect("minimal spec should decode");
        assert_eq!(spec.work_id, "W-001");
        assert!(spec.ticket_alias.is_none());
        assert!(spec.summary.is_none());
        assert!(spec.repo.is_none());
        assert!(spec.labels.is_empty());
        assert!(spec.requirement_ids.is_empty());
    }

    #[test]
    fn tck_00633_loop_profile_minimal_valid() {
        let data = serde_json::to_vec(&serde_json::json!({
            "schema": WORK_LOOP_PROFILE_V1_SCHEMA,
            "work_id": "W-001"
        }))
        .expect("valid json");
        let profile = bounded_decode_loop_profile(&data).expect("minimal profile should decode");
        assert_eq!(profile.work_id, "W-001");
        assert!(profile.workspace.is_none());
        assert!(profile.retry.is_none());
        assert!(profile.nudge_policy.is_none());
    }

    #[test]
    fn tck_00633_authority_bindings_rejects_missing_mandatory_pins() {
        // RFC-0032 §2.5 / RFC-0018 §6.3: mandatory boundary pins must be
        // present. Omitting any one must fail-closed.
        let mandatory_pins: &[&str] = &[
            "permeability_receipt_hash",
            "capability_manifest_hash",
            "context_pack_hash",
            "stop_condition_hash",
        ];
        for omitted_pin in mandatory_pins {
            let mut obj = serde_json::json!({
                "schema": WORK_AUTHORITY_BINDINGS_V1_SCHEMA,
                "work_id": "W-001",
                "role": "IMPLEMENTER",
                "lease_id": "L-001",
                "actor_id": "actor:test",
                "permeability_receipt_hash": "f".repeat(64),
                "capability_manifest_hash": "c".repeat(64),
                "context_pack_hash": "d".repeat(64),
                "stop_condition_hash": "e".repeat(64),
            });
            obj.as_object_mut().unwrap().remove(*omitted_pin);
            let data = serde_json::to_vec(&obj).expect("valid json");
            let result = bounded_decode_authority_bindings(&data);
            assert!(
                matches!(
                    result,
                    Err(WorkCasSchemaError::MissingField(f)) if f == *omitted_pin
                ),
                "missing '{omitted_pin}' must be rejected, got: {result:?}"
            );
        }
    }

    #[test]
    fn tck_00633_authority_bindings_rejects_empty_mandatory_pin() {
        // An empty string for a mandatory pin must also fail-closed.
        let data = serde_json::to_vec(&serde_json::json!({
            "schema": WORK_AUTHORITY_BINDINGS_V1_SCHEMA,
            "work_id": "W-001",
            "role": "IMPLEMENTER",
            "lease_id": "L-001",
            "actor_id": "actor:test",
            "permeability_receipt_hash": "",
            "capability_manifest_hash": "c".repeat(64),
            "context_pack_hash": "d".repeat(64),
            "stop_condition_hash": "e".repeat(64),
        }))
        .expect("valid json");
        let result = bounded_decode_authority_bindings(&data);
        assert!(
            matches!(
                result,
                Err(WorkCasSchemaError::MissingField(
                    "permeability_receipt_hash"
                ))
            ),
            "empty mandatory pin should be rejected, got: {result:?}"
        );
    }

    // ===================================================================
    // WorkSpecType closed allowlist tests
    // ===================================================================

    #[test]
    fn tck_00633_work_spec_rejects_invalid_work_type() {
        let data = serde_json::to_vec(&serde_json::json!({
            "schema": WORK_SPEC_V1_SCHEMA,
            "work_id": "W-001",
            "title": "Test",
            "work_type": "NOT_A_WORK_TYPE"
        }))
        .expect("valid json");
        let result = bounded_decode_work_spec(&data);
        assert!(
            result.is_err(),
            "unrecognized work_type 'NOT_A_WORK_TYPE' must be rejected, got: {result:?}"
        );
    }

    #[test]
    fn tck_00633_work_spec_accepts_all_canonical_work_types() {
        for wt in ["TICKET", "PRD_REFINEMENT", "RFC_REFINEMENT", "REVIEW"] {
            let data = serde_json::to_vec(&serde_json::json!({
                "schema": WORK_SPEC_V1_SCHEMA,
                "work_id": "W-001",
                "title": "Test",
                "work_type": wt
            }))
            .expect("valid json");
            let result = bounded_decode_work_spec(&data);
            assert!(
                result.is_ok(),
                "canonical work_type '{wt}' must be accepted, got: {result:?}"
            );
        }
    }

    // ===================================================================
    // WorkContextKind closed allowlist tests
    // ===================================================================

    #[test]
    fn tck_00633_context_entry_rejects_unscoped_kind() {
        let data = serde_json::to_vec(&serde_json::json!({
            "schema": WORK_CONTEXT_ENTRY_V1_SCHEMA,
            "work_id": "W-001",
            "entry_id": "CTX-001",
            "kind": "UNSCOPED_KIND",
            "dedupe_key": "test"
        }))
        .expect("valid json");
        let result = bounded_decode_context_entry(&data);
        assert!(
            result.is_err(),
            "unrecognized kind 'UNSCOPED_KIND' must be rejected, got: {result:?}"
        );
    }

    #[test]
    fn tck_00633_context_entry_accepts_all_canonical_kinds() {
        for kind in [
            "HANDOFF_NOTE",
            "IMPLEMENTER_TERMINAL",
            "DIAGNOSIS",
            "REVIEW_FINDING",
            "REVIEW_VERDICT",
            "GATE_NOTE",
            "LINKOUT",
        ] {
            let data = serde_json::to_vec(&serde_json::json!({
                "schema": WORK_CONTEXT_ENTRY_V1_SCHEMA,
                "work_id": "W-001",
                "entry_id": "CTX-001",
                "kind": kind,
                "dedupe_key": "test"
            }))
            .expect("valid json");
            let result = bounded_decode_context_entry(&data);
            assert!(
                result.is_ok(),
                "canonical kind '{kind}' must be accepted, got: {result:?}"
            );
        }
    }
}
