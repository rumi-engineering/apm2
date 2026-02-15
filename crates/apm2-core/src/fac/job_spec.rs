//! FAC Job Spec V1 for worker queueing and validation.
//!
//! - [INV-JS-001] `job_spec_digest` covers all fields except the mutable token.
//! - [INV-JS-002] Digest and request-id checks are constant-time.
//! - [INV-JS-003] Validation is fail-closed.
//! - [INV-JS-004] Boundary structs use `#[serde(deny_unknown_fields)]`.

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use thiserror::Error;

use crate::determinism::canonicalize_json;
use crate::pcac::{BoundaryIntentClass, RiskTier};

// Constants

/// Schema identifier for `FacJobSpecV1`.
pub const JOB_SPEC_SCHEMA_ID: &str = "apm2.fac.job_spec.v1";

/// Maximum length for `job_id`.
pub const MAX_JOB_ID_LENGTH: usize = 256;

/// Maximum length for `kind`.
pub const MAX_KIND_LENGTH: usize = 64;

/// Maximum length for `queue_lane`.
pub const MAX_QUEUE_LANE_LENGTH: usize = 64;

/// Maximum length for `lease_id` in the actuation block.
pub const MAX_LEASE_ID_LENGTH: usize = 256;

/// Maximum length for `request_id` in the actuation block.
pub const MAX_REQUEST_ID_LENGTH: usize = 256;

/// Maximum length for `channel_context_token` (base64-encoded).
/// Tokens are base64 of a signed JSON payload; 16 KiB is generous.
pub const MAX_CHANNEL_CONTEXT_TOKEN_LENGTH: usize = 16_384;

/// Maximum length for `decoded_source` hint.
pub const MAX_DECODED_SOURCE_LENGTH: usize = 64;

/// Maximum length for `repo_id` in the source block.
pub const MAX_REPO_ID_LENGTH: usize = 256;

/// Maximum length for `head_sha` in the source block.
pub const MAX_HEAD_SHA_LENGTH: usize = 128;

/// Maximum length for `source.kind`.
pub const MAX_SOURCE_KIND_LENGTH: usize = 64;

/// Maximum serialized size of a patch payload.
pub const MAX_PATCH_SIZE: usize = 10_485_760;

/// Maximum serialized size of a `FacJobSpecV1` (bytes).
/// Protects against memory-exhaustion attacks during bounded deserialization.
pub const MAX_JOB_SPEC_SIZE: usize = 65_536;

/// Digest prefix for BLAKE3-256 hashes.
const B3_256_PREFIX: &str = "b3-256:";

const VALID_JOB_KINDS: &[&str] = &["gates", "warm", "bulk", "control", "stop_revoke"];
const VALID_SOURCE_KINDS: &[&str] = &["mirror_commit", "patch_injection"];

/// Audited policy exception marker: `stop_revoke` jobs bypass RFC-0028 channel
/// context token and RFC-0029 queue admission.
///
/// **Justification**: Control-lane cancellation originates from the local
/// operator (same trust domain) and requires filesystem-level access proof
/// (queue directory ownership).  A broker-issued token adds no authority
/// beyond what filesystem capability already provides.  All structural and
/// digest validation is still enforced; only the token requirement is waived.
///
/// See [`validate_job_spec_control_lane`] for the full policy exception
/// documentation.
pub const CONTROL_LANE_EXCEPTION_AUDITED: bool = true;

/// Maps job kind to RFC-0029 budget admission keys.
#[must_use]
pub fn job_kind_to_budget_key(kind: &str) -> (RiskTier, BoundaryIntentClass) {
    match kind {
        "gates" | "warm" => (RiskTier::Tier0, BoundaryIntentClass::Actuate),
        "bulk" => (RiskTier::Tier1, BoundaryIntentClass::Actuate),
        "control" | "stop_revoke" => (RiskTier::Tier1, BoundaryIntentClass::Govern),
        _ => (RiskTier::Tier2Plus, BoundaryIntentClass::Actuate),
    }
}

// Error type

/// Errors from `FacJobSpecV1` construction and validation.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum JobSpecError {
    /// Schema identifier mismatch.
    #[error("schema mismatch: expected {expected}, got {actual}")]
    SchemaMismatch {
        /// Expected schema identifier.
        expected: String,
        /// Actual schema identifier.
        actual: String,
    },

    /// A required string field is empty.
    #[error("{field} is empty")]
    EmptyField {
        /// Name of the empty field.
        field: &'static str,
    },

    /// A string field exceeds its maximum length.
    #[error("{field} length {len} exceeds max {max}")]
    FieldTooLong {
        /// Name of the oversize field.
        field: &'static str,
        /// Actual length.
        len: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// The `job_spec_digest` does not match the recomputed digest.
    #[error("job_spec_digest mismatch: declared {declared}, computed {computed}")]
    DigestMismatch {
        /// Declared digest in the spec.
        declared: String,
        /// Recomputed digest.
        computed: String,
    },

    /// `actuation.request_id` does not match `job_spec_digest`.
    #[error("request_id mismatch: request_id={request_id}, job_spec_digest={job_spec_digest}")]
    RequestIdMismatch {
        /// Value of `actuation.request_id`.
        request_id: String,
        /// Value of `job_spec_digest`.
        job_spec_digest: String,
    },

    /// A digest field was not validly formatted as `b3-256:<hex>`.
    #[error("invalid digest for {field}: {value}")]
    InvalidDigest {
        /// Field that contained the invalid digest.
        field: &'static str,
        /// Invalid field value.
        value: String,
    },

    /// A field failed format validation.
    #[error("invalid format for {field}: {value}")]
    InvalidFormat {
        /// Field that failed format validation.
        field: &'static str,
        /// Invalid value that triggered the error.
        value: String,
    },

    /// Priority value is out of the valid range (0..=100).
    #[error("priority {value} is out of range (0..=100)")]
    PriorityOutOfRange {
        /// Invalid priority value.
        value: u32,
    },

    /// Canonical JSON serialization failed.
    #[error("canonical JSON error: {detail}")]
    CanonicalJson {
        /// Detail about the failure.
        detail: String,
    },

    /// JSON serialization/deserialization failed.
    #[error("JSON error: {detail}")]
    Json {
        /// Detail about the failure.
        detail: String,
    },

    /// Input exceeds maximum allowed size.
    #[error("input size {size} exceeds maximum {max}")]
    InputTooLarge {
        /// Actual size.
        size: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// A required token field is missing or empty.
    #[error("missing required token: {field}")]
    MissingToken {
        /// Field that is missing.
        field: &'static str,
    },

    /// The source patch field is missing.
    #[error("missing required patch field: {field}")]
    MissingPatchField {
        /// Field that is missing.
        field: &'static str,
    },

    /// The patch descriptor is invalid or unsupported.
    #[error("invalid patch descriptor: {reason}")]
    InvalidPatchFormat {
        /// Patch descriptor validation failure reason.
        reason: String,
    },
}

// Actuation block

/// RFC-0028 actuation block binding the job spec to a broker-signed token.
///
/// Workers MUST validate the `channel_context_token` before execution.
/// The `request_id` MUST equal `job_spec_digest` so the token is bound
/// to this specific spec.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Actuation {
    /// Lease ID binding the token to a lane lease. REQUIRED.
    pub lease_id: String,

    /// Request ID binding the token to the job spec. MUST equal
    /// `job_spec_digest` (checked by [`validate_job_spec`]).
    pub request_id: String,

    /// RFC-0028 `ChannelContextToken` (base64-encoded, daemon-signed).
    /// REQUIRED in default mode. Set to `None` when computing
    /// `job_spec_digest`.
    pub channel_context_token: Option<String>,

    /// Optional hint for decoded source classification.
    /// Workers MUST NOT trust this without token verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decoded_source: Option<String>,
}

// Source block

/// Source provenance for the job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobSource {
    /// Source kind: `"mirror_commit"` or `"patch_injection"`.
    pub kind: String,

    /// Stable logical repository identifier.
    pub repo_id: String,

    /// HEAD commit SHA.
    pub head_sha: String,

    /// Optional patch object for `patch_injection` kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub patch: Option<serde_json::Value>,
}

// Lane requirements

/// Lane resource requirements for the job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaneRequirements {
    /// Required lane profile hash. `None` if no specific lane is required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lane_profile_hash: Option<String>,
}

// Constraints

/// Execution constraints for the job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobConstraints {
    /// Whether nextest is required.
    #[serde(default)]
    pub require_nextest: bool,

    /// Test execution timeout in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_timeout_seconds: Option<u64>,

    /// Memory ceiling in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_max_bytes: Option<u64>,
}

// FacJobSpecV1

/// FAC Job Spec V1: the immutable description of a unit of work.
///
/// This struct is serialized to JSON and stored on disk as a queue item.
/// The `job_spec_digest` field binds the spec to a specific content hash
/// and the `actuation` block binds it to an RFC-0028 authorization token.
///
/// # Schema: `apm2.fac.job_spec.v1`
///
/// See RFC-0019 section 5.3.3 for the full schema definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FacJobSpecV1 {
    /// Schema identifier. MUST be `"apm2.fac.job_spec.v1"`.
    pub schema: String,

    /// Unique job identifier.
    pub job_id: String,

    /// Content-addressable digest of the canonical spec form.
    /// Computed with `actuation.channel_context_token = null`.
    pub job_spec_digest: String,

    /// Job kind: `"gates"`, `"warm"`, `"bulk"`, `"control"`, `"stop_revoke"`.
    pub kind: String,

    /// RFC-0029 queue lane for admission/scheduling.
    pub queue_lane: String,

    /// Priority within the queue lane (0 = highest, 100 = lowest).
    pub priority: u32,

    /// ISO 8601 enqueue timestamp.
    pub enqueue_time: String,

    /// RFC-0028 actuation authorization block.
    pub actuation: Actuation,

    /// Source provenance.
    pub source: JobSource,

    /// Lane resource requirements.
    pub lane_requirements: LaneRequirements,

    /// Execution constraints.
    pub constraints: JobConstraints,

    /// For `stop_revoke` jobs: the job ID of the target job to cancel.
    /// MUST be present when `kind == "stop_revoke"`, absent otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cancel_target_job_id: Option<String>,
}

impl FacJobSpecV1 {
    /// Computes the RFC-0019 digest for this spec.
    ///
    /// # Errors
    ///
    /// Returns `JobSpecError` if JSON serialization or canonicalization fails.
    pub fn compute_digest(&self) -> Result<String, JobSpecError> {
        let mut spec_for_digest = self.clone();
        spec_for_digest.actuation.channel_context_token = None;
        spec_for_digest.actuation.request_id = String::new();
        spec_for_digest.job_spec_digest = String::new();

        let json = serde_json::to_string(&spec_for_digest).map_err(|e| JobSpecError::Json {
            detail: e.to_string(),
        })?;

        let canonical = canonicalize_json(&json).map_err(|e| JobSpecError::CanonicalJson {
            detail: e.to_string(),
        })?;

        let digest_bytes = compute_digest_bytes(JOB_SPEC_SCHEMA_ID, canonical.as_bytes());
        Ok(format_b3_256_digest(&digest_bytes))
    }

    /// Validates schema, required fields, and local bounds.
    ///
    /// # Errors
    ///
    /// Returns `JobSpecError` for schema, field, and bound violations.
    pub fn validate_structure(&self) -> Result<(), JobSpecError> {
        if self.schema != JOB_SPEC_SCHEMA_ID {
            return Err(JobSpecError::SchemaMismatch {
                expected: JOB_SPEC_SCHEMA_ID.to_string(),
                actual: self.schema.clone(),
            });
        }

        check_non_empty("job_id", &self.job_id)?;
        check_non_empty("job_spec_digest", &self.job_spec_digest)?;
        check_non_empty("kind", &self.kind)?;
        check_non_empty("queue_lane", &self.queue_lane)?;
        check_non_empty("enqueue_time", &self.enqueue_time)?;
        check_non_empty("actuation.lease_id", &self.actuation.lease_id)?;
        check_non_empty("actuation.request_id", &self.actuation.request_id)?;
        check_non_empty("source.kind", &self.source.kind)?;
        check_non_empty("source.repo_id", &self.source.repo_id)?;
        check_non_empty("source.head_sha", &self.source.head_sha)?;
        if !VALID_JOB_KINDS.contains(&self.kind.as_str()) {
            return Err(JobSpecError::InvalidFormat {
                field: "kind",
                value: self.kind.clone(),
            });
        }
        if !VALID_SOURCE_KINDS.contains(&self.source.kind.as_str()) {
            return Err(JobSpecError::InvalidFormat {
                field: "source.kind",
                value: self.source.kind.clone(),
            });
        }
        validate_repo_id(&self.source.repo_id)?;
        validate_head_sha(&self.source.head_sha)?;
        if self.source.kind == "patch_injection" {
            self.validate_patch_source()?;
        }
        if let Some(patch) = &self.source.patch {
            let patch_bytes =
                serde_json::to_vec(patch).map_err(|e| JobSpecError::InvalidFormat {
                    field: "source.patch",
                    value: e.to_string(),
                })?;
            if patch_bytes.len() > MAX_PATCH_SIZE {
                return Err(JobSpecError::FieldTooLong {
                    field: "source.patch",
                    len: patch_bytes.len(),
                    max: MAX_PATCH_SIZE,
                });
            }
        }

        self.validate_field_lengths()?;
        self.validate_temporal_and_priority()?;
        self.validate_cancel_target()?;

        Ok(())
    }

    /// Validates field length bounds for all string fields.
    fn validate_field_lengths(&self) -> Result<(), JobSpecError> {
        check_length("job_id", &self.job_id, MAX_JOB_ID_LENGTH)?;
        check_length("kind", &self.kind, MAX_KIND_LENGTH)?;
        check_length("queue_lane", &self.queue_lane, MAX_QUEUE_LANE_LENGTH)?;
        check_length(
            "actuation.lease_id",
            &self.actuation.lease_id,
            MAX_LEASE_ID_LENGTH,
        )?;
        check_length(
            "actuation.request_id",
            &self.actuation.request_id,
            MAX_REQUEST_ID_LENGTH,
        )?;
        if let Some(ref token) = self.actuation.channel_context_token {
            check_length(
                "actuation.channel_context_token",
                token,
                MAX_CHANNEL_CONTEXT_TOKEN_LENGTH,
            )?;
        }
        if let Some(ref ds) = self.actuation.decoded_source {
            check_length("actuation.decoded_source", ds, MAX_DECODED_SOURCE_LENGTH)?;
        }
        check_length("source.kind", &self.source.kind, MAX_SOURCE_KIND_LENGTH)?;
        check_length("source.repo_id", &self.source.repo_id, MAX_REPO_ID_LENGTH)?;
        check_length(
            "source.head_sha",
            &self.source.head_sha,
            MAX_HEAD_SHA_LENGTH,
        )?;
        Ok(())
    }

    /// Validates temporal format and priority bounds.
    fn validate_temporal_and_priority(&self) -> Result<(), JobSpecError> {
        if self.enqueue_time.len() < 20 || !self.enqueue_time.contains('T') {
            return Err(JobSpecError::InvalidFormat {
                field: "enqueue_time",
                value: self.enqueue_time.clone(),
            });
        }

        if self.priority > 100 {
            return Err(JobSpecError::PriorityOutOfRange {
                value: self.priority,
            });
        }
        Ok(())
    }

    /// Validates `cancel_target_job_id`: required for `stop_revoke`, forbidden
    /// otherwise.
    ///
    /// Enforces strict character validation (`[A-Za-z0-9_-]`) to prevent glob
    /// injection, path traversal, and shell metacharacter abuse.
    fn validate_cancel_target(&self) -> Result<(), JobSpecError> {
        if self.kind == "stop_revoke" {
            match &self.cancel_target_job_id {
                Some(target) if !target.is_empty() => {
                    check_length("cancel_target_job_id", target, MAX_JOB_ID_LENGTH)?;
                    // Strict charset: only alphanumeric, underscore, and hyphen.
                    // Prevents glob expansion, path traversal, shell injection.
                    if !target
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                    {
                        return Err(JobSpecError::InvalidFormat {
                            field: "cancel_target_job_id",
                            value: target.clone(),
                        });
                    }
                },
                _ => {
                    return Err(JobSpecError::EmptyField {
                        field: "cancel_target_job_id",
                    });
                },
            }
        } else if self.cancel_target_job_id.is_some() {
            return Err(JobSpecError::InvalidFormat {
                field: "cancel_target_job_id",
                value: "cancel_target_job_id must be absent for non-stop_revoke jobs".to_string(),
            });
        }
        Ok(())
    }

    fn validate_patch_source(&self) -> Result<(), JobSpecError> {
        let patch = self
            .source
            .patch
            .as_ref()
            .ok_or(JobSpecError::MissingPatchField {
                field: "source.patch",
            })?;
        let patch_obj = patch
            .as_object()
            .ok_or_else(|| JobSpecError::InvalidPatchFormat {
                reason: "patch must be a JSON object".to_string(),
            })?;
        if !patch_obj.contains_key("bytes") {
            return Err(JobSpecError::InvalidPatchFormat {
                reason: "patch descriptor must contain 'bytes' field for inline patch data"
                    .to_string(),
            });
        }
        if patch_obj
            .get("bytes")
            .is_some_and(|bytes| !bytes.is_string())
        {
            return Err(JobSpecError::InvalidPatchFormat {
                reason: "patch bytes must be a string".to_string(),
            });
        }
        if let Some(digest) = patch_obj.get("digest").and_then(|value| value.as_str()) {
            if !digest.starts_with(B3_256_PREFIX) || digest.len() != 71 {
                return Err(JobSpecError::InvalidPatchFormat {
                    reason: "patch digest must be b3-256:<64hex>".to_string(),
                });
            }
            if !digest
                .as_bytes()
                .iter()
                .skip(B3_256_PREFIX.len())
                .all(u8::is_ascii_hexdigit)
            {
                return Err(JobSpecError::InvalidPatchFormat {
                    reason: "patch digest must be b3-256:<64hex>".to_string(),
                });
            }
        }
        Ok(())
    }
}

// Full validation (worker-side)

/// Validates a `FacJobSpecV1` for worker execution.
///
/// Performs structural validation, recomputes the digest, and verifies:
/// 1. `job_spec_digest` matches the recomputed digest (constant-time).
/// 2. `actuation.request_id == job_spec_digest` (constant-time).
///
/// # Errors
///
/// Returns the first validation failure. Workers MUST deny/quarantine the
/// job on any error (fail-closed).
///
/// Worker execution paths MUST also call
/// [`crate::channel::decode_channel_context_token`] and
/// [`crate::channel::validate_channel_boundary`] on
/// `actuation.channel_context_token` and deny execution unless both checks
/// succeed.
pub fn validate_job_spec(spec: &FacJobSpecV1) -> Result<(), JobSpecError> {
    spec.validate_structure()?;

    if parse_b3_256_digest(&spec.job_spec_digest).is_none() {
        return Err(JobSpecError::InvalidDigest {
            field: "job_spec_digest",
            value: spec.job_spec_digest.clone(),
        });
    }
    if parse_b3_256_digest(&spec.actuation.request_id).is_none() {
        return Err(JobSpecError::InvalidDigest {
            field: "actuation.request_id",
            value: spec.actuation.request_id.clone(),
        });
    }

    // Recompute digest
    let computed_digest = spec.compute_digest()?;

    // Constant-time comparison of declared vs computed digest (INV-JS-002)
    if !constant_time_str_eq(&spec.job_spec_digest, &computed_digest) {
        return Err(JobSpecError::DigestMismatch {
            declared: spec.job_spec_digest.clone(),
            computed: computed_digest,
        });
    }

    // Verify request_id == job_spec_digest (constant-time)
    if !constant_time_str_eq(&spec.actuation.request_id, &spec.job_spec_digest) {
        return Err(JobSpecError::RequestIdMismatch {
            request_id: spec.actuation.request_id.clone(),
            job_spec_digest: spec.job_spec_digest.clone(),
        });
    }
    if spec
        .actuation
        .channel_context_token
        .as_deref()
        .is_none_or(str::is_empty)
    {
        return Err(JobSpecError::MissingToken {
            field: "actuation.channel_context_token",
        });
    }

    Ok(())
}

/// Validates a `stop_revoke` job spec for the control lane.
///
/// Performs the same structural and digest validation as [`validate_job_spec`]
/// but does NOT require `actuation.channel_context_token`.  Control-lane
/// `stop_revoke` jobs are operator-initiated local commands; the worker MUST
/// verify local-origin authority (queue directory ownership) instead of an
/// RFC-0028 token.
///
/// # `AUDITED_CONTROL_LANE_EXCEPTION`: RFC-0028/0029 bypass justification
///
/// Control-lane cancellation (`stop_revoke`) uses local operator authority
/// proof instead of the standard RFC-0028 channel context token and RFC-0029
/// queue admission flow.  This is an **explicit, audited policy exception**
/// justified by the following trust model:
///
/// 1. **Same trust domain**: Cancellation originates from the local operator
///    (the same user who owns the queue root directory).  The operator already
///    has filesystem-level privilege over the queue, so a broker-issued token
///    would add no additional authority — it would prove what filesystem access
///    already proves.
///
/// 2. **Capability-based proof**: The worker verifies authority by attempting a
///    probe write to the queue root directory.  Only callers with write access
///    to the directory succeed.  This is a stronger proof than a token for
///    local operations because it demonstrates *current* filesystem capability,
///    not a cached authorization.
///
/// 3. **Digest integrity preserved**: All structural and digest validation
///    (schema, field bounds, BLAKE3 digest, `request_id` binding) is still
///    enforced.  The only bypass is the token requirement.
///
/// 4. **Fail-closed on all deny paths**: Every deny path in the control-lane
///    flow emits an explicit refusal receipt before moving the job to
///    `denied/`.  No evidence is dropped.
///
/// See [`CONTROL_LANE_EXCEPTION_AUDITED`] for the compile-time marker.
///
/// # Errors
///
/// Returns the first validation failure.  Workers MUST deny the job on any
/// error (fail-closed).
pub fn validate_job_spec_control_lane(spec: &FacJobSpecV1) -> Result<(), JobSpecError> {
    if spec.kind != "stop_revoke" {
        return Err(JobSpecError::InvalidFormat {
            field: "kind",
            value: format!(
                "validate_job_spec_control_lane only accepts stop_revoke, got {}",
                spec.kind
            ),
        });
    }

    spec.validate_structure()?;

    if parse_b3_256_digest(&spec.job_spec_digest).is_none() {
        return Err(JobSpecError::InvalidDigest {
            field: "job_spec_digest",
            value: spec.job_spec_digest.clone(),
        });
    }
    if parse_b3_256_digest(&spec.actuation.request_id).is_none() {
        return Err(JobSpecError::InvalidDigest {
            field: "actuation.request_id",
            value: spec.actuation.request_id.clone(),
        });
    }

    // Recompute digest
    let computed_digest = spec.compute_digest()?;

    // Constant-time comparison of declared vs computed digest (INV-JS-002)
    if !constant_time_str_eq(&spec.job_spec_digest, &computed_digest) {
        return Err(JobSpecError::DigestMismatch {
            declared: spec.job_spec_digest.clone(),
            computed: computed_digest,
        });
    }

    // Verify request_id == job_spec_digest (constant-time)
    if !constant_time_str_eq(&spec.actuation.request_id, &spec.job_spec_digest) {
        return Err(JobSpecError::RequestIdMismatch {
            request_id: spec.actuation.request_id.clone(),
            job_spec_digest: spec.job_spec_digest.clone(),
        });
    }

    // Token is deliberately NOT required for control-lane stop_revoke jobs.
    // Local-origin authority is verified by the worker via queue directory
    // ownership checks.

    Ok(())
}

/// Deserializes a `FacJobSpecV1` from JSON bytes with bounded size check.
///
/// Enforces [`MAX_JOB_SPEC_SIZE`] before JSON parsing to prevent
/// memory exhaustion from crafted inputs (RSK-1601).
///
/// # Errors
///
/// Returns an error if the input exceeds the size limit or deserialization
/// fails.
pub fn deserialize_job_spec(bytes: &[u8]) -> Result<FacJobSpecV1, JobSpecError> {
    if bytes.len() > MAX_JOB_SPEC_SIZE {
        return Err(JobSpecError::InputTooLarge {
            size: bytes.len(),
            max: MAX_JOB_SPEC_SIZE,
        });
    }
    serde_json::from_slice(bytes).map_err(|e| JobSpecError::Json {
        detail: e.to_string(),
    })
}

// Builder

/// Builder for `FacJobSpecV1` that computes the digest and sets
/// `actuation.request_id` correctly.
pub struct FacJobSpecV1Builder {
    job_id: String,
    kind: String,
    queue_lane: String,
    priority: u32,
    enqueue_time: String,
    lease_id: String,
    channel_context_token: Option<String>,
    decoded_source: Option<String>,
    source: JobSource,
    lane_requirements: LaneRequirements,
    constraints: JobConstraints,
    cancel_target_job_id: Option<String>,
}

impl FacJobSpecV1Builder {
    /// Creates a new builder with required fields.
    #[must_use]
    pub fn new(
        job_id: impl Into<String>,
        kind: impl Into<String>,
        queue_lane: impl Into<String>,
        enqueue_time: impl Into<String>,
        lease_id: impl Into<String>,
        source: JobSource,
    ) -> Self {
        Self {
            job_id: job_id.into(),
            kind: kind.into(),
            queue_lane: queue_lane.into(),
            priority: 50,
            enqueue_time: enqueue_time.into(),
            lease_id: lease_id.into(),
            channel_context_token: None,
            decoded_source: None,
            source,
            lane_requirements: LaneRequirements {
                lane_profile_hash: None,
            },
            constraints: JobConstraints {
                require_nextest: true,
                test_timeout_seconds: None,
                memory_max_bytes: None,
            },
            cancel_target_job_id: None,
        }
    }

    /// Sets the cancel target job ID (for `stop_revoke` jobs).
    #[must_use]
    pub fn cancel_target_job_id(mut self, target: impl Into<String>) -> Self {
        self.cancel_target_job_id = Some(target.into());
        self
    }

    /// Sets the priority (0 = highest, 100 = lowest).
    #[must_use]
    pub const fn priority(mut self, priority: u32) -> Self {
        self.priority = priority;
        self
    }

    /// Sets the RFC-0028 channel context token (base64).
    #[must_use]
    pub fn channel_context_token(mut self, token: impl Into<String>) -> Self {
        self.channel_context_token = Some(token.into());
        self
    }

    /// Sets the decoded source hint.
    #[must_use]
    pub fn decoded_source(mut self, source: impl Into<String>) -> Self {
        self.decoded_source = Some(source.into());
        self
    }

    /// Sets the lane profile hash requirement.
    #[must_use]
    pub fn lane_profile_hash(mut self, hash: impl Into<String>) -> Self {
        self.lane_requirements.lane_profile_hash = Some(hash.into());
        self
    }

    /// Sets the nextest requirement.
    #[must_use]
    pub const fn require_nextest(mut self, require: bool) -> Self {
        self.constraints.require_nextest = require;
        self
    }

    /// Sets the test timeout in seconds.
    #[must_use]
    pub const fn test_timeout_seconds(mut self, seconds: u64) -> Self {
        self.constraints.test_timeout_seconds = Some(seconds);
        self
    }

    /// Sets the memory ceiling in bytes.
    #[must_use]
    pub const fn memory_max_bytes(mut self, bytes: u64) -> Self {
        self.constraints.memory_max_bytes = Some(bytes);
        self
    }

    /// Builds the `FacJobSpecV1`, computing the digest and setting
    /// `actuation.request_id = job_spec_digest`.
    ///
    /// # Errors
    ///
    /// Returns an error if structural validation or digest computation fails.
    pub fn build(self) -> Result<FacJobSpecV1, JobSpecError> {
        let mut spec = FacJobSpecV1 {
            schema: JOB_SPEC_SCHEMA_ID.to_string(),
            job_id: self.job_id,
            job_spec_digest: String::new(), // placeholder; computed below
            kind: self.kind,
            queue_lane: self.queue_lane,
            priority: self.priority,
            enqueue_time: self.enqueue_time,
            actuation: Actuation {
                lease_id: self.lease_id,
                request_id: String::new(), // placeholder; set to digest below
                channel_context_token: self.channel_context_token,
                decoded_source: self.decoded_source,
            },
            source: self.source,
            lane_requirements: self.lane_requirements,
            constraints: self.constraints,
            cancel_target_job_id: self.cancel_target_job_id,
        };

        // Compute digest (with token nulled and digest/request_id empty)
        let digest = spec.compute_digest()?;

        // Set digest and request_id
        spec.job_spec_digest.clone_from(&digest);
        spec.actuation.request_id = digest;

        // Validate structure
        spec.validate_structure()?;

        Ok(spec)
    }
}

// Helpers

/// Computes the raw BLAKE3 digest bytes with domain separation.
///
/// `BLAKE3(schema_id || "\0" || data)`
pub(crate) fn compute_digest_bytes(schema_id: &str, data: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(schema_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(data);
    *hasher.finalize().as_bytes()
}

pub(crate) fn format_b3_256_digest(hash: &[u8; 32]) -> String {
    let mut s = String::with_capacity(B3_256_PREFIX.len() + 64);
    s.push_str(B3_256_PREFIX);
    for byte in hash {
        use std::fmt::Write;
        let _ = write!(s, "{byte:02x}");
    }
    s
}

/// Parses a `"b3-256:<hex>"` string into raw 32 bytes.
///
/// Returns `None` if the prefix is wrong or the hex is malformed.
#[must_use]
pub fn parse_b3_256_digest(s: &str) -> Option<[u8; 32]> {
    let hex_str = s.strip_prefix(B3_256_PREFIX)?;
    if hex_str.len() != 64 {
        return None;
    }
    let mut bytes = [0u8; 32];
    for (i, byte) in bytes.iter_mut().enumerate() {
        let hi = hex_char_to_nibble(hex_str.as_bytes().get(i * 2).copied()?)?;
        let lo = hex_char_to_nibble(hex_str.as_bytes().get(i * 2 + 1).copied()?)?;
        *byte = (hi << 4) | lo;
    }
    Some(bytes)
}

pub(crate) const fn hex_char_to_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn constant_time_str_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

fn validate_repo_id(repo_id: &str) -> Result<(), JobSpecError> {
    if repo_id.is_empty() {
        return Err(JobSpecError::EmptyField {
            field: "source.repo_id",
        });
    }
    if repo_id.len() > MAX_REPO_ID_LENGTH {
        return Err(JobSpecError::FieldTooLong {
            field: "source.repo_id",
            len: repo_id.len(),
            max: MAX_REPO_ID_LENGTH,
        });
    }
    if repo_id.contains('\\') || repo_id.starts_with('/') || repo_id.ends_with('/') {
        return Err(JobSpecError::InvalidFormat {
            field: "source.repo_id",
            value: repo_id.to_string(),
        });
    }
    if repo_id.contains(char::from(0)) {
        return Err(JobSpecError::InvalidFormat {
            field: "source.repo_id",
            value: repo_id.to_string(),
        });
    }
    for segment in repo_id.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(JobSpecError::InvalidFormat {
                field: "source.repo_id",
                value: repo_id.to_string(),
            });
        }
    }
    if repo_id.contains("..") {
        return Err(JobSpecError::InvalidFormat {
            field: "source.repo_id",
            value: repo_id.to_string(),
        });
    }

    Ok(())
}

fn validate_head_sha(head_sha: &str) -> Result<(), JobSpecError> {
    let is_hex = |value: &str| value.as_bytes().iter().all(u8::is_ascii_hexdigit);
    match head_sha.len() {
        40 | 64 if is_hex(head_sha) => Ok(()),
        _ => Err(JobSpecError::InvalidFormat {
            field: "source.head_sha",
            value: head_sha.to_string(),
        }),
    }
}

const fn check_non_empty(field: &'static str, value: &str) -> Result<(), JobSpecError> {
    if value.is_empty() {
        return Err(JobSpecError::EmptyField { field });
    }
    Ok(())
}

const fn check_length(field: &'static str, value: &str, max: usize) -> Result<(), JobSpecError> {
    if value.len() > max {
        return Err(JobSpecError::FieldTooLong {
            field,
            len: value.len(),
            max,
        });
    }
    Ok(())
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_source() -> JobSource {
        JobSource {
            kind: "mirror_commit".to_string(),
            repo_id: "org-repo".to_string(),
            head_sha: "a".repeat(40),
            patch: None,
        }
    }

    fn build_with_ids(job_id: &str, lease_id: &str) -> FacJobSpecV1Builder {
        FacJobSpecV1Builder::new(
            job_id,
            "gates",
            "bulk",
            "2026-02-12T00:00:00Z",
            lease_id,
            sample_source(),
        )
        .priority(50)
        .memory_max_bytes(64_000_000_000)
    }

    fn build_valid_spec() -> FacJobSpecV1 {
        build_with_ids("job1", "L1")
            .build()
            .expect("valid spec should build")
    }

    #[test]
    fn builder_produces_digest_and_request_binding() {
        let tokenless = build_valid_spec();
        let with_token = build_with_ids("job1", "L1")
            .channel_context_token("TOKEN")
            .build()
            .expect("tokenized spec");

        assert_eq!(tokenless.job_spec_digest, with_token.job_spec_digest);
        assert_eq!(tokenless.job_spec_digest, tokenless.actuation.request_id);
        assert_eq!(with_token.actuation.request_id, with_token.job_spec_digest);
        assert_eq!(tokenless.actuation.channel_context_token, None);
        assert_eq!(tokenless.actuation.request_id, tokenless.job_spec_digest);
        assert!(validate_job_spec(&with_token).is_ok());
    }

    #[test]
    fn digest_is_deterministic_and_detects_mutation() {
        let spec1 = build_valid_spec();
        let spec2 = build_valid_spec();
        let mut spec3 = build_with_ids("job1", "L1")
            .channel_context_token("TOKEN")
            .build()
            .expect("tokenized spec");

        assert_eq!(spec1.job_spec_digest, spec2.job_spec_digest);
        spec3.kind = "warm".to_string();
        assert!(matches!(
            validate_job_spec(&spec3),
            Err(JobSpecError::DigestMismatch { .. })
        ));
        spec3.source.repo_id = "evil-org/apm2".to_string();
        assert!(matches!(
            validate_job_spec(&spec3),
            Err(JobSpecError::DigestMismatch { .. })
        ));
        let mut spec4 = build_with_ids("job1", "L1")
            .channel_context_token("TOKEN")
            .build()
            .expect("tokenized spec");
        spec4.actuation.request_id =
            "b3-256:0000000000000000000000000000000000000000000000000000000000000000".to_string();
        assert!(matches!(
            validate_job_spec(&spec4),
            Err(JobSpecError::RequestIdMismatch { .. })
        ));
    }

    #[test]
    fn token_presence_is_rejected_when_missing_or_empty() {
        for token in [None, Some("")] {
            let mut spec = build_with_ids("job1", "L1")
                .channel_context_token("TOKEN")
                .build()
                .expect("tokenized spec");
            spec.actuation.channel_context_token = token.map(str::to_string);
            assert!(matches!(
                validate_job_spec(&spec),
                Err(JobSpecError::MissingToken {
                    field: "actuation.channel_context_token"
                })
            ));
        }
    }

    #[test]
    fn validate_rejects_schema_and_field_errors() {
        let mut bad_schema = build_valid_spec();
        bad_schema.schema = "wrong.schema".to_string();
        assert!(matches!(
            validate_job_spec(&bad_schema),
            Err(JobSpecError::SchemaMismatch { .. })
        ));

        for result in [
            build_with_ids("", "L1").build(),
            build_with_ids("job1", "").build(),
        ] {
            assert!(matches!(result, Err(JobSpecError::EmptyField { .. })));
        }
        assert!(matches!(
            build_with_ids("job1", "L1").priority(101).build(),
            Err(JobSpecError::PriorityOutOfRange { value: 101 })
        ));

        let mut long_fields = [
            {
                let mut spec = build_valid_spec();
                spec.job_id = "x".repeat(MAX_JOB_ID_LENGTH + 1);
                spec
            },
            {
                let mut spec = build_valid_spec();
                spec.queue_lane = "x".repeat(MAX_QUEUE_LANE_LENGTH + 1);
                spec
            },
            {
                let mut spec = build_with_ids("job1", "L1").build().expect("valid spec");
                spec.actuation.request_id = "x".repeat(MAX_REQUEST_ID_LENGTH + 1);
                spec
            },
        ];
        let expected_fields = ["job_id", "queue_lane", "actuation.request_id"];
        for (spec, expected_field) in long_fields.iter_mut().zip(expected_fields.iter()) {
            assert!(matches!(
                spec.validate_structure(),
                Err(JobSpecError::FieldTooLong { field, .. }) if field == *expected_field
            ));
        }

        assert!(matches!(
            {
                let mut spec = build_valid_spec();
                spec.kind = "invalid_kind".to_string();
                spec.validate_structure()
            },
            Err(JobSpecError::InvalidFormat { field: "kind", .. })
        ));
        assert!(matches!(
            {
                let mut spec = build_valid_spec();
                spec.source.kind = "patch_injection".to_string();
                spec.validate_structure()
            },
            Err(JobSpecError::MissingPatchField { .. })
        ));
        assert!(matches!(
            {
                let mut spec = build_valid_spec();
                spec.source.kind = "patch_injection".to_string();
                spec.source.patch = Some(serde_json::json!("bad"));
                spec.validate_structure()
            },
            Err(JobSpecError::InvalidPatchFormat { .. })
        ));
        assert!(matches!(
            {
                let mut spec = build_valid_spec();
                spec.source.kind = "patch_injection".to_string();
                spec.source.patch = Some(
                    serde_json::json!({"bytes": 1, "digest":"b3-256:0000000000000000000000000000000000000000000000000000000000000000"}),
                );
                spec.validate_structure()
            },
            Err(JobSpecError::InvalidPatchFormat { .. })
        ));
    }

    #[test]
    fn test_patch_injection_requires_patch_field() {
        let mut spec = build_with_ids("job-patch", "L1")
            .channel_context_token("TOKEN")
            .build()
            .expect("valid base spec");
        spec.source.kind = "patch_injection".to_string();
        spec.source.patch = None;

        assert!(matches!(
            validate_job_spec(&spec),
            Err(JobSpecError::MissingPatchField {
                field: "source.patch"
            })
        ));
    }

    #[test]
    fn test_validate_rejects_inline_patch_without_bytes() {
        let mut spec = build_with_ids("job-patch", "L1")
            .channel_context_token("TOKEN")
            .build()
            .expect("valid base spec");
        spec.source.kind = "patch_injection".to_string();
        spec.source.patch = Some(serde_json::json!({"format":"git_diff_v1"}));

        assert!(matches!(
            validate_job_spec(&spec),
            Err(JobSpecError::InvalidPatchFormat { .. })
        ));
    }

    #[test]
    fn test_patch_injection_rejects_invalid_digest_format() {
        let mut spec = build_with_ids("job-patch", "L1")
            .channel_context_token("TOKEN")
            .build()
            .expect("valid base spec");
        spec.source.kind = "patch_injection".to_string();
        spec.source.patch = Some(serde_json::json!({
            "bytes": "aGVsbG8=",
            "digest": "invalid"
        }));

        assert!(matches!(
            validate_job_spec(&spec),
            Err(JobSpecError::InvalidPatchFormat { .. })
        ));
    }

    #[test]
    fn test_validate_rejects_source_repo_id_with_nul() {
        let mut spec = build_with_ids("job1", "L1")
            .channel_context_token("TOKEN")
            .build()
            .expect("valid base spec");
        spec.source.repo_id = "org\u{0000}repo".to_string();
        assert!(matches!(
            validate_job_spec(&spec),
            Err(JobSpecError::InvalidFormat {
                field: "source.repo_id",
                ..
            })
        ));
    }

    #[test]
    fn deserialize_roundtrip_and_bounds() {
        let spec = build_with_ids("job2", "L2")
            .channel_context_token("TOKEN")
            .test_timeout_seconds(300)
            .build()
            .expect("valid spec");
        let bytes = serde_json::to_vec_pretty(&spec).expect("serialize");
        let restored = deserialize_job_spec(&bytes).expect("deserialize");

        assert!(bytes.len() <= MAX_JOB_SPEC_SIZE);
        assert_eq!(spec, restored);
        assert!(validate_job_spec(&restored).is_ok());

        let oversized = vec![b' '; MAX_JOB_SPEC_SIZE + 1];
        let mut json: serde_json::Value = serde_json::to_value(&spec).expect("json value");
        json["evil_field"] = serde_json::Value::Bool(true);

        assert!(matches!(
            deserialize_job_spec(&oversized),
            Err(JobSpecError::InputTooLarge { .. })
        ));
        let mut json: serde_json::Value = serde_json::to_value(&spec).expect("json value");
        json["evil_field"] = serde_json::Value::Bool(true);
        assert!(deserialize_job_spec(&serde_json::to_vec(&json).expect("serialize")).is_err());
    }

    #[test]
    fn parse_digest_and_constant_time() {
        let hash = [0x42u8; 32];
        let formatted = format_b3_256_digest(&hash);

        assert_eq!(parse_b3_256_digest(&formatted).expect("parse ok"), hash);
        assert!(parse_b3_256_digest("sha256:aabb").is_none());
        assert!(parse_b3_256_digest("b3-256:aabb").is_none());
        assert!(parse_b3_256_digest(&format!("b3-256:{}", "zz".repeat(32))).is_none());
        assert!(constant_time_str_eq("hello", "hello"));
        assert!(!constant_time_str_eq("hello", "world"));
        assert!(!constant_time_str_eq("hello", "hell"));
        assert!(!constant_time_str_eq("", "a"));
        let mut bad_job_digest = build_with_ids("job1", "L1")
            .channel_context_token("TOKEN")
            .build()
            .expect("tokenized spec");
        bad_job_digest.job_spec_digest = "not-a-digest".to_string();
        let mut bad_request_id = build_with_ids("job1", "L1")
            .channel_context_token("TOKEN")
            .build()
            .expect("tokenized spec");
        bad_request_id.actuation.request_id = "not-a-digest".to_string();
        assert!(matches!(
            validate_job_spec(&bad_job_digest),
            Err(JobSpecError::InvalidDigest {
                field: "job_spec_digest",
                ..
            })
        ));
        assert!(matches!(
            validate_job_spec(&bad_request_id),
            Err(JobSpecError::InvalidDigest {
                field: "actuation.request_id",
                ..
            })
        ));
    }

    #[test]
    fn budget_key_mapping_is_stable() {
        let unknown = job_kind_to_budget_key("unknown-kind");
        assert_eq!(unknown, (RiskTier::Tier2Plus, BoundaryIntentClass::Actuate));

        assert_eq!(
            job_kind_to_budget_key("gates"),
            (RiskTier::Tier0, BoundaryIntentClass::Actuate)
        );
        assert_eq!(
            job_kind_to_budget_key("warm"),
            (RiskTier::Tier0, BoundaryIntentClass::Actuate)
        );
        assert_eq!(
            job_kind_to_budget_key("control"),
            (RiskTier::Tier1, BoundaryIntentClass::Govern)
        );
        assert_eq!(
            job_kind_to_budget_key("bulk"),
            (RiskTier::Tier1, BoundaryIntentClass::Actuate)
        );
    }

    #[test]
    fn cancel_target_rejects_special_characters() {
        // MAJOR 5: cancel_target_job_id must only allow [A-Za-z0-9_-].
        let bad_targets = vec![
            "../evil", "job*glob", "a;b", "a b", "a/b", "a\x00b", "a.b", "a{b}", "a?b",
        ];
        for target in bad_targets {
            let result = FacJobSpecV1Builder::new(
                "sr-1",
                "stop_revoke",
                "control",
                "2026-02-12T00:00:00Z",
                "L1",
                sample_source(),
            )
            .cancel_target_job_id(target)
            .build();
            assert!(
                matches!(
                    result,
                    Err(JobSpecError::InvalidFormat {
                        field: "cancel_target_job_id",
                        ..
                    })
                ),
                "target {target:?} should be rejected, got {result:?}"
            );
        }
    }

    #[test]
    fn cancel_target_accepts_valid_ids() {
        let valid_targets = vec!["abc-123", "ABC_def", "job-42", "a", "Z-0_x"];
        for target in valid_targets {
            let result = FacJobSpecV1Builder::new(
                "sr-1",
                "stop_revoke",
                "control",
                "2026-02-12T00:00:00Z",
                "L1",
                sample_source(),
            )
            .cancel_target_job_id(target)
            .build();
            assert!(
                result.is_ok(),
                "target {target:?} should be accepted, got {result:?}"
            );
        }
    }

    #[test]
    fn validate_control_lane_accepts_stop_revoke_without_token() {
        // validate_job_spec_control_lane does NOT require a channel context token.
        let spec = FacJobSpecV1Builder::new(
            "sr-1",
            "stop_revoke",
            "control",
            "2026-02-12T00:00:00Z",
            "L1",
            sample_source(),
        )
        .cancel_target_job_id("target-123")
        .build()
        .expect("valid stop_revoke spec");

        // Should succeed without token.
        assert!(spec.actuation.channel_context_token.is_none());
        let result = validate_job_spec_control_lane(&spec);
        assert!(
            result.is_ok(),
            "control-lane validation should accept tokenless stop_revoke: {result:?}"
        );

        // Regular validate_job_spec should reject (missing token).
        let result_full = validate_job_spec(&spec);
        assert!(
            matches!(result_full, Err(JobSpecError::MissingToken { .. })),
            "full validation should reject tokenless spec: {result_full:?}"
        );
    }

    #[test]
    fn validate_control_lane_rejects_non_stop_revoke() {
        let spec = build_with_ids("job1", "L1")
            .channel_context_token("TOKEN")
            .build()
            .expect("valid spec");
        let result = validate_job_spec_control_lane(&spec);
        assert!(
            matches!(
                result,
                Err(JobSpecError::InvalidFormat { field: "kind", .. })
            ),
            "control-lane validation should reject non-stop_revoke kind: {result:?}"
        );
    }
}
