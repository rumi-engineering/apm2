//! FAC queue job lifecycle vocabulary and identity helpers.
//!
//! This module defines the canonical `fac.job.*` event payloads used to
//! migrate queue truth toward ledger-backed lifecycle state.
//!
//! Security properties:
//! - Bounded decode for untrusted payload bytes.
//! - `#[serde(deny_unknown_fields)]` on all boundary structs.
//! - Length-framed preimage hashing for content-addressable job identity.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema identifier for [`FacJobLifecycleEventV1`].
pub const JOB_LIFECYCLE_SCHEMA_ID: &str = "apm2.fac.job_lifecycle_event.v1";

/// Event type for enqueue lifecycle transitions.
pub const FAC_JOB_ENQUEUED_EVENT_TYPE: &str = "fac.job.enqueued";
/// Event type for claim lifecycle transitions.
pub const FAC_JOB_CLAIMED_EVENT_TYPE: &str = "fac.job.claimed";
/// Event type for start lifecycle transitions.
pub const FAC_JOB_STARTED_EVENT_TYPE: &str = "fac.job.started";
/// Event type for completion lifecycle transitions.
pub const FAC_JOB_COMPLETED_EVENT_TYPE: &str = "fac.job.completed";
/// Event type for release lifecycle transitions.
pub const FAC_JOB_RELEASED_EVENT_TYPE: &str = "fac.job.released";
/// Event type for failure lifecycle transitions.
pub const FAC_JOB_FAILED_EVENT_TYPE: &str = "fac.job.failed";

/// Maximum encoded lifecycle event payload size in bytes.
pub const MAX_JOB_LIFECYCLE_EVENT_SIZE: usize = 65_536;

/// Maximum string length for lifecycle string fields.
pub const MAX_JOB_LIFECYCLE_STRING_LENGTH: usize = 512;

/// Maximum number of digest entries captured in completion payloads.
pub const MAX_JOB_LIFECYCLE_DIGEST_LIST_LEN: usize = 64;

/// Error type for job lifecycle encode/decode and validation.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum JobLifecycleError {
    /// Event payload exceeded the fixed decode bound.
    #[error("job lifecycle payload too large: {size} > {max}")]
    PayloadTooLarge {
        /// Actual payload size.
        size: usize,
        /// Maximum allowed payload size.
        max: usize,
    },
    /// Schema mismatch during validation.
    #[error("job lifecycle schema mismatch: expected {expected}, got {actual}")]
    SchemaMismatch {
        /// Expected schema identifier.
        expected: String,
        /// Actual schema identifier.
        actual: String,
    },
    /// Validation failed for a field-level bound.
    #[error("job lifecycle field `{field}` exceeds max length: {actual} > {max}")]
    FieldTooLong {
        /// Field name.
        field: &'static str,
        /// Actual field length.
        actual: usize,
        /// Maximum allowed field length.
        max: usize,
    },
    /// Validation failed because a required field was empty.
    #[error("job lifecycle field `{field}` is required and cannot be empty")]
    EmptyField {
        /// Empty field name.
        field: &'static str,
    },
    /// Validation failed for an unsupported event type.
    #[error("unsupported job lifecycle event type: {event_type}")]
    UnsupportedEventType {
        /// Unsupported event type string.
        event_type: String,
    },
    /// Validation failed because a digest list exceeded the bound.
    #[error("job lifecycle digest list `{field}` exceeds max length: {actual} > {max}")]
    DigestListTooLarge {
        /// Field name.
        field: &'static str,
        /// Actual list length.
        actual: usize,
        /// Maximum allowed list length.
        max: usize,
    },
    /// Serialization failure.
    #[error("job lifecycle serialization failed: {message}")]
    Serialization {
        /// Serialization error detail.
        message: String,
    },
    /// Deserialization failure.
    #[error("job lifecycle deserialization failed: {message}")]
    Deserialization {
        /// Deserialization error detail.
        message: String,
    },
    /// Internal size conversion failed.
    #[error("job lifecycle size conversion failed")]
    SizeConversion,
}

/// Stable preimage used to derive the content-addressable queue lifecycle
/// `job_id`.
///
/// The digest preimage is length framed, so `(ab, c)` and `(a, bc)` produce
/// distinct identities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FacJobIdentityPreimageV1 {
    /// Stable work identifier.
    pub work_id: String,
    /// Stable changeset digest (`b3-256:<hex>` recommended).
    pub changeset_digest: String,
    /// Gate/profile selector used for scheduling.
    pub gate_profile: String,
    /// Revision selector (for example a spec digest).
    pub revision: String,
}

impl FacJobIdentityPreimageV1 {
    /// Validates local field bounds.
    ///
    /// # Errors
    ///
    /// Returns [`JobLifecycleError`] when required fields are empty or exceed
    /// [`MAX_JOB_LIFECYCLE_STRING_LENGTH`].
    pub fn validate(&self) -> Result<(), JobLifecycleError> {
        validate_non_empty("work_id", &self.work_id)?;
        validate_non_empty("changeset_digest", &self.changeset_digest)?;
        validate_non_empty("gate_profile", &self.gate_profile)?;
        validate_non_empty("revision", &self.revision)?;
        Ok(())
    }
}

/// Derives a deterministic, content-addressable queue lifecycle job ID.
///
/// Format: `fj1-<blake3-256 hex>`
///
/// # Errors
///
/// Returns [`JobLifecycleError`] when validation fails or framing overflows.
pub fn derive_content_addressable_job_id(
    preimage: &FacJobIdentityPreimageV1,
) -> Result<String, JobLifecycleError> {
    preimage.validate()?;

    let mut framed = Vec::new();
    append_len_framed(&mut framed, preimage.work_id.as_bytes())?;
    append_len_framed(&mut framed, preimage.changeset_digest.as_bytes())?;
    append_len_framed(&mut framed, preimage.gate_profile.as_bytes())?;
    append_len_framed(&mut framed, preimage.revision.as_bytes())?;

    let digest = blake3::hash(&framed);
    Ok(format!("fj1-{}", digest.to_hex()))
}

/// Queue job identity material embedded in each lifecycle event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FacJobIdentityV1 {
    /// Content-addressable lifecycle job ID.
    pub job_id: String,
    /// Filesystem queue job ID (migration compatibility key).
    pub queue_job_id: String,
    /// Stable work identifier.
    pub work_id: String,
    /// Stable changeset digest.
    pub changeset_digest: String,
    /// Canonical job-spec digest.
    pub spec_digest: String,
    /// Gate/profile selector.
    pub gate_profile: String,
    /// Revision selector.
    pub revision: String,
}

impl FacJobIdentityV1 {
    /// Validates local bounds.
    ///
    /// # Errors
    ///
    /// Returns [`JobLifecycleError`] when required fields are empty or exceed
    /// [`MAX_JOB_LIFECYCLE_STRING_LENGTH`].
    pub fn validate(&self) -> Result<(), JobLifecycleError> {
        validate_non_empty("identity.job_id", &self.job_id)?;
        validate_non_empty("identity.queue_job_id", &self.queue_job_id)?;
        validate_non_empty("identity.work_id", &self.work_id)?;
        validate_non_empty("identity.changeset_digest", &self.changeset_digest)?;
        validate_non_empty("identity.spec_digest", &self.spec_digest)?;
        validate_non_empty("identity.gate_profile", &self.gate_profile)?;
        validate_non_empty("identity.revision", &self.revision)?;
        Ok(())
    }
}

/// Payload for `fac.job.enqueued`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FacJobEnqueuedV1 {
    /// Queue job identity.
    pub identity: FacJobIdentityV1,
    /// Enqueue timestamp (nanoseconds since UNIX epoch).
    pub enqueue_epoch_ns: u64,
}

/// Payload for `fac.job.claimed`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FacJobClaimedV1 {
    /// Queue job identity.
    pub identity: FacJobIdentityV1,
    /// Lease identifier for this claim.
    pub lease_id: String,
    /// Actor identity claiming the job.
    pub actor_id: String,
    /// Claim epoch timestamp (nanoseconds since UNIX epoch).
    pub claim_epoch_ns: u64,
}

/// Payload for `fac.job.started`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FacJobStartedV1 {
    /// Queue job identity.
    pub identity: FacJobIdentityV1,
    /// Worker instance ID that started execution.
    pub worker_instance_id: String,
    /// Optional receipt ID for a start acknowledgement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_receipt_id: Option<String>,
}

/// Payload for `fac.job.completed`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FacJobCompletedV1 {
    /// Queue job identity.
    pub identity: FacJobIdentityV1,
    /// Stable completion outcome class.
    pub outcome: String,
    /// Receipt digests supporting completion.
    pub receipt_digests: Vec<String>,
    /// Artifact digests produced by the job.
    pub artifact_digests: Vec<String>,
}

/// Payload for `fac.job.released`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FacJobReleasedV1 {
    /// Queue job identity.
    pub identity: FacJobIdentityV1,
    /// Release reason code.
    pub reason: String,
    /// Previous lease ID, if the release happened after claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_lease_id: Option<String>,
}

/// Payload for `fac.job.failed`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FacJobFailedV1 {
    /// Queue job identity.
    pub identity: FacJobIdentityV1,
    /// Stable reason class code.
    pub reason_class: String,
    /// Whether failure is retryable.
    pub retryable: bool,
}

/// Tagged lifecycle payload for all `fac.job.*` events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event_type", content = "data")]
pub enum FacJobLifecycleEventData {
    /// `fac.job.enqueued`.
    #[serde(rename = "fac.job.enqueued")]
    Enqueued(FacJobEnqueuedV1),
    /// `fac.job.claimed`.
    #[serde(rename = "fac.job.claimed")]
    Claimed(FacJobClaimedV1),
    /// `fac.job.started`.
    #[serde(rename = "fac.job.started")]
    Started(FacJobStartedV1),
    /// `fac.job.completed`.
    #[serde(rename = "fac.job.completed")]
    Completed(FacJobCompletedV1),
    /// `fac.job.released`.
    #[serde(rename = "fac.job.released")]
    Released(FacJobReleasedV1),
    /// `fac.job.failed`.
    #[serde(rename = "fac.job.failed")]
    Failed(FacJobFailedV1),
}

impl FacJobLifecycleEventData {
    /// Returns the canonical lifecycle `job_id` for this event.
    #[must_use]
    pub fn job_id(&self) -> &str {
        match self {
            Self::Enqueued(data) => &data.identity.job_id,
            Self::Claimed(data) => &data.identity.job_id,
            Self::Started(data) => &data.identity.job_id,
            Self::Completed(data) => &data.identity.job_id,
            Self::Released(data) => &data.identity.job_id,
            Self::Failed(data) => &data.identity.job_id,
        }
    }

    /// Returns the migration compatibility queue job ID.
    #[must_use]
    pub fn queue_job_id(&self) -> &str {
        match self {
            Self::Enqueued(data) => &data.identity.queue_job_id,
            Self::Claimed(data) => &data.identity.queue_job_id,
            Self::Started(data) => &data.identity.queue_job_id,
            Self::Completed(data) => &data.identity.queue_job_id,
            Self::Released(data) => &data.identity.queue_job_id,
            Self::Failed(data) => &data.identity.queue_job_id,
        }
    }
}

/// Canonical lifecycle event envelope persisted in the ledger payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FacJobLifecycleEventV1 {
    /// Schema identifier.
    pub schema: String,
    /// Deterministic idempotency intent key.
    pub intent_id: String,
    /// Optional receipt identity for irreversible effects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
    /// Tagged event data.
    #[serde(flatten)]
    pub event: FacJobLifecycleEventData,
}

impl FacJobLifecycleEventV1 {
    /// Creates a new lifecycle event envelope.
    #[must_use]
    pub fn new(
        intent_id: impl Into<String>,
        receipt_id: Option<String>,
        event: FacJobLifecycleEventData,
    ) -> Self {
        Self {
            schema: JOB_LIFECYCLE_SCHEMA_ID.to_string(),
            intent_id: intent_id.into(),
            receipt_id,
            event,
        }
    }

    /// Validates envelope and payload bounds.
    ///
    /// # Errors
    ///
    /// Returns [`JobLifecycleError`] when schema, event type, or payload field
    /// bounds are invalid.
    pub fn validate(&self) -> Result<(), JobLifecycleError> {
        if self.schema != JOB_LIFECYCLE_SCHEMA_ID {
            return Err(JobLifecycleError::SchemaMismatch {
                expected: JOB_LIFECYCLE_SCHEMA_ID.to_string(),
                actual: self.schema.clone(),
            });
        }

        validate_non_empty("intent_id", &self.intent_id)?;
        if let Some(receipt_id) = self.receipt_id.as_deref() {
            validate_non_empty("receipt_id", receipt_id)?;
        }

        match &self.event {
            FacJobLifecycleEventData::Enqueued(data) => data.identity.validate(),
            FacJobLifecycleEventData::Claimed(data) => {
                data.identity.validate()?;
                validate_non_empty("claim.lease_id", &data.lease_id)?;
                validate_non_empty("claim.actor_id", &data.actor_id)
            },
            FacJobLifecycleEventData::Started(data) => {
                data.identity.validate()?;
                validate_non_empty("started.worker_instance_id", &data.worker_instance_id)?;
                if let Some(receipt_id) = data.start_receipt_id.as_deref() {
                    validate_non_empty("started.start_receipt_id", receipt_id)?;
                }
                Ok(())
            },
            FacJobLifecycleEventData::Completed(data) => {
                data.identity.validate()?;
                validate_non_empty("completed.outcome", &data.outcome)?;
                validate_digest_list("completed.receipt_digests", &data.receipt_digests)?;
                validate_digest_list("completed.artifact_digests", &data.artifact_digests)
            },
            FacJobLifecycleEventData::Released(data) => {
                data.identity.validate()?;
                validate_non_empty("released.reason", &data.reason)?;
                if let Some(previous_lease_id) = data.previous_lease_id.as_deref() {
                    validate_non_empty("released.previous_lease_id", previous_lease_id)?;
                }
                Ok(())
            },
            FacJobLifecycleEventData::Failed(data) => {
                data.identity.validate()?;
                validate_non_empty("failed.reason_class", &data.reason_class)
            },
        }
    }

    /// Serializes and validates this event as bounded bytes.
    ///
    /// # Errors
    ///
    /// Returns [`JobLifecycleError`] when validation fails or serialization
    /// exceeds [`MAX_JOB_LIFECYCLE_EVENT_SIZE`].
    pub fn encode_bounded(&self) -> Result<Vec<u8>, JobLifecycleError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|err| JobLifecycleError::Serialization {
            message: err.to_string(),
        })?;
        if bytes.len() > MAX_JOB_LIFECYCLE_EVENT_SIZE {
            return Err(JobLifecycleError::PayloadTooLarge {
                size: bytes.len(),
                max: MAX_JOB_LIFECYCLE_EVENT_SIZE,
            });
        }
        Ok(bytes)
    }

    /// Deserializes a bounded lifecycle payload.
    ///
    /// # Errors
    ///
    /// Returns [`JobLifecycleError`] when decode or validation fails.
    pub fn decode_bounded(bytes: &[u8]) -> Result<Self, JobLifecycleError> {
        if bytes.len() > MAX_JOB_LIFECYCLE_EVENT_SIZE {
            return Err(JobLifecycleError::PayloadTooLarge {
                size: bytes.len(),
                max: MAX_JOB_LIFECYCLE_EVENT_SIZE,
            });
        }
        let event: Self =
            serde_json::from_slice(bytes).map_err(|err| JobLifecycleError::Deserialization {
                message: err.to_string(),
            })?;
        event.validate()?;
        Ok(event)
    }
}

fn validate_digest_list(field: &'static str, digests: &[String]) -> Result<(), JobLifecycleError> {
    if digests.len() > MAX_JOB_LIFECYCLE_DIGEST_LIST_LEN {
        return Err(JobLifecycleError::DigestListTooLarge {
            field,
            actual: digests.len(),
            max: MAX_JOB_LIFECYCLE_DIGEST_LIST_LEN,
        });
    }
    for digest in digests {
        validate_non_empty(field, digest)?;
    }
    Ok(())
}

const fn validate_non_empty(field: &'static str, value: &str) -> Result<(), JobLifecycleError> {
    if value.is_empty() {
        return Err(JobLifecycleError::EmptyField { field });
    }
    if value.len() > MAX_JOB_LIFECYCLE_STRING_LENGTH {
        return Err(JobLifecycleError::FieldTooLong {
            field,
            actual: value.len(),
            max: MAX_JOB_LIFECYCLE_STRING_LENGTH,
        });
    }
    Ok(())
}

fn append_len_framed(buf: &mut Vec<u8>, value: &[u8]) -> Result<(), JobLifecycleError> {
    let len = u32::try_from(value.len()).map_err(|_| JobLifecycleError::SizeConversion)?;
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_identity() -> FacJobIdentityV1 {
        let preimage = FacJobIdentityPreimageV1 {
            work_id: "W-42".to_string(),
            changeset_digest: "b3-256:".to_string() + &"a".repeat(64),
            gate_profile: "gates:balanced".to_string(),
            revision: "b3-256:".to_string() + &"b".repeat(64),
        };
        let job_id = derive_content_addressable_job_id(&preimage).expect("derive job id");
        FacJobIdentityV1 {
            job_id,
            queue_job_id: "gates-old-id".to_string(),
            work_id: preimage.work_id,
            changeset_digest: preimage.changeset_digest,
            spec_digest: "b3-256:".to_string() + &"c".repeat(64),
            gate_profile: preimage.gate_profile,
            revision: preimage.revision,
        }
    }

    #[test]
    fn content_addressable_job_id_is_stable() {
        let preimage = FacJobIdentityPreimageV1 {
            work_id: "W-42".to_string(),
            changeset_digest: "b3-256:".to_string() + &"a".repeat(64),
            gate_profile: "gates:balanced".to_string(),
            revision: "7".to_string(),
        };

        let first = derive_content_addressable_job_id(&preimage).expect("first");
        let second = derive_content_addressable_job_id(&preimage).expect("second");
        assert_eq!(first, second, "job id must be deterministic");
    }

    #[test]
    fn content_addressable_job_id_uses_length_framing() {
        let a = FacJobIdentityPreimageV1 {
            work_id: "ab".to_string(),
            changeset_digest: "c".to_string(),
            gate_profile: "x".to_string(),
            revision: "y".to_string(),
        };
        let b = FacJobIdentityPreimageV1 {
            work_id: "a".to_string(),
            changeset_digest: "bc".to_string(),
            gate_profile: "x".to_string(),
            revision: "y".to_string(),
        };

        let first = derive_content_addressable_job_id(&a).expect("first");
        let second = derive_content_addressable_job_id(&b).expect("second");
        assert_ne!(
            first, second,
            "length framing must prevent concatenation ambiguity"
        );
    }

    #[test]
    fn lifecycle_event_roundtrip_encode_decode() {
        let event = FacJobLifecycleEventV1::new(
            "enqueue:b3-256:abc",
            None,
            FacJobLifecycleEventData::Enqueued(FacJobEnqueuedV1 {
                identity: sample_identity(),
                enqueue_epoch_ns: 7,
            }),
        );
        let bytes = event.encode_bounded().expect("encode");
        let decoded = FacJobLifecycleEventV1::decode_bounded(&bytes).expect("decode");
        assert_eq!(decoded, event);
    }

    #[test]
    fn lifecycle_event_decode_rejects_oversized_payload() {
        let oversized = vec![b'x'; MAX_JOB_LIFECYCLE_EVENT_SIZE + 1];
        let result = FacJobLifecycleEventV1::decode_bounded(&oversized);
        assert!(matches!(
            result,
            Err(JobLifecycleError::PayloadTooLarge { .. })
        ));
    }
}
