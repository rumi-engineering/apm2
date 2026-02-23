//! Authoritative changeset publication identity wiring for FAC vNext.
//!
//! `ChangesetPublication` is the canonical representation of the
//! `work_id <-> changeset_digest <-> cas_hash` binding derived from a
//! `changeset_published` kernel event payload.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::policy_resolution::MAX_STRING_LENGTH;

/// Payload view extracted from a `changeset_published` kernel event.
///
/// This type is intentionally strict and contains only authoritative fields
/// required to derive a [`ChangesetPublication`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeSetPublishedKernelEventPayload {
    /// Work item identifier.
    pub work_id: String,
    /// Canonical changeset digest.
    pub changeset_digest: [u8; 32],
    /// CAS hash for the canonical bundle.
    pub cas_hash: [u8; 32],
    /// Publication timestamp in nanoseconds.
    pub published_at_ns: u64,
    /// Actor that published the changeset.
    pub publisher_actor_id: String,
    /// Stable event identifier for the source `changeset_published` event.
    pub event_id: String,
}

/// Canonical changeset publication identity binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangesetPublication {
    /// Work item identifier.
    pub work_id: String,
    /// Canonical changeset digest.
    pub changeset_digest: [u8; 32],
    /// CAS hash for the canonical bundle.
    pub bundle_cas_hash: [u8; 32],
    /// Publication timestamp in milliseconds.
    pub published_at_ms: u64,
    /// Actor that published the changeset.
    pub publisher_actor_id: String,
    /// Stable event identifier for the source `changeset_published` event.
    pub changeset_published_event_id: String,
}

/// Errors returned while constructing [`ChangesetPublication`].
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ChangesetPublicationError {
    /// `work_id` is empty.
    #[error("work_id must not be empty")]
    EmptyWorkId,
    /// `publisher_actor_id` is empty.
    #[error("publisher_actor_id must not be empty")]
    EmptyPublisherActorId,
    /// Source event id is empty.
    #[error("changeset_published event_id must not be empty")]
    EmptyEventId,
    /// `publisher_actor_id` exceeds maximum length.
    #[error("publisher_actor_id exceeds max length: {actual} > {max}")]
    PublisherActorIdTooLong {
        /// Actual length.
        actual: usize,
        /// Maximum allowed.
        max: usize,
    },
    /// `work_id` exceeds maximum length.
    #[error("work_id exceeds max length: {actual} > {max}")]
    WorkIdTooLong {
        /// Actual length.
        actual: usize,
        /// Maximum allowed.
        max: usize,
    },
    /// `event_id` exceeds maximum length.
    #[error("event_id exceeds max length: {actual} > {max}")]
    EventIdTooLong {
        /// Actual length.
        actual: usize,
        /// Maximum allowed.
        max: usize,
    },
}

impl TryFrom<ChangeSetPublishedKernelEventPayload> for ChangesetPublication {
    type Error = ChangesetPublicationError;

    fn try_from(value: ChangeSetPublishedKernelEventPayload) -> Result<Self, Self::Error> {
        if value.work_id.is_empty() {
            return Err(ChangesetPublicationError::EmptyWorkId);
        }
        if value.work_id.len() > MAX_STRING_LENGTH {
            return Err(ChangesetPublicationError::WorkIdTooLong {
                actual: value.work_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if value.publisher_actor_id.is_empty() {
            return Err(ChangesetPublicationError::EmptyPublisherActorId);
        }
        if value.publisher_actor_id.len() > MAX_STRING_LENGTH {
            return Err(ChangesetPublicationError::PublisherActorIdTooLong {
                actual: value.publisher_actor_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if value.event_id.is_empty() {
            return Err(ChangesetPublicationError::EmptyEventId);
        }
        if value.event_id.len() > MAX_STRING_LENGTH {
            return Err(ChangesetPublicationError::EventIdTooLong {
                actual: value.event_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }

        Ok(Self {
            work_id: value.work_id,
            changeset_digest: value.changeset_digest,
            bundle_cas_hash: value.cas_hash,
            published_at_ms: value.published_at_ns / 1_000_000,
            publisher_actor_id: value.publisher_actor_id,
            changeset_published_event_id: value.event_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ChangeSetPublishedKernelEventPayload, ChangesetPublication, ChangesetPublicationError,
        MAX_STRING_LENGTH,
    };

    fn valid_payload() -> ChangeSetPublishedKernelEventPayload {
        ChangeSetPublishedKernelEventPayload {
            work_id: "W-123".to_string(),
            changeset_digest: [0x11; 32],
            cas_hash: [0x22; 32],
            published_at_ns: 1_706_000_123_456_789,
            publisher_actor_id: "actor:publisher".to_string(),
            event_id: "EVT-abc123".to_string(),
        }
    }

    #[test]
    fn publisher_actor_id_too_long_is_rejected() {
        let mut payload = valid_payload();
        payload.publisher_actor_id = "x".repeat(MAX_STRING_LENGTH + 1);
        let err = ChangesetPublication::try_from(payload).unwrap_err();
        assert!(
            matches!(
                err,
                ChangesetPublicationError::PublisherActorIdTooLong { .. }
            ),
            "expected PublisherActorIdTooLong, got {err:?}"
        );
    }

    #[test]
    fn work_id_too_long_is_rejected() {
        let mut payload = valid_payload();
        payload.work_id = "x".repeat(MAX_STRING_LENGTH + 1);
        let err = ChangesetPublication::try_from(payload).unwrap_err();
        assert!(
            matches!(err, ChangesetPublicationError::WorkIdTooLong { .. }),
            "expected WorkIdTooLong, got {err:?}"
        );
    }

    #[test]
    fn event_id_too_long_is_rejected() {
        let mut payload = valid_payload();
        payload.event_id = "x".repeat(MAX_STRING_LENGTH + 1);
        let err = ChangesetPublication::try_from(payload).unwrap_err();
        assert!(
            matches!(err, ChangesetPublicationError::EventIdTooLong { .. }),
            "expected EventIdTooLong, got {err:?}"
        );
    }

    #[test]
    fn publication_try_from_kernel_payload_is_authoritative() {
        let payload = ChangeSetPublishedKernelEventPayload {
            work_id: "W-123".to_string(),
            changeset_digest: [0x11; 32],
            cas_hash: [0x22; 32],
            published_at_ns: 1_706_000_123_456_789,
            publisher_actor_id: "actor:publisher".to_string(),
            event_id: "EVT-abc123".to_string(),
        };

        let publication =
            ChangesetPublication::try_from(payload).expect("payload should convert to publication");
        assert_eq!(publication.work_id, "W-123");
        assert_eq!(publication.changeset_digest, [0x11; 32]);
        assert_eq!(publication.bundle_cas_hash, [0x22; 32]);
        assert_eq!(publication.published_at_ms, 1_706_000_123);
        assert_eq!(publication.publisher_actor_id, "actor:publisher");
        assert_eq!(publication.changeset_published_event_id, "EVT-abc123");
    }
}
