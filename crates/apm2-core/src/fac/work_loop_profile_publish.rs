//! Publish and anchor `WorkLoopProfileV1` artifacts (RFC-0032 Phase 4).
//!
//! This module provides the [`publish_work_loop_profile`] function which:
//!
//! 1. Validates the raw payload via bounded decode (max 64 KiB,
//!    `deny_unknown_fields`, non-empty `dedupe_key`).
//! 2. Canonicalizes the JSON for deterministic CAS hashing.
//! 3. Stores the canonical JSON in the content-addressed store.
//! 4. Computes a deterministic `evidence_id` with a `WLP-` prefix derived from
//!    `blake3(work_id || dedupe_key)`.
//! 5. Returns a [`PublishWorkLoopProfileResult`] containing everything needed
//!    to anchor the profile via an `evidence.published` event with category
//!    `WORK_LOOP_PROFILE`.
//!
//! # Idempotency
//!
//! Publication is idempotent on `(work_id, dedupe_key)`: the same dedupe
//! key produces the same `evidence_id`, so re-publishing the same profile
//! yields a deduplicated CAS entry and an idempotent ledger anchor.
//!
//! # Security Properties
//!
//! - **Bounded decode**: payloads exceeding 64 KiB are rejected before parsing
//!   (DoS prevention).
//! - **`deny_unknown_fields`**: extra JSON fields are rejected.
//! - **Fail-closed**: empty `dedupe_key` or malformed payloads cause explicit
//!   rejection.
//! - **Canonical JSON**: all artifacts are canonicalized before CAS
//!   storage/hashing for deterministic content addressing.

use thiserror::Error;

use super::work_cas_schemas::{
    WorkCasSchemaError, WorkLoopProfileV1, bounded_decode_loop_profile, canonicalize_for_cas,
};
use crate::crypto::EventHasher;
use crate::evidence::{ContentAddressedStore, DataClassification, EvidenceCategory, PublishResult};

/// Maximum number of metadata entries attached to a published profile.
const MAX_METADATA_ENTRIES: usize = 16;

/// Errors from publishing a work loop profile.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PublishWorkLoopProfileError {
    /// Bounded decode or schema validation failed.
    #[error("profile validation failed: {0}")]
    Validation(#[from] WorkCasSchemaError),

    /// CAS storage failed.
    #[error("CAS storage failed: {0}")]
    CasError(String),

    /// Canonicalization failed.
    #[error("canonicalization failed: {0}")]
    CanonicalizationFailed(String),
}

/// Result of a successful work loop profile publication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishWorkLoopProfileResult {
    /// The validated and decoded profile.
    pub profile: WorkLoopProfileV1,

    /// Deterministic evidence ID (`WLP-<hex>`).
    pub evidence_id: String,

    /// The underlying CAS publish result.
    pub publish_result: PublishResult,

    /// Metadata key-value pairs to attach to the `evidence.published` event.
    pub metadata: Vec<(String, String)>,
}

/// Computes a deterministic evidence ID for a work loop profile.
///
/// Format: `WLP-<first 32 hex chars of blake3(work_id || "\0" || dedupe_key)>`
///
/// The null byte separator prevents ambiguity between `work_id` and
/// `dedupe_key` boundaries.
#[must_use]
pub fn compute_evidence_id(work_id: &str, dedupe_key: &str) -> String {
    let mut hasher_input = Vec::with_capacity(work_id.len() + 1 + dedupe_key.len());
    hasher_input.extend_from_slice(work_id.as_bytes());
    hasher_input.push(0); // null byte separator for domain separation
    hasher_input.extend_from_slice(dedupe_key.as_bytes());
    let hash = EventHasher::hash_content(&hasher_input);
    let hex = hex::encode(hash);
    // Use first 32 hex chars (16 bytes) for a compact but collision-resistant ID.
    format!("WLP-{}", &hex[..32])
}

/// Validates, canonicalizes, stores, and anchors a `WorkLoopProfileV1`.
///
/// # Arguments
///
/// * `raw_payload` - Raw JSON bytes of the profile (max 64 KiB).
/// * `cas` - Content-addressed store for canonical JSON storage.
///
/// # Returns
///
/// A [`PublishWorkLoopProfileResult`] containing the validated profile,
/// deterministic evidence ID, CAS publish result, and metadata for the
/// `evidence.published` event.
///
/// # Errors
///
/// - [`PublishWorkLoopProfileError::Validation`] if the payload is oversized,
///   malformed, has unknown fields, or has an empty `dedupe_key`.
/// - [`PublishWorkLoopProfileError::CanonicalizationFailed`] if JSON
///   canonicalization fails.
/// - [`PublishWorkLoopProfileError::CasError`] if CAS storage fails.
pub fn publish_work_loop_profile<C: ContentAddressedStore>(
    raw_payload: &[u8],
    cas: &C,
) -> Result<PublishWorkLoopProfileResult, PublishWorkLoopProfileError> {
    // Step 1: Bounded decode + schema validation + field validation.
    let profile = bounded_decode_loop_profile(raw_payload)?;

    // Step 2: Compute deterministic evidence ID.
    let evidence_id = compute_evidence_id(&profile.work_id, &profile.dedupe_key);

    // Step 3: Serialize to JSON and canonicalize for deterministic hashing.
    let json_str = serde_json::to_string(&profile).map_err(|e| {
        PublishWorkLoopProfileError::CanonicalizationFailed(format!(
            "failed to serialize profile: {e}"
        ))
    })?;
    let canonical_json = canonicalize_for_cas(&json_str)?;

    // Step 4: Store canonical JSON in CAS.
    let canonical_bytes = canonical_json.as_bytes();
    let store_result = cas
        .store(canonical_bytes)
        .map_err(|e| PublishWorkLoopProfileError::CasError(e.to_string()))?;

    // Step 5: Build metadata for the evidence.published event.
    let metadata = vec![
        ("work_id".to_string(), profile.work_id.clone()),
        ("dedupe_key".to_string(), profile.dedupe_key.clone()),
        ("evidence_id".to_string(), evidence_id.clone()),
    ];
    debug_assert!(
        metadata.len() <= MAX_METADATA_ENTRIES,
        "metadata entries ({}) exceed MAX_METADATA_ENTRIES ({MAX_METADATA_ENTRIES})",
        metadata.len()
    );

    // Step 6: Build the publish result.
    let publish_result = PublishResult {
        evidence_id: evidence_id.clone(),
        work_id: profile.work_id.clone(),
        artifact_hash: store_result.hash,
        artifact_size: store_result.size,
        is_new_content: store_result.is_new,
        category: EvidenceCategory::WorkLoopProfile,
        classification: DataClassification::Internal,
        verification_command_ids: Vec::new(),
    };

    Ok(PublishWorkLoopProfileResult {
        profile,
        evidence_id,
        publish_result,
        metadata,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::MemoryCas;
    use crate::fac::work_cas_schemas::{MAX_LOOP_PROFILE_SIZE, WORK_LOOP_PROFILE_V1_SCHEMA};

    fn valid_profile_json(work_id: &str, dedupe_key: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schema": WORK_LOOP_PROFILE_V1_SCHEMA,
            "work_id": work_id,
            "dedupe_key": dedupe_key,
            "retry": {
                "max_implementer_attempts": 20,
                "max_review_rounds": 10,
                "backoff_seconds": [60, 300, 900]
            }
        }))
        .expect("valid json")
    }

    #[test]
    fn tck_00645_publish_succeeds_with_valid_profile() {
        let cas = MemoryCas::new();
        let payload = valid_profile_json("W-001", "rev:1");

        let result = publish_work_loop_profile(&payload, &cas).expect("publish should succeed");

        assert_eq!(result.profile.work_id, "W-001");
        assert_eq!(result.profile.dedupe_key, "rev:1");
        assert!(result.evidence_id.starts_with("WLP-"));
        assert_eq!(result.evidence_id.len(), 4 + 32); // "WLP-" + 32 hex chars
        assert!(result.publish_result.is_new_content);
        assert_eq!(
            result.publish_result.category,
            EvidenceCategory::WorkLoopProfile
        );
        assert_eq!(result.metadata.len(), 3);
    }

    #[test]
    fn tck_00645_publish_is_idempotent_on_same_dedupe_key() {
        let cas = MemoryCas::new();
        let payload = valid_profile_json("W-001", "rev:1");

        let r1 = publish_work_loop_profile(&payload, &cas).expect("first publish");
        let r2 = publish_work_loop_profile(&payload, &cas).expect("second publish");

        // Same evidence_id, same CAS hash.
        assert_eq!(r1.evidence_id, r2.evidence_id);
        assert_eq!(
            r1.publish_result.artifact_hash,
            r2.publish_result.artifact_hash
        );
        // Second publish is deduplicated.
        assert!(r1.publish_result.is_new_content);
        assert!(!r2.publish_result.is_new_content);
    }

    #[test]
    fn tck_00645_different_dedupe_keys_produce_different_evidence_ids() {
        let cas = MemoryCas::new();
        let p1 = valid_profile_json("W-001", "rev:1");
        let p2 = valid_profile_json("W-001", "rev:2");

        let r1 = publish_work_loop_profile(&p1, &cas).expect("publish 1");
        let r2 = publish_work_loop_profile(&p2, &cas).expect("publish 2");

        assert_ne!(r1.evidence_id, r2.evidence_id);
    }

    #[test]
    fn tck_00645_publish_rejects_empty_dedupe_key() {
        let cas = MemoryCas::new();
        let payload = serde_json::to_vec(&serde_json::json!({
            "schema": WORK_LOOP_PROFILE_V1_SCHEMA,
            "work_id": "W-001",
            "dedupe_key": ""
        }))
        .expect("valid json");

        let result = publish_work_loop_profile(&payload, &cas);
        assert!(
            matches!(
                result,
                Err(PublishWorkLoopProfileError::Validation(
                    WorkCasSchemaError::MissingField("dedupe_key")
                ))
            ),
            "empty dedupe_key must be rejected, got: {result:?}"
        );
    }

    #[test]
    fn tck_00645_publish_rejects_oversized_payload() {
        let cas = MemoryCas::new();
        let payload = vec![b' '; MAX_LOOP_PROFILE_SIZE + 1];

        let result = publish_work_loop_profile(&payload, &cas);
        assert!(result.is_err(), "oversized payload must be rejected");
    }

    #[test]
    fn tck_00645_publish_rejects_unknown_fields() {
        let cas = MemoryCas::new();
        let payload = serde_json::to_vec(&serde_json::json!({
            "schema": WORK_LOOP_PROFILE_V1_SCHEMA,
            "work_id": "W-001",
            "dedupe_key": "rev:1",
            "injected_field": true
        }))
        .expect("valid json");

        let result = publish_work_loop_profile(&payload, &cas);
        assert!(result.is_err(), "unknown fields must be rejected");
    }

    #[test]
    fn tck_00645_publish_stores_canonical_json_in_cas() {
        let cas = MemoryCas::new();
        let payload = valid_profile_json("W-001", "rev:1");

        let result = publish_work_loop_profile(&payload, &cas).expect("publish");

        // Retrieve from CAS and verify it's canonical JSON.
        let stored = cas
            .retrieve(&result.publish_result.artifact_hash)
            .expect("CAS retrieve");
        let stored_str = std::str::from_utf8(&stored).expect("valid UTF-8");

        // Canonical JSON should be re-canonicalizable to itself.
        let re_canon = canonicalize_for_cas(stored_str).expect("re-canonicalize");
        assert_eq!(stored_str, re_canon, "stored JSON must be canonical");
    }

    #[test]
    fn tck_00645_evidence_id_is_deterministic() {
        let id1 = compute_evidence_id("W-001", "rev:1");
        let id2 = compute_evidence_id("W-001", "rev:1");
        assert_eq!(id1, id2, "same inputs must produce same evidence_id");
        assert!(id1.starts_with("WLP-"));
    }

    #[test]
    fn tck_00645_evidence_id_domain_separation() {
        // Different work_ids produce different IDs even with same dedupe_key.
        let id1 = compute_evidence_id("W-001", "rev:1");
        let id2 = compute_evidence_id("W-002", "rev:1");
        assert_ne!(id1, id2);

        // Null byte separator prevents concatenation ambiguity:
        // Without the separator, ("W-001r", "ev:1") and ("W-001", "rev:1")
        // would hash to the same value. The null byte prevents this.
        let id3 = compute_evidence_id("W-001r", "ev:1");
        let id4 = compute_evidence_id("W-001", "rev:1");
        assert_ne!(id3, id4);

        // Same dedupe_key with different work_id produces different results.
        let id5 = compute_evidence_id("W-001", "dedupe");
        let id6 = compute_evidence_id("W-002", "dedupe");
        assert_ne!(id5, id6);
    }

    #[test]
    fn tck_00645_publish_rejects_empty_work_id() {
        let cas = MemoryCas::new();
        let payload = serde_json::to_vec(&serde_json::json!({
            "schema": WORK_LOOP_PROFILE_V1_SCHEMA,
            "work_id": "",
            "dedupe_key": "rev:1"
        }))
        .expect("valid json");

        let result = publish_work_loop_profile(&payload, &cas);
        assert!(
            matches!(
                result,
                Err(PublishWorkLoopProfileError::Validation(
                    WorkCasSchemaError::MissingField("work_id")
                ))
            ),
            "empty work_id must be rejected, got: {result:?}"
        );
    }

    #[test]
    fn tck_00645_publish_rejects_wrong_schema() {
        let cas = MemoryCas::new();
        let payload = serde_json::to_vec(&serde_json::json!({
            "schema": "apm2.wrong.v1",
            "work_id": "W-001",
            "dedupe_key": "rev:1"
        }))
        .expect("valid json");

        let result = publish_work_loop_profile(&payload, &cas);
        assert!(result.is_err(), "wrong schema must be rejected");
    }

    #[test]
    fn tck_00645_metadata_contains_required_fields() {
        let cas = MemoryCas::new();
        let payload = valid_profile_json("W-001", "rev:1");

        let result = publish_work_loop_profile(&payload, &cas).expect("publish");

        let meta_map: std::collections::HashMap<_, _> = result.metadata.into_iter().collect();
        assert_eq!(meta_map.get("work_id").map(String::as_str), Some("W-001"));
        assert_eq!(
            meta_map.get("dedupe_key").map(String::as_str),
            Some("rev:1")
        );
        assert!(meta_map.contains_key("evidence_id"));
    }

    #[test]
    fn tck_00645_max_metadata_entries_bounded() {
        // Verify the constant exists and is reasonable.
        // Use const assertions to avoid runtime-only constant-value assertions.
        const { assert!(MAX_METADATA_ENTRIES <= 64) };
        const { assert!(MAX_METADATA_ENTRIES >= 3) }; // We produce 3 metadata entries.
    }
}
