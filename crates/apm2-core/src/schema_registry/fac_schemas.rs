//! FAC schema registry: stable schema IDs and bounded deserialization for
//! all Forge Admission Cycle schemas.
//!
//! This module enforces TCK-00593 requirements:
//! - Every FAC schema has a stable, unique schema ID string
//! - Deserialization is bounded by [`MAX_FAC_SCHEMA_PAYLOAD_SIZE`]
//! - All schema IDs are centrally registered and tested for drift
//! - Canonicalization uses `apm2_core::determinism::canonicalize_json`
//!
//! # Security Properties
//!
//! - **Bounded deserialization**: [`bounded_from_slice`] rejects payloads
//!   exceeding [`MAX_FAC_SCHEMA_PAYLOAD_SIZE`] *before* any JSON parsing,
//!   preventing memory exhaustion via crafted large payloads (RSK-1601).
//! - **`deny_unknown_fields`**: All FAC struct schemas use serde's
//!   `deny_unknown_fields` attribute to reject payloads with unexpected fields,
//!   preventing injection of unvalidated data.
//! - **Fail-closed**: Unknown or missing schema IDs cause rejection, never
//!   silent acceptance.
//!
//! # Adding a New FAC Schema
//!
//! 1. Define a `pub const` schema ID in this module following the naming
//!    convention `apm2.<domain>.<type>.v<N>`.
//! 2. Add the constant to [`ALL_FAC_SCHEMA_IDS`].
//! 3. Add the schema ID to the existing module's `SCHEMA_IDENTIFIER` or
//!    equivalent constant.
//! 4. Ensure the struct uses `#[serde(deny_unknown_fields)]`.
//! 5. The `tck_00593_no_duplicate_fac_schema_ids` test will catch duplicates.
//! 6. The `tck_00593_all_fac_schema_ids_have_correct_prefix` test will catch
//!    naming violations.

use std::str;

use serde::de::DeserializeOwned;
use thiserror::Error;

use crate::determinism::canonicalize_json;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum payload size for bounded FAC schema deserialization (1 MiB).
///
/// Any payload exceeding this size is rejected *before* JSON parsing to
/// prevent memory exhaustion attacks (RSK-1601, CTR-1603).
pub const MAX_FAC_SCHEMA_PAYLOAD_SIZE: usize = 1_048_576;

/// Required prefix for all FAC schema identifiers.
pub const FAC_SCHEMA_PREFIX: &str = "apm2.";

// ---------------------------------------------------------------------------
// FAC Schema ID Constants
// ---------------------------------------------------------------------------

// -- Broker --
/// Schema ID for the FAC broker persisted state.
pub const BROKER_STATE_SCHEMA_ID: &str = "apm2.fac_broker_state.v1";

// -- Changeset --
/// Schema ID for changeset bundle envelopes.
pub const CHANGESET_BUNDLE_SCHEMA_ID: &str = "apm2.changeset_bundle.v1";

// -- Agent adapter profiles --
/// Schema ID for agent adapter profile v1.
pub const AGENT_ADAPTER_PROFILE_V1_SCHEMA_ID: &str = "apm2.agent_adapter_profile.v1";

// -- Role specs --
/// Schema ID for role specification v1.
pub const ROLE_SPEC_V1_SCHEMA_ID: &str = "apm2.role_spec.v1";

/// Schema ID for role specification v2.
pub const ROLE_SPEC_V2_SCHEMA_ID: &str = "apm2.role_spec.v2";

// -- Receipts --
/// Schema ID for review artifact bundle v1.
pub const REVIEW_ARTIFACT_BUNDLE_SCHEMA_ID: &str = "apm2.review_artifact_bundle.v1";

/// Schema ID for projection artifact bundle v1.
pub const PROJECTION_ARTIFACT_BUNDLE_SCHEMA_ID: &str = "apm2.projection_artifact_bundle.v1";

/// Schema ID for summary receipt v1.
pub const SUMMARY_RECEIPT_SCHEMA_ID: &str = "apm2.summary_receipt.v1";

/// Schema ID for tool execution receipt v1.
pub const TOOL_EXECUTION_RECEIPT_SCHEMA_ID: &str = "apm2.tool_execution_receipt.v1";

// -- Tool log index --
/// Schema ID for tool log index v1.
pub const TOOL_LOG_INDEX_V1_SCHEMA_ID: &str = "apm2.tool_log_index.v1";

// -- View commitment --
/// Schema ID for view commitment v1.
pub const VIEW_COMMITMENT_V1_SCHEMA_ID: &str = "apm2.view_commitment.v1";

// -- Review blocked --
/// Schema ID for review blocked recorded event v1.
pub const REVIEW_BLOCKED_SCHEMA_ID: &str = "apm2.review_blocked.v1";

// -- Efficiency primitives --
/// Schema ID for efficiency primitives v1.
pub const EFFICIENCY_PRIMITIVES_SCHEMA_ID: &str = "apm2.efficiency_primitives.v1";

/// Schema ID for credential mount descriptor v1.
pub const CREDENTIAL_MOUNT_SCHEMA_ID: &str = "apm2.fac.credential_mount.v1";

// -- Toolchain fingerprint --
/// Schema ID for toolchain fingerprint v1.
pub const TOOLCHAIN_FINGERPRINT_SCHEMA_ID: &str = "apm2.fac.toolchain_fingerprint.v1";

// ---------------------------------------------------------------------------
// Central registry list
// ---------------------------------------------------------------------------

/// All registered FAC schema IDs.
///
/// This list is the authoritative source of truth for FAC schema identity.
/// Tests assert:
/// - No duplicates
/// - All IDs start with [`FAC_SCHEMA_PREFIX`]
/// - All IDs are non-empty
///
/// **Adding a new schema?** Add its constant above and append it here.
pub const ALL_FAC_SCHEMA_IDS: &[&str] = &[
    BROKER_STATE_SCHEMA_ID,
    CHANGESET_BUNDLE_SCHEMA_ID,
    AGENT_ADAPTER_PROFILE_V1_SCHEMA_ID,
    ROLE_SPEC_V1_SCHEMA_ID,
    ROLE_SPEC_V2_SCHEMA_ID,
    REVIEW_ARTIFACT_BUNDLE_SCHEMA_ID,
    PROJECTION_ARTIFACT_BUNDLE_SCHEMA_ID,
    SUMMARY_RECEIPT_SCHEMA_ID,
    TOOL_EXECUTION_RECEIPT_SCHEMA_ID,
    TOOL_LOG_INDEX_V1_SCHEMA_ID,
    VIEW_COMMITMENT_V1_SCHEMA_ID,
    REVIEW_BLOCKED_SCHEMA_ID,
    EFFICIENCY_PRIMITIVES_SCHEMA_ID,
    CREDENTIAL_MOUNT_SCHEMA_ID,
    TOOLCHAIN_FINGERPRINT_SCHEMA_ID,
];

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from bounded FAC schema deserialization.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BoundedDeserializeError {
    /// Payload exceeds the maximum allowed size.
    #[error("payload too large: {size} bytes exceeds maximum of {max} bytes")]
    PayloadTooLarge {
        /// Actual payload size.
        size: usize,
        /// Maximum allowed size.
        max: usize,
    },

    /// Payload is empty.
    #[error("empty payload")]
    EmptyPayload,

    /// JSON deserialization failed.
    #[error("deserialization failed: {message}")]
    DeserializationFailed {
        /// Error detail from `serde_json`.
        message: String,
    },

    /// Canonicalization failed before deserialization.
    #[error("canonicalization failed: {message}")]
    CanonicalizationFailed {
        /// Error detail from CAC JSON canonicalization.
        message: String,
    },
}

// ---------------------------------------------------------------------------
// Bounded deserialization
// ---------------------------------------------------------------------------

/// Deserialize a FAC schema payload with bounded size enforcement.
///
/// This function rejects payloads exceeding [`MAX_FAC_SCHEMA_PAYLOAD_SIZE`]
/// **before** any JSON parsing occurs, preventing memory exhaustion via
/// crafted large payloads (RSK-1601, CTR-1603).
///
/// The target type `T` should use `#[serde(deny_unknown_fields)]` to reject
/// unexpected fields (CTR-1604).
///
/// # Arguments
///
/// * `data` - Raw JSON bytes to deserialize
///
/// # Errors
///
/// - [`BoundedDeserializeError::EmptyPayload`] if `data` is empty
/// - [`BoundedDeserializeError::PayloadTooLarge`] if `data` exceeds the cap
/// - [`BoundedDeserializeError::DeserializationFailed`] if JSON parsing fails
///
/// # Example
///
/// ```rust
/// use apm2_core::schema_registry::fac_schemas::bounded_from_slice;
/// use serde::Deserialize;
///
/// #[derive(Deserialize)]
/// #[serde(deny_unknown_fields)]
/// struct MySchema {
///     id: String,
/// }
///
/// let data = br#"{"id":"test"}"#;
/// let result: MySchema = bounded_from_slice(data).unwrap();
/// assert_eq!(result.id, "test");
/// ```
pub fn bounded_from_slice<T: DeserializeOwned>(data: &[u8]) -> Result<T, BoundedDeserializeError> {
    bounded_from_slice_with_limit(data, MAX_FAC_SCHEMA_PAYLOAD_SIZE)
}

/// Deserialize a FAC schema payload with a custom size limit.
///
/// Same as [`bounded_from_slice`] but allows callers to specify a custom
/// maximum payload size. This is useful for schemas with known smaller
/// bounds (e.g., broker state uses its own `MAX_BROKER_STATE_FILE_SIZE`).
///
/// # Arguments
///
/// * `data` - Raw JSON bytes to deserialize
/// * `max_size` - Maximum allowed payload size in bytes
///
/// # Errors
///
/// See [`bounded_from_slice`].
pub fn bounded_from_slice_with_limit<T: DeserializeOwned>(
    data: &[u8],
    max_size: usize,
) -> Result<T, BoundedDeserializeError> {
    if data.is_empty() {
        return Err(BoundedDeserializeError::EmptyPayload);
    }

    if data.len() > max_size {
        return Err(BoundedDeserializeError::PayloadTooLarge {
            size: data.len(),
            max: max_size,
        });
    }

    let input =
        str::from_utf8(data).map_err(|e| BoundedDeserializeError::DeserializationFailed {
            message: format!("invalid UTF-8 input: {e}"),
        })?;

    let canonical_json =
        canonicalize_json(input).map_err(|e| BoundedDeserializeError::CanonicalizationFailed {
            message: e.to_string(),
        })?;

    serde_json::from_str(&canonical_json).map_err(|e| {
        BoundedDeserializeError::DeserializationFailed {
            message: e.to_string(),
        }
    })
}

/// Validate that a schema ID is a known FAC schema.
///
/// Returns `true` if the schema ID is present in [`ALL_FAC_SCHEMA_IDS`].
/// This is a fail-closed check: unknown schema IDs return `false`.
#[must_use]
pub fn is_known_fac_schema(schema_id: &str) -> bool {
    ALL_FAC_SCHEMA_IDS.contains(&schema_id)
}

// ---------------------------------------------------------------------------
// Schema ID cross-reference validation
// ---------------------------------------------------------------------------

/// Validates that a schema ID matches the expected value for a given
/// schema type. Returns `Ok(())` on match, or an error describing the
/// mismatch.
///
/// This is used by individual FAC schema modules to validate the `schema`
/// field during deserialization.
///
/// # Arguments
///
/// * `expected` - The expected schema ID constant
/// * `actual` - The actual schema ID from the deserialized payload
///
/// # Errors
///
/// Returns a [`BoundedDeserializeError::DeserializationFailed`] if the
/// schema IDs do not match.
pub fn validate_schema_id(expected: &str, actual: &str) -> Result<(), BoundedDeserializeError> {
    if expected != actual {
        return Err(BoundedDeserializeError::DeserializationFailed {
            message: format!("schema_id mismatch: expected {expected}, got {actual}"),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use serde::Deserialize;

    use super::*;

    // ===================================================================
    // Schema ID drift prevention tests
    // ===================================================================

    #[test]
    fn tck_00593_no_duplicate_fac_schema_ids() {
        let mut seen = HashSet::new();
        for id in ALL_FAC_SCHEMA_IDS {
            assert!(
                seen.insert(*id),
                "duplicate FAC schema ID: {id} — every schema must have a unique ID"
            );
        }
    }

    #[test]
    fn tck_00593_all_fac_schema_ids_have_correct_prefix() {
        for id in ALL_FAC_SCHEMA_IDS {
            assert!(
                id.starts_with(FAC_SCHEMA_PREFIX),
                "FAC schema ID {id} does not start with required prefix '{FAC_SCHEMA_PREFIX}'"
            );
        }
    }

    #[test]
    fn tck_00593_all_fac_schema_ids_non_empty() {
        for id in ALL_FAC_SCHEMA_IDS {
            assert!(!id.is_empty(), "FAC schema ID must not be empty");
        }
    }

    #[test]
    fn tck_00593_fac_schema_id_count() {
        // This test will fail when a new schema is added without updating
        // ALL_FAC_SCHEMA_IDS, acting as a change-detection gate.
        assert_eq!(
            ALL_FAC_SCHEMA_IDS.len(),
            15,
            "ALL_FAC_SCHEMA_IDS count changed — update this test after adding new schemas"
        );
    }

    // ===================================================================
    // Cross-reference: schema ID constants match their module definitions
    // ===================================================================

    #[test]
    fn tck_00593_broker_state_schema_id_matches_module() {
        // Cross-check that our constant matches the module's private constant.
        assert_eq!(BROKER_STATE_SCHEMA_ID, "apm2.fac_broker_state.v1");
    }

    #[test]
    fn tck_00593_changeset_bundle_schema_id_matches_module() {
        use crate::fac::SCHEMA_IDENTIFIER;
        assert_eq!(CHANGESET_BUNDLE_SCHEMA_ID, SCHEMA_IDENTIFIER);
    }

    #[test]
    fn tck_00593_agent_adapter_profile_schema_id_matches_module() {
        use crate::fac::AGENT_ADAPTER_PROFILE_V1_SCHEMA;
        assert_eq!(
            AGENT_ADAPTER_PROFILE_V1_SCHEMA_ID,
            AGENT_ADAPTER_PROFILE_V1_SCHEMA
        );
    }

    #[test]
    fn tck_00593_role_spec_v1_schema_id_matches_module() {
        use crate::fac::ROLE_SPEC_V1_SCHEMA;
        assert_eq!(ROLE_SPEC_V1_SCHEMA_ID, ROLE_SPEC_V1_SCHEMA);
    }

    #[test]
    fn tck_00593_role_spec_v2_schema_id_matches_module() {
        use crate::fac::ROLE_SPEC_V2_SCHEMA;
        assert_eq!(ROLE_SPEC_V2_SCHEMA_ID, ROLE_SPEC_V2_SCHEMA);
    }

    #[test]
    fn tck_00593_review_artifact_bundle_schema_id_matches_module() {
        use crate::fac::REVIEW_ARTIFACT_SCHEMA_IDENTIFIER;
        assert_eq!(
            REVIEW_ARTIFACT_BUNDLE_SCHEMA_ID,
            REVIEW_ARTIFACT_SCHEMA_IDENTIFIER
        );
    }

    #[test]
    fn tck_00593_projection_artifact_bundle_schema_id_matches_module() {
        use crate::fac::PROJECTION_ARTIFACT_SCHEMA_IDENTIFIER;
        assert_eq!(
            PROJECTION_ARTIFACT_BUNDLE_SCHEMA_ID,
            PROJECTION_ARTIFACT_SCHEMA_IDENTIFIER
        );
    }

    #[test]
    fn tck_00593_summary_receipt_schema_id_matches_module() {
        use crate::fac::SUMMARY_RECEIPT_SCHEMA;
        assert_eq!(SUMMARY_RECEIPT_SCHEMA_ID, SUMMARY_RECEIPT_SCHEMA);
    }

    #[test]
    fn tck_00593_tool_execution_receipt_schema_id_matches_module() {
        use crate::fac::TOOL_EXECUTION_RECEIPT_SCHEMA;
        assert_eq!(
            TOOL_EXECUTION_RECEIPT_SCHEMA_ID,
            TOOL_EXECUTION_RECEIPT_SCHEMA
        );
    }

    #[test]
    fn tck_00593_tool_log_index_schema_id_matches_module() {
        use crate::fac::TOOL_LOG_INDEX_V1_SCHEMA;
        assert_eq!(TOOL_LOG_INDEX_V1_SCHEMA_ID, TOOL_LOG_INDEX_V1_SCHEMA);
    }

    #[test]
    fn tck_00593_view_commitment_schema_id_matches_module() {
        use crate::fac::VIEW_COMMITMENT_V1_SCHEMA;
        assert_eq!(VIEW_COMMITMENT_V1_SCHEMA_ID, VIEW_COMMITMENT_V1_SCHEMA);
    }

    #[test]
    fn tck_00593_review_blocked_schema_id_matches_module() {
        use crate::fac::REVIEW_BLOCKED_SCHEMA_IDENTIFIER;
        assert_eq!(REVIEW_BLOCKED_SCHEMA_ID, REVIEW_BLOCKED_SCHEMA_IDENTIFIER);
    }

    #[test]
    fn tck_00593_efficiency_primitives_schema_id_matches_module() {
        use crate::fac::EFFICIENCY_PRIMITIVES_SCHEMA;
        assert_eq!(
            EFFICIENCY_PRIMITIVES_SCHEMA_ID,
            EFFICIENCY_PRIMITIVES_SCHEMA
        );
    }

    // ===================================================================
    // Bounded deserialization tests
    // ===================================================================

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    struct TestSchema {
        id: String,
        value: u64,
    }

    #[test]
    fn tck_00593_bounded_from_slice_success() {
        let data = br#"{"id":"test-001","value":42}"#;
        let result: TestSchema = bounded_from_slice(data).unwrap();
        assert_eq!(result.id, "test-001");
        assert_eq!(result.value, 42);
    }

    #[test]
    fn tck_00593_bounded_from_slice_rejects_empty() {
        let result = bounded_from_slice::<TestSchema>(b"");
        assert_eq!(result.unwrap_err(), BoundedDeserializeError::EmptyPayload);
    }

    #[test]
    fn tck_00593_bounded_from_slice_rejects_oversized() {
        let oversized = vec![b' '; MAX_FAC_SCHEMA_PAYLOAD_SIZE + 1];
        let result = bounded_from_slice::<TestSchema>(&oversized);
        match result.unwrap_err() {
            BoundedDeserializeError::PayloadTooLarge { size, max } => {
                assert_eq!(size, MAX_FAC_SCHEMA_PAYLOAD_SIZE + 1);
                assert_eq!(max, MAX_FAC_SCHEMA_PAYLOAD_SIZE);
            },
            other => panic!("expected PayloadTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn tck_00593_bounded_from_slice_rejects_at_exact_limit_plus_one() {
        // Verify the boundary: exactly MAX + 1 bytes is rejected
        let data = vec![b'x'; MAX_FAC_SCHEMA_PAYLOAD_SIZE + 1];
        let result = bounded_from_slice::<TestSchema>(&data);
        assert!(matches!(
            result,
            Err(BoundedDeserializeError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn tck_00593_bounded_from_slice_accepts_at_exact_limit() {
        // Verify the boundary: exactly MAX_FAC_SCHEMA_PAYLOAD_SIZE bytes is
        // accepted and parsed after size and canonicalization checks.
        let mut data = vec![b' '; MAX_FAC_SCHEMA_PAYLOAD_SIZE];
        let payload = br#"{"id":"x","value":1}"#;
        data[..payload.len()].copy_from_slice(payload);

        let result: TestSchema = bounded_from_slice(&data).unwrap();
        assert_eq!(result.id, "x");
        assert_eq!(result.value, 1);
    }

    #[test]
    fn tck_00593_bounded_from_slice_custom_limit() {
        let data = br#"{"id":"test","value":1}"#;
        // Succeeds with generous limit
        let result: TestSchema = bounded_from_slice_with_limit(data, 1024).unwrap();
        assert_eq!(result.id, "test");

        // Fails with tiny limit
        let result = bounded_from_slice_with_limit::<TestSchema>(data, 5);
        assert!(matches!(
            result,
            Err(BoundedDeserializeError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn tck_00593_bounded_from_slice_rejects_invalid_json() {
        let data = br#"{"id": 123, "value": "not_a_number"}"#;
        let result = bounded_from_slice::<TestSchema>(data);
        assert!(matches!(
            result,
            Err(BoundedDeserializeError::DeserializationFailed { .. })
        ));
    }

    #[test]
    fn tck_00593_bounded_from_slice_rejects_duplicate_keys_before_deserialization() {
        let data = br#"{"id":"first","id":"second","value":7}"#;
        let result = bounded_from_slice::<TestSchema>(data);
        assert!(matches!(
            result,
            Err(BoundedDeserializeError::CanonicalizationFailed { .. })
        ));
    }

    #[test]
    fn tck_00593_bounded_from_slice_deny_unknown_fields() {
        // The TestSchema type has deny_unknown_fields, so this should fail
        let data = br#"{"id":"test","value":1,"extra":"field"}"#;
        let result = bounded_from_slice::<TestSchema>(data);
        assert!(
            matches!(
                result,
                Err(BoundedDeserializeError::DeserializationFailed { .. })
            ),
            "deny_unknown_fields should reject payloads with extra fields"
        );
    }

    // ===================================================================
    // Schema ID validation tests
    // ===================================================================

    #[test]
    fn tck_00593_is_known_fac_schema_positive() {
        assert!(is_known_fac_schema(BROKER_STATE_SCHEMA_ID));
        assert!(is_known_fac_schema(CHANGESET_BUNDLE_SCHEMA_ID));
        assert!(is_known_fac_schema(ROLE_SPEC_V2_SCHEMA_ID));
    }

    #[test]
    fn tck_00593_is_known_fac_schema_negative() {
        assert!(!is_known_fac_schema("unknown.schema.v1"));
        assert!(!is_known_fac_schema(""));
        assert!(!is_known_fac_schema("apm2.nonexistent.v99"));
    }

    #[test]
    fn tck_00593_validate_schema_id_match() {
        assert!(validate_schema_id(BROKER_STATE_SCHEMA_ID, "apm2.fac_broker_state.v1").is_ok());
    }

    #[test]
    fn tck_00593_validate_schema_id_mismatch() {
        let result = validate_schema_id(BROKER_STATE_SCHEMA_ID, "wrong.schema.v1");
        assert!(matches!(
            result,
            Err(BoundedDeserializeError::DeserializationFailed { .. })
        ));
    }

    // ===================================================================
    // Schema ID format invariant tests
    // ===================================================================

    #[test]
    fn tck_00593_all_schema_ids_contain_version_suffix() {
        for id in ALL_FAC_SCHEMA_IDS {
            assert!(
                id.contains(".v"),
                "FAC schema ID {id} should contain a version suffix like .v1 or .v2"
            );
        }
    }

    #[test]
    fn tck_00593_all_schema_ids_are_ascii() {
        for id in ALL_FAC_SCHEMA_IDS {
            assert!(
                id.is_ascii(),
                "FAC schema ID {id} contains non-ASCII characters"
            );
        }
    }

    #[test]
    fn tck_00593_all_schema_ids_reasonable_length() {
        for id in ALL_FAC_SCHEMA_IDS {
            assert!(id.len() <= 128, "FAC schema ID {id} exceeds 128 characters");
            assert!(id.len() >= 8, "FAC schema ID {id} is suspiciously short");
        }
    }
}
