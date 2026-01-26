//! Run manifest data structures and builder.
//!
//! This module defines the [`RunManifest`] struct that captures a complete
//! record of a pipeline execution, including input/output hashes, routing
//! decisions, and stage timings.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::crypto::EventHasher;

/// Errors that can occur during manifest construction.
#[derive(Debug, Error)]
pub enum ManifestError {
    /// A required field was not provided.
    #[error("missing required field: {field}")]
    MissingField {
        /// The name of the missing field.
        field: &'static str,
    },

    /// An invalid value was provided.
    #[error("invalid value for {field}: {reason}")]
    InvalidValue {
        /// The name of the field.
        field: &'static str,
        /// The reason the value is invalid.
        reason: String,
    },
}

/// A run manifest capturing a complete record of pipeline execution.
///
/// Manifests are designed to be cryptographically signed for verification
/// and reproducibility auditing. All fields use deterministic ordering
/// (`BTreeMap`) to ensure consistent canonicalization for signing.
///
/// # Fields
///
/// - `manifest_id`: UUID v7 for temporal ordering
/// - `lease_id`: Identifies the pipeline execution session
/// - `created_at`: ISO 8601 timestamp
/// - `input_hashes`: Map of input artifact paths to BLAKE3 hashes
/// - `output_hashes`: Map of output artifact paths to BLAKE3 hashes
/// - `routing_profile_id`: Which routing profile was used
/// - `routing_decisions`: Map of stage name to provider used
/// - `stage_timings`: Map of stage name to duration in milliseconds
/// - `ccp_index_hash`: Hash of the CCP index used as grounding
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RunManifest {
    /// Unique identifier for this manifest (UUID v7 for temporal ordering).
    pub manifest_id: String,

    /// The lease ID identifying the pipeline execution session.
    pub lease_id: String,

    /// Timestamp when this manifest was created (ISO 8601).
    pub created_at: DateTime<Utc>,

    /// Map of input artifact paths to their BLAKE3 hashes (hex-encoded).
    pub input_hashes: BTreeMap<String, String>,

    /// Map of output artifact paths to their BLAKE3 hashes (hex-encoded).
    pub output_hashes: BTreeMap<String, String>,

    /// The routing profile ID that was used for this execution.
    pub routing_profile_id: String,

    /// Map of stage name to the provider that was used.
    pub routing_decisions: BTreeMap<String, String>,

    /// Map of stage name to execution duration in milliseconds.
    pub stage_timings: BTreeMap<String, u64>,

    /// BLAKE3 hash of the CCP index used as grounding (hex-encoded).
    pub ccp_index_hash: String,
}

impl RunManifest {
    /// Returns the canonical JSON representation of this manifest.
    ///
    /// This is the byte sequence that should be signed. The representation
    /// uses sorted keys and consistent formatting to ensure determinism.
    ///
    /// # Panics
    ///
    /// Panics if the manifest cannot be serialized to JSON, which should
    /// never happen for valid manifests.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        // serde_json with BTreeMap produces sorted keys
        serde_json::to_vec(self).expect("manifest serialization should not fail")
    }

    /// Computes the BLAKE3 hash of the canonical representation.
    #[must_use]
    pub fn content_hash(&self) -> [u8; 32] {
        EventHasher::hash_content(&self.canonical_bytes())
    }
}

/// Builder for constructing [`RunManifest`] instances with validation.
///
/// # Example
///
/// ```rust
/// use apm2_core::run_manifest::ManifestBuilder;
///
/// let manifest = ManifestBuilder::new()
///     .with_lease_id("lease-123")
///     .with_routing_profile_id("production")
///     .with_ccp_index_hash("abc123...")
///     .add_input("input.yaml", b"content")
///     .add_output("output.yaml", b"result")
///     .record_routing_decision("impact_map", "claude-opus-4")
///     .record_stage_timing("impact_map", 1500)
///     .build()
///     .unwrap();
/// ```
#[derive(Debug, Default)]
pub struct ManifestBuilder {
    lease_id: Option<String>,
    routing_profile_id: Option<String>,
    ccp_index_hash: Option<String>,
    input_hashes: BTreeMap<String, String>,
    output_hashes: BTreeMap<String, String>,
    routing_decisions: BTreeMap<String, String>,
    stage_timings: BTreeMap<String, u64>,
}

impl ManifestBuilder {
    /// Creates a new manifest builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the lease ID for this manifest.
    #[must_use]
    pub fn with_lease_id(mut self, lease_id: impl Into<String>) -> Self {
        self.lease_id = Some(lease_id.into());
        self
    }

    /// Sets the routing profile ID for this manifest.
    #[must_use]
    pub fn with_routing_profile_id(mut self, profile_id: impl Into<String>) -> Self {
        self.routing_profile_id = Some(profile_id.into());
        self
    }

    /// Sets the CCP index hash for this manifest.
    ///
    /// The hash should be a hex-encoded BLAKE3 hash.
    #[must_use]
    pub fn with_ccp_index_hash(mut self, hash: impl Into<String>) -> Self {
        self.ccp_index_hash = Some(hash.into());
        self
    }

    /// Adds an input artifact by computing its BLAKE3 hash.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to the input artifact
    /// * `content` - The raw content of the artifact
    #[must_use]
    pub fn add_input(mut self, path: impl Into<String>, content: &[u8]) -> Self {
        let hash = EventHasher::hash_content(content);
        self.input_hashes.insert(path.into(), hex::encode(hash));
        self
    }

    /// Adds an input artifact with a pre-computed hash.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to the input artifact
    /// * `hash` - The hex-encoded BLAKE3 hash
    #[must_use]
    pub fn add_input_hash(mut self, path: impl Into<String>, hash: impl Into<String>) -> Self {
        self.input_hashes.insert(path.into(), hash.into());
        self
    }

    /// Adds an output artifact by computing its BLAKE3 hash.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to the output artifact
    /// * `content` - The raw content of the artifact
    #[must_use]
    pub fn add_output(mut self, path: impl Into<String>, content: &[u8]) -> Self {
        let hash = EventHasher::hash_content(content);
        self.output_hashes.insert(path.into(), hex::encode(hash));
        self
    }

    /// Adds an output artifact with a pre-computed hash.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to the output artifact
    /// * `hash` - The hex-encoded BLAKE3 hash
    #[must_use]
    pub fn add_output_hash(mut self, path: impl Into<String>, hash: impl Into<String>) -> Self {
        self.output_hashes.insert(path.into(), hash.into());
        self
    }

    /// Records a routing decision for a pipeline stage.
    ///
    /// # Arguments
    ///
    /// * `stage` - The name of the pipeline stage
    /// * `provider` - The provider that was used for this stage
    #[must_use]
    pub fn record_routing_decision(
        mut self,
        stage: impl Into<String>,
        provider: impl Into<String>,
    ) -> Self {
        self.routing_decisions.insert(stage.into(), provider.into());
        self
    }

    /// Records the execution timing for a pipeline stage.
    ///
    /// # Arguments
    ///
    /// * `stage` - The name of the pipeline stage
    /// * `duration_ms` - The execution duration in milliseconds
    #[must_use]
    pub fn record_stage_timing(mut self, stage: impl Into<String>, duration_ms: u64) -> Self {
        self.stage_timings.insert(stage.into(), duration_ms);
        self
    }

    /// Builds the manifest, validating all required fields.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError::MissingField`] if any required field is not
    /// set.
    pub fn build(self) -> Result<RunManifest, ManifestError> {
        let lease_id = self
            .lease_id
            .ok_or(ManifestError::MissingField { field: "lease_id" })?;

        let routing_profile_id = self.routing_profile_id.ok_or(ManifestError::MissingField {
            field: "routing_profile_id",
        })?;

        let ccp_index_hash = self.ccp_index_hash.ok_or(ManifestError::MissingField {
            field: "ccp_index_hash",
        })?;

        // Generate UUID v7 for temporal ordering
        let manifest_id = Uuid::now_v7().to_string();

        Ok(RunManifest {
            manifest_id,
            lease_id,
            created_at: Utc::now(),
            input_hashes: self.input_hashes,
            output_hashes: self.output_hashes,
            routing_profile_id,
            routing_decisions: self.routing_decisions,
            stage_timings: self.stage_timings,
            ccp_index_hash,
        })
    }

    /// Builds the manifest with a specific manifest ID and timestamp.
    ///
    /// This is primarily for testing and replay scenarios where
    /// deterministic values are needed.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError::MissingField`] if any required field is not
    /// set.
    pub fn build_with_id(
        self,
        manifest_id: impl Into<String>,
        created_at: DateTime<Utc>,
    ) -> Result<RunManifest, ManifestError> {
        let lease_id = self
            .lease_id
            .ok_or(ManifestError::MissingField { field: "lease_id" })?;

        let routing_profile_id = self.routing_profile_id.ok_or(ManifestError::MissingField {
            field: "routing_profile_id",
        })?;

        let ccp_index_hash = self.ccp_index_hash.ok_or(ManifestError::MissingField {
            field: "ccp_index_hash",
        })?;

        Ok(RunManifest {
            manifest_id: manifest_id.into(),
            lease_id,
            created_at,
            input_hashes: self.input_hashes,
            output_hashes: self.output_hashes,
            routing_profile_id,
            routing_decisions: self.routing_decisions,
            stage_timings: self.stage_timings,
            ccp_index_hash,
        })
    }
}

#[cfg(test)]
mod unit_tests {
    use chrono::TimeZone;

    use super::*;

    fn create_test_manifest() -> RunManifest {
        let created_at = Utc.with_ymd_and_hms(2024, 1, 15, 12, 0, 0).unwrap();

        ManifestBuilder::new()
            .with_lease_id("lease-abc123")
            .with_routing_profile_id("production")
            .with_ccp_index_hash("deadbeef")
            .add_input("requirements.yaml", b"requirement content")
            .add_output("impact_map.yaml", b"impact map content")
            .record_routing_decision("impact_map", "claude-opus-4")
            .record_stage_timing("impact_map", 1500)
            .build_with_id("manifest-001", created_at)
            .unwrap()
    }

    #[test]
    fn test_manifest_builder_success() {
        let manifest = create_test_manifest();

        assert_eq!(manifest.manifest_id, "manifest-001");
        assert_eq!(manifest.lease_id, "lease-abc123");
        assert_eq!(manifest.routing_profile_id, "production");
        assert_eq!(manifest.ccp_index_hash, "deadbeef");
        assert_eq!(manifest.input_hashes.len(), 1);
        assert_eq!(manifest.output_hashes.len(), 1);
        assert_eq!(manifest.routing_decisions.len(), 1);
        assert_eq!(manifest.stage_timings.len(), 1);
        assert_eq!(
            manifest.routing_decisions.get("impact_map"),
            Some(&"claude-opus-4".to_string())
        );
        assert_eq!(manifest.stage_timings.get("impact_map"), Some(&1500));
    }

    #[test]
    fn test_manifest_builder_missing_lease_id() {
        let result = ManifestBuilder::new()
            .with_routing_profile_id("production")
            .with_ccp_index_hash("deadbeef")
            .build();

        assert!(matches!(
            result,
            Err(ManifestError::MissingField { field: "lease_id" })
        ));
    }

    #[test]
    fn test_manifest_builder_missing_routing_profile_id() {
        let result = ManifestBuilder::new()
            .with_lease_id("lease-123")
            .with_ccp_index_hash("deadbeef")
            .build();

        assert!(matches!(
            result,
            Err(ManifestError::MissingField {
                field: "routing_profile_id"
            })
        ));
    }

    #[test]
    fn test_manifest_builder_missing_ccp_index_hash() {
        let result = ManifestBuilder::new()
            .with_lease_id("lease-123")
            .with_routing_profile_id("production")
            .build();

        assert!(matches!(
            result,
            Err(ManifestError::MissingField {
                field: "ccp_index_hash"
            })
        ));
    }

    #[test]
    fn test_manifest_canonical_bytes_deterministic() {
        let manifest1 = create_test_manifest();
        let manifest2 = create_test_manifest();

        assert_eq!(manifest1.canonical_bytes(), manifest2.canonical_bytes());
    }

    #[test]
    fn test_manifest_content_hash_deterministic() {
        let manifest1 = create_test_manifest();
        let manifest2 = create_test_manifest();

        assert_eq!(manifest1.content_hash(), manifest2.content_hash());
    }

    #[test]
    fn test_manifest_serialization_roundtrip() {
        let manifest = create_test_manifest();
        let json = serde_json::to_string(&manifest).unwrap();
        let deserialized: RunManifest = serde_json::from_str(&json).unwrap();

        assert_eq!(manifest, deserialized);
    }

    #[test]
    fn test_manifest_btree_ordering() {
        // BTreeMap ensures deterministic ordering regardless of insertion order
        let created_at = Utc.with_ymd_and_hms(2024, 1, 15, 12, 0, 0).unwrap();

        let manifest1 = ManifestBuilder::new()
            .with_lease_id("lease-123")
            .with_routing_profile_id("production")
            .with_ccp_index_hash("hash")
            .add_input_hash("z_input.yaml", "hash_z")
            .add_input_hash("a_input.yaml", "hash_a")
            .build_with_id("id", created_at)
            .unwrap();

        let manifest2 = ManifestBuilder::new()
            .with_lease_id("lease-123")
            .with_routing_profile_id("production")
            .with_ccp_index_hash("hash")
            .add_input_hash("a_input.yaml", "hash_a")
            .add_input_hash("z_input.yaml", "hash_z")
            .build_with_id("id", created_at)
            .unwrap();

        assert_eq!(manifest1.canonical_bytes(), manifest2.canonical_bytes());
    }

    #[test]
    fn test_manifest_build_generates_uuid_v7() {
        let manifest = ManifestBuilder::new()
            .with_lease_id("lease-123")
            .with_routing_profile_id("production")
            .with_ccp_index_hash("hash")
            .build()
            .unwrap();

        // UUID v7 should be parseable and have the correct version
        let uuid = Uuid::parse_str(&manifest.manifest_id).unwrap();
        assert_eq!(uuid.get_version_num(), 7);
    }

    #[test]
    fn test_add_input_computes_hash() {
        let created_at = Utc.with_ymd_and_hms(2024, 1, 15, 12, 0, 0).unwrap();
        let content = b"test content";

        let manifest = ManifestBuilder::new()
            .with_lease_id("lease-123")
            .with_routing_profile_id("production")
            .with_ccp_index_hash("hash")
            .add_input("test.yaml", content)
            .build_with_id("id", created_at)
            .unwrap();

        let expected_hash = EventHasher::hash_content(content);
        assert_eq!(
            manifest.input_hashes.get("test.yaml"),
            Some(&hex::encode(expected_hash))
        );
    }

    #[test]
    fn test_add_output_computes_hash() {
        let created_at = Utc.with_ymd_and_hms(2024, 1, 15, 12, 0, 0).unwrap();
        let content = b"output content";

        let manifest = ManifestBuilder::new()
            .with_lease_id("lease-123")
            .with_routing_profile_id("production")
            .with_ccp_index_hash("hash")
            .add_output("output.yaml", content)
            .build_with_id("id", created_at)
            .unwrap();

        let expected_hash = EventHasher::hash_content(content);
        assert_eq!(
            manifest.output_hashes.get("output.yaml"),
            Some(&hex::encode(expected_hash))
        );
    }
}
