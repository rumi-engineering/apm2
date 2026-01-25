//! Evidence state types.

use serde::{Deserialize, Serialize};

use super::category::EvidenceCategory;
use super::classification::DataClassification;
use crate::crypto::Hash;

/// A published evidence artifact.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub struct Evidence {
    /// Unique identifier for this evidence.
    pub evidence_id: String,

    /// The work item this evidence is linked to.
    pub work_id: String,

    /// Category of this evidence.
    pub category: EvidenceCategory,

    /// BLAKE3 hash of the artifact content.
    pub artifact_hash: Hash,

    /// Size of the artifact in bytes.
    pub artifact_size: usize,

    /// Data classification.
    pub classification: DataClassification,

    /// Verification command IDs that apply to this evidence.
    pub verification_command_ids: Vec<String>,

    /// Optional metadata as key-value pairs.
    pub metadata: Vec<(String, String)>,

    /// Timestamp when the evidence was published (Unix nanos).
    pub published_at: u64,

    /// Actor ID that published this evidence.
    pub published_by: String,
}

impl Evidence {
    /// Creates new evidence.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::missing_const_for_fn)] // Can't be const: String/Vec aren't const-constructible
    pub fn new(
        evidence_id: String,
        work_id: String,
        category: EvidenceCategory,
        artifact_hash: Hash,
        artifact_size: usize,
        classification: DataClassification,
        verification_command_ids: Vec<String>,
        metadata: Vec<(String, String)>,
        published_at: u64,
        published_by: String,
    ) -> Self {
        Self {
            evidence_id,
            work_id,
            category,
            artifact_hash,
            artifact_size,
            classification,
            verification_command_ids,
            metadata,
            published_at,
            published_by,
        }
    }

    /// Returns a summary of this evidence.
    #[must_use]
    pub fn summary(&self) -> EvidenceSummary {
        EvidenceSummary {
            evidence_id: self.evidence_id.clone(),
            work_id: self.work_id.clone(),
            category: self.category,
            artifact_hash: self.artifact_hash,
            artifact_size: self.artifact_size,
            classification: self.classification,
            published_at: self.published_at,
        }
    }

    /// Returns whether this evidence requires progressive disclosure.
    #[must_use]
    pub const fn requires_progressive_disclosure(&self) -> bool {
        self.classification.requires_progressive_disclosure()
    }

    /// Returns whether this evidence has verification commands.
    #[must_use]
    pub fn has_verification_commands(&self) -> bool {
        !self.verification_command_ids.is_empty()
    }

    /// Gets a metadata value by key.
    #[must_use]
    pub fn get_metadata(&self, key: &str) -> Option<&str> {
        self.metadata
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

/// A summary view of evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceSummary {
    /// Evidence ID.
    pub evidence_id: String,

    /// Work ID the evidence is linked to.
    pub work_id: String,

    /// Category.
    pub category: EvidenceCategory,

    /// Artifact hash.
    pub artifact_hash: Hash,

    /// Artifact size in bytes.
    pub artifact_size: usize,

    /// Classification.
    pub classification: DataClassification,

    /// When the evidence was published.
    pub published_at: u64,
}

/// A bundle of evidence artifacts for a work item.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub struct EvidenceBundle {
    /// The work item this bundle is for.
    pub work_id: String,

    /// BLAKE3 hash of the bundle manifest.
    pub bundle_hash: Hash,

    /// Evidence IDs included in this bundle.
    pub evidence_ids: Vec<String>,

    /// Categories represented in this bundle.
    pub categories: Vec<EvidenceCategory>,

    /// Total size of all artifacts in bytes.
    pub total_size: usize,

    /// Timestamp when the bundle was created (Unix nanos).
    pub created_at: u64,
}

impl EvidenceBundle {
    /// Creates a new evidence bundle.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Can't be const: String/Vec aren't const-constructible
    pub fn new(
        work_id: String,
        bundle_hash: Hash,
        evidence_ids: Vec<String>,
        categories: Vec<EvidenceCategory>,
        total_size: usize,
        created_at: u64,
    ) -> Self {
        Self {
            work_id,
            bundle_hash,
            evidence_ids,
            categories,
            total_size,
            created_at,
        }
    }

    /// Returns the number of evidence items in this bundle.
    #[must_use]
    pub fn evidence_count(&self) -> usize {
        self.evidence_ids.len()
    }

    /// Returns whether this bundle is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.evidence_ids.is_empty()
    }

    /// Returns whether this bundle contains evidence with the given category.
    #[must_use]
    pub fn has_category(&self, category: EvidenceCategory) -> bool {
        self.categories.contains(&category)
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    fn make_test_evidence() -> Evidence {
        Evidence::new(
            "evid-001".to_string(),
            "work-123".to_string(),
            EvidenceCategory::TestResults,
            [1u8; 32],
            1024,
            DataClassification::Internal,
            vec!["CMD-001".to_string()],
            vec![("key".to_string(), "value".to_string())],
            1_000_000_000,
            "actor-001".to_string(),
        )
    }

    #[test]
    fn test_evidence_new() {
        let evidence = make_test_evidence();

        assert_eq!(evidence.evidence_id, "evid-001");
        assert_eq!(evidence.work_id, "work-123");
        assert_eq!(evidence.category, EvidenceCategory::TestResults);
        assert_eq!(evidence.artifact_hash, [1u8; 32]);
        assert_eq!(evidence.artifact_size, 1024);
        assert_eq!(evidence.classification, DataClassification::Internal);
        assert_eq!(evidence.verification_command_ids, vec!["CMD-001"]);
        assert_eq!(
            evidence.metadata,
            vec![("key".to_string(), "value".to_string())]
        );
        assert_eq!(evidence.published_at, 1_000_000_000);
        assert_eq!(evidence.published_by, "actor-001");
    }

    #[test]
    fn test_evidence_summary() {
        let evidence = make_test_evidence();
        let summary = evidence.summary();

        assert_eq!(summary.evidence_id, "evid-001");
        assert_eq!(summary.work_id, "work-123");
        assert_eq!(summary.category, EvidenceCategory::TestResults);
        assert_eq!(summary.artifact_hash, [1u8; 32]);
        assert_eq!(summary.artifact_size, 1024);
        assert_eq!(summary.classification, DataClassification::Internal);
        assert_eq!(summary.published_at, 1_000_000_000);
    }

    #[test]
    fn test_evidence_progressive_disclosure() {
        let mut evidence = make_test_evidence();

        evidence.classification = DataClassification::Internal;
        assert!(!evidence.requires_progressive_disclosure());

        evidence.classification = DataClassification::Confidential;
        assert!(evidence.requires_progressive_disclosure());

        evidence.classification = DataClassification::Restricted;
        assert!(evidence.requires_progressive_disclosure());
    }

    #[test]
    fn test_evidence_has_verification_commands() {
        let mut evidence = make_test_evidence();
        assert!(evidence.has_verification_commands());

        evidence.verification_command_ids.clear();
        assert!(!evidence.has_verification_commands());
    }

    #[test]
    fn test_evidence_get_metadata() {
        let evidence = make_test_evidence();

        assert_eq!(evidence.get_metadata("key"), Some("value"));
        assert_eq!(evidence.get_metadata("nonexistent"), None);
    }

    #[test]
    fn test_evidence_bundle_new() {
        let bundle = EvidenceBundle::new(
            "work-123".to_string(),
            [2u8; 32],
            vec!["evid-001".to_string(), "evid-002".to_string()],
            vec![EvidenceCategory::TestResults, EvidenceCategory::LintReports],
            2048,
            2_000_000_000,
        );

        assert_eq!(bundle.work_id, "work-123");
        assert_eq!(bundle.bundle_hash, [2u8; 32]);
        assert_eq!(bundle.evidence_ids.len(), 2);
        assert_eq!(bundle.categories.len(), 2);
        assert_eq!(bundle.total_size, 2048);
        assert_eq!(bundle.created_at, 2_000_000_000);
    }

    #[test]
    fn test_evidence_bundle_evidence_count() {
        let bundle = EvidenceBundle::new(
            "work-123".to_string(),
            [2u8; 32],
            vec![
                "evid-001".to_string(),
                "evid-002".to_string(),
                "evid-003".to_string(),
            ],
            vec![EvidenceCategory::TestResults],
            1024,
            1_000_000_000,
        );

        assert_eq!(bundle.evidence_count(), 3);
    }

    #[test]
    fn test_evidence_bundle_is_empty() {
        let empty_bundle = EvidenceBundle::new(
            "work-123".to_string(),
            [0u8; 32],
            vec![],
            vec![],
            0,
            1_000_000_000,
        );
        assert!(empty_bundle.is_empty());

        let non_empty_bundle = EvidenceBundle::new(
            "work-123".to_string(),
            [0u8; 32],
            vec!["evid-001".to_string()],
            vec![EvidenceCategory::TestResults],
            512,
            1_000_000_000,
        );
        assert!(!non_empty_bundle.is_empty());
    }

    #[test]
    fn test_evidence_bundle_has_category() {
        let bundle = EvidenceBundle::new(
            "work-123".to_string(),
            [0u8; 32],
            vec!["evid-001".to_string()],
            vec![EvidenceCategory::TestResults, EvidenceCategory::LintReports],
            512,
            1_000_000_000,
        );

        assert!(bundle.has_category(EvidenceCategory::TestResults));
        assert!(bundle.has_category(EvidenceCategory::LintReports));
        assert!(!bundle.has_category(EvidenceCategory::SecurityScans));
    }
}
